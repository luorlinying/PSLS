# -*- coding: utf-8 -*-
"""
勒索软件文件回滚（阶段一）单元测试

覆盖（对应方案文档"测试计划"）：
  1. 增量快照：仅变化文件新增对象
  2. 回滚恢复内容与 SHA256
  3. 删除 + 改名为 .locked 的检测与隔离
  4. 回滚重入守卫（并发仅 1 条记录）
  5. 超大文件跳过（快照 too_large / 回滚 skipped）
  6. LRU 容量清理
  7. 端到端假勒索（file_protection 回调 → 回滚）
  8. 不写扫描/沙箱协议通道

全部用例把 engine.ransomware_rollback._REPO_ROOT monkeypatch 到 tempfile。
"""
import os
import sys
import json
import time
import shutil
import hashlib
import threading
import tempfile
import inspect
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback
from engine import file_protection as fp_mod
from engine.file_protection import FileProtection


class _FakeQuarantine:
    """轻量隔离管理器替身：把文件移动到隔离目录并记录调用。"""

    def __init__(self, qdir: str):
        self.qdir = qdir
        self.calls = []
        self.unregistered = []
        os.makedirs(qdir, exist_ok=True)

    def quarantine_file(self, path, reason='', malware_name='', **kwargs):
        self.calls.append((path, reason, malware_name))
        try:
            if not os.path.isfile(path):
                return False
            dst = os.path.join(self.qdir, os.path.basename(path) + '.q')
            shutil.move(path, dst)
            return True
        except Exception:
            return False

    def _unregister_soft_quarantine(self, path):
        self.unregistered.append(path)


class TestRansomwareRollback(unittest.TestCase):

    def setUp(self):
        self._old_root = rr._REPO_ROOT
        self.tmp = tempfile.mkdtemp(prefix='psls_rb_')
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        self.protected = os.path.join(self.tmp, 'docs')
        os.makedirs(self.protected, exist_ok=True)
        self.qm = _FakeQuarantine(os.path.join(self.tmp, 'quarantine'))

    def tearDown(self):
        rr._REPO_ROOT = self._old_root
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- 工具 ----

    def _mgr(self, **kwargs):
        kwargs.setdefault('quarantine_manager', self.qm)
        kwargs.setdefault('protected_dirs', [self.protected])
        return RansomwareRollback(**kwargs)

    def _write(self, name: str, data: bytes):
        p = os.path.join(self.protected, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    def _object_count(self) -> int:
        return sum(1 for _ in rr._iter_object_files())

    # ---- 1. 增量快照 ----

    def test_snapshot_incremental_only_changed(self):
        m = self._mgr()
        self._write('a.txt', b'hello')
        self._write('b.txt', b'world')
        r1 = m.snapshot_now('t1')
        self.assertEqual(r1['added'], 2)
        self.assertEqual(self._object_count(), 2)

        # 未修改 → 不新增对象
        r2 = m.snapshot_now('t2')
        self.assertEqual(r2['added'], 0)
        self.assertEqual(r2['unchanged'], 2)
        self.assertEqual(self._object_count(), 2)

        # 改 1 个 → 只增 1 个对象
        time.sleep(0.02)
        self._write('a.txt', b'hello-2')
        r3 = m.snapshot_now('t3')
        self.assertEqual(r3['added'], 1)
        self.assertEqual(self._object_count(), 3)

    # ---- 1b. 单世代快照（启动 / 周期均替换上一世代）----

    def test_startup_snapshot_creates_new_generation(self):
        """新世代语义：启动快照新建世代（不再替换上一世代），旧世代保留。"""
        m = self._mgr()
        p_old = self._write('old.txt', b'OLD-GENERATION')
        r1 = m.snapshot_now('gen1')
        self.assertEqual(r1['added'], 1)
        self.assertEqual(self._object_count(), 1)

        old_sha = hashlib.sha256(b'OLD-GENERATION').hexdigest()
        old_obj = m._object_path(old_sha)
        self.assertTrue(os.path.isfile(old_obj))

        # 旧文件删除 + 新增文件，启动快照新建世代（已保留 <3 → 旧世代仍在）
        os.remove(p_old)
        self._write('new.txt', b'NEW-GENERATION')
        r2 = m.snapshot_now('startup', replace=True)
        self.assertGreater(r2.get('generation_id'), 0)

        # 旧世代未被淘汰（保留 ≤3），其独有对象仍在
        self.assertTrue(os.path.isfile(old_obj))
        new_sha = hashlib.sha256(b'NEW-GENERATION').hexdigest()
        self.assertTrue(os.path.isfile(m._object_path(new_sha)))

        gens = m.get_generations()
        self.assertEqual(len(gens), 2)
        self.assertEqual(gens[0]['file_count'], 1)

        # manifest 最新世代别名只含当前世代条目
        with m._state_lock:
            entries = dict(m._manifest['entries'])
        self.assertEqual(len(entries), 1)
        self.assertEqual(os.path.basename(next(iter(entries))), 'new.txt')

    def test_periodic_snapshot_is_single_generation(self):
        m = self._mgr()
        a = self._write('a.bin', b'AAA')
        m.snapshot_now('gen1')
        sha_a = hashlib.sha256(b'AAA').hexdigest()
        self.assertTrue(os.path.isfile(m._object_path(sha_a)))

        time.sleep(0.02)
        self._write('b.bin', b'BBB')
        m.snapshot_now('periodic', replace=True)

        sha_b = hashlib.sha256(b'BBB').hexdigest()
        self.assertTrue(os.path.isfile(m._object_path(sha_b)))
        # a.bin 未变化仍在保护目录 → 仍属当前世代，应保留
        self.assertTrue(os.path.isfile(m._object_path(sha_a)))

        # 删除 a.bin 后再周期快照 → 上一世代对象（a）被清理，仓库仅剩 b
        os.remove(a)
        m.snapshot_now('periodic', replace=True)
        self.assertFalse(os.path.exists(m._object_path(sha_a)))
        self.assertTrue(os.path.isfile(m._object_path(sha_b)))
        self.assertEqual(self._object_count(), 1)

    # ---- 2. 回滚恢复内容与哈希 ----

    def test_rollback_restores_content_and_hash(self):
        m = self._mgr()
        p = self._write('doc.txt', b'IMPORTANT-CONTENT')
        m.snapshot_now('init')
        expect_hash = hashlib.sha256(b'IMPORTANT-CONTENT').hexdigest()

        self._write('doc.txt', b'ENCRYPTED-GARBAGE')
        res = m.trigger_rollback('unit-test')

        self.assertEqual(res['restored'], 1)
        with open(p, 'rb') as f:
            data = f.read()
        self.assertEqual(data, b'IMPORTANT-CONTENT')
        self.assertEqual(hashlib.sha256(data).hexdigest(), expect_hash)

    # ---- 3. 删除 + 改名（.locked）----

    def test_rollback_detects_deleted_and_renamed(self):
        m = self._mgr()
        p = self._write('x.docx', b'THE-ORIGINAL')
        m.snapshot_now('init')

        os.remove(p)
        locked = p + '.locked'
        with open(locked, 'wb') as f:
            f.write(b'ENCRYPTED')

        res = m.trigger_rollback('unit-test')

        self.assertEqual(res['restored'], 1)
        self.assertTrue(os.path.isfile(p))
        with open(p, 'rb') as f:
            self.assertEqual(f.read(), b'THE-ORIGINAL')
        # 加密残留件被隔离（原位置消失，且隔离管理器被调用）
        self.assertFalse(os.path.exists(locked))
        self.assertTrue(any(c[0] == locked for c in self.qm.calls))

    # ---- 4. 重入守卫 ----

    def test_reentrancy_guard_single_rollback(self):
        m = self._mgr()
        self._write('r.txt', b'BASE')
        m.snapshot_now('init')
        self._write('r.txt', b'CHANGED')

        # 拉长首个回滚的早期阶段，确保两线程确实并发进入
        orig = m._terminate_suspects

        def _slow(paths):
            time.sleep(0.4)
            return orig(paths)
        m._terminate_suspects = _slow

        results = []
        barrier = threading.Barrier(2)

        def _worker():
            barrier.wait()
            results.append(m.trigger_rollback('concurrent'))

        threads = [threading.Thread(target=_worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(m.list_records()), 1)
        self.assertEqual(sum(1 for r in results if r.get('ok')), 1)

    # ---- 5. 超大文件跳过 ----

    def test_trigger_skips_oversize_file(self):
        # 快照时超限 → 不落对象、记 too_large
        m = self._mgr(max_file_bytes=16)
        self._write('big.bin', b'A' * 64)
        r = m.snapshot_now('init')
        self.assertGreaterEqual(r['too_large'], 1)
        self.assertEqual(r['added'], 0)
        self.assertEqual(self._object_count(), 0)

        # 回滚时超限 → 记 skipped / too_large
        os.remove(os.path.join(self.protected, 'big.bin'))  # 清理上一段的超限文件
        m2 = self._mgr(max_file_bytes=1024)
        self._write('big2.bin', b'B' * 64)
        m2.snapshot_now('init')
        m2._max_file_bytes = 16
        self._write('big2.bin', b'C' * 64)
        res = m2.trigger_rollback('unit-test')
        self.assertEqual(res['restored'], 0)
        rec = m2.list_records()[0]
        self.assertEqual(rec['files'][0]['status'], 'skipped')
        self.assertEqual(rec['files'][0]['error'], 'too_large')

    # ---- 6. LRU 容量清理 ----

    def test_lru_eviction_respects_quota(self):
        m = self._mgr(max_repo_bytes=10 ** 9)
        paths = []
        for i in range(4):
            p = self._write(f'f{i}.dat', (f'content-{i}-' * 20).encode())
            paths.append(p)
            m.snapshot_now(f'gen{i}')
            time.sleep(0.02)

        # 配额仅够保留最新的一个对象
        last_size = os.path.getsize(paths[-1])
        m._max_repo_bytes = last_size + 5
        m._enforce_quota()

        self.assertLessEqual(m._repo_usage_bytes(), m._max_repo_bytes)
        with open(paths[-1], 'rb') as f:
            newest_sha = hashlib.sha256(f.read()).hexdigest()
        self.assertTrue(os.path.isfile(m._object_path(newest_sha)))

    # ---- 7. 端到端假勒索 ----

    def test_end_to_end_fake_ransomware(self):
        m = self._mgr()
        fp = FileProtection(quarantine_manager=self.qm)
        fp.on_prewarn = m.prewarn
        fp.on_ransomware_confirmed = (
            lambda info: m.trigger_rollback(
                'ransomware_confirmed', suspect_paths=info.get('files')))

        paths = []
        for i in range(3):
            paths.append(self._write(f'e{i}.txt', f'orig-{i}'.encode()))
        m.snapshot_now('init')

        # 模拟加密（污染内容）
        for i in range(3):
            self._write(f'e{i}.txt', f'enc-{i}'.encode())

        # 直接触发确认勒索链路（避免走 30 文件批量以规避既有锁语义）
        fp._detect_ransomware_pattern(list(paths))

        # 回滚应已由回调触发并复原全部内容
        for i, p in enumerate(paths):
            with open(p, 'rb') as f:
                self.assertEqual(f.read(), f'orig-{i}'.encode())
        self.assertEqual(len(m.list_records()), 1)
        self.assertEqual(m.list_records()[0]['restored'], 3)

    # ---- 7b. 低水位预警接线 ----

    def test_prewarn_callback_fires_at_low_water(self):
        fp = FileProtection()
        fired = []
        fp.on_prewarn = lambda files: fired.append(list(files))
        target = os.path.join(self.protected, 'p.txt')
        for _ in range(fp_mod.PREWARN_THRESHOLD):
            fp._track_modification(target)
        self.assertTrue(fired)
        # 未达勒索阈值（30）前即触发，且判定阈值语义未变
        self.assertLess(fp_mod.PREWARN_THRESHOLD, fp_mod.MASS_MODIFY_THRESHOLD)

    # ---- 8. 不写协议通道 ----

    def test_no_protocol_channel_write(self):
        src = inspect.getsource(rr).lower()
        for token in ('sandbox', 'scan_engine', 'protocol', 'pyqt',
                      'emit_tool_signal', '_add_activity'):
            self.assertNotIn(token, src)

        # 运行一次快照 + 回滚，确认在无任何协议接线时也能自洽工作
        m = self._mgr()
        p = self._write('z.txt', b'data')
        m.snapshot_now('init')
        self._write('z.txt', b'evil')
        res = m.trigger_rollback('unit-test')
        self.assertEqual(res['restored'], 1)
        with open(p, 'rb') as f:
            self.assertEqual(f.read(), b'data')


if __name__ == '__main__':
    unittest.main()