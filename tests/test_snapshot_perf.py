# -*- coding: utf-8 -*-
"""快照性能优化测试：世代继承 / 并行哈希 / prewarn 增量 / 进度 show 语义 / 后台IO。

覆盖：
  1. 继承：连续两次启动快照（无变化）→ 第 2 次 hashed==0、inherited==总数、entries 不变；
  2. 改一个文件 → 仅该文件被哈希（hashed==1）；
  3. 并行(workers=4) 与 串行(workers=1) 结果完全一致（条目/哈希/统计）；
  4. 淘汰与继承共存：共享对象不被误删，保留世代仍可回滚；
  5. prewarn 不再全量 purge（replace=False）；
  6. 进度 show：manual/startup=True；periodic/prewarn=False；
  7. 后台 IO 优先级为尽力而为（不可用不影响快照）。
"""
import os
import sys
import shutil
import hashlib
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback


class TestSnapshotPerf(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_perf_')
        self.protected = os.path.join(self.tmp, 'docs')
        os.makedirs(self.protected, exist_ok=True)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mgr(self, workers=1, **kw):
        m = RansomwareRollback(protected_dirs=[self.protected], **kw)
        m._snapshot_workers = workers
        return m

    def _write(self, name, data):
        p = os.path.join(self.protected, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    # ---- 1/2. 继承与增量 ----

    def test_inheritance_no_rehash_on_second_startup(self):
        m = self._mgr()
        for i in range(5):
            self._write(f'f{i}.txt', f'content-{i}'.encode() * 50)
        r1 = m.snapshot_now('startup', replace=True)
        self.assertEqual(r1['hashed'], 5)
        self.assertEqual(r1['inherited'], 0)
        with m._state_lock:
            entries1 = dict(m._generations[0]['entries'])

        r2 = m.snapshot_now('startup', replace=True)
        self.assertEqual(r2['hashed'], 0, '未变文件不得重算哈希')
        self.assertEqual(r2['inherited'], 5, '未变文件应全部继承')
        self.assertEqual(r2['total'], 5)
        with m._state_lock:
            entries2 = dict(m._generations[0]['entries'])
        self.assertEqual(set(entries1.keys()), set(entries2.keys()))
        for k in entries1:
            self.assertEqual(entries1[k]['hash'], entries2[k]['hash'])

    def test_only_changed_file_is_hashed(self):
        m = self._mgr()
        for i in range(5):
            self._write(f'f{i}.txt', b'A' * 100)
        m.snapshot_now('startup', replace=True)
        self._write('f2.txt', b'CHANGED-' * 40)
        r = m.snapshot_now('startup', replace=True)
        self.assertEqual(r['hashed'], 1)
        self.assertEqual(r['added'], 1)
        self.assertEqual(r['inherited'], 4)

    # ---- 3. 并行 == 串行 ----

    def test_parallel_matches_serial(self):
        # 两套独立仓库 + 目录，分别用 workers=4 / workers=1 跑冷启动
        prot2 = os.path.join(self.tmp, 'docs2')
        os.makedirs(prot2, exist_ok=True)
        for i in range(60):
            data = (f'file-{i}-' * (i + 1)).encode()
            with open(os.path.join(self.protected, f'p{i}.dat'), 'wb') as f:
                f.write(data)
            with open(os.path.join(prot2, f'p{i}.dat'), 'wb') as f:
                f.write(data)

        old_root = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo_par')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        mpar = RansomwareRollback(protected_dirs=[self.protected])
        mpar._snapshot_workers = 4
        rpar = mpar.snapshot_now('startup', replace=True)

        rr._REPO_ROOT = os.path.join(self.tmp, 'repo_ser')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        mser = RansomwareRollback(protected_dirs=[prot2])
        mser._snapshot_workers = 1
        rser = mser.snapshot_now('startup', replace=True)

        rr._REPO_ROOT = old_root

        for key in ('added', 'unchanged', 'failed', 'too_large', 'total',
                    'hashed', 'scanned'):
            self.assertEqual(rpar[key], rser[key], f'{key} 不一致')
        with mpar._state_lock:
            e1 = {os.path.basename(k): v['hash'] for k, v in mpar._generations[0]['entries'].items()}
        with mser._state_lock:
            e2 = {os.path.basename(k): v['hash'] for k, v in mser._generations[0]['entries'].items()}
        self.assertEqual(e1, e2, '并行与串行条目/哈希必须一致')

    # ---- 4. 淘汰与继承共存 ----

    def test_eviction_with_inheritance_keeps_shared_object(self):
        m = self._mgr()
        shared = self._write('shared.txt', b'SHARED-ORIG')
        only1 = self._write('only1.txt', b'ONLY1')
        m.snapshot_now('startup', replace=True)   # gen1
        os.remove(only1)
        m.snapshot_now('startup', replace=True)   # gen2（继承 shared，剪除 only1）
        m.snapshot_now('startup', replace=True)   # gen3
        m.snapshot_now('startup', replace=True)   # gen4 → 淘汰 gen1

        sha_shared = hashlib.sha256(b'SHARED-ORIG').hexdigest()
        self.assertTrue(os.path.isfile(m._object_path(sha_shared)),
                        '共享对象绝不能被误删')
        # 用最新世代回滚
        with open(shared, 'wb') as f:
            f.write(b'ENCRYPTED')
        res = m.trigger_rollback('manual_confirmed')
        self.assertGreaterEqual(res['restored'], 1)
        with open(shared, 'rb') as f:
            self.assertEqual(f.read(), b'SHARED-ORIG')

    # ---- 5. prewarn 增量 ----

    def test_prewarn_uses_incremental_not_purge(self):
        m = self._mgr()
        calls = []
        orig = m.snapshot_now

        def _fake(reason='manual', replace=False):
            calls.append((reason, replace))
            return {'ok': True}
        m.snapshot_now = _fake
        m.prewarn()
        self.assertTrue(calls)
        self.assertEqual(calls[0], ('prewarn', False),
                         'prewarn 必须增量(replace=False)，不得全量 purge')

    # ---- 6. 进度 show 语义 ----

    def test_progress_show_flags(self):
        ev = []
        m = self._mgr()
        m._on_progress = lambda p: ev.append(p)
        self._write('a.txt', b'A')

        ev.clear()
        m.snapshot_now('manual')
        self.assertTrue(ev and all(e.get('show') for e in ev),
                        '手动快照应弹进度窗口')

        ev.clear()
        m.snapshot_now('periodic', replace=True)
        self.assertTrue(ev and all(e.get('show') is False for e in ev),
                        '周期快照不得弹窗')

        ev.clear()
        m.snapshot_now('prewarn', replace=False)
        self.assertTrue(ev and all(e.get('show') is False for e in ev),
                        'prewarn 快照不得弹窗')

        ev.clear()
        m.snapshot_now('startup', replace=True)
        self.assertTrue(ev and all(e.get('show') for e in ev),
                        '启动快照应弹进度窗口')

    # ---- 7. 后台 IO 尽力而为 ----

    def test_background_io_best_effort(self):
        m = self._mgr()
        self._write('b.txt', b'B')
        # 进入/退出后台 IO 优先级不得抛异常，且不影响快照
        with m._background_io():
            r = m.snapshot_now('startup', replace=True)
        self.assertGreaterEqual(r['added'], 1)


if __name__ == '__main__':
    unittest.main()