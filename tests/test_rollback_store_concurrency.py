# -*- coding: utf-8 -*-
"""回滚入仓并发修复回归：并发同 sha、失败路径、重叠目录、编码、argtypes。

覆盖（对应本次根因）：
  1. 【核心】8 线程 × 同一 sha × 多次 `_store_object` → 零失败、无 tmp 残留、
     对象内容哈希正确（修复前因共享固定 tmp 而大量失败）；
  2. 失败路径：`stored=False` 时不登记有效哈希条目、计入 failed；
  3. 重叠受保护目录（父 + 其子目录）→ 同一文件只扫一次；
  4. 中文进度文案 UTF-8 往返无损（worker 帧 payload 级）；
  5. `_set_bg_io` 已声明 argtypes/restype 且调用不抛异常。
"""
import os
import sys
import time
import shutil
import hashlib
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback


class TestStoreObjectConcurrency(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_cc_')
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        # 造多个"同内容"的源文件（模拟重复文件/重叠目录）
        self.srcs = []
        data = b'SHARED-CONTENT-' * 1000
        self.sha = hashlib.sha256(data).hexdigest()
        for i in range(8):
            p = os.path.join(self.tmp, f'src{i}.bin')
            with open(p, 'wb') as f:
                f.write(data)
            self.srcs.append(p)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_concurrent_same_sha_zero_failures(self):
        m = RansomwareRollback()
        results = []
        rlock = threading.Lock()

        def _run(src):
            for _ in range(6):     # 8 线程 × 6 次 = 48 次并发调用
                ok = m._store_object(src, self.sha)
                with rlock:
                    results.append(ok)

        threads = [threading.Thread(target=_run, args=(self.srcs[i % 8],))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 48)
        self.assertTrue(all(results), f'存在失败调用: {results.count(False)}/{len(results)}')
        # 对象内容哈希正确
        obj = m._object_path(self.sha)
        self.assertTrue(os.path.isfile(obj))
        with open(obj, 'rb') as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), self.sha)
        # 无 tmp 残留（任何 .tmp 都不应存在）
        leftovers = []
        for root, _dirs, files in os.walk(rr._REPO_ROOT):
            for fn in files:
                if fn.endswith('.tmp'):
                    leftovers.append(os.path.join(root, fn))
        self.assertEqual(leftovers, [], f'存在 tmp 残留: {leftovers}')
        # 仅真正新建一次 → objects_stored == 1
        self.assertEqual(m.get_stats()['objects_stored'], 1)

    def test_object_lock_serializes_same_sha(self):
        m = RansomwareRollback()
        lk1 = m._object_lock('a' * 64)
        lk2 = m._object_lock('a' * 64)
        self.assertIs(lk1, lk2)


class TestFailurePathAndDedup(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_fp_')
        self.docs = os.path.join(self.tmp, 'docs')
        os.makedirs(self.docs)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_store_failure_not_registered_as_valid_entry(self):
        m = RansomwareRollback(protected_dirs=[self.docs])
        with open(os.path.join(self.docs, 'a.txt'), 'wb') as f:
            f.write(b'DATA-A')
        # 让入仓恒失败（快照入仓走单次打开的 _ingest_file：返回 write_failed 阶段）
        m._ingest_file = lambda src, old_hash=None, attempts=3: (
            None, 'write_failed', 0)
        r = m.snapshot_now('startup', replace=True)
        self.assertEqual(r['failed'], 1, '写入失败必须计入 failed')
        self.assertEqual(r['added'], 0)
        self.assertEqual(r['ingested'], 0)
        self.assertEqual(r['attempted'], 1, '结果应给出"尝试"文件数')
        with m._state_lock:
            entries = dict(m._generations[0]['entries'])
        self.assertNotIn(os.path.abspath(os.path.join(self.docs, 'a.txt')).lower(),
                         entries, '写入失败不得登记为可回滚条目')

    def test_overlapping_dirs_scanned_once(self):
        # 父目录 + 其子目录都设为受保护 → 同一文件只扫一次
        sub = os.path.join(self.docs, 'PSLS')
        os.makedirs(sub, exist_ok=True)
        with open(os.path.join(sub, 'x.jpg'), 'wb') as f:
            f.write(b'JPG-DATA')
        m = RansomwareRollback(protected_dirs=[self.docs, sub])
        r = m.snapshot_now('startup', replace=True)
        self.assertEqual(r['scanned'], 1, '重叠目录不得重复扫描')
        self.assertEqual(r['total'], 1)
        self.assertEqual(r['failed'], 0)
        self.assertEqual(m._dedup_dirs([self.docs, sub]), [self.docs])

    def test_dedup_dirs_keeps_siblings(self):
        d1 = os.path.join(self.tmp, 'Desktop')
        d2 = os.path.join(self.tmp, 'Desktop2')
        os.makedirs(d1, exist_ok=True)
        os.makedirs(d2, exist_ok=True)
        out = RansomwareRollback._dedup_dirs([d1, d2, d1])
        self.assertEqual(len(out), 2, '兄弟目录/重复项应保留 2 个，不得误判包含')


class TestEncodingAndBgIO(unittest.TestCase):

    def test_progress_payload_roundtrip_chinese(self):
        """中文 stage/text 经 JSON 编码往返无损（模拟 worker→主进程 NDJSON）。"""
        import json
        payload = {'stage': '扫描目录中', 'percent': 30,
                   'text': '扫描中（已扫描 100 个文件）', 'show': False}
        wire = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        back = json.loads(wire.decode('utf-8'))
        self.assertEqual(back['stage'], '扫描目录中')
        self.assertEqual(back['text'], '扫描中（已扫描 100 个文件）')

    def test_set_bg_io_declares_argtypes_and_no_raise(self):
        m = RansomwareRollback()
        # 非 Windows 直接返回 False；Windows 下调用不得抛异常
        self.assertIn(m._set_bg_io(True), (True, False))
        with m._background_io():
            pass
        # 源码契约：声明了 argtypes/restype（64 位句柄截断坑）
        with open(os.path.join(ROOT, 'engine', 'ransomware_rollback.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        self.assertIn('SetThreadPriority.argtypes', src)
        self.assertIn('SetThreadPriority.restype', src)


if __name__ == '__main__':
    unittest.main()