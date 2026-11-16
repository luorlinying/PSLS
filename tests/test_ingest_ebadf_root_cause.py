# -*- coding: utf-8 -*-
"""EBADF（Bad file descriptor）根因回归 + 入仓计数可读性。

背景（用户日志）：`rollback_worker: 写入对象失败 <Desktop\\*.JPG>: [Errno 9]
Bad file descriptor`，877 条；桌面 JPG；无勒索在跑；2026-10-05（并行化之前）
同样出现 → 是**系统性**问题，非并行引入。

根因（两处，互相叠加）：
  A. `realtime_monitor` 用 `FILE_SHARE_NONE(0)` 独占打开文件（连"读取"都拒绝）：
     会同时挡住我们自己的快照入仓/自保护备份读取同一文件。
  B. 入仓路径对同一源文件**开两次句柄**（先 `_sha256_file` 再 `_copy_with_retry`），
     任一时刻被外部干扰即在读取中途 EBADF。

修复：A 改为 `FILE_SHARE_READ`（仍拒绝写/删，保护意图不变）；
      B 改为**单次打开**（`_ingest_file` 边读边算哈希边入仓）。
"""
import os
import sys
import errno
import shutil
import hashlib
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback


class TestSingleOpenIngest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_ebadf_')
        self.docs = os.path.join(self.tmp, 'docs')
        os.makedirs(self.docs)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, data):
        p = os.path.join(self.docs, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    # ---- 最小复现：第 2 次打开失败 = 旧实现 EBADF 场景 ----

    def test_minimal_repro_double_open_fails_single_open_succeeds(self):
        """最小复现：源文件只允许"被读一次"（第二次打开抛 EBADF）。

        旧实现（两次打开：哈希 + 拷贝）必然失败；新实现（单次打开）成功。
        """
        p = self._write('photo.jpg', b'JPGDATA' * 1000)
        real_open = open
        calls = {'n': 0}
        lock = threading.Lock()

        def _flaky_open(path, *a, **k):
            # 只对源文件的"读"模式第 2 次调用注入 EBADF（模拟句柄被外部关闭）
            if os.path.abspath(str(path)) == os.path.abspath(p) and 'b' in str(a[0] if a else k.get('mode', 'r')):
                with lock:
                    calls['n'] += 1
                    n = calls['n']
                if n >= 2:
                    raise OSError(errno.EBADF, 'Bad file descriptor')
            return real_open(path, *a, **k)

        m = RansomwareRollback(protected_dirs=[self.docs])
        import builtins
        with mock.patch.object(builtins, 'open', _flaky_open):
            sha, stage, nbytes = m._ingest_file(p)
        self.assertEqual(stage, 'ok', f'单次打开实现应成功，实际 {stage}')
        self.assertEqual(sha, hashlib.sha256(b'JPGDATA' * 1000).hexdigest())
        self.assertGreater(nbytes, 0)
        self.assertTrue(os.path.isfile(m._object_path(sha)))

    def test_unreadable_counted_separately_from_failed(self):
        """源文件始终不可读 → 计 unreadable（非 failed），且结果给出尝试/纳入。"""
        p = self._write('locked.jpg', b'X' * 500)
        m = RansomwareRollback(protected_dirs=[self.docs])
        m._ingest_file = lambda src, old_hash=None, attempts=3: (
            None, 'unreadable', 0)
        r = m.snapshot_now('startup', replace=True)
        self.assertEqual(r['unreadable'], 1)
        self.assertEqual(r['failed'], 0, '并发不可读不得计入真失败')
        self.assertEqual(r['attempted'], 1)
        self.assertEqual(r['ingested'], 0)
        self.assertEqual(r['total'], 0)
        # 世代卡片也要能看到"尝试/纳入/不可读"，避免只显示 0 个文件误导
        gens = m.get_generations()
        self.assertEqual(gens[0]['attempted'], 1)
        self.assertEqual(gens[0]['unreadable'], 1)
        self.assertEqual(gens[0]['ingested'], 0)

    def test_normal_snapshot_reports_attempted_and_ingested(self):
        for i in range(3):
            self._write(f'f{i}.jpg', b'D' * 300)
        m = RansomwareRollback(protected_dirs=[self.docs])
        r = m.snapshot_now('startup', replace=True)
        self.assertEqual(r['attempted'], 3)
        self.assertEqual(r['ingested'], 3)
        self.assertEqual(r['failed'], 0)
        self.assertEqual(r['unreadable'], 0)


class TestConcurrentLockerDoesNotBreakIngest(unittest.TestCase):
    """并发"实时保护的独占占用" + "快照入仓" 不再互相干扰。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_lock_')
        self.docs = os.path.join(self.tmp, 'docs')
        os.makedirs(self.docs)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        self.files = []
        for i in range(20):
            p = os.path.join(self.docs, f'vm{i}.jpg')
            with open(p, 'wb') as f:
                f.write(b'J' * 4096)
            self.files.append(p)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_share_read_lock_coexists_with_ingest(self):
        """用与 realtime_monitor 相同的共享模式（FILE_SHARE_READ）持锁 + 并发入仓。"""
        if sys.platform != 'win32':
            self.skipTest('Windows 专属共享语义')
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
        k32.CreateFileW.restype = ctypes.c_void_p
        CREATE = k32.CreateFileW
        hold = []
        for p in self.files:      # 独占"写入"但允许读取（修复后的语义）
            h = CREATE(p, 0x80000000, 0x00000001, None, 3, 0x80, None)
            if h and h != ctypes.c_void_p(-1).value:
                hold.append(h)
        try:
            m = RansomwareRollback(protected_dirs=[self.docs])
            r = m.snapshot_now('startup', replace=True)
            self.assertEqual(r['unreadable'], 0, '允许只读共享后不应不可读')
            self.assertEqual(r['failed'], 0)
            self.assertEqual(r['ingested'], len(self.files))
        finally:
            for h in hold:
                try:
                    k32.CloseHandle(h)
                except Exception:
                    pass


class TestFdOwnership(unittest.TestCase):
    """断言入仓不会关闭非自己打开的 fd。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_fd_')
        self.docs = os.path.join(self.tmp, 'docs')
        os.makedirs(self.docs)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ingest_does_not_close_foreign_fd(self):
        p = os.path.join(self.docs, 'a.bin')
        with open(p, 'wb') as f:
            f.write(b'B' * 2048)
        # 另开一个"无关"的 fd 并持有；断言入仓不会把它关掉
        foreign_fd = os.open(os.devnull, os.O_RDONLY)
        closed = []
        real_close = os.close

        def _spy_close(fd):
            closed.append(int(fd))
            return real_close(fd)

        m = RansomwareRollback(protected_dirs=[self.docs])
        with mock.patch.object(rr.os, 'close', _spy_close, create=True):
            r = m.snapshot_now('startup', replace=True)
        self.assertEqual(r['failed'], 0)
        self.assertNotIn(foreign_fd, closed, '不得关闭非自己打开的 fd')
        # 无关 fd 仍然可用
        try:
            os.read(foreign_fd, 1)
        finally:
            os.close(foreign_fd)


if __name__ == '__main__':
    unittest.main()