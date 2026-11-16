# -*- coding: utf-8 -*-
"""
勒索触发链路修复单测

覆盖三处已确诊根因：
  1. _find_modifying_process 绝不返回 PSLS 自身（及子孙）PID；
  2. _detect_ransomware_pattern 先发"是否回滚"询问，再把慢操作放后台；
  3. prewarn 在快照进行中被拒时不丢弃，置 pending 并在之后补做。

不依赖真实 psutil/快照：psutil 用轻量替身 monkeypatch，快照用替身函数。
"""
import os
import sys
import time
import types
import shutil
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback
from engine.file_protection import FileProtection


# ---- psutil 轻量替身 ----

class _FakeProc:
    def __init__(self, pid, name='fake.exe', open_files=None, info=None):
        self.pid = pid
        self._name = name
        self._open = list(open_files or [])
        self.info = info if info is not None else {'pid': pid, 'name': name}

    def open_files(self):
        return self._open

    def io_counters(self):
        return types.SimpleNamespace(write_bytes=0)

    def name(self):
        return self._name

    def children(self, recursive=False):
        return []

    def parent(self):
        return None


class _FakePSUtil:
    AccessDenied = type('AccessDenied', (Exception,), {})
    NoSuchProcess = type('NoSuchProcess', (Exception,), {})

    def __init__(self, procs):
        self._procs = list(procs)

    def process_iter(self, attrs=None):
        return list(self._procs)

    def Process(self, pid):
        return _FakeProc(pid)


class _FakeQuarantine:
    def __init__(self, order):
        self.order = order
        self.calls = []

    def quarantine_file(self, path, reason='', malware_name='', **kwargs):
        self.order.append('quarantine')
        self.calls.append((path, reason, malware_name))
        return True


class TestRansomwareTriggerChain(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_chain_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mkfile(self, name='f.txt', data=b'DATA'):
        p = os.path.join(self.tmp, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    # ---- 1. 归因绝不返回自身 ----

    def test_find_modifying_process_never_returns_self(self):
        target = self._mkfile('victim.txt')
        target_lower = os.path.abspath(target).lower()
        hold = [types.SimpleNamespace(path=target_lower)]

        # 只有自身持有句柄；另有一个名字含 psls 的进程也持有句柄
        self_proc = _FakeProc(os.getpid(), name='PSLS.exe', open_files=hold)
        psls_helper = _FakeProc(999999, name='psls_helper.exe', open_files=hold)
        normal_proc = _FakeProc(1234, name='explorer.exe', open_files=[])
        fake = _FakePSUtil([self_proc, psls_helper, normal_proc])

        fp = FileProtection()
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            result = fp._find_modifying_process([target])

        # 必须返回 None，且绝不返回自身 PID
        self.assertIsNone(result)
        self.assertNotEqual(result, os.getpid())

    # ---- 2. 询问先于慢操作 ----

    def test_confirm_callback_emitted_before_slow_work(self):
        target = self._mkfile('r.txt')
        order = []
        qm = _FakeQuarantine(order)

        def _slow_find(files):
            order.append('find')
            time.sleep(0.1)
            return None

        fp = FileProtection(
            quarantine_manager=qm,
            on_ransomware_kill=lambda pid: order.append('kill'),
        )
        fp.on_ransomware_confirmed = lambda info: order.append('confirm')
        fp._find_modifying_process = _slow_find

        fp._detect_ransomware_pattern([target])

        # 询问必须在调用返回时已发出（早于后台的 find/quarantine）
        self.assertIn('confirm', order)

        # 等待后台响应线程完成
        deadline = time.time() + 3
        while time.time() < deadline and 'quarantine' not in order:
            time.sleep(0.02)

        self.assertIn('find', order)
        self.assertIn('quarantine', order)
        self.assertLess(order.index('confirm'), order.index('find'))
        self.assertLess(order.index('confirm'), order.index('quarantine'))

    # ---- 3. prewarn 被拒不丢弃 + 补做 ----

    def test_prewarn_not_dropped_when_snapshot_in_progress(self):
        old_root = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        try:
            m = RansomwareRollback(protected_dirs=[self.tmp])

            calls = []

            def _fake_snapshot(reason='manual', replace=False):
                calls.append(reason)
                if len(calls) == 1:
                    return {'ok': False, 'reason': 'snapshot_in_progress'}
                return {'ok': True, 'reason': reason}

            m.snapshot_now = _fake_snapshot

            # 首次触发（模拟快照进行中）→ 被拒但置 pending，且不消费冷却
            self.assertFalse(m.prewarn())
            self.assertTrue(m._pending_prewarn)
            self.assertEqual(m._last_prewarn, 0.0)

            # worker 单步补做 → pending 被消费，且补做确实发起
            m._consume_pending_prewarn()
            self.assertFalse(m._pending_prewarn)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[1], 'prewarn')
        finally:
            rr._REPO_ROOT = old_root


if __name__ == '__main__':
    unittest.main()