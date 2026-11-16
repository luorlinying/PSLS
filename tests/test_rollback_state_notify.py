# -*- coding: utf-8 -*-
"""回滚中心"世代列表不显示"的回归测试。

根因（实测）：worker 的命令循环是**串行**的，快照/回滚在里面同步跑完才返回，
期间的只读命令（get_state / get_generations）一直排队 → 主进程 10s 超时 →
回滚中心缓存始终为空 → 卡片里看不到任何可回滚的世代。

本测试锁定三件事：
  1. `snapshot_now` / `trigger_rollback` 在 worker 侧**异步受理**（立即返回，不阻塞）；
  2. 快照完成后引擎发出 `snapshot_done` 上报（主进程据此刷新世代列表）；
  3. 主进程收到 `snapshot_done` 会触发一次后台状态刷新。
"""
import os
import sys
import tempfile
import time
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import rollback_worker as rw  # noqa: E402


class _SlowEngine:
    """模拟耗时很长的引擎：任何长任务都 sleep，用来证明命令循环不被阻塞。"""

    def __init__(self, delay=1.5):
        self.delay = delay
        self.snapshot_done = threading.Event()
        self.rollback_done = threading.Event()

    def snapshot_now(self, reason, replace=False):
        time.sleep(self.delay)
        self.snapshot_done.set()
        return {'ok': True, 'reason': reason, 'total': 7}

    def trigger_rollback(self, reason='manual', suspect_paths=None, generation_id=None):
        time.sleep(self.delay)
        self.rollback_done.set()
        return {'ok': True, 'restored': 1}

    # get_state 用到的只读方法
    def get_stats(self):
        return {'snapshots': 1}

    def get_generations(self):
        return [{'generation_id': 1, 'file_count': 7}]

    def list_records(self, n):
        return []

    def get_protected_dirs(self):
        return [r'C:\X']

    def get_snapshot_exts(self):
        return []


class TestWorkerDispatchIsAsync(unittest.TestCase):

    def test_snapshot_dispatch_returns_immediately(self):
        eng = _SlowEngine(delay=1.2)
        t0 = time.perf_counter()
        res = rw._dispatch(eng, 'snapshot_now', {'reason': 'manual'})
        dt = time.perf_counter() - t0
        self.assertTrue(res.get('accepted'))
        self.assertLess(dt, 0.3, f'快照受理耗时 {dt:.2f}s，仍会阻塞命令循环')
        # 受理后仍在后台继续跑
        self.assertTrue(eng.snapshot_done.wait(5.0), '后台快照没有执行')

    def test_readonly_command_not_blocked_by_snapshot(self):
        eng = _SlowEngine(delay=1.2)
        rw._dispatch(eng, 'snapshot_now', {'reason': 'startup'})
        t0 = time.perf_counter()
        st = rw._dispatch(eng, 'get_state', {})
        dt = time.perf_counter() - t0
        self.assertLess(dt, 0.3, f'快照进行中 get_state 耗时 {dt:.2f}s（被阻塞）')
        self.assertEqual(len(st.get('generations') or []), 1)

    def test_rollback_dispatch_returns_immediately(self):
        eng = _SlowEngine(delay=1.2)
        t0 = time.perf_counter()
        res = rw._dispatch(eng, 'trigger_rollback', {'reason': 'manual_confirmed'})
        dt = time.perf_counter() - t0
        self.assertTrue(res.get('accepted'))
        self.assertLess(dt, 0.3, f'回滚受理耗时 {dt:.2f}s')
        self.assertTrue(eng.rollback_done.wait(5.0))


class TestSnapshotNotifiesReport(unittest.TestCase):

    def test_snapshot_emits_snapshot_done_report(self):
        repo = tempfile.mkdtemp(prefix='rbrepo_notify_')
        data = tempfile.mkdtemp(prefix='rbdata_notify_')
        old = os.environ.get('PSLS_ROLLBACK_REPO')
        os.environ['PSLS_ROLLBACK_REPO'] = repo
        try:
            from engine.ransomware_rollback import RansomwareRollback
            with open(os.path.join(data, 'a.txt'), 'w', encoding='utf-8') as f:
                f.write('hello')
            got = []
            m = RansomwareRollback(protected_dirs=[data],
                                   on_report=lambda p: got.append(dict(p or {})))
            m.snapshot_now('startup', replace=True)
            snap = [p for p in got if p.get('action') == 'snapshot_done']
            self.assertTrue(snap, '快照完成后没有上报 snapshot_done')
            self.assertIn('generation_id', snap[-1])
            self.assertIn('total', snap[-1])
        finally:
            if old is None:
                os.environ.pop('PSLS_ROLLBACK_REPO', None)
            else:
                os.environ['PSLS_ROLLBACK_REPO'] = old


class TestBridgeRefreshesOnSnapshotDone(unittest.TestCase):
    """主进程收到 snapshot_done 必须触发后台状态刷新（否则卡片一直空）。"""

    def test_report_triggers_refresh(self):
        import ui.webview.bridge as B

        calls = []

        class Stub:
            def _add_activity(self, *a, **k):
                pass

            def _rollback_refresh_async(self):
                calls.append('refresh')

            def _emit_tool_signal(self, *a, **k):
                pass

            def _request_critical_sound(self):
                pass

            def _close_rollback_progress_win(self):
                pass

        B.PyBridge._on_rollback_report(Stub(), {
            'action': 'snapshot_done', 'reason': 'startup',
            'generation_id': 3, 'total': 12, 'added': 2, 'inherited': 10,
            'failed': 0, 'generations': 3,
        })
        self.assertIn('refresh', calls, '收到 snapshot_done 未触发状态刷新')

    def test_plain_rollback_report_also_refreshes(self):
        import ui.webview.bridge as B

        calls = []

        class Stub:
            def _add_activity(self, *a, **k):
                pass

            def _rollback_refresh_async(self):
                calls.append('refresh')

            def _emit_tool_signal(self, *a, **k):
                pass

            def _request_critical_sound(self):
                pass

            def _close_rollback_progress_win(self):
                pass

        B.PyBridge._on_rollback_report(Stub(), {
            'restored': 2, 'failed': 0, 'skipped': 1, 'reason': 'user_confirmed'})
        self.assertIn('refresh', calls)


if __name__ == '__main__':
    unittest.main()