# -*- coding: utf-8 -*-
"""回滚增强：清场（终止非系统进程）+ 进度窗口 + 询问弹窗 10s/蓝问号 + 调试项。

覆盖：
  1. 清场保护集：Windows 关键进程 / PID 0,4 / PSLS 自身与祖先链 / psls·mlworker
     名字进程**不终止**；普通进程与 explorer.exe **被终止**；
  2. 清场开关关闭、引擎未运行时不清场；
  3. 单个进程 terminate 抛异常不影响其余终止；
  4. 询问弹窗超时 10s + 蓝色问号（源码/常量/配色断言）；
  5. 进度窗口阶段推进与结束关闭（Qt 不可用则跳过）；
  6. 调试选项新增 rollback_ask / rollback_progress（两套主题都有调试容器）。
"""
import os
import re
import sys
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.ransomware_rollback import RansomwareRollback


class _FakeProc:
    def __init__(self, pid, name, fail=False):
        self.pid = pid
        self.info = {'pid': pid, 'name': name}
        self._name = name
        self._fail = fail
        self.terminated = False
        self.killed = False

    def terminate(self):
        if self._fail:
            raise OSError('access denied (demo)')
        self.terminated = True

    def kill(self):
        self.killed = True

    def children(self, recursive=False):
        return []

    def parent(self):
        return None


class _FakePSUtil:
    """psutil 替身：进程表 + Process() 祖先链。"""

    AccessDenied = type('AccessDenied', (Exception,), {})
    NoSuchProcess = type('NoSuchProcess', (Exception,), {})

    def __init__(self, procs):
        self._procs = procs

    def process_iter(self, attrs=None):
        return list(self._procs)

    def Process(self, pid):
        # 模拟祖先链：当前进程的父进程为 PID 111（宿主 python/终端）
        parent = types.SimpleNamespace(pid=111, parent=lambda: None)
        me = types.SimpleNamespace(
            pid=pid, children=lambda recursive=False: [],
            parent=lambda: parent)
        return me

    def wait_procs(self, procs, timeout=1.0):
        # 简化：terminate 未失败者视为已退出
        gone, alive = [], []
        for p in procs:
            if p.terminated or p.killed:
                gone.append(p)
            else:
                alive.append(p)
        return gone, alive


class TestKillAllBeforeRestore(unittest.TestCase):

    def _engine(self, running=True, enabled=True):
        m = RansomwareRollback()
        m._running = running
        m._kill_all_before_restore = enabled
        return m

    def _table(self):
        return [
            _FakeProc(4, 'System'),
            _FakeProc(600, 'svchost.exe'),
            _FakeProc(620, 'lsass.exe'),
            _FakeProc(640, 'csrss.exe'),
            _FakeProc(700, 'dwm.exe'),
            _FakeProc(9000, 'PSLS.exe'),
            _FakeProc(9001, 'MLWorker.exe'),
            _FakeProc(111, 'python.exe'),          # 祖先链（宿主）
            _FakeProc(5000, 'notepad.exe'),
            _FakeProc(5001, 'chrome.exe'),
            _FakeProc(5002, 'explorer.exe'),
        ]

    def test_protected_never_killed_and_others_killed(self):
        m = self._engine()
        fake = _FakePSUtil(self._table())
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            stat = m._kill_all_non_system('manual_confirmed')   # 用户确认路径
        killed = [n.lower() for n in stat['killed']]
        # 保护：关键系统进程 + psls/mlworker + 祖先 python
        for name in ('system', 'svchost.exe', 'lsass.exe', 'csrss.exe',
                     'dwm.exe', 'psls.exe', 'mlworker.exe', 'python.exe'):
            self.assertNotIn(name, killed, f'{name} 必须被保护')
        # 终止：普通进程 + explorer（用户字面要求"非系统即终止"）
        self.assertIn('notepad.exe', killed)
        self.assertIn('chrome.exe', killed)
        self.assertIn('explorer.exe', killed)
        self.assertGreater(stat['protected'], 0)

    def test_disabled_or_not_running_skips(self):
        m = self._engine(enabled=False)
        fake = _FakePSUtil(self._table())
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            stat = m._kill_all_non_system('manual_confirmed')
        self.assertEqual(stat['killed'], [])
        self.assertFalse(any(p.terminated for p in fake._procs))

        m2 = self._engine(running=False)
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            stat2 = m2._kill_all_non_system('manual_confirmed')
        self.assertEqual(stat2['killed'], [])
        self.assertFalse(any(p.terminated for p in fake._procs))

    def test_unconfirmed_reason_never_kills(self):
        """安全闸门：非用户确认路径（误报/自动）绝不触发清场。"""
        m = self._engine()          # 引擎运行中
        fake = _FakePSUtil(self._table())
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            stat = m._kill_all_non_system('auto_detect')   # 自动/误报路径
        self.assertEqual(stat['killed'], [], '误报路径不得终止任何进程')
        self.assertIn('unconfirmed_reason', stat.get('skipped_reason', ''))
        self.assertFalse(any(p.terminated for p in fake._procs))
        # 审计日志应记录"清场跳过"
        self.assertTrue(any('清场跳过' in e.get('action', '')
                            for e in m.get_audit_log()))

    def test_protected_apps_never_killed(self):
        """方案 B：第三方（VMware / QQ / 微信…）**同样会被终止**（不再跳过第三方）。

        注意：本条仅针对"进程终止"；第三方**文件**保护（`_is_protected_app_path`
        用于隔离残留/回滚写回）保持不变，见 tests/test_self_dir_exclusion_and_emergency.py。
        """
        table = self._table()
        table += [_FakeProc(8001, 'vmware-vmx.exe'),
                  _FakeProc(8002, 'vmnat.exe'),
                  _FakeProc(8003, 'vmnetdhcp.exe'),
                  _FakeProc(8004, 'vmware-authd.exe'),
                  _FakeProc(8005, 'QQ.exe'),
                  _FakeProc(8006, 'Tim.exe'),
                  _FakeProc(8007, 'WeChat.exe'),
                  _FakeProc(8008, 'vmware.exe')]
        m = self._engine()
        fake = _FakePSUtil(table)
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            stat = m._kill_all_non_system('manual_confirmed')
        killed = [n.lower() for n in stat['killed']]
        for name in ('vmware-vmx.exe', 'vmnat.exe', 'vmnetdhcp.exe',
                     'vmware-authd.exe', 'qq.exe', 'tim.exe',
                     'wechat.exe', 'vmware.exe'):
            self.assertIn(name, killed, f'{name} 应被终止（方案 B 不再跳过第三方）')
        # 系统关键进程仍必须受保护（保护集不放松）
        for name in ('svchost.exe', 'lsass.exe', 'csrss.exe'):
            self.assertNotIn(name, killed, f'{name} 必须受保护（系统关键进程）')
        # 清场必须有审计日志（可回溯/定责）
        self.assertTrue(any('清场终止' in e.get('action', '')
                            for e in m.get_audit_log()))

    def test_single_failure_does_not_stop_others(self):
        m = self._engine()
        table = self._table()
        table.append(_FakeProc(7777, 'locked.exe', fail=True))
        fake = _FakePSUtil(table)
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            stat = m._kill_all_non_system('user_confirmed')
        killed = [n.lower() for n in stat['killed']]
        self.assertIn('notepad.exe', killed)
        self.assertIn('explorer.exe', killed)
        self.assertTrue(any('locked.exe' in n.lower() for n in stat['failed']))

    def test_toggle_api(self):
        m = RansomwareRollback()
        self.assertTrue(m.get_kill_all_before_restore())   # 默认开启
        m.set_kill_all_before_restore(False)
        self.assertFalse(m.get_kill_all_before_restore())


class TestRollbackPopupAndWindow(unittest.TestCase):

    def test_release_window_default_timeout_still_3(self):
        import ui.webview.sandbox_analysis_window as w
        self.assertEqual(w.SandboxReleaseWindow._TIMEOUT_SEC, 3)

    def test_question_icon_and_blue_palette(self):
        import ui.webview.sandbox_analysis_window as w
        self.assertTrue(hasattr(w._BaseSandboxWindow, '_draw_question_icon'))
        w._apply_theme_palette()
        self.assertGreater(w._C_BLUE.blue(), w._C_BLUE.red())
        self.assertGreater(w._C_BLUE.blue(), w._C_BLUE.green())

    def test_bridge_uses_10s_and_question_icon(self):
        with open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        self.assertGreaterEqual(src.count('timeout_sec=10'), 2)
        self.assertGreaterEqual(src.count("icon_kind='question'"), 2)
        self.assertIn('rollbackProgressUpdated', src)
        self.assertIn('RollbackProgressWindow', src)
        for token in ('rollback_ask', 'rollback_progress'):
            self.assertIn(token, src)

    def test_progress_window_lifecycle(self):
        try:
            os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
            from PyQt5.QtWidgets import QApplication
            app = QApplication.instance() or QApplication([])
        except Exception as e:
            self.skipTest(f'Qt 不可用: {e}')
        import ui.webview.sandbox_analysis_window as w
        win = w.RollbackProgressWindow('回滚')
        closed = []
        win.closed.connect(lambda: closed.append(True))
        win.set_progress(10, '清场')
        self.assertEqual(win._progress, 10)
        self.assertEqual(win._stage, '清场')
        win.set_progress(80, '写回')
        self.assertEqual(win._progress, 80)
        win.show()
        win.start()
        win.finish('完成')
        self.assertTrue(win._finished)
        self.assertEqual(win._progress, 100)
        # 关闭后信号已发出
        self.assertTrue(closed)

    def test_debug_popups_include_rollback(self):
        import ui.webview.bridge as bmod
        kinds = [k for k, _ in bmod.PyBridge._DEBUG_POPUPS]
        self.assertIn('rollback_ask', kinds)
        self.assertIn('rollback_progress', kinds)

    def test_both_themes_have_debug_container(self):
        for name in ('index.html', 'terminal.html'):
            with open(os.path.join(ROOT, 'ui', 'webview', name),
                      'r', encoding='utf-8') as f:
                src = f.read()
            self.assertIn('id="debug-popup-list"', src, name)
            self.assertEqual(len(re.findall(r'class="tool-card', src)), 8, name)


class TestRollbackProgressSequence(unittest.TestCase):

    def test_engine_emits_stage_sequence(self):
        import tempfile
        import shutil
        import engine.ransomware_rollback as rr
        tmp = tempfile.mkdtemp(prefix='psls_prog_')
        old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        try:
            events = []
            m = RansomwareRollback(protected_dirs=[tmp],
                                   on_progress=lambda p: events.append(p))
            with open(os.path.join(tmp, 'a.txt'), 'wb') as f:
                f.write(b'ORIG')
            m.snapshot_now('startup', replace=True)
            with open(os.path.join(tmp, 'a.txt'), 'wb') as f:
                f.write(b'ENCRYPTED')
            events.clear()   # 只统计回滚阶段（快照阶段的进度另有测试）
            m.trigger_rollback('manual_confirmed')
            stages = [e['stage'] for e in events]
            self.assertTrue(any('清场' in s for s in stages), stages)
            self.assertTrue(any('比对' in s for s in stages), stages)
            self.assertIn('完成', stages)
            self.assertEqual(events[-1]['percent'], 100)
            # 进度非递减
            pcts = [e['percent'] for e in events]
            self.assertEqual(pcts, sorted(pcts), pcts)
        finally:
            rr._REPO_ROOT = old
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()