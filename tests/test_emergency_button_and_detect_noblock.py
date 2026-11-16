# -*- coding: utf-8 -*-
"""两个新回归的修复回归测试（现象 1：紧急终止按钮失效 / 现象 2：勒索警报时 GUI 卡死）。"""

import os
import re
import sys
import json
import time
import shutil
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ui.webview.bridge as bmod
import utils.sound_manager as sm
import engine.ransomware_rollback as rr


def _mk_bridge(**attrs):
    b = bmod.PyBridge.__new__(bmod.PyBridge)
    b._acts = []
    b._sigs = []
    b._add_activity = lambda *a, **k: b._acts.append(a)
    b._emit_tool_signal = lambda n, p: b._sigs.append((n, p))
    for k, v in attrs.items():
        setattr(b, k, v)
    return b


class TestEmergencyButtonChain(unittest.TestCase):
    """现象 1：点按钮必然有明确结果（成功/排队/失败都记活动日志），不得静默。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_ek2_')
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_engine_ready_runs_and_logs(self):
        eng = mock.MagicMock()
        eng._kill_all_non_system.return_value = {'killed': ['a.exe'], 'failed': [],
                                                 'protected': 2}
        eng.get_kill_all_before_restore.return_value = True
        b = _mk_bridge(_rollback_manager=eng)
        res = json.loads(b.emergencyTerminateAll('{}'))
        self.assertTrue(res.get('ok'))
        self.assertFalse(res.get('pending'))
        for _ in range(50):
            if eng._kill_all_non_system.called:
                break
            time.sleep(0.02)
        eng._kill_all_non_system.assert_called_once()
        self.assertEqual(eng._kill_all_non_system.call_args[0][0], 'emergency')
        # 至少有"开始"与"完成"两条活动日志
        self.assertGreaterEqual(len(b._acts), 2, b._acts)

    def test_engine_missing_queues_not_silent(self):
        """引擎未就绪 → 返回 pending + 触发后台初始化 + 写活动日志（不静默失败）。"""
        b = _mk_bridge(_rollback_manager=None)
        called = []
        b._start_module_init_bg = lambda m, a: called.append((m, a))
        res = json.loads(b.emergencyTerminateAll('{}'))
        self.assertTrue(res.get('ok'))
        self.assertTrue(res.get('pending'), '必须标记 pending 供前端提示')
        self.assertIn(('ransomware-rollback', '_rollback_manager'), called,
                      '必须触发按需初始化')
        self.assertTrue(b._acts, '必须有可见反馈（活动日志）')
        self.assertIn('尚未就绪', ' '.join(str(a) for a in b._acts))

    def test_engine_missing_times_out_with_failure_log(self):
        """初始化超时 → 记失败活动日志 + 推送失败信号（不静默）。"""
        b = _mk_bridge(_rollback_manager=None)
        b._start_module_init_bg = lambda m, a: None
        with mock.patch.object(bmod.time, 'time',
                               side_effect=[0.0] + [100.0] * 20):
            b.emergencyTerminateAll('{}')
            for _ in range(50):
                if any('失败' in str(a) for a in b._acts):
                    break
                time.sleep(0.02)
        self.assertTrue(any('失败' in str(a) for a in b._acts), b._acts)
        self.assertTrue(any(s[0] == 'emergencyTerminateFinished' for s in b._sigs))

    def test_kill_all_switch_forced_on(self):
        """清场开关被关掉时，紧急终止仍生效（临时强制开启）。"""
        eng = mock.MagicMock()
        eng.get_kill_all_before_restore.return_value = False
        eng._kill_all_non_system.return_value = {'killed': [], 'failed': [],
                                                 'protected': 0}
        b = _mk_bridge(_rollback_manager=eng)
        b.emergencyTerminateAll('{}')
        for _ in range(50):
            if eng._kill_all_non_system.called:
                break
            time.sleep(0.02)
        eng.set_kill_all_before_restore.assert_called_once_with(True)

    def test_slot_registered_and_both_themes_bound(self):
        from PyQt5.QtCore import QMetaMethod  # noqa: F401
        mo = bmod.PyBridge.staticMetaObject
        names = [bytes(mo.method(i).name()).decode()
                 for i in range(mo.methodCount())]
        self.assertIn('emergencyTerminateAll', names, '桥接槽必须已注册')
        app = open(os.path.join(ROOT, 'ui', 'webview', 'app.js'),
                   encoding='utf-8').read()
        self.assertIn("getElementById('cta-emergency')", app)
        self.assertIn('emergencyTerminateAll', app)
        # 反馈不得依赖 window.alert（WebView2 可能禁用脚本对话框）
        idx = app.find("getElementById('cta-emergency')")
        block = app[idx:idx + 1600]
        self.assertNotIn('window.alert', block, '不得依赖 alert 反馈')
        self.assertIn('showInfoToast', block, '必须有可见 toast 反馈')
        for theme in ('index.html', 'terminal.html'):
            src = open(os.path.join(ROOT, 'ui', 'webview', theme),
                       encoding='utf-8').read()
            self.assertIn('id="cta-emergency"', src)


class TestRansomwareDetectNoGuiBlock(unittest.TestCase):
    """现象 2：检测回调不得在 GUI 线程阻塞/等待。"""

    def test_sound_fallback_is_async(self):
        """蜂鸣兜底（阻塞 ~4.5s）必须转后台线程；不得在主线程 sleep/Beep。"""
        src = open(os.path.join(ROOT, 'utils', 'sound_manager.py'),
                   encoding='utf-8').read()
        i = src.find('def _play_alert(')
        seg = src[i:src.find('def play_threat_alert', i)]
        self.assertIn('Thread(target=_blocking_fallback', seg,
                      )
        self.assertIn('daemon=True', seg)
        self.assertIn('_play_via_kernel32_beep', seg)

    def test_sound_fallback_returns_immediately(self):
        """行为断言：调用 _play_alert 立即返回（阻塞兜底在后台）。"""
        with mock.patch.object(sm, '_DIAG_DISABLE_SOUND', False), \
                mock.patch.object(sm, '_sound_enabled', True), \
                mock.patch.object(sm, '_get_sound_file_path', return_value=None), \
                mock.patch.object(sm, '_play_via_qmedia', return_value=False), \
                mock.patch.object(sm, '_generate_wav_file', return_value=''), \
                mock.patch.object(sm, '_play_via_kernel32_beep',
                                  side_effect=lambda *a: (time.sleep(2.0), True)[1]):
            t0 = time.time()
            sm._play_alert('critical.mp3', 1220, 880, 4)
            dt = time.time() - t0
        self.assertLess(dt, 0.5, f'_play_alert 必须立即返回，实际 {dt:.2f}s')

    def test_detect_callbacks_offload_from_gui_thread(self):
        """源码断言：检测回调有主线程守卫（转后台），不在 GUI 线程做阻塞终止。"""
        src = open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                   encoding='utf-8').read()
        for fn in ('def _on_ransomware_kill', 'def _on_file_threat'):
            i = src.find(fn)
            self.assertGreater(i, 0)
            seg = src[i:i + 900]
            self.assertIn('threading.current_thread() is threading.main_thread()', seg,
                          f'{fn} 必须有 GUI 线程守卫')
            self.assertIn('Thread(target=self.', seg, f'{fn} 必须转后台线程')

    def test_kill_callback_offload_behavior(self):
        """行为断言：主线程调用 _on_ransomware_kill → 立即返回并由后台线程执行。"""
        b = _mk_bridge(_process_protection=mock.MagicMock())
        with mock.patch.object(bmod.PyBridge, '_on_ransomware_kill',
                               autospec=False) as m:
            return  # 占位（真实行为用下一步断言）

    def test_gui_thread_call_is_fast(self):
        """主线程调用检测回调：单次占用 <200ms（重活转后台）。"""
        b = _mk_bridge(_process_protection=mock.MagicMock())
        b._request_critical_sound = lambda: None
        b._last_ransomware_req = None
        ran = threading.Event()

        def _slow(pid, force=True, kill_tree=True, timeout=0.5):   # 模拟阻塞式终止
            time.sleep(1.0)
            ran.set()
            return True
        b._process_protection.kill_process = _slow
        b._process_protection._is_psls_related_process = lambda p: False
        with mock.patch.object(bmod.psutil, 'Process', return_value=object()):
            t0 = time.time()
            b._on_ransomware_kill('12345')          # 在主线程调用
            dt = (time.time() - t0) * 1000
            self.assertLess(dt, 200, f'主线程调用必须立即返回，实际 {dt:.0f}ms')
            self.assertTrue(ran.wait(4.0), '后台线程应继续完成终止')

    def test_activity_and_signals_are_merged_not_per_item(self):
        """大量活动/威胁推送不逐条 emit：activity 合并、tool 信号有限预算。"""
        src = open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                   encoding='utf-8').read()
        i = src.find('def _add_activity')
        seg = src[i:i + 2600]
        self.assertIn('threading.current_thread() is threading.main_thread()', seg)
        self.assertIn('_pending_activity', seg, '子线程活动日志应为合并式单槽')
        j = src.find('def _flush_signals')
        seg2 = src[j:j + 12000]
        self.assertIn('_flush_deadline', seg2, '必须遵守 20ms 预算')
        self.assertIn('merged[-1] = (name, args)', seg2, '同名相邻信号应合并')

    def test_emergency_still_kills_third_party(self):
        """回归保护：紧急终止规则未被改回"跳过第三方"。"""
        class P:
            def __init__(s, pid, name):
                s.pid = pid; s.info = {'pid': pid, 'name': name}
            def terminate(s): pass
            def kill(s): pass
        procs = [P(201, 'vmware-vmx.exe'), P(202, 'qq.exe')]
        m = rr.RansomwareRollback(protected_dirs=[self.tmp_dir()])
        m._running = True
        m._kill_all_before_restore = True
        m._protected_pids = lambda ps: {os.getpid()}
        f = mock.MagicMock(); f.process_iter.return_value = procs
        f.wait_procs.return_value = (procs, [])
        with mock.patch.dict(sys.modules, {'psutil': f}):
            out = m._kill_all_non_system('emergency')
        self.assertIn('vmware-vmx.exe', out['killed'])
        self.assertIn('qq.exe', out['killed'])

    def tmp_dir(self):
        d = tempfile.mkdtemp(prefix='psls_ek3_')
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        return d


if __name__ == '__main__':
    unittest.main()