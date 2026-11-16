# -*- coding: utf-8 -*-
"""配置路径 GUI 零长阻塞回归（拨开关 / 打开设置页 / 保存设置）。

根因：`toggleModule` 在引擎为 None 时**在 GUI 线程**调 `_try_reinitialize_module`
就地构造引擎（AutoStartProtection WMI 订阅 / RealtimeMonitor 目录与线程 /
MBRProtector 引导扇区与驱动 …），可达数百 ms~秒级；`notification` 的 start/stop
与 `ransomware-rollback` 的 set_enabled 也在 GUI 线程同步。

修复：构造转后台线程 + 状态"加载中(pending)"，成功后落 enabled，失败才回退并报错；
notification / ransomware-rollback 分支同样转后台。
"""
import os
import sys
import time
import threading
import logging
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
logging.disable(logging.CRITICAL)

import ui.webview.bridge as bmod


MODULES = {
    'autostart-protection': '_autostart_protection',
    'realtime-monitor': '_realtime_monitor',
    'mbr-protection': '_mbr_protector',
    'file-protection': '_file_protection',
    'system-protection': '_system_protection',
    'process-protection': '_process_protection',
}


def _new_bridge():
    b = bmod.PyBridge.__new__(bmod.PyBridge)
    b._module_states = {}
    b._module_pending = {}
    b._module_init_lock = threading.Lock()
    b._module_init_inflight = set()
    b._module_toggle_lock = threading.Lock()
    b._gui_block_samples = []
    b._gui_block_max_ms = 0.0
    b._acts = []
    b._sigs = []
    b._add_activity = lambda *a, **k: b._acts.append(a)
    b._emit_tool_signal = lambda name, payload: b._sigs.append((name, payload))
    b._persist_module_states = lambda: None
    return b


class TestToggleModuleNonBlocking(unittest.TestCase):

    def test_engine_none_delegates_to_background(self):
        """引擎为 None 的 6 个模块：GUI 占用 <200ms，且转后台构造。"""
        for mod, attr in MODULES.items():
            b = _new_bridge()
            setattr(b, attr, None)
            started = []

            def _slow_reinit(module, attr_name, _b=b, _attr=attr, _s=started,
                             _mod=mod):
                _s.append(_mod)
                time.sleep(0.5)                      # 合成 500ms 重构造
                setattr(_b, _attr, type('E', (), {
                    'is_running': False,
                    'start': lambda self: None,
                    'stop': lambda self: None})())
            b._try_reinitialize_module = _slow_reinit

            t0 = time.time()
            b.toggleModule(mod, True)
            dt = (time.time() - t0) * 1000
            self.assertLess(dt, 200, f'{mod}: GUI 线程被阻塞 {dt:.1f}ms')
            self.assertEqual(started, [mod], f'{mod}: 应转后台构造')
            self.assertNotIn(mod, b._module_states,
                             f'{mod}: 构造期间不得先置 False/True（应为加载中）')
            self.assertTrue(b._module_pending.get(mod))
            self.assertTrue(any(s[0] == 'moduleTogglePending' for s in b._sigs))

            # 构造完成后 → 状态落地 enabled=True
            t0 = time.time()
            while time.time() - t0 < 3 and getattr(b, attr, None) is None:
                time.sleep(0.02)
            time.sleep(0.15)
            self.assertIsNotNone(getattr(b, attr, None))
            self.assertTrue(b._module_states.get(mod), f'{mod}: 成功应置 enabled')
            self.assertTrue(any(s[0] == 'moduleToggleSettled' for s in b._sigs))

    def test_init_failure_reports_error_and_reverts(self):
        b = _new_bridge()
        b._autostart_protection = None
        b._try_reinitialize_module = lambda module, attr_name: None  # 不创建引擎
        b.toggleModule('autostart-protection', True)
        t0 = time.time()
        while time.time() - t0 < 2 and 'autostart-protection' not in b._module_states:
            time.sleep(0.02)
        self.assertFalse(b._module_states.get('autostart-protection'),
                         '构造失败才回退 False')
        self.assertTrue(any(s[0] == 'moduleToggleFailed' for s in b._sigs),
                        '构造失败必须报错')
        self.assertTrue(any('初始化失败' in str(a) for a in b._acts))

    def test_construct_does_not_duplicate(self):
        """同一模块并发多次切换只构造一次。"""
        b = _new_bridge()
        b._mbr_protector = None
        calls = []
        b._try_reinitialize_module = lambda module, attr_name: (
            calls.append(module), time.sleep(0.4),
            setattr(b, '_mbr_protector', object()))
        ts = [bmod.threading.Thread(target=lambda: b.toggleModule('mbr-protection', True))
              for _ in range(3)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        time.sleep(0.8)
        self.assertEqual(len(calls), 1, f'应去重，实际构造 {len(calls)} 次')

    def test_notification_and_rollback_off_gui_thread(self):
        b = _new_bridge()
        calls = []

        class _NM:
            is_running = False
            def start(self):
                calls.append(('nm_start', threading.current_thread().name))
            def stop(self):
                calls.append(('nm_stop', threading.current_thread().name))
            def is_sound_enabled(self):
                return False
        b._notification_manager = _NM()

        class _RB:
            def set_enabled(self, en):
                calls.append(('rb_set', threading.current_thread().name))
        b._rollback_manager = _RB()

        t0 = time.time()
        b.toggleModule('notification', True)
        b.toggleModule('ransomware-rollback', True)
        dt = (time.time() - t0) * 1000
        self.assertLess(dt, 200, f'提交耗时应在 GUI 侧极短，实际 {dt:.1f}ms')
        t0 = time.time()
        while time.time() - t0 < 2 and len(calls) < 2:
            time.sleep(0.02)
        names = {c[1] for c in calls}
        self.assertTrue(names)
        self.assertNotIn('MainThread', names, '启停/切换不得在 GUI 主线程执行')

    def test_cfg_timed_warns_over_threshold(self):
        """[配置耗时] 埋点：假引擎构造 300ms → 记录采样（超阈走 WARNING 分支）。"""
        b = _new_bridge()
        b._mbr_protector = None
        b.toggleModule('mbr-protection', True)      # 触发提交埋点
        b._cfg_note('假引擎构造', 300.0)
        samples = b._gui_block_samples
        self.assertTrue(any(s[0].startswith('配置耗时') for s in samples), samples)
        self.assertTrue(any(s[0] == '配置耗时:假引擎构造' and s[1] >= 300.0
                            for s in samples))

    def test_source_contract_no_sync_construct_in_toggle(self):
        with open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        seg = src.split('def toggleModule', 1)[1].split('\n    def _start_module_init_bg', 1)[0]
        self.assertIn('_start_module_init_bg', seg)
        self.assertNotIn('self._try_reinitialize_module(module, attr_name)', seg,
                         'toggleModule 不得在 GUI 线程就地构造引擎')
        self.assertIn('_cfg_timed', src)
        self.assertIn("prefix='配置耗时'", src)


class TestFrontendPendingSignal(unittest.TestCase):

    def test_signals_declared_and_frontend_wired(self):
        with open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        self.assertIn('moduleTogglePending = pyqtSignal(str)', src)
        self.assertIn('moduleToggleSettled = pyqtSignal(str)', src)
        with open(os.path.join(ROOT, 'ui', 'webview', 'app.js'),
                  'r', encoding='utf-8') as f:
            js = f.read()
        self.assertIn('moduleTogglePending', js)
        self.assertIn('正在加载中', js)


if __name__ == '__main__':
    unittest.main()