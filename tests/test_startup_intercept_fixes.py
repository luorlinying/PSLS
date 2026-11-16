# -*- coding: utf-8 -*-
"""启动拦截两项修复的回归测试。

1. 自启动监测必须覆盖 32 位视图（WOW6432Node）的 HKLM 自启动键 ——
   否则在用户态降级模式（非管理员 / 驱动未加载）下，32 位程序写入的
   HKLM Run 项完全不可见，表现为"自启动拦截经常失效"。
2. `_notify_launch_monitoring` 在"非信任程序启动 → 终止"关键路径上调用，
   必须 fire-and-forget —— 否则每次拦截都要先等最多 0.5s UI 回调返回，
   才轮到 `_emergency_kill`，表现为"emergency kill 不及时"。
"""

import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


class TestAutostartWow64Coverage(unittest.TestCase):
    """WOW6432Node（32 位视图）HKLM 自启动路径必须被监控。"""

    def test_hklm_wow6432node_run_paths_monitored(self):
        from engine import autostart_protection as ap
        paths = [(int(h), p.lower()) for h, p in ap.AUTOSTART_KEY_PATHS]
        expected = [
            r'software\wow6432node\microsoft\windows\currentversion\run',
            r'software\wow6432node\microsoft\windows\currentversion\runonce',
        ]
        for rel in expected:
            self.assertIn(
                (int(winreg.HKEY_LOCAL_MACHINE), rel), paths,
                f'缺少 32 位自启动路径: HKLM\\{rel}（32 位程序的自启动写入看不见）')

    def test_64bit_paths_still_present(self):
        """新增 32 位路径不得挤掉原有 64 位/用户路径。"""
        from engine import autostart_protection as ap
        paths = [(int(h), p.lower()) for h, p in ap.AUTOSTART_KEY_PATHS]
        for hive, rel in (
                (winreg.HKEY_CURRENT_USER,
                 r'software\microsoft\windows\currentversion\run'),
                (winreg.HKEY_LOCAL_MACHINE,
                 r'software\microsoft\windows\currentversion\run')):
            self.assertIn((int(hive), rel), paths)


class TestLaunchNotifyNonBlocking(unittest.TestCase):
    """启动监测通知不得阻塞终止关键路径。"""

    def test_notify_does_not_block_on_slow_ui_callback(self):
        from engine.process_protection import ProcessProtection as P
        pp = object.__new__(P)          # 跳过重型 __init__

        def _slow_callback(_payload):
            time.sleep(1.0)

        pp._on_launch_scan = _slow_callback
        t0 = time.time()
        pp._notify_launch_monitoring(
            4321, 'evil.exe', r'C:\tmp\evil.exe', reason='非信任程序启动')
        dt = time.time() - t0
        self.assertLess(
            dt, 0.2,
            f'_notify_launch_monitoring 阻塞了 {dt:.2f}s；'
            f'该调用位于 _sandbox_then_release 阶段 0，'
            f'阻塞会推迟 _emergency_kill（emergency kill 不及时的直接原因）')

    def test_notify_without_callback_is_noop(self):
        from engine.process_protection import ProcessProtection as P
        pp = object.__new__(P)
        pp._on_launch_scan = None
        t0 = time.time()
        pp._notify_launch_monitoring(1, 'x.exe', r'C:\x', reason='r')
        self.assertLess(time.time() - t0, 0.2)


class TestAutostartBaselineRebuilt(unittest.TestCase):
    """回滚(删除)后基线必须剔除该项，否则同名值重写不再被拦截。

    旧实现用"本轮开始时读到的 current"覆盖基线：被回滚删除的项仍残留在
    基线里 → 恶意软件用同名值重新写入会被当成"基线中已存在" → 永远不再
    告警/拦截（"自启动拦截经常失效"）。
    """

    def _obj(self, live, suspicious=False, on_event=None):
        from engine import autostart_protection as ap
        obj = object.__new__(ap.AutostartProtection)
        obj._baseline = {}
        obj._baseline_lock = threading.Lock()
        obj._throttle = lambda key, iv: True
        obj._bump_stat = lambda k: None
        obj._add_event = lambda *a, **k: None
        obj._is_allowed = lambda k: False
        obj._on_ask_user = (lambda info: on_event.append(info)) \
            if on_event is not None else None
        obj._on_suspicious = (lambda info: on_event.append(info)) \
            if on_event is not None else None
        obj._read_key_values = lambda hive, path: dict(live)
        if suspicious:
            obj._analyze_value_only = lambda p, n, d: True
            # 模拟回滚：从"真实注册表"里删掉
            obj._rollback_value = (
                lambda hive, path, name, base: live.pop(name, None) is not None)
        else:
            obj._analyze_value_only = lambda p, n, d: False
        return obj

    HIVE_PATH = (None, r'Software\Test\Run')

    def test_re_added_value_is_detected_again(self):
        live = {'evil': r'C:\Users\x\AppData\evil.exe'}
        seen = []
        obj = self._obj(live, suspicious=True, on_event=seen)
        hive, path = winreg.HKEY_CURRENT_USER, self.HIVE_PATH[1]
        obj._on_value_change_fallback(hive, path)   # 检测 → 回滚删除
        self.assertEqual(len(seen), 1)
        self.assertEqual(live, {})                   # 已被回滚
        live['evil'] = r'C:\Users\x\AppData\evil.exe'  # 恶意软件重新写入
        obj._on_value_change_fallback(hive, path)   # 必须再次检测到
        self.assertEqual(
            len(seen), 2,
            '同名自启动项回滚后重新写入未被再次拦截（基线未剔除已删除项）')

    def test_baseline_matches_live_registry(self):
        live = {'a': 'x'}
        seen = []
        obj = self._obj(live, suspicious=False, on_event=seen)
        hive, path = winreg.HKEY_CURRENT_USER, self.HIVE_PATH[1]
        obj._on_value_change_fallback(hive, path)   # a 新增 → ask
        self.assertEqual(len(seen), 1)
        live.clear()
        live['b'] = 'y'
        obj._on_value_change_fallback(hive, path)   # b 新增 → ask
        keys = set(obj._baseline.keys())
        self.assertNotIn(f'{int(hive)}\\{path}\\a', keys,
                         '已消失的项仍残留在基线中')
        self.assertIn(f'{int(hive)}\\{path}\\b', keys)


if __name__ == '__main__':
    unittest.main()