# -*- coding: utf-8 -*-
"""沙箱分析辅助子进程"不弹黑窗口"回归测试。

失败因（修复前）：PSLS 是 windowed（无控制台）进程，engine/sandbox_analyzer.py
里大量 subprocess.run/Popen 未带 CREATE_NO_WINDOW，直接 spawn SbieIni.exe /
Start.exe / taskkill 等控制台程序时 Windows 会为每个子进程新建并显示一个控制台
窗口；分析期间高频调用（每秒多次 /listpids）→ 用户看到"大量黑窗口闪现"。

本测试用源码断言（与 tests/test_sandbox_self_block.py 同风格）确保：
  1. 存在统一 helper _hidden_spawn_kwargs()
  2. 所有辅助 subprocess 调用都套上该 helper
  3. helper 返回 CREATE_NO_WINDOW + SW_HIDE
  4. 被测样本启动已加官方 /hide_window 开关
"""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SANDBOX_SRC = os.path.join(ROOT, 'engine', 'sandbox_analyzer.py')


class TestSandboxHiddenSpawn(unittest.TestCase):

    def _src(self) -> str:
        with open(SANDBOX_SRC, 'r', encoding='utf-8') as f:
            return f.read()

    def test_helper_exists(self):
        src = self._src()
        self.assertIn('def _hidden_spawn_kwargs', src,
                      '缺少统一 helper _hidden_spawn_kwargs()；'
                      '辅助子进程会继续弹黑窗口。')

    def test_helper_returns_hidden_flags(self):
        import engine.sandbox_analyzer as sa
        kw = sa._hidden_spawn_kwargs()
        if sys.platform == 'win32':
            self.assertEqual(kw.get('creationflags'), sa.CREATE_NO_WINDOW)
            si = kw.get('startupinfo')
            self.assertIsNotNone(si)
            self.assertEqual(si.dwFlags, sa.STARTF_USESHOWWINDOW)
            self.assertEqual(si.wShowWindow, sa.SW_HIDE)

    def test_all_helper_spawns_hidden(self):
        """每个 subprocess.run/Popen（含 _sp.run）调用附近必须出现隐藏参数。"""
        src = self._src()
        calls = list(re.finditer(r'(?:subprocess|_sp)\.(?:run|Popen)\(', src))
        self.assertGreater(len(calls), 5,
                           '未找到预期的辅助子进程调用，正则可能失配')
        for m in calls:
            window = src[m.start(): m.start() + 500]
            self.assertTrue(
                '_hidden_spawn_kwargs()' in window
                or 'CREATE_NO_WINDOW' in window,
                f'位置 {m.start()} 的 subprocess 调用未隐藏控制台窗口:\n'
                f'{window[:200]}')

    def test_sample_launch_uses_official_hide_window(self):
        """被测样本启动使用 Sandboxie 官方 /hide_window（已查证存在）。"""
        src = self._src()
        self.assertIn("'/hide_window'", src,
                      '被测样本启动未加官方 /hide_window；'
                      '样本自身控制台窗口仍会闪现。')


if __name__ == '__main__':
    unittest.main()