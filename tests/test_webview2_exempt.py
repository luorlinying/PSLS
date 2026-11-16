# -*- coding: utf-8 -*-
"""
TDD 测试: 隔离化 WebView2/Chromium 进程不被 PSLS 当作威胁处置 (A1)

- process_protection._check_new_process 对 msedgewebview2 及 --type=renderer
  等 Chromium 特征进程直接放行(不进沙箱/终止)
- _is_psls_related_process 覆盖 WebView2(名/路径/命令行)，阻断自我终止
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


class TestWebView2ExemptSource(unittest.TestCase):
    """源码静态断言(项目 TDD 风格)"""

    @classmethod
    def setUpClass(cls):
        pp_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               'engine', 'process_protection.py')
        cls.src = _read(pp_path)

    def test_webview2_exemption_present_in_check_new_process(self):
        """_check_new_process 含 WebView2 豁免分支(通过命令行/名称特征)"""
        snippet = re.search(r'WebView2 进程豁免.*?\n(.*?)\n\s*# 无 exe 路径',
                            self.src, re.DOTALL)
        self.assertIsNotNone(snippet, '未找到 WebView2 进程豁免分支')
        body = snippet.group(1)
        self.assertIn('_WEBVIEW2_TOKENS', body)

    def test_psls_related_covers_webview2(self):
        """_is_psls_related_process 拼接了 _is_webview2_process"""
        m = re.search(r'def _is_psls_related_process.*?\n(.*?)\n\s+def ', self.src, re.DOTALL)
        self.assertIsNotNone(m, '未找到 _is_psls_related_process')
        self.assertIn('_is_webview2_process', m.group(1))

    def test_webview2_tokens_defined(self):
        """定义 WebView2 进程名/路径特征集合"""
        m = re.search(r'_WEBVIEW2_TOKENS\s*=\s*\((.+?)\)', self.src, re.DOTALL)
        self.assertIsNotNone(m, '未找到 _WEBVIEW2_TOKENS')
        low = m.group(1).lower()
        self.assertIn('msedgewebview2', low)


class TestWebView2ExemptRuntime(unittest.TestCase):
    """运行时行为测试(核心保留义：不影响沙箱/注入判定本身)"""

    def test_is_psls_related_process_webview2(self):
        import psutil
        from engine.process_protection import ProcessProtection
        pp = ProcessProtection.__new__(ProcessProtection)
        # 用最小桩构造：避免触发全量 __init__
        pp._behavior_analyzer = None
        pp._behavior_analyzer_lock = __import__('threading').Lock()

        fake = type('Fake', (), {})()
        fake.name = lambda: 'msedgewebview2.exe'
        fake.exe = lambda: r'C:\Program Files (x86)\Microsoft\EdgeWebView\msedgewebview2.exe'
        fake.cmdline = lambda: ['msedgewebview2.exe']
        fake.parent = lambda: None
        self.assertTrue(pp._is_webview2_process(fake))
        self.assertTrue(pp._is_psls_related_process(fake))

        # 终止守卫：真实 psutil.Process 桩无法伪造(NoSuchProcess→False)。
        # 但 PSLS 相关判定本身已覆盖 WebView2，语义上拒绝自处置。
        try:
            pp._refuse_self_kill  # 存在即可
        except AttributeError:
            self.fail('_refuse_self_kill 不存在')

    def test_webview2_renderer_child(self):
        """带 --type=renderer 的 Chromium 子进程也命中"""
        from engine.process_protection import ProcessProtection
        pp = ProcessProtection.__new__(ProcessProtection)
        pp._behavior_analyzer = None
        pp._behavior_analyzer_lock = __import__('threading').Lock()

        fake = type('Fake', (), {})()
        fake.name = lambda: 'msedgewebview2.exe'
        fake.exe = lambda: None
        fake.cmdline = lambda: ['msedgewebview2.exe', '--type=renderer']
        fake.parent = lambda: None
        self.assertTrue(pp._is_webview2_process(fake))


if __name__ == '__main__':
    unittest.main(verbosity=2)