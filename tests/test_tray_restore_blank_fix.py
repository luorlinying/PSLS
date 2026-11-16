# -*- coding: utf-8 -*-
"""
TDD: 托盘重新打开后主 GUI 白屏、右键无反应的修复

功能要求（用户明确）：
  1. 仅在从托盘恢复（_show_from_tray）时主动检测页面健康度；
  2. 只有检测到页面不健康（渲染进程崩溃待恢复 / URL 异常）才 reload，
     正常/扫描卡顿时绝不误重载；
  3. reload 后必须重建 QWebChannel（否则桥接失效导致右键等 JS 无反应）。

现有实现问题：renderProcessTerminated 需累计 2 次才延迟 reload，
窗口隐藏期间单次崩溃就白屏等待；且 _show_from_tray 仅 show() 无健康检测。
"""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

MW = os.path.join(ROOT, 'ui', 'webview', 'main_window.py')


def read_mw():
    with open(MW, 'r', encoding='utf-8') as f:
        return f.read()


class TestTrayRestoreNoBlankScreen(unittest.TestCase):

    def test_show_from_tray_calls_health_check(self):
        """_show_from_tray 必须在恢复显示时调用页面健康度检测。"""
        src = read_mw()
        m = re.search(
            r"def _show_from_tray\(self\):\n(?P<body>.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group('body')
        # 必须调用健康检测
        self.assertIn('_maybe_recover_blank_webview', body,
                      "_show_from_tray 未调用 _maybe_recover_blank_webview："
                      "托盘恢复时不检测页面健康度，窗口隐藏期间渲染进程崩溃会白屏")

    def test_health_check_only_reloads_on_unhealthy(self):
        """健康检测必须：正常时不 reload（防止扫描卡顿误重载），
        只有检测到不健康（崩溃待恢复标记 / URL 异常）才 reload。"""
        src = read_mw()
        m = re.search(
            r"def _maybe_recover_blank_webview\(self\):\n(?P<body>.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "_maybe_recover_blank_webview 方法缺失")
        body = m.group('body')
        # 必须有崩溃待恢复标记检测
        self.assertIn('_render_crash_pending', body,
                      "健康检测必须读取 _render_crash_pending（渲染崩溃待恢复标记）")
        # reload 必须在条件判断（need_reload）之后才执行
        reload_idx = body.find('.reload()')
        self.assertGreater(reload_idx, 0, "健康检测中缺少 _web_view.reload() 调用")
        need_mask = body[:reload_idx]
        self.assertIn('need_reload', need_mask,
                      "必须在条件判定通过（need_reload=True）后才 reload，"
                      "正常/扫描卡顿不得触发重载")

    def test_reload_rebuilds_webchannel(self):
        """reload 后必须重建 QWebChannel，否则桥接失效导致右键/JS 无反应。"""
        src = read_mw()
        m = re.search(
            r"def _maybe_recover_blank_webview\(self\):\n(?P<body>.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group('body')
        reload_idx = body.find('.reload()')
        after_reload = body[reload_idx:]
        self.assertIn('_setup_webchannel', after_reload,
                      "reload 后必须重建 QWebChannel（_setup_webchannel），"
                      "否则页面虽渲染但桥接失效、右键菜单无反应")

    def test_crash_flag_cleared_on_successful_load(self):
        """页面成功加载（loadFinished ok）后必须清除崩溃标记，避免托盘恢复误重载。"""
        src = read_mw()
        m = re.search(
            r"def _on_load_finished\(self, ok\):\n(?P<body>.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group('body')
        # ok 分支中应有 _render_crash_pending = False
        ok_block = body.split('if ok:')[-1] if 'if ok:' in body else body
        self.assertIn('_render_crash_pending = False', ok_block,
                      "loadFinished ok 后必须清除 _render_crash_pending，"
                      "否则托盘恢复时持续性误重载")


if __name__ == '__main__':
    unittest.main()