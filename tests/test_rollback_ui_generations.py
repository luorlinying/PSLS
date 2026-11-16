# -*- coding: utf-8 -*-
"""勒索拦截 / 回滚中心 UI 契约测试（两套主题一致性）。

覆盖：
  1. index.html（米色经典）与 terminal.html（琥珀终端）都含「立即回滚」按钮，
     id / data-action 完全一致；
  2. 两套主题都含"保留世代列表"容器与空状态（id 一致），并含世代选择动作
     data-action="rollback-gen" 的渲染契约（由 app.js 渲染）；
  3. 两套主题的工具卡片数必须仍各为 8（不得因新增 UI 破坏）；
  4. app.js 中 pyBridge 调用存在且缺失元素时安全返回。
"""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WV = os.path.join(ROOT, 'ui', 'webview')


class TestRollbackUI(unittest.TestCase):

    def _read(self, name):
        with open(os.path.join(WV, name), 'r', encoding='utf-8') as f:
            return f.read()

    def test_manual_rollback_button_in_both_themes(self):
        for name in ('index.html', 'terminal.html'):
            src = self._read(name)
            self.assertIn('data-action="rollback-manual"', src, name)
            self.assertIn('id="rollback-manual-btn"', src, name)
            self.assertIn('立即回滚', src, name)

    def test_generation_list_container_in_both_themes(self):
        for name in ('index.html', 'terminal.html'):
            src = self._read(name)
            self.assertIn('id="rollback-generations"', src, name)
            self.assertIn('id="rollback-generations-empty"', src, name)
            self.assertIn('id="rollback-generations-count"', src, name)

    def test_tool_card_count_is_eight_in_both_themes(self):
        for name in ('index.html', 'terminal.html'):
            src = self._read(name)
            self.assertEqual(len(re.findall(r'class="tool-card', src)), 8, name)

    def test_app_js_generation_contract(self):
        src = self._read('app.js')
        # 前端调用契约
        self.assertIn('getRollbackGenerations', src)
        self.assertIn('triggerRollbackGeneration', src)
        self.assertIn('rollbackTriggerManual', src)
        # 世代项渲染动作契约
        self.assertIn("'rollback-gen'", src)
        # 元素缺失时安全返回：渲染函数对 listEl 判空后直接 return
        self.assertIn('if (!listEl) return;', src)
        # 两处绑定均使用判空
        self.assertIn("if (manualBtn) manualBtn.addEventListener", src)

    def test_bridge_slots_exist(self):
        with open(os.path.join(WV, 'bridge.py'), 'r', encoding='utf-8') as f:
            src = f.read()
        for token in ('def getRollbackGenerations', 'def triggerRollbackGeneration',
                      'def rollbackTriggerManual', 'generation_id'):
            self.assertIn(token, src)


if __name__ == '__main__':
    unittest.main()