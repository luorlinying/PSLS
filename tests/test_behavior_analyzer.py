# -*- coding: utf-8 -*-
"""
TDD 测试: BehaviorAnalyzer 行为启发判定

- 注入序列(脚本父进程+注入) -> behavior_confirmed=malware
- 写系统目录未达阈值(<2次) -> 不升级
- 可信签名(signed=True) / 可信宿主父进程 -> 抑制升级
- 确认级规则写入 confirm=90 分; 佐证规则低分
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.behavior_analyzer import BehaviorAnalyzer  # noqa: E402


class TestBehaviorRules(unittest.TestCase):

    def _ba(self):
        return BehaviorAnalyzer(window=30.0)

    def test_script_parent_inject_confirmed(self):
        """R2: 父=脚本解释器 + 注入句柄 -> behavior_confirmed"""
        ba = self._ba()
        # 父 wscript(脚本解释器), 子 pid=111 无签名
        parent = 100
        child = 111
        ba.feed_process_start(parent, 'wscript.exe', r'C:\Windows\System32\wscript.exe')
        ba.feed_process_start(child, 'evil.exe', r'C:\Users\T\evil.exe', parent_pid=parent)
        ba.feed_handle_audit(child, 9999, 0x0414)
        res = ba.evaluate(child, context={'signed': False, 'parent_signed': False})
        self.assertTrue(res['behavior_confirmed'], f'rules={res["behavior_rules"]}')
        self.assertIn('script_inject', res['behavior_rules'])
        self.assertGreaterEqual(res['behavior_chain'], 90.0)

    def test_sys_exe_write_below_threshold_no_confirm(self):
        """R1: 写系统目录 exe 仅 1 次(阈值=2) -> 不升级"""
        ba = self._ba()
        pid = 200
        ba.feed_process_start(pid, 'drop.exe', r'C:\Users\T\AppData\Local\Temp\drop.exe')
        ba.feed_file_write(pid, r'C:\Windows\System32\new.exe')
        res = ba.evaluate(pid, context={'signed': False, 'parent_signed': False})
        self.assertFalse(res['behavior_confirmed'])
        self.assertNotIn('persist_dropload', res['behavior_rules'])

    def test_persist_dropload_confirmed_at_threshold(self):
        """R1 达阈值: 写系统目录 exe≥2 + 写 Run 持久化点 -> confirm"""
        ba = self._ba()
        pid = 201
        ba.feed_process_start(pid, 'evil.dll.exe', r'C:\Users\T\evil.dll.exe')
        ba.feed_file_write(pid, r'C:\Windows\System32\a.exe')
        ba.feed_file_write(pid, r'C:\Windows\System32\b.exe')
        ba.feed_reg_persist(pid, r'Software\Microsoft\Windows\CurrentVersion\Run')
        res = ba.evaluate(pid, context={'signed': False, 'parent_signed': False})
        self.assertTrue(res['behavior_confirmed'])
        self.assertIn('persist_dropload', res['behavior_rules'])

    def test_trusted_signature_suppresses(self):
        """签名有效(signed=True) -> 不升级 (minimize FP)"""
        ba = self._ba()
        pid = 300
        ba.feed_process_start(pid, 'signed.exe', r'C:\Program Files\X\signed.exe')
        ba.feed_file_write(pid, r'C:\Windows\System32\a.exe')
        ba.feed_file_write(pid, r'C:\Windows\System32\b.exe')
        ba.feed_reg_persist(pid, r'Software\...\CurrentVersion\Run')
        res = ba.evaluate(pid, context={'signed': True, 'parent_signed': True})
        self.assertFalse(res['behavior_confirmed'])
        self.assertEqual(res['behavior_chain'], 0.0)

    def test_trusted_host_parent_suppresses(self):
        """父=svchost(可信宿主) -> 抑制行为升级"""
        ba = self._ba()
        parent = 400
        child = 401
        ba.feed_process_start(parent, 'svchost.exe', r'C:\Windows\System32\svchost.exe')
        ba.feed_process_start(child, 'svc_child.exe', r'C:\Windows\Temp\svc_child.exe',
                              parent_pid=parent)
        ba.feed_file_write(child, r'C:\Windows\System32\a.exe')
        ba.feed_file_write(child, r'C:\Windows\System32\b.exe')
        ba.feed_reg_persist(child, r'...\CurrentVersion\Run')
        res = ba.evaluate(child, context={'signed': False, 'parent_signed': False})
        self.assertFalse(res['behavior_confirmed'])
        self.assertEqual(res['behavior_chain'], 0.0)

    def test_repeat_inject_supporting(self):
        """R5 佐证: 同目标注入≥3 -> 佐证 chain, 不确认"""
        ba = self._ba()
        pid = 500
        ba.feed_process_start(pid, 'beh.exe', r'C:\Users\T\beh.exe')
        for _ in range(3):
            ba.feed_handle_audit(pid, 600, 0x0414)
        res = ba.evaluate(pid, context={'signed': False, 'parent_signed': False})
        self.assertFalse(res['behavior_confirmed'])
        self.assertIn('repeat_inject', res['behavior_rules'])
        self.assertLess(res['behavior_chain'], 82.0)


if __name__ == '__main__':
    unittest.main(verbosity=2)