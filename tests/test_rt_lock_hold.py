"""
TDD 测试: 实时防护检测到 malware/suspicious 后应持续持有文件独占锁，
直到 on_threat 处理完毕，防止扫描结果回到主进程与隔离动作之间用户可以运行文件。
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestRealtimeLockHeldBeyondScan(unittest.TestCase):
    """_process_scan_results 检测到 malware/suspicious 时必须重新获取独占锁"""

    def test_process_scan_results_holds_lock_on_threat(self):
        """RealtimeMonitor._process_scan_results: 存在 malware 结果时
        应在调用 on_threat 之前锁定原文件，并提供释放句柄接口。
        """
        bridge_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'engine', 'realtime_monitor.py')
        with open(bridge_path, 'r', encoding='utf-8') as f:
            src = f.read()

        import re
        m = re.search(
            r"def _process_scan_results\(self, file_path.*?:\n(.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "_process_scan_results 未找到")
        body = m.group(1)

        # 必须在 on_threat 之前进行锁定动作（重新获取 share=0 句柄）
        # 期望表现：进入 on_threat 前有 lock 取得并登记到 _hold_locks 之类的注册表
        # 否则出现漏洞：worker 释放锁 → on_threat 之前（回调间隙）用户可以运行文件
        self.assertIn('_lock_file_exclusive', body,
                      "_process_scan_results 中缺失主进程端的威胁文件再锁定函数调用 "
                      "(_lock_file_exclusive)，导致 worker 释放锁后威胁处理窗口打开")
        # 锁必须在 on_threat 实际调用之前取得（通过代码顺序验证）
        # 注意：忽略注释中 "就回调 on_threat" 的自然语言字样，匹配实际调用 self._on_threat(
        import re as _re
        on_threat_matches = list(_re.finditer(r'self\._on_threat\s*\(', body))
        lock_matches = list(_re.finditer(r'_lock_file_exclusive', body))
        self.assertTrue(on_threat_matches, "找不到 on_threat 实际调用 self._on_threat(")
        self.assertTrue(lock_matches, "找不到威胁锁定调用 _lock_file_exclusive")
        on_threat_idx = on_threat_matches[0].start()
        lock_idx = lock_matches[0].start()
        self.assertLess(lock_idx, on_threat_idx,
                        "威胁文件锁定必须在 on_threat 调用之前执行，否则会有锁释放间隙")

        # RealtimeMonitor 必须提供释放锁定威胁文件的方法（由桥接层在 on_threat 完成后调用）
        self.assertIn('release_threat_lock', src,
                      "RealtimeMonitor 缺失 release_threat_lock() 方法，"
                      "隔离/删除后无法释放句柄")

    def test_lock_before_pool_callback_processes_threat(self):
        """_on_pool_result_done: 判定存在威胁后进入 _process_scan_results 之前或之内
        重新锁定，并提供释放接口以支持回调完成后释放。"""
        bridge_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'engine', 'realtime_monitor.py')
        with open(bridge_path, 'r', encoding='utf-8') as f:
            src = f.read()
        # 对 release_threat_lock 的实现要求：支持按 file_path 释放并关闭句柄
        import re
        m = re.search(
            r"def release_threat_lock\(self.*?:\n(.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "release_threat_lock 函数不存在")
        body = m.group(1)
        self.assertIn('.close()', body,
                      "release_threat_lock 必须 close 句柄（释放独占锁定）")

    def test_sync_fallback_scan_also_locks_threat(self):
        """回退的主进程同步扫描分支：检测到 malware/suspicious 时同样持锁到 on_threat 结束"""
        bridge_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'engine', 'realtime_monitor.py')
        with open(bridge_path, 'r', encoding='utf-8') as f:
            src = f.read()
        # 回退分支调用 _process_scan_results，复用其逻辑即可
        # 只要 _process_scan_results 实现了锁定就 OK
        # 这里只验证调用顺序：同步扫描后才 _process_scan_results
        import re
        m = re.search(
            r"# 回退：主进程同步扫描.*?(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "回退同步扫描分支未找到")
        body = m.group(0)
        self.assertIn('_process_scan_results', body,
                      "回退扫描分支应该调用 _process_scan_results 统一走威胁锁定流程")


if __name__ == '__main__':
    unittest.main()
