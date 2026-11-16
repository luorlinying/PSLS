"""
TDD: 同一进程启动 session 内，驱动防护状态日志必须唯一且结论一致
修复两类 bug：
  1) _log_driver_protection_status 无一次性 guard，被 A 和 B 两条路径
     各调用一次产生矛盾（A 用 _kernel_protection_active 宽松 = OK；
     B 用桥 query_status 严格 = NOT OK → 先后输出 OK + WARN）
  2) A/B 两条路径判定优先级/数据源不一致："真激活"要统一同时
     满足 (_kernel_protection_active OR 桥 available + enable + pid_set)
     否则降级；不能 A 取宽松、B 取严格
"""

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class TestDriverStatusLogIdempotent(unittest.TestCase):
    def test_once_guard_in_method(self):
        """_log_driver_protection_status 自身必须持有一次性 guard，
        不依赖外部 `initRequested` 中设置的 _driver_status_logged。"""
        path = os.path.join(ROOT, 'ui', 'webview', 'bridge.py')
        with open(path, 'r', encoding='utf-8') as f:
            src = f.read()

        # 定位函数体
        m = re.search(
            r"(?m)^    def _log_driver_protection_status\(self\):\n(.*?)(?=\n    @|    def |\nclass |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "找不到 _log_driver_protection_status 定义")
        body = m.group(1)
        # 函数进入时应检查 "driver status 已记录" 类 guard 并在方法内部设 True
        # 允许的模式: `if getattr(self, '_driver_status_logged', False): return`
        # 或 `self._driver_status_logged` 之类的布尔守卫
        guard = bool(re.search(
            r"_driver_status_logged\s*:", body) or
            re.search(r"getattr\(self,\s*['\"]_driver_status_logged['\"]\s*,\s*False\)\s*:",
                       body))
        self.assertTrue(guard,
                        "_log_driver_protection_status 必须自身包含一次性 guard，"
                        "不能依赖外部调用点的 guard，否则两次不同来源调用都会写日志。")
        # guard 命中后必须 return / 立刻结束写 log
        self.assertRegex(body,
                         r"(?s)"
                         r"getattr\(self,\s*['\"]_driver_status_logged['\"]\s*,\s*False\)"
                         r"\s*:\s*\n\s+return",
                         "_log_driver_protection_status guard 命中后必须 return。")
        # 函数内部在写任意 _add_activity 之前必须 set guard=True
        set_guard_idx = body.find("_driver_status_logged = True")
        first_activity_idx = body.find("_add_activity(")
        self.assertGreater(set_guard_idx, 0, "方法内部缺少 `_driver_status_logged = True` 赋值")
        self.assertGreater(first_activity_idx, 0, "方法内部缺少 _add_activity 输出")
        self.assertLess(set_guard_idx, first_activity_idx,
                        "必须在首个 _add_activity 之前就置 `_driver_status_logged = True`，"
                        "否则并发重入仍可能双写。")

    def test_log_uses_unified_truth(self):
        """OK 分支判定标准必须统一：
        - A. `_kernel_protection_active` 为真
        - OR B. 驱动桥 available 且 query_status 同时 enable + pid_set
        两者任一成立都应归到同一个"已激活"输出文案，用统一的 is_active 变量。
        不能先查 A 直接 return（不用桥复核），桥复核单独分支（与 A 矛盾）。"""
        path = os.path.join(ROOT, 'ui', 'webview', 'bridge.py')
        with open(path, 'r', encoding='utf-8') as f:
            src = f.read()
        m = re.search(
            r"(?m)^    def _log_driver_protection_status\(self\):\n(.*?)(?=\n    @|    def |\nclass |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group(1)

        # 必须出现统一真值：先从 self_protection 拿到 kernel_active
        # （其定义必须引用 _kernel_protection_active），
        # 再以 is_active = kernel_active OR (桥端到端) 合取
        has_kernel_var = bool(
            re.search(
                r"kernel_active\s*=\s*bool\([\s\S]*?_kernel_protection_active",
                body)
        )
        has_is_active = bool(re.search(r"(?m)^\s+is_active\s*=", body))
        self.assertTrue(has_kernel_var and has_is_active,
                        "必须引入统一真值 kernel_active（来自 SelfProtection） "
                        "+ is_active = kernel_active OR (桥 available + enable + pid_set)，"
                        "避免 A/B 路径双重标准。"
                        f" kernel_var={has_kernel_var}, is_active_var={has_is_active}")

        # "真激活"输出只能出现一处文案（成功），不能有"优先 1 单独的" + "优先 2 单独的"各写一条
        success_msg_regex = r"内核驱动防护已激活|驱动已加载，内核进程保护运行中"
        matches = list(re.finditer(success_msg_regex, body))
        # 统一后成功文案合并只能保留一处 _add_activity 出口
        self.assertEqual(len(matches), 1,
                         f"成功文案数量应=1（统一出口），当前 {len(matches)} 处："
                         f"{[mm.group(0) for mm in matches]}")

        # "降级 / 未加载"出口只能有一个合并分支，不得再沿用 "先看 self_protection
        # 直接 return（不复核桥）然后桥分支各自写一条"的结构
        degraded_keys = ("内核驱动不可用，已降级为用户态 DACL 进程保护",
                         "内核驱动未加载")
        degraded_found = [k for k in degraded_keys if k in body]
        self.assertEqual(len(degraded_found), 2,
                         "降级分支仍需保留 2 级文案（有 DACL / 无 DACL）但必须在统一真值判定之后，"
                         f"当前缺失 {set(degraded_keys)-set(degraded_found)}")


if __name__ == '__main__':
    unittest.main()
