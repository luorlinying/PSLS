# -*- coding: utf-8 -*-
"""
TDD - 驱动加载状态日志缺失问题（最近活动中看不到驱动防护条目）

根因：initRequested L3228-3233 里在 QTimer.singleShot(8s, _log_driver_protection_status)
之前先把 self._driver_status_logged = True 提前占了 guard；
而 _log_driver_protection_status L3102 一进来就 check guard→直接 return，
导致延迟 8 秒后的调用被静默吃掉，驱动日志一条都不写。

期望：
  1) initRequested 调度延迟 8s 记录时，不得自己抢占 guard（否则延迟回调被吃）。
  2) guard 应该是 _log_driver_protection_status 方法内的终身唯一 guard，
     任何外部调用路径（驱动终态轮询 _finalize_driver_and_launch_ready /
     initRequested 延迟 8s / fallback 回退机制）都公平竞争这个 guard，
     首个到达的调用者真正写日志，之后所有调用被去重。
  3) 单次运行过程中，无论上述 3 个入口怎么交叉调用，驱动活动日志条目
     要么 0 条（非 win32）要么 1 条（win32），绝不多也绝不因抢占为 0 条。
"""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

BRIDGE = os.path.join(ROOT, 'ui', 'webview', 'bridge.py')


def read_bridge():
    with open(BRIDGE, 'r', encoding='utf-8') as f:
        return f.read()


class TestDriverStatusLogNotMissing(unittest.TestCase):

    # ------------------------------------------------------------------ A -----
    def test_init_requested_does_not_preoccupy_guard(self):
        """
        initRequested 调度延迟 8s _log_driver_protection_status 时，
        禁止在 QTimer 之前自己把 _driver_status_logged = True；
        那会导致 8 秒后的回调被 guard 拦截，驱动日志终身 0 条。
        """
        src = read_bridge()
        m = re.search(
            r"def initRequested\(self\):\n(?P<body>.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "initRequested 定义未找到")
        body = m.group('body')

        idx_shot = body.find('QTimer.singleShot(8000, self._log_driver_protection_status)')
        # 另一种写法：lambda / 带参数，找不到就泛化找 8000
        if idx_shot < 0:
            m2 = re.search(r"QTimer\.singleShot\(\s*8000\s*,\s*.*_log_driver_protection_status",
                           body)
            self.assertIsNotNone(
                m2, "initRequested 中未调度 8s 延迟的 _log_driver_protection_status；"
                    "驱动会错过启动初期的状态发布。")
            idx_shot = m2.start()

        # 在 singleShot(8000, ...) 之前的 early 切片里，
        # 绝不能出现【有效代码行上的】 _driver_status_logged = True 抢占式赋值。
        # 【注意】必须剥离注释行（# 起），否则注释里描述 bug 的文字
        # 「self._driver_status_logged = True」会被误匹配。
        early = body[:idx_shot]
        # 逐行处理：去掉每行 # 及其之后内容，空行保留
        early_no_comment = '\n'.join(
            ln.split('#', 1)[0] for ln in early.split('\n'))
        preoccupy = re.findall(
            r"self\._driver_status_logged\s*=\s*True", early_no_comment)
        self.assertEqual(
            len(preoccupy), 0,
            "initRequested 在调度 8s 延迟驱动日志记录前，自己先把 "
            "_driver_status_logged = True 占了 guard → 8 秒后 "
            "_log_driver_protection_status 一进来就 return，驱动日志 "
            "一条都写不出来。请删除 initRequested 中的 guard 抢占赋值，"
            "改为让 _log_driver_protection_status 方法内部统一管去重。")

    # ------------------------------------------------------------------ B -----
    def test_log_method_owns_guard_for_all_callers(self):
        """
        _log_driver_protection_status 必须自己持有终身 guard，
        让 驱动终态轮询/initRequested 8s/fallback 三个入口都公平竞争，
        先到者写，后到者 return。否则就会出现
        「有的入口写两次、有的入口被其他入口先占住 guard 导致根本不写」
        的时序不一致。
        """
        src = read_bridge()
        m = re.search(
            r"def _log_driver_protection_status\(self\):\n"
            r"(?P<body>.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "_log_driver_protection_status 未找到")
        body = m.group('body')

        # 方法最开头应该用 getattr(... False) 做 return；紧接着自己 guard=True
        # 返回 true 表示存在该 guard 三段式
        lines = [ln for ln in body.split('\n') if ln.strip()]
        head = '\n'.join(lines[:8])
        has_early_return = bool(
            re.search(r"if getattr\(self,\s*'_driver_status_logged'\s*,\s*False\)\s*:\s*\n"
                      r"\s*return", body))
        has_guard_set = bool(
            re.search(r"self\._driver_status_logged\s*=\s*True", body))
        self.assertTrue(
            has_early_return and has_guard_set,
            "_log_driver_protection_status 开头必须：先 getattr 查 guard 直接 return；"
            "随后 guard=True。这是让所有入口（_finalize_driver_and_launch_ready/"
            "initRequested 延迟/fallback 回退）共用唯一去重的基础。")

    # ------------------------------------------------------------------ C -----
    def test_finalize_driver_calls_log_method(self):
        """驱动终态判定 _finalize_driver_and_launch_ready 必须调用
        _log_driver_protection_status（这是启动期驱动日志的主入口）。"""
        src = read_bridge()
        m = re.search(
            r"def _finalize_driver_and_launch_ready\(self\):\n"
            r"(?P<body>.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group('body')
        self.assertTrue(
            '_log_driver_protection_status()' in body
            or re.search(r"_log_driver_protection_status\s*\(", body),
            "_finalize_driver_and_launch_ready 必须调用 _log_driver_protection_status，"
            "否则 driver.done 阶段不会把驱动状态写入最近活动。")


if __name__ == '__main__':
    unittest.main()
