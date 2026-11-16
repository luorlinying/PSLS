# -*- coding: utf-8 -*-
"""
TDD: 驱动加载状态变化需实时通知到"最近活动"日志
（不可用 -> 已加载 时追加一条通知，已加载 -> 不可用 也通知；状态未变不重复写）

设计约束：
  - _log_driver_protection_status 保持启动期一次性判定（终身 guard），
    这是已有 test_driver_status_log.py 的语义，不能破坏。
  - 新增独立低频繁驱动状态监视器 _watch_driver_state_change：
    timer 间隔 ~5s，比较 _driver_state_cached 与当前驱动状态，
    变化时 _add_activity 追加一条，并更新缓存。
  - 启动成功后（首次驱动状态判定完成）再启动监视器，避免与首次判定重复写。
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


class TestDriverStateChangeNotification(unittest.TestCase):

    # ---------- 1) 监视器方法必须存在 ----------
    def test_watch_driver_state_change_method_exists(self):
        src = read_bridge()
        m = re.search(
            r"def _watch_driver_state_change\(self\):\n(?P<body>.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(
            m, "_watch_driver_state_change 方法不存在。需新增一个独立低频繁驱动"
            "状态监视器，监听 不可用->已加载 等状态变化并写入活动日志")

    # ---------- 2) 必须有缓存的驱动状态字段 ----------
    def test_driver_state_cached_field_exists(self):
        src = read_bridge()
        # 在 __init__ 里初始化 _driver_state_cached = None
        m = re.search(
            r"_driver_state_cached\s*(:\s*[^=]+)?=\s*None", src)
        self.assertIsNotNone(
            m, "缺少 `_driver_state_cached = None` 初始化字段。用于缓存上次驱动"
            "状态，比较变化以便去重")
        # 也应有变化日志的 guard（避免同一变化刷屏）
        m2 = re.search(r"_driver_state_last_text\s*=|_driver_state_change_logged\s*=",
                       src)
        self.assertTrue(
            m2, "缺少驱动状态变化去重字段（_driver_state_last_text 或 "
            "_driver_state_change_logged）")

    # ---------- 3) 状态变化时必须写活动日志 ----------
    def test_watch_method_writes_activity_on_change(self):
        src = read_bridge()
        m = re.search(
            r"def _watch_driver_state_change\(self\):\n(?P<body>.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group('body')
        # 必须调用 _add_activity（写"最近活动"）
        self.assertIn('_add_activity(', body,
                      "状态变化检测后必须调用 _add_activity 写入活动日志")
        # 必须有"已加载/已激活"文案与"不可用/未加载"文案两类
        self.assertTrue(
            re.search(r'已加载|已激活|运行中', body),
            "监视器需在驱动恢复后输出'已加载/运行中'的日志文案")
        self.assertTrue(
            re.search(r'不可用|未加载|降级|失败', body),
            "监视器需在驱动失效后输出'不可用/降级'的日志文案")

    # ---------- 4) 必须由独立低频繁 timer 驱动 ----------
    def test_watch_driver_timer_setup(self):
        src = read_bridge()
        self.assertIn('_driver_state_watch_timer', src,
                      "缺少 _driver_state_watch_timer 成员")
        # timer 间隔应 >= 3000ms（低频繁，避免频繁轮询驱动桥）
        m = re.search(r"_driver_state_watch_timer\.setInterval\((\d+)\)", src)
        self.assertIsNotNone(
            m, "_driver_state_watch_timer 未设置 setInterval")
        self.assertGreaterEqual(
            int(m.group(1)), 3000,
            f"驱动状态监视 timer 间隔 {m.group(1)}ms 过小；低频繁应在 >=3000ms，"
            f"避免每秒轮询驱动桥造成额外开销")
        # timer 必须 connect 到 _watch_driver_state_change
        self.assertIn('_driver_state_watch_timer.timeout.connect(self._watch_driver_state_change)',
                      src)


if __name__ == '__main__':
    unittest.main()