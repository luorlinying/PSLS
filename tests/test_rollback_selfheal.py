# -*- coding: utf-8 -*-
"""勒索回滚"静默未初始化"的自愈与可观测回归测试。

历史缺陷（VM 日志实证）：
  · 总初始化未覆盖到回滚那段时，`_rollback_manager` 一直是 None；
  · `setRansomwareRollbackEnabled` 对 None 只翻标记、什么都不做；
  · 于是"设置页开关显示已启用，实则没有 worker / 没有快照 / 日志里一条回滚记录都没有"。

本测试锁定：开关启用与状态查询两条路径都会**自动补齐**管理器并启动快照线程。
"""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ui.webview.bridge as B  # noqa: E402


class _FakeManager:
    def __init__(self, running=False):
        self.set_enabled_calls = []
        self.start_calls = 0
        self._running = running
        self.generation_id = 1

    @property
    def is_running(self):
        return self._running

    def start(self):
        self.start_calls += 1
        self._running = True
        return True

    def set_enabled(self, v):
        self.set_enabled_calls.append(bool(v))
        return True

    def get_stats(self):
        return {'running': self._running, 'enabled': True}


class _Stub:
    def __init__(self, rollback_manager=None, module_enabled=True):
        self._rollback_manager = rollback_manager
        self._module_states = {'ransomware-rollback': module_enabled}
        self.activities = []
        self.created = 0

    def _persist_module_states(self):
        pass

    def _add_activity(self, *a, **k):
        self.activities.append(a)

    def _try_reinitialize_module(self, module, attr):
        """模拟懒初始化：创建管理器（真实实现里还会 _wire_rollback_manager）。"""
        self.created += 1
        setattr(self, attr, _FakeManager())


class TestRollbackSelfHeal(unittest.TestCase):

    def test_toggle_enable_creates_manager_and_starts(self):
        stub = _Stub(rollback_manager=None, module_enabled=True)
        B.PyBridge.setRansomwareRollbackEnabled(stub, True)
        self.assertEqual(stub.created, 1, '开关启用时未按需创建管理器')
        mgr = stub._rollback_manager
        self.assertIsNotNone(mgr)
        self.assertEqual(mgr.set_enabled_calls, [True])
        self.assertEqual(mgr.start_calls, 1, '补齐后未启动快照线程')

    def test_toggle_does_not_create_when_disabling(self):
        stub = _Stub(rollback_manager=None, module_enabled=False)
        B.PyBridge.setRansomwareRollbackEnabled(stub, False)
        self.assertEqual(stub.created, 0, '关闭开关不应触发创建')

    def test_status_query_triggers_background_ensure(self):
        """状态查询槽已接线到自愈 helper（pyqtSlot 无法用非 QObject 桩调用，
        故此处断言 helper 行为 + 源码接线）。"""
        stub = _Stub(rollback_manager=None, module_enabled=True)
        B.PyBridge._ensure_rollback_manager_bg(stub)
        self.assertEqual(stub.created, 1, '自愈 helper 未创建管理器')
        self.assertIsNotNone(stub._rollback_manager)
        self.assertEqual(stub._rollback_manager.start_calls, 1)
        # 接线断言：状态槽里必须调用自愈 helper
        import inspect
        src = inspect.getsource(B.PyBridge.getRansomwareRollbackStatus)
        self.assertIn('_ensure_rollback_manager_bg', src)
        self.assertIn('ransomware-rollback', src)


if __name__ == '__main__':
    unittest.main()