"""
TDD 测试: 验证三个启动期问题的修复

1. autostart-protection 可被重新初始化 (issue: 初始化后仍显示"引擎未初始化")
2. signatureCountUpdated 在 core init 完成和 initRequested 后会正确 emit
3. 驱动加载顺序: 自我保护(含驱动)应先于其他防护模块启动
"""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestTryReinitializeAutostart(unittest.TestCase):
    """autostart-protection / system-protection 必须在 _try_reinitialize_module 中有分支"""

    def test_try_reinitialize_module_handles_all_protection_modules(self):
        """toggleModule 的 engine_map 列出的模块，_try_reinitialize_module 必须全部支持"""
        # 读取 bridge.py 的源码解析
        bridge_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'ui', 'webview', 'bridge.py')
        with open(bridge_path, 'r', encoding='utf-8') as f:
            src = f.read()

        # 收集 engine_map 中的模块列表 (toggleModule 方法)
        import re
        engine_map_match = re.search(
            r"engine_map\s*=\s*\{([^}]+)\}", src, re.DOTALL)
        self.assertIsNotNone(engine_map_match, "engine_map 未找到")
        engine_map_body = engine_map_match.group(1)
        modules = re.findall(r"'([a-z-]+)'\s*:", engine_map_body)
        self.assertIn('autostart-protection', modules,
                      "engine_map 应包含 autostart-protection")
        self.assertIn('system-protection', modules,
                      "engine_map 应包含 system-protection")

        # 收集 _try_reinitialize_module 的 if/elif 模块
        reinit_fn_match = re.search(
            r"def _try_reinitialize_module\(self.*?:\n(.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(reinit_fn_match, "_try_reinitialize_module 未找到")
        reinit_body = reinit_fn_match.group(1)
        handled_modules = re.findall(r"module\s*==\s*'([a-z-]+)'", reinit_body)

        for m in modules:
            # notification 是轻量单例，可能不需要 reinit
            if m == 'notification':
                continue
            self.assertIn(m, handled_modules,
                          f"_try_reinitialize_module 缺少模块 {m} 的 reinit 分支 "
                          f"(engine_map 定义了但无法在 reinit 时创建)")


class TestSignatureCountEmit(unittest.TestCase):
    """签名数量必须在 initRequested 和 _on_core_init_done 完成后 push 给前端"""

    def test_initRequested_emits_signature_count(self):
        """initRequested 返回 initialData 时，signature 来自 signature_db；
        同时必须 emit signatureCountUpdated 信号（因为前端 sig-count UI 元素
        仅监听 signatureCountUpdated，不读取 initialData.signatures 显示 stat-signatures 的
        场景被 JS updateDashboardData 处理，但后续若 JS 重连/重渲染会丢失）"""
        bridge_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'ui', 'webview', 'bridge.py')
        with open(bridge_path, 'r', encoding='utf-8') as f:
            src = f.read()

        # initRequested 方法体
        import re
        init_req_match = re.search(
            r"def initRequested\(self\):\n(.*?)(?=\n    @pyqt|\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(init_req_match, "initRequested 未找到")
        body = init_req_match.group(1)
        # 必须有 signatureCountUpdated.emit 调用
        self.assertIn('signatureCountUpdated.emit', body,
                      "initRequested 必须 emit signatureCountUpdated，"
                      "否则前端首次渲染后若 updateDashboardData 先于 pyBridge 连接执行，"
                      "stat-signatures 会保持 0")

    def test_on_core_init_done_emits_signature_count(self):
        """_on_core_init_done 在写回 signature_db 后应 emit signatureCountUpdated"""
        bridge_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'ui', 'webview', 'bridge.py')
        with open(bridge_path, 'r', encoding='utf-8') as f:
            src = f.read()

        import re
        m = re.search(
            r"def _on_core_init_done\(self, result.*?:\n(.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "_on_core_init_done 未找到")
        body = m.group(1)
        # 在写回 self._signature_db 之后必须 emit 一次
        self.assertIn('signatureCountUpdated.emit', body,
                      "_on_core_init_done 写回签名库后必须 emit signatureCountUpdated，"
                      "否则前端已渲染完会显示 0 不刷新")


class TestDriverOrder(unittest.TestCase):
    """驱动加载应优先：_init_protection_modules 中 self-protection (含驱动安装/加载)
    必须在 process/file/system/realtime/autostart 之前，避免防护启动时驱动不可用"""

    def test_self_protection_before_other_modules(self):
        bridge_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'ui', 'webview', 'bridge.py')
        with open(bridge_path, 'r', encoding='utf-8') as f:
            src = f.read()

        import re
        # 防护模块实际 init+start 可能位置：
        #   a) 旧版：直接在 _init_protection_modules 内串行
        #   b) 新版优化（加速启动/防 Splash 卡死）：_init_protection_modules 只开
        #      后台线程，真实顺序代码位于 _start_protection_worker
        # 两个方法体都抽出来拼接搜索，确保两种写法都能测到"驱动首位"的时序约束。
        bodies = []
        m_init = re.search(
            r"def _init_protection_modules\(self\):\n(.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        if m_init:
            bodies.append(m_init.group(1))
        m_worker = re.search(
            r"def _start_protection_worker\(self\):\n(.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        if m_worker:
            bodies.append(m_worker.group(1))
        self.assertTrue(bodies, "_init_protection_modules / _start_protection_worker 均未找到")
        body = "\n".join(bodies)

        # 查找每个模块的初始化位置（通过 _src_xxx = '模块名' 行定位）
        # 顺序应当：自我保护 -> 其他模块（process/file/system/autostart/realtime/notification）
        tag_map = {
            '自我保护': "_src_sp",
            '进程保护': "_src_proc",
            '文件保护': "_src_file",
            '系统保护': "_src_sys",
            '自启动监测': "_src_auto",
            '实时防护': "_src_rt",
            '通知管理': "_src_nm",
        }
        positions = {}
        for label, tag in tag_map.items():
            idx = body.find(tag)
            if idx >= 0:
                positions[label] = idx
        # 至少要包含自我保护和其他模块
        self.assertIn('自我保护', positions,
                      "找不到自我保护初始化标记（驱动安装/SCM 等待必须放在"
                      "_start_protection_worker 的最前部，且先于其他模块）")
        self.assertTrue(len(positions) >= 4, f"找到的模块过少: {positions}")

        # 自我保护必须是第一个
        first_label = min(positions, key=lambda k: positions[k])
        self.assertEqual(
            first_label, '自我保护',
            f"自我保护必须最先初始化（含驱动安装/加载），当前顺序首位: {first_label}，"
            f"位置表: {positions}")


if __name__ == '__main__':
    unittest.main()
