"""
TDD 验证沙箱拦截后文件确实会被隔离（修复"加锁在隔离前、阻塞隔离动作"的竞态）

失败原因（现有代码）：
  - 阶段 3b 在调用 quarantine_file(exe) 之前先调用 _lock_file_exclusive(exe, share=0)
    把 exe 锁住，且登记到 _sandbox_locks 直到隔离调用返回后才 release。
  - quarantine_file 内部要 prep_for_remove / encrypt / move / remove / rename —
    全都会因"文件被本进程独占(share=0)"失败 → 隔离实际不成功 → 用户体感
    "沙箱弹窗说已拦截，但隔离区没东西，原 exe 仍在原地可复制/移动"。
"""

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class TestSandboxQuarantineOrdering(unittest.TestCase):
    def test_quarantine_must_happen_before_lock_reaquired(self):
        """阶段 3b：
        1) _lock_file_exclusive 必须在 Terminate 之前完成（防止用户抢启动）；
        2) 在真正调用 quarantine_file(exe) 之前，必须先 release_sandbox_lock
           / 关闭独占句柄，否则自己独占 share=0 阻塞隔离的
           encrypt/move/remove/rename 成功执行；
        3) quarantine_file 结束后，若仍需占用（如隔离失败等 UI 处置），再重新加锁。

        用源码顺序断言：
          - _lock_file_exclusive 出现一次（正确）
          - 在 quarantine_file(...) 调用前，必须先出现 release_sandbox_lock(exe)
            或等效"显式释放锁句柄"的代码，否则隔离会被自己锁死。
        """
        path = os.path.join(ROOT, 'engine', 'process_protection.py')
        with open(path, 'r', encoding='utf-8') as f:
            src = f.read()

        # 抓取阶段 3b 从 [修复 2] 到 _emit_sandbox_block 前的代码段
        m = re.search(
            r"# \[修复 2\](.*?)self\._emit_sandbox_block\(",
            src, re.DOTALL)
        self.assertIsNotNone(m, "找不到阶段 3b 锁 → 隔离 → emit 的代码段")
        block = m.group(1)

        lock_idx = block.find('_lock_file_exclusive(exe')
        quarantine_idx = block.find('quarantine_file(')
        self.assertGreater(lock_idx, 0, "找不到加锁调用")
        self.assertGreater(quarantine_idx, 0, "找不到隔离调用")
        self.assertLess(lock_idx, quarantine_idx,
                        "加锁必须在隔离之前（防止用户抢启动）")

        # 关键：在 [lock_idx, quarantine_idx) 半开区间内必须出现"释放当前锁"
        release_before_q = None
        # 匹配 release_sandbox_lock(exe) / fh.close() 等释放动作
        candidates = list(re.finditer(
            r"release_sandbox_lock\(exe\)"
            r"|\blocked_fh\.close\(\)"
            r"|\btry:\s*\n\s*locked_fh\.close",
            block, re.MULTILINE | re.DOTALL))
        for c in candidates:
            if lock_idx < c.start() < quarantine_idx:
                release_before_q = c.group(0)
                break
        self.assertIsNotNone(
            release_before_q,
            "阶段 3b 在 quarantine_file(exe) 之前，必须显式释放刚刚登记的独占锁"
            "（share=0），否则 quarantine_file 的复制/加密/删除/改名都会被"
            "PSLS 自己的句柄阻塞，导致'沙箱已拦截但未隔离'的假象。"
            f"\nlock_idx={lock_idx}, quarantine_idx={quarantine_idx}"
            f"\n候选释放调用: {[c.group(0) for c in candidates] if candidates else '（无）'}")

    def test_bridge_sandbox_block_popup_forces_quarantine_regardless_of_action(self):
        """桥层 _on_sandbox_block_popup_requested：
        沙箱判定非 clean（malware/suspicious/error/skipped）时，无论处理策略
        （auto/notify/ignore）都必须兜底隔离样本文件，失败需延迟重试。
        不应再把兜底隔离限制在 _rt_suspicious_action == 'auto' 下。"""
        path = os.path.join(ROOT, 'ui', 'webview', 'bridge.py')
        with open(path, 'r', encoding='utf-8') as f:
            src = f.read()

        m = re.search(
            r"def _on_sandbox_block_popup_requested\(self, block_json: str\):"
            r"\n(.*?)(?=\n    def |\n    @|\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group(1)
        # 必须检查 quarantined 字段
        self.assertIn("quarantined", body,
                      "popup 处理函数未读取 block_data.quarantined；"
                      "无法区分'已隔离成功'和'只拦截未隔离'。")
        # 必须调用隔离管理器
        self.assertIn("quarantine_file(", body,
                      "必须在拦截弹窗处理中兜底调用 quarantine_manager.quarantine_file。")
        # 强制隔离：不得再以 _rt_suspicious_action == 'auto' 作为前置条件
        auto_gate = re.search(
            r"_rt_suspicious_action(?:.|\n)*?==\s*['\"]auto['\"]", body)
        self.assertIsNone(
            auto_gate,
            "沙箱拦截兜底隔离不应再受 _rt_suspicious_action=='auto' 限制，"
            "应为强制隔离（不论处理策略）。")
        # 条件应显式排除 clean 判定
        self.assertIn("verdict != 'clean'", body,
                      "强制隔离条件应排除 clean 判定（clean 属放行，不隔离）。")
        # 失败需延迟重试
        self.assertIn("range(3)", body, "隔离失败应包含重试循环。")


if __name__ == '__main__':
    unittest.main()
