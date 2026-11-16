"""
TDD: 沙箱正在分析的进程不能再次被 _check_new_process 拉进沙箱。

失败因（现有代码）：
  - _sandbox_worker 只在 verdict==clean 时写 launch_scan_cache[exe]=clean，
    verdict!=clean 时**从不写**任何缓存或"分析中"标记。
  - SandboxAnalyzer._launch_sandboxed 通过 CreateProcessW 启动被测 exe
    （SUSPENDED → Job绑定 → Resume）是系统真正意义的进程创建 → ETW 会
    再次触发 _check_new_process。
  - _check_new_process 没有"正在被沙箱分析的路径"豁免 → 对沙箱内部 PID
    又走一次 _sandbox_then_release → 用户看到"同一 exe 多个 scanning/
    多次沙箱拦截"。

修复方向：
  1) ProcessProtection 新增 _sandbox_analyzing_paths 集合（thread-safe），
     在 _sandbox_worker 启动 SandboxAnalyzer.analyze 前登记、结束
     （无论成功异常）移除。
  2) _check_new_process 在快速路径最前面（白名单前）先查该集合：
     如果 exe 在 analyzing_paths（归一化路径匹配），或父进程链能追溯到
     "某个 analyzing exe 的 pid"，就直接 return（只记一条 debug 监测事件）。
  3) 不仅如此，verdict!=clean 后也需要写 analyzing_paths 保持到
     quarantine / emit block 完成，避免后续子进程（如 self-restart 副本）
     再次被沙箱处理。
"""

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class TestSandboxSelfBlockingFix(unittest.TestCase):
    def test_process_protection_has_analyzing_paths_registry(self):
        src = open(os.path.join(ROOT, 'engine', 'process_protection.py'),
                   'r', encoding='utf-8').read()
        # 必须有 analyzing_paths 集合 + lock 初始化（在 __init__）
        self.assertIn('_sandbox_analyzing_paths', src,
                      "缺少 _sandbox_analyzing_paths 注册表；"
                      "沙箱内部启动的被测进程会再次被自己拦截。")
        self.assertIn('_sandbox_analyzing_paths_lock', src,
                      "缺少 _sandbox_analyzing_paths_lock；并发下注册表不安全。")

    def test_sandbox_worker_registers_and_unregisters_path(self):
        """_sandbox_then_release._sandbox_worker 的 analyzer.analyze(exe)
        前后必须 wrap：`analyzing_paths.add(norm(exe))` → analyze → remove。
        即：调用 `_mark_sandbox_analyzing_start(exe)` / `_mark_sandbox_analyzing_end(exe)`
        或等价的 add/remove 包含在 with/try-finally 块中。"""
        src = open(os.path.join(ROOT, 'engine', 'process_protection.py'),
                   'r', encoding='utf-8').read()
        # 抓取 _sandbox_worker 中从"开始分析"日志到 analyzer=SandboxAnalyzer(...) 完成：
        # 分析豁免必须在这条边界之间完成（log 之后、SandboxAnalyzer.analyze 之前）。
        m = re.search(
            r"沙箱放行链路：开始分析 \{display\} \(\{exe\}\)'\n"
            r"(.*?)analyzer = SandboxAnalyzer\(config\)\s*\n"
            r"(?P<mid>.*?)(?=\n\s+# ---- 阶段 3a|\n\s+else:\s*# ---- 阶段 3b)",
            src, re.DOTALL)
        # 上一条用格式化字符串匹配可能不稳，下面降级：从开始分析 log 那行开始
        if m is None:
            m = re.search(
                r"沙箱放行链路：开始分析[\s\S]{0,100}?\n"
                r"(?P<before>.*?)(?:analyzer = SandboxAnalyzer\(config\))\s*\n"
                r"(?P<mid>.*?)(?=result = analyzer\.analyze\(exe\))",
                src, re.DOTALL)
            self.assertIsNotNone(m, "找不到 开始分析 → SandboxAnalyzer.analyze 的代码段")
            block_before_analyze = m.group('before') + m.group('mid')
        else:  # pragma: no cover
            block_before_analyze = m.group(1) + (m.group('mid') if 'mid' in m.groupdict() else '')

        m2 = re.search(r"result = analyzer\.analyze\(exe\)\n(.*?)(?=\n\s+if verdict == 'clean':)",
                        src, re.DOTALL)
        self.assertIsNotNone(m2, "找不到 analyzer.analyze 到 verdict 分支的上下文")
        block_after_analyze = m2.group(1)

        # analyze 前必须先"登记 analyzing"（集合操作或 helper 方法任一）
        has_mark = (
            '_sandbox_analyzing_paths' in block_before_analyze
            or '_mark_sandbox_analyzing' in block_before_analyze
        )
        self.assertTrue(
            has_mark,
            "analyzer.analyze(exe) 执行前，没有把 exe 加入沙箱分析豁免表；"
            "沙箱内 CreateProcessW 的二次启动会再次走拦截链路。")
        # analyze 之后（无论 clean/not clean）必须在 finally/单独 try/finally 里解除
        # 简化判定：在 worker 函数体末尾或紧邻 analyze 后的结果处理分支出现 remove / pop
        # 验证：在 _sandbox_worker 函数体里存在 analyzing_paths 的 pop/discard/remove/difference_update
        worker_end_match = re.search(
            r"result = analyzer\.analyze\(exe\)[\s\S]*?_sandbox_sem\.release\(\)",
            src)
        self.assertIsNotNone(worker_end_match, "找不到 worker 结尾 sem.release")
        worker_block = worker_end_match.group(0)
        discard_re = re.compile(
            r"_sandbox_analyzing_paths\s*\.\s*(?:discard|remove|pop|difference_update)\b"
            r"|_unmark_sandbox_analyzing\s*\(")
        self.assertTrue(
            discard_re.search(worker_block),
            "沙箱 worker 结束前没有移除 exe 的 analyzing 标记；"
            "标记会永久占据导致该路径后续无法被真正拦截。")

    def test_check_new_process_skips_sandbox_analyzing_paths(self):
        """_check_new_process 必须在快速放行早期（至少在 _sandbox_then_release
        之前）检查 analyzing_paths；命中就 return，不再挂起+重复扫描。"""
        src = open(os.path.join(ROOT, 'engine', 'process_protection.py'),
                   'r', encoding='utf-8').read()
        m = re.search(
            r"def _check_new_process\(self, pid: int, entry: dict\):"
            r"\n(.*?)(?=\n    # Windows 系统核心可执行文件白名单|\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "找不到 _check_new_process 定义")
        body = m.group(1)

        # 必须出现 _sandbox_analyzing_paths 的判定 + return
        self.assertIn('_sandbox_analyzing_paths', body,
                      "_check_new_process 快速放行路径未查 _sandbox_analyzing_paths；"
                      "沙箱内部启动子进程会被再次拦截。")
        idx_ref = body.find('_sandbox_analyzing_paths')
        idx_first_sandbox_call = body.find('_sandbox_then_release(')
        if idx_first_sandbox_call > 0:
            self.assertLess(idx_ref, idx_first_sandbox_call,
                            "analyzing_paths 判定必须出现在首次 _sandbox_then_release "
                            "调用之前，否则没有意义。")


if __name__ == '__main__':
    unittest.main()
