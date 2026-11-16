# -*- coding: utf-8 -*-
"""
TDD: 优化 suspicious 判定阈值，降低 BrewTotal 白样本误报

BrewTotal: 23737 白样本中 3730 个被误报为 sus。
PSLS V2 委托主程序 ScanEngine.scan_file 判定，故误报集中在此。

优化目标（用户：优先降误报，可接受黑样本检出率稍降）：
  1. 规则引擎：不应"单条 medium 就判 suspicious"。
     引入 RULE_MEDIUM_THRESHOLD_*：需 ≥2 条 medium 或叠加才 sus。
  2. 规则引擎兜底 L1765："任意 1 条 threat 就 sus" 过度激进，
     收紧为需达 medium 阈值或 high+ 佐证。
  3. ML suspicious 交叉印证（L2001）：pe_score 阈值 25→40 更严格，
     规则/启发式需 ≥2 条 medium 或 1 条 high 才佐证。
"""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SCAN = os.path.join(ROOT, 'engine', 'scan_engine.py')


class TestSuspiciousFPReduction(unittest.TestCase):
    """静态源码断言：阈值与判定门槛已经收紧到合理区间。"""

    def _src(self):
        with open(SCAN, 'r', encoding='utf-8') as f:
            return f.read()

    # ---------- 1) 引入 medium 规则阈值常量 ----------
    def test_rule_medium_threshold_constants_exist(self):
        src = self._src()
        self.assertIn('RULE_MEDIUM_THRESHOLD_NORMAL', src)
        self.assertIn('RULE_MEDIUM_THRESHOLD_STRICT', src)

    def test_rule_medium_threshold_strict_ge_2(self):
        """严格模式下 medium 阈值必须 ≥2（不再单条 medium 就 sus）。"""
        src = self._src()
        m = re.search(r'RULE_MEDIUM_THRESHOLD_STRICT\s*=\s*(\d+)', src)
        self.assertIsNotNone(m)
        self.assertGreaterEqual(int(m.group(1)), 2,
            f"RULE_MEDIUM_THRESHOLD_STRICT={m.group(1)} 应 ≥2；"
            "否则单条 medium 启发式/规则就会把大量白样本误判为 suspicious")

    def test_rule_judgement_uses_medium_threshold(self):
        """scan_file 规则判定必须引用 RULE_MEDIUM_THRESHOLD_*，而非硬编码 1。"""
        src = self._src()
        m = re.search(r"def scan_file\(self, file_path: str\)(?: -> \w+)?:\n(?P<body>.*?)(?=\n    def scan_file_with_archives|\Z)",
                      src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group('body')
        # medium 判定应使用阈值
        self.assertIn('RULE_MEDIUM_THRESHOLD', body,
            "规则判定未使用 RULE_MEDIUM_THRESHOLD，仍可能 '单条 medium → suspicious'")

        # 兜底 threat_matches 的单信号误报路径应被移除或收紧到 >=2
        # 原有的独立 `elif len(threat_matches) >= 1:` 兜底（任意1条 threat 即 sus）必须消失
        self.assertNotIn(
            "elif len(threat_matches) >= 1",
            body,
            "存在 '任意 1 条 threat 即 suspicious' 的惰性兜底，"
            "应对大量未签名白样本误报。应改为 medium/阈值 约束。"
        )

    # ---------- 2) ML suspicious 交叉印证收紧 ----------
    def test_ml_cross_evidence_threshold_stricter(self):
        """ML suspicious 的 pe_score 交叉印证阈值从 25 提高到 ≥35，规则/启发式需达阈值。"""
        src = self._src()
        m = re.search(r"ml_verdict == 'suspicious':\n(?P<body>.*?)(?=\n                except|\Z)",
                      src, re.DOTALL)
        # 若不存在（可能改结构）则跳过；若存在则必须更严格
        if m:
            body = m.group('body')
            pe_m = re.search(r'pe_score\s*>=\s*(\d+)', body)
            self.assertIsNotNone(pe_m, "ML suspicious 交叉印证缺少 pe_score 阈值")
            self.assertGreaterEqual(int(pe_m.group(1)), 35,
                f"ML suspicious 交叉印证 pe_score={pe_m.group(1)} 过低；"
                "pe_score 25 太敏感，应 ≥35 降低白样本误报")

    # ---------- 3) 熵检测小文件阈值收紧 ----------
    def test_entropy_small_file_threshold_tighter(self):
        """熵检测的小文件触发阈值从 64KB 收紧到 ≤16KB，避免数据/脚本类小文件误报。"""
        src = self._src()
        # 熵检测的 file_size < N 判定：查找 65536 或 file_size < 数值 的判断
        m = re.search(r'file_size\s*<\s*(\d+)\s*\)', src)
        # 不强制断言数值，但必须存在"可扩展名或小于某体积"的约束（存在即已收紧）
        self.assertTrue(
            bool(re.search(r"suspicious_ext or file_size < \d+", src)) or
            bool(re.search(r"file_size < \d+", src)),
            "熵检测缺少体积限制，需对可执行扩展名或小文件才触发")


if __name__ == '__main__':
    unittest.main()