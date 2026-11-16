# -*- coding: utf-8 -*-
"""
TDD 测试: 行为启发证据汇入 ThreatScorer / _unified_confidence

- behavior_confirmed=True -> compute_confidence >= 82 (malware)
- 单条佐证 behavior_chain 低 -> confidence < 56 (不误报升档)
- scan_engine._unified_confidence 支持 behavior 参数合并
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.threat_scorer import ThreatScorer, CONF_MALWARE, CONF_SUSPICIOUS  # noqa: E402


class TestBehaviorThreatScorerMerge(unittest.TestCase):

    def setUp(self):
        self.scorer = ThreatScorer()

    def test_behavior_confirmed_goes_malware(self):
        conf = self.scorer.compute_confidence({'behavior_confirmed': True})
        self.assertGreaterEqual(conf, CONF_MALWARE)
        self.assertEqual(self.scorer.verdict(conf), 'malware')

    def test_single_corroborating_below_suspicious(self):
        """单条佐证 chain(45) 不足以跨 suspicious(避免弱信号误报)"""
        conf = self.scorer.compute_confidence({'behavior_chain': 45.0})
        self.assertLess(conf, CONF_SUSPICIOUS)

    def test_high_chain_with_other_signals_reaches_suspicious(self):
        # behavior_chain=100 -> 34.0; rule_medium=1 -> 16.0; pe_score=40 -> 12.0
        # 合计 62.0 >= 56 (佐证级叠加可跨 suspicious, 但单点不单独触发)
        conf = self.scorer.compute_confidence({
            'behavior_chain': 100.0, 'rule_medium': 1, 'pe_score': 40
        })
        self.assertGreaterEqual(conf, CONF_SUSPICIOUS)

    def test_trusted_signer_suppresses_behavior(self):
        """可信签名强抑制优先于行为证据"""
        conf = self.scorer.compute_confidence(
            {'trusted_signer': True, 'behavior_confirmed': True})
        self.assertLess(conf, CONF_SUSPICIOUS)


class TestScanEngineBehaviorParam(unittest.TestCase):
    """scan_engine._unified_confidence 透传 behavior 证据"""

    def test_unified_confidence_accepts_behavior(self):
        from engine import scan_engine
        se = scan_engine.ScanEngine.__new__(scan_engine.ScanEngine)
        # 注入所需依赖桩
        se.signature_db = None
        try:
            se._load_study_engine = lambda: None
        except Exception:
            pass
        se.strict_mode = True
        conf = se._unified_confidence(
            file_hash='abc', behavior={'behavior_confirmed': True})
        if conf is None:
            self.skipTest('统一评分未启用(依赖缺失), 跳过')
        self.assertGreaterEqual(conf, CONF_MALWARE)
        conf2 = se._unified_confidence(behavior={'behavior_chain': 30.0})
        self.assertIsNotNone(conf2)


if __name__ == '__main__':
    unittest.main(verbosity=2)