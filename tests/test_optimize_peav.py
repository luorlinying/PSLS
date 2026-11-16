# -*- coding: utf-8 -*-
"""优化 ① ApiHash 证据 / ③ study-engine / ④ 统一置信 的单元测试"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine.threat_scorer import (  # noqa: E402
    ThreatScorer, compute_confidence, verdict_from_confidence,
    confirm_suspicious, CONF_MALWARE, CONF_SUSPICIOUS,
)
from engine.api_evidence import (  # noqa: E402
    compute_api_evidence, score_imports, score_dll_weighted,
)
from engine.study_engine import (  # noqa: E402
    StudyEngine, MIN_SUPPORT,
)


class TestThreatScorer(unittest.TestCase):
    def setUp(self):
        self.s = ThreatScorer()

    def test_confirmed_signature_is_malware(self):
        conf = self.s.compute_confidence({'signature_mal': True})
        self.assertGreaterEqual(conf, CONF_MALWARE)

    def test_trusted_signer_suppresses(self):
        conf = self.s.compute_confidence({'trusted_signer': True, 'rule_medium': 3})
        self.assertLess(conf, CONF_SUSPICIOUS)
        self.assertLess(conf, 10.0)

    def test_signature_benign_suppresses(self):
        conf = self.s.compute_confidence({'signature_benign': True, 'pe_score': 80})
        self.assertLess(conf, CONF_SUSPICIOUS)

    def test_empty_evidence_is_clean(self):
        conf = self.s.compute_confidence({})
        self.assertLess(conf, CONF_SUSPICIOUS)

    def test_weak_rule_only_below_suspicious(self):
        # 单条 low 规则 + 无其他证据 -> 不足以维持 suspicious(降误报核心)
        conf = self.s.compute_confidence({'rule_low': 1})
        self.assertLess(conf, CONF_SUSPICIOUS)

    def test_medium_rule_with_ml_boosts(self):
        # medium 规则 + ML 中危 + PE 中危 -> 跨入 suspicious
        conf = self.s.compute_confidence({
            'rule_medium': 2, 'ml_susp_prob': 0.6, 'pe_score': 40,
        })
        self.assertGreaterEqual(conf, CONF_SUSPICIOUS)

    def test_study_benign_reduces(self):
        base = self.s.compute_confidence({'rule_medium': 2, 'ml_susp_prob': 0.6})
        reduced = self.s.compute_confidence(
            {'rule_medium': 2, 'ml_susp_prob': 0.6, 'study': 'benign'})
        self.assertLess(reduced, base)

    def test_verdict_bands(self):
        self.assertEqual(verdict_from_confidence(90), 'malware')
        self.assertEqual(verdict_from_confidence(60), 'suspicious')
        self.assertEqual(verdict_from_confidence(30), 'clean')
        self.assertTrue(confirm_suspicious(60))
        self.assertFalse(confirm_suspicious(30))


class TestApiEvidence(unittest.TestCase):
    def test_empty_pe_analysis(self):
        self.assertEqual(compute_api_evidence({}), 0.0)
        self.assertEqual(compute_api_evidence(None), 0.0)

    def test_no_suspicious_imports(self):
        self.assertEqual(compute_api_evidence({'suspicious_imports': []}), 0.0)

    def test_high_risk_imports_score(self):
        apis = ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory']
        ev = score_imports([{'name': a} for a in apis])
        self.assertGreater(ev, 15.0)

    def test_single_weak_halved(self):
        single = score_imports(['CreateRemoteThread'])
        triple = score_imports(['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory'])
        self.assertLess(single, triple)

    def test_dll_weight_thresholds(self):
        self.assertEqual(score_dll_weighted(5), 0.0)
        self.assertEqual(score_dll_weighted(40), 12.0)
        self.assertGreater(score_dll_weighted(20), 0.0)

    def test_capped(self):
        many = ['CreateRemoteThread'] * 50 + ['VirtualAllocEx', 'WriteProcessMemory',
                                              'SetWindowsHookEx', 'RegSetValueEx', 'WinHttpOpen']
        self.assertLessEqual(score_imports(many), 45.0)


class TestStudyEngine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store_path = os.path.join(self.tmp, 'study.json')

    def test_add_and_match_exact_sha(self):
        e = StudyEngine(self.store_path)
        key = e.add_record(meta={'sha256': 'a' * 64, 'size': 100, 'ext': '.exe',
                                 'label': ''}, label='benign')
        self.assertIsNotNone(key)
        m = e.match(meta={'sha256': 'a' * 64, 'size': 100, 'ext': '.exe'})
        self.assertEqual(m['label'], 'benign')
        self.assertGreaterEqual(m['confidence'], 0.5)

    def test_conflict_dominant_label_wins(self):
        e = StudyEngine(self.store_path)
        e.add_record(meta={'sha256': 'b' * 64, 'size': 1, 'ext': '.dll'}, label='benign')
        e.add_record(meta={'sha256': 'b' * 64, 'size': 1, 'ext': '.dll'}, label='malicious')
        e.add_record(meta={'sha256': 'b' * 64, 'size': 1, 'ext': '.dll'}, label='malicious')
        m = e.match(meta={'sha256': 'b' * 64, 'size': 1, 'ext': '.dll'})
        self.assertEqual(m['label'], 'malicious')
        self.assertEqual(m['count'], 3)

    def test_no_support_returns_none(self):
        e = StudyEngine(self.store_path)
        # 缺少记录
        self.assertIsNone(e.match(meta={'sha256': 'c' * 64, 'size': 1, 'ext': '.exe'}))

    def test_confidence_grows_with_count(self):
        e = StudyEngine(self.store_path)
        for _ in range(5):
            e.add_record(meta={'sha256': 'd' * 64, 'size': 2, 'ext': '.exe'}, label='benign')
        m = e.match(meta={'sha256': 'd' * 64, 'size': 2, 'ext': '.exe'})
        self.assertEqual(m['label'], 'benign')
        self.assertGreater(m['confidence'], 0.9)

    def test_save_reload(self):
        e = StudyEngine(self.store_path)
        e.add_record(meta={'sha256': 'e' * 64, 'size': 3, 'ext': '.exe'}, label='malicious')
        e.save()
        e2 = StudyEngine(self.store_path)
        self.assertEqual(e2.size(), 1)
        m = e2.match(meta={'sha256': 'e' * 64, 'size': 3, 'ext': '.exe'})
        self.assertEqual(m['label'], 'malicious')

    def test_api_hist_variant_approx_match(self):
        # hash 不同(变种)但 size/ext/api 高度重叠 -> 近似匹配良性, 用于压制后续误报
        e = StudyEngine(self.store_path)
        e.add_record(meta={'sha256': 'f' * 64, 'size': 100, 'ext': '.exe',
                           'api_hist': [400, 410, 420, 430]}, label='benign')
        m = e.match(meta={'sha256': 'deadbeef' * 8, 'size': 100, 'ext': '.exe',
                          'api_hist': [400, 410, 420]})
        self.assertEqual(m['label'], 'benign')

    def test_api_hist_disjoint_no_match(self):
        e = StudyEngine(self.store_path)
        e.add_record(meta={'sha256': 'g' * 64, 'size': 200, 'ext': '.exe',
                           'api_hist': [400, 410, 420]}, label='benign')
        # API 完全不同 -> 不应近似命中
        self.assertIsNone(e.match(meta={'sha256': 'h' * 64, 'size': 200, 'ext': '.exe',
                                        'api_hist': [450, 460, 470, 480]}))

    def test_autosave_throttle_does_not_break_learning(self):
        e = StudyEngine(self.store_path)
        for i in range(3):
            e.add_record(meta={'sha256': f'{i:064d}', 'size': i + 1, 'ext': '.dll'},
                         label='benign')
        # 节流自动落盘不应抛错, 记录仍可达
        self.assertEqual(e.size(), 3)
        m = e.match(meta={'sha256': '1' * 64, 'size': 1, 'ext': '.dll'})
        self.assertEqual(m['label'], 'benign')


class TestStudyEngineIntegration(unittest.TestCase):
    """验证 scan_engine 侧的学习闭环接线(_study_api_hist / 判定->指纹映射)。"""

    def test_api_hist_bucket_extraction(self):
        from engine.scan_engine import ScanEngine
        hist = ScanEngine._study_api_hist({
            'suspicious_imports': [
                {'name': 'CreateRemoteThread'},
                {'name': 'VirtualAllocEx'},
                {'name': 'WriteProcessMemory'},
            ]})
        self.assertEqual(len(hist), 3)
        for b in hist:
            self.assertTrue(377 <= b < 512)

    def test_api_hist_empty_analysis(self):
        from engine.scan_engine import ScanEngine
        self.assertEqual(ScanEngine._study_api_hist(None), [])
        self.assertEqual(ScanEngine._study_api_hist({}), [])
        self.assertEqual(ScanEngine._study_api_hist({'suspicious_imports': []}), [])

    def test_api_hist_dedup(self):
        from engine.scan_engine import ScanEngine
        hist = ScanEngine._study_api_hist({
            'suspicious_imports': [
                {'name': 'CreateRemoteThread'},
                {'name': 'CreateRemoteThread'},
            ]})
        self.assertEqual(len(hist), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)