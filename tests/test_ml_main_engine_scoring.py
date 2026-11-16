# -*- coding: utf-8 -*-
"""ML 主引擎(LightGBM/EMBER v2)直判接入 ThreatScorer + scan_engine ML 门槛 的单元测试。

背景：brewtotal 平台评测检出率 29%。根因之一是 ML 主引擎判定走弱信号加权
(_GAIN_ML_MALWARE=70)，数学上限 70 < CONF_MALWARE=82，主引擎自己的
malware 判定永远无法变成 malware verdict；且扫描 worker 仅在 file_status=='clean'
时才调用 ML，已判 suspicious 的文件再也不会被 ML 升级。

本测试锁定修复后的行为：
- 主引擎 ('malware', 0.95/0.70) -> verdict 必须是 malware（此前失败的核心断言）
- 主引擎 ('suspicious', 0.55)    -> verdict 必须是 suspicious（不被丢成 clean）
- 回退引擎(128 维 MLP)加权语义保持旧行为
- scan_engine 在 file_status == 'suspicious' 时也会调用 ML（且每文件仅一次）
"""

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine.threat_scorer import (  # noqa: E402
    ThreatScorer, CONF_MALWARE, CONF_SUSPICIOUS,
)


class TestMLMainEngineDirectVerdict(unittest.TestCase):
    def setUp(self):
        self.s = ThreatScorer()

    def test_main_engine_malware_095_is_malware(self):
        conf = self.s.compute_confidence(
            {'ml_main_verdict': 'malware', 'ml_main_prob': 0.95})
        self.assertGreaterEqual(conf, CONF_MALWARE)
        self.assertEqual(self.s.verdict(conf), 'malware')

    def test_main_engine_malware_070_not_downgraded(self):
        """p=0.70（校准 malware 下限）必须仍判 malware，不得被降级。"""
        conf = self.s.compute_confidence(
            {'ml_main_verdict': 'malware', 'ml_main_prob': 0.70})
        self.assertGreaterEqual(conf, CONF_MALWARE)
        self.assertEqual(self.s.verdict(conf), 'malware')

    def test_main_engine_malware_monotonic_in_prob(self):
        low = self.s.compute_confidence(
            {'ml_main_verdict': 'malware', 'ml_main_prob': 0.70})
        high = self.s.compute_confidence(
            {'ml_main_verdict': 'malware', 'ml_main_prob': 1.0})
        self.assertGreater(high, low)

    def test_main_engine_suspicious_055_is_suspicious(self):
        conf = self.s.compute_confidence(
            {'ml_main_verdict': 'suspicious', 'ml_main_prob': 0.55})
        self.assertGreaterEqual(conf, CONF_SUSPICIOUS)
        self.assertLess(conf, CONF_MALWARE)
        self.assertEqual(self.s.verdict(conf), 'suspicious')

    def test_main_engine_suspicious_040_at_lower_bound(self):
        conf = self.s.compute_confidence(
            {'ml_main_verdict': 'suspicious', 'ml_main_prob': 0.40})
        self.assertGreaterEqual(conf, CONF_SUSPICIOUS)
        self.assertLess(conf, CONF_MALWARE)

    def test_main_engine_suspicious_never_reaches_malware(self):
        """suspicious 上限必须严格 < 82，避免越档。"""
        conf = self.s.compute_confidence(
            {'ml_main_verdict': 'suspicious', 'ml_main_prob': 0.6999})
        self.assertLess(conf, CONF_MALWARE)

    def test_suppression_still_wins_over_main_engine(self):
        """可信签名/白名单强抑制优先于主引擎直判。"""
        conf = self.s.compute_confidence({
            'trusted_signer': True,
            'ml_main_verdict': 'malware', 'ml_main_prob': 0.99,
        })
        self.assertLess(conf, CONF_SUSPICIOUS)


class TestFallbackEngineSemanticsPreserved(unittest.TestCase):
    """非主引擎(回退)仍走 _GAIN_ML_* 加权语义，旧行为不得被破坏。"""

    def setUp(self):
        self.s = ThreatScorer()

    def test_fallback_ml_susp_alone_below_suspicious(self):
        conf = self.s.compute_confidence({'ml_susp_prob': 0.6})
        self.assertLess(conf, CONF_SUSPICIOUS)

    def test_fallback_ml_malware_alone_below_malware(self):
        # 70 * 0.9 = 63 < 82，保持旧的"弱信号"语义
        conf = self.s.compute_confidence({'ml_malware_prob': 0.9})
        self.assertLess(conf, CONF_MALWARE)

    def test_fallback_ml_boosts_with_other_signals(self):
        conf = self.s.compute_confidence({
            'rule_medium': 2, 'ml_susp_prob': 0.6, 'pe_score': 40})
        self.assertGreaterEqual(conf, CONF_SUSPICIOUS)


class TestUnifiedConfidenceWiring(unittest.TestCase):
    """scan_engine._unified_confidence 必须能把主引擎证据透传给 ThreatScorer。"""

    def _bare_engine(self):
        from engine import scan_engine
        se = scan_engine.ScanEngine.__new__(scan_engine.ScanEngine)
        se.signature_db = None
        se.strict_mode = True
        return se

    def test_unified_confidence_main_malware(self):
        se = self._bare_engine()
        conf = se._unified_confidence(
            file_hash='a' * 64, ml_main_verdict='malware', ml_main_prob=0.95)
        if conf is None:
            self.skipTest('统一评分未启用(依赖缺失)')
        self.assertGreaterEqual(conf, CONF_MALWARE)

    def test_unified_confidence_main_suspicious(self):
        se = self._bare_engine()
        conf = se._unified_confidence(
            file_hash='b' * 64, ml_main_verdict='suspicious', ml_main_prob=0.55)
        if conf is None:
            self.skipTest('统一评分未启用(依赖缺失)')
        self.assertGreaterEqual(conf, CONF_SUSPICIOUS)
        self.assertLess(conf, CONF_MALWARE)


class _FakeMLDetector:
    """记录调用次数的 ML 检测器桩。"""

    def __init__(self, verdict=None, source='lgb'):
        self.called = 0
        self._strict = False
        self._verdict = verdict
        self._source = source

    def set_strict_mode(self, enabled):
        self._strict = enabled

    def detect_with_context_with_source(self, file_path, **kwargs):
        self.called += 1
        return (self._verdict, self._source if self._verdict else None)

    def detect_with_context(self, file_path, **kwargs):
        self.called += 1
        return self._verdict

    def predict(self, file_path):
        self.called += 1
        return self._verdict


class TestWorkerCallsMLWhenSuspicious(unittest.TestCase):
    """文件已被判 suspicious 时，扫描 worker 仍必须调用 ML（可升级为 malware）。"""

    def setUp(self):
        from engine import scan_engine
        self.se = scan_engine
        self._saved = {}
        for name in (
            '_worker_db', '_worker_rule_engine', '_worker_pe_analyzer',
            '_worker_virus_identifier', '_worker_vi_enabled', '_worker_archive_scanner',
            '_worker_malware_hashes', '_worker_whitelist_cache', '_worker_heuristic_rules',
            '_worker_trusted_dirs', '_worker_executable_extensions', '_worker_min_file_size',
            '_worker_signature_verifier', '_worker_strict_mode', '_worker_self_excluded_dirs',
            '_worker_user_excluded_dirs', '_worker_oem_dir_keys', '_worker_ml_detector',
            '_worker_analysis_cache', '_scan_file_worker_heuristic',
        ):
            self._saved[name] = getattr(self.se, name, None)

    def tearDown(self):
        for name, val in self._saved.items():
            setattr(self.se, name, val)

    class _RuleStub:
        def scan_file(self, p):
            return []

    class _PEStub:
        def analyze(self, p):
            return {}

    def _install_stubs(self, ml_detector, heuristic_matches):
        self.se._worker_db = None
        self.se._worker_rule_engine = self._RuleStub()
        self.se._worker_pe_analyzer = self._PEStub()
        self.se._worker_virus_identifier = None
        self.se._worker_vi_enabled = False
        self.se._worker_archive_scanner = None
        self.se._worker_malware_hashes = set()
        self.se._worker_whitelist_cache = {}
        self.se._worker_heuristic_rules = None
        self.se._worker_trusted_dirs = set()
        self.se._worker_executable_extensions = {'.exe'}
        self.se._worker_min_file_size = 0
        self.se._worker_signature_verifier = None
        self.se._worker_strict_mode = False
        self.se._worker_self_excluded_dirs = set()
        self.se._worker_user_excluded_dirs = set()
        self.se._worker_oem_dir_keys = ()
        self.se._worker_ml_detector = ml_detector
        self.se._worker_analysis_cache = {}
        self.se._scan_file_worker_heuristic = lambda p: list(heuristic_matches)

    def _make_exe(self):
        fd, path = tempfile.mkstemp(suffix='.exe')
        os.write(fd, b'MZ' + b'\x00' * 4096)
        os.close(fd)
        return path

    def test_ml_called_when_file_suspicious(self):
        path = self._make_exe()
        try:
            # 启发式命中 high -> file_status 变 suspicious（在 ML 之前）
            fake = _FakeMLDetector(verdict=None)
            self._install_stubs(fake, [{'name': 'x', 'severity': 'high'}])
            results = self.se._scan_file_worker_full(path)
            self.assertEqual(fake.called, 1,
                             'ML 应在 file_status==suspicious 时被调用且仅一次')
            self.assertTrue(any(r.status == 'suspicious' for r in results))
        finally:
            os.remove(path)

    def test_ml_called_once_for_clean_file(self):
        path = self._make_exe()
        try:
            fake = _FakeMLDetector(verdict=None)
            self._install_stubs(fake, [])
            self.se._scan_file_worker_full(path)
            self.assertEqual(fake.called, 1)
        finally:
            os.remove(path)

    def test_ml_upgrades_suspicious_to_malware(self):
        """已被判 suspicious 的文件，ML 主引擎高置信恶意可升级为 malware。"""
        path = self._make_exe()
        try:
            fake = _FakeMLDetector(verdict=('malware', 0.95), source='lgb')
            self._install_stubs(fake, [{'name': 'x', 'severity': 'high'}])
            results = self.se._scan_file_worker_full(path)
            statuses = [r.status for r in results]
            self.assertIn('malware', statuses,
                          'ML 主引擎应把 suspicious 升级为 malware')
        finally:
            os.remove(path)

    def test_get_scan_stats_exposes_ml_counters(self):
        path = self._make_exe()
        try:
            fake = _FakeMLDetector(verdict=None)
            self._install_stubs(fake, [])
            results = self.se._scan_file_worker_full(path)
            engine = self.se.ScanEngine.__new__(self.se.ScanEngine)
            stats = engine.get_scan_stats(results)
            for key in ('ml_available', 'ml_called', 'ml_malware',
                        'ml_susp', 'ml_none', 'ml_failed',
                        'ml_main_unavailable_reason'):
                self.assertIn(key, stats)
        finally:
            os.remove(path)


if __name__ == '__main__':
    unittest.main(verbosity=2)