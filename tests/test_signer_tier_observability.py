# -*- coding: utf-8 -*-
"""
TDD 测试: 升级3 驱动签名灰名单分层 + 升级5 签名缓存可观测 + 升级6 可观测性中心

- classify_signer 四级归一化 (known/misc/invalid/unsigned)
- get_signer_info 返回 tier 字段
- SignatureVerifier.cache_stats / cache_clear
- ObservabilityHub 埋点/事件/心跳快照
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import signature_verifier as sv_mod  # noqa: E402
from engine.observability import ObservabilityHub, get_hub  # noqa: E402


class TestSignerTier(unittest.TestCase):
    """升级3: classify_signer 四级分层"""

    def test_known_publisher(self):
        self.assertEqual(sv_mod.classify_signer(True, 'Microsoft Windows'),
                         sv_mod.SIGNER_TIER_KNOWN)
        self.assertEqual(sv_mod.classify_signer(True, 'Tencent Technology(Shenzhen) Company Limited'),
                         sv_mod.SIGNER_TIER_KNOWN)

    def test_misc_unknown_publisher(self):
        """已签名但发布者不在名单 -> 灰名单 MISC"""
        self.assertEqual(sv_mod.classify_signer(True, 'Some Unknown Software Co'),
                         sv_mod.SIGNER_TIER_MISC)
        self.assertEqual(sv_mod.classify_signer(True, ''), sv_mod.SIGNER_TIER_MISC)

    def test_invalid(self):
        """有签名但验证失败 -> invalid"""
        self.assertEqual(sv_mod.classify_signer(False, 'Microsoft Windows'),
                         sv_mod.SIGNER_TIER_INVALID)

    def test_unsigned_none(self):
        """无签名/未知(验证器不可用) -> unsigned"""
        self.assertEqual(sv_mod.classify_signer(None, ''), sv_mod.SIGNER_TIER_UNSIGNED)
        self.assertEqual(sv_mod.classify_signer(False, ''), sv_mod.SIGNER_TIER_INVALID)

    def test_tier_policy_sets(self):
        self.assertIn(sv_mod.SIGNER_TIER_KNOWN, sv_mod.TIER_SOFT_PASS)
        self.assertIn(sv_mod.SIGNER_TIER_MISC, sv_mod.TIER_SOFT_PASS)
        self.assertIn(sv_mod.SIGNER_TIER_INVALID, sv_mod.TIER_INSPECT)


class TestSignerCacheObservability(unittest.TestCase):
    """升级5: 签名缓存 stats / clear"""

    def test_cache_stats_and_clear(self):
        v = sv_mod.get_verifier()
        stats = v.cache_stats()
        self.assertIn('verify_cached', stats)
        self.assertIn('max_cached', stats)
        # clear 不抛异常且可重复调用
        v.cache_clear()
        self.assertEqual(v.cache_stats()['verify_cached'], 0)
        self.assertEqual(v.cache_stats()['signer_cached'], 0)


class TestObservabilityHub(unittest.TestCase):
    """升级6: ObservabilityHub 埋点/事件/心跳"""

    def test_incr_and_snapshot(self):
        h = ObservabilityHub()
        h.incr('scan.files', 3)
        h.incr('scan.files', 2)
        h.set_gauge('watched', 100)
        snap = h.snapshot()
        self.assertEqual(snap['counters']['scan.files'], 5)
        self.assertEqual(snap['gauges']['watched'], 100)
        self.assertGreaterEqual(snap['uptime'], 0.0)

    def test_events_capped(self):
        h = ObservabilityHub()
        for i in range(1000):
            h.event('cat', f'msg{i}', level='warn')
        snap = h.snapshot()
        self.assertLessEqual(len(snap['recent_events']), 100)
        self.assertLessEqual(len(h._events), ObservabilityHub.MAX_EVENTS)

    def test_heartbeat(self):
        h = ObservabilityHub()
        h.heartbeat('driver_loop')
        snap = h.snapshot()
        self.assertGreater(snap['counters']['heartbeat.driver_loop'], 0)
        self.assertLessEqual(snap['heartbeat_age_s'], 2.0)


if __name__ == '__main__':
    unittest.main(verbosity=2)