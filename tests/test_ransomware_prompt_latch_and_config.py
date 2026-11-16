# -*- coding: utf-8 -*-
"""勒索回滚确认弹窗防轰炸 + 单文件上限滑动条 + 编译缓存指纹 —— 回归测试。

覆盖本批调整：
  1) Bug：确认弹窗反复弹出 → pending 闩锁 / 决策冷却 / 超时条件 / 前端幂等
  2) 调整决定 3：单文件快照上限滑动条（1..256MB，最顶端=无限制=0）+ 持久化 + 下发引擎
  3) 编译缓存指纹：规则文件变化 → 指纹不匹配 → 自动重编译
  4) docs/ 两份评估文档存在且含关键实测数字

测试不访问网络；不依赖 Qt 事件循环（原生弹窗用替身）。
"""

import os
import sys
import json
import time
import shutil
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ui.webview.bridge as bmod          # noqa: E402
import engine.rule_engine as re_mod        # noqa: E402
import engine.ransomware_rollback as rr    # noqa: E402


class _FakeTime:
    """可注入的时间源（替换 bridge.time），便于测试冷却期/超时。"""
    def __init__(self, now=1000.0):
        self.now = float(now)

    def time(self):
        return self.now

    def sleep(self, *_a, **_k):
        return None


class _SigStub:
    """记录 emit 次数的信号替身。"""
    def __init__(self):
        self.emitted = []

    def emit(self, payload):
        self.emitted.append(payload)


def _mk_bridge(**attrs):
    """绕过 __init__ 构造轻量 bridge（与既有测试同款做法）。"""
    b = bmod.PyBridge.__new__(bmod.PyBridge)
    b._acts = []
    b._add_activity = lambda *a, **k: b._acts.append(a)
    b._emit_tool_signal = lambda n, p: None
    b._rollback_refresh_async = lambda: None
    b._ransomware_prompt_lock = threading.Lock()
    b._ransomware_prompt_pending = False
    b._ransomware_prompt_cooldown_until = 0.0
    b._ransomware_prompt_last_count = 0
    b._ransomware_prompt_dup_count = 0
    b._ransomware_rollback_win = None
    b._last_ransomware_req = None
    b.ransomwareRollbackRequested = _SigStub()
    b._rollback_manager = mock.MagicMock()
    for k, v in attrs.items():
        setattr(b, k, v)
    return b


class TestRansomwarePromptLatch(unittest.TestCase):
    """Bug 修复：同一轮攻击只提示一次（修前 26 次 → 修后 1 次）。"""

    def setUp(self):
        self.ft = _FakeTime(1000.0)
        self._tp = mock.patch.object(bmod, 'time', self.ft)
        self._tp.start()

    def tearDown(self):
        self._tp.stop()

    def _confirmed(self, b, count):
        b._on_ransomware_confirmed({
            'type': 'ransomware_suspected',
            'files': [f'C:/x/{i}.jpg' for i in range(count)]})

    def test_same_round_only_one_prompt(self):
        b = _mk_bridge()
        for _ in range(26):          # 复刻 22:22:17→22:23:06 的 26 次连发
            self._confirmed(b, 30)
        self.assertEqual(1, len(b.ransomwareRollbackRequested.emitted),
                         '同一轮攻击应只发 1 次确认请求')
        self.assertTrue(b._ransomware_prompt_pending)
        self.assertEqual(25, b._ransomware_prompt_dup_count)

    def test_decision_cooldown_suppresses_repeat(self):
        b = _mk_bridge()
        self._confirmed(b, 30)
        # 用户决策落地（例如选择不回滚 / 超时默认）→ 清 pending + 进入冷却
        b._on_ransomware_rollback_rejected({'file_count': 30}, resolve_prompt=True)
        self.assertFalse(b._ransomware_prompt_pending)
        for _ in range(10):          # 冷却期内同规模检测
            self._confirmed(b, 30)
        self.assertEqual(1, len(b.ransomwareRollbackRequested.emitted),
                         '决策冷却期内不得再次弹窗')

    def test_reprompt_allowed_after_cooldown(self):
        b = _mk_bridge()
        self._confirmed(b, 30)
        b._on_ransomware_rollback_rejected({'file_count': 30}, resolve_prompt=True)
        self.ft.now += bmod._RANSOMWARE_PROMPT_COOLDOWN + 1.0
        self._confirmed(b, 30)
        self.assertEqual(2, len(b.ransomwareRollbackRequested.emitted),
                         '冷却期后允许重新提示')

    def test_significant_growth_allows_reprompt_during_cooldown(self):
        b = _mk_bridge()
        self._confirmed(b, 30)
        b._on_ransomware_rollback_rejected({'file_count': 30}, resolve_prompt=True)
        # 冷却期内受影响文件显著增长 30 → 100 → 允许重新提示
        self._confirmed(b, 100)
        self.assertEqual(2, len(b.ransomwareRollbackRequested.emitted),
                         '冷却期内集合显著变化应允许重新提示')
        # 未显著增长（100 → 110）仍被抑制
        b._on_ransomware_rollback_rejected({'file_count': 100}, resolve_prompt=True)
        self._confirmed(b, 110)
        self.assertEqual(2, len(b.ransomwareRollbackRequested.emitted))

    def test_exception_does_not_deadlock_latch(self):
        """异常安全：发出确认失败也绝不能把 pending 卡死。"""
        b = _mk_bridge()
        b.ransomwareRollbackRequested = _SigStub()
        b.ransomwareRollbackRequested.emit = mock.Mock(side_effect=RuntimeError('x'))
        self._confirmed(b, 30)
        self.assertFalse(b._ransomware_prompt_pending)


class _FakeReleaseWin:
    """SandboxReleaseWindow 替身：记录创建数，信号为可 connect 的替身。"""
    created = 0

    def __init__(self, *a, **k):
        _FakeReleaseWin.created += 1
        self._accept = []
        self._reject = []

        class _S:
            def __init__(self, sink):
                self._sink = sink

            def connect(self, fn):
                self._sink.append(fn)
        self.releaseAccepted = _S(self._accept)
        self.releaseRejected = _S(self._reject)

    def show(self):
        pass

    def selected_value(self):
        return None


class TestFrontendPopupIdempotent(unittest.TestCase):
    """前端确认弹窗幂等：同一时刻仅一个（两套主题共用同一原生窗口/入口）。"""

    def setUp(self):
        _FakeReleaseWin.created = 0
        self._old = bmod.SandboxReleaseWindow
        bmod.SandboxReleaseWindow = _FakeReleaseWin

    def tearDown(self):
        bmod.SandboxReleaseWindow = self._old

    def test_only_one_popup_created(self):
        b = _mk_bridge()
        payload = json.dumps({'reason': '短时间内批量加密行为',
                              'file_count': 30, 'suspect_paths': []},
                             ensure_ascii=False)
        b._on_ransomware_rollback_popup_requested(payload)
        b._on_ransomware_rollback_popup_requested(payload)   # 重复请求
        self.assertEqual(1, _FakeReleaseWin.created,
                         '同一时刻只允许一个确认弹窗（幂等）')
        # 两套主题的设置页都带同一滑动条（共用 app.js 与同一桥接入口）
        for theme in ('index.html', 'terminal.html'):
            with open(os.path.join(ROOT, 'ui', 'webview', theme),
                      'r', encoding='utf-8') as f:
                html = f.read()
            self.assertIn('id="rb-max-size"', html, f'{theme} 缺单文件上限滑动条')


class TestMaxFileSizeSlider(unittest.TestCase):
    """调整决定 3：单文件快照上限滑动条（1..256MB，最顶端=无限制=0）。"""

    def test_coerce_boundaries(self):
        c = bmod._coerce_max_file_mb
        self.assertEqual(1, c(1))
        self.assertEqual(64, c(64))
        self.assertEqual(256, c(256))
        self.assertEqual(0, c(0))        # 无限制
        self.assertEqual(0, c(257))      # 最顶端 → 无限制
        self.assertEqual(0, c(-5))
        self.assertEqual(0, bmod._bytes_to_mb(0))
        self.assertEqual(64, bmod._bytes_to_mb(64 * 1024 * 1024))

    def test_engine_setter_and_unlimited_zero(self):
        eng = rr.RansomwareRollback.__new__(rr.RansomwareRollback)
        eng._state_lock = threading.Lock()
        eng._max_file_bytes = 64 * 1024 * 1024
        self.assertEqual(1 * 1024 * 1024, eng.set_max_file_mb(1))
        self.assertEqual(256 * 1024 * 1024, eng.set_max_file_mb(256))
        self.assertEqual(0, eng.set_max_file_mb(0))          # 0 → 不限制
        self.assertEqual(0, eng.get_max_file_bytes())

    def test_config_persist_and_dispatch(self):
        b = _mk_bridge()
        saved = {}
        with mock.patch.object(bmod, '_save_ui_settings',
                               lambda v: saved.update(v)), \
             mock.patch.object(bmod, '_load_ui_settings', lambda: {}):
            ok = b.setRollbackSnapshotConfig(json.dumps(
                {'dirs': [], 'exts': [], 'max_file_mb': 0}))
            self.assertTrue(ok)
            for _ in range(50):
                if b._rollback_manager.set_max_file_mb.called:
                    break
                time.sleep(0.02)
        self.assertEqual(0, saved.get('rollback_max_file_mb'))
        b._rollback_manager.set_max_file_mb.assert_called_once_with(0)

    def test_get_config_reports_saved_mb_when_engine_absent(self):
        b = _mk_bridge(_rollback_manager=None)
        with mock.patch.object(bmod, '_load_ui_settings',
                               lambda: {'rollback_max_file_mb': 128}):
            out = json.loads(b.getRollbackSnapshotConfig())
        self.assertEqual(128, out.get('max_file_mb'))


class TestYaraCompiledCacheFingerprint(unittest.TestCase):
    """调整决定 4：文件规则编译缓存加指纹，改规则后自动重编译。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_yarafp_')
        self.rules_dir = os.path.join(self.tmp, 'rules')
        os.makedirs(self.rules_dir, exist_ok=True)
        self.cache = os.path.join(self.tmp, 'compiled.yc')
        self._old = (re_mod._YARA_RULES_DIR, re_mod._YARA_COMPILED_CACHE,
                     re_mod._get_writable_cache_path)
        re_mod._YARA_RULES_DIR = self.rules_dir
        re_mod._YARA_COMPILED_CACHE = self.cache
        re_mod._get_writable_cache_path = lambda: self.cache

    def tearDown(self):
        (re_mod._YARA_RULES_DIR, re_mod._YARA_COMPILED_CACHE,
         re_mod._get_writable_cache_path) = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _engine(self):
        eng = re_mod.RuleEngine.__new__(re_mod.RuleEngine)
        eng._yara_lock = threading.Lock()
        eng._yara_rules = None
        eng._yara_rules_db = None
        eng._yara_available = True
        eng._yara_rules_ready = False
        eng._signature_db = None
        eng._load_auto_rules_from_db = lambda: []
        return eng

    def _write_rule(self, marker):
        with open(os.path.join(self.rules_dir, 'a.yar'), 'w',
                  encoding='utf-8') as f:
            f.write(f'rule FP_{marker} {{ meta: severity = 100 '
                    f'strings: $s = "PSLS_FP_{marker}_MARKER" condition: $s }}\n')

    def test_recompile_when_rules_change(self):
        if not getattr(re_mod, 'HAS_YARA', False):
            self.skipTest('yara-python 不可用')
        self._write_rule('AAA')
        self._engine()._load_yara_rules()
        self.assertTrue(os.path.isfile(self.cache))
        self.assertTrue(os.path.isfile(self.cache + '.fp'))
        with open(self.cache + '.fp', 'r', encoding='utf-8') as f:
            fp1 = f.read()
        mtime1 = os.path.getmtime(self.cache)

        # 第三次、未改规则 → 命中缓存（跳过编译），缓存 mtime 不变
        self._engine()._load_yara_rules()
        self.assertEqual(mtime1, os.path.getmtime(self.cache),
                         '指纹一致时应命中缓存、不重编译')

        # 改规则文件（内容+mtime 变化）→ 指纹不匹配 → 自动重编译
        time.sleep(0.02)
        self._write_rule('BBB')
        self._engine()._load_yara_rules()
        with open(self.cache + '.fp', 'r', encoding='utf-8') as f:
            fp2 = f.read()
        self.assertNotEqual(fp1, fp2, '规则变化后指纹必须变化')
        self.assertGreater(os.path.getmtime(self.cache), mtime1,
                           '指纹不匹配应触发重编译并刷新缓存')


class TestDocsPresent(unittest.TestCase):
    """两份评估文档存在且含关键实测数字。"""

    def test_docs(self):
        d = os.path.join(ROOT, 'docs')
        p1 = os.path.join(d, 'yara_elastic_eval.md')
        p2 = os.path.join(d, 'elastic_labs_probe.md')
        self.assertTrue(os.path.isfile(p1), '缺少 docs/yara_elastic_eval.md')
        self.assertTrue(os.path.isfile(p2), '缺少 docs/elastic_labs_probe.md')
        with open(p1, 'r', encoding='utf-8') as f:
            t1 = f.read()
        for token in ('2004', '741', '102', 'Elastic License 2.0'):
            self.assertIn(token, t1)
        with open(p2, 'r', encoding='utf-8') as f:
            t2 = f.read()
        for token in ('labs-releases', 'nightMARE', 'SWAT', 'Rizin', '未验证'):
            self.assertIn(token, t2)


if __name__ == '__main__':
    unittest.main()