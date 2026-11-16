# -*- coding: utf-8 -*-
"""启动期 GUI 线程零长阻塞回归（加载界面/主 GUI "未响应"）。

根因：`_init_managers` 由 QTimer 在 **GUI 线程**回调，却在其中直接构造
`SignatureDB()`（内置库 106MB）/`ScanEngine()`/`QuarantineManager()`/`VirusIdentifier()`，
冷盘/高负载下秒级 → Splash/主 GUI 未响应。

修复：`_init_managers` 改为"只调度不构造"——未就绪即委托后台线程 PSLS-CoreInit
并**立即返回**；就绪后由 `_on_core_init_done` 在 GUI 线程写回引用并点亮状态。
"""
import os
import sys
import time
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class _FakeBridgeMixin:
    """最小 PyBridge 替身：只放被测方法所依赖的属性。"""

    @staticmethod
    def _new():
        import ui.webview.bridge as bmod
        b = bmod.PyBridge.__new__(bmod.PyBridge)
        b._signature_db = None
        b._scan_engine = None
        b._quarantine_manager = None
        b._virus_identifier = None
        b._ml_detector = None
        b._core_init_thread = None
        b._core_init_retries = 0
        return b, bmod


class TestInitManagersNonBlocking(unittest.TestCase):

    def test_init_managers_returns_immediately_when_not_ready(self):
        """核心未就绪时，GUI 线程上的 _init_managers 必须**立即返回**（<200ms）。"""
        b, bmod = _FakeBridgeMixin._new()
        started = []

        def _slow_core_init():
            # 模拟后台核心初始化耗时（不阻塞调用方）
            time.sleep(2.0)
        b._start_core_init_async = lambda: (
            started.append(1),
            threading.Thread(target=_slow_core_init, daemon=True).start())[1]
        # 关键：绝不能构造重活
        b._kick_sandboxie_suppress_async = lambda: None
        b._start_browser_launch_watcher = lambda: None

        with mock.patch.object(bmod, 'SignatureDB',
                               side_effect=AssertionError('GUI 线程不得构造 SignatureDB')), \
                mock.patch.object(bmod, 'ScanEngine',
                                  side_effect=AssertionError('GUI 线程不得构造 ScanEngine')):
            t0 = time.time()
            b._init_managers()
            dt = (time.time() - t0) * 1000
        self.assertLess(dt, 200, f'GUI 线程被阻塞 {dt:.1f}ms')
        self.assertEqual(started, [1], '应委托后台核心初始化')
        # 直接用 __dict__ 读取采样（避免未初始化 QObject 的属性代理）
        self.assertLessEqual(float(b.__dict__.get('_gui_block_max_ms', 0.0)), 200)

    def test_kick_core_init_is_idempotent(self):
        b, _ = _FakeBridgeMixin._new()
        calls = []
        b._start_core_init_async = lambda: calls.append(1)

        class _T:
            def is_alive(self):
                return True
        b._core_init_thread = _T()
        b._kick_core_init_async()
        self.assertEqual(calls, [], '已在初始化中不得重复拉起')

        b._core_init_thread = None
        b._kick_core_init_async()
        self.assertEqual(calls, [1])

    def test_init_managers_light_when_ready(self):
        """核心已就绪 → 只做轻量收尾（无重构造）。"""
        b, bmod = _FakeBridgeMixin._new()
        b._signature_db = object()
        b._scan_engine = object()
        done = []
        b._finish_core_init_light = lambda: done.append(1)
        with mock.patch.object(bmod, 'SignatureDB',
                               side_effect=AssertionError('不得再构造')), \
                mock.patch.object(bmod, 'ScanEngine',
                                  side_effect=AssertionError('不得再构造')):
            b._init_managers()
        self.assertEqual(done, [1])

    def test_scan_engine_construction_after_signature_db(self):
        """顺序依赖：ScanEngine 必须在 SignatureDB 就绪后构造（源码顺序断言）。"""
        with open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        worker = src.split('def _start_core_init_async', 1)[1].split('\n    def ', 1)[0]
        i_db = worker.find('db = SignatureDB()')
        i_se = worker.find('ScanEngine(signature_db=')
        self.assertGreater(i_db, -1)
        self.assertGreater(i_se, -1)
        self.assertLess(i_db, i_se, 'ScanEngine 必须在 SignatureDB 之后构造')

    def test_init_managers_source_never_constructs(self):
        with open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        seg = src.split('def _init_managers', 1)[1].split('\n    def ', 1)[0]
        for bad in ('SignatureDB()', 'ScanEngine(', 'QuarantineManager()',
                    'VirusIdentifier('):
            self.assertNotIn(bad, seg, f'_init_managers 不得构造 {bad}')

    def test_flush_signals_declares_gui_block_sampling(self):
        with open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        seg = src.split('def _flush_signals', 1)[1].split('\n    def ', 1)[0]
        self.assertIn('_record_gui_block', seg)


class TestSafeDegradeDuringBackgroundInit(unittest.TestCase):

    def test_scan_deferred_when_engine_not_ready(self):
        b, _ = _FakeBridgeMixin._new()
        acts = []
        emitted = []
        b._add_activity = lambda *a, **k: acts.append(a)
        b._emit_tool_signal = lambda name, payload: emitted.append((name, payload))
        b._scan_running = threading.Event()
        b._emit_tool_signal  # noqa
        self.assertFalse(b._require_scan_engine_ready('快速扫描'))
        self.assertTrue(any('加载中' in str(a) for a in acts))
        self.assertTrue(emitted and emitted[0][0] == 'scanDeferred')

    def test_scan_allowed_when_ready(self):
        b, _ = _FakeBridgeMixin._new()
        b._scan_engine = object()
        b._signature_db = object()
        self.assertTrue(b._require_scan_engine_ready('快速扫描'))

    def test_start_scan_slots_call_gate(self):
        with open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        self.assertGreaterEqual(src.count('_require_scan_engine_ready('), 3,
                                '扫描入口都应经过降级闸门')

    def test_no_blocking_join_on_gui_path(self):
        """GUI 路径（_init_managers / _on_core_init_done / initRequested）不得出现 join/wait。"""
        with open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        for fn in ('def _init_managers', 'def _on_core_init_done',
                   'def initRequested'):
            seg = src.split(fn, 1)[1].split('\n    def ', 1)[0]
            # 排除 os.path.join 等字符串处理，只看"线程/事件 join|wait"
            seg_wo_ospath = seg.replace('os.path.join(', '').replace(
                'path.join(', '')
            self.assertNotIn('.join(', seg_wo_ospath, f'{fn} 不得 join 阻塞 GUI')
            self.assertNotIn('.wait(', seg_wo_ospath, f'{fn} 不得 wait 阻塞 GUI')


if __name__ == '__main__':
    unittest.main()