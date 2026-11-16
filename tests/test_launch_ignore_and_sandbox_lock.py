# -*- coding: utf-8 -*-
"""需求 A（启动扫描忽略表）+ 需求 B（沙箱锁定/候选排除/文案）回归。

实测（用户截图 2026-10-07 14:16）：
  1 沙箱 分析失败：文件复制到沙箱失败（源文件可能被独占锁定）[Errno 9]
  2 实时保护已锁定【Minecraft.exe】              → 是 1 的同源
  3 conhost.exe / sbieini.exe 被当作样本"沙箱分析中"
  4 反复 blocked（忽略后仍反复触发）
"""
import io
import os
import sys
import time
import shutil
import threading
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.sandbox_analyzer as sa
import engine.realtime_monitor as rtm
import ui.webview.bridge as bmod


def _new_bridge(**attrs):
    b = bmod.PyBridge.__new__(bmod.PyBridge)
    b._acts = []
    b._sigs = []
    b._add_activity = lambda *a, **k: b._acts.append(a)
    b._emit_tool_signal = lambda n, p: b._sigs.append((n, p))
    b._gui_block_samples = []
    b._realtime_threat_count = 0
    b._launch_scan_threat_count = 0
    b._realtime_count_lock = threading.Lock()
    for k, v in attrs.items():
        setattr(b, k, v)
    return b


class TestLaunchScanIgnoreTable(unittest.TestCase):
    """需求 A：忽略后不再触发启动扫描；不写白名单；可撤销；跨重启。"""

    def setUp(self):
        self.store = {}
        self._patches = [
            mock.patch.object(bmod, '_load_ui_settings',
                              side_effect=lambda: dict(self.store)),
            mock.patch.object(bmod, '_save_ui_settings',
                              side_effect=lambda d: self.store.update(d)),
        ]
        for p in self._patches:
            p.start()
        self.tmp = tempfile.mkdtemp(prefix='psls_ign_')
        self.exe = os.path.join(self.tmp, 'Minecraft.exe')
        with open(self.exe, 'wb') as f:
            f.write(b'MZ' * 500)

    def tearDown(self):
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _payload(self, status='blocked'):
        return {'pid': 1234, 'name': 'Minecraft.exe', 'exe_path': self.exe,
                'scan_result': {'status': status, 'name': 'blocked'}}

    def test_second_detection_after_ignore_skips_blocked(self):
        b = _new_bridge()
        b._release_realtime_threat_lock = lambda p: None
        b.threatActionResult = mock.MagicMock()
        # 首次：未被忽略 → 产生 blocked 活动 + 前端信号
        b._on_launch_scan_result(self._payload())
        self.assertTrue(any('非安全应用启动' in str(a) for a in b._acts))
        self.assertTrue(any(s[0] == 'processThreatDetected' for s in b._sigs))

        # 用户点击"忽略"（来自启动扫描）
        b.processThreat(__import__('json').dumps({
            'file_path': self.exe, 'action': 'ignore',
            'signature_name': '[启动扫描] blocked', 'status': 'blocked',
            'source': 'launch_scan'}))
        for _ in range(50):
            if b._load_launch_scan_ignores():
                break
            time.sleep(0.02)
        self.assertTrue(b._load_launch_scan_ignores(), '忽略表应有记录')

        # 第二次：应被跳过（无 blocked 活动、无前端信号）
        b._acts.clear(); b._sigs.clear()
        b._on_launch_scan_result(self._payload())
        self.assertFalse(any('非安全应用启动' in str(a) for a in b._acts),
                         '忽略后不得再产生 blocked 活动')
        self.assertEqual(b._sigs, [], '忽略后不得再弹窗/发信号')
        self.assertTrue(any('已忽略对象，跳过启动扫描' in str(a) for a in b._acts))

    def test_ignore_does_not_touch_whitelist(self):
        b = _new_bridge()
        b._add_launch_scan_ignore(self.exe, 'user_ignore')
        t = self.store.get('launch_scan_ignores') or {}
        self.assertTrue(t)
        # 不得写入任何白名单键
        for k in self.store.keys():
            self.assertNotIn('white', k.lower())
            self.assertNotIn('trust', k.lower())
        # 忽略表与白名单分离存储
        self.assertNotIn('whitelist', self.store)

    def test_persist_across_restart_and_clear_restores(self):
        b1 = _new_bridge()
        b1._add_launch_scan_ignore(self.exe, 'user_ignore')
        # "重启"：新 bridge 实例共享同一 settings 存储
        b2 = _new_bridge()
        self.assertTrue(b2._is_launch_scan_ignored(self.exe), '忽略应跨重启生效')
        self.assertTrue(b2.clearLaunchScanIgnore(self.exe), '应可撤销')
        self.assertFalse(b2._is_launch_scan_ignored(self.exe), '撤销后恢复触发')
        # 恢复后可再次产生 blocked
        b3 = _new_bridge()
        b3._on_launch_scan_result(self._payload())
        self.assertTrue(any('非安全应用启动' in str(a) for a in b3._acts))

    def test_clear_all(self):
        b = _new_bridge()
        b._add_launch_scan_ignore(self.exe)
        n = b.clearAllLaunchScanIgnores()
        self.assertGreaterEqual(n, 1)
        self.assertEqual(b._load_launch_scan_ignores(), {})

    def test_size_change_invalidates_ignore(self):
        """文件被替换（大小变化）→ 键不匹配 → 重新触发（防"换马甲"绕过）。"""
        b = _new_bridge()
        b._add_launch_scan_ignore(self.exe)
        self.assertTrue(b._is_launch_scan_ignored(self.exe))
        with open(self.exe, 'ab') as f:
            f.write(b'X' * 10)
        self.assertFalse(b._is_launch_scan_ignored(self.exe))

    def test_other_engines_unaffected(self):
        """忽略表只影响启动扫描；其它引擎的检测入口不被改动。"""
        b = _new_bridge()
        b._add_launch_scan_ignore(self.exe)
        with open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        # 实时防护/扫描链路不应读取忽略表
        for fn in ('def _on_realtime_threat', 'def _on_realtime_scan_result'):
            seg = src.split(fn, 1)[1].split('\n    def ', 1)[0]
            self.assertNotIn('_is_launch_scan_ignored', seg,
                             f'{fn} 不应受启动扫描忽略表影响')


class TestSystemProcessExclusion(unittest.TestCase):
    """需求 B2/B3：系统与沙箱基础设施不进候选；'exe 路径不可用'不再记为分析中。"""

    def test_excluded_names(self):
        b = _new_bridge()
        for n in ('conhost.exe', 'sbieini.exe', 'Start.exe', 'SbieSvc.exe',
                  'SandboxieRpcSs.exe', 'svchost.exe', 'explorer.exe',
                  'PSLS.exe', 'MLWorker.exe'):
            self.assertTrue(b._is_launch_scan_excluded(n), f'{n} 应被排除')
        for n in ('minecraft.exe', 'game.exe', 'setup.exe'):
            self.assertFalse(b._is_launch_scan_excluded(n), f'{n} 不应被排除')

    def test_sandboxie_path_excluded(self):
        b = _new_bridge()
        self.assertTrue(b._is_launch_scan_excluded(
            'unknown.exe', r'C:\Program Files\PSLS\Sandboxie\Start.exe'))

    def test_scanning_with_unavailable_path_not_reported_as_analyzing(self):
        b = _new_bridge()
        b._on_launch_scan_result({
            'pid': 8320, 'name': 'conhost.exe', 'exe_path': '',
            'scan_result': {'status': 'scanning',
                            'reason': 'exe 路径不可用, 无法沙箱分析'},
        })
        # conhost 本身就该被候选排除
        self.assertFalse(any('沙箱分析中' in str(a) for a in b._acts))
        b2 = _new_bridge()
        b2._on_launch_scan_result({
            'pid': 9216, 'name': 'customapp.exe', 'exe_path': '',
            'scan_result': {'status': 'scanning',
                            'reason': 'exe 路径不可用, 无法沙箱分析'},
        })
        self.assertFalse(any('拦截待分析' in str(a) for a in b2._acts),
                         "'exe 路径不可用' 不得记为沙箱分析中")
        self.assertTrue(any('非沙箱分析中' in str(a) for a in b2._acts))

    def test_maybe_trigger_sandbox_excludes_infra(self):
        b = _new_bridge()
        b._scan_excluded_paths = []
        tmp = tempfile.mkdtemp(prefix='psls_sb_')
        try:
            p = os.path.join(tmp, 'conhost.exe')
            with open(p, 'wb') as f:
                f.write(b'MZ')
            b._sandbox_recent = {}
            b._sandbox_recent_lock = threading.Lock()
            b._sandbox_sem = threading.Semaphore(2)
            # 不应进入沙箱流程（无 _run_sandbox_analysis 调用）
            with mock.patch.object(bmod.PyBridge, '_run_sandbox_analysis') as m:
                b._maybe_trigger_sandbox(p, source='手动')
            m.assert_not_called()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestLockedFileCopy(unittest.TestCase):
    """需求 B1：PSLS 自己锁定的文件仍能被沙箱复制（修前失败 → 修后成功）。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_lk_')
        self.src = os.path.join(self.tmp, 'Minecraft.exe')
        with open(self.src, 'wb') as f:
            f.write(b'MZ' + b'\x00' * (64 * 1024))
        self.dst = os.path.join(self.tmp, 'copy.exe')

    def tearDown(self):
        sa.set_internal_copy_provider(None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _fake_monitor_with_lock(self):
        """构造一个"持有该文件独占锁"的 RealtimeMonitor 替身（用真实独占句柄）。"""
        m = rtm.RealtimeMonitor.__new__(rtm.RealtimeMonitor)
        m._threat_locks = {}
        m._threat_locks_lock = threading.Lock()
        m._threat_lock_max_seconds = 60
        m._add_event = lambda *a, **k: None
        # 以"独占"方式持有（share 仅读仍会让写入/属性复制失败；这里用真独占句柄）
        fo = open(self.src, 'rb', buffering=0)
        m._threat_locks[os.path.abspath(self.src)] = (fo, time.time())
        self.addCleanup(lambda: fo.close())
        return m

    def _exclusive_handle_obj(self):
        """用 share=0 打开源文件（**修前**的独占语义）并包成 Python 文件对象。"""
        import ctypes
        import msvcrt
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
        k32.CreateFileW.restype = ctypes.c_void_p
        h = k32.CreateFileW(self.src, 0x80000000, 0x00000000, None, 3, 0x80, None)
        if not h or h == ctypes.c_void_p(-1).value:
            return None
        fd = msvcrt.open_osfhandle(int(h), 0)
        if fd < 0:
            k32.CloseHandle(h)
            return None
        return os.fdopen(fd, 'rb')

    def test_locked_copy_fails_without_internal_channel(self):
        """修前等价：源被 share=0 独占锁 + 无内部通道 → 复制失败（EBADF/共享冲突）。"""
        if sys.platform != 'win32':
            self.skipTest('Windows 专属')
        fo = self._exclusive_handle_obj()
        if fo is None:
            self.skipTest('无法构造独占句柄（环境限制）')
        try:
            sa.set_internal_copy_provider(None)          # 关闭内部通道
            ok, why = sa.copy_sample_with_retry(self.src, self.dst)
            self.assertFalse(ok, f'独占锁且无内部通道时应失败（修前行为）: {why}')
        finally:
            fo.close()

    def test_locked_copy_succeeds_with_internal_channel(self):
        """修后：源被独占锁，但锁是 PSLS 自己的 → 内部通道拷出副本，复制成功。"""
        if sys.platform != 'win32':
            self.skipTest('Windows 专属')
        fo = self._exclusive_handle_obj()
        if fo is None:
            self.skipTest('无法构造独占句柄（环境限制）')
        m = rtm.RealtimeMonitor.__new__(rtm.RealtimeMonitor)
        m._threat_locks = {os.path.abspath(self.src): (fo, time.time())}
        m._threat_locks_lock = threading.Lock()
        m._add_event = lambda *a, **k: None
        try:
            sa.set_internal_copy_provider(m.locked_copy_to_temp)
            ok, why = sa.copy_sample_with_retry(self.src, self.dst)
            self.assertTrue(ok, f'内部通道应让锁定文件可复制: {why}')
            with open(self.dst, 'rb') as f:
                self.assertEqual(f.read(2), b'MZ')
        finally:
            sa.set_internal_copy_provider(None)
            fo.close()

    def test_share_read_alone_already_allows_copy(self):
        """共享读修复的独立证据：以 FILE_SHARE_READ 持锁 → 外部只读复制即可成功。"""
        if sys.platform != 'win32':
            self.skipTest('Windows 专属')
        fo = rtm._lock_file_exclusive(self.src)          # 修复后的共享模式
        if fo is None:
            self.skipTest('无法构造共享句柄（环境限制）')
        try:
            sa.set_internal_copy_provider(None)
            ok, why = sa.copy_sample_with_retry(self.src, self.dst)
            self.assertTrue(ok, f'FILE_SHARE_READ 持锁时应允许只读复制: {why}')
        finally:
            try:
                fo.close()
            except Exception:
                pass

    def test_locked_copy_to_temp_reads_own_handle(self):
        m = self._fake_monitor_with_lock()
        tmp = m.locked_copy_to_temp(self.src)
        self.assertIsNotNone(tmp)
        self.assertTrue(os.path.isfile(tmp))
        try:
            with open(tmp, 'rb') as f:
                self.assertEqual(f.read(2), b'MZ')
        finally:
            os.unlink(tmp)

    def test_no_lock_returns_none(self):
        m = self._fake_monitor_with_lock()
        self.assertIsNone(m.locked_copy_to_temp(os.path.join(self.tmp, 'nope.exe')))

    def test_share_read_on_all_exclusive_sites(self):
        """源码断言：所有 CreateFileW 独占站点都已改为允许只读共享。"""
        src = open(os.path.join(ROOT, 'engine', 'realtime_monitor.py'),
                   'r', encoding='utf-8').read()
        self.assertIn('FILE_SHARE_READ', src)
        self.assertNotIn('FILE_SHARE_NONE,', src)
        # 沙箱复制路径必须走带重试/内部通道的 helper
        s2 = open(os.path.join(ROOT, 'engine', 'sandbox_analyzer.py'),
                  'r', encoding='utf-8').read()
        self.assertIn('copy_sample_with_retry', s2)


if __name__ == '__main__':
    unittest.main()