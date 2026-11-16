# -*- coding: utf-8 -*-
"""沙箱后端选择与回退的单测（免装 Sandboxie 即可运行）。

验证：
  - 无 Sandboxie 时 detect_sandboxie_backend 返回 available=False；
  - backend='auto'/'sandboxie' 在不可用时都回退 AppContainerBackend；
  - backend='appcontainer' 直接使用 AppContainerBackend；
  - AppContainerBackend.launch/terminate 薄包装转发到既有方法（保持回退等价）。
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.sandbox_analyzer import (  # noqa: E402
    SandboxAnalyzer, SandboxConfig, detect_sandboxie_backend,
    AppContainerBackend, SandboxieBackend, _SandboxBackend,
)


class TestSandboxBackendFallback(unittest.TestCase):

    def test_detect_returns_dict(self):
        info = detect_sandboxie_backend()
        self.assertIsInstance(info, dict)
        for k in ('available', 'dir', 'start', 'ini', 'service', 'driver', 'reason'):
            self.assertIn(k, info)

    def test_auto_falls_back_to_appcontainer(self):
        """未装 Sandboxie 时，默认 auto 必须选 AppContainer。"""
        info = detect_sandboxie_backend()
        if info.get('available'):
            self.skipTest('本机已装 Sandboxie，跳过回退断言')
        a = SandboxAnalyzer()
        self.assertEqual(a.backend_name, 'appcontainer')
        self.assertIsInstance(a._backend, AppContainerBackend)

    def test_force_sandboxie_falls_back_when_absent(self):
        info = detect_sandboxie_backend()
        if info.get('available'):
            self.skipTest('本机已装 Sandboxie，跳过回退断言')
        cfg = SandboxConfig()
        cfg.backend = 'sandboxie'
        a = SandboxAnalyzer(cfg)
        # 强制 sandboxie 但不可用 → 仍回退 AppContainer，不报错
        self.assertEqual(a.backend_name, 'appcontainer')

    def test_force_appcontainer(self):
        cfg = SandboxConfig()
        cfg.backend = 'appcontainer'
        a = SandboxAnalyzer(cfg)
        self.assertEqual(a.backend_name, 'appcontainer')

    def test_invalid_backend_defaults_auto(self):
        cfg = SandboxConfig()
        cfg.backend = 'nonsense'
        a = SandboxAnalyzer(cfg)
        self.assertIn(a.backend_name, ('sandboxie', 'appcontainer'))

    def test_appcontainer_backend_is_thin_wrapper(self):
        """AppContainerBackend.launch/terminate 必须转发到 SandboxAnalyzer 既有方法。"""
        a = SandboxAnalyzer(SandboxConfig())
        calls = {'launch': [], 'terminate': 0}

        def _fake_launch(sample, job):
            calls['launch'].append((sample, job))
            return 'PI'

        def _fake_term():
            calls['terminate'] += 1

        a._launch_sandboxed = _fake_launch
        a._terminate_job = _fake_term
        be = AppContainerBackend(a)
        self.assertEqual(be.launch('x.exe'), 'PI')
        self.assertEqual(calls['launch'], [('x.exe', a._job_handle)])
        be.terminate()
        self.assertEqual(calls['terminate'], 1)

    def test_backend_base_subclass(self):
        self.assertTrue(issubclass(AppContainerBackend, _SandboxBackend))
        self.assertTrue(issubclass(SandboxieBackend, _SandboxBackend))


class TestSandboxieOwnPathExemption(unittest.TestCase):
    """Sandboxie 自身组件必须被识别为"自己人"，否则会被当非信任程序强杀。"""

    def test_sandboxie_install_dir_exempted(self):
        from engine.process_protection import ProcessProtection as P
        for exe in (r'C:\Program Files\Sandboxie-Plus\Start.exe',
                    r'C:\Program Files\Sandboxie-Plus\SbieSvc.exe',
                    r'C:\Program Files\Sandboxie-Plus\SandboxieRpcSs.exe',
                    r'C:\Program Files\Sandboxie-Plus\SandboxieDcomLaunch.exe',
                    r'C:\Program Files\Sandboxie-Plus\SbieCtrl.exe'):
            self.assertTrue(P._is_sandboxie_own_path(exe), exe)

    def test_other_paths_not_exempted(self):
        from engine.process_protection import ProcessProtection as P
        for exe in (r'D:\evil\x.exe', r'C:\Users\a\Desktop\m.exe', ''):
            self.assertFalse(P._is_sandboxie_own_path(exe), exe)


class TestSandboxieBoxReady(unittest.TestCase):
    """盒可用性判定的失败路径（免装 Sandboxie 即可校验）。"""

    def test_unavailable_when_no_start_exe(self):
        a = SandboxAnalyzer(SandboxConfig())
        be = SandboxieBackend(a, {'available': True, 'start': '', 'ini': '', 'dir': ''})
        self.assertFalse(be.is_box_available())
        self.assertFalse(be.ensure_ready())

    def test_unavailable_when_start_exe_missing(self):
        a = SandboxAnalyzer(SandboxConfig())
        be = SandboxieBackend(a, {
            'available': True, 'start': r'C:\__no_such__\Start.exe',
            'ini': r'C:\__no_such__\SbieIni.exe', 'dir': ''})
        self.assertFalse(be.is_box_available())

    def test_default_box_name_is_dedicated(self):
        """默认必须用专用盒，避免清空用户自己的 DefaultBox。"""
        self.assertEqual(SandboxConfig().sandboxie_box, 'PSLS_Analysis')


class TestSandboxieBoxElevationAutomation(unittest.TestCase):
    """分析盒必须自动化处理样本的 UAC 提权请求。

    默认 Sandboxie 的 UAC 代理会弹「是否给予管理员权限」窗；分析环境无人
    确认 → 样本卡在提权处、零行为 → 被误判 clean（实测 salinewin 等）。
    因此需在专用盒内下发改三项设置，且必须落在盒段（非 [GlobalSettings]）。
    """

    def _backend(self):
        a = SandboxAnalyzer(SandboxConfig())
        be = SandboxieBackend(a, {
            'available': True, 'start': r'C:\__x__\Start.exe',
            'ini': r'C:\__x__\SbieIni.exe', 'dir': r'C:\__x__'})
        be._file_root = ''            # 跳过 makedirs
        be.is_box_available = lambda: True
        calls = []
        be._run_ini = lambda args, timeout=15.0: calls.append(args)
        return be, calls

    def test_ensure_box_automates_uac(self):
        be, calls = self._backend()
        self.assertTrue(be.ensure_box())
        flat = [' '.join(c) for c in calls]
        box = SandboxConfig().sandboxie_box
        for key, val in (('DropAdminRights', 'y'),
                         ('FakeAdminRights', 'y'),
                         ('NoUACProxy', 'n')):
            self.assertIn(f'set {box} {key} {val}', flat)

    def test_never_writes_global_settings(self):
        """UAC 自动化只能落在盒段，绝不能改全局设置影响用户其它盒。"""
        be, calls = self._backend()
        be.ensure_box()
        for c in calls:
            self.assertNotIn('GlobalSettings', c)


class TestSandboxiePopupSuppression(unittest.TestCase):
    """分析盒必须抑制 Sandboxie 界面弹窗 + 关闭自动兼容性模板注入。

    实测：分析盒被 SbieCtrl 自动写入了 `RecoverFolder=%Desktop%/%Personal%/
    Downloads` 和一串兼容性 Template（SkipHook 等）。样本一写桌面/文档就弹
    "可恢复文件"窗；模板弱化隔离甚至把写操作放行到真实系统（"有些对象跑到
    沙箱外"）。
    """

    def _backend(self, user_section=''):
        a = SandboxAnalyzer(SandboxConfig())
        be = SandboxieBackend(a, {
            'available': True, 'start': r'C:\__x__\Start.exe',
            'ini': r'C:\__x__\SbieIni.exe', 'dir': r'C:\__x__'})
        be._file_root = ''
        be.is_box_available = lambda: True
        be._find_user_settings_section = lambda: user_section
        calls = []
        be._run_ini = lambda args, timeout=15.0: calls.append(args)
        return be, calls

    def test_box_level_popup_suppression(self):
        be, calls = self._backend()
        self.assertTrue(be.ensure_box())
        flat = [' '.join(c) for c in calls]
        box = SandboxConfig().sandboxie_box
        self.assertIn(f'set {box} AutoRecover n', flat)      # 关"可恢复文件"弹窗
        self.assertIn(f'set {box} BlockNetworkFiles y', flat)
        # 清掉界面注入的恢复目录（无值 = 删除该键所有行）
        self.assertIn(f'set {box} RecoverFolder', flat)

    def test_compat_automation_written_to_user_section(self):
        be, calls = self._backend('UserSettings_TEST')
        be.ensure_box()
        flat = [' '.join(c) for c in calls]
        self.assertIn('set UserSettings_TEST SbieCtrl_AutoRunSoftCompat n', flat)
        self.assertIn('set UserSettings_TEST SbieCtrl_AutoApplySettings n', flat)
        for c in calls:
            self.assertNotIn('GlobalSettings', c)

    def test_no_user_section_means_no_global_fallback(self):
        """找不到 UserSettings 段时跳过，绝不退回写 GlobalSettings。"""
        be, calls = self._backend('')
        be.ensure_box()
        flat = [' '.join(c) for c in calls]
        self.assertFalse(any('SbieCtrl_' in f for f in flat))
        for c in calls:
            self.assertNotIn('GlobalSettings', c)


class TestSandboxieUiSuppression(unittest.TestCase):
    """启动早期的 Sandboxie 界面弹窗抑制（软件兼容性 / 可恢复文件）。

    弹窗是由 SbieCtrl.exe（CThirdPartyDialog）在**启动时**读
    `SbieCtrl_AutoRunSoftCompat` 决定是否弹出的 —— 只在"分析时"写太晚。
    另外：写入失败会触发 `SBIE2322 无法重写 Sandboxie.ini` 弹窗刷屏，
    故写入必须受 `_sbie_ini_writes_allowed()` 保护。
    """

    def setUp(self):
        import engine.sandbox_analyzer as sa
        self.sa = sa
        self._old_blocked = sa._SBIE_INI_WRITE_BLOCKED
        self._old_elev = sa._is_elevated
        sa._SBIE_INI_WRITE_BLOCKED = False
        sa._is_elevated = lambda: True          # 假装管理员（可写）

    def tearDown(self):
        self.sa._SBIE_INI_WRITE_BLOCKED = self._old_blocked
        self.sa._is_elevated = self._old_elev

    def test_skips_when_backend_unavailable(self):
        old = self.sa.detect_sandboxie_backend
        self.sa.detect_sandboxie_backend = lambda: {'available': False}
        try:
            self.assertFalse(self.sa.suppress_sandboxie_ui_popups())
        finally:
            self.sa.detect_sandboxie_backend = old

    def test_non_admin_writes_nothing(self):
        """非管理员 → 一个字节都不写（否则 SBIE2322 弹窗刷屏）。"""
        sa = self.sa
        sa._is_elevated = lambda: False
        sa._SBIE_INI_WRITE_BLOCKED = False
        old_detect = sa.detect_sandboxie_backend
        old_run = sa.subprocess.run
        calls = []
        sa.detect_sandboxie_backend = lambda: {'available': True, 'ini': __file__}
        sa.subprocess.run = lambda cmd, **k: calls.append(cmd)
        try:
            self.assertFalse(sa.suppress_sandboxie_ui_popups())
        finally:
            sa.detect_sandboxie_backend = old_detect
            sa.subprocess.run = old_run
        self.assertEqual(calls, [], '非管理员不得发起任何 SbieIni 写入')

    def test_writes_box_and_user_section_never_global(self):
        sa = self.sa

        class _R:
            returncode = 0

            def __init__(self, out=''):
                self.stdout = out

        calls = []
        old_detect = sa.detect_sandboxie_backend
        old_run = sa.subprocess.run
        sa.detect_sandboxie_backend = lambda: {
            'available': True, 'ini': __file__}      # 用存在的文件绕开 isfile

        def _fake_run(cmd, **k):
            calls.append(cmd)
            if len(cmd) >= 2 and cmd[1] == 'query':
                if len(cmd) == 3:
                    return _R('UserSettings_ABC\nPSLS_Analysis\n')
                return _R('n\n')                     # 读回校验：写入已生效
            return _R()

        sa.subprocess.run = _fake_run
        try:
            self.assertTrue(sa.suppress_sandboxie_ui_popups())
        finally:
            sa.detect_sandboxie_backend = old_detect
            sa.subprocess.run = old_run

        flat = [' '.join(c[1:]) for c in calls]      # 去掉 ini_exe 路径
        box = SandboxConfig().sandboxie_box
        self.assertIn(f'set {box} AutoRecover n', flat)
        self.assertIn(f'set {box} RecoverFolder', flat)
        self.assertIn(f'set {box} BlockNetworkFiles y', flat)
        self.assertIn('set UserSettings_ABC SbieCtrl_AutoRunSoftCompat n', flat)
        self.assertIn('set UserSettings_ABC SbieCtrl_AutoApplySettings n', flat)
        self.assertFalse([f for f in flat if 'GlobalSettings' in f],
                         '界面弹窗抑制绝不能写 [GlobalSettings]')

    def test_dialog_sweeper_never_raises(self):
        self.assertIsInstance(self.sa._close_sandboxie_dialogs(), int)


class TestEscapeDetectionPerBackend(unittest.TestCase):
    """逃逸强杀按后端区分：

    基线差异法会把分析窗口内**任何**新出现的系统进程（浏览器/杀软更新等）
    当成逃逸并强杀（实测误杀 msedge/smartscreen）。Sandboxie 由内核级重定向
    提供隔离，样本进程全部在盒内，故该后端停用逃逸强杀；AppContainer 链路
    保持原有行为不变。
    """

    def test_sandboxie_backend_skips_escape_detection(self):
        a = SandboxAnalyzer(SandboxConfig())
        a._baseline_pids = set()          # 让所有进程都算"新增"
        a._escaped_pids = set()
        a._target_pid = -1
        a._block_process_net = lambda pid: False
        a._terminate_proc_hard = lambda pid: None
        a._sbie_pid_provider = lambda: []  # 置位 Sandboxie 标志
        a._detect_escaped_processes()
        self.assertEqual(a._escaped_pids, set())

    def _analyzer(self):
        a = SandboxAnalyzer(SandboxConfig())
        a._baseline_pids = set()          # 让所有进程都算"新增"
        a._escaped_pids = set()
        a._target_pid = -1
        a._block_process_net = lambda pid: False
        a._terminate_proc_hard = lambda pid: None
        return a

    def test_unrelated_new_process_not_flagged(self):
        """与沙箱无关的新进程（浏览器/杀软等）不得被判为逃逸并强杀。"""
        import logging
        logging.disable(logging.WARNING)
        try:
            a = self._analyzer()
            a._work_dir = r'C:\__no_such_work_dir__'
            a._sandbox_file_path = r'C:\__no_such_work_dir__\sample.exe'
            a._detect_escaped_processes()
            self.assertEqual(a._escaped_pids, set())
        finally:
            logging.disable(logging.NOTSET)

    def test_attributable_process_flagged(self):
        """可归因于沙箱的新进程（镜像位于沙箱工作目录）仍应被检出。

        用 System32 这种长期驻留多个守护进程的目录做归因基准，避免
        依赖"某一个 PID 恰好没退出"而出现随机失败。
        """
        import logging
        import psutil
        cand_dir = None
        for p in psutil.process_iter(['pid', 'exe']):
            e = p.info.get('exe') or ''
            if e and os.path.dirname(e).lower().endswith('system32'):
                cand_dir = os.path.dirname(e)
                break
        if not cand_dir:
            self.skipTest('未找到 System32 下的稳定进程')
        logging.disable(logging.WARNING)
        try:
            a = self._analyzer()
            a._work_dir = cand_dir
            a._sandbox_file_path = os.path.join(cand_dir, 'sample.exe')
            a._detect_escaped_processes()
            self.assertGreater(len(a._escaped_pids), 0)
        finally:
            logging.disable(logging.NOTSET)


class TestListPidsParsing(unittest.TestCase):
    """校验 Start.exe /listpids 输出解析。

    实测格式：首行=进程数 N，其后 N 行各一个 PID（空盒输出 "0"）。
    旧实现把计数当成 PID，导致 _target_pid 指向 Sandboxie 基础设施进程
    （常驻）→ 监控白等到超时（"卡住"根因）。
    """

    def test_count_header_stripped(self):
        out = '3\r\n32184\r\n29604\r\n37248\r\n'
        self.assertEqual(SandboxieBackend._parse_listpids(out),
                         [32184, 29604, 37248])

    def test_empty_box(self):
        self.assertEqual(SandboxieBackend._parse_listpids('0\n'), [])
        self.assertEqual(SandboxieBackend._parse_listpids(''), [])

    def test_single_pid_with_header(self):
        self.assertEqual(SandboxieBackend._parse_listpids('1\n1234\n'), [1234])

    def test_no_header_fallback(self):
        self.assertEqual(SandboxieBackend._parse_listpids('1234\n'), [1234])

    def test_comma_separated(self):
        self.assertEqual(SandboxieBackend._parse_listpids('1234, 5678'),
                         [1234, 5678])


class TestSandboxiePopupWatcherHardened(unittest.TestCase):
    """弹窗清理必须能在"属主进程名兜不住"时靠标题关键字兜底。

    实测：向导可能在 Sandboxie 界面进程启动时（安装后 / 开机自启）弹出，
    那时 PSLS 还没跑、或 PSLS 非管理员（写不了 ini，抑制写入被跳过）。
    因此窗口清理必须：
      * 不因"没找到 Sandboxie 界面进程"就直接放弃（旧实现 `if not ui_pids: return`）；
      * 认识向导标题（软件兼容性 / 可恢复文件 / SBIE）。
    """

    def setUp(self):
        import engine.sandbox_analyzer as sa
        self.sa = sa

    def test_title_keywords_cover_wizard(self):
        kws = self.sa._SBIE_DIALOG_TITLE_KEYWORDS
        self.assertIn('软件兼容性', kws)
        self.assertIn('可恢复文件', kws)
        self.assertTrue(any('SBIE' in k for k in kws))

    def test_sweeper_does_not_bail_without_ui_pids(self):
        src = open(os.path.join(ROOT, 'engine', 'sandbox_analyzer.py'),
                   'r', encoding='utf-8').read()
        start = src.index('def _close_sandboxie_dialogs')
        end = src.index('def start_sandboxie_popup_watcher', start)
        body = src[start:end]
        self.assertNotIn(
            'if not ui_pids:\n        return 0', body,
            '不得因未发现 Sandboxie 界面进程就放弃清理（标题兜底是必需的）')
        self.assertIn('_SBIE_DIALOG_TITLE_KEYWORDS', body)
        self.assertIn('BM_CLICK', body, '需在 WM_CLOSE 无效时点按钮兜底')

    def test_autostart_disabled_prevents_wizard_before_psls(self):
        """抑制必须同时关掉界面自启：向导是界面启动时弹的，可能早于 PSLS。"""
        src = open(os.path.join(ROOT, 'engine', 'sandbox_analyzer.py'),
                   'r', encoding='utf-8').read()
        self.assertIn('SbieCtrl_EnableAutoStart', src)

    def test_installer_suppresses_popups_at_install_time(self):
        """安装器（管理员）必须在安装 Sandboxie 后立即写入抑制键。"""
        iss = open(os.path.join(ROOT, 'installer', 'PSLS_Setup.iss'),
                   'r', encoding='utf-8').read()
        self.assertIn('GetSbieIniPath', iss)
        self.assertIn('SbieIniExists', iss)
        for key in ('SbieCtrl_AutoRunSoftCompat', 'SbieCtrl_AutoApplySettings',
                    'SbieCtrl_EnableAutoStart', 'AutoRecover'):
            self.assertIn(key, iss,
                          f'安装脚本缺少 {key} 的抑制写入（向导/恢复弹窗仍会出现）')


if __name__ == '__main__':
    unittest.main()