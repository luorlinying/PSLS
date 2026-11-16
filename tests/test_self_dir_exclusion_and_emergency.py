# -*- coding: utf-8 -*-
"""两项"未响应" + 紧急终止 回归。

实测（用户截图 2026-10-07）：
  图1 手动回滚卡在 96%「正在扫描受影响目录（已扫描 500 个文件）」→ 主窗口未响应
  图2 再次启动 PSLS 自动弹出的"入仓"弹窗停在 60%，背后刷屏
      `skipped C:\\Users\\nightingale\\Desktop\\PSLS\\icon.ico`、`...\\Sandboxie\\7z.dll` …
      （PSLS 装在桌面 → 把自己的安装目录也纳入快照范围）
"""
import os
import re
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

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback
import ui.webview.bridge as bmod


class TestPslsSelfDirExcluded(unittest.TestCase):
    """需求 1：PSLS 自身目录（安装根）必须排除出 快照 / 残留扫描 / 入仓候选。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_self_')
        # 模拟"PSLS 装在桌面"：<tmp>\Desktop\PSLS（安装根）与 <tmp>\Desktop\<其它>
        self.desktop = os.path.join(self.tmp, 'Desktop')
        self.install = os.path.join(self.desktop, 'PSLS')
        os.makedirs(os.path.join(self.install, 'Sandboxie'))
        os.makedirs(os.path.join(self.install, '_internal'))
        os.makedirs(os.path.join(self.install, 'db_backup'))
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        # 自身目录内文件（应被排除）
        for rel in ('PSLS.exe', 'icon.ico', 'LICENSE.GPL3.txt',
                    os.path.join('Sandboxie', '7z.dll'),
                    os.path.join('Sandboxie', 'imdisk_files.cab'),
                    os.path.join('_internal', 'python310.dll'),
                    os.path.join('db_backup', 'signatures.db')):
            p = os.path.join(self.install, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, 'wb') as f:
                f.write(b'SELF')
        # 桌面上的用户文件（应被纳入）
        self.user_file = os.path.join(self.desktop, 'report.docx')
        with open(self.user_file, 'wb') as f:
            f.write(b'USER')
        self._fake_root = mock.patch.object(
            rr, '_psls_self_roots',
            return_value=[os.path.normcase(self.install).rstrip('\\/'),
                          os.path.normcase(rr._REPO_ROOT).rstrip('\\/')])
        self._fake_root.start()

    def tearDown(self):
        self._fake_root.stop()
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_self_files_not_hashed_user_files_are(self):
        m = RansomwareRollback(protected_dirs=[self.desktop])
        r = m.snapshot_now('startup', replace=True)
        entries = m._generations[0]['entries']
        keys = {os.path.normcase(os.path.abspath(k)) for k in entries}
        norm_install = os.path.normcase(self.install)
        self.assertFalse([k for k in keys if k.startswith(norm_install)],
                         '自身安装目录内文件不得入仓')
        self.assertGreater(r.get('hashed', 0), 0)
        self.assertIn(os.path.normcase(os.path.abspath(self.user_file)), keys,
                      '桌面上的用户文件仍应被纳入')

    def test_desktop_itself_is_not_excluded(self):
        """只排安装根子树，绝不把整个桌面排掉。"""
        m = RansomwareRollback(protected_dirs=[self.desktop])
        dirs = [d for d in m.get_protected_dirs()
                if not rr._is_psls_self_path(d)]
        self.assertIn(self.desktop, dirs, '桌面本身不得被排除')

    def test_residual_scan_skips_self_subtree(self):
        m = RansomwareRollback(protected_dirs=[self.desktop])
        m.snapshot_now('startup', replace=True)
        # 在自身目录里放一个"加密残留"形态文件：不得被隔离
        bad = os.path.join(self.install, 'icon.ico.locked')
        with open(bad, 'wb') as f:
            f.write(b'L')
        qm = mock.MagicMock()
        qm.quarantine_file.return_value = True
        m._quarantine_manager = qm
        m._quarantine_residuals(m._generations[0]['entries'])
        self.assertFalse(qm.quarantine_file.called,
                         '自身目录内的残留件不得被隔离扫描命中')

    def test_prefix_match_does_not_confuse_sibling(self):
        """`...\\PSLS2` 不应被当作 `...\\PSLS` 的子路径。"""
        sibling = self.install + '2'
        os.makedirs(sibling, exist_ok=True)
        self.assertFalse(rr._is_psls_self_path(os.path.join(sibling, 'a.txt')))


class TestProgressThrottle(unittest.TestCase):
    """需求 2/3：进度推送限流 + 单调推进 + 前端推送条数受限。"""

    def _bridge(self):
        b = bmod.PyBridge.__new__(bmod.PyBridge)
        b._rollback_progress_last = 0.0
        b._rollback_progress_last_pct = -1
        b._rollback_progress_last_stage = ''
        b._rollback_progress_sent = 0
        b._rollback_progress_dropped = 0
        return b

    def test_2000_progress_frames_are_throttled(self):
        b = self._bridge()
        sent = []
        with mock.patch.object(bmod.time, 'time') as t:
            for i in range(2000):
                t.return_value = 1000.0 + i * 0.001      # 1ms/帧 → 1000 帧/秒
                if b._throttle_rollback_progress(
                        {'stage': '入仓中', 'percent': 60, 'text': 'x'}):
                    sent.append(i)
        self.assertLessEqual(len(sent), 21,
                             '限流应 ≤10 帧/秒（2s 窗口 ≈ ≤20）')
        self.assertGreater(b._rollback_progress_dropped, 1900)

    def test_percent_is_monotonic(self):
        b = self._bridge()
        t0 = [1000.0]
        with mock.patch.object(bmod.time, 'time',
                               side_effect=lambda: t0[0]):
            pcts = []
            seq = [5, 20, 60, 40, 96, 99, 100]        # 含回退 40
            for i, p in enumerate(seq):
                t0[0] = 1000.0 + i
                d = {'stage': 'S', 'percent': p}
                if b._throttle_rollback_progress(d):
                    pcts.append(d['percent'])
        self.assertEqual(pcts, sorted(pcts), f'进度不得回退: {pcts}')

    def test_key_frames_always_pass(self):
        b = self._bridge()
        t0 = [1000.0]
        with mock.patch.object(bmod.time, 'time', side_effect=lambda: t0[0]):
            self.assertTrue(b._throttle_rollback_progress(
                {'stage': '扫描', 'percent': 10}))
            t0[0] += 0.001
            self.assertTrue(b._throttle_rollback_progress(
                {'stage': '入仓中', 'percent': 10}), '阶段变化必须放行')
            t0[0] += 0.001
            self.assertTrue(b._throttle_rollback_progress(
                {'stage': '入仓中', 'percent': 60}), '百分比前进必须放行')

    def test_no_new_files_skips_ingest_stage(self):
        """无新增文件 → 不进入"入仓中 60%"，直接推进（窗口快速结束）。"""
        tmp = tempfile.mkdtemp(prefix='psls_noNew_')
        docs = os.path.join(tmp, 'docs')
        os.makedirs(docs)
        old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        try:
            with open(os.path.join(docs, 'a.txt'), 'wb') as f:
                f.write(b'A')
            ev = []
            m = RansomwareRollback(protected_dirs=[docs],
                                   on_progress=lambda p: ev.append(dict(p)))
            m.snapshot_now('startup', replace=True)
            ev.clear()
            r = m.snapshot_now('startup', replace=True)     # 第二次：全部继承
            self.assertEqual(r.get('hashed'), 0)
            stages = [(e.get('stage'), e.get('percent')) for e in ev]
            self.assertNotIn(('入仓中', 60), stages,
                             '无新增时不得停在"入仓中 60%"')
            self.assertTrue(any(s == '入仓中' and p >= 90 for s, p in stages)
                            or any(p >= 100 for _s, p in stages),
                            f'应快速推进到 90%+/完成: {stages}')
        finally:
            rr._REPO_ROOT = old
            shutil.rmtree(tmp, ignore_errors=True)

    def test_main_thread_not_blocked_by_flood(self):
        """2000 帧洪峰下主线程（模拟 GUI tick）不被长时间占用。"""
        b = self._bridge()
        worst = [0.0]
        stop = threading.Event()

        def _gui():
            while not stop.is_set():
                t0 = time.perf_counter()
                time.sleep(0.001)
                worst[0] = max(worst[0], (time.perf_counter() - t0) * 1000)
        th = threading.Thread(target=_gui, daemon=True)
        th.start()
        for i in range(2000):
            b._throttle_rollback_progress(
                {'stage': '入仓中', 'percent': 60, 'text': 'f%d' % i})
        stop.set()
        th.join(timeout=1)
        self.assertLess(worst[0], 200, f'GUI tick 最长 {worst[0]:.0f}ms')


class TestEmergencyTerminate(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_ek_')
        docs = os.path.join(self.tmp, 'docs')
        os.makedirs(docs)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    class _Proc:
        def __init__(self, pid, name):
            self.pid = pid
            self.info = {'pid': pid, 'name': name}
            self.terminated = False
            self.killed = False

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True

    def _fake_psutil(self, procs):
        m = mock.MagicMock()
        m.process_iter.return_value = procs
        m.wait_procs.return_value = (procs, [])
        return m

    def _engine_with_procs(self, procs):
        m = RansomwareRollback(protected_dirs=[os.path.join(self.tmp, 'docs')])
        m._running = True
        m._kill_all_before_restore = True
        fake = self._fake_psutil(procs)
        m._protected_pids = lambda ps: {os.getpid()}
        return m, fake

    def test_unconfirmed_reason_does_nothing(self):
        procs = [self._Proc(1234, 'steam.exe')]
        m, fake = self._engine_with_procs(procs)
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            out = m._kill_all_non_system('auto_detect')
        self.assertEqual(out['killed'], [])
        self.assertIn('unconfirmed_reason', out['skipped_reason'])
        self.assertFalse(procs[0].terminated)

    def test_emergency_and_rollback_both_kill_third_party(self):
        """方案 B：紧急终止与回滚清场**同一规则**，且**都会**终止第三方。"""
        names = [('vmware-vmx.exe', 2001), ('qq.exe', 2002), ('wechat.exe', 2003),
                 ('wps.exe', 2004), ('VBoxSVC.exe', 2005), ('explorer.exe', 2006)]
        procs = [self._Proc(pid, n) for n, pid in names]

        def _run(reason, plist):
            m, fake = self._engine_with_procs(list(plist))
            with mock.patch.dict(sys.modules, {'psutil': fake}):
                return m._kill_all_non_system(reason)

        ek = _run('emergency', [self._Proc(p, n) for n, p in names])
        rbk = _run('user_confirmed', [self._Proc(p, n) for n, p in names])
        self.assertEqual(sorted(ek['killed']), sorted(rbk['killed']),
                         '两者终止集合规则必须完全一致')
        for n, _pid in names:
            # 引擎统一以小写进程名记账
            self.assertIn(n.lower(), ek['killed'], f'紧急终止应终止第三方: {n}')
            self.assertIn(n.lower(), rbk['killed'], f'回滚清场应终止第三方: {n}')

    def test_protection_set_still_enforced(self):
        """调整决定 2：保护集收窄 → 仅系统关键 / PSLS / 祖先子孙 / mlworker。

        Sandboxie 基础设施（SbieSvc/SbieCtrl/SandboxieRpcSs）不再保护 → 应被终止。
        """
        safe = [('lsass.exe', 3001), ('svchost.exe', 3002), ('csrss.exe', 3003),
                ('PSLS.exe', 3004), ('MLWorker.exe', 3005)]
        sandboxie = [('SbieSvc.exe', 3006), ('SbieCtrl.exe', 3007),
                     ('SandboxieRpcSs.exe', 3008)]
        procs = [self._Proc(pid, n) for n, pid in (safe + sandboxie)]
        m, fake = self._engine_with_procs(procs)
        # 模拟祖先/子孙链保护（_protected_pids 返回本进程 + 指定 pid）
        m._protected_pids = lambda ps: {os.getpid(), 3001}
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            out = m._kill_all_non_system('emergency')
        killed = set(out['killed'])
        for n, _pid in safe:
            self.assertNotIn(n.lower(), killed, f'{n} 必须受保护，不得误杀')
        for n, _pid in sandboxie:
            self.assertIn(n.lower(), killed,
                          f'{n} 为 Sandboxie 基础设施，收窄保护集后应被终止')
        self.assertGreaterEqual(out['protected'], len(safe))

    def test_no_include_third_party_parameter(self):
        """要求 1：不得再有 include_third_party 这类分支。"""
        import inspect
        sig = inspect.signature(RansomwareRollback._kill_all_non_system)
        self.assertNotIn('include_third_party', sig.parameters)
        src = open(os.path.join(ROOT, 'engine', 'ransomware_rollback.py'),
                   'r', encoding='utf-8').read()
        self.assertNotIn('include_third_party', src)

    def test_emergency_reason_accepted_and_rollback_still_requires_confirm(self):
        """要求 3：emergency 能通过受理白名单；自动/误报路径仍被挡。"""
        m, fake = self._engine_with_procs([self._Proc(4101, 'notepad.exe')])
        m._running = False                     # emergency 不依赖引擎运行
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            ek = m._kill_all_non_system('emergency')
        self.assertEqual(ek.get('skipped_reason'), '', 'emergency 必须能执行')
        self.assertIn('notepad.exe', ek['killed'])
        m2, fake2 = self._engine_with_procs([self._Proc(4102, 'notepad.exe')])
        with mock.patch.dict(sys.modules, {'psutil': fake2}):
            auto = m2._kill_all_non_system('auto_detect')       # 误报/自动路径
        self.assertIn('unconfirmed_reason', auto['skipped_reason'])
        self.assertEqual(auto['killed'], [])
        m3, fake3 = self._engine_with_procs([self._Proc(4103, 'notepad.exe')])
        m3._running = False
        with mock.patch.dict(sys.modules, {'psutil': fake3}):
            rbc = m3._kill_all_non_system('user_confirmed')     # 引擎未运行 → 不清场
        self.assertEqual(rbc['killed'], [])

    def test_file_layer_third_party_protection_unchanged(self):
        """要求 4：文件层第三方保护未被削弱（隔离残留/回滚写回仍跳过第三方目录）。"""
        import tempfile as _tf
        tmp = _tf.mkdtemp(prefix='psls_fileprot_')
        try:
            qq_dir = os.path.join(tmp, 'Tencent Files', '123', 'FileRecv')
            os.makedirs(qq_dir, exist_ok=True)
            qq_file = os.path.join(qq_dir, 'msg.db')
            with open(qq_file, 'wb') as f:
                f.write(b'QQDATA')
            self.assertTrue(rr._is_protected_app_path(qq_file),
                            'QQ 目录仍须受文件层保护')
            self.assertTrue(rr._is_protected_app_name('qq.exe'),
                            '第三方名单判定本身保留（仅供文件层使用）')
            vm_dir = os.path.join(tmp, 'VMware', 'vm1')
            os.makedirs(vm_dir, exist_ok=True)
            vm_file = os.path.join(vm_dir, 'vm.vmx')
            with open(vm_file, 'wb') as f:
                f.write(b'VMX')
            self.assertTrue(rr._is_protected_app_path(vm_file))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_audit_contains_reason_counts_and_examples(self):
        """要求 5：审计含 reason / 计数 / 示例进程名。"""
        m, fake = self._engine_with_procs([self._Proc(5001, 'steam.exe'),
                                           self._Proc(5002, 'qq.exe')])
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            m._kill_all_non_system('emergency')
        logs = [a for a in m.get_audit_log() if a.get('action') == '清场终止']
        self.assertTrue(logs, '应有"清场终止"审计')
        detail = logs[-1]['detail']
        for frag in ('reason=emergency', '终止=', '失败=', '保护=', '示例=', 'steam.exe'):
            self.assertIn(frag, detail, f'审计应含 {frag}: {detail}')

    def test_slot_direct_execute_without_confirm(self):
        """调整 1：零确认 → 直接执行，且不再返回 needs_confirm。"""
        b = bmod.PyBridge.__new__(bmod.PyBridge)
        rb = mock.MagicMock()
        rb._kill_all_non_system.return_value = {'killed': ['a.exe'], 'failed': [],
                                                'protected': 3}
        b._rollback_manager = rb
        b._add_activity = lambda *a, **k: None
        b._emit_tool_signal = lambda *a, **k: None
        t0 = time.time()
        res = json.loads(b.emergencyTerminateAll('{}'))       # 无 confirmed 也直接执行
        dt = (time.time() - t0) * 1000
        self.assertTrue(res.get('ok'))
        self.assertNotIn('needs_confirm', res)
        self.assertLess(dt, 200, f'槽必须立即返回（后台执行），实际 {dt:.0f}ms')
        for _ in range(50):
            if rb._kill_all_non_system.called:
                break
            time.sleep(0.02)
        rb._kill_all_non_system.assert_called_once()
        self.assertEqual(rb._kill_all_non_system.call_args[0][0], 'emergency',
                         'reason 必须落在受理白名单内（零确认直呼可执行）')
        self.assertEqual(len(rb._kill_all_non_system.call_args[0]), 1,
                         '不得再传 include_third_party')

    def test_engine_reason_manual_would_still_execute(self):
        """reason=manual_confirmed 属于既有确认白名单 → 不会被闸门挡住。"""
        m, fake = self._engine_with_procs([self._Proc(4001, 'notepad.exe')])
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            out = m._kill_all_non_system('manual_confirmed')
        self.assertEqual(out.get('skipped_reason'), '')
        self.assertIn('notepad.exe', out['killed'])

    def test_rollback_path_also_kills_third_party(self):
        """方案 B：回滚清场**不再**跳过第三方（与紧急终止同一规则）。"""
        third = self._Proc(3001, 'vmware-vmx.exe')
        normal = self._Proc(3002, 'notepad.exe')
        m, fake = self._engine_with_procs([third, normal])
        with mock.patch.dict(sys.modules, {'psutil': fake}):
            out = m._kill_all_non_system('user_confirmed')
        killed = set(out['killed'])
        self.assertIn('vmware-vmx.exe', killed, '回滚清场也应终止第三方')
        self.assertIn('notepad.exe', killed)

    def test_both_themes_have_emergency_button(self):
        for theme in ('index.html', 'terminal.html'):
            src = open(os.path.join(ROOT, 'ui', 'webview', theme),
                       'r', encoding='utf-8').read()
            self.assertIn('紧急终止', src, f'{theme} 应含"紧急终止"按钮')
            self.assertIn('cta-emergency', src, f'{theme} 应有 cta-emergency')
        app = open(os.path.join(ROOT, 'ui', 'webview', 'app.js'),
                   'r', encoding='utf-8').read()
        self.assertIn('emergencyTerminateAll', app)
        self.assertIn('cta-emergency', app)
        # 调整 1：紧急终止处理块内不得有确认弹窗（其它功能仍可各自使用 confirm）
        idx = app.find("getElementById('cta-emergency')")
        self.assertGreater(idx, 0)
        block = app[idx:idx + 900]
        self.assertNotIn('confirm', block, '紧急终止必须零确认')
        self.assertIn('emergencyTerminateAll', block)
        # 智能扫描能力入口保留（不删功能）
        self.assertIn('cta-scan', app)
        ih = open(os.path.join(ROOT, 'ui', 'webview', 'index.html'),
                  'r', encoding='utf-8').read()
        self.assertNotIn('>智能扫描<', ih.replace(' ', ''),
                         '主界面"智能扫描"入口应已被替换')


class TestProtectedDirsUiConsistentWithScanExclude(unittest.TestCase):
    """调整 3：保护目录 UI 与"扫描排除项"同一套实现 + 默认展示引擎目录。"""

    def _app(self):
        return open(os.path.join(ROOT, 'ui', 'webview', 'app.js'),
                    'r', encoding='utf-8').read()

    def test_shared_editor_used_by_both(self):
        app = self._app()
        self.assertIn('function renderPathList(', app)
        self.assertIn('function initPathListEditor(', app)
        # 两处都用同一套（渲染 + 交互）
        self.assertIn("renderPathList('scan-exclude-list'", app)
        self.assertIn("renderPathList('rb-dir-list'", app)
        self.assertIn("inputId: 'scan-exclude-input'", app)
        self.assertIn("inputId: 'rb-dir-input'", app)
        self.assertIn("browseBtnId: 'rb-dir-browse'", app)

    def test_both_themes_have_same_controls(self):
        for theme in ('index.html', 'terminal.html'):
            src = open(os.path.join(ROOT, 'ui', 'webview', theme),
                       'r', encoding='utf-8').read()
            for el in ('rb-dir-list', 'rb-dir-input', 'rb-dir-add', 'rb-dir-browse',
                       'scan-exclude-list', 'scan-exclude-add', 'scan-exclude-browse'):
                self.assertIn(el, src, f'{theme} 缺少 {el}')

    def test_default_dirs_from_engine(self):
        """未配置时默认展示引擎目录（桌面/文档/下载/图片/视频/音乐）。"""
        tmp = tempfile.mkdtemp(prefix='psls_defdirs_')
        old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        try:
            m = RansomwareRollback()          # 未指定 protected_dirs → 引擎默认
            defaults = m.get_default_protected_dirs()
            names = [os.path.basename(d).lower() for d in defaults]
            for want in ('desktop', 'documents', 'downloads', 'pictures',
                         'videos', 'music'):
                self.assertIn(want, names, f'引擎默认目录应含 {want}: {names}')
            # app.js 走引擎接口取默认（不硬编码目录）
            app = self._app()
            self.assertIn('getRollbackDefaultDirs', app)
        finally:
            rr._REPO_ROOT = old
            shutil.rmtree(tmp, ignore_errors=True)

    def test_set_snapshot_config_normalizes_and_dedups(self):
        """保存时规范化 + 剔除重叠子目录（与 _dedup_dirs 同规则）。"""
        tmp = tempfile.mkdtemp(prefix='psls_norm_')
        parent = os.path.join(tmp, 'Desktop')
        child = os.path.join(parent, 'PSLS')
        other = os.path.join(tmp, 'Docs')
        for d in (parent, child, other):
            os.makedirs(d, exist_ok=True)
        b = bmod.PyBridge.__new__(bmod.PyBridge)
        rb = RansomwareRollback(protected_dirs=[parent])
        # _dedup_dirs 是 staticmethod：经实例访问即为原函数（勿手动 __get__ 绑定）
        b._rollback_manager = rb
        saved = {}
        with mock.patch.object(bmod, '_save_ui_settings',
                               side_effect=lambda d: saved.update(d)), \
                mock.patch.object(bmod.PyBridge, '_apply_shadow_config',
                                  lambda self: None), \
                mock.patch.object(bmod.PyBridge, '_add_activity',
                                  lambda self, *a, **k: None):
            ok = b.setRollbackSnapshotConfig(json.dumps(
                {'dirs': [parent, child, other, other], 'exts': []}))
        try:
            self.assertTrue(ok)
            got = [os.path.normcase(p) for p in saved.get('rollback_snapshot_dirs', [])]
            self.assertIn(os.path.normcase(other), got)
            self.assertIn(os.path.normcase(parent), got)
            self.assertNotIn(os.path.normcase(child), got,
                             '重叠子目录应被剔除')
            self.assertEqual(len(got), len(set(got)), '应去重')
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()