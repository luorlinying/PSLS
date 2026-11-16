# -*- coding: utf-8 -*-
"""两现象回归：自启动拦截文案语义 + 自我保护进程树覆盖。

现象 1（"拦截成功却提示回滚失败"）：
  - 根因是 autostart 模块把"注册表项清理失败"当成整体 `success=False`，且文案
    使用"回滚失败"一词（与勒索文件回滚链路混淆），**并非**事件串台。
  - 断言：清理失败时仍 `success=True`（拦截已生效）、文案不含"回滚"；
    自启动链路不发射 `ransomwareRollbackRequested`；"回滚失败"仅属真实回滚路径。

现象 2（任务管理器结束任务树可杀）：
  - 驱动原只保护单一 PID；已扩展为 PID 集合（主进程 + worker/MLWorker）。
  - 用户态新增进程树 DACL 覆盖。
  - 断言：保护名单含主进程，辅助进程被覆盖；驱动源码为集合语义且保留清空通道。
"""
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.autostart_protection import AutostartProtection
import engine.self_protection as sp


class TestAutostartSemantics(unittest.TestCase):

    def _engine(self, cleanup_ok):
        results = []
        e = AutostartProtection(on_result=lambda r: results.append(r))
        e.rollback_value = lambda fp, vn: cleanup_ok
        return e, results

    def test_cleanup_failure_not_reported_as_rollback_failure(self):
        e, results = self._engine(cleanup_ok=False)
        e.on_user_block({'full_path': 'HKCU\\..\\Run', 'value_name': 'x',
                         'name': 'evil.exe'})
        self.assertEqual(len(results), 1)
        r = results[0]
        # 拦截决策已生效 → success 必须为 True（此前为 False → 弹窗显示"失败"）
        self.assertTrue(r['success'], '拦截成功不得被标记为失败')
        self.assertFalse(r['cleanup_ok'])
        self.assertNotIn('回滚', r['message'], '文案不得出现"回滚"（避免与勒索回滚混淆）')
        self.assertNotIn('失败', r['message'])
        self.assertIn('需', r['message'])   # 提示可能需管理员权限

    def test_cleanup_success_message(self):
        e, results = self._engine(cleanup_ok=True)
        e.on_user_block({'full_path': 'HKCU\\..\\Run', 'value_name': 'x',
                         'name': 'evil.exe'})
        r = results[0]
        self.assertTrue(r['success'])
        self.assertTrue(r['cleanup_ok'])
        self.assertEqual(r['message'], '已拦截该自启动项')
        self.assertNotIn('回滚', r['message'])

    def test_rollback_value_is_idempotent(self):
        """键不存在 → 目标已达成，返回 True（此前返回 False → 假"回滚失败"）。"""
        import engine.autostart_protection as ap
        e = ap.AutostartProtection()
        fake_winreg = mock.MagicMock()
        fake_winreg.OpenKey.side_effect = FileNotFoundError('no key')
        with mock.patch.object(ap, 'HAS_WINREG', True), \
                mock.patch.object(ap, 'winreg', fake_winreg):
            self.assertTrue(e._rollback_value(None, 'Some\\Path', 'v', None))

    def test_autostart_path_never_emits_rollback_request(self):
        """自启动链路不得发射勒索回滚请求（证实：不是事件串台）。"""
        with open(os.path.join(ROOT, 'engine', 'autostart_protection.py'),
                  'r', encoding='utf-8') as f:
            eng = f.read()
        self.assertNotIn('ransomwareRollbackRequested', eng)
        with open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                  'r', encoding='utf-8') as f:
            br = f.read()
        # 取 _on_autostart_suspicious 到下一个方法定义之间
        seg = br.split('def _on_autostart_suspicious', 1)[1].split('\n    def ', 1)[0]
        self.assertNotIn('ransomwareRollbackRequested', seg)
        self.assertNotIn('rollbackCompleted', seg)
        self.assertNotIn('回滚', seg, '自启动拦截文案不得使用"回滚"措辞')
        self.assertIn('blocked_ok', seg)

    def test_rollback_failure_text_only_in_rollback_path(self):
        """真实的勒索回滚结果才用 failed/成功 文案；两套主题/共享 js 无"拦截回滚失败"。"""
        with open(os.path.join(ROOT, 'ui', 'webview', 'app.js'),
                  'r', encoding='utf-8') as f:
            js = f.read()
        self.assertIn("action === 'state_refresh'", js)
        self.assertIn('obj.failed', js)            # 真实回滚失败 → warning
        self.assertNotIn('拦截回滚失败', js)
        for name in ('index.html', 'terminal.html'):
            with open(os.path.join(ROOT, 'ui', 'webview', name),
                      'r', encoding='utf-8') as f:
                html = f.read()
            self.assertNotIn('拦截回滚失败', html, name)
            self.assertNotIn('回滚失败', html, name)


class TestSelfProtectionTreeCoverage(unittest.TestCase):

    def test_owned_pids_includes_self(self):
        s = sp.SelfProtection()
        pids = s._iter_psls_owned_pids()
        self.assertIn(os.getpid(), pids)

    def test_related_protect_covers_helpers_excludes_main(self):
        s = sp.SelfProtection()
        called = []

        fake_procs = [
            mock.MagicMock(info={'pid': 111, 'name': 'PSLS.exe'}),
            mock.MagicMock(info={'pid': 222, 'name': 'MLWorker.exe'}),
            mock.MagicMock(info={'pid': 333, 'name': 'notepad.exe'}),
        ]
        fake_me = mock.MagicMock(pid=os.getpid())
        fake_me.children.return_value = [mock.MagicMock(pid=444)]  # worker

        fake_ps = mock.MagicMock()
        fake_ps.Process.return_value = fake_me
        fake_ps.process_iter.return_value = fake_procs

        with mock.patch.dict(sys.modules, {'psutil': fake_ps}), \
                mock.patch.object(sp, '_apply_process_dacl_protection',
                                  side_effect=lambda pid=0: (called.append(pid), True)[1]):
            protected = s._protect_related_processes()

        self.assertNotIn(os.getpid(), called, '主进程不得重复计入辅助列表')
        self.assertIn(111, called)      # 同名 PSLS.exe
        self.assertIn(222, called)      # MLWorker.exe
        self.assertIn(444, called)      # 子孙 worker
        self.assertNotIn(333, called, '非 PSLS 进程不得被保护')
        self.assertEqual(sorted(protected), sorted([111, 222, 444]))

    def test_disable_revokes_helpers(self):
        s = sp.SelfProtection()
        removed = []
        s._dacl_related_pids = [111, 222]
        with mock.patch.object(sp, '_remove_process_dacl_protection',
                               side_effect=lambda pid=0: removed.append(pid)):
            s._unprotect_related_processes()
        self.assertEqual(sorted(removed), [111, 222])
        self.assertEqual(s._dacl_related_pids, [])


class TestDriverMultiPidSource(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(ROOT, 'driver', 'src', 'protect.c'),
                  'r', encoding='utf-8') as f:
            self.src = f.read()

    def test_terminate_masked(self):
        self.assertIn('PROCESS_TERMINATE', self.src)
        self.assertIn('DesiredAccess', self.src)

    def test_multi_pid_set(self):
        self.assertIn('PSLS_MAX_PROTECT_PIDS', self.src)
        self.assertIn('g_PslsProcSet', self.src)
        self.assertIn('g_PslsProcCount', self.src)
        self.assertIn('Protect_IsPslsPid', self.src)

    def test_abi_unchanged_and_clear_channel_kept(self):
        # 复用同一 IOCTL：结构体不可改（ABI 不变）
        with open(os.path.join(ROOT, 'driver', 'include', 'psls_shared.h'),
                  'r', encoding='utf-8') as f:
            shared = f.read()
        self.assertIn('_PSLS_SET_PID', shared)
        # pid==0 → 清空集合（保留退出/卸载通道，绝不造成无法卸载）
        self.assertIn('target set cleared', self.src)
        self.assertIn('g_Driver.PslsPid = 0;', self.src)
        self.assertIn('Protect_Cleanup', self.src)


if __name__ == '__main__':
    unittest.main()