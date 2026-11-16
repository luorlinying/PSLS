# -*- coding: utf-8 -*-
"""安全闸门回归：误报不得导致终止/移动/覆盖第三方文件（VMware/QQ 受损防护）。

覆盖：
  1. 清场仅"用户确认"路径可触发（见 test_rollback_kill_all_and_progress）；
  2. 正常第三方软件文件不会被当作"加密/改名残留"隔离移动（含 stem 误伤规则已移除）；
  3. 回滚绝不写回未快照过的路径；
  4. 回滚不覆盖第三方软件数据目录（QQ/VMware）；
  5. 自保护完整性基线只含 PSLS 自身文件；
  6. 不可逆操作均有审计日志。
"""
import os
import sys
import shutil
import hashlib
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import (
    RansomwareRollback, _is_protected_app_name, _is_protected_app_path)
import engine.self_protection as sp


class _FakeQM:
    """记录 quarantine_file 调用（不真正移动文件）。"""
    def __init__(self, do_move=False):
        self.calls = []
        self._do_move = do_move
    def quarantine_file(self, path, reason='', malware_name=''):
        self.calls.append(path)
        if self._do_move:
            try:
                os.remove(path)
            except Exception:
                pass
        return True


class _RollbackBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_gate_')
        self.docs = os.path.join(self.tmp, 'docs')
        os.makedirs(self.docs)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mgr(self, qm=None):
        return RansomwareRollback(protected_dirs=[self.docs],
                                  quarantine_manager=qm)

    def _write(self, name, data, sub=''):
        d = os.path.join(self.docs, sub) if sub else self.docs
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p


class TestProtectedAppHelpers(unittest.TestCase):
    def test_names(self):
        for n in ('vmware-vmx.exe', 'vmnat.exe', 'vmnetdhcp.exe',
                  'vmware-authd.exe', 'QQ.exe', 'Tim.exe', 'WeChat.exe',
                  'vmware.exe', 'VMWARE.EXE'):
            self.assertTrue(_is_protected_app_name(n), n)
        for n in ('notepad.exe', 'chrome.exe', 'evil.exe'):
            self.assertFalse(_is_protected_app_name(n), n)

    def test_paths(self):
        for p in (r'C:\Users\u\Documents\Tencent Files\123\Msg.db',
                  r'C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe',
                  r'C:\Users\u\Documents\WeChat Files\a\b.dat'):
            self.assertTrue(_is_protected_app_path(p), p)
        self.assertFalse(_is_protected_app_path(r'C:\Users\u\docs\a.txt'))


class TestResidualQuarantineSafe(_RollbackBase):

    def test_stem_lookalike_not_quarantined(self):
        """清单有 report.docx，磁盘上 report.txt 不得被当成残留隔离。"""
        qm = _FakeQM(do_move=True)
        m = self._mgr(qm)
        self._write('report.docx', b'DOCX')
        self._write('report.txt', b'TXT-legit')
        m.snapshot_now('startup', replace=True)
        txt = os.path.join(self.docs, 'report.txt')
        # 构造真实残留（应被隔离）
        self._write('report.docx.locked', b'LOCKED')
        r = m.trigger_rollback('manual_confirmed')
        quarantined = [os.path.basename(p) for p in qm.calls]
        self.assertNotIn('report.txt', quarantined, '同 stem 误伤规则必须已移除')
        self.assertTrue(os.path.isfile(txt), 'report.txt 不得被移动')
        self.assertIn('report.docx.locked', quarantined, '真实改名残留仍应被隔离')

    def test_protected_app_files_never_quarantined(self):
        """QQ/VMware 目录下的 .locked/.enc 文件绝不被隔离移动。"""
        qm = _FakeQM(do_move=True)
        m = self._mgr(qm)
        self._write('a.txt', b'A')
        m.snapshot_now('startup', replace=True)
        qq_dir = os.path.join(self.docs, 'Tencent Files', '123')
        os.makedirs(qq_dir, exist_ok=True)
        qq_file = os.path.join(qq_dir, 'Msg.db.locked')
        with open(qq_file, 'wb') as f:
            f.write(b'QQDATA')
        vm_dir = os.path.join(self.docs, 'VMware')
        os.makedirs(vm_dir, exist_ok=True)
        vm_file = os.path.join(vm_dir, 'vmware.log.enc')
        with open(vm_file, 'wb') as f:
            f.write(b'VMDATA')
        m.trigger_rollback('manual_confirmed')
        self.assertFalse(qm.calls, f'第三方软件目录文件不得被隔离: {qm.calls}')
        self.assertTrue(os.path.isfile(qq_file))
        self.assertTrue(os.path.isfile(vm_file))


class TestRestoreBoundary(_RollbackBase):

    def test_never_restore_path_not_snapshotted(self):
        """回滚绝不写回未快照过的路径。"""
        m = self._mgr()
        a = self._write('a.txt', b'ORIG')
        m.snapshot_now('startup', replace=True)
        # 快照后才出现的文件（未入清单）
        b = self._write('b_new.txt', b'USER-NEW-DATA')
        with open(a, 'wb') as f:
            f.write(b'ENCRYPTED')
        m.trigger_rollback('manual_confirmed')
        with open(b, 'rb') as f:
            self.assertEqual(f.read(), b'USER-NEW-DATA', '未快照文件不得被改动')

    def test_never_restore_into_protected_app_path(self):
        """即使清单里有 QQ 数据目录条目，也不得覆盖（防 QQ 文件受损）。"""
        m = self._mgr()
        qq_dir = os.path.join(self.docs, 'Tencent Files', '123')
        os.makedirs(qq_dir, exist_ok=True)
        qq = os.path.join(qq_dir, 'Msg.db')
        with open(qq, 'wb') as f:
            f.write(b'OLD-SNAPSHOT-DATA')
        m.snapshot_now('startup', replace=True)
        with open(qq, 'wb') as f:
            f.write(b'CURRENT-USER-DATA')       # 用户/QQ 之后正常修改
        r = m.trigger_rollback('manual_confirmed')
        with open(qq, 'rb') as f:
            self.assertEqual(f.read(), b'CURRENT-USER-DATA',
                             '第三方软件数据目录绝不被旧快照覆盖')
        self.assertTrue(any('跳过写回' in e.get('action', '')
                            for e in m.get_audit_log()))

    def test_restore_audited(self):
        m = self._mgr()
        a = self._write('a.txt', b'ORIG')
        m.snapshot_now('startup', replace=True)
        with open(a, 'wb') as f:
            f.write(b'ENCRYPTED')
        r = m.trigger_rollback('manual_confirmed')
        self.assertGreaterEqual(r['restored'], 1)
        actions = [e.get('action') for e in m.get_audit_log()]
        self.assertIn('写回恢复', actions, '写回必须有审计日志')


class TestSelfProtectionBaselineScope(unittest.TestCase):

    def test_baseline_only_own_files(self):
        s = sp.SelfProtection()
        s._init_critical_files()
        root = os.path.normcase(os.path.abspath(s._project_root))
        for f in s._critical_files:
            self.assertTrue(
                os.path.normcase(os.path.abspath(f)).startswith(root),
                f'关键文件基线含项目外文件（越界风险）: {f}')
        # 不得包含任何第三方软件目录文件名
        for f in s._critical_files:
            self.assertFalse(_is_protected_app_path(f),
                             f'基线不得包含第三方软件数据: {f}')


if __name__ == '__main__':
    unittest.main()