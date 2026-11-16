# -*- coding: utf-8 -*-
"""回归：回滚仓库/影子根必须豁免（现象 3：文件保护把"备份"识别为恶意）。

覆盖：
  1. rr.is_psls_repo_path：仓库 objects/shadow 内为 True；...\rollback2 兄弟目录与
     普通目录为 False（尾分隔符前缀比较，避免前缀误伤）；
  2. FileProtection._is_self_path：仓库内 True、仓库外 False；
     且 _on_file_event 对仓库内文件不产生任何修改信号，仓库外同内容文件仍正常计入；
  3. ScanEngine 的 _is_psls_own_path 对仓库内为 True（构造失败则跳过）；
  4. 实时防护/扫描/桥接源码契约（已接入豁免判据）。
"""
import os
import sys
import shutil
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.ransomware_rollback as rr
from engine.file_protection import FileProtection


class TestRepoExempt(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_ex_')
        self.repo = os.path.join(self.tmp, 'rollback')
        os.makedirs(os.path.join(self.repo, 'objects', 'ab'), exist_ok=True)
        os.makedirs(os.path.join(self.repo, 'shadow', '1'), exist_ok=True)
        self.outside = os.path.join(self.tmp, 'docs')
        os.makedirs(self.outside, exist_ok=True)
        self._old_root = rr._REPO_ROOT
        self._old_env = os.environ.get('PSLS_ROLLBACK_REPO')
        rr._REPO_ROOT = self.repo
        os.environ['PSLS_ROLLBACK_REPO'] = self.repo

    def tearDown(self):
        rr._REPO_ROOT = self._old_root
        if self._old_env is None:
            os.environ.pop('PSLS_ROLLBACK_REPO', None)
        else:
            os.environ['PSLS_ROLLBACK_REPO'] = self._old_env
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mk(self, path, data=b'PAYLOAD'):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(data)
        return path

    # ---- 1. rr.is_psls_repo_path ----

    def test_is_psls_repo_path_truth_table(self):
        obj = os.path.join(self.repo, 'objects', 'ab', 'cd' * 32)
        shadow = os.path.join(self.repo, 'shadow', '1', 'deadbeef')
        self.assertTrue(rr.is_psls_repo_path(obj))
        self.assertTrue(rr.is_psls_repo_path(shadow))
        self.assertTrue(rr.is_psls_repo_path(self.repo))          # 仓库根本身
        # 兄弟目录 / 普通文件不得误判（尾分隔符前缀比较）
        self.assertFalse(rr.is_psls_repo_path(self.repo + '2'))
        self.assertFalse(rr.is_psls_repo_path(
            os.path.join(self.repo + '2', 'objects', 'x')))
        self.assertFalse(rr.is_psls_repo_path(
            os.path.join(self.outside, 'a.txt')))

    # ---- 2. FileProtection ----

    def test_file_protection_repo_exempt_but_outside_triggers(self):
        fp = FileProtection()
        repo_obj = self._mk(os.path.join(self.repo, 'objects', 'ab', 'ee' * 32))
        outside_file = self._mk(os.path.join(self.outside, 'note.txt'))

        # 判据
        self.assertTrue(fp._is_self_path(repo_obj))
        self.assertFalse(fp._is_self_path(outside_file))

        # 仓库内事件：不产生任何修改信号
        fp._on_file_event(repo_obj, 'modified')
        self.assertEqual(len(fp._recent_modifications), 0,
                         '仓库内文件不得计入批量修改/勒索检测')
        self.assertEqual(len(fp._recent_size_changes), 0)
        self.assertEqual(len(fp._recent_renames), 0)

        # 仓库外同内容文件：仍正常触发（计入数量维度）
        fp._on_file_event(outside_file, 'modified')
        self.assertEqual(len(fp._recent_modifications), 1,
                         '仓库外文件必须仍正常触发检测')

    def test_shadow_root_exempt(self):
        fp = FileProtection()
        shadow = self._mk(os.path.join(self.repo, 'shadow', '1', 'aa' * 16))
        self.assertTrue(fp._is_self_path(shadow))

    # ---- 3. ScanEngine ----

    def test_scan_engine_exempts_repo(self):
        try:
            from engine.scan_engine import ScanEngine
            se = ScanEngine()
        except Exception as e:
            self.skipTest(f'ScanEngine 构造不可用（环境限制）: {e}')
        repo_obj = os.path.join(self.repo, 'objects', 'ab', 'ff' * 32)
        self.assertTrue(se._is_psls_own_path(repo_obj))
        self.assertFalse(se._is_psls_own_path(
            os.path.join(self.outside, 'x.exe')))

    # ---- 4. 源码契约：实时防护/扫描/桥接均已接入 ----

    def test_wiring_source_contract(self):
        with open(os.path.join(ROOT, 'engine', 'realtime_monitor.py'),
                  'r', encoding='utf-8') as f:
            rt = f.read()
        self.assertIn('is_psls_own_path', rt)
        self.assertIn('is_psls_own_path(p)', rt)
        self.assertIn('self.is_psls_own_path(file_path)', rt)

        with open(os.path.join(ROOT, 'engine', 'scan_engine.py'),
                  'r', encoding='utf-8') as f:
            se = f.read()
        self.assertIn('_is_psls_own_path', se)
        self.assertIn('is_psls_repo_path', se)

        with open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                  'r', encoding='utf-8') as f:
            br = f.read()
        self.assertIn('is_psls_repo_path', br)


if __name__ == '__main__':
    unittest.main()