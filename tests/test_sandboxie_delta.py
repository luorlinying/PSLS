# -*- coding: utf-8 -*-
"""sandboxie_delta 纯函数单测（免装 Sandboxie）。

验证路径还原、可疑文件识别、批量写入阈值、注册表枚举的健壮性。
"""

import os
import sys
import shutil
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine import sandboxie_delta as sd  # noqa: E402


class TestPathMapping(unittest.TestCase):

    def test_drive_mapping(self):
        r = sd._map_sandbox_path(r'C:\box', r'drive\C\Windows\System32\evil.exe')
        self.assertEqual(r.lower().rstrip('\\'), r'c:\windows\system32\evil.exe')

    def test_user_current_mapping(self):
        r = sd._map_sandbox_path(r'C:\box', r'user\current\Desktop\a.txt')
        self.assertTrue(r.lower().endswith(r'desktop\a.txt'))
        self.assertTrue(r.lower().startswith(os.path.expanduser('~').lower()))

    def test_unknown_branch_returns_raw(self):
        r = sd._map_sandbox_path(r'C:\box', r'share\\server\\s\\x')
        self.assertIsNotNone(r)


class TestCollectFiles(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='psls_box_')

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _mk(self, rel: str, content: bytes = b'x'):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as f:
            f.write(content)
        return p

    def test_empty_box_returns_no_records(self):
        self.assertEqual(sd.collect_files(self.root), [])

    def test_exec_and_persist_flagged(self):
        self._mk(r'drive\C\tmp\evil.exe')
        self._mk(r'user\current\AppData\Roaming\Microsoft\Windows'
                 r'\Start Menu\Programs\Startup\run.exe')
        self._mk(r'drive\C\tmp\readme.txt')
        recs = sd.collect_files(self.root)
        descs = ' | '.join(r['description'] for r in recs)
        self.assertIn('落地可执行/脚本文件', descs)
        self.assertIn('在自启动/持久化目录写入文件', descs)
        # 汇总记录存在
        self.assertTrue(any('文件写入/改动' in r['description'] for r in recs))

    def test_ransom_ext_critical(self):
        self._mk(r'drive\C\docs\a.locked')
        recs = sd.collect_files(self.root)
        self.assertTrue(any(r['severity'] == 'critical' and '勒索' in r['description']
                            for r in recs))

    def test_delete_marker(self):
        self._mk(r'drive\C\docs\gone.txt', b'\x00')
        recs = sd.collect_files(self.root)
        self.assertTrue(any('删除文件' in r['description'] for r in recs))

    def test_reghive_skipped(self):
        self._mk(r'RegHive')
        recs = sd.collect_files(self.root)
        # RegHive 本身不应计入文件总数汇总
        self.assertFalse(any('RegHive' in r.get('detail', '') for r in recs))

    def test_internal_files_not_counted(self):
        """盒内自带管理文件（RegHive 事务日志/desktop.ini）不得计入增量。"""
        for rel in (r'RegHive', r'RegHive.LOG1', r'RegHive.LOG2',
                    r'RegHive{4acd}.TM.blf',
                    r'RegHive{4acd}.TMContainer00000001.regtrans-ms',
                    r'user\current\Desktop\desktop.ini',
                    r'DONT-USE.TXT'):
            self._mk(rel)
        # 一份真实样本写入
        self._mk(r'drive\C\tmp\payload.bin')
        recs = sd.collect_files(self.root)
        summary = [r for r in recs if '文件写入/改动' in r['description']]
        self.assertEqual(len(summary), 1)
        # 只应统计到 1 个真实文件
        self.assertIn('1 项', summary[0]['description'])

    def test_is_internal_file(self):
        self.assertTrue(sd._is_internal_file(r'RegHive'))
        self.assertTrue(sd._is_internal_file(r'x\RegHive{guid}.TM.blf'))
        self.assertTrue(sd._is_internal_file(r'desktop.ini'))
        self.assertFalse(sd._is_internal_file(r'drive\C\tmp\a.exe'))


class TestRegistryClassification(unittest.TestCase):
    """注册表白名单打分：持久化键计分，沙盒/系统噪声不计分。"""

    def test_persist_keys_matched(self):
        for k in (r'software\microsoft\windows\currentversion\run',
                  r'software\microsoft\windows\currentversion\runonce',
                  r'software\microsoft\windows nt\currentversion\winlogon',
                  r'system\currentcontrolset\services\evil',
                  r'software\microsoft\windows nt\currentversion\image file execution options\x.exe'):
            self.assertTrue(sd._reg_is_persist(k), k)

    def test_noise_not_matched(self):
        for k in (r'software\classes\undecided\shell\open\command',
                  r'software\classes\unknown\shell\open\command',
                  r'system\currentcontrolset\services\winsock2\parameters',
                  r'system\software\microsoft\tip\aggregateresults',
                  r'software\policies\microsoft\windows\installer',
                  r'software\microsoft\ole'):
            self.assertFalse(sd._reg_is_persist(k), k)

    def test_benign_key_not_matched(self):
        self.assertFalse(sd._reg_is_persist(r'software\psls_sbie_test'))


class TestOfflineHiveRobust(unittest.TestCase):
    """离线 RegHive 加载的健壮性（免管理员即可校验失败路径）。"""

    def test_load_missing_file_returns_none(self):
        self.assertIsNone(sd._offline_load_reg_hive(r'C:\__no_such_root__'))
        self.assertIsNone(sd._offline_load_reg_hive(''))

    def test_unload_none_is_noop(self):
        sd._offline_unload_reg_hive(None)   # 不应抛异常
        sd._offline_unload_reg_hive('__no_such_mount__')

    def test_collect_registry_with_file_root_no_crash(self):
        recs = sd.collect_registry('__no_such_box__', r'C:\__no_such_root__')
        self.assertEqual(recs, [])


class TestCollectRegistryRobust(unittest.TestCase):

    def test_absent_hive_no_crash(self):
        # 不存在的盒名 → 应返回空列表且不抛异常
        self.assertEqual(sd.collect_registry('__no_such_box__'), [])

    def test_collect_all_never_raises(self):
        recs = sd.collect_all(r'C:\__no_such_root__', '__no_such_box__')
        self.assertIsInstance(recs, list)


if __name__ == '__main__':
    unittest.main()