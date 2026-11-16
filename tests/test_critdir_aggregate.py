# -*- coding: utf-8 -*-
"""
TDD 测试: 关键目录保护签名驱动 churn 豁免 (A2)

- 驱动包目录(DriverStore\\FileRepository / System32\\drivers) new_dir 豁免
- 关键目录保护 check() 的 new_dir 分支调用 _is_driver_package_dir 过滤
- 仅目录豁免；底层 .sys/.inf 仍在 _is_trusted_signed_driver_file 签名校验链
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


class TestCritDirDriverExemptSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        mp_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               'engine', 'mbr_protector.py')
        cls.src = _read(mp_path)

    def test_new_dir_branch_uses_driver_package_exemption(self):
        """new_dir 分支含 _is_driver_package_dir 豁免"""
        # 在新增目录遍历块中应出现对本方法的调用
        self.assertIn('_is_driver_package_dir', self.src)
        # 锚定新增目录循环内的豁免调用
        block = re.search(r'for added in sorted\(cur_dirs - old_dirs\):(.*?)\n\s+added_watch',
                          self.src, re.DOTALL)
        self.assertIsNotNone(block, '未找到新增目录遍历块')
        self.assertIn('_is_driver_package_dir', block.group(1))

    def test_driver_package_method_defined(self):
        """存在 _is_driver_package_dir 方法"""
        m = re.search(r'def _is_driver_package_dir\(self, path: str\)', self.src)
        self.assertIsNotNone(m)


class TestCritDirDriverExemptRuntime(unittest.TestCase):
    @classmethod
    def _snap(cls):
        from engine.mbr_protector import _CriticalDirSnapshot
        return _CriticalDirSnapshot.__new__(_CriticalDirSnapshot)

    def test_driver_package_dir_matches(self):
        """DriverStore\\FileRepository 下的包目录命中豁免"""
        mp = self._snap()
        self.assertTrue(mp._is_driver_package_dir(
            r'C:\Windows\System32\DriverStore\FileRepository\amdacpbt.inf_amd64_e2f2a5b86bff1838'))
        self.assertTrue(mp._is_driver_package_dir(
            r'C:\Windows\System32\drivers\NVIDIA'))

    def test_normal_dir_not_exempt(self):
        """普通目录不命中(仍走 new_dir 上报)"""
        mp = self._snap()
        self.assertFalse(mp._is_driver_package_dir(
            r'C:\Windows\System32\Tasks\ASUS'))


if __name__ == '__main__':
    unittest.main(verbosity=2)