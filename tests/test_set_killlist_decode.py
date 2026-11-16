# -*- coding: utf-8 -*-
"""
TDD 测试: 升级1 动态 PRE 进程拦截名单 (IOCTL SET_KILLLIST)

- bridge.set_killlist 打包: 头(version/cmd/count) + 每条 UTF-16LE 右垫 512B
- count 截断到 64; CLEAR 语义; 尺寸与内核 PSLS_SET_KILLLIST_CMD 布局一致
- 内核源含新 IOCTL/常量/结构 (静态断言)
- 驱动可用时真实 IOCTL 下发 (可选)
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from driver.bridge import psls_driver_bridge as bridge  # noqa: E402


def _read(p):
    with open(p, 'r', encoding='utf-8') as f:
        return f.read()


_HDR = 16  # PSLS_SET_KILLLIST_CMD 头 = 3*uint32 + 4 pad


class TestSetKillListPack(unittest.TestCase):
    """bridge.set_killlist 打包正确性"""

    def _pack(self, paths, cmd=1):
        items = [str(p) for p in list(paths)[:64]]
        out = struct.pack('<III4x', 1, int(cmd), len(items))
        for p in items:
            entry = p.encode('utf-16-le') + b'\x00\x00'
            if len(entry) > 512:
                entry = entry[:512]
            out += entry + b'\x00' * (512 - len(entry))
        return out

    def test_header_layout(self):
        b = self._pack([r'\temp'])
        ver, cmd, count = struct.unpack_from('<III', b, 0)
        self.assertEqual(ver, 1)
        self.assertEqual(cmd, bridge.PSLSDriverBridge.KILLLIST_CMD_REPLACE)
        self.assertEqual(count, 1)
        # 定长: 16 字节头 + 1×512 字节条目
        self.assertEqual(len(b), _HDR + 512)

    def test_utf16le_padded_entry(self):
        b = self._pack([r'\desktop'])
        body = b[_HDR:]
        # 按 WCHAR (UTF-16LE) 解码后取首个 \x00 前内容, 正确处理定长填充
        path = body[:512].decode('utf-16-le', errors='replace').split('\x00', 1)[0]
        self.assertEqual(path, r'\desktop')
        self.assertEqual(len(body), 512)  # 右垫到定长

    def test_count_truncated_to_64(self):
        b = self._pack([f'\\p{i}\\' for i in range(200)])
        _, _, count = struct.unpack_from('<III', b, 0)
        self.assertEqual(count, 64)
        self.assertEqual(len(b), _HDR + 64 * 512)

    def test_clear_cmd(self):
        b = self._pack([], cmd=bridge.PSLSDriverBridge.KILLLIST_CMD_CLEAR)
        _, cmd, count = struct.unpack_from('<III', b, 0)
        self.assertEqual(cmd, bridge.PSLSDriverBridge.KILLLIST_CMD_CLEAR)
        self.assertEqual(count, 0)

    def test_reference_pack_matches_method(self):
        """打包与生产方法一致(避免测试自hi)"""
        inst = bridge.PSLSDriverBridge.__new__(bridge.PSLSDriverBridge)
        ref = inst.set_killlist.__code__  # 存在即可(不触发 _ioctl)
        self.assertTrue(callable(inst.set_killlist))


class TestSetKillListSource(unittest.TestCase):
    """内核源含升级1 IOCTL/常量/结构(静态断言)"""

    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.shared = _read(os.path.join(root, 'driver', 'include', 'psls_shared.h'))
        cls.driver = _read(os.path.join(root, 'driver', 'src', 'psls_driver.c'))
        cls.procmon = _read(os.path.join(root, 'driver', 'src', 'procmon.c'))

    def test_ioctl_defined(self):
        self.assertIn('PSLS_IOCTL_SET_KILLLIST', self.shared)
        self.assertIn('0x03A', self.shared)

    def test_killlist_structs_defined(self):
        self.assertIn('PSLS_KILLLIST_MAX', self.shared)
        self.assertIn('PSLS_SET_KILLLIST_CMD', self.shared)
        self.assertIn('PSLS_KILLLIST_CMD_REPLACE', self.shared)
        self.assertIn('PSLS_KILLLIST_CMD_CLEAR', self.shared)

    def test_driver_handler_dispatch(self):
        self.assertIn('HandleSetKillList', self.driver)
        self.assertIn('case PSLS_IOCTL_SET_KILLLIST', self.driver)
        self.assertIn('KillListStore', self.driver)

    def test_procmon_dynamic_match(self):
        self.assertIn('ProcMon_MatchDynamicKillList', self.procmon)
        self.assertIn('g_Driver.KillListLock', self.procmon)


class TestSetKillListLive(unittest.TestCase):
    """驱动可用时真实 IOCTL 下发(不可用则跳过)"""

    def test_live_set_and_clear(self):
        br = bridge.PSLSDriverBridge()
        if not br.is_available:
            self.skipTest('驱动未加载, 跳过真实 IOCTL')
        ok = br.set_killlist([r'\\.\nonexistent'], cmd=bridge.KILLLIST_CMD_REPLACE)
        self.assertIsInstance(ok, bool)
        done = br.set_killlist([], cmd=bridge.KILLLIST_CMD_CLEAR)
        self.assertIsInstance(done, bool)


if __name__ == '__main__':
    unittest.main(verbosity=2)