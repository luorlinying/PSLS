# -*- coding: utf-8 -*-
"""
MBR / 引导扇区保护 TDD 测试

覆盖:
  1. MBR 数据校验 (0x55AA 签名识别)
  2. MBRProtector 备份/校验/恢复逻辑 (mock 设备读写)
  3. 篡改检测与去重告警
  4. trust_change 信任当前状态
  5. 持久化: 备份写入 JSON 并可重载
"""
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.mbr_protector import MBRProtector, _sha256

# 制造一个合法的 MBR 扇区: 446 字节引导代码 + 64 字节分区表 + 0x55AA 签名 = 512
def _make_mbr_file(marker: bytes = b'\x00' * 446, part: bytes = b'\x00' * 64) -> bytes:
    sector = marker + part
    assert len(sector) == 446 + 64
    return sector + b'\x55\xaa'


class FakeDevice:
    """模拟物理设备: 内存中的扇区内容, 可读可写。"""
    def __init__(self, initial: bytes):
        self.sector = bytearray(initial)

    def read(self):
        return bytes(self.sector)

    def write(self, data: bytes):
        self.sector = bytearray(data)


class TestMbrProtectorDetect(unittest.TestCase):
    """验证 MBRProtector 的篡改检测与告警逻辑 (纯逻辑, 不打真实设备)。"""

    def setUp(self):
        self.device_file = os.path.join(tempfile.gettempdir(),
                                        'psls_mbr_test_backup.json')
        # 备份路径隔离, 避免污染真实备份
        self._old_backup_file = None
        import engine.mbr_protector as mp
        self._old_backup_file = mp._BACKUP_FILE
        mp._BACKUP_FILE = self.device_file

    def tearDown(self):
        import engine.mbr_protector as mp
        mp._BACKUP_FILE = self._old_backup_file
        if os.path.exists(self.device_file):
            os.remove(self.device_file)

    def test_mbr_signature_validation(self):
        """合法 MBR 必须含 0x55AA 签名。"""
        sector = _make_mbr_file()
        self.assertEqual(sector[-2:], b'\x55\xaa')
        self.assertEqual(_sha256(sector), _sha256(sector))

    def test_backup_then_detect_modification(self):
        """备份 MBR 后, 修改扇区应被检测为篡改。"""
        mp = MBRProtector()
        sector = _make_mbr_file()
        # 手工塞入备份 (绕过真实磁盘读取)
        mp._backups['\\\\.\\PhysicalDrive0'] = {
            'data': sector,
            'hash': _sha256(sector),
            'label': 'MBR (\\\\.\\PhysicalDrive0)',
            'type': 'mbr',
        }
        mp._has_backup = True

        modified = _make_mbr_file(marker=b'\xde\xad\xbe\xef' * 111 + b'\xde\xad')  # 446 字节
        # 模拟读扇区: patch _read_sector
        import engine.mbr_protector as mp_mod
        original = mp_mod._read_sector
        mp_mod._read_sector = lambda path, count=1: modified
        try:
            tampered = mp._check_all()
            self.assertEqual(len(tampered), 1)
            self.assertEqual(tampered[0]['type'], 'mbr')
        finally:
            mp_mod._read_sector = original

    def test_restore_writes_backup(self):
        """restore 应把备份写回设备。"""
        mp = MBRProtector()
        sector = _make_mbr_file()
        mp._backups['\\\\.\\PhysicalDrive1'] = {
            'data': sector,
            'hash': _sha256(sector),
            'label': 'MBR (\\\\.\\PhysicalDrive1)',
            'type': 'mbr',
        }
        mp._has_backup = True

        fake = FakeDevice(_make_mbr_file(marker=b'\xaa\xaa\xaa\xaa' * 111 + b'\xaa\xaa'))  # 446 字节
        import engine.mbr_protector as mp_mod
        saved_read = mp_mod._read_sector
        saved_write = mp_mod._write_sector
        mp_mod._read_sector = lambda path, count=1: fake.read()
        mp_mod._write_sector = lambda path, data: fake.write(data) or True
        try:
            ok = mp.restore('\\\\.\\PhysicalDrive1')
            self.assertTrue(ok)
            self.assertEqual(fake.read(), sector)
            # 恢复后 hash 已刷新, 重新校验不再报警
            self.assertEqual(mp._check_all(), [])
        finally:
            mp_mod._read_sector = saved_read
            mp_mod._write_sector = saved_write

    def test_alert_dedup_within_window(self):
        """同一设备 30 秒内的重复篡改只处置(告警/回滚)一次。"""
        alerts = []
        mp = MBRProtector(on_threat=lambda t: alerts.append(t))
        mp._backups['\\\\.\\PhysicalDrive2'] = {
            'data': _make_mbr_file(),
            'hash': _sha256(_make_mbr_file()),
            'label': 'MBR2',
            'type': 'mbr',
        }
        mp._has_backup = True
        # 模拟每次校验都返回差异化扇区, 且写入一律失败(无权限)
        import engine.mbr_protector as mp_mod
        saved_read = mp_mod._read_sector
        saved_write = mp_mod._write_sector
        counter = [0]
        def fake_read(path, count=1):
            counter[0] += 1
            return _make_mbr_file(marker=bytes([counter[0]]) * 446)
        mp_mod._read_sector = fake_read
        mp_mod._write_sector = lambda path, data: False
        try:
            t1 = mp._check_all()
            mp._handle_tamper(t1)
            t2 = mp._check_all()
            mp._handle_tamper(t2)
            self.assertEqual(len(alerts), 1)
        finally:
            mp_mod._read_sector = saved_read
            mp_mod._write_sector = saved_write

    def test_auto_restore_rolls_back_and_notifies(self):
        """检测到篡改后自动回滚(无需用户同意), 通知照常发送且标记 auto_restored。"""
        alerts = []
        mp = MBRProtector(on_threat=lambda t: alerts.append(t))  # auto_restore=True
        sector = _make_mbr_file()
        mp._backups['\\\\.\\PhysicalDrive3'] = {
            'data': sector,
            'hash': _sha256(sector),
            'label': 'MBR3',
            'type': 'mbr',
        }
        mp._has_backup = True

        fake = FakeDevice(_make_mbr_file(marker=b'\x11\x22\x33\x44' * 111 + b'\x11\x22'))
        import engine.mbr_protector as mp_mod
        saved_read = mp_mod._read_sector
        saved_write = mp_mod._write_sector
        mp_mod._read_sector = lambda path, count=1: fake.read()
        mp_mod._write_sector = lambda path, data: fake.write(data) or True
        try:
            t = mp._check_all()
            self.assertEqual(len(t), 1)
            mp._handle_tamper(t)
            # 设备已被恢复为备份内容
            self.assertEqual(fake.read(), sector)
            # 通知仍发出, 且标记自动回滚成功
            self.assertEqual(len(alerts), 1)
            self.assertTrue(alerts[0]['auto_restored'])
            self.assertIn('已自动回滚', alerts[0]['message'])
            self.assertEqual(mp.get_stats()['auto_restored'], 1)
            # 恢复后 hash 已刷新, 立即重校验不再报警
            self.assertEqual(mp._check_all(), [])
        finally:
            mp_mod._read_sector = saved_read
            mp_mod._write_sector = saved_write

    def test_auto_restore_failure_still_notifies(self):
        """自动回滚失败(无权限)时仍需通知且标记 auto_restored=False。"""
        alerts = []
        mp = MBRProtector(on_threat=lambda t: alerts.append(t))
        mp._backups['\\\\.\\PhysicalDrive4'] = {
            'data': _make_mbr_file(),
            'hash': _sha256(_make_mbr_file()),
            'label': 'MBR4',
            'type': 'mbr',
        }
        mp._has_backup = True
        import engine.mbr_protector as mp_mod
        saved_read = mp_mod._read_sector
        saved_write = mp_mod._write_sector
        mp_mod._read_sector = lambda path, count=1: _make_mbr_file(marker=b'\x55\x66' * 223)
        mp_mod._write_sector = lambda path, data: False  # 写入失败
        try:
            t = mp._check_all()
            mp._handle_tamper(t)
            self.assertEqual(len(alerts), 1)
            self.assertFalse(alerts[0]['auto_restored'])
            self.assertIn('回滚失败', alerts[0]['message'])
        finally:
            mp_mod._read_sector = saved_read
            mp_mod._write_sector = saved_write

    def test_auto_restore_disabled_detects_only(self):
        """关闭 auto_restore 时仅告警, 不写回。"""
        alerts = []
        mp = MBRProtector(on_threat=lambda t: alerts.append(t), auto_restore=False)
        mp._backups['\\\\.\\PhysicalDrive5'] = {
            'data': _make_mbr_file(),
            'hash': _sha256(_make_mbr_file()),
            'label': 'MBR5',
            'type': 'mbr',
        }
        mp._has_backup = True
        wrote = []
        import engine.mbr_protector as mp_mod
        saved_read = mp_mod._read_sector
        saved_write = mp_mod._write_sector
        mp_mod._read_sector = lambda path, count=1: _make_mbr_file(marker=b'\x77\x88' * 223)
        mp_mod._write_sector = lambda path, data: wrote.append(data) or True
        try:
            t = mp._check_all()
            mp._handle_tamper(t)
            self.assertEqual(len(alerts), 1)
            self.assertFalse(alerts[0]['auto_restored'])
            self.assertEqual(wrote, [])  # 未写入
        finally:
            mp_mod._read_sector = saved_read
            mp_mod._write_sector = saved_write

    def test_trust_change_rebuilds_backup(self):
        """trust_change 应以当前状态刷新备份, 不再告警。"""
        mp = MBRProtector()
        create_calls = []
        mp.create_backup = lambda: create_calls.append(1) or True
        mp.trust_change()
        self.assertEqual(len(create_calls), 1)


class TestMbrProtectorConfig(unittest.TestCase):
    """验证配置与持久化逻辑。"""

    def test_backup_file_roundtrip(self):
        """备份 JSON 可写入并可重载。"""
        tmp = tempfile.gettempdir()
        store_path = os.path.join(tmp, 'psls_mbr_roundtrip.json')
        if os.path.exists(store_path):
            os.remove(store_path)

        import engine.mbr_protector as mp_mod
        old_const = mp_mod._BACKUP_FILE
        mp_mod._BACKUP_FILE = store_path

        # 实例1: 写入
        mp1 = MBRProtector()
        sector = _make_mbr_file()
        mp1._backups['\\\\.\\PhysicalDrive0'] = {
            'data': sector,
            'hash': _sha256(sector),
            'label': 'MBR (\\\\.\\PhysicalDrive0)',
            'type': 'mbr',
        }
        mp1._has_backup = True
        mp1._save_backup_to_disk()
        self.assertTrue(os.path.exists(store_path))

        # 实例2: 重载
        mp2 = MBRProtector()
        loaded = mp2._load_backup_from_disk()
        self.assertTrue(loaded)
        self.assertEqual(mp2._backups['\\\\.\\PhysicalDrive0']['hash'],
                         _sha256(sector))

        mp_mod._BACKUP_FILE = old_const
        if os.path.exists(store_path):
            os.remove(store_path)

    def test_interval_clamped(self):
        """interval 最小值为 1 秒。"""
        mp = MBRProtector(interval=0.1)
        self.assertGreaterEqual(mp._interval, 1.0)


class TestDriverMbrRearm(unittest.TestCase):
    """内核 MBR 写拦截掉线后必须能自动重挂。

    修复"MBR 拦截成功一次、之后失效"：回滚写盘时的 set_mbr_protect(False)
    → 写回 → set_mbr_protect(True) 若重挂失败，_driver_mon_ok 永久停在
    False，之前没有任何地方重试，内核写拦截就此关闭。
    """

    class _Bridge:
        def __init__(self, ret=True):
            self.ret = ret
            self.calls = []

        def set_mbr_protect(self, on):
            self.calls.append(bool(on))
            return self.ret

    def _protector(self, ret=True):
        mp = MBRProtector()
        br = self._Bridge(ret)
        mp._use_driver_mon = True
        mp._driver_mon_ok = False
        mp._driver_rearm_ts = 0.0
        mp._get_driver_bridge = lambda: br
        mp._push_boot_protect = lambda b: None
        return mp, br

    def test_rearm_succeeds(self):
        mp, br = self._protector(ret=True)
        mp._try_rearm_driver_mbr()
        self.assertTrue(mp._driver_mon_ok)
        self.assertEqual(br.calls, [True])

    def test_no_rearm_when_already_ok(self):
        mp, br = self._protector(ret=True)
        mp._driver_mon_ok = True
        mp._try_rearm_driver_mbr()
        self.assertEqual(br.calls, [])

    def test_rearm_throttled_after_failure(self):
        mp, br = self._protector(ret=False)
        mp._try_rearm_driver_mbr()
        self.assertFalse(mp._driver_mon_ok)
        first = len(br.calls)
        self.assertEqual(first, 1)
        # 5s 节流窗口内不得再重试（避免 IOCTL 风暴）
        mp._try_rearm_driver_mbr()
        self.assertEqual(len(br.calls), first)


if __name__ == '__main__':
    unittest.main()