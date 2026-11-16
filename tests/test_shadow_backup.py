# -*- coding: utf-8 -*-
"""
写前影子备份（阶段二）单元测试

覆盖（对应方案"验证"要求，不依赖真实驱动）：
  1. 影子事件 → manifest 记录 source='driver_shadow'（影子文件移动进对象库）
  2. 回滚优先用写前原像（driver_shadow）而非阶段一快照
  3. status != 0（miss/fail）只记 warning，不入仓，并在回滚记录中列为"无写前原像"
  4. 后续周期快照不得覆盖/清除 driver_shadow 原像（优先级高于快照）
  5. 桥接层新 IOCTL 打包（set_shadow_config）与新事件解析
  6. get_shadow_stats 汇总（含驱动侧计数）

全部用例把 engine.ransomware_rollback._REPO_ROOT monkeypatch 到 tempfile，
用 tempfile 做影子目录，绝不依赖真实驱动。
"""
import os
import sys
import time
import shutil
import struct
import hashlib
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback
from driver.bridge import psls_driver_bridge as pb


class TestShadowBackup(unittest.TestCase):

    def setUp(self):
        self._old_root = rr._REPO_ROOT
        self.tmp = tempfile.mkdtemp(prefix='psls_shadow_')
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        self.protected = os.path.join(self.tmp, 'docs')
        os.makedirs(self.protected, exist_ok=True)

    def tearDown(self):
        rr._REPO_ROOT = self._old_root
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mgr(self, **kwargs):
        kwargs.setdefault('protected_dirs', [self.protected])
        return RansomwareRollback(**kwargs)

    def _write(self, name: str, data: bytes) -> str:
        p = os.path.join(self.protected, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    def _make_shadow_file(self, gen: int, name: str, data: bytes) -> str:
        """在 <repo>/shadow/<gen>/ 下伪造一个驱动影子文件，返回其路径。"""
        d = rr._shadow_gen_dir(gen)
        os.makedirs(d, exist_ok=True)
        sp = os.path.join(d, name)
        with open(sp, 'wb') as f:
            f.write(data)
        return sp

    # ---- 1. 影子事件 → manifest + 对象库 ----

    def test_ingest_shadow_backup_records_manifest_and_object(self):
        m = self._mgr()
        m._generation = 5
        real = self._write('photo.jpg', b'ORIGINAL-PHOTO-BYTES')
        shadow = self._make_shadow_file(5, 'abc123', b'ORIGINAL-PHOTO-BYTES')

        ok = m.ingest_shadow_backup(real, shadow, len(b'ORIGINAL-PHOTO-BYTES'), 1234)
        self.assertTrue(ok)
        # 影子文件被移动进对象库（原位置消失，避免重复拷贝大文件）
        self.assertFalse(os.path.exists(shadow))
        sha = hashlib.sha256(b'ORIGINAL-PHOTO-BYTES').hexdigest()
        self.assertTrue(os.path.isfile(m._object_path(sha)))

        key = os.path.abspath(real).lower()
        with m._state_lock:
            meta = dict(m._manifest['entries'][key])
        self.assertEqual(meta['source'], 'driver_shadow')
        self.assertEqual(meta['hash'], sha)
        self.assertEqual(meta['pid'], 1234)
        self.assertEqual(m.get_stats()['shadow_entries'], 1)

    # ---- 2. 回滚优先使用写前原像 ----

    def test_rollback_prefers_driver_shadow_preimage(self):
        m = self._mgr()
        m._generation = 1
        real = self._write('doc.txt', b'PRE-IMAGE-CONTENT')
        # 阶段一快照先拍摄（此时内容=原像）
        m.snapshot_now('init')
        # 驱动写前原像入仓（同一路径，应覆盖快照条目）
        shadow = self._make_shadow_file(1, 'p1', b'PRE-IMAGE-CONTENT')
        m.ingest_shadow_backup(real, shadow, len(b'PRE-IMAGE-CONTENT'), 7)

        # 文件被加密污染
        self._write('doc.txt', b'ENCRYPTED-GARBAGE')
        res = m.trigger_rollback('unit-test')
        self.assertEqual(res['restored'], 1)
        with open(real, 'rb') as f:
            self.assertEqual(f.read(), b'PRE-IMAGE-CONTENT')
        rec = m.list_records()[0]
        self.assertEqual(rec['files'][0]['pre_image'], 'driver_shadow')

    # ---- 3. status!=0 只记 warning 不入仓 ----

    def test_shadow_failure_only_warns(self):
        m = self._mgr()
        m._generation = 2
        real = self._write('f.bin', b'X')
        # miss/IRQL 事件：不入仓
        ok = m.ingest_shadow_failure(real, status=2, reason=1, pid=9,
                                     status_name='miss', reason_name='irql')
        self.assertFalse(ok)
        key = os.path.abspath(real).lower()
        with m._state_lock:
            self.assertNotIn(key, m._manifest['entries'])
        self.assertEqual(m.get_stats()['shadow_no_preimage'], 1)

        # dedup 跳过不算"无原像"
        m.ingest_shadow_failure(real, status=1, reason=5, pid=9,
                                status_name='skip', reason_name='dedup')
        self.assertEqual(len(m._shadow_failures), 1)

        # 回滚记录中体现"该文件无写前原像"
        self._write('f.bin', b'ENCRYPTED')
        m.trigger_rollback('unit-test')
        rec = m.list_records()[0]
        self.assertIn(os.path.abspath(real), rec['shadow_no_preimage'])

    # ---- 4. 周期快照不得清除写前原像 ----

    def test_snapshot_does_not_override_shadow_preimage(self):
        m = self._mgr()
        m._generation = 3
        real = self._write('keep.txt', b'ORIGINAL')
        shadow = self._make_shadow_file(3, 'k1', b'ORIGINAL')
        m.ingest_shadow_backup(real, shadow, len(b'ORIGINAL'), 3)

        sha_orig = hashlib.sha256(b'ORIGINAL').hexdigest()
        # 内容被改（模拟加密后周期快照），replace=True 也不得顶掉/清掉原像
        time.sleep(0.02)
        self._write('keep.txt', b'ENCRYPTED-NEW')
        m.snapshot_now('periodic', replace=True)

        key = os.path.abspath(real).lower()
        with m._state_lock:
            meta = dict(m._manifest['entries'][key])
        self.assertEqual(meta['source'], 'driver_shadow')
        self.assertEqual(meta['hash'], sha_orig)
        self.assertTrue(os.path.isfile(m._object_path(sha_orig)))

    # ---- 5. 桥接层 IOCTL 打包 + 事件解析 ----

    def test_bridge_set_shadow_config_packaging(self):
        b = pb.PSLSDriverBridge()
        captured = {}

        def fake_ioctl(code, in_buf=b'', out_size=0):
            captured['code'] = code
            captured['buf'] = in_buf
            captured['out'] = out_size
            return b''

        b._ioctl = fake_ioctl
        ok = b.set_shadow_config(True, 7, r'C:\tmp\shadow',
                                 dirs=[r'C:\Users\x\Desktop'])
        self.assertTrue(ok)
        self.assertEqual(captured['code'], pb.IOCTL_SET_SHADOW_CONFIG)
        buf = captured['buf']
        # 固定部分 528B + dir_count(4) + 1 个目录项(520B)
        self.assertEqual(len(buf), pb.SHADOW_CONFIG_BASE_SIZE + 4 + 520)
        enable, gen = struct.unpack_from('<II', buf, 0)
        self.assertEqual(enable, 1)
        self.assertEqual(gen, 7)
        root = buf[8:8 + 520].decode('utf-16-le').split('\x00', 1)[0]
        self.assertIn('shadow', root.lower())
        dir_count = struct.unpack_from('<I', buf, pb.SHADOW_CONFIG_BASE_SIZE)[0]
        self.assertEqual(dir_count, 1)

    def test_bridge_decode_shadow_event(self):
        orig = r'\Device\HarddiskVolume3\Users\x\a.jpg'.encode('utf-16-le')
        shadow = r'\Device\HarddiskVolume3\repo\shadow\1\deadbeef'.encode('utf-16-le')
        payload = bytearray(1044)
        payload[0:len(orig)] = orig
        payload[512:512 + len(shadow)] = shadow
        struct.pack_into('<Q', payload, 1024, 4321)
        struct.pack_into('<III', payload, 1032, pb.SHADOW_STATUS_OK, 0, 42)
        ev = pb._decode_event(99, pb.EVENT_FILE_SHADOWED, 1, bytes(payload))
        self.assertIsInstance(ev, pb.ShadowBackupEvent)
        self.assertTrue(ev.orig_path.endswith('a.jpg'))
        self.assertEqual(ev.orig_size, 4321)
        self.assertEqual(ev.status_name, 'ok')
        self.assertEqual(ev.pid, 42)

    # ---- 6. get_shadow_stats 汇总（含驱动侧计数）----

    def test_get_shadow_stats_includes_driver_counts(self):
        m = self._mgr()

        class _FakeBridge:
            is_available = True

            def set_shadow_config(self, *a, **k):
                return True

            def query_shadow_stats(self):
                return {'backed_up': 11, 'skipped': 2, 'missed': 1,
                        'failed': 0, 'dedup_hits': 5, 'generation_id': 4}

        m.set_driver_bridge(_FakeBridge())
        m._generation = 4
        st = m.get_shadow_stats()
        self.assertEqual(st['generation_id'], 4)
        self.assertEqual(st['driver']['backed_up'], 11)
        self.assertEqual(st['driver']['dedup_hits'], 5)


if __name__ == '__main__':
    unittest.main()