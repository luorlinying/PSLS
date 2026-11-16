# -*- coding: utf-8 -*-
"""三项需求回归：隔离去重显示 / 世代跨重启不丢 / 签名库备份回退。

用户报（2026-10-07）：
  1 隔离区"去重显示"：同一对象只出现一条，但动作仍要执行、底层仍记录每次动作
  2 上一代勒索快照在启动后"丢失"
  3 签名库（~106MB）缺失/损坏时不可用 → 需要 PSLS 自身目录内的备份 + 自动回退
"""
import os
import sys
import json
import time
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import db.signature_db as sdb
import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback
from engine.quarantine_manager import QuarantineManager


class TestQuarantineDedupeDisplay(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_qm_')
        self.qdir = os.path.join(self.tmp, 'quarantine')
        os.makedirs(self.qdir, exist_ok=True)
        # 隔离测试必须与真实用户数据隔离：软隔离登记表默认在 %APPDATA%\PSLS
        import engine.quarantine_manager as qmod
        self._soft_patch = mock.patch.object(
            qmod, '_get_soft_registry_path',
            return_value=os.path.join(self.tmp, 'soft_quarantine.json'))
        self._soft_patch.start()

    def tearDown(self):
        try:
            self._soft_patch.stop()
        except Exception:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _qm(self):
        return QuarantineManager(quarantine_dir=self.qdir)

    def _mal(self, name, data=b'MALWARE-XYZ'):
        p = os.path.join(self.tmp, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    def test_same_file_twice_actions_run_list_single(self):
        """同一对象被隔离两次：动作执行 2 次、列表仅 1 条、条目可见次数/时间。

        场景即用户所述："回滚残留隔离时发现该文件已在隔离区"——同一路径上的同一
        内容再次出现（重新落盘/再次解压）；去重键=内容哈希+规范化原路径。
        """
        qm = self._qm()
        p = self._mal('evil.exe')
        r1 = qm.quarantine_file(p, reason='test', malware_name='T')
        self.assertTrue(r1 is True, f'首次应真正隔离，实际 {r1}')
        self.assertFalse(os.path.exists(p), '首次隔离后源文件应已处置')
        # 同一路径再次出现同内容文件（隔离后重新落盘的副本）
        with open(p, 'wb') as f:
            f.write(b'MALWARE-XYZ')
        r2 = qm.quarantine_file(p, reason='test', malware_name='T')
        self.assertEqual(r2, 'duplicate', '第二次命中去重（但仍已处置）')
        self.assertFalse(os.path.exists(p), '第二次也必须真正处置（删除同内容副本）')
        items = qm.get_quarantine_list()
        self.assertEqual(len(items), 1, f'列表必须只有 1 条，实际 {len(items)}')
        it = items[0]
        self.assertEqual(int(it.get('quarantine_count', 1)), 2, '应累计隔离次数')
        self.assertTrue(it.get('first_quarantined'))
        self.assertTrue(it.get('last_quarantined'))
        self.assertGreaterEqual(len(it.get('orig_paths') or []), 1)

    def test_legacy_duplicate_entries_collapsed_on_read(self):
        """历史遗留的重复条目：读侧折叠为一条（不改磁盘数据）。"""
        qm = self._qm()
        meta = {'items': [
            {'original_path': r'C:\a\same.exe', 'file_hash': 'h' * 64,
             'status': 'quarantined', 'quarantine_time': '2026-01-01T00:00:00',
             'quarantine_path': os.path.join(self.qdir, 'x1')},
            {'original_path': r'C:\a\same.exe', 'file_hash': 'h' * 64,
             'status': 'quarantined', 'quarantine_time': '2026-02-02T00:00:00',
             'quarantine_path': os.path.join(self.qdir, 'x2')},
        ]}
        # 造出对应文件，避免被"文件不存在"判定剔除
        for nm in ('x1', 'x2'):
            with open(os.path.join(self.qdir, nm), 'wb') as f:
                f.write(b'1')
        qm._save_metadata(meta)
        items = qm.get_quarantine_list()
        self.assertEqual(len(items), 1, f'读侧应折叠重复，实际 {len(items)}')
        self.assertEqual(items[0].get('quarantine_time'), '2026-02-02T00:00:00',
                         '应保留最新时间')

    def test_dedupe_key_is_hash_plus_path(self):
        qm = self._qm()
        k1 = qm._dedupe_key({'file_hash': 'abc', 'original_path': r'C:\x\a.exe'})
        k2 = qm._dedupe_key({'file_hash': 'abc', 'original_path': r'C:\X\A.EXE'})
        self.assertEqual(k1, k2, '路径应规范化（大小写不敏感）')
        k3 = qm._dedupe_key({'file_hash': 'abc', 'original_path': r'C:\y\a.exe'})
        self.assertNotEqual(k1, k3, '不同原路径应视为不同条目')

    def test_restore_delete_still_work(self):
        """既有还原/删除行为不被破坏。"""
        qm = self._qm()
        p = self._mal('r.exe')
        self.assertTrue(qm.quarantine_file(p, reason='t', malware_name='T') is True)
        items = qm.get_quarantine_list()
        self.assertEqual(len(items), 1)
        idx = 0
        self.assertTrue(qm.restore_file(idx), '还原应成功')


class TestGenerationsSurviveRestart(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_gen_')
        self.docs = os.path.join(self.tmp, 'docs')
        os.makedirs(self.docs)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        for n in ('a.txt', 'b.txt'):
            with open(os.path.join(self.docs, n), 'wb') as f:
                f.write(n.encode())

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_four_restarts_keep_three_generations(self):
        """连续 4 次"重启 + 启动快照" → 恰好 3 世代、最新在前、最旧淘汰。"""
        seen = []
        for i in range(4):
            m = RansomwareRollback(protected_dirs=[self.docs])
            m.start()
            m.stop()
            r = m.snapshot_now('startup', replace=True)
            gs = m.get_generations()
            seen.append(([g['generation_id'] for g in gs],
                         [g['file_count'] for g in gs]))
        # 每次都应有内容（不得丢成 0）
        for ids, counts in seen:
            self.assertTrue(all(c > 0 for c in counts), f'世代文件数不应为 0: {seen}')
        ids, counts = seen[-1]
        self.assertEqual(len(ids), 3, f'应恰好保留 3 个世代，实际 {ids}')
        self.assertEqual(ids, sorted(ids, reverse=True), f'应最新在前: {ids}')
        self.assertNotIn(1, ids, '最旧世代（id=1）应被淘汰')
        manifest = json.load(open(rr._manifest_path(), encoding='utf-8'))
        self.assertEqual(len(manifest.get('generations') or []), 3)

    def test_shared_object_survives_and_rollback_works(self):
        """跨重启淘汰后共享对象不被误删，仍可回滚。"""
        for _ in range(4):
            m = RansomwareRollback(protected_dirs=[self.docs])
            m.start()
            m.stop()
            m.snapshot_now('startup', replace=True)
        m = RansomwareRollback(protected_dirs=[self.docs])
        p = os.path.join(self.docs, 'a.txt')
        with open(p, 'wb') as f:
            f.write(b'ENCRYPTED')
        res = m.trigger_rollback('manual_confirmed')
        self.assertGreaterEqual(res.get('restored', 0), 1)
        with open(p, 'rb') as f:
            self.assertEqual(f.read(), b'a.txt')

    def test_reload_config_snapshot_is_incremental(self):
        """需求 2：reload 触发的补快照必须是增量（不得清空当前世代）。"""
        src = open(os.path.join(ROOT, 'engine', 'rollback_worker.py'),
                   'r', encoding='utf-8').read()
        i = src.find("snapshot_now('reload'")
        self.assertGreater(i, -1)
        seg = src[i:i + 120]
        self.assertIn('replace=False', seg, 'reload 补快照不得用 replace=True')

    def test_generation_counters_persisted(self):
        m = RansomwareRollback(protected_dirs=[self.docs])
        m.snapshot_now('startup', replace=True)
        manifest = json.load(open(rr._manifest_path(), encoding='utf-8'))
        g0 = (manifest.get('generations') or [{}])[0]
        self.assertGreater(int(g0.get('attempted', 0)), 0, '尝试数应持久化')
        self.assertGreater(int(g0.get('ingested', 0)), 0, '纳入数应持久化')


class TestSignatureDbBackupFallback(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_sdb_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_db(self, path, rows=3):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path)
        conn.execute('CREATE TABLE malware_signatures (hash_sha256 TEXT PRIMARY KEY,'
                     ' name TEXT, type TEXT)')
        for i in range(rows):
            conn.execute('INSERT INTO malware_signatures VALUES (?,?,?)',
                         (f'h{i}' * 20, f'eicar{i}', 'test'))
        conn.commit()
        conn.close()
        # 补到阈值以上（避免被判"大小异常"）
        with open(path, 'ab') as f:
            f.write(b'\x00' * (sdb._DB_MIN_BYTES + 1024))

    def test_backup_location_is_psls_own_dir_not_desktop(self):
        """打包模式下备份在 {exe 目录}\\db_backup（**非**用户桌面/AppData）。"""
        fake_app = os.path.join(self.tmp, 'app')
        os.makedirs(fake_app, exist_ok=True)
        with mock.patch.object(sys, 'frozen', True, create=True), \
                mock.patch.object(sys, 'executable',
                                  os.path.join(fake_app, 'PSLS.exe')):
            cands = sdb._db_backup_paths()
        self.assertTrue(cands)
        p = cands[0]
        self.assertTrue(p.endswith(os.path.join('db_backup', 'signatures.db')), p)
        self.assertTrue(os.path.normcase(p).startswith(os.path.normcase(fake_app)),
                        '备份应位于 PSLS 自身目录下')
        norm = os.path.normcase(p)
        for bad in (os.path.join(os.path.expanduser('~'), 'Desktop'),
                    os.path.join(os.path.expanduser('~'), 'Documents'),
                    os.environ.get('APPDATA', '') or '\x00'):
            if bad and bad != '\x00':
                self.assertFalse(norm.startswith(os.path.normcase(bad)),
                                 f'备份不得放在用户目录: {bad}')

    def test_primary_missing_falls_back_to_backup(self):
        primary = os.path.join(self.tmp, 'user', 'signatures.db')   # 不存在
        backup = os.path.join(self.tmp, 'app', 'db_backup', 'signatures.db')
        self._make_db(backup)
        with mock.patch.object(sdb, '_db_backup_paths', return_value=[backup]):
            path, source = sdb._resolve_working_db_path(primary)
        self.assertEqual(source, 'backup')
        self.assertTrue(os.path.isfile(primary), '应把备份恢复到主路径')
        self.assertTrue(sdb._db_integrity_ok(primary))

    def test_primary_corrupt_falls_back_to_backup(self):
        primary = os.path.join(self.tmp, 'user2', 'signatures.db')
        os.makedirs(os.path.dirname(primary), exist_ok=True)
        with open(primary, 'wb') as f:
            f.write(b'not a sqlite db' * 100000)     # 够大但不是 sqlite
        backup = os.path.join(self.tmp, 'app2', 'db_backup', 'signatures.db')
        self._make_db(backup)
        with mock.patch.object(sdb, '_db_backup_paths', return_value=[backup]):
            self.assertFalse(sdb._db_integrity_ok(primary))
            path, source = sdb._resolve_working_db_path(primary)
        self.assertEqual(source, 'backup')

    def test_both_bad_safe_degrade(self):
        primary = os.path.join(self.tmp, 'user3', 'signatures.db')  # 缺失
        with mock.patch.object(sdb, '_db_backup_paths', return_value=[]):
            path, source = sdb._resolve_working_db_path(primary)
        self.assertEqual(source, 'none', '两者都坏 → 安全降级（不崩）')

    def test_integrity_rejects_empty_and_tiny(self):
        tiny = os.path.join(self.tmp, 'tiny.db')
        with open(tiny, 'wb') as f:
            f.write(b'x')
        self.assertFalse(sdb._db_integrity_ok(tiny), '过小文件不算有效签名库')
        empty = os.path.join(self.tmp, 'empty.db')
        conn = sqlite3.connect(empty); conn.close()
        with open(empty, 'ab') as f:
            f.write(b'\x00' * (sdb._DB_MIN_BYTES + 10))
        self.assertFalse(sdb._db_integrity_ok(empty), '无签名表不算有效')

    def test_build_and_installer_ship_backup(self):
        b = open(os.path.join(ROOT, 'build.py'), 'r', encoding='utf-8').read()
        self.assertIn('db_backup', b, 'build.py 应生成 db_backup 备份')
        iss = open(os.path.join(ROOT, 'installer', 'PSLS_Setup.iss'),
                   'r', encoding='utf-8').read()
        # 安装器用 dist\PSLS\* 递归打包 → db_backup 会随之进包
        self.assertIn('recurse', iss.lower())


if __name__ == '__main__':
    unittest.main()