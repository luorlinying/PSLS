# -*- coding: utf-8 -*-
"""勒索回滚"快照拍摄为 0"修复 + 快照范围/文件类型过滤 回归测试。

失败因（修复前）：
  - _do_snapshot(replace=True) 先 _purge_snapshot_generation()（清除上一"快照
    世代"，但**保留** source='driver_shadow' 的写前原像条目），随后对每个文件
    若命中 driver_shadow 条目则直接计 unchanged 并 continue —— 阶段二驱动启用时
    几乎所有受保护文件都有写前原像，added 因此塌缩为 0，用户看到"快照拍摄为 0"。
  - 修复：replace=True 时该分支改计 added（条目属本世代），replace=False 语义不变。
  - 新增：快照文件类型白名单 get_snapshot_exts/set_snapshot_exts（空=全部）。

全部用例把 engine.ransomware_rollback._REPO_ROOT monkeypatch 到 tempfile。
"""
import os
import sys
import json
import time
import shutil
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback


class TestRollbackSnapshotRange(unittest.TestCase):

    def setUp(self):
        self._old_root = rr._REPO_ROOT
        self._old_appdata = os.environ.get('APPDATA')
        self.tmp = tempfile.mkdtemp(prefix='psls_rbsnap_')
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        self.protected = os.path.join(self.tmp, 'docs')
        os.makedirs(self.protected, exist_ok=True)

    def tearDown(self):
        rr._REPO_ROOT = self._old_root
        if self._old_appdata is None:
            os.environ.pop('APPDATA', None)
        else:
            os.environ['APPDATA'] = self._old_appdata
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mgr(self):
        return RansomwareRollback(protected_dirs=[self.protected])

    def _write(self, name, data):
        p = os.path.join(self.protected, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    def _object_count(self):
        return sum(1 for _ in rr._iter_object_files())

    def _make_shadow(self, gen, name, data):
        d = rr._shadow_gen_dir(gen)
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    # ---- 1. 复现并修复：replace=True 时 added 必须 > 0 ----

    def test_replace_snapshot_counts_driver_shadow_as_added(self):
        m = self._mgr()
        m._generation = 3
        real = self._write('a.txt', b'ORIGINAL-A')
        shadow = self._make_shadow(3, 's0', b'ORIGINAL-A')
        m.ingest_shadow_backup(real, shadow, len(b'ORIGINAL-A'), 100)

        r = m.snapshot_now('periodic', replace=True)
        self.assertGreater(r['added'], 0,
                           'replace=True 快照 added 为 0（"快照拍摄为 0"复现）')
        self.assertEqual(r['added'], 1)
        self.assertEqual(r['unchanged'], 0)
        # 写前原像不得被顶掉
        key = os.path.abspath(real).lower()
        with m._state_lock:
            meta = dict(m._manifest['entries'][key])
        self.assertEqual(meta['source'], 'driver_shadow')

    def test_incremental_semantics_unchanged(self):
        """replace=False 增量语义不得改变。"""
        m = self._mgr()
        self._write('a.txt', b'AAA')
        self._write('b.txt', b'BBBB')
        r1 = m.snapshot_now('t1')
        self.assertEqual(r1['added'], 2)
        r2 = m.snapshot_now('t2')
        self.assertEqual(r2['added'], 0)
        self.assertEqual(r2['unchanged'], 2)

        # 有写前原像时，增量快照仍计 unchanged（不误报新增）
        m._generation = 1
        sh = self._make_shadow(1, 'p', b'AAA')
        m.ingest_shadow_backup(os.path.join(self.protected, 'a.txt'), sh,
                               len(b'AAA'), 7)
        r3 = m.snapshot_now('t3', replace=False)
        self.assertEqual(r3['added'], 0)

    def test_e2e_replace_then_incremental_single_changed(self):
        """端到端：快照 → 改一个文件 → 增量再快照只新增该文件。"""
        m = self._mgr()
        self._write('a.dat', b'AAA')
        self._write('b.dat', b'BBB')
        r1 = m.snapshot_now('init', replace=True)
        self.assertGreater(r1['added'], 0)
        time.sleep(0.02)
        self._write('a.dat', b'AAA-CHANGED')
        r2 = m.snapshot_now('incr', replace=False)   # 增量
        self.assertEqual(r2['added'], 1)
        self.assertEqual(r2['unchanged'], 1)

    # ---- 2. 快照文件类型白名单 ----

    def test_ext_filter_limits_snapshot(self):
        m = self._mgr()
        self._write('keep.docx', b'DOC')
        self._write('skip.txt', b'TXT')
        self.assertEqual(m.set_snapshot_exts(['docx']), ['.docx'])   # 补前导点+小写
        r = m.snapshot_now('filtered', replace=True)
        self.assertEqual(r['added'], 1)
        self.assertEqual(self._object_count(), 1)
        with m._state_lock:
            keys = [os.path.basename(k) for k in m._manifest['entries']]
        self.assertEqual(keys, ['keep.docx'])

        # 清空白名单 → 全部类型
        self.assertEqual(m.set_snapshot_exts([]), [])
        r2 = m.snapshot_now('all', replace=True)
        self.assertEqual(r2['added'], 2)

    def test_ext_normalize_star_means_all(self):
        m = self._mgr()
        self.assertEqual(m.set_snapshot_exts(['*']), [])
        self.assertEqual(m.set_snapshot_exts(['.DOC', 'doc', '.txt', '']),
                         ['.doc', '.txt'])

    # ---- 3. 桥接持久化 + 回灌 ----

    def test_settings_persist_and_reflow(self):
        import ui.webview.bridge as bmod
        os.environ['APPDATA'] = os.path.join(self.tmp, 'appdata')

        bmod._save_ui_settings({
            'rollback_snapshot_dirs': [self.protected],
            'rollback_snapshot_exts': ['.docx'],
        })
        # 落盘校验：settings.json 的 "ui" 段
        path = bmod._ui_settings_path()
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertIn('rollback_snapshot_dirs', data.get('ui', {}))
        self.assertEqual(data['ui']['rollback_snapshot_exts'], ['.docx'])

        # 回灌：模拟 _init_managers 读取并写回引擎
        saved = bmod._load_ui_settings()
        m = self._mgr()
        m.set_protected_dirs(saved['rollback_snapshot_dirs'])
        m.set_snapshot_exts(saved['rollback_snapshot_exts'])
        self.assertEqual(m.get_protected_dirs(), [self.protected])
        self.assertEqual(m.get_snapshot_exts(), ['.docx'])

    def test_bridge_slots_persist_without_engine(self):
        import ui.webview.bridge as bmod
        os.environ['APPDATA'] = os.path.join(self.tmp, 'appdata2')
        src_path = os.path.join(ROOT, 'ui', 'webview', 'bridge.py')
        with open(src_path, 'r', encoding='utf-8') as f:
            src = f.read()
        self.assertIn('def setRollbackSnapshotConfig', src)
        self.assertIn('def getRollbackSnapshotConfig', src)
        # 持久化 + 回灌键名必须一致
        self.assertIn('rollback_snapshot_dirs', src)
        self.assertIn('rollback_snapshot_exts', src)


if __name__ == '__main__':
    unittest.main()