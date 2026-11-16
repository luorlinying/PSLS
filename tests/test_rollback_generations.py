# -*- coding: utf-8 -*-
"""勒索回滚世代模型（保留 3 个 + 选择世代回滚）单元测试。

覆盖：
  1. 连续 4 次启动快照 → 仅保留 3 个世代，最旧被淘汰；
  2. 共享对象不被误删（内容寻址去重），保留世代的独有对象被清理、共享对象仍可回滚；
  3. 周期快照刷新当前世代、不新建世代；
  4. 指定 generation_id 回滚 → 恢复该世代内容；None → 最新世代；
  5. get_generations 数量与排序（新→旧）；
  6. driver_shadow 写前原像归属于最新世代且不被保留策略误删。

全部用例把 engine.ransomware_rollback._REPO_ROOT monkeypatch 到 tempfile。
"""
import os
import sys
import shutil
import hashlib
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback, _MAX_GENERATIONS


class _FakeQuarantine:
    def __init__(self, qdir):
        self.qdir = qdir
        self.calls = []
        os.makedirs(qdir, exist_ok=True)

    def quarantine_file(self, path, reason='', malware_name='', **kwargs):
        self.calls.append((path, reason, malware_name))
        try:
            if not os.path.isfile(path):
                return False
            shutil.move(path, os.path.join(self.qdir, os.path.basename(path) + '.q'))
            return True
        except Exception:
            return False

    def _unregister_soft_quarantine(self, path):
        pass


class TestGenerations(unittest.TestCase):

    def setUp(self):
        self._old_root = rr._REPO_ROOT
        self.tmp = tempfile.mkdtemp(prefix='psls_gen_')
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        self.protected = os.path.join(self.tmp, 'docs')
        os.makedirs(self.protected, exist_ok=True)
        self.qm = _FakeQuarantine(os.path.join(self.tmp, 'quarantine'))

    def tearDown(self):
        rr._REPO_ROOT = self._old_root
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mgr(self, **kwargs):
        kwargs.setdefault('quarantine_manager', self.qm)
        kwargs.setdefault('protected_dirs', [self.protected])
        return RansomwareRollback(**kwargs)

    def _write(self, name, data):
        p = os.path.join(self.protected, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    def _obj(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        return os.path.join(rr._objects_dir(), sha[:2], sha)

    # ---- 1. 保留 3 个 ----

    def test_four_startups_keep_three_generations(self):
        m = self._mgr()
        ids = []
        for i in range(4):
            self._write(f'f{i}.txt', f'gen-{i}'.encode())
            r = m.snapshot_now('startup', replace=True)
            ids.append(r['generation_id'])
        gens = m.get_generations()
        self.assertEqual(len(gens), _MAX_GENERATIONS)
        self.assertEqual(gens[0]['generation_id'], ids[-1])   # 最新在前
        self.assertNotIn(ids[0], [g['generation_id'] for g in gens])  # 最旧被淘汰

    # ---- 2. 共享对象不被误删 ----

    def test_shared_object_survives_eviction_and_remains_rollbackable(self):
        m = self._mgr()
        shared = self._write('shared.txt', b'SHARED-ORIG')
        only1 = self._write('only1.txt', b'ONLY1-CONTENT')
        r1 = m.snapshot_now('startup', replace=True)   # gen1: shared + only1
        gen1_id = r1['generation_id']
        gen2_id = m.snapshot_now('startup', replace=True)['generation_id']  # gen2: 仍含两者
        # 删除 only1 → 后续世代不再引用其对象
        os.remove(only1)
        gen3_id = m.snapshot_now('startup', replace=True)['generation_id']
        gen4_id = m.snapshot_now('startup', replace=True)['generation_id']  # 触发淘汰 gen1

        self.assertNotEqual(gen1_id, gen2_id)
        # 共享对象（SHARED-ORIG）仍被 gen2 引用 → 必须保留
        self.assertTrue(os.path.isfile(self._obj(b'SHARED-ORIG')))
        self.assertTrue(os.path.isfile(self._obj(b'ONLY1-CONTENT')),
                        'gen1 独有对象在 gen1 保留时应仍在')

        # 构造第 4 次淘汰前，让 only1 成为 gen1 独有：gen1 与其它世代仅共享 shared
        # 直接回收 gen1 的独有对象验证：先滚动到 gen1 被淘汰
        # 再启动两次即可把含 only1 的世代淘汰
        m.snapshot_now('startup', replace=True)
        m.snapshot_now('startup', replace=True)   # 含 only1 的最老者被淘汰

        gens = m.get_generations()
        self.assertEqual(len(gens), _MAX_GENERATIONS)
        self.assertFalse(os.path.exists(self._obj(b'ONLY1-CONTENT')),
                         '被淘汰世代的独有对象应被清理')
        self.assertTrue(os.path.isfile(self._obj(b'SHARED-ORIG')),
                        '共享对象绝不能随淘汰被删除')

        # 共享对象仍可回滚：改坏文件 → 用含 SHARED-ORIG 的保留世代回滚
        with open(shared, 'wb') as f:
            f.write(b'ENCRYPTED-GARBAGE')
        target_id = [g['generation_id'] for g in gens][-1]
        res = m.trigger_rollback('manual_confirmed', generation_id=target_id)
        self.assertGreaterEqual(res['restored'], 1)
        with open(shared, 'rb') as f:
            self.assertEqual(f.read(), b'SHARED-ORIG')

    # ---- 3. 周期快照不新建世代 ----

    def test_periodic_snapshot_does_not_create_generation(self):
        m = self._mgr()
        self._write('p.txt', b'P1')
        for _ in range(_MAX_GENERATIONS):
            m.snapshot_now('startup', replace=True)
        before = len(m.get_generations())
        m.snapshot_now('periodic', replace=True)
        m.snapshot_now('periodic', replace=True)
        self.assertEqual(len(m.get_generations()), before)
        self.assertEqual(before, _MAX_GENERATIONS)

    # ---- 4. 指定世代回滚 ----

    def test_rollback_specific_generation_restores_that_content(self):
        m = self._mgr()
        p = self._write('doc.txt', b'V1-CONTENT')
        g1 = m.snapshot_now('startup', replace=True)['generation_id']

        with open(p, 'wb') as f:
            f.write(b'V2-CONTENT')
        g2 = m.snapshot_now('startup', replace=True)['generation_id']

        with open(p, 'wb') as f:
            f.write(b'V3-CONTENT')
        g3 = m.snapshot_now('startup', replace=True)['generation_id']
        self.assertTrue(g1 < g2 < g3)

        # 指定 gen2 → 恢复 V2
        with open(p, 'wb') as f:
            f.write(b'ENCRYPTED')
        res2 = m.trigger_rollback('manual_confirmed', generation_id=g2)
        self.assertEqual(res2['generation_id'], g2)
        with open(p, 'rb') as f:
            self.assertEqual(f.read(), b'V2-CONTENT')

        # 指定 gen1 → 恢复 V1
        with open(p, 'wb') as f:
            f.write(b'ENCRYPTED')
        res1 = m.trigger_rollback('manual_confirmed', generation_id=g1)
        with open(p, 'rb') as f:
            self.assertEqual(f.read(), b'V1-CONTENT')

        # None → 最新（gen3）
        with open(p, 'wb') as f:
            f.write(b'ENCRYPTED')
        res_none = m.trigger_rollback('manual_confirmed')
        self.assertEqual(res_none['generation_id'], g3)
        with open(p, 'rb') as f:
            self.assertEqual(f.read(), b'V3-CONTENT')

    # ---- 5. get_generations 排序 ----

    def test_get_generations_order_and_count(self):
        m = self._mgr()
        ids = []
        for i in range(2):
            self._write(f'x{i}.txt', f'X{i}'.encode())
            ids.append(m.snapshot_now('startup', replace=True)['generation_id'])
        gens = m.get_generations()
        self.assertEqual([g['generation_id'] for g in gens], [ids[1], ids[0]])
        for g in gens:
            self.assertIn('created_at', g)
            self.assertIn('reason', g)
            self.assertIn('file_count', g)
            self.assertEqual(g['reason'], 'startup')
        self.assertEqual(gens[0]['file_count'], 2)

    # ---- 6. driver_shadow 归属最新世代且不被误删 ----

    def test_driver_shadow_preimage_kept_by_retention(self):
        m = self._mgr()
        real = self._write('photo.jpg', b'PRE-IMAGE-BYTES')
        shadow = os.path.join(rr._shadow_gen_dir(0), 's0')
        os.makedirs(os.path.dirname(shadow), exist_ok=True)
        with open(shadow, 'wb') as f:
            f.write(b'PRE-IMAGE-BYTES')
        self.assertTrue(m.ingest_shadow_backup(real, shadow,
                                               len(b'PRE-IMAGE-BYTES'), 42))
        # 写前原像落在最新世代
        with m._state_lock:
            latest = m._latest_gen()
            key = os.path.abspath(real).lower()
            self.assertEqual(latest['entries'][key]['source'], 'driver_shadow')
        # 删除原文件，使该对象仅被写前原像条目引用
        os.remove(real)

        # 再启动 2 次：写前原像所在世代仍在保留范围内，其对象不得被删
        self._write('other1.txt', b'O1')
        m.snapshot_now('startup', replace=True)
        self._write('other2.txt', b'O2')
        m.snapshot_now('startup', replace=True)
        self.assertEqual(len(m.get_generations()), 3)
        sha = hashlib.sha256(b'PRE-IMAGE-BYTES').hexdigest()
        self.assertTrue(os.path.isfile(m._object_path(sha)),
                        '写前原像对象不得被保留策略删除')

    # ---- 7. 世代选择列表（≤3）----

    def test_generations_capped_at_three(self):
        m = self._mgr()
        for i in range(6):
            self._write(f'c{i}.txt', f'C{i}'.encode())
            m.snapshot_now('startup', replace=True)
        self.assertLessEqual(len(m.get_generations()), 3)


if __name__ == '__main__':
    unittest.main()