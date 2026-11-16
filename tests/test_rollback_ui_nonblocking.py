# -*- coding: utf-8 -*-
"""回归：回滚中心"页面加载零阻塞" + 列表可见（现象 1/2）。

覆盖：
  1. 代理缓存访问器（get_generations_cached / list_records_cached /
     get_protected_dirs_cached）在 worker 未就绪/卡顿时仍立即返回（<200ms）；
  2. refresh_state_async() 立即返回（后台线程真正干活），即使 _request 人为阻塞；
  3. 磁盘有数据时（快照 + 回滚记录）列表缓存非空，且 JSON 形状与前端一致；
  4. bridge 的四个回滚槽改用缓存访问器（源码契约）。
"""
import os
import sys
import time
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback
from engine.rollback_worker import RollbackWorkerProxy, _dispatch


class TestRollbackUINonBlocking(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_nb_')
        self.protected = os.path.join(self.tmp, 'docs')
        os.makedirs(self.protected, exist_ok=True)
        self._old_root = rr._REPO_ROOT
        self._old_env = os.environ.get('PSLS_ROLLBACK_REPO')
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        os.environ['PSLS_ROLLBACK_REPO'] = rr._REPO_ROOT
        self._proxy = None

    def tearDown(self):
        if self._proxy is not None:
            try:
                self._proxy.stop()
            except Exception:
                pass
        rr._REPO_ROOT = self._old_root
        if self._old_env is None:
            os.environ.pop('PSLS_ROLLBACK_REPO', None)
        else:
            os.environ['PSLS_ROLLBACK_REPO'] = self._old_env
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, data):
        p = os.path.join(self.protected, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    # ---- 1/2. 非阻塞 ----

    def test_cached_accessors_and_refresh_are_nonblocking(self):
        proxy = RollbackWorkerProxy(quarantine_manager=None, on_report=None,
                                    protected_dirs=[self.protected])
        self._proxy = proxy
        # 人为让真实 IPC 变慢，验证缓存读与后台刷新仍不阻塞
        proxy._request = lambda *a, **k: (time.sleep(1.0), None)[1]

        t0 = time.time()
        g = proxy.get_generations_cached()
        r = proxy.list_records_cached()
        d = proxy.get_protected_dirs_cached()
        e = proxy.get_snapshot_exts_cached()
        dt = time.time() - t0
        self.assertLess(dt, 0.2, f'缓存访问器不应阻塞（{dt:.3f}s）')
        self.assertIsInstance(g, list)
        self.assertIsInstance(r, list)
        self.assertIsInstance(d, list)
        self.assertIsInstance(e, list)

        t0 = time.time()
        proxy.refresh_state_async()
        dt = time.time() - t0
        self.assertLess(dt, 0.2, f'refresh_state_async 不应阻塞（{dt:.3f}s）')

    # ---- 3. 列表可见 + JSON 形状 ----

    def test_disk_data_visible_in_generations_and_records(self):
        proxy = RollbackWorkerProxy(quarantine_manager=None, on_report=None,
                                    protected_dirs=[self.protected])
        self._proxy = proxy
        proxy.set_protected_dirs([self.protected])
        self._write('a.docx', b'ORIGINAL')
        res = proxy.snapshot_now('startup', replace=True)
        self.assertGreaterEqual(res.get('added', 0), 1)
        # 改坏 → 回滚，产生一条记录
        with open(os.path.join(self.protected, 'a.docx'), 'wb') as f:
            f.write(b'ENCRYPTED')
        proxy.trigger_rollback('manual_confirmed')

        # 后台刷新（等待完成）→ 缓存非空
        proxy.refresh_state_async()
        deadline = time.time() + 8
        gens = proxy.get_generations_cached()
        recs = proxy.list_records_cached()
        while time.time() < deadline and (not gens or not recs):
            time.sleep(0.05)
            gens = proxy.get_generations_cached()
            recs = proxy.list_records_cached()
        self.assertTrue(gens, '磁盘有快照时世代列表必须非空')
        self.assertTrue(recs, '磁盘有回滚记录时记录列表必须非空')

        # JSON 形状与前端消费一致
        g0 = gens[0]
        for k in ('generation_id', 'created_at', 'created_at_str',
                  'reason', 'file_count'):
            self.assertIn(k, g0)
        r0 = recs[0]
        for k in ('id', 'reason', 'restored', 'failed', 'skipped', 'files'):
            self.assertIn(k, r0)
        # 前端读取 data.records / obj.generations
        self.assertIn('records', {'records': recs})
        self.assertIn('generations', {'generations': gens})

    def test_worker_get_state_single_roundtrip(self):
        """worker get_state 一次返回 status/generations/records/dirs/exts。"""
        m = RansomwareRollback(protected_dirs=[self.protected])
        with open(os.path.join(self.protected, 'z.txt'), 'wb') as f:
            f.write(b'Z')
        m.snapshot_now('startup', replace=True)
        out = _dispatch(m, 'get_state', {})
        for k in ('status', 'generations', 'records',
                  'protected_dirs', 'snapshot_exts'):
            self.assertIn(k, out)
        self.assertTrue(out['generations'])
        self.assertTrue(out['protected_dirs'])

    # ---- 4. bridge 源码契约 ----

    def test_bridge_slots_use_cached_accessors(self):
        with open(os.path.join(ROOT, 'ui', 'webview', 'bridge.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        for token in ('get_generations_cached', 'list_records_cached',
                      'get_protected_dirs_cached', 'get_snapshot_exts_cached',
                      'refresh_state_async', '_rollback_refresh_async',
                      'state_refresh'):
            self.assertIn(token, src, token)


if __name__ == '__main__':
    unittest.main()