# -*- coding: utf-8 -*-
"""回归：默认配置（未自定义快照范围）下快照不得为 0。

根因：worker `_build_engine` 曾无条件 `set_protected_dirs([])`，且主进程未把目录
注入子进程 / `reload_config(dirs=None)` 被静默跳过 → worker 保护目录永远为空，
`_do_snapshot` 空循环 → added/total = 0（"快照又变成 0"），且 get_protected_dirs
返回空导致设置页看不到默认目录。

覆盖：
  1. 默认未注入配置下 worker/代理 get_protected_dirs() 非空；
  2. reload_config(dirs=None) → 回落默认（等于默认解析结果）；
  3. reload_config(dirs=[]) / set_protected_dirs([]) → 回落默认 + WARNING；
  4. 默认路径分支执行快照 → total > 0（用 monkeypatch 默认目录到临时目录）；
  5. dirs 为空时 _do_snapshot 返回 dirs_count=0 且打 WARNING。
"""
import os
import sys
import shutil
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.ransomware_rollback as rr
import engine.rollback_worker as rw
from engine.ransomware_rollback import RansomwareRollback
from engine.rollback_worker import RollbackWorkerProxy


class TestWorkerDefaultDirs(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_def_')
        self.protected = os.path.join(self.tmp, 'docs')
        os.makedirs(self.protected, exist_ok=True)
        # 主进程引擎仓库隔离
        self._old_root = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo_main')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        # worker 子进程仓库隔离 + 清理可能残留的注入变量
        self._old_repo_env = os.environ.get('PSLS_ROLLBACK_REPO')
        self._old_dirs_env = os.environ.pop('PSLS_ROLLBACK_DIRS', None)
        os.environ['PSLS_ROLLBACK_REPO'] = os.path.join(self.tmp, 'repo_worker')
        self._proxy = None

    def tearDown(self):
        if self._proxy is not None:
            try:
                self._proxy.stop()
            except Exception:
                pass
        rr._REPO_ROOT = self._old_root
        if self._old_repo_env is None:
            os.environ.pop('PSLS_ROLLBACK_REPO', None)
        else:
            os.environ['PSLS_ROLLBACK_REPO'] = self._old_repo_env
        if self._old_dirs_env is None:
            os.environ.pop('PSLS_ROLLBACK_DIRS', None)
        else:
            os.environ['PSLS_ROLLBACK_DIRS'] = self._old_dirs_env
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _engine(self):
        m = RansomwareRollback(protected_dirs=[self.protected])
        # 把"默认目录解析"指向临时目录，避免依赖真实用户目录
        m._resolve_default_dirs = lambda: [self.protected]
        return m

    # ---- 1. 默认配置下代理目录非空（核心回归断言）----

    def test_default_config_proxy_dirs_non_empty(self):
        proxy = RollbackWorkerProxy(quarantine_manager=None, on_report=None)
        self._proxy = proxy
        if not proxy.is_worker_process:
            self.skipTest('worker 子进程不可用（环境限制）')
        dirs = proxy.get_protected_dirs()
        self.assertTrue(dirs, '默认配置下 worker 代理必须解析出非空保护目录')
        # 与引擎默认解析结果一致
        expected = set(os.path.normcase(d) for d in RansomwareRollback()._resolve_default_dirs())
        got = set(os.path.normcase(d) for d in dirs)
        if expected:
            self.assertEqual(got, expected)

    # ---- 2/3. reload_config / set_protected_dirs 的 dirs 语义（进程内 dispatch）----

    def test_reload_config_none_falls_back_to_default(self):
        m = self._engine()
        res = rw._dispatch(m, 'reload_config', {'dirs': None})
        self.assertTrue(res['dirs'])
        self.assertEqual([os.path.normcase(d) for d in res['dirs']],
                         [os.path.normcase(self.protected)])

    def test_reload_config_empty_falls_back_with_warning(self):
        from unittest import mock
        m = self._engine()
        # 注：utils.logger 为单例，记录器名不稳定，故直接对模块 logger.warning 打桩
        with mock.patch.object(rw.logger, 'warning') as mw:
            res = rw._dispatch(m, 'reload_config', {'dirs': []})
        self.assertTrue(res['dirs'], '空列表必须回落默认，不能留空')
        self.assertTrue(any('回落默认' in str(c.args) for c in mw.call_args_list),
                        mw.call_args_list)

    def test_set_protected_dirs_empty_falls_back_with_warning(self):
        from unittest import mock
        m = self._engine()
        with mock.patch.object(rw.logger, 'warning') as mw:
            res = rw._dispatch(m, 'set_protected_dirs', {'dirs': []})
        self.assertTrue(res['dirs'])
        self.assertTrue(any('回落默认' in str(c.args) for c in mw.call_args_list),
                        mw.call_args_list)

    # ---- 4. 默认路径分支快照 total > 0 ----

    def test_default_branch_snapshot_has_files(self):
        m = self._engine()
        # 模拟主进程回灌 null 范围（默认配置）→ worker 回落默认目录
        rw._dispatch(m, 'reload_config', {'dirs': None})
        with open(os.path.join(self.protected, 'doc.txt'), 'wb') as f:
            f.write(b'HELLO-DEFAULT')
        r = m.snapshot_now('startup', replace=True)
        self.assertGreater(r['total'], 0)
        self.assertEqual(r['dirs_count'], 1)
        self.assertGreaterEqual(r['added'], 1)

    def test_injected_branch_snapshot_has_files(self):
        m = RansomwareRollback(protected_dirs=[self.protected])
        with open(os.path.join(self.protected, 'doc2.txt'), 'wb') as f:
            f.write(b'HELLO-INJECTED')
        r = m.snapshot_now('startup', replace=True)
        self.assertGreater(r['total'], 0)
        self.assertEqual(r['dirs_count'], 1)

    # ---- 5. dirs 为空时 WARNING + dirs_count=0 ----

    def test_empty_dirs_snapshot_warns(self):
        from unittest import mock
        m = RansomwareRollback()
        m.set_protected_dirs([os.path.join(self.tmp, 'not_exist_dir')])  # 归一化后为空
        self.assertEqual(m.get_protected_dirs(), [])
        with mock.patch.object(rr.logger, 'warning') as mw:
            r = m.snapshot_now('startup', replace=True)
        self.assertEqual(r['dirs_count'], 0)
        self.assertEqual(r['total'], 0)
        self.assertTrue(any('0 个目录' in str(c.args) for c in mw.call_args_list),
                        mw.call_args_list)


if __name__ == '__main__':
    unittest.main()