# -*- coding: utf-8 -*-
"""勒索回滚进程剥离（--rollback-worker 自重启动 + 主进程代理 + 降级）测试。

覆盖：
  1. 自重启动入口：gui_entry 的 --rollback-worker 分支在 PyQt 导入之前，
     且仅调用 worker 主循环；worker 模块不含 PyQt；
  2. 主进程代理真实启动 worker 进程，能收到 snapshot_now 结果；主进程不再
     持有回滚引擎（_local is None）；
  3. worker 启动失败 → 自动降级为进程内线程模式且功能可用；
  4. 真实端到端（B）：worker 模式连做 4 次启动快照 → 世代=3；改动文件后用
     第 2 个世代回滚 → 内容正确。
"""
import os
import sys
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.ransomware_rollback as rr
from engine.rollback_worker import RollbackWorkerProxy


class TestWorkerIsolation(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_wk_')
        self.protected = os.path.join(self.tmp, 'docs')
        os.makedirs(self.protected, exist_ok=True)
        self._old_root = rr._REPO_ROOT
        self._old_appdata = os.environ.get('APPDATA')
        self._old_repo_env = os.environ.get('PSLS_ROLLBACK_REPO')
        # 主进程内降级引擎使用的仓库根
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo_main')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        # worker 子进程通过环境变量定位仓库（与主进程隔离，避免污染项目 rollback/）
        self.worker_repo = os.path.join(self.tmp, 'appdata', 'PSLS', 'rollback')
        os.environ['PSLS_ROLLBACK_REPO'] = self.worker_repo
        os.environ['APPDATA'] = os.path.join(self.tmp, 'appdata')
        self._proxy = None

    def tearDown(self):
        if self._proxy is not None:
            try:
                self._proxy.stop()
            except Exception:
                pass
        rr._REPO_ROOT = self._old_root
        if self._old_appdata is None:
            os.environ.pop('APPDATA', None)
        else:
            os.environ['APPDATA'] = self._old_appdata
        if self._old_repo_env is None:
            os.environ.pop('PSLS_ROLLBACK_REPO', None)
        else:
            os.environ['PSLS_ROLLBACK_REPO'] = self._old_repo_env
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, data):
        p = os.path.join(self.protected, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    # ---- 1. 入口契约 ----

    def test_worker_entry_source_contract(self):
        with open(os.path.join(ROOT, 'gui_entry.py'), 'r', encoding='utf-8') as f:
            ge = f.read()
        i_branch = ge.index("'--rollback-worker' in sys.argv")
        i_pyqt = ge.index('from PyQt5')
        self.assertLess(i_branch, i_pyqt,
                        '--rollback-worker 分支必须在 PyQt 导入之前')
        self.assertIn('run_worker_main', ge)

        with open(os.path.join(ROOT, 'engine', 'rollback_worker.py'),
                  'r', encoding='utf-8') as f:
            wk = f.read()
        self.assertIn("if __name__ == '__main__':", wk)
        self.assertIn('def run_worker_main', wk)
        self.assertNotIn('PyQt5', wk, 'worker 模块不得依赖 Qt')
        self.assertNotIn('QApplication', wk)

    # ---- 2. worker 启动失败降级 ----

    def test_spawn_failure_degrades_to_in_process(self):
        with mock.patch('engine.rollback_worker.subprocess.Popen',
                        side_effect=OSError('spawn blocked')):
            proxy = RollbackWorkerProxy(
                quarantine_manager=None, on_report=None,
                protected_dirs=[self.protected])
        self._proxy = proxy
        self.assertFalse(proxy.is_worker_process,
                         '启动失败必须降级为进程内模式')
        self.assertIsNotNone(proxy._local)
        # 降级后功能可用
        self._write('a.txt', b'DEGRADE')
        res = proxy.snapshot_now('startup', replace=True)
        self.assertGreaterEqual(res.get('added', 0), 1)

    # ---- 3/4. 真实 worker E2E ----

    def test_real_worker_snapshot_generations_and_rollback(self):
        proxy = RollbackWorkerProxy(quarantine_manager=None, on_report=None)
        self._proxy = proxy
        if not proxy.is_worker_process:
            self.skipTest('worker 子进程不可用（环境限制），降级路径另测')
        # 主进程不持有回滚引擎
        self.assertIsNone(proxy._local)
        self.assertGreater(proxy.worker_pid, 0)
        self.assertNotEqual(proxy.worker_pid, os.getpid())
        self.assertIsNotNone(proxy._proc)
        self.assertIsNone(proxy._proc.poll(), 'worker 进程应存活')

        # 直接下发目录并快照（不调 start()，避免与 worker 启动周期快照竞争）
        proxy.set_protected_dirs([self.protected])

        # 连做 4 次启动快照 → 世代最多 3
        specs = [('a.txt', b'G1'), ('b.txt', b'G2'),
                 ('c.txt', b'G3'), ('d.txt', b'G4')]
        for name, data in specs:
            self._write(name, data)
            r = proxy.snapshot_now('startup', replace=True)
            self.assertTrue(r.get('ok'), r)
            self.assertGreaterEqual(r.get('added', 0), 1)

        gens = proxy.get_generations()
        self.assertEqual(len(gens), 3, gens)
        # 新→旧排序：最新文件数最多
        self.assertGreaterEqual(gens[0]['file_count'], gens[-1]['file_count'])

        # 对象仓库内容寻址去重：4 个不同内容 → 4 个对象（淘汰最旧世代不得误删共享对象）
        # worker 仓库根现与主进程强制一致（rr._REPO_ROOT）
        obj_dir = os.path.join(rr._REPO_ROOT, 'objects')
        obj_count = sum(len(fs) for _r, _d, fs in os.walk(obj_dir))
        self.assertEqual(obj_count, 4, '内容寻址对象数应为 4（共享/去重正确）')

        # 用第 2 个世代（含 a=G1,b=G2）回滚
        target = gens[1]['generation_id']
        a = self._write('a.txt', b'CORRUPT')
        b = self._write('b.txt', b'CORRUPT')
        res = proxy.trigger_rollback('manual_confirmed', generation_id=target)
        self.assertEqual(res.get('generation_id'), target)
        with open(a, 'rb') as f:
            self.assertEqual(f.read(), b'G1')
        with open(b, 'rb') as f:
            self.assertEqual(f.read(), b'G2')

        # 主进程仍不持有引擎（快照遍历全部在 worker 内执行）
        self.assertIsNone(proxy._local)


if __name__ == '__main__':
    unittest.main()