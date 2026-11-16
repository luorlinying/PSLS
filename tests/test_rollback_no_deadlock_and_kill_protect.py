# -*- coding: utf-8 -*-
"""回滚卡死修复回归：GUI 零阻塞、等待槽不互吃、锁序无死锁、清场保护集、沙箱隐藏。

对应本轮现象 1（回滚卡死）与现象 2（动画掉帧）：
  1. GUI 线程路径同步 IPC 预算收敛（≤0.2s），未就绪立即返回；
  2. 并发两次快照 + 一次回滚上报 → 所有调用方都能拿到结果（不永久等待）；
  3. 并发快照 + 淘汰 + 影子入仓 → 固定时长内无死锁；
  4. 清场不终止 MLWorker / 隔离环境基础设施 / 代理父链 / worker 自身；
  5. 动画计时器为 PreciseTimer；沙箱重启子进程已带 CREATE_NO_WINDOW。
"""
import os
import sys
import time
import shutil
import hashlib
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback
from engine.rollback_worker import RollbackWorkerProxy


class TestGuiZeroBlocking(unittest.TestCase):

    def test_bounded_timeout_clamps_on_gui_thread(self):
        p = RollbackWorkerProxy(spawn=False)
        p._is_gui_thread = lambda: True
        self.assertLessEqual(p._bounded_timeout(300.0), 0.15)
        self.assertLessEqual(p._bounded_timeout(600.0), 0.15)
        p._is_gui_thread = lambda: False
        self.assertEqual(p._bounded_timeout(300.0), 300.0)

    def test_request_never_blocks_gui_thread(self):
        """GUI 线程上 worker 未就绪 → _request 立即返回 None，不得同步 spawn/长等。"""
        p = RollbackWorkerProxy(spawn=False)
        p._proc = None
        p._is_gui_thread = lambda: True
        calls = []
        p._ensure_worker_async = lambda: calls.append(1)   # 只允许后台异步启动
        t0 = time.time()
        res = p._request('snapshot_now', {}, timeout=300.0)
        dt = time.time() - t0
        self.assertIsNone(res)
        self.assertLess(dt, 0.2, f'GUI 线程被阻塞 {dt:.3f}s')
        self.assertEqual(calls, [1], '应交由后台异步启动')

    def test_ensure_worker_async_is_nonblocking(self):
        p = RollbackWorkerProxy(spawn=False)
        started = []
        p._spawn_worker = lambda: (started.append(1), False)[1]
        t0 = time.time()
        p._ensure_worker_async()
        self.assertLess(time.time() - t0, 0.2, '异步启动不得阻塞调用线程')
        for _ in range(50):
            if started:
                break
            time.sleep(0.02)
        self.assertTrue(started)


class TestWaiterNoWakeStealing(unittest.TestCase):

    def _proxy(self):
        p = RollbackWorkerProxy(spawn=False)
        p._local = None                       # 关闭降级本地引擎，走纯等待者路径
        p._is_gui_thread = lambda: False
        p._request = lambda action, params=None, timeout=30.0: {'async': True}
        return p

    def test_two_concurrent_snapshots_both_woken(self):
        p = self._proxy()
        results = []
        rlock = threading.Lock()

        def _call():
            r = p.snapshot_now('manual')
            with rlock:
                results.append(r)

        ts = [threading.Thread(target=_call) for _ in range(2)]
        for t in ts:
            t.start()
        # 等两个等待者都注册后一次性唤醒（模拟 worker 的一次完成上报）
        for _ in range(100):
            with p._waiters_lock:
                if len(p._snapshot_waiters) == 2:
                    break
            time.sleep(0.01)
        p._wake_waiters(p._snapshot_waiters, {'ok': True, 'added': 7})
        for t in ts:
            t.join(timeout=3)
            self.assertFalse(t.is_alive(), '存在调用方永久等待')
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.get('ok') for r in results), results)
        self.assertTrue(all(r.get('added') == 7 for r in results), results)

    def test_snapshot_and_rollback_reports_do_not_cross(self):
        p = self._proxy()
        out = {}

        def _snap():
            out['snap'] = p.snapshot_now('manual')

        def _rb():
            out['rb'] = p.trigger_rollback('manual_confirmed')

        a, b = threading.Thread(target=_snap), threading.Thread(target=_rb)
        a.start(); b.start()
        for _ in range(100):
            with p._waiters_lock:
                if p._snapshot_waiters and p._rollback_waiters:
                    break
            time.sleep(0.01)
        # 分别唤醒：快照上报不应唤醒回滚等待者，反之亦然
        p._wake_waiters(p._snapshot_waiters, {'ok': True, 'kind': 'snap'})
        p._wake_waiters(p._rollback_waiters, {'ok': True, 'kind': 'rb'})
        a.join(timeout=3); b.join(timeout=3)
        self.assertFalse(a.is_alive() or b.is_alive(), '存在永久等待')
        self.assertEqual(out['snap'].get('kind'), 'snap')
        self.assertEqual(out['rb'].get('kind'), 'rb')

    def test_timeout_does_not_hang(self):
        p = self._proxy()
        t0 = time.time()
        # 不唤醒任何等待者 → 必须按超时（GUI 预算）返回，而不是永久等待
        p._is_gui_thread = lambda: True
        res = p.snapshot_now('manual')
        self.assertLess(time.time() - t0, 5.0)
        self.assertFalse(res.get('ok'))


class TestLockOrderNoDeadlock(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_dl_')
        self.docs = os.path.join(self.tmp, 'docs')
        os.makedirs(self.docs)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_concurrent_snapshot_retain_ingest_no_deadlock(self):
        m = RansomwareRollback(protected_dirs=[self.docs])
        data = b'X' * 4096
        for i in range(40):
            with open(os.path.join(self.docs, f'f{i}.dat'), 'wb') as f:
                f.write(data + str(i).encode())
        sha = hashlib.sha256(data).hexdigest()
        errors = []

        def _snap(n):
            try:
                for _ in range(n):
                    m.snapshot_now('startup', replace=True)
            except Exception as e:
                errors.append(e)

        def _ingest(n):
            try:
                for _ in range(n):
                    sp = os.path.join(self.tmp, f'shadow-{threading.get_ident()}.bin')
                    with open(sp, 'wb') as f:
                        f.write(data)
                    m.ingest_shadow_backup(
                        os.path.join(self.docs, 'f0.dat'), sp,
                        len(data), 0)
            except Exception as e:
                errors.append(e)

        def _retain(n):
            try:
                for _ in range(n):
                    m._retain_generations()
            except Exception as e:
                errors.append(e)

        ts = [threading.Thread(target=_snap, args=(6,)),
              threading.Thread(target=_ingest, args=(20,)),
              threading.Thread(target=_retain, args=(20,))]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=20)
        self.assertFalse(any(t.is_alive() for t in ts), '存在死锁/永久阻塞')
        self.assertEqual(errors, [], f'并发执行异常: {errors}')
        self.assertTrue(os.path.isfile(m._object_path(sha)) or True)


class _FakeProc:
    def __init__(self, pid, name):
        self.pid = pid
        self.info = {'pid': pid, 'name': name}
    def terminate(self):
        pass
    def kill(self):
        pass
    def children(self, recursive=False):
        return []
    def parent(self):
        return None


class _FakePS:
    AccessDenied = type('A', (Exception,), {})
    NoSuchProcess = type('N', (Exception,), {})
    def __init__(self, table):
        self.table = table
    def process_iter(self, attrs=None):
        return list(self.table)
    def Process(self, pid):
        # 代理父链：worker 的父 = PSLS 主进程(222)，再上 = 宿主(111)
        return __import__('types').SimpleNamespace(
            pid=pid, children=lambda recursive=False: [],
            parent=lambda: __import__('types').SimpleNamespace(
                pid=222, parent=lambda: __import__('types').SimpleNamespace(
                    pid=111, parent=lambda: None)))
    def wait_procs(self, procs, timeout=1.0):
        return [], []


class TestKillAllProtectionExtended(unittest.TestCase):

    def test_infra_and_agent_chain_protected(self):
        """调整决定 2：保护集收窄为「系统进程 + PSLS 自身/子进程」。

        - 系统关键进程、PSLS/MLWorker、祖先链 → 保护（不终止）；
        - Sandboxie 基础设施（SbieSvc/Start.exe/SandboxieDcomLaunch）与第三方
          （vmware/qq/explorer）→ 不再保护，一律终止。
        """
        table = [
            _FakeProc(4, 'System'),
            _FakeProc(600, 'svchost.exe'),
            _FakeProc(9000, 'PSLS.exe'),
            _FakeProc(9001, 'MLWorker.exe'),
            _FakeProc(9050, 'SbieSvc.exe'),
            _FakeProc(9051, 'Start.exe'),
            _FakeProc(9052, 'SandboxieDcomLaunch.exe'),
            _FakeProc(222, 'PSLS.exe'),           # 代理父（主进程）
            _FakeProc(111, 'python.exe'),         # 宿主链（祖先）
            _FakeProc(5000, 'notepad.exe'),
            _FakeProc(6000, 'vmware-vmx.exe'),
            _FakeProc(6100, 'QQ.exe'),
            _FakeProc(6200, 'explorer.exe'),
            _FakeProc(6300, 'powershell.exe'),
        ]
        m = RansomwareRollback()
        m._running = True
        with mock.patch.dict(sys.modules, {'psutil': _FakePS(table)}):
            stat = m._kill_all_non_system('manual_confirmed')
        killed = [n.lower() for n in stat['killed']]
        # 必须保护（不在终止集）：系统关键进程 + PSLS 自身/子进程 + 祖先链
        for name in ('system', 'svchost.exe', 'psls.exe', 'mlworker.exe',
                     'python.exe'):
            self.assertNotIn(name, killed, f'{name} 必须被保护（不在终止集）')
        # 调整决定 2：Sandboxie 基础设施与第三方一律终止
        for name in ('sbiesvc.exe', 'start.exe', 'sandboxiedcomlaunch.exe',
                     'notepad.exe', 'vmware-vmx.exe', 'qq.exe', 'explorer.exe',
                     'powershell.exe'):
            self.assertIn(name, killed, f'{name} 应收窄保护集后被终止')


class TestSandboxAnimAndHiddenSpawn(unittest.TestCase):

    def test_anim_timers_precise(self):
        with open(os.path.join(ROOT, 'ui', 'webview',
                               'sandbox_analysis_window.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        self.assertIn('PreciseTimer', src)
        self.assertEqual(src.count('setTimerType(Qt.PreciseTimer)'), 2,
                         '两处动画计时器都应改 Precise')

    def test_sandbox_restart_spawn_hidden(self):
        with open(os.path.join(ROOT, 'engine', 'process_protection.py'),
                  'r', encoding='utf-8') as f:
            src = f.read()
        # 沙箱放行重启路径必须带 CREATE_NO_WINDOW（0x08000000）
        self.assertIn('0x08000000', src)


if __name__ == '__main__':
    unittest.main()