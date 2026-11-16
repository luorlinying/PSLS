# -*- coding: utf-8 -*-
"""三项现象回归：残留隔离有边界 / 0 文件世代秒级完成 / PSLS 目录只读可用。

实测（用户截图 2026-10-07）：
  1 手动回滚在 96%「正在隔离加密残留...」卡死，主窗口"未响应"
  2 快照 0 个文件时直接卡死
  3 应用启动后"占用 PSLS 目录下所有文件，拒绝其他进程读写/删除"
"""
import os
import sys
import time
import shutil
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback


class _Rec:
    """记录残留隔离过程中的进度/日志（断言"聚合"而非逐文件）。"""
    def __init__(self):
        self.progress = []
        self.audits = []

    def on_progress(self, p):
        self.progress.append((p.get('stage', ''), p.get('percent', 0),
                              p.get('text', '')))


class TestZeroFileGenerationFast(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_zero_')
        self.docs = os.path.join(self.tmp, 'docs')
        os.makedirs(self.docs)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_empty_generation_finishes_fast_without_walking(self):
        """0 文件世代：回滚秒级完成，且**不进入任何目录遍历**。"""
        m = RansomwareRollback(protected_dirs=[self.docs])
        # 造一个空世代（无任何条目）
        m.snapshot_now('startup', replace=True)
        with m._state_lock:
            m._generations[0]['entries'] = {}

        walked = []
        real_walk = os.walk

        def _spy_walk(top, *a, **k):
            walked.append(top)
            return real_walk(top, *a, **k)

        t0 = time.time()
        with mock.patch.object(rr.os, 'walk', _spy_walk):
            res = m.trigger_rollback('manual_confirmed')
        dt = time.time() - t0
        self.assertTrue(res.get('ok'))
        self.assertLess(dt, 3.0, f'0 文件世代回滚应秒级完成，实际 {dt:.2f}s')
        self.assertEqual(walked, [], '不得遍历任何目录')

    def test_zero_generation_logs_no_quarantine_needed(self):
        m = RansomwareRollback(protected_dirs=[self.docs])
        m.snapshot_now('startup', replace=True)
        with m._state_lock:
            m._generations[0]['entries'] = {}
        res = m._quarantine_residuals({})
        self.assertEqual(res, [])
        # 审计里不应出现"隔离残留(汇总)"（没有任何遍历/隔离发生）
        self.assertFalse(any('隔离残留(汇总)' in a.get('action', '')
                             for a in m.get_audit_log()))


class TestResidualQuarantineBounded(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_bnd_')
        self.docs = os.path.join(self.tmp, 'docs')
        os.makedirs(self.docs)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_big_dir(self, n=5000):
        d = os.path.join(self.docs, 'big')
        os.makedirs(d, exist_ok=True)
        for i in range(n):
            with open(os.path.join(d, f'f{i}.bin'), 'wb') as f:
                f.write(b'X')
        return d

    def test_scope_limited_to_entries_dirs(self):
        """只扫"清单条目所在目录"，不遍历无关目录。"""
        d = os.path.join(self.docs, 'work')
        os.makedirs(d, exist_ok=True)
        target = os.path.join(d, 'a.docx')
        with open(target, 'wb') as f:
            f.write(b'ORIG')
        m = RansomwareRollback(protected_dirs=[self.docs])
        m.snapshot_now('startup', replace=True)
        # 快照之后才出现的目录：其中没有任何清单条目 → 不属于本次受影响范围
        other = os.path.join(self.docs, 'unrelated')
        os.makedirs(other, exist_ok=True)
        with open(os.path.join(other, 'a.txt'), 'wb') as f:
            f.write(b'A')
        walked = []
        real_walk = os.walk

        def _spy(top, *a, **k):
            walked.append(os.path.normcase(os.path.abspath(top)))
            return real_walk(top, *a, **k)

        with mock.patch.object(rr.os, 'walk', _spy):
            m._quarantine_residuals(m._generations[0]['entries'])
        norm_other = os.path.normcase(os.path.abspath(other))
        self.assertNotIn(norm_other, walked, '不得遍历与本次无关的目录')

    def test_big_dir_respects_limits_and_progress_monotonic(self):
        """大目录（5000 文件）：受文件数/时间上限约束，进度单调推进。"""
        self._make_big_dir(5000)
        m = RansomwareRollback(protected_dirs=[self.docs],
                               on_progress=lambda p: None)
        m.snapshot_now('startup', replace=True)
        entries = m._generations[0]['entries']
        ev = []
        m._on_progress = lambda p: ev.append(p)

        # 收窄上限以便快速断言（仍走真实代码路径）
        with mock.patch.object(rr, '_QUARANTINE_MAX_FILES', 1200), \
                mock.patch.object(rr, '_QUARANTINE_MAX_SECONDS', 6.0):
            t0 = time.time()
            res = m._quarantine_residuals(entries)
            dt = time.time() - t0
        self.assertLess(dt, 8.0, f'受时间上限约束，实际 {dt:.2f}s')
        self.assertEqual(res, [], '大目录内无残留件时不应隔离任何文件')
        # 进度单调不减
        pcts = [p.get('percent', 0) for p in ev]
        self.assertEqual(pcts, sorted(pcts), pcts)
        self.assertTrue(any('已扫描' in p.get('text', '') for p in ev),
                        '应上报真实扫描进度')
        # 达到上限 → 有截断审计
        self.assertTrue(any('截断' in a.get('action', '') for a in m.get_audit_log()))

    def test_aggregated_logging_not_per_file(self):
        """日志聚合：隔离多件也只写一条"隔离残留(汇总)"，示例≤3。"""
        d = os.path.join(self.docs, 'work')
        os.makedirs(d, exist_ok=True)
        base = os.path.join(d, 'a.docx')
        with open(base, 'wb') as f:
            f.write(b'ORIG')
        m = RansomwareRollback(protected_dirs=[self.docs])
        m.snapshot_now('startup', replace=True)
        # 造 10 个"改名残留"（a.docx.locked / a.docx.enc ...）
        for i in range(10):
            with open(f'{base}.locked{i}', 'wb') as f:
                f.write(b'L')
        moved = []
        qm = mock.MagicMock()
        qm.quarantine_file.side_effect = lambda p, **k: (moved.append(p) or True)
        m._quarantine_manager = qm
        res = m._quarantine_residuals(m._generations[0]['entries'])
        self.assertEqual(len(res), 10)
        summaries = [a for a in m.get_audit_log()
                     if '隔离残留(汇总)' in a.get('action', '')]
        self.assertEqual(len(summaries), 1, '应只有一条聚合日志，而非逐文件')
        detail = summaries[0]['detail']
        self.assertIn('隔离 10', detail)
        # 示例不超过 3 个（detail 里只应出现 3 个文件名）
        self.assertLessEqual(detail.count('.locked'), 3)

    def test_main_thread_not_blocked_during_residual(self):
        """残留隔离期间主线程（模拟 GUI tick）不被长时间阻塞。"""
        self._make_big_dir(3000)
        m = RansomwareRollback(protected_dirs=[self.docs])
        m.snapshot_now('startup', replace=True)
        entries = m._generations[0]['entries']
        worst = [0.0]
        stop = threading.Event()

        def _gui_tick():
            while not stop.is_set():
                t0 = time.perf_counter()
                time.sleep(0.002)          # 模拟 GUI 空转
                worst[0] = max(worst[0], (time.perf_counter() - t0) * 1000)
        th = threading.Thread(target=_gui_tick, daemon=True)
        th.start()
        with mock.patch.object(rr, '_QUARANTINE_MAX_SECONDS', 3.0):
            m._quarantine_residuals(entries)
        stop.set()
        th.join(timeout=1)
        # 由残留扫描引起的单次"GUI tick"延迟应远小于"未响应"阈值(5s)
        self.assertLess(worst[0], 3000, f'GUI tick 最长阻塞 {worst[0]:.0f}ms')


class TestProtectedDirReadable(unittest.TestCase):
    """现象 3：PSLS 目录必须允许他进程**只读**；写/删仍拒（保护意图不变）。"""

    def test_driver_has_exempt_dir_and_read_not_blocked(self):
        src = open(os.path.join(ROOT, 'driver', 'src', 'filemon.c'),
                   'r', encoding='utf-8').read()
        # 不存在 IRP_MJ_READ 的拒绝（只读必须放行）
        self.assertNotIn('IRP_MJ_READ', src)
        # 豁免子树机制已实现并优先于受保护目录判定
        self.assertIn('g_ExemptDir', src)
        self.assertIn('FileMon_SetExemptDir', src)
        self.assertIn('return FALSE;', src.split('if (g_ExemptDir.Length != 0')[1][:400])
        # PSLS 全部进程放行（不再只看主进程 pid）
        self.assertIn('Protect_IsPslsPid(*pid)', src)

    def test_shared_header_exposes_exempt_ioctl(self):
        shared = open(os.path.join(ROOT, 'driver', 'include', 'psls_shared.h'),
                      'r', encoding='utf-8').read()
        self.assertIn('PSLS_IOCTL_SET_EXEMPT_DIR', shared)
        self.assertIn('0x03D', shared)
        # 不得与既有功能号冲突
        self.assertNotIn('SET_EXEMPT_DIR       CTL_CODE(FILE_DEVICE_PSLS, 0x037', shared)

    def test_bridge_and_selfprotection_wire_exempt_dir(self):
        br = open(os.path.join(ROOT, 'driver', 'bridge', 'psls_driver_bridge.py'),
                  'r', encoding='utf-8').read()
        self.assertIn('def set_exempt_dir', br)
        self.assertIn('IOCTL_SET_EXEMPT_DIR', br)
        sp = open(os.path.join(ROOT, 'engine', 'self_protection.py'),
                  'r', encoding='utf-8').read()
        self.assertIn("'Sandboxie'", sp)
        self.assertIn('set_exempt_dir', sp)

    def test_selfprotection_baseline_and_backup_use_shared_read(self):
        """自我保护基线与备份不得独占打开（只读共享）。"""
        sp = open(os.path.join(ROOT, 'engine', 'self_protection.py'),
                  'r', encoding='utf-8').read()
        self.assertNotIn("'r+b'", sp)
        self.assertNotIn('CreateFileW', sp)
        self.assertIn("open(file_path, 'rb')", sp)          # 哈希：只读共享
        self.assertIn('shutil.copy2(filepath, backup_file)', sp)  # 备份：共享读

    def test_installer_protected_dir_is_install_root_only(self):
        """安装目录保护范围只应是安装根（Sandboxie 通过豁免处理，非整盘）。"""
        sp = open(os.path.join(ROOT, 'engine', 'self_protection.py'),
                  'r', encoding='utf-8').read()
        self.assertIn('install_dir = _get_install_root()', sp)
        self.assertIn('bridge.set_protected_dir(install_dir)', sp)


if __name__ == '__main__':
    unittest.main()