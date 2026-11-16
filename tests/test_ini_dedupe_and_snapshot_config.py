# -*- coding: utf-8 -*-
"""四项修复回归：ini 幂等写入 / 影子日志去重 / reload+startup 去重 / 单文件上限可配置。

日志证据（psls_logs_20261007_175710.log）：
  #2 `Sandboxie 配置写入未生效（读回 AutoRecover='n\\nn'），已停用后续写入`
  #3 每 10s 一条活动日志 `写前影子备份已启用（已下发世代 1）`（世代没变也记）
  #6 重启后 `[reload]` 全量(hashed 1930) 后 15s `[startup]` 又全量
  #4 `too_large 6`（64MB 上限不可配）
"""
import os
import sys
import json
import time
import shutil
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine.sandbox_analyzer as sa
import engine.ransomware_rollback as rr
from engine.ransomware_rollback import RansomwareRollback
import ui.webview.bridge as bmod


class TestIniIdempotentWrite(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_ini_')
        self.ini = os.path.join(self.tmp, 'Sandboxie.ini')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, text, enc='utf-8', bom=False):
        data = text.encode(enc)
        if bom:
            data = (b'\xff\xfe' if enc == 'utf-16-le' else b'\xef\xbb\xbf') + data
        with open(self.ini, 'wb') as f:
            f.write(data)

    def _text(self):
        t, enc, bom = sa._read_ini_text(self.ini)
        return t, enc, bom

    def test_existing_key_replaced_single_line(self):
        self._write('[PSLS_Analysis]\r\nAutoRecover=y\r\nOther=1\r\n')
        self.assertTrue(sa._write_ini_file(self.ini, 'PSLS_Analysis', 'AutoRecover', 'n'))
        t, _e, _b = self._text()
        vals = sa._ini_get_values(t, 'PSLS_Analysis', 'AutoRecover')
        self.assertEqual(vals, ['n'], f'应只有一行且值正确，实际 {vals}')
        self.assertIn('Other=1', t)
        self.assertIn('\r\n', t, 'CRLF 行尾应保留')

    def test_duplicate_lines_collapse_to_one(self):
        """实测缺陷形态：同 key 两行 → 收敛为一行。"""
        self._write('[PSLS_Analysis]\r\nAutoRecover=n\r\nAutoRecover=n\r\n')
        self.assertTrue(sa._write_ini_file(self.ini, 'PSLS_Analysis', 'AutoRecover', 'n'))
        t, _e, _b = self._text()
        vals = sa._ini_get_values(t, 'PSLS_Analysis', 'AutoRecover')
        self.assertEqual(vals, ['n'], f'应收敛为一行，实际 {vals}')
        self.assertEqual(t.count('AutoRecover='), 1)

    def test_missing_key_appended_to_section(self):
        self._write('[PSLS_Analysis]\r\nRecoverFolder=\r\n\r\n[Other]\r\nX=1\r\n')
        self.assertTrue(sa._write_ini_file(self.ini, 'PSLS_Analysis',
                                          'AutoRecover', 'n'))
        t, _e, _b = self._text()
        self.assertEqual(sa._ini_get_values(t, 'PSLS_Analysis', 'AutoRecover'), ['n'])
        # 不得污染其它段
        self.assertNotIn('AutoRecover', t.split('[Other]')[1])

    def test_missing_section_created(self):
        self._write('[Other]\r\nX=1\r\n')
        self.assertTrue(sa._write_ini_file(self.ini, 'PSLS_Analysis',
                                          'AutoRecover', 'n'))
        t, _e, _b = self._text()
        self.assertEqual(sa._ini_get_values(t, 'PSLS_Analysis', 'AutoRecover'), ['n'])
        self.assertIn('[Other]', t)

    def test_encoding_and_bom_preserved(self):
        self._write('[PSLS_Analysis]\r\nAutoRecover=y\r\n', enc='utf-16-le', bom=True)
        self.assertTrue(sa._write_ini_file(self.ini, 'PSLS_Analysis',
                                          'AutoRecover', 'n'))
        with open(self.ini, 'rb') as f:
            raw = f.read()
        self.assertTrue(raw.startswith(b'\xff\xfe'), 'UTF-16LE BOM 应保留')
        t, enc, bom = self._text()
        self.assertEqual(enc, 'utf-16-le')
        self.assertEqual(sa._ini_get_values(t, 'PSLS_Analysis', 'AutoRecover'), ['n'])

    def test_trailing_comment_and_spaces_not_misjudged(self):
        self._write('[PSLS_Analysis]\r\nAutoRecover = "n"  ; keep off\r\n')
        t, _e, _b = self._text()
        vals = sa._ini_get_values(t, 'PSLS_Analysis', 'AutoRecover')
        self.assertEqual([sa._ini_norm_value(v) for v in vals], ['n'],
                         '行尾注释/引号/空格差异不应误判')

    def test_write_verifies_and_retries_then_blocks(self):
        """读回不一致 → 有限重试；仍失败才降级停写且日志明确（含 section/key/期望/实际）。"""
        sa._SBIE_INI_WRITE_BLOCKED = False
        calls = []

        def _fake_run(cmd, **kw):
            calls.append(list(cmd))
            return mock.MagicMock(stdout='y')          # 永远读回旧值

        try:
            with mock.patch.object(sa.subprocess, 'run', side_effect=_fake_run), \
                    mock.patch.object(sa, '_sbie_ini_file_candidates', return_value=[]), \
                    mock.patch.object(sa.time, 'sleep'), \
                    mock.patch.object(sa.logger, 'warning') as w:
                ok = sa._write_sbie_setting('SbieIni.exe', 'PSLS_Analysis',
                                            'AutoRecover', 'n')
            self.assertFalse(ok)
            self.assertTrue(sa._SBIE_INI_WRITE_BLOCKED, '重试仍失败 → 降级停写')
            msg = ' '.join(str(c) for c in w.call_args_list)
            for frag in ('section=PSLS_Analysis', 'key=AutoRecover',
                         '期望', '实际', '管理员'):
                self.assertIn(frag, msg, f'降级日志应含 {frag}')
            sets = [c for c in calls if len(c) > 1 and c[1] == 'set']
            self.assertGreaterEqual(len(sets), 2, '应有重试（>=2 次 set）')
        finally:
            sa._SBIE_INI_WRITE_BLOCKED = False

    def test_successful_write_does_not_block(self):
        sa._SBIE_INI_WRITE_BLOCKED = False
        self._write('[PSLS_Analysis]\r\n')
        with mock.patch.object(sa, '_sbie_ini_file_candidates',
                               return_value=[self.ini]), \
                mock.patch.object(sa.subprocess, 'run',
                                  return_value=mock.MagicMock(stdout='n')):
            ok = sa._write_sbie_setting('SbieIni.exe', 'PSLS_Analysis',
                                        'AutoRecover', 'n')
        self.assertTrue(ok)
        self.assertFalse(sa._SBIE_INI_WRITE_BLOCKED, '成功不得停写')

    def test_writes_allowed_keeps_non_admin_guard(self):
        """既有语义保留：非管理员不写（避免 SBIE2322 刷屏）；
        而"读回校验失败"不再一次停写（见 test_write_verifies_and_retries_then_blocks）。"""
        sa._SBIE_INI_WRITE_BLOCKED = False
        with mock.patch.object(sa, '_is_elevated', return_value=False):
            self.assertFalse(sa._sbie_ini_writes_allowed(),
                             '非管理员应保持"不写"（既有语义）')
        self.assertTrue(sa._SBIE_INI_WRITE_BLOCKED)
        sa._SBIE_INI_WRITE_BLOCKED = False


class _FakeActivityBridge:
    """只测 _log_shadow_state 的行为，不依赖 Qt。"""


class TestShadowLogDedupe(unittest.TestCase):

    def _bridge(self):
        b = bmod.PyBridge.__new__(bmod.PyBridge)
        b._acts = []
        b._add_activity = lambda *a, **k: b._acts.append(a)
        b._shadow_state_logged = None
        return b

    class _RB:
        def __init__(self):
            self.is_enabled = True
            self.generation_id = 1

    def test_no_activity_when_unchanged(self):
        b = self._bridge()
        rb = self._RB()
        b._rollback_manager = rb
        b._log_shadow_state(force=False)          # 首次变化 → 记一条
        self.assertEqual(len(b._acts), 1)
        for _ in range(5):                        # 模拟每 10s 的周期调用
            b._log_shadow_state(force=False)
        self.assertEqual(len(b._acts), 1, '世代/开关未变时不得重复写活动日志')

    def test_activity_when_generation_changes(self):
        b = self._bridge()
        rb = self._RB()
        b._rollback_manager = rb
        b._log_shadow_state(force=False)
        rb.generation_id = 2
        b._log_shadow_state(force=False)
        self.assertEqual(len(b._acts), 2, '世代变化应记一条')
        rb.is_enabled = False
        b._log_shadow_state(force=False)
        self.assertEqual(len(b._acts), 3, '开关变化应记一条')

    def test_force_records_for_user_toggle(self):
        b = self._bridge()
        b._rollback_manager = self._RB()
        b._log_shadow_state(force=False)
        b._log_shadow_state(force=True)           # 用户切换 → 始终记录
        self.assertEqual(len(b._acts), 2)


class TestReloadStartupDedupe(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_dedup_')
        self.docs = os.path.join(self.tmp, 'docs')
        os.makedirs(self.docs)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        for i in range(20):
            with open(os.path.join(self.docs, f'f{i}.txt'), 'wb') as f:
                f.write(b'x' * 64)

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_reload_then_startup_no_rehash_and_new_generation(self):
        """reload 后的 startup：**世代仍新建**、内容靠继承不重复哈希（hashed=0）。"""
        m = RansomwareRollback(protected_dirs=[self.docs])
        r1 = m.snapshot_now('reload', replace=False)
        self.assertGreater(r1.get('total', 0), 0)
        gens_before = len(m.get_generations())
        r2 = m.snapshot_now('startup', replace=True)
        self.assertEqual(r2.get('hashed'), 0, '不得重新全量哈希（继承短路）')
        self.assertEqual(len(m.get_generations()), gens_before + 1,
                         '世代该建还建（语义不变）')
        self.assertEqual(m.get_generations()[0]['file_count'], r1.get('total'))

    def test_reload_deduped_when_recent(self):
        """reload 在窗口期内、配置未变 → 跳过重复全量（本次报告的冗余那次）。"""
        m = RansomwareRollback(protected_dirs=[self.docs])
        r1 = m.snapshot_now('reload', replace=False)
        self.assertGreater(r1.get('total', 0), 0)
        r2 = m.snapshot_now('reload', replace=False)
        self.assertEqual(r2.get('skipped'), 'recent_identical')
        self.assertEqual(r2.get('hashed'), 0)

    def test_config_change_forces_full_snapshot(self):
        m = RansomwareRollback(protected_dirs=[self.docs])
        m.snapshot_now('reload', replace=False)
        # 配置变了（新增目录）→ 不得跳过
        extra = os.path.join(self.tmp, 'more')
        os.makedirs(extra, exist_ok=True)
        with open(os.path.join(extra, 'g.txt'), 'wb') as f:
            f.write(b'y')
        m.set_protected_dirs([self.docs, extra])
        r = m.snapshot_now('reload', replace=False)
        self.assertNotEqual(r.get('skipped'), 'recent_identical',
                            '配置变化后应正常执行')

    def test_manual_never_skipped(self):
        m = RansomwareRollback(protected_dirs=[self.docs])
        m.snapshot_now('reload', replace=False)
        r = m.snapshot_now('manual', replace=True)
        self.assertNotEqual(r.get('skipped'), 'recent_identical',
                            '手动快照永不跳过')


class TestMaxFileBytesConfigurable(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_max_')
        self.docs = os.path.join(self.tmp, 'docs')
        os.makedirs(self.docs)
        self._old = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        self.big = os.path.join(self.docs, 'big.bin')
        with open(self.big, 'wb') as f:
            f.write(b'z' * (2 * 1024 * 1024))     # 2MB

    def tearDown(self):
        rr._REPO_ROOT = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_default_is_64mb(self):
        self.assertEqual(rr._DEFAULT_MAX_FILE_BYTES, 64 * 1024 ** 2)
        m = RansomwareRollback(protected_dirs=[self.docs])
        self.assertEqual(m._max_file_bytes, 64 * 1024 ** 2)

    def test_env_override_and_zero_means_unlimited(self):
        # 默认值不变
        self.assertEqual(rr._MAX_FILE_BYTES, 64 * 1024 ** 2)
        # 实例级覆盖（等价于环境变量解析后的值）
        m = RansomwareRollback(protected_dirs=[self.docs], max_file_bytes=1)
        r = m.snapshot_now('startup', replace=True)
        self.assertEqual(r.get('too_large'), 1, '1 字节上限 → 2MB 文件应被跳过')
        # 0 = 不限制
        m2 = RansomwareRollback(protected_dirs=[self.docs], max_file_bytes=0)
        r2 = m2.snapshot_now('startup', replace=True)
        self.assertEqual(r2.get('too_large'), 0, '0 应表示不限制')
        self.assertGreaterEqual(r2.get('total', 0), 1)

    def test_env_var_name_and_limit_logged(self):
        src = open(os.path.join(ROOT, 'engine', 'ransomware_rollback.py'),
                   'r', encoding='utf-8').read()
        self.assertIn('PSLS_ROLLBACK_MAX_FILE_MB', src)
        self.assertIn('快照单文件上限 = ', src, '应输出当前上限便于排查')


if __name__ == '__main__':
    unittest.main()