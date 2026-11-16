# -*- coding: utf-8 -*-
"""勒索回滚增强监测（大小变化 / 后缀名改变）单元测试。

覆盖：
  1. 大小变化维度：显著突变（清零/翻倍/腰斩）计入窗口信号并可触发预警；
     正常追加写入不过敏；
  2. 后缀名改变维度：改名强信号以更低阈值触发 on_prewarn / 确认（含边界）；
  3. 改名件复原：原路径写回原内容 + 残留件送隔离（含 .enc 及无加密后缀的同前缀件）。

不依赖 watchdog/驱动：直接调用 FileProtection 内部事件入口。
"""
import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engine.ransomware_rollback as rr
from engine.file_protection import (
    FileProtection, PREWARN_THRESHOLD, MASS_MODIFY_THRESHOLD,
    RENAME_PREWARN_THRESHOLD, RENAME_CONFIRM_THRESHOLD, SIZE_ABS_MIN,
)
from engine.ransomware_rollback import RansomwareRollback


class _FakeQuarantine:
    """轻量隔离管理器替身：把文件移动到隔离目录并记录调用。"""

    def __init__(self, qdir: str):
        self.qdir = qdir
        self.calls = []
        os.makedirs(qdir, exist_ok=True)

    def quarantine_file(self, path, reason='', malware_name='', **kwargs):
        self.calls.append((path, reason, malware_name))
        try:
            if not os.path.isfile(path):
                return False
            dst = os.path.join(self.qdir, os.path.basename(path) + '.q')
            shutil.move(path, dst)
            return True
        except Exception:
            return False

    def _unregister_soft_quarantine(self, path):
        pass


class TestEnhancedMonitor(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_enh_')
        self._old_root = rr._REPO_ROOT
        rr._REPO_ROOT = os.path.join(self.tmp, 'repo')
        os.makedirs(rr._REPO_ROOT, exist_ok=True)
        self.protected = os.path.join(self.tmp, 'docs')
        os.makedirs(self.protected, exist_ok=True)
        self.qm = _FakeQuarantine(os.path.join(self.tmp, 'quarantine'))

    def tearDown(self):
        rr._REPO_ROOT = self._old_root
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, data):
        p = os.path.join(self.protected, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    # ---- 1. 大小变化维度 ----

    def test_size_change_counts_into_window_and_triggers_prewarn(self):
        fp = FileProtection()
        prewarns = []
        confirms = []
        fp.on_prewarn = lambda files: prewarns.append(list(files))
        fp.on_ransomware_confirmed = lambda info: confirms.append(dict(info))

        # 3 个文件各先"正常出现"（记录初始大小），数量维度各记 1 次 = 3
        paths = [self._write(f'd{i}.txt', b'A' * 8192) for i in range(3)]
        for p in paths:
            fp._on_file_event(p, 'modified')
        self.assertEqual(len(prewarns), 0,
                         '仅 3 个文件不应触发预警（数量阈值 %d）' % PREWARN_THRESHOLD)
        self.assertEqual(len(fp._recent_size_changes), 0)

        # 逐个清零：每文件同时命中"数量维度"与"大小变化维度"
        for p in paths:
            with open(p, 'wb'):
                pass
            fp._on_file_event(p, 'modified')

        self.assertTrue(prewarns, '大小突变维度应计入窗口并触发预警')
        # 数量维度（3）本身不足阈值，说明是大小维度补齐了信号
        self.assertGreaterEqual(len(fp._recent_size_changes), 1)
        self.assertLess(len(paths), PREWARN_THRESHOLD)

    def test_normal_append_not_flagged(self):
        fp = FileProtection()
        p = self._write('append.txt', b'B' * 8192)
        fp._on_file_event(p, 'modified')          # 记录初始大小
        with open(p, 'ab') as f:
            f.write(b'C' * 512)                    # 正常追加少量字节
        fp._on_file_event(p, 'modified')
        self.assertEqual(len(fp._recent_size_changes), 0,
                         '正常追加写入不得被计为显著大小变化')

    def test_zeroing_below_abs_min_not_flagged(self):
        fp = FileProtection()
        p = self._write('tiny.txt', b'x' * 10)     # 小于 SIZE_ABS_MIN
        fp._on_file_event(p, 'modified')
        with open(p, 'wb'):
            pass
        fp._on_file_event(p, 'modified')
        self.assertEqual(len(fp._recent_size_changes), 0)

    # ---- 2. 后缀名改变（改名）强信号 ----

    def test_rename_triggers_prewarn_at_low_threshold(self):
        fp = FileProtection()
        prewarns = []
        confirms = []
        fp.on_prewarn = lambda files: prewarns.append(list(files))
        fp.on_ransomware_confirmed = lambda info: confirms.append(dict(info))

        a = self._write('a.docx', b'DOC-A')
        fp._on_file_renamed(a, a + '.locked')      # 第 1 次改名
        self.assertEqual(len(prewarns), 0, '1 次改名不应预警')

        b = self._write('b.docx', b'DOC-B')
        fp._on_file_renamed(b, b + '.enc')         # 第 2 次改名 → 预警边界
        self.assertTrue(prewarns, '改名强信号应在 %d 次即预警'
                        % RENAME_PREWARN_THRESHOLD)
        self.assertEqual(len(confirms), 0)
        self.assertLess(RENAME_PREWARN_THRESHOLD, PREWARN_THRESHOLD)

    def test_rename_triggers_confirm_at_lower_threshold(self):
        fp = FileProtection()
        confirms = []
        fp.on_ransomware_confirmed = lambda info: confirms.append(dict(info))

        for i in range(RENAME_CONFIRM_THRESHOLD):
            p = self._write(f'r{i}.docx', b'DOC-%d' % i)
            fp._on_file_renamed(p, p + '.locked')
        self.assertTrue(confirms, '改名强信号达到 %d 次应确认勒索'
                        % RENAME_CONFIRM_THRESHOLD)
        self.assertLess(RENAME_CONFIRM_THRESHOLD, MASS_MODIFY_THRESHOLD)

    def test_normal_rename_not_flagged(self):
        fp = FileProtection()
        a = self._write('note.txt', b'TEXT')
        b = os.path.join(self.protected, 'other.md')
        fp._on_file_renamed(a, b)   # 不同前缀、非加密后缀 → 非强信号
        self.assertEqual(len(fp._recent_renames), 0)

    def test_same_prefix_new_suffix_without_crypto_ext_flagged(self):
        fp = FileProtection()
        a = self._write('same.docx', b'DOC')
        fp._on_file_renamed(a, a + '.xyz')   # 同前缀新后缀（非加密后缀）→ 强信号
        self.assertEqual(len(fp._recent_renames), 1)

    # ---- 3. 改名件复原（原路径写回 + 残留送隔离）----

    def _mgr(self):
        return RansomwareRollback(quarantine_manager=self.qm,
                                  protected_dirs=[self.protected])

    def test_rollback_restores_renamed_and_quarantines_residual(self):
        m = self._mgr()
        p = self._write('a.docx', b'THE-ORIGINAL')
        m.snapshot_now('init')

        # 改成 .enc（不在 _ENCRYPTED_EXTS 但属于改名残留），写入加密内容
        os.replace(p, p + '.enc')
        with open(p + '.enc', 'wb') as f:
            f.write(b'ENCRYPTED')

        res = m.trigger_rollback('manual_confirmed')

        self.assertEqual(res['restored'], 1)
        self.assertTrue(os.path.isfile(p))
        with open(p, 'rb') as f:
            self.assertEqual(f.read(), b'THE-ORIGINAL')
        # 改名残留件被隔离（原位置消失 + 隔离管理器被调用）
        self.assertFalse(os.path.exists(p + '.enc'))
        self.assertTrue(any(c[0] == p + '.enc' for c in self.qm.calls))

    def test_rollback_quarantines_same_prefix_non_crypto_residual(self):
        m = self._mgr()
        p = self._write('same.docx', b'ORIG')
        m.snapshot_now('init')
        os.replace(p, p + '.xyz')      # 同前缀、无加密后缀的改名残留
        with open(p + '.xyz', 'wb') as f:
            f.write(b'JUNK')

        res = m.trigger_rollback('manual_confirmed')
        self.assertEqual(res['restored'], 1)
        self.assertFalse(os.path.exists(p + '.xyz'))
        self.assertTrue(any(c[0] == p + '.xyz' for c in self.qm.calls))


if __name__ == '__main__':
    unittest.main()