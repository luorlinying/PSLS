# -*- coding: utf-8 -*-
"""Elastic YARA 子集接入 —— 服务评估报告第 ⑥ 部分 步骤 1-3 的回归测试。

覆盖：
  1) 子集落盘正确（无 linux/macos、无 any of them、LICENSE 与 meta.license 齐全）
  2) 子集能被 yara.compile 成功编译（无规则名冲突），编译缓存可加载
  3) severity 数值→high/medium/low 归一化生效，且字符串 severity 行为不变
  4) any of them 排除（含"混合文件不被整文件误删"边界）
  5) System32 取样误报统计（FP 在可接受范围）

测试不访问网络，仅依赖已落盘的 rules/yara/elastic/。
"""

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ELASTIC_DIR = os.path.join(ROOT, 'rules', 'yara', 'elastic')
BASELINE_DIR = os.path.join(ROOT, 'rules', 'yara')

try:
    import yara as _yara
    HAS_YARA = True
except Exception:
    _yara = None
    HAS_YARA = False

import scripts.fetch_elastic_yara as fe  # noqa: E402


def _iter_yara_files(directory):
    for name in sorted(os.listdir(directory)):
        if name.endswith('.yar'):
            yield name, os.path.join(directory, name)


def _read(path):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


class TestElasticSubsetLanded(unittest.TestCase):
    """步骤 1/3：子集落盘正确性（源码层断言）。"""

    def setUp(self):
        if not os.path.isdir(ELASTIC_DIR):
            self.skipTest('elastic 子集目录不存在，请先运行 scripts/fetch_elastic_yara.py')

    def test_dir_has_rules_and_license(self):
        yar_files = [n for n, _ in _iter_yara_files(ELASTIC_DIR)]
        self.assertGreater(len(yar_files), 100, 'elastic 子集规则文件数异常偏少')
        self.assertTrue(os.path.isfile(os.path.join(ELASTIC_DIR, 'LICENSE.txt')),
                        '必须随附 Elastic LICENSE.txt')

    def test_verify_subset_no_problems(self):
        """上游脚本自带的校验：无 linux/macos、无 any of them、meta.license 齐全。"""
        res = fe.verify_subset(ELASTIC_DIR)
        self.assertEqual([], res['problems'], f'落盘子集存在问题: {res["problems"][:10]}')
        # 决定 1（Hacktool 放回且强制 low）后的实测规模：741 文件 / 2004 规则 / 剔除 7 条
        self.assertEqual(res['n_files'], 741)
        self.assertEqual(res['n_rules'], 2004)
        self.assertEqual(res['n_excluded'], 7)

    def test_no_any_of_them_single_string_rules(self):
        """产物断言：落盘目录里不含 condition 恰为 'any of them' 的规则。"""
        bad = []
        total = 0
        for name, path in _iter_yara_files(ELASTIC_DIR):
            for r in fe.parse_yara_rules(_read(path)):
                total += 1
                if fe._norm_ws(r['condition']) == 'any of them':
                    bad.append(f'{name}:{r["name"]}')
        self.assertGreater(total, 1000)
        self.assertEqual([], bad, f'仍存在 any of them 规则: {bad[:5]}')

    def test_no_linux_macos_rules(self):
        bad = []
        for name, path in _iter_yara_files(ELASTIC_DIR):
            for r in fe.parse_yara_rules(_read(path)):
                os_val = fe._norm_ws(r['meta'].get('os', ''))
                if 'windows' not in os_val and 'multi' not in os_val:
                    bad.append(f'{name}:{r["name"]} os={r["meta"].get("os")!r}')
        self.assertEqual([], bad, f'存在非 windows/multi 规则: {bad[:5]}')

    def test_meta_license_preserved(self):
        """许可合规：每条规则 meta.license 未被删改（原样保留）。"""
        missing = []
        for name, path in _iter_yara_files(ELASTIC_DIR):
            for r in fe.parse_yara_rules(_read(path)):
                if not r['meta'].get('license'):
                    missing.append(f'{name}:{r["name"]}')
        self.assertEqual([], missing, f'缺失 meta.license 的规则: {missing[:5]}')


class TestElasticSubsetCompiles(unittest.TestCase):
    """步骤 1/2：编译通过（无规则名冲突），缓存可用。"""

    def setUp(self):
        if not HAS_YARA:
            self.skipTest('yara-python 不可用')
        if not os.path.isdir(ELASTIC_DIR):
            self.skipTest('elastic 子集目录不存在')

    def test_elastic_dir_compiles(self):
        filepaths = {f'elastic_{n}': p for n, p in _iter_yara_files(ELASTIC_DIR)}
        self.assertGreater(len(filepaths), 100)
        rules = _yara.compile(filepaths=filepaths)  # 抛异常即失败（含重名冲突）
        self.assertIsNotNone(rules)

    def test_full_rules_dir_compiles(self):
        """基线 + elastic 合并编译（与 rule_engine 的 namespace 方案一致）。"""
        filepaths = {}
        for root, _dirs, files in os.walk(BASELINE_DIR):
            for fn in files:
                if os.path.splitext(fn)[1].lower() in ('.yar', '.yara'):
                    fp = os.path.join(root, fn)
                    ns = os.path.relpath(fp, BASELINE_DIR).replace(os.sep, '_')
                    filepaths[ns] = fp
        self.assertIn('elastic_Windows_Trojan_CobaltStrike.yar', filepaths)
        rules = _yara.compile(filepaths=filepaths)
        self.assertIsNotNone(rules)

    def test_compiled_cache_loadable(self):
        """编译缓存（compiled.yc）存在且可 yara.load（线上启动走该路径）。"""
        cache = os.path.join(BASELINE_DIR, 'compiled.yc')
        if not os.path.isfile(cache) or os.path.getsize(cache) == 0:
            self.skipTest('compiled.yc 缓存不存在')
        rules = _yara.load(cache)
        self.assertIsNotNone(rules)


class TestSeverityNormalization(unittest.TestCase):
    """步骤 2：severity 数值→high/medium/low 归一化。"""

    def test_unit_mapping(self):
        from engine.rule_engine import normalize_severity as ns
        self.assertEqual('high', ns(100))
        self.assertEqual('high', ns(90))
        self.assertEqual('high', ns('99'))
        self.assertEqual('medium', ns(50))
        self.assertEqual('medium', ns(70))
        self.assertEqual('low', ns(10))
        self.assertEqual('low', ns(49))
        # 缺省值
        self.assertEqual('medium', ns(None))

    def test_string_severity_unchanged(self):
        """既有字符串 severity 行为不变（不得被改写）。"""
        from engine.rule_engine import normalize_severity as ns
        for s in ('high', 'medium', 'low', 'info', 'critical', 'High'):
            self.assertEqual(s, ns(s))

    def _compile_numeric_severity_rules(self, tmpdir):
        src = (
            'rule Sevm_High { meta: severity = 100  strings: $s = "PSLS_SEV_TEST_MARKER" '
            'condition: $s }\n'
            'rule Sevm_Med  { meta: severity = 50   strings: $s = "PSLS_SEV_TEST_MARKER" '
            'condition: $s }\n'
            'rule Sevm_Low  { meta: severity = 10   strings: $s = "PSLS_SEV_TEST_MARKER" '
            'condition: $s }\n'
            'rule Sevm_Str  { meta: severity = "info" strings: $s = "PSLS_SEV_TEST_MARKER" '
            'condition: $s }\n'
        )
        rp = os.path.join(tmpdir, 'sev.yar')
        with open(rp, 'w', encoding='utf-8') as f:
            f.write(src)
        return _yara.compile(filepaths={'sev': rp})

    def test_end_to_end_numeric_severity_maps_and_counts(self):
        """命中数值 severity 规则 → 分别计入 high/medium/low（等价 rule_high_count 上升）。"""
        if not HAS_YARA:
            self.skipTest('yara-python 不可用')
        from engine.rule_engine import RuleEngine
        with tempfile.TemporaryDirectory() as d:
            rules = self._compile_numeric_severity_rules(d)
            target = os.path.join(d, 'sample.bin')
            with open(target, 'wb') as f:
                f.write(b'\x00\x00PSLS_SEV_TEST_MARKER\x00\x00')
            # 走到 YARA meta 进入流水线的唯一入口
            matches = RuleEngine._match_rules_obj(None, rules, target, 'file')
        got = {m['rule_id']: m['severity'] for m in matches}
        self.assertEqual('high', got.get('yara_Sevm_High'))
        self.assertEqual('medium', got.get('yara_Sevm_Med'))
        self.assertEqual('low', got.get('yara_Sevm_Low'))
        # 字符串 severity 既有行为不变
        self.assertEqual('info', got.get('yara_Sevm_Str'))
        # 复刻 scan_engine 的计数表达式，证明"真正参与计分/告警"
        rule_high_count = sum(1 for m in matches if m.get('severity') == 'high')
        rule_med_count = sum(1 for m in matches if m.get('severity') == 'medium')
        rule_low_count = sum(1 for m in matches if m.get('severity') == 'low')
        self.assertGreaterEqual(rule_high_count, 1)
        self.assertGreaterEqual(rule_med_count, 1)
        self.assertGreaterEqual(rule_low_count, 1)

    def test_numeric_severity_string_form_maps(self):
        """meta 里写成带引号的数字串（'90'）也应映射为 high。"""
        if not HAS_YARA:
            self.skipTest('yara-python 不可用')
        from engine.rule_engine import RuleEngine
        with tempfile.TemporaryDirectory() as d:
            rp = os.path.join(d, 'sev2.yar')
            with open(rp, 'w', encoding='utf-8') as f:
                f.write('rule Sevm_S90 { meta: severity = "90" '
                        'strings: $s = "PSLS_SEV90_MARKER" condition: $s }\n')
            rules = _yara.compile(filepaths={'sev2': rp})
            target = os.path.join(d, 's2.bin')
            with open(target, 'wb') as f:
                f.write(b'PSLS_SEV90_MARKER')
            matches = RuleEngine._match_rules_obj(None, rules, target, 'file')
        self.assertEqual('high', matches[0]['severity'])


class TestAnyOfThemExclusionBoundary(unittest.TestCase):
    """步骤 3：any of them 排除逻辑，含"混合文件不整文件误删"边界。"""

    def test_mixed_file_keeps_only_qualifying_rules(self):
        # 真实 Elastic/YARA 规则 meta 为"一行一字段"，此处按同样格式构造
        src = (
            'import "pe"\n'
            'rule Mixed_KeepAll {\n'
            '    meta:\n'
            '        os = "windows"\n'
            '        scan_context = "file"\n'
            '        severity = 100\n'
            '    strings:\n'
            '        $a = "PSLS_MIX_KEEP_AA"\n'
            '        $b = "PSLS_MIX_KEEP_BB"\n'
            '    condition:\n'
            '        all of them\n'
            '}\n'
            'rule Mixed_DropAny {\n'
            '    meta:\n'
            '        os = "windows"\n'
            '        scan_context = "file"\n'
            '        severity = 100\n'
            '    strings:\n'
            '        $a = "CC"\n'
            '    condition:\n'
            '        any of them\n'
            '}\n'
        )
        out_files, stats = fe.build_subset({'mixed.yar': src})
        self.assertIn('mixed.yar', out_files, '混合文件不应被整文件删除')
        rules = fe.parse_yara_rules(out_files['mixed.yar'])
        names = [r['name'] for r in rules]
        self.assertIn('Mixed_KeepAll', names)
        self.assertNotIn('Mixed_DropAny', names)
        self.assertEqual(1, stats['drop_any_of_them'])
        # 头部 import 必须保留（否则 pe.* 规则无法编译）
        self.assertIn('import "pe"', out_files['mixed.yar'])

    def test_should_keep_reasons(self):
        keep, reason = fe.should_keep({'os': 'linux', 'scan_context': 'file'}, '$a')
        self.assertFalse(keep)
        self.assertEqual('os', reason)
        keep, reason = fe.should_keep({'os': 'windows', 'scan_context': 'memory'}, '$a')
        self.assertFalse(keep)
        self.assertEqual('scan_context', reason)
        keep, reason = fe.should_keep(
            {'os': 'windows', 'scan_context': 'file'}, 'any of them')
        self.assertFalse(keep)
        self.assertEqual('any_of_them', reason)
        keep, reason = fe.should_keep(
            {'os': 'Multi', 'scan_context': 'file, memory'}, '3 of them')
        self.assertTrue(keep)


class TestSystem32FalsePositives(unittest.TestCase):
    """步骤 3：System32 取样误报统计（FP 需在可接受范围）。"""

    # 可接受阈值：elastic 子集在取样中的误报率 ≤ 2%，且绝对数 ≤ 3。
    # 依据：300 个 System32 取样实测 elastic 命中 0；留少量余量容忍不同机器差异。
    FP_MAX_FILES = 3
    SAMPLE_MAX = 150

    def _sample_system32(self, limit):
        sys32 = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32')
        files = []
        for root, _dirs, names in os.walk(sys32):
            for n in names:
                if n.lower().endswith(('.dll', '.exe')):
                    files.append(os.path.join(root, n))
            if len(files) > 4000:
                break
        files = sorted(files)
        step = max(1, len(files) // limit)
        return files[::step][:limit]

    def test_elastic_fp_on_system32(self):
        if not HAS_YARA:
            self.skipTest('yara-python 不可用')
        if not os.path.isdir(ELASTIC_DIR):
            self.skipTest('elastic 子集目录不存在')
        samples = self._sample_system32(self.SAMPLE_MAX)
        if not samples:
            self.skipTest('无 System32 样本')
        rules = _yara.compile(
            filepaths={f'elastic_{n}': p for n, p in _iter_yara_files(ELASTIC_DIR)})
        fp_files = []
        fp_rules = {}
        for s in samples:
            try:
                ms = rules.match(filepath=s)
            except Exception:
                continue
            if ms:
                fp_files.append(os.path.basename(s))
                for m in ms:
                    fp_rules[str(m)] = fp_rules.get(str(m), 0) + 1
        self.assertLessEqual(
            len(fp_files), self.FP_MAX_FILES,
            f'elastic 子集 System32 误报过多: {len(fp_files)}/{len(samples)} 文件, '
            f'规则={fp_rules}')


class TestElasticFalsePositiveExclusions(unittest.TestCase):
    """任务B：误报高风险规则剔除的最终产物断言（EXCLUDED.txt 可复现）。"""

    def setUp(self):
        if not os.path.isdir(ELASTIC_DIR):
            self.skipTest('elastic 子集目录不存在')

    def _excluded_names(self):
        return fe._load_excluded_names(ELASTIC_DIR)

    def test_excluded_txt_present_and_reasons_valid(self):
        p = os.path.join(ELASTIC_DIR, 'EXCLUDED.txt')
        self.assertTrue(os.path.isfile(p), '必须落盘 EXCLUDED.txt')
        names = self._excluded_names()
        self.assertEqual(7, len(names), '剔除清单条数与实测不符')
        reasons = {}
        with open(p, 'r', encoding='utf-8') as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith('#'):
                    continue
                parts = s.split('|')
                self.assertGreaterEqual(len(parts), 3, f'EXCLUDED.txt 行格式错误: {s}')
                r = parts[1].strip()
                reasons[r] = reasons.get(r, 0) + 1
        # 剔除原因仅限三类启发式
        for r in reasons:
            self.assertIn(r, ('noise_category', 'one_of_them_few', 'short_strings'))

    def test_excluded_absent_from_landed_dir(self):
        """EXCLUDED.txt 列出的规则不得出现在落盘目录（源码层）。"""
        excluded = set(self._excluded_names())
        present = set()
        for name, path in _iter_yara_files(ELASTIC_DIR):
            for r in fe.parse_yara_rules(_read(path)):
                present.add(r['name'])
        leaked = sorted(excluded & present)
        self.assertEqual([], leaked[:5], f'EXCLUDED 规则仍在落盘目录: {leaked[:5]}')

    def test_excluded_absent_from_compiled_cache(self):
        """编译结果（compiled.yc）不得包含被剔除规则名。"""
        cache = os.path.join(BASELINE_DIR, 'compiled.yc')
        if not os.path.isfile(cache) or os.path.getsize(cache) == 0:
            self.skipTest('compiled.yc 缓存不存在')
        with open(cache, 'rb') as f:
            blob = f.read()
        leaked = [n for n in self._excluded_names() if n.encode('utf-8') in blob]
        self.assertEqual([], leaked[:5], f'编译缓存仍含被剔除规则: {leaked[:5]}')
        # 抽样确认缓存确实包含保留规则，证明"字节包含"检测方法有效
        self.assertIn(b'Windows_VulnDriver_Zuhaowan', blob)

    def test_heuristic_forms_absent(self):
        """落盘目录不应再含任何启发式误报形态（独立于 verify_subset 的复核）。"""
        bad = []
        for name, path in _iter_yara_files(ELASTIC_DIR):
            for r in fe.parse_yara_rules(_read(path)):
                meta, cond = r['meta'], fe._norm_ws(r['condition'])
                strs = r.get('strings') or []
                if fe._threat_category(meta) in fe._NOISE_CATEGORIES:
                    bad.append((name, r['name'], 'noise'))
                if cond in ('any of them', '1 of them') and len(strs) <= 2:
                    bad.append((name, r['name'], 'low_entropy'))
                if strs and all(fe._string_len(k, v) <= 6 for k, v in strs):
                    bad.append((name, r['name'], 'short'))
        self.assertEqual([], bad, f'仍有误报形态规则: {bad[:5]}')

    def test_should_keep_new_reasons(self):
        """新启发式 reason 的单元行为（含边界：3 串 1-of-them 应保留）。"""
        # 决定 1：Hacktool 不再按类别剔除 → keep=True（由 build_subset 强制 severity→low）
        keep, reason = fe.should_keep(
            {'os': 'windows', 'scan_context': 'file',
             'threat_name': 'Windows.Hacktool.Mimikatz'}, 'all of them')
        self.assertTrue(keep)
        self.assertEqual('kept', reason)
        # 其余噪声类别仍剔除
        keep, reason = fe.should_keep(
            {'os': 'windows', 'scan_context': 'file',
             'threat_name': 'Windows.Joke.Prank'}, 'all of them')
        self.assertFalse(keep)
        self.assertEqual('noise_category', reason)

        keep, reason = fe.should_keep(
            {'os': 'windows', 'scan_context': 'file'}, '1 of them', [('hex', 'AABBCC')])
        self.assertFalse(keep)
        self.assertEqual('one_of_them_few', reason)

        keep, reason = fe.should_keep(
            {'os': 'windows', 'scan_context': 'file'}, 'all of them',
            [('hex', 'AABBCCDD'), ('hex', '11223344')])
        self.assertFalse(keep)
        self.assertEqual('short_strings', reason)

        keep, reason = fe.should_keep(
            {'os': 'windows', 'scan_context': 'file'}, 'all of them',
            [('hex', 'AABBCCDDEEFF00112233'), ('text', 'some_long_distinctive_string')])
        self.assertTrue(keep)
        self.assertEqual('kept', reason)

        keep, reason = fe.should_keep(
            {'os': 'windows', 'scan_context': 'file'}, '1 of them',
            [('hex', 'AABBCCDDEEFF0011'), ('hex', '0F1E2D3C4B5A6978'),
             ('hex', '9988776655443322')])
        self.assertTrue(keep)

    def test_verify_subset_flags_new_heuristics(self):
        """--verify 断言：噪声类别 + 短串目录应被判为不符合（新条件并入断言）。"""
        src = (
            'rule NoiseJoke {\n'
            '    meta:\n'
            '        os = "windows"\n'
            '        scan_context = "file"\n'
            '        threat_name = "Windows.Joke.Noise"\n'
            '        license = "Elastic License v2"\n'
            '    strings:\n'
            '        $a = "AAAA"\n'
            '    condition:\n'
            '        all of them\n'
            '}\n'
        )
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'n.yar'), 'w', encoding='utf-8') as f:
                f.write(src)
            with open(os.path.join(d, 'EXCLUDED.txt'), 'w', encoding='utf-8') as f:
                f.write('# (empty)\n')
            with open(os.path.join(d, 'LICENSE.txt'), 'w', encoding='utf-8') as f:
                f.write('x')
            res = fe.verify_subset(d)
        joined = ' '.join(res['problems'])
        self.assertIn('噪声类别', joined)
        self.assertIn('过短', joined)

    def test_verify_subset_flags_hacktool_not_low(self):
        """--verify 断言：Hacktool 规则 severity 未被强制为 low → 判为不符合。"""
        src = (
            'rule HackNotLow {\n'
            '    meta:\n'
            '        os = "windows"\n'
            '        scan_context = "file"\n'
            '        threat_name = "Windows.Hacktool.Noise"\n'
            '        license = "Elastic License v2"\n'
            '        severity = 100\n'
            '    strings:\n'
            '        $a = "PSLS_HACKTOOL_LONG_DISTINCTIVE_STRING"\n'
            '    condition:\n'
            '        all of them\n'
            '}\n'
        )
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'n.yar'), 'w', encoding='utf-8') as f:
                f.write(src)
            with open(os.path.join(d, 'EXCLUDED.txt'), 'w', encoding='utf-8') as f:
                f.write('# (empty)\n')
            with open(os.path.join(d, 'LICENSE.txt'), 'w', encoding='utf-8') as f:
                f.write('x')
            res = fe.verify_subset(d)
        joined = ' '.join(res['problems'])
        self.assertIn('Hacktool severity 未被强制为 low', joined)

    def test_force_low_severity_rewrites_only_severity(self):
        """_force_low_severity 只改 severity 一行，不动其它 meta/strings/condition。"""
        block = (
            'rule R {\n'
            '    meta:\n'
            '        os = "windows"\n'
            '        severity = 100\n'
            '        license = "Elastic License v2"\n'
            '    strings:\n'
            '        $a = "PSLS_FORCE_LOW_MARKER"\n'
            '    condition:\n'
            '        all of them\n'
            '}\n'
        )
        out = fe._force_low_severity(block)
        self.assertIn('severity = "low"', out)
        self.assertNotIn('severity = 100', out)
        self.assertIn('license = "Elastic License v2"', out)
        self.assertIn('$a = "PSLS_FORCE_LOW_MARKER"', out)
        # 无 severity 行时在 meta: 后补一行
        block2 = ('rule R2 {\n    meta:\n        os = "windows"\n'
                  '    strings:\n        $a = "PSLS_XLONG_STRING_ABC"\n'
                  '    condition:\n        all of them\n}\n')
        out2 = fe._force_low_severity(block2)
        self.assertIn('severity = "low"', out2)


class TestHacktoolRestored(unittest.TestCase):
    """决定 1：Hacktool 规则放回且权重强制为 low。"""

    def setUp(self):
        if not os.path.isdir(ELASTIC_DIR):
            self.skipTest('elastic 子集目录不存在')

    def test_hacktool_present_in_set(self):
        names, sevs = [], {}
        for name, path in _iter_yara_files(ELASTIC_DIR):
            for r in fe.parse_yara_rules(_read(path)):
                if fe._threat_category(r['meta']) == 'Hacktool':
                    names.append(r['name'])
                    sevs[fe._norm_ws(r['meta'].get('severity', ''))] = \
                        sevs.get(fe._norm_ws(r['meta'].get('severity', '')), 0) + 1
        self.assertEqual(102, len(names), '放回的 Hacktool 规则数应为 102')
        self.assertEqual({'low': 102}, sevs, 'Hacktool 规则 severity 必须全部为 low')

    def test_hacktool_not_in_excluded(self):
        excluded = set(fe._load_excluded_names(ELASTIC_DIR))
        self.assertFalse(any('Hacktool' in n for n in excluded),
                         'EXCLUDED.txt 不应再列 Hacktool 规则')

    def test_hacktool_normalized_to_low(self):
        from engine.rule_engine import normalize_severity
        self.assertEqual('low', normalize_severity('low'))
        self.assertEqual('low', normalize_severity(10))  # 其它规则数值行为不变
        self.assertEqual('high', normalize_severity(100))

    def test_verify_passes(self):
        res = fe.verify_subset(ELASTIC_DIR)
        self.assertEqual([], res['problems'][:10])
        self.assertEqual(102, res['n_rules'] - 1902)


if __name__ == '__main__':
    unittest.main()