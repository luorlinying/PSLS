# -*- coding: utf-8 -*-
"""筛选接入 Elastic protections-artifacts 的 YARA 规则子集（可复现脚本）。

背景（评估报告第 ⑥ 部分 步骤 1）：
- 上游仓库 https://github.com/elastic/protections-artifacts 的 yara/rules/ 下
  有 1000+ 个 .yar，直接全量接入会带来大量误报与体积膨胀。
- 本脚本按下列条件筛选出"高置信、文件上下文、Windows"子集，落盘到
  rules/yara/elastic/（子目录 → 借由 rule_engine 的 namespace=相对路径 隔离，
  与现有 Rules_General_A1.yar / PSLS_AUTO_* 互不冲突）。

筛选条件：
  1) 平台：meta.os 含 windows 或 multi（排除 linux/macos）
  2) 上下文：meta.scan_context 含 file（排除仅 memory 的）
  3) 排除 condition 恰为 "any of them" 的单串规则（评估确认的误报来源）
  4) 排除噪声家族/类别（meta.threat_name 的类别段 ∈ {AttackSimulation,
     Joke, Prank, Debug}）——模拟/恶搞/调试类是误报高发区
     ★ 注意：Hacktool **不再按类别剔除**（调整决定 1）；改为"保留但强制
       severity→low"——其误报率偏高，降权而非丢弃，避免漏掉真实工具类威胁。
  5) 排除 condition 为 "any of them" / "1 of them" 且字符串数 <=2 的低熵规则
  6) 排除"全部字符串都很短（<=6 字节）"的规则（随机命中概率高）
  7) 保留 all of them / N of them 等高置信规则

强制降权（调整决定 1）：Hacktool 规则在**原样整块复制**的基础上，仅把其
meta.severity 改写为字符串 "low"（_force_low_severity），既不改写其它 meta、
也不改动规则逻辑；这一来源经 rule_engine.normalize_severity() 原样透传为
'low'（不影响其它规则的字符串/数值 severity 语义）。

剔除结果另存 rules/yara/elastic/EXCLUDED.txt（规则名 + 原因 + 证据），
--verify 会把上述 3-6 条一并作为断言校验（并额外断言 Hacktool 规则的
severity 已被强制为 low）。

许可合规：把上游 LICENSE.txt 一并落到 rules/yara/elastic/LICENSE.txt；
每条规则的 meta.license 原样保留（本脚本按"整块原样复制"实现，除按决定 1 把
Hacktool 的 meta.severity 强制改写为 "low" 外，不改写任何 meta）。

用法：
  python scripts/fetch_elastic_yara.py                # 下载 tar 包 → 筛选 → 落盘
  python scripts/fetch_elastic_yara.py --src DIR      # 用本地已解压目录（离线可复现）
  python scripts/fetch_elastic_yara.py --dry-run      # 只统计不写盘
  python scripts/fetch_elastic_yara.py --verify       # 校验已落盘目录是否符合筛选条件

注意：脚本不引入新依赖，仅用标准库（urllib/tarfile/re）。
"""

import os
import re
import sys
import io
import time
import json
import tarfile
import argparse
import urllib.request

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REPO = 'elastic/protections-artifacts'
REPO_REF = 'main'
TARBALL_URL = f'https://codeload.github.com/{REPO}/tar.gz/refs/heads/{REPO_REF}'
API_TREE_URL = f'https://api.github.com/repos/{REPO}/git/trees/{REPO_REF}?recursive=1'
RAW_BASE = f'https://raw.githubusercontent.com/{REPO}/{REPO_REF}/'

RULES_SUBPATH = 'yara/rules/'          # 上游规则目录（tar 内路径片段）
DEFAULT_OUT = os.path.join(_PROJECT_ROOT, 'rules', 'yara', 'elastic')
LICENSE_BASENAME = 'LICENSE.txt'
# tar 包本地缓存（避免重复下载；下载 flaky 时尤其有用）
_TARBALL_CACHE = os.path.join(os.environ.get('TEMP', _PROJECT_ROOT), 'elastic_pa_main.tar.gz')

# 顶层规则声明：rule / private rule / global rule
_RULE_HEAD_RE = re.compile(
    r'(?m)^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)[^{]*\{')
_META_LINE_RE = re.compile(r'^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.+?)[ \t]*$')

# ---- 误报启发式剔除参数（与落盘子集一一对应，--verify 会据此断言） ----
# 噪声家族/类别：取 meta.threat_name 的第 2 段（如 Windows.Joke.X → Joke）。
# 这些类别要么是攻击模拟、要么是恶搞/调试程序，在良性语料上误报概率高。
# 注意：Hacktool 已从该集合移除（调整决定 1）——改为"保留但强制 severity→low"。
_NOISE_CATEGORIES = {'AttackSimulation', 'Joke', 'Prank', 'Debug'}
# 强制降权类别：保留规则，但把 meta.severity 改写为字符串 "low"（Hacktool）。
_FORCE_LOW_CATEGORIES = {'Hacktool'}
# 短串阈值（字节）：一条规则的全部字符串都 <= 该长度时，随机命中概率高，剔除。
_SHORT_STRING_MAX = 6
# 低熵 condition：condition 为 any/1 of them 且字符串数 <= 该值时剔除。
_LOW_ENTROPY_COND_MAX_STRINGS = 2

# 需要落成 EXCLUDED.txt 的"误报高风险"剔除原因（不含常规 os/scan_context 淘汰）。
# EXCLUDED.txt 由本脚本自动生成，保证剔除可复现。
_FP_EXCLUDE_REASONS = ('noise_category', 'one_of_them_few', 'short_strings')
EXCLUDED_BASENAME = 'EXCLUDED.txt'


# ----------------------------------------------------------------------------
# 下载
# ----------------------------------------------------------------------------

def _http_get(url: str, timeout: int = 180, retries: int = 10) -> bytes:
    """带重试的 HTTP GET（网络较 flaky，失败退避重试）。失败抛异常。"""
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'psls-yara-fetch'})
            return urllib.request.urlopen(req, timeout=timeout).read()
        except Exception as e:  # noqa: BLE001 - 网络异常类型多，统一重试
            last = e
            time.sleep(min(2 + i, 6))
    raise RuntimeError(f'下载失败 {url}: {last}')


def _load_tarball_bytes(use_cache: bool = True) -> bytes:
    """获取上游 tar.gz 字节，优先读本地缓存。"""
    if use_cache and os.path.isfile(_TARBALL_CACHE) and os.path.getsize(_TARBALL_CACHE) > 0:
        with open(_TARBALL_CACHE, 'rb') as f:
            data = f.read()
        # 简单完整性校验：能被 tarfile 打开且含规则目录
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tf:
                if any(RULES_SUBPATH in n for n in tf.getnames()):
                    return data
        except Exception:
            pass  # 缓存损坏 → 重新下载
    data = _http_get(TARBALL_URL)
    try:
        with open(_TARBALL_CACHE, 'wb') as f:
            f.write(data)
    except Exception:
        pass
    return data


def fetch_sources_tarball(use_cache: bool = True):
    """从 tar.gz 抽取 {文件名: 文本} 与 LICENSE 文本。"""
    data = _load_tarball_bytes(use_cache=use_cache)
    sources, license_text = {}, None
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            if RULES_SUBPATH in m.name and m.name.endswith('.yar'):
                f = tf.extractfile(m)
                if f is None:
                    continue
                sources[os.path.basename(m.name)] = f.read().decode('utf-8', 'replace')
            elif m.name.endswith(LICENSE_BASENAME) and 'protections-artifacts' in m.name:
                f = tf.extractfile(m)
                if f is not None and license_text is None:
                    license_text = f.read().decode('utf-8', 'replace')
    return sources, license_text


def fetch_sources_api():
    """回退方案：用 GitHub API 列目录 + raw 逐个下载。"""
    tree = json.loads(_http_get(API_TREE_URL).decode('utf-8'))
    sources = {}
    for item in tree.get('tree', []):
        p = item.get('path', '')
        if p.startswith(RULES_SUBPATH) and p.endswith('.yar'):
            sources[os.path.basename(p)] = _http_get(RAW_BASE + p).decode('utf-8', 'replace')
    license_text = _http_get(RAW_BASE + LICENSE_BASENAME).decode('utf-8', 'replace')
    return sources, license_text


def load_sources_from_dir(src_dir: str):
    """从已解压的本地仓库目录读取（离线可复现）。"""
    rules_dir = os.path.join(src_dir, 'yara', 'rules')
    sources = {}
    for name in sorted(os.listdir(rules_dir)):
        full = os.path.join(rules_dir, name)
        if os.path.isfile(full) and name.endswith('.yar'):
            with open(full, 'r', encoding='utf-8', errors='replace') as f:
                sources[name] = f.read()
    license_text = None
    lic = os.path.join(src_dir, LICENSE_BASENAME)
    if os.path.isfile(lic):
        with open(lic, 'r', encoding='utf-8', errors='replace') as f:
            license_text = f.read()
    return sources, license_text


# ----------------------------------------------------------------------------
# 规则解析与筛选
# ----------------------------------------------------------------------------

def _find_matching_brace(text: str, open_idx: int) -> int:
    """返回与 text[open_idx]=='{' 匹配的 '}' 下标；找不到返回 -1。

    跳过字符串字面量与注释，避免被规则正文里的花括号/引号干扰。
    """
    depth = 0
    i = open_idx
    n = len(text)
    in_str = False
    quote = ''
    while i < n:
        c = text[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
            continue
        if c in ('"', "'"):
            in_str = True
            quote = c
            i += 1
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            j = text.find('\n', i)
            i = n if j == -1 else j
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            j = text.find('*/', i + 2)
            i = n if j == -1 else j + 2
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _parse_strings(inner: str):
    """解析 strings: 段，返回 [(kind, value)]。

    kind ∈ {'text', 'hex', 'regex', 'other'}：
      - text: 双引号文本串的内容（保留转义原文，长度近似其字节数）
      - hex : 大括号十六进制串，value 为去掉空白后的十六进制（长度/2 = 字节数）
      - regex: 正则串原文
    用于误报启发式（短串 / 低熵）判定，不做编译。
    """
    m = re.search(r'(?m)^[ \t]*strings[ \t]*:', inner)
    if not m:
        return []
    rest = inner[m.end():]
    stop = re.search(r'(?m)^[ \t]*(?:condition)[ \t]*:', rest)
    seg = rest[:stop.start()] if stop else rest
    out = []
    for line in seg.splitlines():
        s = line.strip()
        if not s or s.startswith('//') or s.startswith('/*') or s.startswith('*'):
            continue
        mm = re.match(r'^\$[A-Za-z0-9_]*\s*=\s*(.+)$', s)
        if not mm:
            continue
        val = mm.group(1).strip()
        if val.startswith('{'):
            end = val.find('}')
            hexpart = val[1:end if end != -1 else len(val)]
            out.append(('hex', re.sub(r'\s+', '', hexpart)))
        elif val.startswith('"'):
            buf = []
            j = 1
            while j < len(val):
                c = val[j]
                if c == '\\':
                    buf.append(val[j:j + 2])
                    j += 2
                    continue
                if c == '"':
                    break
                buf.append(c)
                j += 1
            out.append(('text', ''.join(buf)))
        elif val.startswith('/'):
            out.append(('regex', val))
        else:
            out.append(('other', val))
    return out


def _string_len(kind: str, value: str) -> int:
    """字符串长度（字节近似）：hex 串为十六进制长度/2，其余为字符数。"""
    if kind == 'hex':
        return len(value) // 2
    return len(value)


def _threat_category(meta: dict) -> str:
    """取 meta.threat_name 的家族类别段（第 2 段）。

    如 "Windows.Hacktool.ProcessHacker" → "Hacktool"；缺失 threat_name 返回 ''。
    """
    tn = str(meta.get('threat_name', '') or '').strip()
    parts = tn.split('.')
    return parts[1] if len(parts) > 1 else ''


# meta.severity 赋值行（仅出现在 meta 段内，逐规则块文本内匹配）
_SEVERITY_ASSIGN_RE = re.compile(r'(?m)^([ \t]*)severity[ \t]*=[ \t]*[^\r\n]*$')


def _force_low_severity(block: str) -> str:
    """把单条规则块的 meta.severity 改写为字符串 "low"（保留但强制降权）。

    仅改写 severity 一行，不动其它 meta / strings / condition；规则块若没有
    severity 行，则在 `meta:` 行后补一行。返回改写后的块文本。
    """
    text = str(block or '')
    new_line = r'\1severity = "low"'
    if _SEVERITY_ASSIGN_RE.search(text):
        return _SEVERITY_ASSIGN_RE.sub(new_line, text, count=1)
    # 无 severity 行 → 在 meta: 行后补一行（保持原有缩进风格）
    m = re.search(r'(?m)^([ \t]*)meta[ \t]*:[ \t]*$', text)
    if m:
        indent = m.group(1) + '    '
        return (text[:m.end()] + '\n' + indent + 'severity = "low"' + text[m.end():])
    return text


def parse_yara_rules(text: str):
    """把一段 .yar 文本拆成规则块列表。

    返回 [{name, header_before (首个 rule 之前的头部含 import), block (rule 原文),
            meta (dict), condition (str), strings ([(kind, value)])}]。
    """
    matches = list(_RULE_HEAD_RE.finditer(text))
    rules = []
    for idx, m in enumerate(matches):
        brace = text.find('{', m.start())
        end = _find_matching_brace(text, brace)
        if end == -1:
            continue
        block = text[m.start():end + 1]
        inner = text[brace + 1:end]
        # 头部（首个规则之前的 import/注释）只挂到第一条规则上，便于按文件聚合
        header = text[:m.start()] if idx == 0 else ''
        rules.append({
            'name': m.group(1),
            'header_before': header,
            'block': block,
            'meta': _parse_meta(inner),
            'condition': _parse_condition(inner),
            'strings': _parse_strings(inner),
        })
    return rules


def _parse_meta(inner: str) -> dict:
    """解析 meta: 段（到 strings:/condition: 为止）。"""
    meta = {}
    m = re.search(r'(?m)^[ \t]*meta[ \t]*:', inner)
    if not m:
        return meta
    rest = inner[m.end():]
    stop = re.search(r'(?m)^[ \t]*(?:strings|condition)[ \t]*:', rest)
    seg = rest[:stop.start()] if stop else rest
    for line in seg.splitlines():
        s = line.strip()
        if not s or s.startswith('//') or s.startswith('/*') or s.startswith('*'):
            continue
        mm = _META_LINE_RE.match(line)
        if not mm:
            continue
        key, val = mm.group(1), mm.group(2).strip()
        if (val.startswith('"') and val.endswith('"')) or \
           (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        meta[key] = val
    return meta


def _parse_condition(inner: str) -> str:
    """解析 condition: 段文本。"""
    m = re.search(r'(?m)^[ \t]*condition[ \t]*:', inner)
    if not m:
        return ''
    return inner[m.end():].strip()


def _norm_ws(s: str) -> str:
    return re.sub(r'\s+', ' ', s or '').strip().lower()


def should_keep(meta: dict, condition: str, strings=None):
    """按筛选条件判定单条规则是否保留。返回 (keep, reason)。

    strings 为 _parse_strings 的结果；为 None 时跳过依赖字符串的启发式
    （保持向后兼容：旧调用点/测试仍可只传 meta+condition）。
    """
    os_val = _norm_ws(meta.get('os', ''))
    ctx = _norm_ws(meta.get('scan_context', ''))
    cond = _norm_ws(condition)

    # 1) 平台：windows 或 multi；明确 linux/macos 排除；缺失平台信息也排除
    if ('windows' not in os_val) and ('multi' not in os_val):
        return False, 'os'
    # 2) 上下文：必须含 file
    if 'file' not in ctx:
        return False, 'scan_context'
    # 3) 排除 any of them 单串规则
    if cond == 'any of them':
        return False, 'any_of_them'
    # 4) 噪声家族/类别（攻击模拟 / 恶搞 / 调试）——误报高发区
    #    （Hacktool 不在此列：保留但强制 severity→low）
    if _threat_category(meta) in _NOISE_CATEGORIES:
        return False, 'noise_category'
    if strings is not None:
        n = len(strings)
        # 5) any of them / 1 of them 且字符串极少 → 等价随机命中
        if cond in ('any of them', '1 of them') and n <= _LOW_ENTROPY_COND_MAX_STRINGS:
            return False, 'one_of_them_few'
        # 6) 全部字符串都很短（<= 阈值）→ 随机命中概率高
        if n >= 1 and all(_string_len(k, v) <= _SHORT_STRING_MAX for k, v in strings):
            return False, 'short_strings'
    # 7) 保留其余（all of them / N of them 等高置信规则）
    return True, 'kept'


def build_subset(sources: dict):
    """执行筛选，返回 (out_files: {name: text}, stats: dict)。

    stats['excluded_detail'] 收集"误报高风险"剔除项（噪声类别 / 低熵 1-of-them /
    短串），用于落成 EXCLUDED.txt。
    """
    stats = {'files_total': len(sources), 'rules_total': 0,
             'drop_os': 0, 'drop_scan_context': 0, 'drop_any_of_them': 0,
             'drop_noise_category': 0, 'drop_one_of_them_few': 0,
             'drop_short_strings': 0, 'forced_low': 0,
             'kept': 0, 'files_written': 0, 'sev_dist_all': {}, 'sev_dist_kept': {}}
    excluded = []
    out_files = {}
    for name in sorted(sources):
        rules = parse_yara_rules(sources[name])
        if not rules:
            continue
        stats['rules_total'] += len(rules)
        header = rules[0]['header_before']
        kept_blocks = []
        for r in rules:
            sev = str(r['meta'].get('severity', '')).strip()
            if sev:
                stats['sev_dist_all'][sev] = stats['sev_dist_all'].get(sev, 0) + 1
            keep, reason = should_keep(r['meta'], r['condition'], r.get('strings'))
            if keep:
                stats['kept'] += 1
                block = r['block']
                # 强制降权（调整决定 1）：Hacktool 保留但 severity→low。
                # 归一化后的实际严重度以 'low' 计入统计。
                if _threat_category(r['meta']) in _FORCE_LOW_CATEGORIES:
                    block = _force_low_severity(block)
                    stats['forced_low'] += 1
                    sev = 'low'
                stats['sev_dist_kept'][sev] = stats['sev_dist_kept'].get(sev, 0) + 1
                kept_blocks.append(block)
            else:
                stats['drop_' + reason] = stats['drop_' + reason] + 1
                if reason in _FP_EXCLUDE_REASONS:
                    excluded.append({
                        'name': r['name'], 'file': name, 'reason': reason,
                        'threat_name': str(r['meta'].get('threat_name', '')),
                        'condition': _norm_ws(r['condition']),
                        'n_strings': len(r.get('strings') or []),
                    })
        if kept_blocks:
            text = header.rstrip() + '\n\n' + '\n\n'.join(kept_blocks) + '\n'
            out_files[name] = text
            stats['files_written'] += 1
    stats['excluded_detail'] = excluded
    return out_files, stats


# ----------------------------------------------------------------------------
# 落盘 / 校验
# ----------------------------------------------------------------------------

def _render_excluded(excluded: list) -> str:
    """把"误报高风险"剔除项渲染为 EXCLUDED.txt 文本（可复现）。"""
    lines = [
        '# Elastic YARA 子集 —— 误报高风险规则剔除清单（EXCLUDED）',
        '# 本文件由 scripts/fetch_elastic_yara.py 自动生成（可复现），请勿手工编辑。',
        '# 依据：',
        '#   1) 良性语料实测：Windows 系统/程序目录（System32/SysWOW64/Program Files/',
        '#      Microsoft.NET）共 3000 个文件，elastic 子集扫描命中 0；',
        '#   2) 启发式预筛：噪声家族/类别、低熵 any/1 of them（字符串<=2）、',
        '#      全部字符串过短（<=6 字节）——均为高误报形态。',
        '# 字段: <rule_name> | <reason> | <evidence>',
        '# reason ∈ {noise_category, one_of_them_few, short_strings}',
        '',
    ]
    for e in sorted(excluded, key=lambda x: x['name']):
        ev = (f'threat_name={e["threat_name"]}; condition="{e["condition"]}"; '
              f'n_strings={e["n_strings"]}; file={e["file"]}')
        lines.append(f'{e["name"]} | {e["reason"]} | {ev}')
    return '\n'.join(lines) + '\n'


def write_subset(out_dir: str, out_files: dict, license_text, excluded_detail=None):
    os.makedirs(out_dir, exist_ok=True)
    # 清理：删除本次不再产生的旧 .yar（整文件被剔除时必须同步移除，避免残留）
    for old in os.listdir(out_dir):
        if old.endswith('.yar') and old not in out_files:
            try:
                os.remove(os.path.join(out_dir, old))
            except OSError:
                pass
    total_rules = 0
    total_bytes = 0
    for name in sorted(out_files):
        p = os.path.join(out_dir, name)
        data = out_files[name].encode('utf-8')
        with open(p, 'wb') as f:
            f.write(data)
        total_rules += len(parse_yara_rules(out_files[name]))
        total_bytes += len(data)
    if license_text is not None:
        with open(os.path.join(out_dir, LICENSE_BASENAME), 'w', encoding='utf-8') as f:
            f.write(license_text)
    if excluded_detail is not None:
        with open(os.path.join(out_dir, EXCLUDED_BASENAME), 'w', encoding='utf-8') as f:
            f.write(_render_excluded(excluded_detail))
    return total_rules, total_bytes


def _load_excluded_names(out_dir: str) -> list:
    """读取 EXCLUDED.txt 中被剔除的规则名（去掉 # 头与空行）。"""
    p = os.path.join(out_dir, EXCLUDED_BASENAME)
    names = []
    if not os.path.isfile(p):
        return names
    with open(p, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            names.append(s.split('|')[0].strip())
    return names


def verify_subset(out_dir: str):
    """校验已落盘目录：每条规则满足筛选条件，且不命中任何剔除启发式。

    断言项：
      - 无 os 非 windows/multi、scan_context 缺 file、缺 meta.license；
      - condition 恰为 any of them；
      - condition 为 any/1 of them 且字符串数 <= _LOW_ENTROPY_COND_MAX_STRINGS；
      - 全部字符串 <= _SHORT_STRING_MAX 字节；
      - threat_name 类别 ∈ _NOISE_CATEGORIES；
      - threat_name 类别 ∈ _FORCE_LOW_CATEGORIES（Hacktool）时，severity 必须为 'low'；
      - EXCLUDED.txt 中列出的规则名不得出现在落盘目录；
      - LICENSE.txt 存在。
    """
    problems = []
    n_files = n_rules = 0
    excluded_names = set(_load_excluded_names(out_dir))
    present_names = set()
    for name in sorted(os.listdir(out_dir)):
        full = os.path.join(out_dir, name)
        if not os.path.isfile(full) or not name.endswith('.yar'):
            continue
        n_files += 1
        with open(full, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
        for r in parse_yara_rules(text):
            n_rules += 1
            present_names.add(r['name'])
            cond = _norm_ws(r['condition'])
            strings = r.get('strings') or []
            meta = r['meta']
            if cond == 'any of them':
                problems.append(f'{name}:{r["name"]} 含被排除的 any of them')
            if cond in ('any of them', '1 of them') and len(strings) <= _LOW_ENTROPY_COND_MAX_STRINGS:
                problems.append(
                    f'{name}:{r["name"]} 低熵 any/1 of them（字符串数={len(strings)}）')
            if strings and all(_string_len(k, v) <= _SHORT_STRING_MAX for k, v in strings):
                problems.append(f'{name}:{r["name"]} 全部字符串过短（<= {_SHORT_STRING_MAX} 字节）')
            if _threat_category(meta) in _NOISE_CATEGORIES:
                problems.append(
                    f'{name}:{r["name"]} 噪声类别 {meta.get("threat_name")!r}')
            # 强制降权（调整决定 1）：Hacktool 必须已把 severity 改写为 'low'
            if _threat_category(meta) in _FORCE_LOW_CATEGORIES:
                if _norm_ws(meta.get('severity', '')) != 'low':
                    problems.append(
                        f'{name}:{r["name"]} Hacktool severity 未被强制为 low'
                        f'（{meta.get("severity")!r}）')
            os_val = _norm_ws(meta.get('os', ''))
            if 'windows' not in os_val and 'multi' not in os_val:
                problems.append(f'{name}:{r["name"]} os 非 windows/multi ({meta.get("os")!r})')
            if 'file' not in _norm_ws(meta.get('scan_context', '')):
                problems.append(f'{name}:{r["name"]} scan_context 缺 file')
            if not meta.get('license'):
                problems.append(f'{name}:{r["name"]} 缺 meta.license')
    # EXCLUDED.txt 中的规则必须确实不在落盘目录
    leaked = sorted(excluded_names & present_names)
    for nm in leaked[:50]:
        problems.append(f'EXCLUDED 规则仍存在: {nm}')
    if not os.path.isfile(os.path.join(out_dir, LICENSE_BASENAME)):
        problems.append('缺少 LICENSE.txt')
    if not os.path.isfile(os.path.join(out_dir, EXCLUDED_BASENAME)):
        problems.append(f'缺少 {EXCLUDED_BASENAME}')
    return {'n_files': n_files, 'n_rules': n_rules, 'n_excluded': len(excluded_names),
            'problems': problems}


def _print_stats(stats: dict, n_rules_written: int, n_bytes: int, out_dir: str):
    print('=' * 66)
    print('Elastic YARA 子集筛选统计')
    print('-' * 66)
    print(f'  上游规则文件数        : {stats["files_total"]}')
    print(f'  上游规则条数          : {stats["rules_total"]}')
    print(f'  ├ 淘汰·os 非 win/multi : {stats["drop_os"]}')
    print(f'  ├ 淘汰·scan_context    : {stats["drop_scan_context"]}')
    print(f'  ├ 淘汰·any of them     : {stats["drop_any_of_them"]}')
    print(f'  ├ 淘汰·噪声类别        : {stats["drop_noise_category"]}')
    print(f'  ├ 淘汰·低熵 any/1 them : {stats["drop_one_of_them_few"]}')
    print(f'  └ 淘汰·短串(<=6B)      : {stats["drop_short_strings"]}')
    print(f'  误报高风险剔除数       : {len(stats.get("excluded_detail", []))}')
    print(f'  强制降权(Hacktool→low) : {stats.get("forced_low", 0)}')
    print(f'  入选规则条数          : {stats["kept"]}')
    print(f'  落盘文件数            : {stats["files_written"]}')
    print(f'  落盘规则条数(复核)    : {n_rules_written}')
    print(f'  落盘字节数            : {n_bytes}')
    print(f'  输出目录              : {out_dir}')
    print('-' * 66)
    print(f'  入选前 severity 分布 : {dict(sorted(stats["sev_dist_all"].items()))}')
    print(f'  入选后 severity 分布 : {dict(sorted(stats["sev_dist_kept"].items()))}')
    print('=' * 66)


def main():
    ap = argparse.ArgumentParser(description='筛选并落盘 Elastic protections-artifacts YARA 子集')
    ap.add_argument('--out', default=DEFAULT_OUT, help='输出目录')
    ap.add_argument('--src', default=None, help='本地已解压的仓库根目录（离线可复现）')
    ap.add_argument('--no-cache', action='store_true', help='忽略 tar 包本地缓存，强制重新下载')
    ap.add_argument('--dry-run', action='store_true', help='只统计不写盘')
    ap.add_argument('--verify', action='store_true', help='校验已落盘子集是否符合筛选条件')
    args = ap.parse_args()

    if args.verify:
        res = verify_subset(args.out)
        print(f'校验目录: {args.out}')
        print(f'  文件数={res["n_files"]} 规则数={res["n_rules"]} '
              f'EXCLUDED={res.get("n_excluded", 0)} 问题数={len(res["problems"])}')
        for p in res['problems'][:50]:
            print('  ✗', p)
        print('  ✅ 全部符合筛选条件' if not res['problems'] else '  ❌ 存在不符合项')
        return 0 if not res['problems'] else 1

    if args.src:
        sources, license_text = load_sources_from_dir(args.src)
        print(f'从本地目录读取: {args.src}')
    else:
        try:
            sources, license_text = fetch_sources_tarball(use_cache=not args.no_cache)
            print(f'从 GitHub tar 包读取: {TARBALL_URL}')
        except Exception as e:
            print(f'⚠️ tar 包下载失败（{e}），回退 GitHub API + raw ...')
            sources, license_text = fetch_sources_api()

    if not sources:
        print('❌ 未获取到任何 .yar 源文件')
        return 2

    out_files, stats = build_subset(sources)
    if args.dry_run:
        _print_stats(stats, sum(len(parse_yara_rules(t)) for t in out_files.values()), 0, '(dry-run)')
        return 0

    n_rules_written, n_bytes = write_subset(args.out, out_files, license_text,
                                            excluded_detail=stats.get('excluded_detail'))
    _print_stats(stats, n_rules_written, n_bytes, args.out)
    # 落盘后立即自校验
    res = verify_subset(args.out)
    print(f'落盘后自校验: 文件={res["n_files"]} 规则={res["n_rules"]} 问题={len(res["problems"])}')
    for p in res['problems'][:20]:
        print('  ✗', p)
    return 0 if not res['problems'] else 1


if __name__ == '__main__':
    sys.exit(main())