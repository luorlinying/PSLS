# -*- coding: utf-8 -*-
"""
YARA 规则自动生成器

给定恶意软件样本（PE / 脚本 / 通用文件），提取对套壳、加壳、轻微修改
不敏感的不变特征，生成可直接被 yara-python 编译匹配的 YARA 规则。

设计原则：
1. 特征数量：至少 3 个才生成规则，避免过短误报；最多 8 个，避免过严漏报
2. 特征类型优先级：导入 API 序列 > 节区特征 > C2/硬编码字符串 > 字节签名
3. 每个规则至少包含 1 个"结构性特征"（API/节区）和 1 个"内容性特征"（字符串/字节）
4. 自动命名格式：PSLS_AUTO_<hash12>_<文件类型>
"""

import os
import sys
import re
import struct
import hashlib
import string
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# 允许直接执行 `python engine/yara_generator.py`
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from utils.logger import get_logger

logger = get_logger('yara_generator')

# 安全阈值
_MIN_FEATURES = 3
_MAX_FEATURES = 8
_MIN_BYTESTR_LEN = 6
_MAX_BYTESTR_LEN = 64
_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB 以上跳过（太费时）

# 通用 YARA 黑名单（过泛化的常见字符串）
_GENERIC_BLACKLIST = {
    'microsoft', 'windows', 'system32', 'program files', 'users', 'programdata',
    'localhost', '127.0.0.1', 'http://', 'https://', '.com', '.exe', '.dll',
    'kernel32', 'user32', 'gdi32', 'advapi32', 'ntdll', 'msvcrt', 'shell32',
    'ole32', 'oleaut32', 'urlmon', 'wininet', 'wintrust', 'crypt32',
    'CreateFileW', 'CreateFileA', 'WriteFile', 'ReadFile', 'CloseHandle',
    'GetModuleHandle', 'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW',
    'Sleep', 'GetTickCount', 'GetLastError', 'SetLastError',
}


def _safe_name(s: str) -> str:
    """把任意字符串清洗成合法的 YARA 标识符（[a-zA-Z_][a-zA-Z0-9_]*）。"""
    out = re.sub(r'[^a-zA-Z0-9_]', '_', s)
    if out and out[0].isdigit():
        out = '_' + out
    return out or 'unnamed'


def _hex_escape(data: bytes) -> str:
    """把 bytes 转成 YARA 十六进制字节串格式：{ AA BB CC }。"""
    return '{ ' + ' '.join(f'{b:02X}' for b in data) + ' }'


def _yara_str(s: str) -> str:
    """把任意字符串转为合法的 YARA 双引号字符串字面量（含外层引号）。

    YARA 字符串字面量不允许原始换行 / 控制字符（'unexpected end of file,
    expecting text string' 即由未转义的 \\r\\n 造成）。转义规则：
      \\ → \\\\   " → \\"   \\t → \\t   \\n → \\n   \\r → \\r
    其余控制字符 → \\xNN；非 ASCII 原样保留（UTF-8 字节在 YARA 合法）。
    """
    out = []
    for ch in s:
        o = ord(ch)
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '\t':
            out.append('\\t')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif o < 0x20:
            out.append(f'\\x{o:02X}')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def _ascii_escape(s: str) -> str:
    """把字符串转成 YARA ASCII 字符串字面量（完整转义，防控制字符破坏规则）。"""
    return _yara_str(s)


class YaraGenerator:
    """YARA 规则自动生成器。"""

    def __init__(self):
        self._pe = None
        try:
            import pefile
            self._pe = pefile
        except ImportError:
            logger.warning('pefile 未安装，PE 特征提取将受限')

    # ------------------------------------------------------------------ #
    #  对外主接口                                                         #
    # ------------------------------------------------------------------ #

    def generate(self, file_path: str, sha256: str = '',
                name: str = '', sample_type: str = 'unknown',
                severity: str = 'high') -> Optional[Dict]:
        """为单个样本生成 YARA 规则。

        Returns:
            字典包含 rule_name / rule_content / feature_count / sample_type / sha256，
            或 None（特征不足 / 文件过大 / 解析失败）。
        """
        if not file_path or not os.path.isfile(file_path):
            return None
        file_size = os.path.getsize(file_path)
        if file_size > _MAX_FILE_SIZE:
            logger.debug(f'YARA 生成跳过超大文件: {file_path} ({file_size} bytes)')
            return None

        if not sha256:
            try:
                with open(file_path, 'rb') as f:
                    sha256 = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                sha256 = '0' * 64

        file_ext = os.path.splitext(file_path)[1].lower()
        features: List[Dict] = []

        # 1. PE 特征（如果是 PE 文件）
        is_pe = self._is_pe(file_path)
        pe_features: List[Dict] = []
        if is_pe and self._pe:
            try:
                pe_features = self._extract_pe_features(file_path)
            except Exception as e:
                logger.debug(f'PE 特征提取失败 {file_path}: {e}')
                pe_features = []

        # 2. 字节级/通用特征（字符串 + 硬编码字节）
        generic_features = self._extract_generic_features(file_path)

        # 3. 合并并去重
        features = pe_features + generic_features
        features = self._dedupe_features(features)

        # 4. 挑选 Top N 特征
        features = self._rank_and_trim(features)

        if len(features) < _MIN_FEATURES:
            logger.debug(f'YARA 生成跳过（特征不足 {len(features)}/{_MIN_FEATURES}）: {file_path}')
            return None

        # 5. 生成规则名
        sample_type = pe_features and 'pe' or (file_ext.lstrip('.') or 'bin')
        short_hash = sha256[:12]
        rule_base = _safe_name(name) if name else _safe_name(os.path.basename(file_path))
        rule_name = f'PSLS_AUTO_{short_hash}_{sample_type}'

        # 6. 组装规则
        rule_content = self._assemble_rule(
            rule_name=rule_name,
            features=features,
            sha256=sha256,
            name=name or os.path.basename(file_path),
            file_path=file_path,
            file_size=file_size,
            severity=severity,
            sample_type=sample_type,
        )

        return {
            'rule_name': rule_name,
            'rule_content': rule_content,
            'feature_count': len(features),
            'sample_type': sample_type,
            'sha256': sha256,
            'file_size': file_size,
        }

    def generate_from_bytes(self, data: bytes, sha256: str = '',
                            name: str = '', sample_type: str = 'unknown',
                            severity: str = 'high') -> Optional[Dict]:
        """从内存 bytes 直接生成（供沙箱/扫描引擎调用，无需落盘）。"""
        if len(data) > _MAX_FILE_SIZE:
            return None
        if not sha256:
            sha256 = hashlib.sha256(data).hexdigest()

        features: List[Dict] = []
        pe_features: List[Dict] = []
        if self._is_pe_bytes(data) and self._pe:
            try:
                pe_features = self._extract_pe_features_from_bytes(data)
            except Exception:
                pass

        generic_features = self._extract_generic_features_from_bytes(data)
        features = pe_features + generic_features
        features = self._dedupe_features(features)
        features = self._rank_and_trim(features)

        if len(features) < _MIN_FEATURES:
            return None

        sample_type = pe_features and 'pe' or sample_type
        short_hash = sha256[:12]
        rule_name = f'PSLS_AUTO_{short_hash}_{sample_type}'

        rule_content = self._assemble_rule(
            rule_name=rule_name,
            features=features,
            sha256=sha256,
            name=name or 'memory_sample',
            file_path='<memory>',
            file_size=len(data),
            severity=severity,
            sample_type=sample_type,
        )

        return {
            'rule_name': rule_name,
            'rule_content': rule_content,
            'feature_count': len(features),
            'sample_type': sample_type,
            'sha256': sha256,
            'file_size': len(data),
        }

    def generate_hash_rule(self, sha256: str = '', name: str = '',
                           severity: str = 'high',
                           sample_type: str = 'unknown') -> Optional[Dict]:
        """在源文件缺失时，仅凭 SHA-256 生成一条哈希匹配的 YARA 规则。

        当病毒源文件已被删除、无法提取内容特征时，仍能生成一条按 SHA-256
        精确匹配的 YARA 规则（无需源文件内容），保证重复导入 / 回填时
        也能正常产出 YARA 规则。

        Returns:
            字典包含 rule_name / rule_content / feature_count / sample_type / sha256，
            或 None（sha256 无效）。
        """
        if not sha256:
            sha256 = '0' * 64
        if set(sha256) == {'0'}:
            logger.debug('YARA 哈希规则生成跳过（无效 sha256）')
            return None

        short_hash = sha256[:12]
        sample_type = sample_type or 'unknown'
        rule_name = f'PSLS_AUTO_{short_hash}_hash'
        clean_name = (name or 'unknown').replace('"', "'")[:80]

        rule_content = (
            'import "hash"\n'
            '\n'
            f'rule {rule_name} : hash generic\n'
            '{\n'
            '    meta:\n'
            '        author = "PSLS Auto-Generator"\n'
            f'        description = "Hash-based rule for {clean_name} (source file unavailable)"\n'
            f'        sha256 = "{sha256}"\n'
            f'        severity = "{severity}"\n'
            f'        sample_type = "{sample_type}"\n'
            '    condition:\n'
            f'        hash.sha256(0, filesize) == "{sha256}"\n'
            '}\n'
        )

        # ---- 自检：当前 yara 若未启用 hash 模块，则丢弃该规则 ----
        # rule_engine 会把 DB 内所有规则拼接后一次性编译，任何一条无法编译的
        # 规则都会导致整批 YARA 匹配失效。因此这里在生成时即验证可编译性，
        # 不可用（无 hash 模块）时返回 None，避免把坏规则写入数据库。
        try:
            import yara
            yara.compile(source=rule_content)
        except Exception as e:
            logger.debug(f'YARA hash 规则未能编译（hash 模块不可用），跳过 {short_hash}: {e}')
            return None

        return {
            'rule_name': rule_name,
            'rule_content': rule_content,
            'feature_count': 1,
            'sample_type': sample_type,
            'sha256': sha256,
            'file_size': 0,
        }

    # ------------------------------------------------------------------ #
    #  PE 特征提取                                                         #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_pe(file_path: str) -> bool:
        try:
            with open(file_path, 'rb') as f:
                head = f.read(2)
                return head == b'MZ'
        except Exception:
            return False

    @staticmethod
    def _is_pe_bytes(data: bytes) -> bool:
        return len(data) >= 2 and data[:2] == b'MZ'

    def _extract_pe_features(self, file_path: str) -> List[Dict]:
        try:
            pe = self._pe.PE(file_path, fast_load=False)
        except Exception as e:
            logger.debug(f'pefile 解析失败 {file_path}: {e}')
            return []
        try:
            return self._build_pe_features(pe)
        finally:
            try:
                pe.close()
            except Exception:
                pass

    def _extract_pe_features_from_bytes(self, data: bytes) -> List[Dict]:
        try:
            pe = self._pe.PE(data=data, fast_load=False)
            try:
                return self._build_pe_features(pe)
            finally:
                try:
                    pe.close()
                except Exception:
                    pass
        except Exception:
            return []

    def _build_pe_features(self, pe) -> List[Dict]:
        feats: List[Dict] = []

        # --- 导入 API 序列（dll!api），最多取前 15 个 ---
        try:
            api_calls: List[str] = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = (entry.dll or b'').decode(errors='ignore').lower()
                    for imp in entry.imports:
                        name = ''
                        if imp.name:
                            name = imp.name.decode(errors='ignore')
                        if not name:
                            name = f'ord{imp.ordinal}'
                        api_calls.append(f'{dll}!{name}')
            # 过滤掉过于泛化的
            api_calls = [a for a in api_calls
                         if a.split('!', 1)[1].lower() not in _GENERIC_BLACKLIST]
            # 取前 15 个，去重保持顺序
            seen = set()
            api_calls = [a for a in api_calls
                         if not (a in seen or seen.add(a))]
            for api in api_calls[:15]:
                feats.append({
                    'type': 'api_import',
                    'label': 'imports',
                    'value': api,
                    'yara': f'$api_{len(feats):02d} = {_yara_str(api)} ascii',
                    'priority': 10,
                })
        except Exception:
            pass

        # --- 节区名特征（取前 6 个非标准节区，标准节区 .text/.data/.rdata/.rsrc/.reloc 跳过）---
        try:
            standard_sections = {'.text', '.data', '.rdata', '.rsrc', '.reloc',
                                 '.pdata', '.idata', '.edata', '.tls', '.debug',
                                 '.bss', '.idlsym'}
            for s in pe.sections:
                name = s.Name.rstrip(b'\x00').decode(errors='ignore')
                if not name or name.lower() in standard_sections:
                    continue
                feats.append({
                    'type': 'section_name',
                    'label': 'sections',
                    'value': name,
                    'yara': f'$sec_{len(feats):02d} = "{name}" ascii',
                    'priority': 8,
                })
                if len([f for f in feats if f['type'] == 'section_name']) >= 6:
                    break
        except Exception:
            pass

        # --- 资源类型特征 ---
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                RESOURCE_TYPES = {
                    1: 'RT_CURSOR', 2: 'RT_BITMAP', 3: 'RT_ICON', 4: 'RT_MENU',
                    5: 'RT_DIALOG', 6: 'RT_STRING', 9: 'RT_ACCELERATOR',
                    10: 'RT_RCDATA', 11: 'RT_MESSAGETABLE', 16: 'RT_VERSION',
                    24: 'RT_MANIFEST',
                }
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    rid = entry.struct.Id
                    rname = RESOURCE_TYPES.get(rid, f'RT_{rid}')
                    feats.append({
                        'type': 'resource',
                        'label': 'resources',
                        'value': rname,
                        'yara': f'$res_{len(feats):02d} = {_yara_str(rname)} ascii',
                        'priority': 6,
                    })
        except Exception:
            pass

        # --- 编译时间戳（异常的远古时间戳 1970/2100+ 加进去）---
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            if ts == 0 or ts > 4102444800 or ts < 86400:
                feats.append({
                    'type': 'timestamp',
                    'label': 'timestamp',
                    'value': str(ts),
                    'yara': f'$ts_00 = {{ {struct.pack("<I", ts).hex().upper()} }}',
                    'priority': 7,
                })
        except Exception:
            pass

        return feats

    # ------------------------------------------------------------------ #
    #  通用 / 字节级特征提取                                                #
    # ------------------------------------------------------------------ #

    _URL_RE = re.compile(rb'https?://[^\x00-\x20"\'<>]{6,80}', re.I)
    _IP_RE = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    _REG_RE = re.compile(
        rb'(?i)(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)'
        rb'[^\x00]{2,80}'
    )
    _CMD_RE = re.compile(
        rb'(?i)(powershell|cmd\.exe|certutil|bitsadmin|mshta|wscript|cscript)'
        rb'[^\x00]{0,60}'
    )
    _DANGER_API = [
        b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread',
        b'NtUnmapViewOfSection', b'ZwUnmapViewOfSection',
        b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent',
        b'CreateToolhelp32Snapshot', b'Module32First',
        b'SetWindowsHookEx', b'CallNextHookEx',
        b'ShellExecuteA', b'ShellExecuteW',
        b'WinExec', b'LoadLibraryA', b'LoadLibraryW',
        b'CreateServiceA', b'CreateServiceW',
        b'RegSetValueExA', b'RegSetValueExW',
        b'SchTasksCreate', b'ITaskService',
    ]

    def _extract_generic_features(self, file_path: str) -> List[Dict]:
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception:
            return []
        return self._extract_generic_features_from_bytes(data)

    def _extract_generic_features_from_bytes(self, data: bytes) -> List[Dict]:
        feats: List[Dict] = []

        # URL
        seen_urls = set()
        for m in self._URL_RE.finditer(data):
            raw = m.group(0)
            if len(raw) > 80:
                continue
            if raw.lower() in seen_urls:
                continue
            seen_urls.add(raw.lower())
            decoded = raw.decode(errors='ignore')
            if any(bad in decoded.lower() for bad in _GENERIC_BLACKLIST):
                continue
            feats.append({
                'type': 'url',
                'label': 'urls',
                'value': decoded,
                'yara': f'$url_{len(feats):02d} = {_ascii_escape(decoded)}',
                'priority': 12,
            })
            if len(seen_urls) >= 5:
                break

        # IP
        seen_ips = set()
        for m in self._IP_RE.finditer(data):
            ip = m.group(0)
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            parts = ip.split(b'.')
            if any(int(p) > 255 for p in parts):
                continue
            feats.append({
                'type': 'ip',
                'label': 'ips',
                'value': ip.decode(),
                'yara': f'$ip_{len(feats):02d} = {_ascii_escape(ip.decode())}',
                'priority': 9,
            })
            if len(seen_ips) >= 3:
                break

        # 注册表路径
        seen_regs = set()
        for m in self._REG_RE.finditer(data):
            raw = m.group(0)
            if raw in seen_regs:
                continue
            seen_regs.add(raw)
            if len(raw) > 80:
                continue
            decoded = raw.decode(errors='ignore')
            # 过滤过于通用的
            if decoded.count('\\') < 2:
                continue
            feats.append({
                'type': 'registry',
                'label': 'registry',
                'value': decoded,
                'yara': f'$reg_{len(feats):02d} = {_ascii_escape(decoded)}',
                'priority': 8,
            })
            if len(seen_regs) >= 3:
                break

        # 危险命令行/解释器
        seen_cmds = set()
        for m in self._CMD_RE.finditer(data):
            raw = m.group(0)
            key = raw[:40].lower()
            if key in seen_cmds:
                continue
            seen_cmds.add(key)
            decoded = raw[:60].decode(errors='ignore')
            feats.append({
                'type': 'cmd',
                'label': 'commands',
                'value': decoded,
                'yara': f'$cmd_{len(feats):02d} = {_ascii_escape(decoded)}',
                'priority': 11,
            })
            if len(seen_cmds) >= 4:
                break

        # 危险 API 名称（独立出现时）
        for api in self._DANGER_API:
            if api in data:
                decoded = api.decode()
                feats.append({
                    'type': 'danger_api',
                    'label': 'danger_apis',
                    'value': decoded,
                    'yara': f'$dapi_{len(feats):02d} = {_ascii_escape(decoded)}',
                    'priority': 5,
                })

        # 硬编码字节块：连续非零、非低熵字节序列
        if len(data) > 256:
            byte_feats = self._extract_byte_signatures(data)
            feats.extend(byte_feats)

        return feats

    def _extract_byte_signatures(self, data: bytes) -> List[Dict]:
        """提取文件中的高置信度字节签名（连续 8~24 字节非零块）。"""
        feats: List[Dict] = []
        # 扫描窗口
        i = 0
        max_samples = 4
        while i < len(data) - _MIN_BYTESTR_LEN and len(feats) < max_samples:
            # 找连续非零段
            j = i
            while j < len(data) and data[j] != 0 and j - i < _MAX_BYTESTR_LEN:
                j += 1
            blen = j - i
            if _MIN_BYTESTR_LEN <= blen <= _MAX_BYTESTR_LEN:
                chunk = data[i:j]
                # 跳过全可打印 ASCII（太泛化）
                printable_count = sum(1 for b in chunk if 32 <= b < 127)
                if printable_count >= blen * 0.7:
                    i = j
                    continue
                # 计算熵，熵太低说明是重复模式，跳过
                if self._entropy(chunk) < 3.0:
                    i = j
                    continue
                # 转 YARA 格式（过长的截断到 24 字节）
                take = min(blen, 24)
                chunk_short = data[i:i + take]
                feats.append({
                    'type': 'bytes',
                    'label': 'byte_sigs',
                    'value': chunk_short.hex(),
                    'yara': f'$byte_{len(feats):02d} = {_hex_escape(chunk_short)}',
                    'priority': 4,
                })
                i = j
            else:
                i += 1
        return feats

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        from collections import Counter
        import math
        counts = Counter(data)
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    # ------------------------------------------------------------------ #
    #  特征挑选 & 组装                                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _dedupe_features(features: List[Dict]) -> List[Dict]:
        seen = set()
        out = []
        for f in features:
            key = (f.get('type'), f.get('value'))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    @staticmethod
    def _rank_and_trim(features: List[Dict]) -> List[Dict]:
        """按 priority 降序 + 类型多样性挑选 Top N 特征。"""
        features.sort(key=lambda f: -f.get('priority', 0))
        picked: List[Dict] = []
        picked_types: set = set()
        # 第一轮：每种类型至少取 1 个
        for f in features:
            t = f['type']
            if t not in picked_types:
                picked.append(f)
                picked_types.add(t)
                if len(picked) >= _MAX_FEATURES:
                    break
        # 第二轮：按优先级继续填
        for f in features:
            if f in picked:
                continue
            picked.append(f)
            if len(picked) >= _MAX_FEATURES:
                break
        return picked

    def _assemble_rule(self, rule_name: str, features: List[Dict],
                       sha256: str, name: str, file_path: str,
                       file_size: int, severity: str,
                       sample_type: str) -> str:
        """把挑选好的特征组装成完整的 YARA 规则字符串。"""
        def _ys(val) -> str:
            """YARA meta 字符串内容转义（不包引号）：\\ " 及全部控制字符。"""
            s = str(val)
            out = []
            for ch in s:
                o = ord(ch)
                if ch == '\\':
                    out.append('\\\\')
                elif ch == '"':
                    out.append('\\"')
                elif ch == '\t':
                    out.append('\\t')
                elif ch == '\n':
                    out.append('\\n')
                elif ch == '\r':
                    out.append('\\r')
                elif o < 0x20:
                    out.append(f'\\x{o:02X}')
                else:
                    out.append(ch)
            return ''.join(out)

        meta_lines = [
            f'author = "PSLS Auto-Generator"',
            f'description = "{_ys("Auto-generated rule for " + name)}"',
            f'sha256 = "{_ys(sha256)}"',
            f'sample_path = "{_ys(file_path)}"',
            f'file_size = {file_size}',
            f'sample_type = "{_ys(sample_type)}"',
            f'severity = "{_ys(severity)}"',
            f'feature_count = {len(features)}',
            f'generated = "{_ys(datetime.now().isoformat(timespec="seconds"))}"',
        ]
        tag = ' '.join(self._pick_tags(features))

        # strings 部分
        string_lines = []
        for f in features:
            string_lines.append(f'        {f["yara"]}')

        # condition 部分：所有字符串都必须命中（AND），且文件至少包含 4096 字节上限防误报
        var_names = [f['yara'].split('=')[0].strip() for f in features]
        cond_inner = ' and '.join(var_names)
        condition = f'        filesize < {file_size * 3}KB and ({cond_inner})'

        rule = (
            f'rule {rule_name} : {tag}\n'
            f'{{\n'
            f'    meta:\n'
        )
        for ml in meta_lines:
            rule += f'        {ml}\n'
        rule += f'\n    strings:\n'
        rule += '\n'.join(string_lines) + '\n'
        rule += f'\n    condition:\n{condition}\n'
        rule += f'}}\n'

        return rule

    @staticmethod
    def _pick_tags(features: List[Dict]) -> List[str]:
        tags = set()
        for f in features:
            t = f['type']
            if t == 'api_import':
                tags.add('pe_imports')
            elif t == 'section_name':
                tags.add('pe_sections')
            elif t == 'resource':
                tags.add('pe_resources')
            elif t == 'url':
                tags.add('c2_url')
            elif t == 'ip':
                tags.add('c2_ip')
            elif t == 'registry':
                tags.add('persistence')
            elif t == 'cmd':
                tags.add('command')
            elif t == 'danger_api':
                tags.add('dangerous_api')
            elif t == 'bytes':
                tags.add('byte_sig')
        if 'pe_imports' in tags or 'pe_sections' in tags:
            tags.add('pe')
        if 'pe' not in tags:
            tags.add('generic')
        return sorted(tags)


def test_generator():
    """对隔离区的 .js 文件跑一下，看能生成什么。"""
    gen = YaraGenerator()
    test_path = None
    for root, _, files in os.walk('quarantine'):
        for fn in files:
            if fn.endswith('.js') or fn.endswith('.exe') or fn.endswith('.dll'):
                test_path = os.path.join(root, fn)
                break
        if test_path:
            break
    if not test_path:
        print('没有找到可测试的样本文件')
        return
    print(f'=== 测试文件: {test_path} ===')
    result = gen.generate(test_path)
    if result:
        print(f'规则名: {result["rule_name"]}')
        print(f'特征数: {result["feature_count"]}')
        print(f'样本类型: {result["sample_type"]}')
        print()
        print(result['rule_content'])
    else:
        print('生成失败（特征不足或文件过大）')


if __name__ == '__main__':
    test_generator()
