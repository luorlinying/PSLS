"""
病毒文件识别引擎
分析文件特征，判断是否为恶意软件，并提取签名信息

支持的检测维度:
1. PE 文件结构分析 (节区、导入表、资源)
2. 文件熵值检测 (加壳/加密识别)
3. 可疑 API 导入分析
4. 启发式规则匹配
5. 文件类型与扩展名分析
6. 数字签名验证
7. 字符串特征提取
"""

import os
import re
import sys
import json
import math
import struct
import threading
import hashlib
from typing import Dict, List, Optional, Tuple
from utils.logger import get_logger

logger = get_logger('virus_identifier')

SUSPICIOUS_IMPORTS = {
    'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'ReadProcessMemory',
    'CreateRemoteThread', 'NtCreateThreadEx', 'OpenProcess', 'OpenThread',
    'SetWindowsHookEx', 'CallWndProc', 'GetProcAddress', 'LoadLibrary',
    'WinExec', 'ShellExecute', 'CreateProcess', 'WinCreateString',
    'InternetOpen', 'InternetOpenUrl', 'HttpSendRequest', 'WinHttpSendRequest',
    'URLDownloadToFile', 'DownloadToFile', 'WebClient',
    'RegSetValue', 'RegCreateKey', 'RegDeleteValue', 'RegCloseKey',
    'NtQuerySystemInformation', 'NtUnmapViewOfSection', 'NmapViewOfSection',
    'ZwOpenProcess', 'ZwAllocateVirtualMemory', 'ZwProtectVirtualMemory',
    'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptDestroyKey',
    'GetTickCount', 'QueryPerformanceCounter', 'timeGetTime',
    'FindWindow', 'FindWindowEx', 'EnumWindows', 'GetWindowText',
    'GetForegroundWindow', 'GetActiveWindow', 'SetForegroundWindow',
    'keybd_event', 'mouse_event', 'SendInput', 'MapVirtualKey',
    # 恶搞程序常用 API
    'SetCursorPos', 'GetCursorPos', 'ClipCursor',
    'SystemParametersInfo', 'SystemParametersInfoA', 'SystemParametersInfoW',
    'BlockInput', 'SwapMouseButton', 'ShowCursor',
    'SetDoubleClickTime', 'SetWindowPos', 'BringWindowToTop',
    'SetWindowTextA', 'SetWindowTextW',
    'MessageBoxA', 'MessageBoxW', 'MessageBoxIndirectA', 'MessageBoxIndirectW',
    'EnumDisplaySettingsA', 'EnumDisplaySettingsW',
    'ChangeDisplaySettingsA', 'ChangeDisplaySettingsW',
    'ChangeDisplaySettingsExA', 'ChangeDisplaySettingsExW',
    'ExitWindowsEx', 'LockWorkStation',
    'Clipboard', 'OpenClipboard', 'GetClipboardData', 'EmptyClipboard',
    'CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile', 'CopyFile',
    'MoveFile', 'SetFileAttributes', 'GetFileAttributes',
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugString',
    'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState',
}

SUSPICIOUS_DLLS = {
    'wininet.dll', 'winhttp.dll', 'urlmon.dll', 'ws2_32.dll',
    'advapi32.dll', 'ntdll.dll', 'kernel32.dll', 'user32.dll',
    'gdi32.dll', 'shell32.dll', 'ole32.dll', 'oleaut32.dll',
    'mfc42.dll', 'comctl32.dll', 'comdlg32.dll',
    'bcrypt.dll', 'crypt32.dll', 'secur32.dll', 'schannel.dll',
}

MALWARE_KEYWORDS = [
    'keylog', 'keystroke', 'spyware', 'trojan', 'ransom', 'ransomware',
    'cryptolock', 'cryptolocker', 'cryptominer', 'coinminer', 'bitcoin',
    'rootkit', 'backdoor', 'backdoor', 'worm', 'exploit', 'dropper',
    'downloader', 'injector', 'loader', 'packer', 'crypter', 'stealer',
    'infostealer', 'credential', 'password', 'stealer', 'banker',
    'adware', 'grayware', 'potentially', 'unwanted', 'pup', 'pia',
    'hack', 'crack', 'keygen', 'patch', 'serial', 'registration',
    'botnet', 'irc', 'ddos', 'dos', 'flood', 'spam', 'phish',
    'exfiltrate', 'exfiltration', 'data.theft', 'information.steal',
    # 恶搞程序关键词
    'joke', 'prank', 'hoax', 'fake', 'trick', 'scare',
    'just.a.joke', 'haha', 'scream', 'scary',
]

DANGEROUS_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.scr', '.pif', '.com', '.bat', '.cmd',
    '.ps1', '.vbs', '.js', '.wsf', '.jse', '.vbe', '.hta', '.lnk',
    '.url', '.msi', '.msp', '.cpl', '.inf', '.reg', '.jar', '.wsf',
    '.gadget', '.docm', '.xlsm', '.pptm',
}

SCRIPT_EXTENSIONS = {'.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.jse', '.vbe', '.hta'}

# ===========================================================================
# 白样本画像（train_whitelist.py 训练产物 data/white_profile.json）
# 用于抑制商业软件目录（QQ/Steam 等）的启发式误报。
# 抑制只作用于本引擎的风险分；PE/ML/签名库等主引擎仍独立判定真实威胁。
# ===========================================================================

_WHITE_NAME_SPLIT_RE = re.compile(r'[^a-z0-9]+')
_WHITE_DIR_STOPWORDS = {
    'windows', 'program', 'files', 'x86', 'common', 'bin', 'lib', 'lib64',
    'etc', 'usr', 'local', 'share', 'data', 'cache', 'temp', 'tmp', 'logs',
    'debug', 'release', 'win32', 'win64', 'x64', 'x86_64', 'resources',
    'resource', 'content', 'contents', 'lang', 'locale', 'es', 'zh-cn',
    'zh-tw', 'en-us', 'de', 'fr', 'ru', 'ja', 'ko', 'cn', 'us', 'appdata',
    'roaming', 'microsoft', 'microsoft.net',
}


def _white_profile_path() -> str:
    """画像路径：开发模式为项目根/data，打包模式为 bundle/data"""
    root = getattr(sys, '_MEIPASS', None)
    if not root:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, 'data', 'white_profile.json')


def _white_name_tokens_of(basename: str) -> set:
    """文件名词元：去扩展名整体 + 按非字母数字切分的子词（长度≥3）"""
    stem = os.path.splitext(basename)[0].lower()
    tokens = {stem} if len(stem) >= 3 else set()
    tokens |= {t for t in _WHITE_NAME_SPLIT_RE.split(stem) if len(t) >= 3}
    return tokens


def _white_dir_tokens_of(file_path: str) -> set:
    """路径目录词元：每一级目录名（长度≥3 且非停用词）"""
    tokens = set()
    p = os.path.dirname(os.path.abspath(file_path))
    while True:
        d = os.path.basename(p)
        if not d:
            break
        d_l = d.lower()
        if len(d_l) >= 3 and d_l not in _WHITE_DIR_STOPWORDS:
            tokens.add(d_l)
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    return tokens


class _WhiteProfile:
    """白样本画像惰性加载，进程内只加载一次"""

    _lock = threading.Lock()
    _data: Optional[Dict] = None
    _loaded = False

    @classmethod
    def get(cls) -> Optional[Dict]:
        if cls._loaded:
            return cls._data
        with cls._lock:
            if cls._loaded:
                return cls._data
            try:
                path = _white_profile_path()
                if os.path.isfile(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    if isinstance(data, dict) and data.get('hashes'):
                        cls._data = data
                    else:
                        cls._data = None
                else:
                    cls._data = None
            except Exception as e:
                logger.debug('加载白样本画像失败: %s', e)
                cls._data = None
            cls._loaded = True
            return cls._data

MAX_STRING_SCAN = 10 * 1024 * 1024  # 10MB for string extraction


class VirusIdentifier:
    """病毒文件识别引擎"""

    def __init__(self, signature_db=None):
        self._sig_db = signature_db

    def identify(self, file_path: str, precomputed_sha256: str = None) -> Dict:
        """
        综合分析文件，判断是否为病毒文件

        Args:
            file_path: 文件路径
            precomputed_sha256: 可选的已算好的文件 sha256。调用方（如扫描 worker）
                已在扫描链路上游算过一次 hash，传入可避免 ViiD 重复整文件读盘，
                只读取前 2MB 分析缓冲区做内容分析，显著降低大文件 I/O 开销。

        Returns:
            {
                'is_malware': bool,
                'confidence': float,  # 0.0 - 1.0
                'score': int,         # 风险评分
                'reasons': [str],     # 判断依据
                'file_info': {
                    'type': str,       # 'pe', 'script', 'document', 'archive', 'unknown'
                    'size': int,
                    'entropy': float,
                    'packed': bool,
                    'signed': bool,
                },
                'signatures': {
                    'sha256': str,
                    'md5': str,
                    'strings': [str],  # 可疑字符串特征
                    'suspicious_imports': [str],
                    'yara_rules': [str],  # 可用于 YARA 的特征
                },
                'malware_type': str,   # 'Trojan', 'Virus', 'Ransomware', etc.
                'severity': str,      # 'critical', 'high', 'medium', 'low'
            }
        """
        result = {
            'is_malware': False,
            'confidence': 0.0,
            'score': 0,
            'reasons': [],
            'file_info': {
                'type': 'unknown',
                'size': 0,
                'entropy': 0.0,
                'packed': False,
                'signed': False,
            },
            'signatures': {
                'sha256': '',
                'md5': '',
                'strings': [],
                'suspicious_imports': [],
                'yara_rules': [],
            },
            'malware_type': 'Unknown',
            'severity': 'low',
        }

        if not os.path.isfile(file_path):
            result['reasons'].append('文件不存在')
            return result

        try:
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                result['reasons'].append('文件为空')
                return result
            result['file_info']['size'] = file_size
        except Exception as e:
            result['reasons'].append(f'无法获取文件信息: {e}')
            return result

        ext = os.path.splitext(file_path)[1].lower()
        basename = os.path.basename(file_path)

        # ---- 一次性读取文件数据，避免多次打开文件 ----
        # 分析缓冲区大小：PE/脚本需要的数据量不同
        analyze_limit = 2 * 1024 * 1024  # 2MB 用于 PE 分析和熵值
        string_limit = min(file_size, MAX_STRING_SCAN)  # 字符串提取上限

        # 读取分析所需的数据（一次性）
        # 若调用方已提供文件 sha256，则跳过整文件哈希计算（只读前 2MB 分析缓冲区），
        # 显著减少大文件重复读盘 —— 扫描 worker 在链路上游已经算过 hash。
        file_data = None
        sha256_output = precomputed_sha256 or ''
        try:
            with open(file_path, 'rb') as f:
                # 先读取分析缓冲区
                file_data = f.read(analyze_limit)
                if precomputed_sha256:
                    # 已有 hash：只需分析缓冲区，不再读取剩余数据
                    pass
                else:
                    hashlib_sha = hashlib.sha256()
                    hashlib_md5 = hashlib.md5()
                    hashlib_sha.update(file_data)
                    hashlib_md5.update(file_data)
                    # 继续读取剩余数据以完成哈希计算
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        hashlib_sha.update(chunk)
                        hashlib_md5.update(chunk)
                    sha256_output = hashlib_sha.hexdigest()
                    result['signatures']['md5'] = hashlib_md5.hexdigest()
        except Exception:
            return result

        result['signatures']['sha256'] = sha256_output

        # 检测文件类型（使用已读取的头部数据）
        file_type = self._detect_file_type_from_data(file_data, ext)
        result['file_info']['type'] = file_type

        # 分析熵值（使用已读取的数据，无需再次打开文件）
        entropy = self._calc_entropy_from_data(file_data)
        result['file_info']['entropy'] = entropy
        # 仅对 PE 文件启用高熵检测，阈值 7.8（避免对压缩/加密文档误报）
        if file_type == 'pe' and entropy > 7.8:
            result['file_info']['packed'] = True
            result['score'] += 15
            result['reasons'].append(f'高熵值 ({entropy:.2f})，疑似加壳/加密')

        # PE 文件分析（使用已读取的数据）
        if file_type == 'pe':
            pe_result = self._analyze_pe_from_data(file_data)
            result['score'] += pe_result['score']
            result['reasons'].extend(pe_result['reasons'])
            result['signatures']['suspicious_imports'] = pe_result.get('suspicious_imports', [])
            result['file_info']['packed'] = result['file_info']['packed'] or pe_result.get('packed', False)
            result['file_info']['signed'] = pe_result.get('signed', False)

        # 脚本文件分析
        if file_type == 'script':
            script_result = self._analyze_script(file_path)
            result['score'] += script_result['score']
            result['reasons'].extend(script_result['reasons'])

        # 启发式规则匹配
        if self._sig_db:
            heuristic_score, heuristic_reasons = self._check_heuristics(file_path, basename, ext)
            result['score'] += heuristic_score
            result['reasons'].extend(heuristic_reasons)

        # 字符串特征提取（仅对可执行文件和脚本进行，跳过纯文本/数据文件）
        if file_type in ('pe', 'script', 'executable', 'macro_document'):
            strings = self._extract_suspicious_strings_from_data(file_data, file_type)
            result['signatures']['strings'] = strings
            if strings:
                result['score'] += min(len(strings) * 3, 20)
                result['reasons'].append(f'发现 {len(strings)} 个可疑字符串特征')

        # 文件名关键词分析
        name_score, name_reasons = self._check_filename(basename)
        result['score'] += name_score
        result['reasons'].extend(name_reasons)

        # 证据链叠加加权（多个弱信号同时命中时加成提升敏感性）
        weak_signals = 0
        reasons_text = ' '.join(result['reasons']).lower()
        if any(k in reasons_text for k in ['高熵', '加壳', '加密']):
            weak_signals += 1
        if any(k in reasons_text for k in ['可疑api导入', 'api导入']):
            weak_signals += 1
        if any(k in reasons_text for k in ['可疑字符串']):
            weak_signals += 1
        if any(k in reasons_text for k in ['未签名']):
            weak_signals += 1
        if any(k in reasons_text for k in ['反调试', '沙箱', 'debugger']):
            weak_signals += 1
        if weak_signals >= 3:
            extra = (weak_signals - 2) * 5
            result['score'] += extra
            result['reasons'].append(f'证据链叠加：{weak_signals} 个弱特征同时命中 +{extra} 分')

        # 生成 YARA 规则特征
        result['signatures']['yara_rules'] = self._generate_yara_features(result)

        # 最终判定（阈值微调：敏感性提升 +5 分，配合沙箱二次验证降低误报）
        result['score'] = min(result['score'], 100)

        # 白样本画像抑制（降误报）：命中训练确认为安全的启发式画像时压低风险分。
        # 仅作用于本引擎分量，PE/ML/签名库等主引擎仍独立判定，不影响真实威胁检出。
        self._apply_white_suppression(file_path, basename, sha256_output, file_type, result)

        result['confidence'] = min(result['score'] / 100.0, 1.0)

        # 判定分档：恢复原始敏感分档，主程序保留 suspicious
        #   - score>=65: critical malware
        #   - score>=28: high malware
        #   - score 8-27: suspicious（原 suspicious 区间 8-44 收窄为 8-27，保留 sus）
        #   - score<=7:  clean（保持原始 clean 上限）
        if result['score'] >= 65:
            result['is_malware'] = True
            result['severity'] = 'critical'
            result['malware_type'] = self._classify_malware(result)
        elif result['score'] >= 28:
            result['is_malware'] = True
            result['severity'] = 'high'
            result['malware_type'] = self._classify_malware(result)
        elif result['score'] >= 8:
            result['is_malware'] = False
            result['severity'] = 'medium'
            result['malware_type'] = 'Suspicious'
        else:
            result['is_malware'] = False
            result['severity'] = 'low'
            result['malware_type'] = 'Clean'

        return result

    def _apply_white_suppression(self, file_path: str, basename: str,
                                 sha256_output: str, file_type: str,
                                 result: Dict):
        """白样本画像抑制：命中训练确认为安全的画像时压低风险分（降误报）

        证据强度递减：
        1. sha256 哈希命中      → 风险分 ≤6（clean），最可靠，能抵抗软件更新
        2. 签名者命中            → 风险分 ≤6（clean）
        3. 文件名/目录词元组合  → 风险分 ≤27（降级 suspicious 上限，保留告警）
        单个弱词元不抑制，防恶意借用白样本特征绕过。
        """
        profile = _WhiteProfile.get()
        if not profile:
            return

        # 1. 哈希精确命中
        hashes = profile.get('hashes') or {}
        if sha256_output and sha256_output in hashes:
            if result['score'] > 6:
                result['score'] = 6
                result['reasons'].append('白样本指纹：文件哈希已训练确认为安全（风险分已抑制）')
            return

        # 已在 clean 区间则无需处理，也避免无谓的签名校验开销
        if result['score'] < 8:
            return

        # 2. 签名者命中（仅对 PE 文件、且仅在可疑/威胁分档时做签名校验）
        signer = None
        if file_type == 'pe':
            try:
                from utils.signature_verifier import get_verifier
                si = get_verifier().get_signer_info(file_path)
                if si and si.get('verified'):
                    signer = (si.get('publisher') or '').strip().lower()
            except Exception:
                signer = None
        if signer and signer in (profile.get('signers') or {}):
            if result['score'] > 6:
                result['score'] = 6
                result['reasons'].append(
                    f'白样本指纹：签名者 "{signer}" 已训练确认为安全（风险分已抑制）')
            return

        # 3. 文件名/目录词元组合命中
        name_hits = [t for t in _white_name_tokens_of(basename)
                     if t in (profile.get('name_tokens') or {})]
        dir_hits = [t for t in _white_dir_tokens_of(file_path)
                    if t in (profile.get('dir_tokens') or {})]
        if (len(name_hits) >= 2 or len(dir_hits) >= 2
                or len(name_hits) + len(dir_hits) >= 3):
            if result['score'] > 27:
                result['score'] = 27
                result['reasons'].append(
                    '白样本画像命中（文件名/目录词元），风险分已降级')

    def _detect_file_type_from_data(self, data: bytes, ext: str) -> str:
        """检测文件类型（使用已读取的数据，避免再次打开文件）"""
        # PE 文件检测
        try:
            if len(data) >= 2 and data[:2] == b'MZ':
                if len(data) >= 0x40:
                    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
                    if pe_offset + 4 <= len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                        return 'pe'
        except Exception:
            pass

        if ext in SCRIPT_EXTENSIONS:
            return 'script'
        if ext in {'.docm', '.xlsm', '.pptm'}:
            return 'macro_document'
        if ext in DANGEROUS_EXTENSIONS:
            return 'executable'
        return 'unknown'

    def _calc_entropy_from_data(self, data: bytes) -> float:
        """计算文件熵值 (Shannon entropy) - 基于内存数据"""
        if not data:
            return 0.0
        try:
            freq = [0] * 256
            for b in data:
                freq[b] += 1
            length = len(data)
            entropy = 0.0
            for count in freq:
                if count > 0:
                    p = count / length
                    entropy -= p * math.log2(p)
            return entropy
        except Exception:
            return 0.0

    def _analyze_pe_from_data(self, data: bytes) -> Dict:
        """PE 文件深度分析（基于内存数据，避免重复读取文件）"""
        result = {
            'score': 0,
            'reasons': [],
            'suspicious_imports': [],
            'packed': False,
            'signed': False,
            'section_info': [],
        }

        try:
            if len(data) < 0x40:
                return result

            # 解析 PE 头
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            if pe_offset + 0x60 > len(data):
                return result

            # COFF 头
            num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
            size_optional = struct.unpack_from('<H', data, pe_offset + 20)[0]
            sections_offset = pe_offset + 24 + size_optional

            # 分析节区
            high_entropy_sections = 0
            for i in range(min(num_sections, 96)):
                sec_off = sections_offset + i * 40
                if sec_off + 40 > len(data):
                    break
                sec_name = data[sec_off:sec_off + 8].rstrip(b'\x00').decode('ascii', errors='ignore')
                sec_size = struct.unpack_from('<I', data, sec_off + 16)[0]
                sec_entropy = 0.0
                if sec_size > 0 and sec_off + 40 + sec_size <= len(data):
                    sec_data = data[sec_off + 40:sec_off + 40 + sec_size]
                    sec_freq = [0] * 256
                    for sb in sec_data:
                        sec_freq[sb] += 1
                    for sc in sec_freq:
                        if sc > 0:
                            sp = sc / len(sec_data)
                            sec_entropy -= sp * math.log2(sp)
                if sec_entropy > 7.5:
                    high_entropy_sections += 1
                result['section_info'].append({
                    'name': sec_name,
                    'size': sec_size,
                    'entropy': round(sec_entropy, 2),
                })

            if high_entropy_sections >= 2:
                result['packed'] = True
                result['score'] += 25
                result['reasons'].append(f'检测到 {high_entropy_sections} 个高熵节区，疑似加壳/加密')

            # ---- 新增 PE 结构异常检测维度 PART A（不需要导入表）----
            # 1. 异常节区名检测（自定义/非标准节区名：UPX壳、.text1、空名等）
            STANDARD_SECTIONS = {'.text', '.data', '.rdata', '.rsrc', '.reloc', '.bss',
                                 '.idata', '.edata', '.tls', '.crt', '.pdata', '.xdata',
                                 '.code', '.const', '.didat', '.debug', '.gfids', '.00cfg'}
            non_std_sections = 0
            suspicious_section_names = []
            for sec in result['section_info']:
                sname = sec['name'].lower()
                if sname and sname not in STANDARD_SECTIONS:
                    non_std_sections += 1
                    if any(k in sname for k in ['upx', 'mpress', 'aspack', 'themida', 'vmprotect', 'enigma', 'pelock', 'execrypt', '.text1', 'packed', 'crypt']):
                        suspicious_section_names.append(sec['name'])
            if suspicious_section_names:
                result['score'] += min(len(suspicious_section_names) * 8, 20)
                result['reasons'].append(f'疑似加壳节区名: {", ".join(suspicious_section_names[:5])}')
            if non_std_sections >= 3 and len(result['section_info']) >= 3:
                result['score'] += 8
                result['reasons'].append(f'存在 {non_std_sections} 个非标准节区，结构异常')
            if any(not sec['name'] for sec in result['section_info']):
                result['score'] += 10
                result['reasons'].append('存在空名称节区，结构异常')

            # 2. 节区特征异常：非代码节高熵
            for sec in result['section_info']:
                sname_lower = sec['name'].lower()
                if sname_lower not in ('.text', '.code') and sec.get('entropy', 0) > 7.6 and sec.get('size', 0) > 4096:
                    result['score'] += 6
                    result['reasons'].append(f'非代码节区 {sec["name"]} 熵值异常高 ({sec.get("entropy", 0):.2f})')
                    break

            # 3. 文件体积异常小（微型PE：下载器/Loader）
            file_size = len(data)
            if file_size < 8192 and file_size > 512:
                result['score'] += 5
                result['reasons'].append(f'微型 PE 文件 ({file_size} 字节)，疑似小型下载器/Shellcode Loader')

            # 6. 可选头校验：无节区表 / SizeOfHeaders 异常
            if num_sections == 0 and file_size > 1024:
                result['score'] += 15
                result['reasons'].append('PE 声称无节区，结构极度异常')
            try:
                _opt_headers_offset = pe_offset + 24
                if _opt_headers_offset + 88 <= len(data):
                    sizeof_headers_val = struct.unpack_from('<I', data, _opt_headers_offset + 84)[0]
                    if sizeof_headers_val > file_size or sizeof_headers_val < 0x200:
                        result['score'] += 6
                        result['reasons'].append(f'PE SizeOfHeaders 异常: {sizeof_headers_val}')
            except Exception:
                pass

            # ---- 导入表分析 ----
            imports = self._extract_imports(data, pe_offset, size_optional)
            suspicious_found = []

            # 聚合全文件的func_set用于跨DLL组合检测（木马常用跨DLL组合）
            global_func_set = set()
            global_dll_set = set()
            for imp_dll, imp_funcs in imports:
                global_dll_set.add(imp_dll.lower())
                global_func_set.update(imp_funcs)

            # ---- 新增 PE 结构异常检测维度 PART B（依赖导入表）----
            # 4. 导入表稀疏或异常：导入数量很少但关键API
            total_imports = sum(len(funcs) for _, funcs in imports)
            has_network_imports = any(api in global_func_set for api in ['InternetOpen', 'InternetOpenUrl', 'HttpSendRequest', 'WinHttpConnect', 'URLDownloadToFileW', 'URLDownloadToFileA'])
            has_process_imports = any(api in global_func_set for api in ['VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread', 'WriteProcessMemory'])
            if total_imports > 0 and total_imports <= 8 and (has_network_imports or has_process_imports):
                result['score'] += 8
                result['reasons'].append(f'导入表仅 {total_imports} 项且含敏感API，疑似最小化Loader')
            if not imports and file_size > 16384:
                result['score'] += 12
                result['reasons'].append('PE无导入表（可能自解包/动态获取API）')

            # 5. 导出表异常：DLL 但导出函数异常
            try:
                characteristics = struct.unpack_from('<H', data, pe_offset + 22)[0]
                is_dll = bool(characteristics & 0x2000)
                if is_dll:
                    _section_table_off = pe_offset + 24 + size_optional
                    def _rva_to_off(rva):
                        for i in range(min(num_sections, 96)):
                            _so = _section_table_off + i * 40
                            if _so + 40 > len(data):
                                break
                            _srva = struct.unpack_from('<I', data, _so + 12)[0]
                            _ssize = struct.unpack_from('<I', data, _so + 8)[0]
                            _sraw = struct.unpack_from('<I', data, _so + 20)[0]
                            if _srva <= rva < _srva + _ssize:
                                return _sraw + (rva - _srva)
                        return None
                    _magic_opt = struct.unpack_from('<H', data, pe_offset + 24)[0]
                    export_dir_rva_off = pe_offset + 24 + (104 if _magic_opt != 0x20B else 112)
                    if export_dir_rva_off + 8 <= len(data):
                        export_rva = struct.unpack_from('<I', data, export_dir_rva_off)[0]
                        if export_rva != 0:
                            export_offset = _rva_to_off(export_rva)
                            if export_offset and export_offset + 28 <= len(data):
                                num_funcs = struct.unpack_from('<I', data, export_offset + 20)[0]
                                if num_funcs >= 200:
                                    result['score'] += 6
                                    result['reasons'].append(f'DLL 导出函数异常多 ({num_funcs})，可能插件式加载器')
                                elif num_funcs == 0 and file_size > 32768:
                                    result['score'] += 5
                                    result['reasons'].append('DLL 声称有导出目录但函数数为0')
            except Exception:
                pass

            for imp_dll, imp_funcs in imports:
                dll_lower = imp_dll.lower()
                if dll_lower in SUSPICIOUS_DLLS:
                    for func in imp_funcs:
                        if func in SUSPICIOUS_IMPORTS:
                            suspicious_found.append(f'{imp_dll}.{func}')
                # 检查可疑组合（单DLL）
                func_set = set(imp_funcs)
                if 'VirtualAlloc' in func_set and 'WriteProcessMemory' in func_set:
                    result['score'] += 20
                    result['reasons'].append('检测到进程注入特征 (VirtualAlloc + WriteProcessMemory)')
                if 'CreateRemoteThread' in func_set or 'NtCreateThreadEx' in func_set:
                    result['score'] += 15
                    result['reasons'].append('检测到远程线程创建特征')
                if 'IsDebuggerPresent' in func_set:
                    result['score'] += 10
                    result['reasons'].append('检测到反调试特征')
                if 'GetAsyncKeyState' in func_set or 'GetKeyState' in func_set:
                    result['score'] += 15
                    result['reasons'].append('检测到键盘记录特征')
                if 'InternetOpen' in func_set or 'WinHttpSendRequest' in func_set:
                    if 'VirtualAlloc' in func_set:
                        result['score'] += 10
                        result['reasons'].append('检测到网络通信+内存操作组合，疑似下载器')

                # ---- 恶搞程序行为组合检测 ----
                joke_apis_found = []
                if 'SetCursorPos' in func_set or 'mouse_event' in func_set or 'SendInput' in func_set:
                    joke_apis_found.append('鼠标控制')
                if 'SystemParametersInfo' in func_set or 'SystemParametersInfoA' in func_set or 'SystemParametersInfoW' in func_set:
                    joke_apis_found.append('系统参数修改')
                if 'BlockInput' in func_set:
                    joke_apis_found.append('阻断键鼠输入')
                if 'SwapMouseButton' in func_set:
                    joke_apis_found.append('交换鼠标按键')
                if 'ShowCursor' in func_set:
                    joke_apis_found.append('隐藏光标')
                if 'keybd_event' in func_set:
                    joke_apis_found.append('模拟键盘')
                if 'ChangeDisplaySettingsA' in func_set or 'ChangeDisplaySettingsW' in func_set or 'ChangeDisplaySettingsExA' in func_set or 'ChangeDisplaySettingsExW' in func_set:
                    joke_apis_found.append('修改显示设置')
                if 'MessageBoxA' in func_set or 'MessageBoxW' in func_set:
                    joke_apis_found.append('弹窗消息')
                if 'ExitWindowsEx' in func_set or 'LockWorkStation' in func_set:
                    joke_apis_found.append('注销/关机')

                if len(joke_apis_found) >= 2:
                    result['score'] += 25
                    result['reasons'].append(f'检测到恶搞程序行为组合: {", ".join(joke_apis_found)}')
                elif len(joke_apis_found) == 1:
                    result['score'] += 10
                    result['reasons'].append(f'检测到恶搞相关API: {joke_apis_found[0]}')

            # ---- 跨DLL系统修改类行为组合检测（核心增强） ----
            g = global_func_set
            dl = global_dll_set

            # 1. 注册表持久化组合：RegSetValue + RegCreateKey + 启动项相关关键词路径(通过子串匹配校验通过字符串特征)
            has_reg_write = any(x in g for x in [
                'RegSetValueA', 'RegSetValueW', 'RegSetValueExA', 'RegSetValueExW',
                'RegCreateKeyA', 'RegCreateKeyW', 'RegCreateKeyExA', 'RegCreateKeyExW'
            ])
            has_reg_delete = any(x in g for x in [
                'RegDeleteValueA', 'RegDeleteValueW', 'RegDeleteKeyA', 'RegDeleteKeyW'
            ])
            # 2. 服务安装/配置组合
            has_service_install = any(x in g for x in [
                'CreateServiceA', 'CreateServiceW', 'OpenServiceA', 'OpenServiceW',
                'StartServiceA', 'StartServiceW', 'ChangeServiceConfigA', 'ChangeServiceConfigW',
                'ChangeServiceConfig2A', 'ChangeServiceConfig2W', 'ControlService',
                'ControlServiceExA', 'ControlServiceExW', 'DeleteService'
            ])
            has_svc_mgr = any(x in g for x in [
                'OpenSCManagerA', 'OpenSCManagerW', 'CloseServiceHandle'
            ])
            # 3. 驱动加载/设备IO组合（Rootkit/内核级木马常见）
            has_driver_load = any(x in g for x in [
                'CreateServiceA', 'CreateServiceW', 'StartServiceA', 'StartServiceW',
            ]) and any(x in dl for x in ['setupapi.dll', 'cfgmgr32.dll', 'newdev.dll'])
            has_device_io = 'DeviceIoControl' in g
            # 4. 计划任务创建
            has_task_create = any(x in dl for x in ['taskschd.dll', 'schedcli.dll', 'mstask.dll'])
            # 5. 用户/组管理（木马创建后门账户）
            has_user_mgmt = any(x in g for x in [
                'NetUserAdd', 'NetUserSetInfo', 'NetLocalGroupAddMembers',
                'NetUserEnum', 'NetGroupAdd', 'NetLocalGroupAdd'
            ]) or 'netapi32.dll' in dl and any(x in g for x in ['NetUserAdd', 'NetLocalGroupAddMembers'])
            # 6. 磁盘/MBR底层写入（MBR病毒/Rootkit）
            has_disk_write = any(x in g for x in [
                'WriteFile', 'DeviceIoControl'
            ]) and any(x in g for x in [
                'CreateFileA', 'CreateFileW'
            ])
            # 7. 杀软/安全软件关闭（通过OpenProcess TerminateProcess + 杀软进程名检测通过字符串特征补齐）
            has_process_kill = 'TerminateProcess' in g and any(x in g for x in ['CreateToolhelp32Snapshot', 'Process32FirstA', 'Process32FirstW', 'EnumProcesses'])
            # 8. LSA认证包/SSP注入（窃取凭据）
            has_lsa_inject = any(x in g for x in [
                'LsaRegisterLogonProcess', 'LsaLookupAuthenticationPackage',
                'LsaCallAuthenticationPackage', 'AddSecurityPackage'
            ]) or 'secur32.dll' in dl and any(x in g for x in ['LsaAddAccountRights', 'LsaEnumerateLogonSessions'])
            # 9. 组策略/策略修改
            has_gp_edit = any(x in g for x in [
                'RefreshPolicy', 'RefreshPolicyEx', 'LGPO'
            ]) or 'userenv.dll' in dl and any(x in g for x in ['GetGPOListW', 'GetGPOListA', 'ProcessGroupPolicyCompleted'])
            # 10. 文件系统驱动/过滤（勒索软件防护绕过）
            has_fs_filter = any(x in dl for x in ['fltlib.dll', 'filter.dll']) or has_driver_load
            # 11. 组策略+注册表+持久化三位一体 = 高概率恶意
            has_persist_combo = (has_reg_write or has_service_install or has_task_create)
            has_system_meddle = (has_reg_delete or has_process_kill or has_gp_edit)

            # ---- 组合权重评分（按严重度递增） ----
            combos_found = 0
            if has_reg_write and has_reg_delete:
                result['score'] += 8
                combos_found += 1
                result['reasons'].append('注册表写入+删除: 可能篡改系统配置')
            if has_service_install and has_svc_mgr:
                result['score'] += 18
                combos_found += 1
                result['reasons'].append('服务安装/配置: 可能持久化或加载驱动')
            if has_driver_load or (has_device_io and (any('SetupDi' in x or 'CM_' in x or 'DIFx' in x for x in global_func_set))):
                result['score'] += 22
                combos_found += 1
                result['reasons'].append('驱动/设备IO操作: 可能加载内核驱动或Rootkit')
            if has_task_create:
                # taskschd 导入 => 计划任务能力
                result['score'] += 12
                combos_found += 1
                result['reasons'].append('导入任务计划相关库: 可能添加计划任务持久化')
            if has_user_mgmt:
                result['score'] += 20
                combos_found += 1
                result['reasons'].append('用户/组管理API: 可能创建后门账户')
            if has_disk_write and has_device_io:
                result['score'] += 25
                combos_found += 1
                result['reasons'].append('磁盘/设备底层写入: 可能为MBR病毒或内核Rootkit')
            if has_process_kill and has_svc_mgr:
                result['score'] += 15
                combos_found += 1
                result['reasons'].append('进程枚举+终止+服务控制: 可能试图关闭杀软/安全软件')
            if has_lsa_inject:
                result['score'] += 30
                combos_found += 1
                result['reasons'].append('LSA/SSP认证包操作: 可能窃取凭据或绕过登录')
            if has_gp_edit:
                result['score'] += 10
                combos_found += 1
                result['reasons'].append('组策略修改: 可能篡改系统安全策略')
            if has_fs_filter:
                result['score'] += 10
                combos_found += 1
                result['reasons'].append('文件系统过滤/驱动接口: 可能绕过或禁用安全防护')
            # 三位一体：持久化 + 系统破坏 + 反分析
            if combos_found >= 3:
                result['score'] += 25
                result['reasons'].append(f'系统修改类特征集合（{combos_found}项）: 高概率恶意软件')
            elif combos_found == 2:
                result['score'] += 10
                result['reasons'].append(f'双重系统修改特征: 可疑软件')

            # 增强：单独API单项加权（无组合命中时仍保留敏感度）
            if any(x in g for x in ['CreateServiceA', 'CreateServiceW']) and not has_svc_mgr:
                result['score'] += 12
                result['reasons'].append('CreateService 调用: 可能安装服务')
            if any(x in g for x in ['SetWindowsHookExA', 'SetWindowsHookExW']) and any(x in g for x in ['GetMsgProc', 'CallWndProc', 'LowLevelKeyboardProc', 'LowLevelMouseProc']):
                result['score'] += 18
                result['reasons'].append('全局钩子设置: 可能键盘记录或DLL注入')
            # 剪贴板监控 + 文件枚举 = 勒索/窃密前兆
            if any(x in g for x in ['OpenClipboard', 'GetClipboardData', 'SetClipboardData', 'EmptyClipboard']) and any(x in g for x in ['FindFirstFileA', 'FindFirstFileW', 'FindNextFileA', 'FindNextFileW']):
                result['score'] += 12
                result['reasons'].append('剪贴板操作+文件枚举: 可能窃密或勒索')

            result['suspicious_imports'] = suspicious_found
            if suspicious_found:
                result['score'] += min(len(suspicious_found) * 5, 30)
                result['reasons'].append(f'发现 {len(suspicious_found)} 个可疑API导入')

            # 检查数字签名
            result['signed'] = self._check_pe_signature(data, pe_offset, size_optional)
            if not result['signed'] and num_sections > 0:
                result['score'] += 5
                result['reasons'].append('文件未签名')

        except Exception as e:
            logger.debug(f'PE分析异常: {e}')

        return result

    def _extract_imports(self, data: bytes, pe_offset: int, size_optional: int) -> List[Tuple[str, List[str]]]:
        """提取 PE 导入表"""
        imports = []
        try:
            magic = struct.unpack_from('<H', data, pe_offset + 24)[0]
            if magic == 0x20B:  # PE32+
                import_dir_off = pe_offset + 24 + 112
            else:  # PE32
                import_dir_off = pe_offset + 24 + 104

            if import_dir_off + 8 > len(data):
                return imports

            import_rva = struct.unpack_from('<I', data, import_dir_off)[0]
            if import_rva == 0:
                return imports

            # 简化版：通过搜索 PE 头中的导入信息
            # 定位导入描述符
            section_table_off = pe_offset + 24 + size_optional
            num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]

            def rva_to_offset(rva):
                for i in range(min(num_sections, 96)):
                    sec_off = section_table_off + i * 40
                    if sec_off + 40 > len(data):
                        break
                    sec_rva = struct.unpack_from('<I', data, sec_off + 12)[0]
                    sec_size = struct.unpack_from('<I', data, sec_off + 8)[0]
                    sec_raw = struct.unpack_from('<I', data, sec_off + 20)[0]
                    if sec_rva <= rva < sec_rva + sec_size:
                        return sec_raw + (rva - sec_rva)
                return None

            import_offset = rva_to_offset(import_rva)
            if import_offset is None:
                return imports

            # 遍历导入描述符
            idx = 0
            while True:
                desc_off = import_offset + idx * 20
                if desc_off + 20 > len(data):
                    break
                original_first_thunk = struct.unpack_from('<I', data, desc_off)[0]
                time_date = struct.unpack_from('<I', data, desc_off + 4)[0]
                forwarder = struct.unpack_from('<I', data, desc_off + 8)[0]
                name_rva = struct.unpack_from('<I', data, desc_off + 12)[0]
                first_thunk = struct.unpack_from('<I', data, desc_off + 16)[0]

                if original_first_thunk == 0 and name_rva == 0:
                    break

                # 读取 DLL 名称
                name_off = rva_to_offset(name_rva)
                if name_off and name_off < len(data):
                    dll_name = b''
                    for ci in range(256):
                        if name_off + ci >= len(data) or data[name_off + ci] == 0:
                            break
                        dll_name += bytes([data[name_off + ci]])
                    dll_name = dll_name.decode('ascii', errors='ignore')

                    # 读取函数名
                    func_names = []
                    thunk_rva = original_first_thunk or first_thunk
                    thunk_off = rva_to_offset(thunk_rva)
                    if thunk_off:
                        fi = 0
                        while True:
                            fmt = '<Q' if magic == 0x20B else '<I'
                            ptr_size = 8 if magic == 0x20B else 4
                            if thunk_off + fi * ptr_size + ptr_size > len(data):
                                break
                            thunk_val = struct.unpack_from(fmt, data, thunk_off + fi * ptr_size)[0]
                            if thunk_val == 0:
                                break
                            if magic == 0x20B:
                                if thunk_val & (1 << 63):
                                    func_names.append(f'ordinal_{thunk_val & 0xFFFF}')
                                else:
                                    func_rva = thunk_val & 0x7FFFFFFF
                                    func_off = rva_to_offset(func_rva)
                                    if func_off and func_off < len(data):
                                        func_name = b''
                                        for cn in range(256):
                                            if func_off + cn >= len(data) or data[func_off + cn] == 0:
                                                break
                                            func_name += bytes([data[func_off + cn]])
                                        func_names.append(func_name.decode('ascii', errors='ignore'))
                            else:
                                if thunk_val & 0x80000000:
                                    func_names.append(f'ordinal_{thunk_val & 0xFFFF}')
                                else:
                                    func_rva = thunk_val
                                    func_off = rva_to_offset(func_rva)
                                    if func_off and func_off < len(data):
                                        func_name = b''
                                        for cn in range(256):
                                            if func_off + cn >= len(data) or data[func_off + cn] == 0:
                                                break
                                            func_name += bytes([data[func_off + cn]])
                                        func_names.append(func_name.decode('ascii', errors='ignore'))
                            fi += 1
                    imports.append((dll_name, func_names))
                idx += 1

        except Exception as e:
            logger.debug(f'导入表解析异常: {e}')

        return imports

    def _check_pe_signature(self, data: bytes, pe_offset: int, size_optional: int) -> bool:
        """检查 PE 文件是否有数字签名"""
        try:
            num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
            section_table_off = pe_offset + 24 + size_optional

            # 检查证书表
            magic = struct.unpack_from('<H', data, pe_offset + 24)[0]
            if magic == 0x20B:
                cert_dir_off = pe_offset + 24 + 112 + 8 * 4  # Certificate Directory
            else:
                cert_dir_off = pe_offset + 24 + 104 + 8 * 4

            if cert_dir_off + 8 <= len(data):
                cert_rva = struct.unpack_from('<I', data, cert_dir_off)[0]
                cert_size = struct.unpack_from('<I', data, cert_dir_off + 4)[0]
                if cert_rva > 0 and cert_size > 0:
                    return True
            return False
        except Exception:
            return False

    def _analyze_script(self, file_path: str) -> Dict:
        """脚本文件分析"""
        result = {'score': 0, 'reasons': []}
        ext = os.path.splitext(file_path)[1].lower()

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024 * 1024)  # 最多读 1MB

            if ext == '.vbs' or ext == '.js' or ext == '.wsf' or ext == '.jse' or ext == '.vbe':
                dangerous_patterns = [
                    (r'(?i)(eval|execute|exec)\s*\(', 15, '使用了 eval/execute 执行代码'),
                    (r'(?i)CreateObject\s*\(\s*["\'](Shell\.Application|WScript|Scripting|ADODB|XMLHTTP|WinHttp)', 20, '创建危险 COM 对象'),
                    (r'(?i)(Shell\.Run|WScript\.Shell)\.', 15, '使用 Shell 执行命令'),
                    (r'(?i)(FileSystemObject|CreateTextFile|WriteLine)', 10, '文件系统操作'),
                    (r'(?i)(XMLHttpRequest|WinHttpRequest|ServerXMLHTTP)', 15, '网络请求'),
                    (r'(?i)(regwrite|regdelete|wsh\.shell)', 10, '注册表操作'),
                    (r'(?i)CreateObject\s*\(\s*["\'](Outlook|CDO|ActiveX)', 20, '邮件发送组件'),
                ]
                for pattern, score, desc in dangerous_patterns:
                    if re.search(pattern, content):
                        result['score'] += score
                        result['reasons'].append(desc)

            elif ext in {'.bat', '.cmd'}:
                dangerous_patterns = [
                    (r'(?i)(reg add|reg delete|reg query)', 10, '注册表操作'),
                    (r'(?i)(net user|net localgroup)', 15, '用户管理操作'),
                    (r'(?i)(schtasks|at\s)', 10, '计划任务操作'),
                    (r'(?i)(certutil|bitsadmin|powershell)', 15, '可疑系统工具调用'),
                    (r'(?i)start\s+http', 5, '打开外部链接'),
                    (r'(?i)del\s+/[s/q]', 10, '批量删除文件'),
                    (r'(?i)format\s+[a-z]:', 20, '格式化操作'),
                ]
                for pattern, score, desc in dangerous_patterns:
                    if re.search(pattern, content):
                        result['score'] += score
                        result['reasons'].append(desc)

            elif ext == '.ps1':
                dangerous_patterns = [
                    (r'(?i)(Invoke-Expression|iex)\b', 15, '执行动态代码'),
                    (r'(?i)(DownloadString|DownloadData)', 15, '从网络下载代码'),
                    (r'(?i)(Invoke-WebRequest|Invoke-RestMethod)', 10, '网络请求'),
                    (r'(?i)(Set-ExecutionPolicy|Bypass)', 10, '绕过执行策略'),
                    (r'(?i)(New-Object|Create-Object).*Net\.WebClient', 15, '创建 WebClient 对象'),
                    (r'(?i)(Encrypt|Decrypt|AES|RSA)', 10, '加密操作'),
                ]
                for pattern, score, desc in dangerous_patterns:
                    if re.search(pattern, content):
                        result['score'] += score
                        result['reasons'].append(desc)

        except Exception as e:
            logger.debug(f'脚本分析异常: {e}')

        return result

    def _check_heuristics(self, file_path: str, basename: str, ext: str) -> Tuple[int, List[str]]:
        """启发式规则匹配"""
        score = 0
        reasons = []

        if not self._sig_db:
            return score, reasons

        try:
            rules = self._sig_db.get_heuristic_rules()
            for rule in rules:
                rule_type = rule.get('rule_type', '')
                pattern = rule.get('pattern', '')
                threshold = rule.get('threshold', 1)
                severity = rule.get('severity', 'medium')
                rule_name = rule.get('name', '')

                try:
                    if rule_type == 'filename':
                        matches = len(re.findall(pattern, basename))
                        if matches >= threshold:
                            rule_score = self._severity_to_score(severity) * min(matches, 3)
                            score += rule_score
                            reasons.append(f'启发式规则 "{rule_name}" 匹配 ({matches}次)')
                    elif rule_type == 'extension':
                        if re.search(pattern, ext):
                            rule_score = self._severity_to_score(severity)
                            score += rule_score
                            reasons.append(f'启发式规则 "{rule_name}" 匹配扩展名')
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f'启发式检查异常: {e}')

        return score, reasons

    def _severity_to_score(self, severity: str) -> int:
        """严重级别转分数"""
        return {
            'critical': 25,
            'high': 20,
            'medium': 12,
            'low': 5,
        }.get(severity, 10)

    def _extract_suspicious_strings_from_data(self, data: bytes, file_type: str = '') -> List[str]:
        """提取可疑字符串特征（基于内存数据，性能优化版）

        对非PE文件限制扫描大小，避免大文本文件上的正则性能问题。
        """
        strings = []
        try:
            # 非PE文件限制扫描大小（脚本文件通常较小）
            if file_type == 'script':
                scan_data = data[:256 * 1024]  # 脚本：256KB
            else:
                scan_data = data[:1024 * 1024]  # PE/其他：1MB

            # 提取 ASCII 字符串 (6字符以上)
            ascii_strings = re.findall(rb'[\x20-\x7e]{6,}', scan_data)
            for s in ascii_strings:
                try:
                    decoded = s.decode('ascii', errors='ignore')
                    decoded_lower = decoded.lower()
                    for keyword in MALWARE_KEYWORDS:
                        # 使用词边界匹配，避免子串误匹配（如 'dos' 匹配 'windows'）
                        if re.search(r'\b' + re.escape(keyword) + r'\b', decoded_lower):
                            strings.append(decoded[:100])
                            break
                except Exception:
                    pass

            # 提取 URL/IP
            url_patterns = [
                rb'https?://[^\s\x00-\x1f"\'<>]+',
                rb'ftp://[^\s\x00-\x1f"\'<>]+',
                rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b',
            ]
            for pattern in url_patterns:
                matches = re.findall(pattern, scan_data)
                for m in matches[:5]:
                    if isinstance(m, tuple):
                        m = m[0]
                    try:
                        decoded = m.decode('ascii', errors='ignore')
                        if decoded not in strings:
                            strings.append(decoded[:100])
                    except Exception:
                        pass

            # 提取注册表路径
            reg_patterns = [
                rb'HKEY_[A-Z_]+\\[^\s\x00-\x1f"\'<>]{5,}',
                rb'Software\\[A-Za-z0-9_\\-]+',
            ]
            for pattern in reg_patterns:
                matches = re.findall(pattern, scan_data)
                for m in matches[:3]:
                    try:
                        decoded = m.decode('ascii', errors='ignore')
                        if decoded not in strings:
                            strings.append(decoded[:100])
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f'字符串提取异常: {e}')

        return strings[:20]

    def _check_filename(self, basename: str) -> Tuple[int, List[str]]:
        """文件名特征分析"""
        score = 0
        reasons = []
        name_lower = basename.lower()

        # 多重后缀名伪装（如 virus.exe.txt、virus.pdf.exe.jpg）
        # 可执行扩展名后接一个或多个伪装扩展名，真实扩展名被隐藏在中间
        disguise_ext = re.search(
            r'\.(exe|dll|scr|pif|com|bat|cmd|vbs|ps1|js)(\.(txt|doc|xls|pdf|jpg|jpeg|png|gif|bmp|webp|zip|rar|7z|docx|xlsx|pptx))+$',
            name_lower
        )
        if disguise_ext:
            score += 30
            reasons.append(f'多重后缀名伪装: {basename}')

        # 关键词匹配（使用词边界，避免子串误匹配）
        for keyword in MALWARE_KEYWORDS:
            if re.search(r'\b' + re.escape(keyword) + r'\b', name_lower):
                score += 10
                reasons.append(f'文件名包含可疑关键词: {keyword}')
                break

        # 随机命名检测
        name_without_ext = os.path.splitext(name_lower)[0]
        if re.match(r'^[a-z0-9]{8,}$', name_without_ext):
            score += 5
            reasons.append('文件名疑似随机生成')

        return score, reasons

    def _classify_malware(self, result: Dict) -> str:
        """分类恶意软件类型"""
        reasons_text = ' '.join(result.get('reasons', []))
        imports = result.get('signatures', {}).get('suspicious_imports', [])
        strings = result.get('signatures', {}).get('strings', [])
        imports_text = ' '.join(imports)
        strings_text = ' '.join(strings)
        all_text = (reasons_text + imports_text + strings_text).lower()

        classification_rules = [
            ('Ransomware', ['encrypt', 'crypt', 'ransom', 'locker', 'bitcoin', 'decrypt']),
            ('Trojan', ['trojan', 'backdoor', 'dropper', 'downloader', 'loader']),
            ('Keylogger', ['keylog', 'keystroke', 'keyboard', 'getasynckeystate', 'getkeystate']),
            ('Spyware', ['spy', 'steal', 'credential', 'password', 'infostolen']),
            ('Miner', ['miner', 'coin', 'bitcoin', 'cryptominer', 'cpu']),
            ('Worm', ['worm', 'spread', 'propagate', 'replicate']),
            ('Rootkit', ['rootkit', 'kernel', 'driver', 'hide']),
            ('Botnet', ['botnet', 'irc', 'ddos', 'command']),
            ('Virus', ['virus', 'infect', 'replicate', 'self']),
            ('Joke', ['joke', 'prank', 'hoax', '恶搞', 'setcursorpos', 'systemparametersinfo',
                       'blockinput', 'swapmousebutton', 'showcursor', 'changedisplaysettings',
                       '鼠标控制', '系统参数修改', '阻断键鼠输入', '交换鼠标按键',
                       '隐藏光标', '修改显示设置', '恶搞程序行为组合']),
        ]

        for malware_type, keywords in classification_rules:
            for keyword in keywords:
                if keyword in all_text:
                    return malware_type

        return 'Trojan'

    def _generate_yara_features(self, result: Dict) -> List[str]:
        """生成 YARA 规则特征"""
        features = []
        strings = result.get('signatures', {}).get('strings', [])
        imports = result.get('signatures', {}).get('suspicious_imports', [])
        sha256 = result.get('signatures', {}).get('sha256', '')

        if sha256:
            features.append(f'hash_sha256={sha256}')

        if imports:
            import_str = ', '.join(imports[:5])
            features.append(f'suspicious_imports={import_str}')

        if strings:
            str_examples = strings[:3]
            features.append(f'strings={str_examples}')

        entropy = result.get('file_info', {}).get('entropy', 0)
        if entropy > 7.2:
            features.append(f'high_entropy={entropy:.2f}')

        return features


def identify_file(file_path: str, signature_db=None) -> Dict:
    """便捷函数：识别单个文件"""
    identifier = VirusIdentifier(signature_db)
    return identifier.identify(file_path)
