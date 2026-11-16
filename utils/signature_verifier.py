# -*- coding: utf-8 -*-
"""
数字签名验证模块

架构：
- verify_signature  → WinVerifyTrust（纯 ctypes，<1ms，对 Authenticode 签名文件有效）
- get_signer_info   → verify_signature + lazy PowerShell fallback 获取 publisher
- 类级别共享缓存：进程内所有实例共享 _VERIFY_CACHE / _SIGNER_CACHE

注意：WinVerifyTrust 默认只验证 Embedded Authenticode 签名，
Catalog 签名的系统文件会返回 NOSIGNATURE —— 这些文件在可信目录已被跳过。
"""
import os
import sys
import time
import threading
import subprocess
from typing import Optional, Dict

from utils.logger import get_logger

logger = get_logger('signature_verifier')

try:
    import ctypes
    import ctypes.wintypes
    HAS_CTYPES = True
except ImportError:
    HAS_CTYPES = False
    ctypes = None


# ============ Windows 结构体定义 ============

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.wintypes.DWORD),
        ("Data2", ctypes.wintypes.WORD),
        ("Data3", ctypes.wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8)
    ]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pcwszFilePath", ctypes.wintypes.LPCWSTR),
        ("hFile", ctypes.wintypes.HANDLE),
        ("pgKnownSubject", ctypes.wintypes.LPVOID)
    ]


class WINTRUST_DATA_UNION(ctypes.Union):
    _fields_ = [
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("pCatalog", ctypes.wintypes.LPVOID),
        ("pBlob", ctypes.wintypes.LPVOID),
        ("pSgnr", ctypes.wintypes.LPVOID),
        ("pCert", ctypes.wintypes.LPVOID)
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.wintypes.LPVOID),
        ("pSIPClientData", ctypes.wintypes.LPVOID),
        ("dwUIChoice", ctypes.wintypes.DWORD),
        ("fdwRevocationChecks", ctypes.wintypes.DWORD),
        ("dwUnionChoice", ctypes.wintypes.DWORD),
        ("u", WINTRUST_DATA_UNION),
        ("dwStateAction", ctypes.wintypes.DWORD),
        ("hWVTStateData", ctypes.wintypes.HANDLE),
        ("pwszURLReference", ctypes.wintypes.LPCWSTR),
        ("dwProvFlags", ctypes.wintypes.DWORD),
        ("dwUIContext", ctypes.wintypes.DWORD),
        ("pSignatureSettings", ctypes.wintypes.LPVOID)
    ]


# WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)

# 状态动作常量
WTD_STATEACTION_VERIFY = 0x00000001
WTD_STATEACTION_CLOSE = 0x00000002
WTD_REVOKE_NONE = 0x00000000
WTD_REVOKE_WHOLECHAIN = 0x00000001


class SignatureVerifier:
    """数字签名验证器（类级别共享缓存）"""

    _VERIFY_CACHE: Dict[tuple, bool] = {}
    _SIGNER_CACHE: Dict[tuple, Optional[Dict]] = {}
    _CACHE_LOCK = threading.Lock()
    _MAX_CACHE = 8192

    def __init__(self):
        self._available = HAS_CTYPES and sys.platform == 'win32'
        self._wintrust = None
        self._WinVerifyTrust = None
        if self._available:
            self._init_wintrust()

    # ---- 签名缓存可观测接口（升级5：validate / stats / reset）----
    @classmethod
    def cache_stats(cls) -> dict:
        """返回签名缓存规模统计（供可观测性/状态页展示）。"""
        with cls._CACHE_LOCK:
            return {
                'verify_cached': len(cls._VERIFY_CACHE),
                'signer_cached': len(cls._SIGNER_CACHE),
                'max_cached': cls._MAX_CACHE,
            }

    @classmethod
    def cache_clear(cls) -> None:
        """清空签名缓存（配置变更/阈值调整后用）。"""
        with cls._CACHE_LOCK:
            cls._VERIFY_CACHE.clear()
            cls._SIGNER_CACHE.clear()

    @classmethod
    def _cache_key(cls, file_path: str) -> Optional[tuple]:
        try:
            st = os.stat(file_path)
            return (file_path.lower(), st.st_mtime, st.st_size)
        except OSError:
            return None

    @classmethod
    def _cache_get(cls, cache: Dict, key: tuple):
        with cls._CACHE_LOCK:
            return cache.get(key)

    @classmethod
    def _cache_put(cls, cache: Dict, key: tuple, value):
        with cls._CACHE_LOCK:
            if len(cache) >= cls._MAX_CACHE:
                to_del = list(cache.keys())[:len(cache) // 2]
                for k in to_del:
                    del cache[k]
            cache[key] = value

    def _init_wintrust(self):
        try:
            self._wintrust = ctypes.WinDLL('wintrust', use_last_error=True)
            self._WinVerifyTrust = self._wintrust.WinVerifyTrust
            self._WinVerifyTrust.restype = ctypes.wintypes.LONG
            self._WinVerifyTrust.argtypes = [
                ctypes.wintypes.HWND,
                ctypes.POINTER(GUID),
                ctypes.c_void_p
            ]
        except Exception as e:
            logger.warning(f'初始化 wintrust DLL 失败: {e}')
            self._available = False

    def is_available(self) -> bool:
        return self._available

    def verify_signature(self, file_path: str) -> bool:
        """验证文件的数字签名（WinVerifyTrust + 类级别共享缓存）

        对 Embedded Authenticode 签名文件有效（<1ms）。
        Catalog 签名的系统文件会返回 False（这些文件在可信目录被跳过）。
        """
        if not self._available or not os.path.isfile(file_path):
            return False

        cache_key = self._cache_key(file_path)
        if cache_key:
            cached = self._cache_get(self._VERIFY_CACHE, cache_key)
            if cached is not None:
                return cached

        result = self._verify_raw(file_path)

        if cache_key:
            self._cache_put(self._VERIFY_CACHE, cache_key, result)
        return result

    def _verify_raw(self, file_path: str) -> bool:
        """WinVerifyTrust 原生调用（无缓存）"""
        try:
            fi = WINTRUST_FILE_INFO()
            fi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            fi.pcwszFilePath = os.path.abspath(file_path)
            fi.hFile = None
            fi.pgKnownSubject = None

            wt_union = WINTRUST_DATA_UNION()
            wt_union.pFile = ctypes.pointer(fi)

            td = WINTRUST_DATA()
            td.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            td.dwUIChoice = 2  # WTD_UI_NONE
            td.fdwRevocationChecks = WTD_REVOKE_NONE  # 离线兼容
            td.dwUnionChoice = 1  # WTD_CHOICE_FILE
            td.u = wt_union
            td.dwStateAction = WTD_STATEACTION_VERIFY
            td.hWVTStateData = None
            td.pwszURLReference = None
            td.dwProvFlags = 0
            td.dwUIContext = 0
            td.pSignatureSettings = None

            result = self._WinVerifyTrust(
                None,
                ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(td)
            )

            td.dwStateAction = WTD_STATEACTION_CLOSE
            self._WinVerifyTrust(
                None,
                ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(td)
            )

            return result == 0  # ERROR_SUCCESS
        except Exception:
            return False

    def is_signed(self, file_path: str) -> bool:
        return self.verify_signature(file_path)

    def get_signer_info(self, file_path: str) -> Optional[Dict]:
        """获取签名发布者信息（WinVerifyTrust + lazy PowerShell fallback + 缓存）

        Returns: {'verified': bool, 'publisher': str, 'sign_time': str}
        """
        if not self._available or not os.path.isfile(file_path):
            return None

        cache_key = self._cache_key(file_path)
        if cache_key:
            cached = self._cache_get(self._SIGNER_CACHE, cache_key)
            if cached is not None:
                return cached

        verified = self.verify_signature(file_path)
        result = {'verified': verified, 'publisher': '', 'sign_time': ''}

        if verified:
            publisher = self._get_publisher_powershell(file_path)
            if publisher:
                result['publisher'] = publisher

        # 灰名单分层：随签名信息一起缓存，调用方无需再次判定
        result['tier'] = classify_signer(
            result.get('verified'), result.get('publisher'))

        if cache_key:
            self._cache_put(self._SIGNER_CACHE, cache_key, result)
        return result

    @staticmethod
    def _get_publisher_powershell(file_path: str) -> str:
        """lazy PowerShell fallback：获取签名 Subject CN（只在缓存未命中时调用）

        第一次调用约 100-300ms（PowerShell 冷启动），但被类级别缓存吸收。
        """
        try:
            abs_path = os.path.abspath(file_path)
            # 用简单命令直接提取 Subject，避免复杂 PS 表达式
            ps_cmd = (
                "$s = Get-AuthenticodeSignature -LiteralPath '%s'; "
                "if ($s.SignerCertificate) { $s.SignerCertificate.Subject }"
                % abs_path.replace("'", "''")
            )
            # 使用 System32 全路径调用 powershell，规避 PATH 注入/重定向
            # （恶意样本可能 IFEO 劫持 powershell.exe 或篡改 PATH）
            ps_exe = os.path.join(
                os.environ.get('SystemRoot', r'C:\Windows'),
                'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
            if not os.path.isfile(ps_exe):
                ps_exe = 'powershell'
            cp = subprocess.run(
                [ps_exe, '-NoProfile', '-NonInteractive', '-Command', ps_cmd],
                capture_output=True, text=True, timeout=10,
                creationflags=0x08000000  # CREATE_NO_WINDOW
            )
            subject = (cp.stdout or '').strip()
            if not subject:
                return ''
            # 形如 "CN=Microsoft Windows, O=Microsoft Corporation, ..."
            for part in subject.split(', '):
                part = part.strip()
                if part.upper().startswith('CN='):
                    return part[3:]
            return subject
        except Exception:
            return ''


# ============ 可信发布者名单（需求: 无签名/未知发布者一律送检）============
# 仅当 Authenticode 签名有效 (verified=True) 时，发布者命中本名单才视为"可信来源"。
# Catalog/APPPKG 签名的系统文件会被 WinVerifyTrust 判为无签名 (verified=False)，
# 由 process_protection 的 CI 深层系统目录豁免路径兜底，不在此名单处理。
TRUSTED_PUBLISHER_KEYWORDS = (
    'microsoft', 'windows',                    # 微软
    'google',                                  # Google
    'mozilla',                                 # Mozilla
    'adobe',                                   # Adobe
    'apple',                                   # Apple
    'nvidia',                                  # NVIDIA
    'tencent', '腾讯',                          # 腾讯
    'alibaba', '阿里巴巴',                       # 阿里
    'bytedance', '字节跳动', 'douyin', '抖音',    # 字节跳动
    'huawei', '华为',                           # 华为
    # ===== 安全软件（防 PSLS 与其他杀软互杀死锁）=====
    # 卡巴斯基 avp.exe 有强自我保护，若被判"非信任"会被反复杀→自动重启，
    # 造成 taskkill 死循环 + 系统卡顿（未响应）。签名有效+发布者命中即放行。
    'kaspersky', '卡巴',                        # Kaspersky
    '360', 'qihoo',                            # 360 / 奇虎
    'avast', 'avg',                            # Avast / AVG
    'eset',                                    # ESET
    'bitdefender',                             # Bitdefender
    'malwarebytes',                            # Malwarebytes
    'symantec', 'norton', '赛门铁克', '诺顿',      # Broadcom / Symantec / Norton
    'mcafee',                                  # McAfee
    'trend micro', '趋势科技',                   # Trend Micro
    'sophos', 'comodo',                        # Sophos / Comodo
    'crowdstrike', 'sentinelone', 'webroot',   # EDR 厂商
)


def is_trusted_publisher(publisher: str) -> bool:
    """判断签名发布者是否命中可信大厂名单（子串匹配、大小写不敏感）。

    Args:
        publisher: 发布者名称（Authenticode 签名 Subject CN，如
            "Microsoft Windows" / "Tencent Technology(Shenzhen) Company Limited"）。

    Returns:
        True=可信发布者；空串/未知一律 False（调用方仅在 verified=True 时调用）。
    """
    low = (publisher or '').lower()
    return any(kw in low for kw in TRUSTED_PUBLISHER_KEYWORDS)


# ============ 签名灰名单分层（升级3：二态 → 四级）============
# 把"可信/不可信"二态扩展为四层，供进程送检 / 驱动信任 / 扫描判定按层差异化处置：
#   SIGNER_TIER_UNSIGNED      # 无签名 或 WinVerifyTrust 无法确认（含 Catalog 伪无签名）
#   SIGNER_TIER_INVALID       # 有签名但验证失败（被篡改 / 证书撤销，最高风险）
#   SIGNER_TIER_KNOWN         # 已签名 + 发布者命知名厂商名单（强放行）
#   SIGNER_TIER_MISC          # 已签名 + 发布者不在名单内（"灰名单"：可放行但值得记录/可选送检）
SIGNER_TIER_UNSIGNED = 'unsigned'
SIGNER_TIER_INVALID = 'invalid'
SIGNER_TIER_KNOWN = 'known'
SIGNER_TIER_MISC = 'misc'

# 分层处置策略（供消费方快速映射决策）
TIER_STRONG_PASS = frozenset({SIGNER_TIER_KNOWN})
TIER_SOFT_PASS = frozenset({SIGNER_TIER_KNOWN, SIGNER_TIER_MISC})
TIER_INSPECT = frozenset({SIGNER_TIER_UNSIGNED, SIGNER_TIER_INVALID})


def classify_signer(verified: Optional[bool], publisher: str = '') -> str:
    """将签名验证结果归一化为四级档次。

    Args:
        verified: get_signer_info()['verified']（None=验证器不可用/未知）。
        publisher: 发布者名称（仅 verified=True 时有效）。

    Returns:
        一个 SIGNER_TIER_* 值。
    """
    if verified is True:
        return SIGNER_TIER_KNOWN if is_trusted_publisher(publisher) else SIGNER_TIER_MISC
    if verified is False:
        return SIGNER_TIER_INVALID
    return SIGNER_TIER_UNSIGNED


# ============ 全局单例 ============
_verifier: Optional[SignatureVerifier] = None


def get_verifier() -> SignatureVerifier:
    global _verifier
    if _verifier is None:
        _verifier = SignatureVerifier()
    return _verifier


def verify_file_signature(file_path: str) -> bool:
    return get_verifier().verify_signature(file_path)
