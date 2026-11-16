import os
import re
import sys
import math
import threading
import multiprocessing
from typing import List, Dict, Callable, Optional
from db.signature_db import SignatureDB
from utils.file_walker import FileWalker
from utils.hash_utils import compute_sha256, open_with_retry
from utils.fuzzy_hash import fuzzy_file, fuzzy_compare
from utils.archive_scanner import ArchiveScanner
from utils.logger import get_logger
from utils import load_governor
from engine.rule_engine import RuleEngine
from engine.pe_analyzer import PEAnalyzer
# —— PeAV 借鉴的统一置信评分 / ApiHash 证据 / 指纹学习 ——
try:
    from engine.threat_scorer import compute_confidence, confirm_suspicious, CONF_SUSPICIOUS
    from engine.api_evidence import compute_api_evidence as _compute_api_evidence_signal
    from engine.study_engine import StudyEngine
    _HAS_UNIFIED = True
except Exception:  # pragma: no cover - 依赖缺失时优雅降级
    _HAS_UNIFIED = False
    compute_confidence = None
    confirm_suspicious = None
    CONF_SUSPICIOUS = 56.0
    _compute_api_evidence_signal = None
    StudyEngine = None

logger = get_logger('scan_engine')

class ScanResult:
    """扫描结果类"""
    
    def __init__(self, file_path: str, status: str, malware_info: Dict = None, 
                 heuristic_matches: List[Dict] = None, internal_path: str = '',
                 pe_analysis: Dict = None, rule_matches: List[Dict] = None):
        self.file_path = file_path
        self.status = status  # 'clean', 'malware', 'suspicious', 'error'
        self.malware_info = malware_info or {}
        self.heuristic_matches = heuristic_matches or []
        self.internal_path = internal_path  # 归档内文件路径
        self.pe_analysis = pe_analysis or {}  # PE分析结果
        self.rule_matches = rule_matches or []  # 规则引擎匹配结果
    
    def to_dict(self) -> Dict:
        return {
            'file_path': self.file_path,
            'status': self.status,
            'malware_info': self.malware_info,
            'heuristic_matches': self.heuristic_matches,
            'internal_path': self.internal_path,
            'pe_analysis': self.pe_analysis,
            'rule_matches': self.rule_matches,
        }


# ========== 多进程扫描支持（模块级函数和全局变量）==========
# 每个子进程通过 initializer 初始化一次，避免每个文件重复创建实例

# ========== 阈值配置（严格模式 vs 宽松模式）==========
# 严格模式下所有引擎阈值下调，提升敏感性（配合多维交叉验证控制误报）
# PE 分析阈值
PE_MALWARE_THRESHOLD_NORMAL = 90        # 宽松：≥90 → malware
PE_MALWARE_THRESHOLD_STRICT = 70        # 严格：≥70 → malware
PE_SUSPICIOUS_THRESHOLD_NORMAL = 40     # 宽松：≥40 → suspicious
PE_SUSPICIOUS_THRESHOLD_STRICT = 25     # 严格：≥25 → suspicious

# ========== 可信签名发布者（降误报核心：已签名 + 可信发布者 → medium 以下规则自动降级）==========
# 这些发布者的数字签名意味着文件经过代码完整性校验，medium/info 级 YARA/启发式规则不应误报
TRUSTED_SIGNER_SUBSTRINGS = (
    # 微软生态（覆盖 Windows 签名、.NET 框架、Azure、VS、Office 全家桶）
    'microsoft corporation', 'microsoft windows', 'microsoft',
    'microsoft publisher', 'windows publisher',
    '.net', 'microsoft .net', 'visual studio', 'nuget',
    'azure', 'microsoft azure', 'bing', 'msn', 'xbox',
    'office', 'microsoft office', 'sharepoint', 'teams',
    'powershell', 'sql server', 'dynamics',
    'skype', 'oneDrive', 'outlook',
    # Sysinternals（Mark Russinovich 签的 Sysinternals 工具集）
    'sysinternals',
    # 其他可信大厂（常见企业软件，误报率极低）
    'adobe systems', 'adobe',
    'google', 'google llc', 'chrome',
    'mozilla', 'firefox',
    'apple', 'apple inc',
    'intel', 'intel corporation',
    'amd',
    'nvidia',
    'oracle', 'oracle corporation', 'java',
    'vmware', 'vmware, inc.',
    'cisco', 'cisco systems',
    'red hat', 'redhat',
    'github', 'github inc',
    'dropbox', 'slack',
    # 腾讯生态（QQ/QQNT/微信/腾讯会议/QQ音乐/游戏平台全家桶；数字签名即代码完整性保证，
    # 否则 QQ 各组件（主程序/更新器/语音 DLL 等）会反复命中 YARA/ML/PE/熵等启发式误报）
    'tencent',
    '腾讯',
)
# 熵检测阈值
ENTROPY_THRESHOLD_NORMAL = 7.6          # 宽松：> 7.6 → suspicious
ENTROPY_THRESHOLD_STRICT = 7.3          # 严格：> 7.3 → suspicious
# 压缩/编码媒体格式 — 天然高熵，熵检测直接跳过
_ENTROPY_SKIP_EXTS = frozenset({
    # 图片（PNG/JPEG/WebP 等压缩格式熵 ≈ 7.7-7.9）
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff', '.tif', '.ico', '.heic',
    '.jpe', '.jfif', '.avif',
    # 音视频（MP3/MP4/OGG 等编码后熵 ≈ 7.5-7.9；AMR/OGG Opus 语音编码同理）
    '.mp3', '.flac', '.wav', '.ogg', '.m4a', '.wma', '.aac', '.amr', '.amrwb',
    '.opus', '.caf', '.mid', '.midi',
    '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.ts', '.3gp',
    '.3gpp', '.m4v',
    # 压缩包/安装包（ZIP/7Z/MSI 本身就是压缩流）
    '.zip', '.rar', '.7z', '.gz', '.bz2', '.xz', '.tar', '.tgz', '.cab', '.msi',
    '.arj', '.lz', '.lzma', '.zst', '.iso', '.img',
    # 文档（DOCX/PDF 内部有压缩流）
    '.pdf', '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp',
    # QQ/微信/钉钉 等 IM 聊天缓存（图片/语音/视频下载后的原始格式）
    '.dat', '.cache', '.bak', '.tmp', '.bin',
})
# 用户数据目录（Documents/Downloads/Desktop/OneDrive/Tencent Files 等）
# — 这些目录下的文件基本都是用户自己的数据，熵检测完全误报
# 用路径前缀匹配，统一小写后比较
_USER_DATA_DIR_KEYS = (
    '\\documents\\', '\\downloads\\', '\\desktop\\', '\\onedrive\\',
    '\\pictures\\', '\\videos\\', '\\music\\',
    '\\tencent files\\', '\\wechat\\', '\\x5\\', '\\weixin\\',
    '\\douyin\\', '\\bytedance\\', '\\dingtalk\\', '\\alibaba\\',
    '\\steam\\steamapps\\', '\\epic games\\',
    '\\appdata\\local\\temp\\', '\\appdata\\local\\microsoft\\windows\\temporary internet files\\',
    '\\$recycle.bin\\',
)

# 纯数据/配置文件扩展名 — 这些文件是文本、配置、资源、翻译、HTML、媒体元数据等,
# 不含可执行代码, 必须跳过 content 规则、packer 节区、可疑 API 组合等
# "二进制特征检测"。只做文件名/扩展名规则检查。
# 这是降误报的关键修复: NVIDIA 驱动包 i18n JSON、Chrome 扩展 manifest、
# VSCode 配置等都是纯数据文件, 绝不应被启发式误报。
_PURE_DATA_EXTENSIONS = frozenset({
    # 配置/数据格式
    '.json', '.xml', '.yaml', '.yml', '.ini', '.cfg', '.conf', '.properties',
    '.toml', '.env', '.reg', '.pol',
    # 文本/文档
    '.txt', '.md', '.log', '.csv', '.tsv', '.rtf',
    # 网络前端
    '.html', '.htm', '.css', '.scss', '.sass', '.less', '.jsonc', '.webmanifest',
    # 安装包资源
    '.resx', '.rc', '.dic', '.iss', '.nsi', '.nsh', '.iss',
    # OEM/驱动包特有
    '.inf', '.cat', '.sysfx', '.hlp', '.chm',
    # 脚本源代码 (注意: .ps1/.vbs/.js/.bat/.cmd 这些可执行脚本不在此列)
    '.py', '.pl', '.rb', '.sh', '.bash', '.zsh',
    '.sql', '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.go', '.rs', '.ts',
    # 媒体元数据
    '.ass', '.srt', '.sub', '.vtt',
})

# 可执行脚本扩展名 — 这些可以直接执行代码, 属于启发式重点扫描对象
_EXECUTABLE_SCRIPT_EXTS = frozenset({
    '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.jse', '.vbe', '.hta',
    '.jsx', '.mjs', '.cjs',
})


def _is_in_user_data_dir(file_path: str) -> bool:
    """判断文件是否在用户数据目录（熵检测应对这些目录关闭）"""
    try:
        pl = file_path.lower().replace('/', '\\')
        return any(k in pl for k in _USER_DATA_DIR_KEYS)
    except Exception:
        return False
# 规则引擎：宽松模式需 2 个 low，严格模式 1 个 low 即触发
RULE_LOW_THRESHOLD_NORMAL = 2
RULE_LOW_THRESHOLD_STRICT = 1
# medium 规则需 ≥2 条才判定 suspicious（避免单条 medium 启发式/规则误报大量白样本）
RULE_MEDIUM_THRESHOLD_NORMAL = 2
RULE_MEDIUM_THRESHOLD_STRICT = 2
# ML 阈值（严格模式下降低）
ML_MALWARE_THRESHOLD_NORMAL = 0.82
ML_MALWARE_THRESHOLD_STRICT = 0.75
ML_SUSPICIOUS_THRESHOLD_NORMAL = 0.65
ML_SUSPICIOUS_THRESHOLD_STRICT = 0.55

# ---------- .lnk 快捷方式解析与检测 ----------
# .lnk 是指向其他文件的快捷方式，自身不含可执行代码。
# 直接对 .lnk 二进制做 content 规则/启发式/ViiD 分析会产生大量误报
# （二进制中嵌入的目标路径/命令行参数被当作可疑字符串）。
# 正确做法：解析 .lnk 目标，对目标路径和参数做安全评估。

# 常被恶意快捷方式利用的 Windows 原生解释器
_SUSPICIOUS_LNK_TARGETS = frozenset({
    'powershell.exe', 'powershell_ise.exe',
    'cmd.exe', 'cscript.exe', 'wscript.exe', 'mshta.exe',
    'regsvr32.exe', 'rundll32.exe', 'msiexec.exe',
    'certutil.exe', 'bitsadmin.exe', 'msbuild.exe',
    'installutil.exe', 'regasm.exe', 'regsvcs.exe',
    'forfiles.exe', 'scriptrunner.exe',
})

# 参数中的可疑模式（正则）
_SUSPICIOUS_LNK_ARG_PATTERNS = [
    (re.compile(r'-enc(?:\s|$|")', re.I), 'PowerShell 编码执行', 'high'),
    (re.compile(r'-e(?:\s|")\s*-', re.I), 'PowerShell 编码执行', 'high'),
    (re.compile(r'executionpolicy\s+(?:bypass|unrestricted|remotesigned)', re.I), '执行策略绕过', 'high'),
    (re.compile(r'downloadstring|downloadfile', re.I), '网络下载', 'high'),
    (re.compile(r'iex\s*\(|invoke-expression', re.I), '动态执行表达式', 'high'),
    (re.compile(r'invoke-\w+', re.I), 'PowerShell 攻击框架命令', 'medium'),
    (re.compile(r'/c\s+', re.I), 'CMD 命令执行', 'medium'),
    (re.compile(r'/k\s+', re.I), 'CMD 命令执行', 'medium'),
    (re.compile(r'(?:javascript|vbscript):', re.I), '脚本协议注入', 'high'),
    (re.compile(r'\\.*\.(?:dll|ocx)\b', re.I), '加载 DLL/OCX', 'medium'),
    (re.compile(r'frombase64string|base64', re.I), 'Base64 解码', 'medium'),
]


def _parse_lnk_file(file_path: str) -> dict:
    """解析 .lnk 快捷方式文件，提取目标路径和参数。

    通过二进制解析 MS-SHLINK 格式（不依赖 COM），适用于多进程 worker。
    返回 {'target_path': str, 'arguments': str, 'working_dir': str} 或 None。
    """
    import struct
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except Exception:
        return None
    if len(data) < 76:
        return None

    try:
        header_size = struct.unpack_from('<I', data, 0)[0]
        flags = struct.unpack_from('<I', data, 4)[0]
    except Exception:
        return None

    has_link_target_idlist = bool(flags & 0x00000001)
    has_link_info = bool(flags & 0x00000002)
    has_name = bool(flags & 0x00000004)
    has_relative_path = bool(flags & 0x00000008)
    has_working_dir = bool(flags & 0x00000010)
    has_arguments = bool(flags & 0x00000020)
    has_icon_location = bool(flags & 0x00000040)

    offset = header_size
    if offset >= len(data):
        return None

    # 跳过 LinkTargetIDList
    if has_link_target_idlist:
        if offset + 2 > len(data):
            return None
        idlist_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2 + idlist_size
        if offset >= len(data):
            return None

    # 跳过 LinkInfo
    if has_link_info:
        if offset + 4 > len(data):
            return None
        link_info_size = struct.unpack_from('<I', data, offset)[0]
        offset += link_info_size
        if offset >= len(data):
            return None

    # 读取 StringData 段（按固定顺序）
    strings = {}
    string_order = [
        (has_name, 'name'),
        (has_relative_path, 'relative_path'),
        (has_working_dir, 'working_dir'),
        (has_arguments, 'arguments'),
        (has_icon_location, 'icon_location'),
    ]
    for has_flag, key in string_order:
        if not has_flag:
            continue
        if offset + 2 > len(data):
            break
        char_count = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if char_count == 0:
            strings[key] = ''
            continue
        byte_count = char_count * 2
        if offset + byte_count > len(data):
            break
        try:
            strings[key] = data[offset:offset + byte_count].decode('utf-16-le', errors='ignore')
        except Exception:
            strings[key] = ''
        offset += byte_count

    working_dir = strings.get('working_dir', '')
    relative_path = strings.get('relative_path', '')
    arguments = strings.get('arguments', '')

    target_path = ''
    if relative_path:
        if working_dir:
            target_path = os.path.normpath(os.path.join(working_dir, relative_path))
        else:
            target_path = relative_path

    return {
        'target_path': target_path,
        'arguments': arguments,
        'working_dir': working_dir,
        'relative_path': relative_path,
    }


def _check_lnk_suspicious(lnk_info: dict) -> list:
    """评估 .lnk 快捷方式的目标是否可疑。

    返回可疑匹配列表 [{'name': str, 'severity': str}] 或空列表。
    """
    matches = []
    target_path = (lnk_info.get('target_path') or '').strip()
    arguments = (lnk_info.get('arguments') or '').strip()
    if not target_path and not arguments:
        return matches

    target_lower = os.path.basename(target_path).lower()

    # 1. 目标是高危解释器
    is_suspicious_target = False
    if target_lower in _SUSPICIOUS_LNK_TARGETS:
        is_suspicious_target = True
        matches.append({'name': f'快捷方式指向高危解释器: {target_lower}',
                        'severity': 'medium', 'rule_type': 'builtin_lnk'})

    # 2. 参数含可疑模式
    if arguments:
        for pattern, name, sev in _SUSPICIOUS_LNK_ARG_PATTERNS:
            if pattern.search(arguments):
                # 如果目标是高危解释器且有可疑参数 → 提升到 high
                final_sev = 'high' if is_suspicious_target else sev
                matches.append({'name': f'快捷方式参数可疑: {name}',
                                'severity': final_sev, 'rule_type': 'builtin_lnk'})

    # 3. 目标路径包含 UNC 网络路径（可能的横向移动）
    if target_path.startswith('\\\\') or target_path.lower().startswith('\\\\'):
        matches.append({'name': '快捷方式指向网络路径', 'severity': 'medium',
                        'rule_type': 'builtin_lnk'})

    return matches

_worker_db = None
_worker_rule_engine = None
_worker_pe_analyzer = None
_worker_virus_identifier = None
_worker_archive_scanner = None
# VirusIdentifier 开关（由 bridge 经 _init_scan_worker 注入；默认关闭）
_worker_vi_enabled = False
_worker_malware_hashes = None
_worker_whitelist_cache = None
_worker_heuristic_rules = None
_worker_trusted_dirs = None
_worker_executable_extensions = None
_worker_min_file_size = 1024
_worker_signature_verifier = None
_worker_strict_mode = False
_worker_self_excluded_dirs = None
_worker_user_excluded_dirs = None
_worker_oem_dir_keys = None

# Windows 内核锁定文件：始终跳过扫描（无法读取，且不可能是恶意软件载体）
# 这些文件即使有"可执行扩展名"也不会被扫描器当作恶意
_LOCKED_SYSTEM_FILE_NAMES = frozenset({
    'pagefile.sys',
    'hiberfil.sys',
    'swapfile.sys',
    'dumpstack.log.tmp',
    'dumpstack.log',
    'ntuser.dat',
    'ntuser.dat.log',
    'ntuser.dat.log1',
    'ntuser.dat.log2',
    'ntuser.ini',
    'usrclass.dat',
    'usrclass.dat.log',
    'usrclass.dat.log1',
    'usrclass.dat.log2',
    'iconcache.db',
    'iconcache.db-wal',
    'iconcache.db-shm',
    'thumbcache.db',
    'thumbcache_256.db',
    'thumbcache_1024.db',
    'audit.db',
    'audit.db-wal',
    'audit.db-shm',
    'edb.log',
    'edb00001.log',
})

# 分析结果缓存：hash → {'rule_matches': [...], 'pe_analysis': {...}, 'heuristic_matches': [...]}
# 多进程模式下每个 worker 子进程独立缓存，同 hash 文件（复制/硬链接）跳过重复分析
_worker_analysis_cache: Dict[str, Dict] = {}
_WORKER_ANALYSIS_CACHE_MAX = 2000

# 全局 ML 检测器（扫描 worker 专用）
_worker_ml_detector = None

# ML 参与度可观测计数（扫描 worker 与单进程共用；供平台评测自证 ML 是否参与）。
# 多进程模式下由 _init_scan_worker 注入 Manager 共享字典以汇总到父进程。
_ML_SCAN_STATS = {
    'ml_available': False,
    'ml_called': 0,
    'ml_malware': 0,
    'ml_susp': 0,
    'ml_none': 0,
    'ml_failed': 0,
    'ml_main_unavailable_reason': '',
}
_ML_STATS_LOG_STEP = 500  # 首次 + 每 N 次 ML 调用输出一次累计快照（INFO）


def _ml_stats_incr(key: str, n: int = 1) -> None:
    """累加 ML 参与度计数（异常安全，绝不因计数失败影响扫描）。"""
    try:
        _ML_SCAN_STATS[key] = int(_ML_SCAN_STATS.get(key, 0) or 0) + int(n)
    except Exception:
        pass


def _ml_stats_snapshot() -> Dict:
    """返回 ML 参与度计数快照（只读副本）。"""
    try:
        return dict(_ML_SCAN_STATS)
    except Exception:
        return {}


def _ml_stats_log(reason: str = '', stats: Optional[Dict] = None) -> None:
    """输出 ML 参与度累计快照（INFO，走既有日志通道，绝不写协议通道）。"""
    try:
        s = stats if stats is not None else _ML_SCAN_STATS
        logger.info(
            '[ML统计]%s ml_available=%s ml_called=%d ml_malware=%d ml_susp=%d '
            'ml_none=%d ml_failed=%d reason=%s',
            (' ' + reason) if reason else '', s.get('ml_available'),
            int(s.get('ml_called', 0) or 0), int(s.get('ml_malware', 0) or 0),
            int(s.get('ml_susp', 0) or 0), int(s.get('ml_none', 0) or 0),
            int(s.get('ml_failed', 0) or 0),
            s.get('ml_main_unavailable_reason') or '-')
    except Exception:
        pass


def _vi_cross_confirm(file_path: str, ext: str, pe_analyzer, ml_detector,
                      strict_mode: bool, executable_extensions) -> bool:
    """VirusIdentifier 判恶意时的交叉确认。

    VirusIdentifier 是纯启发式打分引擎（可疑 API 名单 + 关键词 + 熵 + 扩展名
    叠加，>=28 即"high malware"），单独判恶意误报偏高（如正常加壳安装包）。
    这里要求独立引擎（PE 结构分析 / ML）同样认定恶意，才允许最终判恶意；
    两者都不认同时由调用方降级为 suspicious（保留告警，但不自动处置）。

    Returns:
        True  = 有独立引擎交叉确认
        False = 无独立确认（调用方应降级处理）
    """
    # 1) PE 结构分析（仅对可执行扩展名有意义）
    try:
        if pe_analyzer is not None and (
                executable_extensions is None or ext in executable_extensions):
            pa = pe_analyzer.analyze(file_path)
            th = (PE_MALWARE_THRESHOLD_STRICT if strict_mode
                  else PE_MALWARE_THRESHOLD_NORMAL)
            if int(pa.get('total_score', 0) or 0) >= th:
                return True
    except Exception:
        pass
    # 2) ML 引擎（EMBER v2 / ONNX：判定为恶意即为独立确认）
    try:
        if ml_detector is not None:
            res = ml_detector.predict(file_path)
            if res and str(res[0]) == 'malware':
                return True
    except Exception:
        pass
    return False


def _init_scan_worker(db_path: str, scan_archives: bool, trusted_dirs: set,
                      executable_extensions: set, min_file_size: int,
                      strict_mode: bool = False, self_excluded_dirs: set = None,
                      user_excluded_dirs: set = None, oem_dir_keys: tuple = None,
                      virus_identifier_enabled: bool = False, ml_stats=None):
    """进程池初始化函数，在每个子进程中只调用一次"""
    # 修复"扫描结束后 Worker BrokenPipeError 二次崩溃"：
    # 父进程在扫描结束/停止/退出时关闭结果管道，仍持有任务的 worker 向
    # 结果队列 put 会收到 BrokenPipeError [WinError 232]；multiprocessing
    # 随后尝试打印 traceback，若子进程 stdout/stderr 为 None（PyInstaller
    # windowed 打包 / spawn 子进程）会在 _bootstrap 中再抛 AttributeError
    # （'NoneType' object has no attribute 'write'），形成连环报错。
    # 扫描 worker 结果均经管道回传、诊断走文件 logger，无需控制台，
    # 这里统一重定向到 devnull，使"父进程已关闭"的正常终止静默退出。
    try:
        _devnull = open(os.devnull, 'w')
        sys.stdout = _devnull
        sys.stderr = _devnull
    except Exception:
        pass
    global _worker_db, _worker_rule_engine, _worker_pe_analyzer
    global _worker_virus_identifier, _worker_archive_scanner, _worker_vi_enabled
    global _worker_malware_hashes, _worker_whitelist_cache
    global _worker_heuristic_rules, _worker_trusted_dirs, _worker_executable_extensions
    global _worker_min_file_size, _worker_signature_verifier, _worker_strict_mode
    global _worker_self_excluded_dirs, _worker_user_excluded_dirs
    global _worker_oem_dir_keys, _worker_ml_detector, _ML_SCAN_STATS

    # 多进程模式下父进程注入 Manager 共享字典，使 ML 计数可汇总到父进程
    if ml_stats is not None:
        try:
            _ML_SCAN_STATS = ml_stats
        except Exception:
            pass

    _worker_db = SignatureDB(db_path)
    _worker_rule_engine = RuleEngine()
    _worker_pe_analyzer = PEAnalyzer()

    try:
        from engine.virus_identifier import VirusIdentifier
        _worker_virus_identifier = VirusIdentifier(signature_db=_worker_db)
    except Exception as e:
        logger.warning(f'扫描 worker VirusIdentifier 初始化失败: {e}')
        _worker_virus_identifier = None

    _worker_archive_scanner = ArchiveScanner() if scan_archives else None
    _worker_malware_hashes = _worker_db._malware_hashes
    _worker_whitelist_cache = _worker_db._whitelist_cache
    _worker_heuristic_rules = _worker_db._heuristic_rules
    _worker_trusted_dirs = trusted_dirs
    _worker_executable_extensions = executable_extensions
    _worker_min_file_size = min_file_size
    _worker_strict_mode = strict_mode
    _worker_self_excluded_dirs = self_excluded_dirs or set()
    _worker_user_excluded_dirs = user_excluded_dirs or set()
    _worker_oem_dir_keys = oem_dir_keys or tuple(ScanEngine._OEM_PACKAGE_DIR_KEYS)
    _worker_vi_enabled = bool(virus_identifier_enabled)

    # 初始化数字签名验证器（参照 sign_scanner，降低误报）
    try:
        from utils.signature_verifier import get_verifier
        _worker_signature_verifier = get_verifier()
    except Exception:
        _worker_signature_verifier = None

    # 初始化 ML 检测引擎（扫描 worker 进程无 PyQt5，可安全进程内加载 onnxruntime）
    try:
        from engine.ml_detector import MLMalwareDetector, enable_scan_worker_mode
        # 启用扫描 worker 模式，允许进程内加载 onnxruntime
        enable_scan_worker_mode()
        _worker_ml_detector = MLMalwareDetector()
        # 关键：可用性不能只看 ONNX 的 available —— LightGBM 主引擎走
        # ctypes/进程内推理，与 onnxruntime 相互独立。若仅因 ONNX 缺失就
        # 丢弃检测器，主引擎将完全不参与，检出率会骤降（29% 的直接嫌疑）。
        any_avail = bool(getattr(_worker_ml_detector, 'any_engine_available', False))
        if not any_avail and _worker_ml_detector.available:
            any_avail = True
        reason = ''
        try:
            reason = _worker_ml_detector.main_unavailable_reason()
        except Exception:
            reason = ''
        _ML_SCAN_STATS['ml_available'] = any_avail
        _ML_SCAN_STATS['ml_main_unavailable_reason'] = reason
        if any_avail:
            logger.info(
                '扫描 worker: ML 检测引擎已初始化 (main_engine=%s reason=%s)',
                getattr(_worker_ml_detector, 'main_engine_available', False),
                reason or '-')
        else:
            logger.warning(
                '扫描 worker: ML 检测引擎不可用，降级为传统引擎 (reason=%s)',
                reason or 'no_engine_loaded')
            _ML_SCAN_STATS['ml_main_unavailable_reason'] = reason or 'no_engine_loaded'
            _worker_ml_detector = None
    except Exception as e:
        logger.warning(f'扫描 worker ML 检测器初始化失败: {e}')
        _worker_ml_detector = None
        _ML_SCAN_STATS['ml_available'] = False
        _ML_SCAN_STATS['ml_main_unavailable_reason'] = f'init_exception: {e}'
    _ml_stats_log(reason='worker-init')

    # 提升扫描子进程自身优先级（Windows: ABOVE_NORMAL = 0x8000）
    # 扫描在独立进程中运行，不会影响主进程 UI 渲染和事件循环
    try:
        import os as _os
        if sys.platform == 'win32':
            import ctypes as _ct
            _handle = _ct.windll.kernel32.GetCurrentProcess()
            _ct.windll.kernel32.SetPriorityClass(_handle, 0x8000)  # ABOVE_NORMAL_PRIORITY_CLASS
    except Exception:
        pass


def _scan_file_worker_heuristic(file_path: str) -> list:
    """多进程 worker 专用的启发式扫描（使用预编译正则缓存）

    复用 ScanEngine._get_compiled_regex 类方法实现正则缓存
    并内置结构化启发式检测（双扩展名、可疑节区名、可疑导入API等）

    [v2 防误报]
      纯数据/配置文件 (.json/.txt/.html/.ini/.yaml/.xml/.py 源码 等)
      跳过 content 规则、packer 节区、可疑 API 组合这些"二进制特征检测"。
      只保留 文件名/扩展名 级别的规则（这些不会误报）。
      原因: NVIDIA 驱动包 i18n JSON、Chrome manifest、VSCode 配置 等纯数据文件
      里出现 CreateService/DIFx/Run 等子串是正常的，不应被判为可疑。
    """
    global _worker_heuristic_rules
    matches = []
    filename = os.path.basename(file_path)
    _, extension = os.path.splitext(file_path)
    ext_lower = extension.lower()
    is_pure_data = ext_lower in _PURE_DATA_EXTENSIONS

    # ---------- 内建：文件名/路径结构化启发式 (始终执行) ----------
    try:
        name_no_ext, _ = os.path.splitext(filename.lower())
        if name_no_ext:
            _, ext2 = os.path.splitext(name_no_ext)
            if ext2 and ext_lower in ('.exe', '.dll', '.scr', '.pif', '.com',
                                 '.bat', '.cmd', '.js', '.vbs', '.ps1'):
                # 双扩展名：如 invoice.pdf.exe
                common_doc = {'.pdf', '.doc', '.docx', '.xls', '.xlsx',
                              '.ppt', '.pptx', '.txt', '.rtf', '.jpg',
                              '.png', '.bmp', '.gif', '.zip', '.rar'}
                if ext2 in common_doc:
                    matches.append({'name': '双扩展名伪装', 'severity': 'high',
                                    'rule_type': 'builtin', 'detail': f'{filename}'})
    except Exception:
        pass

    try:
        filename_l = filename.lower()
        # 文件名包含多个空白字符（RTLO 攻击常见）或可疑关键字
        if '\u202e' in filename or '\u200f' in filename or '\u200b' in filename:
            matches.append({'name': 'RTLO/Unicode 伪装字符', 'severity': 'high',
                            'rule_type': 'builtin'})
        if any(k in filename_l for k in ('invoice', 'payment', 'bank', 'urgent', 'confirm')) \
                and ext_lower in ('.exe', '.scr', '.bat', '.js', '.vbs', '.ps1'):
            matches.append({'name': '社会工程学文件名模式', 'severity': 'low',
                            'rule_type': 'builtin'})
    except Exception:
        pass

    # ---------- 规则库匹配 ----------
    if _worker_heuristic_rules:
        for rule in _worker_heuristic_rules:
            try:
                rule_type = rule.get('rule_type', '')
                pattern = rule.get('pattern', '')
                if rule_type == 'content':
                    # [防误报] 纯数据/配置文件跳过 content 规则!
                    # 原因: DIFx/InstallDriver/Run 等子串在驱动包 JSON/INF 文件里
                    # 大量出现, 但这些文件是纯数据, 不可能执行任何恶意操作
                    if is_pure_data:
                        continue
                    # 可执行脚本虽然是文本形式但能直接执行代码 — content 规则保留
                    try:
                        sz = os.path.getsize(file_path)
                        if sz == 0 or sz >= 32 * 1024 * 1024:
                            continue
                        with open_with_retry(file_path, 'rb') as f:
                            content = f.read(min(sz, 2 * 1024 * 1024))
                        if content and re.search(pattern, content):
                            matches.append(rule)
                    except Exception:
                        continue
                else:
                    # filename / extension / filepath 规则 — 对所有文件执行
                    regex = ScanEngine._get_compiled_regex(pattern)
                    if regex is None:
                        continue
                    if rule_type == 'filename' and regex.search(filename):
                        matches.append(rule)
                    elif rule_type == 'extension' and regex.search(extension):
                        matches.append(rule)
                    elif rule_type == 'filepath' and regex.search(file_path):
                        matches.append(rule)
            except Exception:
                continue

    # ---------- 内建：字节级结构化启发式 ----------
    # [防误报] 纯数据/配置文件全部跳过!
    # packer_sigs 是 PE 节区特征, suspicious_api_combos 是二进制 API 字符串组合
    # 这些在 .json/.txt/.html/.inf 等纯数据文件里没有意义
    if is_pure_data:
        return matches

    try:
        sz = os.path.getsize(file_path)
        if sz == 0 or sz >= 32 * 1024 * 1024:
            return matches
        with open_with_retry(file_path, 'rb') as f:
            file_content = f.read(min(sz, 2 * 1024 * 1024))
    except Exception:
        return matches

    if not file_content:
        return matches

    try:
        # 可疑节区名：加壳器常见标志
        packer_sigs = [
            (b'.UPX0', 'UPX 加壳节区', 'medium'),
            (b'.UPX1', 'UPX 加壳节区', 'medium'),
            (b'.packed', 'Packed 加壳节区', 'medium'),
            (b'.themida', 'Themida/VMP 保护节区', 'high'),
            (b'.vmp0', 'VMProtect 节区', 'high'),
            (b'.enigma', 'Enigma 保护器', 'high'),
            (b'.aspack', 'ASPack 加壳', 'medium'),
            (b'.petite', 'Petite 加壳', 'low'),
            (b'.pecompact', 'PECompact 加壳', 'medium'),
            (b'.mpress', 'MPress 加壳', 'low'),
        ]
        for sig_bytes, sig_name, sev in packer_sigs:
            if sig_bytes in file_content[:min(len(file_content), 256 * 1024)]:
                matches.append({'name': sig_name, 'severity': sev, 'rule_type': 'builtin'})
                break  # 避免重复加壳告警过多

        # 可疑 API 调用字节序列（简化版本的导入表字符串匹配）
        suspicious_api_combos = [
            (b'CreateRemoteThread', b'WriteProcessMemory', '进程注入 API 组合', 'high'),
            (b'OpenProcess', b'VirtualAllocEx', '远程内存分配/打开进程组合', 'medium'),
            (b'URLDownloadToFile', b'WinExec', '下载+执行网络组合', 'high'),
            (b'InternetOpen', b'HttpSendRequest', '可疑网络请求组合', 'medium'),
            (b'GetAsyncKeyState', b'GetForegroundWindow', '键盘记录 API 组合', 'high'),
        ]
        for a_bytes, b_bytes, sig_name, sev in suspicious_api_combos:
            if a_bytes in file_content and b_bytes in file_content:
                matches.append({'name': sig_name, 'severity': sev, 'rule_type': 'builtin'})
    except Exception:
        pass

    return matches


def _scan_file_worker_full(file_path: str) -> List[ScanResult]:
    """
    完整的文件扫描工作函数（用于多进程模式）
    包含哈希匹配、规则引擎、PE分析、归档扫描
    与单进程 scan_file_with_archives 功能一致
    """
    global _worker_db, _worker_rule_engine, _worker_pe_analyzer
    global _worker_archive_scanner, _worker_malware_hashes, _worker_whitelist_cache
    global _worker_heuristic_rules, _worker_trusted_dirs, _worker_executable_extensions
    global _worker_min_file_size

    results = []

    try:
        # 路径级自身保护：PSLS 自身文件永不被扫描
        if _worker_self_excluded_dirs:
            try:
                fp_lower = os.path.abspath(file_path).lower()
                if any(fp_lower.startswith(d) for d in _worker_self_excluded_dirs):
                    results.append(ScanResult(file_path, 'clean'))
                    return results
                # 用户自定义排除路径
                if _worker_user_excluded_dirs:
                    if any(fp_lower.startswith(d) for d in _worker_user_excluded_dirs):
                        results.append(ScanResult(file_path, 'clean'))
                        return results
            except Exception:
                pass

        # Windows 内核锁定文件快速跳过：pagefile/hiberfil/swapfile/NTUSER/注册表 hive 等
        # 这些文件无法读取 PermissionError，且不可能作为恶意软件载体
        try:
            base_name = os.path.basename(file_path).lower()
            if base_name in _LOCKED_SYSTEM_FILE_NAMES:
                results.append(ScanResult(file_path, 'clean'))
                return results
        except Exception:
            pass

        # 云同步占位符文件跳过：OneDrive/WPSDrive/百度网盘等的 Files-On-Demand 文件
        # 本地无实际内容，open() 会抛 OSError，哈希计算必然失败
        # 只检查 RECALL_ON_DATA_ACCESS 和 OFFLINE，保留 REPARSE_POINT
        # （普通符号链接/junction 仍需扫描，防止指向恶意目标）
        try:
            import ctypes as _ct
            _attrs = _ct.windll.kernel32.GetFileAttributesW(file_path)
            if _attrs != 0xFFFFFFFF:
                # 0x400000 = FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS (云占位符，必须从云端拉取)
                # 0x1000   = FILE_ATTRIBUTE_OFFLINE (离线存储，本地无数据)
                if _attrs & 0x400000 or _attrs & 0x1000:
                    results.append(ScanResult(file_path, 'clean'))
                    return results
        except Exception:
            pass

        # 获取文件扩展名和大小
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()

        try:
            file_size = os.path.getsize(file_path)
        except Exception:
            file_size = 0

        # 检查是否在可信目录中
        file_path_lower = file_path.lower()
        is_in_trusted_dir = any(file_path_lower.startswith(td) for td in _worker_trusted_dirs)

        # [降误报] OEM 驱动包目录关键词检查 — 子串匹配 (路径包含)
        # 比如 C:\eSupport\eDriver\...\DriverDCH\...\NvApp\www\assets\i18n\config.json
        # 这种全签名、永不运行的出厂驱动包内容, 直接跳过启发式检测
        if not is_in_trusted_dir and _worker_oem_dir_keys:
            is_in_oem_pkg = any(k in file_path_lower for k in _worker_oem_dir_keys)
            if is_in_oem_pkg:
                # 标记为 OEM 包, 跳过规则引擎/启发式/PE 分析, 只做哈希检查
                # 但先让哈希检查跑完 — 万一 OEM 包里真混了恶意文件
                pass
            else:
                is_in_oem_pkg = False
        else:
            is_in_oem_pkg = False

        # 计算文件哈希（带重试，杀软锁定时自动退避）
        file_hash = compute_sha256(file_path)
        hash_available = bool(file_hash)
        # 哈希不可用时不立即判定 error
        # 继续尝试 YARA + PE 分析（它们独立 open 文件，可能成功）
        # 所有检测引擎都跑过后仍无法读取 → 在 L637 之后追加 error result

        # 白名单检查
        if hash_available and file_hash in _worker_whitelist_cache:
            results.append(ScanResult(file_path, 'clean'))
            return results

        # 签名匹配（最高优先级）
        is_confirmed_malware = False
        if hash_available and file_hash in _worker_malware_hashes:
            malware_info = _worker_db.get_malware_info(file_hash)
            results.append(ScanResult(file_path, 'malware', malware_info=malware_info))
            is_confirmed_malware = True
            # 已确认恶意文件跳过后续规则/PE/启发式分析，仅保留归档扫描

        # --------- 分析结果缓存检查 ---------
        # 同 hash 文件（复制/硬链接）跳过重复的规则引擎 + PE 分析 + 启发式扫描
        cache_hit = None
        rule_matches = []
        pe_analysis = {}
        heuristic_matches = []

        if not is_confirmed_malware and hash_available:
            cache_hit = _worker_analysis_cache.get(file_hash)
            if cache_hit:
                rule_matches = cache_hit.get('rule_matches', [])
                pe_analysis = cache_hit.get('pe_analysis', {})
                heuristic_matches = cache_hit.get('heuristic_matches', [])

        # ========== 可信签名提前快速放行（降误报+提性能）==========
        if (not is_confirmed_malware and not cache_hit
                and ext in _worker_executable_extensions
                and _worker_signature_verifier
                and file_size > 0):
            try:
                _signer = _worker_signature_verifier.get_signer_info(file_path)
                if _signer and _signer.get('verified', False):
                    _pub = (_signer.get('publisher') or '').lower()
                    if any(_t in _pub for _t in TRUSTED_SIGNER_SUBSTRINGS):
                        results.append(ScanResult(file_path, 'clean'))
                        return results
            except Exception:
                pass

        # ========== .lnk 快捷方式专用处理 ==========
        # .lnk 自身不含可执行代码，直接对二进制做 content 规则/启发式/ViiD 会误报
        # 正确做法：解析快捷方式目标路径和参数，对目标做安全评估
        if not is_confirmed_malware and not cache_hit and ext == '.lnk' and file_size > 0:
            lnk_info = _parse_lnk_file(file_path)
            if lnk_info:
                lnk_matches = _check_lnk_suspicious(lnk_info)
                if lnk_matches:
                    high_count = sum(1 for m in lnk_matches if m.get('severity') == 'high')
                    if high_count >= 1:
                        results.append(ScanResult(file_path, 'suspicious',
                                                 malware_info={'name': '快捷方式指向可疑目标',
                                                               'rule_matches': lnk_matches},
                                                 rule_matches=lnk_matches))
                        return results
                    # medium 级别也标记为可疑
                    results.append(ScanResult(file_path, 'suspicious',
                                             malware_info={'name': '快捷方式指向可疑目标',
                                                           'rule_matches': lnk_matches},
                                             rule_matches=lnk_matches))
                    return results
                # 目标不可疑 → 快捷方式本身判定为 clean，不做后续 content/启发式/ViiD/PE 分析
                results.append(ScanResult(file_path, 'clean'))
                return results
            # 解析失败 → 跳过 .lnk 专用处理，继续走常规流程（极少见）

        # 规则引擎扫描（已确认恶意文件跳过，节省分析时间；缓存命中也跳过）
        # OEM 驱动包目录的文件：全签名且永不运行，跳过规则引擎
        if not is_confirmed_malware and not cache_hit and not is_in_trusted_dir \
                and not is_in_oem_pkg and file_size >= _worker_min_file_size:
            rule_matches = _worker_rule_engine.scan_file(file_path)

        file_status = 'clean'
        malware_info = None

        if rule_matches:
            high_severity = any(m.get('severity') == 'high' for m in rule_matches)
            medium_severity = [m for m in rule_matches if m.get('severity') == 'medium']
            low_severity = [m for m in rule_matches if m.get('severity') == 'low']
            threat_matches = [m for m in rule_matches if m.get('severity') in ('high', 'medium', 'low')]

            # 阈值：严格模式下 1 个 low 即触发 suspicious
            low_threshold = RULE_LOW_THRESHOLD_STRICT if _worker_strict_mode else RULE_LOW_THRESHOLD_NORMAL
            med_threshold = RULE_MEDIUM_THRESHOLD_STRICT if _worker_strict_mode else RULE_MEDIUM_THRESHOLD_NORMAL
            if high_severity:
                file_status = 'malware' if len(threat_matches) >= 1 else 'suspicious'
                malware_info = {'name': '规则引擎检测到威胁', 'rule_matches': rule_matches}
            elif len(medium_severity) >= med_threshold:
                file_status = 'suspicious'
            elif len(low_severity) >= low_threshold:
                file_status = 'suspicious'
            elif len(threat_matches) >= 2:
                file_status = 'suspicious'

            # ---- YARA 误报降级守卫 ----
            # 签名可信 + 仅 medium/low 规则命中（无 high）→ 自动降级为 clean
            # 这是降误报的核心：微软/Adobe/Sysinternals 等可信签名的小 DLL 命中
            # "filesize < 100KB" 这类 YARA 规则不应报 suspicious
            if file_status == 'suspicious' and not high_severity and _worker_signature_verifier:
                try:
                    _si = _worker_signature_verifier.get_signer_info(file_path)
                    if _si and _si.get('verified'):
                        _pub = (_si.get('publisher') or '').lower()
                        _trusted = any(_t in _pub for _t in TRUSTED_SIGNER_SUBSTRINGS)
                        if _trusted:
                            file_status = 'clean'
                            malware_info = None
                            # 标记已做签名降级，供后续 PE 分析参考
                            pe_analysis['signature_verified'] = True
                            pe_analysis['signer_publisher'] = _pub
                except Exception:
                    pass

        # ============ VirusIdentifier 综合引擎（覆盖 PE + 非 PE） ============
        # V2 已接入，PSLS 主扫描链路此前缺失 — 是"扫描能力弱"的根因
        # 7 维度综合分析：PE 结构 + 脚本特征 + 熵 + 字符串 + 启发式 + 文件名 + 综合评分
        # 对非 PE 文件（JS/VBS/BAT/...）也能独立检出
        #
        # [前置快速放行] — 性能优化
        # 对"纯数据/纯文本"扩展名文件（.json/.xml/.ini/.txt/.csv 等不可执行格式）
        # 直接跳过 ViiD 7 维分析：此类文件无法作为独立可执行载体，
        # 其中嵌套的恶意载荷已由 规则引擎(content) + 启发式 + 熵检测 覆盖，
        # ViiD 对它们（file_type 通常为 unknown/document/archive）收益极低，
        # 却要承担整文件读取 + 综合分析开销。跳过可显著降低全盘扫描耗时。
        _viid_fast_pass = False
        if not is_in_trusted_dir and not cache_hit and not is_in_oem_pkg \
                and _worker_executable_extensions is not None and ext not in _worker_executable_extensions:
            # 非可执行扩展名 → 依据是否为纯数据格式决定是否快速放行
            if ext in _PURE_DATA_EXTENSIONS:
                _viid_fast_pass = True
        vid_info = None
        if file_status == 'clean' and not is_confirmed_malware \
                and not is_in_trusted_dir and not cache_hit \
                and not is_in_oem_pkg and _worker_virus_identifier \
                and _worker_vi_enabled \
                and not _viid_fast_pass:
            try:
                vi_result = _worker_virus_identifier.identify(file_path, precomputed_sha256=file_hash)
                if vi_result:
                    vi_score = int(vi_result.get('score', 0))
                    vi_sev = (vi_result.get('severity') or 'low').lower()
                    if vi_score >= 28 or vi_sev in ('critical', 'high'):
                        # 交叉确认：VirusIdentifier 是纯启发式打分引擎，单独判
                        # 恶意误报偏高。须由独立引擎（PE 结构分析 / ML）同向确认
                        # 才最终判恶意；否则降级为可疑（保留告警，不自动处置）。
                        if _vi_cross_confirm(file_path, ext,
                                             _worker_pe_analyzer,
                                             _worker_ml_detector,
                                             _worker_strict_mode,
                                             _worker_executable_extensions):
                            file_status = 'malware'
                            malware_info = {'name': 'VirusIdentifier 检测到威胁（已交叉确认）',
                                            'vi_score': vi_score,
                                            'vi_severity': vi_sev,
                                            'malware_type': vi_result.get('malware_type'),
                                            'vi_reasons': vi_result.get('reasons')}
                        else:
                            file_status = 'suspicious'
                            malware_info = {'name': 'VirusIdentifier 检测到可疑迹象（单引擎未交叉确认）',
                                            'vi_score': vi_score,
                                            'vi_severity': vi_sev,
                                            'malware_type': vi_result.get('malware_type'),
                                            'vi_reasons': vi_result.get('reasons')}
                        vid_info = vi_result
                    elif vi_score >= 8 or vi_sev == 'medium':
                        file_status = 'suspicious'
                        malware_info = {'name': 'VirusIdentifier 检测到可疑迹象',
                                        'vi_score': vi_score,
                                        'vi_severity': vi_sev}
                        vid_info = vi_result
            except Exception as e:
                logger.debug(f'VirusIdentifier worker 扫描异常: {e}')

        # PE文件分析（可信目录中的可执行文件仍做 PE 分析，防止 DLL 侧载攻击；缓存命中跳过）
        # OEM 包：出厂驱动包全签名，PE 分析多余，跳过
        if file_status == 'clean' and not is_confirmed_malware and not cache_hit \
                and not is_in_oem_pkg and ext in _worker_executable_extensions:
            pe_analysis = _worker_pe_analyzer.analyze(file_path)

            pe_score = pe_analysis.get('total_score', 0)
            # 阈值：严格模式 vs 宽松模式
            pe_malw_th = PE_MALWARE_THRESHOLD_STRICT if _worker_strict_mode else PE_MALWARE_THRESHOLD_NORMAL
            pe_susp_th = PE_SUSPICIOUS_THRESHOLD_STRICT if _worker_strict_mode else PE_SUSPICIOUS_THRESHOLD_NORMAL
            if pe_score >= pe_malw_th:
                file_status = 'malware'
                malware_info = {'name': 'PE分析检测到威胁',
                                'pe_score': pe_score,
                                'details': pe_analysis.get('details')}
            elif pe_score >= (pe_malw_th + pe_susp_th) // 2:
                file_status = 'suspicious'
                malware_info = {'name': 'PE分析检测到可疑迹象',
                                'pe_score': pe_score,
                                'details': pe_analysis.get('details')}
            elif pe_score >= pe_susp_th:
                file_status = 'suspicious'
                malware_info = {'name': 'PE分析检测到可疑迹象',
                                'pe_score': pe_score,
                                'details': pe_analysis.get('details')}

            # 数字签名验证（模块级可信签名列表已覆盖 .NET/Sysinternals/Azure 等）
            if file_status in ('suspicious', 'malware') and _worker_signature_verifier:
                try:
                    signer_info = _worker_signature_verifier.get_signer_info(file_path)
                    if signer_info and signer_info.get('verified'):
                        signer_name = (signer_info.get('publisher') or '').lower()
                        is_trusted_signer = any(p in signer_name for p in TRUSTED_SIGNER_SUBSTRINGS)
                        if file_status == 'malware':
                            if pe_score >= 90:
                                file_status = 'suspicious'
                                malware_info = malware_info or {}
                                malware_info['note'] = '已签名极高危文件（保留告警）'
                            elif is_trusted_signer:
                                file_status = 'suspicious'
                                malware_info = malware_info or {}
                                malware_info['note'] = '可信签名文件（降级处理）'
                            else:
                                file_status = 'suspicious'
                                malware_info = malware_info or {}
                                malware_info['note'] = '已签名（降级处理）'
                        else:  # suspicious
                            if is_trusted_signer and pe_score < 50:
                                file_status = 'clean'
                                malware_info = None
                            elif is_trusted_signer:
                                malware_info = malware_info or {}
                                malware_info['note'] = '可信签名（保留告警）'
                        pe_analysis['signature_verified'] = True
                except Exception:
                    pass

        # 启发式扫描（降误报：medium 单独不触发, 需叠加证据；缓存命中跳过）
        # OEM 驱动包：全签名、永不运行的出厂内容, 跳过启发式
        if file_status == 'clean' and not is_confirmed_malware \
                and not is_in_trusted_dir and not cache_hit and not is_in_oem_pkg:
            try:
                heuristic_matches = _scan_file_worker_heuristic(file_path)
                if heuristic_matches:
                    high_count = sum(1 for m in heuristic_matches if m.get('severity') == 'high')
                    medium_count = sum(1 for m in heuristic_matches if m.get('severity') == 'medium')
                    low_count = sum(1 for m in heuristic_matches if m.get('severity') == 'low')

                    if high_count >= 1:
                        file_status = 'suspicious'
                        malware_info = {'name': '启发式扫描发现威胁'}
                    elif medium_count >= 2:
                        file_status = 'suspicious'
                        malware_info = {'name': '启发式扫描发现威胁'}
                    elif medium_count >= 1 and low_count >= 2:
                        file_status = 'suspicious'
                        malware_info = {'name': '启发式扫描发现威胁'}
            except Exception:
                pass

        # 熵检测（降误报：用户数据目录/压缩格式/有效签名/OEM 包则跳过）
        if (file_status == 'clean' and not is_confirmed_malware
                and not is_in_trusted_dir and not cache_hit
                and not is_in_oem_pkg
                and not _is_in_user_data_dir(file_path)
                and ext not in _ENTROPY_SKIP_EXTS):
            if ext in ('.exe', '.dll', '.sys', '.scr', '.pif', '.com',
                       '.bin', '.dat', '.drv', '.ocx', '.cpl'):
                try:
                    file_size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
                    content = ScanEngine._read_file_content(file_path, 16384)
                    if content:
                        entropy = ScanEngine._calculate_shannon_entropy(content)
                        entropy_th = ENTROPY_THRESHOLD_STRICT if _worker_strict_mode else ENTROPY_THRESHOLD_NORMAL
                        if entropy > entropy_th:
                            # 有有效签名 → 跳过熵检测
                            skip_entropy = False
                            if _worker_signature_verifier:
                                try:
                                    if _worker_signature_verifier.verify_signature(file_path):
                                        skip_entropy = True
                                except Exception:
                                    pass
                            if not skip_entropy:
                                file_status = 'suspicious'
                                malware_info = {'name': '熵监测发现威胁', 'entropy': entropy}
                except Exception:
                    pass

        # ---- ML 引擎补充检测（交叉验证上下文） ----
        # 扫描 worker 进程中已初始化 ML 检测器，可安全进程内推理。
        # 门槛：clean / suspicious 都调用（suspicious 仍可由 ML 升级为 malware），
        # 可信目录跳过；每个文件仅调用一次。
        if file_status in ('clean', 'suspicious') and _worker_ml_detector and not is_in_trusted_dir:
            try:
                # 同步严格模式到 ML 引擎
                if hasattr(_worker_ml_detector, 'set_strict_mode'):
                    _worker_ml_detector.set_strict_mode(_worker_strict_mode)

                # 统计各维度严重等级
                pe_score = pe_analysis.get('total_score', 0) if pe_analysis else 0
                rule_high_count = sum(1 for m in rule_matches if m.get('severity') == 'high')
                rule_med_count = sum(1 for m in rule_matches if m.get('severity') == 'medium')
                heuristic_high_count = sum(1 for m in heuristic_matches if m.get('severity') == 'high')
                heuristic_med_count = sum(1 for m in heuristic_matches if m.get('severity') == 'medium')
                entropy_packed = (file_status == 'suspicious' and malware_info and
                                  'entropy' in malware_info)

                _ml_stats_incr('ml_called')
                ml_source = None
                if hasattr(_worker_ml_detector, 'detect_with_context_with_source'):
                    ml_result, ml_source = _worker_ml_detector.detect_with_context_with_source(
                        file_path,
                        pe_score=pe_score,
                        rule_high_count=rule_high_count,
                        rule_medium_count=rule_med_count,
                        heuristic_high_count=heuristic_high_count,
                        heuristic_medium_count=heuristic_med_count,
                        entropy_packed=entropy_packed,
                    )
                elif hasattr(_worker_ml_detector, 'detect_with_context'):
                    ml_result = _worker_ml_detector.detect_with_context(
                        file_path,
                        pe_score=pe_score,
                        rule_high_count=rule_high_count,
                        rule_medium_count=rule_med_count,
                        heuristic_high_count=heuristic_high_count,
                        heuristic_medium_count=heuristic_med_count,
                        entropy_packed=entropy_packed,
                    )
                else:
                    ml_result = _worker_ml_detector.predict(file_path)

                if ml_result:
                    ml_verdict, ml_prob = ml_result
                    if ml_verdict == 'malware':
                        _ml_stats_incr('ml_malware')
                        # malware: 高概率独立判定，中概率需其他维度印证
                        has_evidence = (pe_score >= 45 or rule_high_count >= 1
                                        or rule_med_count >= 2 or heuristic_high_count >= 1)
                        if ml_prob >= 0.88:
                            file_status = 'malware'
                        elif ml_prob >= 0.78 and has_evidence:
                            file_status = 'malware'
                        else:
                            file_status = 'suspicious'
                        malware_info = {
                            'name': 'ML引擎发现威胁',
                            'ml_probability': round(ml_prob, 4),
                            'ml_verdict': ml_verdict,
                            'ml_source': ml_source or 'unknown',
                        }
                    elif ml_verdict == 'suspicious':
                        _ml_stats_incr('ml_susp')
                        # suspicious: 需其他维度印证（pe_score≥40，或 ≥2 medium / ≥1 high）
                        cross_evidence = (
                            pe_score >= 40 or rule_high_count >= 1
                            or rule_med_count >= 2 or heuristic_high_count >= 1
                            or heuristic_med_count >= 2
                        )
                        if cross_evidence:
                            file_status = 'suspicious'
                            malware_info = {
                                'name': f'ML引擎发现威胁 (概率={ml_prob:.2f})',
                                'ml_probability': round(ml_prob, 4),
                                'ml_verdict': 'suspicious',
                                'ml_source': ml_source or 'unknown',
                            }
                else:
                    _ml_stats_incr('ml_none')

                # 累计快照：首次 + 每 N 次输出一行（避免逐文件刷屏）
                _called = int(_ML_SCAN_STATS.get('ml_called', 0) or 0)
                if _called == 1 or _called % _ML_STATS_LOG_STEP == 0:
                    _ml_stats_log(reason='worker-milestone')
            except Exception as e:
                _ml_stats_incr('ml_failed')
                logger.warning(f'Worker ML 推理异常 {file_path}: {e}')

        # 添加文件本身的结果
        if file_status != 'clean' or not results:
            # 哈希不可用时的最终判定：
            #   - YARA/PE/启发式 任何一个引擎检出威胁 → 保持 malware/suspicious
            #   - 全部引擎返回 clean + 哈希不可用 → 文件被外部因素锁定 → skipped
            #     （Windows Defender/杀软实时扫描锁定，重试耗尽后仍无法读取）
            #   - error 仅用于真正的异常（try-except 捕获），不用作"临时不可读"
            if not hash_available and file_status == 'clean':
                logger.debug(f'哈希不可用且所有引擎 clean，标记 skipped: {file_path}')
                file_status = 'skipped'
            results.append(ScanResult(
                file_path, file_status,
                malware_info=malware_info,
                rule_matches=rule_matches,
                pe_analysis=pe_analysis,
            ))

        # --------- 分析结果缓存写入 ---------
        # 缓存未命中时，把本次分析结果写入缓存，后续同 hash 文件跳过重复分析
        if not is_confirmed_malware and not cache_hit and file_hash:
            if len(_worker_analysis_cache) >= _WORKER_ANALYSIS_CACHE_MAX:
                import random
                keys = list(_worker_analysis_cache.keys())
                random.shuffle(keys)
                for k in keys[:len(keys) // 2]:
                    del _worker_analysis_cache[k]
            _worker_analysis_cache[file_hash] = {
                'rule_matches': list(rule_matches),
                'pe_analysis': dict(pe_analysis),
                'heuristic_matches': list(heuristic_matches),
            }

        # 扫描结果为 clean → 自动加入白名单（仅非可信目录，已确认恶意文件不加入）
        if file_status == 'clean' and not is_confirmed_malware and file_hash and not is_in_trusted_dir:
            try:
                pe_score = pe_analysis.get('total_score', 0) if pe_analysis else 0
                rule_high_c = sum(1 for m in rule_matches if m.get('severity') == 'high')
                rule_med_c = sum(1 for m in rule_matches if m.get('severity') == 'medium')
                if file_hash not in _worker_whitelist_cache:
                    _worker_db.add_to_whitelist(
                        file_hash,
                        (f'引擎自动放行(PE={pe_score}分, '
                         f'规则high={rule_high_c}/med={rule_med_c})')
                    )
                    _worker_whitelist_cache.add(file_hash)
            except Exception:
                pass

        # 归档扫描
        if _worker_archive_scanner:
            archive_results = _worker_archive_scanner.scan_archive(
                file_path, _worker_malware_hashes, _worker_heuristic_rules,
                rule_engine=_worker_rule_engine,
            )

            # 基于 internal_path 去重，避免嵌套归档或并发产生重复结果
            # archive_scanner 已将同一内部文件的多个检测来源合并为一条最高严重度记录，
            # 此处 seen_internal 作为防御性去重，确保即使边界情况也不会重复生成 ScanResult
            seen_internal = set()
            for ar in archive_results:
                internal_path = ar.get('internal_path', '')
                status = ar.get('status', 'clean')

                # 同一 internal_path 只保留第一条（已合并为最高严重度）
                if internal_path and internal_path in seen_internal:
                    continue
                if internal_path:
                    seen_internal.add(internal_path)

                if status == 'malware':
                    ar_rule_matches = ar.get('rule_matches', [])
                    hash_match = ar.get('hash_match', False)
                    if hash_match:
                        # 哈希匹配优先显示签名库（即使同时命中规则引擎）
                        results.append(ScanResult(
                            file_path, 'malware',
                            malware_info={'name': f'归档内检测到恶意软件: {internal_path}'},
                            internal_path=internal_path,
                            rule_matches=ar_rule_matches,
                        ))
                    elif ar_rule_matches:
                        results.append(ScanResult(
                            file_path, 'malware',
                            malware_info={'name': f'归档内检测到威胁: {internal_path}'},
                            internal_path=internal_path,
                            rule_matches=ar_rule_matches,
                        ))
                    else:
                        results.append(ScanResult(
                            file_path, 'malware',
                            malware_info={'name': f'归档内检测到恶意软件: {internal_path}'},
                            internal_path=internal_path,
                        ))
                elif status == 'suspicious':
                    reason = ar.get('reason', '')
                    heuristic_matches = ar.get('heuristic_matches', [])
                    ar_rule_matches = ar.get('rule_matches', [])
                    results.append(ScanResult(
                        file_path, 'suspicious',
                        heuristic_matches=heuristic_matches if heuristic_matches else [{'name': reason}],
                        internal_path=internal_path,
                        rule_matches=ar_rule_matches,
                    ))

    except Exception as e:
        logger.error(f"多进程扫描文件失败 {file_path}: {e}")
        results.append(ScanResult(file_path, 'error'))

    return results


class ScanEngine:
    """
    扫描引擎类
    核心功能：签名匹配扫描、规则引擎扫描、PE文件分析
    """
    
    # 可执行文件 + 压缩包扩展名（用于"仅扫描可执行文件"模式）
    # 压缩包加入原因：勒索软件/木马常通过压缩包投递，"仅扫描可执行"模式下
    # 必须连同压缩包一起扫描才能不漏检测
    EXECUTABLE_EXTENSIONS = {
        # PE 可执行
        '.exe', '.dll', '.sys', '.scr', '.pif', '.com',
        '.ocx', '.drv', '.cpl', '.msp', '.msi', '.ace',
        # 脚本
        '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta',
        '.wsf', '.jse', '.vbe', '.py', '.pyw', '.pl', '.rb',
        # 快捷方式/URL
        '.lnk', '.url',
        # Java
        '.jar', '.class',
        # 宏文档
        '.docm', '.xlsm', '.pptm', '.dotm', '.xltm',
        # 压缩包（勒索/木马常见投递载体）
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
        # 其他
        '.swf', '.mht', '.mhtml',
    }
    
    # 可信系统目录（跳过PE分析和规则引擎扫描）
    TRUSTED_DIRECTORIES = {
        # Windows 系统核心目录（完整覆盖）
        # 注意：SystemRoot 根目录自身也必须纳入，regedit.exe/explorer.exe/taskmgr.exe
        # 等大量关键可执行文件直接位于 C:\Windows 根目录，漏掉会被 PE 分析/启发式误报
        os.environ.get('SystemRoot', 'C:\\Windows').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'SysWOW64').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'WinSxS').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Installer').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'SoftwareDistribution').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'SystemApps').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'UUS').lower(),  # Windows 更新中介组件(UUS)
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Temp').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Tasks').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'twain_32').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Web').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'WinSxS').lower(),
        # 整个 Program Files / Program Files (x86) / ProgramData 中的 Microsoft 相关产品
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Common Files').lower(),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Common Files').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Microsoft').lower(),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Microsoft').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Microsoft Office').lower(),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Microsoft Office').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Windows Defender').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Windows Security').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'WindowsApps').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'dotnet').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'PowerShell').lower(),
        # ProgramData / WindowsApps
        os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'Microsoft').lower(),
        os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'Windows Defender').lower(),
        # 用户目录下的 Microsoft 相关目录
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users'), 'AppData', 'Local', 'Microsoft').lower(),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users'), 'AppData', 'Roaming', 'Microsoft').lower(),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users'), 'AppData', 'Local', 'Packages').lower(),  # UWP应用
        # 常见可信软件
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Google').lower(),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Google').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'NVIDIA Corporation').lower(),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'NVIDIA Corporation').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Intel').lower(),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Intel').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'AMD').lower(),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'AMD').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), '7-Zip').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'VideoLAN').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Notepad++').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Mozilla Firefox').lower(),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Mozilla Firefox').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'BraveSoftware').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Oracle').lower(),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Oracle').lower(),
        # Windows 组件
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'assembly').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Microsoft.NET').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'ServiceProfiles').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Fonts').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'ImmersiveControlPanel').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'PLA').lower(),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'PolicyDefinitions').lower(),
    }

    # 将系统盘根目录下的升级/回滚临时目录加入可信目录（受强ACL保护，无法写入）
    _sd = os.environ.get('SystemDrive', 'C:').lower()
    TRUSTED_DIRECTORIES.update({
        (_sd + '\\' + '$WINDOWS.~BT').lower(),
        (_sd + '\\' + '$WINDOWS.~WS').lower(),
        (_sd + '\\' + 'OldWindows').lower(),
    })

    # 可信发行商目录（仅在文件具有有效数字签名时信任）
    _TRUSTED_PUBLISHER_DIRS = {
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Microsoft').lower(),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Microsoft').lower(),
    }

    # OEM 驱动包/预装目录 — 这些目录是厂商出厂时的驱动安装包, 全部签名且永不运行
    # NVIDIA i18n JSON / Intel INF / AMD 配置文件 等都在这里, 绝不应被误报
    # 用路径关键词匹配 (大小写不敏感, 包含关系)
    _OEM_PACKAGE_DIR_KEYS = (
        '\\esupport\\',                      # ASUS/MSI/技嘉等主流 OEM 驱动包统一放在 C:\eSupport
        '\\driverdch\\',                     # ASUS DriverDCH (Windows DCH 驱动)
        '\\driverpack\\',                    # 华硕/惠普/戴尔驱动包
        '\\drivers\\dell\\',                 # Dell 驱动
        '\\drivers\\hp\\',                   # HP 驱动
        '\\swsetup\\',                       # HP 软件安装目录
        '\\driversandutility\\',             # Acer 驱动
        '\\application\\drivers\\',          # Lenovo 驱动
        '\\drivers\\application\\',          # Lenovo 另一驱动目录
        '\\preload\\',                       # 预装驱动
    )
    
    # 最小文件大小阈值（小于此大小的文件跳过规则引擎）
    MIN_FILE_SIZE_FOR_RULE_SCAN = 1024  # 1KB

    # 模糊哈希匹配阈值
    FUZZY_MAX_SIZE = 50 * 1024 * 1024   # 仅对 ≤50MB 文件做 CTPH 模糊匹配
    FUZZY_THRESHOLD = 70                # 相似度 ≥70 判定为疑似同源样本
    
    def __init__(self, db_path: str = None, max_workers: int = None, scan_archives: bool = True,
                 signature_db=None):
        """
        初始化扫描引擎
        
        Args:
            db_path: 签名数据库路径
            max_workers: 并行扫描线程数，默认使用CPU核心数
            scan_archives: 是否扫描归档文件内容
            signature_db: 可选的已实例化 SignatureDB（复用桥接层实例，
                          避免启动时重复加载整个数据库，显著降低启动耗时）
        """
        self.signature_db = signature_db if signature_db is not None else SignatureDB(db_path)
        # 并行度策略：主机多核（>4）沿用 CPU核数*4 上限 32 的速度优先策略；
        # 低核环境（≤4，常见于虚拟机/工控机）进程数超过核数只会互相抢 CPU、
        # 引发大量进程创建销毁并饿死 GUI 主线程，因此降为核数本身使用。
        # 初始化时启动动态降载看门狗：高负载下扫描进程池自动按负载因子缩放。
        try:
            load_governor.start()
        except Exception:
            pass
        _cpu = multiprocessing.cpu_count() or 4
        if _cpu <= 4:
            _base_workers = max(1, _cpu)
        else:
            _base_workers = min(max(_cpu * 4, 8), 32)
        self.max_workers = max_workers or load_governor.effective_workers(_base_workers, min_floor=1)
        self.heuristic_rules = self.signature_db.get_heuristic_rules()
        # 预编译 content 规则的 bytes 正则（去掉 (?i)，后续用 content.lower() 匹配）
        # 初始化时一次性完成，避免多线程 scan_file 里懒编译的数据竞争
        for _rule in self.heuristic_rules:
            if _rule.get('rule_type') == 'content' and _rule.get('_cre') is None:
                _p = _rule['pattern']
                _p_no_i = _p.replace(b'(?i)', b'') if isinstance(_p, bytes) else _p.replace('(?i)', '')
                try:
                    _rule['_cre'] = re.compile(_p_no_i)
                except re.error:
                    pass
        self.scan_archives = scan_archives
        self.archive_scanner = ArchiveScanner() if scan_archives else None

        # 最大扫描文件大小（MB），0 表示无限制（默认 50MB）
        # 仅对**非可执行**类型生效（归档/媒体/镜像等，避免全盘扫描被拖慢）；
        # 可执行/脚本类走下面的硬上限，见 scan_file 内的体积豁免说明。
        self.max_file_size_mb = 50
        # 可执行/脚本类文件的体积硬上限（MB）：超过才跳过。
        # 旧实现一律按 50MB 跳过 → 下载来的大体积木马（实测 77MB 的 Keplerians
        # 样本）零分析零防护；可执行类是唯一能直接运行的载体，不该被体积豁免。
        self.exec_scan_hard_limit_bytes = 256 * 1024 * 1024

        # 严格模式开关（默认关闭，使用宽松模式以降低误报）
        # 严格模式特性：
        #   - 单个 high 启发式规则匹配即判定 suspicious（宽松模式需 2+ 个匹配）
        #   - 启用 Shannon 熵检测（>7.5 触发 suspicious）
        #   - 实时扫描时 MIN_FILE_SIZE_FOR_RULE_SCAN=0（覆盖小文件）
        # 宽松模式特性：
        #   - 启发式规则需 2+ 个匹配
        #   - 不启用熵检测
        #   - 实时扫描保持 MIN_FILE_SIZE_FOR_RULE_SCAN=1024 (1KB 阈值)
        self.strict_mode = False

        # 初始化规则引擎（替代YARA）
        self.rule_engine = RuleEngine(signature_db=self.signature_db)

        # 初始化PE分析器
        self.pe_analyzer = PEAnalyzer()

        # 初始化 study-engine 指纹学习器（懒加载；学习器不可用时不影响扫描主流程）
        self._study_engine = None

        # 初始化 VirusIdentifier 综合引擎（7维度识别，覆盖 PE + 非 PE）
        # 开关默认关闭：VirusIdentifier 是纯启发式打分引擎，误报偏高，
        # 由用户在设置中按需开启（bridge 从 ui.virus_identifier_enabled 注入）
        self.virus_identifier_enabled = False
        self._virus_identifier = None
        try:
            from engine.virus_identifier import VirusIdentifier
            self._virus_identifier = VirusIdentifier(signature_db=self.signature_db)
        except Exception as e:
            logger.warning(f'VirusIdentifier 初始化失败: {e}')

        # 初始化数字签名验证器（参照 sign_scanner，降低误报）
        try:
            from utils.signature_verifier import get_verifier
            self._signature_verifier = get_verifier()
        except Exception:
            self._signature_verifier = None

        # 数字签名验证结果缓存：同一文件（path+mtime+size）只验证一次
        # 签名验证需读取文件末尾的签名块+验证证书链，单次约 50-200ms
        # 同一文件可能在可信目录快速放行和 PE 分析阶段被验证两次，缓存避免重复计算
        self._signer_cache: Dict[str, tuple] = {}  # cache_key -> (signer_info, timestamp)

        # 模糊哈希签名缓存：首次触发模糊匹配时从 DB 加载，之后复用
        self._fuzzy_signatures_cache: Optional[List[Dict]] = None
        self._signer_cache_max = 2048

        # ML 检测引擎（可选层，由 bridge.py 注入，不可用时自动降级）
        self._ml_detector = None

        # 将自身及配置文件添加到白名单 -- 计算每个自身文件的 SHA256 开销大，
        # 放到后台线程执行（计算期间扫描不会立刻开始，延迟导入不影响正确性）
        self._whitelist_thread = threading.Thread(
            target=self._whitelist_self, name='PSLS-WhitelistSelf', daemon=True)
        self._whitelist_thread.start()

        # 初始化自身路径排除集合（路径级防护，不依赖哈希白名单）
        self._init_self_excluded_dirs()

    def _get_fuzzy_signatures(self) -> List[Dict]:
        """从 DB 读取所有 fuzzy_hash 非空的签名（带懒加载缓存）。"""
        if self._fuzzy_signatures_cache is None:
            try:
                self._fuzzy_signatures_cache = self.signature_db.get_all_fuzzy_hash_signatures() or []
                logger.debug(f'已加载 {len(self._fuzzy_signatures_cache)} 条 fuzzy_hash 签名')
            except Exception as e:
                logger.debug(f'加载 fuzzy_hash 签名失败: {e}')
                self._fuzzy_signatures_cache = []
        return self._fuzzy_signatures_cache

    def invalidate_fuzzy_cache(self):
        """当签名库更新时调用，强制下次扫描重新加载 fuzzy 签名。"""
        self._fuzzy_signatures_cache = None

    def _get_signer_info_cached(self, file_path: str):
        """获取数字签名信息（带缓存，避免同一文件重复验证）

        签名验证开销大（50-200ms），同一文件可能在可信目录快速放行
        和 PE 分析阶段被验证两次。基于 (path, mtime, size) 缓存结果。
        """
        if not self._signature_verifier:
            return None
        # 构建缓存键
        try:
            st = os.stat(file_path)
            cache_key = (file_path.lower(), st.st_mtime, st.st_size)
        except OSError:
            cache_key = file_path.lower()

        # 命中缓存
        cached = self._signer_cache.get(cache_key)
        if cached is not None:
            return cached[0]

        # 未命中：执行验证
        try:
            signer = self._signature_verifier.get_signer_info(file_path)
        except Exception:
            signer = None

        # 写入缓存（LRU 简化版：超过上限时清空一半）
        if len(self._signer_cache) >= self._signer_cache_max:
            items = list(self._signer_cache.items())
            self._signer_cache.clear()
            self._signer_cache.update(items[len(items)//2:])
        self._signer_cache[cache_key] = (signer, None)
        return signer

    def _init_self_excluded_dirs(self):
        """初始化自身路径排除集合

        哈希白名单可能因升级/环境变化失效，路径级排除作为兜底防护，
        确保 PSLS 自身文件、备份目录、持久化数据目录永不被扫描。
        """
        self._self_excluded_dirs = set()
        try:
            # 1. PSLS 可执行文件所在目录（打包模式）
            if getattr(sys, 'frozen', False):
                exe_dir = os.path.dirname(os.path.abspath(sys.executable))
                self._self_excluded_dirs.add(exe_dir.lower())
            else:
                # 开发模式：项目根目录
                import __main__
                main_file = getattr(__main__, '__file__', None)
                if main_file and os.path.exists(main_file):
                    project_root = os.path.dirname(os.path.abspath(main_file))
                else:
                    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                self._self_excluded_dirs.add(project_root.lower())

            # 2. %APPDATA%\PSLS 持久化数据目录
            if sys.platform == 'win32':
                appdata = os.environ.get('APPDATA', '')
                if appdata:
                    psls_data_dir = os.path.join(appdata, 'PSLS')
                    self._self_excluded_dirs.add(psls_data_dir.lower())

            # 3. backup 目录（self_protection.py 创建的备份目录）
            # 打包模式：exe_dir/backup 或 _internal/backup
            # 开发模式：project_root/backup
            for base_dir in list(self._self_excluded_dirs):
                backup_dir = os.path.join(base_dir, 'backup')
                self._self_excluded_dirs.add(backup_dir.lower())
                # _internal 子目录（打包模式下组件在此）
                internal_dir = os.path.join(base_dir, '_internal')
                if os.path.isdir(internal_dir):
                    self._self_excluded_dirs.add(internal_dir.lower())

            # 4. 回滚仓库 + 影子原像根（PSLS 自身产出的原始文件副本，绝不扫描）。
            # 显式使用规范化路径（含 PSLS_ROLLBACK_REPO 覆盖），与仓库根同源。
            self._psls_repo_roots = []
            try:
                from engine.ransomware_rollback import (
                    repo_root_norm, shadow_root_norm, is_psls_repo_path)
                self._is_psls_repo_path = is_psls_repo_path
                for r in (repo_root_norm(), shadow_root_norm()):
                    if r:
                        self._psls_repo_roots.append(r)
                        self._self_excluded_dirs.add(r.rstrip('\\/'))
            except Exception:
                self._is_psls_repo_path = None

            logger.info(f"自身路径排除集合: {self._self_excluded_dirs}")
        except Exception as e:
            logger.error(f"初始化自身路径排除集合失败: {e}")

    def _is_psls_own_path(self, file_path: str) -> bool:
        """是否为回滚仓库 / 影子原像子树内路径（PSLS 自身产出 → 豁免扫描）。"""
        if not file_path:
            return False
        fn = getattr(self, '_is_psls_repo_path', None)
        if callable(fn):
            try:
                if fn(file_path):
                    return True
            except Exception:
                pass
        # 兜底：用规范化的仓库根做前缀比较
        try:
            p = os.path.normcase(os.path.abspath(str(file_path)))
        except Exception:
            return False
        for root in getattr(self, '_psls_repo_roots', []) or []:
            if not root:
                continue
            r = root if root.endswith(os.sep) else root + os.sep
            if p == r.rstrip('\\/') or p.startswith(r):
                return True
        return False

    def _is_self_file(self, file_path: str) -> bool:
        """检查文件是否属于 PSLS 自身目录或用户排除路径（路径级防护）"""
        if not hasattr(self, '_self_excluded_dirs') or not self._self_excluded_dirs:
            return False
        try:
            fp_lower = os.path.abspath(file_path).lower()
            for excluded_dir in self._self_excluded_dirs:
                if fp_lower.startswith(excluded_dir):
                    return True
            user_dirs = getattr(self, '_user_excluded_dirs', set())
            for excluded_dir in user_dirs:
                if fp_lower.startswith(excluded_dir):
                    return True
        except Exception:
            pass
        return False

    def set_user_excluded_dirs(self, dirs: list):
        """设置用户自定义排除路径（与自身排除目录合并使用）"""
        self._user_excluded_dirs = set()
        if dirs:
            for d in dirs:
                try:
                    normalized = os.path.abspath(str(d)).lower()
                    self._user_excluded_dirs.add(normalized)
                except Exception:
                    pass
        logger.info(f'用户排除路径已更新: {len(self._user_excluded_dirs)} 条')

    def set_ml_detector(self, ml_detector):
        """注入 ML 检测引擎实例

        由 bridge.py 在初始化后调用，将 MLMalwareDetector 实例传入，
        使扫描流程能在传统引擎判定为 clean 时补充 ML 推理。
        传入 None 可禁用 ML 补充检测。
        """
        self._ml_detector = ml_detector
        if ml_detector:
            logger.info('ML 检测引擎已注入扫描流程')
        else:
            logger.info('ML 检测引擎已从扫描流程移除')
        
    def _whitelist_self(self):
        """构建白名单体系

        三层白名单机制：
        1. 自身及项目文件白名单：将 PSLS 自身、数据库、配置文件、源码的哈希入库
        2. 可信路径白名单：TRUSTED_DIRECTORIES 中的文件跳过规则引擎和PE分析
        3. 用户白名单：通过数据库 whitelist 表存储用户手动排除的文件哈希

        注：可信路径白名单在扫描流程中通过 is_in_trusted_dir 判断实现，
        无需计算哈希，天然支持文件更新后仍然可信。
        """
        try:
            # 获取自身路径（开发模式和打包模式）
            self_path = None

            if getattr(sys, 'frozen', False):
                self_path = sys.executable
            else:
                import __main__
                main_file = getattr(__main__, '__file__', None)
                if main_file and os.path.exists(main_file):
                    self_path = main_file
                elif os.path.exists(__file__):
                    self_path = __file__

            if not self_path or not os.path.exists(self_path):
                return

            # 获取项目根目录
            self_dir = os.path.dirname(os.path.abspath(self_path))
            if not getattr(sys, 'frozen', False):
                if os.path.basename(self_dir) == 'engine':
                    self_dir = os.path.dirname(self_dir)

            whitelist_files = []

            # ---- 1. PSLS 自身文件 ----
            whitelist_files.append((self_path, 'PSLS自身可执行文件'))

            # 打包模式下，主exe所在目录的所有文件
            if getattr(sys, 'frozen', False):
                for root, _dirs, files in os.walk(self_dir):
                    for f in files:
                        fp = os.path.join(root, f)
                        ext = os.path.splitext(f)[1].lower()
                        # 可执行文件、动态库、Python运行时、资源文件
                        if ext in ('.exe', '.dll', '.pyd', '.pyi', '.zip',
                                   '.ico', '.png', '.svg', '.css', '.js',
                                   '.html', '.json', '.db', '.txt', '.manifest'):
                            whitelist_files.append((fp, f'PSLS组件: {f}'))

            # ---- 2. 数据库和配置文件 ----
            data_paths = [
                (os.path.join(self_dir, 'db', 'signatures.db'), '签名数据库'),
                (os.path.join(self_dir, 'db', 'signatures.db-journal'), '签名数据库日志'),
                (os.path.join(self_dir, 'quarantine', 'quarantine.json'), '隔离区数据'),
                (os.path.join(self_dir, 'icon.ico'), '应用程序图标'),
            ]
            for path, reason in data_paths:
                if os.path.exists(path):
                    whitelist_files.append((path, reason))

            # ---- 3. 开发模式下的源码文件 ----
            if not getattr(sys, 'frozen', False):
                src_dirs = ['engine', 'ui', 'utils', 'db', 'models', 'rules']
                for src_dir in src_dirs:
                    dir_path = os.path.join(self_dir, src_dir)
                    if os.path.exists(dir_path):
                        for root, dirs, files in os.walk(dir_path):
                            for f in files:
                                ext = os.path.splitext(f)[1].lower()
                                # .py 源码 + .pyc 字节码 + 模型/规则/数据文件
                                if ext in ('.py', '.pyc', '.pyw', '.pyo',
                                           '.onnx', '.yar', '.yac', '.yc',
                                           '.json', '.db', '.txt', '.csv',
                                           '.html', '.js', '.css', '.svg', '.png',
                                           '.ico', '.mp3', '.wav'):
                                    fp = os.path.join(root, f)
                                    whitelist_files.append((fp, f'源码: {src_dir}/{f}'))

                # HTML/JS/CSS 前端资源
                ui_dir = os.path.join(self_dir, 'ui', 'webview')
                if os.path.isdir(ui_dir):
                    for f in os.listdir(ui_dir):
                        ext = os.path.splitext(f)[1].lower()
                        if ext in ('.html', '.js', '.css', '.svg', '.png'):
                            fp = os.path.join(ui_dir, f)
                            whitelist_files.append((fp, f'前端资源: {f}'))

            # ---- 4. Python 运行时关键文件 ----
            if not getattr(sys, 'frozen', False):
                python_exe = sys.executable
                if python_exe and os.path.exists(python_exe):
                    whitelist_files.append((python_exe, 'Python解释器'))
                python_dir = os.path.dirname(python_exe) if python_exe else ''
                if python_dir:
                    for dll in ('python3.dll', 'python3{}.dll'.format(
                            str(sys.version_info.major) + str(sys.version_info.minor)),
                            'vcruntime140.dll', 'vcruntime140_1.dll'):
                        dll_path = os.path.join(python_dir, dll)
                        if os.path.exists(dll_path):
                            whitelist_files.append((dll_path, f'Python运行时: {dll}'))

            # 计算哈希并写入白名单
            added = 0
            for file_path, reason in whitelist_files:
                try:
                    file_hash = compute_sha256(file_path)
                    if file_hash and not self.signature_db.is_whitelisted(file_hash):
                        self.signature_db.add_to_whitelist(file_hash, reason)
                        added += 1
                except Exception:
                    pass

            logger.info(f"白名单初始化完成: 检查 {len(whitelist_files)} 个文件，新增 {added} 条白名单记录")

        except Exception as e:
            logger.error(f"初始化白名单失败: {e}")
    
    def _get_study_engine(self):
        """懒加载 study-engine。返回实例或 None(不可用/被禁用)。"""
        if not _HAS_UNIFIED or StudyEngine is None:
            return None
        if self._study_engine is None:
            try:
                self._study_engine = StudyEngine()
            except Exception:
                self._study_engine = None
        return self._study_engine

    @staticmethod
    def _study_api_hist(pe_analysis) -> list:
        """从 pe_analysis 的 suspicious_imports 提取 ApiHash 桶索引。

        桶范围与 ONNX API-hash 约定一致([377,512))，仅用于 study-engine 内部记录间的
        一致性比较(变种近似匹配)，无需与训练特征完全对齐。
        """
        if not isinstance(pe_analysis, dict):
            return []
        imp = pe_analysis.get('suspicious_imports') or []
        if not imp:
            return []
        import zlib as _z
        hist = []
        seen = set()
        for x in imp:
            name = (x.get('name') or x.get('api') or '') if isinstance(x, dict) else str(x or '')
            name = str(name or '').lower()
            if not name or name in seen:
                continue
            seen.add(name)
            bucket = 377 + (_z.crc32(name.encode('utf-8')) % (512 - 377))
            hist.append(bucket)
        return hist

    def _study_record(self, file_hash, file_size, ext, pe_analysis, status):
        """学习闭环: 将扫描最终结论(after 全引擎判定)写回 study-engine。

        status: 'clean' -> benign 指纹(FP 压制核心);
                'malware' -> malicious 指纹(增强已知样本/变种召回)。
        """
        se = self._get_study_engine()
        if se is None:
            return
        try:
            se.add_record(meta={
                'sha256': file_hash or '',
                'size': int(file_size or 0),
                'ext': ext or '',
                'api_hist': self._study_api_hist(pe_analysis),
            }, label='malicious' if status == 'malware' else 'benign')
        except Exception:
            pass

    def _unified_confidence(self, *, file_hash=None, file_size=0, ext='',
                            pe_score: float = 0, pe_analysis: Optional[dict] = None,
                            rule_matches: Optional[list] = None,
                            heuristic_matches: Optional[list] = None,
                            ml_verdict: Optional[str] = None, ml_prob: float = 0.0,
                            ml_main_verdict: Optional[str] = None,
                            ml_main_prob: float = 0.0,
                            entropy_high: bool = False,
                            behavior: Optional[dict] = None) -> float:
        """汇聚多源证据，返回统一置信分(0-100)。未启用综合评分时返回 None 语义: 调方按原逻辑。"""
        if not _HAS_UNIFIED or compute_confidence is None:
            return None
        rule_matches = rule_matches or []
        heuristic_matches = heuristic_matches or []
        behavior = behavior or {}

        def _sev_count(lst, sev):
            return sum(1 for m in lst if m.get('severity') == sev)

        evidence = {
            'rule_yara_high': _sev_count(
                [m for m in rule_matches
                 if str(m.get('rule_type', '')).startswith('yara')], 'high'),
            'rule_high': _sev_count(
                [m for m in rule_matches
                 if not str(m.get('rule_type', '')).startswith('yara')], 'high'),
            'rule_medium': _sev_count(rule_matches, 'medium')
                            + _sev_count(heuristic_matches, 'medium'),
            'rule_low': _sev_count(rule_matches, 'low')
                        + _sev_count(heuristic_matches, 'low'),
            'pe_score': float(pe_score or 0.0),
            'entropy_high': bool(entropy_high),
            'api_evidence': 0.0,
        }
        # ApiHash 导入证据(复用 pe_analysis, 避免重复解析)
        if _compute_api_evidence_signal is not None:
            try:
                evidence['api_evidence'] = float(
                    _compute_api_evidence_signal(pe_analysis) or 0.0)
            except Exception:
                evidence['api_evidence'] = 0.0
        # ML 概率：主引擎(lgb)走确定性直判键；回退引擎走弱信号加权键
        if ml_main_verdict in ('malware', 'suspicious'):
            evidence['ml_main_verdict'] = ml_main_verdict
            evidence['ml_main_prob'] = float(ml_main_prob or 0.0)
        elif ml_verdict == 'malware':
            evidence['ml_malware_prob'] = float(ml_prob or 0.0)
        elif ml_verdict == 'suspicious':
            evidence['ml_susp_prob'] = float(ml_prob or 0.0)
        # study-engine 指纹(只读匹配)
        try:
            se = self._get_study_engine()
            if se is not None:
                m = se.match(meta={
                    'sha256': file_hash or '',
                    'size': int(file_size or 0),
                    'ext': ext or '',
                    'api_hist': self._study_api_hist(pe_analysis),
                })
                if m and m.get('label'):
                    evidence['study'] = m['label']
        except Exception:
            pass
        # 行为启发证据(BehaviorAnalyzer.evaluate/snapshot_for_scan 产出)：
        # 确认级(behavior_confirmed)直接短路 malware；佐证级(behavior_chain)叠加。
        # 上层已在喂入前保证"无签名+非白名单"，此处仅透传。
        if behavior.get('behavior_confirmed'):
            evidence['behavior_confirmed'] = True
        b_chain = behavior.get('behavior_chain')
        if b_chain:
            evidence['behavior_chain'] = float(b_chain)
        return compute_confidence(evidence)

    def _confirm_weak_suspicious(self, confidence) -> bool:
        """弱证据路径的统一置信下限把关。confidence 为 None(未启用)时保持原判定。"""
        if confidence is None:
            return True  # 未启用统一评分，维持原逻辑
        return confirm_suspicious(confidence)

    def scan_file(self, file_path: str) -> ScanResult:
        """
        扫描单个文件（不包含归档内部扫描）
        
        集成多重检测引擎：
        1. 哈希签名匹配
        2. 规则引擎（字节模式匹配）
        3. PE文件分析（结构分析）
        
        误报减少策略：
        - 可信目录跳过深度分析
        - 小文件跳过规则引擎
        - 规则匹配需达到最小置信度
        - PE分析需达到更高阈值
        
        Args:
            file_path: 文件路径
            
        Returns:
            ScanResult 对象
        """
        try:
            # 路径级自身保护：PSLS 自身文件、备份目录、APPDATA\PSLS 永不扫描
            if self._is_self_file(file_path):
                return ScanResult(file_path, 'clean')
            # 回滚仓库 / 影子原像根：PSLS 自身产出（原始文件副本），豁免扫描
            if self._is_psls_own_path(file_path):
                return ScanResult(file_path, 'clean')

            # 获取文件扩展名
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()
            
            # 获取文件大小
            try:
                file_size = os.path.getsize(file_path)
            except Exception:
                file_size = 0

            # 检查文件大小限制（0 表示无限制）
            # 可执行/脚本类不做 50MB 体积豁免（唯一能直接运行的载体，下载来的
            # 大体积木马常 >50MB），放宽到 exec_scan_hard_limit_bytes；其余类型
            # （归档/媒体/镜像）仍按 max_file_size_mb 跳过，避免全盘扫描被拖慢。
            if self.max_file_size_mb and self.max_file_size_mb > 0:
                max_bytes = self.max_file_size_mb * 1024 * 1024
                _ext_l = os.path.splitext(file_path)[1].lower()
                if _ext_l in self.EXECUTABLE_EXTENSIONS:
                    if file_size > self.exec_scan_hard_limit_bytes:
                        logger.warning(
                            f'文件超过可执行类硬上限 '
                            f'{self.exec_scan_hard_limit_bytes // (1024 * 1024)}MB，跳过: '
                            f'{file_path} ({file_size} bytes)')
                        return ScanResult(file_path, 'skipped', None)
                elif file_size > max_bytes:
                    # 超过大小限制，跳过扫描
                    return ScanResult(file_path, 'skipped', None)

            # 检查是否在可信目录中（跳过规则引擎和PE分析）
            file_path_lower = file_path.lower()
            is_in_trusted_dir = any(file_path_lower.startswith(trusted_dir) for trusted_dir in self.TRUSTED_DIRECTORIES)
            
            # 计算文件哈希（带重试，杀软锁定时自动退避）
            file_hash = compute_sha256(file_path)
            hash_available = bool(file_hash)
            # 哈希不可用时不立即跳过，继续跑 YARA/PE/启发式/熵检测
            # 这些引擎独立 open 文件，可能成功检出（签名匹配除外，必须依赖哈希）

            # 白名单检查（仅哈希可用时）
            if hash_available and self.signature_db.is_whitelisted(file_hash):
                return ScanResult(file_path, 'clean')
            
            # 签名匹配（最高优先级，必须哈希可用）
            is_confirmed_malware = False
            if hash_available and self.signature_db.is_malware(file_hash):
                malware_info = self.signature_db.get_malware_info(file_hash)
                # 注意: get_malware_info 返回的是签名库共享缓存实例, 绝不能原地修改
                # name —— 否则同一哈希文件每被扫描一次 name 就多包一层前缀,
                # 日志出现 "签名库发现威胁: 签名库发现威胁: ..." 无限循环
                malware_info = dict(malware_info) if isinstance(malware_info, dict) else {}
                if malware_info.get('name'):
                    malware_info['name'] = f"签名库发现威胁: {malware_info['name']}"
                else:
                    malware_info['name'] = '签名库发现威胁'
                return ScanResult(file_path, 'malware', malware_info=malware_info)

            # ========== 可信签名提前快速放行（降误报+提性能）==========
            # 对 PE 可执行文件：如果有有效签名且发布者在可信列表中，
            # 直接返回 clean + 加入白名单，跳过模糊哈希/规则引擎/PE分析/启发式/熵检测
            # 理由：微软/Adobe/Google/Sysinternals 等可信厂商的文件不可能是恶意
            if (not is_in_trusted_dir
                    and ext in self.EXECUTABLE_EXTENSIONS
                    and self._signature_verifier
                    and file_size > 0):
                try:
                    _signer = self._get_signer_info_cached(file_path)
                    if _signer and _signer.get('verified', False):
                        _pub = (_signer.get('publisher') or '').lower()
                        if any(_t in _pub for _t in TRUSTED_SIGNER_SUBSTRINGS):
                            try:
                                if file_hash and not self.signature_db.is_whitelisted(file_hash):
                                    self.signature_db.add_to_whitelist(
                                        file_hash, f'可信签名快速放行（{os.path.basename(file_path)}）'
                                    )
                            except Exception:
                                pass
                            return ScanResult(file_path, 'clean')
                except Exception:
                    pass

            # ========== .lnk 快捷方式专用处理 ==========
            # .lnk 自身不含可执行代码，直接对二进制做 content 规则/启发式/ViiD 会误报
            # 正确做法：解析快捷方式目标路径和参数，对目标做安全评估
            if not is_in_trusted_dir and ext == '.lnk' and file_size > 0:
                lnk_info = _parse_lnk_file(file_path)
                if lnk_info:
                    lnk_matches = _check_lnk_suspicious(lnk_info)
                    if lnk_matches:
                        return ScanResult(file_path, 'suspicious',
                                          malware_info={'name': '快捷方式指向可疑目标'},
                                          rule_matches=lnk_matches)
                    # 目标不可疑 → clean
                    return ScanResult(file_path, 'clean')

            # --- 模糊哈希（CTPH）匹配：精确 miss 时兜底同源样本 ---
            if not is_in_trusted_dir and file_size > 0 and file_size <= self.FUZZY_MAX_SIZE:
                fuzzy_sigs = self._get_fuzzy_signatures()
                if fuzzy_sigs:
                    current_fuzzy = fuzzy_file(file_path)
                    if current_fuzzy and ':' in current_fuzzy:
                        best_score = 0
                        best_sig = None
                        for sig in fuzzy_sigs:
                            s = fuzzy_compare(current_fuzzy, sig['fuzzy_hash'])
                            if s > best_score:
                                best_score = s
                                best_sig = sig
                        if best_sig and best_score >= self.FUZZY_THRESHOLD:
                            ref = best_sig['name'] or best_sig['sha256'][:16]
                            return ScanResult(
                                file_path, 'suspicious',
                                malware_info={
                                    'name': f'模糊哈希命中（与 {ref} 相似度 {best_score}%）',
                                    'fuzzy_score': best_score,
                                    'fuzzy_match_sha256': best_sig['sha256'],
                                },
                            )

            # 规则引擎扫描（仅对非可信目录且大于1KB的文件）
            rule_matches = []
            if not is_in_trusted_dir and file_size >= self.MIN_FILE_SIZE_FOR_RULE_SCAN:
                rule_matches = self.rule_engine.scan_file(file_path)
            
            if rule_matches:
                high_severity = any(m.get('severity') == 'high' for m in rule_matches)
                medium_severity = [m for m in rule_matches if m.get('severity') == 'medium']
                low_severity = [m for m in rule_matches if m.get('severity') == 'low']
                threat_matches = [m for m in rule_matches if m.get('severity') in ('high', 'medium', 'low')]

                # 区分 YARA 引擎和自研规则引擎的检测来源
                yara_matches = [m for m in rule_matches if m.get('rule_type', '').startswith('yara')]
                builtin_matches = [m for m in rule_matches if not m.get('rule_type', '').startswith('yara')]
                if yara_matches and not builtin_matches:
                    detection_source = 'YARA引擎发现威胁'
                elif yara_matches and builtin_matches:
                    detection_source = 'YARA引擎发现威胁'
                else:
                    detection_source = '规则引擎发现威胁'

                # === 判定策略：严格模式 1 个 low 即触发，宽松模式需 2 个 ===
                low_threshold = RULE_LOW_THRESHOLD_STRICT if self.strict_mode else RULE_LOW_THRESHOLD_NORMAL
                med_threshold = RULE_MEDIUM_THRESHOLD_STRICT if self.strict_mode else RULE_MEDIUM_THRESHOLD_NORMAL
                if high_severity:
                    file_status = 'malware' if len(threat_matches) >= 1 else 'suspicious'
                    return ScanResult(
                        file_path,
                        file_status,
                        malware_info={'name': detection_source, 'rule_matches': rule_matches},
                        rule_matches=rule_matches,
                    )
                elif len(medium_severity) >= med_threshold:
                    return ScanResult(file_path, 'suspicious', malware_info={'name': detection_source}, rule_matches=rule_matches)
                elif len(low_severity) >= low_threshold:
                    return ScanResult(file_path, 'suspicious', malware_info={'name': detection_source}, rule_matches=rule_matches)
                elif len(threat_matches) >= 2:
                    return ScanResult(file_path, 'suspicious', malware_info={'name': detection_source}, rule_matches=rule_matches)

            # ============ VirusIdentifier 综合引擎（覆盖 PE + 非 PE） ============
            # 单进程入口此前缺失 VirusIdentifier — 非 PE 文件（JS/VBS/...）无法被综合分析
            # [前置快速放行] 纯数据/纯文本文件跳过 ViiD 7 维分析（与 worker 路径一致）
            if (not is_in_trusted_dir and self._virus_identifier
                    and self.virus_identifier_enabled
                    and not (self.EXECUTABLE_EXTENSIONS is not None
                             and ext not in self.EXECUTABLE_EXTENSIONS
                             and ext in _PURE_DATA_EXTENSIONS)):
                try:
                    vi_result = self._virus_identifier.identify(file_path, precomputed_sha256=file_hash)
                    if vi_result:
                        vi_score = int(vi_result.get('score', 0))
                        vi_sev = (vi_result.get('severity') or 'low').lower()
                        if vi_score >= 28 or vi_sev in ('critical', 'high'):
                            # 交叉确认：VirusIdentifier 是纯启发式打分引擎，
                            # 单独判恶意误报偏高，须由独立引擎（PE 结构分析 /
                            # ML）同向确认；否则降级为可疑（保留告警）。
                            _vi_confirmed = _vi_cross_confirm(
                                file_path, ext, self.pe_analyzer,
                                self._ml_detector, self.strict_mode,
                                self.EXECUTABLE_EXTENSIONS)
                            return ScanResult(
                                file_path,
                                'malware' if _vi_confirmed else 'suspicious',
                                malware_info={
                                    'name': ('VirusIdentifier 检测到威胁（已交叉确认）'
                                             if _vi_confirmed else
                                             'VirusIdentifier 检测到可疑迹象（单引擎未交叉确认）'),
                                    'vi_score': vi_score, 'vi_severity': vi_sev,
                                    'malware_type': vi_result.get('malware_type'),
                                    'vi_reasons': vi_result.get('reasons'),
                                })
                        elif vi_score >= 8 or vi_sev == 'medium':
                            return ScanResult(
                                file_path, 'suspicious',
                                malware_info={
                                    'name': 'VirusIdentifier 检测到可疑迹象',
                                    'vi_score': vi_score, 'vi_severity': vi_sev,
                                })
                except Exception as e:
                    logger.debug(f'VirusIdentifier 单进程扫描异常: {e}')

            # PE文件分析（可信目录中的可执行文件仍做 PE 分析，防止 DLL 侧载攻击）
            pe_analysis = {}
            pe_score = 0
            # 微软官方签名标记（用于PE分析后所有引擎的统一快速放行）
            is_microsoft_signed = False
            # 有效 Authenticode 签名标记（降误报：确定性证据优先于内容启发式）
            has_verified_sig = False

            if ext in self.EXECUTABLE_EXTENSIONS:
                # ============= 微软官方签名快速放行检查（可信目录） =============
                # 在可信目录中的 PE 文件，如果有微软官方有效签名，直接判定 clean 并加入白名单
                # 避免对 rundll32.exe / svchost.exe / mousocoreworker.exe / UEdOrchestrator.exe 等系统组件误报
                if is_in_trusted_dir and self._signature_verifier:
                    try:
                        _signer = self._get_signer_info_cached(file_path)
                        if _signer and _signer.get('verified', False):
                            _pub = (_signer.get('publisher') or '').lower()
                            if 'microsoft' in _pub or 'windows' in _pub:
                                # 可信目录 + 微软有效签名 → 直接 clean + 自动白名单缓存
                                try:
                                    if file_hash and not self.signature_db.is_whitelisted(file_hash):
                                        self.signature_db.add_to_whitelist(
                                            file_hash, f'微软官方签名可信文件（{os.path.basename(file_path)}）'
                                        )
                                except Exception:
                                    pass
                                return ScanResult(file_path, 'clean')
                    except Exception:
                        pass

                # ============= 通用有效签名降误报（任意目录） =============
                # 有效 Authenticode 签名是"文件未被篡改+来自已知发布者"的确定性证据，
                # 其可信度远高于 PE 启发式/熵/ML 概率等内容特征。对已签名文件：
                #   - PE 启发式阈值大幅抬高（只保留极强信号）
                #   - 跳过基于导入表/字符串的文件启发式规则（对签名软件噪声极大）
                #   - ML 独立判 malware 需 0.95 + 交叉印证
                # 这能消除大量对合法签名软件（Electron/Node/安装包等）的误报，
                # 同时保留对超高分 PE 与极高置信 ML 的检测能力。
                if self._signature_verifier:
                    try:
                        _sig = self._get_signer_info_cached(file_path)
                        if _sig and _sig.get('verified', False):
                            has_verified_sig = True
                    except Exception:
                        pass

                pe_analysis = self.pe_analyzer.analyze(file_path)
                pe_score = pe_analysis.get('total_score', 0) or 0

                # === 判定策略：严格模式 vs 宽松模式阈值 ===
                pe_malw_th = PE_MALWARE_THRESHOLD_STRICT if self.strict_mode else PE_MALWARE_THRESHOLD_NORMAL
                pe_susp_th = PE_SUSPICIOUS_THRESHOLD_STRICT if self.strict_mode else PE_SUSPICIOUS_THRESHOLD_NORMAL
                # 已签名文件：抬高 PE 阈值，仅保留极强启发式信号
                if has_verified_sig:
                    pe_malw_th = max(pe_malw_th, 95)
                    pe_susp_th = max(pe_susp_th, 60)
                if pe_analysis.get('severity') == 'high' or pe_score >= pe_susp_th:
                    if pe_score >= pe_malw_th:
                        pe_status = 'malware'
                    elif pe_score >= (pe_malw_th + pe_susp_th) // 2:
                        pe_status = 'suspicious'
                    elif pe_analysis.get('severity') == 'high':
                        pe_status = 'suspicious'
                    elif pe_score >= pe_susp_th:
                        pe_status = 'suspicious'
                    else:
                        pe_status = None

                    if pe_status:
                        pe_malware_info = {'name': 'PE文件分析发现威胁',
                                           'pe_score': pe_score,
                                           'details': pe_analysis.get('details')}

                        # 数字签名验证：仅微软官方签名文件可降级，第三方签名保留告警
                        if self._signature_verifier:
                            try:
                                signer = self._get_signer_info_cached(file_path)
                            except Exception:
                                signer = None

                            verified = False
                            is_microsoft = False
                            if signer:
                                verified = signer.get('verified', False)
                                pub = (signer.get('publisher') or '').lower()
                                is_microsoft = verified and ('microsoft' in pub or 'windows' in pub)
                                pe_analysis['signature_verified'] = verified
                                if signer.get('publisher'):
                                    pe_analysis['signature_publisher'] = signer.get('publisher')
                            else:
                                # fallback 到旧接口
                                try:
                                    verified = self._signature_verifier.verify_signature(file_path)
                                except Exception:
                                    verified = False
                                if verified:
                                    pe_analysis['signature_verified'] = True
                                    is_microsoft = False

                            if verified:
                                if pe_status == 'malware':
                                    if pe_score >= 95 and not is_microsoft:
                                        # 第三方签名+超高分：仅降为 suspicious
                                        pe_status = 'suspicious'
                                        pe_malware_info['note'] = '第三方签名高分恶意（保留告警）'
                                    elif is_microsoft:
                                        # 微软官方签名：PE分析中任何判定直接放行（微软签名文件从不需要PE告警）
                                        pe_status = None
                                    else:
                                        pe_status = 'suspicious'
                                        pe_malware_info['note'] = '已签名文件（降级处理）'
                                else:  # suspicious -> clean（任何有效签名的suspicious都放行）
                                    pe_status = None

                        if pe_status:
                            return ScanResult(
                                file_path, pe_status,
                                malware_info=pe_malware_info,
                                pe_analysis=pe_analysis,
                            )
            
            # 启发式扫描（仅对非可信目录中的文件；已签名文件跳过——导入表/字符串规则
            # 对签名合法软件噪声极大，签名本身是更强的确定性证据）
            heuristic_matches = []
            if not is_in_trusted_dir and not has_verified_sig:
                heuristic_matches = self._heuristic_scan(file_path)
            
            if heuristic_matches:
                high_count = sum(1 for m in heuristic_matches if m.get('severity') == 'high')
                medium_count = sum(1 for m in heuristic_matches if m.get('severity') == 'medium')
                low_count = sum(1 for m in heuristic_matches if m.get('severity') == 'low')

                # 降误报: high单独触发, medium需≥2或叠加low≥2
                if high_count >= 1:
                    return ScanResult(file_path, 'suspicious', malware_info={'name': '启发式扫描发现威胁'}, heuristic_matches=heuristic_matches)
                elif medium_count >= 2:
                    return ScanResult(file_path, 'suspicious', malware_info={'name': '启发式扫描发现威胁'}, heuristic_matches=heuristic_matches)
                elif medium_count >= 1 and low_count >= 2:
                    return ScanResult(file_path, 'suspicious', malware_info={'name': '启发式扫描发现威胁'}, heuristic_matches=heuristic_matches)
            
            # 基于熵的内容检测：严格模式阈值 7.3，宽松模式阈值 7.6
            # 降误报：
            #   1. 压缩/编码媒体格式天然高熵 → 直接跳过（PNG/JPEG/MP3/ZIP/AMR 等）
            #   2. 用户数据目录（Documents/Downloads/Tencent Files）→ 关闭熵检测
            #   3. 有有效签名的文件跳过熵检测（自解压安装包/壳正常高熵）
            #   4. 仅对可执行扩展名 + 小可疑文件触发熵告警
            if (not is_in_trusted_dir
                    and not _is_in_user_data_dir(file_path)
                    and file_size >= 64
                    and ext not in _ENTROPY_SKIP_EXTS):
                try:
                    file_content = self._read_file_content(file_path)
                    if file_content:
                        entropy = self._calculate_shannon_entropy(file_content)
                        entropy_th = ENTROPY_THRESHOLD_STRICT if self.strict_mode else ENTROPY_THRESHOLD_NORMAL
                        if entropy > entropy_th:
                            entropy_skip_signature = False
                            if self._signature_verifier:
                                try:
                                    _sig = self._get_signer_info_cached(file_path)
                                    if _sig and _sig.get('verified', False):
                                        entropy_skip_signature = True
                                except Exception:
                                    pass
                            if entropy_skip_signature:
                                pass
                            else:
                                suspicious_ext = ext in (
                                    '.exe', '.dll', '.sys', '.scr', '.pif', '.com',
                                    '.bin', '.dat', '.drv', '.ocx', '.cpl',
                                )
                                # 熵告警只对可执行扩展名或 < 16KB 的无扩展名/未知小文件触发
                                # （大的非可执行文件即便高熵也是合法压缩/数据）
                                if suspicious_ext or file_size < 16384:
                                    return ScanResult(
                                        file_path, 'suspicious',
                                        malware_info={'name': f'熵监测发现威胁 (熵={entropy:.2f})'},
                                    )
                except Exception:
                    pass

            # 统计规则匹配中严重等级
            rule_high_count = sum(1 for m in rule_matches if m.get('severity') == 'high')
            rule_med_count = sum(1 for m in rule_matches if m.get('severity') == 'medium')
            heuristic_high_count = sum(1 for m in heuristic_matches if m.get('severity') == 'high')
            heuristic_med_count = sum(1 for m in heuristic_matches if m.get('severity') == 'medium')

            # ---- ML 引擎补充检测（交叉验证上下文） ----
            if self._ml_detector and not is_in_trusted_dir:
                try:
                    # 同步严格模式到 ML 引擎（动态调整 ML 阈值）
                    if hasattr(self._ml_detector, 'set_strict_mode'):
                        self._ml_detector.set_strict_mode(self.strict_mode)
                    _ml_stats_incr('ml_called')
                    ml_source = None
                    if hasattr(self._ml_detector, 'detect_with_context_with_source'):
                        ml_result, ml_source = self._ml_detector.detect_with_context_with_source(
                            file_path,
                            pe_score=pe_score,
                            rule_high_count=rule_high_count,
                            rule_medium_count=rule_med_count,
                            heuristic_high_count=heuristic_high_count,
                            heuristic_medium_count=heuristic_med_count,
                        )
                    elif hasattr(self._ml_detector, 'detect_with_context'):
                        ml_result = self._ml_detector.detect_with_context(
                            file_path,
                            pe_score=pe_score,
                            rule_high_count=rule_high_count,
                            rule_medium_count=rule_med_count,
                            heuristic_high_count=heuristic_high_count,
                            heuristic_medium_count=heuristic_med_count,
                        )
                    else:
                        ml_result = self._ml_detector.predict(file_path)
                    if ml_result:
                        ml_verdict, ml_prob = ml_result
                        _ml_is_main = (ml_source == 'lgb')
                        if ml_verdict == 'malware':
                            _ml_stats_incr('ml_malware')
                            # malware: 高概率独立判定, 中概率需其他维度印证
                            has_evidence = (pe_score >= 45 or rule_high_count >= 1
                                            or rule_med_count >= 2 or heuristic_high_count >= 1)
                            # 已签名文件：确定性签名证据优先，ML 独立判 malware 必须
                            # 极高置信(≥0.95) + 交叉印证，避免对合法签名软件误报
                            if has_verified_sig:
                                if ml_prob >= 0.95 and has_evidence:
                                    final_status = 'malware'
                                else:
                                    final_status = 'suspicious' if ml_prob >= 0.85 else None
                            elif ml_prob >= 0.88:
                                final_status = 'malware'
                            elif ml_prob >= 0.78 and has_evidence:
                                final_status = 'malware'
                            else:
                                final_status = 'suspicious'
                            if final_status is None:
                                # 签名 + ML 中低置信：静默放行，由后续扫描决定
                                pass
                            else:
                                # study-engine 学习闭环: 高置信恶意才记录为 malicious(避免单次误判污染指纹库)
                                if final_status == 'malware' and file_hash:
                                    self._study_record(file_hash, file_size, ext, pe_analysis, 'malware')
                                return ScanResult(
                                    file_path, final_status,
                                    malware_info={
                                        'name': 'ML引擎发现威胁',
                                        'ml_probability': round(ml_prob, 4),
                                        'ml_verdict': ml_verdict,
                                        'ml_source': ml_source or 'unknown',
                                    },
                                )
                        elif ml_verdict == 'suspicious':
                            _ml_stats_incr('ml_susp')
                            # suspicious: 必须有其他维度印证才告警, 否则ML独立suspicious很可能是误报
                            # pe_score 提升到 40，规则/启发式需 ≥2 条 medium 或 ≥1 条 high 才佐证
                            cross_evidence = (
                                pe_score >= 40 or rule_high_count >= 1
                                or rule_med_count >= 2 or heuristic_high_count >= 1
                                or heuristic_med_count >= 2
                            )
                            # 统一置信门控: 弱交叉印证(sus)还需置信分达标才判 suspicious,
                            # 过滤"ML中危 + 单维弱佐证"的白样本误报。
                            # 主引擎(lgb)直判走确定性入口(>=56)，回退引擎仍走加权语义。
                            _conf = self._unified_confidence(
                                file_hash=file_hash, file_size=file_size, ext=ext,
                                pe_score=pe_score, pe_analysis=pe_analysis,
                                rule_matches=rule_matches,
                                heuristic_matches=heuristic_matches,
                                ml_verdict=(None if _ml_is_main else ml_verdict),
                                ml_prob=(0.0 if _ml_is_main else ml_prob),
                                ml_main_verdict=(ml_verdict if _ml_is_main else None),
                                ml_main_prob=(ml_prob if _ml_is_main else 0.0),
                            )
                            if cross_evidence and self._confirm_weak_suspicious(_conf):
                                return ScanResult(
                                    file_path, 'suspicious',
                                    malware_info={
                                        'name': f'ML引擎发现威胁 (概率={ml_prob:.2f})',
                                        'ml_probability': round(ml_prob, 4),
                                        'ml_verdict': 'suspicious',
                                        'ml_source': ml_source or 'unknown',
                                    },
                                )
                            # 无交叉印证或置信不足 → ML suspicious 静默放行, 由后续扫描决定
                    else:
                        _ml_stats_incr('ml_none')
                except Exception as e:
                    _ml_stats_incr('ml_failed')
                    logger.warning(f'ML 推理异常 {file_path}: {e}')

            # 扫描结果 clean → 自动加入白名单（避免重复扫描）
            # 仅对非可信目录、经过完整引擎扫描的文件加白（避免系统目录过度膨胀）
            if file_hash and not is_in_trusted_dir:
                try:
                    if not self.signature_db.is_whitelisted(file_hash):
                        whitelist_reason = (f'引擎自动放行 '
                                            f'(PE={pe_score}分, '
                                            f'规则high={rule_high_count}/med={rule_med_count}, '
                                            f'启发high={heuristic_high_count}/med={heuristic_med_count})')
                        self.signature_db.add_to_whitelist(file_hash, whitelist_reason)
                except Exception:
                    pass
                # study-engine 学习闭环: 记住 clean 指纹(含 API 变种), 抑制后续误报
                self._study_record(file_hash, file_size, ext, pe_analysis, 'clean')

            # 哈希不可用且所有引擎 clean → 文件可能被外部因素锁定
            # 返回 skipped 而非 clean：clean 表示"已确认干净"，skipped 表示"无法确认"
            if not hash_available:
                logger.debug(f'单进程 scan_file 哈希不可用且所有引擎 clean，标记 skipped: {file_path}')
                return ScanResult(file_path, 'skipped')

            return ScanResult(file_path, 'clean')
            
        except Exception as e:
            logger.error(f"扫描文件失败 {file_path}: {e}")
            return ScanResult(file_path, 'error')
    
    def scan_file_with_archives(self, file_path: str) -> List[ScanResult]:
        """
        扫描单个文件，包括归档文件内部的内容
        
        Args:
            file_path: 文件路径
            
        Returns:
            ScanResult 对象列表
        """
        results = []
        
        # 首先扫描文件本身
        result = self.scan_file(file_path)
        results.append(result)

        # 如果启用了归档扫描，检查是否为归档文件并扫描内部
        if self.scan_archives and self.archive_scanner:
            archive_results = self.archive_scanner.scan_archive(
                file_path,
                self.signature_db._malware_hashes,
                self.heuristic_rules,
                rule_engine=self.rule_engine,
            )
            
            # 基于 internal_path 去重，避免嵌套归档或并发产生重复结果
            # archive_scanner 已将同一内部文件的多个检测来源合并为一条最高严重度记录，
            # 此处 seen_internal 作为防御性去重，确保即使边界情况也不会重复生成 ScanResult
            seen_internal = set()
            for ar in archive_results:
                internal_path = ar.get('internal_path', '')
                status = ar.get('status', 'clean')

                # 同一 internal_path 只保留第一条（已合并为最高严重度）
                if internal_path and internal_path in seen_internal:
                    continue
                if internal_path:
                    seen_internal.add(internal_path)

                if status == 'malware':
                    rule_matches = ar.get('rule_matches', [])
                    hash_match = ar.get('hash_match', False)
                    if hash_match:
                        # 哈希匹配优先显示签名库（即使同时命中规则引擎）
                        results.append(ScanResult(
                            file_path,
                            'malware',
                            malware_info={'name': f"签名库发现威胁: {internal_path}"},
                            internal_path=internal_path,
                            rule_matches=rule_matches,
                        ))
                    elif rule_matches:
                        # 如果有规则匹配，区分 YARA 和自研规则
                        yara_hits = [m for m in rule_matches if m.get('rule_type', '').startswith('yara')]
                        source = 'YARA引擎发现威胁' if yara_hits else '规则引擎发现威胁'
                        results.append(ScanResult(
                            file_path,
                            'malware',
                            malware_info={'name': f"{source}: {internal_path}"},
                            internal_path=internal_path,
                            rule_matches=rule_matches,
                        ))
                    else:
                        # 否则使用签名库检测
                        results.append(ScanResult(
                            file_path,
                            'malware',
                            malware_info={'name': f"签名库发现威胁: {internal_path}"},
                            internal_path=internal_path,
                        ))
                elif status == 'suspicious':
                    reason = ar.get('reason', '')
                    heuristic_matches = ar.get('heuristic_matches', [])
                    rule_matches = ar.get('rule_matches', [])
                    results.append(ScanResult(
                        file_path,
                        'suspicious',
                        heuristic_matches=heuristic_matches if heuristic_matches else [{'name': reason}],
                        internal_path=internal_path,
                        rule_matches=rule_matches,
                    ))
        
        return results

    def scan_file_with_archives_summary(self, file_path: str) -> dict:
        """扫描单个文件并返回聚合摘要 dict（给单文件处置场景使用）

        说明：scan_file_with_archives 返回 List[ScanResult]（每个内部文件一条结果），
        但调用方（进程保护、行为处置）只需知道该文件最终是恶意/可疑/干净，
        因此本方法聚合所有结果，按 malware > suspicious > clean 优先级，
        返回结构为:
          {
            'status': 'malware' | 'suspicious' | 'clean',
            'name': '病毒名或内部威胁路径（最严重一条）',
            'malware_count': int,
            'suspicious_count': int,
            'clean_count': int,
          }

        Returns:
            聚合结果 dict，与 ScanResult 对象不同，可安全使用 .get()
        """
        scan_results = self.scan_file_with_archives(file_path)

        summary = {
            'status': 'clean',
            'name': '',
            'malware_count': 0,
            'suspicious_count': 0,
            'clean_count': 0,
        }

        malware_name = ''
        suspicious_name = ''

        for r in scan_results:
            status = str(r.status) if r and hasattr(r, 'status') else 'clean'
            if status == 'malware':
                summary['malware_count'] += 1
                if not malware_name:
                    info = r.malware_info if hasattr(r, 'malware_info') else None
                    if isinstance(info, dict):
                        malware_name = info.get('name', '') or status
                    else:
                        malware_name = '签名库发现威胁'
                    if hasattr(r, 'internal_path') and r.internal_path:
                        malware_name = f"{malware_name} -> {r.internal_path}"
            elif status == 'suspicious':
                summary['suspicious_count'] += 1
                if not suspicious_name:
                    matches = r.heuristic_matches if hasattr(r, 'heuristic_matches') else None
                    if isinstance(matches, list) and matches:
                        suspicious_name = matches[0].get('name', '') if isinstance(matches[0], dict) else str(matches[0])
                    if not suspicious_name:
                        suspicious_name = '可疑文件'
                    if hasattr(r, 'internal_path') and r.internal_path:
                        suspicious_name = f"{suspicious_name} -> {r.internal_path}"
            else:
                summary['clean_count'] += 1

        if summary['malware_count'] > 0:
            summary['status'] = 'malware'
            summary['name'] = malware_name
        elif summary['suspicious_count'] > 0:
            summary['status'] = 'suspicious'
            summary['name'] = suspicious_name
        else:
            summary['status'] = 'clean'
            summary['name'] = 'clean'

        return summary

    def _heuristic_scan(self, file_path: str) -> List[Dict]:
        """
        启发式扫描（预编译正则缓存 + content.lower() 预处理）

        内建检测包括：双扩展名伪装、RTLO/Unicode 伪装字符、加壳节区特征、可疑 API 组合。

        性能关键优化：
        - content 规则（bytes 正则）原始 pattern 都带 (?i)，在 2MB 内容上每个 search ~17ms
        - 去掉 (?i) + 对 content 做一次性 .lower() 预处理 → 每个 search ~2ms，5.3x 加速
        - 预编译存在规则 dict 的 _cre 字段，避免每次 compile

        Args:
            file_path: 文件路径

        Returns:
            匹配的启发式规则列表
        """
        matches = []
        filename = os.path.basename(file_path)
        _, extension = os.path.splitext(file_path)
        ext1 = extension.lower()
        file_content_loaded = False
        file_content = b''
        file_content_lower = b''

        # ---------- 内建：文件名/路径结构化启发式 ----------
        try:
            name_no_ext, _ = os.path.splitext(filename.lower())
            if name_no_ext:
                _, ext2 = os.path.splitext(name_no_ext)
                if ext2 and ext1 in ('.exe', '.dll', '.scr', '.pif', '.com',
                                     '.bat', '.cmd', '.js', '.vbs', '.ps1'):
                    common_doc = {'.pdf', '.doc', '.docx', '.xls', '.xlsx',
                                  '.ppt', '.pptx', '.txt', '.rtf', '.jpg',
                                  '.png', '.bmp', '.gif', '.zip', '.rar'}
                    if ext2 in common_doc:
                        matches.append({'name': '双扩展名伪装', 'severity': 'high',
                                        'rule_type': 'builtin', 'detail': f'{filename}'})
        except Exception:
            pass

        try:
            filename_l = filename.lower()
            if '\u202e' in filename or '\u200f' in filename or '\u200b' in filename:
                matches.append({'name': 'RTLO/Unicode 伪装字符', 'severity': 'high',
                                'rule_type': 'builtin'})
            if any(k in filename_l for k in ('invoice', 'payment', 'bank', 'urgent', 'confirm')) \
                    and ext1 in ('.exe', '.scr', '.bat', '.js', '.vbs', '.ps1'):
                matches.append({'name': '社会工程学文件名模式', 'severity': 'low',
                                'rule_type': 'builtin'})
        except Exception:
            pass

        # ---------- 规则库匹配 ----------
        for rule in self.heuristic_rules:
            try:
                rule_type = rule['rule_type']
                pattern = rule['pattern']

                if rule_type == 'content':
                    # content 规则：bytes 正则，性能优化重点
                    # 1. 懒加载文件内容（最多 2MB）
                    # 2. 一次性 .lower() 预处理
                    # 3. 预编译好去掉 (?i) 的 bytes 正则
                    try:
                        if not file_content_loaded:
                            try:
                                sz = os.path.getsize(file_path)
                                if sz > 0 and sz < 32 * 1024 * 1024:
                                    with open_with_retry(file_path, 'rb') as f:
                                        file_content = f.read(min(sz, 2 * 1024 * 1024))
                                    # 关键优化：一次性 lower()，后续所有 content 规则共用
                                    if file_content:
                                        file_content_lower = file_content.lower()
                            except Exception:
                                file_content = b''
                            file_content_loaded = True

                        if not file_content_lower:
                            continue

                        # 懒编译：第一次遇到时去掉 (?i) 并预编译，存在 rule._cre 字段
                        cre = rule.get('_cre')
                        if cre is None:
                            p = pattern
                            if isinstance(p, bytes):
                                p_no_i = p.replace(b'(?i)', b'')
                            else:
                                p_no_i = p.replace('(?i)', '')
                            try:
                                cre = re.compile(p_no_i)
                                rule['_cre'] = cre
                            except re.error:
                                continue

                        if cre.search(file_content_lower):
                            matches.append(rule)
                    except Exception:
                        continue
                else:
                    # 字符串正则：使用预编译正则缓存，避免每次扫描重复编译
                    regex = self._get_compiled_regex(pattern)
                    if regex is None:
                        continue

                    if rule_type == 'filename':
                        if regex.search(filename):
                            matches.append(rule)
                    elif rule_type == 'extension':
                        if regex.search(extension):
                            matches.append(rule)
                    elif rule_type == 'filepath':
                        if regex.search(file_path):
                            matches.append(rule)
            except Exception as e:
                logger.warning(f"启发式规则匹配异常 {rule.get('name', '?')}: {e}")
                continue

        # ---------- 内建：字节级结构化启发式 ----------
        try:
            if not file_content_loaded:
                try:
                    sz = os.path.getsize(file_path)
                    if sz > 0 and sz < 32 * 1024 * 1024:
                        with open_with_retry(file_path, 'rb') as f:
                            file_content = f.read(min(sz, 2 * 1024 * 1024))
                except Exception:
                    file_content = b''
                file_content_loaded = True
        except Exception:
            pass

        if file_content:
            try:
                packer_sigs = [
                    (b'.UPX0', 'UPX 加壳节区', 'medium'),
                    (b'.UPX1', 'UPX 加壳节区', 'medium'),
                    (b'.packed', 'Packed 加壳节区', 'medium'),
                    (b'.themida', 'Themida/VMP 保护节区', 'high'),
                    (b'.vmp0', 'VMProtect 节区', 'high'),
                    (b'.enigma', 'Enigma 保护器', 'high'),
                    (b'.aspack', 'ASPack 加壳', 'medium'),
                    (b'.petite', 'Petite 加壳', 'low'),
                    (b'.pecompact', 'PECompact 加壳', 'medium'),
                    (b'.mpress', 'MPress 加壳', 'low'),
                ]
                for sig_bytes, sig_name, sev in packer_sigs:
                    if sig_bytes in file_content[:min(len(file_content), 256 * 1024)]:
                        matches.append({'name': sig_name, 'severity': sev, 'rule_type': 'builtin'})
                        break

                suspicious_api_combos = [
                    (b'CreateRemoteThread', b'WriteProcessMemory', '进程注入 API 组合', 'high'),
                    (b'OpenProcess', b'VirtualAllocEx', '远程内存分配/打开进程组合', 'medium'),
                    (b'URLDownloadToFile', b'WinExec', '下载+执行网络组合', 'high'),
                    (b'InternetOpen', b'HttpSendRequest', '可疑网络请求组合', 'medium'),
                    (b'GetAsyncKeyState', b'GetForegroundWindow', '键盘记录 API 组合', 'high'),
                ]
                for a_bytes, b_bytes, sig_name, sev in suspicious_api_combos:
                    if a_bytes in file_content and b_bytes in file_content:
                        matches.append({'name': sig_name, 'severity': sev, 'rule_type': 'builtin'})
            except Exception:
                pass

        return matches

    # 预编译正则缓存（避免每次扫描重复 re.compile）
    _REGEX_CACHE: dict = {}
    _REGEX_CACHE_LOCK = threading.Lock()

    @classmethod
    def _get_compiled_regex(cls, pattern: str):
        """获取预编译的正则对象（带缓存）"""
        try:
            with cls._REGEX_CACHE_LOCK:
                cached = cls._REGEX_CACHE.get(pattern)
                if cached is not None:
                    return cached
            # 编译新正则（可能抛 re.error）
            regex = re.compile(pattern)
            with cls._REGEX_CACHE_LOCK:
                cls._REGEX_CACHE[pattern] = regex
            return regex
        except re.error as e:
            logger.warning(f"正则表达式错误 {pattern}: {e}")
            with cls._REGEX_CACHE_LOCK:
                cls._REGEX_CACHE[pattern] = None  # 标记为无效，避免重复尝试
            return None
    
    @staticmethod
    def _read_file_content(file_path: str, max_size: int = 16384) -> Optional[bytes]:
        """读取文件内容用于熵计算（限制最大读取 16KB 以控制性能）"""
        try:
            with open_with_retry(file_path, 'rb') as f:
                return f.read(max_size)
        except Exception:
            return None
    
    @staticmethod
    def _calculate_shannon_entropy(data: bytes) -> float:
        """计算 Shannon 熵值 (0-8)

        熵值越高表明数据越随机/加密/加壳：
        - 0-3: 低熵（结构化数据，如文本）
        - 3-5: 中等熵（普通二进制）
        - 5-7: 较高熵（压缩数据）
        - 7-8: 高熵（加密/加壳/随机填充）

        性能优化：使用 bytes.count 替代逐字节 Python 循环
        """
        if not data:
            return 0.0
        if len(data) == 1:
            return 0.0
        length = len(data)
        entropy = 0.0
        # bytes.count 是 C 实现，比 Python 逐字节循环快 10-50 倍
        for i in range(256):
            count = data.count(i)
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy
    
    def scan_directory(self, root_path: str, 
                       callback: Callable[[ScanResult], None] = None,
                       skip_dirs: List[str] = None,
                       target_extensions: List[str] = None,
                       scan_all: bool = False) -> List[ScanResult]:
        """
        扫描目录（单进程模式）
        
        Args:
            root_path: 根目录路径
            callback: 扫描结果回调函数
            skip_dirs: 跳过的目录列表
            target_extensions: 目标文件扩展名列表
            scan_all: 是否扫描所有文件（包括隐藏文件和所有扩展名）
            
        Returns:
            扫描结果列表
        """
        walker = FileWalker(skip_dirs=skip_dirs, target_extensions=target_extensions, scan_all=scan_all)
        results = []
        
        for file_path in walker.walk(root_path):
            # 使用带归档扫描的方法
            file_results = self.scan_file_with_archives(file_path)
            for result in file_results:
                results.append(result)
                
                if callback:
                    callback(result)
        
        return results
    
    def scan_directory_parallel(self, root_path: str,
                                callback: Callable[[ScanResult], None] = None,
                                skip_dirs: List[str] = None,
                                target_extensions: List[str] = None,
                                scan_all: bool = False) -> List[ScanResult]:
        """
        扫描目录（多进程模式）
        
        使用进程池 initializer 模式，每个子进程只初始化一次数据库和引擎，
        避免每个文件重复创建实例。扫描逻辑与单进程模式完全一致，包含：
        哈希匹配、规则引擎、PE分析、归档扫描。
        
        Args:
            root_path: 根目录路径
            callback: 扫描结果回调函数
            skip_dirs: 跳过的目录列表
            target_extensions: 目标文件扩展名列表
            scan_all: 是否扫描所有文件（包括隐藏文件和所有扩展名）
            
        Returns:
            扫描结果列表
        """
        walker = FileWalker(skip_dirs=skip_dirs, target_extensions=target_extensions, scan_all=scan_all)
        file_list = list(walker.walk(root_path))
        
        if not file_list:
            return []
        
        # 使用进程池，通过 initializer 在每个子进程中只初始化一次
        user_excluded = getattr(self, '_user_excluded_dirs', set())
        # 动态降载：高负载时按负载因子收缩进程池（避免吃掉整机 CPU）
        _pool_workers = load_governor.effective_workers(self.max_workers, min_floor=1)
        # ML 参与度计数跨进程汇总：父进程建共享字典注入各 worker，扫描结束回读
        _ml_mgr = None
        _ml_shared = None
        try:
            _ml_mgr = multiprocessing.Manager()
            _ml_shared = _ml_mgr.dict(_ML_SCAN_STATS)
        except Exception as e:
            logger.warning(f'ML 统计共享字典创建失败（计数仅在各 worker 本地）: {e}')
            _ml_shared = None
        try:
            with multiprocessing.Pool(
                processes=_pool_workers,
                initializer=_init_scan_worker,
                initargs=(
                    self.signature_db.db_path,
                    self.scan_archives,
                    self.TRUSTED_DIRECTORIES,
                    self.EXECUTABLE_EXTENSIONS,
                    self.MIN_FILE_SIZE_FOR_RULE_SCAN,
                    self.strict_mode,
                    self._self_excluded_dirs if hasattr(self, '_self_excluded_dirs') else set(),
                    user_excluded,
                    self._OEM_PACKAGE_DIR_KEYS,
                    self.virus_identifier_enabled,
                    _ml_shared,
                )
            ) as pool:
                # chunksize 调优：n_workers*2 平衡 IPC 开销与负载均衡
                # 文件大小差异大时，较小 chunksize 避免大文件扎堆导致尾部等待
                n_files = len(file_list)
                n_workers = max(self.max_workers, 1)
                chunksize = max(1, n_files // (n_workers * 2))
                # 使用 imap_unordered 替代 map：结果完成即返回，回调可即时触发
                results = []
                for file_results in pool.imap_unordered(_scan_file_worker_full, file_list, chunksize=chunksize):
                    if isinstance(file_results, list):
                        results.extend(file_results)
                        if callback:
                            for r in file_results:
                                callback(r)
                    else:
                        results.append(file_results)
                        if callback:
                            callback(file_results)
        finally:
            # 回读并保存 ML 参与度汇总（供 get_scan_stats / 日志自证）
            if _ml_shared is not None:
                try:
                    self._ml_scan_stats = {
                        k: (int(v) if isinstance(v, (int, float)) else v)
                        for k, v in dict(_ml_shared).items()
                    }
                except Exception:
                    pass
            if _ml_mgr is not None:
                try:
                    _ml_mgr.shutdown()
                except Exception:
                    pass
        _ml_stats_log(reason='scan-end',
                      stats=getattr(self, '_ml_scan_stats', None) or _ml_stats_snapshot())

        return results
    
    def get_scan_stats(self, results: List[ScanResult]) -> Dict:
        """
        获取扫描统计信息
        
        Args:
            results: 扫描结果列表
            
        Returns:
            统计信息字典
        """
        stats = {
            'total_files': len(results),
            'clean': 0,
            'malware': 0,
            'suspicious': 0,
            'error': 0,
            'skipped': 0,  # 跳过的大文件/不可读文件
        }

        for result in results:
            # 防御性：未知状态归入 error，避免 KeyError
            status = result.status if result.status in stats else 'error'
            stats[status] += 1

        # ML 参与度计数：多进程回读自 scan_directory_parallel，单进程用模块计数
        ml_stats = getattr(self, '_ml_scan_stats', None) or _ml_stats_snapshot()
        stats['ml_available'] = bool(ml_stats.get('ml_available'))
        stats['ml_called'] = int(ml_stats.get('ml_called', 0) or 0)
        stats['ml_malware'] = int(ml_stats.get('ml_malware', 0) or 0)
        stats['ml_susp'] = int(ml_stats.get('ml_susp', 0) or 0)
        stats['ml_none'] = int(ml_stats.get('ml_none', 0) or 0)
        stats['ml_failed'] = int(ml_stats.get('ml_failed', 0) or 0)
        stats['ml_main_unavailable_reason'] = (
            ml_stats.get('ml_main_unavailable_reason') or '')
        # 汇总输出（INFO，走既有日志通道；绝不写协议通道）
        _ml_stats_log(reason='stats',
                      stats=getattr(self, '_ml_scan_stats', None) or _ml_stats_snapshot())

        return stats
    
    def close(self):
        """关闭数据库连接"""
        self.signature_db.close()

if __name__ == '__main__':
    # 测试扫描引擎
    engine = ScanEngine()
    
    # 扫描当前目录
    print("开始扫描测试...")
    
    def print_result(result: ScanResult):
        if result.status == 'malware':
            print(f"[恶意软件] {result.file_path} - {result.malware_info.get('name')}")
        elif result.status == 'suspicious':
            print(f"[可疑] {result.file_path}")
        elif result.status == 'error':
            print(f"[错误] {result.file_path}")
    
    results = engine.scan_directory('.', callback=print_result)
    stats = engine.get_scan_stats(results)
    
    print(f"\n扫描统计:")
    print(f"  总文件数: {stats['total_files']}")
    print(f"  安全: {stats['clean']}")
    print(f"  恶意软件: {stats['malware']}")
    print(f"  可疑: {stats['suspicious']}")
    print(f"  错误: {stats['error']}")
    
    engine.close()
