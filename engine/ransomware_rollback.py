# -*- coding: utf-8 -*-
"""
勒索软件文件回滚（阶段一：用户态增量快照 + 回滚）

设计要点（详见 .trae/documents/ransomware-rollback-stage1.md）：
  - 内容寻址仓库：objects/<sha256[:2]>/<sha256> + manifest.json + records.json
  - 增量快照：按 (size, mtime_ns) 判据跳过未变文件，仅在变化时计算 SHA256 并落对象
  - 原子写回：tmp + os.replace（与 mbr_protector 的惯用法一致）
  - 回滚编排：重入守卫 + 逐文件 try/except + 失败 30s 节流/放弃
  - 容量配额：max_repo_bytes / max_file_bytes，超限记 too_large，LRU 清理后台执行
  - 保护范围：桌面/文档/下载/图片/视频/音乐（Windows 已知文件夹，兼容 OneDrive 重定向）

约束：
  - 所有耗时操作在 daemon 线程；start()/stop() 不阻塞调用方
  - 本模块不引用任何扫描/沙箱设施，不向协议通道写任何日志或数据
  - 模块级 _REPO_ROOT 便于测试 monkeypatch
"""
import os
import sys
import json
import time
import shutil
import hashlib
import threading
import uuid
from typing import Callable, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger('ransomware_rollback')

# ---- 常量 ----
_ROLLBACK_INTERVAL = 300.0        # 周期快照间隔（秒）
_RETRY_INTERVAL = 30.0            # 同一文件回滚失败后的节流/放弃间隔（对齐 mbr_protector）
_PREWARN_COOLDOWN = 3.0           # 低水位预警快照最小间隔（秒），避免快照风暴
_OBJECT_PREFIX_LEN = 2            # 对象目录前缀长度（sha256[:2]）
_MANIFEST_VERSION = 2
_MAX_RECORDS = 200                # 回滚记录上限（超出丢弃最旧）
_DEFAULT_MAX_REPO_BYTES = 2 * 1024 ** 3     # 仓库容量上限 2GB
_DEFAULT_MAX_FILE_BYTES = 64 * 1024 ** 2    # 单文件上限 64MB（默认不变）
_MAX_SHADOW_FAILURES = 500        # 影子失败/miss 记录上限
_MAX_GENERATIONS = 3              # 保留的世代数量（新→旧滚动列表，最多 3 个）


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, '') or default)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, '') or default)
    except Exception:
        return default


# 快照性能优化（可环境变量覆盖）
_HASH_QUEUE_MAX = 256                                     # 并行哈希有界队列上限（节流）
_SNAPSHOT_WORKERS = max(1, _env_int('PSLS_ROLLBACK_SNAPSHOT_WORKERS', 4))
_STARTUP_SNAPSHOT_DELAY = max(0.0, _env_float('PSLS_ROLLBACK_STARTUP_DELAY', 15.0))
# 入仓插桩：置 1（PSLS_ROLLBACK_INGEST_DEBUG=1）时逐次记录"哪一步/读了多少字节"失败
_INGEST_DEBUG = bool(_env_int('PSLS_ROLLBACK_INGEST_DEBUG', 0))

# 需求 #4：单文件上限可配置（默认 64MB，保持既有行为不变），便于排查
# "为什么这些文件没入仓"（too_large）。PSLS_ROLLBACK_MAX_FILE_MB=0 表示不限制。
_MAX_FILE_BYTES = (lambda _mb: 0 if _mb <= 0 else _mb * 1024 * 1024)(
    _env_int('PSLS_ROLLBACK_MAX_FILE_MB', 64))

# 需求 #6：短时间内相同配置的重复快照去重窗口（秒）。
# 理由：重启后配置回灌触发 [reload]，15s 后启动快照又跑一遍，实测多一次全量
# walk/哈希（1930 文件）。10s 足以覆盖该场景，又不会把用户"手动/周期"的真实
# 快照需求吞掉（manual 永不跳过；周期默认 300s 远大于该窗口）。
_RELOAD_SNAPSHOT_MIN_INTERVAL = max(0.0, _env_float(
    'PSLS_ROLLBACK_SNAPSHOT_MIN_INTERVAL', 10.0))

# 残留隔离的硬边界（可环境变量覆盖）：防止全盘遍历把回滚卡在 96%（实测事故）
_QUARANTINE_MAX_FILES = max(50, _env_int('PSLS_ROLLBACK_QUARANTINE_MAX', 2000))
_QUARANTINE_MAX_SECONDS = max(1.0, _env_float('PSLS_ROLLBACK_QUARANTINE_MAX_SEC', 20.0))
_QUARANTINE_MAX_DEPTH = max(1, _env_int('PSLS_ROLLBACK_QUARANTINE_MAX_DEPTH', 6))

# 回滚前"清场"（终止所有非系统、非 PSLS 进程）时**绝不终止**的 Windows 关键进程名。
# 另按 pid 保护：0/4、本进程、PSLS 祖先/子孙链、以及名字含 psls/mlworker 的进程。
#
# 调整决定 2（保护集收窄）：保护集**仅**包含「Windows 系统关键进程」+
# 「PSLS 自身及其子进程（含 worker/MLWorker）」。
#   - 不再保护第三方沙箱基础设施（Sbie* 服务、Start.exe 等）
#     → 清场会一并终止它们，副作用：**沙箱服务被终止，需重启沙箱后才能再次使用**；
#   - 不再保护第三方白名单进程（VMware / QQ / 微信 / WPS / explorer 等）
#     → 与系统进程、PSLS 自身/子进程之外的一切进程一并终止。
_PROTECTED_PROCESS_NAMES = {
    'system', 'system idle process', 'registry', 'memory compression',
    'secure system', 'smss', 'csrss', 'wininit', 'winlogon', 'services',
    'lsass', 'svchost', 'dwm', 'fontdrvhost', 'audiodg',
    # Chromium / WebView2 渲染子进程（PSLS 前端即 QtWebEngineProcess 宿主）：
    # 误杀即自冻（界面白屏/"未响应"），名字级双保险 —— 即便进程树收集异常也绝不终止
    'qtwebengineprocess', 'msedgewebview2',
}

# 仓库用量缓存 TTL（秒）：get_stats 等高频查询路径**绝不**全量遍历 objects/
# （大仓库可达数万对象，逐次 os.path.getsize 会拖慢 worker 串行命令循环、
# 降级模式下更会直接卡住 GUI 线程）；过期由后台线程刷新，查询返回旧值。
_REPO_USAGE_TTL = 30.0

# ---------------------------------------------------------------------------
# 正常第三方软件"绝不误伤"名单（进程名片段 + 路径片段）
# 背景：误报（如 VMware/QQ 的正常行为被判恶意）绝不能导致终止/移动/覆盖其文件，
# 否则就是"安全软件越界破坏第三方程序"。此名单为**只读保护**，不降低真实防护。
# 可用环境变量 PSLS_ROLLBACK_EXTRA_PROTECT 追加（逗号分隔的小写片段）。
# ---------------------------------------------------------------------------
_PROTECTED_APP_NAME_FRAGMENTS = (
    # 虚拟化 / 开发工具
    'vmware', 'vmnat', 'vmnet', 'vmware-vmx', 'vmtoolsd', 'vmware-authd',
    'vmware-tray', 'vmware-usbarbitrator', 'virtualbox', 'vboxsvc', 'vboxheadless',
    'docker', 'wsl', 'qemu', 'hyper-v',
    # 常见 IM / 办公
    'qq', 'tim', 'qqprotect', 'qqmusic', 'wechat', 'wxwork', 'telegram',
    'dingtalk', 'feishu', 'lark', 'wps', 'kingsoft', 'dingtalk',
)
_PROTECTED_APP_PATH_FRAGMENTS = (
    '\\vmware\\', '\\vmware workstation\\', '\\vmnet', '\\vmnat',
    '\\virtualbox\\', '\\tencent files\\', '\\qq\\', '\\tim\\',
    '\\qqprotect\\', '\\wechat files\\', '\\wechat\\', '\\wps office\\',
    '\\kingsoft\\',
)


def _extra_protected_fragments() -> tuple:
    try:
        raw = os.environ.get('PSLS_ROLLBACK_EXTRA_PROTECT', '') or ''
        items = tuple(x.strip().lower() for x in raw.split(',') if x.strip())
        return items
    except Exception:
        return ()


def _is_protected_app_name(name: str) -> bool:
    """进程名是否属于"正常第三方软件"（绝不终止）。"""
    n = (name or '').lower().strip()
    if not n:
        return False
    frags = _PROTECTED_APP_NAME_FRAGMENTS + _extra_protected_fragments()
    return any(f and f in n for f in frags)


def _psls_self_roots() -> List[str]:
    """PSLS **自身目录**（安装根 + 回滚仓库根）——用于把"自己的文件"排除出
    快照扫描 / 残留扫描 / 入仓候选。

    实测事故：VM 把 PSLS 装在 `C:\\Users\\nightingale\\Desktop\\PSLS`，而桌面是
    默认受保护目录 → 快照把**自己的安装目录**（图标/许可协议/沙箱组件等）
    也纳入范围，产生大量 skipped 记录并灌爆前端（主窗口"未响应"）。
    注意：只排除"安装根这一子树"，**不能把整个桌面排除**。
    """
    roots: List[str] = []
    try:
        if getattr(sys, 'frozen', False):
            base = os.path.dirname(os.path.abspath(sys.executable))
        else:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        roots.append(base)
    except Exception:
        pass
    try:
        roots.append(os.path.abspath(_REPO_ROOT))
    except Exception:
        pass
    out, seen = [], set()
    for r in roots:
        try:
            n = os.path.normcase(os.path.abspath(r)).rstrip('\\/')
        except Exception:
            continue
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _is_psls_self_path(path: str) -> bool:
    """路径是否落在 PSLS 自身目录子树内（前缀规范化比较，避免 `...\\PSLS2` 误判）。"""
    if not path:
        return False
    try:
        n = os.path.normcase(os.path.abspath(str(path))).rstrip('\\/')
    except Exception:
        return False
    if not n:
        return False
    for r in _psls_self_roots():
        if n == r or n.startswith(r + os.sep):
            return True
    return False


def _is_protected_app_path(path: str) -> bool:
    """路径是否属于"正常第三方软件"数据目录（绝不移动/覆盖/隔离）。"""
    if not path:
        return False
    try:
        p = ('\\' + os.path.normcase(os.path.abspath(path)).replace('/', '\\') + '\\').lower()
    except Exception:
        p = ('\\' + str(path).lower().replace('/', '\\') + '\\')
    frags = _PROTECTED_APP_PATH_FRAGMENTS + _extra_protected_fragments()
    return any(f and f.replace('/', '\\') in p for f in frags)

# 勒索加密残留后缀（与 file_protection.RANSONWARE_EXTENSIONS 同源；
# 此处独立一份，避免引擎间相互 import 造成耦合/循环）
_ENCRYPTED_EXTS = {
    '.locked', '.encrypted', '.crypt', '.cryptolocker',
    '.locky', '.zepto', '.cerber', '.lockbit',
    '.wcry', '.wncry', '.wncry2',
    '.xtbl', '.yay', '.zzzzz', '.lol',
    '.paym', '.exx', '.ecc', '.ezz',
    '.mooe', '.m00e', '.ox', '.fuck',
    '.davinci', '.da_vinci', '.vault', '.vif',
}

# 改名残留件的补充后缀（勒索改名常见形态；_ENCRYPTED_EXTS 之外再补 .enc/.lock/.crypto）。
# 用于回滚时把"被改名后的残留件"送去隔离（沿用既有隔离通道，不自行删除）。
_RENAME_RESIDUAL_EXTS = _ENCRYPTED_EXTS | {'.enc', '.lock', '.crypto'}

# ---- 仓库根（打包 %APPDATA%\PSLS\rollback；开发 <项目根>\rollback）----
# 环境变量 PSLS_ROLLBACK_REPO 可显式覆盖（测试隔离 / 运维自定义路径），
# 优先级最高；未设置时按打包/开发模式解析。
_env_repo_root = os.environ.get('PSLS_ROLLBACK_REPO')
if _env_repo_root:
    _REPO_ROOT = os.path.abspath(_env_repo_root)
elif getattr(sys, 'frozen', False):
    if sys.platform == 'win32':
        _appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
    else:
        _appdata = os.path.expanduser('~/.config')
    _REPO_ROOT = os.path.join(_appdata, 'PSLS', 'rollback')
else:
    _REPO_ROOT = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'rollback')

# Windows 已知文件夹 GUID（用于解析桌面/文档/下载/图片/视频/音乐，
# 兼容 OneDrive 重定向；解析失败时降级到 os.path.expanduser 常见目录）
_KNOWN_FOLDER_GUIDS = {
    'Desktop':   'B4BFCC3A-DB2C-424C-B029-7FE99A87C641',
    'Documents': 'FDD39AD0-238F-46AF-ADB4-6C85480369C7',
    'Downloads': '374DE290-123F-4565-9164-39C4925E467B',
    'Pictures':  '33E28130-4E1E-4676-835A-98395C3BC3BB',
    'Videos':    '18989B1D-99B5-455B-841C-AB7C74E4DDFC',
    'Music':     '4BD8D571-6D19-48D3-BE97-422220080E43',
}


# ---- 模块级路径辅助（均在调用时读取 _REPO_ROOT，便于测试 monkeypatch）----

def _repo_root() -> str:
    return _REPO_ROOT


def _manifest_path() -> str:
    return os.path.join(_REPO_ROOT, 'manifest.json')


def _records_path() -> str:
    return os.path.join(_REPO_ROOT, 'records.json')


def _objects_dir() -> str:
    return os.path.join(_REPO_ROOT, 'objects')


def _shadow_base_dir() -> str:
    """影子原像仓库根（驱动写入 <shadow_root>/<generation>/<path_hash>）。"""
    return os.path.join(_REPO_ROOT, 'shadow')


def _shadow_gen_dir(generation: int) -> str:
    """当前世代的影子原像目录。"""
    return os.path.join(_shadow_base_dir(), str(int(generation)))


# ---- PSLS 自身产出路径豁免（供实时防护/扫描/文件保护共用）----
# 回滚仓库与其影子原像子树内是 PSLS 自己写入的"原始文件副本"，读到/写入它们
# 绝不应当触发检测、隔离或终止。判据统一用"规范化绝对路径 + 尾分隔符"做前缀
# 比较（os.path.normcase）：既能跨大小写，也不会把 ...\rollback2 之类误判为仓库内。

def repo_root_norm() -> str:
    """规范化回滚仓库根（带尾分隔符）；失败返回空串。"""
    try:
        p = os.path.normcase(os.path.abspath(_REPO_ROOT))
    except Exception:
        return ''
    return (p.rstrip('\\/') + os.sep) if p else ''


def shadow_root_norm() -> str:
    """规范化影子原像根（带尾分隔符）；失败返回空串。"""
    root = repo_root_norm()
    return (root + 'shadow' + os.sep) if root else ''


def is_psls_repo_path(path) -> bool:
    """判断路径是否落在回滚仓库 / 影子原像子树内（PSLS 自身产出 → 应豁免）。"""
    if not path:
        return False
    try:
        p = os.path.normcase(os.path.abspath(str(path)))
    except Exception:
        return False
    for root in (repo_root_norm(), shadow_root_norm()):
        if not root:
            continue
        if p == root.rstrip('\\/') or p.startswith(root):
            return True
    return False


def _nt_to_win32_path(nt_path: str) -> str:
    """NT 设备路径 → Win32 盘符路径（驱动事件的 orig_path 为 NT 名）。

    复用桥接层的映射逻辑；桥接不可用时原样返回（回滚写回会失败但记录仍在）。
    """
    try:
        from driver.bridge.psls_driver_bridge import _nt_path_to_win32
        out = _nt_path_to_win32(nt_path)
        return out or nt_path
    except Exception:
        return nt_path


def _sha256_file(path: str) -> Optional[str]:
    """分块计算文件 SHA256（失败返回 None）。"""
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _copy_with_retry(src_path: str, tmp: str, attempts: int = 3) -> None:
    """把 src 内容复制到 tmp；对并发瞬时失败（EBADF/EACCES/占用）退避重试。

    实测：自我保护正在备份同一文件（如 MLWorker.exe）时，回滚入仓的读取可能
    瞬时失败（`[Errno 9] Bad file descriptor`）。每次失败清掉半截 tmp 再重试，
    避免把不完整内容当成对象存下。
    """
    last = None
    for i in range(max(1, attempts)):
        try:
            with open(src_path, 'rb') as fin, open(tmp, 'wb') as fout:
                shutil.copyfileobj(fin, fout, 65536)
                fout.flush()
                try:
                    os.fsync(fout.fileno())
                except Exception:
                    pass
            return
        except OSError as e:
            last = e
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
            if i >= attempts - 1:
                break
            logger.debug(f'写入对象重试 {i + 1}/{attempts - 1} {src_path}: {e}')
            time.sleep(0.2 * (i + 1))
    if last is not None:
        raise last


def _atomic_write_text(path: str, text: str) -> bool:
    """原子写文本（tmp + os.replace，照抄 mbr_protector 的惯用法）。"""
    tmp = path + '.psls_restore.tmp'
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, path)
        return True
    except Exception as e:
        logger.warning(f'原子写文件失败 {path}: {e}')
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return False


def _iter_object_files():
    """遍历仓库内所有对象文件（objects/<prefix>/<sha256>）。"""
    objects_dir = _objects_dir()
    if not os.path.isdir(objects_dir):
        return
    try:
        prefixes = os.listdir(objects_dir)
    except OSError:
        return
    for sub in prefixes:
        subdir = os.path.join(objects_dir, sub)
        if not os.path.isdir(subdir):
            continue
        try:
            names = os.listdir(subdir)
        except OSError:
            continue
        for fn in names:
            p = os.path.join(subdir, fn)
            if os.path.isfile(p):
                yield p


def _known_folder_path(guid_str: str) -> Optional[str]:
    """通过 SHGetKnownFolderPath 解析 Windows 已知文件夹（兼容 OneDrive 重定向）。"""
    try:
        import ctypes
        import uuid as _uuid
        from ctypes import wintypes

        class _GUID(ctypes.Structure):
            _fields_ = [
                ('Data1', wintypes.DWORD),
                ('Data2', wintypes.WORD),
                ('Data3', wintypes.WORD),
                ('Data4', ctypes.c_ubyte * 8),
            ]

        u = _uuid.UUID(guid_str)
        g = _GUID()
        g.Data1 = u.time_low
        g.Data2 = u.time_mid
        g.Data3 = u.time_hi_version
        for i in range(8):
            g.Data4[i] = u.bytes[8 + i]
        ptr = ctypes.c_wchar_p()
        hres = ctypes.windll.shell32.SHGetKnownFolderPath(
            ctypes.byref(g), 0, None, ctypes.byref(ptr))
        if hres != 0 or not ptr.value:
            return None
        try:
            return ptr.value
        finally:
            try:
                ctypes.windll.ole32.CoTaskMemFree(ptr)
            except Exception:
                pass
    except Exception:
        return None


class RansomwareRollback:
    """勒索软件文件回滚引擎（纯用户态增量快照 + 触发回滚）。"""

    def __init__(self, quarantine_manager=None, process_protection=None,
                 on_report: Callable[[dict], None] = None,
                 protected_dirs: Optional[List[str]] = None,
                 max_repo_bytes: int = _DEFAULT_MAX_REPO_BYTES,
                 max_file_bytes: int = None,
                 snapshot_interval: float = _ROLLBACK_INTERVAL,
                 on_progress: Callable[[dict], None] = None,
                 kill_all_before_restore: bool = True):
        self._quarantine_manager = quarantine_manager
        self._process_protection = process_protection
        self._on_report = on_report
        self._on_progress = on_progress
        # 回滚前"清场"：终止所有非系统、非 PSLS 进程（可关闭，默认开启）
        self._kill_all_before_restore = bool(kill_all_before_restore)
        self._max_repo_bytes = int(max_repo_bytes)
        # 需求 #4：默认值可被环境变量 PSLS_ROLLBACK_MAX_FILE_MB 覆盖（默认 64MB 不变）
        self._max_file_bytes = int(max_file_bytes) if max_file_bytes is not None \
            else int(_MAX_FILE_BYTES)
        # 需求 #6：快照去重所需的"上次成功快照时间/配置指纹"
        self._last_snapshot_success_ts = 0.0
        self._last_snapshot_sig = ''
        self._snapshot_interval = float(snapshot_interval)
        # 快照并行哈希线程数（默认常量；测试可改实例属性覆盖）
        self._snapshot_workers = int(_SNAPSHOT_WORKERS)

        self._enabled = True
        self._running = False
        self._stop_event = threading.Event()
        self._worker: Optional[threading.Thread] = None

        self._state_lock = threading.Lock()      # manifest / records / stats 保护
        self._snapshot_lock = threading.Lock()   # 防止并发快照
        self._rollback_lock = threading.Lock()   # 回滚重入守卫
        self._rollback_active = False
        # 按 sha 的细粒度对象写锁：同一内容并发入仓时串行化，避免共享 tmp 竞争
        # （不能用 _state_lock 包住整个拷贝，否则并行退化为串行且易死锁）。
        self._object_locks_guard = threading.Lock()
        self._object_locks: Dict[str, threading.Lock] = {}

        self._manifest: Dict = {
            'version': _MANIFEST_VERSION, 'updated_at': 0, 'dirs': [], 'entries': {},
            'generations': [],
        }
        # 世代模型：_generations 为"新→旧"滚动列表（最多 _MAX_GENERATIONS 个）。
        # 每个世代 = {'generation_id','created_at','reason','entries','dirs','exts'}。
        # _manifest['entries'] 始终作为"最新世代"entries 的别名，保持既有调用兼容。
        self._generations: List[dict] = []
        self._records: List[dict] = []
        self._restore_giveup = set()             # 永久放弃恢复的文件键
        self._last_restore_fail: Dict[str, float] = {}

        self._last_prewarn = 0.0
        # 快照进行中被拒的低水位预警：置 pending，当前快照结束后立即补做
        # （受 _state_lock 保护；被拒不应等同"已消费冷却"）
        self._pending_prewarn = False
        self._stats = {
            'snapshots': 0, 'objects_stored': 0, 'too_large': 0,
            'rollbacks': 0, 'restored': 0, 'failed': 0, 'skipped': 0,
            'quarantined': 0, 'purged_objects': 0, 'started_at': 0,
            'shadow_backups': 0, 'shadow_no_preimage': 0,
            # 扫描期间源文件不可读（并发干扰）——与"真失败 failed"分开统计
            'unreadable': 0,
        }

        # ---- 阶段二: 写前影子备份 ----
        self._driver_bridge = None           # PSLSDriverBridge（由 UI 注入）
        self._generation = 0                 # 当前世代号（每次 start 自增）
        # status!=0 的影子事件（miss/fail/too_large）→ 该文件"无写前原像"
        self._shadow_failures: Dict[str, dict] = {}

        # ---- 仓库用量缓存（get_stats 高频查询不再全量遍历 objects/）----
        self._repo_usage_cache = 0           # 最近一次全量统计结果（字节）
        self._repo_usage_ts = 0.0            # 统计完成时间戳
        self._repo_usage_refreshing = False  # 后台刷新去重

        if protected_dirs:
            self._protected_dirs = self._normalize_dirs(protected_dirs)
        else:
            self._protected_dirs = self._resolve_default_dirs()
        # 快照文件类型白名单（扩展名，如 ['.docx', '.xlsx']）；空 = 全部类型。
        # 由 UI 设置页配置、桥接回灌；仅在 replace/增量快照的文件遍历中生效。
        self._snapshot_exts: List[str] = []

        self._load_state()

    # ---- 属性 ----

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    @property
    def generation_id(self) -> int:
        """当前写前影子备份世代号。"""
        return self._generation

    # ---- 世代模型（最多保留 _MAX_GENERATIONS 个，新→旧）----

    def _sync_latest_alias(self):
        """把 _manifest['entries'] 指向最新世代的 entries（保持既有调用兼容）。"""
        if self._generations:
            self._manifest['entries'] = self._generations[0]['entries']
        else:
            self._manifest['entries'] = {}
        self._manifest['generations'] = self._generations

    def _latest_gen(self) -> Optional[dict]:
        return self._generations[0] if self._generations else None

    def _ensure_latest_gen(self, reason: str = 'auto') -> dict:
        """返回最新世代；不存在时创建一个（用于无显式快照时的影子原像登记）。"""
        gen = self._latest_gen()
        if gen is None:
            gen = self._new_generation(reason)
        return gen

    def _find_generation(self, generation_id) -> Optional[dict]:
        try:
            gid = int(generation_id)
        except (TypeError, ValueError):
            return None
        for g in self._generations:
            if int(g.get('generation_id', -1)) == gid:
                return g
        return None

    def _new_generation(self, reason: str) -> dict:
        """新建一个世代（新→旧列表头部），并同步最新世代别名。

        generation_id 保证全局唯一且单调：以当前计数器为基准，若与已有世代撞号
        则递增（跨进程重启 / 无 start() 直接快照时都能避免重复）。
        """
        with self._state_lock:
            existing = set()
            for g in self._generations:
                try:
                    existing.add(int(g.get('generation_id', -1)))
                except Exception:
                    continue
            gid = int(self._generation)
            while gid in existing:
                gid += 1
            self._generation = gid
        gen = {
            'generation_id': gid,
            'created_at': time.time(),
            'reason': reason,
            'entries': {},
            'dirs': list(self._protected_dirs),
            'exts': list(self._snapshot_exts),
        }
        self._generations.insert(0, gen)
        self._sync_latest_alias()
        return gen

    def get_generations(self) -> List[dict]:
        """枚举保留的世代（新→旧），含 id / 时间 / 原因 / 文件数 / 范围。"""
        out: List[dict] = []
        with self._state_lock:
            for g in self._generations:
                created = g.get('created_at') or 0
                try:
                    created_str = time.strftime(
                        '%Y-%m-%d %H:%M:%S', time.localtime(created)) if created else ''
                except Exception:
                    created_str = ''
                out.append({
                    'generation_id': int(g.get('generation_id', 0)),
                    'created_at': created,
                    'created_at_str': created_str,
                    'reason': g.get('reason', ''),
                    'file_count': len(g.get('entries', {})),
                    'dirs': list(g.get('dirs') or []),
                    'exts': list(g.get('exts') or []),
                    # 可读性：最近一次快照的"尝试/纳入/不可读"，避免只看 file_count=0 误导
                    'attempted': int(g.get('attempted', 0) or 0),
                    'ingested': int(g.get('ingested', 0) or 0),
                    'unreadable': int(g.get('unreadable', 0) or 0),
                    'failed': int(g.get('failed', 0) or 0),
                })
        return out

    def _retain_generations(self, keep: int = _MAX_GENERATIONS) -> int:
        """保留策略：仅保留最新 keep 个世代，淘汰更旧的世代。

        关键正确性：对象库按 SHA256 内容寻址，多个世代会共享同一对象。
        淘汰世代时**只删除不再被任何保留世代引用的对象**（含 driver_shadow 写前
        原像），绝不误删仍被保留世代引用的对象，否则保留世代的回滚会损坏。
        返回被淘汰的世代数量。
        """
        with self._state_lock:
            evicted: List[dict] = []
            while len(self._generations) > int(keep):
                evicted.append(self._generations.pop())
            self._sync_latest_alias()
            if not evicted:
                return 0
            # 仍被保留世代引用的对象集合（世代 + 其 driver_shadow 写前原像）
            referenced = set()
            for g in self._generations:
                for m in g.get('entries', {}).values():
                    o = m.get('object') or m.get('hash')
                    if o:
                        referenced.add(o)
        # 删除被淘汰世代的独有对象（锁外执行 IO）
        removed = 0
        for g in evicted:
            for m in g.get('entries', {}).values():
                o = m.get('object') or m.get('hash')
                if o and o not in referenced:
                    if self._delete_object(o, force=True):
                        removed += 1
        if removed:
            logger.info(
                f'世代保留策略：淘汰 {len(evicted)} 个旧世代，清理 {removed} 个独有对象')
        else:
            logger.info(f'世代保留策略：淘汰 {len(evicted)} 个旧世代')
        self._save_manifest()
        return len(evicted)

    # ---- 保护目录 ----

    def _resolve_default_dirs(self) -> List[str]:
        """解析默认保护目录（桌面/文档/下载/图片/视频/音乐）。"""
        dirs: List[str] = []
        if sys.platform == 'win32':
            for name in ('Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos', 'Music'):
                guid = _KNOWN_FOLDER_GUIDS.get(name)
                p = _known_folder_path(guid) if guid else None
                if p and os.path.isdir(p):
                    dirs.append(p)
        if not dirs:
            # 非 Windows 或已知文件夹解析失败：降级到常见目录（便于单测/跨平台）
            home = os.path.expanduser('~')
            for name in ('Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos', 'Music'):
                p = os.path.join(home, name)
                if os.path.isdir(p):
                    dirs.append(p)
        return self._normalize_dirs(dirs)

    @staticmethod
    def _normalize_dirs(dirs) -> List[str]:
        out: List[str] = []
        seen = set()
        for d in (dirs or []):
            try:
                p = os.path.abspath(str(d))
            except Exception:
                continue
            if not p or not os.path.isdir(p):
                continue
            norm = os.path.normcase(p)
            if norm in seen:
                continue
            seen.add(norm)
            out.append(p)
        return out

    @staticmethod
    def _dedup_dirs(dirs) -> List[str]:
        """规范化去重 + 剔除被其它目录包含的子目录（重叠保护目录）。

        例：['C:\\...\\Desktop', 'C:\\...\\Desktop\\PSLS'] → 仅保留 Desktop。
        规范化用 normcase + 尾分隔符前缀比较，避免 `...\\Desktop2` 误判为子目录。
        """
        normed = []
        seen = set()
        for d in (dirs or []):
            try:
                p = os.path.abspath(str(d))
            except Exception:
                continue
            if not p:
                continue
            n = os.path.normcase(p).rstrip('\\/')
            if not n or n in seen:
                continue
            seen.add(n)
            normed.append((n, p))
        out = []
        for n, p in normed:
            contained = False
            for n2, _p2 in normed:
                if n2 == n:
                    continue
                if n.startswith(n2 + os.sep):
                    contained = True
                    break
            if not contained:
                out.append(p)
        return out

    def get_protected_dirs(self) -> List[str]:
        with self._state_lock:
            return list(self._protected_dirs)

    def get_default_protected_dirs(self) -> List[str]:
        """引擎默认保护目录（桌面/文档/下载/图片/视频/音乐）——**唯一事实来源**。

        供 UI"保护目录"在未配置时默认展示，避免前端硬编码与引擎不一致。
        """
        try:
            return list(self._resolve_default_dirs())
        except Exception:
            return []

    def set_protected_dirs(self, dirs) -> List[str]:
        """设置受保护目录列表（预留自定义目录入口）。"""
        out = self._normalize_dirs(dirs)
        with self._state_lock:
            self._protected_dirs = out
            self._manifest['dirs'] = list(out)
        self._save_manifest()
        logger.info(f'勒索回滚保护目录已更新: {len(out)} 个')
        return list(out)

    # ---- 快照文件类型（扩展名白名单）----

    @staticmethod
    def _normalize_exts(exts) -> List[str]:
        """规范化扩展名列表：小写、补前导点、去空白与重复；非法项丢弃。"""
        out: List[str] = []
        seen = set()
        for e in (exts or []):
            try:
                s = str(e).strip().lower()
            except Exception:
                continue
            if not s:
                continue
            if s == '*':
                # "*" 视为"全部类型" → 返回空列表
                return []
            if not s.startswith('.'):
                s = '.' + s
            # 仅保留字母数字扩展名，避免注入异常字符
            if len(s) < 2 or not all(c.isalnum() for c in s[1:]):
                continue
            if s in seen:
                continue
            seen.add(s)
            out.append(s)
        return out

    def get_snapshot_exts(self) -> List[str]:
        """获取快照文件类型白名单（空 = 全部类型）。"""
        with self._state_lock:
            return list(self._snapshot_exts)

    def set_snapshot_exts(self, exts) -> List[str]:
        """设置快照文件类型白名单（空 = 全部类型）。

        仅影响快照的文件遍历范围，不改变回滚/影子语义。
        """
        out = self._normalize_exts(exts)
        with self._state_lock:
            self._snapshot_exts = out
            self._manifest['exts'] = list(out)
        self._save_manifest()
        logger.info(f'勒索回滚快照文件类型已更新: {out or "全部类型"}')
        return list(out)

    # ---- 单文件快照上限（调整决定 3：设置页滑动条下发）----

    def get_max_file_bytes(self) -> int:
        """单文件快照上限（字节）；0 = 不限制。"""
        with self._state_lock:
            return int(self._max_file_bytes)

    def set_max_file_bytes(self, max_file_bytes) -> int:
        """设置单文件快照上限（字节）；0 = 不限制。

        仅影响快照入仓的大小阈值（超出记 too_large 不入仓），不改变
        回滚/世代/残留隔离语义。非法输入沿用当前值。
        """
        try:
            v = int(max_file_bytes)
        except Exception:
            return self.get_max_file_bytes()
        if v < 0:
            v = 0
        with self._state_lock:
            self._max_file_bytes = v
        if v:
            logger.info(f'勒索回滚单文件上限已更新: {v // (1024 * 1024)} MB')
        else:
            logger.info('勒索回滚单文件上限已更新: 不限制')
        return v

    def set_max_file_mb(self, mb) -> int:
        """按 MB 设置单文件快照上限（0 = 不限制）；返回生效字节数。"""
        try:
            m = int(mb)
        except Exception:
            return self.get_max_file_bytes()
        return self.set_max_file_bytes(0 if m <= 0 else m * 1024 * 1024)

    # ---- 启停（非阻塞）----

    def start(self) -> bool:
        if self._running:
            return True
        self._stop_event.clear()
        self._running = True
        # 换世代：世代号自增 → 驱动侧去重集合清空，重新建立"写前原像"世代。
        # 需避开已持久化世代的 id（跨进程重启时 counter 归零，不能与旧世代撞号）。
        with self._state_lock:
            max_existing = 0
            for g in self._generations:
                try:
                    max_existing = max(max_existing, int(g.get('generation_id', 0)))
                except Exception:
                    continue
            self._generation = max(self._generation, max_existing) + 1
            self._stats['started_at'] = time.time()
        # 启动/换世代时下发写前影子配置（驱动不可用时静默降级）
        try:
            self._push_shadow_config()
        except Exception as e:
            logger.debug(f'启动下发影子配置失败: {e}')
        self._worker = threading.Thread(
            target=self._worker_loop, daemon=True, name='RansomwareRollback')
        self._worker.start()
        logger.info('勒索文件回滚已启动')
        return True

    def stop(self) -> bool:
        if not self._running:
            return True
        self._stop_event.set()
        self._running = False
        w = self._worker
        if w is not None and w.is_alive():
            try:
                w.join(timeout=3)
            except Exception:
                pass
        self._worker = None
        # 关闭驱动侧写前影子备份
        bridge = self._driver_bridge
        if bridge is not None and getattr(bridge, 'is_available', False):
            try:
                bridge.set_shadow_config(False, self._generation, '')
            except Exception:
                pass
        logger.info('勒索文件回滚已停止')
        return True

    def set_enabled(self, enabled: bool):
        """切换引擎开关（线程常驻，仅切标记，不阻塞调用方）。"""
        self._enabled = bool(enabled)
        logger.info(f'勒索文件回滚 {"启用" if self._enabled else "禁用"}')
        # 同步驱动侧写前影子备份开关
        try:
            self._push_shadow_config()
        except Exception as e:
            logger.debug(f'切换影子配置失败: {e}')

    def _worker_loop(self):
        # 启动快照延后：避免与开机/界面加载抢 IO（只延后时机，仍保证"每次启动
        # 新建一个世代"）：等待 _STARTUP_SNAPSHOT_DELAY 秒后再执行。
        # 延后期间若用户手动触发快照，按既有优先级正常执行（不受此等待影响）。
        if _STARTUP_SNAPSHOT_DELAY > 0:
            logger.info(
                f'勒索回滚启动快照延后 {_STARTUP_SNAPSHOT_DELAY:.0f}s 执行 '
                f'（快照线程数 {self._snapshot_workers}）')
            if self._stop_event.wait(_STARTUP_SNAPSHOT_DELAY):
                return
        # 原子快照：单世代语义 → 先删除上一个快照世代，再对新状态整体入仓
        try:
            if self._enabled:
                self.snapshot_now('startup', replace=True)
        except Exception as e:
            logger.error(f'启动快照失败: {e}')
        # 启动快照进行中被挤掉的低水位预警，快照一结束立即补做
        try:
            self._consume_pending_prewarn()
        except Exception as e:
            logger.error(f'补做低水位预警失败: {e}')
        while not self._stop_event.wait(self._snapshot_interval):
            if self._stop_event.is_set():
                break
            if not self._enabled:
                continue
            try:
                # 周期快照刷新当前（最新）世代，不新建世代（避免世代爆炸）
                self.snapshot_now('periodic', replace=True)
                self._enforce_quota()
            except Exception as e:
                logger.error(f'周期快照失败: {e}')
            # 周期快照期间被挤掉的低水位预警，同样立即补做
            try:
                self._consume_pending_prewarn()
            except Exception as e:
                logger.error(f'补做低水位预警失败: {e}')

    # ---- 快照 ----

    def snapshot_now(self, reason: str = 'manual', replace: bool = False) -> dict:
        """立即执行一次快照（同步；调用方若在主线程请自行放后台线程）。

        世代语义（覆盖原"单世代"设计）：
          - reason 含 'startup'（PSLS 每次启动）→ **新建一个世代**，随后执行
            保留策略 retain=_MAX_GENERATIONS，淘汰第 4 个及更旧的世代；
          - 其它 reason（periodic/prewarn/manual/reload）→ **刷新当前（最新）世代**，
            不新建世代（否则周期快照会导致世代爆炸）；
          - replace=True 时对目标世代做"整体刷新"（清除该世代的非写前原像条目后
            重新入仓）；replace=False 为增量语义（保留未变条目）。
        """
        if not self._snapshot_lock.acquire(blocking=False):
            return {'ok': False, 'reason': 'snapshot_in_progress'}
        try:
            # 需求 #6：短时间内的重复全量快照去重——**仅针对 reload**。
            # 场景：重启后配置回灌触发 [reload]，15s 后启动快照又跑一遍全量。
            # 说明：
            #   - reload 是"我们自己下发配置"引起的那一次，重复度最高 → 可跳过；
            #   - startup 必须**每次新建世代**（既有语义），故不在此跳过；其内容
            #     由"世代继承 + (size,mtime) 短路"保证不重复哈希（实测 hashed=0）；
            #   - manual / periodic 一律不跳过（用户显式或固定周期语义）。
            skip_walk = False
            if str(reason).lower() == 'reload':
                sig = self._snapshot_config_sig()
                age = time.time() - float(
                    self._last_snapshot_success_ts or 0)
                if (age < _RELOAD_SNAPSHOT_MIN_INTERVAL
                        and sig and sig == self._last_snapshot_sig):
                    logger.debug(
                        f'快照[{reason}]：{age:.1f}s 内有相同配置的成功快照 → '
                        f'跳过本次全量（未变更配置）')
                    return {'ok': True, 'skipped': 'recent_identical',
                            'hashed': 0, 'reason': reason}
            return self._do_snapshot(reason, replace=replace, skip_walk=skip_walk)
        finally:
            self._snapshot_lock.release()

    def _snapshot_config_sig(self) -> str:
        """快照相关配置指纹（受保护目录 + 快照类型 + 大小上限），用于去重判断。"""
        try:
            dirs = sorted(os.path.normcase(os.path.abspath(d))
                          for d in (self.get_protected_dirs() or []))
            exts = sorted(self.get_snapshot_exts() or [])
            return '|'.join(dirs) + '#' + ','.join(exts) + \
                '#' + str(int(self._max_file_bytes))
        except Exception:
            return ''

    @staticmethod
    def _is_startup_reason(reason: str) -> bool:
        return 'startup' in str(reason or '').lower()

    def _do_snapshot(self, reason: str, replace: bool = False,
                    skip_walk: bool = False) -> dict:
        new_gen = self._is_startup_reason(reason)
        show_progress = bool(new_gen or str(reason) == 'manual')
        # 需求 #6：跳过一次重复全量（内容复用上一世代的继承结果）。
        # 世代语义不变：startup 仍**新建世代**，仅内容不重新 walk/哈希。
        if skip_walk:
            if new_gen:
                gen = self._new_generation(reason)
                with self._state_lock:
                    prev = self._generations[1] if len(self._generations) > 1 else None
                    if prev:
                        gen['entries'].update(
                            {k: dict(m) for k, m in prev.get('entries', {}).items()})
                    self._sync_latest_alias()
                self._retain_generations()
                self._save_manifest()
                self._report({'action': 'snapshot_done', 'reason': reason,
                              'skipped': 'recent_identical',
                              'hashed': 0, 'inherited': len(gen.get('entries', {})),
                              'total': len(gen.get('entries', {})),
                              'generations': len(self._generations)})
                logger.info(
                    f'快照[{reason}] 去重完成：新建世代 '
                    f'{gen.get("generation_id")}，内容继承 '
                    f'{len(gen.get("entries", {}))} 条（未重新哈希）')
                return {'ok': True, 'reason': reason, 'skipped': 'recent_identical',
                        'hashed': 0, 'inherited': len(gen.get('entries', {})),
                        'total': len(gen.get('entries', {}))}
            return {'ok': True, 'reason': reason, 'skipped': 'recent_identical',
                    'hashed': 0}
        # 目标世代：启动快照新建世代；其它快照刷新最新世代（无则创建）
        if new_gen:
            gen = self._new_generation(reason)
            # 世代继承（最高优先优化）：把上一世代（现 index=1）的 entries 拷入新
            # 世代，使 `(size, mtime_ns)` 短路命中未变文件 —— 不重算哈希、不重拷对象。
            with self._state_lock:
                prev = self._generations[1] if len(self._generations) > 1 else None
                if prev:
                    inherited_entries = {k: dict(m)
                                         for k, m in prev.get('entries', {}).items()}
                    gen['entries'].update(inherited_entries)
                self._sync_latest_alias()
        else:
            gen = self._ensure_latest_gen(reason)
            # 整体刷新（periodic/manual replace=True）：清除非写前原像条目后全量重走。
            # 注意：prewarn 已改为增量（replace=False），不再走此分支。
            if replace:
                self._purge_generation_entries(gen)
        dirs = self.get_protected_dirs()
        # 显式排除 PSLS 自身目录（安装根及其全部子目录：沙箱组件/_internal/db_backup 等）：
        # 只排这一子树，不动"桌面"本身。
        dirs = [d for d in dirs if not _is_psls_self_path(d)]
        # 重叠受保护目录去重：剔除被其它目录包含的子目录（如 Desktop 与 Desktop\PSLS），
        # 避免同一文件被遍历两次（浪费 + 放大并发竞争）。
        dirs = self._dedup_dirs(dirs)
        dirs_count = len(dirs)
        if dirs_count == 0:
            # 可观测性：范围为 0 时明确告警，避免"快照 0 文件"被误读为正常
            logger.warning('勒索回滚快照范围为 0 个目录，本次不会入仓任何文件')
        ext_list = self.get_snapshot_exts()
        ext_set = set(ext_list)                   # 空集 = 全部类型
        now = time.time()
        repo_norm = os.path.normcase(os.path.abspath(_REPO_ROOT))
        with self._state_lock:
            known = dict(gen.get('entries', {}))

        updates: Dict[str, dict] = {}
        added = unchanged = too_large = failed = 0
        hashed = inherited = scanned = 0
        skipped_self = 0                          # 排除的 PSLS 自身文件数（可见性）
        unreadable = 0                            # 扫描期间源不可读（并发干扰，非真失败）
        attempted = 0                             # 本次尝试入仓的文件数（待哈希）
        need_hash: List[tuple] = []               # (fp, st, key, old_hash)
        seen_keys: set = set()                     # 本次 walk 实际见到的文件键

        self._progress('扫描目录…', 2,
                       f'扫描中（{dirs_count} 个目录）', show=show_progress)
        # 快照工作期间切到后台 IO 优先级（Windows；不可用则安全跳过）
        with self._background_io():
            for d in dirs:
                if not os.path.isdir(d):
                    continue
                for root, subdirs, files in os.walk(d):
                    root_norm = os.path.normcase(os.path.abspath(root))
                    # 排除仓库自身与 **PSLS 安装目录**整棵子树（含其沙箱/内部资源子目录）
                    if root_norm == repo_norm or root_norm.startswith(repo_norm + os.sep) \
                            or _is_psls_self_path(root):
                        subdirs[:] = []
                        continue
                    for fn in files:
                        # 文件级兜底：受保护目录本身若就是 PSLS 目录，直接跳过其文件
                        if _is_psls_self_path(os.path.join(root, fn)):
                            skipped_self += 1
                            continue
                        # 文件类型白名单过滤：非空且扩展名不匹配 → 完全跳过
                        if ext_set and os.path.splitext(fn)[1].lower() not in ext_set:
                            continue
                        fp = os.path.join(root, fn)
                        try:
                            st = os.stat(fp)
                        except OSError:
                            continue
                        if not os.path.isfile(fp):
                            continue
                        key = os.path.abspath(fp).lower()
                        # 文件级去重：重叠目录/软链导致重复遍历时只处理一次
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        scanned += 1
                        if scanned % 500 == 0:
                            self._progress('扫描目录…', min(55, 5 + scanned // 300),
                                           f'扫描中（已扫描 {scanned} 个文件）',
                                           show=show_progress)
                        if self._max_file_bytes and st.st_size > self._max_file_bytes:
                            too_large += 1
                            continue
                        old = known.get(key)
                        # 阶段二: 写前原像优先级最高 — 不被快照覆盖，仅刷新 last_seen
                        if old and old.get('source') == 'driver_shadow':
                            n = dict(old)
                            n['last_seen'] = now
                            updates[key] = n
                            if replace or new_gen:
                                added += 1
                            else:
                                unchanged += 1
                            continue
                        # 增量短路（含继承）：(size, mtime_ns) 未变 → 不重算哈希
                        if (old and old.get('size') == st.st_size
                                and old.get('mtime_ns') == st.st_mtime_ns):
                            n = dict(old)
                            n['last_seen'] = now
                            updates[key] = n
                            unchanged += 1
                            inherited += 1
                            continue
                        need_hash.append((fp, st, key, old.get('hash') if old else None))

            # 并行哈希 + 入仓（有界队列 + 固定线程池；workers=1 为串行对照）
            if need_hash:
                self._progress('入仓中', 60,
                               f'入仓中（{len(need_hash)} 个待处理文件）',
                               show=show_progress)
            else:
                # 需求 #3：无新增（内容已继承/未变）→ **不进入"入仓中"**，
                # 直接推进到 90%，避免进度窗停在 60% 让人以为卡死。
                self._progress('入仓中', 90, '无新增文件（内容已继承/未变）',
                               show=show_progress)
            workers = self._snapshot_workers
            attempted = len(need_hash)
            results = self._hash_and_store_many(need_hash, workers)
            hashed = len([r for r in results if r[3] is not None])
            total_to_merge = max(1, len(results))
            for i, (key, fp, st, sha, stage, _n) in enumerate(results):
                if i and i % 200 == 0:
                    self._progress('入仓中', 60 + int(35 * i / total_to_merge),
                                   f'入仓中（{i}/{total_to_merge}）',
                                   show=show_progress)
                # 并发不可读（扫描期间被占用/删除）单列统计；不计入真失败
                if stage == 'unreadable':
                    unreadable += 1
                    continue
                if sha is None:
                    failed += 1
                    continue
                old = known.get(key)
                if old and old.get('hash') == sha:
                    n = dict(old)
                    n['size'] = st.st_size
                    n['mtime_ns'] = st.st_mtime_ns
                    n['last_seen'] = now
                    updates[key] = n
                    unchanged += 1
                    continue
                if stage != 'ok':
                    failed += 1
                    continue
                updates[key] = {
                    'path': os.path.abspath(fp),
                    'hash': sha, 'size': st.st_size, 'mtime_ns': st.st_mtime_ns,
                    'object': sha, 'ext': os.path.splitext(fp)[1].lower(),
                    'snapshot_at': now, 'last_seen': now,
                }
                added += 1

        # 继承剪除：新世代中"继承而来但本次 walk 未再出现"的条目（文件已删除/移走）
        # 必须剔除（写前原像除外，其优先级最高），使新世代=当前状态；剔除后其对象
        # 若不再被任何保留世代引用则回收（_delete_object 会自行判定）。
        if new_gen:
            with self._state_lock:
                stale = [k for k, m in gen['entries'].items()
                         if k not in seen_keys
                         and m.get('source') != 'driver_shadow']
                for k in stale:
                    gen['entries'].pop(k, None)
                self._sync_latest_alias()
            for k in stale:
                meta = known.get(k) or {}
                sha = meta.get('hash') or meta.get('object')
                if sha:
                    self._delete_object(sha)

        with self._state_lock:
            gen['entries'].update(updates)
            gen['dirs'] = list(dirs)
            gen['exts'] = list(ext_list)
            # 世代级计数快照（供 get_generations 展示"尝试/纳入/不可读"）
            gen['attempted'] = int(attempted)
            gen['ingested'] = int(added + unchanged)
            gen['unreadable'] = int(unreadable)
            gen['failed'] = int(failed)
            self._manifest['dirs'] = dirs
            self._manifest['entries'] = gen['entries']      # 最新世代别名
            self._manifest['updated_at'] = now
            self._stats['snapshots'] += 1
            self._stats['too_large'] += too_large
        # 启动快照：新建世代后执行保留策略（最多 3 个），淘汰更旧世代
        if new_gen:
            self._retain_generations()
        self._save_manifest()
        # 需求 #6：记录本次成功快照的时间与配置指纹，供后续去重判断
        try:
            self._last_snapshot_success_ts = time.time()
            self._last_snapshot_sig = self._snapshot_config_sig()
        except Exception:
            pass
        # 需求 #4：输出当前单文件上限，便于排查"这些文件为什么没入仓(too_large)"
        limit_desc = (f'{self._max_file_bytes // (1024 * 1024)} MB'
                      if self._max_file_bytes else '不限制')
        logger.info(
            f'[勒索回滚快照] 世代 {gen.get("generation_id", 0)}: '
            f'尝试 {attempted} / 纳入 {max(0, len(updates) - inherited)} / '
            f'继承 {inherited} / 扫描期间不可读 {unreadable} / too_large {too_large} / '
            f'failed {failed} / 排除自身目录 {skipped_self} / '
            f'总纳入 {len(gen.get("entries", {}))}')
        logger.info(f'快照单文件上限 = {limit_desc}'
                    f'（PSLS_ROLLBACK_MAX_FILE_MB 可调，0=不限制）')
        if too_large:
            logger.info(f'本次因超过单文件上限跳过 {too_large} 个文件'
                        f'（上限 {limit_desc}）')

        # 快照完成上报：worker 直接转发为 report 帧 → 主进程据此刷新回滚中心的
        # 世代列表。没有这一步时，启动/周期快照完成后 UI 仍显示旧的空列表
        # （必须先重进页面才更新）。
        try:
            if self._on_report:
                self._on_report({
                    'action': 'snapshot_done', 'ok': True, 'reason': reason,
                    'generation_id': int(gen.get('generation_id', 0)),
                    'added': added, 'inherited': inherited,
                    'total': len(updates), 'failed': failed, 'too_large': too_large,
                    'hashed': hashed, 'generations': len(self._generations),
                    'attempted': attempted, 'ingested': added + unchanged,
                    'unreadable': unreadable,
                })
        except Exception as e:
            logger.debug(f'快照完成上报失败: {e}')

        total = len(updates)
        ingested = added + unchanged          # 本次真正纳入世代的文件数（含未变继承）
        # 可读性修复：不再只显示"纳入 0 个文件"而误导用户。当纳入为 0 但确实尝试过
        # 文件（全部因并发不可读被跳过）时，明确区分"尝试/纳入/不可读"。
        if total == 0 and attempted > 0:
            logger.warning(
                f'勒索回滚快照纳入 0 个文件：尝试 {attempted}，其中扫描期间不可读 '
                f'{unreadable} 个（并发占用/删除），失败 {failed} 个 —— 非引擎故障，'
                f'建议稍后重试或检查实时保护是否持续占用这些文件')
        # 可观测性：类型白名单把所有文件过滤掉（total 为 0 且白名单非空）时说明原因
        if total == 0 and ext_set and attempted == 0:
            logger.warning(
                f'勒索回滚快照已纳入 0 个文件：文件类型白名单 {sorted(ext_set)} '
                f'未匹配到任何文件（范围 {dirs_count} 个目录）')
        result = {
            'ok': True, 'reason': reason, 'added': added, 'unchanged': unchanged,
            'too_large': too_large, 'failed': failed, 'total': total,
            'hashed': hashed, 'inherited': inherited, 'scanned': scanned,
            'unreadable': unreadable, 'attempted': attempted,
            'ingested': ingested,
            'dirs_count': dirs_count,
            'generation_id': int(gen.get('generation_id', 0)),
        }
        logger.info(
            f'勒索回滚快照[{reason}] 世代{result["generation_id"]}: '
            f'尝试 {attempted} / 纳入 {ingested} / hashed {hashed} / '
            f'inherited {inherited} / added {added} / unchanged {unchanged} / '
            f'扫描期间不可读 {unreadable} / too_large {too_large} / failed {failed} / '
            f'total {total} / 扫描 {scanned} / 范围 {dirs_count} 个目录 / '
            f'线程 {workers}')
        self._progress('完成', 100,
                       f'快照完成（新增 {added}，未变 {inherited}）',
                       show=show_progress)
        return result

    @staticmethod
    def _set_bg_io(begin: bool) -> bool:
        """把当前线程切到/退出后台 IO 模式（Windows）。返回是否成功。

        64 位下必须显式声明 argtypes/restype，否则句柄被截断、调用失败
        （与 engine/process_protection.py 同一坑）。
        """
        if sys.platform != 'win32':
            return False
        try:
            import ctypes
            import ctypes.wintypes as wt
            k = ctypes.windll.kernel32
            try:
                k.GetCurrentThread.argtypes = []
                k.GetCurrentThread.restype = wt.HANDLE
                k.SetThreadPriority.argtypes = [wt.HANDLE, ctypes.c_int]
                k.SetThreadPriority.restype = wt.BOOL
            except Exception:
                pass
            mode = 0x00010000 if begin else 0x00020000
            return bool(k.SetThreadPriority(k.GetCurrentThread(), mode))
        except Exception as e:
            logger.debug(f'后台 IO 优先级切换失败（忽略）: {e}')
            return False

    def _background_io(self):
        """快照期间切到后台 IO 优先级（Windows SetThreadPriority BACKGROUND）。"""
        import contextlib

        @contextlib.contextmanager
        def _cm():
            began = self._set_bg_io(True)
            try:
                yield
            finally:
                if began:
                    self._set_bg_io(False)
        return _cm()

    def _hash_and_store_many(self, items, workers: int):
        """并行（有界队列 + 固定线程池）哈希 + 入仓；workers<=1 时串行对照。

        返回 [(key, fp, st, sha_or_None, stored_bool)]。哈希/拷贝在锁外执行，
        仅入仓计数 `_store_object` 内部短暂持锁；单文件异常只记 failed。
        """
        def _one(fp, st, key, old_hash):
            # 单次打开源文件完成哈希+入仓（见 _ingest_file），返回 (sha, stage, n)
            try:
                sha, stage, n = self._ingest_file(fp, old_hash)
            except Exception as e:
                if _INGEST_DEBUG:
                    logger.debug(f'[入仓插桩] _ingest_file 异常 {fp}: {e}')
                return (key, fp, st, None, 'unreadable', 0)
            return (key, fp, st, sha, stage, n)

        if not items:
            return []
        if workers <= 1 or len(items) <= 1:
            return [_one(*it) for it in items]

        import queue as _queue
        q = _queue.Queue(maxsize=_HASH_QUEUE_MAX)
        results = []
        rlock = threading.Lock()

        def _worker():
            # 线程池 worker 也进入后台 IO 优先级（后台模式是"每线程"生效）
            began_bg = self._set_bg_io(True)
            try:
                while True:
                    it = q.get()
                    if it is None:
                        q.task_done()
                        return
                    try:
                        r = _one(*it)
                    except Exception:
                        r = (it[2], it[0], it[1], None, 'unreadable', 0)
                    with rlock:
                        results.append(r)
                    q.task_done()
            finally:
                if began_bg:
                    self._set_bg_io(False)

        threads = [threading.Thread(target=_worker, daemon=True,
                                    name=f'SnapHash{i}') for i in range(workers)]
        for t in threads:
            t.start()
        try:
            # 有界队列：put 会阻塞 → 生产者自然节流，避免一次性塞满 13951 任务
            for it in items:
                q.put(it)
            for _ in threads:
                q.put(None)
            q.join()
        finally:
            for t in threads:
                try:
                    t.join(timeout=5)
                except Exception:
                    pass
        return results

    def _object_lock(self, sha: str) -> threading.Lock:
        """获取某 sha 的对象写锁（首次访问时创建）。"""
        with self._object_locks_guard:
            lk = self._object_locks.get(sha)
            if lk is None:
                lk = threading.Lock()
                self._object_locks[sha] = lk
            return lk

    @staticmethod
    def _safe_remove(path: str):
        """删除自己的临时文件（存在才删；失败静默）。绝不删别人的 tmp/对象。"""
        try:
            if path and os.path.lexists(path):
                os.remove(path)
        except Exception:
            pass

    def _store_object(self, src_path: str, sha: str) -> bool:
        """把文件内容按内容寻址写入仓库（已存在则去重）。

        并发安全：tmp 名带 pid+线程号唯一化；写前在**按 sha 的细粒度锁**内二次
        检查目标是否已存在；`os.replace` 失败且目标已存在时视为成功，WinError
        5/32 再重试一次；最终失败只清理**自己的** tmp。
        已存在返回 True；仅真正新建时 `objects_stored` +1；失败返回 False 并 WARNING。
        """
        obj_dir = os.path.join(_objects_dir(), sha[:_OBJECT_PREFIX_LEN])
        obj_path = os.path.join(obj_dir, sha)
        if os.path.isfile(obj_path):          # 无锁快速路径
            return True
        lock = self._object_lock(sha)
        with lock:
            # 锁内二次检查：其它线程可能已写入同一对象
            if os.path.isfile(obj_path):
                return True
            try:
                os.makedirs(obj_dir, exist_ok=True)
            except Exception:
                pass
            tmp = f'{obj_path}.{os.getpid()}.{threading.get_ident()}.tmp'
            try:
                _copy_with_retry(src_path, tmp)
                try:
                    os.replace(tmp, obj_path)
                except OSError as e:
                    # 目标已存在（他线程已成功）→ 视为成功
                    if os.path.isfile(obj_path):
                        self._safe_remove(tmp)
                        return True
                    winerr = getattr(e, 'winerror', None)
                    if winerr in (5, 32):     # 拒绝访问 / 占用：重试一次
                        try:
                            os.replace(tmp, obj_path)
                        except OSError:
                            if os.path.isfile(obj_path):
                                self._safe_remove(tmp)
                                return True
                            raise
                    else:
                        raise
                with self._state_lock:
                    self._stats['objects_stored'] += 1
                return True
            except Exception as e:
                logger.warning(f'写入对象失败 {src_path}: {e}')
                self._safe_remove(tmp)        # 只删自己的 tmp
                return False

    def _ingest_file(self, src_path: str, old_hash: Optional[str] = None,
                     attempts: int = 3):
        """**单次打开源文件**：边读边算 SHA256 并写入临时对象，再按内容寻址入仓。

        为什么单次打开：原实现先 `_sha256_file()` 再 `_copy_with_retry()`，对同一
        源文件**开两次句柄**，任一时刻被外部（实时监控的独占锁/删除/改名/防病毒）
        干扰就会在读取中途抛 `[Errno 9] Bad file descriptor`。现在一次打开、一次
        遍历同时完成哈希与拷贝，消除第二个打开窗口。

        返回 `(sha_or_None, stage, read_bytes)`：
          - `stage='ok'`        已入仓（或已存在去重）
          - `stage='unchanged'` 内容与 old_hash 相同，无需入仓
          - `stage='unreadable'` **扫描期间源文件不可读/被占用**（并发干扰，非真故障）
          - `stage='write_failed'` 仓库侧写入失败（真故障）
        """
        ingest_dir = os.path.join(_objects_dir(), '.ingest')
        tmp = os.path.join(ingest_dir, f'{os.getpid()}.{threading.get_ident()}.tmp')
        sha = None
        read_bytes = 0
        last_err = None
        for i in range(max(1, attempts)):
            h = hashlib.sha256()
            read_bytes = 0
            try:
                os.makedirs(ingest_dir, exist_ok=True)
                with open(src_path, 'rb') as fin, open(tmp, 'wb') as fout:
                    while True:
                        chunk = fin.read(65536)
                        if not chunk:
                            break
                        read_bytes += len(chunk)
                        h.update(chunk)
                        fout.write(chunk)
                    fout.flush()
                    try:
                        os.fsync(fout.fileno())
                    except Exception:
                        pass
                sha = h.hexdigest()
                break
            except OSError as e:
                last_err = e
                self._safe_remove(tmp)
                if _INGEST_DEBUG:
                    logger.debug(
                        f'[入仓插桩] 读源失败 stage=read src={src_path} '
                        f'bytes={read_bytes} errno={getattr(e, "errno", None)} '
                        f'winerror={getattr(e, "winerror", None)} try={i + 1}')
                if i < attempts - 1:
                    time.sleep(0.2 * (i + 1))
        if sha is None:
            # 并发不可读：单独统计，不并入"真失败"，避免误导为 ingest 故障
            with self._state_lock:
                self._stats['unreadable'] = int(self._stats.get('unreadable', 0)) + 1
                _n = int(self._stats.get('unreadable', 0))
            if _n <= 5 or _n % 50 == 0:
                logger.warning(
                    f'扫描期间文件不可读（已跳过，累计 {_n} 个）: {src_path} '
                    f'bytes={read_bytes} errno={getattr(last_err, "errno", None)} '
                    f'winerror={getattr(last_err, "winerror", None)}')
            return None, 'unreadable', read_bytes

        # 内容未变（与旧哈希相同）→ 无需入仓
        if old_hash and old_hash == sha:
            self._safe_remove(tmp)
            return sha, 'unchanged', read_bytes

        obj_dir = os.path.join(_objects_dir(), sha[:_OBJECT_PREFIX_LEN])
        obj_path = os.path.join(obj_dir, sha)
        if os.path.isfile(obj_path):           # 去重
            self._safe_remove(tmp)
            return sha, 'ok', read_bytes
        lock = self._object_lock(sha)
        with lock:
            if os.path.isfile(obj_path):
                self._safe_remove(tmp)
                return sha, 'ok', read_bytes
            try:
                os.makedirs(obj_dir, exist_ok=True)
            except Exception:
                pass
            try:
                os.replace(tmp, obj_path)
            except OSError as e:
                if os.path.isfile(obj_path):
                    self._safe_remove(tmp)
                    return sha, 'ok', read_bytes
                if getattr(e, 'winerror', None) in (5, 32):
                    try:
                        os.replace(tmp, obj_path)
                    except OSError as e2:
                        if os.path.isfile(obj_path):
                            self._safe_remove(tmp)
                            return sha, 'ok', read_bytes
                        logger.warning(f'写入对象失败 {src_path}: {e2}')
                        self._safe_remove(tmp)
                        return sha, 'write_failed', read_bytes
                else:
                    logger.warning(f'写入对象失败 {src_path}: {e}')
                    self._safe_remove(tmp)
                    return sha, 'write_failed', read_bytes
            with self._state_lock:
                self._stats['objects_stored'] += 1
        return sha, 'ok', read_bytes

    def _object_path(self, sha: str) -> str:
        return os.path.join(_objects_dir(), sha[:_OBJECT_PREFIX_LEN], sha)

    # ---- 阶段二: 写前影子备份 ----

    def set_driver_bridge(self, bridge) -> bool:
        """注入驱动桥接并（若引擎在运行）下发当前影子配置。返回是否下发成功。"""
        self._driver_bridge = bridge
        try:
            return self._push_shadow_config()
        except Exception as e:
            logger.debug(f'注入驱动桥接后下发影子配置失败: {e}')
            return False

    def _push_shadow_config(self) -> bool:
        """下发写前影子备份配置到驱动（enable/generation/shadow_root[/dirs]）。

        未运行或禁用时下发 enable=0，确保驱动侧不备份。
        """
        bridge = self._driver_bridge
        if bridge is None or not getattr(bridge, 'is_available', False):
            return False
        if not self._running or not self._enabled:
            try:
                bridge.set_shadow_config(False, self._generation, '')
            except Exception:
                return False
            return True

        base = _shadow_base_dir()
        gen_dir = _shadow_gen_dir(self._generation)
        try:
            os.makedirs(gen_dir, exist_ok=True)
        except Exception as e:
            logger.warning(f'创建影子目录失败 {gen_dir}: {e}')
        dirs = self.get_protected_dirs()
        try:
            ok = bridge.set_shadow_config(
                True, self._generation, base, dirs=dirs)
        except Exception as e:
            logger.warning(f'下发影子配置失败: {e}')
            return False
        if ok:
            logger.info(
                f'写前影子备份已下发 (世代 {self._generation}, '
                f'触发目录 {len(dirs)} 个)')
        return bool(ok)

    def _move_into_objects(self, src: str, sha: str) -> Optional[str]:
        """把影子文件移动进内容寻址对象库（同卷用 os.replace，避免重复拷贝大文件）。

        与 `_store_object` 共用同一 sha 的对象写锁，避免与快照并行入仓竞争同一
        对象路径（否则会出现"目标正被占用/找不到文件"类竞争）。
        """
        obj_dir = os.path.join(_objects_dir(), sha[:_OBJECT_PREFIX_LEN])
        obj_path = os.path.join(obj_dir, sha)
        if os.path.isfile(obj_path):
            try:
                os.remove(src)
            except Exception:
                pass
            return obj_path
        with self._object_lock(sha):
            if os.path.isfile(obj_path):
                # 内容已存在（其他文件/线程同内容）— 直接丢弃影子文件
                try:
                    os.remove(src)
                except Exception:
                    pass
                return obj_path
            try:
                os.makedirs(obj_dir, exist_ok=True)
                try:
                    os.replace(src, obj_path)
                except OSError:
                    # 跨卷无法 rename → 回退为移动（复制 + 删除）
                    shutil.move(src, obj_path)
                with self._state_lock:
                    self._stats['objects_stored'] += 1
                return obj_path
            except Exception as e:
                logger.warning(f'影子原像入仓失败 {src}: {e}')
                return None

    def ingest_shadow_backup(self, orig_path: str, shadow_path: str,
                             orig_size: int = 0, pid: int = 0) -> bool:
        """接收驱动侧"写前影子备份成功"事件：入仓并向 manifest 登记写前原像。

        校验影子文件存在且大小匹配 → 计算 SHA256 → 移动进 objects/<前2位>/<sha256>
        → 登记为该路径当前世代的"写前原像"（source='driver_shadow'，优先级高于快照）。
        在后台 daemon 线程中调用（驱动事件循环），本方法为普通同步实现。
        """
        if not shadow_path or not os.path.isfile(shadow_path):
            logger.warning(f'影子原像缺失，跳过入仓: {shadow_path}')
            return False
        try:
            real_size = os.path.getsize(shadow_path)
        except OSError:
            return False
        # 大小校验：驱动只记录原始大小，二者不符视为原像不可信
        if orig_size and int(orig_size) != int(real_size):
            logger.warning(
                f'影子原像大小不匹配 (期望 {orig_size} 实际 {real_size}): {orig_path}')
            return False
        sha = _sha256_file(shadow_path)
        if not sha:
            logger.warning(f'影子原像哈希失败: {shadow_path}')
            return False
        obj_path = self._move_into_objects(shadow_path, sha)
        if not obj_path:
            return False
        win_path = _nt_to_win32_path(orig_path)
        if not win_path:
            win_path = orig_path
        key = os.path.abspath(win_path).lower()
        now = time.time()
        entry = {
            'path': os.path.abspath(win_path),
            'hash': sha, 'size': int(real_size), 'mtime_ns': 0,
            'object': sha, 'ext': os.path.splitext(win_path)[1].lower(),
            'snapshot_at': now, 'last_seen': now,
            'source': 'driver_shadow', 'pid': int(pid),
            'nt_path': orig_path,
        }
        gen = self._latest_gen()
        if gen is None:
            gen = self._new_generation('driver_shadow')
        with self._state_lock:
            # 写前原像归属于**最新世代**
            gen.setdefault('entries', {})[key] = entry
            self._manifest['entries'] = gen['entries']
            self._manifest['updated_at'] = now
            self._stats['shadow_backups'] += 1
            # 曾记录的无原像告警作废（已拿到写前原像）
            self._shadow_failures.pop(key, None)
        self._save_manifest()
        return True

    def ingest_shadow_failure(self, orig_path: str, status: int = 0, reason: int = 0,
                              pid: int = 0, status_name: str = '',
                              reason_name: str = '') -> bool:
        """接收驱动侧"未备份/失败"事件 (status!=0)：记 warning，不入仓。

        这些文件在当前世代"无写前原像"，将在回滚记录中以 shadow_no_preimage 体现。
        dedup(跳过) 视为已备份过，不计入无原像集合。
        """
        if not orig_path:
            return False
        win_path = _nt_to_win32_path(orig_path) or orig_path
        key = os.path.abspath(win_path).lower()
        rname = reason_name or f'reason_{reason}'
        sname = status_name or f'status_{status}'
        if reason == 5:   # dedup: 本世代已备份过，非缺失
            logger.debug(f'写前影子去重跳过: {orig_path}')
            return True
        logger.warning(
            f'写前影子未备份 [{sname}/{rname}] (pid={pid}): {orig_path}')
        with self._state_lock:
            self._stats['shadow_no_preimage'] += 1
            self._shadow_failures[key] = {
                'path': os.path.abspath(win_path), 'status': int(status),
                'reason': int(reason), 'reason_name': rname, 'pid': int(pid),
                'ts': time.time(),
            }
            if len(self._shadow_failures) > _MAX_SHADOW_FAILURES:
                oldest = sorted(self._shadow_failures.items(),
                                key=lambda kv: kv[1].get('ts', 0))
                for k, _ in oldest[:len(self._shadow_failures) - _MAX_SHADOW_FAILURES]:
                    self._shadow_failures.pop(k, None)
        return False

    def get_shadow_stats(self) -> dict:
        """写前影子备份统计（用户态计数 + 驱动侧计数）。"""
        with self._state_lock:
            local_backups = self._stats.get('shadow_backups', 0)
            no_preimage = self._stats.get('shadow_no_preimage', 0)
            failures = len(self._shadow_failures)
        driver_stats = None
        bridge = self._driver_bridge
        if bridge is not None:
            try:
                driver_stats = bridge.query_shadow_stats()
            except Exception:
                driver_stats = None
        return {
            'generation_id': self._generation,
            'shadow_root': _shadow_gen_dir(self._generation),
            'shadow_backups': local_backups,
            'shadow_no_preimage': no_preimage,
            'shadow_failures': failures,
            'driver': driver_stats or {},
        }

    # ---- 低水位预警 ----

    def prewarn(self, files=None) -> bool:
        """低水位预警回调：抢在批量加密前对保护目录入仓（带冷却，防快照风暴）。

        若当前正有快照进行中（snapshot_in_progress），不丢弃预警：置 pending
        标记，由 worker 在当前快照结束后立即补做一次；被拒不算"已消费冷却"。
        """
        if not self._enabled:
            return False
        now = time.time()
        with self._state_lock:
            if now - self._last_prewarn < _PREWARN_COOLDOWN:
                return False
        try:
            # 低水位预警改为**增量**（replace=False）：不清空、只补变化文件，未变
            # 文件靠 (size, mtime) 短路/继承跳过 —— 在最需要快的时刻不再全量重走。
            # 为何不损失"加密前原内容"：快照只记录"当时状态"，真正的加密前原内容由
            # 阶段二写前影子备份（driver_shadow 原像）提供，其优先级最高、不被覆盖。
            res = self.snapshot_now('prewarn', replace=False)
        except Exception as e:
            with self._state_lock:
                self._last_prewarn = now
            logger.warning(f'低水位预警快照失败: {e}')
            return False

        if not res.get('ok') and res.get('reason') == 'snapshot_in_progress':
            # 被快照占用：置 pending 待补做，且不消费冷却（否则补做会被冷却挡住）
            with self._state_lock:
                self._pending_prewarn = True
            logger.info('低水位预警快照被快照任务占用, 已置补做标记, 待当前快照结束后补做')
            return False

        with self._state_lock:
            self._last_prewarn = now
        logger.info(f'低水位预警触发快照: {res}')
        return bool(res.get('ok'))

    def _consume_pending_prewarn(self):
        """补做被拒的低水位预警（worker 单步：置 pending 时立即入仓一次）。"""
        with self._state_lock:
            if not self._pending_prewarn:
                return
            self._pending_prewarn = False
            self._last_prewarn = time.time()
        try:
            res = self.snapshot_now('prewarn', replace=False)
            logger.info(f'补做低水位预警快照: {res}')
        except Exception as e:
            logger.warning(f'补做低水位预警快照失败: {e}')

    # ---- 回滚编排 ----

    def trigger_rollback(self, reason: str = 'manual', suspect_paths=None,
                         generation_id=None) -> dict:
        """触发一次回滚（同步；重入守卫保证并发仅产生一条记录）。

        generation_id=None → 使用最新世代；否则使用指定世代（用于"回滚到哪一个"）。
        """
        with self._rollback_lock:
            if self._rollback_active:
                logger.info('已有回滚进行中，忽略重复触发')
                return {'ok': False, 'reason': 'reentrant'}
            self._rollback_active = True

        t0 = time.time()
        try:
            # 0. 清场：终止所有非系统、非 PSLS 进程（可关闭；在写回文件之前）
            self._progress('清场：终止非系统进程', 3, '正在终止非系统、非 PSLS 进程…')
            kill_stat = self._kill_all_non_system(reason)
            if kill_stat.get('killed') or kill_stat.get('failed'):
                logger.critical(
                    f'[勒索回滚] 清场完成: 终止 {len(kill_stat["killed"])} 个 / '
                    f'失败 {len(kill_stat["failed"])} 个 / 保护 {kill_stat["protected"]} 个; '
                    f'示例: {kill_stat["killed"][:10]}')
            self._progress('清场完成', 12,
                           f'清场完成（终止 {len(kill_stat.get("killed", []))} 个进程）')

            # 1. 确认疑似勒索进程已终止（复用 ProcessProtection.kill_process）
            self._terminate_suspects(suspect_paths)

            # 2. 选择目标世代（None → 最新；指定不存在 → 退回最新）
            self._progress('比对文件清单', 22, '正在比对世代清单中的文件…')
            with self._state_lock:
                gen = self._latest_gen()
                if generation_id is not None:
                    found = self._find_generation(generation_id)
                    if found is not None:
                        gen = found
                    else:
                        logger.warning(
                            f'指定世代 {generation_id} 不存在，退回最新世代')
                entries = dict(gen.get('entries', {})) if gen else {}
                used_gen_id = int(gen.get('generation_id', 0)) if gen else 0
            files_rep: List[dict] = []
            restored = failed = skipped = 0
            total_entries = max(1, len(entries))
            idx = 0
            for key, meta in entries.items():
                idx += 1
                status, err = self._restore_entry(key, meta)
                # 写回阶段进度（节流：约每 2% 或每 20 个文件上报一次）
                if idx % 20 == 0 or idx == total_entries:
                    pct = 30 + int(60 * idx / total_entries)
                    self._progress('检查点回滚', min(90, pct),
                                   f'正在写回文件 {idx}/{total_entries}…')
                if status == 'restored':
                    restored += 1
                elif status == 'failed':
                    failed += 1
                else:
                    skipped += 1
                files_rep.append({
                    'path': meta.get('path') or key,
                    'hash': meta.get('hash', ''),
                    'status': status,
                    'error': err,
                    # 阶段二: 写前原像(driver_shadow) 优先于阶段一快照(snapshot)
                    'pre_image': meta.get('source') or 'snapshot',
                })

            # 3. 加密残留件（.locked 等）隔离
            self._progress('校验写回结果', 92, '正在校验写回结果…')
            self._progress('隔离加密残留', 96, '正在隔离加密残留件…')
            quarantined_files = self._quarantine_residuals(entries)
            files_rep.extend(quarantined_files)

            # 阶段二: 本世代"无写前原像"的文件（shadow miss/fail/超限）列入记录
            with self._state_lock:
                shadow_no_preimage = sorted(
                    m.get('path', k) for k, m in self._shadow_failures.items())

            duration_ms = int((time.time() - t0) * 1000)
            record = {
                'id': uuid.uuid4().hex[:12],
                'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
                'reason': reason,
                'generation_id': used_gen_id,
                'trigger_files': list(suspect_paths) if suspect_paths else [],
                'total': len(files_rep),
                'restored': restored, 'failed': failed, 'skipped': skipped,
                'duration_ms': duration_ms,
                'files': files_rep,
                'shadow_no_preimage': shadow_no_preimage,
                'kill_all': {
                    'killed': len(kill_stat.get('killed', [])),
                    'failed': len(kill_stat.get('failed', [])),
                    'protected': kill_stat.get('protected', 0),
                },
            }
            with self._state_lock:
                self._records.insert(0, record)
                self._records = self._records[:_MAX_RECORDS]
                self._stats['rollbacks'] += 1
                self._stats['restored'] += restored
                self._stats['failed'] += failed
                self._stats['skipped'] += skipped
            self._save_records()

            result = {
                'ok': True, 'reason': reason, 'record_id': record['id'],
                'generation_id': used_gen_id,
                'total': len(files_rep), 'restored': restored,
                'failed': failed, 'skipped': skipped,
                'quarantined': len(quarantined_files), 'duration_ms': duration_ms,
                'killed': len(kill_stat.get('killed', [])),
                'kill_failed': len(kill_stat.get('failed', [])),
            }
            self._progress('完成', 100, '回滚完成')
            logger.critical(
                f'[勒索回滚] 完成({reason}, 世代{used_gen_id}): 恢复 {restored} / '
                f'失败 {failed} / 跳过 {skipped} / 隔离残留 {len(quarantined_files)}')
            self._report(result)
            return result
        finally:
            with self._rollback_lock:
                self._rollback_active = False

    def _restore_entry(self, key: str, meta: dict):
        """恢复单个清单条目，返回 (status, error)。"""
        path = meta.get('path') or key
        sha = meta.get('hash') or meta.get('object')
        size = meta.get('size', 0) or 0
        if size > self._max_file_bytes:
            return 'skipped', 'too_large'
        now = time.time()
        with self._state_lock:
            if key in self._restore_giveup:
                return 'skipped', 'giveup'
            last = self._last_restore_fail.get(key)
            if last and (now - last) < _RETRY_INTERVAL:
                return 'skipped', 'throttled'

        # 安全闸门：正常第三方软件（QQ/VMware/微信…）的数据目录**绝不写回**
        # （避免用旧快照覆盖 QQ/VMware 的当前配置/数据 → "文件受损"）
        if _is_protected_app_path(path):
            self._audit('跳过写回', f'{path}（第三方软件数据目录，不覆盖）')
            return 'skipped', 'protected_app_path'

        # 现况比对：文件存在且哈希未变 → 无需恢复
        if sha and os.path.isfile(path):
            cur = _sha256_file(path)
            if cur == sha:
                return 'skipped', 'intact'

        # 安全闸门：目标正被其它进程占用（写不进去/写完会破坏在用数据）→ 跳过
        if os.path.isfile(path) and not self._is_writable(path):
            self._audit('跳过写回', f'{path}（被其它进程占用）')
            return 'skipped', 'in_use'

        obj = self._object_path(sha) if sha else None
        if not obj or not os.path.isfile(obj):
            return 'failed', 'object_missing'

        tmp = path + '.psls_restore.tmp'
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(obj, 'rb') as fin, open(tmp, 'wb') as fout:
                shutil.copyfileobj(fin, fout, 65536)
                fout.flush()
                try:
                    os.fsync(fout.fileno())
                except Exception:
                    pass
            os.replace(tmp, path)
            if sha and _sha256_file(path) != sha:
                raise IOError('写回后哈希校验失败')
            # 写回成功 → 清理可能残留的软隔离登记
            self._cleanup_soft_quarantine(path)
            self._audit('写回恢复', f'{path}（从对象 {str(sha)[:12]} 恢复）')
            with self._state_lock:
                self._last_restore_fail.pop(key, None)
                self._restore_giveup.discard(key)
            return 'restored', ''
        except Exception as e:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
            with self._state_lock:
                prev = self._last_restore_fail.get(key)
                self._last_restore_fail[key] = now
                # 30s 节流窗口外仍失败 → 永久放弃（对齐 mbr_protector 策略）
                if prev and (now - prev) >= _RETRY_INTERVAL:
                    self._restore_giveup.add(key)
            return 'failed', str(e)

    def _cleanup_soft_quarantine(self, path: str):
        qm = self._quarantine_manager
        fn = getattr(qm, '_unregister_soft_quarantine', None) if qm else None
        if callable(fn):
            try:
                fn(path)
            except Exception:
                pass

    def _quarantine_residuals(self, entries: dict) -> List[dict]:
        """隔离"本次回滚受影响路径"内的勒索加密残留件（**有边界、可推进、可中断**）。

        性能事故（实测）：原实现 `os.walk` **全部受保护目录**（桌面/文档/下载/图片/
        视频/音乐，桌面单目录即可上万文件），且逐文件 `_audit`/隔离 → 回滚卡在 96%
        「正在隔离加密残留...」，主窗口"未响应"。世代为 0 文件时还会白跑一遍全盘。

        现实现：
          1. **0 个清单条目 → 直接判定"无需隔离残留"并返回**（绝不全盘遍历）；
          2. 扫描范围**只限本次涉及路径**：清单条目所在目录（去重、剔除被包含的
             子目录），不再遍历无关目录；
          3. 硬上限：最多扫描 `_QUARANTINE_MAX_FILES` 个文件、`_QUARANTINE_MAX_DEPTH`
             层深、最多 `_QUARANTINE_MAX_SECONDS` 秒（可环境变量覆盖），达到即停并
             WARNING；期间按"已扫描 N"上报真实进度；
          4. 日志**聚合**（结束时一条：隔离 N / 跳过 M / 失败 K + 前 3 个示例），
             不再逐文件写日志/信号。
        """
        out: List[dict] = []
        known = set(entries.keys())
        if not known:
            # 现象 2：0 文件世代 → 本就没有"受影响路径"，立即完成（不遍历）
            logger.info('勒索回滚：世代为 0 个文件 → 无需隔离残留，立即完成')
            self._progress('隔离加密残留', 99, '无需隔离残留（本次无受影响文件）')
            return out

        # 清单内文件的文件名（小写），用于"同前缀改名件"识别
        known_names = set()
        for k in known:
            try:
                known_names.add(os.path.basename(k).lower())
            except Exception:
                continue

        # ---- 范围收敛：只扫"清单条目所在目录"（去重 + 剔除被包含子目录）----
        # 注意：用 meta['path']（**保留真实大小写**）而非小写 key，避免 walk 出来的
        # 路径被小写化（历史上曾因小写化导致隔离登记路径与真实路径不一致）。
        scope_dirs: List[str] = []
        seen_norm = set()
        for k, meta in entries.items():
            try:
                p = (meta or {}).get('path') or k
                d = os.path.dirname(p)
            except Exception:
                continue
            if not d or not os.path.isdir(d):
                continue
            nd = os.path.normcase(os.path.abspath(d)).rstrip('\\/')
            if nd in seen_norm:
                continue
            seen_norm.add(nd)
            scope_dirs.append(d)
        # 剔除被其它 scope 目录包含的子目录，避免重复遍历
        try:
            scope_dirs = self._dedup_dirs(scope_dirs)
        except Exception:
            pass

        repo_norm = os.path.normcase(os.path.abspath(_REPO_ROOT))
        t_start = time.time()
        scanned = 0
        skipped_apps = 0
        failed = 0
        examples: List[str] = []
        hit_limits = ''

        for d in scope_dirs:
            if hit_limits:
                break
            depth_base = os.path.normcase(os.path.abspath(d)).count(os.sep)
            for root, subdirs, files in os.walk(d):
                if hit_limits:
                    break
                # 深度上限（相对 scope 根）
                if (os.path.normcase(os.path.abspath(root)).count(os.sep)
                        - depth_base) >= _QUARANTINE_MAX_DEPTH:
                    subdirs[:] = []
                root_norm = os.path.normcase(os.path.abspath(root))
                # 同样排除 PSLS 自身安装目录（图1：96% 卡在"扫描受影响目录"即因扫自己的目录）
                if root_norm == repo_norm or root_norm.startswith(repo_norm + os.sep) \
                        or _is_psls_self_path(root):
                    subdirs[:] = []
                    continue
                for fn in files:
                    scanned += 1
                    if scanned % 500 == 0:
                        self._progress('隔离加密残留', 96 + min(3, scanned // 2000),
                                       f'正在扫描受影响目录（已扫描 {scanned} 个文件）…')
                    if scanned > _QUARANTINE_MAX_FILES:
                        hit_limits = f'文件数上限 {_QUARANTINE_MAX_FILES}'
                        break
                    if time.time() - t_start > _QUARANTINE_MAX_SECONDS:
                        hit_limits = f'时间上限 {_QUARANTINE_MAX_SECONDS:.0f}s'
                        break
                    name_lower = fn.lower()
                    fp = os.path.join(root, fn)
                    if _is_protected_app_path(fp):
                        skipped_apps += 1
                        continue
                    ext = os.path.splitext(name_lower)[1]
                    if ext in _RENAME_RESIDUAL_EXTS:
                        pass
                    elif self._is_rename_residual(name_lower, known_names):
                        pass
                    else:
                        continue
                    key = os.path.abspath(fp).lower()
                    if key in known:
                        continue
                    if self._quarantine_file(fp):
                        if len(examples) < 3:
                            examples.append(os.path.basename(fp))
                        out.append({
                            'path': fp, 'hash': '', 'status': 'quarantined',
                            'error': '',
                        })
                    else:
                        failed += 1

        # ---- 聚合日志（杜绝逐文件信号/日志淹死 GUI）----
        if out or failed or skipped_apps:
            self._audit('隔离残留(汇总)',
                        f'隔离 {len(out)} / 失败 {failed} / 跳过第三方软件 {skipped_apps} '
                        f'/ 扫描 {scanned} 个文件 / 目录 {len(scope_dirs)} 个'
                        + (f' / 示例 {examples}' if examples else ''))
            logger.critical(
                f'[勒索回滚] 残留隔离汇总: 隔离 {len(out)} / 失败 {failed} / '
                f'跳过 {skipped_apps} / 扫描 {scanned} / 用时 {time.time() - t_start:.1f}s')
        if hit_limits:
            logger.warning(f'残留隔离达到{hit_limits}，已提前结束（未扫描部分可能存在残留）')
            self._audit('隔离残留(截断)', f'达到{hit_limits}，提前结束；已扫描 {scanned}')
        return out

    @staticmethod
    def _is_rename_residual(name_lower: str, known_names: set) -> bool:
        """判定文件名是否为"清单内文件的**严格**同前缀改名件"。

        仅保留低误伤的规则：`a.docx` -> `a.docx.locked`（以清单文件名为前缀、更长，
        且多出部分以 '.' 开头构成新后缀）。**已移除**"同 stem 不同后缀"规则——
        该规则会把 `report.txt`（清单里有 `report.docx`）误判为残留而移动用户文件。
        """
        if not name_lower or not known_names:
            return False
        for kn in known_names:
            if not kn or kn == name_lower:
                continue
            if name_lower.startswith(kn) and len(name_lower) > len(kn):
                suffix = name_lower[len(kn):]
                # 多出部分必须是".xxx"形式的新后缀（防 a.txt 命中 a 之类）
                if suffix.startswith('.') and len(suffix) > 1:
                    return True
        return False

    @staticmethod
    def _is_writable(path: str) -> bool:
        """目标文件当前是否可写（未被其它进程独占）。

        用只读+共享方式探测：以 r+b 打开失败（PermissionError/OSError）即视为被占用。
        不修改任何内容，异常安全。
        """
        try:
            with open(path, 'r+b'):
                return True
        except FileNotFoundError:
            return True      # 不存在视为可写（将新建）
        except Exception:
            return False

    def _quarantine_file(self, path: str) -> bool:
        qm = self._quarantine_manager
        if qm is None:
            return False
        try:
            res = qm.quarantine_file(
                path, reason='勒索加密残留文件',
                malware_name='Ransomware.Encrypted')
            ok = (res is True or res == 'duplicate')
            if ok:
                with self._state_lock:
                    self._stats['quarantined'] += 1
            return ok
        except Exception as e:
            logger.warning(f'隔离加密残留件失败 {path}: {e}')
            return False

    # ---- 回滚前"清场"（终止所有非系统、非 PSLS 进程）----

    def set_kill_all_before_restore(self, enabled: bool):
        """开关：回滚前是否清场（终止非系统/非 PSLS 进程）。"""
        self._kill_all_before_restore = bool(enabled)

    def get_kill_all_before_restore(self) -> bool:
        return bool(self._kill_all_before_restore)

    def _progress(self, stage: str, percent: int, text: str = '', show: bool = True):
        """上报阶段进度（仅内存回调；绝不写协议通道）。

        show=False 表示"只记日志、不弹进度窗口"（周期/prewarn 快照用），
        由前端/桥接按 `show` 字段决定是否显示窗口。
        """
        cb = self._on_progress
        if not cb:
            return
        try:
            cb({'stage': stage or '', 'percent': max(0, min(100, int(percent))),
                'text': text or stage or '', 'show': bool(show)})
        except Exception as e:
            logger.debug(f'on_progress 回调异常: {e}')

    def _protected_pids(self, psutil_mod) -> set:
        """收集绝不终止的 PID：本进程 + 全部祖先 + **主进程的完整子孙树**
        + 名字含 psls/mlworker/Chromium 渲染进程。

        关键（进程树语义）：worker 隔离架构下本方法在 **worker 进程**执行，
        主进程（PSLS.exe）的其它子进程 —— 尤其是QtWebEngineProcess.exe（整个
        前端 UI 渲染层）—— 是 worker 的"兄弟"而非子孙；只按"自身子孙"收集
        会把 UI 渲染进程漏出保护集，清场时误杀 → 界面白屏/"未响应"。
        因此：父进程（即主进程）必须收集其**全部子孙**；而祖父及以上祖先
        （如 explorer/cmd 等宿主）仅保护进程本身，**绝不收集其子孙**——
        否则 explorer 整棵进程树都被保护，清场将一条进程都杀不掉（架空清场）。
        """
        pids = {os.getpid()}
        try:
            me = psutil_mod.Process(os.getpid())
            # 1) 自身 + 自身全部子孙
            try:
                for ch in me.children(recursive=True):
                    pids.add(ch.pid)
            except Exception:
                pass
            # 2) 父进程（主进程 PSLS.exe）：加入保护并收集其**完整子孙树**
            #    （覆盖 QtWebEngineProcess / MLWorker / 扫描子进程等兄弟子树）
            try:
                parent = me.parent()
            except Exception:
                parent = None
            if parent is not None:
                pids.add(parent.pid)
                try:
                    for ch in parent.children(recursive=True):
                        pids.add(ch.pid)
                except Exception:
                    pass
                # 3) 祖先链（祖父及以上）：仅保护进程本身，不收集子孙
                p = parent.parent()
                while p is not None:
                    pids.add(p.pid)
                    try:
                        p = p.parent()
                    except Exception:
                        break
        except Exception:
            pass
        try:
            for proc in psutil_mod.process_iter(attrs=['pid', 'name']):
                try:
                    n = (proc.info.get('name') or '').lower()
                except Exception:
                    continue
                # 调整决定 2：仅保护 PSLS 自身/子进程（含 worker/MLWorker）；
                # 不再保护第三方沙箱基础设施（Sbie* 服务、Start.exe 等）。
                if 'psls' in n or 'mlworker' in n:
                    pids.add(proc.pid)
        except Exception:
            pass
        return pids

    @staticmethod
    def _is_protected_name(name: str) -> bool:
        """进程名是否属于保护集（系统关键进程 + psls/mlworker）。

        调整决定 2：**不再**把第三方沙箱基础设施（Sbie* 服务、Start.exe、
        *DcomLaunch 等）与第三方白名单纳入保护集 →
        除系统进程与 PSLS 自身/子进程外，全部终止。
        """
        n = (name or '').lower().strip()
        if not n:
            return False
        if 'psls' in n or 'mlworker' in n:
            return True
        base = n[:-4] if n.endswith('.exe') else n
        return base in _PROTECTED_PROCESS_NAMES or n in _PROTECTED_PROCESS_NAMES

    def _audit(self, action: str, detail: str):
        """审计日志：记录每次"终止/覆盖/移动/隔离"等不可逆操作，便于事后定责。

        统一前缀 `[PSLS-AUDIT]` 便于日志检索；同时保留内存环形缓冲（供测试/自证）。
        """
        try:
            entry = {
                'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
                'action': action,
                'detail': str(detail),
            }
            buf = getattr(self, '_audit_buf', None)
            if buf is None:
                buf = []
                self._audit_buf = buf
            buf.append(entry)
            if len(buf) > 500:
                del buf[:len(buf) - 500]
            logger.warning(f'[PSLS-AUDIT] {action}: {detail}')
        except Exception:
            pass

    def get_audit_log(self) -> list:
        """返回内存审计日志副本（时间倒序无关，原序）。"""
        try:
            return [dict(x) for x in (getattr(self, '_audit_buf', None) or [])]
        except Exception:
            return []

    def _kill_all_non_system(self, reason: str = '') -> dict:
        """终止所有**非系统、非 PSLS** 进程（方案 B：紧急终止与回滚清场同一规则）。

        **已取消"跳过第三方"这条规则**（要求 1）：不再因进程名命中第三方白名单
        （VMware/VirtualBox/QQ/TIM/微信/WPS…）而跳过 → **explorer / VMware / QQ 等
        都会被终止**。紧急终止与回滚前清场走同一条路、同一规则，**无紧急专用分支**
        （不再有任何"包含/排除第三方"的参数）。

        **受理白名单**（要求 3）：`emergency`（零确认直呼）与
        `manual_confirmed`/`user_confirmed`/`manual`（用户确认回滚）均可执行；
        误报/自动路径（如 auto_detect）一律跳过并记 WARNING。

        **必须保留的保护集**（调整决定 2，不得误杀，否则自毁/无法退出）——**仅**：
          - Windows 系统关键进程（`_PROTECTED_PROCESS_NAMES`）、PID 0/4；
          - PSLS 自身 + 祖先/子孙链 + 名字含 `psls`/`mlworker`（含 worker/MLWorker）。
        **不再保护**第三方沙箱基础设施（Sbie* 服务、Start.exe、*RpcSs 等）
        与第三方白名单（VMware/QQ/微信/WPS/explorer…）→ 除系统进程与 PSLS
        自身/子进程外**全部终止**。
        ★ 副作用：第三方沙箱服务会被一并终止，**沙箱需重启**后才能再次使用。
        正常退出通道不受影响（用户主动退出 PSLS 不经过本方法）。

        注意（要求 4）：本方法**只放宽"进程终止"**；第三方**文件**保护
        （`_is_protected_app_path` / `_is_protected_app_name` 用于隔离残留、回滚写回）
        **完全不变**，仍绝不移动/覆盖 QQ/VMware 的文件。
        """
        out = {'enabled': bool(self._kill_all_before_restore),
               'killed': [], 'failed': [], 'protected': 0,
               'skipped_reason': ''}
        if not self._kill_all_before_restore:
            return out
        # ---- 受理白名单：用户确认回滚 + 紧急终止（零确认直呼，必须能执行）----
        _confirmed = {'user_confirmed', 'manual_confirmed', 'manual', 'emergency'}
        if str(reason or '').lower() not in _confirmed:
            out['skipped_reason'] = f'unconfirmed_reason:{reason}'
            logger.warning(
                f'[勒索回滚] 清场已跳过：触发原因 "{reason}" 不在受理白名单'
                f'（防误报触发不可逆清场）')
            self._audit('清场跳过', f'非用户确认路径 reason={reason}')
            return out
        # 引擎未运行（如离线单测）时不清场，避免误杀测试宿主进程；
        # 但**紧急终止**是零确认的独立入口，不依赖回滚引擎是否在跑（要求 3）。
        if not self._running and str(reason or '').lower() != 'emergency':
            logger.info('[勒索回滚] 引擎未运行，跳过回滚前清场')
            return out
        try:
            import psutil
        except ImportError:
            logger.warning('[勒索回滚] psutil 不可用，跳过清场')
            return out
        protected = self._protected_pids(psutil)
        procs = []
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            try:
                pid = proc.pid
                name = (proc.info.get('name') or '').lower()
            except Exception:
                continue
            # 调整决定 2：保护集**仅**系统关键进程、PID 0/4、PSLS 自身/祖先/子孙、
            # psls/mlworker（_is_protected_name 已涵盖后两者）。
            # 第三方沙箱基础设施与第三方（VMware/QQ/explorer…）不再保护 → 一律终止。
            if pid in (0, 4) or pid in protected or self._is_protected_name(name):
                out['protected'] += 1
                continue
            procs.append((proc, name))
        for proc, name in procs:
            try:
                proc.terminate()
                out['killed'].append(name or str(proc.pid))
            except Exception as e:
                out['failed'].append(name or str(getattr(proc, 'pid', '?')))
                logger.warning(f'[勒索回滚] 终止进程失败({name}): {e}')
        # 短等待后对残留进程强杀
        try:
            alive = psutil.wait_procs([p for p, _ in procs], timeout=1.0)[1]
        except Exception:
            alive = []
        for proc in alive:
            try:
                proc.kill()
            except Exception as e:
                logger.warning(f'[勒索回滚] 强杀残留进程失败: {e}')
        # ---- 审计日志（可回溯/定责）----
        self._audit(
            '清场终止',
            f'reason={reason} 终止={len(out["killed"])} 失败={len(out["failed"])} '
            f'保护={out["protected"]} 示例={out["killed"][:10]}')
        return out

    def _terminate_suspects(self, suspect_paths):
        """确认疑似勒索进程已终止（尽力复用 ProcessProtection.kill_process）。"""
        if not suspect_paths or self._process_protection is None:
            return
        try:
            import psutil
        except ImportError:
            return
        targets = set()
        for f in suspect_paths:
            try:
                targets.add(os.path.abspath(f).lower())
            except Exception:
                pass
        if not targets:
            return
        kills = 0
        try:
            for proc in psutil.process_iter(attrs=['pid']):
                try:
                    for of in proc.open_files():
                        if of.path.lower() in targets:
                            self._process_protection.kill_process(
                                proc.pid, force=True, kill_tree=True, timeout=0.5)
                            kills += 1
                            break
                except Exception:
                    continue
        except Exception as e:
            logger.warning(f'终止疑似勒索进程异常: {e}')
        if kills:
            logger.critical(f'[勒索回滚] 已终止 {kills} 个疑似勒索进程')

    # ---- 单文件恢复 / 删除备份 / 清除 ----

    def _find_entry(self, key_or_path):
        """在所有世代中查找条目，返回 (gen, key, meta)；未找到返回 (None,None,None)。

        新→旧遍历，优先命中最新世代。
        """
        try:
            key = os.path.abspath(key_or_path).lower()
        except Exception:
            return None, None, None
        for g in self._generations:
            entries = g.get('entries', {})
            if key in entries:
                return g, key, entries[key]
            for k, m in entries.items():
                if (m.get('path') or '').lower() == key:
                    return g, k, m
        return None, None, None

    def _entry_key(self, path: str) -> Optional[str]:
        _gen, key, _meta = self._find_entry(path)
        return key

    def restore_single_file(self, record_id, path: str) -> bool:
        """从仓库单文件恢复（用于"回滚中心"逐项恢复；跨全部世代查找）。"""
        _gen, key, meta = self._find_entry(path)
        if key is None or not meta:
            return False
        meta = dict(meta)
        status, _err = self._restore_entry(key, meta)
        ok = status == 'restored'
        # 回写记录中的文件状态（供 UI 刷新）
        if record_id is not None:
            with self._state_lock:
                for rec in self._records:
                    if str(rec.get('id')) == str(record_id):
                        for it in rec.get('files', []):
                            if (it.get('path') or '').lower() == key:
                                it['status'] = status
                        break
                self._records = list(self._records)
            self._save_records()
        return ok

    def delete_backup(self, hash_or_path: str) -> bool:
        """按哈希或路径删除备份（对象 + 清单条目；跨全部世代查找）。"""
        arg = str(hash_or_path or '').strip()
        if len(arg) == 64 and all(c in '0123456789abcdef' for c in arg.lower()):
            return self._delete_object(arg.lower())
        gen, key, meta = self._find_entry(arg)
        if key is None or gen is None:
            return False
        with self._state_lock:
            gen.get('entries', {}).pop(key, None)
            if gen is self._latest_gen():
                self._manifest['entries'] = gen.get('entries', {})
            self._manifest['updated_at'] = time.time()
        self._save_manifest()
        sha = (meta or {}).get('hash') or (meta or {}).get('object')
        if sha:
            self._delete_object(sha)
        return True

    def _delete_object(self, sha: str, force: bool = False) -> bool:
        obj_path = self._object_path(sha)
        # 与 `_store_object`/`_move_into_objects` 保持一致的锁序（object → state），
        # 既避免"删除正在写入的对象"，也杜绝反向获取造成死锁。
        with self._object_lock(sha):
            if not os.path.isfile(obj_path):
                return False
            if not force:
                with self._state_lock:
                    # 检查所有世代（含各世代的写前原像条目）是否仍引用该对象
                    for g in self._generations:
                        for m in g.get('entries', {}).values():
                            if (m.get('hash') or m.get('object')) == sha:
                                return False   # 仍被某世代引用，不删除
            try:
                os.remove(obj_path)
                with self._state_lock:
                    self._stats['purged_objects'] += 1
                return True
            except Exception as e:
                logger.warning(f'删除备份对象失败 {sha}: {e}')
                return False

    def _purge_generation_entries(self, gen: dict) -> int:
        """整体刷新某个世代：仅清除该世代中非 driver_shadow 来源的条目。

        阶段二的写前原像 (source='driver_shadow') 优先级高于快照，必须保留，
        否则每次周期/启动快照都会把好不容易拿到的写前原像清掉。
        删除对象时仍按"是否被其它条目/世代引用"判断，绝不误删共享对象。
        """
        with self._state_lock:
            entries = gen.get('entries', {})
            removed = {k: m for k, m in entries.items()
                       if m.get('source') != 'driver_shadow'}
            for k in removed:
                entries.pop(k, None)
            self._manifest['updated_at'] = time.time()
        if removed:
            for m in removed.values():
                sha = m.get('hash') or m.get('object')
                if sha:
                    # 仍被其它条目/世代引用时 _delete_object 会自动保留
                    self._delete_object(sha)
        return len(removed)

    def _purge_snapshot_generation(self) -> int:
        """兼容入口：清除当前（最新）世代的非写前原像条目。"""
        gen = self._latest_gen()
        if gen is None:
            return 0
        return self._purge_generation_entries(gen)

    def purge(self) -> int:
        """清除全部备份（全部世代 + 对象；保留回滚记录用于审计）。"""
        with self._state_lock:
            count = sum(len(g.get('entries', {})) for g in self._generations)
            self._generations = []
            self._sync_latest_alias()
            self._manifest['updated_at'] = time.time()
        self._save_manifest()
        objects_dir = _objects_dir()
        try:
            if os.path.isdir(objects_dir):
                shutil.rmtree(objects_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f'清除仓库对象失败: {e}')
        with self._state_lock:
            self._stats['purged_objects'] += count
        logger.info(f'勒索回滚仓库已清除（{count} 条备份记录）')
        return count

    # ---- 容量配额 / LRU 清理 ----

    def _repo_usage_bytes(self) -> int:
        """全量统计仓库对象占用（并刷新缓存）。较慢——勿在命令/查询热路径直接调用。"""
        total = 0
        for p in _iter_object_files():
            try:
                total += os.path.getsize(p)
            except OSError:
                pass
        with self._state_lock:
            self._repo_usage_cache = total
            self._repo_usage_ts = time.time()
        return total

    def _repo_usage_cached(self) -> int:
        """读取仓库用量缓存；过期则触发后台刷新并**立即返回旧值**（零阻塞）。"""
        with self._state_lock:
            fresh = (time.time() - self._repo_usage_ts) <= _REPO_USAGE_TTL
            val = self._repo_usage_cache
        if not fresh:
            self._refresh_repo_usage_bg()
        return val

    def _refresh_repo_usage_bg(self):
        """后台线程刷新仓库用量缓存（去重；绝不阻塞调用线程）。"""
        with self._state_lock:
            if self._repo_usage_refreshing:
                return
            self._repo_usage_refreshing = True

        def _run():
            try:
                self._repo_usage_bytes()
            except Exception as e:
                logger.debug(f'后台刷新仓库用量失败: {e}')
            finally:
                with self._state_lock:
                    self._repo_usage_refreshing = False
        try:
            threading.Thread(target=_run, daemon=True,
                             name='RbRepoUsageRefresh').start()
        except Exception:
            with self._state_lock:
                self._repo_usage_refreshing = False

    def _enforce_quota(self) -> int:
        """按 LRU（last_seen/snapshot_at）+ 孤立对象优先清理，直到低于容量上限。"""
        usage = self._repo_usage_bytes()
        if usage <= self._max_repo_bytes:
            return 0
        with self._state_lock:
            # 跨全部世代聚合对象的"世代时间"（取最新引用时间）
            obj_ts: Dict[str, float] = {}
            for g in self._generations:
                for m in g.get('entries', {}).values():
                    o = m.get('object') or m.get('hash')
                    if not o:
                        continue
                    ts = m.get('snapshot_at', 0) or m.get('last_seen', 0) or 0
                    if o not in obj_ts or ts > obj_ts[o]:
                        obj_ts[o] = ts

        objs = []
        for p in _iter_object_files():
            try:
                objs.append((p, os.path.getsize(p)))
            except OSError:
                pass
        # 孤立对象（不在清单中）ts=0，最先清理
        objs.sort(key=lambda x: (obj_ts.get(os.path.basename(x[0]), 0.0), x[0]))

        freed = 0
        evicted = set()
        for p, sz in objs:
            if usage - freed <= self._max_repo_bytes:
                break
            try:
                os.remove(p)
                freed += sz
                evicted.add(os.path.basename(p))
            except OSError:
                pass

        if evicted:
            with self._state_lock:
                # 从全部世代中移除已被清理对象的条目
                for g in self._generations:
                    ents = g.get('entries', {})
                    for k in [k for k, m in ents.items()
                              if (m.get('object') or m.get('hash')) in evicted]:
                        ents.pop(k, None)
                self._sync_latest_alias()
                self._stats['purged_objects'] += len(evicted)
            self._save_manifest()
            logger.info(f'勒索回滚仓库超限，LRU 清理 {len(evicted)} 个对象，释放 {freed} 字节')
        return freed

    # ---- 记录 / 统计 ----

    def list_records(self, limit: int = 50) -> List[dict]:
        with self._state_lock:
            return [dict(r) for r in self._records[:max(0, int(limit))]]

    def get_stats(self) -> dict:
        # 用量走缓存（过期后台刷新）：本方法位于 worker 串行命令循环与
        # （降级模式的）GUI 线程轮询路径上，全量遍历 objects/ 会造成
        # 命令排队超时 / 界面卡顿。
        usage = self._repo_usage_cached()
        with self._state_lock:
            stats = dict(self._stats)
            entries = len(self._manifest.get('entries', {}))
            records = len(self._records)
            dirs = list(self._protected_dirs)
            generations = len(self._generations)
            shadow_entries = sum(
                1 for g in self._generations
                for m in g.get('entries', {}).values()
                if m.get('source') == 'driver_shadow')
        stats.update({
            'enabled': self._enabled,
            'running': self._running,
            'entries': entries,
            'records': records,
            'repo_bytes': usage,
            'max_repo_bytes': self._max_repo_bytes,
            'max_file_bytes': self._max_file_bytes,
            'protected_dirs': dirs,
            'generation_id': self._generation,
            'generations': generations,
            'max_generations': _MAX_GENERATIONS,
            'shadow_entries': shadow_entries,
        })
        return stats

    # ---- 持久化 ----

    def _save_manifest(self):
        try:
            with self._state_lock:
                data = {
                    'version': self._manifest.get('version', _MANIFEST_VERSION),
                    'updated_at': self._manifest.get('updated_at', 0),
                    'dirs': list(self._manifest.get('dirs', [])),
                    'exts': list(self._manifest.get('exts', [])),
                    # 世代列表（新→旧）；最新世代 entries 即 _manifest['entries']
                    'generations': [
                        {
                            'generation_id': int(g.get('generation_id', 0)),
                            'created_at': g.get('created_at', 0),
                            'reason': g.get('reason', ''),
                            'dirs': list(g.get('dirs') or []),
                            'exts': list(g.get('exts') or []),
                            'entries': dict(g.get('entries', {})),
                            # 世代级计数持久化：重启后 UI 仍可显示"尝试/纳入"
                            'attempted': int(g.get('attempted', 0) or 0),
                            'ingested': int(g.get('ingested', 0) or 0),
                            'unreadable': int(g.get('unreadable', 0) or 0),
                            'failed': int(g.get('failed', 0) or 0),
                        }
                        for g in self._generations
                    ],
                    # 兼容字段：最新世代 entries
                    'entries': dict(self._manifest.get('entries', {})),
                }
            _atomic_write_text(_manifest_path(),
                               json.dumps(data, ensure_ascii=False))
        except Exception as e:
            logger.warning(f'保存 manifest 失败: {e}')

    def _save_records(self):
        try:
            with self._state_lock:
                payload = json.dumps(
                    {'records': list(self._records[:_MAX_RECORDS])},
                    ensure_ascii=False)
            _atomic_write_text(_records_path(), payload)
        except Exception as e:
            logger.warning(f'保存 records 失败: {e}')

    def _load_state(self):
        try:
            mp = _manifest_path()
            if os.path.isfile(mp):
                with open(mp, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    gens = data.get('generations')
                    if isinstance(gens, list) and gens:
                        loaded = []
                        for g in gens[: _MAX_GENERATIONS]:
                            if not isinstance(g, dict):
                                continue
                            ents = g.get('entries')
                            loaded.append({
                                'generation_id': int(g.get('generation_id', 0)),
                                'created_at': g.get('created_at', 0),
                                'reason': g.get('reason', ''),
                                'dirs': list(g.get('dirs') or []),
                                'exts': list(g.get('exts') or []),
                                'entries': ents if isinstance(ents, dict) else {},
                                'attempted': int(g.get('attempted', 0) or 0),
                                'ingested': int(g.get('ingested', 0) or 0),
                                'unreadable': int(g.get('unreadable', 0) or 0),
                                'failed': int(g.get('failed', 0) or 0),
                            })
                        self._generations = loaded
                        self._sync_latest_alias()
                    else:
                        # 旧格式迁移：顶层 entries → 单个世代（标记为 legacy）
                        entries = data.get('entries')
                        if isinstance(entries, dict) and entries:
                            legacy = {
                                'generation_id': 0, 'created_at': 0,
                                'reason': 'legacy',
                                'dirs': list(data.get('dirs') or []),
                                'exts': list(data.get('exts') or []),
                                'entries': entries,
                            }
                            self._generations = [legacy]
                        self._sync_latest_alias()
                    if isinstance(data.get('dirs'), list):
                        self._manifest['dirs'] = data['dirs']
                    if isinstance(data.get('exts'), list):
                        self._manifest['exts'] = data['exts']
                    self._manifest['version'] = data.get('version', _MANIFEST_VERSION)
                    self._manifest['updated_at'] = data.get('updated_at', 0)
            rp = _records_path()
            if os.path.isfile(rp):
                with open(rp, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                recs = data.get('records') if isinstance(data, dict) else data
                if isinstance(recs, list):
                    self._records = recs[:_MAX_RECORDS]
        except Exception as e:
            logger.debug(f'加载回滚状态失败: {e}')

    # ---- 上报（仅内存回调，不写协议通道）----

    def _report(self, payload: dict):
        cb = self._on_report
        if not cb:
            return
        try:
            cb(dict(payload))
        except Exception as e:
            logger.warning(f'on_report 回调异常: {e}')