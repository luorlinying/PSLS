# -*- coding: utf-8 -*-
"""
MBR / 引导扇区保护引擎

通过用户态周期校验物理磁盘 MBR 和各分区 VBR/PBR 的完整性，
检测 bootkit 篡改行为并在检测到篡改时告警 + 可选恢复。

设计要点:
  - 打开 \\.\PhysicalDrive0 读取前 512 字节 (MBR)
  - 打开 \\.\C: 等卷设备读取各分区引导扇区 (VBR/PBR)
  - SHA-256 指纹比对, 检测到变化时回调 on_threat
  - 支持 trust_change() 信任本次变更 (刷新备份, 不告警)
  - 支持 restore() 从备份恢复引导扇区
  - 线程安全: RLock 保护 _backup / _running 等状态
"""

import os
import sys
import time
import json
import base64
import hashlib
import struct
import threading
from typing import Callable, Dict, List, Optional, Set, Tuple

from utils.logger import get_logger

logger = get_logger('mbr_protector')

try:
    import ctypes
    from ctypes import wintypes
    _HAS_WIN32 = True

    # --- Win32 API 原型声明 (x64 句柄安全, 避免 32 位截断/溢出) ---
    _kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _kernel32.ReadFile.restype = wintypes.BOOL
    _kernel32.ReadFile.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    _kernel32.WriteFile.restype = wintypes.BOOL
    _kernel32.WriteFile.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
except ImportError:
    _HAS_WIN32 = False
    ctypes = None
    wintypes = None

# MBR 扇区大小
_SECTOR_SIZE = 512
# MBR 引导签名 (偏移 0x1FE)
_MBR_SIG_OFFSET = 0x1FE
_MBR_SIG_VALUE = b'\x55\xaa'
# 轮询间隔 (秒) —— 实时监控: 1 秒轮询
_DEFAULT_INTERVAL = 1.0
# 扇区 (MBR/VBR) 快速轮询间隔 (秒)：512 字节 SHA-256 校验开销 <1ms，
# 用远小于关键目录轮询的间隔高频校验，把"引导扇区被改写 → 检测 → 回滚"
# 的响应窗口从 1s(降载时 5~10s) 压缩到 0.25s。不受 load_governor 降载
# 拉长影响（负载高只放宽关键目录检查频率，MBR 防护必须保持灵敏）。
_MBR_FAST_INTERVAL = 0.25
# 扇区恢复失败后的重试间隔 (秒)：恢复动作不再被 30s 通知去重吞掉，
# 每次检测到篡改都尝试回滚，但失败时 1s 节流，避免疯狂重试刷日志。
_MBR_RESTORE_RETRY_INTERVAL = 1.0
# 同一设备篡改处理的最小重试间隔 (秒), 防止恶意软件循环覆盖时刷屏
_RETRY_INTERVAL = 30.0
# 备份目录
_BACKUP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'data')
_BACKUP_FILE = os.path.join(_BACKUP_DIR, 'mbr_backup.json')
# 关键目录备份 (独立文件，避免 mbr_backup.json 过大)
_CRIT_BACKUP_FILE = os.path.join(_BACKUP_DIR, 'critical_dirs_snapshot.json')

# ---- 系统关键目录 (默认保护范围) ----
# 以 %WINDIR% / %SystemDrive% / %ProgramData% 等环境变量构造，
# 用户态兜底 + 内核级 minifilter 事前拒绝写入/删除/重命名。
# 允许使用环境变量 (os.path.expandvars)；不存在的目录在启动时静默跳过。
_DEFAULT_CRITICAL_DIRS: Tuple[str, ...] = (
    # 0. 内核驱动目录：Rootkit/bootkit 常替换磁盘驱动/网络驱动
    r'%WINDIR%\System32\drivers',
    # 1. 注册表配置单元 (HKLM\SYSTEM,SOFTWARE,SAM,SECURITY 原始文件)
    r'%WINDIR%\System32\config',
    # 2. EFI / BCD 引导配置
    r'%WINDIR%\Boot',
    # 3. 系统目录 (bootmgr, winload, ntdll, kernel32 等)
    r'%WINDIR%\System32',
    # 4. 组策略 (木马常篡改脚本启动项)
    r'%WINDIR%\System32\GroupPolicy',
    # 5. 计划任务目录 (常见持久化手段)
    r'%WINDIR%\System32\Tasks',
    # 6. 系统启动目录 (开始菜单→启动)
    r'%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp',
    # 7. 用户级启动目录 (木马常投放到所有用户启动项)
    r'%AppData%\Microsoft\Windows\Start Menu\Programs\Startup',
    # 8. 事件日志 (勒索软件会删除日志，防止溯源)
    r'%WINDIR%\System32\winevt\Logs',
    # 9. 系统 hosts 文件所在目录
    r'%WINDIR%\System32\drivers\etc',
)


# ---- 仅监控目录 (watch-only) ----
# 这些目录内容被 Windows 高频写入（事件日志/系统更新/临时文件），
# 做"内容级快照+自动恢复"必然造成误报刷屏，甚至误删正常文件。
# 因此只做"子目录新增"检测：不校验文件内容、不自动删除文件。
_DEFAULT_WATCH_ONLY_DIRS: Tuple[str, ...] = (
    r'%WINDIR%\System32',           # 高频变化：Windows 更新/缓存/临时文件
    r'%WINDIR%\System32\winevt\Logs',  # 事件日志：每时每刻都在写/删
    r'%WINDIR%\Boot',               # EFI 语言包/kd 调试驱动/CIPolicies 等由
    #   Windows 更新正常新增；严格内容快照会把系统更新误判为"新增文件"
    #   并尝试删除（删 Pascal EFI 引导文件会损坏系统）→ 只监控子目录+告警
    # 驱动运行时数据/ETW 追踪日志：RDP 显卡驱动等每时每刻都有写入
    # (DriverData\LogFiles\WMI\*.etl)，内容快照+恢复必然误报刷屏。
    # 注意：watch 判定用"最长前缀胜出"——System32 下嵌套的 config/drivers
    # 等严格目录不受影响；drivers 下再嵌套的 DriverData 则回到 watch 语义。
    r'%WINDIR%\System32\drivers\DriverData',
)

# ---- 注册表配置单元豁免 ----
# %WINDIR%\System32\config 内的注册表 hive (SYSTEM/SOFTWARE/SAM/...) 及其
# 事务日志由系统进程**持续写入**。若做"内容级快照+自动恢复"，必然：
#   1) 每轮轮询(1s)都产生 modified_file 事件 → 日志刷屏；
#   2) 把 hive 快照字节"原子写回" → 破坏正在运行的注册表，甚至损坏系统。
# 因此对 config 目录下的 hive / 事务日志文件**只做删除检测**，
# 不校验内容、不自动恢复；config 下的新增子目录/文件仍正常检测处置
# (mkdir System32\config\OSDATA 一类的攻击依旧会被拦截删除)。
_REG_CONFIG_DIR_MARK = os.sep.lower() + 'system32' + os.sep.lower() + 'config'
# Windows Defender 内核驱动目录 (%WINDIR%\System32\drivers\wd) 路径段标记。
# 该目录下 WdFilter.sys 等驱动受 WRP + ELAM 保护：PSLS 永远无写权限
# (字节恢复连 .psls_restore.tmp 都无法创建)，且由 Defender/系统更新正常
# 管理 → 同样只做删除检测，不校验内容、不自动恢复。
_DEFENDER_DRV_DIR_MARK = (os.sep.lower() + 'system32' + os.sep.lower()
                          + 'drivers' + os.sep.lower() + 'wd' + os.sep.lower())
# 任务计划程序目录 (%WINDIR%\System32\Tasks)：Windows 更新会正常刷新/
# 改写系统任务 XML (UpdateOrchestrator、Flighting 等) → 跳过内容校验与
# 自动恢复 (写回旧字节会破坏任务)；新增任务文件仍由 new_file 检测处置。
_REG_TASKS_DIR_MARK = (os.sep.lower() + 'system32' + os.sep.lower()
                       + 'tasks' + os.sep.lower())
# hive 主文件名 (无扩展名) 与相邻日志/事务文件后缀
_REG_HIVE_BASENAMES: Set[str] = {
    'system', 'software', 'sam', 'security', 'default',
    'drivers', 'bcd', 'components', 'elam',
}
_REG_HIVE_LOG_SUFFIXES: Tuple[str, ...] = ('.log1', '.log2', '.jrs')
# config 子树下持续被系统写入的数据库类文件 (SQLite 通知库等) → 内容不校验
_REG_DATA_FILE_SUFFIXES: Tuple[str, ...] = ('.db', '.db-wal', '.db-shm')
# TxR 事务日志特征 (Windows 更新时合并/清理，生命周期短，增删重建频繁)
_REG_TXR_LOG_MARKERS: Tuple[str, ...] = ('.txr.',)
_REG_TXR_LOG_SUFFIXES: Tuple[str, ...] = ('.regtrans-ms', '.blf')


def _is_registry_hive_file(path: str) -> bool:
    """判断文件是否属于注册表配置单元或其事务日志 (持续被系统写入)。

    命中规则：
      - 路径含 \\Config\\TxR\\ (注册表事务日志目录)
      - basename 无扩展名为已知 hive 名
      - 扩展名为 .log1 / .log2 / .jrs (hive 相邻日志)
      - 扩展名为 .db / .db-wal / .db-shm (config 下 SQLite 数据文件)
      - TxR 事务日志 (COMPONENTS{uid}.TxR.* / .regtrans-ms / .blf)
    """
    try:
        low = os.path.normcase(os.path.normpath(path))
    except Exception:
        return False
    if '\\txr\\' in low:
        return True
    name = os.path.basename(low)
    base, ext = os.path.splitext(name)
    if base in _REG_HIVE_BASENAMES or ext in _REG_HIVE_LOG_SUFFIXES:
        return True
    if ext in _REG_DATA_FILE_SUFFIXES:
        return True
    return _is_registry_txr_log(path)


def _is_registry_txr_log(path: str) -> bool:
    """是否注册表事务日志 (TxR)：Windows 更新时持续合并/清理、增删重建。

    命中规则：
      - 路径含 \\Config\\TxR\\
      - basename 含 '.TxR.' 片段 (如 COMPONENTS{53b39e62-...}.TxR.0.regtrans-ms)
      - 后缀 .regtrans-ms / .blf

    → 完全豁免：内容不校验、删除不告警、新增不处置 (生命周期短，删除/
      重建是 Windows 正常行为，告警只会刷屏)。
    """
    try:
        low = os.path.normcase(os.path.normpath(path))
    except Exception:
        return False
    if '\\txr\\' in low:
        return True
    name = os.path.basename(low)
    for mk in _REG_TXR_LOG_MARKERS:
        if mk in name:
            return True
    return name.endswith(_REG_TXR_LOG_SUFFIXES)


def _is_system_tasks_file(path: str) -> bool:
    """是否位于 %WINDIR%\\System32\\Tasks 下 (任务计划程序管理的任务文件)。

    Windows 更新会正常刷新/改写系统任务 XML (可执行目录下诸如
    UpdateOrchestrator\\Schedule Wake To Work、Flighting\\OneSettings) →
    跳过内容校验与自动恢复 (写回旧快照字节会破坏任务)；新增任务文件仍由
    new_file 检测处置，删除任务仍告警。
    """
    try:
        low = os.path.normcase(os.path.normpath(path))
    except Exception:
        return False
    return _REG_TASKS_DIR_MARK in low


def _is_system_tasks_churn_file(path: str) -> bool:
    """System32\\Tasks 下由 Windows 更新正常增删/重建的任务计划文件。

    Windows 更新在更新落地期成对删除/重建 SoftLanding 系列任务
    (SoftLandingDeferralTask-{guid}、SoftLandingTriggerTask-...-render-{guid})：
    删除被视为"篡改"后自动恢复必失败 (任务文件受系统管理/锁定)，且每轮
    轮询重复产生 CRITICAL"处置失败"刷屏 (曾连续 3 条) → 完全豁免：
    删除不告警、新增不处置，与 TxR 事务日志同级。其余 System32\\Tasks
    任务文件的删除检测保持不变。
    """
    try:
        low = os.path.normcase(os.path.normpath(path))
    except Exception:
        return False
    if _REG_TASKS_DIR_MARK not in low:
        return False
    # SoftLanding 前缀 (Windows Update 更新落地任务)；name 已 normcase 小写
    return 'softlanding' in os.path.basename(low)


def _is_psls_own_task_file(path: str) -> bool:
    """是否 PSLS 自身计划任务文件 (%WINDIR%\\System32\\Tasks\\PSLS)。

    autostart_manager 启用开机自启时会在 System32\\Tasks 下创建计划任务
    \\PSLS (登录触发 + 最高权限)。关键目录防护曾把该刚创建的任务文件当
    "未知新增文件"直接删除，导致开机自启在本次启动后即失效 (截图: 
    CRITICAL 关键目录篡改 new_file×1 System32\\Tasks\\PSLS + 已自动处置) →
    完全豁免：不产生 new_file 事件、不自动删除。若任务内容被恶意改写，
    由 System32\\Tasks 自身的文件删除/内容比对检测兜底。
    """
    try:
        low = os.path.normcase(os.path.normpath(path))
    except Exception:
        return False
    if _REG_TASKS_DIR_MARK not in low:
        return False
    # basename 已 normcase 小写
    return low.endswith(os.sep.lower() + 'psls')


def _is_defender_driver_file(path: str) -> bool:
    """是否位于 %WINDIR%\\System32\\drivers\\wd 下 (Windows Defender 内核驱动目录)。

    WdFilter.sys 等驱动由 Defender/系统更新受 WRP + ELAM 保护管理：PSLS
    无写权限，字节恢复必失败（连临时文件都无法创建）。→ 跳过内容校验与
    自动恢复，仅保留删除检测，避免每次启动/轮询的恢复失败刷屏与 sfc 空转。
    """
    try:
        low = os.path.normcase(os.path.normpath(path))
    except Exception:
        return False
    return _DEFENDER_DRV_DIR_MARK in low


def _is_psls_driver_file(path: str) -> bool:
    """是否 PSLS 自身内核驱动文件 (PSLS.sys)。

    驱动加载/安装会把驱动文件写入 System32\\drivers 等受保护目录。关键目录
    防护曾把 System32\\drivers\\PSLS.sys 当"未知新增文件"直接删除，导致驱动
    加载失败。→ 完全豁免：不产生 new_file 事件、不自动删除、不恢复内容。
    """
    try:
        base = os.path.basename(path).lower()
    except Exception:
        return False
    return base == 'psls.sys'


# ---- 受信签名驱动白名单 (关键目录驱动区降噪) ----
# System32\drivers 与 DriverStore 是显卡/声卡/主板/网络等硬件厂商
# (NVIDIA/AMD/Intel/Realtek...) 驱动更新的落地区。厂商更新会改写 .sys/.inf
# 并新增文件：若按快照"内容校验 + 自动恢复"，每装/更新一次驱动必然误报
# CRITICAL 且写回旧字节破坏驱动。但**不能无条件放行**——BYOVD / 卸载重投
# 等攻击也往这里落无签名/伪造驱动。因此只放行"带有效 Authenticode 签名"
# 的驱动/INF：签名有效 ⇒ 厂商正规更新；未签名/签名无效 ⇒ 仍严格校验拦截。
_TRUSTED_DRV_REGION_MARKS: Tuple[str, ...] = (
    os.sep.lower() + 'system32' + os.sep.lower() + 'drivers',
    os.sep.lower() + 'system32' + os.sep.lower() + 'driverstore',
)
_TRUSTED_DRV_EXTS: Tuple[str, ...] = ('.sys', '.inf', '.dll', '.exe', '.dat', '.pdb')
_trusted_driver_verifier: Optional[object] = None


def _is_trusted_signed_driver_file(path: str) -> bool:
    """驱动区 (System32\\drivers / DriverStore) 下带有效 Authenticode 签名的文件。"""
    try:
        low = os.path.normcase(os.path.normpath(path))
    except Exception:
        return False
    if not any(m in low for m in _TRUSTED_DRV_REGION_MARKS):
        return False
    base = os.path.basename(low)
    if not base.endswith(_TRUSTED_DRV_EXTS):
        return False
    if not os.path.isfile(path):
        return False
    global _trusted_driver_verifier
    if _trusted_driver_verifier is None:
        try:
            from utils.signature_verifier import SignatureVerifier
            _trusted_driver_verifier = SignatureVerifier()
        except Exception:
            _trusted_driver_verifier = False
    if not _trusted_driver_verifier:
        return False
    try:
        return bool(_trusted_driver_verifier.is_signed(path))
    except Exception:
        return False


# 系统运行时目录标记 (normcase + os.sep 开头，匹配路径段前缀)
# 这些目录由 Windows 自身/系统服务频繁创建、清理、重建，生命周期短且
# 变化是正常行为 → 完全豁免 (不产生 new_dir/new_file 事件)，避免每
# 次系统操作都触发 CRITICAL 通知刷屏。
_SYSTEM_RUNTIME_DIR_MARKS: Tuple[str, ...] = (
    # Print Spooler 打印驱动临时目录: 每个 V4 驱动一个 UUID 子目录，
    # 驱动更新时新建/删除频繁 (如 V4Dirs\{D020A8A8-...})
    os.sep.lower() + 'spool' + os.sep.lower() + 'v4dirs',
    # Windows Update 缓存: 下载、解包、清理周期循环
    os.sep.lower() + 'softwaredistribution',
    # 安装程序补丁缓存: 应用补丁时创建，清理时删除
    os.sep.lower() + 'installer' + os.sep.lower() + '$patchcache$',
    # Windows Installer 临时目录: MSI 安装时临时文件
    os.sep.lower() + 'installer' + os.sep.lower() + '$msiextract',
    # Delivery Optimization P2P 更新缓存
    os.sep.lower() + 'deliveryoptimization',
    # SYSTEM 账户用户配置目录 (System32\config\systemprofile)：
    # 其中 AppData 下 Xbox Live 状态缓存、Microsoft Edge 数据等由系统组件
    # 频繁清理/重建，基线中任何"缓存文件被删除"都是正常系统行为
    os.sep.lower() + 'system32' + os.sep.lower() + 'config' + os.sep.lower() + 'systemprofile',
)


def _is_system_runtime_dir(path: str) -> bool:
    """是否位于系统运行时目录下 (Windows 自身/服务正常创建清理，非篡改)。

    命中后 → 完全豁免 new_dir/new_file 事件，避免正常系统操作触发
    CRITICAL 通知刷屏。

    标记路径段以 os.sep 开头，保证完整路径段匹配（不会误匹配如
    `fooV4Dirsbar` 这类情况）。
    """
    try:
        low = os.path.normcase(os.path.normpath(path))
    except Exception:
        return False
    return any(m in low for m in _SYSTEM_RUNTIME_DIR_MARKS)


class _CriticalDirSnapshot:
    """关键目录文件快照 + 篡改判定 + 自动处置。

    内部采用 sha256(size+mtime) 两层：
    - 快速扫描：只比对 size + mtime，不变直接信任 (I/O 最小)
    - 慢速扫描：size/mtime 变化 → 读文件内容计算 sha256，与快照比较
    - 新增未知文件：关键目录下出现快照中没有的文件，按配置上报+隔离
    - 新增未知子目录：用于拦截 `mkdir 关键目录\新目录`（如 config\OSDATA），
      默认对严格目录删除（仅空目录），对 watch-only 目录节流后上报
    - 删除文件：快照存在但文件不存在，按配置上报+不自动恢复
      (删除比篡改影响更大，但用户态恢复系统文件可能触发 Windows WRP
      拒绝写入 → 仅发送严重告警)

    watch-only 目录（System32 / winevt\Logs 等高频目录）：
    - 不做文件内容校验，不保留文件字节，不自动恢复文件
    - 仅对比"子目录集合"以发现新创建的目录，且轮询节流 (默认 5s)，
      避免高频目录把 CPU/I/O 打满

    单目录最大文件数限制 (避免关键目录误设置成 System32 导致扫描开销过大)：
    - 默认每个关键目录最多只缓存前 4096 个文件 (按路径排序)，超出仅记录
      "超出阈值" 标记，不做完整性校验，只做未知文件检测。
    """

    MAX_FILES_PER_DIR = 4096
    # 快照时立即计算内容 hash 的最大文件大小 (字节)；超过此阈值改为只读 size+mtime
    # —— 首次发现 size/mtime 变化时再计算 hash，并把当时读出来的 hash 视为"旧基线"
    # （快照→首次变化这段窗口内若被篡改，无法识别，所以 MAX 取 10MB 保证覆盖
    #  hosts/驱动 sys/组策略/scripts 等绝大多数关键文件）
    MAX_HASH_BYTES = 10 * 1024 * 1024
    # watch-only 目录的子目录集合检查间隔 (秒)，防止 System32 等高频目录每秒全量扫描
    WATCH_DIR_CHECK_INTERVAL = 5.0

    def __init__(self):
        # dir_path -> { 'file_rel_path': { 'sha256': .., 'size': int, 'mtime': float } }
        self._store: Dict[str, Dict[str, dict]] = {}
        # dir_path -> bool: 是否超出单目录阈值 (True=只做未知文件检测)
        self._overflow: Dict[str, bool] = {}
        # dir_path -> Set[sub_dir_abs_path]: 递归子目录集合 (拦截 mkdir 新增目录)
        self._dir_store: Dict[str, Set[str]] = {}
        # dir_path -> float: 上次目录集合比对时间 (watch-only 节流)
        self._last_dir_check: Dict[str, float] = {}
        # full_path -> float: new_file 上次删除失败时间 (30s 节流，防每轮重试刷屏)
        self._last_del_fail: Dict[str, float] = {}
        # full_path: new_file 连续 30s 节流窗口外仍删除失败 (进程句柄锁/
        # 权限不足) → 永久放弃该文件的新增处置，仅保留删除检测 (攻击者把
        # 它删了也能感知)。若后续文件 size/mtime 变化 (删了又 drop 同名
        # 新文件)，会自动移出 giveup 重新产生 new_file 事件。
        self._newfile_giveup: Set[str] = set()
        # full_path -> (size, mtime_ns): 与 _newfile_giveup 配套的文件指纹。
        # 用于 check() 判断 giveup 的文件是否被替换成了另一个同名文件。
        self._newfile_giveup_sig: Dict[str, tuple] = {}
        # full_path -> float: modified 上次恢复失败时间 (30s 节流)
        self._last_restore_fail: Dict[str, float] = {}
        # full_path: 节流窗口外仍恢复失败 (如 Windows Defender 驱动由系统
        # 更新/ELAM 保护，PSLS 永远无写权限) → 放弃内容恢复，仅保留删除检测
        self._restore_giveup: Set[str] = set()
        self._lock = threading.RLock()

    # ---------- 工具 ----------
    @staticmethod
    def _hash_file(path: str, chunk: int = 65536) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                while True:
                    b = f.read(chunk)
                    if not b:
                        break
                    h.update(b)
            return h.hexdigest()
        except Exception:
            return None

    @staticmethod
    def _stat_file(path: str) -> Optional[tuple]:
        try:
            st = os.stat(path)
            return (st.st_size, st.st_mtime_ns)
        except Exception:
            return None

    @staticmethod
    def _iter_dir(dir_path: str, max_files: int):
        """BFS 遍历 dir_path 下所有常规文件，产出绝对路径列表。

        遇到 junction / 符号链接跳过，防止绕出关键目录。
        """
        out: List[str] = []
        stack = [dir_path]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                out.append(entry.path)
                                if len(out) >= max_files:
                                    return out
                        except Exception:
                            continue
            except Exception:
                continue
        return out

    def _is_driver_package_dir(self, path: str) -> bool:
        """是否为驱动仓库/驱动区下的驱动包目录。

        DriverStore\\FileRepository（amdacpbt.inf_amd64_* 等）与 System32\\drivers
        是硬件驱动更新的落地存放区，目录本身是厂商包（内部 .sys/.inf 走签名/
        内容校验），新建目录属正常 churn 而非威胁。用于关键目录保护 new_dir
        事件豁免，避免隔离化 WebView2/驱动更新触发的批量 new_dir CRITICAL 刷屏。
        """
        try:
            low = os.path.normcase(os.path.normpath(path))
        except Exception:
            return False
        # 只认"仓库子目录"：DriverStore\FileRepository 下的包目录
        repo_mark = os.sep.lower() + 'filerepository' + os.sep.lower()
        return repo_mark in low or any(m in low for m in _TRUSTED_DRV_REGION_MARKS)

    @staticmethod
    def _skip_content_check(d: str, full: str) -> bool:
        """是否跳过文件内容校验 (仅做删除检测)。

        三类由系统持续管理、内容校验 + 自动恢复必然刷屏甚至破坏系统的文件：
        1) %WINDIR%\\System32\\drivers\\wd 下的 Windows Defender 内核驱动
           (WRP + ELAM 保护，PSLS 无写权限，字节恢复必失败)；
        2) %WINDIR%\\System32\\Tasks 下的任务文件 (Windows 更新正常改写，
           写回旧字节会破坏任务，新增/删除仍正常检测)；
        3) 注册表 config 目录下的 hive / 事务日志 / SQLite 数据文件。

        另：PSLS 自身驱动 (PSLS.sys) 每次启动/更新会被驱动加载器重写
        (版本更新、签名刷新)，且文件受系统保护无法字节写回。若纳入内容
        校验 → 每次启动判 modified → 恢复失败报 CRITICAL + 调 sfc + 把
        自己的 .psls_restore.tmp 当未知新增删除 (日志反复出现)。→ 跳过
        内容校验，仅保留删除检测；新装/升级署入的 PSLS.sys 也不会被
        当作"新增未知文件"处置。
        """
        if _is_defender_driver_file(full):
            return True
        if _is_psls_driver_file(full):
            return True
        if _is_system_tasks_file(full):
            return True
        # 受信签名驱动：驱动区 (System32\drivers / DriverStore) 下带有效
        # Authenticode 签名的驱动/INF 由厂商更新正常改写 → 跳过内容校验与
        # 自动恢复 (写回旧字节会破坏驱动)，仅保留删除检测；未签名(如 BYOVD/
        # 伪装驱动) 不豁免，仍严格校验拦截。
        if _is_trusted_signed_driver_file(full):
            return True
        try:
            nd = os.path.normcase(os.path.normpath(d))
        except Exception:
            return False
        return nd.endswith(_REG_CONFIG_DIR_MARK) and _is_registry_hive_file(full)

    @staticmethod
    def _path_region(full: str, watch_list, crit_list) -> Optional[str]:
        """分层判定路径所属保护区域（最长前缀胜出）：

        - 'watch'：位于某个 watch-only 目录子树内 → 跳过内容校验/不自动删
        - 'critical'：位于某个严格关键目录子树内 → 正常校验/处置
        - None：两区之外

        watch 与 critical 会嵌套（System32 是 watch、其下 drivers/config 又是
        critical、drivers 下 DriverData 又是 watch）。以"最具体(最长)前缀"为准，
        使 DriverData 下的驱动 ETW 日志 (`DriverData\LogFiles\WMI\*.etl`)
        不再被 drivers 的内容校验误报，同时 config 的严格语义不受 System32
        watch 前缀影响。
        """
        try:
            f = os.path.normcase(os.path.normpath(full))
        except Exception:
            return None
        best: Optional[str] = None
        best_len = -1
        for w in watch_list or []:
            try:
                wn = os.path.normcase(os.path.normpath(w))
            except Exception:
                continue
            if f == wn or f.startswith(wn + os.sep):
                if len(wn) > best_len:
                    best, best_len = 'watch', len(wn)
        for c in crit_list or []:
            try:
                cn = os.path.normcase(os.path.normpath(c))
            except Exception:
                continue
            if f == cn or f.startswith(cn + os.sep):
                if len(cn) > best_len:
                    best, best_len = 'critical', len(cn)
        return best

    @classmethod
    def _iter_dirs(cls, dir_path: str) -> Set[str]:
        """递归收集 dir_path 下所有子目录的绝对路径（含各级），排除符号链接。

        用于检测"新增子目录"（如 `mkdir C:\Windows\System32\config\OSDATA`），
        这是文件快照无法覆盖的破坏行为。
        """
        out: Set[str] = set()
        stack = [dir_path]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                out.add(entry.path)
                                stack.append(entry.path)
                        except Exception:
                            continue
            except Exception:
                continue
        return out

    # ---------- 快照 ----------
    def snapshot(self, dirs: List[str], watch_dirs: Optional[List[str]] = None) -> int:
        """为一组展开后的目录重建快照。返回已快照的文件总数。

        watch_dirs: 高频变化目录集合。这些目录不做文件内容快照，
        仅记录"子目录集合"，用于检测新增子目录 (mkdir 拦截)。
        """
        watch = set(os.path.normcase(os.path.normpath(w))
                    for w in (watch_dirs or []) if w)
        total = 0
        new_store: Dict[str, Dict[str, dict]] = {}
        new_overflow: Dict[str, bool] = {}
        new_dir_store: Dict[str, Set[str]] = {}
        for d in dirs:
            if not d or not os.path.isdir(d):
                continue
            nd = os.path.normcase(os.path.normpath(d))
            # watch-only 目录：只记录子目录集合，不缓存文件字节（避免启动 I/O 过大）
            if nd in watch:
                new_store[d] = {}
                new_overflow[d] = False
                new_dir_store[d] = self._iter_dirs(d)
                continue
            files = self._iter_dir(d, self.MAX_FILES_PER_DIR * 2)
            # 分层豁免：嵌套在 watch-only 子树下的文件不缓存内容
            # (如 drivers\DriverData\LogFiles\WMI\*.etl 驱动 ETW 日志)，
            # 否则 check 每轮都会把持续写入误判为篡改
            files = [f for f in files
                     if self._path_region(f, watch_dirs, dirs) != 'watch']
            overflow = len(files) > self.MAX_FILES_PER_DIR
            files_sorted = sorted(files)[:self.MAX_FILES_PER_DIR]
            table: Dict[str, dict] = {}
            for full in files_sorted:
                st = self._stat_file(full)
                if st is None:
                    continue
                # 注册表 hive/事务日志：不读字节 (内容持续变化, 校验被 check 跳过),
                # 只留 size+mtime 供"删除检测"与基线比对使用
                skip_content = self._skip_content_check(d, full)
                # 快照阶段：≤10MB 的文件既计算 sha256 又保留原始字节（用于篡改后直接写回），
                # 避免 sfc 只处理系统保护文件、不处理用户自定义关键目录文件的问题。
                if not skip_content and st[0] <= self.MAX_HASH_BYTES:
                    try:
                        with open(full, 'rb') as f:
                            data = f.read()
                    except Exception:
                        data = None
                    if data is not None:
                        h = hashlib.sha256(data).hexdigest()
                        table[full] = {
                            'size': st[0],
                            'mtime': st[1],
                            'sha256': h,
                            'data': data,   # 仅 ≤10MB 保留字节
                        }
                        total += 1
                        continue
                    # 读失败：降级为只留 size/mtime
                # >10MB 或读取失败：只留 size+mtime (modified 时通过 sfc/删除处置)
                table[full] = {
                    'size': st[0],
                    'mtime': st[1],
                    'sha256': None,
                    'data': None,
                }
                total += 1
            new_store[d] = table
            new_overflow[d] = overflow
            new_dir_store[d] = self._iter_dirs(d)
            if overflow:
                logger.warning(f'关键目录 "{d}" 超过单目录阈值 '
                               f'({self.MAX_FILES_PER_DIR}), 仅做未知文件检测')
        with self._lock:
            self._store = new_store
            self._overflow = new_overflow
            self._dir_store = new_dir_store
            self._last_dir_check = {d: 0.0 for d in new_dir_store}
        return total

    # ---------- 校验 ----------
    def check(self, dirs: List[str], watch_dirs: Optional[List[str]] = None) -> List[dict]:
        """校验一组展开后的目录，返回篡改事件列表。

        watch_dirs: 高频变化目录。只做子目录集合比对 (带节流)，不校验文件内容，
        不产生 new_file / modified_file 事件，避免 System32/winevt\Logs 刷屏。
        """
        events: List[dict] = []
        watch = set(os.path.normcase(os.path.normpath(w))
                    for w in (watch_dirs or []) if w)
        now = time.time()
        with self._lock:
            store_copy = {k: dict(v) for k, v in self._store.items()}
            overflow_copy = dict(self._overflow)
            dir_store_copy = {k: (set(v) if v is not None else None)
                              for k, v in self._dir_store.items()}
            last_dir_check = dict(self._last_dir_check)
            # giveup/失败表的快照，check 过程中遍历 current_files 时对比用
            newfile_giveup_snapshot = set(self._newfile_giveup)
            restore_giveup_snapshot = set(self._restore_giveup)
            last_del_fail_snapshot = dict(self._last_del_fail)
            last_restore_fail_snapshot = dict(self._last_restore_fail)
        for d in dirs:
            if not d or not os.path.isdir(d):
                continue
            nd = os.path.normcase(os.path.normpath(d))
            is_watch = nd in watch

            # --- 子目录集合比对 (拦截 mkdir 新增关键子目录) ---
            # 每轮都对比成本高 (System32 递归扫描)；watch 目录节流到 5s 一次。
            last_check = last_dir_check.get(d, 0.0)
            do_dir_check = (not is_watch) or (now - last_check >= self.WATCH_DIR_CHECK_INTERVAL)
            if do_dir_check:
                old_dirs = dir_store_copy.get(d)
                cur_dirs = self._iter_dirs(d)
                if old_dirs is not None:
                    for added in sorted(cur_dirs - old_dirs):
                        # 系统运行时目录 (Print Spooler V4Dirs / Windows Update
                        # 缓存 / Delivery Optimization 等) 由 Windows 自身
                        # 正常创建清理 → 完全豁免，不产生 new_dir 事件
                        if _is_system_runtime_dir(added):
                            continue
                        # 驱动区 (DriverStore\FileRepository / System32\drivers) 的
                        # 驱动包目录：厂商/驱动更新时新建 (如 amdacpbt.inf_amd64_*×63)，
                        # 是正常 churn 而非威胁 → 完全豁免 new_dir，不产生事件。
                        # [底层 .sys/.inf 文件仍在严格文件级校验链条中，bypass 需过
                        # 签名/内容校验，不因目录豁免而放行]
                        if self._is_driver_package_dir(added):
                            continue
                        # watch 语义按新增目录自身 region 判定：
                        # watch-only 树下的新目录 (如 DriverData\NewSession)
                        # 仅上报不自动删除；严格目录 (config\OSDATA) 才删除。
                        added_watch = is_watch or (
                            self._path_region(added, watch_dirs, dirs) == 'watch')
                        events.append({
                            'type': 'critical_dir',
                            'device': d,
                            'label': d,
                            'change_kind': 'new_dir',
                            'file': added,
                            'watch': added_watch,
                            'backup_hash': None,
                            'current_hash': None,
                            'timestamp': now,
                        })
                with self._lock:
                    self._last_dir_check[d] = now
                    if d in self._dir_store:
                        self._dir_store[d] = cur_dirs
                    else:
                        self._dir_store[d] = cur_dirs

            # watch-only 目录：文件内容不校验（高频变化，误报根源）
            if is_watch:
                continue

            # --- 严格目录：文件级校验 (原有逻辑) ---
            table = store_copy.get(d) or {}
            overflow = overflow_copy.get(d, False)
            current_files = self._iter_dir(d, self.MAX_FILES_PER_DIR * 2)
            current_set = set(current_files)

            # 1) 已快照的文件 → 看是否被修改或删除
            for full, meta in table.items():
                # PSLS 自身驱动 (System32\drivers\PSLS.sys)：驱动更新/重装会
                # 覆盖写 System32\drivers，卸载/替换瞬间会短暂"消失"。快照里
                # 一旦 PSLS.sys 落库，后续更新走 modified_file → 会触发"恢复
                # 备份"(覆盖新版为旧版) / deleted_file → 误报删除。这与 new_file
                # 分支的豁免意图一致（注释 `_is_psls_driver_file`：完全豁免，不
                # 产生事件、不自动删除、不恢复内容），故此处同样豁免。
                if _is_psls_driver_file(full):
                    continue
                # 分层豁免：嵌套在 watch-only 子树下的文件不校验内容
                # (e.g. drivers\DriverData 下驱动 ETW 日志持续写入)
                if self._path_region(full, watch_dirs, dirs) == 'watch':
                    continue
                # 注册表事务日志 (TxR)：Windows 更新合并/清理时正常增删重建
                # (如 COMPONENTS{uid}.TxR.*.regtrans-ms) → 完全豁免，删除不告警
                if _is_registry_txr_log(full):
                    continue
                # 系统运行时目录 (Print Spooler V4Dirs / config\systemprofile /
                # Update 缓存等)：Windows 自身/服务正常清理重建 → 完全豁免
                if _is_system_runtime_dir(full):
                    continue
                # System32\Tasks 下 Windows 更新任务 (SoftLanding 系列)：
                # 正常删除/重建，不作为篡改告警 (恢复必失败且刷屏)
                if _is_system_tasks_churn_file(full):
                    continue
                if full not in current_set:
                    events.append({
                        'type': 'critical_dir',
                        'device': d,
                        'label': d,
                        'change_kind': 'deleted_file',
                        'file': full,
                        'backup_hash': meta.get('sha256'),
                        'current_hash': None,
                        'timestamp': time.time(),
                    })
                    continue
                # 注册表 hive/事务日志 (config 目录)：内容持续写入，仅保留
                # 上面的"删除检测"，跳过内容比对与自动恢复，避免刷屏/损坏系统
                if self._skip_content_check(d, full):
                    continue
                st = self._stat_file(full)
                if st is None:
                    continue
                old_size = meta.get('size')
                old_mtime = meta.get('mtime')
                if st[0] == old_size and st[1] == old_mtime:
                    continue
                # size/mtime 变化 → 读内容比对
                cur_hash = self._hash_file(full)
                old_hash = meta.get('sha256')
                if old_hash is None:
                    # 首次碰到变化：把旧内容也哈希一下（只能重新读当前内容，
                    # 快照阶段没存内容 → 把当前 hash 作为"新状态"再下一
                    # 轮才知道变化。但为了不误报，这里写入快照，下次再
                    # 碰到变化才告警）
                    with self._lock:
                        tbl = self._store.get(d)
                        if tbl is not None and full in tbl:
                            tbl[full]['sha256'] = cur_hash
                    continue
                if cur_hash != old_hash:
                    # 已放弃内容恢复的文件（受系统保护/锁定持续写回失败）：
                    # 不再产生 modified 事件，仅保留上面的删除检测，避免刷屏
                    with self._lock:
                        if full in self._restore_giveup:
                            continue
                    events.append({
                        'type': 'critical_dir',
                        'device': d,
                        'label': d,
                        'change_kind': 'modified_file',
                        'file': full,
                        'backup_hash': old_hash,
                        'current_hash': cur_hash,
                        'timestamp': time.time(),
                    })

            # 2) 当前文件中快照里没有的 → 新增未知文件
            for full in current_files:
                # 受信签名驱动：驱动安装/更新新增的有效签名 .sys/.inf 落到
                # 驱动区，是厂商正规更新 → 不作未知新增处置（避免误删驱动）
                if _is_trusted_signed_driver_file(full):
                    continue
                # PSLS 自身驱动文件 (PSLS.sys)：驱动安装/加载会落到受保护
                # 目录，绝不能当未知新增文件删除/告警（曾误删导致驱动加载失败）
                if _is_psls_driver_file(full):
                    continue
                # PSLS 自身计划任务 (System32\Tasks\PSLS)：开机自启时由
                # autostart_manager 创建，绝不能当未知新增文件删除
                # （曾把自启任务删掉，本次启动后开机自启即失效）
                if _is_psls_own_task_file(full):
                    continue
                # 分层豁免：watch-only 子树下新增的文件 (驱动日志/临时文件)
                # 不做 new_file 处置（不自动删除）
                if self._path_region(full, watch_dirs, dirs) == 'watch':
                    continue
                # TxR 事务日志：Windows 会新建/重建 (更新合并)，不做 new_file
                # 处置，避免把刚重建的系统事务日志当新增文件删除
                if _is_registry_txr_log(full):
                    continue
                # 系统运行时目录下的文件 (Print Spooler / Update 缓存等)
                # 完全豁免，不做 new_file 处置
                if _is_system_runtime_dir(full):
                    continue
                # System32\Tasks 下 Windows 更新任务 (SoftLanding 系列)：
                # 更新期正常重建，不作为新增文件处置
                if _is_system_tasks_churn_file(full):
                    continue
                if table and full in table:
                    continue
                # giveup 跳过：new_file 之前删不掉而被 giveup 后，默认不再
                # 产生事件（避免每 30s 刷一条 CRITICAL "处置失败"）。
                # 但若文件 size/mtime 变了（攻击者删了旧文件又 drop 了同
                # 名新文件），自动移出 giveup 重新产生事件——这个新文件
                # 与之前删不掉的不是同一个，可能能删掉。
                if full in newfile_giveup_snapshot:
                    try:
                        cur_st = os.stat(full)
                        st_sig = (cur_st.st_size, cur_st.st_mtime_ns)
                        prev_sig = self._newfile_giveup_sig.get(full)
                        if prev_sig is None or prev_sig == st_sig:
                            # 首次 giveup / 指纹相同 → 同一个删不掉的文件，跳过
                            if prev_sig is None:
                                with self._lock:
                                    self._newfile_giveup_sig[full] = st_sig
                            continue
                        # 文件被换过了 → 移出 giveup，重新产生事件
                        with self._lock:
                            self._newfile_giveup.discard(full)
                            self._last_del_fail.pop(full, None)
                            self._newfile_giveup_sig.pop(full, None)
                            logger.info(
                                f'[关键目录防护] new_file giveup 文件被替换, '
                                f'重新产生事件: {full}')
                    except OSError:
                        # 文件已消失（成功删掉 / 攻击者删了），直接清理并跳过
                        with self._lock:
                            self._newfile_giveup.discard(full)
                            self._last_del_fail.pop(full, None)
                            self._newfile_giveup_sig.pop(full, None)
                        continue
                events.append({
                    'type': 'critical_dir',
                    'device': d,
                    'label': d,
                    'change_kind': 'new_file',
                    'file': full,
                    'backup_hash': None,
                    'current_hash': self._hash_file(full),
                    'timestamp': time.time(),
                })
        return events

    # ---------- 处置 ----------
    def _drop_dir_from_baseline(self, dir_path: str, full_path: str):
        """从子目录集合基线中移除已处置目录 (及全部子级)。

        新增目录被删除后若不更新基线，攻击者重新创建同名目录不会再次
        触发 new_dir 检测 → 变为"一次防御、之后默认放行"。
        """
        try:
            with self._lock:
                base = self._dir_store.get(dir_path)
                if base is None:
                    return
                fp_norm = os.path.normcase(os.path.normpath(full_path))
                drop = set()
                for d in base:
                    try:
                        dn = os.path.normcase(os.path.normpath(d))
                    except Exception:
                        continue
                    if dn == fp_norm or dn.startswith(fp_norm + os.sep):
                        drop.add(d)
                if drop:
                    base.difference_update(drop)
        except Exception as e:
            logger.warning(f'[关键目录防护] 更新目录基线异常: {e}')

    def restore_file(self, dir_path: str, full_path: str, watch: bool = False) -> bool:
        """自动恢复被篡改的文件/目录:
            - new_dir:
                * watch=True (watch-only 目录, 如 System32)：只告警不自动删除——
                  Windows 更新/缓存正常创建临时目录时删除会导致系统异常。
                * watch=False (严格目录, 如 System32\\config)：先删除空目录，
                  非空时递归删除 (真正防住 `mkdir config\OSDATA` 类攻击)。
            - new_file: 直接删除。
            - modified_file:
                1) 若快照中已保留原始字节 (≤10MB): 直接原子写回（比 sfc 快、覆盖自定义关键目录）
                2) 否则（大文件或无字节备份）：调用 sfc.exe 触发 Windows 自身修复，
                   失败则删除被篡改文件避免被执行。
        """
        import subprocess as _sp
        # PSLS 自身驱动 (System32\drivers\PSLS.sys)：彻底豁免——绝不恢复内容、
        # 绝不删除。驱动更新会覆盖/替换该文件，任何恢复/删除都会破坏自身驱动
        # 加载。check() 已豁免，此处为兜底（防御性双保险，防其他路径误调）。
        if _is_psls_driver_file(full_path):
            return False
        kind = None
        with self._lock:
            table = self._store.get(dir_path)
            meta = dict(table.get(full_path)) if table and full_path in table else None
            if not os.path.exists(full_path):
                return False
            if os.path.isdir(full_path):
                kind = 'new_dir'
            elif meta is None:
                kind = 'new_file'
            else:
                kind = 'modified_file'
        # 新增未知目录 (拦截 mkdir)
        if kind == 'new_dir':
            # 系统运行时目录 (Print Spooler V4Dirs / Update 缓存等)：完全豁免，
            # 既不告警也不删除，让 Windows 正常清理
            if _is_system_runtime_dir(full_path):
                logger.info(f'[关键目录防护] 系统运行时目录, 完全豁免: {full_path}')
                return False
            if watch:
                # watch-only 目录 (System32/winevt\Logs 等)：Windows 高频创建
                # 临时/更新目录，误删可能破坏系统 → 只告警不自动删除
                logger.info(f'[关键目录防护] watch 目录新增子目录, 仅上报不删除: {full_path}')
                return False
            try:
                os.rmdir(full_path)  # 空目录直接删
                logger.warning(f'[关键目录防护] 已移除关键目录下新增目录: {full_path}')
                self._drop_dir_from_baseline(dir_path, full_path)
                return True
            except OSError:
                pass
            # 非空目录 (如 OSDATA 创建后被立即写入文件)：
            # 新增目录判定来自快照基线比对，误删正常目录风险低，递归删除以真正防住攻击
            try:
                import shutil
                shutil.rmtree(full_path)
                logger.warning(f'[关键目录防护] 已递归删除关键目录下新增目录: {full_path}')
                self._drop_dir_from_baseline(dir_path, full_path)
                return True
            except Exception as e:
                logger.warning(f'[关键目录防护] 删除新增目录失败 {full_path}: {e}')
                return False
        # 新增未知文件：直接删除（删除失败 30s 节流，避免每轮 check 重复
        # 尝试删同一批权限不足的系统文件 → 日志刷屏；节流窗口外仍失败
        # 标记 giveup 永久放弃，仅保留删除检测，不再产生事件）
        if kind == 'new_file':
            # PSLS 自身驱动文件 (PSLS.sys)：绝不自动删除（防御性，双保险，
            # check() 已豁免，此处防止其他路径误调）
            if _is_psls_driver_file(full_path):
                return False
            # PSLS 自身计划任务 (System32\Tasks\PSLS)：绝不自动删除（同上，
            # 双保险，防止其他路径误调把自启任务删掉）
            if _is_psls_own_task_file(full_path):
                return False
            # 已 giveup 的文件直接跳过（避免反复尝试删除同一个肯定删不掉的文件）
            with self._lock:
                if full_path in self._newfile_giveup:
                    return False
            now = time.time()
            with self._lock:
                last_fail = self._last_del_fail.get(full_path, 0.0)
                in_throttle = now - last_fail < _RETRY_INTERVAL
            if in_throttle:
                return False
            try:
                os.remove(full_path)
                logger.warning(f'[关键目录防护] 删除关键目录下未知新增文件: {full_path}')
                # 删除成功 → 清理所有 giveup/失败痕迹 + 指纹
                with self._lock:
                    self._last_del_fail.pop(full_path, None)
                    self._newfile_giveup.discard(full_path)
                    self._newfile_giveup_sig.pop(full_path, None)
                return True
            except Exception as e:
                with self._lock:
                    self._last_del_fail[full_path] = time.time()
                    # 节流窗口外仍失败 → 文件被系统/其他进程永久占用，
                    # 后续不再尝试删除、不再产生事件（避免每 30s 刷一条 CRITICAL）
                    if last_fail > 0 and now - last_fail > _RETRY_INTERVAL:
                        self._newfile_giveup.add(full_path)
                        # 记录文件指纹：check() 下一轮用它区分"同一个删不掉
                        # 的文件"和"攻击者换了一个同名新文件"。
                        try:
                            st = os.stat(full_path)
                            self._newfile_giveup_sig[full_path] = (st.st_size, st.st_mtime_ns)
                        except OSError:
                            pass
                        logger.warning(
                            f'[关键目录防护] new_file 持续删除失败，标记 giveup: '
                            f'{full_path} ({e})')
                    else:
                        logger.warning(f'[关键目录防护] 删除未知新增文件失败 {full_path}: {e}')
                return False
        # modified_file
        if kind == 'modified_file':
            # 恢复失败节流 + 放弃策略（防 Windows Defender 驱动等受 WRP 保护的
            # 系统文件每轮恢复失败刷屏）：
            #   - 字节恢复失败后 30s 节流：窗口内不再尝试恢复、不再调 sfc、不打 warning；
            #   - 节流窗口外仍失败（持续被系统写入/锁定）→ 放弃内容恢复，
            #     仅保留删除检测（check 不再产生 modified 事件）。
            now = time.time()
            with self._lock:
                if full_path in self._restore_giveup:
                    return False
                in_throttle = now - self._last_restore_fail.get(full_path, 0.0) < _RETRY_INTERVAL
            if in_throttle:
                return False
            # 1) 优先使用快照字节直接原子写回 (更快、更准，非系统目录也能恢复)
            raw = meta.get('data') if isinstance(meta, dict) else None
            if isinstance(raw, (bytes, bytearray)) and len(raw) > 0:
                try:
                    tmp = full_path + '.psls_restore.tmp'
                    with open(tmp, 'wb') as f:
                        f.write(bytes(raw))
                        f.flush()
                        try:
                            os.fsync(f.fileno())
                        except Exception:
                            pass
                    os.replace(tmp, full_path)
                    logger.info(f'[关键目录防护] 已从快照字节恢复: {full_path}')
                    # 写回后刷新快照的 size / mtime / hash，避免下一轮误报
                    st = self._stat_file(full_path)
                    with self._lock:
                        tbl = self._store.get(dir_path)
                        if tbl is not None and full_path in tbl:
                            if st is not None:
                                tbl[full_path]['size'] = st[0]
                                tbl[full_path]['mtime'] = st[1]
                            tbl[full_path]['sha256'] = hashlib.sha256(bytes(raw)).hexdigest()
                    return True
                except Exception as e:
                    with self._lock:
                        last_fail = self._last_restore_fail.get(full_path, 0.0)
                        self._last_restore_fail[full_path] = now
                        # 节流窗口外仍失败 → 文件长期受系统保护/锁定，
                        # 放弃内容恢复（仅保留删除检测），避免每轮无效重试
                        if last_fail > 0 and now - last_fail > _RETRY_INTERVAL:
                            self._restore_giveup.add(full_path)
                    logger.warning(f'[关键目录防护] 字节恢复失败 {full_path}: {e}')
                    # 已放弃恢复的文件不再走 sfc / 删除回退，避免无意义重复修复
                    with self._lock:
                        if full_path in self._restore_giveup:
                            return False
            # 2) 回退：调用 sfc.exe 让 Windows 自己修 (针对真正受 WRP 保护的系统文件)
            win_dir = os.environ.get('WINDIR', r'C:\Windows')
            sfc_path = os.path.join(win_dir, 'System32', 'sfc.exe')
            try:
                if os.path.exists(sfc_path):
                    _sp.Popen(
                        [sfc_path, '/ScanFile=' + full_path],
                        creationflags=getattr(_sp, 'CREATE_NO_WINDOW', 0),
                    )
                    logger.info(f'[关键目录防护] 调用 sfc.exe 修复: {full_path}')
                    return True
            except Exception as e:
                logger.warning(f'sfc.exe 修复异常: {e}')
            # 3) 最终回退：尝试删除被篡改文件，避免被木马继续利用
            try:
                os.remove(full_path)
                logger.warning(f'[关键目录防护] 尝试删除被篡改文件: {full_path}')
                return True
            except Exception as e:
                logger.warning(f'[关键目录防护] 删除被篡改文件失败 {full_path}: {e}')
                return False
        return False

    # ---------- 持久化 ----------
    def save(self, path: str):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with self._lock:
                store_ser: Dict[str, Dict[str, dict]] = {}
                for d, table in self._store.items():
                    t_ser: Dict[str, dict] = {}
                    for fp, meta in table.items():
                        m = dict(meta)
                        raw = m.get('data')
                        if isinstance(raw, (bytes, bytearray)):
                            m['data'] = base64.b64encode(bytes(raw)).decode('ascii')
                        t_ser[fp] = m
                    store_ser[d] = t_ser
                data = {
                    'store': store_ser,
                    'overflow': self._overflow,
                    'dirs': {d: sorted(ss) if ss is not None else []
                             for d, ss in self._dir_store.items()},
                }
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False)
        except Exception as e:
            logger.warning(f'保存关键目录快照失败: {e}')

    def load(self, path: str, expected_dirs: Optional[List[str]] = None) -> bool:
        if not os.path.exists(path):
            return False
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            store_loaded: Dict[str, Dict[str, dict]] = data.get('store') or {}
            # 快照有效性校验：store 键与当前受保护目录必须存在交集。
            # 否则（残留/跨机器/损坏快照，如单元测试临时目录快照被生产环境
            # 误加载）check() 会把生产目录【所有】现存文件误判为 new_file
            # 并逐条尝试删除 → WinError 5 刷屏（用户实测单秒 460+ 条警告）。
            if expected_dirs:
                exp = set()
                for x in expected_dirs:
                    if not x:
                        continue
                    try:
                        exp.add(os.path.normcase(os.path.normpath(x)))
                    except Exception:
                        continue
                keys = set()
                for k in store_loaded:
                    try:
                        keys.add(os.path.normcase(os.path.normpath(k)))
                    except Exception:
                        continue
                if exp and keys and not (exp & keys):
                    logger.warning(
                        '关键目录快照与本机受保护目录零交集，判定为无效快照 '
                        '(残留/跨机器)，将重建基线')
                    return False
            # 快照自毁检测：PSLS 自身文件 (PSLS.sys 等) 版本变化 → 升级安装
            # 场景下安装包会替换驱动/EXE，旧基线存的 hash 必然不匹配 →
            # 若继续使用快照，首轮 check() 会把所有"正常升级"误判为 modified_file
            # 逐条告警刷屏。检测到则直接判定快照无效、触发重建基线。
            _UPGRADE_MARKERS = ('psls',)
            upgrade_hit = False
            for _d, table in store_loaded.items():
                if upgrade_hit:
                    break
                for fp, meta in table.items():
                    try:
                        low = fp.lower()
                    except Exception:
                        continue
                    if not any(m in low for m in _UPGRADE_MARKERS):
                        continue
                    old_hash = (meta or {}).get('sha256')
                    if not old_hash:
                        continue
                    cur_hash = self._hash_file(fp)
                    if cur_hash and cur_hash != old_hash:
                        upgrade_hit = True
                        logger.info(
                            f'快照中自身文件 {fp} hash 已变化 (升级安装)，'
                            f'将重建关键目录基线')
                        break
            if upgrade_hit:
                return False
            store: Dict[str, Dict[str, dict]] = {}
            for d, table in store_loaded.items():
                t: Dict[str, dict] = {}
                for fp, meta in table.items():
                    m = dict(meta)
                    d64 = m.get('data')
                    if isinstance(d64, str):
                        try:
                            m['data'] = base64.b64decode(d64)
                        except Exception:
                            m['data'] = None
                    t[fp] = m
                store[d] = t
            # 目录集合：新格式读 _dirs；旧格式(无该字段)以当前状态重建为基线，
            # 避免升级后首轮把现有目录全部误报为"新增目录"
            dirs_loaded = data.get('dirs')
            dir_store: Dict[str, Set[str]] = {}
            if isinstance(dirs_loaded, dict):
                for d, dd in dirs_loaded.items():
                    if isinstance(dd, list):
                        dir_store[d] = set(dd)
            for d in store:
                if d not in dir_store:
                    dir_store[d] = self._iter_dirs(d)
            with self._lock:
                self._store = store
                self._overflow = data.get('overflow') or {}
                self._dir_store = dir_store
                self._last_dir_check = {d: time.time() for d in dir_store}
            return bool(self._store)
        except Exception as e:
            logger.warning(f'加载关键目录快照失败: {e}')
            return False

    def snapshot_info(self) -> List[dict]:
        with self._lock:
            return [
                {
                    'device': d,
                    'label': d,
                    'type': 'critical_dir',
                    'hash': f'{len(meta)} files',
                    'overflow': self._overflow.get(d, False),
                }
                for d, meta in self._store.items()
            ]


def _expand_dir_path(path: str) -> Optional[str]:
    """展开环境变量并规范化路径。路径不存在或不是目录返回 None。"""
    if not path:
        return None
    expanded = os.path.expandvars(path)
    # 展开后仍含 % 变量说明该变量未定义 (如 %AppData% 在服务账户下为空)
    if '%' in expanded:
        return None
    try:
        real = os.path.abspath(expanded)
    except Exception:
        return None
    return real


def _win32_create_file(path: str, access: int, share: int = 0):
    """通过 CreateFileW 打开设备句柄。返回合法 handle 或 None。"""
    if not _HAS_WIN32:
        return None
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    FILE_SHARE_READ = 1
    FILE_SHARE_WRITE = 2
    FILE_SHARE_DELETE = 4

    # 合并 access 标志
    win_access = 0
    if access & 0x1:
        win_access |= GENERIC_READ
    if access & 0x2:
        win_access |= GENERIC_WRITE

    # 默认允许读共享
    win_share = share or (FILE_SHARE_READ | FILE_SHARE_WRITE)

    handle = _kernel32.CreateFileW(
        _path_for_win(path),
        win_access,
        win_share,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE or handle == 0:
        return None
    return handle


def _path_for_win(path: str) -> str:
    """确保设备路径格式正确。"""
    if path.startswith('\\\\.\\'):
        return path
    return path


def _win32_read_file(handle, num_bytes: int) -> Optional[bytes]:
    """从设备句柄读取 num_bytes 字节。"""
    if not _HAS_WIN32 or not handle:
        return None
    buf = (ctypes.c_ubyte * num_bytes)()
    bytes_read = ctypes.c_ulong(0)
    ok = _kernel32.ReadFile(
        handle,
        ctypes.byref(buf),
        num_bytes,
        ctypes.byref(bytes_read),
        None,
    )
    if not ok or bytes_read.value != num_bytes:
        return None
    return bytes(buf)


def _win32_write_file(handle, data: bytes) -> bool:
    """向设备句柄写入数据。"""
    if not _HAS_WIN32 or not handle:
        return False
    buf = (ctypes.c_ubyte * len(data))(*data)
    bytes_written = ctypes.c_ulong(0)
    ok = _kernel32.WriteFile(
        handle,
        ctypes.byref(buf),
        len(data),
        ctypes.byref(bytes_written),
        None,
    )
    return ok and bytes_written.value == len(data)


def _win32_close_handle(handle) -> bool:
    """关闭设备句柄。"""
    if not _HAS_WIN32 or not handle:
        return False
    return bool(_kernel32.CloseHandle(handle))


def _read_sector(path: str, count: int = 1) -> Optional[bytes]:
    """读取物理磁盘或卷设备的前 count 个扇区。"""
    handle = _win32_create_file(path, access=0x1)  # GENERIC_READ
    if not handle:
        return None
    try:
        return _win32_read_file(handle, _SECTOR_SIZE * count)
    finally:
        _win32_close_handle(handle)


def _write_sector(path: str, data: bytes) -> bool:
    """向物理磁盘或卷设备写入数据。"""
    handle = _win32_create_file(path, access=0x3)  # GENERIC_READ | GENERIC_WRITE
    if not handle:
        return False
    try:
        return _win32_write_file(handle, data)
    finally:
        _win32_close_handle(handle)


def _get_physical_drives() -> List[str]:
    """枚举系统所有物理磁盘设备路径 (\\\\.\\PhysicalDrive0, 1, ...)。"""
    drives = []
    if not _HAS_WIN32:
        return drives
    for i in range(16):
        path = f'\\\\.\\PhysicalDrive{i}'
        handle = _win32_create_file(path, access=0x1)
        if handle:
            _win32_close_handle(handle)
            drives.append(path)
    return drives


def _get_volume_letters() -> List[str]:
    """枚举系统所有卷盘符 (C:, D:, ...)。"""
    letters = []
    try:
        import string
        import os.path
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for i, ch in enumerate(string.ascii_uppercase):
            if mask & (1 << i):
                letters.append(f'{ch}:')
    except Exception:
        # 降级: 硬编码常见盘符
        for ch in 'CDEFGH':
            if os.path.exists(f'{ch}:\\'):
                letters.append(f'{ch}:')
    return letters


def _collect_boot_regions() -> List[Tuple[int, int, int]]:
    """枚举所有卷, 收集各分区 VBR/ESP 引导扇区为内核保护区域集。

    通过 IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS (0x00560000) 由卷句柄
    查询其所在物理盘号与盘内起始偏移, 每个分区保护起始 512B (VBR)。
    返回 [(disk_index, start_offset, length), ...] 供驱动 diskmon 事前拦截。

    Note:
        卷枚举覆盖有盘符与无盘符 (EFI 系统分区 ESP) 的卷。
    """
    regions: List[Tuple[int, int, int]] = []
    if not _HAS_WIN32:
        return regions

    ioctl_extents = 0x00560000   # IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
    share = 0x1 | 0x2            # FILE_SHARE_READ | FILE_SHARE_WRITE
    for n in range(1, 64):
        vol = f'\\\\.\\HarddiskVolume{n}'
        handle = _win32_create_file(vol, access=0)
        if not handle:
            continue
        try:
            # VOLUME_DISK_EXTENTS: DWORD NumberOfDiskExtents + DISK_EXTENT[n]
            # DISK_EXTENT: DWORD DiskNumber + LARGE_INTEGER*2 = 20B
            buf_size = 8 + 16 * 20
            buf = ctypes.create_string_buffer(buf_size)
            returned = wintypes.DWORD(0)
            ok = _kernel32.DeviceIoControl(
                handle, ioctl_extents, None, 0, buf, buf_size,
                ctypes.byref(returned), None)
            if not ok:
                continue
            count = struct.unpack_from('<I', buf.raw, 0)[0]
            for i in range(min(count, 16)):
                disk_no, start, extent_len = struct.unpack_from(
                    '<IQQ', buf.raw, 8 + i * 20)
                if disk_no < 8 and extent_len >= _SECTOR_SIZE:
                    regions.append((disk_no, start, _SECTOR_SIZE))
        finally:
            _win32_close_handle(handle)

    # 去重 (同盘多卷不会重叠, 但保守去重)
    seen: Set[Tuple[int, int, int]] = set()
    uniq = []
    for r in regions:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    return uniq


# ---- 引导链文件候选 (卷根相对路径, 大小写不敏感) ----
_BOOT_FILE_REL_CANDIDATES = (
    r'\bootmgr',                      # BIOS 引导管理器 (系统卷根)
    r'\Boot\BCD',                     # BIOS BCD 存储
    r'\EFI\Microsoft\Boot\BCD',       # UEFI BCD
    r'\EFI\Microsoft\Boot\bootmgfw.efi',
    r'\EFI\Microsoft\Boot\bootmgr.efi',
    r'\EFI\Boot\bootx64.efi',
    r'\EFI\Boot\bootia32.efi',
)


def _collect_boot_file_paths() -> List[str]:
    """枚举所有卷, 收集引导链文件 (bootmgr/BCD/EFI) 的 NT 设备路径。

    minifilter 的规范化文件名为 NT 设备路径
    (如 "\\Device\\HarddiskVolume3\\Boot\\BCD"), 因此这里把每个卷
    ("\\\\.\\HarddiskVolumeN") 映射为 "\\Device\\HarddiskVolumeN" 前缀。
    """
    paths: List[str] = []
    if not _HAS_WIN32:
        return paths
    for n in range(1, 64):
        win_prefix = f'\\\\.\\HarddiskVolume{n}'
        for rel in _BOOT_FILE_REL_CANDIDATES:
            win = win_prefix + rel
            try:
                attrs = _kernel32.GetFileAttributesW(win)
            except Exception:
                attrs = 0xFFFFFFFF
            # INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF; 0x10 = FILE_ATTRIBUTE_DIRECTORY
            if attrs != 0xFFFFFFFF and (attrs & 0x10) == 0:
                paths.append(f'\\Device\\HarddiskVolume{n}' + rel)
    return paths


def _sha256(data: bytes) -> str:
    """计算 SHA-256 指纹。"""
    return hashlib.sha256(data).hexdigest()


class MBRProtector:
    """MBR / 引导扇区保护引擎 + 系统关键目录保护。

    1) 引导扇区: 周期性校验 MBR/VBR 的完整性 (1 秒轮询), 检测到篡改时自动
       回滚 (默认 auto_restore=True)，并通过 on_threat 发送告警。
    2) 系统关键目录: 对 %WINDIR%\System32\drivers\ 等常见木马/勒索破坏目标做
       两层快照校验 (size+mtime 快速跳过 + 变更时 sha256 精读比对)，
       检测到篡改/未知新文件/新增子目录时自动处置 (新增目录可递归删除，
       注册表 hive 豁免内容校验避免刷屏)，同时配合内核 MBR 写拦截。
    """

    # 可供外部查询的默认关键目录列表 (字符串形式，含 %WINDIR% 等变量)
    default_system_critical_dirs: Tuple[str, ...] = tuple(_DEFAULT_CRITICAL_DIRS)

    def __init__(self, on_threat: Optional[Callable[[dict], None]] = None,
                 interval: float = _DEFAULT_INTERVAL,
                 auto_restore: bool = True,
                 use_driver_mon: bool = True):
        self._on_threat = on_threat
        self._interval = max(1.0, float(interval))
        # 检测到篡改后是否自动回滚 (无需用户同意), 通知照常发送
        self._auto_restore = bool(auto_restore)
        # 是否尝试对接内核 diskmon 引导扇区写拦截 (事前防护, 非仅事后回滚)
        self._use_driver_mon = bool(use_driver_mon)
        self._driver_bridge = None      # 延迟加载的 PSLSDriverBridge 实例
        self._driver_mon_ok = False     # 内核写拦截当前是否生效
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()

        # ---- 进程事件触发式关键目录保护（GUI 无响应规避）----
        # _stop_event.wait(self._interval) 提供默认 1s 轮询（兜底）；
        # 同时提供 notify_process_created(pid, image_path)：
        #   - 新进程启动 → 立刻打断 wait → 本轮执行 check，比下次轮询早 <1s 响应
        #   - 1 秒内密集事件 burst（如系统登录瞬间 100+ 进程/秒）：做 400ms 冷却，
        #     防止 check 被 100+ 次调用（递归校验 System32/config 等大目录的 SHA-256
        #     会把主线程拖进"无响应"）
        self._burst_interval: float = 0.4  # 秒：同一窗口内最多触发一次额外 check
        self._last_proc_trigger_ts: float = 0.0
        self._pending_proc_pid: Optional[int] = None
        self._pending_proc_image: Optional[str] = None

        # 是否已初始化备份
        self._has_backup = False
        # 备份的扇区数据: {device_path: {'data': base64, 'hash': sha256, 'label': str}}
        self._backups: Dict[str, dict] = {}
        # 上次破坏处置的时间 (自动回滚/告警去重)
        self._last_alert: Dict[str, float] = {}
        # 扇区快速轮询间隔 (MBR/VBR, 独立于关键目录轮询, 见 _MBR_FAST_INTERVAL)
        self._mbr_interval: float = float(_MBR_FAST_INTERVAL)
        # 关键目录上次检查时间 (按 _interval 节流, 与扇区快轮询解耦)
        self._last_crit_check: float = 0.0
        # 设备 -> 上次恢复尝试时间 (恢复失败 1s 节流重试)
        self._last_restore_attempt: Dict[str, float] = {}
        # 内核 MBR 写拦截上次尝试重挂时间 (掉线后 5s 节流自动重挂)
        self._driver_rearm_ts: float = 0.0
        # 扇区备份是否有效 (MBR/VBR 是否真正读到并持久化)。
        # False 说明引导扇区保护实际未生效（常见原因：未以管理员运行），
        # 必须显式告警，而不是让 _has_backup(关键目录满足) 掩盖降级。
        self._sector_ok: bool = False
        # 降级原因描述 + 一次性降级告警标记
        self._degraded_reason: Optional[str] = None
        self._degraded_alerted: bool = False
        # 引导扇区设备连续读取失败计数/上次告警时间 (防"独占锁定"式静默绕过:
        # 恶意进程以 share=0 独占打开物理盘后, 正常轮询读会失败)
        self._read_fail_count: Dict[str, int] = {}
        self._last_readfail_alert: Dict[str, float] = {}
        # 扇区备份延迟补齐: 驱动加载较慢 (早启备份失败) 时, 启动后由监控
        # 线程在驱动就绪后自动重试 create_backup 补齐扇区备份, 而非一次性
        # 失败后永久降级。记录上次补备尝试时间 (节流, 避免每轮都重试)。
        self._sector_retry_ts: float = 0.0
        self._last_sector_backup_warn_ts: float = 0.0
        # 统计
        self._stats = {
            'checks': 0,
            'threats_detected': 0,
            'restores_attempted': 0,
            'restores_ok': 0,
            'auto_restored': 0,
        }
        self._running = False
        self._enabled = True

        # ----- 系统关键目录保护 (新增) -----
        self._critical_dirs_raw: Tuple[str, ...] = tuple(_DEFAULT_CRITICAL_DIRS)
        # 展开后的关键目录 (运行时刷新，保持与实际系统一致)
        self._critical_dirs_expanded: List[str] = []
        # 仅监控目录 (watch-only)：System32 / winevt\Logs 等高频变化目录，
        # 不做内容级快照+自动恢复，只做子目录新增检测，从根上消除刷屏
        self._watch_only_dirs_raw: Tuple[str, ...] = tuple(_DEFAULT_WATCH_ONLY_DIRS)
        self._watch_only_dirs_expanded: List[str] = []
        self._critical_snapshot = _CriticalDirSnapshot()
        # 目录级驱动事前拦截：安装目录防改由 self_protection 独占注册，
        # 本模块不注册关键目录（见 _enable_driver_mon 注释），恒为 False
        self._driver_dir_ok: bool = False

    # ---- 备份 ----

    # ----- 关键目录 API -----
    def _expand_dir_path(self, p):
        """模块级同名函数的实例方法别名，保持测试接口稳定。"""
        return _expand_dir_path(p)

    def set_critical_dirs(self, dirs):
        """覆盖默认关键目录列表 (测试或用户自定义)。"""
        with self._lock:
            self._critical_dirs_raw = tuple(dirs) if dirs else tuple()
            self._refresh_critical_dirs_expanded_locked()

    def set_watch_only_dirs(self, dirs):
        """覆盖 watch-only 目录集合。

        watch-only 目录（如 System32 / 事件日志）内容高频变化，
        仅做子目录新增检测，不做文件级快照校验与自动恢复，防止误报刷屏。
        """
        with self._lock:
            self._watch_only_dirs_raw = tuple(dirs) if dirs else tuple()
            self._refresh_critical_dirs_expanded_locked()

    def _refresh_critical_dirs_expanded_locked(self):
        """按 raw 列表重新展开环境变量，过滤掉不存在/未授权目录。

        同时刷新 watch-only 目录展开集合。
        """
        expanded: List[str] = []
        seen = set()
        for raw in self._critical_dirs_raw:
            d = _expand_dir_path(raw)
            if not d or not os.path.isdir(d):
                continue
            nd = os.path.normcase(os.path.normpath(d))
            if nd in seen:
                continue
            seen.add(nd)
            expanded.append(d)
        self._critical_dirs_expanded = expanded
        # watch-only 目录
        watch_expanded: List[str] = []
        for raw in self._watch_only_dirs_raw:
            d = _expand_dir_path(raw)
            if not d or not os.path.isdir(d):
                continue
            if d not in watch_expanded:
                watch_expanded.append(d)
        self._watch_only_dirs_expanded = watch_expanded

    def get_critical_dirs_expanded(self) -> List[str]:
        """返回当前已展开、真实存在的关键目录列表（只读视图）。"""
        with self._lock:
            return list(self._critical_dirs_expanded)

    def get_watch_only_dirs_expanded(self) -> List[str]:
        """返回当前已展开、真实存在的 watch-only 目录列表（只读视图）。"""
        with self._lock:
            return list(self._watch_only_dirs_expanded)

    # ----- 关键目录 + 扇区 的总备份 -----
    def _build_sector_backups_locked(self) -> bool:
        """(锁内) 仅重建引导扇区 (MBR/VBR) 备份表。

        与 create_backup 分离：驱动加载较慢时，start() 早期的扇区备份会
        失败。驱动就绪后由监控线程调用本方法**只补扇区**，不重建关键目录
        快照（快照已被 create_backup 建立，频繁重建基线会干扰完整性判定）。
        """
        self._backups.clear()
        ok_any = False

        # 1. 物理磁盘 MBR
        for drive_path in _get_physical_drives():
            data = _read_sector(drive_path, count=1)
            if data and len(data) >= _SECTOR_SIZE:
                sector = data[:_SECTOR_SIZE]
                # 校验 MBR 签名
                if sector[_MBR_SIG_OFFSET:_MBR_SIG_OFFSET + 2] == _MBR_SIG_VALUE:
                    self._backups[drive_path] = {
                        'data': sector,
                        'hash': _sha256(sector),
                        'label': f'MBR ({drive_path})',
                        'type': 'mbr',
                    }
                    ok_any = True
                    logger.info(f'已备份 MBR: {drive_path}')

        # 2. 卷 VBR/PBR
        for vol in _get_volume_letters():
            vol_path = f'\\\\.\\{vol}'
            data = _read_sector(vol_path, count=1)
            if data and len(data) >= _SECTOR_SIZE:
                sector = data[:_SECTOR_SIZE]
                # VBR 也有引导签名
                if sector[_MBR_SIG_OFFSET:_MBR_SIG_OFFSET + 2] == _MBR_SIG_VALUE:
                    self._backups[vol_path] = {
                        'data': sector,
                        'hash': _sha256(sector),
                        'label': f'VBR ({vol})',
                        'type': 'vbr',
                    }
                    ok_any = True
                    logger.info(f'已备份 VBR: {vol}')
        return ok_any

    def _try_rearm_driver_mbr(self):
        """内核 MBR 写拦截掉线后自动重挂（5s 节流）。

        实测现象："MBR 拦截成功一次，之后失效"。根因：回滚写盘若被内核
        拦截（边界场景），_write_backup_with_fallback 会临时
        set_mbr_protect(False) 再写回，写回后尝试 set_mbr_protect(True)；
        一旦这次重挂失败（驱动忙 / IOCTL 失败 / 桥接需重连），
        self._driver_mon_ok 会永久停在 False —— 此前**没有任何地方重试**，
        于是内核写拦截从此关闭，后续 MBR 写入畅通无阻（只剩用户态 0.25s
        轮询事后回滚）。本方法在监控线程里节流重挂，自动恢复事前防护。
        """
        if not self._use_driver_mon or self._driver_mon_ok or not _HAS_WIN32:
            return
        now = time.time()
        if now - self._driver_rearm_ts < 5.0:
            return
        self._driver_rearm_ts = now
        try:
            br = self._get_driver_bridge()
            if br is None:
                return
            if br.set_mbr_protect(True):
                self._driver_mon_ok = True
                logger.info('内核 MBR 写入拦截已重新挂载（重挂成功）')
                try:
                    self._push_boot_protect(br)
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f'内核 MBR 拦截重挂失败: {e}')

    def _try_repair_sector_backup(self):
        """驱动就绪后补齐引导扇区备份 (监控线程内节流调用)。

        场景：start() 早期驱动未加载/未提权，扇区备份失败 (_sector_ok=False)
        但进程实际是管理员（驱动加载成功即证明）。日志中表现为"Mbr_Baseline
        已建立 但无法读取/备份 MBR/引导扇区"并发——备份只失败一次便永久
        降级。这里在驱动就绪后重试补备，成功后解除降级告警。
        """
        if self._sector_ok or not _HAS_WIN32:
            return
        now = time.time()
        # 节流：驱动未就绪时每 5s 尝试一次；就绪后失败也每 5s 重试
        if now - self._sector_retry_ts < 5.0:
            return
        self._sector_retry_ts = now
        try:
            with self._lock:
                ok = self._build_sector_backups_locked()
                if ok:
                    self._sector_ok = True
                    self._save_backup_to_disk()
                    self._degraded_alerted = False
            if ok:
                logger.info('引导扇区备份已补齐, 扇区保护生效')
            else:
                # 持续补备失败 (驱动始终未就绪/真非管理员) → 才发降级告警，
                # 且 30s 去重，避免每 5s 一次刷屏 (start() 不再立即告警，
                # 因为驱动可能只是加载慢，备份会稍后自动补齐)。
                if now - self._last_sector_backup_warn_ts >= _RETRY_INTERVAL:
                    self._last_sector_backup_warn_ts = now
                    self._degraded_reason = (
                        '无法读取/备份 MBR/引导扇区（通常因未以管理员身份'
                        '运行 PSLS），引导扇区事前拦截与自动回滚未生效')
                    logger.warning(self._degraded_reason)
                    self._emit_degraded_alert()
        except Exception as e:
            logger.warning(f'补齐引导扇区备份异常: {e}')

    def create_backup(self) -> bool:
        """扫描所有物理磁盘和卷, 创建引导扇区备份 + 关键目录快照。

        Returns:
            True 至少成功备份一个设备/关键目录快照。
        """
        with self._lock:
            ok_any = self._build_sector_backups_locked()

            # 3. 系统关键目录快照 (与扇区备份同属"信任状态"，一并刷新)
            self._refresh_critical_dirs_expanded_locked()
            if self._critical_dirs_expanded:
                # 快照默认同步执行，便于 trust_change() 等立即生效场景
                dirlist = list(self._critical_dirs_expanded)
                try:
                    total = self._critical_snapshot.snapshot(
                        dirlist, watch_dirs=self._watch_only_dirs_expanded)
                    self._critical_snapshot.save(_CRIT_BACKUP_FILE)
                    logger.info(f'关键目录快照完成: {len(dirlist)} dirs, '
                                f'{total} files (watch-only: '
                                f'{len(self._watch_only_dirs_expanded)})')
                except Exception as e:
                    logger.warning(f'关键目录快照异常: {e}')

            self._has_backup = ok_any or bool(self._critical_dirs_expanded)
            if self._has_backup:
                self._save_backup_to_disk()
            return self._has_backup

    def _save_backup_to_disk(self):
        """将备份持久化到 JSON 文件 (data 为 hex 编码)。"""
        try:
            os.makedirs(_BACKUP_DIR, exist_ok=True)
            store = {}
            for path, info in self._backups.items():
                store[path] = {
                    'data_hex': info['data'].hex(),
                    'hash': info['hash'],
                    'label': info['label'],
                    'type': info['type'],
                }
            with open(_BACKUP_FILE, 'w', encoding='utf-8') as f:
                json.dump(store, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f'保存 MBR 备份到磁盘失败: {e}')

    def _load_backup_from_disk(self) -> bool:
        """从 JSON 文件恢复备份 (扇区备份 + 关键目录快照)。"""
        ok_sector = False
        try:
            if not os.path.exists(_BACKUP_FILE):
                ok_sector = False
            else:
                with open(_BACKUP_FILE, 'r', encoding='utf-8') as f:
                    store = json.load(f)
                self._backups.clear()
                for path, info in store.items():
                    self._backups[path] = {
                        'data': bytes.fromhex(info['data_hex']),
                        'hash': info['hash'],
                        'label': info.get('label', path),
                        'type': info.get('type', 'mbr'),
                    }
                ok_sector = bool(self._backups)
        except Exception as e:
            logger.warning(f'加载 MBR 备份失败: {e}')

        # 关键目录快照 (独立文件，与扇区分开)
        self._refresh_critical_dirs_expanded_locked()
        ok_crit = False
        try:
            if os.path.exists(_CRIT_BACKUP_FILE):
                ok_crit = self._critical_snapshot.load(
                    _CRIT_BACKUP_FILE,
                    expected_dirs=list(self._critical_dirs_expanded))
            else:
                # 没有快照文件：第一次启动/用户清理缓存，重新做一次快照，
                # 与扇区备份相同的"信任状态"
                if self._critical_dirs_expanded:
                    self._critical_snapshot.snapshot(
                        self._critical_dirs_expanded,
                        watch_dirs=self._watch_only_dirs_expanded)
                    self._critical_snapshot.save(_CRIT_BACKUP_FILE)
                    ok_crit = True
        except Exception as e:
            logger.warning(f'加载关键目录快照失败: {e}')

        # 残留/跨机/损坏快照被判定无效时（load 返回 False），立即重建基线，
        # 避免把生产目录所有现存文件误判为"新增"并逐条删除（刷屏根因）
        if not ok_crit and self._critical_dirs_expanded:
            try:
                self._critical_snapshot.snapshot(
                    self._critical_dirs_expanded,
                    watch_dirs=self._watch_only_dirs_expanded)
                self._critical_snapshot.save(_CRIT_BACKUP_FILE)
                ok_crit = True
                logger.info('关键目录快照无效，已重建基线')
            except Exception as e:
                logger.warning(f'重建关键目录快照失败: {e}')

        self._has_backup = ok_sector or ok_crit
        self._sector_ok = ok_sector       # 仅扇区备份可用才算扇区保护有效
        return self._has_backup

    # ---- 校验 ----

    def _check_sectors_only(self) -> List[dict]:
        """仅校验引导扇区 (MBR/VBR) 完整性。快速路径：512B 读 + SHA-256。

        与关键目录检查解耦，由监控循环以 _mbr_interval 高频调用，
        显著缩短"引导扇区被改写 → 检测 → 回滚"的响应时间。
        """
        tampered = []
        with self._lock:
            if not self._has_backup:
                return tampered
            for path, info in list(self._backups.items()):
                data = _read_sector(path, count=1)
                if data is None or len(data) < _SECTOR_SIZE:
                    # 读取失败：设备被拔出 / 权限不足 / 被恶意进程独占锁定
                    # (share=0 打开物理盘可让后续任何读写失效)。防静默绕过：
                    # 连续失败达阈值告警（30s 去重），恢复正常后自动清除计数。
                    fails = self._read_fail_count.get(path, 0) + 1
                    self._read_fail_count[path] = fails
                    if fails >= 3:
                        now = time.time()
                        if now - self._last_readfail_alert.get(path, 0.0) >= _RETRY_INTERVAL:
                            self._last_readfail_alert[path] = now
                            tampered.append({
                                'device': path,
                                'label': info['label'],
                                'type': info.get('type', 'mbr'),
                                'unreadable': True,
                                'timestamp': now,
                            })
                    continue
                self._read_fail_count[path] = 0
                sector = data[:_SECTOR_SIZE]
                current_hash = _sha256(sector)
                if current_hash != info['hash']:
                    tampered.append({
                        'device': path,
                        'label': info['label'],
                        'type': info.get('type', 'mbr'),
                        'backup_hash': info['hash'],
                        'current_hash': current_hash,
                        'timestamp': time.time(),
                    })
        return tampered

    def _check_critical_dirs_only(self) -> List[dict]:
        """仅校验系统关键目录快照 (不包含扇区, 按 _interval 节流)。"""
        with self._lock:
            if not self._critical_dirs_expanded:
                return []
            crit_dirs = list(self._critical_dirs_expanded)
            watch_dirs = list(self._watch_only_dirs_expanded)
        return self._critical_snapshot.check(crit_dirs, watch_dirs=watch_dirs)

    def _check_all(self) -> List[dict]:
        """校验扇区备份 + 关键目录快照的完整性。返回篡改事件列表。

        仅供外部一次性全检使用；监控循环内部改用
        _check_sectors_only / _check_critical_dirs_only 分段调度。
        """
        return self._check_sectors_only() + self._check_critical_dirs_only()

    # ---- 篡改处置 (自动回滚 + 通知) ----

    def _handle_sector_events(self, sector_events: List[dict]):
        """批量处置扇区篡改事件 (逐设备独立)。"""
        now = time.time()
        for t in sector_events:
            try:
                self._handle_sector_tamper_one(t, now)
            except Exception:
                pass

    def _handle_dir_events(self, dir_events: List[dict]):
        """批量处置关键目录事件 (按 device 聚合通知)。"""
        if not dir_events:
            return
        now = time.time()
        dir_groups: Dict[str, List[dict]] = {}
        for t in dir_events:
            dir_groups.setdefault(t.get('device') or '', []).append(t)
        for dev, group in dir_groups.items():
            try:
                self._handle_dir_group(dev, group, now)
            except Exception:
                pass

    def _handle_tamper(self, tampered: List[dict]):
        """处理检测到的篡改: 自动回滚 (如开启) + 发送通知。

        通知防刷屏策略：
        - 引导扇区: 同一设备在 _RETRY_INTERVAL 内只告警一次。
        - 关键目录: 同一目录同一轮多个事件 (批量文件变化/新增) 聚合为
          1 条通知，且同一目录在 _RETRY_INTERVAL 内不重复通知。
          恢复动作仍逐条执行（每个篡改对象都处置，不再受通知去重影响）。
        """
        if not tampered:
            return
        sector_events = [t for t in tampered if t.get('type') != 'critical_dir']
        dir_events = [t for t in tampered if t.get('type') == 'critical_dir']
        self._handle_sector_events(sector_events)
        self._handle_dir_events(dir_events)

    def _handle_sector_tamper_one(self, t: dict, now: float):
        """扇区 (MBR/VBR) 篡改单条处置。

        恢复动作与通知去重**解耦**：
          - 恢复: 每次检测到篡改都尝试回滚（1s 失败节流），不再被 30s
            通知去重吞掉——首次恢复失败后，下一轮快轮询立即重试，
            避免"破坏 MBR → 重启"窗口内因去重而放弃恢复。
          - 通知: 同一设备 30s 窗口内只告警一次 (防刷屏)。
        """
        key = t['device']
        auto_restored = False
        fail_reason = None

        # 设备连续不可读：读不到也就无法写回，跳过恢复仅告警（可能被
        # 恶意进程独占锁定，或保护自身失去权限），30s 去重。
        if t.get('unreadable'):
            with self._lock:
                last = self._last_alert.get(key, 0.0)
                if now - last < _RETRY_INTERVAL:
                    return
                self._last_alert[key] = now
            try:
                if self._on_threat:
                    self._on_threat({
                        'type': 'mbr',
                        'device': key,
                        'label': t.get('label'),
                        'file': None,
                        'change_kind': 'unreadable',
                        'message': (f'引导扇区设备无法读取: {t.get("label")} '
                                    f'(可能被恶意进程独占锁定或权限不足)'),
                        'severity': 'critical',
                        'auto_restored': False,
                        'timestamp': t.get('timestamp', now),
                    })
            except Exception:
                pass
            return

        with self._lock:
            # 1) 恢复动作：不受通知去重约束，失败 1s 节流重试
            if self._auto_restore:
                last_attempt = self._last_restore_attempt.get(key, 0.0)
                if now - last_attempt >= _MBR_RESTORE_RETRY_INTERVAL:
                    self._last_restore_attempt[key] = now
                    auto_restored = self._restore_one_locked(t['device'], t)
                    if not auto_restored:
                        fail_reason = '自动回滚失败(可能缺少管理员权限)'
            if auto_restored:
                self._stats['auto_restored'] += 1

            # 2) 通知 30s 去重（仅影响通知，不影响上面的恢复）
            last = self._last_alert.get(key, 0.0)
            if now - last < _RETRY_INTERVAL:
                return
            self._last_alert[key] = now
            self._stats['threats_detected'] += 1
            if auto_restored:
                message = f'检测到引导扇区被篡改, 已自动回滚: {t["label"]}'
            else:
                message = f'检测到引导扇区被篡改: {t["label"]}'
                if fail_reason:
                    message += f' ({fail_reason})'
        try:
            if self._on_threat:
                self._on_threat({
                    'type': 'mbr',
                    'device': t.get('device'),
                    'label': t.get('label'),
                    'file': None,
                    'change_kind': t.get('type', 'mbr'),
                    'message': message,
                    'severity': 'critical',
                    'auto_restored': auto_restored,
                    'timestamp': t.get('timestamp', time.time()),
                })
        except Exception:
            pass

    def _handle_dir_group(self, dev: str, events: List[dict], now: float):
        """关键目录同一目录的批量篡改：逐条恢复 + 聚合为 1 条通知。

        通知 30s 窗口去重 (按目录)，避免恶意软件循环覆盖/Windows 正常
        批量写文件时刷屏。
        """
        # 1) 统计各类变化与示例路径
        kinds: Dict[str, int] = {}
        examples: List[str] = []
        for t in events:
            k = t.get('change_kind') or 'tamper'
            kinds[k] = kinds.get(k, 0) + 1
            fp = t.get('file') or ''
            if len(examples) < 2 and fp:
                examples.append(fp)
        # 2) 逐条恢复（不受通知去重影响）
        auto_ok = 0
        auto_fail = 0
        if self._auto_restore:
            for t in events:
                d = t.get('device')
                fp = t.get('file')
                if not d or not fp:
                    continue
                try:
                    if self._critical_snapshot.restore_file(
                            d, fp, watch=bool(t.get('watch'))):
                        auto_ok += 1
                    else:
                        auto_fail += 1
                except Exception:
                    auto_fail += 1
        with self._lock:
            self._stats['threats_detected'] += len(events)
            if auto_ok:
                self._stats['auto_restored'] += auto_ok
            # 3) 通知去重：同一目录 30s 内只通知一次
            key = ('crit', dev)
            last = self._last_alert.get(key, 0.0)
            if now - last < _RETRY_INTERVAL:
                return
            self._last_alert[key] = now
        # 4) 聚合消息
        kind_txt = '、'.join(f'{k}×{c}' for k, c in sorted(kinds.items()))
        # 判定所有事件是否都是 watch 目录 (System32 等高频目录下的正常变化)
        all_watch = all(bool(t.get('watch')) for t in events)
        if not self._auto_restore:
            disp = '未启用自动处置'
        elif auto_ok > 0:
            disp = f'已自动处置 {auto_ok}/{len(events)} 处'
        elif all_watch:
            disp = f'watch 目录变更，仅上报不处置 ({auto_fail} 处)'
        else:
            disp = f'已自动处置 0/{len(events)} 处 (处置失败)'
        detail = '; '.join(examples)
        if len(events) > len(examples):
            detail += f" (+{len(events) - len(examples)} 处)"
        message = f'检测到关键目录篡改: {dev}（{kind_txt}），{disp}'
        if detail:
            message += f' | 示例: {detail}'
        # watch 目录下的变化降为 high (仅告警不自动删)，严格目录下仍为 critical
        severity = 'critical'
        if all_watch:
            severity = 'high'
        elif set(kinds) <= {'new_dir', 'new_file'}:
            severity = 'high'
        try:
            if self._on_threat:
                self._on_threat({
                    'type': 'critical_dir',
                    'device': dev,
                    'label': dev,
                    'file': examples[0] if examples else dev,
                    'change_kind': ','.join(sorted(kinds)),
                    'message': message,
                    'severity': severity,
                    'auto_restored': auto_ok > 0,
                    # 仅上报不处置：未启用自动处置，或 watch 目录变化本就不处置。
                    # 与上面的 disp 文案同源；上层据此跳过提示音——这类事件是
                    # 常态噪声（System32 等目录的正常增删），不应鸣笛。
                    'report_only': bool(auto_ok == 0
                                        and (all_watch or not self._auto_restore)),
                    'timestamp': now,
                })
        except Exception:
            pass

    def _restore_one_locked(self, dev: str, tamper_info: dict) -> bool:
        """回滚单设备 (调用方须持有 _lock)。返回是否成功。"""
        info = self._backups.get(dev)
        if not info:
            return False
        self._stats['restores_attempted'] += 1
        if self._write_backup_with_fallback(dev, info['data']):
            # 刷新 hash (恢复后当前状态与备份一致)
            info['hash'] = _sha256(info['data'])
            self._stats['restores_ok'] += 1
            logger.info(f'已自动回滚引导扇区: {dev}')
            return True
        logger.error(f'自动回滚引导扇区失败: {dev}')
        return False

    # ---- 内核驱动拦截对接 (diskmon, 事前防护) ----

    def _get_driver_bridge(self):
        """懒加载驱动桥 (仅 win32 且驱动可用时)。失败返回 None。"""
        if not self._use_driver_mon or not _HAS_WIN32:
            return None
        if self._driver_bridge is None:
            try:
                from driver.bridge.psls_driver_bridge import PSLSDriverBridge
                br = PSLSDriverBridge()
                if br.is_available:
                    self._driver_bridge = br
                else:
                    br.close()
            except Exception as e:
                logger.info(f'驱动桥接不可用(降级为用户态轮询): {e}')
        return self._driver_bridge

    def _enable_driver_mon(self) -> bool:
        """启用内核 MBR 写拦截（磁盘引导扇区事前防护）。

        注意：驱动 的 IOCTL_SET_PROTECTED_DIR 是"安装目录防改"语义
        (single, 每次调用覆盖上一次)，由 self_protection.py 独占注册 PSLS
        安装目录，防止外部进程篡改安装包。这里**不再**复用该 IOCTL 去
        注册关键目录——若注册 System32 等系统目录，Windows 正常写入
        (更新/缓存/临时文件) 会被内核拒绝，导致系统异常，且两次注册会
        互相覆盖，甚至解除安装目录保护。关键目录的事前防御仍由用户态
        1s 轮询快照 + 自动恢复承担，属实时的双保险兜底。
        """
        if not self._use_driver_mon:
            return False
        br = self._get_driver_bridge()
        if br is None:
            self._driver_mon_ok = False
            return False
        ok_any = False
        try:
            ok = br.set_mbr_protect(True)
            self._driver_mon_ok = bool(ok)
            if ok:
                logger.info('内核 MBR 写入拦截已启用 (diskmon, 事前防护)')
                ok_any = True
                # v1.1: 叠加下发改保护区域 (VBR/ESP) 与引导链文件保护
                self._push_boot_protect(br)
            else:
                logger.warning('内核 MBR 拦截开启失败(驱动可能过旧)')
        except Exception as e:
            logger.warning(f'启用内核 MBR 拦截异常: {e}')
            self._driver_mon_ok = False
        return ok_any

    def _push_boot_protect(self, br):
        """v1.1: 向驱动下发 VBR/ESP 分区区域与引导链文件保护列表。

        在 MBR 基础拦截之上补齐 引导链 (VBR/bootmgr/BCD/EFI) 的事前拦截:
          1. set_boot_protect: diskmon 把受保护区域从"仅第0扇区"扩展为
             "MBR + 各分区 VBR/ESP 引导扇区" (卷起始偏移 + 512B)。
          2. set_boot_files: minifilter 拒绝外部进程修改 bootmgr/BCD/EFI
             (TrustedInstaller/TiWorker 的 Windows 更新写被白名单放行)。
        任何一步失败只记录日志, 不影响 MBR 基础拦截的启用状态。
        """
        try:
            regions = _collect_boot_regions()
            if regions:
                br.set_boot_protect(regions, True)
                logger.info(
                    f'内核 VBR/ESP 区域保护已启用: {len(regions)} 个区域')
            else:
                logger.info('未发现 VBR/ESP 区域, 保持 MBR 默认拦截')
        except Exception as e:
            logger.warning(f'下发 VBR/ESP 区域保护失败: {e}')
        try:
            paths = _collect_boot_file_paths()
            if paths:
                if br.set_boot_files(paths, True):
                    logger.info(f'内核引导文件保护已启用: {len(paths)} 条路径')
                else:
                    logger.warning('引导文件保护下发失败(驱动可能过旧)')
            else:
                logger.info('未发现引导链文件, 跳过文件级保护')
        except Exception as e:
            logger.warning(f'下发引导文件保护失败: {e}')

    def _disable_driver_mon(self):
        """关闭内核 MBR 写拦截并释放桥接。

        只关闭自身的 MBR 拦截，**不移除** clear_protected_dir——
        该保护属于 self_protection 的安装目录防改，这里清掉会解除
        安装目录保护。
        """
        if self._driver_bridge is not None:
            try:
                self._driver_bridge.set_mbr_protect(False)
            except Exception:
                pass
            try:
                self._driver_bridge.close()
            except Exception:
                pass
            self._driver_bridge = None
        self._driver_mon_ok = False
        self._driver_dir_ok = False

    def _write_backup_with_fallback(self, dev: str, data: bytes) -> bool:
        """写回备份扇区。若被内核拦截 (非 PSLS 主进程等边界场景),
        临时关闭拦截重试一次, 然后尽力恢复拦截。"""
        ok = _write_sector(dev, data)
        if not ok and self._driver_mon_ok:
            logger.warning(f'回滚写盘被拒, 临时关闭内核拦截重试: {dev}')
            if self._driver_bridge is not None:
                try:
                    self._driver_bridge.set_mbr_protect(False)
                except Exception:
                    pass
                self._driver_mon_ok = False
            ok = _write_sector(dev, data)
            if self._use_driver_mon and self._driver_bridge is not None:
                try:
                    ok2 = self._driver_bridge.set_mbr_protect(True)
                    self._driver_mon_ok = bool(ok2)
                except Exception:
                    pass
        return ok

    # ---- 恢复 ----

    def restore(self, device_path: Optional[str] = None) -> bool:
        """手动从备份恢复引导扇区。

        Args:
            device_path: 指定设备路径; None 则恢复所有设备。

        Returns:
            True 至少成功恢复一个设备。
        """
        with self._lock:
            ok_any = False
            targets = [device_path] if device_path else list(self._backups.keys())
            for path in targets:
                if self._restore_one_locked(path, {}):
                    ok_any = True
            if ok_any:
                # 清除处置去重缓存
                self._last_alert.clear()
            return ok_any

    def trust_change(self):
        """信任当前引导扇区状态 (用户主动修改分区等操作后调用)。

        刷新备份为当前磁盘状态, 不告警。
        """
        self.create_backup()
        self._last_alert.clear()
        logger.info('已信任当前引导扇区状态, 备份已刷新')

    # ---- 线程循环 ----

    def _run(self):
        """后台监控线程主循环。

        分段调度，保证 MBR/引导扇区响应最快：
          - 阶段 1 (每轮必做): _check_sectors_only() 快速校验 512B 扇区哈希，
            间隔 _mbr_interval (0.25s)。检测到篡改 → 立即回滚，不等待
            关键目录的慢速递归扫描，也不被 load_governor 降载拉长。
          - 阶段 2 (按 _interval 节流): _check_critical_dirs_only() 关键目录
            快照校验 (System32 等上万文件，负载高时由降载控制器放宽到
            5s/10s，不影响阶段 1 的灵敏性)。
        收到 notify_process_created 时由 Event.set/clear 打断 wait，
        从而在"进程创建事件发生后"立即执行一轮 check。burst 抑制保证
        短时间密集事件不会把监控线程打爆。
        """
        logger.info('MBR 保护监控线程已启动')
        while not self._stop_event.is_set():
            loop_start = time.time()
            try:
                # 扇区备份延迟补齐：驱动加载慢/早启备份失败时，驱动就绪后
                # 自动重试补备 (节流 5s)，成功后扇区保护才真正开始校验
                self._try_repair_sector_backup()
                # 内核 MBR 写拦截掉线自动重挂（防止"拦截成功一次后就失效"）
                self._try_rearm_driver_mbr()
                if self._has_backup and self._enabled:
                    # 消费进程上下文（可能为 None：说明是常规轮询触发）
                    _ctx = self._consume_proc_event_context()
                    # 阶段 1：扇区 (MBR/VBR) 快速校验 + 立即回滚
                    sector_events = self._check_sectors_only()
                    if sector_events:
                        self._handle_sector_events(sector_events)
                    # 阶段 2：关键目录快照校验（按 _interval 节流）
                    if time.time() - self._last_crit_check >= self._interval:
                        self._last_crit_check = time.time()
                        dir_events = self._check_critical_dirs_only()
                        if dir_events:
                            self._handle_dir_events(dir_events)
                    with self._lock:
                        self._stats['checks'] += 1
            except Exception as e:
                logger.error(f'MBR 校验异常: {e}')

            # 短等待（扇区快速轮询），扣除本轮耗时避免漂移；
            # notify set/clear 打断 wait → 下一轮立即 check
            elapsed = time.time() - loop_start
            wait = max(0.02, self._mbr_interval - elapsed)
            self._stop_event.wait(wait)

        logger.info('MBR 保护监控线程已停止')

    # ---- 启停 ----

    def _emit_degraded_alert(self):
        """引导扇区保护不可用（未读到扇区备份）时，一次性显式告警。

        修复"start() 因关键目录快照成功返回 True，掩盖 MBR 扇区保护
        完全失效"的静默降级：非管理员运行时驱动加载失败 + 物理盘读取
        被拒，若不告警，病毒改写 MBR 时保护全程无感知。
        """
        if self._degraded_alerted:
            return
        self._degraded_alerted = True
        try:
            if self._on_threat:
                self._on_threat({
                    'type': 'mbr',
                    'device': None,
                    'label': 'MBR 扇区保护未生效',
                    'file': None,
                    'change_kind': 'degraded',
                    'message': self._degraded_reason
                               or 'MBR/引导扇区保护未生效',
                    'severity': 'critical',
                    'auto_restored': False,
                    'timestamp': time.time(),
                })
        except Exception:
            pass

    def start(self):
        """启动 MBR 保护监控 (先启用内核写拦截, 再启动轮询兜底)。

        顺序修正 (2026-09-08)：**先尝试加载/建立备份，再启驱动拦截，最后
        启监控线程**。驱动加载较慢时，start() 早期的扇区备份可能失败——
        此时不 return False（否则 MBR 保护直接不启动，实际是全程无保护），
        而是先启动监控线程，由 _try_repair_sector_backup() 在驱动就绪后
        自动补备扇区，避免"备份失败一次便永久降级"。
        """
        with self._lock:
            if self._running:
                return True
            # 先尝试加载磁盘备份, 若无则创建新备份
            if not self._has_backup:
                if not self._load_backup_from_disk():
                    if not self.create_backup():
                        # 备份失败不阻断启动：能否拿到扇区备份取决于驱动
                        # 就绪状态，交由监控线程延迟补备；只有关键目录快照
                        # 也会在 _run 中兜底。
                        logger.warning(
                            '首次创建 MBR 备份暂失败（驱动可能未就绪），'
                            '将由监控线程在驱动就绪后自动补备')
            # 内核 diskmon 事前拦截 (失败则仅靠用户态轮询)
            self._enable_driver_mon()
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run, name='PSLS-MBRProtector', daemon=True)
            self._thread.start()
            self._running = True
            logger.info('MBR 保护已启动')
            return True

    def stop(self):
        """停止 MBR 保护监控 (关闭内核拦截 + 停轮询线程)。"""
        with self._lock:
            if not self._running:
                return
            self._stop_event.set()
            self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._disable_driver_mon()
        logger.info('MBR 保护已停止')

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    @property
    def driver_mon_enabled(self) -> bool:
        """内核 diskmon 引导扇区写拦截当前是否生效。"""
        return self._driver_mon_ok

    @property
    def driver_dir_enabled(self) -> bool:
        """内核 minifilter 关键目录事前写入拦截是否生效。"""
        return self._driver_dir_ok

    def set_enabled(self, enabled: bool):
        self._enabled = bool(enabled)

    def set_poll_interval(self, interval: float) -> None:
        """动态调整关键目录检查频率（负载严重时由降载控制器拉长到 5s / 10s）。

        注意：仅影响阶段 2 关键目录快照校验的节流间隔；
        **不**影响阶段 1 的 MBR/扇区快速轮询（_mbr_interval 固定 0.25s，
        512B 哈希开销极小的关键防护路径不随负载降频）。
        内部至少保留 1s 最小值；设置后下一轮自动使用新值，无需重启线程。
        """
        try:
            v = float(interval)
            if v <= 0:
                return
            self._interval = max(1.0, v)
        except Exception:
            return

    def set_mbr_poll_interval(self, interval: float) -> None:
        """调整 MBR/引导扇区快速轮询间隔（秒, 最小 0.05s）。

        默认 0.25s。仅在用户明确要求放宽/收紧扇区校验频率时调用。
        """
        try:
            v = float(interval)
            if v <= 0:
                return
            self._mbr_interval = max(0.05, v)
        except Exception:
            return

    # ============================================================
    #  进程事件触发 (规避 GUI "无响应" + 提升响应速度)
    # ============================================================
    #
    # 背景：即使 CPU/RAM 指标都低，1s 轮询对关键目录做递归扫描（System32
    # 上万文件、config hives 等）仍可能把线程占满——虽然保护线程是独立的，
    # 但 if self._auto_restore 在 restore_file 中执行 shutil.rmtree / sfc.exe
    # 等操作会与桥接的 _apply_reductions / _on_mbr_threat 在主线程上形成
    # 长消息链，导致 5+ 秒无响应。
    #
    # 思路：
    #   - 保留独立线程 + 兜底 1s 轮询（默认 1s，降载时自动拉到 5/10s）
    #   - 新增 notify_process_created()：驱动进程创建事件回调 → 打断 wait，
    #     下一轮立刻执行 check，而不是等下个 1s 间隔到期。
    #   - burst 抑制：400ms 内重复 notify 不重复触发，避免系统登录时
    #     100+ 进程/秒 把 MBRProtector 刷死。
    def notify_process_created(self, pid: int, image_path: str = '') -> None:
        """通知监控线程：刚有新进程创建 → 立刻做一轮关键目录/扇区校验。

        典型调用方：bridge.py 里 ProcessCreateEvent 回调（驱动的 PsSetCreateProcessNotify
        事件）。任何线程均可安全调用。

        若监控线程未启动：同步执行一轮 check 并立即处置（用于未启动时手动触发、
        单元测试场景，避免依赖 _stop_event.wait 循环）。
        """
        # burst 抑制：距上次真实触发不足 _burst_interval 秒 → 合并到下一轮
        now = time.time()
        if (now - self._last_proc_trigger_ts) < self._burst_interval:
            return
        self._last_proc_trigger_ts = now
        self._pending_proc_pid = int(pid) if pid is not None else None
        self._pending_proc_image = str(image_path or '')

        if self._running and self._thread and self._thread.is_alive():
            try:
                # 打断 _stop_event.wait → 下一轮 check 立刻执行
                self._stop_event.set()
                self._stop_event.clear()
            except Exception:
                pass
            return
        # 监控线程未启动：同步执行一轮 check（便于测试 + 手动触发防御）
        try:
            if not self._enabled:
                return
            self._consume_proc_event_context()
            with self._lock:
                crit_dirs = list(self._critical_dirs_expanded)
                watch_dirs = list(self._watch_only_dirs_expanded)
                store_ready = bool(getattr(self._critical_snapshot, '_store', None))
            # 即使没备份引导扇区，仍执行关键目录快照 check（用户关心的
            # mkdir config\OSDATA、deleted_file 等攻击都在关键目录层）
            tampered: list = []
            if self._has_backup:
                tampered = self._check_all()
            elif crit_dirs and store_ready:
                # 仅在快照已就绪时做 check；快照尚未就绪（start() 还在
                # 创建/加载备份期间）直接跳过，避免把"目录基线"里所有
                # 现有文件误报为 new_file（截图里 623/303 条假告警的根因）。
                tampered = self._critical_snapshot.check(
                    crit_dirs, watch_dirs=watch_dirs)
            if tampered:
                self._handle_tamper(tampered)
            with self._lock:
                self._stats['checks'] += 1
        except Exception as e:
            logger.error(f'同步进程触发校验异常: {e}')

    def _consume_proc_event_context(self) -> Optional[Tuple[int, str]]:
        """监控线程内部（单消费者）消费一次进程事件上下文。线程安全。"""
        pid = self._pending_proc_pid
        img = self._pending_proc_image
        self._pending_proc_pid = None
        self._pending_proc_image = None
        if pid is None and not img:
            return None
        return (pid or 0, img or '')

    def get_stats(self) -> dict:
        """获取统计信息。"""
        with self._lock:
            return dict(self._stats)

    def get_backup_info(self) -> List[dict]:
        """获取已备份设备 + 关键目录快照摘要。"""
        result: List[dict] = []
        with self._lock:
            for path, info in self._backups.items():
                result.append({
                    'device': path,
                    'label': info['label'],
                    'type': info.get('type', 'mbr'),
                    'hash': info['hash'][:16] + '...',
                })
            # 关键目录快照摘要
            result.extend(self._critical_snapshot.snapshot_info())
        return result

    def get_critical_dirs_info(self) -> dict:
        """返回关键目录保护的运行时摘要 (供 bridge 向前端展示)。"""
        with self._lock:
            dirs = list(self._critical_dirs_expanded)
        snapshot_items = self._critical_snapshot.snapshot_info()
        total_files = 0
        overflow_any = False
        for s in snapshot_items:
            try:
                total_files += int(str(s.get('hash', '0 files')).split()[0])
            except Exception:
                pass
            if s.get('overflow'):
                overflow_any = True
        return {
            'count': len(dirs),
            'dirs': dirs,
            'files_tracked': total_files,
            'overflow': overflow_any,
            'driver_hook_enabled': self._driver_dir_ok,
        }

    def get_recent_events(self, limit: int = 20) -> list:
        """获取最近事件 (简化: 返回统计摘要)。"""
        return [{
            'time': time.time(),
            'event': 'check_complete',
            'checks': self._stats['checks'],
        }]
