# -*- coding: utf-8 -*-
"""
psls_driver_bridge.py — PSLS 内核驱动用户态桥接层

职责:
  1. CreateFile 打开 \\.\PSLS 设备 (IoCreateSymbolicLink 创建的 DOS 符号链接)
  2. DeviceIoControl 包装所有 IOCTL
  3. 后台轮询线程从事件池拉事件
  4. 将事件转成 Python dataclass / dict 格式交给上层消费

和现有架构的集成:
  - 替换 etw_monitor.py 的 PowerShell+WMI 进程创建通知 (延迟从 ~500ms → ~5ms)
  - 替换 process_protection.py 里的 psutil 进程轮询
  - 在 gui_entry.py 服务启动后调用 set_psls_pid() 让内核开始防护

线程模型:
  - 本文件只做 IOCTL + 事件消费, 不做扫描/判定 (留给 scan_engine)
  - poll_events 调用会阻塞等待事件 (设备驱动侧 EventPool 唤醒)
  - ack_event 把用户态判定结果回传内核

开发/调试:
  - 驱动未加载时, __init__ 会捕获 FileNotFoundError/AccessDenied,
    所有方法变成空操作 (silent degrade), 上层不需要改代码
"""

import os
import sys
import time
import threading
import struct
from typing import Callable, List, Optional, Dict, Any
from dataclasses import dataclass, field

from utils.logger import get_logger

logger = get_logger('driver_bridge')

# ctypes 声明
import ctypes
import ctypes.wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ  = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING    = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

kernel32.CreateFileW.restype = ctypes.wintypes.HANDLE
kernel32.CreateFileW.argtypes = [
    ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
    ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.HANDLE,
]

kernel32.DeviceIoControl.restype = ctypes.wintypes.BOOL
kernel32.DeviceIoControl.argtypes = [
    ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
    ctypes.c_void_p, ctypes.wintypes.DWORD,
    ctypes.c_void_p, ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_void_p,
]

kernel32.CloseHandle.restype = ctypes.wintypes.BOOL
kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]

kernel32.QueryDosDeviceW.restype = ctypes.wintypes.DWORD
kernel32.QueryDosDeviceW.argtypes = [
    ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPWSTR, ctypes.wintypes.DWORD,
]


# ========================================================================
# IOCTL 值 (和 psls_shared.h 保持完全一致)
# ========================================================================

def _ctl_code(dev, fn, method=0, access=0):
    return ((dev << 16) | (access << 14) | (fn << 2) | method)

FILE_DEVICE_PSLS = 0x8000
METHOD_BUFFERED  = 0

IOCTL_QUERY_STATUS   = _ctl_code(FILE_DEVICE_PSLS, 0x001)
IOCTL_GET_VERSION    = _ctl_code(FILE_DEVICE_PSLS, 0x002)
IOCTL_SET_CONFIG     = _ctl_code(FILE_DEVICE_PSLS, 0x010)
IOCTL_GET_CONFIG     = _ctl_code(FILE_DEVICE_PSLS, 0x011)
IOCTL_SET_PSLS_PID   = _ctl_code(FILE_DEVICE_PSLS, 0x012)
IOCTL_POLL_EVENTS    = _ctl_code(FILE_DEVICE_PSLS, 0x020)
IOCTL_ACK_EVENT      = _ctl_code(FILE_DEVICE_PSLS, 0x021)
IOCTL_BLOCK_PROCESS  = _ctl_code(FILE_DEVICE_PSLS, 0x030)
IOCTL_ALLOW_PROCESS  = _ctl_code(FILE_DEVICE_PSLS, 0x031)
IOCTL_TERMINATE_PROC = _ctl_code(FILE_DEVICE_PSLS, 0x032)
IOCTL_SET_PROTECTED_DIR   = _ctl_code(FILE_DEVICE_PSLS, 0x035)
IOCTL_SET_EXEMPT_DIR      = _ctl_code(FILE_DEVICE_PSLS, 0x03D)
IOCTL_CLEAR_PROTECTED_DIR = _ctl_code(FILE_DEVICE_PSLS, 0x036)
IOCTL_SET_MBR_PROTECT     = _ctl_code(FILE_DEVICE_PSLS, 0x037)
IOCTL_SET_BOOT_PROTECT    = _ctl_code(FILE_DEVICE_PSLS, 0x038)
IOCTL_SET_BOOT_FILES      = _ctl_code(FILE_DEVICE_PSLS, 0x039)
IOCTL_SET_KILLLIST        = _ctl_code(FILE_DEVICE_PSLS, 0x03A)
IOCTL_SET_SHADOW_CONFIG   = _ctl_code(FILE_DEVICE_PSLS, 0x03B)
IOCTL_QUERY_SHADOW_STATS  = _ctl_code(FILE_DEVICE_PSLS, 0x03C)


# ========================================================================
# 桥接协议版本 / 能力位 / 超时与失败策略
# （语义借鉴 Xdows-Security-Driver；**Python 侧为纯增量**，不改动既有
#   结构体布局与 IOCTL 载荷，故不影响已能正常加载驱动的环境）
# ========================================================================
# 设计原则：
#   1. 版本双向可比：回连后先查内核版本，低版按低版语义工作，不假设新字段存在；
#   2. 能力位掩码：不认识/未上报的能力一律视为"不支持"，而非报错（前向兼容）；
#   3. 新字段一律追加到结构体尾部，对端按 struct_size 截断读取；
#   4. 失败策略显式化：基础设施不可用时默认 **fail-open（放行）**，
#      仅内核硬规则命中或已确认威胁才 fail-closed。
PROTOCOL_VERSION = 1

# 能力位（与内核上报的能力掩码对应；未知位忽略）
CAP_PROCESS_BLOCK     = 0x0001   # 进程拦截
CAP_TERMINATE         = 0x0002   # 强制终止
CAP_PROTECTED_DIR     = 0x0004   # 受保护目录写拦截
CAP_MBR_PROTECT       = 0x0008   # MBR 保护
CAP_BOOT_PROTECT      = 0x0010   # 引导扇区保护
CAP_KILLLIST          = 0x0020   # 动态拦截名单
CAP_TIMEOUT_DECISION  = 0x0040   # 支持 Allow/Block/Timeout 三态决策

# 超时参数集中定义（毫秒），消除散落的魔法数字
KERNEL_WAIT_TIMEOUT_MS   = 5000    # 内核等待用户态决策上限
USER_DECISION_TIMEOUT_MS = 30000   # 用户态给出决策上限
ALLOW_CACHE_TTL_MS       = 300000  # 放行结果缓存 TTL（5 分钟）


# ========================================================================
# 结构体解析
# ========================================================================

PSLS_DEVICE_PATH = r'\\.\PSLS'
PSLS_MAX_PATH = 512
PSLS_MAX_CMD  = 1024

EVENT_HEADER_SIZE = 20  # 4+1+1+2+8+4 = 20 bytes (packed, no padding)
STATUS_SIZE       = 32  # PSLS_STATUS packed = 6*4 + 6*1 + 2 pad = 32 bytes

# 事件类型编号 (和内核侧 psls_shared.h 一致)
EVENT_PROCESS_CREATE     = 0x01
EVENT_PROCESS_DELETE     = 0x02
EVENT_REG_PRE_SET_VALUE  = 0x10
EVENT_REG_PRE_CREATE_KEY = 0x11
EVENT_REG_PRE_DELETE_KEY = 0x12
EVENT_IMAGE_LOAD         = 0x20
EVENT_HANDLE_AUDIT       = 0x21   # 进程句柄打开审计 (OB_CALLBACKS)
EVENT_BLOCK_RESULT       = 0x30
EVENT_FILE_BLOCKED       = 0x40   # minifilter 拦截文件写入
EVENT_FILE_SHADOWED      = 0x41   # 写前影子备份结果 (阶段二)
EVENT_NET_BLOCKED        = 0x50   # WFP 拦截网络连接
EVENT_DISK_BLOCKED       = 0x60   # diskmon 拦截引导扇区写入

# 影子备份 status/reason 常量 (与 psls_shared.h 一致)
SHADOW_STATUS_OK   = 0
SHADOW_STATUS_SKIP = 1
SHADOW_STATUS_MISS = 2
SHADOW_STATUS_FAIL = 3

SHADOW_REASON_OK        = 0
SHADOW_REASON_IRQL      = 1
SHADOW_REASON_TOO_LARGE = 2
SHADOW_REASON_TIMEOUT   = 3
SHADOW_REASON_IO_ERROR  = 4
SHADOW_REASON_DEDUP     = 5

# 影子配置固定部分: enable(4) + generation_id(4) + shadow_root[260 个 WCHAR]
SHADOW_ROOT_CHARS = 260
SHADOW_MAX_DIRS   = 8
SHADOW_CONFIG_BASE_SIZE = 8 + SHADOW_ROOT_CHARS * 2   # 528

SHADOW_STATUS_NAMES = {
    SHADOW_STATUS_OK: 'ok',
    SHADOW_STATUS_SKIP: 'skip',
    SHADOW_STATUS_MISS: 'miss',
    SHADOW_STATUS_FAIL: 'fail',
}
SHADOW_REASON_NAMES = {
    SHADOW_REASON_OK: 'ok',
    SHADOW_REASON_IRQL: 'irql',
    SHADOW_REASON_TOO_LARGE: 'too_large',
    SHADOW_REASON_TIMEOUT: 'timeout',
    SHADOW_REASON_IO_ERROR: 'io_error',
    SHADOW_REASON_DEDUP: 'dedup',
}


def _utf16_to_str(buf: bytes, max_len: int) -> str:
    """从 UTF-16LE 字节数组提取字符串"""
    try:
        # 找 \0\0 终止符
        end = buf.find(b'\x00\x00')
        if end >= 0:
            buf = buf[:end]
        else:
            buf = buf[:max_len * 2]
        return buf.decode('utf-16-le', errors='replace')
    except Exception:
        return ''


def _utf16_to_str_exact(buf: bytes, max_chars: int) -> str:
    """严格按 WCHAR 数解析 UTF-16LE 字符串（以首个 NUL 字符截断）。

    与 _utf16_to_str 的区别：后者用 find(b'\\x00\\x00') 定位终止符，对
    "ASCII + NUL" 形态会命中最后一个字符的高字节并丢掉末字符（既有历史行为，
    此处不改动以免影响其它事件）。影子事件的 orig_path 决定回滚写回目标，
    必须精确，故单独使用本函数。
    """
    try:
        end = max_chars
        for i in range(max_chars):
            if buf[i * 2] == 0 and buf[i * 2 + 1] == 0:
                end = i
                break
        return buf[:end * 2].decode('utf-16-le', errors='replace')
    except Exception:
        return ''


def _win32_to_nt_path(path: str) -> str:
    """Win32 路径 → NT 设备路径

    minifilter 的规范化文件名使用 NT 设备前缀
    (如 \\Device\\HarddiskVolume3\\Program Files\\PSLS)，
    通过 QueryDosDeviceW 把盘符映射为设备名后拼接。
    """
    try:
        abs_path = os.path.abspath(path)
        drive, rest = os.path.splitdrive(abs_path)
        if not drive or not drive.endswith(':'):
            return path
        buf = ctypes.create_unicode_buffer(1024)
        n = kernel32.QueryDosDeviceW(drive, buf, 1024)
        if not n:
            return path
        # QueryDosDeviceW 返回多串（\0 分隔），取第一串
        device = buf.value
        if not device:
            return path
        return device + rest
    except Exception:
        return path


# ---- 盘符 → NT 设备名缓存（进程创建回调每秒可能调用成百上千次， ----
#      QueryDosDeviceW 每次一次系统调用太贵，这里做进程级 TTL 缓存。 ----
_DOS_DEVICE_CACHE_LOCK = threading.Lock()
_DOS_DEVICE_CACHE: Dict[str, str] = {}          # "C:" -> "\Device\HarddiskVolume3"
_DOS_DEVICE_CACHE_TS: float = 0.0
_DOS_DEVICE_CACHE_TTL: float = 300.0            # 5 分钟刷新一次（盘符热插拔极罕见）


def _refresh_dos_device_cache() -> None:
    """枚举 A:~Z: 并把 QueryDosDeviceW 结果写入缓存。失败静默保留旧值。"""
    new_cache: Dict[str, str] = {}
    try:
        buf = ctypes.create_unicode_buffer(1024)
        for letter_ord in range(ord('A'), ord('Z') + 1):
            drive = f'{chr(letter_ord)}:'
            try:
                n = kernel32.QueryDosDeviceW(drive, buf, 1024)
                if not n:
                    continue
                device = buf.value
                if not device:
                    continue
                # QueryDosDeviceW 可能把 \??\ 前缀或多个候选用 \0 分隔返回
                for candidate in device.split('\0'):
                    candidate = candidate.strip()
                    if not candidate:
                        continue
                    # 去除 \??\ 前缀（Vista+ 把盘符符号链接挂在 \??\ 下）
                    if candidate.startswith('\\??\\'):
                        candidate = candidate[4:]
                    if candidate:
                        new_cache[candidate] = drive
                        break
            except Exception:
                continue
    except Exception:
        return
    # 只在成功收集到至少一个映射时替换（避免偶发系统调用失败清空缓存）
    if new_cache:
        global _DOS_DEVICE_CACHE, _DOS_DEVICE_CACHE_TS
        with _DOS_DEVICE_CACHE_LOCK:
            _DOS_DEVICE_CACHE = new_cache
            _DOS_DEVICE_CACHE_TS = time.time()


def _nt_path_to_win32(nt_path: str) -> str:
    """NT 设备路径 → Win32 盘符路径（内核回调 image_path 的反向转换）。

    内核 procmon.c / PsSetCreateProcessNotifyRoutineEx 给出的
    CreateInfo->ImageFileName 是 NT 名：
        \\Device\\HarddiskVolume3\\Users\\admin\\Desktop\\virus.exe
    需要转换成
        C:\\Users\\admin\\Desktop\\virus.exe
    才能被 os.path.* / signature_verifier / 可信目录判定正确识别。

    转换策略：
      1. 惰性构建/刷新「\Device\HarddiskVolumeN -> C:」映射缓存
         （QueryDosDeviceW 枚举 A:~Z: 取首个有效目标）。
      2. 对入参路径最长前缀匹配命中缓存 → 替换为盘符。
      3. 无匹配时原样返回（上层再用 psutil.Process(pid).exe() 兜底）。

    入参为 NT 名已含前导反斜杠，大小写不敏感匹配即可。
    """
    if not nt_path:
        return ''
    try:
        p = str(nt_path).replace('/', '\\')
        # 去 \??\ 前缀（极少见情况，防御性）
        if p.startswith('\\??\\'):
            p = '\\Device\\' + p[4:]
        # 1) 确保缓存有效
        with _DOS_DEVICE_CACHE_LOCK:
            now = time.time()
            if not _DOS_DEVICE_CACHE or (now - _DOS_DEVICE_CACHE_TS) > _DOS_DEVICE_CACHE_TTL:
                # 非持锁刷新，避免缓存重建时阻塞其他读取线程
                pass
            cache_snapshot = dict(_DOS_DEVICE_CACHE)
        if not cache_snapshot:
            _refresh_dos_device_cache()
            with _DOS_DEVICE_CACHE_LOCK:
                cache_snapshot = dict(_DOS_DEVICE_CACHE)
        else:
            # 后台惰性刷新：在已存在快照基础上，如到期则异步刷新一次
            with _DOS_DEVICE_CACHE_LOCK:
                ts = _DOS_DEVICE_CACHE_TS
            if (time.time() - ts) > _DOS_DEVICE_CACHE_TTL:
                try:
                    threading.Thread(target=_refresh_dos_device_cache,
                                     daemon=True, name='DOS-Cache-Refresh').start()
                except Exception:
                    pass

        # 2) 最长前缀匹配（遍历 value 长度倒序即可保证 HarddiskVolume10 先于 Volume1 命中）
        p_lower = p.lower()
        candidates = sorted(
            ((dev_prefix, drive_letter)
             for dev_prefix, drive_letter in cache_snapshot.items()),
            key=lambda kv: len(kv[0]),
            reverse=True,
        )
        for dev_prefix, drive_letter in candidates:
            dev_lower = dev_prefix.lower()
            if not dev_lower.endswith('\\'):
                dev_lower_try = dev_lower + '\\'
            else:
                dev_lower_try = dev_lower
            if p_lower.startswith(dev_lower_try):
                rest = p[len(dev_lower_try) - 1:]  # 保留 '\'
                return drive_letter + rest
            # 处理不带尾反斜杠的前缀相等情况（极短路径）
            if p_lower == dev_lower:
                return drive_letter + '\\'
        return nt_path
    except Exception:
        return nt_path


@dataclass
class ProcessCreateEvent:
    """进程创建事件"""
    event_id: int = 0
    timestamp_ns: int = 0
    process_id: int = 0
    parent_pid: int = 0
    session_id: int = 0
    image_path: str = ''
    command_line: str = ''
    parent_path: str = ''
    is_signed: int = 0


@dataclass
class RegKeyEvent:
    """注册表操作事件"""
    event_id: int = 0
    timestamp_ns: int = 0
    event_type: int = 0     # SET_VALUE / CREATE_KEY / DELETE_KEY
    pid: int = 0
    full_path: str = ''
    value_name: str = ''
    value_size: int = 0


@dataclass
class ImageLoadEvent:
    """映像加载事件"""
    event_id: int = 0
    timestamp_ns: int = 0
    pid: int = 0
    image_base: int = 0
    image_size: int = 0
    image_path: str = ''
    load_count: int = 1   # 聚合窗口内该 PID 的映像加载次数 (v1.1+)


@dataclass
class HandleAuditEvent:
    """进程句柄打开审计事件 (OB_CALLBACKS, 内核 0x21)

    语义: 某进程以"注入特征"访问位打开另一进程句柄, 且该打开
    发生在非 PSLS 自身、非 wmiprvse 纯 VM_READ 枚举的前提下。
    count 为聚合窗口 (5s) 内同 (source,target) 的累计次数。
    """
    event_id: int = 0
    timestamp_ns: int = 0
    source_pid: int = 0     # 发起打开者
    target_pid: int = 0     # 被打开目标进程
    desired_access: int = 0 # 与注入掩码相交后的位 (PROCESS_VM_*|CREATE_THREAD 等)
    count: int = 1          # 30s 窗口聚合次数
    first_ts_ns: int = 0    # 首见时间戳


@dataclass
class BlockResultEvent:
    """
    内核层已执行拦截的结果通知。

    来源:
      - procmon.c enable_proc_terminate=1 时 KillList 命中 → 内核 ZwTerminateProcess
      - regmon.c ForceBlockKeys[] 命中 → 内核 return STATUS_ACCESS_DENIED

    payload 是复用的 PSLS_PROCESS_CREATE_PAYLOAD 或 PSLS_REG_PRE_KEY_PAYLOAD,
    由 source 字段区分。
    """
    event_id: int = 0
    timestamp_ns: int = 0
    source: str = 'unknown'   # 'procmon_kill' | 'regmon_block'
    pid: int = 0
    path: str = ''            # 进程图像路径或注册表路径


@dataclass
class FileBlockEvent:
    """
    minifilter 文件写入拦截事件 (R0 级实时拦截)。

    来源: filemon.c 的 FilePreWrite / FilePreSetInfo 回调
    拦截时机: IRP_MJ_WRITE / IRP_MJ_SET_INFORMATION 的 PreOperation 阶段
              (数据尚未写入磁盘, 真正的事前拦截)

    reason:
      'batch_write'       — 进程短时间内批量写入超过阈值 (勒索行为)
      'protected_file'    — 写入 PSLS 受保护目录下的文件
      'ransom_extension'  — 文件被重命名为勒索扩展名 (.locked/.encrypted 等)
    """
    event_id: int = 0
    timestamp_ns: int = 0
    pid: int = 0
    write_count: int = 0
    file_path: str = ''
    reason: str = ''          # 'batch_write' | 'protected_file' | 'ransom_extension'


@dataclass
class NetBlockEvent:
    """
    WFP 网络连接拦截事件 (R0 级实时拦截)。

    来源: netmon.c 的 NetCalloutV4 回调
    拦截时机: ALE_AUTH_CONNECT_V4 层 (出站连接建立前)

    reason:
      'blocked_pid'    — 进程已被标记为禁止联网 (恶意进程 C2 回连拦截)
      'suspicious_port'— 连接可疑端口 (已知恶意 C2 端口)
      'blacklist_ip'   — 连接黑名单 IP
    """
    event_id: int = 0
    timestamp_ns: int = 0
    pid: int = 0
    remote_ip: str = ''       # 点分十进制 IPv4
    remote_port: int = 0
    protocol: str = ''        # 'TCP' | 'UDP' | str(protocol_num)
    direction: str = ''       # 'outbound' | 'inbound'
    reason: str = ''          # 'blocked_pid' | 'suspicious_port' | 'blacklist_ip'
    process_path: str = ''


@dataclass
class DiskBlockEvent:
    """
    diskmon 引导扇区(MBR)写入拦截事件 (R0 级事前拦截)。

    来源: diskmon.c 的 DiskMonDispatch 在 IRP_MJ_WRITE 阶段拦截
    拦截时机: 用户态进程对物理磁盘第 0 扇区发起写入 (数据未落盘)
    """
    event_id: int = 0
    timestamp_ns: int = 0
    pid: int = 0
    offset: int = 0
    device: str = ''          # "\Device\Harddisk0\DR0"
    reason: str = ''          # 'mbr_write_blocked'


@dataclass
class ShadowBackupEvent:
    """写前影子备份结果事件 (阶段二: 零窗口勒索回滚)。

    来源: filemon.c 的 FilePreWrite / FilePreSetInfo 在放行原写操作之前,
    对命中影子作用域的文件同步保存其"写前原像"到影子仓库。

    status: 'ok' | 'skip' | 'miss' | 'fail'
    reason: 'ok' | 'irql' | 'too_large' | 'timeout' | 'io_error' | 'dedup'
      - status=='ok'  : shadow_path 即写前原像, 应交给回滚引擎 ingest
      - status=='skip': dedup/too_large, 已在别处或超限, 不入仓
      - status=='miss': IRQL 不允许未备份即放行 (该文件无写前原像)
      - status=='fail': 备份失败 (timeout/io_error)
    """
    event_id: int = 0
    timestamp_ns: int = 0
    orig_path: str = ''       # 原始文件路径 (NT 设备路径)
    shadow_path: str = ''     # 影子文件路径 (NT 设备路径)
    orig_size: int = 0        # 原始文件字节数
    status: int = 0           # SHADOW_STATUS_*
    reason: int = 0           # SHADOW_REASON_*
    pid: int = 0
    status_name: str = ''     # status 的可读名
    reason_name: str = ''     # reason 的可读名


@dataclass
class DriverStatus:
    version_major: int = 0
    version_minor: int = 0
    version_patch: int = 0
    proc_create_count: int = 0
    reg_mon_count: int = 0
    image_load_count: int = 0
    blocked_count: int = 0
    psls_pid: int = 0
    proc_mon_enabled: bool = False
    reg_mon_enabled: bool = False
    image_mon_enabled: bool = False
    psls_protect_enabled: bool = False
    file_filter_enabled: bool = False   # minifilter 文件写入拦截
    net_filter_enabled: bool = False    # WFP 网络连接拦截
    disk_mon_enabled: bool = False      # diskmon 引导扇区写拦截


def _parse_events(buf: bytes) -> List[Any]:
    """解析 EVENT_POLL 返回的批量事件缓冲区"""
    events = []
    pos = 0
    total = len(buf)

    while pos + EVENT_HEADER_SIZE <= total:
        # PSLS_EVENT_HEADER: 20 bytes packed (4+1+1+2+8+4)
        hdr = struct.unpack_from('<IBBHQI', buf, pos)
        event_id = hdr[0]
        event_type = hdr[1]
        reserved = hdr[2]
        flags = hdr[3]
        timestamp_ns = hdr[4]  # KeQueryPerformanceCounter, 不是真正纳秒, 但唯一
        payload_size = hdr[5]

        pos += EVENT_HEADER_SIZE
        if pos + payload_size > total:
            break

        payload = buf[pos:pos + payload_size]
        pos += payload_size

        events.append(_decode_event(event_id, event_type, timestamp_ns, payload))

    return events


def _decode_event(event_id: int, event_type: int, timestamp_ns: int, payload: bytes):
    if event_type in (EVENT_PROCESS_CREATE, EVENT_PROCESS_DELETE):
        # PSLS_PROCESS_CREATE_PAYLOAD: 4+4+4+4+512+1024+512+4+1+1+6 = 2077 bytes
        # packed 对齐实际布局需要在 C 侧 - 我们用偏移解析
        if len(payload) < 2077:
            return None
        pid, ppid, sess = struct.unpack_from('<III', payload, 0)
        image_path = _utf16_to_str(payload[12:12 + PSLS_MAX_PATH], PSLS_MAX_PATH)
        cmdline = _utf16_to_str(payload[12 + PSLS_MAX_PATH:12 + PSLS_MAX_PATH + PSLS_MAX_CMD],
                                PSLS_MAX_CMD)
        parent_path = _utf16_to_str(
            payload[12 + PSLS_MAX_PATH + PSLS_MAX_CMD:
                    12 + PSLS_MAX_PATH + PSLS_MAX_CMD + PSLS_MAX_PATH],
            PSLS_MAX_PATH)
        offset = 12 + PSLS_MAX_PATH + PSLS_MAX_CMD + PSLS_MAX_PATH
        is_signed = payload[offset + 4] if offset + 5 < len(payload) else 0

        return ProcessCreateEvent(
            event_id=event_id, timestamp_ns=timestamp_ns,
            process_id=pid, parent_pid=ppid, session_id=sess,
            image_path=image_path, command_line=cmdline,
            parent_path=parent_path, is_signed=is_signed,
        )

    elif event_type in (EVENT_REG_PRE_SET_VALUE, EVENT_REG_PRE_CREATE_KEY, EVENT_REG_PRE_DELETE_KEY):
        # PSLS_REG_PRE_KEY_PAYLOAD: 4+4+512+512+1+7+8 = 1048 bytes packed
        if len(payload) < 1048:
            return None
        pid, = struct.unpack_from('<I', payload, 0)
        full_path = _utf16_to_str(payload[4:4 + PSLS_MAX_PATH], PSLS_MAX_PATH)
        value_name = _utf16_to_str(payload[4 + PSLS_MAX_PATH:
                                            4 + PSLS_MAX_PATH + PSLS_MAX_PATH],
                                    PSLS_MAX_PATH)
        offset = 4 + PSLS_MAX_PATH + PSLS_MAX_PATH + 1 + 7
        value_size, = struct.unpack_from('<q', payload, offset)
        return RegKeyEvent(
            event_id=event_id, timestamp_ns=timestamp_ns,
            event_type=event_type, pid=pid, full_path=full_path,
            value_name=value_name, value_size=value_size,
        )

    elif event_type == EVENT_IMAGE_LOAD:
        # PSLS_IMAGE_LOAD_PAYLOAD: 4+8+4+512+1+1+6 = 536 bytes
        # v1.1+ 尾部追加 load_count(4) → 540 bytes; 用 len>=540 兼容新旧
        if len(payload) < 536:
            return None
        pid = struct.unpack_from('<I', payload, 0)[0]
        img_base, img_size = struct.unpack_from('<QI', payload, 4)
        img_path = _utf16_to_str(payload[16:16 + PSLS_MAX_PATH], PSLS_MAX_PATH)
        load_count = 1
        if len(payload) >= 540:
            load_count = struct.unpack_from('<I', payload, 536)[0]
        return ImageLoadEvent(
            event_id=event_id, timestamp_ns=timestamp_ns,
            pid=pid, image_base=img_base, image_size=img_size,
            image_path=img_path, load_count=load_count,
        )

    elif event_type == EVENT_HANDLE_AUDIT:
        # PSLS_HANDLE_AUDIT_PAYLOAD: 4+4+4+4+8 = 24 bytes packed
        if len(payload) < 24:
            return None
        src_pid, tgt_pid, access, count = struct.unpack_from('<IIII', payload, 0)
        first_ts = struct.unpack_from('<Q', payload, 16)[0]
        return HandleAuditEvent(
            event_id=event_id, timestamp_ns=timestamp_ns,
            source_pid=src_pid, target_pid=tgt_pid,
            desired_access=access, count=count, first_ts_ns=first_ts,
        )

    elif event_type == EVENT_BLOCK_RESULT:
        # PSLS_BLOCK_RESULT_PAYLOAD: event_id(4) + pad(4) + timestamp_ns(8) +
        #   source(4) + pid(4) + path[512] = 536 bytes (默认对齐)
        if len(payload) >= 536:
            event_id_field, = struct.unpack_from('<I', payload, 0)
            src, pid = struct.unpack_from('<II', payload, 16)
            path = _utf16_to_str(payload[24:24 + PSLS_MAX_PATH], PSLS_MAX_PATH)
            source_name = {1: 'procmon_pre_block', 2: 'regmon_block'}.get(src, f'unknown_{src}')
            return BlockResultEvent(
                event_id=event_id, timestamp_ns=timestamp_ns,
                source=source_name, pid=pid, path=path,
            )
        # 兼容旧格式 (v2 procmon 用 PSLS_PROCESS_CREATE_PAYLOAD 作 block payload)
        elif len(payload) >= 2077:
            pid = struct.unpack_from('<I', payload, 0)[0]
            img_path = _utf16_to_str(payload[12:12 + PSLS_MAX_PATH], PSLS_MAX_PATH)
            return BlockResultEvent(
                event_id=event_id, timestamp_ns=timestamp_ns,
                source='procmon_kill', pid=pid, path=img_path,
            )
        elif len(payload) >= 1048:
            pid = struct.unpack_from('<I', payload, 0)[0]
            full_path = _utf16_to_str(payload[4:4 + PSLS_MAX_PATH], PSLS_MAX_PATH)
            return BlockResultEvent(
                event_id=event_id, timestamp_ns=timestamp_ns,
                source='regmon_block', pid=pid, path=full_path,
            )
        return BlockResultEvent(event_id=event_id, timestamp_ns=timestamp_ns)

    elif event_type == EVENT_FILE_BLOCKED:
        # PSLS_FILE_BLOCK_PAYLOAD: pid(4) + write_count(4) + file_path[512] + reason(1) + pad[3] = 524 bytes
        if len(payload) < 524:
            return None
        pid, write_count = struct.unpack_from('<II', payload, 0)
        file_path = _utf16_to_str(payload[8:8 + PSLS_MAX_PATH], PSLS_MAX_PATH)
        reason_code = payload[8 + PSLS_MAX_PATH]
        reason_map = {1: 'batch_write', 2: 'protected_file', 3: 'ransom_extension'}
        reason = reason_map.get(reason_code, f'unknown_{reason_code}')
        return FileBlockEvent(
            event_id=event_id, timestamp_ns=timestamp_ns,
            pid=pid, write_count=write_count, file_path=file_path, reason=reason,
        )

    elif event_type == EVENT_NET_BLOCKED:
        # PSLS_NET_BLOCK_PAYLOAD: pid(4) + remote_ip(4) + remote_port(2) + protocol(2) +
        #   direction(1) + reason(1) + pad[2] + process_path[512] = 528 bytes
        if len(payload) < 528:
            return None
        pid = struct.unpack_from('<I', payload, 0)[0]
        # remote_ip 在内核侧是网络字节序 (big-endian) 的 uint32,
        # 直接按字节读取即可得到 a.b.c.d
        ip_bytes = payload[4:8]
        remote_ip = '.'.join(str(b) for b in ip_bytes)
        remote_port, protocol_num = struct.unpack_from('<HH', payload, 8)
        direction_code = payload[12]
        reason_code = payload[13]
        process_path = _utf16_to_str(payload[16:16 + PSLS_MAX_PATH], PSLS_MAX_PATH)
        protocol_map = {6: 'TCP', 17: 'UDP'}
        protocol = protocol_map.get(protocol_num, str(protocol_num))
        direction = 'outbound' if direction_code == 1 else 'inbound'
        reason_map = {1: 'blacklist_ip', 2: 'suspicious_port', 3: 'blocked_pid'}
        reason = reason_map.get(reason_code, f'unknown_{reason_code}')
        return NetBlockEvent(
            event_id=event_id, timestamp_ns=timestamp_ns,
            pid=pid, remote_ip=remote_ip, remote_port=remote_port,
            protocol=protocol, direction=direction, reason=reason,
            process_path=process_path,
        )

    elif event_type == EVENT_DISK_BLOCKED:
        # PSLS_DISK_BLOCK_PAYLOAD: pid(4) + reason(4) + offset(8) + device[512] = 528 bytes
        if len(payload) < 16:
            return None
        pid, reason_code = struct.unpack_from('<II', payload, 0)
        offset = struct.unpack_from('<Q', payload, 8)[0]
        device = _utf16_to_str(payload[16:16 + PSLS_MAX_PATH], PSLS_MAX_PATH)
        # reason: 1=MBR(第0扇区)写, 2=VBR/ESP 受保护区域写, 3=旁路改写
        # (布局 IOCTL / SCSI WRITE 命令)
        reason_map = {
            1: 'mbr_write_blocked',
            2: 'boot_region_write_blocked',
            3: 'layout_scsi_write_blocked',
        }
        return DiskBlockEvent(
            event_id=event_id, timestamp_ns=timestamp_ns,
            pid=pid, offset=offset, device=device,
            reason=reason_map.get(reason_code, f'unknown_{reason_code}'),
        )

    elif event_type == EVENT_FILE_SHADOWED:
        # PSLS_SHADOW_PAYLOAD: orig_path[512] + shadow_path[512] +
        #   orig_size(8) + status(4) + reason(4) + pid(4) = 1044 bytes (packed)
        if len(payload) < 1044:
            return None
        orig_path = _utf16_to_str_exact(payload[0:PSLS_MAX_PATH],
                                        PSLS_MAX_PATH // 2)
        shadow_path = _utf16_to_str_exact(payload[PSLS_MAX_PATH:PSLS_MAX_PATH * 2],
                                          PSLS_MAX_PATH // 2)
        orig_size = struct.unpack_from('<Q', payload, PSLS_MAX_PATH * 2)[0]
        status, reason, pid = struct.unpack_from('<III', payload, PSLS_MAX_PATH * 2 + 8)
        return ShadowBackupEvent(
            event_id=event_id, timestamp_ns=timestamp_ns,
            orig_path=orig_path, shadow_path=shadow_path, orig_size=orig_size,
            status=status, reason=reason, pid=pid,
            status_name=SHADOW_STATUS_NAMES.get(status, f'unknown_{status}'),
            reason_name=SHADOW_REASON_NAMES.get(reason, f'unknown_{reason}'),
        )

    return None


# ========================================================================
# 主桥接类
# ========================================================================

class PSLSDriverBridge:
    """
    与 PSLS 内核驱动通信的用户态桥接。

    所有方法都是线程安全的 (单个 handle, DeviceIoControl 互斥)。
    驱动未加载时自动降级为 "所有方法返回空/False", 上层无需感知。

    用法:
        bridge = PSLSDriverBridge()
        if bridge.is_available:
            bridge.set_psls_pid(os.getpid())
            # 后台消费事件
            bridge.start_event_loop(on_process_create=lambda e: ...)
    """

    def __init__(self, poll_interval: float = 0.005):
        self._handle = INVALID_HANDLE_VALUE
        self._lock = threading.Lock()
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._event_thread: Optional[threading.Thread] = None
        self.is_available = False

        self._callbacks = {
            'process_create': [],
            'process_delete': [],
            'reg_key': [],
            'image_load': [],
            'handle_audit': [],
            'block_result': [],
            'file_blocked': [],
            'file_shadowed': [],
            'net_blocked': [],
            'disk_blocked': [],
            'any': [],
        }

        self._try_connect()

    # ------------------------------------------------------------------
    # 连接/断开
    # ------------------------------------------------------------------

    def _try_connect(self):
        """尝试打开内核设备, 失败则标记 unavailable"""
        try:
            access = GENERIC_READ | GENERIC_WRITE
            share = FILE_SHARE_READ | FILE_SHARE_WRITE
            handle = kernel32.CreateFileW(
                PSLS_DEVICE_PATH, access, share, None,
                OPEN_EXISTING, 0, None,
            )
            if handle != INVALID_HANDLE_VALUE:
                self._handle = handle
                self.is_available = True
                logger.info(f'驱动桥接已连接: handle={handle}')
            else:
                err = ctypes.get_last_error()
                logger.warning(f'驱动设备打开失败 (error={err}): '
                               f'可能驱动未加载')
                self.is_available = False
        except Exception as e:
            logger.warning(f'驱动桥接初始化异常: {e}')
            self.is_available = False

    def close(self):
        """关闭设备句柄, 停止事件循环"""
        self.stop_event_loop()
        if self._handle != INVALID_HANDLE_VALUE:
            try:
                kernel32.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = INVALID_HANDLE_VALUE
        self.is_available = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ------------------------------------------------------------------
    # 协议版本 / 能力 / 失败策略（纯增量，供自检与后续握手使用）
    # ------------------------------------------------------------------

    def query_protocol_version(self) -> int:
        """查询内核协议版本。

        返回 0 表示"未知"（驱动未加载 / IOCTL 不可用 / 老驱动无此功能），
        调用方应据此**按最低版本语义工作**，而不是报错。
        """
        buf = self._ioctl(IOCTL_GET_VERSION, out_size=8)
        if not buf or len(buf) < 4:
            return 0
        try:
            return int(struct.unpack_from('<I', buf, 0)[0])
        except Exception:
            return 0

    @staticmethod
    def supports(cap_mask: int, capability: int) -> bool:
        """能力位判定：未上报/未知能力一律视为**不支持**（安全默认）。"""
        try:
            return bool(int(cap_mask) & int(capability))
        except Exception:
            return False

    @staticmethod
    def policy_on_infra_failure() -> str:
        """基础设施不可用时的默认策略：**fail-open（放行）**。

        仅当内核硬规则命中、或已确认威胁时才 fail-closed；驱动未加载 /
        IOCTL 失败 / 版本不匹配等一律放行，避免把"驱动异常"放大成"全系统阻断"。
        """
        return 'fail-open'

    def get_protocol_info(self) -> dict:
        """协议自检信息（排障 / 写日志用）。"""
        ver = self.query_protocol_version()
        return {
            'expected_version': PROTOCOL_VERSION,
            'driver_version': ver,
            'version_known': ver > 0,
            'version_match': ver == PROTOCOL_VERSION,
            'timeouts_ms': {
                'kernel_wait': KERNEL_WAIT_TIMEOUT_MS,
                'user_decision': USER_DECISION_TIMEOUT_MS,
                'allow_cache_ttl': ALLOW_CACHE_TTL_MS,
            },
            'policy_on_infra_failure': self.policy_on_infra_failure(),
            'available': bool(getattr(self, 'is_available', False)),
        }

    # ------------------------------------------------------------------
    # 底层 DeviceIoControl
    # ------------------------------------------------------------------

    def _ioctl(self, code: int, in_buf: bytes = b'',
               out_size: int = 0) -> Optional[bytes]:
        """
        执行一次 DeviceIoControl。

        Returns:
            out bytes (可能为空), 或 None 表示失败 (驱动未加载或 IO 错误)
        """
        if not self.is_available or self._handle == INVALID_HANDLE_VALUE:
            return None

        with self._lock:
            out_array = ctypes.create_string_buffer(out_size) if out_size else None
            out_ptr = ctypes.cast(out_array, ctypes.POINTER(ctypes.c_byte)) if out_size else None
            out_len = ctypes.wintypes.DWORD()

            in_ptr = ctypes.c_char_p(in_buf) if in_buf else None

            ok = kernel32.DeviceIoControl(
                self._handle, code,
                in_ptr, len(in_buf) if in_buf else 0,
                out_ptr, out_size,
                ctypes.byref(out_len), None,
            )

            if not ok:
                err = ctypes.get_last_error()
                if err != 87:  # ERROR_INVALID_PARAMETER (偶发, 忽略)
                    logger.debug(f'DeviceIoControl 0x{code:04X} 失败: err={err}')
                return None

            if out_len.value == 0:
                return b''
            return bytes(out_array.raw[:out_len.value])

    # ------------------------------------------------------------------
    # 高层 API
    # ------------------------------------------------------------------

    def query_status(self) -> Optional[DriverStatus]:
        buf = self._ioctl(IOCTL_QUERY_STATUS, out_size=64)
        if not buf or len(buf) < 32:
            return None
        # PSLS_STATUS packed: 6*uint32(24) + 7*uint8 + 1 pad = 32 bytes
        parts = struct.unpack_from('<IIIIIIBBBBBBBx', buf, 0)
        ver = parts[0]
        return DriverStatus(
            version_major=(ver >> 24) & 0xFF,
            version_minor=(ver >> 16) & 0xFF,
            version_patch=ver & 0xFFFF,
            proc_create_count=parts[1],
            reg_mon_count=parts[2],
            image_load_count=parts[3],
            blocked_count=parts[4],
            psls_pid=parts[5],
            proc_mon_enabled=bool(parts[6]),
            reg_mon_enabled=bool(parts[7]),
            image_mon_enabled=bool(parts[8]),
            psls_protect_enabled=bool(parts[9]),
            file_filter_enabled=bool(parts[10]),
            net_filter_enabled=bool(parts[11]),
            disk_mon_enabled=bool(parts[12]),
        )

    def set_psls_pid(self, pid: int) -> bool:
        buf = struct.pack('<II', pid, 0)
        return self._ioctl(IOCTL_SET_PSLS_PID, in_buf=buf, out_size=0) is not None

    def set_protected_dir(self, path: str) -> bool:
        """设置内核级受保护目录（安装目录防改）。

        生效后外部进程对该目录下文件的 写入/删除/重命名/截断 在
        minifilter PreOperation 阶段被直接拒绝 (STATUS_ACCESS_DENIED)，
        PSLS 自身进程不受限制。保护生命周期：
          - PSLS 正常退出: deactivate 流程调用 clear_protected_dir()
          - PSLS 被强杀/崩溃: 内核检测到被保护 PID 退出后自动解除，
            不影响卸载程序清理安装目录

        需要驱动 v1.1+ 支持；旧驱动对该 IOCTL 返回失败 → 返回 False。
        """
        if not path:
            return False
        nt_path = _win32_to_nt_path(path)
        if not nt_path:
            return False
        in_buf = nt_path.encode('utf-16-le') + b'\x00\x00'
        return self._ioctl(IOCTL_SET_PROTECTED_DIR,
                           in_buf=in_buf, out_size=0) is not None

    def clear_protected_dir(self) -> bool:
        """解除内核级受保护目录。"""
        return self._ioctl(IOCTL_CLEAR_PROTECTED_DIR, out_size=0) is not None

    def set_exempt_dir(self, path: str) -> bool:
        """设置受保护目录内的"豁免子树"（如 {app}\\Sandboxie）。

        动机（实测）：安装目录防改会拒绝**外部进程**在该目录下的写入/删除/重命名；
        把 Sandboxie 装到 `{app}\\Sandboxie` 后，SbieSvc/Start.exe/盒内进程写自己的
        文件会被误挡 → 沙箱失效 + 用户看到"所有文件拒绝读写/删除"。
        设置豁免后，该子树内的写入/删除/重命名不再被拒（保护意图不变：其余安装文件
        仍拒绝外部写入；**只读始终允许**）。

        path 为空 → 清空豁免（安全 no-op）。需要驱动支持 PSLS_IOCTL_SET_EXEMPT_DIR。
        """
        nt_path = _win32_to_nt_path(path) if path else ''
        if not nt_path:
            # 清空豁免：发送 0 长度输入
            return self._ioctl(IOCTL_SET_EXEMPT_DIR, in_buf=b'', out_size=0) is not None
        in_buf = nt_path.encode('utf-16-le') + b'\x00\x00'
        return self._ioctl(IOCTL_SET_EXEMPT_DIR,
                           in_buf=in_buf, out_size=0) is not None

    def set_mbr_protect(self, enabled: bool) -> bool:
        """启用/关闭内核级引导扇区(MBR)写入拦截。

        enabled=True 后, 驱动在 \Device\HarddiskN\DRN 上拒绝用户态
        非 PSLS 进程对第 0 扇区的 IRP_MJ_WRITE (STATUS_ACCESS_DENIED)
        并上报 EVENT_DISK_BLOCKED, 实现事前防护 (非事后回滚)。

        需要驱动 v1.1+ 支持；旧驱动对该 IOCTL 返回失败 → 返回 False。
        """
        buf = struct.pack('<B', 1 if enabled else 0)
        buf += b'\x00' * 3   # pad[3]
        return self._ioctl(IOCTL_SET_MBR_PROTECT, in_buf=buf, out_size=0) is not None

    def set_boot_protect(self, regions, enabled: bool = True) -> bool:
        """下发受保护引导扇区区域集 (diskmon 事前拦截, v1.1+)。

        regions: iterable of (disk_index:int, start_offset:int, length:int)
                 盘内字节偏移区间。典型值:
                   - MBR/第0扇区: (0, 0, 512)
                   - 分区 VBR:    (0, 分区起始LBA*512, 512)
                驱动保留第 0 扇区 MBR 兜底区域, 与区域集叠加。
                返回 False 表示驱动过旧/未加载 (仅 MBR 默认拦截或降级轮询)。
        """
        items = [(int(d) & 0xFF, int(s), int(l))
                 for (d, s, l) in list(regions)[:32]]
        out = struct.pack('<IB3x', len(items), 1 if enabled else 0)
        for (di, so, ln) in items:
            out += struct.pack('<B3xQQ', di, so, ln)
        return self._ioctl(IOCTL_SET_BOOT_PROTECT, in_buf=out, out_size=0) is not None

    def set_boot_files(self, paths, enabled: bool = True) -> bool:
        """下发引导文件 (bootmgr/BCD/EFI) 保护路径列表 (minifilter, v1.1+)。

        paths: iterable of NT 设备路径 (UTF-16), 如
               "\\Device\\HarddiskVolume3\\Boot\\BCD"
            或 "\\Device\\HarddiskVolume3\\bootmgr"。
        驱动对命中路径的外部进程写/删/改名/截断返回 STATUS_ACCESS_DENIED,
        TrustedInstaller/TiWorker (Windows 更新) 进程放行。
        """
        items = [str(p)[:255] for p in list(paths)[:32]]
        out = struct.pack('<IB3x', len(items), 1 if enabled else 0)
        for p in items:
            entry = p.encode('utf-16-le') + b'\x00\x00'
            if len(entry) > 512:
                entry = entry[:512]
            out += entry
            if len(entry) < 512:
                out += b'\x00' * (512 - len(entry))
        return self._ioctl(IOCTL_SET_BOOT_FILES, in_buf=out, out_size=0) is not None

    # 动态 PRE 进程拦截名单命令 (与内核 PSLS_KILLLIST_CMD_* 一致)
    KILLLIST_CMD_REPLACE = 1
    KILLLIST_CMD_CLEAR = 2

    def set_killlist(self, paths, cmd: int = 1) -> bool:
        """下发动态 PRE 进程拦截名单 (升级1: 内核事件驱动, IOCTL 0x03A)。

        paths: 已知高危路径子串 (UTF-16), 进程创建 PRE 阶段被内核实时否决
               (STATUS_ACCESS_DENIED), 免 1s 轮询窗口/TOCTOU。
        cmd: KILLLIST_CMD_REPLACE=1 整体替换 | KILLLIST_CMD_CLEAR=2 清空动态名单
             (CLEAR 保留内核内置 g_KillList 保底名单)。
        Returns: True=下发成功; False=驱动不可用/过旧 (调用方自行降级)。
        """
        items = [str(p) for p in list(paths)[:64]]
        out = struct.pack('<III4x', 1, int(cmd), len(items))  # version=1, cmd, count
        for p in items:
            entry = p.encode('utf-16-le') + b'\x00\x00'
            if len(entry) > 512:
                entry = entry[:512]
            out += entry + b'\x00' * (512 - len(entry))
        return self._ioctl(IOCTL_SET_KILLLIST, in_buf=out, out_size=0) is not None

    # ---- 阶段二: 写前影子备份 ----

    @staticmethod
    def _encode_shadow_path_field(path: str) -> bytes:
        """把一个路径编码为固定 PSLS_SHADOW_ROOT_CHARS 个 WCHAR 的 UTF-16LE 字段
        (以 '\\0' 结尾, 不足补零, 超长截断)。"""
        max_bytes = SHADOW_ROOT_CHARS * 2
        raw = str(path or '').encode('utf-16-le')
        if len(raw) > max_bytes - 2:
            raw = raw[:max_bytes - 2]
        raw += b'\x00\x00'
        return raw + b'\x00' * (max_bytes - len(raw))

    def set_shadow_config(self, enable: bool, generation_id: int,
                          shadow_root: str, dirs=None) -> bool:
        """下发写前影子备份配置 (阶段二, IOCTL 0x03B)。

        enable: 开关。
        generation_id: 世代号, 变化即清空驱动侧去重集合。
        shadow_root: 影子仓库根 (Win32 或 NT 路径); 驱动写入
            <shadow_root>\\<generation_id>\\<path_hash>。
        dirs: 可选影子触发目录 (Win32/NT 路径, 最多 SHADOW_MAX_DIRS 个),
            用于把备份范围覆盖到用户受保护目录; 缺省时仅作用于内核受保护目录。
        Returns True=下发成功; False=驱动不可用/过旧。
        """
        def _nt(p):
            s = str(p or '')
            if not s:
                return s
            return s if s.startswith('\\') else _win32_to_nt_path(s)

        buf = bytearray()
        buf += struct.pack('<II', 1 if enable else 0,
                           int(generation_id) & 0xFFFFFFFF)
        buf += self._encode_shadow_path_field(_nt(shadow_root))
        items = [d for d in list(dirs or []) if d][:SHADOW_MAX_DIRS]
        buf += struct.pack('<I', len(items))
        for d in items:
            buf += self._encode_shadow_path_field(_nt(d))
        return self._ioctl(IOCTL_SET_SHADOW_CONFIG, in_buf=bytes(buf),
                           out_size=0) is not None

    def query_shadow_stats(self) -> Optional[Dict[str, Any]]:
        """查询写前影子备份统计 (阶段二, IOCTL 0x03C)。

        返回 backed_up/skipped/missed/failed/dedup_hits/generation_id;
        驱动不可用或过旧时返回 None。
        """
        buf = self._ioctl(IOCTL_QUERY_SHADOW_STATS, out_size=24)
        if not buf or len(buf) < 24:
            return None
        parts = struct.unpack_from('<IIIIII', buf, 0)
        return {
            'backed_up': parts[0], 'skipped': parts[1], 'missed': parts[2],
            'failed': parts[3], 'dedup_hits': parts[4], 'generation_id': parts[5],
        }

    def poll_events(self, max_size: int = 64 * 1024) -> List[Any]:
        """
        从内核事件池批量拉事件。

        Returns:
            解析后的事件对象列表 (ProcessCreateEvent / RegKeyEvent / ImageLoadEvent)
            驱动未加载时返回空列表
        """
        buf = self._ioctl(IOCTL_POLL_EVENTS, out_size=max_size)
        if buf is None:
            return []
        return _parse_events(buf)

    def ack_event(self, event_id: int, action: int,
                  apply_to_similar: bool = False) -> bool:
        """
        回传事件判定结果给内核。

        action: 1=放行 2=内核阻止 3=立即终止进程
        """
        buf = struct.pack('<IBBBI', event_id, action, 1 if apply_to_similar else 0, 0, 0)
        return self._ioctl(IOCTL_ACK_EVENT, in_buf=buf, out_size=0) is not None

    def terminate_process(self, pid: int, exit_code: int = 1,
                          force: bool = False) -> bool:
        buf = struct.pack('<IIBBB', pid, exit_code, 1 if force else 0, 0, 0)
        return self._ioctl(IOCTL_TERMINATE_PROC, in_buf=buf, out_size=0) is not None

    def block_process(self, pid: int) -> bool:
        """将指定 PID 加入断网黑名单（沙箱进程断网，WFP 层拦截出站连接）。

        通过内核驱动 netmon 的 NetMon_BlockPid，该进程所有出站连接
        在 ALE_AUTH_CONNECT 层被 BLOCK，阻断 C2 回连与 payload 下载。
        """
        buf = struct.pack('<I', pid)
        return self._ioctl(IOCTL_BLOCK_PROCESS, in_buf=buf, out_size=0) is not None

    def allow_process(self, pid: int) -> bool:
        """解除指定 PID 的断网标记（沙箱结束后清理）。"""
        buf = struct.pack('<I', pid)
        return self._ioctl(IOCTL_ALLOW_PROCESS, in_buf=buf, out_size=0) is not None

    def get_config(self) -> Optional[Dict[str, Any]]:
        """从驱动拉取当前配置 (packed 32 bytes)"""
        size = 32
        buf = self._ioctl(IOCTL_GET_CONFIG, out_size=size)
        if not buf or len(buf) < size:
            return None
        flags_order = ['enable_proc_create', 'enable_proc_terminate',
                       'enable_reg_mon', 'enable_image_load',
                       'enable_psls_protect', 'enable_signature_skip',
                       'enable_file_filter', 'enable_net_filter',
                       'enable_disk_mon']
        result: Dict[str, Any] = {}
        for i, key in enumerate(flags_order):
            result[key] = bool(buf[4 + i])
        params = struct.unpack_from('<IIII', buf, 16)
        result['max_event_pool'] = params[0]
        result['block_timeout_ms'] = params[1]
        result['reg_path_filter_count'] = params[2]
        result['white_list_pid_count'] = params[3]
        return result

    def set_config(self, config_dict: Dict[str, Any], merge: bool = True) -> bool:
        """推送配置到驱动。merge=True 时仅覆盖传入字段, 其余保持驱动当前值。

        默认值映射与驱动 psls_driver.c 初始化保持一致，避免
        final.get(key, 1) 把 enable_proc_terminate / enable_image_load /
        enable_disk_mon 等默认关闭的标志误置为 1 导致误杀桌面进程。
        """
        # 与驱动 g_Driver.Config 初始化保持一致 (psls_driver.c ~L610)
        _DEFAULTS: Dict[str, int] = {
            'enable_proc_create':    1,
            'enable_proc_terminate': 0,  # 内核 PRE 拦截默认关: 黑名单含 \desktop\
            'enable_reg_mon':        1,
            'enable_image_load':     1,  # 路线C: 每-PID 150ms 聚合, 默认开
            'enable_psls_protect':   1,
            'enable_signature_skip': 0,
            'enable_file_filter':    1,
            'enable_net_filter':     1,
            'enable_disk_mon':       0,  # MBR 写拦截默认关
        }

        final = dict(config_dict)
        if merge:
            current = self.get_config()
            if current is not None:
                for k, v in current.items():
                    if k not in final:
                        final[k] = v

        size = 32
        buf = ctypes.create_string_buffer(size)
        struct.pack_into('<I', buf, 0, size)
        flags_order = list(_DEFAULTS.keys())
        for i, key in enumerate(flags_order):
            struct.pack_into('<B', buf, 4 + i,
                             1 if final.get(key, _DEFAULTS[key]) else 0)
        struct.pack_into('<IIII', buf, 16,
                         final.get('max_event_pool', 4096),
                         final.get('block_timeout_ms', 5000),
                         final.get('reg_path_filter_count', 0),
                         final.get('white_list_pid_count', 0))
        return self._ioctl(IOCTL_SET_CONFIG, in_buf=bytes(buf.raw),
                           out_size=0) is not None

    # ------------------------------------------------------------------
    # 事件消费后台循环
    # ------------------------------------------------------------------

    def register_callback(self, event_type: str,
                          handler: Callable[[Any], None]):
        """
        注册事件回调。

        event_type: 'process_create' | 'process_delete' | 'reg_key' |
                    'image_load' | 'handle_audit' | 'block_result' |
                    'file_blocked' | 'file_shadowed' | 'net_blocked' |
                    'disk_blocked' | 'any'
        """
        if event_type not in self._callbacks:
            raise ValueError(f'未知事件类型: {event_type}')
        self._callbacks[event_type].append(handler)

    def start_event_loop(self):
        """启动后台轮询线程"""
        if self._event_thread and self._event_thread.is_alive():
            return
        self._stop_event.clear()
        self._event_thread = threading.Thread(
            target=self._event_loop,
            daemon=True,
            name='psls-driver-event-loop',
        )
        self._event_thread.start()
        logger.info('驱动事件循环已启动')

    def stop_event_loop(self):
        """停止后台轮询线程"""
        self._stop_event.set()
        if self._event_thread:
            self._event_thread.join(timeout=2)
            self._event_thread = None
        logger.info('驱动事件循环已停止')

    def _event_loop(self):
        """后台线程主循环: poll → decode → callback"""
        logger.info('[driver-loop] 开始事件轮询')
        # 心跳：仅当上次心跳超过 30s 才记一条（poll 阻塞期间反映线程存活，
        # 用于定位"PSLS 进程冻结时驱动轮询线程是否卡死"）
        import time as _t
        _last_hb = _t.time()
        while not self._stop_event.is_set():
            try:
                events = self.poll_events()
                for evt in events:
                    self._dispatch(evt)
                # 没有事件时短暂睡眠
                if not events:
                    # 驱动不可用时 poll_events 立即返回空列表（不阻塞），
                    # 若沿用 5ms 间隔会高频空转耗CPU；改为 2 秒低频轮询，
                    # 驱动可用时 poll_events 本身在内核侧阻塞，间隔不影响延迟。
                    if not self.is_available:
                        self._stop_event.wait(2.0)
                    else:
                        self._stop_event.wait(self._poll_interval)
                now = _t.time()
                if now - _last_hb >= 30.0:
                    _last_hb = now
                    logger.info(f'[driver-loop] 心跳 OK, 近轮事件 {len(events)} 条')
                    try:
                        from engine.observability import hub as _obshub
                        _obshub.heartbeat('driver_loop')
                    except Exception:
                        pass
            except Exception as e:
                logger.warning(f'[driver-loop] 异常: {e}')
                self._stop_event.wait(1.0 if not self.is_available else 0.1)
        logger.info('[driver-loop] 事件轮询退出')

    def _dispatch(self, evt):
        """分发单个事件到所有相关回调"""
        for cb in self._callbacks['any']:
            try:
                cb(evt)
            except Exception as e:
                logger.debug(f'回调异常: {e}')

        if isinstance(evt, ProcessCreateEvent):
            for cb in self._callbacks['process_create']:
                try: cb(evt)
                except Exception as e: logger.debug(f'回调异常: {e}')
        elif isinstance(evt, RegKeyEvent):
            for cb in self._callbacks['reg_key']:
                try: cb(evt)
                except Exception as e: logger.debug(f'回调异常: {e}')
        elif isinstance(evt, ImageLoadEvent):
            for cb in self._callbacks['image_load']:
                try: cb(evt)
                except Exception as e: logger.debug(f'回调异常: {e}')
        elif isinstance(evt, HandleAuditEvent):
            for cb in self._callbacks['handle_audit']:
                try: cb(evt)
                except Exception as e: logger.debug(f'回调异常: {e}')
        elif isinstance(evt, BlockResultEvent):
            for cb in self._callbacks['block_result']:
                try: cb(evt)
                except Exception as e: logger.debug(f'回调异常: {e}')
        elif isinstance(evt, FileBlockEvent):
            for cb in self._callbacks['file_blocked']:
                try: cb(evt)
                except Exception as e: logger.debug(f'回调异常: {e}')
        elif isinstance(evt, ShadowBackupEvent):
            for cb in self._callbacks['file_shadowed']:
                try: cb(evt)
                except Exception as e: logger.debug(f'回调异常: {e}')
        elif isinstance(evt, NetBlockEvent):
            for cb in self._callbacks['net_blocked']:
                try: cb(evt)
                except Exception as e: logger.debug(f'回调异常: {e}')
        elif isinstance(evt, DiskBlockEvent):
            for cb in self._callbacks['disk_blocked']:
                try: cb(evt)
                except Exception as e: logger.debug(f'回调异常: {e}')
