# -*- coding: utf-8 -*-
"""
本地沙箱分析引擎
在隔离的 Job Object 中执行可疑文件，监控系统级行为，评分判定威胁等级。

隔离层：Windows Job Object（CPU/内存/进程数限制）+ 受限令牌
监控层：psutil 进程树监控 + 可选 frida API hook（graceful degradation）
判定层：6维行为评分（文件/注册表/网络/进程/系统/反分析）

用法：
    analyzer = SandboxAnalyzer()
    result = analyzer.analyze('suspicious_file.exe')
    # result = {
    #     'verdict': 'malware' | 'suspicious' | 'clean',
    #     'score': 0-100,
    #     'behaviors': [...],
    #     'duration': float,
    #     'process_tree': {...},
    # }
"""

import os
import sys
import time
import shutil
import tempfile
import subprocess
import threading
from typing import Dict, List, Optional, Callable
from utils.logger import get_logger

try:
    import winreg
    _HAS_WINREG = True
except ImportError:
    winreg = None
    _HAS_WINREG = False

logger = get_logger('sandbox_analyzer')

# ---- 方案C: 网络阻断器（复用内核驱动 NetMon_BlockPid 对沙箱进程断网）----
# 惰性初始化的模块级单例，避免每个沙箱实例重复打开驱动设备。
# 驱动不可用时静默降级（返回 False），不影响沙箱其它功能。
_net_blocker = None
_net_blocker_lock = threading.Lock()


def _get_net_blocker():
    """惰性获取网络阻断器（PSLSDriverBridge 复用，仅用于发送 IOCTL）。"""
    global _net_blocker
    if _net_blocker is not None:
        return _net_blocker
    with _net_blocker_lock:
        if _net_blocker is not None:
            return _net_blocker
        try:
            from driver.bridge.psls_driver_bridge import PSLSDriverBridge
            bridge = PSLSDriverBridge()
            if bridge.is_available:
                _net_blocker = bridge
                logger.info('沙箱网络阻断：内核驱动已连接')
            else:
                _net_blocker = None
        except Exception as e:
            logger.debug(f'沙箱网络阻断：驱动不可用，降级: {e}')
            _net_blocker = None
    return _net_blocker


# ---- 平台检测 ----
import ctypes
import ctypes.wintypes

_IS_WINDOWS = sys.platform == 'win32'

# ---- Win32 API 常量 ----

# Job Object 限制信息类
JobObjectBasicLimitInformation = 2
JobObjectBasicUIRestrictions = 4
JobObjectExtendedLimitInformation = 9
JobObjectAssociateCompletionPortInformation = 7

# Server Silo 信息类（Windows 10 1607+ / Server 2016+）
JobObjectCreateSilo = 38               # SetInformationJobObject：将 Job 升级为 Silo 容器
JobObjectSiloBasicInformation = 63     # GetInformationJobObject：获取 Silo 状态/ID
JobObjectSiloRootDirectory = 40        # 获取 Silo 根目录句柄
JobObjectSiloMonitor = 42              # 设置 Silo 监控端口（可选）

# 限制标志
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x0400
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x0008
JOB_OBJECT_LIMIT_CPU_RATE = 0x00040000   # JOB_OBJECT_LIMIT_CPU_RATE_CONTROL (Windows 8+)
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
# 注意: BREAKAWAY_OK 故意不设 — 沙箱 Job 本身不允许子进程再逃逸

# UI 限制
JOB_OBJECT_UILIMIT_NONE = 0x0000
JOB_OBJECT_UILIMIT_HANDLES = 0x0001
JOB_OBJECT_UILIMIT_READCLIPBOARD = 0x0002
JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x0004
JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x0008
JOB_OBJECT_UILIMIT_DISPLAYSETTINGS = 0x0010
JOB_OBJECT_UILIMIT_GLOBALATOMS = 0x0020
JOB_OBJECT_UILIMIT_DESKTOP = 0x0040
JOB_OBJECT_UILIMIT_EXITWINDOWS = 0x0080

# 进程创建标志
CREATE_SUSPENDED = 0x0004
CREATE_NEW_CONSOLE = 0x0010
CREATE_NO_WINDOW = 0x08000000
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
# 扩展启动信息标志：lpAttributeList 生效（AppContainer 必需）
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
# PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES（传入 AppContainer SID 用）
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
# CreateAppContainerProfile 已存在时的 HRESULT（0x800700B7）
_HRESULT_ALREADY_EXISTS = 0x800700B7

# 令牌相关
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
DISABLE_MAX_PRIVILEGE = 0x1
LUA_TOKEN = 0x4

# 进程访问权限
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_TERMINATE = 0x0001
PROCESS_SET_QUOTA = 0x0100
PROCESS_SET_INFORMATION = 0x0200

# STARTUPINFO 结构
STARTF_USESHOWWINDOW = 0x0001
SW_HIDE = 0

# ---- Win32 结构体 ----

class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ('ReadOperationCount', ctypes.c_ulonglong),
        ('WriteOperationCount', ctypes.c_ulonglong),
        ('OtherOperationCount', ctypes.c_ulonglong),
        ('ReadTransferCount', ctypes.c_ulonglong),
        ('WriteTransferCount', ctypes.c_ulonglong),
        ('OtherTransferCount', ctypes.c_ulonglong),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('PerProcessUserTimeLimit', ctypes.wintypes.LARGE_INTEGER),
        ('PerJobUserTimeLimit', ctypes.wintypes.LARGE_INTEGER),
        ('LimitFlags', ctypes.wintypes.DWORD),
        ('MinimumWorkingSetSize', ctypes.c_size_t),
        ('MaximumWorkingSetSize', ctypes.c_size_t),
        ('ActiveProcessLimit', ctypes.wintypes.DWORD),
        ('Affinity', ctypes.c_size_t),
        ('PriorityClass', ctypes.wintypes.DWORD),
        ('SchedulingClass', ctypes.wintypes.DWORD),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BasicLimitInformation', _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ('IoInfo', _IO_COUNTERS),
        ('ProcessMemoryLimit', ctypes.c_size_t),
        ('JobMemoryLimit', ctypes.c_size_t),
        ('PeakProcessMemoryUsed', ctypes.c_size_t),
        ('PeakJobMemoryUsed', ctypes.c_size_t),
    ]


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ('cb', ctypes.wintypes.DWORD),
        ('lpReserved', ctypes.wintypes.LPWSTR),
        ('lpDesktop', ctypes.wintypes.LPWSTR),
        ('lpTitle', ctypes.wintypes.LPWSTR),
        ('dwX', ctypes.wintypes.DWORD),
        ('dwY', ctypes.wintypes.DWORD),
        ('dwXSize', ctypes.wintypes.DWORD),
        ('dwYSize', ctypes.wintypes.DWORD),
        ('dwXCountChars', ctypes.wintypes.DWORD),
        ('dwYCountChars', ctypes.wintypes.DWORD),
        ('dwFillAttribute', ctypes.wintypes.DWORD),
        ('dwFlags', ctypes.wintypes.DWORD),
        ('wShowWindow', ctypes.wintypes.WORD),
        ('cbReserved2', ctypes.wintypes.WORD),
        ('lpReserved2', ctypes.c_void_p),
        ('hStdInput', ctypes.wintypes.HANDLE),
        ('hStdOutput', ctypes.wintypes.HANDLE),
        ('hStdError', ctypes.wintypes.HANDLE),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess', ctypes.wintypes.HANDLE),
        ('hThread', ctypes.wintypes.HANDLE),
        ('dwProcessId', ctypes.wintypes.DWORD),
        ('dwThreadId', ctypes.wintypes.DWORD),
    ]


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('nLength', ctypes.wintypes.DWORD),
        ('lpSecurityDescriptor', ctypes.c_void_p),
        ('bInheritHandle', ctypes.wintypes.BOOL),
    ]


# ---- AppContainer 相关结构（真实写隔离，无需第三方驱动）----

class _SID_AND_ATTRIBUTES(ctypes.Structure):
    """PSID_AND_ATTRIBUTES：能力(Capability) SID 及其属性。"""
    _fields_ = [
        ('Sid', ctypes.c_void_p),
        ('Attributes', ctypes.wintypes.DWORD),
    ]


class _SECURITY_CAPABILITIES(ctypes.Structure):
    """SECURITY_CAPABILITIES：AppContainer 启动时通过属性列表传入。

    AppContainerSid  : 由 CreateAppContainerProfile 生成的容器 SID
    Capabilities     : 授予的能力（如 internetClient）；NULL/0 = 不授予任何能力
    CapabilityCount  : 能力数量
    Reserved         : 保留，必须为 0
    不授予任何能力时，容器内进程**无网络、无真实文件/注册表写权限**，
    仅能写入显式授予了该容器 SID 的目录（如本沙箱的工作目录）。
    """
    _fields_ = [
        ('AppContainerSid', ctypes.c_void_p),
        ('Capabilities', ctypes.POINTER(_SID_AND_ATTRIBUTES)),
        ('CapabilityCount', ctypes.wintypes.DWORD),
        ('Reserved', ctypes.wintypes.DWORD),
    ]


class _STARTUPINFOEXW(ctypes.Structure):
    """STARTUPINFOEXW：首成员即 STARTUPINFOW，其后追加 lpAttributeList。

    CreateProcessW 使用 EXTENDED_STARTUPINFO_PRESENT 时传入本结构，
    以携带 PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES（AppContainer SID）。
    """
    _fields_ = [
        ('StartupInfo', _STARTUPINFOW),
        ('lpAttributeList', ctypes.c_void_p),
    ]


def _make_appcontainer_startupinfo(attr_list) -> '_STARTUPINFOEXW':
    """构造携带 AppContainer 属性列表的 STARTUPINFOEXW（窗口隐藏）。

    注意：使用 EXTENDED_STARTUPINFO_PRESENT 时，StartupInfo.cb 必须等于
    STARTUPINFOEXW 的完整大小（而非 STARTUPINFOW 的大小）。
    """
    si_ex = _STARTUPINFOEXW()
    ctypes.memset(ctypes.byref(si_ex), 0, ctypes.sizeof(si_ex))
    si = si_ex.StartupInfo
    si.cb = ctypes.sizeof(_STARTUPINFOEXW)
    si.dwFlags = STARTF_USESHOWWINDOW
    si.wShowWindow = SW_HIDE
    si_ex.lpAttributeList = attr_list
    return si_ex


def _hidden_spawn_kwargs() -> dict:
    """构造"不弹控制台窗口"的子进程创建参数（Windows）。

    返回 dict，可直接用 ``**`` 展开进 ``subprocess.run/Popen`` 的 kwargs：
        creationflags=CREATE_NO_WINDOW
        startupinfo=<STARTUPINFOW, dwFlags=STARTF_USESHOWWINDOW, wShowWindow=SW_HIDE>

    为什么需要：PSLS 是 windowed（无控制台）进程，直接 spawn 控制台程序
    （SbieIni.exe / Start.exe / taskkill / icacls 等）时 Windows 会为该子进程
    新建并显示一个控制台窗口，分析期间高频调用（例如每秒可能触发多次的
    ``Start.exe /box:X /silent /listpids``）即表现为"大量黑窗口闪现"。
    CREATE_NO_WINDOW 从源头禁止创建控制台；startupinfo 的 SW_HIDE 兼容少数
    仍读取启动信息的程序（两者叠加最稳妥）。

    注意：**仅**用于 PSLS 自己发起的辅助子进程，不改变沙箱内被测样本的启动
    语义（样本由 SbieSvc/Start.exe 在盒内拉起，与本函数无关）。非 Windows
    平台返回空 dict，避免传入非法参数。

    实现细节：必须使用 ``subprocess.STARTUPINFO``（而非自定义 ctypes 结构）——
    subprocess 在带管道时会调用 ``startupinfo.copy()`` 并置
    STARTF_USESTDHANDLES，自定义 ctypes 结构没有 copy() 会直接抛异常。
    """
    if not _IS_WINDOWS:
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return dict(creationflags=CREATE_NO_WINDOW, startupinfo=si)


# ---- Win32 API 绑定 ----

def _load_win32():
    """加载 Win32 API 函数"""
    if not _IS_WINDOWS:
        return None

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

    apis = {}

    # CreateJobObjectW
    kernel32.CreateJobObjectW.restype = ctypes.wintypes.HANDLE
    kernel32.CreateJobObjectW.argtypes = [ctypes.POINTER(_SECURITY_ATTRIBUTES), ctypes.wintypes.LPCWSTR]
    apis['CreateJobObjectW'] = kernel32.CreateJobObjectW

    # SetInformationJobObject
    kernel32.SetInformationJobObject.restype = ctypes.wintypes.BOOL
    kernel32.SetInformationJobObject.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.wintypes.DWORD
    ]
    apis['SetInformationJobObject'] = kernel32.SetInformationJobObject

    # GetInformationJobObject — 查询 Silo 是否生效（SiloBasicInformation）
    # 该 API 仅存在于 Windows 10 1607+ / Server 2016+
    try:
        kernel32.GetInformationJobObject.restype = ctypes.wintypes.BOOL
        kernel32.GetInformationJobObject.argtypes = [
            ctypes.wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.wintypes.DWORD
        ]
        apis['GetInformationJobObject'] = kernel32.GetInformationJobObject
    except AttributeError:
        # 旧系统无此函数，Silo 功能自动降级，不影响基础 Job Object 隔离
        pass

    # AssignProcessToJobObject
    kernel32.AssignProcessToJobObject.restype = ctypes.wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HANDLE]
    apis['AssignProcessToJobObject'] = kernel32.AssignProcessToJobObject

    # CreateProcessW
    kernel32.CreateProcessW.restype = ctypes.wintypes.BOOL
    kernel32.CreateProcessW.argtypes = [
        ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPWSTR,
        ctypes.POINTER(_SECURITY_ATTRIBUTES), ctypes.POINTER(_SECURITY_ATTRIBUTES),
        ctypes.wintypes.BOOL, ctypes.wintypes.DWORD,
        ctypes.c_void_p, ctypes.wintypes.LPCWSTR,
        ctypes.POINTER(_STARTUPINFOW), ctypes.POINTER(_PROCESS_INFORMATION),
    ]
    apis['CreateProcessW'] = kernel32.CreateProcessW

    # ResumeThread
    kernel32.ResumeThread.restype = ctypes.wintypes.DWORD
    kernel32.ResumeThread.argtypes = [ctypes.wintypes.HANDLE]
    apis['ResumeThread'] = kernel32.ResumeThread

    # TerminateJobObject
    kernel32.TerminateJobObject.restype = ctypes.wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.UINT]
    apis['TerminateJobObject'] = kernel32.TerminateJobObject

    # CloseHandle
    kernel32.CloseHandle.restype = ctypes.wintypes.BOOL
    kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    apis['CloseHandle'] = kernel32.CloseHandle

    # OpenProcessToken
    advapi32.OpenProcessToken.restype = ctypes.wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.HANDLE)
    ]
    apis['OpenProcessToken'] = advapi32.OpenProcessToken

    # CreateRestrictedToken
    advapi32.CreateRestrictedToken.restype = ctypes.wintypes.BOOL
    advapi32.CreateRestrictedToken.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD, ctypes.c_void_p,
        ctypes.wintypes.DWORD, ctypes.c_void_p,
        ctypes.wintypes.DWORD, ctypes.c_void_p,
        ctypes.POINTER(ctypes.wintypes.HANDLE),
    ]
    apis['CreateRestrictedToken'] = advapi32.CreateRestrictedToken

    # OpenProcess
    kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
    apis['OpenProcess'] = kernel32.OpenProcess

    # GetCurrentProcess
    kernel32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE
    apis['GetCurrentProcess'] = kernel32.GetCurrentProcess

    # TerminateProcess — 沙箱隔离失败时终止进程 / 无 Job 隔离时兜底终止
    kernel32.TerminateProcess.restype = ctypes.wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.UINT]
    apis['TerminateProcess'] = kernel32.TerminateProcess

    # IsProcessInJob — 检查进程是否已在 Job 中（预判嵌套 Job 场景）
    kernel32.IsProcessInJob.restype = ctypes.wintypes.BOOL
    kernel32.IsProcessInJob.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.BOOL)]
    apis['IsProcessInJob'] = kernel32.IsProcessInJob

    # LookupPrivilegeValueW — 查询特权 LUID（令牌限制用）
    # 第 3 参数用 c_void_p 接收 PLUID：调用方传的是自定义 _LUID 结构体的
    # byref，若声明成 POINTER(LARGE_INTEGER)，ctypes 会先做类型校验并抛
    # TypeError: expected LP_c_longlong instance instead of pointer to _LUID —
    # 结果 SeDebugPrivilege 从来没启用成功（日志里的 DEBUG 告警即此）。
    advapi32.LookupPrivilegeValueW.restype = ctypes.wintypes.BOOL
    advapi32.LookupPrivilegeValueW.argtypes = [
        ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR,
        ctypes.c_void_p,
    ]
    apis['LookupPrivilegeValueW'] = advapi32.LookupPrivilegeValueW

    # AdjustTokenPrivileges — 禁用令牌中的高危特权
    advapi32.AdjustTokenPrivileges.restype = ctypes.wintypes.BOOL
    advapi32.AdjustTokenPrivileges.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.wintypes.BOOL,
        ctypes.c_void_p, ctypes.wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p,
    ]
    apis['AdjustTokenPrivileges'] = advapi32.AdjustTokenPrivileges

    # ---- AppContainer（真实写隔离，无第三方驱动）相关 API ----
    # userenv.dll：创建/删除 AppContainer 配置文件（生成容器 SID）
    try:
        userenv = ctypes.WinDLL('userenv', use_last_error=True)
        userenv.CreateAppContainerProfile.restype = ctypes.c_long  # HRESULT
        userenv.CreateAppContainerProfile.argtypes = [
            ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR, ctypes.c_void_p,
            ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ]
        apis['CreateAppContainerProfile'] = userenv.CreateAppContainerProfile

        userenv.DeleteAppContainerProfile.restype = ctypes.c_long
        userenv.DeleteAppContainerProfile.argtypes = [ctypes.wintypes.LPCWSTR]
        apis['DeleteAppContainerProfile'] = userenv.DeleteAppContainerProfile

        userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
        userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
            ctypes.wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        apis['DeriveAppContainerSidFromAppContainerName'] = \
            userenv.DeriveAppContainerSidFromAppContainerName
    except Exception:
        # 旧系统无相关导出 → AppContainer 层自动降级（不影响 Job/Token 隔离）
        pass

    # kernel32：属性列表（承载 AppContainer SID）
    try:
        kernel32.InitializeProcThreadAttributeList.restype = ctypes.wintypes.BOOL
        kernel32.InitializeProcThreadAttributeList.argtypes = [
            ctypes.c_void_p, ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
        apis['InitializeProcThreadAttributeList'] = \
            kernel32.InitializeProcThreadAttributeList

        kernel32.UpdateProcThreadAttribute.restype = ctypes.wintypes.BOOL
        kernel32.UpdateProcThreadAttribute.argtypes = [
            ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
        apis['UpdateProcThreadAttribute'] = kernel32.UpdateProcThreadAttribute

        kernel32.DeleteProcThreadAttributeList.restype = None
        kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
        apis['DeleteProcThreadAttributeList'] = \
            kernel32.DeleteProcThreadAttributeList
    except Exception:
        pass

    # advapi32：FreeSid（释放 DeriveAppContainerSid... 返回的 SID）
    try:
        advapi32.FreeSid.restype = ctypes.c_void_p
        advapi32.FreeSid.argtypes = [ctypes.c_void_p]
        apis['FreeSid'] = advapi32.FreeSid
    except Exception:
        pass

    # advapi32：SID ↔ 字符串（用于 icacls 授予容器 SID 工作目录写权限）
    try:
        advapi32.ConvertSidToStringSidW.restype = ctypes.wintypes.BOOL
        advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        apis['ConvertSidToStringSidW'] = advapi32.ConvertSidToStringSidW

        advapi32.LocalFree.restype = ctypes.c_void_p
        advapi32.LocalFree.argtypes = [ctypes.c_void_p]
        apis['LocalFree'] = advapi32.LocalFree
    except Exception:
        pass

    # 独立一份 kernel32 供"扩展启动"使用：STARTUPINFOEXW 需要把 9 号参数按
    # c_void_p 传入，与常规 CreateProcessW（POINTER(_STARTUPINFOW)）的 argtypes
    # 隔离，避免 ctypes 参数类型校验冲突（两份 WinDLL 实例的 argtypes 相互独立）。
    try:
        kernel32_ex = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32_ex.CreateProcessW.restype = ctypes.wintypes.BOOL
        kernel32_ex.CreateProcessW.argtypes = [
            ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPWSTR,
            ctypes.c_void_p, ctypes.c_void_p,
            ctypes.wintypes.BOOL, ctypes.wintypes.DWORD,
            ctypes.c_void_p, ctypes.wintypes.LPCWSTR,
            ctypes.c_void_p, ctypes.POINTER(_PROCESS_INFORMATION),
        ]
        apis['CreateProcessW_Ex'] = kernel32_ex.CreateProcessW
    except Exception:
        pass

    return apis


_WIN32 = _load_win32() if _IS_WINDOWS else None

# frida 可选加载
try:
    import frida
    HAS_FRIDA = True
except ImportError:
    HAS_FRIDA = False
    frida = None

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    psutil = None


# ============================================================================
# 行为评分规则
# ============================================================================

# 每个行为类别的最大分值
# 提高各类别上限，让严重行为能充分贡献分数
CATEGORY_MAX_SCORE = {
    'file': 25,
    'registry': 20,
    'network': 20,
    'process': 25,
    'system': 20,
    'anti_analysis': 15,
    'static': 25,  # 新增：静态特征预检分数
}

# 判定阈值（降低，让检测更严格）
# 满分 150，malware 45≈30%, suspicious 20≈13%
VERDICT_MALWARE_THRESHOLD = 45
VERDICT_SUSPICIOUS_THRESHOLD = 20

# 批量文件操作检测阈值（勒索病毒特征）
RANSOM_FILE_OP_THRESHOLD = 10      # 5秒内修改/创建超过10个文件 → 可疑
RANSOM_FILE_OP_CRITICAL = 30       # 5秒内修改/创建超过30个文件 → 高危
RANSOM_FILE_OP_WINDOW = 5.0        # 滑动窗口（秒）

# 勒索"加密-删除替换"足迹阈值
# 勒索软件典型流程：遍历大量目标文件 → 打开读 → 写加密内容 → 删除/替换原文件。
# 若进程在窗口内"接触过"大量独立文件，且其中相当比例随后从磁盘消失（被删除/替换），
# 即为强力勒索特征。现有 OPEN 句柄检测看不出删除足迹，本检测专门补齐这一维度。
RANSOM_REPLACE_DELETED = 15         # 窗口内 ≥15 个被访问文件从磁盘消失 → 勒索替换足迹
RANSOM_REPLACE_MIN_TOUCHED = 40     # 期间至少接触过 40 个独立文件才认定（避免误判）

# 可疑子进程名（从父进程启动这些子进程 = 高风险）
SUSPICIOUS_CHILD_PROCESSES = {
    'cmd.exe', 'powershell.exe', 'pwsh.exe',
    'wscript.exe', 'cscript.exe', 'mshta.exe',
    'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
    'bitsadmin.exe', 'msiexec.exe', 'installutil.exe',
    'regasm.exe', 'regsvcs.exe', 'msbuild.exe',
}

# 可疑命令行关键词（出现即加分）
SUSPICIOUS_CMDLINE_PATTERNS = [
    ('-enc ', 8, 'PowerShell 编码执行'),
    ('-encodedcommand', 8, 'PowerShell 编码执行'),
    ('-exec bypass', 6, 'PowerShell 执行策略绕过'),
    ('-w hidden', 5, 'PowerShell 隐藏窗口'),
    ('-windowstyle hidden', 5, 'PowerShell 隐藏窗口'),
    ('downloadstring', 6, 'PowerShell 下载执行'),
    ('downloadfile', 5, 'PowerShell 下载文件'),
    ('invoke-expression', 5, 'PowerShell 远程执行'),
    ('iex(', 5, 'PowerShell IEX 简写'),
    ('invoke-webrequest', 4, 'PowerShell Web 请求'),
    ('invoke-restmethod', 4, 'PowerShell REST 请求'),
    ('system.reflection', 4, '.NET 反射加载'),
    ('assembly.load', 4, '.NET 程序集加载'),
    ('regsvr32 /s /u /i:', 8, 'squiblydoo 攻击'),
    ('mshta http', 7, 'MSHTA 远程执行'),
    ('certutil -decode', 6, 'CertUtil 解码'),
    ('certutil -urlcache', 6, 'CertUtil 下载'),
    ('bitsadmin /transfer', 5, 'BITS 下载'),
    ('net user /add', 7, '创建用户'),
    ('net localgroup administrators', 7, '提升权限'),
    ('vssadmin delete shadows', 9, '删除卷影副本（勒索）'),
    ('wbadmin delete catalog', 9, '删除备份目录（勒索）'),
    ('bcdedit /set', 6, '修改启动配置'),
    ('reg add hk', 4, '注册表写入'),
    ('reg delete', 4, '注册表删除'),
    ('sc create', 5, '创建服务'),
    ('sc config', 5, '修改服务'),
    ('schtasks /create', 5, '创建计划任务'),
    ('taskkill /f', 4, '强制终止进程'),
    # 银狐家族特征：投毒后强杀安全软件
    ('taskkill /f /im 360', 9, '尝试终止 360 安全软件（银狐特征）'),
    ('taskkill /f /im hips', 9, '尝试终止火绒安全软件（银狐特征）'),
    ('taskkill /f /im msmpeng', 9, '尝试终止 Defender 引擎（银狐特征）'),
    ('taskkill /f /im psls', 10, '尝试终止 PSLS 自身'),
    ('taskkill /f /im hipsdaemon', 9, '尝试终止火绒服务进程'),
    ('wmic process delete', 7, 'WMIC 批量杀进程'),
    # 银狐落地执行链
    ('rundll32 javascript:', 7, 'Rundll32 JS 脚本执行'),
    ('mshta vbscript:', 7, 'MSHTA VBS 脚本执行'),
    ('wscript //e:jscript', 7, 'WSH 脚本编码执行'),
    ('currentversion\\run', 6, '写入 Run 自启动键'),
    ('/c del ', 5, 'CMD 删除文件'),
    ('/c rd /s /q', 5, 'CMD 删除目录'),
    ('> $null', 3, '输出重定向到空'),
    ('2>&1', 2, '合并错误输出'),
    # ---- PeAV 融合：LOLBin 滥用（lolbin_abuse.sa）----
    ('msbuild', 5, 'MSBuild 编译执行（LOLBin）'),
    ('installutil', 5, 'InstallUtil 加载（LOLBin）'),
    ('csc.exe', 4, 'CSC 编译器（LOLBin）'),
    ('/unsafe', 5, 'CSC 不安全代码编译（LOLBin）'),
    ('regsvcs', 5, 'RegSvcs 滥用（LOLBin）'),
    ('regasm', 5, 'RegAsm 滥用（LOLBin）'),
    ('vbc.exe', 4, 'VBC 编译器（LOLBin）'),
    ('ilasm', 4, 'IL 汇编器（LOLBin）'),
    ('dotnet.exe', 4, 'dotnet 加载 DLL（LOLBin）'),
    # ---- PeAV 融合：勒索增强（ransomware_filecrypt.sa）----
    ('cipher /w:', 7, 'Cipher 擦除空闲空间（勒索特征）'),
    # ---- PeAV 融合：Defender 禁用（defenseevasion_defenderdisable.sa）----
    ('set-mppreference', 7, 'PowerShell 修改 Defender 策略'),
    ('disableantiospyware', 6, '禁用反间谍软件'),
    ('disablerealtimemonitoring', 7, '禁用实时保护'),
    ('sc stop windefend', 7, '停止 Defender 服务'),
    ('sc config windefend start= disabled', 7, '禁用 Defender 服务'),
    ('sc delete windefend', 8, '删除 Defender 服务'),
    # ---- PeAV 融合：银狐增强（antisilverfox.sa）----
    ('wevtutil cl', 6, '清除事件日志（银狐反取证）'),
    ('wevtutil sl', 5, '禁用事件日志（银狐反取证）'),
    ('netsh advfirewall add rule', 5, '添加防火墙规则'),
    ('netsh advfirewall delete rule', 5, '删除防火墙规则'),
    ('netsh interface portproxy', 6, '端口代理转发（银狐特征）'),
    ('echo ', 2, 'CMD echo（可能是 hosts 篡改）'),
    # ---- PeAV 融合：信息窃取（info_stealer.sa）----
    ('login data', 6, '访问浏览器登录数据（信息窃取）'),
    ('web data', 5, '访问浏览器 Web 数据（信息窃取）'),
    ('key4.db', 6, '访问 Firefox 密钥库（信息窃取）'),
    ('logins.json', 5, '访问 Firefox 登录信息（信息窃取）'),
    # ---- PeAV 融合：挖矿（miner_cryptocurrency.sa）----
    ('stratum+tcp', 7, '挖矿协议连接'),
    ('stratum+ssl', 7, '挖矿协议连接'),
    ('--donate-level', 5, 'XMRig 挖矿参数'),
    ('--cpu-priority', 5, '挖矿 CPU 优先级设置'),
    ('--max-cpu-usage', 5, '挖矿 CPU 限制'),
    ('xmrig', 7, 'XMRig 挖矿程序'),
    # ---- PeAV 融合：WMI 订阅持久化 ----
    ('__eventfilter', 5, 'WMI 事件订阅（持久化）'),
    ('__eventconsumer', 5, 'WMI 事件消费（持久化）'),
    ('activeScriptEventConsumer', 5, 'WMI 脚本消费（持久化）'),
]

# 可疑文件扩展名（批量创建/修改 = 勒索特征）
# 融合 PeAV ransomware_filecrypt.sa + 现有规则
RANSOM_EXTENSIONS = {
    '.encrypted', '.locked', '.crypto', '.crypt', '.locky',
    '.cerber', '.zepto', '.odin', '.lock', '.wallet',
    '.cry', '.enc', '.race', '.rng', '.petya',
    '.wcry', '.wannacry', '.wncry', '.ryuk', '.sodinokibi',
    '.contis', '.avaddon', '.maze', '.egregor',
    # PeAV 补充
    '.vault', '.ttt', '.micro', '.aes', '.ccc', '.zzz', '.abc', '.xxx',
    '.thor',
}

# 银狐(SilverFox)远控木马文件足迹（来自 PeAV antisilverfox.sa）
# 匹配路径子串（小写），命中即加分
SILVERFOX_FILE_PATTERNS = [
    # AppData\Roaming 随机子目录释放物
    ('appdata\\roaming\\', 6, 'AppData Roaming 释放物（银狐特征）'),
    # 键盘记录 / 屏幕截图 / 剪贴板
    ('\\keylog', 8, '键盘记录目录（银狐特征）'),
    ('\\keystroke', 8, '键盘记录目录（银狐特征）'),
    ('\\keyboard', 6, '键盘记录目录（银狐特征）'),
    ('\\screenshot', 7, '屏幕截图目录（银狐特征）'),
    ('\\capture', 6, '屏幕捕获目录（银狐特征）'),
    ('\\clipboard', 6, '剪贴板窃取目录（银狐特征）'),
    # 窃取信息目录
    ('\\steal', 7, '信息窃取目录（银狐特征）'),
    ('\\password', 7, '密码窃取目录（银狐特征）'),
    ('\\cookie', 5, 'Cookie 窃取目录（银狐特征）'),
    ('\\credential', 7, '凭据窃取目录（银狐特征）'),
    # 代理配置（银狐常篡改系统代理）
    ('\\proxy.conf', 5, '代理配置文件（银狐特征）'),
    ('\\proxy.ini', 5, '代理配置文件（银狐特征）'),
    # hosts 文件篡改
    ('\\drivers\\etc\\hosts', 8, 'Hosts 文件篡改（银狐特征）'),
    # 临时目录随机名可执行
    ('\\temp\\', 3, '临时目录释放物'),
]

# 银狐可疑 DLL 模式（路径子串匹配，小写）
SILVERFOX_DLL_PATTERNS = [
    ('_inject.dll', 8, '注入 DLL（银狐特征）'),
    ('_hook.dll', 7, 'Hook DLL（银狐特征）'),
    ('_api.dll', 6, '可疑 API DLL（银狐特征）'),
    ('_core.dll', 5, '可疑核心 DLL（银狐特征）'),
    ('_client.dll', 5, '可疑客户端 DLL（银狐特征）'),
    ('_server.dll', 5, '可疑服务端 DLL（银狐特征）'),
    ('keylog', 8, '键盘记录 DLL（银狐特征）'),
    ('keyhook', 7, '键盘 Hook DLL（银狐特征）'),
    ('screenshot', 7, '屏幕截图 DLL（银狐特征）'),
    ('screencap', 6, '屏幕捕获 DLL（银狐特征）'),
    # 从 AppData/Temp 加载的系统 DLL（银狐 DLL 劫持）
    ('appdata\\', 5, '从 AppData 加载 DLL（银狐特征）'),
    ('\\temp\\', 4, '从临时目录加载 DLL（银狐特征）'),
]

# 可疑网络 TLD / 动态 DNS（来自 PeAV C2_Communication.sa + antisilverfox.sa）
SUSPICIOUS_NETWORK_DOMAINS = [
    '.ddns.', '.no-ip.', '.duckdns.', '.changeip.',
    '.dynu.', '.freedns.', '.dynv6.', '.dynamic-dns.',
]

# 可疑 C2 端口（扩展自 PeAV C2_Communication.sa + antisilverfox.sa）
SUSPICIOUS_C2_PORTS = {
    # 经典反弹端口
    4444, 5555, 6666, 7777, 8888, 9999,
    1337, 31337, 1234, 4321,
    # 银狐常用 C2 端口（443 变体）
    8443, 9443, 10443, 11443, 12443, 13443, 14443, 15443, 16443, 17443, 18443, 19443, 20443,
    # Webshell / C2 web 端口
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
    # 代理端口
    1080, 3128, 8118, 9050,
    # 银狐重复数字端口
    11111, 22222, 33333, 44444, 55555,
}

# 可疑廉价 TLD（银狐 C2 常用）
SUSPICIOUS_CHEAP_TLDS = (
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.club', '.work', '.click', '.link', '.country',
    '.stream', '.gdn', '.racing', '.win', '.review',
    '.vip', '.wang', '.loan', '.men', '.download',
    '.kim', '.lol', '.rest', '.cf',
)

# 静态预检：可疑 PE 特征
STATIC_SUSPICIOUS_IMPORTS = {
    'VirtualAllocEx': 3,
    'WriteProcessMemory': 4,
    'CreateRemoteThread': 5,
    'NtCreateThreadEx': 5,
    'QueueUserAPC': 4,
    'SetWindowsHookExW': 3,
    'GetAsyncKeyState': 2,
    'AdjustTokenPrivileges': 3,
    'LookupPrivilegeValueW': 2,
    'OpenProcessToken': 2,
    'CreateServiceW': 4,
    'StartServiceW': 3,
    'RegSetValueW': 2,
    'RegCreateKeyW': 1,
    'InternetOpenW': 2,
    'InternetOpenUrlW': 3,
    'WinHttpConnect': 3,
    'URLDownloadToFileW': 4,
    'SHGetFolderPathW': 1,
    'IsDebuggerPresent': 2,
    'CheckRemoteDebuggerPresent': 3,
    'NtQueryInformationProcess': 3,
    'NtSetInformationThread': 3,
    'AddVectoredExceptionHandler': 3,
    # 进程镂空（Process Hollowing，银狐常用）
    'NtUnmapViewOfSection': 5,
    'NtMapViewOfSection': 4,
    'SetThreadContext': 4,
    'NtWriteVirtualMemory': 4,
    'RtlCreateUserThread': 5,
}

# 静态预检：可疑字符串
STATIC_SUSPICIOUS_STRINGS = [
    ('/c powershell', 5, 'CMD 调用 PowerShell'),
    ('/k powershell', 5, 'CMD 调用 PowerShell'),
    ('-enc ', 4, 'PowerShell 编码命令'),
    ('downloadstring', 4, '远程下载执行'),
    ('iex(', 4, 'IEX 简写'),
    ('invoke-expression', 4, 'Invoke-Expression'),
    ('system.reflection', 3, '.NET 反射'),
    ('cmd.exe /c', 3, 'CMD 执行'),
    ('schtasks /create', 4, '计划任务创建'),
    ('taskkill /f /im', 4, '进程强杀命令（银狐特征）'),
    ('vssadmin delete', 6, '删除卷影副本'),
    ('wbadmin delete', 5, '删除备份'),
    ('bcdedit /set', 4, '修改启动配置'),
    ('reg add', 3, '注册表写入'),
    ('net user /add', 5, '创建用户'),
    ('rundll32', 2, 'rundll32 调用'),
    ('regsvr32', 2, 'regsvr32 调用'),
    ('mshta', 3, 'mshta 调用'),
    ('certutil', 3, 'certutil 调用'),
    ('bitsadmin', 3, 'bitsadmin 调用'),
]

# 静态预检：可疑节区名
STATIC_SUSPICIOUS_SECTIONS = {
    '.aspack', '.adata', '.pklst', '.pcle', '.petite',
    '.mpress1', '.mpress2', '.themida', '.winlice',
    '.vmp0', '.vmp1', '.vmp2', '.enigma1', '.enigma2',
    '.svkp', '.taz', '.WWP', '.nsp0', '.nsp1', '.nsp2',
    '.nsp3', '.nsp4', '.nsp5', '.nsp6',
}

# 可疑目录模式（写入这些目录 = 高风险）
SUSPICIOUS_WRITE_DIRS = [
    os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
    os.path.expandvars(r'%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup'),
    os.path.expandvars(r'%SystemRoot%\System32'),
    os.path.expandvars(r'%SystemRoot%\SysWOW64'),
    os.path.expandvars(r'%TEMP%'),
]

# 可疑注册表键模式
SUSPICIOUS_REG_KEYS = [
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects',
    r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs',
    r'SYSTEM\CurrentControlSet\Services',
]

# 可疑 API 调用（frida hook 用）
SUSPICIOUS_API_HOOKS = {
    # 进程注入
    'VirtualAllocEx': {'category': 'process', 'score': 5, 'desc': '远程进程内存分配'},
    'WriteProcessMemory': {'category': 'process', 'score': 8, 'desc': '写入远程进程内存'},
    'CreateRemoteThread': {'category': 'process', 'score': 10, 'desc': '创建远程线程（注入）'},
    'NtCreateThreadEx': {'category': 'process', 'score': 10, 'desc': '底层线程注入'},
    'QueueUserAPC': {'category': 'process', 'score': 7, 'desc': 'APC 注入'},
    # 进程镂空（银狐常用：镂空合法进程躲避查杀）
    'NtUnmapViewOfSection': {'category': 'process', 'score': 9, 'desc': '卸载合法进程节区（镂空）'},
    'NtMapViewOfSection': {'category': 'process', 'score': 7, 'desc': '映射恶意节区（镂空）'},
    'SetThreadContext': {'category': 'process', 'score': 7, 'desc': '篡改线程上下文（镂空）'},
    'NtWriteVirtualMemory': {'category': 'process', 'score': 8, 'desc': '底层远程内存写入'},
    'RtlCreateUserThread': {'category': 'process', 'score': 9, 'desc': '底层远程线程注入'},
    # 进程操作
    'CreateProcessW': {'category': 'process', 'score': 3, 'desc': '创建子进程'},
    'CreateProcessA': {'category': 'process', 'score': 3, 'desc': '创建子进程'},
    'ShellExecuteW': {'category': 'process', 'score': 2, 'desc': 'Shell 执行'},
    # 文件操作
    'MoveFileW': {'category': 'file', 'score': 1, 'desc': '文件移动/重命名'},
    'DeleteFileW': {'category': 'file', 'score': 2, 'desc': '文件删除'},
    'CopyFileW': {'category': 'file', 'score': 1, 'desc': '文件复制'},
    # 注册表
    'RegSetValueW': {'category': 'registry', 'score': 2, 'desc': '注册表写入'},
    'RegCreateKeyW': {'category': 'registry', 'score': 1, 'desc': '创建注册表键'},
    'RegDeleteKeyW': {'category': 'registry', 'score': 3, 'desc': '删除注册表键'},
    # 网络
    'InternetOpenW': {'category': 'network', 'score': 3, 'desc': '初始化网络连接'},
    'InternetOpenUrlW': {'category': 'network', 'score': 5, 'desc': '打开 URL'},
    'WinHttpConnect': {'category': 'network', 'score': 4, 'desc': 'HTTP 连接'},
    'WSAStartup': {'category': 'network', 'score': 2, 'desc': '初始化 Winsock'},
    'connect': {'category': 'network', 'score': 3, 'desc': '网络连接'},
    # 系统
    'CreateServiceW': {'category': 'system', 'score': 8, 'desc': '创建系统服务'},
    'ChangeServiceConfigW': {'category': 'system', 'score': 6, 'desc': '修改服务配置'},
    'ScheduleTask': {'category': 'system', 'score': 6, 'desc': '创建计划任务'},
    # 反分析
    'IsDebuggerPresent': {'category': 'anti_analysis', 'score': 3, 'desc': '调试器检测'},
    'CheckRemoteDebuggerPresent': {'category': 'anti_analysis', 'score': 4, 'desc': '远程调试器检测'},
    'NtQueryInformationProcess': {'category': 'anti_analysis', 'score': 4, 'desc': '进程信息查询（反分析）'},
    'GetTickCount': {'category': 'anti_analysis', 'score': 1, 'desc': '计时检测'},
    'QueryPerformanceCounter': {'category': 'anti_analysis', 'score': 1, 'desc': '高精度计时（沙箱检测）'},
}


# ============================================================================
# 沙箱配置
# ============================================================================

class SandboxConfig:
    """沙箱分析配置"""

    def __init__(self):
        # 超时（秒）— 从 15s 提升到 30s，让恶意程序有更多时间展现行为
        # 很多恶意软件有 5-10s 的延迟执行逻辑，15s 太短
        self.timeout = 30

        # Job Object 限制
        self.max_memory_mb = 256       # 单进程内存上限
        self.max_job_memory_mb = 512   # Job 总内存上限
        self.max_active_processes = 8  # 最大活动进程数
        self.cpu_rate_percent = 25     # CPU 占用百分比上限（Windows 8+）

        # Server Silo 隔离（Windows 10 1607+ / Server 2016+，需管理员权限）
        # Silo 是比 Job Object 更强的容器：独立命名空间 + 整体终止，
        # 可显著降低恶意程序通过 WMI / 计划任务 / SCM 重挂到系统进程的逃逸风险。
        # 创建失败时自动降级为普通 Job Object，不影响兼容性。
        self.use_silo = True

        # AppContainer 真实写隔离（Windows 8+，无需第三方驱动/无需管理员）
        # 与 Job/Silo 互补：Job 只管资源与整体终止，无法阻止样本写真实系统；
        # AppContainer 让样本以**低完整性 + 容器 SID**运行，对用户文件/注册表
        # 无写权限，仅能写入显式授予容器 SID 的工作目录 → 真实"写隔离"。
        # 创建失败（旧系统/权限异常）自动降级为原有 Job+Token 链路，不阻断分析。
        self.use_appcontainer = True
        # 容器能力：默认不授予任何能力（含 internetClient=无网络），
        # 让样本在完全断网、无写权限下暴露行为；如需观察 C2 可显式放开。
        self.appcontainer_capabilities = ()

        # UI 限制（全开）
        self.ui_restrictions = (
            JOB_OBJECT_UILIMIT_HANDLES |
            JOB_OBJECT_UILIMIT_READCLIPBOARD |
            JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
            JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
            JOB_OBJECT_UILIMIT_GLOBALATOMS |
            JOB_OBJECT_UILIMIT_DESKTOP |
            JOB_OBJECT_UILIMIT_EXITWINDOWS
        )

        # 监控选项
        # 默认禁用 frida：ResumeThread 后立即 frida.attach 会与目标进程
        # 的 MSVCP140.dll CRT 初始化路径冲突，导致父进程 PSLS.exe 中
        # PyQt5 加载的同一份 MSVCP140.dll 被抛出 0xc0000005 访问冲突
        # （偏移 0x12ea0）。如需 frida 支持，可在构造 SandboxConfig 后
        # 显式打开 config.use_frida = True，并确保有 500ms+ 的延迟附加。
        self.use_frida = False
        self.frida_attach_delay_ms = 500  # frida 延迟附加等待（毫秒）
        self.monitor_interval = 0.2       # psutil 轮询间隔（秒）
        self.enable_network_monitor = True

        # 临时目录
        self.work_dir = None           # None = 自动创建临时目录

        # ---- 沙箱后端选择 ----
        # 'auto'（首选 Sandboxie-Plus，不可用则回退 AppContainer+Job）
        # | 'sandboxie'（强制 Sandboxie，不可用时记录并回退）
        # | 'appcontainer'（强制现有 AppContainer+Job 链路）
        self.backend = 'auto'
        # Sandboxie-Plus 相关（backend 命中 sandboxie 时使用）
        self.sandboxie_dir = None              # Start.exe/SbieIni.exe 所在目录；None=自动探测
        # 使用的盒名：**专用盒**，由 ensure_box() 通过 SbieIni 按需创建并置
        # Enabled=y（全新安装、无任何盒的机器也能建起来）。用专用盒而非
        # DefaultBox，可避免 analysis 结束时清空盒内容误删用户自己沙盘的资料。
        self.sandboxie_box = 'PSLS_Analysis'
        self.sandboxie_file_root = None        # 沙盒文件根；None=自动探测盒根
        self.sandboxie_stop_control = 1        # 1=分析结束后 /terminate 停止盒内程序


# ============================================================================
# 行为记录
# ============================================================================

class BehaviorRecord:
    """单条行为记录"""

    def __init__(self, category: str, severity: str, description: str,
                 detail: str = '', timestamp: float = None, score: int = 0):
        self.category = category      # file/registry/network/process/system/anti_analysis
        self.severity = severity      # info/warn/critical
        self.description = description
        self.detail = detail
        self.timestamp = timestamp or time.time()
        self.score = score

    def to_dict(self) -> dict:
        return {
            'category': self.category,
            'severity': self.severity,
            'description': self.description,
            'detail': self.detail,
            'timestamp': self.timestamp,
            'score': self.score,
        }


# ============================================================================
# 主沙箱分析器
# ============================================================================

# 脚本类文件 -> 解释器包装命令（沙箱内直接 CreateProcessW 脚本文件会失败，
# 错误码 193 (ERROR_BAD_EXE_FORMAT)/5 (ERROR_ACCESS_DENIED) 等，须经解释器执行）
_SCRIPT_INTERPRETERS = {
    '.ps1': 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File',
    '.vbs': 'cscript.exe //nologo',
    '.js':  'cscript.exe //nologo',
    '.bat': 'cmd.exe /c',
    '.cmd': 'cmd.exe /c',
}

# CreateProcessW 常见失败错误码 -> 可读原因（用于区分"可修复/正常失败"，避免误判）
_LAUNCH_ERROR_REASONS = {
    2:   '系统找不到指定的文件',
    5:   '拒绝访问（可能需要管理员权限运行解释器）',
    193: '不是有效的 Win32 应用程序（可能为无解释器的脚本或损坏文件）',
    740: '请求的操作需要提升权限（沙箱受限令牌无法执行需要管理员的应用）',
    87:  '参数错误',
    206: '文件名或扩展名太长',
}


# ============================================================================
# 沙箱后端抽象（Sandboxie-Plus 首选 / AppContainer+Job 保底）
# ============================================================================
# 设计原则：
#   1. 后端只负责“启动/等待/终止/取证/断网”，打分与判定仍由 SandboxAnalyzer 复用；
#   2. 无 Sandboxie 时行为与既有 AppContainer 链路**完全一致**（AppContainerBackend
#      只做薄包装，转发到原有方法）；
#   3. 任一探测/启动失败都回退 AppContainer，不阻断沙箱分析。

_SANDBOXIE_REG_PATHS = (
    r'SOFTWARE\Sandboxie-Plus',
    r'SOFTWARE\Sandboxie',
)
_SANDBOXIE_DEFAULT_DIRS = (
    r'C:\Program Files\Sandboxie-Plus',
    r'C:\Program Files\Sandboxie',
)

# ---------------------------------------------------------------------------
# 沙箱样本复制：带重试 + "内部通道"（PSLS 自身持锁时用自己句柄拷副本）
# 实测：PSLS 实时防护锁定【Minecraft.exe】期间，沙箱复制同一源文件失败
# （[Errno 9] Bad file descriptor / 共享冲突）→ "沙箱分析失败"。
# ---------------------------------------------------------------------------
_internal_copy_provider = None      # Callable[[str], Optional[str]]：返回可读副本路径


def set_internal_copy_provider(fn) -> None:
    """注册"内部通道"提供者（如 realtime_monitor.locked_copy_to_temp）。

    由桥接层在实时监控创建后注入；未注入时该机制自动跳过（安全降级）。
    """
    global _internal_copy_provider
    _internal_copy_provider = fn


def copy_sample_with_retry(src: str, dst: str, attempts: int = 4) -> tuple:
    """把样本复制到沙箱工作目录：普通复制(重试) → 去元数据复制 → 内部通道。

    返回 `(ok: bool, reason: str)`；任何一步成功即 ok=True。
    绝不直启被锁定的原文件（那会导致 CreateProcessW(32) 被误判为启动失败）。
    """
    last = None
    # 1) 常规复制（含元数据）——多数情况一次成功
    for i in range(max(1, attempts)):
        try:
            shutil.copy2(src, dst)
            return True, ''
        except Exception as e:
            last = e
            time.sleep(0.15 * (i + 1))
    # 2) 去掉 copystat（锁定文件的属性/时间戳复制常是失败点）
    for i in range(2):
        try:
            shutil.copy(src, dst)
            return True, ''
        except Exception as e:
            last = e
            time.sleep(0.2 * (i + 1))
    # 3) 内部通道：若锁是 PSLS 自己持有的，用自己的句柄读出副本
    try:
        if _internal_copy_provider is not None:
            tmp = _internal_copy_provider(src)
            if tmp and os.path.isfile(tmp):
                shutil.copy(tmp, dst)
                try:
                    os.unlink(tmp)
                except Exception:
                    pass
                logger.info(f'沙箱样本经内部通道复制成功: {src}')
                return True, ''
    except Exception as e:
        logger.debug(f'内部通道复制异常: {e}')
    return False, str(last) if last else 'copy_failed'


def _psls_bundled_sandboxie_dir() -> Optional[str]:
    """PSLS 自带 Sandboxie 目录（安装器把沙箱装到 {app}\\Sandboxie）。

    冻结模式: PSLS.exe 所在目录\\Sandboxie
    开发模式: 项目根\\Sandboxie
    这是**首选**来源；找不到再回退注册表/旧默认目录（兼容已装过旧路径的机器）。
    """
    try:
        if getattr(sys, 'frozen', False):
            base = os.path.dirname(os.path.abspath(sys.executable))
        else:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cand = os.path.join(base, 'Sandboxie')
        if os.path.isdir(cand) and os.path.isfile(os.path.join(cand, 'Start.exe')):
            return cand
    except Exception:
        pass
    return None


def _sandboxie_dir_from_registry() -> Optional[str]:
    """从注册表读取 Sandboxie 安装目录（InstallDir / InstallLocation）。

    优先查 Software\\Sandboxie(-Plus)（旧版），再查 Inno 卸载项
    (...\\CurrentVersion\\Uninstall\\Sandboxie*)，兼容安装到非系统盘（如 E:）。
    """
    if not _HAS_WINREG:
        return None

    def _try_key(root, sub):
        try:
            with winreg.OpenKey(root, sub, 0, winreg.KEY_READ) as k:
                for val in ('InstallDir', 'InstallLocation', ''):
                    try:
                        v, _t = winreg.QueryValueEx(k, val)
                    except OSError:
                        continue
                    if v and os.path.isdir(str(v)):
                        return str(v).rstrip('\\/')
        except OSError:
            return None
        return None

    views = (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY)
    # 1) 传统键
    for sub in _SANDBOXIE_REG_PATHS:
        for view in views:
            d = _try_key(winreg.HKEY_LOCAL_MACHINE, sub)
            if d:
                return d
    # 2) Inno 卸载项（兼容任意安装盘）
    uninst_root = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    for view in views:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninst_root, 0,
                                winreg.KEY_READ | view) as k:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(k, i)
                    except OSError:
                        break
                    i += 1
                    if 'sandboxie' not in sub.lower():
                        continue
                    d = _try_key(winreg.HKEY_LOCAL_MACHINE,
                                 uninst_root + '\\' + sub)
                    if d:
                        return d
        except OSError:
            continue
    return None


def _sandboxie_service_present() -> bool:
    """SbieSvc 服务是否已注册（读 SCM 注册表键，无需管理员）。"""
    if not _HAS_WINREG:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r'SYSTEM\CurrentControlSet\Services\SbieSvc',
                            0, winreg.KEY_READ) as _k:
            return True
    except OSError:
        return False


def _sandboxie_driver_present() -> bool:
    """SbieDrv 驱动文件/服务是否已存在。"""
    if _HAS_WINREG:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r'SYSTEM\CurrentControlSet\Services\SbieDrv',
                                0, winreg.KEY_READ) as _k:
                return True
        except OSError:
            pass
    sysroot = os.environ.get('SystemRoot', r'C:\Windows')
    return os.path.isfile(os.path.join(sysroot, 'System32', 'drivers', 'SbieDrv.sys'))


def detect_sandboxie_backend(config=None) -> dict:
    """探测 Sandboxie-Plus 是否可用作沙箱后端。

    返回 {'available': bool, 'dir': str, 'start': str, 'ini': str,
          'service': bool, 'driver': bool, 'reason': str}
    """
    info = {'available': False, 'dir': '', 'start': '', 'ini': '',
            'service': False, 'driver': False, 'reason': '', 'dir_source': ''}
    if not _IS_WINDOWS:
        info['reason'] = '非 Windows 平台'
        return info

    # 1) 定位安装目录（顺序：显式配置 → **PSLS 自带 {app}\Sandboxie** →
    #                    注册表 InstallDir → 旧版默认目录（兼容升级机器））
    cand = None
    src = ''
    cfg_dir = getattr(config, 'sandboxie_dir', None) if config else None
    if cfg_dir and os.path.isdir(cfg_dir):
        cand, src = cfg_dir, 'config'
    else:
        cand = _psls_bundled_sandboxie_dir()
        if cand:
            src = 'psls_bundled'
        if not cand:
            cand = _sandboxie_dir_from_registry()
            if cand:
                src = 'registry'
        if not cand:
            for d in _SANDBOXIE_DEFAULT_DIRS:
                if os.path.isdir(d):
                    cand, src = d, 'legacy_default'
                    break
    if not cand:
        info['reason'] = '未找到 Sandboxie 安装目录'
        return info
    info['dir'] = cand
    info['dir_source'] = src
    logger.info(f'Sandboxie 目录来源={src or "unknown"}: {cand}')

    start_exe = os.path.join(cand, 'Start.exe')
    ini_exe = os.path.join(cand, 'SbieIni.exe')
    if not os.path.isfile(start_exe):
        info['reason'] = f'缺少 Start.exe: {start_exe}'
        return info
    info['start'] = start_exe
    info['ini'] = ini_exe if os.path.isfile(ini_exe) else ''

    # 2) 服务 / 驱动（缺一不可，否则盒内进程无法被隔离）
    info['service'] = _sandboxie_service_present()
    info['driver'] = _sandboxie_driver_present()
    if not info['service']:
        info['reason'] = 'SbieSvc 服务未注册'
        return info
    if not info['driver']:
        info['reason'] = 'SbieDrv 驱动未安装'
        return info

    info['available'] = True
    return info


class _SandboxBackend:
    """沙箱后端基类（启动/等待/终止/取证/断网）。"""

    name = 'unknown'

    def __init__(self, analyzer):
        self._a = analyzer          # SandboxAnalyzer 实例（复用打分/监控/清理）

    def launch(self, sample_path: str, on_progress: Optional[Callable] = None):
        raise NotImplementedError

    def terminate(self):
        raise NotImplementedError

    def collect_delta(self) -> List[dict]:
        """返回本次运行产生的行为增量（文件/注册表），供打分复用。"""
        return []


class AppContainerBackend(_SandboxBackend):
    """保底后端：薄包装既有 AppContainer+Job+Token 实现，行为完全等价。"""

    name = 'appcontainer'

    def launch(self, sample_path: str, on_progress: Optional[Callable] = None):
        return self._a._launch_sandboxed(sample_path, self._a._job_handle)

    def terminate(self):
        self._a._terminate_job()

    def collect_delta(self) -> List[dict]:
        return []


# Sandboxie 盒内基础设施进程（随盒生命周期启动，非样本本身）。
# /listpids 会把它们一并返回，需剔除后才能定位到样本 PID。
_SBIE_INFRA_NAMES = {
    'sandboxiedcomlaunch', 'sandboxierpcss', 'sandboxiecomlaunch',
    'sandboxiemonitor', 'sbiesvc', 'sbiectrl', 'sbieini', 'sandboxievnc',
    'start', 'start64', 'sandman',
}


class SandboxieBackend(_SandboxBackend):
    """首选后端：通过 Sandboxie-Plus 的 Start.exe/SbieIni.exe 在专用盒中引爆样本。

    取证思路：沙盒内的文件/注册表写被重定向到沙盒目录（drive\\<盘符>\\...、
    user\\current\\...、RegHive），运行后读这些增量即可还原真实行为
    （见 engine.sandboxie_delta）。
    """

    name = 'sandboxie'

    def __init__(self, analyzer, info: dict):
        super().__init__(analyzer)
        info = info or {}
        self.start_exe = info.get('start', '')
        self.ini_exe = info.get('ini', '')
        self.install_dir = info.get('dir', '')
        self.box = str(getattr(self._a.config, 'sandboxie_box', 'PSLS_Analysis')
                       or 'PSLS_Analysis')
        self._popen = None
        self._target_pids: List[int] = []
        self._sample_pids: List[int] = []   # 剔除基础设施后的样本进程
        self._file_root = self._resolve_file_root()

    # ---- 盒配置 ----
    def _resolve_file_root(self) -> str:
        cfg_root = getattr(self._a.config, 'sandboxie_file_root', None)
        if cfg_root:
            return cfg_root
        # 先问 Sandboxie 该盒的实际文件根（未显式设置时返回空行）
        if self.ini_exe:
            try:
                r = subprocess.run([self.ini_exe, 'query', self.box, 'FileRootPath'],
                                   capture_output=True, text=True, timeout=10,
                                   **_hidden_spawn_kwargs())
                lines = [x.strip() for x in (r.stdout or '').splitlines() if x.strip()]
                if lines and os.path.isabs(lines[-1]):
                    return lines[-1]
            except Exception:
                pass
        # 回退：Sandboxie 默认盒根 C:\Sandbox\<用户>\<盒>
        user = os.environ.get('USERNAME') or 'user'
        return os.path.join('C:\\Sandbox', user, self.box)

    def _run_ini(self, args: List[str], timeout: float = 15.0):
        if not self.ini_exe:
            return None
        # 只读查询（query）永远允许；**写操作在写入不可用时必须跳过** ——
        # 非管理员/设备不可写时 SbieIni set 会失败，且 Sandboxie 每次都弹
        # `SBIE2322 无法重写 Sandboxie.ini` 消息框（实测刷屏）。
        try:
            _verb = (args[0] or '').lower() if args else ''
        except Exception:
            _verb = ''
        if _verb != 'query' and not _sbie_ini_writes_allowed():
            return None
        try:
            return subprocess.run(
                [self.ini_exe] + args, capture_output=True, text=True,
                timeout=timeout, **_hidden_spawn_kwargs())
        except Exception as e:
            logger.debug(f'SbieIni 调用失败 {args}: {e}')
            return None

    def _find_user_settings_section(self) -> str:
        """定位 `[UserSettings_xxxx]` 段名（`SbieCtrl_*` 用户设置所在段）。

        `SbieCtrl_AutoRunSoftCompat` / `SbieCtrl_AutoApplySettings` 只有写在
        UserSettings 段才会被 Sandboxie 界面读取；段名含随机器/用户变化的
        哈希（如 `UserSettings_0D0C022E`），故运行时用 `SbieIni query *`
        枚举。**查不到时返回空字符串**（调用方跳过写入）—— 绝不回退写
        `GlobalSettings`，避免污染用户其它盒/全局配置。
        结果缓存，避免每次分析都起子进程。
        """
        cached = getattr(self, '_user_settings_section', None)
        if cached is not None:
            return cached
        sec = ''
        if self.ini_exe:
            try:
                r = subprocess.run([self.ini_exe, 'query', '*'],
                                   capture_output=True, text=True, timeout=10,
                                   **_hidden_spawn_kwargs())
                for line in (r.stdout or '').splitlines():
                    s = line.strip()
                    if s.lower().startswith('usersettings'):
                        sec = s
                        break
            except Exception as e:
                logger.debug(f'SbieIni 枚举配置段失败: {e}')
        self._user_settings_section = sec
        return sec

    def ensure_box(self) -> bool:
        """确保目标盒存在且**可用**，并下发分析所需设置。

        关键（实测 1.17/1.18，含全新安装、无任何盒的机器）：
        SbieIni 的 `set <box> <key> <value>` 会按需写出 `[<box>]` 段，但
        **段内必须含 `Enabled=y`**，SbieSvc 才把该名字视为有效盒；否则
        `Start.exe /box:<box>` 返回 1608 并弹出「无效的沙盒名参数」错误框
        （弹框会一直阻塞分析）。因此这里主动建段 + 置 Enabled=y。

        返回 True 表示盒确实可用（`/listpids` 退出码为 0）。
        """
        if not self.ini_exe or not self.start_exe:
            return False
        # 1) 建段并启用（先定文件根，再置 Enabled=y；对已存在的盒重复设置无害）
        if self._file_root:
            self._run_ini(['set', self.box, 'FileRootPath', self._file_root])
        self._run_ini(['set', self.box, 'Enabled', 'y'])
        # 2) 分析用设置：盒级断网 + 不自动删除
        self._run_ini(['set', self.box, 'NetworkAccess', 'n'])
        self._run_ini(['set', self.box, 'AutoDelete', 'n'])
        # 2.5) 提权/UAC 自动化（样本请求 UAC 提升时不再弹窗阻塞）
        #      默认情况下 Sandboxie 的 UAC 代理会弹「是否给予管理员权限」，
        #      分析环境无人确认 → 样本卡在提权处不产生任何行为 → 被误判 clean。
        #        DropAdminRights=y  剥离真实管理员组（绝不授予真提权，保护宿主）
        #        FakeAdminRights=y  让样本"以为"已提权，继续执行主逻辑 → 暴露行为
        #        NoUACProxy=n       **必须让 Sandboxie 的 UAC 代理继续接管提权**
        #          实测样本 G4m0ad2f1qi 用 ShellExecuteExW(lpVerb="runas")
        #          自提权：若放行原生 UAC 路径，consent.exe 提权出来的进程会
        #          **脱离沙箱在宿主运行**（沙箱逃逸 → 真实覆写 MBR）。
        #          置 n 让提权请求始终走 Sandboxie 代理，留在盒子管控内。
        #      仅作用于专用分析盒，不写 [GlobalSettings]、不影响用户其它盒。
        self._run_ini(['set', self.box, 'DropAdminRights', 'y'])
        self._run_ini(['set', self.box, 'FakeAdminRights', 'y'])
        self._run_ini(['set', self.box, 'NoUACProxy', 'n'])
        # 2.6) 抑制 Sandboxie 界面弹窗（分析环境无人值守，任何弹窗都会
        #      卡住分析或干扰用户；实测分析盒被 SbieCtrl 自动写入了
        #      RecoverFolder=%Desktop%/%Personal%/Downloads + 一串兼容性
        #      Template，导致样本一写桌面/文档就弹"可恢复文件"窗）：
        #        AutoRecover=n               关闭"立即恢复文件"弹窗
        #        BlockNetworkFiles=y         拒绝样本经网络共享读写真实文件
        #        SbieCtrl_AutoRunSoftCompat=n  关闭"软件兼容性"自动询问
        #        SbieCtrl_AutoApplySettings=n  禁止界面把兼容性模板自动写进
        #          分析盒（模板会引入 SkipHook/OpenFilePath 等，弱化隔离、
        #          甚至把写操作放行到真实系统 —— 也就是"有些对象跑到沙箱外"）
        self._run_ini(['set', self.box, 'AutoRecover', 'n'])
        self._run_ini(['set', self.box, 'BlockNetworkFiles', 'y'])
        # 清掉界面自动注入的恢复目录：分析盒不应把样本产物"恢复"到真实系统
        self._run_ini(['set', self.box, 'RecoverFolder'])
        _sec = self._find_user_settings_section()
        if _sec:
            self._run_ini(['set', _sec, 'SbieCtrl_AutoRunSoftCompat', 'n'])
            self._run_ini(['set', _sec, 'SbieCtrl_AutoApplySettings', 'n'])
        # 3) 文件根本地目录（Sandboxie 通常会自建，这里兜底）
        try:
            if self._file_root:
                os.makedirs(self._file_root, exist_ok=True)
        except Exception:
            pass
        # 4) 校验盒可用
        return self.is_box_available()

    def is_box_available(self) -> bool:
        """盒是否可用：`/silent /listpids` 退出码为 0（无效盒名返回 1608）。"""
        if not self.start_exe:
            return False
        try:
            r = subprocess.run(
                [self.start_exe, f'/box:{self.box}', '/silent', '/listpids'],
                capture_output=True, text=True, timeout=15,
                **_hidden_spawn_kwargs())
        except Exception as e:
            logger.debug(f'[Sandboxie] 盒可用性检查异常: {e}')
            return False
        if r.returncode != 0:
            logger.info(f'[Sandboxie] 盒 {self.box} 不可用（退出码 {r.returncode}）')
            return False
        return True

    def ensure_ready(self) -> bool:
        """确保后端可投入分析（盒存在且可用）。"""
        try:
            ok = self.ensure_box()
        except Exception as e:
            logger.warning(f'[Sandboxie] 盒准备失败: {e}')
            ok = False
        if not ok:
            logger.warning(f'[Sandboxie] 盒 {self.box} 无法启用，将回退 AppContainer 后端')
        return ok

    def reset_box(self):
        """清空盒内容，保证取证增量从零开始（文件 + 重定向注册表）。

        注意：`Start.exe /box:X /delete` 在本版本实测不可靠 —— 裸 `/delete`
        会弹出交互确认并一直挂住（30s 超时），加 `/silent` 则立即返回但**并不
        清理**。因此改为：先 `/terminate` 停掉盒内程序，再直接删除盒文件根
        （含 RegHive/LOCK/事务日志）。盒会在下次运行时由 Sandboxie 自动重建。
        """
        if self.start_exe:
            try:
                subprocess.run(
                    [self.start_exe, f'/box:{self.box}', '/silent', '/terminate'],
                    capture_output=True, text=True, timeout=15,
                    **_hidden_spawn_kwargs())
            except Exception as e:
                logger.debug(f'[Sandboxie] /terminate 异常: {e}')
        root = self._file_root
        if not root or not os.path.isdir(root):
            return
        try:
            for name in os.listdir(root):
                p = os.path.join(root, name)
                try:
                    if os.path.isdir(p):
                        shutil.rmtree(p, ignore_errors=True)
                    else:
                        os.remove(p)
                except Exception as e:
                    logger.debug(f'[Sandboxie] 清理盒内容失败 {p}: {e}')
        except Exception as e:
            logger.debug(f'[Sandboxie] 清理盒内容失败: {e}')

    @staticmethod
    def _parse_listpids(stdout: str) -> List[int]:
        """解析 Start.exe /listpids 输出。

        实测 Sandboxie-Plus 1.17/1.18 格式：首行是进程数 N，其后 N 行各一个
        PID（空盒输出 "0"）。为兼容无表头输出，仅当首值恰等于其余数字个数时
        才把它当作计数剔除。
        """
        toks: List[int] = []
        for line in (stdout or '').replace(',', ' ').splitlines():
            for t in line.split():
                if t.isdigit():
                    toks.append(int(t))
        if not toks:
            return []
        if toks[0] == len(toks) - 1:
            return toks[1:]
        return toks

    def _is_infra_pid(self, pid: int) -> bool:
        """判断 PID 是否为 Sandboxie 基础设施进程（非样本）。"""
        if not HAS_PSUTIL:
            return False
        try:
            proc = psutil.Process(pid)
            exe = ''
            try:
                exe = proc.exe() or ''
            except Exception:
                exe = ''
            if exe and self.install_dir and \
                    exe.lower().startswith(self.install_dir.lower()):
                return True
            name = (proc.name() or '').lower()
            if name.endswith('.exe'):
                name = name[:-4]
            return name in _SBIE_INFRA_NAMES
        except Exception:
            return False

    def list_pids(self, include_infra: bool = True) -> List[int]:
        """读取盒内正在运行的 PID 列表。

        include_infra=True 返回全部（含基础设施，供上游豁免登记，防快杀）；
        include_infra=False 时剔除基础设施，仅保留样本及其子进程。
        """
        if not self.start_exe:
            return []
        try:
            r = subprocess.run(
                [self.start_exe, f'/box:{self.box}', '/silent', '/listpids'],
                capture_output=True, text=True, timeout=10,
                **_hidden_spawn_kwargs())
        except Exception:
            return []
        pids = self._parse_listpids(r.stdout or '')
        if include_infra:
            return pids
        return [p for p in pids if not self._is_infra_pid(p)]

    def sample_pids(self) -> List[int]:
        """盒内样本进程 PID（已剔除 Sandboxie 基础设施）。"""
        return self.list_pids(include_infra=False)

    # ---- 后端接口 ----
    def launch(self, sample_path: str, on_progress: Optional[Callable] = None):
        """在盒中启动样本（不等待），返回 True/False。"""
        if not self.start_exe:
            return False
        cmd = [self.start_exe, f'/box:{self.box}', '/silent', '/hide_window', sample_path]
        logger.info(f'[Sandboxie] 启动样本: {" ".join(cmd)}')
        try:
            self._popen = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                **_hidden_spawn_kwargs())
        except Exception as e:
            logger.warning(f'[Sandboxie] 启动失败: {e}')
            return False
        # 等待盒内进程出现（最多 ~5s），取 PID 供行为监控复用。
        # 注意：/listpids 会把 SandboxieDcomLaunch/SandboxieRpcSs 等基础设施
        # 一并返回，必须剔除它们才能定位到样本 PID，否则监控存活检测会盯住
        # 常驻的基础设施进程而白等到超时（旧实现"卡住"的根因）。
        deadline = time.time() + 5.0
        while time.time() < deadline:
            all_pids = self.list_pids()
            if all_pids:
                self._target_pids = all_pids
                self._sample_pids = [p for p in all_pids if not self._is_infra_pid(p)]
                if self._sample_pids:
                    break
            time.sleep(0.3)
        return True

    def terminate(self):
        """终止盒内所有程序（+ 兜底杀 Start.exe 进程）。"""
        if self.start_exe:
            try:
                subprocess.run(
                    [self.start_exe, f'/box:{self.box}', '/silent', '/terminate'],
                    capture_output=True, text=True, timeout=15,
                    **_hidden_spawn_kwargs())
            except Exception as e:
                logger.debug(f'[Sandboxie] /terminate 异常: {e}')
        if self._popen is not None:
            try:
                if self._popen.poll() is None:
                    self._popen.terminate()
            except Exception:
                pass
            self._popen = None

    def collect_delta(self) -> List[dict]:
        try:
            from engine.sandboxie_delta import collect_all
            return collect_all(self._file_root, self.box)
        except Exception as e:
            logger.debug(f'[Sandboxie] 读取沙盘增量失败: {e}')
            return []

    def collect_registry_delta(self) -> List[dict]:
        """仅取注册表增量（盒终止后离线 reg load 兜底；需管理员）。"""
        try:
            from engine.sandboxie_delta import collect_registry
            return collect_registry(self.box, self._file_root)
        except Exception as e:
            logger.debug(f'[Sandboxie] 离线读取注册表增量失败: {e}')
            return []

    def collect_registry_mounted(self) -> List[dict]:
        """仅读连接态挂载 hive（免权限；用于样本存活期间的周期采样）。

        Sandboxie 的 RegHive 按需挂载、样本退出即卸载，故须在运行期采样；
        hive 为累积态，最后一次成功快照即本次运行的完整注册表增量。
        """
        try:
            from engine.sandboxie_delta import collect_registry
            return collect_registry(self.box, None)   # file_root=None → 不做离线加载
        except Exception as e:
            logger.debug(f'[Sandboxie] 连接态注册表采样失败: {e}')
            return []


class SandboxAnalyzer:
    """
    本地沙箱分析器

    在隔离的 Job Object 中执行可疑文件，
    监控进程树行为（psutil + 可选 frida），
    按行为评分判定威胁等级。
    """

    def __init__(self, config: SandboxConfig = None):
        self.config = config or SandboxConfig()
        self._behaviors: List[BehaviorRecord] = []
        self._process_tree: Dict[int, dict] = {}
        self._stop_event = threading.Event()
        self._job_handle = None
        self._target_pid = None
        self._work_dir = None
        self._frida_session = None
        self._lock = threading.Lock()
        self._restricted_token = None
        self._sandbox_file_path = None

        # ---- 方案A: 逃逸进程差异追踪状态 ----
        self._baseline_pids = None         # 沙箱启动时的系统进程基线快照
        self._escaped_pids = set()         # 检测到的逃逸进程 PID 集合
        self._last_escape_check = 0.0      # 上次逃逸检测时间戳
        # Sandboxie 后端标志：置位后停用"基线差异逃逸强杀"（见
        # _detect_escaped_processes 的说明）。
        self._sbie_pid_provider = None
        self._orig_sample_path = None     # 待分析样本原路径（逃逸归因用）

        if not _IS_WINDOWS:
            logger.warning('沙箱分析仅支持 Windows 平台')
        if not _WIN32:
            logger.warning('Win32 API 加载失败，沙箱功能不可用')

        # 隔离状态标志（_launch_sandboxed 中设置）
        self._job_isolated = False       # True=Job 绑定成功, False=仅令牌隔离
        self._proc_handle = None         # 保存进程句柄用于无 Job 时的兜底终止
        self._silo_active = False        # True=Job 已升级为 Server Silo 容器
        self._launch_error = None        # 最近一次 _launch_sandboxed 失败原因（可读）
        self._appcontainer_active = False  # True=样本已在 AppContainer 内运行（真实写隔离）
        self._appcontainer_ready = None    # 缓存的容器信息 {sid, attr_list, name, buf}
        self._appcontainer_created = False  # 配置文件是否由本实例创建（决定是否删除）

        # ---- 沙箱后端选择（Sandboxie 首选 / AppContainer 保底）----
        # 可选：上游注册盒内 PID 的回调（用于进程保护豁免，避免误杀 Start.exe/样本）
        self.on_sandbox_pids: Optional[Callable[[List[int]], None]] = None
        self._sandboxie_info = None
        self._backend = self._build_backend()

    def _build_backend(self):
        """按 config.backend 选择后端；Sandboxie 不可用时回退 AppContainer。"""
        want = str(getattr(self.config, 'backend', 'auto') or 'auto').strip().lower()
        if want not in ('auto', 'sandboxie', 'appcontainer'):
            want = 'auto'
        if want in ('auto', 'sandboxie'):
            info = detect_sandboxie_backend(self.config)
            self._sandboxie_info = info
            if info.get('available'):
                logger.info(f'沙箱后端: Sandboxie（{info.get("dir")}）')
                return SandboxieBackend(self, info)
            if want == 'sandboxie':
                logger.warning(
                    f'指定 Sandboxie 后端但不可用（{info.get("reason")}），回退 AppContainer')
            else:
                logger.info(
                    f'Sandboxie 不可用（{info.get("reason")}），使用 AppContainer 后端')
        return AppContainerBackend(self)

    @property
    def backend_name(self) -> str:
        return getattr(self._backend, 'name', 'appcontainer')

    def analyze(self, file_path: str,
                on_progress: Callable[[str, float], None] = None,
                context_trust: int = 0) -> dict:
        """
        分析可疑文件

        Args:
            file_path: 可执行文件路径
            on_progress: 进度回调 (stage, percent)
            context_trust: 上下文信任先验（0-100，来自上游进程保护模块的
                多维评估：进程来源/文件年龄/行为链历史等）。仅在"分数型"
                判定上生效（对下降总分的判定阈值做偏移），一票否决的硬证据
                （勒索加密/删除卷影/银狐≥3 等）不会被信任先验豁免——保证
                真正的恶意软件即使在可信背景下也不会因信任放行。

        Returns:
            {
                'verdict': 'malware' | 'suspicious' | 'clean' | 'error',
                'score': int (0-100),
                'behaviors': [BehaviorRecord.to_dict(), ...],
                'duration': float (秒),
                'process_tree': dict,
                'file_path': str,
                'frida_used': bool,
                'error': str (仅 verdict=error 时),
                'hard_malware': bool,   # 一票否决硬证据是否触发
                'raw_score': int,       # 未应用信任偏移的原始分
                'trust_offset': int,    # 已应用的信任偏移分
            }
        """
        result = {
            'verdict': 'error',
            'score': 0,
            'behaviors': [],
            'duration': 0.0,
            'process_tree': {},
            'file_path': file_path,
            'frida_used': False,
            'isolation_level': 'unknown',  # 'L1' (Job+Token) | 'L2' (仅Token) | 'unknown'
            'silo_active': False,          # 是否使用 Server Silo 容器隔离
            'error': '',
        }

        if not _IS_WINDOWS or not _WIN32:
            result['error'] = '沙箱分析仅支持 Windows 平台'
            return result

        if not os.path.isfile(file_path):
            result['error'] = f'文件不存在: {file_path}'
            return result

        # 检查是否为可执行文件
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in ('.exe', '.scr', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.js'):
            result['error'] = f'沙箱分析仅支持可执行文件，当前扩展名: {ext}'
            return result

        # 记录待分析样本原路径：逃逸归因过滤用（恶意样本常重挂后
        # 再启动原样本，命令行会引用该路径）。
        self._orig_sample_path = file_path

        # 后端分派：首选 Sandboxie 时走独立链路（其余逻辑/契约完全一致）。
        # 先确保盒可用（全新安装的机器上盒可能不存在，ensure_box 会按需
        # 创建并置 Enabled=y）；建不起来则**回退 AppContainer**，绝不带着
        # 无效盒名继续（那会弹出「无效的沙盒名参数」错误框并卡住分析）。
        if self.backend_name == 'sandboxie':
            if self._backend.ensure_ready():
                return self._analyze_via_sandboxie(
                    file_path, on_progress=on_progress, context_trust=context_trust)
            logger.warning('Sandboxie 盒不可用，改用 AppContainer 后端分析')
            self._backend = AppContainerBackend(self)

        start_time = time.time()
        self._behaviors = []
        self._process_tree = {}
        self._stop_event.clear()

        # 0. 启用 SeDebugPrivilege（若 PSLS 持有该特权）：
        #    使后续的用户态终止能打开并结束"UAC 提权/高完整性"逃逸进程，
        #    否则 psutil.kill 对管理员提权进程会 AccessDenied、逃逸无法回收。
        self._enable_se_debug()

        try:
            if on_progress:
                on_progress('正在创建隔离环境...', 0.1)

            # 1. 创建 Job Object
            job_handle = self._create_job_object()
            if not job_handle:
                result['error'] = '创建 Job Object 失败'
                result['duration'] = time.time() - start_time
                return result
            self._job_handle = job_handle

            # 2. 创建工作目录
            self._work_dir = self.config.work_dir or tempfile.mkdtemp(prefix='psls_sandbox_')
            os.makedirs(self._work_dir, exist_ok=True)

            # 2.1 将文件复制到沙箱临时目录，避免原文件被恶意程序修改/删除
            sandbox_file_path = os.path.join(
                self._work_dir,
                f'sample_{os.getpid()}_{time.time_ns():x}{ext}'
            )
            try:
                _ok, _why = copy_sample_with_retry(file_path, sandbox_file_path)
                if not _ok:
                    raise IOError(_why)
                self._sandbox_file_path = sandbox_file_path
                logger.info(f'文件已复制到沙箱: {sandbox_file_path}')
            except Exception as e:
                # 复制失败（最常见原因：源文件被 PSLS 自身以 share=0 独占锁定，
                # 见 process_protection 沙箱拦截阶段1的 exe 锁 / 实时防护的文件锁）。
                # 历史实现在这里回退"直接从原路径启动"：若源文件正被独占锁定，
                # CreateProcessW 必然返回 ERROR_SHARING_VIOLATION(32)，沙箱因此
                # 判为启动失败而被上游强制隔离（误隔离用户程序）。
                # 现在不再直启原文件：正常流程下调用侧已传入可读的运行副本
                # （PSLS 预复制），此处只兜底极端场景；返回明确 error，绝不误隔离。
                logger.warning(f'文件复制到沙箱失败，放弃启动（不再直启被独占锁定的原文件）: {e}')
                self._launch_error = f'文件复制到沙箱失败（源文件可能被独占锁定）: {e}'
                self._cleanup()
                result['error'] = self._launch_error
                result['duration'] = time.time() - start_time
                return result

            if on_progress:
                on_progress('正在启动沙箱进程...', 0.2)

            # 2.5 静态预检：PE 特征 + 可疑字符串快速筛查
            # 在沙箱执行前先做静态分析，如果静态特征已高度可疑，
            # 即使行为不多也能贡献分数，提高检测率
            if on_progress:
                on_progress('正在执行静态特征预检...', 0.15)
            self._static_precheck(sandbox_file_path)
            static_behavior_count = len(self._behaviors)
            if static_behavior_count > 0:
                logger.info(f'静态预检发现 {static_behavior_count} 项可疑特征')

            # 3. 在 Job Object 中启动进程（经后端分派，AppContainer 后端等价）
            pi = self._backend.launch(sandbox_file_path)
            if not pi:
                result['error'] = self._launch_error or '沙箱进程启动失败'
                self._cleanup()
                result['duration'] = time.time() - start_time
                return result

            self._target_pid = pi.dwProcessId

            # 方案C: 启动后立即对目标进程断网（内核 WFP 拦截），
            # 阻断恶意样本自身的 C2 回连与 payload 下载。
            if self._block_process_net(self._target_pid):
                logger.info(f'沙箱目标进程已断网: PID={self._target_pid}')

            # 4. 启动行为监控
            if on_progress:
                on_progress('正在监控系统行为...', 0.3)

            monitor_thread = threading.Thread(
                target=self._monitor_behavior,
                daemon=True,
                name=f'sandbox-monitor-{self._target_pid}'
            )
            monitor_thread.start()

            # 5. 可选：启动 frida hook
            # 注意：use_frida 默认已关闭（见 SandboxConfig.__init__）。
            # 如果用户显式开启，必须先等待目标进程 MSVCP140.dll 完成 CRT
            # 初始化（至少 500ms），否则 frida.attach 立即改写目标进程内存
            # 会导致父进程 PSLS.exe 中 PyQt5 加载的同一份 MSVCP140.dll 出现
            # 偏移 0x12ea0 处的 0xc0000005 访问冲突（两进程共享同一
            # section 的物理页，frida 改 IAT 时 page protection 切换引发 TLB 冲突）。
            if self.config.use_frida and HAS_FRIDA:
                if on_progress:
                    on_progress('正在附加 API 监控...', 0.4)
                delay_ms = max(500, getattr(self.config, 'frida_attach_delay_ms', 500))

                def _frida_worker(delay_ms=delay_ms):
                    try:
                        time.sleep(delay_ms / 1000.0)
                        if self._stop_event.is_set():
                            return
                        # 再次确认进程存活
                        if not self._is_process_alive(self._target_pid):
                            return
                        self._setup_frida_hooks(self._target_pid)
                    except Exception as _e:
                        logger.debug(f'frida worker 异常（降级psutil）: {_e}')

                frida_thread = threading.Thread(
                    target=_frida_worker,
                    daemon=True,
                    name=f'sandbox-frida-{self._target_pid}'
                )
                frida_thread.start()
                result['frida_used'] = True

            # 6. 等待超时或进程退出
            deadline = time.time() + self.config.timeout
            while time.time() < deadline:
                if self._stop_event.is_set():
                    break

                # 检查目标进程是否仍在运行
                if not self._is_process_alive(self._target_pid):
                    self._add_behavior('process', 'info',
                                       '目标进程已退出',
                                       f'PID={self._target_pid}', score=0)
                    break

                remaining = max(0, deadline - time.time())
                progress = 0.3 + 0.6 * (1 - remaining / self.config.timeout)
                if on_progress:
                    on_progress(f'正在分析行为... {remaining:.0f}s', progress)

                time.sleep(0.5)

            if on_progress:
                on_progress('正在生成分析报告...', 0.95)

            # 7. 终止 Job Object 中所有进程（经后端分派）
            self._backend.terminate()

            # 等待监控线程结束
            self._stop_event.set()
            monitor_thread.join(timeout=3)

            # 8. 分析行为，生成判定
            # 应用上下文信任先验偏移（仅影响分数型判定，硬证据不被豁免）
            trust_offset = max(0, min(context_trust, 100)) // 5
            score, verdict, force_malware = self._score_behaviors(
                trust_offset=trust_offset)

            result['verdict'] = verdict
            result['score'] = score
            result['hard_malware'] = bool(force_malware)
            result['raw_score'] = score + trust_offset
            result['trust_offset'] = trust_offset
            result['behaviors'] = [b.to_dict() for b in self._behaviors]
            result['duration'] = round(time.time() - start_time, 2)
            result['process_tree'] = self._build_process_tree_dict()
            result['isolation_level'] = 'L1' if self._job_isolated else 'L2'
            result['silo_active'] = bool(self._silo_active)

            if on_progress:
                on_progress('分析完成', 1.0)

        except Exception as e:
            logger.error(f'沙箱分析异常: {e}', exc_info=True)
            result['error'] = f'分析异常: {e}'
            result['duration'] = round(time.time() - start_time, 2)
        finally:
            self._cleanup()

        return result

    # ========================================================================
    # Sandboxie 后端链路（首选）
    # ========================================================================

    def _analyze_via_sandboxie(self, file_path: str,
                               on_progress: Callable[[str, float], None] = None,
                               context_trust: int = 0) -> dict:
        """经 Sandboxie 专用盒引爆样本，读沙盘增量取证，复用同一打分/契约。

        与 AppContainer 链路的差异仅在“启动/终止/取证”，判定与返回结构一致。
        """
        result = {
            'verdict': 'error', 'score': 0, 'behaviors': [], 'duration': 0.0,
            'process_tree': {}, 'file_path': file_path, 'frida_used': False,
            'isolation_level': 'sandboxie', 'silo_active': False, 'error': '',
            'backend': 'sandboxie',
        }
        backend = self._backend
        start_time = time.time()
        self._behaviors = []
        self._process_tree = {}
        self._stop_event.clear()
        self._enable_se_debug()

        ext = os.path.splitext(file_path)[1].lower()
        try:
            if on_progress:
                on_progress('正在准备 Sandboxie 沙盒...', 0.1)
            self._work_dir = self.config.work_dir or tempfile.mkdtemp(prefix='psls_sandbox_')
            os.makedirs(self._work_dir, exist_ok=True)
            sandbox_file_path = os.path.join(
                self._work_dir, f'sample_{os.getpid()}_{time.time_ns():x}{ext}')
            try:
                shutil.copy2(file_path, sandbox_file_path)
                self._sandbox_file_path = sandbox_file_path
            except Exception as e:
                result['error'] = f'文件复制到沙箱失败: {e}'
                result['duration'] = round(time.time() - start_time, 2)
                self._cleanup()
                return result

            # 静态预检（与 AppContainer 链路一致）
            if on_progress:
                on_progress('正在执行静态特征预检...', 0.15)
            self._static_precheck(sandbox_file_path)

            # 盒重置：清空上次运行残留（盒可用性已由 analyze() 的
            # ensure_ready() 保证）
            try:
                backend.reset_box()
            except Exception as e:
                logger.warning(f'Sandboxie 盒清理失败: {e}')

            if on_progress:
                on_progress('正在启动 Sandboxie 沙盒进程...', 0.2)
            if not backend.launch(sandbox_file_path, on_progress):
                result['error'] = 'Sandboxie 启动失败'
                result['duration'] = round(time.time() - start_time, 2)
                self._cleanup()
                return result

            # 取盒内 PID：全部 PID（含 Sandboxie 基础设施）交上游登记豁免，
            # 防快杀误伤 Start.exe/SbieSvc；样本 PID 用于存活检测与断网。
            all_pids = list(getattr(backend, '_target_pids', []) or [])
            sample_pids = list(getattr(backend, '_sample_pids', []) or [])
            self._target_pid = sample_pids[0] if sample_pids else (
                all_pids[0] if all_pids else None)
            if self.on_sandbox_pids:
                try:
                    self.on_sandbox_pids(all_pids)
                except Exception as e:
                    logger.debug(f'on_sandbox_pids 回调异常: {e}')
            for _p in (sample_pids or all_pids):
                try:
                    self._block_process_net(_p)
                except Exception:
                    pass

            # 置位 Sandboxie 标志：停用"基线差异逃逸强杀"（该法会误杀
            # 分析窗口内新出现的无关系统进程，如浏览器/杀软更新）。
            self._sbie_pid_provider = getattr(backend, 'list_pids', None)

            if on_progress:
                on_progress('正在监控系统行为...', 0.3)
            monitor_thread = threading.Thread(
                target=self._monitor_behavior, daemon=True,
                name='sandbox-monitor-sbie')
            monitor_thread.start()

            deadline = time.time() + self.config.timeout
            next_box_poll = time.time() + 1.5
            # 运行期注册表采样：Sandboxie hive 按需挂载、样本退出即卸载，
            # 必须趁样本存活时抓取；hive 累积，最后一次成功快照即完整增量。
            reg_snapshot: List[dict] = []
            next_reg_poll = time.time() + 2.0
            empty_hits = 0
            while time.time() < deadline:
                if self._stop_event.is_set():
                    break
                now = time.time()
                if self._target_pid and not self._is_process_alive(self._target_pid):
                    # 目标可能是瞬时启动器（reg.exe 等，批次早期就退出）。
                    # 若盒内仍有样本进程，改盯其中一个继续监控，避免过早收尾。
                    dead_pid = self._target_pid
                    try:
                        alive = [p for p in backend.sample_pids() if p != dead_pid]
                    except Exception:
                        alive = []
                    if alive:
                        self._target_pid = alive[0]
                        empty_hits = 0
                    else:
                        # 批次间隙盒可能瞬时为空，连续两次为空才认定样本结束
                        empty_hits += 1
                        if empty_hits >= 2:
                            self._add_behavior('process', 'info', '目标进程已退出',
                                               f'PID={dead_pid}', score=0)
                            break
                elif not self._target_pid and now >= next_box_poll:
                    # 样本 PID 未知时的兜底：按盒内进程是否清空判定结束，
                    # 避免样本已退出却仍白等到超时。要求连续两次为空以容忍
                    # 单次 /listpids 查询失败。
                    next_box_poll = now + 1.5
                    try:
                        empty = not backend.sample_pids()
                    except Exception:
                        empty = False
                    empty_hits = empty_hits + 1 if empty else 0
                    if empty_hits >= 2:
                        self._add_behavior('process', 'info',
                                           '沙箱内进程已全部退出', '', score=0)
                        break
                # 周期采样连接态 hive（免权限；样本退出后 hive 会卸载）
                if now >= next_reg_poll:
                    next_reg_poll = now + 2.0
                    try:
                        snap = backend.collect_registry_mounted()
                        if any(r.get('category') == 'registry' for r in snap):
                            reg_snapshot = snap
                    except Exception:
                        pass
                remaining = max(0, deadline - time.time())
                if on_progress:
                    on_progress(f'正在分析行为... {remaining:.0f}s',
                                0.3 + 0.6 * (1 - remaining / self.config.timeout))
                time.sleep(0.5)

            # 取证（第一遍）：盒若仍活跃，注册表可命中连接态挂载 hive
            recs: List[dict] = []
            try:
                recs = list(backend.collect_delta() or [])
            except Exception as e:
                logger.debug(f'沙盘增量读取失败: {e}')

            # 终止盒内进程：①释放 RegHive 文件锁，使离线 reg load 可用；
            # ②确保文件增量读取时不再有进程写入。盒内容持久（AutoDelete=n）。
            backend.terminate()
            self._stop_event.set()
            monitor_thread.join(timeout=3)

            # 取证（第二遍）：首遍未取到注册表增量时，终止后离线 reg load
            # 兜底（reg load 需管理员；PSLS 以管理员运行，故为常规路径）。
            if not any(r.get('category') == 'registry' for r in recs):
                try:
                    recs.extend(backend.collect_registry_delta() or [])
                except Exception as e:
                    logger.debug(f'离线注册表增量读取失败: {e}')

            # 仍无注册表增量 → 用运行期采样快照（免权限下最可靠的来源）
            if not any(r.get('category') == 'registry' for r in recs) and reg_snapshot:
                recs.extend(reg_snapshot)

            for rec in recs:
                try:
                    self._add_behavior(
                        rec.get('category', 'file'),
                        rec.get('severity', 'warn'),
                        rec.get('description', ''),
                        rec.get('detail', ''),
                        score=int(rec.get('score', 0) or 0))
                except Exception as e:
                    logger.debug(f'沙盘增量注入失败: {e}')

            if on_progress:
                on_progress('正在生成分析报告...', 0.95)

            trust_offset = max(0, min(context_trust, 100)) // 5
            score, verdict, force_malware = self._score_behaviors(trust_offset=trust_offset)
            result['verdict'] = verdict
            result['score'] = score
            result['hard_malware'] = bool(force_malware)
            result['raw_score'] = score + trust_offset
            result['trust_offset'] = trust_offset
            result['behaviors'] = [b.to_dict() for b in self._behaviors]
            result['duration'] = round(time.time() - start_time, 2)
            result['process_tree'] = self._build_process_tree_dict()

            if on_progress:
                on_progress('分析完成', 1.0)
        except Exception as e:
            logger.error(f'Sandboxie 沙箱分析异常: {e}', exc_info=True)
            result['error'] = f'分析异常: {e}'
            result['duration'] = round(time.time() - start_time, 2)
        finally:
            self._cleanup()

        return result

    # ========================================================================
    # Job Object 隔离层
    # ========================================================================

    # ------------------------------------------------------------------
    # AppContainer 真实写隔离（Windows 8+，无需第三方驱动/管理员）
    # ------------------------------------------------------------------

    def _prepare_appcontainer(self, work_dir: str) -> Optional[dict]:
        """创建/复用 AppContainer 配置文件并构建属性列表。

        成功返回 {'sid', 'attr_list', 'name', 'buf', 'caps'} 并授予容器 SID
        工作目录的读写执行权限；任何一步失败返回 None（调用方回退原有
        Job+Token 启动链路，行为完全不变）。

        启用后样本以**低完整性 + 容器 SID**运行：对真实文件/注册表无写权限，
        仅能写入工作目录 —— 真正的"写隔离"，而非"跑在真实系统上靠事后杀进程"。
        """
        try:
            if not getattr(self.config, 'use_appcontainer', True):
                return None
            if not _WIN32 or 'CreateAppContainerProfile' not in _WIN32:
                logger.info('AppContainer 不可用（userenv 导出缺失），使用 Job+Token 隔离')
                return None
            if self._appcontainer_ready is not None:
                return self._appcontainer_ready

            name = f'PSLS.Sandbox.{os.getpid()}'
            sid = ctypes.c_void_p()
            hr = _WIN32['CreateAppContainerProfile'](
                name, 'PSLS Sandbox', 'PSLS 动态分析容器', None, 0,
                ctypes.byref(sid))
            if hr != 0:
                if hr == _HRESULT_ALREADY_EXISTS:
                    hr2 = _WIN32['DeriveAppContainerSidFromAppContainerName'](
                        name, ctypes.byref(sid))
                    if hr2 != 0 or not sid.value:
                        logger.debug(
                            f'AppContainer SID 派生失败 hr=0x{hr2 & 0xffffffff:08x}')
                        return None
                else:
                    logger.info(
                        f'CreateAppContainerProfile 失败 hr=0x{hr & 0xffffffff:08x}，'
                        f'降级为 Job+Token 隔离')
                    return None
            else:
                self._appcontainer_created = True
            if not sid.value:
                return None

            # 属性列表（1 个属性：SECURITY_CAPABILITIES）
            size = ctypes.c_size_t(0)
            _WIN32['InitializeProcThreadAttributeList'](
                None, 1, 0, ctypes.byref(size))
            if not size.value:
                return None
            buf = ctypes.create_string_buffer(size.value)
            attr_list = ctypes.cast(buf, ctypes.c_void_p)
            if not _WIN32['InitializeProcThreadAttributeList'](
                    attr_list, 1, 0, ctypes.byref(size)):
                logger.info('InitializeProcThreadAttributeList 失败，降级 Job+Token')
                return None

            # 默认不授予任何能力：容器内无网络、无真实文件/注册表写权限
            caps = _SECURITY_CAPABILITIES()
            caps.AppContainerSid = ctypes.c_void_p(sid.value)
            caps.Capabilities = None
            caps.CapabilityCount = 0
            caps.Reserved = 0
            if not _WIN32['UpdateProcThreadAttribute'](
                    attr_list, 0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    ctypes.addressof(caps), ctypes.sizeof(caps), None, None):
                _WIN32['DeleteProcThreadAttributeList'](attr_list)
                logger.info('UpdateProcThreadAttribute 失败，降级 Job+Token')
                return None

            info = {'sid': sid.value, 'attr_list': attr_list,
                    'name': name, 'buf': buf, 'caps': caps}
            # 授予容器 SID 工作目录权限（容器默认连用户临时目录都无权限）
            self._grant_appcontainer_workdir(work_dir, sid.value)
            self._appcontainer_ready = info
            logger.info(f'AppContainer 已就绪: {name}（样本无真实写权限/无网络）')
            return info
        except Exception as e:
            logger.warning(f'AppContainer 准备异常，降级为 Job+Token: {e}')
            return None

    @staticmethod
    def _grant_appcontainer_workdir(work_dir: str, sid_value: int) -> None:
        """授予 AppContainer 容器 SID 对工作目录的读写执行权限（best-effort）。

        容器内进程默认对用户目录/临时目录无访问权限（这正是写隔离的来源），
        必须显式授权工作目录，样本才能在其中解压、落地、执行（否则启动即失败）。
        """
        try:
            if not work_dir or not os.path.isdir(work_dir):
                return
            if not _WIN32 or 'ConvertSidToStringSidW' not in _WIN32:
                return
            str_sid = ctypes.c_void_p()
            if not _WIN32['ConvertSidToStringSidW'](
                    ctypes.c_void_p(sid_value), ctypes.byref(str_sid)):
                return
            try:
                sid_str = ctypes.wstring_at(str_sid.value)
            finally:
                try:
                    _WIN32['LocalFree'](str_sid)
                except Exception:
                    pass
            if not sid_str:
                return
            import subprocess
            subprocess.run(
                ['icacls', work_dir, '/grant',
                 f'*{sid_str}:(OI)(CI)M', '/T', '/C', '/Q'],
                capture_output=True, timeout=20, **_hidden_spawn_kwargs())
            logger.debug(f'已授予容器 SID 工作目录权限: {sid_str} -> {work_dir}')
        except Exception as e:
            logger.debug(f'授予容器工作目录权限失败（非致命）: {e}')

    def _release_appcontainer(self) -> None:
        """释放属性列表，并删除"由本实例创建"的 AppContainer 配置文件。"""
        info = self._appcontainer_ready
        self._appcontainer_ready = None
        self._appcontainer_active = False
        if not info or not _WIN32:
            return
        try:
            if info.get('attr_list') is not None and \
                    'DeleteProcThreadAttributeList' in _WIN32:
                _WIN32['DeleteProcThreadAttributeList'](info['attr_list'])
        except Exception:
            pass
        if self._appcontainer_created:
            try:
                if 'DeleteAppContainerProfile' in _WIN32:
                    _WIN32['DeleteAppContainerProfile'](info.get('name') or '')
            except Exception:
                pass
            self._appcontainer_created = False

    def _create_job_object(self) -> Optional[int]:
        """创建配置好限制的 Job Object"""
        try:
            sa = _SECURITY_ATTRIBUTES()
            sa.nLength = ctypes.sizeof(_SECURITY_ATTRIBUTES)
            sa.lpSecurityDescriptor = None
            sa.bInheritHandle = False

            job_handle = _WIN32['CreateJobObjectW'](ctypes.byref(sa), None)
            if not job_handle:
                err = ctypes.get_last_error()
                logger.error(f'CreateJobObjectW 失败: {err}')
                return None

            # ---- Silo 升级（可选，尽力而为）----
            # 在设置限制前先将 Job 升级为 Server Silo 容器。
            # Silo 提供独立命名空间与更强的进程树捕获能力，可降低
            # WMI/计划任务/SCM 重挂逃逸的风险。失败则降级为普通 Job。
            self._silo_active = False
            if getattr(self.config, 'use_silo', False) and _WIN32.get('GetInformationJobObject'):
                try:
                    ok_silo = _WIN32['SetInformationJobObject'](
                        job_handle, JobObjectCreateSilo, None, 0
                    )
                    if ok_silo:
                        # 查询确认 Silo 已生效（SiloBasicInformation 非零 ID）
                        silo_id = ctypes.c_ulonglong(0)
                        if _WIN32['GetInformationJobObject'](
                            job_handle, JobObjectSiloBasicInformation,
                            ctypes.byref(silo_id), ctypes.sizeof(silo_id)
                        ):
                            self._silo_active = True
                            logger.info(f'Server Silo 已创建并生效: SiloID={silo_id.value}')
                        else:
                            # 创建成功但查询失败，仍按 Silo 处理（保守）
                            self._silo_active = True
                            logger.info('Server Silo 已创建（查询状态失败，视为生效）')
                    else:
                        err = ctypes.get_last_error()
                        logger.warning(
                            f'Server Silo 升级失败(err={err})，'
                            f'降级为普通 Job Object'
                        )
                except Exception as e:
                    logger.warning(f'Server Silo 升级异常，降级为普通 Job Object: {e}')
                    self._silo_active = False

            # 设置扩展限制
            # 分步降级：内存限制在某些 Windows 版本上可能返回 87 (INVALID_PARAMETER)，
            # 核心限制 (KILL_ON_JOB_CLOSE + ACTIVE_PROCESS + UI restrictions) 必须生效
            limits = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            limits.BasicLimitInformation.ActiveProcessLimit = self.config.max_active_processes
            limits.BasicLimitInformation.PriorityClass = 0x40  # BELOW_NORMAL_PRIORITY
            limits.BasicLimitInformation.SchedulingClass = 5

            # 核心限制（必设）
            core_flags = (
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
                JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            )
            limits.BasicLimitInformation.LimitFlags = core_flags

            ok = _WIN32['SetInformationJobObject'](
                job_handle, JobObjectExtendedLimitInformation,
                ctypes.byref(limits), ctypes.sizeof(limits)
            )
            if not ok:
                err = ctypes.get_last_error()
                logger.error(f'SetInformationJobObject(core) 失败: {err}')
                # 核心限制都设不上，这个 Job Object 基本没法用了
                _WIN32['CloseHandle'](job_handle)
                return None

            # 内存限制（尽力而为，失败跳过）
            mem_flags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY
            limits2 = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            limits2.BasicLimitInformation.LimitFlags = core_flags | mem_flags
            limits2.BasicLimitInformation.ActiveProcessLimit = self.config.max_active_processes
            limits2.BasicLimitInformation.PriorityClass = 0x40
            limits2.BasicLimitInformation.SchedulingClass = 5
            limits2.ProcessMemoryLimit = self.config.max_memory_mb * 1024 * 1024
            limits2.JobMemoryLimit = self.config.max_job_memory_mb * 1024 * 1024

            ok2 = _WIN32['SetInformationJobObject'](
                job_handle, JobObjectExtendedLimitInformation,
                ctypes.byref(limits2), ctypes.sizeof(limits2)
            )
            if not ok2:
                logger.info(f'内存限制设置失败 (err={ctypes.get_last_error()})，核心限制已生效')
            else:
                logger.info('内存限制已启用')

            # 设置 UI 限制
            ui_restrict = ctypes.wintypes.DWORD(self.config.ui_restrictions)
            ok = _WIN32['SetInformationJobObject'](
                job_handle, JobObjectBasicUIRestrictions,
                ctypes.byref(ui_restrict), ctypes.sizeof(ui_restrict)
            )
            if not ok:
                logger.warning(f'SetInformationJobObject(UI) 失败: {ctypes.get_last_error()}')

            logger.info(f'Job Object 创建成功: handle={job_handle}')
            return job_handle

        except Exception as e:
            logger.error(f'创建 Job Object 异常: {e}')
            return None

    def _launch_sandboxed(self, file_path: str, job_handle: int) -> Optional[_PROCESS_INFORMATION]:
        """在隔离环境中以挂起状态启动进程，然后恢复执行。

        隔离层级（按优先级降级）：
          L1: Job Object (KILL_ON_JOB_CLOSE + 资源限制) + 令牌特权禁用
          L2: 仅令牌特权禁用（Job 绑定失败时降级）
          L3: 终止进程（两者都失败时不允许执行）

        策略：
          1. CREATE_SUSPENDED 创建进程
          2. 先做令牌限制（基础隔离，不依赖 Job）
          3. 再尝试 AssignProcessToJobObject（额外资源限制）
          4. 如果令牌限制成功但 Job 失败 → 降级到 L2 继续执行
          5. 如果两者都失败 → 终止进程，返回 None
        """
        try:
            si = _STARTUPINFOW()
            ctypes.memset(ctypes.byref(si), 0, ctypes.sizeof(si))
            si.cb = ctypes.sizeof(_STARTUPINFOW)
            si.dwFlags = STARTF_USESHOWWINDOW
            si.wShowWindow = SW_HIDE
            si.lpDesktop = None
            si.lpReserved = None
            si.lpTitle = None
            si.cbReserved2 = 0
            si.lpReserved2 = None
            si.hStdInput = None
            si.hStdOutput = None
            si.hStdError = None

            work_dir = self._work_dir or os.path.dirname(file_path)

            # 脚本类文件需要解释器包装（cmdline 拼接解释器 + 脚本路径），
            # 直接 CreateProcessW 脚本会返回 193/5 等错误导致启动失败
            interp = _SCRIPT_INTERPRETERS.get(os.path.splitext(file_path)[1].lower())
            if interp:
                cmdline_text = f'{interp} "{file_path}"'
                logger.info(f'检测到脚本类文件，使用解释器包装: {interp}')
            else:
                cmdline_text = f'"{file_path}"'
            cmdline = ctypes.create_unicode_buffer(cmdline_text, 32768)

            # ---- AppContainer 真实写隔离准备（best-effort，失败自动回退）----
            # 成功：样本在容器内以低完整性运行，对真实文件/注册表无写权限；
            # 失败：_si_ex_holder 为空 → 走下方原有 Job+Token 启动路径，行为不变。
            _appc = self._prepare_appcontainer(work_dir)
            _si_ex_holder: list = []
            if _appc is not None:
                _si_ex_holder.append(
                    _make_appcontainer_startupinfo(_appc['attr_list']))

            def _spawn(flags: int) -> bool:
                """按是否启用 AppContainer 选择扩展/常规 CreateProcessW。"""
                if _si_ex_holder:
                    return bool(_WIN32['CreateProcessW_Ex'](
                        None, cmdline, None, None, False,
                        flags | EXTENDED_STARTUPINFO_PRESENT, None, work_dir,
                        ctypes.addressof(_si_ex_holder[0]),
                        ctypes.byref(pi)))
                return bool(_WIN32['CreateProcessW'](
                    None, cmdline, None, None, False, flags, None, work_dir,
                    ctypes.byref(si), ctypes.byref(pi)))

            # 预检查：当前进程是否在 Job 中
            # 如果在 Job 中且不允许 BREAKAWAY，直接跳过 BREAKAWAY 避免无谓失败
            in_job = ctypes.wintypes.BOOL(False)
            try:
                _WIN32['IsProcessInJob'](_WIN32['GetCurrentProcess'](), None, ctypes.byref(in_job))
            except Exception:
                in_job = ctypes.wintypes.BOOL(False)

            pi = _PROCESS_INFORMATION()
            ctypes.memset(ctypes.byref(pi), 0, ctypes.sizeof(pi))

            # 阶段 1: 如果不在 Job 中，直接创建；否则尝试 BREAKAWAY
            if not in_job.value:
                creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW
                ok = _spawn(creation_flags)
            else:
                # 在 Job 中 — 先尝试 BREAKAWAY
                creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB
                ok = _spawn(creation_flags)
                if not ok and ctypes.get_last_error() == 5:  # ERROR_ACCESS_DENIED
                    # 父级 Job 不允许 break away — 降级为不带 BREAKAWAY
                    logger.info('BREAKAWAY 被父级 Job 拒绝，降级为不带 BREAKAWAY')
                    creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW
                    ctypes.memset(ctypes.byref(pi), 0, ctypes.sizeof(pi))
                    ok = _spawn(creation_flags)

            # === 安全网：AppContainer 启动失败必须回退常规启动 ===
            # 若让隔离层自身导致"启动失败"，上层会把它当成"样本反沙箱/沙箱启动失败"
            # 并强制隔离该文件（_handle_sandbox_launch_failure）——这正是此前误隔离
            # 宿主 IDE 的同一类灾难。因此 AppContainer 启动失败时，清空扩展启动、
            # 立即用常规 Job+Token 路径重试；只有两条路径都失败才算真正的启动失败。
            if not ok and _si_ex_holder:
                _appc_err = ctypes.get_last_error()
                logger.warning(
                    f'AppContainer 启动失败(err={_appc_err})，回退常规 Job+Token 启动 '
                    f'(cmdline={cmdline_text})')
                _si_ex_holder.clear()
                self._appcontainer_active = False
                ctypes.memset(ctypes.byref(pi), 0, ctypes.sizeof(pi))
                ok = _spawn(creation_flags)

            if not ok:
                err = ctypes.get_last_error()
                reason = _LAUNCH_ERROR_REASONS.get(err, f'未知错误({err})')
                self._launch_error = f'CreateProcessW 失败 (err={err}): {reason}'
                logger.error(
                    f'CreateProcessW 失败: {err} ({reason}), cmdline={cmdline_text}'
                )
                return None

            logger.info(f'进程已创建（挂起）: PID={pi.dwProcessId}')

            if _si_ex_holder:
                # 通过扩展启动创建 ⇒ 已进入 AppContainer（低完整性 + 容器 SID）
                self._appcontainer_active = True
                logger.info('样本已在 AppContainer 内运行（真实写隔离生效）')

            proc_handle = pi.hProcess

            # ---- 隔离层 1: 令牌特权禁用（基础隔离，不依赖 Job）----
            token_ok = self._restrict_process_token(pi.dwProcessId, proc_handle)
            if not token_ok:
                logger.warning(f'令牌限制失败，尝试 Job 隔离作为唯一隔离层')

            # ---- 隔离层 2: Job Object 绑定（资源限制 + KILL_ON_JOB_CLOSE）----
            job_ok = _WIN32['AssignProcessToJobObject'](job_handle, proc_handle)
            if job_ok:
                logger.info(f'进程已绑定到沙箱 Job: PID={pi.dwProcessId}')
            else:
                err = ctypes.get_last_error()
                logger.warning(
                    f'AssignProcessToJobObject 失败(err={err})，'
                    f'PID={pi.dwProcessId}'
                )

            # ---- 降级决策 ----
            # 安全策略：严禁"无 Job"降级执行（原 L2 仅 Token 模式）。
            # Job Object 是隔离与可靠终止（KILL_ON_JOB_CLOSE）的核心保证，
            # 一旦 Job 绑定失败，进程即运行在真实系统（沙箱之外），
            # 只靠受限 Token 的进程可能被恶意样本对抗（提权/重启脱离 Token）。
            # 为避免样本在沙箱外被实际执行，一律终止进程并拒绝分析。
            if not job_ok:
                logger.error(
                    f'Job 绑定失败（token_ok={token_ok}），终止进程 PID='
                    f'{pi.dwProcessId}，拒绝在无 Job 环境下执行样本'
                )
                _WIN32['TerminateProcess'](proc_handle, 1)
                _WIN32['CloseHandle'](pi.hThread)
                _WIN32['CloseHandle'](proc_handle)
                return None

            # Job 绑定成功，记录隔离级别：L1（Job+Token 或 仅 Job）
            self._job_isolated = True
            if token_ok:
                logger.info(f'隔离级别 L1 (Job+Token): PID={pi.dwProcessId}')
            else:
                logger.info(f'隔离级别 L1 (仅Job，Token失败): PID={pi.dwProcessId}')

            # 保存进程句柄用于无 Job 隔离时的兜底终止
            self._proc_handle = proc_handle

            # 恢复主线程执行
            _WIN32['ResumeThread'](pi.hThread)
            logger.info(f'进程已恢复执行: PID={pi.dwProcessId}')

            return pi

        except Exception as e:
            logger.error(f'启动沙箱进程异常: {e}', exc_info=True)
            return None

    def _terminate_job(self):
        """终止沙箱进程。

        有 Job 隔离时用 TerminateJobObject 终止整个 Job（含子进程）；
        无 Job 隔离（L2 降级模式）时直接 TerminateProcess 终止目标进程，
        并尝试终止其子进程树。
        """
        if self._job_handle and self._job_isolated:
            try:
                _WIN32['TerminateJobObject'](self._job_handle, 1)
                if self._silo_active:
                    logger.info('Server Silo 已终止所有进程')
                else:
                    logger.info('Job Object 已终止所有进程')
            except Exception as e:
                logger.error(f'终止 Job Object/Silo 失败: {e}')
            # 兜底清理：恶意程序可能通过 WMI / 计划任务 / COM 将子进程
            # 重挂到系统进程（如 svchost），从而脱离 Job Object 的进程树约束
            # （经典 Job 逃逸向量）。此处按原始目标进程的后代关系再扫一遍，
            # 终止所有仍存活的逃逸进程，实现"进程树 + Job"双重兜底。
            self._kill_escaped_descendants()
        else:
            # L2 降级模式：无 Job 隔离，直接终止目标进程 + 子进程树
            if self._target_pid:
                # 用 psutil 终止整个进程树
                if HAS_PSUTIL:
                    try:
                        proc = psutil.Process(self._target_pid)
                        for child in proc.children(recursive=True):
                            try:
                                child.kill()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                        proc.kill()
                        logger.info(f'进程树已终止: PID={self._target_pid}')
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                # 兜底：直接 TerminateProcess
                if self._proc_handle:
                    try:
                        _WIN32['TerminateProcess'](self._proc_handle, 1)
                    except Exception:
                        pass

    def _detect_escaped_processes(self):
        """方案A: 通过系统进程快照差异识别逃逸进程。

        恶意进程通过 WMI/计划任务/COM 让系统服务创建的新进程，其父进程是
        系统服务（PPID 与恶意进程断裂），无法通过父子血缘追踪。但这类进程
        必然是在沙箱启动后"新出现"的进程 —— 用基线快照差异即可捕获，
        不受 Job 进程树与 PPID 关系的限制。

        归因过滤（关键）：基线差异会把分析窗口内**任何**新出现的进程都当成
        候选，其中包括大量与分析无关的系统活动（用户开浏览器、SmartScreen /
        杀软更新等）。若不加过滤就强杀，会误杀 msedge/smartscreen 这类进程
        （且 _process_tree 中的进程最终都会被 _kill_escaped_descendants 终止）。
        因此只有"可归因于沙箱"的新进程才认定为逃逸：其可执行文件位于沙箱
        工作目录下，或其命令行引用了沙箱工作目录 / 样本副本路径。
        无法读取信息的进程（AccessDenied 等）一律不予处置，避免误杀。

        增强: 检测到逃逸进程后，同时触发:
        1. 方案C: 驱动层断网（阻断 C2 回连）
        2. 方案D: 驱动层强制终止（Ring 0 kill，psutil 杀不掉的自保护进程也能杀）
        """
        # Sandboxie 后端不做逃逸判定：Sandboxie 由内核级重定向提供隔离，
        # 样本及其子进程全部在盒内（已由盒 PID 覆盖）。而"基线差异法"会把
        # 分析窗口内**任何**新出现的系统进程都当成逃逸并强杀，风险远大于
        # 收益，故该路径直接跳过（不影响 AppContainer 链路）。
        if self._sbie_pid_provider is not None:
            return
        if self._baseline_pids is None:
            return
        try:
            current_pids = set(p.info['pid'] for p in psutil.process_iter(['pid']))
        except Exception:
            return
        # 归因基准：沙箱工作目录 / 样本副本（用于判定新进程是否与沙箱相关）
        work_dir = (os.path.normcase(os.path.normpath(self._work_dir))
                    if self._work_dir else '')
        sample_path = (os.path.normcase(os.path.normpath(self._sandbox_file_path))
                       if self._sandbox_file_path else '')
        orig_path = (os.path.normcase(os.path.normpath(self._orig_sample_path))
                     if self._orig_sample_path else '')
        for pid in current_pids:
            if pid in self._baseline_pids:
                continue
            if pid == os.getpid():       # 跳过 PSLS 自身
                continue
            if pid == self._target_pid:  # 目标进程本身
                continue
            if pid in self._escaped_pids:
                continue
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                exe = proc.exe() or ''
                cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else ''
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue     # 读不到信息 → 无法归因，绝不盲目处置
            exe_n = os.path.normcase(os.path.normpath(exe)) if exe else ''
            cmd_n = os.path.normcase(cmdline)
            attributable = bool(
                (work_dir and exe_n.startswith(work_dir))
                or (work_dir and work_dir in cmd_n)
                or (sample_path and sample_path in cmd_n)
                or (orig_path and orig_path in cmd_n))
            if not attributable:
                # 与分析无关的系统活动（浏览器/杀软更新等），跳过
                continue
            self._escaped_pids.add(pid)
            with self._lock:
                self._process_tree[pid] = {
                    'pid': pid,
                    'name': name,
                    'exe': exe,
                    'cmdline': cmdline,
                    'escaped': True,   # 标记为逃逸进程，清理阶段重点处理
                    'children': [],
                }
            logger.warning(
                f'沙箱检测到疑似逃逸进程 PID={pid} ({name}) EXE={exe}')
            # 方案C联动: 若能访问内核驱动，立即对该逃逸进程断网，阻断 C2 回连
            self._block_process_net(pid)
            # 方案D联动: 多路兜底强制终止逃逸进程（psutil + OpenProcess +
            # 驱动 + taskkill，含 SeDebug 提权），确保高完整性/提权进程也被回收。
            # _terminate_proc_hard 内部可能等待数秒确认退出，放后台线程执行，
            # 避免阻塞本检测循环（否则大量逃逸进程会拖慢后续检测）。
            def _kill_escaped_bg(_pid=pid):
                try:
                    self._terminate_proc_hard(_pid)
                except Exception:
                    pass
            threading.Thread(target=_kill_escaped_bg, daemon=True,
                             name=f'sandbox-kill-{pid}').start()

    def _block_process_net(self, pid: int) -> bool:
        """方案C: 通过内核驱动对指定进程断网（WFP ALE_CONNECT 层拦截）。

        复用驱动 netmon 的 NetMon_BlockPid，将该 PID 加入断网黑名单，
        其所有出站连接（C2 回连、下载 payload）都会被内核直接 BLOCK。
        驱动不可用时静默降级。
        """
        try:
            import struct
            bridge = _get_net_blocker()
            if bridge is None:
                return False
            from driver.bridge.psls_driver_bridge import IOCTL_BLOCK_PROCESS
            return bridge._ioctl(IOCTL_BLOCK_PROCESS, struct.pack('<I', pid)) is not None
        except Exception:
            return False

    def _driver_terminate_process(self, pid: int) -> bool:
        """方案D: 通过内核驱动强制终止指定进程（Ring 0 级 TerminateProcess）。

        驱动的 TerminateProcess 通过 ObReferenceObjectByHandle 拿到目标进程的
        EPROCESS，调用 PsTerminateSystemThread 或直接设置进程终止状态，
        不受目标进程的反调试/自保护/权限限制影响。
        相比用户态 psutil.Process.kill()，驱动终止对以下场景有效:
        - 恶意进程自保护（PsSetCreateProcessProtect / NtSetInformationProcess）
        - 以更高权限运行的恶意进程
        - 已注入/挂钩的进程（用户态 kill 可能被拦截）

        驱动不可用时静默降级（返回 False，由 _kill_escaped_descendants 的
        psutil 路径兜底）。
        """
        try:
            import struct
            bridge = _get_net_blocker()
            if bridge is None:
                return False
            from driver.bridge.psls_driver_bridge import IOCTL_TERMINATE_PROC
            result = bridge._ioctl(IOCTL_TERMINATE_PROC, struct.pack('<I', pid))
            if result is not None:
                logger.info(f'驱动层已终止进程 PID={pid}')
                return True
            return False
        except Exception:
            return False

    def _unblock_process_net(self, pid: int) -> bool:
        """方案C: 解除指定进程的断网标记（沙箱结束后清理）。"""
        try:
            import struct
            bridge = _get_net_blocker()
            if bridge is None:
                return False
            from driver.bridge.psls_driver_bridge import IOCTL_ALLOW_PROCESS
            return bridge._ioctl(IOCTL_ALLOW_PROCESS, struct.pack('<I', pid)) is not None
        except Exception:
            return False

    def _enable_se_debug(self) -> bool:
        """尝试在 PSLS 自身令牌中启用 SeDebugPrivilege（若当前进程持有该特权）。

        作用：用户态 psutil.Process.kill() 内部走 OpenProcess(PROCESS_TERMINATE)，
        对**高完整性（管理员提权）**的逃逸进程会因权限不足返回 AccessDenied，
        导致驱逐失败、恶意进程在沙箱外持续运行（UAC 提权逃逸的直接后果）。
        若 PSLS 以管理员/持有 SeDebug 特权运行，启用它后即可打开并终止高完整性
        进程。特权不在当前令牌中时静默失败（不影响其它隔离层）。
        """
        if not _WIN32 or not _IS_WINDOWS:
            return False
        try:
            hToken = ctypes.wintypes.HANDLE()
            TOKEN_ADJUST_PRIVILEGES = 0x0020
            TOKEN_QUERY = 0x0008
            if not _WIN32['OpenProcessToken'](
                _WIN32['GetCurrentProcess'](), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(hToken)):
                return False
            try:
                # 动态构造 LUID_AND_ATTRIBUTES 结构，避免固定长度越界
                class _LUID(ctypes.Structure):
                    _fields_ = [('LowPart', ctypes.wintypes.DWORD),
                                ('HighPart', ctypes.c_long)]
                class _LUID_AND_ATTR(ctypes.Structure):
                    _fields_ = [('Luid', _LUID),
                                ('Attributes', ctypes.wintypes.DWORD)]
                class _TP1(ctypes.Structure):
                    _fields_ = [('PrivilegeCount', ctypes.wintypes.DWORD),
                                ('Privileges', _LUID_AND_ATTR * 1)]
                luid = _LUID()
                if not _WIN32['LookupPrivilegeValueW'](
                    None, 'SeDebugPrivilege', ctypes.byref(luid)):
                    return False
                tp = _TP1()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED
                ok = _WIN32['AdjustTokenPrivileges'](
                    hToken, False, ctypes.byref(tp), 0, None, None)
                if not ok:
                    return False
                # AdjustTokenPrivileges 成功但未实际授予也返回 True，
                # 额外用 GetLastError()==1300(ERROR_NOT_ALL_ASSIGNED) 判断。
                if ctypes.get_last_error() == 1300:
                    return False
                logger.info('沙箱已启用 SeDebugPrivilege（可终止高完整性提权进程）')
                return True
            finally:
                _WIN32['CloseHandle'](hToken)
        except Exception as e:
            logger.debug(f'启用 SeDebugPrivilege 失败: {e}')
            return False

    def is_process_alive(self, pid: int) -> bool:
        """判断进程是否存活（OpenProcess + WaitForSingleObject 探测）。"""
        try:
            import psutil as _ps
            return _ps.pid_exists(pid) and _ps.Process(pid).status() != _ps.STATUS_ZOMBIE
        except Exception:
            pass
        return False

    def _terminate_proc_hard(self, pid: int) -> bool:
        """多路兜底强制终止指定进程，直到确认其已退出。

        针对 UAC 提权逃逸：提权子进程带完整管理员令牌、高完整性，单一终止
        方式（psutil.kill / TerminateProcess / 驱动）可能因权限/自保护失败。
        依次尝试并按需重试，任一成功且进程确实退出即返回 True。

        顺序: psutil.kill → OpenProcess+TerminateProcess → 驱动终止 →
              taskkill /F → 短等待确认。每种失败后若进程仍存活继续下一种。
        """
        if pid <= 0 or pid == os.getpid():
            return True
        started = time.time()
        max_wait = 3.0
        while time.time() - started < max_wait:
            if not self.is_process_alive(pid):
                return True  # 已退出

            # 1) psutil.kill（若已启用 SeDebug，可终止高完整性进程）
            try:
                import psutil as _ps
                _ps.Process(pid).kill()
                time.sleep(0.15)
                if not self.is_process_alive(pid):
                    return True
            except Exception:
                pass

            # 2) OpenProcess(PROCESS_TERMINATE) + TerminateProcess（用户态强制）
            try:
                h = _WIN32['OpenProcess'](PROCESS_TERMINATE, False, pid)
                if h:
                    try:
                        _WIN32['TerminateProcess'](h, 1)
                    finally:
                        _WIN32['CloseHandle'](h)
                    time.sleep(0.15)
                    if not self.is_process_alive(pid):
                        return True
            except Exception:
                pass

            # 3) 内核驱动强制终止（Ring 0，能杀自保护/更高权限进程）
            try:
                if self._driver_terminate_process(pid):
                    time.sleep(0.15)
                    if not self.is_process_alive(pid):
                        return True
            except Exception:
                pass

            # 4) taskkill /F /T（兜底）
            try:
                import subprocess as _sp
                _sp.run(['taskkill', '/F', '/T', '/PID', str(pid)],
                        timeout=3, capture_output=True,
                        **_hidden_spawn_kwargs())
                time.sleep(0.15)
                if not self.is_process_alive(pid):
                    return True
            except Exception:
                pass

            time.sleep(0.15)
        # 循环结束仍未确认退出
        return not self.is_process_alive(pid)

    def _unblock_all_net(self):
        """方案C: 清理沙箱期间所有被断网的进程 PID。"""
        for pid in list(self._escaped_pids):
            self._unblock_process_net(pid)
        if self._target_pid:
            self._unblock_process_net(self._target_pid)

    def _kill_escaped_descendants(self):
        """按进程树终止可能逃逸出 Job Object 的后代进程

        恶意程序可将子进程通过 WMI / 计划任务 / COM+ 重挂到系统进程，
        从而脱离数据 Job Object 的进程树约束（经典逃逸向量）。
        这里从沙箱启动的目标进程出发，递归收集其全部直接/间接后代，
        终止所有仍存活者，并与 _process_tree 中记录的后代做并集兜底。
        """
        if not HAS_PSUTIL:
            return
        if not self._target_pid:
            return

        collected = set()
        # 方案A: 基线差异检测到的逃逸进程（PPID 已断裂，血缘追踪不到）
        for pid in self._escaped_pids:
            if pid != self._target_pid and pid != os.getpid():
                collected.add(pid)
        # 从监控阶段记录的进程树补充（含已重挂/退出的后代）
        try:
            with self._lock:
                for pid in self._process_tree:
                    if pid != self._target_pid:
                        collected.add(pid)
        except Exception:
            pass

        # 从当前系统进程关系重新收集目标的后代
        try:
            try:
                root = psutil.Process(self._target_pid)
                for child in root.children(recursive=True):
                    collected.add(child.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        except Exception:
            pass

        killed = 0
        driver_killed = 0
        for pid in collected:
            try:
                proc = psutil.Process(pid)
                if proc.is_running() and pid != os.getpid():
                    proc.kill()
                    killed += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # psutil kill 可能因权限不足/自保护失败 → 多路兜底强制终止
                #（含 OpenProcess+TerminateProcess / 驱动 / taskkill / SeDebug）
                if pid != os.getpid() and pid != self._target_pid:
                    if self._terminate_proc_hard(pid):
                        driver_killed += 1
            except Exception:
                if pid != os.getpid() and pid != self._target_pid:
                    if self._terminate_proc_hard(pid):
                        driver_killed += 1
        if killed or driver_killed:
            logger.warning(
                f'沙箱清理：psutil 终止 {killed} 个 + 驱动终止 {driver_killed} 个'
                f'可能逃逸出 Job 的后代进程')

    def _restrict_process_token(self, pid: int, proc_handle: int) -> bool:
        """禁用进程令牌中的关键特权，降低恶意程序操作能力。

        在挂起状态下对进程令牌执行 AdjustTokenPrivileges，
        禁用 SeDebugPrivilege / SeSystemtimePrivilege / SeShutdownPrivilege
        等高危特权。进程已脱离父级 Job 并绑定到沙箱 Job 后执行。

        Returns:
            True = 至少成功禁用了部分特权; False = 令牌限制完全失败
        """
        if not _WIN32:
            return False

        SE_PRIVILEGE_DISABLED = 0x00000000

        # 需要禁用的特权（高危）
        DISABLE_PRIVILEGES = [
            'SeDebugPrivilege',          # 调试其他进程
            'SeSystemtimePrivilege',     # 修改系统时间
            'SeShutdownPrivilege',       # 关机
            'SeRemoteShutdownPrivilege', # 远程关机
            'SeTakeOwnershipPrivilege',  # 取得文件所有权
            'SeRestorePrivilege',        # 恢复文件（可绕过ACL）
            'SeBackupPrivilege',         # 备份文件（可绕过ACL）
            'SeLoadDriverPrivilege',     # 加载驱动
            'SeTcbPrivilege',            # TCB 权限
            'SeImpersonatePrivilege',    # 模拟其他用户
            'SeDelegateSessionUserImpersonatePrivilege',
        ]

        class _LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ('Luid', ctypes.wintypes.LARGE_INTEGER),
                ('Attributes', ctypes.wintypes.DWORD),
            ]

        try:
            hToken = ctypes.wintypes.HANDLE()
            if not _WIN32['OpenProcessToken'](
                proc_handle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(hToken)
            ):
                logger.debug(f'OpenProcessToken 失败: {ctypes.get_last_error()}')
                return False

            # 构建要禁用的特权列表
            # 注意: _TOKEN_PRIVILEGES 的 Privileges 字段是固定长度 * 1,
            # 直接写 tp.Privileges[i] (i>0) 会触发 ctypes "invalid index" 越界异常,
            # 使令牌限制整体静默失败, 沙箱被降级为仅 Job 隔离。
            # 因此按实际特权数 n 动态定义一个尺寸匹配的结构体实例。
            n = len(DISABLE_PRIVILEGES)

            class _TOKEN_PRIVILEGES_N(ctypes.Structure):
                _fields_ = [
                    ('PrivilegeCount', ctypes.wintypes.DWORD),
                    ('Privileges', _LUID_AND_ATTRIBUTES * n),
                ]

            tp = _TOKEN_PRIVILEGES_N()
            tp.PrivilegeCount = n
            disabled_count = 0
            for i, name in enumerate(DISABLE_PRIVILEGES):
                luid = ctypes.wintypes.LARGE_INTEGER()
                if _WIN32['LookupPrivilegeValueW'](None, name, ctypes.byref(luid)):
                    tp.Privileges[i].Luid = luid
                    tp.Privileges[i].Attributes = SE_PRIVILEGE_DISABLED
                    disabled_count += 1

            if disabled_count == 0:
                logger.warning('未能查询到任何特权 LUID，令牌限制无效')
                _WIN32['CloseHandle'](hToken)
                return False

            ok = _WIN32['AdjustTokenPrivileges'](hToken, False, ctypes.byref(tp), 0, None, None)
            _WIN32['CloseHandle'](hToken)

            if not ok:
                logger.warning(f'AdjustTokenPrivileges 失败: {ctypes.get_last_error()}')
                return False

            logger.info(f'进程 {pid} 已禁用 {disabled_count}/{n} 项高危特权')
            return True
        except Exception as e:
            logger.warning(f'禁用进程特权异常: {e}')
            return False

    # ========================================================================
    # 行为监控层
    # ========================================================================

    def _iter_live_procs(self, pids) -> List['psutil.Process']:
        """返回指定 PID 集合中仍存活的 psutil.Process 列表。

        行为监控需要对"整个进程树"（目标 + 全部子进程）执行运行时行为检查，
        否则恶意父进程只投递子进程、真正动作由子进程完成时会被漏判。
        """
        live = []
        for pid in pids:
            try:
                live.append(psutil.Process(pid))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return live

    def _monitor_behavior(self):
        """使用 psutil 监控进程树行为

        增强检测项：
        - 批量文件操作检测（勒索病毒特征，滑动窗口）
        - 可疑子进程链检测（cmd/powershell/regsvr32 等）
        - 可疑命令行参数检测（-enc / downloadstring / vssadmin 等）
        - 勒索扩展名检测（.encrypted / .locked 等）
        - 加强内存注入检测（RWX + 内存扫描）
        """
        if not HAS_PSUTIL:
            return

        target_pid = self._target_pid
        if not target_pid:
            return

        # 记录已知进程
        known_pids = {target_pid}
        # 批量文件操作滑动窗口记录：[(timestamp, path), ...]
        file_op_window: List[tuple] = []
        last_check = time.time()
        last_file_check = time.time()
        last_net_addrs = set()  # 已记录的网络地址

        # 勒索"加密-删除替换"足迹追踪
        # footprint_seen: 样本曾打开/接触过的独立文件路径集合（小写去重）
        # footprint_deleted: 从磁盘消失（被删除/替换）的路径集合
        footprint_seen = set()
        footprint_deleted = set()
        last_footprint_check = time.time()

        # 视觉恶搞特征检测状态（弹窗洪流 / 进程spawn风暴）
        last_prank_check = time.time()
        prank_prev_windows: Dict[int, int] = {}
        prank_spawn_base = len(known_pids)
        prank_window_warn_ts = 0.0
        prank_spawn_warn_ts = 0.0

        # 目标进程信息
        try:
            target_proc = psutil.Process(target_pid)
            self._process_tree[target_pid] = {
                'pid': target_pid,
                'name': target_proc.name(),
                'exe': target_proc.exe(),
                'create_time': target_proc.create_time(),
                'children': [],
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        # ---- 方案A: 记录系统进程基线（用于差异追踪逃逸进程）----
        # 沙箱进程刚启动，此刻的系统进程集合作为基线。之后凡是在此基础上
        # "新出现"的进程，无论其父进程是谁（WMI/计划任务/COM 重挂会打断
        # PPID 链），都视为潜在逃逸进程，统一收集并在清理阶段终止。
        try:
            self._baseline_pids = set(
                p.info['pid'] for p in psutil.process_iter(['pid']))
        except Exception:
            self._baseline_pids = set()
        self._baseline_pids.add(target_pid)  # 目标进程自身不视为"新增"
        self._escaped_pids = set()
        self._last_escape_check = time.time()

        while not self._stop_event.is_set():
            try:
                # 检查进程是否存活
                if not target_proc.is_running():
                    break

                # ---- 方案A: 周期差异检测，收集逃逸进程 ----
                _now = time.time()
                if _now - self._last_escape_check > 1.0:
                    self._last_escape_check = _now
                    self._detect_escaped_processes()

                # 获取子进程
                try:
                    children = target_proc.children(recursive=True)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    children = []

                for child in children:
                    if child.pid not in known_pids:
                        known_pids.add(child.pid)
                        try:
                            child_name = child.name()
                            child_exe = child.exe() or ''
                            child_cmdline = ' '.join(child.cmdline()) if child.cmdline() else ''
                            child_info = {
                                'pid': child.pid,
                                'name': child_name,
                                'exe': child_exe,
                                'cmdline': child_cmdline,
                                'create_time': child.create_time(),
                                'children': [],
                                'parent_pid': target_pid,
                            }
                            with self._lock:
                                self._process_tree[child.pid] = child_info
                                parent_pid = child.ppid() if hasattr(child, 'ppid') else target_pid
                                if parent_pid in self._process_tree:
                                    self._process_tree[parent_pid].setdefault('children', []).append(child.pid)

                            # ---- 可疑子进程检测 ----
                            child_name_lower = child_name.lower()
                            if child_name_lower in SUSPICIOUS_CHILD_PROCESSES:
                                # 从可疑位置启动 = 更高风险
                                is_suspicious_path = any(
                                    kw in child_exe.lower() for kw in
                                    ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\']
                                )
                                score = 6 if is_suspicious_path else 4
                                severity = 'critical' if is_suspicious_path else 'warn'
                                self._add_behavior(
                                    'process', severity,
                                    f'启动可疑子进程: {child_name}',
                                    f'PID={child.pid}, EXE={child_exe}, CMD={child_cmdline[:100]}',
                                    score=score
                                )
                            else:
                                self._add_behavior(
                                    'process', 'warn',
                                    f'创建子进程: {child_name}',
                                    f'PID={child.pid}, CMD={child_cmdline[:100]}',
                                    score=2
                                )

                            # ---- 可疑命令行检测 ----
                            self._check_suspicious_cmdline(child_cmdline, child_name)

                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                # ---- 检查文件操作（批量检测 + 可疑目录 + 勒索扩展名）----
                # 遍历整个进程树（目标 + 全部子进程），避免仅采父进程文件句柄漏掉
                # "父进程投递、子进程实施"的双进程逃逸型勒索/释放行为。
                now = time.time()
                current_paths = set()  # 本轮样本仍持有句柄的文件
                for mproc in self._iter_live_procs(known_pids):
                    try:
                        open_files = mproc.open_files()
                        mname = mproc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    except Exception:
                        mname = '?'
                    for f in open_files[:80]:
                        fpath = f.path.lower()
                        fpath_orig = f.path
                        current_paths.add(fpath)

                        # 写入可疑目录
                        for suspicious_dir in SUSPICIOUS_WRITE_DIRS:
                            sdir = suspicious_dir.lower()
                            if fpath.startswith(sdir):
                                if not any(b.detail and fpath in b.detail for b in self._behaviors if b.category == 'file'):
                                    self._add_behavior(
                                        'file', 'critical',
                                        f'写入敏感目录: {os.path.basename(f.path)}',
                                        f'路径={fpath_orig}, 进程={mname}',
                                        score=8
                                    )
                                break

                        # 勒索扩展名检测
                        _, ext = os.path.splitext(fpath)
                        if ext in RANSOM_EXTENSIONS:
                            self._add_behavior(
                                'file', 'critical',
                                f'创建勒索扩展名文件: {ext}',
                                f'路径={fpath_orig}, 进程={mname}',
                                score=10
                            )

                        # 银狐(SilverFox)文件足迹检测（PeAV antisilverfox.sa 融合）
                        for pattern, sc, desc in SILVERFOX_FILE_PATTERNS:
                            if pattern in fpath and not any(desc in b.description for b in self._behaviors if b.category == 'file'):
                                self._add_behavior(
                                    'file', 'critical' if sc >= 7 else 'warn',
                                    f'银狐文件足迹: {desc}',
                                    f'路径={fpath_orig}',
                                    score=sc
                                )
                                break  # 每个文件只匹配一条银狐规则

                        # 记录文件操作到滑动窗口（排除系统目录）
                        if not fpath.startswith(r'c:\windows\\') and not fpath.startswith(r'c:\program'):
                            file_op_window.append((now, fpath))

                # ---- 勒索"加密-删除替换"足迹检测 ----
                # 把本轮仍持有的句柄并入足迹集合（曾接触过的所有独立文件）
                footprint_seen.update(current_paths)
                # 每 ~1.5 秒复查一次：已接触的路径如果当前已无句柄、且磁盘文件已不存在，
                # 说明被样本删除或替换（勒索加密的核心足迹，现有持有句柄检测看不到）。
                if now - last_footprint_check > 1.5:
                    last_footprint_check = now
                    # 只复查那些"曾出现、本轮已不在句柄集"的路径
                    candidates = footprint_seen - current_paths - footprint_deleted
                    if len(candidates) > 500:  # 上限保护，避免对海量路径逐个 stat
                        candidates = set(list(candidates)[-500:])
                    for p in candidates:
                        try:
                            if not os.path.exists(p):
                                footprint_deleted.add(p)
                        except Exception:
                            pass
                    if (len(footprint_deleted) >= RANSOM_REPLACE_DELETED
                            and len(footprint_seen) >= RANSOM_REPLACE_MIN_TOUCHED):
                        if not any('批量文件替换' in b.description for b in self._behaviors if b.category == 'file'):
                            self._add_behavior(
                                'file', 'critical',
                                f'批量文件替换（勒索加密足迹）: '
                                f'删除/替换 {len(footprint_deleted)} 个文件，'
                                f'曾接触 {len(footprint_seen)} 个独立文件',
                                f'样本在短时间内处理大量文件并删除/替换原文件，'
                                f'典型的勒索软件加密行为',
                                score=20
                            )

                # ---- 批量文件操作检测（勒索病毒特征）----
                # 清理过期记录
                cutoff = now - RANSOM_FILE_OP_WINDOW
                file_op_window = [(t, p) for t, p in file_op_window if t > cutoff]
                op_count = len(file_op_window)

                if op_count >= RANSOM_FILE_OP_CRITICAL:
                    # 高危：5秒内超过30个文件操作
                    if not any('批量文件操作' in b.description for b in self._behaviors if b.category == 'file'):
                        self._add_behavior(
                            'file', 'critical',
                            f'批量文件操作（勒索特征）: {op_count}次/{RANSOM_FILE_OP_WINDOW}s',
                            f'窗口内操作 {op_count} 次，疑似勒索病毒加密',
                            score=15
                        )
                elif op_count >= RANSOM_FILE_OP_THRESHOLD:
                    if not any('批量文件操作' in b.description for b in self._behaviors if b.category == 'file'):
                        self._add_behavior(
                            'file', 'warn',
                            f'批量文件操作: {op_count}次/{RANSOM_FILE_OP_WINDOW}s',
                            f'窗口内操作 {op_count} 次',
                            score=8
                        )

                # ---- 检查网络连接 ----
                if self.config.enable_network_monitor:
                    # 遍历整个进程树，子进程的 C2 回连/下载同样需要被捕获
                    for mproc in self._iter_live_procs(known_pids):
                        try:
                            connections = mproc.connections()
                            mname = mproc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                        except Exception:
                            mname = '?'
                        for conn in connections[:30]:
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                raddr = f'{conn.raddr.ip}:{conn.raddr.port}'
                                if raddr not in last_net_addrs:
                                    last_net_addrs.add(raddr)
                                    # 可疑端口检测（PeAV 融合：扩展 C2 端口集）
                                    port = conn.raddr.port
                                    ip_str = conn.raddr.ip
                                    is_suspicious_port = port in SUSPICIOUS_C2_PORTS
                                    is_dynamic_dns = any(d in ip_str for d in ('.ddns.', '.no-ip.', '.duckdns.'))

                                    score = 8 if is_suspicious_port else 5
                                    severity = 'critical' if is_suspicious_port else 'warn'

                                    # 银狐 C2：动态 DNS 域名
                                    if is_dynamic_dns:
                                        score = 10
                                        severity = 'critical'

                                    self._add_behavior(
                                        'network', severity,
                                        f'建立网络连接: {raddr}',
                                        f'远程地址={raddr}, 状态={conn.status}, 端口={port}, '
                                        f'进程={mname}',
                                        score=score
                                    )
                                    # 银狐 C2 特征：连接廉价 TLD 域名
                                    ip_lower = ip_str.lower()
                                    for cheap_tld in SUSPICIOUS_CHEAP_TLDS:
                                        if cheap_tld in ip_lower:
                                            self._add_behavior(
                                                'network', 'critical',
                                                f'连接可疑廉价域名: {ip_str}',
                                                f'域名={ip_str}, TLD={cheap_tld}（银狐 C2 特征）',
                                                score=8
                                            )
                                            break

                # ---- 检查内存中的可疑模块（注入检测）----
                if now - last_check > 2.0:  # 每2秒检查一次（从3s缩短到2s）
                    last_check = now
                    # 对整个进程树做内存注入检测 —— 子进程往往是 shellcode 注入的目标
                    for mproc in self._iter_live_procs(known_pids):
                        self._check_memory_injection(mproc)

                # ---- 视觉恶搞特征检测（每 1 秒一次）----
                # 弹窗洪流：进程树内任一 PID 顶层窗口数突增（1 秒 >= 3）
                # 进程 spawn 风暴：沙箱期间新衍生 >10 进程
                if now - last_prank_check >= 1.0:
                    last_prank_check = now
                    try:
                        for pid in list(known_pids):
                            try:
                                proc = psutil.Process(pid)
                                wcnt = len(proc.windows())
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
                            prev = prank_prev_windows.get(pid, 0)
                            inc = wcnt - prev
                            prank_prev_windows[pid] = wcnt
                            if inc >= 3 and now - prank_window_warn_ts > 5:
                                prank_window_warn_ts = now
                                self._add_behavior(
                                    'process', 'warn',
                                    '恶搞特征：高频窗口创建',
                                    f'PID={pid} 在 1 秒内新增 {inc} 个窗口',
                                    score=10,
                                )
                    except Exception:
                        pass
                    cur_spawn = len(known_pids) - prank_spawn_base
                    if cur_spawn > 10 and now - prank_spawn_warn_ts > 5:
                        prank_spawn_warn_ts = now
                        self._add_behavior(
                            'process', 'warn',
                            '恶搞特征：进程 spawn 风暴',
                            f'沙箱期间衍生 {cur_spawn} 个子进程',
                            score=10,
                        )

                time.sleep(self.config.monitor_interval)

            except psutil.NoSuchProcess:
                break
            except Exception as e:
                logger.debug(f'行为监控异常: {e}')
                time.sleep(1)

    def _check_suspicious_cmdline(self, cmdline: str, process_name: str = ''):
        """检测可疑命令行参数

        检测 PowerShell 编码执行、下载执行、隐藏窗口、
        vssadmin 删除卷影副本等高危命令行特征。
        """
        if not cmdline:
            return

        cmdline_lower = cmdline.lower()
        matched_patterns = set()  # 避免同一模式重复记录

        for pattern, score, desc in SUSPICIOUS_CMDLINE_PATTERNS:
            if pattern in cmdline_lower and pattern not in matched_patterns:
                matched_patterns.add(pattern)
                severity = 'critical' if score >= 7 else 'warn'
                self._add_behavior(
                    'process', severity,
                    f'可疑命令行: {desc}',
                    f'进程={process_name}, 模式="{pattern}", CMD={cmdline[:120]}',
                    score=score
                )

    def _check_memory_injection(self, proc: 'psutil.Process'):
        """检查进程内存中的注入特征

        增强：检测 RWX 私有页、可疑模块加载、内存占用异常
        """
        try:
            maps = proc.memory_maps()
            rwx_count = 0
            anonymous_rwx = 0
            suspicious_modules = []

            for m in maps[:200]:
                perms = getattr(m, 'perms', '')
                path = getattr(m, 'path', '') or ''
                addr = getattr(m, 'addr', 0)
                size = getattr(m, 'rss', 0)

                # RWX 内存检测
                if 'x' in perms and 'w' in perms:
                    rwx_count += 1
                    # 匿名 RWX 页 = shellcode 注入特征
                    if not path or path == '' or path == '[':
                        anonymous_rwx += 1
                    # 从临时目录加载的 RWX 模块
                    elif any(kw in path.lower() for kw in
                             ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\']):
                        suspicious_modules.append(path)

            # 匿名 RWX 页 ≥2 = shellcode 注入（从 3 降到 2）
            if anonymous_rwx >= 2:
                self._add_behavior(
                    'process', 'critical',
                    f'检测到 {anonymous_rwx} 个匿名 RWX 内存页',
                    '可能存在 shellcode 注入',
                    score=12
                )
            elif rwx_count >= 5:
                self._add_behavior(
                    'process', 'warn',
                    f'检测到 {rwx_count} 个 RWX 内存页',
                    f'RWX 页较多，可能存在代码注入',
                    score=5
                )

            # 可疑模块加载（从临时目录加载的 DLL）
            for mod_path in suspicious_modules[:3]:
                self._add_behavior(
                    'process', 'critical',
                    f'从临时目录加载模块: {os.path.basename(mod_path)}',
                    f'路径={mod_path}',
                    score=8
                )

            # 银狐(SilverFox)DLL 注入检测（PeAV antisilverfox.sa 融合）
            all_mod_paths = [getattr(m, 'path', '') or '' for m in maps[:200]]
            sf_dll_matched = set()
            for mod_path in all_mod_paths:
                mod_lower = mod_path.lower()
                for pattern, sc, desc in SILVERFOX_DLL_PATTERNS:
                    if pattern in mod_lower and desc not in sf_dll_matched:
                        sf_dll_matched.add(desc)
                        self._add_behavior(
                            'process', 'critical' if sc >= 7 else 'warn',
                            f'银狐DLL足迹: {desc}',
                            f'模块={os.path.basename(mod_path)}, 路径={mod_path}',
                            score=sc
                        )
                        break  # 每个模块只匹配一条银狐规则

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception:
            pass

    # ========================================================================
    # frida API hook 层
    # ========================================================================

    def _setup_frida_hooks(self, pid: int):
        """附加 frida 到目标进程，hook 关键 API"""
        if not HAS_FRIDA or not frida:
            return

        try:
            session = frida.attach(pid)
            self._frida_session = session

            # 构建 JS hook 脚本
            script_src = self._build_frida_script()

            script = session.create_script(script_src)

            # 消息回调
            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message.get('payload', {})
                    self._handle_frida_message(payload)
                elif message['type'] == 'error':
                    logger.debug(f'frida 错误: {message.get("description", "")}')

            script.on('message', on_message)
            script.load()

            logger.info(f'frida 已附加到 PID={pid}')

            # 等待停止信号
            while not self._stop_event.is_set():
                time.sleep(0.5)

            # 卸载脚本
            try:
                script.unload()
            except Exception:
                pass

        except Exception as e:
            logger.debug(f'frida 附加失败（降级到 psutil 监控）: {e}')

    def _build_frida_script(self) -> str:
        """生成 frida JS hook 脚本"""
        hooks_js = []
        for api_name, info in SUSPICIOUS_API_HOOKS.items():
            module = 'kernel32.dll'
            if api_name.startswith('Reg'):
                module = 'advapi32.dll'
            elif api_name.startswith('Internet') or api_name.startswith('WinHttp'):
                module = 'wininet.dll'
            elif api_name in ('connect', 'WSAStartup'):
                module = 'ws2_32.dll'
            elif api_name.startswith('Nt') or api_name.startswith('Zw'):
                module = 'ntdll.dll'

            hooks_js.append(f"""
            try {{
                var addr = Module.findExportByName('{module}', '{api_name}');
                if (addr) {{
                    Interceptor.attach(addr, {{
                        onEnter: function(args) {{
                            send({{
                                api: '{api_name}',
                                category: '{info["category"]}',
                                score: {info["score"]},
                                desc: '{info["desc"]}'
                            }});
                        }}
                    }});
                }}
            }} catch(e) {{ }}
            """)

        return """
        'use strict';
        """ + '\n'.join(hooks_js) + """
        // 批量发送，避免消息洪水
        var _pendingMessages = [];
        var _flushTimer = null;
        function _flush() {
            _flushTimer = null;
        }
        """

    def _handle_frida_message(self, payload: dict):
        """处理 frida hook 消息"""
        if not isinstance(payload, dict):
            return

        api = payload.get('api', '')
        category = payload.get('category', '')
        score = payload.get('score', 0)
        desc = payload.get('desc', '')

        # 限制同类 API 的记录频率（避免洪水）
        api_count = sum(1 for b in self._behaviors if b.detail and api in b.detail)
        if api_count > 10:
            return  # 同一 API 超过 10 次调用，不再记录

        self._add_behavior(
            category, 'warn' if score < 5 else 'critical',
            f'API调用: {api} - {desc}',
            f'API={api}',
            score=score
        )

    # ========================================================================
    # 行为评分层
    # ========================================================================

    def _add_behavior(self, category: str, severity: str,
                      description: str, detail: str = '', score: int = 0):
        """线程安全地添加行为记录"""
        with self._lock:
            record = BehaviorRecord(category, severity, description, detail, score=score)
            self._behaviors.append(record)

    def _static_precheck(self, file_path: str):
        """静态预检：PE 特征快速筛查 + 可疑字符串检测

        在沙箱执行前快速扫描文件静态特征：
        - PE 导入表中的可疑 API
        - 文件中的可疑字符串（PowerShell/CMD/下载命令等）
        - 可疑节区名（加壳特征）
        - 可疑入口点

        静态预检分数加入 'static' 类别，最高 25 分。
        如果静态预检已经高度可疑，即使行为不多也能判定为 suspicious。
        """
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:  # 大文件跳过静态预检
                return

            # 读取文件头（PE 分析）
            with open(file_path, 'rb') as f:
                header = f.read(4096)

            # 检查是否为 PE 文件
            is_pe = len(header) >= 2 and header[:2] == b'MZ'
            if is_pe:
                self._static_precheck_pe(file_path, header)

            # 可疑字符串检测（读取部分内容）
            self._static_precheck_strings(file_path, file_size)

        except Exception as e:
            logger.debug(f'静态预检异常: {e}')

    def _static_precheck_pe(self, file_path: str, header: bytes):
        """PE 文件静态分析"""
        try:
            # 读取更多内容用于导入表分析
            with open(file_path, 'rb') as f:
                pe_data = f.read(min(os.path.getsize(file_path), 256 * 1024))

            # 解析 PE 头
            if len(pe_data) < 0x40:
                return

            e_lfanew = int.from_bytes(pe_data[0x3c:0x40], 'little')
            if e_lfanew + 24 > len(pe_data):
                return

            # PE 签名
            if pe_data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
                return

            # COFF Header
            coff_offset = e_lfanew + 4
            number_of_sections = int.from_bytes(pe_data[coff_offset+2:coff_offset+4], 'little')
            size_of_optional_header = int.from_bytes(pe_data[coff_offset+16:coff_offset+18], 'little')

            # Optional Header
            opt_offset = coff_offset + 20
            if opt_offset + size_of_optional_header > len(pe_data):
                return

            # 检查节区名
            sections_offset = opt_offset + size_of_optional_header
            for i in range(min(number_of_sections, 20)):
                sec_offset = sections_offset + i * 40
                if sec_offset + 40 > len(pe_data):
                    break
                sec_name = pe_data[sec_offset:sec_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore').lower()
                if sec_name in STATIC_SUSPICIOUS_SECTIONS:
                    self._add_behavior(
                        'static', 'critical',
                        f'检测到加壳节区: {sec_name}',
                        f'节区名={sec_name}，疑似加壳/混淆',
                        score=8
                    )

            # 可疑导入 API 检测（扫描整个文件内容）
            pe_text = pe_data.decode('ascii', errors='ignore')
            found_imports = set()
            for api_name, score in STATIC_SUSPICIOUS_IMPORTS.items():
                if api_name in pe_text and api_name not in found_imports:
                    found_imports.add(api_name)
                    severity = 'critical' if score >= 4 else 'warn'
                    self._add_behavior(
                        'static', severity,
                        f'可疑导入 API: {api_name}',
                        f'API={api_name}',
                        score=score
                    )

            # 多个注入相关 API 同时出现 = 高风险
            injection_apis = {'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
                              'NtCreateThreadEx', 'QueueUserAPC',
                              'NtUnmapViewOfSection', 'NtMapViewOfSection',
                              'SetThreadContext', 'NtWriteVirtualMemory',
                              'RtlCreateUserThread'}
            injection_found = found_imports & injection_apis
            if len(injection_found) >= 2:
                self._add_behavior(
                    'static', 'critical',
                    f'检测到注入 API 组合: {", ".join(injection_found)}',
                    f'多个进程注入 API 同时出现',
                    score=10
                )

        except Exception as e:
            logger.debug(f'PE 静态分析异常: {e}')

    def _static_precheck_strings(self, file_path: str, file_size: int):
        """可疑字符串检测"""
        try:
            # 读取文件内容（最多 1MB）
            read_size = min(file_size, 1024 * 1024)
            with open(file_path, 'rb') as f:
                data = f.read(read_size)

            # ASCII 和 UTF-16LE 双重检测
            text_ascii = data.decode('ascii', errors='ignore').lower()
            text_utf16 = data.decode('utf-16-le', errors='ignore').lower()

            found_strings = set()
            for pattern, score, desc in STATIC_SUSPICIOUS_STRINGS:
                if pattern in text_ascii or pattern in text_utf16:
                    if pattern not in found_strings:
                        found_strings.add(pattern)
                        severity = 'critical' if score >= 5 else 'warn'
                        self._add_behavior(
                            'static', severity,
                            f'可疑字符串: {desc}',
                            f'模式="{pattern}"',
                            score=score
                        )
        except Exception as e:
            logger.debug(f'字符串检测异常: {e}')

    def _score_behaviors(self, trust_offset: int = 0) -> tuple:
        """计算行为总分和判定结果

        评分逻辑：
        1. 按类别累加行为分数，每类封顶
        2. 组合行为加分（多维度同时命中 = 更高风险）
        3. 关键行为一票否决（如检测到勒索扩展名 = 直接 malware）

        Args:
            trust_offset: 上下文信任先验偏移（0~20）。仅作用于"分数型"
                阈值判定（effective_total = total - offset），一票否决的
                force_malware 不受影响 —— 硬证据（勒索/卷影/银狐）哪怕是
                修改器背后也绝不因信任而放行。

        Returns:
            (total, verdict, force_malware)
        """
        category_scores = {cat: 0 for cat in CATEGORY_MAX_SCORE}

        for behavior in self._behaviors:
            cat = behavior.category
            if cat in category_scores:
                category_scores[cat] += behavior.score

        # 每个类别封顶
        total = 0
        for cat, max_score in CATEGORY_MAX_SCORE.items():
            capped = min(category_scores[cat], max_score)
            total += capped

        # ---- 组合行为加分 ----
        # 多维度同时命中 = 更高风险（1+1>2）
        active_categories = sum(1 for cat, score in category_scores.items() if score > 0)
        if active_categories >= 4:
            # 4+ 个类别同时有行为 = 高度可疑
            total += 10
        elif active_categories >= 3:
            # 3 个类别同时有行为 = 中度可疑
            total += 5

        # 网络行为 + 进程注入行为 = C2 回连特征
        if category_scores.get('network', 0) > 0 and category_scores.get('process', 0) >= 10:
            total += 8

        # 文件批量操作 + 网络行为 = 勒索病毒上传加密数据
        if category_scores.get('file', 0) >= 15 and category_scores.get('network', 0) > 0:
            total += 10

        # 静态特征 + 任何动态行为 = 确认恶意
        if category_scores.get('static', 0) >= 15 and active_categories >= 2:
            total += 8

        # ---- 关键行为一票否决（直接判定 malware）----
        force_malware = False
        for b in self._behaviors:
            # 检测到勒索扩展名 = 直接判定 malware
            if '勒索扩展名' in b.description:
                force_malware = True
                break
            # 检测到批量文件操作（勒索特征）≥30 次 = 直接判定 malware
            if '批量文件操作（勒索特征）' in b.description:
                force_malware = True
                break
            # 检测到删除卷影副本 = 直接判定 malware
            if '删除卷影副本' in b.description:
                force_malware = True
                break
            # 检测到"加密-删除替换"足迹 = 直接判定 malware
            if '批量文件替换' in b.description:
                force_malware = True
                break

        # ---- 银狐(SilverFox)综合判定（PeAV 融合）----
        # 银狐特征行为计数：≥3 条银狐特征 = 一票否决
        silverfox_hits = sum(1 for b in self._behaviors if '银狐' in b.description)
        if silverfox_hits >= 3:
            force_malware = True
            logger.info(f'银狐特征命中 {silverfox_hits} 条，触发一票否决')

        # 判定
        # 上下文信任先验：仅对"分数型"判定生效（对 total 做偏移后再比较阈值），
        # force_malware（一票否决硬证据）永远不受信任偏移影响。
        effective_total = max(0, total - trust_offset)
        if force_malware or effective_total >= VERDICT_MALWARE_THRESHOLD:
            verdict = 'malware'
        elif effective_total >= VERDICT_SUSPICIOUS_THRESHOLD:
            verdict = 'suspicious'
        else:
            verdict = 'clean'

        if trust_offset:
            logger.info(
                f'沙箱评分: total={total} (应用信任偏移-{trust_offset} → '
                f'effective={effective_total}), categories={category_scores}, '
                f'active_cats={active_categories}, force_malware={force_malware}, '
                f'verdict={verdict}')
        else:
            logger.info(f'沙箱评分: total={total}, categories={category_scores}, '
                        f'active_cats={active_categories}, force_malware={force_malware}, '
                        f'verdict={verdict}')
        return total, verdict, force_malware

    # ========================================================================
    # 辅助方法
    # ========================================================================

    def _is_process_alive(self, pid: int) -> bool:
        """检查进程是否存活"""
        if not HAS_PSUTIL:
            return False
        try:
            return psutil.Process(pid).is_running()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def _build_process_tree_dict(self) -> dict:
        """构建进程树字典（用于前端展示）"""
        with self._lock:
            return dict(self._process_tree)

    def _cleanup(self):
        """清理资源"""
        # 方案C: 解除沙箱期间对所有进程的断网标记，避免影响后续正常使用
        self._unblock_all_net()

        # 终止 Job Object
        self._terminate_job()

        # 释放 AppContainer（属性列表 + 本实例创建的容器配置文件）
        self._release_appcontainer()

        # 关闭句柄
        if self._job_handle:
            try:
                _WIN32['CloseHandle'](self._job_handle)
            except Exception:
                pass
            self._job_handle = None
        self._silo_active = False  # Silo 随 Job 句柄一并失效

        # 关闭进程句柄（无 Job 隔离时保存的，用于兜底终止）
        if self._proc_handle:
            try:
                _WIN32['CloseHandle'](self._proc_handle)
            except Exception:
                pass
            self._proc_handle = None

        # 卸载 frida
        if self._frida_session:
            try:
                self._frida_session.detach()
            except Exception:
                pass
            self._frida_session = None

        # 清理临时目录
        if self._work_dir and self.config.work_dir is None:
            try:
                shutil.rmtree(self._work_dir, ignore_errors=True)
            except Exception:
                pass

        self._target_pid = None
        self._job_isolated = False
        # 清除 Sandboxie 标志与样本原路径，避免影响下一次分析
        self._sbie_pid_provider = None
        self._orig_sample_path = None
        self._stop_event.set()


# ======================================================================
# Sandboxie 界面弹窗抑制（模块级，供 PSLS 启动早期调用）
# ======================================================================
# 背景（实测）：
#   Sandboxie 的"软件兼容性"向导由 CThirdPartyDialog（SbieCtrl.exe）在
#   **启动时**读 `SbieCtrl_AutoRunSoftCompat` 决定是否弹出；它会把兼容性
#   Template/RecoverFolder 写进**所有**沙盒（含我们的 PSLS_Analysis），既
#   弹窗打扰，又弱化分析盒隔离。若等到"分析时"才写这个键，本次会话已经
#   弹过一次 —— 所以必须在 PSLS 启动早期就下发。
#   另外"可恢复文件"弹窗由 `AutoRecover` 控制。

# 会弹 Sandboxie 配置对话框的界面进程
_SBIE_UI_PROC_NAMES = {'sbiectrl.exe', 'sandman.exe', 'sbiesvc.exe'}
_WIN32_DIALOG_CLASS = '#32770'
# Sandboxie 对话框标题关键字（属主进程名兜不住时的第二道识别，实测必需）：
#   "软件兼容性"（CThirdPartyDialog 向导）、"可恢复文件"（AutoRecover 询问）、
#   "Sandboxie" / "SBIE"（各类错误/提示框）
_SBIE_DIALOG_TITLE_KEYWORDS = (
    '软件兼容性', 'Software Compatibility', '可恢复文件', 'Recovery',
    'Sandboxie', 'SBIE',
)
_popup_watcher_stop = threading.Event()

# 已知 Sandboxie.ini 写入会失败（非管理员 / 设备不可写）时置 True：
# `SbieIni set` 失败会让 Sandboxie 弹 `SBIE2322 无法重写 Sandboxie.ini`
# 消息框，且**每次失败弹一次**（实测刷屏）。一旦判定写入不可用，
# 后续所有写入直接跳过，只保留只读查询与盒可用性校验。
_SBIE_INI_WRITE_BLOCKED = False


def _is_elevated() -> bool:
    """当前进程是否管理员（Sandboxie 配置写入需要管理员）。"""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True      # 判断不了时不拦（真失败会被 query 兜住）


def _sbie_env_int(name: str, default: int) -> int:
    """读取整型环境变量（异常安全；解析失败用默认值）。"""
    try:
        return int(os.environ.get(name, '') or default)
    except Exception:
        return default


def _sbie_ini_writes_allowed() -> bool:
    """Sandboxie.ini 是否还可尝试写入。

    - 非管理员：**一个字节都不写**（否则每次失败都弹 SBIE2322 消息框，实测刷屏）；
      这属于"环境不允许"，不是"一次校验失败"，故此处直接跳过（既有语义）。
    - 读回校验失败：**不再**一次失败就永久停写 → 交由 `_write_sbie_setting`
      有限重试 + 退避，仍失败才由其置位降级。
    """
    global _SBIE_INI_WRITE_BLOCKED
    if _SBIE_INI_WRITE_BLOCKED:
        return False
    if not _is_elevated():
        _SBIE_INI_WRITE_BLOCKED = True
        logger.warning(
            '非管理员运行：跳过 Sandboxie 配置写入（否则每次失败都会弹'
            'SBIE2322『无法重写 Sandboxie.ini』）；界面弹窗改由窗口清理兜底')
        return False
    return True


def _sbie_ini_file_candidates() -> List[str]:
    """Sandboxie.ini 文件候选路径（用于**直接文本改写**以保证幂等）。"""
    cands: List[str] = []
    try:
        info = detect_sandboxie_backend() or {}
        d = info.get('dir') or ''
        if d:
            cands.append(os.path.join(d, 'Sandboxie.ini'))
    except Exception:
        pass
    root = os.environ.get('SystemRoot', r'C:\Windows')
    cands.append(os.path.join(root, 'Sandboxie.ini'))
    pd = os.environ.get('ProgramData', r'C:\ProgramData')
    cands.append(os.path.join(pd, 'Sandboxie', 'Sandboxie.ini'))
    out, seen = [], set()
    for c in cands:
        nc = os.path.normcase(c)
        if nc not in seen:
            seen.add(nc)
            out.append(c)
    return out


def _ini_norm_value(v: str) -> str:
    """规范化 ini 取值以便比较：去空白、去引号、忽略行尾注释。

    ini 里同一 key 可能带行尾注释（`AutoRecover=n ; comment`）或多余空格/引号，
    这些差异不应被误判为"写入未生效"。
    """
    s = (v or '').strip()
    # 先去掉行尾注释（`;` / `#` 前须有空白，避免误伤值里的这些字符）
    for mark in (' ;', '\t;', ' #', '\t#'):
        idx = s.find(mark)
        if idx > 0:
            s = s[:idx].strip()
    # 再去掉成对引号
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        s = s[1:-1].strip()
    return s.lower()


def _ini_get_values(text: str, section: str, key: str) -> List[str]:
    """取出某 section 下该 key 的**全部**取值（可能存在多行重复）。"""
    vals: List[str] = []
    cur = ''
    sec_l = section.strip().lower()
    key_l = key.strip().lower()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(';') or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            cur = line[1:-1].strip().lower()
            continue
        if cur != sec_l:
            continue
        if '=' in line:
            k, _, v = line.partition('=')
            if k.strip().lower() == key_l:
                vals.append(v.strip())
    return vals


def _ini_set_value(text: str, section: str, key: str, value: str) -> str:
    """**幂等**设置 `[section] key=value`：同一 key 只保留一行。

    - key 已存在（含多行重复）→ 全部删除后在段首插入一行；
    - key 不存在 → 追加到该段（无该段则新建段）；
    - 保留原文件其它内容、空行与顺序（不影响无关键）。
    """
    lines = text.splitlines()
    sec_l = section.strip().lower()
    key_l = key.strip().lower()
    out: List[str] = []
    cur = ''
    inserted = False
    section_found = False
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            # 进入新段前：若上一段就是目标段且尚未插入，则补插
            if cur == sec_l and not inserted:
                out.append(f'{key}={value}')
                inserted = True
            cur = stripped[1:-1].strip().lower()
            if cur == sec_l:
                section_found = True
            out.append(raw)
            continue
        if cur == sec_l and '=' in stripped:
            k = stripped.partition('=')[0].strip().lower()
            if k == key_l:
                if not inserted:
                    out.append(f'{key}={value}')     # 用第一处位置写入唯一一行
                    inserted = True
                continue                             # 其余重复行丢弃
        out.append(raw)
    if cur == sec_l and not inserted:
        out.append(f'{key}={value}')
        inserted = True
    if not section_found and not inserted:
        out.append(f'[{section}]')
        out.append(f'{key}={value}')
    newline = '\r\n' if '\r\n' in text else '\n'
    return newline.join(out) + (newline if text.endswith(('\n', '\r')) else '')


def _read_ini_text(path: str):
    """读取 ini：返回 `(text, encoding, had_bom)`；保持编码/BOM 原样以便回写。"""
    with open(path, 'rb') as f:
        raw = f.read()
    if raw.startswith(b'\xff\xfe'):
        return raw[2:].decode('utf-16-le', errors='replace'), 'utf-16-le', True
    if raw.startswith(b'\xfe\xff'):
        return raw[2:].decode('utf-16-be', errors='replace'), 'utf-16-be', True
    if raw.startswith(b'\xef\xbb\xbf'):
        return raw[3:].decode('utf-8', errors='replace'), 'utf-8', True
    try:
        return raw.decode('utf-8'), 'utf-8', False
    except UnicodeDecodeError:
        return raw.decode('mbcs', errors='replace'), 'mbcs', False


def _write_ini_file(path: str, section: str, key: str, value: str) -> bool:
    """直接改写 Sandboxie.ini（幂等），保留编码/BOM/行尾。返回是否成功。"""
    try:
        text, enc, had_bom = _read_ini_text(path)
        new_text = _ini_set_value(text, section, key, value)
        if new_text == text:
            return True                      # 无需改动（已是期望值）
        data = new_text.encode(enc, errors='replace')
        if had_bom:
            data = (b'\xff\xfe' if enc == 'utf-16-le' else
                    b'\xfe\xff' if enc == 'utf-16-be' else b'\xef\xbb\xbf') + data
        tmp = path + '.psls_tmp'
        with open(tmp, 'wb') as f:
            f.write(data)
        os.replace(tmp, path)
        return True
    except Exception as e:
        logger.debug(f'直接改写 Sandboxie.ini 失败 {path}: {e}')
        return False


def _write_sbie_setting(ini_exe: str, section: str, key: str, value: str) -> bool:
    """写入 Sandboxie 配置并**读回校验**（幂等替换 + 有限重试 + 退避）。

    修复的实测缺陷：`SbieIni set` 未替换已有行 → 读回 `AutoRecover='n\\nn'`（两行），
    且旧实现一次校验不过就**永久停写**。现在：
      1. 优先**直接文本改写** ini（同一 key 只保留一行，根治多行）；
      2. 再读回校验（规范化比较：忽略空格/引号/行尾注释、多行须收敛为一行同值）；
      3. 不一致 → 退避重试；仍失败才降级停写，并给出可操作提示（需管理员/权限）。
    任何一步失败都不抛异常。
    """
    global _SBIE_INI_WRITE_BLOCKED
    if _SBIE_INI_WRITE_BLOCKED:
        return False
    attempts = max(1, _sbie_env_int('PSLS_SBIE_INI_RETRIES', 2))
    last = ''
    for i in range(attempts):
        if i:
            time.sleep(0.3 * i)              # 退避
        # 1) 直接文本改写（幂等；拿到文件路径时最可靠）
        wrote = False
        for ini_file in _sbie_ini_file_candidates():
            if os.path.isfile(ini_file):
                wrote = _write_ini_file(ini_file, section, key, value) or wrote
        # 2) 若文件不可写/不存在，退回 SbieIni set
        #    （空值表示"仅声明该键"，按旧契约**不传 value 参数**）
        try:
            cmd = [ini_exe, 'set', section, key]
            if value != '':
                cmd.append(value)
            subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                           **_hidden_spawn_kwargs())
        except Exception as e:
            logger.debug(f'SbieIni set {section}/{key} 异常: {e}')
        # 3) 读回校验（文件优先，其次 SbieIni query）
        got = ''
        for ini_file in _sbie_ini_file_candidates():
            if os.path.isfile(ini_file):
                try:
                    t, _e, _b = _read_ini_text(ini_file)
                    vals = _ini_get_values(t, section, key)
                    if vals:
                        got = '\n'.join(vals)
                        break
                except Exception:
                    pass
        if not got:
            try:
                r = subprocess.run([ini_exe, 'query', section, key],
                                   capture_output=True, text=True, timeout=10,
                                   **_hidden_spawn_kwargs())
                got = (r.stdout or '').strip()
            except Exception:
                got = ''
        norm_lines = [_ini_norm_value(x) for x in got.splitlines() if x.strip()]
        if value == '':
            # 空值 = "仅声明该键"：读回只要**存在该键**即视为生效（不比较取值）
            ok = bool(norm_lines)
        else:
            ok = bool(norm_lines) and len(set(norm_lines)) == 1 \
                and norm_lines[0] == _ini_norm_value(value)
        if ok:
            if i:
                logger.info(f'Sandboxie 配置重试后写入生效: [{section}] {key}={value}')
            return True
        last = got
    _SBIE_INI_WRITE_BLOCKED = True
    logger.warning(
        f'Sandboxie 配置写入失败（已停写以免反复弹窗）: '
        f'文件={_sbie_ini_file_candidates()} section={section} key={key} '
        f'期望={value!r} 实际={last!r}；'
        f'可能原因：需要管理员权限 / ini 只读 / Sandboxie 服务占用。'
        f'界面弹窗改由窗口清理兜底')
    return False


def _find_sbie_user_settings_section(ini_exe: str) -> str:
    """枚举 `[UserSettings_xxxx]` 段名（`SbieCtrl_*` 键所在段）。"""
    try:
        r = subprocess.run([ini_exe, 'query', '*'],
                           capture_output=True, text=True, timeout=10,
                           **_hidden_spawn_kwargs())
        for line in (r.stdout or '').splitlines():
            s = line.strip()
            if s.lower().startswith('usersettings'):
                return s
    except Exception as e:
        logger.debug(f'SbieIni 枚举配置段失败: {e}')
    return ''


def suppress_sandboxie_ui_popups() -> bool:
    """下发 Sandboxie 界面弹窗抑制（PSLS 启动早期调用一次）。

    - 盒级 `AutoRecover=n` + 清 `RecoverFolder`：关闭"可恢复文件"弹窗
    - 盒级 `BlockNetworkFiles=y`：拒绝样本经网络共享读写真实文件
    - 用户段 `SbieCtrl_AutoRunSoftCompat=n`：关闭"软件兼容性"自动询问
    - 用户段 `SbieCtrl_AutoApplySettings=n`：禁止界面自动把兼容性模板
      写进分析盒（模板含 SkipHook/OpenFilePath 等，会弱化隔离甚至把写
      操作放行到真实系统）

    只写专用盒与用户段，**绝不写 [GlobalSettings]**。
    """
    info = detect_sandboxie_backend() or {}
    if not info.get('available'):
        return False
    ini_exe = info.get('ini') or ''
    if not ini_exe or not os.path.isfile(ini_exe):
        return False
    # 写入会失败时（非管理员）**一个字节都不要写**：每次失败都弹
    # SBIE2322 消息框（实测刷屏）。
    if not _sbie_ini_writes_allowed():
        return False
    box = getattr(SandboxConfig(), 'sandboxie_box', 'PSLS_Analysis')

    def _run(args):
        # 兼容旧调用点：仅当已有既有键才用（新逻辑统一走 _write_sbie_setting）
        try:
            subprocess.run([ini_exe] + args, capture_output=True,
                           text=True, timeout=15, **_hidden_spawn_kwargs())
            return True
        except Exception as e:
            logger.debug(f'SbieIni {args} 失败: {e}')
            return False

    # 需求 #2：全部改为**幂等写入 + 读回校验 + 有限重试**，
    # 根治"值被写成两行(n\nn)"导致抑制失效（即此前 Edge/向导被莫名启动的根源）。
    _write_sbie_setting(ini_exe, box, 'AutoRecover', 'n')
    _write_sbie_setting(ini_exe, box, 'RecoverFolder', '')
    _write_sbie_setting(ini_exe, box, 'BlockNetworkFiles', 'y')
    sec = _find_sbie_user_settings_section(ini_exe)
    if sec:
        _write_sbie_setting(ini_exe, sec, 'SbieCtrl_AutoRunSoftCompat', 'n')
        _write_sbie_setting(ini_exe, sec, 'SbieCtrl_AutoApplySettings', 'n')
        # 关掉 Sandboxie 托盘界面的自启动：向导是**界面进程启动时**弹的，
        # 而界面常常在 PSLS 启动前（安装后 / 开机登录时）就起来了，那时我们
        # 还没机会写 ini。不自启 = 从源头不再弹（盒功能由 SbieSvc + 驱动提供，
        # 不依赖托盘界面）。
        _write_sbie_setting(ini_exe, sec, 'SbieCtrl_EnableAutoStart', 'n')

    # 校验与降级已由 _write_sbie_setting 内部完成（含重试/退避与可操作提示）
    logger.info(
        f'Sandboxie 界面弹窗抑制已下发（盒={box}, 用户段={sec or "未找到"}）')
    return True


def _close_sandboxie_dialogs() -> int:
    """关闭 Sandboxie 弹出的 Win32 对话框（软件兼容性 / 可恢复文件 / SBIE 错误框）。

    为什么需要：`SbieCtrl_AutoRunSoftCompat` 是 Sandboxie 界面进程**启动时**
    读的；若界面已在本次会话早期启动过（向导已弹出），改 ini 拦不住已经弹出的
    那个窗口 —— 尤其在 PSLS **非管理员**运行（写不了 ini）或界面比 PSLS 更早
    启动（安装后 / 开机自启）时，只能靠窗口清理。

    匹配策略（两道）：
      1. 属主进程是 Sandboxie 界面进程（SbieCtrl / SandMan / SbieSvc）且类为
         `#32770`；
      2. **标题命中 Sandboxie 已知对话框关键字**（不依赖属主进程名 —— 实测
         界面版本/宿主不同会换进程，仅靠名字会漏）。
    只处理对话框类窗口，不碰它们的 Qt 主窗口，也不碰 SbieSvc/Start.exe 本身。
    先 `WM_CLOSE`；未关闭则在下一轮点它的按钮（BM_CLICK）兜底。
    """
    if sys.platform != 'win32':
        return 0
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return 0
    ui_pids = set()
    try:
        import psutil
        for p in psutil.process_iter(['pid', 'name']):
            try:
                _nm = (p.info.get('name') or '').lower()
                if _nm in _SBIE_UI_PROC_NAMES or _nm.startswith(('sbie', 'sandbox')):
                    ui_pids.add(int(p.info['pid']))
            except Exception:
                continue
    except Exception:
        ui_pids = set()

    user32 = ctypes.windll.user32
    WM_CLOSE = 0x0010
    BM_CLICK = 0x00F5
    closed = [0]
    buf = ctypes.create_unicode_buffer(260)
    cls = ctypes.create_unicode_buffer(64)

    def _matches(pid_val: int, title: str, cls_name: str) -> bool:
        if pid_val in ui_pids and cls_name == _WIN32_DIALOG_CLASS:
            return True
        # 标题兜底：只认 Sandboxie 自己的对话框关键字，避免误关别的程序
        return any(kw in title for kw in _SBIE_DIALOG_TITLE_KEYWORDS)

    def _click_buttons(hwnd):
        """兜底：点掉对话框上的默认/取消按钮（部分向导不响应 WM_CLOSE）。"""
        try:
            for cid in (1, 2):        # IDOK / IDCANCEL
                btn = user32.GetDlgItem(hwnd, cid)
                if btn and user32.IsWindowVisible(btn):
                    user32.PostMessageW(btn, BM_CLICK, 0, 0)
                    return True
        except Exception:
            pass
        return False

    def _cb(hwnd, _lparam):
        try:
            pid = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if not user32.IsWindowVisible(hwnd):
                return True
            user32.GetClassNameW(hwnd, cls, 64)
            title = ''
            if user32.GetWindowTextW(hwnd, buf, 260):
                title = buf.value or ''
            if not _matches(pid.value, title, cls.value):
                return True
            user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            # WM_CLOSE 异步；同一轮再点一次按钮，双保险（向导若已关，GetDlgItem 返回 0）
            _click_buttons(hwnd)
            closed[0] += 1
            logger.info(f'已关闭 Sandboxie 界面弹窗: [{title}] '
                        f'(pid={pid.value} class={cls.value})')
        except Exception:
            pass
        return True

    try:
        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND,
                                         wintypes.LPARAM)
        user32.EnumWindows(WNDENUMPROC(_cb), 0)
    except Exception as e:
        logger.debug(f'枚举 Sandboxie 对话框失败: {e}')
    return closed[0]


def start_sandboxie_popup_watcher(interval: float = 1.5) -> threading.Thread:
    """启动后台线程：周期关闭 Sandboxie 界面弹窗（幂等，可重复调用）。"""
    if getattr(start_sandboxie_popup_watcher, '_started', False):
        return None

    def _loop():
        while not _popup_watcher_stop.is_set():
            if _popup_watcher_stop.wait(interval):
                break
            try:
                _close_sandboxie_dialogs()
            except Exception:
                pass

    t = threading.Thread(target=_loop, daemon=True, name='SbieUiSuppress')
    t.start()
    start_sandboxie_popup_watcher._started = True
    return t


def stop_sandboxie_popup_watcher():
    """停止弹窗抑制线程（退出时调用）。"""
    _popup_watcher_stop.set()
