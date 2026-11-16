# -*- coding: utf-8 -*-
"""
PSLS 自我保护引擎
保护 PSLS 自身进程和关键文件不被恶意软件终止、篡改或破坏。

核心功能：
1. 反调试检测：检测调试器附加（IsDebuggerPresent / CheckRemoteDebuggerPresent）
2. 反注入检测：检测远程线程注入到 PSLS 进程
3. 进程守护：监控自身进程状态，检测异常句柄操作
4. 关键文件完整性保护：监控自身可执行文件、签名库、配置文件的哈希基线
5. 关键目录监控：watchdog 监控 PSLS 安装目录的文件变更
6. 自动备份与回滚：开启后定期备份关键文件，检测到篡改时自动从备份恢复

设计原则：
- 轻量级：所有检查在子线程定期执行，不阻塞主线程
- 降级兼容：psutil/ctypes/watchdog 不可用时降级运行
- 误报控制：调试器检测需多次确认，文件变更需校验哈希
"""
import os
import sys
import time
import hashlib
import shutil
import json
import threading
from typing import Callable, Dict, List, Optional, Set

from utils.logger import get_logger

logger = get_logger('self_protection')

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    psutil = None

try:
    import ctypes
    import ctypes.wintypes
    HAS_CTYPES = True
except ImportError:
    HAS_CTYPES = False
    ctypes = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    Observer = None
    FileSystemEventHandler = object


# ---- 配置 ----

# 监控轮询间隔（秒）
_MONITOR_INTERVAL = 5.0

# 完整性检查间隔（秒）
_INTEGRITY_CHECK_INTERVAL = 30.0

# 调试器检测间隔（秒）
_ANTIDEBUG_CHECK_INTERVAL = 10.0

# 注入深度扫描间隔（秒）—— 远程线程/DLL 注入检测较重，降低频率
_INJECTION_SCAN_INTERVAL = 15.0

# 进程保护激活重试间隔（秒）—— 启动时内核/DACL 两级保护均失败才重试
_PROTECTION_RETRY_INTERVAL = 60.0

# 调试器检测连续命中阈值（避免偶发误报）
_DEBUG_CONFIRM_THRESHOLD = 3

# 自动备份间隔（秒）—— 自保护启用后每隔此时间备份一次关键文件
_BACKUP_INTERVAL = 300.0  # 5分钟

# 诊断开关：临时禁用自动备份，用于二分"启动约35秒后静默闪退"根因
# （两次运行均在"自动备份完成"后 6-8 秒内被硬杀）
# 2026-08-31 闪退根因已确定为"自我沙箱误判"，与备份无关，已恢复 False。
_DIAG_DISABLE_BACKUP = False

# 备份目录名（相对项目根目录）
_BACKUP_DIR_NAME = 'backup'

# 备份元数据文件名
_BACKUP_MANIFEST_FILE = 'manifest.json'

# 最大备份数量（滚动备份，超过此数删除最旧的）
_MAX_BACKUP_COPIES = 3

# 回滚重试次数
_ROLLBACK_MAX_RETRIES = 2

# 受保护的 PSLS 关键文件（相对项目根目录）
_CRITICAL_FILES_REL = [
    'gui_entry.py',
    'ui/webview/main_window.py',
    'ui/webview/bridge.py',
    'ui/webview/index.html',
    'engine/scan_engine.py',
    'engine/self_protection.py',
    'engine/process_protection.py',
    'engine/file_protection.py',
    'engine/system_protection.py',
    'engine/notification_manager.py',
    'engine/quarantine_manager.py',
    'db/signature_db.py',
    'utils/archive_scanner.py',
    'utils/autostart_manager.py',
    'utils/sound_manager.py',
    'utils/file_walker.py',
    'utils/hash_utils.py',
    'utils/logger.py',
    # 注意：以下文件不纳入监控（运行时会正常修改）
    # - db/signatures.db（签名库导入时会修改）
    # - quarantine/quarantine.json（隔离/恢复操作时会修改）
    # - logs/*.log（日志持续写入）
]

# Windows API 常量
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# 文件属性常量（SetFileAttributesW）
FILE_ATTRIBUTE_READONLY = 0x01
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

# ---- 进程保护说明 ----
# 之前的 ProcessBreakOnTermination (关键进程) 方案已移除：
#   副作用：任何方式终止进程（包括崩溃）都会触发蓝屏
#
# 当前方案（不蓝屏）：
#   L0: 内核驱动 ObRegisterCallbacks — R0 掩码 PROCESS_TERMINATE，任务管理器拒绝访问
def _get_install_root() -> str:
    """返回应用安装根目录

    冻结模式: PSLS.exe 所在目录（安装目录）
    开发模式: 项目根（engine/ 的上级目录）
    """
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _try_activate_kernel_protection():
    """尝试激活内核驱动进程保护

    通过驱动桥接层:
      1. set_config(enable_psls_protect=1) → 驱动动态注册 ObRegisterCallbacks
      2. set_psls_pid(self_pid)            → 驱动开始拦截对 PSLS 的 OpenProcess
      3. query_status() 端到端复核          → 确认驱动确实持有本进程 PID
      4. set_protected_dir(install_dir)     → 内核级禁止外部进程修改安装目录

    Returns:
        True = 驱动已加载并激活保护, False = 驱动未加载或激活失败
    """
    if sys.platform != 'win32':
        return False
    try:
        from driver.bridge.psls_driver_bridge import PSLSDriverBridge
        bridge = PSLSDriverBridge()

        # 设备句柄能打开 = 驱动已在内核中（无论由哪个服务名加载:
        # 可能是本应用装的 PSLS 服务, 也可能是测试时手动 sc create 的
        # 任意服务名）。服务状态不是驱动在内核的判据, 设备才是。
        if not bridge.is_available:
            from utils.driver_manager import ensure_driver_loaded
            if not ensure_driver_loaded():
                logger.warning('内核驱动未加载，跳过内核进程保护')
                return False
            bridge = PSLSDriverBridge()
            if not bridge.is_available:
                logger.warning('驱动服务已启动但设备打开失败')
                return False

        ok_config = bridge.set_config({'enable_psls_protect': 1})
        if not ok_config:
            logger.warning('内核驱动 set_config(enable_psls_protect=1) 失败')

        ok_pid = bridge.set_psls_pid(os.getpid())
        if not ok_pid:
            logger.warning('内核驱动 set_psls_pid 失败')
            return False

        # 端到端复核: 驱动内部必须同时满足 开关开启 + 目标PID为本进程。
        # (SET_CONFIG 内部注册失败时会静默回滚开关位而 IOCTL 仍返回成功,
        #  不复核会得到"看似激活、实际无防护"的假激活)
        st = bridge.query_status()
        if st is None:
            logger.warning('内核驱动 query_status 失败，无法复核激活状态')
            return False
        if not st.psls_protect_enabled:
            logger.warning('内核驱动保护开关未生效（驱动内部注册可能失败）')
            return False
        if st.psls_pid != os.getpid():
            logger.warning(
                f'内核驱动保护目标不符: 驱动持有 pid={st.psls_pid}, '
                f'本进程 pid={os.getpid()}')
            return False

        # ---- 内核级安装目录防改 ----
        # 驱动加载后禁止外部进程对安装目录的 写入/删除/重命名/截断
        # （minifilter PRE 阶段拒绝；PSLS 自身放行；本进程退出时
        #   内核自动解除保护，不影响卸载流程）
        try:
            install_dir = _get_install_root()
            if install_dir and bridge.set_protected_dir(install_dir):
                logger.info(f'内核级安装目录保护已启用: {install_dir}')
            else:
                logger.warning('内核驱动 set_protected_dir 失败'
                               '（旧版驱动不支持为正常现象）')
            # 豁免子树：安装目录下的 Sandboxie 需要外部进程可写自己的文件，
            # 否则"安装目录防改"会把沙箱自身写操作也拒掉（实测沙箱失效+误报占用）
            try:
                sb_dir = os.path.join(install_dir, 'Sandboxie') if install_dir else ''
                set_exempt = getattr(bridge, 'set_exempt_dir', None)
                if sb_dir and os.path.isdir(sb_dir) and callable(set_exempt):
                    if set_exempt(sb_dir):
                        logger.info(f'内核级豁免目录已设置（沙箱可写）: {sb_dir}')
                    else:
                        logger.warning(f'内核级豁免目录设置失败（旧版驱动为正常现象）: {sb_dir}')
            except Exception as e:
                logger.debug(f'设置豁免目录异常: {e}')
        except Exception as e:
            logger.debug(f'设置安装目录保护异常: {e}')

        logger.info('内核驱动进程保护已激活（ObRegisterCallbacks + set_psls_pid 已复核）')
        return True
    except ImportError:
        logger.debug('驱动桥接模块不可用，内核进程保护未激活')
        return False
    except Exception as e:
        logger.debug(f'激活内核进程保护异常: {e}')
        return False


def _deactivate_kernel_protection():
    """停用内核驱动进程保护

    顺序很重要:
      1. set_config(enable_psls_protect=0) → 驱动先 ObUnRegisterCallbacks (不再拦截)
      2. set_psls_pid(0)                   → 清空 g_PslsPid / 释放 EPROCESS 引用
      3. clear_protected_dir()             → 解除安装目录写保护（允许卸载/升级）
    """
    if sys.platform != 'win32':
        return False
    try:
        from driver.bridge.psls_driver_bridge import PSLSDriverBridge
        bridge = PSLSDriverBridge()
        if not bridge.is_available:
            return False

        bridge.set_config({'enable_psls_protect': 0})
        bridge.set_psls_pid(0)
        try:
            bridge.clear_protected_dir()
        except Exception:
            pass
        logger.info('内核驱动进程保护已停用（ObUnRegisterCallbacks + pid 清零）')
        return True
    except ImportError:
        logger.debug('驱动桥接模块不可用')
        return False
    except Exception as e:
        logger.debug(f'停用内核进程保护异常: {e}')
        return False


# ==================================================================
# 用户态 DACL 进程保护（不需要内核驱动）
# ==================================================================
# 原理：通过 SetSecurityInfo 给进程对象添加 Deny ACE 拒绝 PROCESS_TERMINATE
# 任务管理器调用 OpenProcess(PROCESS_TERMINATE) 会返回 ERROR_ACCESS_DENIED
# 效果：任务管理器右键"结束任务"显示"拒绝访问"，taskkill /F 返回 Access denied
#
# 优势：
#   - 纯用户态，不需要内核驱动签名
#   - 不触发蓝屏（与 ProcessBreakOnTermination 不同）
#   - 对管理员任务管理器也有效（默认不启用 SeDebugPrivilege）
#
# 局限：
#   - 拥有 SeDebugPrivilege 的进程可以绕过 DACL
#   - 正常退出前必须撤销保护（否则自己也退不了）

# DACL 保护相关常量
_PROCESS_TERMINATE = 0x0001
_PROCESS_ALL_ACCESS = 0x001F0FFF
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SE_KERNEL_OBJECT = 6  # SE_OBJECT_TYPE for kernel objects

# SDDL 字符串：用 SDDL 语法构建 DACL，避免 ctypes 结构体对齐和字符串 GC 问题
# 格式: D:(A;;AccessMask;;;SID)(D;;AccessMask;;;SID)
#   A = Allow, D = Deny
#   WD = Everyone (World), BA = Built-in Administrators, SY = SYSTEM
#   0x001F0FFF = PROCESS_ALL_ACCESS, 0x0001 = PROCESS_TERMINATE
#
# 保护 SDDL: Allow ALL_ACCESS + Deny TERMINATE（Deny 优先于 Allow）
_SDDL_PROTECT = (
    'D:'
    '(A;;0x001F0FFF;;;WD)'   # Allow Everyone PROCESS_ALL_ACCESS
    '(A;;0x001F0FFF;;;BA)'   # Allow Administrators PROCESS_ALL_ACCESS
    '(A;;0x001F0FFF;;;SY)'   # Allow SYSTEM PROCESS_ALL_ACCESS
    '(D;;0x00000001;;;WD)'   # Deny Everyone PROCESS_TERMINATE
    '(D;;0x00000001;;;BA)'   # Deny Administrators PROCESS_TERMINATE
    '(D;;0x00000001;;;SY)'   # Deny SYSTEM PROCESS_TERMINATE
)

# 撤销 SDDL: 仅 Allow ALL_ACCESS（无 Deny，恢复正常）
_SDDL_UNPROTECT = (
    'D:'
    '(A;;0x001F0FFF;;;WD)'   # Allow Everyone PROCESS_ALL_ACCESS
    '(A;;0x001F0FFF;;;BA)'   # Allow Administrators PROCESS_ALL_ACCESS
    '(A;;0x001F0FFF;;;SY)'   # Allow SYSTEM PROCESS_ALL_ACCESS
)


def _apply_sddl_dacl(pid: int, sddl: str) -> bool:
    """通过 SDDL 字符串设置进程 DACL

    使用 ConvertStringSecurityDescriptorToSecurityDescriptorW 将 SDDL 转换为
    安全描述符，提取 DACL 后通过 SetSecurityInfo 应用到进程。

    Args:
        pid: 目标进程 PID
        sddl: SDDL 格式的安全描述符字符串

    Returns:
        True 成功，False 失败
    """
    if not HAS_CTYPES or sys.platform != 'win32':
        return False

    handle = None
    sd_ptr = None

    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        # 设置函数签名（关键：x64 上 HANDLE 是 64 位，默认 c_int 会截断）
        kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [
            ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD,
        ]
        kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p

        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
            ctypes.wintypes.BOOL
        )
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            ctypes.c_wchar_p, ctypes.wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.wintypes.ULONG),
        ]

        advapi32.GetSecurityDescriptorDacl.restype = ctypes.wintypes.BOOL
        advapi32.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.wintypes.BOOL),
        ]

        advapi32.SetSecurityInfo.restype = ctypes.wintypes.DWORD
        advapi32.SetSecurityInfo.argtypes = [
            ctypes.wintypes.HANDLE, ctypes.c_int, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ]

        # 1. SDDL -> SecurityDescriptor
        sd_ptr = ctypes.c_void_p(0)
        sd_size = ctypes.wintypes.ULONG(0)
        ok = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1,  # SDDL_REVISION_1
            ctypes.byref(sd_ptr), ctypes.byref(sd_size),
        )
        if not ok:
            err = ctypes.get_last_error()
            logger.warning(f'DACL: ConvertStringSDDtoSD 失败 err={err}')
            return False

        # 2. 从 SD 提取 DACL
        dacl_present = ctypes.wintypes.BOOL(False)
        dacl_ptr = ctypes.c_void_p(0)
        dacl_defaulted = ctypes.wintypes.BOOL(False)
        ok = advapi32.GetSecurityDescriptorDacl(
            sd_ptr, ctypes.byref(dacl_present),
            ctypes.byref(dacl_ptr), ctypes.byref(dacl_defaulted),
        )
        if not ok or not dacl_present.value or not dacl_ptr.value:
            logger.warning(f'DACL: GetSecurityDescriptorDacl 失败 ok={ok} present={dacl_present.value}')
            kernel32.LocalFree(sd_ptr)
            return False

        # 3. 打开目标进程
        _WRITE_DAC = 0x00040000
        _READ_CONTROL = 0x00020000
        handle = kernel32.OpenProcess(
            _WRITE_DAC | _READ_CONTROL, False, int(pid)
        )
        if not handle:
            err = ctypes.get_last_error()
            logger.warning(f'DACL: OpenProcess(WRITE_DAC) 失败 PID={pid} err={err}')
            kernel32.LocalFree(sd_ptr)
            return False

        # 4. 应用新 DACL
        status = advapi32.SetSecurityInfo(
            handle, _SE_KERNEL_OBJECT,
            _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, dacl_ptr, None,
        )

        kernel32.CloseHandle(handle)
        handle = None
        kernel32.LocalFree(sd_ptr)
        sd_ptr = None

        if status != 0:
            logger.warning(f'DACL: SetSecurityInfo 失败 status={status}')
            return False

        return True

    except Exception as e:
        logger.warning(f'DACL: 异常 {e}', exc_info=True)
        if handle:
            try:
                kernel32.CloseHandle(handle)
            except Exception:
                pass
        if sd_ptr:
            try:
                kernel32.LocalFree(sd_ptr)
            except Exception:
                pass
        return False


def _apply_process_dacl_protection(pid: int = 0) -> bool:
    """给进程添加 Deny ACE 拒绝 PROCESS_TERMINATE

    使用 SDDL 方式构建 DACL：
    - Allow PROCESS_ALL_ACCESS for Everyone/Administrators/SYSTEM
    - Deny PROCESS_TERMINATE for Everyone/Administrators/SYSTEM

    任务管理器调用 OpenProcess(PROCESS_TERMINATE) 会返回 ERROR_ACCESS_DENIED，
    显示"拒绝访问"。纯用户态实现，不需要内核驱动。

    Args:
        pid: 目标进程 PID，0 表示当前进程

    Returns:
        True 成功，False 失败
    """
    if not HAS_CTYPES or sys.platform != 'win32':
        return False

    target_pid = os.getpid() if (pid == 0 or pid == os.getpid()) else int(pid)

    ok = _apply_sddl_dacl(target_pid, _SDDL_PROTECT)
    if ok:
        logger.info(f'DACL 保护已设置: PID={target_pid} Deny PROCESS_TERMINATE (SDDL)')
    else:
        logger.warning(f'DACL 保护失败: PID={target_pid}')
    return ok


def _remove_process_dacl_protection(pid: int = 0) -> bool:
    """撤销 DACL 保护，恢复为 Allow ALL_ACCESS，允许进程被终止

    Args:
        pid: 目标进程 PID，0 表示当前进程

    Returns:
        True 成功，False 失败
    """
    if not HAS_CTYPES or sys.platform != 'win32':
        return False

    target_pid = os.getpid() if (pid == 0 or pid == os.getpid()) else int(pid)

    ok = _apply_sddl_dacl(target_pid, _SDDL_UNPROTECT)
    if ok:
        logger.info(f'DACL 保护已撤销: PID={target_pid}')
    else:
        logger.warning(f'DACL 撤销失败: PID={target_pid}')
    return ok


def _get_project_root() -> str:
    """获取项目根目录"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _get_self_pid() -> int:
    """获取当前进程 PID"""
    return os.getpid()


def _get_self_exe_path() -> str:
    """获取自身可执行文件路径（打包模式为 .exe，开发模式为 python.exe）"""
    if getattr(sys, 'frozen', False):
        return sys.executable
    try:
        if HAS_PSUTIL:
            return psutil.Process().exe()
    except Exception:
        pass
    return sys.executable


# ---- Windows API 绑定 ----

def _is_debugger_present() -> bool:
    """调用 IsDebuggerPresent 检测用户态调试器"""
    if not HAS_CTYPES:
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        return bool(kernel32.IsDebuggerPresent())
    except Exception:
        return False


def _check_remote_debugger() -> bool:
    """调用 CheckRemoteDebuggerPresent 检测远程调试器"""
    if not HAS_CTYPES or not sys.platform == 'win32':
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        is_debugged = ctypes.wintypes.BOOL(False)
        handle = kernel32.GetCurrentProcess()
        kernel32.CheckRemoteDebuggerPresent(
            handle, ctypes.byref(is_debugged)
        )
        return bool(is_debugged.value)
    except Exception:
        return False


def _check_debugger_by_port() -> bool:
    """通过检查调试端口检测调试器（anti-debug 技巧）

    检查 PEB.BeingDebugged 标志和 NtGlobalFlag。
    """
    if not HAS_CTYPES or not sys.platform == 'win32':
        return False
    try:
        # 检查 PEB.BeingDebugged（仅 32 位进程可直接通过 TIB 访问）
        # 64 位进程需要通过 NtQueryInformationProcess
        ntdll = ctypes.windll.ntdll

        # ProcessDebugPort = 7
        debug_port = ctypes.c_void_p(0)
        status = ntdll.NtQueryInformationProcess(
            kernel32_handle(),
            7,  # ProcessDebugPort
            ctypes.byref(debug_port),
            ctypes.sizeof(debug_port),
            None
        )
        if status == 0 and debug_port.value:
            return True

        # ProcessDebugFlags = 31（0 = 被调试）
        debug_flags = ctypes.wintypes.ULONG(0)
        status = ntdll.NtQueryInformationProcess(
            kernel32_handle(),
            31,  # ProcessDebugFlags
            ctypes.byref(debug_flags),
            ctypes.sizeof(debug_flags),
            None
        )
        if status == 0 and debug_flags.value == 0:
            return True

    except Exception:
        pass
    return False


def kernel32_handle():
    """获取当前进程句柄"""
    if not HAS_CTYPES:
        return None
    try:
        return ctypes.windll.kernel32.GetCurrentProcess()
    except Exception:
        return None


# ---- 文件属性操作 ----

def _set_file_readonly(file_path: str) -> bool:
    """将文件设置为只读属性（拒绝普通写访问）

    Returns:
        True 成功，False 失败
    """
    if not HAS_CTYPES or sys.platform != 'win32':
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        # Windows API: SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes)
        SetFileAttributesW = kernel32.SetFileAttributesW
        SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        SetFileAttributesW.restype = ctypes.c_bool
        result = SetFileAttributesW(file_path, FILE_ATTRIBUTE_READONLY)
        return bool(result)
    except Exception as e:
        logger.debug(f'设置只读属性失败 {file_path}: {e}')
        return False


def _set_file_normal(file_path: str) -> bool:
    """恢复文件为正常属性（允许读写）

    Returns:
        True 成功，False 失败
    """
    if not HAS_CTYPES or sys.platform != 'win32':
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        SetFileAttributesW = kernel32.SetFileAttributesW
        SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        SetFileAttributesW.restype = ctypes.c_bool
        result = SetFileAttributesW(file_path, FILE_ATTRIBUTE_NORMAL)
        return bool(result)
    except Exception as e:
        logger.debug(f'恢复文件属性失败 {file_path}: {e}')
        return False


# ---- 文件完整性监控 ----

class _SelfFileHandler(FileSystemEventHandler):
    """watchdog 事件处理器：监控 PSLS 自身文件的变更"""

    def __init__(self, manager: 'SelfProtection'):
        super().__init__()
        self._manager = manager

    def on_modified(self, event):
        if event.is_directory:
            return
        self._manager._on_self_file_event(event.src_path, 'modified')

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._manager._on_self_file_event(event.src_path, 'deleted')

    def on_created(self, event):
        if event.is_directory:
            return
        self._manager._on_self_file_event(event.src_path, 'created')

    def on_moved(self, event):
        if event.is_directory:
            return
        self._manager._on_self_file_event(event.src_path, 'moved')


class SelfProtection:
    """
    PSLS 自我保护引擎

    功能：
    1. 反调试：定期检测调试器附加
    2. 反注入：检测远程线程注入
    3. 进程守护：监控自身进程异常
    4. 文件完整性：监控关键文件哈希基线
    5. 目录监控：watchdog 实时监控安装目录变更
    """

    def __init__(self, on_threat: Callable[[dict], None] = None):
        """
        Args:
            on_threat: 检测到威胁时的回调
        """
        self._on_threat = on_threat
        self._running = False
        self._enabled = True  # 自我保护开关（默认启用）
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # watchdog 监控
        self._observer: Optional['Observer'] = None
        self._handler: Optional[_SelfFileHandler] = None

        # 文件哈希基线：{filepath: {'hash': str, 'size': int, 'mtime': float}}
        self._file_baselines: Dict[str, dict] = {}
        self._baseline_lock = threading.Lock()

        # 受保护的关键文件路径（绝对路径）
        self._critical_files: Set[str] = set()

        # 项目根目录
        self._project_root = _get_project_root()

        # 自身进程信息
        self._self_pid = _get_self_pid()
        self._self_exe = _get_self_exe_path()

        # 调试器检测连续计数（避免偶发误报）
        self._debug_hit_count = 0
        self._debug_reported = False  # 避免重复报警

        # 统计数据
        self._stats = {
            'integrity_checks': 0,
            'debugger_detected': 0,
            'injection_detected': 0,
            'tampering_detected': 0,
            'files_monitored': 0,
            'started_at': 0,
            'check_count': 0,
        }
        self._stats_lock = threading.Lock()

        # 最近事件
        self._recent_events: List[dict] = []
        self._events_lock = threading.Lock()
        self._max_events = 200

        # 基线建立延迟到 start() 后执行
        self._baselines_built = False

        # ---- 自动备份与回滚 ----
        self._backup_dir = os.path.join(self._project_root, _BACKUP_DIR_NAME)
        self._backup_manifest_path = os.path.join(self._backup_dir, _BACKUP_MANIFEST_FILE)
        self._backup_lock = threading.Lock()
        self._last_backup_time = 0.0

        # ---- 进程保护状态 ----
        # L0: 内核驱动 ObRegisterCallbacks（需要驱动签名，通常不生效）
        self._kernel_protection_active = False
        # L1: 用户态 DACL 保护（纯用户态，Deny ACE PROCESS_TERMINATE）
        self._dacl_protection_active = False
        # 已应用 DACL 保护的辅助进程 PID（worker/MLWorker 等；退出时需撤销）
        self._dacl_related_pids: list = []
        # 激活/停用互斥锁：监控线程（启动激活/重试）与用户开关（set_enabled）
        # 可能并发调用，串行化以避免并发调用驱动 SET_PID
        self._protection_lock = threading.Lock()

    # ---- 属性 ----

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_enabled(self) -> bool:
        """自保护是否处于启用状态（用户开关）"""
        return self._enabled

    def set_enabled(self, enabled: bool) -> dict:
        """设置自保护开关状态

        开启时：
            1. 启动监控（如未运行）
            2. 为所有关键文件设置只读属性（拒绝普通写访问）
            3. 重新建立文件哈希基线
        关闭时：
            1. 恢复所有关键文件为可写（正常）属性
            2. 监控继续运行但跳过所有检查（保持与当前关闭状态逻辑一致）

        Args:
            enabled: True 启用，False 关闭

        Returns:
            {
                'enabled': bool,          # 实际启用的状态
                'protected_count': int,   # 成功设置为只读的文件数（启用时）
                'restored_count': int,    # 成功恢复的文件数（关闭时）
                'failed_count': int,      # 失败的文件数
                'monitoring': bool,       # 监控是否在运行
            }
        """
        if self._enabled == enabled:
            return {
                'enabled': self._enabled,
                'protected_count': 0,
                'restored_count': 0,
                'failed_count': 0,
                'monitoring': self._running,
            }

        self._enabled = enabled

        result = {
            'enabled': self._enabled,
            'protected_count': 0,
            'restored_count': 0,
            'failed_count': 0,
            'monitoring': False,
        }

        if enabled:
            # 启动监控（如未运行）
            if not self._running:
                self.start()

            # 启用关键进程保护（start() 中已调用，此处确保开启）
            self._enable_critical_protection()

            # 初始化关键文件列表（确保 critical_files 已填充）
            self._init_critical_files()

            # 为所有关键文件设置只读属性
            for filepath in self._critical_files:
                if not os.path.isfile(filepath):
                    continue
                if _set_file_readonly(filepath):
                    result['protected_count'] += 1
                else:
                    result['failed_count'] += 1

            # 重新建立基线
            try:
                self._build_baselines()
            except Exception as e:
                logger.debug(f'重置自保护基线失败: {e}')

            self._add_event('system', 'enabled',
                            f'自我保护已启用（已保护 {result["protected_count"]} 个关键文件）')
            logger.info(f'自我保护已启用（成功 {result["protected_count"]}，失败 {result["failed_count"]}）')

            # 启用时立即执行一次备份
            try:
                self._perform_backup()
            except Exception as e:
                logger.debug(f'启用后自动备份失败: {e}')
        else:
            # 关闭关键进程保护（允许任务管理器终止）
            self._disable_critical_protection()

            # 恢复所有关键文件为可写
            for filepath in self._critical_files:
                if not os.path.isfile(filepath):
                    continue
                if _set_file_normal(filepath):
                    result['restored_count'] += 1
                else:
                    result['failed_count'] += 1

            self._add_event('system', 'disabled',
                            f'自我保护已关闭（已恢复 {result["restored_count"]} 个文件为可写）')
            logger.info(f'自我保护已关闭（恢复 {result["restored_count"]}，失败 {result["failed_count"]}）')

        result['monitoring'] = self._running
        return result

    def get_stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    def get_recent_events(self, limit: int = 20) -> list:
        with self._events_lock:
            return list(reversed(self._recent_events[-limit:]))

    # ---- 内部：日志/事件 ----

    def _add_event(self, event_type: str, status: str,
                   detail: str = '', path: str = ''):
        ev = {
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'type': event_type,
            'status': status,
            'detail': detail,
            'path': path,
        }
        with self._events_lock:
            self._recent_events.append(ev)
            if len(self._recent_events) > self._max_events:
                self._recent_events = self._recent_events[-self._max_events:]
        logger.info(f"[自我保护] {event_type} [{status}] {detail} {path}")

    def _report_threat(self, threat_data: dict):
        """报告威胁（通过回调通知上层）"""
        with self._stats_lock:
            if 'debugger' in threat_data.get('type', ''):
                self._stats['debugger_detected'] += 1
            elif 'injection' in threat_data.get('type', ''):
                self._stats['injection_detected'] += 1
            elif 'tamper' in threat_data.get('type', '') or 'file' in threat_data.get('type', ''):
                self._stats['tampering_detected'] += 1

        self._add_event(
            threat_data.get('type', 'threat'),
            'threat',
            threat_data.get('detail', ''),
            threat_data.get('path', ''),
        )

        if self._on_threat:
            try:
                self._on_threat(threat_data)
            except Exception as e:
                logger.error(f"on_threat 回调异常: {e}")

    # ---- 初始化 ----

    def _init_critical_files(self):
        """初始化受保护的关键文件列表"""
        self._critical_files.clear()
        for rel_path in _CRITICAL_FILES_REL:
            abs_path = os.path.join(self._project_root, rel_path.replace('/', os.sep))
            abs_path = os.path.normpath(abs_path)
            if os.path.exists(abs_path):
                self._critical_files.add(abs_path.lower())

        # 添加自身可执行文件（仅限项目/安装目录内）。
        # 开发模式下 sys.executable / psutil.Process().exe() 指向系统 python.exe，
        # 属于外部解释器：不应被设为只读、建立完整性基线或参与备份，
        # 否则会误改系统 Python 环境并在 backup 目录外产生垃圾文件。
        if self._self_exe and os.path.exists(self._self_exe):
            self_exe_abs = os.path.normpath(os.path.abspath(self._self_exe)).lower()
            project_root_abs = os.path.normpath(os.path.abspath(self._project_root)).lower()
            try:
                same_root = os.path.commonpath(
                    [self_exe_abs, project_root_abs]) == project_root_abs
            except ValueError:
                same_root = False  # 不同驱动器
            if same_root:
                self._critical_files.add(self_exe_abs)
            else:
                logger.info(
                    f'自我保护: 跳过外部自身可执行文件 {self._self_exe}'
                    '（不在项目目录内，开发模式解释器不纳入保护/备份）')

        logger.info(f'自我保护: {len(self._critical_files)} 个关键文件')

    def _build_baselines(self):
        """为所有关键文件建立哈希基线"""
        with self._baseline_lock:
            self._file_baselines.clear()
            for filepath in self._critical_files:
                try:
                    if os.path.isfile(filepath):
                        file_hash = self._compute_file_hash(filepath)
                        stat = os.stat(filepath)
                        self._file_baselines[filepath] = {
                            'hash': file_hash,
                            'size': stat.st_size,
                            'mtime': stat.st_mtime,
                        }
                except Exception as e:
                    logger.debug(f'建立基线失败 {filepath}: {e}')

            with self._stats_lock:
                self._stats['files_monitored'] = len(self._file_baselines)

        self._baselines_built = True
        logger.info(f'自我保护: 已为 {len(self._file_baselines)} 个文件建立完整性基线')

    @staticmethod
    def _compute_file_hash(file_path: str) -> Optional[str]:
        """计算文件 SHA256 哈希"""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    # ---- 启动/停止 ----

    def start(self) -> bool:
        if self._running:
            return True

        self._stop_event.clear()
        self._running = True

        # 启动自愈：尽早清除上次异常退出（强杀/崩溃）残留的驱动保护状态，
        # 避免新进程被自身驱动视为外部进程 → 写入安装目录被拒（"无权限"）。
        # 同步执行、幂等、失败不致命；_enable_critical_protection 中还有兜底调用。
        try:
            self._purge_stale_kernel_state()
        except Exception as e:
            logger.debug(f'启动自愈清理驱动残留失败（非关键）: {e}')

        # 初始化关键文件列表（轻量级，不读文件内容）
        self._init_critical_files()

        # 启动 watchdog 监控项目目录
        if HAS_WATCHDOG and self._project_root:
            try:
                self._observer = Observer()
                self._handler = _SelfFileHandler(self)
                self._observer.schedule(
                    self._handler, self._project_root, recursive=True
                )
                self._observer.start()
                logger.info(f'watchdog 已启动，监控项目目录: {self._project_root}')
            except Exception as e:
                logger.error(f'启动 watchdog 失败: {e}')
                self._observer = None
        else:
            logger.warning('watchdog 不可用，文件实时监控降级为定期轮询')

        # 启动监控线程（基线建立和所有检查都在子线程执行，不阻塞主线程）
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name='SelfProtection'
        )
        self._monitor_thread.start()

        with self._stats_lock:
            self._stats['started_at'] = time.time()

        self._add_event('system', 'info', '自我保护引擎已启动')
        logger.info('自我保护引擎已启动')

        return True

    def stop(self) -> bool:
        if not self._running:
            return True
        self._stop_event.set()
        self._running = False

        # 先取消关键进程保护 — 否则正常退出也会触发蓝屏
        self._disable_critical_protection()


        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=3)
            except Exception:
                pass
            self._observer = None
            self._handler = None

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=3)
        self._monitor_thread = None

        self._add_event('system', 'info', '自我保护引擎已停止')
        logger.info('自我保护引擎已停止')
        return True

    # ---- 监控主循环 ----

    def _monitor_loop(self):
        """主监控循环

        线程启动后立即激活进程保护（内核驱动优先 + DACL 兜底），
        确保首次安装后无需重启或手动开关即可应用驱动；
        随后延迟 8 秒（等 UI 和其他防护模块完全初始化）建立基线，
        之后定期执行：
        1. 调试器检测
        2. 注入检测
        3. 文件完整性检查
        4. 进程保护重试（两级保护均未激活时）

        当 self._enabled 为 False 时，监控线程继续运行但跳过所有检查
        （与"关闭自保护"的当前逻辑一致：保留运行状态，不报告威胁）。
        """
        # 立即激活进程保护（不等延迟）—— 首次安装后驱动即刻生效
        if self._enabled:
            try:
                self._enable_critical_protection()
            except Exception as e:
                logger.error(f'启动时激活进程保护失败: {e}')

        # 启动延迟
        self._stop_event.wait(8)
        if self._stop_event.is_set():
            return

        # 建立基线
        try:
            self._build_baselines()
        except Exception as e:
            logger.error(f'建立自我保护基线失败: {e}')

        last_integrity_check = 0
        last_antidebug_check = 0
        last_backup_time = 0
        last_protection_retry = 0
        last_related_protect = 0

        while not self._stop_event.is_set():
            try:
                # 短间隔轮询开关状态（关闭时不执行任何检查）
                self._stop_event.wait(_MONITOR_INTERVAL)
                if self._stop_event.is_set():
                    break

                # 关闭状态下：不执行任何检查，保持静默（与当前关闭状态一致）
                if not self._enabled:
                    continue

                now = time.time()

                # 进程保护重试：启用中但两级保护均未激活
                # （如首次安装时驱动服务未就绪、SCM 短暂繁忙等瞬时失败）
                if (not self._kernel_protection_active
                        and not self._dacl_protection_active
                        and now - last_protection_retry >= _PROTECTION_RETRY_INTERVAL):
                    try:
                        self._enable_critical_protection()
                    except Exception as e:
                        logger.debug(f'重试激活进程保护失败: {e}')
                    last_protection_retry = now

                # 进程树保护补齐：worker/MLWorker 可能在启动后才出现，
                # 周期性重扫把新进程也纳入 DACL / 驱动保护集（幂等）
                if (self._kernel_protection_active or self._dacl_protection_active) \
                        and now - last_related_protect >= _PROTECTION_RETRY_INTERVAL:
                    try:
                        self._protect_related_processes()
                    except Exception as e:
                        logger.debug(f'进程树保护补齐失败: {e}')
                    last_related_protect = now

                # 调试器检测（定期）
                if now - last_antidebug_check >= _ANTIDEBUG_CHECK_INTERVAL:
                    self._check_debugger()
                    last_antidebug_check = now

                # 注入检测（每次循环都检查，轻量级）
                self._check_injection()

                # 文件完整性检查（定期）
                if now - last_integrity_check >= _INTEGRITY_CHECK_INTERVAL:
                    self._run_integrity_check()
                    last_integrity_check = now

                # 自动备份（定期）
                if now - last_backup_time >= _BACKUP_INTERVAL:
                    try:
                        self._perform_backup()
                    except Exception as e:
                        logger.debug(f'定期自动备份失败: {e}')
                    last_backup_time = now

                with self._stats_lock:
                    self._stats['check_count'] += 1

            except Exception as e:
                logger.error(f'自我保护监控循环异常: {e}')
                self._stop_event.wait(2)

    # ---- 调试器检测 ----

    def _check_debugger(self):
        """检测调试器附加

        使用三种方法组合检测，连续命中 _DEBUG_CONFIRM_THRESHOLD 次才报警，
        避免偶发误报。
        """
        detected = False

        # 方法 1：IsDebuggerPresent
        if _is_debugger_present():
            detected = True

        # 方法 2：CheckRemoteDebuggerPresent
        if not detected and _check_remote_debugger():
            detected = True

        # 方法 3：NtQueryInformationProcess（调试端口）
        if not detected and _check_debugger_by_port():
            detected = True

        if detected:
            self._debug_hit_count += 1
            if self._debug_hit_count >= _DEBUG_CONFIRM_THRESHOLD and not self._debug_reported:
                self._debug_reported = True
                self._report_threat({
                    'type': 'debugger_detected',
                    'detail': f'检测到调试器附加（连续 {self._debug_hit_count} 次命中）',
                    'pid': self._self_pid,
                    'path': self._self_exe,
                })
        else:
            # 调试器消失后重置计数和报警标志
            if self._debug_hit_count > 0:
                self._debug_hit_count = 0
                self._debug_reported = False

    # ---- 注入检测 ----

    def _check_injection(self):
        """检测远程线程注入和 DLL 注入

        三层检测：
        1. 线程数异常增长（原有逻辑，快速检测）
        2. 远程线程注入：通过 NtQueryInformationThread 获取线程起始地址，
           检查是否在已加载模块范围内（精确检测 CreateRemoteThread）
        3. DLL 注入：通过 EnumProcessModulesEx 枚举加载的模块，
           检查是否有从可疑路径加载的 DLL
        """
        # 检测 1：线程数异常增长（轻量级，每次循环执行）
        if HAS_PSUTIL:
            self._check_thread_count_anomaly()

        # 检测 2 & 3：远程线程注入和 DLL 注入（较重，定期执行）
        now = time.time()
        if now - getattr(self, '_last_injection_scan', 0) >= _INJECTION_SCAN_INTERVAL:
            self._last_injection_scan = now
            self._check_remote_thread_injection()
            self._check_dll_injection()

    def _check_thread_count_anomaly(self):
        """检测线程数异常增长（原有逻辑）"""
        if not HAS_PSUTIL:
            return

        try:
            proc = psutil.Process(self._self_pid)

            # 获取线程数
            threads = proc.num_threads()

            # 线程数突然翻倍可能意味着注入
            with self._stats_lock:
                last_threads = self._stats.get('last_thread_count', threads)

            if last_threads > 0 and threads > last_threads * 3 and threads > 20:
                self._report_threat({
                    'type': 'injection_detected',
                    'detail': f'线程数异常增长: {last_threads} -> {threads}',
                    'pid': self._self_pid,
                    'path': self._self_exe,
                })

            with self._stats_lock:
                self._stats['last_thread_count'] = threads

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logger.debug(f'线程数检测异常: {e}')

    def _check_remote_thread_injection(self):
        """检测远程线程注入

        通过对比线程起始地址与已加载模块地址范围，
        精确检测 CreateRemoteThread 注入。
        如果某线程的起始地址不在任何已加载模块内，则疑似注入。
        """
        try:
            from engine.etw_monitor import detect_remote_thread_injection
            suspicious = detect_remote_thread_injection(self._self_pid)

            if suspicious:
                detail = f'检测到 {len(suspicious)} 个可疑线程（起始地址不在已加载模块内）'
                for s in suspicious[:3]:
                    detail += f'\n  TID={s["thread_id"]} addr={s["start_address"]}'
                self._report_threat({
                    'type': 'remote_thread_injection',
                    'detail': detail,
                    'pid': self._self_pid,
                    'path': self._self_exe,
                })
                logger.warning(f'[自保护] 远程线程注入检测: {len(suspicious)} 个可疑线程')
        except ImportError:
            logger.debug('etw_monitor 模块不可用，跳过远程线程注入检测')
        except Exception as e:
            logger.debug(f'远程线程注入检测异常: {e}')

    def _check_dll_injection(self):
        """检测 DLL 注入

        通过枚举自身进程加载的模块，检查是否有从可疑路径
        （临时目录、回收站等）加载的 DLL。
        """
        try:
            from engine.etw_monitor import detect_dll_injection
            # 把 PSLS 自身安装/项目目录及其 _internal 加入可信路径，避免把自身
            # 依赖的模块（如 MLWorker.exe、打包内置的 .exe/.dll/.pyd 等）误判为
            # "非 DLL 模块疑似注入"。真实注入通常来自 temp/下载/未知路径，
            # 这些仍会被上面的 suspicious_keywords 覆盖。
            trust = {
                '\\windows\\', '\\program files\\', '\\program files (x86)\\',
            }
            try:
                self_exe_dir = os.path.dirname(os.path.abspath(self._self_exe)) if self._self_exe else ''
                if self_exe_dir:
                    trust.add(self_exe_dir.lower().rstrip('\\/') + '\\')
                # 打包环境：_internal 目录在可执行文件旁
                if self_exe_dir:
                    trust.add(os.path.join(self_exe_dir, '_internal').lower().rstrip('\\/') + '\\')
                # 源码环境：项目根目录及其子目录
                if self._project_root:
                    trust.add(os.path.normpath(self._project_root).lower().rstrip('\\/') + '\\')
                # Sandboxie 组件目录：SbieDll.dll 会注入盒内进程，防御性放行
                for _sb in (r'c:\program files\sandboxie-plus\\',
                            r'c:\program files\sandboxie\\'):
                    trust.add(_sb)
                try:
                    from engine.sandbox_analyzer import detect_sandboxie_backend
                    _sbd = (detect_sandboxie_backend() or {}).get('dir') or ''
                    if _sbd:
                        trust.add(os.path.normcase(_sbd).rstrip('\\/') + '\\')
                except Exception:
                    pass
            except Exception:
                pass
            suspicious = detect_dll_injection(self._self_pid, trusted_paths=trust)

            if suspicious:
                detail = f'检测到 {len(suspicious)} 个可疑模块'
                for s in suspicious[:5]:
                    detail += f'\n  {s["name"]}: {s["reason"]}'
                self._report_threat({
                    'type': 'dll_injection',
                    'detail': detail,
                    'pid': self._self_pid,
                    'path': self._self_exe,
                })
                logger.warning(f'[自保护] DLL注入检测: {len(suspicious)} 个可疑模块')
        except ImportError:
            logger.debug('etw_monitor 模块不可用，跳过 DLL 注入检测')
        except Exception as e:
            logger.debug(f'DLL 注入检测异常: {e}')

    # ---- 文件完整性检查 ----

    def _run_integrity_check(self):
        """对所有关键文件执行完整性检查"""
        if not self._baselines_built:
            return

        with self._baseline_lock:
            files_to_check = list(self._file_baselines.items())

        for filepath, baseline in files_to_check:
            try:
                if not os.path.exists(filepath):
                    # 文件被删除
                    self._report_threat({
                        'type': 'self_file_deleted',
                        'detail': f'关键文件被删除: {filepath}',
                        'path': filepath,
                    })
                    continue

                # 快速检查：文件大小和修改时间
                stat = os.stat(filepath)
                if stat.st_size != baseline['size'] or stat.st_mtime != baseline['mtime']:
                    # 深度检查：哈希校验
                    current_hash = self._compute_file_hash(filepath)
                    if current_hash != baseline['hash']:
                        # 先尝试自动回滚
                        rollback_ok = self._rollback_file(filepath, baseline['hash'])

                        if rollback_ok:
                            self._report_threat({
                                'type': 'self_file_tampered_rollback',
                                'detail': f'关键文件被篡改已自动恢复: {os.path.basename(filepath)}',
                                'path': filepath,
                            })
                            # 回滚成功后恢复基线（用备份的哈希，即 baseline['hash']）
                            try:
                                new_stat = os.stat(filepath)
                                with self._baseline_lock:
                                    self._file_baselines[filepath] = {
                                        'hash': baseline['hash'],
                                        'size': new_stat.st_size,
                                        'mtime': new_stat.st_mtime,
                                    }
                            except Exception:
                                pass
                        else:
                            self._report_threat({
                                'type': 'self_file_tampered',
                                'detail': f'关键文件被篡改且恢复失败: {filepath}',
                                'path': filepath,
                            })
                            # 回滚失败，更新基线避免重复报警
                            with self._baseline_lock:
                                self._file_baselines[filepath] = {
                                    'hash': current_hash,
                                    'size': stat.st_size,
                                    'mtime': stat.st_mtime,
                                }

            except Exception as e:
                logger.debug(f'完整性检查失败 {filepath}: {e}')

        with self._stats_lock:
            self._stats['integrity_checks'] += 1

    # ---- watchdog 文件事件处理 ----

    def _on_self_file_event(self, file_path: str, event_type: str):
        """处理 watchdog 文件事件

        仅对关键文件变更做响应，非关键文件忽略。
        使用防抖机制，避免文件被频繁修改时的大量报警。

        当自保护关闭时，watchdog 事件会被忽略（保持关闭状态下的逻辑）。
        """
        # 关闭状态下：watchdog 事件不再处理（避免开发时频繁修改源码导致误报）
        if not self._enabled:
            return

        file_path_lower = file_path.lower()

        # 检查是否为受保护的关键文件
        is_critical = False
        for critical in self._critical_files:
            if file_path_lower == critical or file_path_lower.endswith(critical):
                is_critical = True
                break

        if not is_critical:
            return

        # 删除事件：尝试从备份恢复
        if event_type == 'deleted':
            # 尝试自动回滚
            baseline = self._file_baselines.get(file_path_lower)
            baseline_hash = baseline.get('hash') if baseline else None
            rollback_ok = self._rollback_file(file_path_lower, baseline_hash)
            if rollback_ok:
                self._report_threat({
                    'type': 'self_file_deleted_rollback',
                    'detail': f'关键文件被删除已自动恢复: {os.path.basename(file_path)}',
                    'path': file_path,
                })
            else:
                self._report_threat({
                    'type': 'self_file_deleted',
                    'detail': f'关键文件被删除且恢复失败: {os.path.basename(file_path)}',
                    'path': file_path,
                })
            return

        # 修改/创建/移动事件：延迟校验哈希（防抖）
        # 不在 watchdog 回调中直接计算哈希（可能文件还在写入中），
        # 而是触发一次完整性检查
        if event_type in ('modified', 'created', 'moved') and self._baselines_built:
            # 标记需要检查，由 _run_integrity_check 在下次循环时处理
            # 这里仅记录事件，不立即报警（避免开发时频繁修改源码导致误报）
            logger.debug(f'关键文件变更: {file_path} ({event_type})')

    # ---- 基线管理 ----

    def update_baseline(self, file_path: str = None):
        """更新指定文件或所有文件的基线

        当 PSLS 自身升级或配置变更后调用，避免误报。

        Args:
            file_path: 指定文件路径，None 则更新所有
        """
        if file_path:
            file_path = os.path.normpath(file_path).lower()
            try:
                if os.path.isfile(file_path):
                    file_hash = self._compute_file_hash(file_path)
                    stat = os.stat(file_path)
                    with self._baseline_lock:
                        self._file_baselines[file_path] = {
                            'hash': file_hash,
                            'size': stat.st_size,
                            'mtime': stat.st_mtime,
                        }
                    logger.info(f'已更新基线: {file_path}')
            except Exception as e:
                logger.error(f'更新基线失败 {file_path}: {e}')
        else:
            self._build_baselines()

    def get_protected_files(self) -> List[str]:
        """获取受保护文件列表"""
        with self._baseline_lock:
            return list(self._file_baselines.keys())

    # ---- 自动备份与回滚 ----

    def _perform_backup(self):
        """执行一次关键文件备份

        备份策略：
        1. 将所有关键文件复制到 backup/ 目录，保持相对路径结构
        2. 记录 manifest.json（备份时间、文件哈希、版本号）
        3. 滚动备份：保留最近 _MAX_BACKUP_COPIES 个备份，删除最旧的
        4. 仅备份与上次备份不同的文件（增量判断）
        """
        if _DIAG_DISABLE_BACKUP:
            logger.info('自我保护: 自动备份已临时禁用（诊断模式）')
            return
        with self._backup_lock:
            try:
                # 创建带时间戳的备份目录
                timestamp = time.strftime('%Y%m%d_%H%M%S')
                backup_set_dir = os.path.join(self._backup_dir, timestamp)

                manifest = {
                    'timestamp': timestamp,
                    'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'version': 'V26.2.0beta',
                    'files': {},
                }

                backed_up = 0
                skipped = 0

                for filepath in self._critical_files:
                    try:
                        if not os.path.isfile(filepath):
                            skipped += 1
                            continue

                        # 计算相对路径用于备份目录结构
                        try:
                            rel_path = os.path.relpath(filepath, self._project_root)
                        except ValueError:
                            # 不同驱动器无法计算相对路径，使用文件名（放入 backup 根）
                            rel_path = os.path.basename(filepath)

                        # 安全 sanitize：禁止 ../ 向上逃逸到 backup_set_dir 外
                        # os.path.relpath 对项目根外的文件会产生 ../ 前缀，
                        # 这会导致实际备份路径逃出 backup 目录到项目根以上，产生垃圾。
                        # 改用纯文件名放入 external/ 子目录。
                        if '..' in rel_path or os.path.isabs(rel_path):
                            # 外部文件放入 backup 内的 external 子目录，用文件名 + 哈希后缀避免冲突
                            base = os.path.basename(filepath)
                            if '.' not in base:
                                base += '.bin'
                            h = hashlib.sha256(filepath.encode()).hexdigest()[:8]
                            name, ext = os.path.splitext(base)
                            rel_path = os.path.join('external', f"{name}_{h}{ext}")

                        # 备份文件路径（现在一定在 backup_set_dir 子树下）
                        backup_file = os.path.join(backup_set_dir, rel_path)

                        # 创建目标目录
                        os.makedirs(os.path.dirname(backup_file), exist_ok=True)

                        # 复制文件（保留元数据）
                        shutil.copy2(filepath, backup_file)

                        # 记录到 manifest
                        file_hash = self._compute_file_hash(filepath)
                        file_size = os.path.getsize(filepath)
                        manifest['files'][rel_path.replace(os.sep, '/')] = {
                            'hash': file_hash,
                            'size': file_size,
                        }
                        backed_up += 1

                    except Exception as e:
                        logger.debug(f'备份文件失败 {filepath}: {e}')
                        skipped += 1

                # 写入 manifest
                os.makedirs(backup_set_dir, exist_ok=True)
                manifest_path = os.path.join(backup_set_dir, _BACKUP_MANIFEST_FILE)
                with open(manifest_path, 'w', encoding='utf-8') as f:
                    json.dump(manifest, f, ensure_ascii=False, indent=2)

                self._last_backup_time = time.time()

                # 清理旧备份（滚动保留）
                self._cleanup_old_backups()

                self._add_event('backup', 'success',
                                f'自动备份完成: {backed_up} 个文件（跳过 {skipped} 个）')
                logger.info(f'自我保护: 自动备份完成，{backed_up} 个文件，跳过 {skipped} 个')

            except Exception as e:
                logger.error(f'自动备份失败: {e}')
                self._add_event('backup', 'error', f'自动备份失败: {e}')

    def _cleanup_old_backups(self):
        """清理旧备份，仅保留最近 _MAX_BACKUP_COPIES 个"""
        try:
            if not os.path.isdir(self._backup_dir):
                return

            # 列出所有备份目录（格式为 YYYYMMDD_HHMMSS）
            backup_sets = []
            for name in os.listdir(self._backup_dir):
                full_path = os.path.join(self._backup_dir, name)
                if os.path.isdir(full_path) and name != '__pycache__':
                    backup_sets.append((name, full_path))

            # 按名称排序（时间戳格式，字符串排序等同时间排序）
            backup_sets.sort(key=lambda x: x[0])

            # 删除超出的旧备份
            while len(backup_sets) > _MAX_BACKUP_COPIES:
                oldest_name, oldest_path = backup_sets.pop(0)
                try:
                    shutil.rmtree(oldest_path, ignore_errors=True)
                    logger.debug(f'已删除旧备份: {oldest_name}')
                except Exception as e:
                    logger.debug(f'删除旧备份失败 {oldest_name}: {e}')

        except Exception as e:
            logger.debug(f'清理旧备份异常: {e}')

    def _rollback_file(self, filepath: str, expected_hash: str = None) -> bool:
        """从备份恢复单个被篡改/删除的文件

        Args:
            filepath: 被篡改/删除的文件路径（绝对路径）
            expected_hash: 期望恢复到的哈希值（用于验证备份完整性）

        Returns:
            True 恢复成功，False 恢复失败
        """
        with self._backup_lock:
            try:
                # 查找最新的有效备份
                backup_file = self._find_latest_backup(filepath)
                if not backup_file:
                    logger.warning(f'无法回滚 {filepath}: 未找到备份')
                    return False

                # 验证备份文件完整性
                if expected_hash:
                    backup_hash = self._compute_file_hash(backup_file)
                    if backup_hash != expected_hash:
                        # 备份本身也被篡改，尝试更早的备份
                        logger.warning(f'最新备份已被篡改 {filepath}，尝试更早备份...')
                        backup_file = self._find_latest_backup(filepath, skip_first=True)
                        if backup_file:
                            backup_hash = self._compute_file_hash(backup_file)
                            if backup_hash != expected_hash:
                                logger.error(f'所有备份均不可信，回滚失败: {filepath}')
                                return False
                        else:
                            logger.error(f'无更早备份可用，回滚失败: {filepath}')
                            return False

                # 临时解除只读属性
                _set_file_normal(filepath)

                # 恢复文件（带重试）
                for attempt in range(_ROLLBACK_MAX_RETRIES):
                    try:
                        shutil.copy2(backup_file, filepath)
                        # 验证恢复后的文件
                        restored_hash = self._compute_file_hash(filepath)
                        if expected_hash and restored_hash != expected_hash:
                            if attempt < _ROLLBACK_MAX_RETRIES - 1:
                                logger.debug(f'回滚验证失败，重试 {attempt + 1}/{_ROLLBACK_MAX_RETRIES}')
                                continue
                            logger.error(f'回滚后哈希不匹配: {filepath}')
                            return False

                        # 恢复只读属性
                        _set_file_readonly(filepath)

                        logger.info(f'自动回滚成功: {os.path.basename(filepath)}')
                        self._add_event('rollback', 'success',
                                        f'自动恢复文件: {os.path.basename(filepath)}')
                        return True

                    except Exception as e:
                        if attempt < _ROLLBACK_MAX_RETRIES - 1:
                            time.sleep(0.5)
                            continue
                        logger.error(f'回滚写入失败 {filepath}: {e}')
                        return False

                return False

            except Exception as e:
                logger.error(f'回滚异常 {filepath}: {e}')
                return False

    def _find_latest_backup(self, filepath: str, skip_first: bool = False) -> Optional[str]:
        """查找文件在最新备份中的路径

        Args:
            filepath: 原始文件绝对路径
            skip_first: 是否跳过最新的备份（用于降级到更早备份）

        Returns:
            备份文件的绝对路径，未找到返回 None
        """
        try:
            if not os.path.isdir(self._backup_dir):
                return None

            # 计算相对路径
            try:
                rel_path = os.path.relpath(filepath, self._project_root)
            except ValueError:
                rel_path = os.path.basename(filepath)

            # 列出所有备份目录，按时间倒序
            backup_sets = []
            for name in os.listdir(self._backup_dir):
                full_path = os.path.join(self._backup_dir, name)
                if os.path.isdir(full_path) and name != '__pycache__':
                    backup_sets.append((name, full_path))

            backup_sets.sort(key=lambda x: x[0], reverse=True)

            if skip_first and backup_sets:
                backup_sets = backup_sets[1:]

            # 在每个备份目录中查找目标文件
            for _name, set_path in backup_sets:
                candidate = os.path.join(set_path, rel_path)
                if os.path.isfile(candidate):
                    # 验证 manifest 中是否存在此文件记录
                    manifest_path = os.path.join(set_path, _BACKUP_MANIFEST_FILE)
                    if os.path.isfile(manifest_path):
                        try:
                            with open(manifest_path, 'r', encoding='utf-8') as f:
                                manifest = json.load(f)
                            rel_key = rel_path.replace(os.sep, '/')
                            if rel_key in manifest.get('files', {}):
                                return candidate
                        except Exception:
                            pass
                    # 无 manifest 但文件存在，仍返回
                    return candidate

            return None

        except Exception:
            return None

    def get_status(self) -> dict:
        """获取自我保护状态摘要"""
        # 统计备份数量
        backup_count = 0
        try:
            if os.path.isdir(self._backup_dir):
                backup_count = sum(
                    1 for name in os.listdir(self._backup_dir)
                    if os.path.isdir(os.path.join(self._backup_dir, name))
                    and name != '__pycache__'
                )
        except Exception:
            pass

        return {
            'running': self._running,
            'enabled': self._enabled,
            'self_pid': self._self_pid,
            'self_exe': self._self_exe,
            'files_monitored': len(self._file_baselines),
            'debugger_detected': self._debug_reported,
            'backup_count': backup_count,
            'last_backup_time': self._last_backup_time,
            'critical_process': self._kernel_protection_active or self._dacl_protection_active,
            'dacl_protection': self._dacl_protection_active,
            'kernel_protection': self._kernel_protection_active,
            'stats': self.get_stats(),
            'events': self.get_recent_events(10),
        }

    # ==================================================================
    # 内核驱动进程保护 — 任务管理器拒绝访问（不蓝屏）
    # ==================================================================

    def _purge_stale_kernel_state(self):
        """启动自愈：清除上次异常退出（强杀/崩溃）残留的驱动保护状态

        原因：PSLS 被强杀时 _deactivate_kernel_protection 不会执行，驱动内
        g_ProtectedDir（安装目录写保护）与 g_PslsProcess / g_Driver.PslsPid
        会保留旧值。新启动的 PSLS 进程 PID 变化后，驱动仍只放行旧 PID，
        新进程写安装目录文件会被 minifilter 以 STATUS_ACCESS_DENIED 拒绝
        —— 用户表现为"PSLS 重启后一直提示没有权限"。

        同时强制将 enable_proc_terminate 置 0：防止用户态 set_config 默认值
        错误导致该开关被打开，procmon 黑名单含 \\desktop\\ 等路径会把用户
        桌面上的所有程序在创建时直接拦截为 STATUS_ACCESS_DENIED。

        幂等，失败不致命。
        """
        if sys.platform != 'win32':
            return
        try:
            from driver.bridge.psls_driver_bridge import PSLSDriverBridge
            bridge = PSLSDriverBridge()
            if not bridge.is_available:
                return
            # 强制关闭内核 PRE 进程拦截（最危险的残留状态）
            bridge.set_config({'enable_proc_terminate': 0,
                               'enable_image_load': 0,
                               'enable_disk_mon': 0},
                              merge=False)
            bridge.set_psls_pid(0)
            try:
                bridge.clear_protected_dir()
            except Exception:
                pass
            logger.info('已清除残留驱动保护状态（强制关闭危险开关 + pid 清零 + 清保护目录）')
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f'清除驱动残留状态失败（非关键）: {e}')

    def _enable_critical_protection(self):
        """激活进程保护（任务管理器拒绝访问）

        三级降级策略：
        L0: 内核驱动 ObRegisterCallbacks — 最强，但需要驱动签名（通常不生效）
        L1: 用户态 DACL 保护 — 纯用户态，Deny ACE PROCESS_TERMINATE（主用）

        L0 和 L1 至少一个成功即视为"拒绝访问"已生效。

        线程安全：监控线程（启动激活/重试）与用户开关（set_enabled）
        可能并发调用，加锁串行化以避免并发调用驱动 SET_PID。
        """
        with self._protection_lock:
            if not self._enabled:
                # 并发竞态：用户已关闭自保护（关闭发生在激活途中），不再激活
                return
            if self._kernel_protection_active or self._dacl_protection_active:
                return

            # 激活前自愈：清除上次异常退出残留的驱动状态（防"重启无权限"）
            self._purge_stale_kernel_state()

            # L0: 尝试内核驱动（需要驱动签名，通常不生效）
            ok = _try_activate_kernel_protection()
            if ok:
                self._kernel_protection_active = True
                self._add_event('critical', 'enabled',
                                '内核驱动进程保护已激活（任务管理器将拒绝访问）')
                logger.info('内核驱动进程保护已激活 — ObRegisterCallbacks 掩码 PROCESS_TERMINATE')

            # L1: 用户态 DACL 保护（主用方案，纯用户态，不需要驱动）
            if _apply_process_dacl_protection():
                self._dacl_protection_active = True
                self._add_event('critical', 'enabled',
                                'DACL 进程保护已激活（任务管理器将拒绝访问）')
                logger.info('DACL 进程保护已激活 — Deny ACE PROCESS_TERMINATE for Everyone')
            else:
                logger.warning('DACL 保护失败，仅依赖内核保护')
                self._add_event('critical', 'info',
                                'DACL 保护失败，降级为内核保护')

            # L1b: 覆盖整棵 PSLS 进程树（主进程 + worker + MLWorker 等）
            # 任务管理器"结束任务树"会逐个终止子进程；不覆盖辅助进程 = 树被杀。
            try:
                self._protect_related_processes()
            except Exception as e:
                logger.debug(f'进程树保护覆盖失败（非致命）: {e}')

    # ---- 进程树保护（主进程之外的自有进程）----

    def _iter_psls_owned_pids(self) -> list:
        """枚举 PSLS 自身进程树 PID：主进程 → 子孙（worker/MLWorker 等）+ 同名进程。"""
        pids: list = []
        try:
            import psutil
            try:
                me = psutil.Process(os.getpid())
                pids.append(int(me.pid))
                for ch in me.children(recursive=True):
                    try:
                        pids.append(int(ch.pid))
                    except Exception:
                        pass
            except Exception:
                pids.append(os.getpid())
            for p in psutil.process_iter(attrs=['pid', 'name']):
                try:
                    n = (p.info.get('name') or '').lower()
                except Exception:
                    continue
                if 'psls' in n or 'mlworker' in n:
                    pids.append(int(p.info.get('pid') or 0))
        except Exception:
            pids.append(os.getpid())
        out: list = []
        for p in pids:
            if p and p not in out:
                out.append(p)
        return out

    def _protect_related_processes(self) -> list:
        """对主进程之外的 PSLS 自有进程应用保护（DACL + 内核多 PID 追加）。

        - 用户态 DACL：Deny PROCESS_TERMINATE → 任务管理器/任务树对子进程也拒绝访问；
        - 内核：`set_psls_pid(pid)` 追加到驱动保护集（多 PID），剥离 PROCESS_TERMINATE。
        返回成功应用 DACL 的辅助进程 PID 列表。
        """
        pids = self._iter_psls_owned_pids()
        protected: list = []
        for pid in pids:
            if pid == os.getpid():
                continue                       # 主进程已单独保护
            try:
                if _apply_process_dacl_protection(pid):
                    protected.append(pid)
            except Exception as e:
                logger.debug(f'DACL 保护辅助进程 {pid} 失败: {e}')
        # 内核：把每个 pid 追加注册到驱动保护集（ABI 不变，复用 SET_PSLS_PID）
        try:
            from driver.bridge.psls_driver_bridge import PSLSDriverBridge
            bridge = PSLSDriverBridge()
            if bridge.is_available:
                for pid in pids:
                    try:
                        bridge.set_psls_pid(pid)
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f'内核追加保护进程集失败（可能驱动未加载）: {e}')
        self._dacl_related_pids = list(protected)
        if protected:
            logger.info(f'进程树保护已覆盖 {len(protected)} 个辅助进程: {protected}')
        return protected

    def _unprotect_related_processes(self):
        """撤销辅助进程的 DACL 保护（保证正常退出/卸载不被误挡）。"""
        for pid in list(getattr(self, '_dacl_related_pids', []) or []):
            try:
                _remove_process_dacl_protection(pid)
            except Exception:
                pass
        self._dacl_related_pids = []

    def _disable_critical_protection(self):
        """撤销进程保护（允许正常退出）

        顺序:
          1. 内核驱动保护: set_config(enable_psls_protect=0) + set_psls_pid(0)
             → 驱动 ObUnRegisterCallbacks, 不再拦截任何 OpenProcess
          2. DACL 保护: 恢复原始 DACL (主动撤销)
        """
        with self._protection_lock:
            # 先撤销辅助进程保护（含新加入的 worker/MLWorker）
            try:
                self._unprotect_related_processes()
            except Exception as e:
                logger.debug(f'撤销辅助进程保护失败: {e}')
            if self._kernel_protection_active:
                if _deactivate_kernel_protection():
                    self._kernel_protection_active = False
                    logger.info('内核驱动进程保护已停用')
                else:
                    logger.warning('停用内核驱动保护失败，驱动可能仍在拦截')

            if self._dacl_protection_active:
                if _remove_process_dacl_protection():
                    self._dacl_protection_active = False
                    logger.info('DACL 进程保护已撤销，进程可正常退出')
                else:
                    logger.warning('撤销 DACL 保护失败，进程可能无法正常退出')

    # ==================================================================
    # 进程互保 — 防止 taskkill 终止 PSLS
    # ==================================================================
