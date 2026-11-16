# -*- coding: utf-8 -*-
"""
driver_manager.py — PSLS 内核驱动安装/加载管理器

职责:
  1. 定位随应用打包的 PSLS.sys（冻结模式 _internal/driver，开发模式项目根 driver/out）
  2. 通过 Windows 服务控制管理器(Services) 安装内核驱动服务并启动
  3. 写入 minifilter Instances 注册表键（altitude），供文件过滤驱动 FltRegisterFilter 使用
  4. 提供安装/启动/停止/卸载/状态查询，全部优雅降级：
     - 驱动已签名/已加载 → 返回可用
     - 驱动未签名且未开测试签名 → 返回不可用并给出原因（不崩溃）
     - 非 Windows / 无管理员权限 → 返回不可用

与桥接层的关系:
  - 本模块负责"把驱动装上并跑起来"
  - driver.bridge.psls_driver_bridge 负责"打开 \\\\.\\PSLS 设备并通信"
  - 在 self_protection 激活内核保护前，先调用 ensure_driver_loaded()
"""

import ctypes
import os
import sys
from ctypes import wintypes

from utils.logger import get_logger

logger = get_logger('driver_manager')

# ------------------------------------------------------------------------
# 服务控制管理器常量 (advapi32)
# ------------------------------------------------------------------------
SC_MANAGER_CONNECT            = 0x0001
SC_MANAGER_CREATE_SERVICE     = 0x0002
SC_MANAGER_ENUMERATE_SERVICE  = 0x0004
SC_MANAGER_ALL_ACCESS         = 0xF003F

SERVICE_ALL_ACCESS            = 0xF01FF
SERVICE_START                 = 0x0010
SERVICE_STOP                  = 0x0020
SERVICE_QUERY_STATUS          = 0x0004
SERVICE_QUERY_CONFIG          = 0x0001

SERVICE_KERNEL_DRIVER         = 0x00000001
SERVICE_FILE_SYSTEM_DRIVER    = 0x00000002
SERVICE_DEMAND_START          = 0x00000003
SERVICE_AUTO_START            = 0x00000002
SERVICE_ERROR_NORMAL          = 0x00000001
SERVICE_BOOT_START            = 0x00000000

SERVICE_STOPPED               = 0x00000001
SERVICE_START_PENDING         = 0x00000002
SERVICE_STOP_PENDING          = 0x00000003
SERVICE_RUNNING               = 0x00000004

SERVICE_CONTROL_STOP          = 0x00000001

ERROR_SERVICE_EXISTS          = 1073
ERROR_INVALID_IMAGE_HASH      = 577
ERROR_SERVICE_SPECIFIC_ERROR  = 1066
ERROR_ACCESS_DENIED           = 5

SERVICE_NAME = "PSLS"
DRIVER_NT_PATH = r"\SystemRoot\System32\drivers\PSLS.sys"
DEVICE_PATH = r"\\.\PSLS"

# minifilter altitude（与 driver/PSLS.inf 保持一致）
MINIFILTER_ALTITUDE = "370110"
MINIFILTER_INSTANCE = "PSLS Instance"


# ------------------------------------------------------------------------
# ctypes advapi32 声明
# ------------------------------------------------------------------------
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

advapi32.OpenSCManagerW.restype = wintypes.SC_HANDLE
advapi32.OpenSCManagerW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]

advapi32.CreateServiceW.restype = wintypes.SC_HANDLE
advapi32.CreateServiceW.argtypes = [
    wintypes.SC_HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPDWORD,
    wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR]

advapi32.OpenServiceW.restype = wintypes.SC_HANDLE
advapi32.OpenServiceW.argtypes = [
    wintypes.SC_HANDLE, wintypes.LPCWSTR, wintypes.DWORD]

advapi32.StartServiceW.restype = wintypes.BOOL
advapi32.StartServiceW.argtypes = [
    wintypes.SC_HANDLE, wintypes.DWORD, wintypes.LPVOID]

advapi32.ControlService.restype = wintypes.BOOL
advapi32.ControlService.argtypes = [
    wintypes.SC_HANDLE, wintypes.DWORD, wintypes.LPVOID]

advapi32.DeleteService.restype = wintypes.BOOL
advapi32.DeleteService.argtypes = [wintypes.SC_HANDLE]

advapi32.CloseServiceHandle.restype = wintypes.BOOL
advapi32.CloseServiceHandle.argtypes = [wintypes.SC_HANDLE]

advapi32.QueryServiceStatus.restype = wintypes.BOOL
advapi32.QueryServiceStatus.argtypes = [
    wintypes.SC_HANDLE, wintypes.LPVOID]


class _SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ('dwServiceType', wintypes.DWORD),
        ('dwCurrentState', wintypes.DWORD),
        ('dwControlsAccepted', wintypes.DWORD),
        ('dwWin32ExitCode', wintypes.DWORD),
        ('dwServiceSpecificExitCode', wintypes.DWORD),
        ('dwCheckPoint', wintypes.DWORD),
        ('dwWaitHint', wintypes.DWORD),
    ]


# ------------------------------------------------------------------------
# 驱动文件定位
# ------------------------------------------------------------------------

def _resource_dir():
    """返回打包资源根目录（PyInstaller 冻结时指向 _internal）。"""
    if getattr(sys, 'frozen', False):
        base = getattr(sys, '_MEIPASS', None) or os.path.dirname(sys.executable)
        return base
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _file_digest(path: str) -> str:
    """计算文件 MD5（用于比对 Sys32\drivers 与源驱动是否同版本）。"""
    import hashlib
    h = hashlib.md5()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
    except OSError:
        return ''
    return h.hexdigest()


def driver_source_path():
    """返回随应用分发的 PSLS.sys 绝对路径，找不到返回 None。

    开发模式: <项目>/driver/out/PSLS.sys
    冻结模式: <_internal>/driver/PSLS.sys
    """
    base = _resource_dir()
    candidates = [
        os.path.join(base, 'driver', 'PSLS.sys'),
        os.path.join(base, 'driver', 'out', 'PSLS.sys'),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def inf_source_path():
    base = _resource_dir()
    candidates = [
        os.path.join(base, 'driver', 'PSLS.inf'),
        os.path.join(base, 'driver', 'PSLS.inf'),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None  # 兼容: 驱动可独立分发，INF 非必需


# ------------------------------------------------------------------------
# 服务操作
# ------------------------------------------------------------------------

def _query_service_state(handle):
    status = _SERVICE_STATUS()
    if advapi32.QueryServiceStatus(handle, ctypes.byref(status)):
        return status.dwCurrentState
    return None


def _open_scm():
    if sys.platform != 'win32':
        return None
    scm = advapi32.OpenSCManagerW(
        None, None, SC_MANAGER_ALL_ACCESS)
    if not scm:
        return None
    return scm


def is_driver_installed():
    """检查驱动服务是否已注册。"""
    if sys.platform != 'win32':
        return False
    scm = _open_scm()
    if not scm:
        return False
    try:
        svc = advapi32.OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS)
        if svc:
            advapi32.CloseServiceHandle(svc)
            return True
        return False
    finally:
        advapi32.CloseServiceHandle(scm)


def is_driver_running():
    """检查驱动服务是否处于运行状态。"""
    if sys.platform != 'win32':
        return False
    scm = _open_scm()
    if not scm:
        return False
    try:
        svc = advapi32.OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS)
        if not svc:
            return False
        try:
            return _query_service_state(svc) == SERVICE_RUNNING
        finally:
            advapi32.CloseServiceHandle(svc)
    finally:
        advapi32.CloseServiceHandle(scm)


def _write_minifilter_registry():
    """写入 minifilter Instances 注册表键（altitude），供 FltRegisterFilter 使用。

    路径: HKLM\SYSTEM\CurrentControlSet\Services\PSLS\Instances\PSLS Instance
       Altitude = "370110"
       Flags    = 0x0
    """
    try:
        import winreg
        key = winreg.CreateKey(
            winreg.HKEY_LOCAL_MACHINE,
            r'SYSTEM\CurrentControlSet\Services\PSLS\Instances\%s' % MINIFILTER_INSTANCE)
        winreg.SetValueEx(key, 'Altitude', 0, winreg.REG_SZ, MINIFILTER_ALTITUDE)
        winreg.SetValueEx(key, 'Flags', 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)

        default_key = winreg.CreateKey(
            winreg.HKEY_LOCAL_MACHINE,
            r'SYSTEM\CurrentControlSet\Services\PSLS\Instances')
        winreg.SetValueEx(default_key, 'DefaultInstance', 0,
                          winreg.REG_SZ, MINIFILTER_INSTANCE)
        winreg.CloseKey(default_key)
        return True
    except Exception as e:
        logger.debug(f'写入 minifilter 注册表失败（非致命）: {e}')
        return False


def install_driver(system_start: bool = False) -> dict:
    """安装并启动内核驱动服务。

    返回 dict:
      { 'ok': bool, 'reason': str }
    """
    sys_path = driver_source_path()
    if not sys_path:
        return {'ok': False, 'reason': '未找到随应用分发的 PSLS.sys'}

    if sys.platform != 'win32':
        return {'ok': False, 'reason': '非 Windows 平台'}

    # 若已安装且运行，直接返回
    if is_driver_running():
        return {'ok': True, 'reason': 'already_running'}

    # 1. 复制驱动到 System32\drivers
    #    复制需要管理员权限；若目标已存在与源版本一致的驱动文件（哈希相同），
    #    跳过复制直接启动服务，避免非管理员/无写入权限时复制失败阻塞加载。
    drivers_dir = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                               'System32', 'drivers')
    dest = os.path.join(drivers_dir, 'PSLS.sys')
    need_copy = os.path.abspath(sys_path).lower() != dest.lower()
    if need_copy and os.path.isfile(dest):
        # 目标已存在：比对哈希，一致则无需覆盖
        try:
            same = _file_digest(dest) == _file_digest(sys_path)
        except Exception:
            same = False
        if same:
            need_copy = False
    if need_copy:
        try:
            import shutil
            shutil.copy2(sys_path, dest)
        except Exception as e:
            # 复制失败不再一票否决：若目标已存在旧版本，仍尝试用旧驱动启动
            # （真实首装有管理员权限会复制成功；无权限时降级为旧版本驱动）
            if not os.path.isfile(dest):
                return {'ok': False, 'reason': f'驱动复制失败: {e}'}
            logger.warning(f'驱动复制失败({e})，将使用已存在的旧版 PSLS.sys')

    # 写入 minifilter 实例键（尽力而为，失败不阻塞驱动加载）
    _write_minifilter_registry()

    scm = _open_scm()
    if not scm:
        return {'ok': False, 'reason': '打开服务管理器失败（需要管理员权限）'}

    try:
        svc = advapi32.OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS)
        if not svc:
            # 创建内核驱动服务（DEMAND_START，避免开机加载失败拖慢系统）
            start_type = SERVICE_AUTO_START if system_start else SERVICE_DEMAND_START
            svc = advapi32.CreateServiceW(
                scm, SERVICE_NAME, 'PSLS Security Driver',
                SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, start_type,
                SERVICE_ERROR_NORMAL, DRIVER_NT_PATH, None, None,
                None, None, None)
            if not svc:
                err = ctypes.get_last_error()
                if err == ERROR_SERVICE_EXISTS:
                    svc = advapi32.OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS)
                else:
                    return {'ok': False, 'reason': f'创建驱动服务失败 (err={err})'}
        if not svc:
            return {'ok': False, 'reason': '打开驱动服务失败'}

        try:
            # 2. 启动服务
            if not advapi32.StartServiceW(svc, 0, None):
                err = ctypes.get_last_error()
                # 已运行视为成功
                if _query_service_state(svc) == SERVICE_RUNNING:
                    return {'ok': True, 'reason': 'already_running'}
                if err == ERROR_INVALID_IMAGE_HASH:
                    return {'ok': False,
                            'reason': '驱动未签名，需开启测试签名模式（bcdedit /set testsigning on）'}
                if err == 4551 or err == 0x11C7:
                    return {'ok': False,
                            'reason': '驱动被系统安全策略拦截（内存完整性/HVCI 或应用控制策略），'
                                      '请管理员运行 PSLS_签名后_管理员配置.ps1 关闭内存完整性并信任签名'}
                if err == ERROR_ACCESS_DENIED:
                    return {'ok': False, 'reason': '启动驱动服务被拒绝（缺少管理员权限）'}
                return {'ok': False, 'reason': f'启动驱动服务失败 (err={err})'}
            return {'ok': True, 'reason': 'started'}
        finally:
            advapi32.CloseServiceHandle(svc)
    finally:
        advapi32.CloseServiceHandle(scm)


def uninstall_driver() -> dict:
    """停止并删除驱动服务。"""
    if sys.platform != 'win32':
        return {'ok': False, 'reason': '非 Windows 平台'}
    scm = _open_scm()
    if not scm:
        return {'ok': False, 'reason': '打开服务管理器失败'}
    try:
        svc = advapi32.OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS)
        if not svc:
            return {'ok': True, 'reason': 'not_installed'}
        try:
            # 停止
            status = _SERVICE_STATUS()
            if _query_service_state(svc) == SERVICE_RUNNING:
                advapi32.ControlService(svc, SERVICE_CONTROL_STOP, ctypes.byref(status))
            # 删除
            advapi32.DeleteService(svc)
            return {'ok': True, 'reason': 'removed'}
        finally:
            advapi32.CloseServiceHandle(svc)
    finally:
        advapi32.CloseServiceHandle(scm)


def get_driver_status() -> dict:
    """返回驱动安装/运行状态。"""
    return {
        'installed': is_driver_installed(),
        'running': is_driver_running(),
        'source_path': driver_source_path(),
    }


def ensure_driver_loaded() -> bool:
    """确保驱动已安装并运行；失败时优雅降级返回 False。

    供 self_protection 在激活内核驱动保护前调用。
    """
    if sys.platform != 'win32':
        return False
    try:
        if is_driver_running():
            return True
        result = install_driver()
        if result.get('ok') and is_driver_running():
            logger.info(f'内核驱动已加载: {result.get("reason")}')
            return True
        logger.warning(f'内核驱动加载失败: {result.get("reason")}')
        return False
    except Exception as e:
        logger.debug(f'加载内核驱动异常: {e}')
        return False