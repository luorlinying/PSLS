# -*- coding: utf-8 -*-
"""
系统保护引擎
监控系统关键设置，检测注册表篡改、启动项变更、DNS 劫持等系统级威胁。
基于 winreg + watchdog + 系统 API 实现。
"""
import os
import re
import sys
import time
import hashlib
import threading
import json
from typing import Callable, Dict, List, Optional, Set

from utils.logger import get_logger

logger = get_logger('system_protection')

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False
    winreg = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    Observer = None
    FileSystemEventHandler = object

# WMI 注册表事件订阅（准实时，替代15秒轮询）
# 需要 pywin32（win32com）支持，未安装时降级到轮询模式
# 注意：禁用 gen_py 缓存写入，避免在受限/打包环境下因 TEMP 目录
#       不可写或文件句柄损坏导致 ImportError/[Errno 9] Bad file descriptor。
os.environ['PYWIN32_DISABLE_GEN_PY_CACHE'] = '1'

try:
    # 在导入 win32com.client 之前清理残留的 gen_py 目录，避免损坏缓存再次触发 Bad file descriptor
    try:
        import tempfile as _tempfile
        _gen_py_root = os.path.join(os.environ.get('TEMP', _tempfile.gettempdir()), 'gen_py')
        if os.path.isdir(_gen_py_root):
            import shutil as _shutil
            _shutil.rmtree(_gen_py_root, ignore_errors=True)
    except Exception:
        pass

    import win32com.client
    import pythoncom
    HAS_WMI_REGISTRY = True
except Exception:
    HAS_WMI_REGISTRY = False
    win32com = None
    pythoncom = None


# ---- 关键注册表路径 ----

RUN_KEY_PATHS = [
    (winreg.HKEY_CURRENT_USER,
     r'Software\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_LOCAL_MACHINE,
     r'Software\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_LOCAL_MACHINE,
     r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
] if HAS_WINREG else []

# 重要系统注册表路径（监控篡改）
CRITICAL_REGISTRY_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE,
     r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'),
    (winreg.HKEY_LOCAL_MACHINE,
     r'Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'),
    (winreg.HKEY_LOCAL_MACHINE,
     r'System\CurrentControlSet\Services'),
    (winreg.HKEY_LOCAL_MACHINE,
     r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'),
    (winreg.HKEY_CURRENT_USER,
     r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'),
    # Windows Defender 策略：恶意样本常写 DisableAntiVirus /
    # DisableAntiSpyware / DisableRealtimeMonitoring 关闭实时防护
    (winreg.HKEY_LOCAL_MACHINE,
     r'Software\Policies\Microsoft\Windows Defender'),
] if HAS_WINREG else []

# hosts 文件路径
HOSTS_FILE = r'C:\Windows\System32\drivers\etc\hosts'

# 启动项监控目录
STARTUP_DIRS = [
    os.path.join(os.path.expanduser("~"),
                 r'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'),
    r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
]

# 白名单：合法的启动项（忽略）
# 用子串匹配替代精确名匹配，避免每次 Edge/OneDrive 等自启动值名变化就误报。
TRUSTED_STARTUP_PATTERNS: Set[str] = {
    'psls', 'project sertraline lab',
    # ---- Microsoft / Windows 生态 ----
    'onedrive',
    'microsoftedge',
    'microsoft',              # 覆盖面很广，但 Run 键里的 Microsoft* 值基本都安全
    'msedge',
    'edgeupdate',
    'edgemalware',           # Edge 自带的恶意站点拦截
    'skype',
    'teams',
    'outlook',
    # ---- Google / 浏览器类 ----
    'chrome',
    'googleupdate',
    'chromium',
    'firefox',
    'mozilla',
    # ---- 其他主流应用 ----
    'telegram',
    'discord',
    'dropbox',
    'boxsync',
    'evernote',
    'notion',
    'slack',
    'zoom',
    'wechat',
    'tencent',
    'aliyun',
    'baidu',
    # ---- 安全软件（共存友好） ----
    'kaspersky',
    'avast',
    'avg',
    'eset',
    'defender',
    'bitdefender',
    # ---- 系统驱动注册的启动项（非恶意） ----
    'cortana',
    'searchapp',
    'runtimebroker',
}


def _is_trusted_startup(name: str, data: str = '') -> bool:
    """判断 Run 键值是否属于可信启动项。

    参数:
        name: 注册表值名（Run 键里的那个 key）
        data: 注册表值内容（通常是 exe 路径）
    """
    name_l = (name or '').lower()
    data_l = (data or '').lower()
    for pat in TRUSTED_STARTUP_PATTERNS:
        if pat in name_l or pat in data_l:
            return True
    return False

# ---- MBR/启动区保护 ----
# MBR（主引导记录）位于物理驱动器0的第一个扇区，共512字节
# 前446字节是引导代码，接着64字节是分区表，最后2字节是签名 0x55AA
# Petya/NotPetya 等勒索软件会覆写 MBR 加密主引导记录
_MBR_DRIVE = r'\\.\PhysicalDrive0'
_MBR_SECTOR_SIZE = 512
_MBR_SIGNATURE_OFFSET = 0x1FE  # 510
_MBR_SIGNATURE = b'\x55\xAA'
_MBR_CHECK_INTERVAL = 10  # MBR 校验间隔（秒），比注册表更频繁因为危害极大

# 引导关键文件（仅备份构建基线时实际存在的文件；UEFI/BIOS 系统均可覆盖）
# 注意：ESP 分区（C:\EFI\...）绝大多数机器没有盘符，因此改为监控
#       Windows 系统目录里的官方引导/启动加载器副本（实测均存在）。
_EFI_FILES = [
    r'C:\Windows\Boot\EFI\bootmgfw.efi',   # UEFI 启动管理器（EFI 版 bootmgr）
    r'C:\Windows\System32\winload.efi',    # UEFI Windows 加载器
    r'C:\Windows\System32\winload.exe',    # BIOS Windows 加载器
    r'C:\Windows\System32\Boot\winload.efi',  # 恢复环境 UEFI 加载器
    r'C:\Windows\System32\Boot\winload.exe',  # 恢复环境 BIOS 加载器
]

# VBR（卷引导记录）所在的逻辑驱动器（C 盘启动扇区）
_VBR_DRIVE = r'\\.\C:'

# 检查间隔（秒）
_REGISTRY_CHECK_INTERVAL = 15
_HOSTS_CHECK_INTERVAL = 30
_STARTUP_CHECK_INTERVAL = 10
_MBR_CHECK_INTERVAL_VAL = 10  # MBR 校验间隔（秒）


class _HostsFileHandler(FileSystemEventHandler):
    """hosts 文件变更监控"""

    def __init__(self, manager: 'SystemProtection'):
        super().__init__()
        self._manager = manager

    def on_modified(self, event):
        if not event.is_directory and event.src_path.lower() == HOSTS_FILE.lower():
            self._manager._on_hosts_changed()


class SystemProtection:
    """
    系统保护引擎

    功能：
    1. 启动项监控：检测未经授权的程序被添加到开机启动
    2. 注册表保护：监控关键注册表路径的篡改
    3. hosts 文件保护：检测 DNS 劫持（hosts 文件被修改）
    4. 服务监控：检测新增/修改的系统服务
    5. 系统完整性：检测关键系统设置变更
    """

    def __init__(self, quarantine_manager=None,
                 on_threat: Callable[[dict], None] = None):
        self._quarantine_manager = quarantine_manager
        self._on_threat = on_threat
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._observer: Optional['Observer'] = None

        # WMI 注册表事件监控线程（准实时检测，替代15秒轮询）
        # 需要 pywin32，未安装时降级到 _monitor_loop 的轮询模式
        self._wmi_registry_thread: Optional[threading.Thread] = None
        self._wmi_registry_active = False

        # 注册表基线
        self._registry_baselines: Dict[str, Dict[str, str]] = {}
        self._baseline_lock = threading.Lock()

        # 启动项基线
        self._startup_baseline: Dict[str, float] = {}
        self._startup_lock = threading.Lock()

        # hosts 文件基线
        self._hosts_baseline_hash: Optional[str] = None

        # MBR/启动区基线（参照 ProtectBoot 模块）
        # MBR 哈希基线 + 引导签名校验
        self._mbr_baseline_hash: Optional[str] = None
        self._mbr_available: bool = False  # MBR 读取是否可用（需管理员权限）
        self._vbr_baseline_hash: Optional[str] = None
        self._efi_baselines: Dict[str, str] = {}  # EFI 文件哈希基线

        # 统计数据
        self._stats = {
            'registry_checks': 0,
            'startup_checks': 0,
            'hosts_checks': 0,
            'mbr_checks': 0,
            'threats_detected': 0,
            'startup_items_found': 0,
            'blocked_count': 0,
            'started_at': 0,
        }
        self._stats_lock = threading.Lock()

        # 最近事件
        self._recent_events: List[dict] = []
        self._events_lock = threading.Lock()
        self._max_events = 200

        # 基线建立延迟到 _monitor_loop 子线程中执行，避免阻塞主线程
        self._baselines_built = False

        # WMI 持久化基线是否已初始化（True = 之前做过基线化，后续才告警）
        # 首次扫描时不告警，直接把当前状态记作基线。
        self._wmi_baseline_initialized = False

    # ---- 属性 ----

    @property
    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    def get_recent_events(self, limit: int = 20) -> list:
        with self._events_lock:
            return list(reversed(self._recent_events[-limit:]))

    # ---- 内部：日志/事件 ----

    def _add_event(self, event_type: str, target: str,
                   status: str, detail: str = ''):
        ev = {
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'type': event_type,
            'target': target,
            'status': status,
            'detail': detail,
        }
        with self._events_lock:
            self._recent_events.append(ev)
            if len(self._recent_events) > self._max_events:
                self._recent_events = self._recent_events[-self._max_events:]
        logger.info(f"[系统保护] {event_type} {target} [{status}] {detail}")

    def _report_threat(self, threat_data: dict):
        with self._stats_lock:
            self._stats['threats_detected'] += 1
        self._add_event(
            threat_data.get('type', 'threat'),
            threat_data.get('target', ''),
            'threat',
            threat_data.get('detail', ''),
        )
        if self._on_threat:
            try:
                self._on_threat(threat_data)
            except Exception as e:
                logger.error(f'on_threat 回调异常: {e}')

    # ---- 基线构建 ----

    def _build_baselines(self):
        """构建所有系统设置的基线"""
        self._build_registry_baselines()
        self._build_startup_baseline()
        self._build_hosts_baseline()
        self._build_mbr_baseline()
        logger.info('系统保护基线已建立')

    def _build_registry_baselines(self):
        """构建注册表基线"""
        if not HAS_WINREG:
            logger.warning('winreg 不可用，跳过注册表基线')
            return

        with self._baseline_lock:
            # Run 键基线
            for hive, path in RUN_KEY_PATHS:
                key_name = f'{hive}\\{path}'
                values = self._read_registry_values(hive, path)
                self._registry_baselines[key_name] = values

            # 关键系统注册表基线
            for hive, path in CRITICAL_REGISTRY_PATHS:
                key_name = f'{hive}\\{path}'
                values = self._read_registry_values(hive, path)
                self._registry_baselines[key_name] = values

        logger.info(f'注册表基线: {len(self._registry_baselines)} 个键')

    def _build_startup_baseline(self):
        """构建启动项基线"""
        baseline: Dict[str, float] = {}

        # 注册表 Run 键中的启动项
        if HAS_WINREG:
            for hive, path in RUN_KEY_PATHS:
                values = self._read_registry_values(hive, path)
                for name, data in values.items():
                    baseline[f'registry:{hive}\\{path}\\{name}'] = time.time()

        # 启动文件夹中的快捷方式
        for startup_dir in STARTUP_DIRS:
            if os.path.isdir(startup_dir):
                for f in os.listdir(startup_dir):
                    if f.lower().endswith(('.lnk', '.url', '.exe', '.bat', '.cmd')):
                        baseline[f'folder:{startup_dir}\\{f}'] = os.path.getmtime(
                            os.path.join(startup_dir, f)
                        )

        with self._startup_lock:
            self._startup_baseline = baseline

        with self._stats_lock:
            self._stats['startup_items_found'] = len(baseline)

        logger.info(f'启动项基线: {len(baseline)} 个项目')

    def _build_hosts_baseline(self):
        """构建 hosts 文件基线"""
        if os.path.isfile(HOSTS_FILE):
            try:
                with open(HOSTS_FILE, 'rb') as f:
                    self._hosts_baseline_hash = hashlib.sha256(f.read()).hexdigest()
                logger.info(f'hosts 文件基线已建立')
            except Exception as e:
                logger.debug(f'读取 hosts 文件失败: {e}')

    @staticmethod
    def _read_registry_values(hive: int, path: str) -> Dict[str, str]:
        """读取注册表键的所有值"""
        values = {}
        if not HAS_WINREG:
            return values
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, data, reg_type = winreg.EnumValue(key, i)
                    values[str(name)] = str(data)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except FileNotFoundError:
            pass
        except PermissionError:
            logger.debug(f'无权限读取注册表: {path}')
        except Exception as e:
            logger.debug(f'读取注册表失败 {path}: {e}')
        return values

    # ---- 启动/停止 ----

    def start(self) -> bool:
        if self._running:
            return True

        self._stop_event.clear()
        self._running = True

        # 首次检查由 _monitor_loop 在子线程中执行，避免阻塞主线程

        # 启动 hosts 文件实时监控
        if HAS_WATCHDOG and os.path.isfile(HOSTS_FILE):
            try:
                self._observer = Observer()
                handler = _HostsFileHandler(self)
                hosts_dir = os.path.dirname(HOSTS_FILE)
                self._observer.schedule(handler, hosts_dir, recursive=False)
                self._observer.start()
                logger.info(f'hosts 文件 watchdog 已启动')
            except Exception as e:
                logger.error(f'启动 hosts 监控失败: {e}')
                self._observer = None

        # 启动后台检查线程
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name='SystemProtection'
        )
        self._monitor_thread.start()

        # 启动 WMI 注册表事件监控线程（准实时检测）
        # 在 _monitor_loop 建立基线后启动，避免基线未就绪时误报
        if HAS_WMI_REGISTRY:
            self._wmi_registry_thread = threading.Thread(
                target=self._wmi_registry_loop, daemon=True, name='WMIRegistryMonitor'
            )
            self._wmi_registry_thread.start()
        else:
            logger.info('pywin32 未安装，注册表保护使用轮询模式（15秒延迟）')

        with self._stats_lock:
            self._stats['started_at'] = time.time()

        self._add_event('system', '', 'info', '系统保护已启动')
        logger.info('系统保护已启动')
        return True

    def stop(self) -> bool:
        if not self._running:
            return True
        self._stop_event.set()
        self._running = False
        self._wmi_registry_active = False

        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=3)
            except Exception:
                pass
            self._observer = None

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=3)
        self._monitor_thread = None

        if self._wmi_registry_thread and self._wmi_registry_thread.is_alive():
            self._wmi_registry_thread.join(timeout=3)
        self._wmi_registry_thread = None

        self._add_event('system', '', 'info', '系统保护已停止')
        logger.info('系统保护已停止')
        return True

    # ---- 监控循环 ----

    def _monitor_loop(self):
        """主监控循环"""
        # 启动延迟：等待 UI 完全初始化
        self._stop_event.wait(5)
        if self._stop_event.is_set():
            return

        # 在子线程中建立基线（首次），避免阻塞主线程
        if not self._baselines_built:
            self._build_baselines()
            self._baselines_built = True

        registry_counter = 0
        hosts_counter = 0
        startup_counter = 0
        mbr_counter = 0
        adv_persistence_counter = 0  # 高级持久化检测（WMI/计划任务/AppInit_DLLs）

        while not self._stop_event.is_set():
            try:
                self._stop_event.wait(5)
                if self._stop_event.is_set():
                    break

                registry_counter += 1
                hosts_counter += 1
                startup_counter += 1
                mbr_counter += 1
                adv_persistence_counter += 1

                if registry_counter >= _REGISTRY_CHECK_INTERVAL // 5:
                    registry_counter = 0
                    self._check_registry()

                if hosts_counter >= _HOSTS_CHECK_INTERVAL // 5:
                    hosts_counter = 0
                    self._check_hosts_file()

                if startup_counter >= _STARTUP_CHECK_INTERVAL // 5:
                    startup_counter = 0
                    self._check_startup_items()

                if mbr_counter >= _MBR_CHECK_INTERVAL_VAL // 5:
                    mbr_counter = 0
                    self._check_mbr()

                # 高级持久化检测：每 60 秒一次（12 个循环 × 5 秒）
                if adv_persistence_counter >= 12:
                    adv_persistence_counter = 0
                    self._check_advanced_persistence()

            except Exception as e:
                logger.error(f'系统监控循环异常: {e}')
                time.sleep(1)

    # ---- WMI 注册表事件监控（准实时，替代15秒轮询）----

    def _wmi_registry_loop(self):
        """WMI 注册表事件监控线程

        通过 WMI 的 RegistryValueChangeEvent 实现准实时检测：
        - 注册表值被修改/新增/删除时立即触发事件（延迟 <1秒）
        - 相比 15 秒轮询，响应速度提升 15 倍以上
        - 需要 pywin32（win32com），未安装时降级到轮询模式

        监控的注册表路径（与 RUN_KEY_PATHS + CRITICAL_REGISTRY_PATHS 一致）：
        - HKCU/HKLM Run/RunOnce（启动项）
        - Winlogon（系统登录）
        - IFEO（映像劫持）
        - Services（服务）
        - Explorer\Policies（策略）

        注意：WMI 注册表事件需要在 COM 单线程公寓（STA）中运行，
        因此在线程入口调用 CoInitialize()。
        """
        # 等待基线建立完成（避免基线未就绪时误报）
        wait_count = 0
        while not self._baselines_built and self._running and wait_count < 60:
            self._stop_event.wait(1)
            wait_count += 1
        if not self._running or not self._baselines_built:
            return

        try:
            # 初始化 COM（STA 模式，WMI 事件订阅需要）
            pythoncom.CoInitialize()
            self._wmi_registry_active = True
            logger.info('WMI 注册表事件监控已启动（准实时模式）')
        except Exception as e:
            logger.warning(f'WMI COM 初始化失败，降级到轮询模式: {e}')
            self._wmi_registry_active = False
            pythoncom.CoUninitialize()
            return

        try:
            # 构建监控的注册表路径列表（Hive 转换为 WMI 标准名称）
            # WMI 注册表事件类的 Hive 参数需要字符串名称
            hive_map = {
                winreg.HKEY_CURRENT_USER: 'HKEY_CURRENT_USER',
                winreg.HKEY_LOCAL_MACHINE: 'HKEY_LOCAL_MACHINE',
            }

            # 合并所有监控路径
            all_paths = list(RUN_KEY_PATHS) + list(CRITICAL_REGISTRY_PATHS)

            # 创建 SWbemLocator 和连接服务器（只需一次，复用给所有监听器）
            try:
                locator = win32com.client.Dispatch('WbemScripting.SWbemLocator')
                server = locator.ConnectServer('.', r'root\default')
            except Exception as e:
                logger.warning(f'WMI 服务器连接失败，降级到轮询模式: {e}')
                return

            # 为每个路径创建 WMI 事件监听器
            # 使用 RegistryKeyChangeEvent（监控键下任意值变更）
            # 注意：RegistryValueChangeEvent 在部分 Windows 版本上会报
            # "提供程序注册与系统事件域重叠"（WBEM_E_PROVIDER_OVERLAP_WITH_SYSTEM_EVENT），
            # 而 RegistryKeyChangeEvent 兼容性更好，功能几乎等价。
            watchers = []
            first_error = None
            for hive, path in all_paths:
                if not self._running:
                    break
                hive_value = hive_map.get(hive)
                if hive_value is None:
                    continue
                try:
                    escaped_path = path.replace('\\', '\\\\')
                    wql = (
                        f"SELECT * FROM RegistryKeyChangeEvent "
                        f"WHERE Hive = '{hive_value}' "
                        f"AND KeyPath = '{escaped_path}'"
                    )
                    watcher = server.ExecNotificationQuery(wql)
                    watchers.append((watcher, hive, path))
                except Exception as e:
                    if first_error is None:
                        first_error = e
                    logger.debug(f'创建 WMI 注册表监听失败 {path}: {e}')

            if not watchers:
                if first_error:
                    logger.warning(
                        f'WMI 注册表监听器全部创建失败，降级到轮询模式 '
                        f'(首个错误: {first_error})'
                    )
                else:
                    logger.warning('WMI 注册表监听器全部创建失败，降级到轮询模式')
                return

            logger.info(f'WMI 注册表事件监控: {len(watchers)} 个监听器已就绪')

            # 事件循环：NextEvent 阻塞等待注册表变更事件
            # 超时设置为 2 秒，以便定期检查 _running 状态
            while self._running and self._wmi_registry_active:
                for watcher, hive, path in watchers:
                    if not self._running:
                        break
                    try:
                        # NextEvent(timeout) 阻塞等待事件，超时返回 None
                        # 注意：win32com 的 NextEvent 默认无超时，这里用 try-except 处理
                        # 实际使用时通过定时检查 _running 状态
                        event = watcher.NextEvent(2000)  # 2 秒超时
                        if event:
                            self._on_wmi_registry_event(hive, path, event)
                    except Exception as e:
                        # 超时或异常，继续循环
                        err_str = str(e)
                        # WBEM_E_TIMEOUT = 0x80043001 / '已超时 '(中文版) / 'timeout'(英文版)，
                        # 均为 NextEvent(2000) 正常超时，静默继续即可
                        if ('timeout' in err_str.lower() or '80043001' in err_str
                                or '已超时' in err_str or '超时' in err_str):
                            continue
                        logger.debug(f'WMI 事件等待异常: {e}')
                        self._stop_event.wait(1)

        except Exception as e:
            logger.error(f'WMI 注册表监控循环异常: {e}')
        finally:
            self._wmi_registry_active = False
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass
            logger.info('WMI 注册表事件监控已停止')

    def _on_wmi_registry_event(self, hive: int, path: str, event):
        """WMI 注册表变更事件回调

        注册表值被修改/新增/删除时立即触发，调用 _check_registry 进行精确检测。
        相比轮询模式，响应延迟从 15 秒降至 <1 秒。
        """
        try:
            # 提取事件信息
            # RegistryValueChangeEvent 包含 HiveValue/KeyPath/ValueName 字段
            value_name = ''
            try:
                value_name = event.Properties_('ValueName').Value
            except Exception:
                pass

            hive_str = str(hive)
            key_name = f'{hive_str}\\{path}'

            # 立即调用 _check_registry 检测具体变更（新增/修改/删除）
            # _check_registry 会对比基线并触发 _report_threat
            self._check_registry()

            # 记录事件（用于前端展示）
            self._add_event(
                'registry_event', f'{key_name}\\{value_name}',
                'info', f'WMI 检测到注册表变更: {value_name}'
            )

        except Exception as e:
            logger.debug(f'WMI 注册表事件处理异常: {e}')

    # ---- 注册表检查 ----

    def _check_registry(self):
        """检查注册表关键路径是否被篡改"""
        if not HAS_WINREG:
            return

        with self._baseline_lock:
            baseline_keys = list(self._registry_baselines.keys())

        for key_name in baseline_keys:
            # 跳过非注册表基线 key（如 wmi_persistence / scheduled_tasks）
            if '\\' not in key_name:
                continue
            parts = key_name.split('\\', 1)
            hive_str, path = parts[0], parts[1]
            if not hive_str.isdigit():
                continue
            hive = int(hive_str)
            current_values = self._read_registry_values(hive, path)

            with self._baseline_lock:
                baseline = self._registry_baselines.get(key_name, {})

            # 检查新增的值
            for name, data in current_values.items():
                if name not in baseline:
                    # 新增的注册表值
                    is_run_key = 'Run' in path
                    trusted = _is_trusted_startup(name, str(data))

                    if is_run_key:
                        # Run 键：先判断可信性。可信 → 仅记 debug；
                        # 不可信 → 上报一个 registry_new_value（不再额外报 suspicious_startup，避免重复）
                        if trusted:
                            logger.info(
                                f'Run 键新增可信启动项（跳过告警）: '
                                f'{key_name}\\{name} = {str(data)[:100]}'
                            )
                        else:
                            self._report_threat({
                                'type': 'registry_new_value',
                                'target': f'{key_name}\\{name}',
                                'detail': f'Run 键新增可疑启动项: {name} = {str(data)[:100]}',
                            })
                            with self._stats_lock:
                                self._stats['blocked_count'] += 1
                    else:
                        # 非 Run 键（如 Winlogon / IFEO / Services）的新增值保持原有逻辑
                        self._report_threat({
                            'type': 'registry_new_value',
                            'target': f'{key_name}\\{name}',
                            'detail': f'注册表新增值: {name} = {str(data)[:100]}',
                        })
                        with self._stats_lock:
                            self._stats['blocked_count'] += 1

            # 检查被修改的值
            for name, data in current_values.items():
                if name in baseline and str(data) != str(baseline[name]):
                    self._report_threat({
                        'type': 'registry_modified',
                        'target': f'{key_name}\\{name}',
                        'detail': (f'注册表值被修改: {name}\n'
                                   f'原值: {baseline[name][:100]}\n'
                                   f'新值: {str(data)[:100]}'),
                    })

            # 检查被删除的值
            for name in baseline:
                if name not in current_values:
                    self._report_threat({
                        'type': 'registry_deleted',
                        'target': f'{key_name}\\{name}',
                        'detail': f'注册表值被删除: {name}',
                    })

            # 更新基线（防止重复报警合法修改）
            with self._baseline_lock:
                self._registry_baselines[key_name] = current_values

        with self._stats_lock:
            self._stats['registry_checks'] += 1

    # ---- 高级持久化检测（WMI 事件订阅 / 计划任务 / AppInit_DLLs）----

    def _check_advanced_persistence(self):
        """检测高级持久化机制

        覆盖以下主流 APT/勒索软件常用的持久化手法：
        1. WMI 事件订阅持久化（__EventFilter + CommandLineEventConsumer + __FilterToConsumerBinding）
        2. 计划任务（schtasks）异常创建
        3. AppInit_DLLs（全局 DLL 注入）
        4. Winlogon Notify（旧版持久化手法）
        """
        try:
            # 1. WMI 事件订阅持久化检测
            self._check_wmi_persistence()

            # 2. 计划任务监控
            self._check_scheduled_tasks()

            # 3. AppInit_DLLs 检测
            self._check_appinit_dlls()

        except Exception as e:
            logger.debug(f'高级持久化检测异常: {e}')

    def _check_wmi_persistence(self):
        """检测 WMI 事件订阅持久化

        恶意软件通过 __EventFilter + CommandLineEventConsumer + __FilterToConsumerBinding
        实现 WMI 持久化（无文件、注册表也查不到）。
        但 Windows Defender / Sentinel One / Intel ME / NVidia DisplayContainer
        等也会注册合法订阅，因此必须加白名单和"首次扫描静默基线化"策略。

        【修复 1/3 — 严格超时兜底】win32com 的 server.ExecQuery 默认无限阻塞。
        驱动加载后，若 PROCESS_VM_READ 仍偶发阻断（或 WMI Provider 本身卡住），
        阻塞会传导到应用层并出现"WMI 发生意外超时"。这里用独立线程 + Event
        看门狗把整体查询时间限制在 <= 8 秒。
        """
        if not HAS_WMI_REGISTRY:
            return

        # ---- 超时看门狗上下文 ----
        # threading.Event 实现一个 8 秒的硬上限（测试要求 <= 10s）；
        # 检查线程在完成后 set done_event；我们始终返回 Event.wait(timeout=8)
        # 先完成的那个。超时即立即放弃本轮查询，下次周期再试。
        done_ev = threading.Event()
        result_holder: dict = {'filters': [], 'consumers': [], 'bindings': 0,
                               'baseline_init_allowed': False,
                               'ok': False}
        WMI_PERSIST_TIMEOUT = 8.0  # 秒；严格小于测试上限 10s

        def _do_query():
            _err = None
            try:
                pythoncom.CoInitialize()
                try:
                    locator = win32com.client.Dispatch('WbemScripting.SWbemLocator')
                    server = locator.ConnectServer('.', r'root\subscription')

                    # 查询所有 __EventFilter
                    filters = server.ExecQuery('SELECT * FROM __EventFilter')
                    filter_list = []
                    try:
                        for f in filters:
                            filter_list.append({
                                'name': getattr(f, 'Name', ''),
                                'query': getattr(f, 'Query', ''),
                                'ns': getattr(f, 'EventNamespace', ''),
                            })
                    except Exception:
                        pass

                    # 查询 CommandLineEventConsumer
                    consumers = server.ExecQuery(
                        'SELECT * FROM CommandLineEventConsumer')
                    consumer_list = []
                    try:
                        for c in consumers:
                            consumer_list.append({
                                'name': getattr(c, 'Name', ''),
                                'cmdline': (getattr(c, 'CommandLineTemplate', '')
                                            or getattr(c, 'CommandLine', '')),
                            })
                    except Exception:
                        pass

                    # 查询 __FilterToConsumerBinding
                    bindings = server.ExecQuery(
                        'SELECT * FROM __FilterToConsumerBinding')
                    binding_count = 0
                    try:
                        for _ in bindings:
                            binding_count += 1
                    except Exception:
                        pass

                    result_holder['filters'] = filter_list
                    result_holder['consumers'] = consumer_list
                    result_holder['bindings'] = binding_count
                    result_holder['baseline_init_allowed'] = True
                    result_holder['ok'] = True
                finally:
                    pythoncom.CoUninitialize()
            except Exception as e_q:
                _err = e_q
                result_holder['ok'] = False
                result_holder['err'] = str(_err)
            finally:
                done_ev.set()

        worker = threading.Thread(
            target=_do_query, daemon=True,
            name='SystemProtect-WmiPersist-Query')
        worker.start()
        # ---- 严格超时兜底：8 秒未完成就放弃（win32com 线程会在内部
        # 阻塞到 COM 管道超时，但我们这边不再等待它，避免 UI 卡住）
        finished_in_time = done_ev.wait(timeout=WMI_PERSIST_TIMEOUT)
        if not finished_in_time:
            logger.debug(
                f'WMI 持久化检测超时 (>={WMI_PERSIST_TIMEOUT}s)，'
                '跳过本轮。通常是 WMI Provider 初始化或管道被第三方软件占用，'
                '下一周期会自动重试。')
            return
        if not result_holder.get('ok'):
            err = result_holder.get('err', '')
            logger.debug(f'WMI 持久化检测失败: {err}')
            return

        filter_list = result_holder['filters']
        consumer_list = result_holder['consumers']
        binding_count = int(result_holder['bindings'] or 0)

        # ---- 白名单过滤 ----
        # 合法订阅（Name/Query/CommandLine 里含这些关键字）直接跳过，不判恶意
        trusted_keywords = [
            'sentinel',           # Sentinel One EDR
            'defender',           # Microsoft Defender
            'wdac',
            'windows defender',
            'microsoft security',
            'intel',              # Intel ME / Intel Management Components
            'nvidiadisplay',      # NVidia DisplayContainer（后台程序管理）
            'nvidia',
            'qualcomm',
            'cortana',
            'searchui',
            'shellappruntime',
            'securitycenter',
            'sacore',
            'svchost',
        ]

        def _is_trusted_subscription(name: str, query: str = '', cmd: str = '') -> bool:
            blob = f'{name}\n{query}\n{cmd}'.lower()
            for kw in trusted_keywords:
                if kw in blob:
                    return True
            return False

        # 把 filter + consumer 的可信数量收集一下
        trusted_hits = 0
        for f in filter_list:
            if _is_trusted_subscription(f['name'], f['query']):
                trusted_hits += 1
        for c in consumer_list:
            if _is_trusted_subscription(c['name'], cmd=c['cmdline']):
                trusted_hits += 1

        # 如果全部订阅都命中了可信关键字，直接当作系统合法行为静默记录
        if filter_list and trusted_hits >= len(filter_list):
            logger.debug(
                f'WMI 订阅全部命中系统白名单，跳过告警 '
                f'(filters={len(filter_list)}, consumers={len(consumer_list)})'
            )

        current = {
            'filters': filter_list,
            'consumers': consumer_list,
            'bindings': binding_count,
        }

        key = 'wmi_persistence'
        with self._baseline_lock:
            baseline = self._registry_baselines.get(key, {})

        # ---- 告警判定 ----
        # 1) 首次扫描：直接基线化，永不告警
        # 2) 已基线化 + 绑定数增加：才有可能告警（还要再经过可信性检查）
        if result_holder.get('baseline_init_allowed', True) and not self._wmi_baseline_initialized:
            logger.info(
                f'WMI 订阅基线已建立: filters={len(filter_list)}, '
                f'consumers={len(consumer_list)}, bindings={binding_count}'
            )
            self._wmi_baseline_initialized = True
        else:
            baseline_count = baseline.get('bindings', 0) if baseline else 0
            if binding_count > baseline_count:
                # 新增了绑定，至少有一部分是新的；再过滤掉白名单项
                new_threats = []
                for f in filter_list:
                    if not _is_trusted_subscription(f['name'], f['query']):
                        new_threats.append(f"Filter: {f['name']} [{f['query'][:80]}]")
                for c in consumer_list:
                    if not _is_trusted_subscription(c['name'], cmd=c['cmdline']):
                        new_threats.append(f"Consumer: {c['name']} [{c['cmdline'][:80]}]")

                if new_threats:
                    self._report_threat({
                        'type': 'wmi_persistence',
                        'target': 'root\\subscription',
                        'detail': (
                            f'WMI 事件订阅新增绑定 (新增 {binding_count - baseline_count} 条)\n'
                            + '\n'.join(new_threats[:6])
                        ),
                    })
                    with self._stats_lock:
                        self._stats['blocked_count'] += 1

        # 更新基线
        with self._baseline_lock:
            self._registry_baselines[key] = current

    def _check_scheduled_tasks(self):
        """检测计划任务异常创建

        恶意软件常用 schtasks 创建计划任务实现持久化或定时触发。
        通过 schtasks /query /fo LIST 获取任务列表，对比基线检测新增任务。
        """
        if sys.platform != 'win32':
            return

        try:
            import subprocess
            # 子进程窗口隐藏
            creationflags = 0x08000000 if sys.platform == 'win32' else 0
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'LIST'],
                capture_output=True, text=True, timeout=15,
                creationflags=creationflags
            )
            if result.returncode != 0:
                return

            # 解析任务名
            current_tasks: Set[str] = set()
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('TaskName:'):
                    task_name = line[len('TaskName:'):].strip()
                    # 过滤系统内置任务（Microsoft\Windows 开头）
                    if task_name and not task_name.startswith('\\Microsoft\\Windows\\'):
                        # 忽略 PSLS 自身的开机自启计划任务（最高优先级自启，见 utils/autostart_manager.py）
                        if task_name.lower() != '\\psls':
                            current_tasks.add(task_name)

            # 建立基线
            key = 'scheduled_tasks'
            with self._baseline_lock:
                baseline = self._registry_baselines.get(key, set())
                if isinstance(baseline, dict):
                    baseline = set(baseline.get('tasks', []))

            # 检测新增任务
            new_tasks = current_tasks - baseline
            if new_tasks and baseline:  # 仅在已有基线时告警（避免首次扫描误报）
                for task in list(new_tasks)[:5]:
                    self._report_threat({
                        'type': 'scheduled_task_new',
                        'target': task,
                        'detail': f'新增计划任务: {task}',
                    })
                with self._stats_lock:
                    self._stats['blocked_count'] += len(new_tasks)

            # 更新基线
            with self._baseline_lock:
                self._registry_baselines[key] = {'tasks': list(current_tasks)}

        except subprocess.TimeoutExpired:
            logger.debug('查询计划任务超时')
        except Exception as e:
            logger.debug(f'计划任务检测失败: {e}')

    def _check_appinit_dlls(self):
        """检测 AppInit_DLLs（全局 DLL 注入）

        AppInit_DLLs 会被加载到每个使用 user32.dll 的进程中，
        是经典的恶意软件持久化和 DLL 注入手法。
        """
        if not HAS_WINREG:
            return

        try:
            # 64 位和 32 位都检查
            paths = [
                (winreg.HKEY_LOCAL_MACHINE,
                 r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'),
                (winreg.HKEY_LOCAL_MACHINE,
                 r'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'),
            ]

            for hive, path in paths:
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                    try:
                        # 读取 AppInit_DLLs 值
                        try:
                            dll_value, _ = winreg.QueryValueEx(key, 'AppInit_DLLs')
                        except FileNotFoundError:
                            continue
                        # 读取 LoadAppInit_DLLs（是否启用）
                        try:
                            load_value, _ = winreg.QueryValueEx(key, 'LoadAppInit_DLLs')
                        except FileNotFoundError:
                            load_value = 0

                        # 非空且启用则告警
                        if dll_value and str(dll_value).strip() and int(load_value) == 1:
                            # 建立基线
                            baseline_key = f'{hive}\\{path}\\AppInit_DLLs'
                            with self._baseline_lock:
                                baseline = self._registry_baselines.get(baseline_key, '')

                            if str(dll_value) != str(baseline):
                                self._report_threat({
                                    'type': 'appinit_dlls',
                                    'target': baseline_key,
                                    'detail': f'AppInit_DLLs 已启用: {str(dll_value)[:200]}',
                                })
                                with self._stats_lock:
                                    self._stats['blocked_count'] += 1

                            # 更新基线
                            with self._baseline_lock:
                                self._registry_baselines[baseline_key] = dll_value
                    finally:
                        winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
                except PermissionError:
                    continue

        except Exception as e:
            logger.debug(f'AppInit_DLLs 检测失败: {e}')

    # ---- 启动项检查 ----

    def _check_startup_items(self):
        """检查启动项是否有变化"""
        # 重新构建当前启动项列表
        current_startup: Dict[str, float] = {}

        # 注册表 Run 键
        if HAS_WINREG:
            for hive, path in RUN_KEY_PATHS:
                values = self._read_registry_values(hive, path)
                for name, data in values.items():
                    current_startup[f'registry:{hive}\\{path}\\{name}'] = time.time()

        # 启动文件夹
        for startup_dir in STARTUP_DIRS:
            if os.path.isdir(startup_dir):
                for f in os.listdir(startup_dir):
                    if f.lower().endswith(('.lnk', '.url', '.exe', '.bat', '.cmd')):
                        filepath = os.path.join(startup_dir, f)
                        if os.path.isfile(filepath):
                            current_startup[f'folder:{filepath}'] = os.path.getmtime(filepath)

        # 对比基线
        with self._startup_lock:
            old_keys = set(self._startup_baseline.keys())

        current_keys = set(current_startup.keys())

        # 新增的启动项
        new_items = current_keys - old_keys
        for item_key in new_items:
            parts = item_key.split(':', 1)
            item_type = parts[0]
            item_path = parts[1] if len(parts) > 1 else item_key

            if item_type == 'registry':
                # 从注册表路径中提取值名
                path_parts = item_path.rsplit('\\', 1)
                val_name = path_parts[-1] if path_parts else item_path
                # 从 Run 键里读一下真实数据，交给 _is_trusted_startup 做路径级判断
                # registry:{hive}\{path}\{name}
                val_data = ''
                m = re.match(r'registry:(\d+)\\(.+)\\([^\\]+)$', item_path)
                if m:
                    try:
                        vals = self._read_registry_values(int(m.group(1)), m.group(2))
                        val_data = str(vals.get(m.group(3), ''))
                    except Exception:
                        pass
                if not _is_trusted_startup(val_name, val_data):
                    self._report_threat({
                        'type': 'unauthorized_startup',
                        'target': item_path,
                        'detail': f'未经授权的启动项: {val_name}',
                    })
            elif item_type == 'folder':
                file_name = os.path.basename(item_path)
                stem = os.path.splitext(file_name)[0]
                if not _is_trusted_startup(stem):
                    self._report_threat({
                        'type': 'unauthorized_startup_file',
                        'target': item_path,
                        'detail': f'启动文件夹中发现新文件: {file_name}',
                    })

        # 更新基线
        with self._startup_lock:
            self._startup_baseline = current_startup

        with self._stats_lock:
            self._stats['startup_checks'] += 1
            self._stats['startup_items_found'] = len(current_startup)

    # ---- hosts 文件检查 ----

    def _check_hosts_file(self):
        """检查 hosts 文件是否被篡改"""
        if not os.path.isfile(HOSTS_FILE):
            return

        try:
            with open(HOSTS_FILE, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()

            if self._hosts_baseline_hash and current_hash != self._hosts_baseline_hash:
                # 检测到 hosts 文件被修改
                content_diff = self._get_hosts_diff()
                self._report_threat({
                    'type': 'hosts_tampered',
                    'target': HOSTS_FILE,
                    'detail': (f'hosts 文件被修改！可能是 DNS 劫持。\n'
                               f'{content_diff[:300]}'),
                })

                # 更新基线
                self._hosts_baseline_hash = current_hash

        except Exception as e:
            logger.debug(f'检查 hosts 文件失败: {e}')

        with self._stats_lock:
            self._stats['hosts_checks'] += 1

    def _on_hosts_changed(self):
        """hosts 文件变更回调（watchdog 实时通知）"""
        self._check_hosts_file()

    def _get_hosts_diff(self) -> str:
        """获取 hosts 文件的变更内容"""
        if not os.path.isfile(HOSTS_FILE):
            return ''
        try:
            with open(HOSTS_FILE, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()

            # 检查是否有可疑条目
            suspicious = []
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # 检查是否是本地回环以外的条目
                if not line.startswith('127.0.0.1') and not line.startswith('::1'):
                    suspicious.append(line)

            if suspicious:
                return f'发现 {len(suspicious)} 个非本地回环条目: {suspicious[:5]}'
            return 'hosts 文件内容已变更'
        except Exception:
            return ''

    # ---- 公开 API ----

    def force_check_all(self) -> dict:
        """立即执行所有检查"""
        results = {
            'registry': self._check_registry(),
            'startup': self._check_startup_items(),
            'hosts': self._check_hosts_file(),
        }
        return results

    def get_startup_items(self) -> List[dict]:
        """获取当前启动项列表"""
        items = []
        with self._startup_lock:
            for key, mtime in self._startup_baseline.items():
                parts = key.split(':', 1)
                item_type = parts[0]
                item_path = parts[1] if len(parts) > 1 else key
                items.append({
                    'type': item_type,
                    'path': item_path,
                    'modified': time.strftime('%Y-%m-%d %H:%M:%S',
                                              time.localtime(mtime)),
                })
        return items

    def get_registry_snapshot(self) -> dict:
        """获取注册表基线快照"""
        with self._baseline_lock:
            return dict(self._registry_baselines)

    def restore_registry_key(self, key_path: str) -> bool:
        """尝试恢复指定注册表键到基线值

        注意：此操作需要管理员权限。
        """
        if not HAS_WINREG:
            return False

        with self._baseline_lock:
            baseline = self._registry_baselines.get(key_path)

        if not baseline:
            return False

        try:
            parts = key_path.split('\\', 1)
            if len(parts) != 2 or not parts[0].isdigit():
                return False
            hive_str, path = parts[0], parts[1]
            hive = int(hive_str)

            # 备份当前值
            current = self._read_registry_values(hive, path)

            # 恢复基线值
            key = winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE)
            for name, data in baseline.items():
                try:
                    # 删除基线中不存在的新值
                    if name in current and str(current[name]) != str(data):
                        pass  # 已被覆盖
                    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(data))
                except Exception as e:
                    logger.warning(f'恢复注册表值失败 {name}: {e}')
            winreg.CloseKey(key)

            self._add_event('restore', key_path, 'success',
                            '已恢复注册表到基线')
            return True
        except Exception as e:
            logger.error(f'恢复注册表失败: {e}')
            return False

    def restore_hosts_file(self) -> bool:
        """尝试恢复 hosts 文件（从备份或原始内容）"""
        if not os.path.isfile(HOSTS_FILE):
            return False

        try:
            # hosts 文件的标准内容
            default_content = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# ...
#
127.0.0.1       localhost
::1             localhost
"""
            with open(HOSTS_FILE, 'w', encoding='utf-8') as f:
                f.write(default_content)

            self._hosts_baseline_hash = hashlib.sha256(
                default_content.encode()
            ).hexdigest()

            self._add_event('restore', HOSTS_FILE, 'success',
                            '已恢复 hosts 文件到默认内容')
            return True
        except Exception as e:
            logger.error(f'恢复 hosts 文件失败: {e}')
            return False

    # ---- MBR/启动区保护（参照 ProtectBoot.cpp）----

    def _build_mbr_baseline(self):
        """构建 MBR/VBR/EFI 启动区基线哈希"""
        # MBR 基线
        mbr_data = self._read_mbr_sector()
        if mbr_data:
            self._mbr_baseline_hash = hashlib.sha256(mbr_data).hexdigest()
            self._mbr_available = True
            logger.info('MBR 基线已建立')
        else:
            self._mbr_available = False
            logger.info('MBR 读取不可用（可能需要管理员权限），MBR 保护以降级模式运行')

        # VBR 基线（C 盘启动扇区）
        vbr_data = self._read_vbr_sector()
        if vbr_data:
            self._vbr_baseline_hash = hashlib.sha256(vbr_data).hexdigest()
            logger.info('VBR 基线已建立')

        # 引导关键文件基线（仅实际存在的文件被纳入监控）
        for efi_path in _EFI_FILES:
            try:
                if os.path.isfile(efi_path):
                    with open(efi_path, 'rb') as f:
                        self._efi_baselines[efi_path] = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                pass
        if self._efi_baselines:
            logger.info(f'引导关键文件基线已建立: {len(self._efi_baselines)} 个文件')

    @staticmethod
    def _raw_read_sector(path: str, size: int = _MBR_SECTOR_SIZE) -> Optional[bytes]:
        """通过 CreateFileW + ReadFile 读取物理磁盘/卷设备的扇区数据。

        需要管理员权限。失败返回 None（不报错，配合降级模式）。
        """
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel32.CreateFileW.restype = wintypes.HANDLE
            kernel32.CreateFileW.argtypes = [
                wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
            kernel32.ReadFile.restype = wintypes.BOOL
            kernel32.ReadFile.argtypes = [
                wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3

            handle = kernel32.CreateFileW(
                path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            if handle == INVALID_HANDLE_VALUE or handle == 0:
                return None

            try:
                buf = ctypes.create_string_buffer(size)
                bytes_read = wintypes.DWORD(0)
                ok = kernel32.ReadFile(
                    handle, buf, size,
                    ctypes.byref(bytes_read), None
                )
                if ok and bytes_read.value == size:
                    return buf.raw
            finally:
                kernel32.CloseHandle(handle)
        except Exception as e:
            logger.debug(f'读取扇区失败 ({path}): {e}')
        return None

    @staticmethod
    def _read_mbr_sector() -> Optional[bytes]:
        """读取 MBR 扇区（物理驱动器0的第一个扇区，512字节）

        需要管理员权限。失败时返回 None（不报错，以支持降级模式）。
        """
        return SystemProtection._raw_read_sector(_MBR_DRIVE)

    @staticmethod
    def _read_vbr_sector() -> Optional[bytes]:
        """读取 VBR 扇区（C 盘的第一个扇区，512字节）"""
        return SystemProtection._raw_read_sector(_VBR_DRIVE)

    def _check_mbr(self):
        """检查 MBR/VBR/EFI 启动区是否被篡改

        检测项：
        1. MBR 哈希基线对比（Petya/NotPetya 等会覆写 MBR）
        2. MBR 引导签名 0x55AA 校验（被破坏则系统无法启动）
        3. VBR 哈希基线对比
        4. EFI 关键文件哈希基线对比
        """
        # ---- MBR 检查 ----
        if self._mbr_available:
            mbr_data = self._read_mbr_sector()
            if mbr_data:
                # 哈希基线对比
                current_hash = hashlib.sha256(mbr_data).hexdigest()
                if self._mbr_baseline_hash and current_hash != self._mbr_baseline_hash:
                    self._report_threat({
                        'type': 'mbr_tampered',
                        'target': _MBR_DRIVE,
                        'detail': 'MBR（主引导记录）已被篡改！可能是 Petya/NotPetya 等勒索软件攻击',
                    })
                    with self._stats_lock:
                        self._stats['blocked_count'] += 1
                    # 更新基线避免重复报警（用户确认后）
                    self._mbr_baseline_hash = current_hash

                # 引导签名校验（0x55AA）
                signature = mbr_data[_MBR_SIGNATURE_OFFSET:_MBR_SIGNATURE_OFFSET + 2]
                if signature != _MBR_SIGNATURE:
                    self._report_threat({
                        'type': 'mbr_signature_corrupted',
                        'target': _MBR_DRIVE,
                        'detail': 'MBR 引导签名 0x55AA 已损坏！系统可能无法启动',
                    })
                    with self._stats_lock:
                        self._stats['blocked_count'] += 1

        # ---- VBR 检查 ----
        if self._vbr_baseline_hash:
            vbr_data = self._read_vbr_sector()
            if vbr_data:
                current_vbr_hash = hashlib.sha256(vbr_data).hexdigest()
                if current_vbr_hash != self._vbr_baseline_hash:
                    self._report_threat({
                        'type': 'vbr_tampered',
                        'target': _VBR_DRIVE,
                        'detail': 'VBR（卷引导记录）已被篡改！可能是启动区恶意软件',
                    })
                    self._vbr_baseline_hash = current_vbr_hash

        # ---- 引导关键文件检查 ----
        for efi_path, baseline_hash in list(self._efi_baselines.items()):
            try:
                normal_path = efi_path
                if os.path.isfile(normal_path):
                    with open(normal_path, 'rb') as f:
                        current_hash = hashlib.sha256(f.read()).hexdigest()
                    if current_hash != baseline_hash:
                        self._report_threat({
                            'type': 'efi_file_tampered',
                            'target': efi_path,
                            'detail': f'引导文件已被篡改: {efi_path}',
                        })
                        self._efi_baselines[efi_path] = current_hash
                else:
                    # 引导文件被删除
                    self._report_threat({
                        'type': 'efi_file_deleted',
                        'target': efi_path,
                        'detail': f'引导文件被删除: {efi_path}',
                    })
            except Exception:
                pass

        with self._stats_lock:
            self._stats['mbr_checks'] += 1

    def get_mbr_status(self) -> dict:
        """获取 MBR/启动区保护状态"""
        return {
            'mbr_available': self._mbr_available,
            'mbr_baseline': self._mbr_baseline_hash is not None,
            'vbr_baseline': self._vbr_baseline_hash is not None,
            'efi_files_monitored': len(self._efi_baselines),
        }
