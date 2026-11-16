# -*- coding: utf-8 -*-
"""
autostart_protection.py — 自启动项监测模块

功能：
  1. 实时监测 Run/RunOnce/启动文件夹等自启动位置的变更
  2. 有可疑进程试图添加自启动 → 直接拦截 + 回滚 + 终止可疑进程
  3. 非可疑进程添加自启动 → 弹窗询问用户，5 秒无反馈自动拦截并回滚
  4. 对"注册表保护"等系统保护与"文件保护(防勒索)"同样生效（回滚统一走注册表）

双轨检测：
  - 内核驱动模式：驱动 regmon 投递 reg_key 事件，实时精确获取操作 PID（最准最快）
  - 降级模式：驱动不可用时，用 WMI RegistryKeyChangeEvent + 轮询对比基线反推可疑变更

本模块只负责检测、判定与回滚，不直接创建 Qt 弹窗。
弹窗交互由上层（bridge.py）通过 on_ask_user / on_suspicious / on_result 回调处理。
"""
import os
import sys
import time
import threading
from typing import Callable, Dict, List, Optional, Set, Tuple

from utils.logger import get_logger

logger = get_logger('autostart_protection')

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False
    winreg = None

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    psutil = None

# WMI 注册表事件订阅（准实时降级方案）
# 注意：禁用 gen_py 缓存写入，避免在受限/打包环境下因 TEMP 目录
#       不可写或文件句柄损坏导致 ImportError/[Errno 9] Bad file descriptor。
os.environ['PYWIN32_DISABLE_GEN_PY_CACHE'] = '1'

try:
    # 清理残留 gen_py 损坏缓存
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
    HAS_WMI = True
except Exception:
    HAS_WMI = False
    win32com = None
    pythoncom = None


# ---- 自启动监控注册表路径 ----
# 注：64 位 Windows 下，32 位进程写 HKLM\Software\...\Run 会被重定向到
# HKLM\Software\WOW6432Node\...\Run。PSLS 是 64 位进程，winreg 默认读 64 位
# 视图，若不显式列出 WOW6432Node 路径，**32 位恶意软件写入的 HKLM 自启动项
# 在用户态降级模式（非管理员/驱动未加载，即实测 VM 场景）下完全不可见** ——
# 这正是"自启动拦截经常失效"的主要原因。HKCU\...\Run 不做 WOW 重定向，
# 故无需重复。
AUTOSTART_KEY_PATHS = [
    (winreg.HKEY_CURRENT_USER,
     r'Software\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_CURRENT_USER,
     r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
    (winreg.HKEY_LOCAL_MACHINE,
     r'Software\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_LOCAL_MACHINE,
     r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
    (winreg.HKEY_LOCAL_MACHINE,
     r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'),
    (winreg.HKEY_CURRENT_USER,
     r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'),
    # ---- 32 位视图（WOW6432Node）：覆盖 32 位程序的自启动写入 ----
    (winreg.HKEY_LOCAL_MACHINE,
     r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_LOCAL_MACHINE,
     r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'),
    (winreg.HKEY_LOCAL_MACHINE,
     r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'),
] if HAS_WINREG else []

# 自启动文件夹
STARTUP_DIRS = [
    os.path.join(os.path.expanduser('~'),
                 r'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'),
    r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
]

# 驱动 reg_key 事件 full_path 中的自启动特征片段
AUTOSTART_PATH_MARKERS = [
    '\\Run',
    'RUn',
    'run',  # 宽松匹配（大小写由去重忽略）
    'RunOnce',
    'Startup',
]

# 驱动 full_path 前缀 → winreg hive 映射
_DRIVER_HIVE_MAP = {
    '\\REGISTRY\\MACHINE': winreg.HKEY_LOCAL_MACHINE,
    '\\registry\\machine': winreg.HKEY_LOCAL_MACHINE,
    '\\REGISTRY\\USER': winreg.HKEY_CURRENT_USER,
    '\\registry\\user': winreg.HKEY_CURRENT_USER,
} if HAS_WINREG else {}

# 可信进程白名单（不弹窗也不拦截）
TRUSTED_PROCESSES: Set[str] = {
    'system', 'system idle process', 'registry',
    'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
    'lsass.exe', 'svchost.exe', 'spoolsv.exe', 'explorer.exe',
    'winlogon.exe', 'sihost.exe', 'taskhostex.exe',
    'conhost.exe', 'dwm.exe', 'rdpclip.exe', 'ctfmon.exe',
    'dllhost.exe', 'audiodg.exe', 'wmiprvse.exe',
    'searchindexer.exe', 'searchprotocolhost.exe',
    'psls.exe', 'project sertraline lab',
}

# 已知可疑进程名
SUSPICIOUS_PROCESS_NAMES: Set[str] = {
    'svch0st', 'svhost', 'expl0rer', 'explorar',
    'winlog0n', 'rund1l32', 'rundl132',
    'c0m', 'c0md', 'c0mmand',
    'powersh3ll', 'p0wershell',
    'mshta', 'scr0n', 'lssas', 'isass',
}

# 危险目录关键词（从这些位置添加自启动更可疑）
DANGEROUS_DIR_KEYWORDS: List[str] = [
    '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
    '\\recycler', '\\$recycle.bin',
    '\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\',
    '\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\',
]

# 可疑启动值数据特征（指向临时/隐藏/可写位置）
SUSPICIOUS_VALUE_KEYWORDS: List[str] = [
    '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
    '\\$recycle.bin', '\\recycler',
    'powershell.exe -enc', 'powershell.exe -windowstyle hidden',
    'cmd.exe /c', 'wscript.exe', 'mshta.exe',
    'rundll32.exe javascript:', 'regsvr32 /s',
]

# 受信任的常见自启动项（安装类软件自动添加，不弹窗）
TRUSTED_STARTUP_NAMES: Set[str] = {
    'psls', 'project sertraline lab',
}


class AutostartProtection:
    """
    自启动项监测引擎。

    回调（全部在后台线程调用，Qt 弹窗需经信号转发到主线程）：
      on_suspicious(info: dict)  — 可疑进程企图添加自启动，建议直接拦截+回滚+终止
      on_ask_user(info: dict)    — 非可疑进程企图添加自启动，需弹窗询问用户
      on_result(info: dict)      — 拦截/允许/回滚结果通知（用于结果弹窗）
    """

    def __init__(self, signature_db=None,
                 on_suspicious: Optional[Callable[[dict], None]] = None,
                 on_ask_user: Optional[Callable[[dict], None]] = None,
                 on_result: Optional[Callable[[dict], None]] = None):
        self._signature_db = signature_db
        self._on_suspicious = on_suspicious
        self._on_ask_user = on_ask_user
        self._on_result = on_result

        self._running = False
        self._stop_event = threading.Event()

        # 驱动模式
        self._driver_bridge = None
        self._driver_enabled = False

        # WMI 降级模式
        self._wmi_thread: Optional[threading.Thread] = None
        self._wmi_active = False

        # 自启动值基线（用于驱动模式回滚 & 降级模式对比）
        self._baseline: Dict[str, str] = {}
        self._baseline_lock = threading.Lock()

        # 已允许项缓存（用户在一轮中允许放行，避免重复询问）
        self._allowed_cache: Dict[str, float] = {}
        self._cache_lock = threading.Lock()
        self._allowed_ttl = 300.0  # 5 分钟

        # 统计
        self._stats = {
            'blocked': 0,
            'allowed': 0,
            'asked': 0,
            'detected': 0,
        }
        self._stats_lock = threading.Lock()

        # 最近事件
        self._recent_events: List[dict] = []
        self._events_lock = threading.Lock()

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

    # ---- 内部：事件日志 ----

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
            if len(self._recent_events) > 200:
                self._recent_events = self._recent_events[-200:]
        logger.info(f'[自启动监测] {event_type} {target} [{status}] {detail}')

    def _bump_stat(self, key: str):
        with self._stats_lock:
            self._stats[key] += 1

    # ---- 启动/停止 ----

    def start(self) -> bool:
        if self._running:
            return True
        self._stop_event.clear()
        self._running = True

        # 建立当前自启动值基线（供回滚与降级对比）
        self._rebuild_baseline()

        # 优先尝试内核驱动模式（最准最快）
        if HAS_WINREG:
            try:
                from driver.bridge.psls_driver_bridge import PSLSDriverBridge
                bridge = PSLSDriverBridge()
                if bridge.is_available:
                    bridge.register_callback('reg_key', self._on_driver_reg_event)
                    bridge.start_event_loop()
                    self._driver_bridge = bridge
                    self._driver_enabled = True
                    logger.info('自启动监测：内核驱动模式已启用')
                else:
                    logger.warning('自启动监测：驱动不可用，使用 WMI/轮询降级模式')
            except Exception as e:
                logger.warning(f'自启动监测：驱动初始化失败，降级模式: {e}')
                self._driver_enabled = False

        # 降级模式：WMI + 轮询基线对比
        if not self._driver_enabled:
            if HAS_WMI:
                self._wmi_thread = threading.Thread(
                    target=self._wmi_registry_loop, daemon=True,
                    name='AutostartWmiMonitor',
                )
                self._wmi_thread.start()
            else:
                # 纯轮询
                self._poll_thread = threading.Thread(
                    target=self._poll_loop, daemon=True,
                    name='AutostartPollMonitor',
                )
                self._poll_thread.start()

        mode = '驱动模式' if self._driver_enabled else '降级模式'
        self._add_event('system', '', 'info', f'{mode} 自启动监测已启动')
        return True

    def stop(self) -> bool:
        if not self._running:
            return True
        self._stop_event.set()
        self._running = False

        if self._driver_bridge:
            try:
                self._driver_bridge.stop_event_loop()
                self._driver_bridge.close()
            except Exception as e:
                logger.debug(f'停止驱动桥接异常: {e}')
            self._driver_bridge = None
            self._driver_enabled = False

        for attr in ('_wmi_thread', '_poll_thread'):
            t = getattr(self, attr, None)
            if t and t.is_alive():
                t.join(timeout=3)
            if hasattr(self, attr):
                setattr(self, attr, None)

        self._add_event('system', '', 'info', '自启动监测已停止')
        return True

    # ---- 基线 ----

    def _read_key_values(self, hive: int, path: str) -> Dict[str, str]:
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
            pass
        except Exception as e:
            logger.debug(f'读取注册表失败 {path}: {e}')
        return values

    def _rebuild_baseline(self):
        baseline: Dict[str, str] = {}
        if HAS_WINREG:
            for hive, path in AUTOSTART_KEY_PATHS:
                for name, data in self._read_key_values(hive, path).items():
                    baseline[f'{int(hive)}\\{path}\\{name}'] = str(data)
        with self._baseline_lock:
            self._baseline = baseline

    # ---- 驱动事件处理 ----

    def _on_driver_reg_event(self, event):
        """驱动 reg_key 事件回调（后台线程）

        仅关注自启动路径的 SET_VALUE / CREATE_KEY / DELETE_KEY。
        """
        try:
            full_path = getattr(event, 'full_path', '') or ''
            value_name = getattr(event, 'value_name', '') or ''
            pid = getattr(event, 'pid', 0) or 0
            event_type = getattr(event, 'event_type', 0)

            if not full_path or not self._is_autostart_path(full_path):
                return

            # 只处理添加/修改值（SET_VALUE 或 CREATE_KEY）
            if event_type not in (0x10, 0x11):
                return

            if not value_name:
                return

            # 忽略受信任的自启动项
            base = value_name.lower().rsplit('.', 1)[0]
            if value_name.lower() in TRUSTED_STARTUP_NAMES or base in TRUSTED_STARTUP_NAMES:
                return

            # 读取刚写入的值（驱动已放行，此时已落盘）
            value_data = self._read_current_value(full_path, value_name)

            # 去重：同一 pid+value 短时间内只处理一次
            dedup_key = f'{pid}:{full_path}\\{value_name}'
            if not self._throttle(dedup_key, 1.0):
                return

            self._bump_stat('detected')

            info = {
                'type': 'autostart',
                'pid': pid,
                'full_path': full_path,
                'value_name': value_name,
                'value_data': value_data,
                'source': 'driver',
            }

            suspicious, proc_info = self._analyze_process(pid, full_path, value_name, value_data)
            info.update(proc_info)

            if suspicious:
                info['verdict'] = 'block'
                self._bump_stat('blocked')
                self._add_event('suspicious', f'{full_path}\\{value_name}', 'block',
                                f'可疑进程(PID={pid} {proc_info.get("name", "")})试图添加自启动')
                if self._on_suspicious:
                    self._on_suspicious(info)
            else:
                # 非可疑：若用户已允许过则直接放行，否则弹窗询问
                if self._is_allowed(dedup_key):
                    return
                info['verdict'] = 'ask'
                self._bump_stat('asked')
                self._add_event('monitor', f'{full_path}\\{value_name}', 'ask',
                                f'进程(PID={pid} {proc_info.get("name", "")})添加自启动，等待用户确认')
                if self._on_ask_user:
                    self._on_ask_user(info)
        except Exception as e:
            logger.debug(f'自启动驱动事件处理异常: {e}')

    # ---- WMI/轮询降级 ----

    def _wmi_registry_loop(self):
        """WMI RegistryKeyChangeEvent 监听自启动键变更（降级方案，无 PID）"""
        try:
            pythoncom.CoInitialize()
            self._wmi_active = True
        except Exception as e:
            logger.warning(f'自启动 WMI COM 初始化失败: {e}')
            return

        try:
            locator = win32com.client.Dispatch('WbemScripting.SWbemLocator')
            server = locator.ConnectServer('.', r'root\default')
            hive_map = {
                winreg.HKEY_CURRENT_USER: 'HKEY_CURRENT_USER',
                winreg.HKEY_LOCAL_MACHINE: 'HKEY_LOCAL_MACHINE',
            }
            watchers = []
            failed_paths = []
            for hive, path in AUTOSTART_KEY_PATHS:
                if not self._running:
                    break
                hive_value = hive_map.get(hive)
                if hive_value is None:
                    continue
                try:
                    escaped = path.replace('\\', '\\\\')
                    wql = (f"SELECT * FROM RegistryKeyChangeEvent "
                           f"WHERE Hive='{hive_value}' AND KeyPath='{escaped}'")
                    watcher = server.ExecNotificationQuery(wql)
                    watchers.append((watcher, hive, path))
                except Exception as e:
                    # RegEvent 提供程序对部分 hive（如 HKEY_CURRENT_USER）不支持，
                    # 或键不存在 → 该路径的 WMI 监听不可用，记下来走轮询兜底。
                    failed_paths.append((hive, path))
                    logger.debug(f'创建 WMI 自启动监听失败 {path}: {e}')
            if not watchers:
                logger.warning('自启动 WMI 监听创建失败，改用轮询')
                self._wmi_active = False
                self._poll_loop()
                return
            if failed_paths:
                # 关键：只要有一条 WMI 监听成功，就不会进入上面的“全量轮询”分支；
                # 若此处不补充，失败的那几条路径（实测 HKLM 成功、HKCU 失败）
                # 将出现“完全无人监控”的盲区（HKCU 的 Run/RunOnce 新增自启动
                # 检测不到）。这里对失败路径单独起轮询兜底。
                logger.info(
                    f'自启动 WMI 覆盖 {len(watchers)} 个路径；'
                    f'{len(failed_paths)} 个路径 WMI 不可用，转轮询兜底: '
                    + ', '.join(p for _h, p in failed_paths))
                self._poll_thread = threading.Thread(
                    target=self._poll_loop, args=(failed_paths,), daemon=True,
                    name='AutostartPollMonitor',
                )
                self._poll_thread.start()

            while self._running and self._wmi_active:
                for watcher, hive, path in watchers:
                    if not self._running:
                        break
                    try:
                        watcher.NextEvent(2000)
                        self._on_value_change_fallback(hive, path)
                    except Exception as e:
                        err_str = str(e)
                        # WBEM_E_TIMEOUT(0x80043001) / 'timeout'(英文) / '已超时'(中文)，
                        # 均为 NextEvent(2000) 正常超时，静默继续等待下一个事件
                        if ('timeout' in err_str.lower() or '80043001' in err_str
                                or '已超时' in err_str or '超时' in err_str):
                            continue
                        logger.debug(f"WMI 自启动事件等待异常: {e}")
                        self._stop_event.wait(1)
        except Exception as e:
            logger.error(f'自启动 WMI 监控循环异常: {e}')
        finally:
            self._wmi_active = False
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

    def _poll_loop(self, paths=None):
        """纯轮询降级：定时对比基线检测新增自启动项

        paths: 仅轮询指定 (hive, path) 列表；为 None 时轮询全部自启动路径。
        """
        target = list(paths) if paths is not None else list(AUTOSTART_KEY_PATHS)
        while self._running and not self._stop_event.is_set():
            self._stop_event.wait(5)
            if self._stop_event.is_set():
                break
            try:
                if HAS_WINREG:
                    for hive, path in target:
                        self._on_value_change_fallback(hive, path)
            except Exception as e:
                logger.debug(f'自启动轮询异常: {e}')

    def _on_value_change_fallback(self, hive: int, path: str):
        """降级模式：对比基线，发现新增/修改的自启动值"""
        if not HAS_WINREG:
            return
        current = self._read_key_values(hive, path)
        key_prefix = f'{int(hive)}\\{path}'
        with self._baseline_lock:
            baseline = dict(self._baseline)

        for name, data in current.items():
            full_key = f'{key_prefix}\\{name}'
            if full_key not in baseline:
                # 新增自启动项
                base = name.lower().rsplit('.', 1)[0]
                if name.lower() in TRUSTED_STARTUP_NAMES or base in TRUSTED_STARTUP_NAMES:
                    continue
                if not self._throttle(f'fallback:{full_key}', 2.0):
                    continue
                self._bump_stat('detected')
                info = {
                    'type': 'autostart',
                    'pid': 0,
                    'full_path': f'{path}',
                    'value_name': name,
                    'value_data': str(data),
                    'source': 'wmi',
                }
                # 降级模式无 PID，根据值数据与目标路径判定
                suspicious = self._analyze_value_only(path, name, str(data))
                info.update({
                    'name': '',
                    'path': '',
                    'suspicious_flags': ['value_pattern'] if suspicious else ['unknown_process'],
                })
                if suspicious:
                    info['verdict'] = 'block'
                    self._bump_stat('blocked')
                    self._add_event('suspicious', full_key, 'block',
                                    f'检测到可疑自启动项: {name}')
                    if self._on_suspicious:
                        self._on_suspicious(info)
                        # 回滚
                        self._rollback_value(hive, path, name, baseline.get(full_key))
                else:
                    if self._is_allowed(full_key):
                        continue
                    info['verdict'] = 'ask'
                    self._bump_stat('asked')
                    self._add_event('monitor', full_key, 'ask',
                                    f'检测到新自启动项: {name}，等待用户确认')
                    if self._on_ask_user:
                        self._on_ask_user(info)

        # 更新基线：**以当前真实注册表状态为准**重建该键的基线切片。
        # 关键修复：此前用"本轮检测开始时读到的 current"覆盖基线，导致
        # 已被回滚(删除)的项仍残留在基线里 —— 恶意软件随后用同名值重新
        # 写入时会被判定为"基线中已存在"而**永远不再告警/拦截**
        # （"自启动拦截经常失效"的直接原因之一）。重读注册表并剔除不
        # 存在项后，同名值再次写入会重新触发"新增"判定。
        try:
            current_after = self._read_key_values(hive, path)
        except Exception:
            current_after = {}
        with self._baseline_lock:
            baseline = {k: v for k, v in self._baseline.items()
                        if not k.startswith(key_prefix + '\\')}
            for name, data in current_after.items():
                baseline[f'{key_prefix}\\{name}'] = str(data)
            self._baseline = baseline

    # ---- 辅助判定 ----

    def _is_autostart_path(self, full_path: str) -> bool:
        """判断 full_path 是否属于自启动路径（驱动模式）"""
        if not full_path:
            return False
        lower = full_path.lower()
        # 排除 force-block 层路径，避免重复处理
        if '\\run\\' in lower or 'runonce' in lower or 'runservices' in lower:
            return True
        # 宽松匹配 Run 键
        if '\\run' in lower or '\\startup' in lower:
            return True
        return False

    def _read_current_value(self, full_path: str, value_name: str) -> str:
        """根据驱动 full_path 读取当前写入的值"""
        if not HAS_WINREG:
            return ''
        hive = self._hive_from_driver_path(full_path)
        if hive is None:
            return ''
        # 从 full_path 提取相对路径（去掉 \REGISTRY\MACHINE\ 前缀）
        rel = self._rel_path_from_driver_path(full_path)
        if not rel:
            return ''
        try:
            key = winreg.OpenKey(hive, rel, 0, winreg.KEY_READ)
            try:
                data, _ = winreg.QueryValueEx(key, value_name)
                return str(data)
            finally:
                winreg.CloseKey(key)
        except FileNotFoundError:
            return ''
        except Exception as e:
            logger.debug(f'读取当前自启动值失败: {e}')
            return ''

    @staticmethod
    def _hive_from_driver_path(full_path: str):
        upper = full_path.upper()
        for prefix, hive in _DRIVER_HIVE_MAP.items():
            if upper == prefix or upper.startswith(prefix + '\\'):
                return hive
        return None

    @staticmethod
    def _rel_path_from_driver_path(full_path: str) -> str:
        """将驱动 full_path（如 \REGISTRY\MACHINE\SOFTWARE\...）转为 winreg 相对路径"""
        upper = full_path.upper()
        for prefix in ('\\REGISTRY\\MACHINE', '\\REGISTRY\\USER'):
            if upper == prefix:
                return ''
            if upper.startswith(prefix + '\\'):
                return full_path[len(prefix):].lstrip('\\')
        return full_path.lstrip('\\')

    def _analyze_process(self, pid: int, full_path: str,
                         value_name: str, value_data: str) -> Tuple[bool, dict]:
        """分析操作进程是否可疑

        Returns:
            (is_suspicious, info_dict)
        """
        info = {'name': '', 'path': '', 'suspicious_flags': []}
        flags = []

        # 1. 进程名/路径分析
        proc_name = ''
        proc_path = ''
        if HAS_PSUTIL and pid > 0:
            try:
                p = psutil.Process(pid)
                proc_name = p.name() or ''
                try:
                    proc_path = p.exe() or ''
                except Exception:
                    proc_path = ''
            except Exception:
                pass

        info['name'] = proc_name
        info['path'] = proc_path

        # 2. 进程名可疑
        if proc_name:
            if self._is_suspicious_name(proc_name):
                flags.append('suspicious_name')
            elif proc_name.lower() in TRUSTED_PROCESSES:
                # 可信进程默认放行（不弹窗）
                info['suspicious_flags'] = []
                return False, info

        # 3. 进程路径靠近危险目录
        if proc_path:
            pl = proc_path.lower()
            if any(kw in pl for kw in DANGEROUS_DIR_KEYWORDS):
                flags.append('dangerous_path')
            # 系统目录/Program Files 通常可信
            elif pl.startswith('c:\\windows\\') or pl.startswith('c:\\program files'):
                info['suspicious_flags'] = flags
                return False, info

        # 4. 值数据指向可疑位置
        if value_data:
            vl = value_data.lower()
            if any(kw in vl for kw in SUSPICIOUS_VALUE_KEYWORDS):
                flags.append('suspicious_value')
            if vl.startswith(('http://', 'https://')):
                flags.append('remote_value')

        # 5. 签名库哈希匹配（可选）
        if self._signature_db and proc_path and os.path.isfile(proc_path):
            try:
                import hashlib
                h = hashlib.sha256()
                with open(proc_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        h.update(chunk)
                sig = self._signature_db.lookup_hash(h.hexdigest())
                if sig:
                    flags.append('known_malware')
            except Exception:
                pass

        info['suspicious_flags'] = flags
        # 任一明确可疑特征命中即判定可疑
        return bool(flags), info

    def _analyze_value_only(self, full_path: str, value_name: str,
                            value_data: str) -> bool:
        """降级模式（无 PID）：仅凭值数据/路径判定是否可疑"""
        vl = value_data.lower() if value_data else ''
        if any(kw in vl for kw in SUSPICIOUS_VALUE_KEYWORDS):
            return True
        if vl.startswith(('http://', 'https://')):
            return True
        return False

    def _is_suspicious_name(self, name: str) -> bool:
        name_lower = name.lower()
        base = name_lower
        for ext in ('.exe', '.dll', '.scr', '.com', '.bat', '.cmd'):
            if base.endswith(ext):
                base = base[:-len(ext)]
                break
        if name_lower in SUSPICIOUS_PROCESS_NAMES or base in SUSPICIOUS_PROCESS_NAMES:
            return True
        system_names = ['svchost', 'explorer', 'winlogon', 'rundll32',
                        'cmd', 'powershell', 'csrss', 'lsass']
        for sys_name in system_names:
            if self._is_confused_name(base, sys_name):
                return True
        return False

    @staticmethod
    def _is_confused_name(name: str, original: str) -> bool:
        if name == original:
            return False
        if len(name) != len(original):
            return False
        subs = {'0': 'o', 'o': '0', '1': 'l', 'l': '1',
                '3': 'e', 'e': '3', '5': 's', 's': '5',
                '$': 's', '!': 'i', '@': 'a'}
        diff = 0
        for sc, pc in zip(name, original):
            if sc == pc:
                continue
            if subs.get(sc) == pc or subs.get(pc) == sc:
                diff += 1
            else:
                return False
        return 1 <= diff <= 2

    # ---- 回滚 ----

    def rollback_value(self, full_path: str, value_name: str) -> bool:
        """公开回滚接口：根据驱动 full_path 删除/恢复自启动值"""
        if not HAS_WINREG:
            return False
        hive = self._hive_from_driver_path(full_path)
        rel = self._rel_path_from_driver_path(full_path)
        if hive is None or not rel:
            return False
        return self._rollback_value(hive, rel, value_name, None)

    def _rollback_value(self, hive, path: str, value_name: str,
                        baseline_val: Optional[str]) -> bool:
        """移除/恢复自启动项（幂等）。

        语义澄清：本方法只负责**自启动项（注册表值）的移除/恢复**，与"勒索文件
        回滚"无关；返回值表示"注册表清理是否完成"，不再被当作"拦截是否成功"。

        幂等处理：键或值本就不存在 → 目标状态已达成，返回 True（此前会因
        FileNotFoundError 返回 False，导致"拦截成功却显示回滚失败"）。
        权限不足等真实失败才返回 False。
        """
        if not HAS_WINREG:
            return False
        try:
            try:
                key = winreg.OpenKey(
                    hive, path, 0,
                    winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE)
            except FileNotFoundError:
                # 键不存在 → 自启动项已不存在（已达成目标）
                self._add_event('rollback', f'{path}\\{value_name}', 'success',
                                '自启动项不存在，无需清理')
                return True
            try:
                restored = False
                if baseline_val is not None:
                    try:
                        winreg.SetValueEx(key, value_name, 0,
                                          winreg.REG_SZ, str(baseline_val))
                        restored = True
                    except Exception as e:
                        logger.warning(
                            f'恢复自启动项基线失败 {path}\\{value_name}: {e}')
                if not restored:
                    try:
                        winreg.DeleteValue(key, value_name)
                    except FileNotFoundError:
                        pass    # 值本就不存在 = 已达成目标
            finally:
                winreg.CloseKey(key)
            self._add_event('rollback', f'{path}\\{value_name}', 'success',
                            '已清理自启动项')
            return True
        except PermissionError as e:
            logger.warning(f'清理自启动项权限不足 {path}\\{value_name}: {e}')
            return False
        except Exception as e:
            logger.warning(f'清理自启动项失败 {path}\\{value_name}: {e}')
            return False

    # ---- 用户决策接口 ----

    def on_user_allow(self, info: dict):
        """用户允许自启动项"""
        try:
            self._bump_stat('allowed')
            key = self._dedup_key_from_info(info)
            self._remember_allowed(key)
            self._add_event('allow', f'{info.get("full_path", "")}\\{info.get("value_name", "")}',
                            'allowed', '用户允许自启动项')
            if self._on_result:
                self._on_result({
                    'action': 'allow',
                    'info': info,
                    'message': '已允许该自启动项',
                })
        except Exception as e:
            logger.debug(f'用户允许处理异常: {e}')

    def on_user_block(self, info: dict):
        """用户拦截自启动项（移除注册表值）

        语义区分（修复"拦截成功却提示回滚失败"）：
          - `success`  = 用户的拦截决策已生效（恒为 True，除非引擎异常）；
          - `cleanup_ok` = 注册表项清理是否完成（权限不足时可能为 False）；
        文案不再使用"回滚失败"，避免与勒索文件回滚链路混淆。
        """
        try:
            cleanup_ok = self.rollback_value(
                info.get('full_path', ''), info.get('value_name', '')
            )
            self._bump_stat('blocked')
            self._add_event('block', f'{info.get("full_path", "")}\\{info.get("value_name", "")}',
                            'blocked', '用户拦截自启动项')
            if self._on_result:
                self._on_result({
                    'action': 'block',
                    'info': info,
                    'success': True,
                    'cleanup_ok': bool(cleanup_ok),
                    'message': ('已拦截该自启动项'
                                if cleanup_ok else
                                '已拦截该自启动项（注册表项未能移除，可能需要管理员权限）'),
                })
        except Exception as e:
            logger.debug(f'用户拦截处理异常: {e}')

    def on_suspicious_handled(self, info: dict):
        """可疑进程已由上层直接拦截+回滚+终止后，通知结果"""
        pass

    # ---- 去重/允许缓存 ----

    def _throttle(self, key: str, interval: float) -> bool:
        now = time.time()
        last = getattr(self, '_last_handled', {}).get(key)
        if last and now - last < interval:
            return False
        if not hasattr(self, '_last_handled'):
            self._last_handled = {}
        self._last_handled[key] = now
        return True

    def _dedup_key_from_info(self, info: dict) -> str:
        return f"{info.get('pid', 0)}:{info.get('full_path', '')}\\{info.get('value_name', '')}"

    def _remember_allowed(self, key: str):
        now = time.time()
        with self._cache_lock:
            self._allowed_cache[key] = now
            # 清理过期
            for k in [k for k, t in self._allowed_cache.items() if now - t > self._allowed_ttl]:
                self._allowed_cache.pop(k, None)

    def _is_allowed(self, key: str) -> bool:
        now = time.time()
        with self._cache_lock:
            t = self._allowed_cache.get(key)
            if t and now - t <= self._allowed_ttl:
                return True
            return False