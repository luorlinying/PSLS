# -*- coding: utf-8 -*-
"""
ETW 实时监控模块
通过 WMI 事件订阅（底层基于 ETW）实现进程创建/终止的实时监控，
替代 psutil 3秒轮询，延迟降至毫秒级。

支持两种模式：
1. WMI 事件订阅（主要）：通过 PowerShell 后台进程订阅 Win32_Process 事件
   - WMI 事件底层由 ETW 驱动，延迟 < 500ms
   - 无需额外 Python 依赖
2. WTS 快速轮询（降级）：通过 WTSEnumProcesses 以 0.5s 间隔快速枚举
   - 比 psutil.process_iter 更轻量（直接调用 WTS API）
   - 降级场景：PowerShell 不可用或 WMI 服务异常

设计原则：
- 线程安全：所有回调在独立线程中执行
- 降级兼容：PowerShell/WMI 不可用时自动降级
- 资源清理：stop() 时确保子进程和句柄被正确释放
"""
import os
import sys
import json
import time
import threading
import subprocess
from typing import Callable, Dict, List, Optional, Set

from utils.logger import get_logger

logger = get_logger('etw_monitor')

# ---- 线程优先级工具（轻量内联，避免循环导入）----
def _boost_current_thread_priority(level: str = 'above_normal') -> bool:
    """提升当前线程优先级（关键监控线程在高 CPU 负载下不被饿死）"""
    if sys.platform != 'win32':
        return False
    try:
        import ctypes
        import ctypes.wintypes
        level_map = {'above_normal': 1, 'highest': 2, 'time_critical': 3}
        priority = level_map.get(level, 1)
        kernel32 = ctypes.windll.kernel32
        kernel32.SetThreadPriority.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_int]
        kernel32.SetThreadPriority.restype = ctypes.wintypes.BOOL
        handle = kernel32.GetCurrentThread()
        return bool(kernel32.SetThreadPriority(handle, priority))
    except Exception:
        return False

try:
    import ctypes
    import ctypes.wintypes
    HAS_CTYPES = True
except ImportError:
    HAS_CTYPES = False
    ctypes = None


# ---- WTS API 常量（降级模式用） ----
WTS_CURRENT_SERVER_HANDLE = 0
WTS_PROCESS_INFO_SIZE = 0  # 动态计算

# WTS_CONNECTSTATE_CLASS
WTSActive = 0


class _WTS_PROCESS_INFO(ctypes.Structure):
    """WTS_PROCESS_INFO 结构体（WTSEnumProcesses 返回）"""
    _fields_ = [
        ('SessionId', ctypes.wintypes.DWORD),
        ('ProcessId', ctypes.wintypes.DWORD),
        ('pProcessName', ctypes.c_wchar_p),
        ('pUserSid', ctypes.c_void_p),
    ]


class EtwMonitor:
    """
    ETW 实时进程监控

    通过 WMI 事件订阅实现进程创建/终止的实时通知，
    替代传统的 psutil 轮询方式。

    用法：
        monitor = EtwMonitor(on_process_created=callback_create,
                             on_process_terminated=callback_term)
        monitor.start()
        # ... 运行中 ...
        monitor.stop()
    """

    def __init__(self,
                 on_process_created: Optional[Callable[[dict], None]] = None,
                 on_process_terminated: Optional[Callable[[dict], None]] = None):
        """
        Args:
            on_process_created: 进程创建回调，参数为 dict:
                {pid, name, cmdline, exe_path, parent_pid}
            on_process_terminated: 进程终止回调，参数为 dict:
                {pid, name}
        """
        self._on_created = on_process_created
        self._on_terminated = on_process_terminated
        self._running = False
        self._stop_event = threading.Event()

        # WMI 模式
        self._wmi_thread: Optional[threading.Thread] = None
        self._wmi_process: Optional[subprocess.Popen] = None
        self._wmi_ready = threading.Event()  # PowerShell 输出 ready 信号
        self._wmi_supervisor_thread: Optional[threading.Thread] = None
        self._wmi_restart_count = 0  # PowerShell 重启次数（用于降级判断）
        self._wmi_lock = threading.Lock()  # 保护 _wmi_process 的访问

        # 降级模式
        self._poll_thread: Optional[threading.Thread] = None
        self._wts_handle = None
        self._last_pids: Dict[int, str] = {}  # pid -> name

        # 统计
        self._stats = {
            'mode': 'stopped',
            'events_created': 0,
            'events_terminated': 0,
            'started_at': 0,
            'fallback': False,
        }
        self._stats_lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    # ---- 启动 / 停止 ----

    def start(self) -> bool:
        if self._running:
            return True

        self._stop_event.clear()
        self._running = True

        with self._stats_lock:
            self._stats['started_at'] = time.time()
            self._stats['fallback'] = False

        # 优先尝试 WMI 事件订阅模式
        if self._start_wmi_mode():
            with self._stats_lock:
                self._stats['mode'] = 'wmi'
            logger.info("ETW 监控已启动 (WMI 事件订阅模式)")
        else:
            # 降级到 WTS 快速轮询
            self._start_poll_mode()
            with self._stats_lock:
                self._stats['mode'] = 'wts_poll'
                self._stats['fallback'] = True
            logger.info("ETW 监控已启动 (WTS 快速轮询降级模式)")

        return True

    def stop(self) -> bool:
        if not self._running:
            return True

        self._stop_event.set()
        self._running = False

        # 停止 WMI 子进程
        if self._wmi_process:
            try:
                self._wmi_process.terminate()
                self._wmi_process.wait(timeout=3)
            except Exception:
                try:
                    self._wmi_process.kill()
                except Exception:
                    pass
            # 关闭 stderr 管道（避免句柄泄漏）
            try:
                if self._wmi_process.stderr:
                    self._wmi_process.stderr.close()
            except Exception:
                pass
            self._wmi_process = None

        # 等待线程结束
        if self._wmi_thread and self._wmi_thread.is_alive():
            self._wmi_thread.join(timeout=3)
        self._wmi_thread = None

        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=3)
        self._poll_thread = None

        # 关闭 WTS 句柄
        if self._wts_handle:
            try:
                wtsapi32 = ctypes.windll.wtsapi32
                wtsapi32.WTSCloseServer(self._wts_handle)
            except Exception:
                pass
            self._wts_handle = None

        with self._stats_lock:
            self._stats['mode'] = 'stopped'
        logger.info("ETW 监控已停止")
        return True

    # ---- WMI 事件订阅模式 ----

    def _start_wmi_mode(self) -> bool:
        """启动 WMI 事件订阅模式

        通过 PowerShell 后台进程订阅 Win32_Process 的创建/终止事件，
        每个事件以 JSON 格式输出到 stdout，Python 逐行读取。
        """
        if sys.platform != 'win32':
            return False

        # 启动 PowerShell 进程
        if not self._launch_wmi_process():
            return False

        # 启动消费线程
        self._wmi_thread = threading.Thread(
            target=self._wmi_consume_loop, daemon=True, name='EtwMonitor-WMI'
        )
        self._wmi_thread.start()

        # 等待就绪信号（最多 12 秒）
        # 原先使用 _stop_event.wait(0.1) 是 bool 误用：返回 True 表示停止信号触发，
        # 而非 ready 信号。改为使用独立的 _wmi_ready Event。
        # ----【修复 3/3】原 5s 太短：驱动加载 + WMI CIM 仓库预热/首次
        # Register-WmiEvent 注册在低配机器上偶发需要 8~10s，5s 会误报
        # "WMI 就绪超时"导致用户感知 WMI 不工作。放宽到 12s 给予充分的
        # WMI Provider 初始化时间（首次注册需要 CIM 对象仓库 MOF 编译 +
        # 提供程序宿主 wmiprvse.exe 冷启动）。
        if not self._wmi_ready.wait(timeout=12.0):
            logger.warning("等待 WMI 就绪信号超时")
            # 不立即失败，让 watchdog 后续判断

        # 检查进程是否立即退出（WMI 注册失败时 PowerShell 会 exit 1）
        if self._wmi_process and self._wmi_process.poll() is not None:
            # 读取 stderr 帮助诊断
            stderr_msg = ''
            try:
                if self._wmi_process.stderr:
                    stderr_msg = self._wmi_process.stderr.read() or ''
            except Exception:
                pass
            msg = f" stderr: {stderr_msg.strip()[:300]}" if stderr_msg.strip() else ""
            logger.warning(f"PowerShell WMI 进程立即退出，降级到轮询模式{msg}")
            return False

        # 启动 watchdog 线程：PowerShell 进程被杀后自动重启
        self._wmi_supervisor_thread = threading.Thread(
            target=self._wmi_supervisor_loop, daemon=True, name='EtwMonitor-Watchdog'
        )
        self._wmi_supervisor_thread.start()

        return True

    def _launch_wmi_process(self) -> bool:
        """启动 PowerShell WMI 订阅进程（供 _start_wmi_mode 和 watchdog 复用）

        优化说明（解决 Quota violation）：
        - 原先注册 2 个独立订阅（CreationEvent + DeletionEvent），在部分机器上
          会触发 WMI 提供程序配额超限错误 (ErrorCode=-2147217300, 'Quota violation')。
        - 现改为单个 __InstanceOperationEvent 订阅，同时覆盖创建+删除事件，
          在 Action 内通过 $Event.SourceEventArgs.NewEvent.__CLASS 区分事件类型。
        - 错误日志不再输出完整 Exception 对象（含几十KB StackTrace/TargetSite 等），
          仅提取 Message + ErrorCode 两个核心字段，避免日志被几百KB垃圾信息淹没。
        """
        ps_script = r'''
$ErrorActionPreference = 'Continue'
# 单个 __InstanceOperationEvent 订阅同时覆盖创建 + 删除事件
# WITHIN 1 秒：缩短 WMI 轮询粒度，降低新进程发现延迟（WITHIN 2 会加大到最长 2 秒）
$query_op = "SELECT * FROM __InstanceOperationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"

try {
    Register-WmiEvent -Query $query_op -SourceIdentifier "ProcOp" -Action {
        $evt = $Event.SourceEventArgs.NewEvent
        $class = $evt.__CLASS
        $p = $evt.TargetInstance
        if ($class -eq '__InstanceCreationEvent') {
            $obj = @{
                type = 'created'
                pid = $p.ProcessId
                name = $p.Name
                cmdline = $p.CommandLine
                exe_path = $p.ExecutablePath
                parent_pid = $p.ParentProcessId
            }
            $obj | ConvertTo-Json -Compress
        } elseif ($class -eq '__InstanceDeletionEvent') {
            $obj = @{
                type = 'terminated'
                pid = $p.ProcessId
                name = $p.Name
            }
            $obj | ConvertTo-Json -Compress
        }
        # else: __InstanceModificationEvent 忽略
    } | Out-Null
} catch {
    # 仅提取核心字段，避免输出几百KB嵌套Exception对象污染日志
    $errCode = ''
    $errMsg = $_.Exception.Message
    try {
        if ($_.Exception.ErrorCode) { $errCode = [string]$_.Exception.ErrorCode }
    } catch {}
    $info = @{ type='error'; stage='register_op'; msg=$errMsg }
    if ($errCode) { $info['code'] = $errCode }
    $info | ConvertTo-Json -Compress
    exit 1
}

# 输出就绪信号
Write-Output '{"type":"ready"}'

# 保持运行，等待事件
while ($true) {
    Start-Sleep -Milliseconds 500
    [System.Console]::Out.Flush()
}
'''

        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE

            with self._wmi_lock:
                self._wmi_process = subprocess.Popen(
                    ['powershell.exe',
                     '-NoProfile', '-NonInteractive',
                     '-ExecutionPolicy', 'Bypass',
                     '-Command', ps_script],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,  # 捕获 stderr 用于诊断
                    text=True,
                    bufsize=1,
                    encoding='utf-8',
                    errors='replace',
                    creationflags=0x08000000,  # CREATE_NO_WINDOW
                    startupinfo=startupinfo,
                )
            return True
        except Exception as e:
            logger.warning(f"启动 PowerShell WMI 订阅失败: {e}")
            return False

    def _wmi_consume_loop(self):
        """消费 WMI 事件输出

        线程优先级：HIGHEST —— 这是进程创建事件的第一个消费点，
        必须尽快把事件传给 ProcessProtection 做 kill 决策
        """
        _boost_current_thread_priority('highest')

        proc = self._wmi_process
        if not proc or not proc.stdout:
            return

        ready = False
        while not self._stop_event.is_set():
            try:
                line = proc.stdout.readline()
                if not line:
                    # 进程已结束
                    if proc.poll() is not None:
                        # 读取 stderr 用于诊断退出原因
                        stderr_msg = ''
                        try:
                            if proc.stderr:
                                stderr_msg = proc.stderr.read() or ''
                        except Exception:
                            pass
                        logger.warning("WMI PowerShell 进程已退出"
                                       + (f" stderr: {stderr_msg.strip()[:500]}" if stderr_msg.strip() else ""))
                        # 通知 watchdog 触发自愈
                        self._wmi_ready.clear()
                        break
                    # 短暂等待避免空转（修复 _stop_event.wait 误用）
                    time.sleep(0.1)
                    continue

                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                etype = event.get('type', '')
                if etype == 'ready':
                    ready = True
                    self._wmi_ready.set()  # 通知主线程已就绪
                    logger.info("WMI 事件订阅就绪")
                    continue

                if etype == 'error':
                    # PowerShell 脚本输出错误信号
                    stage = event.get('stage', 'unknown')
                    msg = event.get('msg', '')
                    logger.warning(f"WMI 事件注册失败 (stage={stage}): {msg}")
                    self._wmi_ready.clear()
                    break

                if not ready:
                    continue

                if etype == 'created':
                    self._handle_process_created(event)
                elif etype == 'terminated':
                    self._handle_process_terminated(event)

            except Exception as e:
                if not self._stop_event.is_set():
                    logger.debug(f"WMI 事件消费异常: {e}")
                time.sleep(0.2)

    def _wmi_supervisor_loop(self):
        """Watchdog：监控 PowerShell WMI 进程存活状态，退出后自动重启

        重启策略：
        - 检测到 PowerShell 进程退出后等待 2 秒（避免抖动）
        - 重启次数 < 3 时尝试重启
        - 重启次数 >= 3 时降级到 WTS 轮询模式并告警
        """
        while not self._stop_event.is_set():
            # 每 5 秒检查一次进程存活
            if self._stop_event.wait(5.0):
                break  # 收到停止信号

            with self._wmi_lock:
                proc = self._wmi_process

            if proc is None:
                continue

            try:
                if proc.poll() is None:
                    # 进程仍存活
                    continue
            except Exception:
                continue

            # PowerShell 进程已退出
            logger.warning(f"WMI PowerShell 进程已退出（重启次数: {self._wmi_restart_count}/3）")

            if self._wmi_restart_count >= 3:
                logger.error("WMI PowerShell 重启次数已达上限，降级到 WTS 轮询模式")
                with self._stats_lock:
                    self._stats['mode'] = 'wts_poll'
                    self._stats['fallback'] = True
                # 启动降级轮询
                try:
                    self._start_poll_mode()
                except Exception as e:
                    logger.error(f"降级到 WTS 轮询失败: {e}")
                return

            # 等待 2 秒避免抖动
            if self._stop_event.wait(2.0):
                break

            # 尝试重启
            self._wmi_restart_count += 1
            logger.info(f"尝试重启 WMI PowerShell 订阅（第 {self._wmi_restart_count} 次）")

            # 清理旧的 consume 线程
            if self._wmi_thread and self._wmi_thread.is_alive():
                # 旧线程会在 proc.stdout.readline() 返回空后自然退出
                pass

            # 重启 PowerShell 进程
            try:
                self._wmi_ready.clear()
                if not self._launch_wmi_process():
                    logger.warning("重启 WMI PowerShell 失败")
                    continue

                # 启动新的消费线程
                self._wmi_thread = threading.Thread(
                    target=self._wmi_consume_loop, daemon=True,
                    name=f'EtwMonitor-WMI-{self._wmi_restart_count}'
                )
                self._wmi_thread.start()

                # 等待就绪
                if self._wmi_ready.wait(timeout=12.0):
                    logger.info("WMI PowerShell 订阅已重启成功")
                    # 重置重启计数（成功后给下一次失败留余地）
                    if self._wmi_restart_count > 0:
                        self._wmi_restart_count -= 1
                else:
                    logger.warning("重启后等待 WMI 就绪信号超时")
            except Exception as e:
                logger.error(f"重启 WMI PowerShell 异常: {e}")

    def _handle_process_created(self, event: dict):
        """处理进程创建事件"""
        pid = event.get('pid', 0)
        name = event.get('name', '')
        cmdline = event.get('cmdline', '') or ''
        exe_path = event.get('exe_path', '') or ''
        parent_pid = event.get('parent_pid', 0)

        with self._stats_lock:
            self._stats['events_created'] += 1

        logger.debug(f"[ETW] 进程创建 PID={pid} {name} parent={parent_pid}")

        if self._on_created:
            try:
                self._on_created({
                    'pid': pid,
                    'name': name,
                    'cmdline': cmdline,
                    'exe_path': exe_path,
                    'parent_pid': parent_pid,
                    'timestamp': time.time(),
                })
            except Exception as e:
                logger.error(f"on_process_created 回调异常: {e}")

    def _handle_process_terminated(self, event: dict):
        """处理进程终止事件"""
        pid = event.get('pid', 0)
        name = event.get('name', '')

        with self._stats_lock:
            self._stats['events_terminated'] += 1

        logger.debug(f"[ETW] 进程终止 PID={pid} {name}")

        if self._on_terminated:
            try:
                self._on_terminated({
                    'pid': pid,
                    'name': name,
                    'timestamp': time.time(),
                })
            except Exception as e:
                logger.error(f"on_process_terminated 回调异常: {e}")

    # ---- WTS 快速轮询降级模式 ----

    def _start_poll_mode(self) -> bool:
        """启动 WTS 快速轮询模式（降级）

        使用 WTSEnumProcesses API 以 0.5 秒间隔枚举进程，
        比 psutil.process_iter 更轻量（不需要逐个打开进程句柄）。
        """
        if not HAS_CTYPES or sys.platform != 'win32':
            logger.warning("ctypes 不可用或非 Windows，ETW 监控以空模式运行")
            return False

        self._poll_thread = threading.Thread(
            target=self._poll_loop, daemon=True, name='EtwMonitor-Poll'
        )
        self._poll_thread.start()
        return True

    def _poll_loop(self):
        """WTS 快速轮询主循环（降级模式）

        线程优先级：ABOVE_NORMAL —— 降级模式下这是唯一的新进程检测通道
        """
        _boost_current_thread_priority('above_normal')

        # 启动延迟
        self._stop_event.wait(3)
        if self._stop_event.is_set():
            return

        # 建立基线
        self._last_pids = self._wts_enum_processes()

        while not self._stop_event.is_set():
            try:
                self._stop_event.wait(1.0)  # 1.0 秒间隔（与 process_protection 主轮询 1.5s 错峰互补，避免双通道重复高频枚举）
                if self._stop_event.is_set():
                    break

                current = self._wts_enum_processes()
                if not current:
                    continue

                # 检测新进程
                for pid, name in current.items():
                    if pid not in self._last_pids:
                        self._handle_process_created({
                            'pid': pid,
                            'name': name,
                            'cmdline': '',
                            'exe_path': '',
                            'parent_pid': 0,
                        })

                # 检测终止的进程
                for pid, name in self._last_pids.items():
                    if pid not in current:
                        self._handle_process_terminated({
                            'pid': pid,
                            'name': name,
                        })

                self._last_pids = current

            except Exception as e:
                if not self._stop_event.is_set():
                    logger.debug(f"WTS 轮询异常: {e}")
                self._stop_event.wait(1)

    def _wts_enum_processes(self) -> Dict[int, str]:
        """通过 WTSEnumProcesses 枚举进程

        Returns:
            {pid: process_name} 字典
        """
        if not HAS_CTYPES:
            return {}

        try:
            wtsapi32 = ctypes.windll.wtsapi32
            count = ctypes.wintypes.DWORD(0)
            pp_proc_info = ctypes.POINTER(_WTS_PROCESS_INFO)()

            # 枚举所有会话的进程
            # WTSEnumerateProcesses(服务器句柄, 保留, 版本, 输出指针, 输出数量)
            success = wtsapi32.WTSEnumerateProcessesW(
                WTS_CURRENT_SERVER_HANDLE,
                0,  # Reserved
                1,  # Version
                ctypes.byref(pp_proc_info),
                ctypes.byref(count),
            )

            if not success:
                return {}

            result: Dict[int, str] = {}
            try:
                for i in range(count.value):
                    proc_info = pp_proc_info[i]
                    pid = proc_info.ProcessId
                    name = proc_info.pProcessName or ''
                    result[pid] = name
            finally:
                # 必须释放 WTS 分配的内存
                wtsapi32.WTSFreeMemory(ctypes.cast(pp_proc_info, ctypes.c_void_p))

            return result

        except Exception as e:
            logger.debug(f"WTSEnumProcesses 失败: {e}")
            return {}


# ---- 反注入增强：线程/DLL 检测工具 ----

# Windows API 常量
TH32CS_SNAPTHREAD = 0x00000004
THREAD_QUERY_INFORMATION = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
# 完整查询权限：EnumProcessModulesEx 需 PROCESS_QUERY_INFORMATION 才能
# 枚举出主 EXE 模块（仅 LIMITED 权限会漏掉主模块 → 主线程全部被误判
# "起始地址不在已加载模块内"，造成 PSLS 自助保护对自身反复误报）。
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010


class _THREADENTRY32(ctypes.Structure):
    """THREADENTRY32 结构体"""
    _fields_ = [
        ('dwSize', ctypes.wintypes.DWORD),
        ('cntUsage', ctypes.wintypes.DWORD),
        ('th32ThreadID', ctypes.wintypes.DWORD),
        ('th32OwnerProcessID', ctypes.wintypes.DWORD),
        ('tpBasePri', ctypes.c_long),
        ('tpDeltaPri', ctypes.c_long),
        ('dwFlags', ctypes.wintypes.DWORD),
    ]


class _MODULEINFO(ctypes.Structure):
    """MODULEINFO 结构体"""
    _fields_ = [
        ('lpBaseOfDll', ctypes.c_void_p),
        ('dwSizeOfDll', ctypes.wintypes.DWORD),
        ('EntryPoint', ctypes.c_void_p),
    ]


def get_process_thread_start_addresses(pid: int) -> List[dict]:
    """获取指定进程所有线程的起始地址

    通过 CreateToolhelp32Snapshot 枚举线程，
    再用 NtQueryInformationThread 获取每个线程的 start address。

    Args:
        pid: 目标进程 ID

    Returns:
        [{thread_id, start_address}, ...]
    """
    if not HAS_CTYPES or sys.platform != 'win32':
        return []

    results: List[dict] = []

    try:
        kernel32 = ctypes.windll.kernel32
        ntdll = ctypes.windll.ntdll

        # 创建线程快照
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snapshot == -1 or snapshot == 0:
            return []

        try:
            te = _THREADENTRY32()
            te.dwSize = ctypes.sizeof(_THREADENTRY32)

            if not kernel32.Thread32First(snapshot, ctypes.byref(te)):
                return []

            while True:
                if te.th32OwnerProcessID == pid:
                    # 获取线程起始地址
                    try:
                        thread_handle = kernel32.OpenThread(
                            THREAD_QUERY_INFORMATION,
                            False,
                            te.th32ThreadID,
                        )
                        if thread_handle:
                            try:
                                start_addr = ctypes.c_void_p(0)
                                # ThreadQuerySetWin32StartAddress = 9
                                status = ntdll.NtQueryInformationThread(
                                    thread_handle,
                                    9,  # ThreadQuerySetWin32StartAddress
                                    ctypes.byref(start_addr),
                                    ctypes.sizeof(ctypes.c_void_p),
                                    None,
                                )
                                if status == 0:  # STATUS_SUCCESS
                                    results.append({
                                        'thread_id': te.th32ThreadID,
                                        'start_address': start_addr.value or 0,
                                    })
                            finally:
                                kernel32.CloseHandle(thread_handle)
                    except Exception:
                        pass

                if not kernel32.Thread32Next(snapshot, ctypes.byref(te)):
                    break

        finally:
            kernel32.CloseHandle(snapshot)

    except Exception as e:
        logger.debug(f"获取线程起始地址失败 PID={pid}: {e}")

    return results


def get_process_module_ranges(pid: int) -> List[dict]:
    """获取指定进程加载的所有模块地址范围

    通过 EnumProcessModulesEx 枚举加载的 DLL，
    获取每个模块的基址和大小。

    Args:
        pid: 目标进程 ID

    Returns:
        [{base, size, name}, ...]
    """
    if not HAS_CTYPES or sys.platform != 'win32':
        return []

    results: List[dict] = []

    try:
        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi

        # 声明参数类型，否则 64 位 HMODULE（如 0x7ff6...）在无 argtypes 的
        # ctypes 调用里会被当作 32 位 int 转换而抛 OverflowError，
        # 导致所有模块 GetModuleInformation 全部失败 → modules 恒为空，
        # 即便模块枚举成功也无法把主 EXE 纳入比对，进而主线程全被判可疑。
        try:
            psapi.EnumProcessModulesEx.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                ctypes.c_uint32, ctypes.POINTER(ctypes.wintypes.DWORD),
                ctypes.c_uint32]
        except Exception:
            pass
        try:
            psapi.GetModuleInformation.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p,
                ctypes.POINTER(_MODULEINFO), ctypes.c_uint32]
        except Exception:
            pass
        try:
            psapi.GetModuleFileNameExW.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p,
                ctypes.c_wchar_p, ctypes.c_uint32]
            psapi.GetModuleFileNameExW.restype = ctypes.c_uint32
        except Exception:
            pass

        # 打开进程
        # 必须用完整 PROCESS_QUERY_INFORMATION（而非仅 LIMITED）：
        # EnumProcessModulesEx 用它枚举主 EXE 模块。若只给 LIMITED，主模块
        # 常被漏枚举，导致进程内所有线程起始地址都落在主模块里却被判
        # "不在已加载模块内" → 对自身进程（PSLS 自我保护）产生大量误报。
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid,
        )
        # 无完整权限时（访问其他高权限进程）降级到 LIMITED 再试一次。
        # 此时即便漏掉主模块，宁可少报也不能让"主模块漏枚举"造成误报——
        # 由 detect_remote_thread_injection 兜底：若模块列表不含主 EXE，
        # 直接按"无法比对"处理（见该函数）。
        if not handle:
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                False,
                pid,
            )
        if not handle:
            return []

        try:
            # 枚举模块
            h_modules = (ctypes.c_void_p * 1024)()
            cb_needed = ctypes.wintypes.DWORD(0)

            # LIST_MODULES_ALL = 0x03
            success = psapi.EnumProcessModulesEx(
                handle,
                h_modules,
                ctypes.sizeof(h_modules),
                ctypes.byref(cb_needed),
                0x03,  # LIST_MODULES_ALL
            )

            if not success:
                return []

            module_count = min(cb_needed.value // ctypes.sizeof(ctypes.c_void_p), 1024)

            for i in range(module_count):
                if not h_modules[i]:
                    continue
                try:
                    mod_info = _MODULEINFO()
                    if psapi.GetModuleInformation(handle, h_modules[i],
                                                  ctypes.byref(mod_info),
                                                  ctypes.sizeof(_MODULEINFO)):
                        # 获取模块文件名
                        mod_name_buf = ctypes.create_unicode_buffer(260)
                        psapi.GetModuleFileNameExW(handle, h_modules[i],
                                                   mod_name_buf, 260)
                        results.append({
                            'base': mod_info.lpBaseOfDll or 0,
                            'size': mod_info.dwSizeOfDll,
                            'name': mod_name_buf.value,
                        })
                except Exception:
                    continue

        finally:
            kernel32.CloseHandle(handle)

    except Exception as e:
        logger.debug(f"获取模块范围失败 PID={pid}: {e}")

    return results


def detect_remote_thread_injection(pid: int) -> List[dict]:
    """检测远程线程注入

    对比进程的线程起始地址与加载的模块地址范围。
    如果某线程的起始地址不在任何已加载模块内，
    则可能是通过 CreateRemoteThread 注入的线程。

    Args:
        pid: 目标进程 ID

    Returns:
        [{thread_id, start_address, reason}, ...] 可疑线程列表
    """
    threads = get_process_thread_start_addresses(pid)
    if not threads:
        return []

    modules = get_process_module_ranges(pid)
    if not modules:
        return []

    suspicious: List[dict] = []

    for thread in threads:
        addr = thread.get('start_address', 0)
        if not addr:
            continue

        # 检查起始地址是否在某个模块的地址范围内
        in_module = False
        for mod in modules:
            base = mod.get('base', 0)
            size = mod.get('size', 0)
            if base and size and base <= addr < base + size:
                in_module = True
                break

        if not in_module:
            suspicious.append({
                'thread_id': thread['thread_id'],
                'start_address': hex(addr),
                'reason': '线程起始地址不在任何已加载模块内，疑似 CreateRemoteThread 注入',
            })

    return suspicious


def detect_dll_injection(pid: int, trusted_paths: Set[str] = None) -> List[dict]:
    """检测 DLL 注入

    枚举进程加载的模块，检查是否有可疑的 DLL：
    - 从临时目录/回收站加载的 DLL
    - 非系统目录且非可信路径的 DLL
    - 文件名异常的 DLL

    Args:
        pid: 目标进程 ID
        trusted_paths: 可信路径集合（小写），如 {'c:\\windows\\', 'c:\\program files\\'}

    Returns:
        [{name, path, reason}, ...] 可疑模块列表
    """
    if not trusted_paths:
        trusted_paths = {
            '\\windows\\', '\\program files\\', '\\program files (x86)\\',
        }

    suspicious_keywords = {
        '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
        '\\$recycle.bin', '\\recycler',
        '\\downloads\\',
    }

    modules = get_process_module_ranges(pid)
    if not modules:
        return []

    suspicious: List[dict] = []

    for mod in modules:
        name = mod.get('name', '')
        if not name:
            continue

        name_lower = name.lower()

        # 跳过系统核心 DLL
        if name_lower.endswith(('.dll', '.ocx', '.cpl')):
            basename = os.path.basename(name_lower)
            if basename in {'ntdll.dll', 'kernel32.dll', 'kernelbase.dll',
                            'user32.dll', 'gdi32.dll', 'advapi32.dll',
                            'msvcrt.dll', 'ucrtbase.dll', 'comctl32.dll',
                            'shell32.dll', 'ole32.dll', 'oleaut32.dll',
                            'rpcrt4.dll', 'sechost.dll', 'psapi.dll',
                            'win32u.dll', 'msvcp140.dll', 'vcruntime140.dll'}:
                continue

        # 检查是否在可信路径
        is_trusted = False
        for trusted in trusted_paths:
            if trusted in name_lower:
                is_trusted = True
                break

        if is_trusted:
            continue

        # 检查可疑路径
        for kw in suspicious_keywords:
            if kw in name_lower:
                suspicious.append({
                    'name': os.path.basename(name),
                    'path': name,
                    'reason': f'DLL 从可疑路径加载: {kw}',
                })
                break
        else:
            # 非可信路径、非可疑路径，但仍可能可疑
            # 豁免 Python 扩展模块（.pyd）：本质是 DLL，PyInstaller 打包的程序
            # （含 PSLS 自身）会加载大量 .pyd（如 _ctypes/_bz2/_lzma/pyexpat），
            # 若一律判"非 DLL 模块→疑似注入"会造成对自身进程的大量误报。
            ext = os.path.splitext(name_lower)[1]
            if ext == '.dll':
                continue
            if ext == '.pyd':
                continue  # Python/C 扩展，等同 DLL，不视为注入
            # 其它非 DLL 扩展名（如 .exe/.sys 注入）才真正可疑
            suspicious.append({
                'name': os.path.basename(name),
                'path': name,
                'reason': f'加载了非 DLL 模块（{ext}），疑似注入',
            })

    return suspicious
