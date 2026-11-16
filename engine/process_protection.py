# -*- coding: utf-8 -*-
"""
进程保护引擎
监控系统进程，检测恶意进程、进程注入、保护 PSLS 自身进程不被终止。
基于 psutil 轮询 + Windows API 实现。
"""
import os
import sys
import time
import subprocess
import threading
import re
import traceback
import queue as _queue_mod
from typing import Callable, Dict, List, Optional, Set, Tuple

from utils.logger import get_logger
from utils.initiator_exclusions import get_exclusions

logger = get_logger('process_protection')

# 行为启发分析器(懒加载：不可用时降级为无行为升级，不影响既有判定)
try:
    from engine.behavior_analyzer import BehaviorAnalyzer as _BehaviorAnalyzerCls
except Exception:
    try:
        from behavior_analyzer import BehaviorAnalyzer as _BehaviorAnalyzerCls
    except Exception:
        _BehaviorAnalyzerCls = None

# 账户凭据篡改拦截（非微软官方进程改密码/账户 → 终止）
try:
    from engine.credential_protection import (
        classify_credential_tamper as _classify_credential_tamper,
        check_origin_chain as _check_origin_chain,
        is_microsoft_official_exe_cheap as _is_ms_official_cheap)
except Exception:
    try:
        from credential_protection import (
            classify_credential_tamper as _classify_credential_tamper,
            check_origin_chain as _check_origin_chain,
            is_microsoft_official_exe_cheap as _is_ms_official_cheap)
    except Exception:
        _classify_credential_tamper = None
        _check_origin_chain = None
        _is_ms_official_cheap = None

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


# ---- Windows 线程优先级工具 ----

# SetThreadPriority 常量
_THREAD_PRIORITY_TIME_CRITICAL = 3
_THREAD_PRIORITY_HIGHEST = 2
_THREAD_PRIORITY_ABOVE_NORMAL = 1
_THREAD_PRIORITY_NORMAL = 0

def _boost_current_thread_priority(level: str = 'above_normal') -> bool:
    """提升当前线程优先级（关键监控/拦截线程在高 CPU 负载下不被饿死）

    Args:
        level: 'above_normal'(默认,平衡) / 'highest'(关键拦截) / 'time_critical'(watchdog)

    Returns:
        是否成功
    """
    if not HAS_CTYPES or sys.platform != 'win32':
        return False
    try:
        level_map = {
            'above_normal': _THREAD_PRIORITY_ABOVE_NORMAL,
            'highest': _THREAD_PRIORITY_HIGHEST,
            'time_critical': _THREAD_PRIORITY_TIME_CRITICAL,
        }
        priority = level_map.get(level, _THREAD_PRIORITY_ABOVE_NORMAL)
        kernel32 = ctypes.windll.kernel32
        # 显式声明签名，避免 64 位下参数传递错误
        kernel32.SetThreadPriority.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_int]
        kernel32.SetThreadPriority.restype = ctypes.wintypes.BOOL
        handle = kernel32.GetCurrentThread()
        ok = kernel32.SetThreadPriority(handle, priority)
        return bool(ok)
    except Exception:
        return False


def _get_system_load() -> float:
    """轻量级获取系统当前负载（0~100）

    优先使用 psutil.cpu_percent(interval=None) —— 无阻塞，返回上次调用以来的 CPU 占用。
    首次调用会返回 0.0，需要预热一次再使用。
    """
    if not HAS_PSUTIL:
        return 0.0
    try:
        return float(psutil.cpu_percent(interval=None))
    except Exception:
        return 0.0


# ---- Windows API 常量（用于注入检测）----

# 进程/线程访问权限
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ = 0x0010
_PROCESS_VM_WRITE = 0x0020
_PROCESS_VM_OPERATION = 0x0008
_PROCESS_TERMINATE = 0x0001
_THREAD_QUERY_INFORMATION = 0x0040
_THREAD_TERMINATE = 0x0002
_PROCESS_ALL_ACCESS = 0x001F0FFF

# VirtualFree / VirtualFreeEx 释放类型
_MEM_DECOMMIT = 0x4000
_MEM_RELEASE = 0x8000

# NtQueryInformationThread 的 ThreadInformationClass 参数
# ThreadQuerySetWin32StartAddress = 10 (查询线程起始地址)
_THREAD_QUERY_SET_WIN32_START_ADDRESS = 10
# ThreadBasicInformation = 0 (线程基础信息)
_THREAD_BASIC_INFORMATION = 0

# MEMORY_BASIC_INFORMATION 的 State 常量（用于判断内存类型）
_MEM_COMMIT = 0x1000
_MEM_PRIVATE = 0x20000

# 线程基础信息结构
class _THREAD_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('ExitStatus', ctypes.c_long),
        ('PebBaseAddress', ctypes.c_void_p),
        ('AffinityMask', ctypes.c_void_p),
        ('Priority', ctypes.c_long),
        ('BasePriority', ctypes.c_long),
    ]


# MEMORY_BASIC_INFORMATION（VirtualQueryEx 枚举内存区域）
class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_void_p),
        ('AllocationBase', ctypes.c_void_p),
        ('AllocationProtect', ctypes.c_uint32),
        ('__alignment1', ctypes.c_uint32),
        ('RegionSize', ctypes.c_size_t),
        ('State', ctypes.c_uint32),
        ('Protect', ctypes.c_uint32),
        ('Type', ctypes.c_uint32),
        ('__alignment2', ctypes.c_uint32),
    ]


# ---- 可疑进程特征 ----

# 常见恶意软件伪装名（小写匹配）
# 仅包含真正的混淆/伪装名，避免误报正常进程
SUSPICIOUS_PROCESS_NAMES: Set[str] = {
    'svch0st', 'svhost', 'expl0rer', 'explorar',
    'winlog0n', 'rund1l32', 'rundl132',
    'c0m', 'c0md', 'c0mmand',
    'powersh3ll', 'p0wershell',
    'mshta', 'scr0n',
    'lssas', 'isass', 'csrss.exe.exe',
}

# 常见合法进程白名单（不报警）
TRUSTED_PROCESSES: Set[str] = {
    'system', 'system idle process', 'registry',
    'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
    'lsass.exe', 'svchost.exe', 'spoolsv.exe', 'explorer.exe',
    'winlogon.exe', 'sihost.exe', 'taskhostex.exe', 'tasklist.exe',
    'conhost.exe', 'dwm.exe', 'rdpclip.exe', 'ctfmon.exe',
    'dllhost.exe', 'chime.exe', 'audiodg.exe', 'lsass.exe',
    'wmiadap.exe', 'wmiprvse.exe', 'searchindexer.exe',
    'searchprotocolhost.exe', 'powershell.exe', 'pwsh.exe',
    'cmd.exe', 'notepad.exe', 'calc.exe', 'mspaint.exe',
    'wordpad.exe', 'writer.exe', 'ONENOTE.EXE',
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe',
    'code.exe', 'pycharm64.exe', 'idea64.exe', 'webstorm64.exe',
    'python.exe', 'pythonw.exe', 'python3.exe', 'python3w.exe',
    'java.exe', 'javaw.exe', 'node.exe', 'npm.exe',
    'docker.exe', 'docker desktop.exe', 'vpnclient.exe',
    'wechat.exe', 'qq.exe', 'tim.exe', 'dingtalk.exe',
    'netease cloud music.exe', 'cloudmusic.exe',
    'psls.exe', 'project sertraline lab',
}

# 危险目录（从这些位置运行的进程可能可疑）
DANGEROUS_DIR_KEYWORDS: List[str] = [
    '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
    '\\appdata\\local\\microsoft\\windows\\inetcache\\',
    '\\appdata\\local\\microsoft\\windows\\temporary internet files\\',
    '\\recycler', '\\$recycle.bin',
    '\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\',
    '\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\',
]

# 高频 CPU 占用阈值（%）
HIGH_CPU_THRESHOLD = 80

# 监控轮询间隔（秒）
# ETW 事件驱动已将延迟降到 <500ms；纯轮询模式下此值是最坏延迟
# 旧值 0.5s/高负载 0.25s 与 ETW 通道高度冗余，且高负载下越忙轮询越频繁，
# 使"高 CPU 自适应"陷入恶性循环：0.25s 全量进程枚举本身就占满一个核心，
# 反过来把系统负载进一步推高。正常负载 1.5s 轮询的新进程检测延迟
# 依旧可接受（ETW/WTS 事件通道 <1s 兜底）。
_MONITOR_INTERVAL = 1.5

# 句柄审计双信号 TTL（秒）：内核 OB_CALLBACKS 事件后，该 (source,target)
# 关系在多久窗口内仍可支撑"双信号注入判定"。与驱动端 30s 退役周期对齐。
_OB_AUDIT_TTL = 30.0

# ---- 高 CPU 自适应常量 ----
# 系统 CPU 负载超过此阈值（%）时进入"保护模式"：
# - 关键路径（新进程检测）保持可用，但主动降频为系统减负
# - 非关键路径（注入检测、行为检测）跳过/延后
_HIGH_CPU_LOAD_THRESHOLD = 70.0
# 高 CPU 下轮询间隔拉长（主动降频削减自身负载，打破"轮询风暴"恶性循环）；
# 新进程检测延迟由 ETW/WTS 事件通道（<1s）承接
_MONITOR_INTERVAL_HIGH_CPU = 2.0
# 正常 CPU 下注入检测频率（每 N 轮一次 ≈ N * 1.5 秒）
_INJECTION_CHECK_INTERVAL_NORMAL = 8  # ≈ 12 秒
# 高 CPU 下注入检测频率（延后，让出 CPU 给关键路径）
_INJECTION_CHECK_INTERVAL_HIGH_CPU = 20  # ≈ 40 秒
# 注入检测每周期最多审计的进程数（round-robin 轮转，控制单次 CPU 尖峰）
_INJECTION_MAX_PROCESSES_PER_CYCLE = 50

# 进程缓存过期时间（秒）
_PROCESS_CACHE_TTL = 30


class LaunchScanResult(dict):
    """启动监测扫描结果载体（dict 子类，兼容 JSON 序列化与 .get() 访问）。

    由 _check_new_process / _sandbox_then_release 构造，作为 scan_result 传入
    _notify_launch_monitoring，最终经 bridge 广播给前端启动监测记录。
    此前该名称从未定义导致三处调用点抛 NameError：
      - 豁免路径（沙箱内部/进程族）启动监测通知直接中断
      - 沙箱拦截终态刷新（scanning → blocked/quarantined）失败
    """

    def __init__(self, status='clean', verdict=None, score=0,
                 signatures=None, file_path='', **extra):
        data = {
            'status': status,
            'score': score,
            'signatures': list(signatures or []),
        }
        if verdict is not None:
            data['verdict'] = verdict
        if file_path:
            data['file_path'] = file_path
        data.update(extra)
        super().__init__(data)


class ProcessProtection:
    """
    进程保护引擎

    功能：
    1. 进程监控：通过 ETW/WMI 实时事件 + psutil 轮询双轨检测可疑进程
    2. 注入检测：检测进程是否被远程线程注入（线程起始地址 + 模块枚举）
    3. 自我保护：防止 PSLS 自身进程被强制终止
    4. 行为分析：检测高 CPU 占用、从危险目录运行等异常行为
    """

    def __init__(self, signature_db=None,
                 on_threat: Callable[[dict], None] = None,
                 scan_engine_factory: Callable = None,
                 quarantine_manager=None,
                 auto_action: str = 'notify',
                 on_launch_scan: Callable[[dict], None] = None,
                 on_sandbox_block: Callable[[dict], None] = None,
                 on_sandbox_release_request: Callable[[dict], None] = None,
                 on_sandbox_analysis_start: Callable[[str], None] = None,
                 on_sandbox_analysis_progress: Callable[[str, float], None] = None,
                 on_sandbox_analysis_done: Callable[[str, str], None] = None,
                 driver_terminate_by_path_hook: Callable[[str], bool] = None,
                 on_process_created_hook: Callable[[int, str], None] = None,
                 mbr_arm_before_kill_hook: Callable[[str], None] = None,
                 mbr_verify_after_kill_hook: Callable[[str], None] = None,
                 visual_prank_observer: Callable[[int, str, str, Optional[List[str]]], None] = None):
        """
        Args:
            signature_db: 签名数据库实例（用于哈希比对）
            on_threat: 检测到威胁时的回调
            scan_engine_factory: 创建 ScanEngine 实例的工厂函数（用于深度扫描进程文件）
            quarantine_manager: 隔离管理器（用于自动隔离威胁文件）
            auto_action: 自动处理策略 'auto'(自动隔离+终止) / 'notify'(仅告警) / 'ignore'
            on_launch_scan: 启动扫描结果回调，当扫描结果非 clean 时调用
            on_sandbox_block: 沙箱拦截回调，沙箱判定恶意/可疑时调用（用于弹窗通知）
            on_sandbox_release_request: 沙箱判定安全后请求用户确认是否重启进程
            on_sandbox_analysis_start: 沙箱分析开始回调（exe 路径），用于显示分析窗口
            on_sandbox_analysis_progress: 沙箱分析进度回调 (stage, percent 0-1)
            on_sandbox_analysis_done: 沙箱分析完成回调 (exe, verdict)，用于关闭分析窗口
            driver_terminate_by_path_hook: 可选驱动层强制终止回调，签名 (exe_path:str)->bool；
                沙箱判定 malware 时先通过 Ring0 驱动杀一遍，再走用户态终止兜底。
            on_process_created_hook: 可选回调 (pid:int, exe_path:str)->None，
                在每次 ETW 进程创建事件时调用（做"进程触发式"关键目录保护等联动，
                注意：该回调处于进程保护子线程中，实现需自行保证线程安全）。
        """
        self._signature_db = signature_db
        self._on_threat = on_threat
        self._scan_engine_factory = scan_engine_factory
        self._quarantine_manager = quarantine_manager
        self._auto_action = auto_action
        self._on_launch_scan = on_launch_scan
        self._on_sandbox_block = on_sandbox_block
        self._on_sandbox_release_request = on_sandbox_release_request
        self._on_sandbox_analysis_start = on_sandbox_analysis_start
        self._on_sandbox_analysis_progress = on_sandbox_analysis_progress
        self._on_sandbox_analysis_done = on_sandbox_analysis_done
        # 驱动层按路径强制终止（由桥接层注入；为空时仅走用户态终止兜底）
        self._driver_terminate_by_path_hook = driver_terminate_by_path_hook
        # 进程创建事件钩子（用于关键目录保护进程触发式防御）
        self._on_process_created_hook = on_process_created_hook
        # 自爆式病毒防护钩子（桥接层注入）：
        # - 终止前加固 MBR/引导保护（确保备份存在）
        # - 终止后立即校验并回滚引导扇区（不等 0.25s 轮询窗口）
        self._mbr_arm_before_kill_hook = mbr_arm_before_kill_hook
        self._mbr_verify_after_kill_hook = mbr_verify_after_kill_hook
        # 静态预分析缓存：{norm_exe: (mtime, probe_result, ts)}，TTL 内复用，
        # 避免同一文件反复启动/终止时重复读盘反编译
        self._pre_kill_probe_cache: Dict[str, tuple] = {}
        self._pre_kill_probe_lock = threading.Lock()
        # 视觉恶搞检测观察者：非信任 PE 启动时注册到 VisualPrankDetector
        # 观察集合（kill-then-ask 询问重启前，由检测器接管行为审计）
        self._visual_prank_observer = visual_prank_observer

        # 视觉恶搞处置的 exe 独占锁注册表：命中即杀后、询问期间持有，
        # 信任重启/取消后释放（防止询问窗口期间用户重复启动）
        self._prank_locks: Dict[str, tuple] = {}
        self._prank_locks_lock = threading.Lock()
        # 用户信任缓存：{abs_norm_path: ts}，信任重启后 30 分钟内不再拦截
        self._prank_trusted: Dict[str, float] = {}
        self._prank_trusted_lock = threading.Lock()
        # 沙箱拦截时对 exe 文件登记的独占锁注册表：{abs_norm_path:(file_obj, ts)}，
        # 保证处置期间（弹窗等待/用户决策）用户无法再次启动该 exe
        self._sandbox_locks: Dict[str, tuple] = {}
        self._sandbox_locks_lock = threading.Lock()
        self._sandbox_lock_max_seconds = 180  # 3 分钟绝对兜底释放，防止 UI 忘记释放
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_heartbeat = 0.0  # 监控线程最后心跳时间戳
        self._watchdog_thread: Optional[threading.Thread] = None

        # ETW 实时监控（WMI 事件订阅，替代纯轮询）
        self._etw_monitor = None
        self._etw_pids_checked: Set[int] = set()  # ETW 已检查过的 PID（避免重复）
        self._etw_lock = threading.Lock()  # 保护 _etw_pids_checked 的线程安全

        # 进程快照（上次扫描的 PID -> 基本信息映射）
        self._process_snapshot: Dict[int, dict] = {}
        self._snapshot_lock = threading.Lock()

        # 注入检测轮转游标：每周期仅深度审计一部分进程（round-robin），
        # 避免一次性对全部进程做 memory_maps/线程枚举造成 CPU 尖峰
        self._injection_scan_offset = 0

        # 句柄审计双信号表: (source_pid, target_pid) -> {ts, access, count,
        # first_ts}。由内核 OB_CALLBACKS 句柄审计事件填充
        # (on_handle_audit_event, 驱动事件循环线程跨线程写入)，
        # 超过 _OB_AUDIT_TTL 惰性过期。_check_injections 周期性巡检时，
        # 把"行为特征(远线程/RWX/镂空/可疑模块) + 句柄审计信号"作为
        # 双信号注入判定：句柄审计支持的行为命中可降级阈值(误差更小)，
        # 行为命中时在告警 detail 中标注审计来源提升可解释性。
        self._ob_inject_observed: Dict[tuple, dict] = {}
        self._ob_inject_lock = threading.Lock()

        # ---- 银狐断网型反制：DropperMonitor（A：文件落地实时监视）----
        # 监视 AppData/Temp/Downloads/ProgramData/Desktop 可执行落地
        self._dropper_monitor: Optional[object] = None

        # ---- 落地-加载-持久化链路评分（C）----
        # key = 文件路径(normcase lower)，值 = {ts, drop, load, host,
        #   size, disposed}。信号来源：
        #   落地(drop+2):     DropperMonitor 回调 _on_dropped_file_cb
        #   加载(load+3):     on_image_load_event 命中链中文件的 DLL 加载
        #   宿主(host+2):     加载该文件的进程自身已被启动送检判定为威胁
        # 总分 ≥ _DROPLOAD_CHAIN_THRESHOLD → "银狐落地执行链"高置信告警+隔离。
        # 防误报：有有效签名/白名单哈希的文件在 _async_scan_launch 内被放行，
        # 链只在"无签名未知文件"上累积。
        self._dropload_chain: Dict[str, dict] = {}
        self._dropload_chain_lock = threading.Lock()

        # ---- 行为启发分析器(懒创建)：行为序列证据源 ----
        self._behavior_analyzer = None
        self._behavior_analyzer_lock = threading.Lock()
        # 升级1: 内核事件驱动 — 驱动事件是否已激活。
        # 激活后 _monitor_loop 不再靠 1s 逐进程枚举喂入新进程(由驱动/ETW事件喂入),
        # 轮询降为驱动缺失时的 fallback。注入检测同由 HandleAudit 事件驱动。
        self._driver_active = False
        # 白加黑 image_load 送检节流：pid -> {ts, count}
        # 防止初始化期 DLL 风暴（事件本身已被内核 150ms 聚合，这里再限流）
        self._imgload_throttle: Dict[int, dict] = {}
        self._imgload_throttle_lock = threading.Lock()

        # 当前系统进程集合
        self._known_pids: Set[int] = set()

        # 启动扫描缓存：exe_path -> (mtime, status, scan_time)
        # 避免对同一文件重复扫描（1 小时 TTL）
        self._launch_scan_cache: Dict[str, tuple] = {}
        self._launch_scan_lock = threading.Lock()
        self._LAUNCH_SCAN_CACHE_TTL = 3600  # 1 小时

        # --- 同 exe 终止失败冷却（防"杀→唤→再杀"死循环）---
        # 强自我保护进程（如卡巴斯基 avp.exe）杀不掉且会被父进程自动重启，
        # 若不冷却会形成 taskkill/枚举 无限重试，拖垮 CPU 造成 PSLS 未响应。
        # 按 exe 路径记录上次"仍有剩余实例"的时间戳，冷却窗口内直接跳过枚举。
        self._tii_last_fail: Dict[str, float] = {}
        self._tii_lock = threading.Lock()
        self._TII_RETRY_COOLDOWN = 30.0  # 秒

        # --- 上下文信任评估（多维度防误报）---
        # 综合 进程来源/数字签名/行为链/父子进程关系/文件年龄/上下文逻辑
        # 六维给新进程算信任分，用于：
        #   1. trust >= _CTRUST_SKIP_SANDBOX → 用户主动启动的老文件/可信背景
        #      程序直接放行（不终止、不沙箱、写 clean 缓存防止重复打扰）
        #   2. trust >= _CTRUST_MITIGATE_MIN → 仍送沙箱，但作为"调查先验"
        #      降低分数型判定，改器/正常软件不再被误隔离
        # 安全底线：一票否决硬证据（勒索/删除卷影/银狐）永不因信任豁免。
        self._CTRUST_SKIP_SANDBOX = 60      # 跳过终止+沙箱的信任阈值
        self._CTRUST_MITIGATE_MIN = 35      # 启用沙箱分数偏移的最低信任
        self._CTRUST_FILE_AGE_THRESHOLDS = [
            (30 * 86400, 25),  # ≥30 天
            (14 * 86400, 20),  # ≥14 天
            (7 * 86400, 15),   # ≥7 天
            (3 * 86400, 8),    # ≥3 天
            (1 * 86400, 3),    # ≥1 天
        ]
        # 可信用户交互宿主（用户主动双击/命令行启动早祖先）
        self._CTRUST_USER_HOSTS = (
            'explorer.exe', 'windows explorer', 'windowstermi',
            'cmd.exe', 'powershell.exe', 'pwsh.exe', 'dllhost.exe',
            'runtimebroker.exe', 'chome.exe',
        )

        # 启动扫描并发控制：最多 2 个并发扫描，避免短时间大量新进程启动时资源耗尽
        # Windows 开机/用户登录时会在几秒内启动数十个进程，无限制并发会卡死
        self._launch_scan_sem = threading.Semaphore(2)
        # 沙箱并发控制：最多 2 个沙箱同时运行
        # 每个沙箱需要 30s + 临时进程 + CPU/内存，无限制并发会导致系统资源耗尽
        # 之前全部非白名单进程走沙箱链路后，短时间启动大量进程会同时开 10+ 个沙箱，
        # 直接把 CPU/内存耗尽，导致 QtWebEngine 渲染超时 → PSLS 显示"未响应"
        self._sandbox_sem = threading.Semaphore(2)
        # 沙箱排队上限：超过则直接拦截（不排队），避免无限等待
        self._sandbox_queue_limit = 10

        # --- 沙箱分析中的路径豁免表 — 防止沙箱内部被测进程再次被自己拦截 ---
        # 场景：_sandbox_worker 调用 SandboxAnalyzer.analyze(exe) 时，分析器内部会用
        # CreateProcessW 真正拉起该 exe 到隔离 Job（这是合法的"分析行为启动"）；
        # 但 ETW 仍会看到新进程创建事件，若无豁免会再次走 _sandbox_then_release，
        # 造成"同一 exe 先后出现多条 scanning + 多次 ERROR 沙箱拦截"。
        self._sandbox_analyzing_paths: Set[str] = set()
        self._sandbox_analyzing_paths_lock = threading.Lock()
        # ---- Sandboxie 分析盒 PID 列表缓存（用于沙箱逃逸判定）----
        # 被分析目标的运行路径若出现在"盒外"（PID 不在盒 PID 列表里），
        # 说明它以提权/runas 方式脱离了沙箱在宿主运行 → 必须立即终止。
        # 带 1s TTL，避免 ETW 高频回调里反复起子进程查询；查询失败置空集。
        self._sbie_box_pids_cache: Set[int] = set()
        self._sbie_box_pids_ts: float = 0.0
        self._sbie_box_pids_lock = threading.Lock()
        # ---- 已被拦截程序路径黑名单（阻断 runas 自提权重启"逃逸"）----
        # 实测两个样本都用 `runas` 自提权重启自己：提权实例是**同路径的新进程**
        # （新 PID），且会脱离 Sandboxie 分析盒在宿主运行。旧实现只按"正在沙箱
        # 分析的路径"判逃逸，而 >50MB 走 oversize 分支时路径从未登记 → 完全漏判，
        # 提权实例自由运行（写 PhysicalDrive0 / 关防火墙 / 改登录密码）。
        # 现改为：凡被 PSLS 终止过的非信任程序，其路径进入黑名单（TTL 15 分钟）；
        # 该路径的任何新实例（除沙箱盒内实例）立即终止。
        self._blocked_exe_paths: Dict[str, float] = {}
        self._blocked_exe_lock = threading.Lock()
        self._BLOCKED_EXE_TTL = 900.0
        # 单条 analyzing 绝对兜底时间（秒）：正常 worker 在 finally 中清除；
        # 崩溃未清理的条目通过 _cleanup_expired_sandbox_analyzing 周期清理。
        self._sandbox_analyzing_deadline: Dict[str, float] = {}
        # ---- 目录前缀豁免：沙箱把样本复制到 %TEMP%/psls_sandbox_<rand>/
        # sample_*.exe 后启动，ETW 报告的副本路径 != 原始路径。仅登记原始
        # exe 无法匹配副本，会造成二次拦截 → 循环沙箱。
        # 这里保存【规范化的绝对路径目录前缀 + TTL deadline】，
        # _is_sandbox_analyzing 对每个查询做 exe.lower().startswith(prefix)。
        self._sandbox_analyzing_dirs: List[str] = []
        self._sandbox_analyzing_dir_deadline: Dict[str, float] = {}
        # ---- 沙箱目标 PID 集合：SandboxAnalyzer 启动目标进程 PID=XYZ，
        # 后续其子孙进程（parent_pid in set）即便落地到 用户目录 下任意
        # 路径，也应在行为监控(psutil/frida)内观察而非再次被 ProcessProtection
        # 挂起二次沙箱（Job 嵌套会失败或死锁）。
        self._sandbox_target_pids: Set[int] = set()
        self._sandbox_target_pid_deadline: Dict[int, float] = {}
        # 启动扫描的大文件硬上限（256MB，与实时防护 RT_MAGIC_MAX_FILE_SIZE 对齐）
        # 旧值 50MB 且"超过即缓存 clean 放行"→ 下载来的大体积木马（实测 77MB 的
        # Keplerians 样本）完全无防护。现改为：未超此上限照常送引擎深度扫描；
        # 超过则至少做哈希判定，且**不再写 clean 缓存**。
        self._LAUNCH_SCAN_MAX_FILE_SIZE = 256 * 1024 * 1024
        # 启动扫描超时时间（秒）：单个文件扫描超过此时间则放弃，避免永久阻塞
        self._LAUNCH_SCAN_TIMEOUT = 30

        # ---- 银狐落地执行链（DropperMonitor + image_load）常量 ----
        # 链路 TTL（秒）：落地记录在多久窗口内有效（银狐落地→加载通常 <10s，
        # 留 10 分钟余量覆盖分批提取场景）
        self._DROPLOAD_CHAIN_TTL = 600
        # 链阈值：落地(2)+加载(3)=5 即成立；宿主恶意(+2)用于强化链
        self._DROPLOAD_CHAIN_THRESHOLD = 5
        # image_load 送检节流：30s 窗口内每个 PID 最多送检的 DLL 数
        self._IMGLOAD_THROTTLE_TTL = 30
        self._IMGLOAD_THROTTLE_MAX = 3

        # 共享 ScanEngine 实例（避免每次扫描都重新初始化签名库/YARA/ML）
        # 由 _launch_scan_engine_lock 保护，启动扫描复用此实例
        self._launch_scan_engine = None
        self._launch_scan_engine_lock = threading.Lock()
        # 当前正在扫描的文件集合，避免同一文件被多个线程同时扫描
        self._launch_scan_inflight: Set[str] = set()
        self._launch_scan_inflight_lock = threading.Lock()

        # ================================================================
        # 新进程事件「线程分离调度队列」
        #
        # 背景：ETW 回调线程 / 驱动 procmon 事件消费线程 / psutil 轮询线程里，
        # 直接调用 _check_new_process 会同步执行以下潜在阻塞/重型操作，
        # 导致 PSLS 在"未知应用启动"时被 Windows 标记为「未响应」：
        #   * get_signer_info — 300ms 冷启动 PowerShell 子进程
        #   * _emergency_kill — OpenProcess/TerminateProcess 句柄竞争
        #   * _lock_file_exclusive — share=0 独占锁(可能被AV/Defender占用自旋)
        #   * shutil.copy2 — 400MB+ 预复制阻塞数百毫秒
        #   * proc.cmdline() / psutil.Process(...) — 权限受限进程挂起 1~3 秒
        #   * _on_launch_scan callback → bridge._add_activity → _signal_lock 重持锁
        #   * quick_injection_check — 枚举线程 + VirtualQueryEx(每个内存块系统调用)
        #   * 启动监测活动日志的 JSON 序列化
        #
        # 设计：入口(_on_etw_process_created / on_driver_process_create_event /
        # 轮询 _monitor_loop 的新进程分支)只做：规范化→入队→立即 return。
        # 真正的判定由 _launch_check_worker_threads (默认 3 条) 消费。
        # 队列有界(256)，满了丢弃老条目；同一(pid,path)在短窗口内重复
        # 入队被 _launch_check_dedup 合并为一条。
        # ================================================================
        self._launch_check_queue: '_queue_mod.Queue[dict]' = _queue_mod.Queue(maxsize=256)
        self._launch_check_dedup: Dict[Tuple[int, str], float] = {}
        self._launch_check_dedup_lock = threading.Lock()
        self._launch_check_worker_count = 3
        self._launch_check_worker_threads: List[threading.Thread] = []
        self._launch_check_dedup_ttl = 3.0  # 同 (pid,path) 3 秒只处理一次
        # 每工作项绝对时限（从入队开始算）：超过此时间仍没被 worker 拿到，
        # 或执行中途超过此绝对时限时主动跳过，避免工作线程永久卡住。
        self._launch_check_item_deadline = 8.0

        # ================================================================
        # EK 快车道（敏感命令专用，与主 worker 池**物理隔离**）
        # ----------------------------------------------------------------
        # 问题（实测结构性）：主池只有 3 条线程，而单条 _check_new_process 要串行
        # 跑 签名校验(≤1.5s) + 注入预检(≤1.2s) + 上下文注入检查(≤1.2s) + 沙箱链路
        # (自爆预分析 ≤1.2s，补杀最坏 5s)。样本一次性派生 cmd/net/netsh/powershell
        # 多个子进程时，后面的条目在队列里排到 8s deadline 过期 → 被 `continue`
        # **直接丢弃（连检查都没有，自然没有 emergency kill）**；执行中的条目也会
        # 被看门狗放弃。表现就是"EK 不及时 / 根本没杀"。
        # 解决：把**敏感命令**（net user / netsh / net stop / takeown 链 / vssadmin…）
        # 从主池摘出来，交给 4 条独立线程 + 256 槽队列 + 短 deadline，
        # **time_critical 优先级 + SeDebugPrivilege 权限**，独占执行
        # "零 IO 强信号立即终止 → 再判发起链 → BT 兼容处置"，不与沙箱分析抢主池。
        # 只做 µs 级正则判定后投递；未命中敏感命令的进程仍走主池（行为不变）。
        # ================================================================
        self._ek_queue: '_queue_mod.Queue[dict]' = _queue_mod.Queue(maxsize=256)
        self._ek_worker_threads: List[threading.Thread] = []
        self._ek_handled_pids: Dict[int, float] = {}
        self._ek_handled_lock = threading.Lock()
        self._EK_WORKER_COUNT = 4           # 突发子进程风暴也不丢项
        self._EK_ITEM_DEADLINE = 5.0        # 快车道工作项绝对时限（比主池短）
        self._EK_HANDLED_TTL = 60.0         # 已由快车道处置过的 pid 记忆窗口

        # 启动存量进程扫描：PSLS 启动时已存在的进程不会产生"新进程"事件，
        # 启动后 delay_s 秒一次性枚举并复用启动监测判定链路（survey 模式），
        # 仅对静态判定可疑的存量进程执行终止+询问（绝不全部清杀）。
        self._startup_survey_started = False
        self._startup_survey_delay = 20.0

        # 统计数据
        self._stats = {
            'processes_monitored': 0,
            'threats_detected': 0,
            'injections_detected': 0,
            'self_protections': 0,
            'started_at': 0,
            'check_count': 0,
        }
        self._stats_lock = threading.Lock()

        # 最近事件
        self._recent_events: List[dict] = []
        self._events_lock = threading.Lock()
        self._max_events = 200

        # 受保护的进程名（PSLS 自身）
        self._protected_names: Set[str] = set()
        self._self_excluded_dirs: Set[str] = set()
        # 发起者排除名单（可配置：内置项 + 用户项 + 宿主目录动态项）
        # 命中即跳过用户态处置（沙箱/终止/隔离），但内核侧硬规则不受影响。
        self._initiator_exclusions = get_exclusions()
        self._register_self()

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

    def _add_event(self, event_type: str, pid: int, name: str,
                   status: str, detail: str = '', path: str = ''):
        ev = {
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'type': event_type,
            'pid': pid,
            'name': name,
            'status': status,
            'detail': detail,
            'path': path,
        }
        with self._events_lock:
            self._recent_events.append(ev)
            if len(self._recent_events) > self._max_events:
                self._recent_events = self._recent_events[-self._max_events:]
        logger.info(f"[进程保护] {event_type} PID={pid} {name} [{status}] {detail}")

    def _report_threat(self, threat_data: dict):
        with self._stats_lock:
            self._stats['threats_detected'] += 1
        # 全量威胁 trace：记录每次威胁上报的 PID/类型/路径，用于排查
        # "威胁对象恰为自身"导致的静默自我终止（无日志死亡）。
        logger.info(
            f'[威胁上报] type={threat_data.get("type")!r} '
            f'pid={threat_data.get("pid")} name={threat_data.get("name")!r} '
            f'path={threat_data.get("path")!r}')
        self._add_event(
            threat_data.get('type', 'threat'),
            threat_data.get('pid', 0),
            threat_data.get('name', ''),
            'threat',
            threat_data.get('detail', ''),
            threat_data.get('path', ''),
        )
        if self._on_threat:
            try:
                self._on_threat(threat_data)
            except Exception as e:
                logger.error(f"on_threat 回调异常: {e}")

        # 自动处理：注入类威胁优先"剥离+验证"，验证不过再杀进程；
        # 其余威胁（签名确认/行为异常）直接杀进程
        if self._auto_action == 'auto':
            if threat_data.get('type') in (
                    'remote_thread_injection', 'shellcode_injection',
                    'process_injection', 'process_hollowing'):
                self._handle_injection_threat(threat_data)
            else:
                self._auto_handle_threat(threat_data)

    def _auto_handle_threat(self, threat_data: dict):
        """自动处理威胁 — **杀进程优先，扫描/隔离异步跟进**

        旧版问题：签名确认的恶意进程也要先 ScanEngine() 初始化(158ms) + 扫描
        再杀进程 — 恶意进程在这 160ms+ 里已经可以执行任何payload。

        新版处置顺序（追求 1ms 内 kill）：
        1. 签名已确认（malware_process）→ 立即 kill_process(force=True, timeout=1s)
           **完全跳过深度扫描**，签名匹配就是铁证，不需要再扫一次
        2. 行为检测威胁（suspicious/injected/伪装名）→ 立即 kill_process
           （行为异常本身就是铁证，先杀再说，不让它继续跑）
        3. kill 成功后，隔离文件 → 如果是行为检测威胁，后台线程再做一次
           深度扫描确认文件是否恶意（只影响是否隔离，不影响已终止的进程）

        关键优化点：
        - kill 等待 timeout 从 5s 降到 1s（不再傻等进程优雅退出，强杀足够了）
        - 隔离放到后台线程（隔离可能因文件占用/沙箱等慢，绝不阻塞主线程/回调链）
        """
        pid = threat_data.get('pid', 0)
        exe_path = threat_data.get('path', '')
        threat_type = threat_data.get('type', '')
        name = threat_data.get('name', '')

        if not exe_path or not os.path.isfile(exe_path):
            return

        is_confirmed_malware = threat_type == 'malware_process'
        is_behavioral_threat = not is_confirmed_malware

        # ========= 阶段 1：紧急杀进程（<1ms，直接 TerminateProcess）=========
        if pid > 0:
            t0 = time.perf_counter()
            try:
                # 紧急终止：直接 TerminateProcess，不等 wait，<1ms 返回
                self._emergency_kill(pid)
                dt = (time.perf_counter() - t0) * 1000
                tag = '[签名确认]' if is_confirmed_malware else '[行为检测]'
                logger.info(
                    f"已紧急终止威胁进程 {name} (PID={pid}) {tag} 耗时 {dt:.0f}ms")
                # 标记已由 ProcessProtection 完成杀进程，bridge 无需再重复
                threat_data['_pp_handled_kill'] = True
            except Exception as e:
                logger.error(f"紧急终止进程失败 PID={pid}: {e}")
                return  # 杀不掉就隔离也没用，放弃

        # ========= 阶段 2：异步跟进隔离/确认（后台线程，不阻塞）=========
        def _async_followup():
            try:
                # 2.0 后台清理进程树（紧急终止只杀了主进程，子进程可能残留）
                if pid > 0:
                    try:
                        self.kill_process(pid, force=True, kill_tree=True, timeout=3.0)
                    except Exception:
                        pass
                scan_result = None

                # 只有行为检测威胁（签名没命中）才需要扫描确认文件是否真恶意
                # 签名已命中的文件直接隔离，不需要再扫
                if is_behavioral_threat and self._scan_engine_factory:
                    try:
                        engine = self._scan_engine_factory()
                        if engine:
                            scan_result = engine.scan_file_with_archives_summary(exe_path)
                            threat_data['scan_result'] = scan_result
                            threat_data['behavioral_threat'] = True
                            scan_status = scan_result.get('status', 'clean')
                            if scan_status in ('malware', 'suspicious'):
                                threat_data['detail'] = (
                                    f"{threat_data.get('detail', '')} "
                                    f"[深度扫描确认: {scan_result.get('name', scan_status)}]"
                                )
                                is_confirmed_malware = True
                    except Exception as e:
                        logger.warning(f"行为检测威胁的事后扫描失败: {e}")

                # 隔离文件
                if is_confirmed_malware and self._quarantine_manager:
                    try:
                        result = self._quarantine_manager.quarantine_file(
                            exe_path,
                            reason=f"进程保护自动隔离: {threat_data.get('detail', '')}",
                            malware_name=threat_data.get('signature', {}).get(
                                'name',
                                threat_data.get('scan_result', {}).get('name',
                                    'Behavioral.Threat')
                            ),
                        )
                        if result is True:
                            logger.info(f"已隔离威胁文件: {exe_path}")
                        elif result == 'duplicate':
                            logger.info(f"文件已在隔离区，跳过重复隔离: {exe_path}")
                        elif result == 'exempted':
                            logger.info(f"文件已豁免（已恢复），跳过: {exe_path}")
                        else:
                            logger.warning(f"隔离失败，尝试删除: {exe_path}")
                            try:
                                os.remove(exe_path)
                            except Exception:
                                pass
                    except Exception as e:
                        logger.error(f"隔离文件失败 {exe_path}: {e}")
                elif is_behavioral_threat:
                    logger.info(
                        f"行为检测威胁已终止，文件扫描后为 clean，跳过隔离: {exe_path}")

            except Exception as e:
                logger.error(f"_auto_handle_threat 异步跟进异常: {e}")

        # 异步跟进 —— 守护线程，进程退出自动终止
        t = threading.Thread(
            target=_async_followup,
            name=f'auto-followup-{pid}',
            daemon=True,
        )
        t.start()

    # ---- 注入处置：剥离 + 验证 ----

    def _handle_injection_threat(self, threat_data: dict):
        """注入类威胁处置：先剥离注入，验证宿主进程干净则保留，否则杀进程。

        剥离 = 终止可疑远程线程 + 释放 RWX 私有可执行内存（尽量保留宿主进程）。
        验证 = 剥离后重检注入特征，仍存在或宿主进程已崩溃则回退杀进程。

        仅在 auto_action == 'auto' 时由 _report_threat 调用。
        """
        pid = threat_data.get('pid', 0)
        name = threat_data.get('name', '')
        if not pid or pid <= 0:
            self._auto_handle_threat(threat_data)
            return

        # 阶段1：剥离注入
        strip_ok, strip_detail = self._strip_injection(pid, threat_data)
        if strip_ok:
            # 阶段2：短暂等待剥离生效后验证宿主进程
            time.sleep(0.5)
            if not self._has_injection_features(pid):
                # 剥离成功且宿主进程已干净 → 保留宿主进程
                threat_data['_pp_stripped'] = True
                self._add_event(
                    'injection_stripped', pid, name, 'clean',
                    f'已剥离注入，宿主进程保留: {strip_detail}')
                logger.info(
                    f"已剥离 PID={pid} {name} 的注入，宿主进程保留: {strip_detail}")
                return

        # 阶段3：剥离失败/验证未过 → 回退杀进程
        logger.warning(
            f"剥离注入未通过验证，回退杀进程 PID={pid} {name}: {strip_detail}")
        self._auto_handle_threat(threat_data)

    def _strip_injection(self, pid: int, threat_data: dict) -> Tuple[bool, str]:
        """剥离注入：终止可疑远程线程 + 释放注入的 RWX 私有内存。

        仅针对明确的可疑部分（未知起始地址的线程 + 私有 RWX 可执行页），
        尽量不影响宿主进程的正常线程与模块。

        Returns:
            (是否执行了剥离动作, 描述)
        """
        if not HAS_CTYPES or sys.platform != 'win32':
            return False, '非 Windows 平台，无法剥离'
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

        proc_handle = kernel32.OpenProcess(
            _PROCESS_QUERY_INFORMATION | _PROCESS_VM_OPERATION |
            _PROCESS_VM_READ | _PROCESS_VM_WRITE | _PROCESS_TERMINATE,
            False, pid)
        if not proc_handle:
            return False, f'无法打开进程句柄 (err={ctypes.get_last_error()})'

        stripped = 0
        detail = []
        try:
            # ---- 1. 终止可疑远程线程 ----
            try:
                proc = psutil.Process(pid)
                threads = proc.threads()
            except Exception:
                threads = []
            known_ranges = self._get_known_module_ranges(proc, kernel32)
            for t in threads:
                tid = t.id
                h_thread = kernel32.OpenThread(
                    _THREAD_QUERY_INFORMATION | _THREAD_TERMINATE, False, tid)
                if not h_thread:
                    continue
                try:
                    start_addr = ctypes.c_void_p()
                    status = ntdll.NtQueryInformationThread(
                        h_thread, _THREAD_QUERY_SET_WIN32_START_ADDRESS,
                        ctypes.byref(start_addr), ctypes.sizeof(start_addr), None)
                    if status == 0 and start_addr.value:
                        sv = start_addr.value
                        if 0 < sv < (1 << 47) and \
                                not self._is_address_in_known_module(sv, known_ranges):
                            if kernel32.TerminateThread(h_thread, 0):
                                stripped += 1
                finally:
                    kernel32.CloseHandle(h_thread)

            if stripped:
                detail.append(f'终止 {stripped} 个可疑线程')

            # ---- 2. 释放 RWX 私有可执行内存 ----
            freed = self._free_rwx_regions(proc_handle, kernel32)
            if freed:
                detail.append(f'释放 {freed} 块注入内存')
                stripped += freed
        finally:
            kernel32.CloseHandle(proc_handle)

        if stripped > 0:
            return True, '；'.join(detail)
        return False, '未发现可剥离的注入线程/内存'

    def _free_rwx_regions(self, proc_handle: int, kernel32) -> int:
        """释放进程中的 RWX 私有可执行内存区域（shellcode 注入特征）。

        Returns:
            成功释放的区域数
        """
        freed = 0
        addr = ctypes.c_void_p(0)
        mbi = _MEMORY_BASIC_INFORMATION()
        while True:
            ret = kernel32.VirtualQueryEx(
                proc_handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not ret:
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0
            if (size and base and mbi.State & _MEM_COMMIT
                    and mbi.Type & _MEM_PRIVATE
                    and mbi.Protect & 0x40):  # PAGE_EXECUTE_READWRITE (RWX)
                if kernel32.VirtualFreeEx(
                        proc_handle, ctypes.c_void_p(base), 0, _MEM_RELEASE):
                    freed += 1
            next_addr = base + size
            if next_addr <= base:
                break
            addr = ctypes.c_void_p(next_addr)
        return freed

    def _has_injection_features(self, pid: int) -> bool:
        """剥离后验证：检查进程是否仍存在注入特征（不触发告警，避免递归）。

        True = 仍存在注入特征 / 进程不可验证（视为未清除）。
        """
        try:
            proc = psutil.Process(pid)
            if not proc.is_running():
                return True  # 进程已退出，视为剥离失败
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
            known_ranges = self._get_known_module_ranges(proc, kernel32)
            try:
                threads = proc.threads()
            except Exception:
                threads = []
            suspicious = 0
            for t in threads:
                h_thread = kernel32.OpenThread(
                    _THREAD_QUERY_INFORMATION, False, t.id)
                if not h_thread:
                    continue
                try:
                    start_addr = ctypes.c_void_p()
                    status = ntdll.NtQueryInformationThread(
                        h_thread, _THREAD_QUERY_SET_WIN32_START_ADDRESS,
                        ctypes.byref(start_addr), ctypes.sizeof(start_addr), None)
                    if status == 0 and start_addr.value:
                        sv = start_addr.value
                        if 0 < sv < (1 << 47) and \
                                not self._is_address_in_known_module(sv, known_ranges):
                            suspicious += 1
                finally:
                    kernel32.CloseHandle(h_thread)
            if suspicious >= 2:
                return True

            # RWX 私有可执行内存残留检测
            try:
                maps = proc.memory_maps(grouped=False)
            except Exception:
                maps = []
            rwx_private = 0
            rwx_size = 0
            for m in maps:
                perms = getattr(m, 'perms', '') or ''
                path = getattr(m, 'path', '') or ''
                if 'x' in perms and 'w' in perms and 'r' in perms:
                    if not path or path.startswith('['):
                        rwx_private += 1
                        rwx_size += getattr(m, 'rss', 0)
            if rwx_private >= 2 or rwx_size >= 64 * 1024:
                return True
            return False
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return True
        except Exception:
            return True

    # ---- 内部：注册自身 ----

    def _register_self(self):
        """注册 PSLS 自身进程为受保护对象（轻量级，不遍历进程列表）"""
        self_pid = os.getpid()
        try:
            if HAS_PSUTIL:
                proc = psutil.Process(self_pid)
                self._protected_names.add(proc.name().lower())
        except Exception:
            pass
        # 额外注册已知的 PSLS 相关名称
        self._protected_names.update({
            'psls.exe', 'psls', 'gui_entry.exe',
            'project sertraline lab.exe',
            'python.exe', 'pythonw.exe',  # 开发模式下以 python 进程运行
        })
        logger.info(f"已注册受保护进程名: {self._protected_names}")

        # 初始化自身路径排除集合（防止启动扫描误杀自身程序）
        try:
            if getattr(sys, 'frozen', False):
                exe_dir = os.path.dirname(os.path.abspath(sys.executable))
                self._self_excluded_dirs.add(exe_dir.lower())
            else:
                project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                self._self_excluded_dirs.add(project_root.lower())
            if sys.platform == 'win32':
                appdata = os.environ.get('APPDATA', '')
                if appdata:
                    self._self_excluded_dirs.add(os.path.join(appdata, 'PSLS').lower())
            for base in list(self._self_excluded_dirs):
                self._self_excluded_dirs.add(os.path.join(base, 'backup').lower())
                internal = os.path.join(base, '_internal')
                if os.path.isdir(internal):
                    self._self_excluded_dirs.add(internal.lower())
        except Exception:
            pass

        # 宿主进程安装目录豁免（PSLS 生存依赖，必须整体放行）
        # PSLS 常被第三方宿主启动（Trae/VSCode 等 Electron IDE、启动器、安装器）。
        # 这些宿主目录内含大量**无签名**二进制（如 IDE 的 agent-tool-host.exe 80MB+），
        # 会被启动监测当"非信任程序"送沙箱 → 命中大文件分支 kill+隔离 → 把宿主的
        # 可执行文件隔离掉（实测 TRAE SOLO CN.exe / agent-tool-host.exe 被隔离，
        # 宿主随即不可用）。与既有"WebView2/Chromium 子进程绝不送沙箱/终止"同原则：
        # 宿主目录 = 自身运行前提，整体豁免（startswith 判定，覆盖其全部子目录）。
        try:
            host_dir = self._find_host_process_dir(self_pid)
            if host_dir:
                self._self_excluded_dirs.add(host_dir.lower())
                # 同时登记进"发起者排除名单"（动态项），使其在名单里可见可审计
                try:
                    self._initiator_exclusions.add_dynamic(
                        'path_prefix', host_dir, '宿主进程安装目录(自动)')
                except Exception:
                    pass
                logger.info(f'已豁免宿主进程安装目录: {host_dir}')
        except Exception:
            pass

        # 初始化启动扫描目录信任（需求: 无签名/未知发布者 PE 一律送检）
        # 拆两个集合:
        #   _CI_WINDOWS_SYSTEM_DIRS — 仅供目录信任豁免的 Windows 深层系统目录:
        #     WinVerifyTrust 对 Catalog/APPPKG 签名返回 NOSIGNATURE(伪"无签名")，
        #     这些目录受 CI/ACL 保护且文件不可被用户替换，保留目录豁免避免海量误报。
        #   _LAUNCH_SCAN_TRUSTED_DIRS — 其余位置(Program Files/ProgramData/AppData)
        #     不再因目录信任放行，统一走"有效签名+可信发布者"判定，未命中一律送检。
        try:
            ProcessProtection._CI_WINDOWS_SYSTEM_DIRS = set()
            ProcessProtection._LAUNCH_SCAN_TRUSTED_DIRS = set()
            sys_root = os.environ.get('SystemRoot', r'C:\Windows')
            pf = os.environ.get('ProgramFiles', r'C:\Program Files')
            up = os.environ.get('USERPROFILE', r'C:\Users')

            ProcessProtection._CI_WINDOWS_SYSTEM_DIRS.update([
                # Windows 核心系统目录 (CI 保护 + Catalog 签名盲区)
                os.path.join(sys_root, 'System32').lower(),
                os.path.join(sys_root, 'SysWOW64').lower(),
                os.path.join(sys_root, 'WinSxS').lower(),
                os.path.join(sys_root, 'SystemApps').lower(),
                os.path.join(sys_root, 'UUS').lower(),
                os.path.join(sys_root, 'Installer').lower(),
                os.path.join(sys_root, 'assembly').lower(),
                os.path.join(sys_root, 'Microsoft.NET').lower(),
                os.path.join(sys_root, 'SoftwareDistribution').lower(),
                os.path.join(sys_root, 'Fonts').lower(),
                os.path.join(sys_root, 'System32', 'drivers').lower(),
                # AppX 包 (APPPKG 签名, WinVerifyTrust 不识别, 归入系统豁免)
                os.path.join(pf, 'WindowsApps').lower(),
                os.path.join(up, 'AppData', 'Local', 'Packages').lower(),
            ])
        except Exception:
            ProcessProtection._CI_WINDOWS_SYSTEM_DIRS = set()

    @staticmethod
    def _find_host_process_dir(pid: int) -> str:
        """沿父进程链上溯，返回最顶层"非系统宿主"进程的安装目录（无则返回 ''）。

        用途：PSLS 被 Electron/IDE/启动器等宿主拉起时，宿主目录内的无签名二进制
        必须整体豁免，否则会被自身启动监测处置（曾把宿主 IDE 自己隔离）。
        安全约束：
          - 只上溯有限层（8 层），遇到系统关键进程立即停止，避免把
            C:\\Windows、用户桌面/文档等误判为"宿主目录"而大面积放行；
          - 终端/解释器（cmd/powershell/python 等）视为边界，不当作宿主，
            保证"从终端手动运行 PSLS"不会豁免整个上层目录。
        """
        if not HAS_PSUTIL:
            return ''
        _HOST_CHAIN_STOP = {
            'explorer.exe', 'services.exe', 'wininit.exe', 'winlogon.exe',
            'svchost.exe', 'csrss.exe', 'smss.exe', 'lsass.exe',
            'cmd.exe', 'powershell.exe', 'pwsh.exe', 'conhost.exe',
            'windowsterminal.exe', 'wt.exe', 'wsl.exe',
            'python.exe', 'pythonw.exe', 'python3.exe', 'bash.exe',
            'system', 'registry', 'idle',
        }
        try:
            cur = psutil.Process(pid)
            host = None
            for _ in range(8):
                try:
                    parent = cur.parent()
                except Exception:
                    parent = None
                if parent is None:
                    break
                try:
                    pname = (parent.name() or '').lower()
                except Exception:
                    pname = ''
                if not pname or pname in _HOST_CHAIN_STOP:
                    break
                host = parent
                cur = parent
            if host is None:
                return ''
            try:
                exe = host.exe() or ''
            except Exception:
                exe = ''
            if not exe:
                return ''
            return os.path.dirname(os.path.abspath(exe))
        except Exception:
            return ''

    # ---- 启动/停止 ----

    def start(self) -> bool:
        if self._running:
            return True
        if not HAS_PSUTIL:
            logger.warning("psutil 未安装，进程保护以降级模式启动")
            self._running = True
            with self._stats_lock:
                self._stats['started_at'] = time.time()
            self._add_event('system', 0, '', 'info',
                            '进程保护已启动(降级模式: 未安装 psutil)')
            return True

        self._stop_event.clear()
        self._running = True

        # 启动 ETW 实时监控（WMI 事件订阅）
        try:
            from engine.etw_monitor import EtwMonitor
            self._etw_monitor = EtwMonitor(
                on_process_created=self._on_etw_process_created,
                on_process_terminated=self._on_etw_process_terminated,
            )
            if self._etw_monitor.start():
                self._add_event('system', 0, '', 'info',
                                f'ETW 实时监控已启动 ({self._etw_monitor.get_stats().get("mode", "?")})')
            else:
                self._etw_monitor = None
        except ImportError:
            logger.debug('etw_monitor 模块不可用，使用纯轮询模式')
        except Exception as e:
            logger.warning(f'ETW 监控启动失败: {e}')
            self._etw_monitor = None

        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name='ProcessProtection'
        )
        self._monitor_thread.start()

        # 启动 DropperMonitor（文件落地实时监视，银狐断网型反制 A）。
        # 全部在后台线程运行，失败仅静默降级，不影响进程保护主链路。
        if self._dropper_monitor is None:
            try:
                from engine.dropper_monitor import DropperMonitor
                self._dropper_monitor = DropperMonitor(
                    on_file_dropped=self._on_dropped_file_cb,
                    excluded_dirs=tuple(self._self_excluded_dirs or (),
                                        ) if getattr(self, '_self_excluded_dirs', None) else None)
                self._dropper_monitor.start()
            except Exception as e:
                logger.warning(f'文件落地监视启动失败（降级）: {e}')
                self._dropper_monitor = None
        elif not getattr(self._dropper_monitor, '_running', False):
            try:
                self._dropper_monitor.start()
            except Exception:
                pass

        # 启动 watchdog 线程：监控 _monitor_thread 存活状态，异常退出后自动重启
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop, daemon=True, name='ProcessProtection-Watchdog'
        )
        self._watchdog_thread.start()

        # 启动「新进程检查调度 worker 池」：把回调线程和重型判定彻底拆开。
        # 即使启动监测队列有数百条未知程序需要跑签名+沙箱，也不会把驱动
        # procmon 消费线程 / ETW 回调线程卡住，进而避免主 GUI 被 Windows
        # 标记「未响应」。Worker 数固定避免在高压下继续开线程雪崩。
        self._start_launch_check_workers()

        # 启动存量进程扫描：PSLS 启动前就运行的进程不会产生新进程事件，
        # 可能整个会话漏检。此处一次性枚举存量进程（后台 daemon 线程，
        # 延迟 _startup_survey_delay 秒执行），复用启动监测判定链路仅对
        # 静态判定可疑的进程终止+询问。实例级仅触发一次。
        if not getattr(self, '_startup_survey_started', False):
            self._startup_survey_started = True
            threading.Thread(
                target=self._startup_existing_process_survey,
                kwargs={'delay_s': self._startup_survey_delay},
                daemon=True,
                name='StartupProcSurvey',
            ).start()

        with self._stats_lock:
            self._stats['started_at'] = time.time()

        # 快照由 _monitor_loop 在子线程中执行，避免阻塞主线程

        self._add_event('system', 0, '', 'info', '进程保护已启动')
        logger.info("进程保护已启动")
        return True

    # ------------------------------------------------------------------
    # 新进程检查调度（线程分离 Worker 池）
    # ------------------------------------------------------------------

    def _start_launch_check_workers(self) -> None:
        """启动新进程检查 worker 池（幂等）。"""
        # 先清理旧残留（start() 可能因 watchdog 重启主线程时重复调用）
        self._stop_launch_check_workers(join=False)
        threads: List[threading.Thread] = []
        for i in range(max(1, self._launch_check_worker_count)):
            t = threading.Thread(
                target=self._launch_check_worker,
                daemon=True,
                name=f'LaunchCheck-Worker-{i+1}',
            )
            t.start()
            threads.append(t)
        self._launch_check_worker_threads = threads
        logger.info(
            f'[启动监测调度] worker 池已启动：{len(threads)} 条线程，'
            f'队列容量={getattr(self._launch_check_queue, "maxsize", 0)}')
        # EK 快车道：敏感命令专用独立线程（不参与主池排队）
        # 规格：**最高优先级 + 最高权限 + 抢在判定之前终止**
        #   * 线程优先级 time_critical（主池只有 above_normal）
        #   * 启动即启用 SeDebugPrivilege，保证能终止提权/受保护进程
        #   * 4 条线程 + 256 槽队列，突发子进程风暴也不丢项
        try:
            if self._enable_debug_privilege():
                logger.info('[EK 快车道] SeDebugPrivilege 已启用（最高终止权限）')
            else:
                logger.warning(
                    '[EK 快车道] SeDebugPrivilege 启用失败（非管理员？）—— '
                    '提权进程的终止将降级到 完整 kill 链路/驱动')
        except Exception as e:
            logger.debug(f'[EK 快车道] 启用 SeDebugPrivilege 异常: {e}')
        self._ek_worker_threads = []
        for i in range(self._EK_WORKER_COUNT):
            et = threading.Thread(
                target=self._ek_fastlane_worker, daemon=True,
                name=f'EK-FastLane-{i+1}')
            et.start()
            self._ek_worker_threads.append(et)
        logger.info(
            f'[启动监测调度] EK 快车道已启动：{self._EK_WORKER_COUNT} 条独立线程'
            f'（time_critical 优先级，敏感命令专用）')

    # ------------------------------------------------------------------
    # EK 快车道（敏感命令立即处置，不排主 worker 池的队）
    # ------------------------------------------------------------------

    def _ek_should_kill_now(self, pid: int, entry: dict,
                            cmdline_name: str = '') -> str:
        """EK 第 0 级判定：**零 IO 的强信号** → 立即终止（不等发起链分析）。

        返回命中的原因字符串（'' = 未命中，需走完整发起链判定）。

        两个信号都是"确定性"的，不会误杀正常用户的 net user：
          (a) 命令进程自身 exe 不在 Windows/CI 系统目录 —— net.exe / netsh /
              takeown / vssadmin 正常都在 System32，只有**释放/伪装样本**
              才会以非系统路径出现，故可当场终止；
          (b) 发起者（父进程）路径已在"已拦截程序黑名单"里 —— 说明父进程
              刚被 PSLS 判威胁并终止，它再派生的破坏命令无需再判。
        """
        exe = entry.get('exe') or ''
        name = entry.get('name') or ''
        ci_dirs = getattr(type(self), '_CI_WINDOWS_SYSTEM_DIRS', None) or ()
        if exe and _is_ms_official_cheap is not None:
            try:
                if not _is_ms_official_cheap(exe, name, ci_dirs):
                    return '命令进程位于非系统目录（伪装/释放样本）'
            except Exception:
                pass
        ppid = int(entry.get('parent_pid') or 0)
        if ppid > 0 and HAS_PSUTIL:
            try:
                pexe = psutil.Process(ppid).exe() or ''
            except Exception:
                pexe = ''
            if pexe:
                try:
                    if self._is_exe_blocked(pexe):
                        return f'发起者已在拦截黑名单（{os.path.basename(pexe)}）'
                except Exception:
                    pass
        _ = cmdline_name
        return ''

    def _ek_fastlane_worker(self) -> None:
        """快车道 worker：只处理敏感命令，独占线程 → 不受沙箱分析拥塞影响。"""
        # 最短调度延迟优先：time_critical（高 CPU 负载下也不会被抢占饿死）
        _boost_current_thread_priority('time_critical')
        while not self._stop_event.is_set():
            try:
                item = self._ek_queue.get(timeout=0.5)
            except _queue_mod.Empty:
                continue
            if item is None:            # stop 哨兵
                return
            try:
                pid = int(item.get('pid') or 0)
                entry = item.get('entry') or {}
                if pid <= 0 or not entry:
                    continue
                dl = float(item.get('deadline_ts') or 0.0)
                if dl and time.monotonic() >= dl:
                    logger.debug(f'[EK 快车道] 工作项过期跳过 PID={pid}')
                    continue
                self._ek_handle_sensitive(pid, entry)
            except Exception as e:
                logger.debug(f'[EK 快车道] 处理异常: {e}')
            finally:
                try:
                    self._ek_queue.task_done()
                except Exception:
                    pass

    def _ek_handle_sensitive(self, pid: int, entry: dict) -> None:
        """快车道处置：**先抢时间终止，再做发起链判定与上报**。

        顺序（越快越好）：
          0) 零 IO 强信号（非系统目录的命令进程 / 发起者已在黑名单）→ 立刻
             `_emergency_kill`（SeDebug 已启用，<1ms）；
          1) 完整发起链判定（psutil + 签名，2s 硬上限）→ 非官方则按 BT 兼容
             规则处置（只掐断命令进程；样本本体在盒内时不动它）并上报。

        第 0 级命中时进程已被终止：此时发起链从 **父进程** 起算（命令进程已死，
        psutil 读不到它的 ppid），保证仍能正确指认真正的发起者。
        """
        if not HAS_PSUTIL or _classify_credential_tamper is None:
            return
        name = entry.get('name') or ''
        exe = entry.get('exe') or ''
        ppid = int(entry.get('parent_pid') or 0)
        try:
            hit = _classify_credential_tamper(entry.get('cmdline') or [], name)
        except Exception:
            hit = None
        if not hit:
            return

        # ---- 第 0 级：零 IO 强信号 → 立即终止（抢在所有 IO/判定之前）----
        prekilled = False
        try:
            fast_reason = self._ek_should_kill_now(pid, entry, name)
        except Exception:
            fast_reason = ''
        if fast_reason:
            t0 = time.perf_counter()
            try:
                prekilled = bool(self._emergency_kill(pid))
            except Exception:
                prekilled = False
            dt_ms = (time.perf_counter() - t0) * 1000
            logger.error(
                f'[EK 快车道·第0级] 立即终止 PID={pid} {name} '
                f'原因={fast_reason} reason={hit.get("reason")} '
                f'killed={prekilled} 耗时={dt_ms:.1f}ms')

        holder: List[Any] = [None]
        chain_start = ppid if (prekilled and ppid > 0) else pid

        def _runner():
            try:
                holder[0] = _check_origin_chain(
                    chain_start, ppid,
                    ci_dirs=type(self)._CI_WINDOWS_SYSTEM_DIRS)
            except Exception:
                holder[0] = None

        t = threading.Thread(target=_runner, daemon=True, name=f'EKChain-{pid}')
        t.start()
        t.join(timeout=2.0)
        chain = holder[0]
        if chain is None:
            logger.warning(f'[EK 快车道] 发起链判定超时，本条放行: {name} PID={pid}')
            return
        if chain[0]:
            # 微软官方链（用户/系统自身行为）→ 不处置（第 0 级已终止的除外）
            logger.debug(f'[EK 快车道] 发起链为微软官方，放行: {name} PID={pid}')
            if prekilled:
                with self._ek_handled_lock:
                    self._ek_handled_pids[int(pid)] = \
                        time.time() + self._EK_HANDLED_TTL
            return
        offender = chain[1] or {}
        oexe = offender.get('exe') or ''
        opid = int(offender.get('pid') or 0)
        in_box = bool(oexe) and self._is_in_psls_sandbox_dir(oexe)
        if not in_box and opid:
            box_pids = self._sandboxie_box_pids()
            if opid in box_pids:
                in_box = True
            elif not box_pids and oexe and self._is_sandbox_analyzing(oexe):
                in_box = True
        try:
            self._handle_credential_tamper(pid, name, exe, hit, offender,
                                           offender_in_box=in_box)
        finally:
            with self._ek_handled_lock:
                self._ek_handled_pids[int(pid)] = time.time() + self._EK_HANDLED_TTL

    def _is_ek_handled(self, pid: int) -> bool:
        """该 pid 是否已由 EK 快车道处置（主池据此跳过，避免重复上报）。"""
        lock = getattr(self, '_ek_handled_lock', None)
        table = getattr(self, '_ek_handled_pids', None)
        if lock is None or table is None:
            return False
        now = time.time()
        with lock:
            expired = [k for k, dl in table.items() if dl < now]
            for k in expired:
                table.pop(k, None)
            return int(pid) in table

    def _stop_launch_check_workers(self, join: bool = True) -> None:
        """停止 worker 池：发送 stop 哨兵（可选等待），保证退出时不留活线程。"""
        # EK 快车道同样发哨兵（独立队列）
        try:
            for t in list(getattr(self, '_ek_worker_threads', []) or []):
                try:
                    self._ek_queue.put_nowait(None)
                except Exception:
                    pass
        except Exception:
            pass
        self._ek_worker_threads = []
        if not getattr(self, '_launch_check_worker_threads', None):
            return
        threads = list(self._launch_check_worker_threads)
        # 每个线程一个哨兵：保证全部 worker 都能收到退出通知
        try:
            for _ in threads:
                self._launch_check_queue.put_nowait(None)
        except _queue_mod.Full:
            # 队列满也强行塞哨兵：先丢弃若干旧条目再 put，避免永远阻塞
            for _ in range(max(1, len(threads))):
                try:
                    self._launch_check_queue.get_nowait()
                except _queue_mod.Empty:
                    break
            try:
                for _ in threads:
                    self._launch_check_queue.put_nowait(None)
            except _queue_mod.Full:
                pass
        if join:
            for t in threads:
                try:
                    t.join(timeout=2)
                except Exception:
                    pass
        self._launch_check_worker_threads = []

    def _launch_check_worker(self) -> None:
        """新进程检查 worker：队列有界 + 单条绝对时限，保证永不永久阻塞。"""
        # 提升到 ABOVE_NORMAL，避免高压时 worker 被饿死导致队列积压
        _boost_current_thread_priority('above_normal')
        while not self._stop_event.is_set():
            try:
                item = self._launch_check_queue.get(timeout=0.5)
            except _queue_mod.Empty:
                continue
            # None = stop 哨兵
            if item is None:
                return
            pid = 0
            entry = None
            deadline_ts = 0.0
            try:
                pid = int(item.get('pid') or 0)
                entry = item.get('entry')
                deadline_ts = float(item.get('deadline_ts') or 0.0)
                if not entry or pid <= 0:
                    continue
                now = time.monotonic()
                # 过期跳过：被卡在队列里的老条目直接丢弃，防止"积压越多
                # 越跑越慢 → 更积压"的恶性循环。用户已经重新运行程序时，
                # 新的事件会再入队一次重新判定。
                if deadline_ts and (now >= deadline_ts):
                    try:
                        name = entry.get('name', '') or ''
                        exe = entry.get('exe', '') or ''
                    except Exception:
                        name = exe = ''
                    logger.debug(
                        f'[启动监测调度] 工作项排队超时跳过 PID={pid} {name} '
                        f'exe={exe}')
                    continue
                # 执行：_check_new_process 内部自身仍有各子环节超时，
                # 这里再加一层全局子线程"软守护"（Thread.join timeout）避免
                # 单次检查被不可控的驱动/AV 同步调用永久挂住。
                ok = self._run_check_with_guard(pid, entry,
                    overall_timeout_s=max(1.0, self._launch_check_item_deadline),
                    survey=bool(item.get('survey')))
                if not ok:
                    try:
                        exe = entry.get('exe', '') or ''
                    except Exception:
                        exe = ''
                    logger.warning(
                        f'[启动监测调度] _check_new_process 超时/异常，丢弃 PID={pid} '
                        f'exe={exe}')
            except Exception as e:
                logger.warning(f'[启动监测调度] worker 消费异常: {e}')
            finally:
                try:
                    self._launch_check_queue.task_done()
                except Exception:
                    pass

    def _run_check_with_guard(self, pid: int, entry: dict,
                              overall_timeout_s: float,
                              survey: bool = False) -> bool:
        """把 _check_new_process 放到子线程 + join(timeout) 里执行，卡死则直接放弃。

        我们不想回调线程被卡住，但也不想 LaunchCheck Worker 本身被某条
        卡死的 _check_new_process 永久吞掉（比如 antivirus 正独占文件、
        PowerShell 对签名 WMI 调用迟迟不返回时，join 超时时 worker 可
        继续处理下一条）。超时返回 False 仅表示"本次不处理"，不会影响
        其它事件，也不会停止 worker。
        """
        if overall_timeout_s <= 0:
            try:
                self._check_new_process(pid, entry, startup_survey=survey)
                return True
            except Exception:
                return False
        done_holder: List[bool] = [False]
        exc_holder: List[Optional[BaseException]] = [None]

        def _runner():
            try:
                self._check_new_process(pid, entry, startup_survey=survey)
                done_holder[0] = True
            except BaseException as e:  # noqa: BLE001 - 我们想捕获所有异常
                exc_holder[0] = e
                done_holder[0] = True

        t = threading.Thread(target=_runner, daemon=True,
                             name=f'LaunchCheck-Runner-{pid}')
        t.start()
        t.join(timeout=overall_timeout_s)
        if not done_holder[0]:
            # 超时：runner 线程作为 daemon 会在 PSLS 退出时自然消失，
            # 这里不再等待；仅记录日志避免静默漏事。
            try:
                name = entry.get('name', '') or ''
            except Exception:
                name = ''
            logger.warning(
                f'[启动监测调度] _check_new_process 执行超过 {overall_timeout_s:.0f}s '
                f'跳过 PID={pid} {name}')
            return False
        if exc_holder[0] is not None:
            try:
                raise exc_holder[0]
            except Exception:
                logger.warning(
                    f'[启动监测调度] _check_new_process 抛出异常 PID={pid}: '
                    f'{exc_holder[0]}', exc_info=False)
            return False
        return True

    def _enqueue_launch_check(self, pid: int, entry: dict,
                              survey: bool = False) -> bool:
        """入口统一函数：新进程检查事件入调度队列（立即非阻塞）。

        - 回调线程 / ETW 消费线程 / 轮询线程都可调用；全程只做内存级操作，
          不执行任何文件 IO / 系统调用 / 子进程 / 信号发送。
        - 同一 (pid, 规范化exe) 在 _launch_check_dedup_ttl 秒内重复到达会被合并。
        - 队列满时丢弃最旧的一条（FIFO 等价：通过 get_nowait() 弹出）再入队，
          保证最新启动事件始终不丢失。

        Returns:
            True = 已排队（或已被去重认为已排队）。False = 丢弃。
        """
        if pid <= 0 or not entry:
            return False
        # 先做超轻量去重（避免同一进程被 ETW+驱动+轮询 3 条通道同时入队 3 份）
        exe_norm = ''
        try:
            exe_raw = entry.get('exe', '') or ''
            if exe_raw:
                exe_norm = os.path.normcase(os.path.abspath(exe_raw))
        except Exception:
            exe_norm = ''
        dedup_key: Tuple[int, str] = (int(pid), exe_norm)
        now = time.monotonic()
        with self._launch_check_dedup_lock:
            last_ts = self._launch_check_dedup.get(dedup_key, 0.0)
            if (now - last_ts) < self._launch_check_dedup_ttl:
                # 3 秒内已经安排过这条 (pid,path)，直接认为已排队。
                return True
            self._launch_check_dedup[dedup_key] = now
            # 惰性清理 dedup 表（每次随机概率清理，避免线性扫描）：
            if len(self._launch_check_dedup) > 2000:
                cutoff = now - self._launch_check_dedup_ttl
                expired = [k for k, v in self._launch_check_dedup.items()
                           if v < cutoff]
                for k in expired:
                    del self._launch_check_dedup[k]

        deadline_ts = time.monotonic() + self._launch_check_item_deadline

        # ---- EK 快车道投递：敏感命令走独立线程，不排主池的队 ----
        # 只做 µs 级正则判定（纯内存）；命中才投递，队列小(64)、时限短(5s)。
        # 目的：样本一次性派生 cmd/net/netsh/powershell 多个子进程时，破坏命令
        # 也不会因主池拥塞被 deadline 丢弃（"EK 不及时/没杀"的结构性原因）。
        if not survey:
            try:
                if _classify_credential_tamper is not None and \
                        _classify_credential_tamper(
                            entry.get('cmdline') or [],
                            entry.get('name') or ''):
                    self._ek_queue.put_nowait({
                        'pid': int(pid),
                        'entry': dict(entry),
                        'deadline_ts': time.monotonic() + self._EK_ITEM_DEADLINE,
                    })
                    logger.info(
                        f'[EK 快车道] 敏感命令投递 PID={pid} '
                        f'{entry.get("name") or ""}')
            except Exception:
                # 队列满/未初始化等一律忽略：主池仍会处理该条目（行为不外溢）
                pass

        item = {
            'pid': int(pid),
            'entry': dict(entry),  # 拷贝一份，防止入队后调用方改 entry 字段
            'deadline_ts': deadline_ts,
            'enqueued_at': now,
            'survey': bool(survey),  # True=启动存量扫描模式（只处置可疑）
        }

        q = self._launch_check_queue
        # 满了先丢最旧的一条，最多丢 3 条；然后非阻塞 put。
        try:
            q.put_nowait(item)
            return True
        except _queue_mod.Full:
            for _ in range(3):
                try:
                    q.get_nowait()
                except _queue_mod.Empty:
                    break
                try:
                    q.task_done()
                except Exception:
                    pass
            try:
                q.put_nowait(item)
                return True
            except _queue_mod.Full:
                pass
        # 仍然放不下：dedup 表里回退时间戳，保证下一次事件能再进
        with self._launch_check_dedup_lock:
            if self._launch_check_dedup.get(dedup_key) == now:
                del self._launch_check_dedup[dedup_key]
        return False


    def stop(self) -> bool:
        if not self._running:
            # 即便 running=False，也释放残留沙箱/威胁锁（UI 可能忘了释放）
            self._drain_all_sandbox_locks()
            return True
        self._stop_event.set()
        self._running = False

        # 停止 ETW 监控
        if self._etw_monitor:
            try:
                self._etw_monitor.stop()
            except Exception:
                pass
            self._etw_monitor = None

        # 停止 DropperMonitor（文件落地监视）
        if self._dropper_monitor is not None:
            try:
                self._dropper_monitor.stop()
            except Exception:
                pass

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=3)
        self._monitor_thread = None

        # 停止新进程检查 worker 池（先停再释放沙箱锁：防止 worker 还在加锁）
        self._stop_launch_check_workers(join=True)

        # 兜底释放所有沙箱锁（退出程序时避免"占文件关不掉"）
        self._drain_all_sandbox_locks()

        self._add_event('system', 0, '', 'info', '进程保护已停止')
        logger.info("进程保护已停止")
        return True

    # ---- 沙箱 exe 锁：注册/释放/兜底 ----

    def release_sandbox_lock(self, file_path: str) -> bool:
        """释放沙箱阶段 3b 登记的 exe 独占锁（由处置 UI / 隔离模块调用）。

        返回 True 表示找到并释放；False 表示未登记或已释放。
        """
        try:
            key = os.path.normcase(os.path.abspath(file_path))
        except Exception:
            return False
        if not key:
            return False
        entry = None
        with self._sandbox_locks_lock:
            entry = self._sandbox_locks.pop(key, None)
        if entry is None:
            return False
        fh, _ts = entry
        try:
            try:
                fh.close()
            except Exception:
                pass
            return True
        except Exception:
            return False

    def _drain_all_sandbox_locks(self) -> int:
        """stop / 清理时释放所有登记的锁。返回释放数量。"""
        released = 0
        with self._sandbox_locks_lock:
            keys = list(self._sandbox_locks.keys())
            for k in keys:
                entry = self._sandbox_locks.pop(k, None)
                if entry is None:
                    continue
                fh, _ts = entry
                try:
                    fh.close()
                except Exception:
                    pass
                released += 1
        if released:
            logger.info('进程保护: 释放沙箱登记 exe 独占锁 %d 个', released)
        return released

    # ---- 沙箱 analyzing 路径豁免：防止沙箱内部启动的被测进程二次拦截 ----

    def _normalize_path_for_sandbox_analyzing(self, path: str) -> str:
        try:
            return os.path.normcase(os.path.abspath(path))
        except Exception:
            return ''

    def _normalize_dir_prefix(self, dir_path: str) -> str:
        """规范化目录前缀（endswith(sep) 确保 startswith 不误命中同级目录名）。"""
        try:
            p = os.path.normcase(os.path.abspath(dir_path))
            if not p.endswith(os.sep):
                p += os.sep
            return p
        except Exception:
            return ''

    # =============== (1) 精确路径（原始 exe） ===============
    def _mark_sandbox_analyzing(self, exe: str,
                                ttl_seconds: int = 90) -> Optional[str]:
        """把 exe 加入"正在沙箱分析豁免表"（精确路径匹配）。

        返回登记到表中的规范化 key，失败返回 None。
        """
        key = self._normalize_path_for_sandbox_analyzing(exe)
        if not key:
            return None
        with self._sandbox_analyzing_paths_lock:
            self._sandbox_analyzing_paths.add(key)
            self._sandbox_analyzing_deadline[key] = time.time() + max(30, ttl_seconds)
        return key

    def _unmark_sandbox_analyzing(self, exe_or_key: str) -> None:
        """移除 analyzing 精确路径豁免。"""
        key = (
            exe_or_key
            if os.path.isabs(exe_or_key)
            else self._normalize_path_for_sandbox_analyzing(exe_or_key)
        ) or self._normalize_path_for_sandbox_analyzing(exe_or_key)
        if not key:
            return
        with self._sandbox_analyzing_paths_lock:
            self._sandbox_analyzing_paths.discard(key)
            self._sandbox_analyzing_deadline.pop(key, None)

    # =============== (2) 目录前缀（沙箱副本/子落地文件） ===============
    def _mark_sandbox_analyzing_dir(self, dir_prefix: str,
                                    ttl_seconds: int = 90) -> Optional[str]:
        """登记目录前缀豁免：该目录下的所有文件路径 startswith 命中即豁免。

        SandboxAnalyzer.analyze 会把样本复制到 %TEMP%/psls_sandbox_<rand>/
        sample_*.exe 再启动；若我们不提前登记该目录，ETW 看到的副本路径 !=
        原始 exe → 豁免 miss → 二次进入沙箱 → 三重 → 无限循环。

        解决方式：在 _sandbox_worker 中显式创建 work_dir、赋值给
        config.work_dir，并在此登记前缀（analyze 调用前）。
        """
        prefix = self._normalize_dir_prefix(dir_prefix)
        if not prefix:
            return None
        now = time.time()
        with self._sandbox_analyzing_paths_lock:
            if prefix not in self._sandbox_analyzing_dirs:
                self._sandbox_analyzing_dirs.append(prefix)
            self._sandbox_analyzing_dir_deadline[prefix] = now + max(30, ttl_seconds)
        return prefix

    def _unmark_sandbox_analyzing_dir(self, dir_prefix_or_key: str) -> None:
        prefix = (
            dir_prefix_or_key
            if dir_prefix_or_key.endswith(os.sep)
            else self._normalize_dir_prefix(dir_prefix_or_key)
        ) or self._normalize_dir_prefix(dir_prefix_or_key)
        if not prefix:
            return
        with self._sandbox_analyzing_paths_lock:
            if prefix in self._sandbox_analyzing_dirs:
                self._sandbox_analyzing_dirs.remove(prefix)
            self._sandbox_analyzing_dir_deadline.pop(prefix, None)

    # =============== (3) PID 族系（沙箱目标的子孙进程） ===============
    def _mark_sandbox_target_pid(self, pid: int, ttl_seconds: int = 90) -> None:
        """登记沙箱目标进程 PID（沙箱 CreateProcessW 返回的 dwProcessId）。

        之后 ETW 上若看到：
          - pid 自身命中集合 → 同进程被 ETW 重复上报 / Resume 后再事件
          - parent_pid 命中集合 → 沙箱目标直接 Create 的子进程（payload.exe 等）
          都直接豁免，不再二次挂起进沙箱。
        """
        if not isinstance(pid, int) or pid <= 0:
            return
        with self._sandbox_analyzing_paths_lock:
            self._sandbox_target_pids.add(pid)
            self._sandbox_target_pid_deadline[pid] = time.time() + max(30, ttl_seconds)

    def _mark_sandbox_target_pids(self, pids) -> None:
        """批量登记沙箱盒内 PID（Sandboxie 后端 /listpids 返回的进程）。"""
        for _p in list(pids or []):
            try:
                self._mark_sandbox_target_pid(int(_p))
            except Exception:
                continue

    def _is_sandbox_descendant(self, pid: int, parent_pid: int) -> bool:
        """PID 维度豁免查询；顺带清理过期 TTL 条目。"""
        if pid <= 0 and parent_pid <= 0:
            return False
        with self._sandbox_analyzing_paths_lock:
            now = time.time()
            expired = [p for p, dl in self._sandbox_target_pid_deadline.items()
                       if dl < now]
            for p in expired:
                self._sandbox_target_pids.discard(p)
                self._sandbox_target_pid_deadline.pop(p, None)
            return pid in self._sandbox_target_pids or parent_pid in self._sandbox_target_pids

    # =============== (4) 统一查询（纯路径维度，不含 PID） ===============
    def _is_sandbox_analyzing(self, exe: str) -> bool:
        """三层检查：精确路径 → 目录前缀 → 沙箱命名通配（锁外）。"""
        key = self._normalize_path_for_sandbox_analyzing(exe)
        if not key:
            return False
        with self._sandbox_analyzing_paths_lock:
            now = time.time()
            # ---- (a) 清理 + 命中精确路径 ----
            expired_p = [k for k, dl in self._sandbox_analyzing_deadline.items()
                         if dl < now]
            for k in expired_p:
                self._sandbox_analyzing_paths.discard(k)
                self._sandbox_analyzing_deadline.pop(k, None)
            if key in self._sandbox_analyzing_paths:
                return True

            # ---- (b) 清理 + 命中目录前缀 ----
            expired_d = [d for d, dl in self._sandbox_analyzing_dir_deadline.items()
                         if dl < now]
            for d in expired_d:
                if d in self._sandbox_analyzing_dirs:
                    self._sandbox_analyzing_dirs.remove(d)
                self._sandbox_analyzing_dir_deadline.pop(d, None)
            _sandbox_dir_prefix_list = self._sandbox_analyzing_dirs[:]

        # ---- 锁外 startswith（目录列表小，不占锁时间） ----
        for prefix in _sandbox_dir_prefix_list:
            if key.startswith(prefix):
                return True

        # ---- (c) 通配兜底：路径包含 psls_sandbox_ 段即视为沙箱内部进程 ----
        # 即便因极端竞态（sem 超时、临时目录名未预测正确）忘了登记，
        # 沙箱工作目录名固定以 psls_sandbox_ 开头，1us 字符串比较即可覆盖。
        return self._is_in_psls_sandbox_dir(exe)

    def _is_in_psls_sandbox_dir(self, exe: str) -> bool:
        """【锁外 1us】路径上包含 psls_sandbox_ 段则 True。"""
        if not exe:
            return False
        try:
            return 'psls_sandbox_' in exe.replace('\\', '/').lower()
        except Exception:
            return False

    def _sandboxie_box_pids(self) -> Set[int]:
        """当前 Sandboxie 分析盒内的 PID 集合（1s TTL 缓存）。

        用于判定"被分析目标是否跑到盒外"（沙箱逃逸）：盒内 PID 是权威
        依据，不依赖 token/完整性级别（后者会被 FakeAdminRights 干扰）。
        查询失败/盒为空一律返回空集 —— 调用方**必须在空集时跳过判定**，
        避免误杀。
        """
        now = time.time()
        with self._sbie_box_pids_lock:
            if now - self._sbie_box_pids_ts < 1.0:
                return set(self._sbie_box_pids_cache)
        pids: Set[int] = set()
        try:
            from engine.sandbox_analyzer import (
                detect_sandboxie_backend, SandboxConfig, SandboxieBackend)
            info = detect_sandboxie_backend() or {}
            start = info.get('start') or ''
            box = getattr(SandboxConfig(), 'sandboxie_box', 'PSLS_Analysis')
            if start and os.path.isfile(start):
                r = subprocess.run(
                    [start, f'/box:{box}', '/silent', '/listpids'],
                    capture_output=True, text=True, timeout=8)
                if r.returncode == 0:
                    pids = set(SandboxieBackend._parse_listpids(r.stdout or ''))
        except Exception as e:
            logger.debug(f'沙箱盒 PID 查询失败（跳过逃逸判定）: {e}')
        with self._sbie_box_pids_lock:
            self._sbie_box_pids_cache = pids
            self._sbie_box_pids_ts = now
        return pids

    # =============== (5) 已被拦截程序路径黑名单（反 runas 重启逃逸） ===============
    def _mark_exe_blocked(self, exe: str, reason: str = '') -> bool:
        """把"已被 PSLS 终止的非信任程序"路径记入黑名单（TTL 15 分钟）。

        提权重启（runas）产生的实例路径与原始程序**完全相同**，是唯一可靠
        且与沙箱状态无关的识别特征 —— 盒 PID 列表查询失败、oversize 分支
        从未登记 analyzing 等情况下，本表仍能兜住重启逃逸。
        """
        key = self._normalize_path_for_sandbox_analyzing(exe)
        if not key:
            return False
        lock = getattr(self, '_blocked_exe_lock', None)
        table = getattr(self, '_blocked_exe_paths', None)
        if lock is None or table is None:      # 未完成初始化的对象（单测/降级）
            return False
        ttl = float(getattr(self, '_BLOCKED_EXE_TTL', 900.0))
        with lock:
            table[key] = time.time() + ttl
        logger.info(f'已拦截程序路径入黑名单: {exe}（{reason or "拦截处置"}）')
        return True

    def _unmark_exe_blocked(self, exe: str) -> None:
        """用户明确放行/重启批准后解除黑名单（否则用户放行会被反复拦截）。"""
        key = self._normalize_path_for_sandbox_analyzing(exe)
        if not key:
            return
        lock = getattr(self, '_blocked_exe_lock', None)
        table = getattr(self, '_blocked_exe_paths', None)
        if lock is None or table is None:
            return
        with lock:
            if table.pop(key, None) is not None:
                logger.info(f'已解除拦截黑名单（用户放行）: {exe}')

    def _is_exe_blocked(self, exe: str) -> bool:
        """查询路径是否在拦截黑名单内（顺带清理过期条目）。"""
        key = self._normalize_path_for_sandbox_analyzing(exe)
        if not key:
            return False
        lock = getattr(self, '_blocked_exe_lock', None)
        table = getattr(self, '_blocked_exe_paths', None)
        if lock is None or table is None:      # 未完成初始化的对象（单测/降级）
            return False
        now = time.time()
        with lock:
            expired = [k for k, dl in table.items() if dl < now]
            for k in expired:
                table.pop(k, None)
            dl = table.get(key)
            return bool(dl and dl >= now)

    def _kill_blocked_relaunch(self, pid: int, name: str, exe: str,
                               parent_pid: int = 0) -> bool:
        """已拦截程序的提权/重启实例 → 立即终止并上报。

        只杀本实例（不做按路径全量清扫）：Sandboxie 后端下沙箱盒内跑的是
        **同一条原始路径**，按路径清扫会把正在分析的盒内实例一起杀掉，
        导致沙箱分析中断。黑名单判定会对每个新实例各触发一次，平行实例不会漏。
        """
        logger.error(
            f'已拦截程序重现（疑似 runas 自提权重启逃逸）：{name} PID={pid} {exe}')
        killed = False
        try:
            killed = bool(self._emergency_kill(pid))
        except Exception:
            killed = False
        if not killed:
            # 提权实例可能拒绝普通 OpenProcess(PROCESS_TERMINATE)：
            # 走完整终止链路（SeDebug 提权 / taskkill / 驱动 ZwTerminateProcess）
            try:
                killed = bool(self.kill_process(
                    pid, force=True, kill_tree=True, timeout=5.0))
            except Exception:
                killed = False
        if not killed:
            logger.warning(
                f'已拦截程序重现但终止失败 PID={pid} {name} {exe}'
                f'（若为提权实例且驱动未加载，需以管理员运行 PSLS）')

        self._notify_launch_monitoring(
            pid, name or f'PID-{pid}', exe,
            reason='已拦截程序再次启动（疑似提权/runas 重启逃逸），已终止',
            scan_result=LaunchScanResult(
                status='blocked',
                verdict='malware',
                score=90,
                signatures=['Blocked.Exe.Relaunch'],
                file_path=exe,
            ),
        )
        self._add_event(
            'blocked_exe_relaunch', pid, name or '', 'threat',
            '被拦截程序再次启动（提权/runas 重启逃逸），已终止', exe)
        return killed

    def _cleanup_expired_sandbox_analyzing(self) -> int:
        """stop/周期清理入口：清理精确路径 + 目录前缀 + PID TTL 过期条目。"""
        with self._sandbox_analyzing_paths_lock:
            now = time.time()
            before = (len(self._sandbox_analyzing_paths)
                      + len(self._sandbox_analyzing_dirs)
                      + len(self._sandbox_target_pids))
            # 精确路径
            expired_p = [k for k, dl in self._sandbox_analyzing_deadline.items()
                         if dl < now]
            for k in expired_p:
                self._sandbox_analyzing_paths.discard(k)
                self._sandbox_analyzing_deadline.pop(k, None)
            # 目录前缀
            expired_d = [d for d, dl in self._sandbox_analyzing_dir_deadline.items()
                         if dl < now]
            for d in expired_d:
                if d in self._sandbox_analyzing_dirs:
                    self._sandbox_analyzing_dirs.remove(d)
                self._sandbox_analyzing_dir_deadline.pop(d, None)
            # 目标 PID
            expired_t = [p for p, dl in self._sandbox_target_pid_deadline.items()
                         if dl < now]
            for p in expired_t:
                self._sandbox_target_pids.discard(p)
                self._sandbox_target_pid_deadline.pop(p, None)
            after = (len(self._sandbox_analyzing_paths)
                     + len(self._sandbox_analyzing_dirs)
                     + len(self._sandbox_target_pids))
            # 拦截黑名单过期清理（独立锁）
            expired_b = []
            with self._blocked_exe_lock:
                expired_b = [k for k, dl in self._blocked_exe_paths.items()
                             if dl < now]
                for k in expired_b:
                    self._blocked_exe_paths.pop(k, None)
            return before - after + len(expired_b)

    # ---- ETW 实时事件回调 ----

    @staticmethod
    def _parse_cmdline_string(cmdline_str: str) -> List[str]:
        """正确解析 Windows 命令行字符串为参数列表

        Windows 命令行中带双引号的路径需要特殊处理。
        例如: cmd.exe /c "C:\\Program Files\\test.bat"
        应该解析为: ['cmd.exe', '/c', 'C:\\Program Files\\test.bat']
        而不是: ['cmd.exe', '/c', 'C:\\Program', 'Files\\test.bat']

        使用 shlex.split() 处理带引号的字符串，但需要注意
        Windows 路径中的反斜杠可能导致问题，所以先用正则处理。
        """
        if not cmdline_str:
            return []

        # 优先尝试用 Windows 原生解析器（ctypes 调用 CommandLineToArgvW）
        try:
            import ctypes
            from ctypes import wintypes

            # 加载 shell32.dll 并调用 CommandLineToArgvW
            shell32 = ctypes.WinDLL('shell32', use_last_error=True)
            CommandLineToArgvW = shell32.CommandLineToArgvW
            CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
            CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)

            argv_count = ctypes.c_int(0)
            argv = CommandLineToArgvW(cmdline_str, ctypes.byref(argv_count))

            if argv:
                result = []
                for i in range(argv_count.value):
                    arg = argv[i]
                    if arg:
                        result.append(arg)
                ctypes.windll.kernel32.LocalFree(argv)
                return result
        except Exception:
            pass

        # 降级方案：使用简单的引号感知解析
        result = []
        current = []
        in_quotes = False

        for ch in cmdline_str:
            if ch == '"':
                if in_quotes:
                    # 结束引号
                    if current:
                        result.append(''.join(current))
                        current = []
                    in_quotes = False
                else:
                    # 开始引号（保留前导空格）
                    if current:
                        result.append(''.join(current))
                        current = []
                    in_quotes = True
            elif ch == ' ' and not in_quotes:
                # 空格分隔（非引号内）
                if current:
                    result.append(''.join(current))
                    current = []
            else:
                current.append(ch)

        # 处理最后一个参数
        if current:
            result.append(''.join(current))

        return result if result else [cmdline_str]

    def _on_etw_process_created(self, event: dict):
        """ETW 进程创建事件回调（实时，延迟 < 500ms）

        当 ETW/WMI 报告新进程创建时，立即执行安全检查，
        无需等待 3 秒轮询周期。

        注意：cmdline 必须用正确的 Windows 命令行解析，
        不能用简单的 .split()（会破坏带引号的路径）。
        """
        pid = event.get('pid', 0)
        name = (event.get('name', '') or '').lower()
        exe_path = event.get('exe_path', '') or ''
        cmdline_str = event.get('cmdline', '') or ''
        parent_pid = event.get('parent_pid', 0)
        cmdline_list: List[str] = []

        if pid == 0:
            return

        # 降级模式（WTS 快速轮询）事件不携带 exe_path/cmdline，此处补获取，
        # 否则 _check_new_process 会因 `if not exe: return` 直接跳过所有新进程（漏拦）。
        if not exe_path and HAS_PSUTIL:
            try:
                proc = psutil.Process(pid)
                exe_path = proc.exe() or ''
                # 优先使用 psutil 已正确解析的 cmdline 列表
                try:
                    cmdline_list = proc.cmdline()
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        psutil.ZombieProcess):
                    cmdline_list = []
            except (psutil.NoSuchProcess, psutil.AccessDenied,
                    psutil.ZombieProcess):
                exe_path = ''
            except Exception:
                exe_path = ''

        # 如果还没有 cmdline_list，从字符串解析
        if not cmdline_list and cmdline_str:
            cmdline_list = self._parse_cmdline_string(cmdline_str)

        # 跳过已检查的 PID（可能 ETW 和轮询都报告了同一个进程）
        with self._etw_lock:
            if pid in self._etw_pids_checked:
                return
            self._etw_pids_checked.add(pid)
            # 清理已检查集合（避免无限增长）
            if len(self._etw_pids_checked) > 5000:
                self._etw_pids_checked.clear()

        # 跳过 PSLS 自身相关进程
        if name in self._protected_names:
            return
        if cmdline_list:
            cmdline_str_check = ' '.join(cmdline_list).lower()
            if 'qtwebengine' in cmdline_str_check or '--process-per-site' in cmdline_str_check:
                return

        logger.debug(f'[ETW] 实时检测到新进程: PID={pid} {name} parent={parent_pid}')

        # 进程创建事件钩子（用于关键目录保护"进程触发式"快照校验）
        # 调用发生在 _check_new_process 之前，确保防护比执行更早。
        try:
            hook = getattr(self, '_on_process_created_hook', None)
            if hook is not None and callable(hook):
                try:
                    hook(int(pid), str(exe_path or ''))
                except Exception:
                    pass
        except Exception:
            pass

        # 构造 entry 并执行检查（复用现有检查逻辑）
        entry = {
            'name': name,
            'exe': exe_path,
            'cmdline': cmdline_list,  # 已正确解析的列表
            'cpu': 0,
            'threads': 0,
            'create_time': event.get('timestamp', time.time()),
            'proc': None,  # ETW 事件中没有 proc 对象
        }
        # 【线程分离】：直接送入调度队列 worker 执行，回调线程立即返回，
        # 避免 PowerShell 签名校验 / 独占锁 / 沙箱预复制等重型操作把
        # ETW 消费线程（以及驱动 procmon 事件线程）卡住，造成主 GUI
        # 被 Windows 标记「未响应」。
        self._enqueue_launch_check(pid, entry)

        # 行为启发：登记进程启动(父PID/签名由后续评估时按需补)
        try:
            ba = self._get_behavior_analyzer()
            if ba is not None:
                ba.feed_process_start(pid, name, exe_path or '', int(parent_pid or 0))
        except Exception:
            pass

    def _on_etw_process_terminated(self, event: dict):
        """ETW 进程终止事件回调"""
        pid = event.get('pid', 0)
        with self._etw_lock:
            self._etw_pids_checked.discard(pid)
        # 行为启发：进程退出
        try:
            ba = self._get_behavior_analyzer()
            if ba is not None:
                ba.feed_process_exit(pid)
        except Exception:
            pass

    # ---- 进程监控 ----

    def _take_snapshot(self):
        """采集当前所有进程的快照"""
        snapshot: Dict[int, dict] = {}
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline',
                                             'cpu_percent', 'create_time',
                                             'num_threads']):
                try:
                    info = proc.info
                    pid = info['pid']
                    snapshot[pid] = {
                        'name': (info.get('name') or '').lower(),
                        'exe': info.get('exe') or '',
                        'cmdline': info.get('cmdline') or [],
                        'cpu': info.get('cpu_percent') or 0,
                        'threads': info.get('num_threads') or 0,
                        'create_time': info.get('create_time') or 0,
                        'proc': proc,
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        psutil.ZombieProcess):
                    continue
        except Exception as e:
            logger.error(f"采集进程快照失败: {e}")
        with self._snapshot_lock:
            self._process_snapshot = snapshot
            self._known_pids = set(snapshot.keys())
            self._stats['processes_monitored'] = len(snapshot)

    def _watchdog_loop(self):
        """Watchdog：监控主监控线程的存活状态，异常退出后自动重启

        策略：
        - 每 30 秒检查一次 _monitor_thread 是否存活
        - 检查心跳时间戳：若超过 60 秒未更新，判定为卡死
        - 异常退出后重启 _monitor_thread，最多重启 3 次

        线程优先级：HIGHEST —— watchdog 是监控监控者的，自身不能被饿死
        """
        # Watchdog 线程设为 HIGHEST（系统可能拦截 TIME_CRITICAL）
        _boost_current_thread_priority('highest')

        restart_count = 0
        max_restarts = 3

        while not self._stop_event.is_set():
            # 每 30 秒检查一次
            if self._stop_event.wait(30):
                break

            # 检查主线程是否存活
            if self._monitor_thread is None or not self._monitor_thread.is_alive():
                if restart_count >= max_restarts:
                    logger.error(f'监控线程已死亡，重启次数达上限({max_restarts})，放弃重启')
                    self._add_event('system', 0, '', 'error',
                                    f'进程保护监控线程死亡，重启失败 {max_restarts} 次')
                    return

                restart_count += 1
                logger.warning(f'监控线程已死亡，尝试重启 (第 {restart_count}/{max_restarts} 次)')
                self._add_event('system', 0, '', 'warning',
                                f'监控线程异常退出，正在重启 ({restart_count}/{max_restarts})')

                try:
                    self._monitor_thread = threading.Thread(
                        target=self._monitor_loop, daemon=True,
                        name=f'ProcessProtection-Restart-{restart_count}'
                    )
                    self._monitor_thread.start()
                    # 重置心跳
                    self._last_heartbeat = time.time()
                except Exception as e:
                    logger.error(f'重启监控线程失败: {e}')
                continue

            # 检查心跳：超过 60 秒未更新视为卡死
            now = time.time()
            if self._last_heartbeat > 0 and (now - self._last_heartbeat) > 60:
                logger.warning(f'监控线程心跳超时 ({now - self._last_heartbeat:.0f}秒)，判定为卡死')
                # 卡死时无法通过 join 释放线程，只能新建一个
                # 原 _monitor_thread 会作为 daemon 自然回收
                if restart_count < max_restarts:
                    restart_count += 1
                    logger.warning(f'监控线程卡死，尝试重启 (第 {restart_count}/{max_restarts} 次)')
                    self._add_event('system', 0, '', 'warning',
                                    f'监控线程心跳超时，正在重启 ({restart_count}/{max_restarts})')
                    try:
                        self._monitor_thread = threading.Thread(
                            target=self._monitor_loop, daemon=True,
                            name=f'ProcessProtection-Heartbeat-{restart_count}'
                        )
                        self._monitor_thread.start()
                        self._last_heartbeat = time.time()
                    except Exception as e:
                        logger.error(f'重启卡死的监控线程失败: {e}')

    def _monitor_loop(self):
        """主监控循环

        设计要点（解决高 CPU 下拦截延迟问题）：
        1. 线程优先级提升 — ABOVE_NORMAL，避免被 UI/前台进程饿死
        2. psutil 字段精简 — 只采 pid/name/exe/cmdline 四元组，去掉 cpu/threads/status 等非必需
           （每个字段都一次系统调用，200 进程 × 3 个多余字段 = 600 次额外内核调用）
        3. 高 CPU 自适应 — 负载 > 70% 时：
           - 轮询间隔拉到 2.0s（主动降频削减自身负载，打破"轮询风暴"恶性循环；
             新进程检测延迟由 ETW/WTS 事件通道 <1s 兜底）
           - 注入检测频率进一步延后（让出 CPU 给关键路径）
           - 跳过行为检测（非关键）
        4. 注入检测与新进程检查解耦 — 注入检测需要枚举线程/模块，耗时长且需打开句柄，
           放在独立的节奏中，不阻塞关键路径；且按轮转分批执行，控制单次 CPU 尖峰
        """
        # ---- 启动阶段 ----
        # 提升线程优先级（关键！高 CPU 下不被饿死）
        boosted = _boost_current_thread_priority('above_normal')
        if boosted:
            logger.debug('监控线程优先级已提升到 ABOVE_NORMAL')

        # 预热 psutil.cpu_percent（首次调用返回 0.0，第二次才有值）
        _get_system_load()

        # 启动延迟：等待 UI 完全初始化
        self._stop_event.wait(5)
        if self._stop_event.is_set():
            return

        # 第一次心跳，告知 watchdog 主循环已启动
        self._last_heartbeat = time.time()

        # 第一次迭代：建立基线快照
        self._take_snapshot()
        last_snapshot = dict(self._process_snapshot)

        # ---- 主循环 ----
        # 注入检测计数器（与主循环解耦）
        injection_counter = 0

        while not self._stop_event.is_set():
            try:
                # ---- 自适应轮询间隔 ----
                # 高 CPU 负载 → 反而缩短间隔（更频繁检测新进程）
                # 但使用 max() 兜底，避免过于频繁
                load = _get_system_load()
                is_high_cpu = load > _HIGH_CPU_LOAD_THRESHOLD
                interval = _MONITOR_INTERVAL_HIGH_CPU if is_high_cpu else _MONITOR_INTERVAL

                self._stop_event.wait(interval)
                if self._stop_event.is_set():
                    break

                # 更新心跳（每次循环开始时）
                self._last_heartbeat = time.time()

                # ---- 关键路径：新进程检测（字段最精简）----
                # 只采四元组：pid/name/exe/cmdline — 其余字段在需要时按需再取
                current_snapshot: Dict[int, dict] = {}
                new_pids: Dict[int, dict] = {}

                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                    try:
                        # 主进程自身必须显式排除：_is_psls_related_process 只认
                        # 子进程/QtWebEngine，主进程（python.exe 自身）的父进程
                        # 是终端/explorer，不满足任何判定，会被误当"新进程"
                        # 送进沙箱分析，判 malware 后触发自我处置导致闪退。
                        if proc.pid == os.getpid() or self._is_psls_related_process(proc):
                            continue

                        info = proc.info
                        pid = info['pid']
                        entry = {
                            'name': (info.get('name') or '').lower(),
                            'exe': info.get('exe') or '',
                            'cmdline': info.get('cmdline') or [],
                            'proc': proc,
                        }
                        current_snapshot[pid] = entry

                        # 检测新进程 → 立即送入 _check_new_process（含快速注入预检）
                        if pid not in last_snapshot:
                            new_pids[pid] = entry

                    except (psutil.NoSuchProcess, psutil.AccessDenied,
                            psutil.ZombieProcess):
                        continue

                # 检查新进程 — 这是病毒拦截的关键路径，必须最先执行。
                # 【升级1】驱动可用时, 新进程由内核 PRE/ETW 事件喂入(on_driver_
                # process_create_event/_on_etw_process_created, 天然去重),
                # 轮询枚举不再需要逐个入队(仅驱动缺失时回退兜底), 消除 1s 窗口。
                if not self._driver_active:
                    for pid, entry in new_pids.items():
                        try:
                            self._enqueue_launch_check(pid, entry)
                        except Exception as e:
                            logger.error(f'新进程入调度队列失败 PID={pid}: {e}')

                # ---- 非关键路径：注入检测（节奏独立，高 CPU 时延后）----
                injection_counter += 1
                inj_interval = (
                    _INJECTION_CHECK_INTERVAL_HIGH_CPU if is_high_cpu
                    else _INJECTION_CHECK_INTERVAL_NORMAL
                )
                if injection_counter >= inj_interval:
                    injection_counter = 0
                    with self._stats_lock:
                        self._stats['check_count'] += 1
                    try:
                        self._check_injections(current_snapshot)
                    except Exception as e:
                        logger.error(f'注入检测异常: {e}')

                # ---- 更新快照 ----
                last_snapshot = current_snapshot
                with self._snapshot_lock:
                    self._process_snapshot = current_snapshot
                    self._known_pids = set(current_snapshot.keys())
                    with self._stats_lock:
                        self._stats['processes_monitored'] = len(current_snapshot)

            except Exception as e:
                logger.error(f"进程监控循环异常: {e}")
                time.sleep(1)

    # ---- 新进程检查 ----

    def _check_new_process(self, pid: int, entry: dict,
                           startup_survey: bool = False):
        """检查新出现的进程

        新架构（全部先终止后扫描）：
        - 所有非白名单进程 → **立即终止 → 沙箱验证 → 放行/拦截**
        - 仅以下进程直接放行（内存级检查，不阻塞 ETW 回调）：
          1. PSLS 自身相关进程
          2. QtWebEngine 子进程
          3. 系统关键进程名白名单（svchost/explorer 等）
          4. 可信目录（C:\\Windows / C:\\Program Files 等）
          5. 扫描缓存中已判定 clean 的文件
        - 其余全部先终止后沙箱分析，判定 clean 才询问是否重启

        startup_survey=True（启动存量扫描模式）：PSLS 启动时已存在的进程
        走同一判定链路，但"普通非信任程序"分支不全部终止，仅静态判定
        可疑（自爆特征/PE 高风险）才走终止+询问链路，其余放行。
        """
        name = entry.get('name', '')
        exe = entry.get('exe', '')
        cmdline = entry.get('cmdline', [])
        proc = entry.get('proc')

        # 跳过系统空闲进程
        if pid == 0:
            return

        # 启动存量扫描：无 exe 路径的存量进程直接跳过（多为系统/权限受限
        # 进程，走"exe 路径不可用"通知会刷屏），不产生监测记录。
        if startup_survey and not exe:
            return

        # 主进程自身绝不参与新进程检查（ETW/轮询/WTS 任何通道进来的都拦截）：
        # 曾发生 PSLS 自身 python.exe 被当"非信任程序"送进沙箱，判 malware
        # 后自我处置间接导致主 GUI 闪退。
        if pid and pid == os.getpid():
            logger.debug(f'新进程检查跳过 PSLS 主进程自身: PID={pid} {name}')
            return

        # --- 【沙箱逃逸拦截】(必须在下面的"正被分析中"豁免之前) ---
        # 实测样本 G4m0ad2f1qi（加强版）用 ShellExecuteExW(lpVerb="runas")
        # 自提权：Windows UAC(consent.exe) 提权出的进程会**脱离 Sandboxie
        # 在宿主运行**，于是"沙箱里什么都没观察到"，真实系统却被覆写 MBR。
        # 判据（不依赖 token / 完整性级别，避免被 FakeAdminRights 干扰）：
        #   该进程的运行路径正是我们**正在分析的目标**，但它不在 Sandboxie
        #   分析盒的 PID 列表里 → 它跑在盒外 → 逃逸，立即终止并上报。
        # 盒 PID 列表为空（查询失败 / 盒空）时跳过，避免误杀。
        if (exe and self._is_sandbox_analyzing(exe)
                and not self._is_sandboxie_own_path(exe)
                and not self._is_in_psls_sandbox_dir(exe)):
            _box_pids = self._sandboxie_box_pids()
            if _box_pids and pid not in _box_pids:
                logger.error(
                    f'沙箱逃逸拦截：被分析目标出现在盒外 PID={pid} {name} {exe}')
                try:
                    self._emergency_kill(pid)
                except Exception:
                    pass
                self._notify_launch_monitoring(
                    pid, name or f'PID-{pid}', exe,
                    reason='沙箱逃逸（提权/runas 脱离沙箱），已终止',
                    scan_result=LaunchScanResult(
                        status='blocked',
                        verdict='malware',
                        score=90,
                        signatures=['Sandbox.Escape.OutOfBox'],
                        file_path=exe,
                    ),
                )
                self._add_event(
                    'sandbox_escape', pid, name or '', 'threat',
                    '检测到沙箱逃逸：被分析目标在沙盒外运行，已终止', exe)
                return

        # --- 【已拦截程序重现拦截】（必须在"正被分析中"路径豁免之前）---
        # 实测样本（MinecraftRansomware.exe / G4m0ad2f1qi）都用 runas 自提权
        # **重启自己**：提权实例是新 PID、但路径与原程序完全相同。原逻辑只按
        # "正在沙箱分析的路径"判逃逸，而 >50MB 走 oversize 分支时该路径从未
        # 登记 → 提权实例完全放行（写 PhysicalDrive0 / 关防火墙 / 改登录密码）。
        # 这里按"路径黑名单"判定：凡被 PSLS 终止过的程序，其任何新实例
        # （沙箱盒内实例除外）立即终止。
        if exe and not startup_survey and self._is_exe_blocked(exe):
            _br_ppid = int(entry.get('parent_pid') or 0)
            _br_in_box = (self._is_in_psls_sandbox_dir(exe)
                          or self._is_sandbox_descendant(pid, _br_ppid))
            if not _br_in_box:
                _br_box_pids = self._sandboxie_box_pids()
                if pid in _br_box_pids:
                    _br_in_box = True
                elif not _br_box_pids and self._is_sandbox_analyzing(exe):
                    # 盒 PID 查询不可用/为空，但该路径确实正在分析 → 保守豁免
                    # （避免把沙箱盒内正在被分析的实例杀掉导致分析中断）
                    _br_in_box = True
            if not _br_in_box:
                self._kill_blocked_relaunch(pid, name, exe, _br_ppid)
                return

        # --- 【敏感命令拦截】（必须在沙箱豁免之前）---
        # net.exe / cmd.exe / powershell.exe 都是微软自带工具，判据是**发起链**：
        # 链上出现任一非微软官方进程即拦截。覆盖账户/凭据篡改（net user 改密码、
        # net localgroup administrators…）与系统级破坏命令（关防火墙、停安全服务、
        # 删卷影、bcdedit、takeown+icacls+rmdir 破坏链）。
        # 为什么必须早于沙箱豁免：这些破坏命令走**系统服务 RPC / 驱动**，在沙箱盒内
        # 执行同样落到真实系统（Sandboxie 用户态重定向管不住），若因"沙箱子孙进程
        # 豁免"而放行，就等于样本在沙箱里把宿主防火墙关了、把登录密码改了。
        # BT 约束（不得破坏）：**不终止正在被沙箱分析的样本本体** —— 那会让沙箱
        # 变成 error/skipped，违反"沙箱失败→不输出沙箱数据、仅靠 ML 引擎、不改
        # 扫描路结论"的既有语义。故只终止执行破坏命令的子进程（cmd.exe/netsh/…），
        # 样本本体仍交给沙箱 + 扫描链路正常判定。
        # 存量扫描（startup_survey）不适用：只做静态判定，不做终止处置。
        if not startup_survey and _classify_credential_tamper is not None:
            # 已由 EK 快车道处置过（独立线程抢时间，已终止+上报）→ 主池跳过，
            # 既不重复上报，也不再让该条目占用主池时间。
            try:
                if self._is_ek_handled(pid):
                    logger.debug(
                        f'敏感命令已由 EK 快车道处置，主池跳过 PID={pid} {name}')
                    return
            except Exception:
                pass
            _cred = None
            try:
                _cred = _classify_credential_tamper(cmdline, name)
            except Exception:
                _cred = None
            if _cred and HAS_PSUTIL:
                _cred_ppid = int(entry.get('parent_pid') or 0)
                _cred_holder: List[Any] = [None]

                def _cred_chain_runner():
                    try:
                        _cred_holder[0] = _check_origin_chain(
                            pid, _cred_ppid,
                            ci_dirs=type(self)._CI_WINDOWS_SYSTEM_DIRS)
                    except Exception:
                        _cred_holder[0] = None

                _cred_t = threading.Thread(
                    target=_cred_chain_runner, daemon=True,
                    name=f'CredChain-{pid}')
                _cred_t.start()
                # 【不响应保护】签名发布者查询（PowerShell 兜底）最坏可达秒级；
                # 用独立线程 + 2s 硬上限兜底，超时按"官方"放行（宁可漏判也不误杀）。
                _cred_t.join(timeout=2.0)
                _chain = _cred_holder[0]
                if _chain is None:
                    logger.warning(
                        f'敏感命令来源判定超时（>2s），本条放行: {name} PID={pid}')
                elif not _chain[0]:
                    _cred_offender = _chain[1] or {}
                    _co_pid = int(_cred_offender.get('pid') or 0)
                    _co_exe = _cred_offender.get('exe') or ''
                    # 发起者是否正在沙箱盒内（= 被分析样本本体）→ 决定是否动它
                    _co_in_box = bool(_co_exe) and \
                        self._is_in_psls_sandbox_dir(_co_exe)
                    if not _co_in_box and _co_pid:
                        _co_box_pids = self._sandboxie_box_pids()
                        if _co_pid in _co_box_pids:
                            _co_in_box = True
                        elif not _co_box_pids and _co_exe \
                                and self._is_sandbox_analyzing(_co_exe):
                            _co_in_box = True
                    try:
                        self._handle_credential_tamper(
                            pid, name, exe, _cred, _cred_offender,
                            offender_in_box=_co_in_box)
                    except Exception as _e:
                        logger.debug(f'敏感命令处置异常: {_e}')
                    return
                else:
                    logger.debug(
                        f'敏感命令来源为微软官方链，放行: {name} PID={pid} '
                        f'{_cred.get("reason")}')

        # --- 沙箱分析豁免（防止沙箱内被测进程二次被自己的启动监测拦截）---
        # _sandbox_worker 创建 SandboxAnalyzer 前会先把 exe 加入
        # _sandbox_analyzing_paths；SandboxAnalyzer._launch_sandboxed 通过
        # CreateProcessW/SUSPENDED 启动 COPY_PATH（%TEMP%/psls_sandbox_*/sample.exe），
        # ETW 会看到新进程事件，如不豁免会再进入 _sandbox_then_release →
        # 同一 exe 被复制→启动→拦截→复制→… 形成无限循环。
        # 三层命中：精确路径 / 目录前缀 / psls_sandbox_ 目录名通配。
        if exe and self._is_sandbox_analyzing(exe):
            self._notify_launch_monitoring(
                pid, name or f'PID-{pid}', exe,
                reason='沙箱内部启动（豁免：正被分析中）',
                scan_result=LaunchScanResult(
                    status='scanning',
                    verdict='clean',
                    score=0,
                    signatures=['Sandbox.Analyzing-InProgress'],
                    file_path=exe,
                ),
            )
            logger.debug(
                f'_check_new_process 跳过沙箱内部进程[路径命中]: PID={pid} {name} {exe}')
            return

        # --- PID 维度豁免：沙箱目标进程的直系子孙进程（覆盖 payload 落地到
        # 用户目录 AppData/Local/Temp 的情况，这些路径 startswith 无法命中）---
        parent_pid = int(entry.get('parent_pid') or 0)
        if pid and self._is_sandbox_descendant(pid, parent_pid):
            self._notify_launch_monitoring(
                pid, name or f'PID-{pid}', exe,
                reason=f'沙箱进程族衍生（豁免：parent_pid={parent_pid} 属分析中目标）',
                scan_result=LaunchScanResult(
                    status='scanning',
                    verdict='clean',
                    score=0,
                    signatures=['Sandbox.TargetDescendant'],
                    file_path=exe,
                ),
            )
            logger.debug(
                f'_check_new_process 跳过沙箱进程族子孙[PID命中]: PID={pid} '
                f'ppid={parent_pid} {name} {exe}')
            return

        # 自亲和豁免：PSLS 相关进程不检查
        if proc and self._is_psls_related_process(proc):
            logger.debug(f'新进程检查跳过 PSLS 相关进程: PID={pid} {name}')
            return

        # QtWebEngine / WebView2 进程豁免（通过命令行/名称特征，覆盖无 proc 的 ETW 通道）
        # WebView2（msedgewebview2 及 --type=renderer 等 Chromium 子进程）是 PSLS
        # UI 宿主依赖，隔离化场景下绝不能送沙箱/终止，否则冻死 PSLS 自身。
        if cmdline:
            cmdline_str = ' '.join(cmdline).lower()
            if 'qtwebengine' in cmdline_str or '--process-per-site' in cmdline_str:
                logger.debug(f'新进程检查跳过 QtWebEngine 进程: PID={pid} {name}')
                return
            if any(tok in cmdline_str for tok in self._WEBVIEW2_TOKENS) \
                    or any(tok in name.lower() for tok in self._WEBVIEW2_TOKENS):
                logger.debug(f'新进程检查跳过 WebView2 进程: PID={pid} {name}')
                return

        # 无 exe 路径的进程无法沙箱分析 → 记录监测事件，避免静默漏监测
        if not exe:
            self._notify_launch_monitoring(
                pid, name or f'PID-{pid}', '',
                'exe 路径不可用，无法沙箱分析')
            logger.warning(f'新进程检查：exe 路径不可用 PID={pid} name={name}，已记录监测事件')
            return

        # ---------- 快速放行检查（内存级操作，不阻塞 ETW 回调） ----------
        # 注：敏感命令拦截（net user / netsh / net stop / takeown 链…）已前移到
        # "沙箱豁免"之前 —— 沙箱盒内执行的破坏命令走系统服务 RPC，必须照样拦。

        # 0. 系统进程伪装检测（银狐惯用：用户目录下的 svchost/services 副本）
        #    必须在名字白名单之前 — 否则伪装进程会被白名单直接放行
        if self._is_masquerading_system_binary(name, exe):
            self._sandbox_then_release(
                pid, name, exe, cmdline,
                reason=f'系统进程伪装: {name} 运行于非系统目录 {os.path.dirname(exe)}',
            )
            return

        # 1. 系统关键进程名白名单
        # 特殊处理：解释器进程（cmd.exe/powershell.exe 等）若命令行中包含
        # 脚本文件 (.bat/.ps1/.vbs/.js/.cmd)，则放行解释器本身但对脚本文件
        # 进行沙箱分析。这样双击 .bat 不会被直接放行。
        try:
            name_lower = name.lower() if name else ''
            if name_lower in self._SYSTEM_CRITICAL_EXE_NAMES:
                # 解释器特殊处理：提取命令行中的脚本文件路径
                if name_lower in self._SCRIPT_INTERPRETERS and cmdline:
                    script_path = self._extract_script_path_from_cmdline(cmdline)
                    if script_path:
                        # 检查脚本是否在沙箱内部（路径包含 psls_sandbox_）
                        # 沙箱分析器会创建副本 sample_XXXX.bat，这个副本路径
                        # 与原始脚本不同，无法通过 _inflight_script_paths 去重
                        if 'psls_sandbox_' in script_path.lower():
                            logger.debug(
                                f'解释器 {name} 启动沙箱内部脚本副本 {script_path}，'
                                f'跳过检测')
                            return

                        # 去重：如果同一脚本已在分析中，直接放行（不重复沙箱）
                        if self._is_script_analyzing(script_path):
                            logger.debug(
                                f'解释器 {name} 启动脚本 {script_path}，'
                                f'脚本正在分析中，跳过重复检测')
                            return
                        # 登记脚本为"正在分析"，沙箱完成后由调用方取消登记
                        self._mark_script_analyzing(script_path, ttl_seconds=30)
                        # 分析脚本源代码，识别子进程并登记去重
                        # 防止恶意脚本启动的子进程被重复送入沙箱分析
                        script_children = self._register_script_children_for_dedup(script_path)
                        script_name = os.path.basename(script_path)
                        logger.info(
                            f'解释器 {name} 启动脚本 {script_path}，'
                            f'对脚本进行沙箱分析'
                            f'{f"（发现 {len(script_children)} 个子进程目标）" if script_children else ""}')
                        # 使用脚本文件名（如 test.bat）而不是解释器名（cmd.exe）
                        # 这样弹窗和日志才能正确显示被隔离/分析的是脚本文件
                        self._sandbox_then_release(
                            pid, script_name, script_path, cmdline,
                            reason=f'{name_lower} 启动脚本: {script_name}',
                            on_done=lambda sp=script_path: self._unmark_script_analyzing(sp),
                        )
                        return
                    else:
                        # 命令行解析失败：记录警告但仍然放行解释器
                        # （避免因解析问题导致正常 cmd.exe 被拦截）
                        logger.debug(
                            f'解释器 {name} 启动的命令行未匹配到脚本文件: {cmdline}')
                # 无脚本的纯解释器调用（如 cmd.exe 单独启动）直接放行
                return
        except Exception:
            pass

        # 2. PSLS 自身目录
        if self._self_excluded_dirs and exe:
            try:
                ep_lower = os.path.abspath(exe).lower()
                if any(ep_lower.startswith(d) for d in self._self_excluded_dirs):
                    return
            except Exception:
                pass

        # 2.6 Sandboxie 自身进程豁免（必须在"非信任程序启动→终止"链路之前）
        #     Start.exe / SbieSvc / SandboxieRpcSs / SandboxieDcomLaunch /
        #     SbieCtrl 等会在盒启动瞬间新起。若不豁免，它们会被当作"非信任
        #     程序启动"立即 TerminateProcess —— 连 PSLS 自己刚用来启动样本的
        #     Start.exe 都被杀掉，盒随即被拆、盒可用性检查 WinError 32，
        #     被迫回退 AppContainer，表现为"沙箱未检出"。
        #     实测日志：sandboxierpcss.exe / start.exe / sbiectrl.exe /
        #     sandboxiedcomlaunch.exe 逐个被 _emergency_kill。
        if self._is_sandboxie_own_path(exe):
            logger.debug(
                f'新进程检查跳过 Sandboxie 自身进程: PID={pid} {name} {exe}')
            return

        # 2.5 发起者排除名单（可配置：内置项 + 用户项 + 宿主目录动态项）
        #     命中即跳过**用户态**处置（沙箱 / 终止 / 隔离）——名单是数据，
        #     改名单无需重签驱动。**不关闭内核侧硬规则**：受保护目录写入拦截、
        #     MBR/引导防护、自保护等仍照常生效（借鉴 Xdows 的 INITIATOR_EXCLUSION
        #     语义：只免用户态咨询，不免内核强制）。
        try:
            _ie = getattr(self, '_initiator_exclusions', None)
            if _ie is not None:
                _ie_reason = _ie.match(name, exe)
                if _ie_reason:
                    logger.debug(
                        f'发起者排除名单命中，跳过用户态处置: {name} ({exe}) ← {_ie_reason}')
                    return
        except Exception:
            pass

        # 3. CI 深层系统目录豁免（WinVerifyTrust 对 Catalog 签名返回"无签名"，
        #    这些目录受 CI/ACL 保护，保留目录信任避免误报；
        #    伪装进程已在第 0 步被拦截，不会走到这里）
        if exe and self._CI_WINDOWS_SYSTEM_DIRS:
            try:
                ep_lower = os.path.abspath(exe).lower()
                if any(ep_lower.startswith(d) for d in self._CI_WINDOWS_SYSTEM_DIRS):
                    return
            except Exception:
                pass

        # 4. 扫描缓存中已判定 clean（避免重复终止同一程序）
        try:
            mtime = os.path.getmtime(exe)
        except Exception:
            mtime = 0
        with self._launch_scan_lock:
            cached = self._launch_scan_cache.get(exe)
            if cached:
                cached_mtime, cached_status, cached_time = cached
                if (cached_mtime == mtime
                        and time.time() - cached_time < self._LAUNCH_SCAN_CACHE_TTL):
                    if cached_status == 'clean':
                        return  # 缓存判定 clean，直接放行
                    # 缓存判定非 clean → 走终止链路
                    # （可能是同一恶意文件被再次启动）

        # 4.1 沙箱放行信任预检查：沙箱此前判定安全的程序（sandbox_trust 表）放行
        #     —— 满足"沙箱判安全后下次不再经过沙箱"。哈希制不受 mtime/重启影响，
        #     且是独立于 whitelist 的信任，只跳过沙箱，其他模块继续监测。
        #     IO 较轻（仅首次散列 ~1-2ms/次）；仅在必检时执行，避免影响海量系统进程。
        #     同时读取"广义白名单"(whitelist 表)：用户手动添加/扫描链入库的白名单
        #     程序沙箱直接放行，不再送沙箱。方向是单向的——沙箱只读广义白名单；
        #     沙箱自己判定安全后写入的 sandbox_trust 不回写白名单（各模块保持独立，
        #     避免放行扩散到所有模块）。
        try:
            if self._signature_db is not None and exe and os.path.isfile(exe):
                import hashlib as _hl2
                _h2 = _hl2.sha256()
                with open(exe, 'rb') as _f2:
                    for _chunk2 in iter(lambda: _f2.read(65536), b''):
                        _h2.update(_chunk2)
                _digest2 = _h2.hexdigest()
                _trusted_hit = None
                try:
                    if self._signature_db.is_sandbox_trusted(_digest2):
                        _trusted_hit = '沙箱放行信任'
                except Exception:
                    pass
                if _trusted_hit is None:
                    try:
                        # 只读广义白名单（不写入、不回写）
                        if self._signature_db.is_whitelisted(_digest2):
                            _trusted_hit = '广义白名单'
                    except Exception:
                        pass
                if _trusted_hit is not None:
                    try:
                        mtime3 = os.path.getmtime(exe)
                    except Exception:
                        mtime3 = 0
                    with self._launch_scan_lock:
                        self._launch_scan_cache[exe] = (mtime3, 'clean', time.time())
                    logger.info(
                        f'{_trusted_hit}命中（不进沙箱）: {name} ({exe})')
                    return
        except Exception:
            pass

        # 5. 信任签名直接放行（不终止不沙箱）—— 解决 QQ/微信等"误杀"反复出现
        #    微软/腾讯官方签名的可执行文件，Authenticode 数字签名有效即同时保证
        #    代码完整性 + 发布者身份，无法被伪造，信任级别等同系统关键进程名白名单。
        #    原理：QQ 每次更新/升级都会生成新的二进制（mtime 变化 → 缓存失效），
        #    且 QQ 运行时会大量派生已签名的辅助进程，若每次都走"先终止后沙箱"链路
        #    就会反复出现终止→沙箱分析→（行为分偏高时）误杀。签名放行将其彻底豁免。
        #    冷路径约 100-300ms（PowerShell 提取发布者，仅首次），结果在
        #    signature_verifier 类级缓存，后续 <1ms。
        #
        # 【不响应保护：显式线程+1.5s 超时】
        #   get_signer_info 在 PowerShell 5.1 + 受限 WDAC 场景会 hang 数十秒
        #   （Authenticode Catalog 查询会触发 catroot2 重建锁）。这里用独立
        #   daemon 线程把它包起来，超过 1.5s 直接"签名校验失败→继续判
        #   定"，宁可多送沙箱也不要卡死整个 worker。
        _si = None  # 供 5.6 上下文信任评估复用（签名结果类级缓存，<1ms）
        try:
            if exe:
                from utils.signature_verifier import get_verifier, classify_signer, SIGNER_TIER_KNOWN, SIGNER_TIER_MISC
                _v = get_verifier()
                if _v:
                    _signer_info_holder: List[Any] = [None]
                    def _signer_runner():
                        try:
                            _signer_info_holder[0] = _v.get_signer_info(exe)
                        except Exception:
                            _signer_info_holder[0] = None
                    _sig_t = threading.Thread(target=_signer_runner, daemon=True,
                                              name=f'SignerCheck-{pid}')
                    _sig_t.start()
                    _sig_t.join(timeout=1.5)
                    _si = _signer_info_holder[0]
                    if _si and _si.get('verified', False):
                        _tier = _si.get('tier') or classify_signer(
                            _si.get('verified'), _si.get('publisher'))
                        if _tier == SIGNER_TIER_KNOWN:
                            with self._launch_scan_lock:
                                self._launch_scan_cache[exe] = (mtime, 'clean', time.time())
                            logger.info(
                                f'信任签名放行，不再终止沙箱: {name} ({exe}) '
                                f'signer={_si.get("publisher")} tier={_tier}')
                            return
                        if _tier == SIGNER_TIER_MISC:
                            # 有效签名但发布者不在已知名单（灰名单）。
                            # 有效 Authenticode 签名是"文件未被篡改"的确定性证据，
                            # 优先级高于内容启发式。不再直接送沙箱（沙箱会先终止进程
                            # 再分析，对合法签名软件误杀成本高），改为先做文件扫描：
                            #   - 文件扫描 clean → 直接放行（不再终止/沙箱）
                            #   - 文件扫描 suspicious/malware → 继续走沙箱链路深析
                            # 这能消除大量对合法签名软件（Electron/IDE 组件等）的误杀。
                            try:
                                _scan_r = self._scan_exe_for_misc_signer(exe)
                                if _scan_r and _scan_r.status == 'clean':
                                    with self._launch_scan_lock:
                                        self._launch_scan_cache[exe] = (
                                            mtime if mtime else 0, 'clean', time.time())
                                    logger.info(
                                        f'已签名(MISC)+文件扫描clean，放行: {name} ({exe}) '
                                        f'signer={_si.get("publisher")}')
                                    return
                            except Exception as _e:
                                logger.debug(f'MISC签名文件扫描异常，降级走沙箱: {_e}')
                            logger.debug(
                                f'已签名但发布者未知(灰名单MISC)，送检: {name} ({exe})')
        except Exception:
            pass

        # 5.5 视觉恶搞信任缓存：用户在"信任并重启"询问中批准过的 exe
        #     30 分钟窗口内直接放行（避免反复终止用户认可的程序）
        try:
            if self._is_prank_trusted(exe):
                logger.debug(
                    f'_check_new_process 跳过最近被用户信任的程序: '
                    f'{name} ({exe})')
                return
        except Exception:
            pass

        # 5.6 上下文信任放行（多维度防误报核心）
        # 综合 进程来源/数字签名/行为链/父子进程关系/文件年龄/上下文逻辑
        # 六维评估信任分。目标：用户主动双击的老文件、历史 CLEAN 过的程序、
        # 已验证签名程序，不再"每次启动先被杀一次再询问重启"。
        # 强信号（伪装/危险目录/可疑名）在前置步骤已拦截，到不了这里；
        # 高信任还需通过快速注入预检（远线程/RWX 命中 → 仍送沙箱）。
        # 未达放行阈值的，把评估结果随身携带 → 沙箱判定作为"调查先验"
        # 降级分数型误判（修改器/正常软件不被误隔离），一票否决硬证据不豁免。
        ctx = None
        try:
            _sig_verified = bool(_si and _si.get('verified', False))
            _sig_pub = (_si.get('publisher') or '') if _si else ''
            ctx = self._assess_contextual_trust(
                exe, name, parent_pid, cmdline,
                verified=_sig_verified, publisher=_sig_pub)
            if ctx['skip_sandbox']:
                _ctx_inj_hit = False
                if proc and pid > 0:
                    _ctx_inj_holder: List[bool] = [False]
                    def _ctx_inj_runner():
                        try:
                            _ctx_inj_holder[0] = bool(
                                self.quick_injection_check(pid, name, exe, proc))
                        except Exception:
                            _ctx_inj_holder[0] = False
                    _ctx_inj_t = threading.Thread(
                        target=_ctx_inj_runner, daemon=True,
                        name=f'CtxInjCheck-{pid}')
                    _ctx_inj_t.start()
                    _ctx_inj_t.join(timeout=1.2)
                    _ctx_inj_hit = _ctx_inj_holder[0]
                if not _ctx_inj_hit:
                    try:
                        mtime2 = os.path.getmtime(exe)
                    except Exception:
                        mtime2 = 0
                    with self._launch_scan_lock:
                        self._launch_scan_cache[exe] = (mtime2, 'clean', time.time())
                    logger.info(
                        f'上下文信任放行（免终止免沙箱）: {name} ({exe}) '
                        f'trust={ctx["trust"]} reasons={ctx["reasons"]}')
                    self._notify_launch_monitoring(
                        pid, name or f'PID-{pid}', exe,
                        reason=f'上下文信任放行（{"、".join(ctx["reasons"])[:90]}）',
                        scan_result=LaunchScanResult(
                            status='clean',
                            verdict='clean',
                            score=0,
                            signatures=['Context.Trusted'],
                            file_path=exe,
                        ),
                    )
                    return
        except Exception as e_ctx:
            logger.debug(f'上下文信任评估异常（降级走沙箱）: {e_ctx}')
            ctx = None

        # 6. 快速注入预检（命中则走沙箱链路，reason 标注注入特征）
        # 【不响应保护：1.2s 总超时】枚举线程/VirtualQueryEx 在受限 PPL
        #    进程上偶尔 hang（内核回调未返回），超时直接跳过。
        if proc and pid > 0:
            _inj_result_holder: List[bool] = [False]
            def _inj_runner():
                try:
                    _inj_result_holder[0] = bool(
                        self.quick_injection_check(pid, name, exe, proc))
                except Exception:
                    _inj_result_holder[0] = False
            _inj_t = threading.Thread(target=_inj_runner, daemon=True,
                                      name=f'QuickInjCheck-{pid}')
            _inj_t.start()
            _inj_t.join(timeout=1.2)
            if _inj_result_holder[0]:
                self._register_visual_prank(pid, exe, name, cmdline)
                self._sandbox_then_release(
                    pid, name, exe, cmdline,
                    reason='检测到注入特征（远线程/RWX 内存）',
                    context_trust=ctx,
                )
                return

        # ---------- 以下进程均走"先终止后扫描"链路 ----------

        # 危险目录启动
        exe_lower = exe.lower()
        for danger_kw in DANGEROUS_DIR_KEYWORDS:
            if danger_kw in exe_lower:
                self._register_visual_prank(pid, exe, name, cmdline)
                self._sandbox_then_release(
                    pid, name, exe, cmdline,
                    reason=f'从危险目录启动: {os.path.dirname(exe)}',
                    context_trust=ctx,
                )
                return

        # 可疑进程名（混淆伪装）
        if name and self._is_suspicious_name(name):
            self._register_visual_prank(pid, exe, name, cmdline)
            self._sandbox_then_release(
                pid, name, exe, cmdline,
                reason=f'可疑进程名: {name}（可能是伪装的恶意程序）',
                context_trust=ctx,
            )
            return

        # 普通非信任程序：全部先终止后扫描
        # 不在白名单/可信目录/缓存clean的进程，全部走沙箱链路
        if startup_survey:
            # 启动存量扫描（survey）模式：不"全部终止"，仅静态判定可疑才处置。
            # 存量进程大多是已获信任的第三方应用，无签名/未知发布者不能直接
            # 当作可疑（会误杀大量正常程序），只认高置信静态特征（自爆/PE high）。
            if self._is_startup_survey_suspicious(exe, name, pid):
                self._register_visual_prank(pid, exe, name, cmdline)
                self._sandbox_then_release(
                    pid, name, exe, cmdline,
                    reason=f'启动存量扫描发现可疑进程: {name}',
                    context_trust=ctx,
                )
            else:
                logger.info(
                    f'启动存量扫描放行（无可疑静态特征）: PID={pid} {name} ({exe})')
            return
        self._register_visual_prank(pid, exe, name, cmdline)
        self._sandbox_then_release(
            pid, name, exe, cmdline,
            reason=f'非信任程序启动: {name}',
            context_trust=ctx,
        )

    # Windows 系统核心可执行文件白名单（不扫描，避免误报）
    _SYSTEM_CRITICAL_EXE_NAMES = {
        'svchost.exe', 'services.exe', 'winlogon.exe', 'wininit.exe', 'csrss.exe',
        'lsass.exe', 'smss.exe', 'explorer.exe', 'taskhostw.exe', 'taskhostex.exe',
        'runtimebroker.exe', 'searchui.exe', 'searchhost.exe', 'sihost.exe',
        'fontdrvhost.exe', 'ctfmon.exe', 'conhost.exe', 'dwm.exe',
        'rundll32.exe', 'regsvr32.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe',
        'notepad.exe', 'calc.exe', 'mspaint.exe', 'explorerframe.dllhost.exe',
        'backgroundtaskhost.exe', 'backgroundtaskhost.exe',
        'mousocoreworker.exe', 'usocoreworker.exe', 'usoclient.exe',
        'uedorchestrator.exe', 'updateorchestrator.exe',
        'wmiprvse.exe', 'wmiapsrv.exe', 'mmc.exe', 'taskmgr.exe',
        'audiodg.exe', 'sndvolsso.exe', 'sppsvc.exe', 'spoolsv.exe',
        'dllhost.exe', 'com surrogate',
        'systemsettings.exe', 'textinputhost.exe', 'startmenuexperiencehost.exe',
        'shellappruntime.exe', 'runtimebroker.exe',
        'dwm.exe', 'smartscreen.exe',
        'chrome.exe', 'msedge.exe',
    }

    # 核心系统进程合法目录（这些名字只允许从系统目录运行，其他位置=伪装）
    _SYSTEM_BINARY_LEGIT_DIRS = (
        '\\windows\\system32\\',
        '\\windows\\syswow64\\',
        '\\windows\\winsxs\\',
    )

    # 银狐式伪装高危名单：恶意程序最爱以这些名字落在用户目录/临时目录
    _MASQUERADE_CRITICAL_NAMES = {
        'svchost.exe', 'services.exe', 'winlogon.exe', 'wininit.exe',
        'csrss.exe', 'lsass.exe', 'smss.exe', 'fontdrvhost.exe',
    }

    # 脚本文件扩展名（沙箱分析支持）
    _SCRIPT_EXTENSIONS = {'.bat', '.cmd', '.ps1', '.vbs', '.js'}

    # 解释器进程名 → 解析命令行提取脚本路径的策略
    # 对 cmd.exe / powershell.exe / pwsh.exe / wscript.exe / cscript.exe：
    #   - cmd.exe /c script.bat  → 参数中 .bat/.cmd 文件
    #   - powershell.exe -File script.ps1 / -Command "script.ps1" → .ps1 文件
    #   - wscript.exe / cscript.exe script.vbs → .vbs/.js 文件
    _SCRIPT_INTERPRETERS = {
        'cmd.exe', 'powershell.exe', 'pwsh.exe',
        'wscript.exe', 'cscript.exe', 'mshta.exe',
    }

    # ---- 脚本沙箱去重：防止同一脚本被重复送入沙箱 ----
    # 场景：双击 .bat 时，Windows 创建 cmd.exe /c script.bat，
    #   cmd.exe 执行时会触发大量子进程（每条命令一个），
    #   每个子进程的命令行都包含 script.bat 路径，
    #   若不做去重，会导致同一脚本被送入沙箱数十次。
    # 解决方案：_inflight_script_paths 记录当前正在分析的脚本绝对路径，
    #   TTL 30 秒（足够脚本执行完毕）。在 _check_new_process 白名单
    #   检查时先查询此集合，命中则直接放行解释器子进程。
    _inflight_script_paths: Set[str] = set()
    _inflight_script_deadline: Dict[str, float] = {}
    _inflight_script_lock = threading.Lock()

    def _mark_script_analyzing(self, script_path: str, ttl_seconds: int = 30) -> None:
        """登记脚本为"正在分析"，防止重复送入沙箱。

        当 .bat/.ps1/.vbs 等脚本被送入沙箱时，先将其路径登记到
        _inflight_script_paths，后续子进程（cmd.exe/powershell.exe
        的嵌套调用）若包含相同脚本路径，会直接放行而不重复分析。
        TTL 默认 30 秒（脚本执行通常在数秒内完成）。
        """
        if not script_path:
            return
        try:
            normalized = os.path.normcase(os.path.abspath(script_path))
        except Exception:
            return
        with self._inflight_script_lock:
            self._inflight_script_paths.add(normalized)
            self._inflight_script_deadline[normalized] = time.time() + max(5, ttl_seconds)

    def _unmark_script_analyzing(self, script_path: str) -> None:
        """取消登记脚本的"正在分析"状态（分析完成后调用）。"""
        if not script_path:
            return
        try:
            normalized = os.path.normcase(os.path.abspath(script_path))
        except Exception:
            return
        with self._inflight_script_lock:
            self._inflight_script_paths.discard(normalized)
            self._inflight_script_deadline.pop(normalized, None)

    def _is_script_analyzing(self, script_path: str) -> bool:
        """查询脚本是否正在被分析（同时清理过期条目）。"""
        if not script_path:
            return False
        try:
            normalized = os.path.normcase(os.path.abspath(script_path))
        except Exception:
            return False
        with self._inflight_script_lock:
            now = time.time()
            expired = [p for p, dl in self._inflight_script_deadline.items()
                       if dl < now]
            for p in expired:
                self._inflight_script_paths.discard(p)
                self._inflight_script_deadline.pop(p, None)
            return normalized in self._inflight_script_paths

    def _extract_script_path_from_cmdline(self, cmdline: List[str]) -> Optional[str]:
        """从解释器命令行中提取脚本文件路径

        用户双击 .bat/.ps1/.vbs 等脚本时，Windows 实际启动的是解释器进程
        (cmd.exe / powershell.exe 等)，真正的脚本文件路径藏在命令行参数中。
        这些解释器在白名单中会被直接放行，导致脚本本身绕过沙箱分析。

        本方法解析命令行，返回第一个存在于磁盘上的脚本文件绝对路径。

        支持的命令行格式：
        - cmd.exe /c "path\\to\\file.bat"
        - cmd.exe /c path\\to\\file.bat
        - cmd.exe /c "path with spaces\\file.bat"
        - powershell.exe -File "path\\to\\file.ps1"
        - powershell.exe -Command "& 'path\\to\\file.ps1'"
        - wscript.exe "path\\to\\file.vbs"
        - cscript.exe "path\\to\\file.js"
        """
        if not cmdline or len(cmdline) < 2:
            return None

        # 策略 1：直接在参数中查找带脚本扩展名的文件路径
        # 跳过标志参数（以 - 或 / 开头），检查后续参数是否为脚本文件
        flag_prefixes = ('-', '/')
        for i, seg in enumerate(cmdline[1:], start=1):
            seg_clean = seg.strip('"').strip("'")

            # 检测是否为标志参数
            is_flag = seg_clean.startswith(flag_prefixes)

            # 特殊处理 -File 标志：下一个参数是脚本路径
            if is_flag and seg_clean.lower() in ('-file',):
                # 检查下一个参数是否为脚本文件
                if i < len(cmdline):
                    next_seg = cmdline[i].strip('"').strip("'")
                    ext = os.path.splitext(next_seg)[1].lower()
                    if ext in self._SCRIPT_EXTENSIONS and os.path.isfile(next_seg):
                        return os.path.abspath(next_seg)
                continue

            # 特殊处理 -Command 标志：在命令字符串中查找脚本路径
            if is_flag and seg_clean.lower() in ('-command',):
                # -Command "..." 或 -Command "& '...'"
                if i < len(cmdline):
                    cmd_str = cmdline[i]
                    # 尝试提取引号内的脚本路径
                    for ext in self._SCRIPT_EXTENSIONS:
                        # 匹配 'path\to\file.ps1' 或 "path\to\file.ps1"
                        for quote in ('"', "'"):
                            pattern = re.escape(quote) + r'([^' + re.escape(quote) + r']*\\[^' + re.escape(quote) + r']*' + re.escape(ext) + r')' + re.escape(quote)
                            m = re.search(pattern, cmd_str, re.IGNORECASE)
                            if m:
                                candidate = m.group(1)
                                if os.path.isfile(candidate):
                                    return os.path.abspath(candidate)
                    # 匹配 & 'path\to\file.ps1' 格式
                    for ext in self._SCRIPT_EXTENSIONS:
                        m = re.search(r"&\s*'([^']*\\[^']*" + re.escape(ext) + r")'", cmd_str, re.IGNORECASE)
                        if m:
                            candidate = m.group(1)
                            if os.path.isfile(candidate):
                                return os.path.abspath(candidate)
                continue

            # 普通参数：检查是否为脚本文件路径
            if is_flag:
                continue

            # 去除引号后检查是否为脚本文件
            ext = os.path.splitext(seg_clean)[1].lower()
            if ext in self._SCRIPT_EXTENSIONS and os.path.isfile(seg_clean):
                return os.path.abspath(seg_clean)

        # 策略 2：在拼接的命令行字符串中查找（处理复杂的引号嵌套）
        joined = ' '.join(cmdline[1:]) if len(cmdline) > 1 else ''
        for ext in self._SCRIPT_EXTENSIONS:
            # 双引号包围的路径
            m = re.search(r'"([^"]*\\[^"]*' + re.escape(ext) + r')"', joined, re.IGNORECASE)
            if m:
                candidate = m.group(1)
                if os.path.isfile(candidate):
                    return os.path.abspath(candidate)
            # 单引号包围的路径
            m = re.search(r"'([^']*\\[^']*" + re.escape(ext) + r")'", joined, re.IGNORECASE)
            if m:
                candidate = m.group(1)
                if os.path.isfile(candidate):
                    return os.path.abspath(candidate)
            # 不带引号的路径
            m = re.search(r'(\S+\\\S+' + re.escape(ext) + r')', joined, re.IGNORECASE)
            if m:
                candidate = m.group(1)
                if os.path.isfile(candidate):
                    return os.path.abspath(candidate)

        return None

    def _analyze_script_for_child_processes(self, script_path: str) -> List[str]:
        """分析脚本源代码，提取其中可能启动的子进程路径

        支持的脚本类型：.bat/.cmd/.ps1/.vbs/.js/.wsf
        提取策略：
        - .bat/.cmd: 识别 start、call、cmd、powershell、wscript、cscript 等命令
        - .ps1: 识别 Start-Process、Invoke-Expression、iex 等
        - .vbs/.js: 识别 Shell.Run、WScript.Shell 等
        返回：可能的子进程文件路径列表（仅包含存在于磁盘的路径）
        """
        if not script_path or not os.path.isfile(script_path):
            return []

        ext = os.path.splitext(script_path)[1].lower()
        if ext not in self._SCRIPT_EXTENSIONS:
            return []

        child_processes = []
        try:
            with open(script_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(512 * 1024)  # 最多读 512KB

            if ext in ('.bat', '.cmd'):
                # 识别 bat/cmd 中常见的进程启动模式
                patterns = [
                    # start 命令：start "" "path" 或 start path
                    r'(?i)start\s+""\s+"([^"]+\.(?:exe|bat|cmd|com|pif))"',
                    r'(?i)start\s+"([^"]+\.(?:exe|bat|cmd|com|pif))"',
                    r'(?i)start\s+([^\s&|<>]+\.(?:exe|bat|cmd|com|pif))',
                    # cmd /c 调用其他脚本
                    r'(?i)cmd\s+/(?:c|k)\s+""([^"]+\.(?:bat|cmd))"',
                    r'(?i)cmd\s+/(?:c|k)\s+([^\s&|<>]+\.(?:bat|cmd))',
                    # call 调用其他脚本
                    r'(?i)call\s+"?([^\s&|<>"]+\.(?:bat|cmd|exe))"?',
                    # powershell 调用
                    r'(?i)powershell(?:\.exe)?\s+(?:-File|-Command)\s+"?([^\s&|<>"]+\.(?:ps1|exe))"?',
                    # wscript/cscript 调用
                    r'(?i)[wc]script(?:\.exe)?\s+"([^"]+\.(?:vbs|js|wsf))"',
                    r'(?i)[wc]script(?:\.exe)?\s+([^\s&|<>]+\.(?:vbs|js|wsf))',
                    # 直接执行 exe
                    r'(?:^|[\s&|<>("])((?:[a-zA-Z]:\\)?[^&|<>"\s]+\.(?:exe|com|pif))',
                ]
                for pattern in patterns:
                    for m in re.finditer(pattern, content):
                        candidate = m.group(1).strip('"').strip("'")
                        # 规范化路径
                        if not os.path.isabs(candidate):
                            # 尝试相对路径（相对于脚本所在目录）
                            script_dir = os.path.dirname(script_path)
                            candidate = os.path.join(script_dir, candidate)
                        candidate = os.path.normpath(candidate)
                        if os.path.isfile(candidate):
                            abs_path = os.path.abspath(candidate)
                            if abs_path not in child_processes:
                                child_processes.append(abs_path)

            elif ext == '.ps1':
                # 识别 PowerShell 中的进程启动
                patterns = [
                    r'(?i)Start-Process\s+"?([^\s&|<>"]+\.(?:exe|ps1|bat|cmd))"?',
                    r'(?i)Start-Process\s+\$?\w+',  # 变量引用跳过
                    r'(?i)Invoke-Expression\s+"([^"]+)"',
                    r'(?i)iex\s+"([^"]+)"',
                    r'(?i)\s&(?:\s+)?([^\s&|<>"]+\.(?:exe|ps1|bat|cmd))',
                    r'(?i)cmd\s+/(?:c|k)\s+"?([^\s&|<>"]+\.(?:bat|cmd))"?',
                    r'(?i)powershell\s+-File\s+"?([^\s&|<>"]+\.ps1)"?',
                ]
                for pattern in patterns:
                    for m in re.finditer(pattern, content):
                        candidate = m.group(1).strip('"').strip("'")
                        if '$' in candidate or candidate.startswith('{'):
                            continue  # 跳过变量/脚本块
                        if not os.path.isabs(candidate):
                            script_dir = os.path.dirname(script_path)
                            candidate = os.path.join(script_dir, candidate)
                        candidate = os.path.normpath(candidate)
                        if os.path.isfile(candidate):
                            abs_path = os.path.abspath(candidate)
                            if abs_path not in child_processes:
                                child_processes.append(abs_path)

            elif ext in ('.vbs', '.js', '.wsf'):
                # 识别 VBScript/JScript 中的进程启动
                patterns = [
                    r'(?i)Shell\.Run\s+"([^"]+\.(?:exe|bat|cmd|ps1|vbs|js))"',
                    r"(?i)Shell\.Run\s+'([^']+\.(?:exe|bat|cmd|ps1|vbs|js))'",
                    r'(?i)CreateObject\s*\(\s*"WScript\.Shell"\s*\)\.Run\s+"([^"]+)"',
                    r'(?i)exec\s*\(\s*"([^"]+\.(?:exe|bat|cmd|ps1))"',
                ]
                for pattern in patterns:
                    for m in re.finditer(pattern, content):
                        candidate = m.group(1).strip('"').strip("'")
                        if not os.path.isabs(candidate):
                            script_dir = os.path.dirname(script_path)
                            candidate = os.path.join(script_dir, candidate)
                        candidate = os.path.normpath(candidate)
                        if os.path.isfile(candidate):
                            abs_path = os.path.abspath(candidate)
                            if abs_path not in child_processes:
                                child_processes.append(abs_path)

        except Exception as e:
            logger.debug(f'脚本分析异常 {script_path}: {e}')

        if child_processes:
            logger.info(
                f'脚本源代码分析发现 {len(child_processes)} 个子进程目标: '
                f'{[os.path.basename(p) for p in child_processes[:5]]}')

        return child_processes

    def _register_script_children_for_dedup(self, script_path: str) -> List[str]:
        """分析脚本源代码并将发现的子进程路径登记到去重列表

        这样当沙箱执行脚本时，脚本启动的子进程不会被重复送入沙箱分析。
        返回发现的子进程路径列表（用于日志和通知）。
        """
        children = self._analyze_script_for_child_processes(script_path)
        for child_path in children:
            self._mark_script_analyzing(child_path, ttl_seconds=60)
            logger.debug(
                f'登记脚本子进程路径用于去重: {child_path} (来自 {os.path.basename(script_path)})')
        return children

    def _is_masquerading_system_binary(self, name: str, exe: str) -> bool:
        """检测系统进程伪装：核心系统进程名运行在系统目录之外

        银狐惯用手法：将 svchost.exe / services.exe 等副本投放到
        %APPDATA%、%TEMP%、用户下载目录后启动，借系统进程名躲避注意。
        合法的这些进程只从 System32 / SysWOW64 / WinSxS 启动。
        """
        try:
            if not name or not exe:
                return False
            if name.lower() not in self._MASQUERADE_CRITICAL_NAMES:
                return False
            ep = os.path.abspath(exe).lower()
            return not any(d in ep for d in self._SYSTEM_BINARY_LEGIT_DIRS)
        except Exception:
            return False

    # 可信系统目录（启动扫描直接跳过，不送入扫描引擎）
    _LAUNCH_SCAN_TRUSTED_DIRS = None  # 在 _register_self() 中初始化

    def _async_scan_launch(self, pid: int, name: str, exe_path: str):
        """异步扫描新启动的可执行文件（避免阻塞 ETW 回调）

        设计要点（解决卡死问题）：
        1. ETW 回调线程中只做内存级检查（白名单/缓存/inflight），绝不执行文件 IO
        2. 所有 IO 密集型操作（哈希计算/签名验证/引擎扫描）都在扫描线程中执行
        3. 使用信号量限制并发扫描数量（最多 2 个），避免开机时数十个进程同时触发扫描
        4. 复用共享 ScanEngine 实例，避免每次扫描都重新初始化签名库/YARA/ML
        5. 扫描线程带超时保护，避免单个文件扫描永久阻塞
        6. inflight 集合去重，同一文件不会被多个线程同时扫描
        """
        # === 以下检查均为内存级操作，可在 ETW 回调线程中执行 ===

        # 路径级自保护：跳过 PSLS 自身目录下的可执行文件
        if self._self_excluded_dirs and exe_path:
            try:
                ep_lower = os.path.abspath(exe_path).lower()
                if any(ep_lower.startswith(d) for d in self._self_excluded_dirs):
                    return
            except Exception:
                pass

        # === 启动扫描误报防护：第1层 - 系统关键进程名白名单 ===
        # 例外：核心系统进程名运行在系统目录外 = 银狐式伪装，必须扫描
        _is_masquerade = self._is_masquerading_system_binary(name, exe_path)
        if _is_masquerade:
            logger.warning(
                f'检测到系统进程伪装，送入扫描: {name} @ {exe_path}')
        else:
            try:
                name_lower = name.lower() if name else ''
                if name_lower in self._SYSTEM_CRITICAL_EXE_NAMES:
                    return
            except Exception:
                pass

        # === 启动扫描误报防护：第2层 - CI 深层系统目录直接跳过 ===
        # （仅豁免 Catalog 签名盲区且受 CI 保护的深层系统目录；
        #   伪装进程例外：如 C:\Windows\Temp\svchost.exe 不能因 \Windows 前缀放行；
        #   Program Files 等其余位置不再因目录信任放行，须走签名判定）
        if not _is_masquerade and exe_path and self._CI_WINDOWS_SYSTEM_DIRS:
            try:
                ep_lower = os.path.abspath(exe_path).lower()
                if any(ep_lower.startswith(d) for d in self._CI_WINDOWS_SYSTEM_DIRS):
                    return
            except Exception:
                pass

        # 获取文件修改时间（单次 stat 调用，轻量）
        try:
            mtime = os.path.getmtime(exe_path)
        except Exception:
            mtime = 0

        # 检查缓存（内存操作）
        with self._launch_scan_lock:
            cached = self._launch_scan_cache.get(exe_path)
            if cached:
                cached_mtime, cached_status, cached_time = cached
                # 文件未修改且在 TTL 内 → 跳过
                if (cached_mtime == mtime
                        and time.time() - cached_time < self._LAUNCH_SCAN_CACHE_TTL):
                    if cached_status != 'clean' and self._on_launch_scan:
                        # 缓存中是非 clean 状态，仍需通知（可能是新 PID 启动了同一恶意文件）
                        self._on_launch_scan({
                            'pid': pid,
                            'name': name,
                            'exe_path': exe_path,
                            'scan_result': {'status': cached_status, 'cached': True},
                        })
                    return

        # inflight 去重：同一文件正在被扫描则跳过（避免重复扫描同一文件）
        with self._launch_scan_inflight_lock:
            if exe_path in self._launch_scan_inflight:
                return
            self._launch_scan_inflight.add(exe_path)

        # === 以下所有 IO 操作都在扫描线程中执行，不阻塞 ETW 回调 ===

        def _scan_thread():
            inflight_added = True
            try:
                # 并发控制：最多 2 个扫描同时进行，等待最多 5 秒
                # 超时则放弃本次扫描（避免排队过长导致积压）
                acquired = self._launch_scan_sem.acquire(timeout=5)
                if not acquired:
                    logger.debug(f'[启动扫描] 并发已满，跳过: {name} ({exe_path})')
                    return

                try:
                    # === 启动扫描误报防护：第3层 - 微软官方/腾讯等可信签名跳过（IO 操作，已移入线程）===
                    # 腾讯生态（QQ/微信等）与微软同级可信：签名有效即代码完整性保证，
                    # 直接缓存 clean，避免 QQ 每次启动都走哈希+深度引擎扫描（既误杀又耗时）。
                    try:
                        from utils.signature_verifier import get_verifier, classify_signer, SIGNER_TIER_KNOWN
                        _verifier = get_verifier()
                        if _verifier:
                            signer = _verifier.get_signer_info(exe_path)
                            if signer and signer.get('verified', False):
                                tier = signer.get('tier') or classify_signer(
                                    signer.get('verified'), signer.get('publisher'))
                                # 仅"已签名+知名厂商"强放行；MISC(已签名但发布者未知)
                                # 属"灰名单"，不直接信任，继续走哈希+引擎扫描送检。
                                if tier == SIGNER_TIER_KNOWN:
                                    with self._launch_scan_lock:
                                        self._launch_scan_cache[exe_path] = (mtime, 'clean', time.time())
                                    return
                    except Exception:
                        pass

                    # === 白名单哈希预检查（IO 操作，已移入线程）===
                    file_hash_pre = ''
                    try:
                        if self._signature_db:
                            import hashlib
                            h = hashlib.sha256()
                            with open(exe_path, 'rb') as f:
                                for chunk in iter(lambda: f.read(65536), b''):
                                    h.update(chunk)
                            file_hash_pre = h.hexdigest()
                            if self._signature_db.is_whitelisted(file_hash_pre):
                                with self._launch_scan_lock:
                                    self._launch_scan_cache[exe_path] = (mtime, 'clean', time.time())
                                return
                    except Exception:
                        pass

                    # === 大文件处理：不再"体积大即放行" ===
                    # 旧实现 >50MB 直接写 clean 缓存并 return：下载来的大体积木马
                    # （实测 77MB 的 Keplerians 样本）因此零防护，且被固化成
                    # "已确认干净"。现分两段：
                    #   · ≤硬上限(256MB)：照常送共享 ScanEngine 深度扫描
                    #     （可执行/脚本类的 50MB 体积豁免见 ScanEngine.scan_file），
                    #     非 clean 由既有回调按用户设置处置；
                    #   · >硬上限：至少用刚算出的 SHA256 做恶意哈希判定，命中即上报；
                    #     未命中也不写 clean 缓存（保持"未知"，下次仍会检查）。
                    try:
                        file_size = os.path.getsize(exe_path)
                        if file_size > self._LAUNCH_SCAN_MAX_FILE_SIZE:
                            _oversize_hit = False
                            try:
                                if self._signature_db and file_hash_pre:
                                    _oversize_hit = bool(
                                        self._signature_db.is_malware(file_hash_pre))
                            except Exception:
                                _oversize_hit = False
                            if _oversize_hit and self._on_launch_scan:
                                logger.warning(
                                    f'[启动扫描] 超大文件命中恶意哈希: {name} '
                                    f'({file_size} bytes) sha256={file_hash_pre[:16]}…')
                                self._on_launch_scan({
                                    'pid': pid,
                                    'name': name,
                                    'exe_path': exe_path,
                                    'scan_result': {
                                        'status': 'malware',
                                        'name': '已知恶意文件（超大文件哈希命中）',
                                        'hash': file_hash_pre,
                                    },
                                })
                            else:
                                logger.warning(
                                    f'[启动扫描] 超过硬上限 '
                                    f'{self._LAUNCH_SCAN_MAX_FILE_SIZE // (1024 * 1024)}MB，'
                                    f'未深度扫描（不缓存 clean）: {name} '
                                    f'({file_size} bytes)')
                            return
                    except Exception:
                        pass

                    # === 复用共享 ScanEngine 实例（避免重复初始化）===
                    engine = self._get_or_create_launch_scan_engine()
                    if not engine:
                        logger.warning(f'[启动扫描] 引擎不可用，跳过: {name}')
                        return

                    # === 执行扫描（带超时保护）===
                    result = self._scan_file_with_timeout(engine, exe_path,
                                                          self._LAUNCH_SCAN_TIMEOUT)
                    if not result:
                        # 超时或失败，不写入缓存（下次可重试）
                        return

                    status = getattr(result, 'status', 'clean')
                    malware_info = getattr(result, 'malware_info', None) or {}

                    # 写入缓存
                    with self._launch_scan_lock:
                        self._launch_scan_cache[exe_path] = (mtime, status, time.time())
                        # 清理过期缓存
                        if len(self._launch_scan_cache) > 500:
                            cutoff = time.time() - self._LAUNCH_SCAN_CACHE_TTL
                            expired = [k for k, v in self._launch_scan_cache.items()
                                       if v[2] < cutoff]
                            for k in expired:
                                del self._launch_scan_cache[k]

                    # 非 clean → 通知回调
                    if status != 'clean' and self._on_launch_scan:
                        scan_result = {
                            'status': status,
                            'name': malware_info.get('name', status),
                            'malware_info': malware_info,
                        }
                        # 尝试获取 PE 分析和规则匹配信息
                        pe_analysis = getattr(result, 'pe_analysis', None)
                        if pe_analysis:
                            scan_result['pe_score'] = pe_analysis.get('total_score', 0)
                        rule_matches = getattr(result, 'rule_matches', None)
                        if rule_matches:
                            scan_result['rule_match_count'] = len(rule_matches)

                        self._on_launch_scan({
                            'pid': pid,
                            'name': name,
                            'exe_path': exe_path,
                            'scan_result': scan_result,
                        })

                    logger.debug(f'[启动扫描] {name} ({exe_path}) → {status}')

                finally:
                    self._launch_scan_sem.release()

            except Exception as e:
                logger.error(f'启动扫描失败 {exe_path}: {e}')
            finally:
                if inflight_added:
                    with self._launch_scan_inflight_lock:
                        self._launch_scan_inflight.discard(exe_path)

        t = threading.Thread(target=_scan_thread, daemon=True,
                             name=f'LaunchScan-{name}')
        t.start()

    def _get_or_create_launch_scan_engine(self):
        """获取或创建共享的启动扫描 ScanEngine 实例

        复用同一实例避免每次扫描都重新初始化签名库/YARA/ML（初始化可能需要数秒）。
        线程安全：通过 _launch_scan_engine_lock 保护。
        """
        with self._launch_scan_engine_lock:
            if self._launch_scan_engine is not None:
                return self._launch_scan_engine
            try:
                engine = self._scan_engine_factory() if self._scan_engine_factory else None
                if engine:
                    self._launch_scan_engine = engine
                return engine
            except Exception as e:
                logger.error(f'创建启动扫描引擎失败: {e}')
                return None

    def _scan_file_with_timeout(self, engine, exe_path: str, timeout: int):
        """带超时保护的文件扫描

        使用子线程执行扫描，主线程等待 timeout 秒。
        超时则放弃扫描结果（子线程为 daemon 会自动退出）。

        Args:
            engine: ScanEngine 实例
            exe_path: 文件路径
            timeout: 超时秒数

        Returns:
            扫描结果对象，超时或失败返回 None
        """
        result_container = [None]
        error_container = [None]

        def _do_scan():
            try:
                result_container[0] = engine.scan_file(exe_path)
            except Exception as e:
                error_container[0] = e

        scan_thread = threading.Thread(target=_do_scan, daemon=True,
                                       name='LaunchScanWorker')
        scan_thread.start()
        scan_thread.join(timeout=timeout)

        if scan_thread.is_alive():
            # 扫描超时，放弃结果
            logger.warning(f'[启动扫描] 扫描超时({timeout}s)，放弃: {exe_path}')
            return None

        if error_container[0] is not None:
            logger.error(f'[启动扫描] 扫描异常 {exe_path}: {error_container[0]}')
            return None

        return result_container[0]

    def _scan_exe_for_misc_signer(self, exe_path: str):
        """对 MISC 层（有效签名但发布者未知）的可执行文件做快速文件扫描。

        用于替代"直接送沙箱"：有效签名是确定性证据，先经文件扫描（已带签名
        降误报折扣）判定，clean 直接放行，避免合法签名软件被沙箱误杀。
        扫描超时(5s)或异常返回 None（降级走沙箱）。
        """
        if not self._scan_engine_factory:
            return None
        try:
            with self._launch_scan_engine_lock:
                if self._launch_scan_engine is None:
                    self._launch_scan_engine = self._scan_engine_factory()
                engine = self._launch_scan_engine
            return self._scan_file_with_timeout(engine, exe_path, timeout=5)
        except Exception as e:
            logger.debug(f'MISC签名文件扫描异常: {e}')
            return None

    def _is_suspicious_name(self, name: str) -> bool:
        """检查进程名是否匹配可疑特征

        仅对进程名（不含扩展名）进行精确匹配和有限的模糊匹配，
        避免对包含常见词（如 service/update/setup）的正常进程误报。
        """
        name_lower = name.lower()
        # 去掉扩展名再匹配
        base_name = name_lower
        for ext in ('.exe', '.dll', '.scr', '.com', '.bat', '.cmd'):
            if base_name.endswith(ext):
                base_name = base_name[:-len(ext)]
                break

        # 精确匹配（完整文件名或去扩展名后）
        if name_lower in SUSPICIOUS_PROCESS_NAMES:
            return True
        if base_name in SUSPICIOUS_PROCESS_NAMES:
            return True

        # 仅对已知的系统进程名进行混淆检测
        # 检查是否是对已知系统进程名的字符混淆（如 svchost→svch0st）
        system_process_names = [
            'svchost', 'explorer', 'winlogon', 'rundll32',
            'cmd', 'powershell', 'csrss', 'lsass', 'spoolsv',
            'smss', 'wininit', 'services',
        ]
        for sys_name in system_process_names:
            if self._is_confused_name(base_name, sys_name):
                return True
        return False

    @staticmethod
    def _is_confused_name(name: str, original: str) -> bool:
        """检查 name 是否是 original 的字符混淆版本（如 0↔o, 1↔l）"""
        if name == original:
            return False  # 完全相同不算混淆
        if len(name) != len(original):
            return False
        substitutions = {'0': 'o', 'o': '0', '1': 'l', 'l': '1',
                         '3': 'e', 'e': '3', '5': 's', 's': '5',
                         '$': 's', '!': 'i', '@': 'a'}
        diff_count = 0
        for sc, pc in zip(name, original):
            if sc == pc:
                continue
            if substitutions.get(sc) == pc or substitutions.get(pc) == sc:
                diff_count += 1
            else:
                return False  # 非混淆字符差异，不是伪装
        # 仅当有 1-2 个混淆字符差异时才判定为伪装
        return 1 <= diff_count <= 2

    def _is_trusted_path(self, exe: str, name: str) -> bool:
        """检查进程路径是否在可信位置"""
        if name.lower() in TRUSTED_PROCESSES:
            return True
        exe_lower = exe.lower()
        trusted_prefixes = [
            'c:\\windows\\',
            'c:\\program files\\',
            'c:\\program files (x86)\\',
            'c:\\users\\',
        ]
        for prefix in trusted_prefixes:
            if exe_lower.startswith(prefix):
                return True
        # Sandboxie 自身进程（Start.exe / SbieSvc.exe / SbieCtrl.exe 等）必须放行：
        # 否则“非信任程序启动→终止”会误杀沙箱启动器与服务，导致沙箱不可用。
        for sb in self._sandboxie_trust_prefixes():
            if exe_lower.startswith(sb):
                return True
        return False

    @staticmethod
    def _is_sandboxie_own_path(exe: str) -> bool:
        """exe 是否位于 Sandboxie 安装目录（其自身组件与代理进程）。"""
        if not exe:
            return False
        try:
            ep = os.path.abspath(exe).lower()
        except Exception:
            ep = str(exe).lower()
        try:
            return any(ep.startswith(sb)
                       for sb in ProcessProtection._sandboxie_trust_prefixes())
        except Exception:
            return False

    @staticmethod
    def _sandboxie_trust_prefixes():
        """Sandboxie 安装目录前缀（缓存一次）。"""
        cached = getattr(ProcessProtection, '_SB_TRUST_CACHE', None)
        if cached is not None:
            return cached
        prefixes = []
        try:
            from engine.sandbox_analyzer import detect_sandboxie_backend
            d = (detect_sandboxie_backend() or {}).get('dir') or ''
            if d:
                prefixes.append(os.path.normcase(d).rstrip('\\/') + '\\')
        except Exception:
            pass
        for d in (r'C:\Program Files\Sandboxie-Plus',
                  r'C:\Program Files\Sandboxie'):
            prefixes.append(os.path.normcase(d).rstrip('\\/') + '\\')
        ProcessProtection._SB_TRUST_CACHE = prefixes
        return prefixes

    # ---- 上下文信任评估（防误报核心）----

    def _get_parent_context(self, parent_pid: int) -> tuple:
        """查询父进程上下文，返回 (name_lower, is_user_host)

        仅读取父进程名/可执行路径做快速判定，不弹窗不扫描；
        parent_pid<=0 或查询失败一律按"不可信父进程"处理（保守）。
        """
        if not parent_pid or parent_pid <= 0:
            return '', False
        try:
            import psutil as _ps
            pp = _ps.Process(parent_pid)
            pname = (pp.name() or '').lower()
            pexe = ''
            try:
                pexe = (pp.exe() or '').lower()
            except Exception:
                pass
            # 用户交互宿主判定：explorer（用户双击）/Windows Terminal/
            # 控制台/运行框等。系统内核/服务宿主（services/wininit/svchost
            # 派生）不算用户主动上下文。
            if pname == 'explorer.exe' or 'bin\\explorer.exe' in pexe:
                return pname, True
            if any(h in pexe for h in ('windowstermi', 'wt.exe')):
                return pname, True
            if pname in ('cmd.exe', 'powershell.exe', 'pwsh.exe',
                         'dllhost.exe', 'runtimebroker.exe'):
                return pname, True
            return pname, False
        except Exception:
            return '', False

    def _assess_contextual_trust(self, exe: str, name: str,
                                 parent_pid: int, cmdline: Optional[list],
                                 verified: bool = False,
                                 publisher: str = '') -> dict:
        """多维度上下文信任评估 —— 降低正常软件/修改器误报

        综合六维给文件打分（0~100）：
          1. 进程来源   ：exe 路径所在目录（用户下载/桌面/旧安装目录）
          2. 数字签名   ：已验证签名=代码完整性保证（发行者未知也加分）
          3. 行为链     ：本进程曾判 clean / 用户曾批准信任
          4. 父子进程关系：父进程为用户交互宿主（explorer 双击等）
          5. 文件年龄   ：创建时间越久越可信（新落盘=疑似投放）
          6. 上下文逻辑 ：命令行非静默/后台参数，用户主动执行姿势

        返回:
            {'trust': 0-100, 'reasons': [str,...],
             'parent_user_host': bool, 'skip_sandbox': bool}
        """
        trust = 0
        reasons = []

        # --- 维度 2：数字签名（代码完整性已验证 === 强信任凭证）---
        if verified:
            if publisher and publisher.lower() in (
                    'microsoft corporation', 'google llc', 'mozilla corporation',
                    'adobe systems incorporated', 'apple inc.', 'meta platforms',
                    'tencent technology (shenzhen) company limited',
                    'alibaba (china) co., ltd.', 'beijing bytedance network'):
                trust += 25
                reasons.append('已验证签名+可信发布者')
            else:
                trust += 15
                reasons.append('已验证数字签名（发行者非顶级）')

        # --- 维度 3：行为链历史 ---
        try:
            mtime = os.path.getmtime(exe)
        except Exception:
            mtime = 0
        with self._launch_scan_lock:
            cached = self._launch_scan_cache.get(exe)
        if cached:
            cached_mtime, cached_status, cached_time = cached
            if (cached_mtime == mtime
                    and time.time() - cached_time < self._LAUNCH_SCAN_CACHE_TTL
                    and cached_status == 'clean'):
                trust += 20
                reasons.append('扫描缓存历史 clean')
        try:
            if self._is_prank_trusted(exe):
                trust += 15
                reasons.append('用户近期批准信任过')
        except Exception:
            pass

        # --- 维度 4：父子进程关系（用户主动启动上下文）---
        parent_name, is_user_host = self._get_parent_context(parent_pid)
        if is_user_host:
            trust += 20
            reasons.append(f'用户交互宿主启动 (父={parent_name or "?"})')

        # --- 维度 5：文件年龄（创建时间）---
        # 注意：_check_new_process 已经拿过 mtime，这里单独读 ctime。
        # ctime 在 Windows 上是文件创建时间；下载/解压/更新都会刷新。
        try:
            ctime = os.path.getctime(exe)
        except Exception:
            ctime = 0
        if ctime > 0:
            age_days = (time.time() - ctime) / 86400.0
            for thresh_days, pts in self._CTRUST_FILE_AGE_THRESHOLDS:
                if age_days >= thresh_days / 86400.0:
                    trust += pts
                    reasons.append(f'文件存在 ≥{int(thresh_days/86400)} 天')
                    break
        # 补充：即使文件较新，若 EXE 位于旧安装目录（非新落盘）也给少量基础分
        try:
            exe_lower = os.path.abspath(exe).lower()
        except Exception:
            exe_lower = exe.lower() if exe else ''

        # --- 维度 1：进程来源（放置目录上下文）---
        # 注意：下载/桌面目录**只在文件有有效签名时**才加信任分。
        # 旧实现给"位于下载/桌面"无条件 +10，等于给下载来的未签名样本
        # （实测 MinecraftRansomware.exe / G4m0ad2f1qi 就在 Downloads 下）
        # 发信任分，并把它推过 mitigate 阈值 → 沙箱判定被"调查先验"降分 →
        # 勒索/破坏样本被判 clean。未签名 + 用户可写目录 = 零信任加成。
        if exe_lower:
            if any(d in exe_lower for d in (
                    '\\downloads\\', '\\desktop\\',
                    '\\onedrive\\desktop\\', '\\onedrive\\documents\\')):
                if verified:
                    trust += 10
                    reasons.append('位于下载/桌面目录（用户主动获取，已签名）')
            elif any(d in exe_lower for d in (
                    '\\program files\\', '\\program files (x86)\\',
                    '\\game\\', '\\games\\', '\\steamapps\\', '\\epic games\\',
                    '\\software\\', '\\tools\\', '\\apps\\')):
                trust += 8
                reasons.append('位于常规软件/游戏安装目录')

        # --- 维度 6：上下文逻辑（用户主动执行姿态）---
        cmdline_l = ' '.join(cmdline).lower() if cmdline else ''
        if cmdline_l and not any(k in cmdline_l for k in (
                '/silent', '/quiet', '/s', '--silent', '--quiet',
                '--no-sandbox-hidden', 'background', 'headless')):
            trust += 5
            reasons.append('非静默参数启动（用户主动执行）')

        return {
            'trust': min(100, trust),
            'reasons': reasons,
            'parent_user_host': is_user_host,
            'skip_sandbox': trust >= self._CTRUST_SKIP_SANDBOX,
            # "调查先验"会**降低沙箱判定分数**，只能给已签名文件 —— 未签名文件
            # 拿这个先验会让勒索/破坏样本被沙箱判 clean（实测两个样本即如此）。
            'mitigate': (trust >= self._CTRUST_MITIGATE_MIN and verified),
        }

    # ---- 哈希扫描 ----

    def _check_process_hash(self, pid: int, exe: str, name: str):
        """用签名库检查进程文件哈希"""
        if not self._signature_db:
            return
        try:
            import hashlib
            h = hashlib.sha256()
            with open(exe, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            file_hash = h.hexdigest()
            # 查询签名库
            sig = self._signature_db.lookup_hash(file_hash)
            if sig:
                self._report_threat({
                    'type': 'malware_process',
                    'pid': pid,
                    'name': name,
                    'path': exe,
                    'detail': f'检测到已知恶意进程: {sig.get("name", "未知")}',
                    'signature': sig,
                })
        except Exception:
            pass  # 文件可能已不存在或无读取权限

    # ---- 自亲和豁免 ----

    def _is_own_child_process(self, proc: psutil.Process) -> bool:
        """检查进程是否是 PSLS 自己创建的子进程"""
        try:
            parent = proc.parent()
            if parent is None:
                return False
            if parent.pid == os.getpid():
                return True
            if getattr(sys, 'frozen', False):
                return parent.exe() == sys.executable
            return False
        except (psutil.Error, Exception):
            return False

    def _is_qtwebengine_process(self, proc: psutil.Process) -> bool:
        """检查是否是 QtWebEngine 渲染进程"""
        try:
            name = proc.name().lower()
            if 'qtwebengine' in name:
                return True
            cmdline = ' '.join(proc.cmdline()).lower()
            return 'qtwebengine' in cmdline or '--process-per-site' in cmdline
        except (psutil.Error, Exception):
            return False

    # WebView2/Chromium 运行时进程名/路径特征（PSLS 自身 UI 依赖 WebView2）
    _WEBVIEW2_TOKENS = ('msedgewebview2', 'microsoftedgewebview2', 'webview2')

    def _is_webview2_process(self, proc: psutil.Process) -> bool:
        """检查是否是 Microsoft Edge WebView2 / Chromium 运行时进程

        隔离化（sandboxed）WebView2 会派生 msedgewebview2.exe 及带
        --type=renderer/gpu-process/utility/network/crashpad 等特征的
        Chromium 子进程。这些进程是 PSLS 自身 UI 的宿主依赖，绝不能当作
        "非信任威胁"送沙箱或终止，否则会冻死 PSLS 自身。
        """
        try:
            name = proc.name().lower()
            if any(tok in name for tok in self._WEBVIEW2_TOKENS):
                return True
            try:
                exe = (proc.exe() or '').lower()
                if any(tok in exe for tok in self._WEBVIEW2_TOKENS):
                    return True
            except (psutil.Error, Exception):
                exe = ''
            cmdline = ' '.join(proc.cmdline()).lower()
            return any(tok in cmdline for tok in self._WEBVIEW2_TOKENS)
        except (psutil.Error, Exception):
            return False

    def _is_psls_related_process(self, proc: psutil.Process) -> bool:
        """检查是否是 PSLS 相关进程（子进程 + QtWebEngine + WebView2）"""
        return (self._is_own_child_process(proc)
                or self._is_qtwebengine_process(proc)
                or self._is_webview2_process(proc))

    def _refuse_self_kill(self, pid: int, site: str) -> bool:
        """终止守卫：拒绝终止 PSLS 自身进程或 PSLS 相关进程，并记录调用现场。

        背景：曾多轮出现"主 GUI 静默死亡"——无异常/无 minidump/无 aboutToQuit
        日志，退出码 1，符合被 TerminateProcess/taskkill 强杀特征；且主进程在
        19:14:31 已启用 DACL（Deny Everyone PROCESS_TERMINATE）后仍在
        19:14:55 被终止，说明终止方持有绕过 DACL 的能力（旧句柄/内核态）。
        为杜绝内部模块误把自身视为威胁执行杀进程，将全部终止入口统一收口到
        此守卫：命中自身/PSLS 相关进程时立即记录调用栈并拒绝终止。

        Returns:
            True = 该 PID 属于自身/PSLS 相关进程，调用方必须放弃终止；
            False = 可继续执行终止流程（或无法判定，不拦截）。
        """
        if not pid or pid <= 0:
            return False
        try:
            if pid == os.getpid():
                self._log_self_kill_attempt('自身主进程', pid, site)
                return True
            if HAS_PSUTIL:
                proc = psutil.Process(pid)
                if self._is_psls_related_process(proc):
                    self._log_self_kill_attempt('PSLS 相关进程（子进程/QtWebEngine）',
                                                pid, site,
                                                extra=proc.name())
                    return True
        except psutil.NoSuchProcess:
            return False
        except Exception as e:
            logger.debug(f'自我终止守卫判定异常 site={site} pid={pid}: {e}')
        return False

    def _log_self_kill_attempt(self, kind: str, pid: int, site: str, extra: str = ''):
        """记录一次被阻止的自我终止尝试（含调用栈，便于定位误杀源头）"""
        try:
            stack = ''.join(traceback.format_stack()[-7:-1])
        except Exception:
            stack = '(栈获取失败)'
        logger.error(
            f'!! 已阻止终止 {kind} !! site={site} pid={pid} {extra}\n'
            f'调用栈:\n{stack}')

    # ---- 行为检查 ----

    def _check_process_behavior(self, pid: int, entry: dict,
                                 prev_entry: Optional[dict]):
        """检查进程异常行为"""
        name = entry.get('name', '')
        cpu = entry.get('cpu', 0)
        threads = entry.get('threads', 0)
        exe = entry.get('exe', '')

        # 检查 1：异常高 CPU 占用
        if cpu > HIGH_CPU_THRESHOLD and name not in TRUSTED_PROCESSES:
            self._add_event('high_cpu', pid, name, 'warn',
                            f'CPU 占用 {cpu:.0f}%', exe)

        # 检查 2：线程数异常多（可能被注入）
        if prev_entry and threads > prev_entry.get('threads', 0) + 20:
            self._add_event('thread_spike', pid, name, 'warn',
                            f'线程数骤增: {prev_entry.get("threads", 0)} → {threads}',
                            exe)

    # ---- 注入检测 ----

    # ------------------------------------------------------------------
    # 内核驱动进程创建事件入口（R0 投递 → 用户态 psls_driver_bridge 分发）
    # ------------------------------------------------------------------

    def on_driver_process_create_event(self, evt) -> None:
        """驱动 process_create 事件回调（驱动事件循环线程跨线程调用）。

        与 `_on_etw_process_created`（WMI/WTS 通道）并行，双轨汇流：
          - 驱动通道：PsSetCreateProcessNotifyRoutineEx PRE 阶段事件，
            延迟约 1~5ms，是"病毒双击 EXE 启动"场景下的核心检测入口。
          - ETW 通道：WMI PowerShell 订阅或 WTS 枚举轮询降级，延迟 ~500ms，
            作为驱动缺失时的兜底。

        两点关键处理：
          1) 内核给的 image_path_usr 是 **NT 设备路径**（如
             `\\Device\\HarddiskVolume3\\Users\\xx\\Desktop\\virus.exe`），
             必须先转换为 Win32 盘符路径，后续 `_CI_WINDOWS_SYSTEM_DIRS`、
             自保护 `_self_excluded_dirs`、沙箱、可信发布者签名判定、
             `os.path.isfile` 等才会命中。
          2) 转换后直接转发给 `_on_etw_process_created`：后者的
             `_etw_pids_checked` 集合天然完成跨通道去重（同一进程创建既
             被驱动看到也被 WMI 看到时，第二条自动 deduplicate）。
        """
        try:
            if evt is None:
                return
            pid = int(getattr(evt, 'process_id', 0) or 0)
            if pid <= 0 or pid == 4:
                return
            self._driver_active = True   # 内核事件通道已激活(升级1)
            image = getattr(evt, 'image_path', '') or ''
            cmdline = getattr(evt, 'command_line', '') or ''
            parent_pid = int(getattr(evt, 'parent_pid', 0) or 0)

            # (1) NT 设备路径 → Win32 盘符路径；失败/空路径留空字符串，
            #     _on_etw_process_created 内部会走 `psutil.Process(pid).exe()`
            #     作为兜底补获取，不会造成漏检。
            win32_path = ''
            if image:
                try:
                    from driver.bridge.psls_driver_bridge import _nt_path_to_win32
                    win32_path = _nt_path_to_win32(image) or ''
                except Exception:
                    win32_path = ''

            # 进程名：有盘符路径就从 basename 取；否则直接取 NT 路径最后一节兜底
            name = ''
            try:
                if win32_path:
                    name = os.path.basename(win32_path)
                elif image:
                    name = os.path.basename(image.replace('\\', os.sep))
            except Exception:
                name = ''

            event_dict = {
                'pid': pid,
                'name': name.lower(),
                'cmdline': cmdline,
                'exe_path': win32_path,
                'parent_pid': parent_pid,
                'timestamp': time.time(),
                '_source': 'driver_procmon',
            }
            self._on_etw_process_created(event_dict)
        except Exception as e:
            logger.warning(f'[驱动进程创建] 事件消费异常: {e}')

    # ------------------------------------------------------------------
    # 句柄审计双信号 (内核 OB_CALLBACKS 事件 → 注入判定辅助)
    # ------------------------------------------------------------------

    def _get_behavior_analyzer(self):
        """懒创建共享 BehaviorAnalyzer 实例（线程安全）。"""
        if _BehaviorAnalyzerCls is None:
            return None
        if self._behavior_analyzer is None:
            with self._behavior_analyzer_lock:
                if self._behavior_analyzer is None:
                    try:
                        self._behavior_analyzer = _BehaviorAnalyzerCls()
                    except Exception as e:
                        logger.debug(f'行为启发分析器初始化失败: {e}')
                        self._behavior_analyzer = None
        return self._behavior_analyzer

    def on_handle_audit_event(self, evt) -> None:
        """驱动 OB_CALLBACKS 句柄审计事件回调（跨线程，驱动事件循环线程调用）

        内核侧已按 PROCESS_INJECT_AUDIT_MASK 过滤，投递过来的打开操作
        至少包含 VM_OPERATION/VM_WRITE/CREATE_THREAD/SUSPEND_RESUME/DEBUG
        中的注入特征访问位。这里仅登记 (source,target) 关系供
        _check_injections 双信号判定使用，不在此直接处置。
        """
        try:
            source_pid = int(getattr(evt, 'source_pid', 0) or 0)
            target_pid = int(getattr(evt, 'target_pid', 0) or 0)
            if source_pid <= 0 or target_pid <= 0 or source_pid == target_pid:
                return
            if self._is_trusted_audit_source(source_pid):
                return
            access = int(getattr(evt, 'desired_access', 0) or 0)
            count = int(getattr(evt, 'count', 1) or 1)
            first_ts = int(getattr(evt, 'first_ts_ns', 0) or 0)
            key = (source_pid, target_pid)
            now = time.monotonic()
            with self._ob_inject_lock:
                # 同 (source,target) 短时间内累计，保留最大 count 与最新时间戳
                prev = self._ob_inject_observed.get(key)
                if prev is not None:
                    prev['ts'] = now
                    prev['access'] |= access
                    prev['count'] = max(prev['count'], count)
                    if first_ts:
                        prev['first_ts'] = first_ts
                else:
                    self._ob_inject_observed[key] = {
                        'ts': now, 'access': access, 'count': count,
                        'first_ts': first_ts,
                    }
        except Exception as e:
            logger.debug(f"句柄审计回调异常: {e}")
        # 行为启发：只读消费注入信号(不作判定重算)
        try:
            ba = self._get_behavior_analyzer()
            if ba is not None:
                ba.feed_handle_audit(source_pid, target_pid, access)
        except Exception:
            pass
        # 升级1: 句柄事件驱动注入提示 — 同目标注入达阈值时对该 target 定向快检,
        # 不必等下一轮内存巡检(_check_injections still 周期兜底)。
        try:
            if self._driver_active and int(count or 0) >= 3:
                self._ob_inject_event_hint(target_pid)
        except Exception:
            pass

    def _is_trusted_audit_source(self, pid: int) -> bool:
        """判断句柄审计发起者是否为可信进程（不在注入告警范围内）"""
        if pid == os.getpid():
            return True
        try:
            name = (psutil.Process(pid).name() or '').lower()
        except Exception:
            return False
        return name in TRUSTED_PROCESSES

    def _get_ob_audit_signal(self, target_pid: int) -> Optional[dict]:
        """查询 target_pid 在 TTL 窗口内是否被进程以注入特征位打开过

        Returns:
            {'source_pid', 'source_name', 'access', 'count'} 或 None
        """
        if target_pid <= 0:
            return None
        now = time.monotonic()
        best = None
        best_src = 0
        expired: List[tuple] = []
        with self._ob_inject_lock:
            for (src, tgt), rec in self._ob_inject_observed.items():
                if now - rec['ts'] > _OB_AUDIT_TTL:
                    expired.append((src, tgt))
                    continue
                if tgt == target_pid:
                    if best is None or rec['count'] > best['count']:
                        best = dict(rec)
                        best_src = src            # key 中的 source_pid
            for k in expired:
                self._ob_inject_observed.pop(k, None)
        if best is None:
            return None
        source_name = ''
        try:
            p = psutil.Process(best_src)
            source_name = p.name() or ''
        except Exception:
            pass
        return {
            'source_pid': best_src,
            'source_name': source_name,
            'access': best['access'],
            'count': best['count'],
        }

    def _ob_inject_event_hint(self, target_pid: int) -> None:
        """升级1: 句柄事件驱动注入提示 — 对单个 target 定向执行注入快检。

        由 on_handle_audit_event 在 count 达阈值(注入特征位累计)时触发, 构建
        单进程快照复用既有的 _check_injections 判定/处置链, 不另起新逻辑。
        _check_injections 内部会查 _get_ob_audit_signal 作双信号, 因此直接把
        该 target 的已审计命中喂给它即可在此轮即时判定, 不等周期巡检。
        """
        if target_pid <= 0 or not HAS_PSUTIL:
            return
        try:
            if not self._get_ob_audit_signal(target_pid):
                return   # 无有效审计信号, 无谓快检
            proc = psutil.Process(target_pid)
            entry = {
                'name': (proc.name() or '').lower(),
                'exe': proc.exe() or '',
                'cmdline': [],        # 注入快检只读内存, 无需 cmdline
                'proc': proc,
            }
            self._check_injections({target_pid: entry})
        except Exception:
            pass

    @staticmethod
    def _fmt_ob_signal(ob: Optional[dict]) -> str:
        """把句柄审计信号格式化为告警 detail 追加段（无信号返回空串）"""
        if not ob:
            return ''
        src = ob.get('source_name') or f"PID={ob.get('source_pid', 0)}"
        cnt = ob.get('count', 1)
        return f"；句柄审计双信号:{src} 在30s内以注入特征位打开本进程(累计{cnt}次)"

    # ------------------------------------------------------------------
    # 银狐断网型反制：文件落地监视(A) + 加载期白加黑判定(B) + 落地-加载链(C)
    # ------------------------------------------------------------------

    def _on_dropped_file_cb(self, path: str, size: int) -> None:
        """DropperMonitor 文件落地回调（DropperMonitor 消费者线程调用）

        流程：
          1. 登记落地链记录（drop +2，银狐落地执行链 C 的第一信号）
          2. 复用启动送检链路异步送检（白名单哈希/签名验证/引擎深度扫描）
        若是威胁文件，_async_scan_launch 命中后经 _on_launch_scan 通知 UI 处置。
        """
        try:
            key = os.path.normcase(os.path.abspath(path))
            now = time.monotonic()
            with self._dropload_chain_lock:
                rec = self._dropload_chain.get(key)
                if rec is None:
                    self._dropload_chain[key] = {
                        'ts': now, 'drop': 2, 'load': 0, 'host': 0,
                        'size': size, 'disposed': False,
                    }
                else:
                    # 再次落地（重命名/覆盖）→ 重置为新的落地记录
                    rec.update({'ts': now, 'drop': 2, 'load': 0,
                                'host': 0, 'size': size, 'disposed': False})
                # 链字典惰性清理：超 TTL 的条目移除（防无限增长）
                if len(self._dropload_chain) > 256:
                    cutoff = now - self._DROPLOAD_CHAIN_TTL
                    for k in [k for k, v in self._dropload_chain.items()
                              if v['ts'] < cutoff]:
                        del self._dropload_chain[k]
            base = os.path.basename(path) or 'dropped'
            # 异步送检：pid=0 表示未知宿主（仅做文件级处置）
            self._async_scan_launch(0, base, path)
            logger.debug(f'[落地监视] 可执行文件落地待检: {path} ({size} B)')
        except Exception as e:
            logger.debug(f'文件落地回调异常: {e}')

    def on_image_load_event(self, evt) -> None:
        """内核 image_load 事件回调（驱动事件循环线程，仅内存级操作）

        实现"加载期白加黑判定"(B) 与 "落地-加载链评分"(C)：
          - 路径在受信任目录 / PSLS 自身 → 忽略
          - 命中落地链记录（该文件近期被 DropperMonitor 观察到落地）
            → load+3，链路成立则走 _handle_dropload_chain（告警+隔离）
          - 未命中链：无签名/未知 DLL 被加载 → 节流后送检（白加黑主通道）
        所有 IO（哈希/签名/引擎）交给 _async_scan_launch 的扫描线程。
        """
        try:
            pid = int(getattr(evt, 'pid', 0) or 0)
            dll_path = (getattr(evt, 'image_path', '') or '').strip()
            if pid <= 0 or not dll_path:
                return
            name = os.path.basename(dll_path).lower()
            if not (name.endswith('.dll') or name.endswith('.exe')
                    or name.endswith('.ocx') or name.endswith('.scr')):
                return
            # 豁免：CI 深层系统目录（\windows\ 及子目录）+ PSLS 自身目录
            if self._is_trusted_loaded_dir(dll_path):
                return
            key = os.path.normcase(os.path.abspath(dll_path))
            now = time.monotonic()
            chain_hit = False
            with self._dropload_chain_lock:
                rec = self._dropload_chain.get(key)
                if rec is not None and not rec.get('disposed') \
                        and now - rec['ts'] <= self._DROPLOAD_CHAIN_TTL:
                    rec['ts'] = now
                    rec['load'] = 3
                    score = rec['drop'] + rec['load'] + rec['host']
                    if score >= self._DROPLOAD_CHAIN_THRESHOLD:
                        chain_hit = True
            if chain_hit:
                self._handle_dropload_chain(key, dll_path, pid, name)
                return
            # B：加载期白加黑送检（无签名/未知 DLL 被进程加载）
            if self._imgload_throttle_allow(pid):
                self._async_scan_launch(pid, name, dll_path)
        except Exception as e:
            logger.debug(f'image_load 事件处理异常: {e}')

    def _is_trusted_loaded_dir(self, path: str) -> bool:
        """加载路径豁免：CI 深层系统目录 / PSLS 自身目录

        仅豁免绝对可信位置；Program Files/用户目录等一律继续走送检
        （有签名/白名单哈希的在送检链路内被放行并缓存）。
        """
        try:
            lower = (path or '').lower()
        except Exception:
            return False
        if '\\windows\\' in lower:
            return True
        if lower.startswith('c:\\windows\\'):
            return True
        if self._self_excluded_dirs:
            try:
                ap = os.path.abspath(path).lower()
                if any(ap.startswith(d) for d in self._self_excluded_dirs):
                    return True
            except Exception:
                pass
        return False

    def _imgload_throttle_allow(self, pid: int) -> bool:
        """image_load 送检节流：30s 窗口内每 PID 最多送检 _MAX 个 DLL

        防止初始化期 DLL 风暴把扫描线程打满（内核已做 150ms 聚合，
        这里做第二层用户态限流）。
        """
        now = time.monotonic()
        with self._imgload_throttle_lock:
            rec = self._imgload_throttle.get(pid)
            if rec is None or now - rec['ts'] >= self._IMGLOAD_THROTTLE_TTL:
                self._imgload_throttle[pid] = {'ts': now, 'count': 1}
                return True
            if rec['count'] >= self._IMGLOAD_THROTTLE_MAX:
                return False
            rec['count'] += 1
            return True

    def _probe_host_threat(self, pid: int) -> int:
        """探测宿主进程是否为已知威胁（落地链 C 的强化信号 host+2）

        仅当链路已命中 drop+load 时才调用（命中率低，成本可忽略）。
        用 psutil 取宿主 exe → 查启动送检缓存是否判为威胁。
        """
        if pid <= 0:
            return 0
        try:
            import psutil as _ps
            host_exe = _ps.Process(pid).exe() or ''
        except Exception:
            return 0
        if not host_exe:
            return 0
        try:
            with self._launch_scan_lock:
                cached = self._launch_scan_cache.get(
                    os.path.normcase(os.path.abspath(host_exe)))
            if cached:
                _mtime, status, _t = cached
                if status and status != 'clean':
                    return 2
        except Exception:
            pass
        return 0

    def _handle_dropload_chain(self, key: str, dll_path: str,
                               pid: int, name: str) -> None:
        """落地-加载链成立（drop2+load3≥5）→ 高置信告警 + 隔离（C）

        处置策略：只隔离文件、终止宿主风险交给后续扫描/Ui 决策。
        pid 上报为 0 避免 auto 模式直接误杀被注入的合法宿主进程。
        """
        # 宿主维度强化（不影响结论，仅增补 detail）：宿主自身为已知威胁 +2
        host_bonus = 0
        try:
            with self._dropload_chain_lock:
                rec = self._dropload_chain.get(key)
                host_bonus = rec.get('host', 0) if rec else 0
                if rec is not None and not host_bonus:
                    host_bonus = self._probe_host_threat(pid)
                    rec['host'] = host_bonus
                if rec is not None:
                    rec['disposed'] = True
        except Exception:
            pass

        try:
            size = os.path.getsize(dll_path)
        except Exception:
            size = 0
        detail = (f'银狐落地执行链: 无签名可执行文件落地在用户目录({size} B)'
                  + '且已被进程加载(白加黑)，构成高置信落地-加载链'
                  + (f'；宿主进程为已知威胁' if host_bonus else ''))
        logger.warning(f'[落地链] {dll_path} 链分≥5，隔离+告警')
        # 隔离文件（自动隔离策略开启时）
        if self._quarantine_manager:
            try:
                result = self._quarantine_manager.quarantine_file(
                    dll_path,
                    reason=f'银狐落地执行链: {detail[:120]}')
                if not result:
                    logger.warning(f'落地链隔离失败，尝试删除: {dll_path}')
                    try:
                        os.remove(dll_path)
                    except Exception:
                        pass
            except Exception as e:
                logger.warning(f'落地链隔离异常: {e}')
        self._report_threat({
            'type': 'dropload_chain',
            'pid': 0,                       # 不杀宿主（可能为被注入的合法进程）
            'name': name,
            'path': dll_path,
            'detail': detail,
        })

    def _check_injections(self, snapshot: Dict[int, dict]):
        """检测可疑的进程注入行为

        检测维度（按可靠性/速度排序，前序检测命中则跳过后续）：
        1. 远线程起始地址异常（CreateRemoteThread 特征，新增）
        2. 模块/DLL 路径异常
        3. RWX 私有可执行内存页（shellcode 特征）
        4. 进程镂空（PE 头与磁盘文件不一致）

        性能约束（解决内存映射/线程枚举开销被频繁放大导致 CPU 占用过高）：
        - 每周期只轮转审计 _INJECTION_MAX_PROCESSES_PER_CYCLE 个进程
          （round-robin），全量覆盖分散到多个周期，消除单次 CPU 尖峰；
        - memory_maps 每进程仅调用一次，RWX / 镂空检测复用同一份结果，
          不再重复枚举整片地址空间。
        """
        if not HAS_PSUTIL:
            return

        items = list(snapshot.items())
        n = len(items)
        if n == 0:
            return

        # round-robin 轮转切片：每周期最多审计 limit 个进程（进程数少于 limit 时全量审计，不重复）
        limit = min(_INJECTION_MAX_PROCESSES_PER_CYCLE, n)
        offset = self._injection_scan_offset % n
        batch = [items[(offset + i) % n] for i in range(limit)]
        self._injection_scan_offset = (offset + limit) % n

        for pid, entry in batch:
            name = entry.get('name', '')
            exe = entry.get('exe', '')
            proc = entry.get('proc')

            if not proc or not exe:
                continue

            # 跳过系统进程和可信进程
            if name in TRUSTED_PROCESSES:
                continue
            # 跳过 PSLS 自身
            if name in self._protected_names:
                continue

            try:
                # 句柄审计双信号：内核 OB_CALLBACKS 记录该进程近期被
                # 注入特征访问位打开过 → 传给各检测子项降级阈值/标注来源
                ob_signal = self._get_ob_audit_signal(pid)

                # ---- 1. 远线程起始地址异常检测（CreateRemoteThread 特征）----
                # 远线程检测先于模块扫描，速度快、误报低
                if self._check_remote_thread_start(pid, proc, name, exe,
                                                   ob=ob_signal):
                    continue  # 已发现注入，跳过后续检测避免重复告警

                # memory_maps 一次性采集，模块/RWX/镂空检测复用（避免重复枚举地址空间）
                modules = list(proc.memory_maps())

                # ---- 2. 模块/DLL 路径异常检测 ----
                suspicious_modules: List[str] = []

                for m in modules[:200]:
                    path = getattr(m, 'path', '') or ''
                    if not path:
                        continue
                    path_lower = path.lower()
                    if '\\windows\\' in path_lower or '\\program files' in path_lower:
                        continue
                    for kw in DANGEROUS_DIR_KEYWORDS:
                        if kw in path_lower:
                            suspicious_modules.append(os.path.basename(path))
                            break

                if suspicious_modules:
                    with self._stats_lock:
                        self._stats['injections_detected'] += 1
                    self._report_threat({
                        'type': 'process_injection',
                        'pid': pid,
                        'name': name,
                        'path': exe,
                        'detail': (f'检测到 {len(suspicious_modules)} 个可疑模块: '
                                   f'{suspicious_modules[:5]}'
                                   + self._fmt_ob_signal(ob_signal)),
                    })
                    continue

                # ---- 3. RWX 私有可执行内存页检测（shellcode 特征）----
                if self._check_rwx_private_memory(pid, proc, name, exe,
                                                  maps=modules, ob=ob_signal):
                    continue

                # ---- 4. 进程镂空检测（PE 头与磁盘文件不一致）----
                self._check_process_hollowing(pid, proc, name, exe,
                                              maps=modules, ob=ob_signal)

            except (psutil.NoSuchProcess, psutil.AccessDenied,
                    psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f"检查 PID={pid} 注入时出错: {e}")

    def _check_rwx_private_memory(self, pid: int, proc: 'psutil.Process',
                                   name: str, exe: str,
                                   maps: Optional[List] = None,
                                   ob: Optional[dict] = None) -> bool:
        """检测 RWX 私有可执行内存页（shellcode 注入特征）

        正常进程很少有 RWX 私有内存页，但 shellcode 注入（如 VirtualAllocEx +
        WriteProcessMemory + CreateRemoteThread）会创建此类内存页。

        Args:
            maps: 可选，调用方已采集的 memory_maps 结果（避免重复枚举地址空间）
            ob: 可选，句柄审计双信号（内核 OB_CALLBACKS），命中时标注告警来源

        Returns:
            True 表示检测到可疑 shellcode
        """
        try:
            if maps is None:
                maps = proc.memory_maps(grouped=False)
            rwx_private_count = 0
            rwx_private_size = 0

            for m in maps:
                # 提取内存权限
                perms = getattr(m, 'perms', '') or ''
                path = getattr(m, 'path', '') or ''

                # 检测 'rwx' 权限 + 私有内存（无路径或路径为空）
                # 私有内存通常是 shellcode，正常 DLL/EXE 有文件路径
                if 'x' in perms and 'w' in perms and 'r' in perms:
                    if not path or path.startswith('['):
                        # 私有可执行内存
                        rwx_private_count += 1
                        rwx_private_size += getattr(m, 'rss', 0)

            # 阈值：>= 2 个 RWX 私有页 或 总大小 >= 64KB
            if rwx_private_count >= 2 or rwx_private_size >= 64 * 1024:
                with self._stats_lock:
                    self._stats['injections_detected'] += 1
                self._report_threat({
                    'type': 'shellcode_injection',
                    'pid': pid,
                    'name': name,
                    'path': exe,
                    'detail': (f'检测到 RWX 私有可执行内存: '
                               f'{rwx_private_count} 块, '
                               f'共 {rwx_private_size // 1024} KB'
                               + self._fmt_ob_signal(ob)),
                })
                return True

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            logger.debug(f"检查 PID={pid} RWX 内存失败: {e}")

        return False

    def _check_process_hollowing(self, pid: int, proc: 'psutil.Process',
                                  name: str, exe: str,
                                  maps: Optional[List] = None,
                                  ob: Optional[dict] = None) -> bool:
        """检测进程镂空（Process Hollowing）

        进程镂空手法：合法进程被启动后，恶意软件卸载其原始镜像，
        注入恶意 PE。特征：进程内存中的 PE 头与磁盘文件不一致。

        简化检测：比较进程可执行镜像的内存大小与磁盘文件大小，
        差异过大可能是镂空。

        Args:
            maps: 可选，调用方已采集的 memory_maps 结果（避免重复枚举地址空间）
            ob: 可选，句柄审计双信号（内核 OB_CALLBACKS），命中时标注告警来源

        Returns:
            True 表示检测到可疑镂空
        """
        try:
            # 读取磁盘文件大小
            if not os.path.exists(exe):
                return False
            disk_size = os.path.getsize(exe)

            # 获取进程内存映射中的镜像大小
            if maps is None:
                maps = proc.memory_maps(grouped=False)
            image_size = 0
            exe_lower = exe.lower()

            for m in maps:
                path = getattr(m, 'path', '') or ''
                if path.lower() == exe_lower:
                    # 进程的镜像内存映射
                    image_size += getattr(m, 'rss', 0)

            # 如果镜像内存远大于磁盘文件（>2倍），可能是镂空
            # 注意：内存映射包含 BSS、堆栈扩展等，正常情况会略大于磁盘文件
            if disk_size > 0 and image_size > 0:
                ratio = image_size / disk_size
                if ratio > 3.0 and image_size > 1024 * 1024:  # >1MB 且 >3倍
                    with self._stats_lock:
                        self._stats['injections_detected'] += 1
                    self._report_threat({
                        'type': 'process_hollowing',
                        'pid': pid,
                        'name': name,
                        'path': exe,
                        'detail': (f'进程镜像内存与磁盘文件大小差异过大: '
                                   f'磁盘={disk_size // 1024} KB, '
                                   f'内存={image_size // 1024} KB, '
                                   f'比率={ratio:.1f}x'
                                   + self._fmt_ob_signal(ob)),
                    })
                    return True

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            logger.debug(f"检查 PID={pid} 进程镂空失败: {e}")

        return False

    def _get_known_module_ranges(self, proc: 'psutil.Process',
                                 kernel32=None) -> List[tuple]:
        """获取进程中所有已知模块的地址范围 [(base, end), ...]

        使用 EnumProcessModules + GetModuleInformation 精确获取每个模块的
        基地址和大小，比 psutil.memory_maps() 更可靠（后者在 Windows 上
        不返回地址范围）。
        """
        from ctypes import wintypes
        ranges: List[tuple] = []

        if not HAS_CTYPES or sys.platform != 'win32':
            return ranges

        try:
            if kernel32 is None:
                kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            psapi = ctypes.WinDLL('psapi', use_last_error=True)

            # 明确声明函数签名（64 位进程指针不能用默认 int 转换）
            psapi.EnumProcessModules.restype = wintypes.BOOL
            psapi.EnumProcessModules.argtypes = [
                wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE),
                wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
            ]

            class MODULEINFO(ctypes.Structure):
                _fields_ = [
                    ('lpBaseOfDll', wintypes.LPVOID),
                    ('SizeOfImage', wintypes.DWORD),
                    ('EntryPoint', wintypes.LPVOID),
                ]

            psapi.GetModuleInformation.restype = wintypes.BOOL
            psapi.GetModuleInformation.argtypes = [
                wintypes.HANDLE, wintypes.HMODULE,
                ctypes.POINTER(MODULEINFO), wintypes.DWORD,
            ]

            h_process = kernel32.OpenProcess(
                _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ,
                False, proc.pid,
            )
            if not h_process:
                return ranges

            try:
                MAX_MODULES = 1024
                module_handles = (wintypes.HMODULE * MAX_MODULES)()
                cb_needed = wintypes.DWORD(0)

                if not psapi.EnumProcessModules(
                    h_process, module_handles,
                    ctypes.sizeof(module_handles), ctypes.byref(cb_needed),
                ):
                    return ranges

                num_modules = cb_needed.value // ctypes.sizeof(wintypes.HMODULE)

                for i in range(num_modules):
                    h_mod = module_handles[i]
                    mod_info = MODULEINFO()
                    if psapi.GetModuleInformation(
                        h_process, h_mod,
                        ctypes.byref(mod_info),
                        ctypes.sizeof(mod_info),
                    ):
                        base = mod_info.lpBaseOfDll
                        size = mod_info.SizeOfImage
                        if base and size > 0:
                            base_int = int(base)
                            if base_int > 0:
                                end = base_int + size
                                ranges.append((base_int, end))

            finally:
                kernel32.CloseHandle(h_process)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            logger.debug(f"获取 PID={proc.pid} 模块范围失败: {e}")

        return ranges

    def _is_address_in_known_module(self, address: int,
                                     known_ranges: List[tuple]) -> bool:
        """检查一个内存地址是否落在已知模块范围内"""
        if address <= 0:
            return False
        for base, end in known_ranges:
            if base <= address < end:
                return True
        return False

    def _check_remote_thread_start(self, pid: int, proc: 'psutil.Process',
                                    name: str, exe: str,
                                    ob: Optional[dict] = None) -> bool:
        """检测远程线程起始地址异常（最核心的注入检测手段）

        恶意软件常用 CreateRemoteThread + VirtualAllocEx + WriteProcessMemory
        在目标进程中创建起始地址指向 shellcode 的远程线程。
        这些线程的起始地址不会落在任何已知 DLL/EXE 模块范围内。

        使用 NtQueryInformationThread(ThreadQuerySetWin32StartAddress=10)
        查询每个线程的 Win32 起始地址，再和进程中已知模块地址范围比对。

        Args:
            ob: 可选，句柄审计双信号（内核 OB_CALLBACKS）。有审计支撑时
                单个未知起始地址线程即报（双信号降级阈值），降低漏报。

        Returns:
            True 表示检测到可疑远程线程
        """
        if not HAS_CTYPES or sys.platform != 'win32':
            return False

        try:
            ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            # ---- 1. 获取进程中所有已知模块地址范围 ----
            known_ranges = self._get_known_module_ranges(proc, kernel32)

            # ---- 2. 枚举线程 ID ----
            try:
                threads = proc.threads()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                return False

            if not threads:
                return False

            # ---- 3. 对每个线程查询起始地址 ----
            suspicious_threads: List[int] = []

            for t in threads:
                tid = t.id
                try:
                    # OpenThread 获取线程句柄
                    h_thread = kernel32.OpenThread(
                        _THREAD_QUERY_INFORMATION, False, tid
                    )
                    if not h_thread:
                        continue

                    try:
                        # NtQueryInformationThread 查询起始地址
                        start_addr = ctypes.c_void_p()
                        status = ntdll.NtQueryInformationThread(
                            h_thread,
                            _THREAD_QUERY_SET_WIN32_START_ADDRESS,
                            ctypes.byref(start_addr),
                            ctypes.sizeof(start_addr),
                            None,
                        )
                        # STATUS_SUCCESS = 0
                        if status != 0 or not start_addr.value:
                            continue

                        start_val = start_addr.value

                        # 排除 0 / 负数 / 高位内核地址（用户态线程起始地址 < 2^47）
                        if start_val <= 0 or start_val >= (1 << 47):
                            continue

                        # 检查起始地址是否落在已知模块内
                        if not self._is_address_in_known_module(start_val, known_ranges):
                            suspicious_threads.append(tid)

                    finally:
                        kernel32.CloseHandle(h_thread)

                except Exception:
                    continue

            # ---- 4. 判定 ----
            # 阈值：≥ 2 个未知起始地址的线程 → 高度可疑
            # 单个未知起始地址可能是合法的轻量线程池线程，放过避免误报；
            # 但在句柄审计双信号支撑下（明确有进程以注入特征位打开过本进程），
            # 单个未知起始地址也构成"行为+审计"双信号，降级到 1 即报。
            threshold = 1 if ob else 2
            if len(suspicious_threads) >= threshold:
                with self._stats_lock:
                    self._stats['injections_detected'] += 1
                self._report_threat({
                    'type': 'remote_thread_injection',
                    'pid': pid,
                    'name': name,
                    'path': exe,
                    'detail': (f'检测到 {len(suspicious_threads)} 个线程'
                               f'起始地址不在任何已知模块内'
                               f'（远程注入特征）'
                               + self._fmt_ob_signal(ob)),
                    'suspicious_tids': suspicious_threads[:10],
                })
                return True

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            logger.debug(f"检查 PID={pid} 远线程起始地址失败: {e}")

        return False

    def quick_injection_check(self, pid: int, name: str, exe: str,
                              proc: 'psutil.Process') -> bool:
        """新进程轻量注入预检（不等 6 秒周期，立即执行）

        仅检查最快速、最可靠的两项：
        1. 远线程起始地址异常（CreateRemoteThread 特征）
        2. RWX 私有内存（shellcode 特征）

        模块路径异常和镂空检测留给周期性 _check_injections 做完整检查。

        Returns:
            True 表示检测到可疑注入
        """
        if not HAS_PSUTIL or not proc or not exe:
            return False

        if name in TRUSTED_PROCESSES or name in self._protected_names:
            return False

        try:
            # 预检 1：远线程起始地址（最核心）
            if self._check_remote_thread_start(pid, proc, name, exe):
                return True

            # 预检 2：RWX 私有内存（快速 shellcode 检测）
            if self._check_rwx_private_memory(pid, proc, name, exe):
                return True

        except (psutil.NoSuchProcess, psutil.AccessDenied,
                psutil.ZombieProcess):
            pass
        except Exception as e:
            logger.debug(f"PID={pid} 快速注入预检出错: {e}")

        return False

    # ---- 沙箱验证放行链路（新）----

    def _notify_launch_monitoring(self, pid: int, name: str, exe_path: str,
                                  reason: str = '', scan_result: dict = None):
        """监测可见性：非信任/可疑程序启动被拦截时，广播一条启动监测记录。

        默认仅上报"监测中(scanning)"状态，由 bridge 侧识别为纯监测（记活动），
        不触发威胁弹窗、不重复沙箱分析 —— 复用现有隔离链路，无重复扫描。
        传入 scan_result（如 LaunchScanResult）时以其终态为准
        （blocked/quarantined 等，用于终结一直停留的 scanning 状态）。

        【不响应保护】回调实际会跑到 bridge._add_activity →
        _signal_lock / _pending_tool_signals.append。在高压场景下 20ms
        flush_timer 还没来得及消费时，回调线程也会因 GIL+append 争用被
        拖到数百毫秒。这里把真正的回调派发扔到独立 daemon 线程执行，
        并且 500ms 超时直接放弃，保证 LaunchCheck worker 不会因 UI
        排队被卡。
        """
        if self._on_launch_scan is None:
            return
        # 提前在当前线程做好 dict 构造（纯内存操作，不怕卡）
        try:
            if isinstance(scan_result, dict):
                result = dict(scan_result)
                result.setdefault('name', name or '未知')
                result.setdefault('reason', reason)
            else:
                result = {
                    'status': 'scanning',
                    'name': name or '未知',
                    'reason': reason,
                }
            payload = {
                'pid': pid,
                'name': name,
                'exe_path': exe_path,
                'scan_result': result,
            }
        except Exception as e:
            logger.warning(f'启动监测通知构造失败: {e}')
            return

        _done: List[bool] = [False]

        def _sender():
            try:
                cb = self._on_launch_scan
                if cb is not None:
                    cb(payload)
            except Exception as e:
                try:
                    logger.error(f'启动监测通知失败: {e}')
                except Exception:
                    pass
            finally:
                _done[0] = True

        t = threading.Thread(target=_sender, daemon=True,
                             name=f'LaunchNotify-{pid}')
        t.start()
        # 【性能修复】此处**不得**再 join。
        # 本方法在"非信任程序启动 → 终止"的关键路径上被调用
        # （_sandbox_then_release 阶段 0，advisory 通知），原先的
        # join(timeout=0.5) 会让每一次拦截都先白白等最多 0.5s 才轮到
        # _emergency_kill，叠加阶段 0.5 的静态预分析，用户观感就是
        # "emergency kill 不及时、未知对象已经跑起来了"。通知丢失无安全
        # 影响（见上），故彻底 fire-and-forget。
        return

    def _startup_existing_process_survey(self, delay_s: float = 20.0) -> None:
        """PSLS 启动后：一次性扫描已存在的非 Windows 进程（后台 daemon 线程）。

        盲区：PSLS 启动前就已运行的进程不会产生 ETW/轮询"新进程"事件，
        整个会话都可能漏检（病毒可能在杀软常驻之前就在运行）。本方法在
        启动后 delay_s 秒执行一遍存量枚举，逐条复用 _check_new_process
        判定链路（startup_survey 模式），仅对静态判定可疑的进程执行
        终止+询问，其余一律放行。

        约束：
          - 独立 daemon 线程，全程不阻塞任何启动链路 / worker 池；
          - 每条经 _enqueue_launch_check 进入调度队列，复用去重 / 绝对时限 /
            worker 池，处置行为与实时启动监测完全同构；
          - 误杀防控：survey 模式不会"全部终止"，无高置信静态特征的非信任
            程序只记录后放行。
        """
        try:
            if delay_s > 0 and self._stop_event.wait(delay_s):
                return
            if self._stop_event.is_set() or not getattr(self, '_running', False):
                return
            checked = 0
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    if proc.pid == os.getpid() or self._is_psls_related_process(proc):
                        continue
                    info = proc.info
                    pid = int(info['pid'])
                    exe = info.get('exe') or ''
                    if not exe:
                        continue  # 无 exe 的存量进程（系统/权限受限）跳过
                    entry = {
                        'name': (info.get('name') or '').lower(),
                        'exe': exe,
                        'cmdline': info.get('cmdline') or [],
                        'proc': proc,
                    }
                    self._enqueue_launch_check(pid, entry, survey=True)
                    checked += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        psutil.ZombieProcess):
                    continue
            self._add_event('system', 0, '', 'info',
                            f'启动存量进程扫描完成：共检查 {checked} 个存量进程，'
                            f'可疑进程按终止+询问处置')
        except Exception as e:
            logger.warning(f'启动存量进程扫描异常: {e}')

    def _is_startup_survey_suspicious(self, exe: str, name: str,
                                      pid: int) -> bool:
        """启动存量扫描的"可疑"静态判定（保守策略：宁可漏报，不可误报）。

        已运行进程没有"启动时刻行为链"，这里只做 1.2s 限时的静态判定
        （复用 _pre_kill_static_probe，结果含自爆特征与 PEAnalyzer 风险分）：
          - 自爆式特征（物理磁盘直写 / 引导文件目标 / 蓝屏关机 API /
            TLS 回调+磁盘意图 / dd 直写脚本等）→ 可疑；
          - PEAnalyzer 综合风险分 ≥100（severity=high）→ 可疑；
          - 其余（含无签名普通第三方程序、磁盘/系统工具类程序）一律放行。
        命中时由调用方走 _sandbox_then_release（终止+沙箱验证+询问）。
        """
        try:
            if not exe or not os.path.isfile(exe):
                return False
            probe = self._pre_kill_static_probe(exe, timeout_s=1.2)
            if probe.get('self_destruct'):
                logger.warning(
                    f'启动存量扫描：可疑进程 PID={pid} {name} 命中自爆式特征 '
                    f'[{"; ".join(probe.get("reasons") or [])}] → 终止并询问')
                return True
            pe_total = int(probe.get('pe_total_score') or 0)
            if pe_total >= 100:
                logger.warning(
                    f'启动存量扫描：可疑进程 PID={pid} {name} '
                    f'PE 风险分 {pe_total}（=high）→ 终止并询问')
                return True
        except Exception as e:
            logger.debug(f'启动存量扫描可疑判定异常 {exe}: {e}')
        return False

    def _pre_kill_static_probe(self, exe: str, timeout_s: float = 1.2) -> dict:
        """终止进程前的快速静态"反编译"预分析：识别自爆式病毒。

        自爆式病毒（"被终止瞬间破坏 MBR/引导文件后蓝屏"）把破坏逻辑挂在
        进程退出路径或独立守护线程上，常规 kill-then-ask 链路在 TerminateProcess
        之前对样本一无所知。本方法在终止前对 exe 做限时静态分析：
          - 原始字节串扫描（ASCII + UTF-16LE）：物理磁盘设备路径、引导文件
            目标、蓝屏/关机类 API 名称、脚本式 dd 直写磁盘；
          - PE 结构分析（PEAnalyzer）：TLS 回调（经典自爆挂载点）、可疑导入
            （DeviceIoControl/CreateFile*）、打包器、风险评分。
        命中返回 self_destruct=True 供调用方加固引导保护 + 调整终止顺序。

        性能约束：
          - 最多读 min(file_size, 6MB) 字节做字符串扫描；
          - PEAnalyzer 只对 <=16MB 的文件运行；
          - 全程由独立 daemon 子线程 + join(timeout) 守护，超时立即放弃
            返回中性结果（不阻止终止），绝不卡死 kill 链路；
          - 结果按 (exe, mtime) 缓存 60s 复用。
        """
        neutral = {'self_destruct': False, 'reasons': [], 'score': 0,
                   'is_pe': False, 'probe_ok': False}
        if not exe:
            return neutral
        try:
            if not os.path.isfile(exe):
                return neutral
            norm_key = os.path.normcase(os.path.abspath(exe))
        except Exception:
            return neutral

        try:
            mtime = os.path.getmtime(exe)
        except Exception:
            mtime = 0

        # 命中缓存（60s TTL）直接复用，避免重复读盘
        try:
            with self._pre_kill_probe_lock:
                cached = self._pre_kill_probe_cache.get(norm_key)
                if cached:
                    c_mtime, c_result, c_ts = cached
                    if c_mtime == mtime and (time.time() - c_ts) < 60.0:
                        return dict(c_result)
        except Exception:
            pass

        result_holder: List[dict] = [None]

        def _probe_runner():
            try:
                result_holder[0] = self._run_pre_kill_probe_inner(exe)
            except Exception as e:
                logger.warning(f'[自爆预分析] 分析异常 {exe}: {e}')
                result_holder[0] = None

        t = threading.Thread(target=_probe_runner, daemon=True,
                             name=f'PreKillProbe-{os.path.basename(exe)[:16]}')
        t.start()
        t.join(timeout=timeout_s)
        if result_holder[0] is None:
            if t.is_alive():
                logger.warning(
                    f'[自爆预分析] 超时 ({timeout_s:.1f}s) 放弃 {exe}，'
                    f'按无自爆特征继续')
            return dict(neutral)

        result = dict(result_holder[0])
        try:
            with self._pre_kill_probe_lock:
                if len(self._pre_kill_probe_cache) > 256:
                    cutoff = time.time() - 60.0
                    expired = [k for k, v in self._pre_kill_probe_cache.items()
                               if v[2] < cutoff]
                    for k in expired:
                        self._pre_kill_probe_cache.pop(k, None)
                self._pre_kill_probe_cache[norm_key] = (mtime, result, time.time())
        except Exception:
            pass
        return result

    def _run_pre_kill_probe_inner(self, exe: str) -> dict:
        """静态预分析核心逻辑（由守护子线程调用，不再加锁）。"""
        probe: dict = {'self_destruct': False, 'reasons': [],
                       'score': 0, 'is_pe': False, 'probe_ok': True,
                       'pe_total_score': 0}
        reasons: List[str] = []
        score = 0
        is_pe = False

        # ---- 1) 原始字节串扫描（ASCII + UTF-16LE）----
        raw = b''
        try:
            size = os.path.getsize(exe)
            with open(exe, 'rb') as f:
                # 只头 6MB（自爆特征集中在导入/资源区）
                raw = f.read(6 * 1024 * 1024)
        except Exception:
            raw = b''
            size = 0

        def _scan_patterns(data: bytes) -> tuple:
            hits = []
            adds = 0
            low = data.lower()
            # 物理磁盘设备路径：\\.\PhysicalDriveN / \Device\HarddiskN\DRxy
            # （仅"扇区级物理磁盘句柄"才算，\Device\HarddiskVolumeN 卷路径
            #   是 bcdedit/磁盘工具的正常引用，不计入，避免误报）
            _phys_ascii = (b'\\.\\physicaldrive' in low
                           or (b'\\device\\harddisk' in low
                               and b'\\device\\harddiskvolume' not in low))
            if _phys_ascii:
                hits.append('物理磁盘设备路径')
                adds += 40
            # 磁盘控制 IOCTL（含 API 名原始串；弱信号，仅当与物理磁盘路径/自毁
            # API 等强特征共现时参与自爆判定，避免普通磁盘工具误报）
            if (b'ioctl_disk_' in low or b'deviceiocontrol' in low
                    or b'ntwritefile' in low):
                hits.append('磁盘 IOCTL 控制')
                adds += 15
            # 蓝屏/关机/断电类 API（TerminateProcess 不执行退出清理，
            # 但独立守护线程/退出钩子可调用这些接口制造蓝屏）
            for pat in (b'ntraiseharderror', b'ntshutdownsystem',
                        b'ntsetsystempowerstate', b'ntsetsysteminformation',
                        b'kebugcheck', b'bugcheckex'):
                if pat in low:
                    hits.append(f'自毁 API: {pat.decode("latin1")}')
                    adds += 30
                    break
            # 引导链/磁盘写脚本特征
            if b'bootmgr' in low or b'\\efi\\' in low or b'bootmgfw' in low:
                hits.append('引导文件目标')
                adds += 20
            if b'dd if=' in low and (b'of=\\.\\physicaldrive' in low
                                     or b'of=\\\\.\\physicaldrive' in low):
                hits.append('脚本直写物理磁盘(dd)')
                adds += 50
            # UTF-16LE 变体（宽字符串）
            try:
                low16 = data.decode('utf-16-le', errors='ignore').lower()
                _phys_wide = ('\\.\\physicaldrive' in low16
                              or ('\\device\\harddisk' in low16
                                  and '\\device\\harddiskvolume' not in low16))
                if _phys_wide:
                    hits.append('物理磁盘设备路径(宽)')
                    adds += 40
                for pat in ('ntraiseharderror', 'ntshutdownsystem',
                            'ntsetsystempowerstate'):
                    if pat in low16:
                        hits.append(f'自毁 API(宽): {pat}')
                        adds += 30
                        break
            except Exception:
                pass
            return hits, adds

        try:
            hits, adds = _scan_patterns(raw)
            reasons.extend(hits)
            score += adds
        except Exception:
            pass

        # ---- 2) PE 结构静态分析（PEAnalyzer，只对 <=16MB 文件）----
        if size <= 16 * 1024 * 1024:
            try:
                from engine.pe_analyzer import PEAnalyzer
                pa = PEAnalyzer()
                presult = pa.analyze(exe)
                if presult.get('is_pe'):
                    is_pe = True
                    probe['pe_total_score'] = int(
                        presult.get('total_score', 0) or 0)
                    if presult.get('has_tls_callback'):
                        reasons.append(
                            f'TLS 回调 x{presult.get("tls_callback_count", 1)}'
                            '（自爆挂载点）')
                        score += 25
                    suspicious = presult.get('suspicious_imports') or []
                    for imp in suspicious:
                        fn = imp.get('function', '')
                        if fn in ('DeviceIoControl', 'CreateFileA', 'CreateFileW',
                                  'NtWriteFile', 'WriteFile',
                                  'NtRaiseHardError', 'NtShutdownSystem'):
                            reasons.append(f'危险导入: {fn}')
                            score += 20
                            break
                    if presult.get('packer'):
                        reasons.append(f'打包器: {presult["packer"]}')
                        score += 10
                    score += min(presult.get('total_score', 0) // 10, 20)
            except Exception:
                pass  # PEAnalyzer 失败不影响字符串扫描结论

        # ---- 自爆判定（保守策略，宁少勿炸；误报仅触发无害的加固操作）----
        # 核心思路：仅引用物理磁盘/IOCTL ≠ 自爆（bcdedit、磁盘工具都会）；
        # 必须是"有破坏能力 + 有终止触发机制"：
        #   - 直写磁盘脚本（dd）
        #   - 自毁/蓝屏 API ×（磁盘访问 or TLS 回调 or 磁盘 IOCTL）
        #   - 物理磁盘访问 × TLS 回调（TLS 回调是"进程退出时执行代码"的
        #     经典挂载点，配合磁盘写意图 = 典型自爆组合）
        disk_hit = any('物理磁盘' in r for r in reasons)
        crash_hit = any('自毁 API' in r for r in reasons)
        tls_hit = any('TLS 回调' in r for r in reasons)
        disk_ctrl_hit = any('危险导入' in r or '磁盘 IOCTL' in r
                            for r in reasons)
        dd_hit = any('dd' in r for r in reasons)

        if dd_hit:
            probe['self_destruct'] = True
        elif crash_hit and (disk_hit or disk_ctrl_hit or tls_hit):
            probe['self_destruct'] = True
        elif disk_hit and tls_hit:
            probe['self_destruct'] = True

        probe['reasons'] = reasons
        probe['score'] = score
        probe['is_pe'] = is_pe
        return probe

    def _sandbox_then_release(self, pid: int, name: str, exe: str,
                              cmdline: Optional[List[str]],
                              reason: str,
                              on_done: Optional[Callable[[], None]] = None,
                              context_trust: Optional[dict] = None):
        """链路：**直接终止进程 + 独占锁定源文件 → 沙箱验证 → 询问重启 / 隔离**

        启动监测沙箱链路（kill-then-ask 模式，不再挂起进程）：
        - 旧链路：挂起（SuspendThread）→ 沙箱验证 → 恢复原进程。挂起期间
          进程长期冻结状态不友好，且 resume 竞态复杂（线程被反复挂起等）。
        - 新链路：**立即终止**进程（毫秒级）并**立即占用源文件**（对 exe
          加 share=0 独占锁），分析期间用户双击也无法启动该 exe。
        - verdict=clean → 释放源文件锁 + 弹窗询问用户是否重启（默认不重启）
        - verdict!=clean → 保持占用，终止兜底 + 隔离 + 弹窗拦截
        - context_trust: 上下文信任评估结果（_assess_contextual_trust 返回值）。
          携带后作为沙箱"调查先验"传入 analyze(context_trust=trust)，仅降低
          分数型判定，一票否决硬证据（勒索/卷影/银狐）不被信任豁免。

        安全兜底：
        - 终止失败 → 仍走后台分析（文件已锁定，用户无法启动）
        - 排队满 / 槽位超时 / 导入失败 → 释放源文件锁，放弃本次处置
        """
        # ---- 阶段 0：操作前先抓证据（防止竞态，进程死了就拿不到了）----
        if not exe or not os.path.isfile(exe):
            logger.warning(f'沙箱放行链路：exe 不可用，跳过 PID={pid}')
            return

        # 兜底自豁免：无论如何不允许对 PSLS 主进程自身执行终止/沙箱/隔离。
        # 曾发生主进程 python.exe 被当威胁送进沙箱（判 malware）导致主 GUI 闪退。
        if pid and pid == os.getpid():
            logger.error(
                f'沙箱放行链路：拒绝处置 PSLS 主进程自身 PID={pid} {name}，'
                f'原因 {reason!r}（自我保护拦截，放行该进程）')
            return

        saved_cmdline = list(cmdline) if cmdline else None
        if not saved_cmdline and HAS_PSUTIL:
            try:
                proc = psutil.Process(pid)
                saved_cmdline = proc.cmdline()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                saved_cmdline = None

        display = name or os.path.basename(exe)

        # 监测可见性：被拦截的非信任/可疑程序启动即广播启动监测记录
        # （状态=scanning，bridge 侧只记活动、不弹威胁窗、不重复沙箱）
        self._notify_launch_monitoring(pid, display, exe, reason)

        # 大文件（>50MB）跳过沙箱：**体积大 != 恶意，绝不因此终止或隔离**。
        # 旧实现对超大文件执行 kill + 上报 block(verdict='skipped')，而 bridge 对
        # 任何 block 一律"兜底隔离" → 主流大型正常程序（Electron 应用 / QQ / 游戏，
        # 动辄 100~300MB）被误杀并隔离；实测把 PSLS 宿主的 IDE 也隔离了
        # （TRAE SOLO CN.exe 204.7MB、agent-tool-host.exe 84.5MB），导致宿主文件消失。
        # 新策略：超阈值不做沙箱（无法在合理时间/资源内分析），直接放行并记录，
        # 不 kill、不隔离、不上报 block；需要完整分析可开启"大文件沙箱"开关
        # （sandbox_run_large_files=True 时走下方正常沙箱链路）。
        if not getattr(self, 'sandbox_run_large_files', False):
            try:
                file_size = os.path.getsize(exe)
            except OSError:
                file_size = 0
            if file_size > 50 * 1024 * 1024:
                _mb = file_size / 1024 / 1024
                # 体积大既无法在合理资源内沙箱分析，也**不能静默放行**：
                # 实测 64.6MB 的勒索样本正因此"放行不终止"而真实执行，随后
                # 篡改了 PSLS 自身 _internal 文件并写入启动项。
                # 现改为：**终止 + 询问用户是否放行**，且不再写 clean 缓存
                # （避免该文件被永久信任）。既堵住缺口，又给超大正常程序
                # （IDE/游戏等）保留用户放行出口。
                logger.warning(
                    f'沙箱放行链路：文件过大 ({_mb:.1f}MB)，无法沙箱分析，'
                    f'已终止并询问用户是否放行: {exe}')
                self._add_event('sandbox_skip', pid, display, 'warn',
                                f'文件过大 ({_mb:.1f}MB)，无法沙箱分析：'
                                f'已终止并询问是否放行', exe)
                kill_ok_big = False
                if pid > 0:
                    try:
                        kill_ok_big = bool(self._emergency_kill(pid))
                    except Exception as e_big:
                        logger.warning(f'沙箱放行链路：大文件终止异常: {e_big}')
                if not kill_ok_big:
                    logger.warning(
                        f'沙箱放行链路：大文件进程终止未确认 PID={pid} {display}')
                # 询问用户是否放行（复用 release 询问弹窗；5s 超时默认不放行）
                # 同时把路径记入拦截黑名单：该程序（及其 runas 自提权重启的
                # 同路径实例）在用户明确放行前不得再次运行。
                self._mark_exe_blocked(exe, '文件过大未沙箱分析，已终止')
                self._emit_sandbox_release_request(
                    display, exe,
                    f'文件过大({_mb:.1f}MB)，无法沙箱分析，已终止：是否放行？',
                    saved_cmdline, 0,
                    event_desc=(f'文件过大({_mb:.1f}MB)，未沙箱分析，'
                                f'等待用户确认是否放行'),
                    kind='oversize')
                return

        # ---- 阶段 0.5：自爆式预分析（与"立即终止"并行，不再阻塞终止）----
        # 自爆式病毒把破坏（写坏 MBR/引导文件、触发蓝屏）挂在进程退出路径
        # 或独立守护线程上。原实现在终止**之前**串行跑 _pre_kill_static_probe
        # （最坏 1.2s），使"非信任程序启动 → 真正被终止"之间最多多出 1.2s ——
        # 这正是"emergency kill 不及时、未知对象已经跑起来"的直接原因。
        # 现改为：探测放后台线程跑，_emergency_kill **立即**执行；探测结果
        # 收口后再按需 (1) 加固 MBR/引导保护 (2) 清理守护子进程
        # (3) 校验并回滚引导扇区。TerminateProcess 不执行退出清理，事后
        # 清理守护进程同样有效；且子进程 PID 必须在杀主进程之前快照
        # （父进程终止后按 ppid 枚举不可靠）。
        _sd_holder: List[dict] = [None]

        def _pre_kill_probe_runner():
            try:
                _sd_holder[0] = self._pre_kill_static_probe(exe)
            except Exception as e_p:
                logger.debug(f'沙箱放行链路：自爆预分析异常 {e_p}')

        _probe_thread = threading.Thread(
            target=_pre_kill_probe_runner, daemon=True,
            name=f'PreKillAsync-{os.path.basename(exe)[:16]}')
        _probe_thread.start()

        _child_pids: List[int] = []
        if pid > 0 and HAS_PSUTIL:
            try:
                _child_pids = [c.pid for c in
                               psutil.Process(pid).children(recursive=True)]
            except Exception:
                _child_pids = []

        # ---- 阶段 1：立即终止进程 + 占用源文件（不冻结）----
        # 立即终止进程（<1ms，不让恶意代码跑），**不再等待**静态预分析。
        kill_ok = self._emergency_kill(pid)
        fallback_to_kill_mode = True  # kill-then-ask：不再挂起进程
        # 登记"已被拦截"路径黑名单：样本常用 runas 自提权重启同路径实例
        # （提权实例会脱离沙箱盒），任何新实例都必须被立即终止。
        # 用户明确批准重启/放行时由 restart_sandboxed_process 解除。
        self._mark_exe_blocked(exe, reason)

        # ---- 阶段 1.1：收口自爆预分析（限时，绝不拖慢已完成的终止）----
        self_destruct_risk = False
        try:
            _probe_thread.join(timeout=1.2)
            static_probe = _sd_holder[0] or {}
            self_destruct_risk = bool(static_probe.get('self_destruct'))
            if self_destruct_risk:
                _sd_reasons = '; '.join(static_probe.get('reasons') or [])
                logger.warning(
                    f'沙箱放行链路：{display} 静态预分析命中自爆式特征 '
                    f'[{_sd_reasons}]，加固 MBR/引导保护 + 清理守护子进程')
                # 1) 引导保护加固：确保备份存在、写保护生效（桥接层实现）
                try:
                    _arm = getattr(self, '_mbr_arm_before_kill_hook', None)
                    if _arm is not None and callable(_arm):
                        _arm(str(exe))
                except Exception as e_arm:
                    logger.warning(f'沙箱放行链路：MBR 加固失败: {e_arm}')
                # 2) 用快照到的子进程 PID 快速清理守护进程
                _killed_kids = 0
                for _cp in _child_pids:
                    try:
                        if self._emergency_kill(_cp):
                            _killed_kids += 1
                    except Exception:
                        pass
                if _killed_kids:
                    logger.info(
                        f'沙箱放行链路：自爆风险守护进程已清理 {_killed_kids} 个 '
                        f'PID={pid} {display}')
                # 3) 兜底：按树再清一次（限时 1s，失败不阻断）
                if pid > 0:
                    try:
                        _kids = self._kill_process_tree_best_effort(
                            pid, timeout=1.0)
                        if _kids > 0:
                            logger.info(
                                f'沙箱放行链路：自爆风险进程补杀 {_kids} 个子进程 '
                                f'PID={pid} {display}')
                    except Exception as e_kids:
                        logger.warning(
                            f'沙箱放行链路：自爆风险子进程清理异常: {e_kids}')
                # 4) 终止完成后立即校验引导扇区并回滚（不等轮询窗口）
                try:
                    _vf = getattr(self, '_mbr_verify_after_kill_hook', None)
                    if _vf is not None and callable(_vf):
                        _vf(str(exe))
                except Exception as e_vf:
                    logger.warning(f'沙箱放行链路：引导扇区即时校验失败: {e_vf}')
        except Exception as e_sd:
            logger.warning(f'沙箱放行链路：自爆预分析异常，按无风险继续: {e_sd}')

        if kill_ok:
            logger.info(f'沙箱放行链路：已直接终止 PID={pid} {display}，原因: {reason}')
        else:
            logger.warning(f'沙箱放行链路：直接终止失败 PID={pid}，'
                           f'立即执行完整终止链路（不进后台）')
            # 【关键修复】紧急终止（仅 TerminateProcess）失败时，必须在这里
            # 同步补齐完整 kill_process 链路（psutil 树 → SeDebug 提权 →
            # taskkill /F /T → 驱动 ZwTerminateProcess）。此前该补杀放在
            # _sandbox_worker 里且被 `and kill_ok` 短路 → 进程没被杀就进入
            # 沙箱分析，verdict=clean 时直接放行 → "病毒活了但 PSLS 以为
            # 已经拦住"（用户观察到：提示框不断弹出、主破坏程序尚未运行、
            # 沙箱启动却无法终止进程）。
            try:
                if pid > 0:
                    _tree_ok = self.kill_process(pid, force=True, kill_tree=True,
                                                 timeout=5.0)
                    if _tree_ok:
                        kill_ok = True
                        logger.info(
                            f'沙箱放行链路：完整终止链路成功 PID={pid} '
                            f'{display}（代码路径=阶段1补杀）')
                    else:
                        # 完整链路仍失败 → 先驱动按路径终止该 exe 的全部实例；
                        # 驱动不可用 / 未加载 / 失败时，回退用户态按路径枚举
                        # 逐个终止（病毒常在运行中派生多个同 exe 进程弹提示框，
                        # 只按 pid 杀一个会漏）。
                        logger.warning(
                            f'沙箱放行链路：完整终止链路仍失败 PID={pid}，'
                            f'尝试按路径终止该 exe 的全部实例 exe={exe}')
                        try:
                            if self._driver_terminate_by_path_hook:
                                if self._driver_terminate_by_path_hook(exe):
                                    kill_ok = True
                                    logger.info(
                                        f'沙箱放行链路：驱动按路径终止成功 '
                                        f'PID={pid} {display}')
                        except Exception as e_drv:
                            logger.warning(
                                f'沙箱放行链路：驱动按路径终止异常 {exe}: {e_drv}')
                        if not kill_ok:
                            # 驱动兜底失败/不可用 → 用户态按路径枚举终止
                            # 所有同 exe 实例（不依赖内核驱动）
                            try:
                                _remain = self._terminate_image_instances(exe)
                                if _remain == 0:
                                    kill_ok = True
                                    logger.info(
                                        f'沙箱放行链路：用户态按路径补杀成功 '
                                        f'PID={pid} {display}')
                                else:
                                    logger.warning(
                                        f'沙箱放行链路：用户态按路径补杀后仍有 '
                                        f'{_remain} 个同 exe 实例存活 PID={pid}')
                            except Exception as e_img:
                                logger.warning(
                                    f'沙箱放行链路：用户态按路径补杀异常 '
                                    f'{exe}: {e_img}')
            except Exception as e_full:
                logger.warning(f'沙箱放行链路：阶段1完整终止异常 PID={pid}: {e_full}')

        # 对于脚本文件，尝试终止其子进程树（防止脚本已启动的子进程继续运行）
        if HAS_PSUTIL and pid > 0:
            try:
                children_killed = self._kill_process_tree_best_effort(pid, timeout=1.0)
                if children_killed > 0:
                    logger.info(
                        f'沙箱放行链路：已终止 {children_killed} 个子进程'
                        f'（脚本: {display}）')
            except Exception:
                pass

        # 自爆风险：主进程已终止 → 立即校验引导扇区并回滚（不等 0.25s 轮询），
        # 收窄"病毒死亡瞬间写坏 MBR → 检测"的窗口。
        if self_destruct_risk:
            try:
                _vf = getattr(self, '_mbr_verify_after_kill_hook', None)
                if _vf is not None and callable(_vf):
                    _vf(str(exe))
            except Exception as e_vf:
                logger.warning(f'沙箱放行链路：终止后引导扇区校验异常: {e_vf}')

        # ---- 阶段 1.5：预复制沙箱运行副本（必须在加锁前！）----
        # 阶段1 之后会对 exe 加 share=0 独占锁；若把 exe 原文件直接交给
        # SandboxAnalyzer，其内部 copy2 会因自锁失败，历史上又回退"直启
        # 原文件"，必然触发 ERROR_SHARING_VIOLATION(32) → 沙箱失败 → 上游
        # 误判"启动失败"而强制隔离用户程序。
        # 这里在加锁前先复制一份运行副本，之后沙箱只分析副本（源文件仍被
        # 独占锁占用，用户无法在分析期间启动）。
        precopy_dir = None
        precopy_path = None
        try:
            import tempfile
            import shutil as _shutil
            precopy_dir = tempfile.mkdtemp(prefix='psls_sandbox_')
            precopy_ext = os.path.splitext(exe)[1].lower() or '.exe'
            precopy_path = os.path.join(precopy_dir, 'sample' + precopy_ext)
            _shutil.copy2(exe, precopy_path)
            logger.info(f'沙箱拦截：已预复制运行副本 {precopy_path}')
        except Exception as e_copy:
            logger.warning(f'沙箱拦截：预复制运行副本失败，尝试直接分析原文件: {e_copy}')
            precopy_dir = None
            precopy_path = None

        # 立即锁定 exe 源文件（占用），全程持有直至处置完成
        exe_lock_key = None
        locked_fh = None
        try:
            from engine.realtime_monitor import _lock_file_exclusive
            def _norm_key(p: str) -> str:
                try:
                    return os.path.normcase(os.path.abspath(p))
                except Exception:
                    return ''
            exe_lock_key = _norm_key(exe)
            if exe_lock_key:
                locked_fh = _lock_file_exclusive(exe, timeout_sec=1.0)
                if locked_fh is not None:
                    with self._sandbox_locks_lock:
                        self._sandbox_locks[exe_lock_key] = (locked_fh, time.time())
        except Exception as e_lock:
            logger.warning(f'沙箱拦截锁定 exe 失败 {exe}: {e_lock}')

        # ---- 阶段 2：后台线程跑沙箱，然后 Resume / Kill ----
        _waiting_threads = getattr(self, '_sandbox_waiting_count', 0)
        if _waiting_threads >= self._sandbox_queue_limit:
            # 排队已满：进程已终止，需释放源文件锁（放行后用户可重新启动）
            logger.warning(
                f'沙箱放行链路：排队已满 ({_waiting_threads}/{self._sandbox_queue_limit})，'
                f'直接放行 {display}（释放 exe 锁）')
            if locked_fh is not None:
                try:
                    self.release_sandbox_lock(exe)
                except Exception:
                    pass
            if precopy_dir:
                try:
                    import shutil
                    shutil.rmtree(precopy_dir, ignore_errors=True)
                except Exception:
                    pass
            return

        def _sandbox_worker():
            sem_acquired = False
            # analyzing 豁免：精确路径 + 目录前缀（登记 work_dir）；在
            # analyzer.analyze 之前 mark，在 finally 统一清除。
            # 必须在 _sandbox_worker 开头置 None，避免 sem 阶段异常时 finally
            # 引用 sandbox_analyzing_key 报 UnboundLocalError。
            sandbox_analyzing_key = None
            sandbox_dir_key = None   # _mark_sandbox_analyzing_dir 返回的规范化前缀
            sandbox_work_dir = None  # 实际创建的沙箱工作目录（finally 里还需清理）
            self._sandbox_waiting_count = getattr(self, '_sandbox_waiting_count', 0) + 1
            try:
                if not self._sandbox_sem.acquire(timeout=60.0):
                    logger.warning(
                        f'沙箱放行链路：等待沙箱槽位超时 (60s)，放行 {display}')
                    if not fallback_to_kill_mode:
                        self._resume_suspended_process(pid)
                    # kill-then-ask：进程已终止，此处放弃处置 → 释放阶段1的
                    # exe 独占锁，用户可重新启动。
                    try:
                        self.release_sandbox_lock(exe)
                    except Exception:
                        pass
                    return
                sem_acquired = True
            finally:
                self._sandbox_waiting_count -= 1

            try:
                # 回退旧模式（kill-then-ask）→ 后台无条件再清理一次进程树。
                # 不依赖 `kill_ok`（阶段1紧急终止可能失败但进程实际上已经
                # 被完整链路杀掉，也可能阶段1全部失败而进程仍在运行派生
                # 提示框）。此处确认 PID 已退出，未退出则再补杀 + 按路径
                # 终止同 exe 全部实例（病毒常多进程弹提示框，只杀 pid 漏）。
                if fallback_to_kill_mode and pid > 0:
                    try:
                        _still_alive = False
                        try:
                            import psutil as _psutil
                            _still_alive = (
                                _psutil.pid_exists(pid)
                                and _psutil.Process(pid).status()
                                != _psutil.STATUS_ZOMBIE)
                        except Exception:
                            _still_alive = False
                        if _still_alive:
                            logger.warning(
                                f'沙箱放行链路：后台确认 PID={pid} 仍存活，'
                                f'补杀进程树 + 同 exe 实例')
                        # 无条件补杀：先树，再按路径兜底
                        self.kill_process(pid, force=True, kill_tree=True, timeout=3.0)
                        if _still_alive and not _psutil.pid_exists(pid):
                            logger.info(
                                f'沙箱放行链路：后台补杀成功 PID={pid}')
                        elif _still_alive:
                            # 树杀失败 → 先按路径清掉同 exe 平行实例（病毒
                            # 多进程弹提示框，pid 树漏平行实例），再驱动兜底
                            logger.warning(
                                f'沙箱放行链路：后台补杀仍失败 PID={pid}，'
                                f'尝试按路径终止 exe={exe}')
                            try:
                                self._terminate_image_instances(exe)
                            except Exception as e_img:
                                logger.warning(
                                    f'沙箱放行链路：后台用户态按路径补杀异常: '
                                    f'{e_img}')
                            drv_ok = False
                            if self._driver_terminate_by_path_hook:
                                try:
                                    drv_ok = bool(
                                        self._driver_terminate_by_path_hook(exe))
                                    if drv_ok:
                                        logger.info(
                                            f'沙箱放行链路：驱动按路径终止成功 '
                                            f'exe={exe}')
                                except Exception as e_drv:
                                    logger.warning(
                                        f'沙箱放行链路：后台驱动按路径终止异常: '
                                        f'{e_drv}')
                    except Exception as e:
                        logger.debug(f'后台清理进程树异常: {e}')

                # 自爆风险：后台补杀完成后再次校验引导扇区并回滚（阶段1
                # 主杀与后台补杀都在后台线程异步执行，这里兜底收口）。
                if self_destruct_risk:
                    try:
                        _vf2 = getattr(self, '_mbr_verify_after_kill_hook', None)
                        if _vf2 is not None and callable(_vf2):
                            _vf2(str(exe))
                    except Exception:
                        pass

                logger.info(f'沙箱放行链路：开始分析 {display} ({exe})')

                # --- analyzing 精确路径豁免登记（原 exe，用于 copy 失败回退到直启场景）---
                # TTL = max(沙箱超时 15s + 分析初始化 5s) * 2；异常时 finally 清。
                sandbox_analyzing_key = self._mark_sandbox_analyzing(
                    exe, ttl_seconds=60)

                try:
                    from engine.sandbox_analyzer import SandboxAnalyzer, SandboxConfig
                    import tempfile
                except ImportError as e:
                    logger.error(f'沙箱放行链路：SandboxAnalyzer 导入失败: {e}')
                    if not fallback_to_kill_mode:
                        self._resume_suspended_process(pid)
                    # kill-then-ask：无法分析 → 释放阶段1的 exe 独占锁，
                    # 交由拦截弹窗告知用户手动处置（隔离/删除/放行）。
                    try:
                        self.release_sandbox_lock(exe)
                    except Exception:
                        pass
                    self._emit_sandbox_block(display, exe, reason,
                                             verdict='error',
                                             error=f'SandboxAnalyzer 不可用: {e}')
                    return

                config = SandboxConfig()
                config.timeout = 15
                # 沙箱后端选择：auto（首选 Sandboxie，不可用回退 AppContainer）
                config.backend = getattr(self, 'sandbox_backend', 'auto')

                # ---【关键修复】显式创建沙箱工作目录，提前登记前缀豁免 ---
                # SandboxAnalyzer 默认会自己 mkdtemp(prefix='psls_sandbox_')，
                # 但那时我们已错过了 ETW 事件窗口；这里自己创建并赋值给
                # config.work_dir 保证 analyzer.analyze 只在此目录下复制副本。
                # 若阶段1.5 已预复制运行副本，直接复用其目录（副本与后续
                # sample 副本同处一目录，一次前缀豁免全部覆盖）。
                # TTL = 90s（沙箱超时 15s + 启动/等待 15s + 行为监控窗口 60s）。
                try:
                    if precopy_dir:
                        sandbox_work_dir = precopy_dir
                    else:
                        sandbox_work_dir = tempfile.mkdtemp(prefix='psls_sandbox_')
                    config.work_dir = sandbox_work_dir
                    sandbox_dir_key = self._mark_sandbox_analyzing_dir(
                        sandbox_work_dir, ttl_seconds=90)
                except Exception as e_dir:
                    logger.warning(
                        f'沙箱放行链路：预测 work_dir 登记失败（降级兜底 psls_sandbox_ 通配仍会覆盖）: '
                        f'{e_dir}')
                    sandbox_work_dir = None

                analyzer = SandboxAnalyzer(config)
                # Sandboxie 后端启动盒内进程后回调盒内 PID，登记豁免防快杀
                try:
                    analyzer.on_sandbox_pids = self._mark_sandbox_target_pids
                except Exception:
                    pass

                # 分析目标优先用预复制运行副本（源文件被 share=0 锁占用，
                # 直接传 exe 会导致 analyze 内 copy2 失败；副本自身可正常
                # 复制/启动，绕开共享冲突）。预复制失败时兜底原文件。
                analysis_source = precopy_path or exe

                # 分析开始 → 通知 bridge 显示"软件分析室"进度窗口。此后
                # analyze 成功/异常两条路径都必须配对的 _on_sandbox_analysis_done
                # 关闭窗口，否则窗口会残留。
                self._emit_sandbox_analysis_start(exe)

                def _sandbox_progress_cb(stage: str, percent: float):
                    # analyze 在 _sandbox_worker 子线程调用，转发给 bridge 后
                    # 由 bridge 内部信号切回主线程更新窗口。
                    self._emit_sandbox_analysis_progress(stage, percent)

                # 上下文信任先验 → 传入 analyze 作为调查先验（仅降分数型
                # 判定，一票否决硬证据不被信任豁免，见 sandbox_analyzer）。
                _ct_prior = 0
                if context_trust:
                    try:
                        if context_trust.get('mitigate'):
                            _ct_prior = int(context_trust.get('trust') or 0)
                        else:
                            _ct_prior = 0
                    except Exception:
                        _ct_prior = 0
                result = analyzer.analyze(
                    analysis_source,
                    on_progress=_sandbox_progress_cb,
                    context_trust=_ct_prior,
                )
                verdict = result.get('verdict', 'error')
                score = result.get('score', 0)
                error_msg = result.get('error', '')
                duration = result.get('duration', 0.0)

                # ---【PID 维度豁免】把 analyzer 启动的目标 PID（沙箱被测进程）
                # 登记进 _sandbox_target_pids；后续其 CreateProcess 的子进程
                # （payload.exe 等即便落地到用户目录 AppData/Local/Temp 下）
                # 也能通过 parent_pid 命中豁免，不会二次进入沙箱。
                target_pid = getattr(analyzer, '_target_pid', 0) or 0
                if isinstance(target_pid, int) and target_pid > 0:
                    self._mark_sandbox_target_pid(target_pid, ttl_seconds=90)
                # 同时记录 analyzer._process_tree 中的 PIDs（如果存在），
                # 覆盖 psutil 扫描到的直接子进程；此操作 best-effort。
                ptree = getattr(analyzer, '_process_tree', None)
                if isinstance(ptree, dict):
                    def _walk_ptree(node, depth=0):
                        if depth > 5:
                            return
                        if isinstance(node, dict):
                            cpid = node.get('pid')
                            if isinstance(cpid, int) and cpid > 0:
                                self._mark_sandbox_target_pid(cpid, ttl_seconds=90)
                            for child in node.get('children', []) or []:
                                _walk_ptree(child, depth + 1)
                        elif isinstance(node, (list, tuple)):
                            for c in node:
                                _walk_ptree(c, depth + 1)
                    try:
                        _walk_ptree(ptree)
                    except Exception:
                        pass

                logger.info(f'沙箱放行链路：{display} verdict={verdict}, '
                            f'score={score}, duration={duration:.1f}s, '
                            f'target_pid={target_pid}')

                # 分析完成 → 立即通知 bridge 关闭分析进度窗口。
                # 必须排在 _emit_sandbox_release_request / _emit_sandbox_block
                # 之前发射（Qt 跨线程队列保证先入队先处理），确保先关分析窗口、
                # 再显示放行/拦截弹窗。
                self._emit_sandbox_analysis_done(exe, verdict)

                if verdict == 'clean':
                    # 写入内存缓存（避免下次启动重复挂起）
                    try:
                        mtime = os.path.getmtime(exe)
                        with self._launch_scan_lock:
                            self._launch_scan_cache[exe] = (mtime, 'clean', time.time())
                    except Exception:
                        pass

                    # ---- 沙箱判定安全 → 记录"沙箱放行信任" ----
                    # 用户要求：沙箱判定某程序安全后，下一次处理不再经过沙箱。
                    # 注意这是独立于 whitelist 的信任（sandbox_trust 表），
                    # 只让进程启动判定跳过沙箱；文件防篡改/实时扫描/引擎扫描等
                    # 其他模块不受影响、继续监测该文件。不写全局白名单，否则
                    # 会把放行扩散到所有模块（除非需要整体免检才该加白名单）。
                    try:
                        if self._signature_db:
                            import hashlib as _hl
                            _h = _hl.sha256()
                            with open(exe, 'rb') as _f:
                                for _chunk in iter(lambda: _f.read(65536), b''):
                                    _h.update(_chunk)
                            _fhash = _h.hexdigest()
                            if not self._signature_db.is_sandbox_trusted(_fhash):
                                self._signature_db.add_sandbox_trust(
                                    _fhash, reason='沙箱判定安全（clean）→ 跳过二次进沙箱')
                    except Exception:
                        pass

                    # ---- 阶段 3a：沙箱验证通过 ----
                    # 新链路（Suspend 成功时）：直接 ResumeThread 恢复原进程
                    # → 绝不 subprocess.Popen 新进程，避免「PSLS 启动安装包」bug
                    if not fallback_to_kill_mode:
                        resume_ok = self._resume_suspended_process(pid)
                        if resume_ok:
                            logger.info(f'沙箱放行链路：{display} clean，已恢复原挂起进程 PID={pid}')
                        else:
                            logger.info(
                                f'沙箱放行链路：{display} clean，恢复挂起进程失败，'
                                '视为已由用户手动处理或自行退出')
                    else:
                        # kill-then-ask：释放 exe 锁前，先确认目标进程已退出。
                        # 若经过阶段1补杀 + 后台补杀仍未杀死（极端权限场景），
                        # 释放锁会让用户"放行一个还在跑的进程"——病毒先弹
                        # 提示框、主破坏未运行的情况会继续。确认已死才放行。
                        _clean_proc_alive = False
                        try:
                            if pid > 0:
                                import psutil as _psutil3
                                _clean_proc_alive = (
                                    _psutil3.pid_exists(pid)
                                    and _psutil3.Process(pid).status()
                                    != _psutil3.STATUS_ZOMBIE)
                        except Exception:
                            _clean_proc_alive = True  # 无法确认→保守按存活
                        if _clean_proc_alive:
                            try:
                                self._emergency_kill(pid)
                            except Exception:
                                pass
                            try:
                                if self.kill_process(pid, force=True,
                                                     kill_tree=True,
                                                     timeout=3.0):
                                    _clean_proc_alive = False
                            except Exception:
                                pass
                            if _clean_proc_alive:
                                try:
                                    if self._driver_terminate_by_path_hook:
                                        if self._driver_terminate_by_path_hook(exe):
                                            _clean_proc_alive = False
                                except Exception:
                                    pass
                            if _clean_proc_alive:
                                # 驱动不可用/失败 → 用户态按路径枚举终止同 exe
                                # 全部实例。clean 判定前必须确认全清，否则放行
                                # 一个仍在弹提示框的进程（"沙箱似乎无法终止"）。
                                try:
                                    if self._terminate_image_instances(exe) == 0:
                                        _clean_proc_alive = False
                                except Exception:
                                    pass
                        if _clean_proc_alive:
                            # 全部手段用尽仍存活 → 不释放锁、不放行，转拦截
                            # （让用户手动处理，而不是让进程继续弹提示框）
                            logger.critical(
                                f'沙箱放行链路：{display} 判定 clean 但进程'
                                f' PID={pid} 始终无法终止，转为拦截处理')
                            try:
                                self._emit_sandbox_block(
                                    display, exe, reason,
                                    verdict='suspicious',
                                    score=score,
                                    error='进程无法终止（判定clean但仍在运行）')
                            except Exception:
                                pass
                            return
                        # kill-then-ask：先释放阶段1持有的 exe 独占锁。
                        # 无论用户点击"同意重启"（restartSandboxedProcess 需要
                        # CreateProcess 打开 exe）还是稍后手动双击启动，share=0
                        # 锁都必须已释放，否则重启会因共享冲突失败。
                        try:
                            self.release_sandbox_lock(exe)
                        except Exception:
                            pass
                        # emit release_request 弹窗询问用户是否重启（默认不重启）
                        self._emit_sandbox_release_request(
                            display, exe, reason, saved_cmdline, score)
                else:
                    # ---- 阶段 3b：沙箱验证失败 → 终止 + 隔离 + 弹窗拦截 ----

                    # [修复 1] 立即刷新启动监测 scanning → blocked/quarantined。
                    # 此前活动日志永远停在「拦截待分析…沙箱分析中」，
                    # 用户体感就是"之后就没反应了"。
                    try:
                        final_status_for_launch_monitor = (
                            'blocked' if verdict in ('suspicious', 'error', 'skipped')
                            else 'quarantined'
                        )
                        self._notify_launch_monitoring(
                            pid, display, exe,
                            reason=(
                                f'沙箱判定: {verdict} score={score},'
                                f' error={error_msg or "none"}'
                            ),
                            scan_result=LaunchScanResult(
                                status=final_status_for_launch_monitor,
                                verdict=verdict,
                                score=score,
                                signatures=[
                                    f"Sandbox.{verdict.capitalize()}"
                                ],
                                file_path=exe,
                            ),
                        )
                    except Exception as e_nlm:
                        logger.warning(
                            '沙箱拦截刷新启动监测状态失败: %s', e_nlm)

                    # [修复 2] 确保 exe 独占锁（share=0）已持有 —— kill-then-ask
                    # 下阶段1已锁定 source 文件；若阶段1加锁失败（如被其他进程
                    # 短暂占用），此处补锁，阻止用户在 Terminate 后抢启动。
                    exe_lock_key = None
                    locked_fh = None
                    try:
                        from engine.realtime_monitor import _lock_file_exclusive
                        def _norm_key(p: str) -> str:
                            try:
                                return os.path.normcase(os.path.abspath(p))
                            except Exception:
                                return ''
                        exe_lock_key = _norm_key(exe)
                        with self._sandbox_locks_lock:
                            already_locked = (
                                exe_lock_key in self._sandbox_locks
                            ) if exe_lock_key else False
                        if exe_lock_key and not already_locked:
                            locked_fh = _lock_file_exclusive(exe, timeout_sec=0.3)
                            if locked_fh is not None:
                                with self._sandbox_locks_lock:
                                    self._sandbox_locks[exe_lock_key] = (
                                        locked_fh, time.time(),
                                    )
                    except Exception as e_lock:
                        logger.warning(
                            '沙箱拦截锁定 exe 失败 %s: %s', exe, e_lock)

                    # [修复 3] malware 级通过驱动层 Ring0 强制终止，再用户态兜底
                    try:
                        if (verdict == 'malware'
                                and self._driver_terminate_by_path_hook):
                            try:
                                self._driver_terminate_by_path_hook(exe)
                            except Exception as e_drv:
                                logger.warning(
                                    '沙箱驱动强制终止失败 %s: %s', exe, e_drv)
                    except Exception:
                        pass

                    # 【关键修复】verdict!=clean → 一律再次确认目标已终止。
                    # 此前 `if not fallback_to_kill_mode` 在 kill-then-ask 模式
                    # 下恒为 False → 后置的 emergency_kill/kill_process 永不
                    # 执行 → 若阶段1与后台补杀都失败，病毒进程至今仍存活，
                    # 这里却直接隔离文件：用户看到"隔离成功"但进程还在跑
                    # （正是"先弹提示框 → 杀不掉 → 继续弹"的观感）。
                    try:
                        if pid > 0:
                            try:
                                import psutil as _psutil2
                                _target_final_alive = (
                                    _psutil2.pid_exists(pid)
                                    and _psutil2.Process(pid).status()
                                    != _psutil2.STATUS_ZOMBIE)
                            except Exception:
                                _target_final_alive = None  # 无法确认→按存活处置
                            if _target_final_alive is not False:
                                self._emergency_kill(pid)
                                try:
                                    self.kill_process(pid, force=True,
                                                      kill_tree=True,
                                                      timeout=3.0)
                                except Exception:
                                    pass
                                # 仍可能存活 / 存在同 exe 平行实例（弹提示框
                                # 场景常见多实例）→ 按路径全清 + 驱动兜底
                                try:
                                    self._terminate_image_instances(exe)
                                except Exception:
                                    pass
                                if self._driver_terminate_by_path_hook:
                                    try:
                                        self._driver_terminate_by_path_hook(exe)
                                    except Exception:
                                        pass
                    except Exception:
                        pass

                    # ---- 关键：隔离前先释放 exe 独占锁 ----
                    # 阶段1（或上方补锁）持有的都是 share=0 独占句柄；
                    # quarantine_file 内部要做 prep_for_remove / encrypt /
                    # shutil.move / os.remove / os.rename 四步，
                    # 若 PSLS 自己还以 share=0 占着句柄，这四步都会失败
                    # → 用户看到"拦截了但没隔离"。所以这里必须先释放。
                    # 注意：本地 locked_fh 可能为 None（阶段1已持锁时补锁返回
                    # None），release_sandbox_lock 按路径查表释放，不依赖局部变量。
                    try:
                        self.release_sandbox_lock(exe)
                    except Exception:
                        pass

                    quarantine_ok = False
                    if self._quarantine_manager:
                        try:
                            qr = self._quarantine_manager.quarantine_file(
                                exe,
                                reason=(
                                    f"沙箱自动隔离: verdict={verdict},"
                                    f" score={score}, reason={reason}"
                                ),
                                malware_name=f"Sandbox.{verdict.capitalize()}",
                            )
                            if qr is True:
                                quarantine_ok = True
                                logger.info(
                                    f"沙箱已隔离文件: {exe} (verdict={verdict})"
                                )
                            elif qr == 'duplicate':
                                logger.info(
                                    f"沙箱：文件已在隔离区，跳过重复隔离: {exe}"
                                )
                            elif qr == 'exempted':
                                logger.info(f"沙箱：文件已豁免，跳过: {exe}")
                        except Exception as e:
                            logger.warning(f"沙箱隔离失败 {exe}: {e}")

                    # 处置完成（无论成功/失败、有无隔离管理器）都释放 exe 锁。
                    # 隔离成功则原文件已挪走；失败则交给后续处置 UI 自行重锁。
                    if exe_lock_key:
                        try:
                            self.release_sandbox_lock(exe)
                        except Exception:
                            pass

                    # 隔离失败兜底：重新加锁（阻止用户在处置 UI 出现前再启动）。
                    # 注意：若 quarantine 成功，原 exe 通常已被挪走/改名，重新加锁
                    # 会返回 None 而不阻塞。
                    if not quarantine_ok:
                        try:
                            from engine.realtime_monitor import _lock_file_exclusive
                            new_fh = _lock_file_exclusive(exe, timeout_sec=0.3)
                            if new_fh is not None and exe_lock_key:
                                with self._sandbox_locks_lock:
                                    self._sandbox_locks[exe_lock_key] = (
                                        new_fh, time.time(),
                                    )
                        except Exception as e_relock:
                            logger.warning(
                                '沙箱隔离失败后重锁 exe 失败 %s: %s',
                                exe, e_relock)

                    self._emit_sandbox_block(
                        display, exe, reason,
                        verdict=verdict,
                        score=score,
                        error=error_msg,
                        quarantined=quarantine_ok,
                    )

            except Exception as e:
                logger.error(f'沙箱放行链路异常 {display}: {e}', exc_info=True)
                # 若已显示分析窗口，必须先关闭（analyze 抛异常时无 verdict）
                if exe:
                    self._emit_sandbox_analysis_done(exe, 'error')
                # 若仍处于挂起状态就恢复进程（避免用户程序僵死）
                if not fallback_to_kill_mode:
                    self._resume_suspended_process(pid)
                # 异常兜底：释放阶段1的 exe 独占锁，避免文件被永久占用
                # （用户可重新启动，或在拦截弹窗中手动隔离/删除）。
                try:
                    self.release_sandbox_lock(exe)
                except Exception:
                    pass
                self._emit_sandbox_block(display, exe, reason,
                                         verdict='error',
                                         error=str(e))
            finally:
                # analyzing 豁免必须在 finally 清除（精确路径 + 目录前缀），
                # 保证 clean / not clean / exception 三种分支都不会让条目卡住
                # 超过 TTL（TTL 只是极端兜底）。
                try:
                    if sandbox_analyzing_key:
                        self._unmark_sandbox_analyzing(sandbox_analyzing_key)
                except Exception:
                    pass
                try:
                    if sandbox_dir_key:
                        self._unmark_sandbox_analyzing_dir(sandbox_dir_key)
                except Exception:
                    pass
                # 清理沙箱工作目录/预复制副本。analyze 因 config.work_dir 非 None
                # 不自动清理目录；precopy_dir 与 sandbox_work_dir 可能指向同一目录，
                # 用集合去重（None 安全）。
                for _dirty in {precopy_dir, sandbox_work_dir}:
                    if _dirty:
                        try:
                            import shutil
                            shutil.rmtree(_dirty, ignore_errors=True)
                        except Exception:
                            pass
                if sem_acquired:
                    self._sandbox_sem.release()
                # 调用 on_done 回调（如脚本去重的 _unmark_script_analyzing）
                if on_done:
                    try:
                        on_done()
                    except Exception:
                        pass

        t = threading.Thread(target=_sandbox_worker, daemon=True,
                             name=f'SandboxRelease-{display[:25]}')
        t.start()

    def _restart_original_process(self, exe: str,
                                   cmdline: Optional[List[str]],
                                   display: str) -> bool:
        """沙箱判定 clean 后，用原命令行重启进程（放行）

        Returns:
            True 重启成功；False 启动失败
        """
        try:
            if cmdline and len(cmdline) >= 2:
                # 有完整命令行：重建命令行参数（避免 PowerShell 路径解析问题）
                creation_flags = 0x08000000  # CREATE_NO_WINDOW
                if sys.platform == 'win32':
                    proc = subprocess.Popen(
                        cmdline,
                        close_fds=True,
                        creationflags=creation_flags,
                    )
                else:
                    proc = subprocess.Popen(cmdline, close_fds=True)
                logger.info(f'沙箱放行链路：已放行 {display} (PID={proc.pid}) '
                            f'— 沙箱判定 clean')
                return True
            else:
                # 只有 exe 路径：直接启动
                creation_flags = 0x08000000
                if sys.platform == 'win32':
                    proc = subprocess.Popen(
                        [exe],
                        close_fds=True,
                        creationflags=creation_flags,
                    )
                else:
                    proc = subprocess.Popen([exe], close_fds=True)
                logger.info(f'沙箱放行链路：已放行 {display} (PID={proc.pid}) '
                            f'— 沙箱判定 clean（无命令行参数）')
                return True
        except Exception as e:
            logger.error(f'沙箱放行链路：重启进程失败 {display}: {e}')
            # 重启失败 → 不放行，弹窗告知用户文件本来想放行但无法启动
            self._emit_sandbox_block(display, exe, '重启失败',
                                     verdict='error',
                                     error=f'沙箱判定安全，但重启进程失败: {e}')
            return False

    def _emit_sandbox_block(self, name: str, exe: str, reason: str,
                             verdict: str = 'malware',
                             score: int = 0,
                             error: str = '',
                             quarantined: bool = False):
        """沙箱拦截回调 — 自动隔离 + 通知 bridge 弹窗 + 事件记录"""
        # 记录事件
        self._add_event('sandbox_block', 0, name, 'threat',
                        f'沙箱拦截: verdict={verdict}, score={score}, '
                        f'quarantined={quarantined}, reason={reason}',
                        exe)

        # 通过 on_sandbox_block 回调通知 bridge 弹窗
        if self._on_sandbox_block:
            try:
                self._on_sandbox_block({
                    'type': 'sandbox_block',
                    'name': name,
                    'path': exe,
                    'reason': reason,
                    'verdict': verdict,
                    'score': score,
                    'error': error,
                    'quarantined': quarantined,
                })
            except Exception as e:
                logger.error(f'on_sandbox_block 回调异常: {e}')
        else:
            logger.warning(f'on_sandbox_block 未注册，无法弹窗拦截 {name}')

    def _emit_sandbox_release_request(self, name: str, exe: str, reason: str,
                                       cmdline: Optional[List[str]],
                                       score: int = 0,
                                       event_desc: Optional[str] = None,
                                       kind: str = 'clean'):
        """请求用户确认是否放行/重启进程

        通过 on_sandbox_release_request 回调通知 bridge 显示询问弹窗：
        - 用户同意 → bridge 调用 restart_sandboxed_process()
        - 5秒超时未操作 → 不重启
        - 用户拒绝 → 不重启

        event_desc: 自定义事件描述（默认按"沙箱判定安全"文案；大文件未沙箱
        分析等场景传入自己的说明，避免文案与实际原因不符）。
        kind: 放行原因类别 —— 'clean'（沙箱判定安全）或 'oversize'
        （文件过大未分析）。bridge 依此渲染不同语义的弹窗：'clean' 显示
        "判定安全"绿色放行窗，'oversize' 显示警示窗，避免把"未分析的大文件"
        误显示成"判定安全（评分:0）"而诱导用户放行。
        """
        self._add_event('sandbox_release', 0, name, 'info',
                        (event_desc or
                         f'沙箱判定安全，等待用户确认是否重启: score={score}, reason={reason}'),
                        exe)

        if self._on_sandbox_release_request:
            try:
                self._on_sandbox_release_request({
                    'type': 'sandbox_release_request',
                    'name': name,
                    'path': exe,
                    'reason': reason,
                    'cmdline': cmdline,
                    'score': score,
                    'kind': kind,
                })
            except Exception as e:
                logger.error(f'on_sandbox_release_request 回调异常: {e}')
        else:
            # 回调未注册，降级为不重启
            logger.info(f'沙箱判定 {name} 安全，但 release 回调未注册，不重启')

    def _emit_sandbox_analysis_start(self, exe: str):
        """沙箱分析开始 → 通知 bridge 显示"软件分析室"进度窗口。

        在 _sandbox_worker 子线程调用；bridge 内部通过信号切回主线程创建 QWidget。
        """
        if not self._on_sandbox_analysis_start:
            return
        try:
            self._on_sandbox_analysis_start(exe)
        except Exception as e:
            logger.warning(f'on_sandbox_analysis_start 回调异常: {e}')

    def _emit_sandbox_analysis_progress(self, stage: str, percent: float):
        """沙箱分析进度 → 通知 bridge 更新分析窗口。"""
        if not self._on_sandbox_analysis_progress:
            return
        try:
            self._on_sandbox_analysis_progress(stage, percent)
        except Exception as e:
            logger.warning(f'on_sandbox_analysis_progress 回调异常: {e}')

    def _emit_sandbox_analysis_done(self, exe: str, verdict: str):
        """沙箱分析完成 → 通知 bridge 关闭分析窗口。

        verdict 仅用于日志/调试，关闭动作不区分 verdict。
        """
        if not self._on_sandbox_analysis_done:
            return
        try:
            self._on_sandbox_analysis_done(exe, verdict or 'error')
        except Exception as e:
            logger.warning(f'on_sandbox_analysis_done 回调异常: {e}')

    def restart_sandboxed_process(self, exe: str,
                                   cmdline: Optional[List[str]]) -> bool:
        """重启被沙箱终止的进程（用户同意后由 bridge 调用）

        Args:
            exe: 可执行文件路径
            cmdline: 原始命令行参数列表

        Returns:
            True 重启成功, False 失败
        """
        display = os.path.basename(exe) if exe else '未知进程'
        # 用户明确批准重启/放行 → 解除"已拦截路径"黑名单，否则重启会被
        # _kill_blocked_relaunch 立即再杀（用户放行被反复拦截）。
        self._unmark_exe_blocked(exe)
        return self._restart_original_process(exe, cmdline, display)

    # ---- 视觉恶搞检测（VisualPrankDetector）联动 ----

    def _register_visual_prank(self, pid: int, exe: str, name: str,
                               cmdline: Optional[List[str]]):
        """将非信任 PE 注册到视觉恶搞检测观察集合（异常安全的薄封装）。

        在每个"发往 _sandbox_then_release 的非信任分支"命中前调用；
        检测器会持续审计该进程的弹窗/图标/壁纸/设置改动行为。
        """
        if not self._visual_prank_observer or not exe or pid <= 0:
            return
        try:
            self._visual_prank_observer(pid, exe, name, cmdline)
        except Exception as e:
            logger.debug(f'注册视觉恶搞观察对象失败 PID={pid}: {e}')

    def _is_prank_trusted(self, exe: str) -> bool:
        """判断 exe 是否在近期被用户在视觉恶搞询问中标记为信任。

        信任后 30 分钟窗口内同一文件（mtime 不变）再次启动直接放行，
        不重复拦截（用户点击"信任并重启"的语义：这是可信程序）。
        """
        if not exe:
            return False
        try:
            key = os.path.normcase(os.path.abspath(exe))
            mtime = os.path.getmtime(exe)
        except Exception:
            return False
        now = time.time()
        with self._prank_trusted_lock:
            rec = self._prank_trusted.get(key)
            if not rec:
                return False
            t_ts, t_mtime = rec
            if now - t_ts > 1800 or t_mtime != mtime:
                self._prank_trusted.pop(key, None)
                return False
            return True

    def mark_prank_trusted(self, exe: str) -> None:
        """用户点击"信任"后：写入信任缓存 + 启动扫描缓存（clean）。

        这样被信任的程序后续启动既不进视觉恶搞观察、也不再被
        _check_new_process 拦截。同时清理该 exe 的视觉恶搞独占锁。
        """
        if not exe:
            return
        try:
            key = os.path.normcase(os.path.abspath(exe))
            mtime = os.path.getmtime(exe)
        except Exception:
            return
        try:
            with self._prank_trusted_lock:
                self._prank_trusted[key] = (time.time(), mtime)
        except Exception:
            pass
        try:
            with self._launch_scan_lock:
                self._launch_scan_cache[exe] = (mtime, 'clean', time.time())
        except Exception:
            pass
        # 解除视觉恶搞询问期间的 exe 独占锁（信任→重启需要可写打开）
        try:
            self.release_prank_lock(exe)
        except Exception:
            pass
        logger.info(f'视觉恶搞检测：用户信任并重启 {exe}，已写入信任缓存')

    def terminate_prank_process(self, exe: str, pid: int = 0) -> bool:
        """视觉恶搞命中后的全链终止（阶段1：先杀进程）。

        链：紧急终止(pid) → kill_process 树杀 → 驱动按路径 → 用户态
        _terminate_image_instances（同 exe 全部实例）。与 _sandbox_then_release
        阶段1共用同一套终止链路，保证"先杀后问"真正先杀掉。
        """
        kill_ok = False
        try:
            if pid > 0:
                if self._refuse_self_kill(pid, 'terminate_prank_process'):
                    pid = 0
                if pid > 0:
                    kill_ok = self._emergency_kill(pid)
            if pid > 0:
                try:
                    if self.kill_process(pid, force=True, kill_tree=True,
                                         timeout=5.0):
                        kill_ok = True
                except Exception:
                    pass
            # 按路径清同 exe 全部实例（覆盖平行实例 + 杀 pid 失败场景）
            try:
                if self._driver_terminate_by_path_hook:
                    try:
                        if self._driver_terminate_by_path_hook(exe):
                            kill_ok = True
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                if self._terminate_image_instances(exe) == 0:
                    kill_ok = True
            except Exception:
                pass
        except Exception as e:
            logger.warning(f'terminate_prank_process 异常 {exe}: {e}')
        return bool(kill_ok)

    def lock_prank_executable(self, exe: str):
        """询问期间独占锁定被处置 exe（share=0），阻止用户重复启动。

        锁在 mark_prank_trusted（信任重启前）/ release_prank_lock
        （取消/超时/窗口销毁）时释放；180s 绝对兜底。
        """
        if not exe:
            return None
        try:
            from engine.realtime_monitor import _lock_file_exclusive
            key = os.path.normcase(os.path.abspath(exe))
            locked_fh = _lock_file_exclusive(exe, timeout_sec=1.0)
            if locked_fh is not None:
                with self._prank_locks_lock:
                    self._prank_locks[key] = (locked_fh, time.time())
            return locked_fh
        except Exception as e:
            logger.warning(f'lock_prank_executable 失败 {exe}: {e}')
            return None

    def release_prank_lock(self, exe: str) -> bool:
        """释放视觉恶搞询问持有的 exe 独占锁。"""
        if not exe:
            return False
        try:
            key = os.path.normcase(os.path.abspath(exe))
            with self._prank_locks_lock:
                rec = self._prank_locks.pop(key, None)
            if rec:
                try:
                    rec[0].close()
                except Exception:
                    pass
                logger.debug(f'视觉恶搞检测：已释放 {exe} 的独占锁')
                return True
        except Exception:
            pass
        return False

    def restart_prank_process(self, exe: str,
                              cmdline: Optional[List[str]]) -> bool:
        """用户点击"信任并重启"：标记信任 + 重启进程。"""
        self.mark_prank_trusted(exe)
        return self.restart_sandboxed_process(exe, cmdline)

    # ---- 自我保护 ----

    def protect_self(self) -> bool:
        """保护 PSLS 进程不被其他进程终止

        采用多层防护策略（原先的 SetProcessMitigationPolicy 调用参数顺序错误，
        且 ProcessProtectionLevel 并非有效 Mitigation Policy，必然失败）：

        1. 启用正确的进程缓解策略（扩展点禁用，防止旧版 DLL 注入）
        2. 提升 SeDebugPrivilege 特权（用于后续防御操作）
        3. 调整进程优先级（次要手段，使进程更难被抢占）

        注意：用户态保护可被具备 SeDebugPrivilege 的进程绕过，
        真正的内核级保护需要驱动 ObRegisterCallbacks。
        DACL 限制 PROCESS_TERMINATE 的方案会同时阻止 psutil 自身操作，
        因此不采用，文件级保护由 self_protection.py 负责。
        """
        if not HAS_CTYPES or not HAS_PSUTIL:
            return False

        if sys.platform != 'win32':
            return False

        current_pid = os.getpid()
        success_count = 0

        try:
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            # ---- 1. 正确的进程缓解策略 ----
            # ProcessExtensionPointDisablePolicy = 1（禁用旧版扩展点，防止 DLL 注入）
            try:
                if hasattr(kernel32, 'SetProcessMitigationPolicy'):
                    buffer = ctypes.wintypes.DWORD(1)  # 启用
                    kernel32.SetProcessMitigationPolicy(
                        1,  # ProcessExtensionPointDisablePolicy
                        ctypes.byref(buffer),
                        ctypes.sizeof(buffer)
                    )
                    success_count += 1
                    logger.debug('已启用 ProcessExtensionPointDisablePolicy')
            except Exception as e:
                logger.debug(f'设置进程缓解策略失败: {e}')

            # ---- 2. 启用 SeDebugPrivilege ----
            try:
                if self._enable_debug_privilege():
                    success_count += 1
                    logger.debug('已启用 SeDebugPrivilege')
            except Exception as e:
                logger.debug(f'启用 SeDebugPrivilege 失败: {e}')

            # ---- 3. 提升进程优先级 ----
            try:
                proc = psutil.Process(current_pid)
                proc.nice(psutil.HIGH_PRIORITY_CLASS)
                success_count += 1
            except Exception as e:
                logger.debug(f'提升进程优先级失败: {e}')

            # 结果记录
            if success_count > 0:
                self._add_event('self_protect', current_pid, 'psls',
                                'success',
                                f'进程自我保护已启用 ({success_count} 项)')
                with self._stats_lock:
                    self._stats['self_protections'] += 1
                logger.info(f'进程自我保护已启用，成功项数: {success_count}')
                return True
            else:
                self._add_event('self_protect', current_pid, 'psls',
                                'warning', '进程自我保护全部失败')
                return False

        except Exception as e:
            logger.warning(f"设置进程保护失败: {e}")
            return False

    def get_process_info(self, pid: int) -> Optional[dict]:
        """获取指定进程的详细信息"""
        if not HAS_PSUTIL:
            return None
        try:
            proc = psutil.Process(pid)
            return {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': proc.cmdline(),
                'cpu_percent': proc.cpu_percent(),
                'memory_percent': proc.memory_percent(),
                'threads': proc.num_threads(),
                'status': proc.status(),
                'create_time': proc.create_time(),
                'num_fds': proc.num_fds() if hasattr(proc, 'num_fds') else 0,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _handle_credential_tamper(self, pid: int, name: str, exe: str,
                                  cred: dict, offender: dict,
                                  offender_in_box: bool = False) -> None:
        """敏感命令命中处置（BT 兼容版）。

        覆盖两类（见 engine/credential_protection.py 规则表）：
          - 账户/凭据篡改（net user 改密码、net localgroup administrators …）
          - 系统级破坏/防御瘫痪（关防火墙、停安全服务、删卷影、bcdedit、
            takeown+icacls+rmdir 破坏链）

        处置原则：
        * 命令进程（cmd.exe / net.exe / powershell.exe）**总是立即终止** ——
          它执行的命令走系统服务 RPC / 驱动，即使在沙箱盒内也落到真实系统，
          Sandboxie 用户态重定向管不住；
        * 发起进程（非微软官方）只在**不在沙箱盒内**时才终止并上报。
          若它就是正在被分析的样本本体，则不动它：杀掉会让沙箱变成
          error/skipped，违反 BT 要求（沙箱失败 → 不输出任何沙箱数据、
          仅靠 ML 引擎、不改变扫描路结论）。该样本仍由沙箱 + 扫描链路判定。

        Args:
            pid/name/exe: 执行敏感命令的进程
            cred: classify_credential_tamper() 的分类结果
            offender: check_origin_chain() 返回的首个非微软官方节点
            offender_in_box: 发起者是否正在沙箱盒内（= 被分析样本本体）
        """
        opid = int(offender.get('pid') or 0)
        oname = offender.get('name') or f'PID-{opid}'
        oexe = offender.get('exe') or ''
        oreason = offender.get('reason') or ''
        reason = cred.get('reason') or '敏感系统操作'

        if offender_in_box:
            # BT 兼容分支：只掐断破坏命令，不碰被分析的样本本体
            logger.warning(
                f'敏感命令拦截（沙箱盒内）：非微软官方进程发起 '
                f'[{cred.get("kind")}] {reason}；已终止命令进程 {name}(PID={pid})，'
                f'样本本体 {oname}(PID={opid}) 保留给沙箱/扫描链路判定')
            try:
                self._emergency_kill(pid)
            except Exception:
                pass
            self._add_event(
                'sensitive_command_in_sandbox', pid, name or '', 'warn',
                f'沙箱盒内破坏命令被拦截：{reason}（发起者 {oname}）；'
                f'样本本体未终止，保持沙箱判定链路', exe)
            return

        logger.error(
            f'敏感命令拦截：非微软官方进程发起 [{cred.get("kind")}] {reason}；'
            f'命令进程={name}(PID={pid}) 发起者={oname}(PID={opid}) {oexe} {oreason}')

        # 0) 非官方发起者入"已拦截路径"黑名单：它会用 runas 自提权重启，
        #    同路径新实例（新 PID）也必须被 _kill_blocked_relaunch 立即终止。
        if oexe and not self._is_in_psls_sandbox_dir(oexe):
            try:
                self._mark_exe_blocked(oexe, f'敏感命令发起者：{reason}')
            except Exception:
                pass

        # 1) 先终止敏感命令进程（net.exe/…），再终止非官方发起进程
        try:
            self._emergency_kill(pid)
        except Exception:
            pass
        if opid and opid != pid:
            try:
                self._emergency_kill(opid)
            except Exception:
                pass

        # 2) 上报（监测/通知链沿用启动拦截通道；目标指向"非官方发起者"）
        self._notify_launch_monitoring(
            opid or pid, oname, oexe or exe,
            reason=f'非微软官方进程发起敏感操作（{reason}），已终止',
            scan_result=LaunchScanResult(
                status='blocked',
                verdict='malware',
                score=90,
                signatures=['Sensitive.Command.NonMicrosoftOrigin'],
                file_path=oexe or exe,
            ),
        )
        self._add_event(
            'sensitive_command', pid, name or '', 'threat',
            f'敏感命令拦截：{reason}（发起者 {oname}，'
            f'命令 {cred.get("evidence")}）{("；" + oreason) if oreason else ""}',
            oexe or exe)

    def _emergency_kill(self, pid: int) -> bool:
        """紧急终止进程（毫秒级响应，不等 wait）

        专用于可疑进程检测链路：ETW 回调线程中调用，必须 <1ms 返回。

        原理：
        - 直接调用 OpenProcess(PROCESS_TERMINATE) + TerminateProcess
        - TerminateProcess 是 kernel32 API，调用后进程立即被标记为终止
        - CPU 不会再执行该进程的代码（内核级保证）
        - 不调用 wait（不需要确认进程对象 signaled）
        - 不枚举子进程（后台线程再清理进程树）

        与 kill_process 的区别：
        - kill_process: 完整链路（psutil tree + wait + 降级），最坏 14s，用于确认终止
        - _emergency_kill: 仅 TerminateProcess，<1ms，用于紧急拦截

        Args:
            pid: 目标进程 PID

        Returns:
            True 表示 TerminateProcess 调用成功
        """
        # 自身终止守卫：紧急拦截链路同样禁止终止自身/相关进程
        if self._refuse_self_kill(pid, '_emergency_kill'):
            return False

        if not HAS_CTYPES or sys.platform != 'win32':
            # Linux/macOS 回退到 psutil kill（不走 wait）
            if HAS_PSUTIL:
                try:
                    proc = psutil.Process(pid)
                    proc.kill()
                    return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return False
            return False

        try:
            kernel32 = ctypes.windll.kernel32
            PROCESS_TERMINATE = 0x0001

            # OpenProcess + TerminateProcess（显式声明签名）
            kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE
            kernel32.OpenProcess.argtypes = [
                ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD,
            ]
            kernel32.TerminateProcess.restype = ctypes.wintypes.BOOL
            kernel32.TerminateProcess.argtypes = [
                ctypes.wintypes.HANDLE, ctypes.wintypes.UINT,
            ]
            kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]

            handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
            if not handle:
                err = ctypes.get_last_error()
                # ERROR_INVALID_PARAMETER (87) = 进程不存在，视为成功
                if err == 87:
                    return True
                logger.debug(f'_emergency_kill: OpenProcess 失败 PID={pid} err={err}')
                # 权限不足(5)/受保护进程 → 回退内核驱动终止
                if err == 5:
                    logger.debug(f'_emergency_kill: 权限不足 PID={pid}，回退内核驱动终止')
                    if self._terminate_via_driver(pid):
                        return True
                return False

            ok = kernel32.TerminateProcess(handle, 1)
            kernel32.CloseHandle(handle)

            if ok:
                logger.info(f'_emergency_kill: TerminateProcess 成功 PID={pid}')
                return True
            else:
                err = ctypes.get_last_error()
                # ERROR_ACCESS_DENIED (5) = 权限不足，尝试提权后重试
                if err == 5:
                    logger.debug(f'_emergency_kill: 权限不足 PID={pid}，尝试提权')
                    if self._enable_debug_privilege():
                        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
                        if handle:
                            ok = kernel32.TerminateProcess(handle, 1)
                            kernel32.CloseHandle(handle)
                            if ok:
                                logger.info(f'_emergency_kill: 提权后终止成功 PID={pid}')
                                return True
                    # 提权仍失败 → 回退内核驱动终止
                    if self._terminate_via_driver(pid):
                        return True
                logger.warning(f'_emergency_kill: TerminateProcess 失败 PID={pid} err={err}')
                return False
        except Exception as e:
            logger.error(f'_emergency_kill 异常 PID={pid}: {e}')
            return False

    def _terminate_image_instances(self, exe: str, cap: int = 64) -> int:
        """用户态兜底：按可执行文件路径终止所有运行实例（不依赖内核驱动）。

        病毒常派生多个同 exe 平行进程弹提示框；kill_process(pid) 的树杀
        只覆盖种子进程的子孙进程，平行实例（非父子关系）会漏。当驱动
        不可用（非管理员 / 驱动未加载）/ 驱动终止失败时，此方法枚举全部
        同 exe 实例逐个走完整 kill_process 链路，是"同 exe 杀所有实例"
        的用户态实现。

        Args:
            exe: 威胁文件绝对路径
            cap: 单次最多处理实例数（防恶意扩散为海量进程拖垮枚举）
        Returns:
            杀不掉的剩余实例数（0 = 全部清空）
        """
        if not HAS_PSUTIL or not exe:
            return 0
        try:
            target = os.path.normcase(os.path.abspath(exe))
        except Exception:
            return 0

        # 冷却检查：上次本 exe 存在杀不掉的实例，冷却窗口内不再重复枚举，
        # 防止与自我保护/自动重启进程（如杀软）形成"杀→唤→再杀"死循环
        # 拖垮系统（曾导致 PSLS 未响应）。
        _now = time.time()
        with self._tii_lock:
            _last = self._tii_last_fail.get(target, 0.0)
        if _last and (_now - _last) < self._TII_RETRY_COOLDOWN:
            logger.warning(
                f'_terminate_image_instances: {exe} 终止失败未过冷却，'
                f'本轮跳过（防与自我保护进程死循环，{self._TII_RETRY_COOLDOWN:.0f}s 后重试）')
            return 1  # 视为仍有实例存活，调用方不再做"已清空"假设

        remaining = 0
        scanned = 0
        try:
            for proc in psutil.process_iter(['pid', 'exe']):
                try:
                    p_exe = proc.info.get('exe')
                    if not p_exe:
                        # AccessDenied 拿不到 exe（如系统受保护进程）→
                        # 跳过本轮，交由驱动按路径终止兜底
                        continue
                    if os.path.normcase(os.path.abspath(p_exe)) != target:
                        continue
                    pid = proc.pid
                    if self._refuse_self_kill(pid, '_terminate_image_instances'):
                        continue
                    scanned += 1
                    if scanned > cap:
                        logger.warning(
                            f'_terminate_image_instances: 实例数超过上限 {cap}，'
                            f'停止继续枚举 {exe}')
                        remaining += 1
                        continue
                    if self.kill_process(pid, force=True, kill_tree=True,
                                         timeout=2.0):
                        logger.debug(
                            f'_terminate_image_instances: 已终止实例 PID={pid} '
                            f'({os.path.basename(exe)})')
                    else:
                        remaining += 1
                        logger.warning(
                            f'_terminate_image_instances: 实例 PID={pid} '
                            f'终止失败 {exe}')
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        psutil.ZombieProcess):
                    continue
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f'_terminate_image_instances 枚举异常 {exe}: {e}')

        # 记录冷却状态：杀干净则清除标记（下次允许立即重试），
        # 仍有剩余则记时间戳（冷却窗口内跳过，防死循环）
        with self._tii_lock:
            if remaining == 0:
                self._tii_last_fail.pop(target, None)
            else:
                self._tii_last_fail[target] = time.time()
        return remaining

    def _kill_process_tree_best_effort(self, pid: int, timeout: float = 2.0) -> int:
        """尽力终止指定 PID 的所有子进程（不等待，快速返回）

        用于脚本文件的紧急处置：当 bat/ps1 等脚本被终止后，
        其子进程（如 cmd.exe、powershell.exe、恶意可执行文件）
        可能已经启动。本方法枚举子进程并调用 _emergency_kill 终止。

        Args:
            pid: 父进程 PID
            timeout: 等待子进程终止的超时时间（秒），仅用于兜底

        Returns:
            成功终止的子进程数量
        """
        if not HAS_PSUTIL or pid <= 0:
            return 0

        killed_count = 0
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            if not children:
                return 0

            # 先尝试紧急终止（TerminateProcess，毫秒级）
            for child in children:
                try:
                    child_pid = child.pid
                    if self._refuse_self_kill(child_pid, '_kill_process_tree_best_effort'):
                        continue
                    if self._emergency_kill(child_pid):
                        killed_count += 1
                        logger.debug(
                            f'_kill_process_tree: 紧急终止子进程 PID={child_pid}')
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception as e:
                    logger.debug(f'_kill_process_tree 终止子进程失败: {e}')

            # 兜底：如果紧急终止有遗漏，尝试 kill()
            remaining = [c for c in children if c.is_running()]
            for child in remaining:
                try:
                    if self._refuse_self_kill(child.pid, '_kill_process_tree_best_effort'):
                        continue
                    child.kill()
                    killed_count += 1
                    logger.debug(
                        f'_kill_process_tree: kill() 终止子进程 PID={child.pid}')
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception:
                    pass

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # 父进程已不存在或无法访问
            pass
        except Exception as e:
            logger.debug(f'_kill_process_tree_best_effort 异常 PID={pid}: {e}')

        return killed_count

    def _emergency_suspend(self, pid: int) -> bool:
        """紧急挂起进程（毫秒级，不阻塞 ETW 回调）。

        用于「挂起 → 沙箱分析 → Resume 或 Kill」的放行链路：
        用挂起替代旧流程的 Terminate → subprocess.Popen 重启，
        从根本上避免 PSLS 替用户"二次启动"安装程序等可执行文件的 bug。

        原理：
        - OpenProcess(PROCESS_QUERY_INFORMATION) 拿到句柄
        - 用 CreateToolhelp32Snapshot 枚举该 PID 下的所有线程
        - 逐线程 SuspendThread 挂起（挂起计数+1）
        - 枚举线程失败时回退到 TerminateProcess

        Args:
            pid: 目标进程 PID
        Returns:
            True=成功挂起至少一个线程
        """
        if not HAS_CTYPES or sys.platform != 'win32':
            # 非 Windows：挂起无法实现，只能降级为 kill（保持旧行为安全）
            return self._emergency_kill(pid)

        try:
            kernel32 = ctypes.windll.kernel32
            TH32CS_SNAPTHREAD = 0x00000004
            THREAD_SUSPEND_RESUME = 0x0002
            MAX_PATH = 260

            class _THREADENTRY32(ctypes.Structure):
                _fields_ = [
                    ('dwSize', ctypes.wintypes.DWORD),
                    ('cntUsage', ctypes.wintypes.DWORD),
                    ('th32ThreadID', ctypes.wintypes.DWORD),
                    ('th32OwnerProcessID', ctypes.wintypes.DWORD),
                    ('tpBasePri', ctypes.c_ulong),
                    ('tpDeltaPri', ctypes.c_ulong),
                    ('dwFlags', ctypes.wintypes.DWORD),
                ]

            kernel32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE
            kernel32.Thread32First.restype = ctypes.wintypes.BOOL
            kernel32.Thread32Next.restype = ctypes.wintypes.BOOL
            kernel32.OpenThread.restype = ctypes.wintypes.HANDLE
            kernel32.SuspendThread.restype = ctypes.c_ulong
            kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]

            snap = kernel32.CreateToolhelp32Snapshot(
                TH32CS_SNAPTHREAD, 0
            )
            if not snap or snap == -1:
                logger.warning(f'_emergency_suspend: Snapshot 失败 PID={pid}，降级kill')
                return self._emergency_kill(pid)
            try:
                te = _THREADENTRY32()
                te.dwSize = ctypes.sizeof(_THREADENTRY32)
                ok = kernel32.Thread32First(snap, ctypes.byref(te))
                suspended_count = 0
                while ok:
                    if te.th32OwnerProcessID == int(pid):
                        tid = te.th32ThreadID
                        h_thread = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
                        if h_thread:
                            susp = kernel32.SuspendThread(h_thread)
                            if susp != 0xFFFFFFFF:  # (DWORD)-1 == 失败
                                suspended_count += 1
                            kernel32.CloseHandle(h_thread)
                    te.dwSize = ctypes.sizeof(_THREADENTRY32)
                    ok = kernel32.Thread32Next(snap, ctypes.byref(te))
                if suspended_count > 0:
                    logger.info(f'_emergency_suspend: 已挂起 PID={pid} 线程数={suspended_count}')
                    return True
                logger.warning(f'_emergency_suspend: PID={pid} 未找到可挂起线程，降级kill')
                return self._emergency_kill(pid)
            finally:
                kernel32.CloseHandle(snap)
        except Exception as e:
            logger.error(f'_emergency_suspend 异常 PID={pid}: {e}，降级kill')
            return self._emergency_kill(pid)

    def _resume_suspended_process(self, pid: int) -> bool:
        """恢复被 _emergency_suspend 挂起的进程。

        对应 SuspendThread 每个线程 resume 一次（挂起计数归零）。
        """
        if not HAS_CTYPES or sys.platform != 'win32':
            return False
        try:
            kernel32 = ctypes.windll.kernel32
            TH32CS_SNAPTHREAD = 0x00000004
            THREAD_SUSPEND_RESUME = 0x0002

            class _THREADENTRY32(ctypes.Structure):
                _fields_ = [
                    ('dwSize', ctypes.wintypes.DWORD),
                    ('cntUsage', ctypes.wintypes.DWORD),
                    ('th32ThreadID', ctypes.wintypes.DWORD),
                    ('th32OwnerProcessID', ctypes.wintypes.DWORD),
                    ('tpBasePri', ctypes.c_ulong),
                    ('tpDeltaPri', ctypes.c_ulong),
                    ('dwFlags', ctypes.wintypes.DWORD),
                ]

            kernel32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE
            kernel32.Thread32First.restype = ctypes.wintypes.BOOL
            kernel32.Thread32Next.restype = ctypes.wintypes.BOOL
            kernel32.OpenThread.restype = ctypes.wintypes.HANDLE
            kernel32.ResumeThread.restype = ctypes.c_ulong
            kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]

            snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            if not snap or snap == -1:
                return False
            try:
                te = _THREADENTRY32()
                te.dwSize = ctypes.sizeof(_THREADENTRY32)
                ok = kernel32.Thread32First(snap, ctypes.byref(te))
                resumed_count = 0
                # 每个线程可能被多次 suspend，循环 resume 直到计数归零（SuspendCount=0
                # 时 ResumeThread 返回 1，前一次返回 0 表示已归零本次 resume 又 +1
                # 故安全做法是 resume 到返回值 == 1 停止，最后一次 +1 后再 suspend
                # 一次归零。为简化起见，这里 resume 最多 8 次（正常不会超过 2 层）。
                MAX_RESUME_PER_THREAD = 8
                while ok:
                    if te.th32OwnerProcessID == int(pid):
                        tid = te.th32ThreadID
                        h_thread = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
                        if h_thread:
                            for _ in range(MAX_RESUME_PER_THREAD):
                                rc = kernel32.ResumeThread(h_thread)
                                if rc == 0xFFFFFFFF:
                                    break  # 失败，不再试
                                if rc == 1:
                                    # 前一次挂起计数为 0，本次 resume → 变 1
                                    # 需要再 suspend 一次归零
                                    kernel32.SuspendThread(h_thread)
                                    break
                                # rc > 1: 挂起计数仍 >0，继续 resume
                            kernel32.CloseHandle(h_thread)
                            resumed_count += 1
                    te.dwSize = ctypes.sizeof(_THREADENTRY32)
                    ok = kernel32.Thread32Next(snap, ctypes.byref(te))
                if resumed_count > 0:
                    logger.info(f'_resume_suspended_process: 已恢复 PID={pid} 线程数={resumed_count}')
                    return True
                return False
            finally:
                kernel32.CloseHandle(snap)
        except Exception as e:
            logger.error(f'_resume_suspended_process 异常 PID={pid}: {e}')
            return False

    def kill_process(self, pid: int, force: bool = False,
                     kill_tree: bool = True, timeout: float = 5.0) -> bool:
        """强制终止指定进程（用于处理检测到的威胁进程）

        增强版：递归终止进程树 + 等待确认 + 多级降级策略。

        Args:
            pid: 目标进程 PID
            force: True 使用 TerminateProcess（强杀），False 使用 terminate（信号）
            kill_tree: True 同时递归终止所有子孙进程（默认开启，避免恶意软件子进程保活）
            timeout: 终止后等待进程退出的超时秒数

        Returns:
            True 表示目标进程已终止或原本就不存在；False 表示终止失败

        终止链路（按优先级）：
            1. psutil 递归终止进程树（叶子→根逆序，先 terminate 再 kill）
            2. 失败时启用 SeDebugPrivilege 提权重试
            3. 仍失败调用 taskkill /F /T 兜底
        """
        if not HAS_PSUTIL:
            return False

        # 自身终止守卫：PSLS 绝不能终止自己/自身子进程（防误杀导致静默退出）
        if self._refuse_self_kill(pid, 'kill_process'):
            return False

        # 进程不存在视为成功
        try:
            target = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return True
        except (psutil.AccessDenied, psutil.ZombieProcess):
            target = None

        # 第一次尝试：常规 psutil 终止
        if self._kill_tree_psutil(pid, target, force=force, timeout=timeout):
            self._log_kill(pid, target, success=True, method='psutil_tree')
            return True

        # 第二次尝试：启用 SeDebugPrivilege 后重试
        if self._enable_debug_privilege():
            logger.info(f'已启用 SeDebugPrivilege，重试终止 PID={pid}')
            try:
                target = psutil.Process(pid)
            except psutil.NoSuchProcess:
                return True
            except (psutil.AccessDenied, psutil.ZombieProcess):
                target = None
            if self._kill_tree_psutil(pid, target, force=True, timeout=timeout):
                self._log_kill(pid, target, success=True, method='psutil_tree_elevated')
                return True

        # 第三次尝试：taskkill /F /T 兜底
        if sys.platform == 'win32' and self._kill_via_taskkill(pid, tree=kill_tree):
            self._log_kill(pid, target, success=True, method='taskkill')
            return True

        # 第四次尝试：内核驱动 ZwTerminateProcess（最高权限，突破用户态 DACL 限制）
        if self._terminate_via_driver(pid):
            self._log_kill(pid, target, success=True, method='driver_zwterminate')
            return True

        self._log_kill(pid, target, success=False, method='all_exhausted')
        return False

    def _kill_tree_psutil(self, pid: int, target: Optional['psutil.Process'],
                          force: bool = True, timeout: float = 5.0) -> bool:
        """递归终止进程树（叶子→根逆序）"""
        if not HAS_PSUTIL:
            return False

        children = []
        if target is not None:
            try:
                children = target.children(recursive=True)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                children = []
            except Exception as e:
                logger.debug(f'获取 PID={pid} 子进程失败: {e}')
                children = []

        # 逆序：先杀叶子，最后杀根，避免父进程死后子进程被托管或重启
        all_procs = list(reversed(children))
        if target is not None:
            all_procs.append(target)

        for proc in all_procs:
            try:
                if not proc.is_running():
                    continue
                if force:
                    proc.kill()
                else:
                    proc.terminate()
            except psutil.NoSuchProcess:
                continue
            except (psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f'终止 PID={proc.pid} 失败: {e}')

        if target is None:
            return True

        try:
            target.wait(timeout=timeout)
            return True
        except psutil.TimeoutExpired:
            try:
                target.kill()
                target.wait(timeout=2.0)
                return True
            except psutil.TimeoutExpired:
                logger.warning(f'进程 PID={pid} 终止超时，可能仍存活')
                return False
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return True
        except Exception as e:
            logger.warning(f'等待 PID={pid} 退出异常: {e}')
            return False

    def _kill_via_taskkill(self, pid: int, tree: bool = True) -> bool:
        """使用 taskkill 命令兜底终止进程

        /F 强制终止，/T 递归终止进程树

        反 IFEO 劫持：恶意样本常把系统工具的
        HKLM\\...\\Image File Execution Options\\<tool>.exe\\Debugger
        重定向到调试器（如 ntsd/VsJITDebugger），导致 taskkill 启动即被
        Debugger 接管、命令永不生效。调用前先清除该劫持值，并使用
        System32 全路径（规避 PATH 被篡改/重定向）。
        """
        try:
            # 1) 清除 taskkill.exe 的 IFEO Debugger 劫持（需管理员，失败不阻塞）
            self._clear_ifeo_debugger('taskkill.exe')
            # 2) System32 全路径调用，规避 PATH 劫持
            taskkill_exe = os.path.join(
                os.environ.get('SystemRoot', r'C:\Windows'),
                'System32', 'taskkill.exe')
            if not os.path.isfile(taskkill_exe):
                taskkill_exe = 'taskkill'
            import subprocess
            cmd = [taskkill_exe, '/F', '/PID', str(pid)]
            if tree:
                cmd.insert(1, '/T')
            # 子进程窗口隐藏，避免弹出黑色窗口
            creationflags = 0x08000000 if sys.platform == 'win32' else 0
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
                creationflags=creationflags
            )
            if result.returncode == 0:
                return True
            logger.warning(f'taskkill PID={pid} 失败: {result.stderr.strip()[:200]}')
            return False
        except subprocess.TimeoutExpired:
            logger.warning(f'taskkill PID={pid} 超时')
            return False
        except Exception as e:
            logger.warning(f'taskkill PID={pid} 异常: {e}')
            return False

    @staticmethod
    def _clear_ifeo_debugger(image_name: str) -> bool:
        """清除指定映像的 IFEO (Image File Execution Options) Debugger 劫持值。

        恶意样本常把 taskkill/tasklist/powershell/reg 等系统工具的 Debugger
        值重定向到调试器，使"调用该命令"变成"启动调试器" → 杀链兜底失效。
        该方法删除该映像下的 Debugger 值（保留其它合法 IFEO 配置）。
        """
        if sys.platform != 'win32':
            return False
        try:
            import winreg
        except Exception:
            return False
        try:
            key_path = (r'Software\Microsoft\Windows NT\CurrentVersion'
                        r'\Image File Execution Options' + '\\' + image_name)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                                winreg.KEY_SET_VALUE) as k:
                old = ''
                try:
                    old, _ = winreg.QueryValueEx(k, 'Debugger')
                except FileNotFoundError:
                    return True  # 无劫持，无需处理
                except OSError:
                    return False
                try:
                    winreg.DeleteValue(k, 'Debugger')
                    logger.warning(
                        f'已清除 IFEO Debugger 劫持: {image_name} (旧值: {old})')
                    return True
                except OSError as e:
                    logger.debug(f'清除 IFEO Debugger 失败 {image_name}: {e}')
                    return False
        except FileNotFoundError:
            return True  # 映像无 IFEO 键，无劫持
        except OSError:
            # 非管理员无 HKLM 写权限：无法清理，返回 False，调用方继续原链路
            return False
        except Exception as e:
            logger.debug(f'清除 IFEO Debugger 异常 {image_name}: {e}')
            return False

    def _terminate_via_driver(self, pid: int, exit_code: int = 1) -> bool:
        """通过内核驱动 ZwTerminateProcess 终止进程（最高权限兜底）

        内核态 ZwTerminateProcess 不受用户态安全描述符/DACL 限制，
        可终止 SYSTEM 权限、受自我保护保护的高权限进程，弥补
        TerminateProcess/taskkill 在权限不足时的失败。

        驱动未签名/未加载时优雅降级（返回 False，不影响原有链路）。

        Returns:
            True = 驱动终止成功或驱动不可用但无需处理；False = 驱动调用失败
        """
        if sys.platform != 'win32':
            return False
        # 自身终止守卫：内核态 ZwTerminateProcess 可绕过 DACL，更需拦截
        if self._refuse_self_kill(pid, '_terminate_via_driver'):
            return False
        try:
            # 延迟导入，避免与 self_protection/驱动管理器循环引用
            from utils.driver_manager import ensure_driver_loaded
            if not ensure_driver_loaded():
                logger.debug(f'内核驱动未加载，跳过驱动终止 PID={pid}')
                return False
            from driver.bridge.psls_driver_bridge import PSLSDriverBridge
            bridge = PSLSDriverBridge()
            try:
                if not bridge.is_available:
                    logger.debug(f'驱动桥接不可用，跳过驱动终止 PID={pid}')
                    return False
                ok = bridge.terminate_process(pid, exit_code=exit_code, force=True)
                if ok:
                    logger.info(f'内核驱动终止成功 PID={pid}')
                else:
                    logger.warning(f'内核驱动终止失败 PID={pid}')
                return ok
            finally:
                try:
                    bridge.close()
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f'内核驱动终止异常 PID={pid}: {e}')
            return False

    def _enable_debug_privilege(self) -> bool:
        """启用 SeDebugPrivilege 特权，使本进程可以终止更高权限的进程

        需要管理员权限（以管理员身份运行的 PSLS 才能成功）。
        """
        if not HAS_CTYPES or sys.platform != 'win32':
            return False

        try:
            advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            TOKEN_ADJUST_PRIVILEGES = 0x0020
            SE_PRIVILEGE_ENABLED = 0x00000002

            class LUID(ctypes.Structure):
                _fields_ = [
                    ('LowPart', ctypes.wintypes.DWORD),
                    ('HighPart', ctypes.wintypes.LONG),
                ]

            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [
                    ('PrivilegeCount', ctypes.wintypes.DWORD),
                    ('Luid', LUID),
                    ('Attributes', ctypes.wintypes.DWORD),
                ]

            token_handle = ctypes.wintypes.HANDLE()
            if not advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES,
                ctypes.byref(token_handle)
            ):
                return False

            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(
                None, 'SeDebugPrivilege', ctypes.byref(luid)
            ):
                kernel32.CloseHandle(token_handle)
                return False

            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Luid = luid
            tp.Attributes = SE_PRIVILEGE_ENABLED

            ok = advapi32.AdjustTokenPrivileges(
                token_handle, False, ctypes.byref(tp),
                ctypes.sizeof(tp), None, None
            )
            kernel32.CloseHandle(token_handle)

            last_err = ctypes.get_last_error()
            if not ok:
                logger.debug(f'AdjustTokenPrivileges 失败: {last_err}')
                return False
            if last_err == 1300:  # ERROR_NOT_ALL_ASSIGNED
                logger.debug('SeDebugPrivilege 未分配（需管理员权限）')
                return False
            return True
        except Exception as e:
            logger.debug(f'启用 SeDebugPrivilege 异常: {e}')
            return False

    def _log_kill(self, pid: int, target: Optional['psutil.Process'],
                  success: bool, method: str):
        """记录进程终止结果到事件日志"""
        try:
            name = ''
            if target is not None:
                try:
                    name = target.name()
                except Exception:
                    name = ''
            level = 'success' if success else 'warning'
            message = f'进程终止{"成功" if success else "失败"} (方式: {method})'
            self._add_event('process_kill', pid, name, level, message)
            if success:
                logger.info(f'已终止进程: PID={pid} name={name} method={method}')
            else:
                logger.warning(f'终止进程失败: PID={pid} name={name} method={method}')
        except Exception:
            pass
