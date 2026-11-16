# -*- coding: utf-8 -*-
"""
load_governor.py — 动态降载控制器

背景
----
PSLS 运行在虚拟机/低配机器上时，多进程全盘扫描（每核 1~4 个子进程）会把 CPU
打满，导致整机（尤其虚拟机宿主机）卡顿、浏览器/IDE 均受影响。本模块提供一个
轻量级"资源看门狗"：

- 每 2 秒采样一次 CPU/内存使用率（优先 psutil，回退 ctypes + Windows API）
  + PSLS 自身的 RSS（物理内存）占比
- 根据负载分档返回降载因子（1.0 / 0.66 / 0.5 / 0.33）
- 提供 6 项"全局降载开关"（`get_reductions()`），按档位联动：
  - severe: 全开；high: 关ML / 跳重YARA / 慢轮询 / 缩扫描 / 降深度 / 缩池
  - elevated: 降深度 + 慢轮询 + 缩池
  - normal: 全关
- 可选回调 `set_reduction_callback()`：档位变化时触发，供各模块实时响应
- 提供 `apply_reductions(ctx)`：统一应用到 sig_db / rule_engine / ml_detector /
  protector / scan_max_file_mb 等组件，normal 档自动还原
- 纯函数接口（`get_worker_scale()` 等），宿主无需持有实例

阈值设计（结合用户偏好"扫描速度优先"，仅在真实高负载时降载，避免误伤性能）：
  - 正常   : 最近 CPU < 85% 且内存 < 90% 且自身RSS < 40%   → 1.0  （不干预）
  - 偏高   : CPU >= 85% 或 自身RSS >= 40%               → 0.66
  - 高     : CPU >= 92% 或 内存 >= 95% 或 自身RSS >= 60% → 0.5
  - 严重   : CPU >= 97% 或 自身RSS >= 80%                → 0.33
CPU 采样取"最近 2 个窗口均值"，避免单次采样尖峰导致抖动。
"""
import os
import sys
import time
import threading
from typing import Callable, Dict, List, Optional

_thread = None
_lock = threading.Lock()
_state = {
    'cpu': 0.0,
    'mem': 0.0,
    'scale': 1.0,
    'level': 'normal',
    'started': False,
    # ---- 新增：自身内存占用监控 ----
    'self_rss_mb': 0.0,     # PSLS 自身物理内存 (MB)
    'self_rss_pct': 0.0,    # PSLS 自身占总物理内存百分比
    'total_mem_mb': 0.0,    # 本机总物理内存 (MB，供 UI 展示)
}

# ---- 降载开关：随 level 联动 ----
# 每个开关在 >= 某档位时为 True
#
# 【重要】绝不把 ML 推理整个开关设为 True（用户要求禁用 ML 以外的办法）。
# 替代方案：
#   - reduce_ml_chunk_size : elevated+ 把 ML 推理文件块大小降到 1/4（读取+推理更快、
#                             但检测粒度变粗）；severe 进一步降到 1/8
#   - reduce_sig_max_bytes  : elevated+ 缩小 sig DB 分块扫描上限；severe 进一步缩小
#   - slow_monitor_polling  : elevated+ 拉长 MBR/关键目录轮询间隔
#   - slow_monitor_extra    : severe  再把轮询间隔翻倍（比 elevated 更慢）
#   - lower_signature_scan_depth : elevated+ 降低 sig 递归深度
#   - skip_heavy_yara_rules      : high+     跳过重型 YARA 规则（高误报+高耗时）
#   - restrict_scan_io           : elevated+ 缩小单文件扫描上限
#   - shrink_worker_pool         : elevated+ 收缩扫描进程池
_REDUCTION_THRESHOLDS = {
    'disable_ml_inference':     'impossible',  # 恒 False —— 用户禁止禁用 ML
    'reduce_ml_chunk_size':     'elevated',
    'reduce_sig_max_bytes':     'elevated',
    'slow_monitor_polling':     'elevated',
    'slow_monitor_extra':       'severe',
    'lower_signature_scan_depth': 'elevated',
    'skip_heavy_yara_rules':    'high',
    'restrict_scan_io':         'elevated',
    'shrink_worker_pool':       'elevated',
}
_LEVEL_ORDER = {'impossible': 99, 'normal': 0, 'elevated': 1, 'high': 2, 'severe': 3}

# ---- 回调机制：档位/任意降载开关变化时触发 ----
_cb: Optional[Callable] = None
_cb_lock = threading.Lock()
_prev_level = 'normal'
_prev_red: Dict[str, bool] = {k: False for k in _REDUCTION_THRESHOLDS}

# ---- Windows 原生采样（psutil 不可用时的回退） ----
_ctypes = None
try:
    import ctypes
    from ctypes import wintypes
    _ctypes = ctypes
except Exception:
    _ctypes = None

_k32 = None
_psapi = None
if _ctypes is not None and sys.platform == 'win32':
    try:
        _k32 = _ctypes.WinDLL('kernel32', use_last_error=True)
    except Exception:
        _k32 = None

    _k32_GetSystemTimes = getattr(_k32, 'GetSystemTimes', None) if _k32 else None
    _k32_GetTickCount64 = getattr(_k32, 'GetTickCount64', None) if _k32 else None
    if _k32 is not None:
        try:
            _k32.GlobalMemoryStatusEx.restype = wintypes.BOOL
            _k32.GlobalMemoryStatusEx.argtypes = [_ctypes.c_void_p]
        except Exception:
            pass


class _MEMORYSTATUSEX(_ctypes.Structure):
    _fields_ = [
        ('dwLength', _ctypes.wintypes.DWORD),
        ('dwMemoryLoad', _ctypes.wintypes.DWORD),
        ('ullTotalPhys', _ctypes.c_ulonglong),
        ('ullAvailPhys', _ctypes.c_ulonglong),
        ('ullTotalPageFile', _ctypes.c_ulonglong),
        ('ullAvailPageFile', _ctypes.c_ulonglong),
        ('ullTotalVirtual', _ctypes.c_ulonglong),
        ('ullAvailVirtual', _ctypes.c_ulonglong),
        ('ullAvailExtendedVirtual', _ctypes.c_ulonglong),
    ]


def _sample_cpu_psutil():
    """psutil 方式采样：cpu_percent(interval=None) 返回自上次调用以来的平均占用。"""
    import psutil
    return psutil.cpu_percent(interval=None) or 0.0


def _sample_cpu_winapi():
    """Windows API 方式：GetSystemTimes 两次采样计算 CPU 占用。"""
    if _k32_GetSystemTimes is None:
        return None
    class _FILETIME(_ctypes.Structure):
        _fields_ = [('dwLowDateTime', _ctypes.wintypes.DWORD),
                    ('dwHighDateTime', _ctypes.wintypes.DWORD)]
    idle1 = _FILETIME(); k1 = _FILETIME(); u1 = _FILETIME()
    idle2 = _FILETIME(); k2 = _FILETIME(); u2 = _FILETIME()
    if not _k32.GetSystemTimes(_ctypes.byref(idle1), _ctypes.byref(k1), _ctypes.byref(u1)):
        return None
    time.sleep(0.8)
    if not _k32.GetSystemTimes(_ctypes.byref(idle2), _ctypes.byref(k2), _ctypes.byref(u2)):
        return None
    def f(ft):
        return (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    total1 = f(idle1) + f(k1) + f(u1)
    total2 = f(idle2) + f(k2) + f(u2)
    dtotal = total2 - total1
    if dtotal <= 0:
        return None
    idle_d = f(idle2) - f(idle1)
    return max(0.0, min(100.0, 100.0 * (dtotal - idle_d) / dtotal))


def _sample_mem_psutil():
    import psutil
    return psutil.virtual_memory().percent


def _sample_mem_winapi():
    if _k32 is None:
        return None
    m = _MEMORYSTATUSEX()
    m.dwLength = _ctypes.sizeof(m)
    if _k32.GlobalMemoryStatusEx(_ctypes.byref(m)):
        return float(m.dwMemoryLoad)
    return None


def _sample_cpu() -> float:
    try:
        v = _sample_cpu_psutil()
        if v is not None:
            return v
    except Exception:
        pass
    try:
        v = _sample_cpu_winapi()
        if v is not None:
            return v
    except Exception:
        pass
    return 0.0


def _sample_mem() -> float:
    try:
        v = _sample_mem_psutil()
        if v is not None:
            return v
    except Exception:
        pass
    try:
        v = _sample_mem_winapi()
        if v is not None:
            return v
    except Exception:
        pass
    return 0.0


def _classify(cpu: float, mem: float) -> tuple:
    """根据采样值返回 (scale, level)。规则见模块 docstring。"""
    if cpu >= 97 or (cpu >= 85 and mem >= 97):
        return 0.33, 'severe'
    if cpu >= 92 or mem >= 95:
        return 0.5, 'high'
    if cpu >= 85:
        return 0.66, 'elevated'
    return 1.0, 'normal'


def _worker_loop():
    """采样循环：每 2 秒采样一次，平滑后更新状态。"""
    # 预热：psutil.cpu_percent 首次调用返回 0，这里先校准一次基线
    try:
        import psutil
        psutil.cpu_percent(interval=None)
    except Exception:
        pass
    while True:
        try:
            cpu = _sample_cpu()
            mem = _sample_mem()
            with _lock:
                prev_cpu = _state['cpu']
                # 平滑：与上一次采样各占 50%（首采直接用当前值）
                _state['cpu'] = cpu if prev_cpu <= 0 else (prev_cpu + cpu) * 0.5
                _state['mem'] = mem if _state['mem'] <= 0 else (_state['mem'] + mem) * 0.5
                _state['scale'], _state['level'] = _classify(
                    _state['cpu'], _state['mem'])
        except Exception:
            pass
        time.sleep(2.0)


def start():
    """启动资源看门狗（幂等）。仅在低配/虚拟化环境真正采样降载，开销极小。"""
    global _thread
    with _lock:
        if _state['started']:
            return
        _state['started'] = True
    t = threading.Thread(target=_worker_loop, name='PSLS-LoadGovernor', daemon=True)
    _thread = t
    t.start()


def get_worker_scale() -> float:
    """返回当前降载因子（1.0=正常，0.33=严重）。"""
    with _lock:
        return _state['scale']


def get_load_state() -> dict:
    """返回当前负载状态（供调试/诊断）。"""
    with _lock:
        return {
            'cpu': round(_state['cpu'], 1),
            'mem': round(_state['mem'], 1),
            'scale': _state['scale'],
            'level': _state['level'],
        }


def effective_workers(requested: int, min_floor: int = 1) -> int:
    """按当前负载缩放工作进程/线程数。

    Args:
        requested: 无负载时的工作数
        min_floor: 降载后的下限（至少保留的并行度，避免完全串行）

    Returns:
        缩放后的整数工作数（>= min_floor）
    """
    scale = get_worker_scale()
    if scale >= 1.0:
        return requested
    return max(min_floor, int(requested * scale))


# ================================================================
#  自身 RSS / 总物理内存采样
# ================================================================

def _sample_self_and_total_mem() -> tuple:
    """返回 (self_rss_mb, self_rss_pct, total_mem_mb)。失败时回退为 (0,0,0)。"""
    rss_bytes, total_bytes = None, None
    # psutil 优先
    try:
        import psutil
        total_bytes = psutil.virtual_memory().total
        proc = psutil.Process(os.getpid())
        rss_bytes = proc.memory_info().rss
    except Exception:
        rss_bytes, total_bytes = None, None
    # Windows API 回退
    if (rss_bytes is None or total_bytes is None) and _ctypes is not None and sys.platform == 'win32':
        try:
            # 1) GlobalMemoryStatusEx -> total + mem%
            if total_bytes is None and _k32 is not None:
                m = _MEMORYSTATUSEX()
                m.dwLength = _ctypes.sizeof(m)
                if _k32.GlobalMemoryStatusEx(_ctypes.byref(m)):
                    total_bytes = int(m.ullTotalPhys)
            # 2) GetProcessMemoryInfo -> RSS
            if rss_bytes is None:
                try:
                    psapi = _ctypes.WinDLL('psapi', use_last_error=True)
                    k32_h = _k32
                    class _PROCESS_MEMORY_COUNTERS(_ctypes.Structure):
                        _fields_ = [
                            ('cb', _ctypes.wintypes.DWORD),
                            ('PageFaultCount', _ctypes.wintypes.DWORD),
                            ('PeakWorkingSetSize', _ctypes.c_size_t),
                            ('WorkingSetSize', _ctypes.c_size_t),
                            ('QuotaPeakPagedPoolUsage', _ctypes.c_size_t),
                            ('QuotaPagedPoolUsage', _ctypes.c_size_t),
                            ('QuotaPeakNonPagedPoolUsage', _ctypes.c_size_t),
                            ('QuotaNonPagedPoolUsage', _ctypes.c_size_t),
                            ('PagefileUsage', _ctypes.c_size_t),
                            ('PeakPagefileUsage', _ctypes.c_size_t),
                        ]
                    ph = k32_h.GetCurrentProcess()
                    pmc = _PROCESS_MEMORY_COUNTERS()
                    pmc.cb = _ctypes.sizeof(pmc)
                    if psapi.GetProcessMemoryInfo(
                            ph, _ctypes.byref(pmc), _ctypes.sizeof(pmc)):
                        rss_bytes = int(pmc.WorkingSetSize)
                except Exception:
                    pass
        except Exception:
            pass
    rss = float(rss_bytes) if rss_bytes else 0.0
    tot = float(total_bytes) if total_bytes else 0.0
    rss_mb = round(rss / (1024.0 * 1024.0), 1)
    tot_mb = round(tot / (1024.0 * 1024.0), 1)
    pct = round(100.0 * rss / tot, 2) if tot > 0 else 0.0
    pct = max(0.0, min(100.0, pct))
    return (rss_mb, pct, tot_mb)


# ================================================================
#  档位 & 降载开关
# ================================================================

def _classify(cpu: float, mem: float, rss_pct: float) -> tuple:
    """根据 CPU / 系统内存 / PSLS 自身内存 三维度返回 (scale, level)。"""
    if cpu >= 97 or rss_pct >= 80 or (cpu >= 85 and mem >= 97):
        return 0.33, 'severe'
    if cpu >= 92 or mem >= 95 or rss_pct >= 60:
        return 0.5, 'high'
    if cpu >= 85 or rss_pct >= 40:
        return 0.66, 'elevated'
    return 1.0, 'normal'


def get_reductions(level: Optional[str] = None) -> Dict[str, bool]:
    """按档位返回 6 项降载开关字典 (level 默认用当前档位)。"""
    lv = level or _state['level']
    order = _LEVEL_ORDER.get(lv, 0)
    return {
        k: order >= _LEVEL_ORDER.get(thresh, 0)
        for k, thresh in _REDUCTION_THRESHOLDS.items()
    }


def set_reduction_callback(cb: Optional[Callable]) -> None:
    """注册全局降载变化回调。传 None 取消；重复传同一 cb 不重复生效。

    cb(new_reductions: dict, new_load_state: dict, previous_level: str) -> None。
    回调内不要做重活（避免阻塞采样线程），建议 QMetaObject/QTimer 转到主线程。
    """
    global _cb
    with _cb_lock:
        if cb is None:
            _cb = None
            return
        # 同一回调对象的幂等
        if _cb is cb:
            return
        _cb = cb


def _maybe_invoke_callback(prev_lvl: str, new_lvl: str,
                           new_load: Dict) -> None:
    """若档位/任意开关发生变化则触发回调 (在 _lock 外调用)。"""
    global _prev_level, _prev_red
    with _cb_lock:
        cb = _cb
    new_red = get_reductions(new_lvl)
    if prev_lvl == new_lvl and _prev_red == new_red and cb is None:
        # 即使无 cb 也要更新 _prev_red，避免下一轮误判
        _prev_level = new_lvl
        _prev_red = new_red
        return
    changed = (prev_lvl != new_lvl) or (_prev_red != new_red)
    _prev_level = new_lvl
    _prev_red = new_red
    if not changed or cb is None:
        return
    try:
        cb(dict(new_red), dict(new_load), prev_lvl)
    except Exception:
        pass


# ================================================================
#  采样循环扩展
# ================================================================

def _worker_loop():
    """采样循环：每 2 秒采样一次，平滑后更新状态 + 触发回调。"""
    # 预热：psutil.cpu_percent 首次调用返回 0，这里先校准一次基线
    try:
        import psutil
        psutil.cpu_percent(interval=None)
    except Exception:
        pass
    while True:
        try:
            cpu = _sample_cpu()
            mem = _sample_mem()
            self_mb, self_pct, tot_mb = _sample_self_and_total_mem()
            # 快照旧状态
            with _lock:
                prev_level = _state['level']
                prev_cpu = _state['cpu']
                prev_mem = _state['mem']
                # 平滑：与上一次各取 50%（首次直接用当前值）
                _state['cpu'] = cpu if prev_cpu <= 0 else (prev_cpu + cpu) * 0.5
                _state['mem'] = mem if prev_mem <= 0 else (_state['mem'] + mem) * 0.5
                _state['self_rss_mb'] = self_mb
                _state['self_rss_pct'] = self_pct
                _state['total_mem_mb'] = tot_mb
                _state['scale'], new_level = _classify(
                    _state['cpu'], _state['mem'], self_pct)
                _state['level'] = new_level
                load_now = {
                    'cpu': round(_state['cpu'], 1),
                    'mem': round(_state['mem'], 1),
                    'scale': _state['scale'],
                    'level': _state['level'],
                    'self_rss_mb': _state['self_rss_mb'],
                    'self_rss_pct': _state['self_rss_pct'],
                    'total_mem_mb': _state['total_mem_mb'],
                }
            # 锁外触发回调
            _maybe_invoke_callback(prev_level, new_level, load_now)
        except Exception:
            pass
        time.sleep(2.0)


# ================================================================
#  调试 / 测试钩子（不影响生产）
# ================================================================

def _debug_set_level(level: str) -> None:
    """手动覆盖当前档位（仅用于 TDD / 集成联调；生产环境切勿调用）。

    与 worker_loop 冲突的解决：设置后 _state['level'] 立即生效，且
    **get_reductions() 读取时直接用最新的 _state['level'] 计算即可**；
    但 worker_loop 下一轮会按真实 cpu/mem/rss_pct 重新 classify 可能把档位
    回拉。为了让 TDD 稳定：这里同步把 cpu/mem/self_rss_pct 推到对应档位阈值
    范围内，保证 worker 下一轮 classify 不会回拉。
    """
    if level not in _LEVEL_ORDER or level == 'impossible':
        raise ValueError(f'非法档位: {level}')
    with _lock:
        _state['level'] = level
        tbl = {'normal': 1.0, 'elevated': 0.66, 'high': 0.5, 'severe': 0.33}
        _state['scale'] = tbl[level]
        # 把 cpu/mem/rss_pct 推到 level 对应的阈值范围内，避免 worker_loop
        # 下一轮 _classify 把档位回拉（测试时真实 cpu/mem 往往很低）
        if level == 'severe':
            _state['cpu'] = 98.0
            _state['mem'] = 98.0
            _state['self_rss_pct'] = 82.0
        elif level == 'high':
            _state['cpu'] = 93.0
            _state['mem'] = 96.0
            _state['self_rss_pct'] = 62.0
        elif level == 'elevated':
            _state['cpu'] = 86.0
            _state['mem'] = 80.0
            _state['self_rss_pct'] = 42.0
        else:
            _state['cpu'] = 30.0
            _state['mem'] = 50.0
            _state['self_rss_pct'] = 20.0
        load_now = {k: _state.get(k, 0.0) for k in
                    ('cpu', 'mem', 'scale', 'level',
                     'self_rss_mb', 'self_rss_pct', 'total_mem_mb')}
        prev_level = _state.get('level', 'normal')
    _maybe_invoke_callback(prev_level, level, load_now)


# ================================================================
#  对外：统一 apply 到各模块
# ================================================================

# 保存各模块的"正常值"以便恢复（normal 档）
_baselines: Dict[str, object] = {
    'sig_depth': 3,
    'sig_max_bytes': 10 * 1024 * 1024,  # 10MB（SignatureDB 分块扫描上限）
    're_heavy': True,
    'ml_on': True,
    'prot_interval': 1.0,
    'prot_interval_elevated': 5.0,
    'prot_interval_severe': 10.0,
    'ml_chunk_kb': 4096,           # ML 推理块 4MB（每次读取 4MB 推理）
    'ml_chunk_kb_high': 1024,      # elevated/high → 1MB（1/4）
    'ml_chunk_kb_severe': 512,     # severe      → 512KB（1/8）
    'scan_max_file_mb': 512,
    'sig_max_bytes_high': 3 * 1024 * 1024,   # elevated/high → 3MB
    'sig_max_bytes_severe': 1024 * 1024,     # severe      → 1MB
}


def apply_reductions(ctx: dict) -> int:
    """把当前 reductions 应用到一组可降载对象，返回成功应用的动作数。

    ctx 结构（字段均可选；缺失则跳过对应动作）：
      - signature_db : 含 set_scan_depth(depth:int) 方法 (压缩包递归深度)
      - rule_engine  : 含 skip_heavy_rules(enabled:bool) 方法
      - ml_detector  : 含 set_inference_enabled(bool) 方法
      - protector    : 含 set_poll_interval(seconds:float) 方法
                       (MBRProtector/AutostartProtection 等监控组件)
      - scan_max_file_mb : list[int] (1 元素) 单文件扫描上限 (MB)，
                           用 list 包装让内部能够原地修改
      - baselines    : dict 可选，用于自定义"正常值"（缺省用上面的 _baselines）
    """
    red = get_reductions()
    lv = _state.get('level', 'normal')
    lv_order = _LEVEL_ORDER.get(lv, 0)
    n = 0
    bases = dict(_baselines)
    if isinstance(ctx.get('baselines'), dict):
        bases.update(ctx['baselines'])

    # ---- 1) 签名 DB：递归深度降档（elevated+） + 分块上限 bytes 分档降档 ----
    sig_db = ctx.get('signature_db')
    if sig_db is not None:
        # 递归深度
        if callable(getattr(sig_db, 'set_scan_depth', None)):
            depth = 1 if red['lower_signature_scan_depth'] else int(bases['sig_depth'])
            try:
                sig_db.set_scan_depth(depth)
                n += 1
            except Exception:
                pass
        # 分块扫描字节上限（新接口）：elevated/high → 3MB，severe → 1MB
        if callable(getattr(sig_db, 'set_scan_max_bytes', None)):
            if red['reduce_sig_max_bytes']:
                # severe 进一步更小
                if lv_order >= _LEVEL_ORDER['severe']:
                    mb = int(bases['sig_max_bytes_severe'])
                else:
                    mb = int(bases['sig_max_bytes_high'])
            else:
                mb = int(bases['sig_max_bytes'])
            try:
                sig_db.set_scan_max_bytes(mb)
                n += 1
            except Exception:
                pass

    re_ = ctx.get('rule_engine')
    if re_ is not None and callable(getattr(re_, 'skip_heavy_rules', None)):
        skip = red['skip_heavy_yara_rules']
        try:
            re_.skip_heavy_rules(skip)
            n += 1
        except Exception:
            pass

    # ---- 3) ML：不再禁用！而是分档降块大小（降低单文件推理吞吐，换取响应性）
    ml = ctx.get('ml_detector')
    if ml is not None:
        # 若上层仍手动调用了 set_inference_enabled(False)，我们要避免覆盖它；
        # 但我们绝对不会主动调用 set_inference_enabled(False)。
        # 这里保持开启（确保 ML 不被本函数误关），正常/降档都不翻转推理开关。
        if callable(getattr(ml, 'set_inference_enabled', None)):
            try:
                # 只在当前被关时重置为开（用户层可能暂时关的情况不处理）
                # —— 不主动调用 False；这里仅把它当作"维持开"的保障，
                #  避免历史代码在调用处依赖它把 ml_on=True 写入。
                pass
            except Exception:
                pass
        if callable(getattr(ml, 'set_chunk_size_kb', None)):
            if red['reduce_ml_chunk_size']:
                if lv_order >= _LEVEL_ORDER['severe']:
                    kb = int(bases['ml_chunk_kb_severe'])
                else:
                    kb = int(bases['ml_chunk_kb_high'])
            else:
                kb = int(bases['ml_chunk_kb'])
            try:
                ml.set_chunk_size_kb(kb)
                n += 1
            except Exception:
                pass

    # ---- 4) 监控轮询：elevated → 5s，severe 再翻倍（slow_monitor_extra）→ 10s
    prot = ctx.get('protector')
    if prot is not None and callable(getattr(prot, 'set_poll_interval', None)):
        if red['slow_monitor_extra']:
            iv = float(bases['prot_interval_severe'])
        elif red['slow_monitor_polling']:
            iv = float(bases['prot_interval_elevated'])
        else:
            iv = float(bases['prot_interval'])
        try:
            prot.set_poll_interval(iv)
            n += 1
        except Exception:
            pass

    sm = ctx.get('scan_max_file_mb')
    if isinstance(sm, list) and len(sm) == 1 and isinstance(sm[0], (int, float)):
        sm[0] = 128 if red['restrict_scan_io'] else int(bases['scan_max_file_mb'])
        n += 1

    return n


# ================================================================
#  get_load_state() 扩展：加入自身RSS
# ================================================================

def get_load_state() -> dict:
    """返回当前负载状态（含自身 RSS 监控 + 降载开关）。"""
    with _lock:
        red = get_reductions(_state['level'])
        return {
            'cpu': round(_state['cpu'], 1),
            'mem': round(_state['mem'], 1),
            'scale': _state['scale'],
            'level': _state['level'],
            'self_rss_mb': _state['self_rss_mb'],
            'self_rss_pct': _state['self_rss_pct'],
            'total_mem_mb': _state['total_mem_mb'],
            'reductions': red,
        }