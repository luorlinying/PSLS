"""
更激进的特效检测（Aggressive Prank Detector）

利用屏幕截图实时监控桌面异常：不规则图片 / 全屏特效 / 大量相同窗口，
一旦命中立即终止除系统进程以外的所有进程（包括 powershell / cmd），
并通知用户。仅当用户在设置中手动开启（默认关闭）后生效。

与 VisualPrankDetector 的关系：
- VisualPrankDetector：轻量、仅对"观察集合"内非信任 PE 生效，默认开启；
- 本模块：全局截图监控，命中即全量清理，误报风险高，默认关闭。

设计约束：
- 默认关闭；开启存在误报与性能占用风险（设置页有郑重提示）。
- 系统进程白名单 + PSLS 自身进程树/安装目录双保险排除，绝不终止
  PSLS 自身、MLWorker、QtWebEngine、扫描子进程等 PSLS 相关进程。
- powershell.exe / cmd.exe / conhost.exe / explorer.exe 等非核心系统
  进程一律可被终止（符合"终止除系统进程以外的所有进程"的原始语义）。
- 命中处置走 on_aggressive_prank 回调（桥接层负责通知）；
  实际杀进程在本模块内使用注入的 kill_hook（桥接层转发给
  ProcessProtection.kill_process）。
- 命中后 45s 冷却，避免反复触发刷屏。
- 截图失败 / 缺少 Pillow 时优雅降级：仅保留"大量相同窗口"信号。
"""
import os
import sys
import time
import threading
from typing import Callable, Dict, List, Optional, Set, Tuple

from utils.logger import get_logger

logger = get_logger('aggressive_prank_detector')

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
    from PIL import ImageGrab
    HAS_IMAGEGRAB = True
except ImportError:
    HAS_IMAGEGRAB = False
    ImageGrab = None


# ---- 阈值（高敏感档位：轮询更频、阈值更低，反应更快；误报风险相应上升）----
_POLL_INTERVAL = 0.8            # 截图轮询周期（秒）
_GRACE_PERIOD = 8.0             # 启动预热期：只采集基线，不做判定
_KILL_COOLDOWN = 30.0           # 命中处置后冷却（秒）

# 屏幕异常信号
_CHURN_RATIO = 0.40             # 相邻两帧差异像素占比 >40% → 高刷屏
_CHURN_CONSEC = 2               # 连续 2 轮高刷屏才命中（过滤视频转场等瞬时变化）
_TAKEOVER_RATIO = 0.70          # 单一颜色占据屏幕 >70% → 全屏单色占领
_TAKEOVER_CONSEC = 2            # 连续 2 轮单色占领才命中
_SAME_WINDOW_COUNT = 5          # 相同标题的无边框/顶层窗口数 >=5 → 窗口风暴
_WINDOW_CHURN_CONSEC = 2        # 窗口风暴需连续 2 轮确认

_SCREEN_W, _SCREEN_H = 160, 90  # 截图降采样尺寸（性能优先）
_DIFF_THRESHOLD = 18            # 像素灰度差阈值（原 24，降低更易感知变化）
_BLACK_MEAN = 4.0               # 屏幕几乎全黑（锁屏/灭屏）→ 视为空闲，跳过判定


# 伪进程（无 exe 路径，psutil.name() 返回这些名字）
_SYSTEM_PSEUDO = {
    'system idle process', 'system', 'registry',
    'secure system', 'memory compression',
}

# 核心系统进程（绝不可终止，否则系统立即崩溃/蓝屏）
_SYSTEM_EXES = {
    'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'lsass.exe', 'lsaiso.exe', 'svchost.exe',
    'fontdrvhost.exe', 'dwm.exe', 'logonui.exe',
}


class AggressivePrankDetector:
    """更激进的特效检测器（截图监控 + 全量进程清理）

    对外接口：
        set_enabled(bool) / is_running    : 开关控制（默认关闭）
        start() / stop()                  : 线程生命周期
        get_stats()                       : 各信号命中计数

    回调：
        kill_hook(pid) -> bool  : 桥接层注入的"终止单进程"回调
                                  （无注入时内部使用 psutil 强杀兜底）
        on_aggressive_prank(evidence) : 命中处置完成后分发（通知层）
    """

    def __init__(
            self,
            on_aggressive_prank: Callable[[dict], None] = None,
            kill_hook: Callable[[int], bool] = None,
            enabled: bool = False):
        self._on_aggressive_prank = on_aggressive_prank
        self._kill_hook = kill_hook
        self._enabled = bool(enabled)

        # PSLS 自身保护：进程树根 + 安装目录
        self._protected_roots: Set[int] = set()
        self._protected_dirs: Set[str] = set()
        self._collect_psls_protection()

        # 截图状态
        self._prev_gray: Optional[List[int]] = None
        self._churn_serie = 0
        self._takeover_serie = 0
        self._window_serie = 0
        self._start_ts = time.time()
        self._last_action_ts = 0.0

        # 命中统计
        self._stats_lock = threading.Lock()
        self._stats = {
            'screen_churn': 0,
            'screen_takeover': 0,
            'window_storm': 0,
        }

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------- 生命周期
    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def set_enabled(self, enabled: bool):
        self._enabled = bool(enabled)
        logger.info(f'更激进的特效检测 {"启用" if self._enabled else "禁用"}')

    def start(self):
        """启动轮询守护线程（幂等）。启动失败优雅降级：记录日志后返回。"""
        if self.is_running:
            return
        self._stop_event.clear()
        try:
            self._thread = threading.Thread(
                target=self._poll_loop, daemon=True,
                name='AggressivePrankDetector')
            self._thread.start()
            logger.info('更激进的特效检测已启动（截图监控）')
        except Exception as e:
            logger.error(f'更激进的特效检测启动失败: {e}')
            self._thread = None

    def stop(self):
        self._stop_event.set()
        if self._thread:
            try:
                self._thread.join(timeout=3.0)
            except Exception:
                pass
            self._thread = None

    def get_stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    # ------------------------------------------------------------- PSLS 自身保护
    def _collect_psls_protection(self):
        """收集 PSLS 自身进程树根与安装目录，从源头避免误杀自己。

        只把"当前进程及其全部子孙"视为受保护进程树（MLWorker、
        QtWebEngine、扫描子进程均为 PSLS 子进程）；绝不向上追溯
        父进程——否则会把启动 PSLS 的 shell（powershell/cmd）误保护，
        违背"终止除系统进程以外的所有进程"的语义。
        """
        try:
            if HAS_PSUTIL:
                self._protected_roots.add(os.getpid())
        except Exception as e:
            logger.debug(f'收集 PSLS 进程树失败: {e}')

        # 安装目录/项目根目录：frozen 模式下 sys.executable 位于安装目录；
        # 开发模式下以本模块所在目录的上级为项目根。
        for d in (os.path.dirname(sys.executable),
                  os.path.dirname(os.path.dirname(os.path.abspath(__file__)))):
            try:
                d = os.path.normcase(os.path.abspath(d))
                if d and os.path.isdir(d):
                    self._protected_dirs.add(d)
            except Exception:
                continue
        logger.debug(f'更激进的特效检测：保护目录={sorted(self._protected_dirs)}')

    def _protected_pid_set(self) -> Set[int]:
        """实时枚举 PSLS 自身进程树（含全部子孙）的 pid 集合。"""
        out = set(self._protected_roots)
        if not HAS_PSUTIL:
            return out
        for root in list(self._protected_roots):
            try:
                proc = psutil.Process(root)
                out.add(root)
                for c in proc.children(recursive=True):
                    out.add(c.pid)
            except Exception:
                continue
        return out

    def _is_exe_under_dirs(self, exe: str) -> bool:
        if not exe:
            return False
        try:
            p = os.path.normcase(os.path.abspath(exe))
        except Exception:
            return False
        for d in self._protected_dirs:
            if p == d or p.startswith(d + os.sep):
                return True
        return False

    def _is_protected(self, proc) -> bool:
        """判定进程是否受保护（系统进程 / PSLS 自身）。"""
        pid = proc.pid
        if pid <= 4:
            return True
        if pid in self._protected_pid_set():
            return True
        try:
            name = (proc.name() or '').lower()
        except Exception:
            name = ''
        if name in _SYSTEM_PSEUDO:
            return True
        if name in _SYSTEM_EXES:
            return True
        try:
            exe = proc.exe()
        except Exception:
            exe = ''
        if self._is_exe_under_dirs(exe):
            return True
        # 进程名与路径都无法获取（多为系统线程/高权限保护对象）→ 保守保护
        if not name and not exe:
            return True
        return False

    # ------------------------------------------------------------- 轮询主循环
    def _poll_loop(self):
        while not self._stop_event.is_set():
            started = time.time()
            try:
                if self._enabled:
                    self._poll_once()
            except Exception as e:
                logger.debug(f'更激进的特效检测轮询异常: {e}')
            elapsed = time.time() - started
            self._stop_event.wait(max(0.1, _POLL_INTERVAL - elapsed))

    def _poll_once(self):
        now = time.time()
        if now - self._last_action_ts < _KILL_COOLDOWN:
            return
        # 预热期：只采集基线
        if now - self._start_ts < _GRACE_PERIOD:
            self._capture_baseline()
            return

        # 信号 1/2：屏幕截图分析（缺 Pillow 时降级跳过）
        screen_signals: List[Tuple[str, str]] = []
        if HAS_IMAGEGRAB:
            try:
                screen_signals = self._analyze_screen()
            except Exception as e:
                logger.debug(f'截图分析异常: {e}')
        else:
            logger.debug('Pillow 不可用，截图信号降级跳过')

        # 信号 3：大量相同窗口
        window_signal = None
        try:
            window_signal = self._analyze_windows()
        except Exception as e:
            logger.debug(f'窗口风暴检测异常: {e}')

        # 汇总命中（各信号需连续 N 轮确认，防误报）
        hit_signal, hit_desc = self._evaluate(screen_signals, window_signal)
        if hit_signal:
            self._fire_hit(hit_signal, hit_desc)

    def _capture_baseline(self):
        if not HAS_IMAGEGRAB:
            return
        try:
            img = ImageGrab.grab()
            self._prev_gray = self._to_gray(img)
        except Exception as e:
            logger.debug(f'截图基线采集异常: {e}')

    @staticmethod
    def _to_gray(img) -> List[int]:
        """转为固定尺寸灰度列表。"""
        img = img.convert('RGB').resize((_SCREEN_W, _SCREEN_H))
        return [
            int(r * 0.299 + g * 0.587 + b * 0.114)
            for r, g, b in img.getdata()
        ]

    def _analyze_screen(self) -> List[Tuple[str, str]]:
        """截图并返回本轮触发的屏幕级信号列表 [(signal, detail)]。"""
        img = ImageGrab.grab()
        gray = self._to_gray(img)
        if self._prev_gray is None:
            self._prev_gray = gray
            return []
        prev = self._prev_gray
        self._prev_gray = gray

        total = len(gray)
        if total == 0:
            return []
        diff = sum(1 for a, b in zip(prev, gray) if abs(a - b) > _DIFF_THRESHOLD)
        mean = float(sum(gray)) / total
        # 全黑（锁屏/灭屏/纯黑屏保）→ 空闲，不判定
        if mean < _BLACK_MEAN:
            return []

        results: List[Tuple[str, str]] = []
        churn_ratio = diff / total
        if churn_ratio > _CHURN_RATIO:
            results.append(
                ('screen_churn', f'屏幕高刷屏：{churn_ratio * 100:.0f}% 像素快速变化'))

        # 全屏单色占领：降采样后统计量化主色占比
        if diff > 0:
            try:
                top_ratio, dominant = self._dominant_color_ratio(img)
                if (top_ratio > _TAKEOVER_RATIO
                        and dominant is not None
                        and dominant[0] > _BLACK_MEAN * 3
                        and max(dominant) - min(dominant) > 30):
                    results.append(
                        ('screen_takeover',
                         f'全屏单色特效占领：主色占比 {top_ratio * 100:.0f}%'
                         f'（RGB {dominant}）'))
            except Exception as e:
                logger.debug(f'单色占领分析异常: {e}')
        return results

    @staticmethod
    def _dominant_color_ratio(img) -> Tuple[float, Optional[Tuple[int, int, int]]]:
        """统计量化主色占比（3bit/通道 → 512 桶）。"""
        small = img.convert('RGB').resize((_SCREEN_W, _SCREEN_H))
        counts: Dict[int, int] = {}
        totals: Dict[int, Tuple[int, int, int]] = {}
        n = 0
        for r, g, b in small.getdata():
            n += 1
            key = ((r >> 5) << 6) | ((g >> 5) << 3) | (b >> 5)
            counts[key] = counts.get(key, 0) + 1
            rr, gg, bb = totals.get(key, (0, 0, 0))
            totals[key] = (rr + r, gg + g, bb + b)
        if not counts or n == 0:
            return 0.0, None
        top_key = max(counts, key=counts.get)
        r, g, b = totals[top_key]
        cnt = counts[top_key]
        return cnt / n, (r // cnt, g // cnt, b // cnt)

    def _analyze_windows(self) -> Optional[Tuple[str, str]]:
        """枚举可见顶层窗口，检测大量相同标题窗口（全局，非按 pid）。"""
        if not HAS_CTYPES or sys.platform != 'win32':
            return None
        user32 = ctypes.windll.user32
        titles: List[str] = []

        @ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL,
                            ctypes.wintypes.HWND,
                            ctypes.wintypes.LPARAM)
        def _enum_cb(hwnd, lparam):
            try:
                if not user32.IsWindowVisible(hwnd):
                    return True
                length = user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    buf = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(hwnd, buf, length + 1)
                    title = buf.value
                    if title:
                        # 排除 PSLS 自身窗口（其标题以 PSLS 开头）
                        if not title.startswith('PSLS'):
                            titles.append(title)
            except Exception:
                pass
            return True

        try:
            user32.EnumWindows(_enum_cb, 0)
        except Exception:
            return None

        from collections import Counter
        counter = Counter(titles)
        for title, cnt in counter.most_common(3):
            if cnt >= _SAME_WINDOW_COUNT:
                return ('window_storm',
                        f'检测到 {cnt} 个相同标题窗口"{title}"（大量弹窗风暴）')
        return None

    def _evaluate(self, screen_signals: List[Tuple[str, str]],
                  window_signal: Optional[Tuple[str, str]]
                  ) -> Tuple[Optional[str], str]:
        """各信号连续确认 + 冷却校验后决定是否命中。

        返回值恒为二元组 (signal, detail)，未命中时为 (None, '')。
        旧实现末行 `return None`，而调用处是
        `hit_signal, hit_desc = self._evaluate(...)` → 每个"未命中"轮次都抛
        TypeError: cannot unpack non-iterable NoneType object（被 _poll_loop
        吞成 DEBUG 日志），既刷日志又让"检测器到底有没有在跑"无法判断。
        """
        sig_map = {s: d for s, d in screen_signals}

        # 全屏高刷屏
        if 'screen_churn' in sig_map:
            self._churn_serie += 1
            if self._churn_serie >= _CHURN_CONSEC:
                self._churn_serie = 0
                return 'screen_churn', sig_map['screen_churn']
        else:
            self._churn_serie = 0

        # 全屏单色占领
        if 'screen_takeover' in sig_map:
            self._takeover_serie += 1
            if self._takeover_serie >= _TAKEOVER_CONSEC:
                self._takeover_serie = 0
                return 'screen_takeover', sig_map['screen_takeover']
        else:
            self._takeover_serie = 0

        # 大量相同窗口
        if window_signal is not None:
            self._window_serie += 1
            if self._window_serie >= _WINDOW_CHURN_CONSEC:
                self._window_serie = 0
                return window_signal
        else:
            self._window_serie = 0

        return None, ''

    # ------------------------------------------------------------- 命中处置
    def _fire_hit(self, signal: str, description: str):
        now = time.time()
        self._last_action_ts = now

        with self._stats_lock:
            self._stats[signal] = self._stats.get(signal, 0) + 1

        logger.warning(
            f'更激进的特效检测命中 [{signal}] desc={description}，'
            f'开始终止除系统进程以外的所有进程...')

        killed, failed, killed_names = self._kill_all_except_protected()

        evidence = {
            'type': 'aggressive_prank_hit',
            'signal': signal,
            'description': description,
            'killed': killed,
            'failed': failed,
            'killed_names': killed_names[:20],
            'ts': now,
        }
        try:
            if self._on_aggressive_prank:
                self._on_aggressive_prank(evidence)
        except Exception as e:
            logger.warning(f'更激进的特效检测：on_aggressive_prank 回调异常: {e}')

    def _kill_all_except_protected(self) -> Tuple[int, int, List[str]]:
        """终止除系统进程 / PSLS 自身以外的所有进程。"""
        if not HAS_PSUTIL:
            logger.warning('更激进的特效检测：psutil 不可用，跳过全量终止')
            return 0, 0, []

        protected = self._protected_pid_set()
        killable: List[psutil.Process] = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if self._is_protected(proc):
                    continue
                # 再次检查 pid 是否刚被判定时还在（进程可能已退出）
                if proc.pid <= 4 or proc.pid in protected:
                    continue
                killable.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        killed = 0
        failed = 0
        killed_names: List[str] = []
        for proc in killable:
            try:
                pname = proc.info.get('name') or 'unknown'
                if self._kill_process(proc.pid):
                    killed += 1
                    killed_names.append(pname)
                else:
                    failed += 1
            except Exception:
                failed += 1

        logger.warning(
            f'更激进的特效检测：全量终止完成，成功 {killed} 个，'
            f'失败 {failed} 个，保护跳过 {len(protected)} 个系统/PSLS 进程')
        return killed, failed, killed_names

    def _kill_process(self, pid: int) -> bool:
        """终止单进程：优先使用注入的 kill_hook，缺省用 psutil 强杀。"""
        if self._kill_hook:
            try:
                return bool(self._kill_hook(int(pid)))
            except Exception as e:
                logger.debug(f'kill_hook 终止 PID={pid} 异常: {e}')
        if not HAS_PSUTIL:
            return False
        try:
            proc = psutil.Process(pid)
            proc.kill()
            try:
                proc.wait(timeout=2.0)
            except Exception:
                pass
            return True
        except psutil.NoSuchProcess:
            return True
        except Exception as e:
            logger.debug(f'psutil 强杀 PID={pid} 异常: {e}')
            return False

    def close(self):
        """兼容 stop() 的别名。"""
        self.stop()