"""
视觉恶搞行为检测（Visual Prank Detector）

针对纯视觉干扰类恶搞程序（prankware）：弹窗风暴、桌面图标洪流、
壁纸篡改、系统个性化设置批量改写。这类程序静态签名与现有 ML 特征
难以命中（按用户描述：先弹大量 cmd/powershell 提示框，主破坏逻辑
后执行）。本模块以 1s 周期独立轮询引擎识别以上四类视觉信号，命中后
先终止进程再询问用户是否信任重启（kill-then-ask）。

设计约束：
- 仅对"观察集合"内的进程生效。观察集合由 ProcessProtection 在
  非信任 PE 启动时通过 register_observed_pid() 注册（TTL 60s），
  避免误杀系统进程与正常换壁纸程序。
- 独立轮询，不依赖 watchdog / ETW；任意信号采集失败优雅降级
  （该轮跳过），不影响其他信号。
- 命中处置统一走 on_visual_prank 回调（桥接层负责杀进程全链 +
  弹窗询问）。
"""
import os
import sys
import time
import threading
from typing import Callable, Dict, List, Optional, Set, Tuple

from utils.logger import get_logger

logger = get_logger('visual_prank_detector')

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


# ---- 阈值（高敏感档位：轮询更频、阈值更低，反应更快；误报风险相应上升）----
_POPUP_WINDOWS_5S = 6           # 弹窗洪流：5s 滑动窗口内新增顶层窗口数 >6
_ICON_FLOOD_5S = 6              # 桌面图标洪流：5s 内新增图标/脚本类文件 >6
_ICON_FLOOD_1S = 2              # 桌面图标洪流：1s 内 >2
_ICON_EXTS = {'.lnk', '.url', '.ico', '.bat', '.cmd', '.scr', '.pif'}
_WALLPAPER_LOOKBACK = 20        # 壁纸篡改：近 20s 内注册的观察进程为嫌疑（原 10s）
_SETTING_CHANGE_RATIO = 0.35    # 系统自定义项批量更改：>35% 基线项被改（原 50%）
_OBSERVED_TTL = 60              # 观察集合进程 TTL（秒）
_POLL_INTERVAL = 0.5            # 轮询周期（秒，原 1.0）
_WINDOW_SLIDE_WINDOW = 5.0      # 弹窗洪流滑动窗口（秒）


# 系统个性化设置基线（HKCU），恶意程序常批量改写这些项实现"视觉恶搞"
_WALLPAPER_KEY = r'Control Panel\Desktop'
_WALLPAPER_VALUE = 'WallPaper'
_TRANSCODED_WALLPAPER = os.path.join(
    os.environ.get('APPDATA', ''),
    r'Microsoft\Windows\Themes\TranscodedWallpaper')

_SETTING_BASELINE: List[Tuple[str, str, str]] = [
    (r'Control Panel\Desktop', 'WallPaper', ''),
    (r'Control Panel\Desktop', 'WallpaperStyle', ''),
    (r'Control Panel\Desktop', 'TileWallpaper', ''),
    (r'Control Panel\Desktop', 'MenuShowDelay', ''),
    (r'Control Panel\Desktop', 'ShowWindowAnimations', ''),
    (r'Control Panel\Desktop', 'DragFullWindows', ''),
    (r'Control Panel\Desktop', 'CursorBlinkRate', ''),
    (r'Control Panel\Desktop\WindowMetrics', 'IconSpacing', ''),
    (r'Control Panel\Desktop\WindowMetrics', 'CaptionHeight', ''),
    (r'Control Panel\Desktop\WindowMetrics', 'MenuHeight', ''),
    (r'Control Panel\Desktop\WindowMetrics', 'IconFont', ''),
    (r'Control Panel\Personalize', 'AppsUseLightTheme', ''),
    (r'Control Panel\Personalize', 'SystemUsesLightTheme', ''),
    (r'Control Panel\Personalize', 'ColorPrevalence', ''),
    (r'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
     'HideFileExt', ''),
    (r'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
     'ShowSuperHidden', ''),
    (r'AppEvents\Schemes', '(default)', ''),
    (r'Control Panel\Cursors', '(default)', ''),
]


class VisualPrankDetector:
    """视觉恶搞行为检测器（1s 周期守护线程轮询）

    对外接口：
        register_observed_pid(pid, exe)  : 非信任 PE 启动时注册观察对象
        set_enabled(bool) / is_running   : 开关控制
        start() / stop()                 : 线程生命周期
        get_stats()                      : 各信号命中计数（前端可展示）

    回调：
        kill_hook(exe, pid) -> bool      : 桥接层注入的"先杀进程"回调
        on_visual_prank(evidence)        : 命中后分发（在轮询线程调用）
    """

    def __init__(
            self,
            on_visual_prank: Callable[[dict], None] = None,
            kill_hook: Callable[[str, int], bool] = None,
            enabled: bool = True):
        self._on_visual_prank = on_visual_prank
        self._kill_hook = kill_hook
        self._enabled = bool(enabled)

        # 观察集合: {pid: (exe, name, cmdline, ts)}
        self._observed: Dict[int, tuple] = {}
        self._observed_lock = threading.Lock()
        self._observed_last_seen: Dict[int, float] = {}
        # pid -> 该进程当前存活的顶层窗口标题集合（弹窗洪流滑窗）
        self._pid_windows_last: Dict[int, Set[str]] = {}
        # pid -> 事件时间戳列表（窗口出现 / 图标新增 / 进程spawn）
        self._pid_window_events: Dict[int, List[float]] = {}
        self._pid_spawn_events: Dict[int, List[float]] = {}
        # pid -> 上一轮子进程数（spawn 增量统计基准）
        self._pid_spawn_last: Dict[int, int] = {}
        # 桌面文件快照（上一轮文件名集合）
        self._desktop_snapshot = set()
        self._desktop_icon_events: List[float] = []
        # 壁纸快照
        self._wallpaper_last = None
        self._transcoded_mtime_last = None
        # 系统设置基线
        self._setting_baseline: Optional[Dict[str, str]] = None
        self._last_setting_identical = 0  # 上次"基线一致"的时间戳（用于滞回）

        # 命中统计
        self._stats_lock = threading.Lock()
        self._stats = {
            'popup_storm': 0,
            'icon_flood': 0,
            'wallpaper_tamper': 0,
            'settings_changed': 0,
        }

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._recent_hits: List[Tuple[float, str, str]] = []  # (ts, type, exe)

    # ------------------------------------------------------------- 生命周期
    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def set_enabled(self, enabled: bool):
        self._enabled = bool(enabled)
        logger.info(f'视觉恶搞行为检测 {"启用" if self._enabled else "禁用"}')

    def start(self):
        """启动轮询守护线程（幂等）。启动失败优雅降级：记录日志后返回。"""
        if self.is_running:
            return
        self._stop_event.clear()
        try:
            self._thread = threading.Thread(
                target=self._poll_loop, daemon=True,
                name='VisualPrankDetector')
            self._thread.start()
            logger.info('视觉恶搞行为检测已启动（1s 轮询）')
        except Exception as e:
            logger.error(f'视觉恶搞行为检测启动失败: {e}')
            self._thread = None

    def stop(self):
        self._stop_event.set()
        if self._thread:
            try:
                self._thread.join(timeout=3.0)
            except Exception:
                pass
            self._thread = None

    # ------------------------------------------------------------- 观察集合
    def register_observed_pid(self, pid: int, exe: str,
                              name: str = '', cmdline: Optional[List[str]] = None):
        """注册非信任 PE 到观察集合（TTL 60s）。

        由 ProcessProtection._check_new_process 在非信任程序启动时调用，
        检测器仅对观察集合内的进程及其子孙进程做行为审计，从源头
        避免误杀系统进程与正常换壁纸程序。
        """
        if not pid or pid <= 0 or not exe:
            return
        try:
            now = time.time()
            with self._observed_lock:
                self._observed[pid] = (exe, name or os.path.basename(exe),
                                       list(cmdline) if cmdline else None, now)
                self._observed_last_seen[pid] = now
            # 懒初始化桌面快照（首次注册时建立，避免空集合导致图标洪流误报）
            if not self._desktop_snapshot:
                try:
                    self._desktop_snapshot = set(self._iter_desktop_files())
                except Exception:
                    pass
            logger.debug(f'视觉恶搞检测：注册观察对象 PID={pid} {exe}')
        except Exception as e:
            logger.debug(f'register_observed_pid 异常: {e}')

    def get_stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    # ------------------------------------------------------------- 轮询主循环
    def _poll_loop(self):
        # 预热：先收集一轮桌面快照与壁纸基线，避免把启动期自身的文件
        # 变更/当前壁纸误判为"第一次变化"。
        try:
            self._desktop_snapshot = set(self._iter_desktop_files())
            self._wallpaper_last, self._transcoded_mtime_last = \
                self._read_wallpaper_state()
            self._setting_baseline = self._read_settings_baseline()
        except Exception as e:
            logger.debug(f'视觉恶搞检测预热异常: {e}')

        while not self._stop_event.is_set():
            try:
                started = time.time()
                if self._enabled:
                    self._poll_once()
            except Exception as e:
                logger.debug(f'视觉恶搞检测轮询异常: {e}')
            # 固定 1s 周期（减去本轮耗时，避免长时间采集导致周期漂移）
            elapsed = time.time() - started
            self._stop_event.wait(max(0.1, _POLL_INTERVAL - elapsed))

    def _poll_once(self):
        now = time.time()
        self._purge_observed(now)

        observed = self._snapshot_observed()
        if not observed:
            # 无观察对象：仍维护桌面/壁纸基线（防止观察对象注册瞬间
            # 把二者误判为变化）
            try:
                self._refresh_wallpaper_baseline()
            except Exception:
                pass
            try:
                if self._setting_baseline is None:
                    self._setting_baseline = self._read_settings_baseline()
            except Exception:
                pass
            return

        # 信号 1：弹窗洪流（观察 pid 树的顶层窗口新增数量）
        try:
            self._check_popup_storm(observed, now)
        except Exception as e:
            logger.debug(f'弹窗洪流检测异常: {e}')

        # 信号 2：桌面图标洪流
        try:
            self._check_icon_flood(now)
        except Exception as e:
            logger.debug(f'桌面图标洪流检测异常: {e}')

        # 信号 3：壁纸篡改（变化时仅在近 10s 有观察进程存活才处置）
        try:
            self._check_wallpaper(observed, now)
        except Exception as e:
            logger.debug(f'壁纸篡改检测异常: {e}')

        # 信号 4：系统自定义项批量更改
        try:
            self._check_settings_change(now)
        except Exception as e:
            logger.debug(f'系统自定义项批量更改检测异常: {e}')

    # ------------------------------------------------------------- 观察集合工具
    def _snapshot_observed(self) -> Dict[int, tuple]:
        with self._observed_lock:
            return dict(self._observed)

    def _purge_observed(self, now: float):
        """清理已退出/超时(60s)的观察对象及其窗口/事件记录。"""
        dead = []
        with self._observed_lock:
            for pid, rec in list(self._observed.items()):
                alive = False
                if HAS_PSUTIL and pid > 0:
                    try:
                        alive = (psutil.pid_exists(pid)
                                 and psutil.Process(pid).status()
                                 != psutil.STATUS_ZOMBIE)
                    except Exception:
                        alive = False
                expired = now - rec[3] > _OBSERVED_TTL
                if not alive or expired:
                    dead.append(pid)
            for pid in dead:
                self._observed.pop(pid, None)
                self._observed_last_seen.pop(pid, None)
        for pid in dead:
            self._pid_windows_last.pop(pid, None)
            self._pid_window_events.pop(pid, None)
            self._pid_spawn_events.pop(pid, None)

    def _iter_pid_tree(self, pid: int, seen: Optional[Set[int]] = None):
        """遍历 pid 及其全部子孙 pid（生成器，异常安全）。"""
        seen = seen if seen is not None else set()
        if pid <= 0 or pid in seen:
            return
        seen.add(pid)
        yield pid
        if not HAS_PSUTIL:
            return
        try:
            children = psutil.Process(pid).children(recursive=False)
        except Exception:
            return
        for c in children:
            try:
                cpid = c.pid
            except Exception:
                continue
            if cpid not in seen:
                for p in self._iter_pid_tree(cpid, seen):
                    yield p

    def _snapshot_observed_alive(self, now: float) -> List[Tuple[int, str, str]]:
        """返回存活且未超时的观察对象列表 [(pid, exe, name)]。"""
        out = []
        with self._observed_lock:
            for pid, rec in list(self._observed.items()):
                if now - rec[3] > _WALLPAPER_LOOKBACK * 6:
                    continue  # 超过观察 TTL 的不再参与
                if HAS_PSUTIL:
                    try:
                        if not (psutil.pid_exists(pid)
                                and psutil.Process(pid).status()
                                != psutil.STATUS_ZOMBIE):
                            continue
                    except Exception:
                        continue
                out.append((pid, rec[0], rec[1]))
        return out

    def _pick_suspect(self) -> Optional[Tuple[int, tuple]]:
        """选择一个存活的观察对象作为图标洪流/设置改写的嫌疑来源。

        视觉恶搞程序通常在启动后注册为观察对象并保持运行；多个观察
        对象并存时取最早注册者（最可能是主程序）。
        """
        with self._observed_lock:
            if not self._observed:
                return None
            pid, rec = min(self._observed.items(),
                           key=lambda kv: kv[1][3] if kv[1][3] else 0)
            return pid, rec

    # ------------------------------------------------------------- 信号1：弹窗洪流
    def _check_popup_storm(self, observed: Dict[int, tuple], now: float):
        for pid in list(observed.keys()):
            try:
                win_titles = self._collect_top_windows_for_tree(pid)
                prev = self._pid_windows_last.get(pid)
                if prev is None:
                    self._pid_windows_last[pid] = win_titles
                    continue
                new_titles = win_titles - prev
                self._pid_windows_last[pid] = win_titles
                if new_titles:
                    events = self._pid_window_events.setdefault(pid, [])
                    # 按新增窗口"数量"计（而非轮次数）：5s 滑窗内累加
                    events.extend([now] * len(new_titles))
                    events[:] = [t for t in events
                                 if now - t <= _WINDOW_SLIDE_WINDOW]
                    if len(events) > _POPUP_WINDOWS_5S:
                        self._fire_hit(
                            'popup_storm', pid, observed[pid],
                            f'弹窗风暴：5 秒内新增 {len(events)} 个顶层窗口'
                            f'（{self._format_titles(new_titles)}）',
                            level='suspicious')

                # 兜底：进程树 spawn 速率（5s 派生 >10）
                if HAS_PSUTIL:
                    children = self._count_children(pid)
                    if children is not None:
                        prev_cnt = self._pid_spawn_last.get(pid, 0)
                        delta = children - prev_cnt
                        self._pid_spawn_last[pid] = children
                        if delta > 0:
                            spawns = self._pid_spawn_events.setdefault(pid, [])
                            spawns.extend([now] * delta)
                            spawns[:] = [t for t in spawns
                                         if now - t <= _WINDOW_SLIDE_WINDOW]
                            if len(spawns) > _POPUP_WINDOWS_5S:
                                self._fire_hit(
                                    'popup_storm', pid, observed[pid],
                                    f'进程spawn风暴：5 秒内派生 {len(spawns)} 个子进程',
                                    level='suspicious')
            except Exception as e:
                logger.debug(f'弹窗洪流检测 PID={pid} 异常: {e}')

    def _collect_top_windows_for_tree(self, pid: int) -> Set[str]:
        """收集 pid 树所有进程拥有的顶层窗口标题集合（Win32）。

        使用 EnumWindows + GetWindowThreadProcessId，把标题相同的
        并入集合去重（大量 Modal 弹出框标题一致，计数按标题集合计）。
        """
        if not HAS_CTYPES or sys.platform != 'win32':
            # 非 Windows 无法枚举窗口 → 用 psutil 打开的窗口句柄数量兜底
            try:
                proc = psutil.Process(pid) if HAS_PSUTIL else None
                if proc is None:
                    return set()
                titles = set()
                for c in [proc] + proc.children(recursive=True):
                    try:
                        for w in c.windows():
                            if w.title:
                                titles.add(w.title)
                    except Exception:
                        continue
                return titles
            except Exception:
                return set()

        user32 = ctypes.windll.user32
        tree = set(self._iter_pid_tree(pid))
        result: Set[str] = []

        @ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL,
                            ctypes.wintypes.HWND,
                            ctypes.wintypes.LPARAM)
        def _enum_cb(hwnd, lparam):
            try:
                if not user32.IsWindowVisible(hwnd):
                    return True
                pid_holder = ctypes.wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_holder))
                if pid_holder.value in tree:
                    # 排除空标题窗口（常见静默窗口），只计有标题的可见顶层窗
                    length = user32.GetWindowTextLengthW(hwnd)
                    if length > 0:
                        buf = ctypes.create_unicode_buffer(length + 1)
                        user32.GetWindowTextW(hwnd, buf, length + 1)
                        title = buf.value
                        if title:
                            result.append(title)
            except Exception:
                pass
            return True

        try:
            user32.EnumWindows(_enum_cb, 0)
        except Exception:
            pass
        # 标题去重（多个同名窗体 count=1，防止同 ID 弹一条刷 N 次）
        return set(result)

    def _count_children(self, pid: int) -> int:
        if not HAS_PSUTIL:
            return 0
        try:
            return len(psutil.Process(pid).children(recursive=True))
        except Exception:
            return 0

    @staticmethod
    def _format_titles(titles: Set[str], cap: int = 5) -> str:
        titles = [t for t in titles if t][:cap]
        return '; '.join(titles) if titles else '无标题窗口'

    # ------------------------------------------------------------- 信号2：桌面图标洪流
    def _iter_desktop_files(self):
        desktop = os.path.join(
            os.path.expanduser('~'), 'Desktop')
        try:
            if os.path.isdir(desktop):
                for fn in os.listdir(desktop):
                    yield fn
        except Exception:
            pass

    def _check_icon_flood(self, now: float):
        try:
            current = set(self._iter_desktop_files())
        except Exception:
            return
        if not self._desktop_snapshot:
            self._desktop_snapshot = current
            return
        new_icons = {
            fn for fn in (current - self._desktop_snapshot)
            if os.path.splitext(fn)[1].lower() in _ICON_EXTS
        }
        self._desktop_snapshot = (
            self._desktop_snapshot & current) | set(current)
        if new_icons:
            events = self._desktop_icon_events
            # 按新增图标"数量"计（而非轮次数）：1s/5s 滑窗内累加数量
            events.extend([now] * len(new_icons))
            events[:] = [t for t in events
                         if now - t <= _WINDOW_SLIDE_WINDOW + 1]
            # 1s 内 >3 或 5s 内 >10
            recent_1s = len([t for t in events if now - t <= 1.0])
            recent_5s = len(events)
            if recent_5s > _ICON_FLOOD_5S or recent_1s > _ICON_FLOOD_1S:
                self._fire_hit(
                    'icon_flood', None, None,
                    f'桌面图标洪流：5 秒内新增 {recent_5s} 个图标/脚本'
                    f'（1 秒 {recent_1s} 个）：{", ".join(list(new_icons)[:5])}',
                    level='suspicious')

    # ------------------------------------------------------------- 信号3：壁纸篡改
    def _read_wallpaper_state(self) -> Tuple[Optional[str], Optional[float]]:
        value = None
        mtime = None
        if HAS_CTYPES and sys.platform == 'win32':
            try:
                import winreg
                with winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER, _WALLPAPER_KEY) as key:
                    value, _ = winreg.QueryValueEx(key, _WALLPAPER_VALUE)
            except Exception:
                pass
        try:
            if _TRANSCODED_WALLPAPER and os.path.exists(_TRANSCODED_WALLPAPER):
                mtime = os.path.getmtime(_TRANSCODED_WALLPAPER)
        except Exception:
            pass
        return value, mtime

    def _refresh_wallpaper_baseline(self):
        self._wallpaper_last, self._transcoded_mtime_last = \
            self._read_wallpaper_state()

    def _check_wallpaper(self, observed: Dict[int, tuple], now: float):
        value, mtime = self._read_wallpaper_state()
        changed = False
        if self._transcoded_mtime_last is not None and mtime is not None \
                and abs(mtime - self._transcoded_mtime_last) > 0.05:
            changed = True
        elif value and self._wallpaper_last is not None \
                and value != self._wallpaper_last:
            changed = True
        self._wallpaper_last, self._transcoded_mtime_last = value, mtime
        if not changed:
            return
        # 壁纸变化：在近 10s 内注册且存活的观察进程 → 视为非信任 PE 篡改
        suspects = []
        seen = set()
        for pid, rec in list(observed.items()):
            if now - rec[3] > _WALLPAPER_LOOKBACK:
                continue
            if not HAS_PSUTIL:
                suspects.append((pid, rec[0], rec[1]))
                continue
            try:
                if not (psutil.pid_exists(pid)
                        and psutil.Process(pid).status()
                        != psutil.STATUS_ZOMBIE):
                    continue
            except Exception:
                continue
            exe_key = os.path.normcase(os.path.abspath(rec[0]))
            if exe_key in seen:
                continue
            seen.add(exe_key)
            suspects.append((pid, rec[0], rec[1]))
        if not suspects:
            # 无观察进程 → Windows 自带换壁纸通道/用户手动操作，忽略
            logger.debug('壁纸变化但近 10s 无观察进程，忽略（防误杀）')
            return
        # 只处置最早注册的嫌疑进程（最可能是主程序），避免多弹窗
        pid, exe, name = suspects[0]
        self._fire_hit(
            'wallpaper_tamper', pid, (exe, name, None, now),
            f'壁纸篡改：检测到桌面壁纸被替换（来源: {name}）',
            level='danger')

    # ------------------------------------------------------------- 信号4：系统自定义项批量更改
    def _read_reg_value(self, subkey: str, name: str) -> Optional[str]:
        if not HAS_CTYPES or sys.platform != 'win32':
            return None
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey) as key:
                v, _ = winreg.QueryValueEx(key, name)
                return repr(v)
        except Exception:
            return None

    def _read_settings_baseline(self) -> Dict[str, str]:
        baseline = {}
        for subkey, name, _default in _SETTING_BASELINE:
            baseline[f'{subkey}\\{name}'] = self._read_reg_value(subkey, name)
        return baseline

    def _check_settings_change(self, now: float):
        if self._setting_baseline is None:
            self._setting_baseline = self._read_settings_baseline()
            return
        current = {}
        for subkey, name, _default in _SETTING_BASELINE:
            current[f'{subkey}\\{name}'] = self._read_reg_value(subkey, name)
        total = len(self._setting_baseline)
        if total == 0:
            return
        changed = []
        for k, base_v in self._setting_baseline.items():
            # None -> None 视为未变化；None -> 值 或 值不同 视为变化
            cur_v = current.get(k)
            if base_v != cur_v:
                changed.append(k)
        # 滞回：一次性偏差（如用户主动换壁纸导致 1-2 项变化）不触发；
        # 只有超过 50% 项变化且持续被改动才命中，避免误报
        if len(changed) > 0:
            ratio = len(changed) / total
            if ratio > _SETTING_CHANGE_RATIO:
                last_ok = self._last_setting_identical
                if now - last_ok < 1.0:
                    # 连续两轮偏差 >50% → 命中
                    suspect = self._pick_suspect()
                    spid, srec = (suspect[0], suspect[1]) if suspect else (None, None)
                    self._fire_hit(
                        'settings_changed', spid, srec,
                        f'系统自定义项批量更改：{len(changed)}/{total} 项'
                        f'（>50%）被修改：{", ".join(changed[:5])}',
                        level='suspicious')
                else:
                    self._last_setting_identical = now
            else:
                self._last_setting_identical = now
        else:
            self._last_setting_identical = now

    # ------------------------------------------------------------- 命中分发
    def _fire_hit(self, hit_type: str, pid: Optional[int],
                  observed_rec: Optional[tuple], description: str,
                  level: str):
        """命中回调入口：去重 + 统计算入 + 先杀后问回调。"""
        exe = observed_rec[0] if observed_rec else None
        name = observed_rec[1] if observed_rec else '未知进程'
        cmdline = observed_rec[2] if observed_rec else None
        now = time.time()

        # 去重：同一 exe 相同信号 20s 内不重复命中（防止每轮刷屏）
        exe_key = ''
        if exe:
            try:
                exe_key = os.path.normcase(os.path.abspath(exe))
            except Exception:
                exe_key = ''
        for ts, htype, hexe in reversed(self._recent_hits):
            if now - ts > 20:
                break
            if htype != hit_type:
                continue
            # 同 exe 命中 → 去重；图标洪流等无归属 exe 的命中 → 按信号节流
            if not hexe and not exe_key:
                logger.info(
                    f'视觉恶搞检测：{hit_type} 已在 30s 内处理（无归属进程），节流')
                return
            if hexe and exe_key and hexe == exe_key:
                logger.info(
                    f'视觉恶搞检测：{hit_type} 命中 {name} 已在 30s 内处理，去重')
                return
        self._recent_hits.append((now, hit_type, exe_key))
        if len(self._recent_hits) > 50:
            self._recent_hits = self._recent_hits[-50:]

        with self._stats_lock:
            self._stats[hit_type] = self._stats.get(hit_type, 0) + 1

        logger.warning(
            f'视觉恶搞检测命中 [{hit_type}] level={level} 目标={name} '
            f'exe={exe} desc={description}')

        evidence = {
            'type': 'visual_prank_hit',
            'signal': hit_type,
            'level': level,
            'pid': pid or 0,
            'name': name,
            'exe': exe or '',
            'cmdline': cmdline,
            'description': description,
            'ts': now,
        }

        # 第一步：立即终止（kill-then-ask 的前半段）
        kill_ok = False
        if self._kill_hook:
            try:
                kill_ok = bool(self._kill_hook(exe or '', pid or 0))
            except Exception as e:
                logger.warning(f'视觉恶搞检测：kill_hook 异常: {e}')
        evidence['killed'] = bool(kill_ok)

        # 第二步：询问用户是否信任重启（后半段由桥接层弹窗）
        if self._on_visual_prank:
            try:
                self._on_visual_prank(evidence)
            except Exception as e:
                logger.warning(f'视觉恶搞检测：on_visual_prank 回调异常: {e}')

    def close(self):
        """兼容 stop() 的别名（同停止轮询线程）。"""
        self.stop()