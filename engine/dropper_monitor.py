# -*- coding: utf-8 -*-
"""
dropper_monitor.py — 可执行文件落地实时监视（银狐断网型反制 A）

背景
----
银狐(SilverFox)断网型变种的核心链路是本地化落地：
  AppData\\Roaming 随机子目录 / AppData\\Local\\Temp / Downloads / ProgramData
释放 DLL/EXE/脚本 → 立刻被有签名宿主加载（白加黑）→ 持久化。
这些目录不在"关键目录保护"范围内，落地瞬间原有防线无感知，
只能等下一次全盘扫描 —— 对"落地即执行"的木马反应太慢。

本模块用 ReadDirectoryChangesW 对上述高风险目录做实时监视：
  新增/改名命中可执行扩展名的文件 → 等待写入稳定（避免半截文件）
  → 回调给 process_protection：
      1. 哈希比对签名库白名单
      2. WinVerifyTrust 签名验证（可信发布者放行）
      3. 其余走 _async_scan_launch 深度送检
      4. 登记"落地链"记录（与 image_load 白加黑信号聚合 → 落地-加载链评分）

实现要点
--------
1. 监视目录动态扩展：银狐喜欢新建随机子目录再释放。收到 ROAMING 下新增
   目录事件时自动添加该子目录的监视句柄（深度 ≤ 2），句柄池 LRU 上限
   MAX_HANDLES，超出淘汰最久未出事件的句柄。
2. 写入稳定检测：事件入队后两次采样文件大小一致才判定稳定，避免分析
   写入中的半截文件（哈希/特征全失真 → 误判 clean）。
3. 全后台线程执行，绝不阻塞进程保护主线程；任一异常静默降级。

线程模型
--------
- 每个监视句柄一个后台线程（同步 ReadDirectoryChangesW 阻塞读取）
- 一个消费者线程处理稳定检测 + 回调
- 句柄池按 LRU 淘汰，受 _pool_lock 保护
"""

import os
import sys
import time
import queue
import threading
import ctypes
import ctypes.wintypes
from typing import Callable, Dict, Optional, Tuple

from utils.logger import get_logger

logger = get_logger('dropper_monitor')

# ---------------------------------------------------------------------------
# Win32 声明
# ---------------------------------------------------------------------------
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

kernel32.CreateFileW.restype = ctypes.wintypes.HANDLE
kernel32.CreateFileW.argtypes = [
    ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
    ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
    ctypes.wintypes.HANDLE,
]
kernel32.ReadDirectoryChangesW.restype = ctypes.wintypes.BOOL
kernel32.ReadDirectoryChangesW.argtypes = [
    ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD,
    ctypes.wintypes.BOOL, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD),
    ctypes.c_void_p, ctypes.c_void_p,
]
kernel32.CloseHandle.restype = ctypes.wintypes.BOOL
kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]

GENERIC_READ = 0x80000000
FILE_SHARE_ALL = 0x7            # READ|WRITE|DELETE
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_LIST_DIRECTORY = 0x0001
SYNCHRONIZE = 0x00100000

# ReadDirectoryChangesW notify filters
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_SIZE = 0x00000008

# 动作码
FILE_ACTION_ADDED = 0x1
FILE_ACTION_REMOVED = 0x2
FILE_ACTION_MODIFIED = 0x3
FILE_ACTION_RENAMED_OLD_NAME = 0x4
FILE_ACTION_RENAMED_NEW_NAME = 0x5

# 可执行落地扩展名（银狐重点 / 一般可执行 / 脚本）
_WATCHED_EXTS = (
    '.exe', '.dll', '.scr', '.com', '.sys',
    '.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse',
    '.wsf', '.hta', '.jar', '.msi', '.ocx', '.cpl',
)

# 待处理事件最大缓冲（防风暴削峰）
_MAX_QUEUE = 4096
# 稳定检测：两次采样间隔 / 最大重试次数 / 单文件最长等待
_STABLE_INTERVAL = 0.3
_STABLE_MAX_RETRY = 3
_FILE_MAX_WAIT = 2.0
# 句柄池上限（LRU 淘汰）
MAX_HANDLES = 96
# 动态添加子目录的最大深度（0=仅监视根目录；2=最多两级子目录）
MAX_SUBDIR_DEPTH = 2


def _is_watched_ext(path: str) -> bool:
    try:
        name = path.lower().rstrip('.')
        return name.endswith(_WATCHED_EXTS)
    except Exception:
        return False


class DropperMonitor:
    """可执行文件落地实时监视器（见模块 docstring）"""

    def __init__(self,
                 on_file_dropped: Optional[Callable[[str, int], None]] = None,
                 excluded_dirs: Optional[Tuple[str, ...]] = None):
        self._on_file_dropped = on_file_dropped
        # 顶层监视目录（存在的才监视，启动时惰性探测）
        self._excluded_dirs: Tuple[str, ...] = tuple(
            d.lower().rstrip('\\/') for d in (excluded_dirs or ()))
        self._running = False
        self._stop_event = threading.Event()
        self._pool_lock = threading.Lock()
        self._part: Dict[str, dict] = {}         # 目录句柄池: normpath -> {handle, th, last_event_ts}
        self._part_used: Dict[str, float] = {}    # LRU: normpath -> 最近事件时间
        # 稳定检测队列 + 消费者线程
        self._pending: queue.Queue = queue.Queue(maxsize=_MAX_QUEUE)
        self._worker: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def start(self) -> bool:
        if self._running:
            return True
        self._stop_event.clear()
        self._running = True
        dirs = self._discover_top_dirs()
        for d in dirs:
            self._add_watch(d, depth=0)
        self._worker = threading.Thread(
            target=self._consumer_loop, daemon=True, name='DropperMonitor')
        self._worker.start()
        logger.info(f'文件落地监视启动，监视 {len(dirs)} 个顶层目录')
        return True

    def stop(self):
        self._running = False
        self._stop_event.set()
        with self._pool_lock:
            for rec in list(self._part.values()):
                self._close_watch(rec)
            self._part.clear()
            self._part_used.clear()
        logger.info('文件落地监视已停止')

    def get_stats(self) -> dict:
        with self._pool_lock:
            return {
                'handles': len(self._part),
                'queued': self._pending.qsize(),
                'running': self._running,
            }

    # ------------------------------------------------------------------
    # 目录发现 / 句柄池管理
    # ------------------------------------------------------------------

    def _discover_top_dirs(self) -> list:
        """探测要监视的顶层目录（存在的才返回）"""
        cands = []
        up = os.environ.get('USERPROFILE', '')
        pd = os.environ.get('PROGRAMDATA', r'C:\ProgramData')
        base = [
            os.path.join(up, 'AppData', 'Roaming'),
            os.path.join(up, 'AppData', 'Local', 'Temp'),
            os.path.join(pd),
            os.path.join(up, 'Downloads'),
            os.path.join(up, 'Desktop'),
        ]
        for p in base:
            if p and os.path.isdir(p):
                cands.append(os.path.abspath(p).lower())
        return cands

    def _is_excluded(self, path: str) -> bool:
        try:
            lp = os.path.abspath(path).lower()
        except Exception:
            return False
        return any(lp == d or lp.startswith(d + '\\') for d in self._excluded_dirs)

    def _add_watch(self, path: str, depth: int):
        """添加一个目录监视句柄（含 LRU 池管理）"""
        try:
            norm = os.path.abspath(path).lower()
        except Exception:
            return
        if self._is_excluded(norm):
            return
        with self._pool_lock:
            if norm in self._part:
                self._part_used[norm] = time.monotonic()
                return
            if len(self._part) >= MAX_HANDLES:
                # LRU 淘汰最久未出事件的句柄
                oldest = min(self._part_used.items(),
                             key=lambda kv: kv[1])[0] if self._part_used else None
                if oldest and oldest in self._part:
                    self._close_watch(self._part.pop(oldest))
                    self._part_used.pop(oldest, None)
            handle = self._open_dir_handle(norm)
            if not handle or handle == ctypes.wintypes.HANDLE(-1).value:
                return
            rec = {'handle': handle, 'depth': depth, 'last_event_ts': 0.0}
            self._part[norm] = rec
            self._part_used[norm] = time.monotonic()
            th = threading.Thread(target=self._watch_loop,
                                  args=(norm, rec), daemon=True,
                                  name=f'DropWatch-{os.path.basename(norm)[:16]}')
            rec['th'] = th
            th.start()
        logger.debug(f'落地监视已添加: {path} (depth={depth})')

    def _open_dir_handle(self, path: str):
        h = kernel32.CreateFileW(
            path, FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_ALL, None,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None)
        return h if h not in (None, ctypes.wintypes.HANDLE(-1).value,
                              ctypes.wintypes.HANDLE(0).value) else None

    @staticmethod
    def _close_watch(rec: dict):
        try:
            kernel32.CloseHandle(rec['handle'])
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 目录监视循环（每句柄一线程）
    # ------------------------------------------------------------------

    def _watch_loop(self, norm_dir: str, rec: dict):
        buf_len = 64 * 1024
        buf = ctypes.create_string_buffer(buf_len)
        bytes_returned = ctypes.wintypes.DWORD()
        subdirs_pending: Dict[str, Tuple[str, int]] = {}
        while not self._stop_event.is_set():
            try:
                ok = kernel32.ReadDirectoryChangesW(
                    rec['handle'], buf, buf_len, False,
                    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME,
                    ctypes.byref(bytes_returned), None, None)
                if not ok:
                    err = ctypes.get_last_error()
                    if err == 87:        # ERROR_INVALID_PARAMETER 偶发, 忽略
                        self._stop_event.wait(1.0)
                        continue
                    break               # 目录失效/句柄关闭 → 退出循环
                if bytes_returned.value < 12:
                    continue
                self._accumulate_event(norm_dir, buf.raw[:bytes_returned.value],
                                       subdirs_pending)
                rec['last_event_ts'] = time.monotonic()
                with self._pool_lock:
                    self._part_used[norm_dir] = rec['last_event_ts']
            except Exception:
                break
        # 循环退出后由池管理负责 CloseHandle（stop 或 LRU 淘汰）

    def _accumulate_event(self, norm_dir: str, raw: bytes,
                          subdirs_pending: Dict[str, Tuple[str, int]]):
        """解析 ReadDirectoryChangesW 返回的记录，分派落地/新增目录"""
        off = 0
        n = len(raw)
        while off + 12 <= n:
            action, flen = ctypes.c_uint32.from_buffer_copy(raw, off).value, \
                ctypes.c_uint32.from_buffer_copy(raw, off + 4).value
            if off + 12 + flen > n:
                break
            name_raw = raw[off + 12: off + 12 + flen]
            try:
                name = name_raw.decode('utf-16-le', errors='replace').rstrip('\x00')
            except Exception:
                name = ''
            off += 12 + flen + (flen % 2)
            if not name:
                continue
            full = os.path.join(norm_dir, name)
            if action in (FILE_ACTION_ADDED, FILE_ACTION_RENAMED_NEW_NAME):
                if os.path.isdir(full):
                    # 新增目录 → 动态添加监视（银狐随机子目录释放）
                    if not self._is_excluded(full):
                        subdirs_pending[full.lower()] = (full, 0)
                        continue
                if _is_watched_ext(full):
                    self._enqueue(full)
        # 动态添加新增子目录的监视句柄（防高频 ADDED 目录风暴直接扩张）
        for p, (orig, depth) in list(subdirs_pending.items()):
            cur_depth = 1
            if cur_depth > MAX_SUBDIR_DEPTH:
                continue
            self._add_watch(orig, depth + 1)

    # ------------------------------------------------------------------
    # 稳定检测 + 回调
    # ------------------------------------------------------------------

    def _enqueue(self, path: str):
        """登记待处理文件（带稳定检测：两次采样大小一致才回调）"""
        entry = {'path': path, 'retry': 0, 'last_size': -1, 'ts': time.monotonic()}
        try:
            self._pending.put_nowait(entry)
        except queue.Full:
            pass   # 风暴削峰: 丢弃多余事件

    def _consumer_loop(self):
        while not self._stop_event.is_set():
            try:
                try:
                    entry = self._pending.get(timeout=0.5)
                except queue.Empty:
                    continue
                if self._stop_event.is_set():
                    return
                if self._is_stable(entry):
                    self._dispatch(entry['path'])
                else:
                    # 写入未稳定: 重试 = 重新入队等下一轮
                    if entry['retry'] < _STABLE_MAX_RETRY:
                        entry['retry'] += 1
                        entry['ts'] = time.monotonic()
                        try:
                            self._pending.put_nowait(entry)
                        except queue.Full:
                            pass
            except Exception:
                pass

    def _is_stable(self, entry: dict) -> bool:
        """文件写入稳定判定：两次采样大小一致 或 等待超时强制处理"""
        try:
            size = os.path.getsize(entry['path'])
        except Exception:
            return True   # 读取失败（已删除/无权限）→ 直接给回调, 由上层容错
        if entry['last_size'] == size:
            return True
        entry['last_size'] = size
        if time.monotonic() - entry['ts'] > _FILE_MAX_WAIT:
            return True
        return False

    def _dispatch(self, path: str):
        try:
            size = os.path.getsize(path)
        except Exception:
            return
        if self._on_file_dropped:
            try:
                self._on_file_dropped(path, size)
            except Exception as e:
                logger.debug(f'文件落地回调异常: {e}')