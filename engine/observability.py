# -*- coding: utf-8 -*-
"""
可观测性中心 (ObservabilityHub)

集中式事件/指标埋点与心跳聚合，供各引擎轻量上报、前端状态页/诊断拉取。

设计：
- 进程内单例，thread-safe；埋点只做自增/追加，<1µs，绝不阻塞业务线程。
- 计数器（累加） + 环形事件缓冲（最近 N 条，按 level 分级）+ 心跳时间戳。
- 纯内存、无 IO，崩溃诊断依赖外部 faulthandler/日志，此处不持锁外放。

用法：
    from engine.observability import hub
    hub.incr('scan.files'); hub.event('scan.threat', level='warn')
    stats = hub.snapshot()
"""

import threading
import time
from collections import deque
from typing import Callable, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger('observability')

# 事件级别（与 notification_level 对齐，前端可分级上色）
_LEVELS = ('info', 'warn', 'critical')


class ObservabilityHub:
    """集中式指标/事件/心跳聚合器（线程安全）。"""

    MAX_EVENTS = 512  # 环形事件缓冲上限

    def __init__(self):
        self._counters: Dict[str, int] = {}
        self._gauges: Dict[str, float] = {}
        self._events: deque = deque(maxlen=self.MAX_EVENTS)
        self._lock = threading.RLock()
        self._started_at = time.time()
        self._heartbeat_ts = self._started_at
        self._heartbeat_thread = None
        self._stop = threading.Event()

    # ---- 埋点 ----
    def incr(self, key: str, n: int = 1) -> None:
        """累加计数器（key 自动按 '.' 前缀归类）。"""
        if not key:
            return
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + int(n)

    def set_gauge(self, key: str, value: float) -> None:
        """设置瞬时指标（如当前受监控文件数/缓存规模）。"""
        with self._lock:
            self._gauges[key] = float(value)

    def event(self, category: str, message: str = '',
              level: str = 'info') -> None:
        """推送一条事件（不可变快照入环形缓冲）。"""
        if level not in _LEVELS:
            level = 'info'
        rec = {
            'ts': time.time(),
            'category': str(category)[:40],
            'message': str(message)[:200],
            'level': level,
        }
        with self._lock:
            self._events.append(rec)

    def heartbeat(self, source: str = 'default') -> None:
        """记录一次心跳（调用方周期性上报，表示该部件存活）。"""
        with self._lock:
            self._heartbeat_ts = time.time()
        self.incr(f'heartbeat.{source}')

    # ---- 读取 ----
    def snapshot(self) -> dict:
        with self._lock:
            return {
                'started_at': self._started_at,
                'now': time.time(),
                'uptime': time.time() - self._started_at,
                'last_heartbeat_ts': self._heartbeat_ts,
                'heartbeat_age_s': round(time.time() - self._heartbeat_ts, 2),
                'counters': dict(self._counters),
                'gauges': dict(self._gauges),
                'recent_events': list(self._events)[-100:],  # 最近 100 条(快照)
            }

    def counters(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def clear(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._events.clear()


# ---- 注册外部 sink：把事件同步转发前端/日志（可选，不阻塞）----
_sinks: List[Callable[[dict], None]] = []
_sinks_lock = threading.Lock()


def register_event_sink(fn: Callable[[dict], None]) -> None:
    """注册事件 sink（如 bridge 转发前端）。空实现幂等。"""
    with _sinks_lock:
        if fn not in _sinks:
            _sinks.append(fn)


def _event_to_sinks(rec: dict) -> None:
    with _sinks_lock:
        targets = list(_sinks)
    for fn in targets:
        try:
            fn(rec)
        except Exception:
            pass


# 单例
_hub: Optional[ObservabilityHub] = None
_hub_lock = threading.Lock()


def get_hub() -> ObservabilityHub:
    global _hub
    if _hub is None:
        with _hub_lock:
            if _hub is None:
                _hub = ObservabilityHub()
    return _hub


hub = get_hub()