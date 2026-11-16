# -*- coding: utf-8 -*-
"""
行为启发分析器 (BehaviorAnalyzer)

在既有"单点/静态信号"之外，补充**运行期时间窗事件序列**证据：按 PID 聚合一段
窗口内(默认 30s)的进程创建/退出、句柄注入、文件写路径、注册表持久化、联网等
行为，输出综合行为置信，供扫描瀑布/进程监控升级处置。

设计要点：
- **跨时序为主、即时处置为辅**：复现 project 内部 `_dropload_chain`(落地-加载-
  持久化) 的"跨事件链打分"先例，泛化为通用聚合器。
- **minimize FP**：仅对"无有效签名 + 非白名单 + 父进程非可信宿主"的行序列计分；
  每条升级规则必须同时命中 ≥2 个行为维度，杜绝单维度误报。
- **线程安全/性能**：按 PID 桶细粒度短锁，写锁 <1µs(纯 append)；判定在调用线程
  只读。硬上限：单 PID 事件 ≥ 128 条拒新增，全局 ≥ 512 条逐 PID 退役；懒过期。
- 本模块**只读消费** process_protection 的既有判定产出(注入双信号等)，不重复实现
  内存扫描/注入判定。
"""

import os
import sys
import time
import threading
from typing import Dict, List, Optional, Set, Tuple

from utils.logger import get_logger

logger = get_logger('behavior_analyzer')


# ---- 可信宿主进程名(父进程是这些则不按"无签名非可信"计分) ----
_TRUSTED_HOST_NAMES: Tuple[str, ...] = (
    'svchost.exe', 'explorer.exe', 'services.exe', 'csrss.exe',
    'winlogon.exe', 'lsass.exe', 'System', 'registry',
)

# ---- 脚本解释器(作为"父脚本"判定) ----
_SCRIPT_INTERP_NAMES: Tuple[str, ...] = (
    'python', 'wscript', 'cscript', 'powershell', 'pwsh', 'cmd', 'mshta',
)

# ---- 注册表持久化点关键词 ----
_REG_PERSIST_MARKS: Tuple[str, ...] = (
    r'\run\runonce', r'currentversion\run',
    r'\startup', r'\shell\startup', r'services',
)
_REG_PERSIST_MARKS2: Tuple[str, ...] = (r'run', r'runonce', r'startup')

# ---- 路径目录分类 ----
_SYSTEM_DIRS: Tuple[str, ...] = (r'%systemroot%\system32', r'\windows\system32', r'\windows')
_TEMP_DIRS: Tuple[str, ...] = (r'\temp', r'\appdata\local\temp', r'\tmp')
_DOWNLOAD_DIRS: Tuple[str, ...] = (r'\downloads',)


def _norm_lower(s: str) -> str:
    try:
        return (s or '').lower().replace('/', '\\')
    except Exception:
        return (s or '').lower()


def _is_system_path(p: str) -> bool:
    pl = _norm_lower(p)
    return any(m in pl for m in _SYSTEM_DIRS)


def _is_temp_path(p: str) -> bool:
    pl = _norm_lower(p)
    return any(m in pl for m in _TEMP_DIRS)


def _is_download_path(p: str) -> bool:
    pl = _norm_lower(p)
    return any(m in pl for m in _DOWNLOAD_DIRS)


def _is_reg_persist_path(p: str) -> bool:
    pl = _norm_lower(p)
    if any(m in pl for m in _REG_PERSIST_MARKS):
        return True
    return any(m in pl for m in _REG_PERSIST_MARKS2)


class BehaviorAnalyzer:
    """时间窗行为事件聚合器。线程安全(按 PID 桶短锁)。"""

    # ---- 常量 ----
    DEFAULT_WINDOW = 30.0            # 秒, 时间窗
    MAX_PER_PID_EVENTS = 128         # 单 PID 事件上限(达到拒新增)
    MAX_TOTAL_ENTRIES = 512          # 全局 PID 条目上限
    MAX_PIDS = 256

    # 升级规则触发项阈值
    SYS_EXE_WRITE_MIN = 2            # 30s 内向系统目录写 exe ≥2 次
    CHILD_CHAIN_DEPTH = 3            # 无签名子进程链深度
    INJECT_SAME_MIN = 3              # 同一目标注入 ≥N 次

    def __init__(self, window: float = DEFAULT_WINDOW):
        self._window = window
        # pid -> {'name','exe','parent','t0','last', 'signed', 'parent_signed'}
        self._proc_meta: Dict[int, dict] = {}
        # pid -> {'writes':[ts...], 'writes_exe_sys':int, 'reg_persist':[ts],
        #         'net':[ts], 'inject':{(src,tgt):cnt}, 'children':set, 'exited':bool}
        self._per_pid: Dict[int, dict] = {}
        self._lock = threading.RLock()

    # ---------- 内部工具 ----------
    def _now(self) -> float:
        return time.time()

    def _evict_expired(self, now: float):
        """懒过期：清掉超过窗口无活动的 PID 条目(尽力而为，不持长锁)。"""
        stale = []
        for pid, meta in self._proc_meta.items():
            if now - meta.get('last', 0.0) > self._window:
                stale.append(pid)
        for pid in stale:
            self._proc_meta.pop(pid, None)
            self._per_pid.pop(pid, None)

    def _ensure_pid(self, pid: int, meta: Optional[dict] = None) -> dict:
        if pid not in self._per_pid:
            self._per_pid[pid] = {
                'writes': [], 'writes_exe_sys': 0,
                'reg_persist': [], 'net': [], 'inject_cnt': 0,
                'inject_targets': {}, 'children': set(), 'exited': False,
            }
        if meta is not None and pid not in self._proc_meta:
            self._proc_meta[pid] = meta
        return self._per_pid[pid]

    def __len__(self) -> int:
        with self._lock:
            return len(self._proc_meta)

    # ---------- 喂入点(纯转发, 不改产生端) ----------
    def feed_process_start(self, pid: int, name: str = '', exe: str = '',
                           parent_pid: int = 0):
        """新进程创建。parent_signed 由上层在可判定时补传(见 _set_parent_signed)。"""
        if not pid or pid <= 0:
            return
        now = self._now()
        with self._lock:
            self._evict_expired(now)
            if pid in self._proc_meta:
                self._proc_meta[pid]['last'] = now
                return
            meta = {'name': (name or '').lower(), 'exe': exe or '', 'parent': int(parent_pid or 0),
                    't0': now, 'last': now, 'signed': None, 'parent_signed': None}
            self._ensure_pid(pid, meta)
            # 子进程链记录
            if parent_pid and parent_pid != pid and parent_pid in self._per_pid:
                try:
                    self._per_pid[parent_pid]['children'].add(pid)
                except KeyError:
                    pass

    def _set_parent_signed(self, pid: int, parent_pid: int, signed: Optional[bool],
                           parent_signed: Optional[bool]):
        """补充签名状态(扫描/签名判定结果异步返回后回填；None=未知)。"""
        if not pid:
            return
        with self._lock:
            meta = self._proc_meta.get(pid)
            if meta is not None:
                if signed is not None:
                    meta['signed'] = bool(signed)
                if parent_signed is not None:
                    meta['parent_signed'] = bool(parent_signed)

    def feed_process_exit(self, pid: int):
        if not pid:
            return
        with self._lock:
            m = self._per_pid.get(pid)
            if m is not None:
                m['exited'] = True
                m['writes'] = []
                m['reg_persist'] = []
                m['net'] = []

    def feed_file_write(self, pid: int, path: str):
        """文件写(落地)事件。path 全路径。记录系统目录 exe 写 / temp / download。"""
        if not pid or pid <= 0:
            return
        now = self._now()
        with self._lock:
            m = self._ensure_pid(pid)
            if len(m['writes']) >= self.MAX_PER_PID_EVENTS:
                return
            m['writes'].append((now, path or ''))
            pl = _norm_lower(path or '')
            if pl.endswith('.exe') and _is_system_path(pl):
                m['writes_exe_sys'] += 1
            # downloads 单独标记用于佐证规则
            if _is_download_path(pl):
                m.setdefault('download_writes', 0)
                m['download_writes'] = m.get('download_writes', 0) + 1

    def feed_reg_persist(self, pid: int, key_path: str):
        """注册表持久化点写入(key/键路径)。"""
        if not pid or pid <= 0:
            return
        now = self._now()
        with self._lock:
            m = self._ensure_pid(pid)
            if len(m['reg_persist']) >= self.MAX_PER_PID_EVENTS:
                return
            m['reg_persist'].append((now, key_path or ''))

    def feed_net_conn(self, pid: int, remote: str = ''):
        """联网事件(remote 地址/域名)。"""
        if not pid or pid <= 0:
            return
        now = self._now()
        with self._lock:
            m = self._ensure_pid(pid)
            if len(m['net']) >= self.MAX_PER_PID_EVENTS:
                return
            m['net'].append((now, remote or ''))

    def feed_handle_audit(self, src_pid: int, target_pid: int, access: int = 0):
        """句柄审计事件(源自驱动 OB_CALLBACKS)。只读消费注入信号，不作判定。"""
        if not src_pid or src_pid <= 0:
            return
        now = self._now()
        with self._lock:
            m = self._ensure_pid(src_pid)
            m['inject_cnt'] = m.get('inject_cnt', 0) + 1
            tg = int(target_pid or 0)
            m['inject_targets'][tg] = m['inject_targets'].get(tg, 0) + 1

    # ---------- 判定 ----------
    def _is_script_interp(self, name: str) -> bool:
        n = _norm_lower(name)
        return any(i in n for i in _SCRIPT_INTERP_NAMES)

    def _is_trusted_host(self, name: str) -> bool:
        n = _norm_lower(name)
        return any(h in n for h in _TRUSTED_HOST_NAMES)

    def _count_in_window(self, lst: List[Tuple[float, object]], now: float) -> int:
        return sum(1 for t, _ in lst if now - t <= self._window)

    def evaluate(self, pid: int, context: Optional[dict] = None) -> dict:
        """对单个 PID 做时间窗行为评估。纯计算+只读快照，无锁外 IO。

        context 可选覆盖: {'signed':bool, 'parent_signed':bool}。

        Returns:
            {'behavior_chain': 0-100, 'behavior_rules': [ids], 'behavior_confirmed': bool}
        """
        if not pid or pid <= 0:
            return {'behavior_chain': 0.0, 'behavior_rules': [], 'behavior_confirmed': False}
        now = self._now()
        with self._lock:
            meta = dict(self._proc_meta.get(pid) or {})
            m = dict(self._per_pid.get(pid) or {})
            writes = list(m.get('writes', []))
            reg = list(m.get('reg_persist', []))
            nets = list(m.get('net', []))
            inject_cnt = int(m.get('inject_cnt', 0))
            inject_targets = dict(m.get('inject_targets', {}))
            children = set(m.get('children', set()))
            writes_exe_sys = int(m.get('writes_exe_sys', 0))
            download_writes = int(m.get('download_writes', 0))
            exited = bool(m.get('exited', False))

        # ---- 签名闸：无有效签名/非白名单才计分(上层已过滤，这里兜底) ----
        signed = meta.get('signed')
        if context is not None:
            if context.get('signed') is not None:
                signed = context['signed']
            if context.get('parent_signed') is not None:
                meta['parent_signed'] = context['parent_signed']
        parent_signed = meta.get('parent_signed')

        # 父进程是否可信宿主：查父 PID 的 meta(name/exe)。父为系统宿主(svchost/
        # explorer/services...) → 子进程属正常系统调用，不按行为升级。
        parent_is_trusted = False
        parent_interp = False
        with self._lock:
            ppid = meta.get('parent')
            if ppid and ppid in self._proc_meta:
                pmeta = self._proc_meta[ppid]
                pname = pmeta.get('name') or ''
                pexe = pmeta.get('exe') or pname
                parent_is_trusted = self._is_trusted_host(pexe)
                parent_interp = self._is_script_interp(pname) or self._is_script_interp(pexe)

        # 可判定为"签名有效"或"父可信宿主" → 不触发行为升级。
        # (无签名/签名未知 → signed=None → 继续按行为序列评估，即"送检")
        if signed is True or parent_is_trusted:
            return {'behavior_chain': 0.0, 'behavior_rules': [], 'behavior_confirmed': False}

        # ---- 维度统计(窗口内) ----
        w_sys_exe = writes_exe_sys          # 已按次累加
        w_count = self._count_in_window(writes, now)
        reg_count = self._count_in_window(reg, now)
        net_count = self._count_in_window(nets, now)
        interp_parent = parent_interp

        rules: List[str] = []
        confirmed = False

        # R1 确认级：无签名子进程 30s 内向系统目录写 exe≥2 + 写持久化点
        if w_sys_exe >= self.SYS_EXE_WRITE_MIN and reg_count >= 1:
            rules.append('persist_dropload')
            confirmed = True

        # R2 确认级：父=脚本解释器 且 向非可信子进程注入句柄(注入双信号)
        if interp_parent and inject_cnt >= 1:
            # 注入目标非可信(签名闸已通过当前 pid 无签名)
            rules.append('script_inject')
            confirmed = True

        # R3 确认级：temp写入→注册表自启动→联网, 三者均有且无签名
        has_temp = any(_is_temp_path(p) for _, p in writes)
        if has_temp and reg_count >= 1 and net_count >= 1:
            rules.append('temp_reg_c2')
            confirmed = True

        # 佐证级 R4：子进程链 ≥3 且全无签名 + 父写下载目录
        chain_depth = self._chain_depth(pid)
        if chain_depth >= self.CHILD_CHAIN_DEPTH and download_writes >= 1:
            rules.append('deep_child_download')

        # 佐证级 R5：同一目标注入 ≥N 次
        max_tgt = max(inject_targets.values()) if inject_targets else 0
        if max_tgt >= self.INJECT_SAME_MIN:
            rules.append('repeat_inject')

        # ---- 置信分(佐证信号累加) ----
        chain = 0.0
        if 'deep_child_download' in rules:
            chain += 40.0
        if 'repeat_inject' in rules:
            chain += 45.0
        # 确认级条目同时计入 chain 供上层展示
        if confirmed:
            chain = max(chain, 90.0)

        return {
            'behavior_chain': min(100.0, chain),
            'behavior_rules': rules,
            'behavior_confirmed': bool(confirmed),
        }

    def _chain_depth(self, pid: int) -> int:
        """自 pid 向上追溯父链深度(尽量向上，直到不可查)。只读。"""
        depth = 0
        with self._lock:
            cur = pid
            seen = set()
            while cur and cur not in seen and depth < 8:
                seen.add(cur)
                meta = self._proc_meta.get(cur)
                if not meta:
                    break
                parent = meta.get('parent')
                if not parent or parent == cur:
                    break
                depth += 1
                cur = parent
        return depth

    def snapshot_for_scan(self, pid: Optional[int] = None,
                          file_path: str = '', file_hash: str = '') -> dict:
        """扫描侧按需查询。无 PID 时返回空(行为是进程维度, 文件扫描通常无 PID)。

        上层(process_protection)持 PID 语义调用 evaluate 后，把产出传给
        scan_file 的 behavior 参数即可。此处做简洁封装。
        """
        if not pid or pid <= 0:
            return {'behavior_chain': 0.0, 'behavior_rules': [], 'behavior_confirmed': False}
        return self.evaluate(pid)

    def report_stats(self) -> dict:
        with self._lock:
            return {
                'pids': len(self._proc_meta),
                'entries': len(self._per_pid),
                'max': self.MAX_TOTAL_ENTRIES,
                'window': self._window,
            }