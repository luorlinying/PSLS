# -*- coding: utf-8 -*-
"""initiator_exclusions.py — 发起者排除名单（借鉴 Xdows Driver 的 INITIATOR_EXCLUSION 语义）

用途：
  在**用户态决策链**（启动监测 → 沙箱 → 终止/隔离）前按"发起者/目标镜像"过滤，
  命中即跳过本次用户态处置（直接放行），但**不关闭内核侧硬规则**
  （如受保护目录写入拦截、MBR/引导防护仍照常生效）。

为什么需要：
  1. 宿主进程：PSLS 可能被 Electron/IDE 类宿主拉起，宿主目录内大量无签名二进制
     若进入判定链会被误杀（实测曾把宿主 IDE 自己隔离）；
  2. 大型正常程序：Electron 应用/游戏等动辄 100~300MB，误报代价极高；
  3. 与内核解耦：名单是**数据**，改名单不需要重签驱动。

匹配种类（kind）：
  name        镜像名精确匹配（忽略大小写）
  name_glob   镜像名通配匹配（fnmatch，如 "trae*.exe"）
  path_prefix 完整路径前缀匹配（规范化大小写，覆盖整棵目录）
  path_suffix 完整路径后缀匹配（如 "\\resources\\app\\"）

存储：%APPDATA%\\PSLS\\exclusions.json（稳定路径，只存用户新增项；
      内置项与动态项（宿主目录）在运行时合并，不写盘）。
"""

import fnmatch
import json
import os
import sys

from utils.logger import get_logger

logger = get_logger('initiator_exclusions')

_KINDS = ('name', 'name_glob', 'path_prefix', 'path_suffix')


def _registry_path() -> str:
    """用户排除项存储路径（稳定，不受隔离目录/安装位置影响）。"""
    if sys.platform == 'win32':
        appdata = os.environ.get('APPDATA') or os.path.expanduser('~')
    else:
        appdata = os.path.expanduser('~/.config')
    psls_dir = os.path.join(appdata, 'PSLS')
    try:
        os.makedirs(psls_dir, exist_ok=True)
    except Exception:
        pass
    return os.path.join(psls_dir, 'exclusions.json')


def _norm(path: str) -> str:
    try:
        return os.path.normcase(os.path.abspath(path))
    except Exception:
        return str(path or '').lower()


def _builtin_entries() -> list:
    """内置排除项：PSLS 自身相关（自身目录/进程名）。"""
    entries = [
        {'kind': 'name', 'value': 'psls.exe', 'reason': 'PSLS 自身进程'},
        {'kind': 'name', 'value': 'mlworker.exe', 'reason': 'PSLS 子进程(ML Worker)'},
        {'kind': 'name_glob', 'value': 'project sertraline lab*.exe',
         'reason': 'PSLS 安装包/启动器'},
    ]
    try:
        if getattr(sys, 'frozen', False):
            self_dir = os.path.dirname(os.path.abspath(sys.executable))
        else:
            self_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if self_dir:
            entries.append({'kind': 'path_prefix', 'value': self_dir,
                            'reason': 'PSLS 自身安装目录'})
    except Exception:
        pass
    return entries


def load_user_entries() -> list:
    """读取用户自定义排除项（文件缺失/损坏返回空表）。"""
    try:
        path = _registry_path()
        if not os.path.isfile(path):
            return []
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        raw = data.get('items') if isinstance(data, dict) else data
        if not isinstance(raw, list):
            return []
        out = []
        for it in raw:
            if not isinstance(it, dict):
                continue
            kind = str(it.get('kind') or '').strip().lower()
            value = str(it.get('value') or '').strip()
            if kind in _KINDS and value:
                out.append({'kind': kind, 'value': value,
                            'reason': str(it.get('reason') or '用户排除')})
        return out
    except Exception as e:
        logger.warning(f'读取发起者排除名单失败: {e}')
        return []


def save_user_entries(entries: list) -> bool:
    """保存用户自定义排除项（覆盖写；仅保留合法项）。"""
    try:
        clean = []
        for it in entries or []:
            if not isinstance(it, dict):
                continue
            kind = str(it.get('kind') or '').strip().lower()
            value = str(it.get('value') or '').strip()
            if kind in _KINDS and value:
                clean.append({'kind': kind, 'value': value,
                              'reason': str(it.get('reason') or '用户排除')})
        with open(_registry_path(), 'w', encoding='utf-8') as f:
            json.dump({'schema_version': 1, 'items': clean},
                      f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.warning(f'保存发起者排除名单失败: {e}')
        return False


class InitiatorExclusions:
    """发起者排除名单：合并 内置项 + 用户项 + 运行时动态项（如宿主目录）。"""

    def __init__(self):
        self._dynamic: list = []
        self._cached: list = []
        self._cache_sig = None
        self.reload()

    # ---------- 名单维护 ----------

    def add_dynamic(self, kind: str, value: str, reason: str = '运行时注册') -> bool:
        """注册运行时动态项（不写盘），如宿主进程安装目录。"""
        kind = (kind or '').strip().lower()
        if kind not in _KINDS or not value:
            return False
        for it in self._dynamic:
            if it['kind'] == kind and it['value'] == value:
                return False
        self._dynamic.append({'kind': kind, 'value': value, 'reason': reason})
        self._cached = []
        return True

    def reload(self) -> None:
        self._cached = []
        self._cache_sig = None

    def _entries(self) -> list:
        """合并名单（带文件 mtime/size 轻量缓存，避免热路径反复读盘）。"""
        try:
            st = os.stat(_registry_path())
            sig = (st.st_mtime_ns, st.st_size)
        except Exception:
            sig = None
        if self._cached and sig == self._cache_sig:
            return self._cached
        merged = _builtin_entries() + load_user_entries() + list(self._dynamic)
        self._cached = merged
        self._cache_sig = sig
        return merged

    # ---------- 匹配 ----------

    def match(self, image_name: str, full_path: str = '') -> str:
        """命中返回原因（非空字符串），未命中返回 ''。"""
        name = (image_name or '').strip().lower()
        if not name and full_path:
            name = os.path.basename(full_path).lower()
        path_l = _norm(full_path) if full_path else ''
        try:
            for it in self._entries():
                kind = it['kind']
                val = it['value']
                if kind == 'name':
                    if name and name == val.lower():
                        return it.get('reason') or '名单命中(名称)'
                elif kind == 'name_glob':
                    if name and fnmatch.fnmatch(name, val.lower()):
                        return it.get('reason') or '名单命中(名称通配)'
                elif kind == 'path_prefix':
                    if path_l and path_l.startswith(_norm(val)):
                        return it.get('reason') or '名单命中(路径前缀)'
                elif kind == 'path_suffix':
                    if path_l and path_l.endswith(_norm(val)):
                        return it.get('reason') or '名单命中(路径后缀)'
        except Exception as e:
            logger.debug(f'发起者排除匹配异常（按未命中处理）: {e}')
        return ''

    def is_excluded(self, image_name: str, full_path: str = '') -> bool:
        return bool(self.match(image_name, full_path))

    def list_all(self) -> list:
        """列出全部生效项（含 builtin/dynamic 标记），供 UI/排障。"""
        out = []
        try:
            builtin = _builtin_entries()
            user = load_user_entries()
            for it in builtin:
                out.append({**it, 'source': 'builtin'})
            for it in user:
                out.append({**it, 'source': 'user'})
            for it in self._dynamic:
                out.append({**it, 'source': 'dynamic'})
        except Exception as e:
            logger.debug(f'列举排除名单失败: {e}')
        return out


# 进程级单例（供 ProcessProtection 与 UI 共享同一份名单）
_instance = None


def get_exclusions() -> InitiatorExclusions:
    global _instance
    if _instance is None:
        _instance = InitiatorExclusions()
    return _instance