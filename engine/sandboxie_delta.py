# -*- coding: utf-8 -*-
"""
sandboxie_delta.py — Sandboxie 沙盘增量取证

用途：
    沙箱（Sandboxie-Plus）会把样本的文件/注册表写入**重定向**到沙盒目录，
    真实磁盘与真实注册表看不到这些动作。本模块在样本运行结束后读取沙盒内
    的增量，还原为“样本真实想做的事”，再交给 SandboxAnalyzer 复用既有打分。

沙盒布局（Sandboxie-Plus 默认）：
    <FileRootPath>\\drive\\<盘符>\\...        对应真实 X:\\...
    <FileRootPath>\\user\\current\\...        对应用户目录 %USERPROFILE%\\...
    <FileRootPath>\\user\\all\\...            对应 %PUBLIC%\\...
    <FileRootPath>\\RegHive                   重定向的注册表（连接态挂载为
                                              \\REGISTRY\\USER\\Sandbox_<用户>_<盒>）

设计原则：
    - 全部防御式实现：任何异常都只记录日志并返回空/部分结果，绝不抛出；
    - 输出的是 BehaviorRecord 的 dict 形态，直接喂给 SandboxAnalyzer._add_behavior；
    - 为避免正常安装器“写很多文件”被误判，文件类只对**可疑扩展名/可疑目录/批量写**
      单独记分，其余合并为一条 info 汇总；注册表类只对持久化键单独记分。

注意：路径还原、删除标记识别等细节需在本机装 Sandboxie-Plus 后实测校准
（见计划 P0/P3/P4）。
"""

import os
import sys
import logging
import subprocess
from typing import List, Dict, Optional

logger = logging.getLogger('sandboxie_delta')

_IS_WINDOWS = sys.platform == 'win32'

try:
    import winreg
    _HAS_WINREG = True
except ImportError:
    winreg = None
    _HAS_WINREG = False

# 可疑/勒索类扩展名（写入这些扩展名视为高风险）
_SUSPICIOUS_EXTS = {
    '.exe', '.dll', '.scr', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.js',
    '.sys', '.drv', '.ocx', '.cpl', '.msi', '.hta', '.jar',
}
_RANSOM_EXTS = {
    '.locked', '.encrypted', '.enc', '.crypto', '.crypt', '.locky', '.zepto',
    '.cerber', '.wncry', '.wannacry', '.ryk', '.ryuk', '.lockbit', '.conti',
}
# 自启动/持久化相关目录特征（命中→高风险）
_PERSIST_MARKERS = (
    'start menu\\programs\\startup',
    'startup\\',
    '\\run',
    '\\runonce',
    '\\services\\',
    '\\winlogon',
    '\\image file execution options',
    '\\currentversion\\run',
)
_MAX_FILE_RECORDS = 60          # 单个文件行为记录上限（防爆量）
_MASS_WRITE_THRESHOLD = 80      # 批量写入阈值（超过→可疑）

# 盒根下的 Sandboxie 内部管理文件（注册表 hive 及其事务日志、桌面配置等），
# 并非样本写入，必须从文件增量中剔除，否则会污染计数与批量写判定。
# 实测残留：RegHive、RegHive.LOG1/2、
#   RegHive{GUID}.TM.blf、RegHive{GUID}.TMContainer*.regtrans-ms。
_INTERNAL_BASENAMES = {
    'reghive', 'reghive.log1', 'reghive.log2', 'reghive.lock',
    'desktop.ini', 'dont-use.txt', 'sandboxie.ini',
}
_INTERNAL_SUFFIXES = ('.tm.blf', '.regtrans-ms', '.blf')


def _is_internal_file(rel: str) -> bool:
    """判断沙盒内相对路径是否为 Sandboxie 内部管理文件。"""
    base = os.path.basename(rel.replace('/', '\\')).lower()
    if not base:
        return False
    if base in _INTERNAL_BASENAMES:
        return True
    # 所有 RegHive 事务日志/容器均以 "reghive" 前缀命名
    if base.startswith('reghive'):
        return True
    return base.endswith(_INTERNAL_SUFFIXES)


def _norm(p: str) -> str:
    try:
        return os.path.normcase(os.path.normpath(p))
    except Exception:
        return p or ''


# ---------------------------------------------------------------------------
# 文件增量
# ---------------------------------------------------------------------------

def _is_delete_marker(path: str) -> bool:
    """Sandboxie 删除标记：用 1 字节 NUL 文件表示“该文件被删除”。

    该约定需在实测中校准；此处保守识别（仅 1 字节且内容为 0x00）。
    """
    try:
        if os.path.getsize(path) != 1:
            return False
        with open(path, 'rb') as f:
            return f.read(1) == b'\x00'
    except Exception:
        return False


def _map_sandbox_path(file_root: str, rel: str) -> Optional[str]:
    """沙盒内相对路径 → 真实路径。

    drive/<X>/<rest> -> X:\\<rest>
    user/current/<rest> -> %USERPROFILE%\\<rest>
    user/all/<rest> -> %PUBLIC%\\<rest>
    """
    try:
        parts = rel.replace('/', '\\').split('\\')
        if not parts:
            return None
        if parts[0].lower() == 'drive' and len(parts) >= 2:
            drive = parts[1]
            if len(drive) == 1 and drive.isalpha():
                rest = '\\'.join(parts[2:])
                return f'{drive.upper()}:\\{rest}' if rest else f'{drive.upper()}:\\'
        if parts[0].lower() == 'user' and len(parts) >= 2:
            scope = parts[1].lower()
            rest = '\\'.join(parts[2:])
            if scope == 'current':
                base = os.path.expanduser('~')
            elif scope in ('all', 'public'):
                base = os.environ.get('PUBLIC', r'C:\Users\Public')
            else:
                base = os.path.join(os.path.expanduser('~'), scope)
            return os.path.join(base, rest) if rest else base
        # share/... 等其它分支：不映射真实路径，原样返回相对名
        return rel
    except Exception:
        return None


def collect_files(file_root: str) -> List[Dict]:
    """遍历沙盒文件根，产出文件类行为记录。"""
    out: List[Dict] = []
    if not file_root or not os.path.isdir(file_root):
        return out
    total = 0
    suspicious: List[tuple] = []   # (real_path, kind, delete?)
    try:
        for root, _dirs, files in os.walk(file_root):
            for name in files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, file_root)
                # 跳过 Sandboxie 内部管理文件（RegHive 及事务日志、desktop.ini 等）
                if _is_internal_file(rel):
                    continue
                total += 1
                real = _map_sandbox_path(file_root, rel)
                if real is None:
                    continue
                if _is_delete_marker(full):
                    suspicious.append((real, 'delete', True))
                    continue
                ext = os.path.splitext(name)[1].lower()
                rl = _norm(real)
                if ext in _RANSOM_EXTS:
                    suspicious.append((real, 'ransom', False))
                elif any(mk in _norm(rel) for mk in _PERSIST_MARKERS):
                    suspicious.append((real, 'persist', False))
                elif ext in _SUSPICIOUS_EXTS:
                    suspicious.append((real, 'exec', False))
    except Exception as e:
        logger.debug(f'collect_files 遍历异常: {e}')

    if total <= 0:
        return out

    # 汇总（低风险）
    out.append({
        'category': 'file', 'severity': 'info',
        'description': f'沙盘记录: 文件写入/改动 {total} 项',
        'detail': file_root, 'score': 0,
    })

    # 批量写入（超过阈值→可疑）
    if total >= _MASS_WRITE_THRESHOLD:
        out.append({
            'category': 'file', 'severity': 'warn',
            'description': f'沙盘记录: 批量文件写入（{total} 项，疑似批量加密/替换）',
            'detail': file_root, 'score': 12,
        })

    # 逐条可疑文件（限量）
    emitted = 0
    for real, kind, is_del in suspicious:
        if emitted >= _MAX_FILE_RECORDS:
            break
        emitted += 1
        if kind == 'ransom':
            out.append({'category': 'file', 'severity': 'critical',
                        'description': '沙盘记录: 写入可疑勒索扩展名文件',
                        'detail': real, 'score': 25})
        elif kind == 'delete':
            out.append({'category': 'file', 'severity': 'warn',
                        'description': '沙盘记录: 删除文件',
                        'detail': real, 'score': 6})
        elif kind == 'persist':
            out.append({'category': 'file', 'severity': 'critical',
                        'description': '沙盘记录: 在自启动/持久化目录写入文件',
                        'detail': real, 'score': 18})
        else:  # exec
            out.append({'category': 'file', 'severity': 'warn',
                        'description': '沙盘记录: 落地可执行/脚本文件',
                        'detail': real, 'score': 8})
    return out


# ---------------------------------------------------------------------------
# 注册表增量
# ---------------------------------------------------------------------------

def _safe_close(key) -> None:
    try:
        winreg.CloseKey(key)
    except Exception:
        pass


def _iter_hive_values(hive_key) -> List[tuple]:
    """递归枚举 hive_key 下所有 (相对路径, 值名, 值数据)。

    注意：所有 OpenKey 得到的句柄都会在此关闭。离线 `reg unload` 要求
    无残留句柄，否则卸载失败。
    """
    results: List[tuple] = []
    stack = [('', hive_key)]
    budget = 20000   # 防御性上限，避免异常 hive 卡死
    while stack and budget > 0:
        rel, key = stack.pop()
        try:
            sub_count = winreg.QueryInfoKey(key)[0]
            val_count = winreg.QueryInfoKey(key)[1]
        except Exception:
            _safe_close(key)
            continue
        for i in range(val_count):
            try:
                name, data, _t = winreg.EnumValue(key, i)
            except OSError:
                continue
            budget -= 1
            results.append((rel, name, data))
        for i in range(sub_count):
            try:
                sub = winreg.EnumKey(key, i)
            except OSError:
                continue
            try:
                sk = winreg.OpenKey(key, sub, 0, winreg.KEY_READ)
            except OSError:
                continue
            stack.append((f'{rel}\\{sub}' if rel else sub, sk))
        _safe_close(key)
    return results


# --- 离线 hive 加载（盒已终止、RegHive 文件释放后使用；需管理员权限）---
_OFFLINE_MOUNT_PREFIX = 'PSLS_SbieRead'


def _offline_load_reg_hive(file_root: str) -> Optional[str]:
    """把 <file_root>\\RegHive 离线加载到 HKU\\PSLS_SbieRead_<pid>。

    成功返回临时挂载名，失败返回 None（非管理员 / 文件不存在 / 被占用）。
    """
    if not file_root:
        return None
    hive = os.path.join(file_root, 'RegHive')
    if not os.path.isfile(hive):
        return None
    name = f'{_OFFLINE_MOUNT_PREFIX}_{os.getpid()}'
    try:
        r = subprocess.run(['reg', 'load', f'HKU\\{name}', hive],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            logger.debug(f'reg load 失败: {r.stdout} {r.stderr}')
            return None
        logger.info(f'已离线加载沙盒注册表: HKU\\{name} <- {hive}')
        return name
    except Exception as e:
        logger.debug(f'reg load 异常: {e}')
        return None


def _offline_unload_reg_hive(name: Optional[str]) -> None:
    if not name:
        return
    try:
        subprocess.run(['reg', 'unload', f'HKU\\{name}'],
                       capture_output=True, text=True, timeout=30)
    except Exception as e:
        logger.debug(f'reg unload 异常: {e}')


# --- 注册表打分：仅对"持久化/劫持"类键单独记分（白名单式）---
# 沙盒重定向 hive 内混有大量 Sandboxie/Windows 自身噪声（Start.exe 关联项、
# EnableDCOM、遥测 TIP、Winsock 目录、MuiCache 等）。若对每个值都记分，
# registry 类会迅速封顶（20 分）→ 每个样本都被判 suspicious → 强制隔离。
# 因此仅"持久化/劫持"键单独记分，其余只做一条 0 分 info 汇总。
_REG_PERSIST_SUBSTR = (
    '\\currentversion\\run',
    '\\currentversion\\runonce',
    '\\currentversion\\runservices',
    '\\policies\\explorer\\run',
    '\\winlogon',
    '\\image file execution options',
    '\\appinit_dlls',
    '\\active setup\\installed components',
    '\\browser helper objects',
    '\\inprocserver32',
    '\\localserver32',
    '\\shell\\open\\command',
    '\\services\\',
    '\\scheduled tasks',
    '\\taskcache',
    '\\userinit',
    '\\shellserviceobjectdelayload',
)
# 噪声键（盒内自动生成），即便命中上面的子串也排除
_REG_NOISE_SUBSTR = (
    '\\classes\\undecided\\',
    '\\classes\\unknown\\',
    '\\services\\winsock2\\',
    '\\services\\dnscache',
    '\\services\\cryptsvc',
    '\\system\\software\\microsoft\\tip',
    '\\software\\policies\\microsoft\\',
    '\\windows error reporting',
    '\\software\\microsoft\\ole',
    '\\sandboxautoexec',
)
_REG_VALUE_MAXLEN = 200          # 记录里的值数据截断长度（防大二进制刷屏）
_MAX_REG_RECORDS = 40           # 持久化注册表记录上限（防爆量）


def _fmt_value(vdata) -> str:
    """把注册表值格式化为可读字符串（截断过长的二进制数据）。"""
    try:
        s = str(vdata)
    except Exception:
        s = repr(vdata)
    return s if len(s) <= _REG_VALUE_MAXLEN else s[:_REG_VALUE_MAXLEN] + '...'


def _reg_is_persist(rel_path: str) -> bool:
    """判断被写注册表键是否为持久化/劫持类（白名单，且排除噪声）。"""
    low = _norm(rel_path)
    if any(mk in low for mk in _REG_NOISE_SUBSTR):
        return False
    return any(mk in low for mk in _REG_PERSIST_SUBSTR)


def collect_registry(box: str, file_root: str = None) -> List[Dict]:
    """枚举沙盒重定向注册表，产出注册表类行为记录。

    读取路径有两条：
      1) 连接态挂载 hive（HKU\\Sandbox_<用户>_<盒>）—— 免权限，但 Sandboxie
         按需挂载，盒内进程一退即卸载，时机不稳；
      2) 离线 `reg load <file_root>\\RegHive` —— 需管理员权限，但盒终止后
         文件锁释放，读取确定可靠（PSLS 以管理员运行，故为主力路径）。

    映射（实测 1.17/1.18）：hive 内 machine→HKLM、user\\current→HKCU。
    """
    out: List[Dict] = []
    if not (_HAS_WINREG and _IS_WINDOWS):
        return out

    user = os.environ.get('USERNAME', '')
    candidates = [
        f'Sandbox_{user}_{box}',
        f'Sandbox_{user}',
        f'Sandbox_{box}',
    ]
    root = None
    opened_mount = None       # 离线加载的临时挂载名（需在结束时 unload）
    for name in candidates:
        try:
            root = winreg.OpenKey(winreg.HKEY_USERS, name, 0, winreg.KEY_READ)
            logger.debug(f'已打开连接态沙盒 hive: HKEY_USERS\\{name}')
            break
        except OSError:
            continue
    if root is None:
        opened_mount = _offline_load_reg_hive(file_root)
        if opened_mount:
            try:
                root = winreg.OpenKey(winreg.HKEY_USERS, opened_mount,
                                      0, winreg.KEY_READ)
            except OSError:
                root = None
                _offline_unload_reg_hive(opened_mount)
                opened_mount = None
    if root is None:
        return out

    try:
        # machine -> HKLM；user\current -> HKCU
        persist_cnt = 0
        other_cnt = 0
        for scope, hklabel in (('machine', 'HKLM'), ('user\\current', 'HKCU')):
            try:
                sub = winreg.OpenKey(root, scope, 0, winreg.KEY_READ)
            except OSError:
                continue
            for rel, vname, vdata in _iter_hive_values(sub):
                if _reg_is_persist(rel):
                    if persist_cnt >= _MAX_REG_RECORDS:
                        continue
                    persist_cnt += 1
                    full = f'{hklabel}\\{rel}' + (f'\\{vname}' if vname else '')
                    out.append({'category': 'registry', 'severity': 'critical',
                                'description': '沙盘记录: 写入自启动/持久化注册表项',
                                'detail': f'{full} = {_fmt_value(vdata)}',
                                'score': 18})
                else:
                    other_cnt += 1
        if other_cnt > 0:
            out.append({'category': 'registry', 'severity': 'info',
                        'description': f'沙盘记录: 修改注册表 {other_cnt} 项（非持久化）',
                        'detail': '', 'score': 0})
    finally:
        _safe_close(root)
        # 离线加载的 hive 必须在关闭所有句柄后再卸载
        _offline_unload_reg_hive(opened_mount)
    return out


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------

def collect_all(file_root: str, box: str) -> List[Dict]:
    """收集一次沙箱运行的全部增量（文件 + 注册表）。"""
    records: List[Dict] = []
    try:
        records.extend(collect_files(file_root))
    except Exception as e:
        logger.debug(f'collect_files 异常: {e}')
    try:
        records.extend(collect_registry(box, file_root))
    except Exception as e:
        logger.debug(f'collect_registry 异常: {e}')
    return records