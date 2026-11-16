# -*- coding: utf-8 -*-
"""敏感命令拦截（账户凭据篡改 + 系统级破坏命令）。

拦截**非微软官方进程**发起的账户/登录密码修改与系统级破坏命令。

背景：破坏型样本（含本项目测试样本 G4m0ad2f1qi）常用两类手法，
且**都由微软自带工具执行**，故不能按"工具签名"判定，必须按**发起链**：

一、账户 / 凭据
    net user <name> <pwd>                      # 直接改登录密码
    net user <name> /add                       # 新建账户
    net user <name> /active:no                 # 禁用账户
    net localgroup administrators <name> /add  # 提权到管理员组
    net accounts /minpwlen:0                   # 改写密码策略
    wmic useraccount where name='x' set Password='y'
    powershell -enc <base64>                   # 内联脚本里再调 net user / Set-LocalUser
    reg add ...\\Winlogon /v DefaultPassword …  # 写入自动登录凭据

二、系统级破坏 / 防御瘫痪（沙箱用户态重定向**管不住**的那一类：
    它们走系统服务 RPC / 驱动，在沙箱内执行也会落到真实系统）
    netsh advfirewall set allprofiles state off  # 关防火墙
    net stop / sc stop|delete|config <安全服务>   # 停杀软/Defender/防火墙服务
    vssadmin delete shadows / wbadmin delete     # 删卷影/备份（勒索特征）
    bcdedit /set …                               # 改启动配置
    cipher /w:…                                  # 擦除空闲空间
    takeown /f … & icacls … /grant everyone:F & rmdir /s /q …
                                                 # 夺权+授权+删目录（破坏链）

判据：沿父进程链上溯，只要链上出现任一非微软官方进程，即认定"非微软官方
进程发起"，立即终止敏感命令进程与发起进程。

本模块分两部分，均为纯函数/无副作用，便于单测：
    classify_credential_tamper(cmdline, exe_name) -> Optional[dict]
        命令行 → 是否属于上述敏感操作（含 PowerShell -EncodedCommand 解包）
    is_microsoft_official_exe(exe, name, ci_dirs) -> bool
    check_origin_chain(pid, ppid, ci_dirs, ...) -> (official, offender)
        发起链的微软官方判定（psutil 枚举，可注入 proc_info 供单测）
"""

import os
import re
import base64
from typing import Callable, Optional, Sequence, Tuple

from utils.logger import get_logger

logger = get_logger('credential_protection')

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:  # pragma: no cover - psutil 是运行期硬依赖
    HAS_PSUTIL = False
    psutil = None


# ============================================================================
# 规则 1：net.exe / net1.exe 账户子命令
# ============================================================================

# 前缀边界：前一个字符不得是普通标识符字符/点/连字符（允许 " C:\path\ 等分隔符）
_NET_EXE = r"net1?(?:\.exe)?"

_NET_USER_RE = re.compile(
    r"(?<![\w.\-])" + _NET_EXE + r"[\"']?\s+user\b(.*)")
_NET_LOCALGROUP_RE = re.compile(
    r"(?<![\w.\-])" + _NET_EXE + r"[\"']?\s+localgroup\b(.*)")
_NET_ACCOUNTS_RE = re.compile(
    r"(?<![\w.\-])" + _NET_EXE + r"[\"']?\s+accounts\b(.*)")

# /domain 只是"在域控上查询"的选择器，单独出现属只读，不计入篡改


def _analyze_net_user(rest: str) -> Optional[Tuple[str, str]]:
    """解析 `net user` 之后的参数，判断是否真的在改账户。

    只读形态（枚举/查询）返回 None：
        net user              列出所有账户
        net user <name>       查看某账户
        net user <name> /domain
    篡改形态返回 (kind, reason)。
    """
    seg = re.split(r"[|&;]", rest, 1)[0].strip()
    if re.search(r"/(?:add|delete|active|passwordchg|passwordreq|expires|times|"
                 r"comment|fullname|homedir|profilepath|scriptpath|workstations|"
                 r"countrycode|random)\b", seg):
        return ('account_modify', 'net user 修改账户属性（/add 或 /delete 等）')
    toks = [t for t in seg.split() if not t.startswith('/')]
    if len(toks) >= 2:
        # net user <name> <password> / net user <name> * / net user <name> ""
        return ('password_set', 'net user 设置账户登录密码')
    return None


def _analyze_net_localgroup(rest: str) -> Optional[Tuple[str, str]]:
    seg = re.split(r"[|&;]", rest, 1)[0].strip()
    if not re.search(r"/(?:add|delete)\b", seg):
        return None  # 仅列出组成员 → 只读
    grp = ''
    try:
        grp = seg.split()[0]
    except Exception:
        pass
    if 'admin' in grp.lower() or '管理员' in grp:
        return ('admin_group_change', f'net localgroup 变更管理员组成员（{grp}）')
    return ('group_change', f'net localgroup 变更用户组成员（{grp}）')


# ============================================================================
# 规则 2：PowerShell / WMI / 注册表
# ============================================================================

_PS_CREDENTIAL_CMDLETS = (
    'set-localuser', 'new-localuser', 'remove-localuser', 'rename-localuser',
    'enable-localuser', 'disable-localuser', 'set-localuserpassword',
    'add-localgroupmember', 'remove-localgroupmember', 'add-localgroup',
    'set-adaccountpassword', 'set-aduser', 'new-aduser', 'remove-aduser',
    'add-adgroupmember', 'remove-adgroupmember', 'set-adaccountcontrol',
    'unlock-adaccount', 'set-addefaultdomainpasswordpolicy',
)

_WMIC_RE = re.compile(r"(?<![\w.\-])wmic(?:\.exe)?\b")
_WMIC_WRITE_RE = re.compile(r"\b(?:set|delete|call)\b")

_DSMOD_RE = re.compile(
    r"(?<![\w.\-])dsmod(?:\.exe)?[\"']?\s+(?:user|group)\b")

_REG_ADD_RE = re.compile(r"(?<![\w.\-])reg(?:\.exe)?[\"']?\s+add\b")

# ---- 系统级破坏命令规则 ----
# netsh firewall / advfirewall（后面再判 state off / opmode disable）
_NETSH_RE = re.compile(r"(?<![\w.\-])netsh(?:\.exe)?[\"']?\s+(?:adv?firewall|firewall)\b.*")

# net stop|sc stop|delete|config <服务>（后面的服务名再比对安全服务名单）
_SERVICE_CTL_RE = re.compile(
    r"(?<![\w.\-])(?:net1?|sc)(?:\.exe)?[\"']?\s+(?:stop|delete|config)\b(.*)")

# 安全/防护类服务名（停用它们=瘫痪防护）。小写子串匹配。
_SECURITY_SERVICE_NAMES = (
    'windefend', 'mpssvc', 'wscsvc', 'sense', 'securityhealthservice',
    'sharedaccess', 'dnscache', 'wuauserv', 'bits', 'sysmon', 'eventlog',
    'ekrn', 'avp', 'mbamservice', 'csfalconservice', 'savservice',
    'tmccsf', 'nanoservice', 'zhudongfangyu',
)

# 勒索/破坏特征命令
_RANSOM_CMDS = (
    (re.compile(r"vssadmin(?:\.exe)?[\"']?\s+delete\s+shadows"),
     '删除卷影副本（勒索特征）'),
    (re.compile(r"wbadmin(?:\.exe)?[\"']?\s+delete\b"),
     '删除备份目录（勒索特征）'),
    (re.compile(r"(?:win32_)?shadowcopy[\"']?\s+delete\b"),
     '删除卷影副本（勒索特征）'),
    (re.compile(r"bcdedit(?:\.exe)?[\"']?\s+/set\b"),
     '修改启动配置（bcdedit /set）'),
    (re.compile(r"cipher(?:\.exe)?[\"']?\s+/w"),
     '擦除空闲空间（勒索特征）'),
)

# takeown + icacls + rmdir 组合（破坏链，样本用于删除受保护目录）
_TAKEOVER_DELETE_RE = re.compile(
    r"(?<![\w.\-])takeown(?:\.exe)?\b.*icacls(?:\.exe)?\b.*(?:rmdir|rd)\s+/s")

# PowerShell 内联脚本参数（-EncodedCommand 及其合法缩写）
_ENC_FLAGS = ('-encodedcommand', '-enc', '-ec', '-en')

_MAX_ENC_B64 = 1 << 20  # 1MB：超出不再解码（防御畸形输入）


def _decode_encoded_powershell(tokens: Sequence[str]) -> str:
    """解开 `powershell -EncodedCommand <base64>` 的内联脚本（UTF-16LE，容错 UTF-8）。"""
    for i, tok in enumerate(tokens):
        low = str(tok).strip().lower()
        b64 = ''
        if low in _ENC_FLAGS and i + 1 < len(tokens):
            b64 = str(tokens[i + 1]).strip().strip('"\'')
        else:
            m = re.match(r"^(?:-(?:encodedcommand|enc|ec|en))[:=](.+)$", low)
            if m:
                b64 = m.group(1).strip('"\'')
        if not b64 or len(b64) > _MAX_ENC_B64:
            continue
        try:
            raw = base64.b64decode(b64 + '=' * (-len(b64) % 4), validate=False)
        except Exception:
            continue
        for enc in ('utf-16-le', 'utf-8'):
            try:
                text = raw.decode(enc)
                if text.strip():
                    return text
            except Exception:
                continue
        try:
            return raw.decode('latin-1', 'replace')
        except Exception:
            return ''
    return ''


def _analyze_text(text: str, shell_ctx: bool) -> Optional[Tuple[str, str, str]]:
    """在归一化后的文本上套用全部规则。返回 (kind, reason, evidence) 或 None。"""
    low = text.lower()

    # ---- net.exe 账户子命令 ----
    m = _NET_USER_RE.search(low)
    if m:
        hit = _analyze_net_user(m.group(1))
        if hit:
            return hit[0], hit[1], m.group(0)[:240]
    m = _NET_LOCALGROUP_RE.search(low)
    if m:
        hit = _analyze_net_localgroup(m.group(1))
        if hit:
            return hit[0], hit[1], m.group(0)[:240]
    m = _NET_ACCOUNTS_RE.search(low)
    if m and m.group(1).strip():
        return ('password_policy', 'net accounts 修改账户/密码策略', m.group(0)[:240])

    # ---- PowerShell 账户 cmdlet / SetPassword ----
    if shell_ctx:
        for c in _PS_CREDENTIAL_CMDLETS:
            if c in low:
                return ('ps_account_modify', f'PowerShell {c} 修改账户/凭据', c)
        m = re.search(r"\bsetpassword\s*\(", low)
        if m:
            return ('ps_setpassword', 'PowerShell/ADSI SetPassword 修改账户密码',
                    m.group(0))
        if 'winnt://' in low and 'setpassword' in low:
            return ('ps_setpassword', 'WinNT ADSI SetPassword 修改账户密码',
                    'setpassword')

    # ---- dsmod ----
    m = _DSMOD_RE.search(low)
    if m:
        return ('dsmod', 'dsmod 修改域账户/组成员', m.group(0)[:240])

    # ---- WMI useraccount ----
    if 'useraccount' in low and _WMIC_RE.search(low) and _WMIC_WRITE_RE.search(low):
        return ('wmi_account_modify', 'WMI useraccount 修改账户/密码', 'useraccount')

    # ---- 注册表账户数据库 / 自动登录凭据 ----
    if _REG_ADD_RE.search(low):
        if '\\sam\\' in low:
            return ('registry_sam', 'reg add 写入 SAM 账户数据库', '\\sam\\')
        if 'winlogon' in low and ('defaultpassword' in low
                                  or 'autoadminlogon' in low):
            return ('registry_logon_cred', 'reg add 写入 Winlogon 自动登录凭据',
                    'defaultpassword')

    # ========================================================================
    # 系统级破坏 / 防御瘫痪命令（沙箱用户态重定向管不住：走服务 RPC / 驱动）
    # ========================================================================

    # ---- 防火墙关闭 ----
    m = _NETSH_RE.search(low)
    if m and re.search(r'\bstate\s+off\b|\bopmode\s+disable\b', low):
        return ('firewall_off', 'netsh 关闭防火墙', m.group(0)[:240])

    # ---- 停用/删除安全服务 ----
    m = _SERVICE_CTL_RE.search(low)
    if m:
        _svc_blob = (m.group(1) or '')[:200]
        for svc in _SECURITY_SERVICE_NAMES:
            if svc in _svc_blob:
                return ('security_service_stop',
                        f'停用/删除安全服务 {svc}', m.group(0)[:240])

    # ---- 勒索特征命令 ----
    for rx, desc in _RANSOM_CMDS:
        m = rx.search(low)
        if m:
            return ('ransom_command', desc, m.group(0)[:240])

    # ---- 夺权+授权+删目录（破坏链）----
    m = _TAKEOVER_DELETE_RE.search(low)
    if m:
        return ('takeover_delete',
                'takeown+icacls+rmdir 夺权授权后删除目录', m.group(0)[:240])

    return None


def classify_credential_tamper(cmdline, exe_name: str = '') -> Optional[dict]:
    """判定命令行是否为"账户 / 登录密码篡改"操作。

    Args:
        cmdline: 已解析的命令行列表（或字符串）。
        exe_name: 进程名（仅用于日志/证据，不参与判定）。

    Returns:
        None（非篡改）或 {'kind', 'reason', 'evidence'}。
    """
    try:
        if isinstance(cmdline, str):
            toks = [cmdline]
        else:
            toks = [str(t) for t in (cmdline or []) if str(t).strip()]
        if not toks:
            return None
        joined = re.sub(r"\s+", " ", " ".join(toks)).strip()
        if not joined:
            return None

        decoded = ''
        try:
            decoded = _decode_encoded_powershell(toks)
        except Exception:
            decoded = ''

        text = joined if not decoded else (joined + ' ' + decoded)
        shell_ctx = bool(decoded) or ('powershell' in joined.lower()
                                      or 'pwsh' in joined.lower())
        hit = _analyze_text(text, shell_ctx)
        if not hit:
            return None
        kind, reason, evidence = hit
        return {'kind': kind, 'reason': reason, 'evidence': evidence or joined[:240]}
    except Exception as e:  # 分类器绝不抛出（运行在进程创建关键路径）
        logger.debug(f'credential 命令行分类异常: {e}')
        return None


# ============================================================================
# 微软官方进程判定 + 发起链上溯
# ============================================================================

# 无 exe 路径的系统伪进程 / 内核态进程名（这些必然是系统自身）
_MS_PSEUDO_NAMES = {
    'system', 'registry', 'idle', 'system idle process', 'secure system',
    'memory compression', 'smss.exe',
}

# 受保护进程 exe 路径读不到（AccessDenied，如 lsass/EDR 自保护）时的兜底放行名单。
# 仅在**拿不到路径**时按名字认官方；能拿到路径时一律以 目录/签名 判定，
# 避免"用户目录下伪装 svchost.exe"被名字放行。
_MS_SYSTEM_BINARY_NAMES = {
    'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe',
    'lsass.exe', 'lsaiso.exe', 'svchost.exe', 'fontdrvhost.exe', 'dwm.exe',
    'userinit.exe', 'explorer.exe', 'sihost.exe', 'taskhostw.exe',
    'runtimebroker.exe', 'searchhost.exe', 'startmenuexperiencehost.exe',
    'ctfmon.exe', 'conhost.exe', 'spoolsv.exe', 'wmiprvse.exe',
}

# 微软官方签名发布者关键字
_MS_PUBLISHER_KEYWORDS = ('microsoft', 'windows')


def _norm(p: str) -> str:
    try:
        return os.path.normcase(os.path.abspath(p))
    except Exception:
        return ''


def is_microsoft_official_exe(exe_path: str, name: str = '',
                              ci_dirs: Optional[Sequence[str]] = None) -> bool:
    """判断可执行文件是否属于"微软官方"。

    判据（短路，代价从低到高）：
      1. 位于 Windows 安装目录 / 传入的 CI 系统目录集合；
      2. 无路径的系统伪进程名（system/registry/idle…）；
      3. Authenticode 有效且发布者为 Microsoft（发布者结果在
         signature_verifier 类级缓存，重复调用 <1ms）。
    其余一律 False（含第三方有效签名 —— 按需求它们不属于"微软官方"）。
    """
    nm = (name or (os.path.basename(exe_path) if exe_path else '')).lower()
    exe_path = exe_path or ''
    if not exe_path:
        # 无路径：系统伪进程名 / 受保护的系统二进制名（exe 读取被拒）→ 认官方；
        # 其余"来源不可确认" → 非官方。
        return nm in _MS_PSEUDO_NAMES or nm in _MS_SYSTEM_BINARY_NAMES
    p = _norm(exe_path)
    if p:
        try:
            sys_root = _norm(os.environ.get('SystemRoot', r'C:\Windows'))
            if sys_root and p.startswith(sys_root + os.sep):
                return True
        except Exception:
            pass
        for d in (ci_dirs or ()):
            d_norm = _norm(d)
            if d_norm and (p == d_norm or p.startswith(d_norm + os.sep)):
                return True
    try:
        from utils.signature_verifier import get_verifier
        v = get_verifier()
        info = v.get_signer_info(exe_path) if v else None
        if info and info.get('verified'):
            pub = (info.get('publisher') or '').lower()
            return any(kw in pub for kw in _MS_PUBLISHER_KEYWORDS)
    except Exception as e:
        logger.debug(f'微软官方签名判定异常 {exe_path}: {e}')
    return False


def is_microsoft_official_exe_cheap(exe_path: str, name: str = '',
                                    ci_dirs: Optional[Sequence[str]] = None) -> bool:
    """**零 IO** 版微软官方判定（只按目录/伪进程名），供 EK 快车道抢时间用。

    与 `is_microsoft_official_exe` 的差别：不做 Authenticode 查询（那需要
    文件 IO，最坏百毫秒级）。因此它会把"位于用户目录但由微软签名的程序"
    判为非官方 —— 用于**决定是否可立即终止命令进程**时这是安全的：
    命令进程本身（net.exe / netsh / takeown / vssadmin）全部在 System32，
    必然命中目录/名字判定为官方，不会被误杀；只有"非官方路径下的同名工具
    （伪装/释放样本）"才会被判非官方并立即终止。
    """
    nm = (name or (os.path.basename(exe_path) if exe_path else '')).lower()
    exe_path = exe_path or ''
    if not exe_path:
        return nm in _MS_PSEUDO_NAMES or nm in _MS_SYSTEM_BINARY_NAMES
    p = _norm(exe_path)
    if not p:
        return False
    try:
        sys_root = _norm(os.environ.get('SystemRoot', r'C:\Windows'))
        if sys_root and p.startswith(sys_root + os.sep):
            return True
    except Exception:
        pass
    for d in (ci_dirs or ()):
        d_norm = _norm(d)
        if d_norm and (p == d_norm or p.startswith(d_norm + os.sep)):
            return True
    return False


def _default_proc_info(pid: int) -> Optional[Tuple[str, str, int]]:
    """psutil 枚举进程 → (name, exe, ppid)；进程不存在/不可访问返回 None。"""
    if not HAS_PSUTIL:
        return None
    try:
        pr = psutil.Process(int(pid))
        try:
            nm = pr.name() or ''
        except Exception:
            nm = ''
        try:
            exe = pr.exe() or ''
        except Exception:
            exe = ''
        try:
            ppid = int(pr.ppid())
        except Exception:
            ppid = 0
        return nm, exe, ppid
    except Exception:
        return None


def check_origin_chain(pid: int, parent_pid: int = 0,
                       ci_dirs: Optional[Sequence[str]] = None,
                       max_depth: int = 8,
                       proc_info: Optional[Callable[[int], Optional[Tuple[str, str, int]]]] = None
                       ) -> Tuple[bool, Optional[dict]]:
    """沿父进程链上溯，判断"发起链"是否全部为微软官方进程。

    Returns:
        (official, offender)
        official=True  → 全链微软官方（正常用户/系统行为，放行）
        official=False → 链上出现非微软官方节点，offender 为其描述：
            {'pid', 'name', 'exe', 'reason'}
    """
    getter = proc_info or _default_proc_info
    if getter is None:
        return True, None
    cur = int(pid or 0)
    seen = set()
    depth = 0
    while cur and cur > 4 and depth < max_depth and cur not in seen:
        seen.add(cur)
        depth += 1
        try:
            info = getter(cur)
        except Exception:
            info = None
        if info is None:
            # 已退出 / 无法访问的非根节点：来源无法确认 → 视为非官方
            return False, {
                'pid': cur, 'name': '', 'exe': '',
                'reason': '发起链存在无法确认来源的进程',
            }
        name, exe, ppid = (info[0] or ''), (info[1] or ''), int(info[2] or 0)
        if not is_microsoft_official_exe(exe, name, ci_dirs):
            return False, {
                'pid': cur, 'name': name or f'PID-{cur}', 'exe': exe,
                'reason': '',
            }
        if ppid <= 4 or ppid == cur:
            break
        cur = ppid
    _ = parent_pid  # 兼容调用方传入（链上溯以真实 ppid 为准）
    return True, None