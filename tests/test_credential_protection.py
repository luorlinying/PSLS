# -*- coding: utf-8 -*-
"""账户凭据篡改拦截的回归测试。

需求：拦截**非微软官方进程**修改用户登录密码等账户相关内容的行为。

要点：
  1. net.exe / powershell.exe 都是微软自带工具 → 不能按"工具签名"判定，
     必须按**发起链**判定（链上出现非微软官方进程即拦截）。
  2. 只读形态（`net user` 枚举、`net user bob` 查询、`net user bob /domain`、
     `net localgroup administrators` 列成员、`wmic useraccount get`）不得误拦。
  3. 拦截点必须在系统关键进程名白名单（cmd.exe / powershell.exe 会在那里被
     直接放行）与 CI 系统目录豁免（net.exe 在那里被放行）之前。
  4. 处置不得走 _report_threat → _auto_handle_threat：那会把
     C:\\Windows\\System32\\net.exe 当"行为威胁"文件隔离掉。
"""

import os
import sys
import time
import base64
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.credential_protection import (          # noqa: E402
    classify_credential_tamper, is_microsoft_official_exe, check_origin_chain)

SYS32 = r'C:\Windows\System32'


class TestCredentialTamperClassifier(unittest.TestCase):
    """命令行分类：正例必须命中，只读形态不得命中。"""

    def _kind(self, cmdline):
        r = classify_credential_tamper(cmdline)
        return r.get('kind') if r else None

    # ---------------- 正例 ----------------
    def test_net_user_set_password(self):
        self.assertEqual(
            self._kind([rf'{SYS32}\net.exe', 'user', 'bob', 'P@ssw0rd!']),
            'password_set')

    def test_net_user_add_account(self):
        self.assertEqual(
            self._kind([rf'{SYS32}\net.exe', 'user', 'bob', 'P@ss', '/add']),
            'account_modify')

    def test_net_user_disable_account(self):
        self.assertEqual(
            self._kind(['net', 'user', 'bob', '/active:no']), 'account_modify')

    def test_net_user_delete_account(self):
        self.assertEqual(
            self._kind(['net1.exe', 'user', 'bob', '/delete']), 'account_modify')

    def test_net_localgroup_add_admin(self):
        self.assertEqual(
            self._kind([rf'{SYS32}\net.exe', 'localgroup',
                        'administrators', 'bob', '/add']),
            'admin_group_change')

    def test_net_accounts_policy(self):
        self.assertEqual(
            self._kind(['net', 'accounts', '/minpwlen:0']), 'password_policy')

    def test_wmic_useraccount_set_password(self):
        self.assertEqual(
            self._kind(['wmic', 'useraccount', 'where',
                        "name='bob'", 'set', "Password='x'"]),
            'wmi_account_modify')

    def test_powershell_set_localuser(self):
        self.assertEqual(
            self._kind(['powershell.exe', '-NoProfile', '-Command',
                        'Set-LocalUser -Name bob -Password $p']),
            'ps_account_modify')

    def test_powershell_encoded_command(self):
        payload = 'net user bob P@ssw0rd!'
        b64 = base64.b64encode(payload.encode('utf-16-le')).decode()
        self.assertEqual(
            self._kind([rf'{SYS32}\WindowsPowerShell\v1.0\powershell.exe',
                        '-EncodedCommand', b64]),
            'password_set')

    def test_cmd_c_net_user(self):
        self.assertEqual(
            self._kind([rf'{SYS32}\cmd.exe', '/c', 'net', 'user',
                        'bob', 'P@ss']),
            'password_set')

    def test_reg_add_winlogon_defaultpassword(self):
        self.assertEqual(
            self._kind(['reg', 'add',
                        r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
                        '/v', 'DefaultPassword', '/d', 'x', '/f']),
            'registry_logon_cred')

    def test_reg_add_sam(self):
        self.assertEqual(
            self._kind(['reg.exe', 'add',
                        r'HKLM\SAM\SAM\Domains\Account\Users\000001F4',
                        '/v', 'F', '/f']),
            'registry_sam')

    def test_dsmod_user(self):
        self.assertEqual(
            self._kind(['dsmod', 'user', 'CN=bob,CN=Users,DC=x', '-pwd', 'y']),
            'dsmod')

    # ---------------- 只读形态（不得误拦） ----------------
    def test_net_user_enumeration_is_readonly(self):
        self.assertIsNone(classify_credential_tamper(['net', 'user']))
        self.assertIsNone(classify_credential_tamper(['net.exe', 'user']))

    def test_net_user_single_name_is_readonly(self):
        self.assertIsNone(classify_credential_tamper(['net', 'user', 'bob']))

    def test_net_user_domain_query_is_readonly(self):
        self.assertIsNone(
            classify_credential_tamper(['net', 'user', 'bob', '/domain']))

    def test_net_localgroup_list_is_readonly(self):
        self.assertIsNone(
            classify_credential_tamper(['net', 'localgroup', 'administrators']))

    def test_net_accounts_list_is_readonly(self):
        self.assertIsNone(classify_credential_tamper(['net', 'accounts']))

    def test_wmic_useraccount_get_is_readonly(self):
        self.assertIsNone(
            classify_credential_tamper(['wmic', 'useraccount', 'get', 'name']))

    def test_similar_name_not_matched(self):
        # 前缀边界：netkit.exe 不是 net.exe
        self.assertIsNone(
            classify_credential_tamper(['netkit.exe', 'user', 'bob', 'P@ss']))

    def test_plain_echo_not_matched(self):
        self.assertIsNone(classify_credential_tamper(['echo', 'net', 'user']))

    def test_empty_and_garbage(self):
        self.assertIsNone(classify_credential_tamper([]))
        self.assertIsNone(classify_credential_tamper(None))
        self.assertIsNone(classify_credential_tamper(['explorer.exe']))


class TestDestructiveCommandRules(unittest.TestCase):
    """系统级破坏/防御瘫痪命令（沙箱用户态重定向管不住的那一类）。

    用例直接取自实测样本 G4m0ad2f1qi（加强版）.exe 的字符串表。
    """

    def _kind(self, cmdline):
        r = classify_credential_tamper(cmdline)
        return r.get('kind') if r else None

    def test_netsh_firewall_off(self):
        self.assertEqual(
            self._kind(['cmd.exe', '/c', 'netsh', 'advfirewall', 'set',
                        'allprofiles', 'state', 'off']),
            'firewall_off')

    def test_netsh_firewall_set_rule_is_not_touched(self):
        """正常安装程序添加防火墙规则不得误拦。"""
        self.assertIsNone(self._kind(
            ['cmd.exe', '/c', 'netsh', 'advfirewall', 'firewall', 'add',
             'rule', 'name=app', 'dir=in', 'action=allow']))

    def test_stop_security_service(self):
        self.assertEqual(
            self._kind(['cmd.exe', '/c', 'net', 'stop', 'dnscache']),
            'security_service_stop')
        self.assertEqual(
            self._kind(['sc', 'stop', 'windefend']), 'security_service_stop')

    def test_stop_normal_service_not_touched(self):
        self.assertIsNone(self._kind(['net', 'stop', 'spooler']))

    def test_vssadmin_delete_shadows(self):
        self.assertEqual(
            self._kind(['vssadmin', 'delete', 'shadows', '/all', '/quiet']),
            'ransom_command')

    def test_wbadmin_delete_catalog(self):
        self.assertEqual(
            self._kind(['wbadmin', 'delete', 'catalog', '-quiet']),
            'ransom_command')

    def test_bcdedit_set(self):
        self.assertEqual(
            self._kind(['bcdedit', '/set', '{default}', 'recoveryenabled', 'no']),
            'ransom_command')

    def test_cipher_wipe(self):
        self.assertEqual(self._kind(['cipher', '/w:C:\\']), 'ransom_command')

    def test_takeown_icacls_rmdir_chain(self):
        self.assertEqual(
            self._kind(['cmd.exe', '/c', 'takeown', '/f', 'C:\\Target', '/r',
                        '/d', 'y', '&', 'icacls', 'C:\\Target', '/grant',
                        'everyone:F', '/t', '/c', '/q', '&', 'rmdir', '/s',
                        '/q', 'C:\\Target']),
            'takeover_delete')

    def test_takeown_alone_not_touched(self):
        self.assertIsNone(self._kind(
            ['takeown', '/f', 'C:\\Some\\Owned\\Folder', '/r', '/d', 'y']))

    def test_net_user_password_from_sample(self):
        """样本原文：cmd /c net user "%s" cao031700 >nul 2>&1"""
        self.assertEqual(
            self._kind(['cmd.exe', '/c', 'net', 'user', '"%s"', 'cao031700']),
            'password_set')


class TestBlockedExeRelaunch(unittest.TestCase):
    """已被拦截程序路径黑名单：拦截 runas 自提权重启逃逸。"""

    def _pp(self):
        from engine.process_protection import ProcessProtection as P
        pp = object.__new__(P)
        pp._blocked_exe_paths = {}
        pp._blocked_exe_lock = threading.Lock()
        pp._BLOCKED_EXE_TTL = 900.0
        pp._normalize_path_for_sandbox_analyzing = (
            lambda p: os.path.normcase(os.path.abspath(p)) if p else '')
        return pp

    def test_mark_query_unmark_roundtrip(self):
        pp = self._pp()
        exe = r'C:\Users\v\Downloads\MinecraftRansomware.exe'
        self.assertFalse(pp._is_exe_blocked(exe))
        self.assertTrue(pp._mark_exe_blocked(exe, 'oversize'))
        self.assertTrue(pp._is_exe_blocked(exe))
        pp._unmark_exe_blocked(exe)
        self.assertFalse(pp._is_exe_blocked(exe))

    def test_ttl_expiry(self):
        pp = self._pp()
        exe = r'C:\Users\v\Downloads\G4m0ad2f1qi.exe'
        pp._mark_exe_blocked(exe)
        key = pp._normalize_path_for_sandbox_analyzing(exe)
        pp._blocked_exe_paths[key] = 1.0          # 人为过期
        self.assertFalse(pp._is_exe_blocked(exe))

    def test_kill_blocked_relaunch_uses_full_chain_on_failure(self):
        """提权实例可能拒绝 _emergency_kill → 必须回退完整终止链路。"""
        pp = self._pp()
        calls = []
        pp._emergency_kill = lambda pid: calls.append(('emergency', pid)) or False
        pp.kill_process = lambda pid, **kw: calls.append(('full', pid)) or True
        pp._notify_launch_monitoring = lambda *a, **kw: None
        pp._add_event = lambda *a, **k: None
        ok = pp._kill_blocked_relaunch(
            4321, 'MinecraftRansomware.exe',
            r'C:\Users\v\Downloads\MinecraftRansomware.exe')
        self.assertTrue(ok)
        self.assertEqual([c[0] for c in calls], ['emergency', 'full'])


class TestMicrosoftOfficialJudgement(unittest.TestCase):
    """微软官方判定：Windows 目录 / 系统伪进程名 → 官方；用户目录未签名 → 非官方。"""

    def test_windows_dir_is_official(self):
        self.assertTrue(is_microsoft_official_exe(rf'{SYS32}\net.exe'))
        self.assertTrue(is_microsoft_official_exe(
            r'C:\Windows\explorer.exe', ci_dirs=[]))

    def test_ci_dir_is_official(self):
        self.assertTrue(is_microsoft_official_exe(
            r'C:\Program Files\WindowsApps\x\app.exe',
            ci_dirs=[r'C:\Program Files\WindowsApps']))

    def test_user_dir_unsigned_is_not_official(self):
        self.assertFalse(is_microsoft_official_exe(
            r'C:\Users\v\Downloads\evil.exe'))

    def test_pseudo_process_name_is_official(self):
        self.assertTrue(is_microsoft_official_exe('', 'system'))
        self.assertFalse(is_microsoft_official_exe('', 'evil.exe'))

    def test_protected_system_binary_without_path_is_official(self):
        """受保护进程（lsass/EDR）exe 读取被拒时，按系统二进制名兜底放行，
        否则正常 `net user` 会被"无法确认来源的祖先"误拦。"""
        self.assertTrue(is_microsoft_official_exe('', 'lsass.exe'))
        self.assertTrue(is_microsoft_official_exe('', 'svchost.exe'))

    def test_masquerade_not_excused_by_name(self):
        """能拿到路径时必须按目录判定 —— 用户目录下的 svchost.exe 不是官方。"""
        self.assertFalse(is_microsoft_official_exe(
            r'C:\Users\v\Downloads\svchost.exe', 'svchost.exe'))


class TestOriginChain(unittest.TestCase):
    """发起链上溯：链上出现非微软官方节点即判定为非官方发起。"""

    OFFICIAL = {
        100: ('net.exe', rf'{SYS32}\net.exe', 200),
        200: ('cmd.exe', rf'{SYS32}\cmd.exe', 300),
        300: ('explorer.exe', r'C:\Windows\explorer.exe', 0),
    }

    def test_official_chain_allowed(self):
        official, offender = check_origin_chain(
            100, 200, proc_info=lambda p: self.OFFICIAL.get(p))
        self.assertTrue(official)
        self.assertIsNone(offender)

    def test_non_official_ancestor_blocks(self):
        chain = dict(self.OFFICIAL)
        chain[300] = ('evil.exe', r'C:\Users\v\Downloads\evil.exe', 0)
        official, offender = check_origin_chain(
            100, 200, proc_info=lambda p: chain.get(p))
        self.assertFalse(official)
        self.assertEqual(offender['pid'], 300)
        self.assertIn('evil.exe', offender['name'])

    def test_unresolvable_ancestor_blocks(self):
        chain = {100: ('net.exe', rf'{SYS32}\net.exe', 200)}
        official, offender = check_origin_chain(
            100, 200, proc_info=lambda p: chain.get(p))
        self.assertFalse(official)
        self.assertEqual(offender['pid'], 200)
        self.assertTrue(offender['reason'])

    def test_depth_cap(self):
        chain = {}
        for i in range(20):
            chain[1000 + i] = (f'p{i}.exe', rf'{SYS32}\p{i}.exe', 1001 + i)
        official, offender = check_origin_chain(
            1000, 1001, max_depth=8, proc_info=lambda p: chain.get(p))
        self.assertTrue(official)


class TestInterceptionWiring(unittest.TestCase):
    """接线约束：拦截位置必须在白名单/系统目录豁免之前，且不得走 _report_threat。"""

    def setUp(self):
        self.src = open(os.path.join(ROOT, 'engine', 'process_protection.py'),
                        'r', encoding='utf-8').read()

    def _check_new_process_body(self):
        start = self.src.index('def _check_new_process')
        end = self.src.index('_SYSTEM_CRITICAL_EXE_NAMES = {')
        self.assertLess(start, end)
        return self.src[start:end]

    def test_hook_placed_before_name_whitelist(self):
        body = self._check_new_process_body()
        idx_cred = body.index('_classify_credential_tamper')
        idx_whitelist = body.index('if name_lower in self._SYSTEM_CRITICAL_EXE_NAMES')
        idx_ci = body.index('self._CI_WINDOWS_SYSTEM_DIRS')
        self.assertLess(
            idx_cred, idx_whitelist,
            '账户凭据篡改拦截必须早于系统关键进程名白名单 —— '
            'cmd.exe / powershell.exe 会在白名单处被直接放行。')
        self.assertLess(
            idx_cred, idx_ci,
            '账户凭据篡改拦截必须早于 CI 系统目录豁免 —— '
            'net.exe 位于 System32，会在目录豁免处被放行。')

    def test_hook_placed_before_sandbox_exemptions(self):
        """必须在"沙箱分析中"与"沙箱子孙"豁免之前。

        沙箱盒内执行的 netsh / net stop / net user 走系统服务 RPC，用户态重定向
        管不住；若被沙箱豁免先 return，样本在沙箱里就能关掉宿主防火墙、改登录密码。
        """
        body = self._check_new_process_body()
        idx_cred = body.index('_classify_credential_tamper')
        idx_analyzing = body.index('if exe and self._is_sandbox_analyzing(exe):')
        idx_desc = body.index('self._is_sandbox_descendant(pid, parent_pid)')
        self.assertLess(idx_cred, idx_analyzing,
                        '敏感命令拦截必须早于"沙箱分析中"路径豁免')
        self.assertLess(idx_cred, idx_desc,
                        '敏感命令拦截必须早于"沙箱子孙进程"PID 豁免')

    def test_handler_terminates_and_reports(self):
        h_start = self.src.index('def _handle_credential_tamper')
        h_end = self.src.index('def _emergency_kill', h_start)
        handler = self.src[h_start:h_end]
        self.assertIn('_emergency_kill', handler)
        self.assertIn('_notify_launch_monitoring', handler)
        self.assertIn('Sensitive.Command.NonMicrosoftOrigin', handler)
        self.assertNotIn(
            '_report_threat', handler,
            '不得走 _report_threat：_auto_handle_threat 会按行为威胁隔离文件，'
            '而这里的目标文件是 C:\\Windows\\System32\\net.exe 之类的系统工具。')

    def test_in_box_offender_keeps_sandbox_verdict(self):
        """BT 约束：发起者正在沙箱盒内时，只掐断破坏命令，绝不终止样本本体。

        杀掉被分析的样本会让沙箱变 error/skipped，破坏 BT 要求的
        "沙箱失败 → 不输出沙箱数据、仅靠 ML 引擎、不改变扫描路结论"。
        """
        from engine.process_protection import ProcessProtection as P
        pp = object.__new__(P)
        killed, notified, events = [], [], []
        pp._emergency_kill = lambda pid: killed.append(pid) or True
        pp._notify_launch_monitoring = lambda *a, **kw: notified.append(a)
        pp._add_event = lambda *a, **k: events.append(a)
        pp._mark_exe_blocked = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('沙箱盒内分支不得登记黑名单'))

        pp._handle_credential_tamper(
            900, 'cmd.exe', rf'{SYS32}\cmd.exe',
            {'kind': 'firewall_off', 'reason': 'netsh 关闭防火墙',
             'evidence': 'netsh advfirewall set allprofiles state off'},
            {'pid': 901, 'name': 'G4m0ad2f1qi（加强版）.exe',
             'exe': r'C:\Users\v\Downloads\G4m0ad2f1qi（加强版）.exe',
             'reason': ''},
            offender_in_box=True)

        self.assertEqual(killed, [900], '只应终止执行破坏命令的子进程')
        self.assertEqual(notified, [], '不得对沙箱盒内样本发 blocked 上报（扰动判定链路）')
        self.assertEqual(events[0][0], 'sensitive_command_in_sandbox')
        self.assertEqual(events[0][3], 'warn')

    def test_handler_kills_both_processes(self):
        """处置必须终止敏感命令进程与发起进程两方。"""
        from engine.process_protection import ProcessProtection as P
        pp = object.__new__(P)
        killed = []
        notified = []
        events = []
        pp._emergency_kill = lambda pid: killed.append(pid) or True
        pp._notify_launch_monitoring = (
            lambda pid, name, exe, reason='', scan_result=None:
            notified.append((pid, name, exe, scan_result)))
        pp._add_event = lambda *a, **k: events.append(a)

        pp._handle_credential_tamper(
            100, 'net.exe', rf'{SYS32}\net.exe',
            {'kind': 'password_set', 'reason': 'net user 设置账户登录密码',
             'evidence': 'net user bob P@ss'},
            {'pid': 200, 'name': 'evil.exe',
             'exe': r'C:\Users\v\Downloads\evil.exe', 'reason': ''})

        self.assertIn(100, killed)
        self.assertIn(200, killed)
        self.assertEqual(len(events), 1)
        # 上报目标应是"非微软官方发起者"，而非 System32\net.exe
        self.assertEqual(notified[0][0], 200)
        self.assertIn('evil.exe', notified[0][1])
        self.assertEqual(notified[0][3].get('status'), 'blocked')


class TestBlockedRelaunchWiring(unittest.TestCase):
    """接线约束：黑名单判定必须早于"正被分析中"路径豁免，且各处挂点齐备。

    否则：提权实例与原始程序同路径 → 会被"正被分析中"豁免先放行 →
    黑名单形同虚设（这正是"依旧发生逃逸"的代码层原因）。
    """

    def setUp(self):
        self.src = open(os.path.join(ROOT, 'engine', 'process_protection.py'),
                        'r', encoding='utf-8').read()

    def test_check_placed_before_analyzing_exemption(self):
        start = self.src.index('def _check_new_process')
        end = self.src.index('_SYSTEM_CRITICAL_EXE_NAMES = {')
        body = self.src[start:end]
        idx_block = body.index('self._is_exe_blocked(exe)')
        idx_analyzing = body.index('if exe and self._is_sandbox_analyzing(exe):')
        self.assertLess(
            idx_block, idx_analyzing,
            '拦截黑名单判定必须早于"沙箱分析中"路径豁免 —— 提权实例与原程序 '
            '同路径，晚于该豁免就会被直接 return 放行。')
        self.assertIn('_kill_blocked_relaunch', body)

    def test_marked_on_both_interception_paths(self):
        """oversize 分支与常规沙箱分支都必须登记黑名单。"""
        self.assertGreaterEqual(
            self.src.count('self._mark_exe_blocked(exe'), 2,
            '常规拦截（_sandbox_then_release 阶段1）与 oversize 分支都应登记黑名单')

    def test_unmarked_on_user_approval(self):
        start = self.src.index('def restart_sandboxed_process')
        nxt = self.src.find('\n    def ', start + 10)
        body = self.src[start:nxt if nxt > 0 else len(self.src)]
        self.assertIn('_unmark_exe_blocked', body,
                      '用户批准重启/放行时必须解除黑名单，否则会被反复拦截')


class TestEkFastLane(unittest.TestCase):
    """EK 快车道：敏感命令不再与沙箱/启动扫描抢同一个 worker 池。

    结构性病因（实测）：主池固定 3 条线程，单条 _check_new_process 串行跑
    签名(≤1.5s)+注入预检(≤1.2s)+上下文注入(≤1.2s)+沙箱链路(预分析 ≤1.2s，
    补杀最坏 5s)，且有 8s 绝对时限 —— 样本一次派生 cmd/net/netsh/powershell
    多个子进程时，后面的条目在队列里过期被 `continue` 丢弃（连检查都没有，
    自然没有 emergency kill）。故敏感命令必须走独立线程。
    """

    def _pp(self):
        import queue as _q
        from engine.process_protection import ProcessProtection as P
        pp = object.__new__(P)
        pp._launch_check_queue = _q.Queue(maxsize=256)
        pp._ek_queue = _q.Queue(maxsize=64)
        pp._launch_check_dedup = {}
        pp._launch_check_dedup_lock = threading.Lock()
        pp._launch_check_dedup_ttl = 3.0
        pp._launch_check_item_deadline = 8.0
        pp._EK_ITEM_DEADLINE = 5.0
        pp._ek_handled_pids = {}
        pp._ek_handled_lock = threading.Lock()
        pp._EK_HANDLED_TTL = 60.0
        return pp

    def test_sensitive_command_goes_to_fast_lane(self):
        pp = self._pp()
        entry = {
            'name': 'cmd.exe', 'exe': rf'{SYS32}\cmd.exe',
            'cmdline': ['cmd.exe', '/c', 'netsh', 'advfirewall', 'set',
                        'allprofiles', 'state', 'off'],
            'parent_pid': 111,
        }
        pp._enqueue_launch_check(4242, entry)
        self.assertEqual(pp._ek_queue.qsize(), 1,
                         '敏感命令必须投递到 EK 快车道（独立线程）')
        self.assertLessEqual(pp._EK_ITEM_DEADLINE,
                             pp._launch_check_item_deadline,
                             '快车道时限应更短（抢时间）')
        # 主池仍收到一份（供非敏感路径的完整判定）
        self.assertEqual(pp._launch_check_queue.qsize(), 1)

    def test_normal_command_not_in_fast_lane(self):
        pp = self._pp()
        entry = {'name': 'notepad.exe', 'exe': rf'{SYS32}\notepad.exe',
                 'cmdline': ['notepad.exe'], 'parent_pid': 1}
        pp._enqueue_launch_check(100, entry)
        self.assertEqual(pp._ek_queue.qsize(), 0, '普通进程不得进快车道')

    def test_ek_handled_ttl(self):
        pp = self._pp()
        self.assertFalse(pp._is_ek_handled(77))
        with pp._ek_handled_lock:
            pp._ek_handled_pids[77] = time.time() + 60
        self.assertTrue(pp._is_ek_handled(77))
        with pp._ek_handled_lock:
            pp._ek_handled_pids[77] = 1.0        # 人为过期
        self.assertFalse(pp._is_ek_handled(77))

    def test_fast_lane_isolated_and_bt_safe(self):
        src = open(os.path.join(ROOT, 'engine', 'process_protection.py'),
                   'r', encoding='utf-8').read()
        # 独立线程池 + 独立队列
        self.assertIn("name=f'EK-FastLane-", src)
        self.assertIn('self._ek_queue', src)
        start = src.index('def _ek_handle_sensitive')
        end = src.index('def _is_ek_handled', start)
        body = src[start:end]
        self.assertIn('_check_origin_chain', body,
                      '快车道必须做发起链判定（否则正常用户的 net user 会被误杀）')
        self.assertIn('offender_in_box=in_box', body,
                      '快车道必须保留 BT 约束（不杀被沙箱分析的样本本体）')
        self.assertIn('_handle_credential_tamper', body)

    def test_ek_has_top_priority_and_privilege(self):
        """规格：EK 必须 time_critical 优先级 + SeDebugPrivilege 最高权限。"""
        src = open(os.path.join(ROOT, 'engine', 'process_protection.py'),
                   'r', encoding='utf-8').read()
        start = src.index('def _ek_fastlane_worker')
        end = src.index('def _handle_credential_tamper', start)
        seg = src[start:end]
        self.assertIn("_boost_current_thread_priority('time_critical')", seg,
                      'EK 线程必须是 time_critical 优先级')
        self.assertIn('_enable_debug_privilege', src,
                      'EK 启动时必须启用 SeDebugPrivilege')
        self.assertIn('_EK_WORKER_COUNT', src)

    def test_zero_io_signal_kills_before_chain_check(self):
        """第 0 级必须**先终止**、后判定（抢在所有 IO 之前）。"""
        src = open(os.path.join(ROOT, 'engine', 'process_protection.py'),
                   'r', encoding='utf-8').read()
        start = src.index('def _ek_handle_sensitive')
        end = src.index('def _is_ek_handled', start)
        body = src[start:end]
        idx_kill0 = body.index('fast_reason')
        idx_chain = body.index('_check_origin_chain')
        self.assertLess(idx_kill0, idx_chain,
                        '零 IO 强信号命中时必须先 _emergency_kill，再判发起链')
        self.assertIn('chain_start = ppid if (prekilled', body,
                      '第 0 级已终止时发起链必须从父进程起算（否则指认不出发起者）')

    def test_zero_io_signal_decision(self):
        """(a) 非系统目录的命令进程 / (b) 发起者在黑名单 → 立即终止。"""
        from engine.process_protection import ProcessProtection as P
        pp = object.__new__(P)
        blocked = set()

        def _is_blocked(exe):
            return os.path.normcase(exe) in blocked
        pp._is_exe_blocked = _is_blocked
        pp._ek_handled_pids = {}
        pp._ek_handled_lock = threading.Lock()
        pp._EK_HANDLED_TTL = 60.0

        # (a) 命令进程在 System32 → 不算强信号（正常用户 net user 不误杀）
        self.assertEqual(pp._ek_should_kill_now(1, {
            'exe': rf'{SYS32}\net.exe', 'name': 'net.exe', 'parent_pid': 0}), '')
        # (a) 命令进程在用户目录（伪装/释放样本）→ 立即终止
        self.assertTrue(pp._ek_should_kill_now(2, {
            'exe': r'C:\Users\v\Downloads\net.exe', 'name': 'net.exe',
            'parent_pid': 0}))
        # (b) 父进程路径已在拦截黑名单 → 立即终止
        import psutil
        blocked.add(os.path.normcase(r'C:\Users\v\Downloads\evil.exe'))
        orig = psutil.Process
        psutil.Process = lambda _pid: type('X', (), {
            'exe': staticmethod(lambda: r'C:\Users\v\Downloads\evil.exe')})()
        try:
            self.assertTrue(pp._ek_should_kill_now(3, {
                'exe': rf'{SYS32}\cmd.exe', 'name': 'cmd.exe',
                'parent_pid': 4321}))
        finally:
            psutil.Process = orig


if __name__ == '__main__':
    unittest.main()