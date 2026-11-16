# -*- coding: utf-8 -*-
"""
TDD - 驱动加载后 WMI 提示"发生意外超时"的修复

两个根因必须同时消除：

[A] 用户态 win32com WMI 查询（ConnectServer + ExecNotificationQuery + ExecQuery）
    完全没有超时控制，默认 COM/WMI 管道阻塞可达分钟级 → UI 无响应后弹超时。
    要求：所有 WMI 查询调用要么显式加标志 + Next(ms) 严格超时，
    要么被包裹在 Event.wait(timeout<=10s) 的守护线程结构内。

[B] 内核驱动 protect.c 对"所有进程"访问 PSLS 一律剥离 PROCESS_VM_READ。
    而 WMI 提供者宿主 wmiprvse.exe 枚举 Win32_Process 时必须读取每个进程 PEB
    才能拿 Name / CommandLine / ExecutablePath / ParentProcessId。被剥离后
    它会反复重试造成查询堆积 → WMI 管道阻塞 → A 里的无限时查询永久挂。
    要求：PreOperationCallback 对调用者 ImageFileName ∈ {wmiprvse.exe,
    WmiPrvSE.exe, WMIPRVSE.EXE} 的保留 PROCESS_VM_READ（仅豁免这一位，
    PROCESS_TERMINATE / CREATE_THREAD / SET_INFORMATION 等高危位照常剥离）。

[C] etw_monitor.py 启动 PowerShell WMI 订阅时，给子进程写 {"type":"ready"} 的
    等待时间仅 5s；WMI CIM 仓库预热/首次注册在低配机器上偶发需要 8~10s，导致
    warning "等待 WMI 就绪信号超时"，用户感知"WMI 不可用"。要求 >= 10s。
"""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SYS = os.path.join(ROOT, 'engine', 'system_protection.py')
PRO = os.path.join(ROOT, 'engine', 'etw_monitor.py')
DRV = os.path.join(ROOT, 'driver', 'src', 'protect.c')


class TestWmiTimeoutsNotStuck(unittest.TestCase):

    # --------------------------------------------------------------- [A] ---
    def _has_bounded_timeout(self, src: str, snippet_name: str,
                              limit_seconds: int = 10,
                              allow_milliseconds=True) -> bool:
        """判断源码中是否存在明确的时间上限（秒或毫秒，取较小值匹配）。
        优先匹配守护线程 Event.wait(timeout=X) / proc.wait(timeout=X) /
        join(timeout=X)；其次匹配 NextEvent(ms) / ConnectServer 含超时参数。
        """
        # 秒级模式：timeout=X 或 wait(X)
        limit_ms = limit_seconds * 1000 if allow_milliseconds else None
        pat_sec = re.compile(
            r"(?:Event\.wait|_stop_event\.wait|wait_timeout|"
            r"\.wait\(|\.join\(timeout=|\.wait\(timeout=)"
            r"\s*(\d+(?:\.\d+)?)\s*[,)]")
        for m in pat_sec.finditer(src):
            v = float(m.group(1))
            if v > 0 and v <= limit_seconds:
                return True
        if limit_ms is not None:
            # 毫秒：NextEvent(5000) / iFlagsMs 等
            pat_ms = re.compile(
                r"NextEvent\(\s*(\d+)\s*\)")
            for m in pat_ms.finditer(src):
                v = int(m.group(1))
                if 0 < v <= limit_ms:
                    return True
            # wbemFlagUseAmendedQualifiers... 不相关；找显式的 TimeoutMs 参数
        return False

    def test_wmi_registry_monitor_loop_has_strict_timeout(self):
        """_wmi_registry_loop: ConnectServer / ExecNotificationQuery / NextEvent
        整体必须有 <=10s 的超时兜底（Event.wait(timeout) 看门狗，或
        NextEvent(ms) <= 10000）。否则驱动加载后 wmiprvse 卡住会把这个线
        程永久挂起，系统保护后台线程不再跑基线检查。"""
        with open(SYS, 'r', encoding='utf-8') as f:
            src = f.read()
        m = re.search(
            r"def _wmi_registry_loop\(self\):\n(?P<body>.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "_wmi_registry_loop 未找到")
        body = m.group('body')
        # 必须出现有限时间等待：NextEvent(ms) <= 10000 或 Event.wait(<=10s)
        self.assertTrue(
            self._has_bounded_timeout(body, '_wmi_registry_loop', 10),
            "_wmi_registry_loop 内的 ConnectServer + ExecNotificationQuery + "
            "NextEvent 循环未发现 <=10 秒的严格超时兜底。驱动加载后 WMI 管道"
            "阻塞时，这里会永久挂住，是'发生意外超时'的核心根因。")

    def test_check_wmi_persistence_has_bounded_timeout(self):
        """_check_wmi_persistence: 3 个 ExecQuery（Filter/Consumer/Binding）
        必须被 <=10 秒的守护线程/Event.wait 或进程级 timeout 包裹。
        win32com 的 server.ExecQuery 默认无限阻塞。"""
        with open(SYS, 'r', encoding='utf-8') as f:
            src = f.read()
        m = re.search(
            r"def _check_wmi_persistence\(self\):\n(?P<body>.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group('body')
        # 3 次 ExecQuery 必须存在
        self.assertEqual(body.count('.ExecQuery('), 3,
                         "预期 3 个 ExecQuery：__EventFilter / "
                         "CommandLineEventConsumer / __FilterToConsumerBinding")
        # 且整体被 <=10s 超时兜底（timeout=X / Event.wait(X) / 线程看门狗）
        self.assertTrue(
            self._has_bounded_timeout(body, '_check_wmi_persistence', 10),
            "_check_wmi_persistence 的 3 个 ExecQuery 未发现 <=10s 超时兜底；"
            "Win32COM 默认无限阻塞 → 驱动加载后堆积查询会 UI 层报'意外超时'。")

    # --------------------------------------------------------------- [B] ---
    def test_driver_exempts_wmiprvse_vm_read_only(self):
        """protect.c PreOperationCallback 中，对调用者为 wmiprvse.exe 时，
        不得剥离 PROCESS_VM_READ；但 PROCESS_TERMINATE 等高危位仍必须剥离。
        即不能简单地 "if wmiprvse return OB_PREOP_SUCCESS"。"""
        with open(DRV, 'r', encoding='utf-8') as f:
            src = f.read()
        # 回调中必须显式根据调用者进程名豁免 VM_READ（单独这一位）
        self.assertTrue(
            re.search(r"(?i:wmiprvse|WmiPrvSE|WMIPRVSE)", src)
            and ('PROCESS_VM_READ' in src),
            "protect.c 中未发现针对 wmiprvse.exe / WmiPrvSE.EXE 的 PROCESS_VM_READ "
            "豁免逻辑。WMI Provider 宿主枚举 Win32_Process 时必须读 PSLS 的 PEB 才能"
            "返回 Name/CommandLine/ExecutablePath；剥离 VM_READ 会导致它反复重试，"
            "WMI 管道堆积并传导到应用层阻塞。")

        # 必须区分"只豁免 VM_READ"与"豁免全部"：高危掩码 PROCESS_TERMINATE 等
        # 仍然应该被剥离给 wmiprvse，简单放行整个调用是不对的。
        pre_cb = re.search(
            r"static OB_PREOP_CALLBACK_STATUS PreOperationCallback\("
            r".*?^}", src, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(pre_cb)
        body_cb = pre_cb.group(0)
        has_specific_vm_read_exempt = (
            # 出现以下特征之一：
            # 1. 计算 final_mask 时显式把 wmiprvse 加上 VM_READ 回来
            # 2. 计算 blocked / original 时，移除 VM_READ 仅对 wmiprvse
            bool(re.search(
                r"(?i)wmiprvse.*PROCESS_VM_READ|PROCESS_VM_READ.*(?i)wmiprvse",
                body_cb))
            or bool(re.search(
                r"PROCESS_VM_READ\b[^;]{0,160}(?i)wmiprvse",
                body_cb))
            or bool(re.search(
                r"(?i)wmiprvse[^;]{0,220}PROCESS_VM_READ", body_cb))
        )
        self.assertTrue(
            has_specific_vm_read_exempt,
            "PreOperationCallback 中未见【仅豁免 PROCESS_VM_READ 这一位】的 "
            "wmiprvse 专属逻辑。若是简单 return OB_PREOP_SUCCESS 会完全失去"
            "对 wmiprvse 的防护（恶意样本若假冒/注入 WMI Provider 就能终止 PSLS）")

    # --------------------------------------------------------------- [C] ---
    def test_etw_wmi_ready_timeout_ge_10s(self):
        """etw_monitor._start_wmi_mode 中给 PowerShell WMI 订阅的就绪信号
        等待时间至少 10 秒（WMI CIM 仓库预热/首次注册偶发慢）。"""
        with open(PRO, 'r', encoding='utf-8') as f:
            src = f.read()
        m = re.search(
            r"def _start_wmi_mode\(self\).*?(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group(0)
        w = re.search(r"_wmi_ready\.wait\(timeout\s*=\s*(\d+(?:\.\d+)?)\)", body)
        self.assertIsNotNone(w, "_start_wmi_mode 未使用 _wmi_ready.wait(timeout=...)")
        seconds = float(w.group(1))
        self.assertGreaterEqual(
            seconds, 10,
            f"WMI 就绪信号等待只有 {seconds}s；驱动加载 + CIM 仓库预热时首次 "
            "Register-WmiEvent 经常要 7~9s，5s 会造成大量误判超时，用户感知 "
            "'WMI 不工作'。请提升到 >= 10s。")


if __name__ == '__main__':
    unittest.main()
