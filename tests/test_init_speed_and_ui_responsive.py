"""
TDD: 初始化加速 + 威胁处置期间不阻塞主线程（无响应概率下降）

修复目标（失败测试未写之前现状）：
  1) _init_protection_modules 整段在主线程串行，含 SelfProtection.start()
     SCM/驱动安装等待 数秒，Splash 无响应。
     → 预期：__init__ 中防护模块初始化以"后台 worker 线程 + 完成信号切主线程写回"
        的方式进行，主线程只负责接收结果 + 活动日志 + emit launchReady。
  2) Core init worker（SignatureDB + ScanEngine + MLWorker/QuarantineManager）
     目前串行。SignatureDB 读签名磁盘 IO 和 LightGBM 子进程 spawn + QM 初始化
     彼此独立，可并行至少 2~3 倍加速。
  3) processThreat / _delete_threat_file / _auto_process_threat 在 QWebChannel
     主线程中同步做：prep_for_remove(takeown+icacls)、删除(10s cmd timeout)、
     隔离(加密)。大量恶意对象处置时 UI 必然白屏"未响应"。
     → 预期：桥层将这三个耗时操作包进后台线程，主线程只接收 JSON 调用并立刻入队
        返回，完成后通过 threatActionResult + 桌面弹窗通知前端。
        即：processThreat 必须不直接调用 _auto_process_threat / _delete_threat_file
        的同步版，或这两个内部启动线程。
"""

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SRC_BRIDGE = os.path.join(ROOT, 'ui', 'webview', 'bridge.py')


def read_bridge():
    with open(SRC_BRIDGE, 'r', encoding='utf-8') as f:
        return f.read()


class TestInitSpeedup(unittest.TestCase):
    # ------------------------------------------------ 初始化加速 -----
    def test_protection_modules_start_runs_off_ui_thread(self):
        """_init_protection_modules 入口必须不再在主线程中串行做
        SelfProtection.start()/ProcessProtection.start() 等阻塞 start()。
        必须启动 worker thread 或在 _init_protection_modules 内部把所有
        模块 start() 打包到后台线程，最终用 singleShot / 信号在主线程
        写活动日志。
        """
        src = read_bridge()
        m = re.search(
            r"def _init_protection_modules\(self\):\n(.*?)(?=\n    def |\n    @|\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group(1)

        # 守卫仍保留（允许同步 guard 去重），但必须存在后台启动机制：
        # 出现 threading.Thread(target=...) 且目标名 / 代码段里包含
        # "后台初始化防护模块" / "ProtectionInitWorker" / start_protection_modules_worker
        has_worker = bool(
            re.search(r"threading\.Thread\s*\(\s*target\s*=\s*self\._start_protection_worker", body)
            or re.search(r"def _start_protection_worker\b", src)
            or re.search(r"_protection_init_thread\s*=\s*threading\.Thread", src)
        )
        self.assertTrue(
            has_worker,
            "_init_protection_modules 仍在主线程串行跑 start()；"
            "含驱动/SCM 等待的 SelfProtection.start 会卡死 Splash。"
            "需要改：入口开后台线程执行所有模块 init+start，主线程最后 singleShot 写回。")

        # 防护模块初始化完成后，必须调度 launchReady/驱动判定（这部分主线程动作）
        self.assertTrue(
            re.search(r"_finalize_driver_and_launch_ready|_emit_launch_ready_once", body)
            or re.search(r"QTimer\.singleShot\([^)]*_finalize_driver_and_launch_ready", src),
            "防护模块 worker 结束后未在主线程中触发驱动判定 + launchReady，"
            "会出现进度 99% 不结束的情况。")

    def test_core_init_parallelizes_independent_sub_inits(self):
        """core init worker：SignatureDB 加载完成后，ScanEngine 依赖于 DB；
        但 QuarantineManager + VirusIdentifier + MLDetector 与 SignatureDB
        完全独立（QM 甚至只与 data/quarantine 有关）。现状是按顺序依次 init，
        测试约束：在 _start_core_init_async 的 worker() 里必须出现一次
        Thread/ThreadPoolExecutor/手动并发启动：QM + VirusID 独立于
        SignatureDB 之外启动，或者 SignatureDB 加载 + QM init 并行。
        """
        src = read_bridge()
        m = re.search(r"def _start_core_init_async\(self\):\n(.*?)(?=\n    def |\Z)",
                      src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group(1)

        # 允许的并发写法：显式启动子线程做 QM / VirusID / ML 初始化，
        # 或使用 ThreadPoolExecutor。核心是不要串行。
        parallel_markers = [
            # QM 在独立线程初始化（不依赖 SignatureDB）
            r"threading\.Thread\([\s\S]{0,1500}?QuarantineManager\(",
            r"ThreadPoolExecutor\(",
            r"_qm_thread\s*=\s*threading\.Thread",
            r"_vi_thread\s*=\s*threading\.Thread",
            r"_init_qm_thread\s*=",
        ]
        ok = any(re.search(pat, body) for pat in parallel_markers)
        self.assertTrue(
            ok,
            "_start_core_init_async 仍串行做 SignatureDB → ScanEngine → "
            "QM → VirusID → ML 的全部初始化；其中 SignatureDB 读磁盘(MB级)、"
            "QM 遍历隔离区元数据、LightGBM 子进程 spawn 都可以并行。请使用"
            " Thread 或 ThreadPoolExecutor 把 QM/VirusID/ML 与 SignatureDB 并行。")


class TestThreatHandlingNeverBlocksUI(unittest.TestCase):
    # ------------------------------------------------ 恶意处置不卡主线程 -----
    def test_process_threat_offloads_to_worker(self):
        """processThreat() 由 QWebChannel 主线程调用。
        delete / auto / quarantine 三个耗时 action 必须不直接同步跑
        _delete_threat_file / _auto_process_threat（内部会 prep_for_remove +
        cmd del 10s timeout + 隔离加密，全部在主线程 = 未响应）。
        测试约束：
          - processThreat 在 action != ignore 时必须启动后台线程
            （或已有 _dispose_executor submit）执行实际处置。
          - 处置完成后通过 threatActionResult + _show_threat_result_popup
            在主线程通知前端（singleShot / emit 均可）。
        """
        src = read_bridge()
        m = re.search(r"def processThreat\(self, payload_str\):\n(.*?)(?=\n    # =====|    def )",
                      src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group(1)

        # ignore 分支保留同步；其他三个 action 必须 offload
        offloads = bool(
            re.search(r"elif action == 'auto':[\s\S]{0,600}?"
                      r"(?:threading\.Thread\(|ThreadPoolExecutor|"
                      r"submit\(|_threat_executor\s*\.submit)", body)
            or re.search(r"_offload_threat_disposition\(", body)
            or re.search(r"_queue_threat_disposition\(", body)
        )
        self.assertTrue(
            offloads,
            "processThreat 在 action=auto/delete/quarantine 时仍同步跑在主线程；"
            "遇到 500MB 样本隔离加密 / cmd del 10s 超时 / terminate_malware_process "
            "扫 WMI 几秒的场景，QWebChannel 被占用 → Qt 渲染进程超时 → '未响应'。"
            "必须 offload 到后台线程，完成后通过信号/ singleShot 通知 UI。")

    def test_delete_threat_file_reentry_has_worker_only_switch(self):
        """_delete_threat_file / _auto_process_threat 被 offload 后，仍可能被
        其他路径直接调用（如 on_realtime_threat auto）。所以两个函数不能
        直接假设是在子线程，需允许两种调用。更严格：在 on_realtime_threat
        的 auto 分支中也必须与主线程解耦，调用点本身已经在 realtime
        monitor worker 线程（子线程），所以该分支 OK。本断言主要确认：
        `processThreat` 的 auto/delete/quarantine offload 一定不直接执行
        "同步 cmd del 10s"等调用。
        """
        src = read_bridge()
        # 简单验证：在 processThreat 主体中，`elif action == 'delete':` 后面的 10 行内
        # 不能直接出现 `self._delete_threat_file(file_path, sig_name, status)`
        # 同步调用，除非被线程/executor 包起来。正则我们要求：delete 行与
        # _delete_threat_file 之间必须出现 Thread/executor/offload 标记。
        m = re.search(
            r"elif action == 'delete':\n(?P<body>.*?)(?=\n\s{12}elif action == 'quarantine':|\n\s{12}else:)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "processThreat 找不到 delete 分支")
        delete_body = m.group('body')
        has_delete_call = '_delete_threat_file' in delete_body
        offload_wrapper = bool(
            re.search(r"threading\.Thread|ThreadPoolExecutor|submit\(|"
                      r"_offload_threat_disposition|_queue_threat_disposition|"
                      r"QTimer\.singleShot\([^)]*_delete_threat_file",
                      delete_body)
        )
        if has_delete_call:
            self.assertTrue(
                offload_wrapper,
                "processThreat 的 delete 分支仍直接同步调用 _delete_threat_file，"
                "主线程 UI 会在 takeown+icacls+cmd del 期间卡死。请用线程/executor 包装。")


if __name__ == '__main__':
    unittest.main()
