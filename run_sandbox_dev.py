# -*- coding: utf-8 -*-
"""PSLS 沙箱分析窗口 - 开发测试脚本

用法：
    # 仅演示窗口（模拟进度，完成后自动关闭）
    python run_sandbox_dev.py --demo

    # 指定文件模拟分析 + 指定判定结果
    python run_sandbox_dev.py --file C:\\path\\to\\file.exe --verdict clean

    # 安全判定后展示"安全放行确认"窗口（同风格 SandboxReleaseWindow）
    python run_sandbox_dev.py --demo --verdict clean --release

    # 可疑/恶意判定后展示"威胁结果"窗口（SandboxThreatWindow）
    python run_sandbox_dev.py --demo --verdict malware
    python run_sandbox_dev.py --demo --verdict suspicious

    # 沙箱启动失败后展示"失败结果"窗口（SandboxFailureWindow）
    python run_sandbox_dev.py --demo --verdict failed

    # 尝试真实沙箱分析（需要完整 PSLS 环境）
    python run_sandbox_dev.py --file C:\\path\\to\\file.exe --real

新窗口行为遵循用户需求：
- 分析完成后立即关闭分析窗口（emit completed）
- 判定 clean 且 --release 时展示 SandboxReleaseWindow（同意重启/不重启，5s 超时默认拒绝）
- 判定 suspicious/malware 时展示 SandboxThreatWindow（红色 × 图标，单个"知道了"按钮）
- 判定 failed 时展示 SandboxFailureWindow（同威胁窗口样式，文案：沙箱进程启动失败，已将其强制隔离。）
"""
import sys
import os
import time
import threading
import argparse
import json

# ------------------------------------------------------------------ 路径设置
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, 'ui', 'webview'))
sys.path.insert(0, _HERE)


def _setup_high_dpi():
    """高 DPI 适配。"""
    try:
        from PyQt5.QtCore import Qt
        from PyQt5.QtWidgets import QApplication
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    except Exception:
        pass


def _simulate_sandbox_progress(window, file_path, duration=20, verdict=None):
    """模拟沙箱分析进度（开发模式）。

    按阶段推进进度，展示窗口动画效果；完成后按指定/随机 verdict
    调用 set_result（emit completed + 自动关闭窗口）。

    全程在主线程执行（QTimer 驱动），避免跨线程调用 QWidget 更新。
    """
    from PyQt5.QtCore import QTimer

    stages = [
        ('初始化沙箱环境', 10),
        ('准备受限令牌', 18),
        ('启动进程 (低权限)', 28),
        ('注入 Frida 钩子', 38),
        ('加载规则引擎', 48),
        ('采集行为数据', 60),
        ('分析文件系统操作', 70),
        ('分析网络行为', 78),
        ('分析 API 调用链', 85),
        ('评分威胁等级', 92),
        ('生成分析报告', 98),
    ]

    details = [
        '[Frida] Hook: CreateProcessW → 低权限令牌注入',
        '[Frida] Hook: VirtualAlloc → 监测 RWX 区域',
        '[Frida] Hook: CreateRemoteThread → 远程线程监控',
        '[API] LoadLibraryA: 加载非系统 DLL (3次)',
        '[API] WinExec: 执行可疑命令行参数',
        '[FILE] 写入临时文件: C:\\Users\\*\\AppData\\Local\\Temp\\xxx.tmp',
        '[NET] 尝试连接 192.168.*.*:443 (C2 特征)',
        '[ENTROPY] 节区熵: .text=7.85 (疑似加壳)',
        '[IMPORT] 异常导入: IsDebuggerPresent + OutputDebugStringA',
    ]

    step_ms = max(50, int(duration * 1000 / len(stages)))

    def _finish():
        # 最终结果（未指定则随机）
        final_verdict = verdict
        if final_verdict is None:
            import random
            verdict_roll = random.random()
            if verdict_roll < 0.15:
                final_verdict = 'malware'
            elif verdict_roll < 0.45:
                final_verdict = 'suspicious'
            else:
                final_verdict = 'clean'

        if final_verdict == 'malware':
            window.set_result('malware', '检测到木马行为 - 远程线程注入 + C2 通信')
        elif final_verdict == 'suspicious':
            window.set_result('suspicious', '存在可疑特征 - 熵值异常 + 可疑 API 调用')
        elif final_verdict == 'failed':
            window.set_result('failed', '沙箱启动失败，进程无法创建')
        else:
            window.set_result('clean', '文件行为正常，无恶意特征')

        print(f'[sandbox-dev] 模拟分析完成: verdict={final_verdict}，'
              '分析窗口已自动关闭')

    def _step(i):
        if i >= len(stages):
            _finish()
            return
        stage, target_pct = stages[i]
        window.set_status(stage)
        window.set_progress(target_pct, stage)
        if i < len(details):
            window.set_details(details[:i + 1])
        QTimer.singleShot(step_ms, lambda: _step(i + 1))

    _step(0)


def _run_real_sandbox(window, file_path):
    """尝试运行真实沙箱分析（需要完整 PSLS 环境）。

    若 SandboxAnalyzer 导入失败则回退到模拟模式。
    """
    try:
        from engine.sandbox_analyzer import SandboxAnalyzer, SandboxConfig
        print('[sandbox-dev] SandboxAnalyzer 导入成功，启动真实分析...')

        config = SandboxConfig()
        config.timeout = 15
        analyzer = SandboxAnalyzer(config)

        def on_progress(stage: str, percent: float):
            pct = int(percent * 100)
            window.set_progress(pct, stage)
            window.set_status(stage)

        def worker():
            try:
                result = analyzer.analyze(file_path, on_progress=on_progress)
                verdict = result.get('verdict', 'error')
                score = result.get('score', 0)
                behaviors = result.get('behaviors', [])

                # 转为详情文本
                details = []
                for b in behaviors[:10]:
                    cat = b.get('category', 'unknown')
                    desc = b.get('description', '')
                    sev = b.get('severity', '')
                    details.append(f'[{cat}] {desc} ({sev})')
                window.set_details(details)

                # set_result 会 emit completed + 自动关闭窗口
                window.set_result(
                    verdict if verdict in ('malware', 'suspicious', 'clean') else 'error',
                    f'评分 {score}/100 - {verdict}',
                )
                window.set_status(f'评分 {score}/100 - 分析完成({verdict})')

            except Exception as e:
                import traceback
                print(f'[sandbox-dev] 真实分析异常: {e}')
                traceback.print_exc()
                # 回退到模拟模式
                print('[sandbox-dev] 回退到模拟模式...')
                _simulate_sandbox_progress(window, file_path)

        threading.Thread(target=worker, daemon=True,
                         name='RealSandbox-Analyzer').start()

    except ImportError as e:
        print(f'[sandbox-dev] SandboxAnalyzer 导入失败: {e}')
        print('[sandbox-dev] 回退到模拟模式...')
        _simulate_sandbox_progress(window, file_path)
    except Exception as e:
        print(f'[sandbox-dev] 初始化真实分析器异常: {e}')
        print('[sandbox-dev] 回退到模拟模式...')
        _simulate_sandbox_progress(window, file_path)


def main():
    parser = argparse.ArgumentParser(
        description='PSLS 沙箱分析窗口 - 开发测试工具'
    )
    parser.add_argument(
        '--file', '-f', type=str, default='',
        help='要分析的文件路径'
    )
    parser.add_argument(
        '--demo', '-d', action='store_true',
        help='演示模式（创建虚拟文件路径进行演示）'
    )
    parser.add_argument(
        '--real', '-r', action='store_true',
        help='尝试真实沙箱分析（需要完整 PSLS 环境）'
    )
    parser.add_argument(
        '--duration', '-t', type=int, default=20,
        help='模拟模式分析时长（秒，默认 20）'
    )
    parser.add_argument(
        '--verdict', '-v', type=str, default='',
        choices=['clean', 'suspicious', 'malware', 'failed'],
        help='模拟判定的最终结果（默认随机；failed 展示沙箱失败窗口）'
    )
    parser.add_argument(
        '--release', action='store_true',
        help='判定 clean 后展示 SandboxReleaseWindow（安全放行确认/是否重启）'
    )

    args = parser.parse_args()

    _setup_high_dpi()

    from PyQt5.QtCore import Qt
    from PyQt5.QtWidgets import QApplication
    from sandbox_analysis_window import (
        SandboxAnalysisWindow,
        SandboxReleaseWindow,
        SandboxThreatWindow,
        SandboxFailureWindow,
    )

    app = QApplication(sys.argv)
    app.setApplicationName('PSLS Sandbox Dev')

    # 确定文件路径
    file_path = args.file
    if not file_path:
        if args.demo:
            file_path = r'C:\Users\Demo\Desktop\SampleMalware.exe'
        else:
            file_path = r'C:\Users\Test\Desktop\UnknownFile.exe'

    print(f'[sandbox-dev] 目标文件: {file_path}')

    # 创建窗口
    window = SandboxAnalysisWindow(file_path)
    window.show()
    window.start()

    # 全局持有窗口引用（防 GC）
    _release_win = None
    _result_win = None

    def _on_analysis_completed():
        """分析完成（分析窗口已自动关闭）：按 verdict 展示对应结果窗口"""
        nonlocal _release_win, _result_win

        v = getattr(window, '_result_state', 'clean') or 'clean'
        if v == 'failed':
            try:
                print('[sandbox-dev] 沙箱启动失败 → 展示 SandboxFailureWindow')
                _result_win = SandboxFailureWindow(file_path)
                _result_win.acknowledged.connect(
                    lambda: (print('[sandbox-dev] 用户确认失败提示'), app.quit()))
                _result_win.show()
            except Exception as e:
                import traceback
                traceback.print_exc()
                app.quit()
        elif v in ('malware', 'suspicious'):
            try:
                label = '恶意' if v == 'malware' else '可疑'
                print(f'[sandbox-dev] 判定{label} → 展示 SandboxThreatWindow')
                _result_win = SandboxThreatWindow(file_path)
                _result_win.acknowledged.connect(
                    lambda: (print('[sandbox-dev] 用户确认威胁提示'), app.quit()))
                _result_win.show()
            except Exception as e:
                import traceback
                traceback.print_exc()
                app.quit()
        elif v == 'clean' and args.release:
            try:
                print('[sandbox-dev] 判定安全 → 展示 SandboxReleaseWindow（5s 超时默认不重启）')
                _release_win = SandboxReleaseWindow(file_path)
                _release_win.releaseAccepted.connect(
                    lambda: (print('[sandbox-dev] 用户选择: 同意重启'), app.quit()))
                _release_win.releaseRejected.connect(
                    lambda: (print('[sandbox-dev] 用户选择: 不重启（或超时）'), app.quit()))
                _release_win.show()
            except Exception as e:
                import traceback
                traceback.print_exc()
                app.quit()
        else:
            app.quit()

    # 分析线程(模拟/真实子线程)会发射 completed 信号；
    # 必须用 QueuedConnection 切回主线程再创建 SandboxReleaseWindow，
    # 否则会在子线程创建 QWidget 导致挂起/崩溃。
    window.completed.connect(_on_analysis_completed, Qt.QueuedConnection)

    # 启动分析
    if args.real:
        print('[sandbox-dev] 模式: 真实沙箱分析')
        _run_real_sandbox(window, file_path)
    else:
        print('[sandbox-dev] 模式: 模拟分析 (duration={}s, verdict={})'.format(
              args.duration, args.verdict or 'random'))
        print('[sandbox-dev] 使用 --real 参数可尝试真实沙箱分析')
        # 模拟分析已在主线程由 QTimer 驱动，直接启动即可
        _simulate_sandbox_progress(window, file_path, args.duration,
                                   args.verdict or None)

    # 保持运行直到窗口流程结束
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()