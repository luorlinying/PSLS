#!/usr/bin/env python3
"""
GUI入口文件 - 使用 WebView (PyQt5 + QWebEngine)
支持 PyInstaller 打包 (onedir 模式)
"""

import sys
import os
import traceback
import multiprocessing

# Windows multiprocessing 子进程支持（必须在任何其他代码之前调用）
# 实时防护扫描子进程依赖此调用正确初始化
multiprocessing.freeze_support()

# ===========================================================================
# 崩溃捕获：faulthandler + sys.excepthook
# 确保在硬崩溃（segfault）时也能输出诊断信息
# ===========================================================================
try:
    import faulthandler
    _fault_log_path = os.path.join(os.path.expanduser('~'), 'psls_crash.log')
    _fault_file = open(_fault_log_path, 'a', encoding='utf-8')
    # 注意：不调用 faulthandler.enable() —— 它在 Windows 上注册
    # SetUnhandledExceptionFilter 覆盖 WER 崩溃处理，导致 LocalDumps 无法生成
    # minidump。崩溃线程栈由 main_window.py 中的 dump_traceback_later 周期性
    # 转储兜底，原生栈依赖 WER minidump + cdb 分析（-z 离线）。
    def _early_log(msg):
        try:
            ts = __import__('datetime').datetime.now()
            with open(os.path.join(os.path.expanduser('~'), 'psls_debug.log'), 'a', encoding='utf-8') as f:
                f.write(f"[{ts}] {msg}\n")
        except Exception:
            pass
    _early_log(f"faulthandler enabled, crash log -> {_fault_log_path}")
except Exception:
    _early_log = None

def _crash_excepthook(exc_type, exc_value, exc_tb):
    """捕获未处理的异常"""
    try:
        tb_text = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
        try:
            _debug_log(f"UNHANDLED EXCEPTION:\n{tb_text}")
        except Exception:
            print(f"UNHANDLED EXCEPTION:\n{tb_text}", file=sys.stderr)
    except Exception:
        pass
    sys.__excepthook__(exc_type, exc_value, exc_tb)

sys.excepthook = _crash_excepthook

# ===========================================================================
# 原生崩溃 minidump 钩子（定位 0x8001010D RPC_E_DISCONNECTED）
# 策略：用 AddVectoredExceptionHandler 注册 VEH（First 模式）。
#   - SetUnhandledExceptionFilter 会被 QtWebEngine/Chromium 等后加载库
#     覆盖，不可靠；VEH 由系统维护独立链，部分库覆盖 filter 不影响它。
#   - 在 VEH 首次回调里用 MiniDumpWriteDump 立即写 dump，不阻塞处理链
#     （返回 EXCEPTION_CONTINUE_SEARCH 交给后续 VEH/SEH）。
#   - 生成的 dump 供 cdb 离线分析原生调用栈。
# 重要坑：
#   a) AddVectoredExceptionHandler 导出在 kernel32.dll，不在 ntdll!
#   b) msvcrt.get_osfhandle 是 Python 内置 msvcrt 模块的函数，
#     不是 ctypes.WinDLL('msvcrt')！
#   c) CTYPES 回调对象必须保持全局引用，否则被 GC 后 VEH 悬空不触发。
# ===========================================================================
_CRASH_FILTER_KEEPALIVE = []  # 全局引用，防止回调对象被 GC

def _install_native_minidump_hook():
    try:
        import ctypes
        import ctypes.wintypes as wt
        import msvcrt  # Python 内置模块（get_osfhandle 在这里）

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        dbghelp = ctypes.WinDLL('dbghelp')

        _dump_dir = os.path.join(os.path.expanduser('~'), 'crashdumps')
        try:
            os.makedirs(_dump_dir, exist_ok=True)
        except Exception:
            pass

        EXCEPTION_MAXIMUM_PARAMETERS = 15
        class _EXCEPTION_RECORD(ctypes.Structure):
            _fields_ = [
                ('ExceptionCode', wt.DWORD),
                ('ExceptionFlags', wt.DWORD),
                ('ExceptionRecord', ctypes.c_void_p),
                ('ExceptionAddress', ctypes.c_void_p),
                ('NumberParameters', wt.DWORD),
                ('ExceptionInformation', ctypes.c_void_p * EXCEPTION_MAXIMUM_PARAMETERS),
            ]
        class _EXCEPTION_POINTERS(ctypes.Structure):
            _fields_ = [
                ('ExceptionRecord', ctypes.POINTER(_EXCEPTION_RECORD)),
                ('ContextRecord', ctypes.c_void_p),
            ]

        MiniDumpWriteDump = dbghelp.MiniDumpWriteDump
        # ExceptionParam 参数的正确类型是 PMINIDUMP_EXCEPTION_INFORMATION
        # （ThreadId + ExceptionPointers + ClientPointers）。
        # 正确传入该结构时，dump 内包含异常记录/上下文，cdb `.exr`/`.ecxr`
        # 可直接定位异常指令；传 None 则 dump 无异常上下文，只能看线程栈。
        class _MINIDUMP_EXCEPTION_INFORMATION(ctypes.Structure):
            _fields_ = [
                ('ThreadId', wt.DWORD),
                ('ExceptionPointers', ctypes.POINTER(_EXCEPTION_POINTERS)),
                ('ClientPointers', wt.BOOL),
            ]
        MiniDumpWriteDump.argtypes = [
            wt.HANDLE, wt.DWORD, wt.HANDLE, wt.DWORD,
            ctypes.POINTER(_MINIDUMP_EXCEPTION_INFORMATION),
            ctypes.c_void_p, ctypes.c_void_p,
        ]
        MiniDumpWriteDump.restype = wt.BOOL

        # 基类型 dump（含模块列表 + 线程上下文 + 调用栈），比 WithFullMemory 更稳更快
        _MINIDUMP_FLAGS = 0x00000000  # MINIDUMP_TYPE::MiniDumpNormal

        # 限频状态（VEH 回调内避免 Python 全局变量，用列表包裹的简单数值）
        _last_dump_time = [0.0]

        # 文件句柄创建/关闭（异常回调内避免 Python 文件对象，直接用 Win32 句柄）
        CreateFileW = kernel32.CreateFileW
        CreateFileW.argtypes = [
            wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID,
            wt.DWORD, wt.DWORD, wt.HANDLE,
        ]
        CreateFileW.restype = wt.HANDLE
        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [wt.HANDLE]
        CloseHandle.restype = wt.BOOL
        GENERIC_WRITE = 0x40000000
        FILE_SHARE_READ = 0x1
        CREATE_ALWAYS = 2
        FILE_ATTRIBUTE_NORMAL = 0x80
        INVALID_HANDLE_VALUE = wt.HANDLE(-1).value

        @ctypes.WINFUNCTYPE(wt.LONG, ctypes.POINTER(_EXCEPTION_POINTERS))
        def _top_level_filter(pExceptionPointers):
            try:
                code = 0
                addr = 0
                if pExceptionPointers and pExceptionPointers.contents and pExceptionPointers.contents.ExceptionRecord:
                    code = int(pExceptionPointers.contents.ExceptionRecord.contents.ExceptionCode)
                    addr = int(pExceptionPointers.contents.ExceptionRecord.contents.ExceptionAddress or 0)
                # 策略：任何第一次出现的异常都写 dump（含堆损坏 0xC0000374、
                # C++ 异常 0xE06D7363 等原先被白名单漏掉的致命码）。
                # 用限频防风暴：同一进程任何 2 秒内最多写 1 个，避免 COM
                # 异常循环（0x8001010D 启动期可能多次触发）刷爆磁盘。
                #
                # 例外：0x4001000A/0x4001000B 是 DBG_PRINTEXCEPTION_C/W，
                # 即 OutputDebugString 触发的“调试打印”首次异常，**不是崩溃**
                # （Chromium/QtWebEngine 会频繁打印）。原先对它也写 dump，结果
                # crashdumps 目录被每 2 秒一个的无效 dump 刷满（还有 0 字节的
                # 写失败残留），真正的崩溃现场反而被淹没。这里直接跳过。
                if code in (0x4001000A, 0x4001000B):
                    return 0
                t = __import__('time').time()
                if t - _last_dump_time[0] < 2.0:
                    return 0
                _last_dump_time[0] = t
                stamp = __import__('time').strftime('%Y%m%d_%H%M%S')
                dmp_path = os.path.join(_dump_dir, f'psls_py_{os.getpid()}_{stamp}.dmp')
                hfile = CreateFileW(dmp_path, GENERIC_WRITE, FILE_SHARE_READ, None,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None)
                written = 0
                if hfile != INVALID_HANDLE_VALUE:
                    # 传入正确的 PMINIDUMP_EXCEPTION_INFORMATION 使 dump 携带
                    # 异常记录/上下文（cdb .exr/.ecxr 可读）。若该结构传参失败
                    # （0x800703E6），回退传 None 保证至少写出线程栈。
                    mdei = _MINIDUMP_EXCEPTION_INFORMATION(
                        GetCurrentThreadId(),
                        pExceptionPointers,
                        True,
                    )
                    written = MiniDumpWriteDump(
                        _hProc, _dwPid, hfile,
                        _MINIDUMP_FLAGS,
                        ctypes.byref(mdei), None, None,
                    )
                    if not written:
                        written = MiniDumpWriteDump(
                            _hProc, _dwPid, hfile,
                            _MINIDUMP_FLAGS,
                            None, None, None,
                        )
                    CloseHandle(hfile)
                try:
                    with open(os.path.join(os.path.expanduser('~'), 'psls_crash.log'), 'a', encoding='utf-8') as lg:
                        lg.write(f"[{stamp}] [MINIDUMP] code=0x{code:08x} addr=0x{addr:016x} written={written} -> {dmp_path}\n")
                except Exception:
                    pass
            except Exception:
                pass
            # 返回 EXCEPTION_CONTINUE_SEARCH(0)：交回系统默认终止流程
            return 0

        SetUnhandledExceptionFilter = kernel32.SetUnhandledExceptionFilter
        SetUnhandledExceptionFilter.argtypes = [ctypes.c_void_p]
        SetUnhandledExceptionFilter.restype = wt.LPVOID

        # 64位下句柄是指针宽度，必须显式声明 restype/argtypes 防截断
        GetCurrentProcess = kernel32.GetCurrentProcess
        GetCurrentProcess.restype = wt.HANDLE
        GetCurrentProcess.argtypes = []
        GetCurrentProcessId = kernel32.GetCurrentProcessId
        GetCurrentProcessId.restype = wt.DWORD
        GetCurrentProcessId.argtypes = []
        GetCurrentThreadId = kernel32.GetCurrentThreadId
        GetCurrentThreadId.restype = wt.DWORD
        GetCurrentThreadId.argtypes = []
        _hProc = GetCurrentProcess()
        _dwPid = GetCurrentProcessId()

        # VEH: PVOID AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER)
        # First=1 插入链表头部，最先收到任何 SEH/VEH 异常回调。
        # 注意：该 API 导出在 kernel32.dll（ntdll 中不存在）!
        AddVectoredExceptionHandler = kernel32.AddVectoredExceptionHandler
        AddVectoredExceptionHandler.argtypes = [wt.ULONG, ctypes.c_void_p]
        AddVectoredExceptionHandler.restype = ctypes.c_void_p
        _veh_handle = AddVectoredExceptionHandler(1, ctypes.cast(_top_level_filter, ctypes.c_void_p))
        # 同时保留 filter 作为兜底（异常最终未处理时再写一次；正常处理过的
        # 异常不会走到这里）
        SetUnhandledExceptionFilter(ctypes.cast(_top_level_filter, ctypes.c_void_p))
        # 关键：ctypes 回调对象是 Python 对象，局部变量释放后被 GC 会导致
        # VEH/filter 指向悬空指针而静默失效。用模块级列表永久持有引用。
        _CRASH_FILTER_KEEPALIVE.append(_top_level_filter)
        try:
            with open(os.path.join(os.path.expanduser('~'), 'psls_crash.log'), 'a', encoding='utf-8') as lg:
                lg.write(f"[INIT] native minidump hook installed (VEH first, msvcrt module)\n")
        except Exception:
            pass
    except Exception:
        # 钩子安装失败也要记录，避免静默失效误判
        try:
            with open(os.path.join(os.path.expanduser('~'), 'psls_crash.log'), 'a', encoding='utf-8') as lg:
                lg.write(f"[INIT] native minidump hook FAILED: {__import__('traceback').format_exc()}\n")
        except Exception:
            pass

_install_native_minidump_hook()

# ===========================================================================
# QtWebEngine / Chromium 环境变量
# 必须在导入 PyQt5 之前设置，否则子进程 QtWebEngineProcess 无法继承
#
# 渲染策略（以崩溃分析证据为依据，2026-08-31 更新）：
#
# 崩溃证据（cdb 分析 ~/crashdumps/psls_py_*.dmp）：
#   QtWebEngineWidgets 通过 QtQuickWidgets(QQuickWidget) 走 Qt Quick 场景图
#   合成网页纹理，其 GL 上下文由 Qt 自身创建（opengl32 -> nvoglv64 显卡驱动）。
#   在 NVIDIA 驱动上该路径在 QOpenGLTextureUploader::textureImage -> glTexImage2D
#   -> nvoglv64 处硬崩溃（access violation），进程启动约 9 秒即亡 —— 这解释了
#   "主GUI出现后不到1分钟闪退"。Chromium 侧 --disable-gpu 无法阻止 Qt Quick
#   场景图自己的 GL 上下文走硬件驱动。
#
#   修复：QT_OPENGL=software 让 Qt 场景图使用随 PyQt5 分发的 opengl32sw.dll
#   （Mesa llvmpipe 软件渲染），完全绕过 nvoglv64。QtWebEngine 的纹理导入管线
#   仍是 GL API，仅驱动层换成软件实现，功能不受影响，只是渲染走 CPU。
#   历史注释曾担心"QT_OPENGL=software 与 Chromium 内部 Skia 渲染冲突"，
#   经多轮实测与 dump 证据确认该顾虑不成立，且硬件 GL 才是闪退根因。
#
#   1. QT_OPENGL=software : Qt Quick 场景图强制软件 GL（避开 nvoglv64 崩溃）
#   2. --disable-gpu       : 禁用 Chromium GPU 进程硬件加速（Skia software 兜底）
#   3. --no-sandbox        : Win7/精简环境沙箱可能失败，禁用
#   4. --disable-gpu-compositing : 配合 --disable-gpu
#
# 注意：
#   - 不设置 --in-process-gpu（GPU禁用时该标志会导致IPC死锁）
#   - 不设置 --disable-features=VizDisplayCompositor（会导致 Chromium 合成器初始化失败）
# ===========================================================================
os.environ['QT_OPENGL'] = 'software'
_chromium_flags = (
    '--disable-gpu '
    '--no-sandbox '
    '--disable-gpu-compositing '
    '--disable-gpu-shader-disk-cache '
    '--disable-gpu-program-cache '
    '--allow-file-access-from-files'
)
os.environ['QTWEBENGINE_CHROMIUM_FLAGS'] = _chromium_flags

# 在打包模式下，设置 QtWebEngine 资源路径
if getattr(sys, 'frozen', False):
    _meipass = sys._MEIPASS
    _resources_path = os.path.join(_meipass, 'PyQt5', 'Qt5', 'Resources')
    if os.path.isdir(_resources_path):
        os.environ['QTWEBENGINE_RESOURCES_PATH'] = _resources_path
    _locales_path = os.path.join(_meipass, 'PyQt5', 'Qt5', 'translations', 'qtwebengine_locales')
    if os.path.isdir(_locales_path):
        os.environ['QTWEBENGINE_LOCALES_PATH'] = _locales_path
    # 明确指定 QtWebEngineProcess.exe 路径，避免子进程搜索失败
    _process_exe = os.path.join(_meipass, 'PyQt5', 'Qt5', 'bin', 'QtWebEngineProcess.exe')
    if os.path.exists(_process_exe):
        os.environ['QTWEBENGINE_PROCESS_PATH'] = _process_exe
    # 确保 PyQt5\Qt5\bin 在 PATH 最前面（QtWebEngineProcess 依赖该目录下的 DLL）
    _qt_bin_dir = os.path.join(_meipass, 'PyQt5', 'Qt5', 'bin')
    if os.path.isdir(_qt_bin_dir):
        _current_path = os.environ.get('PATH', '')
        os.environ['PATH'] = _qt_bin_dir + os.pathsep + _current_path

# ===========================================================================
# 调试日志：启动早期信息写入临时文件
# ===========================================================================
def _debug_log(msg):
    try:
        debug_path = os.path.join(os.path.expanduser('~'), 'psls_debug.log')
        with open(debug_path, 'a', encoding='utf-8') as f:
            f.write(f"[{__import__('datetime').datetime.now()}] {msg}\n")
    except Exception:
        pass

_debug_log(f"=== PSLS启动 ===")
_debug_log(f"frozen={getattr(sys, 'frozen', False)}")
if getattr(sys, 'frozen', False):
    _debug_log(f"_MEIPASS={sys._MEIPASS}")
    _debug_log(f"sys.executable={sys.executable}")
    _debug_log(f"sys.path[0:5]={sys.path[:5]}")


# ===========================================================================
# ML Worker 子进程入口
# 打包模式下，ML Worker 通过 `PSLS.exe --ml-worker <model_path>` 启动。
# 必须在导入 PyQt5 之前检测该参数，否则 DLL 冲突会导致 onnxruntime 加载失败。
# ===========================================================================
if '--ml-worker' in sys.argv:
    _debug_log("ML Worker mode detected")
    if getattr(sys, 'frozen', False):
        application_path = sys._MEIPASS
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, application_path)
    from engine.ml_detector import run_worker_main
    run_worker_main()
    sys.exit(0)


# ===========================================================================
# 勒索回滚 Worker 子进程入口
# 打包模式下通过 `PSLS.exe --rollback-worker` 自重启动；开发模式为
# `python gui_entry.py --rollback-worker`。必须在本文件最早期识别，且只跑
# worker 主循环 —— 绝不初始化 Qt 窗口 / 托盘 / WebView（否则子进程会弹窗）。
# ===========================================================================
if '--rollback-worker' in sys.argv:
    try:
        _debug_log("Rollback Worker mode detected")
    except Exception:
        pass
    if getattr(sys, 'frozen', False):
        application_path = sys._MEIPASS
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, application_path)
    from engine.rollback_worker import run_worker_main as _run_rollback_worker
    _run_rollback_worker()
    sys.exit(0)


# ===========================================================================
# 系统依赖检测与静默安装（VC++ Redistributable + WebView2 Runtime）
# 全新 Windows 系统可能缺少这些依赖，导致 onnxruntime / QtWebEngine 无法加载
# ===========================================================================
def _is_vcredist_installed():
    """检测 VC++ Redistributable 2015-2022 x64 是否已安装"""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64'
        )
        installed = winreg.QueryValueEx(key, 'Installed')[0]
        winreg.CloseKey(key)
        return installed == 1
    except Exception:
        return False


def _is_webview2_installed():
    """检测 WebView2 Runtime 是否已安装"""
    try:
        import winreg
        # 机器级安装
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
            )
            pv = winreg.QueryValueEx(key, 'pv')[0]
            winreg.CloseKey(key)
            if pv and pv != '0.0.0.0':
                return True
        except Exception:
            pass
        # 用户级安装
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
            )
            pv = winreg.QueryValueEx(key, 'pv')[0]
            winreg.CloseKey(key)
            if pv and pv != '0.0.0.0':
                return True
        except Exception:
            pass
    except Exception:
        pass
    return False


def _run_installer_elevated(exe_path, args):
    """以管理员权限运行安装程序并等待完成

    使用 ShellExecuteExW + runas 提升权限，SEE_MASK_NOCLOSEPROCESS 等待完成。
    """
    import ctypes
    from ctypes import wintypes

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    SW_HIDE = 0
    INFINITE = 0xFFFFFFFF

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ('cbSize', wintypes.DWORD),
            ('fMask', wintypes.ULONG),
            ('hwnd', wintypes.HWND),
            ('lpVerb', wintypes.LPCWSTR),
            ('lpFile', wintypes.LPCWSTR),
            ('lpParameters', wintypes.LPCWSTR),
            ('lpDirectory', wintypes.LPCWSTR),
            ('nShow', wintypes.INT),
            ('hInstApp', wintypes.HINSTANCE),
            ('lpIDList', wintypes.LPVOID),
            ('lpClass', wintypes.LPCWSTR),
            ('hkeyClass', wintypes.HKEY),
            ('dwHotKey', wintypes.DWORD),
            ('hIcon', wintypes.HANDLE),
            ('hProcess', wintypes.HANDLE),
        ]

    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    info.fMask = SEE_MASK_NOCLOSEPROCESS
    info.hwnd = None
    info.lpVerb = 'runas'
    info.lpFile = exe_path
    info.lpParameters = args
    info.lpDirectory = None
    info.nShow = SW_HIDE

    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        _debug_log(f"  [SYSDEP] ShellExecuteExW failed for {exe_path}")
        return False

    if info.hProcess:
        ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, INFINITE)
        ctypes.windll.kernel32.CloseHandle(info.hProcess)
        _debug_log(f"  [SYSDEP] Installer completed: {exe_path}")
        return True
    return False


def _check_and_install_system_deps():
    """检测并静默安装缺失的系统依赖（VC++ Redist + WebView2）"""
    if not getattr(sys, 'frozen', False):
        return  # 开发模式跳过

    meipass = sys._MEIPASS
    deps_dir = os.path.join(meipass, 'redist')
    vc_redist_exe = os.path.join(deps_dir, 'vc_redist.x64.exe')
    webview2_exe = os.path.join(deps_dir, 'MicrosoftEdgeWebview2Setup.exe')

    need_vc = not _is_vcredist_installed()
    need_wv2 = not _is_webview2_installed()

    if not need_vc and not need_wv2:
        _debug_log("[SYSDEP] All system dependencies already installed")
        return

    _debug_log(f"[SYSDEP] Missing deps: VC++={need_vc}, WebView2={need_wv2}")

    # 提示用户即将安装依赖
    try:
        import ctypes
        missing = []
        if need_vc:
            missing.append('Visual C++ 运行库')
        if need_wv2:
            missing.append('WebView2 Runtime')
        msg = 'PSLS 首次运行需要安装以下系统依赖：\n\n' + '\n'.join(f'  • {m}' for m in missing) + '\n\n即将开始静默安装，请在 UAC 提示中点击"是"。'
        ctypes.windll.user32.MessageBoxW(0, msg, 'PSLS - 安装系统依赖', 0x40)
    except Exception:
        pass

    # 安装 VC++ Redistributable（需要管理员权限）
    if need_vc and os.path.exists(vc_redist_exe):
        _debug_log(f"[SYSDEP] Installing VC++ Redist from {vc_redist_exe}")
        try:
            import subprocess
            result = subprocess.run(
                [vc_redist_exe, '/install', '/quiet', '/norestart'],
                capture_output=True, timeout=300,
                creationflags=0x08000000  # CREATE_NO_WINDOW
            )
            code = result.returncode
            _debug_log(f"[SYSDEP] VC++ Redist install returncode={code}")
            # 1638=已安装更新版本, 3010=需要重启, 0=成功
            if code not in (0, 1638, 3010):
                # 可能是权限不足，尝试提升权限
                _debug_log("[SYSDEP] Retrying VC++ Redist with elevation...")
                _run_installer_elevated(vc_redist_exe, '/install /quiet /norestart')
        except Exception as e:
            _debug_log(f"[SYSDEP] VC++ Redist install failed: {e}")
            _run_installer_elevated(vc_redist_exe, '/install /quiet /norestart')
    elif need_vc:
        _debug_log(f"[SYSDEP] VC++ Redist installer not found at {vc_redist_exe}")

    # 安装 WebView2 Runtime（可用户级安装，无需管理员权限）
    if need_wv2 and os.path.exists(webview2_exe):
        _debug_log(f"[SYSDEP] Installing WebView2 from {webview2_exe}")
        try:
            import subprocess
            result = subprocess.run(
                [webview2_exe, '/silent'],
                capture_output=True, timeout=300,
                creationflags=0x08000000  # CREATE_NO_WINDOW
            )
            _debug_log(f"[SYSDEP] WebView2 install returncode={result.returncode}")
        except Exception as e:
            _debug_log(f"[SYSDEP] WebView2 install failed: {e}")
            _run_installer_elevated(webview2_exe, '/silent')
    elif need_wv2:
        _debug_log(f"[SYSDEP] WebView2 installer not found at {webview2_exe}")

    _debug_log("[SYSDEP] System dependency installation completed")


# 执行系统依赖检测与安装（仅打包模式）
_check_and_install_system_deps()


# ===========================================================================
# 全局 DLL 目录句柄（防止 GC 回收）
# ===========================================================================
_dll_dir_handles = []
_onnx_loaded = False
_ctypes_loaded_handles = []


def _setup_dll_directories():
    """在打包模式下设置 DLL 搜索路径
    
    收集所有可能包含 onnxruntime DLL 的目录，
    依次添加到 Windows DLL 搜索路径中。
    """
    if not getattr(sys, 'frozen', False):
        return
    
    meipass = sys._MEIPASS
    _debug_log(f"[DLL-SETUP] _MEIPASS={meipass}")
    
    dll_dirs = []
    
    # 1. onnxruntime/capi 目录
    capi_dir = os.path.join(meipass, 'onnxruntime', 'capi')
    if os.path.isdir(capi_dir):
        dll_dirs.append(capi_dir)
        _debug_log(f"[DLL-SETUP] capi_dir: {capi_dir}")
    
    # 2. _MEIPASS 根目录
    dll_dirs.append(meipass)
    _debug_log(f"[DLL-SETUP] meipass (root): {meipass}")
    
    # 3. onnxruntime 包根目录
    ort_root = os.path.join(meipass, 'onnxruntime')
    if os.path.isdir(ort_root):
        dll_dirs.append(ort_root)
        _debug_log(f"[DLL-SETUP] ort_root: {ort_root}")
    
    # 4. EXE 所在目录 (onedir 模式下 EXE 在 _MEIPASS 上级目录)
    try:
        exe_dir = os.path.dirname(sys.executable)
        if exe_dir != meipass:
            dll_dirs.append(exe_dir)
            _debug_log(f"[DLL-SETUP] exe_dir: {exe_dir}")
    except Exception:
        pass
    
    # 5. onnxruntime 安装路径（回退）—— 已移除
    #    注意：本函数只在 frozen 模式下被调用，而 frozen 模式主进程【不应】
    #    进程内 import onnxruntime（ML 推理由 MLWorker 子进程承载；旧逻辑曾
    #    在中文路径下被 LoadLibrary 硬崩溃）。此处的 `import onnxruntime`
    #    会加载 ~31MB 的 onnxruntime_pybind11_state.pyd 并初始化，冷启动实测
    #    阻塞主线程 4~5 秒（Defender 实时扫描 pyd 时更甚），正落在窗口未显示
    #    的阶段 → “初始化未响应”。DLL 搜索路径已由上方 _MEIPASS/onnxruntime/capi
    #    + PATH 提供，无需再 import 探测安装路径。
    
    # 添加所有目录到 DLL 搜索路径
    for d in dll_dirs:
        try:
            handle = os.add_dll_directory(d)
            _dll_dir_handles.append(handle)
        except (OSError, AttributeError) as e:
            _debug_log(f"[DLL-SETUP] add_dll_directory({d}) failed: {e}")
    
    # 更新 PATH 环境变量
    existing_path = os.environ.get('PATH', '')
    new_path = os.pathsep.join(dll_dirs)
    os.environ['PATH'] = new_path + os.pathsep + existing_path
    _debug_log(f"[DLL-SETUP] PATH updated, {len(dll_dirs)} directories added")
    
    # 验证 DLL 文件存在性
    for dll_name in ['onnxruntime.dll', 'onnxruntime_providers_shared.dll',
                     'onnxruntime_pybind11_state.pyd']:
        found = False
        for d in dll_dirs:
            dll_path = os.path.join(d, dll_name)
            if os.path.exists(dll_path):
                size = os.path.getsize(dll_path)
                _debug_log(f"[DLL-SETUP] Found {dll_name} in {d} ({size:,} bytes)")
                found = True
                break
        if not found:
            _debug_log(f"[DLL-SETUP] WARNING: {dll_name} NOT found in any DLL directory!")


def _preload_onnxruntime():
    """先加载 PyQt5，再加载 onnxruntime

    关键洞察：PyQt5 的 DLL（libcrypto, libssl 等）在 onnxruntime 之前加载，
    可以避免 DLL 初始化冲突。在打包模式下，onnxruntime 的 DllMain
    依赖 MSVC 运行时和其他系统 DLL，如果这些 DLL 先被 PyQt5 加载，
    onnxruntime 的初始化就能正常完成。

    重要：打包模式（frozen）下主进程不再直接 import onnxruntime。
    onnxruntime 的 onnxruntime_pybind11_state.pyd 在 DLL 加载时可能触发
    C 层硬崩溃（access violation），这种崩溃无法被 try/except Exception 捕获。
    当 PSLS 安装在含中文等非 ASCII 字符的路径下时，LoadLibrary 因路径编码
    问题会触发该崩溃，导致整个程序启动即崩溃。ML 推理由独立的 MLWorker.exe
    子进程负责，主进程无需进程内加载 onnxruntime。
    """
    global _onnx_loaded
    _debug_log("_preload_onnxruntime() started")
    
    if getattr(sys, 'frozen', False):
        _setup_dll_directories()
        # 打包模式：跳过进程内 onnxruntime 导入，避免中文路径下 DLL 硬崩溃
        _debug_log("  frozen mode: skip in-process onnxruntime import (use MLWorker subprocess)")
        _onnx_loaded = False
        return
    
    # 开发模式：同样跳过进程内 onnxruntime 导入（原因同打包模式）
    # PyQt5 加载后，onnxruntime 的 onnxruntime_pybind11_state.pyd 在 DLL
    # 加载时可能触发 C 层硬崩溃（access violation），无法被 try/except 捕获，
    # 导致程序启动即崩溃（闪退）。开发模式 ML 推理同样走 MLWorker 子进程。
    _debug_log("  dev mode: skip in-process onnxruntime import (use MLWorker subprocess)")
    _onnx_loaded = False
    return


def _preload_onnxruntime_dll():
    """预加载 onnxruntime 核心 DLL（从 _MEIPASS 根目录）
    
    PyInstaller 的 ctypes hook 会验证 DLL 路径是否在其清单中。
    我们通过 _ort_root_bins 将 DLL 添加到根目录，所以必须从根目录加载。
    """
    import ctypes
    
    meipass = sys._MEIPASS
    loaded = []
    
    # 按依赖顺序加载：先 MSVC 运行时，再 onnxruntime
    # 从 _MEIPASS 根目录加载（PyInstaller 清单中的路径）
    dll_names = [
        'vcruntime140.dll',
        'vcruntime140_1.dll',
        'ucrtbase.dll',
        'msvcp140.dll',
        'onnxruntime_providers_shared.dll',
        'onnxruntime.dll',
    ]
    
    for dll_name in dll_names:
        dll_path = os.path.join(meipass, dll_name)
        if not os.path.exists(dll_path):
            _debug_log(f"  [PRELOAD] SKIP (not found in root): {dll_name}")
            continue
        
        handle = None
        
        # 方法1: ctypes.CDLL (PyInstaller 可能拦截)
        try:
            handle = ctypes.CDLL(dll_path, mode=ctypes.RTLD_GLOBAL)
            if handle:
                loaded.append(handle)
                _debug_log(f"  [PRELOAD] OK (CDLL): {dll_name}")
                continue
        except Exception as e:
            # 获取原始错误
            cause = e.__cause__ if hasattr(e, '__cause__') else None
            _debug_log(f"  [PRELOAD] FAIL (CDLL): {dll_name} -> {type(e).__name__}: {e}")
            if cause:
                _debug_log(f"    Cause: {type(cause).__name__}: {cause}")
                # 尝试获取 Windows 错误码
                import errno
                if hasattr(cause, 'winerror'):
                    _debug_log(f"    WinError: {cause.winerror}")
                if hasattr(cause, 'errno'):
                    _debug_log(f"    Errno: {cause.errno}")
        
        # 方法2: ctypes.WinDLL
        try:
            handle = ctypes.WinDLL(dll_path, mode=ctypes.RTLD_GLOBAL)
            if handle:
                loaded.append(handle)
                _debug_log(f"  [PRELOAD] OK (WinDLL): {dll_name}")
                continue
        except Exception as e:
            _debug_log(f"  [PRELOAD] FAIL (WinDLL): {dll_name} -> {type(e).__name__}: {e}")
        
        # 方法3: LoadLibraryW via windll
        try:
            _kernel32 = ctypes.windll.kernel32
            _kernel32.LoadLibraryW.restype = ctypes.c_void_p
            _kernel32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
            h = _kernel32.LoadLibraryW(dll_path)
            if h:
                loaded.append(h)
                _debug_log(f"  [PRELOAD] OK (LoadLibraryW): {dll_name}")
                continue
            else:
                err = ctypes.get_last_error()
                _debug_log(f"  [PRELOAD] FAIL (LoadLibraryW): {dll_name} (error={err})")
        except Exception as e:
            _debug_log(f"  [PRELOAD] FAIL (LoadLibraryW): {dll_name} -> {type(e).__name__}: {e}")
    
    _debug_log(f"  [PRELOAD] Total preloaded: {len(loaded)} DLLs")
    
    global _ctypes_loaded_handles
    _ctypes_loaded_handles.extend(loaded)


def _ctypes_preload_all_dlls():
    """预加载 MSVC 运行时 DLL
    
    仅预加载 onnxruntime 所需的 MSVC 运行时依赖 DLL，
    不预加载 onnxruntime 自身的 DLL——让 Python import 机制正常加载。
    
    预加载 onnxruntime_providers_shared.dll 或 onnxruntime.dll 反而会破坏
    后续的 Python import，因为：
    - onnxruntime_providers_shared.dll 是转发器，加载时会触发 onnxruntime.dll 的依赖解析
    - 如果 onnxruntime.dll 的 DllMain 失败，会导致模块处于损坏状态
    - 后续 Python import 会因模块状态异常而失败
    """
    import ctypes
    
    meipass = sys._MEIPASS
    loaded_dlls = []
    
    _kernel32 = ctypes.windll.kernel32
    _kernel32.LoadLibraryW.restype = ctypes.c_void_p
    _kernel32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
    
    # 只预加载 MSVC 运行时 DLL（onnxruntime 的依赖）
    runtime_dlls = [
        'vcruntime140.dll',
        'vcruntime140_1.dll',
        'ucrtbase.dll',
        'msvcp140.dll',
    ]
    
    for dll_name in runtime_dlls:
        dll_path = os.path.join(meipass, dll_name)
        if not os.path.exists(dll_path):
            _debug_log(f"  [LoadLibrary] SKIP (not found): {dll_path}")
            continue
        try:
            handle = _kernel32.LoadLibraryW(dll_path)
            if handle:
                loaded_dlls.append(handle)
                _debug_log(f"  [LoadLibrary] OK: {dll_name} ({os.path.getsize(dll_path):,} bytes)")
            else:
                err = ctypes.get_last_error()
                _debug_log(f"  [LoadLibrary] FAIL (NULL): {dll_name} (error={err})")
        except Exception as e:
            _debug_log(f"  [LoadLibrary] FAIL: {dll_name} -> {type(e).__name__}: {e}")
    
    _debug_log(f"  [LoadLibrary] Preloaded {len(loaded_dlls)} runtime DLLs total")
    
    global _ctypes_loaded_handles
    _ctypes_loaded_handles.extend(loaded_dlls)


_preload_onnxruntime()


def _show_error_and_exit(title: str, message: str):
    """显示错误对话框并退出"""
    try:
        from PyQt5.QtWidgets import QApplication, QMessageBox
        app = QApplication.instance() or QApplication(sys.argv)
        QMessageBox.critical(None, title, message)
    except Exception:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)
        except Exception:
            print(f"[{title}] {message}", file=sys.stderr)
    sys.exit(1)


def _is_running_elevated() -> bool:
    """检测当前进程是否以管理员权限运行 (TokenElevation)。"""
    try:
        import ctypes
        import ctypes.wintypes as wt

        class _TOKEN_ELEVATION(ctypes.Structure):
            _fields_ = [('TokenIsElevated', wt.DWORD)]

        TOKEN_QUERY = 0x0008
        TokenElevation = 20
        token = wt.HANDLE()
        if not ctypes.windll.advapi32.OpenProcessToken(
                ctypes.windll.kernel32.GetCurrentProcess(),
                TOKEN_QUERY, ctypes.byref(token)):
            return False
        try:
            elev = _TOKEN_ELEVATION()
            size = wt.DWORD()
            ok = ctypes.windll.advapi32.GetTokenInformation(
                token, TokenElevation, ctypes.byref(elev),
                ctypes.sizeof(elev), ctypes.byref(size))
            return bool(ok and elev.TokenIsElevated)
        finally:
            ctypes.windll.kernel32.CloseHandle(token)
    except Exception:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


def main():
    _debug_log("main() started")

    # ---- 管理员权限检测（仅告警，不自动提权）----
    # MBR/引导扇区读取、内核驱动加载等核心防护需要管理员权限。
    # 打包版 (PSLS.exe) 的 manifest (uac_admin=True) 由 Windows 保证
    # 启动即管理员；开发模式 (python gui_entry.py) 这里仅检测并记录，
    # 不自动 UAC 重启——自动提权曾导致无限闪窗/进程堆积无法终止。
    # 非管理员时由 MBRProtector 的降级告警提示用户。
    if not _is_running_elevated():
        _debug_log("非管理员运行：驱动加载/MBR扇区保护将降级，"
                   "请以管理员身份运行（右键→以管理员身份运行）")

    if getattr(sys, 'frozen', False):
        application_path = sys._MEIPASS
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))

    sys.path.insert(0, application_path)
    _debug_log(f"application_path={application_path}")
    _debug_log(f"sys.path[0:5]={sys.path[:5]}")

    # ---- 开机自启最高优先级 ----
    # 以开机自启方式（--minimized）启动时，将进程优先级提升为 HIGH，
    # 保证防护线程（MBR/进程/注册表轮询）优先调度，不被其他自启程序抢占。
    try:
        from utils.autostart_manager import apply_high_priority_class, is_minimized_startup
        if is_minimized_startup():
            apply_high_priority_class()
            _debug_log("autostart mode: process priority set to HIGH")
    except Exception as e:
        _debug_log(f"apply_high_priority_class failed: {e}")

    _debug_log("Importing ui.webview.main_window...")
    try:
        from ui.webview.main_window import main as webview_main
        _debug_log("ui.webview.main_window imported successfully")
    except ImportError as e:
        _debug_log(f"ImportError: {e}")
        _show_error_and_exit(
            "PSLS 启动失败",
            f"无法加载核心模块：{e}\n\n"
            f"请确保已安装依赖：\n"
            f"  pip install PyQt5 PyQtWebEngine\n\n"
            f"或运行 启动(调试模式).bat 查看详细错误。"
        )
        return

    _debug_log("Calling webview_main()...")
    try:
        webview_main()
        _debug_log("webview_main() returned")
    except Exception as e:
        _debug_log(f"Exception in webview_main(): {e}")
        _debug_log(traceback.format_exc())
        _show_error_and_exit(
            "PSLS 运行错误",
            f"程序运行时发生错误：\n{e}\n\n"
            f"详细信息：\n{traceback.format_exc()}"
        )


if __name__ == '__main__':
    multiprocessing.freeze_support()
    main()