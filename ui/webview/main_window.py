#!/usr/bin/env python3
"""
Webview 主窗口 - 使用 PyQt5 + QWebEngineView + QWebChannel
基于设计稿的现代化UI
"""

import os
import sys
import time
import threading
import traceback
from typing import Optional

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget,
    QSystemTrayIcon, QMenu, QAction
)
from PyQt5.QtCore import Qt, QUrl, QTimer
from PyQt5.QtGui import QIcon
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtWebChannel import QWebChannel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ui.webview.bridge import PyBridge
from ui.webview import theme_tokens
from utils.logger import get_logger
from utils.autostart_manager import is_minimized_startup

logger = get_logger('webview_main')

# 两套内置主题各自的入口 HTML（结构不同，切换时整页替换）
_ENTRY_FILES = {
    theme_tokens.THEME_LIGHT: 'index.html',
    theme_tokens.THEME_TERMINAL: 'terminal.html',
}


def _debug_log(msg):
    """与 gui_entry.py 相同的调试日志函数，写入 ~/psls_debug.log"""
    try:
        debug_path = os.path.join(os.path.expanduser('~'), 'psls_debug.log')
        with open(debug_path, 'a', encoding='utf-8') as f:
            f.write(f"[{__import__('datetime').datetime.now()}] [MW] {msg}\n")
    except Exception:
        pass


def get_resource_path(relative_path: str) -> str:
    """获取资源文件路径，支持开发模式和打包模式"""
    try:
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return os.path.join(base_path, relative_path)
    except Exception:
        return relative_path


class WebViewMainWindow(QMainWindow):
    """Webview 主窗口"""

    _MIN_SPLASH_MS = 2000  # Splash 最短展示时长，避免一闪而过
    _FORCE_REVEAL_MS = 12000  # 兜底：12 秒后无论什么条件都揭示主窗口（防止 Splash 永远不关闭）

    def __init__(self):
        _debug_log("WebViewMainWindow.__init__ start")
        super().__init__()
        self._bridge: Optional[PyBridge] = None
        self._web_view: Optional[QWebEngineView] = None
        self._tray_icon: Optional[QSystemTrayIcon] = None
        self._force_quit: bool = False
        self._splash: Optional[object] = None  # SplashWindow，主 GUI 就绪后关闭
        self._main_loaded: bool = False  # 主 index.html 是否已加载完成
        self._web_init_failed: bool = False  # WebEngine/主界面初始化是否失败（失败时绝不渲染主 GUI）
        self._render_crash_pending: bool = False  # 渲染进程崩溃待恢复标记（托盘恢复时检测）
        self._launch_ready: bool = False  # PyBridge.launchReady 是否已触发（真实启动终态）
        self._start_minimized: bool = False  # 开机自启静默启动
        self._reveal_pending: bool = False  # 是否已进入"待显示"状态（等待授权条件）
        self._app_start_time: float = time.time()  # 启动时刻，用于保证 Splash 最短展示
        self._reveal_timer: Optional[QTimer] = None  # 轮询授权条件并揭示主窗口的定时器
        # 当前内置主题与入口 HTML（启动时按持久化设置决定；切主题时整页替换）
        self._current_theme: str = theme_tokens.load_theme()
        self._entry_file: str = _ENTRY_FILES.get(self._current_theme, 'index.html')
        _debug_log("WebViewMainWindow.__init__ calling _init_ui")
        self._init_ui()
        _debug_log("WebViewMainWindow.__init__ calling _setup_tray")
        self._setup_tray()
        _debug_log("WebViewMainWindow.__init__ done")

    def set_splash(self, splash):
        """设置启动界面窗口引用（主 GUI 就绪后自动关闭）"""
        self._splash = splash

    def _init_ui(self):
        """初始化UI（仅创建空窗口框架，QWebEngineView 延迟到事件循环后创建）

        QWebEngineView 在首次 show() 时会触发 Chromium 渲染管线初始化，
        在无 GPU 的虚拟机上可能导致硬崩溃。因此采用延迟创建策略：
        _init_ui 只创建空框架，_deferred_webengine_init 在事件循环运行后
        才创建 QWebEngineView、设置 WebChannel、加载 HTML。
        """
        _debug_log("_init_ui: set window properties")
        self.setWindowTitle('Project Sertraline Lab Offline Security')
        self.setMinimumSize(480, 360)
        self.resize(1100, 720)

        try:
            icon_path = get_resource_path('logo_small.png')
            _debug_log(f"_init_ui: icon_path={icon_path} exists={os.path.exists(icon_path)}")
            if os.path.exists(icon_path):
                self.setWindowIcon(QIcon(icon_path))
        except Exception as e:
            _debug_log(f"_init_ui: icon load failed: {e}")
            logger.warning(f'加载窗口图标失败: {e}')

        _debug_log("_init_ui: create central widget")
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        self._layout = QVBoxLayout(central_widget)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        # 主 GUI 的 QWebEngineView 由 _begin_loaded_main() 在事件循环运行后
        # 才创建（避免 window.show() 时触发 Chromium 渲染管线初始化导致虚拟机硬崩溃）。
        # 在真正就绪前，由外层 SplashWindow 展示启动界面，此处不创建任何占位控件。
        _debug_log("_init_ui done (webview init deferred to _begin_loaded_main)")

    def _begin_loaded_main(self):
        """延迟执行的 WebEngine 初始化（事件循环运行后由 main() 调用）

        此时 app.exec_() 已运行，QtWebEngineProcess 能正常建立 IPC。
        创建主 GUI 的 QWebEngineView 并加载 index.html；index 真正加载完成
        （loadFinished ok=True）后，由 _on_load_finished 关闭 Splash 并显示主窗口。
        """
        _debug_log("_begin_loaded_main: start")
        try:
            _debug_log("_begin_loaded_main: creating QWebEngineView")
            self._web_view = QWebEngineView(self)
            self._web_view.loadStarted.connect(self._on_load_started)
            self._web_view.loadProgress.connect(self._on_load_progress)
            self._web_view.loadFinished.connect(self._on_load_finished)
            self._web_view.renderProcessTerminated.connect(self._on_render_process_terminated)
            _debug_log("_begin_loaded_main: QWebEngineView signals connected")

            self._layout.addWidget(self._web_view)
            _debug_log("_begin_loaded_main: QWebEngineView added to layout")

            _debug_log("_begin_loaded_main: calling _setup_webchannel")
            self._setup_webchannel()
            _debug_log("_begin_loaded_main: calling _load_html")
            self._load_html()
            _debug_log("_begin_loaded_main: done")
        except Exception as e:
            self._web_init_failed = True
            _debug_log(f"_begin_loaded_main: EXCEPTION: {e}\n{traceback.format_exc()}")
            logger.error(f"WebEngine 初始化失败: {e}")

    def _on_load_started(self):
        _debug_log("SIGNAL loadStarted")

    def _on_load_progress(self, p):
        if p in (0, 25, 50, 75, 100):
            _debug_log(f"SIGNAL loadProgress={p}")

    def _on_load_finished(self, ok):
        _debug_log(f"SIGNAL loadFinished ok={ok}")

        if ok:
            self._main_loaded = True
            self._render_term_count = 0
            # 主页面加载成功：清除崩溃待恢复标记（避免托盘恢复时误重载）
            try:
                self._render_crash_pending = False
            except Exception:
                pass
            # 不直接揭示：进入"待显示"状态，由 _maybe_reveal_main 依据
            # 初始化完成 + Splash 最短展示时长等条件决定何时关闭 Splash 并显示主窗口，
            # 确保主 GUI 在全部初始化完成前不被渲染。
            self._maybe_reveal_main()
        else:
            # 页面加载失败：标记为不可渲染——兜底揭示逻辑会跳过，
            # 主 GUI 不会被"未就绪"地显示出来（宁可停在 Splash 提示，也绝不半成品上屏）
            self._web_init_failed = True

    def _on_launch_progress_updated(self, pct, stage_text):
        """PyBridge 真实启动阶段变化 → 同步到 Splash。"""
        try:
            if self._splash is not None and hasattr(self._splash, 'update_progress'):
                try:
                    self._splash.update_progress(int(pct), str(stage_text))
                except Exception as e:
                    _debug_log(f"_on_launch_progress_updated: splash.update_progress FAILED: {e}")
        except Exception as e:
            _debug_log(f"_on_launch_progress_updated FAILED: {e}")

    def _on_launch_ready(self):
        """PyBridge.launchReady 触发 → 标记启动完成，尝试揭示主窗口。"""
        _debug_log("_on_launch_ready fired: marking _launch_ready=True")
        self._launch_ready = True
        try:
            if self._splash is not None and hasattr(self._splash, 'set_ready_for_close'):
                try:
                    self._splash.set_ready_for_close(True)
                except Exception as e:
                    _debug_log(f"_on_launch_ready: splash.set_ready_for_close FAILED: {e}")
        except Exception as e:
            _debug_log(f"_on_launch_ready: splash FAILED: {e}")
        self._maybe_reveal_main()

    def _launch_all_ready(self) -> bool:
        """全部启动就绪条件（launchReady 或超时兜底 True）。"""
        if self._launch_ready:
            return True
        # 超时兜底（超过 FORCE_REVEAL_MS 就认为 ready，避免 Splash 永远显示）
        try:
            elapsed_ms = (time.time() - self._app_start_time) * 1000
            if elapsed_ms >= self._FORCE_REVEAL_MS:
                _debug_log("_launch_all_ready: 触发 FORCE_REVEAL_MS 兜底")
                return True
        except Exception:
            pass
        return False

    def on_bridge_init_ready(self):
        """由 PyBridge 在全部初始化完成后回调：重新评估是否可显示主窗口"""
        _debug_log("on_bridge_init_ready called")
        self._maybe_reveal_main()

    def _bridge_ui_ready(self) -> bool:
        """桥接层初始化是否全部就绪"""
        if self._bridge is None:
            return False
        return bool(getattr(self._bridge, '_ui_ready', False))

    def _show_main_window(self):
        """显示并激活主窗口"""
        try:
            self.show()
            self.raise_()
            self.activateWindow()
        except Exception as e:
            _debug_log(f"_show_main_window failed: {e}")

    def _maybe_reveal_main(self, force: bool = False):
        """尝试揭示主窗口。

        满足以下条件才关闭 Splash 并显示主窗口：
          - 非静默启动（静默自启仅后台加载，不主动显示）
          - index.html 已加载完成（_main_loaded）
          - 若存在 Splash：
              * 桥接层初始化完成（_ui_ready）
              * PyBridge.launchReady 已触发（或超时兜底）
              * Splash.set_ready_for_close() 返回 True
              * Splash 已展示最短时长
        force=True 为超时兜底，强制显示。
        """
        if self._start_minimized:
            # 静默启动：只在后台加载，托盘点击时显示已就绪窗口
            return

        if force:
            self._reveal_pending = False
            if self._splash is not None:
                try:
                    self._splash.close_splash()
                except Exception as e:
                    _debug_log(f"close splash failed: {e}")
                self._splash = None
                _debug_log("force reveal: splash closed")
            if not self.isVisible():
                self._show_main_window()
            return

        elapsed_ms = (time.time() - self._app_start_time) * 1000
        if self._splash is not None:
            # Splash 模式：需主界面已加载 + 桥就绪 + launchReady + splash ready + 最短展示时长
            splash_ready = (not hasattr(self._splash, 'is_ready_for_close')
                            or bool(self._splash.is_ready_for_close()))
            ready = (self._main_loaded and self._bridge_ui_ready()
                     and self._launch_all_ready()
                     and splash_ready
                     and elapsed_ms >= self._MIN_SPLASH_MS)
        else:
            # 无 Splash（创建失败等路径）：主界面加载完成 + 桥基本就绪即可显示
            ready = (self._main_loaded
                     and (self._launch_all_ready() or elapsed_ms >= self._FORCE_REVEAL_MS))

        if not ready:
            self._reveal_pending = True
            return

        self._reveal_pending = False
        if self._splash is not None:
            try:
                self._splash.close_splash()
            except Exception as e:
                _debug_log(f"close splash failed: {e}")
            self._splash = None
            _debug_log("_maybe_reveal_main: splash closed, showing main window")
        if not self.isVisible():
            self._show_main_window()
        else:
            _debug_log("_maybe_reveal_main: main window already visible")

    def _on_render_process_terminated(self, termStatus, exitCode):
        """渲染进程终止时自动重载页面

        termStatus=0 正常退出 / termStatus=1 异常终止 / termStatus=2 崩溃/OOM / termStatus=3 被 kill
        exitCode=-2147483645 (0x80000003) = STATUS_BREAKPOINT (Chrome CHECK 失败 / OOM / DOM 爆炸)
        exitCode=-2147483645 (0xC0000005) = 访问冲突 / 内存错误

        根因通常是向 QWebEngine 渲染进程推送了过多数据（如 2万+ clean 文件 DOM 节点），
        导致 Chromium 内存耗尽崩溃。主路径修复在 bridge.py 中过滤 clean 结果，
        此处作为兜底：延迟 2 秒后自动 reload 页面，避免用户看到空白界面。
        """
        _debug_log(f"renderProcessTerminated status={termStatus} exitCode={exitCode}")

        # 记录崩溃待恢复标记：供托盘恢复时 _maybe_recover_blank_webview 检测，
        # 避免渲染进程已在后台崩溃但尚未触发兜底 reload 而持续白屏。
        try:
            self._render_crash_pending = True
        except Exception:
            pass

        if not hasattr(self, '_render_term_count'):
            self._render_term_count = 0
        self._render_term_count += 1

        if self._render_term_count >= 2:
            # 连续 2 次终止 → 判定为真崩溃，延迟 reload
            logger.warning(
                f'GUI 渲染进程连续 {self._render_term_count} 次终止 '
                f'(status={termStatus}, exitCode={exitCode})，2秒后自动重载'
            )
            self._render_term_count = 0
            try:
                from PyQt5.QtCore import QTimer
                QTimer.singleShot(2000, self._do_reload_webview)
            except Exception as e:
                logger.error(f'自动重载渲染进程失败: {e}')
        else:
            logger.warning(
                f'GUI 渲染进程终止 (第 {self._render_term_count}/2 次, '
                f'status={termStatus}, exitCode={exitCode})，等待自行恢复'
            )

    def _do_reload_webview(self):
        """延迟回调：重新加载 WebView 页面，重建渲染进程"""
        try:
            if hasattr(self, '_web_view') and self._web_view is not None:
                self._web_view.reload()
                _debug_log("_do_reload_webview: reload() 已调用")
                # 重连 QWebChannel（reload 后需要）
                try:
                    self._setup_webchannel()
                except Exception as e:
                    logger.warning(f'reload 后重建 QWebChannel 失败: {e}')
            else:
                _debug_log("_do_reload_webview: _web_view 不存在，跳过 reload")
        except Exception as e:
            logger.error(f'_do_reload_webview 异常: {e}')

    def _get_app_icon(self) -> QIcon:
        """获取应用图标"""
        # 优先使用 logo_small.png，其次使用 webview/assets 下的图片
        for rel_path in ['logo_small.png',
                         os.path.join('ui', 'webview', 'assets', 'image_0_7mlicq.png')]:
            icon_path = get_resource_path(rel_path)
            if os.path.exists(icon_path):
                return QIcon(icon_path)
        return QIcon()

    def _setup_tray(self):
        """初始化系统托盘图标与右键菜单"""
        _debug_log("_setup_tray start")
        try:
            # 部分虚拟机/终端服务器可能不支持系统托盘，失败不影响主窗口
            if not QSystemTrayIcon.isSystemTrayAvailable():
                _debug_log("_setup_tray: system tray NOT available, skip")
                self._tray_icon = None
                return
            icon = self._get_app_icon()
            _debug_log(f"_setup_tray: icon isNull={icon.isNull()}")
            self._tray_icon = QSystemTrayIcon(icon, self)
            self._tray_icon.setToolTip('PSLS - 安全中心\n单击显示主窗口，右键查看菜单')

            # 右键菜单
            menu = QMenu()
            show_action = QAction('显示主窗口', self)
            show_action.triggered.connect(self._show_from_tray)
            menu.addAction(show_action)

            menu.addSeparator()

            # 一键开/关保护（文案随当前状态变化，点击后走系统通知）
            self._protect_toggle_action = QAction('', self)
            self._refresh_protect_toggle_text()
            self._protect_toggle_action.triggered.connect(self._toggle_protection_from_tray)
            menu.addAction(self._protect_toggle_action)

            menu.addSeparator()

            quit_action = QAction('退出', self)
            quit_action.triggered.connect(self._quit_from_tray)
            menu.addAction(quit_action)

            self._tray_icon.setContextMenu(menu)
            # 单击托盘图标显示主窗口
            self._tray_icon.activated.connect(self._on_tray_activated)
            self._tray_icon.show()
            _debug_log("_setup_tray done")
        except Exception as e:
            _debug_log(f"_setup_tray FAILED: {e}\n{traceback.format_exc()}")
            logger.error(f'初始化系统托盘失败: {e}')
            self._tray_icon = None  # 置空避免后续引用

    def _refresh_protect_toggle_text(self):
        """根据当前防护状态刷新托盘菜单"一键开/关保护"的文案。"""
        try:
            act = getattr(self, '_protect_toggle_action', None)
            if act is None:
                return
            running = False
            if self._bridge and hasattr(self._bridge, 'isAllProtectionEnabled'):
                running = bool(self._bridge.isAllProtectionEnabled())
            act.setText('一键关闭保护' if running else '一键开启保护')
        except Exception as e:
            logger.debug(f'刷新托盘保护切换文案失败: {e}')

    def _toggle_protection_from_tray(self):
        """托盘一键开/关保护：立即显示"切换中"，真实结果由信号回调通知。"""
        try:
            if self._bridge is None or not hasattr(self._bridge, 'setAllProtectionEnabled'):
                return
            was_running = bool(self._bridge.isAllProtectionEnabled()) \
                if hasattr(self._bridge, 'isAllProtectionEnabled') else False
            target = not was_running
            # 先把菜单文案切到目标态（即时反馈），真实完成后由信号回调再校正
            act = getattr(self, '_protect_toggle_action', None)
            if act:
                act.setText('切换中...')
            self._bridge.setAllProtectionEnabled(target)
            if self._tray_icon:
                self._tray_icon.showMessage(
                    'PSLS',
                    '正在%s全部防护模块...' % ('启用' if target else '停用'),
                    QSystemTrayIcon.Information, 1500)
        except Exception as e:
            logger.error(f'托盘一键切换保护失败: {e}')

    def _on_protection_all_toggled(self, enabled: bool, success: bool, detail: str):
        """一键开/关保护完成回调：用真实结果刷新托盘文案 + 发系统通知。"""
        try:
            self._refresh_protect_toggle_text()
            if not self._tray_icon:
                return
            if success:
                title = '保护已恢复' if enabled else '保护未运行'
                msg = '全部防护模块已启用' if enabled else '全部防护模块已停用'
                icon = QSystemTrayIcon.Information if enabled else QSystemTrayIcon.Warning
            else:
                title = '保护切换未完全生效'
                msg = '以下模块未能切换：%s' % detail
                icon = QSystemTrayIcon.Critical
            self._tray_icon.showMessage(title, msg, icon, 4000)
        except Exception as e:
            logger.error(f'保护切换完成回调失败: {e}')

    def _show_from_tray(self):
        """从托盘恢复显示主窗口"""
        self.show()
        self.showNormal()
        self.activateWindow()
        self.raise_()
        # 仅在托盘恢复时检测页面健康度：若 Chromium 渲染进程在窗口隐藏期间
        # 被回收/崩溃（页面白屏），主动 reload + 重建 webchannel。
        # 【关键】只有检测到页面不健康才重载——正常时绝不打断，避免因
        # 扫描等导致的临时卡顿引发误重载。
        try:
            if hasattr(self, '_web_view') and self._web_view is not None:
                self._maybe_recover_blank_webview()
        except Exception as e:
            _debug_log(f"_show_from_tray: 健康度检测 FAILED: {e}")

    def _maybe_recover_blank_webview(self):
        """检测托盘恢复后主页面是否需要 reload 以消除白屏。

        判定"页面不健康"依据（命中任一即重载）：
          1. 渲染进程曾经崩溃且等待兜底 reload（_render_crash_pending=True）
          2. 页面当前加载失败 / URL 被清空（Chromium 崩溃后常 Phone）
          3. 主 frame 处于异常终态（loadFinished 未成功过但页面已完成）

        正常/扫描卡顿时三者皆不满足，故不会误重载。
        """
        try:
            from PyQt5.QtWebEngineWidgets import QWebEngineView
            page = self._web_view.page()
            if page is None:
                return

            need_reload = False
            reason = ''

            # 1) 渲染进程崩溃待恢复标记
            crash_pending = bool(getattr(self, '_render_crash_pending', False))
            if crash_pending:
                need_reload = True
                reason = 'render-crash-pending'
                _debug_log(f"_maybe_recover_blank_webview: 命中渲染崩溃待恢复标记 ({reason})")

            # 2) 页面 URL 异常（正常应为 file:// 的 index.html / terminal.html）
            url = page.url().toString() if hasattr(page, 'url') else ''
            if not need_reload and not self._is_known_entry_url(url):
                need_reload = True
                reason = f'url-invalid: {url}'
                _debug_log(f"_maybe_recover_blank_webview: 页面 URL 异常请求重载 ({reason})")

            if need_reload:
                logger.info(f'托盘恢复检测到主界面不健康（{reason}），自动重载页面')
                self._render_crash_pending = False
                try:
                    self._web_view.reload()
                    self._setup_webchannel()
                    _debug_log("_maybe_recover_blank_webview: reload + webchannel 已重建")
                except Exception as e:
                    logger.warning(f'托盘恢复重载失败: {e}')
        except Exception as e:
            logger.warning(f'_maybe_recover_blank_webview 异常: {e}')

    def _quit_from_tray(self):
        """从托盘菜单真正退出应用"""
        self._force_quit = True
        self._cleanup_and_quit()

    def _cleanup_and_quit(self):
        """清理所有资源并终止应用进程

        防护模块的 stop() 可能因驱动卸载 / 线程 join 阻塞几百毫秒到数秒，
        因此在主线程直接串行执行会造成界面"未响应"。这里把繁重清理放到
        后台守护线程执行，主线程立即退出事件循环；另起一个 watchdog 定时器
        兜底强制退出，确保程序一定能关掉。
        """
        logger.info('开始清理并退出应用...')

        # 重入保护：清理/退出只允许执行一次
        if getattr(self, '_quit_in_progress', False):
            return
        self._quit_in_progress = True

        # 立即停止前台可见的轻量项
        if self._reveal_timer is not None:
            try:
                self._reveal_timer.stop()
            except Exception:
                pass
        if self._tray_icon:
            try:
                self._tray_icon.hide()
                self._tray_icon.deleteLater()
            except Exception:
                pass

        # 兜底：清理线程最多给 X 秒，超时强制退出，避免挂死
        def _force_exit_after(timeout):
            def _force():
                logger.warning(f'清理超时（>{timeout}s），强制退出 PSLS')
                try:
                    os._exit(0)
                except Exception:
                    pass
            t = threading.Timer(timeout, _force)
            t.daemon = True
            t.start()

        def _bg_cleanup():
            try:
                if self._bridge:
                    try:
                        self._bridge._scan_running.clear()
                    except Exception:
                        pass
                    for timer_attr in ('_flush_timer', '_finished_retry_timer',
                                       '_launch_spawn_timer', '_sandbox_cleanup_timer'):
                        try:
                            _tm = getattr(self._bridge, timer_attr, None)
                            if _tm is not None:
                                _tm.stop()
                        except Exception:
                            pass
                    cleanup_attrs_stop = [
                        '_realtime_monitor', '_process_protection', '_file_protection',
                        '_system_protection', '_self_protection', '_notification_manager',
                    ]
                    for attr in cleanup_attrs_stop:
                        mgr = getattr(self._bridge, attr, None)
                        if mgr and hasattr(mgr, 'stop'):
                            try:
                                mgr.stop()
                            except Exception:
                                pass
                    _ml_detector = getattr(self._bridge, '_ml_detector', None)
                    if _ml_detector and hasattr(_ml_detector, 'cleanup'):
                        try:
                            _ml_detector.cleanup()
                        except Exception:
                            pass
            except Exception as e:
                logger.warning(f'后台清理异常: {e}')

        # 启动后台清理线程
        _bg = threading.Thread(target=_bg_cleanup, daemon=True, name='PSLS_Cleanup')
        _bg.start()
        _force_exit_after(8)

        # 主线程立即退出事件循环
        QApplication.instance().quit()

    def _on_tray_activated(self, reason):
        """托盘图标点击事件：单击/双击显示主窗口"""
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self._show_from_tray()

    def closeEvent(self, event):
        """窗口关闭事件：最小化到托盘而非退出

        点击窗口标题栏的关闭按钮或前端"退出"按钮时，隐藏窗口到托盘。
        只有托盘右键菜单"退出"才会真正退出（_force_quit=True）。

        注意：如果系统托盘不可用（虚拟机/终端服务器），关闭窗口应真正退出程序，
        否则用户会无法关闭程序（没有托盘图标）。
        """
        _debug_log(f"closeEvent: _force_quit={self._force_quit}, tray_icon={self._tray_icon is not None}")
        if self._force_quit:
            event.ignore()
            self._cleanup_and_quit()
            return

        # 如果没有托盘图标，用户无法从托盘恢复窗口 → 直接退出
        if self._tray_icon is None:
            _debug_log("closeEvent: no tray icon, allow quit")
            event.accept()
            self._force_quit = True
            self._cleanup_and_quit()
            return

        # 正常情况：隐藏到托盘
        event.ignore()
        self.hide()
        if self._tray_icon:
            try:
                self._tray_icon.showMessage(
                    'PSLS',
                    '程序已最小化到托盘，右键托盘图标可退出。',
                    QSystemTrayIcon.Information,
                    3000
                )
            except Exception:
                pass

    def _setup_webchannel(self):
        """设置 WebChannel 桥接"""
        _debug_log("_setup_webchannel: creating PyBridge")
        self._bridge = PyBridge(self)
        # 一键开/关保护完成信号：用真实结果刷新托盘文案 + 系统通知
        try:
            self._bridge.protectionAllToggled.connect(
                self._on_protection_all_toggled)
        except Exception:
            pass
        # 主题切换信号：整页替换入口 HTML（米色 index.html / 终端 terminal.html）
        try:
            self._bridge.themeReloadRequested.connect(
                self._on_theme_reload_requested)
        except Exception as e:
            _debug_log(f"_setup_webchannel: themeReloadRequested connect FAILED: {e}")
        _debug_log("_setup_webchannel: PyBridge created")

        # —— 启动阶段：把 PyBridge 的真实进度/就绪信号接到 Splash ——
        try:
            self._bridge.launchProgressUpdated.connect(self._on_launch_progress_updated)
            _debug_log("_setup_webchannel: launchProgressUpdated connected")
        except Exception as e:
            _debug_log(f"_setup_webchannel: launchProgressUpdated connect FAILED: {e}")
        try:
            self._bridge.launchReady.connect(self._on_launch_ready)
            _debug_log("_setup_webchannel: launchReady connected")
        except Exception as e:
            _debug_log(f"_setup_webchannel: launchReady connect FAILED: {e}")
        # 把 PyBridge 在 connect 之前就已经 emit 到缓存里的进度信号立刻刷出来
        # （否则主窗口会漏看前几段进度，表现为 Splash 进度一直不动）
        try:
            if hasattr(self._bridge, 'flush_launch_progress'):
                self._bridge.flush_launch_progress()
                _debug_log("_setup_webchannel: flush_launch_progress() called")
        except Exception as e:
            _debug_log(f"_setup_webchannel: flush_launch_progress FAILED: {e}")

        channel = QWebChannel(self)
        channel.registerObject('pyBridge', self._bridge)
        _debug_log("_setup_webchannel: channel registered")

        # 诊断 QtWebEngineProcess 可用性
        try:
            if getattr(sys, 'frozen', False):
                meipass = sys._MEIPASS
            else:
                meipass = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            process_exe = os.path.join(meipass, 'PyQt5', 'Qt5', 'bin', 'QtWebEngineProcess.exe')
            _debug_log(f"_setup_webchannel: QtWebEngineProcess path={process_exe}")
            _debug_log(f"_setup_webchannel: QtWebEngineProcess exists={os.path.exists(process_exe)}")
            if os.path.exists(process_exe):
                _debug_log(f"_setup_webchannel: QtWebEngineProcess size={os.path.getsize(process_exe)}")
            # 检查关键 DLL
            bin_dir = os.path.join(meipass, 'PyQt5', 'Qt5', 'bin')
            for dll in ['Qt5WebEngineCore.dll', 'Qt5Core.dll', 'Qt5Gui.dll', 'Qt5Network.dll',
                        'MSVCP140.dll', 'VCRUNTIME140.dll', 'VCRUNTIME140_1.dll']:
                dll_path = os.path.join(bin_dir, dll)
                _debug_log(f"_setup_webchannel: DLL {dll} exists={os.path.exists(dll_path)}")
            # 检查资源文件
            res_dir = os.path.join(meipass, 'PyQt5', 'Qt5', 'Resources')
            for pak in ['resources.pak', 'resources_100p.pak', 'resources_200p.pak', 'icudtl.dat']:
                pak_path = os.path.join(res_dir, pak)
                _debug_log(f"_setup_webchannel: resource {pak} exists={os.path.exists(pak_path)}")
        except Exception as e:
            _debug_log(f"_setup_webchannel: diagnostic failed: {e}")

        _debug_log("_setup_webchannel: calling page()")
        try:
            page = self._web_view.page()
            _debug_log("_setup_webchannel: page() returned")
            page.setWebChannel(channel)
            _debug_log("_setup_webchannel: webchannel set on page")
        except Exception as e:
            _debug_log(f"_setup_webchannel: page()/setWebChannel FAILED: {e}\n{traceback.format_exc()}")
            raise

        # 禁用 QWebEngineView 磁盘缓存，确保每次启动加载最新 HTML
        try:
            from PyQt5.QtWebEngineWidgets import QWebEngineSettings, QWebEngineProfile
            profile = self._web_view.page().profile()
            profile.setHttpCacheType(QWebEngineProfile.NoCache)
            settings = self._web_view.page().settings()
            settings.setAttribute(QWebEngineSettings.LocalContentCanAccessFileUrls, True)
            settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
        except Exception as e:
            _debug_log(f"_setup_webchannel: cache config failed: {e}")
            print(f'[CACHE] Failed to disable cache: {e}')
        _debug_log("_setup_webchannel done")

    def _load_html(self):
        """加载HTML页面（按当前内置主题选择入口：index.html / terminal.html）"""
        import time
        html_path = get_resource_path(
            os.path.join('ui', 'webview', self._entry_file))
        abs_path = os.path.abspath(html_path)
        # 使用 file:// URL 加载本地 HTML（Qt WebEngine 不会缓存本地文件）
        html_url = QUrl.fromLocalFile(abs_path)
        print(f'[LOAD] Loading HTML from: {abs_path}')
        _debug_log(f"_load_html: theme={self._current_theme} entry={self._entry_file}")
        _debug_log(f"_load_html: html_path={html_path}")
        _debug_log(f"_load_html: exists={os.path.exists(abs_path)} size={os.path.getsize(abs_path) if os.path.exists(abs_path) else 0}")
        _debug_log(f"_load_html: url={html_url.toString()}")
        self._web_view.setUrl(html_url)
        _debug_log("_load_html: setUrl called")

    def _on_theme_reload_requested(self, theme):
        """主题切换：整页替换入口 HTML（复用同一个 QWebEngineView 与 PyBridge）

        两套主题的页面结构不同（米色 = 现有结构；终端 = 设计稿结构），
        因此不做"换肤"，而是整页换入口文件。QWebChannel 已注册在 page 上，
        重新导航后由 Qt 重新注入 webChannelTransport，无需重建 PyBridge
        （重建会二次执行 _init_managers 并重复拉起防护引擎）。
        """
        try:
            new_theme = theme_tokens.normalize(theme)
            self._current_theme = new_theme
            self._entry_file = _ENTRY_FILES.get(new_theme, 'index.html')
            self._main_loaded = False
            _debug_log(f"_on_theme_reload_requested: theme={new_theme} entry={self._entry_file}")
            self._load_html()
        except Exception as e:
            _debug_log(f"_on_theme_reload_requested FAILED: {e}")
            logger.error(f'主题切换重载页面失败: {e}')

    def _is_known_entry_url(self, url: str) -> bool:
        """URL 是否指向某个已知主题入口页（用于健康度检查）。"""
        if not url:
            return False
        return any(name in url for name in set(_ENTRY_FILES.values()))


def main():
    """主函数

    支持 --minimized 命令行参数：开机自启时静默启动到系统托盘，不显示主窗口。
    """
    _debug_log("main() start")
    _debug_log(f"  QT_OPENGL={os.environ.get('QT_OPENGL', '')}")
    _debug_log(f"  QTWEBENGINE_CHROMIUM_FLAGS={os.environ.get('QTWEBENGINE_CHROMIUM_FLAGS', '')[:200]}")
    _debug_log(f"  argv={sys.argv}")

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    # Chromium flags 已在 gui_entry.py 中提前设置
    # 此处确保不会被覆盖
    if 'QTWEBENGINE_CHROMIUM_FLAGS' not in os.environ:
        os.environ['QTWEBENGINE_CHROMIUM_FLAGS'] = '--disable-gpu --no-sandbox'

    _debug_log("main: creating QApplication")
    app = QApplication(sys.argv)
    app.setApplicationName('PSLS')
    app.setOrganizationName('Project Sertraline Lab')
    app.setQuitOnLastWindowClosed(False)
    _debug_log("main: QApplication created")

    _debug_log("main: creating WebViewMainWindow")
    window = WebViewMainWindow()
    _debug_log("main: WebViewMainWindow created")

    def _on_about_to_quit():
        logger.info('aboutToQuit 信号触发，确保所有线程已停止')
        # 记录退出调用栈：定位"静默退出/闪退"时是谁调用了 quit(close)，
        # 便于区分正常关闭、后台线程触发退出还是被引擎清理误触。
        try:
            tb = ''.join(traceback.format_stack())
            logger.info(f'aboutToQuit 调用栈（排查退出来源）:\n{tb}')
        except Exception:
            pass
        try:
            if window._bridge:
                for attr in ['_realtime_monitor', '_process_protection', '_file_protection',
                             '_system_protection', '_self_protection',
                             '_notification_manager']:
                    mgr = getattr(window._bridge, attr, None)
                    if mgr and hasattr(mgr, 'stop'):
                        try:
                            mgr.stop()
                        except Exception:
                            pass
                _ml_detector = getattr(window._bridge, '_ml_detector', None)
                if _ml_detector and hasattr(_ml_detector, 'cleanup'):
                    try:
                        _ml_detector.cleanup()
                    except Exception:
                        pass
            # 关闭 Splash（若仍显示）
            if window._splash is not None:
                try:
                    window._splash.close_splash()
                except Exception:
                    pass
                window._splash = None
        except Exception as e:
            logger.error(f'aboutToQuit 清理出错: {e}')

    app.aboutToQuit.connect(_on_about_to_quit)

    minimized = is_minimized_startup()
    _debug_log(f"main: is_minimized_startup={minimized}")
    window._start_minimized = minimized

    # ---- 启动界面（Splash） ----
    # 纯 Qt 自绘的启动加载界面（不再依赖 QWebEngineView/splash.html，
    # 上屏快、无 Chromium 开销）；主 GUI 的 index.html 后台加载，
    # 真正加载完成（loadFinished ok）后才关闭 Splash 并显示主窗口。
    splash = None
    if not minimized:
        try:
            from ui.webview.splash_window import SplashWindow
            splash = SplashWindow()
            window.set_splash(splash)
            _debug_log("main: SplashWindow created")
        except Exception as e:
            _debug_log(f"main: SplashWindow creation FAILED: {e}\n{traceback.format_exc()}")
            splash = None
            window.set_splash(None)

    def _do_start():
        # 事件循环已运行。
        # 顺序关键：必须先启动并显示 Splash，再启动主 GUI 初始化。
        # 因为 _setup_webchannel() 会构造 PyBridge 并同步执行较重的
        # _init_managers()（加载签名库/ML 模型等），若先做它会把主线程阻塞
        # 数秒，导致 Splash 迟迟无法上屏/渲染不出来。
        if splash is not None:
            try:
                splash.start()          # 启动纯 Qt 自绘进度动画
                splash.center_window()  # 居中显示（即时上屏，无 Chromium 开销）
                _debug_log("main: splash started")
            except Exception as e:
                _debug_log(f"main: splash start FAILED: {e}\n{traceback.format_exc()}")
                try:
                    splash.close_splash()
                except Exception:
                    pass
                window.set_splash(None)

        # 稍作延迟再启动主 GUI 的超重初始化，给 Splash 一段事件循环时间去
        # 完成首次渲染上屏；Splash 上屏后即使主线程随后被初始化阻塞，也能
        # 持续可见（已绘制的窗口不会因主线程阻塞而消失）。
        QTimer.singleShot(200, lambda: window._begin_loaded_main())
        _debug_log("main: _begin_loaded_main scheduled (deferred 200ms for splash paint)")

        # 轮询揭示条件（初始化完成 + 主界面加载 + 最短展示时长）；
        # 一旦显示主窗口即停止。静默自启不主动显示主窗口，无需轮询。
        if not minimized:
            window._reveal_timer = QTimer()
            window._reveal_timer.setInterval(250)
            window._reveal_timer.timeout.connect(
                lambda: (window._maybe_reveal_main(),
                         window._reveal_timer.stop() if not window._reveal_pending else None)
            )
            window._reveal_timer.start()
            _debug_log("main: reveal poll timer started")
            window._maybe_reveal_main()

    QTimer.singleShot(0, _do_start)

    # ---- 心跳 + 退出路径观测（定位"静默闪退"）----
    _debug_log("heartbeat: enabling")
    _hb_count = [0]

    def _hb_tick():
        _hb_count[0] += 1
        _debug_log(f"heartbeat alive #{_hb_count[0]}")

    _heartbeat_timer = QTimer()
    _heartbeat_timer.setInterval(1000)
    _heartbeat_timer.timeout.connect(_hb_tick)
    _heartbeat_timer.start()

    def _atexit_log():
        # 若进程是经 sys.exit/正常 Python 退出，此处会触发并记录调用栈；
        # 若被 TerminateProcess/ExitProcess 硬杀则不会触发。
        try:
            _debug_log("atexit 触发（PyQt 事件循环返回后到达此处）——正常退出路径")
        except Exception:
            pass

    try:
        import atexit
        atexit.register(_atexit_log)
    except Exception:
        pass

    # ---- 超时兜底 ----
    # 若主 index.html 长时间未加载完成（如渲染进程反复崩溃），或初始化迟迟未完成，
    # 强制关闭 Splash 并显示主窗口，避免用户停留在启动界面。
    # 【重要】仅在初始化未失败且页面已加载成功时才强制显示；若 WebEngine/
    # 主界面初始化失败（_web_init_failed），绝不渲染"未就绪"的主 GUI——
    # 关闭 Splash 后给出错误提示，宁可让用户看到提示信息，也不显示半成品界面。
    def _force_reveal():
        if window._reveal_timer is not None:
            window._reveal_timer.stop()
        # 静默自启：不在后台主动弹窗/显示，托盘恢复时再评估
        if getattr(window, '_start_minimized', False):
            return
        # 仅"初始化真实抛异常/页面加载失败"时阻断渲染（这个时候必然不是
        # 可用的主界面）；页面只是加载慢(无异常)仍走兜底显示，避免用户卡 Splash。
        if getattr(window, '_web_init_failed', False):
            _debug_log("main: force reveal skipped (web init failed)")
            if window._splash is not None:
                try:
                    window._splash.close_splash()
                except Exception:
                    pass
                window._splash = None
            try:
                if not window.isVisible():
                    from PyQt5.QtWidgets import QMessageBox
                    QMessageBox.warning(
                        window, 'PSLS 启动失败',
                        '主界面初始化失败或页面加载异常，程序未完全就绪。\n'
                        '请重启 PSLS；若问题持续，请查看 activity / debug 日志。')
            except Exception:
                pass
            return
        _debug_log("main: force reveal main window (timeout)")
        window._maybe_reveal_main(force=True)

    QTimer.singleShot(12000, _force_reveal)

    if minimized:
        logger.info('以静默模式启动（开机自启），最小化到系统托盘')
        # Splash 不显示；主 GUI 仍在后台加载，托盘点击时显示已就绪的窗口
    else:
        _debug_log("main: main window will be shown after init complete + index load (or timeout)")

    # ---- 崩溃现场线程栈转储（定位 0x8001010d COM 崩溃）----
    # 默认关闭：周期性全线程转储会持续写 I/O（每 5s 一次，实测 crash 日志
    # 膨胀到 130MB+），生产环境无必要。仅在排障时设 PSLS_PERIODIC_STACK_DUMP=1
    # 启用；真正的崩溃栈由 gui_entry 的 faulthandler/excepthook 捕获。
    if os.environ.get('PSLS_PERIODIC_STACK_DUMP') == '1':
        try:
            import faulthandler
            _dump_f = open(os.path.join(os.path.expanduser('~'), 'psls_crash.log'), 'a', encoding='utf-8')
            faulthandler.dump_traceback_later(5.0, repeat=True, file=_dump_f)
            _debug_log("faulthandler periodic thread-stack dump enabled (5s)")
        except Exception as _e:
            _debug_log(f"faulthandler periodic dump FAILED: {_e}")

    _debug_log("main: entering app.exec_() event loop")
    _rc = app.exec_()
    try:
        faulthandler.cancel_dump_traceback_later()
    except Exception:
        pass
    _debug_log(f"main: app.exec_() returned {_rc}")
    sys.exit(_rc)


if __name__ == '__main__':
    main()
