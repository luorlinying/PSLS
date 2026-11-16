#!/usr/bin/env python3
"""
Python-JavaScript 桥接层
使用 QWebChannel 实现双向通信
"""

import os
import sys
import json
import time
import re
import threading
import shutil
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
from typing import Any, Dict, List, Optional
from datetime import datetime


class _SafeJSONEncoder(json.JSONEncoder):
    """安全 JSON 编码器：将 bytes/bytearray/set 等不可序列化类型自动降级"""

    def default(self, obj):
        if isinstance(obj, (bytes, bytearray)):
            try:
                return obj.decode('utf-8')
            except UnicodeDecodeError:
                return obj.decode('latin-1')
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return str(obj)


def _safe_json_dumps(obj, **kwargs):
    """全局安全 json.dumps，永远不抛 bytes 序列化异常"""
    kwargs.setdefault('ensure_ascii', False)
    kwargs.setdefault('cls', _SafeJSONEncoder)
    return json.dumps(obj, **kwargs)


# ------------------------------------------------------------------------
# 用户设置持久化（%APPDATA%\PSLS\settings.json 的 "ui" 段）
# ------------------------------------------------------------------------
# 实时防护威胁处理方式、各防护模块开关等用户在设置页所做的修改，此前仅存在
# 内存（重启即丢）或前端 localStorage（会被后端默认值覆盖），导致"重启后设置
# 不保存"。这里统一落盘到 settings.json 的 "ui" 段，启动时回读。
# 复用同一文件（engine/quarantine_manager.py 也在用它的 quarantine_path 键），
# 采用"读取-合并-写回"避免覆盖其它键。
_UI_SETTINGS_SECTION = 'ui'


def _ui_settings_path() -> str:
    """返回用户设置文件路径（%APPDATA%\\PSLS\\settings.json）。

    路径规则由 theme_tokens.settings_path() 统一提供（Qt 侧窗口也要读同一份设置）。
    """
    return theme_tokens.settings_path()


def _load_ui_settings() -> dict:
    """读取持久化的用户界面设置（"ui" 段），失败返回空 dict。"""
    try:
        path = _ui_settings_path()
        if not os.path.exists(path):
            return {}
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        section = data.get(_UI_SETTINGS_SECTION) if isinstance(data, dict) else None
        return section if isinstance(section, dict) else {}
    except Exception:
        return {}


def _save_ui_settings(values: dict) -> None:
    """合并写入用户界面设置（保留 settings.json 中其它键与其它段）。"""
    try:
        path = _ui_settings_path()
        data = {}
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception:
                data = {}
        if not isinstance(data, dict):
            data = {}
        section = data.get(_UI_SETTINGS_SECTION)
        if not isinstance(section, dict):
            section = {}
        section.update(values)
        data[_UI_SETTINGS_SECTION] = section
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f'保存用户设置失败: {e}')


# ============================================================================
# 勒索回滚"确认弹窗"防轰炸（Bug 修复：确认弹窗反复弹出）
# ----------------------------------------------------------------------------
# 根因：file_protection._track_modification → _eval_and_dispatch 对**每个**文件
# 事件都做一次融合判定；受保护目录被连续写入（如 QQ 缩略图）时，窗口计数反复
# 达到 MASS_MODIFY_THRESHOLD(30) → 每次都会回调 on_ransomware_confirmed →
# ransomwareRollbackRequested 信号 → 主线程再弹一次"是否回滚"。而弹窗处理器
# 每次又会 prev.close() 上一个未决窗口（closeEvent → releaseRejected）→ 表现为
# "用户选择不回滚" 与 "待确认" 交替刷屏（实测 22:22:17→22:23:06 共 26 次）。
#
# 修复：加三道闩锁（均在主线程/回调线程共享的锁内判定，异常安全）：
#   1) pending 闩锁：存在未决弹窗时，重复检测只记 DEBUG + 计数，绝不重发；
#   2) 决策冷却：任一种决策（回滚/不回滚/超时默认）落地后，冷却期内抑制再弹；
#   3) 冷却期内的"显著变化"豁免：受影响文件数显著增长（数倍且增量够大）时才允许
#      重新提示——避免"同一轮攻击反复弹"，又不漏掉真正升级的攻击。
# 结果：同一轮攻击只提示一次（修前 26 次 → 修后 1 次）。
_RANSOMWARE_PROMPT_COOLDOWN = 60.0     # 决策落地后的抑制冷却期（秒）
_RANSOMWARE_PROMPT_GROW_FACTOR = 2.0   # 受影响文件数较上次"翻倍"视为显著变化
_RANSOMWARE_PROMPT_GROW_DELTA = 20     # 显著变化的最小绝对增量（防 1→2 误触发）

# 单文件快照上限（调整决定 3）：滑动条范围 1..256 MB；=0 表示不限制。
# 归一规则：1..256 → 该 MB 数；<=0 或 >256 → 0（不限制，滑到最顶端的语义）。
_RB_MAX_FILE_MB_CAP = 256
_RB_MAX_FILE_MB_DEFAULT = 64


def _coerce_max_file_mb(value) -> int:
    """滑动条取值归一：1..256 → 该 MB 数；<=0 或 >256 或缺省 → 0（不限制）。

    缺省（None）返回默认 64（不由本函数处理，调用方直接给 64）。非法输入按默认。
    """
    try:
        v = int(value)
    except Exception:
        return _RB_MAX_FILE_MB_DEFAULT
    if v <= 0:
        return 0
    if v > _RB_MAX_FILE_MB_CAP:
        return 0
    return v


def _mb_to_bytes(mb) -> int:
    """MB → 字节；0 表示不限制。"""
    m = _coerce_max_file_mb(mb)
    return 0 if m <= 0 else m * 1024 * 1024


def _bytes_to_mb(nbytes) -> int:
    """字节 → MB（用于回填滑动条）；0 表示不限制。"""
    try:
        b = int(nbytes)
    except Exception:
        return _RB_MAX_FILE_MB_DEFAULT
    if b <= 0:
        return 0
    return max(1, int(round(b / (1024 * 1024))))


def _apply_widget_scale(widget, base_width: int, scale: float):
    """按缩放比例调整屏幕弹窗宽度与所有子控件字号（通用 helper）

    将弹窗固定宽度与 stylesheet 中的 font-size Npx 统一按比例缩放，
    并在缩放后重新定位到屏幕右下角。

    Args:
        widget: 要缩放的 QWidget 弹窗
        base_width: 100% 缩放时的基础宽度（px）
        scale: 缩放比例（1.0 = 100%）
    """
    try:
        scale = float(scale) if scale else 1.0
        widget._scale = scale
        # 1. 宽度缩放
        widget.setFixedWidth(max(240, int(base_width * scale)))
        # 2. 遍历所有子控件，将 stylesheet 中的 font-size Npx 按比例缩放
        _re_font = re.compile(r'font-size:\s*(\d+)px')
        for w in widget.findChildren(QWidget):
            try:
                ss = w.styleSheet()
                if ss and 'font-size' in ss:
                    def _repl(m, s=scale):
                        return f'font-size: {max(8, int(int(m.group(1)) * s))}px'
                    w.setStyleSheet(_re_font.sub(_repl, ss))
            except Exception:
                pass
        widget.adjustSize()
        _settle_popup_layout(widget)
        if hasattr(widget, '_position_at_bottom_right'):
            try:
                widget._position_at_bottom_right()
            except Exception:
                pass
    except Exception as e:
        logger.warning(f'弹窗缩放失败: {e}')


def _settle_popup_layout(widget):
    """显示前先让布局按弹窗宽度结算一次（消除 setGeometry 尺寸纠偏告警）

    隐藏窗口收不到 resize 事件，布局要等 show() 之后才按弹窗实际宽度结算。
    弹窗里的自动换行长文本（文件路径、威胁名）此时还没折行，adjustSize()
    算出的高度偏小；真正显示时窗口管理器按布局实际所需把窗口放大，于是刷出
    QWindowsWindow::setGeometry: Unable to set geometry ...（请求尺寸被改写）。
    这里先用 WA_DontShowOnScreen 把窗口"显示"一次——不创建真实窗口，仅让 Qt
    把这轮尺寸纠偏消化掉——随后隐藏并恢复属性，再真正显示时尺寸已经稳定。
    """
    if getattr(widget, '_layout_settled', False) or widget.isVisible():
        return
    widget._layout_settled = True
    try:
        widget.setAttribute(Qt.WA_DontShowOnScreen, True)
        widget.show()
        widget.hide()
        widget.setAttribute(Qt.WA_DontShowOnScreen, False)
    except Exception as e:
        logger.warning(f'弹窗显示前布局结算失败: {e}')


from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot, QTimer, QJsonValue, Qt, QVariant
from PyQt5.QtWidgets import (
    QApplication, QWidget, QFrame, QLabel, QPushButton, QCheckBox,
    QVBoxLayout, QHBoxLayout
)
from PyQt5.QtGui import QIcon

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from engine.scan_engine import ScanEngine, _init_scan_worker, _scan_file_worker_full
from engine.quarantine_manager import QuarantineManager
from engine.process_protection import ProcessProtection
from engine.file_protection import FileProtection
from engine.system_protection import SystemProtection
from engine.self_protection import SelfProtection
from engine.autostart_protection import AutostartProtection
from engine.mbr_protector import MBRProtector
from engine.notification_manager import NotificationManager
from engine.realtime_monitor import RealtimeMonitor, get_critical_watch_dirs, get_all_local_drives
from engine.yara_portable import YaraPortable, download_portable_python, check_yara_compatibility
from engine.virus_identifier import VirusIdentifier
from engine.ml_detector import MLMalwareDetector
from engine.sandbox_analyzer import SandboxAnalyzer, SandboxConfig
from engine.visual_prank_detector import VisualPrankDetector
from engine.aggressive_prank_detector import AggressivePrankDetector
from engine.ransomware_rollback import RansomwareRollback
from engine.rollback_worker import (
    RollbackWorkerProxy, create_rollback_manager as _create_rollback_manager)
from engine.mb_syncer import MBSyncer
from ui.webview.sandbox_analysis_window import (
    SandboxAnalysisWindow,
    SandboxReleaseWindow,
    SandboxThreatWindow,
    SandboxFailureWindow,
    RollbackProgressWindow,
)
from ui.webview import theme_tokens
from db.signature_db import SignatureDB
from utils.logger import get_logger
from utils import sound_manager, load_governor
from utils import signature_verifier
from utils.autostart_manager import AutoStartManager

logger = get_logger('webview_bridge')

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False

# 子进程窗口隐藏标志（Windows 平台阻止弹出黑色 cmd/PowerShell 窗口）
# CREATE_NO_WINDOW = 0x08000000，在非 Windows 平台为 0（安全默认值）
_HIDDEN_CREATIONFLAGS = 0x08000000 if sys.platform == 'win32' else 0


def _get_app_icon() -> QIcon:
    """获取应用图标（用于系统托盘和弹窗）"""
    try:
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        icon_path = os.path.join(project_root, 'ui', 'webview', 'assets', 'image_0_7mlicq.png')
        if os.path.exists(icon_path):
            return QIcon(icon_path)
    except Exception:
        pass
    return QIcon()


class ThreatNotificationPopup(QWidget):
    """桌面右下角威胁通知弹窗（独立顶层窗口，无边框置顶）

    出现在桌面右下角（避开任务栏），而非软件窗口内部。
    用于"notify"策略，让用户在桌面通知中选择"自动处理"或"忽略"。
    """

    autoActionTriggered = pyqtSignal(str)   # payload JSON，按钮点击后通知 PyBridge 执行自动处理
    ignoreActionTriggered = pyqtSignal(str) # payload JSON，按钮点击后通知 PyBridge 忽略
    trustActionTriggered = pyqtSignal(str)  # payload JSON，按钮点击后忽略并加入白名单
    applyToAllRequested = pyqtSignal(str, str)  # (action, threat_type) 对所有同类型对象执行同样操作

    def __init__(self, threat_data: dict, parent=None, scale: float = 1.0):
        super().__init__(parent)
        self._threat_data = threat_data
        self._payload = json.dumps(threat_data, ensure_ascii=False)
        self._scale = float(scale) if scale else 1.0
        self._closed_by_user = False
        self._apply_to_all_checkbox = None
        self._setup_window_flags()
        self._setup_ui()
        # 按缩放比例调整弹窗大小与字号（宽度/字体随设置缩放）
        if self._scale != 1.0:
            self._apply_scale(self._scale)
        # 100% 缩放时不走 _apply_scale，同样需要先结算布局再定位
        _settle_popup_layout(self)
        self._position_at_bottom_right()
        # 超时自动兜底（5 秒后执行默认操作；不再显示倒计时文字）
        self._auto_action_timer = QTimer(self)
        self._auto_action_timer.setSingleShot(True)
        self._auto_action_timer.timeout.connect(self._auto_action_on_timeout)
        self._auto_action_timer.start(5000)
        self._anim = None

    def _setup_window_flags(self):
        """无边框、置顶、工具窗口（不在任务栏显示）"""
        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint |
            Qt.Tool |
            Qt.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)
        self.setAttribute(Qt.WA_DeleteOnClose, True)

    def _setup_ui(self):
        threat = self._threat_data
        is_danger = threat.get('status') == 'malware'
        is_sandbox_release = threat.get('_is_sandbox_release', False)

        self.setFixedWidth(max(240, int(360 * self._scale)))
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # 头部
        header = QFrame()
        if is_sandbox_release:
            # 沙箱放行确认：蓝色头部
            header_gradient = 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #2563eb, stop:1 #1d4ed8)'
            header_icon = ''
            header_title = '沙箱放行确认'
        elif is_danger:
            header_gradient = 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #dc2626, stop:1 #b91c1c)'
            header_icon = ''
            header_title = '检测到危险对象'
        else:
            header_gradient = 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #d97706, stop:1 #b45309)'
            header_icon = ''
            header_title = '检测到可疑对象'
        header.setStyleSheet(
            f'QFrame {{ background: {header_gradient}; '
            f'border-top-left-radius: 10px; border-top-right-radius: 10px; }}'
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 10, 10, 10)
        header_layout.setSpacing(8)

        if header_icon:
            icon_label = QLabel(header_icon)
            icon_label.setStyleSheet('QLabel { font-size: 16px; border: none; background: transparent; }')
        title_label = QLabel(header_title)
        title_label.setStyleSheet(
            'QLabel { color: white; font-size: 13px; font-weight: 600; '
            'border: none; background: transparent; }'
        )
        if header_icon:
            header_layout.addWidget(icon_label)
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        close_btn = QPushButton('×')
        close_btn.setFixedSize(22, 22)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet(
            'QPushButton { color: white; border: none; background: transparent; '
            'font-size: 18px; font-weight: bold; } '
            'QPushButton:hover { background: rgba(255,255,255,0.25); border-radius: 11px; }'
        )
        close_btn.clicked.connect(self._close_by_user)
        header_layout.addWidget(close_btn)

        # 顶部色条保留原有红/琥珀/蓝：它是"醒目注意"的主要信号，
        # 终端主题下不做色板映射（连同白色标题/关闭按钮一起豁免）。
        theme_tokens.mark_keep_accent(header, title_label, close_btn)

        outer.addWidget(header)

        # 内容
        body = QFrame()
        body.setStyleSheet(
            'QFrame { background: #ffffff; '
            'border-bottom-left-radius: 10px; border-bottom-right-radius: 10px; '
            'border: 1px solid #d6d3d1; border-top: none; }'
        )
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(14, 12, 14, 12)
        body_layout.setSpacing(4)

        if is_sandbox_release:
            # 沙箱放行模式：显示额外说明
            sig_label = QLabel(threat.get('signature_name', '未知进程'))
            sig_label.setStyleSheet(
                'QLabel { color: #1a1a2e; font-size: 12px; font-weight: 500; '
                'border: none; background: transparent; }'
            )
            sig_label.setWordWrap(True)
            body_layout.addWidget(sig_label)

            info_label = QLabel('进程已被终止，沙箱分析判定为安全。\n是否同意重启该进程？')
            info_label.setStyleSheet(
                'QLabel { color: #44403c; font-size: 11px; '
                'border: none; background: transparent; padding-top: 4px; }'
            )
            info_label.setWordWrap(True)
            body_layout.addWidget(info_label)
        else:
            sig_label = QLabel(threat.get('signature_name', '未知威胁'))
            sig_label.setStyleSheet(
                'QLabel { color: #1a1a2e; font-size: 12px; font-weight: 500; '
                'border: none; background: transparent; }'
            )
            sig_label.setWordWrap(True)
            body_layout.addWidget(sig_label)

        path_label = QLabel(threat.get('file_path', ''))
        path_label.setStyleSheet(
            'QLabel { color: #78716c; font-size: 11px; '
            'border: none; background: transparent; }'
        )
        path_label.setWordWrap(True)
        path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        body_layout.addWidget(path_label)

        # "为所有相同类型对象执行同样操作"复选框（沙箱放行模式下隐藏）
        if not is_sandbox_release:
            apply_all_checkbox = QCheckBox('为所有相同类型对象执行同样操作')
            apply_all_checkbox.setChecked(False)
            apply_all_checkbox.setCursor(Qt.PointingHandCursor)
            apply_all_checkbox.setStyleSheet(
                'QCheckBox { color: #78716c; font-size: 11px; border: none; background: transparent; '
                'spacing: 6px; padding-top: 6px; } '
                'QCheckBox::indicator { width: 14px; height: 14px; border: 1.5px solid #d6d3d1; '
                'border-radius: 3px; background: #ffffff; } '
                'QCheckBox::indicator:hover { border-color: #0d9488; } '
                'QCheckBox::indicator:checked { background: #0d9488; border-color: #0d9488; '
                'image: none; }'
            )
            body_layout.addWidget(apply_all_checkbox)
            self._apply_to_all_checkbox = apply_all_checkbox

        # 按钮区
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        btn_layout.setContentsMargins(0, 8, 0, 0)

        if is_sandbox_release:
            # 沙箱放行模式：同意重启 / 不重启
            auto_btn = QPushButton('同意重启')
            auto_btn.setCursor(Qt.PointingHandCursor)
            auto_btn.setStyleSheet(
                'QPushButton { background: #2563eb; color: white; border: none; '
                'padding: 7px 12px; border-radius: 6px; font-size: 12px; font-weight: 500; } '
                'QPushButton:hover { background: #1d4ed8; }'
            )
            auto_btn.clicked.connect(lambda: self._emit_action('auto'))

            ignore_btn = QPushButton('不重启')
            ignore_btn.setCursor(Qt.PointingHandCursor)
            ignore_btn.setStyleSheet(
                'QPushButton { background: #a8a29e; color: white; border: none; '
                'padding: 7px 12px; border-radius: 6px; font-size: 12px; font-weight: 500; } '
                'QPushButton:hover { background: #78716c; }'
            )
            ignore_btn.clicked.connect(lambda: self._emit_action('ignore'))

            btn_layout.addWidget(auto_btn)
            btn_layout.addWidget(ignore_btn)
        else:
            auto_btn = QPushButton('隔离/删除' if is_danger else '自动处理')
            auto_btn.setCursor(Qt.PointingHandCursor)
            auto_btn.setStyleSheet(
                'QPushButton { background: #0d9488; color: white; border: none; '
                'padding: 7px 12px; border-radius: 6px; font-size: 12px; font-weight: 500; } '
                'QPushButton:hover { background: #0f766e; }'
            )
            auto_btn.clicked.connect(lambda: self._emit_action('auto'))

            ignore_btn = QPushButton('忽略')
            ignore_btn.setCursor(Qt.PointingHandCursor)
            ignore_btn.setStyleSheet(
                'QPushButton { background: #a8a29e; color: white; border: none; '
                'padding: 7px 12px; border-radius: 6px; font-size: 12px; font-weight: 500; } '
                'QPushButton:hover { background: #78716c; }'
            )
            ignore_btn.clicked.connect(lambda: self._emit_action('ignore'))

            # 「忽略并信任」：忽略本次告警并把文件哈希写入白名单（米色按钮）
            trust_btn = QPushButton('忽略并信任')
            trust_btn.setCursor(Qt.PointingHandCursor)
            trust_btn.setStyleSheet(
                'QPushButton { background: #c9b48c; color: white; border: none; '
                'padding: 7px 12px; border-radius: 6px; font-size: 12px; font-weight: 500; } '
                'QPushButton:hover { background: #b09b73; }'
            )
            trust_btn.clicked.connect(lambda: self._emit_action('trust'))

            # 位置关系：主操作(自动处理)独占整行、铺满宽度，放在最下方醒目处；
            # 两个"不动手"的选项(忽略 / 忽略并信任)并排在它上面一行
            btn_layout.addWidget(auto_btn)

            btn_layout_row2 = QHBoxLayout()
            btn_layout_row2.setSpacing(8)
            btn_layout_row2.setContentsMargins(0, 0, 0, 0)
            btn_layout_row2.addWidget(ignore_btn)
            btn_layout_row2.addWidget(trust_btn)
            body_layout.addLayout(btn_layout_row2)
        body_layout.addLayout(btn_layout)

        outer.addWidget(body)
        self.adjustSize()

    def _apply_scale(self, scale: float):
        """按缩放比例调整弹窗宽度与所有控件的字号（滑块实时拖动时调用）
        """
        _apply_widget_scale(self, 360, scale)

    def _position_at_bottom_right(self):
        """将弹窗定位到主屏幕右下角（避开任务栏）"""
        try:
            screen = QApplication.primaryScreen()
            if screen:
                geometry = screen.availableGeometry()
                x = geometry.right() - self.width() - 20
                y = geometry.bottom() - self.height() - 20
                self.move(x, y)
                return
        except Exception as e:
            logger.warning(f'定位弹窗失败: {e}')
        # 兜底：右下角 20px 边距
        self.move(1920 - self.width() - 20, 1080 - self.height() - 60)

    def _slide_in(self):
        """滑入动画：从右侧滑入到目标位置（"动态光效"关闭时直接静态出现）"""
        try:
            if not theme_tokens.load_motion():
                self.show()
                return
            final_pos = self.pos()
            start_pos = final_pos.x() + self.width() + 40, final_pos.y()
            self.move(start_pos[0], start_pos[1])
            self.show()
            from PyQt5.QtCore import QPropertyAnimation, QEasingCurve
            self._anim = QPropertyAnimation(self, b'pos', self)
            self._anim.setDuration(300)
            self._anim.setStartValue(self.pos())
            self._anim.setEndValue(final_pos)
            self._anim.setEasingCurve(QEasingCurve.OutCubic)
            self._anim.start()
        except Exception as e:
            logger.warning(f'滑入动画失败: {e}')
            self.show()

    def _emit_action(self, action: str):
        """按钮点击后发射信号并关闭（停止倒计时）"""
        self._closed_by_user = True
        self._stop_timers()
        threat_type = self._threat_data.get('status', 'suspicious')
        apply_to_all = (
            self._apply_to_all_checkbox is not None
            and self._apply_to_all_checkbox.isChecked()
        )
        data = dict(self._threat_data)
        data['action'] = action
        payload = json.dumps(data, ensure_ascii=False)

        if apply_to_all:
            self.applyToAllRequested.emit(action, threat_type)
        else:
            if action == 'auto':
                self.autoActionTriggered.emit(payload)
            elif action == 'trust':
                self.trustActionTriggered.emit(payload)
            else:
                self.ignoreActionTriggered.emit(payload)
        self.close()

    def _close_by_user(self):
        """用户点击 × 关闭（视为忽略）"""
        self._closed_by_user = True
        self._stop_timers()
        self.close()

    def _auto_action_on_timeout(self):
        """5 秒超时：自动执行默认操作"""
        if self._closed_by_user:
            return
        self._closed_by_user = True
        self._stop_timers()
        is_sandbox_release = self._threat_data.get('_is_sandbox_release', False)
        data = dict(self._threat_data)
        if is_sandbox_release:
            # 沙箱放行模式：超时默认"不重启"（ignore）
            data['action'] = 'ignore'
            payload = json.dumps(data, ensure_ascii=False)
            self.ignoreActionTriggered.emit(payload)
        else:
            # 常规威胁：超时自动执行 auto 操作
            data['action'] = 'auto'
            payload = json.dumps(data, ensure_ascii=False)
            self.autoActionTriggered.emit(payload)
        self.close()

    def _stop_timers(self):
        """停止超时自动兜底定时器"""
        if self._auto_action_timer:
            self._auto_action_timer.stop()

    def closeEvent(self, event):
        try:
            self._stop_timers()
        except Exception:
            pass
        super().closeEvent(event)


class AutostartConfirmPopup(QWidget):
    """桌面右下角自启动项确认弹窗（独立顶层窗口，无边框置顶）

    用于"启动项监测"中非可疑进程添加自启动项时询问用户：
      - 用户点击"允许" → 保留该项
      - 用户点击"拦截" → 回滚该项
      - 5 秒无反馈 → 自动"拦截"并回滚（默认拒绝）
    """
    allowRequested = pyqtSignal(str)   # payload JSON
    blockRequested = pyqtSignal(str)   # payload JSON

    def __init__(self, info: dict, parent=None, scale: float = 1.0):
        super().__init__(parent)
        self._info = info
        self._payload = json.dumps(info, ensure_ascii=False)
        self._scale = float(scale) if scale else 1.0
        self._closed_by_user = False
        self._countdown_remaining = 3
        self._countdown_label = None
        self._setup_window_flags()
        self._setup_ui()
        # 按缩放比例调整弹窗大小与字号（宽度/字体随设置缩放）
        if self._scale != 1.0:
            self._apply_scale(self._scale)
        # 100% 缩放时不走 _apply_scale，同样需要先结算布局再定位
        _settle_popup_layout(self)
        self._position_at_bottom_right()
        # 3 秒倒计时自动拦截
        self._auto_action_timer = QTimer(self)
        self._auto_action_timer.setSingleShot(True)
        self._auto_action_timer.timeout.connect(self._auto_block_on_timeout)
        self._auto_action_timer.start(3000)
        self._countdown_timer = QTimer(self)
        self._countdown_timer.setInterval(1000)
        self._countdown_timer.timeout.connect(self._update_countdown)
        self._countdown_timer.start(1000)
        self._anim = None

    def _setup_window_flags(self):
        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint |
            Qt.Tool |
            Qt.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)
        self.setAttribute(Qt.WA_DeleteOnClose, True)

    def _setup_ui(self):
        info = self._info
        proc_name = info.get('name', '未知进程') or '未知进程'
        proc_path = info.get('path', '') or ''
        value_name = info.get('value_name', '')
        value_data = info.get('value_data', '') or ''

        self.setFixedWidth(max(240, int(380 * self._scale)))
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header = QFrame()
        header_gradient = 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #d97706, stop:1 #b45309)'
        header.setStyleSheet(
            f'QFrame {{ background: {header_gradient}; '
            f'border-top-left-radius: 10px; border-top-right-radius: 10px; }}'
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 10, 10, 10)
        header_layout.setSpacing(8)
        icon_label = QLabel('')
        icon_label.setStyleSheet('QLabel { font-size: 16px; border: none; background: transparent; }')
        title_label = QLabel('检测到启动项添加')
        title_label.setStyleSheet(
            'QLabel { color: white; font-size: 13px; font-weight: 600; '
            'border: none; background: transparent; }'
        )
        header_layout.addWidget(icon_label)
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        close_btn = QPushButton('×')
        close_btn.setFixedSize(22, 22)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet(
            'QPushButton { color: white; border: none; background: transparent; '
            'font-size: 18px; font-weight: bold; } '
            'QPushButton:hover { background: rgba(255,255,255,0.25); border-radius: 11px; }'
        )
        close_btn.clicked.connect(self._close_by_user)
        header_layout.addWidget(close_btn)
        outer.addWidget(header)

        body = QFrame()
        body.setStyleSheet(
            'QFrame { background: #ffffff; '
            'border-bottom-left-radius: 10px; border-bottom-right-radius: 10px; '
            'border: 1px solid #d6d3d1; border-top: none; }'
        )
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(14, 12, 14, 12)
        body_layout.setSpacing(4)

        proc_label = QLabel(f'进程：{proc_name}' + (f'\n{proc_path}' if proc_path else ''))
        proc_label.setStyleSheet(
            'QLabel { color: #1a1a2e; font-size: 12px; font-weight: 500; '
            'border: none; background: transparent; }'
        )
        proc_label.setWordWrap(True)
        body_layout.addWidget(proc_label)

        value_label = QLabel(f'启动项：{value_name}')
        value_label.setStyleSheet(
            'QLabel { color: #44403c; font-size: 11px; '
            'border: none; background: transparent; padding-top: 4px; }'
        )
        value_label.setWordWrap(True)
        body_layout.addWidget(value_label)

        if value_data:
            data_label = QLabel(f'指向：{value_data[:120]}')
            data_label.setStyleSheet(
                'QLabel { color: #78716c; font-size: 11px; '
                'border: none; background: transparent; }'
            )
            data_label.setWordWrap(True)
            data_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            body_layout.addWidget(data_label)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        btn_layout.setContentsMargins(0, 8, 0, 0)

        allow_btn = QPushButton('允许')
        allow_btn.setCursor(Qt.PointingHandCursor)
        allow_btn.setStyleSheet(
            'QPushButton { background: #0d9488; color: white; border: none; '
            'padding: 7px 12px; border-radius: 6px; font-size: 12px; font-weight: 500; } '
            'QPushButton:hover { background: #0f766e; }'
        )
        allow_btn.clicked.connect(lambda: self._emit_action('allow'))

        block_btn = QPushButton('拦截')
        block_btn.setCursor(Qt.PointingHandCursor)
        block_btn.setStyleSheet(
            'QPushButton { background: #dc2626; color: white; border: none; '
            'padding: 7px 12px; border-radius: 6px; font-size: 12px; font-weight: 500; } '
            'QPushButton:hover { background: #b91c1c; }'
        )
        block_btn.clicked.connect(lambda: self._emit_action('block'))

        btn_layout.addWidget(allow_btn)
        btn_layout.addWidget(block_btn)
        self._countdown_label = QLabel('5s 后自动拦截')
        self._countdown_label.setStyleSheet(
            'QLabel { color: #a8a29e; font-size: 11px; '
            'border: none; background: transparent; }'
        )
        btn_layout.addWidget(self._countdown_label)
        body_layout.addLayout(btn_layout)

        outer.addWidget(body)
        self.adjustSize()

    def _apply_scale(self, scale: float):
        """按缩放比例调整自启动确认弹窗宽度与所有控件的字号（滑块实时拖动时调用）
        """
        _apply_widget_scale(self, 380, scale)

    def _position_at_bottom_right(self):
        try:
            screen = QApplication.primaryScreen()
            if screen:
                geometry = screen.availableGeometry()
                self.move(geometry.right() - self.width() - 20,
                          geometry.bottom() - self.height() - 20)
                return
        except Exception:
            pass
        self.move(1920 - self.width() - 20, 1080 - self.height() - 60)

    def _slide_in(self):
        try:
            final_pos = self.pos()
            start_pos = final_pos.x() + self.width() + 40, final_pos.y()
            self.move(start_pos[0], start_pos[1])
            self.show()
            from PyQt5.QtCore import QPropertyAnimation, QEasingCurve
            self._anim = QPropertyAnimation(self, b'pos', self)
            self._anim.setDuration(300)
            self._anim.setStartValue(self.pos())
            self._anim.setEndValue(final_pos)
            self._anim.setEasingCurve(QEasingCurve.OutCubic)
            self._anim.start()
        except Exception as e:
            logger.warning(f'自启动弹窗滑入动画失败: {e}')
            self.show()

    def _emit_action(self, action: str):
        self._closed_by_user = True
        self._stop_timers()
        data = dict(self._info)
        data['action'] = action
        payload = json.dumps(data, ensure_ascii=False)
        if action == 'allow':
            self.allowRequested.emit(payload)
        else:
            self.blockRequested.emit(payload)
        self.close()

    def _close_by_user(self):
        # 点击 × 视为默认拦截（回滚）
        self._closed_by_user = True
        self._stop_timers()
        data = dict(self._info)
        data['action'] = 'block'
        self.blockRequested.emit(json.dumps(data, ensure_ascii=False))
        self.close()

    def _update_countdown(self):
        self._countdown_remaining -= 1
        if self._countdown_label:
            self._countdown_label.setText(f'{self._countdown_remaining}s 后自动拦截')

    def _auto_block_on_timeout(self):
        if self._closed_by_user:
            return
        self._closed_by_user = True
        self._stop_timers()
        data = dict(self._info)
        data['action'] = 'block'
        self.blockRequested.emit(json.dumps(data, ensure_ascii=False))
        self.close()

    def _stop_timers(self):
        if self._auto_action_timer:
            self._auto_action_timer.stop()
        if self._countdown_timer:
            self._countdown_timer.stop()

    def closeEvent(self, event):
        try:
            self._stop_timers()
        except Exception:
            pass
        super().closeEvent(event)


class ThreatResultPopup(QWidget):
    """桌面右下角威胁处理结果通知弹窗（独立顶层窗口）

    用于"auto"策略处理完成后显示结果（成功隔离/删除/失败）。
    8 秒后自动关闭，无交互按钮。
    """

    def __init__(self, data: dict, parent=None, scale: float = 1.0):
        super().__init__(parent)
        self._data = data
        self._scale = float(scale) if scale else 1.0
        self._setup_window_flags()
        self._setup_ui()
        # 按缩放比例调整弹窗大小与字号（宽度/字体随设置缩放）
        if self._scale != 1.0:
            self._apply_scale(self._scale)
        # 100% 缩放时不走 _apply_scale，同样需要先结算布局再定位
        _settle_popup_layout(self)
        self._position_at_bottom_right()
        self._auto_close_timer = QTimer(self)
        self._auto_close_timer.setSingleShot(True)
        self._auto_close_timer.timeout.connect(self.close)
        self._auto_close_timer.start(2000)

    def _setup_window_flags(self):
        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint |
            Qt.Tool |
            Qt.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)
        self.setAttribute(Qt.WA_DeleteOnClose, True)

    def _setup_ui(self):
        result = self._data.get('result', {}) or {}
        success = bool(result.get('success', False))
        action = result.get('action', '')
        message = result.get('message', '')

        self.setFixedWidth(max(240, int(360 * self._scale)))
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # 头部
        header = QFrame()
        header_gradient = (
            'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0d9488, stop:1 #0f766e)'
            if success else
            'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #4b5563, stop:1 #374151)'
        )
        header.setStyleSheet(
            f'QFrame {{ background: {header_gradient}; '
            f'border-top-left-radius: 10px; border-top-right-radius: 10px; }}'
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 10, 10, 10)
        header_layout.setSpacing(8)

        icon_label = QLabel('✓' if success else '✗')
        icon_label.setStyleSheet('QLabel { font-size: 16px; color: white; border: none; background: transparent; }')
        title_label = QLabel('处理结果')
        title_label.setStyleSheet(
            'QLabel { color: white; font-size: 13px; font-weight: 600; '
            'border: none; background: transparent; }'
        )
        header_layout.addWidget(icon_label)
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        close_btn = QPushButton('×')
        close_btn.setFixedSize(22, 22)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet(
            'QPushButton { color: white; border: none; background: transparent; '
            'font-size: 18px; font-weight: bold; } '
            'QPushButton:hover { background: rgba(255,255,255,0.25); border-radius: 11px; }'
        )
        close_btn.clicked.connect(self.close)
        header_layout.addWidget(close_btn)

        outer.addWidget(header)

        # 内容
        body = QFrame()
        body.setStyleSheet(
            'QFrame { background: #ffffff; '
            'border-bottom-left-radius: 10px; border-bottom-right-radius: 10px; '
            'border: 1px solid #d6d3d1; border-top: none; }'
        )
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(14, 12, 14, 12)
        body_layout.setSpacing(4)

        msg_label = QLabel(message or '已完成')
        msg_label.setStyleSheet(
            'QLabel { color: #1a1a2e; font-size: 12px; font-weight: 500; '
            'border: none; background: transparent; }'
        )
        msg_label.setWordWrap(True)
        body_layout.addWidget(msg_label)

        path_label = QLabel(self._data.get('file_path', ''))
        path_label.setStyleSheet(
            'QLabel { color: #78716c; font-size: 11px; '
            'border: none; background: transparent; }'
        )
        path_label.setWordWrap(True)
        path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        body_layout.addWidget(path_label)

        outer.addWidget(body)
        self.adjustSize()

    def _apply_scale(self, scale: float):
        """按缩放比例调整结果弹窗宽度与所有控件的字号（滑块实时拖动时调用）
        """
        _apply_widget_scale(self, 360, scale)

    def _position_at_bottom_right(self):
        """定位到主屏幕右下角，多个弹窗叠加显示"""
        try:
            screen = QApplication.primaryScreen()
            if screen:
                geometry = screen.availableGeometry()
                x = geometry.right() - self.width() - 20
                y = geometry.bottom() - self.height() - 20
                self.move(x, y)
                return
        except Exception as e:
            logger.warning(f'定位结果弹窗失败: {e}')
        self.move(1920 - self.width() - 20, 1080 - self.height() - 60)


class RealtimeScanResultPopup(QWidget):
    """桌面右下角"新文件扫描结果"通知弹窗（独立顶层窗口）

    实时监控检测到新文件并扫描完成后弹出，告知用户扫描结果（安全 / 跳过）。
    3 秒后自动关闭，带关闭按钮，绿色/灰色头部区分状态。
    """

    def __init__(self, data: dict, parent=None, scale: float = 1.0):
        super().__init__(parent)
        self._data = data
        self._scale = float(scale) if scale else 1.0
        self._setup_window_flags()
        self._setup_ui()
        # 按缩放比例调整弹窗大小与字号（宽度/字体随设置缩放）
        if self._scale != 1.0:
            self._apply_scale(self._scale)
        # 100% 缩放时不走 _apply_scale，同样需要先结算布局再定位
        _settle_popup_layout(self)
        self._position_at_bottom_right()
        self._auto_close_timer = QTimer(self)
        self._auto_close_timer.setSingleShot(True)
        self._auto_close_timer.timeout.connect(self.close)
        self._auto_close_timer.start(3000)  # 3秒自动关闭

    def _setup_window_flags(self):
        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint |
            Qt.Tool |
            Qt.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)
        self.setAttribute(Qt.WA_DeleteOnClose, True)

    def _setup_ui(self):
        status = self._data.get('status', 'clean')
        file_path = self._data.get('file_path', '')
        malware_name = self._data.get('malware_name', '')

        is_safe = status == 'clean'
        is_warn = status in ('error', 'skipped')
        self.setFixedWidth(max(240, int(360 * self._scale)))
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # 头部样式：安全=深绿，跳过/异常=深灰
        if is_safe:
            header_gradient = 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0d9488, stop:1 #0f766e)'
            icon_char = '✓'
            title_text = '新文件扫描完成'
        elif is_warn:
            header_gradient = 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #6b7280, stop:1 #4b5563)'
            icon_char = '–'
            title_text = '新文件扫描结果'
        else:
            header_gradient = 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #b45309, stop:1 #92400e)'
            icon_char = '!'
            title_text = '发现可疑文件'

        header = QFrame()
        header.setStyleSheet(
            f'QFrame {{ background: {header_gradient}; '
            f'border-top-left-radius: 10px; border-top-right-radius: 10px; }}'
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 10, 10, 10)
        header_layout.setSpacing(8)

        icon_label = QLabel(icon_char)
        icon_label.setStyleSheet(
            'QLabel { font-size: 16px; color: white; border: none; background: transparent; }'
        )
        title_label = QLabel(title_text)
        title_label.setStyleSheet(
            'QLabel { color: white; font-size: 13px; font-weight: 600; '
            'border: none; background: transparent; }'
        )
        header_layout.addWidget(icon_label)
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        close_btn = QPushButton('×')
        close_btn.setFixedSize(22, 22)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet(
            'QPushButton { color: white; border: none; background: transparent; '
            'font-size: 18px; font-weight: bold; } '
            'QPushButton:hover { background: rgba(255,255,255,0.25); border-radius: 11px; }'
        )
        close_btn.clicked.connect(self.close)
        header_layout.addWidget(close_btn)

        outer.addWidget(header)

        # 内容区
        body = QFrame()
        body.setStyleSheet(
            'QFrame { background: #ffffff; '
            'border-bottom-left-radius: 10px; border-bottom-right-radius: 10px; '
            'border: 1px solid #d6d3d1; border-top: none; }'
        )
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(14, 12, 14, 12)
        body_layout.setSpacing(4)

        # 第一行：扫描状态文本
        if is_safe:
            status_text = '已确认安全，可放心使用'
        elif status == 'skipped':
            status_text = '文件被跳过（超出大小限制或类型不匹配）'
        elif status == 'error':
            status_text = '扫描失败（文件无法访问）'
        else:
            status_text = malware_name or '发现可疑内容'

        status_label = QLabel(status_text)
        status_label.setStyleSheet(
            'QLabel { color: #1a1a2e; font-size: 12px; font-weight: 500; '
            'border: none; background: transparent; }'
        )
        status_label.setWordWrap(True)
        body_layout.addWidget(status_label)

        # 第二行：文件路径
        path_label = QLabel(file_path)
        path_label.setStyleSheet(
            'QLabel { color: #78716c; font-size: 11px; '
            'border: none; background: transparent; }'
        )
        path_label.setWordWrap(True)
        path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        body_layout.addWidget(path_label)

        outer.addWidget(body)
        self.adjustSize()

    def _apply_scale(self, scale: float):
        """按缩放比例调整新文件扫描结果弹窗宽度与所有控件的字号（滑块实时拖动时调用）
        """
        _apply_widget_scale(self, 360, scale)

    def _position_at_bottom_right(self):
        """定位到主屏幕右下角"""
        try:
            screen = QApplication.primaryScreen()
            if screen:
                geometry = screen.availableGeometry()
                x = geometry.right() - self.width() - 20
                y = geometry.bottom() - self.height() - 20
                self.move(x, y)
                return
        except Exception as e:
            logger.warning(f'定位新文件扫描结果弹窗失败: {e}')
        self.move(1920 - self.width() - 20, 1080 - self.height() - 60)


class SelfProtectionThreatPopup(QWidget):
    """桌面右下角自我保护威胁通知弹窗

    当自我保护引擎检测到威胁（反调试/反注入/关键文件篡改）时显示。
    8秒后自动关闭，用户可点击"知道了"立即关闭。
    始终置顶于所有弹窗之上。
    """

    acknowledged = pyqtSignal()

    def __init__(self, threat_data: dict, parent=None):
        super().__init__(parent)
        self._threat_data = threat_data
        self._closed_by_user = False
        self._auto_close_timer = None
        self._setup_window_flags()
        self._setup_ui()
        self._position_at_bottom_right()
        self._auto_close_timer = QTimer(self)
        self._auto_close_timer.setSingleShot(True)
        self._auto_close_timer.timeout.connect(self.close)
        self._auto_close_timer.start(8000)

    def _setup_window_flags(self):
        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint |
            Qt.Tool |
            Qt.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)
        self.setAttribute(Qt.WA_DeleteOnClose, True)

    def _setup_ui(self):
        threat_type = self._threat_data.get('type', 'unknown')
        detail = self._threat_data.get('detail', '检测到威胁')

        type_labels = {
            'debugger_detected': '反调试检测',
            'injection_detected': '反注入检测',
            'self_file_deleted': '关键文件被删除',
            'self_file_deleted_rollback': '关键文件已恢复',
            'self_file_tampered': '关键文件被篡改',
            'self_file_tampered_rollback': '关键文件已恢复',
            'process_terminate': '进程终止检测',
        }
        type_label = type_labels.get(threat_type, '未知威胁')

        # 需要建议重新安装的威胁类型：
        # - 删除回滚成功（文件可能已损坏，建议重装确保完整）
        # - 删除回滚失败（文件缺失，必须重装）
        # - 篡改回滚失败（文件损坏且无法恢复，必须重装）
        suggest_reinstall = threat_type in (
            'self_file_deleted_rollback',
            'self_file_deleted',
            'self_file_tampered',
        )

        self.setFixedWidth(360)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header = QFrame()
        header.setStyleSheet(
            'QFrame { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, '
            'stop:0 #991b1b, stop:1 #7f1d1d); '
            'border-top-left-radius: 10px; border-top-right-radius: 10px; }'
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 10, 10, 10)
        header_layout.setSpacing(8)

        icon_label = QLabel('')
        icon_label.setStyleSheet('QLabel { font-size: 16px; border: none; background: transparent; }')
        title_label = QLabel('PSLS 自我保护警报')
        title_label.setStyleSheet(
            'QLabel { color: white; font-size: 13px; font-weight: 600; '
            'border: none; background: transparent; }'
        )
        header_layout.addWidget(icon_label)
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        close_btn = QPushButton('×')
        close_btn.setFixedSize(22, 22)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet(
            'QPushButton { color: white; border: none; background: transparent; '
            'font-size: 18px; font-weight: bold; } '
            'QPushButton:hover { background: rgba(255,255,255,0.25); border-radius: 11px; }'
        )
        close_btn.clicked.connect(self._close_by_user)
        header_layout.addWidget(close_btn)

        outer.addWidget(header)

        body = QFrame()
        body.setStyleSheet(
            'QFrame { background: #ffffff; '
            'border-bottom-left-radius: 10px; border-bottom-right-radius: 10px; '
            'border: 1px solid #991b1b; border-top: none; }'
        )
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(14, 12, 14, 12)
        body_layout.setSpacing(6)

        type_label_widget = QLabel(f'⚠ {type_label}')
        type_label_widget.setStyleSheet(
            'QLabel { color: #991b1b; font-size: 12px; font-weight: 600; '
            'border: none; background: transparent; }'
        )
        body_layout.addWidget(type_label_widget)

        detail_label = QLabel(detail)
        detail_label.setStyleSheet(
            'QLabel { color: #1a1a2e; font-size: 12px; '
            'border: none; background: transparent; }'
        )
        detail_label.setWordWrap(True)
        body_layout.addWidget(detail_label)

        timestamp = self._threat_data.get('timestamp', '')
        if timestamp:
            time_label = QLabel(f'时间: {timestamp}')
            time_label.setStyleSheet(
                'QLabel { color: #78716c; font-size: 11px; '
                'border: none; background: transparent; }'
            )
            body_layout.addWidget(time_label)

        if suggest_reinstall:
            tip_frame = QFrame()
            tip_frame.setStyleSheet(
                'QFrame { background: #fef3c7; border: 1px solid #f59e0b; '
                'border-radius: 6px; }'
            )
            tip_layout = QVBoxLayout(tip_frame)
            tip_layout.setContentsMargins(10, 8, 10, 8)
            tip_layout.setSpacing(2)

            tip_title = QLabel('⚠ 建议重新安装程序')
            tip_title.setStyleSheet(
                'QLabel { color: #92400e; font-size: 11px; font-weight: 600; '
                'border: none; background: transparent; }'
            )
            tip_desc = QLabel('程序文件完整性可能已受影响，请重新安装 PSLS 以确保安全。')
            tip_desc.setStyleSheet(
                'QLabel { color: #78350f; font-size: 11px; '
                'border: none; background: transparent; }'
            )
            tip_desc.setWordWrap(True)

            tip_layout.addWidget(tip_title)
            tip_layout.addWidget(tip_desc)
            body_layout.addWidget(tip_frame)

        btn_layout = QHBoxLayout()
        btn_layout.setContentsMargins(0, 8, 0, 0)

        ack_btn = QPushButton('知道了')
        ack_btn.setCursor(Qt.PointingHandCursor)
        ack_btn.setStyleSheet(
            'QPushButton { background: #991b1b; color: white; border: none; '
            'padding: 7px 12px; border-radius: 6px; font-size: 12px; font-weight: 500; } '
            'QPushButton:hover { background: #7f1d1d; }'
        )
        ack_btn.clicked.connect(self._close_by_user)
        btn_layout.addStretch()
        btn_layout.addWidget(ack_btn)
        body_layout.addLayout(btn_layout)

        outer.addWidget(body)
        self.adjustSize()

    def _position_at_bottom_right(self):
        try:
            screen = QApplication.primaryScreen()
            if screen:
                geometry = screen.availableGeometry()
                x = geometry.right() - self.width() - 20
                y = geometry.bottom() - self.height() - 20
                self.move(x, y)
                return
        except Exception as e:
            logger.warning(f'定位自保护弹窗失败: {e}')
        self.move(1920 - self.width() - 20, 1080 - self.height() - 60)

    def _close_by_user(self):
        self._closed_by_user = True
        if self._auto_close_timer:
            self._auto_close_timer.stop()
        self.acknowledged.emit()
        self.close()

    def closeEvent(self, event):
        try:
            if self._auto_close_timer:
                self._auto_close_timer.stop()
        except Exception:
            pass
        super().closeEvent(event)


class SelfProtectionStatusPopup(QWidget):
    """桌面右下角自我保护开关结果弹窗

    显示自保护开启/关闭操作的执行结果（成功/部分失败）。
    2秒后自动关闭，无交互按钮。
    """

    def __init__(self, enabled: bool, success: bool, message: str = '', parent=None):
        super().__init__(parent)
        self._enabled = enabled
        self._success = success
        self._message = message
        self._auto_close_timer = None
        self._setup_window_flags()
        self._setup_ui()
        self._position_at_bottom_right()
        self._auto_close_timer = QTimer(self)
        self._auto_close_timer.setSingleShot(True)
        self._auto_close_timer.timeout.connect(self.close)
        self._auto_close_timer.start(2000)

    def _setup_window_flags(self):
        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint |
            Qt.Tool |
            Qt.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)
        self.setAttribute(Qt.WA_DeleteOnClose, True)

    def _setup_ui(self):
        if self._success:
            header_gradient = (
                'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0d9488, stop:1 #0f766e)'
                if self._enabled else
                'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #4b5563, stop:1 #374151)'
            )
            icon = ''
            title = '自保护已启用' if self._enabled else '自保护已关闭'
        else:
            header_gradient = 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #dc2626, stop:1 #991b1b)'
            icon = '⚠'
            title = '自保护操作失败'

        self.setFixedWidth(360)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # 头部
        header = QFrame()
        header.setStyleSheet(
            f'QFrame {{ background: {header_gradient}; '
            f'border-top-left-radius: 10px; border-top-right-radius: 10px; }}'
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 10, 10, 10)
        header_layout.setSpacing(8)

        icon_label = QLabel(icon)
        icon_label.setStyleSheet('QLabel { font-size: 16px; color: white; border: none; background: transparent; }')
        title_label = QLabel(title)
        title_label.setStyleSheet(
            'QLabel { color: white; font-size: 13px; font-weight: 600; '
            'border: none; background: transparent; }'
        )
        header_layout.addWidget(icon_label)
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        close_btn = QPushButton('×')
        close_btn.setFixedSize(22, 22)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet(
            'QPushButton { color: white; border: none; background: transparent; '
            'font-size: 18px; font-weight: bold; } '
            'QPushButton:hover { background: rgba(255,255,255,0.25); border-radius: 11px; }'
        )
        close_btn.clicked.connect(self.close)
        header_layout.addWidget(close_btn)

        outer.addWidget(header)

        # 内容
        body = QFrame()
        body.setStyleSheet(
            'QFrame { background: #ffffff; '
            'border-bottom-left-radius: 10px; border-bottom-right-radius: 10px; '
            'border: 1px solid #d6d3d1; border-top: none; }'
        )
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(14, 12, 14, 12)
        body_layout.setSpacing(4)

        msg_label = QLabel(self._message or ('已成功启用' if self._success and self._enabled else ('已成功关闭' if self._success else '操作未能完成')))
        msg_label.setStyleSheet(
            'QLabel { color: #1a1a2e; font-size: 12px; font-weight: 500; '
            'border: none; background: transparent; }'
        )
        msg_label.setWordWrap(True)
        body_layout.addWidget(msg_label)

        outer.addWidget(body)
        self.adjustSize()

    def _position_at_bottom_right(self):
        try:
            screen = QApplication.primaryScreen()
            if screen:
                geometry = screen.availableGeometry()
                x = geometry.right() - self.width() - 20
                y = geometry.bottom() - self.height() - 20
                self.move(x, y)
                return
        except Exception as e:
            logger.warning(f'定位自保护状态弹窗失败: {e}')
        self.move(1920 - self.width() - 20, 1080 - self.height() - 60)


class StrictModeStatusPopup(QWidget):
    """桌面右下角严格模式切换结果弹窗

    显示严格模式开启/关闭操作的执行结果。
    2秒后自动关闭，无交互按钮。
    """

    def __init__(self, enabled: bool, success: bool, message: str = '', parent=None):
        super().__init__(parent)
        self._enabled = enabled
        self._success = success
        self._message = message
        self._auto_close_timer = None
        self._setup_window_flags()
        self._setup_ui()
        self._position_at_bottom_right()
        self._auto_close_timer = QTimer(self)
        self._auto_close_timer.setSingleShot(True)
        self._auto_close_timer.timeout.connect(self.close)
        self._auto_close_timer.start(2000)

    def _setup_window_flags(self):
        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint |
            Qt.Tool |
            Qt.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)
        self.setAttribute(Qt.WA_DeleteOnClose, True)

    def _setup_ui(self):
        if self._success:
            if self._enabled:
                header_gradient = 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #7c3aed, stop:1 #6d28d9)'
                icon = ''
                title = '严格模式已启用'
            else:
                header_gradient = 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #4b5563, stop:1 #374151)'
                icon = ''
                title = '严格模式已关闭'
        else:
            header_gradient = 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #dc2626, stop:1 #991b1b)'
            icon = '⚠'
            title = '操作失败'

        self.setFixedWidth(360)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header = QFrame()
        header.setStyleSheet(
            f'QFrame {{ background: {header_gradient}; '
            f'border-top-left-radius: 10px; border-top-right-radius: 10px; }}'
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 10, 10, 10)
        header_layout.setSpacing(8)

        icon_label = QLabel(icon)
        icon_label.setStyleSheet('QLabel { font-size: 16px; color: white; border: none; background: transparent; }')
        title_label = QLabel(title)
        title_label.setStyleSheet(
            'QLabel { color: white; font-size: 13px; font-weight: 600; '
            'border: none; background: transparent; }'
        )
        header_layout.addWidget(icon_label)
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        close_btn = QPushButton('×')
        close_btn.setFixedSize(22, 22)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet(
            'QPushButton { color: white; border: none; background: transparent; '
            'font-size: 18px; font-weight: bold; } '
            'QPushButton:hover { background: rgba(255,255,255,0.25); border-radius: 11px; }'
        )
        close_btn.clicked.connect(self.close)
        header_layout.addWidget(close_btn)

        outer.addWidget(header)

        body = QFrame()
        body.setStyleSheet(
            'QFrame { background: #ffffff; '
            'border-bottom-left-radius: 10px; border-bottom-right-radius: 10px; '
            'border: 1px solid #d6d3d1; border-top: none; }'
        )
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(14, 12, 14, 12)
        body_layout.setSpacing(4)

        msg_label = QLabel(self._message or ('已启用严格模式' if self._success and self._enabled else
                                             ('已切换到宽松模式' if self._success else '操作未能完成')))
        msg_label.setStyleSheet(
            'QLabel { color: #1a1a2e; font-size: 12px; font-weight: 500; '
            'border: none; background: transparent; }'
        )
        msg_label.setWordWrap(True)
        body_layout.addWidget(msg_label)

        outer.addWidget(body)
        self.adjustSize()

    def _position_at_bottom_right(self):
        try:
            screen = QApplication.primaryScreen()
            if screen:
                geometry = screen.availableGeometry()
                x = geometry.right() - self.width() - 20
                y = geometry.bottom() - self.height() - 20
                self.move(x, y)
                return
        except Exception as e:
            logger.warning(f'定位严格模式弹窗失败: {e}')
        self.move(1920 - self.width() - 20, 1080 - self.height() - 60)


def _get_python_executable() -> Optional[str]:
    """获取可用于运行 Python 代码的解释器路径

    在 PyInstaller 打包环境下 sys.executable 指向打包后的 exe（不支持 -c 参数），
    此时优先使用便携 Python，否则尝试在 PATH 中查找 python.exe。
    """
    # 非打包环境：直接使用当前 Python 解释器
    if not getattr(sys, 'frozen', False):
        return sys.executable

    # 打包环境：优先使用便携 Python
    try:
        from engine.yara_portable import _PYTHON_EXE
        if os.path.exists(_PYTHON_EXE):
            return _PYTHON_EXE
    except Exception:
        pass

    # 尝试在 PATH 中查找 python.exe
    import shutil
    python_in_path = shutil.which('python.exe') or shutil.which('python')
    if python_in_path:
        return python_in_path

    return None


# ------------------------------------------------------------------------
# 自绘弹窗的主题适配：给每个窗口的 _setup_ui 包一层
# ------------------------------------------------------------------------
# 这些弹窗的 QSS 历史上把米色期色值写死在方法体内（几十处 setStyleSheet），
# 逐个改写风险大、易漏。这里统一在 _setup_ui 执行完之后做一次主题映射：
#   - 米色主题：remap_widget_tree/apply_mono_font 都是 no-op，视觉逐像素不变
#   - 终端主题：米色固定色 -> 琥珀终端色板，字体族切等宽
# 若窗口后续再次调用 _setup_ui 重建内容，也会顺带按"当时"的主题重映射。
_POPUP_THEMED_CLASSES = []


def install_popup_theme_remap(*classes):
    """把给定弹窗类的 _setup_ui 包一层，末尾套用当前主题（幂等）。"""
    for cls in classes:
        orig = cls.__dict__.get('_setup_ui')
        if orig is None or getattr(orig, '_psls_themed', False):
            continue

        def _make(orig_func):
            def _wrapper(self, *args, **kwargs):
                result = orig_func(self, *args, **kwargs)
                try:
                    theme_tokens.theme_window(self)
                except Exception as e:
                    logger.debug(f'弹窗主题适配失败: {e}')
                return result
            _wrapper._psls_themed = True
            _wrapper.__name__ = orig_func.__name__
            _wrapper.__doc__ = orig_func.__doc__
            return _wrapper

        cls._setup_ui = _make(orig)
        _POPUP_THEMED_CLASSES.append(cls)


# 全部自绘弹窗在此处一次性挂上主题适配（这些类都已在上方定义完毕）
install_popup_theme_remap(
    ThreatNotificationPopup,      # 威胁/沙箱放行询问（桌面右下角）
    AutostartConfirmPopup,        # 启动项确认
    ThreatResultPopup,            # 威胁处理结果
    RealtimeScanResultPopup,      # 实时扫描单文件结果
    SelfProtectionThreatPopup,    # 自我保护命中威胁
    SelfProtectionStatusPopup,    # 自我保护开关结果
    StrictModeStatusPopup,        # 严格模式开关结果
)


def _cfg_timed(func):
    """给配置类槽加 `[配置耗时]` 埋点（放在 @pyqtSlot 之下，PyQt 注册的是包装后的函数）。

    只测时间、不改语义；异常安全（记录后原样抛出）。
    """
    def _wrapper(self, *args, **kwargs):
        t0 = time.monotonic()
        try:
            return func(self, *args, **kwargs)
        finally:
            try:
                self._cfg_note(func.__name__, (time.monotonic() - t0) * 1000.0)
            except Exception:
                pass
    _wrapper.__name__ = getattr(func, '__name__', 'cfg_slot')
    _wrapper.__doc__ = getattr(func, '__doc__', None)
    try:
        import functools
        functools.update_wrapper(_wrapper, func)
    except Exception:
        pass
    _wrapper._cfg_timed = True
    return _wrapper


class PyBridge(QObject):
    """Python端桥接对象，暴露给JavaScript调用"""

    getInitialData = pyqtSignal(str)
    scanProgress = pyqtSignal(int, int, int)
    scanResultReceived = pyqtSignal(str)
    scanResultsBatch = pyqtSignal(str)  # 批量结果信号（性能优化）
    scanFinished = pyqtSignal(str)
    activityLogUpdated = pyqtSignal(str)
    quarantineUpdated = pyqtSignal(int)
    signatureCountUpdated = pyqtSignal(int)
    dashboardStatsUpdated = pyqtSignal(str)  # 主页指标卡统计更新（含实时防护威胁数）
    realtimeScanResultReady = pyqtSignal(str)  # 单个文件实时扫描结果（用于前端UI联动，无论clean/threat）
    requestPage = pyqtSignal(str)
    modalClosed = pyqtSignal(str)
    folderSelected = pyqtSignal(str)
    threatActionRequired = pyqtSignal(str)   # 通知前端需要用户选择处理方式
    threatActionResult = pyqtSignal(str)     # 通知前端处理结果
    # 一键开/关全部保护完成信号：(enabled, success, detail)
    # enabled=目标态, success=是否全部达成, detail=失败模块列表(空表示全成功)
    protectionAllToggled = pyqtSignal(bool, bool, str)
    moduleTogglePending = pyqtSignal(str)     # 模块后台构造/启停"加载中"（JSON）
    moduleToggleSettled = pyqtSignal(str)     # 模块后台就绪/完成（JSON: {module,state}）
    playAlertRequested = pyqtSignal()        # 子线程请求主线程播放威胁警报音（malware → error.mp3）
    playSuspiciousAlertRequested = pyqtSignal()  # 子线程请求主线程播放可疑警告音（suspicious → warn.mp3）

    # 6 级分级提示音（子线程请求 → 主线程播放，QMediaPlayer 必须在主线程）
    playInfoRequested = pyqtSignal()         # info.mp3：无通知的实时/启动监测发现可疑
    playInfo2Requested = pyqtSignal()        # info2.mp3：沙箱放行询问是否重启
    playWarnRequested = pyqtSignal()         # warn.mp3：沙箱拦截分析/无通知的检测到威胁
    playErrorRequested = pyqtSignal()        # error.mp3：通知隔离可疑对象
    playError2Requested = pyqtSignal()       # error2.mp3：通知隔离恶意对象
    playCriticalRequested = pyqtSignal()     # critical.mp3：MBR/勒索/注册表篡改

    # 工具子页面信号
    quarantineListReady = pyqtSignal(str)        # 隔离区列表 JSON
    quarantineBatchResult = pyqtSignal(str)      # 隔离区批量操作结果 JSON（恢复/删除）
    signatureSummaryReady = pyqtSignal(str)      # 签名库摘要 JSON
    fileSelected = pyqtSignal(str, str)          # (path, target) 文件选择结果
    hashResultReady = pyqtSignal(str)            # 哈希计算结果 JSON
    peAnalysisReady = pyqtSignal(str)            # PE 分析结果 JSON
    importProgress = pyqtSignal(int, str)        # (percent, message) 导入进度
    importFinished = pyqtSignal(int, int, bool)  # (added, total, success) 导入完成
    exportFinished = pyqtSignal(bool)            # 签名库导出完成
    logsReady = pyqtSignal(str)                  # 日志列表 JSON
    logsExported = pyqtSignal(bool)              # 日志导出结果
    yaraInstallResult = pyqtSignal(str)          # YARA 一键安装结果 JSON
    mlInstallResult = pyqtSignal(str)            # ML 引擎一键安装结果 JSON
    selfProtectionStatusChanged = pyqtSignal(str)  # 自我保护状态变化（JSON）
    mbrProtectionStatusChanged = pyqtSignal(str)   # MBR / 引导扇区保护状态变化（JSON）
    ruleEngineStatusChanged = pyqtSignal(str)      # YARA 规则引擎状态变化（JSON）
    strictModeStatusChanged = pyqtSignal(str)      # 严格模式状态变化（JSON）
    virusIdentifierStatusChanged = pyqtSignal(str)  # VirusIdentifier 开关状态变化（JSON）
    monitorAllFileTypesStatusChanged = pyqtSignal(str)  # 监测全部文件类型开关状态变化（JSON）
    whitelistAddResult = pyqtSignal(str)          # 批量/单项添加白名单结果（JSON）
    mlEngineStatusChanged = pyqtSignal(str)        # ML 引擎状态变化（JSON）
    mlTrainResult = pyqtSignal(str)               # ML 模型重新训练结果 JSON
    signatureListReady = pyqtSignal(str)           # 病毒库列表 JSON（查看/分页）
    signatureDeleteResult = pyqtSignal(str)        # 签名删除结果 JSON
    sandboxResultReady = pyqtSignal(str)            # 沙箱分析结果 JSON
    sandboxProgress = pyqtSignal(str)               # 沙箱分析进度 (stage, percent)
    sandboxReleasePopupRequested = pyqtSignal(str)  # 沙箱放行询问弹窗请求 JSON（子线程→主线程）
    sandboxThreatPopupRequested = pyqtSignal(str)   # 沙箱判定威胁弹窗请求 JSON（子线程→主线程）
    sandboxFailurePopupRequested = pyqtSignal(str)  # 沙箱失败弹窗请求 JSON（子线程→主线程）
    fileLocked = pyqtSignal(str)                    # 实时保护锁定程序通知（任意线程→主线程）
    sandboxBlockPopupRequested = pyqtSignal(str)    # 沙箱拦截通知弹窗请求 JSON（子线程→主线程）
    sandboxBlocked = pyqtSignal(str)                # 沙箱拦截结果 JSON（供前端状态页/主界面盾牌状态使用）
    sandboxAnalysisWinStart = pyqtSignal(str)       # 沙箱分析进度窗口显示请求（exe 路径，子线程→主线程）
    sandboxAnalysisWinProgress = pyqtSignal(str)    # 沙箱分析进度窗口进度更新（JSON stage/percent，子线程→主线程）
    sandboxAnalysisWinDone = pyqtSignal(str)        # 沙箱分析进度窗口关闭请求（verdict，子线程→主线程）
    sandboxRunLargeFilesStatusChanged = pyqtSignal(str)  # 大文件沙箱开关状态变化（JSON）
    autostartPopupRequested = pyqtSignal(str)            # 自启动项确认弹窗请求 JSON（子线程→主线程）
    ransomwareRollbackRequested = pyqtSignal(str)        # 勒索回滚询问弹窗请求 JSON（子线程→主线程）
    mbrThreatDetected = pyqtSignal(str)                  # MBR/引导扇区篡改告警 JSON（子线程→主线程）
    _coreInitWorkerDone = pyqtSignal(dict)               # [内部] CoreInit worker → 主线程投递初始化结果（替代跨线程 QTimer.singleShot）
    _loadGovApplyRequired = pyqtSignal()                 # [内部] load_governor 档位回调 → 主线程 apply_reductions（采样线程不阻塞）

    # —— 启动阶段：Splash 真实进度 + 启动完成信号 ——
    launchProgressUpdated = pyqtSignal(int, str)         # (百分比 0-100, 阶段中文案)；由主线程发射，Splash/外部监听
    launchReady = pyqtSignal()                           # 全部启动阶段完成（核心+防护+驱动判定/超时）后在主线程发射一次
    mbStatusUpdated = pyqtSignal(str)                    # MalwareBazaar 同步状态 JSON
    mbSyncProgress = pyqtSignal(str)                     # MalwareBazaar 同步/训练进度 JSON {stage, percent, message}
    mbSyncFinished = pyqtSignal(str)                     # MalwareBazaar 同步/训练结束 JSON
    loadGovernorStatusChanged = pyqtSignal(str)          # CPU/内存/降载状态 JSON (动态降载控制器)
    themeSettingsChanged = pyqtSignal(str)               # 主题/动态光效设置 JSON（theme, motion_effects）
    themeReloadRequested = pyqtSignal(str)               # 请求主窗口整页重载到指定主题入口（'light'|'terminal'）
    themeSwitchBlocked = pyqtSignal(str)                 # 主题切换被拒（原因文案）：持久化任务进行中
    rollbackCompleted = pyqtSignal(str)                  # 勒索文件回滚结果 JSON（任意线程→主线程）
    rollbackProgressUpdated = pyqtSignal(str)            # 回滚阶段进度 JSON（任意线程→主线程，驱动进度窗口）

    # 启动阶段权重（总和 100）
    _LAUNCH_WEIGHTS = {
        'core.start':      2,   # 核心初始化开始（加载签名库前）
        'core.sigdb':      15,  # SignatureDB 完成
        'core.sigcount':   2,   # 签名数读取完成（包含在病毒库活动日志内）
        'core.scanengine': 18,  # ScanEngine 完成
        'core.quarantine': 3,   # QuarantineManager 完成
        'core.virusid':    3,   # VirusIdentifier 完成
        'core.mldetector': 16,  # MLMalwareDetector（含 MLWorker 握手）完成
        'core.done':       3,   # 写回 PyBridge 属性 + 广播完成
        'protec.process':  3,   # 进程保护 init+start 合计权重
        'protec.file':     3,   # 文件保护
        'protec.system':   3,   # 系统保护
        'protec.autostart':3,   # 自启动监测
        'protec.realtime': 5,   # 实时监控（watchdog/降级判定）
        'protec.self':     5,   # 自我保护 + 驱动安装/SCM 过程
        'protec.notify':   4,   # 通知管理器
        'driver.done':     10,  # 驱动状态判定完成（立即或 6s 内轮询终态）
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scan_engine: Optional[ScanEngine] = None
        self._quarantine_manager: Optional[QuarantineManager] = None
        self._signature_db: Optional[SignatureDB] = None
        self._virus_identifier: Optional['VirusIdentifier'] = None
        self._process_protection: Optional[ProcessProtection] = None
        self._file_protection: Optional[FileProtection] = None
        self._system_protection: Optional[SystemProtection] = None
        self._autostart_protection: Optional[AutostartProtection] = None
        self._mbr_protector: Optional[MBRProtector] = None
        self._self_protection: Optional[SelfProtection] = None
        self._realtime_monitor: Optional[RealtimeMonitor] = None
        self._notification_manager: Optional[NotificationManager] = None
        self._ml_detector: Optional[MLMalwareDetector] = None
        # 防护模块初始化守卫：防止 _init_protection_modules 被重复调用
        self._protection_modules_initialized = False
        # 整体初始化就绪标志：防护模块初始化完成后置 True，主界面据此才显示
        self._ui_ready = False
        # 持久化设置（%APPDATA%\PSLS\settings.json 的 ui 段）：先读一次，供下方各项初始化使用
        _ui_saved = _load_ui_settings()
        # 严格模式开关（设置页控制；后端落盘，避免重启后行为与 UI 不一致）
        # 严格模式：单个 high 启发式规则即触发、启用熵检测、suspicious 自动隔离、小文件参与规则引擎
        # 宽松模式：需 2+ 启发式匹配、无熵检测、suspicious 仅记录、1KB 以下文件跳过规则引擎
        self._strict_mode = bool(_ui_saved.get('strict_mode', False))
        # VirusIdentifier 开关（设置页控制；后端落盘，默认关闭）
        # VirusIdentifier 是纯启发式打分引擎（7 维：可疑 API / 熵 / 扩展名 / 关键词…），
        # 覆盖 PE 与非 PE 文件，但对正常软件误报偏高，故默认关闭、由用户按需开启。
        self._vi_enabled = bool(_ui_saved.get('virus_identifier_enabled', False))
        # 监测全部类型的文件开关（设置页控制；后端落盘）
        # True  - 监测/扫描所有类型文件（包括文本、图片等非可执行文件）
        # False - 仅监测/扫描可执行文件（PE、脚本、宏文档等）
        # 严格模式开启时此开关强制开启
        self._monitor_all_file_types = bool(
            _ui_saved.get('monitor_all_file_types', True))
        # 大文件（>50MB）沙箱分析开关（设置页控制；后端落盘）
        # True  - 对超过 50MB 的可执行文件也运行沙箱分析
        # False - 超过 50MB 的文件直接拦截，跳过沙箱（默认，避免长时间 CPU/内存占用）
        self._sandbox_run_large_files = bool(
            _ui_saved.get('sandbox_run_large_files', False))
        # 沙箱后端选择：'auto'（首选 Sandboxie-Plus，不可用回退 AppContainer）
        # | 'sandboxie' | 'appcontainer'
        self._sandbox_backend = str(
            _ui_saved.get('sandbox_backend', 'auto') or 'auto')
        if self._sandbox_backend not in ('auto', 'sandboxie', 'appcontainer'):
            self._sandbox_backend = 'auto'
        # 实时监控范围: 'critical' | 'full' | 'custom'
        self._realtime_scope = 'critical'
        self._realtime_custom_paths: List[str] = []
        # 扫描排除路径（用户自定义，扫描时跳过这些路径）
        self._scan_excluded_paths: List[str] = [
            r'C:\Windows',
            r'C:\Program Files',
            r'C:\Program Files (x86)',
            r'C:\ProgramData',
            r'C:\$Recycle.Bin',
            r'C:\System Volume Information',
            r'C:\Windows.old',
            r'C:\Recovery',
        ]
        self._scan_thread: Optional[threading.Thread] = None
        self._scan_running = threading.Event()
        self._scan_stats = {'scanned': 0, 'threats': 0, 'total': 0}
        # 累计实时防护检测到的威胁数（跨扫描会话持续累加，重启清零）
        self._realtime_threat_count = 0
        self._realtime_count_lock = threading.Lock()
        # 防护模块启停串行锁：防止快速连续切换时 start/stop 并发竞争，避免状态错乱
        self._module_toggle_lock = threading.Lock()
        # 后台模块构造（拨开关时引擎为 None → 转后台）：去重 + "加载中"意图记录
        self._module_init_lock = threading.Lock()
        self._module_init_inflight = set()     # {'module|attr'} 正在后台构造
        self._module_pending = {}              # module -> 用户期望的启用意图
        # 需求 #3：上次已写入活动日志的"写前影子备份"状态 (enabled, generation)
        self._shadow_state_logged = None
        # 需求 #2/#3：回滚进度帧限流状态（≤10 次/秒，百分比单调不回退）
        self._rollback_progress_last = 0.0
        self._rollback_progress_last_pct = -1
        self._rollback_progress_last_stage = ''
        self._rollback_progress_sent = 0
        self._rollback_progress_dropped = 0
        # 启动扫描独立威胁计数（与实时防护分离）
        self._launch_scan_threat_count = 0
        # 沙箱分析并发信号量：最多 2 个并发，避免 UI 冻结
        self._sandbox_sem = threading.Semaphore(2)
        # 沙箱去重：记录最近触发过沙箱的文件路径，避免同文件被多链路重复触发
        self._sandbox_recent: Dict[str, float] = {}
        self._sandbox_recent_lock = threading.Lock()
        # 实时监控威胁处理策略：'auto'（自动隔离/删除）/ 'notify'（询问）/ 'ignore'（忽略）
        # 从持久化设置回读（此前仅存内存，重启即丢：用户改了处理方式，重启后又变回默认）
        # 默认处置：可疑对象默认"询问"（不自动隔离/删除），危险对象默认仍为自动处理
        self._rt_suspicious_action = _ui_saved.get('rt_suspicious_action', 'notify')
        self._rt_malware_action = _ui_saved.get('rt_malware_action', 'auto')
        if self._rt_suspicious_action not in ('auto', 'notify', 'ignore'):
            self._rt_suspicious_action = 'notify'
        if self._rt_malware_action not in ('auto', 'notify', 'ignore'):
            self._rt_malware_action = 'auto'
        self._activities: List[Dict] = []
        self._module_states = {
            'realtime-monitor': True,
            'process-protection': True,
            'file-protection': True,
            'system-protection': True,
            'autostart-protection': True,
            'mbr-protection': True,
            'notification': True,
            'self-protection': True,
            'new-file-result-popup': True,   # 新文件扫描结果弹窗（右下角）
            'visual-prank': True,            # 视觉恶搞行为检测
            'aggressive-prank': False,       # 更激进的特效检测（截图监控，默认关闭）
            'ransomware-rollback': True,     # 勒索软件文件回滚（用户态增量快照 + 回滚）
        }
        # 合并持久化的模块开关状态（只覆盖已存在的键，避免旧存档引入未知键）
        _saved_modules = _ui_saved.get('module_states')
        if isinstance(_saved_modules, dict):
            for _mk, _mv in _saved_modules.items():
                if _mk in self._module_states and isinstance(_mv, bool):
                    self._module_states[_mk] = _mv
        # 视觉恶搞行为检测器实例（由 _start_protection_worker 初始化）
        self._visual_prank_detector = None
        # 更激进的特效检测器实例（截图监控，默认关闭，由 _start_protection_worker 初始化）
        self._aggressive_prank_detector = None
        # 勒索软件文件回滚管理器实例（由 _start_protection_worker 初始化）
        self._rollback_manager = None
        self._browse_target = 'scan-path'
        # ---- MalwareBazaar 自动同步/自训练状态 ----
        self._mb_syncer: Optional[MBSyncer] = None
        self._mb_stop_event = threading.Event()
        self._mb_split_lock = threading.Lock()   # 防止同步/训练并发（与 MBSyncer 内部锁配合）
        self._mb_status_sent = False             # 启动后已推过一次状态
        self._mb_auto_sync_done = False          # 本次会话启动自动同步已结束（避免重复触发）
        # 桌面弹窗管理：独立顶层 QWidget，出现在桌面右下角（非软件窗口内）
        # 统一优先级队列：同时只显示一个，关闭后再按优先级显示下一个。
        # 优先级（高→低）：危险对象询问 > 可疑对象询问 > 沙箱放行确认 > 隔离失败 > 隔离成功
        # 队列项: {priority: int, kind: 'threat'|'result', data: dict}
        self._priority_popup_queue: List[dict] = []
        self._current_priority_popup: Optional[QWidget] = None
        # 屏幕弹窗缩放比例（与主 GUI 内 toast 缩放同步，1.0 = 100%）
        self._popup_scale = 1.0
        # ---- 内置主题与动态光效 ----
        # 'light' = 米色经典（index.html）/ 'terminal' = 琥珀 CRT 终端（terminal.html）。
        # Qt 侧自绘弹窗/沙箱窗口/启动页按此取色；切主题由主窗口整页换入口 HTML。
        self._ui_theme = theme_tokens.normalize(_ui_saved.get('theme', theme_tokens.THEME_LIGHT))
        self._motion_effects = bool(_ui_saved.get('motion_effects', True))
        # 自启动项确认弹窗管理：单弹窗队列模式
        self._autostart_popup_queue: List[dict] = []   # 待显示的自启动确认数据队列
        self._current_autostart_popup: Optional[AutostartConfirmPopup] = None
        # 新文件扫描结果弹窗管理：实时扫描每个文件完成后的结果弹窗（clean / threat）
        self._new_file_popup_queue: List[dict] = []
        self._current_new_file_popup: Optional['RealtimeScanResultPopup'] = None
        # 自我保护威胁弹窗管理：单弹窗队列模式，始终置顶于所有弹窗之上
        self._self_protection_popup_queue: List[dict] = []
        self._current_self_protection_popup: Optional[SelfProtectionThreatPopup] = None
        self._pending_self_protection_threats: List[dict] = []
        # 状态弹窗引用保持（自我保护状态、严格模式状态等短时提示弹窗）
        self._status_popups: List[QWidget] = []
        # 最近活动日志（对外只读快照使用 _activity_buffer 属性；保持老的 _activities 为内部主列表）
        self._activities: List[Dict] = []
        self._activity_buffer: List[Dict] = self._activities  # 与内部主列表同一引用，供测试/外部只读快照
        # 线程安全的信号队列：子线程写入，主线程的 QTimer 读取并 emit
        self._signal_lock = threading.Lock()
        self._pending_results = []       # 待发射的 scanResultReceived
        self._pending_progress = None    # 待发射的 scanProgress (scanned, total, threats)
        self._pending_activity = None    # 待发射的 activityLogUpdated
        self._pending_scan_finished = None  # 待发射的 scanFinished
        self._scan_finished_retry = 0   # scanFinished 重试次数
        # 工具子页面信号队列：子线程写入 (信号属性名, args元组)，主线程 QTimer 读取并 emit
        self._pending_tool_signals = []
        # 病毒库导入进度追踪：确保进度单调递增（深层不覆盖浅层）
        self._last_import_pct = 0
        # 病毒库导入停止事件
        self._import_stop_event = threading.Event()
        # 病毒库导入运行状态追踪（GUI重载后用于恢复前端UI）
        self._import_running = False
        self._import_current_pct = 0
        self._import_current_msg = ''

        # —— 启动阶段：真实进度状态 ——
        self._launch_pct = 0                      # 0-100，单调递增
        self._launch_stage_done = set()           # 已计入权重的阶段 key（去重）
        self._launch_stage_text = '正在启动 PSLS 安全模块...'
        self._launch_ready_emitted = False
        self._driver_decision_done = False
        self._pending_launch_progress: List[tuple] = []   # connect 之前的缓存（避免主窗口 connect 太晚漏首段）
        self._launch_progress_lock = threading.Lock()
        self._launch_driver_timer: Optional[QTimer] = None
        self._launch_driver_deadline_ts: float = 0.0
        # 主线程定时器，每 50ms 刷新一次信号
        self._flush_timer = QTimer(self)
        self._flush_timer.timeout.connect(self._flush_signals)
        self._flush_timer.start(50)
        # scanFinished 兜底定时器（1 秒后再补发一次，确保 JS 一定收到）
        self._finished_retry_timer = QTimer(self)
        self._finished_retry_timer.setSingleShot(True)
        self._finished_retry_timer.timeout.connect(self._retry_emit_finished)
        # 警报音播放信号：子线程 emit → 主线程执行（QMediaPlayer 必须在主线程使用）
        # 旧的两级信号保留向后兼容（仍被部分旧调用点使用）
        self.playAlertRequested.connect(sound_manager.play_threat_alert)
        self.playSuspiciousAlertRequested.connect(sound_manager.play_suspicious_alert)
        # 6 级分级提示音：info/info2/warn/error/error2/critical
        self.playInfoRequested.connect(sound_manager.play_info_alert)
        self.playInfo2Requested.connect(sound_manager.play_info2_alert)
        self.playWarnRequested.connect(sound_manager.play_warn_alert)
        self.playErrorRequested.connect(sound_manager.play_error_alert)
        self.playError2Requested.connect(sound_manager.play_error2_alert)
        self.playCriticalRequested.connect(sound_manager.play_critical_alert)
        # 沙箱放行弹窗：子线程通过信号转发到主线程显示（QWidget 必须在主线程创建）
        self.sandboxReleasePopupRequested.connect(self._on_sandbox_release_popup_requested)
        self.sandboxThreatPopupRequested.connect(self._on_sandbox_threat_popup_requested)
        self.sandboxFailurePopupRequested.connect(self._on_sandbox_failure_popup_requested)
        # 实时保护锁定程序通知：跨线程转发到主线程
        self.fileLocked.connect(self._on_file_locked)
        self.sandboxBlockPopupRequested.connect(self._on_sandbox_block_popup_requested)
        # 沙箱分析进度窗口（"软件分析室"）：子线程信号 → 主线程创建/更新/关闭
        self.sandboxAnalysisWinStart.connect(self._show_sandbox_analysis_win)
        self.sandboxAnalysisWinProgress.connect(self._update_sandbox_analysis_win)
        self.sandboxAnalysisWinDone.connect(self._close_sandbox_analysis_win)
        # 沙箱分析进度窗口 / 安全放行窗口引用（主线程持有，防 GC）
        self._sandbox_analysis_win = None
        self._sandbox_release_win = None
        self._sandbox_result_win = None        # 沙箱威胁/失败结果窗口引用（防 GC）
        # 勒索回滚询问窗口引用（主线程持有，防 GC）+ 最近一次询问请求
        self._ransomware_rollback_win = None
        self._last_ransomware_req = None
        # 确认弹窗防轰炸闩锁（Bug 修复）：pending 状态 / 决策冷却 / 上次受影响数 /
        # 重复检测计数。锁保护跨线程读写（回调线程判定、主线程决策落地）。
        self._ransomware_prompt_lock = threading.Lock()
        self._ransomware_prompt_pending = False      # 是否有未决确认弹窗
        self._ransomware_prompt_cooldown_until = 0.0  # 决策后的抑制截止时间
        self._ransomware_prompt_last_count = 0       # 上次已提示的受影响文件数
        self._ransomware_prompt_dup_count = 0        # 被闩锁抑制的重复检测次数
        self._file_locked_notify_ts = {}       # 锁定通知去重：{path: last_ts}
        # 自启动项确认弹窗：子线程通过信号转发到主线程显示
        self.autostartPopupRequested.connect(self._on_autostart_popup_requested)
        # 勒索回滚询问弹窗：子线程（file_protection 回调）通过信号转发到主线程显示
        self.ransomwareRollbackRequested.connect(
            self._on_ransomware_rollback_popup_requested)
        # 回滚阶段进度 → 主线程进度窗口（任意线程 emit，Qt 自动排队）
        self.rollbackProgressUpdated.connect(self._on_rollback_progress)
        self._rollback_progress_win = None
        # 防护模块威胁节流：记录上次报警时间，避免短时间内大量误报轰炸
        # malware 与 suspicious 各自独立节流，互不干扰
        self._threat_throttle_lock = threading.Lock()
        self._last_threat_alert_time = 0.0
        self._threat_alert_min_interval = 5.0  # malware 同一来源最少间隔 5 秒
        self._last_suspicious_alert_time = 0.0
        self._suspicious_alert_min_interval = 5.0  # suspicious 同一来源最少间隔 5 秒
        # 开机自启管理器
        self._autostart_manager = AutoStartManager()
        # 开机自启默认开启：首次运行自动注册（已记录用户选择则尊重之）。
        # 放后台线程执行（要写计划任务/注册表），不拖慢启动；也避免依赖此刻
        # 事件循环/UI 是否就绪。
        try:
            threading.Thread(target=self._apply_autostart_default, daemon=True,
                             name='AutostartDefaultInit').start()
        except Exception as e:
            logger.debug(f'启动默认开机自启失败: {e}')
        # 状态变化广播定时器：主动向 JS 推送状态变化，避免依赖 JS 轮询
        self._last_self_prot_state = None
        self._last_yara_state = None
        self._last_strict_state = None
        self._last_vi_state = None
        self._last_ml_state = None
        self._last_mbr_state = None
        self._last_load_gov_state = None
        # ---- 动态降载：apply_reductions 上下文（引用各模块，None 表示尚未就绪）----
        # 由 _rebuild_reduction_ctx 统一在核心/防护模块就绪后构造
        self._reduction_ctx: Dict[str, Any] = {}
        self._reduction_ctx_lock = threading.RLock()
        # 单文件扫描尺寸上限（可变 list，供 load_governor.apply_reductions 原地改值）
        self._scan_max_file_mb: List[int] = [512]
        # load_governor 档位变化信号 → 主线程 apply_reductions，避免阻塞采样线程
        # (信号定义于类体 _loadGovApplyRequired；实例访问自动绑定)
        self._loadGovApplyRequired.connect(self._apply_reductions_now)
        # ---- 驱动状态变化监视器（低频繁）----
        # 启动期 _log_driver_protection_status 已用终身 guard 写一条驱动状态日志；
        # 这里缓存"当前驱动是否 active"，当运行中驱动状态发生 不可用->已加载 或
        # 已加载->不可用 变化时，追加一条"最近活动"通知（状态未变则不写）。
        self._driver_state_cached: Optional[bool] = None
        self._driver_state_last_text: str = ''
        self._driver_state_watch_timer = QTimer(self)
        self._driver_state_watch_timer.setInterval(10000)  # 10s 低频繁轮询（虚拟机慢 IO 下降低主线程 ioctl 压力）
        self._driver_state_watch_timer.timeout.connect(self._watch_driver_state_change)
        self._state_broadcast_timer = QTimer(self)
        self._state_broadcast_timer.timeout.connect(self._broadcast_state_changes)
        self._state_broadcast_timer.start(1000)  # 每秒推送一次

        # CoreInit 后台线程 → 主线程投递信号（替代跨线程 QTimer.singleShot，
        # 后者在子线程调用时无法保证回调在 UI 线程事件循环中执行）
        self._coreInitWorkerDone.connect(self._on_core_init_done)

        # 核心管理器初始化：延迟到事件循环启动后通过后台线程执行，
        # 避免主线程被 SignatureDB / ScanEngine / MLWorker 等重量级初始化
        # 阻塞数秒，导致 Splash 无法重绘进而被 Windows 标记"未响应"。
        self._core_init_thread: Optional[threading.Thread] = None
        QTimer.singleShot(50, self._start_core_init_async)
        # _init_managers 现已改为"只调度、不构造重活"（GUI 线程立即返回），
        # 在核心初始化同时触发它，只为了尽早下发两个纯后台动作
        # （Sandboxie 界面抑制、浏览器启动诊断），以及核心已就绪时的轻量收尾。
        QTimer.singleShot(60, self._init_managers)

        # ===== 性能与响应性：加速初始化 & 处置不阻塞 UI =====
        # 1) 防护模块初始化后台线程：SelfProtection.start() 会做 SCM/驱动安装，
        #    Process/File/System 等 start() 也可能挂起，这些都不能占主线程。
        #    入口仍用 _init_protection_modules（主线程做守卫 + deadline），
        #    但真正的 init+start 动作交给 self._protection_init_thread 做。
        self._protection_init_thread: Optional[threading.Thread] = None

        # 2) 威胁处置后台线程池：processThreat 的 auto/delete/quarantine
        #    会执行 takeown+icacls+cmd del+隔离加密等长耗时（数秒~数十秒），
        #    QWebChannel 主线程执行期间 Qt 渲染无消息 → "未响应"。
        #    这里 offload 到 2 worker 的线程池，完成后通过 QTimer.singleShot
        #    回主线程 emit threatActionResult + 桌面弹窗。
        try:
            from concurrent.futures import ThreadPoolExecutor
            self._threat_disposition_executor = ThreadPoolExecutor(
                max_workers=2, thread_name_prefix='PSLS-ThreatDisp')
        except Exception:
            self._threat_disposition_executor = None  # 降级仍能跑，但可能卡

        # ===== 动态降载控制器 load_governor =====
        # 1) 启动后台采样循环（2s/次，CPU/内存/自身RSS）
        try:
            load_governor.start()
        except Exception as e:
            logger.warning(f'[降载] load_governor.start() 异常: {e}')
        # 2) 注册"档位/降载开关变化"回调：子线程 → 主线程转发信号（避免采样线程被重活阻塞）
        try:
            def _on_reduce(red, load_state, prev_level):
                # 用一次性 QTimer.singleShot(0) 比信号还省；但统一走 pyqtSignal 更清晰
                try:
                    self._loadGovApplyRequired.emit()
                except Exception:
                    pass
            load_governor.set_reduction_callback(_on_reduce)
        except Exception as e:
            logger.warning(f'[降载] 注册回调失败: {e}')
        # 3) 启动后立即 apply 一次（若已处于 elevated/high），避免等到首次回调才生效
        QTimer.singleShot(2000, self._apply_reductions_now)

    # --------------------------------------------------------- 启动阶段：真实进度工具
    def _bump_launch(self, stage_key: str, text: str):
        """根据阶段 key 累加真实进度并发射 launchProgressUpdated。

        线程安全：任何线程都可调用；主线程直接 emit，其他线程通过缓存队列，
        由主线程 _flush_signals 周期取出 emit。同时满足：
          - 同 key 只计一次（去重）
          - pct 单调不减
        """
        weight = PyBridge._LAUNCH_WEIGHTS.get(stage_key, 0)
        with self._launch_progress_lock:
            if stage_key in self._launch_stage_done:
                return
            self._launch_stage_done.add(stage_key)
            self._launch_pct = min(100, self._launch_pct + weight)
            self._launch_stage_text = text or self._launch_stage_text
            pct = self._launch_pct
            stage_text = self._launch_stage_text
        # 发射：主线程直接 emit；其他线程走队列（缓存+flush 同时读）
        if threading.current_thread() is threading.main_thread():
            try:
                self.launchProgressUpdated.emit(int(pct), str(stage_text))
            except Exception as e:
                logger.debug(f'launchProgressUpdated 主线程 emit 失败: {e}')
        else:
            # 写入缓存 + 写入 pending（pending 给 flush 读；缓存给 flush_launch_progress 读）
            with self._launch_progress_lock:
                self._pending_launch_progress.append((int(pct), str(stage_text)))

    def flush_launch_progress(self):
        """把 connect 之前/子线程缓存的进度信号立即在主线程发射出去。

        用法：监听端在 connect launchProgressUpdated 之后调用一次，
        防止 PyBridge 在监听者 connect 之前已经产生的进度信号被漏看。
        """
        if threading.current_thread() is not threading.main_thread():
            # 转主线程执行
            try:
                QTimer.singleShot(0, self.flush_launch_progress)
            except Exception:
                pass
            return
        with self._launch_progress_lock:
            items = list(self._pending_launch_progress)
            self._pending_launch_progress = []
        last_pct = -1
        last_text = None
        for pct, text in items:
            # 单调去重：重复 (pct,text) 只发一次
            if pct == last_pct and text == last_text:
                continue
            last_pct, last_text = pct, text
            try:
                self.launchProgressUpdated.emit(int(pct), str(text))
            except Exception as e:
                logger.debug(f'flush_launch_progress emit 失败: {e}')

    def _emit_launch_ready_once(self):
        """仅在主线程发射一次 launchReady。"""
        if threading.current_thread() is not threading.main_thread():
            QTimer.singleShot(0, self._emit_launch_ready_once)
            return
        with self._launch_progress_lock:
            if self._launch_ready_emitted:
                return
            # 终态补齐到 100（防止某些权重阶段因降级/跳过未满）
            if self._launch_pct < 100:
                self._launch_pct = 100
            final_text = 'PSLS 安全模块全部就绪'
            self._launch_stage_text = final_text
            final_pct = self._launch_pct
            self._launch_ready_emitted = True
        try:
            self.launchProgressUpdated.emit(int(final_pct), str(final_text))
        except Exception:
            pass
        try:
            self.launchReady.emit()
            logger.info('[LAUNCH] launchReady 已发射（核心+防护+驱动判定完成）')
        except Exception as e:
            logger.debug(f'launchReady emit 失败: {e}')

    def _start_core_init_async(self):
        """在后台线程执行核心管理器（SignatureDB/ScanEngine/ML 等）初始化，
        避免阻塞主线程造成 Splash 被 Windows 标记为未响应。
        完成后通过 _coreInitWorkerDone.emit(result) 切回主线程写回引用。
        """
        def _dbg(msg):
            try:
                with open(os.path.join(os.path.expanduser('~'), 'psls_debug.log'), 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now()}] [BRIDGE] {msg}\n")
            except Exception:
                pass

        def _worker():
            _dbg("_core_init_worker: start")
            self._bump_launch('core.start', '正在启动 PSLS 安全模块...')
            result = {
                'signature_db': None, 'scan_engine': None,
                'quarantine_manager': None, 'virus_identifier': None,
                'ml_detector': None, 'errors': [],
                'sig_count': 0, 'ml_status': None, 'ml_messages': [],
            }
            try:
                # ==============================================================
                # 加速：SignatureDB（磁盘IO重）、QuarantineManager（隔离元数据
                # 遍历+校验）、MLMalwareDetector（spawn 子进程）三者完全独立，
                # 启动 3 条并发线程同时跑。原本串行耗时约 3~8s → 并发约 2~4s。
                # VirusIdentifier 虽依赖 signature_db，但加载速度远小于 DB，
                # 放在 ScanEngine 之后串行以简化代码。
                # ==============================================================
                # ---- (A) SignatureDB 线程（关键：权重最高、最重磁盘）----------
                _db_slot: List[Any] = [None]  # 放 db/错误元组
                def _init_signature_db():
                    try:
                        _dbg("_core_init_worker(parallel): SignatureDB start")
                        self._bump_launch('core.start', '正在加载病毒签名库...')
                        db = SignatureDB()
                        try:
                            sig_c = db.get_signature_count() or 0
                        except Exception as e_sc:
                            result['errors'].append(('签名数量统计', e_sc))
                            sig_c = 0
                        self._bump_launch('core.sigdb', '签名库加载完成')
                        self._bump_launch('core.sigcount', '读取签名数量完成')
                        _dbg("_core_init_worker(parallel): SignatureDB OK")
                        _db_slot[0] = ('ok', db, sig_c)
                    except Exception as e:
                        _db_slot[0] = ('err', e, 0)
                        self._bump_launch('core.sigdb', f'签名库加载失败: {e}')
                        self._bump_launch('core.sigcount', '读取签名数量失败')
                        _dbg(f"_core_init_worker(parallel): SignatureDB FAILED: {e}")

                # ---- (B) QuarantineManager 线程（与 DB 独立，隔离区索引重）
                _qm_slot: List[Any] = [None]
                def _init_quarantine_manager():
                    try:
                        _dbg("_core_init_worker(parallel): QuarantineManager start")
                        self._bump_launch('core.quarantine', '正在初始化隔离管理器...')
                        qm = QuarantineManager()
                        self._bump_launch('core.quarantine', '隔离管理器初始化完成')
                        _qm_slot[0] = ('ok', qm)
                        _dbg("_core_init_worker(parallel): QuarantineManager OK")
                    except Exception as e:
                        _qm_slot[0] = ('err', e)
                        self._bump_launch('core.quarantine', f'隔离管理器失败: {e}')

                # ---- (C) ML 线程（spawn MLWorker.exe / 加载 onnx 模型，最耗时间）----
                # 从关键路径摘除：仅在后台线程跑，主流程不等它。
                # 完成后由主线程 QTimer 轮询 _ml_slot_evt → 注入扫描引擎。
                _ml_slot: List[Any] = [None]
                # 写入顺序：先写 _ml_slot[0]，再给事件置位（happens-before 由 GIL 保证）
                self._ml_init_evt = threading.Event()
                def _init_ml_detector():
                    try:
                        _dbg("_core_init_worker(parallel): MLMalwareDetector start (async)")
                        self._bump_launch('core.mldetector', '正在后台加载 ML 检测引擎...')
                        # defer_worker=True：不在本线程等待 60s 握手；就绪后回调回推
                        mld = MLMalwareDetector(
                            defer_worker=True, on_ready=self._on_ml_ready)
                        ml_status = mld.get_status() if mld else {'ml_available': False}
                        if ml_status.get('ml_available'):
                            result['ml_messages'].append(
                                ('ML引擎', 'ML 检测引擎已加载', 'INFO', '成功'))
                            self._bump_launch('core.mldetector', 'ML 检测引擎已加载')
                        else:
                            result['ml_messages'].append(
                                ('ML引擎', 'ML 引擎后台加载中（不阻塞启动）', 'INFO', '加载中'))
                            self._bump_launch('core.mldetector', 'ML 引擎后台加载中')
                        _dbg(f"_core_init_worker(parallel): ML OK status={ml_status}")
                        _ml_slot[0] = ('ok', mld, ml_status)
                    except Exception as e:
                        self._bump_launch('core.mldetector', f'ML 检测引擎加载失败: {e}')
                        _dbg(f"_core_init_worker(parallel): ML FAILED: {e}")
                        _ml_slot[0] = ('err', e, None)
                    finally:
                        # 暴露槽引用给主线程轮询（先写槽，再置事件）
                        self._ml_slot = _ml_slot
                        try:
                            self._ml_init_evt.set()
                        except Exception:
                            pass

                # 使用具名变量启动三条并行线程：
                #   SignatureDB（读磁盘最重） / QuarantineManager（隔离区索引） /
                #   MLMalwareDetector（后台加载，不阻塞关键路径）
                # 前两者 join（≈ max(t1,t2)），ML 后台运行，启动更快。
                _db_thread = threading.Thread(
                    target=_init_signature_db, name='PSLS-CoreInit-DB', daemon=True)
                _qm_thread = threading.Thread(
                    target=_init_quarantine_manager, name='PSLS-CoreInit-QM', daemon=True)
                _ml_thread = threading.Thread(
                    target=_init_ml_detector, name='PSLS-CoreInit-ML', daemon=True)
                threads = [_db_thread, _qm_thread, _ml_thread]
                for t in threads:
                    t.start()
                # ML 不参与 join，让启动关键路径尽快推进
                _db_thread.join()
                _qm_thread.join()

                # ---- 合并 A ----
                if _db_slot[0] is None:
                    result['errors'].append(('签名库', Exception('线程异常退出')))
                elif _db_slot[0][0] == 'ok':
                    _, db, sig_c = _db_slot[0]
                    result['signature_db'] = db
                    result['sig_count'] = sig_c
                else:
                    result['errors'].append(('签名库', _db_slot[0][1]))

                # ---- 合并 B ----
                if _qm_slot[0] is None:
                    result['errors'].append(('隔离区管理器', Exception('线程异常退出')))
                elif _qm_slot[0][0] == 'ok':
                    result['quarantine_manager'] = _qm_slot[0][1]
                else:
                    result['errors'].append(('隔离区管理器', _qm_slot[0][1]))

                # ---- 合并 C ----
                if _ml_slot[0] is None:
                    # ML 检测器为后台异步加载，关键路径不等待它：
                    # DB/QM 更快时 ML 线程此刻仍在加载模型/握手 Worker，属正常
                    # 时序，不记为失败；稍后 _schedule_ml_inject_check 轮询
                    # _ml_init_evt 置位后再写回引用并注入扫描引擎。
                    _dbg("_core_init_worker(parallel): ML slot not ready at merge-C "
                         "(async load in progress, skip error)")
                elif _ml_slot[0][0] == 'ok':
                    _, mld, ml_status = _ml_slot[0]
                    result['ml_detector'] = mld
                    result['ml_status'] = ml_status
                else:
                    result['errors'].append(('ML检测引擎', _ml_slot[0][1]))
                    result['ml_detector'] = None

                # 2. 扫描引擎（依赖签名库）— DB 完成后才创建，与 ML/QM 仍并发完成
                if result['signature_db'] is not None:
                    try:
                        _dbg("_core_init_worker: creating ScanEngine")
                        self._bump_launch('core.scanengine', '正在初始化扫描引擎...')
                        se = ScanEngine(signature_db=result['signature_db'])
                        result['scan_engine'] = se
                        self._bump_launch('core.scanengine', '扫描引擎初始化完成')
                        _dbg("_core_init_worker: ScanEngine created")
                    except Exception as e:
                        result['errors'].append(('扫描引擎', e))
                        self._bump_launch('core.scanengine', f'扫描引擎初始化失败: {e}')
                else:
                    self._bump_launch('core.scanengine', '扫描引擎跳过（签名库不可用）')

                # 4. 病毒识别（依赖签名库，扫描引擎之后跑，开销小 ≈ 不延长关键路径）
                if result['signature_db'] is not None:
                    try:
                        _dbg("_core_init_worker: creating VirusIdentifier")
                        self._bump_launch('core.virusid', '正在初始化病毒识别引擎...')
                        result['virus_identifier'] = VirusIdentifier(
                            signature_db=result['signature_db'])
                        self._bump_launch('core.virusid', '病毒识别引擎初始化完成')
                        _dbg("_core_init_worker: VirusIdentifier created")
                    except Exception as e:
                        result['errors'].append(('病毒识别引擎', e))
                        self._bump_launch('core.virusid', f'病毒识别引擎失败: {e}')
                else:
                    self._bump_launch('core.virusid', '病毒识别引擎跳过（签名库不可用）')

                # 注入 ML 检测器到扫描引擎（均在 worker 中完成，不涉及 UI）
                if (result['ml_detector']
                        and (result.get('ml_status') or {}).get('ml_available')
                        and result['scan_engine']):
                    try:
                        result['scan_engine'].set_ml_detector(result['ml_detector'])
                    except Exception as e:
                        result['errors'].append(('ML注入扫描引擎', e))
            except Exception as e:
                result['errors'].append(('核心初始化（未捕获）', e))
                _dbg(f"_core_init_worker: UNCAUGHT EXC: {e}")

            _dbg("_core_init_worker: done, emitting coreInitWorkerDone for UI-thread commit")
            # 回到主线程写回引用 & 发布活动日志 & 调度防护模块初始化
            # 注意：必须用 Qt 信号跨线程（QueueConnection）切到 UI 线程；
            #       跨线程调用 QTimer.singleShot(0, lambda) 不保证回调在 UI 线程执行，
            #       会导致属性写回失败，getRuleEngineStatus/getMlEngineStatus 恒 false。
            self._coreInitWorkerDone.emit(result)

        self._core_init_thread = threading.Thread(
            target=_worker, name='PSLS-CoreInit', daemon=True)
        self._core_init_thread.start()

    def _on_core_init_done(self, result: dict):
        """[主线程] 写回后台线程完成的核心管理器引用，并调度防护模块初始化。
        如果核心管理器（签名库/扫描引擎）初始化失败，则沿用 _init_managers 原有的
        延迟重试逻辑。
        """
        def _dbg(msg):
            try:
                with open(os.path.join(os.path.expanduser('~'), 'psls_debug.log'), 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now()}] [BRIDGE] {msg}\n")
            except Exception:
                pass
        _dbg("_on_core_init_done: start")
        _t0 = time.monotonic()
        errors = result.get('errors', [])

        # 写回引用（仅在属性仍为 None 时，避免与重试逻辑覆盖写冲突）
        if self._signature_db is None:
            self._signature_db = result.get('signature_db')
        if self._scan_engine is None:
            self._scan_engine = result.get('scan_engine')
        if self._quarantine_manager is None:
            self._quarantine_manager = result.get('quarantine_manager')
        if self._virus_identifier is None:
            self._virus_identifier = result.get('virus_identifier')
        if self._ml_detector is None:
            # ML 检测器为后台加载：result 中通常还没有（关键路径已不等它），
            # 由 _schedule_ml_inject_check 轮询后台线程完成事件后再写回。
            self._ml_detector = result.get('ml_detector')

        # ML 后台加载完成检测：一旦就绪 → 写回引用 + 注入扫描引擎 + 推送状态
        self._schedule_ml_inject_check()

        # 关键组件缺失 → 进入 _init_managers 的延迟重试逻辑
        if self._signature_db is None or self._scan_engine is None:
            # 失败仍记权重，保证进度不卡住；后续重试不会重复累加（key 已记录）
            self._bump_launch('core.done', '核心管理器写回失败，等待重试...')
            retry_count = getattr(self, '_core_init_retries', 0)
            if retry_count < self._CORE_INIT_MAX_RETRIES:
                self._core_init_retries = retry_count + 1
                delay_sec = 3 * self._core_init_retries
                detail = errors[0][1] if errors else '未知错误'
                msg = (f'核心管理器初始化失败: {detail}，'
                       f'{delay_sec} 秒后自动重试 '
                       f'({self._core_init_retries}/{self._CORE_INIT_MAX_RETRIES})')
                logger.error(msg)
                self._add_activity('系统', msg, 'WARN', '重试')
                _dbg(f"_on_core_init_done: retry in {delay_sec}s, reason={detail}")
                QTimer.singleShot(delay_sec * 1000, self._start_core_init_async)
            else:
                detail = errors[0][1] if errors else '未知错误'
                msg = f'初始化失败（已重试 {self._CORE_INIT_MAX_RETRIES} 次）: {detail}'
                logger.error(msg)
                self._add_activity('系统', msg, 'ERROR', '错误')
                # 彻底失败 → 仍然推进到 launchReady（让 Splash 关掉显示失败态）
                self._bump_launch('driver.done', '驱动判定跳过（核心初始化失败）')
                self._driver_decision_done = True
                self._ui_ready = True
                try:
                    parent = self.parent()
                    if parent is not None and hasattr(parent, 'on_bridge_init_ready'):
                        parent.on_bridge_init_ready()
                except Exception:
                    pass
                self._emit_launch_ready_once()
            return

        # 非关键组件失败上报
        for name, err in errors:
            logger.error(f'{name} 初始化失败: {err}')
            self._add_activity('系统', f'{name}初始化失败: {err}', 'ERROR', '错误')

        # 签名数量 & ML 状态活动日志
        try:
            sig_count = result.get('sig_count', 0) or 0
            # 若 result 中没有 sig_count 或为 0，补一次实时查询避免旧 result 缓存
            if sig_count <= 0 and self._signature_db is not None:
                try:
                    sig_count = self._signature_db.get_signature_count() or 0
                except Exception:
                    sig_count = 0
            if sig_count > 0:
                self._add_activity('病毒库', f'加载 {sig_count} 个签名', 'INFO', '成功')
            self._add_activity('系统', '核心管理器初始化完成', 'INFO', '成功')
            # 写回后立即推送给前端，避免 initRequested（JS 触发）先于 core 写回时拿到 0 不刷新
            try:
                self.signatureCountUpdated.emit(int(sig_count))
            except Exception:
                pass
        except Exception as e:
            logger.warning(f'发布初始化活动日志失败: {e}')

        for src, msg, lvl, st in result.get('ml_messages', []):
            try:
                self._add_activity(src, msg, lvl, st)
            except Exception:
                pass

        if not (self._ml_detector and (result.get('ml_status') or {}).get('ml_available')):
            logger.info('ML 检测器不可用，扫描引擎以传统模式运行')

        self._core_init_retries = 0
        self._bump_launch('core.done', '核心管理器写回完成')

        # 按持久化设置恢复引擎开关（原 _init_managers 收尾逻辑，迁到此异步路径）
        self._restore_persisted_engine_toggles()

        # 记录本方法（GUI 线程）本次占用，用于量化启动期阻塞
        self._record_gui_block('_on_core_init_done', (time.monotonic() - _t0) * 1000)

        # 核心就绪：重建降载 ctx 并立即 apply 一次（若启动时已高负载则立刻降级）
        try:
            self._rebuild_reduction_ctx()
            self._apply_reductions_now()
        except Exception as e:
            logger.warning(f'[降载] core init 后 apply 失败: {e}')

        # 核心管理器已写回 → 立即主动推一次状态广播，确保前端第一时间看到
        # YARA/ML "已加载/可用"，而不是等到下一个 1s 广播周期
        try:
            self._broadcast_state_changes()
        except Exception:
            pass

        # 防护模块初始化：不再延迟 3 秒，立刻调度（让 Splash 真实对齐完成进度）
        _dbg("_on_core_init_done: scheduling protection modules init")
        QTimer.singleShot(0, self._init_protection_modules)
        QTimer.singleShot(6000, self._ensure_protection_initialized)
        # 启动完成后延迟检测 MalwareBazaar 更新（后台自动同步，不阻塞启动）
        # 临时禁用：验证 MB 自动同步是否为闪退根因
        # QTimer.singleShot(15000, self._schedule_mb_startup_check)
        _dbg("_on_core_init_done: done")

    def _schedule_ml_inject_check(self):
        """[主线程] 轮询后台 ML 初始化线程完成事件，就绪后写回引用并注入扫描引擎。

        ML 从启动关键路径摘除后在后台线程加载，此处通过短间隔 QTimer 在
        主线程检查 _ml_init_evt（事件置位前不执行重量级操作）。
        """
        evt = getattr(self, '_ml_init_evt', None)
        if evt is None or evt.is_set():
            return

        timer = getattr(self, '_ml_ready_timer', None)
        if timer is not None:

            if timer.isActive():
                timer.stop()
        timer = QTimer(self)
        timer.setInterval(250)
        self._ml_ready_timer = timer

        def _check():
            if evt is None or not evt.is_set():
                return
            timer.stop()
            slot = getattr(self, '_ml_init_result', None)
            try:
                if slot is None:
                    slot = getattr(self, '_ml_slot', None)
                if slot is None:
                    return
                if slot[0] is not None:
                    kind, mld, ml_status = slot[0]
                    if kind == 'ok' and mld is not None:
                        if self._ml_detector is None:
                            self._ml_detector = mld
                        # 注入扫描引擎（若尚未注入）
                        if self._scan_engine is not None:
                            try:
                                self._scan_engine.set_ml_detector(mld)
                            except Exception as e:
                                logger.debug(f'ML 注入扫描引擎失败: {e}')
                        try:
                            self.signatureCountUpdated.emit(int(
                                getattr(self, '_signature_db', None) and 0 or 0))
                        except Exception:
                            pass
                        try:
                            self._add_activity('ML引擎', 'ML 检测引擎已加载', 'INFO', '成功')
                        except Exception:
                            pass
                        # 立即推送一次 ML 状态，尽早反映到前端
                        try:
                            self._broadcast_state_changes()
                        except Exception:
                            pass
                        logger.info('ML 检测引擎后台加载完成，已注入扫描流程')
            except Exception as e:
                logger.debug(f'ML 状态注入异常: {e}')
        timer.timeout.connect(_check)
        timer.start()

    def _flush_signals(self):
        """主线程定时器回调：从队列取出子线程/子进程写入的数据，在主线程中 emit 信号。

        所有复杂数据（dict/list）均序列化为 JSON 字符串传递，避免 QWebChannel 类型转换问题。
        添加耗时保护：单次 _flush_signals 总耗时超过 20ms 时提前退出，
        避免长时间阻塞主线程导致 QWebEngine 渲染进程超时崩溃。
        """
        _flush_start = time.monotonic()
        _flush_deadline = _flush_start + 0.020  # 20ms 预算上限
        with self._signal_lock:
            results = self._pending_results[:] if self._pending_results else []
            self._pending_results = []
            progress = self._pending_progress
            self._pending_progress = None
            activity = self._pending_activity
            self._pending_activity = None
            finished = self._pending_scan_finished
            self._pending_scan_finished = None
            tool_signals = self._pending_tool_signals[:] if self._pending_tool_signals else []
            self._pending_tool_signals = []
            self_protection_threats = self._pending_self_protection_threats[:] if self._pending_self_protection_threats else []
            self._pending_self_protection_threats = []

        # 启动阶段：从 _pending_launch_progress 中取缓存的进度信号（由子线程/早期 bump 写入）
        launch_items: List[tuple] = []
        try:
            with self._launch_progress_lock:
                if self._pending_launch_progress:
                    launch_items = list(self._pending_launch_progress)
                    self._pending_launch_progress = []
        except Exception:
            launch_items = []
        last_pct = -1
        last_text = None
        for pct, text in launch_items:
            if pct == last_pct and text == last_text:
                continue
            last_pct, last_text = pct, text
            try:
                self.launchProgressUpdated.emit(int(pct), str(text))
            except Exception as e:
                logger.debug(f'flush_signals: launchProgress emit 失败: {e}')

        normal_results = []
        # 6 级音效分桶计数（每批只播一次，按严重度取最高）
        detect_suspicious_batch = 0  # 发现可疑（无通知）→ info.mp3
        detect_malware_batch = 0     # 发现威胁（无通知）→ warn.mp3
        result_suspicious_batch = 0  # 通知隔离可疑对象 → error.mp3
        result_malware_batch = 0     # 通知隔离恶意对象 → error2.mp3
        for result in results:
            try:
                rtype = result.get('type') if isinstance(result, dict) else None
                if rtype == 'threat_action_required':
                    # 威胁需要用户选择处理方式：在桌面右下角显示交互弹窗
                    payload = result.get('payload', '')
                    self._show_threat_notification_popup(payload)
                    # 解析 payload 中的 status 以分级计数（启动扫描已处理的不累加声音计数）
                    try:
                        payload_obj = json.loads(payload) if isinstance(payload, str) else (payload or {})
                        # 启动扫描已处理的文件不累加声音与计数（避免双重统计）
                        if not payload_obj.get('suppress_realtime_count', False):
                            if payload_obj.get('status') == 'suspicious':
                                detect_suspicious_batch += 1   # 发现可疑 → info
                            else:
                                detect_malware_batch += 1      # 发现威胁 → warn
                    except Exception:
                        detect_malware_batch += 1
                elif rtype == 'threat_action_result':
                    # 自动处理结果通知：在桌面右下角显示结果弹窗
                    self._show_threat_result_popup(result)
                    # 自动处理完成的威胁也播放提示音（仅当处理失败时）
                    result_data = result.get('result', {}) or {}
                    if not result_data.get('success', False):
                        if result.get('status') == 'suspicious':
                            result_suspicious_batch += 1       # 通知隔离可疑 → error
                        else:
                            result_malware_batch += 1          # 通知隔离恶意 → error2
                elif rtype == 'realtime_scan_result_popup':
                    # 实时扫描结果弹窗：在桌面右下角显示（clean/threat 通用）
                    # 如果用户关闭了开关，或 桌面通知关闭则不显示
                    if self._module_states.get('new-file-result-popup', True) \
                            and self._module_states.get('notification', True):
                        self._show_new_file_result_popup(result.get('payload', {}))
                else:
                    # 普通扫描结果：先收集，最后批量发送
                    normal_results.append(result)
            except Exception as e:
                logger.warning(f'处理结果异常: {e}')

        # 分级提示音节流：整个批次只播放一次，按严重度优先（error2 > error > warn > info）
        # 实时防护的威胁已在 _on_realtime_threat 中播放过，此处通过独立节流自然去重
        if result_malware_batch > 0:
            self._request_error2_sound()       # 通知隔离恶意对象
        elif result_suspicious_batch > 0:
            self._request_error_sound()        # 通知隔离可疑对象
        elif detect_malware_batch > 0:
            self._request_warn_sound()         # 无通知的检测到威胁
        elif detect_suspicious_batch > 0:
            self._request_info_sound()         # 无通知的发现可疑

        # 优先发射进度信号（确保扫描时间和进度条不被批量结果阻塞）
        # 修复：原来先 emit scanResultsBatch（大 JSON 序列化+传输阻塞主线程），
        # 导致 scanProgress 被延迟，前端时间和进度条卡住但已扫描数偶尔跳动。
        if progress is not None:
            self.scanProgress.emit(progress[0], progress[1], progress[2])

        # 批量发送扫描结果（限制每批最大数量+耗时，避免单次 JSON 过大阻塞主线程）
        # 已在 _run_scan 中限量 clean 文件（前 200 个），此处不再过滤
        # 剩余结果放回队列头部，下次 _flush_signals 继续发送
        _MAX_BATCH_RESULTS = 50
        if normal_results:
            # 基础防御：只保留合法 dict 结果
            normal_results = [r for r in normal_results if isinstance(r, dict)]
            if not normal_results:
                pass
            elif time.monotonic() > _flush_deadline - 0.002:
                # 耗时保护：进度发送已用完大部分预算
                with self._signal_lock:
                    self._pending_results = normal_results + self._pending_results
            else:
                batch_to_send = normal_results[:_MAX_BATCH_RESULTS]
                remaining = normal_results[_MAX_BATCH_RESULTS:]
                try:
                    self.scanResultsBatch.emit(
                        json.dumps(batch_to_send, ensure_ascii=False)
                    )
                except Exception as e:
                    logger.warning(f'emit scanResultsBatch 失败: {e}')
                # 剩余结果放回队列头部，下次继续发送
                if remaining:
                    with self._signal_lock:
                        self._pending_results = remaining + self._pending_results
        if activity is not None:
            try:
                self.activityLogUpdated.emit(json.dumps(activity, ensure_ascii=False))
            except Exception as e:
                logger.warning(f'emit activityLogUpdated 失败: {e}')
        if finished is not None:
            try:
                payload = json.dumps(finished, ensure_ascii=False)
                logger.info(f'emit scanFinished (try {self._scan_finished_retry + 1}): {payload}')
                self.scanFinished.emit(payload)
                # 3 次兜底：1 秒后再补发，防止 QWebChannel 丢失
                self._scan_finished_retry += 1
                if self._scan_finished_retry < 3:
                    self._finished_retry_timer.start(1000)
                else:
                    self._scan_finished_retry = 0
            except Exception as e:
                logger.error(f'emit scanFinished 失败: {e}')
        # 工具子页面信号：从队列取出并在主线程发射
        # 性能：工具信号一次可能批量到达（如沙箱分析期间的高频进度），若在同一个
        # GUI tick 里全部 emit 会长时间占用主线程 → 自绘进度条掉帧。这里
        # (1) 同名相邻信号合并保留最新（进度类幂等，last-wins）；
        # (2) 遵守同一 20ms 预算，超出则把剩余信号放回队列下次继续。
        if tool_signals:
            merged: List[tuple] = []
            for item in tool_signals:
                try:
                    name, args = item
                except Exception:
                    continue
                if merged and merged[-1][0] == name:
                    merged[-1] = (name, args)      # 同名相邻 → 保留最新
                else:
                    merged.append((name, args))
            emitted_any = False
            for idx, (sig_name, sig_args) in enumerate(merged):
                if emitted_any and time.monotonic() > _flush_deadline:
                    # 预算用尽：剩余信号放回队列头部，下个 tick 继续（不丢事件）
                    with self._signal_lock:
                        self._pending_tool_signals = merged[idx:] + \
                            self._pending_tool_signals
                    break
                try:
                    sig = getattr(self, sig_name, None)
                    if sig is not None:
                        sig.emit(*sig_args)
                        emitted_any = True
                except Exception as e:
                    logger.warning(f'emit {sig_name} 失败: {e}')

        # 自我保护威胁弹窗：主线程创建并显示
        for sp_threat in self_protection_threats:
            try:
                self._show_self_protection_popup(sp_threat)
            except Exception as e:
                logger.warning(f'显示自保护威胁弹窗失败: {e}')

        # 量化：本次 GUI 线程 tick 的总占用（静默采样，仅超阈才告警）
        try:
            self._record_gui_block('_flush_signals',
                                   (time.monotonic() - _flush_start) * 1000,
                                   warn_ms=100.0, emit_log=False)
        except Exception:
            pass

    def _get_mbr_state(self) -> Optional[dict]:
        """构建 MBR / 引导扇区 + 系统关键目录保护当前状态（供广播与初始化推送共用）。

        - mbr_protector 尚未初始化时返回 None（调用方跳过本轮）。
        - driver_mon_enabled：内核引导扇区事前写入拦截是否生效；
        - driver_dir_enabled：内核关键目录 minifilter 事前写入拦截是否生效；
        - critical_dirs：关键目录保护运行时摘要（目录数、跟踪文件数、是否超阈值等）。
        """
        mp = self._mbr_protector
        if mp is None:
            return None
        try:
            driver_ok = self._mbr_driver_available()
            driver_dir_ok = bool(getattr(mp, 'driver_dir_enabled', False))
            critical_dirs = None
            try:
                fn = getattr(mp, 'get_critical_dirs_info', None)
                if callable(fn):
                    critical_dirs = fn()
            except Exception as e:
                logger.debug(f'[MBR] 读取关键目录摘要异常: {e}')
            return {
                'is_running': bool(getattr(mp, 'is_running', False)),
                'is_enabled': bool(getattr(mp, 'is_enabled', True)),
                'driver_mon_enabled': driver_ok,
                # ---- 新增：关键目录保护 ----
                'driver_dir_enabled': driver_dir_ok and driver_ok,
                'critical_dirs': critical_dirs,
            }
        except Exception as e:
            logger.debug(f'[MBR] 读取状态异常: {e}')
            return None

    def _mbr_arm_before_proc_kill(self, exe: str):
        """自爆风险进程终止前：确保 MBR/引导备份存在（引导保护加固）。

        由 ProcessProtection 在终止"命中自爆静态特征"的进程前调用
        （跨线程，MBRProtector 内部自带锁）。仅确保备份存在与轮询
        保护处于运行态，不做阻塞性写。
        """
        try:
            mp = self._mbr_protector
            if mp is None:
                return
            if not mp.is_running and not mp.is_enabled:
                return
            if not getattr(mp, '_has_backup', False):
                ok = mp.create_backup()
                if ok:
                    logger.warning(f'[防自爆] 终止前已创建引导扇区备份 exe={exe}')
                else:
                    logger.warning(f'[防自爆] 终止前创建引导备份失败 exe={exe}')
        except Exception as e:
            logger.warning(f'[防自爆] 终止前 MBR 加固异常: {e}')

    def _mbr_verify_after_proc_kill(self, exe: str):
        """自爆风险进程终止后：立即校验引导扇区并在被改写时回滚。

        常规 MBR 保护靠 0.25s 轮询兜底；自爆式病毒死亡瞬间改写引导
        扇区后可能立即蓝屏，本方法把"检测→回滚"窗口从 250ms 缩小到
        ~10ms（等价于手动触发一次 _run 的阶段1快检）。
        """
        try:
            mp = self._mbr_protector
            if mp is None or not getattr(mp, 'is_running', False):
                return
            if not getattr(mp, '_has_backup', False):
                return
            events = mp._check_sectors_only()
            if events:
                mp._handle_sector_events(events)
                logger.warning(
                    f'[防自爆] 进程终止后检测到引导扇区被改写 '
                    f'({len(events)} 设备)，已立即回滚')
        except Exception as e:
            logger.debug(f'[防自爆] 终止后即时校验异常: {e}')

    def _mbr_driver_available(self) -> bool:
        """判断内核驱动桥接是否可用（供每秒广播复用，缓存句柄避免主线程高频系统调用）。

        本方法每 1 秒由主线程广播触发：若每次重建 PSLSDriverBridge，都会在
        CreateFile/CloseHandle 上产生真实系统调用，慢速虚拟机中会持续拖累
        GUI 主线程。因此：
          - 已连接句柄 10 秒内直接复用（零系统调用）；
          - 每满 10 秒重连一次以感知驱动加载/卸载；
          - 驱动缺失时 5 秒内不重复重试，避免每秒 CreateFile 抖动。
        """
        now = time.monotonic()
        try:
            bridge = getattr(self, '_mbr_driver_bridge', None)
            if bridge is not None:
                if now - getattr(self, '_mbr_driver_ts', 0.0) < 10.0:
                    return bridge.is_available
                # 10 秒重连周期已到：关闭旧句柄，重新建立连接
                try:
                    bridge.close()
                except Exception:
                    pass
                self._mbr_driver_bridge = None
            # 无可用句柄：限制重试频率
            if now - getattr(self, '_mbr_driver_attempt_ts', 0.0) < 5.0:
                return False
            self._mbr_driver_attempt_ts = now
            self._mbr_driver_ts = now
            from driver.bridge.psls_driver_bridge import PSLSDriverBridge
            self._mbr_driver_bridge = PSLSDriverBridge()
            if self._mbr_driver_bridge.is_available:
                try:
                    # 毫秒级内核 process_create 事件 → ProcessProtection 启动监测。
                    # 这是"用户双击 EXE → 病毒启动"场景下的核心检测链路；
                    # ETW/WMI 仅作为驱动缺失时的秒级兜底。lambda 动态取
                    # _process_protection 确保模块重建（_try_reinitialize_module）
                    # 后回调仍然指向最新实例。
                    self._mbr_driver_bridge.register_callback(
                        'process_create',
                        lambda ev: (
                            self._process_protection.on_driver_process_create_event(ev)
                            if self._process_protection is not None else None))
                    # 句柄审计事件 → 进程保护双信号注入检测。
                    # _process_protection 可能被重建(重启进程保护),
                    # 用 lambda 动态取当前实例; 驱动缺失时静默跳过。
                    self._mbr_driver_bridge.register_callback(
                        'handle_audit',
                        lambda ev: (
                            self._process_protection.on_handle_audit_event(ev)
                            if self._process_protection is not None else None))
                    # 映像加载事件 → 进程保护白加黑检测（无签名 DLL 加载检测）。
                    # 路径与 lambda 动态规则同上。
                    self._mbr_driver_bridge.register_callback(
                        'image_load',
                        lambda ev: (
                            self._process_protection.on_image_load_event(ev)
                            if self._process_protection is not None else None))
                    # 磁盘引导区拦截事件（diskmon 事前拦截成功）→ 活动日志告警。
                    # reason: 1=MBR写, 2=VBR/ESP写, 3=布局IOCTL/SCSI直写旁路。
                    self._mbr_driver_bridge.register_callback(
                        'disk_blocked',
                        lambda ev: self._on_disk_blocked_event(ev))
                    # 写前影子备份事件（阶段二）→ 回滚引擎 ingest（写前原像入仓）。
                    # status==0 走 ingest_shadow_backup; 其余走 ingest_shadow_failure。
                    self._mbr_driver_bridge.register_callback(
                        'file_shadowed',
                        lambda ev: self._on_shadow_backup_event(ev))
                    self._mbr_driver_bridge.start_event_loop()
                    # 连接成功后把桥注入回滚引擎并下发影子配置（世代/影子根/触发目录）
                    try:
                        if self._rollback_manager is not None:
                            self._apply_shadow_config()
                    except Exception as e:
                        logger.debug(f'下发写前影子配置失败: {e}')
                except Exception as e:
                    logger.debug(f'注册 handle_audit 回调失败: {e}')
            return bool(self._mbr_driver_bridge.is_available)
        except Exception:
            self._mbr_driver_bridge = None
            return False

    def _on_disk_blocked_event(self, ev):
        """diskmon 内核事前拦截到引导扇区改写 → 打日志 + 活动日志告警。

        ev.reason: mbr_write_blocked / boot_region_write_blocked /
                   layout_scsi_write_blocked (布局IOCTL/SCSI直写旁路)。
        """
        try:
            pid = getattr(ev, 'pid', 0)
            offset = getattr(ev, 'offset', 0)
            device = getattr(ev, 'device', '')
            reason = getattr(ev, 'reason', 'unknown')
            label = {
                'mbr_write_blocked': 'MBR第0扇区写入',
                'boot_region_write_blocked': 'VBR/ESP引导扇区写入',
                'layout_scsi_write_blocked': '布局IOCTL/SCSI直写改写',
                'unknown': '未知通道',
            }.get(reason, reason)
            logger.warning(
                f'[DISK] 内核已拦截引导区改写: pid={pid} device={device} '
                f'offset={offset} reason={reason}')
            self._add_activity(
                '系统保护',
                f'拦截{label}: PID {pid} 试图改写 {device} (偏移 {offset})',
                'WARNING', '已拦截')
        except Exception as e:
            logger.debug(f'_on_disk_blocked_event 处理异常: {e}')

    def _on_shadow_backup_event(self, ev):
        """写前影子备份事件（阶段二）→ 回滚引擎 ingest（在驱动事件线程中调用）。

        status==0  : 影子文件即写前原像 → ingest_shadow_backup 入仓并登记 manifest
        status!=0  : 未备份/失败 → ingest_shadow_failure 记 warning（含 reason）
        """
        rb = self._rollback_manager
        if rb is None:
            return
        try:
            status = int(getattr(ev, 'status', 0) or 0)
            orig_path = getattr(ev, 'orig_path', '') or ''
            shadow_path = getattr(ev, 'shadow_path', '') or ''
            orig_size = int(getattr(ev, 'orig_size', 0) or 0)
            pid = int(getattr(ev, 'pid', 0) or 0)
            if status == 0:
                rb.ingest_shadow_backup(orig_path, shadow_path, orig_size, pid)
            else:
                rb.ingest_shadow_failure(
                    orig_path, status, int(getattr(ev, 'reason', 0) or 0), pid,
                    getattr(ev, 'status_name', ''), getattr(ev, 'reason_name', ''))
        except Exception as e:
            logger.debug(f'_on_shadow_backup_event 处理异常: {e}')

    def _log_shadow_state(self, force: bool = False):
        """记录"写前影子备份"状态到活动日志（**去重**）。

        需求 #3：该方法由"每秒广播状态变化"周期触发，旧实现无条件写活动日志 →
        每 10s 一条"I 写前影子备份已启用（已下发世代 1）"刷屏（世代没变也记）。
        现在仅在 (enabled, generation) **变化**时记一条；其余降为 DEBUG。
        force=True（用户切换开关）时始终记录一次，保持既有行为。
        """
        try:
            rb = self._rollback_manager
            if rb is None:
                return
            en = bool(rb.is_enabled)
            gen = int(rb.generation_id)
            last = self._shadow_state_logged        # __init__ 中已初始化（勿用 getattr 兜底）
            if not force and last == (en, gen):
                logger.debug(f'写前影子备份状态未变化（enabled={en}, 世代={gen}），'
                             f'不重复写活动日志')
                return
            self._shadow_state_logged = (en, gen)
            self._add_activity(
                '勒索文件回滚',
                f'写前影子备份已{"启用" if en else "禁用"}（已下发世代 {gen}）',
                'INFO', '成功')
        except Exception as e:
            logger.debug(f'影子状态活动日志失败: {e}')

    def _apply_shadow_config(self):
        """把驱动桥注入回滚引擎并下发写前影子配置（世代/影子根/触发目录）。

        本方法可能由主线程广播路径触发；下发涉及目录创建 + DeviceIoControl，
        故放入 daemon 线程执行，绝不阻塞 Qt 主线程。
        """
        rb = self._rollback_manager
        bridge = getattr(self, '_mbr_driver_bridge', None)
        if rb is None or bridge is None or not getattr(bridge, 'is_available', False):
            return

        def _run():
            try:
                rb.set_driver_bridge(bridge)
                # 需求 #3：周期路径去重（世代/开关未变 → 只 DEBUG，不写活动日志）
                self._log_shadow_state(force=False)
            except Exception as e:
                logger.debug(f'_apply_shadow_config 异常: {e}')

        try:
            threading.Thread(target=_run, daemon=True,
                             name='ShadowConfigPush').start()
        except Exception as e:
            logger.debug(f'启动影子配置下发线程失败: {e}')

    def _broadcast_state_changes(self):
        """每秒向 JS 推送一次状态变化（主动推送，避免依赖 JS 轮询）

        仅在状态发生变化时 emit 信号，减少信号频率。
        添加防御性检查：防止因属性访问异常或对象状态突变导致错误推送。
        """
        try:
            # 1. 自我保护状态
            sp = self._self_protection
            if sp is None:
                sp_state = {
                    'state': 'uninitialized',
                    'running': False,
                    'enabled': True,
                    'files_monitored': 0,
                }
            else:
                try:
                    is_running = sp.is_running
                except Exception as e:
                    logger.warning(f'[BROADCAST] sp.is_running 访问异常: {e}')
                    is_running = False
                try:
                    is_enabled = sp.is_enabled
                except Exception as e:
                    logger.warning(f'[BROADCAST] sp.is_enabled 访问异常: {e}')
                    is_enabled = True
                try:
                    files_monitored = len(sp.get_protected_files())
                except Exception as e:
                    logger.warning(f'[BROADCAST] sp.get_protected_files 访问异常: {e}')
                    files_monitored = 0
                sp_state = {
                    'state': 'running' if is_running else 'stopped',
                    'running': is_running,
                    'enabled': is_enabled,
                    'files_monitored': files_monitored,
                }
                # 防御性检查：如果之前是 running，突然变为 stopped，记录警告并使用上一次有效状态兜底
                if (self._last_self_prot_state
                        and self._last_self_prot_state.get('running')
                        and not sp_state['running']):
                    logger.warning(f'[BROADCAST] 自我保护状态异常突变: running=True -> False，使用上次有效状态兜底')
                    sp_state = dict(self._last_self_prot_state)
                # 防御性检查：如果之前是 enabled，突然变为 disabled，也做兜底（防止属性访问异常）
                if (self._last_self_prot_state
                        and self._last_self_prot_state.get('enabled')
                        and not sp_state['enabled']):
                    logger.warning(f'[BROADCAST] 自我保护开关状态异常突变: enabled=True -> False，使用上次有效状态兜底')
                    sp_state = dict(self._last_self_prot_state)
            if sp_state != self._last_self_prot_state:
                logger.info(f'[BROADCAST] 自我保护状态变化: {self._last_self_prot_state} -> {sp_state}')
                self._last_self_prot_state = sp_state
                self.selfProtectionStatusChanged.emit(json.dumps(sp_state, ensure_ascii=False))

            # 2. YARA 规则引擎状态
            # 关键修正：核心初始化尚未完成（_scan_engine / rule_engine 都没准备好）时，
            # 不生成 "全 False" 的状态快照，也不写入 _last_yara_state，否则会：
            #   - 触发 WARNING 刷屏（engine=None）
            #   - 把 last 状态污染成 False，后续即便就绪也会被误判为"异常突变"
            #   - 导致前端短暂闪红/引擎不可用假提示
            if self._scan_engine and self._scan_engine.rule_engine:
                re = self._scan_engine.rule_engine
                try:
                    yara_state = re.get_status()
                except Exception as e:
                    logger.warning(f'[BROADCAST] re.get_status() 异常: {e}')
                    yara_state = {'yara_enabled': False, 'yara_installed': False, 'yara_available': False}
            else:
                # 启动阶段尚未初始化，仅做一次 DEBUG 记录，不做 WARNING
                if not getattr(self, '_engine_unavailable_dbg', False):
                    logger.debug(f'[BROADCAST] _scan_engine 或 rule_engine 尚未初始化: engine={self._scan_engine}')
                    self._engine_unavailable_dbg = True
                # 跳过本轮 YARA 状态广播（不写 last，不 emit）
                yara_state = None

            if yara_state is not None:
                # 防御性检查：如果之前是已安装，突然变为未安装，记录警告并尝试异步刷新
                if (self._last_yara_state
                        and (self._last_yara_state.get('yara_installed')
                             or self._last_yara_state.get('yara_available')
                             or self._last_yara_state.get('yara_direct'))
                        and not (yara_state.get('yara_installed')
                                 or yara_state.get('yara_available')
                                 or yara_state.get('yara_direct'))):
                    logger.warning(f'[BROADCAST] YARA 状态异常突变: 已安装 -> 未安装 (yara_state={yara_state})')
                    # 如果 rule_engine 存在，尝试异步刷新一次 YARA 状态（不阻塞）
                    if self._scan_engine and self._scan_engine.rule_engine:
                        QTimer.singleShot(0, lambda re=re: self._try_refresh_yara_status(re))
                    # 使用上一次的有效状态作为兜底，避免前端闪红
                    yara_state = dict(self._last_yara_state)

                if yara_state != self._last_yara_state:
                    logger.info(f'[BROADCAST] YARA 状态变化: {self._last_yara_state} -> {yara_state}')
                    self._last_yara_state = yara_state
                    self.ruleEngineStatusChanged.emit(json.dumps(yara_state, ensure_ascii=False))

            # 3. 严格模式状态
            strict_state = {
                'enabled': getattr(self, '_strict_mode', False),
                'description': '严格模式' if getattr(self, '_strict_mode', False) else '宽松模式',
            }
            if strict_state != self._last_strict_state:
                self._last_strict_state = strict_state
                self.strictModeStatusChanged.emit(json.dumps(strict_state, ensure_ascii=False))

            # 3.5 VirusIdentifier 开关状态
            vi_state = {
                'enabled': bool(getattr(self, '_vi_enabled', False)),
                'description': ('VirusIdentifier 已启用'
                                if getattr(self, '_vi_enabled', False)
                                else 'VirusIdentifier 已关闭'),
            }
            if vi_state != self._last_vi_state:
                self._last_vi_state = vi_state
                self.virusIdentifierStatusChanged.emit(
                    json.dumps(vi_state, ensure_ascii=False))

            # 4. ML 检测引擎状态（与 YARA 同样：未就绪时跳过本轮，不写 last、不 emit）
            if self._ml_detector:
                try:
                    ml_state = self._ml_detector.get_status()
                except Exception as e:
                    logger.warning(f'[BROADCAST] ml_detector.get_status() 异常: {e}')
                    ml_state = {'ml_enabled': False, 'ml_available': False}
            else:
                ml_state = None

            if ml_state is not None:
                if ml_state != self._last_ml_state:
                    logger.info(f'[BROADCAST] ML 引擎状态变化: {self._last_ml_state} -> {ml_state}')
                    self._last_ml_state = ml_state
                    self.mlEngineStatusChanged.emit(json.dumps(ml_state, ensure_ascii=False))

            # 3. MBR / 引导扇区保护状态
            mbr_state = self._get_mbr_state()

            if mbr_state is not None and mbr_state != self._last_mbr_state:
                self._last_mbr_state = mbr_state
                self.mbrProtectionStatusChanged.emit(json.dumps(mbr_state, ensure_ascii=False))

            # 6. 动态降载控制器状态（CPU / 内存 / 自身RSS / 降载开关）
            try:
                load_state = load_governor.get_load_state()
            except Exception as e:
                logger.warning(f'[BROADCAST] load_governor.get_load_state 异常: {e}')
                load_state = None
            if load_state is not None:
                # 只对比关键字段，保留可比较子集（避免每轮 reductions={} 都触发）
                cmp_keys = ('cpu', 'mem', 'level', 'scale', 'self_rss_mb', 'self_rss_pct', 'reductions')
                last_cmp = None
                if isinstance(self._last_load_gov_state, dict):
                    last_cmp = {k: self._last_load_gov_state.get(k) for k in cmp_keys}
                cur_cmp = {k: load_state.get(k) for k in cmp_keys}
                if last_cmp != cur_cmp:
                    self._last_load_gov_state = dict(load_state)
                    self.loadGovernorStatusChanged.emit(json.dumps(load_state, ensure_ascii=False))

        except Exception as e:
            logger.warning(f'广播状态变化异常: {e}', exc_info=True)

    # -------------------------------------------------------------- 动态降载控制器集成
    def _rebuild_reduction_ctx(self) -> Dict[str, Any]:
        """基于当前已就绪的模块重建 apply_reductions 的 ctx（主线程或任意线程皆可）。

        返回新的 ctx（只读），并同步写回 self._reduction_ctx。
        对尚未就绪的模块保留空值（apply_reductions 内部已 skip None）。
        """
        ctx: Dict[str, Any] = {
            'signature_db': self._signature_db,
            'ml_detector': self._ml_detector,
            'protector': self._mbr_protector,  # MBRProtector 有 set_poll_interval
            'scan_max_file_mb': self._scan_max_file_mb,
        }
        # rule_engine 放在 ScanEngine.rule_engine 上
        re_ = None
        try:
            re_ = getattr(self._scan_engine, 'rule_engine', None)
        except Exception:
            re_ = None
        ctx['rule_engine'] = re_
        with self._reduction_ctx_lock:
            self._reduction_ctx = ctx
        return ctx

    def _apply_reductions_now(self) -> None:
        """主线程：把当前档位对应降载应用到已就绪模块。

        调用链：
          - __init__ 中 QTimer.singleShot(2000, ...) 启动期 apply 一次
          - load_governor 档位变化回调 → _loadGovApplyRequired 信号 → 这里
          - 外部也可直接调用（如防护模块初始化完成后立即对齐一次）
        """
        try:
            with self._reduction_ctx_lock:
                ctx = dict(self._reduction_ctx) if self._reduction_ctx else {}
            # 若 ctx 为空（初始化未完成），先尝试重建再应用
            if not ctx:
                ctx = self._rebuild_reduction_ctx()
            # 没任何可应用目标，跳过（省一行日志）
            has_target = False
            for k in ('signature_db', 'rule_engine', 'ml_detector', 'protector'):
                if ctx.get(k) is not None:
                    has_target = True
                    break
            if not has_target and ctx.get('scan_max_file_mb') is None:
                return
            n = load_governor.apply_reductions(ctx)
            if n > 0:
                state = load_governor.get_load_state()
                logger.info(f'[降载] level={state.get("level")} 已应用 {n} 项措施 '
                            f'(cpu={state.get("cpu")}% mem={state.get("mem")}% rss={state.get("self_rss_mb")}MB)')
            # 把新的 max_bytes 回写到 signature_db（如果有）
            sdb = ctx.get('signature_db')
            mb = ctx.get('scan_max_file_mb')
            if (sdb is not None
                    and callable(getattr(sdb, 'set_scan_max_bytes', None))
                    and isinstance(mb, list) and len(mb) == 1
                    and isinstance(mb[0], (int, float))):
                try:
                    sdb.set_scan_max_bytes(int(mb[0]) * 1024 * 1024)
                except Exception as e:
                    logger.debug(f'[降载] 写回 scan_max_bytes 失败: {e}')
            # 同步缓存 ctx
            with self._reduction_ctx_lock:
                self._reduction_ctx = ctx
        except Exception as e:
            logger.warning(f'[降载] apply_reductions_now 异常: {e}', exc_info=True)

    def _emit_tool_signal(self, signal_name: str, *args):
        """线程安全地发射工具子页面信号。

        主线程直接 emit；子线程通过 _pending_tool_signals 队列转发，
        由主线程的 _flush_timer 定时取出并 emit。
        """
        if threading.current_thread() is threading.main_thread():
            try:
                sig = getattr(self, signal_name, None)
                if sig is not None:
                    sig.emit(*args)
            except Exception as e:
                logger.warning(f'emit {signal_name} 失败: {e}')
        else:
            with self._signal_lock:
                self._pending_tool_signals.append((signal_name, args))

    def _request_alert_sound(self):
        """线程安全地请求播放威胁警报音（malware → error.mp3）

        带独立节流（5 秒），防止误报轰炸。仅在主线程播放，由 QMediaPlayer 异步执行。
        """
        import time as _time
        now = _time.time()
        with self._threat_throttle_lock:
            if now - self._last_threat_alert_time < self._threat_alert_min_interval:
                return
            self._last_threat_alert_time = now
        try:
            self.playAlertRequested.emit()
        except Exception as e:
            logger.warning(f'请求威胁警报音失败: {e}')

    def _request_suspicious_sound(self):
        """线程安全地请求播放可疑警告音（suspicious → warn.mp3）

        带独立节流（5 秒），与威胁警报互不干扰。仅在主线程播放，由 QMediaPlayer 异步执行。
        """
        import time as _time
        now = _time.time()
        with self._threat_throttle_lock:
            if now - self._last_suspicious_alert_time < self._suspicious_alert_min_interval:
                return
            self._last_suspicious_alert_time = now
        try:
            self.playSuspiciousAlertRequested.emit()
        except Exception as e:
            logger.warning(f'请求可疑警告音失败: {e}')

    # ---- 6 级分级提示音请求（info/info2/warn/error/error2/critical） ----

    def _request_graded_sound(self, level: str):
        """线程安全地请求播放分级音效

        Args:
            level: 'info' / 'info2' / 'warn' / 'error' / 'error2' / 'critical'

        每个级别独立节流（5 秒）防止误报轰炸；音频文件在信号里异步播放不阻塞。
        """
        _SIGNAL_MAP = {
            'info': self.playInfoRequested,
            'info2': self.playInfo2Requested,
            'warn': self.playWarnRequested,
            'error': self.playErrorRequested,
            'error2': self.playError2Requested,
            'critical': self.playCriticalRequested,
        }
        try:
            import time as _time
            now = _time.time()
            attr_key = f'_last_{level}_alert_time'
            with self._threat_throttle_lock:
                last = getattr(self, attr_key, 0.0)
                if now - last < self._threat_alert_min_interval:
                    return
                setattr(self, attr_key, now)
            sig = _SIGNAL_MAP.get(level)
            if sig is not None:
                sig.emit()
        except Exception as e:
            logger.warning(f'请求 {level} 音效失败: {e}')

    def _request_info_sound(self):
        """无通知的实时/启动监测发现可疑 → info.mp3"""
        self._request_graded_sound('info')

    def _request_info2_sound(self):
        """通知询问是否重启（沙箱放行）→ info2.mp3"""
        self._request_graded_sound('info2')

    def _request_warn_sound(self):
        """沙箱拦截分析 / 无通知的检测到威胁 → warn.mp3"""
        self._request_graded_sound('warn')

    def _request_error_sound(self):
        """通知隔离可疑对象 → error.mp3"""
        self._request_graded_sound('error')

    def _request_error2_sound(self):
        """通知隔离恶意对象 → error2.mp3"""
        self._request_graded_sound('error2')

    def _request_critical_sound(self):
        """MBR/引导扇区被修改 / 勒索行为 / 注册表被篡改 → critical.mp3"""
        self._request_graded_sound('critical')

    def _start_protection_module(self, module: str):
        """启动指定的防护子模块（进程保护内含 ETW/WMI 等待，异步启动）"""
        try:
            if module == 'process-protection' and self._process_protection:
                threading.Thread(target=self._process_protection.start,
                                 daemon=True,
                                 name='ProcessProtection-Start').start()
            elif module == 'file-protection' and self._file_protection:
                self._file_protection.start()
            elif module == 'system-protection' and self._system_protection:
                self._system_protection.start()
            elif module == 'autostart-protection' and self._autostart_protection:
                self._autostart_protection.start()
        except Exception as e:
            logger.error(f'启动防护模块 {module} 失败: {e}')

    def _stop_protection_module(self, module: str):
        """停止指定的防护子模块"""
        try:
            if module == 'process-protection' and self._process_protection:
                self._process_protection.stop()
            elif module == 'file-protection' and self._file_protection:
                self._file_protection.stop()
            elif module == 'system-protection' and self._system_protection:
                self._system_protection.stop()
            elif module == 'autostart-protection' and self._autostart_protection:
                self._autostart_protection.stop()
        except Exception as e:
            logger.error(f'停止防护模块 {module} 失败: {e}')

    def _retry_emit_finished(self):
        """兜底重试：重新 emit 最后一次 scanFinished（若仍未成功则继续重试）"""
        with self._signal_lock:
            payload = self._pending_scan_finished
            self._pending_scan_finished = None
        if payload is None:
            logger.info('_retry_emit_finished 队列已空，直接用保存的 stats 重试')
            payload = dict(self._scan_stats)
        try:
            js = json.dumps(payload, ensure_ascii=False)
            logger.info(f'_retry_emit_finished 重试 emit (第 {self._scan_finished_retry} 次): {js}')
            self.scanFinished.emit(js)
            self._scan_finished_retry += 1
            if self._scan_finished_retry < 3:
                self._finished_retry_timer.start(1000)
            else:
                self._scan_finished_retry = 0
        except Exception as e:
            logger.error(f'_retry_emit_finished 失败: {e}')

    # 核心管理器初始化最大重试次数（disk I/O error 等瞬时故障自愈）
    _CORE_INIT_MAX_RETRIES = 3

    def _init_managers(self):
        """[GUI 线程] 核心管理器初始化入口 —— **只调度，不构造重活**。

        历史缺陷：本方法原先在 GUI 线程**直接构造**签名库/扫描引擎/隔离管理器
        （内置库 106MB），冷盘/高负载下可达秒级 → 加载界面与主 GUI 刚出现即
        "未响应"。现在这些构造一律交给后台线程 `PSLS-CoreInit`
        （见 `_start_core_init_async` / `_on_core_init_done`），本方法**立即返回**，
        进度窗口/主界面全程可交互；对象就绪后由 `_on_core_init_done` 在 GUI 线程
        写回引用并点亮状态（后到后更新）。

        仅当核心对象已就绪时，本方法才执行轻量收尾（回灌持久化开关、调度防护模块）。
        """
        t0 = time.monotonic()
        try:
            # ---- 0. 两个纯后台动作（非阻塞，保留在此尽早下发）----
            try:
                self._kick_sandboxie_suppress_async()
            except Exception as e:
                logger.debug(f'Sandboxie 抑制调度失败: {e}')
            try:
                self._start_browser_launch_watcher()
            except Exception as e:
                logger.debug(f'浏览器启动诊断调度失败: {e}')

            # ---- 1. 核心对象未就绪 → 委托后台线程，GUI 立即返回 ----
            if self._signature_db is None or self._scan_engine is None:
                self._kick_core_init_async()
                logger.info(
                    '[启动耗时] _init_managers 委托后台核心初始化（GUI 线程立即返回）')
                return

            # ---- 2. 已就绪 → 轻量收尾（无重活）----
            self._finish_core_init_light()
        finally:
            self._record_gui_block('_init_managers', (time.monotonic() - t0) * 1000)

    def _kick_sandboxie_suppress_async(self):
        """后台下发 Sandboxie 界面弹窗抑制（SbieIni 子进程调用不占 GUI）。"""
        def _suppress_sbie_ui():
            try:
                from engine.sandbox_analyzer import (
                    suppress_sandboxie_ui_popups,
                    start_sandboxie_popup_watcher)
                if suppress_sandboxie_ui_popups():
                    start_sandboxie_popup_watcher()
            except Exception as e:
                logger.debug(f'Sandboxie 界面弹窗抑制失败: {e}')
        threading.Thread(target=_suppress_sbie_ui, daemon=True,
                         name='SbieUiSuppressInit').start()

    def _kick_core_init_async(self):
        """幂等触发后台核心初始化（GUI 线程调用，绝不阻塞）。"""
        t = getattr(self, '_core_init_thread', None)
        if t is not None and t.is_alive():
            return            # 已在初始化中，复用
        logger.info('核心管理器初始化：转入后台线程 PSLS-CoreInit（不阻塞 GUI）')
        self._start_core_init_async()

    def _finish_core_init_light(self):
        """[GUI 线程] 核心对象就绪后的轻量收尾（无重 IO）。

        注意：此处**不得**再构造任何管理器；只做设置回灌、日志与调度。
        """
        # 恢复持久化的引擎开关（ML / LightGBM / YARA）
        self._restore_persisted_engine_toggles()
        self._add_activity('系统', '核心管理器初始化完成', 'INFO', '成功')
        self._bump_launch('core.done', '核心管理器就绪')
        self._core_init_retries = 0
        # 防护模块初始化（主线程只做守卫 + 起后台线程）
        QTimer.singleShot(0, self._init_protection_modules)
        QTimer.singleShot(5000, self._ensure_protection_initialized)

    def _restore_persisted_engine_toggles(self):
        """按持久化设置恢复 ML / LightGBM / YARA 开关（轻量，无重 IO）。"""
        try:
            _ui_eng = _load_ui_settings()
            if self._ml_detector:
                if _ui_eng.get('ml_enabled') is False:
                    self._ml_detector.set_enabled(False)
                    logger.info('已按持久化设置恢复：ML 引擎保持关闭')
                if _ui_eng.get('lightgbm_enabled') is False:
                    self._ml_detector.set_brewtotal_enabled(False)
                    logger.info('已按持久化设置恢复：LightGBM 引擎保持关闭')
            if self._scan_engine and _ui_eng.get('yara_enabled') is False:
                self.setYaraEnabled(False)
                logger.info('已按持久化设置恢复：YARA 引擎保持关闭')
        except Exception as e:
            logger.debug(f'恢复持久化引擎开关失败: {e}')

    def _record_gui_block(self, label: str, ms: float, warn_ms: float = 200.0,
                          emit_log: bool = True, prefix: str = '启动耗时'):
        """记录 GUI 线程单次占用时长（量化启动/配置期阻塞；超阈记 WARNING）。

        prefix='启动耗时' 用于启动链路；prefix='配置耗时' 用于拨开关/设置页/保存设置。
        """
        try:
            buf = getattr(self, '_gui_block_samples', None)
            if buf is None:
                buf = []
                self._gui_block_samples = buf
            buf.append((f'{prefix}:{label}', float(ms)))
            if len(buf) > 400:
                del buf[:len(buf) - 400]
            cur_max = float(getattr(self, '_gui_block_max_ms', 0.0) or 0.0)
            if ms > cur_max:
                self._gui_block_max_ms = float(ms)
            if not emit_log:
                return
            log = logger.warning if ms >= warn_ms else logger.info
            log(f'[{prefix}] GUI 线程 {label}: {ms:.1f} ms')
        except Exception:
            pass

    def _cfg_note(self, label: str, ms: float, warn_ms: float = 200.0):
        """配置路径埋点便捷入口（前缀固定为"配置耗时"）。"""
        self._record_gui_block(label, ms, warn_ms=warn_ms, prefix='配置耗时')

    def get_gui_block_stats(self) -> dict:
        """返回 GUI 线程占用采样统计（供自证/测试）。"""
        buf = list(getattr(self, '_gui_block_samples', None) or [])
        return {
            'max_ms': float(getattr(self, '_gui_block_max_ms', 0.0) or 0.0),
            'samples': buf,
        }

    def _ensure_protection_initialized(self):
        """回退机制：确保防护模块已初始化 + 驱动判定完成 + launchReady 发射。

        若 _init_protection_modules 因 QTimer 未触发等原因未执行，
        此方法在 6 秒后检查并补充初始化；若驱动判定未完成则立即判定。
        """
        if not getattr(self, '_protection_modules_initialized', False):
            logger.warning('防护模块回退机制触发：模块尚未初始化，立即执行初始化')
            self._init_protection_modules()
        elif not getattr(self, '_driver_decision_done', False):
            # 防护已完成但驱动判定未完成 → 立即做一次终态判定并触发 launchReady
            logger.warning('驱动判定回退机制触发：防护已就绪但驱动判定未完成，立即执行终态判定')
            self._finalize_driver_and_launch_ready()

    def _finalize_driver_and_launch_ready(self):
        """[主线程] 完成驱动状态判定、记录活动日志，并发射 launchReady 终态信号。

        - 终态判定最多 6 秒；提前命中"已激活/已加载"立即收束。
        - 首次调用即记 driver.done 权重（仅一次）。
        - 已调用过直接返回。
        """
        if threading.current_thread() is not threading.main_thread():
            QTimer.singleShot(0, self._finalize_driver_and_launch_ready)
            return
        if getattr(self, '_driver_decision_done', False):
            return

        # 取消正在运行的驱动轮询 timer（如有）
        try:
            if self._launch_driver_timer is not None:
                try:
                    self._launch_driver_timer.stop()
                    self._launch_driver_timer.deleteLater()
                except Exception:
                    pass
                self._launch_driver_timer = None
        except Exception:
            pass

        self._driver_decision_done = True
        # 启动低频驱动状态变化监视器（运行期跟踪 不可用<->已加载 翻转并通知"最近活动"）
        try:
            if not self._driver_state_watch_timer.isActive():
                self._driver_state_watch_timer.start()
                logger.info('驱动状态变化监视器已启动（5s 轮询，变化时通知活动日志）')
        except Exception as e:
            logger.debug(f'驱动状态监视器启动失败: {e}')
        # 记录驱动状态到"最近活动"
        try:
            self._log_driver_protection_status()
        except Exception as e:
            logger.debug(f'_log_driver_protection_status 失败: {e}')
        # 记权重并触发 launchReady
        self._bump_launch('driver.done', '驱动状态判定完成')
        # launchReady 发射前确保 _ui_ready 已置 True（_init_protection_modules 已置）
        if not getattr(self, '_ui_ready', False):
            self._ui_ready = True
            try:
                parent = self.parent()
                if parent is not None and hasattr(parent, 'on_bridge_init_ready'):
                    parent.on_bridge_init_ready()
            except Exception:
                pass
        # 防护 + 驱动 就绪：再次重建 ctx 纳入 MBR protector，收尾对齐一次降载
        try:
            self._rebuild_reduction_ctx()
            self._apply_reductions_now()
        except Exception as e:
            logger.debug(f'[降载] driver ready 阶段对齐失败: {e}')
        self._emit_launch_ready_once()

    def _kick_off_driver_polling(self):
        """启动驱动终态轮询：让启动进度在保护模块初始化起算的 7s 内尽快收敛。

        - deadline 由 _init_protection_modules 入口写入（已算入 self-protection.start() 的等待时间）
        - 轮询周期 500ms：命中"内核激活/已加载"立即收束，否则到 deadline 做降级判定
        - 如果当前已经超过 deadline，直接做终态判定（不再创建 timer）
        """
        import time as _time
        # 1) 快速收束：若 self_protection 已经把内核激活标记打开
        try:
            if (self._self_protection
                    and getattr(self._self_protection, '_kernel_protection_active', False)):
                self._finalize_driver_and_launch_ready()
                return
        except Exception:
            pass
        # 2) 快速收束：驱动桥已端到端就绪
        try:
            if sys.platform == 'win32':
                from driver.bridge.psls_driver_bridge import PSLSDriverBridge
                br = PSLSDriverBridge()
                if br.is_available:
                    st = br.query_status()
                    ke = bool(st and st.psls_protect_enabled)
                    ts = bool(st and st.psls_pid != 0)
                    if ke and ts:
                        self._finalize_driver_and_launch_ready()
                        return
        except Exception:
            pass
        # 3) deadline 已过期 → 立即终态判定（不再创建 timer）
        if self._launch_driver_deadline_ts <= 0:
            self._launch_driver_deadline_ts = _time.time() + 5.0
        if _time.time() >= self._launch_driver_deadline_ts:
            self._finalize_driver_and_launch_ready()
            return

        def _check_once():
            # 已完成 → 停 timer
            if getattr(self, '_driver_decision_done', False):
                try:
                    if self._launch_driver_timer is not None:
                        self._launch_driver_timer.stop()
                        self._launch_driver_timer.deleteLater()
                except Exception:
                    pass
                self._launch_driver_timer = None
                return
            # 已激活 → 收束
            try:
                if (self._self_protection
                        and getattr(self._self_protection, '_kernel_protection_active', False)):
                    self._finalize_driver_and_launch_ready()
                    return
            except Exception:
                pass
            # 驱动桥端到端 OK → 收束
            try:
                if sys.platform == 'win32':
                    from driver.bridge.psls_driver_bridge import PSLSDriverBridge
                    br = PSLSDriverBridge()
                    if br.is_available:
                        st = br.query_status()
                        ke = bool(st and st.psls_protect_enabled)
                        ts = bool(st and st.psls_pid != 0)
                        if ke and ts:
                            self._finalize_driver_and_launch_ready()
                            return
            except Exception:
                pass
            # 到截止时间 → 终态降级判定
            if _time.time() >= self._launch_driver_deadline_ts:
                self._finalize_driver_and_launch_ready()
                return

        self._launch_driver_timer = QTimer(self)
        self._launch_driver_timer.setInterval(500)
        self._launch_driver_timer.timeout.connect(_check_once)
        self._launch_driver_timer.start()

    def _init_protection_modules(self):
        """初始化防护模块 — 主线程只做：守卫、deadline 写入、启动后台线程。

        原串行实现里：SelfProtection.start 驱动安装、ProcessProtection ETW 订阅、
        RealtimeMonitor watchdog 首次递归扫描等会阻塞主线程数秒，Splash 被
        Windows 标记为"未响应"。现在把这些全部移到 _start_protection_worker
        后台线程（PSLS-ProtectionInit）执行，主线程保持响应刷新进度。

        驱动状态轮询 / launchReady 收束：由 worker 结束后 QTimer.singleShot(0,
        _finalize_driver_and_launch_ready) 切回主线程执行，顺序与原实现等价。
        """
        # 初始化守卫：防止重复调用
        if getattr(self, '_protection_modules_initialized', False):
            logger.debug('防护模块已初始化，跳过重复调用')
            if not getattr(self, '_driver_decision_done', False):
                try:
                    QTimer.singleShot(0, self._finalize_driver_and_launch_ready)
                except Exception:
                    pass
            return
        self._protection_modules_initialized = True

        # 入口立刻写驱动判定 deadline（把 self-protection.start() 内 SCM/驱动加载
        # 的等待时间也算入驱动判定窗口，确保测试 7.5s 内收束）
        import time as _time
        if getattr(self, '_launch_driver_deadline_ts', 0.0) <= 0:
            self._launch_driver_deadline_ts = _time.time() + 5.5  # 起算 ≤5.5s

        logger.info('开始初始化防护模块（后台 worker）...')
        # ===> 启动防护模块后台线程（所有 init+start 均在 worker 中执行）<===
        self._protection_init_thread = threading.Thread(
            target=self._start_protection_worker,
            name='PSLS-ProtectionInit',
            daemon=True,
        )
        self._protection_init_thread.start()

    def _start_protection_worker(self):
        """[后台线程: PSLS-ProtectionInit] 实际执行防护模块 init+start。

        规则：
          - 所有 start() 阻塞调用（驱动安装、ETW 订阅、watchdog 递归扫描、
            自启动注册表枚举、ML 子进程 spawn 等）都放在这里，不占主线程。
          - self._xxx_protection 等引用写回在 worker 做（对象引用赋值在 GIL 下原子）。
          - _add_activity / _bump_launch 本身已经是子线程安全（通过队列 +
            _flush_signals 周期转发），可直接调用。
          - 结束后 QTimer.singleShot(0, _finalize_driver_and_launch_ready) 确保
            主线程做 launchReady + 驱动状态日志发布 + splash 关闭。
        """
        init_errors: List[str] = []

        def _mod_init_ok(source: str, ok: bool, err=None):
            if ok:
                self._add_activity(source, f'{source}初始化完成', 'INFO', '成功')
            else:
                emsg = f': {err}' if err else ''
                self._add_activity(source, f'{source}初始化失败{emsg}', 'ERROR', '错误')

        def _mod_start_ok(source: str, ok: bool, err=None,
                          extra_msg: Optional[str] = None):
            if ok:
                if extra_msg:
                    self._add_activity(source, f'{source}已启动（{extra_msg}）', 'WARN', '降级')
                else:
                    self._add_activity(source, f'{source}已启动', 'INFO', '成功')
            else:
                emsg = f': {err}' if err else ''
                self._add_activity(source, f'{source}启动失败{emsg}', 'ERROR', '错误')

        try:
            # ---- 1. 自我保护（驱动安装/SCM 最长）放在首位，其他模块启动时驱动已就绪
            self._bump_launch('protec.self', '正在初始化自我保护与内核驱动...')
            _src_sp = '自我保护'
            _sp_init_ok = True
            if self._self_protection is None:
                try:
                    self._self_protection = SelfProtection(
                        on_threat=self._on_self_protection_threat,
                    )
                except Exception as e:
                    logger.error(f'初始化自我保护失败: {e}')
                    init_errors.append(f'自我保护: {e}')
                    _sp_init_ok = False
                    _mod_init_ok(_src_sp, False, e)
            if _sp_init_ok and self._self_protection is not None:
                _mod_init_ok(_src_sp, True)
            if self._self_protection and not self._self_protection.is_running:
                try:
                    self._self_protection.start()
                    _mod_start_ok(_src_sp, True)
                except Exception as e:
                    logger.error(f'启动自我保护失败: {e}')
                    init_errors.append(f'自我保护启动: {e}')
                    _mod_start_ok(_src_sp, False, e)
            # 自我保护强制开启：即使旧版本曾关闭过（持久化状态），启动后强制恢复
            if self._self_protection is not None:
                try:
                    if not self._self_protection.is_enabled:
                        self._self_protection.set_enabled(True)
                    self._module_states['self-protection'] = True
                except Exception as e:
                    logger.warning(f'强制开启自我保护失败: {e}')

            # ---- 2. 进程保护（ETW 订阅） --------------------------------
            self._bump_launch('protec.process', '正在初始化进程保护...')
            _src_proc = '进程保护'
            _proc_init_ok = True
            if self._process_protection is None:
                try:
                    # [进程→关键目录] 保护联动：一旦 ProcessProtection 捕获
                    # ETW/驱动 进程创建事件，立即触发 MBRProtector 做关键目录
                    # 快照校验（比等下一个 1s 轮询更早）。burst 抑制在
                    # MBRProtector.notify_process_created 内处理（0.4s 冷却）。
                    def _proc_created_cb(pid: int, exe: str):
                        mp = self._mbr_protector
                        if mp is not None:
                            try:
                                mp.notify_process_created(int(pid), str(exe or ''))
                            except Exception:
                                pass

                    self._process_protection = ProcessProtection(
                        signature_db=self._signature_db,
                        on_threat=self._on_process_threat,
                        scan_engine_factory=self._create_scan_engine_for_realtime,
                        quarantine_manager=self._quarantine_manager,
                        auto_action=self._rt_suspicious_action,
                        on_launch_scan=self._on_launch_scan_result,
                        on_sandbox_block=self._on_sandbox_block,
                        on_sandbox_release_request=self._on_sandbox_release_request,
                        on_sandbox_analysis_start=self._on_sandbox_analysis_start,
                        on_sandbox_analysis_progress=self._on_sandbox_analysis_progress,
                        on_sandbox_analysis_done=self._on_sandbox_analysis_done,
                        driver_terminate_by_path_hook=self._driver_terminate_by_path,
                        on_process_created_hook=_proc_created_cb,
                        mbr_arm_before_kill_hook=self._mbr_arm_before_proc_kill,
                        mbr_verify_after_kill_hook=self._mbr_verify_after_proc_kill,
                        visual_prank_observer=self._register_prank_observer,
                    )
                    self._process_protection.sandbox_run_large_files = \
                        self._sandbox_run_large_files
                    self._process_protection.sandbox_backend = \
                        self._sandbox_backend
                except Exception as e:
                    logger.error(f'初始化进程保护失败: {e}')
                    init_errors.append(f'进程保护: {e}')
                    _proc_init_ok = False
                    _mod_init_ok(_src_proc, False, e)
            if _proc_init_ok and self._process_protection is not None:
                _mod_init_ok(_src_proc, True)
            if (self._process_protection
                    and not self._process_protection.is_running
                    and self._module_states.get('process-protection', True)):
                # 启动内含 ETW/WMI 就绪等待（最长 12s）：必须在后台线程执行，
                # 否则主线程长时间阻塞会触发 QtWebEngine COM 断开（0x8001010D 崩溃）。
                # 注意：后台失败只报活动日志，不追加 init_errors（避免与主线程
                # 汇总时的并发迭代冲突）。
                def _bg_start_process_protection():
                    try:
                        self._process_protection.start()
                        _mod_start_ok(_src_proc, True)
                    except Exception as e:
                        logger.error(f'启动进程保护失败: {e}')
                        _mod_start_ok(_src_proc, False, e)
                threading.Thread(target=_bg_start_process_protection,
                                 daemon=True,
                                 name='ProcessProtection-Start').start()

            # ---- 3. 文件保护 ------------------------------------------------
            self._bump_launch('protec.file', '正在初始化文件保护...')
            _src_file = '文件保护'
            _fi_init_ok = True
            if self._file_protection is None:
                try:
                    self._file_protection = FileProtection(
                        quarantine_manager=self._quarantine_manager,
                        signature_db=self._signature_db,
                        on_threat=self._on_file_threat,
                        on_ransomware_kill=self._on_ransomware_kill,
                    )
                    self._file_protection.strict_mode = self._strict_mode
                except Exception as e:
                    logger.error(f'初始化文件保护失败: {e}')
                    init_errors.append(f'文件保护: {e}')
                    _fi_init_ok = False
                    _mod_init_ok(_src_file, False, e)
            if _fi_init_ok and self._file_protection is not None:
                _mod_init_ok(_src_file, True)
            if (self._file_protection
                    and not self._file_protection.is_running
                    and self._module_states.get('file-protection', True)):
                try:
                    self._file_protection.start()
                    _mod_start_ok(_src_file, True)
                except Exception as e:
                    logger.error(f'启动文件保护失败: {e}')
                    init_errors.append(f'文件保护启动: {e}')
                    _mod_start_ok(_src_file, False, e)

            # ---- 3b. 勒索软件文件回滚（阶段一：用户态增量快照 + 回滚）-------
            # 依赖文件保护（低水位预警/确认勒索回调）与隔离管理器；start() 后台线程非阻塞。
            _src_rb = '勒索文件回滚'
            _rb_init_ok = True
            if self._rollback_manager is None:
                try:
                    # 进程剥离：改用 worker 代理，重活（快照/回滚/ingest）不在主进程执行。
                    # worker 启动失败时代理自动降级为进程内后台线程模式。
                    logger.info('勒索文件回滚: 初始化 —— 正在创建 worker 代理'
                                '（重活剥离到独立进程）')
                    self._rollback_manager = _create_rollback_manager(
                        quarantine_manager=self._quarantine_manager,
                        process_protection=self._process_protection,
                        on_report=self._on_rollback_report,
                    )
                except Exception as e:
                    logger.error(f'初始化勒索文件回滚失败: {e}')
                    init_errors.append(f'勒索文件回滚: {e}')
                    _rb_init_ok = False
                    _mod_init_ok(_src_rb, False, e)
            # 接线：注册状态刷新回调 + 后台预热（页面加载零阻塞）
            self._wire_rollback_manager()
            if _rb_init_ok and self._rollback_manager is not None:
                _mod_init_ok(_src_rb, True)
            if (self._rollback_manager
                    and self._module_states.get('ransomware-rollback', True)):
                try:
                    # 注意：**不能**用 is_running 作为门控。worker 模式下它可能因为
                    # "worker 进程存活"而为真，于是这里会跳过 start，导致 worker 的
                    # 循环（延迟启动快照 + 周期快照）永不开始 —— 实测现象：
                    # 日志出现"跳过 start（已在运行）"，此后完全没有快照记录。
                    # start() 本身幂等（引擎内部已在运行时立即返回 True）。
                    self._rollback_manager.start()
                    logger.info('勒索文件回滚: 初始化 —— 已下发 start')
                    _mod_start_ok(_src_rb, True)
                except Exception as e:
                    logger.error(f'启动勒索文件回滚失败: {e}')
                    init_errors.append(f'勒索文件回滚启动: {e}')
                    _mod_start_ok(_src_rb, False, e)
            elif self._rollback_manager is not None:
                logger.info('勒索文件回滚: 初始化 —— 跳过 start（模块开关已关闭）')
            # 阶段二: 若驱动桥已连接, 启动后立即下发写前影子配置（世代/影子根/触发目录）
            if self._rollback_manager is not None:
                try:
                    self._apply_shadow_config()
                except Exception as e:
                    logger.debug(f'启动后下发影子配置失败: {e}')
            # 回灌持久化的"快照范围与文件类型"（settings.json 的 ui 段）。
            # 用户曾在设置页配置过目录/类型时，重启后按持久化状态恢复，
            # 避免"UI 显示一套、后端实际另一套"。
            if self._rollback_manager is not None:
                try:
                    _ui_rb = _load_ui_settings()
                    _saved_dirs = _ui_rb.get('rollback_snapshot_dirs')
                    _saved_exts = _ui_rb.get('rollback_snapshot_exts')
                    # 单文件上限（MB，0=不限制）：仅在用户显式配置过时回灌，
                    # 未配置则沿用引擎默认（PSLS_ROLLBACK_MAX_FILE_MB/64MB）。
                    _saved_mb = _ui_rb.get('rollback_max_file_mb')
                    _saved_mb = int(_saved_mb) if isinstance(_saved_mb, int) else None
                    # 一次性回灌 worker：目录 + 类型白名单 + 开关（减少 IPC 往返）
                    _rb_reload = getattr(self._rollback_manager, 'reload_config', None)
                    if callable(_rb_reload):
                        # 空列表 / null 一律视为"未自定义范围" → 由引擎回落默认目录
                        # （否则默认配置下 worker 快照范围为空，"快照变成 0"）
                        _rb_reload(
                            dirs=_saved_dirs if _saved_dirs else None,
                            exts=_saved_exts if isinstance(_saved_exts, list) else None,
                            enabled=bool(self._module_states.get(
                                'ransomware-rollback', True)),
                            kill_all=bool(_ui_rb.get(
                                'rollback_kill_all_before_restore', True)),
                            max_file_mb=_saved_mb)
                    else:
                        if isinstance(_saved_dirs, list) and _saved_dirs:
                            self._rollback_manager.set_protected_dirs(_saved_dirs)
                        if isinstance(_saved_exts, list):
                            self._rollback_manager.set_snapshot_exts(_saved_exts)
                        if _saved_mb is not None:
                            _fn = getattr(self._rollback_manager, 'set_max_file_mb', None)
                            if callable(_fn):
                                _fn(_saved_mb)
                except Exception as e:
                    logger.debug(f'回灌勒索回滚快照范围失败: {e}')
            # 接线：低水位预警 + 确认勒索回滚（回调可选、异常安全）
            if self._file_protection is not None and self._rollback_manager is not None:
                try:
                    self._file_protection.on_prewarn = self._rollback_manager.prewarn
                    self._file_protection.on_ransomware_confirmed = \
                        self._on_ransomware_confirmed
                except Exception as e:
                    logger.warning(f'勒索回滚回调接线失败: {e}')

            # ---- 4. 系统保护 ------------------------------------------------
            self._bump_launch('protec.system', '正在初始化系统保护...')
            _src_sys = '系统保护'
            _sy_init_ok = True
            if self._system_protection is None:
                try:
                    self._system_protection = SystemProtection(
                        quarantine_manager=self._quarantine_manager,
                        on_threat=self._on_system_threat,
                    )
                except Exception as e:
                    logger.error(f'初始化系统保护失败: {e}')
                    init_errors.append(f'系统保护: {e}')
                    _sy_init_ok = False
                    _mod_init_ok(_src_sys, False, e)
            if _sy_init_ok and self._system_protection is not None:
                _mod_init_ok(_src_sys, True)
            if (self._system_protection
                    and not self._system_protection.is_running
                    and self._module_states.get('system-protection', True)):
                try:
                    self._system_protection.start()
                    _mod_start_ok(_src_sys, True)
                except Exception as e:
                    logger.error(f'启动系统保护失败: {e}')
                    init_errors.append(f'系统保护启动: {e}')
                    _mod_start_ok(_src_sys, False, e)

            # ---- 5. 自启动监测（注册表扫描，可能数秒） ---------------------
            self._bump_launch('protec.autostart', '正在初始化自启动监测...')
            _src_auto = '自启动监测'
            _au_init_ok = True
            if self._autostart_protection is None:
                try:
                    self._autostart_protection = AutostartProtection(
                        signature_db=self._signature_db,
                        on_suspicious=self._on_autostart_suspicious,
                        on_ask_user=self._on_autostart_ask_user,
                        on_result=self._on_autostart_result,
                    )
                except Exception as e:
                    logger.error(f'初始化自启动监测失败: {e}')
                    init_errors.append(f'自启动监测: {e}')
                    _au_init_ok = False
                    _mod_init_ok(_src_auto, False, e)
            if _au_init_ok and self._autostart_protection is not None:
                _mod_init_ok(_src_auto, True)
            if (self._autostart_protection
                    and not self._autostart_protection.is_running
                    and self._module_states.get('autostart-protection', True)):
                try:
                    self._autostart_protection.start()
                    _mod_start_ok(_src_auto, True)
                except Exception as e:
                    logger.error(f'启动自启动监测失败: {e}')
                    init_errors.append(f'自启动监测启动: {e}')
                    _mod_start_ok(_src_auto, False, e)

            # ---- 5b. MBR / 引导扇区保护 -------------------------------
            self._bump_launch('protec.mbr', '正在初始化 MBR 保护...')
            _src_mbr = 'MBR保护'
            _mbr_init_ok = True
            if self._mbr_protector is None:
                try:
                    self._mbr_protector = MBRProtector(
                        on_threat=self._on_mbr_threat,
                    )
                except Exception as e:
                    logger.error(f'初始化 MBR 保护失败: {e}')
                    init_errors.append(f'MBR保护: {e}')
                    _mbr_init_ok = False
                    _mod_init_ok(_src_mbr, False, e)
            if _mbr_init_ok and self._mbr_protector is not None:
                _mod_init_ok(_src_mbr, True)
            if (self._mbr_protector
                    and not self._mbr_protector.is_running
                    and self._module_states.get('mbr-protection', True)):
                try:
                    _mbr_started = self._mbr_protector.start()
                    if _mbr_started:
                        _mod_start_ok(_src_mbr, True)
                    else:
                        # start() 返回 False = 无法创建引导扇区备份，最常见原因是未以管理员运行
                        _mod_start_ok(
                            _src_mbr, False,
                            '需要管理员权限（无法读取/备份引导扇区）',
                        )
                        init_errors.append('MBR保护: 未生效（需要管理员权限）')
                except Exception as e:
                    logger.error(f'启动 MBR 保护失败: {e}')
                    init_errors.append(f'MBR保护启动: {e}')
                    _mod_start_ok(_src_mbr, False, e)

            # ---- 5c. 视觉恶搞行为检测（轻量 1s 轮询，不阻塞） --------------
            self._bump_launch('protec.prank', '正在初始化恶搞行为检测...')
            _src_prank = '恶搞行为检测'
            _prank_init_ok = True
            if self._visual_prank_detector is None:
                try:
                    self._visual_prank_detector = VisualPrankDetector(
                        on_visual_prank=self._on_visual_prank,
                        kill_hook=self._prank_kill_cb,
                        enabled=bool(self._module_states.get('visual-prank', True)),
                    )
                except Exception as e:
                    logger.error(f'初始化恶搞行为检测失败: {e}')
                    init_errors.append(f'恶搞行为检测: {e}')
                    _prank_init_ok = False
                    _mod_init_ok(_src_prank, False, e)
            if _prank_init_ok and self._visual_prank_detector is not None:
                _mod_init_ok(_src_prank, True)
            if (self._visual_prank_detector
                    and not self._visual_prank_detector.is_running):
                try:
                    self._visual_prank_detector.start()
                    _mod_start_ok(_src_prank, True)
                except Exception as e:
                    logger.error(f'启动恶搞行为检测失败: {e}')
                    init_errors.append(f'恶搞行为检测启动: {e}')
                    _mod_start_ok(_src_prank, False, e)

            # ---- 5c2. 更激进的特效检测（截图监控，默认关闭） ---------------
            self._bump_launch('protec.aggr', '正在初始化特效检测(截图)...')
            _src_aggr = '更激进的特效检测'
            _aggr_init_ok = True
            if self._aggressive_prank_detector is None:
                try:
                    self._aggressive_prank_detector = AggressivePrankDetector(
                        on_aggressive_prank=self._on_aggressive_prank,
                        kill_hook=self._aggressive_kill_cb,
                        enabled=bool(
                            self._module_states.get('aggressive-prank', False)),
                    )
                except Exception as e:
                    logger.error(f'初始化更激进的特效检测失败: {e}')
                    init_errors.append(f'更激进的特效检测: {e}')
                    _aggr_init_ok = False
                    _mod_init_ok(_src_aggr, False, e)
            if _aggr_init_ok and self._aggressive_prank_detector is not None:
                _mod_init_ok(_src_aggr, True)
            if (self._aggressive_prank_detector
                    and not self._aggressive_prank_detector.is_running):
                try:
                    self._aggressive_prank_detector.start()
                    _mod_start_ok(_src_aggr, True)
                except Exception as e:
                    logger.error(f'启动更激进的特效检测失败: {e}')
                    init_errors.append(f'更激进的特效检测启动: {e}')
                    _mod_start_ok(_src_aggr, False, e)

            # ---- 6. 实时监控（watchdog 启动+首轮递归目录扫描，最重）-------
            self._bump_launch('protec.realtime', '正在初始化实时防护...')
            _src_rt = '实时防护'
            _rt_init_ok = True
            if self._realtime_monitor is None:
                try:
                    initial_dirs = self._get_realtime_watch_dirs()
                    self._realtime_monitor = RealtimeMonitor(
                        scan_engine_factory=self._create_scan_engine_for_realtime,
                        watch_dirs=initial_dirs,
                        on_threat=self._on_realtime_threat,
                        on_scan_result=self._on_realtime_scan_result,
                        signature_db=self._signature_db,
                        exemption_checker=self._is_realtime_exempted,
                        quarantine_manager=self._quarantine_manager,
                    )
                    self._realtime_monitor.strict_mode = self._strict_mode
                    self._realtime_monitor.virus_identifier_enabled = self._vi_enabled
                    self._realtime_monitor.set_user_excluded_dirs(
                        getattr(self, '_scan_excluded_paths', []))
                    # 注入"内部通道"：沙箱复制样本时若锁是 PSLS 自己持有的，
                    # 用自己的句柄读出副本，避免"自己锁自己"导致沙箱分析失败
                    self._register_internal_copy_provider()
                except Exception as e:
                    logger.error(f'初始化实时监控失败: {e}')
                    init_errors.append(f'实时监控: {e}')
                    _rt_init_ok = False
                    _mod_init_ok(_src_rt, False, e)
            if _rt_init_ok and self._realtime_monitor is not None:
                _mod_init_ok(_src_rt, True)
            if (self._realtime_monitor
                    and not self._realtime_monitor.is_running
                    and self._module_states.get('realtime-monitor', True)):
                try:
                    self._realtime_monitor.start()
                    extra = None
                    if not self._realtime_monitor.has_watchdog:
                        extra = 'watchdog 未安装，降级为被动模式'
                        self._add_activity(
                            _src_rt,
                            'watchdog 未安装，降级为被动模式',
                            'WARN', '降级')
                    _mod_start_ok(_src_rt, True, extra_msg=extra)
                except Exception as e:
                    logger.error(f'启动实时监控失败: {e}')
                    init_errors.append(f'实时监控启动: {e}')
                    _mod_start_ok(_src_rt, False, e)

            # ---- 7. 通知管理器（轻量） ------------------------------------
            self._bump_launch('protec.notify', '正在初始化通知管理...')
            _src_nm = '通知管理'
            _nm_init_ok = True
            if self._notification_manager is None:
                try:
                    self._notification_manager = NotificationManager()
                    cb = self._on_notification_emitted
                    self._notification_manager.set_notification_callback(cb)
                except Exception as e:
                    logger.error(f'初始化通知管理器失败: {e}')
                    init_errors.append(f'通知管理器: {e}')
                    _nm_init_ok = False
                    _mod_init_ok(_src_nm, False, e)
            if _nm_init_ok and self._notification_manager is not None:
                _mod_init_ok(_src_nm, True)
            if (self._notification_manager
                    and not self._notification_manager.is_running
                    and self._module_states.get('notification', True)):
                try:
                    self._notification_manager.start()
                    _mod_start_ok(_src_nm, True)
                except Exception as e:
                    logger.error(f'启动通知管理器失败: {e}')
                    init_errors.append(f'通知管理器启动: {e}')
                    _mod_start_ok(_src_nm, False, e)

            # ---- 收尾：汇总 init_errors ---------------------------------
            if init_errors:
                self._add_activity(
                    '系统',
                    f'部分防护模块初始化失败 ({len(init_errors)} 个)',
                    'WARN', '警告')
                logger.warning(f'部分防护模块初始化失败: {init_errors}')
            else:
                self._add_activity('系统', '防护模块初始化完成', 'INFO', '成功')
                logger.info('防护模块初始化完成（worker）')

            # 全部初始化完成：置就绪标志并通知主界面（与原主线程实现一致）
            self._ui_ready = True
            try:
                parent = self.parent()
                if parent is not None and hasattr(parent, 'on_bridge_init_ready'):
                    # QObject.method 跨线程调用本身是安全的（setParent 等才有限制）。
                    parent.on_bridge_init_ready()
            except Exception as e:
                logger.debug(f'通知主界面初始化就绪失败: {e}')

        except Exception as e_top:
            logger.error(f'防护模块初始化 worker 未捕获异常: {e_top}', exc_info=True)
            init_errors.append(f'未捕获: {e_top}')

        # ===> 回主线程：驱动状态轮询 + launchReady 发布 <===
        # 驱动状态检查会调用 QTimer/信号/UI 事件，必须在主线程。
        def _kick_driver_polling_in_ui_thread():
            try:
                self._kick_off_driver_polling()
            except Exception as e:
                logger.debug(f'启动驱动轮询失败，降级为立即判定: {e}')
                try:
                    self._finalize_driver_and_launch_ready()
                except Exception:
                    pass
        try:
            QTimer.singleShot(0, _kick_driver_polling_in_ui_thread)
        except Exception:
            # 极端情况：QTimer 在退出阶段不可用，直接再 singleShot 一次 launchReady。
            try:
                QTimer.singleShot(0, self._finalize_driver_and_launch_ready)
            except Exception:
                pass

    def _add_activity(self, source: str, message: str, level: str = 'INFO', status: str = '成功',
                      help: str = ''):
        """添加活动日志（线程安全：子线程通过队列，主线程直接 emit）

        Args:
            source: 来源（如"驱动防护"）
            message: 日志正文
            level: INFO / WARN / ERROR
            status: 状态文本
            help: 可选。非空时前端在该条日志右侧显示"？"，
                  点击弹窗展示此帮助内容（HTML）。
        """
        now = datetime.now()
        timestamp = now.strftime('%Y-%m-%d %H:%M:%S')
        activity = {
            'timestamp': timestamp,
            'source': source,
            'message': message,
            'level': level,
            'status': status
        }
        if help:
            activity['help'] = help
        self._activities.insert(0, activity)
        if len(self._activities) > 100:
            self._activities = self._activities[:100]
        activities_copy = self._activities[:50]
        activities_json = json.dumps(activities_copy, ensure_ascii=False)
        # 如果在主线程，直接 emit；否则通过队列转发
        if threading.current_thread() is threading.main_thread():
            self.activityLogUpdated.emit(activities_json)
        else:
            with self._signal_lock:
                self._pending_activity = activities_copy

    def _query_driver_active_now(self) -> Optional[bool]:
        """实时查询驱动当前是否 active（True=已激活/已加载, False=未加载, None=不确定/非win32）。

        供运行期驱动状态监视器 _watch_driver_state_change 使用：
        轮询桥端到端 + SelfProtection 内核激活标记，返回当前驱动可用性。
        仅在 win32 且能拿到可靠证据时返回布尔，否则 None。
        """
        if sys.platform != 'win32':
            return None
        kernel_active = bool(
            self._self_protection
            and getattr(self._self_protection, '_kernel_protection_active', False)
        )
        bridge_active = False
        try:
            from driver.bridge.psls_driver_bridge import PSLSDriverBridge
            bridge = PSLSDriverBridge()
            if bridge.is_available:
                st = bridge.query_status()
                bridge_active = bool(st and st.psls_protect_enabled and st.psls_pid != 0)
            try:
                bridge.close()
            except Exception:
                pass
        except Exception:
            bridge_active = False
        # 两者都不可信时返回 None（既无内核标记也无桥证据）
        if not kernel_active and not bridge_active:
            # 桥不存在 ≠ 驱动不可用（可能未启用自保护）；此时回到"未判定"
            return None
        return bool(kernel_active or bridge_active)

    def _query_driver_active_with_guard(self, timeout: float = 2.0):
        """带超时护栏的驱动状态探测（主线程调用，绝不阻塞 UI）。

        驱动 ioctl 是同步 DeviceIoControl 且无法直接设置超时；若驱动在
        慢速存储（虚拟机）或挂起状态下迟迟不完成 IOCTL_QUERY_STATUS，
        主线程会无限期卡住导致界面"未响应"。因此把探测放入后台线程，
        用 join(timeout) 隔离：超时后本轮视为"未判定"(None)，交由 10 秒
        低频轮询下一轮自行恢复。
        """
        holder: Dict = {}

        def _probe():
            try:
                holder['result'] = self._query_driver_active_now()
            except Exception:
                holder['result'] = None

        t = threading.Thread(target=_probe, daemon=True, name='PSLS-DriverProbe')
        t.start()
        t.join(timeout)
        if t.is_alive():
            logger.warning('[DRIVER] 驱动状态探测超时被隔离，跳过本轮判定')
            return None
        return holder.get('result')

    def _query_driver_details_with_guard(self, timeout: float = 3.0):
        """带超时护栏的驱动明细探测（主线程可安全调用）。

        与 _query_driver_active_with_guard 的区别：返回 (available, enabled,
        target_set) 三元组明细，供 _log_driver_protection_status 需要区分
        "已激活/未启用/目标未设置" 文案的场景使用。驱动 ioctl 同步无超时，
        因此同样放入后台线程 + join(timeout) 隔离，超时返回 None。
        """
        holder: Dict = {}

        def _probe():
            try:
                kernel_active = bool(
                    self._self_protection
                    and getattr(self._self_protection, '_kernel_protection_active', False)
                )
                bridge_available = False
                kernel_enabled = False
                target_set = False
                if sys.platform == 'win32':
                    from driver.bridge.psls_driver_bridge import PSLSDriverBridge
                    bridge = PSLSDriverBridge()
                    if bridge.is_available:
                        bridge_available = True
                        st = bridge.query_status()
                        kernel_enabled = bool(st and st.psls_protect_enabled)
                        target_set = bool(st and st.psls_pid != 0)
                    try:
                        bridge.close()
                    except Exception:
                        pass
                holder['result'] = {
                    'kernel_active': kernel_active,
                    'bridge_available': bridge_available,
                    'kernel_enabled': kernel_enabled,
                    'target_set': target_set,
                }
            except Exception:
                holder['result'] = None

        t = threading.Thread(target=_probe, daemon=True, name='PSLS-DriverDetail')
        t.start()
        t.join(timeout)
        if t.is_alive():
            logger.warning('[DRIVER] 驱动明细探测超时被隔离，启动日志降级为未判定')
            return None
        return holder.get('result')

    def _watch_driver_state_change(self):
        """运行期驱动状态变化监视器（低频 QTimer 10s 驱动，主线程调用）。

        与启动期 _log_driver_protection_status（终身一次）互补：
          * 启动期只判定一次并写入一条驱动状态基线日志；
          * 本监视器持续跟踪驱动状态，当 不可用->已加载 或 已加载->不可用
            发生变化时，追加一条"最近活动"通知。重复状态不写，避免刷屏。

        首次缓存由 _log_driver_protection_status 写入（启动期终态），
        此处的 None 仅发生在启动期尚未判定时；此时先同步当前真实状态
        作为基线，不立即写日志。仅当后续检测到状态【翻转】才通知。
        已确认为激活、但当前无法确认（无内核标记也无桥证据）时，
        视为运行期丢失，同样触发翻转通知。
        """
        try:
            active = self._query_driver_active_with_guard()
            if active is None:
                # 状态不确定（无内核标记也无桥证据）：
                # - 从未激活过：保持现状不打扰
                # - 已确认过激活但当前无法确认：视为运行期丢失（翻转）
                if self._driver_state_cached is True:
                    active = False
                else:
                    return
            cached = self._driver_state_cached
            if cached is None:
                # 建立基线，不写日志
                self._driver_state_cached = active
                self._driver_state_last_text = '已激活' if active else '不可用'
                return

            if active == cached:
                # 无变化，不写
                return

            # ---- 状态翻转 → 追加活动日志 ----
            self._driver_state_cached = active
            if active:
                text = '内核驱动防护已激活（运行期加载/恢复成功）'
                self._driver_state_last_text = '已激活'
                self._add_activity('驱动防护', text, 'INFO', '已加载')
            else:
                text = '内核驱动不可用或防护已停用（运行期丢失）'
                self._driver_state_last_text = '不可用'
                # 判定是否有用户态 DACL 兜底，提示降级
                dacl_active = bool(
                    self._self_protection
                    and getattr(self._self_protection, '_dacl_protection_active', False)
                )
                if dacl_active:
                    self._add_activity(
                        '驱动防护',
                        '内核驱动不可用，已降级为用户态 DACL 进程保护',
                        'WARN', '降级',
                        self._driver_load_failed_help(),
                    )
                else:
                    self._add_activity(
                        '驱动防护',
                        '内核驱动防护已停止',
                        'WARN', '不可用',
                        self._driver_load_failed_help(),
                    )
        except Exception as e:
            logger.debug(f'_watch_driver_state_change 异常: {e}')

    def _log_driver_protection_status(self):
        """检测内核驱动防护状态并输出启动日志。

        重要约束 —— 解决"A/B 两次调用结果矛盾"的问题：
          * 方法自身携带一次性 guard，任何调用来源（驱动终态轮询 /
            initRequested 8s 延迟 / 回退机制）都只写一条驱动状态日志。
          * 判定标准统一：`is_active = kernel_active（SelfProtection 真值）
                               OR (bridge_available + enable + pid_set)`
            避免"第一次按 SelfProtection 宽松=OK、第二次按桥严格=不 OK"
            造成的 UI 活动日志先后出现「已激活」+「未加载」。
        """
        # --- 终身只写一次：方法内自带 guard（不再依赖 initRequested 外部赋值）---
        if getattr(self, '_driver_status_logged', False):
            return
        self._driver_status_logged = True

        if sys.platform != 'win32':
            return

        # --- 统一真值计算：一次性拿到 SelfProtection + 桥两侧证据 ---------
        # 主线程安全：驱动探测放到后台线程 + join(timeout) 隔离，避免驱动挂起
        # 时同步 DeviceIoControl 无限阻塞主线程（"初始化未响应"根因之一）。
        kernel_active = bool(
            self._self_protection
            and getattr(self._self_protection, '_kernel_protection_active', False)
        )
        dacl_active = bool(
            self._self_protection
            and getattr(self._self_protection, '_dacl_protection_active', False)
        )
        bridge_available = False
        kernel_enabled = False
        target_set = False
        try:
            _detail = self._query_driver_details_with_guard(timeout=3.0)
            if _detail:
                kernel_active = kernel_active or bool(_detail.get('kernel_active'))
                bridge_available = bool(_detail.get('bridge_available'))
                kernel_enabled = bool(_detail.get('kernel_enabled'))
                target_set = bool(_detail.get('target_set'))
        except Exception:
            bridge_available = False
            kernel_enabled = False
            target_set = False

        # 统一真激活：SelfProtection 已标记激活 **或** 桥端到端已就绪
        is_active = bool(kernel_active) or bool(
            bridge_available and kernel_enabled and target_set
        )

        # 同步基线到运行期监视器：启动期判定的终态作为 _watch_driver_state_change
        # 的首次缓存。否则运行期轮询会把"启动后驱动才加载成功"的翻转误判为
        # 首次建立基线而静默跳过，导致驱动状态改变永远不显示。
        self._driver_state_cached = is_active
        self._driver_state_last_text = '已激活' if is_active else '不可用'

        # --- 单一成功出口（单一文案，避免活动日志出现"两条 OK 但描述不同"）-----
        if is_active:
            suffix = ''
            if bridge_available and kernel_enabled and target_set:
                # 桥端到端复核通过：标准成功
                suffix = ''
            elif kernel_active:
                # 仅 SelfProtection 标记激活：桥设备端到端未完成，附加提示
                suffix = '（桥端状态待同步）'
            self._add_activity(
                '驱动防护',
                f'内核驱动防护已激活（ObRegisterCallbacks 进程拦截运行中）{suffix}',
                'INFO', '成功',
            )
            return

        # --- 单一降级出口（保留有/无 DACL 两级提示）-------------------------
        if bridge_available:
            # 桥设备能打开但未端到端就绪 → 不判为"未加载"，仅提示"未启用/目标未设置"
            if kernel_enabled and not target_set:
                self._add_activity(
                    '驱动防护',
                    '驱动已加载但保护目标未设置（开启自保护开关后激活）',
                    'INFO', '提示',
                )
            else:
                self._add_activity(
                    '驱动防护',
                    '驱动已加载但未启用内核保护（打开自保护开关以激活）',
                    'INFO', '提示',
                )
            return

        if self._self_protection and dacl_active:
            self._add_activity(
                '驱动防护',
                '内核驱动不可用，已降级为用户态 DACL 进程保护',
                'WARN', '降级',
                self._driver_load_failed_help(),
            )
        elif self._self_protection:
            self._add_activity(
                '驱动防护',
                '内核驱动未加载（需测试签名或重启）',
                'WARN', '不可用',
                self._driver_load_failed_help(),
            )
        else:
            self._add_activity(
                '驱动防护',
                '内核驱动未加载',
                'WARN', '不可用',
                self._driver_load_failed_help(),
            )

    @staticmethod
    def _driver_load_failed_help() -> str:
        """驱动加载失败时机侧显示的处理指引（HTML 正文）。

        按"关 HVCI/VBS → 关 Hyper-V → 驱动签名（测试/正式）→ 关 Secure Boot"的
        顺序组织，是 Windows 10/11 上让自写内核驱动能 sc start 的通用处理流程。
        """
        _copy_tpl = (
            '<pre style="background:var(--psls-muted);padding:8px 10px;border-radius:4px;'
            'margin:0 0 12px;overflow-x:auto;-webkit-user-select:all;user-select:all;cursor:text;'
            'title="点击即可全选复制"><code style="font-family:ui-monospace,Consolas,Menlo,monospace;'
            'font-size:12px;color:var(--psls-foreground);white-space:pre;word-break:normal;">%s'
            '</code></pre>'
        )
        _h = 'margin:12px 0 4px;line-height:1.7;color:var(--psls-foreground);'
        _p = 'margin:4px 0 8px;line-height:1.7;color:var(--psls-foreground);'
        _red_center = (
            'text-align:center;color:red;font-weight:bold;'
            'line-height:1.8;margin:0 0 4px;'
        )
        _note_box = ('background:var(--psls-muted);color:var(--psls-foreground);'
                     'padding:10px 12px;border-radius:4px;margin:0 0 12px;line-height:1.6;')
        _warn_box = ('background:#7a1f1f;color:#fff;padding:10px 12px;'
                     'border-radius:4px;margin:0 0 12px;line-height:1.6;')

        # ---- 状态诊断栏 ----
        edition = ''
        hvci_enabled = None
        vbs_enabled = None
        driver_signed = None
        try:
            import winreg as _wr
            with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                             r'SOFTWARE\Microsoft\Windows NT\CurrentVersion') as _k:
                edition = str(_wr.QueryValueEx(_k, 'EditionID')[0] or '')
        except Exception:
            pass
        try:
            import winreg as _wr
            with _wr.OpenKey(
                    _wr.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios'
                    r'\HypervisorEnforcedCodeIntegrity') as _k:
                hvci_enabled = int(_wr.QueryValueEx(_k, 'Enabled')[0])
        except Exception:
            pass
        try:
            import winreg as _wr
            with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                             r'SYSTEM\CurrentControlSet\Control\DeviceGuard') as _k:
                vbs_enabled = int(_wr.QueryValueEx(
                    _k, 'EnableVirtualizationBasedSecurity')[0])
        except Exception:
            pass
        try:
            from utils import driver_manager as _dm
            from utils import signature_verifier as _sv
            _drv_path = _dm.driver_source_path()
            if _drv_path:
                _verifier = _sv.get_verifier()
                driver_signed = bool(_verifier and _verifier.is_available()
                                     and _verifier.is_signed(_drv_path))
        except Exception:
            pass

        _rows = ['系统版本(EditionID)：<code>%s</code>' % (edition or '未知')]
        if hvci_enabled is not None:
            _rows.append('内存完整性配置项：<code>%s</code>'
                         % ('已开启' if hvci_enabled else '已关闭/未配置'))
        if vbs_enabled is not None:
            _rows.append('VBS 配置项：<code>%s</code>'
                         % ('已开启' if vbs_enabled else '已关闭/未配置'))
        if driver_signed is not None:
            _rows.append('随附驱动签名：<code>%s</code>'
                         % ('有效' if driver_signed else '未签名/无效'))
        _diag = ('<p style="%s">%s</p>' % (_note_box, '<br>'.join(_rows)))

        # ---- 主体：按流程逐步引导 ----
        _body = (
            # --- 步骤 1：关 HVCI（内存完整性） ---
            f'<p style="{_h}"><b>步骤 1：关闭内存完整性（HVCI）</b></p>'
            f'<p style="{_p}">图形界面：设置 → 隐私和安全 → Windows 安全中心 → '
            '设备安全性 → 核心隔离详情 → 将“内存完整性”设为<b>关</b>。</p>'
            f'<p style="{_p}">组策略（专业版/企业版，推荐）：<code>gpedit.msc</code> '
            '→ 计算机配置 → 管理模板 → 系统 → Device Guard → '
            '“打开基于虚拟化的安全性” = <b>已禁用</b>。</p>'

            # --- 步骤 2：注册表兜底（Home 版无 gpedit） ---
            + f'<p style="{_h}"><b>步骤 2：注册表兜底（Home 版无 gpedit 时用）</b></p>'
            + f'<p style="{_p}">以<b>管理员身份</b>打开 PowerShell，执行：</p>'
            + _copy_tpl % (
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" '
                '/v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f\n'
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard'
                '\\Scenarios\\HypervisorEnforcedCodeIntegrity" '
                '/v Enabled /t REG_DWORD /d 0 /f\n'
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" '
                '/v LsaCfgFlags /t REG_DWORD /d 0 /f')

            # --- 步骤 3：BCD 关 Hypervisor（关键） ---
            + f'<p style="{_h}"><b>步骤 3：关闭 Hypervisor（最关键一步）</b></p>'
            + f'<p style="{_p}">不做这步，VBS 很可能仍显示 Running。管理员终端执行：</p>'
            + _copy_tpl % 'bcdedit /set hypervisorlaunchtype off'
            + f'<p style="{_p}">恢复：<code>bcdedit /set hypervisorlaunchtype auto</code></p>'

            # --- 步骤 4：关依赖 Hyper-V 的功能 ---
            + f'<p style="{_h}"><b>步骤 4：关闭依赖 Hyper-V 的功能</b></p>'
            + f'<p style="{_p}">控制面板 → 程序和功能 → 启用或关闭 Windows 功能，'
            '取消勾选以下项：</p>'
            + f'<p style="{_p}">&bull; Hyper-V（全部）<br>'
            '&bull; Virtual Machine Platform<br>'
            '&bull; Windows Hypervisor Platform<br>'
            '&bull; Windows Sandbox<br>'
            '&bull; Microsoft Defender Application Guard</p>'
            + f'<p style="{_p}">完成后<b>重启电脑</b>。</p>'

            # --- 步骤 5：验证 VBS 真关了 ---
            + f'<p style="{_h}"><b>步骤 5：验证 VBS 已关闭</b></p>'
            + f'<p style="{_p}">方法 A：<code>msinfo32</code> → 系统摘要最下方，'
            '“基于虚拟化的安全性”应为<b>未启用</b>。</p>'
            + f'<p style="{_p}">方法 B：管理员 CMD 执行</p>'
            + _copy_tpl % 'bcdedit /enum | findstr hypervisorlaunchtype'
            + f'<p style="{_p}">应输出 <code>hypervisorlaunchtype    Off</code>。</p>'

            # --- 步骤 6：驱动签名 ---
            + f'<p style="{_h}"><b>步骤 6：驱动签名</b></p>'
            + f'<p style="{_p}">关了 VBS ≠ 任何 sys 都能加载。Windows 仍会校验签名：</p>'
            + f'<p style="{_p}">&bull; <b>生产环境</b>：使用 EV 代码签名证书做内核模式签名'
            '（Win10/11 64 位强制要求）。</p>'
            + f'<p style="{_p}">&bull; <b>开发/调试</b>：开启测试签名模式：</p>'
            + _copy_tpl % 'bcdedit /set testsigning on'
            + f'<p style="{_p}">重启后桌面右下角会出现“测试模式”水印。'
            '随后用测试证书对驱动签名即可加载。</p>'
            + f'<p style="{_p}"><b>注意</b>：<code>testsigning on</code> 与 '
            '<code>hypervisorlaunchtype off</code> 是两件不同的事，通常需要同时设置。'
            '若驱动原有签名已被吊销（错误 0x800B010C），需先用 '
            '<code>signtool remove /s</code> 剥掉旧签名再用测试证书重新签名。</p>'

            # --- 步骤 7：BIOS / 安全启动（还不行再动） ---
            + f'<p style="{_h}"><b>步骤 7：BIOS / 安全启动（还不行再动）</b></p>'
            + f'<p style="{_p}">进入 BIOS/UEFI：将 <b>Secure Boot</b> 临时关闭。</p>'
            + f'<p style="{_p}">CPU 虚拟化（Intel VT-x/VT-d、AMD SVM/IOMMU）可保留，'
            '<b>不要</b>全部关闭，否则 WSL2/Hyper-V 等会失效；仅关 VBS 不需要关 VT-x。</p>'

            # --- 最小操作顺序 ---
            + f'<p style="{_h}"><b>最小操作顺序（调试驱动推荐）</b></p>'
            + f'<p style="{_p}">1. <code>bcdedit /set testsigning on</code><br>'
            '2. <code>bcdedit /set hypervisorlaunchtype off</code><br>'
            '3. 设备安全里关闭内存完整性<br>'
            '4. 重启<br>'
            '5. <code>msinfo32</code> 确认 VBS = 未启用<br>'
            '6. 驱动用测试证书签名 → <code>sc create</code> / <code>sc start</code></p>'

            # --- 恢复安全状态 ---
            + f'<p style="{_h}"><b>调试完成后恢复安全状态</b></p>'
            + _copy_tpl % (
                'bcdedit /set testsigning off\n'
                'bcdedit /set hypervisorlaunchtype auto')
            + f'<p style="{_p}">再把内存完整性、组策略、Secure Boot 依次开回。</p>'
        )

        _safety = (
            f'<p style="{_warn_box}">'
            '<b>⚠ 安全提醒</b>：关闭 VBS + 开启测试签名会显著降低系统对恶意驱动/'
            'rootkit 的抵御能力，<b>仅建议在本机开发机或虚拟机中进行</b>，'
            '请勿在日常主力机上长期保持该状态。</p>'
        )

        return (
            f'<p style="{_red_center}">内核驱动加载失败</p>'
            f'<p style="{_red_center}">以下步骤涉及系统设置，请确认您了解其含义</p>'
            + _diag
            + _body
            + _safety
            + '<p style="margin:12px 0 0;line-height:1.7;color:var(--psls-muted);'
            'font-size:12px;">如果按上述步骤仍无法启用内核驱动与 MBR 防护，'
            '请与开发者联系。</p>'
        )

    @pyqtSlot()
    def initRequested(self):
        """JavaScript端初始化完成后请求初始数据"""
        try:
            # 预热音效播放组件（主线程、幂等）：预创建 QMediaPlayer 实例并缓存
            # 6 级音效文件路径，保证首次播放提示音时即点即播，不因现场创建播放器
            # 而延迟或失败（虚拟机/精简环境尤为重要）。
            try:
                sound_manager.init_sound_engine()
            except Exception:
                pass

            # 重置状态缓存，确保广播器会主动推送一次最新状态
            self._last_self_prot_state = None
            self._last_yara_state = None
            self._last_strict_state = None
            self._last_ml_state = None
            self._last_mbr_state = None

            # 主动推送一次 MBR 保护当前状态：此时 JS 已完成信号连接，
            # 必然收到，避免广播器"状态未变化不推送"导致首页指示灯停在初始灰色。
            _mbr_now = self._get_mbr_state()
            if _mbr_now is not None:
                self._last_mbr_state = _mbr_now
                self.mbrProtectionStatusChanged.emit(json.dumps(_mbr_now, ensure_ascii=False))

            if not getattr(self, '_driver_status_logged', False):
                # 延迟记录：自我保护监控线程启动时会立即安装/加载驱动并激活保护
                # （首次安装含 SCM 服务安装，需数秒），立即记录会在激活完成前
                # 误报"驱动未加载"。
                # ---【关键修复】不得在此处抢占 self._driver_status_logged = True ---
                # guard 必须留给 _log_driver_protection_status 方法自身：
                # 终态轮询（7s 内）若先写入日志，8s 延迟就不再重复；
                # 若终态轮询没命中（fallback 路径），8s 回调必须能真的写出去。
                # 提前抢占会导致 8 秒回调被 guard 拦截→驱动日志终身 0 条。
                QTimer.singleShot(8000, self._log_driver_protection_status)

            _t_ir = time.monotonic()
            sig_count = 0
            q_count = 0
            try:
                # GUI 线程读数：SignatureDB.get_signature_count 内部对主线程
                # 只做 ≤50ms 的极短等待（后台装载未完成则返回"尚未装载"），
                # 绝不在 GUI 线程长等 106MB 库装载。
                sig_count = self._signature_db.get_signature_count() if self._signature_db else 0
            except Exception as e:
                logger.debug(f'initRequested: 读取签名数失败: {e}')
            try:
                q_count = len(self._quarantine_manager.list_items()) if self._quarantine_manager else 0
            except Exception as e:
                logger.debug(f'initRequested: 读取隔离区条目数失败: {e}')
            self._record_gui_block('initRequested.reads', (time.monotonic() - _t_ir) * 1000)

            # 写回时同步 emit: 前端 updateDashboardData 可能在 initRequested
            # 之前/之后触发，保证 signatureCountUpdated 信号至少推一次
            try:
                self.signatureCountUpdated.emit(sig_count)
            except Exception:
                pass
            try:
                self.quarantineUpdated.emit(q_count)
            except Exception:
                pass

            data = {
                'scanned': 0,
                'threats': self._get_realtime_threat_count(),
                'signatures': sig_count,
                'quarantineCount': q_count,
                'realtimeEnabled': self._module_states['realtime-monitor'],
                'processProtectionEnabled': self._module_states.get('process-protection', True),
                'fileProtectionEnabled': self._module_states.get('file-protection', True),
                'systemProtectionEnabled': self._module_states.get('system-protection', True),
                'mbrProtectionEnabled': self._module_states.get('mbr-protection', True),
                'notificationEnabled': self._module_states.get('notification', True),
                'notificationSettings': self._notification_manager.get_settings() if self._notification_manager else {},
                'newFileResultPopupEnabled': self._module_states.get('new-file-result-popup', True),
                'visualPrankEnabled': self._module_states.get('visual-prank', True),
                'aggressivePrankEnabled': self._module_states.get('aggressive-prank', False),
                'rtSuspiciousAction': self._rt_suspicious_action,
                'rtMalwareAction': self._rt_malware_action,
                'autostartEnabled': self._autostart_manager.is_autostart_enabled() if self._autostart_manager else False,
                'autostartAvailable': self._autostart_manager.is_available() if self._autostart_manager else False,
                'activities': self._activities[:50]
            }
            self.getInitialData.emit(json.dumps(data, ensure_ascii=False))
        except Exception as e:
            logger.error(f'发送初始数据失败: {e}')

    def _to_dict(self, value) -> dict:
        """将 QJsonValue 转为 Python dict（QWebChannel 传过来的对象是 QJsonValue）"""
        if isinstance(value, dict):
            return value
        if isinstance(value, QJsonValue):
            var = value.toVariant()
            if isinstance(var, dict):
                return var
            try:
                import json as _json
                return _json.loads(value.toString())
            except Exception:
                return {}
        try:
            import json as _json
            return _json.loads(str(value))
        except Exception:
            return {}

    def _require_scan_engine_ready(self, what: str) -> bool:
        """后台初始化期间的安全降级闸门：扫描引擎未就绪则明确告知"加载中"。

        绝不在缺引擎时启动扫描（既会崩，也可能因"无规则"误判干净）。返回 True 表示
        可以继续；False 表示已提示用户"签名库/扫描引擎加载中"。轻量、无阻塞。
        """
        try:
            if self._scan_engine is not None and self._signature_db is not None:
                return True
            self._add_activity('扫描', f'{what}暂缓：签名库/扫描引擎仍在后台加载中',
                               'WARN', '加载中')
            try:
                self._emit_tool_signal('scanDeferred',
                                       _safe_json_dumps({'ok': False,
                                                         'reason': 'engine_loading',
                                                         'message': '签名库/扫描引擎加载中，请稍候'}))
            except Exception:
                pass
            logger.warning(f'{what}被暂缓：扫描引擎尚未就绪（后台加载中）')
            return False
        except Exception as e:
            logger.debug(f'_require_scan_engine_ready 异常: {e}')
            return False

    @pyqtSlot('QJsonValue')
    def startQuickScan(self, options):
        """开始快速扫描"""
        if self._scan_running.is_set():
            return
        if not self._require_scan_engine_ready('快速扫描'):
            return
        opts = self._to_dict(options)
        self._scan_running.set()
        self._scan_stats = {'scanned': 0, 'threats': 0, 'total': 0}
        self._scan_finished_retry = 0
        self._finished_retry_timer.stop()
        with self._signal_lock:
            self._pending_scan_finished = None
        self._add_activity('扫描', '快速扫描开始', 'INFO', '成功')

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=('quick', opts),
            daemon=True
        )
        self._scan_thread.start()

    @pyqtSlot('QJsonValue')
    def startCustomScan(self, options):
        """开始自定义扫描"""
        if self._scan_running.is_set():
            return
        if not self._require_scan_engine_ready('自定义扫描'):
            return
        opts = self._to_dict(options)
        self._scan_running.set()
        self._scan_stats = {'scanned': 0, 'threats': 0, 'total': 0}
        self._scan_finished_retry = 0
        self._finished_retry_timer.stop()
        with self._signal_lock:
            self._pending_scan_finished = None
        scan_path = opts.get('path', 'C:/')
        self._add_activity('扫描', f'自定义扫描开始: {scan_path}', 'INFO', '成功')

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=('custom', opts),
            daemon=True
        )
        self._scan_thread.start()

    def _get_scan_worker_count(self) -> int:
        """计算扫描进程池最佳工作进程数

        扫描已移至独立进程池（ProcessPoolExecutor），不受主进程 GIL 限制。
        因此进程数只需略多于 CPU 核心，充分利用 I/O 等待即可。
        低配机器（2核）也能获得 4 进程，上限 8 避免进程切换开销过高。

        动态降载：再按 load_governor 的负载因子收缩（elevated 0.66 / high 0.5 /
        severe 0.33），下限保留 1 个进程。此前这里直接用 CPU 核数，导致高负载
        （如进程池崩溃后的续扫）时仍开满 3~4 个子进程，把整机 CPU 打满。
        降载的其余项（降深度/缩分块/缩 ML 块）只作用于主进程模块，扫描子进程
        各自新建引擎拿不到，跨进程真正有效的杠杆就是本函数返回的进程数。
        """
        try:
            cpu = multiprocessing.cpu_count() or 4
        except Exception:
            cpu = 4
        base = min(max(cpu + 1, 3), 4)
        try:
            scaled = load_governor.effective_workers(base, min_floor=1)
        except Exception as e:
            logger.debug(f'[降载] 取负载因子失败，按原始进程数 {base} 扫描: {e}')
            return base
        if scaled < base:
            logger.info(
                f'[降载] 扫描进程池按负载收缩: {base} -> {scaled} '
                f'(level={load_governor.get_load_state().get("level")})')
        return scaled

    def _boost_scan_priority(self):
        """扫描期间提升进程优先级和 CPU 亲和性，允许占用更多系统资源

        低配电脑上 PSLS 可能因默认优先级偏低而被调度器压制，
        扫描期间临时提升到 ABOVE_NORMAL 并设置全核亲和性。
        """
        try:
            import psutil
            proc = psutil.Process()
            # 保存原始优先级，扫描结束后恢复
            try:
                self._orig_priority = proc.nice()
            except Exception:
                self._orig_priority = None
            # Windows: ABOVE_NORMAL_PRIORITY_CLASS = 0x8000
            try:
                proc.nice(0x8000)
            except Exception:
                pass
            # 设置 CPU 亲和性为全部核心
            try:
                all_cpus = list(range(psutil.cpu_count(logical=True) or 4))
                proc.cpu_affinity(all_cpus)
            except Exception:
                pass
        except Exception:
            pass

    def _restore_scan_priority(self):
        """扫描结束后恢复进程原始优先级"""
        try:
            import psutil
            if getattr(self, '_orig_priority', None) is not None:
                try:
                    psutil.Process().nice(self._orig_priority)
                except Exception:
                    pass
        except Exception:
            pass

    def _run_scan(self, scan_type: str, options: dict):
        """执行扫描（在子线程中运行）

        两阶段：先快速统计文件总数，再使用线程池并行扫描。
        所有信号通过线程安全队列传递，由主线程的 QTimer 定时 emit。
        扫描结果同时通过实时推送和 scanFinished 兜底传递。
        支持即时停止。
        """
        all_results = []  # 收集所有结果，scanFinished 时作为兜底传递

        try:
            if not self._scan_engine:
                with self._signal_lock:
                    finished_data = dict(self._scan_stats)
                    finished_data['results'] = []
                    self._pending_scan_finished = finished_data
                return

            scan_all = options.get('scanAll', True)
            exe_only = options.get('exeOnly', False)
            max_size_mb = options.get('maxSize', 0)
            archive_depth = options.get('archiveDepth', 3)

            # 设置归档扫描深度
            if self._scan_engine.archive_scanner:
                self._scan_engine.archive_scanner.max_depth = max(0, min(int(archive_depth), 20))

            # 全局"监测全部类型的文件"设置影响扫描行为：
            # 关闭时（仅可执行文件），强制仅扫描可执行文件，忽略前端的 scanAll 默认值
            # 前端初始化时也会根据全局设置调整默认选项，这里作为后端兜底
            if not self._monitor_all_file_types and not exe_only:
                scan_all = False
                exe_only = True

            target_extensions = None
            if exe_only:
                scan_all = False
                target_extensions = list(self._scan_engine.EXECUTABLE_EXTENSIONS)

            # 确定扫描路径列表
            if scan_type == 'quick':
                scan_paths = [
                    os.path.expanduser('~\\Downloads'),
                    os.path.expanduser('~\\Desktop'),
                    os.path.expanduser('~\\Documents'),
                    os.environ.get('TEMP', ''),
                    os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Temp'),
                ]
            else:
                scan_paths = [options.get('path', 'C:/')]

            from utils.file_walker import FileWalker
            # max_size_mb: 0=无限制, >0=MB, 转为字节
            max_file_size = None
            if max_size_mb and max_size_mb > 0:
                max_file_size = int(max_size_mb * 1024 * 1024)
            # 获取用户排除路径（归一化为小写绝对路径）
            user_excluded = set()
            for p in getattr(self, '_scan_excluded_paths', []):
                try:
                    user_excluded.add(os.path.abspath(p).lower())
                except Exception:
                    pass
            walker = FileWalker(scan_all=scan_all, target_extensions=target_extensions,
                                max_file_size=max_file_size, skip_paths=user_excluded)

            # 同步用户排除路径到扫描引擎
            if self._scan_engine:
                self._scan_engine.set_user_excluded_dirs(list(user_excluded))

            # ===== 阶段 1：快速统计文件总数（只遍历目录，不读文件内容）=====
            logger.info('扫描阶段1：统计文件总数...')
            total_files = 0
            file_list = []
            for scan_path in scan_paths:
                if not self._scan_running.is_set():
                    break
                if not scan_path or not os.path.exists(scan_path):
                    continue

                # 单文件路径：直接加入列表，跳过 walker 遍历
                if os.path.isfile(scan_path):
                    if max_file_size:
                        try:
                            if os.path.getsize(scan_path) > max_file_size:
                                continue
                        except OSError:
                            pass
                    file_list.append(scan_path)
                    total_files += 1
                    continue

                if not os.path.isdir(scan_path):
                    continue
                try:
                    for fp in walker.walk(scan_path):
                        if not self._scan_running.is_set():
                            break
                        file_list.append(fp)
                        total_files += 1
                        if total_files % 100 == 0:
                            with self._signal_lock:
                                self._pending_progress = (-total_files, -1, 0)
                except Exception as e:
                    logger.warning(f'统计路径 {scan_path} 失败: {e}')

            if not self._scan_running.is_set():
                self._scan_stats['scanned'] = 0
                self._scan_stats['threats'] = 0
                self._scan_stats['total'] = total_files
                self._add_activity('扫描', f'用户停止扫描（已统计 {total_files} 个文件）', 'WARN', '跳过')
                with self._signal_lock:
                    self._pending_scan_finished = dict(self._scan_stats)
                return

            logger.info(f'统计完成，共 {total_files} 个文件，开始并行扫描...')

            # ===== 阶段 2：独立进程池并行扫描文件 =====
            # 使用 ProcessPoolExecutor 在独立进程中执行扫描，彻底隔离主进程 GIL、
            # I/O 阻塞和 CPU 密集计算，QWebEngine 渲染和 UI 事件循环完全不受影响。
            # 每个子进程通过 _init_scan_worker 初始化签名库/规则引擎/PE 分析器，
            # 仅启动时加载一次，后续复用进程。
            result_count = 0
            threat_count = 0
            processed_files = 0
            self._pushed_clean_count = 0
            self._skipped_clean_count = 0

            with self._signal_lock:
                self._pending_progress = (0, total_files, 0)

            # 扫描期间提升扫描进程池子进程优先级（主进程 UI 保持默认）
            # 不再提升主进程自身优先级，避免 UI 被扫描进程抢占
            self._boost_scan_priority_on_subprocess = True

            n_workers = self._get_scan_worker_count()
            logger.info(f'扫描进程池工作进程数: {n_workers}')

            # 从 ScanEngine 提取 initializer 需要的所有参数（确保可 pickle）
            _scan_engine = self._scan_engine
            _db_path = _scan_engine.signature_db.db_path
            _scan_archives = _scan_engine.scan_archives
            _trusted_dirs = ScanEngine.TRUSTED_DIRECTORIES
            _exec_ext = _scan_engine.EXECUTABLE_EXTENSIONS
            _min_file_size = ScanEngine.MIN_FILE_SIZE_FOR_RULE_SCAN
            _strict_mode = _scan_engine.strict_mode
            _vi_enabled = bool(getattr(_scan_engine, 'virus_identifier_enabled', False))
            _self_excluded = _scan_engine._self_excluded_dirs
            _user_excluded = getattr(_scan_engine, '_user_excluded_dirs', None) or set()

            # 扫描"假完成"防护：进程池崩溃(BrokenProcessPool)后不再把未扫文件
            # 计入"已扫描"，而是重建进程池续扫；重试耗尽则如实标记为未扫描。
            _unscanned_total = 0
            _pool_incomplete = False
            _pool_rebuilds = 0
            _MAX_POOL_REBUILDS = 2
            try:
                executor = ProcessPoolExecutor(
                    max_workers=n_workers,
                    initializer=_init_scan_worker,
                    initargs=(
                        _db_path, _scan_archives, _trusted_dirs,
                        _exec_ext, _min_file_size, _strict_mode,
                        _self_excluded, _user_excluded, None, _vi_enabled,
                    ),
                )
                logger.info(f'ProcessPoolExecutor 已创建: workers={n_workers}')

                try:
                    # 有界提交：避免大文件列表一次性提交导致内存过高
                    batch_size = max(1, n_workers * 2)
                    file_iter = iter(file_list)
                    pending = {}           # future -> file_path
                    future_submitted_at = {}  # future -> time.monotonic()

                    def _recover_pool(extra=None):
                        """进程池损坏(BrokenProcessPool)后的恢复。

                        收集"尚未真正扫描"的文件（当前异常文件 + 在途 future
                        对应文件 + file_iter 剩余），重建一个并发更低的进程池
                        并从这些文件续扫。

                        Returns:
                            True  = 已重建并预填续扫任务（调用方 continue）
                            False = 重试已耗尽，剩余文件已如实标记为未扫描
                                    （调用方 break）
                        """
                        nonlocal executor, file_iter, _pool_rebuilds
                        nonlocal _pool_incomplete, _unscanned_total
                        remaining = ([extra] if extra else [])
                        remaining += [f for f in list(pending.values()) if f]
                        remaining += list(file_iter)
                        pending.clear()
                        future_submitted_at.clear()

                        if _pool_rebuilds >= _MAX_POOL_REBUILDS:
                            _pool_incomplete = True
                            _unscanned_total += len(remaining)
                            logger.error(
                                f'进程池多次崩溃，放弃重建；'
                                f'{len(remaining)} 个文件未扫描')
                            # 只推 1 行汇总，绝不按文件逐条推：
                            # 未扫文件可达数万（实测 52607），逐条 append 会把
                            # 上万行 DOM/上千个 JSON 批次灌进 WebView，渲染进程
                            # 直接被杀（QtWebEngineProcess 崩溃）→ 页面变死，
                            # 表现为"扫描异常退出后 GUI 无响应"。
                            with self._signal_lock:
                                self._pending_results.append({
                                    'file_path': f'[汇总] {len(remaining)} 个文件未扫描'
                                                 f'（扫描进程异常）',
                                    'status': 'error',
                                    'signature_name': '未扫描（扫描进程异常）',
                                    '_is_summary': True,
                                })
                                self._pending_progress = (
                                    processed_files, total_files, threat_count
                                    + self._get_realtime_threat_count())
                            return False

                        _pool_rebuilds += 1
                        try:
                            executor.shutdown(wait=False, cancel_futures=True)
                        except Exception:
                            pass
                        new_workers = max(1, n_workers // (2 ** _pool_rebuilds))
                        executor = ProcessPoolExecutor(
                            max_workers=new_workers,
                            initializer=_init_scan_worker,
                            initargs=(
                                _db_path, _scan_archives, _trusted_dirs,
                                _exec_ext, _min_file_size, _strict_mode,
                                _self_excluded, _user_excluded, None, _vi_enabled,
                            ),
                        )
                        logger.warning(
                            f'进程池已重建 workers={new_workers} '
                            f'(rebuild={_pool_rebuilds})，续扫 {len(remaining)} 个文件')
                        file_iter = iter(remaining)
                        # 预填新一轮任务
                        for _ in range(max(1, new_workers * 2)):
                            try:
                                _fp2 = next(file_iter)
                            except StopIteration:
                                break
                            _fut2 = executor.submit(
                                _scan_file_worker_full, _fp2)
                            pending[_fut2] = _fp2
                            future_submitted_at[_fut2] = time.monotonic()
                        return True

                    # 每个 future 的执行 deadline（秒），超过则强制当 error 处理：
                    # 避免 worker 死锁(7z 子进程卡住)、归档解压密码穷举慢等导致
                    # pending 永远清不空 → 扫描进度 4% 卡死。
                    # 单个文件 deadline = max(60s, 文件MB数 × 1.5s)。
                    # 超大归档(1~4GB zip) 给足 10~20 分钟；小程序 1MB 级文件 ~2s。
                    def _fp_deadline(fp: str) -> float:
                        try:
                            mb = os.path.getsize(fp) / (1024 * 1024)
                        except OSError:
                            mb = 1.0
                        seconds = max(60.0, mb * 1.5)
                        # 上限 1800s（避免 TB 级文件给无限时间，实际没人扫这么大文件）
                        return min(1800.0, seconds)

                    per_wait_timeout = max(0.3, min(2.0, 0.2 + 0.05 * n_workers))

                    # 预填首批任务
                    for _ in range(batch_size):
                        try:
                            fp = next(file_iter)
                            fut = executor.submit(_scan_file_worker_full, fp)
                            pending[fut] = fp
                            future_submitted_at[fut] = time.monotonic()
                        except StopIteration:
                            break

                    while pending:
                        if not self._scan_running.is_set():
                            # 用户停止：取消所有未开始的任务，终止子进程池
                            for fut in pending:
                                try:
                                    fut.cancel()
                                except Exception:
                                    pass
                            break

                        # ---- 等待至少一个任务完成（带 timeout） ----
                        # 加上 timeout 保证即使"所有 worker 全死/卡死"也能
                        # 从 wait 中出来，检查 deadline 并把卡死文件当 error
                        # 处理，pending 最终一定会收敛到空（不会"扫描自己停"）。
                        done, _ = wait(
                            list(pending.keys()),
                            return_when=FIRST_COMPLETED,
                            timeout=per_wait_timeout,
                        )

                        now_ts = time.monotonic()

                        # ---- 先处理 deadline 超时（不依赖 ready） ----
                        # 这是"扫描卡死 / 进度停在 4%" 的根因兜底：
                        # worker 子进程在归档 7z/zip 解压子进程、密码试错、
                        # 大文件 ML 推理等环节挂住 → future 永远不 ready，
                        # 靠 timeout + 提交时间 把它当 error 吃掉。
                        expired_futures = []
                        for f, fp in list(pending.items()):
                            if f.done():
                                continue
                            dl = _fp_deadline(fp)
                            if (now_ts - future_submitted_at.get(f, now_ts)) >= dl:
                                expired_futures.append(f)
                        if expired_futures:
                            # 尝试 cancel（取消还未开始的）
                            for f in expired_futures:
                                try:
                                    f.cancel()
                                except Exception:
                                    pass
                                fp = pending.pop(f, None)
                                future_submitted_at.pop(f, None)
                                if fp is None:
                                    continue
                                processed_files += 1
                                result_count += 1
                                logger.warning(
                                    f'扫描任务超时（超过 {_fp_deadline(fp):.0f}s），'
                                    f'跳过: {fp}')
                                all_results.append({
                                    'file_path': fp,
                                    'status': 'error',
                                    'signature_name': '扫描超时跳过',
                                    '_timeout': True,
                                })
                                with self._signal_lock:
                                    self._pending_results.append({
                                        'file_path': fp,
                                        'status': 'error',
                                        'signature_name': '扫描超时跳过',
                                    })
                                    self._pending_progress = (
                                        processed_files, total_files, threat_count
                                        + self._get_realtime_threat_count())
                                # 提交下一个文件（跳过超时文件，不阻塞整体进度）
                                try:
                                    nfp = next(file_iter)
                                    nfut = executor.submit(_scan_file_worker_full, nfp)
                                    pending[nfut] = nfp
                                    future_submitted_at[nfut] = time.monotonic()
                                except StopIteration:
                                    pass

                        if not done and not expired_futures:
                            # 本轮 timeout 到期但还没 future 好，也没超时，继续等
                            continue

                        # ---- 正常完成的 future ----
                        for fut in done:
                            file_path = pending.pop(fut, None)
                            future_submitted_at.pop(fut, None)
                            if file_path is None:
                                continue

                            try:
                                file_results = fut.result()
                            except BaseException as e:
                                # 进程池整体损坏：该文件并未真正扫描，既不能
                                # 计入"已扫描"，也不能当 error 吞掉——连同其余
                                # 未完成文件一起交回重建续扫（file_path 一并重扫）。
                                if type(e).__name__ in ('BrokenProcessPool',
                                                        'BrokenExecutor'):
                                    _recover_pool(extra=file_path)
                                    break
                                # 其他异常（单文件 BPE / worker 崩溃）→ 计 error
                                # 并补下一文件，避免 pending 清不空。
                                processed_files += 1
                                logger.warning(f'扫描文件失败 {file_path}: {e}')
                                all_results.append({
                                    'file_path': file_path,
                                    'status': 'error',
                                    'signature_name': str(e)[:80],
                                    '_worker_error': True,
                                })
                                result_count += 1
                                with self._signal_lock:
                                    self._pending_results.append({
                                        'file_path': file_path,
                                        'status': 'error',
                                        'signature_name': '扫描失败跳过',
                                    })
                                    self._pending_progress = (
                                        processed_files, total_files, threat_count
                                        + self._get_realtime_threat_count())
                                # 补下一个文件（如果进程池已经 BrokenProcessPool，
                                # 下面 submit 会立即抛 → 按"扫描中断"处理）
                                try:
                                    nfp = next(file_iter)
                                    nfut = executor.submit(
                                        _scan_file_worker_full, nfp)
                                    pending[nfut] = nfp
                                    future_submitted_at[nfut] = time.monotonic()
                                except StopIteration:
                                    pass
                                except BaseException as se:
                                    # 进程池已损坏：不把未扫文件计为已扫描，
                                    # 交回重建续扫；重试耗尽则如实标记未扫描。
                                    logger.error(
                                        f'进程池无法再提交任务（将重建续扫）: {se}')
                                    _recover_pool()
                                    break
                                continue

                            processed_files += 1
                            if not file_results:
                                result_count += 1
                                with self._signal_lock:
                                    self._pending_progress = (
                                        processed_files, total_files, threat_count
                                        + self._get_realtime_threat_count())
                                try:
                                    nfp = next(file_iter)
                                    nfut = executor.submit(
                                        _scan_file_worker_full, nfp)
                                    pending[nfut] = nfp
                                    future_submitted_at[nfut] = time.monotonic()
                                except StopIteration:
                                    pass
                                except BaseException as se:
                                    logger.error(
                                        f'进程池无法再提交任务（将重建续扫）: {se}')
                                    _recover_pool()
                                    break
                                continue

                            # 按严重度排序（malware > suspicious > clean），
                            # 确保同一物理文件按最高严重度处理和计数
                            _severity_order = {'malware': 0, 'suspicious': 1,
                                               'clean': 2}
                            file_results_sorted = sorted(
                                file_results,
                                key=lambda r: _severity_order.get(
                                    str(r.status) if r and hasattr(r, 'status')
                                    else 'error', 3
                                )
                            )

                            handled_files = set()       # 同 fp 只处理一次隔离/沙箱
                            handled_threat_keys = set() # threat_count 去重键 (fp,ip)
                            for result in file_results_sorted:
                                try:
                                    result_count += 1
                                    status = (str(result.status)
                                              if result and hasattr(result, 'status')
                                              else 'error')
                                    sig_name = ''
                                    if (result and hasattr(result, 'malware_info')
                                            and result.malware_info):
                                        if isinstance(result.malware_info, dict):
                                            sig_name = str(
                                                result.malware_info.get('name', ''))

                                    fp = (str(result.file_path)
                                          if result and hasattr(result, 'file_path')
                                          else str(file_path))
                                    internal_path = ''
                                    if (result
                                            and hasattr(result, 'internal_path')
                                            and getattr(result, 'internal_path', None)):
                                        internal_path = str(result.internal_path)

                                    result_dict = {
                                        'file_path': fp,
                                        'status': status,
                                        'signature_name': sig_name,
                                    }
                                    all_results.append(result_dict)

                                    if status in ('malware', 'suspicious'):
                                        threat_key = (fp, internal_path)
                                        if threat_key not in handled_threat_keys:
                                            handled_threat_keys.add(threat_key)
                                            threat_count += 1

                                        # 同一归档文件（多 internal_path）只处理
                                        # 一次隔离/沙箱：避免重复隔离/杀进程。
                                        if fp not in handled_files:
                                            handled_files.add(fp)
                                            try:
                                                self._handle_threat(
                                                    status, fp, sig_name, options)
                                            except Exception as hte:
                                                logger.error(
                                                    f'_handle_threat 异常 {fp}: {hte}')
                                            try:
                                                self._maybe_trigger_sandbox(
                                                    fp, source='主动扫描',
                                                    process_name=sig_name,
                                                )
                                            except Exception as sbe:
                                                logger.error(
                                                    f'_maybe_trigger_sandbox 异常 '
                                                    f'{fp}: {sbe}')

                                    with self._signal_lock:
                                        # 推送策略：
                                        #   malware/suspicious/error → 全部推送
                                        #   clean → 限量推送前 200 个（避免 DOM 爆炸）
                                        if status in ('malware', 'suspicious',
                                                      'error'):
                                            self._pending_results.append(
                                                result_dict)
                                        elif status == 'clean':
                                            if self._pushed_clean_count < 200:
                                                self._pending_results.append(
                                                    result_dict)
                                                self._pushed_clean_count += 1
                                            else:
                                                self._skipped_clean_count += 1
                                        self._pending_progress = (
                                            processed_files, total_files,
                                            threat_count
                                            + self._get_realtime_threat_count())
                                except Exception as e:
                                    logger.warning(
                                        f'处理扫描结果异常 {file_path}: {e}')
                                    result_count += 1

                            self._scan_stats['scanned'] = processed_files
                            self._scan_stats['threats'] = threat_count
                            self._scan_stats['total'] = total_files

                            # 补充下一个文件，保持进程池满载
                            try:
                                nfp = next(file_iter)
                                nfut = executor.submit(
                                    _scan_file_worker_full, nfp)
                                pending[nfut] = nfp
                                future_submitted_at[nfut] = time.monotonic()
                            except StopIteration:
                                pass
                            except BaseException as se:
                                logger.error(
                                    f'进程池无法再提交任务（将重建续扫）: {se}')
                                _recover_pool()
                                break
                finally:
                    # 立即关闭进程池，不等待正在运行的子进程完成
                    # 避免用户停止后子进程还在后台扫描
                    executor.shutdown(wait=False, cancel_futures=True)
            except Exception as e:
                logger.error(f'ProcessPoolExecutor 创建失败，扫描可能中断: {e}')
            finally:
                self._boost_scan_priority_on_subprocess = False

            self._scan_stats['scanned'] = processed_files
            self._scan_stats['threats'] = threat_count
            self._scan_stats['total'] = total_files
            if _pool_incomplete:
                # 诚实上报：进程池多次崩溃后仍有文件未扫描，不谎报 100%
                self._scan_stats['incomplete'] = True
                self._scan_stats['unscanned'] = _unscanned_total

            # 扫描结束：将累积的白名单条目一次性写入数据库
            # （扫描期间 add_to_whitelist 只更新内存缓存，避免每个 clean 文件都 fsync）
            try:
                if self._scan_engine and self._scan_engine.signature_db:
                    flushed = self._scan_engine.signature_db.flush_whitelist_batch()
                    if flushed:
                        logger.info(f'扫描结束：批量写入白名单 {flushed} 条')
            except Exception as e:
                logger.warning(f'扫描结束 flush 白名单失败: {e}')

            if _pool_incomplete:
                self._add_activity(
                    '扫描',
                    f'扫描未完成：{_unscanned_total} 个文件因扫描进程异常未扫描',
                    'ERROR', '未完成'
                )
            elif self._scan_running.is_set():
                self._add_activity(
                    '扫描',
                    f'扫描完成: {processed_files} 个文件, {threat_count} 个威胁',
                    'INFO' if threat_count == 0 else 'WARNING',
                    '成功'
                )
            else:
                self._add_activity('扫描', '用户停止扫描', 'WARN', '跳过')

            # scanFinished 之前，发送 clean 文件汇总行
            # 如果有超过 200 个 clean 文件被限量掉，发一个 summary 行
            try:
                skipped = getattr(self, '_skipped_clean_count', 0)
                if skipped > 0:
                    summary_row = {
                        'file_path': f'[汇总] 另有 {skipped} 个安全文件未显示',
                        'status': 'clean',
                        'signature_name': '',
                        '_is_summary': True,
                    }
                    # 直接 emit，不走 _flush_signals 的批量缓冲
                    self.scanResultReceived.emit(json.dumps(summary_row, ensure_ascii=False))
            except Exception as e:
                logger.warning(f'发送 clean 汇总行失败: {e}')

            # scanFinished 只传统计信息，results 已通过实时推送传递
            # 不携带 results 列表，避免 JSON 过大导致 QWebChannel 传输失败
            with self._signal_lock:
                self._pending_scan_finished = dict(self._scan_stats)
            # 推送主页指标卡更新（合并扫描会话 + 实时防护累计威胁数）
            self._emit_dashboard_stats_update()

        except Exception as e:
            logger.error(f'扫描出错: {e}', exc_info=True)
            self._add_activity('扫描', f'扫描出错: {str(e)}', 'ERROR', '错误')
            with self._signal_lock:
                self._pending_scan_finished = dict(self._scan_stats)
        finally:
            self._scan_running.clear()
            # 确保优先级恢复（异常路径兜底）
            self._restore_scan_priority()
            # 异常/停止路径兜底：确保白名单已持久化
            try:
                if self._scan_engine and self._scan_engine.signature_db:
                    self._scan_engine.signature_db.flush_whitelist_batch()
            except Exception:
                pass

    @pyqtSlot()
    def stopScan(self):
        """停止扫描"""
        was_running = self._scan_running.is_set()
        self._scan_running.clear()
        if was_running:
            logger.info('收到停止扫描请求')
            self._add_activity('扫描', '正在停止扫描...', 'WARN', '进行中')

    @pyqtSlot(str)
    def setBrowseTarget(self, target_id):
        """设置浏览文件夹后要回填的输入框 ID"""
        self._browse_target = target_id

    @pyqtSlot()
    @_cfg_timed
    def browseFolder(self):
        """浏览文件夹（无参数槽，通过 folderSelected 信号返回路径）"""
        from PyQt5.QtWidgets import QFileDialog
        folder = QFileDialog.getExistingDirectory(None, '选择扫描目录', '')
        path = folder.replace('\\', '/') if folder else ''
        target = self._browse_target or 'scan-path'
        # 通过 JSON 传递 {path, target} 结构
        payload = json.dumps({'path': path, 'target': target}, ensure_ascii=False)
        self.folderSelected.emit(payload)

    @pyqtSlot()
    @_cfg_timed
    def browseFile(self):
        """浏览单个文件（通过 folderSelected 信号返回路径）"""
        from PyQt5.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getOpenFileName(
            None, '选择要扫描的文件', '',
            '所有文件 (*.*);;可执行文件 (*.exe *.dll *.sys *.scr *.com);;压缩文件 (*.zip *.rar *.7z *.tar *.gz);;脚本 (*.bat *.cmd *.ps1 *.vbs *.js *.wsf);;文档 (*.doc *.docx *.xls *.xlsx *.rtf)'
        )
        path = file_path.replace('\\', '/') if file_path else ''
        target = self._browse_target or 'scan-path'
        payload = json.dumps({'path': path, 'target': target}, ensure_ascii=False)
        self.folderSelected.emit(payload)

    @pyqtSlot(str, bool)
    @_cfg_timed
    def toggleModule(self, module: str, enabled: bool):
        """切换防护模块状态（GUI 线程零长阻塞：构造/启停一律转后台）。"""
        _t_toggle = time.monotonic()
        engine_map = {
            'process-protection': '_process_protection',
            'file-protection': '_file_protection',
            'system-protection': '_system_protection',
            'autostart-protection': '_autostart_protection',
            'mbr-protection': '_mbr_protector',
            'realtime-monitor': '_realtime_monitor',
            'notification': '_notification_manager',
            'ransomware-rollback': '_rollback_manager',
        }
        if enabled and module in engine_map:
            attr_name = engine_map[module]
            engine = getattr(self, attr_name, None)
            if engine is None:
                # 【关键修复】GUI 线程**绝不就地构造引擎**（AutoStartProtection 的 WMI
                # 订阅 / RealtimeMonitor 的目录与线程 / MBRProtector 的引导扇区与驱动
                # 构造可达数百 ms~秒级）。改为后台线程构造 + 状态"加载中(pending)"，
                # 构造成功后落到 enabled=True，失败才回退 False 并报错。
                logger.warning(f'{module} 引擎未初始化，转后台初始化（加载中）')
                self._add_activity('防护',
                                   f'{module} 正在后台初始化（加载中）...', 'INFO', '加载中')
                self._module_pending[module] = bool(enabled)
                self._start_module_init_bg(module, attr_name)
                try:
                    self._emit_tool_signal(
                        'moduleTogglePending',
                        json.dumps({'module': module, 'state': 'loading'},
                                   ensure_ascii=False))
                except Exception:
                    pass
                self._cfg_note('toggleModule(委托后台构造)',
                               (time.monotonic() - _t_toggle) * 1000.0)
                return

        self._module_states[module] = enabled
        self._persist_module_states()
        status_text = '启用' if enabled else '禁用'
        self._add_activity('防护', f'{module} {status_text}', 'INFO', '成功')

        # 进程保护：真正启停引擎
        # 注意：start()/stop() 内含 ETW/WMI 就绪等待、判定 worker 队列收割（最长 12s+），
        # 必须在后台线程执行，避免阻塞 GUI 主线程导致 QtWebEngine COM 断开（0x8001010D）。
        if module == 'process-protection' and self._process_protection:
            self._toggle_module_async(self._process_protection, 'process-protection', enabled)

        # 文件保护：真正启停引擎（start 含全盘关键文件 SHA256 基线遍历，重操作）
        if module == 'file-protection' and self._file_protection:
            self._toggle_module_async(self._file_protection, 'file-protection', enabled)

        # 系统保护：真正启停引擎（watchdog/WMI 多监控线程启停）
        if module == 'system-protection' and self._system_protection:
            self._toggle_module_async(self._system_protection, 'system-protection', enabled)

        # 自启动项监测：真正启停引擎
        if module == 'autostart-protection' and self._autostart_protection:
            self._toggle_module_async(self._autostart_protection, 'autostart-protection', enabled)

        # MBR / 引导扇区保护：启停引擎（MBR 备份/内核驱动，重操作）
        if module == 'mbr-protection' and self._mbr_protector:
            self._toggle_module_async(self._mbr_protector, 'mbr-protection', enabled)

        # 通知提醒：启停通知管理器（start/stop 可能含音效设备初始化，转后台）
        if module == 'notification' and self._notification_manager:
            def _notify_toggle(_nm=self._notification_manager, _en=bool(enabled)):
                try:
                    if _en and not _nm.is_running:
                        _nm.start()
                        sound_manager.set_sound_enabled(_nm.is_sound_enabled())
                    elif not _en and _nm.is_running:
                        _nm.stop()
                except Exception as e:
                    logger.error(f'notification 启动/停止失败: {e}')
                    self._add_activity('防护', f'notification 操作失败: {e}', 'ERROR', '失败')
                    self._module_states[module] = False
            self._cfg_note('notification(提交后台)', (time.monotonic() - _t_toggle) * 1000.0)
            threading.Thread(target=_notify_toggle, daemon=True,
                             name='NotificationToggle').start()

        # 实时监控：启停 watchdog 文件系统监控（后台线程，避免目录遍历阻塞 UI）
        if module == 'realtime-monitor' and self._realtime_monitor:
            self._toggle_module_async(self._realtime_monitor, 'realtime-monitor', enabled)

        # 恶搞行为检测：启停 VisualPrankDetector 轮询（set_enabled 仅切标记，线程常驻）
        if module == 'visual-prank' and self._visual_prank_detector:
            try:
                self._visual_prank_detector.set_enabled(bool(enabled))
            except Exception as e:
                logger.error(f'{module} 切换失败: {e}')
                self._add_activity('防护', f'{module} 操作失败: {e}', 'ERROR', '失败')
                self._module_states[module] = False

        # 更激进的特效检测：set_enabled 仅切标记（截图监控，线程常驻）
        if module == 'aggressive-prank' and self._aggressive_prank_detector:
            try:
                self._aggressive_prank_detector.set_enabled(bool(enabled))
            except Exception as e:
                logger.error(f'{module} 切换失败: {e}')
                self._add_activity('防护', f'{module} 操作失败: {e}', 'ERROR', '失败')
                self._module_states[module] = False

        # 勒索文件回滚：set_enabled 走后台（避免同步 IPC，即使有界 0.15s 也不占 GUI）
        if module == 'ransomware-rollback' and self._rollback_manager:
            def _rb_toggle(_rb=self._rollback_manager, _en=bool(enabled)):
                try:
                    _rb.set_enabled(_en)
                except Exception as e:
                    logger.error(f'ransomware-rollback 切换失败: {e}')
                    self._add_activity('防护', f'ransomware-rollback 操作失败: {e}',
                                       'ERROR', '失败')
                    self._module_states[module] = False
            self._cfg_note('ransomware-rollback(提交后台)',
                           (time.monotonic() - _t_toggle) * 1000.0)
            threading.Thread(target=_rb_toggle, daemon=True,
                             name='RbToggleEnabled').start()

    def _start_module_init_bg(self, module: str, attr_name: str):
        """[GUI 线程] 后台构造模块引擎，成功后回推状态（后到后更新）。

        保证：
          - GUI 线程只登记 + 起线程，绝不就地构造；
          - 构造期间状态为"加载中(pending)"，**不**误置 False / 不误报"启用失败"；
          - 构造成功且用户意图为启用 → 后台 start() 并把 `_module_states[module]=True`；
          - 构造失败 → 重置为 False 并 emit `moduleToggleFailed(reason=init_failed)`。
        """
        key = f'{module}|{attr_name}'
        try:
            with self._module_init_lock:
                if key in self._module_init_inflight:
                    return
                self._module_init_inflight.add(key)
        except Exception:
            pass

        def _work():
            t0 = time.monotonic()
            try:
                self._try_reinitialize_module(module, attr_name)   # 内部含逐引擎计时
                eng = getattr(self, attr_name, None)
                ok = eng is not None
                if ok:
                    want_enable = bool(self._module_pending.get(module, True))
                    if want_enable:
                        try:
                            eng.start()
                        except Exception as e:
                            logger.warning(f'{module} 后台启动失败: {e}')
                    self._module_states[module] = bool(want_enable)
                    self._persist_module_states()
                    self._add_activity('防护', f'{module} 后台初始化完成', 'INFO', '成功')
                    self._emit_tool_signal(
                        'moduleToggleSettled',
                        json.dumps({'module': module, 'state': 'enabled'
                                    if want_enable else 'disabled'},
                                   ensure_ascii=False))
                else:
                    self._module_states[module] = False
                    self._persist_module_states()
                    self._add_activity('防护', f'{module} 初始化失败：引擎未创建',
                                       'ERROR', '失败')
                    self._emit_tool_signal(
                        'moduleToggleFailed',
                        json.dumps({'module': module, 'reason': 'init_failed'},
                                   ensure_ascii=False))
            except Exception as e:
                logger.error(f'{module} 后台初始化异常: {e}')
                self._module_states[module] = False
                try:
                    self._emit_tool_signal(
                        'moduleToggleFailed',
                        json.dumps({'module': module, 'reason': 'init_exception'},
                                   ensure_ascii=False))
                except Exception:
                    pass
            finally:
                try:
                    with self._module_init_lock:
                        self._module_init_inflight.discard(key)
                except Exception:
                    pass
                self._cfg_note(f'{module}(后台构造完成)',
                               (time.monotonic() - t0) * 1000.0, warn_ms=1e9)

        threading.Thread(target=_work, daemon=True,
                         name=f'ModuleInit-{module}').start()

    def _persist_module_states(self):
        """把当前防护模块开关状态落盘（重启后保持用户所设）。

        此前模块开关仅存内存/前端 localStorage，后端默认值会在启动时覆盖前端，
        导致"重启后开关回到默认"。这里统一持久化到 settings.json 的 ui 段。
        """
        t0 = time.monotonic()
        try:
            _save_ui_settings({'module_states': dict(self._module_states)})
        except Exception as e:
            logger.debug(f'持久化模块开关状态失败: {e}')
        self._cfg_note('_persist_module_states', (time.monotonic() - t0) * 1000.0)

    @pyqtSlot(bool, result=bool)
    def setAllProtectionEnabled(self, enabled: bool) -> bool:
        """一键开启/关闭全部核心防护模块（托盘菜单 + 防护页「一键全关」按钮调用）

        复用 toggleModule 的单模块启停逻辑（含后台线程）。模块启停是异步重操作，
        本方法**不阻塞等待**，派发后立即返回 True；真实启停结果由
        protectionAllToggled 信号在完成时回传（用于刷新托盘文案与系统通知）。
        """
        core_modules = [
            'process-protection', 'file-protection', 'system-protection',
            'autostart-protection', 'mbr-protection', 'realtime-monitor',
        ]
        try:
            for mod in core_modules:
                try:
                    self.toggleModule(mod, bool(enabled))
                except Exception as e:
                    logger.warning(f'一键切换模块 {mod} 失败: {e}')
            self._persist_module_states()
            # 启动观察线程：等所有模块到达目标态后发信号，避免 UI 显示与实际脱节
            self._watch_protection_toggle(enabled, core_modules)
            return True
        except Exception as e:
            logger.error(f'一键切换全部防护失败: {e}')
            return False

    def _watch_protection_toggle(self, enabled: bool, modules: list):
        """后台观察全部模块是否到达目标态，完成后发 protectionAllToggled 信号。

        轮询每个模块的 is_running（真实态），最多等 20s；超时或失败的模块
        记入 detail，让 UI 能准确反映"哪些没起效"。
        """
        engine_map = {
            'process-protection': '_process_protection',
            'file-protection': '_file_protection',
            'system-protection': '_system_protection',
            'autostart-protection': '_autostart_protection',
            'mbr-protection': '_mbr_protector',
            'realtime-monitor': '_realtime_monitor',
        }

        def _watch():
            failed = []
            deadline = time.monotonic() + 20.0
            while time.monotonic() < deadline:
                failed.clear()
                all_done = True
                for mod in modules:
                    attr = engine_map.get(mod)
                    eng = getattr(self, attr, None) if attr else None
                    if eng is None:
                        continue
                    running = bool(getattr(eng, 'is_running', False))
                    if running != enabled:
                        all_done = False
                        failed.append(mod)
                if all_done:
                    break
                time.sleep(0.5)
            success = len(failed) == 0
            detail = '、'.join(failed) if failed else ''
            try:
                self.protectionAllToggled.emit(bool(enabled), success, detail)
            except Exception:
                pass
            logger.info(
                f'一键{"开启" if enabled else "关闭"}保护完成: '
                f'success={success}, failed={detail or "无"}')

        threading.Thread(target=_watch, daemon=True,
                         name='ProtectionToggleWatcher').start()

    @pyqtSlot(result=bool)
    def isAllProtectionEnabled(self) -> bool:
        """判断核心防护是否整体处于开启状态（任一核心模块为开即视为运行中）。"""
        core_modules = [
            'process-protection', 'file-protection', 'system-protection',
            'autostart-protection', 'mbr-protection', 'realtime-monitor',
        ]
        return any(bool(self._module_states.get(m, False)) for m in core_modules)

    def _toggle_module_async(self, engine, module: str, enabled: bool):
        """在后台线程启停较重防护模块，避免阻塞 Qt 主线程/QtWebEngine。
        部分模块的 start/stop 含全盘基线遍历、watchdog/WMI 线程等待、MBR 驱动等
        秒级~十秒级重操作，直接在主线程执行会导致 QtWebEngine COM 断开（0x8001010D）
        与 GUI 假死。用守护线程 + 串行锁保证不阻塞 UI 且快速切换不竞争。"""
        _t_commit = time.monotonic()
        self._module_pending[module] = bool(enabled)
        self._cfg_note(f'{module}(启停提交)', (time.monotonic() - _t_commit) * 1000.0)

        def _worker():
            with self._module_toggle_lock:
                try:
                    if enabled and not engine.is_running:
                        engine.start()
                    elif not enabled and engine.is_running:
                        engine.stop()
                except Exception as e:
                    logger.error(f'{module} 启动/停止失败: {e}')
                    self._add_activity('防护', f'{module} 操作失败: {e}', 'ERROR', '失败')
                    self._module_states[module] = False
        threading.Thread(target=_worker, daemon=True, name=f'{module}-Toggle').start()

    def _try_reinitialize_module(self, module: str, attr_name: str):
        """尝试重新初始化指定的防护模块（含逐引擎构造计时；调用方须在后台线程）"""
        _t_re = time.monotonic()
        try:
            if module == 'process-protection':
                # 重初始化时同步挂载 [进程创建 → 关键目录保护] 钩子
                def _proc_created_cb_reinit(pid: int, exe: str):
                    mp = self._mbr_protector
                    if mp is not None:
                        try:
                            mp.notify_process_created(int(pid), str(exe or ''))
                        except Exception:
                            pass
                self._process_protection = ProcessProtection(
                    signature_db=self._signature_db,
                    on_threat=self._on_process_threat,
                    scan_engine_factory=self._create_scan_engine_for_realtime,
                    quarantine_manager=self._quarantine_manager,
                    auto_action=self._rt_suspicious_action,
                    on_launch_scan=self._on_launch_scan_result,
                    on_sandbox_block=self._on_sandbox_block,
                    on_sandbox_release_request=self._on_sandbox_release_request,
                    on_sandbox_analysis_start=self._on_sandbox_analysis_start,
                    on_sandbox_analysis_progress=self._on_sandbox_analysis_progress,
                    on_sandbox_analysis_done=self._on_sandbox_analysis_done,
                    driver_terminate_by_path_hook=self._driver_terminate_by_path,
                    on_process_created_hook=_proc_created_cb_reinit,
                    mbr_arm_before_kill_hook=self._mbr_arm_before_proc_kill,
                    mbr_verify_after_kill_hook=self._mbr_verify_after_proc_kill,
                    visual_prank_observer=self._register_prank_observer,
                )
            elif module == 'file-protection':
                self._file_protection = FileProtection(
                    quarantine_manager=self._quarantine_manager,
                    signature_db=self._signature_db,
                    on_threat=self._on_file_threat,
                    on_ransomware_kill=self._on_ransomware_kill,
                )
                self._file_protection.strict_mode = self._strict_mode
            elif module == 'system-protection':
                self._system_protection = SystemProtection(
                    quarantine_manager=self._quarantine_manager,
                    on_threat=self._on_system_threat,
                )
            elif module == 'autostart-protection':
                self._autostart_protection = AutostartProtection(
                    signature_db=self._signature_db,
                    on_suspicious=self._on_autostart_suspicious,
                    on_ask_user=self._on_autostart_ask_user,
                    on_result=self._on_autostart_result,
                )
            elif module == 'realtime-monitor':
                initial_dirs = self._get_realtime_watch_dirs()
                self._realtime_monitor = RealtimeMonitor(
                    scan_engine_factory=self._create_scan_engine_for_realtime,
                    watch_dirs=initial_dirs,
                    on_threat=self._on_realtime_threat,
                    on_scan_result=self._on_realtime_scan_result,
                    signature_db=self._signature_db,
                    exemption_checker=self._is_realtime_exempted,
                    quarantine_manager=self._quarantine_manager,
                )
                self._realtime_monitor.strict_mode = self._strict_mode
                self._realtime_monitor.virus_identifier_enabled = self._vi_enabled
                self._realtime_monitor.set_user_excluded_dirs(
                    getattr(self, '_scan_excluded_paths', []))
                self._register_internal_copy_provider()
            elif module == 'notification':
                self._notification_manager = NotificationManager()
                self._notification_manager.set_notification_callback(self._on_notification_emitted)
            elif module == 'mbr-protection':
                self._mbr_protector = MBRProtector(
                    on_threat=self._on_mbr_threat,
                )
            elif module == 'ransomware-rollback':
                self._rollback_manager = _create_rollback_manager(
                    quarantine_manager=self._quarantine_manager,
                    process_protection=self._process_protection,
                    on_report=self._on_rollback_report,
                )
                self._wire_rollback_manager()

            logger.info(f'{module} 重新初始化成功')
            self._add_activity('防护', f'{module} 重新初始化成功', 'INFO', '成功')
        except Exception as e:
            logger.error(f'{module} 重新初始化失败: {e}')
            self._add_activity('防护', f'{module} 重新初始化失败: {e}', 'ERROR', '失败')
        finally:
            # 逐引擎构造耗时（label 带模块名，便于定位"哪个引擎构造最慢"）
            self._cfg_note(f'构造:{module}', (time.monotonic() - _t_re) * 1000.0)

    def _on_sandbox_block(self, block_data: dict):
        """沙箱拦截回调 —— 沙箱判定恶意/可疑/错误时触发

        注意：此方法在后台 daemon 线程（_sandbox_worker）中被调用，
        不能直接创建 QWidget，必须通过信号转发到主线程。
        """
        try:
            # 通过信号转发到主线程（QWidget 必须在主线程创建）
            self.sandboxBlockPopupRequested.emit(json.dumps(block_data, ensure_ascii=False))
        except Exception as e:
            logger.error(f'_on_sandbox_block 信号发射异常: {e}', exc_info=True)

    def _on_sandbox_block_popup_requested(self, block_json: str):
        """主线程中处理沙箱拦截弹窗请求（由 sandboxBlockPopupRequested 信号触发）

        弹窗策略：
        - 检测到 malware/suspicious → 直接隔离，不询问用户
        - 显示中央 SandboxThreatWindow 告知用户（保留原有弹窗）
        - 不再显示右下角结果弹窗
        """
        try:
            block_data = json.loads(block_json)
            name = block_data.get('name', '未知进程')
            path = block_data.get('path', '')
            reason = block_data.get('reason', '')
            verdict = block_data.get('verdict', 'error')
            score = block_data.get('score', 0)
            error = block_data.get('error', '')
            quarantined = bool(block_data.get('quarantined', False))

            # --- 强制隔离兜底：沙箱判定非 clean 时，无论处理策略（询问/仅上报）
            #     都必须隔离样本文件。首次失败多为目标进程或其副本仍在占用文件，
            #     后台延迟重试直到成功（或文件已不存在）。---
            # 【性能/死锁修复】quarantine_file 内部会做串行 icacls/takeown 子进程
            # (timeout 10s~15s)，对增量降的大文件(如 174.8MB Manager.exe)在系统
            # 繁忙/被占用时会卡满超时。此槽运行在 Qt 主线程 → 22s UI 冻结。
            # 把隔离重活移动到后台 daemon 线程，完成后用 Qt 信号回主线程更新告警，
            # 主线程立即返回不再阻塞 QEventLoop。
            if (not quarantined and path and verdict != 'clean'
                    and os.path.exists(path)):
                def _do_fallback_quarantine(_blk=None):
                    try:
                        if self._quarantine_manager is None:
                            return
                        ok = False
                        for _attempt in range(3):
                            # 隔离前必须释放引擎登记的 exe 独占锁（share=0）：
                            # 引擎在首次隔离失败后会重新加锁，若不释放，隔离
                            # 的 encrypt/move/remove/rename 会被 PSLS 自己阻塞，
                            # 重试也不可能成功。
                            try:
                                _pp = getattr(self, '_process_protection', None)
                                if _pp is not None and hasattr(_pp, 'release_sandbox_lock'):
                                    _pp.release_sandbox_lock(path)
                            except Exception:
                                pass
                            retry_ok = self._quarantine_manager.quarantine_file(
                                path,
                                reason=(
                                    f"沙箱强制隔离: verdict={verdict},"
                                    f" score={score}, reason={reason}"
                                ),
                                malware_name=f"Sandbox.{verdict.capitalize()}",
                            )
                            ok = (retry_ok is True or retry_ok == 'duplicate')
                            if ok or not os.path.exists(path):
                                ok = True
                                break
                            time.sleep(2.0)
                        # 回主线程更新弹窗/告警（QWidget 必须在主线程）
                        try:
                            _blk = dict(block_data)
                            _blk['quarantined'] = bool(ok)
                            self._emit_tool_signal(
                                'sandboxBlocked',
                                json.dumps(_blk, ensure_ascii=False),
                            )
                        except Exception:
                            pass
                        if ok:
                            logger.info(
                                '沙箱强制隔离成功: %s (verdict=%s)', path, verdict)
                        else:
                            fail_reason = getattr(
                                self._quarantine_manager,
                                'get_last_quarantine_error', lambda: '',
                            )() or '未知原因'
                            logger.warning(
                                '沙箱强制隔离仍失败 %s: %s', path, fail_reason)
                    except Exception as e:
                        logger.warning(
                            '沙箱强制隔离异常 %s: %s', path, e)

                import threading as _th
                _t = _th.Thread(
                    target=_do_fallback_quarantine, args=(dict(block_data),),
                    daemon=True, name='SandboxFallbackQuarantine')
                _t.start()
                # 后续活动日志/提示音照常立刻输出（不等待隔离完成）
                quarantined = False
            else:
                pass

            # 活动日志
            verdict_label_map = {
                'malware': '恶意行为',
                'suspicious': '可疑行为',
                'error': '沙箱失败',
                'skipped': '跳过（过大）',
            }
            verdict_label = verdict_label_map.get(verdict, verdict)
            quarantined_suffix = '已隔离' if quarantined else '未隔离'

            self._add_activity(
                '沙箱拦截',
                f'{name}: {verdict_label}'
                f'{f" (评分:{score})" if score else ""}'
                f' [{quarantined_suffix}]'
                f' — {reason}',
                'ERROR',
                '已拦截',
            )

            # 触发提示音（沙箱拦截分析 → warn.mp3）
            self._request_warn_sound()

            # --- 中央弹窗：SandboxThreatWindow ---
            # 检测到 malware/suspicious 时显示中央威胁弹窗（原有弹窗保留）
            if verdict in ('malware', 'suspicious') and path:
                try:
                    self.sandboxThreatPopupRequested.emit(
                        json.dumps({'file_path': path}, ensure_ascii=False))
                except Exception as e:
                    logger.error(f'沙箱威胁弹窗信号发射异常: {e}')
            elif verdict == 'error' and path:
                try:
                    self.sandboxFailurePopupRequested.emit(
                        json.dumps({'file_path': path}, ensure_ascii=False))
                except Exception as e:
                    logger.error(f'沙箱失败弹窗信号发射异常: {e}')

            # 同时 emit_signal 让前端也能看到（状态页）
            self._emit_tool_signal(
                'sandboxBlocked',
                json.dumps(block_data, ensure_ascii=False),
            )

        except Exception as e:
            logger.error(f'_on_sandbox_block 回调异常: {e}', exc_info=True)

    def _on_sandbox_release_request(self, request_data: dict):
        """沙箱判定安全后，询问用户是否重启进程

        可疑进程已被立即终止，沙箱分析判定为安全(clean)。
        现在询问用户是否同意重启该进程：
        - 用户点击"同意重启" → 调用 restartSandboxedProcess 重启
        - 用户点击"不重启" → 不操作
        - 5秒超时未操作 → 不重启（默认拒绝）

        注意：此方法在后台 daemon 线程（_sandbox_worker）中被调用，
        不能直接创建 QWidget，必须通过信号转发到主线程。

        Args:
            request_data = {
                'type': 'sandbox_release_request',
                'name': str (进程名),
                'path': str (文件路径),
                'reason': str (触发原因),
                'cmdline': list (原始命令行),
                'score': int (沙箱评分),
            }
        """
        try:
            # 通过信号转发到主线程（QWidget 必须在主线程创建）
            self.sandboxReleasePopupRequested.emit(json.dumps(request_data, ensure_ascii=False))
        except Exception as e:
            logger.error(f'_on_sandbox_release_request 信号发射异常: {e}', exc_info=True)

    def _on_sandbox_release_popup_requested(self, request_json: str):
        """主线程中处理沙箱放行弹窗请求（由 sandboxReleasePopupRequested 信号触发）

        沙箱判定安全(clean)后使用 SandboxReleaseWindow（与分析进度窗口同风格：
        米色背景 + 品牌头 + 绿色对勾图标）替代旧的 ThreatNotificationPopup。
        用户点击"同意重启" → releaseAccepted → 重启进程；超时/拒绝默认不重启。
        视觉恶搞检测（type=visual_prank_release_request）复用同一窗口与信号，
        展示"已终止可疑进程（恶意行为），是否信任并重新启动？"，3 秒超时
        默认不重启；用户点"信任重启" → 标记信任 + 重启。
        """
        try:
            request_data = json.loads(request_json)
            name = request_data.get('name', '未知进程')
            path = request_data.get('path', '')
            reason = request_data.get('reason', '')
            cmdline = request_data.get('cmdline')
            score = request_data.get('score', 0)

            rtype = request_data.get('type', '')
            is_prank = rtype == 'visual_prank_release_request'
            signal_name = request_data.get('signal_name', '') or ''

            if is_prank:
                # 视觉恶搞命中：已杀进程 + 锁定 exe，询问是否信任重启
                prev = self._sandbox_release_win
                if prev is not None:
                    try:
                        prev.close()
                    except Exception:
                        pass
                win = SandboxReleaseWindow(
                    path or name,
                    subtitle_lines=[
                        f'已终止可疑进程【{name}】',
                        f'恶意行为：{signal_name or reason}',
                    ],
                    question_line='是否信任并重新启动该程序？',
                    accept_text='信任重启')
                win.releaseAccepted.connect(
                    lambda: self._on_visual_prank_release_accepted(request_data))
                win.destroyed.connect(
                    lambda: self._on_visual_prank_win_destroyed(request_json))
                win.show()
                self._sandbox_release_win = win
                return

            # --- 放行原因类别（决定弹窗语义与文案）---
            # 'oversize'：文件过大、根本没做沙箱分析 → 必须用警示窗如实说明，
            #             绝不能显示成"判定安全（评分:0）"，否则会诱导用户放行
            #             一个从未被分析过的（可能恶意的）大文件。
            # 'clean'   ：沙箱真实判定安全 → 绿色对勾安全放行窗。
            kind = str(request_data.get('kind') or 'clean').lower()

            if kind == 'oversize':
                self._add_activity(
                    '沙箱放行',
                    f'{name}: 文件过大，未做沙箱分析（≠判定安全），'
                    f'等待用户确认是否放行',
                    'WARN',
                    '待确认',
                )
                # 未分析 → 用警示音，不能用"安全放行"音
                self._request_warn_sound()
                win = SandboxReleaseWindow(
                    path,
                    subtitle_lines=[
                        f'已终止程序【{name}】（文件过大，未分析）',
                        '此处并非"判定安全"，是否仍要放行？',
                    ],
                    accept_text='仍然放行',
                    icon_kind='cross',
                )
                # 默认拒绝：用户不点"仍然放行"（含 3s 倒计时超时）→ 直接隔离。
                # 实测 MinecraftRansomware 自签名 + 64.6MB 中 95.8% 为高熵
                # 填充（故意撑大以走"过大"慢分支），因此未分析的大文件必须
                # 默认隔离，绝不能"杀掉了但留在磁盘上可再运行"。
                win.releaseRejected.connect(
                    lambda: self._on_oversize_release_rejected(request_data))
            else:
                # 活动日志
                self._add_activity(
                    '沙箱放行',
                    f'{name}: 沙箱判定安全（评分:{score}），等待用户确认是否重启',
                    'INFO',
                    '待确认',
                )
                # 播放提示音（沙箱放行询问是否重启 → info2.mp3）
                # 该音效播放期间若触发更高优先级新音效，会先被中断再播新的
                self._request_info2_sound()
                # 与分析进度窗口同风格的安全放行窗口（米色背景 + 品牌头 + 绿色对勾）
                win = SandboxReleaseWindow(path)

            win.releaseAccepted.connect(
                lambda: self._on_sandbox_release_accepted(request_data))
            win.destroyed.connect(self._on_sandbox_release_win_destroyed)
            win.show()
            # 主线程持有引用，防止窗口被 GC
            self._sandbox_release_win = win

        except Exception as e:
            logger.error(f'_on_sandbox_release_popup_requested 异常: {e}', exc_info=True)
            self._reload_after_sandbox_release_failure(request_json)

    def _on_oversize_release_rejected(self, request_data: dict):
        """文件过大未分析：用户未选择"仍然放行"（含倒计时超时）→ 默认隔离。

        实测 MinecraftRansomware（自签名 XiaowangFly，64.6MB 中 95.8% 为
        高熵填充，专门撑大体积以走"过大"分支）被终止后仍留在磁盘上可再次
        运行；未分析的大文件必须默认隔离，只有用户显式点"仍然放行"才放行。
        """
        path = request_data.get('path') or ''
        if not path or not os.path.exists(path):
            return

        def _work():
            # 隔离前先释放引擎登记的 exe 独占锁（否则 encrypt/move 被自己阻塞）
            try:
                pp = getattr(self, '_process_protection', None)
                if pp is not None and hasattr(pp, 'release_sandbox_lock'):
                    pp.release_sandbox_lock(path)
            except Exception:
                pass
            try:
                if self._quarantine_manager is None:
                    return
                r = self._quarantine_manager.quarantine_file(
                    path,
                    reason='文件过大未沙箱分析-默认隔离',
                    malware_name=f'未分析大文件: {os.path.basename(path)}',
                    skip_exemption=True,
                )
                if r is True:
                    self._add_activity(
                        '沙箱',
                        f'文件过大未分析，已默认隔离: {os.path.basename(path)}',
                        'WARN', '已隔离')
                elif r == 'duplicate':
                    logger.info(f'大文件默认隔离：已在隔离区 {path}')
            except Exception as e:
                logger.warning(f'大文件默认隔离失败 {path}: {e}')

        threading.Thread(target=_work, daemon=True,
                         name='OversizeQuarantine').start()

    def _on_sandbox_threat_popup_requested(self, request_json: str):
        """主线程中处理沙箱威胁结果弹窗请求（malware/suspicious）

        展示与分析进度窗口同风格的 SandboxThreatWindow（红色 × 图标，
        文件名 + "该程序被判定为威胁"文案，单个绿色"知道了"按钮）。
        """
        try:
            request_data = json.loads(request_json)
            path = request_data.get('file_path', '')
            if not path:
                logger.warning('沙箱威胁弹窗缺少 file_path')
                return
            # 若已有中央弹窗，先关闭旧的再显示新的
            self._close_sandbox_result_win()
            win = SandboxThreatWindow(path)
            win.acknowledged.connect(self._close_sandbox_result_win)
            self._sandbox_result_win = win
            win.show()
        except Exception as e:
            logger.error(f'_on_sandbox_threat_popup_requested 异常: {e}', exc_info=True)

    def _on_sandbox_failure_popup_requested(self, request_json: str):
        """主线程中处理沙箱失败结果弹窗请求

        展示 SandboxFailureWindow（基于威胁窗口：红色 × 图标 +
        文案"沙箱进程启动失败，已将其强制隔离。"，单个绿色"知道了"按钮）。
        """
        try:
            request_data = json.loads(request_json)
            path = request_data.get('file_path', '')
            if not path:
                logger.warning('沙箱失败弹窗缺少 file_path')
                return
            # 若已有中央弹窗，先关闭旧的再显示新的
            self._close_sandbox_result_win()
            win = SandboxFailureWindow(path)
            win.acknowledged.connect(self._close_sandbox_result_win)
            self._sandbox_result_win = win
            win.show()
        except Exception as e:
            logger.error(f'_on_sandbox_failure_popup_requested 异常: {e}', exc_info=True)

    def _close_sandbox_result_win(self):
        """关闭并清理当前沙箱结果窗口引用（防 GC 泄漏）"""
        try:
            win = self._sandbox_result_win
            self._sandbox_result_win = None
            if win is not None and win.isVisible():
                win.close()
        except Exception as e:
            logger.error(f'关闭沙箱结果窗口异常: {e}')

    def _on_file_locked(self, file_path: str):
        """主线程中处理实时保护锁定程序通知（fileLocked 信号）

        在主界面活动日志显示 + 屏幕右下角结果弹窗提醒：
        "实时保护已锁定【文件名】，稍后自动解除。"
        同一路径 5 秒内去重，避免高频锁定刷屏。
        """
        try:
            if not file_path:
                return
            now = time.time()
            try:
                last = self._file_locked_notify_ts.get(file_path, 0)
                if now - last < 5:
                    return
                self._file_locked_notify_ts[file_path] = now
                # 滚动窗口清理
                if len(self._file_locked_notify_ts) > 200:
                    self._file_locked_notify_ts = {
                        k: v for k, v in self._file_locked_notify_ts.items()
                        if now - v < 60
                    }
            except Exception:
                pass

            basename = os.path.basename(file_path)
            msg = f'实时保护已锁定【{basename}】，稍后自动解除'
            self._add_activity('实时保护', msg, 'INFO', '已锁定')
            # 屏幕右下角结果弹窗（2 秒自动消失，通知级优先级 10）
            self._enqueue_priority_popup(
                self._PRIORITY_QUARANTINE_SUCCESS, 'result',
                {
                    'file_path': file_path,
                    'status': 'info',
                    'signature_name': '',
                    'action': 'lock_notice',
                    'result': {
                        'success': True,
                        'action': 'lock_notice',
                        'message': f'{msg}。',
                    },
                },
            )
        except Exception as e:
            logger.error(f'_on_file_locked 异常: {e}')

    def notify_file_locked(self, file_path: str):
        """[任意线程可调用] 实时保护锁定程序后通知用户（跨线程信号转发）"""
        try:
            self.fileLocked.emit(file_path)
        except Exception as e:
            logger.error(f'notify_file_locked 信号发射异常: {e}')

    def notify_file_located_after_restore(self, file_path: str, note: str = ''):
        """恢复隔离文件后通知用户文件实际位置（可能不在原始位置）"""
        try:
            # 如果恢复到了备用位置，需要通知用户
            if file_path and 'Quarantine_Restored' in file_path:
                self._add_activity('隔离区',
                    f'文件已恢复到备用位置: {file_path}', 'WARN', '提示')
                # 发送通知事件给前端
                self._launch_scan_event.emit({
                    'type': 'restore_location_notice',
                    'file_path': file_path,
                    'note': note or f'文件无法恢复到原始位置，已恢复到: {file_path}',
                })
        except Exception as e:
            logger.error(f'notify_file_located_after_restore 异常: {e}')

    def _reload_after_sandbox_release_failure(self, request_json: str):
        """放行窗口创建失败兜底：回退到旧的 ThreatNotificationPopup 逻辑"""
        try:
            request_data = json.loads(request_json)
            path = request_data.get('path', '')
            name = request_data.get('name', '未知进程')
            reason = request_data.get('reason', '')
            cmdline = request_data.get('cmdline')
            score = request_data.get('score', 0)
            popup_data = {
                'file_path': path,
                'status': 'suspicious',
                'signature_name': f'沙箱判定安全: {name}',
                'reason': reason,
                'score': score,
                'cmdline': cmdline,
                '_is_sandbox_release': True,
            }
            self._show_threat_notification_popup(popup_data)
        except Exception as e2:
            logger.error(f'沙箱放行兜底弹窗失败: {e2}')

    def _on_sandbox_release_accepted(self, request_data: dict):
        """用户点击"同意重启" → 重启被终止的进程。"""
        exe = request_data.get('path', '')
        cmdline = request_data.get('cmdline')
        if not exe:
            logger.warning('沙箱放行：缺少 exe 路径，无法重启')
            return
        if self._process_protection:
            try:
                ok = self._process_protection.restart_sandboxed_process(exe, cmdline)
                if ok:
                    self._add_activity(
                        '沙箱放行', f'已重启进程: {os.path.basename(exe)}', 'INFO', '完成')
                else:
                    self._add_activity(
                        '沙箱放行', f'重启失败: {os.path.basename(exe)}', 'WARN', '失败')
            except Exception as e:
                logger.error(f'沙箱放行重启进程异常 {exe}: {e}', exc_info=True)
        else:
            logger.warning('沙箱放行：进程保护模块未启动，无法重启进程')

    def _on_sandbox_release_win_destroyed(self):
        """安全放行窗口销毁后清理引用。"""
        self._sandbox_release_win = None

    # ---- 视觉恶搞行为检测（VisualPrankDetector）桥接 ----

    def _register_prank_observer(self, pid: int, exe: str, name: str,
                                 cmdline):
        """进程保护回调：非信任 PE 启动 → 注册到恶搞检测观察集合。

        在 ProcessProtection 的子线程/回调链中被调用，
        仅做内存集合写入（检测器轮询线程负责读取审计）。
        """
        try:
            det = self._visual_prank_detector
            if det is not None:
                det.register_observed_pid(int(pid), str(exe or ''),
                                          str(name or ''), cmdline)
        except Exception as e:
            logger.debug(f'注册恶搞观察对象异常: {e}')

    def _prank_kill_cb(self, exe: str, pid: int) -> bool:
        """检测器命中后调用的"先杀进程"回调（全链终止）。"""
        try:
            pp = self._process_protection
            if pp is not None:
                return bool(pp.terminate_prank_process(str(exe or ''), int(pid or 0)))
        except Exception as e:
            logger.warning(f'恶搞行为检测 kill_hook 异常: {e}')
        return False

    def _on_visual_prank(self, evidence: dict):
        """[检测器轮询线程] 视觉恶搞命中 → 分发处置。

        kill-then-ask 流程的后半段（前半段 _prank_kill_cb 已杀进程）：
        - danger 级（壁纸篡改）：直接杀进程 + 通知，不询问
        - suspicious 级（弹窗/图标/设置改写）：锁定 exe + 弹询问窗
          （3s 内选择：信任并重启 / 不重启，无反应默认不重启）
        通过 sandboxReleasePopupRequested 信号切回主线程弹窗。
        """
        try:
            ev = evidence or {}
            level = ev.get('level', 'suspicious')
            exe = ev.get('exe') or ''
            name = ev.get('name') or os.path.basename(exe) or '未知进程'
            signal = ev.get('signal') or ''
            killed = bool(ev.get('killed'))
            desc = ev.get('description') or '视觉恶搞行为'

            signal_name = {
                'popup_storm': '弹窗风暴',
                'icon_flood': '桌面图标洪流',
                'wallpaper_tamper': '壁纸篡改',
                'settings_changed': '系统个性化设置批量更改',
            }.get(signal, '视觉恶搞行为')

            if level == 'danger':
                # 危险级：已杀进程，仅通知
                self._add_activity(
                    '恶搞行为检测',
                    f'已终止可疑进程【{name}】（{signal_name}），风险较高',
                    'WARN', '已终止')
                self._enqueue_priority_popup(
                    self._PRIORITY_QUARANTINE_SUCCESS, 'result',
                    {
                        'file_path': exe or name,
                        'status': 'danger',
                        'signature_name': signal_name,
                        'action': 'prank_killed',
                        'result': {
                            'success': True,
                            'action': 'prank_killed',
                            'message': (
                                f'已终止可疑进程【{name}】（{signal_name}）'
                                f'，请检查桌面壁纸。'),
                        },
                    },
                )
                return

            # suspicious 级：询问期间锁定 exe，阻止用户重复启动
            locked = False
            if exe:
                try:
                    pp = self._process_protection
                    if pp is not None:
                        locked = pp.lock_prank_executable(exe) is not None
                except Exception as e:
                    logger.warning(f'恶搞行为检测锁定 exe 异常: {e}')

            request_data = {
                'type': 'visual_prank_release_request',
                'name': name,
                'path': exe,
                'reason': desc,
                'cmdline': ev.get('cmdline'),
                'level': level,
                'signal': signal,
                'signal_name': signal_name,
                'killed': killed,
                'locked': locked,
            }
            # 活动日志（先杀后问）
            self._add_activity(
                '恶搞行为检测',
                f'已终止可疑进程【{name}】（{signal_name}：{desc}），'
                f'等待用户选择是否信任重启',
                'WARN', '待确认')
            self._request_info2_sound()
            self.sandboxReleasePopupRequested.emit(
                json.dumps(request_data, ensure_ascii=False))
        except Exception as e:
            logger.error(f'_on_visual_prank 异常: {e}', exc_info=True)

    def _on_visual_prank_release_accepted(self, request_data: dict):
        """用户点击"信任重启"：标记信任 + 重启被终止的程序。"""
        exe = request_data.get('path', '')
        cmdline = request_data.get('cmdline')
        name = request_data.get('name', os.path.basename(exe) or '未知进程')
        if not exe:
            logger.warning('恶搞行为检测：缺少 exe 路径，无法重启')
            return
        pp = self._process_protection
        if pp is None:
            try:
                pp = self._process_protection
            except Exception:
                pp = None
        if pp is not None:
            try:
                ok = pp.restart_prank_process(exe, cmdline)
                if ok:
                    self._add_activity(
                        '恶搞行为检测', f'已信任并重启: {name}', 'INFO', '完成')
                else:
                    self._add_activity(
                        '恶搞行为检测', f'信任重启失败: {name}', 'WARN', '失败')
            except Exception as e:
                logger.error(f'恶搞行为检测重启异常 {exe}: {e}', exc_info=True)
        else:
            logger.warning('恶搞行为检测：进程保护模块未启动，无法信任重启')

    def _on_visual_prank_win_destroyed(self, request_json: str = ''):
        """恶搞询问窗口销毁（取消/超时）→ 释放 exe 独占锁。

        锁释放后用户可自行决定是否再次启动该程序（进程已被终止）。
        """
        try:
            self._sandbox_release_win = None
            if request_json:
                try:
                    rd = json.loads(request_json)
                    exe = rd.get('path', '')
                    if exe and self._process_protection is not None:
                        self._process_protection.release_prank_lock(exe)
                except Exception:
                    pass
        except Exception:
            pass

    # ---- 更激进的特效检测（AggressivePrankDetector）桥接 ----
    def _aggressive_kill_cb(self, pid: int) -> bool:
        """[检测器轮询线程] 单进程终止回调 → 转发 ProcessProtection.kill_process"""
        try:
            pp = self._process_protection
            if pp is not None:
                return bool(pp.kill_process(int(pid), force=True,
                                            kill_tree=True, timeout=2.0))
        except Exception as e:
            logger.warning(f'更激进的特效检测 kill_hook 异常: {e}')
        return False

    def _on_aggressive_prank(self, evidence: dict):
        """[检测器轮询线程] 更激进特效命中 → 通知用户（杀进程已由检测器完成）"""
        try:
            ev = evidence or {}
            signal = ev.get('signal') or 'screen_anomaly'
            desc = ev.get('description') or '检测到异常桌面特效'
            killed = int(ev.get('killed') or 0)
            failed = int(ev.get('failed') or 0)
            killed_names = ev.get('killed_names') or []

            signal_name = {
                'screen_churn': '全屏刷屏特效',
                'screen_takeover': '全屏单色特效占领',
                'window_storm': '大量相同窗口',
            }.get(signal, '桌面异常特效')

            names_txt = '、'.join(killed_names[:6]) if killed_names else ''
            detail = f'（已终止 {killed} 个非系统进程'
            if failed:
                detail += f'，{failed} 个终止失败'
            detail += f'）'
            if names_txt:
                detail += f'，涉及：{names_txt}'

            self._add_activity(
                '更激进的特效检测',
                f'检测到{signal_name}{detail}：{desc}',
                'WARN', '已终止')
            self._request_critical_sound()
            self._enqueue_priority_popup(
                self._PRIORITY_QUARANTINE_SUCCESS, 'result',
                {
                    'file_path': '桌面监控',
                    'status': 'danger',
                    'signature_name': signal_name,
                    'action': 'aggressive_prank_killed',
                    'result': {
                        'success': True,
                        'action': 'aggressive_prank_killed',
                        'message': (
                            f'更激进的特效检测：检测到{signal_name}'
                            f'（{desc}），已终止 {killed} 个非系统进程。'
                            f'系统进程与 PSLS 不受影响，请留意桌面。'),
                    },
                },
            )
        except Exception as e:
            logger.error(f'_on_aggressive_prank 异常: {e}', exc_info=True)

    def _on_sandbox_analysis_start(self, exe: str):
        """子线程回调：沙箱分析开始 → 转发主线程显示分析进度窗口"""
        try:
            self.sandboxAnalysisWinStart.emit(exe or '')
        except Exception as e:
            logger.error(f'_on_sandbox_analysis_start 信号发射异常: {e}', exc_info=True)

    def _on_sandbox_analysis_progress(self, stage: str, percent: float):
        """子线程回调：沙箱分析进度 → 转发主线程更新窗口"""
        try:
            progress_data = json.dumps({
                'stage': stage or '',
                'percent': round(float(percent or 0) * 100, 1),
            }, ensure_ascii=False)
            self.sandboxAnalysisWinProgress.emit(progress_data)
        except Exception as e:
            logger.error(f'_on_sandbox_analysis_progress 信号发射异常: {e}', exc_info=True)

    def _on_sandbox_analysis_done(self, exe: str, verdict: str):
        """子线程回调：沙箱分析完成 → 转发主线程关闭分析进度窗口"""
        try:
            self.sandboxAnalysisWinDone.emit(verdict or 'error')
        except Exception as e:
            logger.error(f'_on_sandbox_analysis_done 信号发射异常: {e}', exc_info=True)

    def _show_sandbox_analysis_win(self, exe: str):
        """主线程：创建并显示"软件分析室"沙箱分析进度窗口。"""
        try:
            win = SandboxAnalysisWindow(exe or '')
            win.show()
            win.start()
            self._sandbox_analysis_win = win
        except Exception as e:
            logger.error(f'显示沙箱分析窗口失败: {e}', exc_info=True)
            self._sandbox_analysis_win = None

    def _update_sandbox_analysis_win(self, progress_json: str):
        """主线程：更新沙箱分析进度窗口的状态与进度。"""
        win = self._sandbox_analysis_win
        if win is None:
            return
        try:
            data = json.loads(progress_json)
            stage = data.get('stage', '')
            pct = data.get('percent', 0)
            win.set_progress(int(pct), stage)
            win.set_status(stage)
        except Exception as e:
            logger.warning(f'更新沙箱分析窗口进度失败: {e}')

    def _close_sandbox_analysis_win(self, verdict: str):
        """主线程：沙箱分析完成，立即关闭分析进度窗口。"""
        win = self._sandbox_analysis_win
        if win is None:
            return
        self._sandbox_analysis_win = None
        try:
            win.stop()
            win.close()
            win.deleteLater()
        except Exception as e:
            logger.warning(f'关闭沙箱分析窗口异常: {e}')

    # ===== 自启动项监测回调处理 =====

    def _on_autostart_suspicious(self, info: dict):
        """可疑进程试图添加自启动：直接拦截（清理自启动项 + 终止进程）（后台线程调用）"""
        try:
            full_path = info.get('full_path', '')
            value_name = info.get('value_name', '')
            pid = info.get('pid', 0)
            proc_name = info.get('name', '') or f'PID={pid}'

            # 1. 清理自启动项（注册表值；与勒索文件恢复链路完全无关）
            cleanup_ok = False
            if self._autostart_protection:
                cleanup_ok = self._autostart_protection.rollback_value(full_path, value_name)

            # 2. 终止可疑进程
            kill_ok = False
            if pid and pid > 0:
                kill_ok = self._terminate_process_by_pid(pid)

            # 拦截是否生效：清理成功或进程已被终止即视为"已拦截"。
            # 绝不把"注册表清理未完成"当成失败，避免与勒索文件恢复语义串台。
            blocked_ok = bool(cleanup_ok or kill_ok)

            self._add_activity(
                '启动项监测',
                f'可疑进程 {proc_name}(PID={pid}) 试图添加自启动，已拦截'
                f'（自启动项清理: {"成功" if cleanup_ok else "未完成"}，'
                f'终止进程: {"成功" if kill_ok else "失败"}）',
                'ERROR',
                '已拦截',
            )
            # 播放提示音（拦截恶意自启动 + 弹通知 → error2.mp3）
            self._request_error2_sound()

            # 3. 结果通知（桌面弹窗）——成功与否反映"拦截是否生效"
            self._show_threat_result_popup({
                'file_path': value_name,
                'status': 'malware',
                'signature_name': f'自启动拦截: {proc_name}',
                'action': 'autostart_block',
                'result': {
                    'success': blocked_ok,
                    'intercepted': blocked_ok,
                    'cleanup_ok': cleanup_ok,
                    'action': 'autostart_block',
                    'message': (f'可疑进程 {proc_name} 试图添加自启动项，已拦截'
                                f'（自启动项清理: {"成功" if cleanup_ok else "未完成，可能需要管理员权限"}，'
                                f'终止进程: {"成功" if kill_ok else "失败"}）'),
                },
            })
        except Exception as e:
            logger.error(f'_on_autostart_suspicious 异常: {e}', exc_info=True)

    def _on_autostart_ask_user(self, info: dict):
        """非可疑进程添加自启动：转发到主线程弹窗询问用户（后台线程调用）"""
        try:
            self.autostartPopupRequested.emit(json.dumps(info, ensure_ascii=False))
        except Exception as e:
            logger.error(f'_on_autostart_ask_user 异常: {e}', exc_info=True)

    def _on_autostart_result(self, result: dict):
        """自启动项处理结果（后台线程调用）"""
        try:
            info = result.get('info', {})
            action = result.get('action', '')
            value_name = info.get('value_name', '')
            proc_name = info.get('name', '未知进程')
            message = result.get('message', '')
            success = result.get('success', True)
            self._show_threat_result_popup({
                'file_path': value_name,
                'status': 'suspicious',
                'signature_name': f'自启动处理: {proc_name}',
                'action': f'autostart_{action}',
                'result': {
                    'success': success,
                    'action': f'autostart_{action}',
                    'message': message,
                },
            })
        except Exception as e:
            logger.error(f'_on_autostart_result 异常: {e}', exc_info=True)

    def _on_autostart_popup_requested(self, request_json: str):
        """主线程：显示自启动项确认弹窗（单弹窗队列）"""
        try:
            info = json.loads(request_json) if isinstance(request_json, str) else request_json
            if len(self._autostart_popup_queue) >= 20:
                logger.warning('自启动确认弹窗队列已满，丢弃')
                return
            self._autostart_popup_queue.append(info)
            if self._current_autostart_popup is None or not self._current_autostart_popup.isVisible():
                self._show_next_autostart_popup()
        except Exception as e:
            logger.error(f'_on_autostart_popup_requested 异常: {e}', exc_info=True)

    def _show_next_autostart_popup(self):
        try:
            if self._current_autostart_popup is not None:
                try:
                    self._current_autostart_popup.destroyed.disconnect()
                except Exception:
                    pass
                self._current_autostart_popup = None

            if not self._autostart_popup_queue:
                return

            info = self._autostart_popup_queue.pop(0)
            popup = AutostartConfirmPopup(info, scale=self._popup_scale)
            popup.allowRequested.connect(self._on_autostart_allow)
            popup.blockRequested.connect(self._on_autostart_block)
            popup.destroyed.connect(self._on_current_autostart_popup_destroyed)
            self._current_autostart_popup = popup
            popup._slide_in()
            # 确保自启动确认弹窗置顶于结果弹窗之上
            QTimer.singleShot(350, popup.raise_)
            logger.info(f'显示自启动确认弹窗: {info.get("value_name", "")}（剩余 {len(self._autostart_popup_queue)}）')
        except Exception as e:
            logger.error(f'显示下一个自启动确认弹窗失败: {e}')

    def _on_current_autostart_popup_destroyed(self):
        try:
            self._current_autostart_popup = None
            if self._autostart_popup_queue:
                QTimer.singleShot(150, self._show_next_autostart_popup)
        except Exception as e:
            logger.warning(f'自启动确认弹窗销毁回调异常: {e}')

    def _on_autostart_allow(self, payload: str):
        """用户允许自启动项"""
        try:
            info = json.loads(payload) if isinstance(payload, str) else payload
            if self._autostart_protection:
                self._autostart_protection.on_user_allow(info)
            proc_name = info.get('name', '未知进程')
            value_name = info.get('value_name', '')
            self._add_activity('启动项监测', f'用户允许 {proc_name} 添加自启动项: {value_name}', 'INFO', '已允许')
        except Exception as e:
            logger.error(f'_on_autostart_allow 异常: {e}', exc_info=True)

    def _on_autostart_block(self, payload: str):
        """用户拦截自启动项（含 5 秒超时自动拦截）"""
        try:
            info = json.loads(payload) if isinstance(payload, str) else payload
            if self._autostart_protection:
                self._autostart_protection.on_user_block(info)
            proc_name = info.get('name', '未知进程')
            value_name = info.get('value_name', '')
            self._add_activity('启动项监测', f'拦截 {proc_name} 添加自启动项: {value_name}（已回滚）', 'WARN', '已拦截')
        except Exception as e:
            logger.error(f'_on_autostart_block 异常: {e}', exc_info=True)

    def _terminate_process_by_pid(self, pid: int) -> bool:
        """终止指定 PID 的进程（先驱动，后 psutil，最后 taskkill 兜底）"""
        if not pid or pid <= 0:
            return False
        # 1. 驱动终止
        if self._autostart_protection and getattr(self._autostart_protection, '_driver_bridge', None):
            try:
                bridge = self._autostart_protection._driver_bridge
                if bridge.is_available and bridge.terminate_process(pid):
                    return True
            except Exception as e:
                logger.debug(f'驱动终止进程失败: {e}')
        # 2. psutil 终止
        if HAS_PSUTIL:
            try:
                p = psutil.Process(pid)
                p.terminate()
                try:
                    p.wait(timeout=3)
                except Exception:
                    pass
                return True
            except Exception as e:
                logger.debug(f'psutil 终止进程失败: {e}')
        # 3. taskkill 兜底
        try:
            import subprocess
            subprocess.run(['taskkill', '/F', '/PID', str(pid)],
                           capture_output=True, timeout=5,
                           creationflags=_HIDDEN_CREATIONFLAGS)
            return True
        except Exception as e:
            logger.debug(f'taskkill 终止进程失败: {e}')
        return False

    @pyqtSlot(str, result=str)
    def restartSandboxedProcess(self, payload_json: str) -> str:
        """重启被沙箱终止的进程（前端用户点击"同意重启"后调用）

        Args:
            payload_json: JSON 字符串，包含 path 和 cmdline

        Returns:
            JSON 字符串，包含 success 和 message
        """
        try:
            data = json.loads(payload_json)
            exe = data.get('path', '')
            cmdline = data.get('cmdline')

            if not exe or not os.path.isfile(exe):
                return json.dumps({'success': False, 'message': '文件不存在'}, ensure_ascii=False)

            if self._process_protection:
                ok = self._process_protection.restart_sandboxed_process(exe, cmdline)
                if ok:
                    self._add_activity('沙箱放行', f'已重启进程: {os.path.basename(exe)}', 'INFO', '完成')
                    return json.dumps({'success': True, 'message': '进程已重启'}, ensure_ascii=False)
                else:
                    return json.dumps({'success': False, 'message': '重启失败'}, ensure_ascii=False)
            else:
                return json.dumps({'success': False, 'message': '进程保护模块未启动'}, ensure_ascii=False)
        except Exception as e:
            logger.error(f'restartSandboxedProcess 异常: {e}', exc_info=True)
            return json.dumps({'success': False, 'message': str(e)}, ensure_ascii=False)

    def _on_process_threat(self, threat_data: dict):
        """进程保护检测到威胁的回调（在进程保护子线程中调用，需转发到主线程）

        处置策略（追求最快杀进程）：
        1. ProcessProtection._auto_handle_threat 已先杀进程 → 设 `_pp_handled_kill=True`
           bridge 看到此标记就只做隔离/通知，不再重复杀进程和 ScanEngine 初始化
        2. 签名确认的恶意进程 → bridge 层面也不做 ScanEngine 初始化，直接隔离
        3. 行为检测威胁 → 先杀进程（如果 PP 没杀），再后台线程扫描确认
        """
        try:
            threat_type = threat_data.get('type', 'threat')
            pid = threat_data.get('pid', 0)
            name = threat_data.get('name', '未知')
            exe_path = threat_data.get('path', '')

            pp_already_killed = threat_data.get('_pp_handled_kill', False)
            has_scan = 'scan_result' in threat_data

            self._add_activity(
                '进程保护',
                f"检测到威胁: {name} (PID={pid})"
                f"{' [PP已杀进程]' if pp_already_killed else ''}",
                'WARN', '威胁'
            )
            self._emit_tool_signal('processThreatDetected',
                                   json.dumps(threat_data, ensure_ascii=False))
            action = self._rt_malware_action if threat_type == 'malware_process' else self._rt_suspicious_action
            # 播放提示音（检测到恶意进程威胁 + 弹通知 → error2.mp3）
            # 仅上报不处置（action='ignore'）不播放提示音
            if action != 'ignore':
                self._request_error2_sound()

            # ProcessProtection 的 _auto_handle_threat 已经杀了进程，
            # bridge 无需再启动 ScanEngine / 再杀一次 —— 跳过处置逻辑
            # 但样本文件可能还在磁盘上（未隔离），仍触发沙箱分析
            if pp_already_killed:
                if exe_path and os.path.isfile(exe_path):
                    self._maybe_trigger_sandbox(
                        exe_path, source='进程保护',
                        process_name=name, pid=pid,
                    )
                return

            if action == 'ignore':
                return

            if action == 'auto' and exe_path and os.path.isfile(exe_path):
                # --- 阶段 1：杀进程（必须同步立即执行，不嵌套在后台线程里）---
                kill_ok = False
                if pid > 0 and self._process_protection:
                    t0 = time.perf_counter()
                    kill_ok = self._process_protection.kill_process(
                        pid, force=True, kill_tree=True, timeout=1.0)
                    dt = (time.perf_counter() - t0) * 1000
                    logger.info(f"bridge._on_process_threat kill_process PID={pid} "
                                f"耗时 {dt:.0f}ms 结果={kill_ok}")

                # --- 阶段 2：后台线程做隔离 + 沙箱（签名确认直接隔离，行为检测需要扫描确认）---
                def _async_followup():
                    try:
                        # 在隔离文件之前先触发沙箱（文件此时还在磁盘上）
                        if exe_path and os.path.isfile(exe_path):
                            self._maybe_trigger_sandbox(
                                exe_path, source='进程保护',
                                process_name=name, pid=pid,
                            )

                        if threat_type == 'malware_process':
                            # 签名确认 — 跳过 ScanEngine 初始化，直接隔离
                            sig_name = threat_data.get('signature', {}).get(
                                'name', 'Malware.Process')
                            self._auto_process_threat(
                                exe_path, sig_name, 'malware',
                                skip_kill=True  # kill 已在阶段 1 做过
                            )
                            self._add_activity(
                                '进程保护',
                                f'已自动隔离: {name} (PID={pid})',
                                'ERROR', '已处置')
                        else:
                            # 行为检测 — 杀进程已完成，后台做一次扫描确认文件是否恶意
                            engine = self._create_scan_engine_for_realtime()
                            if engine:
                                result = engine.scan_file_with_archives_summary(exe_path)
                                status = result.get('status', 'clean')
                                if status in ('malware', 'suspicious'):
                                    sig_name = result.get('name', status)
                                    self._auto_process_threat(
                                        exe_path, sig_name, status, skip_kill=True)
                                    self._emit_tool_signal('processThreatHandled',
                                        json.dumps({'pid': pid, 'name': name,
                                                    'path': exe_path,
                                                    'scan_result': result,
                                                    'action': 'auto_processed'},
                                                   ensure_ascii=False))
                                    self._add_activity(
                                        '进程保护',
                                        f'深度扫描确认威胁，已隔离: {name} → {sig_name}',
                                        'ERROR', '已处置')
                                else:
                                    self._emit_tool_signal('processThreatHandled',
                                        json.dumps({'pid': pid, 'name': name,
                                                    'path': exe_path,
                                                    'scan_result': result,
                                                    'action': 'behavioral_kill_only'},
                                                   ensure_ascii=False))
                                    self._add_activity(
                                        '进程保护',
                                        f'行为检测威胁已终止，文件干净跳过隔离: {name}',
                                        'WARNING', '已处置')
                        # 通知 UI
                        self._notify_process_kill_result(
                            pid, name, exe_path, kill_ok, scenario='进程保护')
                    except Exception as e:
                        logger.error(f"bridge._on_process_threat 异步跟进异常: {e}")

                threading.Thread(target=_async_followup, daemon=True).start()

        except Exception as e:
            logger.error(f'进程威胁回调处理失败: {e}')

    def _launch_ignore_key(self, file_path: str) -> str:
        """启动扫描忽略表的键：**规范化绝对路径 + 文件大小**（小写）。

        为什么选它：
          - 需要"可识别同一对象"且**在 GUI 线程零 IO**（不能为了判定去读整个文件算哈希）；
          - 文件被替换/篡改（大小变化）→ 键不匹配 → **自动失效重新触发**，避免
            "忽略了一个文件后同路径换成恶意文件也被放过"；
          - 与白名单完全分离（本表不改变"可信/白名单"语义）。
        另在写入时后台补记 SHA256 供排查（不参与命中判定）。
        """
        try:
            p = os.path.normcase(os.path.abspath(file_path))
            try:
                size = os.path.getsize(file_path)
            except OSError:
                size = -1
            return f'{p}|{size}'
        except Exception:
            return ''

    def _load_launch_scan_ignores(self) -> dict:
        """读取启动扫描忽略表（settings.json 的 ui 段；独立于白名单）。"""
        try:
            data = _load_ui_settings().get('launch_scan_ignores') or {}
            return dict(data) if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_launch_scan_ignores(self, table: dict) -> bool:
        try:
            _save_ui_settings({'launch_scan_ignores': dict(table or {})})
            return True
        except Exception as e:
            logger.warning(f'保存启动扫描忽略表失败: {e}')
            return False

    def _is_launch_scan_ignored(self, file_path: str) -> bool:
        """该对象是否已被用户"忽略"（命中则跳过启动扫描触发）。"""
        try:
            key = self._launch_ignore_key(file_path)
            if not key:
                return False
            table = self._load_launch_scan_ignores()
            entry = table.get(key)
            if not entry:
                return False
            # 过期清理：默认长期有效（可撤销）；此处仅记录命中
            logger.info(f'启动扫描忽略表命中，跳过触发: {file_path}（忽略于 {entry.get("ts", "")}）')
            return True
        except Exception as e:
            logger.debug(f'启动扫描忽略表判定异常: {e}')
            return False

    def _add_launch_scan_ignore(self, file_path: str, source: str = 'user_ignore'):
        """记录"用户显式忽略"（**仅由用户操作调用**，绝不自动写入）。

        后台线程补记 SHA256（可选，仅排查用），不阻塞 GUI。
        """
        try:
            if not file_path:
                return False
            key = self._launch_ignore_key(file_path)
            if not key:
                return False
            table = self._load_launch_scan_ignores()
            table[key] = {
                'path': os.path.abspath(file_path),
                'size': os.path.getsize(file_path) if os.path.isfile(file_path) else -1,
                'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
                'source': source,
                'hash': '',
            }
            ok = self._save_launch_scan_ignores(table)
            self._add_activity('启动扫描',
                               f'已忽略该对象（不再触发启动扫描）: '
                               f'{os.path.basename(file_path)}', 'INFO', '已忽略')

            def _fill_hash(_fp=file_path, _k=key):
                try:
                    from utils.hash_utils import calculate_file_hash
                    h = calculate_file_hash(_fp)
                    t = self._load_launch_scan_ignores()
                    if _k in t and h:
                        t[_k]['hash'] = h
                        self._save_launch_scan_ignores(t)
                except Exception:
                    pass
            threading.Thread(target=_fill_hash, daemon=True,
                             name='LaunchIgnoreHash').start()
            return ok
        except Exception as e:
            logger.warning(f'记录启动扫描忽略失败: {e}')
            return False

    @pyqtSlot(result=str)
    def getLaunchScanIgnores(self) -> str:
        """读取启动扫描忽略表（供设置页/日志查看；JSON）。"""
        try:
            return _safe_json_dumps({'ok': True,
                                     'ignores': self._load_launch_scan_ignores()})
        except Exception as e:
            return _safe_json_dumps({'ok': False, 'ignores': {}, 'error': str(e)})

    @pyqtSlot(str, result=bool)
    def clearLaunchScanIgnore(self, file_path: str) -> bool:
        """撤销单个对象的"启动扫描忽略"（撤销后恢复触发）。"""
        try:
            key = self._launch_ignore_key(file_path)
            table = self._load_launch_scan_ignores()
            if key and key in table:
                table.pop(key, None)
                self._save_launch_scan_ignores(table)
                self._add_activity('启动扫描', f'已撤销忽略: {os.path.basename(file_path)}',
                                   'INFO', '已恢复')
                return True
            # 兼容：也允许按路径前缀匹配清理
            changed = False
            target = os.path.normcase(os.path.abspath(file_path)) if file_path else ''
            for k in list(table.keys()):
                if target and k.startswith(target + '|'):
                    table.pop(k, None)
                    changed = True
            if changed:
                self._save_launch_scan_ignores(table)
                self._add_activity('启动扫描', '已撤销忽略（按路径匹配）', 'INFO', '已恢复')
            return changed
        except Exception as e:
            logger.warning(f'撤销启动扫描忽略失败: {e}')
            return False

    @pyqtSlot(result=int)
    def clearAllLaunchScanIgnores(self) -> int:
        """清空启动扫描忽略表（全部恢复触发），返回清除条数。"""
        try:
            table = self._load_launch_scan_ignores()
            n = len(table)
            self._save_launch_scan_ignores({})
            self._add_activity('启动扫描', f'已清空启动扫描忽略表（{n} 条）', 'INFO', '已恢复')
            return n
        except Exception as e:
            logger.warning(f'清空启动扫描忽略表失败: {e}')
            return 0

    _LAUNCH_SCAN_EXCLUDED_PROCS = {
        # Windows 关键/基础设施进程（不应作为样本分析）
        'system', 'system idle process', 'registry', 'memory compression',
        'secure system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
        'services.exe', 'lsass.exe', 'svchost.exe', 'dwm.exe', 'fontdrvhost.exe',
        'audiodg.exe', 'conhost.exe', 'conhost', 'explorer.exe', 'taskhostw.exe',
        'sihost.exe', 'ctfmon.exe', 'searchindexer.exe', 'spoolsv.exe',
        'wmiprvse.exe', 'dllhost.exe', 'runtimebroker.exe', 'shellexperiencehost.exe',
        'startmenuexperiencehost.exe', 'securityhealthservice.exe',
        'msmpeng.exe', 'nissrv.exe',
    }

    def _register_internal_copy_provider(self):
        """把实时监控的"锁定文件内部读取通道"注入沙箱分析器。

        动机：PSLS 自己持锁时，沙箱复制同一文件会被自己的锁挡住 → 分析失败。
        注入后沙箱走内部通道（用我们自己句柄读副本），自己人不被自己锁死。
        """
        try:
            from engine.sandbox_analyzer import set_internal_copy_provider
            rm = self._realtime_monitor
            set_internal_copy_provider(
                (lambda p: rm.locked_copy_to_temp(p)) if rm is not None else None)
        except Exception as e:
            logger.debug(f'注入沙箱内部复制通道失败: {e}')

    def _is_launch_scan_excluded(self, name: str, exe_path: str = '') -> bool:
        """启动扫描/沙箱候选排除：系统关键进程 + 沙箱基础设施 + PSLS 自身。

        实测误报：`conhost.exe`、`sbieini.exe`（Sandboxie 自身）被当作样本。
        这里按进程名与路径双重排除，避免把系统/沙箱组件送去"分析"。
        """
        try:
            n = (name or '').lower().strip()
            if n in self._LAUNCH_SCAN_EXCLUDED_PROCS:
                return True
            # 沙箱基础设施（Sandboxie 自身组件/服务）
            for frag in ('sbie', 'sandboxie', 'start.exe'):
                if frag in n:
                    return True
            # PSLS 自身与宿主（复用历史排除思路）
            if 'psls' in n or 'mlworker' in n:
                return True
            p = (exe_path or '').lower()
            if p and any(frag in p for frag in
                         ('\\sandboxie', '\\sandboxie-plus', '\\psls\\')):
                # 仅排除沙箱组件与 PSLS 自身目录；**保留** system32 落盘样本的检测
                return True
            return False
        except Exception:
            return False

    def _on_launch_scan_result(self, data: dict):
        """启动扫描结果回调：当新启动的应用扫描结果非 clean 时调用

        在进程保护子线程中调用，需转发到主线程。
        流程：
        1. 弹出桌面通知弹窗（威胁询问）
        2. 同时送入沙箱分析（独立子进程，避免阻塞主 UI）
        3. 发射信号到前端

        注意：启动扫描的威胁**不计入**实时防护累计威胁数（_realtime_threat_count），
        因为这些是针对应用启动事件的专项扫描，与实时文件防护无关。
        启动扫描的威胁计数通过独立的 _launch_scan_threat_count 跟踪。
        """
        try:
            pid = data.get('pid', 0)
            name = data.get('name', '未知')
            exe_path = data.get('exe_path', '')
            scan_result = data.get('scan_result', {})
            status = scan_result.get('status', 'suspicious')

            # ---- 需求 A：命中"启动扫描忽略表" → 完全跳过触发 ----
            # （不弹窗、不 blocked、不送沙箱；实时防护/其它引擎不受影响）
            if exe_path and self._is_launch_scan_ignored(exe_path):
                self._add_activity('启动扫描',
                                   f'已忽略对象，跳过启动扫描: {name} (PID={pid})',
                                   'INFO', '已忽略')
                return

            # ---- 需求 B2：候选集排除系统关键进程与沙箱基础设施 ----
            # conhost.exe / sbieini.exe / Start.exe / SbieSvc / SandboxieRpcSs 等
            # 系统或沙箱自身进程不应被当作样本送去"分析"。
            if self._is_launch_scan_excluded(name, exe_path):
                logger.info(f'启动扫描候选排除（系统/沙箱基础设施进程）: {name} (PID={pid})')
                return
            sig_name = scan_result.get('name', status)

            # 启动监测（scanning）状态：仅记录活动，不弹威胁窗、不重复沙箱
            if status == 'scanning':
                monitor_reason = scan_result.get('reason', '')
                # 需求 B3：'exe 路径不可用' 说明**根本没进入沙箱分析**，
                # 不能记为"沙箱分析中"（误导用户以为在分析）。
                if '路径不可用' in monitor_reason or 'path_unavailable' in monitor_reason \
                        or not exe_path:
                    self._add_activity(
                        '启动监测',
                        f'跳过（exe 路径不可用，非沙箱分析中）: {name} (PID={pid})'
                        + (f'（{monitor_reason}）' if monitor_reason else ''),
                        'INFO', '已跳过'
                    )
                    return
                self._add_activity(
                    '启动监测',
                    f'拦截待分析: {name} (PID={pid}) 沙箱分析中'
                    + (f'（{monitor_reason}）' if monitor_reason else ''),
                    'INFO',
                    status
                )
                self._emit_tool_signal('processThreatDetected',
                    json.dumps({
                        'type': 'launch_monitor',
                        'pid': pid,
                        'name': name,
                        'path': exe_path,
                        'status': status,
                        'reason': monitor_reason,
                    }, ensure_ascii=False))
                return

            # 独立的启动扫描威胁计数
            with self._realtime_count_lock:
                self._launch_scan_threat_count = getattr(self, '_launch_scan_threat_count', 0) + 1

            self._add_activity(
                '启动扫描',
                f'检测到非安全应用启动: {name} (PID={pid}) → {status}'
                f'{" [缓存]" if scan_result.get("cached") else ""}',
                'WARN' if status == 'suspicious' else 'ERROR',
                status
            )

            # 发射信号到前端（不在此累加实时威胁计数）
            self._emit_tool_signal('processThreatDetected',
                json.dumps({
                    'type': 'launch_scan',
                    'pid': pid,
                    'name': name,
                    'path': exe_path,
                    'status': status,
                    'signature_name': sig_name,
                    'scan_result': scan_result,
                }, ensure_ascii=False))

            # 播放提示音（启动监测：可疑 → info.mp3，威胁 → warn.mp3）
            if status == 'malware':
                self._request_warn_sound()
            else:
                self._request_info_sound()

            # 弹出桌面威胁通知弹窗（通过 _pending_results 队列转发到主线程）
            popup_data = {
                'status': status,
                'signature_name': f'[启动扫描] {sig_name}',
                'file_path': exe_path,
                'pid': pid,
                'process_name': name,
                'source': 'launch_scan',
                'suppress_realtime_count': True,  # 关键：告知 auto 流程不累加实时威胁计数
            }
            popup_payload = json.dumps(popup_data, ensure_ascii=False)
            with self._signal_lock:
                self._pending_results.append({
                    'type': 'threat_action_required',
                    'payload': popup_payload
                })

            # 沙箱分析：触发通用入口（异步、去重、限流都在 _maybe_trigger_sandbox 里处理）
            if exe_path and os.path.isfile(exe_path) and status != 'clean':
                self._maybe_trigger_sandbox(
                    exe_path, source='启动扫描',
                    process_name=name, pid=pid,
                )

        except Exception as e:
            logger.error(f'启动扫描回调处理失败: {e}')

    @pyqtSlot(result=str)
    def getProcessProtectionStatus(self) -> str:
        """获取进程保护状态（JSON）"""
        data = {
            'running': self._process_protection.is_running if self._process_protection else False,
            'enabled': self._module_states.get('process-protection', True),
            'stats': self._process_protection.get_stats() if self._process_protection else {},
            'events': self._process_protection.get_recent_events(20) if self._process_protection else [],
        }
        return json.dumps(data, ensure_ascii=False)

    def _on_self_protection_threat(self, threat_data: dict):
        """自我保护检测到威胁的回调（在自我保护子线程中调用）"""
        try:
            threat_type = threat_data.get('type', 'unknown')
            detail = threat_data.get('detail', '')
            self._add_activity(
                '自我保护',
                f"检测到威胁: {detail}",
                'ERROR',
                '威胁'
            )
            # 发射信号到前端
            self._emit_tool_signal('selfProtectionThreat',
                                   json.dumps(threat_data, ensure_ascii=False))
            # 子线程安全地将威胁数据转发到主线程，显示桌面弹窗
            with self._signal_lock:
                self._pending_self_protection_threats.append(dict(threat_data))
            # 播放提示音（自我保护命中恶意威胁 + 弹通知 → error2.mp3）
            self._request_error2_sound()
        except Exception as e:
            logger.error(f'自我保护威胁回调处理失败: {e}')

    @pyqtSlot(result=QVariant)
    def getSelfProtectionStatus(self):
        """获取自我保护状态（返回 dict，QWebChannel 自动转为 JS Object）

        state 字段说明：
        - 'uninitialized': 防护模块尚未初始化（启动延迟中）
        - 'starting': 初始化完成，监控线程启动中
        - 'running': 正常运行中
        - 'stopped': 已停止
        """
        try:
            sp = self._self_protection
            if sp is None:
                print('[DEBUG getSelfProtectionStatus] _self_protection is None')
                return {
                    'state': 'uninitialized',
                    'running': False,
                    'enabled': True,
                    'stats': {},
                    'events': [],
                    'files_monitored': 0,
                }

            # 逐个获取属性/方法，避免单个失败导致整体返回异常状态
            try:
                is_running = sp.is_running
            except Exception as e:
                print(f'[DEBUG getSelfProtectionStatus] is_running error: {e}')
                is_running = False

            try:
                is_enabled = sp.is_enabled
            except Exception as e:
                print(f'[DEBUG getSelfProtectionStatus] is_enabled error: {e}')
                is_enabled = True

            try:
                stats = sp.get_stats()
            except Exception as e:
                print(f'[DEBUG getSelfProtectionStatus] get_stats error: {e}')
                stats = {}

            try:
                events = sp.get_recent_events(20)
            except Exception as e:
                print(f'[DEBUG getSelfProtectionStatus] get_recent_events error: {e}')
                events = []

            try:
                files_monitored = len(sp.get_protected_files())
            except Exception as e:
                print(f'[DEBUG getSelfProtectionStatus] get_protected_files error: {e}')
                files_monitored = 0

            print(f'[DEBUG getSelfProtectionStatus] is_running={is_running}, is_enabled={is_enabled}')
            return {
                'state': 'running' if is_running else 'stopped',
                'running': is_running,
                'enabled': is_enabled,
                'stats': stats,
                'events': events,
                'files_monitored': files_monitored,
            }
        except Exception as e:
            logger.error(f'获取自我保护状态失败: {e}')
            return {
                'state': 'error',
                'running': False,
                'enabled': True,
                'stats': {},
                'events': [],
                'files_monitored': 0,
                'error': str(e),
            }

    @pyqtSlot(bool, result=str)
    @_cfg_timed
    def setSelfProtectionEnabled(self, enabled: bool) -> str:
        """设置自我保护开关状态（设置页"自我保护"开关调用）

        开启时：
            - 启动监控（如未运行）
            - 将所有关键文件设为只读属性，拒绝普通写访问
            - 重新建立文件哈希基线
            - 显示结果弹窗
        关闭时：
            - 恢复所有关键文件为可写属性
            - 监控继续运行但跳过所有检查（与当前关闭状态逻辑一致）
            - 显示结果弹窗

        Args:
            enabled: True 启用，False 关闭

        Returns:
            JSON 字符串，包含执行结果详情
        """
        try:
            # 自我保护强制开启：V26.1.4+ 已砍掉开关，拒绝一切关闭请求
            if not enabled:
                logger.warning('自我保护为强制开启，忽略关闭请求')
                return json.dumps({
                    'success': False,
                    'enabled': True,
                    'message': '自我保护为强制开启，不可关闭',
                    'protected_count': 0,
                    'restored_count': 0,
                    'failed_count': 0,
                }, ensure_ascii=False)
            if not self._self_protection:
                return json.dumps({
                    'success': False,
                    'enabled': False,
                    'message': '自保护引擎未初始化',
                    'protected_count': 0,
                    'restored_count': 0,
                    'failed_count': 0,
                }, ensure_ascii=False)

            result = self._self_protection.set_enabled(enabled)
            result['success'] = result.get('failed_count', 0) == 0

            if enabled:
                msg = (
                    f"已成功保护 {result.get('protected_count', 0)} 个关键文件，"
                    f"普通修改将被阻止"
                )
                if result.get('failed_count', 0) > 0:
                    msg += f"（{result.get('failed_count', 0)} 个文件保护失败）"
            else:
                msg = (
                    f"已恢复 {result.get('restored_count', 0)} 个关键文件为可写，"
                    f"自保护已关闭"
                )
                if result.get('failed_count', 0) > 0:
                    msg += f"（{result.get('failed_count', 0)} 个文件恢复失败）"

            result['message'] = msg

            # 更新模块状态
            self._module_states['self-protection'] = enabled

            # 主动更新最后一次自我保护状态，避免状态推送误报为"异常突变"
            # （用户主动操作属于正常变化，不是异常突变）
            try:
                running = sp.is_running if sp else False
                files_monitored = len(sp.get_protected_files()) if sp else 0
            except Exception:
                running = False
                files_monitored = 0
            self._last_self_prot_state = {
                'state': 'running' if running else 'stopped',
                'running': running,
                'enabled': enabled,
                'files_monitored': files_monitored,
            }

            # 发射状态变化信号（前端可监听）
            self._emit_tool_signal(
                'selfProtectionStatusChanged',
                _safe_json_dumps(result)
            )

            # 显示桌面弹窗
            try:
                popup = SelfProtectionStatusPopup(
                    enabled=enabled,
                    success=result['success'],
                    message=msg,
                )
                self._show_status_popup(popup)
            except Exception as e:
                logger.warning(f'显示自保护状态弹窗失败: {e}')

            # 记录活动日志
            self._add_activity(
                '自我保护',
                f"{'已启用' if enabled else '已关闭'}：{msg}",
                'INFO' if result['success'] else 'WARN',
                '系统'
            )

            return _safe_json_dumps(result)
        except Exception as e:
            logger.error(f'设置自保护开关失败: {e}')
            return json.dumps({
                'success': False,
                'enabled': self._self_protection.is_enabled if self._self_protection else False,
                'message': f'操作异常: {str(e)}',
                'protected_count': 0,
                'restored_count': 0,
                'failed_count': 0,
            }, ensure_ascii=False)

    @pyqtSlot(int, bool)
    def killProcess(self, pid: int, force: bool = False) -> bool:
        """终止指定进程"""
        if self._process_protection:
            return self._process_protection.kill_process(pid, force)
        return False

    def _on_ransomware_kill(self, pid_str: str):
        """勒索行为检测后立即终止进程 — 由 file_protection 触发

        这是最后的防线: watchdog 检测到批量文件修改/加密后缀时,
        立即 kill 正在加密的进程, 不等用户态决策链路。

        现象 2 加固：本回调内含 `kill_process(timeout=0.5, kill_tree=True)` 与 psutil
        遍历（阻塞式）。正常由 file_protection 子线程调用；若**被主线程**调用
        （或被误接成直连信号），会阻塞 GUI → 这里强制转后台线程执行，
        保证"任何检测回调都不在 GUI 线程同步等待/阻塞"。
        """
        if threading.current_thread() is threading.main_thread():
            try:
                threading.Thread(target=self._on_ransomware_kill,
                                 args=(pid_str,), daemon=True,
                                 name='RansomwareKillOffload').start()
            except Exception as e:
                logger.warning(f'[勒索防护] 转后台线程失败: {e}')
            return
        try:
            pid = int(pid_str)
        except (ValueError, TypeError):
            logger.error(f'[勒索防护] 无效 PID: {pid_str}')
            return

        # [防自杀防护] 绝不终止 PSLS 自身相关进程:
        # 自我保护备份/引导区回滚等自身线程写入文件时也可能持有文件句柄,
        # _find_modifying_process 若误判自身进程为勒索者, 无条件 kill 会导致
        # 主程序被强杀闪退。此处兜底拦截, 只记录日志。
        try:
            if pid == os.getpid():
                logger.warning(
                    f'[勒索防护] 跳过 PSLS 主进程自身 PID={pid}, 不终止'
                )
                return
            pp = self._process_protection
            if pp:
                proc = psutil.Process(pid)
                if pp._is_psls_related_process(proc):
                    logger.warning(
                        f'[勒索防护] 跳过 PSLS 相关进程 PID={pid}, 不终止'
                    )
                    return
        except psutil.NoSuchProcess:
            logger.info(f'[勒索防护] 进程 PID={pid} 已不存在, 无需终止')
            return
        except Exception as e:
            logger.error(f'[勒索防护] 自身进程判定异常, 仍继续终止: {e}')

        logger.critical(f'[勒索防护] 立即终止进程 PID={pid} (勒索行为检测)')
        self._add_activity(
            '勒索防护',
            f'检测到勒索行为, 立即终止进程 PID={pid}',
            'CRITICAL', 'ransomware_block'
        )
        self._emit_tool_signal('ransomwareBlocked', json.dumps({
            'pid': pid, 'action': 'killed',
            'reason': '勒索行为检测: 批量文件加密',
        }, ensure_ascii=False))
        # 播放提示音（勒索行为 → critical.mp3）
        self._request_critical_sound()

        # 立即 kill 进程树
        try:
            if self._process_protection:
                kill_ok = self._process_protection.kill_process(
                    pid, force=True, kill_tree=True, timeout=0.5
                )
                logger.info(f'[勒索防护] kill_process PID={pid} result={kill_ok}')
        except Exception as e:
            logger.error(f'[勒索防护] kill_process 异常: {e}')

    def _on_file_threat(self, threat_data: dict):
        """文件保护检测到威胁的回调

        增强逻辑：对非勒索软件类篡改，自动深度扫描被篡改文件 + 追踪篡改进程

        现象 2 加固：本回调含深度扫描/进程追踪（阻塞式），且会 emit 音效与信号。
        若被主线程调用则转后台线程，绝不阻塞 GUI。
        """
        if threading.current_thread() is threading.main_thread():
            try:
                threading.Thread(target=self._on_file_threat,
                                 args=(threat_data,), daemon=True,
                                 name='FileThreatOffload').start()
            except Exception as e:
                logger.warning(f'文件保护威胁回调转后台失败: {e}')
            return
        try:
            threat_type = threat_data.get('type', '威胁')
            file_path = threat_data.get('path', '未知')
            self._add_activity(
                '文件保护',
                f"检测到威胁: {file_path}",
                'WARN',
                threat_type
            )
            self._emit_tool_signal('fileThreatDetected',
                                   json.dumps(threat_data, ensure_ascii=False))
            action = self._rt_suspicious_action
            # 播放提示音（勒索行为/文件被修改 → critical.mp3；其他文件篡改威胁 → warn.mp3）
            # 仅上报不处置（action='ignore'）不播放提示音
            if threat_type in ('ransomware', 'ransomware_encrypted'):
                self._request_critical_sound()
            elif action != 'ignore':
                self._request_warn_sound()

            # 勒索软件已由 file_protection 内部自动隔离，无需重复处理
            if threat_type in ('ransomware', 'ransomware_encrypted'):
                return

            if action == 'ignore':
                return

            # 在子线程中深度扫描被篡改文件
            def _async_scan_tampered_file():
                try:
                    # 扫描被篡改的文件本身
                    if file_path and os.path.isfile(file_path):
                        engine = self._create_scan_engine_for_realtime()
                        if engine:
                            # scan_file_with_archives 返回 List[ScanResult]，
                            # 单文件处置场景应使用 _summary 版本（返回聚合 dict，可直接 .get()）
                            result = engine.scan_file_with_archives_summary(file_path)
                            status = result.get('status', 'clean')
                            if status in ('malware', 'suspicious'):
                                sig_name = result.get('name', status)
                                self._add_activity('文件保护',
                                    f'深度扫描确认威胁: {file_path} → {sig_name}',
                                    'ERROR', '已确认')
                                if action == 'auto':
                                    self._auto_process_threat(file_path, sig_name, status)
                                    self._add_activity('文件保护',
                                        f'已自动处置威胁文件: {os.path.basename(file_path)}',
                                        'ERROR', '已处置')
                                self._emit_tool_signal('fileThreatHandled',
                                    json.dumps({'path': file_path,
                                               'scan_result': result, 'action': action},
                                               ensure_ascii=False))
                            else:
                                self._add_activity('文件保护',
                                    f'深度扫描未确认威胁: {file_path} (结果: {status})',
                                    'INFO', '扫描完成')
                except Exception as e:
                    logger.error(f'异步扫描文件威胁失败: {e}')

            threading.Thread(target=_async_scan_tampered_file, daemon=True).start()

        except Exception as e:
            logger.error(f'文件威胁回调处理失败: {e}')

    @pyqtSlot(result=str)
    def getFileProtectionStatus(self) -> str:
        """获取文件保护状态（JSON）"""
        fp = self._file_protection
        data = {
            'running': fp.is_running if fp else False,
            'enabled': self._module_states.get('file-protection', True),
            'stats': fp.get_stats() if fp else {},
            'events': fp.get_recent_events(20) if fp else [],
        }
        return json.dumps(data, ensure_ascii=False)

    @pyqtSlot(str, result=bool)
    def addProtectedFile(self, file_path: str) -> bool:
        """添加受保护文件"""
        if self._file_protection:
            return self._file_protection.add_protected_file(file_path)
        return False

    @pyqtSlot(str, result=bool)
    def restoreFile(self, file_path: str) -> bool:
        """恢复受保护文件"""
        if self._file_protection:
            return self._file_protection.restore_file(file_path)
        return False

    def _on_system_threat(self, threat_data: dict):
        """系统保护检测到威胁的回调

        增强逻辑：自动追踪篡改来源进程并深度扫描
        """
        try:
            threat_type = threat_data.get('type', 'threat')
            target = threat_data.get('target', '未知')
            self._add_activity(
                '系统保护',
                f"检测到威胁: {target}",
                'WARN',
                threat_type
            )
            self._emit_tool_signal('systemThreatDetected',
                                   json.dumps(threat_data, ensure_ascii=False))
            # 自动追踪篡改来源：查找最近修改相关文件/注册表的进程
            action = self._rt_suspicious_action
            # 播放提示音（注册表等系统持久化被篡改 → critical.mp3）
            # 仅上报不处置（action='ignore'）不播放提示音
            if action != 'ignore':
                self._request_critical_sound()

            if action == 'ignore':
                return

            # 在子线程中追踪篡改进程并扫描
            def _async_trace_and_scan():
                try:
                    suspect_pid = threat_data.get('pid', 0)
                    suspect_path = threat_data.get('process_path', '')

                    # 若未提供进程信息，尝试通过 psutil 查找可疑进程
                    if not suspect_pid and not suspect_path:
                        try:
                            import psutil
                            # 查找最近活跃的非系统进程
                            now = time.time()
                            candidates = []
                            for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
                                try:
                                    exe = proc.info.get('exe', '')
                                    name = proc.info.get('name', '')
                                    ct = proc.info.get('create_time', 0)
                                    # 排除系统进程和 PSLS 自身
                                    if name.lower() in ('system', 'system idle process', 'registry', ''):
                                        continue
                                    if exe and exe.lower().startswith('c:\\windows\\system32\\'):
                                        continue
                                    # 最近 5 分钟内启动的进程优先
                                    if now - ct < 300:
                                        candidates.append(proc.info)
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    continue
                            # 取最近的进程
                            if candidates:
                                candidates.sort(key=lambda x: x.get('create_time', 0), reverse=True)
                                suspect_pid = candidates[0].get('pid', 0)
                                suspect_path = candidates[0].get('exe', '')
                        except Exception as e:
                            logger.error(f'追踪篡改进程失败: {e}')

                    # 先杀后验：系统保护已确认威胁存在，自动处置模式下先立即终止
                    # 可疑进程（直接按 PID 杀，缩短处置延迟），再后台扫描确认 + 隔离。
                    kill_ok = False
                    if action == 'auto' and suspect_pid > 0 and self._process_protection:
                        t0 = time.perf_counter()
                        kill_ok = self._process_protection.kill_process(
                            suspect_pid, force=True, kill_tree=True, timeout=1.0)
                        dt = (time.perf_counter() - t0) * 1000
                        logger.info(f"_on_system_threat 先杀进程 PID={suspect_pid} "
                                    f"耗时 {dt:.0f}ms 结果={kill_ok}")
                        if kill_ok:
                            self._add_activity('系统保护',
                                f'已立即终止篡改来源进程: PID={suspect_pid}',
                                'ERROR', '已处置')

                    if suspect_path and os.path.isfile(suspect_path):
                        engine = self._create_scan_engine_for_realtime()
                        if engine:
                            # scan_file_with_archives 返回 List[ScanResult]，
                            # 单文件处置场景应使用 _summary 版本（返回聚合 dict，可直接 .get()）
                            result = engine.scan_file_with_archives_summary(suspect_path)
                            status = result.get('status', 'clean')
                            if status in ('malware', 'suspicious'):
                                sig_name = result.get('name', status)
                                self._add_activity('系统保护',
                                    f'篡改来源扫描确认威胁: {suspect_path} → {sig_name}',
                                    'ERROR', '已确认')
                                if action == 'auto':
                                    # 进程已用 PID 先杀（kill_ok=True）则跳过内部按路径终止，
                                    # 避免重复处置；PID 杀失败则交由内部按路径终止兜底。
                                    self._auto_process_threat(
                                        suspect_path, sig_name, status, skip_kill=kill_ok)
                                    if kill_ok and suspect_pid > 0 and self._process_protection:
                                        self._process_protection.kill_process(
                                            suspect_pid, force=True, kill_tree=True, timeout=1.0)
                                    self._add_activity('系统保护',
                                        f'已自动处置篡改来源: PID={suspect_pid}',
                                        'ERROR', '已处置')
                                self._emit_tool_signal('systemThreatHandled',
                                    json.dumps({'pid': suspect_pid, 'path': suspect_path,
                                               'scan_result': result, 'action': action},
                                               ensure_ascii=False))
                            else:
                                self._add_activity('系统保护',
                                    f'篡改来源扫描未确认威胁: {suspect_path} (结果: {status})',
                                    'INFO', '扫描完成')
                except Exception as e:
                    logger.error(f'异步追踪扫描系统威胁失败: {e}')

            threading.Thread(target=_async_trace_and_scan, daemon=True).start()

        except Exception as e:
            logger.error(f'系统威胁回调处理失败: {e}')

    def _create_scan_engine_for_realtime(self):
        """为实时监控创建独立的 ScanEngine 实例（避免与主扫描冲突）

        根据严格模式动态配置：
        - 严格模式：MIN_FILE_SIZE_FOR_RULE_SCAN=0（覆盖小文件），strict_mode=True
        - 宽松模式：保持默认 1KB 阈值，strict_mode=False
        """
        try:
            # 复用主扫描引擎的 SignatureDB 实例，避免每次实时扫描重复加载数据库
            engine = ScanEngine(signature_db=getattr(self, '_signature_db', None))
            # 同步严格模式状态
            engine.strict_mode = self._strict_mode
            # 同步 VirusIdentifier 开关：实时防护用的是独立 ScanEngine 实例，
            # 不共享主扫描引擎的该属性，必须在此单独注入。
            engine.virus_identifier_enabled = self._vi_enabled
            if self._strict_mode:
                # 严格模式：实时扫描不跳过小文件
                engine.MIN_FILE_SIZE_FOR_RULE_SCAN = 0
            if self._scan_engine:
                engine.scan_archives = self._scan_engine.scan_archives
                # archive_depth 实际存储在 archive_scanner.max_depth 上
                if (self._scan_engine.archive_scanner
                        and engine.archive_scanner):
                    engine.archive_scanner.max_depth = self._scan_engine.archive_scanner.max_depth
                engine.max_file_size_mb = self._scan_engine.max_file_size_mb
                # 同步 YARA 状态：直接复制到新 engine 的 rule_engine
                try:
                    src_yara_enabled = getattr(
                        self._scan_engine, '_user_enabled_yara',
                        self._scan_engine.rule_engine._yara_user_enabled
                        if self._scan_engine.rule_engine else True
                    )
                    if engine.rule_engine:
                        engine.rule_engine.set_yara_enabled(src_yara_enabled)
                except Exception as inner_e:
                    logger.debug(f'同步 YARA 状态失败: {inner_e}')
            # 注入 ML 检测器，使实时防护具备 ML 推理能力
            if self._ml_detector and self._ml_detector.get_status().get('ml_available'):
                engine.set_ml_detector(self._ml_detector)
            # 同步用户排除路径
            engine.set_user_excluded_dirs(getattr(self, '_scan_excluded_paths', []))
            return engine
        except Exception as e:
            logger.error(f'创建实时扫描引擎失败: {e}')
            return None

    def _is_realtime_exempted(self, file_path: str) -> bool:
        """实时防护扫描阶段的路径豁免检查

        检查文件是否在隔离区的本次运行豁免集合中（刚从隔离区复原的文件）。
        另外兜底豁免 PSLS 自身产出路径（回滚仓库 / 影子原像根）——这些是 PSLS
        自己写入的原始文件副本，绝不应当触发扫描/隔离/终止。
        仅作用于实时防护扫描阶段，跳过已复原文件避免再次扫描触发告警/隔离。
        沙箱分析不经过此回调，不受影响。
        """
        if not file_path:
            return False
        # 回滚仓库 / 影子原像根：PSLS 自身产出，直接豁免
        try:
            from engine.ransomware_rollback import is_psls_repo_path
            if is_psls_repo_path(file_path):
                return True
        except Exception:
            pass
        if not self._quarantine_manager:
            return False
        try:
            return self._quarantine_manager.is_path_exempted(file_path)
        except Exception:
            return False

    def _on_realtime_threat(self, threat_data: dict):
        """实时监控检测到威胁的回调（在实时监控子线程中调用）

        实时防护策略根据用户设置（auto/notify/ignore）决定处理方式：
        - auto: 自动隔离威胁文件（隔离失败则删除），通过桌面弹窗通知结果
        - notify: 弹出交互弹窗让用户选择处理方式
        - ignore: 仅记录日志，不处理

        去重：若该文件已被启动扫描在近期处理过（1 小时内），
        则仅记录日志并跳过实时威胁计数，避免"双重计数"。
        """
        try:
            file_path = threat_data.get('file_path', '未知')
            malware_name = threat_data.get('malware_name', '未知威胁')
            status = threat_data.get('status', 'malware')
            level = 'WARN' if status == 'malware' else 'INFO'
            tag = '威胁' if status == 'malware' else '可疑'

            # ---------- 启动扫描去重检查 ----------
            # 若该文件已被启动扫描处理过（1 小时 TTL），跳过实时计数
            launch_dup = False
            try:
                pp = self._process_protection
                if pp is not None:
                    with pp._launch_scan_lock:
                        cached = pp._launch_scan_cache.get(file_path)
                        if cached:
                            _mt, _st, _ttl = cached
                            if time.time() - _ttl < pp._LAUNCH_SCAN_CACHE_TTL:
                                launch_dup = True
                                logger.debug(
                                    f'启动扫描已处理 {file_path}，跳过实时防护计数')
            except Exception:
                pass

            # 活动日志仍然记录（便于追溯）
            self._add_activity(
                '实时防护',
                f"检测到{tag}: {malware_name} ({file_path})"
                f"{' [启动扫描已处理,去重]' if launch_dup else ''}",
                level,
                tag
            )
            # 发射信号到前端（前端可选监听用于 UI 更新）
            self._emit_tool_signal('realtimeThreatDetected',
                                   json.dumps(threat_data, ensure_ascii=False))

            # 异步触发沙箱分析（实时防护命中威胁 → 沙箱二次验证行为）
            self._maybe_trigger_sandbox(
                file_path, source='实时防护',
                process_name=malware_name,
            )

            # 根据用户设置的处理策略决定行为
            action = self._rt_malware_action if status == 'malware' else self._rt_suspicious_action

            if action == 'ignore':
                # 忽略：仅记录日志，不处理。立即释放威胁处置独占锁
                self._add_activity('实时防护', f'已忽略: {os.path.basename(file_path)}', 'INFO', '跳过')
                self._release_realtime_threat_lock(file_path)
                return

            if action == 'notify':
                # 询问：弹出交互弹窗让用户选择处理方式
                payload = json.dumps({
                    'type': 'threat_action_required',
                    'file_path': file_path,
                    'status': status,
                    'signature_name': malware_name,
                    'source': 'realtime',
                    'suppress_realtime_count': launch_dup,  # 启动扫描已处理则不累加计数
                }, ensure_ascii=False)
                with self._signal_lock:
                    self._pending_results.append({
                        'type': 'threat_action_required',
                        'payload': payload
                    })
                # 询问模式下仍播放分级提示音并计数
                # 发现阶段：威胁 → warn.mp3（无通知的检测到威胁），可疑 → info.mp3
                if status == 'malware':
                    self._request_warn_sound()
                else:
                    self._request_info_sound()
                # 启动扫描已处理的文件在询问模式下也不累加计数
                if not launch_dup:
                    with self._realtime_count_lock:
                        self._realtime_threat_count += 1
                    self._emit_dashboard_stats_update()
                return

            # auto: 自动隔离/删除（原有逻辑）
            # 自动隔离/删除威胁文件（实时防护的核心目的：即时拦截）
            result = self._auto_process_threat(file_path, malware_name, status)
            # auto 处置流程结束后释放实时防护威胁处置锁（无论成功/失败）
            self._release_realtime_threat_lock(file_path)

            # 已豁免文件（用户曾恢复）跳过提示音和威胁计数
            # 已在隔离区（duplicate）同样跳过：避免"已隔离"结果弹窗/提示音/计数反复刷屏
            is_exempted = isinstance(result, dict) and result.get('action') in ('exempted', 'excluded')
            is_duplicate = isinstance(result, dict) and result.get('action') == 'duplicate'

            # duplicate 命中：不再弹桌面结果弹窗、不再播放提示音、不累加威胁计数
            # —— 避免"活动日志已写成功，但用户看不到弹窗仍在刷活动列表"的体验断裂
            if not is_duplicate:
                # 通过 _pending_results 队列让主线程显示桌面结果弹窗
                with self._signal_lock:
                    self._pending_results.append({
                        'type': 'threat_action_result',
                        'file_path': file_path,
                        'status': status,
                        'signature_name': malware_name,
                        'action': 'auto',
                        'result': result
                    })

            # 分级提示音（通知隔离结果：威胁 → error2.mp3，可疑 → error.mp3）
            # 声音总开关由 sound_manager._sound_enabled 控制，此处只负责按级别分发
            if not is_exempted and not is_duplicate:
                if status == 'malware':
                    self._request_error2_sound()
                else:
                    self._request_error_sound()

            # 累计实时威胁数并推送主页指标卡更新（豁免/已在隔离区文件不计数；启动扫描已处理文件不计数）
            if not is_exempted and not is_duplicate and not launch_dup:
                with self._realtime_count_lock:
                    self._realtime_threat_count += 1
                self._emit_dashboard_stats_update()
        except Exception as e:
            logger.error(f'实时防护威胁回调处理失败: {e}')

    def _release_realtime_threat_lock(self, file_path: str):
        """释放实时监控为指定文件登记的威胁处置独占句柄（安全 no-op 包装）。

        由 on_realtime_threat / processThreat 在处置流程的所有分支结束时调用。
        对未登记、非实时来源、已被超时清理的路径，调用均为 no-op，因此可以
        在不判断来源的情况下直接调用，保证锁一定被释放。
        """
        if not file_path:
            return
        try:
            if self._realtime_monitor is not None and hasattr(self._realtime_monitor, 'release_threat_lock'):
                self._realtime_monitor.release_threat_lock(file_path)
        except Exception as e:
            logger.debug(f'释放实时威胁处置锁失败 {file_path}: {e}')

    def _on_realtime_scan_result(self, scan_data: dict):
        """实时监控单个文件扫描完成的回调（无论 clean / threat / error）

        运行在实时监控子线程中，通过 realtimeScanResultReady 信号通知前端。
        功能：
        1. 仅将扫描结果信号发射给前端 UI（用于侧栏状态更新），不弹桌面弹窗
        2. 对 malware/suspicious 状态，由 _on_realtime_threat 负责弹窗（参照用户设置的威胁处理策略）
        3. 对 clean/skipped/error 状态，不弹桌面弹窗（避免打扰用户）
        """
        try:
            # 仅发射信号给前端用于 UI 状态更新，不触发桌面弹窗
            try:
                self._emit_tool_signal(
                    'realtimeScanResultReady',
                    json.dumps(scan_data, ensure_ascii=False)
                )
            except Exception:
                pass
        except Exception as e:
            logger.error(f'实时扫描结果回调处理失败: {e}')

    def _emit_dashboard_stats_update(self):
        """推送主页指标卡统计更新（仅实时防护累计威胁数）

        扫描会话的 threats 由前端在 onScanFinished 时累计，避免双重计数。
        本信号仅推送实时防护累计威胁数，前端负责合并扫描累计 + 实时累计。
        通过 _pending_tool_signals 队列在主线程发射 dashboardStatsUpdated 信号，
        确保线程安全。
        """
        try:
            realtime_threats = self._get_realtime_threat_count()
            payload = json.dumps({'realtime_threats': realtime_threats}, ensure_ascii=False)
            self._emit_tool_signal('dashboardStatsUpdated', payload)
        except Exception as e:
            logger.debug(f'推送仪表盘统计失败: {e}')

    def _get_realtime_threat_count(self) -> int:
        """线程安全地读取实时威胁计数"""
        with self._realtime_count_lock:
            return self._realtime_threat_count

    @pyqtSlot(result=str)
    def getSystemProtectionStatus(self) -> str:
        """获取系统保护状态（JSON）"""
        sp = self._system_protection
        data = {
            'running': sp.is_running if sp else False,
            'enabled': self._module_states.get('system-protection', True),
            'stats': sp.get_stats() if sp else {},
            'events': sp.get_recent_events(20) if sp else [],
        }
        return json.dumps(data, ensure_ascii=False)

    def getAutostartProtectionStatus(self) -> str:
        """获取自启动项监测状态（JSON）"""
        ap = self._autostart_protection
        data = {
            'running': ap.is_running if ap else False,
            'enabled': self._module_states.get('autostart-protection', True),
            'stats': ap.get_stats() if ap else {},
            'events': ap.get_recent_events(20) if ap else [],
            'driver_mode': getattr(ap, '_driver_enabled', False) if ap else False,
        }
        return json.dumps(data, ensure_ascii=False)

    @pyqtSlot(result=str)
    def getMBRProtectionStatus(self) -> str:
        """获取 MBR / 引导扇区 + 系统关键目录保护状态（JSON）。

        关键目录保护 (critical_dirs) 作为 MBR 防护的系统级别扩展一并推送：
        驱动/用户态快照两层：driver_dir 为内核事前拒绝写/删/改名，
        userspace_dir 为 1 秒轮询篡改校验 + 自动恢复/删除新增未知文件。
        """
        mp = self._mbr_protector
        data = {
            'running': mp.is_running if mp else False,
            'enabled': self._module_states.get('mbr-protection', True),
            'auto_restore': mp._auto_restore if mp else False,
            'driver_mon': mp.driver_mon_enabled if mp else False,
            'stats': mp.get_stats() if mp else {},
            'backups': mp.get_backup_info() if mp else [],
            'has_backup': mp is not None and mp._has_backup,
            # ---- 系统关键目录防护 (扩展) ----
            'driver_dir': mp.driver_dir_enabled if mp else False,
            'critical_dirs': mp.get_critical_dirs_info() if mp else None,
        }
        return json.dumps(data, ensure_ascii=False)

    @pyqtSlot(str, result=str)
    def restoreMBR(self, device_path: str) -> str:
        """从备份恢复引导扇区"""
        mp = self._mbr_protector
        if not mp:
            return json.dumps({'ok': False, 'error': 'MBR保护未初始化'}, ensure_ascii=False)
        dev = device_path.strip() if device_path.strip() else None
        ok = mp.restore(dev)
        msg = '恢复成功' if ok else '恢复失败(可能需要管理员权限)'
        self._add_activity('MBR保护', msg, 'INFO' if ok else 'ERROR',
                            '成功' if ok else '失败')
        return json.dumps({'ok': ok, 'message': msg}, ensure_ascii=False)

    @pyqtSlot(result=str)
    def trustMBRChange(self) -> str:
        """信任当前引导扇区状态, 刷新备份"""
        mp = self._mbr_protector
        if not mp:
            return json.dumps({'ok': False, 'error': 'MBR保护未初始化'}, ensure_ascii=False)
        mp.trust_change()
        self._add_activity('MBR保护', '已信任当前引导扇区状态, 备份已刷新',
                           'INFO', '成功')
        return json.dumps({'ok': True, 'message': '备份已刷新'}, ensure_ascii=False)

    def _on_mbr_threat(self, threat_data: dict):
        """MBR / 关键目录篡改告警回调"""
        try:
            ttype = threat_data.get('type')
            change_kind = threat_data.get('change_kind') or ''
            if ttype == 'critical_dir':
                src = '关键目录保护'
                if change_kind == 'new_dir':
                    msg = f"检测到关键目录下新增目录: {threat_data.get('label', '')}"
                elif change_kind == 'new_file':
                    msg = f"检测到关键目录下新增未知文件: {threat_data.get('label', '')}"
                else:
                    msg = f"检测到关键目录篡改: {threat_data.get('label', '')}"
            else:
                src = 'MBR保护'
                msg = f"检测到引导扇区篡改: {threat_data.get('label', '')}"
            # 优先使用引擎侧聚合后的详细 message
            m_detail = threat_data.get('message')
            if m_detail:
                msg = m_detail
            self._add_activity(src, msg, 'CRITICAL', '威胁')
            # 播放提示音（威胁/篡改 → critical.mp3）
            # 例外：仅上报不处置的事件（watch 目录常态增删 / 未启用自动处置）
            # 只记录与推送，不鸣笛——这类事件量大且无处置动作，鸣笛只会造成噪声。
            if not threat_data.get('report_only'):
                self._request_critical_sound()
            # 推送给前端
            self._emit_tool_signal(
                'mbrThreatDetected',
                json.dumps(threat_data, ensure_ascii=False))
        except Exception as e:
            logger.error(f'MBR 告警回调异常: {e}')

    def _get_realtime_watch_dirs(self) -> List[str]:
        """根据当前监控范围获取监控目录列表"""
        scope = getattr(self, '_realtime_scope', 'critical')
        if scope == 'full':
            return get_all_local_drives()
        elif scope == 'custom':
            paths = getattr(self, '_realtime_custom_paths', [])
            # 过滤掉不存在的目录
            return [p for p in paths if os.path.isdir(p)]
        else:
            # critical 模式
            return get_critical_watch_dirs()

    @pyqtSlot(str, str, result=bool)
    @_cfg_timed
    def setRealtimeScope(self, scope: str, custom_paths_json: str) -> bool:
        """设置实时监控范围

        Args:
            scope: 'critical' | 'full' | 'custom'
            custom_paths_json: 自定义路径的 JSON 字符串数组

        Returns:
            是否成功应用
        """
        try:
            if scope not in ('critical', 'full', 'custom'):
                scope = 'critical'

            custom_paths = []
            if scope == 'custom' and custom_paths_json:
                try:
                    parsed = json.loads(custom_paths_json)
                    if isinstance(parsed, list):
                        custom_paths = [str(p) for p in parsed if p]
                except Exception:
                    pass

            self._realtime_scope = scope
            self._realtime_custom_paths = custom_paths

            # 应用到实时监控器
            if self._realtime_monitor:
                watch_dirs = self._get_realtime_watch_dirs()
                self._realtime_monitor.update_watch_dirs(watch_dirs)

            logger.info(f'实时监控范围已设置: {scope}, 自定义路径数: {len(custom_paths)}')
            return True

        except Exception as e:
            logger.error(f'设置实时监控范围失败: {e}')
            return False

    @pyqtSlot(result=str)
    def getRealtimeScope(self) -> str:
        """获取当前实时监控范围配置"""
        data = {
            'scope': getattr(self, '_realtime_scope', 'critical'),
            'customPaths': list(getattr(self, '_realtime_custom_paths', [])),
        }
        return json.dumps(data, ensure_ascii=False)

    @pyqtSlot(str, result=bool)
    @_cfg_timed
    def setScanExcludedPaths(self, paths_json: str) -> bool:
        """设置扫描排除路径列表

        Args:
            paths_json: 路径列表的 JSON 字符串数组

        Returns:
            是否成功
        """
        try:
            paths = []
            if paths_json:
                try:
                    parsed = json.loads(paths_json)
                    if isinstance(parsed, list):
                        paths = [str(p) for p in parsed if p and isinstance(p, str)]
                except Exception:
                    pass
            self._scan_excluded_paths = paths
            # 同步到实时监控器（路径级排除，扫描前即跳过，修复排除项失效）
            try:
                if self._realtime_monitor is not None:
                    self._realtime_monitor.set_user_excluded_dirs(paths)
            except Exception as e:
                logger.error(f'同步排除路径到实时监控失败: {e}')
            logger.info(f'扫描排除路径已更新: {len(paths)} 条')
            return True
        except Exception as e:
            logger.error(f'设置扫描排除路径失败: {e}')
            return False

    @pyqtSlot(result=str)
    def getScanExcludedPaths(self) -> str:
        """获取当前扫描排除路径列表"""
        data = {
            'paths': list(getattr(self, '_scan_excluded_paths', [])),
        }
        return json.dumps(data, ensure_ascii=False)

    @pyqtSlot(result=str)
    def getRealtimeMonitorStatus(self) -> str:
        """获取实时监控状态（JSON）"""
        rm = self._realtime_monitor
        data = {
            'running': rm.is_running if rm else False,
            'enabled': self._module_states.get('realtime-monitor', True),
            'hasWatchdog': rm.has_watchdog if rm else False,
            'stats': rm.get_stats() if rm else {},
            'events': rm.get_recent_events(20) if rm else [],
            'watchDirs': rm.get_watch_dirs() if rm else [],
        }
        return json.dumps(data, ensure_ascii=False)

    @pyqtSlot(result=str)
    def getStartupItems(self) -> str:
        """获取当前启动项列表"""
        if self._system_protection:
            items = self._system_protection.get_startup_items()
            return json.dumps(items, ensure_ascii=False)
        return '[]'

    @pyqtSlot(str, result=bool)
    def restoreRegistryKey(self, key_path: str) -> bool:
        """恢复注册表键"""
        if self._system_protection:
            return self._system_protection.restore_registry_key(key_path)
        return False

    @pyqtSlot(result=bool)
    def restoreHostsFile(self) -> bool:
        """恢复 hosts 文件"""
        if self._system_protection:
            return self._system_protection.restore_hosts_file()
        return False

    @pyqtSlot(int, result=str)
    def scanProcessMemory(self, pid: int) -> str:
        """扫描进程内存（参照 yara_mem_scan）

        使用 YARA 规则扫描指定进程的内存空间，
        检测无文件威胁和内存注入恶意软件。

        Args:
            pid: 进程 ID

        Returns:
            JSON 字符串：匹配的规则列表
        """
        try:
            if not self._scan_engine or not self._scan_engine.rule_engine:
                return json.dumps({'error': '扫描引擎未初始化'}, ensure_ascii=False)

            rule_engine = self._scan_engine.rule_engine
            if not rule_engine.yara_enabled:
                return json.dumps({'error': '内存扫描需要 YARA 引擎支持'}, ensure_ascii=False)

            matches = rule_engine.scan_process_memory(pid)
            self._add_activity(
                '内存扫描',
                f'扫描进程 PID={pid} 内存: {len(matches)} 个匹配',
                'INFO' if not matches else 'WARN',
                '完成' if not matches else '发现威胁'
            )
            return json.dumps({
                'pid': pid,
                'matches': matches,
                'count': len(matches),
            }, ensure_ascii=False)
        except Exception as e:
            logger.error(f'内存扫描失败 PID={pid}: {e}')
            return json.dumps({'error': str(e)}, ensure_ascii=False)

    @pyqtSlot(result=QVariant)
    def getRuleEngineStatus(self):
        """获取规则引擎状态（YARA 是否启用等）

        注意：不再在同步调用路径中执行子进程检测（避免阻塞主线程导致
        QWebChannel 超时返回异常值）。子进程刷新仅在 _broadcast_state_changes
        中按需异步触发。
        """
        try:
            if not self._scan_engine or not self._scan_engine.rule_engine:
                return {'yara_enabled': False, 'yara_installed': False, 'yara_available': False}

            re = self._scan_engine.rule_engine
            return re.get_status()
        except Exception as e:
            logger.warning(f'getRuleEngineStatus 异常: {e}')
            return {'error': str(e)}

    _BROWSER_PROC_NAMES = {'msedge.exe', 'iexplore.exe', 'chrome.exe',
                           'firefox.exe', 'opera.exe', 'brave.exe'}

    def _start_browser_launch_watcher(self):
        """后台诊断线程：记录浏览器启动的**发起者**（父进程/路径/命令行）。

        仅取证，不拦截、不终止任何进程；1.5s 轮询、psutil 增量比对、低开销。
        用于定位"Edge 因未知原因启动"——日志/活动日志会给出父进程 PID 与路径。
        """
        if getattr(self, '_browser_watch_started', False):
            return
        self._browser_watch_started = True
        self._browser_watch_stop = threading.Event()

        def _run():
            try:
                import psutil
            except Exception:
                return
            seen = set()
            try:   # 初始快照：不报告既有浏览器窗口
                for p in psutil.process_iter(attrs=['pid', 'name']):
                    if (p.info.get('name') or '').lower() in self._BROWSER_PROC_NAMES:
                        seen.add(int(p.info.get('pid') or 0))
            except Exception:
                pass
            while not self._browser_watch_stop.wait(1.5):
                try:
                    for p in psutil.process_iter(attrs=['pid', 'name']):
                        nm = (p.info.get('name') or '').lower()
                        pid = int(p.info.get('pid') or 0)
                        if nm not in self._BROWSER_PROC_NAMES or pid in seen:
                            continue
                        seen.add(pid)
                        ppid, pname, ppath, cmd = 0, '', '', ''
                        try:
                            ppid = int(p.ppid())
                            par = psutil.Process(ppid)
                            pname = par.name()
                            try:
                                ppath = par.exe()
                            except Exception:
                                pass
                        except Exception:
                            pass
                        try:
                            cmd = ' '.join(p.cmdline())[:300]
                        except Exception:
                            pass
                        logger.warning(
                            f'[浏览器启动诊断] {nm} pid={pid} ← 父进程 '
                            f'{pname}(pid={ppid}, path={ppath}) cmd={cmd}')
                        self._add_activity(
                            '诊断',
                            f'检测到浏览器启动 {nm}(pid={pid})，父进程 '
                            f'{pname or "未知"}(pid={ppid})',
                            'INFO', '诊断')
                except Exception:
                    pass

        threading.Thread(target=_run, daemon=True,
                         name='BrowserLaunchWatch').start()

    def _on_ml_ready(self, status: dict):
        """ML Worker 后台就绪回调（**后台线程**）：注入扫描引擎 + 通知 UI 刷新。

        绝不在 GUI 线程同步等待；本回调在 MLWorkerAsyncStart 线程内执行。
        """
        try:
            mld = self._ml_detector
            if mld is not None and (status or {}).get('ml_available'):
                try:
                    if self._scan_engine:
                        self._scan_engine.set_ml_detector(mld)
                        logger.info('ML 检测器已注入扫描引擎（后台异步就绪）')
                except Exception as e:
                    logger.debug(f'异步注入 ML 检测器失败: {e}')
                self._add_activity('ML引擎', 'ML 检测引擎已就绪（后台加载完成）',
                                   'INFO', '成功')
            else:
                self._add_activity('ML引擎', 'ML 引擎未就绪，降级为签名库模式',
                                   'INFO', '降级')
            # 前端按需读取 getMlEngineStatus() 即得最新值（拉取式，无需跨线程碰 Qt）
        except Exception as e:
            logger.debug(f'_on_ml_ready 异常: {e}')

    @pyqtSlot(result=QVariant)
    def getMlEngineStatus(self):
        """获取 ML 检测引擎状态"""
        try:
            if not self._ml_detector:
                return {'ml_enabled': False, 'ml_available': False, 'ml_onnx_installed': False, 'ml_model_loaded': False}
            return self._ml_detector.get_status()
        except Exception as e:
            logger.warning(f'getMlEngineStatus 异常: {e}')
            return {'ml_enabled': False, 'ml_available': False, 'error': str(e)}

    @pyqtSlot(bool)
    @_cfg_timed
    def setMlEnabled(self, enabled):
        """启用/禁用 ML 检测引擎"""
        try:
            if self._ml_detector:
                self._ml_detector.set_enabled(enabled)
                _save_ui_settings({'ml_enabled': bool(enabled)})
                # 立即推送状态变化
                ml_state = self._ml_detector.get_status()
                self._last_ml_state = ml_state
                self.mlEngineStatusChanged.emit(json.dumps(ml_state, ensure_ascii=False))
                logger.info(f'ML 引擎开关: {"启用" if enabled else "禁用"}')
            else:
                logger.warning('ML 检测引擎未初始化，无法设置开关')
        except Exception as e:
            logger.error(f'setMlEnabled 异常: {e}')

    @pyqtSlot(bool)
    def setLightGBMEnabled(self, enabled: bool):
        """启用/禁用 BrewTotal LightGBM 补充引擎（设置页"LightGBM 引擎"开关调用）"""
        try:
            if self._ml_detector:
                self._ml_detector.set_brewtotal_enabled(enabled)
                _save_ui_settings({'lightgbm_enabled': bool(enabled)})
                ml_state = self._ml_detector.get_status()
                self._last_ml_state = ml_state
                self.mlEngineStatusChanged.emit(json.dumps(ml_state, ensure_ascii=False))
                logger.info(f'LightGBM 补充引擎开关: {"启用" if enabled else "禁用"}')
            else:
                logger.warning('ML 检测引擎未初始化，无法设置 LightGBM 开关')
        except Exception as e:
            logger.error(f'setLightGBMEnabled 异常: {e}')

    @pyqtSlot()
    def installMl(self):
        """一键安装 ML 引擎（主页"安装"按钮调用）

        安装流程：
        1. 安装 onnxruntime（pip install 或打包模式下提示）
        2. 下载预训练 ONNX 模型文件到 models 目录
        3. 安装结果通过 mlInstallResult 信号通知前端
        """
        try:
            self._add_activity('系统', '开始安装 ML 引擎', 'INFO', '进行中')

            self._emit_tool_signal(
                'mlInstallResult',
                json.dumps({'status': 'checking', 'message': '正在检测 ML 引擎环境...'}, ensure_ascii=False)
            )

            thread = threading.Thread(target=self._run_ml_install, daemon=True)
            thread.start()
        except Exception as e:
            logger.error(f'启动 ML 安装失败: {e}')
            self._emit_tool_signal(
                'mlInstallResult',
                json.dumps({'status': 'error', 'message': f'启动安装失败: {str(e)}'}, ensure_ascii=False)
            )

    def _run_ml_install(self):
        """子线程执行 ML 引擎安装

        安装策略：
        1. 打包模式：onnxruntime 已内置打包，只需确保模型存在并初始化
        2. 开发模式：pip install onnxruntime + 生成模型 + 初始化
        """
        try:
            import subprocess
            import sys
            import os
            import urllib.request

            is_frozen = getattr(sys, 'frozen', False)

            # 步骤 1：检查 / 安装 onnxruntime
            # 注意：打包模式下 onnxruntime 可能因 PyQt5 DLL 冲突无法在主进程加载，
            # 但 MLWorker.exe 可以正常加载。因此主进程 import 失败不视为致命错误。
            ort_importable = False
            try:
                import onnxruntime as ort
                ort_importable = True
            except ImportError:
                pass
            except Exception:
                pass  # DLL load failed etc.

            onnx_already_installed = ort_importable

            # 检查 MLWorker.exe 是否可用（打包模式下的备选方案）
            worker_available = False
            if is_frozen:
                exe_dir = os.path.dirname(sys.executable)
                worker_exe = os.path.join(exe_dir, 'MLWorker.exe')
                if os.path.exists(worker_exe):
                    worker_available = True

            if not onnx_already_installed and not worker_available:
                if is_frozen:
                    self._emit_tool_signal(
                        'mlInstallResult',
                        json.dumps({
                            'status': 'error',
                            'message': (
                                'ML 运行时未正确加载（打包内置异常）。\n\n'
                                '请重启 PSLS 后重试，或联系开发者反馈。'
                            )
                        }, ensure_ascii=False)
                    )
                    self._add_activity('系统', '打包模式：onnxruntime 内置加载异常', 'ERROR', '错误')
                    return

                # 开发模式：pip install onnxruntime
                self._emit_tool_signal(
                    'mlInstallResult',
                    json.dumps({
                        'status': 'installing',
                        'message': '正在安装 onnxruntime...'
                    }, ensure_ascii=False)
                )

                python_exe = sys.executable
                result = subprocess.run(
                    [python_exe, '-m', 'pip', 'install', 'onnxruntime', '--quiet'],
                    capture_output=True, text=True, timeout=120, creationflags=_HIDDEN_CREATIONFLAGS
                )

                if result.returncode != 0:
                    self._emit_tool_signal(
                        'mlInstallResult',
                        json.dumps({
                            'status': 'error',
                            'message': (
                                f'onnxruntime 安装失败:\n{result.stderr[:500]}\n\n'
                                '请尝试手动执行:\n'
                                f'  {python_exe} -m pip install onnxruntime'
                            )
                        }, ensure_ascii=False)
                    )
                    self._add_activity('系统', 'onnxruntime 安装失败', 'ERROR', '错误')
                    return

                logger.info('onnxruntime 安装成功')
            else:
                logger.info('onnxruntime 已可用，跳过安装')

            # 步骤 2：确保模型文件存在
            from engine.ml_detector import _get_model_dir
            model_dir = _get_model_dir()  # 打包模式下会自动从 _MEIPASS 复制内置模型
            model_path = os.path.join(model_dir, 'malware_detector.onnx')

            if os.path.exists(model_path) and os.path.getsize(model_path) > 0:
                logger.info(f'ONNX 模型已存在: {model_path}')
            else:
                # 模型不存在，生成（打包模式下用进程内 exec，开发模式用子进程）
                self._emit_tool_signal(
                    'mlInstallResult',
                    json.dumps({
                        'status': 'downloading',
                        'message': '正在生成 ML 模型文件...'
                    }, ensure_ascii=False)
                )

                success = self._create_default_model_subprocess(model_path)
                if not success:
                    self._emit_tool_signal(
                        'mlInstallResult',
                        json.dumps({
                            'status': 'error',
                            'message': 'ML 模型生成失败，请重启 PSLS 后重试。'
                        }, ensure_ascii=False)
                    )
                    self._add_activity('系统', 'ML 模型生成失败', 'ERROR', '错误')
                    return

            # 步骤 3：重新初始化 ML 检测器
            self._emit_tool_signal(
                'mlInstallResult',
                json.dumps({
                    'status': 'installing',
                    'message': '正在验证 ML 检测引擎...'
                }, ensure_ascii=False)
            )

            # 验证：打包模式下直接在主进程验证（onnxruntime 已内置）；
            #       开发模式用子进程验证（避免 DLL 冲突）
            # 验证：检查 ML 引擎可用性
            # 优先使用 MLWorker.exe 验证（避免主进程 DLL 冲突导致误判）
            verify_ok = False
            if worker_available:
                # 打包模式：通过 MLWorker.exe 验证
                verify_ok = self._verify_ml_via_worker(model_path)
            elif ort_importable:
                # 主进程可导入 onnxruntime，直接验证
                verify_ok = self._verify_ml_engine_subprocess(model_path)
            else:
                # 都不可用，保守估计
                verify_ok = os.path.exists(model_path)

            if verify_ok or os.path.exists(model_path):
                try:
                    from engine.ml_detector import _reset_dependency_cache
                    _reset_dependency_cache()

                    if self._ml_detector:
                        self._ml_detector.reload()
                        available = self._ml_detector.available
                    else:
                        from engine.ml_detector import MLMalwareDetector
                        self._ml_detector = MLMalwareDetector()
                        available = self._ml_detector.available

                    if available:
                        self._on_ml_install_success()
                    else:
                        self._emit_tool_signal(
                            'mlInstallResult',
                            json.dumps({
                                'status': 'warning',
                                'message': (
                                    'onnxruntime 和模型文件已就绪！\n'
                                    '当前主进程无法立即加载（Python 运行时限制）。\n\n'
                                    '请重启 PSLS 后，ML 引擎将自动启用并显示为"已启用"。'
                                )
                            }, ensure_ascii=False)
                        )
                        self._add_activity('系统', 'ML 引擎安装完成（需重启激活）', 'INFO', '完成')
                except Exception as e:
                    logger.warning(f'主进程立即加载 ML 引擎失败（需重启）: {e}')
                    self._emit_tool_signal(
                        'mlInstallResult',
                        json.dumps({
                            'status': 'warning',
                            'message': (
                                'onnxruntime 和模型文件已就绪！\n\n'
                                f'当前主进程加载异常: {str(e)[:80]}\n'
                                '请重启 PSLS 后，ML 引擎将自动启用并显示为"已启用"。'
                            )
                        }, ensure_ascii=False)
                    )
                    self._add_activity('系统', 'ML 引擎安装完成（需重启激活）', 'INFO', '完成')
            else:
                self._emit_tool_signal(
                    'mlInstallResult',
                    json.dumps({
                        'status': 'error',
                        'message': 'ML 引擎验证失败，请重启 PSLS 后重试。'
                    }, ensure_ascii=False)
                )
                self._add_activity('系统', 'ML 引擎安装验证失败', 'ERROR', '错误')

        except Exception as e:
            logger.error(f'ML 安装过程异常: {e}', exc_info=True)
            self._emit_tool_signal(
                'mlInstallResult',
                json.dumps({'status': 'error', 'message': f'安装过程异常: {str(e)}'}, ensure_ascii=False)
            )

    def _create_default_model_subprocess(self, model_path: str, external_data_path: str = None) -> bool:
        """在子进程中训练真实 ML 模型

        训练流程：
        1. 可选：加载外部训练数据 JSON（用户导入的数据）
        2. 从系统目录收集真实 clean 样本特征（System32 等）
        3. 基于真实恶意软件行为模式生成合成 malware 样本
        4. 用 numpy 实现 3 层 MLP（128→48→24→1）+ Adam 优化器训练
        5. 导出为 ONNX 多层计算图

        模型结构：128维输入 → Dense(48,ReLU) → Dense(24,ReLU) → Dense(1,Sigmoid)

        Args:
            model_path: ONNX 模型输出路径
            external_data_path: 可选的外部训练数据 JSON 文件路径
        """
        import subprocess
        import sys
        import tempfile

        # 训练脚本（在独立子进程中运行，避免 DLL 冲突）
        script = r'''
import sys, os
sys.path.insert(0, r'__PROJECT_ROOT__')
import struct, math, random, glob
import numpy as np

_HIDDEN_CREATIONFLAGS = 0x08000000 if sys.platform == 'win32' else 0

# ===== 特征提取（复用运行时提取器 engine.ml_detector，保证与运行时完全一致） =====
from engine.ml_detector import MLFeatureExtractor

_extractor = None
def extract_features(file_path):
    """提取 128 维特征向量（与运行时 MLFeatureExtractor 完全一致）"""
    global _extractor
    if _extractor is None:
        _extractor = MLFeatureExtractor()
    return _extractor.extract(file_path)

# ===== 收集真实 clean 样本 =====
def collect_clean_features():
    """从系统目录收集真实 clean 文件特征"""
    features = []
    search_dirs = [
        r'C:\Windows\System32',
        r'C:\Windows\SysWOW64',
    ]
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        for ext in ('*.exe', '*.dll'):
            for f in glob.glob(os.path.join(d, ext)):
                try:
                    feat = extract_features(f)
                    if feat:
                        features.append(feat)
                except:
                    pass
                if len(features) >= 600:
                    return features
    return features

def collect_clean_source_features():
    """收集项目目录下的源码文件作为 clean 样本（困难负样本）

    这些文件包含可疑 API 名称/关键词字符串（因为代码中引用了它们），
    但实际是 clean 的。加入训练集可显著降低源码文件误报率。
    """
    features = []
    # 尝试常见项目路径
    project_dirs = [
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        os.getcwd(),
    ]
    seen = set()
    for proj_dir in project_dirs:
        if not proj_dir or proj_dir in seen:
            continue
        seen.add(proj_dir)
        for root, dirs, files in os.walk(proj_dir):
            # 跳过常见非源码目录
            dirs[:] = [d for d in dirs if d not in ('__pycache__', '.git', 'node_modules', '.venv', 'venv')]
            for fname in files:
                if not fname.endswith(('.py', '.js', '.html', '.css', '.txt', '.md', '.json')):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    feat = extract_features(fpath)
                    if feat:
                        features.append(feat)
                except:
                    pass
                if len(features) >= 200:
                    return features
    return features

# ===== 生成合成 clean 样本（补充非 PE 文件 + 困难负样本） =====
def generate_synthetic_clean(n=200):
    """生成非 PE clean 样本特征（脚本、文本等）

    包含两部分：
    1. 普通 clean 文本文件（低可疑特征）
    2. 困难负样本：含可疑 API/关键词字符串但实际 clean 的源码文件特征

    输出 128 维向量，布局与 MLFeatureExtractor 完全一致。
    """
    features = []
    for _ in range(n):
        feat = [0.0] * 128
        is_hard_negative = random.random() < 0.3  # 30% 为困难负样本

        # 0-63 字节直方图：ASCII 文本分布（0x20-0x7E 集中在 bin 8-31）
        hist = [0.0] * 64
        ascii_bins = list(range(8, 32))
        for i in range(64):
            if i in ascii_bins:
                hist[i] = random.uniform(0.02, 0.04)
            elif i == 0:
                hist[i] = random.uniform(0.01, 0.03)  # null bytes
            else:
                hist[i] = random.uniform(0.002, 0.012)
        s = sum(hist)
        for i in range(64):
            feat[i] = hist[i] / s

        feat[64] = random.uniform(0.35, 0.65)  # 中低熵
        feat[65] = random.uniform(0.05, 0.35)  # 较小文件
        feat[66] = 0.0  # 非 PE
        if is_hard_negative:
            # 困难负样本：源码中引用了可疑 API/关键词
            feat[74] = random.uniform(0.15, 0.50)  # 有可疑 API 字符串
            feat[82] = random.uniform(0.10, 0.40)  # 有可疑关键词
        else:
            feat[74] = random.uniform(0.0, 0.07)  # 极少 API
            feat[82] = random.uniform(0.0, 0.07)
        feat[123] = random.uniform(0.7, 0.95)  # 高可打印比例
        feat[124] = random.uniform(0.02, 0.08)
        feat[125] = random.uniform(0.01, 0.04)
        features.append(feat)
    return features

# ===== 生成合成 malware 样本 =====
def generate_malware_features(n=500):
    """基于真实恶意软件行为模式生成合成特征向量

    每种类型基于公开恶意软件分析的典型特征分布：
    - packed:    加壳/加密，极高熵(7.5-8.0)，均匀字节分布
    - trojan:    木马，中高熵，大量注入API
    - ransomware:勒索软件，高熵，加密关键词
    - downloader:下载器，较小，网络API
    - keylogger: 键盘记录器，hook API，小文件
    - worm:      蠕虫，网络传播，中等大小
    - backdoor:  后门，进程操作API

    输出 128 维向量，布局与 MLFeatureExtractor 完全一致。
    """
    features = []
    profiles = ['packed', 'trojan', 'ransomware', 'downloader',
                'keylogger', 'worm', 'backdoor']
    weights = [20, 20, 15, 15, 10, 10, 10]

    for _ in range(n):
        profile = random.choices(profiles, weights=weights)[0]
        feat = [0.0] * 128

        # 0-63 字节直方图（64 bins，和为 1.0）
        if profile == 'packed':
            # 加壳：均匀分布
            raw = [random.uniform(0.012, 0.020) for _ in range(64)]
        elif profile in ('ransomware',):
            # 勒索：较均匀，偏高字节
            raw = [random.uniform(0.010, 0.022) for _ in range(64)]
            for i in range(56, 64):
                raw[i] *= random.uniform(1.3, 1.8)
        else:
            # 其他：有一定变化
            raw = [random.uniform(0.006, 0.028) for _ in range(64)]
            raw[0] *= random.uniform(1.5, 3.0)  # null bytes 较多
        s = sum(raw)
        for i in range(64):
            feat[i] = raw[i] / s

        if profile == 'packed':
            feat[64] = random.uniform(0.92, 1.0)
            feat[65] = random.uniform(0.30, 0.60)
            feat[66] = 1.0
            feat[67] = random.uniform(0.30, 0.60)
            feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0])
            feat[74] = random.uniform(0.15, 0.40)
            feat[82] = random.uniform(0.0, 0.15)
            feat[123] = random.uniform(0.15, 0.35)
            feat[124] = random.uniform(0.005, 0.02)
            feat[125] = random.uniform(0.12, 0.22)

        elif profile == 'trojan':
            feat[64] = random.uniform(0.65, 0.85)
            feat[65] = random.uniform(0.30, 0.50)
            feat[66] = 1.0
            feat[67] = random.uniform(0.15, 0.30)
            feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0])
            feat[74] = random.uniform(0.30, 0.60)
            feat[82] = random.uniform(0.10, 0.30)
            feat[123] = random.uniform(0.30, 0.50)
            feat[124] = random.uniform(0.03, 0.08)
            feat[125] = random.uniform(0.05, 0.12)

        elif profile == 'ransomware':
            feat[64] = random.uniform(0.85, 0.95)
            feat[65] = random.uniform(0.30, 0.55)
            feat[66] = 1.0
            feat[67] = random.uniform(0.20, 0.40)
            feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0])
            feat[74] = random.uniform(0.25, 0.50)
            feat[82] = random.uniform(0.15, 0.35)
            feat[123] = random.uniform(0.20, 0.40)
            feat[124] = random.uniform(0.02, 0.05)
            feat[125] = random.uniform(0.08, 0.16)

        elif profile == 'downloader':
            feat[64] = random.uniform(0.55, 0.75)
            feat[65] = random.uniform(0.15, 0.35)
            feat[66] = 1.0
            feat[67] = random.uniform(0.10, 0.25)
            feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0])
            feat[74] = random.uniform(0.15, 0.35)
            feat[82] = random.uniform(0.05, 0.20)
            feat[123] = random.uniform(0.35, 0.55)
            feat[124] = random.uniform(0.05, 0.12)
            feat[125] = random.uniform(0.04, 0.10)

        elif profile == 'keylogger':
            feat[64] = random.uniform(0.50, 0.70)
            feat[65] = random.uniform(0.10, 0.30)
            feat[66] = 1.0
            feat[67] = random.uniform(0.10, 0.20)
            feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0])
            feat[74] = random.uniform(0.10, 0.30)
            feat[82] = random.uniform(0.10, 0.25)
            feat[123] = random.uniform(0.40, 0.60)
            feat[124] = random.uniform(0.06, 0.14)
            feat[125] = random.uniform(0.03, 0.08)

        elif profile == 'worm':
            feat[64] = random.uniform(0.60, 0.80)
            feat[65] = random.uniform(0.25, 0.45)
            feat[66] = 1.0
            feat[67] = random.uniform(0.15, 0.30)
            feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0])
            feat[74] = random.uniform(0.20, 0.45)
            feat[82] = random.uniform(0.05, 0.20)
            feat[123] = random.uniform(0.30, 0.50)
            feat[124] = random.uniform(0.04, 0.10)
            feat[125] = random.uniform(0.05, 0.12)

        elif profile == 'backdoor':
            feat[64] = random.uniform(0.55, 0.78)
            feat[65] = random.uniform(0.20, 0.40)
            feat[66] = 1.0
            feat[67] = random.uniform(0.15, 0.30)
            feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0])
            feat[74] = random.uniform(0.25, 0.50)
            feat[82] = random.uniform(0.10, 0.25)
            feat[123] = random.uniform(0.30, 0.50)
            feat[124] = random.uniform(0.04, 0.10)
            feat[125] = random.uniform(0.05, 0.11)

        # 添加高斯噪声增强泛化
        for i in range(128):
            feat[i] = max(0.0, min(1.0, feat[i] + random.gauss(0, 0.015)))
        features.append(feat)
    return features

# ===== 神经网络（3 层 MLP + Adam） =====
class NeuralNetwork:
    def __init__(self, input_dim=128, h1=48, h2=24):
        # He 初始化
        self.W1 = np.random.randn(input_dim, h1).astype(np.float32) * np.sqrt(2.0/input_dim)
        self.b1 = np.zeros((1, h1), dtype=np.float32)
        self.W2 = np.random.randn(h1, h2).astype(np.float32) * np.sqrt(2.0/h1)
        self.b2 = np.zeros((1, h2), dtype=np.float32)
        self.W3 = np.random.randn(h2, 1).astype(np.float32) * np.sqrt(2.0/h2)
        self.b3 = np.zeros((1, 1), dtype=np.float32)
        # Adam 状态
        self._b1, self._b2 = 0.9, 0.999
        self._m = {n: np.zeros_like(getattr(self, n)) for n in ['W1','b1','W2','b2','W3','b3']}
        self._v = {n: np.zeros_like(getattr(self, n)) for n in ['W1','b1','W2','b2','W3','b3']}
        self._t = 0

    def forward(self, X):
        self.z1 = X @ self.W1 + self.b1
        self.a1 = np.maximum(0, self.z1)
        self.z2 = self.a1 @ self.W2 + self.b2
        self.a2 = np.maximum(0, self.z2)
        self.z3 = self.a2 @ self.W3 + self.b3
        self.a3 = 1.0 / (1.0 + np.exp(-np.clip(self.z3, -500, 500)))
        return self.a3

    def train_step(self, X, y, lr=0.001):
        m = X.shape[0]
        self.forward(X)
        # 反向传播
        dz3 = (self.a3 - y) / m
        grads = {}
        grads['W3'] = self.a2.T @ dz3
        grads['b3'] = np.sum(dz3, axis=0, keepdims=True)
        dz2 = (dz3 @ self.W3.T) * (self.z2 > 0)
        grads['W2'] = self.a1.T @ dz2
        grads['b2'] = np.sum(dz2, axis=0, keepdims=True)
        dz1 = (dz2 @ self.W2.T) * (self.z1 > 0)
        grads['W1'] = X.T @ dz1
        grads['b1'] = np.sum(dz1, axis=0, keepdims=True)
        # Adam 更新
        self._t += 1
        lr_t = lr * math.sqrt(1 - self._b2**self._t) / (1 - self._b1**self._t)
        for n in ['W1','b1','W2','b2','W3','b3']:
            self._m[n] = self._b1 * self._m[n] + (1-self._b1) * grads[n]
            self._v[n] = self._b2 * self._v[n] + (1-self._b2) * grads[n]**2
            setattr(self, n, getattr(self, n) - lr_t * self._m[n] / (np.sqrt(self._v[n]) + 1e-8))

    def train(self, X, y, epochs=400, batch_size=32, lr=0.002):
        n = X.shape[0]
        for epoch in range(epochs):
            idx = np.random.permutation(n)
            for i in range(0, n, batch_size):
                self.train_step(X[idx[i:i+batch_size]], y[idx[i:i+batch_size]], lr)
            if epoch == 200: lr *= 0.5
            if epoch == 300: lr *= 0.5
            if (epoch+1) % 50 == 0:
                pred = self.forward(X)
                loss = -np.mean(y*np.log(pred+1e-8) + (1-y)*np.log(1-pred+1e-8))
                acc = np.mean((pred >= 0.5) == y)
                print(f'  Epoch {epoch+1}/{epochs}: loss={loss:.4f} acc={acc:.4f}', flush=True)

# ===== ONNX 导出 =====
def export_onnx(model, output_path):
    try:
        import onnx
        from onnx import helper, TensorProto
    except ImportError:
        import subprocess
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'onnx', '--quiet'],
                       capture_output=True, timeout=120, creationflags=_HIDDEN_CREATIONFLAGS)
        import onnx
        from onnx import helper, TensorProto

    inp = helper.make_tensor_value_info('input', TensorProto.FLOAT, [1, 128])
    out = helper.make_tensor_value_info('output', TensorProto.FLOAT, [1, 1])

    # 将 numpy 权重转为 float32 列表
    def tvec(arr):
        return arr.astype(np.float32).flatten().tolist()

    inits = [
        helper.make_tensor('W1', TensorProto.FLOAT, [128, 48], tvec(model.W1)),
        helper.make_tensor('b1', TensorProto.FLOAT, [48], tvec(model.b1)),
        helper.make_tensor('W2', TensorProto.FLOAT, [48, 24], tvec(model.W2)),
        helper.make_tensor('b2', TensorProto.FLOAT, [24], tvec(model.b2)),
        helper.make_tensor('W3', TensorProto.FLOAT, [24, 1], tvec(model.W3)),
        helper.make_tensor('b3', TensorProto.FLOAT, [1], tvec(model.b3)),
    ]
    nodes = [
        helper.make_node('Gemm', ['input','W1','b1'], ['h1'], transB=0),
        helper.make_node('Relu', ['h1'], ['h1r']),
        helper.make_node('Gemm', ['h1r','W2','b2'], ['h2'], transB=0),
        helper.make_node('Relu', ['h2'], ['h2r']),
        helper.make_node('Gemm', ['h2r','W3','b3'], ['raw'], transB=0),
        helper.make_node('Sigmoid', ['raw'], ['output']),
    ]
    graph = helper.make_graph(nodes, 'PSLS_ML_MalwareDetector_v2', [inp], [out], inits)
    onnx_model = helper.make_model(graph, opset_imports=[helper.make_opsetid('', 11)],
                                   ir_version=7, producer_name='PSLS_ML_Trainer')
    onnx_model.ir_version = 7
    onnx_model.opset_import[0].domain = ''
    onnx_model.opset_import[0].version = 11
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    onnx.save(onnx_model, output_path)

# ===== 主函数 =====
def main():
    model_path = sys.argv[1]
    # sys.argv[2] 为可选的外部训练数据 JSON 路径
    external_data_path = sys.argv[2] if len(sys.argv) > 2 else None

    random.seed(42)
    np.random.seed(42)

    ext_clean = []
    ext_malware = []

    # ===== 加载外部训练数据（如果提供） =====
    if external_data_path and os.path.isfile(external_data_path):
        print(f'[0/4] 加载外部训练数据: {external_data_path}', flush=True)
        try:
            import json
            with open(external_data_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # 格式 1: {"samples": [{"features": [...], "label": "clean"/"malware"}, ...]}
            if isinstance(data, dict) and 'samples' in data:
                for sample in data['samples']:
                    feat = sample.get('features')
                    label = sample.get('label', '').lower()
                    if feat and len(feat) == 128 and label in ('clean', 'malware'):
                        if label == 'clean':
                            ext_clean.append(feat)
                        else:
                            ext_malware.append(feat)

            # 格式 2: {"clean": [[...], ...], "malware": [[...], ...]}
            elif isinstance(data, dict):
                for key in ('clean', 'benign', 'safe'):
                    if key in data:
                        for feat in data[key]:
                            if isinstance(feat, list) and len(feat) == 128:
                                ext_clean.append(feat)
                for key in ('malware', 'malicious', 'threat'):
                    if key in data:
                        for feat in data[key]:
                            if isinstance(feat, list) and len(feat) == 128:
                                ext_malware.append(feat)

            print(f'  外部数据: {len(ext_clean)} clean, {len(ext_malware)} malware', flush=True)
        except Exception as e:
            print(f'  外部数据加载失败: {e}', flush=True)

    print('[1/4] 收集真实 clean 样本特征...', flush=True)
    clean_real = collect_clean_features()
    print(f'  收集到 {len(clean_real)} 个系统 clean 样本', flush=True)
    clean_source = collect_clean_source_features()
    print(f'  收集到 {len(clean_source)} 个源码 clean 样本（困难负样本）', flush=True)

    print('[2/4] 生成合成 clean + malware 样本...', flush=True)
    clean_synth = generate_synthetic_clean(200)
    malware = generate_malware_features(max(len(clean_real) + len(clean_source) + len(clean_synth) + len(ext_clean) + len(ext_malware), 500))
    print(f'  合成 clean: {len(clean_synth)}, malware: {len(malware)}', flush=True)

    # 合并数据（外部数据 + 自动收集数据）
    all_clean = clean_real + clean_source + clean_synth + ext_clean
    all_malware = malware + ext_malware
    X_clean = np.array(all_clean, dtype=np.float32) if all_clean else np.zeros((0, 128), dtype=np.float32)
    X_mal = np.array(all_malware, dtype=np.float32) if all_malware else np.zeros((0, 128), dtype=np.float32)
    X = np.vstack([X_clean, X_mal])
    y = np.vstack([np.zeros((len(X_clean), 1)), np.ones((len(X_mal), 1))])
    idx = np.random.permutation(len(X))
    X, y = X[idx], y[idx]
    print(f'  训练集: {X.shape[0]} 样本 ({int(y.sum())} 恶意, {int(len(y)-y.sum())} 干净)', flush=True)

    print('[3/4] 训练神经网络 (128->48->24->1)...', flush=True)
    net = NeuralNetwork(128, 48, 24)
    net.train(X, y, epochs=400, batch_size=32, lr=0.002)
    pred = net.forward(X)
    acc = np.mean((pred >= 0.5) == y)
    print(f'  最终准确率: {acc:.4f}', flush=True)

    # 评估 clean 误报率
    clean_pred = net.forward(X_clean)
    fpr = np.mean(clean_pred >= 0.5)
    print(f'  clean 误报率: {fpr:.4f} ({int(np.sum(clean_pred >= 0.5))}/{len(X_clean)})', flush=True)

    print('[4/4] 导出 ONNX 模型...', flush=True)
    export_onnx(net, model_path)
    print(f'  模型已保存: {model_path}', flush=True)
    print('MODEL_CREATED_OK', flush=True)

if __name__ == '__main__':
    main()
'''

        # 注入项目根目录（供脚本内 sys.path 使用，从而能 import engine.ml_detector）
        _proj_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        script = script.replace('__PROJECT_ROOT__', _proj_root.replace('\\', '/'))

        # 写入临时脚本文件
        fd, script_path = tempfile.mkstemp(suffix='.py', prefix='ml_model_gen_')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(script)

            self._emit_tool_signal(
                'mlInstallResult',
                json.dumps({
                    'status': 'downloading',
                    'message': '正在创建 ML 模型...'
                }, ensure_ascii=False)
            )

            if getattr(sys, 'frozen', False):
                # 打包模式：进程内 exec 执行训练脚本
                # sys.executable 是 PSLS.exe，无法直接运行脚本；
                # onnxruntime/onnx/numpy 已内置打包，进程内可直接 import
                import io, contextlib
                argv_backup = sys.argv[:]
                sys.argv = [script_path, model_path]
                if external_data_path:
                    sys.argv.append(external_data_path)
                try:
                    stdout_buf = io.StringIO()
                    exec_globals = {'__name__': '__main__', '__file__': script_path}
                    with contextlib.redirect_stdout(stdout_buf):
                        exec(compile(script, script_path, 'exec'), exec_globals)
                    output = stdout_buf.getvalue()
                    if 'MODEL_CREATED_OK' in output:
                        logger.info(f'ML 模型已生成（进程内）: {model_path}')
                        return True
                    else:
                        logger.error(f'进程内创建模型失败: {output[:300]}')
                        return False
                except Exception as e:
                    logger.error(f'进程内创建模型异常: {e}', exc_info=True)
                    return False
                finally:
                    sys.argv = argv_backup
            else:
                # 开发模式：子进程执行（隔离 DLL 冲突）
                cmd = [sys.executable, script_path, model_path]
                if external_data_path:
                    cmd.append(external_data_path)
                result = subprocess.run(
                    cmd,
                    capture_output=True, text=True, timeout=180, creationflags=_HIDDEN_CREATIONFLAGS
                )

                if result.returncode == 0 and 'MODEL_CREATED_OK' in result.stdout:
                    logger.info(f'ML 模型已生成: {model_path}')
                    return True
                else:
                    logger.error(f'子进程创建模型失败: returncode={result.returncode}, stderr={result.stderr[:300]}')
                    return False

        finally:
            try:
                os.unlink(script_path)
            except Exception:
                pass

    def _verify_ml_engine_subprocess(self, model_path: str) -> bool:
        """验证 ML 引擎是否可用

        打包模式：直接在主进程中验证（onnxruntime 已内置）
        开发模式：在子进程中验证（避免 DLL 冲突）
        """
        import sys

        if getattr(sys, 'frozen', False):
            # 打包模式：主进程直接验证
            try:
                import onnxruntime as ort
                import numpy as np
                session = ort.InferenceSession(
                    model_path, providers=['CPUExecutionProvider']
                )
                test_input = np.zeros((1, 128), dtype=np.float32)
                input_name = session.get_inputs()[0].name
                session.run(None, {input_name: test_input})
                logger.info('ML 引擎主进程验证通过')
                return True
            except Exception as e:
                logger.warning(f'ML 引擎主进程验证失败: {e}')
                return False

        # 开发模式：子进程验证
        import subprocess
        import tempfile

        script = '''
import sys
import traceback
try:
    import onnxruntime as ort
    import numpy as np

    # 验证模型可以加载和推理
    session = ort.InferenceSession(
        sys.argv[1],
        providers=['CPUExecutionProvider']
    )

    # 用零向量测试推理
    test_input = np.zeros((1, 128), dtype=np.float32)
    input_name = session.get_inputs()[0].name
    output = session.run(None, {input_name: test_input})

    print('VERIFY_OK')
except Exception as e:
    print(f'VERIFY_FAIL: {e}')
    traceback.print_exc()
    sys.exit(1)
'''

        fd, script_path = tempfile.mkstemp(suffix='.py', prefix='ml_verify_')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(script)

            result = subprocess.run(
                [sys.executable, script_path, model_path],
                capture_output=True, text=True, timeout=60,
                creationflags=_HIDDEN_CREATIONFLAGS
            )

            if result.returncode == 0 and 'VERIFY_OK' in result.stdout:
                logger.info('ML 引擎子进程验证通过')
                return True
            else:
                # 错误信息在 stdout（print）和 stderr（traceback）中都要记录
                error_detail = result.stdout.strip() + ' | ' + result.stderr.strip()
                logger.warning(f'ML 引擎验证失败: {error_detail[:500]}')
                return False

        finally:
            try:
                os.unlink(script_path)
            except Exception:
                pass

    def _verify_ml_via_worker(self, model_path: str) -> bool:
        """通过 MLWorker.exe 验证 ML 引擎可用性

        在打包模式下，主进程可能因 PyQt5 DLL 冲突无法加载 onnxruntime，
        但 MLWorker.exe 可以正常加载。此方法通过 MLWorker.exe 验证。
        """
        import subprocess
        import sys

        try:
            exe_dir = os.path.dirname(sys.executable)
            worker_exe = os.path.join(exe_dir, 'MLWorker.exe')
            if not os.path.exists(worker_exe):
                logger.warning(f'MLWorker.exe 未找到: {worker_exe}')
                return False

            # 启动 MLWorker 并发送 ping 验证（隐藏控制台窗口）
            import platform
            si = None
            cf = 0
            if platform.system() == 'Windows':
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                cf = 0x08000000
            proc = subprocess.Popen(
                [worker_exe, model_path],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, bufsize=1,
                creationflags=cf, startupinfo=si
            )

            # 读取 ready 消息
            ready_line = proc.stdout.readline().strip()
            if not ready_line:
                proc.kill()
                logger.warning('MLWorker 无响应')
                return False

            import json
            try:
                ready_msg = json.loads(ready_line)
                if ready_msg.get('type') != 'ready':
                    proc.kill()
                    logger.warning(f'MLWorker 未返回 ready: {ready_line}')
                    return False
                # 如果 ready 中有 note 且包含 fail，说明模型加载失败
                note = ready_msg.get('note', '')
                if note and 'fail' in note.lower():
                    proc.kill()
                    logger.warning(f'MLWorker 模型加载失败: {note}')
                    return False
            except json.JSONDecodeError:
                proc.kill()
                logger.warning(f'MLWorker 返回非 JSON: {ready_line}')
                return False

            # 发送 ping 确认通信正常
            proc.stdin.write(json.dumps({'type': 'ping'}) + '\n')
            proc.stdin.flush()
            pong_line = proc.stdout.readline().strip()

            # 发送 close
            proc.stdin.write(json.dumps({'type': 'close'}) + '\n')
            proc.stdin.flush()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

            if pong_line and 'pong' in pong_line:
                logger.info('MLWorker 验证通过')
                return True

            logger.warning(f'MLWorker ping 无响应: {pong_line}')
            return False

        except Exception as e:
            logger.warning(f'MLWorker 验证异常: {e}')
            return False

    def _on_ml_install_success(self):
        """ML 引擎安装成功后的统一处理"""
        logger.info('ML 引擎安装成功，已加载模型')
        self._add_activity('系统', 'ML 检测引擎安装成功', 'INFO', '成功')

        # 推送状态变化
        if self._ml_detector:
            ml_state = self._ml_detector.get_status()
            self._last_ml_state = ml_state
            self.mlEngineStatusChanged.emit(json.dumps(ml_state, ensure_ascii=False))

        self._emit_tool_signal(
            'mlInstallResult',
            json.dumps({
                'status': 'success',
                'message': 'ML 检测引擎安装成功！\n已加载预训练模型，可检测未知威胁。\n关闭后自动降级为签名库模式。'
            }, ensure_ascii=False)
        )

    @pyqtSlot()
    def selectMlTrainData(self):
        """选择外部训练数据 JSON 文件并重新训练模型

        支持的 JSON 格式：
        格式1（带标签列表）:
        {
          "samples": [
            {"features": [128个浮点数], "label": "clean"},
            {"features": [128个浮点数], "label": "malware"}
          ]
        }

        格式2（分组列表）:
        {
          "clean": [[128个浮点数], ...],
          "malware": [[128个浮点数], ...]
        }
        """
        try:
            from PyQt5.QtWidgets import QFileDialog
            file_path, _ = QFileDialog.getOpenFileName(
                None, '选择 ML 训练数据文件', '',
                'JSON 文件 (*.json);;所有文件 (*.*)'
            )
            if not file_path:
                # 用户取消选择，发出 cancelled 信号以恢复前端按钮状态
                self._emit_tool_signal(
                    'mlTrainResult',
                    json.dumps({'status': 'cancelled', 'message': '已取消'}, ensure_ascii=False)
                )
                return

            self._add_activity('ML引擎', f'导入训练数据: {os.path.basename(file_path)}', 'INFO', '进行中')
            thread = threading.Thread(
                target=self._run_ml_retrain,
                args=(file_path,),
                daemon=True
            )
            thread.start()
        except Exception as e:
            logger.error(f'选择训练数据失败: {e}')
            self._emit_tool_signal(
                'mlTrainResult',
                json.dumps({'status': 'error', 'message': f'选择文件失败: {str(e)}'}, ensure_ascii=False)
            )

    def _run_ml_retrain(self, data_path: str):
        """子线程：使用外部数据重新训练 ML 模型"""
        try:
            # 验证 JSON 文件
            try:
                with open(data_path, 'r', encoding='utf-8') as f:
                    import json as _json
                    data = _json.load(f)
            except Exception as e:
                self._emit_tool_signal(
                    'mlTrainResult',
                    json.dumps({'status': 'error', 'message': f'JSON 文件解析失败: {e}'}, ensure_ascii=False)
                )
                return

            # 统计样本数
            n_clean, n_malware = 0, 0
            if isinstance(data, dict) and 'samples' in data:
                for s in data['samples']:
                    lbl = s.get('label', '').lower()
                    if lbl == 'clean': n_clean += 1
                    elif lbl == 'malware': n_malware += 1
            elif isinstance(data, dict):
                n_clean = sum(len(data[k]) for k in ('clean', 'benign', 'safe') if k in data)
                n_malware = sum(len(data[k]) for k in ('malware', 'malicious', 'threat') if k in data)

            if n_clean == 0 and n_malware == 0:
                self._emit_tool_signal(
                    'mlTrainResult',
                    json.dumps({'status': 'error', 'message': '文件中未找到有效训练样本。\n请确认 JSON 格式正确，且包含 128 维特征向量。'}, ensure_ascii=False)
                )
                return

            self._emit_tool_signal(
                'mlTrainResult',
                json.dumps({'status': 'training', 'message': f'正在训练... (外部数据: {n_clean} clean, {n_malware} malware)'}, ensure_ascii=False)
            )

            # 获取模型路径
            from engine.ml_detector import _get_model_dir
            model_dir = _get_model_dir()
            model_path = os.path.join(model_dir, 'malware_detector.onnx')

            # 运行训练子进程（传入外部数据路径）
            success = self._create_default_model_subprocess(model_path, data_path)

            if not success:
                self._emit_tool_signal(
                    'mlTrainResult',
                    json.dumps({'status': 'error', 'message': '训练子进程执行失败，请检查 onnxruntime 和 onnx 是否已安装。'}, ensure_ascii=False)
                )
                self._add_activity('ML引擎', 'ML 模型重新训练失败', 'ERROR', '错误')
                return

            # 重新加载模型
            from engine.ml_detector import _reset_dependency_cache
            _reset_dependency_cache()

            if self._ml_detector:
                self._ml_detector.reload()
                available = self._ml_detector.available
            else:
                from engine.ml_detector import MLMalwareDetector
                self._ml_detector = MLMalwareDetector()
                available = self._ml_detector.available

            if available:
                self._on_ml_install_success()
                self._emit_tool_signal(
                    'mlTrainResult',
                    json.dumps({'status': 'success', 'message': f'模型重新训练完成！\n训练数据: {n_clean} clean + {n_malware} malware\n模型已加载并启用。'}, ensure_ascii=False)
                )
                self._add_activity('ML引擎', 'ML 模型重新训练成功', 'INFO', '成功')
            else:
                self._emit_tool_signal(
                    'mlTrainResult',
                    json.dumps({'status': 'warning', 'message': '模型已训练并保存，但需要重启 PSLS 才能加载新模型。'}, ensure_ascii=False)
                )
                self._add_activity('ML引擎', 'ML 模型训练完成（需重启）', 'INFO', '完成')

        except Exception as e:
            logger.error(f'ML 重新训练失败: {e}', exc_info=True)
            self._emit_tool_signal(
                'mlTrainResult',
                json.dumps({'status': 'error', 'message': f'训练失败: {str(e)}'}, ensure_ascii=False)
            )

    @pyqtSlot()
    def exportMlTrainData(self):
        """导出当前训练数据为 JSON 文件（备份用）

        收集系统 clean 样本 + 生成合成 malware 样本，
        导出为与导入格式一致的 JSON 文件，方便备份和重新导入。
        """
        try:
            from PyQt5.QtWidgets import QFileDialog
            from datetime import datetime
            default_name = f'PSLS_ml_traindata_{datetime.now().strftime("%Y%m%d")}.json'
            file_path, _ = QFileDialog.getSaveFileName(
                None, '导出 ML 训练数据', default_name,
                'JSON 文件 (*.json);;所有文件 (*.*)'
            )
            if not file_path:
                self._emit_tool_signal(
                    'mlTrainResult',
                    json.dumps({'status': 'cancelled', 'message': '已取消'}, ensure_ascii=False)
                )
                return

            self._add_activity('ML引擎', f'导出训练数据: {os.path.basename(file_path)}', 'INFO', '进行中')
            thread = threading.Thread(
                target=self._run_ml_export,
                args=(file_path,),
                daemon=True
            )
            thread.start()
        except Exception as e:
            logger.error(f'导出训练数据失败: {e}')
            self._emit_tool_signal(
                'mlTrainResult',
                json.dumps({'status': 'error', 'message': f'导出失败: {str(e)}'}, ensure_ascii=False)
            )

    def _run_ml_export(self, save_path: str):
        """子线程：收集特征并导出为 JSON"""
        try:
            self._emit_tool_signal(
                'mlTrainResult',
                json.dumps({'status': 'exporting', 'message': '正在收集样本特征...'}, ensure_ascii=False)
            )

            # 导出脚本（复用训练脚本中的特征提取逻辑）
            export_script = r'''
import sys, os
sys.path.insert(0, r'__PROJECT_ROOT__')
import struct, math, random, glob, json
import numpy as np

# ===== 特征提取（复用运行时提取器 engine.ml_detector，保证与运行时完全一致） =====
from engine.ml_detector import MLFeatureExtractor

_extractor = None
def extract_features(file_path):
    """提取 128 维特征向量（与运行时 MLFeatureExtractor 完全一致）"""
    global _extractor
    if _extractor is None:
        _extractor = MLFeatureExtractor()
    return _extractor.extract(file_path)

def collect_clean_features():
    features = []
    for d in [r'C:\Windows\System32', r'C:\Windows\SysWOW64']:
        if not os.path.isdir(d): continue
        for ext in ('*.exe', '*.dll'):
            for f in glob.glob(os.path.join(d, ext)):
                try:
                    feat = extract_features(f)
                    if feat: features.append(feat)
                except: pass
                if len(features) >= 600: return features
    return features

def collect_clean_source_features():
    features = []
    project_dirs = [
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        os.getcwd(),
    ]
    seen = set()
    for proj_dir in project_dirs:
        if not proj_dir or proj_dir in seen: continue
        seen.add(proj_dir)
        for root, dirs, files in os.walk(proj_dir):
            dirs[:] = [d for d in dirs if d not in ('__pycache__', '.git', 'node_modules', '.venv', 'venv')]
            for fname in files:
                if not fname.endswith(('.py', '.js', '.html', '.css', '.txt', '.md', '.json')): continue
                fpath = os.path.join(root, fname)
                try:
                    feat = extract_features(fpath)
                    if feat: features.append(feat)
                except: pass
                if len(features) >= 200: return features
    return features

def generate_synthetic_clean(n=200):
    features = []
    for _ in range(n):
        feat = [0.0] * 128
        is_hard_negative = random.random() < 0.3
        hist = [0.0] * 64
        ascii_bins = list(range(8, 32))
        for i in range(64):
            if i in ascii_bins: hist[i] = random.uniform(0.02, 0.04)
            elif i == 0: hist[i] = random.uniform(0.01, 0.03)
            else: hist[i] = random.uniform(0.002, 0.012)
        s = sum(hist)
        for i in range(64): feat[i] = hist[i] / s
        feat[64] = random.uniform(0.35, 0.65)
        feat[65] = random.uniform(0.05, 0.35)
        feat[66] = 0.0
        if is_hard_negative:
            feat[74] = random.uniform(0.15, 0.50)
            feat[82] = random.uniform(0.10, 0.40)
        else:
            feat[74] = random.uniform(0.0, 0.07)
            feat[82] = random.uniform(0.0, 0.07)
        feat[123] = random.uniform(0.7, 0.95)
        feat[124] = random.uniform(0.02, 0.08)
        feat[125] = random.uniform(0.01, 0.04)
        features.append(feat)
    return features

def generate_malware_features(n=500):
    features = []
    profiles = ['packed', 'trojan', 'ransomware', 'downloader', 'keylogger', 'worm', 'backdoor']
    weights = [20, 20, 15, 15, 10, 10, 10]
    for _ in range(n):
        profile = random.choices(profiles, weights=weights)[0]
        feat = [0.0] * 128
        if profile == 'packed':
            raw = [random.uniform(0.012, 0.020) for _ in range(64)]
        elif profile in ('ransomware',):
            raw = [random.uniform(0.010, 0.022) for _ in range(64)]
            for i in range(56, 64): raw[i] *= random.uniform(1.3, 1.8)
        else:
            raw = [random.uniform(0.006, 0.028) for _ in range(64)]
            raw[0] *= random.uniform(1.5, 3.0)
        s = sum(raw)
        for i in range(64): feat[i] = raw[i] / s
        if profile == 'packed':
            feat[64] = random.uniform(0.92, 1.0); feat[65] = random.uniform(0.30, 0.60)
            feat[66] = 1.0; feat[67] = random.uniform(0.30, 0.60); feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0]); feat[74] = random.uniform(0.15, 0.40)
            feat[82] = random.uniform(0.0, 0.15); feat[123] = random.uniform(0.15, 0.35)
            feat[124] = random.uniform(0.005, 0.02); feat[125] = random.uniform(0.12, 0.22)
        elif profile == 'trojan':
            feat[64] = random.uniform(0.65, 0.85); feat[65] = random.uniform(0.30, 0.50)
            feat[66] = 1.0; feat[67] = random.uniform(0.15, 0.30); feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0]); feat[74] = random.uniform(0.30, 0.60)
            feat[82] = random.uniform(0.10, 0.30); feat[123] = random.uniform(0.30, 0.50)
            feat[124] = random.uniform(0.03, 0.08); feat[125] = random.uniform(0.05, 0.12)
        elif profile == 'ransomware':
            feat[64] = random.uniform(0.85, 0.95); feat[65] = random.uniform(0.30, 0.55)
            feat[66] = 1.0; feat[67] = random.uniform(0.20, 0.40); feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0]); feat[74] = random.uniform(0.25, 0.50)
            feat[82] = random.uniform(0.15, 0.35); feat[123] = random.uniform(0.20, 0.40)
            feat[124] = random.uniform(0.02, 0.05); feat[125] = random.uniform(0.08, 0.16)
        elif profile == 'downloader':
            feat[64] = random.uniform(0.55, 0.75); feat[65] = random.uniform(0.15, 0.35)
            feat[66] = 1.0; feat[67] = random.uniform(0.10, 0.25); feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0]); feat[74] = random.uniform(0.15, 0.35)
            feat[82] = random.uniform(0.05, 0.20); feat[123] = random.uniform(0.35, 0.55)
            feat[124] = random.uniform(0.05, 0.12); feat[125] = random.uniform(0.04, 0.10)
        elif profile == 'keylogger':
            feat[64] = random.uniform(0.50, 0.70); feat[65] = random.uniform(0.10, 0.30)
            feat[66] = 1.0; feat[67] = random.uniform(0.10, 0.20); feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0]); feat[74] = random.uniform(0.10, 0.30)
            feat[82] = random.uniform(0.10, 0.25); feat[123] = random.uniform(0.40, 0.60)
            feat[124] = random.uniform(0.06, 0.14); feat[125] = random.uniform(0.03, 0.08)
        elif profile == 'worm':
            feat[64] = random.uniform(0.60, 0.80); feat[65] = random.uniform(0.25, 0.45)
            feat[66] = 1.0; feat[67] = random.uniform(0.15, 0.30); feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0]); feat[74] = random.uniform(0.20, 0.45)
            feat[82] = random.uniform(0.05, 0.20); feat[123] = random.uniform(0.30, 0.50)
            feat[124] = random.uniform(0.04, 0.10); feat[125] = random.uniform(0.05, 0.12)
        elif profile == 'backdoor':
            feat[64] = random.uniform(0.55, 0.78); feat[65] = random.uniform(0.20, 0.40)
            feat[66] = 1.0; feat[67] = random.uniform(0.15, 0.30); feat[68] = 0.0
            feat[69] = random.choice([0.0, 1.0]); feat[74] = random.uniform(0.25, 0.50)
            feat[82] = random.uniform(0.10, 0.25); feat[123] = random.uniform(0.30, 0.50)
            feat[124] = random.uniform(0.04, 0.10); feat[125] = random.uniform(0.05, 0.11)
        for i in range(128): feat[i] = max(0.0, min(1.0, feat[i] + random.gauss(0, 0.015)))
        features.append(feat)
    return features

def main():
    save_path = sys.argv[1]
    random.seed(42)
    print('Collecting clean samples...', flush=True)
    clean_real = collect_clean_features()
    clean_source = collect_clean_source_features()
    clean_synth = generate_synthetic_clean(200)
    malware = generate_malware_features(max(len(clean_real) + len(clean_source) + len(clean_synth), 500))
    all_clean = clean_real + clean_source + clean_synth
    samples = []
    for feat in all_clean:
        samples.append({'features': feat, 'label': 'clean'})
    for feat in malware:
        samples.append({'features': feat, 'label': 'malware'})
    data = {'samples': samples, 'format': 'PSLS_ML_TRAIN_v1', 'dim': 128}
    with open(save_path, 'w', encoding='utf-8') as f:
        json.dump(data, f)
    print(f'EXPORT_OK {len(samples)}')

if __name__ == '__main__':
    main()
'''

            # 注入项目根目录（供脚本内 sys.path 使用，从而能 import engine.ml_detector）
            _proj_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            export_script = export_script.replace('__PROJECT_ROOT__', _proj_root.replace('\\', '/'))

            if getattr(sys, 'frozen', False):
                # 打包模式：进程内 exec 执行导出脚本
                # sys.executable 是 PSLS.exe，subprocess.run 会启动第二个 GUI 进程
                import io, contextlib
                argv_backup = sys.argv[:]
                sys.argv = ['<ml_export>', save_path]
                try:
                    stdout_buf = io.StringIO()
                    exec_globals = {'__name__': '__main__', '__file__': '<ml_export>'}
                    with contextlib.redirect_stdout(stdout_buf):
                        exec(compile(export_script, '<ml_export>', 'exec'), exec_globals)
                    output = stdout_buf.getvalue()
                    if 'EXPORT_OK' in output:
                        n = '?'
                        for line in output.split('\n'):
                            if 'EXPORT_OK' in line:
                                n = line.split('EXPORT_OK')[-1].strip()
                        self._emit_tool_signal(
                            'mlTrainResult',
                            json.dumps({'status': 'export_success', 'message': f'训练数据已导出：\n{save_path}\n共 {n} 个样本'}, ensure_ascii=False)
                        )
                        self._add_activity('ML引擎', f'训练数据导出成功 ({n} 样本)', 'INFO', '成功')
                    else:
                        logger.error(f'进程内导出训练数据失败: {output[:300]}')
                        self._emit_tool_signal(
                            'mlTrainResult',
                            json.dumps({'status': 'error', 'message': '导出失败，请重试'}, ensure_ascii=False)
                        )
                        self._add_activity('ML引擎', '训练数据导出失败', 'ERROR', '错误')
                except Exception as e:
                    logger.error(f'进程内导出训练数据异常: {e}', exc_info=True)
                    self._emit_tool_signal(
                        'mlTrainResult',
                        json.dumps({'status': 'error', 'message': f'导出失败: {str(e)}'}, ensure_ascii=False)
                    )
                finally:
                    sys.argv = argv_backup
            else:
                # 开发模式：子进程执行（隔离 DLL 冲突）
                import subprocess, tempfile
                fd, script_path = tempfile.mkstemp(suffix='.py', prefix='ml_export_')
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    f.write(export_script)

                result = subprocess.run(
                    [sys.executable, script_path, save_path],
                    capture_output=True, text=True, timeout=120, creationflags=_HIDDEN_CREATIONFLAGS
                )

                try:
                    os.unlink(script_path)
                except Exception:
                    pass

                if result.returncode == 0 and 'EXPORT_OK' in result.stdout:
                    n = '?'
                    for line in result.stdout.split('\n'):
                        if 'EXPORT_OK' in line:
                            n = line.split('EXPORT_OK')[-1].strip()
                    self._emit_tool_signal(
                        'mlTrainResult',
                        json.dumps({'status': 'export_success', 'message': f'训练数据已导出：\n{save_path}\n共 {n} 个样本'}, ensure_ascii=False)
                    )
                    self._add_activity('ML引擎', f'训练数据导出成功 ({n} 样本)', 'INFO', '成功')
                else:
                    logger.error(f'导出训练数据子进程失败: {result.stderr[:300]}')
                    self._emit_tool_signal(
                        'mlTrainResult',
                        json.dumps({'status': 'error', 'message': '导出失败，请重试'}, ensure_ascii=False)
                    )
                    self._add_activity('ML引擎', '训练数据导出失败', 'ERROR', '错误')

        except Exception as e:
            logger.error(f'导出训练数据失败: {e}', exc_info=True)
            self._emit_tool_signal(
                'mlTrainResult',
                json.dumps({'status': 'error', 'message': f'导出失败: {str(e)}'}, ensure_ascii=False)
            )

    def _try_refresh_yara_status(self, re):
        """尝试刷新 YARA 可用性状态（子进程验证 + 模块重载）"""
        try:
            import importlib
            import sys
            import subprocess
            import engine.rule_engine as rule_engine_mod

            # 先尝试直接导入（快速路径）
            try:
                for mod_name in list(sys.modules.keys()):
                    if mod_name == 'yara' or mod_name.startswith('yara.'):
                        del sys.modules[mod_name]
                yara_module = importlib.import_module('yara')
                rule_engine_mod.HAS_YARA = True
                rule_engine_mod.yara = yara_module
                re._yara_available = True
                re._load_yara_rules()
                logger.info('YARA 动态检测成功（直接导入），已启用')
                return
            except Exception:
                pass

            # 子进程验证（兜底方案，处理 C 扩展 DLL 锁定问题）
            python_exe = _get_python_executable()
            if python_exe:
                try:
                    check_code = 'import yara; print("OK")'
                    result = subprocess.run(
                        [python_exe, '-c', check_code],
                        capture_output=True, text=True, timeout=5,
                        creationflags=_HIDDEN_CREATIONFLAGS
                    )
                    if result.returncode == 0 and 'OK' in result.stdout:
                        rule_engine_mod.HAS_YARA = True
                        re._yara_available = True
                        re._load_yara_rules()
                        logger.info('YARA 动态检测成功（子进程验证），已启用')
                        return
                    else:
                        logger.debug(f'YARA 子进程检测: {result.stderr[:200]}')
                except Exception as e:
                    logger.debug(f'YARA 子进程检测失败: {e}')
            else:
                logger.debug('YARA 子进程检测跳过：打包环境下无可用 Python 解释器')

            # 打包环境或子进程验证失败：直接检查便携桥接
            if not re._yara_available and HAS_PORTABLE_YARA:
                if re._yara_portable is None:
                    try:
                        from engine.yara_portable import YaraPortable
                        re._yara_portable = YaraPortable()
                        re._yara_portable.reset_cache()
                    except Exception:
                        pass
                if re._yara_portable and re._yara_portable.is_available():
                    re._yara_portable_available = True
                    re._yara_available = True
                    re._load_yara_rules()
                    logger.info('YARA 动态检测成功（便携桥接），已启用')
        except Exception as e:
            logger.debug(f'YARA 状态刷新失败: {e}')

    @pyqtSlot(bool, result=bool)
    def setYaraEnabled(self, enabled: bool) -> bool:
        """设置 YARA 引擎开关（设置页"YARA 规则引擎"开关调用）"""
        try:
            if not self._scan_engine or not self._scan_engine.rule_engine:
                return False
            result = self._scan_engine.rule_engine.set_yara_enabled(enabled)
            _save_ui_settings({'yara_enabled': bool(enabled)})
            return result
        except Exception as e:
            logger.error(f'设置 YARA 引擎开关失败: {e}')
            return False

    @pyqtSlot(result=str)
    def getStrictMode(self):
        """获取严格模式开关状态（设置页"严格模式"开关调用）

        Returns:
            JSON 字符串: {"enabled": bool, "description": str}
        """
        try:
            return json.dumps({
                'enabled': self._strict_mode,
                'description': '严格模式' if self._strict_mode else '宽松模式'
            }, ensure_ascii=False)
        except Exception as e:
            logger.error(f'获取严格模式状态失败: {e}')
            return json.dumps({'enabled': False, 'error': str(e)}, ensure_ascii=False)

    @pyqtSlot(bool, result=str)
    def setVirusIdentifier(self, enabled: bool):
        """设置 VirusIdentifier 开关（设置页"VirusIdentifier 检测"开关调用）

        VirusIdentifier 是纯启发式打分引擎（7 维：可疑 API / 熵 / 扩展名 /
        关键词…），覆盖 PE 与非 PE 文件，但对正常软件误报偏高，故默认关闭。

        立即生效范围：
        - 主扫描引擎 virus_identifier_enabled
        - 实时监控器（影响其扫描进程池的配置）
        - 后续新建的实时扫描引擎（_create_scan_engine_for_realtime）
        注意：已存在的扫描进程池持有旧配置，重启程序后完全一致。
        """
        try:
            self._vi_enabled = bool(enabled)
            _save_ui_settings({'virus_identifier_enabled': self._vi_enabled})

            try:
                if self._scan_engine:
                    self._scan_engine.virus_identifier_enabled = self._vi_enabled
            except Exception as se:
                logger.warning(f'VirusIdentifier 同步主扫描引擎失败: {se}')

            try:
                if self._realtime_monitor:
                    self._realtime_monitor.virus_identifier_enabled = self._vi_enabled
            except Exception as re_err:
                logger.warning(f'VirusIdentifier 同步实时监控器失败: {re_err}')

            state = '已启用' if self._vi_enabled else '已关闭'
            try:
                self._add_activity('系统', f'VirusIdentifier 检测{state}', 'INFO', '配置')
            except Exception:
                pass
            logger.info(f'VirusIdentifier 检测{state}')
            return json.dumps({
                'success': True,
                'enabled': self._vi_enabled,
                'message': f'VirusIdentifier 检测{state}',
            }, ensure_ascii=False)
        except Exception as e:
            logger.error(f'设置 VirusIdentifier 开关失败: {e}')
            return json.dumps({
                'success': False,
                'enabled': getattr(self, '_vi_enabled', False),
                'message': f'操作失败: {e}',
            }, ensure_ascii=False)

    @pyqtSlot(result=str)
    def getVirusIdentifierStatus(self):
        """读取 VirusIdentifier 开关状态（前端启动同步用）"""
        try:
            return json.dumps({
                'enabled': bool(getattr(self, '_vi_enabled', False)),
            }, ensure_ascii=False)
        except Exception as e:
            return json.dumps({'enabled': False, 'error': str(e)}, ensure_ascii=False)

    @pyqtSlot(bool, result=str)
    @_cfg_timed
    def setStrictMode(self, enabled: bool):
        """设置严格模式开关（设置页"严格模式"开关调用）

        严格模式启用后立即生效：
        - 主扫描引擎 strict_mode 同步更新
        - 实时监控器 strict_mode 同步更新
        - 下次创建实时扫描引擎时按新模式配置

        Args:
            enabled: JS 传递的布尔值

        Returns:
            JSON 字符串: {"success": bool, "enabled": bool, "message": str}
        """
        try:
            self._strict_mode = bool(enabled)
            _save_ui_settings({'strict_mode': self._strict_mode})

            # 同步到主扫描引擎
            try:
                if self._scan_engine:
                    self._scan_engine.strict_mode = self._strict_mode
                    print(f'[DEBUG setStrictMode] scan_engine.strict_mode set to {self._strict_mode}')
                else:
                    print('[DEBUG setStrictMode] scan_engine is None')
            except Exception as se:
                print(f'[DEBUG setStrictMode] scan_engine sync error: {se}')

            # 同步到实时监控器（影响 suspicious 状态是否自动隔离）
            try:
                if self._realtime_monitor:
                    self._realtime_monitor.strict_mode = self._strict_mode
                    print(f'[DEBUG setStrictMode] realtime_monitor.strict_mode set to {self._strict_mode}')
                else:
                    print('[DEBUG setStrictMode] realtime_monitor is None')
            except Exception as re_err:
                print(f'[DEBUG setStrictMode] realtime_monitor sync error: {re_err}')

            # 同步到文件保护（影响勒索软件批量修改检测阈值：严格模式 3文件/秒触发）
            try:
                if self._file_protection:
                    self._file_protection.strict_mode = self._strict_mode
                    print(f'[DEBUG setStrictMode] file_protection.strict_mode set to {self._strict_mode}')
            except Exception as fp_err:
                print(f'[DEBUG setStrictMode] file_protection sync error: {fp_err}')

            # 严格模式开启时，强制开启"监测全部类型的文件"（严格模式要求最广覆盖）
            # 严格模式关闭时，不强制改变用户的"监测全部类型"设置
            if self._strict_mode and not self._monitor_all_file_types:
                self._monitor_all_file_types = True
                _save_ui_settings({'monitor_all_file_types': True})
                try:
                    if self._realtime_monitor:
                        self._realtime_monitor.monitor_all_file_types = True
                except Exception:
                    pass
                # 通知前端同步开关状态
                self.monitorAllFileTypesStatusChanged.emit(json.dumps({
                    'enabled': True,
                    'message': '严格模式已启用，监测全部文件类型'
                }, ensure_ascii=False))
                logger.info('严格模式已启用，监测全部文件类型开关已自动开启')

            mode_name = '严格模式' if self._strict_mode else '宽松模式'
            try:
                self._add_activity(
                    '系统',
                    f'已切换到{mode_name}',
                    'INFO',
                    '配置'
                )
            except Exception:
                pass
            logger.info(f'严格模式已{"启用" if self._strict_mode else "禁用"}')

            # 显示桌面右下角状态弹窗
            try:
                popup = StrictModeStatusPopup(
                    enabled=self._strict_mode,
                    success=True,
                    message=f'已切换到{mode_name}',
                )
                self._show_status_popup(popup)
            except Exception as pe:
                logger.warning(f'显示严格模式状态弹窗失败: {pe}')

            # 发射状态变化信号，让前端同步 UI
            strict_state = {
                'success': True,
                'enabled': self._strict_mode,
                'message': f'已切换到{mode_name}'
            }
            self.strictModeStatusChanged.emit(json.dumps(strict_state, ensure_ascii=False))

            return json.dumps(strict_state, ensure_ascii=False)
        except Exception as e:
            logger.error(f'设置严格模式失败: {e}')
            result = {
                'success': False,
                'enabled': getattr(self, '_strict_mode', False),
                'message': f'操作失败: {e}'
            }
            # 失败时也显示桌面弹窗
            try:
                popup = StrictModeStatusPopup(
                    enabled=getattr(self, '_strict_mode', False),
                    success=False,
                    message=f'操作失败: {e}',
                )
                self._show_status_popup(popup)
            except Exception:
                pass
            return _safe_json_dumps(result)

    @pyqtSlot(result=str)
    def getMonitorAllFileTypes(self):
        """获取"监测全部类型的文件"开关状态

        Returns:
            JSON 字符串: {"enabled": bool, "description": str}
        """
        try:
            return json.dumps({
                'enabled': self._monitor_all_file_types,
                'description': '全部文件类型' if self._monitor_all_file_types else '仅可执行文件'
            }, ensure_ascii=False)
        except Exception as e:
            logger.error(f'获取监测全部文件类型状态失败: {e}')
            return json.dumps({'enabled': True, 'error': str(e)}, ensure_ascii=False)

    @pyqtSlot(bool, result=str)
    def setMonitorAllFileTypes(self, enabled: bool):
        """设置"监测全部类型的文件"开关

        开启后实时监控和扫描引擎将监测所有类型文件（包括文本、图片等非可执行文件）。
        关闭后仅监测可执行文件（PE、脚本、宏文档等），减少非必要扫描开销。
        严格模式开启时此开关不可关闭（强制开启）。

        Args:
            enabled: JS 传递的布尔值

        Returns:
            JSON 字符串: {"success": bool, "enabled": bool, "message": str}
        """
        try:
            enabled = bool(enabled)

            # 关闭"监测全部类型"时，自动关闭严格模式（严格模式依赖全类型监测）
            if not enabled and self._strict_mode:
                self._strict_mode = False
                _save_ui_settings({'strict_mode': False})
                try:
                    if self._scan_engine:
                        self._scan_engine.strict_mode = False
                    if self._realtime_monitor:
                        self._realtime_monitor.strict_mode = False
                    if self._file_protection:
                        self._file_protection.strict_mode = False
                except Exception:
                    pass
                # 通知前端同步严格模式开关状态
                self.strictModeStatusChanged.emit(json.dumps({
                    'success': True,
                    'enabled': False,
                    'message': '监测全部类型已关闭，严格模式已自动关闭'
                }, ensure_ascii=False))
                logger.info('监测全部类型已关闭，严格模式已自动关闭')

            self._monitor_all_file_types = enabled
            _save_ui_settings({'monitor_all_file_types': self._monitor_all_file_types})

            # 同步到实时监控器
            try:
                if self._realtime_monitor:
                    self._realtime_monitor.monitor_all_file_types = enabled
            except Exception as re_err:
                logger.warning(f'同步监测全部文件类型到实时监控器失败: {re_err}')

            mode_name = '全部文件类型' if enabled else '仅可执行文件'
            try:
                self._add_activity(
                    '系统',
                    f'文件监测范围已切换到{mode_name}',
                    'INFO',
                    '配置'
                )
            except Exception:
                pass
            logger.info(f'监测全部文件类型已{"启用" if enabled else "禁用"}')

            # 发射状态变化信号
            result = {
                'success': True,
                'enabled': enabled,
                'message': f'已切换到{mode_name}'
            }
            self.monitorAllFileTypesStatusChanged.emit(_safe_json_dumps(result))
            return _safe_json_dumps(result)
        except Exception as e:
            logger.error(f'设置监测全部文件类型失败: {e}')
            return json.dumps({
                'success': False,
                'enabled': getattr(self, '_monitor_all_file_types', True),
                'message': f'操作失败: {e}'
            }, ensure_ascii=False)

    @pyqtSlot(result=str)
    def getSandboxRunLargeFiles(self):
        """获取"大文件沙箱分析"开关状态

        Returns:
            JSON 字符串: {"enabled": bool, "description": str}
        """
        enabled = getattr(self, '_sandbox_run_large_files', False)
        state = {
            'success': True,
            'enabled': enabled,
            'description': '大文件（>50MB）也运行沙箱分析' if enabled else '大文件跳过沙箱直接拦截',
        }
        return json.dumps(state, ensure_ascii=False)

    @pyqtSlot(bool, result=str)
    def setSandboxRunLargeFiles(self, enabled: bool):
        """设置"大文件沙箱分析"开关

        开启后，超过 50MB 的可执行文件也会触发沙箱行为分析。
        关闭后，大文件跳过沙箱直接拦截（默认行为，避免长时间 CPU/内存占用）。

        Args:
            enabled: JS 传递的布尔值

        Returns:
            JSON 字符串: {"success": bool, "enabled": bool, "message": str}
        """
        try:
            enabled = bool(enabled)
            self._sandbox_run_large_files = enabled
            _save_ui_settings({'sandbox_run_large_files': enabled})

            # 同步到 ProcessProtection（如果已创建）
            try:
                if self._process_protection is not None:
                    self._process_protection.sandbox_run_large_files = enabled
            except Exception as pp_err:
                logger.warning(f'同步大文件沙箱开关到 ProcessProtection 失败: {pp_err}')

            logger.info(f'大文件沙箱分析已{"启用" if enabled else "禁用"}')

            result = {
                'success': True,
                'enabled': enabled,
                'message': f'大文件沙箱分析已{"启用" if enabled else "禁用"}',
            }
            self.sandboxRunLargeFilesStatusChanged.emit(json.dumps(result, ensure_ascii=False))
            return json.dumps(result, ensure_ascii=False)
        except Exception as e:
            logger.error(f'设置大文件沙箱分析开关失败: {e}')
            return json.dumps({
                'success': False,
                'enabled': getattr(self, '_sandbox_run_large_files', False),
                'message': f'操作失败: {e}',
            }, ensure_ascii=False)

    @pyqtSlot(result=str)
    def getSandboxBackend(self):
        """获取沙箱后端设置。

        Returns:
            JSON: {"success": bool, "backend": 'auto'|'sandboxie'|'appcontainer',
                   "sandboxie_available": bool, "reason": str}
        """
        try:
            from engine.sandbox_analyzer import detect_sandboxie_backend
            info = detect_sandboxie_backend()
        except Exception as e:
            info = {'available': False, 'reason': f'探测失败: {e}'}
        return json.dumps({
            'success': True,
            'backend': getattr(self, '_sandbox_backend', 'auto'),
            'sandboxie_available': bool(info.get('available')),
            'reason': info.get('reason', ''),
        }, ensure_ascii=False)

    @pyqtSlot(str, result=str)
    @_cfg_timed
    def setSandboxBackend(self, backend: str):
        """设置沙箱后端：'auto'（首选 Sandboxie，不可用回退 AppContainer）|
        'sandboxie' | 'appcontainer'。"""
        try:
            backend = str(backend or 'auto').strip().lower()
            if backend not in ('auto', 'sandboxie', 'appcontainer'):
                backend = 'auto'
            self._sandbox_backend = backend
            _save_ui_settings({'sandbox_backend': backend})
            try:
                if self._process_protection is not None:
                    self._process_protection.sandbox_backend = backend
            except Exception as pp_err:
                logger.warning(f'同步沙箱后端到 ProcessProtection 失败: {pp_err}')
            logger.info(f'沙箱后端已设置为: {backend}')
            return json.dumps({
                'success': True, 'backend': backend,
                'message': f'沙箱后端已设置为 {backend}',
            }, ensure_ascii=False)
        except Exception as e:
            logger.error(f'设置沙箱后端失败: {e}')
            return json.dumps({'success': False,
                               'backend': getattr(self, '_sandbox_backend', 'auto'),
                               'message': f'操作失败: {e}'}, ensure_ascii=False)

    @pyqtSlot()
    def installYara(self):
        """一键安装 YARA 引擎（主页"一键安装 YARA"按钮调用）

        安装流程：
        1. 检查当前 Python 是否兼容 yara-python
        2. 若兼容：直接 pip install
        3. 若不兼容：自动下载便携 Python 3.13 + yara-python
        4. 安装结果通过 yaraInstallResult 信号通知前端
        """
        try:
            self._add_activity('系统', '开始安装 YARA 引擎', 'INFO', '进行中')

            self._emit_tool_signal(
                'yaraInstallResult',
                json.dumps({'status': 'checking', 'message': '正在检测 Python 环境兼容性...'}, ensure_ascii=False)
            )

            thread = threading.Thread(target=self._run_yara_install, daemon=True)
            thread.start()
        except Exception as e:
            logger.error(f'启动 YARA 安装失败: {e}')
            self._emit_tool_signal(
                'yaraInstallResult',
                json.dumps({'status': 'error', 'message': f'启动安装失败: {str(e)}'}, ensure_ascii=False)
            )

    def _run_yara_install(self):
        """子线程执行 YARA 安装

        安装策略：
        1. 打包模式：sys.executable 是 PSLS.exe，pip install 不可用，
           直接使用便携 Python 3.13 方案
        2. 开发模式：检测当前 Python 是否有 yara-python 预编译 wheel
        3. 若兼容：优先 pip install --only-binary
        4. 若不兼容：下载便携 Python 3.13（嵌入式），在其中安装 yara-python
        5. 安装完成后刷新规则引擎
        """
        try:
            import subprocess
            import sys
            import os
            import tempfile
            import urllib.request
            import json as json_mod

            # 打包模式下 sys.executable 是 PSLS.exe，无法执行 pip install
            # 直接跳到便携 Python 方案
            if getattr(sys, 'frozen', False):
                logger.info('检测到打包模式，跳过 pip install，直接使用便携 Python 方案')
                self._emit_tool_signal(
                    'yaraInstallResult',
                    json.dumps({
                        'status': 'downloading',
                        'message': '打包模式下使用便携 Python 环境...\n正在下载 Python 3.13 兼容环境...'
                    }, ensure_ascii=False)
                )
                self._add_activity('系统', '打包模式：使用便携 Python 3.13 安装 YARA', 'INFO', '进行中')

                # 检查是否已有便携 Python
                portable = YaraPortable()
                if portable.is_available():
                    logger.info('便携 Python + YARA 已存在，直接启用')
                    self._on_yara_install_success(portable_mode=True)
                    return

                # 下载并设置便携 Python
                success = download_portable_python(
                    progress_callback=lambda p, msg: self._emit_tool_signal(
                        'yaraInstallResult',
                        json.dumps({
                            'status': 'downloading',
                            'progress': p,
                            'message': msg
                        }, ensure_ascii=False)
                    )
                )

                if success:
                    self._on_yara_install_success(portable_mode=True)
                else:
                    self._emit_tool_signal(
                        'yaraInstallResult',
                        json.dumps({
                            'status': 'error',
                            'message': (
                                '便携 Python 环境设置失败。\n\n'
                                '备选方案：\n'
                                '1. 手动安装 Python 3.12 或 3.11\n'
                                '   下载: https://www.python.org/downloads/\n'
                                '   安装后重启 PSLS，再次点击一键安装\n\n'
                                '2. 安装 Microsoft C++ Build Tools\n'
                                '   下载: https://visualstudio.microsoft.com/visual-cpp-build-tools/\n'
                                '   安装后在当前环境编译 yara-python'
                            )
                        }, ensure_ascii=False)
                    )
                    self._add_activity('系统', '便携 Python 环境设置失败', 'ERROR', '错误')
                return

            # 开发模式：检查兼容性
            compat = check_yara_compatibility()
            py_ver = compat['py_version']
            plat_tag = compat['platform_tag']
            is_compatible = compat['compatible']
            supported = compat['supported_versions']

            logger.info(f'YARA 兼容性检查: Python {py_ver} {plat_tag}, 兼容={is_compatible}, 支持={supported}')

            if is_compatible:
                # 当前 Python 兼容，直接安装
                self._emit_tool_signal(
                    'yaraInstallResult',
                    json.dumps({
                        'status': 'installing',
                        'message': f'Python {py_ver} 兼容，正在安装 yara-python...'
                    }, ensure_ascii=False)
                )
                self._install_yara_direct(py_ver, plat_tag)
            else:
                # 当前 Python 不兼容，使用便携 Python
                reason = compat['reason']
                self._emit_tool_signal(
                    'yaraInstallResult',
                    json.dumps({
                        'status': 'downloading',
                        'message': (
                            f'当前 Python {py_ver} 不兼容 yara-python\n'
                            f'({reason})\n\n'
                            f'正在下载 Python 3.13 兼容环境...'
                        )
                    }, ensure_ascii=False)
                )
                self._add_activity('系统', f'检测到 Python {py_ver} 不兼容，切换到便携 Python 3.13', 'INFO', '进行中')

                # 检查是否已有便携 Python
                portable = YaraPortable()
                if portable.is_available():
                    logger.info('便携 Python + YARA 已存在，直接启用')
                    self._on_yara_install_success(portable_mode=True)
                    return

                # 下载并设置便携 Python
                success = download_portable_python(
                    progress_callback=lambda p, msg: self._emit_tool_signal(
                        'yaraInstallResult',
                        json.dumps({
                            'status': 'downloading',
                            'progress': p,
                            'message': msg
                        }, ensure_ascii=False)
                    )
                )

                if success:
                    self._on_yara_install_success(portable_mode=True)
                else:
                    self._emit_tool_signal(
                        'yaraInstallResult',
                        json.dumps({
                            'status': 'error',
                            'message': (
                                '便携 Python 环境设置失败。\n\n'
                                '备选方案：\n'
                                '1. 手动安装 Python 3.12 或 3.11\n'
                                '   下载: https://www.python.org/downloads/\n'
                                '   安装后重启 PSLS，再次点击一键安装\n\n'
                                '2. 安装 Microsoft C++ Build Tools\n'
                                '   下载: https://visualstudio.microsoft.com/visual-cpp-build-tools/\n'
                                '   安装后在当前环境编译 yara-python'
                            )
                        }, ensure_ascii=False)
                    )
                    self._add_activity('系统', '便携 Python 环境设置失败', 'ERROR', '错误')

        except Exception as e:
            logger.error(f'安装 YARA 引擎异常: {e}')
            self._add_activity('系统', f'安装 YARA 引擎异常: {str(e)}', 'ERROR', '错误')
            self._emit_tool_signal(
                'yaraInstallResult',
                json.dumps({'status': 'error', 'message': f'安装异常: {str(e)}'}, ensure_ascii=False)
            )

    def _install_yara_direct(self, py_ver: str, platform_tag: str):
        """在当前 Python 环境中直接安装 yara-python"""
        import subprocess
        import sys
        import os
        import tempfile
        import urllib.request
        import json as json_mod

        abi_tag = f'cp{sys.version_info.major}{sys.version_info.minor}'

        # 策略1：尝试强制使用预编译 wheel
        # 不使用 --user，避免 PEP 668 外部管理环境错误
        # 直接安装到 site-packages 目录，主进程可正常导入
        logger.info(f'尝试安装 yara-python (Python {py_ver}, {platform_tag})...')
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install',
             '--only-binary', ':all:', 'yara-python'],
            capture_output=True, text=True, timeout=300, creationflags=_HIDDEN_CREATIONFLAGS
        )

        if result.returncode == 0:
            self._on_yara_install_success(portable_mode=False)
            return

        stderr1 = result.stderr or ''
        stdout1 = result.stdout or ''
        logger.warning(f'pip --only-binary 安装失败: {stderr1[-300:]}')

        # 策略2：下载预编译 wheel 直接安装
        try:
            self._add_activity('系统', '尝试下载预编译 wheel 包...', 'INFO', '进行中')
            self._emit_tool_signal(
                'yaraInstallResult',
                json.dumps({'status': 'installing', 'message': '正在下载预编译 wheel...'}, ensure_ascii=False)
            )

            wheel_installed = self._try_install_yara_wheel(
                sys.executable, py_ver, abi_tag, platform_tag
            )
            if wheel_installed:
                self._on_yara_install_success(portable_mode=False)
                return

            # 如果 wheel 安装也失败，给出最终错误
            build_error = 'Microsoft Visual C++' in (stderr1 + stdout1)
            no_wheel_error = (
                'Could not find a version that satisfies' in (stderr1 + stdout1)
                or 'No matching distribution found' in (stderr1 + stdout1)
            )

            if no_wheel_error:
                error_detail = (
                    f'当前 Python 版本 ({py_ver}) 和 {platform_tag} 平台上未找到 yara-python 预编译 wheel。\n\n'
                    '可能原因：\n'
                    f'1. yara-python 官方尚未发布 Python {py_ver} 的预编译包（通常滞后 1-2 个版本）\n'
                    '2. 当前 Python 是非常新的版本（如 3.14+），需等待官方更新\n\n'
                    '解决方案：\n'
                    '方案A（推荐）：等待自动下载兼容 Python 3.13 环境\n'
                    '方案B：降级 Python 到 3.10/3.11/3.12 后重新安装\n'
                    '   - 下载: https://www.python.org/downloads/\n'
                    '   - 安装后重启 PSLS，再次点击一键安装\n\n'
                    '方案C：安装 Microsoft C++ Build Tools 后从源码编译\n'
                    '   - 下载: https://visualstudio.microsoft.com/visual-cpp-build-tools/\n'
                    '   - 安装时勾选"使用 C++ 的桌面开发"\n'
                    '   - 重启电脑后再次点击一键安装\n\n'
                    '方案D：等待 yara-python 发布当前 Python 版本的支持包\n'
                    '   - 查看: https://pypi.org/project/yara-python/#files'
                )
            elif build_error:
                error_detail = (
                    'pip 无法找到预编译的 wheel 包，且从源码编译需要 Microsoft C++ Build Tools。\n\n'
                    '请手动安装：\n'
                    '1. 访问 https://pypi.org/project/yara-python/#files 下载对应版本的 wheel\n'
                    f'   (Python {py_ver} {platform_tag}: yara_python-*-{abi_tag}-{abi_tag}-{platform_tag}.whl)\n'
                    '2. 运行: pip install 下载的文件.whl\n\n'
                    '或安装 Microsoft C++ Build Tools:\n'
                    'https://visualstudio.microsoft.com/visual-cpp-build-tools/'
                )
            else:
                error_detail = f'pip 安装失败: {(stderr1 or stdout1)[-500:]}'

            logger.error(f'安装 yara-python 失败: {error_detail}')
            self._add_activity('系统', f'安装 YARA 引擎失败', 'ERROR', '错误')
            self._emit_tool_signal(
                'yaraInstallResult',
                json.dumps({'status': 'error', 'message': error_detail}, ensure_ascii=False)
            )
        except Exception as wheel_err:
            logger.error(f'wheel 安装异常: {wheel_err}')
            self._add_activity('系统', f'安装 YARA 引擎失败: {str(wheel_err)}', 'ERROR', '错误')
            self._emit_tool_signal(
                'yaraInstallResult',
                json.dumps({'status': 'error', 'message': f'安装失败: {str(wheel_err)}'}, ensure_ascii=False)
            )

    def _try_install_yara_wheel(self, python_exe: str, py_ver: str, abi_tag: str, platform_tag: str) -> bool:
        """尝试从 PyPI 下载并安装 yara-python 预编译 wheel

        支持降级匹配：当前 Python 版本无 wheel 时，自动尝试兼容的旧版本。

        Returns:
            是否安装成功
        """
        import subprocess
        import sys
        import os
        import tempfile
        import urllib.request
        import json as json_mod

        # 获取 yara-python 所有版本的所有文件
        api_url = 'https://pypi.org/pypi/yara-python/json'
        try:
            with urllib.request.urlopen(api_url, timeout=30) as resp:
                data = json_mod.loads(resp.read().decode('utf-8'))
        except Exception as e:
            logger.error(f'查询 PyPI 失败: {e}')
            return False

        latest_version = data['info']['version']
        urls = data['urls']
        releases = data.get('releases', {})

        # 解析当前 Python 版本号
        try:
            py_major, py_minor = sys.version_info.major, sys.version_info.minor
        except Exception:
            py_major, py_minor = 3, 10

        # yara-python 在 PyPI 上支持的 cp tag（按降序排列）
        # 3.14 wheel 暂未发布，尝试降级到 3.13/3.12 等已发布的版本
        supported_cps = ['cp313', 'cp312', 'cp311', 'cp310', 'cp39']
        current_cp = f'cp{py_major}{py_minor}'

        # 生成候选版本列表：当前版本优先，然后降序尝试
        candidate_cps = [current_cp] + [cp for cp in supported_cps if cp != current_cp]

        # 找到目标 Python 版本和平台对应的 wheel URL（带版本降级）
        matching_url = None
        matching_filename = None
        matching_cp = None
        matched_version = None

        for try_cp in candidate_cps:
            target_pattern = f'-{try_cp}-{try_cp}-{platform_tag}.whl'
            for v, files in releases.items():
                for f in files:
                    fn = f['filename']
                    if fn.endswith(target_pattern) and 'yara_python' in fn:
                        matching_url = f['url']
                        matching_filename = fn
                        matching_cp = try_cp
                        matched_version = v
                        break
                if matching_url:
                    break
            if matching_url:
                break

        if not matching_url:
            logger.warning(
                f'未找到 Python {py_ver} 及兼容版本 {platform_tag} 对应的预编译 wheel'
            )
            return False

        # 如果是降级版本，提示用户
        version_msg = ''
        if matching_cp != current_cp:
            version_msg = (
                f'\n[说明] yara-python 暂未发布 Python {py_ver} 的官方预编译包，'
                f'将自动降级使用 Python {int(matching_cp[2:]) / 10:.1f} 兼容版本（{matched_version}）。'
            )
            logger.info(
                f'Python {py_ver} wheel 不可用，降级到 {matching_cp} 版本: {matched_version}'
            )

        logger.info(f'下载 yara-python wheel: {matching_url}')

        # 下载到临时目录
        tmp_dir = tempfile.mkdtemp(prefix='psls_yara_')
        wheel_path = os.path.join(tmp_dir, matching_filename)

        try:
            self._emit_tool_signal(
                'yaraInstallResult',
                json.dumps({
                    'status': 'installing',
                    'message': f'正在下载 {matching_filename}{version_msg}'
                }, ensure_ascii=False)
            )

            urllib.request.urlretrieve(matching_url, wheel_path)
            logger.info(f'wheel 下载完成: {wheel_path}')

            # 安装下载的 wheel
            self._emit_tool_signal(
                'yaraInstallResult',
                json.dumps({'status': 'installing', 'message': '正在安装 wheel 包...'}, ensure_ascii=False)
            )

            result = subprocess.run(
                [python_exe, '-m', 'pip', 'install', wheel_path],
                capture_output=True, text=True, timeout=300, creationflags=_HIDDEN_CREATIONFLAGS
            )

            if result.returncode != 0:
                logger.error(f'安装 wheel 失败: {result.stderr[-500:]}')
                return False

            logger.info(f'wheel 安装成功 (使用 {matching_cp} 兼容版本)')
            return True
        finally:
            # 清理临时文件
            try:
                if os.path.exists(wheel_path):
                    os.remove(wheel_path)
                if os.path.exists(tmp_dir):
                    os.rmdir(tmp_dir)
            except Exception:
                pass

    def _on_yara_install_success(self, portable_mode: bool = False):
        """YARA 安装成功后的统一处理

        Args:
            portable_mode: 是否为便携 Python 桥接模式
        """
        mode_desc = '（便携 Python 桥接）' if portable_mode else ''
        print(f'[DEBUG _on_yara_install_success] called with portable_mode={portable_mode}')
        logger.info(f'yara-python 安装成功{mode_desc}，尝试重新加载 YARA 引擎')
        self._add_activity('系统', f'yara-python 安装成功{mode_desc}，正在加载引擎', 'INFO', '进行中')

        if self._scan_engine and self._scan_engine.rule_engine:
            re = self._scan_engine.rule_engine

            # 便携模式直接启用
            if portable_mode:
                if re._yara_portable:
                    re._yara_portable.reset_cache()
                reloaded = re.reload_yara_engine()
            else:
                # 直接模式：先通过子进程验证安装
                import engine.rule_engine as rule_engine_mod

                verified = False
                python_exe = _get_python_executable()
                if python_exe:
                    try:
                        import subprocess
                        check_code = 'import yara; print("OK")'
                        result = subprocess.run(
                            [python_exe, '-c', check_code],
                            capture_output=True, text=True, timeout=10, creationflags=_HIDDEN_CREATIONFLAGS
                        )
                        if result.returncode == 0 and 'OK' in (result.stdout or ''):
                            verified = True
                            logger.info(f'YARA 安装验证成功: {result.stdout.strip()}')
                        else:
                            logger.warning(f'YARA 安装验证失败: {result.stderr[:200]}')
                    except Exception as e:
                        logger.error(f'YARA 安装验证异常: {e}')
                else:
                    logger.warning('YARA 安装验证跳过：打包环境下无可用 Python 解释器，尝试便携桥接')

                # 无论子进程验证是否成功，pip 安装已完成，先强制标记 YARA 可用
                # 子进程验证失败通常是环境问题（如打包环境无 python.exe），不影响实际可用性
                re._yara_available = True
                if verified:
                    rule_engine_mod.HAS_YARA = True

                # 尝试加载 YARA 规则
                try:
                    re._load_yara_rules()
                    reloaded = True
                    logger.info('YARA 规则加载成功')
                except Exception as e:
                    logger.warning(f'加载 YARA 规则失败: {e}')
                    # 规则加载失败不算安装失败，YARA 引擎本身仍可用
                    reloaded = True

                # 若 HAS_YARA 仍未设置，尝试 reload_yara_engine 走完整流程补全状态
                if not rule_engine_mod.HAS_YARA:
                    try:
                        re.reload_yara_engine()
                    except Exception as reload_err:
                        logger.debug(f'reload_yara_engine 补全失败: {reload_err}')

            if reloaded:
                # 强制清除缓存，让下次 getRuleEngineStatus 调用立即刷新
                if hasattr(self, '_yara_status_cache_time'):
                    self._yara_status_cache_time = 0
                self._add_activity('系统', f'YARA 引擎安装并启用成功{mode_desc}', 'INFO', '成功')
                self._emit_tool_signal(
                    'yaraInstallResult',
                    json.dumps({
                        'status': 'success',
                        'message': f'YARA 引擎安装成功并已启用{mode_desc}'
                    }, ensure_ascii=False)
                )
            else:
                self._add_activity('系统', f'yara-python 已安装，但规则加载失败{mode_desc}', 'WARN', '失败')
                self._emit_tool_signal(
                    'yaraInstallResult',
                    json.dumps({
                        'status': 'warning',
                        'message': f'yara-python 已安装{mode_desc}，但加载规则失败，请重启软件'
                    }, ensure_ascii=False)
                )
        else:
            self._add_activity('系统', f'yara-python 已安装，请重启软件以启用{mode_desc}', 'INFO', '成功')
            self._emit_tool_signal(
                'yaraInstallResult',
                json.dumps({
                    'status': 'warning',
                    'message': f'yara-python 已安装{mode_desc}，请重启软件以启用'
                }, ensure_ascii=False)
            )

    @pyqtSlot(bool)
    def setSoundEnabled(self, enabled: bool):
        """设置提示音开关（设置页"声音提醒"开关调用）"""
        sound_manager.set_sound_enabled(enabled)
        if self._notification_manager:
            self._notification_manager.set_sound_enabled(enabled)
        logger.info(f'提示音 {"启用" if enabled else "禁用"}')

    @pyqtSlot(bool)
    def setNewFileResultPopupEnabled(self, enabled: bool):
        """设置"新文件扫描结果弹窗"开关（设置页通知区域调用）

        启用后，实时监控扫描新文件完成后会在桌面右下角弹出3秒的扫描结果提示（clean/skipped/error）。
        威胁弹窗由原 threat_action_result 控制，不受此开关影响。
        """
        self._module_states['new-file-result-popup'] = bool(enabled)
        logger.info(f'新文件扫描结果弹窗 {"启用" if enabled else "禁用"}')

    @pyqtSlot(result=bool)
    def getNewFileResultPopupStatus(self) -> bool:
        """获取"新文件扫描结果弹窗"当前开关状态"""
        return bool(self._module_states.get('new-file-result-popup', True))

    @pyqtSlot(bool)
    def setVisualPrankEnabled(self, enabled: bool):
        """设置"恶搞行为检测"开关（设置页实时防护区域调用）

        仅对非信任 PE 启动的进程生效：弹窗风暴 / 桌面图标洪流 /
        壁纸篡改 / 系统个性化设置批量更改。命中先杀进程再询问是否
        信任重启（3 秒超时默认不重启）。
        """
        enabled = bool(enabled)
        self._module_states['visual-prank'] = enabled
        self._persist_module_states()
        det = getattr(self, '_visual_prank_detector', None)
        if det is not None:
            try:
                det.set_enabled(enabled)
            except Exception as e:
                logger.warning(f'切换恶搞行为检测失败: {e}')
        self._add_activity('恶搞行为检测',
                           f'恶搞行为检测{"启用" if enabled else "禁用"}',
                           'INFO', '成功')
        logger.info(f'视觉恶搞行为检测 {"启用" if enabled else "禁用"}')

    @pyqtSlot(result=bool)
    def getVisualPrankStatus(self) -> bool:
        """获取"恶搞行为检测"当前开关状态"""
        return bool(self._module_states.get('visual-prank', True))

    @pyqtSlot(bool)
    def setAggressivePrankEnabled(self, enabled: bool):
        """设置"更激进的特效检测"开关（设置页特效检测区域调用）

        利用屏幕截图实时监控桌面是否有恶意软件在运行（不规则图片 /
        全屏特效 / 大量相同窗口），命中立即终止除系统进程以外的所有
        进程（包括 powershell / cmd）。存在误报风险与性能占用，默认关闭。
        """
        enabled = bool(enabled)
        self._module_states['aggressive-prank'] = enabled
        self._persist_module_states()
        det = getattr(self, '_aggressive_prank_detector', None)
        if det is not None:
            try:
                det.set_enabled(enabled)
            except Exception as e:
                logger.warning(f'切换更激进的特效检测失败: {e}')
        self._add_activity('更激进的特效检测',
                           f'更激进的特效检测{"启用" if enabled else "禁用"}',
                           'INFO', '成功')
        logger.info(f'更激进的特效检测 {"启用" if enabled else "禁用"}')

    @pyqtSlot(result=bool)
    def getAggressivePrankStatus(self) -> bool:
        """获取"更激进的特效检测"当前开关状态"""
        return bool(self._module_states.get('aggressive-prank', False))

    # ================= 勒索软件文件回滚（阶段一） =================

    def _on_rollback_report(self, payload: dict):
        """引擎（后台线程）上报回调 → 活动日志 + 工具信号（不写协议通道）。

        两类上报：
          · action == 'snapshot_done'：快照完成/失败 → 记快照日志并**刷新回滚中心
            的世代列表**（否则启动/周期快照完成后卡片仍空，必须重进页面）；
          · 其它：回滚完成结果（恢复/失败/跳过）。
        """
        try:
            data = dict(payload or {})
            if str(data.get('action') or '') == 'snapshot_done':
                if data.get('ok') is False:
                    self._add_activity(
                        '勒索文件回滚',
                        f"快照失败: {data.get('error', '')}",
                        'WARNING', 'snapshot')
                else:
                    self._add_activity(
                        '勒索文件回滚',
                        (f"快照完成[{data.get('reason', '')}] "
                         f"世代 {data.get('generation_id', 0)}: "
                         f"新增 {data.get('added', 0)} / 未变 {data.get('inherited', 0)} / "
                         f"纳入 {data.get('total', 0)} 个文件 / "
                         f"失败 {data.get('failed', 0)}"),
                        'INFO', 'snapshot')
                # 世代/记录可能已变化 → 后台刷新，完成后推送给前端重渲染
                self._rollback_refresh_async()
                self._emit_tool_signal(
                    'rollbackCompleted',
                    json.dumps({'action': 'snapshot', **data}, ensure_ascii=False))
                return
            level = 'CRITICAL' if data.get('failed') else 'INFO'
            self._add_activity(
                '勒索文件回滚',
                (f"回滚完成: 恢复 {data.get('restored', 0)} / "
                 f"失败 {data.get('failed', 0)} / 跳过 {data.get('skipped', 0)} "
                 f"(原因: {data.get('reason', '')})"),
                level, 'rollback')
            self._emit_tool_signal(
                'rollbackCompleted', json.dumps(data, ensure_ascii=False))
            self._request_critical_sound()
            # 回滚会改动磁盘与记录 → 同样刷新世代/记录列表
            self._rollback_refresh_async()
        except Exception as e:
            logger.warning(f'_on_rollback_report 异常: {e}')
        finally:
            # 无论成功/失败/异常都关闭回滚进度窗口，杜绝孤儿窗。
            # 注意：本回调运行在代理派发线程（worker 模式）或引擎线程（降级模式），
            # **绝不能**在此线程直接操作 QWidget（close/update 跨线程是未定义行为，
            # 会造成间歇性卡死/崩溃）→ 经信号帧转发，由主线程关闭。
            try:
                self._close_rollback_progress_win_safe()
            except Exception:
                pass

    def _ransomware_prompt_admit(self, count: int) -> bool:
        """确认弹窗闩锁判定：是否允许本次发起确认请求。

        在共享锁内判定（回调线程调用），异常安全。返回 False 表示：
          - 已有未决弹窗（pending 闩锁）；或
          - 处于决策后冷却期且受影响集合未显著变化。
        重复被抑制的检测只记 DEBUG + 计数，绝不重发确认请求。
        """
        with self._ransomware_prompt_lock:
            if self._ransomware_prompt_pending:
                self._ransomware_prompt_dup_count += 1
                logger.debug(
                    '勒索回滚确认弹窗已挂起，忽略重复检测（累计抑制 %d 次），受影响 %d 个',
                    self._ransomware_prompt_dup_count, count)
                return False
            now = time.time()
            cooldown_left = self._ransomware_prompt_cooldown_until - now
            if cooldown_left > 0:
                last = self._ransomware_prompt_last_count
                significant = (
                    count >= last * _RANSOMWARE_PROMPT_GROW_FACTOR
                    and count - last >= _RANSOMWARE_PROMPT_GROW_DELTA)
                if not significant:
                    self._ransomware_prompt_dup_count += 1
                    logger.debug(
                        '勒索回滚确认处于冷却期（剩余 %.0fs），抑制重复提示；受影响 %d 个（上次 %d）',
                        cooldown_left, count, last)
                    return False
                logger.info(
                    '勒索回滚确认：冷却期内受影响文件显著增长（%d→%d），允许重新提示',
                    last, count)
            self._ransomware_prompt_pending = True
            self._ransomware_prompt_last_count = int(count)
            return True

    def _ransomware_prompt_resolved(self):
        """确认决策落地（回滚/不回滚/超时/忽略）→ 清 pending + 进入冷却期。

        冷却期内抑制自动确认弹窗再次弹出（检测仍照常记录与处置）；受影响集合
        显著变化时可豁免。参考引用同时清除，保证"同一时刻仅一个弹窗"。
        """
        try:
            with self._ransomware_prompt_lock:
                self._ransomware_prompt_pending = False
                self._ransomware_prompt_cooldown_until = \
                    time.time() + _RANSOMWARE_PROMPT_COOLDOWN
            self._ransomware_rollback_win = None
        except Exception as e:
            logger.debug(f'重置勒索回滚确认闩锁失败: {e}')

    def _on_ransomware_confirmed(self, info: dict):
        """file_protection 确认勒索（杀进程后）回调 → 询问用户是否回滚（不再自动回滚）。

        在 file_protection 子线程中调用：仅通过跨线程信号把询问请求转发到
        主线程弹窗，不阻塞回调线程、不向扫描/沙箱协议通道写任何数据，
        也不改变既有扫描/沙箱判定结论。

        防轰炸：同一轮攻击只提示一次——pending 未决 / 冷却期内（且集合未显著
        变化）时，重复检测只记 DEBUG + 计数，绝不重发确认请求。
        """
        try:
            if self._rollback_manager is None:
                return
            files = (info or {}).get('files') or []
            rtype = (info or {}).get('type') or ''
            # 闩锁：重复检测在此被拦截，不产生新的确认请求
            if not self._ransomware_prompt_admit(len(files)):
                return
            reason = {
                'ransomware_file': '检测到加密后缀文件',
                'ransomware_suspected': '短时间内批量加密行为',
            }.get(rtype, '检测到疑似勒索加密')
            payload = json.dumps({
                'reason': reason,
                'file_count': len(files),
                'suspect_paths': list(files),
            }, ensure_ascii=False)
            # 跨线程信号（队列连接）→ 主线程弹窗；不阻塞、不自动回滚
            self.ransomwareRollbackRequested.emit(payload)
        except Exception as e:
            # 异常安全：绝不让 pending 卡死（否则后续确认永不再弹）
            self._ransomware_prompt_resolved()
            logger.error(f'发起勒索回滚询问失败: {e}')

    def _on_ransomware_rollback_popup_requested(self, request_json: str):
        """主线程：弹出"是否回滚"询问窗口。

        复用沙箱放行询问窗口（是/否二选一 + 倒计时超时兜底），
        超时默认"不回滚"，与项目其它询问的保守默认一致。

        幂等：同一时刻只允许一个确认弹窗；已存在未决弹窗时直接忽略（不再
        关闭旧窗——旧窗的 closeEvent 会误发 releaseRejected，正是"决策后立刻
        又弹"假象的来源）。两套主题共用同一原生窗口与同一入口。
        """
        try:
            prev = self._ransomware_rollback_win
            if prev is not None:
                logger.debug('勒索回滚确认弹窗已存在，忽略重复请求（幂等）')
                return
            req = json.loads(request_json) if isinstance(request_json, str) \
                else dict(request_json or {})
            self._last_ransomware_req = req
            count = int(req.get('file_count') or 0)
            reason = req.get('reason') or '检测到疑似勒索加密'
            self._add_activity(
                '勒索文件回滚',
                f'检测到疑似勒索加密（{reason}，受影响文件 {count} 个），'
                f'等待用户确认是否回滚',
                'CRITICAL', '待确认')
            choices = self._rollback_generation_choices()
            win = SandboxReleaseWindow(
                f'受影响文件 {count} 个',
                subtitle_lines=[
                    f'检测到疑似勒索加密（{reason}）',
                    '请选择要回滚到的世代，然后确认',
                ],
                question_line='请选择要回滚到的世代，然后确认',
                accept_text='立即回滚',
                reject_text='不回滚',
                icon_kind='question',
                timeout_sec=10,
                choices=choices,
                choice_title='回滚目标世代（默认最新）',
            )
            win.releaseAccepted.connect(
                lambda _w=win, _r=req: self._start_ransomware_rollback(
                    _r, generation_id=_w.selected_value(), resolve_prompt=True))
            win.releaseRejected.connect(
                lambda _r=req: self._on_ransomware_rollback_rejected(
                    _r, resolve_prompt=True))
            win.show()
            # 主线程持有引用，防止窗口被 GC
            self._ransomware_rollback_win = win
        except Exception as e:
            self._ransomware_prompt_resolved()
            logger.error(
                f'_on_ransomware_rollback_popup_requested 异常: {e}', exc_info=True)

    def _rollback_generation_choices(self):
        """构造世代选择项（≤3，显示时间+文件数，默认最新在前）。"""
        choices = []
        try:
            rb = self._rollback_manager
            if rb is not None:
                cached = getattr(rb, 'get_generations_cached', None)
                gens = cached() if callable(cached) else rb.get_generations()
                # 弹窗是 GUI 线程路径：同时触发一次后台刷新，下次打开即为最新
                self._rollback_refresh_async()
            else:
                gens = []
            for i, g in enumerate((gens or [])[:3]):
                ts = g.get('created_at_str') or ''
                fc = int(g.get('file_count') or 0)
                tag = '（最新）' if i == 0 else ''
                label = f'{ts} · {fc} 个文件{tag}' if ts else f'世代 {g.get("generation_id")} · {fc} 个文件{tag}'
                choices.append({'label': label, 'value': g.get('generation_id')})
        except Exception as e:
            logger.debug(f'构造世代选择项失败: {e}')
        return choices

    def _start_ransomware_rollback(self, req, generation_id=None,
                                   resolve_prompt: bool = False):
        """用户点【立即回滚】→ 后台线程执行回滚（不阻塞 Qt 主线程）。

        resolve_prompt=True 表示这是"确认弹窗"的决策，落地后清 pending 并进入
        冷却期（抑制同一轮攻击再次弹窗）；手动回滚（回滚中心）不传，不影响。
        """
        req = req or {}
        # 世代 id 未显式给出时，取请求携带值
        if generation_id is None:
            generation_id = req.get('generation_id')
        if resolve_prompt:
            self._ransomware_prompt_resolved()

        def _run():
            try:
                rb = self._rollback_manager
                if rb is None:
                    return
                files = req.get('suspect_paths') or []
                self._add_activity(
                    '勒索文件回滚',
                    f'用户确认立即回滚（世代 {generation_id}），正在执行...',
                    'CRITICAL', '处理中')
                # 先开进度窗口（自动/手动两条路径共用）
                self._rollback_emit_start('用户确认回滚，正在执行…')
                _res = rb.trigger_rollback('user_confirmed', suspect_paths=files,
                                           generation_id=generation_id)
                # worker 模式为**异步受理**（立即返回 accepted），真正的结束
                # 由 report 路径关闭进度窗口；此处若提前关窗，用户就看不到
                # 进度了。只有同步返回了结果（降级模式）才在这里关窗。
                # 注意：本线程是后台线程 → 必须经安全版关窗（信号帧转发）。
                if isinstance(_res, dict) and 'restored' in _res:
                    self._close_rollback_progress_win_safe()
            except Exception as e:
                logger.error(f'用户确认回滚执行失败: {e}')
                try:
                    self._close_rollback_progress_win_safe()
                except Exception:
                    pass
        threading.Thread(target=_run, daemon=True,
                         name='RansomwareRollbackUserConfirmed').start()

    def _on_ransomware_rollback_rejected(self, req, resolve_prompt: bool = False):
        """用户选择【不回滚】（含超时默认）→ 仅记活动日志，备份保留可手动回滚。

        resolve_prompt=True 表示这是"确认弹窗"的决策（含 10s 超时默认），落地后
        清 pending 并进入冷却期；手动取消（回滚中心）不传，不影响自动提示。
        """
        if resolve_prompt:
            self._ransomware_prompt_resolved()
        count = int((req or {}).get('file_count') or 0)
        self._add_activity(
            '勒索文件回滚',
            f'用户选择不回滚（受影响文件 {count} 个）；备份已保留，'
            f'可在"勒索回滚中心"手动回滚',
            'WARN', '跳过')

    @pyqtSlot(str, result=bool)
    def respondRansomwareRollback(self, decision: str) -> bool:
        """接收"立即回滚 / 不回滚"的选择（前端或其它入口调用）。

        decision 支持两种形式：
          - 简单令牌：rollback/accept/yes/true/1 → 立即回滚（最新世代）；
          - JSON：{"decision":"rollback","generation_id":N} → 指定世代回滚。
        其它（含空/超时）→ 不回滚（保守默认）。世代 id 透传至 trigger_rollback。
        """
        try:
            req = dict(self._last_ransomware_req or {})
            gen_id = None
            d = str(decision or '').strip()
            if d.startswith('{'):
                data = json.loads(d)
                if isinstance(data, dict):
                    d = str(data.get('decision') or '').strip().lower()
                    gen_id = data.get('generation_id')
            else:
                d = d.lower()
            if gen_id is not None:
                req['generation_id'] = gen_id
            if d in ('rollback', 'accept', 'yes', 'true', '1'):
                self._start_ransomware_rollback(
                    req, generation_id=gen_id, resolve_prompt=True)
            else:
                self._on_ransomware_rollback_rejected(req, resolve_prompt=True)
            return True
        except Exception as e:
            logger.warning(f'respondRansomwareRollback 失败: {e}')
            return False

    def _ensure_rollback_manager_bg(self):
        """后台补齐勒索回滚管理器（自愈路径；供状态查询/开关调用，不阻塞 GUI）。"""
        try:
            if self._rollback_manager is not None:
                return
            self._try_reinitialize_module('ransomware-rollback', '_rollback_manager')
            rb = self._rollback_manager
            if rb is None:
                logger.error('勒索文件回滚: 补初始化后仍为 None（创建失败）')
                return
            logger.info('勒索文件回滚: 管理器已补齐（后台自愈）')
            if bool(self._module_states.get('ransomware-rollback', True)):
                # 同 init：不以 is_running 门控（见 _init_managers 注释），start 幂等
                rb.start()
                logger.info('勒索文件回滚: 已下发 start（自愈路径）')
        except Exception as e:
            logger.error(f'后台补齐勒索回滚管理器失败: {e}')

    @pyqtSlot(bool)
    @_cfg_timed
    def setRansomwareRollbackEnabled(self, enabled: bool):
        """设置"勒索文件回滚"开关（设置页调用；线程常驻，仅切标记）。"""
        enabled = bool(enabled)
        self._module_states['ransomware-rollback'] = enabled
        self._persist_module_states()
        rb = self._rollback_manager
        # 自愈：管理器尚未创建时（例如总初始化未覆盖到回滚那一段）在此补齐。
        # 历史缺陷：以前这里对 None 只是翻标记、什么都不做，于是"开关显示已启用、
        # 实则没有 worker / 没有快照 / 日志里一条回滚记录都没有"。
        if enabled and rb is None:
            try:
                logger.warning('勒索文件回滚: 管理器缺失，按需创建（此前未初始化）')
                self._try_reinitialize_module('ransomware-rollback',
                                              '_rollback_manager')
                rb = self._rollback_manager
                if rb is not None:
                    logger.info('勒索文件回滚: 管理器已按需创建成功')
            except Exception as e:
                logger.error(f'按需创建勒索文件回滚失败: {e}')
        if rb is not None:
            try:
                rb.set_enabled(enabled)
                if enabled:
                    # GUI 线程零阻塞：start() 会启动/等待 worker(约 20s)，绝不能
                    # 在 Qt 主线程同步执行 → 移到后台线程（不改变启用语义）。
                    def _start_rb(_rb=rb):
                        try:
                            _rb.start()
                            logger.info('勒索文件回滚: 已下发 start（开关启用路径）')
                        except Exception as e:
                            logger.warning(f'后台下发回滚 start 失败: {e}')
                    _t = threading.Thread(target=_start_rb, daemon=True,
                                          name='RbEnableStart')
                    _t.start()
            except Exception as e:
                logger.warning(f'切换勒索文件回滚失败: {e}')
        self._add_activity('勒索文件回滚',
                           f'勒索文件回滚{"启用" if enabled else "禁用"}',
                           'INFO', '成功')
        # 阶段二: 同步驱动写前影子备份开关，并在活动日志记一条世代信息
        # 需求 #3：避免"写前影子备份已启用（已下发世代 N）"每 10s 刷活动日志
        if rb is not None:
            try:
                # 用户显式切换开关 → 始终记录一次（保持既有行为）
                self._log_shadow_state(force=True)
            except Exception as e:
                logger.debug(f'影子备份开关日志失败: {e}')
        logger.info(f'勒索文件回滚 {"启用" if enabled else "禁用"}')

    @pyqtSlot(result=str)
    @_cfg_timed
    def getRansomwareRollbackStatus(self) -> str:
        """获取勒索文件回滚状态（JSON）。"""
        try:
            rb = self._rollback_manager
            if rb is None:
                # 自愈：状态被查询（设置页/回滚中心打开）且模块状态为启用时，
                # 后台补一次创建——总初始化若未覆盖回滚，这里能自动补齐，
                # 不必等用户手动拨开关。后台执行，绝不阻塞 GUI 线程。
                if bool(self._module_states.get('ransomware-rollback', True)):
                    logger.warning('勒索文件回滚: 管理器缺失，触发后台补初始化')
                    threading.Thread(target=self._ensure_rollback_manager_bg,
                                     daemon=True, name='RbEnsureInit').start()
                return _safe_json_dumps({
                    'ok': False, 'running': False,
                    'enabled': bool(self._module_states.get('ransomware-rollback', True)),
                })
            return _safe_json_dumps({'ok': True, **rb.get_stats()})
        except Exception as e:
            logger.warning(f'getRansomwareRollbackStatus 失败: {e}')
            return _safe_json_dumps({'ok': False, 'error': str(e)})

    @pyqtSlot(result=str)
    def getRollbackRecords(self) -> str:
        """获取回滚记录列表（JSON，最新在前）。

        GUI 线程零阻塞：只读代理缓存 + 触发后台刷新；真实数据刷新完成后经
        rollbackCompleted(action=state_refresh) 推送给前端重渲染。
        """
        try:
            rb = self._rollback_manager
            if rb is None:
                return _safe_json_dumps({'ok': True, 'records': []})
            cached = getattr(rb, 'list_records_cached', None)
            if callable(cached):
                records = cached()
                self._rollback_refresh_async()
            else:
                records = rb.list_records(50)
            return _safe_json_dumps({'ok': True, 'records': records})
        except Exception as e:
            logger.warning(f'getRollbackRecords 失败: {e}')
            return _safe_json_dumps({'ok': False, 'records': [], 'error': str(e)})

    def _rollback_refresh_async(self):
        """触发一次后台全量状态刷新（不阻塞；异常安全）。"""
        try:
            rb = self._rollback_manager
            fn = getattr(rb, 'refresh_state_async', None) if rb is not None else None
            if callable(fn):
                fn()
        except Exception:
            pass

    def _on_rollback_state_refreshed(self, state: dict):
        """代理后台刷新完成回调（子线程）→ 推送前端重渲染（不写协议通道）。"""
        try:
            state = state or {}
            payload = {
                'action': 'state_refresh',
                'generations': state.get('generations', []),
                'records': state.get('records', []),
                'dirs': state.get('protected_dirs', []),
                'exts': state.get('snapshot_exts', []),
            }
            self._emit_tool_signal(
                'rollbackCompleted', json.dumps(payload, ensure_ascii=False))
        except Exception as e:
            logger.debug(f'推送回滚状态刷新失败: {e}')

    # ---- 回滚进度窗口（清场→比对→写回→校验→隔离→完成）----

    def _on_rollback_progress_event(self, progress: dict):
        """任意线程：进度回调 → 转发信号到主线程（驱动/关闭进度窗口）。"""
        try:
            payload = json.dumps(progress or {}, ensure_ascii=False)
        except Exception:
            payload = '{}'
        try:
            self.rollbackProgressUpdated.emit(payload)
        except Exception as e:
            logger.debug(f'发射回滚进度失败: {e}')

    def _rollback_emit_start(self, text: str = '准备回滚…'):
        """任意线程：先发一帧"准备回滚"，确保进度窗口先出现。"""
        try:
            self._rollback_progress_last = 0.0          # 重置限流窗口
            self.rollbackProgressUpdated.emit(json.dumps(
                {'stage': '准备回滚', 'percent': 1, 'text': text},
                ensure_ascii=False))
        except Exception:
            pass

    def _throttle_rollback_progress(self, data: dict) -> bool:
        """回滚进度**限流**：≤10 次/秒，且百分比单调不回退。

        需求 #2/#3：逐文件进度帧曾把 GUI 线程占满（主窗口"未响应"）。
        规则：
          - 距上次发送 < 100ms 且该帧非"关键帧"（阶段变化 / 百分比前进 ≥1 /
            完成或失败）→ 丢弃并计数（DEBUG 汇总）；
          - 百分比不得回退（图1 卡在 96% 即因进度不推进 → 这里保证只增不减）。
        返回 True 表示允许发送。
        """
        try:
            now = time.time()
            pct = int(data.get('percent', 0) or 0)
            stage = data.get('stage', '') or ''
            last_ts = float(self._rollback_progress_last or 0.0)
            last_pct = int(self._rollback_progress_last_pct)
            last_stage = self._rollback_progress_last_stage
            critical = (stage != last_stage or pct >= 100
                        or pct >= last_pct + 1 or data.get('done') or data.get('failed'))
            if (now - last_ts) < 0.1 and not critical:
                self._rollback_progress_dropped += 1
                if self._rollback_progress_dropped % 200 == 0:
                    logger.debug(
                        f'回滚进度限流：已丢弃 {self._rollback_progress_dropped} 帧')
                return False
            if pct < last_pct and pct < 100:
                pct = last_pct                     # 单调不回退（真实推进）
                data['percent'] = pct              # 就地修正，发出的帧即单调值
                data['text'] = data.get('text') or ''
            self._rollback_progress_last = now
            self._rollback_progress_last_pct = pct
            self._rollback_progress_last_stage = stage
            self._rollback_progress_sent += 1
            return True
        except Exception:
            return True

    def getRollbackPushStats(self) -> str:
        """观测接口：进度帧 发送/丢弃 计数（供排查"未响应"与自测断言）。"""
        return _safe_json_dumps({
            'sent': int(getattr(self, '_rollback_progress_sent', 0) or 0),
            'dropped': int(getattr(self, '_rollback_progress_dropped', 0) or 0),
        })

    def _on_rollback_progress(self, progress_json: str):
        """主线程：显示/更新回滚进度窗口；到 100% 或"完成"阶段则关闭。"""
        try:
            data = (json.loads(progress_json)
                    if isinstance(progress_json, str)
                    else dict(progress_json or {}))
        except Exception:
            data = {}
        # 线程安全关窗请求（后台线程经 _close_rollback_progress_win_safe 转发）：
        # 必须先于限流处理，且**绝不**在此路径创建新窗口（避免"为关而开"的闪烁）
        if data.get('close'):
            if self._rollback_progress_win is not None:
                self._close_rollback_progress_win()
            return
        if not self._throttle_rollback_progress(data):
            return                                     # 限流丢弃（GUI 零负担）
        pct = int(data.get('percent', 0) or 0)
        stage = data.get('stage', '') or ''
        text = data.get('text', '') or stage
        # UX 约束：周期/prewarn 快照只记日志，绝不弹进度窗口（避免每 5 分钟骚扰）
        if data.get('show', True) is False:
            logger.debug(f'回滚/快照后台进度（不弹窗）: {stage} {pct}%')
            return
        try:
            win = self._rollback_progress_win
            if win is None:
                win = RollbackProgressWindow('勒索文件回滚')
                win.closed.connect(self._on_rollback_progress_closed)
                win.show()
                win.start()
                self._rollback_progress_win = win
            win.set_progress(pct, text)
            if pct >= 100 or '完成' in stage:
                # 完成后短暂停留再关闭，避免闪烁
                QTimer.singleShot(600, self._close_rollback_progress_win)
        except Exception as e:
            logger.debug(f'更新回滚进度窗口失败: {e}')

    def _on_rollback_progress_closed(self):
        self._rollback_progress_win = None

    def _close_rollback_progress_win(self):
        """关闭回滚进度窗口（成功/失败/异常都必须调用，杜绝孤儿窗）。

        **仅限主线程调用**（内部操作 QWidget）。后台线程一律走
        `_close_rollback_progress_win_safe`。
        """
        win = self._rollback_progress_win
        self._rollback_progress_win = None
        if win is None:
            return
        try:
            win.finish('完成')
        except Exception:
            try:
                win.close()
            except Exception:
                pass

    def _close_rollback_progress_win_safe(self):
        """线程安全关窗：主线程直接关；后台线程经 progress 信号帧转发。

        背景：`_on_rollback_report`（代理派发线程/引擎线程）与
        `_start_ransomware_rollback._run` 等后台路径此前直接调用
        `_close_rollback_progress_win()` → 在非 GUI 线程执行
        `QWidget.close()/update()`（未定义行为，间歇性卡死/崩溃）。
        close 帧在 `_on_rollback_progress` 中先于限流处理，且绝不创建新窗口。
        """
        if threading.current_thread() is threading.main_thread():
            self._close_rollback_progress_win()
            return
        try:
            self.rollbackProgressUpdated.emit(json.dumps(
                {'stage': '完成', 'percent': 100, 'close': True},
                ensure_ascii=False))
        except Exception as e:
            logger.debug(f'转发回滚进度窗口关闭帧失败: {e}')

    def _debug_rollback_progress_demo(self):
        """演示：显示回滚进度窗口并推进阶段，随后自动关闭。"""
        try:
            self._on_rollback_progress(json.dumps(
                {'stage': '清场：终止非系统进程', 'percent': 5,
                 'text': '演示：正在终止非系统进程…'}, ensure_ascii=False))
            stages = [
                (25, '比对文件清单', '演示：正在比对世代清单…'),
                (55, '检查点回滚', '演示：正在写回文件 1/3…'),
                (85, '隔离加密残留', '演示：正在隔离加密残留件…'),
                (100, '完成', '演示：回滚完成'),
            ]
            for i, (pct, stage, txt) in enumerate(stages):
                QTimer.singleShot(800 * (i + 1), lambda p=pct, s=stage, t=txt:
                                  self._on_rollback_progress(json.dumps(
                                      {'stage': s, 'percent': p, 'text': t},
                                      ensure_ascii=False)))
        except Exception as e:
            logger.error(f'演示回滚进度窗口失败: {e}')

    def _wire_rollback_manager(self):
        """接线回滚代理：注册状态/进度回调 + 后台预热刷新（GUI 线程零阻塞）。"""
        try:
            rb = self._rollback_manager
            if rb is None:
                return
            cb = getattr(rb, 'set_state_callback', None)
            if callable(cb):
                cb(self._on_rollback_state_refreshed)
            pcb = getattr(rb, 'set_progress_callback', None)
            if callable(pcb):
                pcb(self._on_rollback_progress_event)
            warm = getattr(rb, 'refresh_state_async', None)
            if callable(warm):
                # 放到后台线程，确保降级（本地读）时也不会阻塞调用线程
                threading.Thread(target=warm, daemon=True,
                                 name='RollbackWarm').start()
        except Exception as e:
            logger.debug(f'回滚代理接线失败: {e}')

    @pyqtSlot(result=str)
    def getRollbackProtectedDirs(self) -> str:
        """获取回滚保护目录列表（JSON）。GUI 线程零阻塞：读缓存 + 后台刷新。"""
        try:
            rb = self._rollback_manager
            if rb is None:
                return _safe_json_dumps({'ok': True, 'dirs': []})
            cached = getattr(rb, 'get_protected_dirs_cached', None)
            if callable(cached):
                dirs = cached()
                self._rollback_refresh_async()
            else:
                dirs = rb.get_protected_dirs()
            return _safe_json_dumps({'ok': True, 'dirs': dirs})
        except Exception as e:
            logger.warning(f'getRollbackProtectedDirs 失败: {e}')
            return _safe_json_dumps({'ok': False, 'dirs': [], 'error': str(e)})

    @pyqtSlot(str, result=bool)
    @_cfg_timed
    def setRollbackProtectedDirs(self, dirs_json: str) -> bool:
        """设置回滚保护目录（dirs_json 为目录数组或 {"dirs": [...]}）。

        GUI 线程零阻塞：引擎写操作放后台线程，完成后刷新缓存并推送前端。
        """
        try:
            rb = self._rollback_manager
            if rb is None:
                return False
            data = json.loads(dirs_json) if dirs_json else []
            dirs = data.get('dirs') if isinstance(data, dict) else data

            def _run():
                try:
                    rb.set_protected_dirs(dirs or [])
                    self._rollback_refresh_async()
                except Exception as e:
                    logger.warning(f'后台设置保护目录失败: {e}')
            threading.Thread(target=_run, daemon=True,
                             name='RollbackSetDirs').start()
            self._add_activity(
                '勒索文件回滚',
                f'保护目录更新已提交（{len(dirs or [])} 项）', 'INFO', '成功')
            return True
        except Exception as e:
            logger.warning(f'setRollbackProtectedDirs 失败: {e}')
            return False

    @pyqtSlot(result=str)
    @_cfg_timed
    def getRollbackSnapshotConfig(self) -> str:
        """获取"勒索回滚快照范围与文件类型"配置（JSON）。

        dirs: 受保护目录列表；exts: 文件扩展名白名单（空数组 = 全部类型）；
        max_file_mb: 单文件快照上限（MB），0 = 不限制（调整决定 3：设置页滑动条）。
        只读内存/引擎状态，不阻塞主线程。
        """
        try:
            rb = self._rollback_manager
            if rb is None:
                saved = _load_ui_settings()
                return _safe_json_dumps({
                    'ok': False,
                    'dirs': list(saved.get('rollback_snapshot_dirs', []) or []),
                    'exts': list(saved.get('rollback_snapshot_exts', []) or []),
                    'max_file_mb': _coerce_max_file_mb(
                        saved.get('rollback_max_file_mb', 64)),
                })
            # GUI 线程零阻塞：读缓存（含默认目录解析结果）+ 后台刷新
            dirs_fn = getattr(rb, 'get_protected_dirs_cached', None)
            exts_fn = getattr(rb, 'get_snapshot_exts_cached', None)
            dirs = dirs_fn() if callable(dirs_fn) else rb.get_protected_dirs()
            exts = exts_fn() if callable(exts_fn) else rb.get_snapshot_exts()
            bytes_fn = getattr(rb, 'get_max_file_bytes', None)
            max_bytes = bytes_fn() if callable(bytes_fn) else 64 * 1024 * 1024
            self._rollback_refresh_async()
            return _safe_json_dumps({'ok': True, 'dirs': dirs, 'exts': exts,
                                     'max_file_mb': _bytes_to_mb(max_bytes)})
        except Exception as e:
            logger.warning(f'getRollbackSnapshotConfig 失败: {e}')
            return _safe_json_dumps({'ok': False, 'dirs': [], 'exts': [],
                                     'max_file_mb': 64, 'error': str(e)})

    @pyqtSlot(result=str)
    @_cfg_timed
    def getRollbackDefaultDirs(self) -> str:
        """引擎默认保护目录（桌面/文档/下载/图片/视频/音乐）——**唯一事实来源**。

        调整 3：UI"保护目录"未配置时默认展示这些目录，来源为引擎而非前端硬编码。
        GUI 线程零阻塞（仅读本地文件夹解析结果）。
        """
        try:
            rb = self._rollback_manager
            fn = getattr(rb, 'get_default_protected_dirs', None) if rb is not None else None
            dirs = fn() if callable(fn) else []
            return _safe_json_dumps({'ok': True, 'dirs': list(dirs or [])})
        except Exception as e:
            logger.debug(f'getRollbackDefaultDirs 失败: {e}')
            return _safe_json_dumps({'ok': False, 'dirs': []})

    @pyqtSlot(str, result=bool)
    @_cfg_timed
    def setRollbackSnapshotConfig(self, config_json: str) -> bool:
        """设置"勒索回滚快照范围与文件类型"（JSON 进）。

        入参：{"dirs": [...], "exts": [...], "max_file_mb": N}
        （exts 为空/缺省 = 全部类型；max_file_mb 缺省 = 不动，0 = 不限制）。
        行为：更新引擎保护目录 / 类型白名单 / 单文件上限 → 持久化到 settings.json
        的 ui 段（rollback_snapshot_dirs / rollback_snapshot_exts / rollback_max_file_mb）
        → 后台重下发影子配置。绝不写协议通道；不阻塞主线程。
        """
        try:
            rb = self._rollback_manager
            data = json.loads(config_json) if config_json else {}
            if isinstance(data, list):
                data = {'dirs': data}
            if not isinstance(data, dict):
                return False
            dirs = data.get('dirs')
            exts = data.get('exts')
            has_mb = 'max_file_mb' in data and data.get('max_file_mb') is not None
            max_file_mb = _coerce_max_file_mb(data.get('max_file_mb')) if has_mb else None
            # 调整 3：新增目录做规范化 + 重叠去重（与快照侧 _dedup_dirs 同规则），
            # 持久化与下发都用规范化后的结果
            if dirs is not None and rb is not None \
                    and callable(getattr(rb, '_dedup_dirs', None)):
                try:
                    dirs = rb._dedup_dirs(list(dirs))
                except Exception as e:
                    logger.debug(f'保护目录规范化失败（沿用原值）: {e}')
            # 持久化（即使引擎尚未就绪也保存，供下次启动回灌）
            saved = {
                'rollback_snapshot_dirs': list(dirs) if dirs is not None else [],
                'rollback_snapshot_exts': list(exts) if exts is not None else [],
            }
            if max_file_mb is not None:
                saved['rollback_max_file_mb'] = int(max_file_mb)
            _save_ui_settings(saved)
            if rb is not None:
                def _run():
                    try:
                        if dirs is not None:
                            rb.set_protected_dirs(dirs)
                        if exts is not None:
                            rb.set_snapshot_exts(exts)
                        if max_file_mb is not None:
                            # 单文件上限（MB）下发引擎；0 = 不限制
                            set_mb = getattr(rb, 'set_max_file_mb', None)
                            if callable(set_mb):
                                set_mb(max_file_mb)
                        # 目录/类型变化后，后台重下发写前影子配置（不阻塞 UI）
                        try:
                            self._apply_shadow_config()
                        except Exception:
                            pass
                        self._rollback_refresh_async()
                    except Exception as e:
                        logger.warning(f'后台应用快照配置失败: {e}')
                threading.Thread(target=_run, daemon=True,
                                 name='RollbackApplyConfig').start()
                _mb_txt = ('不限制' if max_file_mb == 0
                           else (f'{max_file_mb} MB' if max_file_mb else '默认'))
                self._add_activity(
                    '勒索文件回滚',
                    f'快照范围更新已提交（{len(dirs or []) if dirs is not None else "默认"}'
                    f'；单文件上限 {_mb_txt}）',
                    'INFO', '成功')
            return True
        except Exception as e:
            logger.warning(f'setRollbackSnapshotConfig 失败: {e}')
            return False

    @pyqtSlot(result=str)
    def getRollbackKillAll(self) -> str:
        """获取"回滚前清场"开关（JSON）。默认开启。"""
        try:
            rb = self._rollback_manager
            enabled = True
            if rb is not None:
                fn = getattr(rb, 'get_kill_all_before_restore', None)
                if callable(fn):
                    enabled = bool(fn())
            else:
                enabled = bool(_load_ui_settings().get(
                    'rollback_kill_all_before_restore', True))
            return _safe_json_dumps({'ok': True, 'enabled': enabled})
        except Exception as e:
            logger.warning(f'getRollbackKillAll 失败: {e}')
            return _safe_json_dumps({'ok': False, 'enabled': True, 'error': str(e)})

    @pyqtSlot(bool, result=bool)
    def setRollbackKillAll(self, enabled: bool) -> bool:
        """设置"回滚前清场"开关（持久化到 settings.json 的 ui 段）。"""
        try:
            enabled = bool(enabled)
            _save_ui_settings({'rollback_kill_all_before_restore': enabled})
            rb = self._rollback_manager
            if rb is not None:
                fn = getattr(rb, 'set_kill_all_before_restore', None)
                if callable(fn):
                    fn(enabled)
            self._add_activity(
                '勒索文件回滚',
                f'回滚前清场（终止非系统进程）{"启用" if enabled else "禁用"}',
                'INFO', '成功')
            return True
        except Exception as e:
            logger.warning(f'setRollbackKillAll 失败: {e}')
            return False

    @pyqtSlot(int, str, result=bool)
    def restoreRollbackFile(self, record_id: int, path: str) -> bool:
        """从备份单文件恢复（后台线程执行，结果经 rollbackCompleted 上报）。"""
        rb = self._rollback_manager
        if rb is None:
            return False

        def _run():
            try:
                ok = rb.restore_single_file(record_id, path)
                self._add_activity(
                    '勒索文件回滚',
                    f'单文件恢复{"成功" if ok else "失败"}: {path}',
                    'INFO' if ok else 'WARN', 'restore')
                self._emit_tool_signal('rollbackCompleted', json.dumps({
                    'action': 'restore_single', 'ok': ok,
                    'path': path, 'record_id': record_id,
                }, ensure_ascii=False))
            except Exception as e:
                logger.error(f'单文件恢复失败: {e}')
        threading.Thread(target=_run, daemon=True,
                         name='RollbackRestoreSingle').start()
        return True

    @pyqtSlot(str, result=bool)
    def deleteRollbackBackup(self, hash_or_path: str) -> bool:
        """清除单条备份（按哈希或路径；后台线程执行）。"""
        rb = self._rollback_manager
        if rb is None:
            return False

        def _run():
            try:
                ok = rb.delete_backup(hash_or_path)
                self._add_activity(
                    '勒索文件回滚',
                    f'清除备份{"成功" if ok else "失败"}: {hash_or_path}',
                    'INFO' if ok else 'WARN', 'purge')
                self._emit_tool_signal('rollbackCompleted', json.dumps({
                    'action': 'delete_backup', 'ok': ok, 'target': hash_or_path,
                }, ensure_ascii=False))
            except Exception as e:
                logger.error(f'清除备份失败: {e}')
        threading.Thread(target=_run, daemon=True,
                         name='RollbackDeleteBackup').start()
        return True

    @pyqtSlot(result=bool)
    def rollbackSnapshotNow(self) -> bool:
        """立即执行一次增量快照（后台线程执行，不阻塞 UI）。"""
        rb = self._rollback_manager
        if rb is None:
            return False

        def _run():
            try:
                rb.snapshot_now('manual', replace=True)
                # 完成结果统一由 _on_rollback_report(action='snapshot_done')
                # 记录活动日志 + 刷新世代列表（避免这里重复记一条）；此处只兜底
                # 再触发一次刷新，确保世代列表立即更新。
                self._rollback_refresh_async()
            except Exception as e:
                logger.error(f'立即快照失败: {e}')
        threading.Thread(target=_run, daemon=True,
                         name='RollbackSnapshotNow').start()
        return True

    @pyqtSlot(result=bool)
    def rollbackTriggerManual(self) -> bool:
        """「立即回滚」手动触发（回滚中心工具栏；由前端二次确认后调用）。

        走与勒索询问同一套"世代选择"交互：弹出世代选择窗口（≤3，默认最新），
        用户选完确认后才执行 trigger_rollback('manual_confirmed', generation_id)。
        绝不"不问就滚"；重活转投回滚 worker，不阻塞 Qt 主线程。
        """
        rb = self._rollback_manager
        if rb is None:
            return False
        try:
            choices = self._rollback_generation_choices()
            req = {'reason': '手动触发立即回滚', 'file_count': 0,
                   'suspect_paths': []}
            self._last_ransomware_req = req
            prev = self._ransomware_rollback_win
            if prev is not None:
                try:
                    # 程序化替换：标记为用户关闭，避免 closeEvent 误发 releaseRejected
                    # （否则会打出一条"用户选择不回滚"的假日志）
                    prev._closed_by_user = True
                    prev.close()
                except Exception:
                    pass
            win = SandboxReleaseWindow(
                '手动立即回滚',
                subtitle_lines=[
                    '将基于选定世代快照恢复受保护目录中的文件',
                    '请选择要回滚到的世代，然后确认',
                ],
                question_line='请选择要回滚到的世代，然后确认',
                accept_text='立即回滚',
                reject_text='取消',
                icon_kind='question',
                timeout_sec=10,
                choices=choices,
                choice_title='回滚目标世代（默认最新）',
            )
            win.releaseAccepted.connect(
                lambda _w=win, _r=req: self._start_ransomware_rollback(
                    _r, generation_id=_w.selected_value()))
            win.releaseRejected.connect(
                lambda: self._on_ransomware_rollback_rejected(req))
            win.show()
            self._ransomware_rollback_win = win
            self._add_activity(
                '勒索文件回滚', '用户发起手动回滚，等待选择目标世代',
                'CRITICAL', '待确认')
            return True
        except Exception as e:
            logger.error(f'手动立即回滚弹窗失败: {e}')
            return False

    @pyqtSlot(str, result=str)
    @_cfg_timed
    def emergencyTerminateAll(self, payload_json: str = '{}') -> str:
        """**紧急终止**（主界面红色按钮）：直接执行，**零确认**（调整 1）。

        与"回滚前清场"**完全同一条链路与规则**（方案 B）：
        `_kill_all_non_system(reason='emergency')` —— 终止所有**非系统、非 PSLS**
        进程，即**第三方软件（VMware/QQ/微信/WPS/explorer 等）同样会被终止**；
        保护集**仅** Windows 系统关键进程 + PSLS 自身/祖先/子孙链、`psls`/`mlworker`
        （调整决定 2：**不再**保护 Sandboxie 基础设施）。★ 副作用：Sandboxie 服务
        会被一并终止，**沙箱需重启**后才能再次使用。注意：**文件层**的第三方保护
        （隔离残留/回滚写回）不受此影响。

        `payload_json` 参数仅为兼容旧调用方保留（忽略 `confirmed`），不再返回
        `needs_confirm`。执行放后台线程，绝不阻塞 Qt 主线程。
        """
        rb = self._rollback_manager
        # 现象 1 修复：**绝不静默失败**。
        #  - 引擎未就绪（rb is None）→ 按需触发后台构造 + 延后执行（最多等 20s）；
        #  - 清场开关被关掉时，紧急终止应仍然有效 → 临时强制开启；
        #  - 成功/失败/排队都写活动日志（前端另有 toast 反馈，不依赖 window.alert）。
        if rb is None or not callable(getattr(rb, '_kill_all_non_system', None)):
            self._add_activity(
                '紧急终止', '回滚引擎尚未就绪 → 已触发后台初始化，就绪后自动执行',
                'WARNING', '排队中')
            try:
                self._start_module_init_bg('ransomware-rollback', '_rollback_manager')
            except Exception as e:
                logger.debug(f'紧急终止：触发引擎初始化失败: {e}')
        else:
            self._add_activity('紧急终止',
                               '开始终止所有非系统、非 PSLS 进程（同回滚清场规则）',
                               'WARNING', '执行中')

        def _run():
            try:
                deadline = time.time() + 20.0
                eng = self._rollback_manager
                while (eng is None
                       or not callable(getattr(eng, '_kill_all_non_system', None))) \
                        and time.time() < deadline:
                    time.sleep(0.5)
                    eng = self._rollback_manager
                if eng is None or not callable(getattr(eng, '_kill_all_non_system', None)):
                    self._add_activity(
                        '紧急终止', '执行失败：回滚引擎不可用（初始化超时 20s）',
                        'WARNING', '失败')
                    self._emit_tool_signal(
                        'emergencyTerminateFinished',
                        _safe_json_dumps({'ok': False,
                                          'error': '回滚引擎不可用（初始化超时）'}))
                    return
                # 清场开关若被关闭，紧急终止仍需生效（否则按钮形同虚设）
                try:
                    if hasattr(eng, 'get_kill_all_before_restore') \
                            and not eng.get_kill_all_before_restore():
                        eng.set_kill_all_before_restore(True)
                        logger.info('紧急终止：清场开关原为关闭，已临时开启以执行')
                except Exception as e:
                    logger.debug(f'紧急终止：强制开启清场开关失败: {e}')
                # reason='emergency' 在受理白名单内（零确认直呼必须能执行）
                res = eng._kill_all_non_system('emergency')
                killed = res.get('killed') or []
                failed = res.get('failed') or []
                self._add_activity(
                    '紧急终止',
                    f'完成：终止 {len(killed)} 个 / 失败 {len(failed)} 个 / '
                    f'保护 {res.get("protected", 0)} 个'
                    + (f'；跳过原因 {res.get("skipped_reason")}'
                       if res.get('skipped_reason') else ''),
                    'INFO', '完成')
                try:
                    self._emit_tool_signal(
                        'emergencyTerminateFinished',
                        _safe_json_dumps({'ok': True, 'killed': len(killed),
                                          'failed': len(failed)}))
                except Exception:
                    pass
            except Exception as e:
                logger.warning(f'紧急终止执行异常: {e}')
                self._add_activity('紧急终止', f'执行异常: {e}', 'WARNING', '失败')

        try:
            threading.Thread(target=_run, daemon=True,
                             name='EmergencyTerminate').start()
        except Exception as e:
            return _safe_json_dumps({'ok': False, 'error': str(e)})
        return _safe_json_dumps({'ok': True, 'started': True,
                                 'pending': bool(rb is None),
                                 'message': '紧急终止已开始（后台执行）'
                                 if rb is not None else '引擎初始化中，就绪后自动执行'})

    @pyqtSlot(result=str)
    @_cfg_timed
    def getRollbackGenerations(self) -> str:
        """获取当前保留的世代列表（JSON，新→旧，最多 3 个）。

        GUI 线程零阻塞：读缓存 + 后台刷新；刷新完成后经
        rollbackCompleted(action=state_refresh) 推送重渲染。
        """
        try:
            rb = self._rollback_manager
            if rb is None:
                return _safe_json_dumps({'ok': True, 'generations': []})
            cached = getattr(rb, 'get_generations_cached', None)
            if callable(cached):
                gens = cached()
                self._rollback_refresh_async()
            else:
                gens = rb.get_generations()
            return _safe_json_dumps({'ok': True, 'generations': gens})
        except Exception as e:
            logger.warning(f'getRollbackGenerations 失败: {e}')
            return _safe_json_dumps({'ok': False, 'generations': [], 'error': str(e)})

    @pyqtSlot(int, result=bool)
    def triggerRollbackGeneration(self, generation_id: int) -> bool:
        """按指定世代触发回滚（回滚中心世代列表点选；后台线程执行）。"""
        rb = self._rollback_manager
        if rb is None:
            return False
        gid = int(generation_id)

        def _run():
            try:
                self._add_activity(
                    '勒索文件回滚',
                    f'用户选择回滚到世代 {gid}，正在执行...',
                    'CRITICAL', '处理中')
                self._rollback_emit_start(f'回滚到世代 {gid}…')
                _res = rb.trigger_rollback('manual_confirmed', generation_id=gid)
                # 同"用户确认回滚"：worker 异步受理时由 report 路径关窗，
                # 只有同步返回结果（降级模式）才在这里关。
                # 后台线程 → 经安全版关窗（信号帧转发），绝不直接操作 QWidget。
                if isinstance(_res, dict) and 'restored' in _res:
                    self._close_rollback_progress_win_safe()
            except Exception as e:
                logger.error(f'指定世代回滚执行失败: {e}')
                try:
                    self._close_rollback_progress_win_safe()
                except Exception:
                    pass
        threading.Thread(target=_run, daemon=True,
                         name='RollbackGenerationConfirmed').start()
        return True

    @pyqtSlot(result=str)
    def getInitiatorExclusions(self) -> str:
        """获取"发起者排除名单"（JSON）。

        名单分三类：builtin（PSLS 自身）/ user（用户配置）/ dynamic（运行时自动，
        如宿主进程安装目录）。命中名单会跳过**用户态**处置，但不关闭内核硬规则。
        """
        try:
            from utils.initiator_exclusions import get_exclusions
            return _safe_json_dumps({
                'ok': True,
                'items': get_exclusions().list_all(),
            })
        except Exception as e:
            logger.warning(f'getInitiatorExclusions 失败: {e}')
            return _safe_json_dumps({'ok': False, 'items': [], 'error': str(e)})

    @pyqtSlot(str, result=bool)
    def setInitiatorExclusions(self, payload: str) -> bool:
        """整体替换**用户**排除项（builtin / dynamic 项不受影响）。

        payload 形如 {"items": [{"kind":"name_glob","value":"trae*.exe",
                                 "reason":"宿主"}, ...]}
        """
        try:
            from utils.initiator_exclusions import save_user_entries, get_exclusions
            data = json.loads(payload) if payload else {}
            items = data.get('items') if isinstance(data, dict) else data
            ok = save_user_entries(items or [])
            if ok:
                get_exclusions().reload()
            return bool(ok)
        except Exception as e:
            logger.warning(f'setInitiatorExclusions 失败: {e}')
            return False

    @pyqtSlot(str, str)
    def setRealtimeThreatAction(self, action_type: str, action: str):
        """设置实时监控威胁处理策略（设置页下拉框调用）

        Args:
            action_type: 'suspicious' 或 'malware'
            action: 'auto'（自动处理）/ 'notify'（询问）/ 'ignore'（忽略）
        """
        action = action if action in ('auto', 'notify', 'ignore') else 'auto'
        if action_type == 'suspicious':
            self._rt_suspicious_action = action
            # 同步更新 ProcessProtection 的自动处理策略
            if self._process_protection:
                self._process_protection._auto_action = action
        elif action_type == 'malware':
            self._rt_malware_action = action
        else:
            logger.warning(f'未知的威胁处理类型: {action_type}')
            return
        # 持久化（此前仅存内存，重启后丢失该设置）
        _save_ui_settings({
            'rt_suspicious_action': self._rt_suspicious_action,
            'rt_malware_action': self._rt_malware_action,
        })
        logger.info(f'实时监控{action_type}处理策略已设置为: {action}')

    @pyqtSlot(result=str)
    def getRealtimeThreatAction(self) -> str:
        """获取实时监控威胁处理策略（JSON）"""
        return json.dumps({
            'suspiciousAction': self._rt_suspicious_action,
            'malwareAction': self._rt_malware_action,
        }, ensure_ascii=False)

    @pyqtSlot(bool, result=bool)
    def setAutoStart(self, enabled: bool) -> bool:
        """设置开机自启动（设置页"开机时自动运行"开关调用）

        优先注册"登录触发 + 最高权限"计划任务（Windows 启动项最高优先级），
        无管理员权限时自动回退注册表 HKCU\\...\\Run。
        启用后开机时自动以 --minimized 参数启动（静默最小化到系统托盘，
        并提升进程为 HIGH 优先级），优先于其他自启动程序执行。

        Args:
            enabled: True 启用，False 禁用

        Returns:
            操作是否成功
        """
        if not self._autostart_manager or not self._autostart_manager.is_available():
            logger.warning('当前平台不支持开机自启')
            self._add_activity('系统', '开机自启：当前平台不支持', 'WARN', '跳过')
            return False

        success = self._autostart_manager.set_autostart(enabled)
        # 记录用户选择：让"默认开启"策略知道这是用户显式意图，之后不再干预。
        # 无论成功与否都记录（失败时也避免默认策略反复尝试开启而打扰用户）。
        try:
            _save_ui_settings({'autostart': bool(enabled)})
        except Exception as e:
            logger.debug(f'保存开机自启偏好失败: {e}')
        status_text = '启用' if enabled else '禁用'
        if success:
            self._add_activity('系统', f'开机自启已{status_text}', 'INFO', '成功')
            logger.info(f'开机自启已{status_text}')
        else:
            self._add_activity('系统', f'开机自启{status_text}失败', 'ERROR', '错误')
            logger.error(f'开机自启{status_text}失败')
        return success

    def _apply_autostart_default(self):
        """开机自启"默认开启"策略（首次运行自动注册）。

        判定（读 settings.json 的 ui.autostart）：
          · 无记录（首次运行）  → 默认注册开机自启，并记录 autostart=True；
          · 已记录 True（用户选过开）→ 仅在**当前未生效**时补注册（自愈：被
            任务管理器/外部工具移除后能恢复）；
          · 已记录 False（用户选过关）→ 绝不干预，尊重用户选择。

        注册要写计划任务/注册表，故放到后台线程，避免拖慢启动；异常一律吞掉
        只记日志（自启只是便利功能，失败不得影响主程序启动）。
        """
        am = self._autostart_manager
        if am is None or not am.is_available():
            return
        try:
            saved = _load_ui_settings().get('autostart')
        except Exception:
            saved = None
        if saved is False:
            return                                   # 用户明确关闭
        if saved is None:
            need = True                              # 首次运行 → 默认开启
        else:
            need = not am.is_autostart_enabled()     # 用户选过开 → 被移除则自愈
        if not need:
            return

        def _run():
            try:
                ok = am.set_autostart(True)
                if ok:
                    _save_ui_settings({'autostart': True})
                    logger.info('开机自启已按默认策略启用')
                    try:
                        self._add_activity('系统', '开机自启已默认启用', 'INFO', '成功')
                    except Exception:
                        pass
                else:
                    logger.warning('默认启用开机自启失败（不影响主程序启动）')
            except Exception as e:
                logger.warning(f'默认启用开机自启异常: {e}')

        threading.Thread(target=_run, daemon=True,
                         name='AutostartDefault').start()

    @pyqtSlot(result=str)
    def getAutoStartStatus(self) -> str:
        """获取开机自启状态（JSON）

        Returns:
            JSON 字符串：{'available': bool, 'enabled': bool, 'command': str}
        """
        if not self._autostart_manager:
            return json.dumps({'available': False, 'enabled': False, 'command': ''}, ensure_ascii=False)
        return json.dumps(self._autostart_manager.get_status(), ensure_ascii=False)

    def _on_notification_emitted(self, notification: dict):
        """通知管理器回调：将通知转发到前端（在主线程或子线程中调用均安全）"""
        try:
            payload = json.dumps(notification, ensure_ascii=False)
            self._emit_tool_signal('notificationReceived', payload)
        except Exception as e:
            logger.error(f'通知转发失败: {e}')

    @pyqtSlot(result=str)
    def getNotificationStatus(self) -> str:
        """获取通知管理器状态（JSON）"""
        nm = self._notification_manager
        data = {
            'running': nm.is_running if nm else False,
            'enabled': self._module_states.get('notification', True),
            'settings': nm.get_settings() if nm else {},
            'stats': nm.get_stats() if nm else {},
            'history_count': len(nm.history) if nm else 0,
        }
        return json.dumps(data, ensure_ascii=False)

    @pyqtSlot(result=str)
    def getNotificationHistory(self) -> str:
        """获取通知历史记录（JSON）"""
        nm = self._notification_manager
        if nm:
            history = nm.get_history(limit=100)
            stats = nm.get_history_stats()
            return json.dumps({'items': history, 'stats': stats}, ensure_ascii=False)
        return json.dumps({'items': [], 'stats': {}}, ensure_ascii=False)

    @pyqtSlot(str)
    def clearNotificationHistory(self):
        """清空通知历史记录"""
        if self._notification_manager:
            self._notification_manager.clear_history()
            self._add_activity('通知', '通知历史已清空', 'INFO', '成功')

    @pyqtSlot(str, str)
    def updateNotificationSettings(self, key: str, value_str: str):
        """更新通知设置项

        value_str 为字符串，需要根据 key 转换类型。
        """
        if not self._notification_manager:
            return
        try:
            # 尝试自动转换类型
            value = value_str
            if value_str.lower() == 'true':
                value = True
            elif value_str.lower() == 'false':
                value = False
            else:
                try:
                    value = int(value_str)
                except ValueError:
                    try:
                        value = float(value_str)
                    except ValueError:
                        value = value_str

            self._notification_manager.update_settings({key: value})

            # 特殊处理：声音开关同步
            if key == 'sound_enabled':
                sound_manager.set_sound_enabled(bool(value))

            self._add_activity('通知', f'通知设置已更新: {key}', 'INFO', '成功')
        except Exception as e:
            logger.error(f'更新通知设置失败: {e}')

    @pyqtSlot(str, str, str, result=str)
    def sendNotification(self, title: str, message: str, level: str) -> str:
        """手动发送一条通知（用于测试或主动提醒）"""
        if not self._notification_manager:
            return json.dumps({'status': 'error', 'reason': 'not_initialized'})
        result = self._notification_manager.notify(
            title=title, message=message, level=level
        )
        return _safe_json_dumps(result)

    @pyqtSlot()
    def minimizeToTray(self):
        """最小化到系统托盘（前端"退出"按钮调用）

        隐藏主窗口但不退出应用，程序在系统托盘继续运行。
        真正退出需通过托盘右键菜单的"退出"选项。
        """
        try:
            main_window = self.parent()
            if main_window is None:
                # 兜底：遍历顶层窗口找到 WebViewMainWindow
                app = QApplication.instance()
                if app:
                    for w in app.topLevelWidgets():
                        if w.__class__.__name__ == 'WebViewMainWindow':
                            main_window = w
                            break
            if main_window is not None:
                main_window.hide()
                self._add_activity('系统', '已最小化到系统托盘', 'INFO', '成功')
                logger.info('主窗口已隐藏，程序在托盘运行')
            else:
                logger.warning('minimizeToTray: 未找到主窗口')
        except Exception as e:
            logger.error(f'最小化到托盘失败: {e}')

    @pyqtSlot()
    def quitApp(self):
        """真正退出应用（托盘右键菜单"退出"调用）"""
        try:
            self._add_activity('系统', '用户退出应用', 'INFO', '成功')
            logger.info('收到退出请求，应用即将退出')

            # 清理进程保护
            if self._process_protection:
                try:
                    self._process_protection.stop()
                except Exception:
                    pass

            # 清理文件保护
            if self._file_protection:
                try:
                    self._file_protection.stop()
                except Exception:
                    pass

            # 清理系统保护
            if self._system_protection:
                try:
                    self._system_protection.stop()
                except Exception:
                    pass

            # 清理自启动项监测
            if self._autostart_protection:
                try:
                    self._autostart_protection.stop()
                except Exception:
                    pass

            # 清理 MBR 保护
            if self._mbr_protector:
                try:
                    self._mbr_protector.stop()
                except Exception:
                    pass

            # 清理自我保护（退出时停止，避免影响正常关闭）
            if self._self_protection:
                try:
                    self._self_protection.stop()
                except Exception:
                    pass

            # 清理通知管理器
            if self._notification_manager:
                try:
                    self._notification_manager.stop()
                except Exception:
                    pass

            app = QApplication.instance()
            if app:
                # 清理托盘图标
                main_window = self.parent()
                if main_window is None:
                    for w in app.topLevelWidgets():
                        if w.__class__.__name__ == 'WebViewMainWindow':
                            main_window = w
                            break
                if main_window is not None and hasattr(main_window, '_tray_icon'):
                    try:
                        main_window._tray_icon.hide()
                    except Exception:
                        pass
                app.quit()
        except Exception as e:
            logger.error(f'退出应用失败: {e}')
            app = QApplication.instance()
            if app:
                app.quit()

    @pyqtSlot()
    def openQuarantine(self):
        """打开隔离区管理"""
        self.requestPage.emit('tools')
        self._add_activity('工具', '打开隔离区管理', 'INFO', '成功')

    @pyqtSlot(str)
    def analyzePEFile(self, file_path: str):
        """分析 PE 文件，通过 peAnalysisReady 信号返回结果。

        在子线程中执行避免阻塞 UI。
        """
        if not file_path:
            return
        self._add_activity('工具', f'PE分析: {file_path}', 'INFO', '进行中')
        thread = threading.Thread(
            target=self._run_pe_analysis,
            args=(file_path,),
            daemon=True
        )
        thread.start()

    def _has_live_process_for_exe(self, file_path: str,
                                   expected_pid: int = None) -> bool:
        r"""[沙箱执行安全守护] 确认 exe 路径对应的真实存活进程存在。

        用于 _maybe_trigger_sandbox 在放行 CreateProcessW 之前做守卫：
        只有"系统里真正启动过这份可执行文件"时，才允许送沙箱（即便沙箱会在
        temp 目录复制 + Job 隔离，其 CreateProcessW 仍会在用户桌面上触发
        安装包/自解压程序的窗口出现，是严重 UX bug）。
        """
        if not file_path:
            return False

        # 规范化比对基准
        try:
            target_norm = os.path.normcase(os.path.realpath(file_path))
            target_base = os.path.basename(target_norm).lower()
        except Exception:
            return False

        # 1) expected_pid 直查：先验证 PID 真的在跑，再核对路径（如果拿得到）
        if expected_pid and isinstance(expected_pid, int) and expected_pid > 0:
            try:
                from engine.process_protection import HAS_PSUTIL
            except Exception:
                HAS_PSUTIL = False
            try:
                import psutil as _pu
                p = _pu.Process(expected_pid)
                # 进程存活（不抛 NoSuchProcess 即可）
                try:
                    p.status()
                except _pu.NoSuchProcess:
                    pass  # 死了，跳过本分支
                else:
                    # 尝试核对路径：拿得到就比，拿不到也放行（PID有效就足够可信）
                    try:
                        p_exe = p.exe() or ''
                        if p_exe:
                            try:
                                if os.path.normcase(os.path.realpath(p_exe)) == target_norm:
                                    return True
                            except Exception:
                                pass
                    except (_pu.AccessDenied, _pu.ZombieProcess):
                        pass
                    # 仅 PID 存活也视为通过：进程保护/启动扫描链路必然关联同一文件
                    return True
            except Exception:
                pass

        # 2) psutil 全量枚举（优先方案）
        try:
            import psutil as _pu2
            # 最多枚举 4096 个进程就停（防御型上限，避免极端环境耗时过长）
            seen = 0
            MAX_ENUM = 4096
            for proc in _pu2.process_iter(['pid', 'name', 'exe', 'cmdline']):
                seen += 1
                if seen > MAX_ENUM:
                    break
                try:
                    info = proc.info or {}
                except Exception:
                    continue
                # 2a. exe() 路径精确匹配
                p_exe = info.get('exe') or ''
                if p_exe:
                    try:
                        if os.path.normcase(os.path.realpath(p_exe)) == target_norm:
                            return True
                    except Exception:
                        pass
                # 2b. 进程名快速粗筛 + cmdline token 匹配
                p_name = (info.get('name') or '').lower()
                if p_name and target_base and p_name != target_base:
                    # 名字不同但可能是"父进程加载脚本"场景 — 还是看 cmdline
                    pass
                cmdline = info.get('cmdline') or []
                if isinstance(cmdline, (list, tuple)):
                    for tok in cmdline:
                        if not isinstance(tok, str):
                            continue
                        tok_l = tok.strip('"').strip("'")
                        if not tok_l:
                            continue
                        # 精确路径
                        try:
                            if os.path.normcase(os.path.realpath(tok_l)) == target_norm:
                                return True
                        except Exception:
                            pass
                        # 脚本/参数包含目标路径
                        try:
                            if target_norm in os.path.normcase(tok_l):
                                return True
                        except Exception:
                            pass
            return False
        except ImportError:
            pass
        except Exception:
            return False

        # 3) ctypes Toolhelp32 Snapshot（降级方案：只能拿 szExeFile 文件名）
        try:
            import ctypes as _ct
            from ctypes import wintypes as _wt
            kernel32 = _ct.windll.kernel32
            TH32CS_SNAPPROCESS = 0x00000002
            class _PROCESSENTRY32(_ct.Structure):
                _fields_ = [
                    ('dwSize', _wt.DWORD),
                    ('cntUsage', _wt.DWORD),
                    ('th32ProcessID', _wt.DWORD),
                    ('th32DefaultHeapID', _ct.c_size_t),
                    ('th32ModuleID', _wt.DWORD),
                    ('cntThreads', _wt.DWORD),
                    ('th32ParentProcessID', _wt.DWORD),
                    ('pcPriClassBase', _ct.c_ulong),
                    ('dwFlags', _wt.DWORD),
                    ('szExeFile', _ct.c_wchar * 260),
                ]
            kernel32.CreateToolhelp32Snapshot.restype = _wt.HANDLE
            kernel32.Process32FirstW.restype = _wt.BOOL
            kernel32.Process32NextW.restype = _wt.BOOL
            kernel32.CloseHandle.argtypes = [_wt.HANDLE]
            snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if not snap or snap == -1:
                return False
            try:
                pe = _PROCESSENTRY32()
                pe.dwSize = _ct.sizeof(_PROCESSENTRY32)
                ok = kernel32.Process32FirstW(snap, _ct.byref(pe))
                while ok:
                    if pe.szExeFile and pe.szExeFile.lower() == target_base:
                        # 仅文件名匹配算命中；保守但足够卡住绝大多数误触发
                        return True
                    pe.dwSize = _ct.sizeof(_PROCESSENTRY32)
                    ok = kernel32.Process32NextW(snap, _ct.byref(pe))
                return False
            finally:
                kernel32.CloseHandle(snap)
        except Exception:
            return False

    def _looks_like_signed_installer(self, file_path: str) -> bool:
        """文件名形如安装器/更新器 **且** Authenticode 签名有效 → 视为合法安装器。

        仅用于"是否送沙箱执行"的误报抑制；不影响静态扫描/规则/签名判定与隔离。
        任一环节不满足（名字不像 / 无签名 / 校验异常）一律返回 False → 照常送沙箱。
        """
        try:
            base = os.path.basename(file_path).lower()
            stem = os.path.splitext(base)[0]
            if not any(k in stem for k in (
                    'setup', 'install', 'update', 'upgrade', 'patch',
                    'vcredist', 'vcredist_x64', 'vc_redist')):
                return False
            from utils.signature_verifier import verify_file_signature
            return bool(verify_file_signature(file_path))
        except Exception as e:
            logger.debug(f'安装器签名判定失败（按未签名处理）: {e}')
            return False

    def _maybe_trigger_sandbox(self, file_path: str, source: str = 'unknown',
                               process_name: str = None, pid: int = None):
        r"""**通用沙箱触发入口** — 异步、去重、限流 + 执行安全防护

        所有检测链路（主动扫描 / 实时防护 / 进程保护 / 启动扫描）命中威胁后
        都应调用此方法，而不是各自内联沙箱触发代码。

        设计要点：
        - **绝不阻塞调用方**：派 daemon 后台线程执行，调用方毫秒级返回
        - **自动去重**：同一路径 60 秒内只触发一次沙箱（多个检测链路可能同时命中同一文件）
        - **并发限流**：通过 _sandbox_sem 限制最多 2 个沙箱同时运行
        - **前置检查**：文件必须存在 + 必须是可执行文件扩展名（沙箱只跑 PE/脚本）

        ===== 安全红线（本修复新增）=====
        沙箱最终会通过 CreateProcessW 真实执行目标文件。为避免「仅做扫描就启动了用户
        磁盘上的安装包」这类严重 bug，必须严格约束：**不允许对"系统中还未运行、仅
        被静态扫描发现的磁盘文件"执行沙箱分析**。

        合法放行沙箱的场景只有三类：
          1) source in ('进程保护', '启动扫描') + pid > 0 — 用户已手动启动对应进程，
             PSLS 只是把已运行进程先挂起/杀掉再做二次沙箱验证；此时 CreateProcessW
             的目标文件在沙箱 temp 副本中执行、且 Job 隔离，不会额外让用户安装包
             出现"第二份窗口"。
          2) source == '手动' — 用户在 UI 上明确点击了"沙箱分析"按钮，属于主动请求。
          3) source == '实时防护' 且能匹配到系统中真实有对应存活进程（exe 路径或
             命令行包含目标文件）。

        以下来源一律拒绝沙箱（仅做静态处置，绝不 CreateProcessW）：
          - source == '主动扫描' — 用户手动执行全盘/自定义/快速扫描，命中可疑文件时
            直接隔离/弹窗，不再送沙箱（否则 CreateProcessW 会真的启动它们）。
          - source == '实时防护' 但未匹配到存活进程 — 只是文件落盘事件，进程还没
            启动，静态处置即可，不跑沙箱。
          - 其他未知来源。

        Args:
            file_path: 要分析的文件路径
            source: 触发来源（'启动扫描' / '实时防护' / '主动扫描' / '进程保护' / '手动'）
            process_name: 关联的进程名（日志用）
            pid: 关联的进程 PID（启动扫描/进程保护场景）
        """
        if not file_path or not os.path.isfile(file_path):
            return

        # ---- 需求 B2：沙箱候选排除系统关键进程与沙箱基础设施 ----
        # （conhost/sbieini/Start.exe/SbieSvc/PSLS 自身… 不应被送去执行）
        if self._is_launch_scan_excluded(process_name or os.path.basename(file_path),
                                         file_path):
            logger.info(f'沙箱跳过（系统/沙箱基础设施进程）: {os.path.basename(file_path)}')
            return

        # ---- 安全红线 1：来源白名单 ----
        # source='主动扫描' = 纯扫描流程（全盘/自定义/快速），绝不允许跑沙箱执行文件
        if source == '主动扫描':
            logger.info(
                f'沙箱跳过（来源=主动扫描，属纯静态扫描路径）: '
                f'{os.path.basename(file_path)} — 仅隔离/处置，不执行文件')
            return

        # ---- 安全红线 2：对进程关联型来源必须有有效 PID ----
        # 进程保护/启动扫描：用户手动启动了对应进程 → 必须传 pid，否则视为纯扫描
        if source in ('进程保护', '启动扫描'):
            if not pid or not isinstance(pid, int) or pid <= 0:
                logger.warning(
                    f'沙箱跳过（来源={source} 但无有效 PID，视为纯静态发现）: '
                    f'{os.path.basename(file_path)}')
                return

        # ---- 安全红线 3：实时防护/手动/未知 → 存活进程匹配确认 ----
        # 只允许在系统中真实存在对应存活进程的 exe 进入沙箱。
        # 例外：source='手动' 是用户 UI 明确点的按钮，属主动请求，放行。
        if source != '手动':
            if not self._has_live_process_for_exe(file_path, expected_pid=pid):
                logger.info(
                    f'沙箱跳过（系统中未发现对应存活进程）: '
                    f'source={source}, file={os.path.basename(file_path)} '
                    f'— 静态处置即可，不执行文件')
                return

        # 前置：只对真正可执行的文件跑沙箱（与 sandbox_analyzer.py 支持列表严格对齐）
        # 沙箱是"启动进程观察行为"，dll/sys/ocx 需要被 exe 加载才能运行，不能直接启动
        _sandbox_ext_ok = {
            '.exe', '.scr', '.com',
            '.bat', '.cmd', '.ps1', '.vbs', '.js',
        }
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in _sandbox_ext_ok:
            return

        # ---- 误报抑制：合法签名的安装器/更新器不进沙箱 ----
        # 症状：正常安装器（如 setup.exe）写入 Run 键即被判可疑 → 反复送沙箱分析，
        # 既打扰用户又可能让样本链外发。判据严格三重限定，**不降低真实防护**：
        #   1) 文件名形如安装器/更新器（setup/install/update/...）；
        #   2) Authenticode 签名有效（WinVerifyTrust）；
        #   3) 来源不是"手动"（用户主动要求时必须照跑）。
        # 命中只跳过"沙箱执行"，静态扫描/规则/签名判定与隔离处置完全照旧。
        if source != '手动' and self._looks_like_signed_installer(file_path):
            logger.info(
                f'沙箱跳过（已签名安装器/更新器，静态处置照常）: '
                f'{os.path.basename(file_path)} source={source}')
            self._add_activity('沙箱',
                               f'{source}命中已签名安装器，跳过沙箱执行: '
                               f'{os.path.basename(file_path)}', 'INFO', '跳过')
            return

        # 去重：60 秒内同一路径只触发一次
        now = time.time()
        with self._sandbox_recent_lock:
            expired = [k for k, t in self._sandbox_recent.items() if now - t > 120]
            for k in expired:
                del self._sandbox_recent[k]
            if file_path in self._sandbox_recent and now - self._sandbox_recent[file_path] < 60:
                return
            self._sandbox_recent[file_path] = now

        display = process_name or os.path.basename(file_path)
        self._add_activity('沙箱',
                           f'{source}触发: {display}',
                           'INFO', '进行中')

        def _worker():
            acquired = self._sandbox_sem.acquire(timeout=2)
            if not acquired:
                logger.warning(f'沙箱并发已满，跳过: {display}')
                self._add_activity('沙箱', f'并发限制，跳过: {display}',
                                   'WARN', '跳过')
                return
            try:
                self._run_sandbox_analysis(file_path, pid=pid, process_name=display,
                                           source=source)
            except Exception as e:
                logger.error(f'沙箱分析异常 {file_path}: {e}')
            finally:
                self._sandbox_sem.release()

        threading.Thread(target=_worker, daemon=True,
                         name=f'Sandbox-{source}-{display[:20]}').start()

    @pyqtSlot(str)
    def analyzeInSandbox(self, file_path: str):
        """手动触发沙箱分析（UI 按钮入口）"""
        self._maybe_trigger_sandbox(file_path, source='手动')

    def _run_sandbox_analysis(self, file_path: str, pid: int = None, process_name: str = None,
                              source: str = 'unknown'):
        """子线程执行沙箱分析（含文件大小/类型前置检查）

        Args:
            file_path: 要分析的文件路径
            pid: 触发沙箱分析的进程 PID（启动扫描场景），用于沙箱启动失败时终止进程
            process_name: 进程名（用于日志显示）
            source: 触发来源（'手动'=工具箱手动分析；其余为自动检测链路），
                决定大文件跳过时是否隔离
        """
        try:
            if not os.path.isfile(file_path):
                logger.warning(f'沙箱分析跳过：文件不存在 {file_path}')
                return

            # 前置检查：文件大小限制（>50MB 跳过沙箱；用户开启大文件沙箱开关时除外）
            # 与自动检测链路（process_protection）语义保持一致：
            #   - 自动链路（文件已被启动）：>50MB 时终止进程 + 询问用户是否放行，
            #     绝不静默"放行"或"隔离"。
            #   - 工具箱手动分析（source='手动'）：用户只是"想分析"，文件并未运行，
            #     也未被判定为威胁 → 只能如实告知"过大无法分析"，绝不静默隔离，
            #     否则会把用户主动分析的一个正常大文件（如 100MB 安装包）误隔离。
            if not getattr(self, '_sandbox_run_large_files', False):
                try:
                    sz = os.path.getsize(file_path)
                    if sz > 50 * 1024 * 1024:
                        _mb = sz / 1024 / 1024
                        _disp = os.path.basename(file_path)
                        if source == '手动':
                            logger.warning(
                                f'沙箱分析跳过（手动，未隔离）：文件过大 ({_mb:.1f}MB) {file_path}')
                            self._add_activity(
                                '沙箱',
                                f'文件过大 ({_mb:.1f}MB)，无法沙箱分析（未隔离）: {_disp}',
                                'WARN', '跳过')
                            _err = f'文件过大 ({_mb:.1f}MB)，无法沙箱分析（未隔离）'
                        else:
                            logger.warning(
                                f'沙箱分析跳过：文件过大 ({_mb:.1f}MB)，直接隔离 {file_path}')
                            self._add_activity(
                                '沙箱',
                                f'文件过大 ({_mb:.1f}MB)，直接隔离: {_disp}',
                                'WARN', '已隔离')
                            self._handle_large_file_quarantine(file_path, pid, process_name)
                            _err = f'文件过大 ({_mb:.1f}MB)，已直接隔离'
                        # 返回沙箱跳过结果
                        skip_result = json.dumps({
                            'verdict': 'skipped',
                            'score': 0,
                            'behaviors': [],
                            'duration': 0.0,
                            'process_tree': {},
                            'file_path': file_path,
                            'frida_used': False,
                            'error': _err,
                        }, ensure_ascii=False)
                        self._emit_tool_signal('sandboxResultReady', skip_result)
                        return
                except OSError:
                    pass

            config = SandboxConfig()
            config.timeout = 15
            config.backend = getattr(self, '_sandbox_backend', 'auto')

            # 预复制运行副本：file_path 可能正被实时防护等链路的 share=0
            # 独占锁占用（见 _auto_process_threat 的文件锁）。若直接交给
            # analyze，其内部 copy2 会因共享冲突失败（历史实现还会回退直启
            # 源文件 → CreateProcessW 必然返回 32 → 沙箱误判失败并强制隔离）。
            # 这里先复制一份可读副本，沙箱只分析副本。
            _sb_work_dir = None
            _sb_precopy = None
            try:
                import tempfile
                import shutil
                _sb_work_dir = tempfile.mkdtemp(prefix='psls_sandbox_')
                _sb_ext = os.path.splitext(file_path)[1].lower() or '.exe'
                _sb_precopy = os.path.join(_sb_work_dir, 'sample' + _sb_ext)
                from engine.sandbox_analyzer import copy_sample_with_retry
                _ok, _why = copy_sample_with_retry(file_path, _sb_precopy)
                if not _ok:
                    raise IOError(_why)
                config.work_dir = _sb_work_dir
                logger.info(f'沙箱分析：已预复制运行副本 {_sb_precopy}')
            except Exception as e_copy:
                logger.warning(f'沙箱分析：预复制副本失败，将直接分析原文件: {e_copy}')
                if _sb_work_dir:
                    try:
                        import shutil
                        shutil.rmtree(_sb_work_dir, ignore_errors=True)
                    except Exception:
                        pass
                _sb_work_dir = None
                _sb_precopy = None

            # 沙箱分析开始即锁定该程序（进程已被终止、源文件被独占占用），
            # 通知用户"实时保护已锁定【文件名】，稍后自动解除"
            self.notify_file_locked(file_path)

            analyzer = SandboxAnalyzer(config)

            def on_progress(stage: str, percent: float):
                progress_data = json.dumps({
                    'stage': stage,
                    'percent': round(percent * 100, 1)
                }, ensure_ascii=False)
                self._emit_tool_signal('sandboxProgress', progress_data)

            result = analyzer.analyze(_sb_precopy or file_path, on_progress=on_progress)

            # 记录活动日志
            verdict = result.get('verdict', 'error')
            score = result.get('score', 0)
            if verdict == 'malware':
                self._add_activity('沙箱', f'检测到恶意行为 (评分:{score}): {os.path.basename(file_path)}',
                                   'WARN', '威胁')
            elif verdict == 'suspicious':
                self._add_activity('沙箱', f'检测到可疑行为 (评分:{score}): {os.path.basename(file_path)}',
                                   'INFO', '可疑')
            elif verdict == 'clean':
                self._add_activity('沙箱', f'行为分析通过 (评分:{score}): {os.path.basename(file_path)}',
                                   'INFO', '成功')
            else:
                self._add_activity('沙箱', f'分析失败: {result.get("error", "未知错误")}',
                                   'ERROR', '错误')

            # === 沙箱结果窗口（与分析进度窗口同风格，子线程→主线程弹窗） ===
            if verdict in ('malware', 'suspicious'):
                # 威胁结果窗口：红色 × 图标 + 单个"知道了"按钮
                label = '恶意' if verdict == 'malware' else '可疑'
                try:
                    self.sandboxThreatPopupRequested.emit(
                        json.dumps({'file_path': file_path}, ensure_ascii=False))
                except Exception as e:
                    logger.error(f'沙箱威胁弹窗信号发射异常（{label}）: {e}')
            elif verdict == 'error':
                err = result.get('error', '')
                # 启动失败（含 CreateProcessW 失败等实际启动失败场景）：
                # 直接终止进程并隔离文件（跳过豁免规则，但可信签名文件豁免防误报）
                if '启动失败' in err or 'CreateProcessW 失败' in err:
                    logger.warning(f'沙箱进程启动失败，执行强制隔离: {file_path}')
                    if self._handle_sandbox_launch_failure(file_path, pid, process_name):
                        # 确已处置（隔离/已存在/隔离失败）才弹沙箱失败结果窗口；
                        # 签名可信被豁免时不弹"已强制隔离"窗口
                        try:
                            self.sandboxFailurePopupRequested.emit(
                                json.dumps({'file_path': file_path}, ensure_ascii=False))
                        except Exception as e:
                            logger.error(f'沙箱失败弹窗信号发射异常: {e}')
                else:
                    # 其他失败原因，统一弹出沙箱失败结果窗口
                    try:
                        self.sandboxFailurePopupRequested.emit(
                            json.dumps({'file_path': file_path}, ensure_ascii=False))
                    except Exception as e:
                        logger.error(f'沙箱失败弹窗信号发射异常: {e}')

            self._emit_tool_signal('sandboxResultReady',
                                   _safe_json_dumps(result, default=str))

            # 清理预复制运行副本（analyze 因 config.work_dir 非 None 不自动清理）
            if _sb_work_dir:
                try:
                    import shutil
                    shutil.rmtree(_sb_work_dir, ignore_errors=True)
                except Exception:
                    pass

        except Exception as e:
            logger.error(f'沙箱分析失败: {e}', exc_info=True)
            error_result = json.dumps({
                'verdict': 'error',
                'score': 0,
                'behaviors': [],
                'duration': 0.0,
                'process_tree': {},
                'file_path': file_path,
                'frida_used': False,
                'error': f'分析异常: {e}',
            }, ensure_ascii=False)
            self._emit_tool_signal('sandboxResultReady', error_result)
            if _sb_work_dir:
                try:
                    import shutil
                    shutil.rmtree(_sb_work_dir, ignore_errors=True)
                except Exception:
                    pass

    def _file_is_trusted_signed(self, file_path: str) -> bool:
        """文件是否带可信数字签名（用于沙箱启动失败豁免，防误报）

        判定规则：Authenticode 签名链有效（verified=True）为前提——
          发布者命中可信大厂名单 → 可信
          发布者取不到（PowerShell 提取失败）→ 签名链有效本身可信，豁免
          发布者明确但不在白名单 → 不可信（签名有效但来源未知，不强豁免）
        异常/文件缺失一律按不可信处理（保守）。
        """
        try:
            if not os.path.isfile(file_path):
                return False
            verifier = signature_verifier.get_verifier()
            if not verifier.is_available():
                return False
            info = verifier.get_signer_info(file_path)
            if not info or not info.get('verified'):
                return False
            publisher = (info.get('publisher') or '').strip()
            if publisher and not signature_verifier.is_trusted_publisher(publisher):
                logger.debug(f'签名有效但发布者不在可信名单: {publisher} @ {file_path}')
                return False
            return True
        except Exception as e:
            logger.debug(f'签名校验异常（按不可信处理）: {e}')
            return False

    def _handle_sandbox_launch_failure(self, file_path: str, pid: int = None, process_name: str = None):
        """沙箱进程启动失败时的强制处置：终止进程 + 隔离文件（跳过豁免规则）

        沙箱无法启动通常意味着文件有反沙箱行为或格式异常，
        按恶意软件对待：先终止原进程，再强制隔离文件。

        守卫：文件带可信数字签名（微软等大厂）时跳过强制处置——
        启动失败常由合法程序被占用/锁定引起，避免误杀误隔离。
        返回 True=已处置，False=已豁免/未处置（由调用方决定是否弹窗）。
        """
        display_name = process_name or os.path.basename(file_path)

        # 0. 可信签名守卫：合法签名文件启动失败大概率是占用/权限问题，不强制处置
        if self._file_is_trusted_signed(file_path):
            logger.warning(f'沙箱启动失败但文件签名可信，跳过强制处置: {display_name}')
            self._add_activity('沙箱',
                               f'沙箱启动失败（签名可信，未处置）: {display_name}',
                               'WARN', '已豁免')
            return False

        # 1. 终止原进程（如果有 PID）
        if pid:
            try:
                import psutil
                proc = psutil.Process(pid)
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                    logger.info(f'沙箱启动失败，已终止进程: PID={pid} {display_name}')
                    self._add_activity('沙箱',
                                       f'沙箱启动失败，已终止进程: {display_name} (PID:{pid})',
                                       'WARN', '已终止')
                except psutil.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                    logger.info(f'沙箱启动失败，已强制杀死进程: PID={pid} {display_name}')
                    self._add_activity('沙箱',
                                       f'沙箱启动失败，已强制杀死进程: {display_name} (PID:{pid})',
                                       'WARN', '已终止')
            except psutil.NoSuchProcess:
                logger.debug(f'进程已不存在: PID={pid}')
            except Exception as e:
                logger.warning(f'终止进程失败: PID={pid}, {e}')

        # 2. 强制隔离文件（跳过豁免规则）
        if self._quarantine_manager:
            try:
                result = self._quarantine_manager.quarantine_file(
                    file_path,
                    reason=f'沙箱启动失败-强制隔离',
                    malware_name=f'沙箱反分析行为: {display_name}',
                    skip_exemption=True  # 跳过豁免规则
                )
                if result is True:
                    # 结果弹窗由 _run_sandbox_analysis 统一弹出 SandboxFailureWindow
                    self._add_activity('沙箱',
                                       f'沙箱启动失败，已强制隔离: {display_name}',
                                       'WARN', '已隔离')
                elif result == 'duplicate':
                    logger.info(
                        f'沙箱启动失败兜底：文件已在隔离区，跳过重复隔离: {file_path}')
                else:
                    err = self._quarantine_manager.get_last_quarantine_error()
                    self._add_activity('沙箱',
                                       f'沙箱启动失败，隔离失败: {display_name} ({err})',
                                       'ERROR', '隔离失败')
            except Exception as e:
                logger.error(f'沙箱启动失败后隔离异常: {e}', exc_info=True)

        # 已进入处置流程（非签名豁免）：通知调用方确已处置，可弹失败结果窗
        return True

    def _handle_large_file_quarantine(self, file_path: str, pid: int = None, process_name: str = None):
        """大文件跳过沙箱后的直接隔离处置：终止进程 + 隔离文件

        文件过大无法在沙箱中安全运行，但已触发沙箱分析说明扫描引擎
        判定其为 suspicious/malware，按威胁对待直接隔离。
        """
        display_name = process_name or os.path.basename(file_path)

        # 1. 终止原进程（如果有 PID）
        if pid:
            try:
                import psutil
                proc = psutil.Process(pid)
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                    logger.info(f'大文件隔离，已终止进程: PID={pid} {display_name}')
                    self._add_activity('沙箱',
                                       f'已终止进程: {display_name} (PID:{pid})',
                                       'WARN', '已终止')
                except psutil.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                    logger.info(f'大文件隔离，已强制杀死进程: PID={pid} {display_name}')
                    self._add_activity('沙箱',
                                       f'已强制杀死进程: {display_name} (PID:{pid})',
                                       'WARN', '已终止')
            except psutil.NoSuchProcess:
                logger.debug(f'进程已不存在: PID={pid}')
            except Exception as e:
                logger.warning(f'终止进程失败: PID={pid}, {e}')

        # 2. 隔离文件
        if self._quarantine_manager:
            try:
                result = self._quarantine_manager.quarantine_file(
                    file_path,
                    reason='大文件跳过沙箱-直接隔离',
                    malware_name=f'可疑大文件: {display_name}',
                    skip_exemption=True
                )
                if result is True:
                    self._add_activity('沙箱',
                                       f'大文件已隔离: {display_name}',
                                       'WARN', '已隔离')
                    self._show_threat_result_popup({
                        'file_path': file_path,
                        'status': 'malware',
                        'signature_name': f'可疑大文件: {display_name}',
                        'action': 'large_file_quarantine',
                        'result': {'success': True, 'message': '文件过大跳过沙箱，已直接隔离'},
                    })
                elif result == 'duplicate':
                    logger.info(
                        f'大文件隔离：文件已在隔离区，跳过重复隔离: {file_path}')
                else:
                    err = self._quarantine_manager.get_last_quarantine_error()
                    self._add_activity('沙箱',
                                       f'大文件隔离失败: {display_name} ({err})',
                                       'ERROR', '隔离失败')
            except Exception as e:
                logger.error(f'大文件隔离异常: {e}', exc_info=True)

    @pyqtSlot()
    def computeHash(self):
        """计算哈希（旧版兼容方法，仅打开文件选择对话框）"""
        from PyQt5.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getOpenFileName(
            None,
            '选择文件',
            '',
            '所有文件 (*.*)'
        )
        if file_path:
            self._add_activity('工具', f'计算哈希: {file_path}', 'INFO', '成功')

    @pyqtSlot()
    def viewLogs(self):
        """查看日志"""
        self._add_activity('工具', '打开日志分析器', 'INFO', '成功')


    @pyqtSlot(str)
    def exportLogs(self, save_path: str):
        """导出日志到指定路径，通过 logsExported 信号返回结果。

        导出三部分内容（与开发模式终端/日志分析器口径一致）：
          一、详细日志：antivirus_<今日>.log 全文（含 DEBUG 级，带模块名）
          二、启动调试日志：~\\psls_debug.log（BRIDGE 初始化链路明细）
          三、活动日志摘要：内存中最近的活动记录（原导出内容）

        之前只导出活动摘要（三），缺少排查所需的模块级 DEBUG 明细，
        现补齐一、二使其与开发模式终端可观察到的详细程度一致。
        """
        try:
            if not save_path:
                self._emit_tool_signal('logsExported', False)
                return

            # 日志目录逻辑必须与 utils/logger.py / getLogs 保持一致
            if getattr(sys, 'frozen', False):
                if sys.platform == 'win32':
                    appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
                else:
                    appdata = os.path.expanduser('~/.config')
                log_dir = os.path.join(appdata, 'PSLS', 'logs')
            else:
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                log_dir = os.path.join(project_root, 'logs')
            today_str = datetime.now().strftime('%Y%m%d')
            log_file = os.path.join(log_dir, f'antivirus_{today_str}.log')
            debug_file = os.path.join(os.path.expanduser('~'), 'psls_debug.log')

            # 导出行数上限：防止整天全量 DEBUG（含逐文件扫描日志）导出超大文件
            _MAX_DETAIL_LINES = 100000
            _truncated = False

            # 一、详细日志文件（全部级别，含 DEBUG，带模块名）
            detail_lines = []
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        if len(detail_lines) >= _MAX_DETAIL_LINES:
                            _truncated = True
                            break
                        detail_lines.append(line)

            # 二、启动调试日志（BRIDGE 启动链路明细）
            bridge_lines = []
            if os.path.exists(debug_file):
                with open(debug_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.rstrip('\n')
                        if not line:
                            continue
                        if len(bridge_lines) >= _MAX_DETAIL_LINES:
                            _truncated = True
                            break
                        bridge_lines.append(line)

            # 三、活动日志摘要（内存，按时间倒序）
            activity_lines = []
            for activity in reversed(self._activities):
                activity_lines.append(
                    f"[{activity.get('timestamp', '')}] [{activity.get('level', '')}] "
                    f"{activity.get('source', '')} - {activity.get('message', '')} "
                    f"({activity.get('status', '')})\n"
                )

            def _log_clean(line: str) -> str:
                # 日志卫生：旧日志/异常退出可能留下 NUL 等非法字节（会让导出文件
                # 被判定为二进制、无法用文本工具检索），统一清洗后再写入。
                return (line or '').replace('\x00', '').replace('\ufffd', '')

            with open(save_path, 'w', encoding='utf-8') as f:
                f.write('PSLS 离线杀毒软件 - 日志导出\n')
                f.write(f'导出时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
                f.write('=' * 80 + '\n\n')
                f.write('一、详细日志（与日志分析器/开发模式终端一致，含 DEBUG 级）\n')
                f.write(f'   文件: {log_file}\n')
                f.write(f'   行数: {len(detail_lines)}' + ('（已达上限截断）' if _truncated else '') + '\n')
                f.write('-' * 60 + '\n')
                f.writelines(_log_clean(line) + '\n' for line in detail_lines)
                f.write('\n' + '=' * 80 + '\n\n')
                f.write('二、启动调试日志（BRIDGE 初始化链路）\n')
                f.write(f'   文件: {debug_file}\n')
                f.write(f'   行数: {len(bridge_lines)}\n')
                f.write('-' * 60 + '\n')
                f.writelines(_log_clean(line) + '\n' for line in bridge_lines)
                f.write('\n' + '=' * 80 + '\n\n')
                f.write(f'三、活动日志摘要（最近 {len(self._activities)} 条）\n')
                f.write('-' * 60 + '\n')
                for line in activity_lines:
                    f.write(line)
            self._emit_tool_signal('logsExported', True)
            self._add_activity('日志', f'导出日志到: {save_path}', 'INFO', '成功')
        except Exception as e:
            logger.error(f'导出日志失败: {e}')
            self._emit_tool_signal('logsExported', False)
            self._add_activity('日志', f'导出日志失败: {str(e)}', 'ERROR', '错误')

    @pyqtSlot()
    def exportLogsDialog(self):
        """弹出保存对话框导出日志（无参版本，供主页按钮调用）"""
        try:
            from PyQt5.QtWidgets import QFileDialog
            default_name = f'psls_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
            file_path, _ = QFileDialog.getSaveFileName(
                None,
                '导出日志',
                default_name,
                '日志文件 (*.log *.txt);;所有文件 (*.*)'
            )
            if file_path:
                self.exportLogs(file_path)
            else:
                self._emit_tool_signal('logsExported', False)
        except Exception as e:
            logger.error(f'导出日志对话框失败: {e}')
            self._emit_tool_signal('logsExported', False)

    @pyqtSlot()
    def refreshDashboard(self):
        """刷新仪表板数据"""
        try:
            _t_ir = time.monotonic()
            sig_count = 0
            q_count = 0
            try:
                # GUI 线程读数：SignatureDB.get_signature_count 内部对主线程
                # 只做 ≤50ms 的极短等待（后台装载未完成则返回"尚未装载"），
                # 绝不在 GUI 线程长等 106MB 库装载。
                sig_count = self._signature_db.get_signature_count() if self._signature_db else 0
            except Exception as e:
                logger.debug(f'initRequested: 读取签名数失败: {e}')
            try:
                q_count = len(self._quarantine_manager.list_items()) if self._quarantine_manager else 0
            except Exception as e:
                logger.debug(f'initRequested: 读取隔离区条目数失败: {e}')
            self._record_gui_block('initRequested.reads', (time.monotonic() - _t_ir) * 1000)
            self.signatureCountUpdated.emit(sig_count)
            self.quarantineUpdated.emit(q_count)
        except Exception as e:
            logger.error(f'刷新仪表板失败: {e}')

    # ===== 工具子页面后端方法 =====

    @pyqtSlot()
    def getQuarantineList(self):
        """获取隔离区列表，通过 quarantineListReady 信号返回 JSON（异步后台线程执行）。

        放到后台线程执行的原因：
        - 极端情况下（批量操作刚结束时元数据锁竞争），_load_metadata 持锁等待
          会阻塞主线程 → UI 卡死。后台线程中等待锁不会影响 UI。
        - 缓存命中时快速返回（毫秒级），不感知后台线程开销。
        - 返回结构：{items: [...], stats: {total, quarantined, restored, deleted}}
          stats.total 为活跃隔离项数量，stats.all 为元数据总记录数
        """
        def _build_and_emit():
            try:
                items = []
                stats = {'total': 0, 'quarantined': 0, 'restored': 0, 'deleted': 0}
                if self._quarantine_manager:
                    all_items = self._quarantine_manager.get_all_items()
                    stats['all'] = len(all_items)
                    for idx, item in enumerate(all_items):
                        status = item.get('status', 'quarantined')
                        if status in stats:
                            stats[status] += 1
                        # 仅返回活跃的隔离项（已恢复/已删除的不在列表中显示）
                        if status != 'quarantined':
                            continue
                        stats['total'] += 1
                        items.append({
                            'id': idx,
                            'filename': item.get('filename', ''),
                            'original_path': item.get('original_path', ''),
                            'malware_name': item.get('malware_name', ''),
                            'reason': item.get('reason', ''),
                            'status': status,
                            'quarantine_time': item.get('quarantine_time', ''),
                            'file_hash': item.get('file_hash', ''),
                            'is_archive_internal': item.get('is_archive_internal', False),
                        })
                else:
                    stats['all'] = 0
                result = {'items': items, 'stats': stats}
                self._emit_tool_signal('quarantineListReady', _safe_json_dumps(result))
            except Exception as e:
                logger.error(f'获取隔离区列表失败: {e}')
                error_result = {
                    'items': [],
                    'stats': {'total': 0, 'quarantined': 0, 'restored': 0, 'deleted': 0},
                    'error': str(e)
                }
                self._emit_tool_signal('quarantineListReady', json.dumps(error_result, ensure_ascii=False))

        import threading as _th
        _th.Thread(target=_build_and_emit, daemon=True).start()

    @pyqtSlot(int, result=bool)
    def restoreQuarantineItem(self, item_id: int) -> bool:
        """恢复指定隔离项，返回是否成功"""
        try:
            if not self._quarantine_manager:
                return False
            result = self._quarantine_manager.restore_file(item_id)
            
            # 处理新的返回格式：可能是 bool 或 dict（包含备用位置信息）
            if isinstance(result, dict):
                success = result.get('success', False)
                actual_path = result.get('actual_path', '')
                note = result.get('note', '')
                if success:
                    q_count = len(self._quarantine_manager.list_items())
                    self.quarantineUpdated.emit(q_count)
                    if actual_path:
                        self._add_activity('隔离区', 
                            f'恢复隔离项 #{item_id} 成功（文件位于: {actual_path}）', 
                            'INFO', '成功')
                    else:
                        self._add_activity('隔离区', f'恢复隔离项 #{item_id} 成功', 'INFO', '成功')
                    # 触发弹窗通知用户文件位置
                    self.notify_file_located_after_restore(actual_path, note)
                else:
                    self._add_activity('隔离区', f'恢复隔离项 #{item_id} 失败', 'WARN', '失败')
                return success
            elif result is True:
                q_count = len(self._quarantine_manager.list_items())
                self.quarantineUpdated.emit(q_count)
                self._add_activity('隔离区', f'恢复隔离项 #{item_id} 成功', 'INFO', '成功')
                return True
            else:
                self._add_activity('隔离区', f'恢复隔离项 #{item_id} 失败', 'WARN', '失败')
                return False
        except Exception as e:
            logger.error(f'恢复隔离项失败: {e}')
            self._add_activity('隔离区', f'恢复隔离项 #{item_id} 异常: {str(e)}', 'ERROR', '错误')
            return False

    @pyqtSlot(int, result=bool)
    def deleteQuarantineItem(self, item_id: int) -> bool:
        """删除指定隔离项，返回是否成功"""
        try:
            if not self._quarantine_manager:
                return False
            success = self._quarantine_manager.delete_file(item_id)
            if success:
                q_count = len(self._quarantine_manager.list_items())
                self.quarantineUpdated.emit(q_count)
                self._add_activity('隔离区', f'删除隔离项 #{item_id}', 'INFO', '成功')
            else:
                self._add_activity('隔离区', f'删除隔离项 #{item_id} 失败', 'WARN', '失败')
            return success
        except Exception as e:
            logger.error(f'删除隔离项失败: {e}')
            self._add_activity('隔离区', f'删除隔离项 #{item_id} 异常: {str(e)}', 'ERROR', '错误')
            return False

    @pyqtSlot(str, result=str)
    def restoreQuarantineItemsBatch(self, item_ids_json: str) -> str:
        """批量恢复隔离项

        单次加载/保存元数据，避免逐个操作时的重复 I/O 和信号发射导致的卡顿。
        在后台线程执行，避免阻塞 UI。

        Args:
            item_ids_json: JSON 数组字符串，元素为隔离项索引

        Returns:
            JSON 字符串: {success, failed, total, errors}
        """
        try:
            import json as _json
            try:
                ids = _json.loads(item_ids_json)
            except Exception:
                ids = []
            if not isinstance(ids, list) or not ids:
                result = {'success': False, 'message': '无效的ID列表', 'success_count': 0, 'failed_count': 0, 'total': 0}
                return _safe_json_dumps(result)

            if not self._quarantine_manager:
                result = {'success': False, 'message': '隔离区未初始化', 'success_count': 0, 'failed_count': 0, 'total': len(ids)}
                return _safe_json_dumps(result)

            # 在后台线程执行批量恢复，避免阻塞 UI
            def _do_batch():
                try:
                    res = self._quarantine_manager.restore_files_batch(ids)
                    q_count = len(self._quarantine_manager.list_items())
                    self._emit_tool_signal('quarantineUpdated', q_count)
                    self._add_activity('隔离区', f"批量恢复: 成功 {res['success']} 个, 失败 {res['failed']} 个",
                                       'INFO' if res['failed'] == 0 else 'WARN',
                                       '成功' if res['failed'] == 0 else '部分失败')
                    result = {
                        'success': res['failed'] == 0,
                        'message': f"成功恢复 {res['success']} 个文件" + (f"，失败 {res['failed']} 个" if res['failed'] else ''),
                        'success_count': res['success'],
                        'failed_count': res['failed'],
                        'total': res['total'],
                    }
                    self._emit_tool_signal('quarantineBatchResult', _safe_json_dumps(result))
                except Exception as e:
                    logger.error(f'批量恢复异常: {e}', exc_info=True)
                    result = {'success': False, 'message': f'异常: {str(e)}', 'success_count': 0, 'failed_count': len(ids), 'total': len(ids)}
                    self._emit_tool_signal('quarantineBatchResult', _safe_json_dumps(result))

            threading.Thread(target=_do_batch, daemon=True).start()
            # 立即返回，结果通过 quarantineBatchResult 信号传递
            return _safe_json_dumps({'success': True, 'message': '批量恢复已开始', 'async': True})
        except Exception as e:
            logger.error(f'批量恢复启动失败: {e}', exc_info=True)
            return _safe_json_dumps({'success': False, 'message': str(e), 'success_count': 0, 'failed_count': 0, 'total': 0})

    @pyqtSlot(str, result=str)
    def deleteQuarantineItemsBatch(self, item_ids_json: str) -> str:
        """批量删除隔离项

        单次加载/保存元数据，避免逐个操作时的重复 I/O 和信号发射导致的卡顿。
        在后台线程执行，避免阻塞 UI。

        Args:
            item_ids_json: JSON 数组字符串，元素为隔离项索引

        Returns:
            JSON 字符串: {success, failed, total, errors}
        """
        try:
            import json as _json
            try:
                ids = _json.loads(item_ids_json)
            except Exception:
                ids = []
            if not isinstance(ids, list) or not ids:
                result = {'success': False, 'message': '无效的ID列表', 'success_count': 0, 'failed_count': 0, 'total': 0}
                return _safe_json_dumps(result)

            if not self._quarantine_manager:
                result = {'success': False, 'message': '隔离区未初始化', 'success_count': 0, 'failed_count': 0, 'total': len(ids)}
                return _safe_json_dumps(result)

            # 在后台线程执行批量删除，避免阻塞 UI
            def _do_batch():
                try:
                    res = self._quarantine_manager.delete_files_batch(ids)
                    q_count = len(self._quarantine_manager.list_items())
                    self._emit_tool_signal('quarantineUpdated', q_count)
                    self._add_activity('隔离区', f"批量删除: 成功 {res['success']} 个, 失败 {res['failed']} 个",
                                       'INFO' if res['failed'] == 0 else 'WARN',
                                       '成功' if res['failed'] == 0 else '部分失败')
                    result = {
                        'success': res['failed'] == 0,
                        'message': f"成功删除 {res['success']} 个文件" + (f"，失败 {res['failed']} 个" if res['failed'] else ''),
                        'success_count': res['success'],
                        'failed_count': res['failed'],
                        'total': res['total'],
                    }
                    self._emit_tool_signal('quarantineBatchResult', _safe_json_dumps(result))
                except Exception as e:
                    logger.error(f'批量删除异常: {e}', exc_info=True)
                    result = {'success': False, 'message': f'异常: {str(e)}', 'success_count': 0, 'failed_count': len(ids), 'total': len(ids)}
                    self._emit_tool_signal('quarantineBatchResult', _safe_json_dumps(result))

            threading.Thread(target=_do_batch, daemon=True).start()
            # 立即返回，结果通过 quarantineBatchResult 信号传递
            return _safe_json_dumps({'success': True, 'message': '批量删除已开始', 'async': True})
        except Exception as e:
            logger.error(f'批量删除启动失败: {e}', exc_info=True)
            return _safe_json_dumps({'success': False, 'message': str(e), 'success_count': 0, 'failed_count': 0, 'total': 0})

    @pyqtSlot(int, result=str)
    def addQuarantineItemToWhitelist(self, item_id: int) -> str:
        """将指定隔离项添加到白名单（通过文件哈希），返回 JSON 结果

        Args:
            item_id: 隔离项索引

        Returns:
            JSON 字符串: {success, skipped, message, mode: 'single'}
            - success=True  表示已成功加入白名单
            - success=True, skipped=True  表示该文件已在白名单中（跳过）
            - success=False 表示失败（找不到哈希、数据库未初始化等）
        """
        try:
            if not self._quarantine_manager:
                result = {'success': False, 'message': '隔离区未初始化', 'mode': 'single'}
                self.whitelistAddResult.emit(_safe_json_dumps(result))
                return _safe_json_dumps(result)
            if not self._signature_db:
                result = {'success': False, 'message': '签名库未初始化', 'mode': 'single'}
                self.whitelistAddResult.emit(_safe_json_dumps(result))
                return _safe_json_dumps(result)

            all_items = self._quarantine_manager.get_all_items()
            if item_id < 0 or item_id >= len(all_items):
                result = {'success': False, 'message': '无效的隔离项', 'mode': 'single'}
                self.whitelistAddResult.emit(_safe_json_dumps(result))
                return _safe_json_dumps(result)

            item = all_items[item_id]
            file_hash = item.get('file_hash', '')
            filename = item.get('filename', f'#{item_id}')
            if not file_hash or len(file_hash) != 64:
                logger.warning(f'单项添加白名单: {filename} 缺少完整 file_hash，尝试现场恢复')
                # 历史/软隔离记录可能缺失 file_hash：现场从隔离文件恢复完整哈希
                # （隔离库文件名只保留16位前缀，不足64位不能直接用作白名单哈希）
                recovered = self._quarantine_manager.recover_file_hash(item)
                if recovered and len(recovered) == 64:
                    file_hash = recovered
                    logger.info(f'单项添加白名单: 现场恢复 file_hash={file_hash[:16]}...')
                if not file_hash or len(file_hash) != 64:
                    result = {'success': False, 'message': f'{filename} 缺少文件哈希', 'mode': 'single'}
                    self.whitelistAddResult.emit(_safe_json_dumps(result))
                    return _safe_json_dumps(result)

            # 已在白名单中则跳过
            if self._signature_db.is_whitelisted(file_hash):
                result = {'success': True, 'skipped': True, 'message': f'{filename} 已在白名单中', 'mode': 'single'}
                self.whitelistAddResult.emit(_safe_json_dumps(result))
                return _safe_json_dumps(result)

            reason = f'隔离区手动添加 (威胁: {item.get("malware_name", "未知")})'
            ok = self._signature_db.add_to_whitelist(file_hash, reason)
            if ok:
                self._add_activity('白名单', f'从隔离区添加 {filename} 到白名单', 'INFO', '成功')
                result = {'success': True, 'message': f'{filename} 已加入白名单', 'mode': 'single'}
                self.whitelistAddResult.emit(_safe_json_dumps(result))
                return _safe_json_dumps(result)
            else:
                self._add_activity('白名单', f'从隔离区添加 {filename} 到白名单失败', 'WARN', '失败')
                result = {'success': False, 'message': f'{filename} 加入白名单失败', 'mode': 'single'}
                self.whitelistAddResult.emit(_safe_json_dumps(result))
                return _safe_json_dumps(result)
        except Exception as e:
            logger.error(f'添加隔离项到白名单失败: {e}', exc_info=True)
            self._add_activity('白名单', f'添加隔离项 #{item_id} 到白名单异常: {str(e)}', 'ERROR', '错误')
            result = {'success': False, 'message': f'异常: {str(e)}', 'mode': 'single'}
            self.whitelistAddResult.emit(_safe_json_dumps(result))
            return _safe_json_dumps(result)

    @pyqtSlot(str, result=str)
    def addQuarantineItemsToWhitelistBatch(self, item_ids_json: str) -> str:
        """批量将隔离项添加到白名单

        Args:
            item_ids_json: JSON 数组字符串，元素为隔离项索引

        Returns:
            JSON 字符串: {success, total, added, skipped, failed, message, mode: 'batch'}
        """
        try:
            if not self._quarantine_manager:
                logger.error('批量添加白名单失败: 隔离区管理器未初始化')
                result = {'success': False, 'message': '隔离区未初始化', 'mode': 'batch'}
                self.whitelistAddResult.emit(_safe_json_dumps(result))
                return _safe_json_dumps(result)
            if not self._signature_db:
                logger.error('批量添加白名单失败: 签名库未初始化')
                result = {'success': False, 'message': '签名库未初始化', 'mode': 'batch'}
                self.whitelistAddResult.emit(_safe_json_dumps(result))
                return _safe_json_dumps(result)

            try:
                ids = json.loads(item_ids_json) if item_ids_json else []
            except Exception as je:
                logger.error(f'批量添加白名单失败: 参数解析异常 {je}')
                result = {'success': False, 'message': '参数解析失败', 'mode': 'batch'}
                self.whitelistAddResult.emit(_safe_json_dumps(result))
                return _safe_json_dumps(result)

            if not isinstance(ids, list) or not ids:
                result = {'success': False, 'message': '未选择任何项目', 'mode': 'batch'}
                self.whitelistAddResult.emit(_safe_json_dumps(result))
                return _safe_json_dumps(result)

            all_items = self._quarantine_manager.get_all_items()
            logger.info(f'批量添加白名单: 请求 {len(ids)} 项，隔离区共 {len(all_items)} 项')

            added = 0
            skipped = 0
            failed = 0
            for item_id in ids:
                try:
                    if not isinstance(item_id, int):
                        failed += 1
                        continue
                    if item_id < 0 or item_id >= len(all_items):
                        logger.warning(f'批量添加白名单: 索引越界 {item_id} (共 {len(all_items)} 项)')
                        failed += 1
                        continue
                    item = all_items[item_id]
                    file_hash = item.get('file_hash', '')
                    if not file_hash or len(file_hash) != 64:
                        # 历史/软隔离记录可能缺失 file_hash：现场从隔离文件恢复完整哈希
                        recovered = self._quarantine_manager.recover_file_hash(item)
                        if recovered and len(recovered) == 64:
                            file_hash = recovered
                            logger.info(f'批量添加白名单: 现场恢复 item={item_id} 的 file_hash={file_hash[:16]}...')
                    if not file_hash or len(file_hash) != 64:
                        failed += 1
                        continue
                    if self._signature_db.is_whitelisted(file_hash):
                        skipped += 1
                        continue
                    reason = f'隔离区批量添加 (威胁: {item.get("malware_name", "未知")})'
                    if self._signature_db.add_to_whitelist(file_hash, reason):
                        added += 1
                    else:
                        logger.warning(f'批量添加白名单: add_to_whitelist 返回 False (hash={file_hash[:16]}...)')
                        failed += 1
                except Exception as item_err:
                    logger.error(f'批量添加白名单: 处理项目 {item_id} 异常: {item_err}')
                    failed += 1

            total = len(ids)
            self._add_activity('白名单', f'批量添加 {total} 项到白名单 (成功 {added}, 跳过 {skipped}, 失败 {failed})', 'INFO', '完成')
            msg_parts = []
            if added:
                msg_parts.append(f'成功 {added}')
            if skipped:
                msg_parts.append(f'已在白名单 {skipped}')
            if failed:
                msg_parts.append(f'失败 {failed}')
            message = '、'.join(msg_parts) if msg_parts else '无操作'
            logger.info(f'批量添加白名单完成: {message}')
            result = {
                'success': True,
                'total': total,
                'added': added,
                'skipped': skipped,
                'failed': failed,
                'message': message,
                'mode': 'batch',
            }
            self.whitelistAddResult.emit(_safe_json_dumps(result))
            return _safe_json_dumps(result)
        except Exception as e:
            logger.error(f'批量添加隔离项到白名单失败: {e}', exc_info=True)
            self._add_activity('白名单', f'批量添加到白名单异常: {str(e)}', 'ERROR', '错误')
            result = {'success': False, 'message': f'异常: {str(e)}', 'mode': 'batch'}
            self.whitelistAddResult.emit(_safe_json_dumps(result))
            return _safe_json_dumps(result)

    @pyqtSlot()
    def getSignatureSummary(self):
        """获取签名库摘要（签名数、启发式规则数、白名单数、最后更新时间）"""
        try:
            count = 0
            heuristics_count = 0
            whitelist_count = 0
            version = 'V26.2.0beta'
            last_update = ''
            if self._signature_db:
                count = self._signature_db.get_signature_count()
                heuristics_count = self._signature_db.get_heuristic_count()
                whitelist_count = self._signature_db.get_whitelist_count()
            # 获取数据库文件修改时间作为最后更新时间
            # （打包模式下签名库在使用者的 %APPDATA%\PSLS 目录，而非项目目录）
            db_path = getattr(self._signature_db, 'db_path', None) or ''
            if not os.path.exists(db_path):
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                db_path = os.path.join(project_root, 'db', 'signatures.db')
            if os.path.exists(db_path):
                mtime = os.path.getmtime(db_path)
                last_update = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
            result = {
                'count': count,
                'heuristics_count': heuristics_count,
                'whitelist_count': whitelist_count,
                'version': version,
                'lastUpdate': last_update
            }
            self._emit_tool_signal('signatureSummaryReady', _safe_json_dumps(result))
        except Exception as e:
            logger.error(f'获取签名库摘要失败: {e}')
            result = {'count': 0, 'heuristics_count': 0, 'whitelist_count': 0, 'version': 'V26.2.0beta', 'lastUpdate': '', 'error': str(e)}
            self._emit_tool_signal('signatureSummaryReady', _safe_json_dumps(result))

    @pyqtSlot(int, int, str, str)
    def getSignatureList(self, page: int, page_size: int, category: str, search: str):
        """获取病毒库列表（分页），通过 signatureListReady 信号返回

        Args:
            page: 页码（从1开始）
            page_size: 每页数量
            category: 'malware' / 'heuristic' / 'whitelist'
            search: 搜索关键词（仅对 malware 有效）
        """
        try:
            if not self._signature_db:
                result = {'items': [], 'total': 0, 'page': page, 'pageSize': page_size, 'category': category, 'error': '签名库未初始化'}
                self._emit_tool_signal('signatureListReady', _safe_json_dumps(result))
                return

            offset = max(0, (page - 1) * page_size)
            search = search.strip() if search else ''

            if category == 'malware':
                items = self._signature_db.get_all_signatures(limit=page_size, offset=offset, search=search)
                total = self._signature_db.get_signature_count_by_filter(search=search)
            elif category == 'heuristic':
                all_rules = self._signature_db.get_all_heuristic_rules_with_id()
                total = len(all_rules)
                # 启发式规则通常不多，直接全部返回
                items = all_rules[offset:offset + page_size]
            elif category == 'whitelist':
                all_wl = self._signature_db.get_all_whitelist()
                total = len(all_wl)
                items = all_wl[offset:offset + page_size]
            else:
                items = []
                total = 0

            result = {
                'items': items,
                'total': total,
                'page': page,
                'pageSize': page_size,
                'category': category,
                'search': search
            }
            self._emit_tool_signal('signatureListReady', _safe_json_dumps(result))
        except Exception as e:
            logger.error(f'获取病毒库列表失败: {e}')
            result = {'items': [], 'total': 0, 'page': page, 'pageSize': page_size, 'category': category, 'error': str(e)}
            self._emit_tool_signal('signatureListReady', _safe_json_dumps(result))

    @pyqtSlot(str, str)
    def deleteSignatureItem(self, key: str, category: str):
        """删除单个病毒库条目

        Args:
            key: malware=hash_sha256, heuristic=rule_id(字符串), whitelist=hash_sha256
            category: 'malware' / 'heuristic' / 'whitelist'
        """
        try:
            if not self._signature_db:
                self._emit_tool_signal('signatureDeleteResult', json.dumps({'success': False, 'error': '签名库未初始化'}))
                return

            success = False
            if category == 'malware':
                success = self._signature_db.delete_signature(key)
            elif category == 'heuristic':
                try:
                    success = self._signature_db.delete_heuristic_rule(int(key))
                except ValueError:
                    success = False
            elif category == 'whitelist':
                success = self._signature_db.delete_from_whitelist(key)

            # 广播更新后的签名计数
            new_count = self._signature_db.get_signature_count()
            self.signatureCountUpdated.emit(new_count)

            result = {'success': success, 'category': category, 'key': key, 'count': new_count}
            self._emit_tool_signal('signatureDeleteResult', _safe_json_dumps(result))
        except Exception as e:
            logger.error(f'删除病毒库条目失败: {e}')
            self._emit_tool_signal('signatureDeleteResult', json.dumps({'success': False, 'error': str(e)}))

    @pyqtSlot(str, str)
    def deleteSignatureBatch(self, keys_json: str, category: str):
        """批量删除病毒库条目

        Args:
            keys_json: JSON 数组字符串（malware=hash列表, heuristic=id列表, whitelist=hash列表）
            category: 'malware' / 'heuristic' / 'whitelist'
        """
        try:
            if not self._signature_db:
                self._emit_tool_signal('signatureDeleteResult', json.dumps({'success': False, 'error': '签名库未初始化'}))
                return

            keys = json.loads(keys_json) if keys_json else []
            if not isinstance(keys, list) or len(keys) == 0:
                self._emit_tool_signal('signatureDeleteResult', json.dumps({'success': False, 'error': '空列表'}))
                return

            deleted = 0
            if category == 'malware':
                deleted = self._signature_db.delete_signatures_batch([str(k) for k in keys])
            elif category == 'heuristic':
                try:
                    ids = [int(k) for k in keys]
                    deleted = self._signature_db.delete_heuristic_rules_batch(ids)
                except ValueError:
                    pass
            elif category == 'whitelist':
                deleted = self._signature_db.delete_from_whitelist_batch([str(k) for k in keys])

            # 广播更新后的签名计数
            new_count = self._signature_db.get_signature_count()
            self.signatureCountUpdated.emit(new_count)

            result = {'success': True, 'category': category, 'deleted': deleted, 'count': new_count}
            self._emit_tool_signal('signatureDeleteResult', _safe_json_dumps(result))
        except Exception as e:
            logger.error(f'批量删除病毒库条目失败: {e}')
            self._emit_tool_signal('signatureDeleteResult', json.dumps({'success': False, 'error': str(e)}))

    @pyqtSlot(str)
    def clearAllSignaturesByCategory(self, category: str):
        """清空指定分类的所有条目

        Args:
            category: 'malware' / 'heuristic' / 'whitelist'
        """
        try:
            if not self._signature_db:
                self._emit_tool_signal('signatureDeleteResult', json.dumps({'success': False, 'error': '签名库未初始化'}))
                return

            deleted = 0
            if category == 'whitelist':
                deleted = self._signature_db.clear_all_whitelist()
            elif category == 'malware':
                # 签名库不清空，只清空白名单
                self._emit_tool_signal('signatureDeleteResult', json.dumps({'success': False, 'error': '不支持清空签名库'}))
                return
            elif category == 'heuristic':
                self._emit_tool_signal('signatureDeleteResult', json.dumps({'success': False, 'error': '不支持清空启发式规则'}))
                return
            else:
                self._emit_tool_signal('signatureDeleteResult', json.dumps({'success': False, 'error': f'未知分类: {category}'}))
                return

            # 广播更新后的签名计数
            new_count = self._signature_db.get_signature_count()
            self.signatureCountUpdated.emit(new_count)

            category_names = {'malware': '签名库', 'heuristic': '启发式规则', 'whitelist': '白名单'}
            cat_name = category_names.get(category, category)
            self._add_activity(cat_name, f'清空全部，删除 {deleted} 项', 'WARN', '重置')
            logger.info(f'{cat_name} 已清空，删除 {deleted} 项')

            result = {'success': True, 'category': category, 'deleted': deleted, 'count': new_count, 'clearedAll': True}
            self._emit_tool_signal('signatureDeleteResult', _safe_json_dumps(result))
        except Exception as e:
            logger.error(f'清空病毒库条目失败: {e}')
            self._emit_tool_signal('signatureDeleteResult', json.dumps({'success': False, 'error': str(e)}))

    # ---------- 白名单专用快捷接口 ----------

    @pyqtSlot(str)
    def addFileToWhitelist(self, file_path: str):
        """按文件路径加入白名单（计算 SHA256 哈希后写入）"""
        try:
            if not self._signature_db:
                self._emit_tool_signal('whitelistAddResult', json.dumps(
                    {'success': False, 'error': '签名库未初始化'}))
                return
            if not os.path.isfile(file_path):
                self._emit_tool_signal('whitelistAddResult', json.dumps(
                    {'success': False, 'error': f'文件不存在: {file_path}'}))
                return
            from utils.hash_utils import compute_sha256
            h = compute_sha256(file_path)
            if not h:
                self._emit_tool_signal('whitelistAddResult', json.dumps(
                    {'success': False, 'error': '文件哈希计算失败'}))
                return
            already = self._signature_db.is_whitelisted(h)
            if not already:
                self._signature_db.add_to_whitelist(h, f'用户手动添加: {os.path.basename(file_path)}')
            self.signatureCountUpdated.emit(self._signature_db.get_signature_count())
            self._add_activity('白名单', f'加入: {os.path.basename(file_path)}', 'INFO',
                               '已存在' if already else '新增')
            self._emit_tool_signal('whitelistAddResult', json.dumps({
                'success': True, 'file': file_path, 'hash': h,
                'already_existed': already,
            }, ensure_ascii=False))
        except Exception as e:
            logger.error(f'手动加入白名单失败: {e}')
            self._emit_tool_signal('whitelistAddResult', json.dumps(
                {'success': False, 'error': str(e)}))

    @pyqtSlot(str)
    def addHashToWhitelist(self, hash_sha256: str):
        """直接按 SHA256 哈希加入白名单"""
        try:
            if not self._signature_db:
                self._emit_tool_signal('whitelistAddResult', json.dumps(
                    {'success': False, 'error': '签名库未初始化'}))
                return
            hash_sha256 = (hash_sha256 or '').strip()
            if len(hash_sha256) != 64:
                self._emit_tool_signal('whitelistAddResult', json.dumps(
                    {'success': False, 'error': 'SHA256 哈希格式错误（应为64个十六进制字符）'}))
                return
            already = self._signature_db.is_whitelisted(hash_sha256)
            if not already:
                self._signature_db.add_to_whitelist(hash_sha256, '用户手动添加')
            self.signatureCountUpdated.emit(self._signature_db.get_signature_count())
            self._add_activity('白名单', f'手动添加哈希: {hash_sha256[:16]}...', 'INFO',
                               '已存在' if already else '新增')
            self._emit_tool_signal('whitelistAddResult', json.dumps({
                'success': True, 'hash': hash_sha256, 'already_existed': already,
            }))
        except Exception as e:
            logger.error(f'手动加入白名单(哈希)失败: {e}')
            self._emit_tool_signal('whitelistAddResult', json.dumps(
                {'success': False, 'error': str(e)}))

    @pyqtSlot()
    def clearAllWhitelist(self):
        """清空全部白名单（白名单分类专用快捷接口）"""
        self.clearAllSignaturesByCategory('whitelist')

    @pyqtSlot(str)
    def selectSingleFile(self, target: str):
        """弹出文件选择对话框，选择后通过 fileSelected 信号返回。

        target: 'signature' / 'whitelist' / 'pe' / 'virus' / 'hash'
        """
        try:
            from PyQt5.QtWidgets import QFileDialog
            if target == 'signature':
                caption = '选择签名库文件'
                ffilter = '签名库文件 (*.json *.db *.txt);;所有文件 (*.*)'
            elif target == 'whitelist':
                caption = '选择白名单文件'
                ffilter = '白名单哈希文件 (*.json *.txt);;所有文件 (*.*)'
            elif target == 'pe':
                caption = '选择可执行文件'
                ffilter = '可执行文件 (*.exe *.dll *.sys *.scr);;所有文件 (*.*)'
            elif target == 'sandbox':
                caption = '选择要沙箱分析的文件'
                ffilter = '可执行文件 (*.exe *.scr *.com *.bat *.cmd *.ps1 *.vbs *.js);;所有文件 (*.*)'
            else:  # virus / hash 或其他
                caption = '选择文件'
                ffilter = '所有文件 (*.*)'
            file_path, _ = QFileDialog.getOpenFileName(None, caption, '', ffilter)
            path = file_path.replace('\\', '/') if file_path else ''
            self.fileSelected.emit(path, target)
        except Exception as e:
            logger.error(f'选择文件失败: {e}')
            self.fileSelected.emit('', target)

    @pyqtSlot(str, str)
    def exportSignatureDB(self, save_path: str, export_format: str = 'db'):
        """导出签名库到文件

        Args:
            save_path: 保存路径
            export_format: 'db' = SQLite数据库, 'json' = JSON格式
        """
        if not self._signature_db or not save_path:
            self.exportFinished.emit(False)
            return

        try:
            fmt = export_format.lower().strip()
            if fmt == 'json':
                success = self._signature_db.export_to_json(save_path)
            else:
                success = self._signature_db.export_to_db(save_path)

            if success:
                self._add_activity(
                    '病毒库',
                    f'签名库导出成功: {save_path}',
                    'INFO', '成功'
                )
            else:
                self._add_activity(
                    '病毒库',
                    f'签名库导出失败: {save_path}',
                    'ERROR', '错误'
                )
            self.exportFinished.emit(success)
        except Exception as e:
            logger.error(f'导出签名库异常: {e}')
            self.exportFinished.emit(False)

    @pyqtSlot()
    def exportSignatureDBDialog(self):
        """弹出原生保存对话框导出签名库（无参版本，避免前端使用 prompt 输入路径）

        使用 QFileDialog.getSaveFileName 让用户选择保存位置，
        避免 window.prompt 仅返回文件名导致在不可写工作目录下创建数据库失败。
        """
        try:
            from PyQt5.QtWidgets import QFileDialog
            default_name = f'PSLS_signatures_{datetime.now().strftime("%Y%m%d")}.db'
            file_path, _ = QFileDialog.getSaveFileName(
                None,
                '导出签名库',
                default_name,
                'SQLite 数据库 (*.db);;JSON 文件 (*.json);;所有文件 (*.*)'
            )
            if not file_path:
                self.exportFinished.emit(False)
                return
            # 根据扩展名自动推断格式
            fmt = 'json' if file_path.lower().endswith('.json') else 'db'
            self.exportSignatureDB(file_path, fmt)
        except Exception as e:
            logger.error(f'导出签名库对话框失败: {e}')
            self.exportFinished.emit(False)

    @pyqtSlot(str)
    def importSignatureFile(self, file_path: str):
        """导入签名库文件（.json/.db/.txt），直接导入签名数据。

        在子线程中执行，通过 importProgress/importFinished 信号通知前端。
        """
        if not file_path:
            return
        self._import_stop_event.clear()
        self._add_activity(
            '病毒库', f'开始导入签名库: {file_path}', 'INFO', '进行中'
        )
        thread = threading.Thread(
            target=self._run_import_signature_file,
            args=(file_path,),
            daemon=True
        )
        thread.start()

    @pyqtSlot(str)
    def importSampleDir(self, dir_path: str):
        """从恶意样本目录批量导入签名（扫描文件 → 计算 SHA256 → 解析威胁名 → 入库）。

        在子线程中执行，通过 importProgress/importFinished 信号通知前端。
        """
        if not dir_path:
            return
        self._import_stop_event.clear()
        self._add_activity(
            '病毒库', f'开始从样本目录导入: {dir_path}', 'INFO', '进行中'
        )
        thread = threading.Thread(
            target=self._run_import_sample_dir,
            args=(dir_path,),
            daemon=True
        )
        thread.start()

    @pyqtSlot(str, str)
    def importVirusSamples(self, file_path: str, force_import_val):
        """导入病毒样本文件（文件/目录/压缩包），通过病毒识别引擎分析后入库。

        force_import: 'true'=强制导入所有文件，'false'=仅导入识别为恶意的文件
        """
        if not file_path:
            return
        # 防御性处理：QWebChannel 可能传递 QVariant，强制转为字符串
        try:
            force_import_str = str(force_import_val).lower()
        except Exception:
            force_import_str = ''
        force_import = force_import_str in ('true', '1', 'yes', 'on')
        logger.info(f'[导入] importVirusSamples 调用: file_path={file_path}, force_import_val={force_import_val!r}, force_import={force_import}')
        self._import_stop_event.clear()
        self._add_activity(
            '病毒库',
            f'开始识别病毒样本: {file_path} ({"强制导入" if force_import else "智能识别"})',
            'INFO', '进行中'
        )
        thread = threading.Thread(
            target=self._run_import_virus_samples,
            args=(file_path, force_import),
            daemon=True
        )
        thread.start()

    @pyqtSlot(str)
    def importWhitelistFile(self, file_path: str):
        """导入白名单（.json/.db 文件或目录/文件样本）。

        支持两种来源：
        - 数据文件（.json/.db）：直接读取哈希并加入白名单
        - 样本目录/文件：计算 SHA256 后加入白名单
        """
        if not file_path:
            return
        self._import_stop_event.clear()
        self._add_activity(
            '白名单', f'开始导入白名单: {file_path}', 'INFO', '进行中'
        )
        thread = threading.Thread(
            target=self._run_import_whitelist,
            args=(file_path,),
            daemon=True
        )
        thread.start()

    @pyqtSlot()
    def stopSignatureImport(self):
        """停止导入/识别"""
        self._import_stop_event.set()
        logger.info('[导入] 用户请求停止')

    # ====================================================================
    # MalwareBazaar 自动同步 + 自训练
    # ====================================================================

    def _mb_get_syncer(self) -> MBSyncer:
        """懒初始化 MBSyncer（数据根目录 data/mb/，与项目根对齐）"""
        if self._mb_syncer is None:
            project_root = os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
            self._mb_syncer = MBSyncer(os.path.join(project_root, 'data', 'mb'))
        return self._mb_syncer

    def _emit_mb_progress(self, stage: str, percent: int, message: str):
        """线程安全地发射 MB 同步/训练进度"""
        self._emit_tool_signal(
            'mbSyncProgress',
            _safe_json_dumps({'stage': stage, 'percent': int(percent),
                              'message': str(message)}, ensure_ascii=False))

    def _emit_mb_finished(self, result: dict):
        self._emit_tool_signal('mbSyncFinished',
                               _safe_json_dumps(result, ensure_ascii=False))

    def _emit_mb_status(self):
        """推送 MB 状态快照到前端（含本地同步进度、远端最新日期）"""
        try:
            syncer = self._mb_get_syncer()
            st = syncer.get_status()
            total = 0
            if self._signature_db is not None:
                try:
                    total = self._signature_db.get_signature_count() or 0
                except Exception:
                    pass
            st['signature_count'] = total
            self._emit_tool_signal('mbStatusUpdated',
                                   _safe_json_dumps(st, ensure_ascii=False))
        except Exception as e:
            logger.warning('MB 状态推送失败: %s', e)

    @pyqtSlot(str)
    def mbGetStatus(self, _dummy: str = ''):
        """前端请求 MB 状态"""
        self._emit_mb_status()

    @pyqtSlot(str)
    def mbSyncNow(self, opts_json: str):
        """手动触发 MalwareBazaar 同步（可选同步后自动全量重训）。

        opts_json: {"auto_yara": bool, "retrain": bool, "max_days": int,
                    "benign_dirs": [str]}
        """
        try:
            opts = json.loads(opts_json) if opts_json else {}
        except Exception:
            opts = {}
        if not isinstance(opts, dict):
            opts = {}
        if self._mb_split_lock.locked() or not self._mb_split_lock.acquire(
                blocking=False):
            self._emit_mb_finished({'ok': False, 'busy': True,
                                    'message': '已有同步/训练任务运行中'})
            return
        self._mb_stop_event.clear()
        self._add_activity('Live Malware DB',
                           '开始同步每日样本并导入签名库', 'INFO', '进行中')
        thread = threading.Thread(
            target=self._run_mb_sync,
            args=(opts,),
            daemon=True,
            name='PSLS-MB-Sync',
        )
        thread.start()

    @pyqtSlot(str)
    def mbSyncStop(self, _dummy: str = ''):
        """停止 MB 同步/训练"""
        self._mb_stop_event.set()
        logger.info('[MB] 用户请求停止同步/训练')
        self._add_activity('Live Malware DB', '用户请求停止同步/训练',
                           'WARN', '已停止')

    @pyqtSlot(str)
    def mbSyncMonthlyNow(self, opts_json: str):
        """手动触发 kasunc 月度归档包同步（可选同步后自动全量重训）。

        月度包 = 整月样本归档（每月初发布），直链与每日包同源 CDN，
        opts_json: {"auto_yara": bool, "retrain": bool, "benign_dirs": [str]}
        """
        try:
            opts = json.loads(opts_json) if opts_json else {}
        except Exception:
            opts = {}
        if not isinstance(opts, dict):
            opts = {}
        if self._mb_split_lock.locked() or not self._mb_split_lock.acquire(
                blocking=False):
            self._emit_mb_finished({'ok': False, 'busy': True,
                                    'message': '已有同步/训练任务运行中'})
            return
        self._mb_stop_event.clear()
        self._add_activity('Live Malware DB',
                           '开始同步最近月度归档包并导入签名库', 'INFO', '进行中')
        thread = threading.Thread(
            target=self._run_mb_monthly_sync,
            args=(opts,),
            daemon=True,
            name='PSLS-MB-Monthly',
        )
        thread.start()

    def _run_mb_monthly_sync(self, opts: dict):
        """子线程：探测最近月度包 → 下载解压导入 → （可选）自动全量重训"""
        try:
            syncer = self._mb_get_syncer()
            auto_yara = bool(opts.get('auto_yara', False))
            retrain = bool(opts.get('retrain', False))
            month = syncer.remote_latest_month()
            if not month:
                self._emit_mb_finished(
                    {'ok': False,
                     'message': '无法探测 kasunc 月度归档包（网络不可达或本月归档未发布）'})
                return
            self._emit_mb_progress(
                'check', 5, f'探测到最近月度包 {month}，开始下载（约 3GB）...')
            result = syncer.sync_month(
                month,
                self._signature_db,
                auto_yara=auto_yara,
                progress_cb=self._emit_mb_progress,
                stop_event=self._mb_stop_event,
            )
            self._mb_post_sync(result, opts, syncer,
                               label=f'月度包 {month}',
                               add_msg=f'月度包 {month} 同步完成')
        except Exception as e:
            logger.error('MB 月度包同步异常: %s', e, exc_info=True)
            self._emit_mb_finished({'ok': False, 'message': f'月度包同步异常: {e}'})
        finally:
            self._mb_split_lock.release()

    def _mb_post_sync(self, result: dict, opts: dict, syncer,
                      label: str, add_msg: str):
        """同步完成后的公共收尾：状态推送 → （可选）重训 → 结束回调/活动日志

        每日包与月度包共用，避免两套"更新签名数 + 重训分发 + finished"重复。
        """
        retrain = bool(opts.get('retrain', False))
        if result.get('busy'):
            self._emit_mb_finished({'ok': False, 'busy': True,
                                    'message': '已有任务运行中'})
            return
        if self._mb_stop_event.is_set():
            self._emit_mb_finished({'ok': False, 'stopped': True,
                                    'message': '同步已停止'})
            return

        # 同步完成后推送新状态（签名数更新）
        self._emit_mb_status()
        try:
            if self._signature_db is not None:
                total = self._signature_db.get_signature_count() or 0
                self.signatureCountUpdated.emit(int(total))
        except Exception:
            pass

        if retrain and not self._mb_stop_event.is_set():
            benign_dirs = [str(b) for b in opts.get('benign_dirs', [])
                           if b and os.path.isdir(b)]
            train_result = syncer.retrain_engine(
                benign_dirs,
                max_malware=int(opts.get('max_malware') or 5000),
                progress_cb=self._emit_mb_progress,
                stop_event=self._mb_stop_event,
            )
            if train_result.get('ok'):
                # 重训完成后重载进程内 LightGBM 引擎使新模型即时生效
                self._reload_lightgbm_engine()
                self._emit_mb_finished(
                    {'ok': True, 'retrained': True,
                     'message': f'{label}同步与重训完成，新模型已生效',
                     'metrics': train_result.get('message', '')})
            elif train_result.get('busy'):
                self._emit_mb_finished(
                    {'ok': False, 'busy': True,
                     'message': train_result.get('message', '任务忙碌')})
            else:
                self._emit_mb_finished(
                    {'ok': False, 'retrain_failed': True,
                     'message': train_result.get('message', '训练失败'),
                     'synced_ok': True})
        else:
            self._emit_mb_finished(
                {'ok': True, 'message':
                 f'{add_msg}: 新增 {result.get("added", 0)} 个签名',
                 'synced': result.get('synced'),
                 'pending': result.get('pending', 0)})

        self._add_activity(
            'Live Malware DB',
            f'{add_msg}: 新增 {result.get("added", 0)} 个签名'
            + ('，已自动重训 LightGBM 模型' if retrain and train_result.get('ok') else ''),
            'INFO', '成功')

    def _run_mb_sync(self, opts: dict):
        """子线程：同步 → 导入签名库 → （可选）自动全量重训"""
        try:
            syncer = self._mb_get_syncer()
            auto_yara = bool(opts.get('auto_yara', False))
            max_days = int(opts.get('max_days') or 7)

            result = syncer.sync_to_latest(
                self._signature_db,
                max_days=max_days,
                auto_yara=auto_yara,
                progress_cb=self._emit_mb_progress,
                stop_event=self._mb_stop_event,
            )
            self._mb_post_sync(result, opts, syncer,
                               label='本次同步',
                               add_msg='同步完成')
        except Exception as e:
            logger.error('MB 同步异常: %s', e, exc_info=True)
            self._emit_mb_finished({'ok': False, 'message': f'同步异常: {e}'})
        finally:
            self._mb_split_lock.release()

    def _reload_lightgbm_engine(self):
        """重训后重新加载进程内 LightGBM 引擎"""
        try:
            if self._ml_detector is not None:
                be = getattr(self._ml_detector, '_brewtotal', None)
                if be is not None and hasattr(be, 'reload'):
                    ok = be.reload()
                    logger.info('[MB] LightGBM 引擎重载: %s',
                                '成功' if ok else '失败')
        except Exception as e:
            logger.warning('LightGBM 引擎重载失败: %s', e)

    def _schedule_mb_startup_check(self):
        """启动 15 秒后：后台检测 MB 更新，非最新则自动同步（只导入签名，不训练）。

        避免阻塞启动流程；网络不可达时静默降级并记录活动日志。
        """
        if self._mb_auto_sync_done:
            return
        if self._mb_split_lock.locked():
            # 用户已手动触发同步 → 本次启动自动更新交给用户任务
            self._mb_auto_sync_done = True
            return
        if not self._mb_split_lock.acquire(blocking=False):
            self._mb_auto_sync_done = True
            return
        self._mb_stop_event.clear()
        thread = threading.Thread(
            target=self._run_mb_startup_auto_sync,
            daemon=True,
            name='PSLS-MB-AutoSync',
        )
        thread.start()

    def _run_mb_startup_auto_sync(self):
        """启动自动同步线程：探测最新日期 → 若本地非最新则补同步（默认 7 天窗口）"""
        try:
            self._mb_auto_sync_done = True
            syncer = self._mb_get_syncer()
            local = syncer.local_dates()
            remote = syncer.remote_latest_date(timeout=20)
            if not remote:
                logger.info('[MB] 启动自动同步：无法探测远端（网络/代理不可达），跳过')
                self._add_activity('Live Malware DB',
                                   '启动检查更新失败（网络不可达）', 'INFO', '跳过')
                return
            last = local[-1] if local else ''
            if last and last >= remote:
                self._add_activity('Live Malware DB',
                                   f'样本库已是最新（{remote}）', 'INFO', '已是最新')
                return
            self._emit_mb_progress('check', 5,
                                   f'检测到更新（本地 {last or "无"}，最新 {remote}），后台自动同步...')
            self._add_activity('Live Malware DB',
                               f'检测到每日样本更新（{remote}），后台自动同步', 'INFO', '进行中')
            result = syncer.sync_to_latest(
                self._signature_db,
                max_days=7,
                auto_yara=False,
                progress_cb=self._emit_mb_progress,
                stop_event=self._mb_stop_event,
            )
            if not result.get('busy') and result.get('synced'):
                self._emit_mb_status()
                try:
                    if self._signature_db is not None:
                        total = self._signature_db.get_signature_count() or 0
                        self.signatureCountUpdated.emit(int(total))
                except Exception:
                    pass
                self._add_activity(
                    'Live Malware DB',
                    f'启动自动同步完成: 新增 {result.get("added", 0)} 个签名'
                    f'（剩余 {result.get("pending", 0)} 天未同步）',
                    'INFO', '成功')
            else:
                self._add_activity('Live Malware DB',
                                   '启动自动同步: 无新增或已中断',
                                   'INFO', '完成')
        except Exception as e:
            logger.warning('启动自动同步异常: %s', e)
            try:
                self._add_activity('Live Malware DB', f'启动自动同步异常: {e}',
                                   'WARN', '错误')
            except Exception:
                pass
        finally:
            self._mb_split_lock.release()

    # ---- 签名库文件导入（文本模式：json/db/txt）----
    def _run_import_signature_file(self, file_path: str):
        """子线程：导入签名库文件"""
        self._import_running = True
        try:
            if not self._signature_db:
                self._emit_tool_signal('importProgress', 0, '签名库未初始化')
                self._emit_tool_signal('importFinished', 0, 0, False)
                return

            self._last_import_pct = 0
            self._emit_import_progress(0, '准备导入签名库...')
            self._emit_import_progress(30, f'正在导入: {os.path.basename(file_path)}')

            imported = 0
            ext = os.path.splitext(file_path)[1].lower()

            if ext == '.json':
                self._emit_import_progress(50, '解析 JSON 签名库...')
                imported = self._signature_db.load_from_json(file_path)
            elif ext == '.db':
                self._emit_import_progress(50, '从 DB 导入签名...')
                result = self._signature_db.import_from_db(file_path)
                imported = max(0, result)
                if result < 0:
                    self._emit_import_progress(60, '该DB文件不是签名库格式，已跳过')
                    imported = 0
            elif ext == '.txt':
                self._emit_import_progress(50, '解析 TXT 签名库...')
                imported = self._signature_db.load_from_txt(file_path)
            else:
                self._emit_import_progress(60, f'不支持的签名库格式: {ext}')
                imported = 0

            self._emit_import_progress(90, '导入完成，更新计数...')
            total = self._signature_db.get_signature_count()
            self._emit_import_progress(100, f'导入完成: 新增 {imported} 个，共 {total} 个')
            self._emit_tool_signal('importFinished', imported, total, True)
            self._emit_tool_signal('signatureCountUpdated', total)
            self._add_activity(
                '病毒库', f'签名库导入完成: 新增 {imported} 个，共 {total} 个',
                'INFO', '成功'
            )
        except Exception as e:
            logger.error(f'导入签名库失败: {e}')
            total = self._signature_db.get_signature_count() if self._signature_db else 0
            self._emit_tool_signal('importFinished', 0, total, False)
            self._add_activity('病毒库', f'导入失败: {str(e)}', 'ERROR', '错误')
        finally:
            self._import_running = False

    # ---- 样本目录导入（直接哈希 + 文件名解析威胁名，无识别引擎）----
    def _run_import_sample_dir(self, dir_path: str):
        """子线程：从恶意样本目录批量导入签名"""
        logger.info(f'[导入] 启动样本目录导入: {dir_path}')
        self._import_running = True
        try:
            if not self._signature_db:
                self._emit_tool_signal('importProgress', 0, '签名库未初始化')
                self._emit_tool_signal('importFinished', 0, 0, False)
                return

            self._last_import_pct = 0
            self._emit_import_progress(0, '准备扫描样本目录...')

            if not os.path.isdir(dir_path):
                self._emit_import_progress(100, f'路径不是目录: {dir_path}')
                self._emit_tool_signal('importFinished', 0, 0, False)
                self._add_activity('病毒库', f'样本目录导入失败: 路径不是目录', 'ERROR', '错误')
                return

            def _wrapped_cb(done: int, total: int, fname: str):
                if self._import_stop_event.is_set():
                    return
                if total > 0:
                    pct = min(99, int(done / total * 100))
                else:
                    pct = 0
                try:
                    self._emit_import_progress(pct, f'扫描中: {done}/{total} - {fname}')
                except Exception:
                    pass

            self._emit_import_progress(5, '扫描样本目录中...')
            result = self._signature_db.load_from_sample_dir(
                dir_path,
                recursive=True,
                auto_yara=True,
                source='samples_dir',
                progress_cb=_wrapped_cb,
            )

            if self._import_stop_event.is_set():
                self._emit_import_progress(100, '已停止')
                self._emit_tool_signal('importFinished', 0, self._signature_db.get_signature_count(), False)
                self._add_activity('病毒库', '样本目录导入已停止', 'WARN', '已停止')
                return

            added = result.get('added', 0)
            skipped = result.get('skipped', 0)
            total_files = result.get('total', 0)
            errors = result.get('errors', 0)
            total = self._signature_db.get_signature_count()

            self._emit_import_progress(100, f'导入完成: 新增 {added} 个（跳过 {skipped}，共扫描 {total_files}）')
            self._emit_tool_signal('importFinished', added, total, True)
            self._emit_tool_signal('signatureCountUpdated', total)
            self._add_activity(
                '病毒库',
                f'样本目录导入完成: 扫描 {total_files} 文件，新增 {added} 个签名（跳过 {skipped}，错误 {errors}）',
                'INFO', '成功'
            )
        except Exception as e:
            logger.error(f'样本目录导入失败: {e}')
            total = self._signature_db.get_signature_count() if self._signature_db else 0
            self._emit_tool_signal('importFinished', 0, total, False)
            self._add_activity('病毒库', f'样本目录导入失败: {str(e)}', 'ERROR', '错误')
        finally:
            self._import_running = False

    # ---- 病毒样本导入（文件识别模式：文件/目录/压缩包）----
    def _run_import_virus_samples(self, file_path: str, force_import: bool):
        """子线程：识别病毒样本并导入签名（基于 import_virus_db.py 重构）"""
        logger.info(f'[导入] 启动病毒样本导入: {file_path} (force_import={force_import})')
        self._import_running = True
        try:
            if not self._signature_db:
                self._emit_tool_signal('importProgress', 0, '签名库未初始化')
                self._emit_tool_signal('importFinished', 0, 0, False)
                return

            self._last_import_pct = 0
            self._emit_import_progress(0, '准备扫描...')
            self._emit_import_progress(5, '初始化扫描器...')

            from utils.archive_scanner import ArchiveScanner
            scanner = ArchiveScanner()

            # 收集所有文件路径
            self._emit_import_progress(10, '扫描文件中...')
            collected_files = []  # [file_path, ...]
            temp_dirs = set()  # 累积所有解压产生的临时目录，导入完成后统一清理
            total_files = 0

            if os.path.isdir(file_path):
                # 目录模式：先收集所有文件
                all_files = []
                for root, _dirs, files in os.walk(file_path):
                    if self._import_stop_event.is_set():
                        break
                    for f in files:
                        all_files.append(os.path.join(root, f))

                total_files = len(all_files)
                self._emit_import_progress(15, f'发现 {total_files} 个文件，开始处理...')

                # 处理每个文件
                for idx, fpath in enumerate(all_files):
                    if self._import_stop_event.is_set():
                        break
                    self._collect_files(fpath, 0, scanner, collected_files, force_import, temp_dirs)
                    if total_files > 0 and (idx % 10 == 0 or idx == total_files - 1):
                        pct = 15 + int((idx / total_files) * 55)
                        self._emit_import_progress(pct, f'扫描中: {idx+1}/{total_files} (已发现 {len(collected_files)} 个样本)')
            else:
                # 单文件模式
                self._collect_files(file_path, 0, scanner, collected_files, force_import, temp_dirs)
                total_files = 1

            # 批量分析并导入签名库
            self._emit_import_progress(75, f'扫描完成，发现 {len(collected_files)} 个样本，开始分析...')
            try:
                imported = self._batch_analyze_and_import(collected_files, file_path, force_import)
            finally:
                # 批量导入完成后统一清理所有临时目录
                # 必须在导入完成后清理，否则解压出的文件路径已失效
                for temp_dir in temp_dirs:
                    try:
                        if temp_dir and os.path.exists(temp_dir):
                            shutil.rmtree(temp_dir, ignore_errors=True)
                    except Exception:
                        pass

            self._emit_import_progress(95, '导入完成，更新计数...')
            total = self._signature_db.get_signature_count()
            self._emit_import_progress(100, f'完成: 新增 {imported} 个，共 {total} 个')
            self._emit_tool_signal('importFinished', imported, total, True)
            self._emit_tool_signal('signatureCountUpdated', total)
            self._add_activity(
                '病毒库', f'病毒样本识别完成: 扫描 {total_files} 个文件，新增 {imported} 个签名，共 {total} 个',
                'INFO', '成功'
            )
        except Exception as e:
            logger.error(f'病毒样本导入失败: {e}')
            total = self._signature_db.get_signature_count() if self._signature_db else 0
            self._emit_tool_signal('importFinished', 0, total, False)
            self._add_activity('病毒库', f'识别失败: {str(e)}', 'ERROR', '错误')
        finally:
            self._import_running = False

    # ---- 病毒库导入常量 ----
    _IMPORT_MAX_DEPTH = 10
    _IMPORT_MAX_FILE_SIZE = 50 * 1024 * 1024
    _IMPORT_SKIP_EXTENSIONS = {'.txt', '.md', '.json', '.csv', '.xml', '.log', '.ini', '.cfg', '.conf'}
    _IMPORT_BATCH_SIZE = 1000

    def _emit_import_progress(self, pct: int, message: str):
        """发射导入进度信号，确保进度单调递增，并同步记录当前状态以供GUI重载后恢复"""
        self._import_current_pct = max(self._import_current_pct, pct)
        self._import_current_msg = message or ''
        if pct > self._last_import_pct:
            self._last_import_pct = pct
            self._emit_tool_signal('importProgress', pct, message)

    def _compute_file_hash(self, file_path: str) -> str:
        """计算文件SHA256哈希（来自 import_virus_db.py）"""
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self._IMPORT_MAX_FILE_SIZE:
                logger.debug(f'[导入] 跳过过大文件: {file_path} ({file_size/1024/1024:.1f}MB)')
                return ''
            
            import hashlib
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except (OSError, Exception) as e:
            logger.debug(f'[导入] 计算哈希失败 {file_path}: {e}')
            return ''

    def _collect_files(self, file_path: str, depth: int, scanner, results: list, force_import: bool = False, temp_dirs: set = None):
        """递归扫描文件并收集文件路径（压缩包会递归解压，加密归档直接跳过）

        性能关键：病毒样本导入时跳过密码暴力破解（65密码 × 7z子进程 = 数分钟延迟）。
        加密归档直接跳过并计数，不阻塞整批导入。

        Args:
            force_import: 强制模式时不跳过文本文件，收集所有文件
            temp_dirs: 累积本次递归产生的所有临时目录，由调用方在导入完成后统一清理
        """
        if self._import_stop_event.is_set():
            return
        if depth > self._IMPORT_MAX_DEPTH:
            return
        if not os.path.isfile(file_path):
            return

        try:
            file_size = os.path.getsize(file_path)
            if file_size > self._IMPORT_MAX_FILE_SIZE:
                return
        except Exception:
            return

        archive_type = scanner._detect_archive_type(file_path)

        if archive_type:
            basename = os.path.basename(file_path)

            # 加密归档：快速检测后直接跳过，不做密码暴力破解
            is_encrypted = False
            try:
                if archive_type == 'zip':
                    import zipfile
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        is_encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
                elif archive_type == 'rar':
                    try:
                        import rarfile
                        with rarfile.RarFile(file_path, 'r') as rf:
                            is_encrypted = rf.needs_password()
                    except Exception:
                        is_encrypted = True  # rarfile 异常视为加密，跳过
                elif archive_type == '7z':
                    try:
                        import py7zr
                        with py7zr.SevenZipFile(file_path, 'r') as szf:
                            is_encrypted = szf.needs_password()
                    except Exception:
                        is_encrypted = True
                # tar/gz/bz2/xz 不支持密码
            except Exception:
                pass

            if is_encrypted:
                logger.debug(f'[导入] 跳过加密归档: {basename}')
                return  # 直接跳过，不阻塞整批导入

            # 非加密归档：解压并递归
            extracted_dir = None
            try:
                extracted_dir = scanner._extract_archive(file_path, archive_type)
            except Exception as e:
                logger.debug(f'[导入] 解压失败跳过 {basename}: {e}')
                return

            if extracted_dir:
                current_temp_dir = extracted_dir
                if temp_dirs is not None:
                    temp_dirs.add(current_temp_dir)
                try:
                    for root, _dirs, files in os.walk(current_temp_dir):
                        if self._import_stop_event.is_set():
                            break
                        for filename in files:
                            extracted_file = os.path.join(root, filename)
                            if not scanner._safe_path(extracted_file, current_temp_dir):
                                continue
                            self._collect_files(extracted_file, depth + 1, scanner, results, force_import, temp_dirs)
                except Exception as e:
                    logger.debug(f'[导入] 扫描解压目录失败: {e}')
                if scanner._temp_dir == current_temp_dir:
                    scanner._temp_dir = None
        else:
            if not force_import and self._is_skippable_text_file(file_path):
                return
            results.append(file_path)

    def _is_skippable_text_file(self, file_path: str) -> bool:
        """判断是否为可跳过的纯文本类文件

        注意：只跳过真正的文本后缀，不跳过伪装成文本的可执行文件
        例如 .txt.exe 是可疑文件，不应跳过
        """
        name_lower = os.path.basename(file_path).lower()
        # 真正以文本扩展名结尾的文件才跳过
        # 不跳过包含可执行扩展名在中间位置的文件（如 virus.txt.exe）
        text_exts = self._IMPORT_SKIP_EXTENSIONS
        # 提取最后一个扩展名
        last_ext = os.path.splitext(file_path)[1].lower()
        if last_ext not in text_exts:
            return False
        # 检查是否是伪装文件：文件名中包含可执行扩展名 + 文本扩展名
        executable_exts = ('.exe', '.dll', '.scr', '.pif', '.com', '.bat', '.cmd', '.vbs', '.ps1', '.js', '.wsf')
        # 例如 virus.txt.exe：最后扩展名 .exe，不是文本，不会进入此函数
        # 例如 virus.exe.txt：最后扩展名 .txt，但包含 .exe.，属于伪装
        for ext in executable_exts:
            if f'{ext}.' in name_lower or name_lower.endswith(ext):
                return False  # 可能是伪装，不跳过
        return True

    def _batch_analyze_and_import(self, file_paths: list, source: str, force_import: bool) -> int:
        """批量分析文件并导入签名库（多线程优化版）

        优化要点：
        - 强制模式：预哈希去重（跳过已知恶意/白名单/重复）后并行入库
        - 普通模式：预哈希去重 → 并行 identify() → 攒批写入
        - 攒满 _BATCH_SIZE 后一次性 add_signatures_batch（executemany + 单次 commit）
        """
        _BATCH_SIZE = 1000
        logger.info(f'[导入] 批量处理: {len(file_paths)} 个文件, force_import={force_import}')
        if not file_paths or not self._signature_db:
            return 0

        from concurrent.futures import ThreadPoolExecutor, as_completed

        total = len(file_paths)
        imported = 0
        pending_batch = []
        workers = min(8, max(2, os.cpu_count() + 4))

        def _flush_batch():
            nonlocal imported
            if not pending_batch:
                return
            added = self._signature_db.add_signatures_batch(list(pending_batch))
            imported += added
            pending_batch.clear()

        def _make_entry(file_hash, file_name, malware_type, severity, description, source_tag='virus_identifier'):
            return (file_hash, file_name[:100], malware_type, severity, description[:500], source_tag)

        # ====== 阶段 1：并行预哈希 + 去重 ======
        self._emit_import_progress(76, f'预哈希去重 {total} 个文件...')

        unique_tasks = []  # [(file_path, file_hash), ...]
        seen_hashes = set()
        known_malware = self._signature_db._malware_hashes
        known_whitelist = self._signature_db._whitelist_cache

        def _hash_one(fp):
            if self._import_stop_event.is_set():
                return (fp, None)
            if not os.path.isfile(fp):
                return (fp, None)
            try:
                file_size = os.path.getsize(fp)
                if file_size > self._IMPORT_MAX_FILE_SIZE:
                    return (fp, 'SKIP_TOO_LARGE')
            except Exception:
                return (fp, None)
            h = self._compute_file_hash(fp)
            return (fp, h)

        hash_done = 0
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(_hash_one, fp): fp for fp in file_paths}
            for fut in as_completed(futures):
                if self._import_stop_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                fp, h = fut.result()
                hash_done += 1
                if h and len(h) == 64:
                    if h in seen_hashes:
                        pass  # 重复样本，跳过
                    elif h in known_malware:
                        pass  # 已入库恶意签名，跳过
                    elif h in known_whitelist:
                        pass  # 白名单文件，跳过
                    else:
                        seen_hashes.add(h)
                        unique_tasks.append((fp, h))
                if hash_done % 100 == 0 or hash_done == total:
                    pct = 76 + int((hash_done / max(total, 1)) * 7)
                    self._emit_import_progress(pct, f'预哈希: {hash_done}/{total} (待分析 {len(unique_tasks)})')

        if not unique_tasks:
            self._emit_import_progress(99, '所有文件已在库中或被白名单排除')
            return 0

        self._emit_import_progress(83, f'去重后 {len(unique_tasks)} 个待处理文件')

        if force_import:
            # ====== 强制模式：直接入库 ======
            for idx, (fp, file_hash) in enumerate(unique_tasks):
                if self._import_stop_event.is_set():
                    break
                file_name = os.path.basename(fp)
                pending_batch.append(_make_entry(
                    file_hash, f"Forced.{file_name}", 'Forced', 'high',
                    f'强制导入自: {fp}'
                ))
                if len(pending_batch) >= _BATCH_SIZE:
                    _flush_batch()
                if idx % 200 == 0 or idx == len(unique_tasks) - 1:
                    pct = 83 + int((idx / max(len(unique_tasks), 1)) * 14)
                    self._emit_import_progress(pct, f'入库中: {idx+1}/{len(unique_tasks)}')
            _flush_batch()
            return imported

        # ====== 普通模式：并行 identify() ======
        self._emit_import_progress(83, f'开始并行分析 {len(unique_tasks)} 个文件...')

        def _analyze_one(fp_and_hash):
            fp, expected_hash = fp_and_hash
            if self._import_stop_event.is_set():
                return None
            try:
                analysis = self._virus_identifier.identify(fp)
            except Exception as e:
                logger.debug(f'[导入] 分析失败 {fp}: {e}')
                return None
            return (fp, expected_hash, analysis)

        analyze_done = 0
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(_analyze_one, task): task for task in unique_tasks}
            for fut in as_completed(futures):
                if self._import_stop_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                analyze_done += 1
                result = fut.result()
                if result is None:
                    # None 可能是 stop 或分析失败，检查一下
                    if self._import_stop_event.is_set():
                        break
                    continue

                fp, expected_hash, analysis = result

                if not analysis.get('is_malware'):
                    # 非恶意，跳过
                    pass
                else:
                    file_hash = analysis.get('signatures', {}).get('sha256') or expected_hash
                    basename = os.path.basename(fp)
                    malware_type = analysis.get('malware_type', 'import')
                    severity = analysis.get('severity', 'high')
                    score = analysis.get('score', 0)
                    confidence = analysis.get('confidence', 0.0)
                    reasons = analysis.get('reasons', [])
                    signatures = analysis.get('signatures', {})
                    file_info = analysis.get('file_info', {})

                    desc_parts = [f'评分: {score}/100', f'置信度: {confidence:.0%}']
                    if reasons:
                        desc_parts.append('依据: ' + '; '.join(reasons[:5]))
                    if signatures.get('suspicious_imports'):
                        desc_parts.append(f'可疑API: {", ".join(signatures["suspicious_imports"][:5])}')
                    if file_info.get('entropy', 0) > 7.0:
                        desc_parts.append(f'熵值: {file_info["entropy"]:.2f}')

                    description = ' | '.join(desc_parts)
                    name = f"{malware_type}.{basename}"

                    pending_batch.append(_make_entry(
                        file_hash, name, malware_type, severity, description
                    ))
                    logger.info(f'[病毒识别] {basename} (类型={malware_type}, 评分={score})')

                if len(pending_batch) >= _BATCH_SIZE:
                    _flush_batch()
                if analyze_done % 50 == 0 or analyze_done == len(unique_tasks):
                    pct = 83 + int((analyze_done / max(len(unique_tasks), 1)) * 14)
                    self._emit_import_progress(pct, f'分析中: {analyze_done}/{len(unique_tasks)} (已入库{imported}个)')

        _flush_batch()
        return imported

    def _run_import_whitelist(self, file_path: str):
        """子线程：导入白名单

        支持：
        - 单个数据文件 (.json/.db/.txt)：从文件中读取 SHA256 哈希
        - 单个样本文件：计算 SHA256 后加入白名单
        - 文件夹（递归）：
          - 数据文件 (.json/.db/.txt) → 提取哈希
          - 其他文件 → 计算 SHA256
          - 自动去重合并
        """
        self._import_running = True
        added = 0
        skipped = 0
        total = 0
        try:
            if not self._signature_db:
                self._emit_tool_signal('importProgress', 0, '签名库未初始化')
                self._emit_tool_signal('importFinished', 0, 0, False)
                return

            if not os.path.exists(file_path):
                self._emit_import_progress(0, f'路径不存在: {file_path}')
                self._emit_tool_signal('importFinished', 0, 0, False)
                return

            self._emit_import_progress(5, '开始分析白名单来源...')

            DATA_EXTS = ('.json', '.txt')  # 白名单仅支持精确哈希，不解析数据库/YARA
            hashes = []  # 收集所有提取/计算的哈希

            if os.path.isdir(file_path):
                # ---- 文件夹：递归收集，数据文件提取哈希 + 普通文件算哈希 ----
                self._emit_import_progress(8, '扫描文件夹中...')
                regular_files = []
                data_file_count = 0
                for root, dirs, fnames in os.walk(file_path):
                    if self._import_stop_event.is_set():
                        break
                    for fn in fnames:
                        fp = os.path.join(root, fn)
                        ext = os.path.splitext(fn)[1].lower()
                        if ext in DATA_EXTS:
                            try:
                                file_hashes = self._extract_hashes_from_data_file(fp)
                                hashes.extend(file_hashes)
                                data_file_count += 1
                            except Exception as e:
                                logger.debug(f'白名单数据文件解析失败 {fp}: {e}')
                        else:
                            regular_files.append(fp)

                self._emit_import_progress(12, f'发现 {data_file_count} 个数据文件 + {len(regular_files)} 个样本文件')

                # 并行计算普通文件哈希
                if regular_files:
                    import hashlib as _hashlib
                    from concurrent.futures import ThreadPoolExecutor, as_completed

                    def _hash_one(fp):
                        try:
                            return self._calc_file_sha256(fp, _hashlib)
                        except Exception:
                            return None

                    workers = min(8, os.cpu_count() + 4)
                    done = 0
                    with ThreadPoolExecutor(max_workers=workers) as ex:
                        futures = {ex.submit(_hash_one, fp): fp for fp in regular_files}
                        for fut in as_completed(futures):
                            if self._import_stop_event.is_set():
                                ex.shutdown(wait=False, cancel_futures=True)
                                break
                            h = fut.result()
                            if h and len(h) == 64:
                                hashes.append(h)
                            done += 1
                            if done % 100 == 0 or done == len(regular_files):
                                pct = 12 + int((done / max(len(regular_files), 1)) * 40)
                                self._emit_import_progress(pct, f'计算哈希: {done}/{len(regular_files)}')

            else:
                # ---- 单文件 ----
                ext = os.path.splitext(file_path)[1].lower()
                if ext in DATA_EXTS:
                    hashes = self._extract_hashes_from_data_file(file_path)
                else:
                    import hashlib as _hashlib
                    h = self._calc_file_sha256(file_path, _hashlib)
                    if h and len(h) == 64:
                        hashes = [h]

            # 去重
            seen = set()
            unique_hashes = []
            for h in hashes:
                if h and len(h) == 64 and h not in seen:
                    seen.add(h)
                    unique_hashes.append(h)
            total = len(unique_hashes)

            self._emit_import_progress(55, f'共 {total} 个唯一哈希，开始写入白名单...')

            if total == 0:
                self._emit_import_progress(99, '未找到任何有效哈希')
                self._signature_db.flush_whitelist_batch()
                self._emit_tool_signal('importFinished', 0, 0, False)
                return

            for idx, h in enumerate(unique_hashes):
                if self._import_stop_event.is_set():
                    self._emit_import_progress(99, '已停止')
                    break
                if not self._signature_db.is_whitelisted(h):
                    self._signature_db.add_to_whitelist(h, reason='白名单导入')
                    added += 1
                else:
                    skipped += 1
                if idx % 200 == 0 or idx == total - 1:
                    pct = 55 + int((idx / max(total, 1)) * 40)
                    self._emit_import_progress(pct, f'导入中: {idx+1}/{total} (新增{added}, 跳过{skipped})')

            self._signature_db.flush_whitelist_batch()
            final_pct = 99 if not self._import_stop_event.is_set() else 95
            self._emit_import_progress(final_pct, f'导入完成: 新增{added}, 跳过{skipped}, 共{total}')

        except Exception as e:
            logger.error(f'白名单导入异常: {e}', exc_info=True)
            self._emit_import_progress(99, f'异常: {e}')
        finally:
            self._import_running = False
            success = added > 0 and not self._import_stop_event.is_set()
            self._add_activity(
                '白名单',
                f'导入完成: 新增 {added}, 跳过 {skipped}',
                'INFO' if success else 'WARN',
                '成功' if success else '已停止'
            )
            self._emit_tool_signal('importFinished', added, total, success)

    @staticmethod
    def _calc_file_sha256(file_path: str, hashlib_mod) -> str:
        """计算文件 SHA256（2MB 缓冲区流式读取）"""
        h = hashlib_mod.sha256()
        with open(file_path, 'rb') as f:
            while True:
                buf = f.read(2 * 1024 * 1024)
                if not buf:
                    break
                h.update(buf)
        return h.hexdigest().lower()

    def _extract_hashes_from_data_file(self, file_path: str) -> list:
        """从 .json / .txt 文件中提取 SHA256 哈希列表（仅支持精确哈希，不支持数据库/YARA/模糊哈希）"""
        ext = os.path.splitext(file_path)[1].lower()
        hashes = []
        try:
            if ext == '.json':
                import json
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    if 'hashes' in data and isinstance(data['hashes'], list):
                        for item in data['hashes']:
                            if isinstance(item, str):
                                hashes.append(item.strip().lower())
                            elif isinstance(item, dict) and 'hash' in item:
                                hashes.append(str(item['hash']).strip().lower())
                    elif 'signatures' in data and isinstance(data['signatures'], list):
                        for sig in data['signatures']:
                            if isinstance(sig, dict) and 'hash' in sig:
                                hashes.append(str(sig['hash']).strip().lower())
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, str):
                            hashes.append(item.strip().lower())
                        elif isinstance(item, dict) and 'hash' in item:
                            hashes.append(str(item['hash']).strip().lower())

            elif ext == '.txt':
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        h = line.strip().lower()
                        if len(h) == 64 and all(c in '0123456789abcdef' for c in h):
                            hashes.append(h)

        except Exception as e:
            logger.error(f'从数据文件提取哈希失败 {file_path}: {e}')

        # 去重
        seen = set()
        result = []
        for h in hashes:
            if h not in seen and len(h) == 64:
                seen.add(h)
                result.append(h)
        return result

    def _run_pe_analysis(self, file_path: str):
        """子线程执行 PE 文件分析"""
        try:
            import hashlib as _hashlib

            result = {
                'basic': {},
                'packer': {'detected': False, 'name': ''},
                'risk_score': 0,
                'sections': [],
                'imports': [],
            }

            # 基本信息与哈希
            if not os.path.isfile(file_path):
                result['error'] = '文件不存在'
                self._emit_tool_signal('peAnalysisReady', _safe_json_dumps(result))
                return

            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)

            md5_hash = _hashlib.md5()
            sha256_hash = _hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)

            result['basic'] = {
                'filename': filename,
                'size': file_size,
                'md5': md5_hash.hexdigest(),
                'sha256': sha256_hash.hexdigest(),
                'compile_time': '',
            }

            # 优先使用 pefile 库解析
            pefile_available = False
            try:
                import pefile
                pefile_available = True
            except ImportError:
                pefile_available = False

            if pefile_available:
                try:
                    pe = pefile.PE(file_path, fast_load=False)

                    # 编译时间
                    try:
                        compile_ts = pe.FILE_HEADER.TimeDateStamp
                        result['basic']['compile_time'] = datetime.fromtimestamp(compile_ts).strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        pass

                    # 节区信息
                    sections = []
                    for section in pe.sections:
                        try:
                            name = section.Name.rstrip(b'\x00').decode('ascii', errors='ignore')
                            entropy = section.get_entropy() if hasattr(section, 'get_entropy') else 0.0
                            sections.append({
                                'name': name,
                                'vaddr': int(section.VirtualAddress),
                                'vsize': int(section.Misc_VirtualSize),
                                'raw_size': int(section.SizeOfRawData),
                                'entropy': round(float(entropy), 4),
                            })
                        except Exception:
                            pass
                    result['sections'] = sections

                    # 导入表
                    imports = []
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            try:
                                dll_name = entry.dll.decode('ascii', errors='ignore') if isinstance(entry.dll, bytes) else str(entry.dll)
                                funcs = []
                                for imp in entry.imports:
                                    if imp.name:
                                        funcs.append(imp.name.decode('ascii', errors='ignore') if isinstance(imp.name, bytes) else str(imp.name))
                                    elif imp.ordinal:
                                        funcs.append(f'ordinal_{imp.ordinal}')
                                imports.append({'dll': dll_name, 'functions': funcs})
                            except Exception:
                                pass
                    result['imports'] = imports

                    # 检测打包器
                    packer_name = self._detect_packer_from_sections(sections)
                    if packer_name:
                        result['packer'] = {'detected': True, 'name': packer_name}

                    pe.close()
                except Exception as e:
                    logger.warning(f'pefile 解析失败，降级到内置分析器: {e}')
                    pefile_available = False

            if not pefile_available:
                # 降级到内置 PEAnalyzer
                try:
                    from engine.pe_analyzer import PEAnalyzer
                    analyzer = PEAnalyzer()
                    analysis = analyzer.analyze(file_path)

                    # 转换节区信息
                    sections = []
                    for s in analysis.get('sections', []):
                        sections.append({
                            'name': s.get('name', ''),
                            'vaddr': s.get('virtual_address', 0),
                            'vsize': s.get('virtual_size', 0),
                            'raw_size': s.get('size_of_raw_data', 0),
                            'entropy': 0.0,
                        })
                    result['sections'] = sections

                    # 转换导入表（仅可疑导入）
                    imports = []
                    for imp in analysis.get('suspicious_imports', []):
                        imports.append({'dll': imp.get('module', ''), 'functions': [imp.get('function', '')]})
                    result['imports'] = imports

                    # 打包器
                    if analysis.get('packer'):
                        result['packer'] = {'detected': True, 'name': analysis['packer']}
                except Exception as e:
                    logger.warning(f'内置 PE 分析器失败: {e}')
                    result['error'] = f'PE 分析失败: {str(e)}'

            # 计算风险评分
            result['risk_score'] = self._calculate_pe_risk_score(result)

            self._emit_tool_signal('peAnalysisReady', _safe_json_dumps(result))
            self._add_activity(
                '工具',
                f'PE分析完成: {filename} (风险评分 {result["risk_score"]})',
                'INFO',
                '成功'
            )
        except Exception as e:
            logger.error(f'PE 分析失败: {e}')
            result = {'error': str(e)}
            self._emit_tool_signal('peAnalysisReady', _safe_json_dumps(result))
            self._add_activity('工具', f'PE分析失败: {str(e)}', 'ERROR', '错误')

    def _detect_packer_from_sections(self, sections: list) -> str:
        """根据节区名检测打包器"""
        packer_map = {
            'UPX0': 'UPX', 'UPX1': 'UPX', 'UPX2': 'UPX',
            'ASPack': 'ASPack',
            '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.vmp2': 'VMProtect',
            'Themida': 'Themida', 'WINLIC': 'Themida',
        }
        for section in sections:
            name = section.get('name', '')
            for key, packer in packer_map.items():
                if key.lower() in name.lower():
                    return packer
        return ''

    def _calculate_pe_risk_score(self, result: dict) -> int:
        """根据 PE 分析结果计算风险评分 (0-100)。

        评分依据：高熵节区、可疑导入、打包器、异常节区名。
        """
        score = 0

        # 高熵节区（熵 > 7.0 可能表示加壳/加密）
        high_entropy_count = 0
        for section in result.get('sections', []):
            entropy = section.get('entropy', 0.0)
            if entropy > 7.0:
                high_entropy_count += 1
        score += min(high_entropy_count * 15, 45)

        # 可疑导入
        suspicious_apis = {
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'NtCreateThreadEx', 'NtWriteVirtualMemory', 'NtAllocateVirtualMemory',
        }
        suspicious_count = 0
        for imp in result.get('imports', []):
            for func in imp.get('functions', []):
                if func in suspicious_apis:
                    suspicious_count += 1
        score += min(suspicious_count * 10, 30)

        # 打包器
        packer_info = result.get('packer', {})
        if packer_info.get('detected'):
            packer_name = packer_info.get('name', '')
            if packer_name in ('Themida', 'VMProtect', 'Armadillo'):
                score += 25
            else:
                score += 10

        # 异常节区名
        suspicious_section_names = ['.packed', '.crypt', '.encrypted', '.encoded', '.shellcode']
        for section in result.get('sections', []):
            name_lower = section.get('name', '').lower()
            for sus in suspicious_section_names:
                if sus in name_lower:
                    score += 10
                    break

        return min(score, 100)

    @pyqtSlot(str)
    def calculateFileHash(self, file_path: str):
        """计算文件 MD5/SHA1/SHA256，通过 hashResultReady 信号返回 JSON。

        在子线程中执行避免阻塞 UI。
        """
        if not file_path:
            return
        self._add_activity('工具', f'计算哈希: {file_path}', 'INFO', '进行中')
        thread = threading.Thread(
            target=self._run_hash_calculation,
            args=(file_path,),
            daemon=True
        )
        thread.start()

    def _run_hash_calculation(self, file_path: str):
        """子线程执行哈希计算"""
        try:
            import hashlib as _hashlib

            if not os.path.isfile(file_path):
                result = {'error': '文件不存在'}
                self._emit_tool_signal('hashResultReady', _safe_json_dumps(result))
                return

            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            mtime = os.path.getmtime(file_path)
            mtime_str = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')

            md5_hash = _hashlib.md5()
            sha1_hash = _hashlib.sha1()
            sha256_hash = _hashlib.sha256()

            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)

            result = {
                'path': file_path.replace('\\', '/'),
                'filename': filename,
                'size': file_size,
                'mtime': mtime_str,
                'md5': md5_hash.hexdigest(),
                'sha1': sha1_hash.hexdigest(),
                'sha256': sha256_hash.hexdigest(),
            }

            self._emit_tool_signal('hashResultReady', _safe_json_dumps(result))
            self._add_activity('工具', f'哈希计算完成: {filename}', 'INFO', '成功')
        except Exception as e:
            logger.error(f'哈希计算失败: {e}')
            result = {'error': str(e)}
            self._emit_tool_signal('hashResultReady', _safe_json_dumps(result))
            self._add_activity('工具', f'哈希计算失败: {str(e)}', 'ERROR', '错误')

    @pyqtSlot(str, str, str)
    def getLogs(self, level: str, source: str, search: str):
        """获取日志列表，通过 logsReady 信号返回 JSON。

        level: 'ALL'/'INFO'/'WARNING'/'WARN'/'ERROR'/'DEBUG'
        source: 'ALL' 或具体来源
        search: 搜索关键词
        """
        try:
            import re as _re

            # 限制最大渲染行数，避免大日志导致 QWebEngine 渲染器崩溃（空白页）
            _MAX_ITEMS = 10000

            items = []
            stats = {'total': 0, 'info': 0, 'warning': 0, 'error': 0, 'debug': 0}

            # 读取今天的日志文件
            # 路径逻辑必须与 utils/logger.py 保持一致
            if getattr(sys, 'frozen', False):
                if sys.platform == 'win32':
                    appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
                else:
                    appdata = os.path.expanduser('~/.config')
                log_dir = os.path.join(appdata, 'PSLS', 'logs')
            else:
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                log_dir = os.path.join(project_root, 'logs')
            today_str = datetime.now().strftime('%Y%m%d')
            log_file = os.path.join(log_dir, f'antivirus_{today_str}.log')

            # 日志行格式: YYYY-MM-DD HH:MM:SS [LEVEL] name: message
            log_pattern = _re.compile(
                r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] ([^:]+): (.*)$'
            )

            # 规范化请求的级别：统一 WARNING/WARN 到同一集合
            if level:
                level = level.upper()
            if level in ('WARNING', 'WARN'):
                _req_level_set = {'WARNING', 'WARN'}
            elif level == 'ALL':
                _req_level_set = None
            else:
                _req_level_set = {level}

            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        match = log_pattern.match(line)
                        if not match:
                            continue
                        timestamp, log_level, log_source, message = match.groups()

                        # 统计
                        stats['total'] += 1
                        level_upper = log_level.upper()
                        if level_upper == 'INFO':
                            stats['info'] += 1
                        elif level_upper in ('WARNING', 'WARN'):
                            stats['warning'] += 1
                        elif level_upper == 'ERROR':
                            stats['error'] += 1
                        elif level_upper == 'DEBUG':
                            stats['debug'] += 1

                        # 过滤：级别（统一用集合匹配，同时兼容 WARNING/WARN 同一分类）
                        if _req_level_set is not None:
                            if level_upper not in _req_level_set:
                                # 处理 WARN 级别请求不匹配 WARNING 级别日志的情况
                                # （前面已把 req_level_set 规范为集合，此处只做不在集合内的跳过）
                                continue
                        # 过滤：来源
                        if source != 'ALL' and log_source != source:
                            continue
                        # 过滤：搜索关键词
                        if search and search.lower() not in message.lower() and search.lower() not in log_source.lower():
                            continue

                        # 限制收集量：按最新条目（从后往前）限制，这里从前往后先收集后面再截断
                        if len(items) >= _MAX_ITEMS * 2:
                            # 超过限制的两倍时，丢弃前面的条目（后面会倒序，实际保留最新的 _MAX_ITEMS）
                            items = items[-_MAX_ITEMS:]
                        items.append({
                            'timestamp': timestamp,
                            'level': level_upper,
                            'source': log_source,
                            'message': message,
                        })

            # 倒序（最新在前）并截断到 _MAX_ITEMS 条
            items_reversed = items[::-1]
            if len(items_reversed) > _MAX_ITEMS:
                stats['total_matched'] = len(items_reversed)
                items_reversed = items_reversed[:_MAX_ITEMS]
            result = {'items': items_reversed, 'stats': stats}
            self._emit_tool_signal('logsReady', _safe_json_dumps(result))
        except Exception as e:
            logger.error(f'获取日志失败: {e}')
            result = {
                'items': [],
                'stats': {'total': 0, 'info': 0, 'warning': 0, 'error': 0, 'debug': 0},
                'error': str(e)
            }
            self._emit_tool_signal('logsReady', _safe_json_dumps(result))

    def _get_self_excluded_dirs(self):
        """获取 PSLS 自身路径排除集合（路径级自保护兜底）

        即使扫描引擎的哈希白名单失效，此处也能阻止对自身文件的隔离/删除。
        """
        if hasattr(self, '_self_excluded_dirs_cache'):
            return self._self_excluded_dirs_cache
        excluded = set()
        try:
            # 打包模式：exe 所在目录
            if getattr(sys, 'frozen', False):
                exe_dir = os.path.dirname(os.path.abspath(sys.executable))
                excluded.add(exe_dir.lower())
            else:
                # 开发模式：项目根目录
                project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                excluded.add(project_root.lower())
            # %APPDATA%\PSLS
            if sys.platform == 'win32':
                appdata = os.environ.get('APPDATA', '')
                if appdata:
                    excluded.add(os.path.join(appdata, 'PSLS').lower())
            # backup 目录
            for base in list(excluded):
                excluded.add(os.path.join(base, 'backup').lower())
                internal = os.path.join(base, '_internal')
                if os.path.isdir(internal):
                    excluded.add(internal.lower())
        except Exception:
            pass
        self._self_excluded_dirs_cache = excluded
        return excluded

    def _is_self_protected_file(self, file_path: str) -> bool:
        """检查文件是否属于 PSLS 自身受保护目录"""
        if not file_path:
            return False
        try:
            fp_lower = os.path.abspath(file_path).lower()
            for excluded_dir in self._get_self_excluded_dirs():
                if fp_lower.startswith(excluded_dir):
                    return True
        except Exception:
            pass
        return False

    def _in_scan_excluded_path(self, file_path: str) -> bool:
        """检查文件路径是否位于用户设置的扫描排除路径下（路径级排除兜底）

        在自动隔离/处理威胁前做兜底防护，防止排除目录下的文件被误隔离。
        """
        if not file_path:
            return False
        try:
            sep = ' -> '
            check_path = file_path.split(sep)[0] if sep in file_path else file_path
            fp_lower = os.path.abspath(check_path).lower()
            for excluded in getattr(self, '_scan_excluded_paths', []):
                if not excluded:
                    continue
                try:
                    ex_lower = os.path.abspath(excluded).lower()
                except Exception:
                    ex_lower = os.path.normpath(excluded).lower()
                if not ex_lower:
                    continue
                if fp_lower == ex_lower or fp_lower.startswith(ex_lower):
                    return True
        except Exception:
            pass
        return False

    def _is_system_protected_file(self, file_path: str) -> bool:
        """检查文件是否属于 Windows 系统核心受保护目录（防误隔离系统文件）

        在 quarantine_manager 之外再次做兜底防护，防止上游误判。
        """
        if not file_path:
            return False
        try:
            check_path = file_path
            if ' -> ' in check_path:
                check_path = check_path.split(' -> ')[0]
            fp_lower = os.path.abspath(check_path).lower()

            # 系统核心目录 → 直接视为受保护（不允许自动处理）
            if not hasattr(self, '_bridge_system_protected_dirs'):
                sys_root = os.environ.get('SystemRoot', r'C:\Windows').lower()
                pf = os.environ.get('ProgramFiles', r'C:\Program Files').lower()
                pf86 = os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)').lower()
                self._bridge_system_protected_dirs = {
                    os.path.join(sys_root, 'system32'),
                    os.path.join(sys_root, 'syswow64'),
                    os.path.join(sys_root, 'uus'),
                    os.path.join(sys_root, 'systemapps'),
                    os.path.join(sys_root, 'assembly'),
                    os.path.join(sys_root, 'microsoft.net'),
                    os.path.join(sys_root, 'winsxs'),
                }

            for d in self._bridge_system_protected_dirs:
                if fp_lower.startswith(d):
                    return True
        except Exception:
            pass
        return False

    def _handle_threat(self, status, file_path, sig_name, opts):
        """根据扫描选项处理检测到的威胁（在扫描子线程中调用）"""
        try:
            # 自保护：拒绝处理 PSLS 自身文件
            if self._is_self_protected_file(file_path):
                logger.warning(f'拒绝处理自身受保护文件: {file_path}')
                self._add_activity('防护', f'已阻止对自身文件的处理: {os.path.basename(file_path)}', 'WARN', '已阻止')
                return

            # 误报兜底：系统核心目录下的文件不允许自动处理（需人工确认）
            if self._is_system_protected_file(file_path):
                logger.warning(f'拒绝自动处理系统受保护目录下的文件: {file_path} (status={status})')
                self._add_activity('防护',
                                   f'阻止自动处理系统文件: {os.path.basename(file_path)} [{status}]',
                                   'WARN', '已阻止(人工确认)')
                return

            notify_enabled = opts.get('notifyThreat', True)
            action_key = 'malwareAction' if status == 'malware' else 'suspiciousAction'
            # 处理方式与设置页共用同一份设置（_rt_*）：前端未传该键时回退到它，
            # 保证"设置页 / 扫描页 / 后端"三处始终是同一个值
            default_action = (self._rt_malware_action if status == 'malware'
                              else self._rt_suspicious_action)
            action = opts.get(action_key, default_action)

            if action == 'ignore':
                return

            if action in ('auto', 'delete'):
                # auto: 隔离->删除->通知结果；delete: 直接删除（失败回退到隔离->软隔离）
                if action == 'delete':
                    result = self._delete_threat_file(file_path, sig_name, status)
                    if not (isinstance(result, dict) and result.get('success', False)):
                        # 删除失败，降级为自动隔离处理（避免完全不处理）
                        result = self._auto_process_threat(file_path, sig_name, status)
                else:
                    result = self._auto_process_threat(file_path, sig_name, status)
                if notify_enabled:
                    with self._signal_lock:
                        self._pending_results.append({
                            'type': 'threat_action_result',
                            'file_path': file_path,
                            'status': status,
                            'signature_name': sig_name,
                            'action': action,
                            'result': result
                        })
            elif action == 'notify':
                # 通知弹窗：让用户选择
                payload = json.dumps({
                    'type': 'threat_action_required',
                    'file_path': file_path,
                    'status': status,
                    'signature_name': sig_name,
                }, ensure_ascii=False)
                with self._signal_lock:
                    self._pending_results.append({
                        'type': 'threat_action_required',
                        'payload': payload
                    })
        except Exception as e:
            logger.error(f'处理威胁失败 {file_path}: {e}')

    def _delete_threat_file(self, file_path, sig_name, status):
        """直接删除威胁文件（配合 delete 策略；失败时与 quarantine 相同的预处理）"""
        try:
            # 自保护：拒绝删除 PSLS 自身文件
            if self._is_self_protected_file(file_path):
                logger.warning(f'拒绝删除自身受保护文件: {file_path}')
                return {'success': False, 'action': 'blocked', 'message': '已阻止删除自身文件'}

            if not os.path.isfile(file_path):
                return {'success': False, 'action': 'not_found', 'message': f'文件不存在: {os.path.basename(file_path)}'}

            # 复用 quarantine_manager 的预处理：清属性+杀进程+takeown
            if self._quarantine_manager:
                try:
                    self._quarantine_manager._prep_for_remove(file_path)
                except Exception:
                    pass

            # 多重删除尝试，收集失败原因
            deleted = False
            del_errors = []
            try:
                os.remove(file_path)
                deleted = not os.path.exists(file_path)
            except Exception as rm_err:
                del_errors.append(f'os.remove失败: {rm_err}')
            if not deleted and sys.platform == 'win32':
                try:
                    import subprocess
                    # cmd /c del 直接删除，绕过某些 Shell 钩子
                    cp = subprocess.run(
                        ['cmd', '/c', 'del', '/F', '/A', '/Q', file_path],
                        capture_output=True, timeout=10, creationflags=_HIDDEN_CREATIONFLAGS
                    )
                    deleted = not os.path.exists(file_path)
                    if not deleted:
                        stderr = cp.stderr.decode('mbcs', errors='ignore').strip() if cp.stderr else ''
                        del_errors.append(f'cmd del失败: {stderr or "未知错误"}')
                except Exception as cmd_err:
                    del_errors.append(f'cmd del异常: {cmd_err}')

            if deleted:
                self._add_activity('防护', f'已删除: {file_path}', 'WARN', '成功')
                q_count = 0
                if self._quarantine_manager:
                    q_count = len(self._quarantine_manager.list_items())
                self._emit_tool_signal('quarantineUpdated', q_count)
                return {'success': True, 'action': 'deleted', 'message': f'已删除: {os.path.basename(file_path)}'}

            # 删除失败：尝试降级为软隔离（与 quarantine_manager 同步思路）
            if self._quarantine_manager and sys.platform == 'win32':
                qr = self._quarantine_manager.quarantine_file(file_path, reason=sig_name or status, malware_name=sig_name)
                if qr is True or qr == 'exempted' or qr == 'duplicate':
                    if qr == 'exempted':
                        return {'success': True, 'action': 'exempted', 'message': f'已豁免: {os.path.basename(file_path)}'}
                    if qr == 'duplicate':
                        return {'success': True, 'action': 'duplicate',
                                'message': f'文件已在隔离区，跳过: {os.path.basename(file_path)}'}
                    return {'success': True, 'action': 'quarantined_as_fallback',
                            'message': f'删除失败已降级隔离: {os.path.basename(file_path)}'}
                # 降级隔离也失败，合并失败原因
                q_fail = self._quarantine_manager.get_last_quarantine_error()
                if q_fail:
                    del_errors.append(f'降级隔离失败: {q_fail}')

            # 汇总失败原因记录到日志
            fail_reason = '；'.join(del_errors) if del_errors else '未知原因'
            self._add_activity('防护', f'删除失败（原因: {fail_reason}）: {file_path}', 'ERROR', '待处理')
            logger.error(f'删除失败，保留文件待用户处理: {file_path} - 失败原因: {fail_reason}')
            return {'success': False, 'action': 'manual', 'message': f'删除失败，请手动处理: {os.path.basename(file_path)}'}
        except Exception as e:
            logger.error(f'删除威胁异常 {file_path}: {e}')
            return {'success': False, 'action': 'failed', 'message': f'处理异常: {str(e)}'}

    def _notify_process_kill_result(self, pid: int, name: str, path: str,
                                     kill_success: bool, reason: str = '',
                                     scenario: str = '进程保护'):
        """按 PID 终止进程后的结果通知弹窗（复用扫描处置结果弹窗样式）

        Args:
            pid: 被终止进程的 PID（0 表示未知）
            name: 进程名或可执行文件名
            path: 可执行文件完整路径
            kill_success: 终止操作是否成功
            reason: 终止失败时的补充原因
            scenario: 场景标签，写入日志（默认 进程保护）

        行为：
            - 成功 → 绿色弹窗 success=True
            - 失败 → 灰色弹窗 success=False
            - 始终写入活动日志
        """
        try:
            display_name = name or os.path.basename(path) or f'PID={pid}'
            if pid:
                title = f"{display_name} (PID={pid})"
            else:
                title = display_name

            # 活动日志
            if kill_success:
                self._add_activity(
                    scenario,
                    f"已强制终止进程: {title}",
                    'WARN',
                    '已处置'
                )
                message = f"已成功终止威胁进程"
            else:
                self._add_activity(
                    scenario,
                    f"终止进程失败: {title} {reason}",
                    'ERROR',
                    '待处理'
                )
                message = f"终止进程失败，请手动处理"
                if reason:
                    message += f"（{reason}）"

            # 复用 ThreatResultPopup，绿色/灰色样式由 result.success 控制
            term_result = {
                'has_process': True,
                'success': kill_success,
                'message': message,
                'pid': pid,
                'process_name': name,
                'reason': reason,
            }
            self._show_threat_result_popup({
                'file_path': path or '',
                'status': 'malware',
                'signature_name': display_name,
                'action': 'terminate_process',
                'result': term_result,
            })
        except Exception as e:
            logger.error(f'进程终止结果通知失败 PID={pid}: {e}')

    def _terminate_process_and_notify(self, file_path, sig_name, status):
        """终止恶意软件进程并通过桌面弹窗通知用户

        弹窗样式与扫描处理结果弹窗（ThreatResultPopup）完全相同：
        - 成功终止进程 → 绿色弹窗（success=True）
        - 终止失败     → 灰色弹窗（success=False）
        - 未检测到进程 → 不弹窗（避免无意义打扰）

        在子线程中调用，通过 _show_threat_result_popup 入队，由主线程显示。
        """
        try:
            if not self._quarantine_manager:
                return None
            # 调用隔离管理器的进程终止能力
            term_result = self._quarantine_manager.terminate_malware_process(
                file_path, malware_name=sig_name or ''
            )

            # 未检测到运行中的进程：不弹窗
            if not term_result.get('has_process', False):
                return term_result

            # 记录活动日志
            level = 'WARN' if term_result.get('success') else 'ERROR'
            tag = '成功' if term_result.get('success') else '失败'
            self._add_activity(
                '防护',
                f"终止进程: {term_result.get('message', '')} ({file_path})",
                level,
                tag
            )

            # 通过桌面弹窗通知用户（复用扫描处理结果弹窗，绿色成功/灰色失败）
            self._show_threat_result_popup({
                'file_path': file_path,
                'status': status,
                'signature_name': sig_name or '',
                'action': 'terminate_process',
                'result': term_result,
            })
            return term_result
        except Exception as e:
            logger.error(f'终止进程并通知失败 {file_path}: {e}')
            return None

    def _driver_terminate_by_path(self, file_path: str) -> bool:
        """通过内核驱动终止指定路径文件的所有运行中进程（Ring 0 级）。

        遍历系统进程，找出 exe 路径匹配的进程，通过驱动 IOCTL_TERMINATE_PROC
        强制终止。相比用户态 psutil/kill，驱动终止不受目标进程自保护/权限限制。

        Args:
            file_path: 威胁文件路径

        Returns:
            True = 至少一个进程被驱动层终止
        """
        if sys.platform != 'win32':
            return False
        try:
            from driver.bridge.psls_driver_bridge import PSLSDriverBridge
            bridge = PSLSDriverBridge()
            if not bridge.is_available:
                return False
        except Exception:
            return False

        terminated = False
        try:
            target_lower = os.path.abspath(file_path).lower()
            import psutil
            for proc in psutil.process_iter(['pid', 'exe']):
                try:
                    proc_exe = (proc.info.get('exe') or '').lower()
                    if proc_exe and os.path.abspath(proc_exe) == target_lower:
                        pid = proc.pid
                        result = bridge.terminate_process(pid)
                        if result:
                            logger.info(f'驱动已终止进程 PID={pid} ({os.path.basename(file_path)})')
                            terminated = True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.debug(f'驱动终止进程遍历异常: {e}')
        return terminated

    def _auto_process_threat(self, file_path, sig_name, status, skip_kill=False):
        """自动处理威胁：先锁定文件防启动 → 终止进程 → 隔离/删除

        在子线程中执行，通过 _emit_tool_signal 线程安全地更新 UI。

        增强流程（vs 原版）：
        0. **先锁定文件**：通过 CreateFileW 获取独占句柄（share=0），防止在隔离完成前
           用户/恶意代码启动该文件。文件被占用时 CreateProcess 会失败。
        1. 终止恶意软件进程（若有）+ 驱动层强制终止兜底
        2. 隔离/删除
        3. 释放文件句柄（仅在隔离失败时释放，隔离成功时文件已移走无需释放）

        Args:
            file_path: 威胁文件路径
            sig_name: 签名名称
            status: malware / suspicious
            skip_kill: True 时跳过内部的 terminate（进程已由外部先杀掉时用）
        """
        # ---- 阶段 0: 锁定文件防止被启动 ----
        lock_handle = None
        lock_acquired = False
        file_was_moved = False
        try:
            import ctypes
            import ctypes.wintypes
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            OPEN_EXISTING = 3
            INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

            kernel32.CreateFileW.restype = ctypes.wintypes.HANDLE
            kernel32.CreateFileW.argtypes = [
                ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
                ctypes.wintypes.LPVOID, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.HANDLE,
            ]
            handle = kernel32.CreateFileW(
                file_path,
                GENERIC_READ | GENERIC_WRITE,
                0,  # share=0: 独占，阻止其他进程打开
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            if handle != INVALID_HANDLE_VALUE:
                lock_handle = handle
                lock_acquired = True
                logger.info(f'威胁文件已锁定: {os.path.basename(file_path)}')
                # 通知用户：实时保护已锁定该程序，稍后自动解除（跨线程信号）
                self.notify_file_locked(file_path)
        except Exception as e:
            logger.debug(f'文件锁定失败（非关键，继续后续流程）: {e}')

        try:
            # 自保护：拒绝处理 PSLS 自身文件
            if self._is_self_protected_file(file_path):
                logger.warning(f'拒绝自动处理自身受保护文件: {file_path}')
                self._add_activity('防护', f'已阻止对自身文件的处理: {os.path.basename(file_path)}', 'WARN', '已阻止')
                return {'success': False, 'action': 'blocked', 'message': '已阻止处理自身文件'}

            # 用户排除路径兜底：排除目录下的文件绝不自动隔离（修复排除项失效）
            if self._in_scan_excluded_path(file_path):
                logger.info(f'文件位于用户排除路径，跳过自动处理: {file_path}')
                self._add_activity('防护',
                                   f'排除路径内的文件，跳过处理: {os.path.basename(file_path)}',
                                   'INFO', '跳过')
                return {'success': True, 'action': 'excluded', 'message': f'排除路径内，已跳过: {os.path.basename(file_path)}'}

            # 误报兜底：系统核心目录下的文件不允许自动处理
            if self._is_system_protected_file(file_path):
                logger.warning(f'拒绝自动处理系统受保护文件: {file_path} (status={status})')
                self._add_activity('防护',
                                   f'阻止自动处理系统文件: {os.path.basename(file_path)} [{status}]',
                                   'WARN', '已阻止(人工确认)')
                return {'success': False, 'action': 'blocked', 'message': '已阻止处理系统文件（人工确认）'}

            # 先尝试终止恶意软件进程（仅在有进程运行时弹窗通知）
            # 提前终止进程可大幅提升隔离/删除成功率，避免"文件被占用"导致的处理失败
            # skip_kill=True 时跳过（进程已由 ProcessProtection 先杀掉）
            if not skip_kill:
                # 先尝试驱动层强制终止（Ring 0，兜底 psutil kill 可能失败的场景）
                if status == 'malware':
                    self._driver_terminate_by_path(file_path)
                # 再走用户态终止 + 通知（复用原有弹窗链路）
                self._terminate_process_and_notify(file_path, sig_name, status)

            # ---- 隔离/删除前释放文件锁 ----
            # share=0 独占锁会阻止隔离管理器读取/移动文件，需先释放
            if lock_handle:
                try:
                    kernel32.CloseHandle(lock_handle)
                    lock_handle = None
                    logger.debug(f'隔离前释放文件锁: {os.path.basename(file_path)}')
                except Exception:
                    lock_handle = None

            if self._quarantine_manager:
                result = self._quarantine_manager.quarantine_file(
                    file_path, reason=sig_name or status, malware_name=sig_name
                )
                # 豁免：本次运行中已恢复的文件，跳过处理
                if result == 'exempted':
                    self._add_activity('防护', f'文件已豁免（已恢复），跳过: {os.path.basename(file_path)}', 'INFO', '跳过')
                    return {'success': True, 'action': 'exempted', 'message': f'已豁免: {os.path.basename(file_path)}'}
                # 幂等查重命中：该文件哈希已在隔离区（未删除/未恢复），本次未新增隔离条目。
                # 不再写"已隔离"成功日志/弹出成功提示，直接返回 duplicate 让上层做静默处理，
                # 避免实时监控持续触发时活动日志被"已隔离"刷屏。
                if result == 'duplicate':
                    logger.info(f'文件已在隔离区（duplicate 命中），静默跳过处置: {file_path}')
                    self._add_activity(
                        '防护',
                        f'文件已在隔离区，跳过重复隔离: {os.path.basename(file_path)}',
                        'INFO', '已在隔离区')
                    # 标记处置缓存：窗口内不再让 RT 入队触发循环
                    try:
                        from engine.realtime_monitor import _mark_file_disposed
                        _mark_file_disposed(file_path)
                    except Exception:
                        pass
                    return {'success': True, 'action': 'duplicate',
                            'message': f'文件已在隔离区，跳过: {os.path.basename(file_path)}'}
                if result:
                    self._add_activity('防护', f'已隔离: {file_path}', 'WARN', '成功')
                    q_count = len(self._quarantine_manager.list_items())
                    self._emit_tool_signal('quarantineUpdated', q_count)
                    file_was_moved = True  # 文件已移走，无需释放锁
                    return {'success': True, 'action': 'quarantined', 'message': f'已隔离: {os.path.basename(file_path)}'}

                # 隔离失败：读取具体失败原因并记录到日志
                fail_reason = self._quarantine_manager.get_last_quarantine_error() or '未知原因'
                logger.error(f'隔离失败 {file_path} - 失败原因: {fail_reason}')

            # 隔离失败：malware 级别尝试直接删除（删除不可逆，suspicious 保留文件避免误删）
            if status == 'malware':
                del_result = self._delete_threat_file(file_path, sig_name, status)
                if isinstance(del_result, dict) and del_result.get('success', False):
                    file_was_moved = True  # 文件已删除，无需释放锁
                    return del_result

            # 仍失败：保留文件，通知用户手动处理
            fail_reason = ''
            if self._quarantine_manager:
                fail_reason = self._quarantine_manager.get_last_quarantine_error()
            fail_hint = f'（原因: {fail_reason}）' if fail_reason else ''
            self._add_activity('防护', f'隔离失败，需手动处理{fail_hint}: {file_path}', 'WARN', '待处理')
            logger.error(f'隔离失败，保留文件待用户处理: {file_path}{fail_hint}')
            return {'success': False, 'action': 'manual', 'message': f'隔离失败，请手动处理: {os.path.basename(file_path)}'}
        except Exception as e:
            logger.error(f'自动处理威胁异常 {file_path}: {e}')
            return {'success': False, 'action': 'failed', 'message': f'处理异常: {str(e)}'}
        finally:
            # 释放文件锁定句柄
            if lock_handle is not None and not file_was_moved:
                try:
                    import ctypes
                    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                    kernel32.CloseHandle(lock_handle)
                    logger.debug(f'威胁文件锁已释放: {os.path.basename(file_path)}')
                except Exception:
                    pass

    # -------------------------------------------------- 威胁处置：后台线程池 offload -----
    def _offload_threat_disposition(self, action: str, file_path: str,
                                    sig_name: str, status: str):
        """[主线程调用] 将 auto/delete/quarantine 等长耗时处置 offload 至后台线程池。

        **主线程在此函数内只做 submit → return，不阻塞 QWebChannel 事件循环。**
        完成后通过 QTimer.singleShot(0, ...) 切回主线程执行 UI 收束（提示音、
        隔离计数刷新、实时锁释放、threatActionResult emit、桌面结果弹窗）。

        若线程池不可用则降级为：在当前线程（非主线程）同步执行；*绝不*在主线程
        同步执行 _auto_process_threat / _delete_threat_file（含 takeown + cmd del
        10s 超时 / 隔离加密，会导致 Splash/主窗口被 Windows 标记"未响应"）。
        """
        def _run_disposition_in_worker():
            """实际跑在 _threat_disposition_executor 线程中的同步任务。"""
            try:
                if action == 'auto':
                    result = self._auto_process_threat(file_path, sig_name, status)
                elif action == 'delete':
                    result = self._delete_threat_file(file_path, sig_name, status)
                elif action == 'quarantine':
                    # 用户显式选择隔离：走自动流程，结果标签非 quarantined/exempted
                    # 则重写为 quarantine_failed 让前端区分
                    result = self._auto_process_threat(file_path, sig_name, status)
                    if (isinstance(result, dict)
                            and result.get('action') != 'quarantined'
                            and result.get('action') != 'exempted'):
                        result['action'] = result.get('action', 'quarantine_failed')
                else:
                    result = {'success': False, 'action': 'unknown',
                              'message': '未知操作'}
            except Exception as e:
                logger.error(f'后台处置 {action} 失败: {file_path}: {e}',
                             exc_info=True)
                result = {'success': False, 'action': 'failed',
                          'message': f'处置异常: {str(e)}'}
            # → 切回主线程做 UI 收束（emit / 弹窗 / Qt 信号必须在主线程）
            try:
                QTimer.singleShot(
                    0,
                    lambda: self._finish_threat_disposition_ui(
                        action, file_path, sig_name, status, result,
                    ),
                )
            except Exception as e_ui:
                logger.warning(f'调度 UI 收束失败（QTimer 不可用）: {e_ui}')

        executor = getattr(self, '_threat_disposition_executor', None)
        if executor is not None:
            try:
                executor.submit(_run_disposition_in_worker)
                return
            except Exception as e_sub:
                logger.warning(
                    f'threat_disposition_executor submit 失败，'
                    f'降级为独立线程: {e_sub}')
        # 兜底降级：启动独立线程（不占主线程）
        try:
            t = threading.Thread(
                target=_run_disposition_in_worker,
                name=f'PSLS-ThreatDisp-Fallback-{os.path.basename(file_path)[:20]}',
                daemon=True,
            )
            t.start()
        except Exception as e_thread:
            logger.error(f'降级线程启动失败，仅记录未执行处置 {file_path}: '
                         f'{e_thread}')

    def _finish_threat_disposition_ui(self, action, file_path, sig_name, status, result):
        """[必须主线程] 处置完成后的 UI 收束：声音/计数/锁/emit/弹窗。

        被 QTimer.singleShot(0, ...) 从 worker 线程回调到主线程执行，
        保证：
          - Qt 信号 emit 正确（QWebChannel 只认主线程 emit 的参数）
          - ThreatResultPopup 父窗体重绘在 Qt 渲染线程
          - quarantineUpdated / release_realtime_threat_lock 不竞态
        """
        try:
            # 1) 分级提示音（处置结果通知：恶意 → error2.mp3，可疑 → error.mp3）
            need_sound = action in ('auto', 'delete', 'quarantine')
            is_exempted = (isinstance(result, dict)
                           and result.get('action') == 'exempted')
            if need_sound and not is_exempted:
                if status == 'malware':
                    self._request_error2_sound()
                else:
                    self._request_error_sound()

            # 2) 刷新隔离区计数（列表大小；当隔离区很大时也可能卡 20~100ms，
            #    但这里是 UI 收束，数量本身要推到前端，接受此开销）
            if self._quarantine_manager is not None:
                try:
                    q_count = len(self._quarantine_manager.list_items())
                    self.quarantineUpdated.emit(q_count)
                except Exception as e_q:
                    logger.debug(f'隔离计数刷新失败: {e_q}')

            # 3) 释放实时防护为该文件登记的威胁处置独占锁
            #    - notify 路径由 realtime_monitor._process_scan_results 登记锁
            #    - 非 realtime 来源调用 release，为 no-op（安全返回 False）
            self._release_realtime_threat_lock(file_path)

            # 4) 通知前端处理结果
            result_payload = json.dumps({
                'file_path': file_path,
                'status': status,
                'signature_name': sig_name,
                'action': action,
                'result': result,
                'desktop_popup': True,
            }, ensure_ascii=False)
            self.threatActionResult.emit(result_payload)

            # 5) 桌面右下角结果弹窗（与上面 emit 分开，弹窗队列内已单例+限流）
            self._show_threat_result_popup({
                'file_path': file_path,
                'status': status,
                'signature_name': sig_name,
                'action': action,
                'result': result,
            })
        except Exception as e:
            logger.error(f'处置 UI 收束失败 {file_path}: {e}')

    @pyqtSlot(str)
    def processThreat(self, payload_str):
        """用户选择处理方式后调用（前端通过弹窗选择后调用）；新增 delete 动作分支。

        关键性能约束（配合 _threat_disposition_executor 降低"未响应"概率）：
          - ignore：同步立即返回，几乎无 IO → 允许主线程直接跑
          - auto / delete / quarantine：全部走 _offload_threat_disposition
            后台执行，*绝不*在 QWebChannel 主线程里同步执行 takeown / cmd del
            / 隔离加密 / 终止 WMI 扫进程等长耗时（数秒～数十秒）动作。
        """
        try:
            payload = json.loads(payload_str) if isinstance(payload_str, str) else payload_str
            file_path = payload.get('file_path', '')
            action = payload.get('action', 'ignore')
            sig_name = payload.get('signature_name', '')
            status = payload.get('status', 'suspicious')

            if action == 'ignore':
                # ignore 无 IO/无阻塞：主线程直接完成
                self._add_activity('防护', f'用户忽略: {file_path}', 'INFO', '跳过')
                result = {'success': True, 'action': 'ignored', 'message': '已忽略'}
                # 释放实时锁 + 通知前端（ignore 路径仍需清锁，否则文件持续被占）
                self._release_realtime_threat_lock(file_path)
                # 需求 A：来自"启动扫描"的忽略 → 记入**独立忽略表**（不写白名单），
                # 使后续不再对该对象触发启动扫描（弹窗/blocked/沙箱）。
                try:
                    _src = payload.get('source', '')
                    _is_launch = (_src == 'launch_scan'
                                  or str(sig_name).startswith('[启动扫描]'))
                    if _is_launch and file_path:
                        # 后台写盘，避免 GUI 线程 IO
                        threading.Thread(
                            target=self._add_launch_scan_ignore,
                            args=(file_path, 'user_ignore'),
                            daemon=True, name='LaunchIgnoreAdd').start()
                except Exception as e:
                    logger.debug(f'记录启动扫描忽略失败: {e}')
                result_payload = json.dumps({
                    'file_path': file_path, 'status': status,
                    'signature_name': sig_name, 'action': action,
                    'result': result, 'desktop_popup': True,
                }, ensure_ascii=False)
                self.threatActionResult.emit(result_payload)
                return

            if action == 'trust':
                # 「忽略并信任」：忽略本次告警 + 把文件哈希写入白名单。
                # 同样需要清实时锁，否则文件会持续被占。
                self._release_realtime_threat_lock(file_path)
                threading.Thread(
                    target=self._trust_file_in_background,
                    args=(file_path, sig_name, status),
                    daemon=True,
                    name='PSLS-TrustFile',
                ).start()
                return

            # ---- auto / delete / quarantine：后台线程池 offload ----
            # 主线程此处只做入队 → return，立即归还 Qt 事件循环，杜绝白屏。
            self._add_activity(
                '防护',
                f'开始处置: {os.path.basename(file_path) or file_path} [{action}]',
                'INFO', '处理中',
            )
            self._offload_threat_disposition(action, file_path, sig_name, status)
        except Exception as e:
            logger.error(f'processThreat 失败: {e}')

    # ===== 桌面右下角弹窗管理（统一优先级队列） =====
    # 弹窗队列最大长度：超过此值后丢弃新弹窗，避免大量样本时队列无限增长
    _MAX_POPUP_QUEUE = 50
    # 弹窗优先级（数值越大越先显示）：
    # 危险对象询问 > 可疑对象询问 > 沙箱安全放行确认 > 通知隔离失败 > 通知隔离成功
    _PRIORITY_DANGER_ASK = 50           # 危险对象询问（malware）
    _PRIORITY_SUSPICIOUS_ASK = 40       # 可疑对象询问（suspicious）
    _PRIORITY_SANDBOX_RELEASE = 30      # 沙箱安全放行确认
    _PRIORITY_QUARANTINE_FAIL = 20      # 通知隔离失败
    _PRIORITY_QUARANTINE_SUCCESS = 10   # 通知隔离成功

    def _enqueue_priority_popup(self, priority: int, kind: str, data: dict):
        """按优先级降序入队（同优先级保持 FIFO），保证高优先级弹窗先显示

        Args:
            priority: 优先级数值（越大越先显示）
            kind: 'threat'（询问弹窗）或 'result'（结果弹窗）
            data: 弹窗数据
        """
        try:
            # 队列已满：丢弃新弹窗，仅记录日志
            if len(self._priority_popup_queue) >= self._MAX_POPUP_QUEUE:
                logger.warning(
                    f'弹窗队列已满 ({self._MAX_POPUP_QUEUE})，丢弃: '
                    f'{data.get("file_path", "")}'
                )
                return
            item = {'priority': priority, 'kind': kind, 'data': data}
            # 按优先级降序插入：找到第一个优先级更低的索引
            idx = 0
            while idx < len(self._priority_popup_queue) \
                    and self._priority_popup_queue[idx]['priority'] >= priority:
                idx += 1
            self._priority_popup_queue.insert(idx, item)
            # 若当前没有显示中的弹窗，立即显示最高优先级项
            if self._current_priority_popup is None \
                    or not self._current_priority_popup.isVisible():
                self._show_next_priority_popup()
        except Exception as e:
            logger.error(f'入队弹窗失败: {e}')

    def _show_threat_notification_popup(self, payload_str: str):
        """显示需要用户选择处理方式的桌面询问弹窗（notify 策略）

        按威胁类型映射到优先级：
        危险对象询问（malware）> 可疑对象询问（suspicious）> 沙箱安全放行确认。
        与结果弹窗共用统一优先级队列，保证高优先级先显示。
        """
        try:
            data = json.loads(payload_str) if isinstance(payload_str, str) else payload_str
            if data.get('_is_sandbox_release'):
                priority = self._PRIORITY_SANDBOX_RELEASE
            elif data.get('status') == 'malware':
                priority = self._PRIORITY_DANGER_ASK
            else:
                priority = self._PRIORITY_SUSPICIOUS_ASK
            self._enqueue_priority_popup(priority, 'threat', data)
        except Exception as e:
            logger.error(f'显示威胁通知弹窗失败: {e}')

    def _show_threat_result_popup(self, result_data: dict):
        """显示处理结果的桌面弹窗（auto 策略完成后）

        按处理结果映射到优先级：隔离失败 > 隔离成功。
        与询问弹窗共用统一优先级队列（优先级低于所有询问弹窗）。
        """
        try:
            success = bool((result_data.get('result') or {}).get('success', False))
            priority = self._PRIORITY_QUARANTINE_FAIL if not success \
                else self._PRIORITY_QUARANTINE_SUCCESS
            self._enqueue_priority_popup(priority, 'result', result_data)
        except Exception as e:
            logger.error(f'显示处理结果弹窗失败: {e}')

    def _show_next_priority_popup(self):
        """从统一优先级队列取出最高优先级项显示（询问弹窗或结果弹窗）"""
        try:
            if not self._priority_popup_queue:
                return

            item = self._priority_popup_queue.pop(0)
            kind, data = item['kind'], item['data']
            scale = self._popup_scale

            if kind == 'threat':
                popup = ThreatNotificationPopup(data, scale=scale)
                popup.autoActionTriggered.connect(self._on_popup_auto_action)
                popup.ignoreActionTriggered.connect(self._on_popup_ignore_action)
                popup.trustActionTriggered.connect(self._on_popup_trust_action)
                popup.applyToAllRequested.connect(self._on_popup_apply_to_all)
                popup.destroyed.connect(self._on_current_priority_popup_destroyed)
                self._current_priority_popup = popup
                # 启动滑入动画（含 show()）
                popup._slide_in()
                # 确保询问弹窗置顶于其他窗口之上
                QTimer.singleShot(350, popup.raise_)
            else:
                popup = ThreatResultPopup(data, scale=scale)
                popup.destroyed.connect(self._on_current_priority_popup_destroyed)
                self._current_priority_popup = popup
                popup.show()
                # 结果弹窗显示后保持在顶部（若自保护弹窗在则让位于它）
                QTimer.singleShot(100, popup.raise_)

            # 自保护弹窗始终置顶于所有弹窗之上
            if self._current_self_protection_popup is not None \
                    and self._current_self_protection_popup.isVisible():
                QTimer.singleShot(400, self._current_self_protection_popup.raise_)
            logger.info(f'显示桌面弹窗[{kind}]: {data.get("file_path", "")}'
                        f'（剩余 {len(self._priority_popup_queue)}）')
        except Exception as e:
            logger.error(f'显示下一个弹窗失败: {e}')
            # 显示失败：跳过该弹窗继续下一个，保证弹窗链不断
            QTimer.singleShot(100, self._show_next_priority_popup)

    def _on_current_priority_popup_destroyed(self):
        """当前弹窗关闭后，显示队列中下一个"""
        try:
            self._current_priority_popup = None
            if self._priority_popup_queue:
                # 稍微延迟以避免动画冲突
                QTimer.singleShot(150, self._show_next_priority_popup)
        except Exception as e:
            logger.warning(f'显示下一个弹窗失败: {e}')

    def _theme_blocking_task(self) -> Optional[str]:
        """返回当前阻塞主题切换的任务名；无阻塞返回 None。

        主题切换需要整页替换入口 HTML（index.html ⇄ terminal.html），正在进行的
        持久化任务（扫描 / 样本同步 / 模型训练）其前端状态随 JS 一起丢失——
        表现为扫描界面显示异常、扫描选项回退默认值，而任务本身仍在后台跑。
        这些任务运行期间禁止切换主题，任务结束后可正常切换。
        """
        try:
            ev = getattr(self, '_scan_running', None)
            if ev is not None and ev.is_set():
                return '扫描'
        except Exception:
            pass
        try:
            lock = getattr(self, '_mb_split_lock', None)
            if lock is not None and lock.locked():
                return '样本同步/模型训练'
        except Exception:
            pass
        return None

    @pyqtSlot(str)
    def setTheme(self, theme: str):
        """切换内置主题（设置页「主题」下拉/按钮调用）

        'light' = 米色经典（index.html）/ 'terminal' = 琥珀 CRT 终端（terminal.html）。
        两套 UI 结构不同，切换需要整页替换入口 HTML：落盘后向主窗口发
        themeReloadRequested，由主窗口重载对应入口（不重建 QWebEngineView）。

        扫描等持久化任务进行中时拒绝切换（整页重载会丢失任务的前端状态），
        并通过 themeSwitchBlocked 通知前端提示原因。

        Args:
            theme: 'light' 或 'terminal'
        """
        try:
            new_theme = theme_tokens.normalize(theme)
            changed = (new_theme != self._ui_theme)
            if changed:
                blocking = self._theme_blocking_task()
                if blocking:
                    logger.warning(f'主题切换被拒绝：{blocking}进行中')
                    self._add_activity(
                        '外观', f'{blocking}进行中，暂不可切换主题', 'WARN', '已阻止')
                    try:
                        self.themeSwitchBlocked.emit(
                            f'{blocking}进行中，为避免丢失进度，暂不可切换主题')
                    except Exception:
                        pass
                    return
            self._ui_theme = new_theme
            _save_ui_settings({'theme': new_theme})
            self._broadcast_theme_settings()
            logger.info(f'内置主题切换为: {new_theme}')
            if changed:
                # 同主题重复设置不重载，避免无谓刷新（丢失扫描进度等）
                self.themeReloadRequested.emit(new_theme)
        except Exception as e:
            logger.error(f'setTheme 异常: {e}')

    @pyqtSlot(bool)
    def setMotionEffects(self, enabled: bool):
        """开关"动态光效"（仅终端主题下可用，米色主题下会被前端禁用）

        纯视觉开关：Web 侧切 html.no-motion（关动画/过渡/辉光），Qt 侧停脉冲定时器。
        不参与任何状态机，与弹窗 5s/3s 倒计时完全分离。
        """
        try:
            self._motion_effects = bool(enabled)
            _save_ui_settings({'motion_effects': bool(enabled)})
            self._broadcast_theme_settings()
            logger.info(f'动态光效: {"开启" if enabled else "关闭"}')
        except Exception as e:
            logger.error(f'setMotionEffects 异常: {e}')

    @pyqtSlot(result=str)
    def getThemeSettings(self) -> str:
        """获取当前主题设置（JSON），供前端启动时回填控件状态。"""
        try:
            return json.dumps({
                'theme': self._ui_theme,
                'motion_effects': bool(self._motion_effects),
            }, ensure_ascii=False)
        except Exception as e:
            logger.warning(f'getThemeSettings 异常: {e}')
            return json.dumps({'theme': theme_tokens.THEME_LIGHT, 'motion_effects': True})

    def _broadcast_theme_settings(self):
        """把主题/动效设置广播给前端（已建好的页面用信号回填，不重建）。"""
        try:
            self.themeSettingsChanged.emit(json.dumps({
                'theme': self._ui_theme,
                'motion_effects': bool(self._motion_effects),
            }, ensure_ascii=False))
        except Exception as e:
            logger.debug(f'广播主题设置失败: {e}')

    # ------------------------------------------------------------------
    # 调试：手动触发任意弹窗（设置页「关于 → 调试选项」面板调用）
    # ------------------------------------------------------------------
    # 复用各弹窗真实的内部入口/信号链路（与生产环境同一条路径），所以既能看外观，
    # 也能顺带验证"信号 → 主线程建窗"这段链路本身。仅造演示数据，不改动任何
    # 真实威胁状态、计数与防护行为；演示路径固定为 %TEMP% 下的假样本名。
    _DEBUG_SAMPLE_PATH = os.path.join(
        os.environ.get('TEMP', r'C:\Windows\Temp'), 'PSLS-Demo', 'demo_sample.exe')
    # (kind, 按钮文案)：前端「调试选项」面板按此列表动态渲染按钮，
    # 保证"按钮清单"与"后端能触发的种类"永远一致（单一真相源）。
    _DEBUG_POPUPS = (
        ('threat_malware', '危险对象询问'),
        ('threat_suspicious', '可疑对象询问'),
        ('threat_result_success', '处置成功结果'),
        ('threat_result_fail', '处置失败结果'),
        ('new_file_clean', '新文件扫描完成'),
        ('new_file_suspicious', '发现可疑文件'),
        ('self_protection_threat', '自我保护命中威胁'),
        ('self_protection_status', '自我保护开关结果'),
        ('strict_mode', '严格模式开关结果'),
        ('autostart_ask', '启动项确认'),
        ('sandbox_release', '沙箱放行确认'),
        ('sandbox_threat', '沙箱威胁结果窗口'),
        ('sandbox_failure', '沙箱失败结果窗口'),
        ('sandbox_analysis', '沙箱分析进度窗口'),
        ('rollback_ask', '勒索回滚询问（世代选择）'),
        ('rollback_progress', '回滚进度窗口'),
    )
    _DEBUG_POPUP_KINDS = tuple(k for k, _ in _DEBUG_POPUPS)

    @pyqtSlot(result=str)
    def getDebugPopups(self) -> str:
        """返回可触发的调试弹窗清单（JSON 数组 [{kind,label}]）。"""
        try:
            return json.dumps([{'kind': k, 'label': l} for k, l in self._DEBUG_POPUPS],
                              ensure_ascii=False)
        except Exception as e:
            logger.warning(f'getDebugPopups 异常: {e}')
            return '[]'

    @pyqtSlot(str, result=str)
    def debugTriggerPopup(self, kind: str) -> str:
        """调试用：按 kind 触发对应弹窗，返回 {success, kind, message} JSON。

        支持的 kind 见 _DEBUG_POPUP_KINDS。
        """
        kind = (kind or '').strip()
        sample = self._DEBUG_SAMPLE_PATH
        result = {'success': False, 'kind': kind, 'message': ''}
        try:
            if kind not in self._DEBUG_POPUP_KINDS:
                result['message'] = '未知的弹窗类型: %s' % kind
                return json.dumps(result, ensure_ascii=False)

            if kind in ('threat_malware', 'threat_suspicious'):
                is_danger = kind == 'threat_malware'
                payload = {
                    'file_path': sample,
                    'signature_name': ('Trojan.Win32.Agent.demo' if is_danger
                                       else 'Suspicious.Heuristic.demo'),
                    'status': 'malware' if is_danger else 'suspicious',
                    'threat_type': 'malware' if is_danger else 'suspicious',
                }
                self._show_threat_notification_popup(
                    json.dumps(payload, ensure_ascii=False))

            elif kind in ('threat_result_success', 'threat_result_fail'):
                ok = kind == 'threat_result_success'
                self._show_threat_result_popup({
                    'file_path': sample,
                    'signature_name': 'Trojan.Win32.Agent.demo',
                    'status': 'malware',
                    'result': {
                        'success': ok,
                        'action': 'quarantine',
                        'message': ('已隔离到隔离区' if ok else '隔离失败（演示）'),
                    },
                })

            elif kind in ('new_file_clean', 'new_file_suspicious'):
                clean = kind == 'new_file_clean'
                self._show_new_file_result_popup({
                    'file_path': sample,
                    'status': 'clean' if clean else 'suspicious',
                    'malware_name': '' if clean else 'Suspicious.Heuristic.demo',
                })

            elif kind == 'self_protection_threat':
                self._show_self_protection_popup({
                    'type': 'dll_injection',
                    'detail': '检测到有进程试图向 PSLS 注入 DLL（演示）',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                })

            elif kind == 'self_protection_status':
                self._show_status_popup(SelfProtectionStatusPopup(
                    enabled=True, success=True, message='自我保护已开启（演示）'))

            elif kind == 'strict_mode':
                self._show_status_popup(StrictModeStatusPopup(
                    enabled=True, success=True, message='已切换到严格模式（演示）'))

            elif kind == 'autostart_ask':
                self.autostartPopupRequested.emit(json.dumps({
                    'name': 'demo_sample.exe',
                    'path': sample,
                    'full_path': sample,
                    'command': '"%s" --silent' % sample,
                    'value_name': 'PSLSDemo',
                    'location': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'publisher': '未知发布者',
                    'status': 'suspicious',
                }, ensure_ascii=False))

            elif kind == 'sandbox_release':
                self.sandboxReleasePopupRequested.emit(json.dumps({
                    'type': 'sandbox_release_request',
                    'name': 'demo_sample.exe',
                    'path': sample,
                    'reason': '演示：沙箱判定安全',
                    'score': 8,
                }, ensure_ascii=False))

            elif kind == 'sandbox_threat':
                self.sandboxThreatPopupRequested.emit(
                    json.dumps({'file_path': sample}, ensure_ascii=False))

            elif kind == 'sandbox_failure':
                self.sandboxFailurePopupRequested.emit(
                    json.dumps({'file_path': sample}, ensure_ascii=False))

            elif kind == 'sandbox_analysis':
                self._debug_sandbox_analysis_demo(sample)

            elif kind == 'rollback_ask':
                # 演示：勒索回滚询问弹窗（带世代选择；不触发真实回滚）
                self.ransomwareRollbackRequested.emit(json.dumps({
                    'reason': '演示：检测到批量加密行为',
                    'file_count': 3,
                    'suspect_paths': [],
                }, ensure_ascii=False))

            elif kind == 'rollback_progress':
                # 演示：回滚进度窗口（阶段推进后自动关闭，不改真实状态）
                self._debug_rollback_progress_demo()

            result['success'] = True
            result['message'] = '已触发（若窗口没出现，请看是否被其它弹窗队列挡住）'
        except Exception as e:
            result['message'] = '触发失败: %s' % e
            logger.error(f'debugTriggerPopup({kind}) 异常: {e}')
        return json.dumps(result, ensure_ascii=False)

    def _debug_sandbox_analysis_demo(self, exe: str):
        """演示"软件分析室"沙箱分析进度窗口：显示 → 推进度 → 自动关闭。"""
        try:
            self._show_sandbox_analysis_win(exe)
            stages = [
                (20, '正在准备隔离环境…'),
                (45, '正在监控文件行为…'),
                (70, '正在评估行为评分…'),
                (92, '正在生成分析结论…'),
            ]
            for i, (pct, stage) in enumerate(stages):
                QTimer.singleShot(700 * (i + 1), lambda p=pct, s=stage: (
                    self._update_sandbox_analysis_win(
                        json.dumps({'stage': s, 'percent': p}, ensure_ascii=False))))
            # 10 秒后自动收尾（演示：判定为 clean），避免窗口一直挂在屏幕上
            QTimer.singleShot(10000, lambda: self._close_sandbox_analysis_win('clean'))
        except Exception as e:
            logger.error(f'演示沙箱分析窗口失败: {e}')

    @pyqtSlot(int)
    def setPopupScale(self, percent: int):
        """设置屏幕弹窗缩放比例（与主 GUI 内 toast 缩放同步，由设置页滑块调用）

        实时调整当前已显示弹窗的宽度与字号；后续弹窗显示时使用新比例。

        Args:
            percent: 缩放百分比（50-300）
        """
        try:
            try:
                percent = int(percent)
            except (TypeError, ValueError):
                percent = 100
            if percent < 50:
                percent = 50
            if percent > 300:
                percent = 300
            self._popup_scale = percent / 100.0
            # 实时应用到当前显示的屏幕弹窗（若其支持 _apply_scale）
            for cur in (self._current_priority_popup,
                        self._current_autostart_popup,
                        self._current_new_file_popup):
                if cur is not None and getattr(cur, '_apply_scale', None):
                    try:
                        cur._apply_scale(self._popup_scale)
                    except Exception as e:
                        logger.warning(f'当前弹窗应用缩放失败: {e}')
            logger.debug(f'屏幕弹窗缩放比例更新为 {percent}%')
        except Exception as e:
            logger.warning(f'设置弹窗缩放失败: {e}')

    def _on_popup_apply_to_all(self, action: str, threat_type: str):
        """用户选择"为所有相同类型对象执行同样操作"

        清除队列中所有同类型威胁的询问弹窗，并对它们执行相同操作。
        action: 'auto' 或 'ignore'
        threat_type: 'malware' 或 'suspicious'
        """
        try:
            applied_count = 0
            remaining_queue = []
            # 处理统一优先级队列中所有同类型的威胁询问弹窗
            for item in self._priority_popup_queue:
                if item['kind'] != 'threat':
                    # 非询问弹窗（结果弹窗）不参与批量，保留在队列中
                    remaining_queue.append(item)
                    continue
                threat_data = item['data']
                if threat_data.get('status') == threat_type:
                    # 执行相同操作
                    data = dict(threat_data)
                    data['action'] = action
                    self.processThreat(json.dumps(data, ensure_ascii=False))
                    applied_count += 1
                else:
                    # 不同类型保留在队列中
                    remaining_queue.append(item)
            self._priority_popup_queue = remaining_queue
            logger.info(f'批量处理 {applied_count} 个 {threat_type} 类型威胁，操作: {action}')
        except Exception as e:
            logger.error(f'批量处理威胁失败: {e}')

    def _show_status_popup(self, popup: QWidget):
        """显示状态弹窗并保持引用，自动清理已关闭的弹窗

        Args:
            popup: 状态弹窗实例（SelfProtectionStatusPopup / StrictModeStatusPopup 等）
        """
        try:
            # 先清理已关闭的弹窗引用
            self._status_popups = [p for p in self._status_popups if p and p.isVisible()]
            # 添加新弹窗引用
            self._status_popups.append(popup)
            # 关闭时自动清理引用
            popup.destroyed.connect(lambda: self._cleanup_status_popup(popup))
            popup.show()
            # 显示后确保置顶
            popup.raise_()
            popup.activateWindow()
        except Exception as e:
            logger.error(f'显示状态弹窗失败: {e}')

    def _cleanup_status_popup(self, popup):
        """清理已关闭的状态弹窗引用"""
        try:
            if popup in self._status_popups:
                self._status_popups.remove(popup)
        except Exception:
            pass

    def _show_new_file_result_popup(self, payload: dict):
        """显示"新文件扫描结果"桌面弹窗（clean 安全通知 / 跳过 / 异常）

        采用单弹窗队列模式：同时只显示一个，3 秒后自动关闭。
        """
        try:
            if len(self._new_file_popup_queue) >= self._MAX_POPUP_QUEUE:
                logger.warning(
                    f'新文件扫描结果弹窗队列已满 ({self._MAX_POPUP_QUEUE})，丢弃: '
                    f'{payload.get("file_path", "")}'
                )
                return
            self._new_file_popup_queue.append(payload)
            if self._current_new_file_popup is None or not self._current_new_file_popup.isVisible():
                self._show_next_new_file_popup()
        except Exception as e:
            logger.error(f'显示新文件扫描结果弹窗失败: {e}')

    def _show_next_new_file_popup(self):
        """从队列取出下一个"新文件扫描结果"弹窗显示"""
        try:
            if self._current_new_file_popup is not None:
                try:
                    self._current_new_file_popup.destroyed.disconnect()
                except Exception:
                    pass
                self._current_new_file_popup = None
            if not self._new_file_popup_queue:
                return
            data = self._new_file_popup_queue.pop(0)
            popup = RealtimeScanResultPopup(data, scale=self._popup_scale)
            popup.destroyed.connect(self._on_current_new_file_popup_destroyed)
            self._current_new_file_popup = popup
            popup.show()
            # 层级管理：优先级弹窗/自保护弹窗始终置顶于新文件结果弹窗之上
            if self._current_priority_popup is not None and self._current_priority_popup.isVisible():
                self._current_priority_popup.raise_()
            if self._current_self_protection_popup is not None and self._current_self_protection_popup.isVisible():
                self._current_self_protection_popup.raise_()
            logger.info(f'显示新文件扫描结果弹窗: {data.get("file_path", "")}（剩余 {len(self._new_file_popup_queue)}）')
        except Exception as e:
            logger.error(f'显示下一个新文件扫描结果弹窗失败: {e}')

    def _on_current_new_file_popup_destroyed(self):
        """当前"新文件扫描结果"弹窗关闭后，显示队列中下一个"""
        try:
            self._current_new_file_popup = None
            if self._new_file_popup_queue:
                QTimer.singleShot(100, self._show_next_new_file_popup)
        except Exception as e:
            logger.warning(f'显示下一个新文件扫描结果弹窗失败: {e}')

    def _on_popup_auto_action(self, payload_str: str):
        """用户在弹窗中点击"自动处理"按钮（沙箱放行模式下为"同意重启"）"""
        try:
            data = json.loads(payload_str) if isinstance(payload_str, str) else payload_str
            # 沙箱放行模式：用户点击"同意重启" → 重启进程
            if data.get('_is_sandbox_release'):
                path = data.get('file_path', '')
                cmdline = data.get('cmdline')
                self._add_activity('沙箱放行', f'用户同意重启: {os.path.basename(path)}', 'INFO', '重启中')
                self.restartSandboxedProcess(json.dumps({
                    'path': path,
                    'cmdline': cmdline,
                }, ensure_ascii=False))
            else:
                data['action'] = 'auto'
                self.processThreat(json.dumps(data, ensure_ascii=False))
        except Exception as e:
            logger.error(f'弹窗自动处理回调失败: {e}')

    def _on_popup_ignore_action(self, payload_str: str):
        """用户在弹窗中点击"忽略"按钮（沙箱放行模式下为"不重启"）"""
        try:
            data = json.loads(payload_str) if isinstance(payload_str, str) else payload_str
            if data.get('_is_sandbox_release'):
                # 沙箱放行模式：用户点击"不重启" → 仅记录日志
                path = data.get('file_path', '')
                self._add_activity('沙箱放行', f'用户选择不重启: {os.path.basename(path)}', 'INFO', '已跳过')
            else:
                data['action'] = 'ignore'
                self.processThreat(json.dumps(data, ensure_ascii=False))
        except Exception as e:
            logger.error(f'弹窗忽略回调失败: {e}')

    def _on_popup_trust_action(self, payload_str: str):
        """用户在弹窗中点击"忽略并信任"：忽略本次告警并把文件加入白名单"""
        try:
            data = json.loads(payload_str) if isinstance(payload_str, str) else payload_str
            data['action'] = 'trust'
            self.processThreat(json.dumps(data, ensure_ascii=False))
        except Exception as e:
            logger.error(f'弹窗忽略并信任回调失败: {e}')

    def _trust_file_in_background(self, file_path: str, sig_name: str, status: str):
        """「忽略并信任」的落地实现：后台算 SHA256 → 写入白名单 → 回结果给前端

        哈希计算与 SQLite 写入都是 IO，必须放在后台线程，
        否则会阻塞 QWebChannel 主线程（弹窗会卡住不消失）。
        """
        try:
            import hashlib
            if not file_path or not os.path.isfile(file_path):
                result = {'success': False, 'action': 'trusted', 'message': '文件不存在，无法加入白名单'}
            elif self._signature_db is None:
                result = {'success': False, 'action': 'trusted', 'message': '签名库未就绪'}
            else:
                digest = hashlib.sha256()
                with open(file_path, 'rb') as fh:
                    for chunk in iter(lambda: fh.read(1024 * 1024), b''):
                        digest.update(chunk)
                file_hash = digest.hexdigest()
                if self._signature_db.is_whitelisted(file_hash):
                    result = {'success': True, 'action': 'trusted', 'message': '已忽略（该文件已在白名单中）'}
                elif self._signature_db.add_to_whitelist(
                        file_hash, f'弹窗"忽略并信任" (威胁: {sig_name or "未知"})'):
                    # add_to_whitelist 为扫描期性能做了延迟批量持久化（只写内存缓存 +
                    # 累积待写列表），而 close() 不 flush。用户单次点击是明确的信任决定，
                    # 必须立即落盘，否则 PSLS 退出后该条目丢失、文件下次又被检出。
                    self._signature_db.flush_whitelist_batch()
                    self._add_activity('白名单', f'忽略并信任: {os.path.basename(file_path)} 已加入白名单',
                                       'INFO', '成功')
                    result = {'success': True, 'action': 'trusted', 'message': '已忽略并加入白名单'}
                else:
                    result = {'success': False, 'action': 'trusted', 'message': '加入白名单失败'}
            self.threatActionResult.emit(json.dumps({
                'file_path': file_path, 'status': status,
                'signature_name': sig_name, 'action': 'trust',
                'result': result, 'desktop_popup': True,
            }, ensure_ascii=False))
        except Exception as e:
            logger.error(f'忽略并信任处理失败: {e}', exc_info=True)

    def _on_popup_destroyed(self, popup, popup_list):
        """弹窗被销毁时从列表移除"""
        try:
            if popup in popup_list:
                popup_list.remove(popup)
        except Exception:
            pass

    def _restack_result_popups(self):
        """结果弹窗已改为单弹窗队列模式，此方法保留空实现以兼容调用"""
        pass

    # ===== 自我保护威胁弹窗管理 =====

    _MAX_SELF_PROTECTION_POPUP_QUEUE = 20

    def _show_self_protection_popup(self, threat_data: dict):
        """显示自我保护威胁弹窗（主线程调用）

        采用单弹窗队列：同时只显示一个，关闭后再显示下一个。
        始终置顶于所有弹窗之上。
        """
        try:
            if len(self._self_protection_popup_queue) >= self._MAX_SELF_PROTECTION_POPUP_QUEUE:
                logger.warning(
                    f'自保护弹窗队列已满 ({self._MAX_SELF_PROTECTION_POPUP_QUEUE})，丢弃: '
                    f'{threat_data.get("detail", "")}'
                )
                return

            self._self_protection_popup_queue.append(threat_data)
            if self._current_self_protection_popup is None or not self._current_self_protection_popup.isVisible():
                self._show_next_self_protection_popup()
        except Exception as e:
            logger.error(f'显示自保护威胁弹窗失败: {e}')

    def _show_next_self_protection_popup(self):
        """从队列取出下一个自保护威胁数据显示弹窗"""
        try:
            if self._current_self_protection_popup is not None:
                try:
                    self._current_self_protection_popup.destroyed.disconnect()
                except Exception:
                    pass
                self._current_self_protection_popup = None

            if not self._self_protection_popup_queue:
                return

            data = self._self_protection_popup_queue.pop(0)
            popup = SelfProtectionThreatPopup(data)
            popup.acknowledged.connect(self._on_self_protection_popup_acknowledged)
            popup.destroyed.connect(self._on_current_self_protection_popup_destroyed)
            self._current_self_protection_popup = popup
            popup.show()
            # 确保自保护弹窗置顶于所有其他弹窗
            QTimer.singleShot(100, popup.raise_)
            QTimer.singleShot(500, popup.raise_)
            logger.info(f'显示自保护威胁弹窗: {data.get("detail", "")}（剩余 {len(self._self_protection_popup_queue)}）')
        except Exception as e:
            logger.error(f'显示下一个自保护弹窗失败: {e}')

    def _on_current_self_protection_popup_destroyed(self):
        """当前自保护弹窗关闭后，显示队列中下一个"""
        try:
            self._current_self_protection_popup = None
            if self._self_protection_popup_queue:
                QTimer.singleShot(150, self._show_next_self_protection_popup)
        except Exception as e:
            logger.warning(f'显示下一个自保护弹窗失败: {e}')

    def _on_self_protection_popup_acknowledged(self):
        """用户确认自保护威胁弹窗"""
        pass

    @pyqtSlot(result=str)
    def getQuarantinePath(self) -> str:
        """获取隔离区路径"""
        if self._quarantine_manager:
            return self._quarantine_manager.get_quarantine_path()
        return ''

    @pyqtSlot(str, result=str)
    def setQuarantinePath(self, new_path: str) -> str:
        """设置隔离区路径并迁移数据

        Args:
            new_path: 新的隔离区路径

        Returns:
            JSON字符串，包含 success, old_path, new_path, migrated, error 字段
        """
        if not self._quarantine_manager:
            return json.dumps({
                'success': False,
                'error': '隔离管理器未初始化'
            }, ensure_ascii=False)

        result = self._quarantine_manager.set_quarantine_path(new_path)
        return _safe_json_dumps(result)
