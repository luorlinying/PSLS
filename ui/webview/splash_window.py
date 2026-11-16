#!/usr/bin/env python3
"""
启动加载界面（Splash）窗口 —— 纯 Qt 自绘实现

对齐 sertraline-splash.design 的暗色设计稿（参考图2）。
精确像素对齐：757×373 画布，36/28/20 外边距，双 auto-margin 布局。
"""

import os
import sys
import time
import traceback
from datetime import datetime

from PyQt5.QtCore import Qt, QTimer, QRectF, QPointF, QEventLoop
from PyQt5.QtGui import (
    QPainter, QColor, QLinearGradient, QRadialGradient, QPen, QFont,
    QPainterPath, QFontMetrics
)
from PyQt5.QtWidgets import QWidget


def _splash_debug(msg):
    try:
        with open(os.path.join(os.path.expanduser('~'), 'psls_debug.log'), 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now()}] [SPLASH] {msg}\n")
    except Exception:
        pass


# —— 配色 ——
# 启动页历史上是"深色 + 绿色强调"的独立设计；这里把它也纳入两套内置主题：
#   米色主题（默认）-> 保持原有深绿启动页（逐像素不变）
#   终端主题       -> 换成琥珀 CRT 深底
# 绘制代码统一读下面的模块级全局量，构造时调用 _apply_theme() 刷新一次即可。
C_PRIMARY     = QColor('#1db954')
C_PRIMARY_2   = QColor('#17a34a')
C_FG          = QColor('#e8eaed')  # 主文字
C_MUTED       = QColor('#9aa0a6')  # 次级文字
C_FAINT       = QColor('#4a5568')  # 最弱文字
C_LOG_TIME    = QColor('#4a5568')  # 日志时间戳
C_LOG_DONE    = QColor('#5a7a6a')  # 已完成日志文字
C_BG_DONE     = QColor(29, 185, 84)  # 已完成对勾/路径
C_PENDING     = QColor('#4a5568')    # 未完成行（更灰）

C_BG_TOP = QColor('#0a0e14')
C_BG_MID = QColor('#0d1520')
C_BG_BTM = QColor('#0a1414')

# 字体族（终端主题下切等宽）
_FONT_SANS = 'Segoe UI'
_FONT_MONO = 'Consolas'


def _acc(alpha: int) -> QColor:
    """取当前强调色并附上透明度（用于渐变/描边等半透明强调色）。"""
    return QColor(C_PRIMARY.red(), C_PRIMARY.green(), C_PRIMARY.blue(), alpha)


def _apply_theme():
    """按当前内置主题刷新启动页配色与字体。"""
    global C_PRIMARY, C_PRIMARY_2, C_FG, C_MUTED, C_FAINT, C_LOG_TIME, C_LOG_DONE
    global C_BG_DONE, C_PENDING, C_BG_TOP, C_BG_MID, C_BG_BTM, _FONT_SANS, _FONT_MONO
    try:
        from ui.webview import theme_tokens
        is_terminal = theme_tokens.load_theme() == theme_tokens.THEME_TERMINAL
    except Exception:
        is_terminal = False
    if not is_terminal:
        C_PRIMARY = QColor('#1db954')
        C_PRIMARY_2 = QColor('#17a34a')
        C_FG = QColor('#e8eaed')
        C_MUTED = QColor('#9aa0a6')
        C_FAINT = QColor('#4a5568')
        C_LOG_TIME = QColor('#4a5568')
        C_LOG_DONE = QColor('#5a7a6a')
        C_BG_DONE = QColor(29, 185, 84)
        C_PENDING = QColor('#4a5568')
        C_BG_TOP = QColor('#0a0e14')
        C_BG_MID = QColor('#0d1520')
        C_BG_BTM = QColor('#0a1414')
        _FONT_SANS = 'Segoe UI'
        _FONT_MONO = 'Consolas'
        return
    # 琥珀 CRT 终端
    C_PRIMARY = QColor('#FF9500')
    C_PRIMARY_2 = QColor('#CC7700')
    C_FG = QColor('#FFB347')
    C_MUTED = QColor('#8B6914')
    C_FAINT = QColor('#5c4a20')
    C_LOG_TIME = QColor('#5c4a20')
    C_LOG_DONE = QColor('#CC7700')
    C_BG_DONE = QColor(255, 149, 0)
    C_PENDING = QColor('#5c4a20')
    C_BG_TOP = QColor('#0a0700')
    C_BG_MID = QColor('#0d0900')
    C_BG_BTM = QColor('#0a0700')
    _FONT_SANS = 'Courier New'
    _FONT_MONO = 'Courier New'


# —— 精确布局常量（像素级） ——
# 基于 CSS flex column + 双 margin-top:auto 推算：
#   可用高度 = 373 - 28(top) - 20(bot) = 325
#   固定区 = 50(header) + 30(status+mb) + 6(mt) + 24(progress) + 24(footer) = 134
#   日志区 = 325 - 134 - 2×39(auto) = 113
#   7 行 × 16px + 6×1px gap = 118 ... 实测用 16px 行高 × 7 = 112 刚好
W = 757            # SPLASH_WIDTH
H = 373            # SPLASH_HEIGHT
MX = 36            # 左右外边距
MY_TOP = 28        # 顶部外边距
MY_BOT = 20        # 底部外边距

# Y 坐标（精确像素对齐）
Y_HEADER_TOP = 28
Y_HEADER_BOT = 78          # 28 + 44(icon) + 6(margin-bottom)
Y_STATUS_TOP = 117         # 78 + 39(auto margin)
Y_STATUS_BOT = 147         # 117 + 20 + 10(margin-bottom)
Y_PROGRESS_TOP = 153       # 147 + 6(margin-top)
Y_TRACK_TOP = 173          # 153 + 14(label) + 6(gap)
Y_LOG_TOP = 177            # 153 + 24(progress section)
# footer 已移除，日志区撑满到底部外边距
Y_LOG_BOT = H - MY_BOT     # 373 - 20 = 353

LOG_LINE_H = 16
LOG_MAX_LINES = 10


# —— 版本号（项目单一来源；打包脚本/安装器需同步）——
APP_VERSION = 'V26.2.0beta'


class SplashWindow(QWidget):
    """精确对齐设计稿的启动加载界面"""

    # 初始化阶段（与 PSLS 真实启动链路对齐）
    # 每个 phase 同时定义对应的日志文案 —— phase 开始时日志追加一条 active，
    # 下一 phase 开始时上一条变 done。动态时间在运行时由 _advance_phase 填充。
    PHASES = [
        (0,   '正在初始化安全引擎核心…',       '安全引擎核心初始化完成'),
        (14,  '正在加载签名数据库…',           '签名数据库加载完成'),
        (28,  '正在加载扫描引擎模块…',         '扫描引擎模块加载完成'),
        (42,  '正在加载机器学习模型…',         '机器学习模型加载完成'),
        (56,  '正在初始化隔离管理器…',         '隔离管理器初始化完成'),
        (70,  '正在编译 YARA 规则集…',         'YARA 规则集编译完成'),
        (82,  '正在加载内核驱动 PSLS.sys…',    '内核驱动 PSLS.sys 注册完成'),
        (92,  '正在初始化实时防护…',           '实时防护进程监控启动完成'),
        (100, '所有模块加载完成 — 防护已激活', '所有模块就绪 — 防护已激活'),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        # 按当前内置主题刷新启动页配色（终端主题 -> 琥珀 CRT 深底）
        _apply_theme()
        self.setWindowTitle('PSLS - 正在启动')
        self.setWindowFlags(
            Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint
        )
        self.setFixedSize(W, H)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)

        self._phase_idx = 0
        self._anim_timer = None
        self._scan_timer = None
        self._pulse_t = 0.0
        self._scan_x = 0.0
        self._scan_dir = 1
        self._externally_driven = False
        self._ext_pct = 0
        self._ext_text = self.PHASES[0][1]
        self._ready_for_close = False

        # 运行时日志（time_str, text, status），由 _advance_phase 动态填充
        self._log_entries: list = []

    # ------------------------------------------------------------------ 对外接口
    def start(self):
        _splash_debug("SplashWindow.start() begin")
        try:
            self._phase_idx = 0
            # 初始化运行时日志：先把所有 phase 的日志条目以 pending 状态建好，
            # 时间戳在 phase 真正推进时填入（避免假时间）
            self._log_entries = [
                ('', phase[2], 'pending') for phase in self.PHASES
            ]
            # 第一条立即激活（启动即进入 phase 0）
            if self._log_entries:
                self._log_entries[0] = (
                    datetime.now().strftime('%H:%M:%S'),
                    self.PHASES[0][2], 'active')

            if self._anim_timer is None:
                self._anim_timer = QTimer(self)
                self._anim_timer.timeout.connect(self._advance_phase)
            if not self._externally_driven:
                self._anim_timer.start(700)
            if self._scan_timer is None:
                self._scan_timer = QTimer(self)
                self._scan_timer.timeout.connect(self._tick_anim)
            # "动态光效"关闭时不起扫描线动效（进度填充仍由 phase/真实进度驱动）
            try:
                from ui.webview import theme_tokens
                _motion_on = theme_tokens.load_motion()
            except Exception:
                _motion_on = True
            if _motion_on:
                self._scan_timer.start(40)
        except Exception as e:
            _splash_debug(f"start FAILED: {e}\n{traceback.format_exc()}")

    def update_progress(self, pct: int, stage_text: str):
        """外部（PyBridge 真实阶段）驱动的进度更新。

        调用后会：
          - 切换为外部驱动模式（停止自动 phase 动画）
          - 根据真实 pct 批量推进日志条目（之前的 done、当前的 active）
          - 更新进度百分比与阶段文案
          - 触发重绘
        """
        try:
            # clamp + 单调不减（外部已保证，此处兜底）
            p = max(0, min(100, int(pct)))
            if p < self._ext_pct:
                p = self._ext_pct
            self._ext_pct = p
            if stage_text:
                self._ext_text = str(stage_text).splitlines()[0]
            self._externally_driven = True
            # 关闭自动 phase 动画（避免模拟阶段与真实阶段来回跳）
            if self._anim_timer is not None:
                try:
                    self._anim_timer.stop()
                except Exception:
                    pass
            # ---- 根据真实 pct 批量推进日志条目 ----
            self._sync_log_from_pct(p)
            self.update()
        except Exception as e:
            _splash_debug(f"update_progress FAILED: {e}\n{traceback.format_exc()}")

    def _sync_log_from_pct(self, p: int):
        """根据进度百分比 p(0-100) 反推 phase，批量更新日志条目状态。

        逻辑：PHASES 每个条目有一个进度阈值，找到阈值 ≤ p 的最大 index = cur
        - index < cur  → done（填入当前时间戳，表示已完成）
        - index == cur → active（填入当前时间戳，表示正在进行）
        - index > cur  → pending（保持原样）

        这样不管 bridge 回调多么稀疏，每次都能把"应该已完成"的日志批量补到位。
        """
        if not self._log_entries:
            return
        now_str = datetime.now().strftime('%H:%M:%S')

        # 找到当前进度覆盖到的 phase index
        cur = 0
        for idx, (thresh, _txt, _log) in enumerate(self.PHASES):
            if thresh <= p:
                cur = idx
            else:
                break
        self._phase_idx = cur

        # 批量推进状态
        for i in range(len(self._log_entries)):
            ts, text, _ = self._log_entries[i]
            if i < cur:
                # 用第一次被标记为 done 的时间戳（后面不再覆盖，保留原始完成时刻）
                if not ts:
                    ts = now_str
                self._log_entries[i] = (ts, text, 'done')
            elif i == cur:
                # 保留已有的时间戳（自动定时器可能已经设置过），只更新状态
                self._log_entries[i] = (ts or now_str, text, 'active')
            else:
                # i > cur：必须回滚成 pending（清空时间戳）
                # 场景：bridge 第一次回调时，自动定时器可能已把后面的条目推到 active，
                # 但当前真实 pct 还没覆盖到，要把它们回退。
                self._log_entries[i] = ('', text, 'pending')

    def set_ready_for_close(self, ready: bool = True):
        """launchReady 触发后由主窗口调用：允许主窗口关闭 Splash。"""
        self._ready_for_close = bool(ready)
        if self._ready_for_close:
            # 终态：所有 phase 日志置 done，进度拉满
            try:
                if self._ext_pct < 100:
                    self._ext_pct = 100
                self._ext_text = '所有模块加载完成 — 防护已激活'
                self._sync_log_from_pct(100)
                self.update()
            except Exception:
                pass
            _splash_debug("SplashWindow.set_ready_for_close(True)")

    def is_ready_for_close(self) -> bool:
        return bool(self._ready_for_close)

    def _tick_anim(self):
        self._pulse_t += 0.06
        # 扫描线在进度条范围内来回移动
        track_left = MX
        track_right = W - MX
        self._scan_x += self._scan_dir * 3
        if self._scan_x >= track_right:
            self._scan_x = track_right
            self._scan_dir = -1
        elif self._scan_x <= track_left:
            self._scan_x = track_left
            self._scan_dir = 1
        self.update()
        # 心跳：主动排空 Qt 队列，避免启动阶段（WebEngine/Chromium 初始化）的
        # 短时阻塞导致 Windows 5 秒无消息判定为"未响应"。
        # 排除用户输入事件，避免在消息风暴中引发重入 paintEvent 死循环。
        try:
            from PyQt5.QtWidgets import QApplication
            QApplication.processEvents(
                Qt.QEventLoopFlags.ExcludeUserInputEvents
                if hasattr(Qt, 'QEventLoopFlags') else QEventLoop.ExcludeUserInputEvents
            )
        except Exception:
            pass

    def center_window(self):
        try:
            from PyQt5.QtWidgets import QApplication, QDesktopWidget
            screen = QApplication.desktop().screenGeometry()
            self.move((screen.width() - W) // 2,
                      (screen.height() - H) // 2)
        except Exception as e:
            _splash_debug(f"center_window failed: {e}")
        self.show()
        self.raise_()

    def close_splash(self):
        _splash_debug("SplashWindow.close_splash()")
        for t in (self._anim_timer, self._scan_timer):
            if t is not None:
                try:
                    t.stop()
                    t.deleteLater()
                except Exception:
                    pass
        self._anim_timer = None
        self._scan_timer = None
        try:
            self.hide()
        except Exception:
            pass
        try:
            self.deleteLater()
        except Exception:
            pass

    def closeEvent(self, event):
        self.close_splash()
        super().closeEvent(event)

    def _advance_phase(self):
        """自动推进 phase 动画 — 同步更新日志条目状态：

        上一条日志：pending→done（填入真实时间戳）
        当前日志：pending→active（填入真实时间戳）
        到最后一条时当前已激活的自动变 done
        """
        now_str = datetime.now().strftime('%H:%M:%S')

        # 先把上一条 active 标记为 done，并填入当前真实时间戳
        if 0 <= self._phase_idx < len(self._log_entries):
            ts, text, _ = self._log_entries[self._phase_idx]
            self._log_entries[self._phase_idx] = (now_str, text, 'done')

        if self._phase_idx < len(self.PHASES) - 1:
            self._phase_idx += 1
            # 激活新的当前 phase 条目
            if self._phase_idx < len(self._log_entries):
                ts, text, _ = self._log_entries[self._phase_idx]
                self._log_entries[self._phase_idx] = (now_str, text, 'active')
        else:
            # 已到最后一个 phase，停止自动推进
            try:
                if self._anim_timer is not None:
                    self._anim_timer.stop()
            except Exception:
                pass
        self.update()

    # ------------------------------------------------------------------ 绘制
    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        try:
            self._draw_background(p)
            self._draw_header(p)
            self._draw_status(p)
            self._draw_progress(p)
            self._draw_log(p)
            # footer 已移除
        finally:
            p.end()

    def _draw_background(self, p):
        path = QPainterPath()
        path.addRoundedRect(QRectF(0, 0, W, H), 12, 12)
        p.save()
        p.setClipPath(path)
        # 135° 对角渐变
        grad = QLinearGradient(0, 0, W, H)
        grad.setColorAt(0.00, C_BG_TOP)
        grad.setColorAt(0.40, C_BG_MID)
        grad.setColorAt(1.00, C_BG_BTM)
        p.fillRect(0, 0, W, H, grad)
        # 右上光晕
        glow = QRadialGradient(QPointF(W * 0.85, -H * 0.05), H * 0.85)
        glow.setColorAt(0.0, _acc(18))
        glow.setColorAt(0.6, _acc(6))
        glow.setColorAt(1.0, _acc(0))
        p.fillRect(0, 0, W, H, glow)
        p.restore()

    def _draw_header(self, p):
        """头部：盾牌图标 + 标题 + 副标题"""
        ix = MX          # 图标左上 x
        iy = Y_HEADER_TOP  # 图标左上 y
        isz = 44         # 图标尺寸
        ir = 10          # 图标圆角

        # 图标容器
        icon_rect = QRectF(ix, iy, isz, isz)
        icon_path = QPainterPath()
        icon_path.addRoundedRect(icon_rect, ir, ir)
        ig = QLinearGradient(0, iy, 0, iy + isz)
        ig.setColorAt(0.0, _acc(38))
        ig.setColorAt(1.0, _acc(12))
        p.save()
        p.setClipPath(icon_path)
        p.fillRect(icon_rect, ig)
        p.restore()
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(_acc(51), 1))
        p.drawRoundedRect(icon_rect, ir, ir)

        # 盾牌 SVG 绘制（24x24 viewBox → 32px 实际尺寸，居中于 44px 容器）
        # 盾牌在 viewBox 中的几何中心约 (12,12)，经 scale=s 后偏移 (12s, 12s)
        # 因此需要 translate(cx - 12s, cy - 12s) + scale(s) 才能居中
        cx = ix + isz / 2
        cy = iy + isz / 2
        s = 32.0 / 24.0  # viewBox 24 → 实际 32px

        p.save()
        # 先平移补偿缩放偏移，再缩放
        p.translate(cx - 12 * s, cy - 12 * s)
        p.scale(s, s)

        # 盾牌轮廓（精确还原 SVG: M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z）
        # 路径从底部尖角 (12,22) 出发逆时针绘制：
        #   1. 底部 → 右上弧 (s8-4 8-10): 控制 (12,22)→(20,18), 终点 (20,12)
        #   2. 右边直线: (20,12) → (20,5)
        #   3. 右上斜边: (20,5) → (12,2)
        #   4. 左上斜边: (12,2) → (4,5)
        #   5. 左边直线: (4,5) → (4,12)
        #   6. 底部弧: c0 6 8 10 → (4,12)→(12,22), 控制 (4,18),(12,22)
        sp = QPainterPath()
        sp.moveTo(12, 22)
        # 右下弧到底部 → 右侧
        sp.cubicTo(12, 22, 20, 18, 20, 12)
        sp.lineTo(20, 5)
        sp.lineTo(12, 2)
        sp.lineTo(4, 5)
        sp.lineTo(4, 12)
        # 左下弧到底部
        sp.cubicTo(4, 18, 12, 22, 12, 22)
        sp.closeSubpath()

        p.setPen(QPen(C_PRIMARY, 1.8, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        p.setBrush(Qt.NoBrush)
        p.drawPath(sp)

        # 对勾（精确 SVG: M9 12l2 2 4-4 → (9,12)→(11,14)→(15,10)）
        p.setPen(QPen(C_PRIMARY, 2.2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        p.drawLine(QPointF(9, 12), QPointF(11, 14))
        p.drawLine(QPointF(11, 14), QPointF(15, 10))
        p.restore()

        # 标题：16px / font-weight:600 / color:#e8eaed
        tx = ix + isz + 14
        f_title = QFont(_FONT_SANS)
        f_title.setPixelSize(16)
        f_title.setWeight(QFont.DemiBold)
        p.setPen(C_FG)
        p.setFont(f_title)
        p.drawText(QRectF(tx, iy - 2, 420, 22),
                   Qt.AlignVCenter | Qt.AlignLeft, 'Project Sertraline Lab')

        # 副标题：11px / color:#9aa0a6 / uppercase / letter-spacing:0.02em
        f_sub = QFont(_FONT_SANS)
        f_sub.setPixelSize(11)
        f_sub.setLetterSpacing(QFont.AbsoluteSpacing, 0.24)
        p.setPen(C_MUTED)
        p.setFont(f_sub)
        p.drawText(QRectF(tx, iy + 26, 420, 16),
                   Qt.AlignVCenter | Qt.AlignLeft, 'OFFLINE SECURITY SUITE')

    def _draw_status(self, p):
        """状态行：脉冲绿点 + 文案，位于 y=117"""
        x = MX
        y = Y_STATUS_TOP
        # 脉冲
        pulse = 0.5 + 0.5 * abs(self._pulse_t % 2 - 1)
        p.setOpacity(pulse)
        p.setBrush(C_PRIMARY)
        p.setPen(Qt.NoPen)
        p.drawEllipse(QRectF(x, y + 4, 7, 7))
        p.setOpacity(1.0)
        # 文案（12px, #9aa0a6）
        p.setPen(C_MUTED)
        f_status = QFont(_FONT_SANS)
        f_status.setPixelSize(12)
        p.setFont(f_status)
        # 外部驱动时使用真实阶段文案，否则用内置 PHASES 动画文案
        if self._externally_driven:
            txt = self._ext_text or ''
        else:
            txt = self.PHASES[self._phase_idx][1]
        p.drawText(QRectF(x + 16, y - 1, 680, 18),
                   Qt.AlignVCenter | Qt.AlignLeft, txt)

    def _draw_progress(self, p):
        """进度区：y=153（标签），y=173（轨道）"""
        x = MX
        label_y = Y_PROGRESS_TOP
        track_y = Y_TRACK_TOP
        track_w = W - 2 * MX
        track_h = 4
        # 外部驱动时使用真实 pct，否则走 PHASES 动画 pct
        if self._externally_driven:
            pct = int(self._ext_pct)
        else:
            pct = self.PHASES[self._phase_idx][0]

        # 标签 "SCAN PROGRESS"（11px, #9aa0a6, font-weight:500, uppercase, ls:0.04em）
        p.setPen(C_MUTED)
        f = QFont(_FONT_SANS)
        f.setPixelSize(11)
        f.setWeight(QFont.Medium)  # 500
        f.setLetterSpacing(QFont.AbsoluteSpacing, 0.44)
        p.setFont(f)
        p.drawText(QRectF(x, label_y, 200, 14),
                   Qt.AlignVCenter | Qt.AlignLeft, 'SCAN PROGRESS')

        # 百分比（右对齐，11px 绿色加粗）
        p.setPen(C_PRIMARY)
        f2 = QFont(_FONT_SANS)
        f2.setPixelSize(11)
        f2.setWeight(QFont.DemiBold)
        p.setFont(f2)
        p.drawText(QRectF(x + track_w - 55, label_y - 2, 55, 16),
                   Qt.AlignVCenter | Qt.AlignRight, f'{pct}%')

        # 轨道
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(255, 255, 255, 15))
        p.drawRoundedRect(QRectF(x, track_y, track_w, track_h), 2, 2)

        # 填充
        fill_w = max(track_w * pct / 100.0, 2.0)
        if pct > 0:
            fg = QLinearGradient(x, 0, x + fill_w, 0)
            fg.setColorAt(0.0, C_PRIMARY)
            fg.setColorAt(1.0, C_PRIMARY_2)
            p.setBrush(fg)
            p.drawRoundedRect(QRectF(x, track_y, fill_w, track_h), 2, 2)

            # 尾部 glow (40px)
            glow_w = min(40.0, fill_w)
            if glow_w > 2:
                gg = QLinearGradient(x + fill_w - glow_w, 0, x + fill_w, 0)
                gg.setColorAt(0.0, _acc(0))
                gg.setColorAt(1.0, _acc(102))
                p.setBrush(gg)
                p.drawRect(QRectF(x + fill_w - glow_w, track_y, glow_w, track_h))

        # 扫描线（在轨道范围内来回）
        sx = max(x, min(x + track_w, self._scan_x))
        p.setBrush(QColor(255, 255, 255, 128))
        p.drawRect(QRectF(sx - 1, track_y, 2, track_h))

    def _draw_log(self, p):
        """日志区：运行时日志条目，phase 推进时动态填充真实时间戳"""
        x = MX
        y = Y_LOG_TOP
        line_h = LOG_LINE_H

        entries = self._log_entries
        if not entries:
            return

        f_time = QFont(_FONT_MONO)
        f_time.setPixelSize(11)
        f_path = QFont(_FONT_MONO)
        f_path.setPixelSize(11)

        for i, (ts, path, status) in enumerate(entries):
            yy = y + i * line_h
            cy = yy + line_h / 2

            # 时间戳（56px 宽，右对齐）
            if status == 'done':
                p.setPen(C_LOG_TIME)
            elif status == 'active':
                p.setPen(C_PRIMARY)
            else:
                p.setPen(C_PENDING)   # pending 时间戳更灰（占位）
            p.setFont(f_time)
            # pending 状态时间戳为空 → 画成 "    " 占位，保持对齐
            ts_show = ts if ts else '    '
            p.drawText(QRectF(x, yy, 56, line_h),
                       Qt.AlignVCenter | Qt.AlignRight, ts_show)

            icon_cx = x + 63
            path_x = x + 74

            if status == 'done':
                # 绿色对勾
                p.setPen(QPen(C_PRIMARY, 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
                p.drawLine(QPointF(icon_cx - 4, cy + 1), QPointF(icon_cx - 1, cy + 4))
                p.drawLine(QPointF(icon_cx - 1, cy + 4), QPointF(icon_cx + 5, cy - 3))
                p.setPen(C_PRIMARY)
                p.setFont(f_path)
                p.drawText(QRectF(path_x, yy, W - MX - path_x, line_h),
                           Qt.AlignVCenter | Qt.AlignLeft, path)

            elif status == 'active':
                # 脉冲绿点
                pulse = 0.5 + 0.5 * abs(self._pulse_t % 2 - 1)
                p.setOpacity(pulse)
                p.setBrush(C_PRIMARY)
                p.setPen(Qt.NoPen)
                p.drawEllipse(QRectF(icon_cx - 3, cy - 3, 6, 6))
                p.setOpacity(1.0)
                p.setPen(C_PRIMARY)
                p.setFont(f_path)
                p.drawText(QRectF(path_x, yy, W - MX - path_x, line_h),
                           Qt.AlignVCenter | Qt.AlignLeft, path)

            else:  # pending
                p.setBrush(C_PENDING)
                p.setPen(Qt.NoPen)
                p.drawEllipse(QRectF(icon_cx - 1.5, cy - 1.5, 3, 3))
                p.setPen(C_PENDING)
                p.setFont(f_path)
                p.drawText(QRectF(path_x, yy, W - MX - path_x, line_h),
                           Qt.AlignVCenter | Qt.AlignLeft, path)


def create_splash():
    return SplashWindow()


if __name__ == '__main__':
    from PyQt5.QtWidgets import QApplication
    app = QApplication(sys.argv)
    w = create_splash()
    QTimer.singleShot(0, w.start)
    QTimer.singleShot(0, w.center_window)
    QTimer.singleShot(6000, w.close_splash)
    QTimer.singleShot(6200, app.quit)
    sys.exit(app.exec_())