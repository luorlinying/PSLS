# -*- coding: utf-8 -*-
"""PSLS 沙箱分析窗口 - Project Sertraline Lab 风格

窗口风格：
  - 背景为 PSLS 主窗口同款米色 (#F5F0E8)
  - 左上角仅 PSLS 图标 + "Project Sertraline Lab 软件分析室"
  - 中间图标 = 数据库查看卡片图标（放大镜形状），红色
  - 描述两行："该程序进程已被终止。" + "璱鸲计划实验室正在进行分析以确认它是否安全。"
  - 进度条仅保留来回移动的短横杠（无填充长条）
  - "查看详细信息" 箭头 ▼ / ▲，展开时窗口向下扩展
  - 无右上角关闭按钮、窗口不可移动
  - 分析完成后立即关闭窗口（emits completed）

另含 SandboxReleaseWindow：安全放行结果窗口（clean 时展示），
与分析窗口同风格，提供"同意重启 / 不重启"（5s 超时默认拒绝）。

使用 paintEvent 自绘，不依赖 WebView 加载。
"""
import os
from typing import Optional, List

from PyQt5.QtCore import (
    Qt, QTimer, QRectF, QPointF, pyqtSignal, QEvent, QSize
)
from PyQt5.QtGui import (
    QPainter, QColor, QPainterPath, QLinearGradient,
    QRadialGradient, QPen, QBrush, QFont, QFontMetrics, QFontMetricsF,
    QCursor, QMouseEvent, QGuiApplication, QIcon, QPixmap
)
from PyQt5.QtWidgets import (
    QWidget, QApplication, QPushButton, QRadioButton, QButtonGroup)

from ui.webview import theme_tokens


# ------------------------------------------------------------------ 常量
_W = 520                       # 窗口宽
_H = 430                       # 收起高度
_H_EXPANDED = 580              # 展开高度（向下扩展）

_BRAND_TITLE = 'Project Sertraline Lab 软件分析室'

# PSLS 主程序图标路径（在模块加载时探测一次）
_PSLS_ICON_PNG: Optional[QPixmap] = None

def _load_psls_logo() -> Optional[QPixmap]:
    """尝试加载 PSLS 主程序图标，使用高分辨率源 + devicePixelRatio 保证高清显示。"""
    global _PSLS_ICON_PNG
    if _PSLS_ICON_PNG is not None:
        return _PSLS_ICON_PNG
    here = os.path.dirname(os.path.abspath(__file__))
    # 优先使用高分辨率的 image_0_7mlicq.png（648x605），其次 logo_small.png（256x256）
    candidates = [
        os.path.join(here, 'assets', 'image_0_7mlicq.png'),
        os.path.join(here, 'assets', 'logo_small.png'),
        os.path.join(os.path.dirname(os.path.dirname(here)), 'icon.ico'),
    ]
    for p in candidates:
        if os.path.exists(p):
            pm = QPixmap(p)
            if not pm.isNull():
                # 使用 devicePixelRatio 缩放，保证高 DPI 屏幕清晰
                screen = QApplication.primaryScreen()
                dpr = screen.devicePixelRatio() if screen else 1.0
                logical_size = 30
                target_px = int(logical_size * dpr)
                scaled = pm.scaled(target_px, target_px,
                                   Qt.KeepAspectRatio, Qt.SmoothTransformation)
                scaled.setDevicePixelRatio(dpr)
                _PSLS_ICON_PNG = scaled
                return _PSLS_ICON_PNG
    _PSLS_ICON_PNG = QPixmap()  # 缓存空结果
    return None

# ------------------------------------------------------------------ 配色
# 绘制代码统一读下面的模块级配色全局量，因此只需在窗口构造时按当前主题
# 刷新一次（_apply_theme_palette），整套自绘窗口就会换色；paintEvent 每次重绘
# 都重新读全局量，所以已显示的窗口也会在下次重绘时跟随。
# 默认值为米色系（light），与改动前完全一致。
_C_BG = QColor(245, 240, 232)         # #F5F0E8 主背景（与主窗口一致）
_C_BG_SOFT = QColor(239, 233, 222)    # #EFE9DE 次级背景
_C_CARD = QColor(250, 248, 243)       # #FAF8F3 卡片
_C_BORDER = QColor(214, 205, 188)     # 边框
_C_TEXT = QColor(56, 46, 33)          # 主文本（深褐）
_C_TEXT_MUTED = QColor(120, 110, 95)  # 次级文本
_C_TEXT_DIM = QColor(150, 140, 122)   # 辅助文本

# 功能色
_C_RED = QColor(225, 29, 72)          # #E11D48 威胁 / 图标红
_C_GREEN = QColor(34, 197, 94)        # #22C55E 安全
_C_CYAN = QColor(0, 168, 198)         # progress 短横杠（青色）
_C_CYAN_SOFT = QColor(0, 130, 158)
_C_BLUE = QColor(37, 99, 235)         # #2563EB 询问图标蓝（问号）

_C_BG_ALPHA = QColor(245, 240, 232, 0)

# 形态参数（终端主题下按设计稿收敛为直角小圆角 + 等宽字体）
_FONT = 'Segoe UI'                    # 绘制字体族
_RADIUS = 14                          # 窗口圆角
_BTN_RADIUS = 8                       # 按钮圆角
_GLOW_A = QColor(255, 255, 255, 90)   # 顶部高光

# 按钮样式：米色原样保留（逐像素不变），终端主题换成琥珀终端形态
_BTN_QSS_LIGHT = {
    'primary': ('QPushButton { background: #0d9488; color: white; '
                'border: none; border-radius: 8px; } '
                'QPushButton:hover { background: #0f766e; }'),
    'muted': ('QPushButton { background: #a8a29e; color: white; '
              'border: none; border-radius: 8px; } '
              'QPushButton:hover { background: #78716c; }'),
    'success': ('QPushButton { background: #CCFBF1; color: white; '
                'border: none; border-radius: 8px; } '
                'QPushButton:hover { background: #48D38E; }'),
}
_BTN_QSS_TERMINAL = {
    'primary': ('QPushButton { background: #FF9500; color: #0a0700; '
                'border: none; border-radius: 4px; font-weight: bold; } '
                'QPushButton:hover { background: #CC7700; }'),
    'muted': ('QPushButton { background: #2a1f00; color: #FFB347; '
              'border: 1px solid #4a3500; border-radius: 4px; } '
              'QPushButton:hover { background: #4a3500; }'),
    'success': ('QPushButton { background: #34C759; color: #0a0700; '
                'border: none; border-radius: 4px; font-weight: bold; } '
                'QPushButton:hover { background: #2fa84e; }'),
}


def _apply_theme_palette():
    """按当前主题刷新模块级配色与形态参数（米色 / 琥珀终端）。"""
    global _C_BG, _C_BG_SOFT, _C_CARD, _C_BORDER, _C_TEXT, _C_TEXT_MUTED, _C_TEXT_DIM
    global _C_RED, _C_GREEN, _C_CYAN, _C_CYAN_SOFT, _C_BG_ALPHA, _C_BLUE
    global _FONT, _RADIUS, _BTN_RADIUS, _GLOW_A
    pal = theme_tokens.palette(theme_tokens.load_theme())
    if not pal.get('is_terminal'):
        _C_BG = QColor(245, 240, 232)
        _C_BG_SOFT = QColor(239, 233, 222)
        _C_CARD = QColor(250, 248, 243)
        _C_BORDER = QColor(214, 205, 188)
        _C_TEXT = QColor(56, 46, 33)
        _C_TEXT_MUTED = QColor(120, 110, 95)
        _C_TEXT_DIM = QColor(150, 140, 122)
        _C_RED = QColor(225, 29, 72)
        _C_GREEN = QColor(34, 197, 94)
        _C_CYAN = QColor(0, 168, 198)
        _C_CYAN_SOFT = QColor(0, 130, 158)
        _C_BLUE = QColor(37, 99, 235)
        _C_BG_ALPHA = QColor(245, 240, 232, 0)
        _FONT = 'Segoe UI'
        _RADIUS = 14
        _BTN_RADIUS = 8
        _GLOW_A = QColor(255, 255, 255, 90)
        return
    # 琥珀 CRT 终端
    _C_BG = QColor(10, 7, 0)            # #0a0700
    _C_BG_SOFT = QColor(18, 13, 2)      # #120d02
    _C_CARD = QColor(13, 9, 0)          # #0d0900
    _C_BORDER = QColor(74, 53, 0)       # #4a3500
    _C_TEXT = QColor(255, 179, 71)      # #FFB347
    _C_TEXT_MUTED = QColor(139, 105, 20)  # #8B6914
    _C_TEXT_DIM = QColor(92, 74, 32)    # #5c4a20
    _C_RED = QColor(255, 59, 48)        # #FF3B30
    _C_GREEN = QColor(52, 199, 89)      # #34C759
    _C_CYAN = QColor(255, 149, 0)       # 进度短横杠 -> 琥珀
    _C_CYAN_SOFT = QColor(204, 119, 0)
    _C_BLUE = QColor(59, 130, 246)      # 询问问号蓝（终端主题下用更亮的蓝）
    _C_BG_ALPHA = QColor(10, 7, 0, 0)
    _FONT = 'Courier New'
    _RADIUS = 4
    _BTN_RADIUS = 4
    _GLOW_A = QColor(255, 149, 0, 40)   # 顶部琥珀高光


def _btn_qss(kind: str) -> str:
    """按当前主题返回按钮样式（kind: primary / muted / success）。"""
    if theme_tokens.load_theme() == theme_tokens.THEME_TERMINAL:
        return _BTN_QSS_TERMINAL.get(kind, _BTN_QSS_TERMINAL['primary'])
    return _BTN_QSS_LIGHT.get(kind, _BTN_QSS_LIGHT['primary'])


class _BaseSandboxWindow(QWidget):
    """共有基础：米色背景 + 品牌头 + 图标绘制支持。"""

    def __init__(self, file_path: str = '', parent=None):
        super().__init__(parent)
        # 按当前内置主题刷新自绘配色（终端主题 -> 琥珀 CRT 深底）
        _apply_theme_palette()
        self._file_path = file_path
        self._file_name = os.path.basename(file_path) if file_path else ''
        self._brand_title = _BRAND_TITLE
        self._icon_kind = 'database'
        self._icon_color = QColor(_C_RED)
        self._bg_color = QColor(_C_BG)   # 米色背景（与 PSLS 主窗口一致）

        self.setWindowTitle(f'PSLS - 沙箱分析: {self._file_name or "文件"}')
        self.setWindowFlags(
            Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)

        # 窗口不可移动
        self._can_drag = False

    def set_file_path(self, file_path: str):
        if not file_path:
            return
        self._file_path = file_path
        self._file_name = os.path.basename(file_path)
        self.setWindowTitle(f'PSLS - 沙箱分析: {self._file_name}')
        self.update()

    def _center(self):
        try:
            screen = QApplication.primaryScreen()
            if screen is None:
                return
            g = screen.geometry()
            self.move(int((g.width() - self.width()) / 2),
                      int((g.height() - self.height()) / 2))
        except Exception:
            pass

    # ------------------------------------------------------------------ 绘制
    def _draw_background(self, p: QPainter, w: int, h: int):
        path = QPainterPath()
        path.addRoundedRect(QRectF(0, 0, w, h), _RADIUS, _RADIUS)
        p.save()
        p.setClipPath(path)
        p.fillRect(0, 0, w, h, _C_BG)
        # 顶部浅色高光（终端主题下换成琥珀色弱高光）
        glow = QRadialGradient(QPointF(w * 0.5, 0), w * 0.6)
        glow.setColorAt(0.0, _GLOW_A)
        glow.setColorAt(0.6, QColor(_GLOW_A.red(), _GLOW_A.green(), _GLOW_A.blue(), 0))
        p.fillRect(0, 0, w, h, glow)
        p.restore()
        # 边框
        p.setPen(QPen(_C_BORDER, 1))
        p.setBrush(Qt.NoBrush)
        p.drawRoundedRect(QRectF(0.5, 0.5, w - 1, h - 1), _RADIUS, _RADIUS)

    def _draw_header(self, p: QPainter):
        """左上角仅品牌文字（无图标）。"""
        p.save()
        p.setPen(_C_TEXT)
        font = QFont(_FONT, 12, QFont.Bold)
        p.setFont(font)
        # 文字从 x=24 开始（原图标位置腾出空间）
        p.drawText(24, 26, _BRAND_TITLE)
        p.restore()

    def _draw_database_icon(self, p: QPainter, cx: float, cy: float,
                            w: float = 80, color=None):
        """中间图标：Lucide file-search（纯描边，无填充）。

        收窄比例 + 放大镜完全在文件内 + 仅保留红色框架线。
        """
        color = color or self._icon_color
        p.save()
        s = w
        unit = s / 24.0

        # 文件主体（收窄：宽度 14，高度 17，居中偏右让放大镜完整嵌入）
        fw = 14 * unit    # 文件宽度（原 18，收窄到 14）
        fh = 17 * unit
        fx = cx - fw * 0.4   # 文件中心偏左，留出右侧空间
        fy = cy - fh / 2

        # 折角比例
        fold_w = 4 * unit   # 折角宽度
        fold_h = 4 * unit   # 折角高度

        # 无填充，仅描边
        p.setPen(QPen(color, 2.8))
        p.setBrush(Qt.NoBrush)

        # 文件矩形（带右上角折角）
        file_path = QPainterPath()
        file_path.moveTo(fx, fy)
        file_path.lineTo(fx + fw - fold_w, fy)          # 上边到折角起点
        file_path.lineTo(fx + fw, fy + fold_h)           # 折角斜线
        file_path.lineTo(fx + fw, fy + fh)                # 右缘
        file_path.lineTo(fx, fy + fh)                     # 下缘
        file_path.closeSubpath()
        p.drawPath(file_path)

        # 折角三角形（仅描边）
        corner_path = QPainterPath()
        corner_path.moveTo(fx + fw - fold_w, fy)
        corner_path.lineTo(fx + fw, fy + fold_h)
        corner_path.lineTo(fx + fw - fold_w, fy + fold_h)
        corner_path.closeSubpath()
        p.drawPath(corner_path)

        # 文件内部装饰线（两条淡线）
        p.setPen(QPen(color, 1.2, Qt.SolidLine, Qt.RoundCap))
        inner_x = fx + 1.5 * unit
        inner_y1 = fy + 4.5 * unit
        inner_y2 = fy + 7 * unit
        p.drawLine(QPointF(inner_x, inner_y1), QPointF(inner_x + fw * 0.55, inner_y1))
        p.drawLine(QPointF(inner_x, inner_y2), QPointF(inner_x + fw * 0.40, inner_y2))

        # --- 放大镜（完全在文件内部，无填充）---
        # 圆心居中偏下，确保圆圈和手柄都在文件内
        lens_cx = fx + fw * 0.55   # 圆圈中心偏右
        lens_cy = fy + fh * 0.60   # 圆圈中心偏下
        lens_r = 3.2 * unit

        # 圆圈（仅描边，无填充）
        p.setPen(QPen(color, 2.5))
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(QPointF(lens_cx, lens_cy), lens_r, lens_r)

        # 手柄（短，完全在文件内）
        hx1 = lens_cx + lens_r * 0.70
        hy1 = lens_cy + lens_r * 0.70
        hx2 = lens_cx + lens_r * 1.55
        hy2 = lens_cy + lens_r * 1.55
        p.setPen(QPen(color, 2.5, Qt.SolidLine, Qt.RoundCap))
        p.drawLine(QPointF(hx1, hy1), QPointF(hx2, hy2))

        p.restore()

    def _draw_check_icon(self, p: QPainter, cx: float, cy: float,
                         w: float = 84, color=None):
        """绿色圆形 + 对勾图标（两段独立描边，避免 V 形拐角色差）。"""
        color = color or self._icon_color
        p.save()
        r = w / 2
        grad = QRadialGradient(QPointF(cx, cy), r)
        grad.setColorAt(0.0, QColor(color.red(), color.green(), color.blue(), 50))
        grad.setColorAt(1.0, QColor(color.red(), color.green(), color.blue(), 18))
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(grad))
        p.drawEllipse(QPointF(cx, cy), r, r)

        # 对勾两段笔画中心线
        p1 = QPointF(cx - w * 0.22, cy + 2)          # 起点
        p2 = QPointF(cx - w * 0.04, cy + w * 0.16)   # 拐角
        p3 = QPointF(cx + w * 0.24, cy - w * 0.16)   # 终点

        # 两段独立路径 + 独立描边 → 拐角处 RoundCap 重叠，无 RoundJoin 色差
        pen = QPen(color, 6, Qt.SolidLine, Qt.RoundCap)
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)

        path_l = QPainterPath()
        path_l.moveTo(p1)
        path_l.lineTo(p2)
        p.drawPath(path_l)

        path_r = QPainterPath()
        path_r.moveTo(p2)
        path_r.lineTo(p3)
        p.drawPath(path_r)
        p.restore()

    def _draw_cross_icon(self, p: QPainter, cx: float, cy: float,
                         w: float = 84, color=None):
        """红色圆形 + × 图标（两段独立描边，无 RoundJoin 色差）。"""
        color = color or self._icon_color
        p.save()
        r = w / 2
        grad = QRadialGradient(QPointF(cx, cy), r)
        grad.setColorAt(0.0, QColor(color.red(), color.green(), color.blue(), 50))
        grad.setColorAt(1.0, QColor(color.red(), color.green(), color.blue(), 18))
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(grad))
        p.drawEllipse(QPointF(cx, cy), r, r)

        # × 两段笔画（左上→右下 + 右上→左下）
        inset = w * 0.22
        p_tl = QPointF(cx - inset, cy - inset)
        p_br = QPointF(cx + inset, cy + inset)
        p_tr = QPointF(cx + inset, cy - inset)
        p_bl = QPointF(cx - inset, cy + inset)

        pen = QPen(color, 6, Qt.SolidLine, Qt.RoundCap)
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)

        path1 = QPainterPath()
        path1.moveTo(p_tl)
        path1.lineTo(p_br)
        p.drawPath(path1)

        path2 = QPainterPath()
        path2.moveTo(p_tr)
        path2.lineTo(p_bl)
        p.drawPath(path2)
        p.restore()

    def _draw_question_icon(self, p: QPainter, cx: float, cy: float,
                            w: float = 84, color=None):
        """蓝色圆形 + 问号图标（回滚/询问弹窗用）。"""
        color = color or self._icon_color
        p.save()
        r = w / 2
        grad = QRadialGradient(QPointF(cx, cy), r)
        grad.setColorAt(0.0, QColor(color.red(), color.green(), color.blue(), 50))
        grad.setColorAt(1.0, QColor(color.red(), color.green(), color.blue(), 18))
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(grad))
        p.drawEllipse(QPointF(cx, cy), r, r)

        # 问号用文本绘制（字形稳定、跨字体一致）；圆形描边让它更像图标
        p.setPen(QPen(color, 2.5))
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(QPointF(cx, cy), r * 0.86, r * 0.86)

        p.setPen(color)
        font = QFont(_FONT, int(w * 0.42), QFont.Bold)
        p.setFont(font)
        # 问号居中：此前用 QRectF(cx-r, cy-0.72r, w, w) + AlignVCenter，矩形高为
        # w=2r 而顶边在 cy-0.72r，垂直中心落到 cy+0.28r → 问号偏下约 12px。
        # 现按**字形墨迹外框**精确居中（水平也修掉按字宽居中带来的略偏右）。
        # 注意：无字体环境（如 offscreen）下 boundingRect 会返回无效矩形
        # （left/top 为 ±1e5），因此必须做有效性守卫，否则会画到画布外。
        fm = QFontMetricsF(font)
        br = fm.tightBoundingRect('?')
        valid = (br.width() > 0 and 0 < br.width() < w
                 and 0 < br.height() < w and abs(br.left()) < w and abs(br.top()) < w)
        if valid:
            ox = cx - br.width() / 2.0 - br.left()
            # 实测（Segoe UI Bold）：按墨迹外框居中时，"?"字形的墨迹质量质心仍
            # 偏上约 5px（上钩重、下点轻）。这里补 5% 字高（约 2.5px）的光学下沉，
            # 使外框居中与视觉居中折中，避免看起来"偏上"。
            oy = cy - br.height() / 2.0 - br.top() + br.height() * 0.05
            p.drawText(QPointF(ox, oy), '?')
        else:
            # 退化兜底：用字高（cap height）与字宽居中，仍是有效度量
            adv = fm.horizontalAdvance('?')
            cap = fm.capHeight()
            if adv > 0 and 0 < cap <= w:
                p.drawText(QPointF(cx - adv / 2.0, cy + cap / 2.0), '?')
            else:
                p.drawText(QRectF(cx - r, cy - r, w, w),
                           Qt.AlignHCenter | Qt.AlignVCenter, '?')
        p.restore()


# ------------------------------------------------------------------ 沙箱分析窗口
class SandboxAnalysisWindow(_BaseSandboxWindow):
    """分析进度窗口（米色、品牌头、红色图标、仅移动短横杠、向下扩展详情）。

    信号:
        completed: 分析完成（窗口即将自动关闭）
    """
    completed = pyqtSignal()

    def __init__(self, file_path: str = '', parent=None):
        super().__init__(file_path, parent)
        self._icon_kind = 'database'
        self._icon_color = QColor(_C_RED)

        # 文案
        self._status_text = '检测到可疑文件'
        self._progress_text = '正在分析...'
        self._progress = 0
        self._desc_lines = [
            '该程序进程已被终止。',
            '璱鸲计划实验室正在进行分析以确认它是否安全。',
        ]

        # 详细信息
        self._details: List[str] = []
        self._detail_expanded = False
        self._detail_scroll_offset = 0   # 详细信息滚动偏移量
        # 初始 rect（会在 showEvent/toggle_detail 中通过 _update_detail_toggle_rect 更新）
        self._detail_toggle_rect = QRectF(60, _H - 74, _W - 120, 34)

        # 动画
        self._anim_timer: Optional[QTimer] = None
        self._scan_x = 0.0
        self._scan_dir = 1
        self._show_fill_bar = False
        self._track_left = 60.0
        self._track_right = _W - 60.0

        self.setFixedSize(_W, _H)

    # toggle 按钮常量
    _TOGGLE_BOTTOM_MARGIN = 40   # 距离窗口底部
    _TOGGLE_HEIGHT = 34          # toggle 按钮高度

    # ------------------------------------------------------------------ 接口
    def start(self):
        if self._anim_timer is None:
            self._anim_timer = QTimer(self)
            # PreciseTimer：40ms 滑动动画对节拍敏感；CoarseTimer 默认按 5% 粒度
            # 对齐合并，会造成忽快忽慢的"卡顿"观感。
            try:
                self._anim_timer.setTimerType(Qt.PreciseTimer)
            except Exception:
                pass
            self._anim_timer.timeout.connect(self._tick_anim)
        if not self._anim_timer.isActive():
            self._anim_timer.start(40)

    def stop(self):
        if self._anim_timer is not None:
            self._anim_timer.stop()

    def set_status(self, text: str):
        self._status_text = text or ''
        self.update()

    def set_progress(self, pct: int, text: str = ''):
        self._progress = max(0, min(100, int(pct)))
        if text:
            self._progress_text = text
        self.update()

    def set_details(self, details: List[str]):
        self._details = list(details or [])
        self.update()

    def set_result(self, state: str, text: str = ''):
        """分析完成：立即关闭窗口并发出 completed 信号。"""
        self._result_state = state
        self._result_text = text or ''
        self.stop()
        self.completed.emit()
        self.close()

    def toggle_detail(self):
        """展开/收起详细信息（窗口向下扩展，保持屏幕中央）。"""
        self._detail_expanded = not self._detail_expanded
        self._detail_scroll_offset = 0  # 重置滚动
        height = _H_EXPANDED if self._detail_expanded else _H
        self.setFixedSize(_W, height)
        self._update_detail_toggle_rect()
        # 展开/收起后重新居中
        self._center()
        self.update()

    def _arrow_label(self) -> str:
        if not self._details:
            return ''
        return ('收起详细信息 ▲' if self._detail_expanded
                else '查看详细信息 ▼')

    # ------------------------------------------------------------------ 事件
    def showEvent(self, event):
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self._center()
        self._update_detail_toggle_rect()
        # 展开状态保持原定位（top-left 不变 → 向下扩展）
        super().showEvent(event)

    def closeEvent(self, event):
        self.stop()
        super().closeEvent(event)

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton and self._details:
            pos = event.pos()
            if self._detail_toggle_rect.contains(pos):
                self.toggle_detail()
                event.accept()
                return
        super().mousePressEvent(event)

    def wheelEvent(self, event):
        """详细信息区域的滚轮滚动。"""
        if self._detail_expanded and self._details:
            # 只在鼠标位置在详细信息区域内时处理滚动
            collapsed_top = _H - self._TOGGLE_BOTTOM_MARGIN - self._TOGGLE_HEIGHT
            mouse_y = event.pos().y()
            if mouse_y >= collapsed_top and mouse_y < self._detail_toggle_rect.top():
                delta = event.angleDelta().y()
                line_h = 24
                max_offset = max(0, len(self._details) * line_h - self._get_detail_area_height())
                self._detail_scroll_offset = max(0, min(
                    self._detail_scroll_offset - delta, max_offset))
                self.update()
                event.accept()
                return
        super().wheelEvent(event)

    def _get_detail_area_height(self) -> int:
        """计算详细信息显示区域高度。"""
        collapsed_top = _H - self._TOGGLE_BOTTOM_MARGIN - self._TOGGLE_HEIGHT
        sep_y = self._detail_toggle_rect.top() - 12
        return max(0, int(sep_y - collapsed_top - 6))

    def event(self, event):
        if event.type() in (QEvent.Type.HoverEnter, QEvent.Type.HoverMove):
            pos = self.mapFromGlobal(self.cursor().pos())
            has_details = bool(self._details)
            self.setCursor(Qt.PointingHandCursor
                           if has_details and self._detail_toggle_rect.contains(pos)
                           else Qt.ArrowCursor)
        return super().event(event)

    def _update_detail_toggle_rect(self):
        """更新 toggle 按钮位置（始终在窗口底部）。"""
        h = self.height()
        top = h - self._TOGGLE_BOTTOM_MARGIN - self._TOGGLE_HEIGHT
        self._detail_toggle_rect = QRectF(
            60, top, _W - 120, self._TOGGLE_HEIGHT)

    def _tick_anim(self):
        self._track_left = 60.0
        self._track_right = float(self.width() - 60)
        # 滑动条长度 = 轨迹长度的 1/3
        bar_w = (self._track_right - self._track_left) / 3
        slide_max = self._track_right - bar_w
        self._scan_x += self._scan_dir * 8
        if self._scan_x >= slide_max:
            self._scan_x = slide_max
            self._scan_dir = -1
        elif self._scan_x <= self._track_left:
            self._scan_x = self._track_left
            self._scan_dir = 1
        self.update()

    # ------------------------------------------------------------------ 绘制
    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        try:
            w = self.width()
            h = self.height()
            self._draw_background(p, w, h)
            self._draw_header(p)
            self._draw_center_icon(p)
            self._draw_file_info(p)
            self._draw_progress(p)
            self._draw_status(p)
            self._draw_detail_toggle(p)
        finally:
            p.end()

    def _draw_center_icon(self, p: QPainter):
        self._draw_database_icon(p, _W / 2, 118)

    def _draw_file_info(self, p: QPainter):
        p.save()
        y = 165
        p.setPen(_C_TEXT)
        font = QFont(_FONT, 14, QFont.Bold)
        p.setFont(font)
        p.drawText(QRectF(60, y, _W - 120, 24),
                   Qt.AlignHCenter | Qt.AlignTop,
                   self._file_name or '未知文件')

        y += 26
        p.setPen(_C_TEXT_MUTED)
        font = QFont(_FONT, 11)
        p.setFont(font)
        for line in self._desc_lines[:2]:
            p.drawText(QRectF(60, y, _W - 120, 18),
                       Qt.AlignHCenter | Qt.AlignTop, line)
            y += 18
        p.restore()

    def _draw_progress(self, p: QPainter):
        """纯色滑动条 + 统一高度轨道线。"""
        p.save()
        w = self.width()
        track_left = self._track_left
        track_right = self._track_right
        y = 262

        # 统一高度：3px
        bar_h = 3
        # 滑动条长度 = 轨迹长度的 1/3
        bar_w = (track_right - track_left) / 3

        # 轨道线与滑动条统一高度
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(_C_BORDER))
        track_y = y - bar_h / 2
        p.drawRoundedRect(
            QRectF(track_left, track_y, track_right - track_left, bar_h),
            bar_h / 2, bar_h / 2)

        # 纯色滑动条（无渐变、无高光）
        # 滑动区间：[track_left, track_right - bar_w]，保证条始终在轨道内
        slide_min = track_left
        slide_max = track_right - bar_w
        sx = max(slide_min, min(self._scan_x, slide_max))
        bar_x = sx
        p.setBrush(QBrush(_C_CYAN))
        p.drawRoundedRect(
            QRectF(bar_x, track_y, bar_w, bar_h),
            bar_h / 2, bar_h / 2)

        # 进度百分比文字
        p.setPen(_C_TEXT_DIM)
        font = QFont(_FONT, 10, QFont.Bold)
        p.setFont(font)
        p.drawText(QRectF(60, y + 20, w - 120, 18),
                   Qt.AlignHCenter, f'{self._progress}%')
        p.restore()

    def _draw_status(self, p: QPainter):
        p.save()
        y = 305
        p.setPen(_C_TEXT)
        font = QFont(_FONT, 11)
        p.setFont(font)
        text = self._progress_text or self._status_text
        p.drawText(QRectF(60, y, _W - 120, 20),
                   Qt.AlignHCenter | Qt.AlignTop, text)
        p.restore()

    def _draw_detail_toggle(self, p: QPainter):
        p.save()
        rect = self._detail_toggle_rect

        # 仅当有详细信息时才显示分隔线和 toggle 按钮
        if not self._details:
            p.restore()
            return

        # 收起时 toggle 按钮所在位置（用于计算展开时详细信息区域）
        collapsed_top = _H - self._TOGGLE_BOTTOM_MARGIN - self._TOGGLE_HEIGHT

        # 分隔线（始终在 toggle 按钮上方 12px）
        sep_y = rect.top() - 12
        p.setPen(QPen(_C_BORDER, 1))
        p.drawLine(QPointF(60, sep_y), QPointF(_W - 60, sep_y))

        # 详细信息（展开时绘制在收起位置与展开 toggle 之间，支持滚动）
        if self._detail_expanded:
            details_top = collapsed_top + 4
            details_bottom = sep_y - 2
            area_height = details_bottom - details_top
            line_h = 24
            total_lines = len(self._details)
            max_lines_visible = max(1, int(area_height / line_h))
            scroll_offset = self._detail_scroll_offset
            first_visible = int(scroll_offset / line_h)
            visible_count = min(max_lines_visible, total_lines - first_visible)

            # 裁剪详细信息区域
            clip_path = QPainterPath()
            clip_path.addRect(QRectF(60, details_top, _W - 120, area_height))
            p.setClipPath(clip_path)

            # 当详情条数较少（无需滚动）时，底对齐显示，避免底部出现大片空白
            need_scroll = total_lines > max_lines_visible
            if not need_scroll:
                content_h = total_lines * line_h
                # 让详情紧贴 toggle 按钮上方显示
                content_top = details_bottom - content_h
                if content_top < details_top:
                    content_top = details_top
            else:
                content_top = details_top

            p.setPen(_C_TEXT)
            font = QFont('Consolas', 10)
            p.setFont(font)
            x = 70
            for i in range(visible_count):
                idx = first_visible + i
                if idx >= total_lines:
                    break
                line = self._details[idx]
                y = content_top + i * line_h - (scroll_offset % line_h)
                p.drawText(
                    QRectF(x, y, _W - 140, line_h - 2),
                    Qt.AlignLeft | Qt.AlignVCenter,
                    line if len(line) < 52 else line[:51] + '...'
                )

            # 滚动条指示（右侧薄线）
            if total_lines > max_lines_visible:
                bar_x = _W - 68
                bar_h = area_height
                bar_w = 3
                p.setPen(Qt.NoPen)
                p.setBrush(QBrush(_C_BORDER))
                p.drawRoundedRect(QRectF(bar_x, details_top, bar_w, bar_h), 1, 1)
                # 滑块
                slider_h = max(12, bar_h * max_lines_visible / total_lines)
                slider_y = details_top
                if total_lines > max_lines_visible:
                    slider_y = details_top + (bar_h - slider_h) * (
                        scroll_offset / max(1, total_lines * line_h - area_height))
                p.setBrush(QBrush(_C_TEXT_MUTED))
                p.drawRoundedRect(
                    QRectF(bar_x, slider_y, bar_w, slider_h), 1, 1)

            # 关键：无论是否需要滚动，都要重置裁剪
            p.setClipping(False)

        # toggle 按钮文字
        p.setPen(_C_TEXT_MUTED)
        font = QFont(_FONT, 10, QFont.Bold)
        p.setFont(font)
        p.drawText(rect, Qt.AlignHCenter | Qt.AlignVCenter,
                   self._arrow_label())
        p.restore()


# ------------------------------------------------------------------ 安全放行结果窗口
class SandboxReleaseWindow(_BaseSandboxWindow):
    """安全放行结果窗口（沙箱检查 clean 时展示）。

    与分析窗口同风格：米色背景 + 品牌头 + 绿色对勾图标。
    提供"同意重启 / 不重启"按钮，3 秒超时默认拒绝。

    支持视觉恶搞检测复用：通过 subtitle_lines / question_line /
    accept_text 注入自定义文案与按钮文字（"信任重启"）。

    信号:
        releaseAccepted: 用户同意重启
        releaseRejected: 用户不重启（或超时默认）
    """
    releaseAccepted = pyqtSignal()
    releaseRejected = pyqtSignal()

    _TIMEOUT_SEC = 3

    def __init__(self, file_path: str = '', parent=None,
                 subtitle_lines: Optional[List[str]] = None,
                 question_line: str = '',
                 accept_text: str = '信任重启',
                 reject_text: str = '不重启',
                 icon_kind: str = 'check',
                 icon_color=None,
                 choices: Optional[List[dict]] = None,
                 choice_title: str = '',
                 timeout_sec: Optional[int] = None):
        super().__init__(file_path, parent)
        # 图标语义：'check' 绿勾（判定安全放行）；'cross' 红叉（警示）；
        # 'question' 蓝色问号（询问类，如勒索回滚是否回滚）。
        self._icon_kind = icon_kind or 'check'
        if icon_color is not None:
            self._icon_color = QColor(icon_color)
        elif self._icon_kind == 'check':
            self._icon_color = QColor(_C_GREEN)
        elif self._icon_kind == 'question':
            self._icon_color = QColor(_C_BLUE)
        else:
            self._icon_color = QColor(_C_RED)
        self._closed_by_user = False

        # 视觉恶搞检测复用：自定义文案
        self._subtitle_lines = subtitle_lines or [
            '璱鸲计划实验室分析完成，该对象被判定为安全',
            '进程已终止，是否同意重启该程序？',
        ]
        self._question_line = question_line or ''
        self._accept_text = accept_text or '信任重启'
        # 拒绝/默认动作文案（默认"不重启"；勒索回滚询问复用为"不回滚"）
        self._reject_text = reject_text or '不重启'

        # 可选单选列表（勒索回滚世代选择复用；默认 None = 纯是/否）
        self._choices = list(choices) if choices else []
        self._choice_title = choice_title or ''
        self._radio_group = None
        self._radios = []

        self.setFixedSize(_W, _H)

        # 倒计时（默认 3s；勒索回滚询问传 10s）
        self._timeout_sec = int(timeout_sec) if timeout_sec else self._TIMEOUT_SEC
        self._countdown = self._timeout_sec
        self._timeout_timer = QTimer(self)
        self._timeout_timer.setInterval(1000)
        self._timeout_timer.timeout.connect(self._on_tick)

        # 按钮
        self._accept_btn = QPushButton(self._accept_text, self)
        self._reject_btn = QPushButton(self._reject_text, self)
        self._setup_buttons()
        self._setup_choices()

    def _setup_choices(self):
        """构建世代选择单选按钮（最多 3 项，默认选中第一项=最新世代）。"""
        if not self._choices:
            return
        self._radio_group = QButtonGroup(self)
        base_y = 270
        for i, ch in enumerate(self._choices[:3]):
            label = str((ch or {}).get('label', '') or '')
            rb = QRadioButton(label, self)
            rb.setFont(QFont(_FONT, 10))
            rb.setStyleSheet(f'QRadioButton {{ color:{_C_TEXT.name()}; }}')
            rb.move(92, base_y + i * 26)
            rb.setFixedWidth(_W - 184)
            rb.setCursor(Qt.PointingHandCursor)
            self._radio_group.addButton(rb, i)
            self._radios.append(rb)
        if self._radios:
            self._radios[0].setChecked(True)

    def selected_value(self):
        """返回当前选中的选项值（无选项时返回 None）。"""
        if not self._radios or self._radio_group is None:
            return None
        idx = self._radio_group.checkedId()
        if 0 <= idx < len(self._choices):
            return (self._choices[idx] or {}).get('value')
        return (self._choices[0] or {}).get('value') if self._choices else None

    def _setup_buttons(self):
        font = QFont(_FONT, 11, QFont.Bold)
        for b in (self._accept_btn, self._reject_btn):
            b.setFont(font)
            b.setCursor(Qt.PointingHandCursor)
            b.setFixedSize(132, 38)

        self._accept_btn.setStyleSheet(_btn_qss('primary'))
        self._reject_btn.setStyleSheet(_btn_qss('muted'))
        self._accept_btn.clicked.connect(self._on_release_accept)
        self._reject_btn.clicked.connect(self._on_release_reject)

    def showEvent(self, event):
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self._center()
        self._layout_buttons()
        self._timeout_timer.start()
        super().showEvent(event)

    def closeEvent(self, event):
        self._timeout_timer.stop()
        if not self._closed_by_user:
            self.releaseRejected.emit()
        super().closeEvent(event)

    def _layout_buttons(self):
        bw = _W
        gap = 18
        total = 132 * 2 + gap
        x0 = (bw - total) / 2
        # 有世代选择项时按钮下移，避免与单选列表重叠
        y = 356 if self._choices else 300
        self._accept_btn.move(int(x0), y)
        self._reject_btn.move(int(x0 + 132 + gap), y)

    def _on_tick(self):
        self._countdown -= 1
        if self._countdown <= 0:
            self._on_timeout_default()
        self.update()

    def _on_timeout_default(self):
        """5 秒超时默认不重启。"""
        self._closed_by_user = True
        self._timeout_timer.stop()
        self.releaseRejected.emit()
        self.close()

    def _on_release_accept(self):
        self._closed_by_user = True
        self._timeout_timer.stop()
        self.releaseAccepted.emit()
        self.close()

    def _on_release_reject(self):
        self._closed_by_user = True
        self._timeout_timer.stop()
        self.releaseRejected.emit()
        self.close()

    # ------------------------------------------------------------------ 绘制
    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        try:
            w = self.width()
            h = self.height()
            self._draw_background(p, w, h)
            self._draw_header(p)
            if self._icon_kind == 'cross':
                self._draw_cross_icon(p, _W / 2, 118, color=self._icon_color)
            elif self._icon_kind == 'question':
                self._draw_question_icon(p, _W / 2, 118, color=self._icon_color)
            else:
                self._draw_check_icon(p, _W / 2, 118, color=self._icon_color)

            # 文案
            p.setPen(_C_TEXT)
            font = QFont(_FONT, 14, QFont.Bold)
            p.setFont(font)
            p.drawText(QRectF(60, 175, _W - 120, 24),
                       Qt.AlignHCenter,
                       self._file_name or '未知文件')

            p.setPen(_C_TEXT_MUTED)
            font = QFont(_FONT, 11)
            p.setFont(font)
            line_a = self._subtitle_lines[0] if self._subtitle_lines else ''
            line_b = self._question_line or (
                self._subtitle_lines[1] if self._subtitle_lines
                else '进程已终止，是否同意重启该程序？')
            p.drawText(QRectF(60, 205, _W - 120, 20),
                       Qt.AlignHCenter,
                       line_a)
            p.drawText(QRectF(60, 227, _W - 120, 20),
                       Qt.AlignHCenter,
                       line_b)

            # 世代选择标题（如"选择回滚目标世代"）
            if self._choices and self._choice_title:
                p.setPen(_C_TEXT_MUTED)
                font = QFont(_FONT, 10, QFont.Bold)
                p.setFont(font)
                p.drawText(QRectF(60, 250, _W - 120, 18),
                           Qt.AlignHCenter, self._choice_title)

            # 倒计时文字
            if self._countdown > 0:
                p.setPen(_C_TEXT_DIM)
                font = QFont(_FONT, 10)
                p.setFont(font)
                _cy = 404 if self._choices else 348
                p.drawText(QRectF(60, _cy, _W - 120, 18),
                           Qt.AlignHCenter,
                           f'{self._countdown}s 后默认{self._reject_text}')
        finally:
            p.end()


# ------------------------------------------------------------------ 威胁结果窗口
class SandboxThreatWindow(_BaseSandboxWindow):
    """威胁判定结果窗口（沙箱检查 suspicious/malware 时展示）。

    与放行窗口同风格：米色背景 + 品牌头 + 红色 × 图标。
    提供单个居中的"知道了"按钮（绿色）。

    信号:
        acknowledged: 用户点击知道了
    """
    acknowledged = pyqtSignal()

    def __init__(self, file_path: str = '', parent=None):
        super().__init__(file_path, parent)
        self._icon_kind = 'cross'
        self._icon_color = QColor(_C_RED)
        # 描述文字（子类可覆写）
        self._subtitle_lines = [
            '璱鸲计划实验室分析完成，该对象被判定为威胁。',
            '已将其移动到隔离区，它将不会再造成威胁。',
        ]

        self.setFixedSize(_W, _H)

        # 按钮
        self._ok_btn = QPushButton('知道了', self)
        self._setup_buttons()

    def _setup_buttons(self):
        font = QFont(_FONT, 11, QFont.Bold)
        self._ok_btn.setFont(font)
        self._ok_btn.setCursor(Qt.PointingHandCursor)
        self._ok_btn.setFixedSize(132, 38)
        self._ok_btn.setStyleSheet(_btn_qss('success'))
        self._ok_btn.clicked.connect(self._on_acknowledged)

    def showEvent(self, event):
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self._center()
        self._layout_buttons()
        super().showEvent(event)

    def closeEvent(self, event):
        super().closeEvent(event)

    def _layout_buttons(self):
        bw = _W
        x0 = (bw - 132) / 2
        self._ok_btn.move(int(x0), 300)

    def _on_acknowledged(self):
        self.acknowledged.emit()
        self.close()

    # ------------------------------------------------------------------ 绘制
    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        try:
            w = self.width()
            h = self.height()
            self._draw_background(p, w, h)
            self._draw_header(p)
            self._draw_cross_icon(p, _W / 2, 118, color=_C_RED)

            # 文件名
            p.setPen(_C_TEXT)
            font = QFont(_FONT, 14, QFont.Bold)
            p.setFont(font)
            p.drawText(QRectF(60, 175, _W - 120, 24),
                       Qt.AlignHCenter,
                       self._file_name or '未知文件')

            # 描述文字
            p.setPen(_C_TEXT_MUTED)
            font = QFont(_FONT, 11)
            p.setFont(font)
            for i, line in enumerate(self._subtitle_lines[:2]):
                p.drawText(QRectF(60, 205 + i * 22, _W - 120, 20),
                           Qt.AlignHCenter, line)
        finally:
            p.end()


class SandboxFailureWindow(SandboxThreatWindow):
    """沙箱启动失败结果窗口（基于威胁窗口，仅替换描述文字）。"""
    def __init__(self, file_path: str = '', parent=None):
        super().__init__(file_path, parent)
        self._subtitle_lines = [
            '沙箱进程启动失败，已将其强制隔离。',
        ]


# ------------------------------------------------------------------ 回滚进度窗口
class RollbackProgressWindow(_BaseSandboxWindow):
    """勒索文件回滚进度窗口（与沙箱分析同款"滑动短横杠"视觉语言）。

    信号:
        closed: 窗口关闭（供上层清理引用，避免孤儿窗）
    """

    closed = pyqtSignal()

    _H = 330

    def __init__(self, title: str = '勒索文件回滚', parent=None):
        super().__init__('', parent)
        self._icon_kind = 'database'
        self._icon_color = QColor(_C_BLUE)
        self._title = title or '勒索文件回滚'
        self._stage = '准备中…'
        self._progress = 0
        self._anim_timer: Optional[QTimer] = None
        self._scan_x = 60.0
        self._scan_dir = 1
        self._track_left = 60.0
        self._track_right = float(_W - 60)
        self._finished = False
        self.setFixedSize(_W, self._H)

    # ---- 接口 ----
    def start(self):
        if self._anim_timer is None:
            self._anim_timer = QTimer(self)
            # PreciseTimer：40ms 滑动动画对节拍敏感；CoarseTimer 默认按 5% 粒度
            # 对齐合并，会造成忽快忽慢的"卡顿"观感。
            try:
                self._anim_timer.setTimerType(Qt.PreciseTimer)
            except Exception:
                pass
            self._anim_timer.timeout.connect(self._tick_anim)
        if not self._anim_timer.isActive():
            self._anim_timer.start(40)

    def stop(self):
        if self._anim_timer is not None:
            self._anim_timer.stop()

    def set_stage(self, text: str):
        self._stage = text or self._stage
        self.update()

    def set_progress(self, pct: int, text: str = ''):
        self._progress = max(0, min(100, int(pct)))
        if text:
            self._stage = text
        self.update()

    def finish(self, text: str = '完成'):
        """结束：停止动画并可关闭（关闭由上层判断，成功/失败/异常都调用）。"""
        self._finished = True
        self._stage = text or '完成'
        self._progress = 100
        self.stop()
        self.update()
        self.close()

    def showEvent(self, event):
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self._center()
        self.start()
        super().showEvent(event)

    def closeEvent(self, event):
        self.stop()
        try:
            self.closed.emit()
        except Exception:
            pass
        super().closeEvent(event)

    def _tick_anim(self):
        if self._finished:
            return
        self._track_left = 60.0
        self._track_right = float(self.width() - 60)
        bar_w = (self._track_right - self._track_left) / 3
        slide_max = self._track_right - bar_w
        self._scan_x += self._scan_dir * 8
        if self._scan_x >= slide_max:
            self._scan_x = slide_max
            self._scan_dir = -1
        elif self._scan_x <= self._track_left:
            self._scan_x = self._track_left
            self._scan_dir = 1
        self.update()

    # ---- 绘制 ----
    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        try:
            w = self.width()
            h = self.height()
            self._draw_background(p, w, h)
            self._draw_header(p)
            self._draw_database_icon(p, w / 2.0, 112, w=72, color=self._icon_color)

            p.setPen(_C_TEXT)
            p.setFont(QFont(_FONT, 14, QFont.Bold))
            p.drawText(QRectF(60, 158, w - 120, 24), Qt.AlignHCenter, self._title)

            # 滑动短横杠（与沙箱分析同款）
            y = 214
            bar_h = 3
            track_left = 60.0
            track_right = float(w - 60)
            bar_w = (track_right - track_left) / 3
            p.setPen(Qt.NoPen)
            p.setBrush(QBrush(_C_BORDER))
            p.drawRoundedRect(QRectF(track_left, y - bar_h / 2,
                                     track_right - track_left, bar_h),
                              bar_h / 2, bar_h / 2)
            slide_max = track_right - bar_w
            sx = max(track_left, min(self._scan_x, slide_max))
            p.setBrush(QBrush(_C_CYAN if not self._finished else _C_GREEN))
            p.drawRoundedRect(QRectF(sx, y - bar_h / 2, bar_w, bar_h),
                              bar_h / 2, bar_h / 2)

            p.setPen(_C_TEXT_DIM)
            p.setFont(QFont(_FONT, 10, QFont.Bold))
            p.drawText(QRectF(60, y + 18, w - 120, 18),
                       Qt.AlignHCenter, f'{self._progress}%')

            p.setPen(_C_TEXT)
            p.setFont(QFont(_FONT, 11))
            p.drawText(QRectF(60, 258, w - 120, 40),
                       Qt.AlignHCenter | Qt.AlignTop, self._stage)
        finally:
            p.end()


def create_rollback_progress_window(title: str = '勒索文件回滚',
                                    parent=None) -> RollbackProgressWindow:
    """创建并展示一个回滚进度窗口。"""
    w = RollbackProgressWindow(title, parent)
    w.show()
    w.start()
    return w


# ------------------------------------------------------------------ 便捷工厂
def create_sandbox_window(file_path: str = '',
                          parent=None) -> SandboxAnalysisWindow:
    """创建并展示一个沙箱分析窗口。"""
    w = SandboxAnalysisWindow(file_path, parent)
    w.show()
    w.start()
    return w


def create_release_window(file_path: str = '',
                          parent=None) -> SandboxReleaseWindow:
    """创建并展示安全放行结果窗口。"""
    w = SandboxReleaseWindow(file_path, parent)
    w.show()
    return w


def create_threat_window(file_path: str = '',
                         parent=None) -> SandboxThreatWindow:
    """创建并展示威胁判定结果窗口。"""
    w = SandboxThreatWindow(file_path, parent)
    w.show()
    return w


def create_failure_window(file_path: str = '',
                          parent=None) -> SandboxFailureWindow:
    """创建并展示沙箱启动失败结果窗口。"""
    w = SandboxFailureWindow(file_path, parent)
    w.show()
    return w