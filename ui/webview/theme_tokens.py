# -*- coding: utf-8 -*-
"""PSLS 两套内置主题的令牌（Qt 侧单一真相源）。

Web 侧两套入口页（index.html / terminal.html）各自内联同一份色值；
Qt 侧自绘窗口（威胁弹窗、启动项确认弹窗、沙箱分析/放行窗口、启动页）
统一从这里取色与形态参数，避免多处硬编码导致主题漂移。

本模块只负责"读"设置与"给"令牌；写入仍由 bridge 的
_save_ui_settings() 完成（保持设置文件的读改写在一处）。
"""
import json
import os
import re
import sys

THEME_LIGHT = 'light'
THEME_TERMINAL = 'terminal'

# ------------------------------------------------------------------ 令牌
_LIGHT = {
    'name': '米色经典',
    'mono': False,
    'is_terminal': False,
    'font_family': "'Segoe UI', 'Microsoft YaHei UI', sans-serif",
    'mono_family': "'Cascadia Code', 'Consolas', monospace",

    'background': '#f5f0e8',
    'background_soft': '#efe9de',
    'card': '#ffffff',
    'card_alt': '#faf8f3',
    'foreground': '#1a1a2e',
    'muted_foreground': '#78716c',
    'muted': '#a8a29e',
    'border': '#d6d3d1',
    'border_soft': '#e7e2d9',
    'input': '#e7e5e4',

    'primary': '#0d9488',
    'primary_foreground': '#ffffff',
    'primary_dim': '#0f766e',
    'primary_soft': 'rgba(13,148,136,0.10)',

    'danger': '#dc2626',
    'danger_soft': '#fef2f2',
    'success': '#22c55e',
    'success_text': '#16a34a',
    'success_soft': '#f0fdf4',
    'warn': '#d97706',
    'warn_text': '#b45309',
    'warn_soft': '#fffbeb',
    'info': '#2563eb',
    'info_soft': '#eff6ff',

    'radius_lg': 10,
    'radius_md': 8,
    'radius_sm': 6,
    'glow': 'none',
    'header_danger': 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #dc2626, stop:1 #b91c1c)',
    'header_warn': 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #d97706, stop:1 #b45309)',
    'header_info': 'qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #2563eb, stop:1 #1d4ed8)',
    'header_text': '#ffffff',
}

# 琥珀 CRT 磷光终端（与 psls-terminal-ui.design/assets/colors_and_type.css 对齐）
_TERMINAL = {
    'name': '琥珀终端',
    'mono': True,
    'is_terminal': True,
    'font_family': "'Courier New', 'Consolas', 'Lucida Console', monospace",
    'mono_family': "'Courier New', 'Consolas', 'Lucida Console', monospace",

    'background': '#0a0700',
    'background_soft': '#120d02',
    'card': '#0d0900',
    'card_alt': '#140e02',
    'foreground': '#FFB347',
    'muted_foreground': '#8B6914',
    'muted': '#5c4a20',
    'border': '#4a3500',
    'border_soft': '#2a1f00',
    'input': '#140e02',

    'primary': '#FF9500',
    'primary_foreground': '#0a0700',
    'primary_dim': '#CC7700',
    'primary_soft': 'rgba(255,149,0,0.10)',

    'danger': '#FF3B30',
    'danger_soft': 'rgba(255,59,48,0.12)',
    'success': '#34C759',
    'success_text': '#34C759',
    'success_soft': 'rgba(52,199,89,0.12)',
    'warn': '#FF9500',
    'warn_text': '#FFB347',
    'warn_soft': 'rgba(255,149,0,0.12)',
    'info': '#5AC8FA',
    'info_soft': 'rgba(90,200,250,0.12)',

    'radius_lg': 4,
    'radius_md': 3,
    'radius_sm': 2,
    'glow': 'rgba(255,149,0,0.35)',
    # 终端主题的标题条=纯色深底 + 琥珀文字（设计稿无渐变）
    'header_danger': '#1a0603',
    'header_warn': '#1a1103',
    'header_info': '#04141c',
    'header_text': '#FFB347',
}

THEMES = {THEME_LIGHT: _LIGHT, THEME_TERMINAL: _TERMINAL}

# ------------------------------------------------------------------ 强调色豁免
# 部分控件的色块本身就是"注意力信号"（弹窗顶部的红/琥珀/蓝渐变条），
# 被终端主题映射成深色后会失去醒目作用。用动态属性标记这些控件，
# remap_widget_tree 会跳过它们自身的 QSS 映射（子控件仍继续遍历）。
KEEP_ACCENT_PROP = 'pslsKeepAccent'


def mark_keep_accent(*widgets) -> None:
    """把控件标记为"强调色豁免"：终端主题下保留其原有色块。

    注意只豁免被标记的控件本身，所以标题文字/关闭按钮也要一并标记——
    否则标题的白色会被映射成终端琥珀色，压在红/琥珀渐变上几乎看不清。
    """
    for w in widgets:
        if w is None:
            continue
        try:
            w.setProperty(KEEP_ACCENT_PROP, True)
        except Exception:
            continue


def is_keep_accent(w) -> bool:
    """控件是否被标记为强调色豁免（未设置属性时返回 False）。"""
    try:
        return bool(w.property(KEEP_ACCENT_PROP))
    except Exception:
        return False

# load_ui_settings() 的 mtime 缓存（避免弹窗反复解析设置文件）
_CACHE = {'mtime': None, 'data': {}}


def normalize(theme) -> str:
    """把任意输入归一化为受支持的主题键（默认米色）。"""
    try:
        t = str(theme or '').strip().lower()
    except Exception:
        return THEME_LIGHT
    return t if t in THEMES else THEME_LIGHT


def palette(theme) -> dict:
    """返回指定主题的令牌 dict。"""
    return THEMES[normalize(theme)]


# ------------------------------------------------------------------ 米色固定色 -> 终端色（Qt QSS）
# Qt 侧窗口历史上把米色期色值写死在 QSS 与 QPainter 调用里。这里集中映射一次：
# 米色主题原样返回（保证米色视觉逐像素不变），只在终端主题下替换。
QSS_COLOR_REMAP = (
    # 表面
    ('#ffffff', _TERMINAL['card']),
    ('#faf8f3', _TERMINAL['card_alt']),
    ('#f5f0e8', _TERMINAL['background']),
    ('#efe9de', _TERMINAL['background_soft']),
    # 描边 / 输入
    ('#d6d3d1', _TERMINAL['border']),
    ('#e7e2d9', _TERMINAL['border_soft']),
    ('#e7e5e4', _TERMINAL['input']),
    ('#b09b73', _TERMINAL['border']),
    ('#c9b48c', _TERMINAL['border_soft']),
    # 文本
    ('#1a1a2e', _TERMINAL['foreground']),
    ('#78716c', _TERMINAL['muted_foreground']),
    ('#a8a29e', _TERMINAL['muted']),
    ('#44403c', _TERMINAL['foreground']),
    ('#374151', _TERMINAL['foreground']),
    ('#4b5563', _TERMINAL['muted_foreground']),
    ('#6b7280', _TERMINAL['muted_foreground']),
    # 主色
    ('#0d9488', _TERMINAL['primary']),
    ('#0f766e', _TERMINAL['primary_dim']),
    ('#7c3aed', _TERMINAL['primary']),
    ('#6d28d9', _TERMINAL['primary_dim']),
    # 危险
    ('#dc2626', _TERMINAL['danger']),
    ('#b91c1c', _TERMINAL['danger']),
    ('#991b1b', _TERMINAL['danger']),
    ('#7f1d1d', _TERMINAL['danger']),
    # 警告
    ('#d97706', _TERMINAL['warn']),
    ('#b45309', _TERMINAL['warn']),
    ('#92400e', _TERMINAL['warn']),
    ('#78350f', _TERMINAL['warn']),
    ('#f59e0b', _TERMINAL['warn']),
    ('#fef3c7', _TERMINAL['warn_soft']),
    # 信息
    ('#2563eb', _TERMINAL['info']),
    ('#1d4ed8', _TERMINAL['info']),
)

# 圆角收敛：米色用 6~10px，终端按设计稿收到 4px
# 注意必须限定 -radius 关键字，否则会把 `border: 1px solid` 的线宽也改掉
_RADIUS_RE = re.compile(
    r'(border(?:-(?:top|bottom)-(?:left|right))?-radius\s*:\s*)(\d+)px')


def remap_qss(qss: str, theme) -> str:
    """把米色期写死的 QSS 映射到当前主题色板。

    light 主题原样返回；terminal 主题下：
      1) 先把三条弹窗头部渐变整体换成终端纯色深底（否则标题文字对比度不足）
      2) 再做逐色替换
      3) 圆角统一收敛到 4px，标题/关闭按钮的白色改为琥珀
    """
    if normalize(theme) != THEME_TERMINAL or not qss:
        return qss
    out = qss
    for key in ('header_danger', 'header_warn', 'header_info'):
        out = out.replace(_LIGHT[key], _TERMINAL[key])
    for src, dst in QSS_COLOR_REMAP:
        out = out.replace(src, dst)
        out = out.replace(src.upper(), dst)
    out = _RADIUS_RE.sub(lambda m: m.group(1) + '%dpx' % _TERMINAL['radius_lg'], out)
    out = out.replace('color: white', 'color: %s' % _TERMINAL['header_text'])
    out = out.replace('color:white', 'color: %s' % _TERMINAL['header_text'])
    out = out.replace('color: #fff', 'color: %s' % _TERMINAL['header_text'])
    # 实心按钮：米色期是"主色底 + 白字"，终端下底色变成亮琥珀，文字必须反过来用深色，
    # 否则琥珀字压琥珀底几乎看不见。
    for fill_key in ('primary', 'danger', 'warn', 'success'):
        fill = _TERMINAL[fill_key]
        out = out.replace(
            'background: %s; color: %s' % (fill, _TERMINAL['header_text']),
            'background: %s; color: %s' % (fill, _TERMINAL['primary_foreground']))
        out = out.replace(
            'background-color: %s; color: %s' % (fill, _TERMINAL['header_text']),
            'background-color: %s; color: %s' % (fill, _TERMINAL['primary_foreground']))
    return out


def remap_widget_tree(root, theme) -> None:
    """对整棵控件树已设置的内联 QSS 做一次主题映射（light 主题为 no-op）。

    在窗口 _setup_ui() 末尾调用即可：不改动任何布局/尺寸逻辑，
    只在终端主题下把"米色固定色"换成终端色板。
    """
    if normalize(theme) != THEME_TERMINAL or root is None:
        return
    stack = [root]
    guard = 0
    while stack and guard < 5000:
        guard += 1
        w = stack.pop()
        try:
            if is_keep_accent(w):
                # 强调色控件：保留原有色块，仅继续遍历子控件
                stack.extend(w.children())
                continue
            qss = w.styleSheet()
            if qss:
                new_qss = remap_qss(qss, theme)
                if new_qss != qss:
                    w.setStyleSheet(new_qss)
            stack.extend(w.children())
        except Exception:
            continue


def apply_window_palette(root, theme) -> None:
    """终端主题下给窗口树设置一套深底琥珀调色板。

    必要原因：不少控件没有显式设置文字颜色，用的是 Qt 默认调色板（黑字）。
    深色卡片背景下黑字不可见，必须靠 palette 让"默认色文字"也变成琥珀色。
    """
    if normalize(theme) != THEME_TERMINAL or root is None:
        return
    try:
        from PyQt5.QtGui import QPalette, QColor
    except Exception:
        return
    p = _TERMINAL
    try:
        pal = QPalette()
        pal.setColor(QPalette.Window, QColor(p['card']))
        pal.setColor(QPalette.WindowText, QColor(p['foreground']))
        pal.setColor(QPalette.Base, QColor(p['card']))
        pal.setColor(QPalette.AlternateBase, QColor(p['background_soft']))
        pal.setColor(QPalette.Text, QColor(p['foreground']))
        pal.setColor(QPalette.Button, QColor(p['background_soft']))
        pal.setColor(QPalette.ButtonText, QColor(p['foreground']))
        pal.setColor(QPalette.ToolTipBase, QColor(p['card']))
        pal.setColor(QPalette.ToolTipText, QColor(p['foreground']))
        pal.setColor(QPalette.Highlight, QColor(p['primary']))
        pal.setColor(QPalette.HighlightedText, QColor(p['primary_foreground']))
        pal.setColor(QPalette.PlaceholderText, QColor(p['muted_foreground']))
        pal.setColor(QPalette.Disabled, QPalette.WindowText, QColor(p['muted_foreground']))
        pal.setColor(QPalette.Disabled, QPalette.Text, QColor(p['muted_foreground']))
        pal.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(p['muted_foreground']))
        root.setPalette(pal)
    except Exception:
        return


def apply_mono_font(root, theme) -> None:
    """终端主题下把整棵控件树的字体族切为等宽（只改族名，不改字号）。

    只作用于传入的窗口树（自绘弹窗/沙箱窗口/启动页），不动全局 QApplication 字体，
    因此不影响 WebView 与其它窗口。
    """
    if normalize(theme) != THEME_TERMINAL or root is None:
        return
    try:
        from PyQt5.QtGui import QFont
    except Exception:
        return
    family = _TERMINAL['mono_family'].split(',')[0].strip().strip("'\"")
    stack = [root]
    guard = 0
    while stack and guard < 5000:
        guard += 1
        w = stack.pop()
        try:
            f = w.font()
            if f is None:
                f = QFont()
            if f.family() != family:
                f.setFamily(family)
                w.setFont(f)
            stack.extend(w.children())
        except Exception:
            continue


def theme_window(root, theme=None) -> None:
    """一站式为自绘窗口套用当前主题：调色板 + 色板映射 + 等宽字体。"""
    t = theme if theme is not None else load_theme()
    apply_window_palette(root, t)
    remap_widget_tree(root, t)
    apply_mono_font(root, t)


# ------------------------------------------------------------------ 设置读取
def settings_path() -> str:
    """返回用户设置文件路径（%APPDATA%\\PSLS\\settings.json）。"""
    if sys.platform == 'win32':
        appdata = os.environ.get('APPDATA') or os.path.expanduser('~')
    else:
        appdata = os.path.expanduser('~/.config')
    psls_dir = os.path.join(appdata, 'PSLS')
    try:
        os.makedirs(psls_dir, exist_ok=True)
    except Exception:
        pass
    return os.path.join(psls_dir, 'settings.json')


def load_ui_settings() -> dict:
    """读取持久化的用户界面设置（"ui" 段），失败返回空 dict。

    带 mtime 缓存：弹窗/沙箱窗口每次构造都会读一次，避免反复解析 JSON；
    设置文件被改写时 mtime 变化即自动失效。
    """
    try:
        path = settings_path()
        if not os.path.exists(path):
            return {}
        mtime = os.path.getmtime(path)
        if _CACHE['mtime'] == mtime:
            return _CACHE['data']
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        section = data.get('ui') if isinstance(data, dict) else None
        section = section if isinstance(section, dict) else {}
        _CACHE['mtime'] = mtime
        _CACHE['data'] = section
        return section
    except Exception:
        return {}


def load_theme() -> str:
    """读取当前主题（'light' / 'terminal'）。"""
    return normalize(load_ui_settings().get('theme', THEME_LIGHT))


def load_motion() -> bool:
    """读取"动态光效"开关（默认开启）。"""
    try:
        return bool(load_ui_settings().get('motion_effects', True))
    except Exception:
        return True