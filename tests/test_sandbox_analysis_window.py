# -*- coding: utf-8 -*-
"""SandboxAnalysisWindow / SandboxReleaseWindow 单元测试

验证（按用户需求）：
1. 窗口背景 = PSLS 主窗口米色 (#f5f0e8)
2. 左上角仅 PSLS 图标 + "Project Sertraline Lab 软件分析室"
3. 中间图标 = 数据库查看卡片图标（file-search 放大镜形状）改红色
4. 描述文字两行："该程序进程已被终止。" + "璱鸲计划实验室正在进行分析以确认它是否安全。"
5. 进度条仅保留来回移动的短横杠（无填充长条）
6. "查看详细信息"箭头为 ▼ / ▲
7. 展开时窗口向下扩展，显示详细信息
8. 无右上角关闭按钮
9. 窗口不可移动
10. 沙箱分析完成后立即关闭窗口（completed 信号）
11. clean → SandboxReleaseWindow（同风格安全放行窗口：同意重启/不重启 + 5s 超时默认拒绝）
"""
import sys
import os
import unittest

# 将 ui/webview 加入 path
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, '..', 'ui', 'webview'))

from PyQt5.QtCore import Qt, QPointF, QRectF
from PyQt5.QtWidgets import QApplication

_app = None


def _ensure_app():
    global _app
    if _app is None:
        _app = QApplication.instance()
        if _app is None:
            _app = QApplication([])


class TestSandboxAnalysisWindow(unittest.TestCase):
    """分析进度窗口（米色、品牌头、红色图标、短横杠进度、向下扩展详情）。"""

    @classmethod
    def setUpClass(cls):
        _ensure_app()

    def _make(self, path='C:\\test\\WinPerf.exe'):
        from sandbox_analysis_window import SandboxAnalysisWindow
        w = SandboxAnalysisWindow(path)
        self.addCleanup(lambda: (w.close(), w.deleteLater()))
        return w

    def test_01_window_properties(self):
        """窗口创建：无边框 + 置顶 + 标题含文件名。"""
        w = self._make('C:\\test\\WinPerf.exe')
        self.assertTrue(w.windowFlags() & Qt.FramelessWindowHint, "应无边框")
        self.assertTrue(w.windowFlags() & Qt.WindowStaysOnTopHint, "应置顶")
        self.assertIn('WinPerf', w.windowTitle(), "标题应含文件名")
        self.assertEqual(w._file_name, 'WinPerf.exe', "文件名解析")

    def test_02_beige_background(self):
        """背景应为 PSLS 主窗口米色 #f5f0e8。"""
        w = self._make()
        self.assertEqual(w._bg_color.name().upper(), '#F5F0E8',
                         "背景应为 PSLS 主窗口米色")

    def test_03_brand_header(self):
        """左上角品牌文字应为 'Project Sertraline Lab 软件分析室'。"""
        from sandbox_analysis_window import _BRAND_TITLE
        self.assertEqual(_BRAND_TITLE, 'Project Sertraline Lab 软件分析室')
        w = self._make()
        self.assertTrue(hasattr(w, '_brand_title'))
        self.assertEqual(w._brand_title, _BRAND_TITLE)

    def test_04_database_icon_red(self):
        """中间图标应为数据库查看卡片图标样式且为红色。"""
        w = self._make()
        self.assertEqual(w._icon_kind, 'database',
                         "图标类型应为数据库查看卡片图标")
        self.assertEqual(w._icon_color.name().upper(), '#E11D48',
                         "图标颜色应为 PSLS 红色")

    def test_05_desc_lines(self):
        """描述文字两行（进程已终止 + 实验室分析中）。"""
        w = self._make()
        self.assertGreaterEqual(len(w._desc_lines), 2)
        self.assertIn('该程序进程已被终止', w._desc_lines[0])
        self.assertIn('实验室正在进行分析', w._desc_lines[1])

    def test_06_start_stop_animation(self):
        """动画计时器启动/停止。"""
        w = self._make()
        w.start()
        self.assertIsNotNone(w._anim_timer, "启动后应有动画计时器")
        self.assertTrue(w._anim_timer.isActive(), "计时器应活跃")
        w.stop()
        self.assertFalse(w._anim_timer.isActive(), "停止后应失活")

    def test_07_sweep_bar_moves(self):
        """仅短横杠在轨道内来回运动（无填充长条）。"""
        w = self._make()
        w.start()
        self.assertFalse(w._show_fill_bar, "不应绘制填充长条")
        initial_x = w._scan_x
        for _ in range(300):
            w._tick_anim()
        self.assertNotEqual(initial_x, w._scan_x, "短横杠应发生位移")
        self.assertGreaterEqual(w._scan_x, w._track_left - 1.0,
                                "不应越过左边界")
        self.assertLessEqual(w._scan_x, w._track_right + 1.0,
                             "不应越过右边界")
        w.stop()

    def test_08_update_status(self):
        """状态与进度更新接口。"""
        w = self._make()
        w.set_status('正在扫描...')
        self.assertIn('正在扫描', w._status_text, "状态文本更新")
        w.set_progress(42, '分析 PE 结构')
        self.assertEqual(w._progress, 42, "进度百分比")
        self.assertIn('PE 结构', w._progress_text, "进度文本更新")

    def test_09_detail_arrow_and_expand(self):
        """▼/▲ 箭头 + 展开向下扩展窗口高度。"""
        from sandbox_analysis_window import _H, _H_EXPANDED
        w = self._make()
        w.set_details(['规则引擎命中: Backdoor',
                       '可疑 API: CreateRemoteThread',
                       'TLS 回调异常'])

        # 初始收起
        self.assertFalse(w._detail_expanded, "初始收起")
        self.assertEqual(w.height(), _H, "初始高度为收起高度")
        self.assertIn('▼', w._arrow_label(), "收起时应显示 ▼")

        # 展开 → 高度增加（向下扩展）
        w.toggle_detail()
        self.assertTrue(w._detail_expanded, "展开")
        self.assertEqual(w.height(), _H_EXPANDED, "展开后高度应增加")
        self.assertIn('▲', w._arrow_label(), "展开时应显示 ▲")

        # 收回归位
        w.toggle_detail()
        self.assertFalse(w._detail_expanded, "收回")
        self.assertEqual(w.height(), _H, "收回后恢复原高度")

    def test_10_no_close_button(self):
        """不应存在右上角关闭按钮。"""
        w = self._make()
        self.assertFalse(hasattr(w, '_close_rect'), "不应有关闭按钮热区")
        self.assertFalse(hasattr(w, '_on_close_clicked'), "不应有关闭处理")

    def test_11_not_movable(self):
        """窗口不可移动。"""
        w = self._make()
        self.assertFalse(getattr(w, '_can_drag', True),
                         "窗口应不可拖拽移动")

    def test_12_auto_close_on_complete(self):
        """沙箱分析完成后立即关闭窗口并发出 completed 信号。"""
        w = self._make()
        w.show()
        completed = []
        w.completed.connect(lambda: completed.append(True))
        w.set_result('clean', '文件安全')
        self.assertTrue(completed, "完成应发出 completed 信号")
        self.assertFalse(w.isVisible(), "完成后应关闭窗口")


class TestSandboxReleaseWindow(unittest.TestCase):
    """安全放行结果窗口（clean 时展示，与分析窗口同风格）。"""

    @classmethod
    def setUpClass(cls):
        _ensure_app()

    def _make(self, path='C:\\test\\safe.exe'):
        from sandbox_analysis_window import SandboxReleaseWindow
        w = SandboxReleaseWindow(path)
        self.addCleanup(lambda: (w.close(), w.deleteLater()))
        return w

    def test_01_release_window_properties(self):
        """放行窗口：无边框 + 置顶 + 米色背景 + 品牌头。"""
        w = self._make()
        w.set_file_path('C:\\test\\WinPerf.exe')
        self.assertTrue(w.windowFlags() & Qt.FramelessWindowHint, "无边框")
        self.assertTrue(w.windowFlags() & Qt.WindowStaysOnTopHint, "置顶")
        self.assertEqual(w._bg_color.name().upper(), '#F5F0E8', "米色背景")
        self.assertIn('WinPerf', w.windowTitle(), "标题含文件名")

    def test_02_safe_icon(self):
        """安全图标应为绿色对勾。"""
        w = self._make()
        self.assertEqual(w._icon_kind, 'check', "应为对勾图标")
        self.assertEqual(w._icon_color.name().upper(), '#22C55E',
                         "应为安全绿")

    def test_03_release_accept(self):
        """点击同意重启 → releaseAccepted 信号。"""
        w = self._make()
        accepted = []
        w.releaseAccepted.connect(lambda: accepted.append(True))
        w._on_release_accept()
        self.assertTrue(accepted, "同意重启应发出信号")

    def test_04_release_reject(self):
        """点击不重启 → releaseRejected 信号。"""
        from sandbox_analysis_window import SandboxReleaseWindow
        w = self._make()
        rejected = []
        w.releaseRejected.connect(lambda: rejected.append(True))
        w._on_release_reject()
        self.assertTrue(rejected, "不重启应发出信号")

    def test_05_timeout_defaults_reject(self):
        """5 秒超时默认不重启。"""
        w = self._make()
        rejected = []
        w.releaseRejected.connect(lambda: rejected.append(True))
        w._on_timeout_default()
        self.assertTrue(rejected, "超时默认不重启")
        self.assertFalse(w.isVisible() or hasattr(w, '_closed_by_user') is False,
                         "超时后窗口应被标记关闭")


if __name__ == '__main__':
    unittest.main()