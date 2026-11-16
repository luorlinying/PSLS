# -*- coding: utf-8 -*-
"""版本号与更新日志一致性回归（V26.2.0beta）。

覆盖两块：
  1. 版本一致性：两套主题（index.html / terminal.html）、代码常量、启动页、
     安装脚本 PSLS_Setup.iss（AppVersion + OutputBaseFilename）、SetupBoot 打包
     spec 引用，全部指向同一版本；并断言下列"活"版本位置不再残留旧版本串
     （26.1.7 / V26.1.7）。
  2. 更新日志：两套主题与 build.py 生成的 README 均包含 V26.2.0beta，且 13 条
     ◆ 条目一条不少。

说明：历史更新日志条目（V26.1.7 及更早）属正常的版本历史，保留在日志正文里，
不在"残留"断言范围内——因此对两套主题只断言"活"位置的形态已被替换。
"""
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DISPLAY = 'V26.2.0beta'   # UI/展示形态
PLAIN = '26.2.0beta'      # 文件名 / AppVersion 形态
OLD_DISPLAY = 'V26.1.7'
OLD_PLAIN = '26.1.7'

# 本次更新日志的 13 条正文（与原文逐字一致，不含 ◆ 前缀）
CHANGELOG_ITEMS = [
    '优化了沙箱，使用sandboxie同捆。',
    '增加了一键终止所有进程的紧急按钮。',
    '修复了隔离区逃逸文件无法再次隔离的问题',
    '添加了勒索回滚功能。',
    '开机自启动现在设置为默认。',
    '提升了Emergency Kill的优先级，现在能够更快地结束可疑进程。',
    '提高了视觉特效检测的敏感性。',
    '持久化激进视觉特效检测。',
    '添加了拦截非法修改用户开机密钥的功能。',
    '修复了签名库可能无法加载的问题。',
    '添加了VirusIdentifier开关，现在可以自行启用该7维度启发式引擎（误报高，谨慎启用）',
    '勘误了ML错误的训练说明。',
    '引入了一部分Elastic Security技术，目前仍处于试验阶段。',
]

# 不含历史日志正文、必须彻底无旧版本串的"活"文件
OLD_FREE_FILES = [
    'ui/webview/splash.html',
    'ui/webview/splash_window.py',
    'ui/webview/bridge.py',
    'engine/self_protection.py',
    'forBT/bt_engine.py',
    'installer/PSLS_Setup.iss',
    'psls-installer-wizard/pages/language-select.html',
    'psls-installer-wizard/pages/complete.html',
    'psls-installer-wizard/pages/complete-en.html',
    'psls-installer-wizard/SetupBootOnefile.spec',
]


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class TestVersionConsistency(unittest.TestCase):

    def test_themes_carry_new_display_version(self):
        """两套主题的"活"版本位置均为 V26.2.0beta。"""
        index = _read('ui/webview/index.html')
        terminal = _read('ui/webview/terminal.html')
        # 侧边栏 / 关于 / 更新日志首条 均为新版本
        self.assertIn('PSLS V26.2.0beta', index)
        self.assertIn('>V26.2.0beta</span>', index)
        self.assertIn('>V26.2.0beta</div>', index)
        self.assertIn('<div class="version">V26.2.0beta</div>', terminal)
        self.assertIn('[ V26.2.0beta ]', terminal)
        # 旧版本只应残留在历史日志正文（每套主题 2 处：注释 + 条目标签）
        self.assertEqual(index.count(OLD_DISPLAY), 2, 'index.html 旧版本应仅剩历史日志 2 处')
        self.assertEqual(terminal.count(OLD_DISPLAY), 2, 'terminal.html 旧版本应仅剩历史日志 2 处')
        self.assertNotIn('PSLS ' + OLD_DISPLAY, index)
        self.assertNotIn('>V26.1.7</div>', index)
        self.assertNotIn('[ V26.1.7 ]', terminal)
        self.assertNotIn('<div class="version">V26.1.7</div>', terminal)

    def test_code_constants_carry_new_version(self):
        self.assertIn("APP_VERSION = 'V26.2.0beta'",
                      _read('ui/webview/splash_window.py'))
        splash = _read('ui/webview/splash.html')
        self.assertIn('PSLS V26.2.0beta', splash)
        self.assertIn("version = 'V26.2.0beta'", _read('ui/webview/bridge.py'))
        self.assertIn("'version': 'V26.2.0beta'", _read('engine/self_protection.py'))
        self.assertIn("ENGINE_VERSION = 'V26.2.0beta'", _read('forBT/bt_engine.py'))

    def test_installer_appversion_and_output_filename(self):
        iss = _read('installer/PSLS_Setup.iss')
        self.assertIn('#define MyAppVersion "26.2.0beta"', iss)
        # OutputBaseFilename 由 MyAppVersion 派生 → PSLS-Setup-26.2.0beta(.exe)
        self.assertIn('OutputBaseFilename=PSLS-Setup-{#MyAppVersion}', iss)
        self.assertIn('AppVersion={#MyAppVersion}', iss)

    def test_setupboot_spec_reference_matches(self):
        """SetupBoot 单文件打包 spec 以通配符引用安装包，须仍能命中新文件名。"""
        spec = _read('psls-installer-wizard/SetupBootOnefile.spec')
        self.assertIn("PSLS-Setup-*.exe", spec)
        self.assertNotIn(OLD_PLAIN, spec)
        # 安装向导页展示版本同步
        self.assertIn(PLAIN, _read('psls-installer-wizard/pages/language-select.html'))
        self.assertIn(PLAIN, _read('psls-installer-wizard/pages/complete.html'))
        self.assertIn(PLAIN, _read('psls-installer-wizard/pages/complete-en.html'))

    def test_no_residual_old_version_in_live_files(self):
        """活文件不得残留任何旧版本串。"""
        for rel in OLD_FREE_FILES:
            content = _read(rel)
            self.assertNotIn(OLD_PLAIN, content, f'{rel} 残留旧版本串 {OLD_PLAIN}')


class TestChangelog(unittest.TestCase):

    def _assert_entry(self, content, rel):
        self.assertIn(DISPLAY, content, f'{rel} 缺少 {DISPLAY}')
        for item in CHANGELOG_ITEMS:
            self.assertIn(item, content, f'{rel} 缺少日志条目: {item}')

    def test_index_theme_changelog(self):
        self._assert_entry(_read('ui/webview/index.html'), 'ui/webview/index.html')

    def test_terminal_theme_changelog(self):
        self._assert_entry(_read('ui/webview/terminal.html'), 'ui/webview/terminal.html')

    def test_build_readme_changelog(self):
        content = _read('build.py')
        self._assert_entry(content, 'build.py')
        # 顶部"版本:"行须为新版本（历史日志正文另计）
        self.assertIn('版本: ' + DISPLAY, content)
        self.assertNotIn('版本: ' + OLD_DISPLAY, content)

    def test_only_latest_entry_marked_latest(self):
        """两套主题里"最新版本"标记只应出现在新的 V26.2.0beta 条目上。"""
        for rel in ('ui/webview/index.html', 'ui/webview/terminal.html'):
            self.assertEqual(_read(rel).count('最新版本'), 1,
                             f'{rel} "最新版本"标记数量应为 1')


if __name__ == '__main__':
    unittest.main()