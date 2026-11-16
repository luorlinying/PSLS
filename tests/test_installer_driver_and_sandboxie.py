# -*- coding: utf-8 -*-
"""安装器驱动部署 + Sandboxie 目录/图标 回归。

要求：
  1) 安装器携带并部署 PSLS.sys（复制到 System32\\drivers + sc create/start），
     与 utils/driver_manager 同一服务名/路径；失败只提示不阻断安装；卸载清理。
  2) Sandboxie 装到 PSLS 目录下（{app}\\Sandboxie）、不创建桌面图标；
     运行时定位优先该目录，回退旧路径，都找不到时安全降级。
"""
import os
import sys
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ISS_PATH = os.path.join(ROOT, 'installer', 'PSLS_Setup.iss')


def _read(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def _section(src, name):
    """取 ini 段内容（以行首 '[' 作为下一段边界，避免被正文里的 [Code] 干扰）。"""
    body = src.split(name + '\n', 1)
    if len(body) < 2:
        body = src.split(name, 1)
    return body[1].split('\n[', 1)[0]


class TestInstallerDriverEntries(unittest.TestCase):

    def setUp(self):
        self.src = _read(ISS_PATH)

    def test_driver_files_included(self):
        files = _section(self.src, '[Files]')
        self.assertIn('PSLS.sys', files, '安装器必须携带 PSLS.sys')
        self.assertIn('driver\\out\\PSLS.sys', files)
        self.assertIn('skipifsourcedoesntexist', files,
                      '驱动缺失时 ISCC 仍须能编译（不阻断发布）')

    def test_service_create_start_present(self):
        code = self.src.split('[Code]', 1)[1]
        self.assertIn('DeployPslsDriver', code)
        self.assertIn("'create ' + DriverServiceName", code)
        self.assertIn("'start ' + DriverServiceName", code)
        self.assertIn("DriverServiceName = 'PSLS'", code)
        self.assertIn(r"DriverNtPath = '\SystemRoot\System32\drivers\PSLS.sys'", code)

    def test_graceful_degradation_and_hint(self):
        code = self.src.split('[Code]', 1)[1]
        # 未签名/测试签名未开 → 明确提示，且不阻断安装
        self.assertIn('ERROR_INVALID_IMAGE_HASH', code)
        self.assertIn('testsigning', code)
        self.assertIn('用户态保护', code)
        # Inno Pascal 无异常机制：不得出现 try/except 语句
        flat = code.replace('\r', '')
        self.assertNotIn('\ntry\n', flat)
        self.assertNotIn('\nexcept\n', flat)

    def test_uninstall_removes_driver(self):
        self.assertIn('RemovePslsDriver', self.src)
        unrun = _section(self.src, '[UninstallRun]')
        self.assertIn('sc.exe', unrun)
        self.assertIn('stop PSLS', unrun)
        self.assertIn('delete PSLS', unrun)
        undel = _section(self.src, '[UninstallDelete]')
        self.assertIn(r'{sys}\drivers\PSLS.sys', undel)

    def test_sandboxie_dir_under_app_and_no_desktop_icon(self):
        run = _section(self.src, '[Run]')
        hits = [l for l in run.splitlines() if 'Sandboxie-Plus-x64' in l]
        self.assertTrue(hits, '[Run] 应包含 Sandboxie 安装条目')
        line = hits[0]
        self.assertIn('/DIR=', line, 'Sandboxie 必须指定安装目录')
        self.assertIn(r'{app}\Sandboxie', line,
                      'Sandboxie 必须装到 {app}\\Sandboxie')
        self.assertIn('!desktopicon', line, '必须抑制 Sandboxie 桌面图标')
        self.assertIn('!quicklaunchicon', line)
        # 不得为 Sandboxie 创建公共桌面/启动 图标
        self.assertNotIn('{commondesktop}', self.src)
        self.assertNotIn('{commonstartup}', self.src)

    def test_service_name_matches_driver_manager(self):
        from utils import driver_manager as dm
        self.assertEqual(dm.SERVICE_NAME, 'PSLS')
        nt = dm.DRIVER_NT_PATH.replace('/', '\\')
        self.assertIn('System32', nt)
        self.assertIn(r'drivers\PSLS.sys', nt)
        # 安装器侧同一服务名 + 同一镜像路径
        self.assertIn("DriverServiceName = 'PSLS'", self.src)
        self.assertIn(r'drivers\PSLS.sys', self.src)


class TestSandboxieDirResolution(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='psls_sbie_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mk(self, base, name='Sandboxie'):
        d = os.path.join(base, name)
        os.makedirs(d, exist_ok=True)
        for exe in ('Start.exe', 'SbieIni.exe'):
            with open(os.path.join(d, exe), 'wb') as f:
                f.write(b'MZ')
        return d

    def test_prefers_psls_bundled_dir(self):
        import engine.sandbox_analyzer as sa
        base = os.path.join(self.tmp, 'app')
        os.makedirs(base, exist_ok=True)
        bundled = self._mk(base)
        with mock.patch.object(sys, 'frozen', True, create=True), \
                mock.patch.object(sys, 'executable', os.path.join(base, 'PSLS.exe')), \
                mock.patch.object(sa, '_sandboxie_dir_from_registry',
                                  return_value=r'C:\Program Files\Sandboxie-Plus'), \
                mock.patch.object(sa, '_IS_WINDOWS', True), \
                mock.patch.object(sa, '_sandboxie_service_present', return_value=True), \
                mock.patch.object(sa, '_sandboxie_driver_present', return_value=True):
            got = sa._psls_bundled_sandboxie_dir()
            self.assertEqual(os.path.normcase(got), os.path.normcase(bundled))
            info = sa.detect_sandboxie_backend()
        self.assertEqual(os.path.normcase(info['dir']), os.path.normcase(bundled))
        self.assertEqual(info.get('dir_source'), 'psls_bundled')

    def test_falls_back_to_registry_when_not_bundled(self):
        import engine.sandbox_analyzer as sa
        base = os.path.join(self.tmp, 'app2')
        os.makedirs(base, exist_ok=True)          # 没有 Sandboxie 子目录
        legacy = self._mk(self.tmp, 'Sandboxie-Plus')
        with mock.patch.object(sys, 'frozen', True, create=True), \
                mock.patch.object(sys, 'executable', os.path.join(base, 'PSLS.exe')), \
                mock.patch.object(sa, '_sandboxie_dir_from_registry', return_value=legacy), \
                mock.patch.object(sa, '_IS_WINDOWS', True), \
                mock.patch.object(sa, '_sandboxie_service_present', return_value=True), \
                mock.patch.object(sa, '_sandboxie_driver_present', return_value=True):
            self.assertIsNone(sa._psls_bundled_sandboxie_dir())
            info = sa.detect_sandboxie_backend()
        self.assertEqual(os.path.normcase(info['dir']), os.path.normcase(legacy))
        self.assertEqual(info.get('dir_source'), 'registry')

    def test_safe_degrade_when_no_sandboxie(self):
        import engine.sandbox_analyzer as sa
        base = os.path.join(self.tmp, 'app3')
        os.makedirs(base, exist_ok=True)
        with mock.patch.object(sys, 'frozen', True, create=True), \
                mock.patch.object(sys, 'executable', os.path.join(base, 'PSLS.exe')), \
                mock.patch.object(sa, '_sandboxie_dir_from_registry', return_value=None), \
                mock.patch.object(sa, '_SANDBOXIE_DEFAULT_DIRS', ()), \
                mock.patch.object(sa, '_IS_WINDOWS', True):
            info = sa.detect_sandboxie_backend()
        self.assertFalse(info['available'], '找不到时须安全降级（不抛异常）')
        self.assertTrue(info['reason'])
        self.assertEqual(info.get('dir_source'), '')


if __name__ == '__main__':
    unittest.main()