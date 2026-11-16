#!/usr/bin/env python3
"""
开机自启动管理器
实现两种开机自启方式，**优先采用"最高优先级"方案**：

1. 计划任务（最高优先级，首选）
   登录触发（/SC ONLOGON）+ 最高权限（/RL HIGHEST）+ 零延迟。
   相比注册表 Run 自启项在用户登录时更早、更高权限地启动，
   是 Windows 上"启动项最高优先级"的主要载体（需管理员权限创建）。
2. 注册表 HKCU\\...\\Run（兜底）
   用户级别，无需管理员权限。

计划任务创建成功时自动清理注册表 Run 项，避免双启动。

支持开发模式（python.exe + 脚本）和打包模式（PyInstaller .exe）
支持 --minimized 参数，开机启动后静默最小化到系统托盘
"""

import os
import subprocess
import sys

from utils.logger import get_logger

logger = get_logger('autostart')

# 注册表自启键路径（兜底方案）
AUTOSTART_REG_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'
# 注册表值名称
AUTOSTART_VALUE_NAME = 'PSLS'
# 计划任务名（最高优先级方案）
AUTOSTART_TASK_NAME = 'PSLS'

# 静默启动参数
MINIMIZED_ARG = '--minimized'

# Windows 进程优先级类常量（SetPriorityClass）
# 0x00000080 = HIGH_PRIORITY_CLASS（最高优先级）
_HIGH_PRIORITY_CLASS = 0x00000080


def _get_app_command() -> str:
    """获取应用程序启动命令字符串

    开发模式：pythonw.exe "path/to/gui_entry.py" --minimized
    打包模式："path/to/PSLS.exe" --minimized

    Returns:
        启动命令字符串（带引号和 --minimized 参数）
    """
    if getattr(sys, 'frozen', False):
        # PyInstaller 打包模式
        exe_path = sys.executable
        return f'"{exe_path}" {MINIMIZED_ARG}'
    else:
        # 开发模式：使用 pythonw.exe（无控制台窗口）
        # 优先使用 pythonw.exe，找不到则回退到当前 Python 解释器
        python_exe = sys.executable
        pythonw = python_exe.replace('python.exe', 'pythonw.exe')
        if os.path.exists(pythonw):
            python_exe = pythonw

        # 获取入口脚本路径
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'gui_entry.py'
        )
        return f'"{python_exe}" "{script_path}" {MINIMIZED_ARG}'


def apply_high_priority_class() -> bool:
    """将当前进程优先级提升为 HIGH（最高优先级）。

    在开机自启模式（--minimized）下调用：相比其他自启动程序/后台进程，
    PSLS 的防护线程（MBR 0.25s 轮询、进程创建、注册表监测等）优先获得
    CPU 调度，不被饿死。扫描 worker 由 load_governor 限流降载，
    不影响整体系统调度安全。

    Returns:
        True 设置成功（或非 Windows 平台视为成功），False 失败
    """
    if sys.platform != 'win32':
        return True
    try:
        import ctypes
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        ok = ctypes.windll.kernel32.SetPriorityClass(
            ctypes.c_void_p(handle), _HIGH_PRIORITY_CLASS)
        if ok:
            logger.info('进程优先级已提升为 HIGH（最高优先级）')
            return True
        logger.warning(f'设置 HIGH 优先级失败，错误码: {ctypes.get_last_error()}')
        return False
    except Exception as e:
        logger.error(f'设置 HIGH 优先级异常: {e}')
        return False


class AutoStartManager:
    """开机自启动管理器

    首选"登录触发 + 最高权限"计划任务（Windows 启动项最高优先级），
    无管理员权限时回退到注册表 HKCU\\...\\Run。
    两种方式任一启用即视为开机自启已开启；禁用时全部清理。
    """

    def __init__(self):
        self._available = sys.platform == 'win32'

    def is_available(self) -> bool:
        """是否支持开机自启（仅 Windows 平台）"""
        return self._available

    def is_autostart_enabled(self) -> bool:
        """检查开机自启是否已启用

        两种方式任一启用即视为开启：
        - 计划任务 PSLS（最高优先级路径）
        - 注册表 HKCU\\...\\Run 项指向当前应用（兜底路径）

        Returns:
            True 如果开机自启已启用
        """
        if not self._available:
            return False

        try:
            if self._priority_task_exists():
                return True
        except Exception as e:
            logger.warning(f'查询计划任务状态异常: {e}')

        return self._is_reg_run_enabled()

    def enable_autostart(self) -> bool:
        """启用开机自启动（最高优先级）

        第一步先注册"登录触发 + 最高权限"计划任务——这是 Windows 上
        启动项的最高优先级方案；成功时清理注册表 Run 项防止双启动。
        计划任务创建失败（通常因缺少管理员权限）时回退到注册表 Run。

        Returns:
            True 成功，False 失败
        """
        if not self._available:
            logger.warning('当前平台不支持开机自启')
            return False

        # 首选：计划任务（登录触发 + 最高权限 + 零延迟）
        if self._enable_priority_task():
            self._remove_run_key()
            logger.info('开机自启已启用（计划任务方式，最高优先级）')
            return True

        # 兜底：注册表 HKCU\\...\\Run（用户级，无需管理员）
        try:
            import winreg
            command = _get_app_command()

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                AUTOSTART_REG_KEY,
                0,
                winreg.KEY_SET_VALUE
            ) as key:
                winreg.SetValueEx(
                    key,
                    AUTOSTART_VALUE_NAME,
                    0,
                    winreg.REG_SZ,
                    command
                )

            logger.info(f'已启用开机自启（注册表 Run 方式）: {command}')
            return True
        except OSError as e:
            logger.error(f'启用开机自启失败（注册表写入错误）: {e}')
            return False
        except Exception as e:
            logger.error(f'启用开机自启异常: {e}')
            return False

    def disable_autostart(self) -> bool:
        """禁用开机自启动（计划任务与注册表 Run 一并清理）

        Returns:
            True 成功（任一路径清理成功即视为成功），False 失败
        """
        if not self._available:
            return False

        # 1) 清理注册表 Run 项
        run_ok = True
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                AUTOSTART_REG_KEY,
                0,
                winreg.KEY_SET_VALUE
            ) as key:
                try:
                    winreg.DeleteValue(key, AUTOSTART_VALUE_NAME)
                    logger.info('已禁用开机自启（注册表 Run 项）')
                except FileNotFoundError:
                    # 本来就没有，视为成功
                    logger.info('注册表无 PSLS 自启项，跳过')
        except OSError as e:
            logger.error(f'禁用开机自启失败（注册表访问错误）: {e}')
            run_ok = False
        except Exception as e:
            logger.error(f'禁用开机自启异常: {e}')
            run_ok = False

        # 2) 清理计划任务（删除失败仅告警）
        task_ok = self._disable_priority_task()

        return run_ok or task_ok

    def set_autostart(self, enabled: bool) -> bool:
        """设置开机自启状态

        Args:
            enabled: True 启用，False 禁用

        Returns:
            操作是否成功
        """
        if enabled:
            return self.enable_autostart()
        else:
            return self.disable_autostart()

    def get_status(self) -> dict:
        """获取开机自启状态信息

        Returns:
            {
                'available': bool,    # 平台是否支持
                'enabled': bool,      # 是否已启用
                'priority': bool,     # 是否以最高优先级（计划任务）方式启用
                'command': str,       # 当前启动命令（若启用）
            }
        """
        if not self._available:
            return {'available': False, 'enabled': False, 'priority': False, 'command': ''}

        enabled = self.is_autostart_enabled()
        priority = False
        command = ''
        if enabled:
            priority = self._priority_task_exists()
            if priority:
                command = _get_app_command()
            else:
                try:
                    import winreg
                    with winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER,
                        AUTOSTART_REG_KEY,
                        0,
                        winreg.KEY_READ
                    ) as key:
                        try:
                            command, _ = winreg.QueryValueEx(key, AUTOSTART_VALUE_NAME)
                        except FileNotFoundError:
                            pass
                except Exception:
                    pass

        return {
            'available': True,
            'enabled': enabled,
            'priority': priority,
            'command': command,
        }

    # ------------------------------------------------------------------
    # 计划任务（最高优先级启动项）私有实现
    # ------------------------------------------------------------------
    def _priority_task_exists(self) -> bool:
        """计划任务 PSLS 是否已注册且命令指向当前应用

        解析 /V 详情的 Task To Run 行，比对可执行文件路径，
        与注册表 Run 项的路径校验保持一致（安装目录移动后视为未启用）。
        """
        code, out, err = self._run_schtasks(
            ['/Query', '/TN', AUTOSTART_TASK_NAME, '/FO', 'LIST', '/V'])
        if code != 0:
            return False
        cur = self._extract_exe_path(_get_app_command())
        for line in out.splitlines():
            stripped = line.lstrip()
            if stripped.startswith(('Task To Run:', '任务要运行:')):
                value = stripped.split(':', 1)[1].strip()
                if self._task_command_matches(value, cur):
                    return True
                # 路径不匹配：视为未启用（便于 GUI 开关回滚并重新注册）
                return False
        # 查询成功但未解析到 "Task To Run" 行（本地化/编码差异）→ 以"任务存在"
        # 兜底，避免因解析差异把已注册的自启误判为未启用（重启后开关变灰）。
        return True

    @staticmethod
    def _task_command_matches(value: str, expected_exe: str) -> bool:
        """比对计划任务 "Task To Run" 的命令是否指向期望的可执行文件。

        schtasks 输出的 Task To Run 有两种形态：
          - 带引号: "C:\\Program Files\\PSLS\\PSLS.exe" --minimized
          - 不带引号: C:\\Program Files\\PSLS\\PSLS.exe --minimized
        旧实现用 _extract_exe_path 取"第一个空格前的部分"，安装路径含空格
        （默认 {autopf}\\PSLS = C:\\Program Files\\PSLS）时会被截断成
        'c:\\program'，导致比对永远失败 → 重启后自启开关被后端判为"未启用"
        而显示为关闭/变灰（实际计划任务已注册且生效）。

        这里改为：去掉首尾引号后按"规范化前缀 + 边界字符"匹配，兼容两种形态。
        """
        try:
            v = (value or '').strip().strip('"').strip()
            v_low = v.lower().replace('/', '\\')
            e = (expected_exe or '').strip().strip('"').lower().replace('/', '\\')
            if not e or not v_low.startswith(e):
                return False
            # 前缀之后必须是结束/空白/引号，避免 "PSLS.exe" 误匹配 "PSLS.exe.bak"
            rest = v_low[len(e):]
            return rest == '' or rest[0] in ' \t"'
        except Exception:
            return False

    def _enable_priority_task(self) -> bool:
        """注册"登录触发 + 最高权限"计划任务

        schtasks 参数说明：
          /SC ONLOGON  登录时触发（零延迟，早于注册表 Run 自启项）
          /RL HIGHEST  以最高权限运行（需管理员权限创建）

        Returns:
            True 创建成功，False 失败（由调用方回退注册表 Run）
        """
        command = _get_app_command()
        code, out, err = self._run_schtasks([
            '/Create', '/TN', AUTOSTART_TASK_NAME,
            '/TR', command,
            '/SC', 'ONLOGON',
            '/RL', 'HIGHEST',
            '/F',
        ])
        if code == 0:
            logger.info(f'已注册开机计划任务（最高优先级）: {command}')
            return True
        logger.warning(
            f'注册开机计划任务失败（可能无管理员权限），将回退注册表 Run 方式: '
            f'{(err or out).strip()}')
        return False

    def _disable_priority_task(self) -> bool:
        """删除开机计划任务（不存在视为成功）

        Returns:
            True 删除成功或任务不存在，False 删除失败
        """
        code, out, err = self._run_schtasks(
            ['/Delete', '/TN', AUTOSTART_TASK_NAME, '/F'])
        if code == 0:
            logger.info('已删除开机计划任务')
            return True
        msg = (out + err).lower()
        # 任务不存在视为成功（中英文错误文案均覆盖）
        if ('cannot find' in msg or 'not exist' in msg
                or '找不到' in msg or '没有' in msg):
            return True
        logger.warning(f'删除开机计划任务失败: {(err or out).strip()}')
        return False

    @staticmethod
    def _run_schtasks(args: list, timeout: int = 15):
        """执行 schtasks 命令，返回 (退出码, stdout, stderr)"""
        try:
            creationflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            p = subprocess.run(
                ['schtasks'] + args,
                capture_output=True, text=True, errors='replace', timeout=timeout,
                creationflags=creationflags,
            )
            return p.returncode, p.stdout or '', p.stderr or ''
        except FileNotFoundError:
            return -1, '', 'schtasks.exe 不可用'
        except subprocess.TimeoutExpired:
            return -1, '', 'schtasks 执行超时'
        except Exception as e:
            return -1, '', str(e)

    @staticmethod
    def _remove_run_key() -> None:
        """删除注册表 HKCU\\...\\Run 自启项（切换/禁用时清理，防双启动）"""
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                AUTOSTART_REG_KEY,
                0,
                winreg.KEY_SET_VALUE
            ) as key:
                try:
                    winreg.DeleteValue(key, AUTOSTART_VALUE_NAME)
                except FileNotFoundError:
                    pass
        except OSError as e:
            logger.warning(f'清理注册表自启项失败: {e}')
        except Exception as e:
            logger.warning(f'清理注册表自启项异常: {e}')

    @classmethod
    def _is_reg_run_enabled(cls) -> bool:
        """注册表 Run 自启项是否存在且指向当前应用"""
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                AUTOSTART_REG_KEY,
                0,
                winreg.KEY_READ
            ) as key:
                try:
                    value, _ = winreg.QueryValueEx(key, AUTOSTART_VALUE_NAME)
                    # 统一使用 _task_command_matches：兼容带/不带引号、含空格路径，
                    # 避免 _extract_exe_path 在无引号时截断成 'c:\program' 类误判。
                    return cls._task_command_matches(
                        value, cls._extract_exe_path(_get_app_command()))
                except FileNotFoundError:
                    return False
        except OSError as e:
            logger.warning(f'查询开机自启状态失败: {e}')
            return False
        except Exception as e:
            logger.error(f'检查开机自启状态异常: {e}')
            return False

    @staticmethod
    def _extract_exe_path(command: str) -> str:
        """从命令字符串中提取可执行文件路径（用于比对）

        例如：
            '"C:\\Python\\pythonw.exe" "script.py" --minimized' -> 'c:\\python\\pythonw.exe'
            '"C:\\app\\PSLS.exe" --minimized' -> 'c:\\app\\psls.exe'
        """
        try:
            command = command.strip()
            if command.startswith('"'):
                # 提取第一个引号内的路径
                end = command.find('"', 1)
                if end > 0:
                    return command[1:end].lower()
            # 没有引号，取第一个空格前的部分
            space = command.find(' ')
            if space > 0:
                return command[:space].lower()
            return command.lower()
        except Exception:
            return command.lower() if command else ''


def is_minimized_startup() -> bool:
    """检查当前是否以 --minimized 参数启动（开机自启静默模式）

    Returns:
        True 如果命令行参数包含 --minimized
    """
    return MINIMIZED_ARG in sys.argv


if __name__ == '__main__':
    # 测试
    mgr = AutoStartManager()
    print(f"平台支持: {mgr.is_available()}")
    print(f"当前状态: {mgr.get_status()}")
    print(f"启动命令: {_get_app_command()}")
    print(f"静默启动: {is_minimized_startup()}")
