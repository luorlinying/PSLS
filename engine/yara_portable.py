# -*- coding: utf-8 -*-
"""
YARA Portable Manager - 便携 Python 环境管理器

当主 Python 版本不支持 yara-python 预编译 wheel 时，
自动下载 Python 3.13 嵌入式版本并安装 yara-python，
通过子进程桥接方式使用 YARA 扫描能力。

使用方式：
    from engine.yara_portable import YaraPortable

    portable = YaraPortable()
    if portable.is_available():
        result = portable.scan_file('/path/to/file')
"""
import os
import sys
import json
import subprocess
import tempfile
import shutil
import zipfile
import urllib.request
import platform
from typing import Optional, Dict, List

from utils.logger import get_logger

logger = get_logger('yara_portable')

# 子进程窗口隐藏标志（Windows 平台阻止弹出黑色 cmd 窗口）
# CREATE_NO_WINDOW = 0x08000000，在非 Windows 平台为 0（安全默认值）
_HIDDEN_CREATIONFLAGS = 0x08000000 if sys.platform == 'win32' else 0


_PORTABLE_PYTHON_VERSION = '3.13.7'
_PORTABLE_PYTHON_MAJOR_MINOR = '313'

_BASE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'portable_python'
)

_PYTHON_EXE = os.path.join(_BASE_DIR, 'python.exe')
_WORKER_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'yara_worker.py'
)

_PYPI_URL = 'https://pypi.org/pypi/yara-python/json'

_PYTHON_EMBEDDED_URLS = {
    'win_amd64': f'https://www.python.org/ftp/python/{_PORTABLE_PYTHON_VERSION}/python-{_PORTABLE_PYTHON_VERSION}-embed-amd64.zip',
    'win32': f'https://www.python.org/ftp/python/{_PORTABLE_PYTHON_VERSION}/python-{_PORTABLE_PYTHON_VERSION}-embed-win32.zip',
}


def _get_platform_tag() -> str:
    is_64bit = sys.maxsize > 2**32
    if sys.platform == 'win32':
        return 'win_amd64' if is_64bit else 'win32'
    return 'linux'


def _get_rules_dir() -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'rules', 'yara'
    )


def _get_compiled_cache() -> str:
    return os.path.join(_get_rules_dir(), 'compiled.yc')


class YaraPortable:
    """便携 Python YARA 桥接管理器

    当主 Python 不支持 yara-python 时使用。
    通过子进程调用便携 Python 中的 yara_worker.py 实现扫描。
    """

    def __init__(self):
        self._available = None
        self._python_exe = _PYTHON_EXE
        self._worker_script = _WORKER_SCRIPT
        self._rules_dir = _get_rules_dir()
        self._compiled_cache = _get_compiled_cache()

    @property
    def is_setup(self) -> bool:
        """检查便携 Python 是否已设置完成"""
        return os.path.exists(self._python_exe) and os.path.exists(self._worker_script)

    def is_available(self) -> bool:
        """检查 YARA 是否可用（便携 Python 已安装且 yara-python 可用）"""
        if self._available is not None:
            return self._available

        if not self.is_setup:
            self._available = False
            return False

        try:
            result = self._run_worker('ping')
            if result and result.get('yara_available'):
                self._available = True
                logger.info(f'便携 YARA 可用: Python {result.get("python_version")}, yara {result.get("yara_version")}')
            else:
                self._available = False
                logger.warning(f'便携 YARA 不可用: {result}')
        except Exception as e:
            self._available = False
            logger.warning(f'检查便携 YARA 状态失败: {e}')

        return self._available

    def reset_cache(self):
        """重置可用性缓存（安装完成后调用）"""
        self._available = None

    def scan_file(self, file_path: str) -> List[Dict]:
        """使用便携 YARA 扫描文件"""
        result = self._run_worker('scan_file', file_path=file_path)
        if result is None:
            return []
        if 'error' in result:
            logger.warning(f'便携 YARA 扫描失败: {result["error"]}')
            return []
        return result.get('matches', [])

    def scan_memory(self, pid: int) -> List[Dict]:
        """使用便携 YARA 扫描进程内存"""
        result = self._run_worker('scan_memory', pid=pid)
        if result is None:
            return []
        if 'error' in result:
            logger.warning(f'便携 YARA 内存扫描失败: {result["error"]}')
            return []
        return result.get('matches', [])

    def compile_rules(self) -> bool:
        """编译 YARA 规则"""
        output = self._compiled_cache
        result = self._run_worker('compile_rules', output=output)
        if result and result.get('success'):
            return True
        return False

    def get_status(self) -> Dict:
        """获取便携 YARA 状态"""
        result = self._run_worker('ping')
        return result or {'error': '无法连接便携 YARA'}

    def _run_worker(self, action: str, **kwargs) -> Optional[Dict]:
        """运行 YARA worker 脚本

        Args:
            action: 操作类型 (scan_file, scan_memory, compile_rules, ping)
            **kwargs: 操作参数

        Returns:
            解析后的 JSON 结果，失败返回 None
        """
        if not os.path.exists(self._python_exe):
            logger.error(f'便携 Python 不存在: {self._python_exe}')
            return None

        if not os.path.exists(self._worker_script):
            logger.error(f'Worker 脚本不存在: {self._worker_script}')
            return None

        cmd = [
            self._python_exe,
            self._worker_script,
            '--action', action,
            '--rules-dir', self._rules_dir,
        ]

        if self._compiled_cache:
            cmd.extend(['--compiled-cache', self._compiled_cache])

        if action == 'scan_file' and 'file_path' in kwargs:
            cmd.extend(['--file', kwargs['file_path']])
        elif action == 'scan_memory' and 'pid' in kwargs:
            cmd.extend(['--pid', str(kwargs['pid'])])
        elif action == 'compile_rules' and 'output' in kwargs:
            cmd.extend(['--output', kwargs['output']])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=os.path.dirname(self._worker_script),
                creationflags=_HIDDEN_CREATIONFLAGS
            )

            if result.returncode != 0:
                logger.error(f'YARA worker 执行失败: {result.stderr[:300]}')
                return None

            output = result.stdout.strip()
            if not output:
                return None

            return json.loads(output)
        except subprocess.TimeoutExpired:
            logger.error('YARA worker 执行超时')
            return None
        except json.JSONDecodeError as e:
            logger.error(f'YARA worker 输出解析失败: {e}')
            return None
        except Exception as e:
            logger.error(f'运行 YARA worker 异常: {e}')
            return None


def download_portable_python(progress_callback=None) -> bool:
    """下载并设置便携 Python 3.13 环境

    Args:
        progress_callback: 进度回调函数 (step, message)

    Returns:
        是否成功
    """
    try:
        # 清理可能的不完整安装
        if os.path.exists(_BASE_DIR):
            if not os.path.exists(_PYTHON_EXE):
                logger.info('检测到不完整的便携 Python 安装，正在清理...')
                shutil.rmtree(_BASE_DIR, ignore_errors=True)
            else:
                # python.exe 存在，检查 yara-python 是否可用
                try:
                    test_result = subprocess.run(
                        [_PYTHON_EXE, '-c', 'import yara; print("ok")'],
                        capture_output=True, text=True, timeout=10,
                        cwd=_BASE_DIR,
                        creationflags=_HIDDEN_CREATIONFLAGS
                    )
                    if test_result.returncode == 0:
                        logger.info('便携 Python 已有完整的 yara-python，无需重新安装')
                        return True
                    else:
                        logger.info('便携 Python 存在但 yara-python 不可用，重新设置...')
                except Exception:
                    logger.info('便携 Python 检测失败，重新设置...')

        os.makedirs(_BASE_DIR, exist_ok=True)

        plat_tag = _get_platform_tag()
        url = _PYTHON_EMBEDDED_URLS.get(plat_tag)
        if not url:
            logger.error(f'不支持的平台: {plat_tag}')
            if progress_callback:
                progress_callback(-1, f'不支持的平台: {plat_tag}')
            return False

        if progress_callback:
            progress_callback(0, f'正在下载 Python {_PORTABLE_PYTHON_VERSION} 嵌入式版本...')
        logger.info(f'下载便携 Python: {url}')

        zip_path = os.path.join(_BASE_DIR, 'python_embed.zip')

        def _report_progress(block_num, block_size, total_size):
            if total_size > 0 and progress_callback:
                downloaded = block_num * block_size
                percent = min(int(downloaded * 100 / total_size), 99)
                progress_callback(percent, f'正在下载 Python 嵌入式版本... {percent}%')

        urllib.request.urlretrieve(url, zip_path, reporthook=_report_progress)

        if progress_callback:
            progress_callback(100, '下载完成，正在解压...')
        logger.info('下载完成，解压中...')

        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(_BASE_DIR)

        try:
            os.remove(zip_path)
        except Exception:
            pass

        if progress_callback:
            progress_callback(100, '解压完成，正在配置 pip...')
        logger.info('解压完成，配置 pip...')

        if not _setup_portable_pip():
            logger.warning('pip 设置失败')
            return False

        if progress_callback:
            progress_callback(100, 'pip 配置完成，正在安装 yara-python...')
        logger.info('pip 设置完成，安装 yara-python...')

        python_exe = _PYTHON_EXE
        result = subprocess.run(
            [python_exe, '-m', 'pip', 'install', '--only-binary', ':all:', 'yara-python'],
            capture_output=True, text=True, timeout=300,
            cwd=_BASE_DIR,
            creationflags=_HIDDEN_CREATIONFLAGS
        )

        if result.returncode != 0:
            logger.warning(f'pip 安装 yara-python 失败: {result.stderr[:300]}')
            if progress_callback:
                progress_callback(-1, f'yara-python 安装失败')
            return False

        logger.info('yara-python 安装成功')
        if progress_callback:
            progress_callback(100, 'YARA 安装完成！')

        return True

    except Exception as e:
        logger.error(f'下载便携 Python 失败: {e}')
        if progress_callback:
            progress_callback(-1, f'下载失败: {str(e)}')
        return False


def _setup_portable_pip() -> bool:
    """为便携 Python 设置 pip

    嵌入式 Python 默认不带 pip，需要通过 get-pip.py 安装。
    """
    python_exe = _PYTHON_EXE
    if not os.path.exists(python_exe):
        logger.error(f'Python 可执行文件不存在: {python_exe}')
        return False

    result = subprocess.run(
        [python_exe, '-c', 'import pip; print(pip.__version__)'],
        capture_output=True, text=True, timeout=30,
        cwd=_BASE_DIR,
        creationflags=_HIDDEN_CREATIONFLAGS
    )

    if result.returncode == 0 and result.stdout.strip():
        logger.info(f'便携 Python 已有 pip: {result.stdout.strip()}')
        return True

    logger.info('便携 Python 无 pip，正在下载 get-pip.py...')

    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        get_pip_url = 'https://bootstrap.pypa.io/get-pip.py'
        get_pip_path = os.path.join(_BASE_DIR, 'get-pip.py')

        with urllib.request.urlopen(get_pip_url, context=ctx, timeout=60) as resp:
            with open(get_pip_path, 'wb') as f:
                f.write(resp.read())

        logger.info('get-pip.py 下载完成，安装中...')

        result = subprocess.run(
            [python_exe, get_pip_path],
            capture_output=True, text=True, timeout=120,
            cwd=_BASE_DIR,
            env={**os.environ, 'PYTHONPATH': ''},
            creationflags=_HIDDEN_CREATIONFLAGS
        )

        if result.returncode != 0:
            logger.error(f'get-pip.py 执行失败: {result.stderr[:500]}')
            return False

        logger.info('pip 安装成功')

        result2 = subprocess.run(
            [python_exe, '-m', 'pip', 'install', '--upgrade', 'pip'],
            capture_output=True, text=True, timeout=60,
            cwd=_BASE_DIR,
            creationflags=_HIDDEN_CREATIONFLAGS
        )
        if result2.returncode != 0:
            logger.warning(f'pip 升级失败: {result2.stderr[:200]}')

        return True

    except Exception as e:
        logger.error(f'设置 pip 失败: {e}')
        return False


def check_yara_compatibility() -> Dict:
    """检查当前 Python 是否兼容 yara-python

    Returns:
        {
            'compatible': bool,
            'reason': str,
            'py_version': str,
            'platform_tag': str,
            'supported_versions': list
        }
    """
    py_ver = f'{sys.version_info.major}.{sys.version_info.minor}'
    plat_tag = _get_platform_tag()
    abi_tag = f'cp{sys.version_info.major}{sys.version_info.minor}'

    try:
        with urllib.request.urlopen(_PYPI_URL, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        return {
            'compatible': False,
            'reason': f'无法查询 PyPI: {e}',
            'py_version': py_ver,
            'platform_tag': plat_tag,
            'supported_versions': []
        }

    releases = data.get('releases', {})
    supported_cps = set()

    for v, files in releases.items():
        for f in files:
            fn = f['filename']
            if plat_tag in fn and 'yara_python' in fn:
                parts = fn.split('-')
                for part in parts:
                    if part.startswith('cp') and len(part) >= 5:
                        supported_cps.add(part[:5])

    supported_cps = sorted(supported_cps)
    is_compatible = abi_tag in supported_cps

    return {
        'compatible': is_compatible,
        'reason': '' if is_compatible else f'Python {py_ver} ({abi_tag}) 无对应预编译 wheel',
        'py_version': py_ver,
        'platform_tag': plat_tag,
        'abi_tag': abi_tag,
        'supported_versions': supported_cps,
        'latest_version': data['info']['version']
    }
