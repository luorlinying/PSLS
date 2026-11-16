# -*- coding: utf-8 -*-
"""
实时防护引擎
基于 watchdog 监控文件系统变化,自动扫描新建/修改的文件。
若 watchdog 未安装,则降级为"仅记录状态"模式(不报错)。
"""
import os
import sys
import threading
import time
import multiprocessing
from typing import Callable, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger('realtime_monitor')


# ===========================================================================
# 模块级扫描进程池工作器（multiprocessing.spawn 要求函数在模块顶层）
# ===========================================================================
# 实时防护最大并发扫描数（同时最多扫描的文件数）
# 10 → 6：10个worker同时全量加载引擎会导致内存风暴闪退，降为6避免OOM
RT_MAX_PARALLEL_SCANS = 6

# 进程池内共享的扫描引擎（每个 worker 进程各持一份，懒加载避免内存爆炸）
_POOL_ENGINE = None
_POOL_CONFIG = None


# ===========================================================================
# 临时排除集合（进程级全局，用于 MB 同步/训练等内部作业）
# ===========================================================================
# MB 同步/训练时会把 data/mb/ 目录加入此集合，实时监控扫到该目录下
# 的文件时直接跳过（避免恶意样本被当作可疑文件告警/隔离）。
# 采用模块级全局 set + 线程锁，任何 engine 层代码都可以临时注册。
_TEMP_EXCLUDED_DIRS_LOCK = threading.Lock()
_TEMP_EXCLUDED_DIRS: set = set()


def add_temp_excluded_dir(path: str) -> None:
    """注册一个临时排除目录（同步/训练开始前调用）"""
    if not path:
        return
    normalized = os.path.normcase(os.path.abspath(path))
    with _TEMP_EXCLUDED_DIRS_LOCK:
        _TEMP_EXCLUDED_DIRS.add(normalized)
        logger.debug('临时排除目录已注册: %s', normalized)


def remove_temp_excluded_dir(path: str) -> None:
    """移除一个临时排除目录（同步/训练结束后调用）"""
    if not path:
        return
    normalized = os.path.normcase(os.path.abspath(path))
    with _TEMP_EXCLUDED_DIRS_LOCK:
        _TEMP_EXCLUDED_DIRS.discard(normalized)
        logger.debug('临时排除目录已移除: %s', normalized)


def _path_in_temp_excluded(file_path: str) -> bool:
    """判断文件路径是否落在任一临时排除目录下（模块级辅助）"""
    if not _TEMP_EXCLUDED_DIRS:
        return False
    try:
        fp_lower = os.path.normcase(os.path.abspath(file_path))
    except Exception:
        return False
    with _TEMP_EXCLUDED_DIRS_LOCK:
        dirs = list(_TEMP_EXCLUDED_DIRS)
    for d in dirs:
        if fp_lower == d or fp_lower.startswith(d + os.sep):
            return True
    return False


def _setup_worker_syspath():
    """在 worker 进程中补全项目根目录 / 打包 _internal 路径到 sys.path"""
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _project_root = os.path.dirname(_script_dir)
    if _project_root not in sys.path:
        sys.path.insert(0, _project_root)
    if getattr(sys, 'frozen', False):
        _base = os.path.dirname(sys.executable)
        if _base not in sys.path:
            sys.path.insert(0, _base)
        _internal = os.path.join(_base, '_internal')
        if os.path.isdir(_internal) and _internal not in sys.path:
            sys.path.insert(0, _internal)


def _pool_worker_init(config_dict):
    """进程池 worker 初始化：仅保存配置，引擎延迟到首次扫描时懒加载

    Args:
        config_dict: {'strict_mode': bool, 'max_file_size_mb': int,
                       'user_excluded_dirs': list}

    懒加载的意义：10个worker进程若在创建池的瞬间同时执行 ScanEngine()
    全量初始化（加载40662条YARA规则 + ML模型 + 白名单画像，每份数百MB），
    会形成内存风暴导致进程被系统OOM终止而闪退。改为首次扫描文件时才
    加载引擎，worker同一时刻只处理一个任务，天然错峰。
    """
    # 与 scan_engine._init_scan_worker 同款防护：父进程关闭/池终止时 worker
    # 向结果队列 put 会抛 BrokenPipeError，子进程打印 traceback 时若
    # stdout/stderr 为 None（PyInstaller windowed/spawn）会二次崩溃
    # （'NoneType' object has no attribute 'write'）。重定向到 devnull
    # 使"父进程已关闭"的正常终止静默退出。
    try:
        _pool_devnull = open(os.devnull, 'w')
        sys.stdout = _pool_devnull
        sys.stderr = _pool_devnull
    except Exception:
        pass
    global _POOL_CONFIG
    _setup_worker_syspath()
    _logger = get_logger('realtime_pool_worker')
    _POOL_CONFIG = dict(config_dict or {})
    # 引擎不在此初始化，交由 _ensure_pool_engine 按需加载
    _logger.info("扫描进程池 worker 已就绪（引擎懒加载）")


def _ensure_pool_engine():
    """按需创建 worker 进程内的扫描引擎（懒加载，每进程仅一次）"""
    global _POOL_ENGINE
    if _POOL_ENGINE is not None:
        return _POOL_ENGINE
    _logger = get_logger('realtime_pool_worker')
    try:
        from engine.scan_engine import ScanEngine
        engine = ScanEngine()
        cfg = _POOL_CONFIG or {}
        if cfg.get('strict_mode'):
            engine.strict_mode = True
        if cfg.get('virus_identifier'):
            engine.virus_identifier_enabled = True
        if cfg.get('max_file_size_mb'):
            engine.max_file_size_mb = cfg['max_file_size_mb']
        # 同步用户排除路径，确保并发扫描同样尊重排除项（关键：修复排除项失效）
        user_excluded = cfg.get('user_excluded_dirs') or []
        if user_excluded:
            engine.set_user_excluded_dirs(user_excluded)
        _POOL_ENGINE = engine
        _logger.info("扫描进程池 worker 引擎初始化完成")
    except Exception as e:
        _logger.error(f"扫描进程池 worker 引擎初始化失败: {e}")
        _POOL_ENGINE = None
    return _POOL_ENGINE


def _lock_and_copy_temp(file_path):
    """以 Windows 独占句柄（share=0）占用原文件，并将其内容拷贝到临时文件

    - 独占句柄持有期间，其他进程无法再打开该文件（无法读取/启动/执行）。
    - 通过同一句柄读取内容到独立临时文件，供扫描引擎正常打开（避免独占锁
      阻塞自身读取）。
    - 调用方在扫描结束前须保持返回文件对象的 open 状态，扫描完成后 close
      即释放独占锁。

    Returns:
        (file_obj_or_None, temp_path_or_empty)
        - file_obj: 包裹独占句柄的打开文件对象（None 表示锁定失败）
        - temp_path: 拷贝出的临时文件路径；锁定失败时为空串，
          调用方应改用原文件直接扫描（best-effort 降级）
    """
    if sys.platform != 'win32':
        return None, ''
    import tempfile
    import ctypes
    import msvcrt
    try:
        from ctypes import wintypes
    except Exception:
        return None, ''

    h = None
    f = None
    try:
        kernel32 = ctypes.windll.kernel32
        GENERIC_READ = 0x80000000
        # 共享模式修正（EBADF/读取失败根因之一）：
        # 原 `FILE_SHARE_NONE(0)` 连"其它进程读取"都拒绝 —— 会同时挡住我们自己的
        # 勒索快照入仓 / 自保护备份 / 系统备份工具读取同一文件，表现为读取中途
        # `[Errno 9] Bad file descriptor`/共享冲突。改为 `FILE_SHARE_READ(1)`：
        # **仍拒绝写入/删除/重命名（保护意图不变）**，但允许只读共享。
        FILE_SHARE_READ = 0x00000001
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        h = kernel32.CreateFileW(
            file_path, GENERIC_READ, FILE_SHARE_READ, None,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if not h or h == ctypes.c_void_p(-1).value:
            return None, ''
        fd = msvcrt.open_osfhandle(h, os.O_RDONLY)
        if fd < 0:
            kernel32.CloseHandle(h)
            return None, ''
        f = os.fdopen(fd, 'rb')  # f 持有独占句柄；保持 open 即持续占用原文件
        h = None
    except Exception as e:
        logger.debug(f"独占锁定文件失败 {file_path}: {e}")
        if h:
            try:
                ctypes.windll.kernel32.CloseHandle(h)
            except Exception:
                pass
        return None, ''

    # 通过独占句柄读取内容并写入临时文件（保留原扩展名以便 magic/PE 判断）
    tmp = ''
    try:
        _fd, tmp = tempfile.mkstemp(
            prefix='psls_rt_', suffix=os.path.splitext(file_path)[1])
        with os.fdopen(_fd, 'wb') as out:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                out.write(chunk)
        return f, tmp
    except Exception as e:
        logger.debug(f"拷贝临时文件失败 {file_path}: {e}")
        try:
            f.close()
        except Exception:
            pass
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except Exception:
                pass
        return None, ''


def _lock_file_exclusive(file_path, timeout_sec: float = 0.0):
    """在调用进程中获取 Windows 独占句柄（share=0）占用文件。

    与 _lock_and_copy_temp 不同：仅获取句柄、不做复制，用于主进程在
    「worker 释放锁 -> on_threat 处理完毕」的窗口内阻塞其他进程启动/读取。
    timeout_sec>0 时会在获取失败后重试一段时间（秒），保证文件被其他
    进程短暂占用（如浏览器下载流关闭前）时有机会拿到锁。

    Returns:
        持有独占句柄的 Python file 对象（保持 open 即持续占用），
        失败返回 None。调用方处理完成后必须 .close() 释放。
    """
    if sys.platform != 'win32' or not file_path or not os.path.isfile(file_path):
        return None
    import ctypes
    import msvcrt
    import time as _time
    try:
        from ctypes import wintypes
    except Exception:
        return None

    GENERIC_READ = 0x80000000
    # 同上：允许只读共享（保护写入/删除，但不挡自己/备份工具的读取）
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    INVALID_HANDLE = ctypes.c_void_p(-1).value

    kernel32 = ctypes.windll.kernel32
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]

    deadline = _time.time() + max(0.0, float(timeout_sec))
    interval = 0.05  # 50ms 重试间隔
    while True:
        h = kernel32.CreateFileW(
            file_path, GENERIC_READ, FILE_SHARE_READ, None,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if h and h != INVALID_HANDLE:
            try:
                fd = msvcrt.open_osfhandle(h, os.O_RDONLY)
            except Exception:
                kernel32.CloseHandle(h)
                return None
            if fd < 0:
                kernel32.CloseHandle(h)
                return None
            try:
                return os.fdopen(fd, 'rb')
            except Exception:
                try:
                    os.close(fd)
                except Exception:
                    pass
                return None
        # 获取失败
        if _time.time() >= deadline:
            return None
        _time.sleep(interval)


def _pool_scan_file(file_path):
    """进程池扫描单个文件：锁定占用 + 独立进程扫描

    在独立 worker 进程中执行，拥有独立 GIL 和内存空间；
    大文件扫描（PE/ML/YARA/归档解压）不会阻塞主进程 UI，也不互相卡死。

    Windows 下扫描期间以独占句柄占用原文件，阻止其被启动/执行；
    实际扫描通过临时副本完成。锁定失败则降级为直接扫描原文件。

    Returns:
        dict: {'file_path', 'results': [ScanResult.to_dict()], 'error'}
    """
    lock_f = None
    copy_path = ''
    try:
        lock_f, copy_path = _lock_and_copy_temp(file_path)
    except Exception:
        lock_f, copy_path = None, ''
    scan_target = copy_path if copy_path else file_path
    _logger = get_logger('realtime_pool_scan')
    try:
        engine = _ensure_pool_engine()
        if engine is None:
            raise RuntimeError("扫描引擎未初始化")
        results = engine.scan_file_with_archives(scan_target)
        return {
            'file_path': file_path,
            'results': [r.to_dict() for r in results],
            'error': None,
        }
    except Exception as e:
        _logger.error(f"进程池扫描失败 {file_path}: {e}")
        return {'file_path': file_path, 'results': [], 'error': str(e)}
    finally:
        # 扫描结束：关闭独占句柄释放锁，删除临时副本
        if lock_f is not None:
            try:
                lock_f.close()
            except Exception:
                pass
        if copy_path and os.path.exists(copy_path):
            try:
                os.unlink(copy_path)
            except Exception:
                pass

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    Observer = None
    FileSystemEventHandler = object  # type: ignore


# 实时防护关注的可执行文件扩展名
# 注意：包含常见脚本/文档扩展名，因为 EICAR 等测试病毒可以是文本格式
RT_EXECUTABLE_EXTENSIONS = {
    # Windows 可执行文件
    '.exe', '.dll', '.scr', '.sys', '.pif', '.com', '.msi',
    '.ocx', '.drv', '.cpl', '.msp', '.ace',
    # 脚本文件
    '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.wsf', '.jse', '.vbe',
    '.py', '.pyw', '.pl', '.rb',
    # 文档/可能携带宏的文件（含宏文档）
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf',
    '.docm', '.xlsm', '.pptm', '.dotm', '.xltm',
    # 压缩包
    '.zip', '.rar', '.7z', '.tar', '.gz',
    # 磁盘镜像（BumbleBee/Qakbot 主要投递方式）
    '.iso', '.img', '.vhd', '.vhdx',
    # 快捷方式
    '.lnk', '.url',
    # Java
    '.jar', '.class',
    # OneNote 恶意样本
    '.one', '.onetoc2',
    # 其他
    '.mht', '.mhtml', '.swf',
    # 文本/无扩展名也能携带 EICAR 等恶意内容
    '.txt', '.htm', '.html', '.svg', '.xml', '.json', '.csv',
    '',  # 无扩展名文件
}

# 高危扩展名（零延迟扫描，跳过去抖）
RT_HIGH_RISK_EXTENSIONS = {
    '.exe', '.scr', '.com', '.pif', '.bat', '.cmd', '.ps1',
    '.vbs', '.js', '.hta', '.lnk', '.msi', '.jar',
}

# 纯可执行文件 + 压缩包扩展名（当"监测全部类型"关闭时使用）
# 压缩包加入原因：勒索/木马常通过压缩包投递，必须一起监测
# 与 ScanEngine.EXECUTABLE_EXTENSIONS 保持一致
RT_PURE_EXECUTABLE_EXTENSIONS = {
    # PE 可执行
    '.exe', '.dll', '.sys', '.scr', '.pif', '.com',
    '.ocx', '.drv', '.cpl', '.msp', '.msi', '.ace',
    # 脚本
    '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta',
    '.wsf', '.jse', '.vbe', '.py', '.pyw', '.pl', '.rb',
    # 快捷方式/URL
    '.lnk', '.url',
    # Java
    '.jar', '.class',
    # 宏文档（可携带恶意宏）
    '.docm', '.xlsm', '.pptm', '.dotm', '.xltm',
    # 压缩包（勒索/木马常见投递载体）
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
    # 其他
    '.swf',
}

# 浏览器下载临时文件扩展名（下载完成后会重命名为真实扩展名）
# 当这些临时文件被重命名时，即使新扩展名是新的也要扫描
RT_DOWNLOAD_TEMP_EXTENSIONS = {
    '.crdownload',  # Chrome / Edge
    '.part',        # Firefox
    '.tmp',         # 通用临时文件
    '.download',    # Safari / 其他下载器
    '.crswap',      # Chromium 交换文件
    '.!ut',         # uTorrent
    '.!bt',         # BitTorrent
}

# 默认监控目录(用户目录常见威胁入口)
RT_DEFAULT_WATCH_DIRS = [
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "Documents"),
]


def get_critical_watch_dirs() -> List[str]:
    """获取系统关键位置监控目录列表

    包括：桌面、下载、文档、启动项、临时目录、公共下载等
    """
    dirs = []
    home = os.path.expanduser("~")

    # 用户常用目录
    for sub in ["Downloads", "Desktop", "Documents"]:
        p = os.path.join(home, sub)
        if os.path.isdir(p):
            dirs.append(p)

    # 启动项
    startup = os.path.join(
        home, "AppData", "Roaming", "Microsoft",
        "Windows", "Start Menu", "Programs", "Startup"
    )
    if os.path.isdir(startup):
        dirs.append(startup)

    # 公共下载
    public_downloads = os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "Downloads")
    if os.path.isdir(public_downloads):
        dirs.append(public_downloads)

    # 去重并返回
    return list(dict.fromkeys(dirs))


def get_all_local_drives() -> List[str]:
    """获取所有本地磁盘根目录（整台电脑模式）"""
    drives = []
    try:
        import string
        import ctypes
        # 使用 Windows API 获取驱动器类型
        DRIVE_FIXED = 3
        kernel32 = ctypes.windll.kernel32
        bitmask = kernel32.GetLogicalDrives()
        for i, letter in enumerate(string.ascii_uppercase):
            if bitmask & (1 << i):
                drive = f"{letter}:\\"
                try:
                    drive_type = kernel32.GetDriveTypeW(drive)
                    if drive_type == DRIVE_FIXED:
                        drives.append(drive)
                except Exception:
                    pass
    except Exception:
        # 降级：只返回常见盘符
        for letter in ["C", "D", "E", "F"]:
            drive = f"{letter}:\\"
            if os.path.isdir(drive):
                drives.append(drive)
    return drives

# 去抖动:同一文件短时间内多次变更只扫描一次
RT_DEBOUNCE_SECONDS = 1.0

# 软隔离标记后缀：quarantine_manager 在"文件无法移动/复制"时会将原文件
# 改名为 <原路径>.PSLS_QUARANTINED 做原地隔离 + ACL 禁用。
# 该文件仍存在于原目录，会持续触发 watchdog 事件（修改时间戳/属性变化等）。
# 此标记用于在事件捕获阶段直接跳过，避免软隔离文件反复入队扫描。
RT_QUARANTINED_MARKER = '.PSLS_QUARANTINED'

# 已处置文件最短回看窗口（秒）：文件一旦被成功处置（隔离/删除/软隔离），
# 在窗口期内即便再次触发 watchdog 事件，也直接跳过入队，避免"检测→隔离→再检测"
# 的快速循环（实测 YARA 对同一文件每 10~60s 会重新触发，此 TTL 足够去抖）。
RT_DISPOSITION_CACHE_TTL = 300  # 5 分钟

# 已处置文件缓存：{norm_path: disposal_timestamp}，线程安全
# 结构简单，用 dict + 锁即可，无需单独 LRU。
_RT_DISPOSITION_CACHE: "Dict[str, float]" = {}
_RT_DISPOSITION_CACHE_LOCK = threading.Lock()


def _mark_file_disposed(file_path: str) -> None:
    """标记某路径下的文件已被处置，后续 RT_DISPOSITION_CACHE_TTL 秒内跳过入队。"""
    global _RT_DISPOSITION_CACHE
    try:
        norm = os.path.abspath(file_path) if file_path else ''
        if not norm:
            return
        with _RT_DISPOSITION_CACHE_LOCK:
            # 顺手清理过期条目，避免长期运行无限增长
            now = time.time()
            stale = [k for k, ts in _RT_DISPOSITION_CACHE.items()
                     if now - ts > RT_DISPOSITION_CACHE_TTL]
            for k in stale:
                _RT_DISPOSITION_CACHE.pop(k, None)
            _RT_DISPOSITION_CACHE[norm] = now
    except Exception:
        pass


def _is_file_disposed(file_path: str) -> bool:
    """检查文件路径是否已在处置缓存中（命中则跳过入队）。"""
    global _RT_DISPOSITION_CACHE
    try:
        norm = os.path.abspath(file_path) if file_path else ''
        if not norm:
            return False
        with _RT_DISPOSITION_CACHE_LOCK:
            ts = _RT_DISPOSITION_CACHE.get(norm)
            if ts is None:
                return False
            return (time.time() - ts) <= RT_DISPOSITION_CACHE_TTL
    except Exception:
        return False


def _is_quarantined_marker_path(file_path: str) -> bool:
    """判断路径是否是软隔离标记文件（跳过扫描，避免重复处置）。"""
    if not file_path:
        return False
    return file_path.endswith(RT_QUARANTINED_MARKER)


# Magic byte 签名表：用于识别无扩展名或伪装扩展名的可执行/归档文件
# 格式: (前缀字节, 描述) —— 只需读取文件前 8 字节即可判断
RT_MAGIC_SIGNATURES = (
    (b'MZ', 'pe'),                # Windows PE 可执行文件（含 DLL/SCR）
    (b'\x7fELF', 'elf'),          # Linux ELF 可执行文件
    (b'PK\x03\x04', 'zip'),       # ZIP/JAR/DOCX/XPI/APK 等
    (b'PK\x05\x06', 'zip_empty'), # 空归档
    (b'PK\x07\x08', 'zip_span'),  # 分卷归档
    (b'Rar!\x1a\x07', 'rar'),     # RAR 归档（v4/v5）
    (b'\x37\x7a\xbc\xaf\x27\x1c', '7z'),  # 7z 归档
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'ole'),  # OLE2（老式 Office/MSI）
    (b'\x53\x50\x30\x31', 'sparse'),  # Android sparse image
    (b'\x23\x21', 'shebang'),     # 脚本 shebang (#!)
    (b'<html', 'html'),           # HTML（小写）
    (b'<HTML', 'html'),           # HTML（大写）
    (b'\xff\xd8\xff', 'jpg'),     # JPEG（仅记录，不视为威胁载体）
    (b'\x89PNG', 'png'),          # PNG（仅记录）
)

# Magic byte 识别为威胁载体的类型（需进入扫描队列）
RT_MAGIC_THREAT_TYPES = {'pe', 'elf', 'zip', 'rar', '7z', 'ole', 'shebang', 'html'}

# Magic byte 检测的最大文件头读取长度
RT_MAGIC_READ_SIZE = 8

# Magic byte 检测的最大文件大小限制（避免对超大非威胁文件做 IO）
# 超过 256MB 的文件一般不通过实时监控扫描，交给手动扫描
RT_MAGIC_MAX_FILE_SIZE = 256 * 1024 * 1024


def _detect_magic_type(file_path: str) -> Optional[str]:
    """通过文件头 magic byte 识别文件真实类型

    用于检测伪装扩展名（如 image.jpg 实为 PE）和无扩展名的可执行文件。

    Args:
        file_path: 文件路径

    Returns:
        检测到的类型字符串（如 'pe'/'zip'/'rar'），未识别返回 None
    """
    try:
        # 先检查文件大小，避免对超大文件做无谓 IO
        size = os.path.getsize(file_path)
        if size == 0 or size > RT_MAGIC_MAX_FILE_SIZE:
            return None
        with open(file_path, 'rb') as f:
            header = f.read(RT_MAGIC_READ_SIZE)
        if not header:
            return None
        for sig, ftype in RT_MAGIC_SIGNATURES:
            if header.startswith(sig):
                return ftype
    except OSError:
        return None
    except Exception:
        return None
    return None


class _ThreatHandler(FileSystemEventHandler):
    """watchdog 事件处理器:捕获新建/修改事件并排队扫描"""

    def __init__(self, monitor: 'RealtimeMonitor'):
        super().__init__()
        self._monitor = monitor

    def _on_any(self, event, extra_path=None):
        """统一事件处理

        Args:
            event: watchdog 事件对象
            extra_path: 额外需要检查的路径（用于 on_moved 的 dest_path）
        """
        if event.is_directory:
            return
        # 对 on_moved，同时检查 src_path 和 dest_path（dest_path 是重命名后的新文件）
        paths = []
        src = getattr(event, 'src_path', '')
        if src:
            paths.append(src)
        dest = getattr(event, 'dest_path', '')
        if dest and dest != src:
            paths.append(dest)
        if extra_path:
            paths.append(extra_path)
        if not paths:
            return

        # 记录 src 是否是临时下载文件（用于 on_moved：从临时文件重命名为真实扩展名时强制扫描）
        src_ext = os.path.splitext(src)[1].lower() if src else ''
        src_is_download_temp = src_ext in RT_DOWNLOAD_TEMP_EXTENSIONS

        for p in paths:
            if not p:
                continue
            # 回滚仓库 / 影子原像根：PSLS 自身产出，事件阶段即跳过（不做任何扫描）
            if self._monitor.is_psls_own_path(p):
                continue
            # 路径级自保护：跳过 PSLS 自身目录下的文件事件
            # 同时匹配目录前缀和单独的可执行文件路径（MLWorker.exe 等）
            if self._monitor._self_excluded_dirs:
                try:
                    p_lower = os.path.abspath(p).lower()
                    # 先检查是否是 PSLS 附属进程的可执行文件本身
                    if p_lower in self._monitor._self_excluded_dirs:
                        continue
                    # 再检查是否在 PSLS 排除目录下
                    if any(p_lower.startswith(d) for d in self._monitor._self_excluded_dirs):
                        continue
                except Exception:
                    pass
            # 用户排除路径：事件阶段即跳过，避免进入扫描队列（修复排除项失效）
            if self._monitor._in_user_excluded(p):
                continue
            # 临时排除目录（MB 同步/训练等内部作业）：事件阶段即跳过
            if _path_in_temp_excluded(p):
                logger.debug('事件路径在临时排除目录内，跳过: %s', p)
                continue
            # 软隔离标记文件：已被 quarantine_manager 原地改名做软隔离
            # （<原路径>.PSLS_QUARANTINED），跳过扫描避免重复处置
            if _is_quarantined_marker_path(p):
                logger.debug(f'跳过软隔离标记文件: {p}')
                continue
            # 已处置 TTL 窗口内：避免 YARA/软隔离文件的"检测→处置→再检测"快速循环
            if _is_file_disposed(p):
                logger.debug(f'跳过已处置文件（TTL={RT_DISPOSITION_CACHE_TTL}s）: {p}')
                continue
            _, ext = os.path.splitext(p)
            ext_lower = ext.lower()
            # 判断是否需要扫描：
            #   监测全部类型开启：
            #     1) 扩展名在关注白名单中（RT_EXECUTABLE_EXTENSIONS）
            #     2) 或 是 on_moved 事件中从下载临时文件重命名而来
            #     3) 或 magic byte 识别为威胁载体（伪装扩展名检测）
            #   监测全部类型关闭：
            #     1) 扩展名在纯可执行文件集合中（RT_PURE_EXECUTABLE_EXTENSIONS）
            #     2) 或 是 on_moved 事件中从下载临时文件重命名而来
            #     （跳过 magic byte 检测，减少非必要扫描开销）
            should_scan = False
            if self._monitor.monitor_all_file_types:
                # 全部类型模式：使用完整白名单 + magic byte 检测
                if ext_lower in RT_EXECUTABLE_EXTENSIONS or src_is_download_temp:
                    should_scan = True
                else:
                    # Magic byte 检测：识别伪装扩展名（如 image.jpg 实为 PE）和无扩展名威胁
                    magic_type = _detect_magic_type(p)
                    if magic_type and magic_type in RT_MAGIC_THREAT_TYPES:
                        should_scan = True
                        logger.info(f"Magic byte 检测到伪装文件: {p} (扩展名={ext_lower or '无'}, 真实类型={magic_type})")
            else:
                # 仅可执行文件模式：纯可执行扩展名命中，或源为下载临时文件
                if ext_lower in RT_PURE_EXECUTABLE_EXTENSIONS or src_is_download_temp:
                    should_scan = True
                else:
                    # 即便"仅可执行文件"模式也启用 magic byte 检测，防止伪装/无扩展名威胁漏拦
                    magic_type = _detect_magic_type(p)
                    if magic_type and magic_type in RT_MAGIC_THREAT_TYPES:
                        should_scan = True
                        logger.info(f"Magic byte 检测到伪装文件: {p} (扩展名={ext_lower or '无'}, 真实类型={magic_type})")
            if not should_scan:
                continue
            # 异步处理（去抖动由 _enqueue_scan 内部按路径 debounce）
            self._monitor._enqueue_scan(p)

    def on_created(self, event):
        self._on_any(event)

    def on_modified(self, event):
        if event.is_directory:
            return
        # 不再按 ctime 过滤：Windows 原地覆写已存在文件不改变创建时间，
        # 若仅扫描"新文件"会漏掉对监控目录内既有文件的恶意覆写。
        # 相关性与扫描开销由 _on_any 的扩展名/magic 过滤 + _enqueue_scan 去抖控制。
        self._on_any(event)

    def on_moved(self, event):
        # on_moved 事件: 从临时下载文件（crdownload/part等重命名为真实文件名时必须扫描
        self._on_any(event)


class RealtimeMonitor:
    """
    实时防护监控器
    在独立线程中运行 watchdog Observer,对变更的可执行/归档文件进行即时扫描。
    """

    def __init__(self, scan_engine_factory: Callable, watch_dirs: List[str] = None,
                 on_threat: Callable[[dict], None] = None,
                 on_scan_result: Callable[[dict], None] = None,
                 signature_db=None,
                 exemption_checker: Callable[[str], bool] = None,
                 quarantine_manager=None):
        """
        Args:
            scan_engine_factory: 返回 ScanEngine 实例的可调用对象(惰性创建,避免循环依赖)
            watch_dirs: 监控目录列表,默认 RT_DEFAULT_WATCH_DIRS
            on_threat: 发现威胁时的回调(传入扫描结果字典，仅 malware/suspicious)
            on_scan_result: 每次扫描完成的回调（无论 clean/threat，用于新文件扫描结果弹窗）
            signature_db: SignatureDB 实例（用于白名单哈希预检查，命中则跳过扫描）
            exemption_checker: 路径豁免检查回调（传入文件路径，返回是否豁免扫描），
                用于跳过刚从隔离区复原的文件，避免实时防护再次扫描并触发告警/隔离。
                注意：此豁免仅作用于实时防护扫描阶段，不影响沙箱分析。
            quarantine_manager: QuarantineManager 实例，用于在威胁回调前做
                哈希级前置去重：若同一哈希已存在未删除/未恢复的隔离条目，
                则跳过 on_threat 回调，避免"检测→隔离→再检测"循环。
        """
        self._scan_engine_factory = scan_engine_factory
        self._watch_dirs = watch_dirs if watch_dirs is not None else list(RT_DEFAULT_WATCH_DIRS)
        self._on_threat = on_threat
        self._on_scan_result = on_scan_result  # 新文件扫描结果回调（含 clean）
        self._signature_db = signature_db  # 白名单哈希预检查
        self._exemption_checker = exemption_checker  # 路径豁免检查（跳过已复原文件）
        self._quarantine_manager = quarantine_manager  # 隔离管理器（哈希级前置去重）
        self._observer: Optional['Observer'] = None
        self._handler: Optional[_ThreatHandler] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._running = False
        # 队列优化：dict 保存 file_path->入队时间戳，set 用于 O(1) 成员判断
        # 原 List 结构的 `if file_path not in self._queue` 是 O(n) 操作，高并发下成为瓶颈
        self._queue: Dict[str, float] = {}
        self._queue_set: set = set()
        # 使用 Condition 替代 Lock + sleep 轮询，实现阻塞式事件循环
        # 高危文件入队时 notify_all() 立即唤醒扫描线程，响应延迟从 0.5s 降至毫秒级
        self._queue_cond = threading.Condition()
        self._last_scan: Dict[str, float] = {}
        self._stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'errors': 0,
            'started_at': 0,
        }
        self._stats_lock = threading.Lock()
        # 严格模式开关（默认关闭，与桥接层 _strict_mode = False 保持一致）：
        #   True  - suspicious 状态也触发 on_threat 回调（自动隔离），防止未知威胁漏网
        #   False - suspicious 状态仅记录日志，不触发自动隔离
        self.strict_mode = False
        # 监测全部类型的文件开关（默认开启）：
        #   True  - 监测所有类型文件（包括文本、图片等非可执行文件）+ magic byte 伪装检测
        #   False - 仅监测可执行文件（PE、脚本、宏文档等），跳过 magic byte 检测
        # 严格模式开启时此开关强制为 True
        self.monitor_all_file_types = True
        self._recent_events: List[dict] = []  # 最近的防护事件(供前端展示)
        self._events_lock = threading.Lock()
        # 威胁文件独占锁注册表：{abs_norm_path: (file_obj, 登记时间戳)}
        # 用途：worker 扫描释放锁 → on_threat 回调处置完毕 的窗口内，
        # 由主进程保持 share=0 句柄占用，防止用户在检测到可疑后到隔离前运行文件。
        # 最长存活 RT_THREAT_LOCK_MAX_SECONDS，超时自动释放避免泄漏。
        self._threat_locks: Dict[str, tuple] = {}
        self._threat_locks_lock = threading.Lock()
        # 威胁锁最长生存时间（秒）：对应用户弹窗自动执行的 3s 默认窗口 + 处置延迟，
        # 取 60s 作为绝对兜底，防止任意原因导致 release_threat_lock 没调用时句柄泄漏
        self._threat_lock_max_seconds = 60
        # 缓存扫描引擎实例，避免每次扫描重复创建（YARA 规则加载等开销大）
        self._cached_engine = None
        self._engine_lock = threading.Lock()
        # PSLS 启动时间戳：on_modified 仅扫描此时间之后创建的文件
        self._start_time: float = 0.0
        # 扫描进程池：将大文件扫描分离到最多 RT_MAX_PARALLEL_SCANS 个独立进程，
        # 拥有独立 GIL + 内存空间，并发扫描不阻塞主进程 UI，也不互相卡死。
        self._pool: Optional[multiprocessing.Pool] = None
        # 扫描进程池持久禁用标志（打包 onedir spawn 子进程句柄复制失败/权限拒绝
        # 时置 True），之后不再重复 spawn，回退到主进程扫描，避免反复触发
        # spawn 子进程的 WinError5（reduction.duplicate 拒绝访问）风暴。
        self._scan_subprocess_disabled = False
        self._scan_pool_lock = threading.Lock()
        # 自身路径排除集合（防止监控误扫 PSLS 自身文件及附属文件）
        # 包含：主程序目录、_internal、MLWorker、redist、
        #       安装包解包临时目录（%TEMP%\PSLS_V*）、PyInstaller onefile 解包目录(_MEI*)
        self._self_excluded_dirs: set = set()
        # 用户自定义排除路径（小写绝对路径集合），实时防护在扫描前即跳过
        # 与 ScanEngine._user_excluded_dirs 保持一致，避免子进程/主进程扫描遗漏
        self._user_excluded_dirs: set = set()
        try:
            if getattr(sys, 'frozen', False):
                exe_dir = os.path.dirname(os.path.abspath(sys.executable))
                self._self_excluded_dirs.add(exe_dir.lower())
            else:
                project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                self._self_excluded_dirs.add(project_root.lower())
            if sys.platform == 'win32':
                appdata = os.environ.get('APPDATA', '')
                if appdata:
                    self._self_excluded_dirs.add(os.path.join(appdata, 'PSLS').lower())
            for base in list(self._self_excluded_dirs):
                self._self_excluded_dirs.add(os.path.join(base, 'backup').lower())
                internal = os.path.join(base, '_internal')
                if os.path.isdir(internal):
                    self._self_excluded_dirs.add(internal.lower())
                # redist 子目录（VC++ Redist + WebView2 安装包）
                redist_dir = os.path.join(base, 'redist')
                if os.path.isdir(redist_dir):
                    self._self_excluded_dirs.add(redist_dir.lower())
            # 安装包解包临时目录：%TEMP%\PSLS_V*（Inno Setup 解包）
            # PyInstaller onefile 解包目录：%TEMP%\_MEI*（PSLS_Setup.exe 解包）
            if sys.platform == 'win32':
                temp_dir = os.environ.get('TEMP', '') or os.environ.get('TMP', '')
                if temp_dir and os.path.isdir(temp_dir):
                    try:
                        for entry in os.listdir(temp_dir):
                            entry_lower = entry.lower()
                            if entry_lower.startswith('psls_v') or entry_lower.startswith('_mei'):
                                full_path = os.path.join(temp_dir, entry)
                                if os.path.isdir(full_path):
                                    self._self_excluded_dirs.add(full_path.lower())
                    except Exception:
                        pass
            # 回滚仓库 + 影子原像根：PSLS 自身产出（原始文件副本），绝不扫描/隔离。
            # 用规范化绝对路径 + 尾分隔符，避免 ...\rollback2 之类前缀误伤。
            self._psls_repo_roots = []
            try:
                from engine.ransomware_rollback import (
                    repo_root_norm, shadow_root_norm)
                for r in (repo_root_norm(), shadow_root_norm()):
                    if r:
                        self._psls_repo_roots.append(r)
                        self._self_excluded_dirs.add(r.rstrip('\\/'))
            except Exception:
                pass
        except Exception:
            pass

        # PSLS 附属进程名集合（小写）
        # 这些进程创建/修改的文件不触发扫描，避免误报
        self._self_process_names: set = {
            'psls.exe',           # 主程序
            'mlworker.exe',       # ML 推理子进程
            'psls_setup.exe',     # 安装程序
            'python.exe',         # 开发模式下解释器
        }

    def _refresh_self_process_paths(self):
        """枚举正在运行的 PSLS 附属进程，将其可执行文件路径加入排除集合

        解决场景：
          - MLWorker.exe / MLWorker 不在 PSLS 安装目录下时
            （例如开发模式或自定义路径）
          - 安装包解包后产生的临时可执行文件
        """
        try:
            import psutil
        except ImportError:
            return
        try:
            self_pid = os.getpid()
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    info = proc.info
                    if not info or info.get('pid') == self_pid:
                        continue
                    name = (info.get('name') or '').lower()
                    exe_path = info.get('exe')
                    if not exe_path:
                        continue
                    # 进程名匹配 PSLS 附属进程
                    if name in self._self_process_names:
                        exe_dir = os.path.dirname(exe_path).lower()
                        self._self_excluded_dirs.add(exe_dir)
                        self._self_excluded_dirs.add(exe_path.lower())
                        # 同目录下可能存在的依赖文件
                        self._self_excluded_dirs.add(
                            os.path.join(exe_dir, '_internal').lower())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.debug(f'刷新附属进程路径异常: {e}')

    @property
    def is_running(self) -> bool:
        return self._running

    def set_user_excluded_dirs(self, dirs) -> None:
        """设置用户自定义排除路径（小写绝对路径集合）

        Args:
            dirs: 路径列表（可为 str / list / set）
        """
        normalized = set()
        if dirs:
            if isinstance(dirs, str):
                dirs = [dirs]
            for p in dirs:
                if not p:
                    continue
                try:
                    normalized.add(os.path.abspath(p).lower())
                except Exception:
                    pass
        self._user_excluded_dirs = normalized

    def _in_user_excluded(self, file_path: str) -> bool:
        """检查文件路径是否位于用户排除路径下（路径级排除，扫描前即跳过）"""
        if not self._user_excluded_dirs:
            return False
        try:
            fp_lower = os.path.abspath(file_path).lower()
            if fp_lower in self._user_excluded_dirs:
                return True
            if any(fp_lower.startswith(d) for d in self._user_excluded_dirs):
                return True
        except Exception:
            pass
        return False

    def is_psls_own_path(self, file_path: str) -> bool:
        """是否为 PSLS 自身产出路径（回滚仓库 / 影子原像根）。

        这类路径内是 PSLS 自己写入的原始文件副本，读取/写入绝不能触发检测、
        隔离或终止。用规范化绝对路径 + 尾分隔符前缀比较。
        """
        if not file_path:
            return False
        try:
            p = os.path.normcase(os.path.abspath(str(file_path)))
        except Exception:
            return False
        for root in getattr(self, '_psls_repo_roots', []) or []:
            if not root:
                continue
            if not root.endswith(os.sep):
                root = root + os.sep
            if p == root.rstrip('\\/') or p.startswith(root):
                return True
        return False

    @property
    def has_watchdog(self) -> bool:
        return HAS_WATCHDOG

    def get_watch_dirs(self) -> List[str]:
        return list(self._watch_dirs)

    def update_watch_dirs(self, watch_dirs: List[str]) -> bool:
        """动态更新监控目录

        如果监控器正在运行，则重启 observer 以应用新目录。
        返回是否成功应用（运行中重启失败时返回 False）。
        """
        if not watch_dirs:
            watch_dirs = []
        self._watch_dirs = list(watch_dirs)

        if not self._running:
            return True

        # 正在运行：重启 observer
        if not HAS_WATCHDOG:
            return True

        try:
            # 停止旧 observer
            if self._observer:
                self._observer.stop()
                self._observer.join(timeout=2)
                self._observer = None
            self._handler = None

            # 启动新 observer
            self._observer = Observer()
            self._handler = _ThreatHandler(self)
            watched = 0
            for d in self._watch_dirs:
                if d and os.path.isdir(d):
                    self._observer.schedule(self._handler, d, recursive=True)
                    watched += 1

            if watched == 0:
                logger.warning("更新后无有效监控目录，实时监控保持运行但不监控任何目录")
                self._observer.start()
            else:
                self._observer.start()

            self._add_event('system', '', 'info',
                            f'实时监控范围已更新，监控 {watched} 个目录')
            logger.info(f"实时监控范围已更新，监控 {watched} 个目录: {self._watch_dirs}")
            return True

        except Exception as e:
            logger.error(f"更新实时监控目录失败: {e}")
            return False

    def get_stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    def get_recent_events(self, limit: int = 20) -> list:
        with self._events_lock:
            return list(reversed(self._recent_events[-limit:]))

    def _add_event(self, event_type: str, file_path: str, status: str, detail: str = ''):
        """记录一条防护事件"""
        ev = {
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'type': event_type,
            'file_path': file_path,
            'status': status,  # success / threat / error / info
            'detail': detail,
        }
        with self._events_lock:
            self._recent_events.append(ev)
            if len(self._recent_events) > 200:
                self._recent_events = self._recent_events[-200:]
        logger.info(f"[实时防护] {event_type} {file_path} -> {status} {detail}")

    # ===================================================================
    # 并发扫描进程池管理
    # ===================================================================

    def _start_scan_subprocess(self):
        """创建并发扫描进程池（**非阻塞**，立即返回）

        每个 worker 独立进程各持一份 ScanEngine（独立 GIL + 内存空间），
        同时最多 RT_MAX_PARALLEL_SCANS 个文件并行扫描，大文件扫描不阻塞
        主进程 UI；扫描期间 worker 以独占句柄占用文件，阻止其被启动/执行。
        """
        config = {
            'strict_mode': self.strict_mode,
            'max_file_size_mb': 50,
            'user_excluded_dirs': sorted(list(self._user_excluded_dirs)),
            # VirusIdentifier 开关（由 bridge 从设置注入；默认关闭）
            'virus_identifier': bool(getattr(self, 'virus_identifier_enabled', False)),
        }
        # 从已缓存的引擎读取配置
        with self._engine_lock:
            if self._cached_engine is not None:
                config['max_file_size_mb'] = getattr(
                    self._cached_engine, 'max_file_size_mb', 50)

        # 持久禁用后不再重复 spawn（打包 onedir spawn 子进程 WinError5 兜底）
        if self._scan_subprocess_disabled:
            return

        # PyInstaller 打包环境(frozen)下 multiprocessing spawn 的 WinError5：
        # Pool() 同步拉起 6 个子进程时，任意一个 spawn 在 reduction.duplicate
        # 句柄复制被拒 → 逐个阻塞秒级，累计造成启动"未响应"，触发 Windows
        # 无响应检测且主线程极难被中断，即使最终降级也让用户误以为卡死。
        # 直接回退主进程扫描（扫描在后台 daemon 线程执行，不阻塞 Qt 主线程）。
        if getattr(sys, 'frozen', False):
            self._scan_subprocess_disabled = True
            logger.warning("打包环境禁用扫描进程池，回退主进程扫描（规避 WinError5 spawn 卡死）")
            return

        try:
            if self._pool is not None:
                return
            self._pool = multiprocessing.Pool(
                processes=RT_MAX_PARALLEL_SCANS,
                initializer=_pool_worker_init,
                initargs=(config,),
            )
            logger.info(
                f"实时防护扫描进程池就绪（workers={RT_MAX_PARALLEL_SCANS}，独立进程，"
                f"扫描期间占用文件）")
        except Exception as e:
            logger.warning(f"创建扫描进程池失败，回退到主进程扫描: {e}")
            self._pool = None
            # 持久禁用：WinError5(spawn 子进程句柄复制被拒)时不再反复重试 spawn，
            # 直接回退主进程扫描，避免每次启动都刷一遍 spawn 报错。
            self._scan_subprocess_disabled = True

    def _stop_scan_subprocess(self):
        """停止并销毁扫描进程池

        先优雅回收（等待在途扫描完成后释放文件锁），超时 10 秒则强制终止，
        确保关闭实时防护时不阻塞主进程关闭流程。
        """
        pool = self._pool
        if pool is None:
            return
        self._pool = None
        try:
            pool.close()
        except Exception:
            pass
        # 优雅回收带超时：在途任务完成后会清理临时副本并释放独占锁
        finisher = threading.Thread(target=pool.join, daemon=True)
        finisher.start()
        finisher.join(timeout=10)
        if finisher.is_alive():
            logger.warning("扫描进程池回收超时，强制终止")
            try:
                pool.terminate()
                pool.join()
            except Exception:
                pass

    def start(self) -> bool:
        """启动实时防护"""
        if self._running:
            return True
        if not HAS_WATCHDOG:
            logger.warning("watchdog 未安装,实时防护以降级模式启动(仅记录状态)")
            self._running = True
            self._start_time = time.time()
            with self._stats_lock:
                self._stats['started_at'] = self._start_time
            self._add_event('system', '', 'info', '实时防护已启动(降级模式:未安装 watchdog)')
            return True

        try:
            # 启动前刷新 PSLS 附属进程路径（动态收集 MLWorker 等可执行文件位置）
            self._refresh_self_process_paths()

            self._observer = Observer()
            self._handler = _ThreatHandler(self)
            watched = 0
            for d in self._watch_dirs:
                if d and os.path.isdir(d):
                    self._observer.schedule(self._handler, d, recursive=True)
                    watched += 1
            if watched == 0:
                logger.warning("无有效监控目录,实时防护未启动")
                self._observer = None
                return False
            self._observer.start()
            self._running = True
            self._start_time = time.time()
            with self._stats_lock:
                self._stats['started_at'] = self._start_time
            # 启动扫描消费线程
            self._scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
            self._scan_thread.start()
            # 启动并发扫描进程池（独立进程，避免大文件扫描卡死主进程 UI）
            self._start_scan_subprocess()
            self._add_event('system', '', 'info', f'实时防护已启动,监控 {watched} 个目录')
            logger.info(f"实时防护已启动,监控 {watched} 个目录: {self._watch_dirs}")
            return True
        except Exception as e:
            logger.error(f"启动实时防护失败: {e}")
            self._observer = None
            self._running = False
            return False

    def stop(self) -> bool:
        """停止实时防护"""
        if not self._running:
            return True
        self._running = False
        # 唤醒阻塞在 Condition 上的扫描线程，使其能检测到 _running=False 并退出
        with self._queue_cond:
            self._queue_cond.notify_all()
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=2)
            except Exception:
                pass
            self._observer = None
        self._handler = None
        # 停止扫描子进程
        self._stop_scan_subprocess()
        # 清理缓存的扫描引擎
        with self._engine_lock:
            self._cached_engine = None
        # 释放所有尚未释放的威胁处置独占锁（否则句柄会滞留到进程退出）
        with self._threat_locks_lock:
            for fo, _ts in list(self._threat_locks.values()):
                try:
                    fo.close()
                except Exception:
                    pass
            self._threat_locks.clear()
        self._add_event('system', '', 'info', '实时防护已停止')
        logger.info("实时防护已停止")
        return True

    def release_threat_lock(self, file_path: str) -> bool:
        """释放威胁处置阶段登记的文件独占句柄。

        在 on_threat 回调处置完成（隔离成功/删除成功/用户手动放行了事）后，
        桥接层必须调用本方法释放 share=0 句柄，否则文件会一直处于 PSLS 占用状态，
        用户/系统对该文件的合法操作（比如删除被隔离残留、用户手动放行后启动）会失败。

        对已不存在路径、未登记路径、已被自动超时清理的路径，调用是安全的 no-op。

        Args:
            file_path: 原始文件路径（未规范化前的即可，内部做 os.path.abspath 对齐）
        Returns:
            True=实际释放了一个句柄；False=无匹配句柄（通常是预期的 no-op）
        """
        import time as _t
        if not file_path:
            return False
        try:
            norm_fp = os.path.abspath(file_path)
        except Exception:
            norm_fp = file_path
        released = False
        with self._threat_locks_lock:
            old = self._threat_locks.pop(norm_fp, None)
            if old is not None:
                try:
                    old[0].close()
                    released = True
                except Exception:
                    released = True  # 失败也算"处理过"，避免重复
            # 顺手清理过期句柄：release 调用是最轻量的回收时机
            stale_ts = _t.time() - self._threat_lock_max_seconds
            stale_keys = [k for k, (_fo, ts) in self._threat_locks.items() if ts < stale_ts]
            for sk in stale_keys:
                try:
                    self._threat_locks[sk][0].close()
                except Exception:
                    pass
                self._threat_locks.pop(sk, None)
        if released:
            logger.debug(f'威胁处置锁已释放: {file_path}')
        return released

    def locked_copy_to_temp(self, file_path: str) -> Optional[str]:
        """**内部通道**：若该文件正被 PSLS 自己持有处置锁，则通过该句柄拷出临时副本。

        动机（实测）：「实时保护已锁定【Minecraft.exe】」期间，沙箱分析要复制同一
        源文件 → 外部打开被拒（`[Errno 9] Bad file descriptor` / 共享冲突），
        沙箱因此"分析失败"。自己人不该被自己锁死：这里用**已持有的句柄**直接读取
        内容写出临时文件，供沙箱使用（不改动锁的生命周期）。

        返回临时副本路径；无锁/读取失败返回 None（调用方回退普通复制/重试）。
        """
        if not file_path:
            return None
        try:
            norm_fp = os.path.abspath(file_path)
        except Exception:
            norm_fp = file_path
        with self._threat_locks_lock:
            entry = self._threat_locks.get(norm_fp)
        if not entry or entry[0] is None:
            return None
        src_obj = entry[0]
        tmp = ''
        try:
            import tempfile as _tf
            ext = os.path.splitext(file_path)[1]
            fd, tmp = _tf.mkstemp(prefix='psls_locked_', suffix=ext)
            with os.fdopen(fd, 'wb') as out:
                # 用我们的句柄读取（独占锁持有者自身读取不受共享模式限制）
                src_obj.seek(0)
                while True:
                    chunk = src_obj.read(65536)
                    if not chunk:
                        break
                    out.write(chunk)
            logger.info(f'经内部通道读取锁定文件副本: {file_path} -> {tmp}')
            return tmp
        except Exception as e:
            logger.warning(f'内部通道复制锁定文件失败 {file_path}: {e}')
            if tmp:
                try:
                    os.unlink(tmp)
                except Exception:
                    pass
            return None

    def _enqueue_scan(self, file_path: str):
        """将变更文件加入扫描队列

        优化点：
        1. dict+set 结构实现 O(1) 入队和去重
        2. 高危扩展名（.exe/.scr/.bat 等）跳过去抖，立即唤醒扫描线程实现零延迟扫描
        3. 普通文件保留 RT_DEBOUNCE_SECONDS 去抖，避免短时间内重复变更触发多次扫描
        """
        now = time.time()
        ext = os.path.splitext(file_path)[1].lower()
        is_high_risk = ext in RT_HIGH_RISK_EXTENSIONS

        # 去抖动：高危扩展名跳过去抖，普通文件保留去抖
        if not is_high_risk:
            last = self._last_scan.get(file_path, 0)
            if now - last < RT_DEBOUNCE_SECONDS:
                return
        self._last_scan[file_path] = now

        # O(1) 入队判断（set 替代 list 的 O(n) `in` 检查）
        with self._queue_cond:
            if file_path in self._queue_set:
                return
            self._queue[file_path] = now
            self._queue_set.add(file_path)
            # 高危文件立即唤醒扫描线程；普通文件也唤醒（Condition 模式下成本极低）
            self._queue_cond.notify_all()

    def _scan_loop(self):
        """扫描消费线程：阻塞式从队列取文件并扫描

        使用 threading.Condition 替代 sleep 轮询：
        - 队列为空时 wait() 阻塞，不消耗 CPU
        - 文件入队时 notify_all() 立即唤醒，响应延迟 <1ms
        - 带超时的 wait(1.0) 作为兜底，防止遗漏 notify 信号
        """
        while self._running:
            try:
                with self._queue_cond:
                    if not self._queue:
                        # 队列空闲时清理过期去抖记录，防止长期运行 _last_scan 无限增长
                        try:
                            now = time.time()
                            stale = [fp for fp, ts in self._last_scan.items()
                                     if now - ts > RT_DEBOUNCE_SECONDS * 4]
                            for fp in stale:
                                self._last_scan.pop(fp, None)
                        except Exception:
                            pass
                        # 阻塞等待新文件入队，最多等 1 秒后再次检查 _running
                        self._queue_cond.wait(timeout=1.0)
                        if not self._queue:
                            continue
                    # 取出并清空队列
                    items = list(self._queue.items())
                    self._queue.clear()
                    self._queue_set.clear()
                for fp, _ts in items:
                    if not self._running:
                        break
                    self._scan_single(fp)
            except Exception as e:
                logger.error(f"实时扫描循环异常: {e}")

    def _scan_single(self, file_path: str):
        """扫描单个变更文件（白名单预检查优先）"""
        try:
            if not os.path.exists(file_path):
                return
            # 回滚仓库 / 影子原像根：PSLS 自身产出，扫描前直接跳过（兜底）
            if self.is_psls_own_path(file_path):
                logger.debug('文件在回滚仓库/影子根内，跳过实时扫描: %s', file_path)
                return
            # PSLS 自身文件二次检查（防止 _on_any 漏过的边缘情况）
            if self._self_excluded_dirs:
                try:
                    fp_lower = os.path.abspath(file_path).lower()
                    if fp_lower in self._self_excluded_dirs:
                        return
                    if any(fp_lower.startswith(d) for d in self._self_excluded_dirs):
                        return
                except Exception:
                    pass
            # 用户排除路径二次检查（防止 _on_any 漏过的边缘情况，直达扫描前拦截）
            if self._in_user_excluded(file_path):
                return
            # 临时排除（MB 同步/训练等内部作业注册）：优先级同用户排除
            if _path_in_temp_excluded(file_path):
                logger.debug('文件落在临时排除目录，跳过实时扫描: %s', file_path)
                return
            # 路径豁免检查：跳过刚从隔离区复原的文件，避免再次扫描触发告警/隔离。
            # 仅作用于实时防护扫描阶段；沙箱分析不经过此路径，不受影响。
            if self._exemption_checker:
                try:
                    if self._exemption_checker(file_path):
                        logger.info(f'文件已豁免（本次运行已复原），实时防护跳过扫描: {file_path}')
                        with self._stats_lock:
                            self._stats['files_scanned'] += 1
                        return
                except Exception:
                    pass
            # 白名单哈希预检查：命中 SignatureDB 白名单则直接跳过，避免引擎扫描开销
            if self._signature_db:
                try:
                    import hashlib
                    sz = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
                    if sz > 0 and sz < 2 * 1024 * 1024 * 1024:  # <2GB
                        h = hashlib.sha256()
                        with open(file_path, 'rb') as f:
                            while True:
                                chunk = f.read(65536)
                                if not chunk:
                                    break
                                h.update(chunk)
                        f_hash = h.hexdigest()
                        if self._signature_db.is_whitelisted(f_hash):
                            # 计入已扫描但不触发回调（已通过白名单）
                            with self._stats_lock:
                                self._stats['files_scanned'] += 1
                            return
                except Exception:
                    pass
            # 主路径：进程池异步并发扫描（同时最多 RT_MAX_PARALLEL_SCANS 个，
            # 独立进程扫描，期间独占占用文件防启动；不阻塞主进程 UI，也不互相卡死）
            if self._pool is not None:
                try:
                    self._pool.apply_async(
                        _pool_scan_file, (file_path,),
                        callback=self._on_pool_result_done,
                    )
                    return
                except Exception as e:
                    logger.warning(f"进程池提交失败，回退主进程扫描: {e}")
                    # 半废池：销毁并持久禁用，后续回退主进程扫描
                    try:
                        self._pool.terminate()
                    except Exception:
                        pass
                    self._pool = None
                    self._scan_subprocess_disabled = True
            # 回退：主进程同步扫描（进程池不可用时）
            with self._engine_lock:
                if self._cached_engine is None:
                    self._cached_engine = self._scan_engine_factory()
                engine = self._cached_engine
            if engine is None:
                return
            results = engine.scan_file_with_archives(file_path)
            with self._stats_lock:
                self._stats['files_scanned'] += 1
            self._process_scan_results(file_path, results)
        except Exception as e:
            with self._stats_lock:
                self._stats['errors'] += 1
            logger.error(f"实时扫描文件失败 {file_path}: {e}")

    def _on_pool_result_done(self, payload):
        """进程池扫描完成回调（运行于主进程，由进程池结果线程调用）

        将 worker 返回的序列化结果还原为 ScanResult 后统一走 _process_scan_results。
        """
        if not isinstance(payload, dict):
            return
        file_path = payload.get('file_path', '')
        error = payload.get('error')
        serialized = payload.get('results', [])
        results = []
        if error is None and serialized:
            try:
                from engine.scan_engine import ScanResult
                for d in serialized:
                    results.append(ScanResult(
                        file_path=file_path,  # 使用原始路径，覆盖临时副本路径
                        status=d.get('status', 'error'),
                        malware_info=d.get('malware_info', {}),
                        heuristic_matches=d.get('heuristic_matches', []),
                        internal_path=d.get('internal_path', ''),
                        pe_analysis=d.get('pe_analysis', {}),
                        rule_matches=d.get('rule_matches', []),
                    ))
            except Exception as e:
                logger.debug(f"进程池结果反序列化失败: {e}")
                results = []
        with self._stats_lock:
            self._stats['files_scanned'] += 1
            if error is not None:
                self._stats['errors'] += 1
        if not results:
            # 扫描出错 or 无子结果：出错不回调；无子结果（如空压缩包）回调一次 clean
            if error is None and self._on_scan_result:
                try:
                    self._on_scan_result({
                        'file_path': file_path,
                        'status': 'clean',
                        'malware_name': '',
                        'internal_path': '',
                    })
                except Exception:
                    pass
            return
        self._process_scan_results(file_path, results)

    def _process_scan_results(self, file_path: str, results: List):
        """统一的扫描结果后置逻辑（隔离计数、事件记录、on_scan_result / on_threat 回调）

        同一 file_path（如压缩包）的多个内部威胁只触发一次 on_threat，
        避免同一物理文件被重复隔离（首次隔离后文件已不存在，后续必然失败）。
        优先选择最高严重度（malware > suspicious）的威胁信息触发 on_threat。
        """
        emitted_any_result = False
        top_threat_info = None
        top_threat_rank = 0
        _severity_rank = {'malware': 3, 'suspicious': 2}
        for r in results:
            emitted_any_result = True
            if r.status == 'malware':
                with self._stats_lock:
                    self._stats['threats_detected'] += 1
                name = (r.malware_info or {}).get('name', '未知威胁')
                self._add_event('threat', file_path, 'threat', f'检测到威胁: {name}')
                threat_info = {
                    'file_path': file_path,
                    'status': 'malware',
                    'malware_name': name,
                    'internal_path': r.internal_path,
                }
                # 收集最高严重度威胁，不立即触发 on_threat（循环后统一触发一次）
                rank = _severity_rank.get('malware', 0)
                if rank > top_threat_rank:
                    top_threat_rank = rank
                    top_threat_info = threat_info
            elif r.status == 'suspicious':
                name = '可疑文件'
                if r.heuristic_matches:
                    name = r.heuristic_matches[0].get('name', '可疑文件')
                elif r.rule_matches:
                    name = r.rule_matches[0].get('rule_name', '可疑文件')
                elif r.pe_analysis:
                    name = f"PE分析: {r.pe_analysis.get('details', {}).get('reason', '可疑文件')}"

                # 严格模式计入 threats_detected 计数；非严格模式仅记录为 warn 级别扫描事件
                if self.strict_mode:
                    with self._stats_lock:
                        self._stats['threats_detected'] += 1
                    self._add_event('threat', file_path, 'warn', f'可疑文件: {name}')
                else:
                    self._add_event('scan', file_path, 'warn', f'可疑文件: {name}')

                # 无论严格/非严格，只要用户设置了可疑处理策略就回调 on_threat，
                # 由桥接层按 rt_suspicious_action（auto/notify/ignore）决定是否处置。
                threat_info = {
                    'file_path': file_path,
                    'status': 'suspicious',
                    'malware_name': name,
                    'internal_path': r.internal_path,
                }
                # 收集最高严重度威胁，不立即触发 on_threat
                rank = _severity_rank.get('suspicious', 0)
                if rank > top_threat_rank:
                    top_threat_rank = rank
                    top_threat_info = threat_info
            elif r.status == 'error':
                with self._stats_lock:
                    self._stats['errors'] += 1

            # 对每个扫描结果（含 clean）触发 on_scan_result 回调，驱动新文件扫描结果弹窗
            if self._on_scan_result:
                try:
                    self._on_scan_result({
                        'file_path': file_path,
                        'status': r.status,  # clean / malware / suspicious / error / skipped
                        'malware_name': (r.malware_info or {}).get('name', '') if r.status in ('malware', 'suspicious') else '',
                        'internal_path': r.internal_path or '',
                    })
                except Exception:
                    pass

        # 循环结束后，只对最高严重度威胁触发一次 on_threat（避免重复隔离同一物理文件）
        if top_threat_info and self._on_threat:
            # ---- 前置去重：若该文件哈希已在隔离区中，直接跳过本次回调 ----
            # 背景：
            #   1) 软隔离（quarantine_manager 降级分支）会将原文件改名 + ACL 禁用，
            #      但文件仍在原路径，watchdog 会继续触发事件，形成"检测→已隔离→再检测"循环。
            #   2) 硬隔离成功后，即便 watchdog 因其他文件属性变更再次触发同一文件扫描，
            #      同一哈希不会产生新的威胁，避免 on_threat 反复写活动日志/弹窗。
            _already_quarantined = False
            try:
                _qm = getattr(self, '_quarantine_manager', None)
                if _qm is None:
                    # 尝试从 ScanEngine 实例上取（通过 _cached_engine）
                    _eng = getattr(self, '_cached_engine', None)
                    if _eng is not None:
                        _qm = getattr(_eng, '_quarantine_manager', None)
                if _qm is not None and hasattr(_qm, 'is_hash_quarantined'):
                    import hashlib as _hl
                    if os.path.exists(file_path):
                        sz = os.path.getsize(file_path)
                        if 0 < sz < 2 * 1024 * 1024 * 1024:
                            _h = _hl.sha256()
                            with open(file_path, 'rb') as _f:
                                for _chunk in iter(lambda: _f.read(65536), b''):
                                    _h.update(_chunk)
                            _digest = _h.hexdigest()
                            if _qm.is_hash_quarantined(_digest):
                                _already_quarantined = True
                                logger.info(
                                    f'文件已在隔离区（hash命中），跳过实时威胁回调: {file_path}')
                                with self._stats_lock:
                                    self._stats.setdefault(
                                        'threats_skipped_already_quarantined', 0)
                                    self._stats['threats_skipped_already_quarantined'] += 1
            except Exception as _e:
                logger.debug(f'前置去重检查异常（继续处置）: {_e}')

            if _already_quarantined:
                # 已在隔离区的文件：标记处置缓存 TTL，窗口内不再入队
                _mark_file_disposed(file_path)
                # 若磁盘上现存文件是隔离后重新出现的恶意副本（哈希命中=同一恶意内容），
                # 必须直接删除，不能无条件跳过——否则会长期留在桌面
                # （场景：重新下载/云同步/再次解压同一恶意文件，哈希仍命中隔离区）。
                try:
                    if _qm is not None and hasattr(_qm, 'remove_recreated_copy'):
                        if _qm.remove_recreated_copy(file_path, _digest):
                            logger.info(f'实时防护已删除隔离后重新出现的恶意副本: {file_path}')
                            with self._stats_lock:
                                self._stats.setdefault(
                                    'threats_removed_recreated_copies', 0)
                                self._stats['threats_removed_recreated_copies'] += 1
                except Exception as _re_e:
                    logger.debug(f'清理重新出现的恶意副本异常: {_re_e}')
                # 跳过 on_threat 以及后续锁登记
                return

            # 记录处置缓存（即便隔离失败，至少 TTL 内不再入队引发循环检测）
            _mark_file_disposed(file_path)

            # —— 关键：调用 on_threat（UI 弹窗/隔离/删除）前，在主进程端重新拿独占句柄 ——
            # worker 的 finally 已关闭它的锁，若不重新拿，用户可以在扫描完成到
            # 处置执行的窗口内双击启动文件（实测可达 0.5~3s 甚至更长）。
            # 锁获取失败（文件已被其他进程抢先打开）不影响回调流程，仅记录告警。
            try:
                import time as _t
                lock_obj = _lock_file_exclusive(file_path, timeout_sec=0.25)
                if lock_obj is not None:
                    try:
                        norm_fp = os.path.abspath(file_path)
                    except Exception:
                        norm_fp = file_path
                    with self._threat_locks_lock:
                        # 先清理同路径旧句柄（避免多次检测导致累积）
                        old = self._threat_locks.pop(norm_fp, None)
                        if old:
                            try:
                                old[0].close()
                            except Exception:
                                pass
                        # 登记新句柄 + 登记时间戳；后续 on_threat 处置完成会 release
                        self._threat_locks[norm_fp] = (lock_obj, _t.time())
                        # 顺便清理过期威胁锁（防止 release 未调用时句柄泄漏）
                        stale_ts = _t.time() - self._threat_lock_max_seconds
                        stale_keys = [k for k, (_fo, ts) in self._threat_locks.items()
                                      if ts < stale_ts and k != norm_fp]
                        for sk in stale_keys:
                            try:
                                self._threat_locks[sk][0].close()
                            except Exception:
                                pass
                            self._threat_locks.pop(sk, None)
                    logger.debug(f'威胁处置锁定文件成功: {file_path}')
                else:
                    logger.warning(f'威胁文件已被占用，主进程无法独占锁定：{file_path} '
                                   f'(可能用户已抢先启动)')
            except Exception as e:
                logger.warning(f'威胁文件加锁失败 {file_path}: {e}')
            try:
                self._on_threat(top_threat_info)
            except Exception:
                pass

        # 如果没有任何子扫描结果（例如压缩包为空或文件被跳过），也回调一次 clean，
        # 确保"新文件扫描结果"弹窗不会漏掉任何实际已扫描的文件
        if not emitted_any_result and self._on_scan_result:
            try:
                self._on_scan_result({
                    'file_path': file_path,
                    'status': 'clean',
                    'malware_name': '',
                    'internal_path': '',
                })
            except Exception:
                pass
