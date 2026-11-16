# -*- coding: utf-8 -*-
"""
文件保护引擎
监控关键系统/用户文件的完整性，检测篡改、删除和勒索软件行为。
基于文件哈希校验 + watchdog 文件系统监控实现。
"""
import os
import sys
import time
import shutil
import hashlib
import threading
import json
from typing import Callable, Dict, List, Optional, Set, Tuple

from utils.logger import get_logger

logger = get_logger('file_protection')

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    Observer = None
    FileSystemEventHandler = object


# ---- 关键保护文件列表 ----

# 系统关键文件（Windows）
WINDOWS_CRITICAL_FILES = [
    r'C:\Windows\System32\kernel32.dll',
    r'C:\Windows\System32\ntdll.dll',
    r'C:\Windows\System32\user32.dll',
    r'C:\Windows\System32\explorer.exe',
    r'C:\Windows\System32\winlogon.exe',
    r'C:\Windows\System32\cmd.exe',
    r'C:\Windows\System32\notepad.exe',
]

# 关键注册表备份（以文件形式保护）
REGISTRY_KEYWORDS = [
    'Software\\Microsoft\\Windows\\CurrentVersion',
    'Software\\Microsoft\\Windows NT\\CurrentVersion',
    'System\\CurrentControlSet\\Services',
]

# 保护配置文件类型（用户重要文档）
IMPORTANT_EXTENSIONS = {
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.pdf', '.odt', '.ods', '.odp',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
    '.mp3', '.wav', '.flac', '.mp4', '.avi', '.mkv',
    '.txt', '.md', '.rtf', '.csv',
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '.py', '.js', '.ts', '.cpp', '.h', '.java', '.html', '.css',
    '.json', '.xml', '.yaml', '.yml', '.ini', '.conf',
    '.db', '.sqlite', '.sql',
}

# 勒索软件特征扩展名（加密后的文件）
RANSONWARE_EXTENSIONS = {
    '.locked', '.encrypted', '.crypt', '.cryptolocker',
    '.locky', '.zepto', '.cerber', '.lockbit',
    '.wcry', '.wncry', '.wncry2',
    '.xtbl', '.yay', '.zzzzz', '.lol',
    '.paym', '.exx', '.ecc', '.ezz',
    '.mooe', '.m00e', '.ox', '.fuck',
    '.davinci', '.da_vinci', '.vault', '.vif',
}

# 二进制运行时扩展名 — 勒索软件不会加密这些（修改它们是病毒感染，
# 走病毒扫描/进程保护链路，不走勒索检测链路）
BINARY_RUNTIME_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.scr', '.com', '.ocx', '.dat',
    '.bin', '.msi', '.cab', '.jar', '.apk', '.so', '.dylib',
    '.node', '.pyc', '.pyo', '.class', '.woff', '.woff2',
}

# 短时间内大量文件被修改的阈值（勒索软件行为特征）
# 勒索软件加密的是用户文档（doc/xls/pdf/jpg/zip 等），不是 DLL/exe
# — 阈值针对 IMPORTANT_EXTENSIONS 中的文档类型
MASS_MODIFY_THRESHOLD = 30        # 数量: 30 个文档文件
MASS_MODIFY_TIME_WINDOW = 5       # 秒: 5 秒窗口

# 低水位预警阈值：同一 5s 窗口内修改达到 5 个文件即回调 on_prewarn，
# 抢在 (30 个) 勒索判定前对保护目录入仓（仅通知，不改变判定语义）。
PREWARN_THRESHOLD = 5

# ---- 增强监测维度（大小变化 / 后缀名改变）----
# 这些维度不改变上面"数量维度"的既有阈值语义，只是把额外信号融合进同一窗口：
#   - 大小变化信号计入"窗口信号总数"（数量维度 + 大小维度）
#   - 后缀名改变（改名）是更明确的勒索形态 → 用更低的次数阈值即触发预警/确认

# 大小变化判定阈值（避免对"正常追加写入"过敏）：
#   1) 变为 0：文件被清零（> SIZE_ABS_MIN 才计），勒索加密前的典型清空/截断
#   2) 增长到 >= SIZE_GROW_RATIO 倍，且增长绝对值 >= SIZE_ABS_MIN
#   3) 缩小到 <= SIZE_SHRINK_RATIO 倍，且原大小 >= SIZE_ABS_MIN
# 普通追加写入每次只增加少量字节，既不满足 2) 的倍数，也不满足 3)，不会被计入。
SIZE_ABS_MIN = 4096          # 绝对最小变化量（字节），低于此视为正常小改动
SIZE_GROW_RATIO = 2.0        # 增长到原大小的 2 倍视为显著
SIZE_SHRINK_RATIO = 0.5      # 缩小到原大小的 1/2 视为显著

# 后缀名改变（改名）强信号阈值：强信号次数远小于数量阈值即可触发
RENAME_PREWARN_THRESHOLD = 2     # 2 次改名 → 低水位预警
RENAME_CONFIRM_THRESHOLD = 3     # 3 次改名 → 确认勒索

# 勒索改名常见目标后缀（在 RANSONWARE_EXTENSIONS 基础上补充少量常见形态，
# 仅用于"改名"这一强信号的识别，不改动 RANSONWARE_EXTENSIONS 的既有语义）
RANSOMWARE_RENAME_EXTS = RANSONWARE_EXTENSIONS | {'.enc', '.lock', '.crypto'}


class _ProtectedFileHandler(FileSystemEventHandler):
    """watchdog 事件处理器：监控受保护文件的变更"""

    def __init__(self, manager: 'FileProtection'):
        super().__init__()
        self._manager = manager

    def on_modified(self, event):
        if event.is_directory:
            return
        self._manager._on_file_event(event.src_path, 'modified')

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._manager._on_file_event(event.src_path, 'deleted')

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path.lower()
        # 检测勒索软件加密文件
        _, ext = os.path.splitext(path)
        if ext.lower() in RANSONWARE_EXTENSIONS:
            self._manager._on_ransomware_detected(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        # src_path（原路径）计入批量修改检测（勒索软件重命名文件）
        self._manager._on_file_event(event.src_path, 'moved')
        # dest_path（新路径）检查是否出现勒索软件加密后缀
        dest = getattr(event, 'dest_path', '')
        if dest:
            _, dest_ext = os.path.splitext(dest.lower())
            if dest_ext in RANSONWARE_EXTENSIONS:
                self._manager._on_ransomware_detected(dest)
            # dest_path 也计入批量修改检测
            self._manager._on_file_event(dest, 'moved')
            # 后缀名改变维度：识别"改名成新后缀"的强信号
            self._manager._on_file_renamed(event.src_path, dest)


class FileProtection:
    """
    文件保护引擎

    功能：
    1. 完整性保护：为关键文件建立哈希基线，检测篡改
    2. 实时监控：watchdog 监控受保护目录的文件变更
    3. 勒索软件检测：短时间内大量文件修改 / 出现加密后缀
    4. 文件备份：对关键文件创建受保护的备份副本
    5. 主动防御：检测到威胁时隔离受影响文件
    """

    def __init__(self, quarantine_manager=None, signature_db=None,
                 on_threat: Callable[[dict], None] = None,
                 on_ransomware_kill: Callable[[str], None] = None,
                 on_prewarn: Callable[[List[str]], None] = None,
                 on_ransomware_confirmed: Callable[[dict], None] = None):
        self._quarantine_manager = quarantine_manager
        self._signature_db = signature_db
        self._on_threat = on_threat
        self._on_ransomware_kill = on_ransomware_kill
        # 勒索文件回滚接线（可选，默认 None）：
        #   on_prewarn: 低水位预警（5 文件/5s）时回调，用于抢在加密前入仓
        #   on_ransomware_confirmed: 确认勒索（杀进程后）时回调，用于触发回滚
        # 二者均为公开属性，便于引擎构造后再接线。仅回调，绝不影响既有判定语义。
        self.on_prewarn = on_prewarn
        self.on_ransomware_confirmed = on_ransomware_confirmed
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._observer: Optional['Observer'] = None
        self._handler: Optional[_ProtectedFileHandler] = None

        # 文件哈希基线
        self._file_baselines: Dict[str, dict] = {}
        self._baseline_lock = threading.Lock()

        # 监控目录列表
        self._protected_dirs: List[str] = []
        self._protected_files: Set[str] = set()

        # PSLS 自身安装目录（小写, 带尾分隔符）— 自身运行时产生的文件写入
        # （日志/缓存/隔离区/数据库等）不得计入勒索批量修改检测,
        # 否则 PSLS 装在 Desktop 下时会自己触发自己的 ransomware_suspected
        # 误报, 极端情况下还会经 _on_ransomware_kill 终止自身进程。
        # PSLS 自身文件的防篡改由 self_protection 模块独立负责, 此处不涉及。
        # 注意: 开发模式下 sys.executable 是 python 解释器, 目录并不包含项目根,
        # 必须显式使用项目根, 否则项目内 backup/ 等自身产出目录无法豁免,
        # 自我保护自动备份 → 备份目录批量写入 → 勒索软件误报风暴。
        if getattr(sys, 'frozen', False):
            self._self_root = os.path.dirname(
                os.path.abspath(sys.executable)).lower().rstrip('\\/') + os.sep
        else:
            self._self_root = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))).lower().rstrip('\\/') + os.sep

        # PSLS 回滚仓库目录（打包 %APPDATA%\PSLS\rollback；开发 <项目根>\rollback；
        # 可被环境变量 PSLS_ROLLBACK_REPO 覆盖，与 ransomware_rollback._REPO_ROOT 同源）。
        # 回滚快照会读取受监控目录下的文件（持有句柄/触发读写），必须与自身安装
        # 目录一样排除在"被监控/被隔离/被归因"之外，否则启动快照会自干扰归因。
        _repo_env = os.environ.get('PSLS_ROLLBACK_REPO')
        if _repo_env:
            _repo_abs = os.path.abspath(_repo_env)
        elif getattr(sys, 'frozen', False):
            if sys.platform == 'win32':
                _appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
            else:
                _appdata = os.path.expanduser('~/.config')
            _repo_abs = os.path.join(_appdata, 'PSLS', 'rollback')
        else:
            _repo_abs = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'rollback')
        # 规范化（normcase）+ 尾分隔符：跨大小写安全，且不会误伤 ...\rollback2
        self._repo_root = os.path.normcase(_repo_abs).rstrip('\\/') + os.sep

        # 批量修改检测
        self._recent_modifications: List[Tuple[float, str]] = []
        self._mod_lock = threading.Lock()
        # 增强监测维度（与 _recent_modifications 同窗口、同锁）：
        #   _recent_size_changes: 显著大小变化信号 (time, path)
        #   _recent_renames:      后缀名改变（改名）强信号 (time, path)
        #   _last_sizes:          每个文件上次观测到的大小（用于判定变化幅度）
        self._recent_size_changes: List[Tuple[float, str]] = []
        self._recent_renames: List[Tuple[float, str]] = []
        self._last_sizes: Dict[str, int] = {}
        # 勒索响应线程去重标记：避免加密持续期间反复触发导致后台线程风暴
        self._ransomware_responding = False

        # 勒索软件防护模式开关
        self._ransomware_guard = True

        # 统计数据
        self._stats = {
            'files_monitored': 0,
            'integrity_checks': 0,
            'tampering_detected': 0,
            'ransomware_alerts': 0,
            'files_restored': 0,
            'quarantined': 0,
            'started_at': 0,
        }
        self._stats_lock = threading.Lock()

        # 最近事件
        self._recent_events: List[dict] = []
        self._events_lock = threading.Lock()
        self._max_events = 200

        # 备份目录
        # 打包模式下使用 %APPDATA%\PSLS\quarantine\_file_backups 避免只读临时目录
        if getattr(sys, 'frozen', False):
            if sys.platform == 'win32':
                appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
            else:
                appdata = os.path.expanduser('~/.config')
            self._backup_dir = os.path.join(appdata, 'PSLS', 'quarantine', '_file_backups')
        else:
            self._backup_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'quarantine', '_file_backups'
            )
        os.makedirs(self._backup_dir, exist_ok=True)

        # 基线建立延迟到 start() 后由子线程执行，避免阻塞主线程
        self._baselines_built = False

    # ---- 属性 ----

    @property
    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    def get_recent_events(self, limit: int = 20) -> list:
        with self._events_lock:
            return list(reversed(self._recent_events[-limit:]))

    def add_protected_directory(self, dir_path: str):
        """添加受保护目录"""
        dir_path = os.path.abspath(dir_path)
        if os.path.isdir(dir_path) and dir_path not in self._protected_dirs:
            self._protected_dirs.append(dir_path)
            logger.info(f'添加受保护目录: {dir_path}')

    def remove_protected_directory(self, dir_path: str):
        """移除受保护目录"""
        dir_path = os.path.abspath(dir_path)
        if dir_path in self._protected_dirs:
            self._protected_dirs.remove(dir_path)

    # ---- 初始化 ----

    def _init_protected_files(self):
        """初始化受保护文件列表"""
        # 系统关键文件
        for path in WINDOWS_CRITICAL_FILES:
            if os.path.isfile(path):
                self._protected_files.add(path.lower())

        # 用户文档目录
        user_dirs = [
            os.path.join(os.path.expanduser("~"), "Documents"),
            os.path.join(os.path.expanduser("~"), "Desktop"),
            os.path.join(os.path.expanduser("~"), "Downloads"),
        ]
        for d in user_dirs:
            if os.path.isdir(d):
                self._protected_dirs.append(d)

        # 对关键文件建立基线
        self._build_baselines()

        logger.info(
            f'文件保护初始化: {len(self._protected_files)} 个受保护文件, '
            f'{len(self._protected_dirs)} 个受保护目录'
        )

    def _build_baselines(self):
        """为所有受保护文件建立哈希基线"""
        with self._baseline_lock:
            for filepath in self._protected_files:
                try:
                    if os.path.isfile(filepath):
                        file_hash = self._compute_file_hash(filepath)
                        stat = os.stat(filepath)
                        self._file_baselines[filepath] = {
                            'hash': file_hash,
                            'size': stat.st_size,
                            'mtime': stat.st_mtime,
                            'protected_at': time.time(),
                        }
                except Exception as e:
                    logger.debug(f'建立基线失败 {filepath}: {e}')

            with self._stats_lock:
                self._stats['files_monitored'] = len(self._file_baselines)

        logger.info(f'已为 {len(self._file_baselines)} 个文件建立完整性基线')

    # ---- 内部工具 ----

    @staticmethod
    def _compute_file_hash(file_path: str) -> Optional[str]:
        """计算文件 SHA256 哈希"""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    def _add_event(self, event_type: str, file_path: str,
                   status: str, detail: str = ''):
        ev = {
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'type': event_type,
            'file_path': file_path,
            'status': status,
            'detail': detail,
        }
        with self._events_lock:
            self._recent_events.append(ev)
            if len(self._recent_events) > self._max_events:
                self._recent_events = self._recent_events[-self._max_events:]
        logger.info(f"[文件保护] {event_type} {file_path} [{status}] {detail}")

    def _report_threat(self, threat_data: dict):
        with self._stats_lock:
            self._stats['tampering_detected'] += 1
        self._add_event(
            threat_data.get('type', 'threat'),
            threat_data.get('path', ''),
            'threat',
            threat_data.get('detail', ''),
        )
        if self._on_threat:
            try:
                self._on_threat(threat_data)
            except Exception as e:
                logger.error(f'on_threat 回调异常: {e}')

    # ---- 启动/停止 ----

    def start(self) -> bool:
        if self._running:
            return True

        self._stop_event.clear()
        self._running = True

        # watchdog 监控将在 _monitor_loop 子线程中 _init_protected_files() 完成后启动
        # （_protected_dirs 在 _init_protected_files 中才填充，start() 时还是空列表）

        # 启动完整性检查线程（定期）
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name='FileProtection'
        )
        self._monitor_thread.start()

        with self._stats_lock:
            self._stats['started_at'] = time.time()

        self._add_event('system', '', 'info', '文件保护已启动')
        logger.info('文件保护已启动')
        return True

    def stop(self) -> bool:
        if not self._running:
            return True
        self._stop_event.set()
        self._running = False

        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=3)
            except Exception:
                pass
            self._observer = None
            self._handler = None

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=3)
        self._monitor_thread = None

        self._add_event('system', '', 'info', '文件保护已停止')
        logger.info('文件保护已停止')
        return True

    def _start_watchdog(self):
        """启动 watchdog 文件系统监控（在 _init_protected_files 完成后调用）"""
        if not HAS_WATCHDOG or not self._protected_dirs:
            logger.warning('watchdog 不可用或无受保护目录，跳过实时文件监控')
            return
        try:
            self._observer = Observer()
            self._handler = _ProtectedFileHandler(self)
            watched = 0
            for d in self._protected_dirs:
                if os.path.isdir(d):
                    self._observer.schedule(self._handler, d, recursive=True)
                    watched += 1
            if watched > 0:
                self._observer.start()
                logger.info(f'watchdog 已启动，监控 {watched} 个目录')
            else:
                self._observer = None
                logger.warning('无有效监控目录，watchdog 未启动')
        except Exception as e:
            logger.error(f'启动 watchdog 失败: {e}')
            self._observer = None

    # ---- 完整性检查 ----

    def _run_integrity_check(self):
        """对所有受保护文件执行完整性检查"""
        with self._baseline_lock:
            files_to_check = list(self._file_baselines.items())

        compromised: List[str] = []

        for filepath, baseline in files_to_check:
            try:
                if not os.path.exists(filepath):
                    # 文件被删除
                    with self._stats_lock:
                        self._stats['tampering_detected'] += 1
                    self._report_threat({
                        'type': 'file_deleted',
                        'path': filepath,
                        'detail': f'受保护文件被删除: {os.path.basename(filepath)}',
                    })
                    compromised.append(filepath)
                    continue

                current_hash = self._compute_file_hash(filepath)
                if current_hash and current_hash != baseline['hash']:
                    # 文件被篡改
                    with self._stats_lock:
                        self._stats['tampering_detected'] += 1
                    self._report_threat({
                        'type': 'file_tampered',
                        'path': filepath,
                        'detail': f'文件哈希已改变: {os.path.basename(filepath)}',
                        'old_hash': baseline['hash'],
                        'new_hash': current_hash,
                    })
                    compromised.append(filepath)

            except Exception as e:
                logger.debug(f'完整性检查失败 {filepath}: {e}')

        with self._stats_lock:
            self._stats['integrity_checks'] += 1

        return compromised

    def _monitor_loop(self):
        """主监控循环：定期检查完整性 + 批量修改检测"""
        INTEGRITY_CHECK_INTERVAL = 60  # 每 60 秒检查一次完整性
        RANSOMWARE_CHECK_INTERVAL = 5  # 每 5 秒检查批量修改

        # 启动延迟：等待 UI 完全初始化
        self._stop_event.wait(5)
        if self._stop_event.is_set():
            return

        # 在子线程中建立基线（首次），避免阻塞主线程
        if not self._baselines_built:
            self._init_protected_files()
            self._baselines_built = True
            # 基线建立完成后启动 watchdog 实时监控（此时 _protected_dirs 已填充）
            if self._running:
                self._start_watchdog()

        integrity_counter = 0

        while not self._stop_event.is_set():
            try:
                self._stop_event.wait(RANSOMWARE_CHECK_INTERVAL)
                if self._stop_event.is_set():
                    break

                integrity_counter += 1
                if integrity_counter >= INTEGRITY_CHECK_INTERVAL // RANSOMWARE_CHECK_INTERVAL:
                    integrity_counter = 0
                    self._run_integrity_check()

                # 清理过期的修改记录
                self._cleanup_old_modifications()

            except Exception as e:
                logger.error(f'文件监控循环异常: {e}')
                time.sleep(1)

    def _cleanup_old_modifications(self):
        """清理过期的修改记录（数量 / 大小 / 改名三个维度的窗口同步清理）"""
        now = time.time()
        with self._mod_lock:
            self._recent_modifications = [
                (t, p) for t, p in self._recent_modifications
                if now - t < MASS_MODIFY_TIME_WINDOW
            ]
            self._recent_size_changes = [
                (t, p) for t, p in self._recent_size_changes
                if now - t < MASS_MODIFY_TIME_WINDOW
            ]
            self._recent_renames = [
                (t, p) for t, p in self._recent_renames
                if now - t < MASS_MODIFY_TIME_WINDOW
            ]

    # ---- 文件事件处理 ----

    def _is_self_path(self, file_path: str) -> bool:
        """PSLS 自身目录 + 回滚仓库目录豁免判定（规范化前缀匹配）。

        自身安装目录子树、以及回滚仓库目录（快照/对象/影子落地处）均属 PSLS
        自身产出，不参与批量修改/勒索检测、不被隔离、不被归因，避免启动快照
        自干扰误报。判据用 os.path.normcase + 尾分隔符，跨大小写安全且不会把
        `...\\rollback2` 之类误判为仓库内。
        """
        try:
            p = os.path.normcase(os.path.abspath(file_path))
        except Exception:
            return False
        return p.startswith(self._self_root) or p.startswith(self._repo_root)

    def _is_whitelisted(self, file_path: str) -> bool:
        """文件是否命中白名单哈希（与进程启动链路同一 signature_db.is_whitelisted）。

        白名单按 SHA256 存储；导入白名单时目录下各文件均已计算哈希入库。
        文件监控/勒索检测链路上，命中白名单的文件不应被处置/隔离。
        """
        db = self._signature_db
        if db is None:
            return False
        try:
            _h = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    _h.update(chunk)
            return db.is_whitelisted(_h.hexdigest())
        except Exception:
            return False

    def _on_file_event(self, file_path: str, event_type: str):
        """处理文件系统事件"""
        path_lower = file_path.lower()

        # 自身安装目录 / 回滚仓库子树放行: PSLS 自己的写入不参与批量修改/勒索检测
        # （安装目录或仓库可能位于受监控的 Desktop/Documents 下）
        if self._is_self_path(path_lower):
            return

        # 检查是否是重要文件类型
        _, ext = os.path.splitext(path_lower)
        if ext not in IMPORTANT_EXTENSIONS and path_lower not in self._protected_files:
            # 非重要文件，仅做记录
            if event_type in ('modified', 'deleted'):
                self._track_modification(file_path)
            return

        # 跟踪修改（用于勒索软件检测）
        self._track_modification(file_path)

        # 白名单哈希放行：桌面/文档等受监控目录下，用户已加入白名单的文件
        # 不被处置（防止"导入白名单后文件监控仍误隔离"）
        if self._is_whitelisted(file_path):
            return

        if event_type == 'modified':
            # 大小变化维度：在数量维度之外，额外监测同一文件的显著大小突变
            # （清零 / 翻倍 / 腰斩），正常追加写入不会命中（见常量注释）。
            self._note_size_change(file_path)
            self._check_file_tampering(file_path)
        elif event_type == 'deleted':
            self._handle_file_deletion(file_path)

    def _track_modification(self, file_path: str):
        """记录文件修改用于批量检测（数量维度）"""
        now = time.time()
        with self._mod_lock:
            self._recent_modifications.append((now, file_path))
        # 融合判定放在锁外统一执行
        self._eval_and_dispatch(now)

    def _note_size_change(self, file_path: str):
        """大小变化维度：与上次观测大小比较，判定是否为显著突变。

        显著判据（避免对正常追加写入过敏）：
          - 变为 0 且原大小 > SIZE_ABS_MIN；
          - 原大小 >= SIZE_ABS_MIN 且增长到 >= SIZE_GROW_RATIO 倍；
          - 原大小 >= SIZE_ABS_MIN 且缩小到 <= SIZE_SHRINK_RATIO 倍。
        命中后记入窗口信号并触发融合判定。
        """
        try:
            new_size = os.path.getsize(file_path)
        except OSError:
            return
        now = time.time()
        hit = False
        with self._mod_lock:
            key = file_path.lower()
            old_size = self._last_sizes.get(key)
            self._last_sizes[key] = new_size
            if old_size is None or old_size == new_size:
                return
            if new_size == 0 and old_size > SIZE_ABS_MIN:
                hit = True
            elif old_size >= SIZE_ABS_MIN and new_size >= old_size * SIZE_GROW_RATIO:
                hit = True
            elif old_size >= SIZE_ABS_MIN and new_size <= old_size * SIZE_SHRINK_RATIO:
                hit = True
            if not hit:
                return
            self._recent_size_changes.append((now, file_path))
        self._add_event(
            'ransomware_size_change', file_path, 'threat',
            f'检测到文件大小显著变化: {old_size} -> {new_size} 字节')
        self._eval_and_dispatch(now)

    def _on_file_renamed(self, src_path: str, dest_path: str):
        """后缀名改变（改名）维度：识别勒索改名形态，记为强信号。

        强信号判据（改名后缀或"同前缀新后缀"）：
          - 目标后缀命中 RANSOMWARE_RENAME_EXTS（含 .locked/.enc 等）；或
          - 目标文件名与源文件同前缀（a.docx -> a.docx.locked / a.txt）。
        仅当源文件本身是受保护文档类型（或已在受保护文件集合）时才计强信号，
        避免把无关文件的普通改名误判为勒索。强信号次数阈值远低于数量阈值。
        """
        try:
            src_lower = src_path.lower()
            dest_lower = dest_path.lower()
        except Exception:
            return
        if self._is_self_path(src_lower) or self._is_self_path(dest_lower):
            return
        src_ext = os.path.splitext(src_lower)[1]
        dest_ext = os.path.splitext(dest_lower)[1]
        if src_ext == dest_ext:
            return
        src_name = os.path.basename(src_lower)
        dest_name = os.path.basename(dest_lower)
        src_stem = os.path.splitext(src_name)[0]
        dest_stem = os.path.splitext(dest_name)[0]
        # 同前缀：a.docx -> a.enc（stem 相等），或 a.docx -> a.docx.locked（stem 等于原名）
        same_prefix = (dest_stem == src_stem) or (dest_stem == src_name)
        dest_is_crypto = dest_ext in RANSOMWARE_RENAME_EXTS
        src_is_important = (src_ext in IMPORTANT_EXTENSIONS
                            or src_lower in self._protected_files)
        # 源文件不是受保护文档类型时，仅当目标后缀明确是加密后缀才计强信号
        if not src_is_important and not dest_is_crypto:
            return
        if not (dest_is_crypto or same_prefix):
            return
        now = time.time()
        with self._mod_lock:
            self._recent_renames.append((now, dest_path))
        self._add_event(
            'ransomware_rename', dest_path, 'threat',
            f'检测到文件改名（疑似勒索）: {src_name} -> {dest_name}')
        self._eval_and_dispatch(now)

    def _eval_and_dispatch(self, now: float):
        """融合三个维度的窗口信号并派发预警/确认（回调一律在锁外执行）。

        融合规则（不破坏既有数量阈值语义）：
          - 窗口信号总数 = 数量维度 + 大小变化维度；
          - 达到 MASS_MODIFY_THRESHOLD → 确认勒索；
          - 改名强信号达到 RENAME_CONFIRM_THRESHOLD → 确认勒索；
          - 否则达到 PREWARN_THRESHOLD（或改名达到 RENAME_PREWARN_THRESHOLD）
            → 低水位预警。
        """
        prewarn_files: Optional[List[str]] = None
        ransomware_files: Optional[List[str]] = None
        with self._mod_lock:
            recent_mods = [p for t, p in self._recent_modifications
                           if now - t < MASS_MODIFY_TIME_WINDOW]
            size_files = [p for t, p in self._recent_size_changes
                          if now - t < MASS_MODIFY_TIME_WINDOW]
            rename_files = [p for t, p in self._recent_renames
                            if now - t < MASS_MODIFY_TIME_WINDOW]
            total_files = recent_mods + size_files
            if len(total_files) >= MASS_MODIFY_THRESHOLD:
                ransomware_files = total_files
            elif len(rename_files) >= RENAME_CONFIRM_THRESHOLD:
                ransomware_files = rename_files
            elif len(total_files) >= PREWARN_THRESHOLD:
                prewarn_files = list(total_files)
            elif len(rename_files) >= RENAME_PREWARN_THRESHOLD:
                prewarn_files = list(rename_files)
        # 锁外回调：_detect_ransomware_pattern 会再次取 _mod_lock，持锁调用会自锁
        if ransomware_files is not None:
            self._detect_ransomware_pattern(ransomware_files)
        if prewarn_files is not None and self.on_prewarn is not None:
            try:
                self.on_prewarn(prewarn_files)
            except Exception as e:
                logger.debug(f'on_prewarn 回调异常: {e}')

    def _check_file_tampering(self, file_path: str):
        """检查单个文件是否被篡改"""
        path_lower = file_path.lower()
        with self._baseline_lock:
            baseline = self._file_baselines.get(path_lower)

        if not baseline:
            return

        try:
            if not os.path.isfile(file_path):
                return
            current_hash = self._compute_file_hash(file_path)
            if current_hash and current_hash != baseline['hash']:
                # 检测到篡改
                self._report_threat({
                    'type': 'file_tampered',
                    'path': file_path,
                    'detail': f'受保护文件被修改: {os.path.basename(file_path)}',
                })
                # 更新基线（防止重复报警）
                with self._baseline_lock:
                    self._file_baselines[path_lower]['hash'] = current_hash
                    self._file_baselines[path_lower]['mtime'] = os.stat(file_path).st_mtime
        except Exception:
            pass

    def _handle_file_deletion(self, file_path: str):
        """处理文件删除事件"""
        path_lower = file_path.lower()
        with self._baseline_lock:
            baseline = self._file_baselines.get(path_lower)

        if not baseline:
            return

        self._report_threat({
            'type': 'file_deleted',
            'path': file_path,
            'detail': f'受保护文件被删除: {os.path.basename(file_path)}',
        })

        # 尝试从备份恢复
        self._try_restore(file_path, baseline)

    def _try_restore(self, file_path: str, baseline: dict):
        """尝试从备份恢复文件"""
        backup_path = self._get_backup_path(file_path)
        if os.path.isfile(backup_path):
            try:
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                shutil.copy2(backup_path, file_path)
                self._add_event('restore', file_path, 'success',
                                '已从备份恢复文件')
                with self._stats_lock:
                    self._stats['files_restored'] += 1
                # 更新基线
                new_hash = self._compute_file_hash(file_path)
                with self._baseline_lock:
                    self._file_baselines[file_path.lower()] = {
                        'hash': new_hash or baseline['hash'],
                        'size': os.stat(file_path).st_size,
                        'mtime': os.stat(file_path).st_mtime,
                        'protected_at': time.time(),
                    }
            except Exception as e:
                logger.error(f'恢复文件失败 {file_path}: {e}')
                self._add_event('restore', file_path, 'error',
                                f'恢复失败: {e}')

    def _get_backup_path(self, file_path: str) -> str:
        """获取文件的备份路径"""
        safe_name = file_path.replace(':', '_').replace('\\', '_').replace('/', '_')
        return os.path.join(self._backup_dir, safe_name)

    def backup_file(self, file_path: str) -> bool:
        """手动备份指定文件"""
        try:
            if not os.path.isfile(file_path):
                return False
            backup_path = self._get_backup_path(file_path)
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            shutil.copy2(file_path, backup_path)
            self._add_event('backup', file_path, 'success',
                            f'已备份到 {self._backup_dir}')
            return True
        except Exception as e:
            logger.error(f'备份文件失败 {file_path}: {e}')
            return False

    # ---- 勒索软件检测 ----

    def _detect_ransomware_pattern(self, modified_files: List[str]):
        """检测勒索软件行为模式"""
        if not self._ransomware_guard:
            return

        sample_files = modified_files[:5]
        # ① 先上报（保持原样）
        self._report_threat({
            'type': 'ransomware_suspected',
            'path': sample_files[0] if sample_files else '',
            'detail': (
                f'检测到勒索软件行为特征！'
                f'短时间内 {len(modified_files)} 个文件被修改。'
                f'示例: {[os.path.basename(f) for f in sample_files]}'
            ),
        })

        with self._stats_lock:
            self._stats['ransomware_alerts'] += 1

        # 记录检测时刻：后台隔离时据此跳过"检测后又被回滚/改写"的文件
        cutoff = time.time()

        # ② 紧接着立刻回调上层发"是否回滚"询问（毫秒级信号转发）。
        # 询问绝不与"找进程/kill/隔离"串行，避免被 48s 的进程枚举拖到勒索
        # 进程结束都没发出。
        if self.on_ransomware_confirmed is not None:
            try:
                self.on_ransomware_confirmed({
                    'type': 'ransomware_suspected',
                    'files': list(modified_files),
                })
            except Exception as e:
                logger.error(f'on_ransomware_confirmed 回调异常: {e}')

        # 清空修改记录，避免重复报警风暴（检测已完成，立即清理）；
        # 大小/改名维度的窗口信号同步清空，避免同一批信号反复触发确认；
        # 同时去重：已有后台响应线程在跑时不再叠加，避免线程风暴。
        with self._mod_lock:
            self._recent_modifications.clear()
            self._recent_size_changes.clear()
            self._recent_renames.clear()
            if self._ransomware_responding:
                return
            self._ransomware_responding = True

        # ③ "找进程 + kill + 隔离受影响文件"整体移入独立 daemon 线程，
        # 不阻塞 watchdog 回调线程、不延迟上面的询问；kill 与询问并行（安全优先）。
        try:
            threading.Thread(
                target=self._handle_ransomware_response,
                args=(list(modified_files), cutoff),
                daemon=True, name='RansomwareResponse').start()
        except Exception as e:
            logger.error(f'启动勒索响应线程失败: {e}')
            with self._mod_lock:
                self._ransomware_responding = False

    def _handle_ransomware_response(self, modified_files: List[str], cutoff: float):
        """后台执行：找进程 → kill → 隔离受影响文件。

        安全优先：第一步就"找进程并 kill"；与前台询问并行、互不阻塞。
        隔离开关跳过 PSLS 自身/回滚仓库产出与白名单文件，并跳过检测后被
        回滚/改写（mtime 晚于 cutoff）的文件，避免误隔离已恢复的原文件。
        任何异常只记日志，绝不抛到 watchdog 线程。
        """
        try:
            # 1) 找进程并 kill
            if self._on_ransomware_kill:
                try:
                    killer_pid = self._find_modifying_process(modified_files)
                    if killer_pid:
                        logger.critical(
                            f'[勒索防护] 检测到进程 PID={killer_pid} 正在批量加密文件, 立即终止'
                        )
                        self._on_ransomware_kill(str(killer_pid))
                except Exception as e:
                    logger.error(f'勒索进程终止回调失败: {e}')

            # 2) 隔离受影响文件（跳过自身/仓库产出 + 白名单 + 已被回滚的文件）
            if self._quarantine_manager:
                for f in modified_files[:50]:  # 最多隔离 50 个
                    try:
                        if not os.path.isfile(f):
                            continue
                        if self._is_self_path(f) or self._is_whitelisted(f):
                            continue
                        try:
                            if os.stat(f).st_mtime > cutoff:
                                continue   # 检测后已被回滚/改写，勿重复处置
                        except OSError:
                            continue
                        result = self._quarantine_manager.quarantine_file(
                            f, reason='疑似勒索软件加密',
                            malware_name='Ransomware.Suspected'
                        )
                        if result is True:
                            with self._stats_lock:
                                self._stats['quarantined'] += 1
                        # duplicate / exempted 跳过计数（已在隔离区或已豁免）
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f'勒索响应后台任务异常: {e}')
        finally:
            with self._mod_lock:
                self._ransomware_responding = False

    def _on_ransomware_detected(self, file_path: str):
        """检测到加密后缀的文件"""
        # 自身安装目录 / 回滚仓库子树放行 — 该入口由 watchdog 的 on_created/on_moved
        # 直接调用, 绕过了 _on_file_event 的豁免, 必须在此单独拦截,
        # 否则自我保护备份/隔离区等自身产出若恰好带加密后缀,
        # 会触发 _on_ransomware_kill 误杀 PSLS 自身进程导致闪退。
        if self._is_self_path(file_path):
            return
        ext = os.path.splitext(file_path)[1].lower()
        self._report_threat({
            'type': 'ransomware_file',
            'path': file_path,
            'detail': f'检测到加密文件 ({ext})，可能是勒索软件加密',
        })
        with self._stats_lock:
            self._stats['ransomware_alerts'] += 1

        # [安全修复] 立即终止勒索进程
        if self._on_ransomware_kill:
            try:
                killer_pid = self._find_modifying_process([file_path])
                if killer_pid:
                    logger.critical(
                        f'[勒索防护] 检测到进程 PID={killer_pid} 正在创建加密文件, 立即终止'
                    )
                    self._on_ransomware_kill(str(killer_pid))
            except Exception as e:
                logger.error(f'勒索进程终止回调失败: {e}')

        # 立即隔离（跳过 PSLS 自身/回滚仓库产出 + 白名单文件）
        if (self._quarantine_manager and os.path.isfile(file_path)
                and not self._is_self_path(file_path)
                and not self._is_whitelisted(file_path)):
            try:
                result = self._quarantine_manager.quarantine_file(
                    file_path, reason='勒索软件加密文件',
                    malware_name='Ransomware.Encrypted'
                )
                if result is True:
                    with self._stats_lock:
                        self._stats['quarantined'] += 1
                # duplicate / exempted 跳过计数
            except Exception:
                pass

        # 确认勒索（已杀进程 + 隔离）后回调上层触发文件回滚（可选，默认 None）
        if self.on_ransomware_confirmed is not None:
            try:
                self.on_ransomware_confirmed({
                    'type': 'ransomware_file',
                    'files': [file_path],
                })
            except Exception as e:
                logger.error(f'on_ransomware_confirmed 回调异常: {e}')

    def _find_modifying_process(self, files: List[str]) -> Optional[int]:
        """查找正在修改指定文件的进程 PID

        策略: 遍历所有进程的 open_files(), 找到持有目标文件句柄的进程。
        若 open_files 失败(权限不足), 退化为查找 I/O 写入增量最大的进程。

        归因必须排除 PSLS 自身及其全部子孙/祖先进程：回滚快照会读取同一批
        受监控文件并持有句柄, 若把自身归因为勒索进程, 上层防自杀守卫会拒绝
        终止, 勒索进程永远杀不掉。排除后无候选则返回 None（交给上层兜底），
        绝不返回自身 PID。
        """
        try:
            import psutil
        except ImportError:
            return None

        self_pids = self._collect_self_related_pids(psutil)

        def _is_excluded(proc) -> bool:
            try:
                pid = proc.pid
            except Exception:
                return True
            if pid in self_pids or pid == os.getpid():
                return True
            name = ''
            try:
                info = getattr(proc, 'info', None)
                if info is not None:
                    name = info.get('name') or ''
                else:
                    name = proc.name()
            except Exception:
                name = ''
            return self._is_psls_proc_name(name)

        # 次级信号兜底：只对"最近被修改时间最接近的近 30 个文件"做句柄反查，
        # 排除自身/回滚仓库产出路径，降低自干扰归因概率。
        recent_files = [f for f in files if os.path.isfile(f)]
        try:
            recent_files = sorted(
                recent_files, key=lambda p: os.stat(p).st_mtime,
                reverse=True)[:30]
        except Exception:
            recent_files = list(files)
        target_set = set()
        for f in recent_files:
            try:
                ap = os.path.abspath(f).lower()
            except Exception:
                continue
            if ap.startswith(self._self_root) or ap.startswith(self._repo_root):
                continue
            target_set.add(ap)
        if not target_set:
            return None

        # 策略 1: 查找持有目标文件句柄的进程
        try:
            for proc in psutil.process_iter(attrs=['pid', 'name']):
                if _is_excluded(proc):
                    continue
                try:
                    for f in proc.open_files():
                        if f.path.lower() in target_set:
                            return proc.pid
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                except Exception:
                    continue
        except Exception:
            pass

        # 策略 2: 查找 I/O 写入增量最大的进程 (近 0.3 秒)
        try:
            io_snapshots = {}
            for proc in psutil.process_iter(attrs=['pid', 'name']):
                if _is_excluded(proc):
                    continue
                try:
                    io = proc.io_counters()
                    io_snapshots[proc.pid] = io.write_bytes
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

            time.sleep(0.3)

            max_delta = 0
            max_pid = 0
            for proc in psutil.process_iter(attrs=['pid', 'name']):
                if _is_excluded(proc):
                    continue
                try:
                    io = proc.io_counters()
                    prev = io_snapshots.get(proc.pid, 0)
                    delta = io.write_bytes - prev
                    if delta > max_delta:
                        max_delta = delta
                        max_pid = proc.pid
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

            # 只有写入量超过 1MB 且非自身相关进程才认为是可疑进程
            if (max_pid and max_pid != os.getpid() and max_pid not in self_pids
                    and max_delta > 1024 * 1024):
                return max_pid
        except Exception:
            pass

        # 无法定位：明确 warning（含被改文件示例），便于事后归因
        try:
            sample = [os.path.basename(f) for f in files[:3]]
        except Exception:
            sample = []
        logger.warning(
            f'[勒索防护] 未能定位批量修改文件的进程(已排除自身及相关进程), '
            f'受影响示例: {sample}')
        return None

    def _collect_self_related_pids(self, psutil_mod) -> set:
        """收集 PSLS 自身及其全部子孙/祖先进程 PID（沿 psutil 父链判断）。

        用于 _find_modifying_process 归因排除，确保绝不把自身/回滚快照相关
        进程当作勒索进程返回。
        """
        pids = {os.getpid()}
        try:
            me = psutil_mod.Process(os.getpid())
            for ch in me.children(recursive=True):
                try:
                    pids.add(ch.pid)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            p = psutil_mod.Process(os.getpid()).parent()
            while p is not None:
                pids.add(p.pid)
                try:
                    p = p.parent()
                except Exception:
                    break
        except Exception:
            pass
        return pids

    @staticmethod
    def _is_psls_proc_name(name: str) -> bool:
        """PSLS 相关进程名判定（子进程/服务名含 psls）。"""
        try:
            return 'psls' in (name or '').lower()
        except Exception:
            return False

    # ---- 公开 API ----

    def check_file_integrity(self, file_path: str) -> dict:
        """检查单个文件的完整性"""
        path_lower = file_path.lower()
        with self._baseline_lock:
            baseline = self._file_baselines.get(path_lower)

        result = {
            'path': file_path,
            'exists': os.path.isfile(file_path),
            'protected': path_lower in self._file_baselines,
            'status': 'unknown',
        }

        if not result['exists']:
            result['status'] = 'deleted'
            return result

        if not baseline:
            result['status'] = 'not_protected'
            return result

        current_hash = self._compute_file_hash(file_path)
        if current_hash:
            result['current_hash'] = current_hash
            result['baseline_hash'] = baseline['hash']
            result['tampered'] = current_hash != baseline['hash']
            result['status'] = 'tampered' if result['tampered'] else 'intact'
        else:
            result['status'] = 'hash_error'

        return result

    def get_all_integrity_status(self) -> List[dict]:
        """获取所有受保护文件的完整性状态"""
        results = []
        with self._baseline_lock:
            files = list(self._file_baselines.keys())
        for f in files:
            results.append(self.check_file_integrity(f))
        return results

    def restore_file(self, file_path: str) -> bool:
        """手动恢复指定文件"""
        path_lower = file_path.lower()
        with self._baseline_lock:
            baseline = self._file_baselines.get(path_lower)
        if baseline:
            self._try_restore(file_path, baseline)
            return True
        return False

    def add_protected_file(self, file_path: str) -> bool:
        """添加受保护文件（手动）"""
        file_path = os.path.abspath(file_path)
        if not os.path.isfile(file_path):
            return False
        path_lower = file_path.lower()
        if path_lower in self._file_baselines:
            return True

        file_hash = self._compute_file_hash(file_path)
        stat = os.stat(file_path)
        with self._baseline_lock:
            self._file_baselines[path_lower] = {
                'hash': file_hash,
                'size': stat.st_size,
                'mtime': stat.st_mtime,
                'protected_at': time.time(),
            }
            with self._stats_lock:
                self._stats['files_monitored'] = len(self._file_baselines)

        self._add_event('protect', file_path, 'success',
                        '已添加到文件保护')
        # 同时创建备份
        self.backup_file(file_path)
        return True

    def remove_protected_file(self, file_path: str):
        """移除受保护文件"""
        path_lower = os.path.abspath(file_path).lower()
        with self._baseline_lock:
            if path_lower in self._file_baselines:
                del self._file_baselines[path_lower]
                with self._stats_lock:
                    self._stats['files_monitored'] = len(self._file_baselines)
                self._add_event('protect', file_path, 'info',
                                '已从文件保护中移除')
