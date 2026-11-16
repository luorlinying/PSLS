import json
import os
import sys
import time
import hashlib
import sqlite3
import threading
from datetime import datetime
from typing import Dict, Set, Optional, List
from utils.logger import get_logger

logger = get_logger('signature_db')


def _db_backup_paths() -> List[str]:
    """签名库备份候选路径（**PSLS 自身目录**，绝不放桌面/用户目录）。

    打包模式: {exe 所在目录}\\db_backup\\signatures.db（安装器随包分发）
    开发模式: <项目根>\\db_backup\\signatures.db
    """
    cands: List[str] = []
    try:
        if getattr(sys, 'frozen', False):
            base = os.path.dirname(os.path.abspath(sys.executable))
        else:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cands.append(os.path.join(base, 'db_backup', 'signatures.db'))
    except Exception:
        pass
    return cands


# 备份完整性阈值：签名库约 100MB 级，小于 1MB 视为"不是有效签名库"
_DB_MIN_BYTES = 1 * 1024 * 1024


def _db_integrity_ok(path: str) -> bool:
    """签名库完整性校验：存在 + 大小 > 阈值 + sqlite3 可打开 + integrity_check 通过。

    口径选择理由：`PRAGMA integrity_check`（而非 quick_check）能发现索引/页损坏，
    对只读校验而言成本可接受（本机 106MB 库 <1s）；同时要求能读到表，避免"空库/
    新库"被误判为可用（会导致漏检）。
    """
    if not path or not os.path.isfile(path):
        return False
    try:
        if os.path.getsize(path) < _DB_MIN_BYTES:
            return False
    except OSError:
        return False
    conn = None
    try:
        import sqlite3
        conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=3)
        cur = conn.cursor()
        cur.execute('PRAGMA integrity_check')
        row = cur.fetchone()
        if not row or str(row[0]).lower() != 'ok':
            return False
        # 必须存在签名表（空库/错误库不算可用）
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name='malware_signatures'")
        if cur.fetchone() is None:
            return False
        return True
    except Exception:
        return False
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


def _resolve_working_db_path(primary: str) -> tuple:
    """确定实际可用的签名库路径：主库 → 备份 → 都不可用（安全降级）。

    返回 `(path, source)`，source ∈ 'primary' | 'backup' | 'none'。
    仅当主库不可用且备份可用时才把备份**复制回主路径**（一次性恢复，避免每次
    重启都从只读目录读；不会额外常驻占用空间）。日志明确标出来源。
    """
    if _db_integrity_ok(primary):
        logger.info(f'signature_db: source=primary ({primary})')
        return primary, 'primary'
    backup = ''
    for cand in _db_backup_paths():
        if _db_integrity_ok(cand):
            backup = cand
            break
    if not backup:
        logger.error(f'signature_db: source=none（主库与备份均不可用）'
                     f' primary={primary} 备份候选={_db_backup_paths()}')
        return primary, 'none'
    # 恢复：备份 → 主路径（主路径可写；失败则直接使用备份路径）
    try:
        os.makedirs(os.path.dirname(primary), exist_ok=True)
        import shutil as _sh
        _sh.copy2(backup, primary)
        logger.warning(f'signature_db: source=backup ({backup}) → 已恢复到主路径')
        return primary, 'backup'
    except Exception as e:
        logger.warning(f'signature_db: source=backup ({backup})（恢复复制失败: {e}，'
                       f'直接使用备份路径）')
        return backup, 'backup'


def _get_default_db_path() -> str:
    """获取默认数据库路径

    打包模式（PyInstaller）下 __file__ 指向只读临时目录 _MEIxxxxx，
    SQLite 无法在该目录创建数据库文件（需要写权限创建 -journal/-wal 文件）。
    因此打包模式下使用 %APPDATA%\\PSLS\\signatures.db 持久化路径。

    首次运行时若用户目录无签名库，则从打包内置资源（_MEIPASS/db/signatures.db）
    复制一份到用户目录，实现开箱即用，无需用户手动导入病毒库。
    
    支持多路径回退搜索，确保即使 PyInstaller 改变文件位置也能找到内置签名库。
    """
    if getattr(sys, 'frozen', False):
        # 打包模式：使用 %APPDATA%\PSLS\signatures.db
        if sys.platform == 'win32':
            appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
        else:
            appdata = os.path.expanduser('~/.config')
        psls_dir = os.path.join(appdata, 'PSLS')
        if not os.path.exists(psls_dir):
            try:
                os.makedirs(psls_dir, exist_ok=True)
            except OSError:
                pass
        user_db = os.path.join(psls_dir, 'signatures.db')

        # 查找内置签名库（尝试多个可能的路径）
        bundled_db = _find_bundled_db()
        
        if bundled_db and os.path.exists(bundled_db):
            bundled_size = os.path.getsize(bundled_db)
            user_size = os.path.getsize(user_db) if os.path.exists(user_db) else 0
            
            need_copy = _should_copy_bundled_db(bundled_size, user_size, bundled_db, user_db)
            
            if need_copy:
                _copy_bundled_db(bundled_db, user_db, bundled_size)
        
        return user_db
    # 开发模式：使用项目目录下的 db/signatures.db
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'signatures.db')


def _find_bundled_db() -> Optional[str]:
    """在打包产物中查找内置签名库文件

    搜索多个可能的路径，适应不同 PyInstaller 打包配置：
    1. sys._MEIPASS/db/signatures.db （标准 onedir 路径）
    2. sys._MEIPASS/signatures.db （根目录）
    3. sys._MEIPASS/_internal/db/signatures.db （嵌套 _internal 情况）
    4. EXE 同级目录/db/signatures.db （onedir 根目录）
    5. EXE 同级目录/signatures.db （根目录）
    6. %APPDATA%/PSLS/signatures.db （已复制到用户目录）
    7. 项目根目录/db/signatures.db （开发模式回退）
    """
    candidates = []

    if getattr(sys, 'frozen', False):
        meipass = sys._MEIPASS
        exe_dir = os.path.dirname(sys.executable)

        # 标准 onedir 路径（子目录）
        candidates.append(os.path.join(meipass, 'db', 'signatures.db'))

        # 根目录副本（spec datas 可能放在根）
        candidates.append(os.path.join(meipass, 'signatures.db'))

        # EXE 同级目录（onedir 模式下 EXE 在 _MEIPASS 上级目录）
        candidates.append(os.path.join(exe_dir, 'db', 'signatures.db'))
        candidates.append(os.path.join(exe_dir, 'signatures.db'))

        # _internal 嵌套情况（双重保险）
        internal_dir = os.path.join(exe_dir, '_internal')
        if internal_dir != meipass:
            candidates.append(os.path.join(internal_dir, 'db', 'signatures.db'))
            candidates.append(os.path.join(internal_dir, 'signatures.db'))

        # 用户数据目录（首次运行已复制的位置）
        try:
            appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
            candidates.append(os.path.join(appdata, 'PSLS', 'signatures.db'))
        except Exception:
            pass

    # 开发模式回退路径
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'signatures.db'))

    # 去重并搜索
    seen = set()
    for path in candidates:
        norm_path = os.path.normpath(path)
        if norm_path in seen:
            continue
        seen.add(norm_path)

        if os.path.exists(path) and os.path.getsize(path) > 0:
            size = os.path.getsize(path)
            logger.info(f'找到内置签名库: {path} ({size:,} bytes)')
            return path

    logger.warning(f'未找到内置签名库，搜索路径: {list(seen)}')
    return None


def _is_db_valid(db_path: str) -> bool:
    """验证 SQLite 数据库是否完整且可读取。

    通过执行 PRAGMA integrity_check 判断数据库是否损坏，
    防止因异常退出导致的 'database disk image is malformed' 错误。
    """
    if not os.path.exists(db_path) or os.path.getsize(db_path) == 0:
        return False

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # 轻量级完整性检查
        cursor.execute("PRAGMA integrity_check")
        result = cursor.fetchone()
        if result and result[0] == 'ok':
            # 再验证核心表是否存在（实际表名是 malware_signatures；兼容旧命名）
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name IN ('malware_signatures', 'signatures', 'metadata')"
            )
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()
            return len(tables) >= 1
        else:
            conn.close()
            logger.warning(f'数据库完整性检查失败: {db_path} -> {result}')
            return False
    except sqlite3.DatabaseError as e:
        logger.warning(f'数据库已损坏: {db_path} -> {e}')
        try:
            conn.close()
        except Exception:
            pass
        return False
    except Exception as e:
        logger.warning(f'数据库验证异常: {db_path} -> {e}')
        return False


def _should_copy_bundled_db(bundled_size: int, user_size: int,
                            bundled_path: str, user_path: str) -> bool:
    """判断是否需要从内置资源复制签名库

    复制条件（满足任一）：
    0. 用户库已损坏（完整性检查失败）
    1. 用户库不存在或为空
    2. 用户库小于内置库的 50%（旧版空库或严重缩水）
    3. 内置库文件修改时间晚于用户库（版本更新）
    4. 内置库签名条数多于用户库（打包新增签名的版本升级）
       —— 修复用户库因运行期写 whitelist 导致 mtime 恒新、
       且新旧库文件大小相近（如 48070 vs 40000 条）时不触发
       条件 2/3 而拒绝更新的问题。按真实签名条数比较最可靠。
    """
    if bundled_size == 0:
        return False

    # 条件 0: 用户库已损坏（最关键的恢复逻辑）
    if user_size > 0 and not _is_db_valid(user_path):
        logger.warning(f'用户签名库已损坏，将从内置资源恢复: {user_path}')
        return True

    # 条件 1: 用户库不存在或为空
    if user_size == 0:
        logger.info('用户签名库不存在或为空，需要从内置资源复制')
        return True

    # 条件 4: 内置库签名条数多于用户库 → 版本升级，必须复制
    # （放在大小/时间判断之前，优先以条数为准）
    try:
        bundled_count = _count_malware_signatures(bundled_path)
        user_count = _count_malware_signatures(user_path)
        if bundled_count is not None and user_count is not None:
            if bundled_count > user_count:
                logger.info(
                    f'内置库包含更多签名 ({bundled_count} > {user_count})，'
                    f'将覆盖更新用户库')
                return True
            # 用户库条数 >= 内置库：用户可能导入过额外签名，保留用户库
            if bundled_count < user_count:
                logger.info(
                    f'用户库签名条数 ({user_count}) 多于内置库 ({bundled_count})，'
                    f'保留用户库（不覆盖用户导入的签名）')
                return False
    except Exception as e:
        logger.debug(f'签名条数比较失败，回退到大小/时间判断: {e}')

    # 条件 2: 用户库严重缩水（小于内置 50%）
    if user_size < bundled_size * 0.5:
        logger.info(f'用户签名库 ({user_size} bytes) 明显小于内置库 ({bundled_size} bytes)，将覆盖更新')
        return True

    # 条件 3: 内置库比用户库更新（通过修改时间判断）
    try:
        bundled_mtime = os.path.getmtime(bundled_path)
        user_mtime = os.path.getmtime(user_path)
        if bundled_mtime > user_mtime:
            logger.info(f'内置签名库更新时间晚于用户库，将复制更新')
            return True
    except OSError:
        pass

    return False


def _count_malware_signatures(db_path: str) -> Optional[int]:
    """统计数据库中恶意软件签名的条数（无法读取时返回 None）"""
    try:
        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM malware_signatures')
            return int(cursor.fetchone()[0])
        finally:
            conn.close()
    except Exception as e:
        logger.debug(f'统计签名条数失败 {db_path}: {e}')
        return None


def _copy_bundled_db(bundled_db: str, user_db: str, bundled_size: int):
    """安全地从内置资源复制签名库到用户目录

    使用原子性操作：先复制到临时文件，再重命名替换，避免复制过程中崩溃导致文件损坏。
    复制前进行磁盘剩余空间预检，替换前清理旧库的 WAL/SHM 残留。
    """
    try:
        import shutil

        # 磁盘剩余空间预检：目标分区需 >= 库大小 x 1.5（临时副本 + 本体 + WAL 增长）
        user_dir = os.path.dirname(user_db) or '.'
        try:
            free_bytes = shutil.disk_usage(user_dir).free
            required = int(bundled_size * 1.5)
            if free_bytes < required:
                logger.warning(
                    f'磁盘剩余空间不足 ({free_bytes:,} < {required:,} bytes)，'
                    f'跳过签名库复制，保留现有库: {user_db}')
                return
        except Exception:
            pass  # 空间查询失败不阻塞复制（后续写入失败仍有兜底）

        tmp_db = user_db + '.tmp'
        shutil.copy2(bundled_db, tmp_db)

        # 验证临时文件
        if not os.path.exists(tmp_db) or os.path.getsize(tmp_db) < bundled_size * 0.5:
            raise IOError(f'复制后文件大小异常: {os.path.getsize(tmp_db) if os.path.exists(tmp_db) else 0} vs {bundled_size}')

        # 替换前清理旧库的 WAL/SHM 残留（避免新主库配旧 WAL 导致 disk I/O error）
        for suffix in ('-wal', '-shm'):
            stale = user_db + suffix
            if os.path.exists(stale):
                try:
                    os.remove(stale)
                    logger.info(f'已清理旧库残留文件: {stale}')
                except OSError as e:
                    logger.warning(f'清理 {stale} 失败（可能被占用）: {e}')

        # 原子替换
        if os.path.exists(user_db):
            # 若目标正被占用（如主程序运行中已打开该库连接），覆盖会失败。
            # 这种情况下宁可保留现有库、下次启动再更新，也不允许复制抛错
            # 打断主程序，更不允许把运行中的库文件破坏。用独占打开探测占用。
            try:
                _probe = open(user_db, 'r+b')
                _probe.close()
            except OSError:
                logger.warning(
                    f'目标签名库正被占用，跳过本次覆盖更新（下次启动将应用）: {user_db}')
                try:
                    os.remove(tmp_db)
                except Exception:
                    pass
                return False
            os.remove(user_db)
        os.rename(tmp_db, user_db)

        final_size = os.path.getsize(user_db)
        logger.info(f'已从内置资源复制签名库到: {user_db} ({bundled_size} -> {final_size} bytes)')
        return True
    except Exception as e:
        logger.warning(f'复制内置签名库失败（将尝试保留现有库）: {e}')
        try:
            tmp_db = user_db + '.tmp'
            if os.path.exists(tmp_db):
                os.remove(tmp_db)
        except Exception:
            pass


def _resolve_export_path(export_path: str) -> str:
    """解析导出路径，确保为绝对路径且位于可写目录。

    若传入仅为文件名（无目录部分），则解析到用户桌面目录，
    避免在打包模式下工作目录不可写导致 sqlite 报
    'unable to open database file' 错误。
    """
    if not export_path:
        return export_path
    # 已是绝对路径直接返回
    if os.path.isabs(export_path):
        return export_path
    # 相对路径：解析到桌面目录
    try:
        if sys.platform == 'win32':
            home = os.environ.get('USERPROFILE', os.path.expanduser('~'))
        else:
            home = os.path.expanduser('~')
        desktop = os.path.join(home, 'Desktop')
        if not os.path.exists(desktop):
            desktop = home
        return os.path.join(desktop, export_path)
    except Exception:
        return os.path.abspath(export_path)

class SignatureDB:
    """
    签名数据库管理类
    支持SHA256哈希签名和启发式规则的存储与查询
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = _get_default_db_path()
        # 需求 3：主库不可用（缺失/损坏/大小异常）→ 自动回退 PSLS 自身目录下的备份；
        # 两者都坏 → 安全降级（db_source='none'，不崩、不把一切判为干净）。
        db_path, self.db_source = _resolve_working_db_path(db_path)
        self.db_unavailable = (self.db_source == 'none')
        if self.db_source == 'backup':
            try:
                logger.warning('签名库已回退到 PSLS 目录内的备份副本（source=backup）')
            except Exception:
                pass
        self.db_path = db_path
        self._conn = None
        self._malware_hashes: Set[str] = set()
        self._malware_info: Dict[str, Dict] = {}
        self._heuristic_rules: List[Dict] = []
        self._whitelist_cache: Set[str] = set()  # 白名单内存缓存
        # 沙箱放行信任内存缓存（独立于白名单；仅进程启动判定跳过沙箱使用）
        self._sandbox_trust_cache: Set[str] = set()
        self._lock = threading.RLock()  # 线程锁
        # 白名单批量写入缓冲：扫描时 add_to_whitelist 只更新内存，
        # 累积到此列表，由扫描流程在合适时机调用 flush_whitelist_batch 批量持久化
        # 避免扫描每个 clean 文件都触发 fsync 严重拖慢扫描速度
        self._whitelist_pending: List[tuple] = []  # [(hash, reason), ...]
        self._whitelist_flush_threshold = 200  # 累积 200 条自动 flush
        # ---- 异步缓存装载状态（加速启动：缓存装载转到后台线程）----
        # _cache_evt: 缓存装载完成后置位；_cache_mutex: 保护内存缓存并发读写
        self._cache_evt = threading.Event()
        self._cache_mutex = threading.RLock()
        self._cache_load_thread: Optional[threading.Thread] = None

        # ---- 降载控制：压缩包启发式扫描递归深度 ----
        # 默认 3 层嵌套 (zip in zip)；高负载时降为 1 层，
        # 避免深度解压带来的 CPU/内存抖动 (尤其 VM 环境解压缩炸弹风险最大)
        self._archive_scan_depth: int = 3
        # 单文件扫描尺寸阈值（配合 load_governor lower_signature_scan_depth）
        self._scan_max_bytes: int = 512 * 1024 * 1024  # 512MB
        self._init_db()

    # ---- 降载控制：压缩包递归深度 / 单文件扫描尺寸上限 ----
    def set_scan_depth(self, depth: int) -> None:
        """动态设置压缩包启发式扫描递归深度（load_governor 调用）。

        Args:
            depth: 嵌套深度 (1..8)。非法值按 1 兜底，避免设为 0 跳过所有压缩包
                   或过大 (>=9) 造成解压缩炸弹/内存爆炸。
        """
        try:
            d = int(depth)
        except (TypeError, ValueError):
            d = 1
        if d < 1:
            d = 1
        if d > 8:
            d = 8
        if self._archive_scan_depth != d:
            self._archive_scan_depth = d
            logger.info(f'[降载] 压缩包扫描深度调整为 {d}')

    def set_scan_max_bytes(self, size_bytes: int) -> None:
        """动态设置单文件扫描尺寸上限（字节）。兜底：1MB..4GB。"""
        MIN = 1 * 1024 * 1024
        MAX = 4 * 1024 * 1024 * 1024
        try:
            s = int(size_bytes)
        except (TypeError, ValueError):
            s = MIN
        if s < MIN:
            s = MIN
        if s > MAX:
            s = MAX
        if self._scan_max_bytes != s:
            self._scan_max_bytes = s
            logger.info(f'[降载] 单文件扫描上限调整为 {s // (1024 * 1024)}MB')

    @staticmethod
    def _to_str(val) -> str:
        """将数据库字段值安全转为 JSON 可序列化的字符串。

        SQLite 在某些情况下会返回 bytes（如 BLOB 字段或非 UTF-8 内容），
        json.dumps 无法序列化 bytes，统一在此兜底转换。
        """
        if val is None:
            return ''
        if isinstance(val, bytes):
            try:
                return val.decode('utf-8')
            except UnicodeDecodeError:
                return val.decode('latin-1')
        if isinstance(val, (int, float, bool)):
            return val
        return str(val)
    
    def _cleanup_stale_db_files(self):
        """清理残留的 SQLite WAL/SHM 文件

        残留/损坏的 -wal/-shm 是 'disk I/O error' 的常见根因
        （如上次运行异常退出、或主库被替换后旧 WAL 未清理）。
        仅在连接失败的重试路径上调用，正常路径绝不触碰。
        """
        for suffix in ('-wal', '-shm'):
            p = self.db_path + suffix
            try:
                if os.path.exists(p):
                    os.remove(p)
                    logger.warning(f'已清理残留数据库文件: {p}')
            except OSError as e:
                logger.debug(f'清理 {p} 失败（可能被其他进程占用）: {e}')

    def _self_heal_rebuild(self) -> bool:
        """终极自愈：签名库连续打不开时，用内置/参考库重建当前库。

        覆盖根因：主库只读、损坏、旧 WAL 冲突等 —— 通过"拷贝到同盘临时
        文件 → 原库改名备份 → 临时文件改名为正式库"三步替换，即使内置库
        与当前库同路径（开发模式）也能安全重建。任一步被其他实例占用失败
        时自动回滚，绝不把库置于半替换状态。
        """
        src = _find_bundled_db()
        if not src or not os.path.isfile(src):
            return False
        db_dir = os.path.dirname(self.db_path)
        if not db_dir or not os.path.isdir(db_dir):
            return False
        import shutil
        tmp = self.db_path + f'.heal_{int(time.time())}'
        bak = self.db_path + f'.corrupt_{int(time.time())}'
        moved_main = False
        try:
            # 1) 内置/参考库 → 同盘临时文件（保证后续 rename 原子）
            shutil.copy2(src, tmp)
            # 2) 异常主库 → 备份改名（被占用则失败，直接放弃不冒险）
            os.replace(self.db_path, bak)
            moved_main = True
            for s in ('-wal', '-shm'):
                p = self.db_path + s
                if os.path.exists(p):
                    try:
                        os.replace(p, bak + s)
                    except OSError:
                        pass
            # 3) 临时文件 → 正式路径
            os.replace(tmp, self.db_path)
            logger.warning(f'签名库已自愈重建: {self.db_path} (来源: {src})')
            return True
        except Exception as e:
            # 任一步失败：回滚，恢复原始库，绝不让 DB 处于半替换状态
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
                if moved_main and not os.path.exists(self.db_path) \
                        and os.path.exists(bak):
                    os.replace(bak, self.db_path)
            except Exception:
                pass
            logger.warning(f'签名库自愈重建失败（可能被其他实例占用）: {e}')
            return False

    def _open_connection_with_retry(self) -> sqlite3.Connection:
        """打开数据库连接，瞬时故障指数退避重试 + 终极自愈。

        首启复制大签名库后 / 旧实例未退出 / 杀软短时锁定时，SQLite 可能抛出
        'disk I/O error' / 'database is locked'。重试策略：
          第 1 次失败 -> 直接重试（瞬时锁竞争通常自愈）
          第 2 次失败 -> 清理残留 -wal/-shm 后重试
          第 3 次失败 -> 用内置/参考库终极自愈重建后重试一次
          仍失败 -> 抛出带路径的详细异常（由上层调度延迟重建）
        连接建立后执行一次真实查询确认 I/O 通路可用。
        """
        last_err: Optional[Exception] = None
        for attempt in range(1, 4):
            conn = None
            try:
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute('PRAGMA journal_mode=WAL')
                cursor.execute('PRAGMA synchronous=NORMAL')
                cursor.execute('PRAGMA cache_size=-8192')  # 8MB 缓存
                # 触发一次真实磁盘 I/O，确保连接真正可用
                cursor.execute('SELECT count(*) FROM sqlite_master').fetchone()
                return conn
            except sqlite3.Error as e:
                last_err = e
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
                logger.warning(f'打开签名库失败 (第 {attempt}/3 次): {e}')
                if attempt == 2:
                    self._cleanup_stale_db_files()
                time.sleep(0.3 * attempt)

        # 3 次常规重试均失败 → 终极自愈：用内置/参考库重建后重试一次
        try:
            if self._self_heal_rebuild():
                conn = None
                try:
                    conn = sqlite3.connect(self.db_path, check_same_thread=False)
                    cursor = conn.cursor()
                    cursor.execute('PRAGMA journal_mode=WAL')
                    cursor.execute('PRAGMA synchronous=NORMAL')
                    cursor.execute('PRAGMA cache_size=-8192')
                    cursor.execute('SELECT count(*) FROM malware_signatures').fetchone()
                    return conn
                except sqlite3.Error as e:
                    last_err = e
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass
                    logger.warning(f'签名库自愈重建后仍失败: {e}')
        except Exception as e:
            logger.warning(f'签名库自愈重建异常: {e}')

        raise RuntimeError(
            f'签名库 disk I/O error（可能只读/损坏/被占用）: {self.db_path}'
            f' | 原始错误: {last_err}')

    def _init_db(self):
        """初始化SQLite数据库"""
        # 确保数据库目录存在（打包模式下路径可能尚未创建）
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
            except OSError as e:
                logger.warning(f'创建数据库目录失败 {db_dir}: {e}')

        self._conn = self._open_connection_with_retry()
        cursor = self._conn.cursor()

        # 创建恶意软件签名表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_signatures (
                hash_sha256 TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT DEFAULT 'high',
                description TEXT,
                source TEXT,
                added_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 创建启发式规则表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS heuristic_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                threshold INTEGER DEFAULT 1,
                severity TEXT DEFAULT 'medium',
                description TEXT
            )
        ''')

        # 创建白名单表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                hash_sha256 TEXT PRIMARY KEY,
                reason TEXT,
                added_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # ---- 沙箱放行信任表（独立于 whitelist，仅供进程启动判定跳过沙箱）----
        # 语义：沙箱判定某程序安全后，仅"进沙箱"这一环节被跳过；文件防篡改、
        # 实时扫描、引擎扫描等其他模块仍照常监测（不受该表影响）。
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sandbox_trust (
                hash_sha256 TEXT PRIMARY KEY,
                reason TEXT,
                added_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 创建索引（IF NOT EXISTS 确保幂等）
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_malware_name ON malware_signatures(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_malware_added_date ON malware_signatures(added_date)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_malware_type ON malware_signatures(type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_heuristic_name ON heuristic_rules(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_heuristic_rule_type ON heuristic_rules(rule_type)')

        # ---- Schema 升级: malware_signatures 增加模糊哈希/样本路径/YARA 规则引用字段 ----
        self._ensure_column(cursor, 'malware_signatures', 'fuzzy_hash', 'TEXT')
        self._ensure_column(cursor, 'malware_signatures', 'sample_path', 'TEXT')
        self._ensure_column(cursor, 'malware_signatures', 'yara_rule_id', 'INTEGER')
        self._ensure_column(cursor, 'malware_signatures', 'last_yara_gen', 'TEXT')

        # ---- 自动生成 YARA 规则表 ----
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auto_yara_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL UNIQUE,
                hash_sha256 TEXT,
                rule_content TEXT NOT NULL,
                rule_source TEXT DEFAULT 'auto',
                signature_id TEXT,
                severity TEXT DEFAULT 'high',
                feature_count INTEGER DEFAULT 0,
                file_size INTEGER DEFAULT 0,
                sample_type TEXT DEFAULT 'unknown',
                is_active INTEGER DEFAULT 1,
                created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                last_match_date TEXT,
                match_count INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_yara_rule_name ON auto_yara_rules(rule_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_yara_hash ON auto_yara_rules(hash_sha256)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_yara_active ON auto_yara_rules(is_active)')

        self._conn.commit()
        self._ensure_builtin_signatures()
        self._ensure_builtin_heuristic_rules()
        # 缓存装载改为后台线程执行：96MB 签名库装载约 1~3s，若同步阻塞在此
        # 会拖慢 PSLS 启动关键路径。通过 _cache_evt 通知装载完成，读缓存的方法
        # 在完成前会短暂等待（毫秒级~亚秒级），后续扫描不受影响。
        self._start_async_cache_load()

    @staticmethod
    def _ensure_column(cursor, table: str, col: str, col_type: str):
        """幂等添加列：先 PRAGMA table_info 检查是否已存在，不存在则 ALTER TABLE ADD COLUMN。"""
        try:
            cursor.execute(f'PRAGMA table_info({table})')
            existing = {row[1] for row in cursor.fetchall()}
            if col not in existing:
                cursor.execute(f'ALTER TABLE {table} ADD COLUMN {col} {col_type}')
                logger.info(f'Schema 升级: {table} 新增列 {col} ({col_type})')
        except Exception as e:
            logger.warning(f'Schema 升级 {table}.{col} 失败（可忽略）: {e}')
    
    def _ensure_builtin_signatures(self):
        """确保内置签名存在（EICAR 等标准测试签名）

        每次启动时检查并补充，确保即使数据库为空也能检测标准测试文件。
        """
        # EICAR 标准测试文件（行业通用杀毒验证）
        eicar_content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        eicar_sha256 = hashlib.sha256(eicar_content).hexdigest()

        builtins = [
            (eicar_sha256, 'EICAR-Test-File', 'test', 'high',
             'EICAR标准杀毒软件测试文件', 'builtin'),
        ]

        cursor = self._conn.cursor()
        for sha256, name, mtype, severity, desc, source in builtins:
            cursor.execute(
                'SELECT 1 FROM malware_signatures WHERE hash_sha256 = ?',
                (sha256,)
            )
            if cursor.fetchone() is None:
                cursor.execute('''
                    INSERT OR REPLACE INTO malware_signatures
                    (hash_sha256, name, type, severity, description, source)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (sha256, name, mtype, severity, desc, source))
        self._conn.commit()
    
    def _ensure_builtin_heuristic_rules(self):
        """确保内置启发式规则存在

        每次启动时检查并补充，覆盖常见恶意软件特征：
        - 多重后缀名伪装
        - 可疑文件名关键词
        - 危险脚本扩展名
        - 随机命名可执行文件
        - 勒索软件加密后缀
        - 伪装系统进程
        - UAC绕过关键词
        - 文档图标欺骗
        """
        builtin_rules = [
            # ---- 多重后缀名伪装 ----
            (
                'Suspicious.DoubleExtension',
                'filename',
                r'(?i)\.(exe|dll|scr|pif|com|bat|cmd|vbs|ps1|js)(\.(txt|doc|docx|xls|xlsx|pdf|jpg|jpeg|png|gif|bmp|webp|zip|rar|7z|pptx))+\s*$',
                1,
                'high',
                '多重后缀名伪装（如 malware.exe.txt、malware.pdf.exe.jpg）'
            ),
            # ---- 文档图标欺骗 ----
            (
                'Suspicious.DocumentSpoof',
                'filename',
                r'(?i)\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf)\.(exe|scr|com|bat|cmd|vbs|js|pif)\s*$',
                1,
                'high',
                '伪装为文档的可执行文件（如 report.pdf.exe）'
            ),
            # ---- 勒索软件加密后缀 ----
            (
                'Suspicious.RansomExtension',
                'extension',
                r'(?i)\.(locked|encrypted|crypt|cry|locky|cerber|zepto|wncry|lockd|crysis|dharma|phobos|ryuk|maze|conti|lockbit|blackcat|alphv|hive|blackbasta)\s*$',
                1,
                'high',
                '已知勒索软件加密文件后缀'
            ),
            # ---- 伪装系统进程名 ----
            (
                'Suspicious.SystemProcessSpoof',
                'filename',
                r'(?i)^(svchost|csrss|lsass|smss|wininit|winlogon|services|spoolsv|dwm|conhost|taskhostw?|runtimebroker|searchindexer|sihost|shellexperiencehost)\.(exe|dll)\s*$',
                1,
                'medium',
                '文件名伪装为系统关键进程（真品在System32中）'
            ),
            # ---- UAC绕过关键词 ----
            (
                'Suspicious.UACBypass',
                'filename',
                r'(?i)(uac.bypass|fodhelper|eventvwr|sdclt|actionqueue|consent)_',
                1,
                'medium',
                '文件名含UAC绕过技术关键词'
            ),
            # ---- 可疑文件名关键词 ----
            (
                'Suspicious.FileName',
                'filename',
                r'(?i)(malware|virus|trojan|ransom|cryptominer|keylogger|spyware|worm|backdoor|exploit|rootkit|botnet|stealer|infostealer|cryptolocker|ransomware|adware|grayware|dropper|downloader|injector|loader|packer|crypter|hack|crack|keygen|joke|prank|hoax|trick|scare|scream|fool|fake)\.(exe|dll|bat|cmd|ps1|vbs|js|scr|pif|com|sys)',
                1,
                'high',
                '包含恶意/恶搞相关关键词的文件名'
            ),
            # ---- 危险脚本扩展名 ----
            (
                'Suspicious.ScriptExtension',
                'extension',
                r'(?i)\.(bat|cmd|ps1|vbs|js|wsf|jse|vbe|hta|com|lnk|url|pif|scr|msi|msp|cpl|inf|reg)\s*$',
                1,
                'medium',
                '危险的可执行/脚本文件扩展名'
            ),
            # ---- PE 可执行文件（仅 info 级提示，已由 PEAnalyzer 做深入检查） ----
            (
                'Suspicious.PEFile',
                'extension',
                r'(?i)\.(exe|dll|ocx|sys|drv)\s*$',
                1,
                'info',
                'PE 可执行文件（已由 PE 分析模块深入检查）'
            ),
            # ---- 随机命名可执行/脚本文件（收紧: ≥12位且含数字+字母混合, 避免误报 explorer/svchost 等系统文件） ----
            (
                'Suspicious.RandomPE',
                'filename',
                r'(?i)^(?=[a-z0-9]{12,}$)(?=.*[a-z])(?=.*[0-9])[a-z0-9]+\.(exe|dll|sys|scr|pif|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|inf|reg|cpl|msi|msp|jar|class|jsp|py|pyw|sh|bash|lnk|url|chm|xap|apk)$',
                1,
                'medium',
                '文件名由 12+ 位字母+数字随机组成的可执行/脚本文件'
            ),
            # ---- 哈希文件名（恶意样本常见：直接用 MD5/SHA1/SHA256 作为文件名） ----
            (
                'Suspicious.HashFilename',
                'filename',
                r'(?i)^[a-f0-9]{32,}\.(exe|dll|sys|scr|pif|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|inf|reg|cpl|msi|msp|jar|class|jsp|py|pyw|sh|bash|lnk|url|chm|xap|apk)$',
                1,
                'medium',
                '文件名为 MD5(32位)/SHA1(40位)/SHA256(64位) 哈希格式的可执行/脚本文件'
            ),
            # ---- 宏文档 ----
            (
                'Suspicious.MacroDocument',
                'filename',
                r'(?i)\.(docm|xlsm|pptm|dotm|xltm|potm)\s*$',
                1,
                'medium',
                '包含宏的Office文档（潜在恶意宏）'
            ),
            # ---- AutoRun脚本 ----
            (
                'Suspicious.AutoRun',
                'filename',
                r'(?i)^autorun\.inf$',
                1,
                'medium',
                'U盘自动运行脚本'
            ),
            # ---- 恶搞程序文件名特征 ----
            (
                'Suspicious.JokeFileName',
                'filename',
                r'(?i)(joke|prank|hoax|trick|scare|scream|fool|fake|funny).{0,20}\.(exe|scr|bat|vbs|js|cmd|ps1|pif|com)',
                1,
                'medium',
                '文件名含恶搞程序关键词'
            ),
            # ---- 屏幕保护伪装 ----
            (
                'Suspicious.ScreenSaver',
                'filename',
                r'(?i)\.scr$',
                1,
                'low',
                '屏幕保护程序（常被恶搞程序伪装利用）'
            ),
            # ---- 注册表启动项修改路径（content规则，匹配RegSetValue的路径字符串） ----
            (
                'SystemModify.RunKey',
                'content',
                rb'(?i)\\Software\\Microsoft\\Windows\\(CurrentVersion|Windows\s+NT\\CurrentVersion)\\(Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce|Policies\\Explorer\\Run)',
                1,
                'medium',
                '包含注册表启动项路径，可能添加自启动程序'
            ),
            # ---- 映像劫持/调试器劫持路径 ----
            (
                'SystemModify.ImageHijack',
                'content',
                rb'(?i)\\Software\\Microsoft\\Windows\\NT\\CurrentVersion\\Image\\s*File\\s*Execution\\s*Options',
                1,
                'high',
                '包含映像劫持注册表路径（IFEO），可能劫持系统程序'
            ),
            # ---- 杀软/防火墙白名单修改路径（WD/Defender/Firewall排除项、禁用键） ----
            (
                'SystemModify.AVDisable',
                'content',
                rb'(?i)(Windows\\s+Defender\\Exclusions|DisableAntiSpyware|DisableRealtimeMonitoring|DisableAntiVirus|FirewallPolicy\\DisableFirewall|System\\CurrentControlSet\\Services\\(WinDefend|WdNisSvc|wuauserv|SecurityHealthService)\\Start\\s*=\s*[34])',
                1,
                'high',
                '包含杀软/系统安全防护禁用或排除项注册表路径'
            ),
            # ---- 服务创建/驱动安装命令（cmd/bat/ps1脚本中） ----
            (
                'SystemModify.ServiceDriverInstall',
                'content',
                rb'(?i)(sc\s+(create|config|start)|CreateService|net\s+start\s+[a-z0-9_]{5,}|rundll32\s+setupapi,InstallHinfSection|pnputil\s+-?/?i\s+-?/?a|InstallDriver|DIFx)',
                1,
                'medium',
                '包含服务/驱动安装命令'
            ),
            # ---- 计划任务创建命令 ----
            (
                'SystemModify.ScheduledTask',
                'content',
                rb'(?i)(schtasks\s+/(Create|Change)|New-ScheduledTask|Register-ScheduledTask|ITaskService|ITaskFolder)',
                1,
                'medium',
                '包含计划任务创建命令，可能用于持久化'
            ),
            # ---- UAC绕过方法 ----
            (
                'SystemModify.UACBypass',
                'content',
                rb'(?i)(fodhelper|eventvwr|sdclt|consent|CompMgmtLauncher|ComputerDefaults|sysprep\\cryptbase|shellrunas.exe\s+/uac|RunAs\\Administrator|HKCU\\s*\\Environment\\\\s*__COMPAT_LAYER\\s*=\\s*.*RunAsInvoker)',
                1,
                'high',
                '包含UAC绕过常见技术特征'
            ),
            # ---- 勒索软件典型操作（卷影删除+加密命令） ----
            (
                'Ransomware.ShadowDelete',
                'content',
                rb'(?i)(vssadmin\s+Delete\s+Shadows|wmic\s+shadowcopy\s+delete|bcdedit\s+/set\s+recoveryenabled\s+No|wbadmin\s+delete\s+systemstatebackup|cipher\s+/w)',
                1,
                'high',
                '包含删除卷影副本/备份的勒索软件典型操作'
            ),
            # ---- PowerShell下载执行（下一个） ----
            (
                'SystemModify.PSLauncher',
                'content',
                rb'(?i)(powershell\s+(-NoP|NoProfile|-NonInteractive|Hidden|-Exec\s+Bypass|ExecutionPolicy\s+Bypass|iex|Invoke-Expression|Net\.WebClient|DownloadString|DownloadData)\b.{0,400}(http|https|Base64|FromBase64String)|-enc\s+[A-Za-z0-9+/=]{30,})',
                1,
                'high',
                '包含PowerShell下载执行绕过（Bypass/EncodedCommand/WebClient）'
            ),
        ]

        cursor = self._conn.cursor()
        for name, rule_type, pattern, threshold, severity, desc in builtin_rules:
            cursor.execute(
                'SELECT id, severity, pattern, description FROM heuristic_rules WHERE name = ?',
                (name,)
            )
            row = cursor.fetchone()
            if row is None:
                cursor.execute('''
                    INSERT INTO heuristic_rules
                    (name, rule_type, pattern, threshold, severity, description)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (name, rule_type, pattern, threshold, severity, desc))
            else:
                # 规则已存在但属性变化 → 自动 UPDATE（支持内置规则迭代优化）
                _, old_sev, old_pat, old_desc = row
                if (old_sev != severity or old_pat != pattern or old_desc != desc):
                    cursor.execute('''
                        UPDATE heuristic_rules
                        SET severity=?, pattern=?, description=?
                        WHERE name=?
                    ''', (severity, pattern, desc, name))
        self._conn.commit()
    
    def _start_async_cache_load(self):
        """在后台线程异步装载内存缓存（不影响启动关键路径）"""
        def _loader():
            try:
                self._load_cache()
            except Exception as e:
                logger.warning(f'签名库缓存后台装载失败: {e}')
            finally:
                self._cache_evt.set()

        # 幂等保护：已有装载线程则跳过
        if self._cache_evt.is_set():
            return
        with self._cache_mutex:
            if self._cache_load_thread is not None and self._cache_load_thread.is_alive():
                return
            self._cache_load_thread = threading.Thread(
                target=_loader, name='PSLS-SigDBCacheLoad', daemon=True)
            self._cache_load_thread.start()

    def _ensure_cache_loaded(self, timeout: float = 3.0):
        """确保内存缓存已装载。

        后台装载线程启动后（_init_db 内）绝大多数读缓存调用都能在几毫秒后
        命中已完成状态；未完成时按调用线程区别对待：

          * GUI 线程（Qt 主线程）：只做极短等待即返回。装载线程全程持
            _cache_mutex（大签名表在机械盘/高负载下可达数十秒），主线程
            一旦等待就会让整个界面"未响应"——历史上 PSLS 假死即由此产生。
          * 其它线程（扫描/防护）：最多等待 timeout 秒，让签名判定尽量完整；
            超时且装载仍在进行时返回 False，不再强制同步装载（会二次等锁）。
        """
        if self._cache_evt.is_set():
            return True
        # 关键：此处不能获取 _cache_mutex——装载线程在整个装载期间（大表 +
        # 机械盘/高负载下可达数十秒）持有它，一旦在此等待就会无界阻塞。
        # 原先主线程走"扫描库摘要/白名单"等路径时会卡在这里，表现为
        # 界面"未响应"（这正是 PSLS 假死的根因）。这里只做一次属性读取。
        tl = self._cache_load_thread
        if tl is not None and tl.is_alive():
            if threading.current_thread() is threading.main_thread():
                # GUI 线程绝不等待装载：宁可本次拿到"尚未装载"的部分缓存，
                # 也不能阻塞 Qt 消息循环。装载完成后 _cache_evt 置位，
                # 后续调用立即命中。
                self._cache_evt.wait(min(timeout, 0.05))
                return self._cache_evt.is_set()
            if self._cache_evt.wait(timeout):
                return True
            # 非 GUI 线程（扫描/防护）超时：装载线程仍在跑，直接返回，
            # 由调用方按"缓存未就绪"处理；不再强制同步装载（会二次等锁）。
            return False
        # 装载线程未启动（外部直接构造后同步调用）或已结束但未置位
        # → 同步兜底装载一次（装载本身带锁保护，不会并发双写）
        self._load_cache()
        self._cache_evt.set()
        return True

    def _load_cache(self):
        """加载签名到内存缓存（线程安全：_cache_mutex 保护）

        使用**独立连接**读取，不与主连接 self._conn 共用：
        装载在后台线程中可能持续数秒到数十秒，期间其它线程在主连接上的
        INSERT/commit 会让本次游标失效（日志中的
        'Cursor needed to be reset because of commit/rollback'），
        主连接被 close() 时则抛 'Cannot operate on a closed database'；
        两者都会让装载中途失败，使本次会话退化成"空签名缓存"（哈希检出全失效）。
        """
        if not self._cache_evt.is_set():
            with self._cache_mutex:
                # 双重检测：可能已被其他线程装载
                if self._cache_evt.is_set():
                    return
                conn = None
                try:
                    conn = sqlite3.connect(self.db_path, timeout=5.0)
                    self._load_cache_from(conn)
                finally:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass

    def _load_cache_from(self, conn):
        """从指定连接读取各表填充内存缓存（调用方负责连接生命周期）"""
        cursor = conn.cursor()

        # 加载恶意软件签名
        # 逐行迭代而非 fetchall()：每个扫描子进程都会装载一次缓存，
        # fetchall() 会先把整表复制成一份 Python 列表（大库下数百 MB/进程），
        # 多个 worker 并发时极易把内存打满（历史上子进程被系统终止、
        # ProcessPool 崩溃即与此有关）。逐行迭代内存占用只与最终缓存相当。
        cursor.execute(
            'SELECT hash_sha256, name, type, severity, description '
            'FROM malware_signatures')
        for row in cursor:
            self._malware_hashes.add(row[0])
            self._malware_info[row[0]] = {
                'name': row[1],
                'type': row[2],
                'severity': row[3],
                'description': row[4]
            }

        # 加载启发式规则
        cursor.execute(
            'SELECT id, name, rule_type, pattern, threshold, severity, '
            'description FROM heuristic_rules')
        for row in cursor:
            self._heuristic_rules.append({
                'id': row[0],
                'name': row[1],
                'rule_type': row[2],
                'pattern': row[3],
                'threshold': row[4],
                'severity': row[5],
                'description': row[6]
            })

        # 加载白名单到内存缓存
        cursor.execute('SELECT hash_sha256 FROM whitelist')
        for row in cursor:
            self._whitelist_cache.add(row[0])

        # 加载沙箱放行信任到内存缓存（独立表，仅跳过沙箱用）
        cursor.execute('SELECT hash_sha256 FROM sandbox_trust')
        for row in cursor:
            self._sandbox_trust_cache.add(row[0])
    
    def add_signature(self, hash_sha256: str, name: str, malware_type: str,
                      severity: str = 'high', description: str = '', source: str = '',
                      sample_path: Optional[str] = None):
        """添加恶意软件签名（线程安全，幂等，保护扩展字段）

        关键行为：
        1. hash 不存在 → INSERT（含 sample_path 扩展列一并写入）
        2. hash 已存在  → UPDATE 仅覆盖基础字段，**保留** fuzzy_hash / yara_rule_id / sample_path / last_yara_gen
        3. 传了 sample_path 且文件存在 → 触发 _enrich_from_sample，补 fuzzy_hash + YARA（即使已存在也 upsert）
        4. hash 已存在但 sample_path 本次没传 → 尝试复用 DB 中已有的 sample_path 自动补全缺失的 fuzzy/YARA

        Args:
            hash_sha256: SHA-256 哈希
            name: 恶意软件名称
            malware_type: 类型（Trojan/Ransomware/...）
            severity: 严重级别
            description: 描述
            source: 来源
            sample_path: 可选样本文件路径；提供时自动计算 fuzzy_hash + 生成 YARA 规则
        """
        if not hash_sha256:
            return False

        # 启动期缓存可能还在后台装载：先确保完成，避免装载后半覆盖本次写入
        self._ensure_cache_loaded()

        enriched_sample_path: Optional[str] = None

        with self._lock:
            cursor = self._conn.cursor()
            try:
                # 先查是否已存在
                cursor.execute(
                    'SELECT hash_sha256, fuzzy_hash, yara_rule_id, sample_path '
                    'FROM malware_signatures WHERE hash_sha256 = ?',
                    (hash_sha256,)
                )
                existing = cursor.fetchone()

                if existing is None:
                    # 不存在 → INSERT（只写基础字段，扩展列由 enrich 写）
                    cursor.execute('''
                        INSERT INTO malware_signatures
                        (hash_sha256, name, type, severity, description, source)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (hash_sha256, name, malware_type, severity, description, source))
                else:
                    # 已存在 → 只 UPDATE 基础字段，保护扩展字段不动
                    cursor.execute('''
                        UPDATE malware_signatures
                        SET name = ?, type = ?, severity = ?, description = ?, source = ?
                        WHERE hash_sha256 = ?
                    ''', (name, malware_type, severity, description, source, hash_sha256))

                    # 自动恢复：如果已有的 sample_path 还存在、但 fuzzy 或 yara 缺失 → 本次顺便补全
                    if not sample_path:
                        old_sample = existing[3]
                        old_has_fuzzy = bool(existing[1])
                        old_has_yara = bool(existing[2])
                        if old_sample and os.path.isfile(old_sample) and not (old_has_fuzzy and old_has_yara):
                            enriched_sample_path = old_sample

                self._conn.commit()
                self._malware_hashes.add(hash_sha256)
                self._malware_info[hash_sha256] = {
                    'name': name,
                    'type': malware_type,
                    'severity': severity,
                    'description': description
                }
            except Exception as e:
                logger.error(f"添加签名失败: {e}")
                return False

        # ---- 样本驱动的自动衍生：fuzzy hash + YARA ----
        # 优先级：显式传入 > 从 DB 恢复
        effective_sample = sample_path or enriched_sample_path
        if effective_sample and os.path.isfile(effective_sample):
            self._enrich_from_sample(hash_sha256, effective_sample, name, severity)

        return True

    def _enrich_from_sample(self, hash_sha256: str, sample_path: str,
                            name: str = '', severity: str = 'high'):
        """有样本文件时：计算 fuzzy_hash + 生成 YARA 规则 + 更新 DB。"""
        try:
            # fuzzy hash
            fuzzy_hash = None
            try:
                from utils.fuzzy_hash import fuzzy_file
                fuzzy_hash = fuzzy_file(sample_path)
            except Exception as e:
                logger.debug(f'计算 fuzzy hash 失败（可忽略）: {e}')

            # YARA 规则
            yara_rule_id = None
            last_gen = None
            try:
                from engine.yara_generator import YaraGenerator
                gen = YaraGenerator()
                result = gen.generate(sample_path, sha256=hash_sha256,
                                      name=name or os.path.basename(sample_path),
                                      severity=severity)
                if result:
                    yara_rule_id = self.upsert_yara_rule(
                        rule_name=result['rule_name'],
                        hash_sha256=hash_sha256,
                        rule_content=result['rule_content'],
                        severity=severity,
                        feature_count=result['feature_count'],
                        file_size=result['file_size'],
                        sample_type=result['sample_type'],
                    )
                    last_gen = result.get('generated_date') or ''
                    logger.info(
                        f'已为 {hash_sha256[:12]} 生成 YARA 规则: '
                        f'{result["rule_name"]} ({result["feature_count"]} 特征)'
                    )
            except Exception as e:
                logger.warning(f'YARA 规则生成失败 {sample_path}: {e}')

            # 更新 malware_signatures 扩展列
            with self._lock:
                cursor = self._conn.cursor()
                updates = []
                params: list = []
                if fuzzy_hash:
                    updates.append('fuzzy_hash = ?')
                    params.append(fuzzy_hash)
                updates.append('sample_path = ?')
                params.append(sample_path)
                if yara_rule_id is not None:
                    updates.append('yara_rule_id = ?')
                    params.append(yara_rule_id)
                if last_gen:
                    updates.append('last_yara_gen = ?')
                    params.append(last_gen)
                if updates:
                    params.append(hash_sha256)
                    cursor.execute(
                        f'UPDATE malware_signatures SET {", ".join(updates)} '
                        f'WHERE hash_sha256 = ?',
                        params
                    )
                    self._conn.commit()
        except Exception as e:
            logger.error(f'样本富集失败 {sample_path}: {e}')

    def _batch_insert_ignore(self, cursor, batch: list, debug_label: str = '') -> tuple:
        """批量 INSERT OR IGNORE 并返回 (实际新增数量, 新增哈希集合)

        Python sqlite3 的 executemany() 不更新 rowcount（始终为 -1），
        因此通过预查询已存在的哈希来计算实际新增数量。

        Returns:
            (实际新增数量, 本批次实际插入的哈希集合)
        """
        if not batch:
            return 0, set()
        hashes = [row[0] for row in batch]
        unique_hashes = set(hashes)
        # 查询已存在的哈希
        placeholders = ','.join('?' * len(unique_hashes))
        cursor.execute(
            f'SELECT hash_sha256 FROM malware_signatures WHERE hash_sha256 IN ({placeholders})',
            list(unique_hashes)
        )
        existing = {row[0] for row in cursor.fetchall()}
        newly_inserted = unique_hashes - existing
        actual_new = len(newly_inserted)

        # 诊断日志：输出样本哈希的查询结果
        if debug_label:
            sample_hashes = list(unique_hashes)[:3]
            sample_existing = sample_hashes and sample_hashes[0] in existing
            logger.debug(
                f'[诊断] {debug_label}: 批次{len(batch)}条, 唯一{len(unique_hashes)}个, '
                f'已存在{len(existing)}个, 新增{actual_new}个. '
                f'样本哈希={sample_hashes[:2]}, 第一个已存在={sample_existing}'
            )

        # 执行插入
        cursor.executemany('''
            INSERT OR IGNORE INTO malware_signatures
            (hash_sha256, name, type, severity, description, source)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', batch)
        return actual_new, newly_inserted

    def add_signatures_batch(self, signatures: list) -> int:
        """批量添加恶意软件签名（线程安全，使用 executemany + 单次 commit）

        Args:
            signatures: 元组列表 [(hash_sha256, name, type, severity, description, source), ...]
        Returns:
            成功添加的数量
        """
        if not signatures:
            return 0
        added = 0
        with self._lock:
            cursor = self._conn.cursor()
            try:
                # executemany 批量插入，单次 commit
                cursor.executemany('''
                    INSERT OR REPLACE INTO malware_signatures 
                    (hash_sha256, name, type, severity, description, source)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', signatures)
                self._conn.commit()
                added = len(signatures)
                # 更新内存缓存
                for sig in signatures:
                    sha256 = sig[0]
                    self._malware_hashes.add(sha256)
                    self._malware_info[sha256] = {
                        'name': sig[1],
                        'type': sig[2],
                        'severity': sig[3] if len(sig) > 3 else 'high',
                        'description': sig[4] if len(sig) > 4 else ''
                    }
            except Exception as e:
                logger.error(f"批量添加签名失败: {e}")
                self._conn.rollback()
        return added
    
    def add_heuristic_rule(self, name: str, rule_type: str, pattern: str, 
                           threshold: int = 1, severity: str = 'medium', description: str = ''):
        """添加启发式规则（线程安全）"""
        with self._lock:
            cursor = self._conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO heuristic_rules 
                    (name, rule_type, pattern, threshold, severity, description)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (name, rule_type, pattern, threshold, severity, description))
                self._conn.commit()
                self._heuristic_rules.append({
                    'id': cursor.lastrowid,
                    'name': name,
                    'rule_type': rule_type,
                    'pattern': pattern,
                    'threshold': threshold,
                    'severity': severity,
                    'description': description
                })
                return True
            except Exception as e:
                logger.error(f"添加启发式规则失败: {e}")
                return False
    
    def is_malware(self, hash_sha256: str) -> bool:
        """检查哈希是否为恶意软件（内存缓存；未装载时先确保装载）"""
        self._ensure_cache_loaded()
        return hash_sha256 in self._malware_hashes
    
    def get_malware_info(self, hash_sha256: str) -> Optional[Dict]:
        """获取恶意软件详细信息（内存缓存；未装载时先确保装载）"""
        self._ensure_cache_loaded()
        return self._malware_info.get(hash_sha256)

    def lookup_signature(self, hash_sha256: str) -> Optional[Dict]:
        """查询 DB 中完整签名行（包含 sample_path / fuzzy_hash / yara_rule_id 等扩展字段）。"""
        try:
            with self._lock:
                cur = self._conn.execute(
                    "SELECT hash_sha256 AS hash, name, type, severity, "
                    "description, source, fuzzy_hash, sample_path, yara_rule_id, "
                    "last_yara_gen, added_date "
                    "FROM malware_signatures WHERE hash_sha256 = ?", (hash_sha256,)
                )
                row = cur.fetchone()
                if row:
                    col_names = [d[0] for d in cur.description]
                    return dict(zip(col_names, row))
        except Exception:
            pass
        return None

    def get_heuristic_rules(self) -> List[Dict]:
        """获取所有启发式规则（内存缓存；未装载时先确保装载）"""
        self._ensure_cache_loaded()
        return self._heuristic_rules
    
    def is_whitelisted(self, hash_sha256: str) -> bool:
        """检查是否在白名单中（使用内存缓存；未装载时先确保装载）"""
        self._ensure_cache_loaded()
        return hash_sha256 in self._whitelist_cache
    
    def get_signature_count(self) -> int:
        """获取签名数量（内存缓存；未装载时先确保装载）"""
        self._ensure_cache_loaded()
        return len(self._malware_hashes)

    def get_whitelist_count(self) -> int:
        """获取白名单数量（内存缓存；未装载时先确保装载）"""
        self._ensure_cache_loaded()
        return len(self._whitelist_cache)

    def get_heuristic_count(self) -> int:
        """获取启发式规则数量（内存缓存；未装载时先确保装载）"""
        self._ensure_cache_loaded()
        return len(self._heuristic_rules)

    def lookup_hash(self, hash_sha256: str) -> Optional[Dict]:
        """查询哈希对应的恶意软件信息（供进程保护等模块调用）"""
        self._ensure_cache_loaded()
        info = self._malware_info.get(hash_sha256)
        if info:
            return info
        return None
    
    def add_to_whitelist(self, hash_sha256: str, reason: str = ''):
        """添加到白名单（线程安全，只更新内存缓存，延迟批量持久化）

        性能优化：扫描期间每个 clean 文件都会调用此方法，若每次都执行
        INSERT+commit 会触发 fsync 磁盘同步，严重拖慢扫描速度（10000文件
        = 10000次 fsync）。改为只更新内存缓存 + 累积到待写入列表，
        由扫描流程在合适时机调用 flush_whitelist_batch 批量持久化。

        命中缓存时直接返回，避免重复添加。
        """
        # 启动期缓存可能还在后台装载：先确保完成（内部快速返回）
        self._ensure_cache_loaded()
        # 快速路径：已存在则直接返回（无锁判断，set 是线程安全的读取）
        if hash_sha256 in self._whitelist_cache:
            return True
        with self._lock:
            # 双重检测
            if hash_sha256 in self._whitelist_cache:
                return True
            # 更新内存缓存（立即对查询生效）
            self._whitelist_cache.add(hash_sha256)
            # 累积到待写入列表，延迟持久化
            self._whitelist_pending.append((hash_sha256, reason))
            # 达到阈值时自动 flush（避免内存无限增长）
            if len(self._whitelist_pending) >= self._whitelist_flush_threshold:
                self._flush_whitelist_unlocked()
            return True

    def _flush_whitelist_unlocked(self):
        """将待写入的白名单批量持久化到数据库（内部方法，调用方需持锁）"""
        if not self._whitelist_pending:
            return 0
        pending = self._whitelist_pending[:]
        self._whitelist_pending.clear()
        try:
            cursor = self._conn.cursor()
            cursor.executemany(
                'INSERT OR IGNORE INTO whitelist (hash_sha256, reason) VALUES (?, ?)',
                pending
            )
            self._conn.commit()
            return len(pending)
        except Exception as e:
            logger.error(f'批量写入白名单失败: {e} (count={len(pending)})')
            # 失败时把数据放回 pending，下次再试
            try:
                self._whitelist_pending.extend(pending)
            except Exception:
                pass
            return 0

    def flush_whitelist_batch(self):
        """将待写入的白名单批量持久化到数据库（线程安全）

        扫描流程在扫描结束、用户停止扫描、定期检查点等时机调用此方法，
        将累积的白名单条目一次性写入数据库。
        """
        with self._lock:
            return self._flush_whitelist_unlocked()

    # ---- 沙箱放行信任（独立于白名单，仅跳过"二次进沙箱"，不影响其他模块）----

    def is_sandbox_trusted(self, hash_sha256: str) -> bool:
        """该哈希是否因"沙箱判安全"而被跳过沙箱。

        注意：此信任独立于 whitelist。不要用全局白名单判断，否则会把沙箱
        放行扩散到文件防篡改/实时扫描/引擎扫描等所有模块。这里的唯一用途
        是《check_new_process》在送沙箱前据此放行，做到"判安全后不再进沙箱"。
        """
        self._ensure_cache_loaded()
        return hash_sha256 in self._sandbox_trust_cache

    def add_sandbox_trust(self, hash_sha256: str, reason: str = ''):
        """记录"沙箱判定安全"信任（立即入内存缓存 + 直接落库）。

        频率远低于扫描期 add_to_whitelist（每次干净文件），故直接同步写库，
        不需要批量缓冲 + 手动 flush，保证持久化即时生效（重启后仍跳过沙箱）。
        """
        self._ensure_cache_loaded()
        if hash_sha256 in self._sandbox_trust_cache:
            return True
        with self._lock:
            if hash_sha256 in self._sandbox_trust_cache:
                return True
            self._sandbox_trust_cache.add(hash_sha256)
            try:
                cursor = self._conn.cursor()
                cursor.execute(
                    'INSERT OR IGNORE INTO sandbox_trust (hash_sha256, reason) '
                    'VALUES (?, ?)', (hash_sha256, reason))
                self._conn.commit()
                return True
            except Exception as e:
                logger.error(f'写入沙箱放行信任失败: {e}')
                # 写库失败时回滚内存缓存，避免"以为已信任实际没持久化"的不一致
                self._sandbox_trust_cache.discard(hash_sha256)
                return False
    
    def get_all_signatures(self, limit: int = 100, offset: int = 0, search: str = '') -> List[Dict]:
        """获取恶意软件签名列表（分页，可选搜索）

        Args:
            limit: 每页数量
            offset: 偏移量
            search: 搜索关键词（匹配 name/hash/type/source）

        Returns:
            签名列表，每项包含 hash/name/type/severity/description/source/added_date
        """
        cursor = self._conn.cursor()
        if search:
            like = f'%{search}%'
            cursor.execute('''
                SELECT hash_sha256, name, type, severity, description, source, added_date
                FROM malware_signatures
                WHERE name LIKE ? OR hash_sha256 LIKE ? OR type LIKE ? OR source LIKE ?
                ORDER BY added_date DESC
                LIMIT ? OFFSET ?
            ''', (like, like, like, like, limit, offset))
        else:
            cursor.execute('''
                SELECT hash_sha256, name, type, severity, description, source, added_date
                FROM malware_signatures
                ORDER BY added_date DESC
                LIMIT ? OFFSET ?
            ''', (limit, offset))
        return [
            {
                'hash': self._to_str(row[0]),
                'name': self._to_str(row[1]),
                'type': self._to_str(row[2]),
                'severity': self._to_str(row[3]),
                'description': self._to_str(row[4]),
                'source': self._to_str(row[5]),
                'added_date': self._to_str(row[6]),
            }
            for row in cursor.fetchall()
        ]

    def get_signature_count_by_filter(self, search: str = '') -> int:
        """获取符合条件的签名总数"""
        cursor = self._conn.cursor()
        if search:
            like = f'%{search}%'
            cursor.execute(
                'SELECT COUNT(*) FROM malware_signatures WHERE name LIKE ? OR hash_sha256 LIKE ? OR type LIKE ? OR source LIKE ?',
                (like, like, like, like)
            )
        else:
            cursor.execute('SELECT COUNT(*) FROM malware_signatures')
        return cursor.fetchone()[0]

    def delete_signature(self, hash_sha256: str) -> bool:
        """删除单个恶意软件签名"""
        cursor = self._conn.cursor()
        cursor.execute('DELETE FROM malware_signatures WHERE hash_sha256 = ?', (hash_sha256,))
        self._conn.commit()
        if cursor.rowcount > 0:
            self._malware_hashes.discard(hash_sha256)
            self._malware_info.pop(hash_sha256, None)
            return True
        return False

    def delete_signatures_batch(self, hashes: List[str]) -> int:
        """批量删除恶意软件签名"""
        cursor = self._conn.cursor()
        deleted = 0
        for h in hashes:
            cursor.execute('DELETE FROM malware_signatures WHERE hash_sha256 = ?', (h,))
            if cursor.rowcount > 0:
                deleted += 1
                self._malware_hashes.discard(h)
                self._malware_info.pop(h, None)
        self._conn.commit()
        return deleted

    def get_all_heuristic_rules_with_id(self) -> List[Dict]:
        """获取所有启发式规则（带数据库ID）"""
        cursor = self._conn.cursor()
        cursor.execute('SELECT id, name, rule_type, pattern, threshold, severity, description FROM heuristic_rules ORDER BY id')
        return [
            {'id': row[0], 'name': self._to_str(row[1]), 'rule_type': self._to_str(row[2]),
             'pattern': self._to_str(row[3]), 'threshold': row[4],
             'severity': self._to_str(row[5]), 'description': self._to_str(row[6])}
            for row in cursor.fetchall()
        ]

    def delete_heuristic_rule(self, rule_id: int) -> bool:
        """删除单个启发式规则"""
        cursor = self._conn.cursor()
        cursor.execute('DELETE FROM heuristic_rules WHERE id = ?', (rule_id,))
        self._conn.commit()
        if cursor.rowcount > 0:
            self._heuristic_rules = [r for r in self._heuristic_rules if r.get('id') != rule_id]
            return True
        return False

    def delete_heuristic_rules_batch(self, rule_ids: List[int]) -> int:
        """批量删除启发式规则"""
        cursor = self._conn.cursor()
        deleted = 0
        for rid in rule_ids:
            cursor.execute('DELETE FROM heuristic_rules WHERE id = ?', (rid,))
            if cursor.rowcount > 0:
                deleted += 1
        self._conn.commit()
        id_set = set(rule_ids)
        self._heuristic_rules = [r for r in self._heuristic_rules if r.get('id') not in id_set]
        return deleted

    def get_all_fuzzy_hash_signatures(self) -> List[Dict]:
        """获取所有 fuzzy_hash 非空的签名（用于 CTPH 模糊匹配，线程安全）

        返回列表每项字段：sha256 / name / type / severity / fuzzy_hash。
        """
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                'SELECT hash_sha256, name, type, severity, fuzzy_hash '
                'FROM malware_signatures '
                "WHERE fuzzy_hash IS NOT NULL AND fuzzy_hash != ''"
            )
            return [
                {
                    'sha256': self._to_str(row[0]),
                    'name': self._to_str(row[1]),
                    'type': self._to_str(row[2]),
                    'severity': self._to_str(row[3]),
                    'fuzzy_hash': self._to_str(row[4]),
                }
                for row in cursor.fetchall()
            ]

    def get_all_whitelist(self) -> List[Dict]:
        """获取白名单列表（线程安全）"""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute('SELECT hash_sha256, reason, added_date FROM whitelist ORDER BY added_date DESC')
            return [
                {'hash': self._to_str(row[0]), 'reason': self._to_str(row[1]),
                 'added_date': self._to_str(row[2])}
                for row in cursor.fetchall()
            ]

    def delete_from_whitelist(self, hash_sha256: str) -> bool:
        """从白名单删除单个条目（线程安全）"""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute('DELETE FROM whitelist WHERE hash_sha256 = ?', (hash_sha256,))
            self._conn.commit()
            if cursor.rowcount > 0:
                self._whitelist_cache.discard(hash_sha256)
                return True
            return False

    def delete_from_whitelist_batch(self, hashes: List[str]) -> int:
        """批量从白名单删除（线程安全）"""
        with self._lock:
            cursor = self._conn.cursor()
            deleted = 0
            for h in hashes:
                cursor.execute('DELETE FROM whitelist WHERE hash_sha256 = ?', (h,))
                if cursor.rowcount > 0:
                    deleted += 1
                    self._whitelist_cache.discard(h)
            self._conn.commit()
            return deleted

    def clear_all_whitelist(self) -> int:
        """清空所有白名单条目，返回删除的条目数（线程安全）"""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM whitelist')
            count_before = cursor.fetchone()[0]
            if count_before == 0:
                return 0
            cursor.execute('DELETE FROM whitelist')
            self._conn.commit()
            self._whitelist_cache.clear()
            return count_before

    def load_from_json(self, json_path: str) -> int:
        """从JSON文件批量导入签名（返回实际新增数量）

        支持的格式：
        1. {"signatures": [{hash, name, type, ...}, ...]}  - PSLS 标准格式
        2. [{hash, name, ...}, ...]                        - 直接列表
        3. {hash: "...", name: "..."}                      - 单条对象
        4. {"file_hashes": ["sha256", ...]}                - CDST 纯哈希格式
        5. ["sha256", "sha256", ...]                       - 纯哈希字符串列表
        6. {"data"/"items"/"records"/"results": [...]}     - 其他常见顶层键名

        哈希字段名兼容：hash_sha256, hash, sha256, SHA256, md5, sha1

        优化：分批提交（每 _BATCH_SIZE 条 commit 一次），避免逐条 commit 导致
        大量磁盘同步（fsync）卡住 UI。
        """
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # --- 哈希字段名候选（按优先级）---
            _HASH_KEYS = ('hash_sha256', 'hash', 'sha256', 'SHA256', 'md5', 'sha1')
            # --- 顶层列表键名候选 ---
            _LIST_KEYS = ('signatures', 'file_hashes', 'data', 'items',
                          'records', 'results', 'malware', 'hashes')

            # --- 解析为统一的 entries 列表 ---
            if isinstance(data, list):
                # 格式 2/5: 直接列表（可能是字符串或对象）
                entries = data
            elif isinstance(data, dict):
                # 检查是否为单条签名对象
                if any(k in data for k in _HASH_KEYS):
                    entries = [data]
                else:
                    # 尝试已知的顶层列表键名
                    entries = []
                    for key in _LIST_KEYS:
                        if key in data:
                            raw = data[key]
                            if key == 'file_hashes':
                                entries = [h for h in raw if isinstance(h, str) and len(h) == 64]
                                logger.info(f'检测到 file_hashes 格式，共 {len(entries)} 个纯哈希')
                            elif isinstance(raw, list):
                                entries = raw
                            break
                    if not entries:
                        # 遍历 dict 的值，找到第一个列表
                        for k, v in data.items():
                            if isinstance(v, list) and len(v) > 0:
                                entries = v
                                logger.info(f'检测到自定义顶层键 "{k}"，共 {len(entries)} 条')
                                break
            else:
                entries = []

            if not entries:
                logger.warning(f'JSON 文件未识别到签名数据，请检查格式。'
                               f'支持的顶层键: {_LIST_KEYS}，'
                               f'支持的哈希字段: {_HASH_KEYS}')
                return 0

            logger.info(f'JSON 解析到 {len(entries)} 条原始数据')

            # --- 验证并入库（分批提交）---
            import re
            _sha_re = re.compile(r'^[a-fA-F0-9]{64}$')
            _md5_re = re.compile(r'^[a-fA-F0-9]{32}$')
            _sha1_re = re.compile(r'^[a-fA-F0-9]{40}$')
            _BATCH_SIZE = 500
            skipped = 0
            skip_no_hash = 0
            skip_bad_format = 0
            valid_entries = []  # [(hash, name, type, severity, description, source), ...]

            # 第一遍：收集所有有效条目
            for entry in entries:
                if isinstance(entry, str):
                    hash_val = entry.strip().lower()
                    if not (_sha_re.match(hash_val) or _md5_re.match(hash_val)
                            or _sha1_re.match(hash_val)):
                        skipped += 1
                        skip_bad_format += 1
                        continue
                    name = f'Imported-{hash_val[:8]}'
                    mtype = 'import'
                    severity = 'high'
                    description = ''
                elif isinstance(entry, dict):
                    hash_val = ''
                    for hk in _HASH_KEYS:
                        v = entry.get(hk)
                        if v and isinstance(v, str):
                            hash_val = v.strip()
                            break
                    if not hash_val:
                        skipped += 1
                        skip_no_hash += 1
                        continue
                    hash_val = hash_val.lower()
                    if not (_sha_re.match(hash_val) or _md5_re.match(hash_val)
                            or _sha1_re.match(hash_val)):
                        skipped += 1
                        skip_bad_format += 1
                        continue
                    name = entry.get('name', entry.get('malware_name',
                            entry.get('threat_name', 'Unknown')))
                    mtype = entry.get('type', entry.get('category',
                            entry.get('malware_type', 'import')))
                    severity = entry.get('severity', entry.get('threat_level', 'high'))
                    description = entry.get('description', entry.get('reason', ''))
                else:
                    skipped += 1
                    continue

                valid_entries.append((hash_val, name, mtype, severity, description, json_path))

            if not valid_entries:
                logger.warning(f'无有效条目（跳过 {skipped} 条）')
                return 0

            # 预检查：统计唯一哈希数和已存在数
            all_hashes = [e[0] for e in valid_entries]
            unique_hash_list = list(set(all_hashes))
            unique_count = len(unique_hash_list)

            with self._lock:
                cursor = self._conn.cursor()
                # 分批预查询已存在哈希（避免参数过多）
                existing_count = 0
                for i in range(0, len(unique_hash_list), _BATCH_SIZE):
                    chunk = unique_hash_list[i:i + _BATCH_SIZE]
                    ph = ','.join('?' * len(chunk))
                    cursor.execute(
                        f'SELECT COUNT(*) FROM malware_signatures WHERE hash_sha256 IN ({ph})',
                        chunk
                    )
                    existing_count += cursor.fetchone()[0]

                logger.info(
                    f'预检查: 有效{len(valid_entries)}条, 唯一{unique_count}个哈希, '
                    f'已存在{existing_count}个, 预计新增{unique_count - existing_count}个'
                )

                if unique_count <= existing_count:
                    # 所有哈希已存在，无需执行插入
                    if skipped > 0:
                        logger.warning(f'跳过 {skipped} 个无效条目')
                    logger.info(f'成功从 JSON 导入 0 个签名（全部已存在）')
                    return 0

                # 第二遍：分批插入
                count = 0
                batch = []
                for valid_entry in valid_entries:
                    batch.append(valid_entry)
                    if len(batch) >= _BATCH_SIZE:
                        actual_inserted, inserted_hashes = self._batch_insert_ignore(
                            cursor, batch, debug_label=f'JSON批次#{count // _BATCH_SIZE + 1}'
                        )
                        count += actual_inserted
                        self._conn.commit()
                        if inserted_hashes:
                            for sig in batch:
                                sha = sig[0]
                                if sha in inserted_hashes:
                                    self._malware_hashes.add(sha)
                                    self._malware_info[sha] = {
                                        'name': sig[1], 'type': sig[2],
                                        'severity': sig[3], 'description': sig[4]
                                    }
                        batch.clear()

                if batch:
                    actual_inserted, inserted_hashes = self._batch_insert_ignore(
                        cursor, batch, debug_label=f'JSON尾部批次'
                    )
                    count += actual_inserted
                    self._conn.commit()
                    if inserted_hashes:
                        for sig in batch:
                            sha = sig[0]
                            if sha in inserted_hashes:
                                self._malware_hashes.add(sha)
                                self._malware_info[sha] = {
                                    'name': sig[1], 'type': sig[2],
                                    'severity': sig[3], 'description': sig[4]
                                }
                    batch.clear()

            if skipped > 0:
                detail = []
                if skip_no_hash > 0:
                    detail.append(f'{skip_no_hash} 个无哈希字段')
                if skip_bad_format > 0:
                    detail.append(f'{skip_bad_format} 个哈希格式不正确')
                logger.warning(f'跳过 {skipped} 个无效条目（{", ".join(detail)}）')
            logger.info(f'成功从 JSON 导入 {count} 个签名（原始 {len(entries)} 条，跳过 {skipped} 条）')
            return count
        except Exception as e:
            logger.error(f'从 JSON 导入签名失败: {e}')
            return 0

    def load_from_txt(self, txt_path: str) -> int:
        """从TXT文件导入签名（每行一个SHA256哈希，或格式 hash,name,type,severity）

        支持格式：
        - 每行一个纯 SHA256 哈希（64 位十六进制）
        - hash,name,type,severity 逗号分隔
        - 以 # 开头的注释行会被跳过

        优化：分批提交（每 _BATCH_SIZE 条 commit 一次）。
        """
        try:
            lines = []
            with open(txt_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 1:
                        hash_val = parts[0]
                        if len(hash_val) == 64:
                            name = parts[1] if len(parts) > 1 else f'Imported-{hash_val[:8]}'
                            mtype = parts[2] if len(parts) > 2 else 'import'
                            severity = parts[3] if len(parts) > 3 else 'high'
                            lines.append((hash_val, name, mtype, severity))

            _BATCH_SIZE = 500
            count = 0
            with self._lock:
                cursor = self._conn.cursor()
                batch = []
                for hash_val, name, mtype, severity in lines:
                    batch.append((hash_val, name, mtype, severity, '', txt_path))
                    if len(batch) >= _BATCH_SIZE:
                        actual_inserted, inserted_hashes = self._batch_insert_ignore(cursor, batch)
                        count += actual_inserted
                        self._conn.commit()
                        if inserted_hashes:
                            for sig in batch:
                                sha = sig[0]
                                if sha in inserted_hashes:
                                    self._malware_hashes.add(sha)
                                    self._malware_info[sha] = {
                                        'name': sig[1], 'type': sig[2],
                                        'severity': sig[3], 'description': ''
                                    }
                        batch.clear()
                if batch:
                    actual_inserted, inserted_hashes = self._batch_insert_ignore(cursor, batch)
                    count += actual_inserted
                    self._conn.commit()
                    if inserted_hashes:
                        for sig in batch:
                            sha = sig[0]
                            if sha in inserted_hashes:
                                self._malware_hashes.add(sha)
                                self._malware_info[sha] = {
                                    'name': sig[1], 'type': sig[2],
                                    'severity': sig[3], 'description': ''
                                }
                    batch.clear()

            logger.info(f'成功从 TXT 导入 {count} 个签名')
            return count
        except Exception as e:
            logger.error(f'从 TXT 导入签名失败: {e}')
            return 0

    def import_from_db(self, db_path: str) -> int:
        """从另一个SQLite数据库导入签名

        Returns:
            导入的签名数量；-1 表示该DB不是PSLS签名库格式（缺少表）

        优化：分批提交（每 _BATCH_SIZE 条 commit 一次）。
        """
        try:
            dest_conn = sqlite3.connect(db_path)
            dest_cursor = dest_conn.cursor()
            # 先检查表是否存在，避免抛出异常
            dest_cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='malware_signatures'"
            )
            if not dest_cursor.fetchone():
                dest_conn.close()
                logger.debug(f'DB 文件不是签名库格式（无 malware_signatures 表）: {db_path}')
                return -1
            rows = dest_cursor.execute(
                'SELECT hash_sha256, name, type, severity, description FROM malware_signatures'
            ).fetchall()
            dest_conn.close()

            _BATCH_SIZE = 500
            count = 0
            with self._lock:
                cursor = self._conn.cursor()
                batch = []
                for row in rows:
                    hash_val = row[0]
                    batch.append((hash_val, row[1], row[2], row[3], row[4] or '', db_path))
                    if len(batch) >= _BATCH_SIZE:
                        actual_inserted, inserted_hashes = self._batch_insert_ignore(cursor, batch)
                        count += actual_inserted
                        self._conn.commit()
                        if inserted_hashes:
                            for sig in batch:
                                sha = sig[0]
                                if sha in inserted_hashes:
                                    self._malware_hashes.add(sha)
                                    self._malware_info[sha] = {
                                        'name': sig[1], 'type': sig[2],
                                        'severity': sig[3], 'description': sig[4] or ''
                                    }
                        batch.clear()
                if batch:
                    actual_inserted, inserted_hashes = self._batch_insert_ignore(cursor, batch)
                    count += actual_inserted
                    self._conn.commit()
                    if inserted_hashes:
                        for sig in batch:
                            sha = sig[0]
                            if sha in inserted_hashes:
                                self._malware_hashes.add(sha)
                                self._malware_info[sha] = {
                                    'name': sig[1], 'type': sig[2],
                                    'severity': sig[3], 'description': sig[4] or ''
                                }
                    batch.clear()

            logger.info(f'成功从 DB 导入 {count} 个签名')
            return count
        except Exception as e:
            logger.error(f'从 DB 导入签名失败: {e}')
            return -1

    def export_to_db(self, export_path: str) -> bool:
        """导出签名库到 SQLite 数据库文件

        导出的数据库包含 malware_signatures 表，可直接导入到另一个 PSLS 实例。

        Args:
            export_path: 导出文件保存路径

        Returns:
            True 表示成功，False 表示失败
        """
        try:
            # 解析相对路径到可写目录（避免打包模式下工作目录不可写）
            export_path = _resolve_export_path(export_path)

            # 确保目标目录存在
            export_dir = os.path.dirname(export_path)
            if export_dir and not os.path.exists(export_dir):
                os.makedirs(export_dir, exist_ok=True)

            # 若目标文件已存在则先删除，避免旧数据库结构残留
            if os.path.exists(export_path):
                try:
                    os.remove(export_path)
                except OSError:
                    pass

            # 连接到目标数据库
            dest_conn = sqlite3.connect(export_path)
            dest_cursor = dest_conn.cursor()

            # 创建 malware_signatures 表（与主库相同结构）
            dest_cursor.execute('''
                CREATE TABLE IF NOT EXISTS malware_signatures (
                    hash_sha256 TEXT PRIMARY KEY,
                    name TEXT,
                    type TEXT,
                    severity TEXT,
                    description TEXT,
                    source TEXT,
                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 导出恶意软件签名
            with self._lock:
                cursor = self._conn.cursor()
                cursor.execute(
                    'SELECT hash_sha256, name, type, severity, description, source, added_date '
                    'FROM malware_signatures ORDER BY added_date DESC'
                )
                rows = cursor.fetchall()
                count = 0
                for row in rows:
                    dest_cursor.execute('''
                        INSERT OR REPLACE INTO malware_signatures
                        (hash_sha256, name, type, severity, description, source, added_date)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', row)
                    count += 1
                dest_conn.commit()

            logger.info(f'成功导出 {count} 个签名到 {export_path}')
            dest_conn.close()
            return True

        except Exception as e:
            logger.error(
                f'导出签名库失败: {e}\n'
                f'  导出路径: {export_path}\n'
                f'  目录存在: {os.path.exists(os.path.dirname(export_path)) if export_path else "N/A"}\n'
                f'  目录可写: {os.access(os.path.dirname(export_path), os.W_OK) if export_path and os.path.exists(os.path.dirname(export_path)) else "N/A"}'
            )
            return False

    def export_to_json(self, export_path: str) -> bool:
        """导出签名库到 JSON 文件

        Args:
            export_path: 导出文件保存路径

        Returns:
            True 表示成功，False 表示失败
        """
        try:
            # 解析相对路径到可写目录
            export_path = _resolve_export_path(export_path)

            # 确保目标目录存在
            export_dir = os.path.dirname(export_path)
            if export_dir and not os.path.exists(export_dir):
                os.makedirs(export_dir, exist_ok=True)

            signatures = []
            with self._lock:
                cursor = self._conn.cursor()
                cursor.execute(
                    'SELECT hash_sha256, name, type, severity, description, source, added_date '
                    'FROM malware_signatures ORDER BY added_date DESC'
                )
                for row in cursor.fetchall():
                    signatures.append({
                        'hash_sha256': row[0],
                        'name': row[1],
                        'type': row[2],
                        'severity': row[3],
                        'description': row[4],
                        'source': row[5],
                        'added_date': row[6]
                    })

            data = {
                'version': 1,
                'type': 'psls_signature_db',
                'count': len(signatures),
                'signatures': signatures
            }

            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            logger.info(f'成功导出 {len(signatures)} 个签名到 {export_path}')
            return True

        except Exception as e:
            logger.error(
                f'导出签名库 JSON 失败: {e}\n'
                f'  导出路径: {export_path}\n'
                f'  目录存在: {os.path.exists(os.path.dirname(export_path)) if export_path else "N/A"}\n'
                f'  目录可写: {os.access(os.path.dirname(export_path), os.W_OK) if export_path and os.path.exists(os.path.dirname(export_path)) else "N/A"}'
            )
            return False

    # ================================================================ #
    #  auto_yara_rules 表操作                                            #
    # ================================================================ #

    def upsert_yara_rule(self, rule_name: str, rule_content: str,
                         hash_sha256: str = '', signature_id: str = '',
                         severity: str = 'high', feature_count: int = 0,
                         file_size: int = 0, sample_type: str = 'unknown',
                         rule_source: str = 'auto') -> Optional[int]:
        """插入或更新一条 auto_yara_rule，返回其 id。"""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute('SELECT id FROM auto_yara_rules WHERE rule_name = ?', (rule_name,))
            row = cursor.fetchone()
            try:
                if row:
                    rid = row[0]
                    cursor.execute('''
                        UPDATE auto_yara_rules
                        SET hash_sha256=?, rule_content=?, rule_source=?, signature_id=?,
                            severity=?, feature_count=?, file_size=?, sample_type=?, is_active=1
                        WHERE id=?
                    ''', (hash_sha256, rule_content, rule_source, signature_id,
                         severity, feature_count, file_size, sample_type, rid))
                else:
                    cursor.execute('''
                        INSERT INTO auto_yara_rules
                        (rule_name, hash_sha256, rule_content, rule_source, signature_id,
                         severity, feature_count, file_size, sample_type)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (rule_name, hash_sha256, rule_content, rule_source, signature_id,
                         severity, feature_count, file_size, sample_type))
                    rid = cursor.lastrowid
                self._conn.commit()
                return rid
            except Exception as e:
                logger.error(f'upsert_yara_rule 失败: {e}')
                return None

    def get_active_yara_rules(self, limit: int = 0) -> List[Dict]:
        """获取所有启用的自动 YARA 规则。"""
        with self._lock:
            cursor = self._conn.cursor()
            sql = '''
                SELECT id, rule_name, hash_sha256, rule_content, severity,
                       feature_count, file_size, sample_type
                FROM auto_yara_rules WHERE is_active = 1
                ORDER BY id
            '''
            if limit > 0:
                sql += f' LIMIT {int(limit)}'
            cursor.execute(sql)
            return [
                {
                    'id': r[0], 'rule_name': r[1], 'hash_sha256': self._to_str(r[2]),
                    'rule_content': self._to_str(r[3]), 'severity': self._to_str(r[4]),
                    'feature_count': r[5], 'file_size': r[6],
                    'sample_type': self._to_str(r[7]),
                }
                for r in cursor.fetchall()
            ]

    def get_yara_rule_by_hash(self, hash_sha256: str) -> Optional[Dict]:
        """根据签名哈希查对应的 YARA 规则。"""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                'SELECT id, rule_name, rule_content, severity FROM auto_yara_rules '
                'WHERE hash_sha256 = ? AND is_active = 1 LIMIT 1',
                (hash_sha256,)
            )
            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0], 'rule_name': self._to_str(row[1]),
                    'rule_content': self._to_str(row[2]), 'severity': self._to_str(row[3]),
                }
            return None

    def deactivate_yara_rule(self, rule_id: int) -> bool:
        """停用一条 YARA 规则（软删除）。"""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute('UPDATE auto_yara_rules SET is_active = 0 WHERE id = ?', (rule_id,))
            self._conn.commit()
            return cursor.rowcount > 0

    def count_yara_rules(self, active_only: bool = True) -> int:
        with self._lock:
            cursor = self._conn.cursor()
            if active_only:
                cursor.execute('SELECT COUNT(*) FROM auto_yara_rules WHERE is_active = 1')
            else:
                cursor.execute('SELECT COUNT(*) FROM auto_yara_rules')
            return cursor.fetchone()[0]

    # ================================================================ #
    #  签名扩展字段辅助操作（回填用）                                     #
    # ================================================================ #

    def update_signature_fuzzy(self, hash_sha256: str, fuzzy_hash: str):
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                'UPDATE malware_signatures SET fuzzy_hash = ? WHERE hash_sha256 = ?',
                (fuzzy_hash, hash_sha256)
            )
            self._conn.commit()

    def lookup_signatures_without_yara(self, limit: int = 500) -> List[Dict]:
        """查询还没生成 YARA 规则的签名哈希列表（回填脚本用）。"""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute('''
                SELECT hash_sha256, name, type, severity
                FROM malware_signatures
                WHERE yara_rule_id IS NULL OR yara_rule_id = 0
                ORDER BY added_date DESC
                LIMIT ?
            ''', (limit,))
            return [
                {
                    'hash': r[0], 'name': self._to_str(r[1]),
                    'type': self._to_str(r[2]), 'severity': self._to_str(r[3]),
                }
                for r in cursor.fetchall()
            ]

    def lookup_signatures_without_fuzzy(self, limit: int = 500) -> List[Dict]:
        """查询还没算 fuzzy_hash 的签名（回填脚本用）。"""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute('''
                SELECT hash_sha256, name
                FROM malware_signatures
                WHERE fuzzy_hash IS NULL OR fuzzy_hash = ''
                ORDER BY added_date DESC
                LIMIT ?
            ''', (limit,))
            return [
                {'hash': r[0], 'name': self._to_str(r[1])}
                for r in cursor.fetchall()
            ]

    # ================================================================ #
    #  模糊哈希查找（扫描引擎用）                                        #
    # ================================================================ #

    def match_by_fuzzy_hash(self, fuzzy: str, threshold: int = 75,
                            limit: int = 20) -> List[Dict]:
        """在已入库签名中做模糊哈希相似度匹配。

        惰性加载所有带 fuzzy_hash 的签名到临时列表，用纯 Python compare。
        threshold: 相似度阈值（0-100），默认 75。
        """
        try:
            from utils.fuzzy_hash import fuzzy_compare
        except ImportError:
            return []

        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                'SELECT hash_sha256, fuzzy_hash, name, type, severity '
                'FROM malware_signatures '
                'WHERE fuzzy_hash IS NOT NULL AND fuzzy_hash != ""'
            )
            rows = cursor.fetchall()

        results = []
        for row in rows:
            sha, fuzzy_stored, name, mtype, sev = row
            sim = fuzzy_compare(fuzzy, fuzzy_stored or '')
            if sim >= threshold:
                results.append({
                    'hash': sha, 'name': self._to_str(name),
                    'type': self._to_str(mtype), 'severity': self._to_str(sev),
                    'similarity': sim,
                })
                if len(results) >= limit:
                    break
        results.sort(key=lambda x: -x['similarity'])
        return results

    def _generate_yara_for_entry(self, sha256: str, name: str, severity: str,
                                 sample_path: Optional[str]) -> bool:
        """为单个签名生成 YARA 规则（源文件缺失时回退为哈希规则）。

        优先基于源文件内容生成特征规则；当源文件已被删除（或特征不足）时，
        退化为仅凭 SHA-256 的哈希匹配规则，确保重复导入也能产出 YARA 规则。
        """
        try:
            from engine.yara_generator import YaraGenerator
            gen = YaraGenerator()
            result = None
            if sample_path and os.path.isfile(sample_path):
                result = gen.generate(
                    sample_path, sha256=sha256,
                    name=name or os.path.basename(sample_path),
                    severity=severity,
                )
            if not result:
                # 源文件缺失 / 特征不足 → 生成哈希匹配规则
                result = gen.generate_hash_rule(sha256=sha256, name=name,
                                                severity=severity)
            if not result:
                return False

            rid = self.upsert_yara_rule(
                rule_name=result['rule_name'],
                hash_sha256=sha256,
                rule_content=result['rule_content'],
                severity=severity,
                feature_count=result['feature_count'],
                file_size=result['file_size'],
                sample_type=result['sample_type'],
            )
            if not rid:
                return False

            with self._lock:
                cur = self._conn.cursor()
                cur.execute(
                    'UPDATE malware_signatures SET yara_rule_id = ?, last_yara_gen = ? '
                    'WHERE hash_sha256 = ?',
                    (rid, datetime.now().isoformat(timespec='seconds'), sha256)
                )
                self._conn.commit()
            logger.info(f'已为 {sha256[:12]} 生成 YARA 规则: {result["rule_name"]}')
            return True
        except Exception as e:
            logger.warning(f'YARA 规则生成失败 {sha256[:12]}: {e}')
            return False

    def backfill_yara_rules(self, progress_cb=None) -> int:
        """为所有缺失 YARA 规则的存量签名生成规则（源文件缺失时用哈希规则）。

        用于病毒源文件已删除的场景：重复导入 / 主动回填时，无需源文件内容
        也能为库内签名产出（哈希匹配）YARA 规则。

        Args:
            progress_cb: 可选回调 progress_cb(done, total)

        Returns:
            实际生成的规则数量
        """
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                'SELECT hash_sha256, name, type, severity, sample_path '
                'FROM malware_signatures '
                'WHERE yara_rule_id IS NULL OR yara_rule_id = 0'
            )
            rows = cursor.fetchall()

        total = len(rows)
        generated = 0
        for i, (sha, name, mtype, sev, spath) in enumerate(rows, 1):
            if self._generate_yara_for_entry(sha, name, sev, spath):
                generated += 1
            if progress_cb and (i % 50 == 0 or i == total):
                try:
                    progress_cb(i, total)
                except Exception:
                    pass
        logger.info(f'YARA 规则回填完成: 需处理{total}, 生成{generated}')
        return generated

    def load_from_sample_dir(self, dir_path: str, recursive: bool = True,
                            auto_yara: bool = False, source: str = 'samples_dir',
                            progress_cb=None, name_map: Optional[dict] = None) -> dict:
        """从恶意样本文件目录批量导入签名（计算 SHA-256 + 从文件名解析威胁名）

        典型输入: VirusTotal/威胁情报平台导出的样本目录，文件命名如
          Backdoor.MSIL.AsyncRat.y-XXXXhashXXXX.exe
          Trojan.Generic.KD-a3b5c6d789ab0cde.exe
        输出: 入库的 (sha256, name, type='high') 条目，同时 sample_path
              指向原文件供后续 _enrich_from_sample 使用（auto_yara=True 时自动生成）

        Args:
            dir_path: 样本目录路径
            recursive: 是否递归扫描子目录（默认 True）
            auto_yara: 是否自动为每个样本生成 YARA 规则（默认 False，批量导入时较慢）
            source: 签名来源标记
            progress_cb: 可选回调 progress_cb(done, total, current_name)，供 UI 进度显示
            name_map: 可选的 文件名（小写，含扩展名）→ 元数据 覆盖映射：
                - 键存在且值为 (name, type) → 显式使用该威胁名/类型
                - 键存在且值为 None           → 跳过该文件（不导入）
                - 键不存在                  → 回退到文件名自动解析（默认行为）
                供 MalwareBazaar 等以 hash 命名的样本导入，用 manifest 元数据补全威胁名。

        Returns:
            {'total': 扫描文件总数, 'added': 实际新增哈希数,
             'skipped': 已存在/无效文件数, 'errors': 计算失败数}
        """
        import re

        if not os.path.isdir(dir_path):
            logger.error(f'样本目录不存在: {dir_path}')
            return {'total': 0, 'added': 0, 'skipped': 0, 'errors': 0}

        # ---- 收集文件列表 ----
        file_list = []
        if recursive:
            for root, _, files in os.walk(dir_path):
                for fn in files:
                    file_list.append(os.path.join(root, fn))
        else:
            for fn in os.listdir(dir_path):
                p = os.path.join(dir_path, fn)
                if os.path.isfile(p):
                    file_list.append(p)

        total = len(file_list)
        if total == 0:
            logger.warning(f'目录中无文件: {dir_path}')
            return {'total': 0, 'added': 0, 'skipped': 0, 'errors': 0}

        logger.info(f'样本目录导入: {dir_path}, 共发现 {total} 个文件')

        # ---- 文件名 → (name, type) 解析 ----
        # 常见模式: Category.Family.Variant.[subtype]-xxxxhashxxxx
        _KNOWN_TYPES = {
            'trojan', 'backdoor', 'worm', 'virus', 'ransomware', 'ransom',
            'spyware', 'adware', 'rootkit', 'dropper', 'downloader',
            'keylogger', 'infostealer', 'stealer', 'cryptominer', 'miner',
            'exploit', 'wmi', 'hacktool', 'grayware', 'heur', 'generic',
        }

        def _parse_filename(filename: str):
            """从文件名解析威胁名称和类型。

            'Backdoor.MSIL.AsyncRat.y-abc123.exe' → ('Backdoor.MSIL.AsyncRat', 'Backdoor')
            'Trojan.Generic.KD-a3b5c6d7.exe'       → ('Trojan.Generic.KD', 'Trojan')
            'unknown.exe'                           → ('unknown', 'Unknown')
            """
            name_no_ext = os.path.splitext(filename)[0]
            # 去掉尾部的 -hash / y-hash / .hash 后缀
            cleaned = re.sub(r'[-_.][a-f0-9]{8,}$', '', name_no_ext, flags=re.IGNORECASE)
            cleaned = re.sub(r'[-_.]y$', '', cleaned, flags=re.IGNORECASE)  # y=yellow VT 标记

            # 第一段作为类型（小写化匹配已知类别）
            first_seg = cleaned.split('.')[0].split('-')[0].lower()
            if first_seg in _KNOWN_TYPES:
                mtype = cleaned.split('.')[0]
            else:
                mtype = 'Unknown'

            name = cleaned if cleaned else filename
            return name, mtype

        def _sha256_file(path: str, chunk_size: int = 1 << 20) -> Optional[str]:
            h = hashlib.sha256()
            try:
                with open(path, 'rb') as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        h.update(chunk)
                return h.hexdigest()
            except (OSError, IOError):
                return None

        # ---- 逐文件计算（分批入库）----
        _BATCH_SIZE = 500
        valid_entries = []      # [(sha256, name, type, 'high', '', source, sample_path), ...]
        all_entries = []        # 累积全部条目，用于 YARA 规则生成
        skipped = 0
        errors = 0
        done = 0

        for fpath in file_list:
            done += 1
            fname = os.path.basename(fpath)

            # 跳过太小/明显非样本的
            try:
                fsize = os.path.getsize(fpath)
            except OSError:
                errors += 1
                continue
            if fsize == 0 or fsize > 512 * 1024 * 1024:  # 空文件或 >512MB 跳过
                skipped += 1
                continue

            sha = _sha256_file(fpath)
            if not sha:
                errors += 1
                continue

            # name_map 覆盖（MB 等 hash 命名样本：None=跳过，元组=显式威胁名）
            map_entry = name_map.get(fname.lower()) if name_map else None
            if map_entry is None and name_map is not None and fname.lower() in name_map:
                # 显式跳过（manifest 判定为无威胁名/不导入）
                skipped += 1
                continue
            if map_entry is not None:
                name, mtype = map_entry
            else:
                name, mtype = _parse_filename(fname)
            entry = (sha, name, mtype, 'high', '', source, fpath)
            valid_entries.append(entry)
            all_entries.append(entry)

            if progress_cb and (done % 100 == 0 or done == total):
                try:
                    progress_cb(done, total, fname)
                except Exception:
                    pass

            if len(valid_entries) >= _BATCH_SIZE:
                self._batch_insert_samples(valid_entries)
                valid_entries = []

        if valid_entries:
            added = self._batch_insert_samples(valid_entries)
        else:
            added = 0

        # ---- 生成 YARA 规则（auto_yara=True 时）----
        if auto_yara:
            # 为本次导入的每条签名生成规则（源文件仍在 → 特征规则；缺失 → 哈希规则）
            for (sha, name, mtype, sev, desc, src, spath) in all_entries:
                self._generate_yara_for_entry(sha, name, sev, spath)

            # 源文件已删除的存量签名 → 回填哈希 YARA 规则，保证重复导入也能产出
            def _yara_cb(y_done, y_total):
                if progress_cb:
                    try:
                        progress_cb(y_done, y_total, f'生成 YARA 规则 {y_done}/{y_total}')
                    except Exception:
                        pass

            self.backfill_yara_rules(progress_cb=_yara_cb)

        logger.info(
            f'样本目录导入完成: 总{total}文件, 新增{added}, '
            f'跳过{skipped}, 计算失败{errors}'
        )
        return {'total': total, 'added': added, 'skipped': skipped, 'errors': errors}

    def _batch_insert_samples(self, entries: list) -> int:
        """批量插入样本签名 + 内存缓存更新。"""
        _BATCH_SIZE = 500
        count = 0
        with self._lock:
            cursor = self._conn.cursor()
            batch = []
            for sha, name, mtype, sev, desc, src, spath in entries:
                batch.append((sha, name, mtype, sev, desc, src))
                if len(batch) >= _BATCH_SIZE:
                    actual_inserted, inserted_hashes = self._batch_insert_ignore(
                        cursor, batch, debug_label=f'sample_dir批次#{count // _BATCH_SIZE + 1}'
                    )
                    count += actual_inserted
                    self._conn.commit()
                    if inserted_hashes:
                        for sig in batch:
                            sha256 = sig[0]
                            if sha256 in inserted_hashes:
                                self._malware_hashes.add(sha256)
                                self._malware_info[sha256] = {
                                    'name': sig[1], 'type': sig[2],
                                    'severity': sig[3], 'description': sig[4]
                                }
                    batch.clear()

            if batch:
                actual_inserted, inserted_hashes = self._batch_insert_ignore(cursor, batch)
                count += actual_inserted
                self._conn.commit()
                if inserted_hashes:
                    for sig in batch:
                        sha256 = sig[0]
                        if sha256 in inserted_hashes:
                            self._malware_hashes.add(sha256)
                            self._malware_info[sha256] = {
                                'name': sig[1], 'type': sig[2],
                                'severity': sig[3], 'description': sig[4]
                            }

            # ---- sample_path 补写到扩展列 ----
            sample_updates = [(spath, sha) for sha, _, _, _, _, _, spath in entries
                              if sha in self._malware_hashes and spath]
            if sample_updates:
                cursor.executemany(
                    'UPDATE malware_signatures SET sample_path = ? WHERE hash_sha256 = ?',
                    sample_updates
                )
                self._conn.commit()

        return count

    def close(self):
        """关闭数据库连接"""
        if self._conn:
            self._conn.close()
    
    def __del__(self):
        """析构函数，安全关闭数据库连接"""
        try:
            self.close()
        except Exception:
            # 忽略线程安全相关的异常
            pass

if __name__ == '__main__':
    # 初始化数据库并添加一些测试签名
    db = SignatureDB()
    
    # 添加测试恶意软件签名（示例哈希，非真实恶意软件）
    test_malware = [
        ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Test.Malware.1', 'Trojan'),
        ('d4a5a1568982889334e4287360b3f894c4667fa5a5d9610b8247d683f4b9899a', 'Test.Malware.2', 'Virus'),
        ('7c211433f02071597741e6ff5a8ea34789abbf4304b4b09389c05b8e9b7d8e8', 'Test.Malware.3', 'Ransomware'),
    ]
    
    for hash_val, name, mtype in test_malware:
        db.add_signature(hash_val, name, mtype)
    
    # 添加测试启发式规则
    db.add_heuristic_rule(
        'Suspicious.FileName',
        'filename',
        r'(?i)(malware|virus|trojan|ransom|cryptominer)\.(exe|dll|bat|cmd|ps1)',
        1,
        'high',
        '包含可疑关键词的文件名'
    )
    
    db.add_heuristic_rule(
        'Suspicious.Extension',
        'extension',
        r'\.(scr|pif|hta|msi|msp|com|cpl)',
        1,
        'medium',
        '可疑的文件扩展名'
    )
    
    print("数据库初始化完成，测试签名已添加")
