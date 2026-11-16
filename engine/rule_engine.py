# -*- coding: utf-8 -*-
"""
规则引擎 - 集成 YARA 工业级规则引擎 + 自研规则降级方案

参照 rule_scanner 设计：
1. 优先使用 YARA 引擎（yara-python）进行高速模式匹配
2. YARA 不可用时降级到自研 Python 规则引擎
3. 支持文件扫描和进程内存扫描（YARA match(pid=pid)）
4. 支持编译规则缓存（.yc 文件）加速启动
"""
import os
import re
import sys
import time
import threading
from typing import List, Dict, Optional

from utils.logger import get_logger
from utils.hash_utils import open_with_retry

logger = get_logger('rule_engine')

# 子进程窗口隐藏标志（Windows 平台阻止弹出黑色 cmd 窗口）
_HIDDEN_CREATIONFLAGS = 0x08000000 if sys.platform == 'win32' else 0

# 尝试导入 YARA
# 注意：必须捕获 Exception 而非仅 ImportError。系统 Python 的 yara-python
# 若安装损坏（如缺失 libyara.dll），import yara 会抛出 FileNotFoundError /
# OSError，若只捕获 ImportError 将导致启动即崩溃（闪退）。
try:
    import yara
    HAS_YARA = True
except Exception:
    HAS_YARA = False
    yara = None

# 尝试导入便携 YARA 桥接
try:
    from engine.yara_portable import YaraPortable
    HAS_PORTABLE_YARA = True
except Exception:
    HAS_PORTABLE_YARA = False
    YaraPortable = None

if not HAS_YARA:
    logger.warning('yara-python 未安装，规则引擎降级为 Python 模式')


# ============================================================================
# severity 归一化（唯一集中映射点）
# ----------------------------------------------------------------------------
# 背景：PSLS 计分按字符串严重度计数（scan_engine._sev_count / rule_high_count
# 均用 `m.get('severity') == 'high'` 比较），而 Elastic protections-artifacts 的
# 规则 meta.severity 是数值型（100/90/50…）。直接把数值塞进流水线会导致所有
# 比较失配 → 规则"只显示、不计分、不告警"。
#
# 解决方案：在 YARA meta 进入扫描流水线的唯一入口 rule_engine._match_rules_obj
# 处，把数值 severity 归一化为 high/medium/low；非数值字符串（PSLS 现有规则的
# 'high'/'medium'/'low'/'info' 等）原样返回 → 现有规则行为完全不变。
#
# 阈值依据（Elastic 实际分布，本子集 1902 条入选规则；已剔除 109 条高误报规则）：
#   severity=100 → 620 条，90 → 7 条，99 → 2 条（合计 629 条，占 33%）
#   severity=50  → 1262 条（占 66%）
#   其余 <50（1/10/25/49）仅 4 条
# Elastic 用 90-100 表示极高危（critical 级），50 表示 medium 级。故取
#   >=90 → high、>=50 → medium、<50 → low
# 该阈值"偏保守"（80/84/85 归 medium 而非 high），利于降误报。
# ============================================================================
_YARA_SEV_HIGH_MIN = 90.0
_YARA_SEV_MEDIUM_MIN = 50.0


def normalize_severity(value) -> str:
    """把 YARA meta.severity 归一化为 high/medium/low。

    - 数值（int/float 或纯数字字符串，如 100/50/'90'）→ 按阈值映射；
    - 非数值字符串（如 'high'/'medium'/'low'/'info'/'critical'）→ 原样返回，
      保证 PSLS 现有规则的字符串 severity 行为不变。
      其中 'low' 亦覆盖"强制降权"来源：Elastic Hacktool 规则由
      scripts/fetch_elastic_yara.py 把 meta.severity 改写为字符串 "low"
      （保留但降权，见该脚本 _force_low_severity）→ 此处原样透传为 'low'，
      不改动其它规则的 severity 语义。

    Args:
        value: meta['severity'] 原始值（可能是 int/float/str/None）

    Returns:
        归一化后的严重度字符串
    """
    if value is None:
        return 'medium'
    s = str(value).strip()
    try:
        num = float(s)
    except (TypeError, ValueError):
        # 非数值字符串：保持既有语义不变
        return s
    if num >= _YARA_SEV_HIGH_MIN:
        return 'high'
    if num >= _YARA_SEV_MEDIUM_MIN:
        return 'medium'
    return 'low'


def _get_python_executable() -> Optional[str]:
    """获取可用于运行 Python 代码的解释器路径

    在 PyInstaller 打包环境下 sys.executable 指向打包后的 exe（不支持 -c 参数），
    此时优先使用便携 Python，否则尝试在 PATH 中查找 python.exe。
    """
    import sys
    if not getattr(sys, 'frozen', False):
        return sys.executable
    # 打包环境：优先使用便携 Python
    try:
        from engine.yara_portable import _PYTHON_EXE
        if os.path.exists(_PYTHON_EXE):
            return _PYTHON_EXE
    except Exception:
        pass
    # 尝试在 PATH 中查找
    import shutil
    python_in_path = shutil.which('python.exe') or shutil.which('python')
    if python_in_path:
        return python_in_path
    return None


# YARA 规则目录（相对项目根目录）
_YARA_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'rules', 'yara'
)

# 编译规则缓存路径
# 打包模式下 _YARA_RULES_DIR 指向只读临时目录 _MEIxxxxx，
# 加载缓存从该目录读取（只读OK），但保存缓存需要可写目录。
_YARA_COMPILED_CACHE = os.path.join(_YARA_RULES_DIR, 'compiled.yc')


def _get_writable_cache_path() -> str:
    """获取可写的编译缓存路径

    打包模式下 _YARA_COMPILED_CACHE 位于只读临时目录，
    保存编译缓存时需要使用 %APPDATA%\\PSLS\\ 下的可写路径。
    """
    if getattr(sys, 'frozen', False):
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
        return os.path.join(psls_dir, 'yara_compiled.yc')
    return _YARA_COMPILED_CACHE


def _get_all_yara_cache_paths() -> List[str]:
    """获取所有可能的 YARA 编译缓存路径（按优先级排序）

    解决 PyInstaller 打包后 __file__ 路径不一致的问题，
    覆盖多种可能的文件布局。
    """
    paths = []

    # 1. 可写缓存路径（用户 APPDATA 目录）
    paths.append(_get_writable_cache_path())

    # 2. 基于 __file__ 计算的路径（开发模式和标准打包模式）
    paths.append(_YARA_COMPILED_CACHE)

    # 3. 打包模式下的多种回退路径
    if getattr(sys, 'frozen', False):
        meipass = sys._MEIPASS
        exe_dir = os.path.dirname(sys.executable)

        paths.append(os.path.join(meipass, 'rules', 'yara', 'compiled.yc'))
        paths.append(os.path.join(meipass, 'compiled.yc'))
        paths.append(os.path.join(exe_dir, 'rules', 'yara', 'compiled.yc'))
        paths.append(os.path.join(exe_dir, 'compiled.yc'))

    # 去重
    seen = set()
    result = []
    for p in paths:
        norm = os.path.normpath(p)
        if norm not in seen:
            seen.add(norm)
            result.append(p)
    return result


def _get_writable_db_cache_path() -> str:
    """获取可写的 DB 自动 YARA 规则编译缓存路径（与文件规则缓存分开）。

    打包后 _YARA_RULES_DIR 为只读临时目录，必须保存到 %APPDATA%\\PSLS\\ 下。
    """
    base = _get_writable_cache_path()
    return os.path.join(os.path.dirname(base), 'yara_db_compiled.yc')


def _db_rules_fingerprint(db_rules) -> str:
    """计算 DB 自动 YARA 规则的指纹，用于校验编译缓存是否过期。

    以 (id, rule_content) 排序后做 SHA-256，DB 规则任何增删改都会改变指纹，
    从而触发重新编译；指纹一致则直接加载磁盘缓存，跳过耗时编译。
    """
    import hashlib
    h = hashlib.sha256()
    for r in sorted(db_rules, key=lambda x: str(x.get('id') or x.get('rule_id') or '')):
        rid = str(r.get('id') or r.get('rule_id') or '')
        content = r.get('rule_content') or ''
        h.update(rid.encode('utf-8', 'ignore'))
        h.update(b'\x00')
        h.update(content.encode('utf-8', 'ignore'))
        h.update(b'\x00')
    return h.hexdigest()


def _yara_files_fingerprint(yara_files: dict) -> str:
    """计算磁盘 YARA 规则文件集合的指纹，用于校验文件规则编译缓存是否过期。

    用料：排序后的 (namespace, size, mtime_ns) 逐项 + 规则文件总数 → SHA-256。
    规则文件任何增删改（含内容变化导致 mtime/size 变化）都会改变指纹，从而
    触发重新编译；指纹一致则直接加载 compiled.yc，跳过耗时全量编译。
    （DB 规则缓存另有 _db_rules_fingerprint，行为不变。）
    """
    import hashlib
    h = hashlib.sha256()
    for ns in sorted(yara_files or {}):
        p = yara_files[ns]
        try:
            st = os.stat(p)
            size, mtime = int(st.st_size), int(st.st_mtime_ns)
        except OSError:
            size, mtime = -1, -1
        h.update(str(ns).encode('utf-8', 'ignore'))
        h.update(b'\x00')
        h.update(f'{size}:{mtime}'.encode('ascii', 'ignore'))
        h.update(b'\x00')
    h.update(str(len(yara_files or {})).encode('ascii'))
    return h.hexdigest()


class RuleEngine:
    """规则引擎 - YARA 优先，自研降级

    扫描流程：
    1. YARA 可用：使用编译后的 YARA 规则进行高速匹配
    2. YARA 不可用：降级到自研 Python 规则引擎
    3. 文件名/扩展名规则始终由自研引擎处理（YARA 不擅长）
    """

    def __init__(self, signature_db=None):
        """初始化规则引擎

        Args:
            signature_db: 可选的已实例化 SignatureDB（复用桥接层/扫描引擎实例，
                          避免启动时重复加载整个数据库，显著降低启动耗时）。
                          为 None 时按需自建。
        """
        self._signature_db = signature_db
        # 自研内置规则（始终加载，补充 YARA 不擅长的文件名/扩展名规则）
        self._builtin_rules = self._load_builtin_rules()

        # YARA 引擎：磁盘文件规则 + DB 自动规则（分开编译，scan 时合并）
        self._yara_rules = None       # 文件规则（.yar/.yara from disk）
        self._yara_rules_db = None    # auto_yara_rules 表规则
        self._yara_available = HAS_YARA
        self._yara_user_enabled = True  # 默认启用，用户可手动关闭

        # ---- 加速启动：YARA 规则懒加载状态 ----
        # 规则编译（尤其 DB 自动规则上万条）耗时较长，全部转到后台线程执行，
        # __init__ 立即返回，不阻塞 PSLS 启动关键路径。
        # _yara_rules_ready 置位后规则才可被扫描使用；扫描在未就绪前回落到自研规则。
        self._yara_rules_ready = False
        self._yara_loading = False
        self._yara_load_thread: Optional[threading.Thread] = None
        self._yara_load_lock = threading.Lock()

        # ---- 降载：高负载时跳过重型 YARA 规则 / 降低自研最大扫描尺寸 ----
        # "重型规则"定义：包含 loops / math / regex / pe.imphash / hash 等昂贵子句。
        # 当前通过两条开关实现：
        #   1) _skip_heavy_rules(bool): 高负载时对 > 64MB 的 PE/压缩包
        #      以及重型 YARA 规则不做字节扫描，文件名/扩展名规则仍运行。
        #   2) _max_scan_bytes(int): 单文件字节读取上限（默认 128MB；高负载缩到 8MB）
        self._skip_heavy_rules = False
        self._max_scan_bytes = 128 * 1024 * 1024
        # 编译过程与扫描读取之间的保护锁（yara.compile 写 self._yara_rules*）
        self._yara_lock = threading.Lock()

        # 威胁情报数据库（IP/域名黑名单）
        # 惰性加载，避免循环依赖和启动延迟
        self._threat_intel = None
        self._threat_intel_loaded = False

        # 便携 YARA 桥接（当 yara-python 无法安装在当前 Python 时使用）
        self._yara_portable = None
        self._yara_portable_available = False
        if HAS_PORTABLE_YARA and not self._yara_available:
            self._yara_portable = YaraPortable()
            if self._yara_portable.is_available():
                self._yara_portable_available = True
                self._yara_available = True
                logger.info('使用便携 Python YARA 桥接')

        if self._yara_available:
            self._start_yara_async_load()

    # ---- 内部工具：YARA 后台懒加载 ----

    def _start_yara_async_load(self):
        """后台线程加载 YARA 规则（文件规则 + DB 自动规则），不阻塞启动关键路径。"""
        def _loader():
            try:
                self._load_yara_rules()
            except Exception as e:
                logger.error(f'后台加载 YARA 规则异常: {e}')
            finally:
                with self._yara_lock:
                    self._yara_loading = False
                    self._yara_rules_ready = True
                logger.info('YARA 规则后台加载完成')

        with self._yara_lock:
            if self._yara_loading or self._yara_rules_ready:
                return
            self._yara_loading = True
        self._yara_load_thread = threading.Thread(
            target=_loader, name='PSLS-YaraLoad', daemon=True)
        self._yara_load_thread.start()

    def ensure_yara_ready(self, wait: float = 8.0) -> bool:
        """确保 YARA 规则就绪（阻塞等待后台加载，用于扫描/开关/内存检测等强依赖场景）。

        Returns:
            True=规则已就绪；False=加载失败或超时，调用方应回落自研规则。
        """
        if self._yara_rules_ready:
            return True
        # 未启动后台加载（如直接构造后立即扫描）→ 同步装载
        started = False
        with self._yara_load_lock:
            if not self._yara_loading and not self._yara_rules_ready:
                started = True
        if started:
            try:
                self._load_yara_rules()
                with self._yara_lock:
                    self._yara_rules_ready = True
                return True
            except Exception:
                with self._yara_lock:
                    self._yara_rules_ready = True
                return False
        # 等待后台加载完成（上限 wait 秒）
        deadline = time.time() + wait
        while time.time() < deadline and not self._yara_rules_ready:
            time.sleep(0.05)
        with self._yara_lock:
            return self._yara_rules_ready

    def _yara_scan_ready_pair(self):
        """线程安全读取 YARA 规则对象（files, db），未就绪返回 (None, None)。"""
        with self._yara_lock:
            return self._yara_rules, self._yara_rules_db

    # ---- YARA 引擎集成 ----

    def _load_yara_rules(self):
        """加载 YARA 规则（参照 rule_scanner.load_path）

        分两部分独立编译：
        1. self._yara_rules  — 文件规则（.yar/.yara from disk），可走磁盘编译缓存
        2. self._yara_rules_db — DB auto_yara_rules 内联规则，每次都从 DB 拉最新
        """
        # 仅当系统 yara-python 可用（HAS_YARA）时才直接编译。
        # 若系统 yara 损坏/未装但便携桥接可用（_yara_available 因 portable 为 True），
        # 直接编译会因 yara=None 抛错；此时磁盘+DB 规则由便携 worker 子进程负责。
        if not HAS_YARA:
            logger.info('系统 yara-python 不可用，YARA 直接编译跳过（由便携桥接子进程处理）')
            return
        if not self._yara_available:
            return
        # 后台线程加载期间置为"未就绪"，避免扫描提前使用半编译状态
        with self._yara_lock:
            self._yara_rules_ready = False

        db_rules = self._load_auto_rules_from_db()
        has_db_rules = bool(db_rules)

        # --- Part 1: 文件规则（磁盘缓存 + 指纹校验，避免改规则后不重编译） ---
        # 先扫描规则文件集合（指纹与编译都用它）
        search_dirs = [_YARA_RULES_DIR]
        if getattr(sys, 'frozen', False):
            meipass = sys._MEIPASS
            exe_dir = os.path.dirname(sys.executable)
            search_dirs.extend([
                os.path.join(meipass, 'rules', 'yara'),
                os.path.join(exe_dir, 'rules', 'yara'),
            ])

        yara_files = {}
        for rules_dir in search_dirs:
            if os.path.isdir(rules_dir):
                for root, _, files in os.walk(rules_dir):
                    for file in files:
                        ext = os.path.splitext(file)[1].lower()
                        if ext in ('.yara', '.yar'):
                            full_path = os.path.join(root, file)
                            namespace = os.path.relpath(full_path, rules_dir).replace(os.sep, '_')
                            yara_files[namespace] = full_path

        # 规则文件集合指纹（mtime+size + 文件数）：只有与缓存旁记录的指纹一致才
        # 加载 compiled.yc，否则视为"规则已变更" → 重新编译并刷新缓存。
        files_fp = _yara_files_fingerprint(yara_files) if yara_files else ''
        writable_cache = _get_writable_cache_path()
        files_fp_file = writable_cache + '.fp'

        cache_paths = _get_all_yara_cache_paths()
        loaded_from_cache = False
        # 仅当 DB 无自动规则时才考虑磁盘缓存（避免旧缓存不含新 DB 规则）
        if yara_files and not has_db_rules:
            for cache_path in cache_paths:
                if not (cache_path and os.path.exists(cache_path)
                        and os.path.getsize(cache_path) > 0):
                    continue
                _fp_file = cache_path + '.fp'
                if os.path.exists(_fp_file):
                    try:
                        with open(_fp_file, 'r', encoding='utf-8') as f:
                            saved_fp = f.read().strip()
                    except Exception:
                        saved_fp = ''
                    if saved_fp != files_fp:
                        logger.debug(
                            f'YARA 文件规则指纹变化，忽略缓存并重新编译: {cache_path}')
                        continue
                elif os.path.normcase(os.path.abspath(cache_path)) == \
                        os.path.normcase(os.path.abspath(writable_cache)):
                    # 可写缓存却缺少指纹（旧版本遗留）→ 无法确认新鲜度，重编译
                    logger.debug(f'可写 YARA 缓存缺少指纹，将重新编译: {cache_path}')
                    continue
                # 只读内置缓存且无指纹：规则随包固定，按旧行为加载
                try:
                    with self._yara_lock:
                        self._yara_rules = yara.load(cache_path)
                    loaded_from_cache = True
                    logger.info(f'已加载 YARA 编译缓存（指纹匹配）: {cache_path}')
                    break
                except Exception as e:
                    logger.warning(f'加载 YARA 编译缓存失败 {cache_path}: {e}')

        if yara_files and not loaded_from_cache:
            try:
                with self._yara_lock:
                    self._yara_rules = yara.compile(filepaths=yara_files)
                logger.info(f'已编译 {len(yara_files)} 个 YARA 文件规则')
                # 仅当 DB 无规则时才保存磁盘缓存（连同规则文件指纹）
                if not has_db_rules:
                    try:
                        with self._yara_lock:
                            self._yara_rules.save(writable_cache)
                        with open(files_fp_file, 'w', encoding='utf-8') as f:
                            f.write(files_fp)
                        logger.info(f'YARA 编译缓存已保存: {writable_cache}')
                    except Exception as e:
                        logger.debug(f'保存 YARA 编译缓存失败: {e}')
            except Exception as e:
                logger.error(f'编译 YARA 文件规则失败: {e}')
                with self._yara_lock:
                    self._yara_rules = None

        # --- Part 2: DB 自动规则（磁盘缓存 + 指纹校验，避免每次启动重编译上万条） ---
        with self._yara_lock:
            self._yara_rules_db = None
        if db_rules:
            try:
                db_cache_file = _get_writable_db_cache_path()
                db_fp_file = db_cache_file + '.fp'

                # 指纹匹配才加载缓存；指纹不一致说明 DB 规则已变化，需要重新编译
                fp = _db_rules_fingerprint(db_rules)
                loaded_from_cache = False
                if os.path.exists(db_cache_file) and os.path.getsize(db_cache_file) > 0:
                    try:
                        with open(db_fp_file, 'r', encoding='utf-8') as f:
                            saved_fp = f.read().strip()
                        if saved_fp == fp:
                            with self._yara_lock:
                                self._yara_rules_db = yara.load(db_cache_file)
                            loaded_from_cache = True
                            logger.info(
                                f'已从缓存加载 DB 自动 YARA 规则: {db_cache_file} ({len(db_rules)}条)')
                        else:
                            logger.debug('DB YARA 规则指纹变化，重新编译')
                    except Exception as e:
                        logger.warning(f'加载 DB YARA 编译缓存失败，将重新编译: {e}')
                        with self._yara_lock:
                            self._yara_rules_db = None

                if not loaded_from_cache or self._yara_rules_db is None:
                    # 把所有 DB 规则拼成一个大字符串一起编译；单条坏规则会导致
                    # 整批失败（'unexpected end of file'），故失败时回退分块剔除
                    with self._yara_lock:
                        rules_obj, ok_n, removed = self._compile_db_rules(db_rules)
                        if rules_obj is None:
                            self._yara_rules_db = None
                        else:
                            self._yara_rules_db = rules_obj
                    if rules_obj is None:
                        logger.error('编译 DB 自动 YARA 规则失败: 全部规则不可编译')
                    else:
                        logger.info(f'已编译 {ok_n} 条 DB 自动 YARA 规则'
                                    + (f'（剔除 {removed} 条坏规则）' if removed else ''))
                        # 保存缓存（连同指纹），下次启动直接加载
                        try:
                            os.makedirs(os.path.dirname(db_cache_file), exist_ok=True)
                            self._yara_rules_db.save(db_cache_file)
                            with open(db_fp_file, 'w', encoding='utf-8') as f:
                                f.write(fp)
                            logger.info(f'DB YARA 编译缓存已保存: {db_cache_file}')
                        except Exception as e:
                            logger.debug(f'保存 DB YARA 编译缓存失败: {e}')
            except Exception as e:
                logger.error(f'编译 DB 自动 YARA 规则失败: {e}')
                self._yara_rules_db = None

    @staticmethod
    def _compile_db_rules(db_rules: List[Dict]):
        """编译全部 DB 自动 YARA 规则；若整批因个别坏规则失败，回退为分块
        编译并剔除坏规则，保证一条坏规则（如含未转义换行的字符串）不至于
        让所有 DB YARA 匹配全部失效。

        Returns:
            (rules_obj, ok_count, removed_count)；全部不可编译时 rules_obj=None。
        """
        def _cc(src):
            try:
                return yara.compile(source=src)
            except Exception:
                return None

        if not db_rules:
            return None, 0, 0
        sources = [str(r.get('rule_content') or '') for r in db_rules]
        combined = '\n\n'.join(sources)
        rules_obj = _cc(combined)
        if rules_obj is not None:
            return rules_obj, len(sources), 0

        # 整批失败 → 分块定位坏规则（快路径全块通过，慢路径块内逐条）
        ok_idx: List[int] = []
        block = 512
        for start in range(0, len(sources), block):
            chunk = sources[start:start + block]
            if _cc('\n\n'.join(chunk)) is not None:
                ok_idx.extend(range(start, start + len(chunk)))
                continue
            for i, src in enumerate(chunk):
                if _cc(src) is not None:
                    ok_idx.append(start + i)
        removed = len(sources) - len(ok_idx)
        logger.warning('DB auto_yara_rules 存在 %d 条无法编译的坏规则，已剔除',
                       removed)
        if not ok_idx:
            return None, 0, removed
        final = _cc('\n\n'.join(sources[i] for i in ok_idx))
        return final, len(ok_idx), removed

    def _load_auto_rules_from_db(self) -> List[Dict]:
        """从 SignatureDB 读取所有启用的自动 YARA 规则（惰性导入，避免循环依赖）。

        优先复用传入的已实例化 SignatureDB（避免重复加载整个数据库）；否则自建。
        """
        try:
            if self._signature_db is not None:
                try:
                    return self._signature_db.get_active_yara_rules()
                except Exception as e:
                    logger.debug(f'复用 SignatureDB 读取 auto_yara_rules 失败（可忽略）: {e}')
                    return []
            from db.signature_db import SignatureDB
            db = SignatureDB()
            try:
                rules = db.get_active_yara_rules()
                return rules
            finally:
                db.close()
        except Exception as e:
            logger.debug(f'读取 DB auto_yara_rules 失败（可忽略）: {e}')
            return []

    def _match_rules_obj(self, rules_obj, target, scan_type: str = 'file') -> List[Dict]:
        """匹配单个 YARA 编译规则对象（文件或进程内存），返回统一格式结果。"""
        out = []
        if rules_obj is None:
            return out
        raw_matches = None
        for attempt in range(3):
            try:
                if scan_type == 'file':
                    raw_matches = rules_obj.match(filepath=target)
                else:
                    raw_matches = rules_obj.match(pid=target)
                break
            except PermissionError as e:
                if attempt < 2:
                    time.sleep(0.05 * (2 ** attempt))
                    continue
                logger.debug(f'YARA {scan_type} 扫描失败（权限） {target}: {e}')
                return out
            except Exception as e:
                logger.debug(f'YARA {scan_type} 扫描失败 {target}: {e}')
                return out
        if raw_matches is None:
            return out
        for m in raw_matches:
            rule_name = str(m)
            severity = 'medium'
            description = rule_name
            try:
                meta = m.meta
                if 'severity' in meta:
                    # 数值 severity（Elastic 100/50/…）→ high/medium/low；
                    # 字符串 severity 原样返回（现有规则行为不变）
                    severity = normalize_severity(meta['severity'])
                if 'description' in meta:
                    description = meta['description']
            except Exception:
                pass
            rid_prefix = 'yara_mem_' if scan_type == 'memory' else 'yara_'
            out.append({
                'rule_id': f'{rid_prefix}{rule_name}',
                'rule_name': f'{rule_name} (内存)' if scan_type == 'memory' else rule_name,
                'severity': severity,
                'description': (f'进程内存匹配: {description}' if scan_type == 'memory' else description),
                'rule_type': 'yara_memory' if scan_type == 'memory' else 'yara',
                **({'pid': target} if scan_type == 'memory' else {}),
            })
        return out

    def _yara_scan_file(self, file_path: str) -> List[Dict]:
        """使用 YARA 扫描文件（文件规则 + DB 自动规则 并联匹配）。"""
        matches = []
        rules, rules_db = self._yara_scan_ready_pair()
        if HAS_YARA:
            matches.extend(self._match_rules_obj(rules, file_path, 'file'))
            matches.extend(self._match_rules_obj(rules_db, file_path, 'file'))
        # 降级到便携 Python 桥接
        if self._yara_portable_available and self._yara_portable:
            try:
                port_matches = self._yara_portable.scan_file(file_path)
                for m in port_matches:
                    rule_name = m.get('rule', 'unknown')
                    severity = 'medium'
                    tags = m.get('tags', [])
                    if 'high' in tags or 'critical' in tags:
                        severity = 'high'
                    elif 'low' in tags:
                        severity = 'low'
                    matches.append({
                        'rule_id': f'yara_portable_{rule_name}',
                        'rule_name': rule_name,
                        'severity': severity,
                        'description': m.get('description', rule_name),
                        'rule_type': 'yara_portable',
                    })
            except Exception as e:
                logger.debug(f'便携 YARA 扫描文件失败 {file_path}: {e}')
        return matches

    def yara_scan_memory(self, pid: int) -> List[Dict]:
        """使用 YARA 扫描进程内存（文件规则 + DB 自动规则 并联匹配）。"""
        matches = []
        rules, rules_db = self._yara_scan_ready_pair()
        if HAS_YARA:
            matches.extend(self._match_rules_obj(rules, pid, 'memory'))
            matches.extend(self._match_rules_obj(rules_db, pid, 'memory'))
        # 降级到便携 Python 桥接
        if self._yara_portable_available and self._yara_portable:
            try:
                port_matches = self._yara_portable.scan_memory(pid)
                for m in port_matches:
                    rule_name = m.get('rule', 'unknown')
                    severity = 'medium'
                    tags = m.get('tags', [])
                    if 'high' in tags or 'critical' in tags:
                        severity = 'high'
                    elif 'low' in tags:
                        severity = 'low'
                    matches.append({
                        'rule_id': f'yara_portable_mem_{rule_name}',
                        'rule_name': f'{rule_name} (内存)',
                        'severity': severity,
                        'description': f'进程内存匹配: {m.get("description", rule_name)}',
                        'rule_type': 'yara_portable_memory',
                        'pid': pid,
                    })
            except Exception as e:
                logger.debug(f'便携 YARA 内存扫描失败 PID={pid}: {e}')
        return matches

    @property
    def yara_enabled(self) -> bool:
        """YARA 引擎当前是否可用（规则已就绪，直接或便携桥接）"""
        if HAS_YARA and self._yara_rules_ready and self._yara_rules is not None:
            return True
        if self._yara_portable_available and self._yara_portable:
            return self._yara_portable.is_available()
        return False

    # ---- 降载控制：高负载时跳过重型规则 / 缩小字节扫描上限 ----
    def skip_heavy_rules(self, skip: bool) -> None:
        """是否跳过重型 YARA / 自研字节规则（高负载降载开关）。

        Args:
            skip: True → 只做文件名/扩展名规则 + 对≤16MB小文件做轻量字节规则，
                  跳过 loops/math/pe.imphash/hash 等昂贵规则；
                  False → 恢复完整规则匹配。
        """
        self._skip_heavy_rules = bool(skip)
        # 联动：重型规则关闭时把单文件扫描上限从 128MB 缩到 8MB
        self._max_scan_bytes = (8 * 1024 * 1024) if skip else (128 * 1024 * 1024)

    def reload_yara_rules(self):
        """重新加载 YARA 规则（规则文件更新后调用）"""
        if self._yara_available:
            # 删除旧缓存强制重编译
            try:
                if os.path.exists(_YARA_COMPILED_CACHE):
                    os.remove(_YARA_COMPILED_CACHE)
            except Exception:
                pass
            self._load_yara_rules()
            with self._yara_lock:
                self._yara_rules_ready = True

    def reload_yara_engine(self) -> bool:
        """重新检测并加载 YARA 引擎（一键安装 yara-python 后调用）

        由于 yara-python 是 C 扩展 DLL，在主进程中无法卸载重载，
        所以采用"子进程验证 + 重启标记"策略：
        1. 在子进程中 import yara 验证是否真正安装成功
        2. 主进程标记 _yara_available=True（即使模块不能重载）
        3. 扫描时会通过子进程或便携桥接使用 YARA

        Returns:
            是否成功启用 YARA 引擎
        """
        global HAS_YARA, yara

        # 第一步：子进程验证 yara-python 是否真正可用
        python_exe = _get_python_executable()
        if python_exe:
            try:
                import subprocess

                # 通过子进程检测 yara 是否可用
                check_code = 'import yara; print(yara.__version__)'
                result = subprocess.run(
                    [python_exe, '-c', check_code],
                    capture_output=True, text=True, timeout=10, creationflags=_HIDDEN_CREATIONFLAGS
                )
                if result.returncode == 0:
                    yara_version = result.stdout.strip()
                    logger.info(f'子进程检测 yara-python 可用: 版本 {yara_version}')

                    # 标记 YARA 已安装可用
                    self._yara_available = True
                    HAS_YARA = True

                    # 尝试在主进程中导入（如果可以就直接使用）
                    try:
                        import importlib
                        import sys as _sys
                        # 清理 yara 相关缓存
                        for mod_name in list(_sys.modules.keys()):
                            if mod_name == 'yara' or mod_name.startswith('yara.'):
                                del _sys.modules[mod_name]

                        # 处理 --user 安装：把用户站点目录加入 sys.path
                        import site
                        user_site = site.getusersitepackages()
                        if user_site and user_site not in _sys.path:
                            _sys.path.insert(0, user_site)

                        yara_module = importlib.import_module('yara')
                        yara = yara_module
                        self._load_yara_rules()
                        with self._yara_lock:
                            self._yara_rules_ready = True
                        logger.info('YARA 引擎重新加载成功（直接模式）')
                        return True
                    except Exception as e:
                        # 主进程无法直接导入（C扩展DLL锁定），但已通过子进程验证
                        logger.info(f'主进程导入 yara 失败（{e}），但子进程已验证可用，标记为已安装')
                        # 即使不能直接导入，也标记为可用（扫描时可通过子进程或便携桥接）
                        return True
                else:
                    logger.warning(f'子进程检测 yara-python 失败: {result.stderr[:200]}')
            except Exception as e:
                logger.debug(f'YARA 验证子进程失败: {e}')
        else:
            logger.debug('YARA 验证子进程跳过：打包环境下无可用 Python 解释器')

        # 尝试便携 Python 桥接
        if HAS_PORTABLE_YARA:
            if self._yara_portable is None:
                self._yara_portable = YaraPortable()
                self._yara_portable.reset_cache()

            if self._yara_portable.is_available():
                self._yara_portable_available = True
                self._yara_available = True
                self._load_yara_rules()
                with self._yara_lock:
                    self._yara_rules_ready = True
                logger.info('YARA 引擎重新加载成功（便携桥接模式）')
                return True

        logger.warning('重新加载 YARA 引擎失败：直接模式和便携桥接均不可用')
        return False

    # ---- 自研规则引擎（降级方案 + 补充规则）----

    def _load_builtin_rules(self) -> List[Dict]:
        """加载内置自研规则

        规则分级策略：
        - high:  高置信度恶意特征，单条即可触发威胁判定
        - medium: 可疑特征，需与其他规则组合判定
        - low:   弱特征，仅辅助评分
        - info:  提示性规则，不参与威胁判定

        规则类型：
        - byte_string: 字节串精确匹配
        - byte_regex:  字节正则匹配
        - filename_regex: 文件名正则匹配
        - extension:  扩展名正则匹配
        """
        rules = []

        # ================================================================
        # 1. 高置信度恶意软件字节签名（YARA 降级备用）
        # ================================================================
        rules.append({
            'id': 'rule_001', 'name': 'EICAR测试字符串',
            'type': 'byte_string',
            'pattern': b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
            'severity': 'high',
            'description': 'EICAR标准杀毒软件测试文件'
        })
        rules.append({
            'id': 'rule_002', 'name': 'Metasploit Payload',
            'type': 'byte_string', 'pattern': b'msfpayload',
            'severity': 'high', 'description': 'Metasploit载荷标识'
        })
        rules.append({
            'id': 'rule_003', 'name': 'Cobalt Strike Beacon',
            'type': 'byte_string', 'pattern': b'Malware.Agent.CobaltStrike',
            'severity': 'high', 'description': 'Cobalt Strike Beacon特征标识'
        })
        rules.append({
            'id': 'rule_004', 'name': 'Emotet C2通信',
            'type': 'byte_regex', 'pattern': b'http://emotet[0-9]+\\.com',
            'severity': 'high', 'description': 'Emotet恶意软件C2服务器特征'
        })
        rules.append({
            'id': 'rule_005', 'name': 'TrickBot标识',
            'type': 'byte_string', 'pattern': b'TrickBot.Banking.Trojan',
            'severity': 'high', 'description': 'TrickBot银行木马特征标识'
        })

        # ================================================================
        # 2. 注入/逃逸技术字节特征
        # ================================================================
        rules.append({
            'id': 'rule_006', 'name': 'RDP劫持',
            'type': 'byte_regex', 'pattern': b'ShadowCopy\\|termsrv',
            'severity': 'medium', 'description': 'RDP服务劫持特征'
        })
        rules.append({
            'id': 'rule_007', 'name': 'Process Injection',
            'type': 'byte_regex', 'pattern': b'VirtualAllocEx.*CreateRemoteThread',
            'severity': 'medium', 'description': '进程注入技术组合特征'
        })
        rules.append({
            'id': 'rule_020', 'name': 'DLL注入',
            'type': 'byte_regex',
            'pattern': b'LoadLibraryA.*VirtualAllocEx|WriteProcessMemory.*LoadLibrary',
            'severity': 'medium', 'description': 'DLL注入经典技术组合'
        })
        rules.append({
            'id': 'rule_021', 'name': 'Reflective DLL注入',
            'type': 'byte_string',
            'pattern': b'ReflectiveLoader',
            'severity': 'medium', 'description': '反射式DLL注入标识'
        })
        rules.append({
            'id': 'rule_022', 'name': '进程空心化',
            'type': 'byte_regex',
            'pattern': b'NtUnmapViewOfSection|ZwUnmapViewOfSection',
            'severity': 'high', 'description': 'Process Hollowing进程空心化特征'
        })
        rules.append({
            'id': 'rule_023', 'name': 'API动态解析',
            'type': 'byte_regex',
            'pattern': b'GetProcAddress.*LoadLibrary|LdrGetProcAddress',
            'severity': 'low', 'description': '运行时动态解析API（常用于绕过静态分析）'
        })

        # ================================================================
        # 3. 反分析/反调试特征
        # ================================================================
        rules.append({
            'id': 'rule_024', 'name': '反调试检测',
            'type': 'byte_regex',
            'pattern': b'IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess',
            'severity': 'low', 'description': '反调试检测API调用'
        })
        rules.append({
            'id': 'rule_025', 'name': '反虚拟机检测',
            'type': 'byte_regex',
            'pattern': b'VMware|VBOX|QEMU|Sandboxie|wireshark',
            'severity': 'low', 'description': '虚拟机/沙箱环境检测字符串'
        })
        rules.append({
            'id': 'rule_026', 'name': 'timing反调试',
            'type': 'byte_regex',
            'pattern': b'rdtsc.*cmp|QueryPerformanceCounter.*sub|GetTickCount.*cmp',
            'severity': 'low', 'description': '时序检测反调试技术'
        })

        # ================================================================
        # 4. 恶意脚本/命令特征
        # ================================================================
        rules.append({
            'id': 'rule_017', 'name': 'PowerShell编码命令',
            'type': 'byte_regex',
            'pattern': b'powershell[^\\x00]{0,200}-EncodedCommand',
            'severity': 'medium', 'description': 'PowerShell编码命令执行特征'
        })
        rules.append({
            'id': 'rule_018', 'name': 'VBScript创建Shell',
            'type': 'byte_string', 'pattern': b'CreateObject.*WScript\\.Shell',
            'severity': 'medium', 'description': 'VBScript创建Shell对象特征'
        })
        rules.append({
            'id': 'rule_019', 'name': 'WMI查询执行',
            'type': 'byte_regex',
            'pattern': b'WMI[^\\x00]{0,100}ExecQuery[^\\x00]{0,100}SELECT.*FROM',
            'severity': 'low', 'description': 'WMI查询执行特征'
        })
        rules.append({
            'id': 'rule_027', 'name': 'PowerShell下载执行',
            'type': 'byte_regex',
            'pattern': b'powershell[^\\x00]{0,300}(DownloadString|Net\\.WebClient|Invoke-WebRequest|IEX|Invoke-Expression)',
            'severity': 'high', 'description': 'PowerShell从网络下载并执行代码'
        })
        rules.append({
            'id': 'rule_028', 'name': 'Bat/CMDownloader',
            'type': 'byte_regex',
            'pattern': b'(certutil|bitsadmin)\\s[^\\x00]{0,100}(urlcache|transfer|http://|https://)',
            'severity': 'high', 'description': '利用系统工具下载恶意文件'
        })
        rules.append({
            'id': 'rule_029', 'name': 'MSHTA远程执行',
            'type': 'byte_regex',
            'pattern': b'mshta[^\\x00]{0,200}http',
            'severity': 'high', 'description': 'mshta加载远程HTA脚本'
        })
        rules.append({
            'id': 'rule_030', 'name': '批处理混淆',
            'type': 'byte_regex',
            'pattern': b'set[^\\x00]{0,50}=%[^\\x00]{0,50}%(::|&&|%%)',
            'severity': 'low', 'description': '批处理脚本变量混淆技术'
        })

        # ================================================================
        # 5. 持久化/自启动特征
        # ================================================================
        rules.append({
            'id': 'rule_031', 'name': '注册表自启动写入',
            'type': 'byte_regex',
            'pattern': b'(CurrentVersion\\\\Run|CurrentVersion\\\\RunOnce|Winlogon\\\\Shell|Winlogon\\\\Userinit)',
            'severity': 'medium', 'description': '写入注册表自启动键值'
        })
        rules.append({
            'id': 'rule_032', 'name': '计划任务创建',
            'type': 'byte_regex',
            'pattern': b'schtasks[^\\x00]{0,200}(create|/create|/sc|/tr)',
            'severity': 'medium', 'description': '创建计划任务实现持久化'
        })
        rules.append({
            'id': 'rule_033', 'name': 'WMI事件订阅持久化',
            'type': 'byte_regex',
            'pattern': b'__EventToConsumerBinding|__EventFilter|CommandLineEventConsumer',
            'severity': 'high', 'description': 'WMI事件订阅持久化（高级免杀技术）'
        })
        rules.append({
            'id': 'rule_034', 'name': 'Shellcode特征',
            'type': 'byte_regex',
            'pattern': b'\\xfc\\xe8\\x00\\x00\\x00\\x00|\\xe8\\x00\\x00\\x00\\x00\\x5b',
            'severity': 'high', 'description': '常见shellcode入口模式'
        })

        # ================================================================
        # 6. 网络通信/C2特征
        # ================================================================
        rules.append({
            'id': 'rule_035', 'name': 'Cobalt Strike水滴特征',
            'type': 'byte_regex',
            'pattern': b'/[^\\x00]{2,20}\\.(php|asp|jsp)\\?[^\\x00]{0,50}=[^\\x00]{1,30}$',
            'severity': 'low', 'description': 'HTTP信标URI模式（需结合其他特征判断）'
        })
        rules.append({
            'id': 'rule_036', 'name': 'DNS隧道特征',
            'type': 'byte_regex',
            'pattern': b'[a-z0-9]{20,}\\.[a-z]{2,6}\\.[a-z]{2,6}',
            'severity': 'low', 'description': '超长子域名疑似DNS隧道'
        })

        # ================================================================
        # 7. 文件名正则规则
        # ================================================================
        # 可疑文件名模式
        rules.append({
            'id': 'rule_009', 'name': '可疑文件名模式',
            'type': 'filename_regex',
            'pattern': r'^[a-zA-Z0-9]{8,16}\.(exe|dll|bat|cmd|scr|pif)$',
            'severity': 'info', 'description': '随机命名的可执行文件（仅提示）'
        })
        # 宏文档
        rules.append({
            'id': 'rule_010', 'name': '宏文档',
            'type': 'filename_regex',
            'pattern': r'.+\.(docm|xlsm|pptm|dotm|xltm|potm)$',
            'severity': 'info', 'description': '包含宏的Office文档（仅提示，非病毒特征）'
        })
        # 勒索软件加密后缀
        rules.append({
            'id': 'rule_011', 'name': '勒索软件模式',
            'type': 'filename_regex',
            'pattern': r'.+\.(locked|encrypted|crypt|cry|locky|cerber|zepto|odin|thor|aesir|osiris|lockd|wncry|wannacry|wn Crypt|crysis|dharma|phobos|sodinokibi|ryuk|maze|revil|conti|lockbit|blackcat|alphv|hive|blackbasta)$',
            'severity': 'high', 'description': '勒索软件加密文件后缀标识'
        })
        # AutoRun脚本
        rules.append({
            'id': 'rule_012', 'name': 'AutoRun脚本',
            'type': 'filename_regex',
            'pattern': r'^autorun\.inf$',
            'severity': 'info', 'description': 'U盘自动运行脚本（仅提示）'
        })
        # 多重后缀名伪装
        rules.append({
            'id': 'rule_040', 'name': '多重后缀名伪装',
            'type': 'filename_regex',
            'pattern': r'\.(exe|dll|scr|pif|com|bat|cmd|vbs|ps1|js)(\.(txt|doc|docx|xls|xlsx|pdf|jpg|jpeg|png|gif|bmp|webp|zip|rar|7z|pptx))+$',
            'severity': 'high', 'description': '多重后缀名伪装（如 virus.exe.txt）'
        })
        # 双扩展名：文档图标欺骗
        rules.append({
            'id': 'rule_041', 'name': '文档图标欺骗',
            'type': 'filename_regex',
            'pattern': r'.+\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf)\.(exe|scr|com|bat|cmd|vbs|js|pif)$',
            'severity': 'high', 'description': '伪装为文档的可执行文件（如 report.pdf.exe）'
        })
        # UAC绕过文件名
        rules.append({
            'id': 'rule_042', 'name': 'UAC绕过关键词',
            'type': 'filename_regex',
            'pattern': r'(?i)(uac.bypass|fodhelper|eventvwr|sdclt|actionqueue|consent)_',
            'severity': 'medium', 'description': '文件名含UAC绕过技术关键词'
        })
        # 伪装系统进程
        rules.append({
            'id': 'rule_043', 'name': '伪装系统进程名',
            'type': 'filename_regex',
            'pattern': r'(?i)^(svchost|csrss|lsass|smss|wininit|winlogon|services|spoolsv|dwm|conhost|taskhostw?|runtimebroker|searchindexer|sihost|shellexperiencehost)\.(exe|dll)$',
            'severity': 'medium', 'description': '文件名伪装为系统进程（真品在System32中）'
        })
        # HTA/JSE/VBE脚本文件
        rules.append({
            'id': 'rule_044', 'name': '危险脚本类型',
            'type': 'filename_regex',
            'pattern': r'.+\.(hta|jse|vbe|wsf|wsh)$',
            'severity': 'info', 'description': '潜在危险脚本文件类型（仅提示）'
        })
        # LNK快捷方式
        rules.append({
            'id': 'rule_045', 'name': 'LNK快捷方式',
            'type': 'filename_regex',
            'pattern': r'.+\.lnk$',
            'severity': 'info', 'description': 'LNK快捷方式文件（仅提示，可能包含恶意命令）'
        })

        # ================================================================
        # 8. 扩展名规则
        # ================================================================
        rules.append({
            'id': 'rule_013', 'name': '可疑扩展名',
            'type': 'extension',
            'pattern': r'\.(scr|pif|com|hta|js|vbs|wsf)$',
            'severity': 'info', 'description': '潜在危险文件扩展名（仅提示）'
        })
        rules.append({
            'id': 'rule_014', 'name': '可执行文件',
            'type': 'extension',
            'pattern': r'\.(exe|dll|sys|bat|cmd|ps1)$',
            'severity': 'info', 'description': '可执行文件类型（仅提示）'
        })
        rules.append({
            'id': 'rule_050', 'name': '勒索扩展名',
            'type': 'extension',
            'pattern': r'\.(locked|encrypted|crypt|cry|locky|cerber|zepto|wncry|lockd|crysis|dharma|phobos|ryuk|maze|conti|lockbit|blackcat|hive)$',
            'severity': 'high', 'description': '已知勒索软件加密后缀'
        })
        rules.append({
            'id': 'rule_051', 'name': '网络脚本扩展名',
            'type': 'extension',
            'pattern': r'\.(asp|aspx|php|jsp|cgi)$',
            'severity': 'info', 'description': 'Web脚本文件类型（仅提示）'
        })

        # ---- 恶搞程序检测规则 ----
        rules.append({
            'id': 'rule_060', 'name': '恶搞程序-鼠标控制API组合',
            'type': 'byte',
            'pattern': rb'SetCursorPos.{0,200}(mouse_event|SendInput)',
            'severity': 'high', 'description': '检测到鼠标位置控制+模拟点击API组合，典型恶搞程序特征'
        })
        rules.append({
            'id': 'rule_061', 'name': '恶搞程序-系统参数修改',
            'type': 'byte',
            'pattern': rb'SystemParametersInfo(?:A|W)?.{0,200}(SPI_SETDESKWALLPAPER|SPI_SETSCREENSAVETIMEOUT|SPI_SETWORKAREA)',
            'severity': 'high', 'description': '检测到系统参数修改API+壁纸/屏保参数组合，疑似恶搞程序'
        })
        rules.append({
            'id': 'rule_062', 'name': '恶搞程序-阻断输入',
            'type': 'byte',
            'pattern': rb'BlockInput.{0,200}(SwapMouseButton|ShowCursor|keybd_event|SetCursorPos)',
            'severity': 'high', 'description': '检测到阻断键鼠输入+其他恶搞API组合'
        })
        rules.append({
            'id': 'rule_063', 'name': '恶搞程序-屏幕翻转',
            'type': 'byte',
            'pattern': rb'ChangeDisplaySettings(?:Ex)?(?:A|W).{0,300}(DMDO_90|DMDO_180|DMDO_270|0x00000004|0x00000008)',
            'severity': 'high', 'description': '检测到修改显示设置+旋转参数，疑似屏幕翻转恶搞'
        })
        rules.append({
            'id': 'rule_064', 'name': '恶搞程序-疯狂弹窗',
            'type': 'byte',
            'pattern': rb'(MessageBox(?:A|W|IndirectA|IndirectW)).{0,500}\1',
            'severity': 'medium', 'description': '检测到重复弹窗API调用模式，疑似疯狂弹窗恶搞'
        })
        rules.append({
            'id': 'rule_065', 'name': '恶搞程序-字符串特征',
            'type': 'byte',
            'pattern': rb'(?i)(just\s*a\s*joke|haha|prank|scare(d|y)|scream|gotcha|fooled|tricked)',
            'severity': 'medium', 'description': '检测到恶搞程序常见字符串'
        })
        rules.append({
            'id': 'rule_066', 'name': '恶搞程序-文件名特征',
            'type': 'filename',
            'pattern': r'(?i)(joke|prank|hoax|trick|scare|scream|fool|fake_|funny).{0,20}\.(exe|scr|bat|vbs|js|cmd|ps1)',
            'severity': 'medium', 'description': '文件名含恶搞程序关键词'
        })
        rules.append({
            'id': 'rule_067', 'name': '恶搞程序-屏幕保护伪装',
            'type': 'filename',
            'pattern': r'(?i)\.scr$',
            'severity': 'medium', 'description': '屏幕保护程序常被恶搞程序伪装利用'
        })

        return rules

    def _builtin_scan_file(self, file_path: str, max_read_bytes: Optional[int] = None) -> List[Dict]:
        """使用自研规则扫描文件（降级方案）

        Args:
            max_read_bytes: 字节扫描时最多读取的字节数（降载模式下减少 I/O）；
                            None 表示读取整个文件。
        """
        matches = []

        if not os.path.isfile(file_path):
            return matches

        try:
            filename = os.path.basename(file_path)
            _, extension = os.path.splitext(filename)

            # 跳过源代码文件
            if extension.lower() in ('.py', '.pyc', '.pyw', '.pyo'):
                return matches

            # ---- 文件名/扩展名规则：不依赖内容，必须跑 ----
            filename_only_rules = [r for r in self._builtin_rules
                                   if r.get('type') in ('filename_regex', 'extension')]
            for rule in filename_only_rules:
                matched = False
                rule_type = rule['type']
                try:
                    pattern = rule['pattern']
                    if rule_type == 'filename_regex':
                        if re.search(pattern, filename, re.IGNORECASE):
                            matched = True
                    elif rule_type == 'extension':
                        if isinstance(pattern, (list, tuple)):
                            if extension.lower() in [p.lower() for p in pattern]:
                                matched = True
                        elif extension.lower() == pattern.lower():
                            matched = True
                except Exception:
                    continue
                if matched:
                    matches.append({
                        'rule_id': rule.get('id'),
                        'rule_name': rule.get('name', 'builtin'),
                        'severity': rule.get('severity', 'medium'),
                        'description': rule.get('description', ''),
                        'rule_type': rule.get('type', 'builtin'),
                    })

            # ---- 依赖内容的规则（byte_string / regex）：降载时只读 max_read_bytes 头部 ----
            byte_rules = [r for r in self._builtin_rules
                          if r.get('type') not in ('filename_regex', 'extension')]
            if byte_rules:
                try:
                    with open_with_retry(file_path, 'rb') as f:
                        if max_read_bytes and max_read_bytes > 0:
                            file_content = f.read(max_read_bytes)
                        else:
                            file_content = f.read()
                except Exception:
                    file_content = b''

                for rule in byte_rules:
                    rule_type = rule['type']
                    matched = False
                    try:
                        if rule_type == 'byte_string':
                            pattern = rule['pattern']
                            if isinstance(pattern, str):
                                pattern = pattern.encode('latin-1', errors='ignore')
                            if pattern in file_content:
                                matched = True
                        elif rule_type == 'content_regex':
                            pattern = rule['pattern']
                            try:
                                if re.search(pattern, file_content, re.IGNORECASE):
                                    matched = True
                            except Exception:
                                pass
                    except Exception:
                        continue
                    if matched:
                        matches.append({
                            'rule_id': rule.get('id'),
                            'rule_name': rule.get('name', 'builtin'),
                            'severity': rule.get('severity', 'medium'),
                            'description': rule.get('description', ''),
                            'rule_type': rule.get('type', 'builtin'),
                        })

            return matches

        except Exception as e:
            logger.debug(f'自研规则扫描失败 {file_path}: {e}')

        return matches

    # ---- 统一扫描接口 ----

    def _get_threat_intel(self):
        """惰性获取威胁情报数据库实例"""
        if not self._threat_intel_loaded:
            try:
                from engine.threat_intel import get_threat_intel
                self._threat_intel = get_threat_intel()
            except Exception as e:
                logger.debug(f'威胁情报数据库加载失败: {e}')
                self._threat_intel = None
            self._threat_intel_loaded = True
        return self._threat_intel

    def scan_file(self, file_path: str) -> List[Dict]:
        """扫描文件，返回匹配的规则列表

        优先使用 YARA（高速），补充自研规则（文件名/扩展名）。
        YARA 不可用或用户关闭时完全降级到自研规则。
        高负载降载时 (skip_heavy_rules=True):
          - 大文件(>64MB) / 重型 YARA 规则跳过，只做文件名/扩展名和小型文件字节规则
          - 自研字节扫描最多读 _max_scan_bytes（默认 8MB，通常为 128MB）

        Args:
            file_path: 文件路径

        Returns:
            匹配规则列表，每项包含 rule_id, rule_name, severity, description, rule_type
        """
        all_matches = []

        # 判断 YARA 是否实际生效：已安装 + 用户启用 + 规则已加载就绪
        yara_active = bool(self._yara_rules) and self._yara_user_enabled

        # ---- 降载：大文件 / 重型规则跳过 ----
        skip_bytes = False
        if self._skip_heavy_rules:
            try:
                sz = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                if sz > 64 * 1024 * 1024:
                    skip_bytes = True  # 超 64MB → 只跑文件名/扩展名规则
            except Exception:
                pass

        # 1. YARA 扫描（如果可用且用户启用且降载未跳过）
        if yara_active and not skip_bytes:
            all_matches.extend(self._yara_scan_file(file_path))

        # 2. 自研规则补充扫描（文件名/扩展名规则始终执行，YARA 不擅长）
        #    YARA 不可用或用户关闭时，字节规则也在此执行（降级）。
        #    自研字节扫描前把 _max_scan_bytes 作为 size cap 传入（若接口支持）。
        if not yara_active or skip_bytes:
            # 完全降级模式 / 降载模式：执行自研规则（文件名始终，字节按需降档）
            builtin_matches = self._builtin_scan_file(file_path,
                                                      max_read_bytes=self._max_scan_bytes
                                                      if self._skip_heavy_rules else None)
            all_matches.extend(builtin_matches)
        elif yara_active:
            # YARA 已处理字节规则，仅补充文件名/扩展名规则
            all_matches.extend(self._scan_filename_rules(file_path))

        # 3. 威胁情报扫描（IP/域名黑名单匹配）
        #    从文件内容中提取 IP/URL/域名，匹配本地黑名单。
        #    降载下仅读 _max_scan_bytes 头部避免大文件 Ti 扫描吃 CPU。
        ti_matches = self._scan_threat_intel(
            file_path,
            max_read_bytes=self._max_scan_bytes if self._skip_heavy_rules else None,
        )
        if ti_matches:
            all_matches.extend(ti_matches)

        return all_matches

    def _scan_threat_intel(self, file_path: str,
                           max_read_bytes: Optional[int] = None) -> List[Dict]:
        """威胁情报扫描：提取文件中的 IP/域名/URL 并匹配黑名单

        Args:
            file_path: 待扫描文件
            max_read_bytes: 仅读取文件前 N 字节（降载时节省 I/O）；None 读全文

        检测场景：
        - 恶意脚本中硬编码的 C2 服务器 IP/域名
        - 钓鱼页面中的恶意 URL
        - 配置文件中的恶意基础设施地址
        """
        matches = []
        try:
            ti = self._get_threat_intel()
            if not ti or not ti.is_loaded():
                return matches

            # ti.scan_file 通常支持 size cap；若不支持也可用后备手段：
            # 通过传入 max 参数（如其 API 支持）；否则直接调用。
            try:
                hits = ti.scan_file(file_path, max_read_bytes=max_read_bytes)
            except TypeError:
                hits = ti.scan_file(file_path)
            if not hits:
                return matches

            # 将命中的威胁指标转为规则匹配格式
            for hit in hits:
                indicator_type = hit.get('type', '')
                indicator_value = hit.get('value', '')
                if indicator_type == 'ip':
                    rule_name = 'ThreatIntel.MaliciousIP'
                    description = f'文件包含恶意 IP 地址: {indicator_value}'
                    severity = 'high'
                elif indicator_type == 'domain':
                    rule_name = 'ThreatIntel.MaliciousDomain'
                    description = f'文件包含恶意域名: {indicator_value}'
                    severity = 'high'
                elif indicator_type == 'url':
                    rule_name = 'ThreatIntel.MaliciousURL'
                    description = f'文件包含恶意 URL: {indicator_value}'
                    severity = 'high'
                else:
                    continue

                matches.append({
                    'rule_id': rule_name,
                    'rule_name': rule_name,
                    'severity': severity,
                    'description': description,
                    'rule_type': 'threat_intel',
                    'indicator': indicator_value,
                    'indicator_type': indicator_type,
                })
        except Exception as e:
            logger.debug(f'威胁情报扫描异常 {file_path}: {e}')
        return matches

    def _scan_filename_rules(self, file_path: str) -> List[Dict]:
        """仅扫描文件名/扩展名规则（YARA 补充）"""
        matches = []

        if not os.path.isfile(file_path):
            return matches

        try:
            filename = os.path.basename(file_path)
            _, extension = os.path.splitext(filename)

            for rule in self._builtin_rules:
                rule_type = rule['type']
                if rule_type not in ('filename_regex', 'extension'):
                    continue

                matched = False
                try:
                    if rule_type == 'filename_regex':
                        if re.search(rule['pattern'], filename, re.IGNORECASE):
                            matched = True
                    elif rule_type == 'extension':
                        if re.search(rule['pattern'], extension, re.IGNORECASE):
                            matched = True
                except (re.error, TypeError):
                    continue

                if matched:
                    matches.append({
                        'rule_id': rule['id'],
                        'rule_name': rule['name'],
                        'severity': rule['severity'],
                        'description': rule['description'],
                        'rule_type': rule_type,
                    })
        except Exception:
            pass

        return matches

    def scan_process_memory(self, pid: int) -> List[Dict]:
        """扫描进程内存（仅 YARA 模式支持）

        Args:
            pid: 进程 ID

        Returns:
            匹配规则列表
        """
        # 等待 YARA 规则后台加载就绪（内存扫描强依赖 YARA）
        if not self.ensure_yara_ready(wait=6.0):
            logger.warning('内存扫描需要 YARA 引擎支持（规则未加载完成或不可用）')
            return []
        return self.yara_scan_memory(pid)

    # ---- 规则管理 ----

    def add_rule(self, rule: Dict):
        """添加自定义规则（自研规则）"""
        required_fields = ['id', 'name', 'type', 'pattern', 'severity', 'description']
        if all(field in rule for field in required_fields):
            self._builtin_rules.append(rule)

    def remove_rule(self, rule_id: str):
        """删除规则"""
        self._builtin_rules = [r for r in self._builtin_rules if r['id'] != rule_id]

    def get_rules(self) -> List[Dict]:
        """获取所有自研规则"""
        return self._builtin_rules

    def get_status(self) -> dict:
        """获取规则引擎状态"""
        # yara_installed: 只要 YARA 可用（直接导入/子进程验证/便携桥接任一方式）即视为已安装
        yara_installed = self._yara_available or self._yara_portable_available or HAS_YARA
        return {
            'yara_enabled': self.yara_enabled and self._yara_user_enabled,
            'yara_available': self._yara_available,
            'yara_installed': yara_installed,
            'yara_direct': HAS_YARA,
            'yara_portable': self._yara_portable_available,
            'yara_loading': self._yara_loading and not self._yara_rules_ready,
            'builtin_rules_count': len(self._builtin_rules),
            'yara_rules_dir': _YARA_RULES_DIR,
        }

    def set_yara_enabled(self, enabled: bool):
        """用户开关 YARA 引擎

        Args:
            enabled: True 启用 YARA，False 降级为自研规则
        """
        if enabled and not self._yara_available:
            logger.warning('yara-python 未安装且便携桥接不可用，无法启用 YARA 引擎')
            return False

        self._yara_user_enabled = enabled
        if enabled and self._yara_available:
            if HAS_YARA:
                if self._yara_rules is None:
                    # 规则未加载：触发后台加载并等待就绪
                    self._start_yara_async_load()
                    self.ensure_yara_ready(wait=8.0)
                elif not self._yara_rules_ready:
                    self.ensure_yara_ready(wait=8.0)
            elif self._yara_portable_available and self._yara_portable:
                self._yara_portable.is_available()
        logger.info(f'YARA 引擎 {"启用" if enabled else "禁用（降级为自研规则）"}')
        return True


if __name__ == '__main__':
    # 测试规则引擎
    engine = RuleEngine()
    print(f'规则引擎状态: {engine.get_status()}')

    # 测试EICAR文件
    eicar_content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.com') as f:
        f.write(eicar_content)
        test_file = f.name

    print(f'\n测试文件: {test_file}')
    matches = engine.scan_file(test_file)

    print(f'\n匹配规则 ({len(matches)}):')
    for match in matches:
        print(f'  - [{match["severity"]}] {match["rule_name"]}: {match["description"]} ({match["rule_type"]})')

    os.unlink(test_file)
