import os
import sys
import shutil
import json
import hashlib
import struct
import threading
from datetime import datetime
from typing import Dict, List, Optional

from utils.logger import get_logger

logger = get_logger('quarantine_manager')

# 子进程窗口隐藏标志（Windows 平台阻止弹出黑色 cmd/PowerShell 窗口）
# CREATE_NO_WINDOW = 0x08000000，在非 Windows 平台为 0（安全默认值）
_HIDDEN_CREATIONFLAGS = 0x08000000 if sys.platform == 'win32' else 0

# 隔离文件加密密钥（用于XOR加密，防止恶意文件被误执行）
_QUARANTINE_XOR_KEY = b'PSLS_Quarantine_v1_SecurityKey'

# 隔离文件魔数头（用于标识已加密的隔离文件）
_QUARANTINE_MAGIC = b'PQLS'  # PSLS Quarantine Lock Seal

# 配置文件路径（%APPDATA%\PSLS\settings.json）
def _get_settings_path() -> str:
    """获取配置文件路径"""
    if sys.platform == 'win32':
        appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
    else:
        appdata = os.path.expanduser('~/.config')
    psls_dir = os.path.join(appdata, 'PSLS')
    if not os.path.exists(psls_dir):
        try:
            os.makedirs(psls_dir)
        except Exception:
            pass
    return os.path.join(psls_dir, 'settings.json')

def _load_settings() -> dict:
    """加载配置文件"""
    settings_path = _get_settings_path()
    if os.path.exists(settings_path):
        try:
            with open(settings_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_settings(settings: dict):
    """保存配置文件"""
    settings_path = _get_settings_path()
    try:
        with open(settings_path, 'w', encoding='utf-8') as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f'保存配置文件失败: {e}')


# 软隔离（改名/原地 ACL）标记后缀：文件无法移动时改名为 <原路径>.PSLS_QUARANTINED
SOFT_QUARANTINE_SUFFIX = '.PSLS_QUARANTINED'


def _get_soft_registry_path() -> str:
    """软隔离登记表路径（**固定位置**，不随 quarantine_path 变动而迁移）。

    软隔离发生在受保护目录（无法移动文件），若登记信息只存在
    <quarantine_dir>/quarantine.json，则用户一旦更改隔离目录、或该目录被清理，
    记录即随文件一起"丢档" → 软隔离文件在隔离区不可见、也无法恢复
    （实测两个宿主可执行文件因此变成孤儿 .PSLS_QUARANTINED 且查询不到）。
    因此软隔离登记单独落在稳定的 %APPDATA%\\PSLS\\ 下。
    """
    if sys.platform == 'win32':
        appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
    else:
        appdata = os.path.expanduser('~/.config')
    psls_dir = os.path.join(appdata, 'PSLS')
    try:
        os.makedirs(psls_dir, exist_ok=True)
    except Exception:
        pass
    return os.path.join(psls_dir, 'soft_quarantine.json')

class QuarantineManager:
    """
    隔离管理类
    负责将可疑文件移动到隔离区并记录信息
    """
    
    def __init__(self, quarantine_dir: str = None):
        """
        初始化隔离管理器

        Args:
            quarantine_dir: 隔离区目录，优先级：参数 > 配置文件 > 默认路径
        """
        # 优先级1：参数指定
        if quarantine_dir is None:
            # 优先级2：从配置文件读取
            settings = _load_settings()
            quarantine_dir = settings.get('quarantine_path', None)

            # 优先级3：默认使用 %APPDATA%\PSLS\quarantine（持久化路径）
            if quarantine_dir is None:
                if sys.platform == 'win32':
                    appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
                else:
                    appdata = os.path.expanduser('~/.config')
                quarantine_dir = os.path.join(appdata, 'PSLS', 'quarantine')

        # 确保路径是绝对路径
        self.quarantine_dir = os.path.abspath(quarantine_dir)
        self.meta_file = os.path.join(self.quarantine_dir, 'quarantine.json')
        # 本次运行期间已恢复文件的豁免集合（程序重启后清空）
        self._exempted_paths: set = set()
        # 最近一次隔离操作的失败原因（供调用方查询具体失败原因记录到日志）
        self._last_quarantine_error: str = ''
        # 元数据文件读写锁：防止并发写入导致文件损坏（批量操作 + 列表刷新并发场景）
        self._meta_lock = threading.RLock()
        # 元数据内存缓存（大幅减少列表加载时间），避免每次 UI 进入隔离区都读磁盘+解析 JSON
        self._metadata_cache: Optional[Dict] = None
        self._metadata_cache_mtime: float = 0.0
        self._metadata_cache_size: int = 0
        # 初始化隔离区目录，失败时回退到默认路径
        if not self._init_quarantine():
            # 回退到默认路径
            if sys.platform == 'win32':
                appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
            else:
                appdata = os.path.expanduser('~/.config')
            self.quarantine_dir = os.path.join(appdata, 'PSLS', 'quarantine')
            self.meta_file = os.path.join(self.quarantine_dir, 'quarantine.json')
            # 清理无效的配置项，避免下次启动再次失败
            try:
                settings = _load_settings()
                if 'quarantine_path' in settings:
                    del settings['quarantine_path']
                    _save_settings(settings)
            except Exception:
                pass
            # 用回退路径再次初始化（此时不应失败）
            self._init_quarantine()

        # 软隔离登记表内存缓存（mtime/size 双判定失效，避免热路径反复读盘）
        self._soft_cache: Optional[List[Dict]] = None
        self._soft_cache_mtime: float = 0.0
        self._soft_cache_size: int = 0

        # 初始化自身路径排除集合（路径级自保护）
        self._init_self_excluded_dirs()

    def _init_self_excluded_dirs(self):
        """初始化自身路径排除集合，防止误隔离 PSLS 自身文件"""
        self._self_excluded_dirs = set()
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
        except Exception:
            pass

    def _is_self_protected(self, file_path: str) -> bool:
        """检查文件是否属于 PSLS 自身受保护目录"""
        if not hasattr(self, '_self_excluded_dirs') or not self._self_excluded_dirs:
            return False
        try:
            # 解析归档路径（归档内文件取外层归档路径判断）
            check_path = file_path
            if ' -> ' in check_path:
                check_path = check_path.split(' -> ')[0]
            fp_lower = os.path.abspath(check_path).lower()
            for excluded_dir in self._self_excluded_dirs:
                if fp_lower.startswith(excluded_dir):
                    return True
        except Exception:
            pass
        return False

    def _is_system_protected(self, file_path: str) -> bool:
        """检查文件是否属于 Windows 系统核心受保护目录（防误隔离系统文件）

        判断逻辑：
        1. 若在系统核心目录中（System32/SysWOW64/UUS 等），直接视为受保护
        2. 若在 Program Files/Microsoft 等可信发行商目录中，检查微软官方签名
        这样既不会误隔离系统文件，也不会放过非 Program Files 目录下的恶意程序。
        """
        try:
            check_path = file_path
            if ' -> ' in check_path:
                check_path = check_path.split(' -> ')[0]
            fp_lower = os.path.abspath(check_path).lower()

            if not hasattr(self, '_system_protected_dirs'):
                sys_root = os.environ.get('SystemRoot', r'C:\Windows').lower()
                pf = os.environ.get('ProgramFiles', r'C:\Program Files').lower()
                pf86 = os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)').lower()
                # 系统盘根目录下的升级/回滚临时目录
                _sd = os.environ.get('SystemDrive', 'C:').lower()
                self._system_protected_dirs = {
                    # Windows 系统核心目录（任何在此目录下的文件都不允许直接隔离）
                    os.path.join(sys_root, 'system32'),
                    os.path.join(sys_root, 'syswow64'),
                    os.path.join(sys_root, 'uus'),
                    os.path.join(sys_root, 'systemapps'),
                    os.path.join(sys_root, 'assembly'),
                    os.path.join(sys_root, 'microsoft.net'),
                    os.path.join(sys_root, 'winsxs'),
                    os.path.join(sys_root, 'installer'),
                    os.path.join(sys_root, 'softwaredistribution'),
                    # 系统盘根目录下的升级/回滚临时目录（受强ACL保护）
                    (_sd + '\\' + '$WINDOWS.~BT').lower(),
                    (_sd + '\\' + '$WINDOWS.~WS').lower(),
                    (_sd + '\\' + 'OldWindows').lower(),
                }
                self._microsoft_program_dirs = {
                    os.path.join(pf, 'common files'),
                    os.path.join(pf86, 'common files'),
                    os.path.join(pf, 'microsoft'),
                    os.path.join(pf86, 'microsoft'),
                    os.path.join(pf, 'microsoft office'),
                    os.path.join(pf86, 'microsoft office'),
                    os.path.join(pf, 'windows defender'),
                    os.path.join(pf, 'windows security'),
                    os.path.join(pf, 'windowsapps'),
                    os.path.join(pf, 'dotnet'),
                    os.path.join(pf, 'powershell'),
                }

            # 系统核心目录 → 直接保护
            for d in self._system_protected_dirs:
                if fp_lower.startswith(d):
                    return True

            # Program Files 下 Microsoft 目录 → 检查微软有效签名
            for d in self._microsoft_program_dirs:
                if fp_lower.startswith(d):
                    try:
                        from utils.signature_verifier import get_verifier
                        _verifier = get_verifier()
                        if _verifier:
                            signer = _verifier.get_signer_info(check_path)
                            if signer and signer.get('verified', False):
                                pub = (signer.get('publisher') or '').lower()
                                if 'microsoft' in pub or 'windows' in pub:
                                    return True
                    except Exception:
                        # 无法验证签名时 → 假设是系统可信文件，也保护
                        return True
                    break
        except Exception:
            pass
        return False

    def _init_quarantine(self) -> bool:
        """初始化隔离区目录

        Returns:
            True 表示成功，False 表示失败（路径不可访问）
        """
        try:
            if not os.path.exists(self.quarantine_dir):
                os.makedirs(self.quarantine_dir)

            if not os.path.exists(self.meta_file):
                with open(self.meta_file, 'w', encoding='utf-8') as f:
                    json.dump({'items': []}, f)
            return True
        except (OSError, Exception) as e:
            logger.warning(f'初始化隔离区目录失败 {self.quarantine_dir}: {e}，将回退到默认路径')
            return False

    def _add_exemption(self, file_path: str):
        """将路径加入本次运行的豁免集合"""
        norm = os.path.normpath(os.path.abspath(file_path))
        self._exempted_paths.add(norm)

    def _is_exempted(self, file_path: str) -> bool:
        """检查路径是否在本次运行的豁免集合中"""
        norm = os.path.normpath(os.path.abspath(file_path))
        return norm in self._exempted_paths

    def is_path_exempted(self, file_path: str) -> bool:
        """公开接口：检查路径是否在本次运行的豁免集合中（用于实时防护扫描阶段跳过已复原文件）"""
        return self._is_exempted(file_path)

    def clear_exemptions(self):
        """清空本次运行的所有豁免（用于测试或手动重置）"""
        self._exempted_paths.clear()

    def _encrypt_file(self, src_path: str, dst_path: str) -> bool:
        """
        加密文件并写入目标路径（XOR加密 + 魔数头）
        
        Args:
            src_path: 源文件路径
            dst_path: 目标文件路径
            
        Returns:
            是否加密成功
        """
        try:
            # 修复源文件读取权限
            self._fix_file_permissions(src_path)
            key_len = len(_QUARANTINE_XOR_KEY)
            with open(src_path, 'rb') as fin, open(dst_path, 'wb') as fout:
                # 写入魔数头标识
                fout.write(_QUARANTINE_MAGIC)
                offset = 0
                for chunk in iter(lambda: fin.read(65536), b''):
                    # XOR加密每个块
                    encrypted = bytearray(len(chunk))
                    for i in range(len(chunk)):
                        encrypted[i] = chunk[i] ^ _QUARANTINE_XOR_KEY[(offset + i) % key_len]
                    fout.write(encrypted)
                    offset += len(chunk)
            return True
        except Exception as e:
            logger.warning(f"加密文件失败: {e}")
            return False
    
    def _decrypt_file(self, src_path: str, dst_path: str) -> bool:
        """
        解密隔离文件到目标路径
        
        Args:
            src_path: 加密的源文件路径
            dst_path: 解密后的目标文件路径
            
        Returns:
            是否解密成功
        """
        try:
            # 修复源文件读取权限
            self._fix_file_permissions(src_path)
            key_len = len(_QUARANTINE_XOR_KEY)
            with open(src_path, 'rb') as fin:
                # 检查魔数头
                magic = fin.read(len(_QUARANTINE_MAGIC))
                if magic == _QUARANTINE_MAGIC:
                    # 新格式：加密文件，跳过魔数头后解密
                    with open(dst_path, 'wb') as fout:
                        offset = 0
                        for chunk in iter(lambda: fin.read(65536), b''):
                            decrypted = bytearray(len(chunk))
                            for i in range(len(chunk)):
                                decrypted[i] = chunk[i] ^ _QUARANTINE_XOR_KEY[(offset + i) % key_len]
                            fout.write(decrypted)
                            offset += len(chunk)
                else:
                    # 旧格式：未加密文件，直接复制
                    with open(dst_path, 'wb') as fout:
                        fout.write(magic)
                        while True:
                            chunk = fin.read(65536)
                            if not chunk:
                                break
                            fout.write(chunk)
            return True
        except Exception as e:
            logger.warning(f"解密文件失败: {e}")
            return False
    
    def _load_metadata(self) -> Dict:
        """加载隔离区元数据

        线程安全（通过 _meta_lock 保护），并处理文件损坏情况：
        - UTF-8 解码失败：尝试其他编码，失败则备份并重置
        - JSON 解析失败：备份损坏文件并重置
        - 文件不存在：返回空结构

        优化：使用内存缓存 + 文件 mtime/size 双判定失效，
        避免每次 UI 进入隔离区都读磁盘+解析 JSON（隔离项多时JSON解析慢）。
        """
        # 先快速检查缓存是否有效（不持锁，避免批量操作持锁时卡死读取）
        try:
            st = os.stat(self.meta_file)
            cache_ok = (
                self._metadata_cache is not None
                and self._metadata_cache_mtime == st.st_mtime
                and self._metadata_cache_size == st.st_size
            )
            if cache_ok:
                return self._metadata_cache
        except FileNotFoundError:
            if self._metadata_cache is not None:
                return self._metadata_cache
        except Exception:
            pass

        with self._meta_lock:
            # 持锁后再次检查缓存（双重检测，避免刚有其他线程更新）
            try:
                st = os.stat(self.meta_file)
                cache_ok = (
                    self._metadata_cache is not None
                    and self._metadata_cache_mtime == st.st_mtime
                    and self._metadata_cache_size == st.st_size
                )
                if cache_ok:
                    return self._metadata_cache
                file_mtime = st.st_mtime
                file_size = st.st_size
            except FileNotFoundError:
                self._metadata_cache = {'items': []}
                self._metadata_cache_mtime = 0.0
                self._metadata_cache_size = 0
                return self._metadata_cache
            except Exception:
                file_mtime = 0.0
                file_size = 0

            try:
                with open(self.meta_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self._metadata_cache = data
                self._metadata_cache_mtime = file_mtime
                self._metadata_cache_size = file_size
                return data
            except FileNotFoundError:
                self._metadata_cache = {'items': []}
                self._metadata_cache_mtime = 0.0
                self._metadata_cache_size = 0
                return self._metadata_cache
            except UnicodeDecodeError:
                # 文件因并发写入或异常退出导致编码损坏，尝试恢复
                logger.warning('隔离区元数据 UTF-8 解码失败，尝试恢复...')
                try:
                    # 尝试用 errors='replace' 读取，保留可解析部分
                    with open(self.meta_file, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                    data = json.loads(content)
                    logger.info('隔离区元数据恢复成功（replace 模式）')
                    # 恢复成功，立即用干净 UTF-8 重写（同时更新缓存）
                    self._save_metadata_unlocked(data)
                    return data
                except Exception:
                    logger.error('隔离区元数据无法恢复，备份并重置')
                    self._backup_corrupted_metadata()
                    self._metadata_cache = {'items': []}
                    self._metadata_cache_mtime = 0.0
                    self._metadata_cache_size = 0
                    return self._metadata_cache
            except json.JSONDecodeError:
                logger.warning('隔离区元数据 JSON 解析失败，备份并重置')
                self._backup_corrupted_metadata()
                self._metadata_cache = {'items': []}
                self._metadata_cache_mtime = 0.0
                self._metadata_cache_size = 0
                return self._metadata_cache
            except Exception as e:
                logger.warning(f'加载隔离区元数据失败: {e}')
                return self._metadata_cache if self._metadata_cache else {'items': []}

    def _save_metadata_unlocked(self, data: Dict):
        """保存隔离区元数据（内部方法，不获取锁，供 _load_metadata 恢复时调用）

        采用原子写入：先写入临时文件，再替换目标文件，避免写入过程中
        崩溃或并发读取导致文件损坏。

        保存成功后同步更新内存缓存，确保下次 _load_metadata 直接命中。
        """
        tmp_file = self.meta_file + '.tmp'
        try:
            with open(tmp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            # Windows 上 os.replace 是原子的，会覆盖目标文件
            os.replace(tmp_file, self.meta_file)
            # 保存成功：立即更新缓存 + mtime/size
            try:
                st = os.stat(self.meta_file)
                self._metadata_cache = data
                self._metadata_cache_mtime = st.st_mtime
                self._metadata_cache_size = st.st_size
            except Exception:
                # 缓存失效就好，不要让保存本身失败
                self._metadata_cache = None
                self._metadata_cache_mtime = 0.0
                self._metadata_cache_size = 0
        except Exception as e:
            logger.error(f'保存隔离区元数据失败: {e}')
            # 清理临时文件
            try:
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
            except Exception:
                pass

    def _backup_corrupted_metadata(self):
        """备份损坏的元数据文件并重置为空结构"""
        try:
            import time as _time
            backup_path = self.meta_file + f'.corrupt_{int(_time.time())}'
            os.replace(self.meta_file, backup_path)
            logger.info(f'已备份损坏的元数据到: {backup_path}')
        except Exception:
            pass
        # 重置为空结构
        try:
            with open(self.meta_file, 'w', encoding='utf-8') as f:
                json.dump({'items': []}, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f'重置元数据文件失败: {e}')

    def _save_metadata(self, data: Dict):
        """保存隔离区元数据（线程安全，原子写入）"""
        with self._meta_lock:
            self._save_metadata_unlocked(data)

    def _dedupe_key(self, item: Dict) -> str:
        """隔离条目去重键：**内容哈希 + 规范化原路径**。

        选择理由：
          - 内容哈希标识"同一对象"（同一恶意样本换名/换目录仍是同一份内容）；
          - 叠加规范化原路径，避免"同内容但来源不同"被错误地抹掉来源信息；
          - 两者都为空时退回隔离文件名，保证一定有键。
        """
        try:
            h = (item.get('file_hash') or '') or (item.get('object') or '')
            op = item.get('original_path') or ''
            if op:
                op = os.path.normcase(os.path.abspath(op))
            if not h and not op:
                return 'qf:' + os.path.normcase(str(
                    item.get('quarantine_path') or item.get('archive_path') or ''))
            return f'{h}|{op}'
        except Exception:
            return ''

    def _find_entry_by_key(self, file_hash: str, orig_path: str,
                           active_only: bool = True) -> Optional[dict]:
        """按去重键查找既有条目（默认仅活跃项）。"""
        try:
            h = file_hash or ''
            op = os.path.normcase(os.path.abspath(orig_path)) if orig_path else ''
            metadata = self._load_metadata()
            for item in metadata.get('items', []):
                if active_only and item.get('status') != 'quarantined':
                    continue
                ih = (item.get('file_hash') or '') or (item.get('object') or '')
                iop = item.get('original_path') or ''
                iop = os.path.normcase(os.path.abspath(iop)) if iop else ''
                if h and ih == h and iop == op:
                    return item
                # 兼容：历史条目可能缺 original_path，此时仅按哈希匹配
                if h and ih == h and not iop:
                    return item
        except Exception as e:
            logger.debug(f'按去重键查找条目失败: {e}')
        return None

    def _find_quarantined_by_hash(self, file_hash: str) -> Optional[dict]:
        """按文件哈希查找隔离区中已隔离且未删除/未恢复的条目。

        用于 quarantine_file 隔离前查重：同一文件（同哈希）可能被多个模块
        （实时监控/进程保护/手动扫描）重复命中，若无查重会向隔离区反复写入
        重复条目，导致隔离区出现多个同名文件。
        """
        if not file_hash:
            return None
        try:
            metadata = self._load_metadata()
            for item in metadata.get('items', []):
                if (item.get('file_hash') == file_hash
                        and item.get('status') == 'quarantined'):
                    return item
        except Exception:
            pass
        return None

    def is_hash_quarantined(self, file_hash: str) -> bool:
        """按文件哈希快速判断隔离区中是否存在'未删除/未恢复'的隔离条目。

        设计为轻量级公共 API：供实时监控、进程保护等高频调用方在扫描/处置前
        做前置去重，避免同一哈希被反复隔离、反复触发 on_threat 回调。

        相比直接使用 _find_quarantined_by_hash：
          - 语义更清晰（返回 bool，符合"是否已隔离"的判断场景）
          - 对外暴露稳定接口，内部实现可演进（后续可加内存缓存/过期清理）

        Args:
            file_hash: 文件 SHA-256 哈希（大小写敏感，空串直接返回 False）
        """
        if not file_hash:
            return False
        try:
            return self._find_quarantined_by_hash(file_hash) is not None
        except Exception:
            return False

    def remove_recreated_copy(self, file_path: str, file_hash: str = '') -> bool:
        """删除隔离之后重新出现在原路径的恶意副本。

        前置去重（is_hash_quarantined / quarantine_file 的 duplicate 分支）对已隔离
        哈希会跳过处置，但若该文件是隔离之后由下载器/云同步/再次解压等重新生成的
        副本，跳过会导致恶意文件长期留在磁盘（即"已隔离文件再次出现在桌面"）。
        本方法在哈希命中隔离区的前提下，直接删除这份新副本（隔离条目已存在，
        无需重复入隔离区）。

        Args:
            file_path: 当前在磁盘上的文件路径（通常为原始路径）
            file_hash: 已知哈希，可选；为空时内部按路径重新计算

        Returns:
            True 表示检测到并删除了重新出现的副本；False 表示无需处理或删除失败

        Note:
            软隔离（原地改名 .PSLS_QUARANTINED）时原路径已不存在，本方法不会命中误删。
        """
        try:
            if not os.path.exists(file_path):
                return False
            if not file_hash:
                file_hash = self._compute_file_hash(file_path)
            entry = self._find_quarantined_by_hash(file_hash)
            if entry is None:
                return False
            # 判定"重新出现"：文件修改时间晚于隔离记录时间。
            # 时间解析失败时退化为"文件存在即视为新副本"——哈希已命中隔离区，
            # 内容即已隔离的恶意文件，删除是安全且必要的。
            recreated = True
            qtime = entry.get('quarantine_time') or ''
            if qtime:
                try:
                    recreated = os.path.getmtime(file_path) > datetime.fromisoformat(qtime).timestamp()
                except Exception:
                    pass
            if not recreated:
                return False
            self._prep_for_remove(file_path)
            os.remove(file_path)
            logger.info(f"已删除隔离后重新出现的恶意副本: {file_path}")
            return True
        except Exception as e:
            logger.warning(f"删除重新出现的恶意副本失败 {file_path}: {e}")
            return False

    def quarantine_file(self, file_path: str, reason: str = '', malware_name: str = '',
                    internal_path: str = '', skip_exemption: bool = False) -> bool:
        """
        将文件隔离

        Args:
            file_path: 要隔离的文件路径
            reason: 隔离原因
            malware_name: 检测到的恶意软件名称
            internal_path: 归档内文件路径（如果是归档内文件）

        Returns:
            是否隔离成功，或 'exempted' 表示本次运行中已恢复豁免

        Note:
            失败时具体原因链会汇总记录到 self._last_quarantine_error，
            调用方可通过 get_last_quarantine_error() 获取并记录到日志。
        """
        # 重置上次失败原因
        self._last_quarantine_error = ''
        # 收集本次隔离的失败原因链（按尝试顺序）
        failure_reasons: List[str] = []

        # 自保护：拒绝隔离 PSLS 自身文件（路径级防护，不依赖哈希白名单）
        if self._is_self_protected(file_path):
            logger.warning(f'拒绝隔离 PSLS 自身受保护文件: {file_path}')
            self._last_quarantine_error = '自身受保护文件，禁止隔离'
            return False

        # 误报兜底：拒绝隔离 Windows 系统核心目录和已签名可信目录下的文件
        if self._is_system_protected(file_path):
            logger.warning(f'拒绝隔离系统受保护目录下的文件: {file_path}')
            self._last_quarantine_error = '系统受保护文件，禁止隔离（请人工确认）'
            return False

        # 解析归档路径
        archive_path = file_path
        is_archive_internal = False

        # 检查是否为归档内文件（路径格式: archive.zip -> internal/file.exe）
        if ' -> ' in file_path:
            is_archive_internal = True
            archive_path = file_path.split(' -> ')[0]

        # 规范化路径：确保存储的都是绝对路径，避免恢复时找不到文件
        # 这是"恢复隔离区文件后在原来位置找不到"的根因之一
        try:
            archive_path = os.path.abspath(archive_path)
            file_path = os.path.abspath(file_path) if ' -> ' not in file_path else file_path
        except Exception:
            pass

        if not os.path.exists(archive_path):
            err_msg = f"文件不存在: {archive_path}"
            logger.warning(err_msg)
            self._last_quarantine_error = err_msg
            return False

        # 豁免检查：本次运行中已恢复的文件不再隔离（沙箱分析触发时跳过此检查）
        if not skip_exemption and self._is_exempted(archive_path):
            logger.info(f"文件已豁免（本次运行已恢复），跳过隔离: {archive_path}")
            return 'exempted'

        # ---- 隔离前预处理：解除占用、清只读属性、调整ACL，避免"处理失败" ----
        try:
            self._prep_for_remove(archive_path)
        except Exception as prep_err:
            logger.debug(f"隔离前预处理未完全成功(继续尝试隔离): {prep_err}")
            failure_reasons.append(f"预处理未完全成功: {prep_err}")

        try:
            # 生成隔离文件名（使用哈希+时间戳）
            file_hash = self._compute_file_hash(archive_path)
            # 幂等查重：同一哈希文件已在隔离区（未删除/未恢复）则跳过重复隔离，
            # 避免实时监控/进程保护/手动扫描多路命中时隔离区堆积重复条目
            _dup_entry = self._find_entry_by_key(file_hash, archive_path)
            if _dup_entry:
                # 需求 1：**隔离动作照做，列表不重复**。
                #  - 动作：确保磁盘上的这份副本被"处置"——同内容已在隔离区时优先直接删除
                #    （无需重复存 blob）；删不掉（被占用等）则搬进隔离区唯一文件并登记为
                #    附加 blob（列表仍只有一条，清理/删除时会一并处理）；
                #  - 记账：在既有条目上累加次数、刷新最新时间、追加来源路径 → 不新增列表项。
                ext = os.path.splitext(os.path.basename(archive_path))[1]
                extra_blob = ''
                neutralized = False
                try:
                    if self.remove_recreated_copy(archive_path, file_hash):
                        neutralized = True
                        logger.info(f"已删除隔离后重新出现的副本: {file_path}")
                except Exception as rec_err:
                    logger.debug(f"清理重新出现的副本失败: {rec_err}")
                if not neutralized and os.path.exists(archive_path):
                    try:
                        extra_blob = os.path.join(
                            self.quarantine_dir,
                            f"{file_hash[:16]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                            f"_{threading.get_ident()}{ext}")
                        if self._encrypt_file(archive_path, extra_blob):
                            os.remove(archive_path)
                            neutralized = True
                        else:
                            shutil.move(archive_path, extra_blob)
                            neutralized = True
                        logger.info(f"重复内容已搬运入隔离区（附加 blob）: {extra_blob}")
                    except Exception as mv_err:
                        logger.warning(f"重复内容处置失败（仍留在磁盘）: {file_path}: {mv_err}")
                        extra_blob = ''
                now_str = datetime.now().isoformat()
                try:
                    with self._meta_lock:
                        meta = self._load_metadata()
                        for it in meta.get('items', []):
                            if self._dedupe_key(it) == self._dedupe_key(_dup_entry):
                                it['quarantine_count'] = int(
                                    it.get('quarantine_count', 1) or 1) + 1
                                it['last_quarantined'] = now_str
                                it['quarantine_time'] = now_str      # 保留最新时间
                                it.setdefault('first_quarantined',
                                              it.get('quarantine_time', now_str))
                                paths = it.setdefault('orig_paths', [])
                                try:
                                    real = os.path.abspath(archive_path)
                                except Exception:
                                    real = archive_path
                                if real and real not in paths:
                                    paths.append(real)
                                if extra_blob:
                                    it.setdefault('extra_blobs', []).append(extra_blob)
                                break
                        self._save_metadata_unlocked(meta)
                except Exception as merge_err:
                    logger.debug(f"合并隔离条目失败: {merge_err}")
                self._last_quarantine_error = ''
                # 保持既有契约：'duplicate' = "已处置但不是新增条目"（调用方静默、不弹窗/不计数）
                return 'duplicate'
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.basename(archive_path)
            ext = os.path.splitext(filename)[1]
            quarantine_filename = f"{file_hash[:16]}_{timestamp}{ext}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)

            # 移动文件到隔离区（加密后写入，然后删除原文件）
            moved = False

            # 方法1: 加密文件到隔离路径，然后删除原文件
            try:
                if self._encrypt_file(archive_path, quarantine_path):
                    os.remove(archive_path)
                    moved = True
            except Exception as enc_err:
                logger.warning(f"加密隔离失败: {enc_err}")
                failure_reasons.append(f"加密隔离失败: {enc_err}")

                # 方法2: 加密失败时降级为普通移动
                try:
                    shutil.move(archive_path, quarantine_path)
                    moved = True
                except Exception as move_err:
                    logger.warning(f"shutil.move失败: {move_err}")
                    failure_reasons.append(f"移动失败: {move_err}")

                    # 方法3: 尝试先复制再删除
                    try:
                        shutil.copy2(archive_path, quarantine_path)
                        os.remove(archive_path)
                        moved = True
                    except Exception as copy_err:
                        logger.warning(f"复制删除失败: {copy_err}")
                        failure_reasons.append(f"复制删除失败: {copy_err}")

            # ---- 降级：文件仍被占用时，做"软隔离"：改名+禁执行ACL+隐藏属性 ----
            if not moved and sys.platform == 'win32':
                try:
                    # 改名以阻止默认方式启动（双击/原路径运行）
                    poisoned_path = archive_path + '.PSLS_QUARANTINED'
                    try:
                        os.rename(archive_path, poisoned_path)
                        archive_path = poisoned_path
                    except Exception as ren_err:
                        logger.debug(f"改名软隔离失败: {ren_err}")
                        failure_reasons.append(f"改名软隔离失败: {ren_err}")

                    # 仅拒绝执行权限（保留读取/删除能力，便于恢复/删除操作）
                    try:
                        import subprocess
                        subprocess.run(
                            ['icacls', archive_path, '/deny', '*S-1-1-0:(OI)(CI)(X)', '/T', '/C'],
                            capture_output=True, timeout=10, creationflags=_HIDDEN_CREATIONFLAGS
                        )
                    except Exception:
                        pass
                    # 设隐藏+系统属性，降低可见度
                    try:
                        import ctypes
                        FILE_ATTRIBUTE_HIDDEN = 0x02
                        FILE_ATTRIBUTE_SYSTEM = 0x04
                        ctypes.windll.kernel32.SetFileAttributesW(
                            archive_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
                        )
                    except Exception:
                        pass
                    moved = True
                    quarantine_path = archive_path  # 记录原地软隔离
                    logger.warning(f"隔离失败，已降级为原地软隔离(改名+ACL): {archive_path}")
                    # 登记到稳定软隔离表：即使主隔离目录被更改/清理，软隔离文件
                    # 仍能在隔离区列表中出现并被恢复（此前记录随目录丢失变孤儿）
                    self._register_soft_quarantine({
                        'original_path': file_path,
                        'archive_path': archive_path,
                        'quarantine_path': quarantine_path,
                        'filename': filename,
                        'malware_name': malware_name,
                        'reason': reason,
                        'file_hash': file_hash,
                    })
                except Exception as soft_err:
                    logger.warning(f"原地软隔离也失败: {soft_err}")
                    failure_reasons.append(f"原地软隔离失败: {soft_err}")

            if not moved:
                err_summary = '；'.join(failure_reasons) if failure_reasons else '无法移动或复制文件（原因未知）'
                self._last_quarantine_error = err_summary
                logger.error(f"隔离文件失败 {file_path}: {err_summary}")
                return False

            # 记录元数据
            metadata = self._load_metadata()
            metadata['items'].append({
                'original_path': file_path,  # 保留原始显示路径
                'archive_path': archive_path,  # 归档文件实际路径
                'internal_path': internal_path,  # 归档内文件路径（如果有）
                'quarantine_path': quarantine_path,  # 存储绝对路径
                'file_hash': file_hash,
                'filename': filename,
                'malware_name': malware_name,
                'reason': reason,
                'is_archive_internal': is_archive_internal,
                'quarantine_time': datetime.now().isoformat(),
                # 需求 1：审计用计数与时间（重复隔离时在原条目上累加，不新增列表项）
                'quarantine_count': 1,
                'first_quarantined': datetime.now().isoformat(),
                'last_quarantined': datetime.now().isoformat(),
                'orig_paths': [file_path],
                'status': 'quarantined',  # quarantined, restored, deleted
            })
            self._save_metadata(metadata)

            if is_archive_internal:
                logger.info(f"归档文件已隔离（内部文件: {internal_path}）: {archive_path} -> {quarantine_path}")
            else:
                logger.info(f"文件已隔离: {file_path} -> {quarantine_path}")
            return True

        except Exception as e:
            err_msg = f"隔离异常: {e}"
            failure_reasons.append(err_msg)
            err_summary = '；'.join(failure_reasons)
            self._last_quarantine_error = err_summary
            logger.error(f"隔离文件失败 {file_path}: {err_summary}")
            return False

    def get_last_quarantine_error(self) -> str:
        """获取最近一次隔离操作的失败原因（供调用方记录到日志）

        Returns:
            失败原因摘要字符串；若上次隔离成功或为空则返回空字符串
        """
        return self._last_quarantine_error

    def _prep_for_remove(self, file_path: str):
        """
        删除/隔离前的通用预处理：
        1) 清除只读/系统/存档属性（避免"Permission denied"）
        2) Windows下尝试takeown + icacls grant获取文件控制权
        3) 结束正在持有该文件的同名进程（最常见的隔离失败原因）
        """
        try:
            if not os.path.exists(file_path):
                return
            import stat
            # 1. 清只读/系统等属性
            try:
                attrs = os.stat(file_path).st_mode
                os.chmod(file_path, attrs | stat.S_IWRITE | stat.S_IREAD | stat.S_IWUSR | stat.S_IRUSR)
            except Exception:
                pass
            if sys.platform == 'win32':
                try:
                    import subprocess
                    subprocess.run(
                        ['attrib', '-R', '-S', '-H', file_path],
                        capture_output=True, timeout=5, creationflags=_HIDDEN_CREATIONFLAGS
                    )
                except Exception:
                    pass

            # 2. 结束与该文件同名/同路径相关的进程（典型：恶意程序自身在运行，句柄未释放）
            self._kill_processes_for_file(file_path)

            # 3. 尝试取得所有权并赋权（管理员权限不足时的常见失败点）
            if sys.platform == 'win32':
                # 先移除 DENY ACL 规则（软隔离添加的 deny 会阻塞所有权限）
                try:
                    import subprocess
                    subprocess.run(
                        ['icacls', file_path, '/delete', '*S-1-1-0', '/deny', '/T', '/C'],
                        capture_output=True, timeout=8, creationflags=_HIDDEN_CREATIONFLAGS
                    )
                except Exception:
                    pass
                try:
                    import subprocess
                    subprocess.run(
                        ['takeown', '/F', file_path, '/A', '/R', '/D', 'Y'],
                        capture_output=True, timeout=8, creationflags=_HIDDEN_CREATIONFLAGS
                    )
                except Exception:
                    pass
                try:
                    import subprocess
                    subprocess.run(
                        ['icacls', file_path, '/grant',
                         '*S-1-5-32-544:(OI)(CI)F', '*S-1-1-0:(OI)(CI)M', '/T', '/C'],
                        capture_output=True, timeout=8, creationflags=_HIDDEN_CREATIONFLAGS
                    )
                except Exception:
                    pass
        except Exception:
            pass

    def _fix_file_permissions(self, file_path: str):
        """
        修复文件读取/删除权限（轻量级版本，用于恢复/删除时）
        与 _prep_for_remove 不同，此方法不杀进程，仅修复文件属性和ACL
        """
        if not os.path.exists(file_path):
            return
        try:
            import stat
            # 清除只读/系统/隐藏属性
            try:
                attrs = os.stat(file_path).st_mode
                os.chmod(file_path, attrs | stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass
            if sys.platform == 'win32':
                try:
                    import subprocess
                    subprocess.run(
                        ['attrib', '-R', '-S', '-H', file_path],
                        capture_output=True, timeout=5, creationflags=_HIDDEN_CREATIONFLAGS
                    )
                except Exception:
                    pass
                # 先移除可能存在的 DENY ACL 规则（软隔离添加的 deny 会阻塞所有权限）
                try:
                    import subprocess
                    # 移除所有人的 deny 规则
                    subprocess.run(
                        ['icacls', file_path, '/delete', '*S-1-1-0', '/deny', '/T', '/C'],
                        capture_output=True, timeout=10, creationflags=_HIDDEN_CREATIONFLAGS
                    )
                except Exception:
                    pass
                # 尝试获取文件所有权并赋予读写权限
                try:
                    import subprocess
                    subprocess.run(
                        ['takeown', '/F', file_path, '/A', '/D', 'Y'],
                        capture_output=True, timeout=10, creationflags=_HIDDEN_CREATIONFLAGS
                    )
                except Exception:
                    pass
                try:
                    import subprocess
                    subprocess.run(
                        ['icacls', file_path, '/grant',
                         '*S-1-5-32-544:(OI)(CI)F', '*S-1-1-0:(OI)(CI)M', '/C'],
                        capture_output=True, timeout=10, creationflags=_HIDDEN_CREATIONFLAGS
                    )
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def _kill_processes_for_file(file_path: str) -> int:
        """
        结束持有目标文件路径（或其同名可执行）的进程，返回成功结束的进程数。
        使用 PowerShell + ctypes Toolhelp + taskkill 三重策略，避免 wmic 等被禁用时失败。
        """
        killed = 0
        try:
            if not (os.path.exists(file_path) and sys.platform == 'win32'):
                return 0
            try:
                norm_path = os.path.normcase(os.path.abspath(file_path))
            except Exception:
                return 0

            # 策略1：PowerShell Get-Process，匹配 Path/Name
            try:
                import subprocess
                base = os.path.basename(norm_path).replace("'", "''")
                full = norm_path.replace("'", "''")
                cmd = (
                    '$targets = Get-Process -ErrorAction SilentlyContinue | Where-Object {'
                    ' ($_.Path -and ([System.IO.Path]::GetFullPath($_.Path) -ieq \'' + full + '\'))'
                    ' -or ($_.Name -ieq \'' + base + '\') }; '
                    'if ($targets) { $targets | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue; $_.Id } }'
                )
                cp = subprocess.run(
                    ['powershell', '-NoProfile', '-NonInteractive', '-Command', cmd],
                    capture_output=True, text=True, timeout=12, creationflags=_HIDDEN_CREATIONFLAGS
                )
                killed += sum(1 for _ in cp.stdout.strip().splitlines() if _.strip())
            except Exception:
                pass

            # 策略2：ctypes Toolhelp32 快照直接 TerminateProcess（对 SYSTEM 进程仍可成功部分）
            try:
                import ctypes
                import ctypes.wintypes
                PROCESS_TERMINATE = 0x0001
                PROCESS_QUERY_INFORMATION = 0x0400
                TH32CS_SNAPPROCESS = 0x00000002

                class PROCESSENTRY32(ctypes.Structure):
                    _fields_ = [
                        ('dwSize', ctypes.wintypes.DWORD),
                        ('cntUsage', ctypes.wintypes.DWORD),
                        ('th32ProcessID', ctypes.wintypes.DWORD),
                        ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
                        ('th32ModuleID', ctypes.wintypes.DWORD),
                        ('cntThreads', ctypes.wintypes.DWORD),
                        ('th32ParentProcessID', ctypes.wintypes.DWORD),
                        ('pcPriClassBase', ctypes.c_long),
                        ('dwFlags', ctypes.wintypes.DWORD),
                        ('szExeFile', ctypes.c_char * 260),
                    ]

                CreateToolhelp32Snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot
                Process32First = ctypes.windll.kernel32.Process32First
                Process32Next = ctypes.windll.kernel32.Process32Next
                CloseHandle = ctypes.windll.kernel32.CloseHandle
                OpenProcess = ctypes.windll.kernel32.OpenProcess
                TerminateProcess = ctypes.windll.kernel32.TerminateProcess

                snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                if snap != -1:
                    try:
                        pe = PROCESSENTRY32()
                        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
                        if Process32First(snap, ctypes.byref(pe)):
                            target_exe_lower = os.path.basename(norm_path).lower()
                            while True:
                                try:
                                    exe_name = pe.szExeFile.decode('mbcs', errors='ignore').lower()
                                except Exception:
                                    exe_name = ''
                                if exe_name == target_exe_lower:
                                    h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, False, pe.th32ProcessID)
                                    if h:
                                        try:
                                            if TerminateProcess(h, 1) != 0:
                                                killed += 1
                                        finally:
                                            CloseHandle(h)
                                if not Process32Next(snap, ctypes.byref(pe)):
                                    break
                    finally:
                        CloseHandle(snap)
            except Exception:
                pass

            # 策略3：taskkill /F /IM /T 兜底（兼容性最广）
            try:
                import subprocess
                subprocess.run(
                    ['taskkill', '/F', '/IM', os.path.basename(file_path), '/T'],
                    capture_output=True, timeout=8, creationflags=_HIDDEN_CREATIONFLAGS
                )
            except Exception:
                pass

            return killed
        except Exception:
            return killed

    def _detect_processes_for_file(self, file_path: str) -> List[int]:
        """检测持有目标文件路径（或其同名可执行）的进程 PID 列表（不终止）

        用于 terminate_malware_process 在终止前先统计目标进程数，
        以便在弹窗中区分"无进程运行"与"有进程但终止失败"。
        """
        pids: List[int] = []
        try:
            if not (os.path.exists(file_path) and sys.platform == 'win32'):
                return pids
            try:
                norm_path = os.path.normcase(os.path.abspath(file_path))
            except Exception:
                return pids

            # 策略1：PowerShell Get-Process 枚举匹配 Path/Name 的进程
            try:
                import subprocess
                base = os.path.basename(norm_path).replace("'", "''")
                full = norm_path.replace("'", "''")
                cmd = (
                    '$targets = Get-Process -ErrorAction SilentlyContinue | Where-Object {'
                    ' ($_.Path -and ([System.IO.Path]::GetFullPath($_.Path) -ieq \'' + full + '\'))'
                    ' -or ($_.Name -ieq \'' + base + '\') }; '
                    'if ($targets) { $targets | ForEach-Object { $_.Id } }'
                )
                cp = subprocess.run(
                    ['powershell', '-NoProfile', '-NonInteractive', '-Command', cmd],
                    capture_output=True, text=True, timeout=10, creationflags=_HIDDEN_CREATIONFLAGS
                )
                for line in cp.stdout.strip().splitlines():
                    line = line.strip()
                    if line and line.isdigit():
                        pids.append(int(line))
            except Exception:
                pass

            # 策略2：ctypes Toolhelp32 快照枚举同名可执行进程
            try:
                import ctypes
                import ctypes.wintypes
                TH32CS_SNAPPROCESS = 0x00000002
                class PROCESSENTRY32(ctypes.Structure):
                    _fields_ = [
                        ('dwSize', ctypes.wintypes.DWORD),
                        ('cntUsage', ctypes.wintypes.DWORD),
                        ('th32ProcessID', ctypes.wintypes.DWORD),
                        ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
                        ('th32ModuleID', ctypes.wintypes.DWORD),
                        ('cntThreads', ctypes.wintypes.DWORD),
                        ('th32ParentProcessID', ctypes.wintypes.DWORD),
                        ('pcPriClassBase', ctypes.c_long),
                        ('dwFlags', ctypes.wintypes.DWORD),
                        ('szExeFile', ctypes.c_char * 260),
                    ]
                snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                if snap != -1:
                    try:
                        pe = PROCESSENTRY32()
                        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
                        target_exe_lower = os.path.basename(norm_path).lower()
                        if ctypes.windll.kernel32.Process32First(snap, ctypes.byref(pe)):
                            while True:
                                try:
                                    exe_name = pe.szExeFile.decode('mbcs', errors='ignore').lower()
                                except Exception:
                                    exe_name = ''
                                if exe_name == target_exe_lower:
                                    if pe.th32ProcessID not in pids:
                                        pids.append(pe.th32ProcessID)
                                if not ctypes.windll.kernel32.Process32Next(snap, ctypes.byref(pe)):
                                    break
                    finally:
                        ctypes.windll.kernel32.CloseHandle(snap)
            except Exception:
                pass
        except Exception:
            pass
        return pids

    def terminate_malware_process(self, file_path: str, malware_name: str = '') -> Dict:
        """终止恶意软件进程（独立能力，可用于隔离前的进程清理或单独的进程终止动作）

        先检测目标文件对应的运行进程，再调用 _kill_processes_for_file 终止。
        返回结构化结果，供 bridge 层弹窗通知用户。

        Args:
            file_path: 恶意软件文件路径（按同名可执行/路径匹配进程）
            malware_name: 检测到的恶意软件名称（用于日志）

        Returns:
            {
                'success': bool,           # 是否成功终止所有检测到的进程
                'action': 'terminate_process',
                'detected_count': int,     # 检测到的进程数
                'killed_count': int,       # 实际终止的进程数
                'killed_pids': list,       # 已终止的 PID 列表
                'message': str,            # 用户可读的描述
                'has_process': bool,       # 是否检测到有进程运行（无进程时不弹窗）
            }
        """
        result = {
            'success': False,
            'action': 'terminate_process',
            'detected_count': 0,
            'killed_count': 0,
            'killed_pids': [],
            'message': '',
            'has_process': False,
        }
        try:
            # 解析归档内文件路径（格式: archive.zip -> internal/file.exe）
            # 归档内文件没有独立进程，直接返回无进程
            target_path = file_path
            if ' -> ' in file_path:
                target_path = file_path.split(' -> ')[0]

            if not os.path.exists(target_path):
                result['message'] = '文件不存在，无需终止进程'
                return result

            if sys.platform != 'win32':
                result['message'] = '当前系统不支持进程终止'
                return result

            # 检测目标进程
            detected_pids = self._detect_processes_for_file(target_path)
            result['detected_count'] = len(detected_pids)
            result['has_process'] = len(detected_pids) > 0

            if not detected_pids:
                result['success'] = True  # 无进程运行视为"无需处理"，成功
                result['message'] = '未检测到运行中的进程'
                return result

            # 调用三重策略终止进程
            killed_count = self._kill_processes_for_file(target_path)

            # 重新检测，确认哪些 PID 已被终止
            remaining_pids = self._detect_processes_for_file(target_path)
            killed_pids = [pid for pid in detected_pids if pid not in remaining_pids]

            result['killed_count'] = len(killed_pids)
            result['killed_pids'] = killed_pids
            result['success'] = len(remaining_pids) == 0

            name_hint = f' ({malware_name})' if malware_name else ''
            if result['success']:
                if len(killed_pids) > 0:
                    result['message'] = f'已终止 {len(killed_pids)} 个恶意进程{name_hint}'
                    logger.info(f'终止恶意进程成功: {target_path} -> PID {killed_pids}{name_hint}')
                else:
                    # 检测到进程但 killed_count=0 且 remaining 为空：可能进程已自行退出
                    result['message'] = f'检测到 {len(detected_pids)} 个进程，已全部结束{name_hint}'
            else:
                failed_count = len(remaining_pids)
                result['message'] = (
                    f'终止进程失败: 检测到 {len(detected_pids)} 个进程，'
                    f'已终止 {len(killed_pids)} 个，剩余 {failed_count} 个无法终止{name_hint}'
                )
                logger.warning(
                    f'终止恶意进程失败: {target_path} -> 剩余 PID {remaining_pids}{name_hint}'
                )
        except Exception as e:
            logger.error(f'终止恶意进程异常 {file_path}: {e}')
            result['message'] = f'终止进程异常: {str(e)}'
        return result

    def restore_file(self, quarantine_id: int) -> bool:
        """
        恢复隔离的文件
        
        Args:
            quarantine_id: 隔离记录的索引

        Returns:
            是否恢复成功
        """
        metadata = self._load_metadata()
        items = metadata.get('items', [])

        if quarantine_id < 0 or quarantine_id >= len(items):
            logger.debug("无效的隔离记录ID")
            return False

        item = items[quarantine_id]
        
        if item['status'] != 'quarantined':
            logger.info("文件状态不是已隔离")
            return False
        
        try:
            # 获取隔离路径（检查是否需要重新定位）
            quarantine_path = item['quarantine_path']
            
            # 如果隔离路径不存在，尝试在当前隔离区目录中查找
            if not os.path.exists(quarantine_path):
                # 尝试根据文件名在当前隔离区目录中查找
                filename = os.path.basename(quarantine_path)
                new_path = os.path.join(self.quarantine_dir, filename)
                if os.path.exists(new_path):
                    quarantine_path = new_path
                    logger.info(f"隔离文件路径已更新: {new_path}")
                else:
                    # 尝试查找匹配哈希的文件
                    file_hash = item.get('file_hash', '')
                    if file_hash:
                        for f in os.listdir(self.quarantine_dir):
                            if f.startswith(file_hash[:16]):
                                new_path = os.path.join(self.quarantine_dir, f)
                                if os.path.exists(new_path):
                                    quarantine_path = new_path
                                    logger.info(f"通过哈希找到隔离文件: {new_path}")
                                    break
            
            if not os.path.exists(quarantine_path):
                logger.debug(f"隔离文件不存在，标记为已恢复: {quarantine_path}")
                # 文件已不存在（可能被外部清理），直接更新状态为已恢复
                item['status'] = 'restored'
                item['restore_time'] = datetime.now().isoformat()
                item['restore_note'] = 'file_missing'
                self._save_metadata(metadata)
                # 仍将原始路径加入豁免集合
                orig_path = item.get('archive_path', item.get('original_path', ''))
                if orig_path:
                    self._add_exemption(orig_path)
                return True
            
            # 使用 original_path 作为恢复目标（始终是原始路径，不受软隔离影响）
            # archive_path 在软隔离时被改为 .PSLS_QUARANTINED 路径，不能用作恢复目标
            original_path = item['original_path']

            # ---- 原地软隔离特判：隔离文件从未离开原路径（quarantine_path 即原始文件） ----
            # 原地软隔离是 quarantine_file 降级路径（"改名+ACL"）：quarantine_path 记录的就是
            # 原文件本身，恢复即解除 ACL 限制并清除隐藏/系统属性，无需也无法移动/解密
            # （源与目标为同一文件，shutil.copy2/move 会抛 'are the same file' 导致恢复失败）。
            try:
                _qp_abs = os.path.normcase(os.path.normpath(os.path.abspath(quarantine_path)))
                _op_abs = os.path.normcase(os.path.normpath(os.path.abspath(original_path)))
                _ap_abs = os.path.normcase(os.path.normpath(os.path.abspath(item.get('archive_path', '')) or ''))
                if _qp_abs == _op_abs or (_ap_abs and _qp_abs == _ap_abs):
                    self._fix_file_permissions(quarantine_path)
                    if sys.platform == 'win32':
                        try:
                            import ctypes
                            # 清除隐藏/系统属性，让文件重新可见
                            ctypes.windll.kernel32.SetFileAttributesW(quarantine_path, 0x00)
                        except Exception:
                            pass
                    # 改名型软隔离（<原文件>.PSLS_QUARANTINED）恢复时必须**改回原名**：
                    # 否则只解除 ACL/隐藏属性、文件仍以 .PSLS_QUARANTINED 命名存在，
                    # 被隔离的程序依旧无法运行（等于"恢复了但没恢复"）。
                    try:
                        if (_qp_abs != _op_abs
                                and quarantine_path.endswith(SOFT_QUARANTINE_SUFFIX)
                                and original_path):
                            _rdir = os.path.dirname(original_path)
                            if _rdir and not os.path.isdir(_rdir):
                                os.makedirs(_rdir, exist_ok=True)
                            if (os.path.exists(original_path)
                                    and os.path.normcase(os.path.abspath(original_path)) != _qp_abs):
                                os.remove(original_path)
                            os.replace(quarantine_path, original_path)
                            logger.info(f"软隔离文件已改回原名: {original_path}")
                    except Exception as _ren_err:
                        logger.warning(
                            f"软隔离改名回原失败（文件保持 .PSLS_QUARANTINED 名）: {_ren_err}")
                    item['status'] = 'restored'
                    item['restore_time'] = datetime.now().isoformat()
                    item['restore_note'] = 'in_place_unquarantined'
                    self._save_metadata(metadata)
                    self._unregister_soft_quarantine(original_path)
                    self._add_exemption(original_path)
                    logger.info(f"原地软隔离文件已解除隔离（原路径）: {quarantine_path}")
                    return True
            except Exception as in_place_err:
                logger.warning(f"原地软隔离特判失败，继续常规恢复: {in_place_err}")

            # 防路径逃逸：拒绝含 .. 路径组件或非绝对路径的原始路径，改写为安全兜底
            _has_traversal = False
            try:
                for _seg in str(original_path).replace('/', os.sep).split(os.sep):
                    if _seg == '..':
                        _has_traversal = True
                        break
            except Exception:
                _has_traversal = True
            if _has_traversal or not os.path.isabs(original_path):
                logger.warning(f"隔离恢复目标不合法(含穿越/非绝对路径)，将恢复到安全目录: {original_path}")
                original_path = os.path.join(
                    os.path.expanduser('~'), 'Documents', 'Quarantine_Restored', item['filename']
                )
            
            # 检查原始目录是否可写（系统受保护目录通常不可写）
            original_dir = os.path.dirname(original_path)
            dir_writable = False
            try:
                if os.path.exists(original_dir):
                    test_file = os.path.join(original_dir, '.psls_write_test')
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    dir_writable = True
                else:
                    dir_writable = True  # 目录不存在时尝试创建
            except Exception:
                dir_writable = False
            
            if not dir_writable:
                logger.warning(f"原始目录不可写({original_dir})，将恢复到备用目录")
                original_path = os.path.join(
                    os.path.expanduser('~'), 'Documents', 'Quarantine_Restored', item['filename']
                )
                dir_writable = True
            
            # 确保目标目录存在
            original_dir = os.path.dirname(original_path)
            if not os.path.exists(original_dir):
                try:
                    os.makedirs(original_dir, exist_ok=True)
                except Exception as e:
                    logger.warning(f"创建目标目录失败: {e}")
                    # 最终兜底
                    fallback_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'Quarantine_Restored')
                    os.makedirs(fallback_dir, exist_ok=True)
                    original_path = os.path.join(fallback_dir, item['filename'])
            
            # 恢复文件（解密隔离文件到目标路径）
            restored = False

            # 方法1: 解密文件到目标路径
            try:
                # 尝试修复源文件读取权限（软隔离文件可能在受保护目录）
                self._fix_file_permissions(quarantine_path)
                if self._decrypt_file(quarantine_path, original_path):
                    try:
                        os.remove(quarantine_path)
                    except Exception:
                        pass  # 软隔离文件可能无法删除，不影响恢复结果
                    restored = True
            except Exception as dec_err:
                logger.warning(f"解密恢复失败: {dec_err}")

                # 方法2: 降级为普通移动
                try:
                    shutil.move(quarantine_path, original_path)
                    restored = True
                except Exception as move_err:
                    logger.warning(f"shutil.move失败: {move_err}")

                    # 方法3: 尝试先复制再删除
                    try:
                        shutil.copy2(quarantine_path, original_path)
                        try:
                            os.remove(quarantine_path)
                        except Exception:
                            pass
                        restored = True
                    except Exception as copy_err:
                        logger.warning(f"复制删除失败: {copy_err}")

            # 所有方法均失败：尝试恢复到用户文档目录（最终兜底）
            if not restored:
                fallback_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'Quarantine_Restored')
                os.makedirs(fallback_dir, exist_ok=True)
                fallback_path = os.path.join(fallback_dir, item['filename'])
                logger.info(f"尝试恢复到备用目录: {fallback_path}")
                try:
                    self._fix_file_permissions(quarantine_path)
                    if self._decrypt_file(quarantine_path, fallback_path):
                        try:
                            os.remove(quarantine_path)
                        except Exception:
                            pass
                        restored = True
                        original_path = fallback_path
                except Exception as dec_err2:
                    logger.warning(f"备用目录解密失败: {dec_err2}")
                    try:
                        shutil.move(quarantine_path, fallback_path)
                        restored = True
                        original_path = fallback_path
                    except Exception as move_err2:
                        logger.warning(f"备用目录移动失败: {move_err2}")
            
            if not restored:
                logger.warning(f"恢复文件失败: 无法移动或复制文件")
                return False
            
            # 恢复后验证：确认文件确实存在于目标位置
            # 这是"恢复隔离区文件后在原来位置找不到"的关键反馈机制
            if not os.path.exists(original_path):
                logger.error(f"恢复失败：文件未出现在目标位置 {original_path}")
                # 尝试在隔离目录或备用目录中查找
                alt_locations = [
                    os.path.join(self.quarantine_dir, item.get('filename', '')),
                    os.path.join(os.path.expanduser('~'), 'Documents', 'Quarantine_Restored', item.get('filename', '')),
                ]
                for alt in alt_locations:
                    if os.path.exists(alt):
                        logger.warning(f"文件实际位于: {alt}")
                        # 更新记录为实际位置
                        item['original_path'] = alt
                        item['restore_note'] = f"恢复到备用位置: {alt}"
                        self._add_exemption(alt)
                        # 通知用户文件在备用位置
                        return {'success': True, 'actual_path': alt, 'note': f'文件已恢复到备用位置：{alt}'}
                return False
            
            # 成功恢复到原始位置：修复文件属性（清除隐藏/系统属性）
            try:
                import ctypes
                FILE_ATTRIBUTE_NORMAL = 0x00
                ctypes.windll.kernel32.SetFileAttributesW(original_path, FILE_ATTRIBUTE_NORMAL)
            except Exception:
                pass
            
            # 更新状态
            item['status'] = 'restored'
            item['restore_time'] = datetime.now().isoformat()
            item['actual_restore_path'] = original_path  # 记录实际恢复位置
            self._save_metadata(metadata)

            # 将恢复的文件加入本次运行的豁免集合
            self._add_exemption(original_path)
            logger.info(f"已加入豁免列表，本次运行不再隔离: {original_path}")
            
            if item.get('is_archive_internal'):
                logger.info(f"归档文件已恢复（内部文件: {item.get('internal_path', '')}）: {quarantine_path} -> {original_path}")
            else:
                logger.info(f"文件已恢复: {quarantine_path} -> {original_path}")
            return True
            
        except Exception as e:
            logger.debug(f"恢复文件失败: {e}")
            return False
    
    def delete_file(self, quarantine_id: int) -> bool:
        """
        删除隔离的文件
        
        Args:
            quarantine_id: 隔离记录的索引
            
        Returns:
            是否删除成功
        """
        metadata = self._load_metadata()
        items = metadata.get('items', [])
        
        if quarantine_id < 0 or quarantine_id >= len(items):
            logger.debug("无效的隔离记录ID")
            return False
        
        item = items[quarantine_id]
        
        try:
            quarantine_path = item['quarantine_path']
            
            if os.path.exists(quarantine_path):
                # 使用 _prep_for_remove：先杀进程再修复权限（处理文件被占用的情况）
                self._prep_for_remove(quarantine_path)
                
                # 尝试直接删除
                deleted = False
                try:
                    os.remove(quarantine_path)
                    deleted = True
                except Exception:
                    pass
                
                # 直接删除失败时尝试移动到临时目录再删除
                if not deleted:
                    try:
                        import tempfile
                        tmp_dir = tempfile.gettempdir()
                        tmp_path = os.path.join(tmp_dir, os.path.basename(quarantine_path) + '.psls_del')
                        shutil.move(quarantine_path, tmp_path)
                        try:
                            os.remove(tmp_path)
                        except Exception:
                            pass
                        deleted = True
                    except Exception:
                        pass
                
                # 仍失败：尝试用Windows API强制删除
                if not deleted and sys.platform == 'win32':
                    try:
                        import subprocess
                        subprocess.run(
                            ['cmd', '/c', 'del', '/F', '/Q', quarantine_path],
                            capture_output=True, timeout=10, creationflags=_HIDDEN_CREATIONFLAGS
                        )
                        if not os.path.exists(quarantine_path):
                            deleted = True
                    except Exception:
                        pass
                
                if not deleted and os.path.exists(quarantine_path):
                    logger.warning(f"无法删除隔离文件: {quarantine_path}")
                    return False
            
            # 更新状态
            item['status'] = 'deleted'
            item['delete_time'] = datetime.now().isoformat()
            self._save_metadata(metadata)
            
            logger.info(f"文件已删除: {quarantine_path}")
            return True
            
        except Exception as e:
            logger.debug(f"删除文件失败: {e}")
            return False
    
    # ------------------------------------------------------------------
    # 软隔离登记表（稳定路径，保证软隔离文件在隔离区可见且可恢复）
    # ------------------------------------------------------------------

    def _load_soft_registry(self) -> List[Dict]:
        """读取软隔离登记表（mtime/size 缓存，热路径不反复读盘）。"""
        path = _get_soft_registry_path()
        try:
            st = os.stat(path)
            if (self._soft_cache is not None
                    and self._soft_cache_mtime == st.st_mtime
                    and self._soft_cache_size == st.st_size):
                return self._soft_cache
        except FileNotFoundError:
            self._soft_cache = []
            self._soft_cache_mtime = 0.0
            self._soft_cache_size = 0
            return self._soft_cache
        except Exception:
            pass
        recs: List[Dict] = []
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            raw = data.get('items') if isinstance(data, dict) else data
            if isinstance(raw, list):
                recs = [r for r in raw if isinstance(r, dict)]
        except Exception:
            recs = []
        self._soft_cache = recs
        try:
            st = os.stat(path)
            self._soft_cache_mtime = st.st_mtime
            self._soft_cache_size = st.st_size
        except Exception:
            self._soft_cache_mtime = 0.0
            self._soft_cache_size = 0
        return recs

    def _save_soft_registry(self, records: List[Dict]) -> None:
        try:
            with open(_get_soft_registry_path(), 'w', encoding='utf-8') as f:
                json.dump({'items': records}, f, ensure_ascii=False, indent=2)
            st = os.stat(_get_soft_registry_path())
            self._soft_cache = list(records)
            self._soft_cache_mtime = st.st_mtime
            self._soft_cache_size = st.st_size
        except Exception as e:
            logger.warning(f'保存软隔离登记表失败: {e}')

    def _register_soft_quarantine(self, rec: Dict) -> None:
        """登记一个软隔离文件（写稳定路径，防止记录随隔离目录迁移而丢失）。"""
        try:
            records = self._load_soft_registry()

            def _key(d: Dict) -> str:
                p = d.get('quarantine_path') or d.get('archive_path') \
                    or d.get('original_path') or ''
                try:
                    return os.path.normcase(os.path.abspath(p))
                except Exception:
                    return str(p).lower()

            key = _key(rec)
            out: List[Dict] = []
            replaced = False
            for r in records:
                if _key(r) == key:
                    merged = dict(r)
                    merged.update(rec)
                    merged['status'] = 'quarantined'
                    out.append(merged)
                    replaced = True
                else:
                    out.append(r)
            if not replaced:
                entry = dict(rec)
                entry['registered_at'] = datetime.now().isoformat()
                entry['status'] = 'quarantined'
                out.append(entry)
            self._save_soft_registry(out)
            logger.info(f'软隔离已登记（隔离区可见/可恢复）: {rec.get("original_path")}')
        except Exception as e:
            logger.warning(f'登记软隔离记录失败: {e}')

    def _unregister_soft_quarantine(self, original_path: str) -> None:
        """从软隔离登记表移除记录（恢复成功后即时调用，保持登记表一致）。"""
        try:
            if not original_path:
                return
            records = self._load_soft_registry()
            if not records:
                return
            try:
                key = os.path.normcase(os.path.abspath(original_path))
            except Exception:
                key = str(original_path).lower()
            kept: List[Dict] = []
            removed = False
            for r in records:
                op = r.get('original_path') or ''
                try:
                    rk = os.path.normcase(os.path.abspath(op)) if op else ''
                except Exception:
                    rk = ''
                if rk and rk == key:
                    removed = True
                    continue
                kept.append(r)
            if removed:
                self._save_soft_registry(kept)
        except Exception as e:
            logger.debug(f'清理软隔离登记记录失败: {e}')

    def _reconcile_soft_registry(self, metadata: Dict) -> bool:
        """把软隔离登记表并入主元数据，使其在隔离区列表可见、可恢复。

        - 登记文件仍存在且主元数据中无该 original_path 记录 → 追加为活跃隔离项；
        - 登记文件已不存在（已恢复/已删除）→ 从登记表清理。
        返回 True 表示登记表发生变化（调用方需保存）。
        """
        try:
            records = self._load_soft_registry()
            if not records:
                return False
            items = metadata.setdefault('items', [])
            present = set()
            for it in items:
                op = it.get('original_path') or ''
                if op:
                    try:
                        present.add(os.path.normcase(os.path.abspath(op)))
                    except Exception:
                        pass
            kept: List[Dict] = []
            changed = False
            for r in records:
                qp = (r.get('quarantine_path') or r.get('archive_path')
                      or r.get('original_path') or '')
                op = r.get('original_path') or ''
                # 文件已不存在 → 登记表清理（恢复改名回原 / 已删除）
                if not qp or not os.path.exists(qp):
                    changed = True
                    continue
                kept.append(r)
                try:
                    op_key = os.path.normcase(os.path.abspath(op)) if op else ''
                except Exception:
                    op_key = ''
                if op_key and op_key not in present:
                    items.append({
                        'original_path': op,
                        'archive_path': r.get('archive_path') or qp,
                        'internal_path': '',
                        'quarantine_path': qp,
                        'file_hash': r.get('file_hash', ''),
                        'filename': r.get('filename') or os.path.basename(op or qp),
                        'malware_name': r.get('malware_name', '软隔离'),
                        'reason': r.get('reason', '软隔离（原文件被改名就地隔离）'),
                        'is_archive_internal': False,
                        'quarantine_time': (r.get('registered_at')
                                            or datetime.now().isoformat()),
                        'status': 'quarantined',
                        'is_soft_quarantine': True,
                    })
                    present.add(op_key)
                    changed = True
            if changed:
                self._save_soft_registry(kept)
            return changed
        except Exception as e:
            logger.debug(f'软隔离登记表对账失败: {e}')
            return False

    def _dedupe_items(self, items: List[Dict]) -> List[Dict]:
        """按去重键折叠条目：同一对象只保留一条（最新时间 + 累计次数 + 合并来源）。

        读侧兜底：历史 quarantine.json 里可能已存在重复条目（旧版本写入），
        这里统一折叠，保证 UI/查询接口**无重复**；不修改磁盘数据（只影响返回）。
        """
        out: Dict[str, Dict] = {}
        order: List[str] = []
        for it in items or []:
            try:
                k = self._dedupe_key(it)
            except Exception:
                k = ''
            if not k:
                order.append(id(it).__str__())
                out[order[-1]] = it
                continue
            prev = out.get(k)
            if prev is None:
                out[k] = dict(it)
                order.append(k)
                continue
            # 合并：保留最新 quarantine_time，累计 count，合并来源路径
            try:
                if str(it.get('quarantine_time', '')) > str(prev.get('quarantine_time', '')):
                    prev['quarantine_time'] = it.get('quarantine_time')
                prev['quarantine_count'] = int(prev.get('quarantine_count', 1) or 1) + \
                    int(it.get('quarantine_count', 1) or 1)
                ops = prev.setdefault('orig_paths', [])
                for p in (it.get('orig_paths') or [it.get('original_path')]):
                    if p and p not in ops:
                        ops.append(p)
            except Exception:
                pass
        return [out[k] for k in order]

    def get_quarantine_list(self) -> List[Dict]:
        """获取隔离区活跃文件列表（仅 status=='quarantined' 的项；**按去重键折叠，无重复**）"""
        metadata = self._load_metadata()
        try:
            if self._reconcile_soft_registry(metadata):
                self._save_metadata(metadata)
        except Exception:
            pass
        actives = [item for item in metadata.get('items', [])
                   if item.get('status') == 'quarantined']
        return self._dedupe_items(actives)

    def get_all_items(self) -> List[Dict]:
        """获取所有隔离区记录（包括已恢复/已删除的历史项；同样按去重键折叠）"""
        metadata = self._load_metadata()
        # 并入软隔离登记表：保证软隔离文件在隔离区列表可见且可恢复
        try:
            if self._reconcile_soft_registry(metadata):
                self._save_metadata(metadata)
        except Exception:
            pass
        return self._dedupe_items(metadata.get('items', []))

    def list_items(self) -> List[Dict]:
        """获取隔离区活跃文件列表（UI兼容方法，仅活跃隔离项）"""
        return self.get_quarantine_list()

    def restore_files_batch(self, quarantine_ids: List[int]) -> Dict:
        """批量恢复隔离文件（分段加锁 + 并行 I/O，避免长时间持锁卡死 UI）

        三阶段执行：
        阶段1（持锁，快速）：加载元数据，筛选需处理的 item，快照为待处理列表
        阶段2（释放锁，并行）：批量执行目录检查/创建、解密恢复、删除加密副本等 I/O
        阶段3（重新持锁，快速）：合并每个 item 的状态变更，统一保存元数据

        Args:
            quarantine_ids: 隔离记录索引列表

        Returns:
            {'success': int, 'failed': int, 'total': int, 'errors': List[str]}
        """
        if not quarantine_ids:
            return {'success': 0, 'failed': 0, 'total': 0, 'errors': []}

        # ============ 阶段1：持锁加载元数据 + 构建待处理快照 ============
        pending: List[Dict] = []  # 每项: {'id': int, 'item': Dict, 'orig_quarantine_path': str}
        id_set = set(quarantine_ids)

        with self._meta_lock:
            metadata = self._load_metadata()
            items = metadata.get('items', [])
            for qid in quarantine_ids:
                if qid < 0 or qid >= len(items):
                    continue
                item = items[qid]
                if item.get('status') != 'quarantined':
                    continue  # 已恢复/已删除的跳过
                qpath = item.get('quarantine_path', '')
                pending.append({'id': qid, 'item_snapshot': dict(item), 'qpath': qpath})

        # ============ 阶段2：释放锁，并行执行 I/O ============
        # 结果映射: {qid: {'ok': bool, 'final_qpath': str, 'final_orig': str, 'error': str}}
        io_results: Dict[int, Dict] = {}
        lock_for_io = threading.Lock()

        def _do_one(p: Dict):
            qid = p['id']
            snap = p['item_snapshot']
            qpath = p['qpath']
            orig_path = snap.get('original_path', '')
            filename = snap.get('filename', 'unknown')

            # --- 重新定位隔离文件路径（如移动目录后找不到） ---
            if not os.path.exists(qpath):
                bname = os.path.basename(qpath)
                candidate = os.path.join(self.quarantine_dir, bname)
                if os.path.exists(candidate):
                    qpath = candidate
                else:
                    file_hash = snap.get('file_hash', '') or ''
                    if len(file_hash) >= 16:
                        try:
                            prefix = file_hash[:16]
                            for f in os.listdir(self.quarantine_dir):
                                if f.startswith(prefix):
                                    candidate = os.path.join(self.quarantine_dir, f)
                                    if os.path.exists(candidate):
                                        qpath = candidate
                                        break
                        except Exception:
                            pass

            # 找不到隔离文件：视为已恢复（不失败）
            if not os.path.exists(qpath):
                with lock_for_io:
                    io_results[qid] = {'ok': True, 'missing_file': True}
                return

            if not orig_path:
                with lock_for_io:
                    io_results[qid] = {'ok': False, 'error': '缺少原始路径'}
                return

            # --- 检查/选择恢复目标目录 ---
            target_dir = os.path.dirname(orig_path)
            target_path = orig_path
            dir_writable = False
            try:
                if os.path.exists(target_dir):
                    tf = os.path.join(target_dir, '.psls_write_test')
                    with open(tf, 'w') as f:
                        f.write('t')
                    os.remove(tf)
                    dir_writable = True
                else:
                    dir_writable = True
            except Exception:
                dir_writable = False

            if not dir_writable:
                target_path = os.path.join(
                    os.path.expanduser('~'), 'Documents', 'Quarantine_Restored', filename
                )
                target_dir = os.path.dirname(target_path)

            if not os.path.exists(target_dir):
                try:
                    os.makedirs(target_dir, exist_ok=True)
                except Exception:
                    with lock_for_io:
                        io_results[qid] = {'ok': False, 'error': '无法创建恢复目录'}
                    return

            # ---- 原地软隔离特判：隔离文件与原文件为同一路径（软隔离降级），
            # 恢复即解除 ACL + 清隐藏属性，无需也无法移动/解密（同路径 copy2 报 same file）----
            try:
                _qnorm = os.path.normcase(os.path.normpath(os.path.abspath(qpath)))
                _onorm = os.path.normcase(os.path.normpath(os.path.abspath(orig_path)))
                _anorm = os.path.normcase(os.path.normpath(os.path.abspath(snap.get('archive_path', '') or '')))
                if _qnorm == _onorm or (_anorm and _qnorm == _anorm):
                    self._fix_file_permissions(qpath)
                    if sys.platform == 'win32':
                        try:
                            import ctypes
                            ctypes.windll.kernel32.SetFileAttributesW(qpath, 0x00)
                        except Exception:
                            pass
                    # 改名型软隔离（<原文件>.PSLS_QUARANTINED）必须改回原名，否则
                    # 被隔离程序仍无法运行（只解 ACL 不改名 = 没真正恢复）
                    try:
                        if (_qnorm != _onorm
                                and qpath.endswith(SOFT_QUARANTINE_SUFFIX)
                                and orig_path):
                            _rd = os.path.dirname(orig_path)
                            if _rd and not os.path.isdir(_rd):
                                os.makedirs(_rd, exist_ok=True)
                            if (os.path.exists(orig_path)
                                    and os.path.normcase(os.path.abspath(orig_path)) != _qnorm):
                                os.remove(orig_path)
                            os.replace(qpath, orig_path)
                            logger.info(f'批量恢复：软隔离文件已改回原名 {orig_path}')
                    except Exception as _bren_err:
                        logger.warning(
                            f'批量恢复：软隔离改名回原失败（保持原名）: {_bren_err}')
                    self._unregister_soft_quarantine(orig_path)
                    self._add_exemption(orig_path)
                    with lock_for_io:
                        io_results[qid] = {'ok': True, 'target_path': orig_path,
                                           'archive_path': snap.get('archive_path', '')}
                    return
            except Exception as _ip_err:
                logger.warning(f'批量恢复原地软隔离特判失败(继续常规恢复) {qpath}: {_ip_err}')

            # --- 解密 + 删除加密副本 ---
            ok = self._decrypt_file(qpath, target_path)
            if not ok:
                # 解密失败：降级为移动/复制（与单文件 restore_file 一致），减少概率性失败
                try:
                    # 先修复权限再尝试移动
                    self._fix_file_permissions(qpath)
                    shutil.move(qpath, target_path)
                    ok = True
                except Exception:
                    try:
                        shutil.copy2(qpath, target_path)
                        try:
                            os.remove(qpath)
                        except Exception:
                            pass
                        ok = True
                    except Exception as copy_err:
                        logger.warning(f'批量恢复复制降级失败 {qpath}: {copy_err}')
                        ok = False
            if ok:
                try:
                    os.remove(qpath)
                except Exception:
                    pass
                archive_path = snap.get('archive_path', '')
                # 解密落盘后立即加入豁免集合（set.add 为 GIL 原子操作，并行线程安全）。
                # 关键：避免实时监控在阶段3统一加豁免之前扫描到已恢复文件并二次隔离，
                # 这是批量恢复"概率失败"的主要根因。
                if target_path:
                    self._add_exemption(target_path)
                with lock_for_io:
                    io_results[qid] = {
                        'ok': True,
                        'target_path': target_path,
                        'archive_path': archive_path,
                    }
            else:
                with lock_for_io:
                    io_results[qid] = {'ok': False, 'error': '解密恢复失败'}

        # 并行执行（最多 4 个恢复线程，避免占用过多 IO）
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            max_workers = min(4, max(1, len(pending)))
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = [pool.submit(_do_one, p) for p in pending]
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception:
                        pass
        except Exception:
            # 并行不可用时回退到串行
            for p in pending:
                try:
                    _do_one(p)
                except Exception:
                    pass

        # ============ 阶段3：重新持锁，合并结果并保存 ============
        success_count = 0
        failed_count = 0
        processed_ids: set = set()
        errors_out: List[str] = []

        with self._meta_lock:
            metadata2 = self._load_metadata()
            items2 = metadata2.get('items', [])
            now = datetime.now().isoformat()

            for qid in quarantine_ids:
                if qid in processed_ids:
                    continue
                processed_ids.add(qid)

                if qid < 0 or qid >= len(items2):
                    failed_count += 1
                    errors_out.append(f'#{qid} 无效的隔离记录ID')
                    continue

                item2 = items2[qid]
                if item2.get('status') != 'quarantined':
                    continue  # 已被其他线程处理过（正常情况）

                res = io_results.get(qid)
                if res is None:
                    # 没被处理（无效ID等）
                    failed_count += 1
                    errors_out.append(f'#{qid} 未处理')
                    continue

                if res.get('missing_file'):
                    item2['status'] = 'restored'
                    item2['restore_time'] = now
                    item2['restore_note'] = 'file_missing'
                    orig_path = item2.get('archive_path', item2.get('original_path', ''))
                    if orig_path:
                        self._add_exemption(orig_path)
                    # file_missing 情况无 target_path，原 original_path 也需加入（可能已被重定向）
                    orig_restore = item2.get('original_path', '')
                    if orig_restore and orig_restore != orig_path:
                        self._add_exemption(orig_restore)
                    success_count += 1
                    continue

                if not res.get('ok'):
                    failed_count += 1
                    errors_out.append(f'#{qid} {res.get("error", "未知错误")}')
                    continue

                # 恢复成功
                item2['status'] = 'restored'
                item2['restore_time'] = now
                # 豁免路径必须使用实际复原目标路径（target_path），
                # 因为原目录不可写时文件会被重定向到 Documents\Quarantine_Restored，
                # 此时 archive_path/original_path 与实际落盘路径不一致，会导致实时防护再次隔离
                target_path = res.get('target_path', '')
                archive_path = res.get('archive_path', '') or item2.get('archive_path', '')
                orig_restore = item2.get('original_path', '')
                if target_path:
                    self._add_exemption(target_path)
                # 同时加入元数据中的原始路径，覆盖原目录可写的情况
                if archive_path and archive_path != target_path:
                    self._add_exemption(archive_path)
                elif orig_restore and orig_restore != target_path:
                    self._add_exemption(orig_restore)
                success_count += 1

            self._save_metadata_unlocked(metadata2)

        return {
            'success': success_count,
            'failed': failed_count,
            'total': len(quarantine_ids),
            'errors': errors_out,
        }

    def delete_files_batch(self, quarantine_ids: List[int]) -> Dict:
        """批量删除隔离文件（分段加锁 + 并行 I/O，跳过加密副本的预处理）

        三阶段执行，避免长时间持锁卡死 UI：
        阶段1（持锁，快速）：加载元数据，构建待删除快照
        阶段2（释放锁，并行）：执行文件删除（加密副本跳过 _prep_for_remove，直接 os.remove）
        阶段3（重新持锁，快速）：合并结果，保存元数据

        Args:
            quarantine_ids: 隔离记录索引列表

        Returns:
            {'success': int, 'failed': int, 'total': int, 'errors': List[str]}
        """
        if not quarantine_ids:
            return {'success': 0, 'failed': 0, 'total': 0, 'errors': []}

        # ============ 阶段1：持锁加载 + 构建快照 ============
        pending_delete: List[Dict] = []

        with self._meta_lock:
            metadata = self._load_metadata()
            items = metadata.get('items', [])
            for qid in quarantine_ids:
                if qid < 0 or qid >= len(items):
                    continue
                item = items[qid]
                if item.get('status') == 'deleted':
                    continue
                qpath = item.get('quarantine_path', '')
                pending_delete.append({'id': qid, 'qpath': qpath})

        # ============ 阶段2：释放锁，并行删除 ============
        delete_results: Dict[int, bool] = {}  # qid -> 是否删除成功（文件不存在也视为成功）
        lock_del = threading.Lock()

        def _del_one(p: Dict):
            qid = p['id']
            qpath = p['qpath']
            if not os.path.exists(qpath):
                with lock_del:
                    delete_results[qid] = True
                return

            # 关键优化：加密隔离副本文件位于隔离区目录内，不存在进程持有、
            # 也不会被误加系统 ACL；完全不需要 _prep_for_remove（4个 subprocess 调用）
            # 直接 os.remove 即可，90% 情况下都能成功
            deleted = False
            try:
                os.remove(qpath)
                deleted = True
            except Exception:
                deleted = False

            # 若 os.remove 失败（罕见：真正被进程锁定或权限问题），才走兜底
            if not deleted and os.path.exists(qpath):
                try:
                    self._prep_for_remove(qpath)
                except Exception:
                    pass
                try:
                    os.remove(qpath)
                    deleted = not os.path.exists(qpath)
                except Exception:
                    pass

            if not deleted and os.path.exists(qpath):
                try:
                    import tempfile
                    tmp_dir = tempfile.gettempdir()
                    tmp_path = os.path.join(tmp_dir, os.path.basename(qpath) + '.psls_del')
                    shutil.move(qpath, tmp_path)
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
                    deleted = not os.path.exists(qpath)
                except Exception:
                    pass

            if not deleted and os.path.exists(qpath) and sys.platform == 'win32':
                try:
                    import subprocess
                    subprocess.run(
                        ['cmd', '/c', 'del', '/F', '/Q', qpath],
                        capture_output=True, timeout=10, creationflags=_HIDDEN_CREATIONFLAGS
                    )
                    deleted = not os.path.exists(qpath)
                except Exception:
                    pass

            with lock_del:
                delete_results[qid] = deleted or (not os.path.exists(qpath))

        # 并行删除（最多 8 个线程，删除是 IO+少量 subprocess，并发收益大）
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            max_workers = min(8, max(1, len(pending_delete)))
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = [pool.submit(_del_one, p) for p in pending_delete]
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception:
                        pass
        except Exception:
            for p in pending_delete:
                try:
                    _del_one(p)
                except Exception:
                    pass

        # ============ 阶段3：重新持锁，合并结果 + 保存 ============
        success_count = 0
        failed_count = 0
        processed_ids: set = set()
        errors_out: List[str] = []

        with self._meta_lock:
            metadata2 = self._load_metadata()
            items2 = metadata2.get('items', [])
            now = datetime.now().isoformat()

            for qid in quarantine_ids:
                if qid in processed_ids:
                    continue
                processed_ids.add(qid)

                if qid < 0 or qid >= len(items2):
                    failed_count += 1
                    errors_out.append(f'#{qid} 无效的隔离记录ID')
                    continue

                item2 = items2[qid]
                if item2.get('status') == 'deleted':
                    continue  # 已被删除

                res = delete_results.get(qid)
                if res is None:
                    # 不在 pending_delete 里 → 无效 ID 或当时就已 deleted
                    continue

                if not res:
                    failed_count += 1
                    errors_out.append(f'#{qid} 无法删除文件')
                    continue

                item2['status'] = 'deleted'
                item2['delete_time'] = now
                success_count += 1

            self._save_metadata_unlocked(metadata2)

        return {
            'success': success_count,
            'failed': failed_count,
            'total': len(quarantine_ids),
            'errors': errors_out,
        }

    def _compute_file_hash(self, file_path: str) -> str:
        """计算文件哈希值"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception:
            return ''

    def recover_file_hash(self, item: Dict) -> str:
        """尽力恢复隔离项对应原始文件的完整 SHA-256（64位十六进制）。

        用于历史隔离记录缺失 file_hash 的场景（如早期版本写入的元数据，
        或软隔离降级路径）。隔离库文件名仅保留哈希前16位，无法直接作为白名单哈希，
        因此需要现场恢复完整哈希：

        恢复优先级：
        1. 记录中已有完整 file_hash → 直接返回
        2. 原地软隔离（quarantine_path 与 original_path/archive_path 为同一文件，
           文件未加密未移动）→ 直接对源文件计算哈希
        3. 加密隔离副本（quarantine_path 在隔离目录内）→ 解密到临时文件后计算哈希
        4. 兜底 attempt 直接计算 quarantine_path 文件哈希

        Args:
            item: 隔离元数据记录（dict）

        Returns:
            64位十六进制哈希；无法恢复时返回 ''
        """
        try:
            # 已有完整哈希直接返回
            file_hash = item.get('file_hash', '') or ''
            if len(file_hash) == 64:
                return file_hash.lower()

            qp = item.get('quarantine_path', '') or ''
            if not qp or not os.path.exists(qp):
                logger.warning(f'恢复隔离项哈希失败: quarantine_path 不存在 {qp}')
                return ''

            # 原地软隔离（quarantine_path 即原始文件，未加密未移动）
            op = item.get('original_path', '') or ''
            ap = item.get('archive_path', '') or ''
            qp_norm = os.path.normcase(os.path.normpath(os.path.abspath(qp)))
            op_norm = os.path.normcase(os.path.normpath(os.path.abspath(op))) if op else ''
            ap_norm = os.path.normcase(os.path.normpath(os.path.abspath(ap))) if ap else ''
            if (op_norm and qp_norm == op_norm) or (ap_norm and qp_norm == ap_norm):
                fh = self._compute_file_hash(qp)
                if len(fh) == 64:
                    return fh
                return ''

            # 加密隔离副本：解密到临时文件后计算哈希
            import tempfile
            fd, tmp_path = tempfile.mkstemp(suffix=os.path.splitext(qp)[1] or '.dat')
            os.close(fd)
            try:
                if self._decrypt_file(qp, tmp_path):
                    fh = self._compute_file_hash(tmp_path)
                    if len(fh) == 64:
                        logger.info(f'恢复隔离项哈希成功(解密源文件): {fh[:16]}...')
                        return fh
            except Exception as dec_err:
                logger.warning(f'恢复隔离项哈希: 解密失败 {dec_err}')
            finally:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass

            # 兜底：直接计算 quarantine_path（未加密副本）
            fh = self._compute_file_hash(qp)
            if len(fh) == 64:
                logger.info(f'恢复隔离项哈希成功(直接计算): {fh[:16]}...')
                return fh
            return ''
        except Exception as e:
            logger.warning(f'恢复隔离项哈希异常: {e}')
            return ''

    def get_quarantine_path(self) -> str:
        """获取当前隔离区路径"""
        return self.quarantine_dir

    def set_quarantine_path(self, new_path: str) -> dict:
        """
        设置新的隔离区路径
        
        Args:
            new_path: 新的隔离区路径
            
        Returns:
            {
                'success': bool,
                'old_path': str,
                'new_path': str,
                'migrated': bool,  # 是否迁移了数据
                'error': str       # 错误信息（失败时）
            }
        """
        try:
            old_path = self.quarantine_dir
            new_path = os.path.abspath(new_path)

            if old_path == new_path:
                return {
                    'success': True,
                    'old_path': old_path,
                    'new_path': new_path,
                    'migrated': False,
                    'error': ''
                }

            # 路径有效性预检查：确保目标盘符存在且可访问
            # 避免用户选择不存在的盘符（如已断开的U盘/网络磁盘）导致后续启动失败
            drive_root = os.path.splitdrive(new_path)[0]
            if drive_root and not os.path.exists(drive_root + os.sep):
                return {
                    'success': False,
                    'old_path': old_path,
                    'new_path': new_path,
                    'migrated': False,
                    'error': f'路径不可访问：盘符 {drive_root} 不存在或未就绪'
                }

            # 创建新目录
            if not os.path.exists(new_path):
                os.makedirs(new_path)
            
            # 迁移数据
            migrated = False
            if os.path.exists(old_path) and os.path.isdir(old_path):
                try:
                    # 迁移 quarantine.json
                    old_meta = os.path.join(old_path, 'quarantine.json')
                    new_meta = os.path.join(new_path, 'quarantine.json')
                    if os.path.exists(old_meta):
                        shutil.copy2(old_meta, new_meta)
                    
                    # 迁移隔离文件
                    for item in os.listdir(old_path):
                        if item == 'quarantine.json':
                            continue
                        old_file = os.path.join(old_path, item)
                        new_file = os.path.join(new_path, item)
                        if os.path.isfile(old_file):
                            shutil.copy2(old_file, new_file)
                    
                    migrated = True
                except Exception as e:
                    logger.warning(f'迁移隔离数据失败: {e}')
            
            # 更新实例路径
            self.quarantine_dir = new_path
            self.meta_file = os.path.join(new_path, 'quarantine.json')
            
            # 保存到配置文件
            settings = _load_settings()
            settings['quarantine_path'] = new_path
            _save_settings(settings)
            
            return {
                'success': True,
                'old_path': old_path,
                'new_path': new_path,
                'migrated': migrated,
                'error': ''
            }
            
        except Exception as e:
            logger.error(f'设置隔离区路径失败: {e}')
            return {
                'success': False,
                'old_path': self.quarantine_dir,
                'new_path': new_path,
                'migrated': False,
                'error': str(e)
            }

if __name__ == '__main__':
    # 测试隔离管理器
    quarantine = QuarantineManager()
    
    # 创建测试文件
    test_file = 'test_malware.txt'
    with open(test_file, 'w') as f:
        f.write('This is a test file')
    
    # 测试隔离
    logger.debug("测试隔离文件...")
    quarantine.quarantine_file(test_file, reason='测试隔离', malware_name='Test.Malware')
    
    # 测试获取列表
    logger.debug("\n隔离区列表:")
    for i, item in enumerate(quarantine.get_quarantine_list()):
        logger.debug(f"{i}: {item['filename']} - {item['status']}")
    
    # 测试恢复
    logger.debug("\n测试恢复文件...")
    quarantine.restore_file(0)
    
    # 清理测试文件
    if os.path.exists(test_file):
        os.remove(test_file)
    
    logger.info("测试完成!")
