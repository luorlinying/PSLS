import os
import sys
import tempfile
import shutil
import hashlib
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# 子进程窗口隐藏标志（Windows 平台阻止弹出黑色 cmd 窗口）
# CREATE_NO_WINDOW = 0x08000000，在非 Windows 平台为 0（安全默认值）
_HIDDEN_CREATIONFLAGS = 0x08000000 if sys.platform == 'win32' else 0

# 常见压缩格式的magic bytes
ARCHIVE_MAGIC = {
    'zip': b'\x50\x4B\x03\x04',
    'zip_encrypted': b'\x50\x4B\x03\x04',  # 加密zip的magic bytes相同
    'rar': b'\x52\x61\x72\x21\x1A\x07',
    '7z': b'\x37\x7A\xBC\xAF\x27\x1C',
    'tar': b'\x75\x73\x74\x61\x72',
    'gz': b'\x1F\x8B\x08',
    'bz2': b'\x42\x5A\x68',
    'xz': b'\xFD\x37\x7A\x58\x5A\x00',
}

# 常见恶意软件归档密码
COMMON_PASSWORDS = [
    '',  # 空密码（先尝试不加密）
    'malware',
    'infected',
    'virus',
    '123456',
    'password',
    '123',
    'qwerty',
    'admin',
    'test',
    'toor',
    'root',
    'infected123',
    'malware123',
    'virus123',
    'pass',
    '1234',
    'abcd',
    'file',
    'data',
    'archive',
]

# 压缩炸弹防护配置
MAX_DECOMPRESSION_RATIO = 100  # 最大解压比（解压后大小/压缩前大小）
MAX_EXTRACTED_SIZE = 1 * 1024 * 1024 * 1024  # 最大解压后总大小（1GB）
MAX_NESTED_DEPTH = 3  # 最大嵌套深度
MAX_FILES_PER_ARCHIVE = 10000  # 每个归档最多处理的文件数

class ArchiveScanner:
    """
    归档扫描器
    支持扫描压缩文件内的内容，具备压缩炸弹防护能力
    """
    
    def __init__(self, max_depth: int = MAX_NESTED_DEPTH):
        self.scan_results: List[Dict] = []
        self._temp_dir = None
        self.max_depth = max_depth
        # 缓存 7z 路径（只查找一次，避免每个文件都扫描注册表/PATH）
        self._seven_zip_path: Optional[str] = None
        self._seven_zip_resolved = False  # 是否已尝试解析过 7z 路径
        # RAR 解压后端策略：首次使用时确定（'rarfile' / '7z' / 'none'）
        # 避免每个 RAR 文件都先尝试 rarfile 失败再回退 7z
        self._rar_backend: Optional[str] = None
    
    # 使用 ZIP 作为容器的应用文件格式，不应当作压缩包解压
    _ZIP_CONTAINER_EXTS = {
        '.apk', '.jar', '.war', '.ear', '.ipa', '.aar',
        '.docx', '.xlsx', '.pptx', '.vsdx',
        '.msix', '.appx', '.xpi', '.crx', '.kdbx',
        '.odt', '.ods', '.odp', '.odg',
    }

    def _detect_archive_type(self, file_path: str) -> Optional[str]:
        """通过magic bytes检测归档类型

        注意：APK/JAR/IPA/DOCX 等文件虽使用 ZIP 容器，但属于应用文件，
        不应作为压缩包解压，通过扩展名排除。
        """
        try:
            # 先检查扩展名：ZIP 容器格式的应用文件不作为压缩包处理
            ext = os.path.splitext(file_path)[1].lower()
            if ext in self._ZIP_CONTAINER_EXTS:
                return None

            with open(file_path, 'rb') as f:
                header = f.read(512)

            for archive_type, magic in ARCHIVE_MAGIC.items():
                if archive_type == 'tar':
                    # tar 的 "ustar" magic 位于 offset 257
                    if len(header) >= 262 and header[257:262] == magic:
                        return archive_type
                elif header.startswith(magic):
                    return archive_type

            return None
        except (OSError, Exception):
            return None
    
    def _is_encrypted(self, file_path: str, archive_type: str) -> bool:
        """检查归档是否加密"""
        try:
            if archive_type == 'zip':
                import zipfile
                with zipfile.ZipFile(file_path, 'r') as zf:
                    for info in zf.infolist():
                        if info.flag_bits & 0x1:
                            return True
                return False
            
            elif archive_type == 'rar':
                backend = self._get_rar_backend()
                if backend == 'rarfile':
                    try:
                        import rarfile
                        with rarfile.RarFile(file_path, 'r') as rf:
                            return rf.needs_password()
                    except Exception as e:
                        # rarfile 异常时回退到 7z 检测
                        return self._is_encrypted_with_7z(file_path)
                elif backend == '7z':
                    # rarfile 不可用，直接用 7z 检测加密状态
                    return self._is_encrypted_with_7z(file_path)
                return False
            
            elif archive_type == '7z':
                try:
                    import py7zr
                    with py7zr.SevenZipFile(file_path, 'r') as szf:
                        return szf.needs_password()
                except ImportError:
                    return False
            
            return False
        except (OSError, Exception):
            return False
    
    def _calculate_decompression_ratio(self, file_path: str, archive_type: str) -> Tuple[bool, float, int]:
        """计算解压比，检查是否为压缩炸弹
        
        Returns:
            (is_safe, ratio, total_uncompressed_size)
        """
        try:
            compressed_size = os.path.getsize(file_path)
            
            if archive_type == 'zip':
                import zipfile
                with zipfile.ZipFile(file_path, 'r') as zf:
                    total_uncompressed = sum(info.file_size for info in zf.infolist())
                    file_count = len(zf.infolist())
            
            elif archive_type == 'rar':
                try:
                    import rarfile
                    with rarfile.RarFile(file_path, 'r') as rf:
                        total_uncompressed = sum(info.uncompressed_size for info in rf.infolist())
                        file_count = len(rf.infolist())
                except ImportError:
                    return False, 0, 0
            
            elif archive_type == '7z':
                try:
                    import py7zr
                    with py7zr.SevenZipFile(file_path, 'r') as szf:
                        total_uncompressed = sum(info.uncompressed for info in szf.list())
                        file_count = len(szf.list())
                except ImportError:
                    return False, 0, 0
            
            elif archive_type == 'tar':
                import tarfile
                with tarfile.open(file_path, 'r:*') as tf:
                    total_uncompressed = sum(info.size for info in tf.getmembers() if info.isfile())
                    file_count = sum(1 for info in tf.getmembers() if info.isfile())
            elif archive_type in ('gz', 'bz2', 'xz'):
                # 可能是 tar.gz/tar.bz2/tar.xz，也可能是单文件压缩
                import tarfile
                try:
                    with tarfile.open(file_path, 'r:*') as tf:
                        total_uncompressed = sum(info.size for info in tf.getmembers() if info.isfile())
                        file_count = sum(1 for info in tf.getmembers() if info.isfile())
                except tarfile.ReadError:
                    # 单文件压缩：解压后大小约为压缩前的 3-10 倍（估算）
                    total_uncompressed = compressed_size * 5
                    file_count = 1
            
            else:
                return False, 0, 0
            
            # 检查文件数量限制
            if file_count > MAX_FILES_PER_ARCHIVE:
                return False, 0, total_uncompressed
            
            # 计算解压比
            if compressed_size > 0:
                ratio = total_uncompressed / compressed_size
            else:
                ratio = float('inf')
            
            # 检查解压比和总大小
            is_safe = (ratio <= MAX_DECOMPRESSION_RATIO) and (total_uncompressed <= MAX_EXTRACTED_SIZE)
            
            return is_safe, ratio, total_uncompressed
            
        except (OSError, Exception):
            return False, 0, 0
    
    def _extract_archive(self, file_path: str, archive_type: str, password: str = None) -> Optional[str]:
        """解压归档到临时目录"""
        try:
            # 创建临时目录
            self._temp_dir = tempfile.mkdtemp(prefix='antivirus_archive_')
            
            if archive_type == 'zip':
                zip_extracted = False
                try:
                    import pyzipper
                    try:
                        with pyzipper.AESZipFile(file_path, 'r') as zf:
                            if password:
                                zf.pwd = password.encode('utf-8')
                            zf.extractall(self._temp_dir)
                        zip_extracted = True
                    except Exception:
                        # pyzipper 处理普通 zip 可能失败，回退到 zipfile
                        import zipfile
                        with zipfile.ZipFile(file_path, 'r') as zf:
                            if password:
                                zf.setpassword(password.encode('utf-8'))
                            zf.extractall(self._temp_dir)
                        zip_extracted = True
                except ImportError:
                    import zipfile
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        if password:
                            zf.setpassword(password.encode('utf-8'))
                        zf.extractall(self._temp_dir)
                    zip_extracted = True
                if not zip_extracted:
                    return None
            
            elif archive_type == 'rar':
                backend = self._get_rar_backend()
                if backend == 'rarfile':
                    try:
                        import rarfile
                        with rarfile.RarFile(file_path, 'r') as rf:
                            if password:
                                rf.setpassword(password)
                            rf.extractall(self._temp_dir)
                    except Exception as e:
                        # rarfile 解压失败，回退到 7z
                        return self._extract_with_7z(file_path, password)
                elif backend == '7z':
                    # rarfile 不可用，直接用 7z 解压
                    return self._extract_with_7z(file_path, password)
                else:
                    return None
            
            elif archive_type == '7z':
                try:
                    import py7zr
                    with py7zr.SevenZipFile(file_path, 'r', password=password) as szf:
                        szf.extractall(self._temp_dir)
                except ImportError:
                    return None
            
            elif archive_type == 'tar':
                import tarfile
                with tarfile.open(file_path, 'r:*') as tf:
                    tf.extractall(self._temp_dir)
            elif archive_type in ('gz', 'bz2', 'xz'):
                # 可能是 tar.gz/tar.bz2/tar.xz，也可能是单文件压缩
                import tarfile
                try:
                    with tarfile.open(file_path, 'r:*') as tf:
                        tf.extractall(self._temp_dir)
                except tarfile.ReadError:
                    # 非 tar 压缩，按单文件解压
                    import shutil
                    if archive_type == 'gz':
                        import gzip
                        out_name = os.path.splitext(os.path.basename(file_path))[0]
                        out_path = os.path.join(self._temp_dir, out_name)
                        with gzip.open(file_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    elif archive_type == 'bz2':
                        import bz2
                        out_name = os.path.splitext(os.path.basename(file_path))[0]
                        out_path = os.path.join(self._temp_dir, out_name)
                        with bz2.open(file_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    elif archive_type == 'xz':
                        import lzma
                        out_name = os.path.splitext(os.path.basename(file_path))[0]
                        out_path = os.path.join(self._temp_dir, out_name)
                        with lzma.open(file_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
            
            else:
                return None
            
            return self._temp_dir
            
        except (OSError, Exception) as e:
            # 清理临时目录
            self._cleanup_temp()
            return None
    
    def _cleanup_temp(self):
        """清理临时目录"""
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                shutil.rmtree(self._temp_dir)
            except (OSError, Exception):
                pass
            self._temp_dir = None
    
    def _extract_with_7z(self, file_path: str, password: str = None) -> Optional[str]:
        """使用7z命令行工具解压归档文件（作为rarfile的备用方案）"""
        import subprocess
        
        # 查找7z可执行文件
        seven_zip_path = self._find_seven_zip()
        if not seven_zip_path:
            print(f"  [错误] 未找到7z工具，请安装7-Zip")
            return None
        
        # 创建临时目录
        if not self._temp_dir:
            self._temp_dir = tempfile.mkdtemp()
        
        try:
            # 构建7z命令
            cmd = [seven_zip_path, 'x', '-o' + self._temp_dir, '-y']
            if password:
                cmd.append(f'-p{password}')
            cmd.append(file_path)
            
            # 执行命令
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, creationflags=_HIDDEN_CREATIONFLAGS)
            
            if result.returncode == 0:
                return self._temp_dir
            else:
                print(f"  [错误] 7z解压失败: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print(f"  [错误] 7z解压超时")
            return None
        except Exception as e:
            print(f"  [错误] 7z解压异常: {e}")
            return None
    
    def _find_seven_zip(self) -> Optional[str]:
        """查找7z可执行文件路径（结果缓存，避免重复扫描注册表/PATH）"""
        import os

        # 已解析过：直接返回缓存结果
        if self._seven_zip_resolved:
            return self._seven_zip_path

        # 1. 从注册表读取安装路径（最可靠）
        try:
            import winreg
            # 检查32位和64位注册表
            for hive in [winreg.HKEY_LOCAL_MACHINE]:
                for subkey in [r'SOFTWARE\7-Zip', r'SOFTWARE\WOW6432Node\7-Zip']:
                    try:
                        with winreg.OpenKey(hive, subkey) as key:
                            path, _ = winreg.QueryValueEx(key, 'Path')
                            seven_zip_path = os.path.join(path, '7z.exe')
                            if os.path.exists(seven_zip_path):
                                self._seven_zip_path = seven_zip_path
                                self._seven_zip_resolved = True
                                print(f"  [信息] 从注册表找到7-Zip: {seven_zip_path}")
                                return seven_zip_path
                    except FileNotFoundError:
                        continue
        except Exception as e:
            print(f"  [警告] 读取注册表失败: {e}")

        # 2. 常见7z安装路径
        common_paths = [
            r'C:\Program Files\7-Zip\7z.exe',
            r'C:\Program Files (x86)\7-Zip\7z.exe',
            r'C:\Program Files\7-Zip\7z',
            r'C:\Program Files (x86)\7-Zip\7z',
            r'E:\7-Zip\7z.exe',
            r'D:\7-Zip\7z.exe',
            r'F:\7-Zip\7z.exe',
        ]

        for path in common_paths:
            if os.path.exists(path):
                self._seven_zip_path = path
                self._seven_zip_resolved = True
                print(f"  [信息] 找到7-Zip: {path}")
                return path

        # 3. 检查PATH环境变量
        for dir_path in os.environ.get('PATH', '').split(os.pathsep):
            seven_zip = os.path.join(dir_path, '7z.exe')
            if os.path.exists(seven_zip):
                self._seven_zip_path = seven_zip
                self._seven_zip_resolved = True
                return seven_zip
            seven_zip = os.path.join(dir_path, '7z')
            if os.path.exists(seven_zip):
                self._seven_zip_path = seven_zip
                self._seven_zip_resolved = True
                return seven_zip

        # 标记为已解析（未找到），避免下次重复查找
        self._seven_zip_resolved = True
        self._seven_zip_path = None
        print(f"  [警告] 未找到7z工具，请安装7-Zip")
        return None

    def _get_rar_backend(self) -> str:
        """确定 RAR 解压后端策略（首次调用时确定并缓存）

        返回值：
        - 'rarfile'：使用 rarfile 库（需要 unrar.exe 可用）
        - '7z'：使用 7z 命令行工具（rarfile 不可用时的回退）
        - 'none'：两者都不可用

        缓存后后续 RAR 文件直接使用已确定的策略，
        不再每次都先尝试 rarfile 失败再回退 7z。
        """
        if self._rar_backend is not None:
            return self._rar_backend

        # 先检查 rarfile 库是否可用且 unrar 工具存在
        try:
            import rarfile
            if rarfile.UNRAR_TOOL:
                self._rar_backend = 'rarfile'
                return self._rar_backend
        except ImportError:
            pass

        # rarfile 不可用，检查 7z
        if self._find_seven_zip():
            self._rar_backend = '7z'
        else:
            self._rar_backend = 'none'
        return self._rar_backend

    def _is_encrypted_with_7z(self, file_path: str) -> bool:
        """使用 7z 命令行工具检测归档是否加密

        通过 `7z l -slt` 输出的 "Encrypted = +" 标志判断。
        用于 rarfile 不可用时检测 RAR 加密状态。超时 5s（原 30s）。
        """
        seven_zip = self._find_seven_zip()
        if not seven_zip:
            return False
        try:
            import subprocess
            result = subprocess.run(
                [seven_zip, 'l', '-slt', '-y', file_path],
                capture_output=True, text=True, timeout=5,
                creationflags=_HIDDEN_CREATIONFLAGS
            )
            output = result.stdout + result.stderr
            return 'Encrypted = +' in output
        except Exception:
            return False
    
    def _safe_path(self, path: str, base_path: str) -> bool:
        """检查路径是否在基础路径范围内（防止路径遍历攻击）"""
        try:
            real_path = os.path.realpath(path)
            real_base = os.path.realpath(base_path)
            return real_path.startswith(real_base)
        except (OSError, Exception):
            return False
    
    def scan_archive(self, file_path: str, malware_hashes: set, heuristic_rules: list, 
                     rule_engine=None, depth: int = 0) -> List[Dict]:
        """
        扫描归档文件
        
        Args:
            file_path: 归档文件路径
            malware_hashes: 恶意软件哈希集合
            heuristic_rules: 启发式规则列表
            rule_engine: 规则引擎实例（可选）
            depth: 当前嵌套深度
            
        Returns:
            扫描结果列表
        """
        results = []
        
        # 检查嵌套深度
        if depth > self.max_depth:
            return results
        
        # 检测归档类型
        archive_type = self._detect_archive_type(file_path)
        if not archive_type:
            return results
        
        # 计算解压比，检查压缩炸弹
        is_safe, ratio, total_size = self._calculate_decompression_ratio(file_path, archive_type)
        if not is_safe:
            results.append({
                'file_path': file_path,
                'status': 'suspicious',
                'reason': f'压缩炸弹检测：解压比 {ratio:.1f}:1，总大小 {total_size/1024/1024:.1f}MB',
                'severity': 'high',
            })
            return results
        
        # 检查是否加密
        is_encrypted = self._is_encrypted(file_path, archive_type)
        
        # 尝试密码（仅尝试前 5 个最常见密码，避免 21 个密码 × 7z子进程 = 严重瓶颈）
        password = None
        extracted_dir = None
        
        if is_encrypted:
            # 仅尝试前 5 个最常见密码（空密码 + 最常用恶意样本密码）
            _QUICK_PASSWORDS = COMMON_PASSWORDS[:5]  # '', 'malware', 'infected', 'virus', '123456'
            for pwd in _QUICK_PASSWORDS:
                extracted_dir = self._extract_archive(file_path, archive_type, pwd)
                if extracted_dir:
                    password = pwd
                    break
            else:
                results.append({
                    'file_path': file_path,
                    'status': 'suspicious',
                    'reason': '密码保护的归档文件，无法破解密码',
                    'severity': 'medium',
                })
                return results
        else:
            extracted_dir = self._extract_archive(file_path, archive_type)
        
        if not extracted_dir:
            return results
        
        try:
            # 递归扫描解压后的文件
            # 注意：对同一内部文件，将哈希/启发式/规则引擎检测结果合并为一条记录，
            # 按严重度优先级（malware > suspicious）取最高级别，避免同一文件产生多条
            # 结果导致后续 scan_engine 重复生成 ScanResult、bridge 重复触发隔离。
            for root, dirs, files in os.walk(extracted_dir):
                for filename in files:
                    extracted_file = os.path.join(root, filename)

                    # 路径遍历保护
                    if not self._safe_path(extracted_file, extracted_dir):
                        continue

                    internal_path = extracted_file.replace(extracted_dir, '', 1).lstrip(os.sep)

                    # ---- 聚合同一内部文件的所有检测结果 ----
                    # 1. 哈希匹配（最高优先级，命中即 malware）
                    file_hash = self._compute_hash(extracted_file)
                    hash_match = bool(file_hash and file_hash in malware_hashes)

                    # 2. 启发式检查（仅基于文件名）
                    heuristic_matches = self._check_heuristics(filename, heuristic_rules)

                    # 3. 规则引擎扫描
                    rule_matches = []
                    if rule_engine:
                        rule_matches = rule_engine.scan_file(extracted_file) or []
                    threat_matches = [m for m in rule_matches
                                      if m.get('severity') in ('high', 'medium', 'low')]

                    # ---- 判定最终状态（malware > suspicious > clean）----
                    final_status = 'clean'
                    severity = 'low'

                    if hash_match:
                        # 哈希匹配：直接判定为 malware
                        final_status = 'malware'
                        severity = 'high'
                    elif threat_matches:
                        # 规则引擎判定（与原逻辑保持一致）
                        high_severity = any(m.get('severity') == 'high' for m in threat_matches)
                        medium_count = sum(1 for m in threat_matches if m.get('severity') == 'medium')
                        # 高严重度 + 至少1个其他威胁规则 = malware
                        # 至少2个中等严重度 = suspicious
                        # 至少3个威胁规则 = suspicious
                        if high_severity and len(threat_matches) >= 2:
                            final_status = 'malware'
                            severity = 'high'
                        elif medium_count >= 2 or len(threat_matches) >= 3:
                            final_status = 'suspicious'
                            severity = 'medium'

                    # 启发式匹配仅在未达 malware 时补充为 suspicious（避免覆盖更高判定）
                    if final_status != 'malware' and heuristic_matches:
                        final_status = 'suspicious'
                        severity = 'medium'

                    # ---- 合并为单条结果（保留所有来源信息）----
                    if final_status != 'clean':
                        result_entry = {
                            'file_path': file_path,
                            'internal_path': internal_path,
                            'status': final_status,
                            'severity': severity,
                        }
                        if hash_match:
                            result_entry['hash'] = file_hash
                            result_entry['hash_match'] = True
                        if heuristic_matches:
                            result_entry['heuristic_matches'] = heuristic_matches
                        if threat_matches:
                            result_entry['rule_matches'] = rule_matches
                        results.append(result_entry)

                    # 检查是否为嵌套归档（独立处理，不与文件本身检测结果合并）
                    nested_type = self._detect_archive_type(extracted_file)
                    if nested_type:
                        nested_results = self.scan_archive(
                            extracted_file, malware_hashes, heuristic_rules, rule_engine, depth + 1
                        )
                        for nr in nested_results:
                            nr['file_path'] = f"{file_path} -> {nr.get('internal_path', '')}"
                            results.append(nr)

            return results
            
        finally:
            # 清理临时目录
            self._cleanup_temp()
    
    def _compute_hash(self, file_path: str) -> str:
        """计算文件SHA256哈希"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except (OSError, Exception):
            return ''
    
    def _check_heuristics(self, filename: str, heuristic_rules: list) -> List[Dict]:
        """检查启发式规则"""
        import re
        
        matches = []
        _, extension = os.path.splitext(filename)
        
        for rule in heuristic_rules:
            try:
                rule_type = rule.get('rule_type', '')
                pattern = rule.get('pattern', '')
                
                if not pattern:
                    continue
                
                regex = re.compile(pattern)
                
                if rule_type == 'filename' and regex.search(filename):
                    matches.append(rule)
                elif rule_type == 'extension' and regex.search(extension):
                    matches.append(rule)
            except (re.error, Exception):
                continue
        
        return matches

if __name__ == '__main__':
    # 测试归档扫描器
    scanner = ArchiveScanner()
    
    # 测试数据
    test_hashes = {
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    }
    
    test_rules = [
        {
            'name': 'Suspicious.FileName',
            'rule_type': 'filename',
            'pattern': r'(?i)(malware|virus|trojan)\.',
            'severity': 'high',
        }
    ]
    
    # 测试扫描（需要创建测试归档文件）
    print("归档扫描器初始化完成")
    print(f"支持的归档类型: {list(ARCHIVE_MAGIC.keys())}")
    print(f"最大解压比: {MAX_DECOMPRESSION_RATIO}:1")
    print(f"最大解压大小: {MAX_EXTRACTED_SIZE/1024/1024:.0f}MB")
    print(f"最大嵌套深度: {MAX_NESTED_DEPTH}")
