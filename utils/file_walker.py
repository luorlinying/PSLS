import os
import stat
from typing import Generator, Set, List

# 默认跳过的目录（系统相关，通常不需要扫描）
DEFAULT_SKIP_DIRS = {
    '$Recycle.Bin',
    'System Volume Information',
    'Windows.old',
    'WinSxS',
    'ProgramData',
    'Program Files',
    'Program Files (x86)',
    'AppData',
    'Application Data',
    'Local Settings',
    'Temp',
    'Temporary Internet Files',
    'cache',
    'Caches',
    '.cache',
    'node_modules',
    '__pycache__',
    '.git',
    '.svn',
    'Thumbs.db',
    '$WINDOWS.~BT',
    '$WINDOWS.~WS',
    'OldWindows',
    'Panther',
}

# 默认关注的文件扩展名（可执行文件、脚本和压缩包）
DEFAULT_TARGET_EXTENSIONS = {
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf',
    '.scr', '.pif', '.hta', '.msi', '.msp', '.com', '.cpl',
    '.jar', '.py', '.php', '.html', '.htm', '.xml', '.json',
    '.lnk', '.inf', '.reg', '.ini', '.cfg',
    # 压缩包（勒索/木马常见投递载体）
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
}

class FileWalker:
    """
    文件遍历工具类
    支持目录剪枝、扩展名过滤、大小过滤等功能
    """
    
    def __init__(self, 
                 skip_dirs: Set[str] = None,
                 target_extensions: Set[str] = None,
                 max_file_size: int = None,  # 字节，None表示不限制
                 min_file_size: int = 0,     # 字节，默认0
                 scan_all: bool = False,    # 是否扫描所有文件（包括隐藏文件和所有扩展名）
                 skip_paths: Set[str] = None):  # 完整路径前缀排除集合（小写）
        
        self.skip_dirs = skip_dirs if skip_dirs else DEFAULT_SKIP_DIRS
        self.target_extensions = target_extensions if target_extensions else DEFAULT_TARGET_EXTENSIONS
        self.max_file_size = max_file_size
        self.min_file_size = min_file_size
        self.scan_all = scan_all
        self.skip_paths = skip_paths or set()
        self.scanned_count = 0
        self.skipped_count = 0
    
    def should_skip_dir(self, dir_name: str) -> bool:
        """判断是否应跳过该目录"""
        # 跳过以点开头的隐藏目录
        if dir_name.startswith('.'):
            return True
        # 跳过系统目录
        if dir_name in self.skip_dirs:
            return True
        return False
    
    def _is_symlink(self, path: str) -> bool:
        """检查是否为符号链接"""
        try:
            # Windows上检查符号链接
            return os.path.islink(path)
        except (OSError, Exception):
            return False
    
    def should_scan_file(self, file_path: str) -> bool:
        """判断是否应扫描该文件（保留用于兼容旧调用方）"""
        try:
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size

            if self.max_file_size and file_size > self.max_file_size:
                return False
            if file_size < self.min_file_size:
                return False

            if self.scan_all:
                return True

            _, ext = os.path.splitext(file_path)
            ext = ext.lower()

            if self.target_extensions and ext not in self.target_extensions:
                return False

            if file_stat.st_file_attributes & (stat.FILE_ATTRIBUTE_SYSTEM | stat.FILE_ATTRIBUTE_HIDDEN):
                return False

            return True
        except (OSError, Exception):
            return False

    def _should_scan_entry(self, entry, name: str, is_dir: bool) -> bool:
        """基于 os.scandir 的 DirEntry 判断是否应扫描（避免额外 os.stat 调用）

        os.scandir 在 Windows 上通过一次 FindFirstFile/FindNextFile 即可获取
        文件名、属性、大小等信息，DirEntry.stat() 不需要额外系统调用即可返回
        缓存的文件信息。相比 os.walk + os.stat 每个 file 调用一次 stat 的方式，
        可减少 50%-80% 的系统调用次数。
        """
        try:
            # 跳过符号链接（防止链接环）
            if entry.is_symlink():
                return False

            # 检查完整路径是否在排除列表中
            if self.skip_paths:
                try:
                    entry_path_lower = entry.path.lower()
                    if any(entry_path_lower.startswith(p) for p in self.skip_paths):
                        return False
                except Exception:
                    pass

            if is_dir:
                # 目录：仅判断是否应跳过（隐藏/系统目录）
                if name.startswith('.'):
                    return False
                if name in self.skip_dirs:
                    return False
                return True

            # 文件：用 DirEntry 缓存的 stat 信息
            try:
                file_stat = entry.stat(follow_symlinks=False)
            except (OSError, AttributeError):
                # DirEntry.stat 失败时回退到 os.stat
                try:
                    file_stat = os.stat(entry.path)
                except (OSError, Exception):
                    return False

            file_size = file_stat.st_size

            # 文件大小限制
            if self.max_file_size and file_size > self.max_file_size:
                return False
            if file_size < self.min_file_size:
                return False

            if self.scan_all:
                return True

            _, ext = os.path.splitext(name)
            ext = ext.lower()

            if self.target_extensions and ext not in self.target_extensions:
                return False

            # 检查文件属性（跳过系统文件和隐藏文件）
            try:
                attrs = file_stat.st_file_attributes
                if attrs & (stat.FILE_ATTRIBUTE_SYSTEM | stat.FILE_ATTRIBUTE_HIDDEN):
                    return False
            except (AttributeError, OSError):
                pass

            return True
        except (OSError, Exception):
            return False

    def walk(self, root_path: str) -> Generator[str, None, None]:
        """遍历目录并生成待扫描文件路径（使用 os.scandir 递归实现，性能更优）

        os.scandir 相比 os.walk 的优势：
        - Windows 上一次 FindFirstFile/FindNextFile 即返回文件名+属性+大小
        - DirEntry.stat() 使用缓存数据，不需要额外系统调用
        - os.walk 需要对每个文件再调用 os.stat 获取大小/属性
        """
        if not os.path.isdir(root_path):
            raise ValueError(f"路径不是有效的目录: {root_path}")

        root_path = os.path.abspath(root_path)

        # 使用栈进行深度优先遍历，避免递归深度限制
        stack = [root_path]

        while stack:
            current_dir = stack.pop()
            try:
                with os.scandir(current_dir) as it:
                    for entry in it:
                        name = entry.name
                        try:
                            is_dir = entry.is_dir(follow_symlinks=False)
                        except (OSError, Exception):
                            is_dir = False

                        if is_dir:
                            # 目录：判断是否应遍历
                            if self._should_scan_entry(entry, name, is_dir=True):
                                stack.append(entry.path)
                            else:
                                self.skipped_count += 1
                        else:
                            # 文件：判断是否应扫描
                            if self._should_scan_entry(entry, name, is_dir=False):
                                self.scanned_count += 1
                                yield entry.path
                            else:
                                self.skipped_count += 1
            except (OSError, PermissionError):
                # 权限不足或目录不可访问，跳过
                continue
            except Exception:
                continue
    
    def get_stats(self) -> dict:
        """获取扫描统计信息"""
        return {
            'scanned_files': self.scanned_count,
            'skipped_files': self.skipped_count,
        }

def get_system_drives() -> List[str]:
    """获取系统所有驱动器"""
    drives = []
    for drive in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        drive_path = f'{drive}:/'
        if os.path.exists(drive_path):
            drives.append(drive_path)
    return drives

if __name__ == '__main__':
    # 测试文件遍历
    walker = FileWalker()
    
    # 扫描当前目录
    print("开始扫描测试...")
    for filepath in walker.walk('.'):
        print(f"  {filepath}")
    
    stats = walker.get_stats()
    print(f"\n扫描统计:")
    print(f"  已扫描文件: {stats['scanned_files']}")
    print(f"  跳过文件: {stats['skipped_files']}")
    
    # 测试获取系统驱动器
    drives = get_system_drives()
    print(f"\n系统驱动器: {drives}")
