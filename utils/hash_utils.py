import hashlib
import os
import mmap
import threading
import time

# 哈希结果 LRU 缓存：(path, mtime, size) -> sha256
# 避免实时监控与手动扫描重复计算同一文件哈希
_HASH_CACHE: dict = {}
_HASH_CACHE_LOCK = threading.Lock()
_HASH_CACHE_MAX = 8192  # 最大缓存条目数

# 大文件 mmap 阈值：超过此大小使用 mmap 读取（减少用户态拷贝）
_MMAP_THRESHOLD = 512 * 1024  # 512KB
# 分块读取缓冲区大小（512KB，减少 syscall 次数）
_READ_CHUNK_SIZE = 524288

# 文件读取重试：Windows Defender / 其他杀软实时扫描时会短暂锁定恶意样本文件
# 指数退避：1st fail → 50ms, 2nd → 100ms, 3rd → 200ms, 4th → 400ms, 5th → 800ms
_MAX_OPEN_RETRIES = 5

def open_with_retry(file_path: str, mode: str = 'rb'):
    """
    带重试的文件打开。被杀软实时扫描锁定时自动退避重试。
    PermissionError → 重试；其他 OSError → 直接抛出。

    指数退避：1st fail → 50ms, 2nd → 100ms, 3rd → 200ms, 4th → 400ms, 5th → 800ms
    """
    last_err = None
    for attempt in range(_MAX_OPEN_RETRIES):
        try:
            return open(file_path, mode)
        except PermissionError as e:
            last_err = e
            if attempt < _MAX_OPEN_RETRIES - 1:
                time.sleep(0.05 * (2 ** attempt))
            continue
        except OSError:
            raise
    raise last_err


# 向后兼容别名（旧代码引用 _open_with_retry 仍可用）
_open_with_retry = open_with_retry

def compute_sha256(file_path: str) -> str:
    """
    计算文件的SHA256哈希值（带缓存，大文件使用mmap提升吞吐量）

    Args:
        file_path: 文件路径

    Returns:
        SHA256哈希值字符串，如果计算失败返回空字符串
    """
    try:
        # 缓存命中检查：基于 (path, mtime, size) 判断文件是否变更
        cache_key = None
        file_size = 0
        try:
            stat = os.stat(file_path)
            cache_key = (file_path, stat.st_mtime, stat.st_size)
            file_size = stat.st_size
            with _HASH_CACHE_LOCK:
                cached = _HASH_CACHE.get(cache_key)
                if cached is not None:
                    return cached
        except OSError:
            pass

        sha256_hash = hashlib.sha256()

        if file_size >= _MMAP_THRESHOLD:
            # 大文件：使用 mmap 零拷贝读取，避免用户态缓冲区拷贝
            try:
                with _open_with_retry(file_path, 'rb') as f:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        sha256_hash.update(mm)
                result = sha256_hash.hexdigest()
            except (ValueError, OSError, PermissionError):
                # mmap 失败（空文件/不支持/杀软锁定）时回退到分块读取
                result = _sha256_chunked(file_path)
        else:
            result = _sha256_chunked(file_path)

        # 写入缓存（LRU 简化版：超过上限时清空一半）
        if cache_key is not None:
            with _HASH_CACHE_LOCK:
                if len(_HASH_CACHE) >= _HASH_CACHE_MAX:
                    items = list(_HASH_CACHE.items())
                    _HASH_CACHE.clear()
                    _HASH_CACHE.update(items[len(items)//2:])
                _HASH_CACHE[cache_key] = result
        return result
    except (OSError, Exception) as e:
        return ''

def _sha256_chunked(file_path: str) -> str:
    """分块读取计算SHA256（小文件路径，带重试）"""
    sha256_hash = hashlib.sha256()
    with _open_with_retry(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(_READ_CHUNK_SIZE), b''):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def compute_md5(file_path: str) -> str:
    """
    计算文件的MD5哈希值（带重试）
    
    Args:
        file_path: 文件路径
        
    Returns:
        MD5哈希值字符串，如果计算失败返回空字符串
    """
    try:
        md5_hash = hashlib.md5()
        with _open_with_retry(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    except Exception:
        return ''

def compute_file_hashes(file_path: str) -> dict:
    """
    计算文件的多种哈希值
    
    Args:
        file_path: 文件路径
        
    Returns:
        包含SHA256和MD5哈希值的字典
    """
    return {
        'sha256': compute_sha256(file_path),
        'md5': compute_md5(file_path),
        'file_path': file_path,
        'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
    }

if __name__ == '__main__':
    # 测试哈希计算
    test_file = __file__
    print(f"测试文件: {test_file}")
    sha256 = compute_sha256(test_file)
    md5 = compute_md5(test_file)
    print(f"SHA256: {sha256}")
    print(f"MD5: {md5}")
