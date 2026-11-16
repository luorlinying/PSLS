# -*- coding: utf-8 -*-
"""
模糊哈希模块

优先使用 python-ssdeep（fast），不可用时降级到纯 Python 的 CTPH 简化版。
提供两个公开接口：
    fuzzy_file(path)      -> str     对文件计算模糊哈希
    fuzzy_compare(a, b)   -> int[0,100]  两个模糊哈希的相似度（0=完全不同，100=完全相同）
"""

import os
import math
from typing import Optional


# --------------------------------------------------------------------------- #
#  可选依赖：python-ssdeep                                                    #
# --------------------------------------------------------------------------- #
try:
    import ssdeep as _ssdeep
    _HAS_SSDEEP = True
except ImportError:
    _ssdeep = None
    _HAS_SSDEEP = False

HAS_SSDEEP = _HAS_SSDEEP  # 公开只读别名


# --------------------------------------------------------------------------- #
#  纯 Python CTPH 实现（参考 ssdeep 算法，简化版）                             #
# --------------------------------------------------------------------------- #

# 触发阈值选择表（ssdeep 原版的默认块大小）
_BLOCK_SIZES = [
    3,   2016,
    7,   4032,
    13,  8064,
    27,  16128,
    53,  32256,
    105, 64512,
    211, 129024,
    421, 258048,
    903, 516096,
    1819, 1032192,
    3637, 2064384,
    7283, 4128768,
    14567, 8257536,
    29137, 16515072,
    58271, 33030144,
    116537, 66060288,
    233063, 132120576,
]

_BASE64_ALPHABET = (
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    'abcdefghijklmnopqrstuvwxyz'
    '0123456789+/'
)

# Rolling hash 参数（FNV-1a 变种）
_ROLL_WINDOW = 7


def _rolling_hash(data: bytes) -> int:
    """7 字节窗口的 FNV-1a rolling hash。"""
    h = 0x28021FE2
    for b in data[:_ROLL_WINDOW]:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def _piece_hash(chunk: bytes) -> str:
    """对一个触发块做 piece hash（6 字符 base64，取自 FNV-1a 的前 6 字节）。"""
    h = 0x811C9DC5
    for b in chunk:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    # 取低 36 bit，分成 6 个 6-bit
    val = h & 0xFFFFFFFF
    chars = []
    for _ in range(6):
        chars.append(_BASE64_ALPHABET[val & 0x3F])
        val >>= 6
    return ''.join(reversed(chars))


def _pick_block_size(file_size: int) -> int:
    """根据文件大小选最合适的块大小。"""
    for i in range(0, len(_BLOCK_SIZES), 2):
        bs, bound = _BLOCK_SIZES[i], _BLOCK_SIZES[i + 1]
        if file_size <= bound:
            return bs
    return _BLOCK_SIZES[-2]


def _ctph(data: bytes) -> str:
    """纯 Python CTPH 实现，返回 'bs:piece1,piece2' 格式的模糊哈希。"""
    file_size = len(data)
    block_size = _pick_block_size(file_size)

    # 第一轮：用 block_size 触发，收集 piece hash
    chunks_small: list = []
    i = 0
    rolling = 0
    buf = bytearray()
    while i < len(data):
        if i >= _ROLL_WINDOW:
            rolling = ((rolling ^ data[i]) * 0x01000193) & 0xFFFFFFFF
        else:
            rolling = ((rolling ^ data[i]) * 0x01000193) & 0xFFFFFFFF
        buf.append(data[i])
        # 触发条件：rolling hash 最后 log2(bs) 位全为 1，或累计长度到 bs*2
        trigger_mask = (1 << max(1, block_size.bit_length())) - 1
        if (rolling & trigger_mask) == trigger_mask or len(buf) >= block_size * 2:
            if len(buf) >= 3:
                chunks_small.append(_piece_hash(bytes(buf)))
            buf.clear()
        i += 1
    if buf and len(buf) >= 3:
        chunks_small.append(_piece_hash(bytes(buf)))

    # 如果块大小 ≥ 2016 或 chunk 数 ≥ 32，就输出到 small；否则再做一次用 2x block_size 的
    if block_size >= 2016:
        big = ''
    else:
        big_block = block_size * 2
        chunks_big: list = []
        i = 0
        rolling = 0
        buf_big = bytearray()
        while i < len(data):
            rolling = ((rolling ^ data[i]) * 0x01000193) & 0xFFFFFFFF
            buf_big.append(data[i])
            trigger_mask = (1 << max(1, big_block.bit_length())) - 1
            if (rolling & trigger_mask) == trigger_mask or len(buf_big) >= big_block * 2:
                if len(buf_big) >= 3:
                    chunks_big.append(_piece_hash(bytes(buf_big)))
                buf_big.clear()
            i += 1
        if buf_big and len(buf_big) >= 3:
            chunks_big.append(_piece_hash(bytes(buf_big)))
        big = ''.join(chunks_big)

    small = ''.join(chunks_small)
    return f'{block_size}:{small}:{big}'


# --------------------------------------------------------------------------- #
#  相似度计算：基于 piece hash 的局部对齐 + 编辑距离                          #
# --------------------------------------------------------------------------- #

def _parse_fuzzy(h: str):
    """解析 'bs:small:big' 格式。"""
    parts = h.split(':')
    if len(parts) != 3:
        return None, None, None
    try:
        bs = int(parts[0])
    except ValueError:
        return None, None, None
    return bs, parts[1], parts[2]


def _longest_common_substring(a: str, b: str) -> int:
    m, n = len(a), len(b)
    if m == 0 or n == 0:
        return 0
    prev = [0] * (n + 1)
    best = 0
    for i in range(1, m + 1):
        curr = [0] * (n + 1)
        ai = a[i - 1]
        for j in range(1, n + 1):
            if ai == b[j - 1]:
                curr[j] = prev[j - 1] + 1
                if curr[j] > best:
                    best = curr[j]
            else:
                curr[j] = max(prev[j], curr[j - 1])
        prev = curr
    return best


def _edit_distance(a: str, b: str, max_d: int = 128) -> int:
    """限制最大距离的编辑距离（超过 max_d 直接返回 max_d+1）。"""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > max_d:
        return max_d + 1
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        curr = [i] + [0] * lb
        ai = a[i - 1]
        min_curr = curr[0]
        for j in range(1, lb + 1):
            cost = 0 if ai == b[j - 1] else 1
            curr[j] = min(
                prev[j] + 1,        # 删除
                curr[j - 1] + 1,    # 插入
                prev[j - 1] + cost, # 替换
            )
            if curr[j] < min_curr:
                min_curr = curr[j]
        if min_curr > max_d:
            return max_d + 1
        prev = curr
    return prev[lb]


def _piecewise_compare(a: str, b: str) -> float:
    """比较两段 piece hash 字符串，返回 [0,1] 相似度。"""
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return 0.0
    # LCS + 编辑距离 混合打分
    lcs_len = _longest_common_substring(a, b)
    ed = _edit_distance(a, b, max_d=max(la, lb))
    denom = max(la, lb)
    # 综合：LCS 占 70%，编辑距离占 30%
    lcs_score = lcs_len / denom
    ed_score = max(0.0, 1.0 - ed / (denom * 0.8 + 1))
    return 0.7 * lcs_score + 0.3 * ed_score


def _fuzzy_compare_py(a: str, b: str) -> int:
    """纯 Python 版相似度比较，返回 0-100。"""
    a_bs, a_small, a_big = _parse_fuzzy(a)
    b_bs, b_small, b_big = _parse_fuzzy(b)
    if a_bs is None or b_bs is None:
        return 0

    if a == b:
        return 100

    # 块大小差距太大 → 0 相似度
    if a_bs != b_bs and a_bs * 2 != b_bs and b_bs * 2 != a_bs:
        return 0

    # 选块大小较小的那个的 big/small 分别比较
    candidates = []
    if a_bs == b_bs:
        candidates.append(_piecewise_compare(a_small, b_small))
        candidates.append(_piecewise_compare(a_big, b_big))
    elif a_bs < b_bs:
        candidates.append(_piecewise_compare(a_big, b_small))
    else:
        candidates.append(_piecewise_compare(a_small, b_big))

    if not candidates:
        return 0
    raw = max(candidates)
    return int(round(raw * 100))


# --------------------------------------------------------------------------- #
#  对外公开接口                                                               #
# --------------------------------------------------------------------------- #

def fuzzy_file(path: str) -> Optional[str]:
    """对文件计算模糊哈希。"""
    try:
        if _HAS_SSDEEP:
            return _ssdeep.hash_from_file(path)
        with open(path, 'rb') as f:
            data = f.read()
        return _ctph(data)
    except Exception:
        return None


def fuzzy_bytes(data: bytes) -> Optional[str]:
    """对内存 bytes 计算模糊哈希。"""
    try:
        if _HAS_SSDEEP:
            return _ssdeep.hash(data)
        return _ctph(data)
    except Exception:
        return None


def fuzzy_compare(a: str, b: str) -> int:
    """比较两个模糊哈希，返回 0-100。"""
    if not a or not b:
        return 0
    try:
        if _HAS_SSDEEP:
            return _ssdeep.compare(a, b)
        return _fuzzy_compare_py(a, b)
    except Exception:
        return 0


def fuzzy_available() -> bool:
    """模糊哈希是否可用（任何后端都行）。"""
    return True


if __name__ == '__main__':
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    test_path = 'quarantine/fce3cc7f2d9a94bd_20260728_133326.js'
    if os.path.exists(test_path):
        h1 = fuzzy_file(test_path)
        print(f'sample hash: {h1}')
        # 自己和自己比较
        print(f'self compare: {fuzzy_compare(h1, h1)}')
        # 和一个简单字符串比较
        print(f'vs random: {fuzzy_compare(h1, "3:AAAA:BBBB")}')
        print(f'ssdeep available: {_HAS_SSDEEP}')
    else:
        # 纯 Python 自测
        s1 = b'Hello World ' * 1000
        s2 = b'Hello World! ' * 1000  # 只差一个字符
        h1 = fuzzy_bytes(s1)
        h2 = fuzzy_bytes(s2)
        print(f'h1: {h1}')
        print(f'h2: {h2}')
        print(f'self-compare: {fuzzy_compare(h1, h1)}')
        print(f'similar-compare: {fuzzy_compare(h1, h2)}')
