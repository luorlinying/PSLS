# -*- coding: utf-8 -*-
"""ApiHash 轻量静态证据

从 PE 导入表提取"罕见高危 API"哈希信号，产出 0-100 的导入证据分，供统一置信
评分器使用。设计为 FP-safe：只累计罕见高危 API 命中，不因普遍被引用的系统
DLL(如 kernel32/user32)存在而加分——那是误报主源。

输入复用 pe_analyzer 的 pe_analysis 结果(suspicious_imports / import_count /
system_modify_dll_score)，避免重复解析 PE。也提供 from_file 便捷入口。
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# ========= 罕见高危 API 指纹(API 级, 覆盖注入/持久化/绕过/横向) =========
# value = 权重。分类与 pe_analyzer 的"8 功能类别"保持一致的语义。
_HIGH_RISK_APIS: Dict[str, float] = {
    # 进程注入 / 远程线程
    'createremotethread': 12, 'virtualallocex': 10, 'writeprocessmemory': 10,
    'queueuserapc': 8, 'setthreadcontext': 8, 'getthreadcontext': 4,
    'createprocessinternalw': 6, 'ntcreatesection': 4, 'maphybridsection': 4,
    'mapviewofsection': 4, 'ntmapviewofsection': 5,
    # 持久化 / 自启动
    'regsetvalueex': 8, 'regcreatekeyex': 6, 'regopenkeyex': 4,
    'scheduledworkitem': 6, 'scheraddentry': 6, 'createservice': 8,
    'openservice': 5, 'copynotifywatchresult': 5,
    # 反调试 / 反分析
    'isdebuggerpresent': 5, 'checkremotedebuggerpresent': 5,
    'ntqueryinformationprocess': 4, 'ntsetinformationprocess': 3,
    'getthreadcontext': 3, 'ntdeviceiocontrolfile': 3,
    'getpebaddress': 4, 'ntreadvirtualmemory': 3,
    # 网络 / 外联 (C2)
    'winhttpwinhttpopen': 8, 'winhttpwinhttpconnect': 6, 'winhttpwinhttpsendrequest': 6,
    'internetopen': 6, 'internetopenurl': 6, 'urldownloadtofile': 8,
    'httpopenrequest': 6, 'httpclient': 5,
    # 混淆 / 动态加载 (静态绕过)
    'getprocaddress': 3, 'loadlibrary': 3, 'loadlibraryex': 3,
    'writeprocessmemory': 5, 'virtualprotect': 5, 'ntprotectvirtualmemory': 4,
    'flsalloc': 3, 'lopen': 3,
    # 键盘/屏幕记录 (间谍类)
    'setwindowshookex': 7, 'getasynckeystate': 6, 'getkeystate': 4,
    'bitblt': 4, 'getdc': 3, 'createscreencompatiblebitmap': 3,
    # 权限提升 / 提权
    'opentokentoken': 6, 'openprocesstoken': 5, 'adjusttokenprivileges': 6,
    'lookupprivilegevalue': 5, 'gettokeninformation': 3,
    # 隐藏 / 清痕
    'deletefile': 3, 'movefileex': 3, 'cleareventlog': 6,
}

_CAP_EVIDENCE = 45.0  # 与 threat_scorer 的 _CAP_API 对齐


def _norm(name: str) -> str:
    """去下划线/点号并小写,便于与指纹匹配。"""
    return (name or '').lower().replace('_', '').replace('.', '')


def score_imports(suspicious_imports: Optional[List]) -> float:
    """仅由 suspicious_imports(API 级罕见高危命中)计算证据分。FP-safe。"""
    if not suspicious_imports:
        return 0.0
    score = 0.0
    matched = 0
    seen = set()
    for imp in suspicious_imports:
        if isinstance(imp, dict):
            name = imp.get('name') or imp.get('api') or ''
        else:
            name = str(imp)
        key = _norm(name)
        if not key or key in seen:
            continue
        seen.add(key)
        w = _HIGH_RISK_APIS.get(key, 0.0)
        if w > 0:
            score += w
            matched += 1
    # 罕见高危 API 数量本身也是信号(即便不在白名单,name 未命中但人为可疑导入)
    if matched == 0 and len(seen) >= 3:
        score += min(6.0, len(seen) * 1.5)
    score = min(score, _CAP_EVIDENCE)
    # 极少量(1 个)同源对抗常见于正常安全软件, 给轻微弹上限下限
    if matched <= 1:
        score *= 0.5
    return round(min(score, _CAP_EVIDENCE), 2)


def score_dll_weighted(system_modify_dll_score) -> float:
    """由系统修改类 DLL 加权分贡献少量证据(罕见驱动/权限类)。"""
    s = float(system_modify_dll_score or 0.0)
    # 分值越高越可疑, 但大量普通 app 也导入较低分 DLL, 故上限压低、非线性
    if s < 8:
        return 0.0
    if s >= 30:
        return 12.0
    return round((s - 8) / 22.0 * 12.0, 2)


def compute_api_evidence(pe_analysis: Optional[Dict]) -> float:
    """计算 ApiHash 导入证据分(0-100, 实际封顶 _CAP_EVIDENCE)。"""
    if not isinstance(pe_analysis, dict):
        return 0.0
    imp = score_imports(pe_analysis.get('suspicious_imports'))
    dll = score_dll_weighted(pe_analysis.get('system_modify_dll_score', 0))
    ev = imp + dll
    return round(min(ev, _CAP_EVIDENCE), 2)


def compute_api_evidence_from_file(file_path: str, pe_analyzer=None) -> float:
    """便捷入口: 传入 PeAnalyzer 实例(依赖注入), 解析后计算。"""
    if pe_analyzer is None:
        try:
            from engine.pe_analyzer import PeAnalyzer
            pe_analyzer = PeAnalyzer()
        except Exception:
            return 0.0
    try:
        pe_analysis = pe_analyzer.analyze(file_path)
        return compute_api_evidence(pe_analysis)
    except Exception:
        return 0.0


__all__ = ['compute_api_evidence', 'compute_api_evidence_from_file',
           'score_imports', 'score_dll_weighted', '_HIGH_RISK_APIS']