# -*- coding: utf-8 -*-
"""study-engine 指纹学习引擎

运行期增量维护"文件指纹 -> 良/恶"记录库，为统一置信评分器提供 hard-negative/正样本
佐证。指纹由以下维度构成：
  sha256        : 精确匹配首选
  size          : 文件大小(字节)
  ext           : 扩展名(小写, 含点)
  api_hist      : ApiHash 桶直方图(可选, 用于查杀/变种近似匹配)

记录带计数与标签(benign/malicious)。匹配时:
  1) sha256 精确命中 -> 直接返回该记录标签与支持度
  2) 无 hash 时用 size+ext+api_hist 近似匹配, 若无 api_hist 则仅 size+ext(弱)

置信度 = 标签计数 / 总计数(双方都有记录), 并受总出现次数平滑。仅当支持样本数
>= MIN_SUPPORT 才对外宣告, 否则返回 None(不给判定), 避免单例误判。

纯内存/JSON, 无外部 RPC, 便于单测与嵌入。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Dict, List, Optional


# 最少支持样本数，低于此不宣告结论
MIN_SUPPORT = 1
# 判定需达到的最小占比(对同 key 双方计数)
MIN_DOMINANCE = 0.60
# 距上次出现超过该秒数视为"冷却"，明显降权
STALE_SECONDS = 90 * 24 * 3600
# 记录库硬上限(超出后清理最旧的 benign 记录)
MAX_RECORDS = 20000
# 无 hash 近似匹配的最小 api_hist 重叠比例
_API_HIST_MIN_OVERLAP = 0.5
# 自动落盘节流: 距上次保存超此秒数才真正写盘(避免高频 JSON IO)
_AUTOSAVE_INTERVAL = 30

_EMPTY_HIST = ()


def _sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _default_store_path() -> str:
    """项目根/data/study_engine.json；打包模式回退 APPDATA/PSLS。"""
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cand = os.path.join(root, 'data', 'study_engine.json')
        os.makedirs(os.path.dirname(cand), exist_ok=True)
        if os.access(os.path.dirname(cand), os.W_OK):
            return cand
    except Exception:
        pass
    try:
        base = os.path.join(os.environ.get('APPDATA', ''), 'PSLS')
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, 'study_engine.json')
    except Exception:
        return 'study_engine.json'


class StudyEngine:
    def __init__(self, store_path: Optional[str] = None, store: Optional[Dict] = None):
        self._store_path = store_path or _default_store_path()
        self._last_save = 0.0
        self._lock = threading.RLock()
        # store: {key: {label:{'count':int,'last':ts}, ...同一key双label}, 'meta':...}
        self._store: Dict = store if store is not None else self._load()
        self._load_store()

    # ---------- 持久化 ----------
    def _load(self) -> Dict:
        try:
            if os.path.isfile(self._store_path):
                with open(self._store_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
        except Exception:
            pass
        return {}

    def _load_store(self):
        self._records = self._store.get('records', {})
        if not isinstance(self._records, dict):
            self._records = {}
        self._store['records'] = self._records
        self._store.setdefault('meta', {'version': 1, 'created': int(time.time())})

    def save(self):
        with self._lock:
            try:
                with open(self._store_path, 'w', encoding='utf-8') as f:
                    json.dump(self._store, f, ensure_ascii=False, separators=(',', ':'))
            except Exception:
                pass

    # ---------- 指纹 key ----------
    @staticmethod
    def _key(sha256: str, size: int, ext: str) -> str:
        return f"{sha256 or '?'}:{size}:{ext.lower()}"

    # ---------- 增: 添加记录 ----------
    def add_record(self, path: Optional[str] = None, label: str = 'benign',
                   meta: Optional[Dict] = None) -> Optional[str]:
        """添加一条指纹记录。label in {'benign','malicious'}。返回 key 或 None。

        meta 可提供 sha256/size/ext/api_hist(优先于从 path 现算)。
        """
        if label not in ('benign', 'malicious'):
            return None
        meta = meta or {}
        sha = meta.get('sha256') or (_sha256_file(path) if path else None)
        size = int(meta.get('size') or (os.path.getsize(path) if path else 0) or 0)
        ext = (meta.get('ext') or (os.path.splitext(path)[1] if path else '')).lower()
        api_hist = meta.get('api_hist') or []
        key = self._key(sha or '', size, ext)
        now = int(time.time())
        with self._lock:
            rec = self._records.get(key)
            if rec is None:
                rec = {
                    'labels': {label: {'count': 1, 'last': now}},
                    'first_seen': now, 'last_seen': now,
                    'sha256': sha, 'size': size, 'ext': ext, 'api_hist': list(api_hist),
                }
                self._records[key] = rec
            else:
                lbl = rec['labels'].setdefault(label, {'count': 0, 'last': now})
                lbl['count'] += 1
                lbl['last'] = now
                rec['last_seen'] = now
                if api_hist and not rec.get('api_hist'):
                    rec['api_hist'] = list(api_hist)
            self._prune_locked()
            self._maybe_autosave_locked()
        return key

    def _maybe_autosave_locked(self):
        """节流落盘: 距上次保存超过 _AUTOSAVE_INTERVAL 秒才写盘。外部仍可强制 save()。"""
        now = time.time()
        if now - self._last_save < _AUTOSAVE_INTERVAL:
            return
        self._last_save = now
        try:
            with open(self._store_path, 'w', encoding='utf-8') as f:
                json.dump(self._store, f, ensure_ascii=False, separators=(',', ':'))
        except Exception:
            pass

    def _prune_locked(self):
        if len(self._records) <= MAX_RECORDS:
            return
        # 清理最久未见的 benign-only 记录，直到达标
        items = [(k, r.get('last_seen', 0), r.get('labels', {}).get('benign'))
                 for k, r in self._records.items()]
        items.sort(key=lambda it: it[1])
        for k, last, benign in items:
            if not benign:
                continue
            labels = self._records[k].get('labels', {})
            if 'malicious' not in labels:
                del self._records[k]
                if len(self._records) <= MAX_RECORDS:
                    return

    # ---------- 查: 匹配 ----------
    def match(self, path: Optional[str] = None, meta: Optional[Dict] = None
              ) -> Optional[Dict]:
        """返回 {'label':str,'confidence':0-1,'count':int} 或 None(证据不足)。

        优先级: sha256 精确 -> size+ext+api_hist 近似。
        """
        meta = meta or {}
        sha = meta.get('sha256') or (_sha256_file(path) if path else None)
        size = int(meta.get('size') or (os.path.getsize(path) if path else 0) or 0)
        ext = (meta.get('ext') or (os.path.splitext(path)[1] if path else '')).lower()
        api_hist = meta.get('api_hist') or []

        with self._lock:
            if sha:
                rec = self._records.get(self._key(sha, size, ext))
                if rec is None:
                    # hash 一样但大小/扩展略有偏差也尝试
                    for k, r in self._records.items():
                        if r.get('sha256') == sha:
                            rec = r
                            break
                if rec is not None:
                    return self._decide(rec)
            # 近似匹配
            cand = None
            best = -1.0
            for k, r in self._records.items():
                if r.get('size') != size:
                    continue
                if ext and r.get('ext') != ext:
                    continue
                score = self._approx_score(api_hist, r.get('api_hist') or [])
                if score > best:
                    best = score
                    cand = r
            if cand is not None and best >= _API_HIST_MIN_OVERLAP:
                return self._decide(cand)
        return None

    @staticmethod
    def _approx_score(a: List, b: List) -> float:
        a = list(a)
        b = list(b)
        if not a or not b:
            return 0.5 if len(a) == len(b) else 0.0  # 无语义信息，弱匹配
        total = max(len(a), len(b))
        if total == 0:
            return 0.0
        inter = 0
        for x in set(a):
            if x in b:
                inter += 1
        return inter / total

    def _decide(self, rec: Dict) -> Dict:
        labels = rec.get('labels', {})
        ben = labels.get('benign', {}).get('count', 0)
        mal = labels.get('malicious', {}).get('count', 0)
        total = ben + mal
        if total < MIN_SUPPORT:
            return {'label': None, 'confidence': 0.0, 'count': total}
        if mal >= ben and mal > 0:
            label, cnt, other = 'malicious', mal, ben
        else:
            label, cnt, other = 'benign', ben, mal
        dominance = (cnt / total) if total else 0.0
        if dominance < MIN_DOMINANCE:
            return {'label': None, 'confidence': 0.0, 'count': total}
        # 支持度平滑; 距上次出现太旧则降权(明显不影响标记,只影响 confidence)
        conf = min(1.0, 0.5 + cnt * 0.15)
        return {'label': label, 'confidence': round(conf, 3), 'count': total}

    # ---------- 元数据/便利 ----------
    def size(self) -> int:
        with self._lock:
            return len(self._records)

    def merge(self, other: "StudyEngine"):
        """合并另一实例的记录(用于测试/导入)。"""
        for key, rec in other._records.items():
            self._records.setdefault(key, json.loads(json.dumps(rec)))


_default = None


def get_study_engine() -> "StudyEngine":
    global _default
    if _default is None:
        _default = StudyEngine()
    return _default


__all__ = ['StudyEngine', 'get_study_engine', 'MIN_SUPPORT']