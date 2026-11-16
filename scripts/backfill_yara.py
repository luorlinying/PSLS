"""回填脚本：为签名库中已有签名补全 fuzzy_hash + 自动 YARA 规则

用法:
    python scripts/backfill_yara.py                  # 默认隔离区
    python scripts/backfill_yara.py --sample-dir DIR  # 指定样本目录
    python scripts/backfill_yara.py --limit 50       # 限制处理数量
    python scripts/backfill_yara.py --force           # 强制重跑已生成过的签名
    python scripts/backfill_yara.py --dry-run         # 只打印不写 DB

流程:
    1. 从 signatures 表拉所有 hash
    2. 根据 hash 在样本目录中定位文件 (hash.ext / hash_*.ext / 匹配 quarantine.json 记录)
    3. 找到样本 -> 计算 fuzzy_hash -> 写回 signatures 表
    4. 用 yara_generator 生成规则 -> upsert 到 auto_yara_rules 表
"""

import os
import sys
import json
import time
import hashlib
import argparse
from typing import Optional

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from db.signature_db import SignatureDB
from engine.yara_generator import YaraGenerator
from utils.fuzzy_hash import fuzzy_file
from utils.logger import get_logger

logger = get_logger('backfill_yara')


def _find_sample(hash_sha256: str, sample_dirs: list) -> Optional[str]:
    """在候选目录中找 hash 对应的样本文件。

    尝试策略（按优先级）:
    1. {hash}.*  （hash 全名 + 任意扩展名）
    2. {hash}_*.*  （hash 前缀 + 下划线 + 时间戳 + 扩展名，隔离区命名）
    3. 遍历所有文件算 sha256 对比（代价高，最后兜底）
    """
    for d in sample_dirs:
        if not d or not os.path.isdir(d):
            continue
        # 策略 1 & 2: 按文件名模式匹配
        try:
            for entry in os.listdir(d):
                if entry.startswith('.') or entry == 'quarantine.json' or entry == '_file_backups':
                    continue
                full = os.path.join(d, entry)
                if not os.path.isfile(full):
                    continue
                name_no_ext = os.path.splitext(entry)[0]
                # 精准 hash
                if name_no_ext.lower() == hash_sha256.lower():
                    return full
                # hash 前缀 + 下划线隔离区模式
                if name_no_ext.lower().startswith(hash_sha256.lower() + '_'):
                    return full
                # hash 前缀就是它（有的隔离区命名直接把 hash 裁短当前缀）
                if len(hash_sha256) >= 16 and name_no_ext.lower().startswith(hash_sha256[:16].lower() + '_'):
                    # 读一下算 hash 确认
                    try:
                        h = hashlib.sha256()
                        with open(full, 'rb') as f:
                            for chunk in iter(lambda: f.read(65536), b''):
                                h.update(chunk)
                        if h.hexdigest().lower() == hash_sha256.lower():
                            return full
                    except Exception:
                        pass
        except Exception:
            continue

    # 策略 3: 兜底扫描所有文件算 hash
    for d in sample_dirs:
        if not d or not os.path.isdir(d):
            continue
        try:
            for root, _, files in os.walk(d):
                for f in files:
                    full = os.path.join(root, f)
                    try:
                        h = hashlib.sha256()
                        with open(full, 'rb') as fp:
                            for chunk in iter(lambda: fp.read(65536), b''):
                                h.update(chunk)
                        if h.hexdigest().lower() == hash_sha256.lower():
                            return full
                    except Exception:
                        continue
        except Exception:
            continue

    return None


def _load_quarantine_registry(sample_dirs: list) -> dict:
    """尝试从 quarantine.json 读取 hash -> file_path 映射。"""
    registry = {}
    for d in sample_dirs:
        if not d:
            continue
        qjson = os.path.join(d, 'quarantine.json')
        if not os.path.isfile(qjson):
            continue
        try:
            with open(qjson, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # 尝试不同结构
            entries = data if isinstance(data, list) else data.get('quarantined', data.get('items', []))
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                h = entry.get('hash') or entry.get('sha256') or ''
                path = entry.get('path') or entry.get('original_path') or entry.get('file_path') or ''
                if h and path:
                    registry[h.lower()] = path
        except Exception as e:
            logger.debug(f'读取 quarantine.json 失败 {qjson}: {e}')
    return registry


def main():
    ap = argparse.ArgumentParser(description='回填签名库的 fuzzy_hash 和自动 YARA 规则')
    ap.add_argument('--sample-dir', action='append', default=[], help='样本目录，可多次指定')
    ap.add_argument('--limit', type=int, default=0, help='最多处理多少条签名，0=全部')
    ap.add_argument('--force', action='store_true', help='强制重跑已有 fuzzy/yara 的签名')
    ap.add_argument('--dry-run', action='store_true', help='只打印不写 DB')
    args = ap.parse_args()

    # 默认样本目录：隔离区 + appdata 隔离区
    default_dirs = [
        os.path.join(_PROJECT_ROOT, 'quarantine'),
        os.path.join(os.environ.get('APPDATA', ''), 'PSLS', 'quarantine'),
    ]
    sample_dirs = args.sample_dir or [d for d in default_dirs if d]

    print(f'📂 样本搜索目录: {sample_dirs}')
    print(f'📋 连接签名库...')
    db = SignatureDB()
    gen = YaraGenerator()

    # 收集所有待处理签名
    if args.force:
        all_sigs = db.get_all_signatures(limit=args.limit or 5000)
    else:
        # 只挑缺失 yara 或 fuzzy 的
        need_yara = db.lookup_signatures_without_yara(limit=args.limit or 5000)
        need_fuzzy = db.lookup_signatures_without_fuzzy(limit=args.limit or 5000)
        seen = set()
        all_sigs = []
        for s in need_yara + need_fuzzy:
            h = s['hash']
            if h not in seen:
                seen.add(h)
                all_sigs.append(s)

    # 按 --limit 截断
    if args.limit > 0 and len(all_sigs) > args.limit:
        all_sigs = all_sigs[:args.limit]

    total = len(all_sigs)
    print(f'🎯 待处理签名: {total} 条')

    # 预加载 quarantine.json 注册表
    qregistry = _load_quarantine_registry(sample_dirs)
    if qregistry:
        print(f'📑 quarantine.json 注册表: {len(qregistry)} 条映射')

    found_count = 0
    fuzzy_ok = 0
    yara_ok = 0
    skipped_nosample = 0
    failed = 0

    for i, sig in enumerate(all_sigs, 1):
        h = sig['hash']
        name = sig.get('name') or h[:16]
        severity = sig.get('severity', 'high')
        mal_type = sig.get('type', sig.get('malware_type', 'unknown'))

        # 1. 先查 quarantine registry
        sample_path = qregistry.get(h.lower())
        if sample_path and not os.path.isfile(sample_path):
            sample_path = None

        # 2. DB 里有没有存 sample_path
        if not sample_path:
            try:
                row = db.lookup_signature(h)
                if row and row.get('sample_path') and os.path.isfile(row['sample_path']):
                    sample_path = row['sample_path']
            except Exception:
                pass

        # 3. 文件名扫描
        if not sample_path:
            sample_path = _find_sample(h, sample_dirs)

        status_tag = ''
        if sample_path:
            found_count += 1
            status_tag = '✅'
        else:
            skipped_nosample += 1
            status_tag = '❓'

        print(f'  [{i}/{total}] {status_tag} {name[:50]:50s}  sample={os.path.basename(sample_path) if sample_path else "-"}')

        if not sample_path or args.dry_run:
            continue

        try:
            # --- fuzzy hash ---
            fuzzy = fuzzy_file(sample_path)
            if fuzzy and ':' in fuzzy:
                db.update_signature_fuzzy(h, fuzzy)
                fuzzy_ok += 1

            # --- YARA 规则 ---
            rule_info = gen.generate(
                file_path=sample_path,
                sha256=h,
                name=name,
                sample_type=mal_type,
                severity=severity,
            )
            if rule_info and rule_info.get('rule_content'):
                db.upsert_yara_rule(
                    rule_name=rule_info['rule_name'],
                    rule_content=rule_info['rule_content'],
                    hash_sha256=h,
                    severity=severity,
                    feature_count=rule_info.get('feature_count', 0),
                    file_size=rule_info.get('file_size', 0),
                    sample_type=rule_info.get('sample_type', mal_type),
                    rule_source='backfill',
                )
                yara_ok += 1
            else:
                print(f'       ⚠️  无法生成 YARA 规则（特征不足或样本问题）')

        except Exception as e:
            failed += 1
            logger.exception(f'处理 {h} 失败: {e}')

    db.close()

    print()
    print('=' * 60)
    print(f'📊 回填完成')
    print(f'   总签名数:      {total}')
    print(f'   找到样本:      {found_count}')
    print(f'   fuzzy_hash 写库: {fuzzy_ok}')
    print(f'   YARA 规则写库:  {yara_ok}')
    print(f'   无样本跳过:    {skipped_nosample}')
    print(f'   处理失败:      {failed}')
    if args.dry_run:
        print('   (dry-run，未写库)')
    print('=' * 60)


if __name__ == '__main__':
    main()
