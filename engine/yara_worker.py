#!/usr/bin/env python3
"""
YARA Worker - 在便携 Python 环境中运行的 YARA 扫描服务

通过 stdin/stdout JSON 协议与主进程通信，支持：
- scan_file: 扫描文件
- scan_memory: 扫描进程内存
- compile_rules: 编译规则
- ping: 健康检查
"""
import sys
import os
import json
import argparse
import traceback

# 将项目根目录加入 sys.path（便携 Python 运行 worker 时默认仅含脚本所在目录），
# 以便能 import db.signature_db 读取 DB 自动 YARA 规则。
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    import yara
    HAS_YARA = True
except Exception:
    HAS_YARA = False
    yara = None


def scan_file(file_path: str, rules_dir: str, compiled_cache: str = None) -> dict:
    if not HAS_YARA:
        return {'error': 'yara-python 未安装'}

    rules = _load_rules(rules_dir, compiled_cache)
    if rules is None:
        return {'matches': [], 'warning': '无可用规则'}

    try:
        matches = rules.match(filepath=file_path)
        result = []
        for m in matches:
            # yara-python 4.x 的 StringMatch 仅含 identifier/instances/is_xor，
            # 具体偏移和数据在 instances（StringMatchInstance）上。
            strings_info = []
            for s in (m.strings or []):
                insts = getattr(s, 'instances', None) or []
                for it in insts:
                    try:
                        strings_info.append({
                            'offset': getattr(it, 'offset', None),
                            'identifier': getattr(s, 'identifier', None),
                            'data': str(getattr(it, 'data', b''))[:64],
                        })
                    except Exception:
                        pass
            result.append({
                'rule': m.rule,
                'namespace': m.namespace,
                'description': m.description if hasattr(m, 'description') else '',
                'tags': list(m.tags) if hasattr(m, 'tags') else [],
                'strings': strings_info,
            })
        return {'matches': result}
    except yara.Error as e:
        return {'error': f'YARA 扫描错误: {str(e)}'}
    except Exception as e:
        return {'error': f'扫描异常: {str(e)}'}


def scan_memory(pid: int, rules_dir: str, compiled_cache: str = None) -> dict:
    if not HAS_YARA:
        return {'error': 'yara-python 未安装'}

    rules = _load_rules(rules_dir, compiled_cache)
    if rules is None:
        return {'matches': [], 'warning': '无可用规则'}

    try:
        matches = rules.match(pid=pid)
        result = []
        for m in matches:
            result.append({
                'rule': m.rule,
                'namespace': m.namespace,
                'description': m.description if hasattr(m, 'description') else '',
                'tags': list(m.tags) if hasattr(m, 'tags') else [],
                'strings_count': len(m.strings) if hasattr(m, 'strings') and m.strings else 0
            })
        return {'matches': result}
    except yara.Error as e:
        return {'error': f'YARA 内存扫描错误: {str(e)}'}
    except Exception as e:
        return {'error': f'内存扫描异常: {str(e)}'}


def compile_rules(rules_dir: str, output_path: str) -> dict:
    if not HAS_YARA:
        return {'error': 'yara-python 未安装'}

    yara_files = {}
    if os.path.isdir(rules_dir):
        for root, _, files in os.walk(rules_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in ('.yara', '.yar'):
                    full_path = os.path.join(root, file)
                    namespace = os.path.relpath(full_path, rules_dir).replace(os.sep, '_')
                    yara_files[namespace] = full_path

    if not yara_files:
        return {'success': False, 'error': '规则目录为空'}

    try:
        rules = yara.compile(filepaths=yara_files)
        rules.save(output_path)
        return {'success': True, 'rules_count': len(yara_files)}
    except Exception as e:
        return {'success': False, 'error': f'编译失败: {str(e)}'}


def check_status() -> dict:
    import platform
    return {
        'yara_available': HAS_YARA,
        'python_version': f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}',
        'platform': platform.platform(),
        'yara_version': yara.__version__ if HAS_YARA else None,
    }


def _load_db_rule_sources() -> list:
    """从 SignatureDB 读取所有启用的 auto_yara_rules（DB 自动 YARA 规则）。

    与主进程 rule_engine._load_auto_rules_from_db 保持一致。DB 不可用时静默跳过，
    仅返回磁盘规则。
    """
    sources = []
    try:
        from db.signature_db import SignatureDB
        db = SignatureDB()
        try:
            rules = db.get_active_yara_rules()
            for r in rules:
                content = r.get('rule_content')
                if content and content.strip():
                    sources.append(content.strip())
        finally:
            db.close()
    except Exception as e:
        print(f'加载 DB 自动 YARA 规则失败（可忽略）: {e}', file=sys.stderr)
    return sources


def _load_rules(rules_dir: str, compiled_cache: str = None):
    if not HAS_YARA:
        return None

    if compiled_cache and os.path.exists(compiled_cache):
        try:
            return yara.load(compiled_cache)
        except Exception:
            pass

    yara_files = {}
    if os.path.isdir(rules_dir):
        for root, _, files in os.walk(rules_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in ('.yara', '.yar'):
                    full_path = os.path.join(root, file)
                    namespace = os.path.relpath(full_path, rules_dir).replace(os.sep, '_')
                    yara_files[namespace] = full_path

    # DB 自动规则：与磁盘规则合并后一起编译。YARA 的 compile(filepaths=...)
    # 与 compile(source=...) 不能同时传入，因此把 DB 规则写入临时文件后并入
    # filepaths 命名空间，一次性编译，避免同名规则冲突。
    db_sources = _load_db_rule_sources()

    if not yara_files and not db_sources:
        return None

    tmp_path = None
    if db_sources:
        try:
            import tempfile
            fd, tmp_path = tempfile.mkstemp(suffix='.yar')
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write('\n\n'.join(db_sources))
            yara_files['_db_auto_rules'] = tmp_path
        except Exception as e:
            print(f'写入 DB 规则临时文件失败: {e}', file=sys.stderr)
            tmp_path = None

    try:
        return yara.compile(filepaths=yara_files)
    except Exception as e:
        print(f'规则编译失败: {e}', file=sys.stderr)
        return None
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description='YARA Worker')
    parser.add_argument('--action', required=True,
                        choices=['scan_file', 'scan_memory', 'compile_rules', 'ping'],
                        help='Action to perform')
    parser.add_argument('--file', help='File path for scan_file')
    parser.add_argument('--pid', type=int, help='PID for scan_memory')
    parser.add_argument('--rules-dir', default=None, help='YARA rules directory')
    parser.add_argument('--compiled-cache', default=None, help='Compiled rules cache path')
    parser.add_argument('--output', default=None, help='Output path for compile_rules')

    args = parser.parse_args()

    try:
        if args.action == 'ping':
            result = check_status()
        elif args.action == 'scan_file':
            if not args.file:
                result = {'error': 'scan_file 需要 --file 参数'}
            else:
                rules_dir = args.rules_dir or os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'rules', 'yara'
                )
                result = scan_file(args.file, rules_dir, args.compiled_cache)
        elif args.action == 'scan_memory':
            if args.pid is None:
                result = {'error': 'scan_memory 需要 --pid 参数'}
            else:
                rules_dir = args.rules_dir or os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'rules', 'yara'
                )
                result = scan_memory(args.pid, rules_dir, args.compiled_cache)
        elif args.action == 'compile_rules':
            if not args.output:
                result = {'error': 'compile_rules 需要 --output 参数'}
            else:
                rules_dir = args.rules_dir or os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'rules', 'yara'
                )
                result = compile_rules(rules_dir, args.output)
        else:
            result = {'error': f'未知操作: {args.action}'}
    except Exception as e:
        result = {'error': f'执行异常: {str(e)}', 'traceback': traceback.format_exc()}

    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
