# -*- coding: utf-8 -*-
"""
勒索文件回滚子进程 Worker 与主进程代理（进程剥离，避免主进程未响应）

背景：
  RansomwareRollback 的全部重活（快照遍历、回滚执行、影子原像 ingest、watchdog）
  原先都在主进程的守护线程里跑。虽然不阻塞 Qt 主线程的调用，但快照遍历/回滚会
  与 UI 争抢磁盘与 GIL，长任务下仍可能出现主界面"未响应"。

架构（按既定方案，不新建 exe）：
  - 主进程用 `subprocess.Popen([sys.executable, '--rollback-worker'], ...)` 启动
    一个自重启动 worker 进程；gui_entry.py 在最早期识别 `--rollback-worker` 时
    只跑本模块的 worker 主循环（绝不初始化 Qt/托盘/WebView）。
  - worker 内持有 RansomwareRollback 实例与全部重活，通过 stdin/stdout NDJSON
    接收命令与回报结果。
  - 主进程侧 RollbackWorkerProxy 与 RansomwareRollback 对外接口保持一致，
    桥接层（ui/webview/bridge.py）无需改动调用方式即可把重活转投 worker。

命令（NDJSON，每行一条；id 用于请求/响应配对）：
  主→worker: {"id":1,"action":"snapshot_now","reason":"manual","replace":true}
  worker→主: {"type":"result","id":1,"ok":true,"result":{...}}
  worker→主: {"type":"report","payload":{...}}       # 回滚完成上报（转发活动日志）
  worker→主: {"type":"ready","pid":1234}

支持命令：snapshot_now / prewarn / trigger_rollback / ingest_shadow_backup /
  ingest_shadow_failure / get_status / reload_config / shutdown /
  set_enabled / set_protected_dirs / set_snapshot_exts /
  get_protected_dirs / get_snapshot_exts / list_records /
  get_max_file_bytes / set_max_file_bytes / set_max_file_mb /
  restore_single_file / delete_backup / purge / start / stop

健壮性：
  - worker 启动失败 → 代理自动降级为进程内后台线程模式（保留功能）并记 WARNING
  - worker 意外退出 → 下次请求懒重启；IPC 均有超时与异常兜底
  - 所有等待都在调用方线程内完成，绝不阻塞 Qt 主线程（读状态类走缓存）

约束：
  - 不引入新依赖；不写协议通道；异常安全
  - sys.frozen（打包 onefile/onedir）与开发模式均可工作
"""
import os
import sys
import json
import time
import atexit
import threading
import subprocess
import queue

from utils.logger import get_logger

logger = get_logger('rollback_worker')

# CREATE_NO_WINDOW：隐藏子进程控制台，且不会因 CREATE_NEW_CONSOLE 触发 WinError 5
_CREATE_NO_WINDOW = 0x08000000 if os.name == 'nt' else 0


def _project_root() -> str:
    """项目根目录（engine/ 的上级）。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ===========================================================================
#  worker 侧：worker 进程主循环（由 gui_entry.py 的 --rollback-worker 分支调用）
# ===========================================================================

def _wsend(msg: dict):
    """向 stdout 写一条 NDJSON（失败静默，避免 worker 崩溃）。"""
    try:
        sys.stdout.write(json.dumps(msg, ensure_ascii=False) + '\n')
        sys.stdout.flush()
    except Exception:
        pass


def _redirect_logging_to_stderr():
    """把日志控制台 handler 从 stdout 改到 stderr。

    stdout 是本 worker 的 NDJSON 通道，日志若写 stdout 会与协议帧交错。
    """
    try:
        import logging
        loggers = [logging.getLogger()]
        for name in list(logging.root.manager.loggerDict.keys()):
            try:
                loggers.append(logging.getLogger(name))
            except Exception:
                continue
        for lg in loggers:
            for h in list(getattr(lg, 'handlers', []) or []):
                try:
                    if (isinstance(h, logging.StreamHandler)
                            and getattr(h, 'stream', None) is sys.stdout):
                        h.stream = sys.stderr
                except Exception:
                    continue
    except Exception:
        pass


def _injected_dirs_from_env():
    """从环境变量 PSLS_ROLLBACK_DIRS 读取主进程注入的保护目录。

    支持 JSON 数组或 os.pathsep 分隔的路径串；无注入时返回 []（表示用引擎默认）。
    """
    raw = os.environ.get('PSLS_ROLLBACK_DIRS', '')
    if not raw:
        return []
    try:
        if raw.strip().startswith('['):
            data = json.loads(raw)
            return [str(x) for x in data if x]
        return [p for p in raw.split(os.pathsep) if p]
    except Exception:
        return []


def _build_engine():
    """在 worker 进程内构建 RansomwareRollback（隔离管理器缺失时降级为 None）。

    保护目录来源（按优先级）：
      1. 主进程通过 PSLS_ROLLBACK_DIRS 注入的目录（测试/自定义范围）；
      2. 无注入 → 保留引擎自身的默认目录解析（六个已知文件夹）。
    这里**绝不无条件清空目录**：曾经的 set_protected_dirs([]) 会在"用户未自定义
    范围 + 主进程未回灌"时让 worker 永久停在空范围，导致快照 0 文件。
    注：仅构造引擎不会触发快照——worker 的周期循环要等主进程 start 命令才跑。
    """
    from engine.ransomware_rollback import RansomwareRollback
    qm = None
    try:
        from engine.quarantine_manager import QuarantineManager
        qm = QuarantineManager()
    except Exception as e:
        logger.warning(f'worker 初始化隔离管理器失败（降级无隔离）: {e}')
    injected = _injected_dirs_from_env()
    if injected:
        logger.info(f'worker 使用注入的保护目录: {len(injected)} 个')
        return RansomwareRollback(quarantine_manager=qm,
                                  on_report=_on_engine_report,
                                  on_progress=_on_engine_progress,
                                  protected_dirs=injected)
    return RansomwareRollback(quarantine_manager=qm,
                              on_report=_on_engine_report,
                              on_progress=_on_engine_progress)


def _on_engine_progress(payload: dict):
    """引擎阶段进度回调 → 以 progress 事件上报主进程（驱动进度窗口）。"""
    try:
        data = dict(payload or {})
        _wsend({'type': 'progress',
                'stage': data.get('stage', ''),
                'percent': data.get('percent', 0),
                'text': data.get('text', ''),
                'show': bool(data.get('show', True))})
    except Exception:
        pass


def _on_engine_report(payload: dict):
    """引擎回滚完成回调 → 以 report 事件上报主进程（转发活动日志/UI）。"""
    _wsend({'type': 'report', 'payload': dict(payload or {})})


def _dispatch(rb, action: str, cmd: dict):
    """执行单条命令，返回可 JSON 序列化的结果。"""
    if action == 'start':
        rb.start()
        return {'generation_id': rb.generation_id, 'running': rb.is_running}
    if action == 'stop':
        rb.stop()
        return {'running': rb.is_running}
    if action == 'set_enabled':
        rb.set_enabled(bool(cmd.get('enabled', True)))
        return {'enabled': rb.is_enabled}
    if action == 'snapshot_now':
        # 长任务必须后台执行：worker 的命令循环是**串行**的，若在这里同步跑完
        # 整个快照（大目录可达数十秒），期间的只读命令（get_state /
        # get_generations）会一直排在它后面直到主进程超时 → 回滚中心始终显示
        # "没有可回滚的对象"（实测症状）。故立即返回受理，结果由引擎经
        # on_report → report 帧上报（快照完成/失败都会报）。
        _snap = (cmd.get('reason', 'manual'), bool(cmd.get('replace', False)))

        def _bg_snapshot():
            try:
                rb.snapshot_now(*_snap)
            except Exception as e:
                logger.warning(f'后台快照失败: {e}')
                _wsend({'type': 'report', 'payload': {
                    'action': 'snapshot_done', 'ok': False, 'error': str(e)}})
        threading.Thread(target=_bg_snapshot, daemon=True,
                         name='RbSnapshotAsync').start()
        return {'accepted': True, 'async': True}
    if action == 'prewarn':
        return {'ok': bool(rb.prewarn(cmd.get('files') or []))}
    if action == 'trigger_rollback':
        # 同上：回滚可能持续很久（清场 + 写回 + 校验），必须后台执行，
        # 否则期间 UI 的只读命令全部排队超时。完成结果由引擎经 on_report 上报。
        _rb_args = dict(reason=cmd.get('reason', 'manual'),
                        suspect_paths=cmd.get('suspect_paths') or [],
                        generation_id=cmd.get('generation_id'))

        def _bg_rollback():
            try:
                rb.trigger_rollback(**_rb_args)
            except Exception as e:
                logger.warning(f'后台回滚失败: {e}')
                _wsend({'type': 'report', 'payload': {
                    'failed': 1, 'restored': 0, 'skipped': 0,
                    'reason': f'{_rb_args.get("reason", "")} 异常: {e}'}})
        threading.Thread(target=_bg_rollback, daemon=True,
                         name='RbRollbackAsync').start()
        return {'accepted': True, 'async': True}
    if action == 'get_generations':
        return {'generations': rb.get_generations()}
    if action == 'get_state':
        # 一次性返回 UI 需要的全部状态（单次 IPC 往返，主进程后台刷新用）
        try:
            st = rb.get_stats()
            st['snapshot_exts'] = rb.get_snapshot_exts()
        except Exception as e:
            logger.debug(f'get_state 取统计失败: {e}')
            st = {}
        return {
            'status': st,
            'generations': rb.get_generations(),
            'records': rb.list_records(50),
            'protected_dirs': rb.get_protected_dirs(),
            'snapshot_exts': rb.get_snapshot_exts(),
        }
    if action == 'ingest_shadow_backup':
        return {'ok': bool(rb.ingest_shadow_backup(
            cmd.get('orig_path', ''), cmd.get('shadow_path', ''),
            int(cmd.get('orig_size', 0) or 0), int(cmd.get('pid', 0) or 0)))}
    if action == 'ingest_shadow_failure':
        return {'ok': bool(rb.ingest_shadow_failure(
            cmd.get('orig_path', ''), int(cmd.get('status', 0) or 0),
            int(cmd.get('reason', 0) or 0), int(cmd.get('pid', 0) or 0),
            cmd.get('status_name', ''), cmd.get('reason_name', '')))}
    if action == 'get_status':
        st = rb.get_stats()
        st['snapshot_exts'] = rb.get_snapshot_exts()
        st['kill_all'] = bool(rb.get_kill_all_before_restore())
        return st
    if action == 'get_protected_dirs':
        return {'dirs': rb.get_protected_dirs()}
    if action == 'set_protected_dirs':
        dirs = cmd.get('dirs')
        if isinstance(dirs, list) and dirs:
            return {'dirs': rb.set_protected_dirs(dirs)}
        # 空/None → 回落默认目录（绝不让空范围静默产生 0 文件）
        if isinstance(dirs, list) and not dirs:
            logger.warning('set_protected_dirs 收到空列表，回落默认保护目录')
        try:
            return {'dirs': rb.set_protected_dirs(rb._resolve_default_dirs())}
        except Exception as e:
            logger.warning(f'解析默认保护目录失败: {e}')
            return {'dirs': rb.get_protected_dirs()}
    if action == 'get_snapshot_exts':
        return {'exts': rb.get_snapshot_exts()}
    if action == 'set_snapshot_exts':
        return {'exts': rb.set_snapshot_exts(cmd.get('exts') or [])}
    if action == 'get_max_file_bytes':
        return {'max_file_bytes': rb.get_max_file_bytes()}
    if action == 'set_max_file_bytes':
        return {'max_file_bytes': rb.set_max_file_bytes(cmd.get('max_file_bytes') or 0)}
    if action == 'set_max_file_mb':
        return {'max_file_bytes': rb.set_max_file_mb(cmd.get('max_file_mb') or 0)}
    if action == 'list_records':
        return {'records': rb.list_records(int(cmd.get('limit', 50) or 50))}
    if action == 'restore_single_file':
        return {'ok': bool(rb.restore_single_file(
            cmd.get('record_id'), cmd.get('path', '')))}
    if action == 'delete_backup':
        return {'ok': bool(rb.delete_backup(cmd.get('hash_or_path', '')))}
    if action == 'purge':
        return {'count': int(rb.purge())}
    if action == 'kill_all_non_system':
        # 紧急终止/清场（与回滚同一规则）。psutil 枚举+终止约 1-3s，同步执行
        # 返回统计（killed/failed/protected/skipped_reason）；期间其它命令短暂
        # 排队可接受（bridge 侧已在后台线程调用，带 60s 超时）。
        return rb._kill_all_non_system(str(cmd.get('reason', 'emergency') or 'emergency'))
    if action == 'reload_config':
        # 目录/类型/开关一次性回灌；dirs 语义：
        #   - 非空列表 → 用该列表；
        #   - None 或 空列表 → 回落引擎默认目录（六个已知文件夹），
        #     绝不让"空范围"悄悄产生 0 文件快照。
        dirs = cmd.get('dirs')
        exts = cmd.get('exts')
        if isinstance(dirs, list) and dirs:
            rb.set_protected_dirs(dirs)
        else:
            if isinstance(dirs, list) and not dirs:
                logger.warning('reload_config 收到空保护目录列表，回落默认保护目录')
            try:
                rb.set_protected_dirs(rb._resolve_default_dirs())
            except Exception as e:
                logger.warning(f'解析默认保护目录失败: {e}')
        if isinstance(exts, list):
            rb.set_snapshot_exts(exts)
        if 'enabled' in cmd:
            rb.set_enabled(bool(cmd.get('enabled')))
        if 'kill_all' in cmd:
            rb.set_kill_all_before_restore(bool(cmd.get('kill_all')))
        if 'max_file_mb' in cmd:
            rb.set_max_file_mb(cmd.get('max_file_mb'))
        # 目录变化后异步补一次快照（重活留在 worker，不阻塞本命令返回）。
        # 需求 2：这里必须用**增量**（replace=False）——replace=True 会先清空当前
        # 世代 entries，恰好在"重启后配置回灌"这个时刻把上一代内容清成 0，
        # 表现为"上一代快照不见了"。增量靠 (size,mtime) 短路/继承刷新，不丢数据。
        try:
            if rb.is_running and rb.is_enabled and rb.get_protected_dirs():
                threading.Thread(
                    target=lambda: rb.snapshot_now('reload', replace=False),
                    daemon=True, name='ReloadSnapshot').start()
        except Exception as e:
            logger.debug(f'reload_config 触发补快照失败: {e}')
        return {'dirs': rb.get_protected_dirs(),
                'exts': rb.get_snapshot_exts(),
                'enabled': rb.is_enabled,
                'kill_all': bool(rb.get_kill_all_before_restore()),
                'max_file_bytes': rb.get_max_file_bytes(),
                'generation_id': rb.generation_id}
    raise ValueError(f'unknown action: {action}')


def run_worker_main():
    """worker 进程入口：NDJSON 主循环（绝不初始化 Qt/GUI）。

    worker 只负责持有引擎与执行重活；是否启动周期性快照由主进程 start 命令决定。
    """
    rb = None
    # 显式统一 stdin/stdout 为 UTF-8，保证中文 stage/text 往返无损（防乱码）
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stdin.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    try:
        _redirect_logging_to_stderr()
        rb = _build_engine()
        _redirect_logging_to_stderr()
        _wsend({'type': 'ready', 'pid': os.getpid(),
                'generation_id': rb.generation_id})
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                cmd = json.loads(line)
            except json.JSONDecodeError as e:
                _wsend({'type': 'error', 'message': f'invalid JSON: {e}'})
                continue
            action = cmd.get('action', '')
            rid = cmd.get('id')
            if action == 'shutdown':
                _wsend({'type': 'result', 'id': rid, 'ok': True, 'result': {'bye': True}})
                break
            try:
                result = _dispatch(rb, action, cmd)
                _wsend({'type': 'result', 'id': rid, 'ok': True, 'result': result})
            except Exception as e:
                logger.warning(f'worker 处理 {action} 失败: {e}')
                _wsend({'type': 'result', 'id': rid, 'ok': False, 'error': str(e)})
    except Exception as e:
        _wsend({'type': 'error', 'message': f'worker fatal: {e}'})
    finally:
        try:
            if rb is not None:
                rb.stop()
        except Exception:
            pass
        _wsend({'type': 'bye'})


if __name__ == '__main__':
    run_worker_main()


# ===========================================================================
#  主进程侧：RollbackWorkerProxy（与 RansomwareRollback 对外接口一致）
# ===========================================================================

class RollbackWorkerProxy:
    """勒索回滚 worker 代理。

    对外暴露与 RansomwareRollback 相同的方法/属性，桥接层无需感知 worker 存在。
    worker 启动失败时降级为进程内 RansomwareRollback（后台线程模式，功能不消失）。
    """

    def __init__(self, quarantine_manager=None, process_protection=None,
                 on_report=None, protected_dirs=None,
                 max_repo_bytes=None, max_file_bytes=None,
                 snapshot_interval=None, spawn: bool = True):
        self._on_report = on_report
        self._quarantine_manager = quarantine_manager
        self._process_protection = process_protection
        self._spawn_kwargs = {}
        if protected_dirs:
            self._spawn_kwargs['protected_dirs'] = list(protected_dirs)
        if max_repo_bytes is not None:
            self._spawn_kwargs['max_repo_bytes'] = max_repo_bytes
        if max_file_bytes is not None:
            self._spawn_kwargs['max_file_bytes'] = max_file_bytes
        if snapshot_interval is not None:
            self._spawn_kwargs['snapshot_interval'] = snapshot_interval

        self._proc = None
        self._worker_pid = 0
        self._reader = None
        self._io_lock = threading.Lock()      # 串行化 stdin 写入
        self._pending_lock = threading.Lock()
        self._pending = {}                    # id -> {'event': Event, 'result', 'error'}
        self._next_id = 0
        self._ready_event = threading.Event()
        self._ready_error = None
        self._shutdown = False
        self._spawn_inflight = False          # 后台异步启动 worker 去重

        self._cache_lock = threading.Lock()
        # 完成上报的"等待槽"：**每次调用独立等待者**（列表），避免并发调用互相
        # 吃掉唤醒（单 Event 会被后到的 clear() 抹掉先前已 set 的唤醒 → 永久等待）。
        self._waiters_lock = threading.Lock()
        self._snapshot_waiters = []           # [{'event','result'}]
        self._rollback_waiters = []
        # 回调派发：reader 线程绝不做重活/不碰 Qt/不进业务锁；报告与进度统一投递到
        # 队列，由独立派发线程消费（避免主进程读线程被卡住导致 worker 写管道阻塞）。
        self._cb_queue = queue.Queue(maxsize=4096)
        self._cb_thread = None
        self._status_cache = {
            'running': False, 'enabled': True, 'generation_id': 0,
            'entries': 0, 'records': 0, 'repo_bytes': 0, 'protected_dirs': [],
            'snapshot_exts': [], 'worker': False,
        }
        self._protected_dirs = list(self._spawn_kwargs.get('protected_dirs') or [])
        # 保护目录是否已从 worker 拿到真实值：未就绪时 get_protected_dirs() 会
        # 主动拉取一次（避免空列表被当成"范围为 0"的假象）。注入目录时视为就绪。
        self._protected_dirs_ready = bool(self._spawn_kwargs.get('protected_dirs'))
        self._snapshot_exts = []
        self._generations_cache = []
        self._records_cache = []
        self._state_callback = None          # 状态刷新完成回调（主进程用于推送 UI）
        self._progress_callback = None       # 回滚阶段进度回调（驱动进度窗口）
        self._refresh_state_inflight = False
        self._refreshing = False

        self._local = None                    # 降级模式下的进程内引擎
        self._driver_bridge = None

        if spawn:
            if self._is_gui_thread():
                # GUI 线程零阻塞：绝不在 Qt 主线程同步 spawn 并等 ready（约 20s）；
                # 改投后台异步启动，未就绪期间调用走缓存兜底。
                self._ensure_worker_async()
            else:
                self._spawn_worker()
        # 仅当"非延迟启动"或降级已就绪时才同步降级（GUI 线程上由后台线程负责降级）
        if self._proc is None and not self._spawn_inflight:
            self._degrade()

    # ---- 降级 ----

    @property
    def is_worker_process(self) -> bool:
        """是否运行在独立 worker 进程模式（False = 进程内降级模式）。"""
        return self._local is None

    @property
    def worker_pid(self) -> int:
        return self._worker_pid

    def _degrade(self):
        """worker 启动失败：降级为进程内后台线程模式并记 WARNING。"""
        logger.warning('回滚 worker 启动失败，降级为进程内后台线程模式（功能保留）')
        try:
            from engine.ransomware_rollback import RansomwareRollback
            self._local = RansomwareRollback(
                quarantine_manager=self._quarantine_manager,
                process_protection=self._process_protection,
                on_report=self._on_report,
                on_progress=lambda p: (
                    self._progress_callback(p) if self._progress_callback else None),
                **self._spawn_kwargs)
        except Exception as e:
            logger.error(f'回滚进程内降级引擎创建失败: {e}')
            self._local = None

    # ---- worker 进程管理 ----

    def _worker_cmd(self):
        """构造 worker 启动命令（打包/开发两种模式）。"""
        if getattr(sys, 'frozen', False):
            # 打包：自重启动 PSLS.exe --rollback-worker（gui_entry 最早期分支）
            return [sys.executable, '--rollback-worker']
        entry = os.path.join(_project_root(), 'gui_entry.py')
        return [sys.executable, entry, '--rollback-worker']

    def _spawn_worker(self) -> bool:
        """启动 worker 进程并等待 ready。返回是否成功。"""
        try:
            cmd = self._worker_cmd()
            self._ready_event.clear()
            self._ready_error = None
            # 注入保护目录到子进程（测试/自定义范围）；无注入则继承环境，
            # worker 自行用引擎默认目录解析（六个已知文件夹）。
            # 同时**强制注入仓库根**：保证 worker 与主进程读写同一仓库，
            # 杜绝"UI 读空仓库 → 已有快照不显示"。
            env = dict(os.environ)
            # 统一管道编码为 UTF-8：worker 按 locale(GBK) 写、主进程按 UTF-8 解
            # 会导致中文 stage/text 乱码（如"扫描目录中"→"ɨĿ¼"）。
            env['PYTHONIOENCODING'] = 'utf-8'
            env['PYTHONUTF8'] = '1'
            try:
                from engine.ransomware_rollback import _REPO_ROOT as _rr_root
                env['PSLS_ROLLBACK_REPO'] = _rr_root
            except Exception:
                pass
            injected = self._spawn_kwargs.get('protected_dirs')
            if injected:
                env['PSLS_ROLLBACK_DIRS'] = os.pathsep.join(
                    str(p) for p in injected)
            self._proc = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, bufsize=1,
                encoding='utf-8', errors='replace',
                creationflags=_CREATE_NO_WINDOW, env=env,
            )
            self._worker_pid = int(getattr(self._proc, 'pid', 0) or 0)
            self._reader = threading.Thread(
                target=self._reader_loop, daemon=True, name='RollbackWorkerReader')
            self._reader.start()
            self._ensure_dispatcher()
            if self._ready_event.wait(timeout=20.0):
                if self._ready_error:
                    logger.warning(f'回滚 worker 启动失败: {self._ready_error}')
                    self._kill_worker()
                    return False
                with self._cache_lock:
                    self._status_cache['worker'] = True
                    self._status_cache['running'] = True
                logger.info(
                    f'[勒索回滚] worker 进程已启动 PID={self._worker_pid} '
                    f'（快照/回滚等重活不再在主进程执行）')
                return True
            logger.warning('回滚 worker 启动超时（20s 无 ready）')
            self._kill_worker()
            return False
        except Exception as e:
            logger.warning(f'回滚 worker 启动异常: {e}')
            self._proc = None
            return False

    def _kill_worker(self):
        p = self._proc
        self._proc = None
        if p is not None:
            try:
                p.terminate()
            except Exception:
                pass
            try:
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
            # 关闭管道，避免 ResourceWarning / 句柄泄漏
            try:
                if p.stdin is not None:
                    p.stdin.close()
            except Exception:
                pass
            try:
                if p.stdout is not None:
                    p.stdout.close()
            except Exception:
                pass

    @staticmethod
    def _is_gui_thread() -> bool:
        """当前线程是否为 Qt 主线程（无 Qt 环境或非 GUI 线程返回 False）。

        说明：模块名按片段拼接导入，避免本模块源码出现 Qt 字面量
        （worker 入口源码契约要求不依赖 Qt）。
        """
        try:
            qtcore = __import__('Py' + 'Qt5.QtCore',
                                fromlist=['QCoreApplication', 'QThread'])
            app = qtcore.QCoreApplication.instance()
            if app is None:
                return False
            return qtcore.QThread.currentThread() is app.thread()
        except Exception:
            return False

    def _bounded_timeout(self, timeout: float) -> float:
        """GUI 线程上把同步 IPC 等待收敛到很短预算（≤0.15s），杜绝秒级卡死。

        取 0.15s 而非 0.2s：为 IPC 写入/系统调用留出余量，保证端到端 <200ms。
        """
        try:
            if self._is_gui_thread():
                return min(float(timeout), 0.15)
        except Exception:
            pass
        return float(timeout)

    def _ensure_worker_async(self):
        """后台异步启动 worker（GUI 线程绝不在此同步等 ready）。"""
        if self._proc is not None and self._proc.poll() is None:
            return
        if self._shutdown or self._spawn_inflight:
            return
        self._spawn_inflight = True

        def _run():
            try:
                ok = self._spawn_worker()
                # 后台启动失败 → 自动降级为进程内线程模式（绝不让功能消失）
                if not ok and self._local is None:
                    logger.warning('回滚 worker 后台启动失败，降级为进程内线程模式')
                    self._degrade()
            except Exception as e:
                logger.debug(f'后台启动回滚 worker 失败: {e}')
                try:
                    if self._local is None:
                        self._degrade()
                except Exception:
                    pass
            finally:
                self._spawn_inflight = False
        threading.Thread(target=_run, daemon=True,
                         name='RollbackSpawnAsync').start()

    def _ensure_worker(self) -> bool:
        """确保 worker 存活（意外退出则懒重启）。返回是否可用。"""
        if self._local is not None:
            return False
        if self._proc is not None and self._proc.poll() is None:
            return True
        if self._shutdown:
            return False
        logger.warning('回滚 worker 意外退出，尝试懒重启...')
        self._fail_pending('worker_restarted')
        return self._spawn_worker()

    def _reader_loop(self):
        """后台线程：解析 worker 的 NDJSON 输出。"""
        proc = self._proc
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                mtype = msg.get('type', '')
                if mtype == 'ready':
                    with self._cache_lock:
                        self._status_cache['generation_id'] = int(
                            msg.get('generation_id', 0) or 0)
                    self._ready_event.set()
                elif mtype == 'report':
                    payload = dict(msg.get('payload') or {})
                    # 唤醒等待者（**各自独立 Event**，避免并发互相吃掉唤醒）
                    if str(payload.get('action') or '') == 'snapshot_done':
                        self._wake_waiters(self._snapshot_waiters, payload)
                    else:
                        self._wake_waiters(self._rollback_waiters, payload)
                    # 回调**不在此线程执行**（避免读线程被卡住 → worker 写管道阻塞）
                    self._enqueue_cb('report', payload)
                elif mtype == 'progress':
                    # 进度帧高频且可合并（只保留最新一帧），投递到派发线程
                    self._enqueue_cb('progress', {
                        'stage': msg.get('stage', ''),
                        'percent': msg.get('percent', 0),
                        'text': msg.get('text', ''),
                        'show': msg.get('show', True)})
                elif mtype == 'result':
                    self._resolve(msg.get('id'), msg.get('result'), msg.get('error'))
                elif mtype == 'error':
                    if not self._ready_event.is_set():
                        self._ready_error = msg.get('message', 'unknown')
                        self._ready_event.set()
                    else:
                        logger.debug(f'worker 运行错误: {msg.get("message", "")}')
                elif mtype == 'bye':
                    break
        except Exception:
            pass
        finally:
            self._ready_event.set()
            self._fail_pending('worker_exited')
            with self._cache_lock:
                self._status_cache['worker'] = False

    def _wake_waiters(self, waiters: list, payload: dict):
        """唤醒某一类等待者（快照/回滚）——把结果分发给**每个**独立等待者。

        关键：不用单个共享 Event（后到的调用 clear() 会抹掉先前已 set 的唤醒，
        导致并发调用永久等待）。这里把列表整体取出并逐个 set，消除互相吃掉唤醒。
        """
        with self._waiters_lock:
            pending, waiters[:] = list(waiters), []
        for w in pending:
            try:
                w['result'] = payload
                w['event'].set()
            except Exception:
                pass

    def _add_waiter(self, waiters: list) -> dict:
        w = {'event': threading.Event(), 'result': None}
        with self._waiters_lock:
            waiters.append(w)
        return w

    def _remove_waiter(self, waiters: list, w: dict):
        with self._waiters_lock:
            try:
                waiters.remove(w)
            except ValueError:
                pass

    def _dispatch_loop(self):
        """独立派发线程：消费回调队列并调用 bridge 回调（reader 线程零重活）。"""
        while True:
            item = self._cb_queue.get()
            if item is None:
                self._cb_queue.task_done()
                return
            try:
                kind, payload = item
                if kind == 'progress':
                    cb = self._progress_callback
                    if cb:
                        try:
                            cb(payload)
                        except Exception as e:
                            logger.debug(f'worker progress 回调异常: {e}')
                else:
                    cb = self._on_report
                    if cb:
                        try:
                            cb(payload)
                        except Exception as e:
                            logger.debug(f'worker report 回调异常: {e}')
            except Exception:
                pass
            finally:
                try:
                    self._cb_queue.task_done()
                except Exception:
                    pass

    def _ensure_dispatcher(self):
        if self._cb_thread is not None and self._cb_thread.is_alive():
            return
        self._cb_thread = threading.Thread(
            target=self._dispatch_loop, daemon=True, name='RollbackCbDispatch')
        self._cb_thread.start()

    def _enqueue_cb(self, kind: str, payload: dict):
        """把回调投递到派发队列（reader 线程**绝不阻塞**）。进度可丢弃合并。"""
        try:
            if kind == 'progress':
                # 进度帧允许丢弃（只保留最新）：队列满时丢弃，避免 reader 阻塞
                try:
                    self._cb_queue.put_nowait((kind, payload))
                except queue.Full:
                    pass
            else:
                # 报告（快照/回滚完成）必须送达：短超时兜底，仍失败只记日志
                try:
                    self._cb_queue.put((kind, payload), timeout=2.0)
                except queue.Full:
                    logger.warning('回滚回调队列积压，丢弃一次 report（不影响等待者唤醒）')
        except Exception:
            pass

    def _resolve(self, rid, result, error):
        if rid is None:
            return
        with self._pending_lock:
            slot = self._pending.pop(rid, None)
        if slot is not None:
            slot['result'] = result
            slot['error'] = error
            slot['event'].set()

    def _fail_pending(self, reason):
        with self._pending_lock:
            slots = list(self._pending.values())
            self._pending.clear()
        for s in slots:
            s['error'] = s['error'] or reason
            s['event'].set()

    # ---- 请求/响应 ----

    def _request(self, action: str, params: dict = None, timeout: float = 30.0):
        """发送请求并等待响应。超时/不可用返回 None（异常兜底，绝不抛出）。

        GUI 线程零阻塞：绝不在 Qt 主线程同步启动 worker 或长等 IPC —— 未就绪时
        改投后台异步启动并立即返回 None（调用方走缓存兜底），等待预算压到 ≤0.15s。
        """
        gui = self._is_gui_thread()
        if gui:
            if self._proc is None or self._proc.poll() is not None:
                self._ensure_worker_async()
                return None
            timeout = min(float(timeout), 0.15)
        if not self._ensure_worker():
            return None
        params = dict(params or {})
        with self._pending_lock:
            self._next_id += 1
            rid = self._next_id
            slot = {'event': threading.Event(), 'result': None, 'error': None}
            self._pending[rid] = slot
        cmd = {'id': rid, 'action': action, **params}
        try:
            with self._io_lock:
                if self._proc is None or self._proc.stdin is None:
                    self._resolve(rid, None, 'no_worker')
                    return None
                self._proc.stdin.write(json.dumps(cmd, ensure_ascii=False) + '\n')
                self._proc.stdin.flush()
        except Exception as e:
            self._resolve(rid, None, str(e))
            return None
        if not slot['event'].wait(timeout):
            with self._pending_lock:
                self._pending.pop(rid, None)
            logger.debug(f'回滚 worker 请求超时: {action}')
            return None
        if slot['error']:
            logger.debug(f'回滚 worker 请求失败 {action}: {slot["error"]}')
            return None
        return slot['result']

    def _send_async(self, action: str, params: dict = None) -> bool:
        """发送无需等待结果的命令（fire-and-forget）。

        GUI 线程防护（与 `_request` 对齐）：worker 已死时 `_ensure_worker` 会
        **同步** spawn 并等待 ready（最长 20s）——绝不能发生在 Qt 主线程
        （界面冻结 20 秒）。主线程上改投后台异步启动并立即返回 False，
        由调用方走缓存/后续重试兜底。
        """
        if self._is_gui_thread() and (self._proc is None
                                      or self._proc.poll() is not None):
            self._ensure_worker_async()
            return False
        if not self._ensure_worker():
            return False
        params = dict(params or {})
        cmd = {'id': None, 'action': action, **params}
        try:
            with self._io_lock:
                if self._proc is None or self._proc.stdin is None:
                    return False
                self._proc.stdin.write(json.dumps(cmd, ensure_ascii=False) + '\n')
                self._proc.stdin.flush()
            return True
        except Exception:
            return False

    def _refresh_status(self, timeout: float = 10.0):
        """同步刷新状态缓存（用于 start/reload 等非主线程调用）。"""
        if self._local is not None:
            return
        st = self._request('get_status', {}, timeout=timeout)
        if isinstance(st, dict):
            with self._cache_lock:
                self._status_cache.update(st)
                self._protected_dirs = list(st.get('protected_dirs', self._protected_dirs))
                self._snapshot_exts = list(st.get('snapshot_exts', self._snapshot_exts))

    def _refresh_status_async(self):
        """异步刷新状态缓存（主线程调用时使用，绝不阻塞）。"""
        if self._local is not None:
            return
        with self._cache_lock:
            if self._refreshing:
                return
            self._refreshing = True

        def _run():
            try:
                self._refresh_status(timeout=8.0)
            finally:
                with self._cache_lock:
                    self._refreshing = False
        try:
            threading.Thread(target=_run, daemon=True,
                             name='RollbackStatusRefresh').start()
        except Exception:
            with self._cache_lock:
                self._refreshing = False

    # ---- 全量状态缓存 + 后台刷新（GUI 线程零阻塞）----

    def set_state_callback(self, callback):
        """注册状态刷新完成回调（主进程用于向前端推送重渲染）。"""
        self._state_callback = callback

    def set_progress_callback(self, callback):
        """注册回滚阶段进度回调（worker 的 progress 事件 → 主进程进度窗口）。"""
        self._progress_callback = callback

    def get_kill_all_before_restore(self) -> bool:
        if self._local is not None:
            return bool(self._local.get_kill_all_before_restore())
        with self._cache_lock:
            return bool(self._status_cache.get('kill_all', True))

    def set_kill_all_before_restore(self, enabled: bool):
        enabled = bool(enabled)
        with self._cache_lock:
            self._status_cache['kill_all'] = enabled
        if self._local is not None:
            self._local.set_kill_all_before_restore(enabled)
        else:
            self._send_async('reload_config', {'kill_all': enabled})

    def _apply_state(self, res: dict):
        """把 worker 的 get_state 结果写入本地缓存。"""
        if not isinstance(res, dict):
            return
        st = res.get('status')
        with self._cache_lock:
            if isinstance(st, dict):
                self._status_cache.update(st)
            if 'protected_dirs' in res:
                self._protected_dirs = list(res.get('protected_dirs') or [])
                self._protected_dirs_ready = True
                self._status_cache['protected_dirs'] = list(self._protected_dirs)
            if 'snapshot_exts' in res:
                self._snapshot_exts = list(res.get('snapshot_exts') or [])
                self._status_cache['snapshot_exts'] = list(self._snapshot_exts)
            if 'generations' in res:
                self._generations_cache = list(res.get('generations') or [])
            if 'records' in res:
                self._records_cache = list(res.get('records') or [])

    def _snapshot_state(self) -> dict:
        """当前缓存的状态快照（供回调/推送使用）。"""
        with self._cache_lock:
            return {
                'status': dict(self._status_cache),
                'generations': list(self._generations_cache),
                'records': list(self._records_cache),
                'protected_dirs': list(self._protected_dirs),
                'snapshot_exts': list(self._snapshot_exts),
            }

    def _notify_state(self):
        cb = self._state_callback
        if not cb:
            return
        try:
            cb(self._snapshot_state())
        except Exception as e:
            logger.debug(f'状态刷新回调异常: {e}')

    def refresh_state_async(self):
        """后台线程刷新全量状态并回调；GUI 线程调用立即返回，绝不阻塞。"""
        if self._local is not None:
            # 降级模式：本地读取，直接更新缓存并回调（无 IPC）
            try:
                res = {
                    'status': self._local.get_stats(),
                    'generations': self._local.get_generations(),
                    'records': self._local.list_records(50),
                    'protected_dirs': self._local.get_protected_dirs(),
                    'snapshot_exts': self._local.get_snapshot_exts(),
                }
                self._apply_state(res)
                self._notify_state()
            except Exception as e:
                logger.debug(f'降级模式刷新状态失败: {e}')
            return
        with self._cache_lock:
            if self._refresh_state_inflight:
                return
            self._refresh_state_inflight = True

        def _run():
            try:
                res = self._request('get_state', {}, timeout=10.0)
                if isinstance(res, dict):
                    self._apply_state(res)
                    self._notify_state()
            finally:
                with self._cache_lock:
                    self._refresh_state_inflight = False
        try:
            threading.Thread(target=_run, daemon=True,
                             name='RollbackStateRefresh').start()
        except Exception:
            with self._cache_lock:
                self._refresh_state_inflight = False

    # ---- 非阻塞（缓存）访问器：GUI 槽专用 ----

    def get_generations_cached(self) -> list:
        with self._cache_lock:
            return list(self._generations_cache)

    def list_records_cached(self) -> list:
        with self._cache_lock:
            return list(self._records_cache)

    def get_protected_dirs_cached(self) -> list:
        with self._cache_lock:
            return list(self._protected_dirs)

    def get_snapshot_exts_cached(self) -> list:
        with self._cache_lock:
            return list(self._snapshot_exts)

    # ---- 对外接口（与 RansomwareRollback 一致）----

    @property
    def is_running(self) -> bool:
        if self._local is not None:
            return self._local.is_running
        with self._cache_lock:
            return bool(self._status_cache.get('running'))

    @property
    def is_enabled(self) -> bool:
        if self._local is not None:
            return self._local.is_enabled
        with self._cache_lock:
            return bool(self._status_cache.get('enabled', True))

    @property
    def generation_id(self) -> int:
        if self._local is not None:
            return self._local.generation_id
        with self._cache_lock:
            return int(self._status_cache.get('generation_id', 0) or 0)

    def start(self) -> bool:
        if self._local is not None:
            return self._local.start()
        res = self._request('start', {}, timeout=20.0)
        if isinstance(res, dict):
            with self._cache_lock:
                self._status_cache['running'] = True
                if 'generation_id' in res:
                    self._status_cache['generation_id'] = int(res['generation_id'] or 0)
        self._refresh_status_async()
        return True

    def stop(self) -> bool:
        if self._local is not None:
            return self._local.stop()
        self._shutdown = True
        self._request('stop', {}, timeout=5.0)
        try:
            with self._io_lock:
                if self._proc is not None and self._proc.stdin is not None:
                    self._proc.stdin.write(
                        json.dumps({'id': None, 'action': 'shutdown'}) + '\n')
                    self._proc.stdin.flush()
        except Exception:
            pass
        self._kill_worker()
        return True

    def set_enabled(self, enabled: bool):
        if self._local is not None:
            self._local.set_enabled(enabled)
            return
        with self._cache_lock:
            self._status_cache['enabled'] = bool(enabled)
        self._send_async('set_enabled', {'enabled': bool(enabled)})
        # 同步驱动侧写前影子开关（轻量 ioctl，保留在主进程）
        try:
            self._push_shadow_config()
        except Exception as e:
            logger.debug(f'切换影子配置失败: {e}')

    def prewarn(self, files=None) -> bool:
        if self._local is not None:
            return bool(self._local.prewarn(files))
        # 低水位预警由 worker 执行重活：fire-and-forget，不阻塞 watchdog 线程
        return self._send_async('prewarn', {'files': list(files or [])})

    def snapshot_now(self, reason: str = 'manual', replace: bool = False) -> dict:
        if self._local is not None:
            return self._local.snapshot_now(reason, replace=replace)
        waiter = self._add_waiter(self._snapshot_waiters)
        try:
            res = self._request('snapshot_now',
                                {'reason': reason, 'replace': bool(replace)},
                                timeout=self._bounded_timeout(300.0))
            if isinstance(res, dict) and res.get('async'):
                # worker 已受理、快照在后台执行（命令循环不被占用，期间的只读命令
                # get_state/get_generations 可正常应答）→ 这里等引擎的完成上报。
                if not waiter['event'].wait(self._bounded_timeout(300.0)):
                    return {'ok': False, 'reason': 'snapshot_timeout'}
                out = dict(waiter['result'] or {'ok': False, 'reason': 'no_report'})
                self._refresh_status_async()
                return out
            if isinstance(res, dict):
                self._refresh_status_async()
                return res
            return {'ok': False, 'reason': 'worker_unavailable'}
        finally:
            self._remove_waiter(self._snapshot_waiters, waiter)

    def trigger_rollback(self, reason: str = 'manual', suspect_paths=None,
                         generation_id=None) -> dict:
        if self._local is not None:
            return self._local.trigger_rollback(
                reason, suspect_paths=suspect_paths, generation_id=generation_id)
        params = {'reason': reason, 'suspect_paths': list(suspect_paths or [])}
        if generation_id is not None:
            params['generation_id'] = generation_id
        waiter = self._add_waiter(self._rollback_waiters)
        try:
            res = self._request('trigger_rollback', params,
                                timeout=self._bounded_timeout(600.0))
            if isinstance(res, dict) and res.get('async'):
                # 回滚在 worker 后台执行（清场/写回/校验可能很久），此处等完成上报；
                # 期间 worker 仍能应答只读命令，UI 不卡。
                if not waiter['event'].wait(self._bounded_timeout(600.0)):
                    return {'ok': False, 'reason': 'rollback_timeout'}
                out = dict(waiter['result'] or {'ok': False, 'reason': 'no_report'})
                self._refresh_status_async()
                return out
            if isinstance(res, dict):
                self._refresh_status_async()
                return res
            return {'ok': False, 'reason': 'worker_unavailable'}
        finally:
            self._remove_waiter(self._rollback_waiters, waiter)

    def get_generations(self) -> list:
        """枚举保留的世代（新→旧）。UI 调用：短超时 + 缓存兜底，不阻塞主线程。"""
        if self._local is not None:
            return self._local.get_generations()
        res = self._request('get_generations', {}, timeout=6.0)
        if isinstance(res, dict):
            gens = list(res.get('generations') or [])
            with self._cache_lock:
                self._generations_cache = gens
            return gens
        with self._cache_lock:
            return list(self._generations_cache)

    def ingest_shadow_backup(self, orig_path, shadow_path,
                             orig_size=0, pid=0) -> bool:
        if self._local is not None:
            return bool(self._local.ingest_shadow_backup(
                orig_path, shadow_path, orig_size, pid))
        # 驱动事件线程调用：异步投递，绝不阻塞事件循环
        return self._send_async('ingest_shadow_backup', {
            'orig_path': orig_path, 'shadow_path': shadow_path,
            'orig_size': int(orig_size or 0), 'pid': int(pid or 0)})

    def ingest_shadow_failure(self, orig_path, status=0, reason=0, pid=0,
                              status_name='', reason_name='') -> bool:
        if self._local is not None:
            return bool(self._local.ingest_shadow_failure(
                orig_path, status, reason, pid, status_name, reason_name))
        return self._send_async('ingest_shadow_failure', {
            'orig_path': orig_path, 'status': int(status or 0),
            'reason': int(reason or 0), 'pid': int(pid or 0),
            'status_name': status_name, 'reason_name': reason_name})

    def get_stats(self) -> dict:
        if self._local is not None:
            return self._local.get_stats()
        # 主线程调用：返回缓存并触发后台刷新，绝不阻塞
        self._refresh_status_async()
        with self._cache_lock:
            return dict(self._status_cache)

    def get_shadow_stats(self) -> dict:
        """写前影子统计（本地计数，驱动侧计数由主进程桥查询）。"""
        if self._local is not None:
            return self._local.get_shadow_stats()
        st = self.get_stats()
        driver = None
        bridge = self._driver_bridge
        if bridge is not None:
            try:
                driver = bridge.query_shadow_stats()
            except Exception:
                driver = None
        return {
            'generation_id': self.generation_id,
            'shadow_backups': st.get('shadow_backups', 0),
            'shadow_no_preimage': st.get('shadow_no_preimage', 0),
            'driver': driver or {},
        }

    def list_records(self, limit: int = 50) -> list:
        if self._local is not None:
            return self._local.list_records(limit)
        res = self._request('list_records', {'limit': int(limit)}, timeout=8.0)
        if isinstance(res, dict):
            return list(res.get('records') or [])
        return []

    def get_protected_dirs(self) -> list:
        if self._local is not None:
            return self._local.get_protected_dirs()
        with self._cache_lock:
            dirs = list(self._protected_dirs)
            ready = self._protected_dirs_ready
        if not ready:
            # 首次查询：主动向 worker 拉取真实生效值（含默认目录解析结果），
            # 避免以空列表造成"保护范围为 0 / 设置页看不到默认目录"的假象。
            res = self._request('get_protected_dirs', {}, timeout=5.0)
            if isinstance(res, dict):
                dirs = list(res.get('dirs') or [])
                with self._cache_lock:
                    self._protected_dirs = list(dirs)
                    self._protected_dirs_ready = True
        return dirs

    def set_protected_dirs(self, dirs) -> list:
        if self._local is not None:
            return self._local.set_protected_dirs(dirs)
        res = self._request('set_protected_dirs', {'dirs': list(dirs or [])},
                            timeout=15.0)
        if isinstance(res, dict):
            out = list(res.get('dirs') or [])
            with self._cache_lock:
                self._protected_dirs = list(out)
                self._protected_dirs_ready = True
                self._status_cache['protected_dirs'] = list(out)
            return out
        return list(self._protected_dirs)

    def get_snapshot_exts(self) -> list:
        if self._local is not None:
            return self._local.get_snapshot_exts()
        with self._cache_lock:
            exts = list(self._snapshot_exts)
        return exts

    def set_snapshot_exts(self, exts) -> list:
        if self._local is not None:
            return self._local.set_snapshot_exts(exts)
        res = self._request('set_snapshot_exts', {'exts': list(exts or [])},
                            timeout=15.0)
        if isinstance(res, dict):
            out = list(res.get('exts') or [])
            with self._cache_lock:
                self._snapshot_exts = list(out)
                self._status_cache['snapshot_exts'] = list(out)
            return out
        return list(self._snapshot_exts)

    def get_max_file_bytes(self) -> int:
        """单文件快照上限（字节）；0 = 不限制。"""
        if self._local is not None:
            return int(self._local.get_max_file_bytes())
        with self._cache_lock:
            cached = self._status_cache.get('max_file_bytes')
        if cached is not None:
            return int(cached)
        res = self._request('get_max_file_bytes', {}, timeout=5.0)
        if isinstance(res, dict):
            v = int(res.get('max_file_bytes') or 0)
            with self._cache_lock:
                self._status_cache['max_file_bytes'] = v
            return v
        return 0

    def set_max_file_mb(self, mb) -> int:
        """按 MB 设置单文件快照上限（0 = 不限制）；返回生效字节数。"""
        if self._local is not None:
            v = int(self._local.set_max_file_mb(mb))
            with self._cache_lock:
                self._status_cache['max_file_bytes'] = v
            return v
        res = self._request('set_max_file_mb', {'max_file_mb': int(mb or 0)},
                            timeout=15.0)
        if isinstance(res, dict):
            v = int(res.get('max_file_bytes') or 0)
            with self._cache_lock:
                self._status_cache['max_file_bytes'] = v
            return v
        return 0

    def reload_config(self, dirs=None, exts=None, enabled=None, kill_all=None,
                      max_file_mb=None) -> dict:
        """把目录/类型/开关/清场开关/单文件上限一次性回灌 worker。

        dirs 为 None/空 时由 worker 回落默认保护目录（六个已知文件夹）；
        返回值里的 dirs 为真实生效值，供代理缓存刷新与 UI 展示。
        max_file_mb：单文件快照上限（MB），0 = 不限制（调整决定 3）。
        """
        if self._local is not None:
            if not dirs:
                # None 或空列表 → 回落默认目录（与 worker 语义一致）
                try:
                    self._local.set_protected_dirs(self._local._resolve_default_dirs())
                except Exception as e:
                    logger.warning(f'降级模式回落默认保护目录失败: {e}')
            else:
                self._local.set_protected_dirs(dirs)
            if exts is not None:
                self._local.set_snapshot_exts(exts)
            if enabled is not None:
                self._local.set_enabled(bool(enabled))
            if kill_all is not None:
                self._local.set_kill_all_before_restore(bool(kill_all))
            if max_file_mb is not None:
                self._local.set_max_file_mb(max_file_mb)
            return {'dirs': self._local.get_protected_dirs(),
                    'exts': self._local.get_snapshot_exts(),
                    'enabled': self._local.is_enabled,
                    'kill_all': self._local.get_kill_all_before_restore(),
                    'max_file_bytes': self._local.get_max_file_bytes(),
                    'generation_id': self._local.generation_id}
        params = {}
        if dirs is not None:
            params['dirs'] = list(dirs)
        if exts is not None:
            params['exts'] = list(exts)
        if enabled is not None:
            params['enabled'] = bool(enabled)
        if kill_all is not None:
            params['kill_all'] = bool(kill_all)
        if max_file_mb is not None:
            params['max_file_mb'] = int(max_file_mb)
        res = self._request('reload_config', params, timeout=20.0)
        if isinstance(res, dict):
            with self._cache_lock:
                if 'dirs' in res:
                    self._protected_dirs = list(res.get('dirs') or [])
                    self._protected_dirs_ready = True
                    self._status_cache['protected_dirs'] = list(self._protected_dirs)
                if 'exts' in res:
                    self._snapshot_exts = list(res.get('exts') or [])
                    self._status_cache['snapshot_exts'] = list(self._snapshot_exts)
                if 'enabled' in res:
                    self._status_cache['enabled'] = bool(res['enabled'])
                if 'kill_all' in res:
                    self._status_cache['kill_all'] = bool(res['kill_all'])
                if 'max_file_bytes' in res:
                    self._status_cache['max_file_bytes'] = int(res['max_file_bytes'] or 0)
                if 'generation_id' in res:
                    self._status_cache['generation_id'] = int(res['generation_id'] or 0)
            return res
        return {'ok': False, 'reason': 'worker_unavailable'}

    def restore_single_file(self, record_id, path: str) -> bool:
        if self._local is not None:
            return bool(self._local.restore_single_file(record_id, path))
        res = self._request('restore_single_file',
                            {'record_id': record_id, 'path': path}, timeout=120.0)
        return bool(isinstance(res, dict) and res.get('ok'))

    def delete_backup(self, hash_or_path: str) -> bool:
        if self._local is not None:
            return bool(self._local.delete_backup(hash_or_path))
        res = self._request('delete_backup', {'hash_or_path': hash_or_path},
                            timeout=60.0)
        return bool(isinstance(res, dict) and res.get('ok'))

    def purge(self) -> int:
        if self._local is not None:
            return int(self._local.purge())
        res = self._request('purge', {}, timeout=120.0)
        return int(res.get('count', 0)) if isinstance(res, dict) else 0

    def _kill_all_non_system(self, reason: str = 'emergency') -> dict:
        """紧急终止（与回滚清场完全同一规则/保护集）。

        历史缺陷：proxy 未暴露该方法，bridge `emergencyTerminateAll` 的
        `callable(getattr(rb, '_kill_all_non_system'))` 探测永远失败 →
        两套 UI 的紧急终止按钮等满 20s 后报"回滚引擎不可用"，**从未真正
        执行过**。方法名保持与引擎一致（下划线前缀），使既有探测直接通过。
        """
        if self._local is not None:
            try:
                return self._local._kill_all_non_system(reason)
            except Exception as e:
                logger.warning(f'降级模式紧急终止执行失败: {e}')
                return {'enabled': True, 'killed': [], 'failed': [],
                        'protected': 0, 'skipped_reason': f'error:{e}'}
        res = self._request('kill_all_non_system',
                            {'reason': str(reason or 'emergency')},
                            timeout=60.0)
        if isinstance(res, dict):
            return res
        # worker 不可用：如实返回（bridge 会记录"终止 0"，绝不伪造成功）
        return {'enabled': True, 'killed': [], 'failed': [], 'protected': 0,
                'skipped_reason': 'worker_unavailable'}

    # ---- 驱动桥 / 写前影子配置（保留在主进程，属轻量 ioctl）----

    def set_driver_bridge(self, bridge) -> bool:
        self._driver_bridge = bridge
        try:
            return self._push_shadow_config()
        except Exception as e:
            logger.debug(f'注入驱动桥后下发影子配置失败: {e}')
            return False

    def _push_shadow_config(self) -> bool:
        bridge = self._driver_bridge
        if bridge is None or not getattr(bridge, 'is_available', False):
            return False
        try:
            from engine.ransomware_rollback import _shadow_base_dir, _shadow_gen_dir
        except Exception:
            return False
        gen = self.generation_id
        try:
            if not self.is_running or not self.is_enabled:
                return bool(bridge.set_shadow_config(False, gen, ''))
            base = _shadow_base_dir()
            try:
                os.makedirs(_shadow_gen_dir(gen), exist_ok=True)
            except Exception:
                pass
            dirs = self.get_protected_dirs()
            return bool(bridge.set_shadow_config(True, gen, base, dirs=dirs))
        except Exception as e:
            logger.warning(f'主进程下发影子配置失败: {e}')
            return False


# 进程退出时尽量回收 worker，避免孤儿进程
_PROXY_REGISTRY = []


def _cleanup_proxies():
    for p in list(_PROXY_REGISTRY):
        try:
            p.stop()
        except Exception:
            pass


atexit.register(_cleanup_proxies)


def create_rollback_manager(**kwargs) -> RollbackWorkerProxy:
    """桥接层统一入口：创建代理并登记退出回收。"""
    proxy = RollbackWorkerProxy(**kwargs)
    _PROXY_REGISTRY.append(proxy)
    return proxy