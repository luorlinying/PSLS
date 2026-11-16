"""TDD RED: 启动阶段 BROADCAST 不应在引擎尚未初始化时生成 False 快照或发出 WARNING，
也不应写 _last_yara_state/_last_ml_state 为 False；一旦核心初始化成功，应立即主动广播 true。

断言：
1. 启动日志中不应出现 `[BROADCAST] _scan_engine 或 rule_engine 不可用: engine=None` WARNING。
2. 在引擎（_scan_engine/_ml_detector）尚未准备好时，_last_yara_state / _last_ml_state 必须为 None；
   一旦引擎就绪则可以是 True 快照（不要求写回的具体时间）。
3. 核心初始化完成后，_last_yara_state 里 yara_installed=True；_last_ml_state 里 ml_available=True。
"""
from __future__ import annotations
import os, sys, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QTimer, QEventLoop, Qt
import logging

def main() -> int:
    # 捕获日志
    warns = []
    infos = []
    class _H(logging.Handler):
        def emit(self, record):
            msg = self.format(record)
            if record.levelno >= logging.WARNING:
                warns.append(msg)
            infos.append(msg)
    handler = _H()
    handler.setFormatter(logging.Formatter('%(message)s'))
    logging.getLogger('psls').addHandler(handler)
    logging.getLogger('psls').setLevel(logging.DEBUG)
    # bridge 模块 logger
    import ui.webview.bridge as _bmod
    bmod_logger = getattr(_bmod, 'logger', None)
    if bmod_logger is not None:
        bmod_logger.addHandler(handler)
        bmod_logger.setLevel(logging.DEBUG)

    app = QApplication(sys.argv)
    from ui.webview.bridge import PyBridge
    b = PyBridge(None)
    states = []

    def flush(t=40):
        loop = QEventLoop()
        QTimer.singleShot(t, loop.quit)
        loop.exec_()

    def snap(when):
        states.append({
            'when': when,
            '_scan_engine': b._scan_engine is not None,
            '_ml_detector': b._ml_detector is not None,
            '_last_yara_state': getattr(b, '_last_yara_state', None),
            '_last_ml_state': getattr(b, '_last_ml_state', None),
            'warn_count_engnone': sum(1 for w in warns if '_scan_engine 或 rule_engine 不可用: engine=None' in w),
        })

    snap('0s')
    # ~0.6s 通常引擎尚未就绪（coreInit 一般 1.2s+ 完成），用于检查 "未就绪时写了 False 快照" 的 bug
    QTimer.singleShot(600, lambda: (snap('0.6s'), flush(10)))
    # 2.5s：coreInit 通常已完成写回
    QTimer.singleShot(2500, lambda: (snap('2.5s'), flush(10)))
    done = {'ok': False}
    def final():
        # 强制 broadcast 再跑一次（主动触发 _broadcast_state_changes）
        b._broadcast_state_changes()
        flush(20)
        snap('final')
        done['ok'] = True
        QApplication.quit()
    QTimer.singleShot(5500, final)
    app.exec_()

    print(json.dumps(states, ensure_ascii=False, indent=2, default=str))

    # 断言
    ok = True
    # (1) 警告
    bad_warns = [w for w in warns if '[BROADCAST] _scan_engine 或 rule_engine 不可用: engine=None' in w]
    if bad_warns:
        print("ASSERT FAIL: 出现不期望的 WARNING（启动阶段 engine=None 不应作为 WARNING 刷屏/留痕）：")
        for w in bad_warns: print(' -', w)
        ok = False

    def _is_false_yara(s):
        """是否为无效 YARA False 快照：installed/available/direct 全为 False 且不是 None。"""
        if s is None:
            return False
        true_flags = (bool(s.get('yara_installed')) or bool(s.get('yara_available'))
                      or bool(s.get('yara_direct')) or bool(s.get('yara_rules_dir'))
                      or bool(s.get('builtin_rules_count')))
        return not true_flags

    def _is_false_ml(s):
        if s is None:
            return False
        return not (bool(s.get('ml_available')) or bool(s.get('ml_model_loaded'))
                    or bool(s.get('ml_onnx_installed')))

    # (2) 所有快照：如果当时引擎尚未 ready，则 last 状态必须是 None，不能是 False 快照；
    #     若引擎已 ready，则允许写回 True 快照（不做严格时间约束，取决于机器 I/O）。
    for s in states:
        if not s['_scan_engine'] and _is_false_yara(s['_last_yara_state']):
            print(f"ASSERT FAIL: {s['when']} 时 _scan_engine 尚为 False，但 _last_yara_state 被写入无效 False 快照: {s['_last_yara_state']}")
            ok = False
        if not s['_ml_detector'] and _is_false_ml(s['_last_ml_state']):
            print(f"ASSERT FAIL: {s['when']} 时 _ml_detector 尚为 False，但 _last_ml_state 被写入无效 False 快照: {s['_last_ml_state']}")
            ok = False

    # (3) 完成时引擎必须 ready，且 last 状态必须为有效 True
    sf = next((s for s in states if s['when'] == 'final'), None)
    if sf is None or not sf['_scan_engine']:
        print("ASSERT FAIL: final 时 _scan_engine 仍 None → coreInit 链路失败")
        ok = False
    else:
        yara = sf['_last_yara_state'] or {}
        ml = sf['_last_ml_state'] or {}
        if not (yara.get('yara_installed') and yara.get('yara_available')):
            print(f"ASSERT FAIL: final _last_yara_state 不是有效 True 状态: {yara}")
            ok = False
        if not ml.get('ml_available'):
            print(f"ASSERT FAIL: final _last_ml_state 不是有效 True 状态: {ml}")
            ok = False

    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())
