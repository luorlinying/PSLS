"""PyBridge 启动后 YARA/ML 状态快照（延长时间 + 强制事件驱动 flush）。
断言：
- 7.5s 时 getRuleEngineStatus() yara_installed=True, yara_available=True
- 7.5s 时 getMlEngineStatus()  ml_available=True
"""
from __future__ import annotations
import os, sys, json, traceback
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QTimer, QEventLoop

def main() -> int:
    app = QApplication(sys.argv)
    from ui.webview.bridge import PyBridge
    b = PyBridge(None)
    snapshots = []

    def flush():
        """强制排空事件队列"""
        loop = QEventLoop()
        QTimer.singleShot(50, loop.quit)
        loop.exec_()

    def snap(when: str):
        try:
            snapshots.append({
                'when': when,
                '_scan_engine': b._scan_engine is not None,
                '_signature_db': b._signature_db is not None,
                '_ml_detector': b._ml_detector is not None,
                'yara': (lambda r: (json.loads(r) if isinstance(r, str) else r))(b.getRuleEngineStatus()),
                'ml':   (lambda r: (json.loads(r) if isinstance(r, str) else r))(b.getMlEngineStatus()),
            })
        except Exception:
            snapshots.append({'when': when, 'err': traceback.format_exc()})

    final_called = False
    def final():
        nonlocal final_called
        if final_called:
            return
        final_called = True
        for _ in range(4):
            flush()
        snap('7.5s')
        with open(os.path.join(ROOT, 'tests', '_pybridge_status.json'), 'w', encoding='utf-8') as f:
            json.dump(snapshots, f, ensure_ascii=False, indent=2, default=str)
        QApplication.quit()

    snap('0s')
    QTimer.singleShot(500, lambda: (flush(), snap('0.5s')))
    QTimer.singleShot(2500, lambda: (flush(), snap('2.5s')))
    QTimer.singleShot(7500, final)
    app.exec_()
    print(json.dumps(snapshots, ensure_ascii=False, indent=2, default=str))

    # 断言
    last = next((s for s in reversed(snapshots) if 'yara' in s), None)
    ok = True
    if not last:
        print("ASSERT: no yara/ml captured")
        return 1
    yara = last['yara']
    ml = last['ml']
    if not (yara.get('yara_installed') and yara.get('yara_available')):
        print(f"ASSERT FAIL yara: {yara}")
        ok = False
    if not ml.get('ml_available'):
        print(f"ASSERT FAIL ml: {ml}")
        ok = False
    if not last.get('_scan_engine'):
        print(f"ASSERT FAIL _scan_engine not set")
        ok = False
    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())
