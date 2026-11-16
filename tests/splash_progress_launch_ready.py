"""TDD RED → GREEN: 启动进度真实对齐 + Splash 直到 launchReady 才关闭 + 防护/驱动状态进入最近活动。

断言：
1) PyBridge 有信号 launchProgressUpdated(int, str) 与 launchReady()
2) 10s 内（慢机器上防护模块初始化同步阻塞）必须满足：
   - 最终 pct == 100
   - launchReady 在 (ui_ready==True) 且 (最终 pct >= 100) 之后才触发
   - 进度序列严格单调不减（不允许回退）
3) 最近活动里至少包含（每条匹配 source+关键字）：
   - "病毒库" 含 "加载" + "签名"
   - "系统" 含 "核心管理器初始化完成"
   - 防护逐项：进程保护 / 文件保护 / 系统保护 / 自启动监测 / 实时防护 / 自我保护 / 通知管理  每个都有 1+ 条
   - "驱动防护" 1+ 条（含"内核/DACL/未加载/已加载"任一关键字）
"""
from __future__ import annotations
import os, sys, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QTimer, QEventLoop

def main() -> int:
    app = QApplication(sys.argv)
    from ui.webview.bridge import PyBridge
    # (1) 信号存在检查
    assert hasattr(PyBridge, 'launchProgressUpdated'), "MISSING SIGNAL: PyBridge.launchProgressUpdated"
    assert hasattr(PyBridge, 'launchReady'), "MISSING SIGNAL: PyBridge.launchReady"
    b = PyBridge(None)

    progress_events = []       # list[(pct:int, stage:str)]
    ready_fired = {'pct': None, 'ui_ready_at_pct': None, 'ui_ready_fired_before_ready': None}

    # 连接信号
    def on_prog(p, t):
        p = int(p)
        if progress_events and progress_events[-1][0] == p and progress_events[-1][1] == t:
            return
        progress_events.append((max(0, min(100, p)), str(t)))
    b.launchProgressUpdated.connect(on_prog)

    def on_ready():
        ready_fired['pct'] = progress_events[-1][0] if progress_events else None
        ready_fired['ui_ready_at_pct'] = (
            progress_events[-1][0] if progress_events else None
        )
        ready_fired['ui_ready_fired_before_ready'] = bool(getattr(b, '_ui_ready', False))
        # 立即抓活动列表
        ready_fired['activities_snapshot'] = [dict(a) for a in list(getattr(b, '_activity_buffer', []) or [])]
        # launchReady 触发即结束（允许再 pump 少许事件让信号/日志完全落盘）
        QTimer.singleShot(120, QApplication.quit)
    b.launchReady.connect(on_ready)

    # 补齐 PyBridge 启动早期可能错过的启动进度信号（_pending_launch_progress flush）
    if hasattr(b, 'flush_launch_progress'):
        try: b.flush_launch_progress()
        except Exception: pass

    def flush(t=40):
        loop = QEventLoop()
        QTimer.singleShot(t, loop.quit)
        loop.exec_()

    for _ in range(3):
        flush()

    # 结束策略：
    #   a) launchReady 触发 → 立即结束（首选，快机器 ~4s）
    #   b) 兜底：10s 强制结束（慢机器 + 驱动判定 6s 窗口上限）
    done = {'v': False}
    final = {'activities': []}
    def final_cb():
        # 再抓一次最终活动快照
        final['activities'] = [dict(a) for a in list(getattr(b, '_activity_buffer', []) or [])]
        done['v'] = True
        QApplication.quit()
    QTimer.singleShot(10000, final_cb)
    app.exec_()

    # 若兜底触发导致 activities 仍为空，再取一次
    if not final['activities']:
        final['activities'] = [dict(a) for a in list(getattr(b, '_activity_buffer', []) or [])]

    result = {
        'progress_events_cnt': len(progress_events),
        'progress_first_pct': progress_events[0][0] if progress_events else None,
        'progress_final_pct': progress_events[-1][0] if progress_events else None,
        'progress_tail': progress_events[-10:],
        'ready_fired_pct': ready_fired.get('pct'),
        'ready_fired_after_ui_ready': ready_fired.get('ui_ready_fired_before_ready'),
        'monotonic': (
            all(progress_events[i][0] <= progress_events[i+1][0]
                for i in range(len(progress_events)-1)) if progress_events else True
        ),
        'activities_final_count': len(final['activities']),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))

    ok = True

    # (2) 最终 pct == 100
    if result['progress_final_pct'] != 100:
        print(f"ASSERT FAIL progress_final_pct={result['progress_final_pct']}, 期望 100")
        ok = False

    # 单调不减
    if not result['monotonic']:
        print("ASSERT FAIL 进度出现回退（非单调）")
        ok = False

    # ready 信号已触发
    if result['ready_fired_pct'] is None:
        print("ASSERT FAIL launchReady 未触发")
        ok = False
    else:
        # 触发时 pct 必须 >=100
        if result['ready_fired_pct'] < 100:
            print(f"ASSERT FAIL launchReady 触发过早(pct={result['ready_fired_pct']})，必须在 100% 后")
            ok = False
        # 触发时 ui_ready 必须 True
        if not result['ready_fired_after_ui_ready']:
            print("ASSERT FAIL launchReady 触发时 _ui_ready 仍 False")
            ok = False

    # (3) 活动日志
    acts = final['activities'] or (ready_fired.get('activities_snapshot') or [])
    def has(src_kw=None, msg_kw=None):
        for a in acts:
            s = a.get('source',''); m = a.get('message','')
            if src_kw and src_kw not in s: continue
            if msg_kw and msg_kw not in m: continue
            return True
        return False

    checks = [
        ('病毒库-加载签名', has('病毒库', '加载') and has('病毒库', '签名')),
        ('核心管理器初始化完成', has('系统', '核心管理器初始化完成')),
        ('进程保护', has('进程保护')),
        ('文件保护', has('文件保护')),
        ('系统保护', has('系统保护')),
        ('自启动监测', has('自启动监测')),
        ('实时防护', has('实时防护')),
        ('自我保护', has('自我保护')),
        ('通知管理', has('通知管理')),
    ]
    for name, val in checks:
        if not val:
            print(f"ASSERT FAIL 最近活动缺少: {name}")
            ok = False
    # 驱动防护至少 1 条（关键字：内核/DACL/未加载/已加载 任一）
    drv_ok = False
    for a in acts:
        if a.get('source') == '驱动防护':
            m = a.get('message','')
            if any(k in m for k in ['内核','DACL','未加载','已加载','未启用','激活','降级','不可用']):
                drv_ok = True; break
    if not drv_ok:
        print("ASSERT FAIL 最近活动缺少 驱动防护 状态记录（带内核/DACL/已加载/未加载 等关键字）")
        ok = False

    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())
