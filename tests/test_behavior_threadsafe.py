# -*- coding: utf-8 -*-
"""
TDD 测试: BehaviorAnalyzer 线程安全 & 内存上限

- 并发喂事件不抛异常、条目不超上限
- evaluate 并发读安全
"""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.behavior_analyzer import BehaviorAnalyzer  # noqa: E402


class TestBehaviorThreadsafe(unittest.TestCase):

    def test_concurrent_feeds_no_crash_and_capped(self):
        ba = BehaviorAnalyzer(window=30.0)
        errors = []

        def feeder(start, count):
            try:
                for i in range(count):
                    pid = start + (i % 20)
                    ba.feed_process_start(pid, f'p{pid}.exe', f'C:\\Users\\T\\p{pid}.exe')
                    ba.feed_file_write(pid, r'C:\Windows\System32\w.exe')
                    ba.feed_reg_persist(pid, r'...\CurrentVersion\Run')
                    ba.feed_handle_audit(pid, 9999, 0x414)
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=feeder, args=(1000 + i * 100, 200))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

        # 单 PID 事件不超上限
        pid = 1
        for _ in range(300):
            ba.feed_file_write(pid, r'C:\Windows\System32\w.exe')
        with ba._lock:
            m = ba._per_pid[pid]
            self.assertLessEqual(len(m['writes']), ba.MAX_PER_PID_EVENTS)

    def test_evaluate_concurrent_read(self):
        ba = BehaviorAnalyzer(window=30.0)
        pid = 42
        ba.feed_process_start(pid, 'x.exe', r'C:\Users\T\x.exe')
        ba.feed_file_write(pid, r'C:\Windows\System32\a.exe')
        ba.feed_file_write(pid, r'C:\Windows\System32\b.exe')
        ba.feed_reg_persist(pid, r'...\CurrentVersion\Run')
        results = []

        def reader():
            for _ in range(50):
                results.append(ba.evaluate(pid, context={'signed': False}))

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(all(r['behavior_confirmed'] for r in results))


if __name__ == '__main__':
    unittest.main(verbosity=2)