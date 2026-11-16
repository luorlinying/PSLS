# -*- coding: utf-8 -*-
r"""
TDD - shen du "xun huan sha xiang" wen ti (process_protection.py Sandbox zi xun huan).

Shang yi lun jin deng ji le 【yuan shi exe jue dui lu jing】zuo analyzing huo mian, dan
SandboxAnalyzer.analyze(exe) de zhen shi qi dong lian lu shi:
    shutil.copy2(exe -> %TEMP%/psls_sandbox_<rand>/sample_<pid>_<ts><ext>)
    -> _launch_sandboxed(CreateProcessW(THIS_COPY_PATH, CREATE_SUSPENDED))
    -> Job fen pei -> ResumeThread
Yin ci ETW bao gao de ProcessCreate exe_path = fu ben lu jing, != yuan shi lu jing
-> _is_sandbox_analyzing(fu ben lu jing) False -> zai ci jin ru _sandbox_then_release
-> zai fu zhi dao di er ge psls_sandbox_ mu lu -> san chong xun huan, yong wu zhi jing.

Zai jin yi bu: bei ce yang ben yun xing guo cheng zhong ke neng luo di payload dao
yong hu mu lu/AppData/Local/Temp/payload.exe bing CreateProcessW(payload.exe),
ETW zai ci ming zhong. Zhe pi "sun zi jin cheng" li ying zai sha xiang xing wei jian kong
(psutil/frida) xia bei guan cha, jue bu neng bei wai ceng ProcessProtection you gua
qi + jin ru er ci sha xiang, fou ze Job qian tao shi bai / si suo / qu dong
chong chong zhong zhi.

Ben TDD de san ge shi bai ce shi fu gai:
    A. 【mu lu qian zhuo huo mian】_is_sandbox_analyzing bi xu zhi chi:
       exe startswith yi deng ji de analyzing_dir_prefix
       (li ru gong zuo mu lu C:/Users/xxx/AppData/Local/Temp/psls_sandbox_abc)
       -> gai mu lu xia de fu ben wen jian, zi wen jian, yan sheng luo di wen jian
       dou zi dong huo mian.
    B. 【_sandbox_worker deng ji dir qian zhuo】Zai _sandbox_worker zhong, diao yong
       SandboxAnalyzer.analyze() zhi qian bi xu xian shi chuang jian config.work_dir,
       bing tong guo _mark_sandbox_analyzing_dir(work_dir, ttl) deng ji qian zhuo.
    C. 【PID ji he huo mian】Xin zeng _sandbox_target_pids: deng ji analyzer.analyze
       qi dong de mu biao PID; _check_new_process dui parent_pid zai gai ji he nei
       de jin cheng (zhi xi zi jin cheng) zhi jie huo mian; ji he tiao mu dai TTL
       qing li.
"""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PROC_PROT = os.path.join(ROOT, 'engine', 'process_protection.py')


def read_pp():
    with open(PROC_PROT, 'r', encoding='utf-8') as f:
        return f.read()


class TestSandboxLoopDeepFix(unittest.TestCase):
    # ------------------------------------------------------------------ A -----
    def test_analyzing_exempts_dir_prefix(self):
        src = read_pp()
        # (A1) cun zai dir-prefix deng ji fang fa: _mark_sandbox_analyzing_dir(prefix, ttl)
        self.assertTrue(
            re.search(r"def _mark_sandbox_analyzing_dir\b", src),
            "Que shao _mark_sandbox_analyzing_dir fang fa; wu fa zai analyze "
            "qian ba sha xiang gong zuo mu lu qian zhuo jia ru huo mian, fu ben lu "
            "jing hui bei er ci lan jie dao zhi xun huan sha xiang.")
        # (A2) cun zai dir-prefix qing li fang fa: _unmark_sandbox_analyzing_dir
        self.assertTrue(
            re.search(r"def _unmark_sandbox_analyzing_dir\b", src),
            "Que shao _unmark_sandbox_analyzing_dir; analyzing jie shu hou bu "
            "shi fang qian zhuo hui dao zhi hou xu zheng chang yang ben bei wu huo mian.")
        # (A3) _is_sandbox_analyzing nei bu chu le jing que key pi pei, hai bi xu
        # sao qian zhuo biao: chu xian startswith / dir_prefix yi ji.
        m = re.search(
            r"def _is_sandbox_analyzing\(self, exe.*?:\n(.*?)(?=\n    def |\n    # |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "_is_sandbox_analyzing wei zhao dao")
        body = m.group(1)
        has_prefix = bool(
            re.search(r"startswith\s*\(", body)
            and re.search(r"(?:analyzing_dir|sandbox_analyzing_dir|_dir_prefix)",
                          body)
        ) or bool(re.search(r"_sandbox_analyzing_dirs", body))
        self.assertTrue(
            has_prefix,
            "_is_sandbox_analyzing reng zhi zuo jing que key pi pei. "
            "SandboxAnalyzer ba yang ben fu zhi dao psls_sandbox_* lin shi mu lu "
            "qi dong hou, ETW bao gao de lu jing yu yuan shi exe wan quan bu tong -> "
            "huo mian miss -> xun huan sha xiang. Qing jia ru mu lu qian zhuo biao bing "
            "zai _is_sandbox_analyzing li jian cha exe.startswith(prefix).")

    # ------------------------------------------------------------------ B -----
    def test_sandbox_worker_registers_work_dir_before_analyze(self):
        src = read_pp()
        m = re.search(
            r"def _sandbox_worker\(\):\n(?P<body>.*?)(?=^\s{8}def |\Z)",
            src, re.DOTALL | re.MULTILINE)
        self.assertIsNotNone(m, "Zhao bu dao _sandbox_worker han shu ding yi")
        body = m.group('body')

        # bi xu cun zai: xian shi config.work_dir = ... fu zhi
        self.assertTrue(
            re.search(r"config\.work_dir\s*=\s*\S", body),
            "_sandbox_worker bi xu xian shi she zhi config.work_dir (fou ze wu "
            "fa ti qian zhi dao fu ben luo di mu lu, wu fa deng ji qian zhuo).")

        idx_mark = body.find('_mark_sandbox_analyzing_dir(')
        # 定位【实际调用】analyzer.analyze(exe) 点（带括号），避开注释/文档描述中的文字
        idx_analyze_call = body.find('analyzer.analyze(exe)')
        if idx_analyze_call < 0:
            # 另一种调用：传了 on_progress
            idx_analyze_call = body.find('analyzer.analyze(')
        self.assertGreater(
            idx_mark, -1,
            "worker nei wei diao yong _mark_sandbox_analyzing_dir( deng ji gong "
            "zuo mu lu qian zhuo, fu ben lu jing bi bei zhong lan jie.")
        self.assertGreater(idx_analyze_call, -1,
                           "worker nei zhao bu dao analyzer.analyze diao yong dian")
        self.assertLess(
            idx_mark, idx_analyze_call,
            "_mark_sandbox_analyzing_dir bi xu zai analyzer.analyze(exe) zhi "
            "qian diao yong; xian qi dong zai deng ji hui you jing tai "
            "(CreateProcessW zhi hou ETW ji hu tong bu chu fa).")

    # ------------------------------------------------------------------ C -----
    def test_pid_based_sandbox_descendant_exemption(self):
        """Sun zi jin cheng luo di dao yong hu mu lu/AppData/Local/Temp/xxx.exe
        shi: lu jing wu fa ming zhong gong zuo mu lu qian zhuo, dan ta men de
        【fu PID】bi ran deng yu analyzer qi dong de sha xiang mu biao PID.
        Wei ci xin zeng _sandbox_target_pids ji he + deng ji, _check_new_process
        jian cha parent_pid.
        """
        src = read_pp()
        self.assertTrue(
            re.search(r"_sandbox_target_pids", src),
            "Que shao _sandbox_target_pids; yang ben zai sha xiang zhong sheng "
            "cheng payload.exe bing CreateProcessW(payload.exe) shi, yong hu mu "
            "lu lu jing miss qian zhuo huo mian -> zhong ru.")
        self.assertTrue(
            re.search(r"def _mark_sandbox_target_pid\b", src)
            or re.search(r"_sandbox_target_pids\s*\.add\s*\(", src),
            "Mei you ba sha xiang mu biao PID xie ru _sandbox_target_pids de "
            "luo ji; sun zi jin cheng wu fa tong guo fu PID guan xi shi bie wei "
            "sha xiang nei bu yan sheng.")
        m = re.search(
            r"def _check_new_process\(self,.*?:\n(?P<body>.*?)(?=\n    def |\Z)",
            src, re.DOTALL)
        self.assertIsNotNone(m, "_check_new_process wei zhao dao")
        body = m.group('body')
        # 必须找【实际调用】：self._sandbox_then_release(（带 self. + 括号），
        # 避开注释/文档中的文字描述（如「再进入 _sandbox_then_release →」），
        # 否则注释中的引用会出现在豁免代码之前，导致 early 切片误判。
        idx_str = body.find('self._sandbox_then_release(')
        if idx_str <= 0:
            idx_str = body.find('_sandbox_then_release(')
        if idx_str > 0:
            early = body[:idx_str]
            self.assertTrue(
                bool(re.search(r"_sandbox_target_pids", early))
                or bool(re.search(
                    r"parent_pid\b.*_sandbox_target_pid", early))
                or bool(re.search(r"_is_sandbox_descendant\b", early)),
                "_check_new_process zai diao yong _sandbox_then_release zhi qian "
                "mei you ji yu _sandbox_target_pids de fu PID huo mian pan duan; "
                "sun zi jin cheng jiang bei zai ci gua qi jin ru sha xiang -> si "
                "xun huan / Job qian tao shi bai.")


if __name__ == '__main__':
    unittest.main()
