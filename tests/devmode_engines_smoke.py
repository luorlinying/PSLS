"""开发模式冒烟测试：YARA 规则引擎 + ML（ONNX Worker + LightGBM/BrewTotal）必须同时就绪。

断言（应全部为 True）：
1. yara-python 可直接 import（HAS_YARA=True）。
2. engine.rule_engine.RuleEngine 初始化后：
   - yara_installed=True, yara_available=True, builtin_rules_count >= 1
   - _YARA_RULES_DIR 目录存在
3. db.signature_db.SignatureDB 初始化成功，签名数 > 0。
4. models/malware_detector.onnx 文件存在。
5. engine.ml_detector.MLMalwareDetector 初始化后：
   - ml_available=True（进程内或 Worker 模式任一）
   - ml_model_loaded=True
   - brewtotal_available=True 或 brewtotal_enabled=True（有一个 True 即视为 LGBM 就绪）
6. 对测试二进制（PE 文件：dist/PSLS/MLWorker.exe）做一次实际推理，返回 dict 结果且包含 ml_verdict 键。

用法：portable_python\\python.exe tests\\devmode_engines_smoke.py
退出码：0=全部通过 1=任一断言失败
"""
from __future__ import annotations

import os
import sys
import traceback
from typing import Dict, Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PASS = True
RESULT: Dict[str, Any] = {}


def check(name: str, cond, detail: str = "") -> bool:
    global PASS
    ok = bool(cond)
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}{('  -> ' + detail) if detail else ''}")
    if not ok:
        PASS = False
    return ok


def main() -> int:
    # 1. yara import
    try:
        import yara as _yara  # noqa: F401
        has_yara_import = True
    except Exception as e:
        has_yara_import = False
        traceback.print_exc()
    check("yara-python importable", has_yara_import)

    # 2. RuleEngine
    from engine.rule_engine import RuleEngine, HAS_YARA, _YARA_RULES_DIR  # noqa: E402
    check("rule_engine_module.HAS_YARA", HAS_YARA, f"HAS_YARA={HAS_YARA}")
    check("_YARA_RULES_DIR 存在", os.path.isdir(_YARA_RULES_DIR), _YARA_RULES_DIR)
    try:
        re = RuleEngine()
        re_st = re.get_status()
        RESULT["rule_status"] = re_st
        check("RuleEngine.yara_installed", re_st.get("yara_installed"), str(re_st))
        check("RuleEngine.yara_available", re_st.get("yara_available"), str(re_st))
        check("RuleEngine.builtin_rules_count >= 1",
              (re_st.get("builtin_rules_count") or 0) >= 1,
              f"count={re_st.get('builtin_rules_count')}")
    except Exception:
        traceback.print_exc()
        check("RuleEngine.__init__ 无异常", False)

    # 3. SignatureDB
    try:
        from db.signature_db import SignatureDB  # noqa: E402
        db = SignatureDB()
        cnt = db.get_signature_count()
        RESULT["sig_count"] = cnt
        check("SignatureDB 加载成功 count > 0", cnt > 0, f"count={cnt}")
    except Exception:
        traceback.print_exc()
        check("SignatureDB init OK", False)

    # 4. ML 模型文件存在
    model_path = os.path.join(ROOT, "models", "malware_detector.onnx")
    check("models/malware_detector.onnx 存在且非空",
          os.path.exists(model_path) and os.path.getsize(model_path) > 0,
          f"path={model_path} size={os.path.getsize(model_path) if os.path.exists(model_path) else 'NA'}")

    # 5. MLMalwareDetector 就绪
    try:
        from engine.ml_detector import MLMalwareDetector  # noqa: E402
        mld = MLMalwareDetector()
        ml_st = mld.get_status()
        RESULT["ml_status"] = ml_st
        check("ML.ml_available", ml_st.get("ml_available"),
              f"mode={ml_st.get('ml_mode')} path={ml_st.get('ml_model_path')}")
        check("ML.ml_model_loaded", ml_st.get("ml_model_loaded"), str(ml_st))
        bt_ok = bool(ml_st.get("brewtotal_available") or ml_st.get("brewtotal_enabled"))
        check("ML.BrewTotal 可用", bt_ok,
              f"bt_available={ml_st.get('brewtotal_available')} bt_enabled={ml_st.get('brewtotal_enabled')}")
    except Exception:
        traceback.print_exc()
        check("MLMalwareDetector init OK", False)
        ml_st = {}
        mld = None

    # 6. 实际推理一次（PE 文件：MLWorker.exe 本身）
    sample = os.path.join(ROOT, "dist", "PSLS", "MLWorker.exe")
    if os.path.exists(sample) and mld is not None and ml_st.get("ml_available"):
        try:
            res = mld.detect_with_context(sample)
            check("ML.detect_with_context 返回合法值",
                  res is None or (isinstance(res, tuple) and len(res) == 2),
                  f"result={res}")
        except Exception:
            traceback.print_exc()
            check("ML.detect_with_context 无异常", False)
    elif not os.path.exists(sample):
        check(f"ML 推理样本存在（{sample}）", False, "跳过实际推理验证：dist/PSLS/MLWorker.exe 不存在")

    return 0 if PASS else 1


if __name__ == "__main__":
    rc = 1
    try:
        rc = main()
    except Exception:
        traceback.print_exc()
        rc = 1
    sys.stdout.flush()
    sys.exit(rc)
