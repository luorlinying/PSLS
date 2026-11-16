# -*- coding: utf-8 -*-
"""威胁统一置信评分器

将扫描过程中各引擎产出的异构证据(签名/规则/ML/PE/启发式/API指纹/沙箱/学习引擎)
归一化到同一条 0-100 置信标尺，再按分档阈值映射为 verdict。

设计动机(对齐 exploration 指南的"双阈值/统一标尺"思路)：
- 过去各引擎各自用一套高低阈值做判定，阈值移动易顾此失彼；
- 统一为单标尺后，调试降误报只需调 CONF_* 三个分桶阈值，可控性更强。

仅做"加法"：不重写主判定瀑布，而是在弱证据判定点用本评分器把关——
强证据路径(签名确认、高严重度 YARA、VirusIdentifier 高分、PE 高分)不受影响。
"""

# ========= 分档阈值(0-100)==========
# 严格模式 = 更高敏感度历史陷阱导致误报，故统一后收紧 suspicious 档
CONF_MALWARE = 82.0        # >= 82  -> malware
CONF_SUSPICIOUS = 56.0     # [56, 82) -> suspicious
CONF_CLEAN = 0.0           # < 56   -> clean
CONF_MAX = 100.0

# ========= 确定性证据(直接决定 verdict, 不稀释) =========
# 哈希签名确认 / VirusIdentifier critical 属于"确认型"证据，不去跟弱信号抢权重。
# ========= 弱信号累加(0-100, 各源加分求和) =========
# 弱信号只有叠加到一定量才能跨进 suspicious。设计目标：
#   单条 low / 单条 medium / 单个 ML 中危 -> 不足以判 suspicious (降误报核心)
#   多维度中危叠加(如 2 medium + ML 中危 + PE 中危 + ApiHash) -> 判 suspicious
_GAIN_RULE_YARA_HIGH = 40.0
_GAIN_RULE_HIGH = 32.0
_GAIN_RULE_MEDIUM = 16.0
_GAIN_RULE_LOW = 6.0
_GAIN_ML_MALWARE = 70.0  # 乘 ml_malware_prob(0-1)（回退引擎加权语义，仅非主引擎）
_GAIN_ML_SUSP = 40.0     # 乘 ml_susp_prob(0-1)（回退引擎加权语义，仅非主引擎）

# ========= ML 主引擎(LightGBM/EMBER v2)直判阈值 =========
# 主引擎是经本地 A/B 校准的确定性判定源（白样本实测最高仅 0.044），
# 其 verdict 属于"确定性证据"，直接映射到统一标尺、不与弱信号稀释：
#   malware   (p >= 0.70)      -> [82, 100]，p 越高分越高
#   suspicious(0.40 <= p < 0.70)-> [56, 82)，按 p 线性映射
# 与之相对，非主引擎(128 维 MLP 回退等)仍走上面的 _GAIN_ML_* 加权语义。
_ML_MAIN_MALWARE_LO = 0.70
_ML_MAIN_SUSP_LO = 0.40
_GAIN_PE = 0.30          # 乘 pe_score(0-100)
_GAIN_API = 18.0         # 乘 api_evidence/45(0-1)
_GAIN_STUDY_MAL = 20.0
_GAIN_STUDY_BENIGN = -18.0
# 行为启发：运行期时间窗事件序列签发。仅"无有效签名 + 非白名单 + 父进程非可信
# 宿主"的进程序列参与计分（minimize FP）。确认级行为规则直接判 malware。
_GAIN_BEHAVIOR = 34.0          # 乘 behavior_chain/100，佐证级叠加
_CONF_BEHAVIOR_CONFIRM = 82.0  # behavior_confirmed -> 直接判 malware


class ThreatScorer:
    """统一置信评分器。纯计算, 无 IO, 便于单测。"""

    def compute_confidence(self, evidence: dict) -> float:
        """由证据字典计算统一置信分(0-100)。

        evidence 约定(值均为归一化 0-100 或布尔):
          signature_mal      bool  : 哈希签名确认为病毒
          signature_benign   bool  : 哈希签名确认白名单(强抑制)
          trusted_signer     bool  : 可信发布者有效签名(强抑制)
          vi_score           float : VirusIdentifier score
          vi_critical        bool  : vi 严重度 critical/high
          rule_high          int   : 命中的 high 规则数
          rule_medium        int   : 命中的 medium 规则数
          rule_low           int   : 命中的 low 规则数
          rule_yara_high     int   : 命中的 high YARA 规则数
          ml_malware_prob    float : ML(回退引擎)判定为 malware 的概率(0-1)，弱信号加权
          ml_susp_prob       float : ML(回退引擎)判定为 suspicious 的概率(0-1)，弱信号加权
          ml_main_verdict    str   : ML 主引擎(LightGBM)直判结果 'malware'|'suspicious'，
                                     属确定性证据，直接决定 verdict(不稀释)
          ml_main_prob       float : ML 主引擎原始概率(0-1)
          pe_score           float : PE 分析总分(0-100)
          api_evidence       float : ApiHash 导入证据分(0-100)
          entropy_high       bool  : 高熵(加壳/加密)
          study              str   : 'benign'|'malicious'|None  学习引擎指纹结论
          behavior_confirmed bool  : 命中确认级行为规则(直接判 malware, 不稀释)
          behavior_chain     float : 行为启发综合置信(0-100), 佐证级叠加

        Returns:
            float 0-100
        """
        if not isinstance(evidence, dict):
            evidence = {}
        e = evidence

        # --- 强抑制：可信签名 / 白名单直接压到最低 --------------
        if e.get('signature_benign') or e.get('trusted_signer'):
            return 5.0

        # --- 确认型证据：直接拉满，不稀释 ------------------------
        if e.get('signature_mal'):
            return 100.0
        if e.get('vi_critical'):
            return 94.0
        # 行为启发确认级(高置信升级规则, 已内部保证"无签名+非白名单+多维度")
        if e.get('behavior_confirmed'):
            return _CONF_BEHAVIOR_CONFIRM

        # --- ML 主引擎直判：确定性证据，直接映射、不稀释 ----------
        # 主引擎(LightGBM/EMBER v2, 2381 维)经本地 A/B 校准，
        # 其 verdict 直接决定统一置信分，避免被 _GAIN_ML_* 的加法上限压制。
        ml_main = self._ml_main_confidence(e)
        if ml_main is not None:
            return ml_main

        # --- 弱信号累加 ------------------------------------------
        score = (
            _GAIN_RULE_YARA_HIGH * int(e.get('rule_yara_high', 0) or 0)
            + _GAIN_RULE_HIGH * int(e.get('rule_high', 0) or 0)
            + _GAIN_RULE_MEDIUM * int(e.get('rule_medium', 0) or 0)
            + _GAIN_RULE_LOW * int(e.get('rule_low', 0) or 0)
            + _GAIN_ML_MALWARE * float(e.get('ml_malware_prob', 0.0) or 0.0)
            + _GAIN_ML_SUSP * float(e.get('ml_susp_prob', 0.0) or 0.0)
            + _GAIN_PE * (float(e.get('pe_score', 0.0) or 0.0))
            + _GAIN_API * (min(45.0, float(e.get('api_evidence', 0.0) or 0.0)) / 45.0)
            + _GAIN_BEHAVIOR * (
                min(100.0, max(0.0, float(e.get('behavior_chain', 0.0) or 0.0))) / 100.0)
        )
        # study-engine 指纹：明确恶性加分，明确良性减分(但不清零其他弱信号)
        study = e.get('study')
        if study == 'malicious':
            score += _GAIN_STUDY_MAL
        elif study == 'benign':
            score += _GAIN_STUDY_BENIGN
        return max(0.0, min(CONF_MAX, score))

    @staticmethod
    def _ml_main_confidence(e: dict) -> float:
        """把 ML 主引擎直判映射为统一置信分；非主引擎证据返回 None。

        - malware   (p >= 0.70)       -> [82, 100]，p 越高分越高
        - suspicious(0.40 <= p < 0.70)-> [56, 82)，按 p 线性映射（上限严格 < 82）
        """
        verdict = e.get('ml_main_verdict')
        if verdict not in ('malware', 'suspicious'):
            return None
        try:
            p = float(e.get('ml_main_prob', 0.0) or 0.0)
        except (TypeError, ValueError):
            p = 0.0
        p = max(0.0, min(1.0, p))

        if verdict == 'malware':
            span = 1.0 - _ML_MAIN_MALWARE_LO
            frac = (p - _ML_MAIN_MALWARE_LO) / span if span > 0 else 1.0
            frac = max(0.0, min(1.0, frac))
            return CONF_MALWARE + (CONF_MAX - CONF_MALWARE) * frac

        span = _ML_MAIN_MALWARE_LO - _ML_MAIN_SUSP_LO
        frac = (p - _ML_MAIN_SUSP_LO) / span if span > 0 else 0.0
        frac = max(0.0, min(1.0, frac))
        score = CONF_SUSPICIOUS + (CONF_MALWARE - CONF_SUSPICIOUS) * frac
        # 上限严格低于 CONF_MALWARE，保证仍落在 suspicious 档
        return min(score, CONF_MALWARE - 0.01)

    def verdict(self, confidence: float, strict: bool = True) -> str:
        """由置信分映射 verdict。"""
        if confidence >= CONF_MALWARE:
            return 'malware'
        if confidence >= CONF_SUSPICIOUS:
            return 'suspicious'
        return 'clean'

    def confirm_suspicious(self, confidence: float) -> bool:
        """是否足以维持 suspicious 档(弱证据路径的下限把关)。"""
        return confidence >= CONF_SUSPICIOUS


_scorer = ThreatScorer()


def compute_confidence(evidence: dict) -> float:
    """模块级便捷入口。"""
    return _scorer.compute_confidence(evidence)


def verdict_from_confidence(confidence: float, strict: bool = True) -> str:
    return _scorer.verdict(confidence, strict)


def confirm_suspicious(confidence: float) -> bool:
    return _scorer.confirm_suspicious(confidence)