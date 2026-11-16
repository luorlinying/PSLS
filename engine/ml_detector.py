# PSLS - Project Sertraline Lab Offline Security
# Copyright (C) 2026 璱鸲计划实验室
# SPDX-License-Identifier: GPL-3.0-only
"""Dantrolene V1 机器学习层的开源空实现。

本仓库不包含 Dantrolene V1 的私有实现（模型权重、特征管线与推理代码）。
这里保留与完整版一致的公开接口，使扫描引擎、桥接层与界面能够正常导入并
优雅降级：ML 层始终报告“不可用”，检测由 PE 解析、YARA、模糊哈希与签名库
继续完成。

如果你持有完整版引擎，可将此文件替换为真实实现，或通过环境变量/插件方式
注入自有引擎；上游接口约定见各方法的 docstring。
"""

from __future__ import annotations

import os
from typing import Any, List, Optional, Tuple

ML_ENGINE_NOTICE = (
    "Dantrolene V1 私有引擎未包含在此开源构建中；"
    "ML 层已降级为空实现，判定由 PE 解析 / YARA / 模糊哈希 / 签名库完成。"
)

__all__ = [
    "ML_ENGINE_NOTICE",
    "MLFeatureExtractor",
    "MLMalwareDetector",
    "enable_scan_worker_mode",
    "run_worker_main",
]


def enable_scan_worker_mode() -> None:
    """完整版用于把扫描器切换到 MLWorker 子进程模式；开源构建无操作。"""


def run_worker_main() -> None:
    """完整版的 MLWorker 入口；开源构建没有可运行的推理进程。"""
    raise SystemExit(ML_ENGINE_NOTICE)


def _get_model_dir() -> str:
    """返回模型目录约定位置（供界面显示路径；开源构建中通常为空）。"""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "models")


def _reset_dependency_cache() -> None:
    """完整版用于重置 onnxruntime/numpy 的探测缓存；开源构建无操作。"""


class MLFeatureExtractor:
    """特征提取接口占位。

    完整版返回 2381 维 EMBER 风格特征向量；开源构建返回 ``None``，
    调用方应把结果视为“特征不可用”。
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._chunk_size_kb = 4096

    def set_chunk_size_kb(self, kb: int) -> None:
        self._chunk_size_kb = int(kb)

    def extract(self, file_path: str) -> Optional[List[float]]:
        return None


class MLMalwareDetector:
    """ML 检测器接口占位：始终不可用，不产生任何判定。"""

    def __init__(self, defer_worker: bool = False, on_ready: Any = None,
                 *args: Any, **kwargs: Any) -> None:
        self.defer_worker = bool(defer_worker)
        self.on_ready = on_ready
        # 与完整版对齐的状态属性（桥接层与扫描器会直接读取）
        self.available = False
        self.any_engine_available = False
        self.main_engine_available = False
        self._enabled = False
        self._brewtotal_enabled = False
        self._strict_mode = False

    # ---- 状态 ----
    def get_status(self) -> dict:
        return {
            "ml_available": False,
            "available": False,
            "enabled": self._enabled,
            "main_engine_available": False,
            "any_engine_available": False,
            "brewtotal_available": False,
            "model_found": False,
            "engine": "Dantrolene V1 (not included)",
            "reason": ML_ENGINE_NOTICE,
            "messages": [ML_ENGINE_NOTICE],
        }

    def main_unavailable_reason(self) -> str:
        return ML_ENGINE_NOTICE

    # ---- 开关 ----
    def set_enabled(self, enabled: bool) -> None:
        self._enabled = bool(enabled)

    def set_brewtotal_enabled(self, enabled: bool) -> None:
        self._brewtotal_enabled = bool(enabled)

    def set_strict_mode(self, enabled: bool) -> None:
        self._strict_mode = bool(enabled)

    def reload(self) -> bool:
        return False

    def stop(self) -> None:
        return None

    # ---- 推理（全部空实现） ----
    def predict(self, file_path: str,
                features: Optional[List[float]] = None
                ) -> Optional[Tuple[str, float]]:
        return None

    def detect_with_context(self, file_path: str, **context: Any
                            ) -> Optional[Tuple[str, float]]:
        return None

    def detect_with_context_with_source(self, file_path: str, **context: Any
                                        ) -> Tuple[Optional[Tuple[str, float]], str]:
        return None, ""
