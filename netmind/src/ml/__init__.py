"""NetMind AI - Machine Learning and Explainability Layer (Phase 2).

Modular architecture:
- dataset: Preprocessing pipeline (Robust/Standard scaling, imputation, stratified splitting).
- anomaly_detector: Unsupervised Isolation Forest with dynamic threshold calibration.
- attack_classifier: Supervised XGBoost multiclass model classifying DoS, Port Scan, Brute Force, Web Attack.
- traffic_predictor: Time-series rate regression with lagged windows and rolling aggregations.
- explainer: TreeSHAP integration generating human-readable SOC reasoning sentences.
- train_all: Full pipeline orchestration and model artifact serialization.
"""

from netmind.src.ml.anomaly_detector import (
    AnomalyDetectionResult,
    NetworkAnomalyDetector,
)
from netmind.src.ml.attack_classifier import (
    ATTACK_CLASS_MAP,
    AttackClassifier,
    EvaluationReport,
)
from netmind.src.ml.dataset import (
    DatasetSplits,
    NetMindPreprocessor,
    prepare_train_val_test_splits,
)
from netmind.src.ml.explainer import (
    FlowExplanation,
    NetMindExplainer,
)
from netmind.src.ml.traffic_predictor import (
    ForecastEvaluationReport,
    NetworkTrafficPredictor,
    TrafficForecastMetrics,
)

__all__ = [
    "DatasetSplits",
    "NetMindPreprocessor",
    "prepare_train_val_test_splits",
    "AnomalyDetectionResult",
    "NetworkAnomalyDetector",
    "ATTACK_CLASS_MAP",
    "AttackClassifier",
    "EvaluationReport",
    "ForecastEvaluationReport",
    "NetworkTrafficPredictor",
    "TrafficForecastMetrics",
    "FlowExplanation",
    "NetMindExplainer",
]
