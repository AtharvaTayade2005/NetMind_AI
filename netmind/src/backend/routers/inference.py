"""NetMind AI - Real-Time ML Inference & Scoring API Router.

Integrates Phase 2 serialized artifacts:
- Preprocessor (RobustScaler & Median Imputer)
- Multiclass Attack Classifier (XGBoost)
- Explainability Layer (TreeSHAP)
- Unsupervised Anomaly Detector (Isolation Forest)
- Decision Engine (Multi-vector Risk Scoring & Rule-based Mitigation Playbooks)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from netmind.src.backend import models
from netmind.src.backend.database import get_db
from netmind.src.backend.decision_engine import DecisionEngine
from netmind.src.backend.repository import (
    AnomalyRepository,
    HostRepository,
    RecommendationRepository,
    RiskScoreRepository,
    SecurityEventRepository,
)
from netmind.src.backend.schemas import (
    AnomalyPredictionResponse,
    AttackPredictionResponse,
    EventSeverity,
    FlowFeaturesInput,
)
from netmind.src.ml.anomaly_detector import NetworkAnomalyDetector
from netmind.src.ml.attack_classifier import ATTACK_CLASS_MAP, AttackClassifier
from netmind.src.ml.dataset import NetMindPreprocessor
from netmind.src.ml.explainer import NetMindExplainer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/predict", tags=["Real-Time ML Inference"])


class ModelManager:
    """Singleton cache and loader for Phase 2 serialized model artifacts."""

    _instance: Optional["ModelManager"] = None

    def __init__(self) -> None:
        self.preprocessor: Optional[NetMindPreprocessor] = None
        self.classifier: Optional[AttackClassifier] = None
        self.detector: Optional[NetworkAnomalyDetector] = None
        self.explainer: Optional[NetMindExplainer] = None
        self.is_loaded: bool = False
        self._load_artifacts()

    @classmethod
    def get_instance(cls) -> "ModelManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _find_model_path(self, filename: str) -> Optional[Path]:
        """Search common model directories for serialized joblib file."""
        repo_root = Path(__file__).resolve().parent.parent.parent.parent
        candidates = [
            repo_root / "netmind" / "models" / filename,
            repo_root / "models" / filename,
            Path("netmind/models") / filename,
            Path("models") / filename,
        ]
        for p in candidates:
            if p.is_file():
                return p
        return None

    def _load_artifacts(self) -> None:
        """Load preprocessor, classifier, anomaly detector, and TreeSHAP explainer."""
        try:
            prep_path = self._find_model_path("preprocessor.joblib")
            cls_path = self._find_model_path("attack_classifier.joblib")
            det_path = self._find_model_path("anomaly_detector.joblib")

            if not prep_path or not cls_path or not det_path:
                logger.warning(
                    f"One or more model artifacts missing (prep={prep_path}, cls={cls_path}, det={det_path}). "
                    "Run 'python netmind/src/ml/train_all.py' to generate artifacts."
                )
                return

            logger.info("Loading Phase 2 machine learning artifacts...")
            self.preprocessor = NetMindPreprocessor.load(prep_path)
            self.classifier = AttackClassifier.load(cls_path)
            self.detector = NetworkAnomalyDetector.load(det_path)
            self.explainer = NetMindExplainer(self.classifier)
            self.is_loaded = True
            logger.info("Phase 2 ML models and TreeSHAP explainer loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load ML artifacts: {e}", exc_info=True)


@router.post("/attack", response_model=AttackPredictionResponse)
def predict_attack(
    flow_input: FlowFeaturesInput,
    db: Session = Depends(get_db),
) -> AttackPredictionResponse:
    """Real-time multiclass attack classification with TreeSHAP explanations and decision support."""
    mm = ModelManager.get_instance()
    if not mm.is_loaded or mm.preprocessor is None or mm.classifier is None or mm.explainer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Machine learning model artifacts are not loaded. Run 'python netmind/src/ml/train_all.py' first.",
        )

    # 1. Convert input Pydantic model to single-row DataFrame
    data_dict = flow_input.model_dump(exclude={"src_ip", "dst_ip"})

    # Auto-fill computed rates if omitted
    dur = max(flow_input.duration, 1e-4)
    if data_dict.get("avg_packet_size") is None:
        data_dict["avg_packet_size"] = float(flow_input.byte_count / max(flow_input.packet_count, 1.0))
    if data_dict.get("packets_per_second") is None:
        data_dict["packets_per_second"] = float(flow_input.packet_count / dur)
    if data_dict.get("bytes_per_second") is None:
        data_dict["bytes_per_second"] = float(flow_input.byte_count / dur)
    if data_dict.get("syn_ack_ratio") is None:
        data_dict["syn_ack_ratio"] = float(flow_input.syn_count / (flow_input.ack_count + 1e-5))

    input_df = pd.DataFrame([data_dict])

    # 2. Preprocess with RobustScaler
    scaled_df = mm.preprocessor.transform(input_df)

    # 3. Model Inference (XGBoost)
    pred_class_id = int(mm.classifier.predict(scaled_df)[0])
    pred_class_name = ATTACK_CLASS_MAP.get(pred_class_id, "Unknown")
    probs = mm.classifier.predict_proba(scaled_df)[0]
    confidence = float(probs[pred_class_id])

    prob_map = {ATTACK_CLASS_MAP.get(i, f"Class_{i}"): round(float(p), 4) for i, p in enumerate(probs)}

    # 4. TreeSHAP Explanation Generation
    explanation = mm.explainer.explain_instance(scaled_df, target_class=pred_class_id, top_k=3)
    reasons = explanation.human_readable_reasons

    # 5. Anomaly detector cross-validation score
    anomaly_score = 0.1
    if mm.detector is not None:
        anom_res = mm.detector.predict(scaled_df)
        anomaly_score = float(anom_res.anomaly_scores[0])

    # 6. Decision Engine Composite Risk & Mitigation Action
    src_ip = flow_input.src_ip or "192.168.1.100"
    dst_ip = flow_input.dst_ip or "10.0.0.1"
    dst_port = int(flow_input.dst_port)

    host_repo = HostRepository(db)
    host = host_repo.get_or_create(src_ip)
    is_quarantined = (host.status == "quarantined")

    risk_res = DecisionEngine.evaluate_flow_risk(
        attack_type=pred_class_name,
        confidence=confidence,
        anomaly_score=anomaly_score,
        bytes_per_sec=data_dict["bytes_per_second"],
        packets_per_sec=data_dict["packets_per_second"],
        is_quarantined_host=is_quarantined,
    )

    mitigations = DecisionEngine.generate_recommendations(
        attack_type=pred_class_name,
        confidence=confidence,
        risk_result=risk_res,
        source_ip=src_ip,
        destination_ip=dst_ip,
        dst_port=dst_port,
    )
    primary_mitigation = mitigations[0] if mitigations else None
    action_str = primary_mitigation.action_str if primary_mitigation else "MONITOR_BASELINE"
    reason_str = primary_mitigation.reason if primary_mitigation else "Nominal baseline activity."

    # 7. Persistence: Update host risk, create security event if attack detected
    host_repo.update_risk(host.id, risk_res.overall_score)
    RiskScoreRepository(db).create(
        host_id=host.id,
        security_score=risk_res.security_risk,
        anomaly_score=risk_res.anomaly_score,
        performance_score=risk_res.performance_risk,
        overall_score=risk_res.overall_score,
    )

    if pred_class_name != "Normal":
        sev = EventSeverity.HIGH if risk_res.overall_score > 70 else EventSeverity.MEDIUM
        if risk_res.overall_score > 85:
            sev = EventSeverity.CRITICAL

        event = SecurityEventRepository(db).create(
            source_ip=src_ip,
            destination_ip=dst_ip,
            event_type=pred_class_name,
            severity=sev.value,
            confidence=confidence,
            description=f"{pred_class_name} detected with {confidence:.1%} confidence. {'; '.join(reasons)}",
        )

        if primary_mitigation and primary_mitigation.requires_human_approval:
            RecommendationRepository(db).create(
                event_id=event.id,
                action=action_str,
                reason=reason_str,
                status="pending",
            )

    return AttackPredictionResponse(
        predicted_class_id=pred_class_id,
        predicted_class_name=pred_class_name,
        confidence=round(confidence, 4),
        class_probabilities=prob_map,
        top_explainability_reasons=reasons,
        risk_score=risk_res.overall_score,
        risk_category=risk_res.risk_category,
        recommended_action=action_str,
        recommendation_reason=reason_str,
    )


@router.post("/anomaly", response_model=AnomalyPredictionResponse)
def predict_anomaly(
    flow_input: FlowFeaturesInput,
    db: Session = Depends(get_db),
) -> AnomalyPredictionResponse:
    """Real-time zero-day anomaly detection using Unsupervised Isolation Forest."""
    mm = ModelManager.get_instance()
    if not mm.is_loaded or mm.preprocessor is None or mm.detector is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Anomaly detector model artifacts are not loaded. Run 'python netmind/src/ml/train_all.py' first.",
        )

    data_dict = flow_input.model_dump(exclude={"src_ip", "dst_ip"})
    dur = max(flow_input.duration, 1e-4)
    if data_dict.get("avg_packet_size") is None:
        data_dict["avg_packet_size"] = float(flow_input.byte_count / max(flow_input.packet_count, 1.0))
    if data_dict.get("packets_per_second") is None:
        data_dict["packets_per_second"] = float(flow_input.packet_count / dur)
    if data_dict.get("bytes_per_second") is None:
        data_dict["bytes_per_second"] = float(flow_input.byte_count / dur)
    if data_dict.get("syn_ack_ratio") is None:
        data_dict["syn_ack_ratio"] = float(flow_input.syn_count / (flow_input.ack_count + 1e-5))

    input_df = pd.DataFrame([data_dict])
    scaled_df = mm.preprocessor.transform(input_df)

    res = mm.detector.predict(scaled_df, extract_indicators=True, top_k=3)
    is_anom = bool(res.is_anomaly[0])
    score = float(res.anomaly_scores[0])
    thresh = float(res.threshold)
    indicators = res.top_indicators[0] if res.top_indicators else []

    # If flagged as anomaly, record in database
    if is_anom:
        AnomalyRepository(db).create(
            anomaly_score=round(score, 4),
            model_version="iso_forest_v1",
            status="open",
        )

    return AnomalyPredictionResponse(
        is_anomaly=is_anom,
        anomaly_score=round(score, 4),
        calibrated_threshold=round(thresh, 4),
        requires_investigation=is_anom,
        top_behavioral_indicators=indicators,
    )
