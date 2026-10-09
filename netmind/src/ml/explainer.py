r"""NetMind AI - Explainable AI (XAI) Layer via TreeSHAP.

Cybersecurity & Mathematical Rationale:
----------------------------------------
1. The Black-Box Problem in Security Operations Centers (SOC):
   Modern SOC teams handle thousands of alerts daily. When an ML model predicts an attack category
   (e.g., "96% probability of Port Scan"), security analysts cannot take disruptive containment
   actions (quarantining a subnet, severing an enterprise server) without verifiable evidence.
   Unexplained predictions cause analyst mistrust, alert fatigue, and dangerous alert dismissals.

2. Cooperative Game Theory & Shapley Values:
   Formulated by Lloyd Shapley (Nobel Prize, 1953), Shapley values provide the unique mathematical
   framework that fairly distributes a total payout among collaborating coalition members.
   In machine learning:
   - Players = Input telemetry features F = {x_1, x_2, ..., x_M}
   - Payout = Model prediction f(x) minus expected baseline prediction E[f(x)]
   The marginal attribution phi_i for feature i across all possible subsets S subseteq F \ {i} is:
       phi_i = sum_{S subseteq F \ {i}} [ |S|! * (|F| - |S| - 1)! / |F|! ] * [ f(S union {i}) - f(S) ]

3. TreeSHAP Computational Breakthrough:
   While model-agnostic KernelSHAP scales exponentially (O(2^|F|)), TreeSHAP (Lundberg et al., 2020)
   computes exact Shapley values in polynomial time:
       O(T * L * D^2)
   where T is the number of trees, L is the maximum number of leaves, and D is the maximum tree depth.
   It optimizes computation by recursively tracking the proportion of training paths through tree nodes.

4. Mathematical Axioms Guaranteed by Shapley Values:
   - Efficiency (Local Accuracy): sum_{i=1}^M phi_i(x) = f(x) - E[f(x)]
   - Missingness: If feature i has zero effect across all coalitions, phi_i = 0.
   - Monotonicity: Increasing a feature's marginal contribution cannot decrease its attribution.
   - Symmetry: Features with identical marginal contributions receive identical credit.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
import shap

from netmind.src.ml.attack_classifier import ATTACK_CLASS_MAP, AttackClassifier

logger = logging.getLogger(__name__)

# Feature humanizing templates for SOC analyst reporting
FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "syn_ack_ratio": "SYN/ACK ratio",
    "packets_per_second": "packets per second rate",
    "bytes_per_second": "bandwidth consumption (bytes/sec)",
    "duration": "flow connection duration",
    "packet_count": "total packet volume",
    "byte_count": "total byte volume",
    "avg_packet_size": "average packet size",
    "unique_destinations": "distinct destination IP targets",
    "failed_connections": "failed connection attempts",
    "failed_conn_ratio": "ratio of failed connections",
    "unique_dest_ports": "unique destination ports probed",
    "is_failed_connection": "connection termination failure flag",
    "is_dst_well_known_port": "well-known destination service port",
    "is_src_private_ip": "private RFC 1918 source subnet",
    "is_dst_private_ip": "private RFC 1918 destination subnet",
    "proto_tcp": "TCP transport protocol",
    "proto_udp": "UDP transport protocol",
    "proto_icmp": "ICMP transport protocol",
    "dst_port": "destination service port",
}


@dataclass
class FlowExplanation:
    """Structured explanation artifact for a single network flow classification."""

    predicted_class_id: int
    predicted_class_name: str
    class_probability: float
    base_value: float
    feature_attributions: Dict[str, float]
    human_readable_reasons: List[str]
    raw_shap_values: np.ndarray


class NetMindExplainer:
    """Explainability engine for attack classifications powered by TreeSHAP."""

    def __init__(
        self,
        classifier: AttackClassifier,
        feature_names: Optional[List[str]] = None,
    ) -> None:
        """Initialize the TreeSHAP explainer.

        Args:
            classifier: Fitted AttackClassifier instance.
            feature_names: Optional explicit list of feature names.
        """
        if not classifier._is_fitted or classifier.model is None:
            raise ValueError("AttackClassifier must be fitted before initializing NetMindExplainer.")

        self.classifier = classifier
        self.feature_names = feature_names or classifier.feature_names_

        logger.info("Initializing TreeSHAP TreeExplainer for XGBoost ensemble...")
        # TreeExplainer calculates exact Shapley values natively from tree structures
        self.explainer = shap.TreeExplainer(self.classifier.model)
        logger.info("TreeSHAP explainer successfully initialized.")

    def explain_instance(
        self,
        x_vector: Union[pd.DataFrame, pd.Series, np.ndarray],
        target_class: Optional[int] = None,
        top_k: int = 4,
    ) -> FlowExplanation:
        """Generate local Shapley feature attribution for a single network flow vector.

        Args:
            x_vector: 1D or single-row 2D flow feature vector.
            target_class: Optional attack class ID to explain. If None, explains the model's
                highest-probability predicted class.
            top_k: Number of top driving factors to format into human-readable strings.

        Returns:
            FlowExplanation: Comprehensive explanation object containing SHAP values and SOC reasons.
        """
        # Format input vector as 2D numpy array with 1 row
        if isinstance(x_vector, pd.Series):
            feat_values = x_vector.to_numpy().reshape(1, -1)
            row_df = x_vector.to_frame().T
        elif isinstance(x_vector, pd.DataFrame):
            feat_values = x_vector.iloc[0:1].to_numpy()
            row_df = x_vector.iloc[0:1]
        else:
            feat_values = np.asarray(x_vector).reshape(1, -1)
            row_df = pd.DataFrame(feat_values, columns=self.feature_names)

        # 1. Compute Model Predictions
        probs = self.classifier.predict_proba(feat_values)[0]
        pred_class_id = int(np.argmax(probs)) if target_class is None else target_class
        pred_class_name = ATTACK_CLASS_MAP.get(pred_class_id, f"Class_{pred_class_id}")
        class_prob = float(probs[pred_class_id])

        # 2. Compute TreeSHAP attributions
        # shap_values shape for multiclass: (num_samples, num_features, num_classes) or list
        shap_raw = self.explainer.shap_values(feat_values)

        if isinstance(shap_raw, list):
            # List of (n_samples, n_features) per class
            class_shap = shap_raw[pred_class_id][0]
        elif isinstance(shap_raw, np.ndarray) and len(shap_raw.shape) == 3:
            # (n_samples, n_features, n_classes)
            class_shap = shap_raw[0, :, pred_class_id]
        else:
            # Binary or flat array
            class_shap = shap_raw[0]

        # Base value (expected output across baseline dataset)
        expected_val = self.explainer.expected_value
        if isinstance(expected_val, (list, np.ndarray)):
            base_val = float(expected_val[pred_class_id])
        else:
            base_val = float(expected_val)

        # 3. Map features to their attributions
        feature_attributions: Dict[str, float] = {}
        for idx, col in enumerate(self.feature_names):
            feature_attributions[col] = float(class_shap[idx])

        # 4. Generate human-readable reason strings
        reasons = self._generate_human_reasons(
            row_df=row_df,
            attributions=feature_attributions,
            pred_class_name=pred_class_name,
            top_k=top_k,
        )

        return FlowExplanation(
            predicted_class_id=pred_class_id,
            predicted_class_name=pred_class_name,
            class_probability=round(class_prob, 4),
            base_value=round(base_val, 4),
            feature_attributions=feature_attributions,
            human_readable_reasons=reasons,
            raw_shap_values=class_shap,
        )

    def explain_batch(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        top_k: int = 3,
    ) -> List[FlowExplanation]:
        """Generate explanations for a batch of network flow vectors."""
        if isinstance(X, pd.DataFrame):
            df = X
        else:
            df = pd.DataFrame(X, columns=self.feature_names)

        explanations: List[FlowExplanation] = []
        for i in range(len(df)):
            exp = self.explain_instance(df.iloc[i : i + 1], top_k=top_k)
            explanations.append(exp)
        return explanations

    def _generate_human_reasons(
        self,
        row_df: pd.DataFrame,
        attributions: Dict[str, float],
        pred_class_name: str,
        top_k: int = 4,
    ) -> List[str]:
        """Translate raw numerical Shapley credits into actionable SOC reason sentences.

        Cybersecurity Rationale:
        Translates raw math (+0.42 SHAP on syn_ack_ratio) into clear language:
        "Abnormal SYN/ACK ratio (+0.42, observed 480.00)"
        """
        # Sort features by absolute SHAP impact (descending)
        sorted_feats = sorted(attributions.items(), key=lambda item: abs(item[1]), reverse=True)

        reasons: List[str] = []
        for feat_name, shap_val in sorted_feats[:top_k]:
            if abs(shap_val) < 1e-4:
                continue

            readable_name = FEATURE_DESCRIPTIONS.get(feat_name, feat_name.replace("_", " "))
            val = float(row_df[feat_name].iloc[0]) if feat_name in row_df.columns else 0.0

            # Sign determines whether feature increases or decreases attack likelihood
            sign_str = f"+{shap_val:.2f}" if shap_val > 0 else f"{shap_val:.2f}"

            if shap_val > 0:
                direction = "Abnormal" if ("ratio" in feat_name or "port" in feat_name) else "Elevated"
                reason_str = (
                    f"{direction} {readable_name} ({sign_str}, observed: {val:,.2f}) "
                    f"pushed classification toward {pred_class_name}"
                )
            else:
                reason_str = (
                    f"Standard {readable_name} ({sign_str}, observed: {val:,.2f}) "
                    f"reduced attack confidence toward Normal"
                )

            reasons.append(reason_str)

        if not reasons:
            reasons.append(f"Classification as {pred_class_name} driven by nominal baseline behavior.")

        return reasons
