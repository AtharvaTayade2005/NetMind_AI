"""NetMind AI - Supervised Multiclass Network Attack Classifier.

Cybersecurity & Mathematical Rationale:
----------------------------------------
1. Why XGBoost for Network Attack Classification?
   Network security telemetry features are non-linear, heterogeneous, and exhibit complex
   feature interactions. For example, a high packet rate is benign during a video stream, but
   a high packet rate coupled with a high SYN/ACK ratio and zero duration is a definitive SYN flood DoS.

   Extreme Gradient Boosting (XGBoost) is optimal for tabular telemetry:
   - Second-Order Taylor Expansion: Incorporates both first-order gradients (g_i) and second-order
     Hessians (h_i) of the cross-entropy loss function to calculate optimal leaf weights:
         w_j* = - (sum_{i in I_j} g_i) / (sum_{i in I_j} h_i + lambda)
   - Built-In Regularization: L1 (alpha) and L2 (lambda) penalties penalize complex trees, preventing
     the model from memorizing noisy transient traffic fluctuations.
   - Softprob Formulation: Calibrates posterior class probabilities P(y = k | x) across all attack vectors.

2. Attack Taxonomy & Operational Significance:
   - Class 0 (Normal): Benign corporate/campus network communications.
   - Class 1 (DoS): High-volume volumetric floods (SYN flood, UDP amplification) intended to exhaust bandwidth/CPU.
   - Class 2 (Port Scan): Reconnaissance sweeps probing for open listening ports across destination IP ranges.
   - Class 3 (Brute Force): Repeated credential stuffing against SSH (22), RDP (3389), or database endpoints.
   - Class 4 (Web Attack): Layer-7 attacks targeting HTTP/HTTPS endpoints (SQL injection, XSS, directory traversal).

3. SOC Operational Trade-offs (Precision vs. Recall):
   - Attack Recall: Maximized to prevent False Negatives (an unflagged DoS or Brute Force compromises operations).
   - Normal Precision: Maximized to eliminate False Positives (preventing SOC alert fatigue).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from xgboost import XGBClassifier

logger = logging.getLogger(__name__)

ATTACK_CLASS_MAP: Dict[int, str] = {
    0: "Normal",
    1: "DoS",
    2: "Port Scan",
    3: "Brute Force",
    4: "Web Attack",
}

CLASS_NAME_TO_ID: Dict[str, int] = {v: k for k, v in ATTACK_CLASS_MAP.items()}


@dataclass
class EvaluationReport:
    """Comprehensive evaluation metrics container for classification."""

    accuracy: float
    macro_f1: float
    weighted_f1: float
    class_metrics: Dict[str, Dict[str, float]]
    confusion_matrix: pd.DataFrame
    raw_report_text: str

    def summary_table(self) -> str:
        """Return formatted summary table for logging and reporting."""
        return self.raw_report_text


class AttackClassifier:
    """Production multiclass attack classifier powered by XGBoost."""

    def __init__(
        self,
        n_estimators: int = 200,
        max_depth: int = 6,
        learning_rate: float = 0.08,
        subsample: float = 0.85,
        colsample_bytree: float = 0.85,
        reg_alpha: float = 0.1,
        reg_lambda: float = 1.0,
        random_state: int = 42,
        n_jobs: int = -1,
    ) -> None:
        """Initialize XGBoost attack classifier.

        Args:
            n_estimators: Number of gradient boosted boosting rounds (trees).
            max_depth: Maximum tree depth. Controls feature interaction complexity.
            learning_rate: Shrinkage factor (eta) applied to leaf weights to prevent overfitting.
            subsample: Subsample ratio of training instances per tree.
            colsample_bytree: Subsample ratio of columns when constructing each tree.
            reg_alpha: L1 regularization term on weights. Encourages sparsity.
            reg_lambda: L2 regularization term on weights. Prevents extreme leaf weights.
            random_state: Deterministic random seed.
            n_jobs: CPU cores for parallel boosting computation (-1 = all available).
        """
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.subsample = subsample
        self.colsample_bytree = colsample_bytree
        self.reg_alpha = reg_alpha
        self.reg_lambda = reg_lambda
        self.random_state = random_state
        self.n_jobs = n_jobs

        self.model: Optional[XGBClassifier] = None
        self.feature_names_: List[str] = []
        self._is_fitted = False

    def fit(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        y: Union[pd.Series, np.ndarray],
        eval_set: Optional[List[Tuple[Union[pd.DataFrame, np.ndarray], Union[pd.Series, np.ndarray]]]] = None,
        early_stopping_rounds: Optional[int] = 15,
        verbose: bool = False,
    ) -> "AttackClassifier":
        """Train multiclass XGBoost classifier on labeled telemetry data.

        Args:
            X: Training features.
            y: Numeric target labels (0 to 4).
            eval_set: Optional validation splits for early stopping.
            early_stopping_rounds: Stop training if validation metric does not improve.
            verbose: Logging verbosity of boosting iterations.

        Returns:
            self
        """
        if isinstance(X, pd.DataFrame):
            self.feature_names_ = list(X.columns)
            X_mat = X.to_numpy()
        else:
            self.feature_names_ = [f"feat_{i}" for i in range(X.shape[1])]
            X_mat = np.asarray(X)

        y_arr = np.asarray(y)

        num_classes = len(ATTACK_CLASS_MAP)

        self.model = XGBClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            subsample=self.subsample,
            colsample_bytree=self.colsample_bytree,
            reg_alpha=self.reg_alpha,
            reg_lambda=self.reg_lambda,
            objective="multi:softprob",
            num_class=num_classes,
            eval_metric="mlogloss",
            random_state=self.random_state,
            n_jobs=self.n_jobs,
            early_stopping_rounds=early_stopping_rounds if eval_set is not None else None,
        )

        formatted_eval_set = None
        if eval_set is not None:
            formatted_eval_set = [
                (
                    e_x.to_numpy() if isinstance(e_x, pd.DataFrame) else np.asarray(e_x),
                    np.asarray(e_y),
                )
                for e_x, e_y in eval_set
            ]

        logger.info(f"Training XGBoost AttackClassifier on {len(X_mat)} samples across {len(self.feature_names_)} features...")
        self.model.fit(
            X_mat,
            y_arr,
            eval_set=formatted_eval_set,
            verbose=verbose,
        )
        self._is_fitted = True
        logger.info("AttackClassifier training complete.")
        return self

    def predict(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Predict discrete attack class IDs (0 to 4) for flow records."""
        if not self._is_fitted or self.model is None:
            raise RuntimeError("AttackClassifier is not fitted. Call fit() first.")
        X_mat = X.to_numpy() if isinstance(X, pd.DataFrame) else np.asarray(X)
        return self.model.predict(X_mat)

    def predict_proba(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Compute calibrated probability distribution over all attack classes."""
        if not self._is_fitted or self.model is None:
            raise RuntimeError("AttackClassifier is not fitted.")
        X_mat = X.to_numpy() if isinstance(X, pd.DataFrame) else np.asarray(X)
        return self.model.predict_proba(X_mat)

    def predict_labels(self, X: Union[pd.DataFrame, np.ndarray]) -> List[str]:
        """Predict human-readable attack category names (e.g. 'Normal', 'DoS', 'Port Scan')."""
        preds = self.predict(X)
        return [ATTACK_CLASS_MAP.get(int(p), f"Unknown({p})") for p in preds]

    def evaluate(
        self,
        X_test: Union[pd.DataFrame, np.ndarray],
        y_test: Union[pd.Series, np.ndarray],
    ) -> EvaluationReport:
        """Generate comprehensive classification metrics report and confusion matrix.

        Returns:
            EvaluationReport: Detailed evaluation metrics including per-class metrics
                and confusion matrix DataFrame.
        """
        y_true = np.asarray(y_test)
        y_pred = self.predict(X_test)

        # Unique labels present
        target_names = [ATTACK_CLASS_MAP[i] for i in sorted(ATTACK_CLASS_MAP.keys())]

        report_dict = classification_report(
            y_true,
            y_pred,
            target_names=target_names,
            output_dict=True,
            zero_division=0,
        )
        report_text = classification_report(
            y_true,
            y_pred,
            target_names=target_names,
            zero_division=0,
        )

        cm = confusion_matrix(y_true, y_pred, labels=sorted(ATTACK_CLASS_MAP.keys()))
        cm_df = pd.DataFrame(
            cm,
            index=[f"True: {name}" for name in target_names],
            columns=[f"Pred: {name}" for name in target_names],
        )

        class_metrics: Dict[str, Dict[str, float]] = {}
        for name in target_names:
            if name in report_dict:
                class_metrics[name] = {
                    "precision": round(float(report_dict[name]["precision"]), 4),
                    "recall": round(float(report_dict[name]["recall"]), 4),
                    "f1_score": round(float(report_dict[name]["f1-score"]), 4),
                    "support": int(report_dict[name]["support"]),
                }

        accuracy = float(report_dict.get("accuracy", 0.0))
        macro_f1 = float(report_dict.get("macro avg", {}).get("f1-score", 0.0))
        weighted_f1 = float(report_dict.get("weighted avg", {}).get("f1-score", 0.0))

        return EvaluationReport(
            accuracy=accuracy,
            macro_f1=macro_f1,
            weighted_f1=weighted_f1,
            class_metrics=class_metrics,
            confusion_matrix=cm_df,
            raw_report_text=report_text,
        )

    def save(self, filepath: Union[str, Path]) -> None:
        """Serialize trained attack classifier artifact to disk via joblib."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        logger.info(f"Saved AttackClassifier artifact to {path}")

    @classmethod
    def load(cls, filepath: Union[str, Path]) -> "AttackClassifier":
        """Load trained attack classifier artifact from disk."""
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Attack classifier artifact not found at {path}")
        classifier = joblib.load(path)
        if not isinstance(classifier, cls):
            raise TypeError(f"Loaded object is of type {type(classifier)}, expected {cls.__name__}")
        logger.info(f"Loaded AttackClassifier artifact from {path}")
        return classifier
