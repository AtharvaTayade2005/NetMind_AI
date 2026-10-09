"""NetMind AI - Unsupervised Network Flow Anomaly Detector.

Cybersecurity & Mathematical Rationale:
----------------------------------------
1. Why Isolation Forest for Zero-Day & Covert Network Flows?
   Supervised intrusion detection models are blind to zero-day attacks and novel exploit techniques
   because their decision boundaries depend strictly on previously observed training signatures.
   Unsupervised density/distance-based detectors (e.g., k-NN, LOF, GMM) scale with O(N^2) complexity,
   making them computationally prohibitive for wire-speed enterprise telemetry streams.

   Isolation Forest (Liu et al.) operates on an orthogonal geometric principle: anomalies are "few and
   different". By recursively applying random axis-aligned hyperplane splits, anomalous flows are isolated
   near the root of decision trees (small path length h(x)). Normal baseline clusters require deep
   recursive partitioning.

2. Path Length & Anomaly Score Formulation:
   Given a dataset of size n, the average path length of unsuccessful searches in a Binary Search Tree is:
       c(n) = 2 * (ln(n - 1) + 0.5772156649) - (2 * (n - 1) / n)
   The anomaly score s for an instance x across an ensemble of t isolation trees is:
       s(x, n) = 2^(-E(h(x)) / c(n))
   - When E(h(x)) -> 0, s -> 1 (High certainty of anomaly / intrusion)
   - When E(h(x)) -> n - 1, s -> 0 (Normal dense traffic)
   - When E(h(x)) -> c(n), s -> 0.5 (Typical baseline behavior)

3. Dynamic Threshold Calibration:
   Rather than relying on arbitrary static cutoffs, NetMind calibrates anomaly thresholds dynamically
   against the empirical percentile distribution (e.g. 95th/99th percentile) of benign enterprise baseline traffic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)


@dataclass
class AnomalyDetectionResult:
    """Structured output for network flow anomaly inference."""

    is_anomaly: np.ndarray
    anomaly_scores: np.ndarray
    raw_scores: np.ndarray
    threshold: float
    top_indicators: Optional[List[List[Dict[str, Any]]]] = None


class NetworkAnomalyDetector:
    """Unsupervised Isolation Forest detector for zero-day and anomalous network flows."""

    def __init__(
        self,
        n_estimators: int = 150,
        contamination: float = 0.05,
        max_samples: Union[int, float, str] = "auto",
        random_state: int = 42,
        n_jobs: int = -1,
    ) -> None:
        """Initialize the anomaly detector.

        Args:
            n_estimators: Number of isolation trees in the ensemble (default: 150).
            contamination: Expected proportion of outliers in baseline dataset (default: 0.05).
            max_samples: Number of samples drawn to train each isolation tree.
            random_state: Deterministic random seed.
            n_jobs: CPU cores for parallel tree isolation (-1 uses all available cores).
        """
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.max_samples = max_samples
        self.random_state = random_state
        self.n_jobs = n_jobs

        self.model: Optional[IsolationForest] = None
        self.feature_names_: List[str] = []
        self.calibrated_threshold_: float = 0.5
        self.baseline_stats_: Dict[str, Dict[str, float]] = {}
        self._is_fitted = False

    def fit(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        feature_names: Optional[List[str]] = None,
        calibrate_percentile: float = 95.0,
    ) -> "NetworkAnomalyDetector":
        """Fit Isolation Forest on baseline network traffic and calibrate dynamic threshold.

        Args:
            X: Baseline feature matrix (ideally representing normal operating telemetry).
            feature_names: Explicit column names if X is a numpy array.
            calibrate_percentile: Empirical percentile of anomaly scores used to establish
                the threshold (e.g. 95.0 for top 5% anomalous boundary).

        Returns:
            self
        """
        if isinstance(X, pd.DataFrame):
            self.feature_names_ = list(X.columns)
            X_mat = X.to_numpy()
        else:
            self.feature_names_ = feature_names or [f"feat_{i}" for i in range(X.shape[1])]
            X_mat = np.asarray(X)

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_samples=self.max_samples,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
        )

        logger.info(f"Fitting IsolationForest on {len(X_mat)} baseline flow vectors...")
        self.model.fit(X_mat)
        self._is_fitted = True

        # Compute empirical baseline statistics for feature deviation attribution
        self._compute_baseline_stats(X_mat)

        # Calibrate dynamic percentile threshold from raw decision function
        raw_scores = self.score_samples(X_mat)
        self.calibrated_threshold_ = float(np.percentile(raw_scores, calibrate_percentile))

        logger.info(
            f"Fitted anomaly detector. Calibrated threshold ({calibrate_percentile}th percentile): "
            f"{self.calibrated_threshold_:.4f}"
        )
        return self

    def score_samples(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Compute continuous anomaly score in [0, 1] where higher = more anomalous.

        Mathematical Rationale:
        Scikit-learn's IsolationForest outputs score_samples as negative anomaly scores:
        lower/negative indicates severe anomaly. We invert and normalize so:
        score = 0.5 - decision_function(X), clipped to [0, 1].
        """
        if not self._is_fitted or self.model is None:
            raise RuntimeError("Anomaly detector is not fitted. Call fit() first.")

        X_mat = X.to_numpy() if isinstance(X, pd.DataFrame) else np.asarray(X)
        # decision_function: positive for inliers, negative for outliers
        dec = self.model.decision_function(X_mat)
        # Shift and scale: typical dec is in [-0.5, +0.5].
        # Invert: anomaly score = 0.5 - dec, mapped safely to [0.0, 1.0]
        anomaly_scores = np.clip(0.5 - dec, 0.0, 1.0)
        return anomaly_scores

    def predict(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        threshold: Optional[float] = None,
        extract_indicators: bool = False,
        top_k: int = 3,
    ) -> AnomalyDetectionResult:
        """Evaluate flow records for anomalous zero-day behaviors.

        Args:
            X: Input network flow feature records.
            threshold: Optional custom score threshold override in [0, 1].
            extract_indicators: If True, computes root-cause behavioral drivers for each anomaly.
            top_k: Number of top driving features to extract per anomalous flow.

        Returns:
            AnomalyDetectionResult: Structured detection output with scores, flags, and drivers.
        """
        if not self._is_fitted:
            raise RuntimeError("Anomaly detector is not fitted.")

        X_mat = X.to_numpy() if isinstance(X, pd.DataFrame) else np.asarray(X)
        scores = self.score_samples(X_mat)
        active_thresh = threshold if threshold is not None else self.calibrated_threshold_
        is_anom = scores >= active_thresh

        indicators = None
        if extract_indicators:
            indicators = self.extract_top_behavioral_indicators(X_mat, is_anom, top_k=top_k)

        return AnomalyDetectionResult(
            is_anomaly=is_anom,
            anomaly_scores=scores,
            raw_scores=scores,
            threshold=active_thresh,
            top_indicators=indicators,
        )

    def extract_top_behavioral_indicators(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        is_anomaly_mask: Optional[np.ndarray] = None,
        top_k: int = 3,
    ) -> List[List[Dict[str, Any]]]:
        """Identify which behavioral features drove the flow to be flagged as anomalous.

        Cybersecurity Rationale:
        In Security Operations Centers (SOC), an unexplained anomaly flag causes alert fatigue.
        This function identifies features with the largest deviation (z-score) from baseline
        normal traffic behavior (e.g. "syn_ack_ratio" 50x above baseline, "bytes_per_second" 10x above normal).

        Args:
            X: Input flow records matrix.
            is_anomaly_mask: Optional boolean mask specifying which records to analyze.
            top_k: Number of top driving features to return per instance.

        Returns:
            List[List[Dict[str, Any]]]: Per-sample ranked list of top driving indicators.
        """
        X_mat = X.to_numpy() if isinstance(X, pd.DataFrame) else np.asarray(X)
        num_samples = len(X_mat)
        all_indicators: List[List[Dict[str, Any]]] = []

        means = np.array([self.baseline_stats_[col]["mean"] for col in self.feature_names_])
        stds = np.array([self.baseline_stats_[col]["std"] for col in self.feature_names_])
        # Prevent division by zero for invariant baseline features
        stds_safe = np.where(stds > 1e-6, stds, 1.0)

        for i in range(num_samples):
            # If mask provided and sample is not anomalous, return empty list
            if is_anomaly_mask is not None and not is_anomaly_mask[i]:
                all_indicators.append([])
                continue

            sample_vals = X_mat[i]
            # Normalized z-score deviation from benign baseline
            z_scores = np.abs((sample_vals - means) / stds_safe)
            top_indices = np.argsort(z_scores)[::-1][:top_k]

            sample_drivers: List[Dict[str, Any]] = []
            for idx in top_indices:
                feat_name = self.feature_names_[idx]
                observed_val = float(sample_vals[idx])
                baseline_mean = float(means[idx])
                z_score = float(z_scores[idx])

                # Direction of deviation
                direction = "elevated" if observed_val > baseline_mean else "suppressed"
                sample_drivers.append({
                    "feature": feat_name,
                    "observed_value": round(observed_val, 4),
                    "baseline_mean": round(baseline_mean, 4),
                    "z_score": round(z_score, 2),
                    "direction": direction,
                    "reason": f"{direction.capitalize()} {feat_name} ({observed_val:.2f} vs baseline {baseline_mean:.2f}, z={z_score:.1f})",
                })
            all_indicators.append(sample_drivers)

        return all_indicators

    def _compute_baseline_stats(self, X_mat: np.ndarray) -> None:
        """Compute mean, std, median, and IQR for each feature across baseline training set."""
        means = np.mean(X_mat, axis=0)
        stds = np.std(X_mat, axis=0)
        medians = np.median(X_mat, axis=0)
        q75 = np.percentile(X_mat, 75, axis=0)
        q25 = np.percentile(X_mat, 25, axis=0)
        iqrs = q75 - q25

        for i, col in enumerate(self.feature_names_):
            self.baseline_stats_[col] = {
                "mean": float(means[i]),
                "std": float(stds[i]),
                "median": float(medians[i]),
                "iqr": float(iqrs[i]),
            }

    def save(self, filepath: Union[str, Path]) -> None:
        """Serialize trained anomaly detector artifact to disk."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        logger.info(f"Saved NetworkAnomalyDetector artifact to {path}")

    @classmethod
    def load(cls, filepath: Union[str, Path]) -> "NetworkAnomalyDetector":
        """Load trained anomaly detector artifact from disk."""
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Anomaly detector artifact not found at {path}")
        detector = joblib.load(path)
        if not isinstance(detector, cls):
            raise TypeError(f"Loaded object is of type {type(detector)}, expected {cls.__name__}")
        logger.info(f"Loaded NetworkAnomalyDetector artifact from {path}")
        return detector
