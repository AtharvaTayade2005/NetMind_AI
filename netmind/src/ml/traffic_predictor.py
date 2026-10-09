"""NetMind AI - Time-Series Network Traffic Predictor.

Cybersecurity & Mathematical Rationale:
----------------------------------------
1. Auto-Regressive Dynamics & Self-Similarity in Network Traffic:
   Network traffic rate series (bytes/sec, packets/sec) exhibit pronounced self-similarity,
   temporal autocorrelation, and heavy-tailed burstiness. Standard stateless flow inspection
   treats each connection independently, missing macroscopic bandwidth surges.

2. Operational Value in Security Operations:
   - Proactive Capacity Management: Forecasts bandwidth consumption to alert network engineering
     before ingress links reach saturation (packet dropping / denial of service).
   - Telemetry Anomaly Detection: By comparing real-time observed telemetry y_t against predicted
     expected rate y_hat_t, large residual spikes (y_t >> y_hat_t + 3 * sigma) indicate volumetric
     DDoS floods or covert massive data exfiltration events prior to signature matching.

3. Time-Series Feature Engineering:
   - Lagged features (t-1, t-2, t-5): Encode short-term auto-regressive momentum and recent state.
   - Rolling window statistics (mean, std, max over 3 and 5 steps): Capture localized trend drift
     and traffic volatility.
   - Strict Temporal Causality: Splitting strictly respects time order (past trains future; never shuffle).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from xgboost import XGBRegressor

logger = logging.getLogger(__name__)

TARGET_COLUMNS = ["bytes_per_second", "packets_per_second"]


@dataclass
class TrafficForecastMetrics:
    """Evaluation metrics for traffic forecasting regression."""

    target_name: str
    mae: float
    rmse: float
    r2: float

    def to_dict(self) -> Dict[str, float]:
        return {
            "mae": self.mae,
            "rmse": self.rmse,
            "r2": self.r2,
        }


@dataclass
class ForecastEvaluationReport:
    """Aggregated evaluation metrics across all forecasted telemetry targets."""

    metrics_by_target: Dict[str, TrafficForecastMetrics]
    mean_r2: float
    mean_mae: float

    def summary(self) -> str:
        lines = ["Network Traffic Forecasting Evaluation:"]
        for target, m in self.metrics_by_target.items():
            lines.append(f"  [{target}] MAE: {m.mae:,.2f} | RMSE: {m.rmse:,.2f} | R²: {m.r2:.4f}")
        lines.append(f"  Overall Average R²: {self.mean_r2:.4f}")
        return "\n".join(lines)


class NetworkTrafficPredictor:
    """Multi-target time-series regressor for forecasting bytes/sec and packets/sec."""

    def __init__(
        self,
        target_cols: Optional[List[str]] = None,
        lags: Tuple[int, ...] = (1, 2, 5),
        rolling_windows: Tuple[int, ...] = (3, 5),
        n_estimators: int = 150,
        max_depth: int = 5,
        learning_rate: float = 0.05,
        random_state: int = 42,
    ) -> None:
        """Initialize traffic predictor.

        Args:
            target_cols: Target metrics to forecast (default: ['bytes_per_second', 'packets_per_second']).
            lags: Backward time-step lag indices (e.g., (1, 2, 5) creates t-1, t-2, t-5).
            rolling_windows: Window sizes for rolling mean and std calculation.
            n_estimators: Number of boosting trees per target regressor.
            max_depth: Maximum tree depth.
            learning_rate: Gradient boosting shrinkage rate.
            random_state: Deterministic random seed.
        """
        self.target_cols = target_cols or list(TARGET_COLUMNS)
        self.lags = list(lags)
        self.rolling_windows = list(rolling_windows)
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.random_state = random_state

        self.models: Dict[str, XGBRegressor] = {}
        self.feature_names_: List[str] = []
        self._is_fitted = False

    def create_lagged_features(
        self,
        df: pd.DataFrame,
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Generate lag windows and rolling aggregates from sequential telemetry.

        Mathematical Rationale:
        Constructs an autoregressive tabular feature matrix X and forward step target Y (t+1).
        Respects strict temporal causality with no forward-looking leakage.

        Args:
            df: Chronologically ordered DataFrame containing telemetry metrics.

        Returns:
            Tuple[pd.DataFrame, pd.DataFrame]:
                - X_lagged: Autoregressive features containing t-1, t-5, rolling means, stds.
                - y_targets: Forward step (t+1) target values.
        """
        for col in self.target_cols:
            if col not in df.columns:
                raise ValueError(f"Target column '{col}' missing from input DataFrame.")

        features_dict: Dict[str, pd.Series] = {}

        # 1. Generate Autoregressive Lag Features
        for col in self.target_cols:
            for lag in self.lags:
                features_dict[f"{col}_lag_{lag}"] = df[col].shift(lag)

        # 2. Generate Rolling Window Statistics (mean and standard deviation)
        for col in self.target_cols:
            for w in self.rolling_windows:
                # shift by 1 to prevent including current step t in past window
                shifted = df[col].shift(1)
                features_dict[f"{col}_rolling_mean_{w}"] = shifted.rolling(window=w).mean()
                features_dict[f"{col}_rolling_std_{w}"] = shifted.rolling(window=w).std()

        # Combine into DataFrame
        X_all = pd.DataFrame(features_dict, index=df.index)

        # Target is next-step value (t)
        y_all = df[self.target_cols].copy()

        # Drop initial NaN rows created by lags and rolling windows
        max_lookback = max(max(self.lags), max(self.rolling_windows))
        valid_indices = X_all.index[max_lookback:]

        X_clean = X_all.loc[valid_indices].fillna(0.0)
        y_clean = y_all.loc[valid_indices]

        return X_clean, y_clean

    def fit(
        self,
        X_train: pd.DataFrame,
        y_train: pd.DataFrame,
    ) -> "NetworkTrafficPredictor":
        """Train independent gradient-boosted regressors for each traffic metric.

        Args:
            X_train: Lagged and rolling features DataFrame.
            y_train: Forward step target metrics DataFrame.

        Returns:
            self
        """
        self.feature_names_ = list(X_train.columns)
        X_mat = X_train.to_numpy()

        for target in self.target_cols:
            if target not in y_train.columns:
                raise ValueError(f"Target '{target}' not found in y_train columns.")

            logger.info(f"Training XGBRegressor for network telemetry target '{target}'...")
            regressor = XGBRegressor(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                learning_rate=self.learning_rate,
                objective="reg:squarederror",
                random_state=self.random_state,
                n_jobs=-1,
            )
            regressor.fit(X_mat, y_train[target].to_numpy())
            self.models[target] = regressor

        self._is_fitted = True
        logger.info("Traffic forecasting model training complete.")
        return self

    def predict(self, X: Union[pd.DataFrame, np.ndarray]) -> pd.DataFrame:
        """Forecast future network rate metrics.

        Args:
            X: Input lagged features.

        Returns:
            pd.DataFrame: Forecasted predictions for each target column.
        """
        if not self._is_fitted:
            raise RuntimeError("NetworkTrafficPredictor is not fitted.")

        X_mat = X.to_numpy() if isinstance(X, pd.DataFrame) else np.asarray(X)
        predictions: Dict[str, np.ndarray] = {}

        for target in self.target_cols:
            preds = self.models[target].predict(X_mat)
            # Traffic rates cannot physically be negative
            predictions[target] = np.clip(preds, a_min=0.0, a_max=None)

        index = X.index if isinstance(X, pd.DataFrame) else None
        return pd.DataFrame(predictions, index=index)

    def evaluate(
        self,
        X_test: pd.DataFrame,
        y_test: pd.DataFrame,
    ) -> ForecastEvaluationReport:
        """Evaluate traffic forecasting accuracy using MAE, RMSE, and R².

        Mathematical Rationale:
        - MAE (Mean Absolute Error): Average absolute magnitude of rate forecasting error.
        - RMSE (Root Mean Squared Error): Penalizes severe burst prediction errors quadratically.
        - R² (Coefficient of Determination): Proportion of variance explained by the model.

        Returns:
            ForecastEvaluationReport: Metrics report per target.
        """
        y_pred = self.predict(X_test)
        metrics_dict: Dict[str, TrafficForecastMetrics] = {}

        r2_list: List[float] = []
        mae_list: List[float] = []

        for target in self.target_cols:
            y_t = y_test[target].to_numpy()
            y_p = y_pred[target].to_numpy()

            mae = float(mean_absolute_error(y_t, y_p))
            rmse = float(np.sqrt(mean_squared_error(y_t, y_p)))
            r2 = float(r2_score(y_t, y_p))

            metrics_dict[target] = TrafficForecastMetrics(
                target_name=target,
                mae=round(mae, 4),
                rmse=round(rmse, 4),
                r2=round(r2, 4),
            )
            r2_list.append(r2)
            mae_list.append(mae)

        return ForecastEvaluationReport(
            metrics_by_target=metrics_dict,
            mean_r2=round(float(np.mean(r2_list)), 4),
            mean_mae=round(float(np.mean(mae_list)), 4),
        )

    def save(self, filepath: Union[str, Path]) -> None:
        """Persist trained traffic predictor artifact to disk via joblib."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        logger.info(f"Saved NetworkTrafficPredictor artifact to {path}")

    @classmethod
    def load(cls, filepath: Union[str, Path]) -> "NetworkTrafficPredictor":
        """Load trained traffic predictor artifact from disk."""
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Traffic predictor artifact not found at {path}")
        predictor = joblib.load(path)
        if not isinstance(predictor, cls):
            raise TypeError(f"Loaded object is of type {type(predictor)}, expected {cls.__name__}")
        logger.info(f"Loaded NetworkTrafficPredictor artifact from {path}")
        return predictor
