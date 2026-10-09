"""NetMind AI - Machine Learning Dataset Preprocessing and Partitioning Module.

Cybersecurity & Mathematical Rationale:
----------------------------------------
1. Non-Gaussian Heavy Tails in Network Telemetry:
   Network traffic telemetry (byte counts, packet counts, flow durations) exhibits extreme
   power-law and log-normal distributions (Pareto distributions). Standard z-score normalization
   ((x - mu) / sigma) is severely compromised by attack bursts (e.g., multi-gigabit volumetric DoS)
   which distort the mean and inflate variance. `RobustScaler` uses the median and Interquartile
   Range (IQR = Q3 - Q1), making feature scaling immune to outlier pollution during baseline profiling.

2. Prevention of Data Leakage:
   Preprocessing statistics (imputation medians, scaling quantiles) are strictly estimated
   from the training partition ONLY, and subsequently applied to validation and test partitions.

3. Class Imbalance & Stratification:
   Advanced cyber attacks (e.g., zero-day exploitation, stealthy C2 beaconing, brute force)
   constitute a tiny fraction (<1%) of overall enterprise network telemetry. Stratified sampling
   guarantees that rare attack classes maintain identical representation across train, validation,
   and test splits.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler, StandardScaler

logger = logging.getLogger(__name__)


@dataclass
class DatasetSplits:
    """Container for partitioned network telemetry datasets."""

    X_train: pd.DataFrame
    X_val: pd.DataFrame
    X_test: pd.DataFrame
    y_train: Optional[pd.Series] = None
    y_val: Optional[pd.Series] = None
    y_test: Optional[pd.Series] = None

    @property
    def shapes(self) -> Dict[str, Tuple[int, ...]]:
        """Return diagnostic shapes of all partitions."""
        info = {
            "X_train": self.X_train.shape,
            "X_val": self.X_val.shape,
            "X_test": self.X_test.shape,
        }
        if self.y_train is not None:
            info["y_train"] = self.y_train.shape
            info["y_val"] = self.y_val.shape if self.y_val is not None else ()
            info["y_test"] = self.y_test.shape if self.y_test is not None else ()
        return info


class NetMindPreprocessor(BaseEstimator, TransformerMixin):
    """Production preprocessor for network telemetry features.

    Imputes missing/NaN values using column-wise medians and standardizes features
    using either Robust (median/IQR) or Standard (mean/variance) scaling.
    Preserves pandas DataFrame column names and indices.
    """

    def __init__(
        self,
        scaler_type: str = "robust",
        impute_strategy: str = "median",
    ) -> None:
        """Initialize preprocessor.

        Args:
            scaler_type: 'robust' (default, recommended for heavy-tailed network metrics)
                or 'standard' (z-score scaling).
            impute_strategy: Strategy for SimpleImputer ('median', 'mean', 'most_frequent').
        """
        self.scaler_type = scaler_type.lower()
        self.impute_strategy = impute_strategy
        self.imputer: Optional[SimpleImputer] = None
        self.scaler: Optional[Union[RobustScaler, StandardScaler]] = None
        self.feature_names_: List[str] = []
        self._is_fitted = False

    def fit(self, X: pd.DataFrame, y: Optional[Any] = None) -> "NetMindPreprocessor":
        """Fit the imputer and scaler on training feature matrix.

        Mathematical Rationale:
        Quantiles and medians are derived exclusively from X_train to prevent
        lookahead data leakage into evaluation splits.
        """
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)

        self.feature_names_ = list(X.columns)

        # 1. Fit Imputer
        self.imputer = SimpleImputer(strategy=self.impute_strategy)
        X_imputed = self.imputer.fit_transform(X)

        # 2. Fit Scaler
        if self.scaler_type == "robust":
            # Uses median and Interquartile Range (IQR): resistant to DoS/Scan volume outliers
            self.scaler = RobustScaler(quantile_range=(25.0, 75.0), with_centering=True, with_scaling=True)
        elif self.scaler_type == "standard":
            # Traditional Gaussian (mu, sigma)
            self.scaler = StandardScaler(with_mean=True, with_std=True)
        else:
            raise ValueError(f"Unsupported scaler_type: {self.scaler_type}. Choose 'robust' or 'standard'.")

        self.scaler.fit(X_imputed)
        self._is_fitted = True
        logger.info(f"Fitted NetMindPreprocessor on {len(X)} samples across {len(self.feature_names_)} features.")
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        """Apply fitted imputation and scaling to feature matrix.

        Returns:
            pd.DataFrame: Cleaned and normalized feature matrix.
        """
        if not self._is_fitted or self.imputer is None or self.scaler is None:
            raise RuntimeError("NetMindPreprocessor is not fitted. Call fit() or fit_transform() first.")

        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=self.feature_names_)

        # Ensure column alignment
        X_aligned = X.reindex(columns=self.feature_names_, fill_value=0.0)

        # Impute then scale
        X_imputed = self.imputer.transform(X_aligned)
        X_scaled = self.scaler.transform(X_imputed)

        return pd.DataFrame(X_scaled, columns=self.feature_names_, index=X.index)

    def fit_transform(self, X: pd.DataFrame, y: Optional[Any] = None) -> pd.DataFrame:
        """Fit preprocessor and transform features in a single pass."""
        return self.fit(X, y).transform(X)

    def save(self, filepath: Union[str, Path]) -> None:
        """Persist fitted preprocessor artifact to disk."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        logger.info(f"Saved NetMindPreprocessor artifact to {path}")

    @classmethod
    def load(cls, filepath: Union[str, Path]) -> "NetMindPreprocessor":
        """Load persisted preprocessor artifact from disk."""
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Preprocessor artifact not found at {path}")
        preprocessor = joblib.load(path)
        if not isinstance(preprocessor, cls):
            raise TypeError(f"Loaded object is of type {type(preprocessor)}, expected {cls.__name__}")
        logger.info(f"Loaded NetMindPreprocessor artifact from {path}")
        return preprocessor


def prepare_train_val_test_splits(
    X: pd.DataFrame,
    y: Optional[pd.Series] = None,
    val_size: float = 0.15,
    test_size: float = 0.15,
    random_state: int = 42,
    stratify: bool = True,
) -> DatasetSplits:
    """Partition telemetry features and optional labels into Train/Val/Test splits.

    Cybersecurity Rationale:
    Network security models evaluate zero-day and multi-stage attacks across isolated
    holdout sets. Using stratified holdouts ensures representative test performance
    across infrequent attack vectors (e.g. web application attacks).

    Args:
        X: Feature matrix DataFrame.
        y: Optional target class series (e.g., attack categories).
        val_size: Fraction of total data reserved for validation (e.g., 0.15).
        test_size: Fraction of total data reserved for testing (e.g., 0.15).
        random_state: Random seed for deterministic reproducibility.
        stratify: Whether to use stratified sampling when `y` is provided.

    Returns:
        DatasetSplits: Structured container holding partitioned splits.
    """
    total_eval_size = val_size + test_size
    if total_eval_size >= 1.0 or total_eval_size <= 0.0:
        raise ValueError(f"val_size ({val_size}) + test_size ({test_size}) must be strictly between 0 and 1.")

    stratify_target = y if (stratify and y is not None) else None

    # Step 1: Split into Train and temporary Holdout (Val + Test)
    X_train, X_holdout, y_train, y_holdout = train_test_split(
        X,
        y if y is not None else np.zeros(len(X)),
        test_size=total_eval_size,
        random_state=random_state,
        stratify=stratify_target,
    )

    # Step 2: Split Holdout into Validation and Test sets
    val_proportion_in_holdout = val_size / total_eval_size
    stratify_holdout = y_holdout if (stratify and y is not None) else None

    X_val, X_test, y_val, y_test = train_test_split(
        X_holdout,
        y_holdout,
        train_size=val_proportion_in_holdout,
        random_state=random_state,
        stratify=stratify_holdout,
    )

    return DatasetSplits(
        X_train=X_train,
        X_val=X_val,
        X_test=X_test,
        y_train=pd.Series(y_train, index=X_train.index) if y is not None else None,
        y_val=pd.Series(y_val, index=X_val.index) if y is not None else None,
        y_test=pd.Series(y_test, index=X_test.index) if y is not None else None,
    )
