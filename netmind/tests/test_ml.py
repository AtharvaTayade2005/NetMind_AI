"""Unit and Integration Tests for NetMind AI Phase 2: Machine Learning & Explainability Layer.

Verifies:
1. Preprocessing pipeline: Robust scaling, median imputation, DataFrame shape/column preservation.
2. Partitioning logic: Stratified train/val/test splits with zero leakage.
3. Anomaly detection: Isolation Forest scoring, dynamic threshold calibration, top behavioral indicators.
4. Multiclass attack classification: XGBoost training, prediction, evaluation reporter, confusion matrix.
5. Time-series rate forecasting: Lag windows (t-1, t-5), rolling aggregates, MAE/RMSE/R² metrics.
6. TreeSHAP explainability: Exact Shapley values, local attribution, human-readable reason translation.
7. Model artifact persistence: Saving and reloading all models via joblib.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

# Ensure repo paths in sys.path
TEST_DIR = Path(__file__).resolve().parent
NETMIND_DIR = TEST_DIR.parent
WORKSPACE_DIR = NETMIND_DIR.parent

for p in [str(WORKSPACE_DIR), str(NETMIND_DIR), str(NETMIND_DIR / "src")]:
    if p not in sys.path:
        sys.path.insert(0, p)

from netmind.src.ml.anomaly_detector import NetworkAnomalyDetector
from netmind.src.ml.attack_classifier import ATTACK_CLASS_MAP, AttackClassifier
from netmind.src.ml.dataset import NetMindPreprocessor, prepare_train_val_test_splits
from netmind.src.ml.explainer import NetMindExplainer
from netmind.src.ml.traffic_predictor import NetworkTrafficPredictor
from netmind.src.ml.train_all import generate_synthetic_flow_dataset


@pytest.fixture(scope="module")
def sample_telemetry_data():
    """Generate small synthetic flow dataset for fast testing."""
    X, y = generate_synthetic_flow_dataset(
        n_normal=200,
        n_dos=50,
        n_portscan=50,
        n_bruteforce=30,
        n_webattack=20,
        random_state=42,
    )
    return X, y


def test_preprocessor_robust_scaling_and_imputation(sample_telemetry_data, tmp_path):
    """Test NetMindPreprocessor handles missing values, applies RobustScaler, and serializes."""
    X, _ = sample_telemetry_data
    # Inject synthetic missing values
    X_with_nans = X.copy()
    X_with_nans.iloc[0, 0] = np.nan
    X_with_nans.iloc[5, 3] = np.nan

    preprocessor = NetMindPreprocessor(scaler_type="robust", impute_strategy="median")
    X_scaled = preprocessor.fit_transform(X_with_nans)

    assert isinstance(X_scaled, pd.DataFrame)
    assert not X_scaled.isna().any().any(), "Imputed scaled DataFrame must contain no NaNs"
    assert list(X_scaled.columns) == list(X.columns)
    assert len(X_scaled) == len(X)

    # Test serialization
    save_path = tmp_path / "test_preprocessor.joblib"
    preprocessor.save(save_path)
    loaded_preprocessor = NetMindPreprocessor.load(save_path)
    X_reloaded_scaled = loaded_preprocessor.transform(X.iloc[:5])
    assert X_reloaded_scaled.shape == (5, X.shape[1])


def test_dataset_stratified_partitioning(sample_telemetry_data):
    """Test deterministic stratified train/val/test split logic."""
    X, y = sample_telemetry_data
    splits = prepare_train_val_test_splits(X, y, val_size=0.15, test_size=0.15, random_state=42)

    total_samples = len(X)
    assert len(splits.X_train) == pytest.approx(int(total_samples * 0.70), abs=3)
    assert len(splits.X_val) == pytest.approx(int(total_samples * 0.15), abs=3)
    assert len(splits.X_test) == pytest.approx(int(total_samples * 0.15), abs=3)

    # Verify all 5 classes are represented in train, val, and test splits
    assert set(splits.y_train.unique()) == {0, 1, 2, 3, 4}
    assert set(splits.y_val.unique()) == {0, 1, 2, 3, 4}
    assert set(splits.y_test.unique()) == {0, 1, 2, 3, 4}


def test_anomaly_detector_scoring_and_indicators(sample_telemetry_data, tmp_path):
    """Test Isolation Forest scoring, dynamic calibration, and root-cause indicators."""
    X, y = sample_telemetry_data
    # Train anomaly detector on normal traffic only
    X_normal = X[y == 0]

    preprocessor = NetMindPreprocessor(scaler_type="robust")
    X_normal_scaled = preprocessor.fit_transform(X_normal)

    detector = NetworkAnomalyDetector(n_estimators=50, contamination=0.05, random_state=42)
    detector.fit(X_normal_scaled, calibrate_percentile=95.0)

    assert detector.calibrated_threshold_ > 0.0
    assert detector._is_fitted

    # Evaluate on mixed batch (containing normal and attacks)
    X_test_scaled = preprocessor.transform(X.iloc[:20])
    results = detector.predict(X_test_scaled, extract_indicators=True, top_k=3)

    assert len(results.is_anomaly) == 20
    assert len(results.anomaly_scores) == 20
    assert all(0.0 <= s <= 1.0 for s in results.anomaly_scores)
    assert results.top_indicators is not None
    assert len(results.top_indicators) == 20

    # Test serialization
    save_path = tmp_path / "test_detector.joblib"
    detector.save(save_path)
    loaded_detector = NetworkAnomalyDetector.load(save_path)
    loaded_res = loaded_detector.predict(X_test_scaled)
    np.testing.assert_array_equal(results.is_anomaly, loaded_res.is_anomaly)


def test_attack_classifier_evaluation_and_serialization(sample_telemetry_data, tmp_path):
    """Test supervised XGBoost multiclass model, report generation, and confusion matrix."""
    X, y = sample_telemetry_data
    splits = prepare_train_val_test_splits(X, y, val_size=0.15, test_size=0.15, random_state=42)

    preprocessor = NetMindPreprocessor(scaler_type="robust")
    X_train_s = preprocessor.fit_transform(splits.X_train)
    X_test_s = preprocessor.transform(splits.X_test)

    classifier = AttackClassifier(n_estimators=30, max_depth=4, learning_rate=0.1, random_state=42)
    classifier.fit(X_train_s, splits.y_train)

    preds = classifier.predict(X_test_s)
    probs = classifier.predict_proba(X_test_s)
    labels = classifier.predict_labels(X_test_s)

    assert len(preds) == len(splits.X_test)
    assert probs.shape == (len(splits.X_test), 5)
    assert np.allclose(probs.sum(axis=1), 1.0, atol=1e-5)
    assert len(labels) == len(splits.X_test)

    # Evaluation report
    eval_rep = classifier.evaluate(X_test_s, splits.y_test)
    assert 0.0 <= eval_rep.accuracy <= 1.0
    assert 0.0 <= eval_rep.macro_f1 <= 1.0
    assert eval_rep.confusion_matrix.shape == (5, 5)

    # Save and reload
    save_path = tmp_path / "test_classifier.joblib"
    classifier.save(save_path)
    loaded_classifier = AttackClassifier.load(save_path)
    np.testing.assert_array_equal(preds, loaded_classifier.predict(X_test_s))


def test_traffic_predictor_lag_windows_and_regression(sample_telemetry_data, tmp_path):
    """Test time-series predictor autoregressive lag feature creation and regression."""
    X, _ = sample_telemetry_data
    predictor = NetworkTrafficPredictor(
        target_cols=["bytes_per_second", "packets_per_second"],
        lags=(1, 2, 5),
        rolling_windows=(3, 5),
        n_estimators=25,
        max_depth=3,
        random_state=42,
    )

    X_lag, y_target = predictor.create_lagged_features(X)
    assert not X_lag.empty
    assert not y_target.empty
    assert len(X_lag) == len(y_target)
    # Check that lag columns exist
    assert "bytes_per_second_lag_1" in X_lag.columns
    assert "packets_per_second_lag_5" in X_lag.columns
    assert "bytes_per_second_rolling_mean_3" in X_lag.columns

    # Train and evaluate
    split_idx = int(len(X_lag) * 0.8)
    X_train, X_test = X_lag.iloc[:split_idx], X_lag.iloc[split_idx:]
    y_train, y_test = y_target.iloc[:split_idx], y_target.iloc[split_idx:]

    predictor.fit(X_train, y_train)
    preds = predictor.predict(X_test)

    assert preds.shape == (len(X_test), 2)
    # Forecasts cannot be negative
    assert (preds >= 0.0).all().all()

    report = predictor.evaluate(X_test, y_test)
    assert "bytes_per_second" in report.metrics_by_target
    assert "packets_per_second" in report.metrics_by_target

    # Test serialization
    save_path = tmp_path / "test_predictor.joblib"
    predictor.save(save_path)
    loaded_predictor = NetworkTrafficPredictor.load(save_path)
    preds_loaded = loaded_predictor.predict(X_test)
    pd.testing.assert_frame_equal(preds, preds_loaded)


def test_treeshap_explainer_and_human_readable_reasons(sample_telemetry_data):
    """Test TreeSHAP feature attributions and translation to SOC reason sentences."""
    X, y = sample_telemetry_data
    splits = prepare_train_val_test_splits(X, y, val_size=0.15, test_size=0.15, random_state=42)

    preprocessor = NetMindPreprocessor(scaler_type="robust")
    X_train_s = preprocessor.fit_transform(splits.X_train)
    X_test_s = preprocessor.transform(splits.X_test)

    classifier = AttackClassifier(n_estimators=25, max_depth=3, random_state=42)
    classifier.fit(X_train_s, splits.y_train)

    explainer = NetMindExplainer(classifier)
    assert explainer.explainer is not None

    # Explain single test instance
    sample_vec = X_test_s.iloc[0]
    explanation = explainer.explain_instance(sample_vec, top_k=3)

    assert explanation.predicted_class_id in ATTACK_CLASS_MAP
    assert explanation.predicted_class_name in ATTACK_CLASS_MAP.values()
    assert 0.0 <= explanation.class_probability <= 1.0
    assert len(explanation.feature_attributions) == X.shape[1]
    assert len(explanation.human_readable_reasons) > 0

    # Verify reasons contain structured phrases
    for reason in explanation.human_readable_reasons:
        assert isinstance(reason, str)
        assert ("pushed classification toward" in reason) or ("reduced attack confidence" in reason)


def test_pipeline_saved_model_artifacts_exist():
    """Verify that train_all successfully generated and persisted all model artifacts."""
    models_dir = NETMIND_DIR / "models"
    expected_artifacts = [
        "preprocessor.joblib",
        "anomaly_detector.joblib",
        "attack_classifier.joblib",
        "traffic_predictor.joblib",
    ]
    for art in expected_artifacts:
        art_path = models_dir / art
        assert art_path.is_file(), f"Expected artifact {art} missing in {models_dir}"


if __name__ == "__main__":
    pytest.main(["-v", str(Path(__file__))])
