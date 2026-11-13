"""
IDS Anomaly Detection Model (Real-Time)
=======================================
Uses Isolation Forest + optional Autoencoder ensemble to detect anomalous
network traffic from real input files.

This version removes synthetic seeded data generation and runs real-time checks
against appended flow records.

Example:
    python idsanomly.py --baseline-csv baseline_normal.csv --stream-csv live_flows.csv
"""

import argparse
import time
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler

warnings.filterwarnings("ignore")

# Optional deep learning autoencoder
try:
    from tensorflow.keras import Model, layers

    KERAS_AVAILABLE = True
except ImportError:
    KERAS_AVAILABLE = False
    print("[INFO] TensorFlow not found - running Isolation Forest only.\n")


class IsolationForestDetector:
    def __init__(self, contamination: float = 0.05):
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )

    def fit(self, X_train: np.ndarray):
        self.model.fit(X_train)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        raw = self.model.predict(X)
        return (raw == -1).astype(int)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return self.model.score_samples(X)


def build_autoencoder(input_dim: int, encoding_dim: int = 4) -> "Model":
    inp = layers.Input(shape=(input_dim,))
    x = layers.Dense(32, activation="relu")(inp)
    x = layers.Dense(16, activation="relu")(x)
    encoded = layers.Dense(encoding_dim, activation="relu")(x)
    x = layers.Dense(16, activation="relu")(encoded)
    x = layers.Dense(32, activation="relu")(x)
    decoded = layers.Dense(input_dim, activation="linear")(x)

    autoencoder = Model(inp, decoded)
    autoencoder.compile(optimizer="adam", loss="mse")
    return autoencoder


class AutoencoderDetector:
    def __init__(self, input_dim: int, threshold_percentile: float = 95):
        self.ae = build_autoencoder(input_dim)
        self.threshold_percentile = threshold_percentile
        self.threshold_ = None

    def fit(self, X_train: np.ndarray, epochs: int = 20, batch_size: int = 256):
        self.ae.fit(
            X_train,
            X_train,
            epochs=epochs,
            batch_size=batch_size,
            shuffle=True,
            validation_split=0.1,
            verbose=0,
        )
        recon_errors = self._reconstruction_error(X_train)
        self.threshold_ = np.percentile(recon_errors, self.threshold_percentile)
        print(f"[AE] Reconstruction-error threshold: {self.threshold_:.6f}")
        return self

    def _reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        X_pred = self.ae.predict(X, verbose=0)
        return np.mean(np.square(X - X_pred), axis=1)

    def predict(self, X: np.ndarray) -> np.ndarray:
        errors = self._reconstruction_error(X)
        return (errors > self.threshold_).astype(int)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return self._reconstruction_error(X)


class EnsembleIDS:
    def __init__(self, detectors: list):
        self.detectors = detectors

    def predict(self, X: np.ndarray) -> np.ndarray:
        votes = np.stack([d.predict(X) for d in self.detectors], axis=1)
        return (votes.mean(axis=1) >= 0.5).astype(int)


def fit_preprocessor(df: pd.DataFrame):
    feature_cols = [c for c in df.columns if c != "label"]
    X = df[feature_cols].copy()
    encoders = {}

    for col in X.select_dtypes(include="object").columns:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        encoders[col] = le

    for col in X.columns:
        if col not in encoders:
            X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled, scaler, feature_cols, encoders


def transform_records(
    df: pd.DataFrame,
    feature_cols: list,
    scaler: StandardScaler,
    encoders: dict,
) -> np.ndarray:
    X = df.copy()

    for col in feature_cols:
        if col not in X.columns:
            X[col] = 0

    X = X[feature_cols].copy()

    for col in feature_cols:
        if col in encoders:
            le = encoders[col]
            mapping = {cls: i for i, cls in enumerate(le.classes_)}
            X[col] = X[col].astype(str).map(mapping).fillna(-1).astype(int)
        else:
            X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0)

    return scaler.transform(X)


class IDSPipeline:
    def __init__(self, detector, scaler: StandardScaler, feature_cols: list, encoders: dict):
        self.detector = detector
        self.scaler = scaler
        self.feature_cols = feature_cols
        self.encoders = encoders

    def inspect(self, df: pd.DataFrame) -> pd.DataFrame:
        X_scaled = transform_records(df, self.feature_cols, self.scaler, self.encoders)
        preds = self.detector.predict(X_scaled)

        result = df.copy()
        result["anomaly_flag"] = preds
        result["alert"] = result["anomaly_flag"].map({0: "NORMAL", 1: "ALERT"})

        if hasattr(self.detector, "score_samples"):
            scores = self.detector.score_samples(X_scaled)
            result["anomaly_score"] = np.round(scores, 6)
        return result


def read_csv_required(path: str, purpose: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(path)
    except Exception as e:
        raise ValueError(f"Failed to read {purpose} CSV '{path}': {e}") from e

    if df.empty:
        raise ValueError(f"{purpose} CSV '{path}' is empty")
    return df


def main():
    parser = argparse.ArgumentParser(description="Real-time IDS anomaly detection")
    parser.add_argument("--baseline-csv", required=True, help="Historical mostly-normal traffic for fitting")
    parser.add_argument("--stream-csv", required=True, help="Live/appended traffic CSV to monitor")
    parser.add_argument("--poll-seconds", type=float, default=2.0, help="Polling interval for real-time checks")
    parser.add_argument("--batch-size", type=int, default=200, help="Max rows processed per polling cycle")
    parser.add_argument("--contamination", type=float, default=0.05, help="IsolationForest contamination")
    parser.add_argument("--use-autoencoder", action="store_true", help="Enable optional AE model")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print(" IDS Anomaly Detection (Real-Time)")
    print("=" * 60)

    print("\n[1] Loading baseline traffic ...")
    baseline_df = read_csv_required(args.baseline_csv, "baseline")
    X_train, scaler, feature_cols, encoders = fit_preprocessor(baseline_df)
    print(f"    Baseline rows: {len(baseline_df):,}")
    print(f"    Features: {', '.join(feature_cols)}")

    print("\n[2] Training Isolation Forest ...")
    iso = IsolationForestDetector(contamination=args.contamination)
    iso.fit(X_train)
    detectors = [iso]

    if args.use_autoencoder:
        if KERAS_AVAILABLE:
            print("\n[3] Training Autoencoder ...")
            ae_det = AutoencoderDetector(input_dim=X_train.shape[1], threshold_percentile=95)
            ae_det.fit(X_train)
            detectors.append(ae_det)
        else:
            print("\n[3] Autoencoder requested but TensorFlow is unavailable. Continuing with IF only.")

    if len(detectors) > 1:
        detector = EnsembleIDS(detectors)
        print("[4] Ensemble mode enabled.")
    else:
        detector = iso
        print("[4] IsolationForest mode enabled.")

    ids = IDSPipeline(detector, scaler, feature_cols, encoders)
    print("\n[5] Real-time checking started. Press Ctrl+C to stop.")
    print(f"    Stream source: {args.stream_csv}")

    last_offset = 0
    try:
        while True:
            stream_df = read_csv_required(args.stream_csv, "stream")
            if last_offset >= len(stream_df):
                time.sleep(args.poll_seconds)
                continue

            batch_df = stream_df.iloc[last_offset:last_offset + args.batch_size].copy()
            last_offset += len(batch_df)
            if batch_df.empty:
                time.sleep(args.poll_seconds)
                continue

            results = ids.inspect(batch_df)
            alerts = results[results["anomaly_flag"] == 1]

            print(f"\nChecked rows: {len(batch_df)} | Alerts: {len(alerts)}")
            if not alerts.empty:
                cols = [c for c in ["source_ip", "destination_ip", "src_port", "dst_port", "protocol", "alert"] if c in alerts.columns]
                if cols:
                    print(alerts[cols].head(10).to_string(index=False))
                else:
                    print(alerts.head(10).to_string(index=False))

            time.sleep(args.poll_seconds)
    except KeyboardInterrupt:
        print("\nStopped real-time checking.")


if __name__ == "__main__":
    main()