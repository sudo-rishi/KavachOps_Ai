from __future__ import annotations

import importlib.util
import json
import os
from math import log2
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request as URLRequest
from urllib.request import urlopen

import pandas as pd
from flask import Flask, jsonify, request

ROOT_DIR = Path(__file__).resolve().parent
MALWARE_DIR = ROOT_DIR / "Malware Detection Model"
ANOMALY_DIR = ROOT_DIR / "Anomly Detection Model"
YARA_DIR = ROOT_DIR / "Yara Detection Model"
DEFAULT_YARA_RULES_DIR = YARA_DIR / "Rules"
SARVAM_CHAT_URL = "https://api.sarvam.ai/v1/chat/completions"

def _load_module(module_name: str, module_path: Path):
    if not module_path.exists():
        raise FileNotFoundError(f"Module not found: {module_path}")
    spec = importlib.util.spec_from_file_location(module_name, str(module_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not create import spec for {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


app = Flask(__name__)

# Malware model integration
_malware_err: str | None = None
_malware_predict_fn = None
_malware_feature_names_fn = None

try:
    malware_predict_mod = _load_module("KavachOps_malware_predict", MALWARE_DIR / "predict.py")
    _malware_predict_fn = getattr(malware_predict_mod, "predict", None)
    _malware_feature_names_fn = getattr(malware_predict_mod, "get_model_feature_names", None)
    if _malware_predict_fn is None:
        raise RuntimeError("Missing predict() in Malware Detection Model/predict.py")
except Exception as ex:
    _malware_err = str(ex)


# YARA integration
_yara_err: str | None = None
_yara_load_rules = None
_yara_scan_file = None
_yara_rules_cache: dict[str, Any] = {}

try:
    yara_core_mod = _load_module("KavachOps_yara_core", YARA_DIR / "yaradetect" / "core.py")
    _yara_load_rules = getattr(yara_core_mod, "load_rules_from_dir", None)
    _yara_scan_file = getattr(yara_core_mod, "scan_file", None)
    if _yara_load_rules is None or _yara_scan_file is None:
        raise RuntimeError("Missing load_rules_from_dir() or scan_file() in YARA core module")
except Exception as ex:
    _yara_err = str(ex)


# Anomaly integration
_anomaly_err: str | None = None


class AnomalyService:
    def __init__(self) -> None:
        self._lock = RLock()
        self._detector = None
        self._scaler = None
        self._feature_cols: list[str] = []
        self._encoders: dict[str, Any] = {}
        self._baseline_rows: int = 0

        self._mod = _load_module("KavachOps_ids_anomaly", ANOMALY_DIR / "idsanomly.py")
        self._fit_preprocessor = getattr(self._mod, "fit_preprocessor")
        self._transform_records = getattr(self._mod, "transform_records")
        self._IsolationForestDetector = getattr(self._mod, "IsolationForestDetector")

    def train(self, baseline_df: pd.DataFrame, contamination: float = 0.05) -> dict[str, Any]:
        if baseline_df.empty:
            raise ValueError("Baseline dataset is empty")

        with self._lock:
            X_train, scaler, feature_cols, encoders = self._fit_preprocessor(baseline_df)
            detector = self._IsolationForestDetector(contamination=contamination)
            detector.fit(X_train)

            self._detector = detector
            self._scaler = scaler
            self._feature_cols = list(feature_cols)
            self._encoders = dict(encoders)
            self._baseline_rows = int(len(baseline_df))

            return {
                "trained": True,
                "baselineRows": self._baseline_rows,
                "featureCount": len(self._feature_cols),
                "contamination": contamination,
            }

    def is_ready(self) -> bool:
        with self._lock:
            return self._detector is not None

    def state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "ready": self._detector is not None,
                "baselineRows": self._baseline_rows,
                "featureCount": len(self._feature_cols),
            }

    def detect(self, records_df: pd.DataFrame) -> list[dict[str, Any]]:
        if records_df.empty:
            return []

        with self._lock:
            if self._detector is None or self._scaler is None:
                raise RuntimeError("Anomaly model is not trained")

            X_scaled = self._transform_records(
                records_df,
                self._feature_cols,
                self._scaler,
                self._encoders,
            )
            preds = self._detector.predict(X_scaled)
            scores = self._detector.score_samples(X_scaled)

        output: list[dict[str, Any]] = []
        for i, pred in enumerate(preds):
            output.append(
                {
                    "index": i,
                    "anomaly": bool(pred == 1),
                    "anomaly_flag": int(pred),
                    "anomaly_score": float(round(float(scores[i]), 6)),
                }
            )
        return output


_anomaly_service = None
try:
    _anomaly_service = AnomalyService()
except Exception as ex:
    _anomaly_err = str(ex)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * log2(p)
    return entropy


def _get_malware_feature_names() -> list[str]:
    if _malware_feature_names_fn is None:
        return []
    try:
        return list(_malware_feature_names_fn())
    except Exception:
        return []


def _build_malware_features_from_file(file_path: Path) -> dict[str, float]:
    stat = file_path.stat()
    raw = file_path.read_bytes()
    sample = raw[:65536]

    file_size = float(stat.st_size)
    sample_size = float(len(sample) or 1)
    entropy = _shannon_entropy(sample)
    null_ratio = float(sample.count(0)) / sample_size
    printable_ratio = float(sum(32 <= b <= 126 for b in sample)) / sample_size
    has_mz = 1.0 if sample.startswith(b"MZ") else 0.0
    path_depth = float(len(file_path.parts))
    extension_len = float(len(file_path.suffix.lstrip(".")))

    model_features = _get_malware_feature_names()
    if not model_features:
        return {
            "file_size": file_size,
            "entropy": entropy,
            "null_byte_ratio": null_ratio,
            "printable_ratio": printable_ratio,
            "has_mz_header": has_mz,
            "path_depth": path_depth,
            "extension_len": extension_len,
        }

    features = {name: 0.0 for name in model_features}
    for name in model_features:
        key = name.lower()
        if "size" in key:
            features[name] = file_size
        elif "entropy" in key:
            features[name] = entropy
        elif "null" in key or "zero" in key:
            features[name] = null_ratio
        elif "print" in key or "ascii" in key:
            features[name] = printable_ratio
        elif "mz" in key or "exe" in key or "pe" in key:
            features[name] = has_mz
        elif "depth" in key:
            features[name] = path_depth
        elif "ext" in key:
            features[name] = extension_len
        elif "time" in key or "age" in key:
            features[name] = _safe_float(stat.st_mtime)
    return features


def _scan_file_with_malware(file_path: Path) -> dict[str, Any]:
    if _malware_predict_fn is None:
        raise RuntimeError(_malware_err or "Malware model is unavailable")

    features = _build_malware_features_from_file(file_path)
    result = _malware_predict_fn(features)

    return {
        "label": result.get("label", "unknown"),
        "confidence": _safe_float(result.get("confidence"), 0.0),
        "class_id": int(result.get("class_id", -1)),
        "source": "ml",
        "details": {
            "inputType": "file",
            "filePath": str(file_path),
            "fileName": file_path.name,
            "fileSize": file_path.stat().st_size,
            "modelFeatureCount": len(_get_malware_feature_names()) or result.get("feature_count", 0),
            "derivedFeatureCount": len(features),
        },
    }


def _load_rules_cached(rules_dir: Path):
    key = str(rules_dir.resolve())
    if key in _yara_rules_cache:
        return _yara_rules_cache[key]
    if _yara_load_rules is None:
        raise RuntimeError(_yara_err or "YARA engine is unavailable")
    rules = _yara_load_rules(rules_dir)
    _yara_rules_cache[key] = rules
    return rules


def _scan_file_with_yara(file_path: Path, rules_dir: Path) -> dict[str, Any]:
    if _yara_scan_file is None:
        raise RuntimeError(_yara_err or "YARA engine is unavailable")

    rules = _load_rules_cached(rules_dir)
    if not rules:
        return {
            "status": "ok",
            "source": "yara",
            "filePath": str(file_path),
            "rulesDir": str(rules_dir),
            "matched": False,
            "matchCount": 0,
            "matchedRules": [],
            "matches": {},
            "details": {"rulesLoaded": 0},
        }

    result = _yara_scan_file(rules, file_path)
    matched_rules = result.get("matched_rules", [])

    return {
        "status": "ok",
        "source": "yara",
        "filePath": str(file_path),
        "rulesDir": str(rules_dir),
        "matched": len(matched_rules) > 0,
        "matchCount": len(matched_rules),
        "matchedRules": matched_rules,
        "matches": result.get("matches", {}),
        "details": {"rulesLoaded": len(rules)},
    }


def _parse_records(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(payload.get("records"), list):
        return [r for r in payload["records"] if isinstance(r, dict)]
    if isinstance(payload.get("samples"), list):
        return [r for r in payload["samples"] if isinstance(r, dict)]
    if isinstance(payload.get("record"), dict):
        return [payload["record"]]
    if isinstance(payload.get("features"), dict):
        return [payload["features"]]
    return []


def _train_anomaly_from_request(body: dict[str, Any]) -> None:
    if _anomaly_service is None or _anomaly_service.is_ready():
        return

    baseline_records = body.get("baselineRecords")
    if not isinstance(baseline_records, list):
        return

    baseline_df = pd.DataFrame([record for record in baseline_records if isinstance(record, dict)])
    if not baseline_df.empty:
        _anomaly_service.train(
            baseline_df,
            contamination=_safe_float(body.get("contamination"), 0.05),
        )


def _load_baseline_if_configured() -> str | None:
    if _anomaly_service is None:
        return _anomaly_err or "Anomaly service unavailable"

    baseline_path = os.getenv("IDS_BASELINE_CSV", "").strip()
    if not baseline_path:
        return None

    path = Path(baseline_path).expanduser().resolve()
    if not path.exists() or not path.is_file():
        return f"Configured IDS_BASELINE_CSV not found: {path}"

    df = pd.read_csv(path)
    _anomaly_service.train(df)
    return None


_baseline_init_err = _load_baseline_if_configured()


@app.route("/", methods=["GET"])
def index():
    return jsonify(
        {
            "service": "KavachOps-ml-unified",
            "status": "ok",
            "endpoints": [
                "/api/health",
                "/api/sarvam/chat",
                "/api/scan-file",
                "/api/malware/scan-file",
                "/api/yara/scan-file",
                "/api/anomaly/detect",
                "/api/anomaly/batch",
                "/api/anomaly/train",
                "/api/model/retrain",
            ],
        }
    )


@app.route("/api/health", methods=["GET"])
def health():
    anomaly_state = _anomaly_service.state() if _anomaly_service else {"ready": False}
    return jsonify(
        {
            "status": "ok",
            "services": {
                "sarvam": {"configured": bool(os.getenv("SARVAM_API_KEY", "").strip())},
                "malware": {"ready": _malware_err is None, "error": _malware_err},
                "yara": {
                    "ready": _yara_err is None,
                    "error": _yara_err,
                    "defaultRulesDir": str(DEFAULT_YARA_RULES_DIR),
                },
                "anomaly": {
                    **anomaly_state,
                    "error": _anomaly_err or _baseline_init_err,
                },
            },
        }
    )


@app.route("/api/sarvam/chat", methods=["POST"])
def sarvam_chat():
    api_key = os.getenv("SARVAM_API_KEY", "").strip()
    if not api_key:
        return (
            jsonify({"error": "Sarvam API key is not configured", "hint": "Set SARVAM_API_KEY"}),
            503,
        )

    body = request.get_json(silent=True) or {}
    messages = body.get("messages")
    if messages is None:
        message = body.get("message")
        if not isinstance(message, str) or not message.strip():
            return jsonify({"error": "Provide a non-empty message or messages array"}), 400
        messages = [{"role": "user", "content": message}]

    if not isinstance(messages, list) or not messages:
        return jsonify({"error": "messages must be a non-empty array"}), 400
    for item in messages:
        if (
            not isinstance(item, dict)
            or item.get("role") not in {"system", "user", "assistant"}
            or not isinstance(item.get("content"), str)
        ):
            return jsonify({"error": "Each message needs a supported role and string content"}), 400

    model = body.get("model", os.getenv("SARVAM_MODEL", "sarvam-105b"))
    if not isinstance(model, str) or not model.strip():
        return jsonify({"error": "model must be a non-empty string"}), 400

    payload = json.dumps({"model": model.strip(), "messages": messages}).encode("utf-8")
    api_request = URLRequest(
        SARVAM_CHAT_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "api-subscription-key": api_key,
        },
        method="POST",
    )

    try:
        with urlopen(api_request, timeout=60) as response:
            result = json.loads(response.read().decode("utf-8"))
    except HTTPError as ex:
        details = ex.read().decode("utf-8", errors="replace")[:4000]
        return jsonify({"error": "Sarvam API request failed", "details": details}), ex.code
    except TimeoutError:
        return jsonify({"error": "Sarvam API request timed out"}), 504
    except URLError as ex:
        return jsonify({"error": "Could not connect to Sarvam API", "details": str(ex.reason)}), 502
    except (UnicodeDecodeError, json.JSONDecodeError):
        return jsonify({"error": "Sarvam API returned an invalid JSON response"}), 502

    return jsonify(result), 200


@app.route("/api/malware/scan-file", methods=["POST"])
@app.route("/api/scan-file", methods=["POST"])
def malware_or_compat_scan_file():
    try:
        body = request.get_json(silent=True) or {}
        file_path_raw = body.get("filePath")
        if not file_path_raw:
            return jsonify({"error": "filePath is required"}), 400

        file_path = Path(file_path_raw).expanduser().resolve()
        if not file_path.exists() or not file_path.is_file():
            return jsonify({"error": f"File not found or not a regular file: {file_path}"}), 400

        # Compatibility mode:
        # If caller includes rulesDir (as Java YARA integration does), treat as YARA scan.
        if body.get("rulesDir") or str(body.get("engine", "")).lower() == "yara":
            rules_dir_raw = body.get("rulesDir")
            rules_dir = Path(rules_dir_raw).expanduser().resolve() if rules_dir_raw else DEFAULT_YARA_RULES_DIR
            if not rules_dir.exists() or not rules_dir.is_dir():
                return jsonify({"error": f"Rules directory not found: {rules_dir}"}), 400
            return jsonify(_scan_file_with_yara(file_path, rules_dir)), 200

        return jsonify(_scan_file_with_malware(file_path)), 200
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


@app.route("/api/yara/scan-file", methods=["POST"])
def yara_scan_file_api():
    try:
        body = request.get_json(silent=True) or {}
        file_path_raw = body.get("filePath")
        if not file_path_raw:
            return jsonify({"error": "filePath is required"}), 400

        rules_dir_raw = body.get("rulesDir")
        rules_dir = Path(rules_dir_raw).expanduser().resolve() if rules_dir_raw else DEFAULT_YARA_RULES_DIR
        file_path = Path(file_path_raw).expanduser().resolve()

        if not file_path.exists() or not file_path.is_file():
            return jsonify({"error": f"File not found or not a regular file: {file_path}"}), 400
        if not rules_dir.exists() or not rules_dir.is_dir():
            return jsonify({"error": f"Rules directory not found: {rules_dir}"}), 400

        return jsonify(_scan_file_with_yara(file_path, rules_dir)), 200
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


@app.route("/api/anomaly/train", methods=["POST"])
def anomaly_train():
    try:
        if _anomaly_service is None:
            return jsonify({"error": _anomaly_err or "Anomaly service unavailable"}), 500

        body = request.get_json(silent=True) or {}
        contamination = _safe_float(body.get("contamination"), 0.05)

        records = _parse_records(body)
        baseline_csv = body.get("baselineCsvPath")

        if records:
            baseline_df = pd.DataFrame(records)
        elif baseline_csv:
            baseline_df = pd.read_csv(Path(str(baseline_csv)).expanduser().resolve())
        else:
            return jsonify({"error": "Provide records/samples/record/features or baselineCsvPath"}), 400

        result = _anomaly_service.train(baseline_df, contamination=contamination)
        return jsonify({"status": "ok", **result}), 200
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


@app.route("/api/anomaly/detect", methods=["POST"])
def anomaly_detect():
    try:
        if _anomaly_service is None:
            return jsonify({"error": _anomaly_err or "Anomaly service unavailable"}), 500

        body = request.get_json(silent=True) or {}
        records = _parse_records(body)
        if not records:
            return jsonify({"error": "Missing record/features payload"}), 400

        _train_anomaly_from_request(body)

        if not _anomaly_service.is_ready():
            return (
                jsonify(
                    {
                        "error": "Anomaly model is not trained",
                        "hint": "Call /api/anomaly/train or provide baselineRecords in this request",
                    }
                ),
                503,
            )

        detections = _anomaly_service.detect(pd.DataFrame(records))
        first = detections[0] if detections else {"anomaly": False, "anomaly_score": 0.0}

        return (
            jsonify(
                {
                    "status": "ok",
                    "anomaly": first.get("anomaly", False),
                    "anomaly_flag": first.get("anomaly_flag", 0),
                    "anomaly_score": first.get("anomaly_score", 0.0),
                    "details": first,
                }
            ),
            200,
        )
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


@app.route("/api/anomaly/batch", methods=["POST"])
def anomaly_batch():
    try:
        if _anomaly_service is None:
            return jsonify({"error": _anomaly_err or "Anomaly service unavailable"}), 500

        body = request.get_json(silent=True) or {}
        records = _parse_records(body)
        if not records:
            return jsonify({"error": "Missing records/samples payload"}), 400

        _train_anomaly_from_request(body)

        if not _anomaly_service.is_ready():
            return (
                jsonify(
                    {
                        "error": "Anomaly model is not trained",
                        "hint": "Call /api/anomaly/train or include baselineRecords in the request",
                    }
                ),
                503,
            )

        detections = _anomaly_service.detect(pd.DataFrame(records))
        alert_count = sum(1 for item in detections if item.get("anomaly"))

        return (
            jsonify(
                {
                    "status": "ok",
                    "count": len(detections),
                    "alerts": alert_count,
                    "results": detections,
                }
            ),
            200,
        )
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


@app.route("/api/model/retrain", methods=["POST"])
def model_retrain():
    try:
        if _anomaly_service is None:
            return jsonify({"error": _anomaly_err or "Anomaly service unavailable"}), 500

        body = request.get_json(silent=True) or {}
        model_type = str(body.get("type", "anomaly")).lower()
        if model_type not in {"anomaly", "ids"}:
            return jsonify({"error": f"Unsupported model type: {model_type}"}), 400

        samples = body.get("samples")
        if not isinstance(samples, list) or not samples:
            return jsonify({"error": "samples must be a non-empty array of records"}), 400

        baseline_df = pd.DataFrame([r for r in samples if isinstance(r, dict)])
        if baseline_df.empty:
            return jsonify({"error": "No valid sample records provided"}), 400

        result = _anomaly_service.train(baseline_df, contamination=_safe_float(body.get("contamination"), 0.05))
        return jsonify({"status": "ok", "model": "anomaly", **result}), 200
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


if __name__ == "__main__":
    host = os.getenv("ML_APP_HOST", "0.0.0.0")
    port = int(os.getenv("ML_APP_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
