# Python ML Detection System

This project combines malware classification, YARA-style rule scanning, network
anomaly detection, and Sarvam AI chat behind a Flask API.

## Components

- `app.py` is the unified Flask backend (default port `5000`).
- `Malware Detection Model/` contains the trained malware model, inference code,
  training script, and training artifacts.
- `Yara Detection Model/` contains the rule parser, rules, and standalone API.
- `Anomly Detection Model/` contains the anomaly preprocessing and detector.

The root `requirements.txt` contains the dependencies needed by the unified
backend and model inference. Each subsystem's own requirements file is for
running or developing that subsystem separately. Scikit-learn is pinned to
`1.8.0` to match the serialized malware model artifacts.

## Setup and run

From the project directory in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Set the Sarvam key in the server environment (do not put it in source code):

```powershell
$env:SARVAM_API_KEY = "your-sarvam-api-key"
python app.py
```

The server reads `ML_APP_HOST` (default `0.0.0.0`) and `ML_APP_PORT` (default
`5000`). For local-only access, set `ML_APP_HOST` to `127.0.0.1`. For deployment,
run with a production WSGI server such as Gunicorn rather than Flask's built-in
development server.

Optional configuration:

| Variable | Purpose | Default |
| --- | --- | --- |
| `SARVAM_API_KEY` | Server-side key for Sarvam chat requests | Not configured |
| `SARVAM_MODEL` | Default Sarvam chat model | `sarvam-105b` |
| `IDS_BASELINE_CSV` | CSV used to train the anomaly detector at startup | Not configured |
| `ML_APP_HOST` | Flask bind address | `0.0.0.0` |
| `ML_APP_PORT` | Flask port | `5000` |

If `IDS_BASELINE_CSV` is not set, train the anomaly detector through the API
before requesting detections. Check `/api/health` to see which integrations are
available.

## Unified API

All endpoints return JSON. Scan endpoints use paths on the server hosting this
application.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/` | Service status and endpoint list |
| `GET` | `/api/health` | Readiness of model integrations and Sarvam configuration |
| `POST` | `/api/sarvam/chat` | Send a chat request to Sarvam |
| `POST` | `/api/scan-file` | Malware scan; accepts YARA options for compatibility |
| `POST` | `/api/malware/scan-file` | Malware model scan |
| `POST` | `/api/yara/scan-file` | Scan a file with YARA rules |
| `POST` | `/api/anomaly/train` | Train the anomaly detector |
| `POST` | `/api/anomaly/detect` | Detect an anomaly in one record |
| `POST` | `/api/anomaly/batch` | Detect anomalies in multiple records |
| `POST` | `/api/model/retrain` | Compatibility endpoint for anomaly retraining |

### Sarvam chat

Send a message:

```json
{
  "message": "Summarize this alert"
}
```

Or send a conversation:

```json
{
  "model": "sarvam-105b",
  "messages": [
    {"role": "system", "content": "Answer concisely."},
    {"role": "user", "content": "Summarize this alert"}
  ]
}
```

The response is the JSON response from Sarvam. The API key remains on the
backend and is sent to Sarvam using the `api-subscription-key` header. The chat
endpoint returns `503` if `SARVAM_API_KEY` is not configured.

### File scanning

```json
{
  "filePath": "C:\\data\\sample.exe"
}
```

Use `/api/yara/scan-file` to run a YARA scan. Its optional `rulesDir` field
selects a rules directory; otherwise the bundled `Yara Detection Model/Rules`
directory is used. `/api/scan-file` also accepts `{"engine": "yara"}` or a
`rulesDir` field to select YARA instead of malware classification.

### Anomaly detection

Train from records:

```json
{
  "records": [
    {"bytes": 1200, "packets": 16, "protocol": "tcp"},
    {"bytes": 900, "packets": 11, "protocol": "udp"}
  ],
  "contamination": 0.05
}
```

Then send a record to `/api/anomaly/detect`:

```json
{
  "record": {"bytes": 1500, "packets": 25, "protocol": "tcp"}
}
```

Batch requests use `{"records": [...]}` at `/api/anomaly/batch`. A first
detection request can include `baselineRecords` to train the detector lazily.

## Operational notes

- Keep API keys in environment variables or a secret manager, not in requests,
  source files, or committed configuration.
- The scanner accepts server-side file paths. Do not expose it to untrusted
  clients without adding authentication and restricting allowed paths.
- The anomaly detector is held in process memory; retraining is not persisted
  across server restarts unless a baseline CSV is configured.
- The bundled YARA subsystem parses supported rule constructs itself; it is not
  the upstream YARA engine.
