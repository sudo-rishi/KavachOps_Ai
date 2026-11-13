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

For Spring-style deployment environments, `KAVACHOPSAI_SARVAM_API_KEY` is also
accepted. It corresponds to the property name
`kavachopsai.sarvam.api-key`; set it as an environment variable for the Python
process rather than adding the secret to source-controlled configuration.

Run the standalone Sarvam example from this directory with:

```powershell
python sarvam-api.py
```

It uses `glm5.3` by default; set `SARVAM_MODEL` to override it.

The server reads `ML_APP_HOST` (default `0.0.0.0`) and `ML_APP_PORT` (default
`5000`). For local-only access, set `ML_APP_HOST` to `127.0.0.1`. For deployment,
run with a production WSGI server such as Gunicorn rather than Flask's built-in
development server.

Optional configuration:

| Variable | Purpose | Default |
| --- | --- | --- |
| `SARVAM_API_KEY` / `KAVACHOPSAI_SARVAM_API_KEY` | Server-side key for Sarvam requests | Not configured |
| `SARVAM_MODEL` | Default Sarvam chat model | `glm5.3` |
| `SARVAM_ANALYSIS_MODEL` | Model used for anomaly/malware assessments and PDF reports | `glm5.3` |
| `IDS_BASELINE_CSV` | CSV used to train the anomaly detector at startup | Not configured |
| `ML_APP_HOST` | Flask bind address | `0.0.0.0` |
| `ML_APP_PORT` | Flask port | `5000` |

If `IDS_BASELINE_CSV` is not set, train the anomaly detector through the API
before requesting detections. Check `/api/health` to see which integrations are
available.

## Unified API

Endpoints return JSON unless noted; `/api/sarvam/report` returns a PDF
attachment. Scan endpoints use paths on the server hosting this application.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/` | Service status and endpoint list |
| `GET` | `/api/health` | Readiness of model integrations and Sarvam configuration |
| `POST` | `/api/sarvam/chat` | Send a chat request to Sarvam |
| `POST` | `/api/sarvam/report` | Generate a Sarvam-explained downloadable PDF from supplied analysis data |
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
  "model": "glm5.3",
  "messages": [
    {"role": "system", "content": "Answer concisely."},
    {"role": "user", "content": "Summarize this alert"}
  ]
}
```

The response is the JSON response from Sarvam. The API key remains on the
backend and is sent to Sarvam using the `api-subscription-key` header. The chat
endpoint returns `503` if neither supported API-key environment variable is configured.

### Sarvam-assisted detections and reports

`/api/anomaly/detect`, `/api/anomaly/batch`, and the malware/YARA scan endpoints
include a `sarvamAnalysis` assessment when Sarvam is configured. A suspicious AI
assessment can elevate the final verdict, but an AI benign assessment never
clears an anomaly, malware prediction, or YARA match. The original model result
is retained in `model_anomaly` or `modelVerdict`. If Sarvam is unavailable or
returns an invalid assessment, the response is marked `partial` and includes the
reason; the deterministic result remains available.

Malware analysis sends derived file metadata and model features to Sarvam, not
the file bytes or full local path. Set `SARVAM_ANALYSIS_MODEL` to choose another
model. Sarvam-assisted batch anomaly detection accepts up to 25 records.
Anomaly records and the `data` submitted for a report are sent to Sarvam; do not
include information that should not leave your environment.

Generate a downloadable PDF by posting analysis data to `/api/sarvam/report`:

```json
{
  "title": "Network anomaly report",
  "data": {
    "period": "2026-11-14",
    "detections": [
      {
        "anomaly": true,
        "anomaly_score": -0.31,
        "sarvamAnalysis": {
          "assessment": "suspicious",
          "summary": "The connection volume is unusual for this baseline."
        }
      }
    ]
  }
}
```

The endpoint returns an `application/pdf` attachment. Reports are AI-generated
and should be reviewed before taking action.

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
