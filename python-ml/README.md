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

For the standalone chat example, add `SARVAM_API_KEY=` to the project-root
`.env` file and paste the key there. `.env` is ignored by Git. The service itself
reads the key from its process environment. The unified Flask service also reads
`SARVAM_API_KEY`, `KAVACHOPSAI_SARVAM_API_KEY`, or
`kavachopsai.sarvam.api-key` from that root `.env` file when no process variable
is set; process variables take precedence:

```powershell
$env:SARVAM_API_KEY = "your-sarvam-api-key"
python app.py
```

For Spring-style deployment environments, `KAVACHOPSAI_SARVAM_API_KEY` is also
accepted. It corresponds to the property name
`kavachopsai.sarvam.api-key`; set it as an environment variable for the Python
process rather than adding the secret to source-controlled configuration.

The `/api/health` endpoint checks Sarvam connectivity with a read-only
`GET /v2/models` request and caches the result for 30 seconds. It reports
`configured` separately from `connected`, so the frontend can distinguish a
saved key from a reachable Sarvam API.

## Spring and frontend integration

The browser calls the Spring API; Spring proxies authenticated `/api/ml/*`
requests to the Python service. Set `PYTHON_ML_BASE_URL` when the services do
not share the default local network. Keep the Python service on a private
interface and do not expose its unauthenticated Flask routes publicly.

The backend requires `KAVACHOPSAI_JWT_SECRET` (at least 32 bytes). On a new
database, provision the first administrator explicitly by setting
`KAVACHOPSAI_BOOTSTRAP_ADMIN_ENABLED=true` and a unique
`KAVACHOPSAI_BOOTSTRAP_ADMIN_PASSWORD` of at least 12 characters, plus the
optional username/email variables. Admin bootstrap is disabled by default and
never resets an existing account's password or role.

To start the local full stack from the project root, ensure PostgreSQL is
running and the JWT secret is configured, then run
`.\run-kavachops.ps1`. It opens the Python ML service, Spring API, and frontend
in separate PowerShell windows; it does not start PostgreSQL or send a standalone
Sarvam chat request.

The CVE page imports `dataset/nvd_vulnerabilities_with_os.csv` only after an
administrator selects **Import bundled dataset**. Startup auto-import is off by
default; `KAVACHOPSAI_CVE_DATASET_PATH` can point to another trusted server-side
CSV, and the browser cannot submit arbitrary filesystem paths.

Run the standalone Sarvam example from this directory with:

```powershell
py -3.12 sarvam-api.py
```

It reads `SARVAM_API_KEY` from the process environment first, then the
project-root `.env`. As a fallback, it accepts `KAVACHOPSAI_SARVAM_API_KEY`,
including the dotted `kavachopsai.sarvam.api-key` property. It does not use the
VirusTotal setting. The script sends one chat completion request using `glm5.3`.

The server reads `ML_APP_HOST` (default `127.0.0.1`) and `ML_APP_PORT` (default
`5000`). If the services run in separate containers, bind Flask to a private
container interface and restrict network access to the Java backend. For
deployment, run with a production WSGI server such as Gunicorn rather than
Flask's built-in development server.

Optional configuration:

| Variable | Purpose | Default |
| --- | --- | --- |
| `SARVAM_API_KEY` / `KAVACHOPSAI_SARVAM_API_KEY` | Server-side key for Sarvam requests | Not configured |
| `SARVAM_MODEL` | Default Sarvam chat model | `glm5.3` |
| `SARVAM_ANALYSIS_MODEL` | Model used for anomaly/malware assessments and PDF reports | `glm5.3` |
| `IDS_BASELINE_CSV` | CSV used to train the anomaly detector at startup | Not configured |
| `ML_APP_HOST` | Flask bind address | `127.0.0.1` |
| `ML_APP_PORT` | Flask port | `5000` |
| `PYTHON_ML_BASE_URL` | URL the authenticated Spring ML gateway uses | `http://localhost:5000` |
| `KAVACHOPSAI_VIRUSTOTAL_API_KEY` | VirusTotal API key (or `kavachopsai.virustotal.api-key` in `.env`) | Not configured |
| `KAVACHOPSAI_VIRUSTOTAL_ENABLED` | Explicitly enable VirusTotal lookups | `false` |

If `IDS_BASELINE_CSV` is not set, train the anomaly detector through the API
before requesting detections. Check `/api/health` to see which integrations are
available.

VirusTotal requests are hash/IP lookups only; files are not uploaded. Successful
lookups are cached in-process for 24 hours, malware scan records are reused from
the database, requests are spaced by at least 16 seconds, and each running
backend instance is capped at 450 lookups per rolling 24 hours. HTTP 429
responses pause requests, and invalid credentials disable further lookups until
restart. These local guards do not increase VirusTotal account quotas. The
standard free public API shown in the account page is not permitted for business
workflows or commercial products; obtain an appropriately licensed plan before
using VirusTotal that way.

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
| `POST` | `/api/malware/analyze` | Sarvam advisory analysis of scan metadata |
| `POST` | `/api/yara/scan-file` | Scan a file with YARA rules |
| `POST` | `/api/anomaly/train` | Train the anomaly detector |
| `POST` | `/api/anomaly/detect` | Detect an anomaly in one record |
| `POST` | `/api/anomaly/batch` | Detect anomalies in multiple records |
| `POST` | `/api/model/retrain` | Compatibility endpoint for anomaly retraining |

The frontend does not call these Flask routes directly. It uses Spring's
authenticated proxy routes: `GET /api/ml/health`, `POST
/api/ml/anomaly/{detect,batch,train}`, `POST /api/ml/malware/analyze`, and
`POST /api/ml/sarvam/report`.

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

`/api/anomaly/detect` uses the detector only unless `includeSarvam: true` is
explicitly requested. `/api/anomaly/batch` accepts at most 25 records and
requests Sarvam analysis for the batch. The frontend's separate Sarvam-review
action is user-initiated. A suspicious AI assessment can elevate a verdict, but
a benign assessment never clears a deterministic anomaly, malware prediction,
or YARA match.

The frontend uses authenticated Java routes under `/api/ml/*`; the Java service
proxies requests to this Python service. Malware advisory analysis sends a
basename and scan metadata only, never file bytes or the local path. The Sarvam
report receives the aggregated data selected by the frontend. Review data before
enabling Sarvam because it is sent to the external Sarvam service. Set
`SARVAM_ANALYSIS_MODEL` to choose another model.

To train the anomaly detector, post a `records` array to `/api/anomaly/train`.
The UI's training action uses up to 500 recent packet-metadata records and
requires at least 20; choose representative benign traffic before training.

Generate a downloadable PDF by posting analysis data to `/api/sarvam/report`
(or through the authenticated frontend route `/api/ml/sarvam/report`):

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
