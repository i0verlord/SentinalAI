# SentinelAI

A local log anomaly and threat triage demo. The stack ingests Nginx access logs and Linux SSH auth logs, aggregates per-IP one-minute activity, flags unusual windows with IsolationForest, and presents the evidence in a Next.js operations dashboard.

## Run the full stack

Requirements: Docker Desktop with Compose enabled.

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Open the dashboard at [http://localhost:3000](http://localhost:3000) and the API docs at [http://localhost:8000/docs](http://localhost:8000/docs). PostgreSQL data persists in the `postgres_data` volume. To stop the services, run `docker compose down`.

## Try it

- Select **Simulate traffic** to load several minutes of ordinary requests plus a directory-probing spike and SSH login failures.
- Select **Upload logs** to ingest a `.log` or `.txt` file in Nginx access-log or Linux SSH auth-log format. The parser auto-detects each line; malformed lines are counted as skipped.
- Select an alert row to inspect the bounded raw-evidence sample. AI triage is optional and does not block ingestion or detection.

Sample files are in `samples/`. The upload endpoint accepts files up to 10 MB. The API keeps raw log lines in PostgreSQL; use synthetic or appropriately sanitized data when trying the demo.

## Security and data

This demo has no authentication and is intended for local, trusted use only. Raw events persist in the PostgreSQL volume under Compose or in the SQLite database during local development. An LLM receives up to 20 raw lines only when triage is explicitly requested; review your provider's data-retention policy before sending sensitive logs. Suggested remediation is never executed.

## Configure AI triage

Set the provider URL, key, and model in `.env`, then restart the API:

```dotenv
LLM_BASE_URL=https://api.openai.com/v1
LLM_API_KEY=your-key
LLM_MODEL=gpt-4o-mini
```

`LLM_BASE_URL` is the API base URL; `/chat/completions` is appended when absent. Triage sends at most 20 lines from one flagged IP/minute window and validates the returned JSON against the incident schema. Without configuration, alerts remain usable and triage is marked unavailable. Suggested remediation is displayed only; it is never run automatically.

## Local development

API (Python 3.11+, from `services/api`):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:DATABASE_URL = "sqlite:///./sentinelai.db"
alembic upgrade head
uvicorn app.main:app --reload
pytest
```

Frontend (from `apps/web`):

```powershell
npm ci
npm run dev
npm run lint
npm run typecheck
npm run build
```

Set `NEXT_PUBLIC_API_URL` to the API base (default `http://localhost:8000/api`) when the frontend runs outside Compose. The backend defaults to SQLite for local development and uses PostgreSQL in Compose.

## API outline

- `POST /api/ingestion/upload` — multipart file upload; optional `format=auto|nginx|ssh`.
- `POST /api/ingestion/simulate` — insert deterministic test traffic and run detection.
- `GET /api/dashboard/overview` and `GET /api/dashboard/traffic` — KPI and chart data.
- `GET /api/alerts` and `GET /api/alerts/{id}` — alert summaries and evidence.
- `POST /api/alerts/{id}/triage` — request a validated LLM assessment.
- `GET /health` and `GET /health/ready` — liveness and database readiness checks.

## Detection notes

Events are grouped by UTC minute and source IP. The model features are requests per minute, HTTP 4xx/5xx percentage, unique HTTP endpoints, and SSH failures. IsolationForest prediction and decision score are kept separate; sparse data also uses explicit thresholds so a fresh local demo can still surface brute-force and request-spike behavior. A score shown in the UI is the model's negative decision-function value (or a positive rule score for threshold-only detections), not a probability.
