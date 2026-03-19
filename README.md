# Okta ASPM — Access Security Posture Management

> **Disclaimer:** This project is **not affiliated with, endorsed by, or officially associated with Okta, Inc.** in any way. "Okta" is a registered trademark of Okta, Inc. This is an independent, open-source security assessment tool that interacts with the publicly documented Okta API. Use at your own risk and in compliance with Okta's terms of service.

A security platform that tests whether your Okta tenant's authentication policies actually enforce access controls under risky conditions. It simulates access attempts via the Okta Policy Simulation API and flags policies that ALLOW access when they should DENY.

This solution was originally presented at [Oktane 2025 — Showcase: Build Your Own Security Tools Using Okta and Auth0 APIs](https://www.okta.com/oktane/on-demand/2025/showcase-build-your-own-security-tools-using-okta-and-auth0-apis/). It has since been rebuilt from the ground up and made open source for Okta administrators to use.

## Quick Start

### Prerequisites
- Docker & Docker Compose
- An Okta tenant with an API token (SSWS)

### 1. Configure environment

```bash
git clone <repo-url>
cd okta-access-security-posture-management
cp .env.example .env
```

Edit `.env` and fill in your Okta credentials:

```bash
OKTA_API_TOKEN=00aBcDeFgHiJkLmNoPqRsTuVwXyZ   # Your Okta SSWS API token
OKTA_ORG=your-company                            # Your Okta org subdomain
OKTA_ORG_TYPE=okta                               # "okta" or "oktapreview"
ENCRYPTION_KEY=<generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
```

### 2. Start the app

```bash
docker compose up -d
```

That's it. This starts PostgreSQL, Redis, the API server, and the background worker. Database tables are created automatically on first startup.

### 3. Open the API

- **http://localhost:8000/docs** — Interactive Swagger UI (test every endpoint)
- **http://localhost:8000/api/v1/health** — Health check
- **http://localhost:8000/api/v1/settings/health** — DB + Redis connectivity

## Usage

### Create risk scenarios

Before running scans, create risk scenarios that define what "risky access" looks like:

```bash
# Create a scenario: personal Windows device, medium risk
curl -X POST http://localhost:8000/api/v1/scenarios \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Personal Windows Device, Medium Risk",
    "description": "Unmanaged personal Windows device under medium risk",
    "risk_level": "MEDIUM",
    "device_platform": "WINDOWS",
    "device_registered": false,
    "device_managed": false
  }'
```

Or import all 6 default scenarios at once:

```bash
curl -X POST http://localhost:8000/api/v1/scenarios/import \
  -H "Content-Type: application/json" \
  -d '[
    {"name":"Personal Windows, Medium Risk","risk_level":"MEDIUM","device_platform":"WINDOWS","device_registered":false},
    {"name":"Personal macOS, Medium Risk","risk_level":"MEDIUM","device_platform":"MACOS","device_registered":false},
    {"name":"Personal ChromeOS, Medium Risk","risk_level":"MEDIUM","device_platform":"CHROMEOS","device_registered":false},
    {"name":"Personal Android, Medium Risk","risk_level":"MEDIUM","device_platform":"ANDROID","device_registered":false},
    {"name":"Personal iOS, Medium Risk","risk_level":"MEDIUM","device_platform":"IOS","device_registered":false},
    {"name":"Unknown Desktop, High Risk","risk_level":"HIGH","device_platform":"DESKTOP_OTHER","device_registered":false}
  ]'
```

### Run a single-user assessment

```bash
curl -X POST http://localhost:8000/api/v1/assessments/single \
  -H "Content-Type: application/json" \
  -d '{"email": "user@yourcompany.com"}'
```

This resolves the user, fetches their apps, simulates every scenario against every app, and persists the results.

### Run a full tenant scan

```bash
curl -X POST http://localhost:8000/api/v1/assessments/batch \
  -H "Content-Type: application/json" \
  -d '{
    "user_selection": "all",
    "include_posture_checks": true,
    "max_workers": 5,
    "generate_ai_summary": false
  }'
```

Returns a `scan_id` immediately. The scan runs in the background.

### Monitor scan progress

```bash
# Poll for status
curl http://localhost:8000/api/v1/assessments/{scan_id}

# Or stream real-time progress (SSE)
curl -N http://localhost:8000/api/v1/assessments/{scan_id}/stream
```

### View results

```bash
# Dashboard overview
curl http://localhost:8000/api/v1/dashboard/summary

# List vulnerabilities (with filters)
curl "http://localhost:8000/api/v1/vulnerabilities?status=ACTIVE&severity=HIGH"

# Posture findings
curl http://localhost:8000/api/v1/posture/findings

# Posture score (0-100)
curl http://localhost:8000/api/v1/posture/score
```

### Generate reports

```bash
# Generate a PDF report from a scan
curl -X POST http://localhost:8000/api/v1/reports \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "your-scan-id", "report_type": "pdf"}'

# Available report types: csv_full, csv_violations, csv_inactive, csv_posture, pdf, json, ai_summary
```

## Risk Scoring

Every vulnerability and posture finding receives a composite risk score from 0 to 100, calculated from six weighted factors:

| Factor | Max Points | Description |
|--------|-----------|-------------|
| **Severity** | 30 | Base weight from finding severity (CRITICAL=30, HIGH=25, MEDIUM=15, LOW=5) |
| **Scenario risk** | 15 | Risk level of the simulation scenario that triggered the finding (HIGH=12, MEDIUM=8, LOW=4) |
| **App criticality** | 15 | User-assigned criticality of the affected application (critical=15, high=12, medium=8, low=4) |
| **User privilege** | 15 | Whether the finding affects admin users (+10) or service accounts (+5) |
| **Exposure breadth** | 15 | Number of distinct users affected: >=100 users=15, >=50=12, >=10=8, >=1=4 |
| **Auth strength** | 10 | No MFA required=10, MFA but not phishing-resistant=5, phishing-resistant MFA=0 |

Risk scores are recalculated after each scan based on the actual number of affected users. A vulnerability affecting 3 users scores lower than one affecting 150 users, even if the severity is the same.

**Risk bands:** 0-25 Low, 26-50 Medium, 51-75 High, 76-100 Critical.

## Background Worker

For batch scans, scheduled jobs, and report generation, start the SAQ worker:

```bash
python -m saq src.tasks.worker.settings
```

This runs:
- Batch scan tasks (from `/api/v1/assessments/batch`)
- Report generation tasks
- Health monitoring (every 5 minutes — checks Okta API token validity)
- Data retention cleanup (daily at 3am — deletes data older than RETENTION_DAYS)

## Running Tests

```bash
# All unit/domain tests (no external services needed)
pytest tests/ --ignore=tests/test_api -v

# Integration tests (requires running API server + DB + Redis)
# In terminal 1: docker compose up db redis -d && uvicorn src.api.main:app
# In terminal 2:
pytest tests/test_api/ -v

# With coverage
pytest tests/ --ignore=tests/test_api --cov=src --cov-report=term-missing
```

## Project Structure

```
src/
├── api/              # FastAPI routes, middleware, error handling
│   └── routes/       # 10 route files (~40 endpoints)
├── core/             # Domain logic (Okta client, simulators, engines)
│   └── posture_checks/  # Admin security + MFA posture modules
├── models/           # 11 SQLAlchemy ORM models
├── schemas/          # Pydantic request/response schemas
├── tasks/            # SAQ background workers (scans, reports, health)
├── reports/          # CSV, PDF, JSON, AI summary generators
├── config.py         # Environment variable configuration
└── db.py             # Database engine and session management
```

## Key API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/assessments/single` | Run single-user assessment |
| POST | `/api/v1/assessments/batch` | Run full tenant scan |
| GET | `/api/v1/assessments/{id}` | Scan status and summary |
| GET | `/api/v1/vulnerabilities` | List vulnerabilities (filterable) |
| GET | `/api/v1/vulnerabilities/stats` | Aggregated statistics |
| GET | `/api/v1/posture/findings` | Posture check results |
| GET | `/api/v1/posture/score` | Aggregate posture score (0-100) |
| GET | `/api/v1/dashboard/summary` | Dashboard metrics |
| POST | `/api/v1/reports` | Generate report (CSV/PDF/JSON/AI) |
| GET | `/api/v1/scenarios` | List risk scenarios |
| POST | `/api/v1/schedules` | Create scheduled scan |
| GET | `/api/v1/settings/health` | System health check |
| GET | `/docs` | Interactive Swagger UI |

## Production Deployment

### Docker (VM / Cloud)

```bash
cp .env.example .env
# Edit .env with production values

docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
# Tables are created automatically on startup
```

This starts: PostgreSQL, Redis, backend (4 workers), SAQ worker, Caddy (auto-TLS).

Point your DNS A record to the VM IP — Caddy handles HTTPS automatically.

### Minimum VM spec
- 2 vCPU, 4GB RAM, 40GB disk
- Ubuntu 22.04+

## Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OKTA_API_TOKEN` | Yes | — | Okta SSWS API token |
| `OKTA_ORG` | Yes | — | Okta org subdomain |
| `OKTA_ORG_TYPE` | No | `okta` | `okta` or `oktapreview` |
| `ENCRYPTION_KEY` | Yes | — | Fernet key for token encryption |
| `DATABASE_URL` | No | `postgresql+asyncpg://aspm:aspm@localhost:5432/aspm` | PostgreSQL connection string |
| `REDIS_URL` | No | `redis://localhost:6379/0` | Redis connection string |
| `SECRET_KEY` | No | `change-me-in-production` | JWT/session signing key |
| `MAX_WORKERS` | No | `5` | Concurrent Okta API workers |
| `API_DELAY` | No | `0` | Delay (seconds) between users in batch scans |
| `RETENTION_DAYS` | No | `180` | Days to keep assessment data |
| `LLM_MODEL` | No | `azure/gpt-4o` | LiteLLM model string (any provider) |
| `ALLOWED_ORIGINS` | No | `http://localhost:5173` | CORS allowed origins (comma-separated) |

## Disclaimer

This software is provided "as is", without warranty of any kind. This project is **not affiliated with, endorsed by, or officially associated with Okta, Inc.** "Okta" is a registered trademark of Okta, Inc.

This tool makes API calls to your Okta tenant using credentials you provide. It does not modify any Okta configuration — it only reads data and simulates policies via the read-only Policy Simulation API. However, excessive API calls may consume your Okta rate limits. Use responsibly and in compliance with your Okta subscription terms.

The authors are not responsible for any consequences arising from the use of this software, including but not limited to rate limit consumption, service disruption, or security incidents.
