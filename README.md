# Access Security Posture Management

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://react.dev)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> Penetration testing for identity policies.

A security platform that **dynamically simulates access attempts** against your Okta tenant's authentication policies and flags cases where risky access is incorrectly allowed. Unlike static config scanners, this uses the Okta Policy Simulation API to test whether policies actually work under realistic threat conditions.

This is an open-source rebuild of a project originally presented at [Oktane 2025 — Build Your Own Security Tools Using Okta and Auth0 APIs](https://www.okta.com/oktane/on-demand/2025/showcase-build-your-own-security-tools-using-okta-and-auth0-apis/).

## Features

- **Policy Simulation** — Tests user x app x scenario combinations against Okta's policy engine. Reports when access is allowed that should be denied.
- **Posture Checks** — Static analysis of admin security and MFA gaps (the MGM/Caesars attack vectors: help desk MFA reset, shadow admins, weak factors).
- **Risk Scoring** — Composite 0-100 scores factoring severity, user privilege, app criticality, exposure breadth, and auth strength.
- **Vulnerability Lifecycle** — Tracks findings across scans with automatic remediation detection. No duplicates.
- **Reports** — CSV, PDF, and JSON exports.
- **Scheduled Scans** — Cron-based recurring scans with webhook notifications.
- **React Dashboard** — Full UI for running scans, viewing findings, and managing scenarios.

## Tech Stack

**Backend:** Python 3.13 · FastAPI · SQLAlchemy (async) · PostgreSQL 17 · Redis · SAQ
**Frontend:** React · TypeScript · Vite · TailwindCSS
**Infra:** Docker · Caddy (auto-TLS)

## Quick Start

### Prerequisites

- Docker & Docker Compose
- An [Okta API token](https://developer.okta.com/docs/guides/create-an-api-token/main/) with read access

### 1. Configure

```bash
git clone https://github.com/<your-username>/okta-access-security-posture-management.git
cd okta-access-security-posture-management
cp .env.example .env
```

Edit `.env` with your values:

```bash
OKTA_API_TOKEN=your-okta-api-token
OKTA_ORG=your-org                   # e.g. dev-12345678
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
```

### 2. Start

```bash
docker compose up -d
```

This launches everything — PostgreSQL, Redis, API server, background worker, and the React frontend. Tables are created automatically.

- **Dashboard:** http://localhost:5173
- **API docs:** http://localhost:8000/docs

## Usage

```bash
# Import default risk scenarios
curl -X POST http://localhost:8000/api/v1/scenarios/reset

# Run a single-user assessment
curl -X POST http://localhost:8000/api/v1/assessments/single \
  -H "Content-Type: application/json" \
  -d '{"email": "user@yourcompany.com"}'

# Run a full tenant scan (background)
curl -X POST http://localhost:8000/api/v1/assessments/batch \
  -H "Content-Type: application/json" \
  -d '{"user_selection": "all", "include_posture_checks": true}'

# View results
curl http://localhost:8000/api/v1/dashboard/summary
curl http://localhost:8000/api/v1/vulnerabilities?status=ACTIVE&severity=HIGH
curl http://localhost:8000/api/v1/posture/score
```

## Project Structure

```
src/
├── api/routes/             # 50 FastAPI endpoints
├── core/
│   ├── okta_client.py      # Okta API (retry, rate limiting, pagination)
│   ├── policy_simulator.py # Policy simulation engine
│   ├── assessment_engine.py
│   ├── vulnerability_engine.py
│   ├── risk_scorer.py
│   └── posture_checks/     # Admin security + MFA modules
├── models/                 # SQLAlchemy ORM (10 models)
├── tasks/                  # Background jobs (scans, health, retention)
└── reports/                # CSV, PDF, JSON generators
frontend/                   # React + TypeScript dashboard
```

## Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/assessments/single` | Single-user assessment |
| `POST` | `/api/v1/assessments/batch` | Full tenant scan |
| `GET` | `/api/v1/vulnerabilities` | List vulnerabilities (filterable) |
| `GET` | `/api/v1/posture/findings` | Posture check results |
| `GET` | `/api/v1/dashboard/summary` | Dashboard metrics |
| `POST` | `/api/v1/reports/generate` | Generate report (CSV/PDF/JSON) |
| `GET` | `/docs` | Interactive Swagger UI |

See http://localhost:8000/docs for the full API reference.

## Production Deployment

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Point your DNS to the server — Caddy handles HTTPS automatically. Min spec: 2 vCPU, 4GB RAM.

## Running Tests

```bash
pip install -e ".[dev]"
pytest
```

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `OKTA_API_TOKEN` | Yes | Okta SSWS API token |
| `OKTA_ORG` | Yes | Okta org subdomain |
| `SECRET_KEY` | Yes | App signing key |
| `ENCRYPTION_KEY` | Yes | Fernet key for token encryption |
| `MAX_WORKERS` | No | Concurrent API workers (default: `5`) |
| `RETENTION_DAYS` | No | Data retention period (default: `180`) |

See [`.env.example`](.env.example) for the full list.

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

## License

Apache 2.0

## Disclaimer

This tool only reads data and simulates policies via the read-only Policy Simulation API — it does not modify any Okta configuration. Use responsibly and in compliance with your Okta subscription terms. "Okta" is a registered trademark of Okta, Inc.
