# Build: Okta Access Security Posture Management (ASPM) Platform

## Overview
Build a production-grade Okta ASPM platform. The system performs **dynamic policy simulation** — testing whether an Okta tenant's authentication policies actually enforce access controls under risky conditions — combined with **static posture checks** covering admin security and MFA gaps. It simulates access attempts via the Okta Policy Simulation API, flags cases where policies ALLOW access that should be DENIED, and provides risk-scored findings with remediation guidance.

**Positioning:** "Penetration testing for identity policies." Unlike SSPM competitors that perform static configuration checks, this platform dynamically validates policy enforcement through simulation.

## Tech Stack
- **Backend:** Python 3.13+, FastAPI, async (httpx for HTTP, asyncio for concurrency)
- **Frontend:** React + TypeScript + Vite + TailwindCSS + shadcn/ui
- **Database:** PostgreSQL 17 (via SQLAlchemy async ORM + Alembic migrations)
- **Task Queue:** SAQ (async-native Redis queue with built-in cron, progress tracking, and web dashboard)
- **Auth:** OAuth2/OIDC via Okta
- **Secrets:** Fernet encryption for Okta API tokens
- **PDF Reports:** fpdf2 (pure Python, no system dependencies, supports HTML via `write_html()`)
- **Containerization:** Docker + docker-compose (PostgreSQL, Redis, backend, frontend, Caddy reverse proxy)
- **Testing:** pytest + pytest-asyncio + httpx test client
- **Logging:** structlog (JSON-formatted)

### Key design choices
- **SAQ** over ARQ (unmaintained) / Celery (async friction): async-native, built-in cron/progress/web UI
- **Caddy**: zero-config TLS. **fpdf2**: pure Python PDF, no system deps
- **PostgreSQL 17**: better JSON perf. **Python 3.13**: no-GIL build available

## Build Order

Development is organized into sequential milestones. Each milestone produces a working, testable increment.

### Milestone 1: Core Simulation Loop
Build and test the Okta API client and policy simulator against mocked responses. This is the heart of the system — nothing else matters until this works.
- `src/core/okta_client.py` — HTTP calls with retry logic, pagination, rate limiting
- `src/core/policy_simulator.py` — Build payloads, parse simulation responses, extract rule actions
- `src/core/risk_scenarios.py` — Scenario model + 6 built-in default scenarios
- `tests/test_okta_client.py`, `tests/test_policy_simulator.py` — Mocked Okta API responses
- **Done when:** You can simulate a policy for one user × one app × one scenario against mocked data and get ALLOW/DENY.

### Milestone 2: Single-User Assessment + Database
Wire up PostgreSQL, create models, persist assessment results. Run a real scan for one user.
- `src/db.py` — Async engine, session factory
- `src/models/` — Base, Scenario, AssessmentResult, Vulnerability, VulnerabilityImpact, Scan
- `src/core/assessment_engine.py` — Orchestrates the single-user flow
- `src/core/vulnerability_engine.py` — Detection + lifecycle (idempotent upsert)
- `src/core/log_analyzer.py` — Parse system logs for login patterns
- `src/api/routes/assessments.py` — `POST /api/v1/assessments/single`
- `alembic/` — Initial migration
- **Done when:** You can POST an email, scan a real Okta user, and see persisted results in the DB.

### Milestone 3: Batch Scan + Background Worker
Support scanning all users via SAQ background task with progress tracking.
- `src/tasks/worker.py` — SAQ worker settings
- `src/tasks/tenant_scan.py` — Batch scan task with per-user persistence, resumability
- `src/api/routes/assessments.py` — `POST /api/v1/assessments/batch`, `GET /api/v1/assessments/{scan_id}`
- SSE endpoint for real-time progress via Redis pub/sub
- **Done when:** You can kick off a batch scan, see progress in real-time, and resume after a crash.

### Milestone 4: Vulnerability Dashboard + API
Expose findings through the API. Build the dashboard backend.
- `src/api/routes/vulnerabilities.py` — CRUD + stats + filters
- `src/api/routes/dashboard.py` — Summary metrics, severity breakdown
- `src/core/risk_scorer.py` — Composite risk scoring (0-100)
- **Done when:** The API returns paginated, filtered vulnerabilities with risk scores.

### Milestone 5: Posture Checks (2 modules)
Add static posture checks — admin security and MFA posture only. These cover the MGM/Caesars attack vectors.
- `src/core/posture_checks/admin_security.py` — Super admin count, shadow admins, help desk MFA reset, inactive admins
- `src/core/posture_checks/mfa_posture.py` — Weak factors, no MFA enrolled, phishing-resistant coverage
- `src/models/posture_finding.py` — PostureFinding model
- `src/api/routes/posture_checks.py`
- **Done when:** A scan produces posture findings alongside simulation results.

### Milestone 6: Reports
Generate CSV, PDF, and JSON reports from persisted data.
- `src/reports/csv_generator.py`
- `src/reports/pdf_generator.py` — fpdf2 with `write_html()` for tables and formatting
- `src/reports/json_generator.py`
- `src/api/routes/reports.py`
- **Done when:** You can generate and download CSV, PDF, and JSON reports for any past scan.

### Milestone 7: Frontend
Build the React dashboard. (Frontend architecture defined in separate spec or discovered during development.)
- Pages: Login, Dashboard, Scan History, Scan Detail, Vulnerabilities List, Vulnerability Detail, Scenarios CRUD, Settings, Reports
- State management: TanStack Query for server state
- Auth: Okta OIDC redirect flow
- **Done when:** A user can log in, run a scan, see results, and download reports through the UI.

### Milestone 8: Operational Features
Add the features that make the product production-ready.
- `src/tasks/health_monitor.py` — Periodic Okta token health check
- `src/tasks/data_retention.py` — Daily cleanup of old assessment data
- `src/models/audit_log.py` + audit logging middleware
- `src/api/routes/schedules.py` — Scheduled scan CRUD
- `src/api/routes/notifications.py` — Webhook notification channels
- `src/core/notifier.py` — Webhook dispatcher
- **Done when:** Scans run on schedule, findings fire webhooks, old data gets cleaned up, all mutations are audited.

## Project Structure
```
aspm/
├── alembic/
│   └── versions/
├── src/
│   ├── api/
│   │   ├── routes/
│   │   │   ├── assessments.py
│   │   │   ├── vulnerabilities.py
│   │   │   ├── scenarios.py
│   │   │   ├── posture_checks.py
│   │   │   ├── reports.py
│   │   │   ├── schedules.py
│   │   │   ├── settings.py
│   │   │   ├── notifications.py
│   │   │   └── dashboard.py
│   │   ├── dependencies.py     # FastAPI DI (DB sessions, OktaClient, RBAC)
│   │   ├── middleware.py       # CORS, request logging
│   │   └── errors.py          # Structured error responses + global exception handler
│   ├── core/
│   │   ├── okta_client.py
│   │   ├── policy_simulator.py
│   │   ├── posture_checks/
│   │   │   ├── admin_security.py
│   │   │   └── mfa_posture.py
│   │   ├── assessment_engine.py
│   │   ├── vulnerability_engine.py
│   │   ├── risk_scenarios.py
│   │   ├── risk_scorer.py
│   │   ├── log_analyzer.py
│   │   ├── notifier.py
│   │   └── crypto.py
│   ├── models/
│   │   ├── base.py
│   │   ├── vulnerability.py
│   │   ├── vulnerability_impact.py
│   │   ├── scenario.py
│   │   ├── posture_finding.py
│   │   ├── scan.py
│   │   ├── assessment_result.py
│   │   ├── job.py
│   │   ├── report.py
│   │   ├── audit_log.py
│   │   └── notification_channel.py
│   ├── schemas/                # Pydantic request/response schemas
│   ├── tasks/
│   │   ├── worker.py
│   │   ├── tenant_scan.py
│   │   ├── report_generation.py
│   │   ├── data_retention.py
│   │   └── health_monitor.py
│   ├── reports/
│   │   ├── csv_generator.py
│   │   ├── pdf_generator.py
│   │   ├── json_generator.py
│   ├── db.py
│   └── config.py
├── frontend/
├── tests/
│   ├── conftest.py
│   ├── test_okta_client.py
│   ├── test_policy_simulator.py
│   ├── test_posture_checks.py
│   ├── test_risk_scorer.py
│   ├── test_assessment_engine.py
│   ├── test_vulnerability_engine.py
│   └── test_api/
├── docker-compose.yml
├── docker-compose.prod.yml
├── Dockerfile
├── Caddyfile
└── pyproject.toml
```

## CORE LOGIC — Okta API Integration

### Authentication
All Okta API calls use SSWS token auth:
```
Authorization: SSWS {OKTA_API_TOKEN}
Content-Type: application/json
Accept: application/json
```
Base URL pattern: `https://{OKTA_ORG}.{OKTA_ORG_TYPE}.com` where ORG_TYPE is `okta` or `oktapreview`.

Okta API tokens are encrypted via Fernet before storage in PostgreSQL. Decrypted in-memory only when making API calls.

### Okta API Endpoints to Implement

#### 1. List All Users (with pagination)
- `GET /api/v1/users?limit=200`
- Follow pagination via `Link` header: parse `<url>; rel="next"` to get next page URL
- Continue until no `rel="next"` link exists
- Returns: `{id, status, lastLogin, profile: {login, email, firstName, lastName, department}}`

#### 2. Get User by Login/Email
- `GET /api/v1/users/?search=profile.login eq "{email}"`
- URL-encode the search parameter. Returns array (take first match).

#### 3. Get User by ID
- `GET /api/v1/users/{user_id}`

#### 4. Get User's Assigned Applications
- `GET /api/v1/apps?filter=user.id+eq+"{user_id}"+or+status+eq+"ACTIVE"&expand=user/{user_id}&limit=200`
- Returns: `{id, name, label, status, signOnMode}`

#### 5. Policy Simulation (THE CORE API)
- `POST /api/v1/policies/simulate?expand=RULE`
- Request body:
```json
{
  "policyTypes": [],
  "appInstance": "{app_id}",
  "policyContext": {
    "user": {"id": "{user_id}"},
    "risk": {"level": "LOW|MEDIUM|HIGH"},
    "device": {
      "platform": "WINDOWS|MACOS|CHROMEOS|ANDROID|IOS|DESKTOP_OTHER|MOBILE_OTHER",
      "registered": true|false,
      "managed": true|false,
      "assuranceId": "{optional_device_assurance_id}"
    },
    "ip": "{optional_ip_address}",
    "zones": {"ids": ["{optional_zone_id}"]}
  }
}
```
- `ip` and `zones` are mutually exclusive
- Response `evaluation[]` → find `policyType: ACCESS_POLICY` → find `rules[]` with `status: MATCH`

#### 6. Get Policy Rule Details
- `GET /api/v1/policies/{policy_id}/rules/{rule_id}`
- Returns `actions.appSignOn.access` = "ALLOW" or "DENY"
- Also `actions.appSignOn.verificationMethod`: `factorMode`, `reauthenticateIn`, `constraints[].possession.phishingResistant`

#### 7. Get System Logs (per user per app)
- `GET /api/v1/logs?since={iso8601_90days_ago}&until={iso8601_now}&limit=200&sortOrder=DESCENDING&filter=actor.id+eq+"{user_id}"+and+target.id+eq+"{app_id}"`
- Returns: `{eventType, published, client: {ipAddress, geographicalContext}, securityContext: {asOrg, isp}}`

#### 8. Get Org Info (health check)
- `GET /api/v1/org` — Lightweight token validity check.

#### 9. Additional APIs for Posture Checks
- `GET /api/v1/users/{user_id}/factors` — enrolled MFA factors per user
- `GET /api/v1/policies?type=OKTA_SIGN_ON` — global session policies
- `GET /api/v1/policies?type=MFA_ENROLL` — MFA enrollment policies
- `GET /api/v1/policies?type=ACCESS_POLICY` — app sign-on policies
- `GET /api/v1/zones` — network zone definitions
- `GET /api/v1/idps` — identity provider configurations (rogue IdP detection)
- `GET /api/v1/roles` — admin roles and assignments
- `GET /api/v1/groups/{group_id}/roles` — group-based admin assignments (shadow admin detection)

### Rule Action Caching
During a scan, the same policy rule gets fetched potentially hundreds of times (N users × M apps can hit the same rule). Use an in-memory dict cache keyed by `(policy_id, rule_id)` that lives for the duration of a scan. Clear the cache when the scan ends.

### Concurrency & Rate Limiting (CRITICAL)
- Async semaphore to limit concurrent Okta API calls (default: 5 workers)
- Exponential backoff with jitter: base 2s, doubles each retry (2→4→8→16→32), random jitter 0-3s, max 5 retries
- HTTP 429 with Okta error `E0000047` → fail the assessment for that user, don't retry
- Retry on: 429, 5xx, ConnectionError, Timeout, DNS failures
- Do NOT retry on: 4xx (except 429)
- **Adaptive throttling:** Read `X-Rate-Limit-Remaining` header; if < 10%, add 1-second delay between calls

### Thread Safety for Policy Simulation
The simulation API is stateful on Okta's side — concurrent requests can contaminate each other.
- Deep-copy all simulation payloads before sending
- Validate user_id in payload matches expected user before and after building
- Log warnings on mismatch

## CORE LOGIC — Assessment Engine

### Single User Assessment Flow
1. **Resolve user** by email → extract `id`, `status`, `lastLogin`
2. **Fetch apps** assigned to user
3. **For each app × each active risk scenario:**
   a. Build simulation payload (deep-copied)
   b. Call policy simulation API
   c. Parse response: find ACCESS_POLICY → MATCH'd rule
   d. Call rule details API (cached) → ALLOW or DENY
   e. Persist result to `assessment_results` table regardless of outcome
   f. If ALLOW → record as vulnerability, calculate risk score
   g. Extract verificationMethod for auth strength analysis
4. **For each app:** fetch system logs
   a. Parse last login date, MFA methods, login locations
   b. If no login in 90 days → flag as inactive app user
5. **Persist** all results to DB

### Batch Scan Flow
1. Get user list (all users with pagination, or specific subset)
2. Run single-user assessment concurrently (configurable max workers)
3. **Persist per-user results to DB as they complete** (not at the end)
4. **Update `last_processed_user_index`** on JobExecution after each user (for resumability)
5. Run posture checks (once per scan, not per user)
6. Calculate risk scores for all findings
7. Update vulnerability lifecycle (idempotent upsert)
8. Generate reports
9. Fire webhook notifications

### Scan Resumability
1. `JobExecution` tracks `last_processed_user_index`
2. On resume: query `assessment_result` for user_ids already processed for this scan_id, skip them
3. Frontend shows "Resume" button on failed/stale scans

### Partial Failure Handling
A scan that processes 4997 out of 5000 users is not "failed" — it's "completed with errors."
- `JobExecution.status` includes `completed_with_errors` in addition to `pending`, `running`, `completed`, `failed`
- `JobExecution.failed_user_details` is a JSON array: `[{"user_id": "...", "user_email": "...", "error": "..."}]`
- Resume can optionally retry only the failed users

### Concurrent Scan Safety
Prevent two scans from processing the same user simultaneously:
- Before processing a user, check if another running scan already has assessment_results for that user_id with a `created_at` within the last 10 minutes
- If so, skip that user (the other scan is handling them)
- This prevents the vulnerability lifecycle race condition where scan A resolves impacts that scan B just created

## CORE LOGIC — Risk Scenarios

### Scenario Data Model
```
Scenario {
  id: UUID
  name: string
  description: string
  is_active: boolean
  risk_level: enum(LOW, MEDIUM, HIGH)
  device_platform: enum(WINDOWS, MACOS, CHROMEOS, ANDROID, IOS, DESKTOP_OTHER, MOBILE_OTHER)
  device_registered: boolean
  device_managed: boolean (optional)
  device_assurance_id: string (optional)
  ip_address: string (optional)
  zone_ids: string[] (optional)
  created_at: datetime
  updated_at: datetime
}
```

### Built-in Default Scenarios
1. **Personal Windows Device, Medium Risk** — risk=MEDIUM, platform=WINDOWS, registered=false, managed=false
2. **Personal macOS Device, Medium Risk** — risk=MEDIUM, platform=MACOS, registered=false, managed=false
3. **Personal ChromeOS Device, Medium Risk** — risk=MEDIUM, platform=CHROMEOS, registered=false, managed=false
4. **Personal Android Device, Medium Risk** — risk=MEDIUM, platform=ANDROID, registered=false, managed=false
5. **Personal iOS Device, Medium Risk** — risk=MEDIUM, platform=IOS, registered=false, managed=false
6. **Unknown Desktop Device, High Risk** — risk=HIGH, platform=DESKTOP_OTHER, registered=false, managed=false

A well-configured Okta tenant should DENY access for all of these.

## CORE LOGIC — Posture Checks (v1: 2 modules)

v1 ships with the two highest-value modules — admin security and MFA posture — because these cover the MGM/Caesars attack vectors. Additional modules (API token hygiene, app config, network zones, device trust, IdP config) use the same `PostureFinding` model and are added incrementally in v1.1.

### Admin Security Checks
| Check | Severity | Description |
|---|---|---|
| Super Admin count | HIGH | Flag if > 4 Super Admin accounts |
| Super Admin without phishing-resistant MFA | CRITICAL | Admins must use FIDO2/FastPass, not SMS |
| Super Admin without device/zone restrictions | HIGH | Admin access should require managed device + trusted network |
| Help desk can reset admin MFA | CRITICAL | The MGM attack vector |
| Shadow admin detection | HIGH | Users with admin-equivalent permissions via group membership |
| Inactive admin accounts | HIGH | Admin accounts with no login in 30+ days |

### MFA Posture Checks
| Check | Severity | Description |
|---|---|---|
| Users with only weak MFA factors | HIGH | SMS, voice call, security questions are phishable |
| Users with no MFA enrolled | CRITICAL | Single-factor access to any app |
| MFA enrollment policy gaps | MEDIUM | Enrollment policy doesn't require strong factors |
| Phishing-resistant MFA coverage | HIGH | % of users with FIDO2/FastPass enrolled |
| Direct auth without MFA | HIGH | Users accessing apps outside SSO without MFA |

### v1.1 Posture Modules (add incrementally)
- **API Token Hygiene** — token age, privilege level, usage recency
- **App Sign-On Configuration** — SWA vs SAML/OIDC, unsigned assertions, missing policies
- **Network Zone Assessment** — zone coverage, admin restrictions, overly broad zones
- **Device Trust Coverage** — device assurance gaps per app/platform
- **IdP Configuration Audit** — rogue IdP detection (the MGM attack vector), stale IdP configs

### Posture Finding Data Model
```
PostureFinding {
  id: UUID
  scan_id: FK
  check_category: enum(admin_security, mfa_posture, api_token_hygiene, app_config, network_zones, device_trust, idp_config, security_events)
  check_name: string
  severity: enum(CRITICAL, HIGH, MEDIUM, LOW)
  status: enum(OPEN, RESOLVED, ACKNOWLEDGED, FALSE_POSITIVE)
  title: string
  description: string
  affected_resources: JSON
  remediation_steps: string
  compliance_mappings: JSON (nullable)  # Populated when compliance mapper is built (v1.1+)
  risk_score: integer
  first_detected: datetime
  last_detected: datetime
  resolved_at: datetime (nullable)
  created_at: datetime
}
```

## CORE LOGIC — Okta System Log Security Events

During a scan, fetch and flag critical security events from the past 7 days. These become PostureFinding records with category `security_events`:

| Event Type | Severity | Why |
|---|---|---|
| `user.account.privilege.grant` | CRITICAL | Admin role granted |
| `user.mfa.factor.reset_all` | CRITICAL | All MFA factors reset (MGM vector) |
| `system.mfa.factor.deactivate` | CRITICAL | System-level MFA deactivation |
| `system.idp.lifecycle.create` | CRITICAL | Rogue IdP created (MGM vector) |
| `security.threat.detected` | CRITICAL | ThreatInsight detection |
| `group.privilege.grant` | HIGH | Admin via group |
| `user.mfa.factor.deactivate` | HIGH | Single MFA factor removed |
| `system.idp.lifecycle.update` | HIGH | IdP config modified |
| `policy.lifecycle.delete` | HIGH | Policy deleted |
| `policy.rule.delete` | HIGH | Rule deleted |
| `system.org.rate_limit.violation` | HIGH | Possible brute force |
| `user.account.report_suspicious_activity_by_enduser` | HIGH | User-reported suspicious activity |
| `policy.lifecycle.update` | MEDIUM | Policy modified |
| `policy.rule.update` | MEDIUM | Rule modified |
| `system.api_token.create` | MEDIUM | New API token |

## CORE LOGIC — Risk Scoring

### Composite Risk Score (0-100)
Every vulnerability and posture finding gets a composite score based on:
- **Base severity weight (0-30):** CRITICAL=30, HIGH=22, MEDIUM=14, LOW=6
- **Scenario risk factor (0-15):** HIGH=15, MEDIUM=10, LOW=5 (simulation findings only)
- **App criticality factor (0-15):** User-assigned per app (critical=15, high=10, medium=5, low=2)
- **User privilege factor (0-15):** Admin users=15, service accounts=10
- **Exposure breadth factor (0-15):** >100 users=15, >20=10, >5=5
- **Auth strength factor (0-10):** No MFA=10, MFA but not phishing-resistant=5

**Bands:** 0-25 Low, 26-50 Medium, 51-75 High, 76-100 Critical

## CORE LOGIC — Compliance Mapping (v1.1)

Not built in v1. The `compliance_mappings` JSON field exists on Vulnerability and PostureFinding models (nullable, defaults to null) so no migration is needed when this is built.

When built, maps each finding type to:
- **Tier 1:** NIST CSF 2.0, NIST 800-63 (AAL levels), CIS Controls v8
- **Tier 2:** SOC 2 Type II (CC6.x), ISO 27001:2022, MITRE ATT&CK
- **Tier 3:** HIPAA, PCI DSS v4.0, FedRAMP, custom frameworks

## CORE LOGIC — Vulnerability Detection & Lifecycle

### Vulnerability Types
**1. Authentication Policy Violation (dynamic severity)** — Policy simulation returns ALLOW for a risky scenario. Grouped by `rule_id`. Severity is determined by the authentication strength required by the matched rule:

| Simulation Result | MFA Required | Phishing-Resistant | Severity |
|---|---|---|---|
| ALLOW | No (`factorMode` is null, empty, or `1FA`) | N/A | **CRITICAL** |
| ALLOW | Yes | No | **HIGH** |
| ALLOW | Yes | Yes | **MEDIUM** |

This logic lives in `determine_policy_violation_severity()` in `src/core/vulnerability_engine.py`. It is used by both the vulnerability engine (to set `Vulnerability.severity`) and the assessment engine (to feed the correct severity into `RiskInput` for composite risk scoring). When an existing vulnerability is re-detected with a worse auth strength, severity is escalated (never downgraded).

**2. Inactive App User (severity: MEDIUM)** — No login activity for a user-app pair in 90 days. Grouped by `app_id`.

### Vulnerability Data Model
```
Vulnerability {
  id: UUID
  title: string
  description: string
  category: enum(auth_policy_violation, inactive_app_users)
  severity: enum(CRITICAL, HIGH, MEDIUM, LOW)
  status: enum(ACTIVE, REMEDIATED, ACKNOWLEDGED)
  risk_score: integer
  risk_factors: JSON
  compliance_mappings: JSON (nullable)
  policy_name: string (nullable)
  policy_id: string (nullable)
  rule_name: string (nullable)
  rule_id: string (nullable)
  app_name: string (nullable)
  app_id: string (nullable)
  active_impact_count: integer
  first_detected: datetime
  last_detected: datetime
  remediated_at: datetime (nullable)
  created_at: datetime
  updated_at: datetime
}
```

### Vulnerability Impact
```
VulnerabilityImpact {
  id: UUID
  vulnerability_id: FK
  scan_id: FK
  user_id: string
  user_email: string
  user_name: string
  app_name: string (optional)
  app_id: string (optional)
  scenario_name: string (optional)
  status: enum(ACTIVE, RESOLVED)
  first_detected: datetime
  last_detected: datetime
  resolved_at: datetime (nullable)
}
```

### Vulnerability Lifecycle (per scan)
1. **Pre-scan**: Mark ALL existing ACTIVE impacts for the scanned user as RESOLVED
2. **During scan**: Upsert — look up existing vulnerability by grouping key, create or reactivate impact
3. **Post-scan**: Count ACTIVE impacts per vulnerability. If 0 → REMEDIATED. If >0 → ACTIVE.
4. **Consistency check**: Periodically verify impact counts match actual records.

### Assessment Result Data Model
```
AssessmentResult {
  id: UUID
  scan_id: FK
  user_id: string
  user_email: string
  app_id: string
  app_name: string
  scenario_id: FK (nullable)
  scenario_name: string
  policy_id: string (nullable)
  policy_name: string (nullable)
  rule_id: string (nullable)
  rule_name: string (nullable)
  access_decision: enum(ALLOW, DENY, NO_MATCH)
  factor_mode: string (nullable)
  reauthenticate_in: string (nullable)
  phishing_resistant: boolean (nullable)
  created_at: datetime
}
```

This table is the **source of truth** for all assessment data. Reports are generated from this table, not ephemeral data.

## CORE LOGIC — Report Generation

Reports query `assessment_results`, `vulnerabilities`, and `posture_findings` tables. Any report can be regenerated at any time from persisted data.

### Report Metadata Model
```
Report {
  id: UUID
  scan_id: FK
  report_type: enum(csv_full, csv_violations, csv_inactive, csv_posture, pdf, json)
  file_path: string (nullable)
  content: text (nullable)
  generated_at: datetime
  created_at: datetime
}
```

### PDF Reports
Use fpdf2 with `write_html()` for table-based reports. Pure Python, no system dependencies, works identically in Docker and local dev.

## CORE LOGIC — Notifications

### Notification Channel Model (webhook only)
```
NotificationChannel {
  id: UUID
  name: string
  channel_type: enum(webhook)
  config: JSON {url, headers, secret}
  events: string[]
  is_active: boolean
  created_at: datetime
  updated_at: datetime
}
```

### Events
| Event | Trigger |
|---|---|
| `scan_completed` | Scan finishes (success, failure, or completed_with_errors) |
| `new_vulnerabilities` | HIGH/CRITICAL vulnerabilities found |
| `posture_critical` | CRITICAL posture finding detected |
| `token_health` | Okta API token invalid or rate limit critically low |

Webhooks cover Slack, Teams, PagerDuty, Splunk HEC, and any custom endpoint.

## Scheduled Scans (SAQ-based)

### How scheduling works
The database `ScheduledJob` table is the **single source of truth**. SAQ does NOT use static cron_jobs for user-created schedules. On worker startup, load all active ScheduledJob records from DB and register them with SAQ. On worker restart, reload from DB.

SAQ's built-in cron is only used for system tasks (health checks, data retention) — not for user-created schedules.

### Job Configuration
```
ScheduledJob {
  id: UUID
  name: string
  description: string
  is_active: boolean
  schedule_type: enum(cron, interval, once)
  cron_expression: string (nullable)
  interval_seconds: integer (nullable)
  run_at: datetime (nullable)
  scan_config: ScanConfig (validated via Pydantic on read/write, stored as JSON)
  last_run_at: datetime (nullable)
  next_run_at: datetime (nullable)
  created_at: datetime
  updated_at: datetime
}
```

### ScanConfig (Pydantic model, serialized to JSON)
```
ScanConfig {
  user_selection: enum(all, limited, specific)
  max_users: integer (nullable)
  specific_users: string[] (nullable)
  include_deactivated: boolean = false
  include_posture_checks: boolean = true
  max_workers: integer = 5
  api_delay: float = 0
}
```

This is validated by Pydantic on every write and read. The DB column is JSON, but the application layer enforces the schema. When you add a new config option, Pydantic handles defaults for old records missing the field.

### Execution History
```
JobExecution {
  id: UUID
  job_id: FK (nullable for manual runs)
  job_name: string
  started_at: datetime
  completed_at: datetime (nullable)
  status: enum(pending, running, completed, completed_with_errors, failed)
  total_users: integer
  successful_users: integer
  failed_users: integer
  failed_user_details: JSON (nullable)    # [{user_id, user_email, error}]
  posture_findings_count: integer
  last_processed_user_index: integer (default: 0)
  progress_pct: float (nullable)
  duration_seconds: float (nullable)
  error_message: string (nullable)
  created_at: datetime
}
```

## CORE LOGIC — Audit Trail

```
AuditLog {
  id: UUID
  actor_email: string
  actor_role: string
  action: enum(scan_started, scan_resumed, vulnerability_acknowledged, vulnerability_status_changed, scenario_created, scenario_updated, scenario_deleted, schedule_created, schedule_updated, schedule_deleted, tenant_config_updated, notification_channel_created, notification_channel_updated, notification_channel_deleted, report_generated)
  resource_type: string
  resource_id: string
  details: JSON (nullable)
  ip_address: string
  created_at: datetime
}
```

Append-only. No UPDATE or DELETE, ever. No retention policy.

## CORE LOGIC — Other Operational Features

### Real-Time Scan Progress (SSE)
`GET /api/v1/assessments/{scan_id}/stream` — SSE endpoint via Redis pub/sub. Publishes after each user completes.

### Data Retention
Daily SAQ cron at 3am. Delete `assessment_result`, `report`, `posture_finding`, `job_execution` rows older than `RETENTION_DAYS`. Do NOT delete `vulnerability`, `vulnerability_impact`, or `audit_log`.

### Okta Token Health Monitoring
SAQ cron every 5 minutes. Call `GET /api/v1/org`, read `X-Rate-Limit-Remaining`. Store in Redis with 10-min TTL. Fire `token_health` webhook on status change.

### Structured Error Responses
Every API error returns:
```json
{"error": {"code": "SCAN_IN_PROGRESS", "message": "...", "details": {...}}}
```

| Code | HTTP | When |
|---|---|---|
| `VALIDATION_ERROR` | 422 | Pydantic validation failure |
| `NOT_FOUND` | 404 | Resource doesn't exist |
| `FORBIDDEN` | 403 | Insufficient role |
| `SCAN_IN_PROGRESS` | 409 | Scan already running |
| `OKTA_UNREACHABLE` | 502 | Okta API failed after retries |
| `OKTA_RATE_LIMITED` | 429 | Okta rate limit (E0000047) |
| `OKTA_TOKEN_INVALID` | 502 | SSWS token invalid/revoked |
| `INTERNAL_ERROR` | 500 | Unhandled exception |

## RBAC (v1: two roles)

| Role | Permissions |
|---|---|
| `admin` | Full access: run scans, manage scenarios/schedules/notifications, change settings, acknowledge vulns |
| `viewer` | Read-only: dashboard, vulnerabilities, reports, scan history |

Roles derived from Okta OIDC group claims in the JWT.

## Dashboard Metrics
- Total vulnerabilities (open vs remediated) + posture findings
- Risk score distribution
- Severity breakdown (CRITICAL/HIGH/MEDIUM/LOW)
- Category breakdown (policy violations, posture findings, inactive users)
- Users scanned / Apps scanned
- New vulnerabilities today
- Trend charts (risk scores over time)
- Recent scan history with success/failure rates
- Okta API token health indicator (green/yellow/red)
- Posture score (0-100 aggregate across posture checks)

## API Endpoints

**All routes prefixed with `/api/v1/`.**

### Assessments
- `POST /api/v1/assessments/single` — Single user assessment. **Admin.**
- `POST /api/v1/assessments/batch` — Batch assessment (accepts optional `resume_scan_id`). **Admin.**
- `GET /api/v1/assessments/{scan_id}` — Scan status + summary
- `GET /api/v1/assessments/{scan_id}/results` — Paginated assessment results
- `GET /api/v1/assessments/{scan_id}/posture` — Posture findings for a scan
- `GET /api/v1/assessments/{scan_id}/stream` — SSE real-time progress
- `GET /api/v1/assessments` — List past scans

### Vulnerabilities
- `GET /api/v1/vulnerabilities` — List with filters (status, severity, category, risk score range)
- `GET /api/v1/vulnerabilities/{id}` — Details with impacts
- `PATCH /api/v1/vulnerabilities/{id}` — Update status. **Admin.**
- `GET /api/v1/vulnerabilities/stats` — Aggregated statistics

### Posture Findings
- `GET /api/v1/posture/findings` — List with filters
- `GET /api/v1/posture/findings/{id}` — Detail
- `PATCH /api/v1/posture/findings/{id}` — Acknowledge/false-positive. **Admin.**
- `GET /api/v1/posture/score` — Aggregate posture score (0-100)

### Scenarios
- `GET /api/v1/scenarios` — List all
- `POST /api/v1/scenarios` — Create. **Admin.**
- `PUT /api/v1/scenarios/{id}` — Update. **Admin.**
- `DELETE /api/v1/scenarios/{id}` — Delete. **Admin.**
- `POST /api/v1/scenarios/import` — Import from JSON. **Admin.**
- `GET /api/v1/scenarios/export` — Export to JSON

### Reports
- `POST /api/v1/reports/generate` — Generate from scan_id. **Admin.**
- `GET /api/v1/reports` — List
- `GET /api/v1/reports/{id}/download` — Download

### Schedules
- `GET /api/v1/schedules` — List
- `POST /api/v1/schedules` — Create. **Admin.**
- `PUT /api/v1/schedules/{id}` — Update. **Admin.**
- `DELETE /api/v1/schedules/{id}` — Delete. **Admin.**
- `POST /api/v1/schedules/{id}/run-now` — Trigger. **Admin.**
- `GET /api/v1/schedules/history` — Execution history

### Notifications
- `GET /api/v1/notifications/channels` — List. **Admin.**
- `POST /api/v1/notifications/channels` — Create. **Admin.**
- `PUT /api/v1/notifications/channels/{id}` — Update. **Admin.**
- `DELETE /api/v1/notifications/channels/{id}` — Delete. **Admin.**
- `POST /api/v1/notifications/channels/{id}/test` — Send test. **Admin.**

### Settings
- `GET /api/v1/settings/tenant` — Current config (token masked)
- `PUT /api/v1/settings/tenant` — Update. **Admin.**
- `POST /api/v1/settings/tenant/test` — Test Okta connectivity. **Admin.**
- `GET /api/v1/settings/health` — Health check (DB, Redis, Okta token from cache)
- `PUT /api/v1/settings/app-criticality` — Set app criticality levels. **Admin.**

### Dashboard
- `GET /api/v1/dashboard/summary` — All metrics
- `GET /api/v1/dashboard/trends` — Trend data

### Audit Logs
- `GET /api/v1/audit-logs` — List with filters. **Admin.**

## Database Schema

### Connection Pooling
Pool size 20, max overflow 10, pre-ping enabled, hourly recycle.

### Common Base Model
All models get `id` (UUID primary key), `created_at`, `updated_at` from a `TimestampMixin`.

### Index Strategy
- `vulnerability`: `(category, status)`, `(rule_id)`, `(app_id)`, `(risk_score DESC)`
- `vulnerability_impact`: `(vulnerability_id, status)`, `(user_email)`, `(scan_id)`
- `assessment_result`: `(scan_id)`, `(user_id, app_id)`, `(created_at)` — created_at critical for retention
- `posture_finding`: `(scan_id)`, `(check_category, status)`, `(severity)`
- `job_execution`: `(job_id, status)`, `(started_at DESC)`
- `audit_log`: `(actor_email)`, `(resource_type, resource_id)`, `(created_at DESC)`

## Configuration (Environment Variables)
```
# Okta API (for scanning target tenant)
OKTA_API_TOKEN=
OKTA_ORG=
OKTA_ORG_TYPE=okta

# Okta Auth (for the ASPM app's own login)
OKTA_CLIENT_ID=
OKTA_CLIENT_SECRET=
OKTA_ISSUER=
OKTA_ADMIN_GROUP=ASPM_Admins

# Encryption
ENCRYPTION_KEY=                 # Fernet key for API token encryption

# Database
DATABASE_URL=postgresql+asyncpg://aspm:aspm@db:5432/aspm

# Redis
REDIS_URL=redis://redis:6379/0

# App
SECRET_KEY=
LOG_LEVEL=INFO
MAX_WORKERS=5
API_DELAY=0
REPORTS_DIR=/data/reports
RETENTION_DAYS=180
ALLOWED_ORIGINS=http://localhost:5173
```

## Database Migrations (Alembic)

All schema changes are managed by Alembic. **Never use inline SQL or `Base.metadata.create_all()` in application startup.**

### Migration workflow
```bash
# Apply all pending migrations (run before starting the app)
alembic upgrade head

# Create a new migration after changing models
alembic revision --autogenerate -m "description of change"

# Rollback last migration
alembic downgrade -1

# View migration history
alembic history
```

### Rules
- **One migration per schema change.** Don't batch unrelated changes.
- **Every migration must have a working `downgrade()`.** Test rollback before merging.
- **Never edit a migration that has been applied to any environment.** Create a new migration instead.
- **The `docker-entrypoint.sh` runs `alembic upgrade head` automatically** before starting the backend or worker. No manual migration step needed when using Docker.
- **For fresh databases**, run the initial migration (`001_initial_schema`) which creates all tables and enums.
- **Alembic reads `DATABASE_URL` from the environment.** The `alembic.ini` default is overridden at runtime by `alembic/env.py`.

### Files
```
alembic.ini              # Alembic config (logging, script location)
alembic/
├── env.py               # Async engine setup, reads DATABASE_URL from env
├── script.py.mako       # Template for new migrations
└── versions/
    └── 001_initial_schema.py   # Full schema: all 10 tables + enums + indexes
```

## Docker Architecture

### Container design principles
- **Multi-stage builds** for both backend and frontend to minimize image size and attack surface.
- **Non-root users** in all containers. Backend runs as `aspm` user, frontend uses nginx's default non-root user.
- **Health checks** on all containers for automatic restart on failure.
- **`docker-entrypoint.sh`** runs Alembic migrations before starting the backend.

### Development (`docker-compose.yml`)
- Source code mounted as volumes for hot-reload.
- Frontend uses Vite dev server (target: `dev`).
- DB and Redis ports exposed to host for local tooling.
- `restart: unless-stopped` on all services.

### Production (`docker-compose.prod.yml`)
Overlay on top of `docker-compose.yml`:
- Frontend uses nginx serving static build (target: `production`).
- **DB and Redis ports NOT exposed** — only accessible within the Docker network.
- DB credentials from environment variables (not hardcoded).
- Redis persistence enabled (`appendonly yes`).
- Resource limits and reservations on all services.
- Log rotation configured (`json-file` driver, max 100MB × 10 files).
- Caddy reverse proxy with auto-TLS.

### Caddy (reverse proxy)
The `Caddyfile` includes:
- **Security headers:** HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, CSP.
- **JSON request logging** to stdout.
- Server header removed (`-Server`).

### Running
```bash
# Development
docker compose up -d

# Production
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

## Deployment
Min spec: 2 vCPU, 4GB RAM, 40GB disk, Ubuntu 22.04+.

### Steps
1. Clone → copy `.env.example` → `.env` → fill in secrets
2. Set `POSTGRES_PASSWORD` in `.env` (required in production)
3. `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d`
4. Migrations run automatically via `docker-entrypoint.sh`
5. Point DNS to server → Caddy auto-provisions TLS

### DR
PostgreSQL WAL to S3 (RPO 15min), Redis ephemeral (re-queued), reports to S3/GCS, app tier stateless (auto-restart).

### Production checklist
- [ ] `POSTGRES_PASSWORD` set to a strong random value
- [ ] `SECRET_KEY` and `ENCRYPTION_KEY` generated and set
- [ ] `ALLOWED_ORIGINS` set to actual domain (never `*`)
- [ ] `COOKIE_SECURE=true` (HTTPS only)
- [ ] DB/Redis ports NOT exposed (handled by `docker-compose.prod.yml`)
- [ ] Caddy `DOMAIN` env var set to actual domain
- [ ] Backup strategy for PostgreSQL configured
- [ ] Log aggregation configured (Caddy + backend output JSON to stdout)

## Roadmap (post v1 — do NOT build into v1)
- **v1.1:** Additional posture modules, compliance mapping (NIST/CIS), scan diffing
- **v2:** Multi-tenancy (RLS), event-driven scanning, WorkOS SSO, NHI discovery, SIEM exports, envelope encryption, expanded RBAC
- **v3:** Cross-IdP (Entra/GWS), automated remediation, OSCAL/FedRAMP

## Implementation Notes

1. **Policy simulation is the HEART of this system.** Build Milestone 1 first. Nothing else matters until this works.
2. **Rate limiting is critical.** Exponential backoff + jitter + adaptive throttling is essential.
3. **Vulnerability lifecycle must be idempotent.** Running a scan twice must not create duplicates.
4. **All long-running operations are async.** SAQ tasks with progress tracking. Frontend uses SSE with polling fallback.
6. **Structured logging from day one.** structlog JSON. Every Okta API call: endpoint, user_id, app_id, status, duration_ms, retry_count.
7. **Test with real PostgreSQL.** Mock Okta API for unit tests. Real DB via docker for integration tests.
8. **Persist everything that matters.** Assessment results, posture findings, vulns, audit logs → PostgreSQL. Redis is ephemeral.
9. **CORS must be explicit.** Read `ALLOWED_ORIGINS`. Never `*` in production.
10. **Every API error uses the structured envelope.**
11. **Audit every mutating action.** Append-only, no retention limit.
12. **API versioning from day one.** All routes under `/api/v1/`.
13. **Data retention runs automatically.** Daily cleanup at `RETENTION_DAYS`.
14. **Scan resumability is non-negotiable.** Pick up where it left off on crash.
15. **Risk scores, not just severity.** Composite 0-100 with business context.
16. **Prevent concurrent scans for the same user.** Avoids vulnerability lifecycle race conditions.
17. **DB is the source of truth for schedules.** SAQ loads from DB on startup, not static config.
18. **scan_config validated by Pydantic.** Stored as JSON in DB, but the app layer enforces the schema.
19. **Ship v1, then iterate.** Don't build v1.1/v2/v3 features into v1.
20. **Schema changes via Alembic only.** Never use `Base.metadata.create_all()` or inline SQL in app startup. Create a migration file, test upgrade + downgrade, then deploy.
21. **Docker containers run as non-root.** Backend as `aspm` user, frontend via nginx. Never run production containers as root.
22. **Security headers via Caddy.** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Do not rely on the application layer for transport security headers.
