"""Comprehensive integration tests for all API endpoints.

Tests run against a real PostgreSQL database (localhost:5432/aspm).
Each test creates its own data and cleans up relevant tables.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import psycopg2
import psycopg2.extras
import pytest
from itsdangerous import URLSafeTimedSerializer

# These tests hit a real running server at localhost:8000.
# Start it with: uvicorn src.api.main:app --port 8000

BASE_URL = os.environ.get("TEST_BASE_URL", "http://localhost:8000")
SYNC_DSN = os.environ.get("TEST_DATABASE_URL", "postgresql://aspm:aspm@localhost:5432/aspm_test")

# Must match the SECRET_KEY used by the running backend (read from .env directly)
def _read_secret_key() -> str:
    """Read SECRET_KEY from .env file, not from os.environ (conftest overrides it)."""
    env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("SECRET_KEY=") and not line.startswith("#"):
                    return line.split("=", 1)[1].strip()
    return "NjihoDZl6dGbvtjJHwR-vGKCkQ8DhDbn5mjrjuSupHg"

_SECRET_KEY = _read_secret_key()
_SESSION_COOKIE_NAME = "aspm_session"

# Table cleanup order (respects FK constraints)
CLEANUP_TABLES = [
    "reports", "vulnerability_impacts", "posture_findings",
    "assessment_results", "vulnerabilities", "audit_logs",
    "notification_channels", "scans", "jobs", "scenarios",
]


@pytest.fixture
def dbconn():
    """Sync psycopg2 connection for test data setup/cleanup. No event loop issues."""
    conn = psycopg2.connect(SYNC_DSN)
    conn.autocommit = True
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def clean_db(dbconn):
    """Clean all tables before each test."""
    cur = dbconn.cursor()
    for table in CLEANUP_TABLES:
        cur.execute(f"DELETE FROM {table}")
    cur.close()


@pytest.fixture
def db(dbconn):
    """Provide a cursor for inserting test data."""
    psycopg2.extras.register_uuid()
    cur = dbconn.cursor()
    yield cur
    cur.close()


def _make_session_cookie(role: str = "admin") -> str:
    """Generate a signed session cookie matching the backend's auth scheme."""
    serializer = URLSafeTimedSerializer(_SECRET_KEY)
    user_data = {
        "sub": "test-user-id",
        "email": "testadmin@example.com",
        "name": "Test Admin",
        "role": role,
        "groups": ["ASPM_Admins"] if role == "admin" else [],
        "authenticated_at": datetime.now(timezone.utc).isoformat(),
    }
    return serializer.dumps(user_data)


@pytest.fixture
def client():
    """Provide a sync httpx client with admin session cookie."""
    cookie = _make_session_cookie("admin")
    with httpx.Client(
        base_url=BASE_URL,
        timeout=10.0,
        headers={"Cookie": f"{_SESSION_COOKIE_NAME}={cookie}"},
    ) as c:
        yield c


@pytest.fixture
def viewer_client():
    """Provide a sync httpx client with viewer session cookie."""
    cookie = _make_session_cookie("viewer")
    with httpx.Client(
        base_url=BASE_URL,
        timeout=10.0,
        headers={"Cookie": f"{_SESSION_COOKIE_NAME}={cookie}"},
    ) as c:
        yield c


@pytest.fixture
def anon_client():
    """Provide a sync httpx client with no authentication."""
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as c:
        yield c


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _make_scenario_payload(**overrides) -> dict:
    base = {
        "name": "Test Scenario",
        "description": "A test scenario",
        "is_active": True,
        "risk_level": "MEDIUM",
        "device_platform": "WINDOWS",
        "device_registered": False,
        "device_managed": False,
    }
    base.update(overrides)
    return base


def _insert_scan(cur, **overrides) -> uuid.UUID:
    """Insert a scan row via raw SQL and return its id."""
    scan_id = overrides.pop("id", uuid.uuid4())
    defaults = dict(
        job_name="test-scan",
        status="COMPLETED",
        total_users=1,
        successful_users=1,
        failed_users=0,
        job_id=None,
    )
    defaults.update(overrides)
    cur.execute(
        "INSERT INTO scans (id, job_id, job_name, status, total_users, successful_users, failed_users, posture_findings_count, last_processed_user_index, started_at, created_at) "
        "VALUES (%s, %s, %s, %s::scanstatus, %s, %s, %s, 0, 0, NOW(), NOW())",
        (str(scan_id), defaults["job_id"], defaults["job_name"], defaults["status"],
         defaults["total_users"], defaults["successful_users"], defaults["failed_users"]),
    )
    return scan_id


def _insert_vulnerability(cur, **overrides) -> uuid.UUID:
    """Insert a vulnerability row via raw SQL and return its id."""
    vuln_id = overrides.pop("id", uuid.uuid4())
    now = datetime.now(timezone.utc)
    defaults = dict(
        title="Test Vuln",
        description="Test vulnerability description",
        category="AUTH_POLICY_VIOLATION",
        severity="HIGH",
        status="ACTIVE",
        risk_score=75,
        risk_factors=json.dumps({}),
        active_impact_count=1,
        first_detected=now,
        last_detected=now,
    )
    defaults.update(overrides)
    # Ensure jsonb fields are strings
    if isinstance(defaults["risk_factors"], dict):
        defaults["risk_factors"] = json.dumps(defaults["risk_factors"])
    cur.execute(
        "INSERT INTO vulnerabilities "
        "(id, title, description, category, severity, status, risk_score, risk_factors, "
        "active_impact_count, first_detected, last_detected, created_at, updated_at) "
        "VALUES (%s, %s, %s, %s::vulnerabilitycategory, %s::severity, %s::vulnerabilitystatus, %s, %s, %s, %s, %s, NOW(), NOW())",
        (str(vuln_id), defaults["title"], defaults["description"], defaults["category"],
         defaults["severity"], defaults["status"], defaults["risk_score"],
         defaults["risk_factors"], defaults["active_impact_count"],
         defaults["first_detected"], defaults["last_detected"]),
    )
    return vuln_id


def _insert_posture_finding(cur, scan_id: uuid.UUID, **overrides) -> uuid.UUID:
    """Insert a posture finding row via raw SQL and return its id."""
    finding_id = overrides.pop("id", uuid.uuid4())
    now = datetime.now(timezone.utc)
    defaults = dict(
        check_category="MFA_POSTURE",
        check_name="mfa_enrollment_check",
        severity="HIGH",
        status="OPEN",
        title="MFA Not Enrolled",
        description="Users not enrolled in MFA",
        affected_resources=json.dumps([{"user": "test@example.com"}]),
        remediation_steps="Enroll users in MFA",
        risk_score=80,
        first_detected=now,
        last_detected=now,
    )
    defaults.update(overrides)
    if isinstance(defaults["affected_resources"], (list, dict)):
        defaults["affected_resources"] = json.dumps(defaults["affected_resources"])
    cur.execute(
        "INSERT INTO posture_findings "
        "(id, scan_id, check_category, check_name, severity, status, title, description, "
        "affected_resources, remediation_steps, risk_score, first_detected, last_detected, created_at) "
        "VALUES (%s, %s, %s::checkcategory, %s, %s::severity, %s::findingstatus, %s, %s, %s, %s, %s, %s, %s, NOW())",
        (str(finding_id), str(scan_id), defaults["check_category"], defaults["check_name"],
         defaults["severity"], defaults["status"], defaults["title"], defaults["description"],
         defaults["affected_resources"], defaults["remediation_steps"], defaults["risk_score"],
         defaults["first_detected"], defaults["last_detected"]),
    )
    return finding_id


def _insert_impact(cur, vulnerability_id: uuid.UUID, scan_id: uuid.UUID, **overrides) -> uuid.UUID:
    """Insert a vulnerability impact row and return its id."""
    impact_id = overrides.pop("id", uuid.uuid4())
    now = datetime.now(timezone.utc)
    defaults = dict(
        user_id="test-user",
        user_email="test@example.com",
        user_name="Test User",
        app_name="TestApp",
        scenario_name="Test Scenario",
        status="ACTIVE",
        first_detected=now,
        last_detected=now,
    )
    defaults.update(overrides)
    cur.execute(
        "INSERT INTO vulnerability_impacts "
        "(id, vulnerability_id, scan_id, user_id, user_email, user_name, app_name, scenario_name, "
        "status, first_detected, last_detected) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::impactstatus, %s, %s)",
        (str(impact_id), str(vulnerability_id), str(scan_id),
         defaults["user_id"], defaults["user_email"], defaults["user_name"],
         defaults["app_name"], defaults["scenario_name"], defaults["status"],
         defaults["first_detected"], defaults["last_detected"]),
    )
    return impact_id


# ===========================================================================
# SCENARIOS CRUD
# ===========================================================================

class TestScenarios:
    def test_create_scenario(self, client, db):
        payload = _make_scenario_payload()
        resp = client.post("/api/v1/scenarios", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Test Scenario"
        assert data["risk_level"] == "MEDIUM"
        assert data["device_platform"] == "WINDOWS"
        assert data["device_registered"] is False
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data

    def test_list_scenarios(self, client, db):
        client.post("/api/v1/scenarios", json=_make_scenario_payload(name="Scenario A"))
        client.post("/api/v1/scenarios", json=_make_scenario_payload(name="Scenario B"))

        resp = client.get("/api/v1/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        names = {s["name"] for s in data}
        assert names == {"Scenario A", "Scenario B"}

    def test_list_scenarios_filter_active(self, client, db):
        client.post("/api/v1/scenarios", json=_make_scenario_payload(name="Active", is_active=True))
        client.post("/api/v1/scenarios", json=_make_scenario_payload(name="Inactive", is_active=False))

        resp = client.get("/api/v1/scenarios", params={"is_active": "true"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["name"] == "Active"

    def test_update_scenario(self, client, db):
        create_resp = client.post("/api/v1/scenarios", json=_make_scenario_payload())
        scenario_id = create_resp.json()["id"]

        update_resp = client.put(
            f"/api/v1/scenarios/{scenario_id}",
            json={"name": "Updated Name"},
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["name"] == "Updated Name"

        # Verify persisted
        get_resp = client.get("/api/v1/scenarios")
        assert get_resp.json()[0]["name"] == "Updated Name"

    def test_delete_scenario(self, client, db):
        create_resp = client.post("/api/v1/scenarios", json=_make_scenario_payload())
        scenario_id = create_resp.json()["id"]

        del_resp = client.delete(f"/api/v1/scenarios/{scenario_id}")
        assert del_resp.status_code == 204

        list_resp = client.get("/api/v1/scenarios")
        assert len(list_resp.json()) == 0

    def test_delete_nonexistent_scenario(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.delete(f"/api/v1/scenarios/{fake_id}")
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "NOT_FOUND"

    def test_import_scenarios(self, client, db):
        scenarios = [
            _make_scenario_payload(name="Import A", device_platform="WINDOWS"),
            _make_scenario_payload(name="Import B", device_platform="MACOS"),
            _make_scenario_payload(name="Import C", device_platform="IOS"),
        ]
        resp = client.post("/api/v1/scenarios/import", json=scenarios)
        assert resp.status_code == 201
        data = resp.json()
        assert len(data) == 3
        assert {s["name"] for s in data} == {"Import A", "Import B", "Import C"}

    def test_export_scenarios(self, client, db):
        scenarios = [
            _make_scenario_payload(name="Export A"),
            _make_scenario_payload(name="Export B"),
        ]
        client.post("/api/v1/scenarios/import", json=scenarios)

        resp = client.get("/api/v1/scenarios/export")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    def test_create_scenario_invalid_data(self, client, db):
        resp = client.post("/api/v1/scenarios", json={"name": "Bad"})
        assert resp.status_code == 422
        body = resp.json()
        assert "error" in body
        assert body["error"]["code"] == "VALIDATION_ERROR"
        assert "details" in body["error"]

    def test_update_nonexistent_scenario(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.put(f"/api/v1/scenarios/{fake_id}", json={"name": "Ghost"})
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "NOT_FOUND"


# ===========================================================================
# VULNERABILITIES
# ===========================================================================

class TestVulnerabilities:
    def test_list_vulnerabilities(self, client, db):
        _insert_vulnerability(db, title="Vuln A")
        _insert_vulnerability(db, title="Vuln B", severity="MEDIUM")

        resp = client.get("/api/v1/vulnerabilities")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2
        assert data["page"] == 1

    def test_list_vulnerabilities_pagination(self, client, db):
        for i in range(5):
            _insert_vulnerability(db, title=f"Vuln {i}")

        resp = client.get("/api/v1/vulnerabilities", params={"page": 1, "page_size": 2})
        data = resp.json()
        assert data["total"] == 5
        assert len(data["items"]) == 2
        assert data["pages"] == 3

        resp2 = client.get("/api/v1/vulnerabilities", params={"page": 3, "page_size": 2})
        data2 = resp2.json()
        assert len(data2["items"]) == 1

    def test_list_vulnerabilities_filter_status(self, client, db):
        scan_id = _insert_scan(db)
        vuln_id = _insert_vulnerability(db, title="Active", status="ACTIVE")
        _insert_impact(db, vuln_id, scan_id)  # Prevent auto-reconcile to CLOSED
        _insert_vulnerability(db, title="Closed", status="CLOSED")

        resp = client.get("/api/v1/vulnerabilities", params={"status": "ACTIVE"})
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["title"] == "Active"

    def test_list_vulnerabilities_filter_severity(self, client, db):
        _insert_vulnerability(db, title="High", severity="HIGH")
        _insert_vulnerability(db, title="Low", severity="LOW")

        resp = client.get("/api/v1/vulnerabilities", params={"severity": "LOW"})
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["title"] == "Low"

    def test_list_vulnerabilities_filter_category(self, client, db):
        _insert_vulnerability(db, category="AUTH_POLICY_VIOLATION")
        _insert_vulnerability(db, category="INACTIVE_APP_USERS")

        resp = client.get("/api/v1/vulnerabilities", params={"category": "inactive_app_users"})
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["category"] == "inactive_app_users"

    def test_get_vulnerability_detail(self, client, db):
        scan_id = _insert_scan(db)
        vuln_id = _insert_vulnerability(db)
        impact_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        db.execute(
            "INSERT INTO vulnerability_impacts "
            "(id, vulnerability_id, scan_id, user_id, user_email, user_name, app_name, scenario_name, status, first_detected, last_detected) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::impactstatus, %s, %s)",
            (str(impact_id), str(vuln_id), str(scan_id), "user1", "test@example.com",
             "Test User", "TestApp", "Test Scenario", "ACTIVE", now, now),
        )

        resp = client.get(f"/api/v1/vulnerabilities/{vuln_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["title"] == "Test Vuln"
        assert len(data["impacts"]) == 1
        assert data["impacts"][0]["user_email"] == "test@example.com"

    def test_patch_vulnerability_status(self, client, db):
        vuln_id = _insert_vulnerability(db, status="ACTIVE")

        resp = client.patch(
            f"/api/v1/vulnerabilities/{vuln_id}",
            json={"status": "ACKNOWLEDGED"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ACKNOWLEDGED"

    def test_patch_vulnerability_closed_sets_timestamp(self, client, db):
        scan_id = _insert_scan(db)
        vuln_id = _insert_vulnerability(db, status="ACTIVE")
        _insert_impact(db, vuln_id, scan_id)  # Keep ACTIVE through auto-reconcile

        resp = client.patch(
            f"/api/v1/vulnerabilities/{vuln_id}",
            json={"status": "CLOSED"},
        )
        assert resp.status_code == 200
        assert resp.json()["remediated_at"] is not None

    def test_patch_vulnerability_invalid_status(self, client, db):
        vuln_id = _insert_vulnerability(db)

        resp = client.patch(
            f"/api/v1/vulnerabilities/{vuln_id}",
            json={"status": "INVALID"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "INVALID_STATUS"

    def test_get_vulnerability_stats(self, client, db):
        scan_id = _insert_scan(db)
        vuln1 = _insert_vulnerability(db, status="ACTIVE", severity="HIGH")
        _insert_impact(db, vuln1, scan_id, user_id="u1")  # Keep ACTIVE
        vuln2 = _insert_vulnerability(db, status="ACTIVE", severity="MEDIUM")
        _insert_impact(db, vuln2, scan_id, user_id="u2")  # Keep ACTIVE
        _insert_vulnerability(db, status="CLOSED", severity="HIGH")

        resp = client.get("/api/v1/vulnerabilities/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert data["active"] == 2
        assert data["closed"] == 1
        assert data["acknowledged"] == 0
        assert data["by_severity"]["HIGH"] == 2
        assert data["by_severity"]["MEDIUM"] == 1

    def test_get_vulnerability_not_found(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/v1/vulnerabilities/{fake_id}")
        assert resp.status_code == 404
        body = resp.json()
        assert body["error"]["code"] == "NOT_FOUND"
        assert "message" in body["error"]

    def test_get_vulnerability_invalid_uuid(self, client, db):
        resp = client.get("/api/v1/vulnerabilities/not-a-uuid")
        assert resp.status_code == 422


# ===========================================================================
# POSTURE FINDINGS
# ===========================================================================

class TestPostureFindings:
    def test_list_findings(self, client, db):
        scan_id = _insert_scan(db)
        _insert_posture_finding(db, scan_id, title="Finding A")
        _insert_posture_finding(db, scan_id, title="Finding B")

        resp = client.get("/api/v1/posture/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2

    def test_list_findings_filter_severity(self, client, db):
        scan_id = _insert_scan(db)
        _insert_posture_finding(db, scan_id, severity="HIGH")
        _insert_posture_finding(db, scan_id, severity="LOW")

        resp = client.get("/api/v1/posture/findings", params={"severity": "LOW"})
        data = resp.json()
        assert data["total"] == 1

    def test_list_findings_filter_status(self, client, db):
        scan_id = _insert_scan(db)
        _insert_posture_finding(db, scan_id, status="OPEN")
        _insert_posture_finding(db, scan_id, status="RESOLVED")

        resp = client.get("/api/v1/posture/findings", params={"status": "OPEN"})
        data = resp.json()
        assert data["total"] == 1

    def test_get_finding_detail(self, client, db):
        scan_id = _insert_scan(db)
        finding_id = _insert_posture_finding(db, scan_id)

        resp = client.get(f"/api/v1/posture/findings/{finding_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["title"] == "MFA Not Enrolled"
        assert data["check_category"] == "mfa_posture"

    def test_get_finding_not_found(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/v1/posture/findings/{fake_id}")
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "NOT_FOUND"

    def test_patch_finding_acknowledge(self, client, db):
        scan_id = _insert_scan(db)
        finding_id = _insert_posture_finding(db, scan_id)

        resp = client.patch(
            f"/api/v1/posture/findings/{finding_id}",
            json={"status": "ACKNOWLEDGED"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ACKNOWLEDGED"

    def test_patch_finding_resolve_sets_timestamp(self, client, db):
        scan_id = _insert_scan(db)
        finding_id = _insert_posture_finding(db, scan_id)

        resp = client.patch(
            f"/api/v1/posture/findings/{finding_id}",
            json={"status": "RESOLVED"},
        )
        assert resp.status_code == 200
        assert resp.json()["resolved_at"] is not None

    def test_patch_finding_invalid_status(self, client, db):
        scan_id = _insert_scan(db)
        finding_id = _insert_posture_finding(db, scan_id)

        resp = client.patch(
            f"/api/v1/posture/findings/{finding_id}",
            json={"status": "GARBAGE"},
        )
        assert resp.status_code == 400

    def test_posture_score(self, client, db):
        scan_id = _insert_scan(db)
        # 1 HIGH (10 pts) + 1 MEDIUM (5 pts) = 15 deduction => score = 85
        _insert_posture_finding(db, scan_id, severity="HIGH", status="OPEN")
        _insert_posture_finding(db, scan_id, severity="MEDIUM", status="OPEN")
        # RESOLVED finding should NOT affect score
        _insert_posture_finding(db, scan_id, severity="CRITICAL", status="RESOLVED")

        resp = client.get("/api/v1/posture/score")
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] == 85
        assert data["total_findings"] == 3
        assert data["high"] == 1
        assert data["medium"] == 1
        assert data["critical"] == 0  # resolved, not counted in open


# ===========================================================================
# ASSESSMENTS
# ===========================================================================

class TestAssessments:
    @pytest.mark.skipif(True, reason="Requires valid Okta credentials — skipped in CI")
    def test_post_single_assessment_fails_gracefully(self, client, db):
        """Single assessment with no valid Okta token should create a scan with error."""
        with httpx.Client(base_url=BASE_URL, timeout=60.0) as long_client:
            resp = long_client.post(
                "/api/v1/assessments/single",
                json={"email": "nonexistent@example.com"},
            )
        assert resp.status_code == 201
        data = resp.json()
        assert "id" in data
        assert data["status"] in ("completed", "failed")

    def test_post_batch_assessment(self, client, db):
        resp = client.post(
            "/api/v1/assessments/batch",
            json={"user_selection": "limited", "max_users": 5},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "pending"
        assert data["total_users"] == 5

    def test_list_scans(self, client, db):
        _insert_scan(db, job_name="Scan 1")
        _insert_scan(db, job_name="Scan 2")

        resp = client.get("/api/v1/assessments")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2

    def test_get_scan_detail(self, client, db):
        scan_id = _insert_scan(db, job_name="Detail Test")

        resp = client.get(f"/api/v1/assessments/{scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["job_name"] == "Detail Test"

    def test_get_scan_not_found(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/v1/assessments/{fake_id}")
        assert resp.status_code == 404

    def test_get_scan_results(self, client, db):
        scan_id = _insert_scan(db)

        resp = client.get(f"/api/v1/assessments/{scan_id}/results")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_get_scan_posture(self, client, db):
        scan_id = _insert_scan(db)
        _insert_posture_finding(db, scan_id)

        resp = client.get(f"/api/v1/assessments/{scan_id}/posture")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1


# ===========================================================================
# DASHBOARD
# ===========================================================================

class TestDashboard:
    def test_summary(self, client, db):
        scan_id = _insert_scan(db)
        vuln_id = _insert_vulnerability(db, status="ACTIVE", severity="HIGH")
        _insert_impact(db, vuln_id, scan_id)  # Keep ACTIVE through auto-reconcile
        _insert_vulnerability(db, status="CLOSED", severity="MEDIUM")
        _insert_posture_finding(db, scan_id, severity="HIGH", status="OPEN")

        resp = client.get("/api/v1/dashboard/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_vulnerabilities"] == 2
        assert data["active_vulnerabilities"] == 1
        assert data["closed_vulnerabilities"] == 1
        assert data["total_posture_findings"] == 1
        # Score: 100 - 10 (1 HIGH) = 90
        assert data["posture_score"] == 90
        assert "by_severity" in data
        assert "by_category" in data
        assert "recent_scans" in data
        assert "okta_health" in data

    def test_summary_empty_db(self, client, db):
        resp = client.get("/api/v1/dashboard/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_vulnerabilities"] == 0
        assert data["posture_score"] == 100

    def test_trends(self, client, db):
        now = datetime.now(timezone.utc)
        _insert_vulnerability(
            db,
            status="ACTIVE",
            first_detected=now - timedelta(days=5),
        )

        resp = client.get("/api/v1/dashboard/trends", params={"days": 30})
        assert resp.status_code == 200
        data = resp.json()
        assert "data" in data
        assert len(data["data"]) == 30
        point = data["data"][0]
        assert "date" in point
        assert "active" in point
        assert "remediated" in point


# ===========================================================================
# SCHEDULES
# ===========================================================================

class TestSchedules:
    def _make_schedule_payload(self, **overrides) -> dict:
        base = {
            "name": "Daily Scan",
            "description": "Runs daily",
            "is_active": True,
            "schedule_type": "cron",
            "cron_expression": "0 2 * * *",
            "scan_config": {
                "user_selection": "all",
                "max_workers": 5,
                "api_delay": 0,
            },
        }
        base.update(overrides)
        return base

    def test_create_schedule(self, client, db):
        payload = self._make_schedule_payload()
        resp = client.post("/api/v1/schedules", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Daily Scan"
        assert data["schedule_type"] == "cron"
        assert data["cron_expression"] == "0 2 * * *"
        assert "id" in data

    def test_list_schedules(self, client, db):
        client.post("/api/v1/schedules", json=self._make_schedule_payload(name="Job A"))
        client.post("/api/v1/schedules", json=self._make_schedule_payload(name="Job B"))

        resp = client.get("/api/v1/schedules")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    def test_update_schedule(self, client, db):
        create_resp = client.post("/api/v1/schedules", json=self._make_schedule_payload())
        job_id = create_resp.json()["id"]

        update_resp = client.put(
            f"/api/v1/schedules/{job_id}",
            json={"name": "Updated Job", "cron_expression": "0 3 * * *"},
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["name"] == "Updated Job"
        assert update_resp.json()["cron_expression"] == "0 3 * * *"

    def test_delete_schedule(self, client, db):
        create_resp = client.post("/api/v1/schedules", json=self._make_schedule_payload())
        job_id = create_resp.json()["id"]

        del_resp = client.delete(f"/api/v1/schedules/{job_id}")
        assert del_resp.status_code == 204

        list_resp = client.get("/api/v1/schedules")
        assert len(list_resp.json()) == 0

    def test_delete_nonexistent_schedule(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.delete(f"/api/v1/schedules/{fake_id}")
        assert resp.status_code == 404

    def test_run_now(self, client, db):
        create_resp = client.post("/api/v1/schedules", json=self._make_schedule_payload())
        job_id = create_resp.json()["id"]

        resp = client.post(f"/api/v1/schedules/{job_id}/run-now")
        assert resp.status_code == 201
        data = resp.json()
        assert "scan_id" in data
        assert data["message"] == "Scan enqueued"

    def test_run_now_nonexistent(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.post(f"/api/v1/schedules/{fake_id}/run-now")
        assert resp.status_code == 404

    def test_execution_history(self, client, db):
        job_id = uuid.uuid4()
        db.execute(
            "INSERT INTO jobs (id, name, schedule_type, cron_expression, scan_config, is_active, created_at, updated_at) "
            "VALUES (%s, %s, %s::scheduletype, %s, %s, %s, NOW(), NOW())",
            (str(job_id), "History Test", "CRON", "0 0 * * *",
             json.dumps({"user_selection": "all"}), True),
        )
        _insert_scan(db, job_id=str(job_id), job_name="History Test",
                     status="COMPLETED", total_users=10, successful_users=10, failed_users=0)

        resp = client.get("/api/v1/schedules/history")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["job_name"] == "History Test"

    def test_execution_history_empty(self, client, db):
        resp = client.get("/api/v1/schedules/history")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []


# ===========================================================================
# NOTIFICATIONS
# ===========================================================================

class TestNotifications:
    def _make_channel_payload(self, **overrides) -> dict:
        base = {
            "name": "Test Webhook",
            "channel_type": "webhook",
            "webhook_url": "https://hooks.example.com/test",
            "events": ["scan_completed", "new_vulnerabilities"],
            "is_active": True,
        }
        base.update(overrides)
        return base

    def test_create_channel(self, client, db):
        payload = self._make_channel_payload()
        resp = client.post("/api/v1/notifications/channels", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Test Webhook"
        assert data["channel_type"] == "webhook"
        assert data["webhook_url"] == "https://hooks.example.com/test"
        assert data["events"] == ["scan_completed", "new_vulnerabilities"]
        assert data["is_active"] is True
        assert data["has_secret"] is False
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data

    def test_create_channel_with_hmac_secret(self, client, db):
        payload = self._make_channel_payload(hmac_secret="my-secret-key")
        resp = client.post("/api/v1/notifications/channels", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["has_secret"] is True

    def test_list_channels(self, client, db):
        client.post("/api/v1/notifications/channels", json=self._make_channel_payload(name="Ch A"))
        client.post("/api/v1/notifications/channels", json=self._make_channel_payload(name="Ch B"))

        resp = client.get("/api/v1/notifications/channels")
        assert resp.status_code == 200
        channels = resp.json()
        assert len(channels) == 2
        # Verify response shape
        for ch in channels:
            assert "webhook_url" in ch
            assert "events" in ch
            assert "is_active" in ch
            assert "created_at" in ch

    def test_list_channels_empty(self, client, db):
        resp = client.get("/api/v1/notifications/channels")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_update_channel(self, client, db):
        create_resp = client.post(
            "/api/v1/notifications/channels",
            json=self._make_channel_payload(),
        )
        channel_id = create_resp.json()["id"]

        update_resp = client.put(
            f"/api/v1/notifications/channels/{channel_id}",
            json={"name": "Updated Channel"},
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["name"] == "Updated Channel"
        # URL should remain unchanged
        assert update_resp.json()["webhook_url"] == "https://hooks.example.com/test"

    def test_update_channel_url(self, client, db):
        create_resp = client.post(
            "/api/v1/notifications/channels",
            json=self._make_channel_payload(),
        )
        channel_id = create_resp.json()["id"]

        update_resp = client.put(
            f"/api/v1/notifications/channels/{channel_id}",
            json={"webhook_url": "https://new-url.example.com/hook"},
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["webhook_url"] == "https://new-url.example.com/hook"

    def test_update_channel_events(self, client, db):
        create_resp = client.post(
            "/api/v1/notifications/channels",
            json=self._make_channel_payload(),
        )
        channel_id = create_resp.json()["id"]

        update_resp = client.put(
            f"/api/v1/notifications/channels/{channel_id}",
            json={"events": ["token_health"]},
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["events"] == ["token_health"]

    def test_delete_channel(self, client, db):
        create_resp = client.post(
            "/api/v1/notifications/channels",
            json=self._make_channel_payload(),
        )
        channel_id = create_resp.json()["id"]

        del_resp = client.delete(f"/api/v1/notifications/channels/{channel_id}")
        assert del_resp.status_code == 204

        list_resp = client.get("/api/v1/notifications/channels")
        assert len(list_resp.json()) == 0

    def test_delete_nonexistent_channel(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.delete(f"/api/v1/notifications/channels/{fake_id}")
        assert resp.status_code == 404

    def test_create_channel_missing_url(self, client, db):
        payload = {
            "name": "Bad Channel",
            "channel_type": "webhook",
            "events": ["scan_completed"],
        }
        resp = client.post("/api/v1/notifications/channels", json=payload)
        assert resp.status_code == 422

    def test_list_channels_viewer_forbidden(self, viewer_client, db):
        """Viewers cannot list channels (admin-only)."""
        resp = viewer_client.get("/api/v1/notifications/channels")
        assert resp.status_code == 403

    def test_create_channel_viewer_forbidden(self, viewer_client, db):
        """Viewers cannot create channels (admin-only)."""
        payload = {
            "name": "Viewer Channel",
            "channel_type": "webhook",
            "webhook_url": "https://example.com/hook",
            "events": ["scan_completed"],
        }
        resp = viewer_client.post("/api/v1/notifications/channels", json=payload)
        assert resp.status_code == 403

    def test_list_channels_anon_unauthorized(self, anon_client, db):
        """Unauthenticated users get 401."""
        resp = anon_client.get("/api/v1/notifications/channels")
        assert resp.status_code == 401


# ===========================================================================
# SETTINGS
# ===========================================================================

class TestSettings:
    def test_get_tenant_config(self, client, db):
        resp = client.get("/api/v1/settings/tenant")
        assert resp.status_code == 200
        data = resp.json()
        assert "okta_org" in data
        assert "okta_org_type" in data
        assert "okta_api_token_masked" in data
        assert "****" in data["okta_api_token_masked"]

    def test_health_check(self, client, db):
        resp = client.get("/api/v1/settings/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["database"] == "ok"
        assert data["redis"] == "ok"
        assert data["status"] == "ok"

    def test_update_app_criticality(self, client, db):
        resp = client.put(
            "/api/v1/settings/app-criticality",
            json={"app_criticality": {"app123": "critical", "app456": "medium"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2

    def test_update_tenant_config(self, client, db):
        resp = client.put(
            "/api/v1/settings/tenant",
            json={"okta_org": "test-org", "okta_org_type": "oktapreview"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["okta_org"] == "test-org"
        assert data["okta_org_type"] == "oktapreview"


# ===========================================================================
# AUDIT LOGS
# ===========================================================================

class TestAuditLogs:
    def test_list_audit_logs(self, client, db):
        now = datetime.now(timezone.utc)
        for actor, role, action, rtype, rid, ip in [
            ("admin@example.com", "admin", "create_scenario", "scenario", "abc-123", "127.0.0.1"),
            ("user@example.com", "viewer", "view_report", "report", "def-456", "10.0.0.1"),
        ]:
            db.execute(
                "INSERT INTO audit_logs (id, actor_email, actor_role, action, resource_type, resource_id, ip_address, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (str(uuid.uuid4()), actor, role, action, rtype, rid, ip, now),
            )

        resp = client.get("/api/v1/audit-logs")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2

    def test_list_audit_logs_filter_actor(self, client, db):
        now = datetime.now(timezone.utc)
        for actor, action, rid in [
            ("admin@example.com", "create", "x"),
            ("other@example.com", "delete", "y"),
        ]:
            db.execute(
                "INSERT INTO audit_logs (id, actor_email, actor_role, action, resource_type, resource_id, ip_address, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (str(uuid.uuid4()), actor, "admin", action, "scenario", rid, "127.0.0.1", now),
            )

        resp = client.get("/api/v1/audit-logs", params={"actor_email": "admin@example.com"})
        data = resp.json()
        assert data["total"] == 1

    def test_list_audit_logs_filter_action(self, client, db):
        now = datetime.now(timezone.utc)
        db.execute(
            "INSERT INTO audit_logs (id, actor_email, actor_role, action, resource_type, resource_id, ip_address, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (str(uuid.uuid4()), "admin@example.com", "admin", "create_scenario", "scenario", "x", "127.0.0.1", now),
        )

        resp = client.get("/api/v1/audit-logs", params={"action": "create_scenario"})
        data = resp.json()
        assert data["total"] == 1

    def test_list_audit_logs_filter_date_range(self, client, db):
        now = datetime.now(timezone.utc)
        db.execute(
            "INSERT INTO audit_logs (id, actor_email, actor_role, action, resource_type, resource_id, ip_address, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (str(uuid.uuid4()), "admin@example.com", "admin", "test", "test", "z", "127.0.0.1", now),
        )

        date_from = (now - timedelta(hours=1)).isoformat()
        date_to = (now + timedelta(hours=1)).isoformat()
        resp = client.get("/api/v1/audit-logs", params={
            "date_from": date_from,
            "date_to": date_to,
        })
        data = resp.json()
        assert data["total"] == 1

    def test_list_audit_logs_empty(self, client, db):
        resp = client.get("/api/v1/audit-logs")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []


# ===========================================================================
# REPORTS
# ===========================================================================

class TestReports:
    def test_create_report(self, client, db):
        scan_id = _insert_scan(db)

        resp = client.post(
            "/api/v1/reports",
            json={"scan_id": str(scan_id), "report_type": "csv_full"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["scan_id"] == str(scan_id)
        assert data["report_type"] == "csv_full"

    def test_create_report_scan_not_found(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.post(
            "/api/v1/reports",
            json={"scan_id": fake_id, "report_type": "csv_full"},
        )
        assert resp.status_code == 404

    def test_list_reports(self, client, db):
        scan_id = _insert_scan(db)
        report_id = uuid.uuid4()
        db.execute(
            "INSERT INTO reports (id, scan_id, report_type, generated_at, created_at) "
            "VALUES (%s, %s, %s::reporttype, NOW(), NOW())",
            (str(report_id), str(scan_id), "CSV_FULL"),
        )

        resp = client.get("/api/v1/reports")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1

    def test_download_report_no_content(self, client, db):
        scan_id = _insert_scan(db)
        report_id = uuid.uuid4()
        db.execute(
            "INSERT INTO reports (id, scan_id, report_type, generated_at, created_at) "
            "VALUES (%s, %s, %s::reporttype, NOW(), NOW())",
            (str(report_id), str(scan_id), "CSV_FULL"),
        )

        resp = client.get(f"/api/v1/reports/{report_id}/download")
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "NOT_FOUND"

    def test_download_report_not_found(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/v1/reports/{fake_id}/download")
        assert resp.status_code == 404

    def test_download_report_with_content(self, client, db):
        scan_id = _insert_scan(db)
        report_id = uuid.uuid4()
        db.execute(
            "INSERT INTO reports (id, scan_id, report_type, content, generated_at, created_at) "
            "VALUES (%s, %s, %s::reporttype, %s, NOW(), NOW())",
            (str(report_id), str(scan_id), "JSON", "This is the JSON report content."),
        )

        resp = client.get(f"/api/v1/reports/{report_id}/download")
        assert resp.status_code == 200
        data = resp.json()
        assert data["content"] == "This is the JSON report content."
        assert data["report_type"] == "json"


# ===========================================================================
# ERROR HANDLING
# ===========================================================================

class TestErrorHandling:
    def test_404_on_nonexistent_vulnerability(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/v1/vulnerabilities/{fake_id}")
        assert resp.status_code == 404
        body = resp.json()
        assert "error" in body
        assert body["error"]["code"] == "NOT_FOUND"
        assert "message" in body["error"]

    def test_404_on_nonexistent_scenario(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.put(f"/api/v1/scenarios/{fake_id}", json={"name": "ghost"})
        assert resp.status_code == 404
        body = resp.json()
        assert body["error"]["code"] == "NOT_FOUND"

    def test_422_on_invalid_input(self, client, db):
        resp = client.post("/api/v1/scenarios", json={"invalid": "data"})
        assert resp.status_code == 422
        body = resp.json()
        assert body["error"]["code"] == "VALIDATION_ERROR"
        assert "details" in body["error"]

    def test_422_on_bad_uuid(self, client, db):
        resp = client.get("/api/v1/vulnerabilities/not-a-valid-uuid")
        assert resp.status_code == 422

    def test_structured_error_envelope(self, client, db):
        """All error responses should follow the envelope pattern."""
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/v1/vulnerabilities/{fake_id}")
        body = resp.json()
        assert "error" in body
        err = body["error"]
        assert "code" in err
        assert "message" in err

    def test_404_on_nonexistent_posture_finding(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/v1/posture/findings/{fake_id}")
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "NOT_FOUND"

    def test_404_on_nonexistent_scan(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/v1/assessments/{fake_id}")
        assert resp.status_code == 404

    def test_404_on_nonexistent_schedule(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.put(f"/api/v1/schedules/{fake_id}", json={"name": "ghost"})
        assert resp.status_code == 404

    def test_404_on_nonexistent_notification_channel(self, client, db):
        fake_id = str(uuid.uuid4())
        resp = client.delete(f"/api/v1/notifications/channels/{fake_id}")
        assert resp.status_code == 404


# ===========================================================================
# RBAC ENFORCEMENT
# ===========================================================================

class TestRBAC:
    """Verify that admin-only endpoints reject viewer-role users with 403."""

    def test_viewer_cannot_create_scenario(self, viewer_client, db):
        resp = viewer_client.post("/api/v1/scenarios", json={
            "name": "Test", "description": "Test", "is_active": True,
            "risk_level": "MEDIUM", "device_platform": "WINDOWS",
            "device_registered": False, "device_managed": False,
        })
        assert resp.status_code == 403

    def test_viewer_cannot_update_scenario(self, viewer_client, db):
        fake_id = str(uuid.uuid4())
        resp = viewer_client.put(f"/api/v1/scenarios/{fake_id}", json={"name": "X"})
        assert resp.status_code == 403

    def test_viewer_cannot_delete_scenario(self, viewer_client, db):
        fake_id = str(uuid.uuid4())
        resp = viewer_client.delete(f"/api/v1/scenarios/{fake_id}")
        assert resp.status_code == 403

    def test_viewer_cannot_create_schedule(self, viewer_client, db):
        resp = viewer_client.post("/api/v1/schedules", json={
            "name": "Daily", "schedule_type": "cron",
            "cron_expression": "0 2 * * *",
            "scan_config": {"user_selection": "all"},
        })
        assert resp.status_code == 403

    def test_viewer_cannot_update_tenant_config(self, viewer_client, db):
        resp = viewer_client.put("/api/v1/settings/tenant", json={
            "okta_org": "test-org",
        })
        assert resp.status_code == 403

    def test_viewer_cannot_reset_data(self, viewer_client, db):
        resp = viewer_client.post("/api/v1/settings/reset?confirm=RESET")
        assert resp.status_code == 403

    def test_viewer_cannot_patch_vulnerability(self, viewer_client, db):
        fake_id = str(uuid.uuid4())
        resp = viewer_client.patch(
            f"/api/v1/vulnerabilities/{fake_id}",
            json={"status": "ACKNOWLEDGED"},
        )
        assert resp.status_code == 403

    def test_viewer_can_read_dashboard(self, viewer_client, db):
        """Viewers should still be able to access read-only endpoints."""
        resp = viewer_client.get("/api/v1/dashboard/summary")
        assert resp.status_code == 200

    def test_viewer_can_list_vulnerabilities(self, viewer_client, db):
        resp = viewer_client.get("/api/v1/vulnerabilities")
        assert resp.status_code == 200

    def test_viewer_can_list_scenarios(self, viewer_client, db):
        resp = viewer_client.get("/api/v1/scenarios")
        assert resp.status_code == 200

    def test_viewer_can_get_tenant_config(self, viewer_client, db):
        resp = viewer_client.get("/api/v1/settings/tenant")
        assert resp.status_code == 200


# ===========================================================================
# WEBHOOK SSRF PREVENTION
# ===========================================================================

class TestWebhookSSRF:
    """Verify that webhook URL validation blocks internal/private targets."""

    def test_block_localhost_ip(self, client, db):
        resp = client.post("/api/v1/notifications/channels", json={
            "name": "SSRF Test", "webhook_url": "http://127.0.0.1:8080/hook",
            "events": ["scan_completed"],
        })
        assert resp.status_code == 422

    def test_block_private_ip(self, client, db):
        resp = client.post("/api/v1/notifications/channels", json={
            "name": "SSRF Test", "webhook_url": "http://10.0.0.1/hook",
            "events": ["scan_completed"],
        })
        assert resp.status_code == 422

    def test_block_link_local(self, client, db):
        resp = client.post("/api/v1/notifications/channels", json={
            "name": "SSRF Test", "webhook_url": "http://169.254.169.254/latest/meta-data/",
            "events": ["scan_completed"],
        })
        assert resp.status_code == 422

    def test_block_localhost_hostname(self, client, db):
        resp = client.post("/api/v1/notifications/channels", json={
            "name": "SSRF Test", "webhook_url": "http://localhost:6379/",
            "events": ["scan_completed"],
        })
        assert resp.status_code == 422

    def test_allow_public_url(self, client, db):
        resp = client.post("/api/v1/notifications/channels", json={
            "name": "Public Hook", "webhook_url": "https://hooks.slack.com/services/test",
            "events": ["scan_completed"],
        })
        assert resp.status_code == 201
