"""Comprehensive tests for CSV and JSON report generators."""

from __future__ import annotations

import csv
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.models.assessment_result import AccessDecision
from src.models.posture_finding import CheckCategory, FindingSeverity, FindingStatus
from src.models.vulnerability import VulnerabilityCategory, VulnerabilityStatus, Severity
from src.reports.csv_generator import generate_csv, _FULL_COLUMNS, _INACTIVE_COLUMNS, _POSTURE_COLUMNS
from src.reports.json_generator import generate_json
from src.schemas.reports import ReportGenerateRequest, ReportResponse


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def _mock_assessment_row(
    *,
    user_email: str = "user@example.com",
    user_id: str = "uid1",
    app_name: str = "TestApp",
    app_id: str = "app1",
    scenario_name: str = "High Risk Scenario",
    access_decision: AccessDecision = AccessDecision.ALLOW,
    policy_name: str | None = "Default Policy",
    policy_id: str | None = "pol1",
    rule_name: str | None = "Allow All",
    rule_id: str | None = "rule1",
    factor_mode: str | None = "2FA",
    reauthenticate_in: str | None = "PT2H",
    phishing_resistant: bool | None = False,
    created_at: datetime | None = None,
) -> MagicMock:
    row = MagicMock()
    row.user_email = user_email
    row.user_id = user_id
    row.app_name = app_name
    row.app_id = app_id
    row.scenario_name = scenario_name
    row.access_decision = access_decision
    row.policy_name = policy_name
    row.policy_id = policy_id
    row.rule_name = rule_name
    row.rule_id = rule_id
    row.factor_mode = factor_mode
    row.reauthenticate_in = reauthenticate_in
    row.phishing_resistant = phishing_resistant
    row.created_at = created_at or datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
    return row


def _mock_posture_finding(
    *,
    check_category=CheckCategory.MFA_POSTURE,
    check_name: str = "mfa_check",
    severity=FindingSeverity.HIGH,
    status=FindingStatus.OPEN,
    title: str = "MFA Gap",
    description: str = "Users without MFA",
    affected_resources: list | dict | None = None,
    remediation_steps: str = "Enable MFA for all users",
    risk_score: int = 80,
    first_detected: datetime | None = None,
    last_detected: datetime | None = None,
) -> MagicMock:
    row = MagicMock()
    row.check_category = check_category
    row.check_name = check_name
    row.severity = severity
    row.status = status
    row.title = title
    row.description = description
    row.affected_resources = affected_resources or [{"user": "test@example.com"}]
    row.remediation_steps = remediation_steps
    row.risk_score = risk_score
    row.first_detected = first_detected or datetime(2026, 3, 15, tzinfo=timezone.utc)
    row.last_detected = last_detected or datetime(2026, 3, 15, tzinfo=timezone.utc)
    return row


def _mock_vulnerability(
    *,
    id: uuid.UUID | None = None,
    title: str = "Policy Violation",
    category=VulnerabilityCategory.AUTH_POLICY_VIOLATION,
    severity=Severity.HIGH,
    status=VulnerabilityStatus.ACTIVE,
    policy_name: str | None = "Default Policy",
    rule_name: str | None = "Allow All",
    app_name: str | None = "TestApp",
    active_impact_count: int = 5,
    risk_score: int = 75,
    first_detected: datetime | None = None,
    last_detected: datetime | None = None,
) -> MagicMock:
    row = MagicMock()
    row.id = id or uuid.uuid4()
    row.title = title
    row.category = category
    row.severity = severity
    row.status = status
    row.policy_name = policy_name
    row.rule_name = rule_name
    row.app_name = app_name
    row.active_impact_count = active_impact_count
    row.risk_score = risk_score
    row.first_detected = first_detected or datetime(2026, 3, 10, tzinfo=timezone.utc)
    row.last_detected = last_detected or datetime(2026, 3, 15, tzinfo=timezone.utc)
    return row


def _mock_impact(
    *,
    user_email: str = "user@example.com",
    user_name: str = "Test User",
    app_name: str | None = "TestApp",
    app_id: str | None = "app1",
    vulnerability_title: str = "Inactive App User",
    first_detected: datetime | None = None,
    last_detected: datetime | None = None,
) -> MagicMock:
    from src.models.vulnerability_impact import ImpactStatus
    row = MagicMock()
    row.user_email = user_email
    row.user_name = user_name
    row.app_name = app_name
    row.app_id = app_id
    row.status = ImpactStatus.ACTIVE
    row.first_detected = first_detected or datetime(2026, 3, 10, tzinfo=timezone.utc)
    row.last_detected = last_detected or datetime(2026, 3, 15, tzinfo=timezone.utc)
    vuln_mock = MagicMock()
    vuln_mock.title = vulnerability_title
    row.vulnerability = vuln_mock
    return row


def _mock_db_session(rows: list[MagicMock]) -> AsyncMock:
    """Mock a db session where execute returns given rows."""
    session = AsyncMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = rows
    result_mock = MagicMock()
    result_mock.scalars.return_value = scalars_mock
    session.execute = AsyncMock(return_value=result_mock)
    return session


def _mock_db_session_multi(call_results: list[list]) -> AsyncMock:
    """Mock a db session where each successive execute call returns different rows."""
    session = AsyncMock()
    call_index = 0

    async def mock_execute(stmt):
        nonlocal call_index
        result_mock = MagicMock()
        scalars_mock = MagicMock()
        if call_index < len(call_results):
            scalars_mock.all.return_value = call_results[call_index]
        else:
            scalars_mock.all.return_value = []
        result_mock.scalars.return_value = scalars_mock
        if call_index < len(call_results):
            result_mock.scalar.return_value = len(call_results[call_index])
            result_mock.all.return_value = []
        else:
            result_mock.scalar.return_value = 0
            result_mock.all.return_value = []
        call_index += 1
        return result_mock

    session.execute = mock_execute
    return session


# ===========================================================================
# CSV FULL EXPORT
# ===========================================================================

@pytest.mark.asyncio
class TestCSVFullExport:
    async def test_empty_data_produces_header_only(self):
        db = _mock_db_session([])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.csv")
            result = await generate_csv(uuid.uuid4(), db, path, report_type="csv_full")

            assert result == path
            with open(path, "r") as f:
                reader = csv.reader(f)
                header = next(reader)
                assert header == _FULL_COLUMNS
                assert list(reader) == []

    async def test_allow_and_deny_rows_written(self):
        allow_row = _mock_assessment_row(
            user_email="alice@corp.com",
            access_decision=AccessDecision.ALLOW,
        )
        deny_row = _mock_assessment_row(
            user_email="bob@corp.com",
            access_decision=AccessDecision.DENY,
            policy_name=None, policy_id=None,
            rule_name=None, rule_id=None,
            factor_mode=None, reauthenticate_in=None,
            phishing_resistant=None,
        )
        db = _mock_db_session([allow_row, deny_row])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_full")

            with open(path, "r") as f:
                rows = list(csv.DictReader(f))

            assert len(rows) == 2
            assert rows[0]["user_email"] == "alice@corp.com"
            assert rows[0]["access_decision"] == "ALLOW"
            assert rows[1]["user_email"] == "bob@corp.com"
            assert rows[1]["access_decision"] == "DENY"
            assert rows[1]["policy_name"] == ""
            assert rows[1]["phishing_resistant"] == ""

    async def test_no_match_decision_serialized(self):
        row = _mock_assessment_row(access_decision=AccessDecision.NO_MATCH)
        db = _mock_db_session([row])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_full")

            with open(path, "r") as f:
                rows = list(csv.DictReader(f))
            assert rows[0]["access_decision"] == "NO_MATCH"

    async def test_phishing_resistant_true_serialized(self):
        row = _mock_assessment_row(phishing_resistant=True)
        db = _mock_db_session([row])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_full")

            with open(path, "r") as f:
                rows = list(csv.DictReader(f))
            assert rows[0]["phishing_resistant"] == "True"

    async def test_creates_parent_directories(self):
        db = _mock_db_session([])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "sub", "dir", "report.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_full")
            assert os.path.exists(path)

    async def test_row_ordering_preserved(self):
        rows = [_mock_assessment_row(user_email=f"user{i}@corp.com") for i in range(5)]
        db = _mock_db_session(rows)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_full")

            with open(path, "r") as f:
                csv_rows = list(csv.DictReader(f))
            assert len(csv_rows) == 5
            for i, row in enumerate(csv_rows):
                assert row["user_email"] == f"user{i}@corp.com"

    async def test_special_characters_in_fields(self):
        row = _mock_assessment_row(
            user_email="user@corp.com",
            app_name='App "With" Quotes, And Commas',
            scenario_name="Scenario\nNewline",
        )
        db = _mock_db_session([row])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_full")

            with open(path, "r") as f:
                rows = list(csv.DictReader(f))
            assert rows[0]["app_name"] == 'App "With" Quotes, And Commas'

    async def test_large_dataset(self):
        rows = [
            _mock_assessment_row(user_email=f"user{i}@corp.com", app_name=f"App{i}")
            for i in range(100)
        ]
        db = _mock_db_session(rows)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_full")

            with open(path, "r") as f:
                csv_rows = list(csv.DictReader(f))
            assert len(csv_rows) == 100


# ===========================================================================
# CSV VIOLATIONS (backend still supports this via API)
# ===========================================================================

@pytest.mark.asyncio
class TestCSVViolationsFilter:
    async def test_violations_report_creates_valid_file(self):
        db = _mock_db_session([])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "violations.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_violations")

            assert os.path.exists(path)
            with open(path, "r") as f:
                header = next(csv.reader(f))
                assert header == _FULL_COLUMNS

    async def test_violations_with_data(self):
        row = _mock_assessment_row(access_decision=AccessDecision.ALLOW)
        db = _mock_db_session([row])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "violations.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_violations")

            with open(path, "r") as f:
                rows = list(csv.DictReader(f))
            assert len(rows) == 1
            assert rows[0]["access_decision"] == "ALLOW"


# ===========================================================================
# CSV INACTIVE USERS
# ===========================================================================

@pytest.mark.asyncio
class TestCSVInactiveUsers:
    async def test_empty_produces_header_only(self):
        db = _mock_db_session([])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "inactive.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_inactive")

            with open(path, "r") as f:
                reader = csv.reader(f)
                assert next(reader) == _INACTIVE_COLUMNS
                assert list(reader) == []

    async def test_inactive_with_data(self):
        impact = _mock_impact(
            user_email="alice@corp.com",
            user_name="Alice",
            app_name="SlackApp",
            app_id="slack1",
            vulnerability_title="Inactive user on SlackApp",
        )
        db = _mock_db_session([impact])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "inactive.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_inactive")

            with open(path, "r") as f:
                rows = list(csv.DictReader(f))
            assert len(rows) == 1
            assert rows[0]["user_email"] == "alice@corp.com"
            assert rows[0]["vulnerability_title"] == "Inactive user on SlackApp"


# ===========================================================================
# CSV POSTURE FINDINGS
# ===========================================================================

@pytest.mark.asyncio
class TestCSVPostureFindings:
    async def test_empty_produces_header_only(self):
        db = _mock_db_session([])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "posture.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_posture")

            with open(path, "r") as f:
                reader = csv.reader(f)
                assert next(reader) == _POSTURE_COLUMNS
                assert list(reader) == []

    async def test_posture_with_list_affected_resources(self):
        finding = _mock_posture_finding(
            title="No MFA enrolled",
            severity=FindingSeverity.CRITICAL,
            affected_resources=[{"user": "a@b.com"}, {"user": "c@d.com"}],
        )
        db = _mock_db_session([finding])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "posture.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_posture")

            with open(path, "r") as f:
                rows = list(csv.DictReader(f))
            assert len(rows) == 1
            assert rows[0]["title"] == "No MFA enrolled"
            assert rows[0]["severity"] == "CRITICAL"
            assert len(json.loads(rows[0]["affected_resources"])) == 2

    async def test_posture_with_dict_affected_resources(self):
        finding = _mock_posture_finding(
            affected_resources={"admin1": "superadmin", "admin2": "orgadmin"},
        )
        db = _mock_db_session([finding])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "posture.csv")
            await generate_csv(uuid.uuid4(), db, path, report_type="csv_posture")

            with open(path, "r") as f:
                rows = list(csv.DictReader(f))
            parsed = json.loads(rows[0]["affected_resources"])
            assert isinstance(parsed, dict)
            assert parsed["admin1"] == "superadmin"


# ===========================================================================
# JSON GENERATOR
# ===========================================================================

@pytest.mark.asyncio
class TestJSONGeneratorEmpty:
    async def test_empty_data_produces_valid_structure(self):
        session = _mock_db_session_multi([[], [], []])
        scan_id = uuid.uuid4()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.json")
            result = await generate_json(scan_id, session, path)

            assert result == path
            with open(path, "r") as f:
                report = json.load(f)

            assert report["scan_info"]["scan_id"] == str(scan_id)
            assert report["policy_violations"] == []
            assert report["posture_findings"] == []
            assert report["vulnerability_summary"] == []
            assert report["metadata"]["total_violations"] == 0
            assert report["metadata"]["total_posture_findings"] == 0
            assert report["metadata"]["total_active_vulnerabilities"] == 0
            assert report["metadata"]["report_version"] == "1.0"


@pytest.mark.asyncio
class TestJSONGeneratorWithData:
    async def test_violations_included(self):
        violation = _mock_assessment_row(
            user_email="alice@corp.com",
            access_decision=AccessDecision.ALLOW,
        )
        session = _mock_db_session_multi([[violation], [], []])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.json")
            await generate_json(uuid.uuid4(), session, path)

            with open(path, "r") as f:
                report = json.load(f)

            assert len(report["policy_violations"]) == 1
            v = report["policy_violations"][0]
            assert v["user_email"] == "alice@corp.com"
            assert v["access_decision"] == "ALLOW"
            assert v["factor_mode"] == "2FA"
            assert v["phishing_resistant"] is False
            assert report["metadata"]["total_violations"] == 1

    async def test_posture_findings_included(self):
        finding = _mock_posture_finding(
            title="Weak MFA",
            severity=FindingSeverity.HIGH,
            status=FindingStatus.OPEN,
        )
        session = _mock_db_session_multi([[], [finding], []])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.json")
            await generate_json(uuid.uuid4(), session, path)

            with open(path, "r") as f:
                report = json.load(f)

            assert len(report["posture_findings"]) == 1
            pf = report["posture_findings"][0]
            assert pf["title"] == "Weak MFA"
            assert pf["severity"] == "HIGH"
            assert report["metadata"]["total_posture_findings"] == 1

    async def test_vulnerabilities_included(self):
        vuln = _mock_vulnerability(
            title="Auth Policy Violation - Allow All",
            active_impact_count=10,
        )
        session = _mock_db_session_multi([[], [], [vuln]])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.json")
            await generate_json(uuid.uuid4(), session, path)

            with open(path, "r") as f:
                report = json.load(f)

            assert len(report["vulnerability_summary"]) == 1
            vs = report["vulnerability_summary"][0]
            assert vs["title"] == "Auth Policy Violation - Allow All"
            assert vs["active_impact_count"] == 10

    async def test_all_sections_populated(self):
        violation = _mock_assessment_row()
        finding = _mock_posture_finding()
        vuln = _mock_vulnerability()
        session = _mock_db_session_multi([[violation], [finding], [vuln]])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.json")
            await generate_json(uuid.uuid4(), session, path)

            with open(path, "r") as f:
                report = json.load(f)

            assert report["metadata"]["total_violations"] == 1
            assert report["metadata"]["total_posture_findings"] == 1
            assert report["metadata"]["total_active_vulnerabilities"] == 1

    async def test_creates_parent_directories(self):
        session = _mock_db_session_multi([[], [], []])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "deep", "nested", "report.json")
            await generate_json(uuid.uuid4(), session, path)
            assert os.path.exists(path)


# ===========================================================================
# REPORT SCHEMA
# ===========================================================================

class TestReportSchemas:
    def test_generate_request_csv(self):
        req = ReportGenerateRequest(scan_id=uuid.uuid4(), report_type="csv_full")
        assert req.report_type == "csv_full"

    def test_generate_request_json(self):
        req = ReportGenerateRequest(scan_id=uuid.uuid4(), report_type="json")
        assert req.report_type == "json"

    def test_response_with_file_path(self):
        resp = ReportResponse(
            id=uuid.uuid4(),
            scan_id=uuid.uuid4(),
            report_type="csv_full",
            file_path="/data/reports/scan1/csv_full.csv",
            generated_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
        )
        assert resp.file_path == "/data/reports/scan1/csv_full.csv"
        assert resp.content is None

    def test_response_pending_no_file(self):
        resp = ReportResponse(
            id=uuid.uuid4(),
            scan_id=uuid.uuid4(),
            report_type="json",
            generated_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
        )
        assert resp.file_path is None
        assert resp.content is None

    def test_response_from_orm_attributes(self):
        class FakeReport:
            id = uuid.uuid4()
            scan_id = uuid.uuid4()
            report_type = "json"
            file_path = "/data/report.json"
            content = None
            generated_at = datetime.now(timezone.utc)
            created_at = datetime.now(timezone.utc)

        resp = ReportResponse.model_validate(FakeReport(), from_attributes=True)
        assert resp.report_type == "json"
        assert resp.file_path == "/data/report.json"
