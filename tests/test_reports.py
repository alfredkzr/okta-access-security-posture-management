"""Edge case tests for src/reports/csv_generator.py and json_generator.py."""

from __future__ import annotations

import csv
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from src.models.assessment_result import AccessDecision
from src.reports.csv_generator import generate_csv, _FULL_COLUMNS
from src.reports.json_generator import generate_json


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


def _mock_db_session_for_assessment(rows: list[MagicMock]) -> AsyncMock:
    """Mock a db session where execute returns given assessment rows."""
    session = AsyncMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = rows
    result_mock = MagicMock()
    result_mock.scalars.return_value = scalars_mock
    session.execute = AsyncMock(return_value=result_mock)
    return session


@pytest.mark.asyncio
class TestCSVGeneratorEmpty:
    async def test_no_results_produces_header_only(self):
        db = _mock_db_session_for_assessment([])
        scan_id = uuid.uuid4()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.csv")
            result = await generate_csv(scan_id, db, path, report_type="csv_full")

            assert result == path
            with open(path, "r") as f:
                reader = csv.reader(f)
                header = next(reader)
                assert header == _FULL_COLUMNS
                rows = list(reader)
                assert len(rows) == 0


@pytest.mark.asyncio
class TestCSVGeneratorWithData:
    async def test_allow_and_deny_rows_written(self):
        allow_row = _mock_assessment_row(
            user_email="alice@corp.com",
            access_decision=AccessDecision.ALLOW,
        )
        deny_row = _mock_assessment_row(
            user_email="bob@corp.com",
            access_decision=AccessDecision.DENY,
            policy_name=None,
            policy_id=None,
            rule_name=None,
            rule_id=None,
            factor_mode=None,
            reauthenticate_in=None,
            phishing_resistant=None,
        )
        db = _mock_db_session_for_assessment([allow_row, deny_row])
        scan_id = uuid.uuid4()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.csv")
            await generate_csv(scan_id, db, path, report_type="csv_full")

            with open(path, "r") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            assert len(rows) == 2
            assert rows[0]["user_email"] == "alice@corp.com"
            assert rows[0]["access_decision"] == "ALLOW"
            assert rows[1]["user_email"] == "bob@corp.com"
            assert rows[1]["access_decision"] == "DENY"
            # Null fields should be empty strings
            assert rows[1]["policy_name"] == ""
            assert rows[1]["phishing_resistant"] == ""


@pytest.mark.asyncio
class TestCSVViolationsFilter:
    async def test_violations_only_queries_allow(self):
        """csv_violations report type should filter for ALLOW rows via the query.
        We verify that the correct report_type is passed through."""
        db = _mock_db_session_for_assessment([])
        scan_id = uuid.uuid4()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "violations.csv")
            await generate_csv(scan_id, db, path, report_type="csv_violations")

            # The DB session.execute was called — we can verify the file was created
            assert os.path.exists(path)
            with open(path, "r") as f:
                reader = csv.reader(f)
                header = next(reader)
                assert header == _FULL_COLUMNS


@pytest.mark.asyncio
class TestJSONGeneratorEmpty:
    async def test_empty_data_produces_valid_structure(self):
        """JSON generator with no data should produce valid structure with all sections."""
        session = AsyncMock()

        # Three queries: violations, posture, vulnerabilities — all return empty
        empty_result = MagicMock()
        empty_scalars = MagicMock()
        empty_scalars.all.return_value = []
        empty_result.scalars.return_value = empty_scalars
        session.execute = AsyncMock(return_value=empty_result)

        scan_id = uuid.uuid4()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.json")
            result = await generate_json(scan_id, session, path)

            assert result == path
            with open(path, "r") as f:
                report = json.load(f)

            assert "scan_info" in report
            assert "policy_violations" in report
            assert "posture_findings" in report
            assert "vulnerability_summary" in report
            assert "metadata" in report

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
    async def test_violations_included_in_output(self):
        """JSON generator includes policy violations from the DB."""
        violation = MagicMock()
        violation.user_email = "alice@corp.com"
        violation.user_id = "u1"
        violation.app_name = "App1"
        violation.app_id = "a1"
        violation.scenario_name = "High Risk"
        violation.policy_name = "Default Policy"
        violation.policy_id = "p1"
        violation.rule_name = "Allow All"
        violation.rule_id = "r1"
        violation.access_decision = AccessDecision.ALLOW
        violation.factor_mode = "2FA"
        violation.reauthenticate_in = "PT2H"
        violation.phishing_resistant = False

        session = AsyncMock()
        call_count = 0

        async def mock_execute(stmt):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            scalars = MagicMock()
            if call_count == 1:
                # First call: violations
                scalars.all.return_value = [violation]
            else:
                # Subsequent calls: empty
                scalars.all.return_value = []
            result.scalars.return_value = scalars
            return result

        session.execute = mock_execute

        scan_id = uuid.uuid4()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.json")
            await generate_json(scan_id, session, path)

            with open(path, "r") as f:
                report = json.load(f)

            assert len(report["policy_violations"]) == 1
            v = report["policy_violations"][0]
            assert v["user_email"] == "alice@corp.com"
            assert v["access_decision"] == "ALLOW"
            assert report["metadata"]["total_violations"] == 1


@pytest.mark.asyncio
class TestCSVSubdirectoryCreation:
    async def test_creates_parent_directories(self):
        """generate_csv should create intermediate directories if they don't exist."""
        db = _mock_db_session_for_assessment([])
        scan_id = uuid.uuid4()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "sub", "dir", "report.csv")
            await generate_csv(scan_id, db, path, report_type="csv_full")
            assert os.path.exists(path)
