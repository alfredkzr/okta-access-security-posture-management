"""Tests for the assessment engine with mocked OktaClient and PolicySimulator."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.assessment_result import AccessDecision, AssessmentResult
from src.models.scan import Scan, ScanStatus
from src.models.vulnerability import Vulnerability, VulnerabilityCategory, VulnerabilityStatus
from src.models.vulnerability_impact import ImpactStatus, VulnerabilityImpact
from src.core.assessment_engine import assess_single_user, run_batch_scan
from src.core.policy_simulator import RuleAction, SimulationResult


# ---------------------------------------------------------------------------
# Fixtures (engine and db_session come from conftest.py)
# ---------------------------------------------------------------------------

@pytest.fixture
def scan_id():
    return uuid.uuid4()


@pytest_asyncio.fixture
async def scan_record(db_session, scan_id):
    scan = Scan(
        id=scan_id,
        job_name="test-scan",
        status=ScanStatus.PENDING,
        total_users=1,
    )
    db_session.add(scan)
    await db_session.flush()
    return scan


@pytest.fixture
def mock_scenario():
    s = MagicMock()
    s.id = uuid.uuid4()
    s.name = "Personal Windows Device, Medium Risk"
    s.risk_level = "MEDIUM"
    s.device_platform = "WINDOWS"
    s.device_registered = False
    s.device_managed = False
    s.device_assurance_id = None
    s.ip_address = None
    s.zone_ids = None
    s.is_active = True
    return s


@pytest.fixture
def mock_user():
    return {
        "id": "okta-user-001",
        "status": "ACTIVE",
        "lastLogin": "2026-03-10T10:00:00.000Z",
        "profile": {
            "login": "alice@example.com",
            "email": "alice@example.com",
            "firstName": "Alice",
            "lastName": "Smith",
            "department": "Engineering",
        },
    }


@pytest.fixture
def mock_apps():
    return [
        {"id": "app-001", "label": "Salesforce", "name": "salesforce", "status": "ACTIVE", "signOnMode": "SAML_2_0"},
        {"id": "app-002", "label": "Slack", "name": "slack", "status": "ACTIVE", "signOnMode": "SAML_2_0"},
    ]


def _make_allow_sim_result(user_id: str, app_id: str, scenario_name: str) -> SimulationResult:
    """Create a SimulationResult that matched with a policy/rule."""
    return SimulationResult(
        user_id=user_id,
        app_id=app_id,
        scenario_name=scenario_name,
        matched=True,
        policy_id="policy-001",
        policy_name="Default Access Policy",
        rule_id="rule-001",
        rule_name="Allow All",
    )


def _make_deny_sim_result(user_id: str, app_id: str, scenario_name: str) -> SimulationResult:
    """Create a SimulationResult that matched but results in DENY."""
    return SimulationResult(
        user_id=user_id,
        app_id=app_id,
        scenario_name=scenario_name,
        matched=True,
        policy_id="policy-002",
        policy_name="Strict Access Policy",
        rule_id="rule-002",
        rule_name="Deny Risky",
    )


def _make_no_match_sim_result(user_id: str, app_id: str, scenario_name: str) -> SimulationResult:
    return SimulationResult(
        user_id=user_id,
        app_id=app_id,
        scenario_name=scenario_name,
        matched=False,
    )


ALLOW_RULE = RuleAction(
    access="ALLOW",
    policy_id="policy-001",
    policy_name="Default Access Policy",
    rule_id="rule-001",
    rule_name="Allow All",
    factor_mode="2FA",
    reauthenticate_in="PT2H",
    phishing_resistant=False,
)

DENY_RULE = RuleAction(
    access="DENY",
    policy_id="policy-002",
    policy_name="Strict Access Policy",
    rule_id="rule-002",
    rule_name="Deny Risky",
    factor_mode="2FA",
    reauthenticate_in="PT2H",
    phishing_resistant=True,
)


# ---------------------------------------------------------------------------
# Tests: assess_single_user
# ---------------------------------------------------------------------------


class TestAssessSingleUser:
    @pytest.mark.asyncio
    async def test_allow_results_create_vulnerabilities(
        self, db_session, scan_record, scan_id, mock_scenario, mock_user, mock_apps
    ):
        """When policy simulation returns ALLOW, vulnerabilities are created."""
        okta_client = AsyncMock()
        okta_client.get_user_by_login.return_value = mock_user
        okta_client.get_user_apps.return_value = mock_apps
        # Return active logs so user is not flagged inactive
        okta_client.get_user_app_logs.return_value = [
            {"published": "2026-03-10T10:00:00.000Z", "client": {}, "securityContext": {}}
        ]

        with patch("src.core.assessment_engine.PolicySimulator") as MockSimulator:
            sim_instance = AsyncMock()
            MockSimulator.return_value = sim_instance

            # All simulations return ALLOW
            async def fake_simulate(user_id, app_id, scenario):
                return _make_allow_sim_result(user_id, app_id, scenario.name)

            sim_instance.simulate = fake_simulate
            sim_instance.get_rule_action = AsyncMock(return_value=ALLOW_RULE)

            summary = await assess_single_user(
                email="alice@example.com",
                db_session=db_session,
                okta_client=okta_client,
                scenarios=[mock_scenario],
                scan_id=scan_id,
            )

        assert summary["user_email"] == "alice@example.com"
        assert summary["apps_scanned"] == 2
        assert summary["violations_found"] == 2  # 2 apps x 1 scenario = 2 ALLOW results
        assert summary["inactive_apps"] == 0

        # Verify assessment results persisted
        stmt = select(AssessmentResult).where(AssessmentResult.scan_id == scan_id)
        result = await db_session.execute(stmt)
        assessments = result.scalars().all()
        assert len(assessments) == 2
        assert all(a.access_decision == AccessDecision.ALLOW for a in assessments)

        # Verify vulnerabilities created
        vuln_stmt = select(Vulnerability).where(
            Vulnerability.category == VulnerabilityCategory.AUTH_POLICY_VIOLATION
        )
        vuln_result = await db_session.execute(vuln_stmt)
        vulns = vuln_result.scalars().all()
        # Both use rule_id="rule-001", so only 1 vulnerability with 1 impact for alice
        assert len(vulns) == 1

    @pytest.mark.asyncio
    async def test_deny_results_create_no_vulnerabilities(
        self, db_session, scan_record, scan_id, mock_scenario, mock_user, mock_apps
    ):
        """When policy simulation returns DENY, no vulnerabilities are created."""
        okta_client = AsyncMock()
        okta_client.get_user_by_login.return_value = mock_user
        okta_client.get_user_apps.return_value = mock_apps
        okta_client.get_user_app_logs.return_value = [
            {"published": "2026-03-10T10:00:00.000Z", "client": {}, "securityContext": {}}
        ]

        with patch("src.core.assessment_engine.PolicySimulator") as MockSimulator:
            sim_instance = AsyncMock()
            MockSimulator.return_value = sim_instance

            async def fake_simulate(user_id, app_id, scenario):
                return _make_deny_sim_result(user_id, app_id, scenario.name)

            sim_instance.simulate = fake_simulate
            sim_instance.get_rule_action = AsyncMock(return_value=DENY_RULE)

            summary = await assess_single_user(
                email="alice@example.com",
                db_session=db_session,
                okta_client=okta_client,
                scenarios=[mock_scenario],
                scan_id=scan_id,
            )

        assert summary["violations_found"] == 0

        # Assessment results should still be persisted
        stmt = select(AssessmentResult).where(AssessmentResult.scan_id == scan_id)
        result = await db_session.execute(stmt)
        assessments = result.scalars().all()
        assert len(assessments) == 2
        assert all(a.access_decision == AccessDecision.DENY for a in assessments)

        # No vulnerabilities
        vuln_stmt = select(Vulnerability)
        vuln_result = await db_session.execute(vuln_stmt)
        assert len(vuln_result.scalars().all()) == 0

    @pytest.mark.asyncio
    async def test_inactive_app_detection(
        self, db_session, scan_record, scan_id, mock_scenario, mock_user, mock_apps
    ):
        """Apps with no login in 90 days are flagged as inactive."""
        okta_client = AsyncMock()
        okta_client.get_user_by_login.return_value = mock_user
        okta_client.get_user_apps.return_value = mock_apps
        # Return empty logs = no login activity = inactive
        okta_client.get_user_app_logs.return_value = []

        with patch("src.core.assessment_engine.PolicySimulator") as MockSimulator:
            sim_instance = AsyncMock()
            MockSimulator.return_value = sim_instance

            async def fake_simulate(user_id, app_id, scenario):
                return _make_no_match_sim_result(user_id, app_id, scenario.name)

            sim_instance.simulate = fake_simulate

            summary = await assess_single_user(
                email="alice@example.com",
                db_session=db_session,
                okta_client=okta_client,
                scenarios=[mock_scenario],
                scan_id=scan_id,
            )

        assert summary["inactive_apps"] == 2  # Both apps are inactive
        assert summary["violations_found"] == 0

        # Verify inactive vulns
        vuln_stmt = select(Vulnerability).where(
            Vulnerability.category == VulnerabilityCategory.INACTIVE_APP_USERS
        )
        vuln_result = await db_session.execute(vuln_stmt)
        vulns = vuln_result.scalars().all()
        assert len(vulns) == 2  # One per app

    @pytest.mark.asyncio
    async def test_user_not_found_raises(self, db_session, scan_record, scan_id, mock_scenario):
        """If user is not found in Okta, ValueError is raised."""
        okta_client = AsyncMock()
        okta_client.get_user_by_login.return_value = None

        with pytest.raises(ValueError, match="User not found"):
            await assess_single_user(
                email="nonexistent@example.com",
                db_session=db_session,
                okta_client=okta_client,
                scenarios=[mock_scenario],
                scan_id=scan_id,
            )


# ---------------------------------------------------------------------------
# Tests: run_batch_scan
# ---------------------------------------------------------------------------


class TestRunBatchScan:
    @pytest.mark.asyncio
    async def test_batch_scan_tracks_failures(
        self, db_session, scan_record, scan_id, mock_scenario
    ):
        """Failed users are tracked in failed_user_details."""
        okta_client = AsyncMock()

        # First user succeeds, second fails
        call_count = 0

        async def fake_get_user(email):
            nonlocal call_count
            call_count += 1
            if email == "alice@example.com":
                return {
                    "id": "okta-user-001",
                    "profile": {"login": "alice@example.com", "email": "alice@example.com",
                                "firstName": "Alice", "lastName": "Smith"},
                }
            return None  # Bob not found

        okta_client.get_user_by_login = fake_get_user
        okta_client.get_user_apps = AsyncMock(return_value=[])
        okta_client.get_user_app_logs = AsyncMock(return_value=[])

        with patch("src.core.assessment_engine.PolicySimulator"):
            summary = await run_batch_scan(
                scan_id=scan_id,
                user_list=["alice@example.com", "bob@example.com"],
                scenarios=[mock_scenario],
                db_session=db_session,
                okta_client=okta_client,
                max_workers=2,
                api_delay=0,
            )

        assert summary["total_users"] == 2
        assert summary["successful_users"] == 1
        assert summary["failed_users"] == 1
        assert summary["status"] == ScanStatus.COMPLETED_WITH_ERRORS.value
        assert len(summary["failed_user_details"]) == 1
        assert summary["failed_user_details"][0]["email"] == "bob@example.com"

    @pytest.mark.asyncio
    async def test_batch_scan_all_succeed(
        self, db_session, scan_record, scan_id, mock_scenario
    ):
        """All users succeed -> status is COMPLETED."""
        okta_client = AsyncMock()
        okta_client.get_user_by_login.return_value = {
            "id": "okta-user-001",
            "profile": {"login": "alice@example.com", "email": "alice@example.com",
                        "firstName": "Alice", "lastName": "Smith"},
        }
        okta_client.get_user_apps.return_value = []
        okta_client.get_user_app_logs.return_value = []

        with patch("src.core.assessment_engine.PolicySimulator"):
            summary = await run_batch_scan(
                scan_id=scan_id,
                user_list=["alice@example.com"],
                scenarios=[mock_scenario],
                db_session=db_session,
                okta_client=okta_client,
                max_workers=2,
                api_delay=0,
            )

        assert summary["status"] == ScanStatus.COMPLETED.value
        assert summary["successful_users"] == 1
        assert summary["failed_users"] == 0

    @pytest.mark.asyncio
    async def test_batch_scan_all_fail(
        self, db_session, scan_record, scan_id, mock_scenario
    ):
        """All users fail -> status is FAILED."""
        okta_client = AsyncMock()
        okta_client.get_user_by_login.return_value = None  # All users not found

        with patch("src.core.assessment_engine.PolicySimulator"):
            summary = await run_batch_scan(
                scan_id=scan_id,
                user_list=["alice@example.com", "bob@example.com"],
                scenarios=[mock_scenario],
                db_session=db_session,
                okta_client=okta_client,
                max_workers=2,
                api_delay=0,
            )

        assert summary["status"] == ScanStatus.FAILED.value
        assert summary["failed_users"] == 2

    @pytest.mark.asyncio
    async def test_batch_scan_updates_progress(
        self, db_session, scan_record, scan_id, mock_scenario
    ):
        """Scan progress is updated in the DB."""
        okta_client = AsyncMock()
        okta_client.get_user_by_login.return_value = {
            "id": "okta-user-001",
            "profile": {"login": "user@example.com", "email": "user@example.com",
                        "firstName": "User", "lastName": "One"},
        }
        okta_client.get_user_apps.return_value = []
        okta_client.get_user_app_logs.return_value = []

        with patch("src.core.assessment_engine.PolicySimulator"):
            await run_batch_scan(
                scan_id=scan_id,
                user_list=["user@example.com"],
                scenarios=[mock_scenario],
                db_session=db_session,
                okta_client=okta_client,
                max_workers=1,
                api_delay=0,
            )

        # Check scan record was updated
        stmt = select(Scan).where(Scan.id == scan_id)
        result = await db_session.execute(stmt)
        scan = result.scalar_one()
        assert scan.progress_pct == 100.0
        assert scan.completed_at is not None
        assert scan.duration_seconds is not None
