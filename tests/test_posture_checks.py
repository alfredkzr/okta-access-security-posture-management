"""Tests for posture check modules: admin_security and mfa_posture."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.core.posture_checks.admin_security import (
    INACTIVE_ADMIN_DAYS,
    SUPER_ADMIN_THRESHOLD,
    check_admin_security,
)
from src.core.posture_checks.mfa_posture import (
    PHISHING_RESISTANT_COVERAGE_THRESHOLD,
    check_mfa_posture,
)
from src.models.posture_finding import FindingSeverity, FindingStatus


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_user(
    user_id: str = "u1",
    login: str = "user@example.com",
    first_name: str = "Test",
    last_name: str = "User",
    status: str = "ACTIVE",
    last_login: str | None = None,
) -> dict[str, Any]:
    """Build a minimal Okta user dict."""
    return {
        "id": user_id,
        "status": status,
        "lastLogin": last_login,
        "profile": {
            "login": login,
            "email": login,
            "firstName": first_name,
            "lastName": last_name,
        },
    }


def _make_mock_response(json_data: Any, status_code: int = 200) -> httpx.Response:
    """Build an httpx.Response mock for _request return values."""
    resp = MagicMock(spec=httpx.Response)
    resp.json.return_value = json_data
    resp.status_code = status_code
    resp.headers = {}
    return resp


class FakeOktaClient:
    """Lightweight async mock of OktaClient for posture check tests."""

    def __init__(self) -> None:
        self.users: list[dict] = []
        self.user_roles: dict[str, list[dict]] = {}  # user_id -> roles
        self.user_factors: dict[str, list[dict]] = {}  # user_id -> factors
        self.groups: list[dict] = []
        self.group_roles: dict[str, list[dict]] = {}  # group_id -> roles

    async def list_users(self, *, limit: int = 200) -> list[dict]:
        return self.users

    async def get_user_factors(self, user_id: str) -> list[dict]:
        return self.user_factors.get(user_id, [])

    async def get_group_roles(self, group_id: str) -> list[dict]:
        return self.group_roles.get(group_id, [])

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Mock _request for admin role lookups."""
        if "/roles" in path and "/groups/" not in path:
            # Extract user_id from path like /api/v1/users/{user_id}/roles
            parts = path.strip("/").split("/")
            if len(parts) >= 4 and parts[2] == "users":
                user_id = parts[3]
                return _make_mock_response(self.user_roles.get(user_id, []))
        return _make_mock_response([])

    async def _get_paginated(self, path: str, *, params: dict | None = None) -> list[dict]:
        """Mock paginated endpoint for groups listing."""
        if "/groups" in path:
            return self.groups
        return []


class FakeDbSession:
    """Minimal mock of an async SQLAlchemy session."""

    def __init__(self) -> None:
        self.added: list[Any] = []

    def add(self, obj: Any) -> None:
        self.added.append(obj)


# ---------------------------------------------------------------------------
# admin_security tests
# ---------------------------------------------------------------------------


class TestSuperAdminCountDetection:
    @pytest.mark.asyncio
    async def test_no_finding_when_under_threshold(self) -> None:
        client = FakeOktaClient()
        # 3 super admins (within threshold of 4)
        for i in range(3):
            uid = f"sa{i}"
            client.users.append(_make_user(user_id=uid, login=f"admin{i}@example.com"))
            client.user_roles[uid] = [{"type": "SUPER_ADMIN"}]
            client.user_factors[uid] = [{"factorType": "webauthn"}]

        db = FakeDbSession()
        findings = await check_admin_security(client, db, uuid.uuid4())

        count_findings = [f for f in findings if f.check_name == "super_admin_count_exceeded"]
        assert len(count_findings) == 0

    @pytest.mark.asyncio
    async def test_finding_when_exceeds_threshold(self) -> None:
        client = FakeOktaClient()
        # 6 super admins (exceeds threshold of 4)
        for i in range(6):
            uid = f"sa{i}"
            client.users.append(_make_user(user_id=uid, login=f"admin{i}@example.com"))
            client.user_roles[uid] = [{"type": "SUPER_ADMIN"}]
            client.user_factors[uid] = [{"factorType": "webauthn"}]

        db = FakeDbSession()
        findings = await check_admin_security(client, db, uuid.uuid4())

        count_findings = [f for f in findings if f.check_name == "super_admin_count_exceeded"]
        assert len(count_findings) == 1
        finding = count_findings[0]
        assert finding.severity == FindingSeverity.HIGH
        assert finding.status == FindingStatus.OPEN
        assert len(finding.affected_resources) == 6


class TestSuperAdminPhishingResistantMfa:
    @pytest.mark.asyncio
    async def test_no_finding_when_all_have_phishing_resistant(self) -> None:
        client = FakeOktaClient()
        for i in range(2):
            uid = f"sa{i}"
            client.users.append(_make_user(user_id=uid, login=f"admin{i}@example.com"))
            client.user_roles[uid] = [{"type": "SUPER_ADMIN"}]
            client.user_factors[uid] = [{"factorType": "webauthn"}]

        db = FakeDbSession()
        findings = await check_admin_security(client, db, uuid.uuid4())

        mfa_findings = [f for f in findings if f.check_name == "super_admin_no_phishing_resistant_mfa"]
        assert len(mfa_findings) == 0

    @pytest.mark.asyncio
    async def test_finding_when_admin_lacks_phishing_resistant(self) -> None:
        client = FakeOktaClient()
        # Admin 0 has webauthn, admin 1 only has sms
        client.users.append(_make_user(user_id="sa0", login="admin0@example.com"))
        client.user_roles["sa0"] = [{"type": "SUPER_ADMIN"}]
        client.user_factors["sa0"] = [{"factorType": "webauthn"}]

        client.users.append(_make_user(user_id="sa1", login="admin1@example.com"))
        client.user_roles["sa1"] = [{"type": "SUPER_ADMIN"}]
        client.user_factors["sa1"] = [{"factorType": "sms"}]

        db = FakeDbSession()
        findings = await check_admin_security(client, db, uuid.uuid4())

        mfa_findings = [f for f in findings if f.check_name == "super_admin_no_phishing_resistant_mfa"]
        assert len(mfa_findings) == 1
        finding = mfa_findings[0]
        assert finding.severity == FindingSeverity.CRITICAL
        assert len(finding.affected_resources) == 1
        assert finding.affected_resources[0]["id"] == "sa1"

    @pytest.mark.asyncio
    async def test_signed_nonce_counts_as_phishing_resistant(self) -> None:
        client = FakeOktaClient()
        client.users.append(_make_user(user_id="sa0", login="admin0@example.com"))
        client.user_roles["sa0"] = [{"type": "SUPER_ADMIN"}]
        client.user_factors["sa0"] = [{"factorType": "signed_nonce"}]

        db = FakeDbSession()
        findings = await check_admin_security(client, db, uuid.uuid4())

        mfa_findings = [f for f in findings if f.check_name == "super_admin_no_phishing_resistant_mfa"]
        assert len(mfa_findings) == 0


class TestInactiveAdminDetection:
    @pytest.mark.asyncio
    async def test_finding_for_inactive_admin(self) -> None:
        client = FakeOktaClient()
        # Admin who hasn't logged in for 60 days
        old_login = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        client.users.append(
            _make_user(user_id="sa0", login="admin0@example.com", last_login=old_login)
        )
        client.user_roles["sa0"] = [{"type": "ORG_ADMIN"}]
        client.user_factors["sa0"] = [{"factorType": "push"}]

        db = FakeDbSession()
        findings = await check_admin_security(client, db, uuid.uuid4())

        inactive_findings = [f for f in findings if f.check_name == "inactive_admin_accounts"]
        assert len(inactive_findings) == 1
        finding = inactive_findings[0]
        assert finding.severity == FindingSeverity.HIGH
        assert len(finding.affected_resources) == 1
        assert finding.affected_resources[0]["days_inactive"] >= 59

    @pytest.mark.asyncio
    async def test_finding_for_never_logged_in_admin(self) -> None:
        client = FakeOktaClient()
        client.users.append(
            _make_user(user_id="sa0", login="admin0@example.com", last_login=None)
        )
        client.user_roles["sa0"] = [{"type": "SUPER_ADMIN"}]
        client.user_factors["sa0"] = [{"factorType": "webauthn"}]

        db = FakeDbSession()
        findings = await check_admin_security(client, db, uuid.uuid4())

        inactive_findings = [f for f in findings if f.check_name == "inactive_admin_accounts"]
        assert len(inactive_findings) == 1
        assert inactive_findings[0].affected_resources[0]["days_inactive"] == "never"

    @pytest.mark.asyncio
    async def test_no_finding_for_recently_active_admin(self) -> None:
        client = FakeOktaClient()
        recent_login = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        client.users.append(
            _make_user(user_id="sa0", login="admin0@example.com", last_login=recent_login)
        )
        client.user_roles["sa0"] = [{"type": "ORG_ADMIN"}]
        client.user_factors["sa0"] = [{"factorType": "push"}]

        db = FakeDbSession()
        findings = await check_admin_security(client, db, uuid.uuid4())

        inactive_findings = [f for f in findings if f.check_name == "inactive_admin_accounts"]
        assert len(inactive_findings) == 0


class TestShadowAdminDetection:
    @pytest.mark.asyncio
    async def test_finding_for_group_with_admin_roles(self) -> None:
        client = FakeOktaClient()
        # Need at least one user for the admin collection to work
        client.users.append(_make_user(user_id="u1"))
        client.user_roles["u1"] = []

        client.groups = [
            {"id": "g1", "profile": {"name": "IT Admins", "description": "IT team"}},
        ]
        client.group_roles["g1"] = [{"type": "SUPER_ADMIN"}]

        db = FakeDbSession()
        findings = await check_admin_security(client, db, uuid.uuid4())

        shadow_findings = [f for f in findings if f.check_name == "shadow_admin_groups"]
        assert len(shadow_findings) == 1
        assert shadow_findings[0].severity == FindingSeverity.HIGH
        assert shadow_findings[0].affected_resources[0]["group_name"] == "IT Admins"

    @pytest.mark.asyncio
    async def test_no_finding_when_no_group_has_roles(self) -> None:
        client = FakeOktaClient()
        client.users.append(_make_user(user_id="u1"))
        client.user_roles["u1"] = []

        client.groups = [
            {"id": "g1", "profile": {"name": "Everyone", "description": ""}},
        ]
        client.group_roles["g1"] = []

        db = FakeDbSession()
        findings = await check_admin_security(client, db, uuid.uuid4())

        shadow_findings = [f for f in findings if f.check_name == "shadow_admin_groups"]
        assert len(shadow_findings) == 0


# ---------------------------------------------------------------------------
# mfa_posture tests
# ---------------------------------------------------------------------------


class TestNoMfaEnrolledDetection:
    @pytest.mark.asyncio
    async def test_finding_for_users_with_no_factors(self) -> None:
        client = FakeOktaClient()
        users = [
            _make_user(user_id="u1", login="user1@example.com"),
            _make_user(user_id="u2", login="user2@example.com"),
        ]
        # u1 has no factors, u2 has only security question
        client.user_factors["u1"] = []
        client.user_factors["u2"] = [{"factorType": "question"}]

        db = FakeDbSession()
        findings = await check_mfa_posture(client, db, uuid.uuid4(), users)

        no_mfa = [f for f in findings if f.check_name == "users_no_mfa_enrolled"]
        assert len(no_mfa) == 1
        finding = no_mfa[0]
        assert finding.severity == FindingSeverity.CRITICAL
        assert len(finding.affected_resources) == 2

    @pytest.mark.asyncio
    async def test_no_finding_when_all_have_mfa(self) -> None:
        client = FakeOktaClient()
        users = [
            _make_user(user_id="u1", login="user1@example.com"),
        ]
        client.user_factors["u1"] = [{"factorType": "push"}]

        db = FakeDbSession()
        findings = await check_mfa_posture(client, db, uuid.uuid4(), users)

        no_mfa = [f for f in findings if f.check_name == "users_no_mfa_enrolled"]
        assert len(no_mfa) == 0


class TestWeakMfaOnlyDetection:
    @pytest.mark.asyncio
    async def test_finding_for_users_with_only_sms(self) -> None:
        client = FakeOktaClient()
        users = [
            _make_user(user_id="u1", login="user1@example.com"),
            _make_user(user_id="u2", login="user2@example.com"),
        ]
        client.user_factors["u1"] = [{"factorType": "sms"}]
        client.user_factors["u2"] = [{"factorType": "sms"}, {"factorType": "call"}]

        db = FakeDbSession()
        findings = await check_mfa_posture(client, db, uuid.uuid4(), users)

        weak = [f for f in findings if f.check_name == "users_weak_mfa_only"]
        assert len(weak) == 1
        finding = weak[0]
        assert finding.severity == FindingSeverity.HIGH
        assert len(finding.affected_resources) == 2

    @pytest.mark.asyncio
    async def test_no_finding_when_user_has_strong_factor(self) -> None:
        client = FakeOktaClient()
        users = [
            _make_user(user_id="u1", login="user1@example.com"),
        ]
        # Has SMS but also has push (strong) → not weak-only
        client.user_factors["u1"] = [{"factorType": "sms"}, {"factorType": "push"}]

        db = FakeDbSession()
        findings = await check_mfa_posture(client, db, uuid.uuid4(), users)

        weak = [f for f in findings if f.check_name == "users_weak_mfa_only"]
        assert len(weak) == 0


class TestPhishingResistantCoverage:
    @pytest.mark.asyncio
    async def test_finding_when_coverage_below_threshold(self) -> None:
        client = FakeOktaClient()
        # 10 users, only 2 have webauthn = 20% coverage (below 50%)
        users = []
        for i in range(10):
            uid = f"u{i}"
            users.append(_make_user(user_id=uid, login=f"user{i}@example.com"))
            if i < 2:
                client.user_factors[uid] = [{"factorType": "webauthn"}]
            else:
                client.user_factors[uid] = [{"factorType": "push"}]

        db = FakeDbSession()
        findings = await check_mfa_posture(client, db, uuid.uuid4(), users)

        coverage = [f for f in findings if f.check_name == "low_phishing_resistant_mfa_coverage"]
        assert len(coverage) == 1
        finding = coverage[0]
        assert finding.severity == FindingSeverity.HIGH
        assert "20.0%" in finding.title

    @pytest.mark.asyncio
    async def test_no_finding_when_coverage_meets_threshold(self) -> None:
        client = FakeOktaClient()
        # 10 users, 6 have webauthn = 60% coverage (above 50%)
        users = []
        for i in range(10):
            uid = f"u{i}"
            users.append(_make_user(user_id=uid, login=f"user{i}@example.com"))
            if i < 6:
                client.user_factors[uid] = [{"factorType": "webauthn"}]
            else:
                client.user_factors[uid] = [{"factorType": "push"}]

        db = FakeDbSession()
        findings = await check_mfa_posture(client, db, uuid.uuid4(), users)

        coverage = [f for f in findings if f.check_name == "low_phishing_resistant_mfa_coverage"]
        assert len(coverage) == 0

    @pytest.mark.asyncio
    async def test_signed_nonce_counts_for_coverage(self) -> None:
        client = FakeOktaClient()
        # 2 users, both have signed_nonce = 100% coverage
        users = [
            _make_user(user_id="u0", login="user0@example.com"),
            _make_user(user_id="u1", login="user1@example.com"),
        ]
        client.user_factors["u0"] = [{"factorType": "signed_nonce"}]
        client.user_factors["u1"] = [{"factorType": "signed_nonce"}]

        db = FakeDbSession()
        findings = await check_mfa_posture(client, db, uuid.uuid4(), users)

        coverage = [f for f in findings if f.check_name == "low_phishing_resistant_mfa_coverage"]
        assert len(coverage) == 0


class TestMfaPostureEdgeCases:
    @pytest.mark.asyncio
    async def test_empty_user_list_produces_no_findings(self) -> None:
        client = FakeOktaClient()
        db = FakeDbSession()
        findings = await check_mfa_posture(client, db, uuid.uuid4(), [])
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_findings_added_to_session(self) -> None:
        client = FakeOktaClient()
        users = [_make_user(user_id="u1")]
        client.user_factors["u1"] = []  # No factors -> will create finding

        db = FakeDbSession()
        findings = await check_mfa_posture(client, db, uuid.uuid4(), users)

        # Findings should be added to db session
        assert len(db.added) > 0
        assert len(db.added) == len(findings)
