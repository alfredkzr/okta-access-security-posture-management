"""Admin security posture checks.

Evaluates Okta admin account hygiene: super admin count, phishing-resistant
MFA enrollment, inactive admin accounts, and shadow admin detection.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog

from src.core.risk_scorer import RiskInput, calculate_risk_score
from src.models.posture_finding import (
    CheckCategory,
    FindingSeverity,
    FindingStatus,
    PostureFinding,
)

logger = structlog.get_logger(__name__)

# Okta super admin role type identifier
SUPER_ADMIN_ROLE = "SUPER_ADMIN"

# Factor types considered phishing-resistant (FIDO2 / Okta FastPass)
PHISHING_RESISTANT_FACTORS = {"webauthn", "signed_nonce"}

# Max number of super admins before flagging
SUPER_ADMIN_THRESHOLD = 4

# Days of inactivity before flagging an admin as inactive
INACTIVE_ADMIN_DAYS = 30


async def check_admin_security(
    okta_client: Any,
    db_session: Any,
    scan_id: uuid.UUID,
) -> list[PostureFinding]:
    """Run all admin security posture checks.

    Checks performed:
      1. Super admin count exceeds threshold
      2. Super admins without phishing-resistant MFA
      3. Inactive admin accounts (no login in 30+ days)
      4. Shadow admin detection (groups with admin roles)

    Args:
        okta_client: An initialised OktaClient instance.
        db_session: SQLAlchemy async session (findings are added but not committed).
        scan_id: UUID of the current posture scan.

    Returns:
        List of PostureFinding ORM objects created during the check.
    """
    findings: list[PostureFinding] = []
    now = datetime.now(timezone.utc)

    # Gather admin users via role assignments API
    admin_users: list[dict[str, Any]] = []
    super_admin_users: list[dict[str, Any]] = []

    try:
        admin_users, super_admin_users = await _collect_admin_users(okta_client)
    except Exception:
        logger.exception("admin_security.collect_admin_users_failed")

    # ---- Check 1: Super admin count ----
    try:
        finding = _check_super_admin_count(super_admin_users, scan_id, now)
        if finding:
            findings.append(finding)
    except Exception:
        logger.exception("admin_security.super_admin_count_check_failed")

    # ---- Check 2: Super admins without phishing-resistant MFA ----
    try:
        finding = await _check_super_admin_mfa(okta_client, super_admin_users, scan_id, now)
        if finding:
            findings.append(finding)
    except Exception:
        logger.exception("admin_security.super_admin_mfa_check_failed")

    # ---- Check 3: Inactive admin accounts ----
    try:
        finding = _check_inactive_admins(admin_users, scan_id, now)
        if finding:
            findings.append(finding)
    except Exception:
        logger.exception("admin_security.inactive_admin_check_failed")

    # ---- Check 4: Shadow admin detection ----
    try:
        shadow_findings = await _check_shadow_admins(okta_client, scan_id, now)
        findings.extend(shadow_findings)
    except Exception:
        logger.exception("admin_security.shadow_admin_check_failed")

    # Add all findings to the session (caller commits)
    for f in findings:
        db_session.add(f)

    logger.info(
        "admin_security.checks_complete",
        scan_id=str(scan_id),
        findings_count=len(findings),
    )
    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _collect_admin_users(okta_client: Any) -> tuple[list[dict], list[dict]]:
    """Enumerate all users with admin role assignments.

    Uses the Okta Users API with a search for admin role bindings.
    Falls back to listing all users and checking roles individually if needed.

    Returns:
        (all_admin_users, super_admin_users) where each entry is a dict with
        user profile data plus a ``roles`` key listing assigned role types.
    """
    all_admins: list[dict[str, Any]] = []
    super_admins: list[dict[str, Any]] = []

    # List all users then check role assignments
    # The Okta API requires fetching role assignments per user via
    # GET /api/v1/users/{userId}/roles
    users = await okta_client.list_users(limit=200)

    sem = asyncio.Semaphore(5)

    async def _get_roles(user: dict) -> tuple[dict, list[dict]]:
        async with sem:
            try:
                resp = await okta_client._request("GET", f"/api/v1/users/{user['id']}/roles")
                roles = resp.json()
                if not isinstance(roles, list):
                    roles = []
                return user, roles
            except Exception:
                logger.warning(
                    "admin_security.role_lookup_failed",
                    user_id=user.get("id"),
                )
                return user, []

    results = await asyncio.gather(
        *[_get_roles(u) for u in users],
        return_exceptions=True,
    )

    for result in results:
        if isinstance(result, Exception):
            continue
        user, roles = result
        if not roles:
            continue

        role_types = [r.get("type", "") for r in roles]
        user_entry = {
            "id": user.get("id"),
            "login": user.get("profile", {}).get("login", ""),
            "email": user.get("profile", {}).get("email", ""),
            "firstName": user.get("profile", {}).get("firstName", ""),
            "lastName": user.get("profile", {}).get("lastName", ""),
            "status": user.get("status"),
            "lastLogin": user.get("lastLogin"),
            "roles": role_types,
        }
        all_admins.append(user_entry)
        if SUPER_ADMIN_ROLE in role_types:
            super_admins.append(user_entry)

    return all_admins, super_admins


def _check_super_admin_count(
    super_admins: list[dict],
    scan_id: uuid.UUID,
    now: datetime,
) -> PostureFinding | None:
    """Flag if more than SUPER_ADMIN_THRESHOLD super admins exist."""
    if len(super_admins) <= SUPER_ADMIN_THRESHOLD:
        return None

    affected = [
        {"id": u["id"], "login": u["login"], "name": f"{u['firstName']} {u['lastName']}"}
        for u in super_admins
    ]

    risk = calculate_risk_score(
        RiskInput(
            severity="HIGH",
            affects_admin_users=True,
            affected_user_count=len(super_admins),
        )
    )

    return PostureFinding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        check_category=CheckCategory.ADMIN_SECURITY,
        check_name="super_admin_count_exceeded",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title=f"Excessive super admin accounts ({len(super_admins)} found, threshold is {SUPER_ADMIN_THRESHOLD})",
        description=(
            f"There are {len(super_admins)} users with the Super Admin role. "
            f"The recommended maximum is {SUPER_ADMIN_THRESHOLD}. "
            "Excessive super admin accounts increase the blast radius of credential compromise."
        ),
        affected_resources=affected,
        remediation_steps=(
            "1. Navigate to Okta Admin Console > Security > Administrators.\n"
            "2. Review the list of Super Admin role assignments.\n"
            "3. Downgrade unnecessary Super Admins to more restrictive roles "
            "(e.g., Organization Admin, Application Admin, Help Desk Admin).\n"
            "4. Ensure remaining Super Admins have phishing-resistant MFA enrolled."
        ),
        risk_score=risk,
        first_detected=now,
        last_detected=now,
    )


async def _check_super_admin_mfa(
    okta_client: Any,
    super_admins: list[dict],
    scan_id: uuid.UUID,
    now: datetime,
) -> PostureFinding | None:
    """Flag super admins who lack phishing-resistant MFA (FIDO2/FastPass)."""
    if not super_admins:
        return None

    sem = asyncio.Semaphore(5)
    vulnerable_admins: list[dict] = []

    async def _check_one(user: dict) -> dict | None:
        async with sem:
            try:
                factors = await okta_client.get_user_factors(user["id"])
                factor_types = {f.get("factorType", "") for f in factors}
                has_phishing_resistant = bool(factor_types & PHISHING_RESISTANT_FACTORS)
                if not has_phishing_resistant:
                    return {
                        "id": user["id"],
                        "login": user["login"],
                        "name": f"{user['firstName']} {user['lastName']}",
                        "enrolled_factors": sorted(factor_types - {""}),
                    }
            except Exception:
                logger.warning(
                    "admin_security.factor_lookup_failed",
                    user_id=user["id"],
                )
            return None

    results = await asyncio.gather(*[_check_one(u) for u in super_admins])
    vulnerable_admins = [r for r in results if r is not None]

    if not vulnerable_admins:
        return None

    risk = calculate_risk_score(
        RiskInput(
            severity="CRITICAL",
            affects_admin_users=True,
            affected_user_count=len(vulnerable_admins),
            phishing_resistant=False,
        )
    )

    return PostureFinding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        check_category=CheckCategory.ADMIN_SECURITY,
        check_name="super_admin_no_phishing_resistant_mfa",
        severity=FindingSeverity.CRITICAL,
        status=FindingStatus.OPEN,
        title=f"{len(vulnerable_admins)} Super Admin(s) without phishing-resistant MFA",
        description=(
            f"{len(vulnerable_admins)} out of {len(super_admins)} Super Admin users "
            "do not have a phishing-resistant MFA factor (FIDO2 WebAuthn or Okta FastPass) "
            "enrolled. Super Admin accounts are high-value targets and must be protected "
            "with phishing-resistant authentication."
        ),
        affected_resources=vulnerable_admins,
        remediation_steps=(
            "1. Navigate to Okta Admin Console > Security > Authenticators.\n"
            "2. Ensure FIDO2 (WebAuthn) or Okta Verify (FastPass) authenticators are enabled.\n"
            "3. For each affected Super Admin, require enrollment of a phishing-resistant "
            "factor via an authentication policy.\n"
            "4. Consider creating a dedicated admin authentication policy that mandates "
            "phishing-resistant MFA for all admin console access."
        ),
        risk_score=risk,
        first_detected=now,
        last_detected=now,
    )


def _check_inactive_admins(
    admin_users: list[dict],
    scan_id: uuid.UUID,
    now: datetime,
) -> PostureFinding | None:
    """Flag admin accounts with no login in the past INACTIVE_ADMIN_DAYS days."""
    cutoff = now - timedelta(days=INACTIVE_ADMIN_DAYS)
    inactive: list[dict] = []

    for user in admin_users:
        last_login = user.get("lastLogin")
        if last_login is None:
            # Never logged in
            inactive.append({
                "id": user["id"],
                "login": user["login"],
                "name": f"{user['firstName']} {user['lastName']}",
                "lastLogin": None,
                "days_inactive": "never",
                "roles": user.get("roles", []),
            })
        else:
            try:
                if isinstance(last_login, str):
                    login_dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                else:
                    login_dt = last_login

                if login_dt < cutoff:
                    days = (now - login_dt).days
                    inactive.append({
                        "id": user["id"],
                        "login": user["login"],
                        "name": f"{user['firstName']} {user['lastName']}",
                        "lastLogin": last_login,
                        "days_inactive": days,
                        "roles": user.get("roles", []),
                    })
            except (ValueError, TypeError):
                logger.warning(
                    "admin_security.invalid_last_login",
                    user_id=user["id"],
                    last_login=last_login,
                )

    if not inactive:
        return None

    risk = calculate_risk_score(
        RiskInput(
            severity="HIGH",
            affects_admin_users=True,
            affected_user_count=len(inactive),
        )
    )

    return PostureFinding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        check_category=CheckCategory.ADMIN_SECURITY,
        check_name="inactive_admin_accounts",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title=f"{len(inactive)} admin account(s) inactive for {INACTIVE_ADMIN_DAYS}+ days",
        description=(
            f"{len(inactive)} administrator accounts have not logged in within the past "
            f"{INACTIVE_ADMIN_DAYS} days (or have never logged in). Inactive admin accounts "
            "are a security risk as they may be targets for credential stuffing or account "
            "takeover attacks."
        ),
        affected_resources=inactive,
        remediation_steps=(
            "1. Navigate to Okta Admin Console > Security > Administrators.\n"
            "2. Review the inactive admin accounts listed in this finding.\n"
            "3. For accounts that are no longer needed, remove the admin role assignment.\n"
            "4. For accounts that are still needed, verify the user is aware of their "
            "admin privileges and encourage them to log in.\n"
            "5. Consider implementing a policy to automatically deactivate admin accounts "
            "after a period of inactivity."
        ),
        risk_score=risk,
        first_detected=now,
        last_detected=now,
    )


async def _check_shadow_admins(
    okta_client: Any,
    scan_id: uuid.UUID,
    now: datetime,
) -> list[PostureFinding]:
    """Detect groups that have admin roles assigned (shadow admin groups).

    Users in these groups inherit admin-equivalent access without direct role
    assignment, making them harder to audit.
    """
    findings: list[PostureFinding] = []

    try:
        # List all groups
        groups = await okta_client._get_paginated("/api/v1/groups", params={"limit": "200"})
    except Exception:
        logger.exception("admin_security.list_groups_failed")
        return findings

    sem = asyncio.Semaphore(5)
    shadow_groups: list[dict] = []

    async def _check_group(group: dict) -> dict | None:
        group_id = group.get("id", "")
        async with sem:
            try:
                roles = await okta_client.get_group_roles(group_id)
                if isinstance(roles, list) and roles:
                    role_types = [r.get("type", "") for r in roles]
                    return {
                        "group_id": group_id,
                        "group_name": group.get("profile", {}).get("name", ""),
                        "group_description": group.get("profile", {}).get("description", ""),
                        "assigned_roles": role_types,
                    }
            except Exception:
                logger.warning(
                    "admin_security.group_role_lookup_failed",
                    group_id=group_id,
                )
            return None

    results = await asyncio.gather(*[_check_group(g) for g in groups])
    shadow_groups = [r for r in results if r is not None]

    if not shadow_groups:
        return findings

    risk = calculate_risk_score(
        RiskInput(
            severity="HIGH",
            affects_admin_users=True,
            affected_user_count=len(shadow_groups),
        )
    )

    finding = PostureFinding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        check_category=CheckCategory.ADMIN_SECURITY,
        check_name="shadow_admin_groups",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title=f"{len(shadow_groups)} group(s) with admin role assignments detected",
        description=(
            f"{len(shadow_groups)} Okta group(s) have admin roles assigned directly to the "
            "group. All members of these groups inherit admin-equivalent access, creating "
            "'shadow admins' that are difficult to audit and may grant unintended privileges "
            "when users are added to these groups."
        ),
        affected_resources=shadow_groups,
        remediation_steps=(
            "1. Navigate to Okta Admin Console > Security > Administrators.\n"
            "2. Review the groups listed in this finding that have admin roles assigned.\n"
            "3. Consider assigning admin roles directly to individual users instead of groups "
            "for better auditability.\n"
            "4. If group-based admin assignment is required, ensure group membership is "
            "tightly controlled with approval workflows.\n"
            "5. Regularly audit group membership to ensure no unauthorized users have "
            "inherited admin access."
        ),
        risk_score=risk,
        first_detected=now,
        last_detected=now,
    )
    findings.append(finding)

    return findings
