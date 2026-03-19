"""MFA posture checks.

Evaluates MFA enrollment across the user population: users with no MFA,
users with only weak factors, and overall phishing-resistant MFA coverage.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from src.core.constants import PHISHING_RESISTANT_FACTORS, STRONG_FACTOR_TYPES, WEAK_FACTOR_TYPES
from src.core.risk_scorer import RiskInput, calculate_risk_score
from src.models.posture_finding import (
    CheckCategory,
    FindingSeverity,
    FindingStatus,
    PostureFinding,
)

logger = structlog.get_logger(__name__)

# Minimum phishing-resistant coverage percentage before flagging
PHISHING_RESISTANT_COVERAGE_THRESHOLD = 50


async def check_mfa_posture(
    okta_client: Any,
    db_session: Any,
    scan_id: uuid.UUID,
    users: list[dict[str, Any]],
) -> list[PostureFinding]:
    """Run MFA posture checks across the provided user list.

    Checks performed:
      1. Users with no MFA enrolled (or only security question)
      2. Users with only weak MFA factors (SMS/voice/question)
      3. Phishing-resistant MFA coverage below threshold

    Args:
        okta_client: An initialised OktaClient instance.
        db_session: SQLAlchemy async session (findings are added but not committed).
        scan_id: UUID of the current posture scan.
        users: List of Okta user dicts (from list_users).

    Returns:
        List of PostureFinding ORM objects.
    """
    findings: list[PostureFinding] = []
    now = datetime.now(timezone.utc)

    if not users:
        logger.info("mfa_posture.no_users_to_check", scan_id=str(scan_id))
        return findings

    # Fetch factors for all users with concurrency control
    user_factors = await _fetch_all_user_factors(okta_client, users)

    # Classify users
    no_mfa_users: list[dict] = []
    weak_only_users: list[dict] = []
    phishing_resistant_count = 0

    for user, factors in user_factors:
        factor_types = {f.get("factorType", "") for f in factors}
        factor_types.discard("")

        has_any_real_factor = bool(factor_types - {"question"})
        has_phishing_resistant = bool(factor_types & PHISHING_RESISTANT_FACTORS)
        has_strong = bool(factor_types & STRONG_FACTOR_TYPES) or has_phishing_resistant
        has_only_weak = bool(factor_types) and not has_strong

        user_info = {
            "id": user.get("id"),
            "login": user.get("profile", {}).get("login", ""),
            "name": (
                f"{user.get('profile', {}).get('firstName', '')} "
                f"{user.get('profile', {}).get('lastName', '')}"
            ).strip(),
            "enrolled_factors": sorted(factor_types),
        }

        if not has_any_real_factor:
            no_mfa_users.append(user_info)
        elif has_only_weak:
            weak_only_users.append(user_info)

        if has_phishing_resistant:
            phishing_resistant_count += 1

    # ---- Check 1: Users with no MFA enrolled ----
    try:
        finding = _check_no_mfa(no_mfa_users, len(users), scan_id, now)
        if finding:
            findings.append(finding)
    except Exception:
        logger.exception("mfa_posture.no_mfa_check_failed")

    # ---- Check 2: Users with only weak MFA ----
    try:
        finding = _check_weak_mfa_only(weak_only_users, len(users), scan_id, now)
        if finding:
            findings.append(finding)
    except Exception:
        logger.exception("mfa_posture.weak_mfa_check_failed")

    # ---- Check 3: Phishing-resistant coverage ----
    try:
        finding = _check_phishing_resistant_coverage(
            phishing_resistant_count, len(users), scan_id, now
        )
        if finding:
            findings.append(finding)
    except Exception:
        logger.exception("mfa_posture.phishing_resistant_coverage_check_failed")

    for f in findings:
        db_session.add(f)

    logger.info(
        "mfa_posture.checks_complete",
        scan_id=str(scan_id),
        findings_count=len(findings),
        total_users=len(users),
        no_mfa_count=len(no_mfa_users),
        weak_only_count=len(weak_only_users),
        phishing_resistant_count=phishing_resistant_count,
    )
    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _fetch_all_user_factors(
    okta_client: Any,
    users: list[dict[str, Any]],
) -> list[tuple[dict, list[dict]]]:
    """Fetch MFA factors for all users with a concurrency semaphore."""
    sem = asyncio.Semaphore(5)
    results: list[tuple[dict, list[dict]]] = []

    async def _fetch_one(user: dict) -> tuple[dict, list[dict]]:
        async with sem:
            try:
                factors = await okta_client.get_user_factors(user["id"])
                return user, factors if isinstance(factors, list) else []
            except Exception:
                logger.warning(
                    "mfa_posture.factor_lookup_failed",
                    user_id=user.get("id"),
                )
                return user, []

    gathered = await asyncio.gather(*[_fetch_one(u) for u in users])
    results = [r for r in gathered if not isinstance(r, Exception)]
    return results


def _check_no_mfa(
    no_mfa_users: list[dict],
    total_users: int,
    scan_id: uuid.UUID,
    now: datetime,
) -> PostureFinding | None:
    """Create finding for users with no MFA enrolled."""
    if not no_mfa_users:
        return None

    risk = calculate_risk_score(
        RiskInput(
            severity="CRITICAL",
            affected_user_count=len(no_mfa_users),
            requires_mfa=False,
        )
    )

    pct = round(len(no_mfa_users) / total_users * 100, 1) if total_users else 0

    return PostureFinding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        check_category=CheckCategory.MFA_POSTURE,
        check_name="users_no_mfa_enrolled",
        severity=FindingSeverity.CRITICAL,
        status=FindingStatus.OPEN,
        title=f"{len(no_mfa_users)} user(s) have no MFA enrolled ({pct}% of users)",
        description=(
            f"{len(no_mfa_users)} out of {total_users} users ({pct}%) have no MFA factors "
            "enrolled (or only a security question, which does not qualify as MFA). "
            "These accounts are vulnerable to password-based attacks including phishing, "
            "credential stuffing, and brute force."
        ),
        affected_resources=no_mfa_users,
        remediation_steps=(
            "1. Navigate to Okta Admin Console > Security > Authenticators.\n"
            "2. Ensure at least one strong authenticator is enabled (e.g., Okta Verify, "
            "FIDO2 WebAuthn, Google Authenticator).\n"
            "3. Navigate to Security > Authentication Policies.\n"
            "4. Update the default sign-on policy to require MFA for all users.\n"
            "5. Consider setting an MFA enrollment deadline to enforce enrollment."
        ),
        risk_score=risk,
        first_detected=now,
        last_detected=now,
    )


def _check_weak_mfa_only(
    weak_only_users: list[dict],
    total_users: int,
    scan_id: uuid.UUID,
    now: datetime,
) -> PostureFinding | None:
    """Create finding for users with only weak MFA factors (SMS/voice/question)."""
    if not weak_only_users:
        return None

    risk = calculate_risk_score(
        RiskInput(
            severity="HIGH",
            affected_user_count=len(weak_only_users),
            requires_mfa=True,
            phishing_resistant=False,
        )
    )

    pct = round(len(weak_only_users) / total_users * 100, 1) if total_users else 0

    return PostureFinding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        check_category=CheckCategory.MFA_POSTURE,
        check_name="users_weak_mfa_only",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title=f"{len(weak_only_users)} user(s) have only weak MFA factors ({pct}% of users)",
        description=(
            f"{len(weak_only_users)} out of {total_users} users ({pct}%) have MFA enrolled "
            "but only weak factors (SMS, voice call, or security question). These factors "
            "are susceptible to SIM swapping, social engineering, and real-time phishing attacks."
        ),
        affected_resources=weak_only_users,
        remediation_steps=(
            "1. Navigate to Okta Admin Console > Security > Authenticators.\n"
            "2. Enable stronger authenticators such as Okta Verify (push/TOTP) or "
            "FIDO2 WebAuthn.\n"
            "3. Consider deprecating SMS and voice call authenticators.\n"
            "4. Update authentication policies to require stronger factor types.\n"
            "5. Communicate to affected users about enrolling a stronger MFA method."
        ),
        risk_score=risk,
        first_detected=now,
        last_detected=now,
    )


def _check_phishing_resistant_coverage(
    phishing_resistant_count: int,
    total_users: int,
    scan_id: uuid.UUID,
    now: datetime,
) -> PostureFinding | None:
    """Create finding if phishing-resistant MFA coverage is below threshold."""
    if total_users == 0:
        return None

    coverage_pct = round(phishing_resistant_count / total_users * 100, 1)
    if coverage_pct >= PHISHING_RESISTANT_COVERAGE_THRESHOLD:
        return None

    risk = calculate_risk_score(
        RiskInput(
            severity="HIGH",
            affected_user_count=total_users - phishing_resistant_count,
            phishing_resistant=False,
        )
    )

    return PostureFinding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        check_category=CheckCategory.MFA_POSTURE,
        check_name="low_phishing_resistant_mfa_coverage",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title=(
            f"Phishing-resistant MFA coverage is {coverage_pct}% "
            f"(below {PHISHING_RESISTANT_COVERAGE_THRESHOLD}% threshold)"
        ),
        description=(
            f"Only {phishing_resistant_count} out of {total_users} users ({coverage_pct}%) "
            "have a phishing-resistant MFA factor (FIDO2 WebAuthn or Okta FastPass/signed_nonce) "
            f"enrolled. The recommended minimum coverage is {PHISHING_RESISTANT_COVERAGE_THRESHOLD}%. "
            "Phishing-resistant factors are the strongest defense against credential theft and "
            "adversary-in-the-middle attacks."
        ),
        affected_resources=[{
            "metric": "phishing_resistant_coverage",
            "enrolled_count": phishing_resistant_count,
            "total_users": total_users,
            "coverage_percentage": coverage_pct,
        }],
        remediation_steps=(
            "1. Navigate to Okta Admin Console > Security > Authenticators.\n"
            "2. Enable FIDO2 (WebAuthn) and/or Okta Verify with FastPass.\n"
            "3. Create or update authentication policies to prefer or require "
            "phishing-resistant factors.\n"
            "4. Run a phishing-resistant MFA enrollment campaign for all users.\n"
            "5. Consider setting enrollment deadlines and providing FIDO2 security keys "
            "to users who need them."
        ),
        risk_score=risk,
        first_detected=now,
        last_detected=now,
    )
