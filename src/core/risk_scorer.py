"""Composite risk scoring for ASPM findings."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RiskInput:
    """Input parameters for the composite risk score calculation.

    Attributes:
        severity: Finding severity (CRITICAL, HIGH, MEDIUM, LOW).
        scenario_risk_level: Risk level from the simulation scenario (HIGH, MEDIUM, LOW) or None.
        app_criticality: User-assigned app criticality (critical, high, medium, low) or None.
        affects_admin_users: Whether the finding affects admin/privileged users.
        affects_service_accounts: Whether the finding affects service accounts.
        affected_user_count: Number of users affected by this finding.
        requires_mfa: Whether the matching rule requires MFA, or None if unknown.
        phishing_resistant: Whether the MFA is phishing-resistant, or None if unknown.
    """

    severity: str
    scenario_risk_level: str | None = None
    app_criticality: str | None = None
    affects_admin_users: bool = False
    affects_service_accounts: bool = False
    affected_user_count: int = 0
    requires_mfa: bool | None = None
    phishing_resistant: bool | None = None


def calculate_risk_score(finding: RiskInput) -> int:
    """Compute a composite risk score from 0 to 100.

    Weight breakdown (max contribution):
        - Severity:       0-30
        - Scenario risk:  0-15
        - App criticality: 0-15
        - User privilege:  0-15
        - Exposure:        0-15
        - Auth strength:   0-10

    Args:
        finding: A RiskInput with the relevant attributes.

    Returns:
        An integer score capped at 100.
    """
    score = 0

    # --- Severity weight (0-30) ---
    severity_map = {
        "CRITICAL": 30,
        "HIGH": 25,
        "MEDIUM": 15,
        "LOW": 5,
    }
    score += severity_map.get(finding.severity.upper(), 0)

    # --- Scenario risk level weight (0-15) ---
    scenario_map = {
        "CRITICAL": 15,
        "HIGH": 12,
        "MEDIUM": 8,
        "LOW": 4,
    }
    if finding.scenario_risk_level:
        score += scenario_map.get(finding.scenario_risk_level.upper(), 0)

    # --- App criticality weight (0-15) ---
    criticality_map = {
        "critical": 15,
        "high": 12,
        "medium": 8,
        "low": 4,
    }
    if finding.app_criticality:
        score += criticality_map.get(finding.app_criticality.lower(), 0)

    # --- User privilege weight (0-15) ---
    if finding.affects_admin_users:
        score += 10
    if finding.affects_service_accounts:
        score += 5

    # --- Exposure weight (0-15) ---
    if finding.affected_user_count >= 100:
        score += 15
    elif finding.affected_user_count >= 50:
        score += 12
    elif finding.affected_user_count >= 10:
        score += 8
    elif finding.affected_user_count >= 1:
        score += 4

    # --- Auth strength weight (0-10) ---
    if finding.requires_mfa is not None:
        if not finding.requires_mfa:
            # No MFA required at all — worst case
            score += 10
        elif finding.phishing_resistant is not None and not finding.phishing_resistant:
            # MFA required but not phishing-resistant
            score += 5
        # If MFA is required and phishing-resistant, no additional risk

    return min(score, 100)


def get_risk_band(score: int) -> str:
    """Map a numeric risk score to a risk band label.

    Bands:
        0-25  -> LOW
        26-50 -> MEDIUM
        51-75 -> HIGH
        76-100 -> CRITICAL

    Args:
        score: An integer risk score (0-100).

    Returns:
        The risk band string.
    """
    if score <= 25:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"
