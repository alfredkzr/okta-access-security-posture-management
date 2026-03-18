"""Tests for src.core.risk_scorer module."""

import pytest

from src.core.risk_scorer import RiskInput, calculate_risk_score, get_risk_band


# ---------------------------------------------------------------------------
# Severity base weight tests
# ---------------------------------------------------------------------------


class TestSeverityWeights:
    def test_critical_severity(self):
        inp = RiskInput(severity="CRITICAL")
        score = calculate_risk_score(inp)
        assert score == 30

    def test_high_severity(self):
        inp = RiskInput(severity="HIGH")
        score = calculate_risk_score(inp)
        assert score == 25

    def test_medium_severity(self):
        inp = RiskInput(severity="MEDIUM")
        score = calculate_risk_score(inp)
        assert score == 15

    def test_low_severity(self):
        inp = RiskInput(severity="LOW")
        score = calculate_risk_score(inp)
        assert score == 5

    def test_unknown_severity_gives_zero(self):
        inp = RiskInput(severity="UNKNOWN")
        score = calculate_risk_score(inp)
        assert score == 0


# ---------------------------------------------------------------------------
# Score capping
# ---------------------------------------------------------------------------


class TestScoreCapping:
    def test_score_capped_at_100(self):
        inp = RiskInput(
            severity="CRITICAL",                # 30
            scenario_risk_level="CRITICAL",      # 15
            app_criticality="critical",          # 15
            affects_admin_users=True,            # 10
            affects_service_accounts=True,       # 5
            affected_user_count=200,             # 15
            requires_mfa=False,                  # 10
        )
        score = calculate_risk_score(inp)
        assert score == 100


# ---------------------------------------------------------------------------
# Minimum / zero input
# ---------------------------------------------------------------------------


class TestMinimumInput:
    def test_all_defaults_minimum_score(self):
        """With severity UNKNOWN and all defaults, score should be 0."""
        inp = RiskInput(severity="UNKNOWN")
        assert calculate_risk_score(inp) == 0

    def test_low_severity_only(self):
        inp = RiskInput(severity="LOW")
        assert calculate_risk_score(inp) == 5


# ---------------------------------------------------------------------------
# Admin / service account flag
# ---------------------------------------------------------------------------


class TestPrivilegeFlags:
    def test_admin_users_adds_weight(self):
        base = RiskInput(severity="LOW")
        with_admin = RiskInput(severity="LOW", affects_admin_users=True)
        assert calculate_risk_score(with_admin) - calculate_risk_score(base) == 10

    def test_service_accounts_adds_weight(self):
        base = RiskInput(severity="LOW")
        with_svc = RiskInput(severity="LOW", affects_service_accounts=True)
        assert calculate_risk_score(with_svc) - calculate_risk_score(base) == 5

    def test_both_flags_combined(self):
        base = RiskInput(severity="LOW")
        both = RiskInput(
            severity="LOW",
            affects_admin_users=True,
            affects_service_accounts=True,
        )
        assert calculate_risk_score(both) - calculate_risk_score(base) == 15


# ---------------------------------------------------------------------------
# Risk band boundaries
# ---------------------------------------------------------------------------


class TestRiskBand:
    def test_score_0_is_low(self):
        assert get_risk_band(0) == "LOW"

    def test_score_25_is_low(self):
        assert get_risk_band(25) == "LOW"

    def test_score_26_is_medium(self):
        assert get_risk_band(26) == "MEDIUM"

    def test_score_50_is_medium(self):
        assert get_risk_band(50) == "MEDIUM"

    def test_score_51_is_high(self):
        assert get_risk_band(51) == "HIGH"

    def test_score_75_is_high(self):
        assert get_risk_band(75) == "HIGH"

    def test_score_76_is_critical(self):
        assert get_risk_band(76) == "CRITICAL"

    def test_score_100_is_critical(self):
        assert get_risk_band(100) == "CRITICAL"


# ---------------------------------------------------------------------------
# Auth strength weight
# ---------------------------------------------------------------------------


class TestAuthStrength:
    def test_no_mfa_adds_10(self):
        base = RiskInput(severity="LOW")
        no_mfa = RiskInput(severity="LOW", requires_mfa=False)
        assert calculate_risk_score(no_mfa) - calculate_risk_score(base) == 10

    def test_mfa_not_phishing_resistant_adds_5(self):
        base = RiskInput(severity="LOW")
        weak_mfa = RiskInput(severity="LOW", requires_mfa=True, phishing_resistant=False)
        assert calculate_risk_score(weak_mfa) - calculate_risk_score(base) == 5

    def test_mfa_phishing_resistant_adds_0(self):
        base = RiskInput(severity="LOW")
        strong_mfa = RiskInput(severity="LOW", requires_mfa=True, phishing_resistant=True)
        assert calculate_risk_score(strong_mfa) == calculate_risk_score(base)
