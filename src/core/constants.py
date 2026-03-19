"""Shared constants for core modules."""

from src.models.posture_finding import FindingSeverity

# Factor types considered phishing-resistant (FIDO2 / Okta FastPass)
PHISHING_RESISTANT_FACTORS = {"webauthn", "signed_nonce"}

# Factor types considered weak (easily phished or intercepted)
WEAK_FACTOR_TYPES = {"sms", "call", "question"}

# Factor types considered strong (not phishing-resistant but better than weak)
STRONG_FACTOR_TYPES = {"token:software:totp", "push", "token:hotp", "token", "totp"}

# Severity weights for posture score calculation
SEVERITY_WEIGHTS: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 15,
    FindingSeverity.HIGH: 10,
    FindingSeverity.MEDIUM: 5,
    FindingSeverity.LOW: 2,
}


def requires_mfa(factor_mode: str | None) -> bool:
    """Check if a factor_mode value indicates MFA is required.

    Returns False for None, empty string, or "1FA" (single-factor).
    """
    return factor_mode is not None and factor_mode != "" and factor_mode != "1FA"


def extract_user_email(user: dict) -> str:
    """Extract email from an Okta user dict."""
    profile = user.get("profile", {})
    return profile.get("email", profile.get("login", ""))


def extract_user_name(user: dict) -> str:
    """Extract full name from an Okta user dict."""
    profile = user.get("profile", {})
    return f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip()


def extract_app_name(app: dict) -> str:
    """Extract display name from an Okta app dict."""
    return app.get("label", app.get("name", ""))
