"""Okta system log security event detection.

Defines known security-relevant Okta event types and provides detection
logic to scan log entries for matching events.
"""

from __future__ import annotations


# Mapping of Okta event type strings to severity levels.
# These cover authentication, authorization, and administrative security events.
SECURITY_EVENTS: dict[str, str] = {
    # Authentication events
    "user.session.start": "LOW",
    "user.authentication.auth_via_mfa": "LOW",
    "user.authentication.sso": "LOW",
    "user.authentication.auth_via_IDP": "LOW",
    "user.authentication.auth_via_social": "MEDIUM",
    "user.authentication.auth_via_radius": "MEDIUM",

    # Authentication failures
    "user.session.end": "LOW",
    "user.authentication.authenticate": "LOW",
    "user.account.lock": "HIGH",
    "user.account.lock.limit": "CRITICAL",
    "user.authentication.auth_fail": "MEDIUM",
    "user.authentication.auth_fail.mfa": "HIGH",

    # Credential events
    "user.credential.forgot_password": "MEDIUM",
    "user.credential.reset_password": "MEDIUM",
    "user.credential.change_password": "MEDIUM",
    "user.credential.enroll": "MEDIUM",
    "user.credential.unenroll": "HIGH",
    "user.credential.update": "MEDIUM",
    "user.credential.revoke": "HIGH",

    # MFA lifecycle
    "user.mfa.factor.activate": "MEDIUM",
    "user.mfa.factor.deactivate": "HIGH",
    "user.mfa.factor.reset_all": "CRITICAL",
    "user.mfa.factor.update": "MEDIUM",
    "user.mfa.attempt_bypass": "CRITICAL",

    # Account lifecycle
    "user.lifecycle.create": "MEDIUM",
    "user.lifecycle.activate": "LOW",
    "user.lifecycle.deactivate": "MEDIUM",
    "user.lifecycle.suspend": "MEDIUM",
    "user.lifecycle.unsuspend": "MEDIUM",
    "user.lifecycle.delete.initiated": "HIGH",
    "user.lifecycle.delete.completed": "HIGH",

    # Admin events
    "user.account.privilege.grant": "CRITICAL",
    "user.account.privilege.revoke": "HIGH",
    "group.privilege.grant": "CRITICAL",

    # Policy events
    "policy.lifecycle.create": "MEDIUM",
    "policy.lifecycle.update": "HIGH",
    "policy.lifecycle.delete": "HIGH",
    "policy.lifecycle.activate": "MEDIUM",
    "policy.lifecycle.deactivate": "HIGH",
    "policy.rule.create": "MEDIUM",
    "policy.rule.update": "HIGH",
    "policy.rule.delete": "HIGH",
    "policy.rule.activate": "MEDIUM",
    "policy.rule.deactivate": "HIGH",

    # Application events
    "application.lifecycle.create": "MEDIUM",
    "application.lifecycle.update": "MEDIUM",
    "application.lifecycle.delete": "HIGH",
    "application.lifecycle.activate": "LOW",
    "application.lifecycle.deactivate": "MEDIUM",
    "application.user_membership.add": "MEDIUM",
    "application.user_membership.remove": "MEDIUM",
    "application.user_membership.change_username": "MEDIUM",

    # Group events
    "group.user_membership.add": "LOW",
    "group.user_membership.remove": "MEDIUM",

    # System events
    "system.api_token.create": "HIGH",
    "system.api_token.revoke": "HIGH",
    "system.org.rate_limit.violation": "HIGH",
    "system.org.rate_limit.warning": "MEDIUM",

    # Zone / network events
    "zone.lifecycle.create": "MEDIUM",
    "zone.lifecycle.update": "HIGH",
    "zone.lifecycle.delete": "HIGH",
}


def detect_security_events(logs: list[dict]) -> list[dict]:
    """Scan Okta system log entries for known security events.

    Args:
        logs: List of Okta system log event dicts. Each should have at minimum
              an ``eventType`` field.

    Returns:
        A list of finding dicts, each containing:
            - event_type: The Okta event type string
            - severity: The mapped severity level
            - published: The event timestamp (from the log entry)
            - actor: The actor information (from the log entry)
            - details: A summary dict with target and outcome info
    """
    findings: list[dict] = []

    for log in logs:
        event_type = log.get("eventType")
        if event_type is None:
            continue

        severity = SECURITY_EVENTS.get(event_type)
        if severity is None:
            continue

        actor = log.get("actor", {})
        target = log.get("target", [])
        outcome = log.get("outcome", {})

        finding = {
            "event_type": event_type,
            "severity": severity,
            "published": log.get("published"),
            "actor": {
                "id": actor.get("id"),
                "type": actor.get("type"),
                "alternateId": actor.get("alternateId"),
                "displayName": actor.get("displayName"),
            },
            "details": {
                "target": [
                    {
                        "id": t.get("id"),
                        "type": t.get("type"),
                        "alternateId": t.get("alternateId"),
                        "displayName": t.get("displayName"),
                    }
                    for t in (target if isinstance(target, list) else [])
                ],
                "outcome": {
                    "result": outcome.get("result"),
                    "reason": outcome.get("reason"),
                },
                "displayMessage": log.get("displayMessage"),
            },
        }

        findings.append(finding)

    return findings
