"""Edge case tests for src/core/security_events.py."""

from __future__ import annotations

from src.core.security_events import SECURITY_EVENTS, detect_security_events


class TestDetectSecurityEventsEmpty:
    def test_empty_logs_returns_empty_list(self):
        assert detect_security_events([]) == []

    def test_single_empty_dict_skipped(self):
        """A log entry with no eventType should be silently skipped."""
        assert detect_security_events([{}]) == []


class TestDetectSecurityEventsCritical:
    def test_mfa_factor_reset_all(self):
        log = {
            "eventType": "user.mfa.factor.reset_all",
            "published": "2026-01-15T10:00:00Z",
            "actor": {
                "id": "admin1",
                "type": "User",
                "alternateId": "admin@example.com",
                "displayName": "Admin User",
            },
        }
        findings = detect_security_events([log])
        assert len(findings) == 1
        assert findings[0]["event_type"] == "user.mfa.factor.reset_all"
        assert findings[0]["severity"] == "CRITICAL"

    def test_security_threat_detected_not_in_dict(self):
        """security.threat.detected is NOT in SECURITY_EVENTS and must be ignored."""
        log = {
            "eventType": "security.threat.detected",
            "published": "2026-01-15T10:00:00Z",
        }
        assert detect_security_events([log]) == []

    def test_system_idp_lifecycle_create_not_in_dict(self):
        """system.idp.lifecycle.create is not in SECURITY_EVENTS — should be ignored."""
        log = {
            "eventType": "system.idp.lifecycle.create",
            "published": "2026-01-15T10:00:00Z",
        }
        assert detect_security_events([log]) == []


class TestUnknownEventsIgnored:
    def test_unknown_event_type_ignored(self):
        log = {
            "eventType": "some.unknown.event.type",
            "published": "2026-01-15T10:00:00Z",
        }
        assert detect_security_events([log]) == []

    def test_none_event_type_ignored(self):
        log = {"eventType": None, "published": "2026-01-15T10:00:00Z"}
        assert detect_security_events([log]) == []


class TestMultipleEvents:
    def test_multiple_events_all_detected(self):
        logs = [
            {"eventType": "user.account.lock", "published": "2026-01-15T10:00:00Z"},
            {"eventType": "user.account.lock.limit", "published": "2026-01-15T10:01:00Z"},
            {"eventType": "system.api_token.create", "published": "2026-01-15T10:02:00Z"},
        ]
        findings = detect_security_events(logs)
        assert len(findings) == 3
        event_types = {f["event_type"] for f in findings}
        assert event_types == {"user.account.lock", "user.account.lock.limit", "system.api_token.create"}

    def test_mix_of_known_and_unknown_events(self):
        logs = [
            {"eventType": "user.session.start", "published": "2026-01-15T10:00:00Z"},
            {"eventType": "totally.fake.event", "published": "2026-01-15T10:01:00Z"},
            {"eventType": "policy.lifecycle.delete", "published": "2026-01-15T10:02:00Z"},
        ]
        findings = detect_security_events(logs)
        assert len(findings) == 2


class TestMalformedLogEntries:
    def test_missing_event_type_key(self):
        """Log entry without eventType key at all should be skipped."""
        log = {"published": "2026-01-15T10:00:00Z", "actor": {"id": "123"}}
        assert detect_security_events([log]) == []

    def test_missing_published(self):
        """Log entry with valid eventType but no published still produces a finding."""
        log = {"eventType": "user.session.start"}
        findings = detect_security_events([log])
        assert len(findings) == 1
        assert findings[0]["published"] is None

    def test_missing_actor(self):
        """Log entry with no actor field should use empty defaults."""
        log = {"eventType": "user.session.start", "published": "2026-01-15T10:00:00Z"}
        findings = detect_security_events([log])
        assert len(findings) == 1
        assert findings[0]["actor"]["id"] is None
        assert findings[0]["actor"]["type"] is None
        assert findings[0]["actor"]["alternateId"] is None
        assert findings[0]["actor"]["displayName"] is None

    def test_target_not_a_list(self):
        """If target is not a list, it should be treated as empty."""
        log = {
            "eventType": "user.session.start",
            "published": "2026-01-15T10:00:00Z",
            "target": "not_a_list",
        }
        findings = detect_security_events([log])
        assert len(findings) == 1
        assert findings[0]["details"]["target"] == []

    def test_empty_log_dict_in_batch(self):
        """An empty dict mixed with valid entries should not crash."""
        logs = [
            {},
            {"eventType": "user.session.start", "published": "2026-01-15T10:00:00Z"},
            {},
        ]
        findings = detect_security_events(logs)
        assert len(findings) == 1


class TestActorExtraction:
    def test_actor_fields_extracted(self):
        log = {
            "eventType": "user.account.privilege.grant",
            "published": "2026-01-15T10:00:00Z",
            "actor": {
                "id": "actor123",
                "type": "User",
                "alternateId": "admin@corp.com",
                "displayName": "Super Admin",
            },
        }
        findings = detect_security_events([log])
        actor = findings[0]["actor"]
        assert actor["id"] == "actor123"
        assert actor["type"] == "User"
        assert actor["alternateId"] == "admin@corp.com"
        assert actor["displayName"] == "Super Admin"

    def test_partial_actor(self):
        """Actor dict with only some fields should still work."""
        log = {
            "eventType": "user.session.start",
            "published": "2026-01-15T10:00:00Z",
            "actor": {"id": "partial_actor"},
        }
        findings = detect_security_events([log])
        actor = findings[0]["actor"]
        assert actor["id"] == "partial_actor"
        assert actor["type"] is None


class TestSeverityMapping:
    def test_low_severity(self):
        log = {"eventType": "user.session.start"}
        findings = detect_security_events([log])
        assert findings[0]["severity"] == "LOW"

    def test_medium_severity(self):
        log = {"eventType": "user.credential.forgot_password"}
        findings = detect_security_events([log])
        assert findings[0]["severity"] == "MEDIUM"

    def test_high_severity(self):
        log = {"eventType": "user.account.lock"}
        findings = detect_security_events([log])
        assert findings[0]["severity"] == "HIGH"

    def test_critical_severity(self):
        log = {"eventType": "user.account.lock.limit"}
        findings = detect_security_events([log])
        assert findings[0]["severity"] == "CRITICAL"

    def test_all_events_have_valid_severity(self):
        """Every entry in SECURITY_EVENTS must map to a valid severity level."""
        valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for event_type, severity in SECURITY_EVENTS.items():
            assert severity in valid_severities, f"{event_type} has invalid severity {severity}"


class TestDetailsExtraction:
    def test_outcome_extracted(self):
        log = {
            "eventType": "user.session.start",
            "published": "2026-01-15T10:00:00Z",
            "outcome": {"result": "SUCCESS", "reason": "User logged in"},
        }
        findings = detect_security_events([log])
        outcome = findings[0]["details"]["outcome"]
        assert outcome["result"] == "SUCCESS"
        assert outcome["reason"] == "User logged in"

    def test_display_message_extracted(self):
        log = {
            "eventType": "user.session.start",
            "published": "2026-01-15T10:00:00Z",
            "displayMessage": "User login to Okta",
        }
        findings = detect_security_events([log])
        assert findings[0]["details"]["displayMessage"] == "User login to Okta"

    def test_target_list_extracted(self):
        log = {
            "eventType": "user.session.start",
            "published": "2026-01-15T10:00:00Z",
            "target": [
                {
                    "id": "target1",
                    "type": "AppInstance",
                    "alternateId": "app@example.com",
                    "displayName": "MyApp",
                }
            ],
        }
        findings = detect_security_events([log])
        targets = findings[0]["details"]["target"]
        assert len(targets) == 1
        assert targets[0]["id"] == "target1"
        assert targets[0]["displayName"] == "MyApp"
