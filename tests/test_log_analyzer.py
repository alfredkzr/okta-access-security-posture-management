"""Tests for src.core.log_analyzer module."""

from datetime import datetime, timedelta, timezone

import pytest

from src.core.log_analyzer import LoginPattern, analyze_logs, is_inactive


# ---------------------------------------------------------------------------
# Empty logs
# ---------------------------------------------------------------------------


class TestEmptyLogs:
    def test_empty_list_returns_empty_pattern(self):
        pattern = analyze_logs([])
        assert pattern.last_login is None
        assert pattern.unique_ips == set()
        assert pattern.unique_cities == set()
        assert pattern.unique_states == set()
        assert pattern.unique_isps == set()
        assert pattern.auth_methods == set()
        assert pattern.login_count == 0


# ---------------------------------------------------------------------------
# IP extraction
# ---------------------------------------------------------------------------


class TestIPExtraction:
    def test_unique_ips_extracted(self):
        logs = [
            {"published": "2025-06-01T10:00:00.000Z", "client": {"ipAddress": "1.2.3.4"}},
            {"published": "2025-06-02T10:00:00.000Z", "client": {"ipAddress": "5.6.7.8"}},
            {"published": "2025-06-03T10:00:00.000Z", "client": {"ipAddress": "1.2.3.4"}},
        ]
        pattern = analyze_logs(logs)
        assert pattern.unique_ips == {"1.2.3.4", "5.6.7.8"}

    def test_missing_ip_skipped(self):
        logs = [
            {"published": "2025-06-01T10:00:00.000Z", "client": {}},
            {"published": "2025-06-02T10:00:00.000Z"},
        ]
        pattern = analyze_logs(logs)
        assert pattern.unique_ips == set()


# ---------------------------------------------------------------------------
# City / State / ISP extraction
# ---------------------------------------------------------------------------


class TestGeoExtraction:
    def test_cities_extracted(self):
        logs = [
            {
                "published": "2025-06-01T10:00:00.000Z",
                "client": {
                    "ipAddress": "1.2.3.4",
                    "geographicalContext": {"city": "San Francisco", "state": "California"},
                },
            },
            {
                "published": "2025-06-02T10:00:00.000Z",
                "client": {
                    "ipAddress": "5.6.7.8",
                    "geographicalContext": {"city": "New York", "state": "New York"},
                },
            },
        ]
        pattern = analyze_logs(logs)
        assert pattern.unique_cities == {"San Francisco", "New York"}
        assert pattern.unique_states == {"California", "New York"}

    def test_isps_extracted(self):
        logs = [
            {
                "published": "2025-06-01T10:00:00.000Z",
                "securityContext": {"isp": "Comcast", "asOrg": "Comcast Cable"},
            },
            {
                "published": "2025-06-02T10:00:00.000Z",
                "securityContext": {"isp": "AT&T", "asOrg": "AT&T Services"},
            },
        ]
        pattern = analyze_logs(logs)
        assert "Comcast" in pattern.unique_isps
        assert "AT&T" in pattern.unique_isps
        assert "Comcast Cable" in pattern.unique_isps
        assert "AT&T Services" in pattern.unique_isps


# ---------------------------------------------------------------------------
# Last login detection
# ---------------------------------------------------------------------------


class TestLastLogin:
    def test_most_recent_timestamp_used(self):
        logs = [
            {"published": "2025-06-01T10:00:00.000Z"},
            {"published": "2025-06-15T14:30:00.000Z"},
            {"published": "2025-06-10T08:00:00.000Z"},
        ]
        pattern = analyze_logs(logs)
        assert pattern.last_login is not None
        assert pattern.last_login.year == 2025
        assert pattern.last_login.month == 6
        assert pattern.last_login.day == 15
        assert pattern.login_count == 3

    def test_single_log_sets_last_login(self):
        logs = [{"published": "2025-03-20T12:00:00.000Z"}]
        pattern = analyze_logs(logs)
        assert pattern.last_login is not None
        assert pattern.login_count == 1


# ---------------------------------------------------------------------------
# is_inactive
# ---------------------------------------------------------------------------


class TestIsInactive:
    def test_no_login_is_inactive(self):
        pattern = LoginPattern()
        assert is_inactive(pattern) is True

    def test_recent_login_is_not_inactive(self):
        pattern = LoginPattern(
            last_login=datetime.now(timezone.utc) - timedelta(days=10)
        )
        assert is_inactive(pattern) is False

    def test_old_login_is_inactive(self):
        pattern = LoginPattern(
            last_login=datetime.now(timezone.utc) - timedelta(days=91)
        )
        assert is_inactive(pattern) is True

    def test_exactly_at_threshold(self):
        pattern = LoginPattern(
            last_login=datetime.now(timezone.utc) - timedelta(days=90)
        )
        assert is_inactive(pattern) is True

    def test_custom_threshold(self):
        pattern = LoginPattern(
            last_login=datetime.now(timezone.utc) - timedelta(days=30)
        )
        assert is_inactive(pattern, threshold_days=30) is True
        assert is_inactive(pattern, threshold_days=31) is False

    def test_just_under_threshold_is_active(self):
        pattern = LoginPattern(
            last_login=datetime.now(timezone.utc) - timedelta(days=89)
        )
        assert is_inactive(pattern) is False
