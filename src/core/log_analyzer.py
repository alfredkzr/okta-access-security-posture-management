"""Okta system log analysis for login pattern detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class LoginPattern:
    """Aggregated login pattern extracted from Okta system logs."""

    last_login: datetime | None = None
    unique_ips: set[str] = field(default_factory=set)
    unique_cities: set[str] = field(default_factory=set)
    unique_states: set[str] = field(default_factory=set)
    unique_isps: set[str] = field(default_factory=set)
    auth_methods: set[str] = field(default_factory=set)
    login_count: int = 0


def _safe_get(d: dict, *keys: str) -> str | None:
    """Safely traverse nested dict keys, returning None if any key is missing."""
    current = d
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    if current is None:
        return None
    return str(current) if not isinstance(current, str) else current


def _parse_timestamp(ts: str) -> datetime | None:
    """Parse an ISO-8601 timestamp string into a timezone-aware datetime."""
    if not ts:
        return None
    try:
        # Handle Okta's ISO-8601 format (e.g. "2025-01-15T10:30:00.000Z")
        cleaned = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except (ValueError, TypeError):
        return None


def analyze_logs(logs: list[dict]) -> LoginPattern:
    """Parse Okta system log entries and extract a login pattern.

    Extracts from each log entry:
        - published: timestamp (for last_login and login_count)
        - client.ipAddress: IP address
        - client.geographicalContext.city / state / country: location info
        - securityContext.asOrg / isp: ISP info
        - authenticationContext.externalSessionId: auth method indicator

    Args:
        logs: List of Okta system log event dicts.

    Returns:
        A LoginPattern with aggregated data.
    """
    pattern = LoginPattern()

    for log in logs:
        # Parse published timestamp
        published_str = log.get("published")
        if published_str:
            ts = _parse_timestamp(published_str)
            if ts is not None:
                pattern.login_count += 1
                if pattern.last_login is None or ts > pattern.last_login:
                    pattern.last_login = ts

        # Extract IP address
        ip = _safe_get(log, "client", "ipAddress")
        if ip:
            pattern.unique_ips.add(ip)

        # Extract geographical context
        city = _safe_get(log, "client", "geographicalContext", "city")
        if city:
            pattern.unique_cities.add(city)

        state = _safe_get(log, "client", "geographicalContext", "state")
        if state:
            pattern.unique_states.add(state)

        # Extract ISP info
        isp = _safe_get(log, "securityContext", "isp")
        if isp:
            pattern.unique_isps.add(isp)

        as_org = _safe_get(log, "securityContext", "asOrg")
        if as_org:
            pattern.unique_isps.add(as_org)

        # Extract auth methods
        auth_method = _safe_get(log, "authenticationContext", "externalSessionId")
        if auth_method:
            pattern.auth_methods.add(auth_method)

    return pattern


def is_inactive(pattern: LoginPattern, threshold_days: int = 90) -> bool:
    """Determine if a user is inactive based on their login pattern.

    Args:
        pattern: The login pattern to evaluate.
        threshold_days: Number of days without login to be considered inactive.

    Returns:
        True if the user has no login or last login is older than threshold_days.
    """
    if pattern.last_login is None:
        return True

    now = datetime.now(timezone.utc)
    delta = now - pattern.last_login
    return delta.days >= threshold_days
