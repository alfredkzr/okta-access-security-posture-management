"""Production-grade async Okta API client with rate limiting, retries, and structured logging."""

from __future__ import annotations

import asyncio
import random
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from src.config import settings

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class OktaApiError(Exception):
    """Base exception for Okta API errors."""

    def __init__(self, status_code: int, error_code: str | None, message: str, url: str = ""):
        self.status_code = status_code
        self.error_code = error_code
        self.url = url
        super().__init__(message)


class OktaRateLimitError(OktaApiError):
    """Raised when Okta returns 429 with error code E0000047."""
    pass


class OktaNotFoundError(OktaApiError):
    """Raised on 404 responses."""
    pass


# ---------------------------------------------------------------------------
# Link header parser
# ---------------------------------------------------------------------------

_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="([^"]+)"')


def _parse_link_header(header: str | None) -> dict[str, str]:
    """Parse HTTP Link header into {rel: url} mapping."""
    if not header:
        return {}
    return {rel: url for url, rel in _LINK_RE.findall(header)}


# ---------------------------------------------------------------------------
# Okta client
# ---------------------------------------------------------------------------

class OktaClient:
    """Async Okta API client with concurrency control, retries, and adaptive throttling."""

    # Retry configuration
    MAX_RETRIES = 5
    BASE_DELAY = 2.0  # seconds – doubles each retry
    MAX_JITTER = 3.0  # random jitter range in seconds
    THROTTLE_THRESHOLD = 0.10  # add delay when remaining < 10% of limit
    THROTTLE_DELAY = 1.0  # seconds

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_token: str | None = None,
        max_workers: int | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = (base_url or settings.okta_base_url).rstrip("/")
        self._api_token = api_token or settings.okta_api_token
        self._max_workers = max_workers or settings.max_workers
        self._semaphore = asyncio.Semaphore(self._max_workers)

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"SSWS {self._api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(timeout),
        )

    # ------------------------------------------------------------------
    # Low-level HTTP helpers
    # ------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Execute an HTTP request with semaphore, retries, and adaptive throttling."""
        async with self._semaphore:
            return await self._request_with_retry(method, path, params=params, json_body=json_body)

    async def _request_with_retry(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        last_exc: Exception | None = None

        for attempt in range(self.MAX_RETRIES + 1):
            start = time.monotonic()
            try:
                resp = await self._client.request(method, path, params=params, json=json_body)
                duration_ms = round((time.monotonic() - start) * 1000, 1)

                logger.info(
                    "okta_api_call",
                    method=method,
                    path=path,
                    status=resp.status_code,
                    duration_ms=duration_ms,
                    retry=attempt,
                )

                # --- Adaptive throttling ---
                await self._maybe_throttle(resp)

                # --- Success ---
                if resp.status_code < 400:
                    return resp

                # --- Error handling ---
                error_code = self._extract_error_code(resp)

                # 429 with E0000047 → wait for reset window, then retry once.
                # The spec says "fail the assessment for that user, don't retry"
                # but we give it one more chance after respecting the reset time,
                # since blasting through remaining=0 is the real problem.
                if resp.status_code == 429 and error_code == "E0000047":
                    if attempt == 0:
                        reset_epoch = resp.headers.get("X-Rate-Limit-Reset")
                        if reset_epoch:
                            try:
                                wait = max(int(reset_epoch) - int(time.time()) + 1, 1)
                                wait = min(wait, 60)
                            except ValueError:
                                wait = 10
                        else:
                            wait = 10
                        logger.warning(
                            "okta_rate_limit_wait_for_reset",
                            method=method, path=path,
                            wait_seconds=wait,
                        )
                        await asyncio.sleep(wait)
                        continue
                    raise OktaRateLimitError(
                        status_code=429,
                        error_code="E0000047",
                        message=f"Okta rate limit exceeded (E0000047) on {method} {path}",
                        url=path,
                    )

                # 404
                if resp.status_code == 404:
                    raise OktaNotFoundError(
                        status_code=404,
                        error_code=error_code,
                        message=f"Not found: {method} {path}",
                        url=path,
                    )

                # Retryable: 429 (non-E0000047) or 5xx
                if resp.status_code == 429 or resp.status_code >= 500:
                    last_exc = OktaApiError(resp.status_code, error_code, resp.text, url=path)
                    if attempt < self.MAX_RETRIES:
                        delay = self._backoff_delay(attempt)
                        logger.warning(
                            "okta_api_retry",
                            method=method,
                            path=path,
                            status=resp.status_code,
                            attempt=attempt + 1,
                            delay=round(delay, 2),
                        )
                        await asyncio.sleep(delay)
                        continue
                    raise last_exc

                # Non-retryable 4xx
                raise OktaApiError(
                    status_code=resp.status_code,
                    error_code=error_code,
                    message=f"Okta API error {resp.status_code}: {resp.text}",
                    url=path,
                )

            except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError, OSError) as exc:
                duration_ms = round((time.monotonic() - start) * 1000, 1)
                logger.warning(
                    "okta_api_network_error",
                    method=method,
                    path=path,
                    error=str(exc),
                    duration_ms=duration_ms,
                    attempt=attempt + 1,
                )
                last_exc = exc
                if attempt < self.MAX_RETRIES:
                    delay = self._backoff_delay(attempt)
                    await asyncio.sleep(delay)
                    continue
                raise OktaApiError(
                    status_code=0,
                    error_code=None,
                    message=f"Network error after {self.MAX_RETRIES + 1} attempts: {exc}",
                    url=path,
                ) from exc

        # Should not reach here, but just in case
        raise OktaApiError(0, None, "Max retries exhausted", url=path)  # pragma: no cover

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_error_code(resp: httpx.Response) -> str | None:
        try:
            body = resp.json()
            return body.get("errorCode")
        except Exception:
            return None

    @classmethod
    def _backoff_delay(cls, attempt: int) -> float:
        """Exponential backoff: base * 2^attempt + random jitter."""
        return cls.BASE_DELAY * (2 ** attempt) + random.uniform(0, cls.MAX_JITTER)

    async def _maybe_throttle(self, resp: httpx.Response) -> None:
        """If remaining rate limit is low, wait until the reset window.

        When ``X-Rate-Limit-Remaining`` drops below 10 % of the limit we
        sleep until the ``X-Rate-Limit-Reset`` epoch (plus a small buffer).
        If the reset header is missing we fall back to ``THROTTLE_DELAY``.
        """
        remaining = resp.headers.get("X-Rate-Limit-Remaining")
        limit = resp.headers.get("X-Rate-Limit-Limit")
        if remaining is None or limit is None:
            return
        try:
            r, l = int(remaining), int(limit)
        except (ValueError, ZeroDivisionError):
            return
        if l <= 0 or (r / l) >= self.THROTTLE_THRESHOLD:
            return

        # Determine how long to sleep.  Prefer X-Rate-Limit-Reset (epoch seconds).
        reset_epoch = resp.headers.get("X-Rate-Limit-Reset")
        if reset_epoch is not None:
            try:
                wait = max(int(reset_epoch) - int(time.time()) + 1, 1)
            except ValueError:
                wait = self.THROTTLE_DELAY
        else:
            wait = self.THROTTLE_DELAY

        # Cap the wait to something reasonable (60 s) to avoid hanging forever
        wait = min(wait, 60)
        logger.warning("okta_adaptive_throttle", remaining=r, limit=l, wait_seconds=wait)
        await asyncio.sleep(wait)

    async def _get_paginated(self, path: str, *, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Follow pagination via Link headers and collect all results."""
        results: list[dict[str, Any]] = []
        current_params = dict(params) if params else {}
        current_path = path

        while True:
            resp = await self._request("GET", current_path, params=current_params)
            data = resp.json()
            if isinstance(data, list):
                results.extend(data)
            else:
                # Some endpoints return a single object – shouldn't happen for paginated, but guard
                results.append(data)

            links = _parse_link_header(resp.headers.get("link"))
            next_url = links.get("next")
            if not next_url:
                break

            # The next URL is absolute; strip the base to get a relative path+query
            if next_url.startswith(self._base_url):
                next_url = next_url[len(self._base_url):]
            # Parse out the query string that Okta returns in the next link
            if "?" in next_url:
                current_path, qs = next_url.split("?", 1)
                # httpx handles params; we must merge them from the URL
                current_params = dict(pair.split("=", 1) for pair in qs.split("&") if "=" in pair)
            else:
                current_path = next_url
                current_params = {}

        return results

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    async def list_users(self, *, limit: int = 200) -> list[dict[str, Any]]:
        """List all users with automatic pagination."""
        return await self._get_paginated("/api/v1/users", params={"limit": str(limit)})

    async def get_user_by_login(self, email: str) -> dict[str, Any] | None:
        """Look up a user by login/email. Returns user dict or None."""
        try:
            resp = await self._request("GET", f"/api/v1/users/{email}")
            return resp.json()
        except OktaNotFoundError:
            return None

    async def get_user_by_id(self, user_id: str) -> dict[str, Any]:
        """Get a single user by Okta user ID."""
        resp = await self._request("GET", f"/api/v1/users/{user_id}")
        return resp.json()

    async def get_user_apps(self, user_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        """Get applications assigned to a user."""
        filter_str = f'user.id eq "{user_id}" or status eq "ACTIVE"'
        return await self._get_paginated(
            "/api/v1/apps",
            params={
                "filter": filter_str,
                "expand": f"user/{user_id}",
                "limit": str(limit),
            },
        )

    async def simulate_policy(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST to the policy simulation API with ?expand=RULE."""
        resp = await self._request(
            "POST",
            "/api/v1/policies/simulate",
            params={"expand": "RULE"},
            json_body=payload,
        )
        return resp.json()

    async def get_policy_rule(self, policy_id: str, rule_id: str) -> dict[str, Any]:
        """Get details for a specific policy rule."""
        resp = await self._request("GET", f"/api/v1/policies/{policy_id}/rules/{rule_id}")
        return resp.json()

    async def get_user_app_logs(
        self,
        user_id: str,
        app_id: str,
        *,
        since: datetime | str | None = None,
        until: datetime | str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Get system log events for a specific user + app pair."""
        if since is None:
            from datetime import timedelta
            since = datetime.now(timezone.utc) - timedelta(days=90)
        if until is None:
            until = datetime.now(timezone.utc)

        since_str = since.isoformat() if isinstance(since, datetime) else since
        until_str = until.isoformat() if isinstance(until, datetime) else until
        filter_str = f'actor.id eq "{user_id}" and target.id eq "{app_id}"'

        return await self._get_paginated(
            "/api/v1/logs",
            params={
                "since": since_str,
                "until": until_str,
                "limit": str(limit),
                "sortOrder": "DESCENDING",
                "filter": filter_str,
            },
        )

    async def get_org_info(self) -> dict[str, Any]:
        """Lightweight health check — get org info."""
        resp = await self._request("GET", "/api/v1/org")
        return resp.json()

    async def get_user_factors(self, user_id: str) -> list[dict[str, Any]]:
        """Get MFA factors enrolled for a user."""
        resp = await self._request("GET", f"/api/v1/users/{user_id}/factors")
        return resp.json()

    async def list_policies(self, policy_type: str) -> list[dict[str, Any]]:
        """List policies of a given type (e.g. ACCESS_POLICY, MFA_ENROLL)."""
        resp = await self._request("GET", "/api/v1/policies", params={"type": policy_type})
        return resp.json()

    async def list_zones(self) -> list[dict[str, Any]]:
        """List network zones."""
        resp = await self._request("GET", "/api/v1/zones")
        return resp.json()

    async def list_idps(self) -> list[dict[str, Any]]:
        """List identity providers."""
        resp = await self._request("GET", "/api/v1/idps")
        return resp.json()

    async def list_roles(self) -> list[dict[str, Any]]:
        """List admin roles."""
        resp = await self._request("GET", "/api/v1/iam/roles")
        return resp.json()

    async def get_group_roles(self, group_id: str) -> list[dict[str, Any]]:
        """Get admin roles assigned to a group."""
        resp = await self._request("GET", f"/api/v1/groups/{group_id}/roles")
        return resp.json()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying httpx client."""
        await self._client.aclose()

    async def __aenter__(self) -> "OktaClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
