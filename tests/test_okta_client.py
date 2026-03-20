"""Tests for OktaClient — mocked httpx responses."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from src.core.okta_client import (
    OktaApiError,
    OktaClient,
    OktaNotFoundError,
    OktaRateLimitError,
    _parse_link_header,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json_response(
    data: dict | list,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    hdrs = {"content-type": "application/json"}
    if headers:
        hdrs.update(headers)
    return httpx.Response(status, json=data, headers=hdrs)


def _make_transport(handler):
    """Create an httpx.MockTransport from an async or sync handler."""
    return httpx.MockTransport(handler)


def _client_with_transport(transport, **kwargs) -> OktaClient:
    """Build an OktaClient whose internal httpx client uses the given transport."""
    client = OktaClient(
        base_url="https://test.okta.com",
        api_token="test-token",
        max_workers=5,
        **kwargs,
    )
    # Replace internal httpx client with one using our mock transport
    client._client = httpx.AsyncClient(
        transport=transport,
        base_url="https://test.okta.com",
        headers=client._client.headers,
        timeout=httpx.Timeout(5.0),
    )
    return client


# ---------------------------------------------------------------------------
# Link header parsing
# ---------------------------------------------------------------------------

class TestLinkHeaderParsing:
    def test_parse_single_next(self):
        header = '<https://test.okta.com/api/v1/users?after=abc>; rel="next"'
        result = _parse_link_header(header)
        assert result == {"next": "https://test.okta.com/api/v1/users?after=abc"}

    def test_parse_multiple_rels(self):
        header = (
            '<https://test.okta.com/api/v1/users?after=abc>; rel="next", '
            '<https://test.okta.com/api/v1/users>; rel="self"'
        )
        result = _parse_link_header(header)
        assert "next" in result
        assert "self" in result

    def test_parse_none(self):
        assert _parse_link_header(None) == {}

    def test_parse_empty(self):
        assert _parse_link_header("") == {}


# ---------------------------------------------------------------------------
# Successful API calls
# ---------------------------------------------------------------------------

class TestSuccessfulCalls:
    @pytest.mark.asyncio
    async def test_get_user_by_id(self):
        user = {"id": "u1", "status": "ACTIVE", "profile": {"login": "a@b.com"}}

        def handler(request: httpx.Request) -> httpx.Response:
            assert "/api/v1/users/u1" in str(request.url)
            return _json_response(user)

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            result = await client.get_user_by_id("u1")
            assert result["id"] == "u1"
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_user_by_login(self):
        user = {"id": "u1", "profile": {"login": "alice@example.com"}}

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(user)

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            result = await client.get_user_by_login("alice@example.com")
            assert result is not None
            assert result["id"] == "u1"
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_user_by_login_not_found(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"errorCode": "E0000007", "errorSummary": "Not found"})

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            result = await client.get_user_by_login("nobody@example.com")
            assert result is None
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_simulate_policy(self):
        sim_response = {"evaluation": [{"policyType": "ACCESS_POLICY", "result": {"policies": []}}]}

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "POST"
            assert "expand=RULE" in str(request.url)
            return _json_response(sim_response)

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            result = await client.simulate_policy({"policyTypes": [], "appInstance": "app1"})
            assert "evaluation" in result
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_policy_rule(self):
        rule = {"id": "r1", "actions": {"appSignOn": {"access": "ALLOW"}}}

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(rule)

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            result = await client.get_policy_rule("p1", "r1")
            assert result["id"] == "r1"
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_org_info(self):
        org = {"id": "org1", "name": "Test Org"}

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(org)

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            result = await client.get_org_info()
            assert result["id"] == "org1"
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_list_zones(self):
        zones = [{"id": "z1", "name": "HQ"}]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(zones)

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            result = await client.list_zones()
            assert len(result) == 1
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

class TestPagination:
    @pytest.mark.asyncio
    async def test_list_users_pagination(self):
        page1 = [{"id": "u1"}, {"id": "u2"}]
        page2 = [{"id": "u3"}]
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _json_response(
                    page1,
                    headers={"link": '<https://test.okta.com/api/v1/users?after=u2&limit=200>; rel="next"'},
                )
            return _json_response(page2)

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            users = await client.list_users()
            assert len(users) == 3
            assert [u["id"] for u in users] == ["u1", "u2", "u3"]
            assert call_count == 2
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_no_pagination_single_page(self):
        data = [{"id": "u1"}]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(data)

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            users = await client.list_users()
            assert len(users) == 1
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------

class TestRetryLogic:
    @pytest.mark.asyncio
    async def test_retry_on_500(self):
        """Should retry on 5xx and eventually succeed."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return httpx.Response(500, json={"errorCode": "E0000009"})
            return _json_response({"id": "org1"})

        client = _client_with_transport(httpx.MockTransport(handler))
        # Speed up retries for testing
        client.BASE_DELAY = 0.01
        client.MAX_JITTER = 0.01
        try:
            result = await client.get_org_info()
            assert result["id"] == "org1"
            assert call_count == 3
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_retry_exhausted_raises(self):
        """Should raise after max retries exhausted."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, json={"errorCode": "E0000009"})

        client = _client_with_transport(httpx.MockTransport(handler))
        client.BASE_DELAY = 0.01
        client.MAX_JITTER = 0.01
        try:
            with pytest.raises(OktaApiError) as exc_info:
                await client.get_org_info()
            assert exc_info.value.status_code == 503
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_no_retry_on_400(self):
        """Should NOT retry on non-429 4xx errors."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(400, json={"errorCode": "E0000001", "errorSummary": "Bad request"})

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            with pytest.raises(OktaApiError) as exc_info:
                await client.get_org_info()
            assert exc_info.value.status_code == 400
            assert call_count == 1  # No retries
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_404_raises_not_found(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"errorCode": "E0000007"})

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            with pytest.raises(OktaNotFoundError):
                await client.get_user_by_id("nonexistent")
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# Rate limit handling
# ---------------------------------------------------------------------------

class TestRateLimiting:
    @pytest.mark.asyncio
    async def test_429_e0000047_raises_rate_limit_error(self):
        """HTTP 429 with E0000047 should raise OktaRateLimitError after one retry."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(429, json={"errorCode": "E0000047", "errorSummary": "Rate limit"})

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            with pytest.raises(OktaRateLimitError):
                await client.get_org_info()
            assert call_count == 2  # One retry after respecting the reset window
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_429_non_e0000047_retries(self):
        """HTTP 429 without E0000047 should be retried."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                return httpx.Response(429, json={"errorCode": "E0000049"})
            return _json_response({"id": "org1"})

        client = _client_with_transport(httpx.MockTransport(handler))
        client.BASE_DELAY = 0.01
        client.MAX_JITTER = 0.01
        try:
            result = await client.get_org_info()
            assert result["id"] == "org1"
            assert call_count == 2
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# Adaptive throttling
# ---------------------------------------------------------------------------

class TestAdaptiveThrottling:
    @pytest.mark.asyncio
    async def test_throttle_when_remaining_low(self):
        """Should add delay when remaining is < 10% of limit."""
        throttle_observed = False

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(
                {"id": "org1"},
                headers={
                    "X-Rate-Limit-Remaining": "5",
                    "X-Rate-Limit-Limit": "100",
                },
            )

        client = _client_with_transport(httpx.MockTransport(handler))
        # Reduce throttle delay for test speed
        client.THROTTLE_DELAY = 0.01

        original_sleep = asyncio.sleep

        async def mock_sleep(delay):
            nonlocal throttle_observed
            if delay >= 0.005:  # Our throttle delay
                throttle_observed = True
            await original_sleep(delay)

        try:
            with patch("src.core.okta_client.asyncio.sleep", side_effect=mock_sleep):
                await client.get_org_info()
            assert throttle_observed
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_no_throttle_when_remaining_high(self):
        """Should NOT throttle when remaining is above threshold."""
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(
                {"id": "org1"},
                headers={
                    "X-Rate-Limit-Remaining": "90",
                    "X-Rate-Limit-Limit": "100",
                },
            )

        client = _client_with_transport(httpx.MockTransport(handler))
        # If throttle fires it would be this delay
        client.THROTTLE_DELAY = 5.0  # We'd notice if this fires

        try:
            # Should complete quickly without the 5s delay
            result = await client.get_org_info()
            assert result["id"] == "org1"
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# Auth header
# ---------------------------------------------------------------------------

class TestAuthHeader:
    @pytest.mark.asyncio
    async def test_ssws_header_sent(self):
        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("authorization")
            assert auth == "SSWS test-token"
            return _json_response({"id": "org1"})

        client = _client_with_transport(httpx.MockTransport(handler))
        try:
            await client.get_org_info()
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# Backoff calculation
# ---------------------------------------------------------------------------

class TestBackoff:
    def test_backoff_increases_exponentially(self):
        # With jitter the exact value varies, but the base should double
        delays = []
        for attempt in range(4):
            # Remove jitter to test base
            base = OktaClient.BASE_DELAY * (2 ** attempt)
            delays.append(base)
        assert delays == [2.0, 4.0, 8.0, 16.0]

    def test_backoff_delay_within_range(self):
        for attempt in range(5):
            delay = OktaClient._backoff_delay(attempt)
            base = OktaClient.BASE_DELAY * (2 ** attempt)
            assert base <= delay <= base + OktaClient.MAX_JITTER
