"""Tests for src/core/notifier.py — Standard Webhooks implementation."""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import json
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.core.notifier import _build_envelope, _sign, dispatch


def _make_channel(
    *,
    name: str = "test-channel",
    events: list[str] | None = None,
    url: str = "https://hooks.example.com/webhook",
    secret: str | None = None,
    headers: dict[str, str] | None = None,
    is_active: bool = True,
) -> MagicMock:
    """Create a mock NotificationChannel."""
    ch = MagicMock()
    ch.id = uuid.uuid4()
    ch.name = name
    ch.is_active = is_active
    ch.events = events or []
    config: dict[str, Any] = {"url": url}
    if secret:
        config["secret"] = secret
    if headers:
        config["headers"] = headers
    ch.config = config
    return ch


def _mock_db_session(channels: list[MagicMock]) -> AsyncMock:
    """Create a mock async DB session that returns given channels from execute()."""
    session = AsyncMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = channels
    result_mock = MagicMock()
    result_mock.scalars.return_value = scalars_mock
    session.execute = AsyncMock(return_value=result_mock)
    return session


def _mock_http_client(status_code: int = 200, side_effect=None) -> AsyncMock:
    """Create a mock httpx.AsyncClient."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code

    mock_client = AsyncMock()
    if side_effect:
        mock_client.post = AsyncMock(side_effect=side_effect)
    else:
        mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


@pytest.fixture(autouse=True)
def _mock_structlog():
    """Mock the structlog logger in notifier to avoid 'event' kwarg conflicts."""
    mock_logger = MagicMock()
    with patch("src.core.notifier.logger", mock_logger):
        yield mock_logger


# ---------------------------------------------------------------------------
# Envelope & Signing
# ---------------------------------------------------------------------------

class TestEnvelope:
    def test_envelope_has_standard_fields(self):
        msg_id, envelope = _build_envelope("scan_completed", {"key": "val"})
        assert msg_id.startswith("msg_")
        assert envelope["id"] == msg_id
        assert envelope["type"] == "scan_completed"
        assert "timestamp" in envelope
        assert envelope["data"] == {"key": "val"}

    def test_envelope_id_is_unique(self):
        id1, _ = _build_envelope("test", {})
        id2, _ = _build_envelope("test", {})
        assert id1 != id2


class TestSigning:
    def test_sign_produces_v1_prefixed_base64(self):
        sig = _sign("secret", "msg_abc", 1710856200, b'{"test":true}')
        assert sig.startswith("v1,")
        # Should be valid base64 after prefix
        b64_part = sig[3:]
        base64.b64decode(b64_part)  # Should not raise

    def test_sign_is_deterministic(self):
        sig1 = _sign("secret", "msg_abc", 1710856200, b'{"test":true}')
        sig2 = _sign("secret", "msg_abc", 1710856200, b'{"test":true}')
        assert sig1 == sig2

    def test_sign_changes_with_different_body(self):
        sig1 = _sign("secret", "msg_abc", 1710856200, b'{"a":1}')
        sig2 = _sign("secret", "msg_abc", 1710856200, b'{"a":2}')
        assert sig1 != sig2

    def test_sign_verifiable_externally(self):
        """Verify signature matches manual HMAC computation."""
        secret = "my-secret"
        msg_id = "msg_test123"
        ts = 1710856200
        body = b'{"data":"hello"}'

        sig = _sign(secret, msg_id, ts, body)
        b64_sig = sig[3:]  # strip "v1,"

        # Manually compute expected signature
        signed_content = f"{msg_id}.{ts}.".encode("utf-8") + body
        expected = hmac_mod.new(
            secret.encode("utf-8"), signed_content, hashlib.sha256
        ).digest()
        assert base64.b64decode(b64_sig) == expected


# ---------------------------------------------------------------------------
# Dispatch — Channel Matching
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDispatchNoChannels:
    async def test_no_matching_channels_does_nothing(self):
        db = _mock_db_session([])
        mock_client = _mock_http_client()
        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan_completed", {"status": "ok"}, db)
            mock_client.post.assert_not_called()

    async def test_channel_with_non_matching_event_skipped(self):
        ch = _make_channel(events=["new_vulnerabilities"])
        db = _mock_db_session([ch])
        mock_client = _mock_http_client()
        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan_completed", {"status": "ok"}, db)
            mock_client.post.assert_not_called()


# ---------------------------------------------------------------------------
# Dispatch — Webhook Delivery
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDispatchWebhook:
    async def test_sends_post_to_correct_url(self):
        ch = _make_channel(events=["scan_completed"], url="https://hooks.example.com/test")
        db = _mock_db_session([ch])
        mock_client = _mock_http_client()

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan_completed", {"scan_id": "123"}, db)

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        assert call_kwargs.args[0] == "https://hooks.example.com/test"

    async def test_sends_to_all_matching_channels(self):
        ch1 = _make_channel(name="ch1", events=["scan_completed"], url="https://hook1.example.com")
        ch2 = _make_channel(name="ch2", events=["scan_completed"], url="https://hook2.example.com")
        ch3 = _make_channel(name="ch3", events=["new_vulnerabilities"], url="https://hook3.example.com")
        db = _mock_db_session([ch1, ch2, ch3])
        mock_client = _mock_http_client()

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan_completed", {}, db)

        # ch1 and ch2 match, ch3 does not
        assert mock_client.post.call_count == 2

    async def test_channel_without_url_is_skipped(self):
        ch = _make_channel(events=["scan_completed"])
        ch.config = {}  # No URL
        db = _mock_db_session([ch])
        mock_client = _mock_http_client()

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan_completed", {}, db)

        mock_client.post.assert_not_called()


# ---------------------------------------------------------------------------
# Standard Headers
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestStandardHeaders:
    async def test_includes_standard_webhook_headers(self):
        ch = _make_channel(events=["scan_completed"])
        db = _mock_db_session([ch])
        mock_client = _mock_http_client()

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan_completed", {}, db)

        headers = mock_client.post.call_args.kwargs["headers"]
        assert headers["Content-Type"] == "application/json"
        assert headers["User-Agent"] == "OktaASPM-Webhooks/1.0"
        assert "Webhook-Id" in headers
        assert headers["Webhook-Id"].startswith("msg_")
        assert "Webhook-Timestamp" in headers
        assert headers["Webhook-Event-Type"] == "scan_completed"

    async def test_custom_headers_included(self):
        ch = _make_channel(
            events=["scan_completed"],
            headers={"X-Custom": "custom-value", "Authorization": "Bearer token123"},
        )
        db = _mock_db_session([ch])
        mock_client = _mock_http_client()

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan_completed", {}, db)

        headers = mock_client.post.call_args.kwargs["headers"]
        assert headers["X-Custom"] == "custom-value"
        assert headers["Authorization"] == "Bearer token123"


# ---------------------------------------------------------------------------
# HMAC Signing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDispatchHMAC:
    async def test_signature_header_present_when_secret_set(self):
        ch = _make_channel(events=["scan_completed"], secret="my-webhook-secret")
        db = _mock_db_session([ch])
        mock_client = _mock_http_client()

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan_completed", {"data": "value"}, db)

        headers = mock_client.post.call_args.kwargs["headers"]
        assert "Webhook-Signature" in headers
        assert headers["Webhook-Signature"].startswith("v1,")

    async def test_no_signature_header_without_secret(self):
        ch = _make_channel(events=["scan_completed"])  # no secret
        db = _mock_db_session([ch])
        mock_client = _mock_http_client()

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan_completed", {}, db)

        headers = mock_client.post.call_args.kwargs["headers"]
        assert "Webhook-Signature" not in headers

    async def test_signature_is_verifiable(self):
        secret = "test-secret-key"
        ch = _make_channel(events=["scan_completed"], secret=secret)
        db = _mock_db_session([ch])
        mock_client = _mock_http_client()

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan_completed", {"scan_id": "xyz"}, db)

        call_kwargs = mock_client.post.call_args.kwargs
        headers = call_kwargs["headers"]
        body_bytes = call_kwargs["content"]
        msg_id = headers["Webhook-Id"]
        ts = headers["Webhook-Timestamp"]

        # Verify signature manually
        signed_content = f"{msg_id}.{ts}.".encode("utf-8") + body_bytes
        expected_sig = hmac_mod.new(
            secret.encode("utf-8"), signed_content, hashlib.sha256
        ).digest()
        expected = f"v1,{base64.b64encode(expected_sig).decode('utf-8')}"
        assert headers["Webhook-Signature"] == expected


# ---------------------------------------------------------------------------
# Body Structure
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestWebhookBodyStructure:
    async def test_body_has_standard_envelope(self):
        ch = _make_channel(events=["scan_completed"])
        db = _mock_db_session([ch])
        mock_client = _mock_http_client()

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan_completed", {"key": "val"}, db)

        body_bytes = mock_client.post.call_args.kwargs["content"]
        body = json.loads(body_bytes)
        assert body["type"] == "scan_completed"
        assert body["id"].startswith("msg_")
        assert "timestamp" in body
        assert body["data"] == {"key": "val"}


# ---------------------------------------------------------------------------
# Retry Logic
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRetryLogic:
    async def test_retries_on_5xx(self):
        ch = _make_channel(events=["scan_completed"])
        db = _mock_db_session([ch])

        mock_resp_500 = MagicMock()
        mock_resp_500.status_code = 500
        mock_resp_200 = MagicMock()
        mock_resp_200.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[mock_resp_500, mock_resp_200])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client), \
             patch("src.core.notifier.RETRY_DELAYS", [0]):  # no actual wait
            await dispatch("scan_completed", {}, db)

        assert mock_client.post.call_count == 2

    async def test_no_retry_on_4xx(self):
        ch = _make_channel(events=["scan_completed"])
        db = _mock_db_session([ch])
        mock_client = _mock_http_client(status_code=400)

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan_completed", {}, db)

        # 4xx is a permanent failure, no retry
        assert mock_client.post.call_count == 1

    async def test_retries_on_connection_error(self):
        ch = _make_channel(events=["scan_completed"])
        db = _mock_db_session([ch])

        mock_resp_200 = MagicMock()
        mock_resp_200.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[
            httpx.ConnectError("Connection refused"),
            mock_resp_200,
        ])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client), \
             patch("src.core.notifier.RETRY_DELAYS", [0]):
            await dispatch("scan_completed", {}, db)

        assert mock_client.post.call_count == 2

    async def test_delivery_attempt_header_increments(self):
        ch = _make_channel(events=["scan_completed"])
        db = _mock_db_session([ch])

        mock_resp_500 = MagicMock()
        mock_resp_500.status_code = 500
        mock_resp_200 = MagicMock()
        mock_resp_200.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[mock_resp_500, mock_resp_200])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client), \
             patch("src.core.notifier.RETRY_DELAYS", [0]):
            await dispatch("scan_completed", {}, db)

        # First call (attempt 1) should not have Webhook-Delivery-Attempt
        first_headers = mock_client.post.call_args_list[0].kwargs["headers"]
        assert "Webhook-Delivery-Attempt" not in first_headers

        # Second call (attempt 2) should have it
        second_headers = mock_client.post.call_args_list[1].kwargs["headers"]
        assert second_headers["Webhook-Delivery-Attempt"] == "2"

    async def test_same_webhook_id_across_retries(self):
        ch = _make_channel(events=["scan_completed"])
        db = _mock_db_session([ch])

        mock_resp_500 = MagicMock()
        mock_resp_500.status_code = 500
        mock_resp_200 = MagicMock()
        mock_resp_200.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[mock_resp_500, mock_resp_200])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client), \
             patch("src.core.notifier.RETRY_DELAYS", [0]):
            await dispatch("scan_completed", {}, db)

        first_id = mock_client.post.call_args_list[0].kwargs["headers"]["Webhook-Id"]
        second_id = mock_client.post.call_args_list[1].kwargs["headers"]["Webhook-Id"]
        assert first_id == second_id


# ---------------------------------------------------------------------------
# Failure Handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDispatchFailure:
    async def test_failed_webhook_does_not_raise(self):
        ch = _make_channel(events=["scan_completed"])
        db = _mock_db_session([ch])
        mock_client = _mock_http_client(side_effect=httpx.ConnectError("Connection refused"))

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client), \
             patch("src.core.notifier.RETRY_DELAYS", [0, 0, 0]):
            await dispatch("scan_completed", {"data": "test"}, db)

    async def test_db_query_failure_does_not_raise(self):
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=Exception("DB connection lost"))
        await dispatch("scan_completed", {}, session)
