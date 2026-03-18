"""Edge case tests for src/core/notifier.py."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio

from src.core.notifier import dispatch


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


@pytest.fixture(autouse=True)
def _mock_structlog():
    """Mock the structlog logger in notifier to avoid 'event' kwarg conflicts."""
    mock_logger = MagicMock()
    with patch("src.core.notifier.logger", mock_logger):
        yield mock_logger


@pytest.mark.asyncio
class TestDispatchNoChannels:
    async def test_no_matching_channels_does_nothing(self):
        """When no channels match the event, no HTTP calls are made."""
        db = _mock_db_session([])
        with patch("src.core.notifier.httpx.AsyncClient") as mock_client_cls:
            await dispatch("scan.completed", {"status": "ok"}, db)
            mock_client_cls.assert_not_called()

    async def test_channel_with_non_matching_event_skipped(self):
        """A channel whose events list doesn't include the dispatched event is skipped."""
        ch = _make_channel(events=["vulnerability.created"])
        db = _mock_db_session([ch])
        with patch("src.core.notifier.httpx.AsyncClient") as mock_client_cls:
            await dispatch("scan.completed", {"status": "ok"}, db)
            mock_client_cls.assert_not_called()


@pytest.mark.asyncio
class TestDispatchWebhook:
    async def test_sends_post_to_correct_url(self):
        ch = _make_channel(events=["scan.completed"], url="https://hooks.example.com/test")
        db = _mock_db_session([ch])

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan.completed", {"scan_id": "123"}, db)

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        # The url is the first positional arg
        assert call_args.args[0] == "https://hooks.example.com/test" or \
               call_args.kwargs.get("url") == "https://hooks.example.com/test"


@pytest.mark.asyncio
class TestDispatchHMAC:
    async def test_hmac_secret_includes_signature_header(self):
        ch = _make_channel(events=["scan.completed"], secret="my-webhook-secret")
        db = _mock_db_session([ch])

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan.completed", {"data": "value"}, db)

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert "X-Signature" in headers

        # Verify signature is valid HMAC-SHA256
        body_bytes = call_kwargs.kwargs.get("content")
        expected_sig = hmac_mod.new(
            b"my-webhook-secret", body_bytes, hashlib.sha256
        ).hexdigest()
        assert headers["X-Signature"] == expected_sig


@pytest.mark.asyncio
class TestDispatchCustomHeaders:
    async def test_custom_headers_included(self):
        ch = _make_channel(
            events=["scan.completed"],
            headers={"X-Custom": "custom-value", "Authorization": "Bearer token123"},
        )
        db = _mock_db_session([ch])

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan.completed", {}, db)

        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert headers.get("X-Custom") == "custom-value"
        assert headers.get("Authorization") == "Bearer token123"


@pytest.mark.asyncio
class TestDispatchFailure:
    async def test_failed_webhook_does_not_raise(self):
        """A webhook that throws an exception should not propagate."""
        ch = _make_channel(events=["scan.completed"])
        db = _mock_db_session([ch])

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            # Should not raise
            await dispatch("scan.completed", {"data": "test"}, db)

    async def test_db_query_failure_does_not_raise(self):
        """If the DB query fails, dispatch should not propagate."""
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=Exception("DB connection lost"))

        # Should not raise
        await dispatch("scan.completed", {}, session)


@pytest.mark.asyncio
class TestDispatchMultipleChannels:
    async def test_sends_to_all_matching_channels(self):
        ch1 = _make_channel(name="ch1", events=["scan.completed"], url="https://hook1.example.com")
        ch2 = _make_channel(name="ch2", events=["scan.completed"], url="https://hook2.example.com")
        ch3 = _make_channel(name="ch3", events=["vulnerability.created"], url="https://hook3.example.com")
        db = _mock_db_session([ch1, ch2, ch3])

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan.completed", {}, db)

        # ch1 and ch2 match, ch3 does not
        assert mock_client.post.call_count == 2


@pytest.mark.asyncio
class TestDispatchMissingURL:
    async def test_channel_without_url_is_skipped(self):
        """A channel whose config has no url should be skipped without error."""
        ch = _make_channel(events=["scan.completed"])
        ch.config = {}  # No URL
        db = _mock_db_session([ch])

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan.completed", {}, db)

        mock_client.post.assert_not_called()


@pytest.mark.asyncio
class TestWebhookBodyStructure:
    async def test_body_contains_event_timestamp_data(self):
        """The webhook body should have event, timestamp, and data fields."""
        ch = _make_channel(events=["scan.completed"])
        db = _mock_db_session([ch])

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.core.notifier.httpx.AsyncClient", return_value=mock_client):
            await dispatch("scan.completed", {"key": "val"}, db)

        body_bytes = mock_client.post.call_args.kwargs["content"]
        body = json.loads(body_bytes)
        assert body["event"] == "scan.completed"
        assert "timestamp" in body
        assert body["data"] == {"key": "val"}
