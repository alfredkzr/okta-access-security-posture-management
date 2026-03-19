"""Webhook notification dispatcher.

Implements the Standard Webhooks specification for outgoing webhooks:
- Standard envelope: {id, type, timestamp, data}
- HMAC-SHA256 signing: sign("{msg_id}.{timestamp}.{body}")
- Standard headers: Webhook-Id, Webhook-Timestamp, Webhook-Signature
- Retry with exponential backoff on 5xx/timeout
- Unique delivery ID for consumer-side idempotency

Reference: https://github.com/standard-webhooks/standard-webhooks
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac as hmac_mod
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.notification_channel import NotificationChannel

logger = structlog.get_logger(__name__)

# Timeouts
CONNECT_TIMEOUT = 5.0  # seconds
READ_TIMEOUT = 15.0  # seconds

# Retry schedule (delays in seconds between attempts)
RETRY_DELAYS = [2, 5]  # 2s, 5s — 3 total attempts (keep it fast, don't block callers)

USER_AGENT = "OktaASPM-Webhooks/1.0"


def _build_envelope(event: str, payload: dict[str, Any]) -> tuple[str, dict]:
    """Build the standard webhook envelope.

    Returns (message_id, envelope_dict).
    """
    msg_id = f"msg_{uuid.uuid4().hex[:24]}"
    envelope = {
        "id": msg_id,
        "type": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": payload,
    }
    return msg_id, envelope


def _sign(secret: str, msg_id: str, timestamp: int, body_bytes: bytes) -> str:
    """Compute HMAC-SHA256 signature per Standard Webhooks spec.

    signed_content = "{msg_id}.{timestamp}.{body}"
    Returns base64-encoded signature prefixed with "v1,".
    """
    signed_content = f"{msg_id}.{timestamp}.".encode("utf-8") + body_bytes
    sig = hmac_mod.new(
        secret.encode("utf-8"),
        signed_content,
        hashlib.sha256,
    ).digest()
    return f"v1,{base64.b64encode(sig).decode('utf-8')}"


def _build_headers(
    msg_id: str,
    timestamp: int,
    event: str,
    secret: str | None,
    body_bytes: bytes,
    custom_headers: dict[str, str] | None,
    attempt: int = 1,
) -> dict[str, str]:
    """Build standard webhook headers."""
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "Webhook-Id": msg_id,
        "Webhook-Timestamp": str(timestamp),
        "Webhook-Event-Type": event,
    }

    if attempt > 1:
        headers["Webhook-Delivery-Attempt"] = str(attempt)

    if secret:
        headers["Webhook-Signature"] = _sign(secret, msg_id, timestamp, body_bytes)

    if isinstance(custom_headers, dict):
        headers.update(custom_headers)

    return headers


async def dispatch(event: str, payload: dict[str, Any], db_session: AsyncSession) -> None:
    """Dispatch a webhook notification to all matching active channels.

    This function is fire-and-forget: it never raises exceptions and never
    blocks the caller on webhook failures.
    """
    try:
        channels = await _get_matching_channels(event, db_session)
    except Exception:
        logger.exception("notifier.channel_query_failed", notification_event=event)
        return

    if not channels:
        logger.debug("notifier.no_matching_channels", notification_event=event)
        return

    # Build envelope once, share across all channels
    msg_id, envelope = _build_envelope(event, payload)
    body_bytes = json.dumps(envelope, default=str).encode("utf-8")
    timestamp = int(time.time())

    for channel in channels:
        try:
            await _send_webhook(channel, event, msg_id, timestamp, body_bytes)
        except Exception:
            logger.exception(
                "notifier.webhook_failed",
                notification_event=event,
                channel_id=str(channel.id),
                channel_name=channel.name,
            )


async def dispatch_test(channel: NotificationChannel) -> dict[str, Any]:
    """Send a test webhook using the same signing and envelope as production.

    Returns a result dict with success, status_code, and message.
    """
    config = channel.config or {}
    url = config.get("url")
    if not url:
        return {"success": False, "status_code": None, "message": "Channel config is missing 'url'"}

    payload = {
        "message": "Test notification from Okta ASPM",
        "channel_id": str(channel.id),
        "channel_name": channel.name,
    }
    msg_id, envelope = _build_envelope("test", payload)
    body_bytes = json.dumps(envelope, default=str).encode("utf-8")
    timestamp = int(time.time())

    secret = config.get("secret")
    custom_headers = config.get("headers")
    headers = _build_headers(msg_id, timestamp, "test", secret, body_bytes, custom_headers)

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT, write=READ_TIMEOUT, pool=READ_TIMEOUT),
        ) as client:
            resp = await client.post(url, content=body_bytes, headers=headers)
        return {
            "success": resp.status_code < 400,
            "status_code": resp.status_code,
            "message": "Test notification sent",
        }
    except httpx.RequestError as exc:
        return {
            "success": False,
            "status_code": None,
            "message": f"Failed to send test notification: {exc}",
        }


async def _get_matching_channels(
    event: str,
    db_session: AsyncSession,
) -> list[NotificationChannel]:
    """Query active notification channels whose events list includes the given event."""
    stmt = select(NotificationChannel).where(NotificationChannel.is_active.is_(True))
    result = await db_session.execute(stmt)
    all_active = result.scalars().all()

    matching: list[NotificationChannel] = []
    for ch in all_active:
        events = ch.events
        if isinstance(events, list) and event in events:
            matching.append(ch)

    return matching


async def _send_webhook(
    channel: NotificationChannel,
    event: str,
    msg_id: str,
    timestamp: int,
    body_bytes: bytes,
) -> None:
    """Send a webhook with retries on 5xx/timeout.

    Retries use the same msg_id and timestamp so consumers can deduplicate.
    """
    config = channel.config or {}
    url = config.get("url")
    if not url:
        logger.warning(
            "notifier.channel_missing_url",
            channel_id=str(channel.id),
            channel_name=channel.name,
        )
        return

    secret = config.get("secret")
    custom_headers = config.get("headers")
    max_attempts = 1 + len(RETRY_DELAYS)

    for attempt in range(1, max_attempts + 1):
        headers = _build_headers(msg_id, timestamp, event, secret, body_bytes, custom_headers, attempt)

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT, write=READ_TIMEOUT, pool=READ_TIMEOUT),
            ) as client:
                resp = await client.post(url, content=body_bytes, headers=headers)

            if resp.status_code < 400:
                # 2xx/3xx = success
                logger.info(
                    "notifier.webhook_delivered",
                    notification_event=event,
                    channel_id=str(channel.id),
                    channel_name=channel.name,
                    webhook_id=msg_id,
                    status_code=resp.status_code,
                    attempt=attempt,
                )
                return

            if 400 <= resp.status_code < 500 and resp.status_code != 429:
                # 4xx (except 429) = permanent failure, don't retry
                logger.warning(
                    "notifier.webhook_client_error",
                    notification_event=event,
                    channel_id=str(channel.id),
                    channel_name=channel.name,
                    webhook_id=msg_id,
                    status_code=resp.status_code,
                    attempt=attempt,
                )
                return

            # 429 or 5xx — retry
            retry_after = resp.headers.get("Retry-After")
            logger.warning(
                "notifier.webhook_retryable_error",
                notification_event=event,
                channel_id=str(channel.id),
                webhook_id=msg_id,
                status_code=resp.status_code,
                attempt=attempt,
                retry_after=retry_after,
            )

        except httpx.RequestError as exc:
            logger.warning(
                "notifier.webhook_request_error",
                notification_event=event,
                channel_id=str(channel.id),
                webhook_id=msg_id,
                error=str(exc),
                attempt=attempt,
            )

        # Wait before next retry (if there are retries left)
        if attempt <= len(RETRY_DELAYS):
            delay = RETRY_DELAYS[attempt - 1]
            await asyncio.sleep(delay)

    logger.error(
        "notifier.webhook_exhausted",
        notification_event=event,
        channel_id=str(channel.id),
        channel_name=channel.name,
        webhook_id=msg_id,
        total_attempts=max_attempts,
    )
