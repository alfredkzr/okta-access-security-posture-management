"""Webhook notification dispatcher.

Sends fire-and-forget webhook notifications to active notification channels
whose event filters match the dispatched event. Supports HMAC-SHA256 signing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.notification_channel import NotificationChannel

logger = structlog.get_logger(__name__)

WEBHOOK_TIMEOUT = 10.0  # seconds


async def dispatch(event: str, payload: dict[str, Any], db_session: AsyncSession) -> None:
    """Dispatch a webhook notification to all matching active channels.

    This function is fire-and-forget: it never raises exceptions and never
    blocks the caller on webhook failures.

    Args:
        event: The event name (e.g. "scan.completed", "vulnerability.created").
        payload: Arbitrary JSON-serialisable data to include in the webhook body.
        db_session: SQLAlchemy async session for querying notification channels.
    """
    try:
        channels = await _get_matching_channels(event, db_session)
    except Exception:
        logger.exception("notifier.channel_query_failed", notification_event=event)
        return

    if not channels:
        logger.debug("notifier.no_matching_channels", notification_event=event)
        return

    for channel in channels:
        try:
            await _send_webhook(channel, event, payload)
        except Exception:
            # Never propagate — notifications are best-effort
            logger.exception(
                "notifier.webhook_failed",
                notification_event=event,
                channel_id=str(channel.id),
                channel_name=channel.name,
            )


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
    payload: dict[str, Any],
) -> None:
    """Send a single webhook notification to a channel.

    Builds the request body, optionally signs it with HMAC-SHA256, and POSTs
    to the channel's configured URL.
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

    # Build webhook body
    body = {
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": payload,
    }
    body_bytes = json.dumps(body, default=str).encode("utf-8")

    # Build headers
    headers: dict[str, str] = {
        "Content-Type": "application/json",
    }

    # Add custom headers from channel config
    custom_headers = config.get("headers")
    if isinstance(custom_headers, dict):
        headers.update(custom_headers)

    # HMAC-SHA256 signature if a secret is configured
    secret = config.get("secret")
    if secret:
        signature = hmac.new(
            secret.encode("utf-8"),
            body_bytes,
            hashlib.sha256,
        ).hexdigest()
        headers["X-Signature"] = signature

    # Send the webhook
    async with httpx.AsyncClient(timeout=httpx.Timeout(WEBHOOK_TIMEOUT)) as client:
        resp = await client.post(url, content=body_bytes, headers=headers)

    logger.info(
        "notifier.webhook_sent",
        notification_event=event,
        channel_id=str(channel.id),
        channel_name=channel.name,
        url=url,
        status_code=resp.status_code,
    )
