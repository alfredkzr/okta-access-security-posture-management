"""SAQ cron task: monitor Okta API token health and rate limits."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import structlog

from src.core.okta_client import OktaClient

logger = structlog.get_logger(__name__)

_REDIS_KEY = "okta:health"
_REDIS_TTL = 600  # seconds


async def check_okta_health(ctx: dict) -> None:
    """Check Okta API connectivity and rate limit status.

    Stores the result in Redis with a 10-minute TTL. If the health status
    changes from the previous check, dispatches a notification.
    """
    import redis.asyncio as aioredis

    from src.config import settings

    redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)

    try:
        # Get previous health state
        previous_raw = await redis_client.get(_REDIS_KEY)
        previous_status = None
        if previous_raw:
            try:
                previous_status = json.loads(previous_raw).get("status")
            except (json.JSONDecodeError, AttributeError):
                pass

        # Check Okta health
        health_data = await _check_okta(settings)

        # Store in Redis
        await redis_client.set(
            _REDIS_KEY,
            json.dumps(health_data),
            ex=_REDIS_TTL,
        )

        current_status = health_data["status"]

        logger.info(
            "okta_health_checked",
            status=current_status,
            rate_limit_remaining_pct=health_data.get("rate_limit_remaining_pct"),
        )

        # Notify on status change
        if previous_status is not None and previous_status != current_status:
            logger.warning(
                "okta_health_status_changed",
                previous=previous_status,
                current=current_status,
            )
            await _dispatch_notification(ctx, health_data, previous_status)

    except Exception as exc:
        logger.error("okta_health_check_failed", error=str(exc))

        # Store error state
        error_data = {
            "status": "error",
            "error": str(exc)[:500],
            "rate_limit_remaining_pct": None,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            await redis_client.set(_REDIS_KEY, json.dumps(error_data), ex=_REDIS_TTL)
        except Exception:
            pass

    finally:
        await redis_client.aclose()


async def _check_okta(settings) -> dict:
    """Call Okta org endpoint and parse rate limit headers.

    Returns a health status dict.
    """
    async with OktaClient(
        base_url=settings.okta_base_url,
        api_token=settings.okta_api_token,
    ) as client:
        # Use the low-level _request to get the raw response with headers
        resp = await client._request("GET", "/api/v1/org")

        rate_remaining = resp.headers.get("X-Rate-Limit-Remaining")
        rate_limit = resp.headers.get("X-Rate-Limit-Limit")

        remaining_pct = None
        if rate_remaining is not None and rate_limit is not None:
            try:
                r = int(rate_remaining)
                l = int(rate_limit)
                if l > 0:
                    remaining_pct = round((r / l) * 100, 1)
            except (ValueError, ZeroDivisionError):
                pass

        # Determine status
        if resp.status_code >= 400:
            status = "unhealthy"
        elif remaining_pct is not None and remaining_pct < 10:
            status = "degraded"
        else:
            status = "healthy"

        return {
            "status": status,
            "rate_limit_remaining_pct": remaining_pct,
            "rate_limit_remaining": rate_remaining,
            "rate_limit_limit": rate_limit,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }


async def _dispatch_notification(ctx: dict, health_data: dict, previous_status: str) -> None:
    """Attempt to dispatch a health status change notification.

    This is best-effort; failures are logged but do not propagate.
    """
    try:
        from src.config import settings as app_settings
        from src.services import notifier

        await notifier.dispatch(
            "token_health",
            {
                "previous_status": previous_status,
                "current_status": health_data["status"],
                "rate_limit_remaining_pct": health_data.get("rate_limit_remaining_pct"),
                "rate_limit_remaining": health_data.get("rate_limit_remaining"),
                "okta_org": app_settings.okta_org,
                "checked_at": health_data["checked_at"],
            },
        )
    except ImportError:
        logger.debug("notifier_not_available", msg="src.services.notifier not found")
    except Exception as exc:
        logger.warning("health_notification_failed", error=str(exc))
