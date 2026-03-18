"""SAQ task: run a full tenant scan."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings as app_settings
from src.core.assessment_engine import run_batch_scan
from src.core.okta_client import OktaClient
from src.models.scan import Scan, ScanStatus
from src.models.scenario import Scenario
from src.schemas.schedules import ScanConfig

logger = structlog.get_logger(__name__)


async def run_tenant_scan(ctx: dict, *, scan_id: str, scan_config: dict) -> dict:
    """Execute a tenant-wide or scoped security scan.

    This is an SAQ task function. It is enqueued by the API layer and executed
    by the SAQ worker process.

    Args:
        ctx: SAQ context dict (contains db_session_factory from startup).
        scan_id: UUID string of the Scan record.
        scan_config: Dict that deserializes to ScanConfig.

    Returns:
        Scan summary dict.
    """
    config = ScanConfig(**scan_config)
    scan_uuid = uuid.UUID(scan_id)
    session_factory = ctx["db_session_factory"]
    job = ctx.get("job")  # SAQ job object for heartbeat updates

    logger.info(
        "tenant_scan_started",
        scan_id=scan_id,
        user_selection=config.user_selection,
        max_workers=config.max_workers,
    )

    async with session_factory() as db_session:
        try:
            async with OktaClient(
                    base_url=app_settings.okta_base_url,
                    api_token=app_settings.okta_api_token,
                    max_workers=config.max_workers,
                ) as okta_client:
                # Resolve user list
                user_emails = await _resolve_users(okta_client, config)

                if job:
                    await job.update(progress=5)

                # Update scan with user count
                scan_stmt = select(Scan).where(Scan.id == scan_uuid)
                result = await db_session.execute(scan_stmt)
                scan = result.scalar_one_or_none()
                if scan is None:
                    raise ValueError(f"Scan record not found: {scan_id}")

                scan.total_users = len(user_emails)
                await db_session.flush()

                # Load active scenarios
                scenario_stmt = select(Scenario).where(Scenario.is_active.is_(True))
                scenario_result = await db_session.execute(scenario_stmt)
                scenarios = list(scenario_result.scalars().all())

                if not scenarios:
                    logger.warning("no_active_scenarios", scan_id=scan_id)

                if job:
                    await job.update(progress=10)

                # Run batch scan
                summary = await run_batch_scan(
                    scan_id=scan_uuid,
                    user_list=user_emails,
                    scenarios=scenarios,
                    db_session=db_session,
                    okta_client=okta_client,
                    max_workers=config.max_workers,
                    api_delay=config.api_delay,
                    saq_job=job,
                )

                await db_session.commit()
                logger.info("tenant_scan_completed", tenant_scan_id=scan_id, summary=summary)
                return summary

        except BaseException as exc:
            # BaseException catches CancelledError (SAQ timeout) as well as
            # regular exceptions.  Without this, a cancelled job leaves the
            # scan stuck in PENDING/RUNNING forever.
            logger.error("tenant_scan_failed", scan_id=scan_id, error=str(exc))

            # Update scan status to failed
            try:
                # Roll back any dirty session state before writing the failure
                await db_session.rollback()
                scan_stmt = select(Scan).where(Scan.id == scan_uuid)
                result = await db_session.execute(scan_stmt)
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.completed_at = datetime.now(timezone.utc)
                    scan.error_message = str(exc)[:2000]
                    await db_session.commit()
            except Exception as db_exc:
                logger.error("scan_status_update_failed", error=str(db_exc))

            raise


async def _resolve_users(okta_client: OktaClient, config: ScanConfig) -> list[str]:
    """Determine the list of user emails to scan based on config.

    Args:
        okta_client: Configured OktaClient.
        config: Scan configuration.

    Returns:
        List of user email strings.
    """
    if config.user_selection == "specific" and config.specific_users:
        return config.specific_users

    # Fetch all users from Okta
    all_users = await okta_client.list_users()

    # Filter out deactivated unless requested
    if not config.include_deactivated:
        all_users = [u for u in all_users if u.get("status") != "DEPROVISIONED"]

    emails = []
    for user in all_users:
        profile = user.get("profile", {})
        email = profile.get("email") or profile.get("login")
        if email:
            emails.append(email)

    # Apply max_users limit
    if config.user_selection == "limited" and config.max_users:
        emails = emails[: config.max_users]

    logger.info("users_resolved", count=len(emails), selection=config.user_selection)
    return emails
