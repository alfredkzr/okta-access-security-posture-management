"""SAQ cron task: check scheduled jobs and enqueue due scans."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import structlog
from croniter import croniter
from saq import Queue
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings as app_settings
from src.models.job import Job, ScheduleType
from src.models.scan import Scan, ScanStatus

logger = structlog.get_logger(__name__)


async def check_scheduled_jobs(ctx: dict) -> None:
    """Poll the jobs table and enqueue any scans that are due.

    Runs every 60 seconds as a SAQ cron job.
    """
    session_factory = ctx["db_session_factory"]
    now = datetime.now(timezone.utc)

    async with session_factory() as db_session:
        # Mark stale scans as FAILED so they don't block scheduling forever.
        # PENDING > 10 min or RUNNING > 2 hours with no progress → FAILED.
        stale_cutoff_pending = now - timedelta(minutes=10)
        stale_cutoff_running = now - timedelta(hours=2)
        stale_stmt = select(Scan).where(
            (
                (Scan.status == ScanStatus.PENDING)
                & (Scan.created_at < stale_cutoff_pending)
            )
            | (
                (Scan.status == ScanStatus.RUNNING)
                & (Scan.started_at < stale_cutoff_running)
            )
        )
        stale_result = await db_session.execute(stale_stmt)
        for stale_scan in stale_result.scalars().all():
            stale_scan.status = ScanStatus.FAILED
            stale_scan.completed_at = now
            stale_scan.error_message = "Marked as failed by scheduler (stale)"
            logger.warning(
                "scheduler_marked_stale_scan",
                scan_id=str(stale_scan.id),
                previous_status=stale_scan.status.value if hasattr(stale_scan.status, "value") else str(stale_scan.status),
            )

        # Query all active jobs
        stmt = select(Job).where(Job.is_active.is_(True))
        result = await db_session.execute(stmt)
        jobs = list(result.scalars().all())

        if not jobs:
            await db_session.commit()
            return

        enqueued_count = 0

        for job in jobs:
            try:
                if not _is_job_due(job, now):
                    continue

                # Per-job guard: skip if THIS job already has a PENDING or RUNNING scan
                job_scan_stmt = select(Scan.id).where(
                    Scan.job_id == job.id,
                    Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
                ).limit(1)
                job_scan_result = await db_session.execute(job_scan_stmt)
                if job_scan_result.scalar_one_or_none() is not None:
                    logger.debug(
                        "scheduler_skipped_job_scan_in_progress",
                        job_id=str(job.id),
                        job_name=job.name,
                    )
                    continue

                await _enqueue_job(job, now, db_session)
                enqueued_count += 1
            except Exception as exc:
                logger.error(
                    "scheduler_job_check_failed",
                    job_id=str(job.id),
                    job_name=job.name,
                    error=str(exc),
                )

        await db_session.commit()
        if enqueued_count > 0:
            logger.info("scheduler_enqueued_jobs", count=enqueued_count)


def _is_job_due(job: Job, now: datetime) -> bool:
    """Determine whether a job is due for execution."""
    if job.schedule_type == ScheduleType.CRON:
        if not job.cron_expression:
            return False
        # Use last_run_at as the base time; if never run, use created_at
        base_time = job.last_run_at or job.created_at
        if base_time.tzinfo is None:
            base_time = base_time.replace(tzinfo=timezone.utc)
        cron = croniter(job.cron_expression, base_time)
        next_run = cron.get_next(datetime)
        if next_run.tzinfo is None:
            next_run = next_run.replace(tzinfo=timezone.utc)
        return now >= next_run

    elif job.schedule_type == ScheduleType.INTERVAL:
        if not job.interval_seconds:
            return False
        if job.last_run_at is None:
            return True
        last_run = job.last_run_at
        if last_run.tzinfo is None:
            last_run = last_run.replace(tzinfo=timezone.utc)
        return now >= last_run + timedelta(seconds=job.interval_seconds)

    elif job.schedule_type == ScheduleType.ONCE:
        if job.last_run_at is not None:
            # Already ran
            return False
        if job.run_at is None:
            return False
        run_at = job.run_at
        if run_at.tzinfo is None:
            run_at = run_at.replace(tzinfo=timezone.utc)
        return now >= run_at

    return False


async def _enqueue_job(job: Job, now: datetime, db_session: AsyncSession) -> None:
    """Create a Scan record and enqueue it via SAQ."""
    scan = Scan(
        id=uuid.uuid4(),
        job_id=job.id,
        job_name=job.name,
        status=ScanStatus.PENDING,
        total_users=0,
    )
    db_session.add(scan)
    await db_session.flush()

    scan_config = job.scan_config or {}

    queue = Queue.from_url(app_settings.redis_url)
    try:
        await queue.connect()
        await queue.enqueue(
            "run_tenant_scan",
            scan_id=str(scan.id),
            scan_config=scan_config,
            timeout=0,
            heartbeat=600,
            retries=0,
        )
    finally:
        await queue.disconnect()

    # Update the job's last_run_at and compute next_run_at
    job.last_run_at = now
    job.next_run_at = _compute_next_run(job, now)

    logger.info(
        "scheduled_job_enqueued",
        job_id=str(job.id),
        job_name=job.name,
        scan_id=str(scan.id),
        next_run_at=job.next_run_at.isoformat() if job.next_run_at else None,
    )

    # For one-time jobs, deactivate after enqueue
    if job.schedule_type == ScheduleType.ONCE:
        job.is_active = False


def _compute_next_run(job: Job, now: datetime) -> datetime | None:
    """Compute the next run time for a job after execution."""
    if job.schedule_type == ScheduleType.CRON and job.cron_expression:
        cron = croniter(job.cron_expression, now)
        next_dt = cron.get_next(datetime)
        if next_dt.tzinfo is None:
            next_dt = next_dt.replace(tzinfo=timezone.utc)
        return next_dt

    elif job.schedule_type == ScheduleType.INTERVAL and job.interval_seconds:
        return now + timedelta(seconds=job.interval_seconds)

    elif job.schedule_type == ScheduleType.ONCE:
        return None

    return None
