"""SAQ cron task: clean up old data based on retention policy."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.models.assessment_result import AssessmentResult
from src.models.posture_finding import PostureFinding
from src.models.report import Report
from src.models.scan import Scan

logger = structlog.get_logger(__name__)

# Batch size for deletes to avoid long-held locks
_BATCH_SIZE = 10_000


async def cleanup_old_data(ctx: dict) -> None:
    """Delete assessment results, reports, posture findings, and scans
    older than RETENTION_DAYS.

    Does NOT delete vulnerabilities, vulnerability_impacts, or audit_logs.
    Runs as a daily SAQ cron job.
    """
    session_factory = ctx["db_session_factory"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.retention_days)

    logger.info(
        "data_retention_started",
        retention_days=settings.retention_days,
        cutoff=cutoff.isoformat(),
    )

    async with session_factory() as db_session:
        # 1. Delete old reports (and their files on disk)
        await _cleanup_reports(db_session, cutoff)

        # 2. Delete old assessment results
        deleted = await _batch_delete(
            db_session,
            AssessmentResult,
            AssessmentResult.created_at < cutoff,
            "assessment_results",
        )

        # 3. Delete old posture findings
        deleted_pf = await _batch_delete(
            db_session,
            PostureFinding,
            PostureFinding.created_at < cutoff,
            "posture_findings",
        )

        # 4. Delete old scans (CASCADE will handle remaining FK refs)
        deleted_scans = await _batch_delete(
            db_session,
            Scan,
            Scan.created_at < cutoff,
            "scans",
        )

        await db_session.commit()

    logger.info("data_retention_completed")


async def _cleanup_reports(db_session: AsyncSession, cutoff: datetime) -> int:
    """Delete old reports and remove associated files from disk."""
    # First, fetch file paths so we can delete files
    stmt = select(Report).where(Report.created_at < cutoff)
    result = await db_session.execute(stmt)
    reports = result.scalars().all()

    file_paths = [r.file_path for r in reports if r.file_path]

    # Delete from DB in batch
    total_deleted = 0
    if reports:
        total_deleted = await _batch_delete(
            db_session,
            Report,
            Report.created_at < cutoff,
            "reports",
        )

    # Delete files from disk
    files_deleted = 0
    for path in file_paths:
        try:
            if os.path.exists(path):
                os.remove(path)
                files_deleted += 1
                # Try to remove parent dir if empty
                parent = os.path.dirname(path)
                if parent and os.path.isdir(parent) and not os.listdir(parent):
                    os.rmdir(parent)
        except OSError as exc:
            logger.warning("report_file_delete_failed", path=path, error=str(exc))

    if files_deleted > 0:
        logger.info("report_files_deleted", count=files_deleted)

    return total_deleted


async def _batch_delete(
    db_session: AsyncSession,
    model: type,
    condition,
    table_name: str,
) -> int:
    """Delete rows matching condition in batches to avoid long transactions.

    Returns total number of rows deleted.
    """
    total_deleted = 0

    while True:
        # Find IDs to delete in this batch
        id_stmt = select(model.id).where(condition).limit(_BATCH_SIZE)
        result = await db_session.execute(id_stmt)
        ids = [row[0] for row in result.all()]

        if not ids:
            break

        del_stmt = delete(model).where(model.id.in_(ids))
        del_result = await db_session.execute(del_stmt)
        batch_deleted = del_result.rowcount or 0
        total_deleted += batch_deleted
        await db_session.flush()

        logger.debug(
            "batch_delete_progress",
            table=table_name,
            batch_deleted=batch_deleted,
            total_deleted=total_deleted,
        )

        # If we deleted fewer than batch size, we're done
        if batch_deleted < _BATCH_SIZE:
            break

    if total_deleted > 0:
        logger.info("data_retention_table_cleaned", table=table_name, rows_deleted=total_deleted)

    return total_deleted
