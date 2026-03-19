"""SAQ task: generate reports (CSV, PDF, JSON)."""

from __future__ import annotations

import os
import uuid

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.models.report import Report, ReportType

logger = structlog.get_logger(__name__)

# Map report_type string to file extension
_EXTENSIONS = {
    "csv_full": "csv",
    "csv_violations": "csv",
    "csv_inactive": "csv",
    "csv_posture": "csv",
    "pdf": "pdf",
    "json": "json",
}


async def generate_report_task(ctx: dict, *, scan_id: str, report_type: str) -> dict:
    """Generate a report for the given scan and persist the result.

    Args:
        ctx: SAQ context dict (contains db_session_factory).
        scan_id: UUID string of the Scan record.
        report_type: One of csv_full, csv_violations, csv_inactive, csv_posture,
                     pdf, json.

    Returns:
        Dict with report_id and file_path.
    """
    scan_uuid = uuid.UUID(scan_id)
    session_factory = ctx["db_session_factory"]

    logger.info("report_generation_started", scan_id=scan_id, report_type=report_type)

    async with session_factory() as db_session:
        try:
            report_record = Report(
                id=uuid.uuid4(),
                scan_id=scan_uuid,
                report_type=ReportType(report_type),
            )

            file_path = await _generate_file_report(
                scan_uuid, db_session, report_type
            )
            report_record.file_path = file_path
            report_record.content = None

            db_session.add(report_record)
            await db_session.commit()

            logger.info(
                "report_generation_completed",
                scan_id=scan_id,
                report_type=report_type,
                report_id=str(report_record.id),
            )

            return {
                "report_id": str(report_record.id),
                "report_type": report_type,
                "file_path": report_record.file_path,
            }

        except Exception as exc:
            logger.error(
                "report_generation_failed",
                scan_id=scan_id,
                report_type=report_type,
                error=str(exc),
            )
            raise


async def _generate_file_report(
    scan_id: uuid.UUID,
    db_session: AsyncSession,
    report_type: str,
) -> str:
    """Generate a file-based report and return its path."""
    ext = _EXTENSIONS.get(report_type, "bin")
    output_dir = os.path.join(settings.reports_dir, str(scan_id))
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"{report_type}.{ext}")

    if report_type in ("csv_full", "csv_violations", "csv_inactive", "csv_posture"):
        from src.reports.csv_generator import generate_csv

        await generate_csv(scan_id, db_session, output_path, report_type=report_type)

    elif report_type == "pdf":
        from src.reports.pdf_generator import generate_pdf

        await generate_pdf(scan_id, db_session, output_path)

    elif report_type == "json":
        from src.reports.json_generator import generate_json

        await generate_json(scan_id, db_session, output_path)

    else:
        raise ValueError(f"Unsupported report type: {report_type}")

    return output_path
