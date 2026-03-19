import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.audit import log_audit
from src.api.dependencies import get_db, require_admin, require_auth
from src.api.errors import AppError
from src.config import settings
from src.db import async_session
from src.models.report import Report
from src.models.scan import Scan
from src.schemas.reports import ReportGenerateRequest, ReportResponse

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


async def _generate_report_background(report_id: uuid.UUID, scan_id: uuid.UUID, report_type: str):
    """Generate the report file in the background."""
    import structlog
    logger = structlog.get_logger("report_gen")

    try:
        async with async_session() as db:
            report = await db.get(Report, report_id)
            if not report:
                return

            output_dir = Path(settings.reports_dir) / str(scan_id)
            os.makedirs(output_dir, exist_ok=True)

            try:
                if report_type in ("csv_full", "csv_violations", "csv_inactive"):
                    from src.reports.csv_generator import generate_csv
                    ext = "csv"
                    output_path = str(output_dir / f"{report_type}.{ext}")
                    await generate_csv(scan_id, db, output_path, report_type)
                    report.file_path = output_path

                elif report_type == "json":
                    from src.reports.json_generator import generate_json
                    output_path = str(output_dir / "report.json")
                    await generate_json(scan_id, db, output_path)
                    report.file_path = output_path

                elif report_type == "pdf":
                    from src.reports.pdf_generator import generate_pdf
                    output_path = str(output_dir / "report.pdf")
                    await generate_pdf(scan_id, db, output_path)
                    report.file_path = output_path

                else:
                    report.content = f"Unsupported report type: {report_type}"

                report.generated_at = datetime.now(timezone.utc)
                logger.info("report_generated", report_id=str(report_id), report_type=report_type)

            except Exception as exc:
                report.content = f"Report generation failed: {exc}"
                logger.error("report_generation_failed", report_id=str(report_id), error=str(exc))

            await db.commit()

    except Exception as exc:
        import structlog
        structlog.get_logger("report_gen").exception("report_gen_crash", error=str(exc))


@router.post("", status_code=201, response_model=ReportResponse)
async def generate_report(
    body: ReportGenerateRequest,
    background_tasks: BackgroundTasks,
    http_request: Request,
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(Scan, body.scan_id)
    if not scan:
        raise AppError("NOT_FOUND", "Scan not found", status=404)

    report = Report(
        scan_id=body.scan_id,
        report_type=body.report_type,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    actor = current_user.get("email", "unknown")
    ip = http_request.client.host if http_request.client else "unknown"
    await log_audit(
        db, actor, "report_generated", "report", str(report.id),
        details={"scan_id": str(body.scan_id), "report_type": body.report_type},
        ip_address=ip,
    )

    await db.commit()

    # Generate the actual report in background
    background_tasks.add_task(
        _generate_report_background, report.id, body.scan_id, body.report_type
    )

    return report


@router.get("", response_model=list[ReportResponse])
async def list_reports(
    scan_id: uuid.UUID | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    query = select(Report).order_by(Report.created_at.desc())
    if scan_id:
        query = query.where(Report.scan_id == scan_id)
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    report = await db.get(Report, report_id)
    if not report:
        raise AppError("NOT_FOUND", "Report not found", status=404)

    if report.content:
        return {"content": report.content, "report_type": report.report_type}

    if report.file_path:
        reports_base = Path(settings.reports_dir).resolve()
        path = Path(report.file_path).resolve()
        # Prevent path traversal — file must be within the reports directory
        if not path.is_relative_to(reports_base):
            raise AppError("FORBIDDEN", "Invalid report path", status=403)
        if not path.exists():
            raise AppError("NOT_FOUND", "Report file not found on disk", status=404)
        media_type = {
            "csv_full": "text/csv",
            "csv_violations": "text/csv",
            "csv_inactive": "text/csv",
            "pdf": "application/pdf",
            "json": "application/json",
        }.get(report.report_type, "application/octet-stream")
        return FileResponse(path, media_type=media_type, filename=path.name)

    raise AppError("NOT_FOUND", "Report is still being generated. Please try again in a moment.", status=404)
