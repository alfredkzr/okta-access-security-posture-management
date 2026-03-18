"""Assessment (scan) management routes."""

import asyncio
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.audit import log_audit
from src.api.dependencies import get_db, get_okta_client
from src.api.errors import AppError
from src.config import settings
from src.core.okta_client import OktaClient
from src.db import async_session
from src.models.assessment_result import AssessmentResult
from src.models.posture_finding import PostureFinding
from src.models.scan import Scan, ScanStatus
from src.models.scenario import Scenario
from src.schemas.assessments import (
    AssessmentResultResponse,
    BatchAssessmentRequest,
    ScanSummaryResponse,
    SingleAssessmentRequest,
)
from src.schemas.common import PaginatedResponse
from src.schemas.posture import PostureFindingResponse

router = APIRouter(prefix="/api/v1/assessments", tags=["assessments"])


async def _run_single_scan_background(scan_id: uuid.UUID, email: str):
    """Run a single-user scan in the background with its own DB session."""
    import structlog
    logger = structlog.get_logger("background_scan")

    okta = OktaClient(
        base_url=settings.okta_base_url,
        api_token=settings.okta_api_token,
        max_workers=settings.max_workers,
    )
    try:
        from src.core.assessment_engine import assess_single_user

        async with async_session() as db:
            # Load scenarios
            result = await db.execute(select(Scenario).where(Scenario.is_active == True))  # noqa: E712
            scenarios = result.scalars().all()

            # Load the scan record
            scan = await db.get(Scan, scan_id)
            if not scan:
                logger.error("background_scan.scan_not_found", scan_id=str(scan_id))
                return

            try:
                logger.info("background_scan.started", scan_id=str(scan_id), email=email)
                await assess_single_user(
                    email=email,
                    db_session=db,
                    okta_client=okta,
                    scenarios=scenarios,
                    scan_id=scan.id,
                )
                scan.status = ScanStatus.COMPLETED
                scan.successful_users = 1
                logger.info("background_scan.completed", scan_id=str(scan_id))
            except Exception as exc:
                scan.status = ScanStatus.FAILED
                scan.failed_users = 1
                scan.error_message = str(exc)[:1000]
                logger.error("background_scan.failed", scan_id=str(scan_id), error=str(exc))

            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = (scan.completed_at - scan.started_at).total_seconds()
            scan.progress_pct = 100.0

            await db.commit()

        # Fire notification (best-effort, separate session)
        try:
            from src.core.notifier import dispatch as notify
            async with async_session() as notify_db:
                await notify("scan_completed", {
                    "scan_id": str(scan_id),
                    "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
                    "total_users": 1,
                    "duration_seconds": scan.duration_seconds,
                }, notify_db)
        except Exception:
            pass  # Notifications are best-effort

    except Exception as exc:
        # Last resort: if everything fails, still try to mark the scan as failed
        logger.exception("background_scan.crash", scan_id=str(scan_id), error=str(exc))
        try:
            async with async_session() as db:
                scan = await db.get(Scan, scan_id)
                if scan and scan.status == ScanStatus.RUNNING:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = f"Background task crashed: {exc}"[:1000]
                    scan.completed_at = datetime.now(timezone.utc)
                    scan.progress_pct = 100.0
                    await db.commit()
        except Exception:
            logger.exception("background_scan.crash_recovery_failed", scan_id=str(scan_id))
    finally:
        await okta.close()


@router.post("/single", response_model=ScanSummaryResponse, status_code=201)
async def run_single_assessment(
    body: SingleAssessmentRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Create and commit the scan record before starting background work
    scan = Scan(
        job_name=f"Single: {body.email}",
        status=ScanStatus.RUNNING,
        total_users=1,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Audit log
    actor = request.headers.get("X-Actor-Email", "system")
    ip = request.client.host if request.client else "unknown"
    await log_audit(
        db, actor, "scan_started", "scan", str(scan.id),
        details={"email": body.email, "type": "single"},
        ip_address=ip,
    )

    await db.commit()

    # Run the actual scan in the background — returns immediately
    background_tasks.add_task(_run_single_scan_background, scan.id, body.email)

    return scan


@router.post("/batch", response_model=ScanSummaryResponse, status_code=201)
async def run_batch_assessment(
    body: BatchAssessmentRequest,
    db: AsyncSession = Depends(get_db),
):
    scan = Scan(
        job_name="Batch scan",
        status=ScanStatus.PENDING,
        total_users=body.max_users or 0,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Commit before enqueuing so the worker can find the Scan record
    await db.commit()

    # Enqueue the scan as a background task via SAQ
    try:
        from saq import Queue

        queue = Queue.from_url(settings.redis_url)
        try:
            await queue.connect()
            await queue.enqueue(
                "run_tenant_scan",
                scan_id=str(scan.id),
                scan_config={
                    "user_selection": body.user_selection,
                    "max_users": body.max_users,
                    "specific_users": body.specific_users,
                    "include_deactivated": body.include_deactivated,
                    "include_posture_checks": body.include_posture_checks,
                    "max_workers": body.max_workers,
                    "api_delay": body.api_delay,
                    "generate_ai_summary": body.generate_ai_summary,
                },
                timeout=0,
                heartbeat=600,
                retries=0,
            )
        finally:
            await queue.disconnect()
    except Exception as exc:
        import structlog
        structlog.get_logger(__name__).warning(
            "batch_scan_enqueue_failed",
            scan_id=str(scan.id),
            error=str(exc),
        )

    return scan


@router.get("/{scan_id}", response_model=ScanSummaryResponse)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise AppError(code="NOT_FOUND", message="Scan not found", status=404)
    return scan


@router.get("/{scan_id}/results", response_model=PaginatedResponse)
async def get_scan_results(
    scan_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not scan_result.scalar_one_or_none():
        raise AppError(code="NOT_FOUND", message="Scan not found", status=404)

    count_stmt = select(func.count(AssessmentResult.id)).where(
        AssessmentResult.scan_id == scan_id
    )
    total = (await db.execute(count_stmt)).scalar() or 0

    offset = (page - 1) * page_size
    stmt = (
        select(AssessmentResult)
        .where(AssessmentResult.scan_id == scan_id)
        .order_by(AssessmentResult.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    items = [AssessmentResultResponse.model_validate(r) for r in result.scalars().all()]

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )


@router.get("/{scan_id}/posture", response_model=PaginatedResponse)
async def get_scan_posture(
    scan_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not scan_result.scalar_one_or_none():
        raise AppError(code="NOT_FOUND", message="Scan not found", status=404)

    count_stmt = select(func.count(PostureFinding.id)).where(
        PostureFinding.scan_id == scan_id
    )
    total = (await db.execute(count_stmt)).scalar() or 0

    offset = (page - 1) * page_size
    stmt = (
        select(PostureFinding)
        .where(PostureFinding.scan_id == scan_id)
        .order_by(PostureFinding.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    items = [PostureFindingResponse.model_validate(f) for f in result.scalars().all()]

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )


@router.get("/{scan_id}/stream")
async def stream_scan_progress(scan_id: uuid.UUID):
    """SSE endpoint that polls scan status until complete."""

    async def event_generator():
        while True:
            async with async_session() as db:
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if not scan:
                    yield f'data: {{"error": "Scan not found"}}\n\n'
                    return

                yield f'data: {{"status": "{scan.status.value}", "progress_pct": {scan.progress_pct or 0}, "successful_users": {scan.successful_users}, "total_users": {scan.total_users}}}\n\n'

                if scan.status in (ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS, ScanStatus.FAILED):
                    return

            await asyncio.sleep(2)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


@router.get("", response_model=PaginatedResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    count_stmt = select(func.count(Scan.id))
    total = (await db.execute(count_stmt)).scalar() or 0

    offset = (page - 1) * page_size
    stmt = (
        select(Scan)
        .order_by(Scan.started_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    items = [ScanSummaryResponse.model_validate(s) for s in result.scalars().all()]

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )
