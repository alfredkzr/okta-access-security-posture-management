"""Scheduled job CRUD and execution history."""

import uuid
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, Query, Request
from saq import Queue
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.audit import log_audit
from src.api.dependencies import get_db
from src.api.errors import AppError
from src.config import settings
from src.models.job import Job
from src.models.scan import Scan, ScanStatus
from src.schemas.common import PaginatedResponse
from src.schemas.schedules import (
    ScanConfig,
    ScheduleCreate,
    ScheduleResponse,
    ScheduleUpdate,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/schedules", tags=["schedules"])


@router.get("/history", response_model=PaginatedResponse)
async def list_execution_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    count_stmt = select(func.count(Scan.id)).where(Scan.job_id.isnot(None))
    total = (await db.execute(count_stmt)).scalar() or 0

    offset = (page - 1) * page_size
    stmt = (
        select(Scan)
        .where(Scan.job_id.isnot(None))
        .order_by(Scan.started_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    items = []
    for s in result.scalars().all():
        items.append({
            "id": str(s.id),
            "job_id": str(s.job_id) if s.job_id else None,
            "job_name": s.job_name,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "status": s.status.value if hasattr(s.status, "value") else str(s.status),
            "total_users": s.total_users,
            "successful_users": s.successful_users,
            "failed_users": s.failed_users,
            "duration_seconds": s.duration_seconds,
            "error_message": s.error_message,
        })

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )


@router.get("", response_model=list[ScheduleResponse])
async def list_schedules(
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Job).order_by(Job.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=ScheduleResponse, status_code=201)
async def create_schedule(
    body: ScheduleCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Validate scan_config by constructing it (Pydantic validation)
    _ = body.scan_config

    job = Job(
        name=body.name,
        description=body.description or "",
        is_active=body.is_active,
        schedule_type=body.schedule_type,
        cron_expression=body.cron_expression,
        interval_seconds=body.interval_seconds,
        run_at=body.run_at,
        scan_config=body.scan_config.model_dump(),
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    actor = request.headers.get("X-Actor-Email", "system")
    ip = request.client.host if request.client else "unknown"
    await log_audit(
        db, actor, "schedule_created", "schedule", str(job.id),
        details={"name": job.name, "schedule_type": body.schedule_type},
        ip_address=ip,
    )

    return job


@router.put("/{job_id}", response_model=ScheduleResponse)
async def update_schedule(
    job_id: uuid.UUID,
    body: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Job).where(Job.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise AppError(code="NOT_FOUND", message="Scheduled job not found", status=404)

    update_data = body.model_dump(exclude_unset=True)
    if "scan_config" in update_data and update_data["scan_config"] is not None:
        update_data["scan_config"] = body.scan_config.model_dump()

    for key, value in update_data.items():
        setattr(job, key, value)
    await db.flush()
    await db.refresh(job)
    return job


@router.delete("/{job_id}", status_code=204)
async def delete_schedule(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Job).where(Job.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise AppError(code="NOT_FOUND", message="Scheduled job not found", status=404)
    await db.delete(job)
    await db.flush()


@router.post("/{job_id}/run-now", response_model=dict, status_code=201)
async def run_schedule_now(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Job).where(Job.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise AppError(code="NOT_FOUND", message="Scheduled job not found", status=404)

    # Create a scan record linked to this job
    scan = Scan(
        job_id=job.id,
        job_name=job.name,
        status=ScanStatus.PENDING,
        total_users=0,
    )
    db.add(scan)

    job.last_run_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(scan)

    # Commit before enqueuing so the worker can find the Scan record
    await db.commit()

    # Enqueue the scan to SAQ worker
    scan_config = job.scan_config or {}
    try:
        queue = Queue.from_url(settings.redis_url)
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
        logger.info("run_now_enqueued", job_id=str(job.id), scan_id=str(scan.id))
    except Exception as exc:
        logger.error("run_now_enqueue_failed", job_id=str(job.id), error=str(exc))
        scan.status = ScanStatus.FAILED
        scan.error_message = f"Failed to enqueue: {exc}"[:1000]

    return {"scan_id": str(scan.id), "message": "Scan enqueued"}
