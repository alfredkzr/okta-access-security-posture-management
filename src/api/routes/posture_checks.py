"""Posture findings: list, detail, status update, aggregate score."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, require_admin, require_auth
from src.api.errors import AppError
from src.core.constants import SEVERITY_WEIGHTS
from src.models.posture_finding import FindingSeverity, FindingStatus, PostureFinding
from src.schemas.common import PaginatedResponse
from src.schemas.posture import PostureFindingResponse, PostureFindingUpdate, PostureScoreResponse

router = APIRouter(prefix="/api/v1/posture", tags=["posture"])


@router.get("/findings", response_model=PaginatedResponse)
async def list_findings(
    check_category: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    scan_id: uuid.UUID | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(PostureFinding)
    count_stmt = select(func.count(PostureFinding.id))

    if check_category:
        stmt = stmt.where(PostureFinding.check_category == check_category)
        count_stmt = count_stmt.where(PostureFinding.check_category == check_category)
    if severity:
        stmt = stmt.where(PostureFinding.severity == severity)
        count_stmt = count_stmt.where(PostureFinding.severity == severity)
    if status:
        stmt = stmt.where(PostureFinding.status == status)
        count_stmt = count_stmt.where(PostureFinding.status == status)
    if scan_id:
        stmt = stmt.where(PostureFinding.scan_id == scan_id)
        count_stmt = count_stmt.where(PostureFinding.scan_id == scan_id)

    total = (await db.execute(count_stmt)).scalar() or 0

    offset = (page - 1) * page_size
    stmt = stmt.order_by(PostureFinding.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    items = [PostureFindingResponse.model_validate(f) for f in result.scalars().all()]

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )


@router.get("/score", response_model=PostureScoreResponse)
async def get_posture_score(
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    # Only count OPEN findings for the score
    stmt = select(
        PostureFinding.severity, func.count(PostureFinding.id)
    ).where(
        PostureFinding.status == FindingStatus.OPEN,
    ).group_by(PostureFinding.severity)

    result = await db.execute(stmt)
    severity_counts: dict[str, int] = {}
    total_deduction = 0
    for row in result.all():
        sev = row[0]
        count = row[1]
        severity_counts[sev.value] = count
        total_deduction += SEVERITY_WEIGHTS.get(sev, 0) * count

    score = max(0, 100 - total_deduction)

    # Total findings across all statuses
    total_stmt = select(func.count(PostureFinding.id))
    total_findings = (await db.execute(total_stmt)).scalar() or 0

    return PostureScoreResponse(
        score=score,
        total_findings=total_findings,
        critical=severity_counts.get("CRITICAL", 0),
        high=severity_counts.get("HIGH", 0),
        medium=severity_counts.get("MEDIUM", 0),
        low=severity_counts.get("LOW", 0),
    )


@router.get("/findings/{finding_id}", response_model=PostureFindingResponse)
async def get_finding(
    finding_id: uuid.UUID,
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(PostureFinding).where(PostureFinding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise AppError(code="NOT_FOUND", message="Posture finding not found", status=404)
    return finding


@router.patch("/findings/{finding_id}", response_model=PostureFindingResponse)
async def update_finding_status(
    finding_id: uuid.UUID,
    body: PostureFindingUpdate,
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    valid_statuses = {"OPEN", "RESOLVED", "ACKNOWLEDGED", "FALSE_POSITIVE"}
    if body.status not in valid_statuses:
        raise AppError(
            code="INVALID_STATUS",
            message=f"Status must be one of: {', '.join(valid_statuses)}",
            status=400,
        )

    result = await db.execute(
        select(PostureFinding).where(PostureFinding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise AppError(code="NOT_FOUND", message="Posture finding not found", status=404)

    finding.status = body.status
    if body.status == "RESOLVED":
        finding.resolved_at = datetime.now(timezone.utc)
    elif body.status == "OPEN":
        finding.resolved_at = None

    await db.flush()
    await db.refresh(finding)
    await db.commit()
    return finding
