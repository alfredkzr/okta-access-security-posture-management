"""Vulnerability listing, detail, status update, and stats."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.audit import log_audit
from src.api.dependencies import get_db
from src.api.errors import AppError
from src.core import vulnerability_engine
from src.models.vulnerability import Severity, Vulnerability, VulnerabilityCategory, VulnerabilityStatus
from src.models.vulnerability_impact import ImpactStatus, VulnerabilityImpact
from src.schemas.common import PaginatedResponse
from src.schemas.vulnerabilities import (
    VulnerabilityDetailResponse,
    VulnerabilityImpactResponse,
    VulnerabilityResponse,
    VulnerabilityStatsResponse,
    VulnerabilityUpdateRequest,
)

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])


@router.get("/stats", response_model=VulnerabilityStatsResponse)
async def get_vulnerability_stats(
    db: AsyncSession = Depends(get_db),
):
    # Reconcile before computing stats
    await _auto_reconcile_all(db)

    # Total counts by status
    status_stmt = select(
        Vulnerability.status, func.count(Vulnerability.id)
    ).group_by(Vulnerability.status)
    status_result = await db.execute(status_stmt)
    status_counts = {str(row[0].value): row[1] for row in status_result.all()}

    # Counts by severity
    sev_stmt = select(
        Vulnerability.severity, func.count(Vulnerability.id)
    ).group_by(Vulnerability.severity)
    sev_result = await db.execute(sev_stmt)
    by_severity = {str(row[0].value): row[1] for row in sev_result.all()}

    # Counts by category
    cat_stmt = select(
        Vulnerability.category, func.count(Vulnerability.id)
    ).group_by(Vulnerability.category)
    cat_result = await db.execute(cat_stmt)
    by_category = {str(row[0].value): row[1] for row in cat_result.all()}

    total = sum(status_counts.values())

    return VulnerabilityStatsResponse(
        total=total,
        active=status_counts.get("ACTIVE", 0),
        remediated=status_counts.get("REMEDIATED", 0),
        acknowledged=status_counts.get("ACKNOWLEDGED", 0),
        by_severity=by_severity,
        by_category=by_category,
    )


@router.get("", response_model=PaginatedResponse)
async def list_vulnerabilities(
    status: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    risk_score_min: int | None = None,
    risk_score_max: int | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Vulnerability)
    count_stmt = select(func.count(Vulnerability.id))

    if status:
        stmt = stmt.where(Vulnerability.status == status)
        count_stmt = count_stmt.where(Vulnerability.status == status)
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity)
        count_stmt = count_stmt.where(Vulnerability.severity == severity)
    if category:
        stmt = stmt.where(Vulnerability.category == category)
        count_stmt = count_stmt.where(Vulnerability.category == category)
    if risk_score_min is not None:
        stmt = stmt.where(Vulnerability.risk_score >= risk_score_min)
        count_stmt = count_stmt.where(Vulnerability.risk_score >= risk_score_min)
    if risk_score_max is not None:
        stmt = stmt.where(Vulnerability.risk_score <= risk_score_max)
        count_stmt = count_stmt.where(Vulnerability.risk_score <= risk_score_max)

    # Auto-reconcile stale statuses before listing so counts and filters
    # are always accurate.
    await _auto_reconcile_all(db)

    total = (await db.execute(count_stmt)).scalar() or 0

    offset = (page - 1) * page_size
    stmt = stmt.order_by(Vulnerability.last_detected.desc()).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    items = [VulnerabilityResponse.model_validate(v) for v in result.scalars().all()]

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )


@router.post("/reconcile")
async def reconcile_vulnerability_statuses(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Reconcile all vulnerability statuses based on actual active impact counts.

    Marks ACTIVE vulnerabilities with zero active impacts as REMEDIATED,
    and REMEDIATED vulnerabilities with active impacts as ACTIVE.
    """
    result = await vulnerability_engine.reconcile_all_vulnerability_statuses(db)
    await db.commit()

    actor = request.headers.get("X-Actor-Email", "system")
    ip = request.client.host if request.client else "unknown"
    await log_audit(
        db, actor, "vulnerability_status_changed", "vulnerability", "all",
        details={"action": "reconcile", **result},
        ip_address=ip,
    )
    await db.commit()

    return result


@router.get("/{vuln_id}", response_model=VulnerabilityDetailResponse)
async def get_vulnerability(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(Vulnerability)
        .options(selectinload(Vulnerability.impacts))
        .where(Vulnerability.id == vuln_id)
    )
    result = await db.execute(stmt)
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise AppError(code="NOT_FOUND", message="Vulnerability not found", status=404)

    # Auto-reconcile: if all impacts are RESOLVED but vuln is still ACTIVE,
    # mark it REMEDIATED on the spot so the UI always reflects reality.
    await _auto_reconcile(db, vuln)

    return vuln


@router.patch("/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability_status(
    vuln_id: uuid.UUID,
    body: VulnerabilityUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    valid_statuses = {"ACTIVE", "REMEDIATED", "ACKNOWLEDGED"}
    if body.status not in valid_statuses:
        raise AppError(
            code="INVALID_STATUS",
            message=f"Status must be one of: {', '.join(valid_statuses)}",
            status=400,
        )

    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise AppError(code="NOT_FOUND", message="Vulnerability not found", status=404)

    old_status = vuln.status.value if hasattr(vuln.status, "value") else str(vuln.status)
    vuln.status = body.status
    if body.status == "REMEDIATED":
        vuln.remediated_at = datetime.now(timezone.utc)
    elif body.status == "ACTIVE":
        vuln.remediated_at = None

    actor = request.headers.get("X-Actor-Email", "system")
    ip = request.client.host if request.client else "unknown"
    await log_audit(
        db, actor, "vulnerability_status_changed", "vulnerability", str(vuln_id),
        details={"old_status": old_status, "new_status": body.status},
        ip_address=ip,
    )

    await db.flush()
    await db.refresh(vuln)
    return vuln


# ---------------------------------------------------------------------------
# Helpers: auto-reconcile vulnerability status from actual impact data
# ---------------------------------------------------------------------------


async def _auto_reconcile(db: AsyncSession, vuln: Vulnerability) -> None:
    """Reconcile a single vulnerability's status against its actual impacts.

    If all impacts are RESOLVED and the vuln is ACTIVE → set REMEDIATED.
    If any impact is ACTIVE and the vuln is REMEDIATED → set ACTIVE.
    """
    if vuln.status == VulnerabilityStatus.ACKNOWLEDGED:
        return  # User-acknowledged — don't auto-change

    active_count_stmt = (
        select(func.count(VulnerabilityImpact.id))
        .where(
            VulnerabilityImpact.vulnerability_id == vuln.id,
            VulnerabilityImpact.status == ImpactStatus.ACTIVE,
        )
    )
    active_count = (await db.execute(active_count_stmt)).scalar() or 0
    vuln.active_impact_count = active_count

    if active_count == 0 and vuln.status == VulnerabilityStatus.ACTIVE:
        vuln.status = VulnerabilityStatus.REMEDIATED
        vuln.remediated_at = datetime.now(timezone.utc)
        await db.flush()
    elif active_count > 0 and vuln.status == VulnerabilityStatus.REMEDIATED:
        vuln.status = VulnerabilityStatus.ACTIVE
        vuln.remediated_at = None
        await db.flush()


async def _auto_reconcile_all(db: AsyncSession) -> None:
    """Reconcile all ACTIVE vulnerabilities that have zero active impacts."""
    # Find ACTIVE vulns with no ACTIVE impacts via a LEFT JOIN + HAVING
    from sqlalchemy import literal_column

    subq = (
        select(
            Vulnerability.id,
            func.count(
                case(
                    (VulnerabilityImpact.status == ImpactStatus.ACTIVE, VulnerabilityImpact.id),
                )
            ).label("active_count"),
        )
        .outerjoin(VulnerabilityImpact, VulnerabilityImpact.vulnerability_id == Vulnerability.id)
        .where(Vulnerability.status == VulnerabilityStatus.ACTIVE)
        .group_by(Vulnerability.id)
        .having(
            func.count(
                case(
                    (VulnerabilityImpact.status == ImpactStatus.ACTIVE, VulnerabilityImpact.id),
                )
            ) == 0
        )
    ).subquery()

    stale_stmt = select(Vulnerability).where(Vulnerability.id.in_(select(subq.c.id)))
    result = await db.execute(stale_stmt)
    stale_vulns = result.scalars().all()

    if not stale_vulns:
        return

    now = datetime.now(timezone.utc)
    for vuln in stale_vulns:
        vuln.status = VulnerabilityStatus.REMEDIATED
        vuln.remediated_at = now
        vuln.active_impact_count = 0

    await db.flush()
