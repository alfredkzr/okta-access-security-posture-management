"""Dashboard aggregated metrics and trend data."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Date, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, require_auth
from src.core.constants import SEVERITY_WEIGHTS
from src.models.assessment_result import AssessmentResult
from src.models.posture_finding import FindingSeverity, FindingStatus, PostureFinding
from src.models.scan import Scan, ScanStatus
from src.models.vulnerability import Vulnerability, VulnerabilityStatus
from src.schemas.dashboard import DashboardSummaryResponse, DashboardTrendsResponse, TrendDataPoint

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    # Combined vulnerability aggregation: status, severity, category in one query
    vuln_agg_stmt = select(
        Vulnerability.status,
        Vulnerability.severity,
        Vulnerability.category,
        func.count(Vulnerability.id).label("cnt"),
    ).group_by(Vulnerability.status, Vulnerability.severity, Vulnerability.category)
    vuln_agg_result = await db.execute(vuln_agg_stmt)

    status_counts: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for row in vuln_agg_result.all():
        s_val = str(row[0].value)
        sev_val = str(row[1].value)
        cat_val = str(row[2].value)
        cnt = row[3]
        status_counts[s_val] = status_counts.get(s_val, 0) + cnt
        by_severity[sev_val] = by_severity.get(sev_val, 0) + cnt
        by_category[cat_val] = by_category.get(cat_val, 0) + cnt

    total_vulns = sum(status_counts.values())
    active = status_counts.get("ACTIVE", 0)
    closed = status_counts.get("CLOSED", 0)
    acknowledged = status_counts.get("ACKNOWLEDGED", 0)

    # Posture findings count + score
    posture_stmt = select(
        PostureFinding.severity, func.count(PostureFinding.id)
    ).where(PostureFinding.status == FindingStatus.OPEN).group_by(PostureFinding.severity)
    posture_result = await db.execute(posture_stmt)
    deduction = 0
    for row in posture_result.all():
        deduction += SEVERITY_WEIGHTS.get(row[0], 0) * row[1]
    posture_score = max(0, 100 - deduction)

    total_posture = (await db.execute(select(func.count(PostureFinding.id)))).scalar() or 0

    # Users scanned — use the latest completed scan's successful_users count
    # (not distinct assessment_result rows, which misses users with zero apps)
    latest_scan_stmt = (
        select(Scan.successful_users)
        .where(Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS]))
        .order_by(Scan.started_at.desc())
        .limit(1)
    )
    users_scanned = (await db.execute(latest_scan_stmt)).scalar() or 0

    # Apps scanned
    apps_scanned_stmt = select(func.count(func.distinct(AssessmentResult.app_id)))
    apps_scanned = (await db.execute(apps_scanned_stmt)).scalar() or 0

    # New today
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    new_today_stmt = select(func.count(Vulnerability.id)).where(
        Vulnerability.first_detected >= today_start
    )
    new_today = (await db.execute(new_today_stmt)).scalar() or 0

    # Recent scans (last 10)
    recent_stmt = select(Scan).order_by(Scan.started_at.desc()).limit(10)
    recent_result = await db.execute(recent_stmt)
    recent_scans = []
    for s in recent_result.scalars().all():
        recent_scans.append({
            "id": str(s.id),
            "job_name": s.job_name,
            "status": s.status.value if hasattr(s.status, "value") else str(s.status),
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "total_users": s.total_users,
            "successful_users": s.successful_users,
            "failed_users": s.failed_users,
            "posture_findings_count": s.posture_findings_count,
            "progress_pct": s.progress_pct,
            "duration_seconds": s.duration_seconds,
            "error_message": s.error_message,
        })

    return DashboardSummaryResponse(
        total_vulnerabilities=total_vulns,
        active_vulnerabilities=active,
        closed_vulnerabilities=closed,
        acknowledged_vulnerabilities=acknowledged,
        by_severity=by_severity,
        by_category=by_category,
        total_posture_findings=total_posture,
        posture_score=posture_score,
        users_scanned=users_scanned,
        apps_scanned=apps_scanned,
        new_today=new_today,
        recent_scans=recent_scans,
        okta_health={"status": "unknown", "message": "Real-time health check not yet connected"},
    )


@router.get("/trends", response_model=DashboardTrendsResponse)
async def get_dashboard_trends(
    days: int = Query(30, ge=1, le=365),
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Active vulnerabilities by date (using first_detected)
    active_stmt = (
        select(
            cast(Vulnerability.first_detected, Date).label("date"),
            func.count(Vulnerability.id),
        )
        .where(
            Vulnerability.first_detected >= since,
            Vulnerability.status == VulnerabilityStatus.ACTIVE,
        )
        .group_by(cast(Vulnerability.first_detected, Date))
        .order_by(cast(Vulnerability.first_detected, Date))
    )
    active_result = await db.execute(active_stmt)
    active_by_date = {str(row[0]): row[1] for row in active_result.all()}

    # Remediated vulnerabilities by date (using remediated_at)
    remediated_stmt = (
        select(
            cast(Vulnerability.remediated_at, Date).label("date"),
            func.count(Vulnerability.id),
        )
        .where(
            Vulnerability.remediated_at >= since,
            Vulnerability.remediated_at.isnot(None),
        )
        .group_by(cast(Vulnerability.remediated_at, Date))
        .order_by(cast(Vulnerability.remediated_at, Date))
    )
    remediated_result = await db.execute(remediated_stmt)
    remediated_by_date = {str(row[0]): row[1] for row in remediated_result.all()}

    # Build data points for each day
    data = []
    for i in range(days):
        d = (since + timedelta(days=i)).date()
        ds = str(d)
        data.append(TrendDataPoint(
            date=ds,
            active=active_by_date.get(ds, 0),
            remediated=remediated_by_date.get(ds, 0),
        ))

    return DashboardTrendsResponse(data=data)
