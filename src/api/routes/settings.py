"""Tenant configuration, health check, and app criticality settings."""

import json
import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_okta_client, require_admin, require_auth
from src.api.errors import AppError
from src.config import settings
from src.core.okta_client import OktaClient
from src.schemas.settings import (
    AppCriticalityUpdate,
    HealthResponse,
    TenantConfigResponse,
    TenantConfigUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


@router.get("/tenant", response_model=TenantConfigResponse)
async def get_tenant_config(current_user: dict = Depends(require_auth)):
    token = settings.okta_api_token
    masked = ("****" + token[-4:]) if len(token) >= 4 else "****"
    return TenantConfigResponse(
        okta_org=settings.okta_org,
        okta_org_type=settings.okta_org_type,
        okta_api_token_masked=masked,
    )


@router.put("/tenant", response_model=TenantConfigResponse)
async def update_tenant_config(body: TenantConfigUpdate, current_user: dict = Depends(require_admin)):
    # Single-tenant mode: config comes from env vars.
    # Validate the payload but do not persist (env vars are read-only at runtime).
    return TenantConfigResponse(
        okta_org=body.okta_org or settings.okta_org,
        okta_org_type=body.okta_org_type or settings.okta_org_type,
        okta_api_token_masked="****" + (body.okta_api_token[-4:] if body.okta_api_token and len(body.okta_api_token) >= 4 else ""),
    )


@router.post("/tenant/test")
async def test_tenant_connection(
    current_user: dict = Depends(require_admin),
    okta_client: OktaClient = Depends(get_okta_client),
):
    try:
        org_info = await okta_client.get_org_info()
        return {"success": True, "org_info": org_info}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@router.get("/health", response_model=HealthResponse)
async def health_check(
    db: AsyncSession = Depends(get_db),
    okta_client: OktaClient = Depends(get_okta_client),
):
    # Check database
    db_status = "ok"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unhealthy"

    # Check Redis
    redis_status = "ok"
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.ping()
        await r.aclose()
    except Exception:
        redis_status = "unhealthy"

    # Check Okta
    okta_info = None
    try:
        org = await okta_client.get_org_info()
        okta_info = {"status": "ok", "org": org.get("name", settings.okta_org)}
    except Exception as exc:
        okta_info = {"status": "unhealthy", "error": str(exc)}

    overall = "ok"
    if db_status == "unhealthy" or redis_status == "unhealthy":
        overall = "degraded" if db_status == "ok" or redis_status == "ok" else "unhealthy"
    if okta_info and okta_info.get("status") == "unhealthy":
        overall = "degraded" if overall == "ok" else overall

    return HealthResponse(
        status=overall,
        database=db_status,
        redis=redis_status,
        okta=okta_info,
    )


@router.post("/reset", status_code=200)
async def reset_all_data(
    confirm: str = Query(..., description="Must be 'RESET' to confirm"),
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Delete ALL application data for a fresh start.

    Requires ``?confirm=RESET`` query parameter as a safety guard.
    Clears every table except alembic_version.  Scenarios are re-seeded
    with the built-in defaults after truncation.
    """
    if confirm != "RESET":
        raise AppError(
            code="VALIDATION_ERROR",
            message="Pass ?confirm=RESET to confirm the reset",
            status=400,
        )

    # Order matters: respect foreign-key constraints (children first).
    # Use ORM delete to avoid SQL injection risk from dynamic table names.
    from src.models.vulnerability_impact import VulnerabilityImpact
    from src.models.assessment_result import AssessmentResult
    from src.models.posture_finding import PostureFinding
    from src.models.report import Report
    from src.models.vulnerability import Vulnerability
    from src.models.scan import Scan
    from src.models.job import Job
    from src.models.notification_channel import NotificationChannel
    from src.models.scenario import Scenario
    from sqlalchemy import delete

    # AuditLog is intentionally excluded — it is append-only with no retention limit.
    tables_to_clear = [
        VulnerabilityImpact, AssessmentResult, PostureFinding, Report,
        Vulnerability, Scan, Job, NotificationChannel, Scenario,
    ]
    for model in tables_to_clear:
        await db.execute(delete(model))
    await db.commit()
    tables = [m.__tablename__ for m in tables_to_clear]

    # Re-seed default scenarios
    try:
        from src.core.risk_scenarios import DEFAULT_SCENARIOS
        from src.models.scenario import Scenario as ScenarioModel

        for s in DEFAULT_SCENARIOS:
            db.add(ScenarioModel(
                name=s.name,
                description=s.description,
                is_active=s.is_active,
                risk_level=s.risk_level.value if hasattr(s.risk_level, 'value') else s.risk_level,
                device_platform=s.device_platform.value if hasattr(s.device_platform, 'value') else s.device_platform,
                device_registered=s.device_registered,
                device_managed=s.device_managed,
                device_assurance_id=s.device_assurance_id,
                ip_address=s.ip_address,
                zone_ids=s.zone_ids if s.zone_ids else None,
            ))
        await db.commit()
        scenarios_seeded = len(DEFAULT_SCENARIOS)
    except Exception as exc:
        logger.error("scenario_seed_failed", exc_info=exc)
        scenarios_seeded = 0

    # Flush Redis ephemeral data
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.flushdb()
        await r.aclose()
    except Exception:
        pass

    logger.warning("full_application_reset_performed")
    return {
        "message": "All data has been reset",
        "tables_cleared": tables,
        "scenarios_seeded": scenarios_seeded,
    }


@router.put("/app-criticality")
async def update_app_criticality(body: AppCriticalityUpdate, current_user: dict = Depends(require_admin)):
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.set("aspm:app_criticality", json.dumps(body.app_criticality))
        await r.aclose()
        return {"message": "App criticality updated", "count": len(body.app_criticality)}
    except Exception as exc:
        raise AppError(
            code="REDIS_ERROR",
            message=f"Failed to store app criticality: {exc}",
            status=500,
        )
