"""CRUD routes for risk scenarios."""

import uuid

import structlog
from fastapi import APIRouter, Body, Depends, Query, Request
from sqlalchemy import delete, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.audit import log_audit
from src.api.dependencies import get_db, require_admin, require_auth
from src.api.errors import AppError
from src.models.scenario import Scenario
from src.schemas.scenarios import ScenarioCreate, ScenarioResponse, ScenarioUpdate

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/scenarios", tags=["scenarios"])


@router.get("", response_model=list[ScenarioResponse])
async def list_scenarios(
    is_active: bool | None = None,
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Scenario).order_by(Scenario.created_at.desc())
    if is_active is not None:
        stmt = stmt.where(Scenario.is_active == is_active)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("", response_model=ScenarioResponse, status_code=201)
async def create_scenario(
    body: ScenarioCreate,
    request: Request,
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    scenario = Scenario(**body.model_dump())
    db.add(scenario)
    await db.flush()
    await db.refresh(scenario)

    actor = current_user.get("email", "unknown")
    ip = request.client.host if request.client else "unknown"
    await log_audit(
        db, actor, "scenario_created", "scenario", str(scenario.id),
        details={"name": scenario.name},
        ip_address=ip,
    )
    await db.commit()

    return scenario


@router.put("/{scenario_id}", response_model=ScenarioResponse)
async def update_scenario(
    scenario_id: uuid.UUID,
    body: ScenarioUpdate,
    request: Request,
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Scenario).where(Scenario.id == scenario_id))
    scenario = result.scalar_one_or_none()
    if not scenario:
        raise AppError(code="NOT_FOUND", message="Scenario not found", status=404)

    # Capture old values before update for sync
    old_name = scenario.name
    old_risk_level = scenario.risk_level.value if hasattr(scenario.risk_level, 'value') else str(scenario.risk_level)

    update_data = body.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(scenario, key, value)
    await db.flush()
    await db.refresh(scenario)

    new_risk_level = scenario.risk_level.value if hasattr(scenario.risk_level, 'value') else str(scenario.risk_level)
    new_name = scenario.name

    # If risk_level or name changed, recalculate affected vulnerability scores
    if new_risk_level != old_risk_level or new_name != old_name:
        from src.core.scenario_sync import recalculate_after_scenario_update
        updated_count = await recalculate_after_scenario_update(
            db_session=db,
            scenario_id=scenario_id,
            new_risk_level=new_risk_level,
            old_name=old_name if new_name != old_name else None,
            new_name=new_name if new_name != old_name else None,
        )
        logger.info(
            "scenario_update_synced_vulnerabilities",
            scenario_id=str(scenario_id),
            risk_level_change=f"{old_risk_level}->{new_risk_level}" if new_risk_level != old_risk_level else None,
            name_change=f"{old_name}->{new_name}" if new_name != old_name else None,
            vulnerabilities_updated=updated_count,
        )

    actor = current_user.get("email", "unknown")
    ip = request.client.host if request.client else "unknown"
    await log_audit(
        db, actor, "scenario_updated", "scenario", str(scenario_id),
        details={"updated_fields": list(update_data.keys())},
        ip_address=ip,
    )
    await db.commit()

    return scenario


@router.delete("/{scenario_id}", status_code=204)
async def delete_scenario(
    scenario_id: uuid.UUID,
    request: Request,
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Scenario).where(Scenario.id == scenario_id))
    scenario = result.scalar_one_or_none()
    if not scenario:
        raise AppError(code="NOT_FOUND", message="Scenario not found", status=404)

    scenario_name = scenario.name
    await db.delete(scenario)
    await db.flush()

    actor = current_user.get("email", "unknown")
    ip = request.client.host if request.client else "unknown"
    await log_audit(
        db, actor, "scenario_deleted", "scenario", str(scenario_id),
        details={"name": scenario_name},
        ip_address=ip,
    )
    await db.commit()


@router.post("/import", response_model=list[ScenarioResponse], status_code=201)
async def import_scenarios(
    scenarios: list[ScenarioCreate] = Body(...),
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    created = []
    for s in scenarios:
        scenario = Scenario(**s.model_dump())
        db.add(scenario)
        created.append(scenario)
    await db.flush()
    for s in created:
        await db.refresh(s)

    actor = current_user.get("email", "unknown")
    await log_audit(
        db, actor, "scenario_created", "scenario", "import",
        details={"count": len(created), "names": [s.name for s in created]},
        ip_address="unknown",
    )
    await db.commit()

    return created


@router.post("/reset", response_model=list[ScenarioResponse], status_code=201)
async def reset_scenarios(
    request: Request,
    current_user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Delete all existing scenarios and recreate the defaults."""
    from src.core.risk_scenarios import DEFAULT_SCENARIOS

    # Delete all existing scenarios
    await db.execute(delete(Scenario))

    # Create defaults
    created = []
    for rs in DEFAULT_SCENARIOS:
        scenario = Scenario(
            name=rs.name,
            description=rs.description,
            is_active=rs.is_active,
            risk_level=rs.risk_level,
            device_platform=rs.device_platform,
            device_registered=rs.device_registered,
            device_managed=rs.device_managed,
            device_assurance_id=rs.device_assurance_id,
            ip_address=rs.ip_address,
            zone_ids=rs.zone_ids or None,
        )
        db.add(scenario)
        created.append(scenario)

    await db.flush()
    for s in created:
        await db.refresh(s)

    actor = current_user.get("email", "unknown")
    ip = request.client.host if request.client else "unknown"
    await log_audit(
        db, actor, "scenario_updated", "scenario", "all",
        details={"action": "reset_to_defaults", "count": len(created)},
        ip_address=ip,
    )

    return created


@router.get("/export", response_model=list[ScenarioResponse])
async def export_scenarios(
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Scenario).order_by(Scenario.created_at))
    return result.scalars().all()
