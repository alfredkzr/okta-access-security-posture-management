"""Recalculate vulnerability risk scores when a scenario changes."""

from __future__ import annotations

import uuid

import structlog
from sqlalchemy import distinct, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.risk_scorer import RiskInput, calculate_risk_score
from src.models.assessment_result import AccessDecision, AssessmentResult
from src.models.vulnerability import Vulnerability, VulnerabilityCategory, VulnerabilityStatus
from src.models.vulnerability_impact import ImpactStatus, VulnerabilityImpact

logger = structlog.get_logger(__name__)


async def recalculate_after_scenario_update(
    db_session: AsyncSession,
    scenario_id: uuid.UUID,
    new_risk_level: str,
    old_name: str | None = None,
    new_name: str | None = None,
) -> int:
    """Recalculate risk scores for all vulnerabilities linked to a scenario.

    Finds vulnerabilities via two paths:
    1. assessment_results with this scenario_id + access_decision=ALLOW → rule_id → vulnerability
    2. vulnerability_impacts with matching scenario_name → vulnerability

    For each affected vulnerability, recalculates the composite risk score
    using the scenario's new risk_level.

    Also updates scenario_name on impacts if the name changed.

    Returns:
        Number of vulnerabilities updated.
    """
    updated_count = 0

    # --- Path 1: Find affected rule_ids via assessment_results ---
    rule_stmt = (
        select(distinct(AssessmentResult.rule_id))
        .where(
            AssessmentResult.scenario_id == scenario_id,
            AssessmentResult.access_decision == AccessDecision.ALLOW,
            AssessmentResult.rule_id.isnot(None),
        )
    )
    rule_result = await db_session.execute(rule_stmt)
    rule_ids = [r[0] for r in rule_result.all()]

    # Find the vulnerabilities for those rule_ids
    affected_vuln_ids: set[uuid.UUID] = set()

    if rule_ids:
        vuln_stmt = select(Vulnerability).where(
            Vulnerability.rule_id.in_(rule_ids),
            Vulnerability.category == VulnerabilityCategory.AUTH_POLICY_VIOLATION,
            Vulnerability.status.in_([VulnerabilityStatus.ACTIVE, VulnerabilityStatus.ACKNOWLEDGED]),
        )
        vuln_result = await db_session.execute(vuln_stmt)
        for vuln in vuln_result.scalars().all():
            affected_vuln_ids.add(vuln.id)

    # --- Path 2: Find via impact scenario_name (fallback for older data) ---
    names_to_search = set()
    if old_name:
        names_to_search.add(old_name)
    if new_name:
        names_to_search.add(new_name)

    if names_to_search:
        impact_stmt = (
            select(distinct(VulnerabilityImpact.vulnerability_id))
            .where(
                VulnerabilityImpact.scenario_name.in_(names_to_search),
                VulnerabilityImpact.status == ImpactStatus.ACTIVE,
            )
        )
        impact_result = await db_session.execute(impact_stmt)
        for row in impact_result.all():
            affected_vuln_ids.add(row[0])

    if not affected_vuln_ids:
        logger.info("scenario_sync_no_vulns", scenario_id=str(scenario_id))
        return 0

    # --- Recalculate each vulnerability's risk score ---
    for vuln_id in affected_vuln_ids:
        vuln_stmt = select(Vulnerability).where(Vulnerability.id == vuln_id)
        vuln_result = await db_session.execute(vuln_stmt)
        vuln = vuln_result.scalar_one_or_none()
        if vuln is None:
            continue

        # Count active impacts for exposure breadth
        from sqlalchemy import func as sa_func
        impact_count_stmt = (
            select(sa_func.count(VulnerabilityImpact.user_email.distinct()))
            .where(
                VulnerabilityImpact.vulnerability_id == vuln_id,
                VulnerabilityImpact.status == ImpactStatus.ACTIVE,
            )
        )
        impact_result = await db_session.execute(impact_count_stmt)
        active_count = impact_result.scalar() or 0

        # Look at the latest assessment result for this vulnerability's rule
        # to get auth strength info
        requires_mfa = None
        phishing_resistant = None
        if vuln.rule_id:
            ar_stmt = (
                select(AssessmentResult)
                .where(
                    AssessmentResult.rule_id == vuln.rule_id,
                    AssessmentResult.access_decision == AccessDecision.ALLOW,
                )
                .order_by(AssessmentResult.created_at.desc())
                .limit(1)
            )
            ar_result = await db_session.execute(ar_stmt)
            ar = ar_result.scalar_one_or_none()
            if ar:
                requires_mfa = ar.factor_mode is not None and ar.factor_mode != ""
                phishing_resistant = ar.phishing_resistant

        old_score = vuln.risk_score
        new_score = calculate_risk_score(RiskInput(
            severity=vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
            scenario_risk_level=new_risk_level,
            affected_user_count=active_count,
            requires_mfa=requires_mfa,
            phishing_resistant=phishing_resistant,
        ))

        vuln.risk_score = new_score

        # Update risk_factors to reflect new scenario info
        rf = dict(vuln.risk_factors) if vuln.risk_factors else {}
        if new_name and rf.get("scenario") in (old_name, new_name):
            rf["scenario"] = new_name
        rf["scenario_risk_level"] = new_risk_level
        vuln.risk_factors = rf

        updated_count += 1
        logger.info(
            "vulnerability_risk_recalculated",
            vuln_id=str(vuln_id),
            old_score=old_score,
            new_score=new_score,
            scenario_risk_level=new_risk_level,
        )

    # --- Update scenario_name on impacts if name changed ---
    if old_name and new_name and old_name != new_name:
        from sqlalchemy import update
        rename_stmt = (
            update(VulnerabilityImpact)
            .where(VulnerabilityImpact.scenario_name == old_name)
            .values(scenario_name=new_name)
        )
        await db_session.execute(rename_stmt)

        # Also update assessment_results scenario_name
        ar_rename = (
            update(AssessmentResult)
            .where(
                AssessmentResult.scenario_id == scenario_id,
                AssessmentResult.scenario_name == old_name,
            )
            .values(scenario_name=new_name)
        )
        await db_session.execute(ar_rename)

        logger.info("scenario_name_synced", old_name=old_name, new_name=new_name)

    await db_session.flush()

    logger.info(
        "scenario_sync_complete",
        scenario_id=str(scenario_id),
        vulnerabilities_updated=updated_count,
        new_risk_level=new_risk_level,
    )
    return updated_count
