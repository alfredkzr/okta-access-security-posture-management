"""Assessment engine — orchestrates single-user and batch assessments."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.constants import extract_app_name, extract_user_email, requires_mfa
from src.core.log_analyzer import analyze_logs, is_inactive
from src.core.okta_client import OktaClient
from src.core.policy_simulator import PolicySimulator
from src.core.risk_scorer import RiskInput, calculate_risk_score
from src.core import vulnerability_engine
from src.core.vulnerability_engine import determine_policy_violation_severity
from src.models.assessment_result import AccessDecision, AssessmentResult
from src.models.scan import Scan, ScanStatus

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data structures for carrying results between fetch and persist phases
# ---------------------------------------------------------------------------

@dataclass
class _SimData:
    """Results of a single policy simulation (one app × one scenario)."""
    app: dict
    scenario_id: uuid.UUID | None
    scenario_name: str
    scenario_risk_level: str | None
    sim_result: Any  # SimulationResult
    rule_action: Any | None = None  # RuleAction
    access_decision: str = "NO_MATCH"
    factor_mode: str | None = None
    reauthenticate_in: str | None = None
    phishing_resistant: bool | None = None


@dataclass
class _LogData:
    """Results of log analysis for one app."""
    app: dict
    is_inactive: bool = False
    error: str | None = None


@dataclass
class _UserData:
    """All Okta API results for a single user (no DB operations)."""
    email: str
    user: dict | None = None
    apps: list[dict] = field(default_factory=list)
    sims: list[_SimData] = field(default_factory=list)
    logs: list[_LogData] = field(default_factory=list)
    error: str | None = None
    skipped: bool = False


# ---------------------------------------------------------------------------
# Phase 1: Okta API calls only (no DB) — safe to run concurrently
# ---------------------------------------------------------------------------

async def _fetch_user_data(
    email: str,
    okta_client: OktaClient,
    scenarios: list[Any],
) -> _UserData:
    """Fetch all Okta data for a single user. No database operations."""
    data = _UserData(email=email)

    user = await okta_client.get_user_by_login(email)
    if user is None:
        data.error = f"User not found: {email}"
        return data
    data.user = user
    user_id = user["id"]
    user_email = user.get("profile", {}).get("email", email)

    logger.info("assessment_started", user_email=user_email, user_id=user_id)

    all_apps = await okta_client.get_user_apps(user_id)
    # Filter to only apps the user is actually assigned to (the Okta API
    # returns all active apps with expand=user/{id}; unassigned users have
    # _embedded.user.status != "ACTIVE" or no _embedded.user at all)
    apps = [
        app for app in all_apps
        if app.get("_embedded", {}).get("user", {}).get("id") == user_id
    ]
    data.apps = apps
    logger.info("user_apps_fetched", user_email=user_email, app_count=len(apps), total_tenant_apps=len(all_apps))

    simulator = PolicySimulator(okta_client)

    # Simulate policies for each app × scenario
    for app in apps:
        app_id = app.get("id", "")

        for scenario in scenarios:
            scenario_name = getattr(scenario, "name", "unknown")
            scenario_id = getattr(scenario, "id", None)
            scenario_risk_level = getattr(scenario, "risk_level", None)

            sim_result = await simulator.simulate(user_id, app_id, scenario)

            if sim_result.error:
                logger.warning(
                    "simulation_error",
                    user_email=user_email,
                    app_id=app_id,
                    scenario=scenario_name,
                    error=sim_result.error,
                )

            sd = _SimData(
                app=app,
                scenario_id=scenario_id,
                scenario_name=scenario_name,
                scenario_risk_level=scenario_risk_level,
                sim_result=sim_result,
            )

            if sim_result.matched and sim_result.policy_id and sim_result.rule_id:
                try:
                    rule_action = await simulator.get_rule_action(
                        sim_result.policy_id, sim_result.rule_id,
                        policy_name=sim_result.policy_name,
                    )
                    sd.rule_action = rule_action
                    sd.access_decision = rule_action.access
                    sd.factor_mode = rule_action.factor_mode
                    sd.reauthenticate_in = rule_action.reauthenticate_in
                    sd.phishing_resistant = rule_action.phishing_resistant
                except Exception as exc:
                    logger.warning(
                        "get_rule_action_failed",
                        policy_id=sim_result.policy_id,
                        rule_id=sim_result.rule_id,
                        error=str(exc),
                    )

            data.sims.append(sd)

    # Fetch and analyze logs for each app
    for app in apps:
        app_id = app.get("id", "")
        try:
            logs = await okta_client.get_user_app_logs(user_id, app_id)
            pattern = analyze_logs(logs)
            data.logs.append(_LogData(app=app, is_inactive=is_inactive(pattern)))
        except Exception as exc:
            logger.warning(
                "log_analysis_failed",
                user_email=user_email,
                app_id=app_id,
                error=str(exc),
            )
            data.logs.append(_LogData(app=app, error=str(exc)))

    return data


# ---------------------------------------------------------------------------
# Phase 2: DB writes only (no API calls) — runs sequentially on one session
# ---------------------------------------------------------------------------

async def _persist_user_data(
    data: _UserData,
    db_session: AsyncSession,
    scan_id: uuid.UUID,
) -> dict[str, Any]:
    """Persist all assessment results and vulnerabilities for one user."""
    user = data.user
    assert user is not None

    user_id = user["id"]
    user_email = extract_user_email(user) or data.email

    # Pre-scan: resolve existing impacts for this user, scoped to scenarios being tested
    scenario_names = list({sd.scenario_name for sd in data.sims})
    pre_scan_vuln_ids = await vulnerability_engine.pre_scan_resolve_impacts(
        db_session, user_email, scenario_names=scenario_names if scenario_names else None,
    )
    vulnerability_ids: set[uuid.UUID] = set(pre_scan_vuln_ids)
    violations_found = 0
    new_violations_found = 0
    inactive_apps = 0
    new_violation_sims: list[_SimData] = []  # only truly new vulns for notification

    # Persist simulation results
    for sd in data.sims:
        access_decision = AccessDecision.NO_MATCH
        if sd.access_decision in ("ALLOW", "DENY"):
            access_decision = AccessDecision(sd.access_decision)

        app_id = sd.app.get("id", "")
        app_name = extract_app_name(sd.app)

        assessment = AssessmentResult(
            id=uuid.uuid4(),
            scan_id=scan_id,
            user_id=user_id,
            user_email=user_email,
            app_id=app_id,
            app_name=app_name,
            scenario_id=sd.scenario_id,
            scenario_name=sd.scenario_name,
            policy_id=sd.sim_result.policy_id,
            policy_name=sd.sim_result.policy_name,
            rule_id=sd.sim_result.rule_id,
            rule_name=sd.sim_result.rule_name,
            access_decision=access_decision,
            factor_mode=sd.factor_mode,
            reauthenticate_in=sd.reauthenticate_in,
            phishing_resistant=sd.phishing_resistant,
        )
        db_session.add(assessment)

        # Record vulnerability if access is ALLOW
        if access_decision == AccessDecision.ALLOW and sd.rule_action is not None:
            severity = determine_policy_violation_severity(
                sd.factor_mode, sd.phishing_resistant,
            )
            risk_input = RiskInput(
                severity=severity.value,
                scenario_risk_level=sd.scenario_risk_level,
                affected_user_count=1,
                requires_mfa=requires_mfa(sd.factor_mode),
                phishing_resistant=sd.phishing_resistant,
            )
            risk_score = calculate_risk_score(risk_input)

            vuln, _impact, is_new = await vulnerability_engine.record_policy_violation(
                db_session=db_session,
                scan_id=scan_id,
                user=user,
                app=sd.app,
                scenario_name=sd.scenario_name,
                rule_action=sd.rule_action,
                risk_score=risk_score,
                scenario_risk_level=sd.scenario_risk_level,
            )
            vulnerability_ids.add(vuln.id)
            violations_found += 1
            if is_new:
                new_violations_found += 1
                new_violation_sims.append(sd)

    # Persist inactive app user findings
    for ld in data.logs:
        if ld.is_inactive:
            risk_input = RiskInput(
                severity="MEDIUM",
                affected_user_count=1,
            )
            risk_score = calculate_risk_score(risk_input)

            vuln, _impact, _is_new = await vulnerability_engine.record_inactive_app_user(
                db_session=db_session,
                scan_id=scan_id,
                user=user,
                app=ld.app,
                risk_score=risk_score,
            )
            vulnerability_ids.add(vuln.id)
            inactive_apps += 1

    # Post-scan: update vulnerability impact counts
    if vulnerability_ids:
        await vulnerability_engine.post_scan_update_counts(
            db_session, list(vulnerability_ids)
        )

    await db_session.flush()

    # Fire notification only for NEWLY CREATED vulnerabilities (not re-detections
    # of existing ones). This prevents duplicate webhook noise on every re-scan.
    if new_violations_found > 0:
        try:
            from src.core.notifier import dispatch as notify

            vuln_details = []
            max_risk_score = 0
            for sd in new_violation_sims:
                sev = determine_policy_violation_severity(
                    sd.factor_mode, sd.phishing_resistant,
                ).value
                app_name = extract_app_name(sd.app)
                risk_input = RiskInput(
                    severity=sev,
                    scenario_risk_level=sd.scenario_risk_level,
                    affected_user_count=1,
                    requires_mfa=requires_mfa(sd.factor_mode),
                    phishing_resistant=sd.phishing_resistant,
                )
                score = calculate_risk_score(risk_input)
                max_risk_score = max(max_risk_score, score)
                vuln_details.append({
                    "title": f"Policy allows access: {app_name}",
                    "severity": sev,
                    "app_name": app_name,
                    "rule_name": sd.sim_result.rule_name,
                    "scenario_name": sd.scenario_name,
                    "risk_score": score,
                })

            async def _fire_new_vuln_notification():
                from src.db import async_session
                async with async_session() as session:
                    await notify("new_vulnerabilities", {
                        "scan_id": str(scan_id),
                        "user_email": user_email,
                        "count": new_violations_found,
                        "max_risk_score": max_risk_score,
                        "vulnerabilities": vuln_details,
                    }, session)

            asyncio.create_task(_fire_new_vuln_notification())
        except Exception:
            logger.debug("vuln_notification_failed", user_email=user_email)

    summary = {
        "user_email": user_email,
        "apps_scanned": len(data.apps),
        "violations_found": violations_found,
        "inactive_apps": inactive_apps,
    }
    logger.info("assessment_completed", **summary)
    return summary


# ---------------------------------------------------------------------------
# Single-user assessment (used by the single-user API endpoint)
# ---------------------------------------------------------------------------

async def assess_single_user(
    email: str,
    db_session: AsyncSession,
    okta_client: OktaClient,
    scenarios: list[Any],
    scan_id: uuid.UUID,
) -> dict[str, Any]:
    """Run a full assessment for a single user.

    Steps:
    1. Resolve user by email via okta_client.get_user_by_login()
    2. Fetch user's apps via okta_client.get_user_apps()
    3. For each app x each active scenario: simulate policy + record results
    4. For each app: fetch system logs, analyze for inactivity
    5. Return summary dict

    Args:
        email: User's email/login to assess.
        db_session: Async SQLAlchemy session.
        okta_client: Configured OktaClient instance.
        scenarios: List of scenario objects (ORM models or dicts with scenario attributes).
        scan_id: UUID of the current scan.

    Returns:
        Summary dict with user_email, apps_scanned, violations_found, inactive_apps.

    Raises:
        ValueError: If user cannot be found.
    """
    data = await _fetch_user_data(email, okta_client, scenarios)
    if data.error or data.user is None:
        raise ValueError(data.error or f"User not found: {email}")
    return await _persist_user_data(data, db_session, scan_id)


# ---------------------------------------------------------------------------
# Batch scan — concurrent fetch, sequential persist
# ---------------------------------------------------------------------------

async def run_batch_scan(
    scan_id: uuid.UUID,
    user_list: list[str],
    scenarios: list[Any],
    db_session: AsyncSession,
    okta_client: OktaClient,
    max_workers: int = 5,
    api_delay: float = 0,
    redis_client: Any | None = None,
    saq_job: Any | None = None,
    session_factory: Any | None = None,
) -> dict[str, Any]:
    """Run batch assessment for multiple users.

    Users are assessed concurrently (up to max_workers at a time) for the
    Okta API fetch phase.  DB writes use a fresh session per user to avoid
    asyncpg "another operation is in progress" errors.

    Args:
        scan_id: UUID of the scan record.
        user_list: List of user emails to assess.
        scenarios: Active scenarios to test against.
        db_session: Async SQLAlchemy session (used for scan progress only).
        okta_client: Configured OktaClient instance.
        max_workers: Max concurrent user assessments.
        api_delay: Delay in seconds between starting user assessments.
        redis_client: Optional Redis client for pub/sub progress updates.
        saq_job: Optional SAQ job for heartbeat updates.
        session_factory: Async session factory for creating per-user sessions.

    Returns:
        Scan summary dict.
    """
    # If no session_factory provided (e.g. tests), fall back to a context
    # manager that just yields the existing db_session.
    if session_factory is None:
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _fallback_factory():
            yield db_session

        session_factory = _fallback_factory

    total_users = len(user_list)

    # Update scan record to running
    scan_stmt = select(Scan).where(Scan.id == scan_id)
    scan_result = await db_session.execute(scan_stmt)
    scan = scan_result.scalar_one_or_none()

    if scan is None:
        raise ValueError(f"Scan not found: {scan_id}")

    scan.status = ScanStatus.RUNNING
    scan.total_users = total_users
    scan.started_at = datetime.now(timezone.utc)
    # Commit immediately so the frontend can see RUNNING status
    await db_session.commit()

    successful_users = 0
    failed_users = 0
    failed_user_details: list[dict[str, str]] = []
    processed_count = 0

    # Pre-filter: check for users recently scanned by another concurrent scan
    users_to_scan: list[str] = []
    for email in user_list:
        if await _has_recent_assessment(db_session, email, scan_id):
            logger.info("skipping_user_recent_scan", user_email=email)
            successful_users += 1
            processed_count += 1
            await _update_progress(
                db_session, scan, processed_count, total_users, redis_client, scan_id, saq_job,
                successful_users=successful_users, failed_users=failed_users,
                failed_user_details=failed_user_details,
            )
            await db_session.commit()
        else:
            users_to_scan.append(email)

    # --- Concurrent fetch, sequential persist via asyncio.Queue ---
    sem = asyncio.Semaphore(max_workers)
    queue: asyncio.Queue[_UserData] = asyncio.Queue()
    fetch_started = 0

    async def _fetch_worker(email: str) -> None:
        """Fetch one user's data from Okta (runs concurrently)."""
        async with sem:
            if api_delay > 0 and fetch_started > 0:
                await asyncio.sleep(api_delay)
            try:
                user_data = await _fetch_user_data(email, okta_client, scenarios)
                await queue.put(user_data)
            except Exception as exc:
                err_data = _UserData(email=email, error=str(exc))
                await queue.put(err_data)

    # Launch all fetch tasks
    tasks = []
    for email in users_to_scan:
        fetch_started += 1
        tasks.append(asyncio.create_task(_fetch_worker(email)))

    # Consume results as they arrive — each user gets a fresh DB session to
    # prevent asyncpg "another operation is in progress" errors that occur
    # when a single session's connection is shared across awaits.
    for _ in range(len(users_to_scan)):
        user_data = await queue.get()

        if user_data.error or user_data.user is None:
            failed_users += 1
            failed_user_details.append({
                "email": user_data.email,
                "error": user_data.error or "Unknown error",
            })
            logger.error(
                "batch_user_failed",
                user_email=user_data.email,
                error=user_data.error,
            )
        else:
            try:
                # Use a fresh session per user to isolate DB operations.
                # This prevents concurrent asyncpg operations when background
                # tasks (notifications) or eager relationship loading issue
                # queries on the same connection.
                async with session_factory() as user_session:
                    await _persist_user_data(user_data, user_session, scan_id)
                    await user_session.commit()
                successful_users += 1
            except Exception as exc:
                failed_users += 1
                failed_user_details.append({
                    "email": user_data.email,
                    "error": str(exc),
                })
                logger.error(
                    "batch_user_persist_failed",
                    user_email=user_data.email,
                    error=str(exc),
                )

        processed_count += 1
        await _update_progress(
            db_session, scan, processed_count, total_users, redis_client, scan_id, saq_job,
            successful_users=successful_users, failed_users=failed_users,
            failed_user_details=failed_user_details,
        )
        # Commit scan progress so frontend can see updates
        await db_session.commit()

    # Wait for all fetch tasks to complete (they should be done already since
    # we consumed all queue items, but this ensures clean task cleanup)
    await asyncio.gather(*tasks, return_exceptions=True)

    # Global reconciliation: sweep ALL vulnerabilities and fix any stale statuses.
    # Use a fresh session to avoid sharing the scan-progress session.
    async with session_factory() as recon_session:
        await vulnerability_engine.reconcile_all_vulnerability_statuses(recon_session)
        await recon_session.commit()

    # Finalize scan record
    now = datetime.now(timezone.utc)
    scan.completed_at = now
    scan.successful_users = successful_users
    scan.failed_users = failed_users
    scan.failed_user_details = failed_user_details if failed_user_details else None
    scan.last_processed_user_index = total_users
    scan.progress_pct = 100.0

    if scan.started_at:
        scan.duration_seconds = (now - scan.started_at).total_seconds()

    if failed_users == 0:
        scan.status = ScanStatus.COMPLETED
    elif successful_users == 0:
        scan.status = ScanStatus.FAILED
    else:
        scan.status = ScanStatus.COMPLETED_WITH_ERRORS

    await db_session.flush()

    summary = {
        "scan_id": str(scan_id),
        "status": scan.status.value,
        "total_users": total_users,
        "successful_users": successful_users,
        "failed_users": failed_users,
        "failed_user_details": failed_user_details,
        "duration_seconds": scan.duration_seconds,
    }
    logger.info("batch_scan_completed", **summary)

    # Fire notification (best-effort) — uses its own session throughout
    try:
        from src.core.notifier import dispatch as notify
        from src.models.vulnerability import Vulnerability, VulnerabilityStatus
        from src.models.posture_finding import PostureFinding, FindingStatus
        from sqlalchemy import func as sa_func

        async with session_factory() as notif_session:
            # Query vulnerability counts
            vuln_stmt = (
                select(
                    sa_func.count().label("total"),
                    sa_func.count().filter(Vulnerability.severity.in_(["CRITICAL"])).label("critical"),
                    sa_func.count().filter(Vulnerability.severity.in_(["HIGH"])).label("high"),
                )
                .where(Vulnerability.status == VulnerabilityStatus.ACTIVE)
            )
            vuln_row = (await notif_session.execute(vuln_stmt)).one()

            # Query posture findings count for this scan
            posture_stmt = (
                select(sa_func.count())
                .where(PostureFinding.scan_id == scan_id)
                .where(PostureFinding.status == FindingStatus.OPEN)
            )
            posture_count = (await notif_session.execute(posture_stmt)).scalar() or 0

            await notify("scan_completed", {
                "scan_id": str(scan_id),
                "job_name": scan.job_name,
                "status": scan.status.value,
                "total_users": total_users,
                "successful_users": successful_users,
                "failed_users": failed_users,
                "duration_seconds": scan.duration_seconds,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "vulnerabilities_found": vuln_row.total,
                "critical_count": vuln_row.critical,
                "high_count": vuln_row.high,
                "posture_findings_count": posture_count,
            }, notif_session)
    except Exception:
        logger.debug("batch_scan_notification_failed", scan_id=str(scan_id))

    return summary


async def _has_recent_assessment(
    db_session: AsyncSession,
    user_email: str,
    current_scan_id: uuid.UUID,
    window_minutes: int = 10,
) -> bool:
    """Check if another running scan has recent assessment results for this user.

    Returns True if another scan (not the current one) has created assessment
    results for this user_email within the last `window_minutes` minutes.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    stmt = (
        select(AssessmentResult.id)
        .where(
            AssessmentResult.user_email == user_email,
            AssessmentResult.scan_id != current_scan_id,
            AssessmentResult.created_at >= cutoff,
        )
        .limit(1)
    )
    result = await db_session.execute(stmt)
    return result.scalar_one_or_none() is not None


async def _update_progress(
    db_session: AsyncSession,
    scan: Scan,
    processed: int,
    total: int,
    redis_client: Any | None,
    scan_id: uuid.UUID,
    saq_job: Any | None = None,
    successful_users: int = 0,
    failed_users: int = 0,
    failed_user_details: list[dict[str, str]] | None = None,
) -> None:
    """Update scan progress in DB and optionally publish to Redis."""
    pct = round((processed / total) * 100, 1) if total > 0 else 0.0
    scan.last_processed_user_index = processed
    scan.progress_pct = pct
    scan.successful_users = successful_users
    scan.failed_users = failed_users
    scan.failed_user_details = failed_user_details if failed_user_details else None

    # Publish to Redis pub/sub if available
    if redis_client is not None:
        try:
            channel = f"scan:{scan_id}:progress"
            await redis_client.publish(
                channel,
                f'{{"processed": {processed}, "total": {total}, "pct": {pct}, "successful": {successful_users}, "failed": {failed_users}}}',
            )
        except Exception as exc:
            logger.debug("redis_publish_failed", error=str(exc))

    # Update SAQ job heartbeat to prevent timeout cancellation
    if saq_job is not None and total > 0:
        try:
            await saq_job.update(progress=10 + (pct * 0.9))
        except Exception:
            pass
