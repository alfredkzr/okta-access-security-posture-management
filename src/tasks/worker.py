"""SAQ worker configuration.

Run with: saq src.tasks.worker.settings
"""

from __future__ import annotations

import structlog
from saq import CronJob, Queue

from src.config import settings as app_settings

logger = structlog.get_logger(__name__)


async def startup(ctx: dict) -> None:
    """Initialize resources when the worker starts."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    engine = create_async_engine(
        app_settings.database_url,
        pool_size=10,
        max_overflow=5,
        pool_pre_ping=True,
        pool_recycle=3600,
    )
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    ctx["db_engine"] = engine
    ctx["db_session_factory"] = session_factory

    logger.info("worker_started", database=app_settings.database_url.split("@")[-1])


async def shutdown(ctx: dict) -> None:
    """Clean up resources when the worker stops."""
    engine = ctx.get("db_engine")
    if engine:
        await engine.dispose()
    logger.info("worker_stopped")


# Import task functions
from src.tasks.tenant_scan import run_tenant_scan  # noqa: E402
from src.tasks.report_generation import generate_report_task  # noqa: E402
from src.tasks.data_retention import cleanup_old_data  # noqa: E402
from src.tasks.health_monitor import check_okta_health  # noqa: E402
from src.tasks.scheduler import check_scheduled_jobs  # noqa: E402

settings = {
    "queue": Queue.from_url(app_settings.redis_url),
    "functions": [run_tenant_scan, generate_report_task],
    "cron_jobs": [
        CronJob(cleanup_old_data, cron="0 3 * * *"),
        CronJob(check_okta_health, cron="*/5 * * * *"),
        CronJob(check_scheduled_jobs, cron="* * * * *"),
    ],
    "startup": startup,
    "shutdown": shutdown,
    "concurrency": 10,
}
