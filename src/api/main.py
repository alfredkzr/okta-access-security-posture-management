import sqlalchemy as sa
import structlog
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from src.api.errors import AppError, app_error_handler, unhandled_error_handler, validation_error_handler
from src.api.middleware import RequestLoggingMiddleware
from src.api.routes import (
    assessments,
    auth,
    audit_logs,
    dashboard,
    notifications,
    posture_checks,
    reports,
    scenarios,
    schedules,
    settings as settings_routes,
    vulnerabilities,
)
from src.config import settings

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
)

app = FastAPI(
    title="Access Security Posture Management",
    description="Access Security Posture Management Platform",
    version="0.1.0",
)

# Middleware (order matters — outermost first)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)
app.add_middleware(RequestLoggingMiddleware)

# Exception handlers
app.add_exception_handler(AppError, app_error_handler)
app.add_exception_handler(RequestValidationError, validation_error_handler)
app.add_exception_handler(Exception, unhandled_error_handler)

# Register routers
app.include_router(auth.router)
app.include_router(scenarios.router)
app.include_router(vulnerabilities.router)
app.include_router(posture_checks.router)
app.include_router(assessments.router)
app.include_router(dashboard.router)
app.include_router(schedules.router)
app.include_router(notifications.router)
app.include_router(settings_routes.router)
app.include_router(audit_logs.router)
app.include_router(reports.router)


@app.on_event("startup")
async def on_startup():
    """Verify database connectivity on startup.

    Schema migrations are handled by Alembic (run `alembic upgrade head`
    before starting the application). See alembic/ directory.
    """
    from src.db import engine

    logger = structlog.get_logger("startup")
    async with engine.connect() as conn:
        await conn.execute(sa.text("SELECT 1"))
    logger.info("database_connected")


@app.get("/api/v1/health")
async def health():
    return {"status": "ok"}
