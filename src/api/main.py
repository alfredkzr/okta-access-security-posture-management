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
    title="Okta ASPM",
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
    """Create database tables if they don't exist."""
    from src.db import engine
    from src.models.base import Base
    import src.models  # noqa: F401

    import sqlalchemy as sa

    async with engine.begin() as conn:
        # Create tables first (handles fresh DB)
        await conn.run_sync(Base.metadata.create_all)

        # Migrations for existing databases — guarded so they're safe on fresh DBs
        # Add CLOSED to the vulnerabilitystatus enum if it doesn't exist yet
        await conn.execute(
            sa.text(
                "DO $$ BEGIN "
                "IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'vulnerabilitystatus') THEN "
                "IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'CLOSED' "
                "AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'vulnerabilitystatus')) THEN "
                "ALTER TYPE vulnerabilitystatus ADD VALUE 'CLOSED'; "
                "END IF; END IF; END $$;"
            )
        )
        # Make scenarios.risk_level nullable for existing tables
        await conn.execute(
            sa.text(
                "DO $$ BEGIN "
                "ALTER TABLE scenarios ALTER COLUMN risk_level DROP NOT NULL; "
                "EXCEPTION WHEN undefined_table THEN NULL; "
                "END $$;"
            )
        )
        # Add acknowledged_by column if it doesn't exist yet
        await conn.execute(
            sa.text(
                "DO $$ BEGIN "
                "ALTER TABLE vulnerabilities ADD COLUMN acknowledged_by VARCHAR(255); "
                "EXCEPTION WHEN duplicate_column THEN NULL; WHEN undefined_table THEN NULL; "
                "END $$;"
            )
        )
        # Migrate any existing REMEDIATED vulnerabilities to CLOSED
        await conn.execute(
            sa.text(
                "UPDATE vulnerabilities SET status = 'CLOSED' WHERE status = 'REMEDIATED'"
            )
        )


@app.get("/api/v1/health")
async def health():
    return {"status": "ok"}
