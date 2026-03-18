"""Audit logging utility for recording actions to the audit_logs table."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.models.audit_log import AuditLog


async def log_audit(
    db_session: AsyncSession,
    actor_email: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any] | None = None,
    ip_address: str = "unknown",
) -> None:
    """Write an immutable audit log entry.

    This is best-effort: callers should handle exceptions if they want
    to avoid blocking the primary operation.
    """
    entry = AuditLog(
        actor_email=actor_email,
        actor_role="admin",  # TODO: derive from auth context
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id),
        details=details,
        ip_address=ip_address,
    )
    db_session.add(entry)
