from collections.abc import AsyncGenerator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.core.okta_client import OktaClient
from src.db import get_session


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_session():
        yield session


def get_okta_client() -> OktaClient:
    return OktaClient(
        base_url=settings.okta_base_url,
        api_token=settings.okta_api_token,
        max_workers=settings.max_workers,
    )


def require_auth(request: Request) -> dict:
    """Dependency that requires a valid authenticated session.

    Returns the user dict from the signed session cookie.
    Raises 401 if not authenticated.
    """
    from src.api.routes.auth import get_current_user

    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail={
            "error": {"code": "UNAUTHORIZED", "message": "Authentication required"}
        })
    return user


def require_admin(user: dict = Depends(require_auth)) -> dict:
    """Alias for require_auth — RBAC removed, all authenticated users have full access."""
    return user
