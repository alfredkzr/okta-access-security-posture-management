from collections.abc import AsyncGenerator

from fastapi import Depends, HTTPException
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
