"""Notification channel CRUD and test endpoint."""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, require_auth
from src.api.errors import AppError
from src.models.notification_channel import NotificationChannel
from src.schemas.notifications import (
    NotificationChannelCreate,
    NotificationChannelResponse,
    NotificationChannelUpdate,
)

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])


@router.get("/channels", response_model=list[NotificationChannelResponse])
async def list_channels(
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(NotificationChannel).order_by(NotificationChannel.created_at.desc())
    )
    channels = result.scalars().all()
    return [NotificationChannelResponse.from_model(ch) for ch in channels]


@router.post("/channels", response_model=NotificationChannelResponse, status_code=201)
async def create_channel(
    body: NotificationChannelCreate,
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    channel = NotificationChannel(
        name=body.name,
        channel_type=body.channel_type,
        config=body.to_config(),
        events=body.events,
        is_active=body.is_active,
    )
    db.add(channel)
    await db.flush()
    await db.refresh(channel)
    return NotificationChannelResponse.from_model(channel)


@router.put("/channels/{channel_id}", response_model=NotificationChannelResponse)
async def update_channel(
    channel_id: uuid.UUID,
    body: NotificationChannelUpdate,
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(NotificationChannel).where(NotificationChannel.id == channel_id)
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise AppError(code="NOT_FOUND", message="Notification channel not found", status=404)

    if body.name is not None:
        channel.name = body.name
    if body.events is not None:
        channel.events = body.events
    if body.is_active is not None:
        channel.is_active = body.is_active

    new_config = body.to_config(channel.config)
    if new_config is not None:
        channel.config = new_config

    await db.flush()
    await db.refresh(channel)
    return NotificationChannelResponse.from_model(channel)


@router.delete("/channels/{channel_id}", status_code=204)
async def delete_channel(
    channel_id: uuid.UUID,
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(NotificationChannel).where(NotificationChannel.id == channel_id)
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise AppError(code="NOT_FOUND", message="Notification channel not found", status=404)
    await db.delete(channel)
    await db.flush()


@router.post("/channels/{channel_id}/test")
async def test_channel(
    channel_id: uuid.UUID,
    current_user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    from src.core.notifier import dispatch_test

    result = await db.execute(
        select(NotificationChannel).where(NotificationChannel.id == channel_id)
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise AppError(code="NOT_FOUND", message="Notification channel not found", status=404)

    return await dispatch_test(channel)
