"""Notification channel CRUD and test endpoint."""

import uuid

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db
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
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(NotificationChannel).order_by(NotificationChannel.created_at.desc())
    )
    return result.scalars().all()


@router.post("/channels", response_model=NotificationChannelResponse, status_code=201)
async def create_channel(
    body: NotificationChannelCreate,
    db: AsyncSession = Depends(get_db),
):
    channel = NotificationChannel(
        name=body.name,
        channel_type=body.channel_type,
        config=body.config,
        events=body.events,
        is_active=body.is_active,
    )
    db.add(channel)
    await db.flush()
    await db.refresh(channel)
    return channel


@router.put("/channels/{channel_id}", response_model=NotificationChannelResponse)
async def update_channel(
    channel_id: uuid.UUID,
    body: NotificationChannelUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(NotificationChannel).where(NotificationChannel.id == channel_id)
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise AppError(code="NOT_FOUND", message="Notification channel not found", status=404)

    update_data = body.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(channel, key, value)
    await db.flush()
    await db.refresh(channel)
    return channel


@router.delete("/channels/{channel_id}", status_code=204)
async def delete_channel(
    channel_id: uuid.UUID,
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
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(NotificationChannel).where(NotificationChannel.id == channel_id)
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise AppError(code="NOT_FOUND", message="Notification channel not found", status=404)

    url = channel.config.get("url")
    if not url:
        raise AppError(
            code="INVALID_CONFIG",
            message="Channel config is missing 'url'",
            status=400,
        )

    test_payload = {
        "event": "test",
        "message": "Test notification from Okta ASPM",
        "channel_id": str(channel.id),
        "channel_name": channel.name,
    }

    headers = channel.config.get("headers", {})
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=test_payload, headers=headers)
        return {
            "success": resp.status_code < 400,
            "status_code": resp.status_code,
            "message": "Test notification sent",
        }
    except httpx.RequestError as exc:
        return {
            "success": False,
            "status_code": None,
            "message": f"Failed to send test notification: {exc}",
        }
