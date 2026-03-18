import uuid
from datetime import datetime

from pydantic import BaseModel


class NotificationChannelCreate(BaseModel):
    name: str
    channel_type: str = "webhook"
    config: dict  # {url, headers, secret}
    events: list[str]  # ["scan_completed", "new_vulnerabilities", ...]
    is_active: bool = True


class NotificationChannelUpdate(BaseModel):
    name: str | None = None
    config: dict | None = None
    events: list[str] | None = None
    is_active: bool | None = None


class NotificationChannelResponse(BaseModel):
    id: uuid.UUID
    name: str
    channel_type: str
    config: dict
    events: list[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
