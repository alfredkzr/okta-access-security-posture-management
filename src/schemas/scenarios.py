import uuid
from enum import Enum
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, field_validator


# Okta policy simulation only supports LOW, MEDIUM, HIGH
OktaRiskLevel = Literal["LOW", "MEDIUM", "HIGH"]


class ScenarioCreate(BaseModel):
    name: str
    description: str = ""
    is_active: bool = True
    risk_level: OktaRiskLevel  # Okta risk signal: LOW, MEDIUM, HIGH
    device_platform: str  # WINDOWS, MACOS, etc.
    device_registered: bool = False
    device_managed: bool = False
    device_assurance_id: str | None = None
    ip_address: str | None = None
    zone_ids: list[str] | None = None


class ScenarioUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    is_active: bool | None = None
    risk_level: OktaRiskLevel | None = None
    device_platform: str | None = None
    device_registered: bool | None = None
    device_managed: bool | None = None
    device_assurance_id: str | None = None
    ip_address: str | None = None
    zone_ids: list[str] | None = None


class ScenarioResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None = None
    is_active: bool
    risk_level: str
    device_platform: str
    device_registered: bool
    device_managed: bool | None = None
    device_assurance_id: str | None = None
    ip_address: str | None = None
    zone_ids: list[str] | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
