import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base, TimestampMixin


class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DevicePlatform(str, enum.Enum):
    WINDOWS = "WINDOWS"
    MACOS = "MACOS"
    CHROMEOS = "CHROMEOS"
    ANDROID = "ANDROID"
    IOS = "IOS"
    DESKTOP_OTHER = "DESKTOP_OTHER"
    MOBILE_OTHER = "MOBILE_OTHER"


class Scenario(TimestampMixin, Base):
    __tablename__ = "scenarios"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    risk_level: Mapped[RiskLevel | None] = mapped_column(nullable=True)
    device_platform: Mapped[DevicePlatform] = mapped_column(nullable=False)
    device_registered: Mapped[bool] = mapped_column(Boolean, nullable=False)
    device_managed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    device_assurance_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    zone_ids: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_scenarios_is_active", "is_active"),
        Index("ix_scenarios_risk_level", "risk_level"),
    )
