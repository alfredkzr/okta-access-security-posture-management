import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    job_name: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[ScanStatus] = mapped_column(nullable=False, default=ScanStatus.PENDING)
    total_users: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    successful_users: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_users: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_user_details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    posture_findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_processed_user_index: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    progress_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_scans_status", "status"),
        Index("ix_scans_started_at", "started_at"),
        Index("ix_scans_job_id", "job_id"),
    )
