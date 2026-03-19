import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class ReportType(str, enum.Enum):
    CSV_FULL = "csv_full"
    CSV_VIOLATIONS = "csv_violations"
    CSV_INACTIVE = "csv_inactive"
    CSV_POSTURE = "csv_posture"
    PDF = "pdf"
    JSON = "json"


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    report_type: Mapped[ReportType] = mapped_column(nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan", lazy="select")

    __table_args__ = (
        Index("ix_reports_scan_id", "scan_id"),
        Index("ix_reports_report_type", "report_type"),
    )
