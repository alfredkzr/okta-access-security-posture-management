import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class AccessDecision(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    NO_MATCH = "NO_MATCH"


class AssessmentResult(Base):
    __tablename__ = "assessment_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False)
    app_id: Mapped[str] = mapped_column(String(255), nullable=False)
    app_name: Mapped[str] = mapped_column(String(255), nullable=False)
    scenario_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scenarios.id", ondelete="SET NULL"),
        nullable=True,
    )
    scenario_name: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    policy_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rule_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    access_decision: Mapped[AccessDecision] = mapped_column(nullable=False)
    factor_mode: Mapped[str | None] = mapped_column(String(50), nullable=True)
    reauthenticate_in: Mapped[str | None] = mapped_column(String(50), nullable=True)
    phishing_resistant: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan", lazy="select")
    scenario = relationship("Scenario", lazy="select")

    __table_args__ = (
        Index("ix_assessment_results_scan_id", "scan_id"),
        Index("ix_assessment_results_user_email", "user_email"),
        Index("ix_assessment_results_app_id", "app_id"),
        Index("ix_assessment_results_access_decision", "access_decision"),
        Index("ix_assessment_results_scan_user", "scan_id", "user_id"),
        Index("ix_assessment_results_created_at", "created_at"),
        Index("ix_assessment_results_user_email_created_at", "user_email", "created_at"),
    )
