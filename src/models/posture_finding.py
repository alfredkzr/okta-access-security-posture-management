import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base
from src.models.vulnerability import Severity as FindingSeverity  # Re-export for backwards compat


class CheckCategory(str, enum.Enum):
    ADMIN_SECURITY = "admin_security"
    MFA_POSTURE = "mfa_posture"
    API_TOKEN_HYGIENE = "api_token_hygiene"
    APP_CONFIG = "app_config"
    NETWORK_ZONES = "network_zones"
    DEVICE_TRUST = "device_trust"
    IDP_CONFIG = "idp_config"
    SECURITY_EVENTS = "security_events"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class PostureFinding(Base):
    __tablename__ = "posture_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    check_category: Mapped[CheckCategory] = mapped_column(nullable=False)
    check_name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(nullable=False)
    status: Mapped[FindingStatus] = mapped_column(nullable=False, default=FindingStatus.OPEN)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    affected_resources: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    remediation_steps: Mapped[str] = mapped_column(Text, nullable=False)
    compliance_mappings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_detected: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_detected: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan", lazy="selectin")

    __table_args__ = (
        Index("ix_posture_findings_scan_id", "scan_id"),
        Index("ix_posture_findings_check_category", "check_category"),
        Index("ix_posture_findings_severity", "severity"),
        Index("ix_posture_findings_status", "status"),
        Index("ix_posture_findings_category_status", "check_category", "status"),
    )
