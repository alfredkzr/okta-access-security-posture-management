import uuid
from datetime import datetime

from pydantic import BaseModel


class PostureFindingResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    check_category: str
    check_name: str
    severity: str
    status: str
    title: str
    description: str
    affected_resources: list[dict] | None = None
    remediation_steps: str | None = None
    compliance_mappings: dict | None = None
    risk_score: int
    first_detected: datetime
    last_detected: datetime
    resolved_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class PostureFindingUpdate(BaseModel):
    status: str  # OPEN, RESOLVED, ACKNOWLEDGED, FALSE_POSITIVE


class PostureScoreResponse(BaseModel):
    score: int  # 0-100 aggregate
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
