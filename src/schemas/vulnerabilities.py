import uuid
from datetime import datetime

from pydantic import BaseModel


class VulnerabilityResponse(BaseModel):
    id: uuid.UUID
    title: str
    description: str
    category: str
    severity: str
    status: str
    risk_score: int
    risk_factors: dict | None = None
    compliance_mappings: dict | None = None
    policy_name: str | None = None
    policy_id: str | None = None
    rule_name: str | None = None
    rule_id: str | None = None
    app_name: str | None = None
    app_id: str | None = None
    active_impact_count: int
    first_detected: datetime
    last_detected: datetime
    remediated_at: datetime | None = None
    acknowledged_by: str | None = None

    model_config = {"from_attributes": True}


class VulnerabilityUpdateRequest(BaseModel):
    status: str  # ACTIVE, CLOSED, ACKNOWLEDGED


class VulnerabilityImpactResponse(BaseModel):
    id: uuid.UUID
    vulnerability_id: uuid.UUID
    scan_id: uuid.UUID
    user_id: str
    user_email: str
    user_name: str
    app_name: str | None = None
    app_id: str | None = None
    scenario_name: str | None = None
    status: str
    first_detected: datetime
    last_detected: datetime
    resolved_at: datetime | None = None

    model_config = {"from_attributes": True}


class VulnerabilityDetailResponse(VulnerabilityResponse):
    impacts: list[VulnerabilityImpactResponse] = []


class VulnerabilityStatsResponse(BaseModel):
    total: int
    active: int
    closed: int
    acknowledged: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
