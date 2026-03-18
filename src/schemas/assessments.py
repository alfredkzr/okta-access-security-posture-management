import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


class SingleAssessmentRequest(BaseModel):
    email: str


class BatchAssessmentRequest(BaseModel):
    user_selection: str = "all"  # all, limited, specific
    max_users: int | None = None
    specific_users: list[str] | None = None
    include_deactivated: bool = False
    include_posture_checks: bool = True
    max_workers: int = 5
    api_delay: float = 0
    generate_ai_summary: bool = False
    resume_scan_id: uuid.UUID | None = None


class ScanSummaryResponse(BaseModel):
    id: uuid.UUID
    job_id: uuid.UUID | None = None
    job_name: str | None = None
    started_at: datetime
    completed_at: datetime | None = None
    status: str
    total_users: int
    successful_users: int
    failed_users: int
    failed_user_details: list[dict] | None = None
    posture_findings_count: int
    last_processed_user_index: int = 0
    progress_pct: float | None = None
    duration_seconds: float | None = None
    error_message: str | None = None

    model_config = {"from_attributes": True}


class AssessmentResultResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    user_id: str
    user_email: str
    app_id: str
    app_name: str
    scenario_name: str
    policy_name: str | None = None
    rule_name: str | None = None
    access_decision: str
    factor_mode: str | None = None
    phishing_resistant: bool | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
