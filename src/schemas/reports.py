import uuid
from datetime import datetime

from pydantic import BaseModel


class ReportGenerateRequest(BaseModel):
    scan_id: uuid.UUID
    report_type: str  # csv_full, csv_violations, csv_inactive, csv_posture, pdf, json, ai_summary


class ReportResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    report_type: str
    file_path: str | None = None
    content: str | None = None
    generated_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}
