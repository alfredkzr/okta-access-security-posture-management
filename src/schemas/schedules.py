import uuid
from datetime import datetime

from pydantic import BaseModel


class ScanConfig(BaseModel):
    user_selection: str = "all"
    max_users: int | None = None
    specific_users: list[str] | None = None
    include_deactivated: bool = False
    include_posture_checks: bool = True
    max_workers: int = 10
    api_delay: float = 0
    save_individual_reports: bool = False
    generate_ai_summary: bool = False


class ScheduleCreate(BaseModel):
    name: str
    description: str | None = ""
    is_active: bool = True
    schedule_type: str  # cron, interval, once
    cron_expression: str | None = None
    interval_seconds: int | None = None
    run_at: datetime | None = None
    scan_config: ScanConfig = ScanConfig()


class ScheduleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    is_active: bool | None = None
    schedule_type: str | None = None
    cron_expression: str | None = None
    interval_seconds: int | None = None
    run_at: datetime | None = None
    scan_config: ScanConfig | None = None


class ScheduleResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None = None
    is_active: bool
    schedule_type: str
    cron_expression: str | None = None
    interval_seconds: int | None = None
    run_at: datetime | None = None
    scan_config: dict
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
