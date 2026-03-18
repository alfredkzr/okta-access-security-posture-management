from pydantic import BaseModel


class DashboardSummaryResponse(BaseModel):
    total_vulnerabilities: int
    active_vulnerabilities: int
    remediated_vulnerabilities: int
    acknowledged_vulnerabilities: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    total_posture_findings: int
    posture_score: int
    users_scanned: int
    apps_scanned: int
    new_today: int
    recent_scans: list[dict]
    okta_health: dict | None = None


class TrendDataPoint(BaseModel):
    date: str
    active: int
    remediated: int
    risk_score_avg: float | None = None


class DashboardTrendsResponse(BaseModel):
    data: list[TrendDataPoint]
