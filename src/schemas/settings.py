from pydantic import BaseModel


class TenantConfigResponse(BaseModel):
    okta_org: str
    okta_org_type: str
    okta_api_token_masked: str  # e.g. "****abcd"


class TenantConfigUpdate(BaseModel):
    okta_org: str | None = None
    okta_org_type: str | None = None
    okta_api_token: str | None = None


class HealthResponse(BaseModel):
    status: str  # ok, degraded, unhealthy
    database: str
    redis: str
    okta: dict | None = None  # {status, rate_limit_remaining_pct, checked_at}


class AppCriticalityUpdate(BaseModel):
    app_criticality: dict[str, str]  # {app_id: "critical"|"high"|"medium"|"low"}
