from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Okta API (scanning target)
    okta_api_token: str = ""
    okta_org: str = ""
    okta_org_type: str = "okta"

    # Okta Auth (app login)
    okta_client_id: str = ""
    okta_client_secret: str = ""
    okta_issuer: str = ""
    okta_admin_group: str = "ASPM_Admins"

    # Encryption
    encryption_key: str = ""

    # LLM
    llm_model: str = "azure/gpt-4o"
    llm_temperature: float = 0.1
    llm_max_tokens: int = 16384
    llm_timeout: int = 120

    # Database
    database_url: str = "postgresql+asyncpg://aspm:aspm@db:5432/aspm"

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # App
    secret_key: str = "change-me-in-production"
    log_level: str = "INFO"
    max_workers: int = 5
    api_delay: float = 0
    reports_dir: str = "/data/reports"
    retention_days: int = 180
    allowed_origins: str = "http://localhost:5173"

    @property
    def okta_base_url(self) -> str:
        return f"https://{self.okta_org}.{self.okta_org_type}.com"

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
