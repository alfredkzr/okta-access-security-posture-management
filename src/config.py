from pydantic import model_validator
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
    # Encryption
    encryption_key: str = ""

    # Database
    database_url: str = "postgresql+asyncpg://aspm:aspm@db:5432/aspm"

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # App
    secret_key: str = ""
    log_level: str = "INFO"
    max_workers: int = 5
    api_delay: float = 0
    reports_dir: str = "/data/reports"
    retention_days: int = 180
    allowed_origins: str = "http://localhost:5173"
    cookie_secure: bool = True

    @model_validator(mode="after")
    def _validate_secrets(self) -> "Settings":
        if not self.secret_key or self.secret_key == "change-me-in-production":
            raise ValueError(
                "SECRET_KEY must be set to a strong random value. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )
        if not self.encryption_key:
            raise ValueError(
                "ENCRYPTION_KEY must be set to a valid Fernet key. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        # Validate that encryption_key is a valid Fernet key
        try:
            from cryptography.fernet import Fernet
            Fernet(self.encryption_key.encode())
        except Exception as exc:
            raise ValueError(
                f"ENCRYPTION_KEY is not a valid Fernet key: {exc}. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            ) from exc
        return self

    @property
    def okta_base_url(self) -> str:
        return f"https://{self.okta_org}.{self.okta_org_type}.com"

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()
