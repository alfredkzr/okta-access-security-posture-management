import ipaddress
import uuid
from datetime import datetime
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator


def _validate_webhook_url(url: str) -> str:
    """Validate webhook URL is not targeting internal/private networks (SSRF prevention)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Webhook URL must use http or https, got: {parsed.scheme}")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Webhook URL must have a hostname")
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError(f"Webhook URL cannot target private/internal address: {ip}")
    except ValueError as exc:
        if "does not appear to be" not in str(exc):
            raise
        # It's a hostname, not an IP — allow it (DNS resolves at request time)
    return url


class NotificationChannelCreate(BaseModel):
    name: str
    channel_type: str = "webhook"
    webhook_url: str
    events: list[str]  # ["scan_completed", "new_vulnerabilities", ...]
    is_active: bool = True
    hmac_secret: str | None = None
    custom_headers: dict[str, str] | None = None

    @field_validator("webhook_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        return _validate_webhook_url(v)

    def to_config(self) -> dict:
        """Convert flat fields to config dict for DB storage."""
        config: dict = {"url": self.webhook_url, "headers": self.custom_headers or {}}
        if self.hmac_secret:
            config["secret"] = self.hmac_secret
        return config


class NotificationChannelUpdate(BaseModel):
    name: str | None = None
    webhook_url: str | None = None
    events: list[str] | None = None
    is_active: bool | None = None
    hmac_secret: str | None = None
    custom_headers: dict[str, str] | None = None

    @field_validator("webhook_url")
    @classmethod
    def validate_url(cls, v: str | None) -> str | None:
        if v is not None:
            return _validate_webhook_url(v)
        return v

    def to_config(self, existing_config: dict | None = None) -> dict | None:
        """Convert flat fields to config dict, merging with existing if partial."""
        if self.webhook_url is None and self.hmac_secret is None and self.custom_headers is None:
            return None
        config = dict(existing_config or {})
        if self.webhook_url is not None:
            config["url"] = self.webhook_url
        if self.hmac_secret is not None:
            if self.hmac_secret:
                config["secret"] = self.hmac_secret
            else:
                config.pop("secret", None)
        if self.custom_headers is not None:
            config["headers"] = self.custom_headers
        return config


class NotificationChannelResponse(BaseModel):
    id: uuid.UUID
    name: str
    channel_type: str
    webhook_url: str
    events: list[str]
    is_active: bool
    has_secret: bool = False
    custom_headers: dict[str, str] | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, channel) -> "NotificationChannelResponse":
        """Create response from ORM model, extracting config fields."""
        config = channel.config or {}
        return cls(
            id=channel.id,
            name=channel.name,
            channel_type=channel.channel_type,
            webhook_url=config.get("url", ""),
            events=channel.events or [],
            is_active=channel.is_active,
            has_secret=bool(config.get("secret")),
            custom_headers=config.get("headers") or None,
            created_at=channel.created_at,
            updated_at=channel.updated_at,
        )
