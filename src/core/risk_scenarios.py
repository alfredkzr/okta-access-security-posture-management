"""Risk scenario definitions and simulation payload builder for Okta ASPM."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DevicePlatform(str, Enum):
    WINDOWS = "WINDOWS"
    MACOS = "MACOS"
    CHROMEOS = "CHROMEOS"
    ANDROID = "ANDROID"
    IOS = "IOS"
    DESKTOP_OTHER = "DESKTOP_OTHER"
    MOBILE_OTHER = "MOBILE_OTHER"


@dataclass
class RiskScenario:
    """Represents a risk scenario used to simulate access attempts against Okta policies."""

    name: str
    description: str
    device_platform: DevicePlatform
    device_registered: bool = False
    risk_level: RiskLevel | None = None
    device_managed: bool = False
    device_assurance_id: str | None = None
    ip_address: str | None = None
    zone_ids: list[str] = field(default_factory=list)
    is_active: bool = True

    def build_policy_context(self, user_id: str, app_id: str) -> dict:
        """Build the Okta Policy Simulation API request payload.

        Args:
            user_id: The Okta user ID.
            app_id: The Okta application ID.

        Returns:
            A dict matching the POST /api/v1/policies/simulate request body.
        """
        device: dict = {
            "platform": self.device_platform.value,
            "registered": self.device_registered,
            "managed": self.device_managed,
        }
        if self.device_assurance_id is not None:
            device["assuranceId"] = self.device_assurance_id

        policy_context: dict = {
            "user": {"id": user_id},
            "device": device,
        }

        if self.risk_level is not None:
            # Okta API only supports LOW/MEDIUM/HIGH — map CRITICAL to HIGH
            okta_risk_level = "HIGH" if self.risk_level == RiskLevel.CRITICAL else self.risk_level.value
            policy_context["risk"] = {"level": okta_risk_level}

        # ip and zones are mutually exclusive
        if self.ip_address is not None:
            policy_context["ip"] = self.ip_address
        elif self.zone_ids:
            policy_context["zones"] = {"ids": copy.deepcopy(self.zone_ids)}

        payload = {
            "policyTypes": [],
            "appInstance": app_id,
            "policyContext": policy_context,
        }

        return copy.deepcopy(payload)


DEFAULT_SCENARIOS: list[RiskScenario] = [
    RiskScenario(
        name="Personal Windows",
        description="Simulates access from an unregistered, unmanaged Windows device.",
        device_platform=DevicePlatform.WINDOWS,
        device_registered=False,
        device_managed=False,
    ),
    RiskScenario(
        name="Personal macOS",
        description="Simulates access from an unregistered, unmanaged macOS device.",
        device_platform=DevicePlatform.MACOS,
        device_registered=False,
        device_managed=False,
    ),
    RiskScenario(
        name="Personal ChromeOS",
        description="Simulates access from an unregistered, unmanaged ChromeOS device.",
        device_platform=DevicePlatform.CHROMEOS,
        device_registered=False,
        device_managed=False,
    ),
    RiskScenario(
        name="Personal Android",
        description="Simulates access from an unregistered, unmanaged Android device.",
        device_platform=DevicePlatform.ANDROID,
        device_registered=False,
        device_managed=False,
    ),
    RiskScenario(
        name="Personal iOS",
        description="Simulates access from an unregistered, unmanaged iOS device.",
        device_platform=DevicePlatform.IOS,
        device_registered=False,
        device_managed=False,
    ),
    RiskScenario(
        name="Unknown Desktop",
        description="Simulates access from an unknown desktop device.",
        device_platform=DevicePlatform.DESKTOP_OTHER,
        device_registered=False,
        device_managed=False,
    ),
    RiskScenario(
        name="Unknown Mobile",
        description="Simulates access from an unknown mobile device.",
        device_platform=DevicePlatform.MOBILE_OTHER,
        device_registered=False,
        device_managed=False,
    ),
]
