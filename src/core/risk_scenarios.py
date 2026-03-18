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
    risk_level: RiskLevel
    device_platform: DevicePlatform
    device_registered: bool
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

        # Okta API only supports LOW/MEDIUM/HIGH — map CRITICAL to HIGH
        okta_risk_level = "HIGH" if self.risk_level == RiskLevel.CRITICAL else self.risk_level.value

        policy_context: dict = {
            "user": {"id": user_id},
            "risk": {"level": okta_risk_level},
            "device": device,
        }

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
        name="Personal Windows Device, Medium Risk, No Network Zone",
        description=(
            "Simulates access from a personal (unregistered, unmanaged) Windows device "
            "at medium risk level with no network zone restrictions."
        ),
        risk_level=RiskLevel.MEDIUM,
        device_platform=DevicePlatform.WINDOWS,
        device_registered=False,
        device_managed=False,
    ),
    RiskScenario(
        name="Personal macOS Device, Medium Risk, No Network Zone",
        description=(
            "Simulates access from a personal (unregistered, unmanaged) macOS device "
            "at medium risk level with no network zone restrictions."
        ),
        risk_level=RiskLevel.MEDIUM,
        device_platform=DevicePlatform.MACOS,
        device_registered=False,
        device_managed=False,
    ),
    RiskScenario(
        name="Personal ChromeOS Device, Medium Risk, No Network Zone",
        description=(
            "Simulates access from a personal (unregistered, unmanaged) ChromeOS device "
            "at medium risk level with no network zone restrictions."
        ),
        risk_level=RiskLevel.MEDIUM,
        device_platform=DevicePlatform.CHROMEOS,
        device_registered=False,
        device_managed=False,
    ),
    RiskScenario(
        name="Personal Android Device, Medium Risk, No Network Zone",
        description=(
            "Simulates access from a personal (unregistered, unmanaged) Android device "
            "at medium risk level with no network zone restrictions."
        ),
        risk_level=RiskLevel.MEDIUM,
        device_platform=DevicePlatform.ANDROID,
        device_registered=False,
        device_managed=False,
    ),
    RiskScenario(
        name="Personal iOS Device, Medium Risk, No Network Zone",
        description=(
            "Simulates access from a personal (unregistered, unmanaged) iOS device "
            "at medium risk level with no network zone restrictions."
        ),
        risk_level=RiskLevel.MEDIUM,
        device_platform=DevicePlatform.IOS,
        device_registered=False,
        device_managed=False,
    ),
    RiskScenario(
        name="Unknown Desktop Device, High Risk, No Network Zone",
        description=(
            "Simulates access from an unknown desktop device "
            "at high risk level with no network zone restrictions."
        ),
        risk_level=RiskLevel.HIGH,
        device_platform=DevicePlatform.DESKTOP_OTHER,
        device_registered=False,
        device_managed=False,
    ),
]
