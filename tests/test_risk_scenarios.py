"""Edge case tests for src/core/risk_scenarios.py."""

from __future__ import annotations

import copy

from src.core.risk_scenarios import (
    DEFAULT_SCENARIOS,
    DevicePlatform,
    RiskLevel,
    RiskScenario,
)


class TestBuildPolicyContext:
    def test_basic_structure(self):
        scenario = RiskScenario(
            name="Test",
            description="Test scenario",
            risk_level=RiskLevel.MEDIUM,
            device_platform=DevicePlatform.WINDOWS,
            device_registered=False,
        )
        payload = scenario.build_policy_context("user123", "app456")
        assert payload["policyTypes"] == []
        assert payload["appInstance"] == "app456"
        assert payload["policyContext"]["user"]["id"] == "user123"
        assert payload["policyContext"]["risk"]["level"] == "MEDIUM"
        assert payload["policyContext"]["device"]["platform"] == "WINDOWS"
        assert payload["policyContext"]["device"]["registered"] is False
        assert payload["policyContext"]["device"]["managed"] is False

    def test_ip_takes_precedence_over_zones(self):
        """When both ip_address and zone_ids are set, ip should be used, not zones."""
        scenario = RiskScenario(
            name="Test",
            description="Test",
            risk_level=RiskLevel.HIGH,
            device_platform=DevicePlatform.MACOS,
            device_registered=False,
            ip_address="1.2.3.4",
            zone_ids=["zone1", "zone2"],
        )
        payload = scenario.build_policy_context("u1", "a1")
        assert payload["policyContext"]["ip"] == "1.2.3.4"
        assert "zones" not in payload["policyContext"]

    def test_no_ip_no_zones_neither_key_present(self):
        scenario = RiskScenario(
            name="Test",
            description="Test",
            risk_level=RiskLevel.LOW,
            device_platform=DevicePlatform.ANDROID,
            device_registered=True,
        )
        payload = scenario.build_policy_context("u1", "a1")
        assert "ip" not in payload["policyContext"]
        assert "zones" not in payload["policyContext"]

    def test_zone_ids_produces_correct_structure(self):
        scenario = RiskScenario(
            name="Test",
            description="Test",
            risk_level=RiskLevel.LOW,
            device_platform=DevicePlatform.IOS,
            device_registered=False,
            zone_ids=["zone-abc", "zone-def"],
        )
        payload = scenario.build_policy_context("u1", "a1")
        assert payload["policyContext"]["zones"] == {"ids": ["zone-abc", "zone-def"]}

    def test_device_assurance_id_included(self):
        scenario = RiskScenario(
            name="Test",
            description="Test",
            risk_level=RiskLevel.MEDIUM,
            device_platform=DevicePlatform.WINDOWS,
            device_registered=True,
            device_managed=True,
            device_assurance_id="da-12345",
        )
        payload = scenario.build_policy_context("u1", "a1")
        assert payload["policyContext"]["device"]["assuranceId"] == "da-12345"

    def test_device_assurance_id_absent_when_none(self):
        scenario = RiskScenario(
            name="Test",
            description="Test",
            risk_level=RiskLevel.MEDIUM,
            device_platform=DevicePlatform.WINDOWS,
            device_registered=False,
        )
        payload = scenario.build_policy_context("u1", "a1")
        assert "assuranceId" not in payload["policyContext"]["device"]


class TestDeepCopy:
    def test_modifying_returned_payload_does_not_affect_scenario(self):
        scenario = RiskScenario(
            name="Test",
            description="Test",
            risk_level=RiskLevel.HIGH,
            device_platform=DevicePlatform.CHROMEOS,
            device_registered=False,
            zone_ids=["zone1"],
        )
        payload1 = scenario.build_policy_context("u1", "a1")
        # Mutate the returned payload
        payload1["policyContext"]["user"]["id"] = "MUTATED"
        payload1["policyContext"]["device"]["platform"] = "MUTATED"
        if "zones" in payload1["policyContext"]:
            payload1["policyContext"]["zones"]["ids"].append("MUTATED_ZONE")

        # Build again — should be unaffected
        payload2 = scenario.build_policy_context("u1", "a1")
        assert payload2["policyContext"]["user"]["id"] == "u1"
        assert payload2["policyContext"]["device"]["platform"] == "CHROMEOS"
        assert payload2["policyContext"]["zones"]["ids"] == ["zone1"]

    def test_two_payloads_are_independent(self):
        scenario = RiskScenario(
            name="Test",
            description="Test",
            risk_level=RiskLevel.MEDIUM,
            device_platform=DevicePlatform.ANDROID,
            device_registered=False,
        )
        p1 = scenario.build_policy_context("user_a", "app_x")
        p2 = scenario.build_policy_context("user_b", "app_y")
        p1["policyContext"]["user"]["id"] = "CHANGED"
        assert p2["policyContext"]["user"]["id"] == "user_b"


class TestDefaultScenarios:
    def test_exactly_six_scenarios(self):
        assert len(DEFAULT_SCENARIOS) == 6

    def test_all_active(self):
        for s in DEFAULT_SCENARIOS:
            assert s.is_active is True, f"Scenario '{s.name}' should be active"

    def test_all_unregistered_unmanaged(self):
        for s in DEFAULT_SCENARIOS:
            assert s.device_registered is False, f"Scenario '{s.name}' should have device_registered=False"
            assert s.device_managed is False, f"Scenario '{s.name}' should have device_managed=False"

    def test_expected_platforms(self):
        platforms = {s.device_platform for s in DEFAULT_SCENARIOS}
        assert platforms == {
            DevicePlatform.WINDOWS,
            DevicePlatform.MACOS,
            DevicePlatform.CHROMEOS,
            DevicePlatform.ANDROID,
            DevicePlatform.IOS,
            DevicePlatform.DESKTOP_OTHER,
        }

    def test_risk_levels(self):
        """First 5 should be MEDIUM, last one HIGH."""
        levels = [s.risk_level for s in DEFAULT_SCENARIOS]
        assert levels[:5] == [RiskLevel.MEDIUM] * 5
        assert levels[5] == RiskLevel.HIGH

    def test_no_ip_or_zones_on_defaults(self):
        for s in DEFAULT_SCENARIOS:
            assert s.ip_address is None, f"Scenario '{s.name}' should have no ip_address"
            assert s.zone_ids == [], f"Scenario '{s.name}' should have empty zone_ids"

    def test_each_has_name_and_description(self):
        for s in DEFAULT_SCENARIOS:
            assert s.name, f"Scenario should have a name"
            assert s.description, f"Scenario '{s.name}' should have a description"


class TestEdgeCases:
    def test_empty_zone_ids_list_treated_as_no_zones(self):
        scenario = RiskScenario(
            name="Test",
            description="Test",
            risk_level=RiskLevel.LOW,
            device_platform=DevicePlatform.IOS,
            device_registered=False,
            zone_ids=[],
        )
        payload = scenario.build_policy_context("u1", "a1")
        assert "zones" not in payload["policyContext"]

    def test_ip_address_only(self):
        scenario = RiskScenario(
            name="Test",
            description="Test",
            risk_level=RiskLevel.LOW,
            device_platform=DevicePlatform.WINDOWS,
            device_registered=False,
            ip_address="10.0.0.1",
        )
        payload = scenario.build_policy_context("u1", "a1")
        assert payload["policyContext"]["ip"] == "10.0.0.1"
        assert "zones" not in payload["policyContext"]
