"""Tests for PolicySimulator — mocked OktaClient responses."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.policy_simulator import PolicySimulator, RuleAction, SimulationResult


# ---------------------------------------------------------------------------
# Fake scenario
# ---------------------------------------------------------------------------

@dataclass
class FakeScenario:
    name: str = "Personal Windows, Medium Risk"
    risk_level: str = "MEDIUM"
    device_platform: str = "WINDOWS"
    device_registered: bool = False
    device_managed: bool = False
    device_assurance_id: str | None = None
    ip_address: str | None = None
    zone_ids: list[str] | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sim_response(
    *,
    access_policy: bool = True,
    policy_id: str = "pol1",
    policy_name: str = "Test Policy",
    rule_id: str = "rul1",
    rule_name: str = "Catch-All",
    rule_status: str = "MATCH",
) -> dict:
    """Build a mock simulation API response."""
    rule = {"id": rule_id, "name": rule_name, "status": rule_status}
    policy = {"id": policy_id, "name": policy_name, "status": "ACTIVE", "rules": [rule]}
    evaluations = []
    if access_policy:
        evaluations.append({
            "policyType": "ACCESS_POLICY",
            "result": {"policies": [policy]},
        })
    # Include a non-ACCESS_POLICY to verify we skip it
    evaluations.append({
        "policyType": "MFA_ENROLL",
        "result": {"policies": []},
    })
    return {"evaluation": evaluations}


def _make_rule_data(
    *,
    access: str = "ALLOW",
    factor_mode: str | None = "2FA",
    reauthenticate_in: str | None = "PT2H",
    phishing_resistant: bool = False,
) -> dict:
    constraints = []
    if phishing_resistant:
        constraints.append({"possession": {"phishingResistant": True}})
    else:
        constraints.append({"possession": {"phishingResistant": False}})

    return {
        "id": "rul1",
        "name": "Catch-All Rule",
        "actions": {
            "appSignOn": {
                "access": access,
                "verificationMethod": {
                    "factorMode": factor_mode,
                    "reauthenticateIn": reauthenticate_in,
                    "constraints": constraints,
                },
            },
        },
    }


def _mock_client(sim_response=None, rule_data=None) -> AsyncMock:
    client = AsyncMock()
    if sim_response is not None:
        client.simulate_policy.return_value = sim_response
    if rule_data is not None:
        client.get_policy_rule.return_value = rule_data
    return client


# ---------------------------------------------------------------------------
# Simulation parsing — ALLOW
# ---------------------------------------------------------------------------

class TestSimulationAllow:
    @pytest.mark.asyncio
    async def test_matched_rule_found(self):
        sim_resp = _make_sim_response(rule_status="MATCH")
        client = _mock_client(sim_response=sim_resp)
        simulator = PolicySimulator(client)

        result = await simulator.simulate("u1", "app1", FakeScenario())
        assert result.matched is True
        assert result.policy_id == "pol1"
        assert result.rule_id == "rul1"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_allow_access_detected(self):
        sim_resp = _make_sim_response(rule_status="MATCH")
        rule_data = _make_rule_data(access="ALLOW")
        client = _mock_client(sim_response=sim_resp, rule_data=rule_data)
        simulator = PolicySimulator(client)

        result = await simulator.simulate("u1", "app1", FakeScenario())
        assert result.matched is True

        action = await simulator.get_rule_action(result.policy_id, result.rule_id)
        assert action.access == "ALLOW"
        assert action.factor_mode == "2FA"
        assert action.reauthenticate_in == "PT2H"


# ---------------------------------------------------------------------------
# Simulation parsing — DENY
# ---------------------------------------------------------------------------

class TestSimulationDeny:
    @pytest.mark.asyncio
    async def test_deny_access_detected(self):
        sim_resp = _make_sim_response(rule_status="MATCH")
        rule_data = _make_rule_data(access="DENY")
        client = _mock_client(sim_response=sim_resp, rule_data=rule_data)
        simulator = PolicySimulator(client)

        result = await simulator.simulate("u1", "app1", FakeScenario())
        action = await simulator.get_rule_action(result.policy_id, result.rule_id)
        assert action.access == "DENY"


# ---------------------------------------------------------------------------
# Simulation parsing — NO MATCH
# ---------------------------------------------------------------------------

class TestSimulationNoMatch:
    @pytest.mark.asyncio
    async def test_unmatched_rule(self):
        sim_resp = _make_sim_response(rule_status="UNMATCHED")
        client = _mock_client(sim_response=sim_resp)
        simulator = PolicySimulator(client)

        result = await simulator.simulate("u1", "app1", FakeScenario())
        assert result.matched is False
        assert result.rule_id is None

    @pytest.mark.asyncio
    async def test_no_access_policy_evaluation(self):
        """Response has no ACCESS_POLICY evaluation at all."""
        sim_resp = {"evaluation": [{"policyType": "MFA_ENROLL", "result": {"policies": []}}]}
        client = _mock_client(sim_response=sim_resp)
        simulator = PolicySimulator(client)

        result = await simulator.simulate("u1", "app1", FakeScenario())
        assert result.matched is False

    @pytest.mark.asyncio
    async def test_empty_evaluation(self):
        sim_resp = {"evaluation": []}
        client = _mock_client(sim_response=sim_resp)
        simulator = PolicySimulator(client)

        result = await simulator.simulate("u1", "app1", FakeScenario())
        assert result.matched is False


# ---------------------------------------------------------------------------
# Rule action caching
# ---------------------------------------------------------------------------

class TestRuleCache:
    @pytest.mark.asyncio
    async def test_cache_hit(self):
        rule_data = _make_rule_data(access="ALLOW")
        client = _mock_client(rule_data=rule_data)
        simulator = PolicySimulator(client)

        # First call — cache miss
        action1 = await simulator.get_rule_action("pol1", "rul1")
        # Second call — cache hit
        action2 = await simulator.get_rule_action("pol1", "rul1")

        assert action1.access == "ALLOW"
        assert action2.access == "ALLOW"
        # Should only call API once
        assert client.get_policy_rule.call_count == 1

    @pytest.mark.asyncio
    async def test_cache_miss_different_keys(self):
        rule_data = _make_rule_data(access="DENY")
        client = _mock_client(rule_data=rule_data)
        simulator = PolicySimulator(client)

        await simulator.get_rule_action("pol1", "rul1")
        await simulator.get_rule_action("pol1", "rul2")

        assert client.get_policy_rule.call_count == 2

    @pytest.mark.asyncio
    async def test_cache_clear(self):
        rule_data = _make_rule_data(access="ALLOW")
        client = _mock_client(rule_data=rule_data)
        simulator = PolicySimulator(client)

        await simulator.get_rule_action("pol1", "rul1")
        assert client.get_policy_rule.call_count == 1

        simulator.clear_cache()

        await simulator.get_rule_action("pol1", "rul1")
        assert client.get_policy_rule.call_count == 2


# ---------------------------------------------------------------------------
# Phishing-resistant detection
# ---------------------------------------------------------------------------

class TestPhishingResistant:
    @pytest.mark.asyncio
    async def test_phishing_resistant_true(self):
        rule_data = _make_rule_data(access="DENY", phishing_resistant=True)
        client = _mock_client(rule_data=rule_data)
        simulator = PolicySimulator(client)

        action = await simulator.get_rule_action("pol1", "rul1")
        assert action.phishing_resistant is True

    @pytest.mark.asyncio
    async def test_phishing_resistant_false(self):
        rule_data = _make_rule_data(access="DENY", phishing_resistant=False)
        client = _mock_client(rule_data=rule_data)
        simulator = PolicySimulator(client)

        action = await simulator.get_rule_action("pol1", "rul1")
        assert action.phishing_resistant is False

    @pytest.mark.asyncio
    async def test_no_constraints(self):
        """Rule with no constraints should default phishing_resistant=False."""
        rule_data = {
            "id": "rul1",
            "name": "Rule",
            "actions": {
                "appSignOn": {
                    "access": "DENY",
                    "verificationMethod": {
                        "factorMode": "2FA",
                    },
                },
            },
        }
        client = _mock_client(rule_data=rule_data)
        simulator = PolicySimulator(client)

        action = await simulator.get_rule_action("pol1", "rul1")
        assert action.phishing_resistant is False


# ---------------------------------------------------------------------------
# Contamination guard
# ---------------------------------------------------------------------------

class TestContaminationGuard:
    @pytest.mark.asyncio
    async def test_clean_payload_passes(self):
        """Normal case: user_id in payload matches expected."""
        sim_resp = _make_sim_response()
        client = _mock_client(sim_response=sim_resp)
        simulator = PolicySimulator(client)

        result = await simulator.simulate("u1", "app1", FakeScenario())
        assert result.error is None

    @pytest.mark.asyncio
    async def test_contamination_detected_pre_call(self):
        """If _build_payload somehow produces wrong user_id, error is returned."""
        sim_resp = _make_sim_response()
        client = _mock_client(sim_response=sim_resp)
        simulator = PolicySimulator(client)

        # Monkey-patch _build_payload to inject wrong user
        original_build = PolicySimulator._build_payload

        @staticmethod
        def bad_build(user_id, app_id, scenario):
            payload = original_build(user_id, app_id, scenario)
            payload["policyContext"]["user"]["id"] = "WRONG_USER"
            return payload

        simulator._build_payload = bad_build

        result = await simulator.simulate("u1", "app1", FakeScenario())
        assert result.error is not None
        assert "contamination" in result.error.lower()
        # API should NOT have been called
        client.simulate_policy.assert_not_called()


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------

class TestPayloadBuilding:
    def test_basic_payload(self):
        payload = PolicySimulator._build_payload("u1", "app1", FakeScenario())
        assert payload["appInstance"] == "app1"
        assert payload["policyContext"]["user"]["id"] == "u1"
        assert payload["policyContext"]["risk"]["level"] == "MEDIUM"
        assert payload["policyContext"]["device"]["platform"] == "WINDOWS"
        assert payload["policyContext"]["device"]["registered"] is False
        assert "ip" not in payload["policyContext"]
        assert "zones" not in payload["policyContext"]

    def test_ip_address_included(self):
        scenario = FakeScenario(ip_address="1.2.3.4")
        payload = PolicySimulator._build_payload("u1", "app1", scenario)
        assert payload["policyContext"]["ip"] == "1.2.3.4"
        assert "zones" not in payload["policyContext"]

    def test_zone_ids_included(self):
        scenario = FakeScenario(zone_ids=["z1", "z2"])
        payload = PolicySimulator._build_payload("u1", "app1", scenario)
        assert payload["policyContext"]["zones"]["ids"] == ["z1", "z2"]
        assert "ip" not in payload["policyContext"]

    def test_ip_takes_precedence_over_zones(self):
        """ip and zones are mutually exclusive; ip wins."""
        scenario = FakeScenario(ip_address="1.2.3.4", zone_ids=["z1"])
        payload = PolicySimulator._build_payload("u1", "app1", scenario)
        assert "ip" in payload["policyContext"]
        assert "zones" not in payload["policyContext"]

    def test_device_assurance_id(self):
        scenario = FakeScenario(device_assurance_id="da-123")
        payload = PolicySimulator._build_payload("u1", "app1", scenario)
        assert payload["policyContext"]["device"]["assuranceId"] == "da-123"

    def test_deep_copy_isolation(self):
        """Modifying the returned payload should not affect subsequent calls."""
        payload1 = PolicySimulator._build_payload("u1", "app1", FakeScenario())
        payload1["policyContext"]["user"]["id"] = "TAMPERED"
        payload2 = PolicySimulator._build_payload("u1", "app1", FakeScenario())
        assert payload2["policyContext"]["user"]["id"] == "u1"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestSimulationErrors:
    @pytest.mark.asyncio
    async def test_api_exception_captured(self):
        client = AsyncMock()
        client.simulate_policy.side_effect = RuntimeError("connection lost")
        simulator = PolicySimulator(client)

        result = await simulator.simulate("u1", "app1", FakeScenario())
        assert result.error is not None
        assert "connection lost" in result.error
        assert result.matched is False
