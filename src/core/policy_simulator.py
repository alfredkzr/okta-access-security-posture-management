"""Policy simulation engine — builds payloads, calls Okta, and parses results."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

import structlog

from src.core.okta_client import OktaClient

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class RuleAction:
    """Parsed details from a policy rule."""
    access: str  # "ALLOW" or "DENY"
    policy_id: str
    policy_name: str
    rule_id: str
    rule_name: str
    factor_mode: str | None = None
    reauthenticate_in: str | None = None
    phishing_resistant: bool = False


@dataclass
class SimulationResult:
    """Result of simulating one scenario for a user + app."""
    user_id: str
    app_id: str
    scenario_name: str
    matched: bool = False
    policy_id: str | None = None
    policy_name: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    rule_action: RuleAction | None = None
    raw_response: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# Scenario protocol (duck-typed for flexibility)
# ---------------------------------------------------------------------------

class Scenario:
    """Minimal scenario interface expected by the simulator.

    Any object with these attributes will work (ORM model, Pydantic schema, dict wrapper, etc.).
    """
    name: str
    risk_level: str  # LOW | MEDIUM | HIGH | CRITICAL
    device_platform: str  # WINDOWS | MACOS | etc.
    device_registered: bool
    device_managed: bool | None
    device_assurance_id: str | None
    ip_address: str | None
    zone_ids: list[str] | None


# ---------------------------------------------------------------------------
# PolicySimulator
# ---------------------------------------------------------------------------

class PolicySimulator:
    """Orchestrates policy simulation against Okta and parses results."""

    def __init__(self, client: OktaClient) -> None:
        self._client = client
        self._rule_cache: dict[tuple[str, str], RuleAction] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def simulate(
        self,
        user_id: str,
        app_id: str,
        scenario: Any,
    ) -> SimulationResult:
        """Build a simulation payload, call Okta, and parse the result.

        *scenario* must have the attributes listed in the ``Scenario`` protocol.
        """
        result = SimulationResult(
            user_id=user_id,
            app_id=app_id,
            scenario_name=getattr(scenario, "name", "unknown"),
        )

        # --- Build payload (deep-copied to prevent contamination) ---
        payload = self._build_payload(user_id, app_id, scenario)

        # --- Contamination guard: validate user_id ---
        payload_user_id = payload.get("policyContext", {}).get("user", {}).get("id")
        if payload_user_id != user_id:
            logger.error(
                "payload_contamination_detected",
                expected_user=user_id,
                payload_user=payload_user_id,
                scenario=result.scenario_name,
            )
            result.error = f"Payload contamination: expected user {user_id}, got {payload_user_id}"
            return result

        try:
            raw = await self._client.simulate_policy(payload)
        except Exception as exc:
            logger.error("policy_simulation_failed", user_id=user_id, app_id=app_id, error=str(exc))
            result.error = str(exc)
            return result

        # --- Post-call contamination guard ---
        payload_user_id_after = payload.get("policyContext", {}).get("user", {}).get("id")
        if payload_user_id_after != user_id:
            logger.warning(
                "payload_contamination_post_call",
                expected_user=user_id,
                payload_user=payload_user_id_after,
            )

        result.raw_response = raw
        self._parse_response(result, raw)
        return result

    async def get_rule_action(
        self,
        policy_id: str,
        rule_id: str,
        policy_name: str | None = None,
    ) -> RuleAction:
        """Fetch rule details from Okta (with in-memory caching).

        Args:
            policy_id: The policy ID.
            rule_id: The rule ID.
            policy_name: The policy name from the simulation response.
                         The rule detail endpoint doesn't return the parent
                         policy name, so it must be supplied by the caller.
        """
        cache_key = (policy_id, rule_id)
        if cache_key in self._rule_cache:
            logger.debug("rule_cache_hit", policy_id=policy_id, rule_id=rule_id)
            cached = self._rule_cache[cache_key]
            # Always use the caller-supplied policy_name if available,
            # since the cached entry may have been created without one.
            if policy_name and cached.policy_name != policy_name:
                cached.policy_name = policy_name
            return cached

        rule_data = await self._client.get_policy_rule(policy_id, rule_id)
        action = self._parse_rule_action(policy_id, rule_id, rule_data, policy_name)
        self._rule_cache[cache_key] = action
        return action

    def clear_cache(self) -> None:
        """Clear the in-memory rule action cache."""
        self._rule_cache.clear()

    # ------------------------------------------------------------------
    # Payload building
    # ------------------------------------------------------------------

    @staticmethod
    def _build_payload(user_id: str, app_id: str, scenario: Any) -> dict[str, Any]:
        """Construct the simulation request body from a scenario, deep-copied."""
        device: dict[str, Any] = {
            "platform": getattr(scenario, "device_platform", "WINDOWS"),
            "registered": getattr(scenario, "device_registered", False),
            "managed": getattr(scenario, "device_managed", False),
        }
        assurance_id = getattr(scenario, "device_assurance_id", None)
        if assurance_id:
            device["assuranceId"] = assurance_id

        # Okta API only supports LOW/MEDIUM/HIGH — map CRITICAL to HIGH
        risk_level = getattr(scenario, "risk_level", "MEDIUM")
        if isinstance(risk_level, str) and risk_level.upper() == "CRITICAL":
            risk_level = "HIGH"

        policy_context: dict[str, Any] = {
            "user": {"id": user_id},
            "risk": {"level": risk_level},
            "device": device,
        }

        # ip and zones are mutually exclusive
        ip_address = getattr(scenario, "ip_address", None)
        zone_ids = getattr(scenario, "zone_ids", None)
        if ip_address:
            policy_context["ip"] = ip_address
        elif zone_ids:
            policy_context["zones"] = {"ids": list(zone_ids)}

        payload = {
            "policyTypes": [],
            "appInstance": app_id,
            "policyContext": policy_context,
        }

        # Deep-copy to isolate from any external mutation
        return copy.deepcopy(payload)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_response(result: SimulationResult, raw: dict[str, Any]) -> None:
        """Find ACCESS_POLICY evaluation → matched policy → matched rule."""
        evaluations = raw.get("evaluation", [])
        for evaluation in evaluations:
            if evaluation.get("policyType") != "ACCESS_POLICY":
                continue

            policies = evaluation.get("result", {}).get("policies", [])
            for policy in policies:
                policy_id = policy.get("id")
                policy_name = policy.get("name", "")

                rules = policy.get("rules", [])
                for rule in rules:
                    if rule.get("status") == "MATCH":
                        result.matched = True
                        result.policy_id = policy_id
                        result.policy_name = policy_name
                        result.rule_id = rule.get("id")
                        result.rule_name = rule.get("name", "")
                        return  # First match wins

    @staticmethod
    def _parse_rule_action(
        policy_id: str,
        rule_id: str,
        rule_data: dict[str, Any],
        policy_name: str | None = None,
    ) -> RuleAction:
        """Extract access decision and verification method from rule details.

        Args:
            policy_id: The policy ID.
            rule_id: The rule ID.
            rule_data: Raw rule detail response from Okta.
            policy_name: The policy name from the simulation response.
                         The rule detail endpoint only returns the rule's own
                         name, not the parent policy name.
        """
        actions = rule_data.get("actions", {})
        app_sign_on = actions.get("appSignOn", {})

        access = app_sign_on.get("access", "DENY")
        verification = app_sign_on.get("verificationMethod", {})

        factor_mode = verification.get("factorMode")
        reauthenticate_in = verification.get("reauthenticateIn")

        # Check phishing resistance in constraints
        phishing_resistant = False
        constraints = verification.get("constraints", [])
        for constraint in constraints:
            possession = constraint.get("possession", {})
            if possession.get("phishingResistant") is True:
                phishing_resistant = True
                break

        rule_name = rule_data.get("name", "")

        return RuleAction(
            access=access,
            policy_id=policy_id,
            policy_name=policy_name or "",
            rule_id=rule_id,
            rule_name=rule_name,
            factor_mode=factor_mode,
            reauthenticate_in=reauthenticate_in,
            phishing_resistant=phishing_resistant,
        )
