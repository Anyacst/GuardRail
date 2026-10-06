"""Deterministic policy rules for the Policy Guard."""

from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
import re
from typing import Any, Optional, Sequence
from urllib.parse import urlparse

from guardx.domain.context import EvaluationContext
from guardx.domain.enums import Confidence, InterceptionPoint, RecommendedAction, RiskCategory, Severity
from guardx.domain.evidence import Evidence
from guardx.guards.policy.risk_types import PolicyRiskType


def _extract_action_name(payload: Any) -> Optional[str]:
    """Extract action/tool identifier from payload."""
    if isinstance(payload, dict):
        for key in ("action", "name", "tool", "command", "tool_name"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    elif isinstance(payload, str):
        # Match function-call syntax like: send_email(to="...")
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*\(", payload.strip())
        if match:
            return match.group(1)
        # Or simple action string
        if payload.strip() and not (" " in payload.strip() and len(payload.strip().split()) > 3):
            return payload.strip()
    return None


def _extract_destinations(payload: Any) -> tuple[str, ...]:
    """Extract destination domains, hosts, or URLs from payload."""
    destinations: list[str] = []

    if isinstance(payload, dict):
        for key in ("destination", "url", "host", "domain", "to", "target", "endpoint"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                destinations.append(val.strip())
            elif isinstance(val, (list, tuple)):
                for item in val:
                    if isinstance(item, str) and item.strip():
                        destinations.append(item.strip())
        # Also check nested arguments
        for arg_key in ("arguments", "params", "args"):
            if arg_key in payload and isinstance(payload[arg_key], dict):
                destinations.extend(_extract_destinations(payload[arg_key]))

    # Extract any URLs or domain patterns from string representation
    text = str(payload)
    url_matches = re.findall(r"https?://([a-zA-Z0-9_\-\.]+)(?::\d+)?", text)
    destinations.extend(url_matches)

    # Clean domain extractions
    cleaned: list[str] = []
    for d in destinations:
        if "://" in d:
            parsed = urlparse(d)
            host = parsed.hostname or parsed.netloc
            if host:
                cleaned.append(host.lower())
        elif "@" in d:
            domain = d.split("@")[-1].strip()
            if domain:
                cleaned.append(domain.lower())
        else:
            cleaned.append(d.lower())

    return tuple(set(cleaned))


def _get_policy_dict(context: EvaluationContext) -> Optional[Mapping[str, Any]]:
    """Retrieve top-level or nested policy dictionary from EvaluationContext."""
    policies = context.policies
    if not policies or not isinstance(policies, Mapping):
        return policies
    if "policy" in policies and isinstance(policies["policy"], Mapping):
        return policies["policy"]
    return policies


class PolicyRule(ABC):
    """Abstract base class for modular deterministic policy evaluation rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Stable machine-readable identifier for this rule."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this rule detects."""
        ...

    @property
    @abstractmethod
    def supported_interception_points(self) -> tuple[InterceptionPoint, ...]:
        """Interception points where this rule is active."""
        ...

    @abstractmethod
    def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        """Evaluate the policy against context and return Evidence."""
        ...


class ForbiddenActionRule(PolicyRule):
    """Detects proposed actions that are explicitly forbidden by application policy (T-09)."""

    rule_id: str = "POL-RULE-001"
    description: str = "Detects actions explicitly prohibited by configured application policy."
    supported_interception_points: tuple[InterceptionPoint, ...] = (InterceptionPoint.ACTION,)

    def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        policy = _get_policy_dict(context)
        if not policy:
            return ()

        # Validation: check forbidden_actions type
        if "forbidden_actions" in policy:
            forbidden_actions = policy["forbidden_actions"]
            if not isinstance(forbidden_actions, (list, tuple, set)):
                return (
                    Evidence(
                        source_guard="PolicyGuard",
                        guard_version="1.0.0",
                        risk_category=RiskCategory.POLICY,
                        risk_type=PolicyRiskType.MALFORMED_POLICY.value,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description="Policy field 'forbidden_actions' must be a sequence/collection.",
                        affected_entities=(context.event.event_id,),
                        supporting_data={"rule_id": self.rule_id, "field": "forbidden_actions"},
                        recommended_action=RecommendedAction.BLOCK,
                    ),
                )

            action_name = _extract_action_name(context.event.payload)
            if action_name:
                for forbidden in forbidden_actions:
                    if isinstance(forbidden, str) and forbidden.strip().lower() == action_name.lower():
                        return (
                            Evidence(
                                source_guard="PolicyGuard",
                                guard_version="1.0.0",
                                risk_category=RiskCategory.POLICY,
                                risk_type=PolicyRiskType.FORBIDDEN_ACTION.value,
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                description=f"Proposed action '{action_name}' is forbidden by application policy.",
                                affected_entities=(context.event.event_id,),
                                supporting_data={
                                    "rule_id": self.rule_id,
                                    "action": action_name,
                                    "forbidden_by": forbidden,
                                },
                                recommended_action=RecommendedAction.BLOCK,
                            ),
                        )

        return ()


class ForbiddenDestinationRule(PolicyRule):
    """Detects communication or data transfer to forbidden destination domains (T-12)."""

    rule_id: str = "POL-RULE-002"
    description: str = "Detects connections or destinations prohibited by destination policy."
    supported_interception_points: tuple[InterceptionPoint, ...] = (
        InterceptionPoint.ACTION,
        InterceptionPoint.TOOL_RESULT,
        InterceptionPoint.INPUT,
    )

    def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        policy = _get_policy_dict(context)
        if not policy:
            return ()

        if "forbidden_destination_domains" in policy:
            forbidden_domains = policy["forbidden_destination_domains"]
            if not isinstance(forbidden_domains, (list, tuple, set)):
                return (
                    Evidence(
                        source_guard="PolicyGuard",
                        guard_version="1.0.0",
                        risk_category=RiskCategory.POLICY,
                        risk_type=PolicyRiskType.MALFORMED_POLICY.value,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description="Policy field 'forbidden_destination_domains' must be a sequence.",
                        affected_entities=(context.event.event_id,),
                        supporting_data={"rule_id": self.rule_id, "field": "forbidden_destination_domains"},
                        recommended_action=RecommendedAction.BLOCK,
                    ),
                )

            destinations = _extract_destinations(context.event.payload)
            for dest in destinations:
                for forbidden in forbidden_domains:
                    if isinstance(forbidden, str):
                        forbidden_clean = forbidden.strip().lower()
                        if dest == forbidden_clean or dest.endswith(f".{forbidden_clean}"):
                            return (
                                Evidence(
                                    source_guard="PolicyGuard",
                                    guard_version="1.0.0",
                                    risk_category=RiskCategory.POLICY,
                                    risk_type=PolicyRiskType.FORBIDDEN_DESTINATION.value,
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    description=f"Destination '{dest}' matches forbidden domain '{forbidden}'.",
                                    affected_entities=(context.event.event_id,),
                                    supporting_data={
                                        "rule_id": self.rule_id,
                                        "destination": dest,
                                        "forbidden_domain": forbidden,
                                    },
                                    recommended_action=RecommendedAction.BLOCK,
                                ),
                            )

        return ()


class HumanReviewRequiredRule(PolicyRule):
    """Detects high-impact actions that explicitly require human approval according to policy."""

    rule_id: str = "POL-RULE-003"
    description: str = "Detects actions configured to require explicit human review."
    supported_interception_points: tuple[InterceptionPoint, ...] = (InterceptionPoint.ACTION,)

    def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        policy = _get_policy_dict(context)
        if not policy:
            return ()

        if "require_human_review" in policy:
            review_actions = policy["require_human_review"]
            if not isinstance(review_actions, (list, tuple, set)):
                return (
                    Evidence(
                        source_guard="PolicyGuard",
                        guard_version="1.0.0",
                        risk_category=RiskCategory.POLICY,
                        risk_type=PolicyRiskType.MALFORMED_POLICY.value,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description="Policy field 'require_human_review' must be a sequence.",
                        affected_entities=(context.event.event_id,),
                        supporting_data={"rule_id": self.rule_id, "field": "require_human_review"},
                        recommended_action=RecommendedAction.BLOCK,
                    ),
                )

            action_name = _extract_action_name(context.event.payload)
            if action_name:
                for target_action in review_actions:
                    if isinstance(target_action, str) and target_action.strip().lower() == action_name.lower():
                        return (
                            Evidence(
                                source_guard="PolicyGuard",
                                guard_version="1.0.0",
                                risk_category=RiskCategory.POLICY,
                                risk_type=PolicyRiskType.HUMAN_REVIEW_REQUIRED.value,
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                description=f"Action '{action_name}' requires human review per policy.",
                                affected_entities=(context.event.event_id,),
                                supporting_data={
                                    "rule_id": self.rule_id,
                                    "action": action_name,
                                    "policy_requirement": "human_review",
                                },
                                recommended_action=RecommendedAction.HUMAN_REVIEW,
                            ),
                        )

        return ()
