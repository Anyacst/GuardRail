"""Security Guard implementation for deterministic threat detection."""

from typing import Optional, Sequence

from guardx.domain.context import EvaluationContext
from guardx.domain.enums import RiskCategory
from guardx.domain.evidence import Evidence
from guardx.guards.base import Guard
from guardx.guards.security.rules import (
    IndirectInjectionMarkerRule,
    InstructionOverrideRule,
    SecurityRule,
    SuspiciousCommandExecutionRule,
    SystemPromptExtractionRule,
)


def _default_security_rules() -> tuple[SecurityRule, ...]:
    """Default set of deterministic security rules for the Security Guard."""
    return (
        InstructionOverrideRule(),
        SystemPromptExtractionRule(),
        IndirectInjectionMarkerRule(),
        SuspiciousCommandExecutionRule(),
    )


class SecurityGuard(Guard):
    """Deterministic Security Guard evaluating prompt injection, instruction manipulation, and command threats."""

    def __init__(self, rules: Optional[Sequence[SecurityRule]] = None) -> None:
        self._rules: tuple[SecurityRule, ...] = (
            tuple(rules) if rules is not None else _default_security_rules()
        )

    @property
    def name(self) -> str:
        return "SecurityGuard"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def risk_category(self) -> RiskCategory:
        return RiskCategory.SECURITY

    @property
    def rules(self) -> tuple[SecurityRule, ...]:
        """Active security rules configured for this Guard."""
        return self._rules

    async def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        """Evaluate the context against active security rules matching the interception point.

        Args:
            context: The EvaluationContext containing the SafetyEvent and metadata.

        Returns:
            A sequence of structured immutable Evidence records.
        """
        interception_point = context.event.interception_point
        findings: list[Evidence] = []

        for rule in self._rules:
            if interception_point in rule.supported_interception_points:
                rule_findings = rule.evaluate(context)
                if rule_findings:
                    findings.extend(rule_findings)

        return tuple(findings)
