"""Policy Guard implementation for deterministic application policy evaluation."""

from typing import Optional, Sequence

from guardx.domain.context import EvaluationContext
from guardx.domain.enums import RiskCategory
from guardx.domain.evidence import Evidence
from guardx.guards.base import Guard
from guardx.guards.policy.rules import (
    ForbiddenActionRule,
    ForbiddenDestinationRule,
    HumanReviewRequiredRule,
    PolicyRule,
)


class PolicyGuard(Guard):
    """Deterministic Policy Guard evaluating application-supplied policies from EvaluationContext.

    Emits immutable Evidence with recommendations (does not make the final system Verdict).
    """

    def __init__(self, rules: Optional[Sequence[PolicyRule]] = None) -> None:
        if rules is not None:
            self._rules = tuple(rules)
        else:
            self._rules = (
                ForbiddenActionRule(),
                ForbiddenDestinationRule(),
                HumanReviewRequiredRule(),
            )

    @property
    def name(self) -> str:
        return "PolicyGuard"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def risk_category(self) -> RiskCategory:
        return RiskCategory.POLICY

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return self._rules

    def is_applicable(self, context: EvaluationContext) -> bool:
        """Check if any registered rule supports the current event's interception point."""
        point = context.event.interception_point
        return any(point in rule.supported_interception_points for rule in self._rules)

    async def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        """Evaluate applicable policy rules against the context and return Evidence."""
        point = context.event.interception_point
        findings: list[Evidence] = []

        for rule in self._rules:
            if point in rule.supported_interception_points:
                rule_findings = rule.evaluate(context)
                findings.extend(rule_findings)

        return tuple(findings)
