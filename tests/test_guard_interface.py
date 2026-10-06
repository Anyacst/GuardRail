"""Tests for Guard base contract and deterministic fake Guard evaluation."""

import asyncio
from typing import Sequence
import unittest

from guardx.domain.context import EvaluationContext
from guardx.domain.enums import (
    Confidence,
    InterceptionPoint,
    RecommendedAction,
    RiskCategory,
    Severity,
)
from guardx.domain.events import SafetyEvent
from guardx.domain.evidence import Evidence
from guardx.guards.base import Guard


class DeterministicFakeGuard(Guard):
    """A deterministic fake Guard used to verify Phase 1 exit criteria."""

    @property
    def name(self) -> str:
        return "DeterministicFakeGuard"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def risk_category(self) -> RiskCategory:
        return RiskCategory.SECURITY

    async def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        payload = context.event.payload
        if isinstance(payload, str) and "injection" in payload.lower():
            return (
                Evidence(
                    source_guard=self.name,
                    guard_version=self.version,
                    risk_category=self.risk_category,
                    risk_type="DETERMINISTIC_PROMPT_INJECTION",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="Detected deterministic injection keyword in payload.",
                    affected_entities=(context.event.event_id,),
                    recommended_action=RecommendedAction.BLOCK,
                ),
            )
        return ()


class TestGuardInterface(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying Guard abstract contract and deterministic execution."""

    def test_guard_incomplete_subclass_rejected(self) -> None:
        class IncompleteGuard(Guard):
            pass

        with self.assertRaises(TypeError):
            IncompleteGuard()  # type: ignore[abstract]

    async def test_fake_guard_evaluation_benign_event(self) -> None:
        """Verify Phase 1 exit criteria on benign event: SafetyEvent -> Context -> evaluate() -> ()"""
        guard = DeterministicFakeGuard()
        self.assertEqual(guard.name, "DeterministicFakeGuard")
        self.assertEqual(guard.version, "1.0.0")
        self.assertEqual(guard.risk_category, RiskCategory.SECURITY)

        event = SafetyEvent(
            interception_point=InterceptionPoint.INPUT,
            payload="Hello, what is the weather today?",
        )
        context = EvaluationContext(event=event)

        evidence_list = await guard.evaluate(context)
        self.assertEqual(len(evidence_list), 0)

    async def test_fake_guard_evaluation_flagged_event(self) -> None:
        """Verify Phase 1 exit criteria on flagged event: SafetyEvent -> Context -> evaluate() -> Evidence[]"""
        guard = DeterministicFakeGuard()

        event = SafetyEvent(
            interception_point=InterceptionPoint.INPUT,
            payload="Perform prompt injection now.",
        )
        context = EvaluationContext(event=event)

        evidence_list = await guard.evaluate(context)
        self.assertEqual(len(evidence_list), 1)

        evidence = evidence_list[0]
        self.assertEqual(evidence.source_guard, "DeterministicFakeGuard")
        self.assertEqual(evidence.risk_category, RiskCategory.SECURITY)
        self.assertEqual(evidence.risk_type, "DETERMINISTIC_PROMPT_INJECTION")
        self.assertEqual(evidence.severity, Severity.HIGH)
        self.assertEqual(evidence.confidence, Confidence.HIGH)
        self.assertEqual(evidence.recommended_action, RecommendedAction.BLOCK)
        self.assertEqual(evidence.affected_entities, (event.event_id,))


if __name__ == "__main__":
    unittest.main()
