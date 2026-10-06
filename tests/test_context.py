"""Tests for EvaluationContext domain model."""

from dataclasses import FrozenInstanceError
import unittest

from guardx.domain.context import EvaluationContext
from guardx.domain.events import SafetyEvent


class TestEvaluationContext(unittest.TestCase):
    """Test suite verifying EvaluationContext structure, validation, and immutability."""

    def test_valid_context_creation(self) -> None:
        event = SafetyEvent(event_id="evt-1", session_id="sess-1")
        context = EvaluationContext(
            event=event,
            policies={"block_external": True},
            risk_memory_entries=["prior_warning"],
            provenance_context={"source_node": "node-1"},
            metadata={"caller": "test"},
        )
        self.assertEqual(context.event, event)
        self.assertEqual(context.policies, {"block_external": True})
        self.assertEqual(context.risk_memory_entries, ["prior_warning"])
        self.assertEqual(context.provenance_context, {"source_node": "node-1"})
        self.assertEqual(context.metadata, {"caller": "test"})

    def test_context_default_values(self) -> None:
        event = SafetyEvent(event_id="evt-1", session_id="sess-1")
        context = EvaluationContext(event=event)
        self.assertEqual(context.policies, {})
        self.assertEqual(context.risk_memory_entries, ())
        self.assertEqual(context.provenance_context, {})
        self.assertEqual(context.metadata, {})

    def test_invalid_event_rejected(self) -> None:
        with self.assertRaises(TypeError):
            EvaluationContext(event={"event_id": "evt-1"})  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            EvaluationContext(event=None)  # type: ignore[arg-type]

    def test_immutability(self) -> None:
        event = SafetyEvent(event_id="evt-1", session_id="sess-1")
        context = EvaluationContext(event=event)
        with self.assertRaises(FrozenInstanceError):
            context.event = SafetyEvent(event_id="evt-2", session_id="sess-2")  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
