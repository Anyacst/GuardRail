"""Tests for SafetyEvent domain model."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import unittest

from guardx.domain.enums import InterceptionPoint
from guardx.domain.events import SafetyEvent


class TestSafetyEvent(unittest.TestCase):
    """Test suite verifying SafetyEvent instantiation, validation, and immutability."""

    def test_default_creation(self) -> None:
        event = SafetyEvent()
        self.assertTrue(isinstance(event.event_id, str))
        self.assertTrue(len(event.event_id) > 0)
        self.assertTrue(isinstance(event.session_id, str))
        self.assertTrue(len(event.session_id) > 0)
        self.assertEqual(event.interception_point, InterceptionPoint.INPUT)
        self.assertIsNone(event.payload)
        self.assertEqual(event.metadata, {})
        self.assertEqual(event.provenance_refs, ())
        self.assertTrue(isinstance(event.timestamp, datetime))

    def test_explicit_creation(self) -> None:
        now = datetime.now(timezone.utc)
        event = SafetyEvent(
            event_id="evt-123",
            session_id="sess-456",
            interception_point=InterceptionPoint.ACTION,
            payload={"tool": "send_email", "args": {"to": "user@example.com"}},
            metadata={"user_role": "admin"},
            provenance_refs=("node-1", "node-2"),
            timestamp=now,
        )
        self.assertEqual(event.event_id, "evt-123")
        self.assertEqual(event.session_id, "sess-456")
        self.assertEqual(event.interception_point, InterceptionPoint.ACTION)
        self.assertEqual(event.payload, {"tool": "send_email", "args": {"to": "user@example.com"}})
        self.assertEqual(event.metadata, {"user_role": "admin"})
        self.assertEqual(event.provenance_refs, ("node-1", "node-2"))
        self.assertEqual(event.timestamp, now)

    def test_invalid_event_id_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SafetyEvent(event_id="")
        with self.assertRaises(ValueError):
            SafetyEvent(event_id="   ")
        with self.assertRaises(ValueError):
            SafetyEvent(event_id=123)  # type: ignore[arg-type]

    def test_invalid_session_id_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SafetyEvent(session_id="")
        with self.assertRaises(ValueError):
            SafetyEvent(session_id="   ")
        with self.assertRaises(ValueError):
            SafetyEvent(session_id=None)  # type: ignore[arg-type]

    def test_invalid_interception_point_rejected(self) -> None:
        with self.assertRaises(TypeError):
            SafetyEvent(interception_point="INPUT")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            SafetyEvent(interception_point=None)  # type: ignore[arg-type]

    def test_invalid_timestamp_rejected(self) -> None:
        with self.assertRaises(TypeError):
            SafetyEvent(timestamp="2026-10-06")  # type: ignore[arg-type]

    def test_immutability(self) -> None:
        event = SafetyEvent(event_id="evt-immutable", session_id="sess-1")
        with self.assertRaises(FrozenInstanceError):
            event.event_id = "evt-mutated"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            event.interception_point = InterceptionPoint.OUTPUT  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
