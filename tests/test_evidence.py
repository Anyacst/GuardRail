"""Tests for Evidence domain model."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import unittest

from guardx.domain.enums import Confidence, RecommendedAction, RiskCategory, Severity
from guardx.domain.evidence import Evidence


class TestEvidence(unittest.TestCase):
    """Test suite verifying Evidence structure, independence of severity/confidence, validation, and immutability."""

    def test_valid_evidence_creation(self) -> None:
        evidence = Evidence(
            source_guard="SecurityGuard",
            risk_category=RiskCategory.SECURITY,
            risk_type="PROMPT_INJECTION",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Direct prompt injection attempt detected.",
            affected_entities=["user_prompt"],
            provenance_refs=["node-1"],
            supporting_data={"pattern": "ignore previous instructions"},
            recommended_action=RecommendedAction.BLOCK,
            recommended_modification=None,
            investigation_requested=False,
        )
        self.assertEqual(evidence.source_guard, "SecurityGuard")
        self.assertEqual(evidence.risk_category, RiskCategory.SECURITY)
        self.assertEqual(evidence.risk_type, "PROMPT_INJECTION")
        self.assertEqual(evidence.severity, Severity.HIGH)
        self.assertEqual(evidence.confidence, Confidence.HIGH)
        self.assertEqual(evidence.description, "Direct prompt injection attempt detected.")
        self.assertEqual(evidence.affected_entities, ("user_prompt",))
        self.assertEqual(evidence.provenance_refs, ("node-1",))
        self.assertEqual(evidence.supporting_data["pattern"], "ignore previous instructions")
        self.assertEqual(evidence.recommended_action, RecommendedAction.BLOCK)
        self.assertIsNone(evidence.recommended_modification)
        self.assertFalse(evidence.investigation_requested)
        self.assertIsNone(evidence.previous_evidence_ref)
        self.assertTrue(isinstance(evidence.timestamp, datetime))

    def test_severity_and_confidence_independence(self) -> None:
        """Verify architectural invariant 5: severity and confidence are separate concepts."""
        # Critical severity with low confidence (e.g., potential catastrophic risk with weak evidence)
        crit_low = Evidence(
            source_guard="PrivacyGuard",
            risk_category=RiskCategory.PRIVACY,
            risk_type="POTENTIAL_EXFILTRATION",
            severity=Severity.CRITICAL,
            confidence=Confidence.LOW,
            description="Possible secret exfiltration signature, highly uncertain.",
        )
        self.assertEqual(crit_low.severity, Severity.CRITICAL)
        self.assertEqual(crit_low.confidence, Confidence.LOW)

        # None/Low severity with high confidence (e.g., verified harmless match)
        low_high = Evidence(
            source_guard="ContentSafetyGuard",
            risk_category=RiskCategory.CONTENT_SAFETY,
            risk_type="SAFE_INSPECTION",
            severity=Severity.NONE,
            confidence=Confidence.HIGH,
            description="Verified benign input.",
        )
        self.assertEqual(low_high.severity, Severity.NONE)
        self.assertEqual(low_high.confidence, Confidence.HIGH)

    def test_top_level_immutability(self) -> None:
        """Verify architectural invariant 6: Evidence is immutable after emission."""
        evidence = Evidence(
            source_guard="SecurityGuard",
            risk_category=RiskCategory.SECURITY,
            risk_type="PROMPT_INJECTION",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Direct injection",
        )
        with self.assertRaises(FrozenInstanceError):
            evidence.severity = Severity.LOW  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            evidence.description = "Altered description"  # type: ignore[misc]

    def test_deep_collection_immutability(self) -> None:
        """Verify nested collections cannot be mutated externally or via instance attributes."""
        entities = ["entity_1", "entity_2"]
        refs = ["ref_1"]
        raw_supporting_data = {
            "key": "value",
            "nested_list": [1, 2, 3],
            "nested_dict": {"inner_key": "inner_value"},
        }

        evidence = Evidence(
            source_guard="PrivacyGuard",
            risk_category=RiskCategory.PRIVACY,
            risk_type="CREDENTIAL_EXPOSURE",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="API key discovered.",
            affected_entities=entities,
            provenance_refs=refs,
            supporting_data=raw_supporting_data,
        )

        # Mutate original external collections
        entities.append("entity_3")
        refs.append("ref_2")
        raw_supporting_data["key"] = "mutated_value"
        raw_supporting_data["nested_list"].append(4)
        raw_supporting_data["nested_dict"]["inner_key"] = "mutated_inner"

        # Verify evidence instance remains completely unaffected
        self.assertEqual(evidence.affected_entities, ("entity_1", "entity_2"))
        self.assertEqual(evidence.provenance_refs, ("ref_1",))
        self.assertEqual(evidence.supporting_data["key"], "value")
        self.assertEqual(evidence.supporting_data["nested_list"], (1, 2, 3))
        self.assertEqual(evidence.supporting_data["nested_dict"]["inner_key"], "inner_value")

        # Verify direct mutation on supporting_data raises error
        with self.assertRaises((TypeError, AttributeError)):
            evidence.supporting_data["new_key"] = "fail"  # type: ignore[index]
        with self.assertRaises((TypeError, AttributeError)):
            evidence.supporting_data["nested_dict"]["new_inner"] = "fail"  # type: ignore[index]

    def test_investigation_evidence_linking(self) -> None:
        """Verify that investigation produces new Evidence linked to earlier Evidence without mutating original."""
        e1 = Evidence(
            source_guard="SecurityGuard",
            risk_category=RiskCategory.SECURITY,
            risk_type="PROMPT_INJECTION",
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            description="Initial ambiguous finding.",
            investigation_requested=True,
        )

        # Investigation creates E2 referencing E1
        e2 = Evidence(
            source_guard="SecurityGuard",
            risk_category=RiskCategory.SECURITY,
            risk_type="PROMPT_INJECTION",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Investigated finding with full context confirmed attack.",
            previous_evidence_ref=e1.evidence_id,
        )

        self.assertEqual(e2.previous_evidence_ref, e1.evidence_id)
        self.assertEqual(e1.confidence, Confidence.LOW)
        self.assertEqual(e2.confidence, Confidence.HIGH)
        self.assertNotEqual(e1.evidence_id, e2.evidence_id)

    def test_validation_rules(self) -> None:
        """Verify invalid values and types are strictly rejected."""
        # Empty / whitespace strings
        with self.assertRaises(ValueError):
            Evidence(
                source_guard="",
                risk_category=RiskCategory.SECURITY,
                risk_type="TEST",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                description="desc",
            )
        with self.assertRaises(ValueError):
            Evidence(
                source_guard="Guard",
                risk_category=RiskCategory.SECURITY,
                risk_type="",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                description="desc",
            )
        with self.assertRaises(ValueError):
            Evidence(
                source_guard="Guard",
                risk_category=RiskCategory.SECURITY,
                risk_type="TEST",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                description="desc",
                guard_version="   ",
            )
        with self.assertRaises(ValueError):
            Evidence(
                source_guard="Guard",
                risk_category=RiskCategory.SECURITY,
                risk_type="TEST",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                description="desc",
                evidence_id="",
            )
        with self.assertRaises(ValueError):
            Evidence(
                source_guard="Guard",
                risk_category=RiskCategory.SECURITY,
                risk_type="TEST",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                description="desc",
                previous_evidence_ref="",
            )

        # Type errors
        with self.assertRaises(TypeError):
            Evidence(
                source_guard="Guard",
                risk_category="SECURITY",  # type: ignore[arg-type]
                risk_type="TEST",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                description="desc",
            )
        with self.assertRaises(TypeError):
            Evidence(
                source_guard="Guard",
                risk_category=RiskCategory.SECURITY,
                risk_type="TEST",
                severity="LOW",  # type: ignore[arg-type]
                confidence=Confidence.LOW,
                description="desc",
            )
        with self.assertRaises(TypeError):
            Evidence(
                source_guard="Guard",
                risk_category=RiskCategory.SECURITY,
                risk_type="TEST",
                severity=Severity.LOW,
                confidence="LOW",  # type: ignore[arg-type]
                description="desc",
            )
        with self.assertRaises(TypeError):
            Evidence(
                source_guard="Guard",
                risk_category=RiskCategory.SECURITY,
                risk_type="TEST",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                description="desc",
                recommended_action="BLOCK",  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
