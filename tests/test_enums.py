"""Tests for GuardX domain enumerations."""

import unittest

from guardx.domain.enums import (
    Confidence,
    InterceptionPoint,
    RecommendedAction,
    RiskCategory,
    Severity,
    Verdict,
)


class TestDomainEnums(unittest.TestCase):
    """Test suite ensuring enum values strictly conform to architectural specifications."""

    def test_interception_point_values(self) -> None:
        expected = {"INPUT", "OUTPUT", "ACTION", "TOOL_RESULT"}
        actual = {point.value for point in InterceptionPoint}
        self.assertEqual(actual, expected)

    def test_risk_category_values(self) -> None:
        expected = {"SECURITY", "PRIVACY", "CONTENT_SAFETY", "POLICY"}
        actual = {category.value for category in RiskCategory}
        self.assertEqual(actual, expected)

    def test_severity_values(self) -> None:
        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
        actual = {severity.value for severity in Severity}
        self.assertEqual(actual, expected)

    def test_confidence_values(self) -> None:
        expected = {"HIGH", "MEDIUM", "LOW"}
        actual = {confidence.value for confidence in Confidence}
        self.assertEqual(actual, expected)

    def test_recommended_action_values(self) -> None:
        expected = {"ALLOW", "MODIFY", "BLOCK", "HUMAN_REVIEW"}
        actual = {action.value for action in RecommendedAction}
        self.assertEqual(actual, expected)

    def test_verdict_values(self) -> None:
        expected = {"ALLOW", "MODIFY", "BLOCK", "HUMAN_REVIEW"}
        actual = {verdict.value for verdict in Verdict}
        self.assertEqual(actual, expected)

    def test_enum_string_comparison(self) -> None:
        self.assertEqual(InterceptionPoint.INPUT, "INPUT")
        self.assertEqual(RiskCategory.SECURITY, "SECURITY")
        self.assertEqual(Severity.CRITICAL, "CRITICAL")
        self.assertEqual(Confidence.HIGH, "HIGH")
        self.assertEqual(RecommendedAction.BLOCK, "BLOCK")
        self.assertEqual(Verdict.BLOCK, "BLOCK")


if __name__ == "__main__":
    unittest.main()
