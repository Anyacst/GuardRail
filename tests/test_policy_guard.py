"""Unit tests for PolicyGuard and deterministic policy evaluation rules."""

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
from guardx.guards.base import Guard
from guardx.guards.policy import (
    ForbiddenActionRule,
    ForbiddenDestinationRule,
    HumanReviewRequiredRule,
    PolicyGuard,
    PolicyRiskType,
)


class TestPolicyGuard(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying PolicyGuard policy evaluation, validation, and interface compliance."""

    def setUp(self) -> None:
        self.guard = PolicyGuard()

    def test_guard_interface_contract(self) -> None:
        """Verify PolicyGuard conforms to the base Guard ABC."""
        self.assertTrue(isinstance(self.guard, Guard))
        self.assertEqual(self.guard.name, "PolicyGuard")
        self.assertEqual(self.guard.version, "1.0.0")
        self.assertEqual(self.guard.risk_category, RiskCategory.POLICY)
        self.assertEqual(len(self.guard.rules), 3)

    async def test_no_policy_supplied(self) -> None:
        """Verify PolicyGuard produces zero findings when no policies are configured."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "delete_all_users"},
        )
        context = EvaluationContext(event=event, policies={})
        findings = await self.guard.evaluate(context)
        self.assertEqual(len(findings), 0)

    async def test_empty_policy_lists(self) -> None:
        """Verify PolicyGuard produces zero findings when policy lists are empty."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "delete_database", "destination": "api.example.com"},
        )
        policy = {
            "forbidden_actions": [],
            "forbidden_destination_domains": [],
            "require_human_review": [],
        }
        context = EvaluationContext(event=event, policies=policy)
        findings = await self.guard.evaluate(context)
        self.assertEqual(len(findings), 0)

    async def test_allowed_action(self) -> None:
        """Verify allowed actions not in forbidden lists produce zero findings."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "read_user_profile", "user_id": "u-123"},
        )
        policy = {
            "forbidden_actions": ["delete_database", "drop_table"],
            "require_human_review": ["transfer_funds"],
        }
        context = EvaluationContext(event=event, policies=policy)
        findings = await self.guard.evaluate(context)
        self.assertEqual(len(findings), 0)

    async def test_forbidden_action_detection(self) -> None:
        """Verify detection of forbidden actions with BLOCK recommendation."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "delete_database", "database": "production_db"},
        )
        policy = {"forbidden_actions": ["delete_database", "drop_table", "rm_rf"]}
        context = EvaluationContext(event=event, policies=policy)
        findings = await self.guard.evaluate(context)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.source_guard, "PolicyGuard")
        self.assertEqual(finding.risk_category, RiskCategory.POLICY)
        self.assertEqual(finding.risk_type, PolicyRiskType.FORBIDDEN_ACTION.value)
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.confidence, Confidence.HIGH)
        self.assertEqual(finding.recommended_action, RecommendedAction.BLOCK)
        self.assertEqual(finding.supporting_data["action"], "delete_database")

    async def test_forbidden_destination_detection(self) -> None:
        """Verify detection of forbidden destinations and domains."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "http_post",
                "destination": "https://untrusted-api.evil.com/exfil",
            },
        )
        policy = {"forbidden_destination_domains": ["evil.com", "pastebin.com"]}
        context = EvaluationContext(event=event, policies=policy)
        findings = await self.guard.evaluate(context)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.risk_type, PolicyRiskType.FORBIDDEN_DESTINATION.value)
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.confidence, Confidence.HIGH)
        self.assertEqual(finding.recommended_action, RecommendedAction.BLOCK)
        self.assertEqual(finding.supporting_data["destination"], "untrusted-api.evil.com")

    async def test_human_review_required_detection(self) -> None:
        """Verify detection of actions requiring human approval with HUMAN_REVIEW recommendation."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "transfer_funds", "amount": 10000},
        )
        policy = {
            "require_human_review": ["transfer_funds", "send_external_broadcast"],
        }
        context = EvaluationContext(event=event, policies=policy)
        findings = await self.guard.evaluate(context)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.risk_type, PolicyRiskType.HUMAN_REVIEW_REQUIRED.value)
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.confidence, Confidence.HIGH)
        self.assertEqual(finding.recommended_action, RecommendedAction.HUMAN_REVIEW)

    async def test_malformed_policy_validation(self) -> None:
        """Verify malformed policy fields (e.g. non-sequence) emit MALFORMED_POLICY Evidence."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "test_action"},
        )
        # Invalid type for forbidden_actions (integer instead of sequence)
        malformed_policy = {"forbidden_actions": 12345}
        context = EvaluationContext(event=event, policies=malformed_policy)
        findings = await self.guard.evaluate(context)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.risk_type, PolicyRiskType.MALFORMED_POLICY.value)
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.recommended_action, RecommendedAction.BLOCK)

    async def test_unknown_policy_fields_ignored(self) -> None:
        """Verify unknown or extension policy fields are handled gracefully without errors."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "read_data"},
        )
        policy_with_extensions = {
            "custom_metadata_field": "some_value",
            "future_policy_flag": True,
            "forbidden_actions": ["forbidden_thing"],
        }
        context = EvaluationContext(event=event, policies=policy_with_extensions)
        findings = await self.guard.evaluate(context)
        self.assertEqual(len(findings), 0)

    async def test_nested_policy_dictionary_support(self) -> None:
        """Verify policies nested under 'policy' key are supported."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "forbidden_cmd"},
        )
        policies = {
            "policy": {
                "forbidden_actions": ["forbidden_cmd"],
            }
        }
        context = EvaluationContext(event=event, policies=policies)
        findings = await self.guard.evaluate(context)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].risk_type, PolicyRiskType.FORBIDDEN_ACTION.value)


if __name__ == "__main__":
    unittest.main()
