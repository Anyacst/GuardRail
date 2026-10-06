"""Comprehensive deterministic tests for ActionAuthorizationEngine (Phase 8)."""

import unittest

from guardx.arbiter import Arbiter
from guardx.authorization import (
    ActionAuthorizationEngine,
    ActionRequest,
    AuthorizationRiskType,
)
from guardx.domain.context import EvaluationContext
from guardx.domain.enums import (
    Confidence,
    InterceptionPoint,
    RecommendedAction,
    RiskCategory,
    Severity,
    Verdict,
)
from guardx.domain.events import SafetyEvent
from guardx.domain.evidence import Evidence
from guardx.engine.models import GuardExecutionResult, GuardExecutionStatus, RiskEngineResult
from guardx.provenance import (
    ActionProvenanceDAG,
    ProvenanceEdgeType,
    ProvenanceNodeType,
    SafetyProperty,
)


class TestActionAuthorization(unittest.TestCase):
    """Test suite for ActionAuthorizationEngine."""

    def setUp(self) -> None:
        self.auth_engine = ActionAuthorizationEngine()
        self.arbiter = Arbiter()

    def test_benign_action_with_no_sensitive_provenance(self) -> None:
        """1. Benign action with no sensitive provenance produces zero authorization Evidence."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "calculator.add", "args": {"a": 1, "b": 2}},
        )
        context = EvaluationContext(event=event)
        evidence = self.auth_engine.authorize(context)
        self.assertEqual(evidence, ())

    def test_allowed_action_with_public_data(self) -> None:
        """2. Allowed action with public/non-sensitive data."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("pub_doc", ProvenanceNodeType.RESOURCE, resource_ref="public.txt")
        dag.create_node("data", ProvenanceNodeType.DATA)
        dag.add_edge("pub_doc", "data", ProvenanceEdgeType.READS)

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "send_email",
                "destination": "partner@example.com",
                "provenance_refs": ["data"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={"forbid_external_transfer_of": ["CONFIDENTIAL", "PII"]},
        )
        evidence = self.auth_engine.authorize(context, dag=dag)
        self.assertEqual(evidence, ())

    def test_confidential_data_to_allowed_internal_destination(self) -> None:
        """3. Confidential data to allowed internal destination is permitted."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("res", ProvenanceNodeType.RESOURCE, safety_properties=[SafetyProperty.CONFIDENTIAL])

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "store_internal",
                "destination": "internal.corp.local",
                "provenance_refs": ["res"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={
                "allowed_internal_domains": ["corp.local"],
                "forbid_external_transfer_of": ["CONFIDENTIAL"],
            },
        )
        evidence = self.auth_engine.authorize(context, dag=dag)
        self.assertEqual(evidence, ())

    def test_confidential_data_to_forbidden_external_destination(self) -> None:
        """4. Confidential data to forbidden/external destination emits BLOCK Evidence."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("res", ProvenanceNodeType.RESOURCE, safety_properties=[SafetyProperty.CONFIDENTIAL])

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "send_email",
                "destination": "attacker@external.com",
                "provenance_refs": ["res"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={
                "forbid_external_transfer_of": ["CONFIDENTIAL"],
            },
        )
        evidence = self.auth_engine.authorize(context, dag=dag)
        self.assertEqual(len(evidence), 1)
        ev = evidence[0]
        self.assertEqual(ev.risk_type, AuthorizationRiskType.UNAUTHORIZED_SENSITIVE_DATA_TRANSFER.value)
        self.assertEqual(ev.recommended_action, RecommendedAction.BLOCK)
        self.assertIn("CONFIDENTIAL", ev.description)

    def test_pii_to_forbidden_external_destination(self) -> None:
        """5. PII to forbidden external destination emits BLOCK Evidence."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("res", ProvenanceNodeType.RESOURCE, safety_properties=[SafetyProperty.PII])

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "post_webhook",
                "destination": "https://api.thirdparty.com/webhook",
                "provenance_refs": ["res"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={"forbid_external_transfer_of": ["PII"]},
        )
        evidence = self.auth_engine.authorize(context, dag=dag)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].risk_type, AuthorizationRiskType.UNAUTHORIZED_SENSITIVE_DATA_TRANSFER.value)
        self.assertEqual(evidence[0].recommended_action, RecommendedAction.BLOCK)

    def test_credential_bearing_data_transfer(self) -> None:
        """6. Credential-bearing data transfer blocked by policy."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("env_file", ProvenanceNodeType.RESOURCE, safety_properties=[SafetyProperty.CREDENTIAL])

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "upload_file",
                "destination": "s3.amazonaws.com",
                "provenance_refs": ["env_file"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={"forbid_external_transfer_of": ["CREDENTIAL"]},
        )
        evidence = self.auth_engine.authorize(context, dag=dag)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].risk_type, AuthorizationRiskType.UNAUTHORIZED_SENSITIVE_DATA_TRANSFER.value)

    def test_missing_required_permission(self) -> None:
        """7. Action executed without required permission emits BLOCK Evidence."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "database_delete",
                "args": {"table": "users"},
                "permissions": ["db_read"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={"required_permissions": {"database_delete": "db_admin"}},
        )
        evidence = self.auth_engine.authorize(context)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].risk_type, AuthorizationRiskType.MISSING_ACTION_PERMISSION.value)
        self.assertEqual(evidence[0].recommended_action, RecommendedAction.BLOCK)

    def test_explicitly_allowed_permission(self) -> None:
        """8. Action executed with granted permission succeeds with no Evidence."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "database_delete",
                "permissions": ["db_admin", "db_read"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={"required_permissions": {"database_delete": "db_admin"}},
        )
        evidence = self.auth_engine.authorize(context)
        self.assertEqual(evidence, ())

    def test_action_requiring_human_review(self) -> None:
        """9. Action configured to require human approval emits HUMAN_REVIEW Evidence."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "reboot_server"},
        )
        context = EvaluationContext(
            event=event,
            policies={"require_human_review": ["reboot_server"]},
        )
        evidence = self.auth_engine.authorize(context)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].risk_type, AuthorizationRiskType.ACTION_HUMAN_REVIEW_REQUIRED.value)
        self.assertEqual(evidence[0].recommended_action, RecommendedAction.HUMAN_REVIEW)

    def test_multiple_provenance_inputs(self) -> None:
        """10. Multiple provenance inputs combined into authorization context."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("input1", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.PII])
        dag.create_node("input2", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.FINANCIAL_DATA])

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "export_report",
                "destination": "external@partner.com",
                "provenance_refs": ["input1", "input2"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={"forbid_external_transfer_of": ["FINANCIAL_DATA"]},
        )
        evidence = self.auth_engine.authorize(context, dag=dag)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].risk_type, AuthorizationRiskType.UNAUTHORIZED_SENSITIVE_DATA_TRANSFER.value)

    def test_combined_pii_and_confidential_inputs(self) -> None:
        """11. Combined PII + CONFIDENTIAL inputs."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("names", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.PII])
        dag.create_node("contracts", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.CONFIDENTIAL])

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "send_bundle",
                "destination": "external@public.org",
                "provenance_refs": ["names", "contracts"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={"forbid_external_transfer_of": ["CONFIDENTIAL", "PII"]},
        )
        evidence = self.auth_engine.authorize(context, dag=dag)
        self.assertEqual(len(evidence), 1)
        # Violating properties must report both (frozen as immutable tuple)
        self.assertEqual(
            evidence[0].supporting_data["violating_properties"],
            ("CONFIDENTIAL", "PII"),
        )

    def test_provenance_ancestor_and_propagation_lookup(self) -> None:
        """12 & 13. Verifies ancestor propagation through summarization is evaluated by authorization."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("db", ProvenanceNodeType.RESOURCE, safety_properties=[SafetyProperty.SECRET])
        dag.create_node("raw", ProvenanceNodeType.DATA)
        dag.create_node("summary", ProvenanceNodeType.DATA)

        dag.add_edge("db", "raw", ProvenanceEdgeType.READS)
        dag.add_edge("raw", "summary", ProvenanceEdgeType.DERIVED_FROM)

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "publish_summary",
                "destination": "external@public.org",
                "provenance_refs": ["summary"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={"forbid_external_transfer_of": ["SECRET"]},
        )
        evidence = self.auth_engine.authorize(context, dag=dag)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].risk_type, AuthorizationRiskType.UNAUTHORIZED_SENSITIVE_DATA_TRANSFER.value)

    def test_unknown_provenance_reference(self) -> None:
        """14. Unknown provenance reference fails safely with BLOCK Evidence."""
        dag = ActionProvenanceDAG(session_id="s1")
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "send_data",
                "destination": "ext@ex.com",
                "provenance_refs": ["non_existent_node"],
            },
        )
        context = EvaluationContext(event=event)
        evidence = self.auth_engine.authorize(context, dag=dag)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].risk_type, AuthorizationRiskType.RESTRICTED_RESOURCE_USE.value)
        self.assertEqual(evidence[0].recommended_action, RecommendedAction.BLOCK)

    def test_no_provenance_action_where_provenance_not_required(self) -> None:
        """15. No-provenance action is allowed when provenance tracking is not strictly mandated."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "time.now"},
        )
        context = EvaluationContext(event=event, policies={"require_provenance_for_actions": False})
        evidence = self.auth_engine.authorize(context)
        self.assertEqual(evidence, ())

    def test_malformed_action_payload(self) -> None:
        """16. Malformed action payload fails safely with BLOCK Evidence."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload=12345,  # Invalid payload type
        )
        context = EvaluationContext(event=event)
        evidence = self.auth_engine.authorize(context)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].risk_type, AuthorizationRiskType.MALFORMED_ACTION_REQUEST.value)
        self.assertEqual(evidence[0].recommended_action, RecommendedAction.BLOCK)

    def test_malformed_policy_extension(self) -> None:
        """17 & 18. Malformed policy extension fails safely."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "tool.run"},
        )
        context = EvaluationContext(
            event=event,
            policies={"forbidden_data_transfers": 9999},  # Invalid type
        )
        evidence = self.auth_engine.authorize(context)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].risk_type, AuthorizationRiskType.MALFORMED_ACTION_REQUEST.value)

    def test_authorization_produces_evidence_not_verdict(self) -> None:
        """19. ActionAuthorizationEngine produces Evidence, NEVER a Verdict."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={"action": "send_email", "destination": "external@example.com"},
        )
        context = EvaluationContext(event=event)
        result = self.auth_engine.authorize(context)
        self.assertIsInstance(result, tuple)
        for item in result:
            self.assertIsInstance(item, Evidence)
            self.assertNotIsInstance(item, Verdict)

    def test_arbiter_remains_final_decision_owner(self) -> None:
        """20. Arbiter consumes authorization Evidence and decides final Verdict."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("res", ProvenanceNodeType.RESOURCE, safety_properties=[SafetyProperty.CONFIDENTIAL])

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "send_email",
                "destination": "external@example.com",
                "provenance_refs": ["res"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={"forbid_external_transfer_of": ["CONFIDENTIAL"]},
        )

        auth_evidence = self.auth_engine.authorize(context, dag=dag)
        risk_engine_result = RiskEngineResult(
            context=context,
            evidence=tuple(auth_evidence),
            guard_results=(
                GuardExecutionResult(
                    guard_name="ActionAuthorizationEngine",
                    status=GuardExecutionStatus.SUCCESS,
                    evidence=tuple(auth_evidence),
                    duration_ms=1.0,
                ),
            ),
            duration_ms=1.0,
        )

        arbiter_result = self.arbiter.arbitrate(risk_engine_result)
        self.assertEqual(arbiter_result.verdict, Verdict.BLOCK)
        self.assertTrue(arbiter_result.is_blocked)

    def test_authorization_block_cannot_be_majority_voted_away(self) -> None:
        """21. Authorization BLOCK Evidence cannot be outvoted by benign ALLOW Evidence."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("res", ProvenanceNodeType.RESOURCE, safety_properties=[SafetyProperty.CONFIDENTIAL])

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "send_email",
                "destination": "external@example.com",
                "provenance_refs": ["res"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={"forbid_external_transfer_of": ["CONFIDENTIAL"]},
        )

        auth_evidence = list(self.auth_engine.authorize(context, dag=dag))
        # Add 3 benign unrelated ALLOW findings
        for i in range(3):
            auth_evidence.append(
                Evidence(
                    source_guard=f"Guard_{i}",
                    guard_version="1.0.0",
                    risk_category=RiskCategory.PRIVACY,
                    risk_type="privacy.benign_finding",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=f"Benign finding {i}",
                    affected_entities=(event.event_id,),
                    recommended_action=RecommendedAction.ALLOW,
                )
            )

        risk_engine_result = RiskEngineResult(
            context=context,
            evidence=tuple(auth_evidence),
            guard_results=(),
            duration_ms=0.0,
        )
        arbiter_result = self.arbiter.arbitrate(risk_engine_result)
        self.assertEqual(arbiter_result.verdict, Verdict.BLOCK)

    def test_deterministic_repeatability(self) -> None:
        """22. Repeated authorization calls return semantically identical Evidence."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("node", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.PII])
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "transfer",
                "destination": "ext@ex.com",
                "provenance_refs": ["node"],
            },
        )
        context = EvaluationContext(
            event=event,
            policies={"forbid_external_transfer_of": ["PII"]},
        )
        first_res = self.auth_engine.authorize(context, dag=dag)
        self.assertEqual(len(first_res), 1)
        first_ev = first_res[0]
        for _ in range(5):
            repeated = self.auth_engine.authorize(context, dag=dag)
            self.assertEqual(len(repeated), 1)
            rep_ev = repeated[0]
            # Semantic equality verification (UUID and timestamp differ per instance)
            self.assertEqual(first_ev.source_guard, rep_ev.source_guard)
            self.assertEqual(first_ev.guard_version, rep_ev.guard_version)
            self.assertEqual(first_ev.risk_category, rep_ev.risk_category)
            self.assertEqual(first_ev.risk_type, rep_ev.risk_type)
            self.assertEqual(first_ev.severity, rep_ev.severity)
            self.assertEqual(first_ev.confidence, rep_ev.confidence)
            self.assertEqual(first_ev.description, rep_ev.description)
            self.assertEqual(first_ev.affected_entities, rep_ev.affected_entities)
            self.assertEqual(first_ev.provenance_refs, rep_ev.provenance_refs)
            self.assertEqual(first_ev.supporting_data, rep_ev.supporting_data)
            self.assertEqual(first_ev.recommended_action, rep_ev.recommended_action)

    def test_full_showcase_customers_csv_exfiltration_blocked(self) -> None:
        """23. Full real showcase flow:

        1. read_file("customers.csv") -> customer_data [PII, CONFIDENTIAL]
        2. summarize(customer_data) -> summary [PII, CONFIDENTIAL]
        3. send_email(destination="external@example.com", body=summary)
        -> ActionAuthorizationEngine detects CONFIDENTIAL transfer to external destination
        -> Arbiter produces Verdict.BLOCK
        """
        dag = ActionProvenanceDAG(session_id="showcase-session")

        # Step 1: Read customers.csv
        dag.create_node(
            node_id="res:customers.csv",
            node_type=ProvenanceNodeType.RESOURCE,
            resource_ref="customers.csv",
            safety_properties=[SafetyProperty.PII, SafetyProperty.CONFIDENTIAL],
        )
        dag.create_node("data:customer_data", ProvenanceNodeType.DATA)
        dag.add_edge("res:customers.csv", "data:customer_data", ProvenanceEdgeType.READS)

        # Step 2: Summarize
        dag.create_node(
            "trans:summarize",
            ProvenanceNodeType.TRANSFORMATION,
            metadata={"transformation_rule": "SUMMARIZE"},
        )
        dag.add_edge("data:customer_data", "trans:summarize", ProvenanceEdgeType.TRANSFORMS)
        dag.create_node("data:summary", ProvenanceNodeType.DATA)
        dag.add_edge("trans:summarize", "data:summary", ProvenanceEdgeType.PRODUCES)

        # Step 3: Proposed ACTION: send_email to external destination
        action_request = ActionRequest(
            action_name="send_email",
            arguments={"destination": "external@example.com", "body_ref": "data:summary"},
            destination="external@example.com",
            provenance_refs=("data:summary",),
        )

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload=action_request,
            provenance_refs=("data:summary",),
        )

        context = EvaluationContext(
            event=event,
            policies={
                "forbid_external_transfer_of": ["CONFIDENTIAL", "PII"],
                "external_destinations": ["example.com"],
            },
            provenance_context={"dag": dag},
        )

        # Execute authorization
        auth_evidence = self.auth_engine.authorize(context, dag=dag)
        self.assertTrue(len(auth_evidence) > 0)
        self.assertEqual(
            auth_evidence[0].risk_type,
            AuthorizationRiskType.UNAUTHORIZED_SENSITIVE_DATA_TRANSFER.value,
        )

        # Pass through Arbiter
        risk_result = RiskEngineResult(
            context=context,
            evidence=tuple(auth_evidence),
            guard_results=(
                GuardExecutionResult(
                    guard_name="ActionAuthorizationEngine",
                    status=GuardExecutionStatus.SUCCESS,
                    evidence=tuple(auth_evidence),
                    duration_ms=1.0,
                ),
            ),
            duration_ms=1.0,
        )
        verdict_result = self.arbiter.arbitrate(risk_result)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)
        self.assertTrue(verdict_result.is_blocked)

    def test_full_showcase_safe_contrasting_case_allowed(self) -> None:
        """24. Safe contrasting showcase flow:

        1. read_file("public.txt") -> public_data [None]
        2. summarize(public_data) -> summary [None]
        3. send_email(destination="allowed@company.org", body=summary)
        -> ActionAuthorizationEngine detects no forbidden properties
        -> Arbiter produces Verdict.ALLOW
        """
        dag = ActionProvenanceDAG(session_id="showcase-session")

        # Step 1: Read public.txt
        dag.create_node(
            node_id="res:public.txt",
            node_type=ProvenanceNodeType.RESOURCE,
            resource_ref="public.txt",
            safety_properties=[],  # No sensitive properties
        )
        dag.create_node("data:public_data", ProvenanceNodeType.DATA)
        dag.add_edge("res:public.txt", "data:public_data", ProvenanceEdgeType.READS)

        # Step 2: Summarize
        dag.create_node(
            "trans:summarize",
            ProvenanceNodeType.TRANSFORMATION,
            metadata={"transformation_rule": "SUMMARIZE"},
        )
        dag.add_edge("data:public_data", "trans:summarize", ProvenanceEdgeType.TRANSFORMS)
        dag.create_node("data:summary", ProvenanceNodeType.DATA)
        dag.add_edge("trans:summarize", "data:summary", ProvenanceEdgeType.PRODUCES)

        # Step 3: Proposed ACTION: send_email to internal allowed destination
        action_request = ActionRequest(
            action_name="send_email",
            arguments={"destination": "allowed@company.org", "body_ref": "data:summary"},
            destination="allowed@company.org",
            provenance_refs=("data:summary",),
        )

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload=action_request,
            provenance_refs=("data:summary",),
        )

        context = EvaluationContext(
            event=event,
            policies={
                "forbid_external_transfer_of": ["CONFIDENTIAL", "PII"],
                "allowed_internal_domains": ["company.org"],
            },
            provenance_context={"dag": dag},
        )

        # Execute authorization
        auth_evidence = self.auth_engine.authorize(context, dag=dag)
        self.assertEqual(auth_evidence, ())

        # Pass through Arbiter
        risk_result = RiskEngineResult(
            context=context,
            evidence=(),
            guard_results=(
                GuardExecutionResult(
                    guard_name="ActionAuthorizationEngine",
                    status=GuardExecutionStatus.SUCCESS,
                    evidence=(),
                    duration_ms=1.0,
                ),
            ),
            duration_ms=1.0,
        )
        verdict_result = self.arbiter.arbitrate(risk_result)
        self.assertEqual(verdict_result.verdict, Verdict.ALLOW)
        self.assertTrue(verdict_result.is_allowed)

    def test_malformed_destination(self) -> None:
        """25. Malformed destination type fails safely with BLOCK Evidence."""
        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "send_data",
                "destination": 12345,  # Invalid destination type (non-string)
            },
        )
        context = EvaluationContext(event=event)
        evidence = self.auth_engine.authorize(context)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].risk_type, AuthorizationRiskType.MALFORMED_ACTION_REQUEST.value)
        self.assertEqual(evidence[0].recommended_action, RecommendedAction.BLOCK)

    def test_session_isolation_across_provenance_dags(self) -> None:
        """26. Session isolation: node belonging to another session cannot be resolved in current session."""
        dag1 = ActionProvenanceDAG(session_id="session-user-1")
        dag1.create_node("sensitive_res", ProvenanceNodeType.RESOURCE, safety_properties=[SafetyProperty.CONFIDENTIAL])

        dag2 = ActionProvenanceDAG(session_id="session-user-2")
        # DAG 2 does not contain sensitive_res from session 1
        event = SafetyEvent(
            session_id="session-user-2",
            interception_point=InterceptionPoint.ACTION,
            payload={
                "action": "export",
                "destination": "external@example.com",
                "provenance_refs": ["sensitive_res"],
            },
        )
        context = EvaluationContext(event=event)
        evidence = self.auth_engine.authorize(context, dag=dag2)
        # Provenance reference from other session cannot be verified in dag2 -> fails safely with BLOCK
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].risk_type, AuthorizationRiskType.RESTRICTED_RESOURCE_USE.value)
        self.assertEqual(evidence[0].recommended_action, RecommendedAction.BLOCK)


if __name__ == "__main__":
    unittest.main()
