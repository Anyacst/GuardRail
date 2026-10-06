"""Execution adapter connecting demonstration scenarios to actual GuardX components.

CRITICAL INVARIANTS:
1. No hardcoded verdicts.
2. Every Verdict, Evidence, and Propagated Property comes from actual GuardX execution.
3. Completely deterministic and reproducible.
"""

import asyncio
from dataclasses import dataclass
import os
import sys
import time
from typing import Any, Mapping, Optional, Sequence, Union

# Ensure repository root is on sys.path for direct invocation
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from demo.scenarios import SCENARIOS, DemoScenario
from guardx.arbiter import Arbiter, ArbiterResult
from guardx.authorization import ActionAuthorizationEngine, ActionRequest
from guardx.domain.context import EvaluationContext
from guardx.domain.enums import InterceptionPoint
from guardx.domain.events import SafetyEvent
from guardx.domain.evidence import Evidence
from guardx.engine import (
    GuardExecutionResult,
    GuardExecutionStatus,
    RiskEngine,
    RiskEngineResult,
)
from guardx.guards.policy import PolicyGuard
from guardx.guards.privacy import PrivacyGuard
from guardx.guards.security import SecurityGuard
from guardx.provenance import (
    ActionProvenanceDAG,
    ProvenanceEdgeType,
    ProvenanceNodeType,
    PropertyPropagationEngine,
    SafetyProperty,
)


@dataclass(frozen=True)
class DemoExecutionResult:
    """Rich structured outcome of a live GuardX demonstration run."""

    scenario: DemoScenario
    step_number: Optional[int]
    event: SafetyEvent
    dag: Optional[ActionProvenanceDAG]
    effective_properties: dict[str, tuple[str, ...]]
    risk_result: RiskEngineResult
    arbiter_result: ArbiterResult
    duration_ms: float

    @property
    def verdict(self) -> str:
        return self.arbiter_result.verdict.name

    @property
    def is_blocked(self) -> bool:
        return self.arbiter_result.is_blocked

    @property
    def is_allowed(self) -> bool:
        return self.arbiter_result.is_allowed

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        return self.risk_result.evidence

    @property
    def evidence_records(self) -> tuple[Evidence, ...]:
        return self.risk_result.evidence

    @property
    def dag_nodes(self) -> list[dict[str, Any]]:
        if self.dag is None:
            return []
        nodes = []
        for node in self.dag.get_nodes():
            effective = self.effective_properties.get(node.node_id, ())
            nodes.append({
                "id": node.node_id,
                "type": node.node_type.name,
                "description": node.description,
                "declared_properties": list(node.safety_properties),
                "effective_properties": list(effective),
                "resource_ref": node.resource_ref,
            })
        return nodes


class DemoRunner:
    """Orchestrates actual GuardX safety analysis for demonstration purposes."""

    def __init__(self) -> None:
        self._security_guard = SecurityGuard()
        self._privacy_guard = PrivacyGuard()
        self._policy_guard = PolicyGuard()
        self._risk_engine = RiskEngine([
            self._security_guard,
            self._privacy_guard,
            self._policy_guard,
        ])
        self._auth_engine = ActionAuthorizationEngine()
        self._propagation_engine = PropertyPropagationEngine()
        self._arbiter = Arbiter()

    def run_scenario(
        self,
        scenario_id: Union[str, DemoScenario],
        up_to_step: Optional[int] = None,
    ) -> DemoExecutionResult:
        """Execute a predefined scenario through real GuardX components.

        Args:
            scenario_id: Key matching SCENARIOS or a DemoScenario instance.
            up_to_step: For step-by-step scenarios, simulate up to this step.

        Returns:
            DemoExecutionResult containing live GuardX outcomes.
        """
        if isinstance(scenario_id, DemoScenario):
            scenario = scenario_id
            scenario_key = scenario.scenario_id
        elif scenario_id in SCENARIOS:
            scenario_key = scenario_id
            scenario = SCENARIOS[scenario_id]
        else:
            raise KeyError(f"Unknown scenario ID '{scenario_id}'")
        start_time = time.perf_counter()

        # Build real provenance DAG if scenario uses provenance
        dag: Optional[ActionProvenanceDAG] = None
        effective_properties: dict[str, tuple[str, ...]] = {}

        if scenario.dag_builder is not None:
            dag = scenario.dag_builder(up_to_step)
            for node in dag.get_nodes():
                props = self._propagation_engine.compute_effective_properties(dag, node.node_id)
                effective_properties[node.node_id] = tuple(sorted(props))

        # Build real SafetyEvent
        event_payload = scenario.payload
        provenance_refs = ()
        if isinstance(event_payload, ActionRequest):
            provenance_refs = event_payload.provenance_refs

        event = SafetyEvent(
            interception_point=scenario.interception_point,
            payload=event_payload,
            provenance_refs=provenance_refs,
        )

        context = EvaluationContext(
            event=event,
            policies=scenario.policies,
            provenance_context={"dag": dag} if dag is not None else {},
        )

        # Run actual GuardX pipeline using common pipeline runner
        risk_result, arbiter_result = self._run_pipeline(context, dag=dag)
        total_elapsed = (time.perf_counter() - start_time) * 1000.0

        return DemoExecutionResult(
            scenario=scenario,
            step_number=up_to_step,
            event=event,
            dag=dag,
            effective_properties=effective_properties,
            risk_result=risk_result,
            arbiter_result=arbiter_result,
            duration_ms=total_elapsed,
        )

    def _run_pipeline(
        self,
        context: EvaluationContext,
        dag: Optional[ActionProvenanceDAG] = None,
    ) -> tuple[RiskEngineResult, ArbiterResult]:
        """Execute the appropriate real GuardX pipeline based on the event interception point."""
        point = context.event.interception_point
        if point in (InterceptionPoint.INPUT, InterceptionPoint.OUTPUT, InterceptionPoint.TOOL_RESULT):
            # 1. Concurrent Guard Orchestration via RiskEngine
            risk_result = asyncio.run(self._risk_engine.evaluate(context))
            # 2. Deterministic Arbitration
            arbiter_result = self._arbiter.arbitrate(risk_result)
            return risk_result, arbiter_result

        elif point == InterceptionPoint.ACTION:
            # 1. Action Authorization + PolicyGuard
            auth_start = time.perf_counter()
            auth_evidence = self._auth_engine.authorize(context, dag=dag)
            policy_evidence = asyncio.run(self._policy_guard.evaluate(context))
            auth_elapsed = (time.perf_counter() - auth_start) * 1000.0

            all_evidence = tuple(list(auth_evidence) + list(policy_evidence))
            guard_results = (
                GuardExecutionResult(
                    guard_name="ActionAuthorizationEngine",
                    status=GuardExecutionStatus.SUCCESS,
                    evidence=tuple(auth_evidence),
                    duration_ms=auth_elapsed,
                ),
                GuardExecutionResult(
                    guard_name="PolicyGuard",
                    status=GuardExecutionStatus.SUCCESS,
                    evidence=tuple(policy_evidence),
                    duration_ms=auth_elapsed,
                ),
            )

            risk_result = RiskEngineResult(
                context=context,
                evidence=all_evidence,
                guard_results=guard_results,
                duration_ms=auth_elapsed,
            )

            # 2. Deterministic Arbitration
            arbiter_result = self._arbiter.arbitrate(risk_result)
            return risk_result, arbiter_result

        else:
            raise ValueError(f"Unsupported interception point: {point}")

    def analyze_arbitrary_event(
        self,
        interception_point: Union[str, InterceptionPoint],
        payload: Any,
        policies: Optional[Mapping[str, Any]] = None,
    ) -> DemoExecutionResult:
        """Execute arbitrary user-provided content through real GuardX core pipeline.

        Args:
            interception_point: One of INPUT, OUTPUT, TOOL_RESULT, or ACTION.
            payload: Free-form text or structured ActionRequest/dict.
            policies: Optional application security policy configuration.

        Returns:
            DemoExecutionResult from actual GuardX evaluation.
        """
        start_time = time.perf_counter()
        if isinstance(interception_point, str):
            point_key = interception_point.strip().upper()
            try:
                point = InterceptionPoint[point_key]
            except KeyError:
                raise ValueError(
                    f"Invalid interception point '{interception_point}'. "
                    f"Must be one of: {[p.name for p in InterceptionPoint]}"
                )
        elif isinstance(interception_point, InterceptionPoint):
            point = interception_point
        else:
            raise TypeError(f"Expected str or InterceptionPoint, got {type(interception_point).__name__}")

        provenance_refs = ()
        event_payload = payload
        if point == InterceptionPoint.ACTION:
            if isinstance(payload, ActionRequest):
                event_payload = payload
                provenance_refs = payload.provenance_refs
            elif isinstance(payload, Mapping):
                action_name = payload.get("action_name") or payload.get("action")
                if not action_name or not isinstance(action_name, str) or not action_name.strip():
                    raise ValueError("Action payload must specify non-empty 'action_name'")
                destination = payload.get("destination")
                arguments = payload.get("arguments") or {}
                permissions = payload.get("permissions") or ()
                provenance_refs = tuple(payload.get("provenance_refs") or ())
                event_payload = ActionRequest(
                    action_name=action_name.strip(),
                    destination=destination.strip() if isinstance(destination, str) and destination.strip() else None,
                    arguments=dict(arguments) if isinstance(arguments, Mapping) else {},
                    permissions=tuple(str(p) for p in permissions),
                    provenance_refs=provenance_refs,
                )
            else:
                raise ValueError("ACTION payload must be an ActionRequest or dictionary of action fields")
        else:
            if event_payload is None:
                event_payload = ""

        event = SafetyEvent(
            interception_point=point,
            payload=event_payload,
            provenance_refs=provenance_refs,
        )

        context = EvaluationContext(
            event=event,
            policies=dict(policies) if policies else {},
            provenance_context={},
        )

        risk_result, arbiter_result = self._run_pipeline(context, dag=None)
        total_elapsed = (time.perf_counter() - start_time) * 1000.0

        scenario = DemoScenario(
            scenario_id="custom_analysis",
            title=f"GuardX Playground: {point.name} Live Analysis",
            category="PLAYGROUND",
            description=f"Arbitrary {point.name} content analyzed dynamically by GuardX runtime",
            interception_point=point,
            payload=event_payload,
            policies=dict(policies) if policies else {},
            simulated_context={"mode": "Live Interactive Analysis", "interception_point": point.name},
        )

        return DemoExecutionResult(
            scenario=scenario,
            step_number=None,
            event=event,
            dag=None,
            effective_properties={},
            risk_result=risk_result,
            arbiter_result=arbiter_result,
            duration_ms=total_elapsed,
        )

    def analyze_arbitrary_action(
        self,
        action_name: str,
        destination: Optional[str] = None,
        arguments: Optional[Mapping[str, Any]] = None,
        permissions: Optional[Sequence[str]] = None,
        policies: Optional[Mapping[str, Any]] = None,
    ) -> DemoExecutionResult:
        """Inspect and authorize an arbitrary ACTION event."""
        if not action_name or not isinstance(action_name, str) or not action_name.strip():
            raise ValueError("action_name must be a non-empty string.")

        action_req = ActionRequest(
            action_name=action_name.strip(),
            destination=destination.strip() if destination and isinstance(destination, str) and destination.strip() else None,
            arguments=dict(arguments) if arguments and isinstance(arguments, Mapping) else {},
            permissions=tuple(str(p) for p in permissions) if permissions else (),
        )
        return self.analyze_arbitrary_event(
            interception_point=InterceptionPoint.ACTION,
            payload=action_req,
            policies=policies,
        )

    def analyze_arbitrary_trace(
        self,
        resource_name: str,
        safety_properties: Sequence[str],
        transformation_type: str,
        action_name: str,
        destination: str,
        policies: Optional[Mapping[str, Any]] = None,
    ) -> DemoExecutionResult:
        """Construct a real ActionProvenanceDAG from trace parameters and evaluate action authorization."""
        start_time = time.perf_counter()
        if not resource_name or not isinstance(resource_name, str) or not resource_name.strip():
            raise ValueError("resource_name must be a non-empty string.")
        if not transformation_type or not isinstance(transformation_type, str) or not transformation_type.strip():
            raise ValueError("transformation_type must be a non-empty string.")
        if not action_name or not isinstance(action_name, str) or not action_name.strip():
            raise ValueError("action_name must be a non-empty string.")
        if not destination or not isinstance(destination, str) or not destination.strip():
            raise ValueError("destination must be a non-empty string.")

        norm_props = []
        for p in safety_properties:
            if isinstance(p, SafetyProperty):
                norm_props.append(p.value)
            elif isinstance(p, str) and p.strip():
                norm_props.append(p.strip().upper())
        props_tuple = tuple(sorted(set(norm_props)))

        # 1. Construct real ActionProvenanceDAG
        dag = ActionProvenanceDAG(session_id="trace-playground-session")

        res_id = f"res:{resource_name.strip()}"
        dag.create_node(
            node_id=res_id,
            node_type=ProvenanceNodeType.RESOURCE,
            resource_ref=resource_name.strip(),
            safety_properties=props_tuple,
            description=f"Resource source: {resource_name.strip()}",
        )

        data_in_id = "data:extracted"
        dag.create_node(
            node_id=data_in_id,
            node_type=ProvenanceNodeType.DATA,
            description=f"Extracted data from {resource_name.strip()}",
        )
        dag.add_edge(
            source_id=res_id,
            destination_id=data_in_id,
            edge_type=ProvenanceEdgeType.READS,
        )

        trans_id = f"trans:{transformation_type.strip().lower()}"
        dag.create_node(
            node_id=trans_id,
            node_type=ProvenanceNodeType.TRANSFORMATION,
            description=f"Transformation: {transformation_type.strip().upper()}",
            metadata={"transformation_rule": transformation_type.strip().upper()},
        )
        dag.add_edge(
            source_id=data_in_id,
            destination_id=trans_id,
            edge_type=ProvenanceEdgeType.TRANSFORMS,
        )

        data_out_id = "data:output"
        dag.create_node(
            node_id=data_out_id,
            node_type=ProvenanceNodeType.DATA,
            description=f"Transformed output ({transformation_type.strip().upper()})",
        )
        dag.add_edge(
            source_id=trans_id,
            destination_id=data_out_id,
            edge_type=ProvenanceEdgeType.PRODUCES,
        )

        # 2. Compute effective properties for each node in DAG via PropertyPropagationEngine
        effective_properties: dict[str, tuple[str, ...]] = {}
        for node in dag.get_nodes():
            computed = self._propagation_engine.compute_effective_properties(dag, node.node_id)
            effective_properties[node.node_id] = tuple(sorted(computed))

        # Default policy enforcing data transfer rules unless overridden
        effective_policies: dict[str, Any] = {
            "forbid_external_transfer_of": ["PII", "CONFIDENTIAL", "CREDENTIAL", "SECRET", "FINANCIAL_DATA"],
            "allowed_internal_domains": ["company.org", "internal.corp", "localhost"],
        }
        if policies:
            effective_policies.update(policies)

        # 3. Construct real ActionRequest targeting destination with provenance ref
        action_request = ActionRequest(
            action_name=action_name.strip(),
            destination=destination.strip(),
            arguments={
                "source_resource": resource_name.strip(),
                "transformation": transformation_type.strip().upper(),
            },
            provenance_refs=(data_out_id,),
        )

        event = SafetyEvent(
            interception_point=InterceptionPoint.ACTION,
            payload=action_request,
            provenance_refs=(data_out_id,),
        )

        context = EvaluationContext(
            event=event,
            policies=effective_policies,
            provenance_context={"dag": dag},
        )

        # 4. Authorize action and arbitrate
        risk_result, arbiter_result = self._run_pipeline(context, dag=dag)
        total_elapsed = (time.perf_counter() - start_time) * 1000.0

        scenario = DemoScenario(
            scenario_id="trace_playground",
            title=f"Trace: {resource_name.strip()} -> {transformation_type.strip().upper()} -> {action_name.strip()} ({destination.strip()})",
            category="TRACE_PLAYGROUND",
            description=f"Simulated execution trace with {resource_name.strip()} transformed via {transformation_type.strip().upper()} egressed to {destination.strip()}",
            interception_point=InterceptionPoint.ACTION,
            payload=action_request,
            policies=effective_policies,
            simulated_context={
                "source_resource": resource_name.strip(),
                "declared_properties": ", ".join(props_tuple) if props_tuple else "None",
                "transformation": transformation_type.strip().upper(),
                "action": action_name.strip(),
                "destination": destination.strip(),
            },
        )

        return DemoExecutionResult(
            scenario=scenario,
            step_number=None,
            event=event,
            dag=dag,
            effective_properties=effective_properties,
            risk_result=risk_result,
            arbiter_result=arbiter_result,
            duration_ms=total_elapsed,
        )


def serialize_execution_result(result: DemoExecutionResult) -> dict[str, Any]:
    """Serialize DemoExecutionResult to JSON-compatible dictionary for UI presentation."""
    dag_nodes = []
    dag_edges = []
    if result.dag is not None:
        for node in result.dag.get_nodes():
            effective = result.effective_properties.get(node.node_id, ())
            dag_nodes.append({
                "id": node.node_id,
                "type": node.node_type.name,
                "description": node.description,
                "declared_properties": [p.value if hasattr(p, "value") else str(p) for p in node.safety_properties],
                "effective_properties": list(effective),
                "resource_ref": node.resource_ref,
            })
        for edge in result.dag.get_edges():
            dag_edges.append({
                "source": edge.source_id,
                "target": edge.destination_id,
                "type": edge.edge_type.name,
            })

    evidence_list = []
    for ev in result.evidence:
        evidence_list.append({
            "evidence_id": ev.evidence_id,
            "source_guard": ev.source_guard,
            "risk_category": ev.risk_category.name,
            "risk_type": ev.risk_type,
            "severity": ev.severity.name,
            "confidence": ev.confidence.name,
            "recommended_action": ev.recommended_action.name if ev.recommended_action else None,
            "description": ev.description,
            "affected_entities": list(ev.affected_entities),
            "provenance_refs": list(ev.provenance_refs),
            "supporting_data": dict(ev.supporting_data),
        })

    guard_records = []
    for gr in result.risk_result.guard_results:
        guard_records.append({
            "guard_name": gr.guard_name,
            "status": gr.status.name,
            "findings_count": len(gr.evidence),
            "duration_ms": round(gr.duration_ms, 2),
            "error_message": gr.error_message,
        })

    decisive_evidence_list = []
    for dev in result.arbiter_result.decisive_evidence:
        decisive_evidence_list.append({
            "source_guard": dev.source_guard,
            "risk_type": dev.risk_type,
            "severity": dev.severity.name,
            "recommendation": dev.recommended_action.name if dev.recommended_action else None,
            "description": dev.description,
        })

    # Prepare payload representation
    payload_repr = result.event.payload
    if isinstance(payload_repr, ActionRequest):
        payload_data = {
            "type": "ActionRequest",
            "action_name": payload_repr.action_name,
            "arguments": dict(payload_repr.arguments),
            "destination": payload_repr.destination,
            "provenance_refs": list(payload_repr.provenance_refs),
            "permissions": list(payload_repr.permissions),
        }
    else:
        payload_data = str(payload_repr)

    # Presentation mode summary
    sensitive_props: set[str] = set()
    for props in result.effective_properties.values():
        sensitive_props.update(props)
    for ev in result.evidence:
        violating = ev.supporting_data.get("violating_properties")
        if isinstance(violating, (list, tuple, set)):
            sensitive_props.update(violating)

    destination_val = None
    if isinstance(result.event.payload, ActionRequest):
        destination_val = result.event.payload.destination
    elif isinstance(result.event.payload, Mapping):
        destination_val = result.event.payload.get("destination")

    source_val = None
    if result.dag_nodes and result.dag_nodes[0].get("resource_ref"):
        source_val = result.dag_nodes[0]["resource_ref"]
    elif isinstance(result.event.payload, ActionRequest):
        source_val = result.event.payload.arguments.get("source_resource") or result.event.payload.action_name
    else:
        source_val = result.event.interception_point.name

    presentation_data = {
        "verdict": result.arbiter_result.verdict.name,
        "is_blocked": result.arbiter_result.is_blocked,
        "is_allowed": result.arbiter_result.is_allowed,
        "reason": result.arbiter_result.reason,
        "sensitive_properties": sorted(list(sensitive_props)),
        "source": source_val,
        "destination": destination_val,
    }

    return {
        "presentation": presentation_data,
        "scenario": {
            "id": result.scenario.scenario_id,
            "title": result.scenario.title,
            "category": result.scenario.category,
            "description": result.scenario.description,
            "simulated_context": dict(result.scenario.simulated_context),
            "total_steps": len(result.scenario.steps),
            "current_step": result.step_number,
            "steps": [
                {
                    "step_number": s.step_number,
                    "title": s.title,
                    "description": s.description,
                    "action_type": s.action_type,
                    "detail": s.detail,
                }
                for s in result.scenario.steps
            ],
        },
        "event": {
            "id": result.event.event_id,
            "interception_point": result.event.interception_point.name,
            "payload": payload_data,
        },
        "policies": dict(result.scenario.policies),
        "dag": {
            "nodes": dag_nodes,
            "edges": dag_edges,
        },
        "guards": guard_records,
        "evidence": evidence_list,
        "arbiter": {
            "verdict": result.arbiter_result.verdict.name,
            "reason": result.arbiter_result.reason,
            "reason_code": result.arbiter_result.reason_code,
            "is_blocked": result.arbiter_result.is_blocked,
            "is_allowed": result.arbiter_result.is_allowed,
            "decisive_evidence": decisive_evidence_list,
            "missing_guard_coverage": list(result.arbiter_result.missing_guard_coverage),
        },
        "execution_time_ms": round(result.duration_ms, 2),
    }
