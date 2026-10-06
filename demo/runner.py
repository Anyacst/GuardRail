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
from typing import Any, Optional

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
    PropertyPropagationEngine,
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

        # Run actual GuardX pipeline based on interception point
        if scenario.interception_point == InterceptionPoint.INPUT:
            # 1. Concurrent Guard Orchestration via RiskEngine
            risk_result = asyncio.run(self._risk_engine.evaluate(context))
            # 2. Deterministic Arbitration
            arbiter_result = self._arbiter.arbitrate(risk_result)

        elif scenario.interception_point == InterceptionPoint.ACTION:
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

        else:
            raise ValueError(f"Unsupported interception point: {scenario.interception_point}")

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

    return {
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
