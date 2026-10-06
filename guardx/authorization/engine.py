"""ActionAuthorizationEngine implementation.

Deterministic pre-execution inspection of proposed ACTION events.
Evaluates action details, permissions, destination restrictions, and effective
safety properties from the ActionProvenanceDAG.

Emits structured Evidence for the Arbiter (does NOT make the final Verdict).
"""

from collections.abc import Mapping
from typing import Any, Optional, Sequence
from urllib.parse import urlparse

from guardx.authorization.models import ActionRequest, AuthorizationRiskType
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
from guardx.provenance.dag import ActionProvenanceDAG, ProvenanceNodeNotFoundError
from guardx.provenance.models import SafetyProperty
from guardx.provenance.propagation import PropertyPropagationEngine


def _get_policy_dict(context: EvaluationContext) -> Optional[Mapping[str, Any]]:
    """Retrieve policy dictionary from EvaluationContext."""
    policies = context.policies
    if not policies or not isinstance(policies, Mapping):
        return policies
    if "policy" in policies and isinstance(policies["policy"], Mapping):
        return policies["policy"]
    return policies


def _extract_destination_domain(destination: str | None) -> str | None:
    """Extract clean domain/host from destination string (email, URL, or domain)."""
    if not destination or not isinstance(destination, str):
        return None
    d = destination.strip()
    if not d:
        return None
    if "://" in d:
        parsed = urlparse(d)
        host = parsed.hostname or parsed.netloc
        return host.lower() if host else None
    if "@" in d:
        domain = d.split("@")[-1].strip()
        return domain.lower() if domain else None
    return d.lower()


class ActionAuthorizationEngine:
    """Pre-execution authorization engine for ACTION events.

    Invariants:
    1. Produces structured Evidence; Arbiter produces final Verdict.
    2. Deterministic, inspectable, and auditable.
    3. Leverages ActionProvenanceDAG and PropertyPropagationEngine to trace effective safety properties.
    4. Evaluates application policy constraints:
       - required permissions for actions
       - human review requirements for sensitive actions
       - data transfer restrictions (e.g. forbid external transfer of CONFIDENTIAL, PII, etc.)
       - destination restrictions (allowed/external destinations)
    """

    def __init__(
        self,
        propagation_engine: Optional[PropertyPropagationEngine] = None,
    ) -> None:
        self._propagation_engine = propagation_engine or PropertyPropagationEngine()

    def authorize(
        self,
        context: EvaluationContext,
        dag: Optional[ActionProvenanceDAG] = None,
    ) -> Sequence[Evidence]:
        """Inspect the proposed action in context and return structured authorization Evidence.

        Args:
            context: The EvaluationContext containing the SafetyEvent(ACTION) and policies.
            dag: Optional ActionProvenanceDAG representing execution and data lineage.
                If not provided, attempts to find DAG in context.provenance_context["dag"].

        Returns:
            Sequence of Evidence objects (empty if no policy/safety issues found).
        """
        event = context.event
        if event.interception_point != InterceptionPoint.ACTION:
            # ActionAuthorization only evaluates ACTION events
            return ()

        # Resolve ActionRequest from event
        try:
            action_request = self._resolve_action_request(event)
        except (ValueError, TypeError) as exc:
            return (
                Evidence(
                    source_guard="ActionAuthorizationEngine",
                    guard_version="1.0.0",
                    risk_category=RiskCategory.POLICY,
                    risk_type=AuthorizationRiskType.MALFORMED_ACTION_REQUEST.value,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"Action request is malformed: {str(exc)}",
                    affected_entities=(event.event_id,),
                    supporting_data={"error": str(exc)},
                    recommended_action=RecommendedAction.BLOCK,
                ),
            )

        policy = _get_policy_dict(context) or {}
        findings: list[Evidence] = []

        # -------------------------------------------------------------
        # 1. Validate Policy Structure
        # -------------------------------------------------------------
        policy_validation_evidence = self._validate_policy_structure(policy, event.event_id)
        if policy_validation_evidence:
            return policy_validation_evidence

        # -------------------------------------------------------------
        # 2. Check Action Permissions
        # -------------------------------------------------------------
        perm_evidence = self._check_permissions(action_request, policy, event.event_id)
        if perm_evidence:
            findings.extend(perm_evidence)

        # -------------------------------------------------------------
        # 3. Check Human Review Requirements
        # -------------------------------------------------------------
        review_evidence = self._check_human_review(action_request, policy, event.event_id)
        if review_evidence:
            findings.extend(review_evidence)

        # -------------------------------------------------------------
        # 4. Check Provenance & Data Transfer Restrictions
        # -------------------------------------------------------------
        resolved_dag = dag
        if resolved_dag is None and isinstance(context.provenance_context, Mapping):
            resolved_dag = context.provenance_context.get("dag")

        data_transfer_evidence = self._check_data_transfer(
            request=action_request,
            policy=policy,
            event_id=event.event_id,
            dag=resolved_dag,
        )

        if data_transfer_evidence:
            findings.extend(data_transfer_evidence)

        return tuple(findings)

    def _resolve_action_request(self, event: SafetyEvent) -> ActionRequest:
        """Parse or extract an ActionRequest from SafetyEvent."""
        payload = event.payload

        if isinstance(payload, ActionRequest):
            return payload

        if isinstance(payload, dict):
            # Extract action_name
            action_name = None
            for key in ("action", "action_name", "name", "tool", "tool_name", "command"):
                if key in payload and isinstance(payload[key], str) and payload[key].strip():
                    action_name = payload[key].strip()
                    break

            if not action_name:
                raise ValueError("Could not extract action_name from event payload dictionary")

            args = payload.get("arguments") or payload.get("args") or payload.get("parameters") or {}
            if not isinstance(args, Mapping):
                args = {}

            # Destination from top-level or arguments
            destination = payload.get("destination") or payload.get("to") or payload.get("url") or payload.get("domain")
            if not destination and isinstance(args, Mapping):
                destination = args.get("destination") or args.get("to") or args.get("url") or args.get("domain")
            if destination is not None and not isinstance(destination, str):
                raise TypeError("destination must be a string")

            # Provenance refs from payload or event
            prov_refs = payload.get("provenance_refs") or event.provenance_refs or ()
            if not isinstance(prov_refs, (list, tuple)):
                raise TypeError("provenance_refs must be a sequence")

            # Permissions from payload or metadata
            perms = payload.get("permissions") or event.metadata.get("permissions") or ()
            if not isinstance(perms, (list, tuple)):
                raise TypeError("permissions must be a sequence")

            return ActionRequest(
                action_name=action_name,
                arguments=dict(args),
                destination=destination,
                provenance_refs=tuple(prov_refs),
                permissions=tuple(perms),
                metadata=dict(payload.get("metadata") or {}),
            )

        if isinstance(payload, str) and payload.strip():
            # String representation like send_email(to="...")
            prov_refs = event.provenance_refs or ()
            perms = event.metadata.get("permissions") or ()
            return ActionRequest(
                action_name=payload.strip().split("(")[0].strip(),
                arguments={"raw_command": payload.strip()},
                destination=None,
                provenance_refs=tuple(prov_refs),
                permissions=tuple(perms),
            )

        raise ValueError(f"Unsupported event payload type: {type(payload)}")

    def _validate_policy_structure(self, policy: Mapping[str, Any], event_id: str) -> Sequence[Evidence]:
        """Validate structure of authorization policy fields."""
        sequence_fields = [
            "required_permissions",
            "forbidden_data_transfers",
            "external_destinations",
            "allowed_destinations",
        ]
        for field_name in sequence_fields:
            if field_name in policy:
                val = policy[field_name]
                if not isinstance(val, (list, tuple, set, Mapping)):
                    return (
                        Evidence(
                            source_guard="ActionAuthorizationEngine",
                            guard_version="1.0.0",
                            risk_category=RiskCategory.POLICY,
                            risk_type=AuthorizationRiskType.MALFORMED_ACTION_REQUEST.value,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=f"Policy field '{field_name}' must be a sequence or mapping.",
                            affected_entities=(event_id,),
                            supporting_data={"field": field_name},
                            recommended_action=RecommendedAction.BLOCK,
                        ),
                    )
        return ()

    def _check_permissions(
        self,
        request: ActionRequest,
        policy: Mapping[str, Any],
        event_id: str,
    ) -> Sequence[Evidence]:
        """Check if action requires permissions that are missing."""
        req_perms_config = policy.get("required_permissions")
        if not req_perms_config or not isinstance(req_perms_config, Mapping):
            return ()

        # Look up required permission for this action
        required = req_perms_config.get(request.action_name)
        if not required:
            return ()

        required_set = {required} if isinstance(required, str) else set(required)
        granted_set = set(request.permissions)

        missing = required_set - granted_set
        if missing:
            return (
                Evidence(
                    source_guard="ActionAuthorizationEngine",
                    guard_version="1.0.0",
                    risk_category=RiskCategory.POLICY,
                    risk_type=AuthorizationRiskType.MISSING_ACTION_PERMISSION.value,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Action '{request.action_name}' requires permission(s) "
                        f"{sorted(list(missing))} but only {sorted(list(granted_set))} granted."
                    ),
                    affected_entities=(event_id,),
                    supporting_data={
                        "action": request.action_name,
                        "missing_permissions": sorted(list(missing)),
                    },
                    recommended_action=RecommendedAction.BLOCK,
                ),
            )
        return ()

    def _check_human_review(
        self,
        request: ActionRequest,
        policy: Mapping[str, Any],
        event_id: str,
    ) -> Sequence[Evidence]:
        """Check if action specifically requires human review."""
        review_actions = policy.get("require_human_review") or policy.get("action_require_human_review")
        if review_actions and isinstance(review_actions, (list, tuple, set)):
            for r in review_actions:
                if isinstance(r, str) and r.strip().lower() == request.action_name.lower():
                    return (
                        Evidence(
                            source_guard="ActionAuthorizationEngine",
                            guard_version="1.0.0",
                            risk_category=RiskCategory.POLICY,
                            risk_type=AuthorizationRiskType.ACTION_HUMAN_REVIEW_REQUIRED.value,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            description=f"Action '{request.action_name}' requires human approval per policy.",
                            affected_entities=(event_id,),
                            supporting_data={"action": request.action_name},
                            recommended_action=RecommendedAction.HUMAN_REVIEW,
                        ),
                    )
        return ()

    def _check_data_transfer(
        self,
        request: ActionRequest,
        policy: Mapping[str, Any],
        event_id: str,
        dag: Optional[ActionProvenanceDAG],
    ) -> Sequence[Evidence]:
        """Inspect data consumed by action and enforce transfer/egress policies."""
        if not request.provenance_refs:
            # Action has no provenance references: check if policy forbids untracked actions
            if policy.get("require_provenance_for_actions", False):
                return (
                    Evidence(
                        source_guard="ActionAuthorizationEngine",
                        guard_version="1.0.0",
                        risk_category=RiskCategory.POLICY,
                        risk_type=AuthorizationRiskType.RESTRICTED_RESOURCE_USE.value,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"Action '{request.action_name}' requires provenance reference but none provided.",
                        affected_entities=(event_id,),
                        supporting_data={"action": request.action_name},
                        recommended_action=RecommendedAction.BLOCK,
                    ),
                )
            return ()

        if dag is None:
            # Action claims to consume provenance, but DAG is missing
            return (
                Evidence(
                    source_guard="ActionAuthorizationEngine",
                    guard_version="1.0.0",
                    risk_category=RiskCategory.POLICY,
                    risk_type=AuthorizationRiskType.RESTRICTED_RESOURCE_USE.value,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Action '{request.action_name}' references provenance {request.provenance_refs} "
                        "but no Provenance DAG was provided for verification."
                    ),
                    affected_entities=(event_id,),
                    supporting_data={"action": request.action_name},
                    recommended_action=RecommendedAction.BLOCK,
                ),
            )

        # Collect effective safety properties from all consumed provenance nodes
        all_effective_properties: set[str] = set()
        for pref in request.provenance_refs:
            try:
                props = self._propagation_engine.compute_effective_properties(dag, pref)
                all_effective_properties.update(props)
            except ProvenanceNodeNotFoundError:
                return (
                    Evidence(
                        source_guard="ActionAuthorizationEngine",
                        guard_version="1.0.0",
                        risk_category=RiskCategory.POLICY,
                        risk_type=AuthorizationRiskType.RESTRICTED_RESOURCE_USE.value,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            f"Action '{request.action_name}' references non-existent "
                            f"provenance node '{pref}'."
                        ),
                        affected_entities=(event_id,),
                        supporting_data={"action": request.action_name, "missing_ref": pref},
                        recommended_action=RecommendedAction.BLOCK,
                    ),
                )

        if not all_effective_properties:
            # Consumed data carries no sensitive safety properties
            return ()

        # Determine if destination is external or restricted
        dest_domain = _extract_destination_domain(request.destination)
        is_external = self._is_external_destination(dest_domain, policy)

        # Evaluate forbidden data transfer rules
        # Policy format e.g.:
        # "forbid_external_transfer_of": ["CONFIDENTIAL", "PII", "SECRET", "FINANCIAL_DATA"]
        # or "forbidden_data_transfers": {"external": ["CONFIDENTIAL", "PII"]}
        forbidden_properties: set[str] = set()

        forbid_external = (
            policy.get("forbid_external_transfer_of")
            or policy.get("forbid_external_data_properties")
            or []
        )
        if is_external and isinstance(forbid_external, (list, tuple, set)):
            for p in forbid_external:
                if isinstance(p, str):
                    forbidden_properties.add(p.strip().upper())

        # Also support destination-specific transfer rules:
        # "forbidden_data_transfers": [{"destination_domain": "...", "properties": ["..."]}]
        dt_rules = policy.get("forbidden_data_transfers")
        if isinstance(dt_rules, (list, tuple)):
            for r in dt_rules:
                if isinstance(r, Mapping):
                    rule_dest = r.get("destination") or r.get("destination_domain")
                    rule_props = r.get("properties") or []
                    if (
                        rule_dest == "*"
                        or (is_external and rule_dest == "external")
                        or (dest_domain and rule_dest and dest_domain == rule_dest.lower())
                    ):
                        for p in rule_props:
                            if isinstance(p, str):
                                forbidden_properties.add(p.strip().upper())

        # Check for intersection between effective properties and forbidden properties
        violating_properties = all_effective_properties.intersection(forbidden_properties)
        if violating_properties:
            dest_desc = f"'{request.destination}'" if request.destination else "external destination"
            return (
                Evidence(
                    source_guard="ActionAuthorizationEngine",
                    guard_version="1.0.0",
                    risk_category=RiskCategory.POLICY,
                    risk_type=AuthorizationRiskType.UNAUTHORIZED_SENSITIVE_DATA_TRANSFER.value,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Action '{request.action_name}' attempts unauthorized transfer of "
                        f"{sorted(list(violating_properties))} data to {dest_desc}."
                    ),
                    affected_entities=(event_id,),
                    provenance_refs=request.provenance_refs,
                    supporting_data={
                        "action": request.action_name,
                        "destination": request.destination,
                        "violating_properties": sorted(list(violating_properties)),
                        "effective_properties": sorted(list(all_effective_properties)),
                    },
                    recommended_action=RecommendedAction.BLOCK,
                ),
            )

        return ()

    def _is_external_destination(self, dest_domain: str | None, policy: Mapping[str, Any]) -> bool:
        """Determine if a destination is classified as external according to policy."""
        if not dest_domain:
            # If no destination specified, check default transfer posture
            return policy.get("treat_unspecified_destination_as_external", False)

        # If explicit external_destinations / external_domains list provided
        external_list = policy.get("external_destinations") or policy.get("external_domains")
        if external_list is not None and isinstance(external_list, (list, tuple, set)):
            return any(
                isinstance(ext, str) and (dest_domain == ext.lower() or dest_domain.endswith(f".{ext.lower()}"))
                for ext in external_list
            )

        # If allowed_internal_domains provided, anything NOT in internal list is external
        internal_list = policy.get("allowed_internal_domains") or policy.get("internal_domains")
        if internal_list is not None and isinstance(internal_list, (list, tuple, set)):
            is_internal = any(
                isinstance(internal, str)
                and (dest_domain == internal.lower() or dest_domain.endswith(f".{internal.lower()}"))
                for internal in internal_list
            )
            return not is_internal

        # Conservative default: if destination cannot be verified internal, treat as external
        return True
