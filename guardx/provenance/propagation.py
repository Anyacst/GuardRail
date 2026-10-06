"""Semantic safety property propagation engine over ActionProvenanceDAG.

Computes effective safety properties deterministically across lineage graphs:
- PRESERVE: Inherited properties are preserved by default.
- REDUCE/REMOVE: Verified trusted transformations may remove specific properties.
- INTRODUCE: Transformations or source nodes can introduce new properties.
- COMBINE: Multiple parent properties are combined (union) conservatively.
- IMMUTABILITY: Operates non-destructively; historical ProvenanceNodes remain untouched.
"""

from collections import deque
from typing import Sequence

from guardx.provenance.dag import ActionProvenanceDAG, ProvenanceNodeNotFoundError
from guardx.provenance.models import ProvenanceNodeType, SafetyProperty, _freeze_properties
from guardx.provenance.rules import TransformationRule, TransformationType


class PropertyPropagationEngine:
    """Deterministic engine for computing effective semantic safety properties on Provenance DAGs.

    Invariants:
    1. Operates over existing ActionProvenanceDAG without modifying the graph or nodes.
    2. Conservative default: unknown transformations preserve all incoming properties.
    3. Property removal requires an explicitly registered TransformationRule with is_trusted_reduction=True.
    4. Multi-parent branches combine properties conservatively via set union.
    5. Pure Python, deterministic, repeatable.
    """

    def __init__(self, rules: Sequence[TransformationRule] | None = None) -> None:
        """Initialize the propagation engine with an optional set of registered TransformationRules.

        Default built-in rules:
        - FORMAT: preserves properties (conservative).
        - SUMMARIZE: preserves properties (summarization does NOT remove confidentiality or PII).
        - VERIFIED_PII_REDACTION: trusted reduction removing PII.
        - VERIFIED_SECRET_REDACTION: trusted reduction removing CREDENTIAL and SECRET.
        - VERIFIED_AGGREGATION: trusted reduction removing PII.
        - EXTERNAL_INGESTION: introduces UNTRUSTED_SOURCE.
        """
        self._rules: dict[str, TransformationRule] = {}

        # Register default standard transformation rules
        self._register_default_rules()

        # Register any custom rules supplied
        if rules:
            for rule in rules:
                self.register_rule(rule)

    def _register_default_rules(self) -> None:
        """Register default transformation rules."""
        self.register_rule(
            TransformationRule(
                rule_id=TransformationType.FORMAT.value,
                description="Formatting or serialization transformation preserving properties",
            )
        )
        self.register_rule(
            TransformationRule(
                rule_id=TransformationType.SUMMARIZE.value,
                description="Summarization transformation preserving confidential and sensitive properties",
            )
        )
        self.register_rule(
            TransformationRule(
                rule_id=TransformationType.VERIFIED_PII_REDACTION.value,
                description="Verified PII redaction/anonymization pipeline",
                is_trusted_reduction=True,
                reduces_properties=(SafetyProperty.PII.value,),
            )
        )
        self.register_rule(
            TransformationRule(
                rule_id=TransformationType.VERIFIED_SECRET_REDACTION.value,
                description="Verified secret and credential redaction filter",
                is_trusted_reduction=True,
                reduces_properties=(SafetyProperty.CREDENTIAL.value, SafetyProperty.SECRET.value),
            )
        )
        self.register_rule(
            TransformationRule(
                rule_id=TransformationType.VERIFIED_AGGREGATION.value,
                description="Verified k-anonymity aggregation removing individual personal identifiers",
                is_trusted_reduction=True,
                reduces_properties=(SafetyProperty.PII.value,),
            )
        )
        self.register_rule(
            TransformationRule(
                rule_id=TransformationType.EXTERNAL_INGESTION.value,
                description="Ingestion from an external untrusted source or document",
                introduces_properties=(SafetyProperty.UNTRUSTED_SOURCE.value,),
            )
        )

    def register_rule(self, rule: TransformationRule) -> None:
        """Register a transformation rule. Overwrites any previous rule with the same rule_id."""
        if not isinstance(rule, TransformationRule):
            raise TypeError(f"rule must be an instance of TransformationRule, got {type(rule)}")
        self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> TransformationRule | None:
        """Get a registered rule by its rule_id, or None if not found."""
        return self._rules.get(rule_id)

    def compute_effective_properties(
        self,
        dag: ActionProvenanceDAG,
        target_node_id: str,
    ) -> tuple[str, ...]:
        """Compute the effective semantic safety properties for target_node_id.

        Traverses the DAG in topological/causal order from root sources down to target_node_id.
        Combines properties from multiple parents and applies transformation rules at each step.

        Args:
            dag: The ActionProvenanceDAG containing the lineage.
            target_node_id: The node ID to compute properties for.

        Returns:
            Sorted, deduplicated tuple of property strings.

        Raises:
            ProvenanceNodeNotFoundError: If target_node_id is not in the DAG.
        """
        if not dag.has_node(target_node_id):
            raise ProvenanceNodeNotFoundError(f"Target node '{target_node_id}' does not exist in DAG")

        # Get all ancestors relevant to target_node_id (plus target_node_id itself)
        ancestor_nodes = dag.get_ancestors(target_node_id)
        relevant_node_ids = {a.node_id for a in ancestor_nodes}
        relevant_node_ids.add(target_node_id)

        # Compute in-degrees within the relevant subgraph
        subgraph_in_degree: dict[str, int] = {nid: 0 for nid in relevant_node_ids}
        for nid in relevant_node_ids:
            parents = dag.get_direct_parents(nid)
            for p in parents:
                if p.node_id in relevant_node_ids:
                    subgraph_in_degree[nid] += 1

        # Queue nodes with 0 in-degree within subgraph (root sources)
        queue: deque[str] = deque(
            sorted([nid for nid, deg in subgraph_in_degree.items() if deg == 0])
        )

        # Memoized effective properties: node_id -> set of properties
        effective: dict[str, set[str]] = {}

        while queue:
            curr_id = queue.popleft()
            node = dag.get_node(curr_id)

            # Start with node's own intrinsic safety_properties
            node_props = set(node.safety_properties)

            # Combine properties from direct parents
            parent_props: set[str] = set()
            for parent in dag.get_direct_parents(curr_id):
                if parent.node_id in relevant_node_ids and parent.node_id in effective:
                    parent_props.update(effective[parent.node_id])

            # Union intrinsic with parent props
            combined_props = parent_props.union(node_props)

            # Check if this node is a TRANSFORMATION or specifies a transformation rule in metadata
            rule = self._resolve_transformation_rule(node)
            if rule is not None:
                # Apply transformation rule to combined properties
                result_props = set(rule.apply(tuple(combined_props)))
            else:
                # Conservative default: preserve all properties
                result_props = combined_props

            effective[curr_id] = result_props

            if curr_id == target_node_id:
                # We can return once target properties are computed
                return tuple(sorted(effective[target_node_id]))

            # Advance BFS
            for child in dag.get_direct_children(curr_id):
                if child.node_id in relevant_node_ids:
                    subgraph_in_degree[child.node_id] -= 1
                    if subgraph_in_degree[child.node_id] == 0:
                        queue.append(child.node_id)

        return tuple(sorted(effective.get(target_node_id, set())))

    def _resolve_transformation_rule(self, node) -> TransformationRule | None:
        """Resolve any transformation rule declared on a node.

        Checks:
        1. Explicit 'transformation_rule' or 'rule_id' or 'transformation_type' in node.metadata.
        2. If node.node_type == TRANSFORMATION, checks description/resource_ref matching known rule_ids.
        3. Returns None if no rule is associated (conservative preservation applied).
        """
        # Metadata check
        rule_key = (
            node.metadata.get("transformation_rule")
            or node.metadata.get("rule_id")
            or node.metadata.get("transformation_type")
        )
        if isinstance(rule_key, TransformationType):
            rule_key = rule_key.value
        if isinstance(rule_key, str) and rule_key in self._rules:
            return self._rules[rule_key]

        # Node type / ID check for TRANSFORMATION nodes
        if node.node_type == ProvenanceNodeType.TRANSFORMATION:
            if node.node_id in self._rules:
                return self._rules[node.node_id]
            if node.description in self._rules:
                return self._rules[node.description]

        return None
