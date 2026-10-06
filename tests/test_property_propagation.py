"""Tests for semantic safety property propagation across ActionProvenanceDAG (Phase 7)."""

import unittest

from guardx.provenance import (
    ActionProvenanceDAG,
    PropertyPropagationEngine,
    ProvenanceEdgeType,
    ProvenanceNode,
    ProvenanceNodeNotFoundError,
    ProvenanceNodeType,
    SafetyProperty,
    TransformationRule,
    TransformationType,
)


class TestPropertyPropagation(unittest.TestCase):
    """Test suite for Phase 7 Semantic Safety Property Propagation."""

    def setUp(self) -> None:
        self.engine = PropertyPropagationEngine()

    def test_typed_property_creation_and_normalization(self) -> None:
        """1. Typed property creation and enum/string normalization."""
        node = ProvenanceNode(
            node_id="n1",
            node_type=ProvenanceNodeType.RESOURCE,
            session_id="s1",
            safety_properties=[SafetyProperty.CONFIDENTIAL, "pii", " financial_data "],
        )
        self.assertEqual(
            node.safety_properties,
            (SafetyProperty.CONFIDENTIAL.value, SafetyProperty.FINANCIAL_DATA.value, SafetyProperty.PII.value),
        )

    def test_duplicate_property_normalization(self) -> None:
        """2. Duplicate property normalization (deduplication & sorting)."""
        node = ProvenanceNode(
            node_id="n1",
            node_type=ProvenanceNodeType.RESOURCE,
            session_id="s1",
            safety_properties=["PII", SafetyProperty.PII, "pii", "PII"],
        )
        self.assertEqual(node.safety_properties, ("PII",))

    def test_direct_preservation(self) -> None:
        """3. Direct preservation: A [PII] -> B [None] preserves PII."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("A", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.PII])
        dag.create_node("B", ProvenanceNodeType.DATA)
        dag.add_edge("A", "B", ProvenanceEdgeType.DERIVED_FROM)

        props = self.engine.compute_effective_properties(dag, "B")
        self.assertEqual(props, (SafetyProperty.PII.value,))

    def test_multi_hop_preservation(self) -> None:
        """4. Multi-hop preservation: A -> B -> C -> D preserves initial properties."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node(
            "A",
            ProvenanceNodeType.RESOURCE,
            safety_properties=[SafetyProperty.CONFIDENTIAL, SafetyProperty.SECRET],
        )
        dag.create_node("B", ProvenanceNodeType.DATA)
        dag.create_node("C", ProvenanceNodeType.DATA)
        dag.create_node("D", ProvenanceNodeType.DATA)

        dag.add_edge("A", "B", ProvenanceEdgeType.READS)
        dag.add_edge("B", "C", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("C", "D", ProvenanceEdgeType.DERIVED_FROM)

        props = self.engine.compute_effective_properties(dag, "D")
        self.assertEqual(
            props,
            (SafetyProperty.CONFIDENTIAL.value, SafetyProperty.SECRET.value),
        )

    def test_unknown_transformation_conservatively_preserves_properties(self) -> None:
        """5. Unknown transformation conservatively preserves properties (anti-laundering)."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("A", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.PII])
        dag.create_node(
            "T",
            ProvenanceNodeType.TRANSFORMATION,
            description="unknown_custom_blackbox_cleaner",
        )
        dag.create_node("B", ProvenanceNodeType.DATA)

        dag.add_edge("A", "T", ProvenanceEdgeType.TRANSFORMS)
        dag.add_edge("T", "B", ProvenanceEdgeType.PRODUCES)

        props = self.engine.compute_effective_properties(dag, "B")
        # Anti-laundering invariant: unknown transformation CANNOT remove PII
        self.assertIn(SafetyProperty.PII.value, props)

    def test_explicitly_trusted_reduction(self) -> None:
        """6. Explicitly trusted reduction removes configured property."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node(
            "A",
            ProvenanceNodeType.DATA,
            safety_properties=[SafetyProperty.PII, SafetyProperty.CONFIDENTIAL],
        )
        dag.create_node(
            "T",
            ProvenanceNodeType.TRANSFORMATION,
            metadata={"transformation_rule": TransformationType.VERIFIED_PII_REDACTION.value},
        )
        dag.create_node("B", ProvenanceNodeType.DATA)

        dag.add_edge("A", "T", ProvenanceEdgeType.TRANSFORMS)
        dag.add_edge("T", "B", ProvenanceEdgeType.PRODUCES)

        props = self.engine.compute_effective_properties(dag, "B")
        # PII is removed, but CONFIDENTIAL remains
        self.assertEqual(props, (SafetyProperty.CONFIDENTIAL.value,))

    def test_reduction_removes_only_configured_property(self) -> None:
        """7. Reduction removes only configured property, leaving other sensitive labels."""
        rule = TransformationRule(
            rule_id="REMOVE_SECRET_ONLY",
            is_trusted_reduction=True,
            reduces_properties=[SafetyProperty.SECRET],
        )
        engine = PropertyPropagationEngine(rules=[rule])

        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node(
            "A",
            ProvenanceNodeType.DATA,
            safety_properties=[SafetyProperty.SECRET, SafetyProperty.FINANCIAL_DATA, SafetyProperty.PII],
        )
        dag.create_node("T", ProvenanceNodeType.TRANSFORMATION, metadata={"rule_id": "REMOVE_SECRET_ONLY"})
        dag.create_node("B", ProvenanceNodeType.DATA)

        dag.add_edge("A", "T", ProvenanceEdgeType.TRANSFORMS)
        dag.add_edge("T", "B", ProvenanceEdgeType.PRODUCES)

        props = engine.compute_effective_properties(dag, "B")
        self.assertEqual(
            props,
            (SafetyProperty.FINANCIAL_DATA.value, SafetyProperty.PII.value),
        )

    def test_introduction_of_property(self) -> None:
        """8. Introduction of property: EXTERNAL_INGESTION introduces UNTRUSTED_SOURCE."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("web_doc", ProvenanceNodeType.RESOURCE, resource_ref="https://example.com/doc")
        dag.create_node(
            "ingest",
            ProvenanceNodeType.TRANSFORMATION,
            metadata={"transformation_rule": TransformationType.EXTERNAL_INGESTION.value},
        )
        dag.create_node("retrieved_text", ProvenanceNodeType.DATA)

        dag.add_edge("web_doc", "ingest", ProvenanceEdgeType.TRANSFORMS)
        dag.add_edge("ingest", "retrieved_text", ProvenanceEdgeType.PRODUCES)

        props = self.engine.compute_effective_properties(dag, "retrieved_text")
        self.assertEqual(props, (SafetyProperty.UNTRUSTED_SOURCE.value,))

    def test_multiple_property_introduction(self) -> None:
        """9. Multiple property introduction via custom rule."""
        custom_rule = TransformationRule(
            rule_id="ENRICH_FINANCIAL_CONFIDENTIAL",
            introduces_properties=[SafetyProperty.FINANCIAL_DATA, SafetyProperty.CONFIDENTIAL],
        )
        engine = PropertyPropagationEngine(rules=[custom_rule])

        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("input", ProvenanceNodeType.DATA)
        dag.create_node("t", ProvenanceNodeType.TRANSFORMATION, metadata={"rule_id": "ENRICH_FINANCIAL_CONFIDENTIAL"})
        dag.create_node("output", ProvenanceNodeType.DATA)

        dag.add_edge("input", "t", ProvenanceEdgeType.TRANSFORMS)
        dag.add_edge("t", "output", ProvenanceEdgeType.PRODUCES)

        props = engine.compute_effective_properties(dag, "output")
        self.assertEqual(
            props,
            (SafetyProperty.CONFIDENTIAL.value, SafetyProperty.FINANCIAL_DATA.value),
        )

    def test_combining_two_parents(self) -> None:
        """10. Combining two parents merges their properties (union)."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("A", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.PII])
        dag.create_node("B", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.CONFIDENTIAL])
        dag.create_node("merged", ProvenanceNodeType.DATA)

        dag.add_edge("A", "merged", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("B", "merged", ProvenanceEdgeType.DERIVED_FROM)

        props = self.engine.compute_effective_properties(dag, "merged")
        self.assertEqual(
            props,
            (SafetyProperty.CONFIDENTIAL.value, SafetyProperty.PII.value),
        )

    def test_combining_three_or_more_parents(self) -> None:
        """11. Combining three or more parents."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("P1", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.PII])
        dag.create_node("P2", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.CREDENTIAL])
        dag.create_node("P3", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.FINANCIAL_DATA])
        dag.create_node("report", ProvenanceNodeType.DATA)

        dag.add_edge("P1", "report", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("P2", "report", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("P3", "report", ProvenanceEdgeType.DERIVED_FROM)

        props = self.engine.compute_effective_properties(dag, "report")
        self.assertEqual(
            props,
            (
                SafetyProperty.CREDENTIAL.value,
                SafetyProperty.FINANCIAL_DATA.value,
                SafetyProperty.PII.value,
            ),
        )

    def test_branching_propagation(self) -> None:
        """12. Branching propagation: A -> B, A -> C (both inherit A's properties)."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node(
            "A",
            ProvenanceNodeType.RESOURCE,
            safety_properties=[SafetyProperty.CONFIDENTIAL],
        )
        dag.create_node("B", ProvenanceNodeType.DATA)
        dag.create_node("C", ProvenanceNodeType.DATA)

        dag.add_edge("A", "B", ProvenanceEdgeType.READS)
        dag.add_edge("A", "C", ProvenanceEdgeType.READS)

        self.assertEqual(self.engine.compute_effective_properties(dag, "B"), (SafetyProperty.CONFIDENTIAL.value,))
        self.assertEqual(self.engine.compute_effective_properties(dag, "C"), (SafetyProperty.CONFIDENTIAL.value,))

    def test_merging_propagation(self) -> None:
        """13. Merging diamond propagation: A -> B, A -> C, B -> D, C -> D."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node(
            "A",
            ProvenanceNodeType.RESOURCE,
            safety_properties=[SafetyProperty.SECRET],
        )
        dag.create_node("B", ProvenanceNodeType.DATA)
        dag.create_node("C", ProvenanceNodeType.DATA)
        dag.create_node("D", ProvenanceNodeType.DATA)

        dag.add_edge("A", "B", ProvenanceEdgeType.READS)
        dag.add_edge("A", "C", ProvenanceEdgeType.READS)
        dag.add_edge("B", "D", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("C", "D", ProvenanceEdgeType.DERIVED_FROM)

        self.assertEqual(self.engine.compute_effective_properties(dag, "D"), (SafetyProperty.SECRET.value,))

    def test_pii_and_confidential_merge(self) -> None:
        """14. PII + CONFIDENTIAL merge."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("name", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.PII])
        dag.create_node("contract", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.CONFIDENTIAL])
        dag.create_node("doc", ProvenanceNodeType.DATA)

        dag.add_edge("name", "doc", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("contract", "doc", ProvenanceEdgeType.DERIVED_FROM)

        props = self.engine.compute_effective_properties(dag, "doc")
        self.assertEqual(props, (SafetyProperty.CONFIDENTIAL.value, SafetyProperty.PII.value))

    def test_pii_and_financial_data_merge(self) -> None:
        """15. PII + FINANCIAL_DATA merge."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("user", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.PII])
        dag.create_node("balance", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.FINANCIAL_DATA])
        dag.create_node("statement", ProvenanceNodeType.DATA)

        dag.add_edge("user", "statement", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("balance", "statement", ProvenanceEdgeType.DERIVED_FROM)

        props = self.engine.compute_effective_properties(dag, "statement")
        self.assertEqual(props, (SafetyProperty.FINANCIAL_DATA.value, SafetyProperty.PII.value))

    def test_untrusted_source_propagation(self) -> None:
        """16. UNTRUSTED_SOURCE propagation into model context."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node(
            "untrusted_web",
            ProvenanceNodeType.RESOURCE,
            safety_properties=[SafetyProperty.UNTRUSTED_SOURCE],
        )
        dag.create_node("extracted_text", ProvenanceNodeType.DATA)
        dag.create_node("prompt_context", ProvenanceNodeType.MODEL_OUTPUT)

        dag.add_edge("untrusted_web", "extracted_text", ProvenanceEdgeType.READS)
        dag.add_edge("extracted_text", "prompt_context", ProvenanceEdgeType.USES)

        props = self.engine.compute_effective_properties(dag, "prompt_context")
        self.assertEqual(props, (SafetyProperty.UNTRUSTED_SOURCE.value,))

    def test_summarization_does_not_silently_remove_confidentiality(self) -> None:
        """17. Crucial test: summarization does NOT remove CONFIDENTIAL or PII."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node(
            "raw_doc",
            ProvenanceNodeType.DATA,
            safety_properties=[SafetyProperty.CONFIDENTIAL, SafetyProperty.PII],
        )
        dag.create_node(
            "summary_tool",
            ProvenanceNodeType.TRANSFORMATION,
            metadata={"transformation_rule": TransformationType.SUMMARIZE.value},
        )
        dag.create_node("summary", ProvenanceNodeType.DATA)

        dag.add_edge("raw_doc", "summary_tool", ProvenanceEdgeType.TRANSFORMS)
        dag.add_edge("summary_tool", "summary", ProvenanceEdgeType.PRODUCES)

        props = self.engine.compute_effective_properties(dag, "summary")
        # Must retain both
        self.assertIn(SafetyProperty.CONFIDENTIAL.value, props)
        self.assertIn(SafetyProperty.PII.value, props)

    def test_format_conversion_preserves_properties(self) -> None:
        """18. Format conversion preserves all properties."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("json_data", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.SECRET])
        dag.create_node(
            "formatter",
            ProvenanceNodeType.TRANSFORMATION,
            metadata={"transformation_rule": TransformationType.FORMAT.value},
        )
        dag.create_node("yaml_data", ProvenanceNodeType.DATA)

        dag.add_edge("json_data", "formatter", ProvenanceEdgeType.TRANSFORMS)
        dag.add_edge("formatter", "yaml_data", ProvenanceEdgeType.PRODUCES)

        props = self.engine.compute_effective_properties(dag, "yaml_data")
        self.assertEqual(props, (SafetyProperty.SECRET.value,))

    def test_explicit_verified_redaction_removes_pii_where_configured(self) -> None:
        """19. Explicit verified redaction removes PII."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("doc", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.PII])
        dag.create_node(
            "redactor",
            ProvenanceNodeType.TRANSFORMATION,
            metadata={"transformation_rule": TransformationType.VERIFIED_PII_REDACTION.value},
        )
        dag.create_node("clean_doc", ProvenanceNodeType.DATA)

        dag.add_edge("doc", "redactor", ProvenanceEdgeType.TRANSFORMS)
        dag.add_edge("redactor", "clean_doc", ProvenanceEdgeType.PRODUCES)

        props = self.engine.compute_effective_properties(dag, "clean_doc")
        self.assertEqual(props, ())

    def test_verified_redaction_does_not_automatically_remove_confidential(self) -> None:
        """20. Verified PII redaction does NOT remove CONFIDENTIAL."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node(
            "doc",
            ProvenanceNodeType.DATA,
            safety_properties=[SafetyProperty.PII, SafetyProperty.CONFIDENTIAL],
        )
        dag.create_node(
            "redactor",
            ProvenanceNodeType.TRANSFORMATION,
            metadata={"transformation_rule": TransformationType.VERIFIED_PII_REDACTION.value},
        )
        dag.create_node("clean_doc", ProvenanceNodeType.DATA)

        dag.add_edge("doc", "redactor", ProvenanceEdgeType.TRANSFORMS)
        dag.add_edge("redactor", "clean_doc", ProvenanceEdgeType.PRODUCES)

        props = self.engine.compute_effective_properties(dag, "clean_doc")
        self.assertEqual(props, (SafetyProperty.CONFIDENTIAL.value,))

    def test_source_node_with_no_properties(self) -> None:
        """21. Source node with no properties results in empty effective properties downstream."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("public_file", ProvenanceNodeType.RESOURCE, resource_ref="public.txt")
        dag.create_node("content", ProvenanceNodeType.DATA)

        dag.add_edge("public_file", "content", ProvenanceEdgeType.READS)
        props = self.engine.compute_effective_properties(dag, "content")
        self.assertEqual(props, ())

    def test_unknown_node_behavior(self) -> None:
        """22. Unknown node raises ProvenanceNodeNotFoundError."""
        dag = ActionProvenanceDAG(session_id="s1")
        with self.assertRaises(ProvenanceNodeNotFoundError):
            self.engine.compute_effective_properties(dag, "non_existent")

    def test_untrusted_reduction_ignored(self) -> None:
        """23. If is_trusted_reduction is False, reduction attempts are ignored."""
        untrusted_rule = TransformationRule(
            rule_id="FAKE_CLEANER",
            is_trusted_reduction=False,
            reduces_properties=[SafetyProperty.PII],
        )
        engine = PropertyPropagationEngine(rules=[untrusted_rule])

        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("data", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.PII])
        dag.create_node("cleaner", ProvenanceNodeType.TRANSFORMATION, metadata={"rule_id": "FAKE_CLEANER"})
        dag.create_node("out", ProvenanceNodeType.DATA)

        dag.add_edge("data", "cleaner", ProvenanceEdgeType.TRANSFORMS)
        dag.add_edge("cleaner", "out", ProvenanceEdgeType.PRODUCES)

        props = engine.compute_effective_properties(dag, "out")
        # Untrusted rule cannot remove PII
        self.assertIn(SafetyProperty.PII.value, props)

    def test_original_provenance_node_remains_immutable(self) -> None:
        """24. Original ProvenanceNode objects remain completely immutable after propagation."""
        dag = ActionProvenanceDAG(session_id="s1")
        node_a = dag.create_node("A", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.PII])
        node_b = dag.create_node("B", ProvenanceNodeType.DATA)

        dag.add_edge("A", "B", ProvenanceEdgeType.DERIVED_FROM)
        props_b = self.engine.compute_effective_properties(dag, "B")

        self.assertEqual(props_b, (SafetyProperty.PII.value,))
        # Node B's own intrinsic safety_properties remain empty tuple
        self.assertEqual(node_b.safety_properties, ())
        # Node A remains untouched
        self.assertEqual(node_a.safety_properties, (SafetyProperty.PII.value,))

    def test_deterministic_repeated_propagation(self) -> None:
        """25. Repeated propagation computations yield identical results."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("n1", ProvenanceNodeType.DATA, safety_properties=[SafetyProperty.CREDENTIAL])
        dag.create_node("n2", ProvenanceNodeType.DATA)
        dag.add_edge("n1", "n2", ProvenanceEdgeType.DERIVED_FROM)

        first_run = self.engine.compute_effective_properties(dag, "n2")
        for _ in range(5):
            repeated_run = self.engine.compute_effective_properties(dag, "n2")
            self.assertEqual(first_run, repeated_run)

    def test_dag_convenience_method_get_effective_properties(self) -> None:
        """26. Test ActionProvenanceDAG.get_effective_properties convenience method."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("src", ProvenanceNodeType.RESOURCE, safety_properties=[SafetyProperty.FINANCIAL_DATA])
        dag.create_node("dst", ProvenanceNodeType.DATA)
        dag.add_edge("src", "dst", ProvenanceEdgeType.READS)

        props = dag.get_effective_properties("dst")
        self.assertEqual(props, (SafetyProperty.FINANCIAL_DATA.value,))

    def test_primary_showcase_customers_csv_propagation(self) -> None:
        """27. Primary showcase scenario:

        customers.csv [PII, CONFIDENTIAL]
              |
              v (READS)
        customer_data [PII, CONFIDENTIAL]
              |
              v (TRANSFORMS: SUMMARIZE)
           summary [PII, CONFIDENTIAL]
              |
              v (USES)
          send_email (TOOL_CALL / ACTION)

        Verify that summary and send_email retain CONFIDENTIAL and PII safety context.
        """
        dag = ActionProvenanceDAG(session_id="showcase-session")

        # 1. Source resource with sensitive properties
        dag.create_node(
            node_id="res:customers.csv",
            node_type=ProvenanceNodeType.RESOURCE,
            resource_ref="customers.csv",
            safety_properties=[SafetyProperty.PII, SafetyProperty.CONFIDENTIAL],
        )

        # 2. In-memory loaded data
        dag.create_node(
            node_id="data:customer_data",
            node_type=ProvenanceNodeType.DATA,
            description="Loaded customer records",
        )
        dag.add_edge("res:customers.csv", "data:customer_data", ProvenanceEdgeType.READS)

        # 3. Summarization step
        dag.create_node(
            node_id="trans:summarize",
            node_type=ProvenanceNodeType.TRANSFORMATION,
            description="Summarize customer records",
            metadata={"transformation_rule": TransformationType.SUMMARIZE.value},
        )
        dag.add_edge("data:customer_data", "trans:summarize", ProvenanceEdgeType.TRANSFORMS)

        # 4. Resulting summary data
        dag.create_node(
            node_id="data:summary",
            node_type=ProvenanceNodeType.DATA,
            description="Aggregated customer summary",
        )
        dag.add_edge("trans:summarize", "data:summary", ProvenanceEdgeType.PRODUCES)

        # 5. Outgoing action
        dag.create_node(
            node_id="action:send_email",
            node_type=ProvenanceNodeType.TOOL_CALL,
            description="send_email external tool invocation",
        )
        dag.add_edge("data:summary", "action:send_email", ProvenanceEdgeType.USES)

        # Compute effective properties of data:summary
        summary_props = dag.get_effective_properties("data:summary")
        self.assertIn(SafetyProperty.CONFIDENTIAL.value, summary_props)
        self.assertIn(SafetyProperty.PII.value, summary_props)

        # Compute effective properties available at action:send_email
        action_props = dag.get_effective_properties("action:send_email")
        self.assertIn(SafetyProperty.CONFIDENTIAL.value, action_props)
        self.assertIn(SafetyProperty.PII.value, action_props)


if __name__ == "__main__":
    unittest.main()
