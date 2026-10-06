"""Tests for ActionProvenanceDAG and provenance models (Phase 6)."""

import unittest
from datetime import datetime

from guardx.provenance import (
    ActionProvenanceDAG,
    DuplicateProvenanceNodeError,
    ProvenanceCycleError,
    ProvenanceEdge,
    ProvenanceEdgeType,
    ProvenanceNode,
    ProvenanceNodeNotFoundError,
    ProvenanceNodeType,
    SessionMismatchError,
)


class TestActionProvenanceDAG(unittest.TestCase):
    """Test suite for ActionProvenanceDAG."""

    def test_create_empty_dag(self) -> None:
        """1. Create empty DAG."""
        dag = ActionProvenanceDAG(session_id="session-1")
        self.assertEqual(len(dag), 0)
        self.assertEqual(dag.session_id, "session-1")
        self.assertEqual(dag.get_edges(), [])

    def test_add_node(self) -> None:
        """2. Add node to DAG."""
        dag = ActionProvenanceDAG(session_id="session-1")
        node = ProvenanceNode(
            node_id="node-1",
            node_type=ProvenanceNodeType.USER_INPUT,
            session_id="session-1",
            description="Initial prompt",
        )
        added = dag.add_node(node)
        self.assertIs(added, node)
        self.assertEqual(len(dag), 1)
        self.assertTrue(dag.has_node("node-1"))
        self.assertEqual(dag.get_node("node-1").description, "Initial prompt")

    def test_duplicate_node_rejection(self) -> None:
        """3. Duplicate node ID rejection."""
        dag = ActionProvenanceDAG(session_id="session-1")
        dag.create_node(
            node_id="node-1",
            node_type=ProvenanceNodeType.RESOURCE,
            description="Resource 1",
        )
        with self.assertRaises(DuplicateProvenanceNodeError):
            dag.create_node(
                node_id="node-1",
                node_type=ProvenanceNodeType.DATA,
                description="Duplicate",
            )

    def test_retrieve_node(self) -> None:
        """4. Retrieve node by ID."""
        dag = ActionProvenanceDAG(session_id="session-1")
        dag.create_node(
            node_id="res-1",
            node_type=ProvenanceNodeType.RESOURCE,
            resource_ref="customers.csv",
        )
        node = dag.get_node("res-1")
        self.assertEqual(node.node_id, "res-1")
        self.assertEqual(node.resource_ref, "customers.csv")
        self.assertEqual(node.node_type, ProvenanceNodeType.RESOURCE)

    def test_add_valid_edge(self) -> None:
        """5. Add valid edge."""
        dag = ActionProvenanceDAG(session_id="session-1")
        dag.create_node("n1", ProvenanceNodeType.RESOURCE, resource_ref="file.txt")
        dag.create_node("n2", ProvenanceNodeType.DATA, description="file_content")

        edge = dag.add_edge("n1", "n2", ProvenanceEdgeType.READS)
        self.assertIsInstance(edge, ProvenanceEdge)
        self.assertEqual(edge.source_id, "n1")
        self.assertEqual(edge.destination_id, "n2")
        self.assertEqual(edge.edge_type, ProvenanceEdgeType.READS)
        self.assertEqual(len(dag.get_edges()), 1)

    def test_missing_source_rejection(self) -> None:
        """6. Missing source node rejection."""
        dag = ActionProvenanceDAG(session_id="session-1")
        dag.create_node("n2", ProvenanceNodeType.DATA)
        with self.assertRaises(ProvenanceNodeNotFoundError):
            dag.add_edge("missing-src", "n2", ProvenanceEdgeType.PRODUCES)

    def test_missing_destination_rejection(self) -> None:
        """7. Missing destination node rejection."""
        dag = ActionProvenanceDAG(session_id="session-1")
        dag.create_node("n1", ProvenanceNodeType.DATA)
        with self.assertRaises(ProvenanceNodeNotFoundError):
            dag.add_edge("n1", "missing-dst", ProvenanceEdgeType.PRODUCES)

    def test_duplicate_edge_behavior(self) -> None:
        """8. Duplicate edge behavior is idempotent."""
        dag = ActionProvenanceDAG(session_id="session-1")
        dag.create_node("n1", ProvenanceNodeType.DATA)
        dag.create_node("n2", ProvenanceNodeType.DATA)

        e1 = dag.add_edge("n1", "n2", ProvenanceEdgeType.DERIVED_FROM)
        e2 = dag.add_edge("n1", "n2", ProvenanceEdgeType.DERIVED_FROM)
        self.assertIs(e1, e2)
        self.assertEqual(len(dag.get_edges()), 1)
        self.assertEqual(len(dag.get_direct_children("n1")), 1)

    def test_direct_parent_query(self) -> None:
        """9. Direct parent query."""
        dag = ActionProvenanceDAG(session_id="session-1")
        dag.create_node("p1", ProvenanceNodeType.DATA)
        dag.create_node("p2", ProvenanceNodeType.DATA)
        dag.create_node("child", ProvenanceNodeType.TRANSFORMATION)

        dag.add_edge("p1", "child", ProvenanceEdgeType.TRANSFORMS)
        dag.add_edge("p2", "child", ProvenanceEdgeType.TRANSFORMS)

        parents = dag.get_direct_parents("child")
        parent_ids = [p.node_id for p in parents]
        self.assertEqual(parent_ids, ["p1", "p2"])

    def test_direct_child_query(self) -> None:
        """10. Direct child query."""
        dag = ActionProvenanceDAG(session_id="session-1")
        dag.create_node("parent", ProvenanceNodeType.DATA)
        dag.create_node("c1", ProvenanceNodeType.DATA)
        dag.create_node("c2", ProvenanceNodeType.TOOL_CALL)

        dag.add_edge("parent", "c1", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("parent", "c2", ProvenanceEdgeType.USES)

        children = dag.get_direct_children("parent")
        child_ids = [c.node_id for c in children]
        self.assertEqual(child_ids, ["c1", "c2"])

    def test_ancestor_query(self) -> None:
        """11. Ancestor query."""
        dag = ActionProvenanceDAG(session_id="session-1")
        dag.create_node("A", ProvenanceNodeType.RESOURCE)
        dag.create_node("B", ProvenanceNodeType.DATA)
        dag.create_node("C", ProvenanceNodeType.TRANSFORMATION)
        dag.create_node("D", ProvenanceNodeType.DATA)

        dag.add_edge("A", "B", ProvenanceEdgeType.READS)
        dag.add_edge("B", "C", ProvenanceEdgeType.TRANSFORMS)
        dag.add_edge("C", "D", ProvenanceEdgeType.PRODUCES)

        ancestors = dag.get_ancestors("D")
        ancestor_ids = [a.node_id for a in ancestors]
        self.assertEqual(ancestor_ids, ["C", "B", "A"])

    def test_descendant_query(self) -> None:
        """12. Descendant query."""
        dag = ActionProvenanceDAG(session_id="session-1")
        dag.create_node("A", ProvenanceNodeType.RESOURCE)
        dag.create_node("B", ProvenanceNodeType.DATA)
        dag.create_node("C", ProvenanceNodeType.DATA)

        dag.add_edge("A", "B", ProvenanceEdgeType.READS)
        dag.add_edge("B", "C", ProvenanceEdgeType.DERIVED_FROM)

        descendants = dag.get_descendants("A")
        descendant_ids = [d.node_id for d in descendants]
        self.assertEqual(descendant_ids, ["B", "C"])

    def test_linear_lineage(self) -> None:
        """13. Linear lineage chain: A -> B -> C -> D."""
        dag = ActionProvenanceDAG(session_id="s1")
        for name in ["A", "B", "C", "D"]:
            dag.create_node(name, ProvenanceNodeType.DATA)

        dag.add_edge("A", "B", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("B", "C", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("C", "D", ProvenanceEdgeType.DERIVED_FROM)

        self.assertTrue(dag.derives_from("D", "A"))
        self.assertTrue(dag.derives_from("D", "B"))
        self.assertTrue(dag.derives_from("D", "C"))
        self.assertFalse(dag.derives_from("A", "D"))

    def test_branching(self) -> None:
        """14. Branching lineage: A -> B, A -> C."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("A", ProvenanceNodeType.DATA)
        dag.create_node("B", ProvenanceNodeType.DATA)
        dag.create_node("C", ProvenanceNodeType.DATA)

        dag.add_edge("A", "B", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("A", "C", ProvenanceEdgeType.DERIVED_FROM)

        self.assertEqual([c.node_id for c in dag.get_direct_children("A")], ["B", "C"])
        self.assertTrue(dag.derives_from("B", "A"))
        self.assertTrue(dag.derives_from("C", "A"))
        self.assertFalse(dag.derives_from("B", "C"))

    def test_merging(self) -> None:
        """15. Merging lineage: B -> D, C -> D."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("B", ProvenanceNodeType.DATA)
        dag.create_node("C", ProvenanceNodeType.DATA)
        dag.create_node("D", ProvenanceNodeType.DATA)

        dag.add_edge("B", "D", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("C", "D", ProvenanceEdgeType.DERIVED_FROM)

        parents = [p.node_id for p in dag.get_direct_parents("D")]
        self.assertEqual(parents, ["B", "C"])
        self.assertTrue(dag.derives_from("D", "B"))
        self.assertTrue(dag.derives_from("D", "C"))

    def test_branching_and_merging_ancestry(self) -> None:
        """16. Branching + merging diamond graph: A -> B, A -> C, B -> D, C -> D."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("A", ProvenanceNodeType.RESOURCE)
        dag.create_node("B", ProvenanceNodeType.DATA)
        dag.create_node("C", ProvenanceNodeType.DATA)
        dag.create_node("D", ProvenanceNodeType.DATA)

        dag.add_edge("A", "B", ProvenanceEdgeType.READS)
        dag.add_edge("A", "C", ProvenanceEdgeType.READS)
        dag.add_edge("B", "D", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("C", "D", ProvenanceEdgeType.DERIVED_FROM)

        ancestors = [a.node_id for a in dag.get_ancestors("D")]
        # D's ancestors must contain B, C, and A
        self.assertIn("B", ancestors)
        self.assertIn("C", ancestors)
        self.assertIn("A", ancestors)
        self.assertEqual(len(ancestors), 3)

        self.assertTrue(dag.derives_from("D", "A"))
        self.assertTrue(dag.derives_from("D", "B"))
        self.assertTrue(dag.derives_from("D", "C"))

    def test_cycle_rejection(self) -> None:
        """17. Multi-node cycle rejection: A -> B -> C -> A."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("A", ProvenanceNodeType.DATA)
        dag.create_node("B", ProvenanceNodeType.DATA)
        dag.create_node("C", ProvenanceNodeType.DATA)

        dag.add_edge("A", "B", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("B", "C", ProvenanceEdgeType.DERIVED_FROM)

        with self.assertRaises(ProvenanceCycleError):
            dag.add_edge("C", "A", ProvenanceEdgeType.DERIVED_FROM)

    def test_self_cycle_rejection(self) -> None:
        """18. Self-cycle rejection: A -> A."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("A", ProvenanceNodeType.DATA)

        with self.assertRaises(ProvenanceCycleError):
            dag.add_edge("A", "A", ProvenanceEdgeType.DERIVED_FROM)

    def test_session_isolation(self) -> None:
        """19. Session isolation enforcement."""
        dag = ActionProvenanceDAG(session_id="session-user-1")

        # Node with matching session succeeds
        dag.create_node("node-1", ProvenanceNodeType.DATA, session_id="session-user-1")

        # Node with different session raises SessionMismatchError
        foreign_node = ProvenanceNode(
            node_id="foreign-node",
            node_type=ProvenanceNodeType.DATA,
            session_id="session-user-2",
        )
        with self.assertRaises(SessionMismatchError):
            dag.add_node(foreign_node)

        # Separate session DAG cannot see first DAG's nodes
        other_dag = ActionProvenanceDAG(session_id="session-user-2")
        self.assertFalse(other_dag.has_node("node-1"))
        with self.assertRaises(ProvenanceNodeNotFoundError):
            other_dag.get_node("node-1")

    def test_unknown_node_query_behavior(self) -> None:
        """20. Unknown node queries raise ProvenanceNodeNotFoundError."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("A", ProvenanceNodeType.DATA)

        with self.assertRaises(ProvenanceNodeNotFoundError):
            dag.get_direct_parents("unknown")
        with self.assertRaises(ProvenanceNodeNotFoundError):
            dag.get_direct_children("unknown")
        with self.assertRaises(ProvenanceNodeNotFoundError):
            dag.get_ancestors("unknown")
        with self.assertRaises(ProvenanceNodeNotFoundError):
            dag.get_descendants("unknown")
        with self.assertRaises(ProvenanceNodeNotFoundError):
            dag.derives_from("unknown", "A")
        with self.assertRaises(ProvenanceNodeNotFoundError):
            dag.derives_from("A", "unknown")

    def test_deterministic_traversal_ordering(self) -> None:
        """21. Deterministic BFS traversal ordering."""
        dag = ActionProvenanceDAG(session_id="s1")
        dag.create_node("root", ProvenanceNodeType.DATA)
        dag.create_node("child1", ProvenanceNodeType.DATA)
        dag.create_node("child2", ProvenanceNodeType.DATA)
        dag.create_node("grandchild", ProvenanceNodeType.DATA)

        dag.add_edge("root", "child1", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("root", "child2", ProvenanceEdgeType.DERIVED_FROM)
        dag.add_edge("child1", "grandchild", ProvenanceEdgeType.DERIVED_FROM)

        # Order must be stable across multiple runs
        for _ in range(5):
            descendants = [d.node_id for d in dag.get_descendants("root")]
            self.assertEqual(descendants, ["child1", "child2", "grandchild"])

    def test_append_oriented_historical_behavior(self) -> None:
        """22. Nodes and edges are immutable once created."""
        dag = ActionProvenanceDAG(session_id="s1")
        node = dag.create_node(
            "n1",
            ProvenanceNodeType.RESOURCE,
            resource_ref="data.db",
            safety_properties=["CONFIDENTIAL"],
            metadata={"source": "sql"},
        )
        edge = dag.add_edge(
            "n1",
            dag.create_node("n2", ProvenanceNodeType.DATA).node_id,
            ProvenanceEdgeType.READS,
            metadata={"rows": 100},
        )

        # Frozen dataclass mutation attempts fail
        with self.assertRaises((AttributeError, TypeError)):
            node.description = "Mutated"  # type: ignore
        with self.assertRaises((AttributeError, TypeError)):
            edge.edge_type = ProvenanceEdgeType.USES  # type: ignore

    def test_safety_metadata_cannot_accidentally_mutate(self) -> None:
        """23. External mutation of passed collections does not mutate node/edge."""
        props = ["CONFIDENTIAL", "PII"]
        meta = {"table": "users"}

        dag = ActionProvenanceDAG(session_id="s1")
        node = dag.create_node(
            "n1",
            ProvenanceNodeType.RESOURCE,
            safety_properties=props,
            metadata=meta,
        )

        # Mutate local objects
        props.append("MALICIOUS")
        meta["table"] = "overwritten"

        self.assertEqual(node.safety_properties, ("CONFIDENTIAL", "PII"))
        self.assertEqual(node.metadata["table"], "users")

    def test_mvp_customers_csv_lineage_scenario(self) -> None:
        """24. Primary MVP showcase scenario:

        customers.csv (RESOURCE)
              |
              v (READS)
        customer_data (DATA)
              |
              v (TRANSFORMS / DERIVED_FROM)
           summary (DATA)
              |
              v (USES)
          send_email (TOOL_CALL / ACTION)
              |
              v (SENDS_TO)
        external@example.com (EXTERNAL_DESTINATION)
        """
        dag = ActionProvenanceDAG(session_id="showcase-session")

        # 1. Resource node: customers.csv
        r_file = dag.create_node(
            node_id="res:customers.csv",
            node_type=ProvenanceNodeType.RESOURCE,
            resource_ref="customers.csv",
            description="Sensitive customer database export",
            safety_properties=["CONFIDENTIAL", "PII"],
        )

        # 2. Tool result / Data: customer_data
        d_cust = dag.create_node(
            node_id="data:customer_data",
            node_type=ProvenanceNodeType.DATA,
            description="In-memory loaded customer records",
        )
        dag.add_edge(r_file.node_id, d_cust.node_id, ProvenanceEdgeType.READS)

        # 3. Intermediate transformation: summarize
        t_sum = dag.create_node(
            node_id="trans:summarize",
            node_type=ProvenanceNodeType.TRANSFORMATION,
            description="LLM customer summary transformation",
        )
        dag.add_edge(d_cust.node_id, t_sum.node_id, ProvenanceEdgeType.TRANSFORMS)

        # 4. Resulting data: summary
        d_sum = dag.create_node(
            node_id="data:summary",
            node_type=ProvenanceNodeType.DATA,
            description="Textual summary of customers",
        )
        dag.add_edge(t_sum.node_id, d_sum.node_id, ProvenanceEdgeType.PRODUCES)

        # 5. Outgoing action / tool call: send_email
        a_send = dag.create_node(
            node_id="action:send_email",
            node_type=ProvenanceNodeType.TOOL_CALL,
            description="send_email tool invocation",
            metadata={"destination": "external@example.com"},
        )
        dag.add_edge(d_sum.node_id, a_send.node_id, ProvenanceEdgeType.USES)

        # 6. External destination: external@example.com
        dst = dag.create_node(
            node_id="dest:external_email",
            node_type=ProvenanceNodeType.EXTERNAL_DESTINATION,
            description="external@example.com",
        )
        dag.add_edge(a_send.node_id, dst.node_id, ProvenanceEdgeType.SENDS_TO)

        # Assert ancestors of send_email
        ancestor_ids = [a.node_id for a in dag.get_ancestors(a_send.node_id)]
        self.assertIn("data:summary", ancestor_ids)
        self.assertIn("trans:summarize", ancestor_ids)
        self.assertIn("data:customer_data", ancestor_ids)
        self.assertIn("res:customers.csv", ancestor_ids)

        # Assert derivation queries
        self.assertTrue(dag.derives_from(a_send.node_id, r_file.node_id))
        self.assertTrue(dag.derives_from(a_send.node_id, d_cust.node_id))
        self.assertTrue(dag.derives_from(a_send.node_id, d_sum.node_id))
        self.assertTrue(dag.derives_from(dst.node_id, r_file.node_id))

        # Assert downstream queries
        descendant_ids = [d.node_id for d in dag.get_descendants(r_file.node_id)]
        self.assertIn("data:customer_data", descendant_ids)
        self.assertIn("data:summary", descendant_ids)
        self.assertIn("action:send_email", descendant_ids)
        self.assertIn("dest:external_email", descendant_ids)


if __name__ == "__main__":
    unittest.main()
