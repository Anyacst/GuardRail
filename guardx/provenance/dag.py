"""Action Provenance Directed Acyclic Graph (DAG) implementation.

Pure standard-library Python in-memory representation tracking data and execution lineage.
Enforces uniqueness, cycle rejection, session boundary isolation, and deterministic traversals.
"""

from collections import deque
from typing import Sequence

from guardx.provenance.models import (
    ProvenanceEdge,
    ProvenanceEdgeType,
    ProvenanceNode,
    ProvenanceNodeType,
)


class ProvenanceCycleError(ValueError):
    """Raised when an edge would introduce a cycle into the Directed Acyclic Graph."""


class ProvenanceNodeNotFoundError(KeyError):
    """Raised when a referenced node ID does not exist in the DAG."""


class DuplicateProvenanceNodeError(ValueError):
    """Raised when attempting to add a node with an ID that already exists."""


class SessionMismatchError(ValueError):
    """Raised when attempting to add a node or edge that violates session boundaries."""


class ActionProvenanceDAG:
    """In-memory Directed Acyclic Graph (DAG) for tracking safety-relevant data/action lineage.

    Invariants enforced:
    1. Node IDs are unique within the DAG.
    2. Edges must reference existing nodes.
    3. Self-loops and multi-node cycles are strictly rejected (raises ProvenanceCycleError).
    4. Session boundaries are strictly preserved: if session_id is bound, all nodes must match.
    5. Edges are directional: source_id -> destination_id (source flows into destination).
    6. Historical records are append-only.
    7. Traversal queries (ancestors, descendants, parents, children) return deterministic lists.
    """

    def __init__(self, session_id: str | None = None) -> None:
        """Initialize an in-memory provenance DAG.

        Args:
            session_id: Optional session identifier to bind this DAG exclusively to one session.
        """
        self._session_id = session_id
        # node_id -> ProvenanceNode
        self._nodes: dict[str, ProvenanceNode] = {}
        # node_id -> set of direct child node_ids (outgoing edges: source -> dest)
        self._adjacency: dict[str, list[str]] = {}
        # node_id -> set of direct parent node_ids (incoming edges: source -> dest)
        self._reverse_adjacency: dict[str, list[str]] = {}
        # (source_id, destination_id, edge_type) -> ProvenanceEdge
        self._edges: dict[tuple[str, str, ProvenanceEdgeType], ProvenanceEdge] = {}

    @property
    def session_id(self) -> str | None:
        """The session ID bound to this DAG, if any."""
        return self._session_id

    def add_node(self, node: ProvenanceNode) -> ProvenanceNode:
        """Add a ProvenanceNode to the DAG.

        Args:
            node: An immutable ProvenanceNode.

        Returns:
            The added ProvenanceNode.

        Raises:
            TypeError: If node is not a ProvenanceNode.
            SessionMismatchError: If the node's session_id does not match the DAG's session_id.
            DuplicateProvenanceNodeError: If a node with the same node_id already exists.
        """
        if not isinstance(node, ProvenanceNode):
            raise TypeError(f"node must be an instance of ProvenanceNode, got {type(node)}")

        if self._session_id is not None and node.session_id != self._session_id:
            raise SessionMismatchError(
                f"Node session '{node.session_id}' does not match DAG session '{self._session_id}'"
            )

        if node.node_id in self._nodes:
            raise DuplicateProvenanceNodeError(f"Node with id '{node.node_id}' already exists in DAG")

        self._nodes[node.node_id] = node
        self._adjacency[node.node_id] = []
        self._reverse_adjacency[node.node_id] = []
        return node

    def create_node(
        self,
        node_id: str,
        node_type: ProvenanceNodeType,
        session_id: str | None = None,
        description: str = "",
        resource_ref: str | None = None,
        safety_properties: Sequence[str] = (),
        metadata: dict | None = None,
    ) -> ProvenanceNode:
        """Convenience method to construct and add a node in one call."""
        sid = session_id or self._session_id
        if sid is None:
            raise ValueError("session_id must be provided or configured on the DAG")
        node = ProvenanceNode(
            node_id=node_id,
            node_type=node_type,
            session_id=sid,
            description=description,
            resource_ref=resource_ref,
            safety_properties=tuple(safety_properties),
            metadata=metadata or {},
        )
        return self.add_node(node)

    def get_node(self, node_id: str) -> ProvenanceNode:
        """Retrieve a node by its node_id.

        Raises:
            ProvenanceNodeNotFoundError: If node_id does not exist.
        """
        if node_id not in self._nodes:
            raise ProvenanceNodeNotFoundError(f"Node '{node_id}' does not exist in DAG")
        return self._nodes[node_id]

    def has_node(self, node_id: str) -> bool:
        """Check if a node ID exists in the DAG."""
        return node_id in self._nodes

    def add_edge(
        self,
        source_id: str,
        destination_id: str,
        edge_type: ProvenanceEdgeType,
        metadata: dict | None = None,
    ) -> ProvenanceEdge:
        """Add a directed edge from source_id to destination_id.

        Direction: source -> destination
        Represents data/action flow where source flows into, is read by, or precedes destination.

        Args:
            source_id: ID of the originating node.
            destination_id: ID of the target node.
            edge_type: Relationship category.
            metadata: Optional safe contextual metadata.

        Returns:
            The added ProvenanceEdge.

        Raises:
            ProvenanceNodeNotFoundError: If source_id or destination_id does not exist.
            ProvenanceCycleError: If the edge would introduce a cycle (including self-cycles).
            TypeError: If edge_type is invalid.
        """
        if source_id not in self._nodes:
            raise ProvenanceNodeNotFoundError(f"Source node '{source_id}' does not exist in DAG")
        if destination_id not in self._nodes:
            raise ProvenanceNodeNotFoundError(f"Destination node '{destination_id}' does not exist in DAG")

        if not isinstance(edge_type, ProvenanceEdgeType):
            raise TypeError(f"edge_type must be an instance of ProvenanceEdgeType, got {type(edge_type)}")

        # Self-cycle rejection
        if source_id == destination_id:
            raise ProvenanceCycleError(
                f"Cannot add self-cycle edge from '{source_id}' to itself"
            )

        # Check if destination can already reach source (which adding source -> destination would complete into a cycle)
        if self._is_reachable(from_id=destination_id, to_id=source_id):
            raise ProvenanceCycleError(
                f"Adding edge from '{source_id}' to '{destination_id}' would create a cycle in the DAG"
            )

        edge_key = (source_id, destination_id, edge_type)
        if edge_key in self._edges:
            # Duplicate identical edge is idempotent, return existing edge
            return self._edges[edge_key]

        edge = ProvenanceEdge(
            source_id=source_id,
            destination_id=destination_id,
            edge_type=edge_type,
            metadata=metadata or {},
        )
        self._edges[edge_key] = edge
        if destination_id not in self._adjacency[source_id]:
            self._adjacency[source_id].append(destination_id)
        if source_id not in self._reverse_adjacency[destination_id]:
            self._reverse_adjacency[destination_id].append(source_id)

        return edge

    def get_edges(self) -> list[ProvenanceEdge]:
        """Return all edges in the DAG."""
        return list(self._edges.values())

    def get_nodes(self) -> list[ProvenanceNode]:
        """Return all nodes in the DAG in deterministic insertion order."""
        return list(self._nodes.values())

    def get_direct_parents(self, node_id: str) -> list[ProvenanceNode]:
        """Get nodes that have a direct edge pointing to node_id (source -> node_id).

        Returns:
            List of parent ProvenanceNodes in deterministic order.

        Raises:
            ProvenanceNodeNotFoundError: If node_id does not exist.
        """
        if node_id not in self._nodes:
            raise ProvenanceNodeNotFoundError(f"Node '{node_id}' does not exist in DAG")
        parent_ids = self._reverse_adjacency[node_id]
        return [self._nodes[pid] for pid in parent_ids]

    def get_direct_children(self, node_id: str) -> list[ProvenanceNode]:
        """Get nodes that node_id has a direct edge pointing to (node_id -> destination).

        Returns:
            List of child ProvenanceNodes in deterministic order.

        Raises:
            ProvenanceNodeNotFoundError: If node_id does not exist.
        """
        if node_id not in self._nodes:
            raise ProvenanceNodeNotFoundError(f"Node '{node_id}' does not exist in DAG")
        child_ids = self._adjacency[node_id]
        return [self._nodes[cid] for cid in child_ids]

    def get_ancestors(self, node_id: str) -> list[ProvenanceNode]:
        """Get all transitive ancestors of node_id (all nodes reachable by following incoming edges backward).

        Deterministic breadth-first search from node_id backward.

        Returns:
            List of ancestor ProvenanceNodes in BFS discovery order.

        Raises:
            ProvenanceNodeNotFoundError: If node_id does not exist.
        """
        if node_id not in self._nodes:
            raise ProvenanceNodeNotFoundError(f"Node '{node_id}' does not exist in DAG")

        visited: set[str] = set()
        queue: deque[str] = deque([node_id])
        ancestors: list[ProvenanceNode] = []

        while queue:
            curr_id = queue.popleft()
            for parent_id in self._reverse_adjacency[curr_id]:
                if parent_id not in visited:
                    visited.add(parent_id)
                    ancestors.append(self._nodes[parent_id])
                    queue.append(parent_id)

        return ancestors

    def get_descendants(self, node_id: str) -> list[ProvenanceNode]:
        """Get all transitive descendants of node_id (all nodes reachable by following outgoing edges forward).

        Deterministic breadth-first search from node_id forward.

        Returns:
            List of descendant ProvenanceNodes in BFS discovery order.

        Raises:
            ProvenanceNodeNotFoundError: If node_id does not exist.
        """
        if node_id not in self._nodes:
            raise ProvenanceNodeNotFoundError(f"Node '{node_id}' does not exist in DAG")

        visited: set[str] = set()
        queue: deque[str] = deque([node_id])
        descendants: list[ProvenanceNode] = []

        while queue:
            curr_id = queue.popleft()
            for child_id in self._adjacency[curr_id]:
                if child_id not in visited:
                    visited.add(child_id)
                    descendants.append(self._nodes[child_id])
                    queue.append(child_id)

        return descendants

    def derives_from(self, target_id: str, source_id: str) -> bool:
        """Check if target_id ultimately derives from or has source_id as an ancestor.

        Answers the MVP question: 'Does this data/action ultimately derive from resource X?'

        Args:
            target_id: The downstream node (e.g., 'send_email' or 'summary').
            source_id: The potential upstream source (e.g., 'customers.csv').

        Returns:
            True if source_id is in target_id's ancestor path, False otherwise.

        Raises:
            ProvenanceNodeNotFoundError: If either node does not exist.
        """
        if target_id not in self._nodes:
            raise ProvenanceNodeNotFoundError(f"Target node '{target_id}' does not exist in DAG")
        if source_id not in self._nodes:
            raise ProvenanceNodeNotFoundError(f"Source node '{source_id}' does not exist in DAG")

        return self._is_reachable(from_id=source_id, to_id=target_id)

    def get_effective_properties(
        self,
        node_id: str,
        propagation_engine: "PropertyPropagationEngine | None" = None,
    ) -> tuple[str, ...]:
        """Compute effective semantic safety properties for node_id.

        Args:
            node_id: Node ID to compute properties for.
            propagation_engine: Optional PropertyPropagationEngine instance.
                If None, uses a default PropertyPropagationEngine.

        Returns:
            Sorted, deduplicated tuple of property strings.
        """
        if propagation_engine is None:
            from guardx.provenance.propagation import PropertyPropagationEngine

            propagation_engine = PropertyPropagationEngine()
        return propagation_engine.compute_effective_properties(self, node_id)


    def _is_reachable(self, from_id: str, to_id: str) -> bool:
        """Return True if to_id can be reached from from_id following outgoing edges."""
        if from_id == to_id:
            return True

        visited: set[str] = set()
        queue: deque[str] = deque([from_id])

        while queue:
            curr = queue.popleft()
            for neighbor in self._adjacency[curr]:
                if neighbor == to_id:
                    return True
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        return False

    def __len__(self) -> int:
        """Return total number of nodes in the DAG."""
        return len(self._nodes)
