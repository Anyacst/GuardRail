"""Provenance domain types: Node types, Edge types, and Provenance models."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence


class ProvenanceNodeType(str, Enum):
    """Types of entities tracked in the Action Provenance DAG."""

    USER_INPUT = "USER_INPUT"
    MODEL_OUTPUT = "MODEL_OUTPUT"
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    RESOURCE = "RESOURCE"
    DATA = "DATA"
    TRANSFORMATION = "TRANSFORMATION"
    EXTERNAL_DESTINATION = "EXTERNAL_DESTINATION"


class ProvenanceEdgeType(str, Enum):
    """Types of directional relationships between provenance nodes."""

    READS = "READS"
    PRODUCES = "PRODUCES"
    DERIVED_FROM = "DERIVED_FROM"
    TRANSFORMS = "TRANSFORMS"
    USES = "USES"
    SENDS_TO = "SENDS_TO"
    RETURNS = "RETURNS"


class SafetyProperty(str, Enum):
    """Semantic safety property labels tracked across data and execution lineage."""

    PII = "PII"
    CREDENTIAL = "CREDENTIAL"
    SECRET = "SECRET"
    CONFIDENTIAL = "CONFIDENTIAL"
    FINANCIAL_DATA = "FINANCIAL_DATA"
    UNTRUSTED_SOURCE = "UNTRUSTED_SOURCE"


def _freeze_mapping(data: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a shallow copy of a mapping to prevent external mutation."""
    if data is None:
        return {}
    return dict(data)


def _freeze_properties(items: Sequence[str | SafetyProperty] | None) -> tuple[str, ...]:
    """Normalize and freeze safety property sequence into a sorted, deduplicated tuple of strings."""
    if not items:
        return ()
    normalized: set[str] = set()
    for item in items:
        if isinstance(item, SafetyProperty):
            normalized.add(item.value)
        elif isinstance(item, str) and item.strip():
            # If string matches a known SafetyProperty enum, normalize to it, else use uppercase stripped string
            val = item.strip().upper()
            normalized.add(val)
        else:
            raise TypeError(f"Property must be SafetyProperty or non-empty str, got {type(item)}")
    return tuple(sorted(normalized))



@dataclass(frozen=True)
class ProvenanceNode:
    """An immutable node in the Action Provenance DAG.

    Represents an entity, artifact, action, or resource observed during execution.
    Data minimization principle: does NOT store raw sensitive contents or full prompts.

    Attributes:
        node_id: Unique identifier for the node within its session.
        node_type: Categorical type from ProvenanceNodeType.
        session_id: Session identifier to which this lineage belongs.
        description: Non-sensitive human-readable description of the entity.
        resource_ref: Optional safe identifier/path of the resource (e.g. 'customers.csv').
        safety_properties: Initial safety property labels (e.g. 'CONFIDENTIAL', 'PII').
            Placeholder for Phase 7 semantic propagation.
        metadata: Optional safe contextual metadata (e.g. tool name, arguments summary).
        timestamp: UTC timestamp when the node was recorded.
    """

    node_id: str
    node_type: ProvenanceNodeType
    session_id: str
    description: str = ""
    resource_ref: str | None = None
    safety_properties: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.node_id or not isinstance(self.node_id, str):
            raise ValueError("node_id must be a non-empty string")
        if not isinstance(self.node_type, ProvenanceNodeType):
            raise TypeError(f"node_type must be an instance of ProvenanceNodeType, got {type(self.node_type)}")
        if not self.session_id or not isinstance(self.session_id, str):
            raise ValueError("session_id must be a non-empty string")
        if not isinstance(self.description, str):
            raise TypeError("description must be a string")

        # Ensure safety_properties is frozen tuple of strings
        object.__setattr__(self, "safety_properties", _freeze_properties(self.safety_properties))
        # Ensure metadata is copied to protect against external mutation
        object.__setattr__(self, "metadata", _freeze_mapping(self.metadata))



@dataclass(frozen=True)
class ProvenanceEdge:
    """An immutable directed edge in the Action Provenance DAG.

    Directed edge from source node to destination node representing data/action flow:
    source -> destination (e.g. customer_data -> summary with DERIVED_FROM means
    summary is derived from customer_data, or summary -> send_email with USES).

    Attributes:
        source_id: Node ID where the edge originates.
        destination_id: Node ID where the edge points.
        edge_type: Relationship category from ProvenanceEdgeType.
        metadata: Optional safe contextual metadata.
        timestamp: UTC timestamp when the relationship was recorded.
    """

    source_id: str
    destination_id: str
    edge_type: ProvenanceEdgeType
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.source_id or not isinstance(self.source_id, str):
            raise ValueError("source_id must be a non-empty string")
        if not self.destination_id or not isinstance(self.destination_id, str):
            raise ValueError("destination_id must be a non-empty string")
        if not isinstance(self.edge_type, ProvenanceEdgeType):
            raise TypeError(f"edge_type must be an instance of ProvenanceEdgeType, got {type(self.edge_type)}")

        object.__setattr__(self, "metadata", _freeze_mapping(self.metadata))
