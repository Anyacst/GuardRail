"""EvaluationContext domain model providing contextual safety information to Guards."""

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from guardx.domain.events import SafetyEvent


@dataclass(frozen=True)
class EvaluationContext:
    """Carries the contextual information required for Guards to evaluate an event.

    Attributes:
        event: The SafetyEvent being evaluated.
        policies: Applicable configured security and organizational policies.
        risk_memory_entries: Relevant prior safety findings and session state.
        provenance_context: Provenance DAG nodes/edges relevant to this evaluation.
        metadata: Additional invocation or runtime metadata.
    """

    event: SafetyEvent
    policies: Mapping[str, Any] = field(default_factory=dict)
    risk_memory_entries: Sequence[Any] = field(default_factory=tuple)
    provenance_context: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.event, SafetyEvent):
            raise TypeError(f"event must be an instance of SafetyEvent, got {type(self.event)}")
