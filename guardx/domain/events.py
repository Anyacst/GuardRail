"""SafetyEvent domain model representing runtime safety-relevant events."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
import uuid

from guardx.domain.enums import InterceptionPoint


@dataclass(frozen=True)
class SafetyEvent:
    """Represents a safety-relevant event occurring at a specific interception point.

    Attributes:
        event_id: Unique identifier for this safety event.
        session_id: Identifier grouping related events within a session.
        interception_point: Stage at which the event is intercepted.
        payload: Event payload (e.g. prompt text, model response, tool arguments).
        metadata: Additional contextual metadata.
        provenance_refs: References to provenance nodes associated with this event.
        timestamp: Time when the safety event occurred (UTC).
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    interception_point: InterceptionPoint = InterceptionPoint.INPUT
    payload: Any = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    provenance_refs: Sequence[str] = field(default_factory=tuple)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id.strip():
            raise ValueError("event_id must be a non-empty string")
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        if not isinstance(self.interception_point, InterceptionPoint):
            raise TypeError(
                f"interception_point must be an instance of InterceptionPoint, got {type(self.interception_point)}"
            )
        if not isinstance(self.timestamp, datetime):
            raise TypeError("timestamp must be a datetime instance")
