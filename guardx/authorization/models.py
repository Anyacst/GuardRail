"""Action Authorization domain models and risk types."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence


class AuthorizationRiskType(str, Enum):
    """Machine-readable risk identifiers for Action Authorization findings."""

    UNAUTHORIZED_SENSITIVE_DATA_TRANSFER = "policy.unauthorized_sensitive_data_transfer"
    MISSING_ACTION_PERMISSION = "policy.missing_action_permission"
    RESTRICTED_RESOURCE_USE = "policy.restricted_resource_use"
    ACTION_HUMAN_REVIEW_REQUIRED = "policy.action_human_review_required"
    MALFORMED_ACTION_REQUEST = "policy.malformed_action_request"


def _freeze_mapping(data: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a shallow copy of a mapping to protect against external mutation."""
    if data is None:
        return {}
    return dict(data)


def _freeze_sequence(items: Sequence[str] | None) -> tuple[str, ...]:
    """Return a tuple copy of string sequence to protect against external mutation."""
    if items is None:
        return ()
    return tuple(items)


@dataclass(frozen=True)
class ActionRequest:
    """Explicit, immutable representation of a proposed ACTION evaluated by ActionAuthorizationEngine.

    Attributes:
        action_name: Machine-readable identifier for the tool/action (e.g. 'send_email', 'read_file').
        arguments: Parameters passed to the action (e.g. {'destination': '...', 'body': '...'}).
        destination: Optional destination domain/host/address (e.g. 'external@example.com').
        provenance_refs: Tuple of provenance node IDs corresponding to data consumed by this action.
        permissions: Permissions granted to the executing agent/context.
        metadata: Optional contextual metadata.
        timestamp: Time the action request was recorded (UTC).
    """

    action_name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    destination: str | None = None
    provenance_refs: tuple[str, ...] = field(default_factory=tuple)
    permissions: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.action_name or not isinstance(self.action_name, str) or not self.action_name.strip():
            raise ValueError("action_name must be a non-empty string")
        if not isinstance(self.arguments, Mapping):
            raise TypeError("arguments must be a Mapping")
        if self.destination is not None and not isinstance(self.destination, str):
            raise TypeError("destination must be a string or None")

        object.__setattr__(self, "arguments", _freeze_mapping(self.arguments))
        object.__setattr__(self, "provenance_refs", _freeze_sequence(self.provenance_refs))
        object.__setattr__(self, "permissions", _freeze_sequence(self.permissions))
        object.__setattr__(self, "metadata", _freeze_mapping(self.metadata))
