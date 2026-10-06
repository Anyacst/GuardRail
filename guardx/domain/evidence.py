"""Evidence domain model representing immutable structured safety findings."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping, Optional, Sequence
import uuid

from guardx.domain.enums import Confidence, RecommendedAction, RiskCategory, Severity


def _freeze_supporting_data(data: Any) -> Any:
    """Recursively freeze dictionaries and lists into immutable structures."""
    if isinstance(data, dict):
        return MappingProxyType({k: _freeze_supporting_data(v) for k, v in data.items()})
    if isinstance(data, (list, tuple, set)):
        return tuple(_freeze_supporting_data(item) for item in data)
    return data


@dataclass(frozen=True)
class Evidence:
    """Structured, immutable finding emitted by a specialized Guard.

    Attributes:
        evidence_id: Unique identifier for this evidence record.
        source_guard: Name of the Guard that emitted this finding.
        guard_version: Version identifier of the Guard.
        risk_category: Safety category (Security, Privacy, Content Safety, Policy).
        risk_type: Specific finding classification within the risk category.
        severity: Potential impact if this finding is accurate.
        confidence: Certainty level of the finding.
        description: Human-readable explanation of the finding.
        affected_entities: Entity/resource identifiers involved in the finding.
        provenance_refs: Lineage references supporting this finding.
        supporting_data: Structured diagnostic and analytical evidence data.
        recommended_action: Guard's recommended handling (ALLOW, MODIFY, BLOCK, HUMAN_REVIEW).
        recommended_modification: Suggested modification text/plan if recommending MODIFY.
        investigation_requested: True if the Guard requests further bounded investigation.
        timestamp: Time of evidence emission in UTC.
        previous_evidence_ref: Optional reference to prior Evidence when this is an investigation result.
    """

    source_guard: str
    risk_category: RiskCategory
    risk_type: str
    severity: Severity
    confidence: Confidence
    description: str
    guard_version: str = "1.0.0"
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    affected_entities: Sequence[str] = field(default_factory=tuple)
    provenance_refs: Sequence[str] = field(default_factory=tuple)
    supporting_data: Mapping[str, Any] = field(default_factory=dict)
    recommended_action: Optional[RecommendedAction] = None
    recommended_modification: Optional[str] = None
    investigation_requested: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    previous_evidence_ref: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, str) or not self.evidence_id.strip():
            raise ValueError("evidence_id must be a non-empty string")
        if not isinstance(self.source_guard, str) or not self.source_guard.strip():
            raise ValueError("source_guard must be a non-empty string")
        if not isinstance(self.guard_version, str) or not self.guard_version.strip():
            raise ValueError("guard_version must be a non-empty string")
        if not isinstance(self.risk_category, RiskCategory):
            raise TypeError(f"risk_category must be an instance of RiskCategory, got {type(self.risk_category)}")
        if not isinstance(self.risk_type, str) or not self.risk_type.strip():
            raise ValueError("risk_type must be a non-empty string")
        if not isinstance(self.severity, Severity):
            raise TypeError(f"severity must be an instance of Severity, got {type(self.severity)}")
        if not isinstance(self.confidence, Confidence):
            raise TypeError(f"confidence must be an instance of Confidence, got {type(self.confidence)}")
        if not isinstance(self.description, str):
            raise TypeError(f"description must be a string, got {type(self.description)}")
        if self.recommended_action is not None and not isinstance(self.recommended_action, RecommendedAction):
            raise TypeError(
                f"recommended_action must be an instance of RecommendedAction or None, got {type(self.recommended_action)}"
            )
        if self.previous_evidence_ref is not None:
            if not isinstance(self.previous_evidence_ref, str) or not self.previous_evidence_ref.strip():
                raise ValueError("previous_evidence_ref must be a non-empty string when provided")

        # Freeze collections deeply for audit immutability (DD-005)
        object.__setattr__(
            self,
            "affected_entities",
            tuple(self.affected_entities) if self.affected_entities else (),
        )
        object.__setattr__(
            self,
            "provenance_refs",
            tuple(self.provenance_refs) if self.provenance_refs else (),
        )
        object.__setattr__(
            self,
            "supporting_data",
            _freeze_supporting_data(self.supporting_data)
            if self.supporting_data
            else MappingProxyType({}),
        )
