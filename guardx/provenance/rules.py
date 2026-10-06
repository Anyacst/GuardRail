"""Transformation rules and models for semantic safety property propagation."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

from guardx.provenance.models import SafetyProperty, _freeze_properties


class TransformationType(str, Enum):
    """Categorical type of operation applied to data in the provenance DAG."""

    GENERIC = "GENERIC"
    FORMAT = "FORMAT"
    SUMMARIZE = "SUMMARIZE"
    ENCODE = "ENCODE"
    VERIFIED_PII_REDACTION = "VERIFIED_PII_REDACTION"
    VERIFIED_SECRET_REDACTION = "VERIFIED_SECRET_REDACTION"
    VERIFIED_AGGREGATION = "VERIFIED_AGGREGATION"
    RETRIEVAL = "RETRIEVAL"
    EXTERNAL_INGESTION = "EXTERNAL_INGESTION"


@dataclass(frozen=True)
class TransformationRule:
    """An explicit, deterministic rule governing property preservation, reduction, and introduction.

    Invariants:
    - Default behavior is conservative: all incoming properties are preserved unless explicitly
      listed in `reduces_properties`.
    - Property reduction requires an explicitly registered rule with `is_trusted_reduction=True`.
    - If `is_trusted_reduction=False`, `reduces_properties` is ignored to prevent unverified laundering.

    Attributes:
        rule_id: Unique identifier for this transformation rule.
        description: Non-sensitive human-readable explanation of what this transformation does.
        is_trusted_reduction: Boolean flag indicating if this transformation is authorized to remove properties.
        reduces_properties: Tuple of properties that this verified transformation removes.
        introduces_properties: Tuple of properties introduced by this transformation.
    """

    rule_id: str
    description: str = ""
    is_trusted_reduction: bool = False
    reduces_properties: tuple[str, ...] = field(default_factory=tuple)
    introduces_properties: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.rule_id or not isinstance(self.rule_id, str):
            raise ValueError("rule_id must be a non-empty string")
        if not isinstance(self.is_trusted_reduction, bool):
            raise TypeError("is_trusted_reduction must be a bool")

        object.__setattr__(
            self,
            "reduces_properties",
            _freeze_properties(self.reduces_properties),
        )
        object.__setattr__(
            self,
            "introduces_properties",
            _freeze_properties(self.introduces_properties),
        )

    def apply(self, inherited_properties: Sequence[str | SafetyProperty]) -> tuple[str, ...]:
        """Apply this rule to a set of inherited properties and return the resulting effective properties."""
        inherited_set = set(_freeze_properties(inherited_properties))

        # Only authorized trusted reduction rules can remove properties
        if self.is_trusted_reduction and self.reduces_properties:
            inherited_set.difference_update(self.reduces_properties)

        # Introduce new properties
        if self.introduces_properties:
            inherited_set.update(self.introduces_properties)

        return tuple(sorted(inherited_set))
