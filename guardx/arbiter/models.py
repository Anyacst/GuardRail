"""Data models representing Arbiter evaluation results and decision metadata."""

from dataclasses import dataclass, field
from typing import Optional, Sequence

from guardx.domain.enums import Verdict
from guardx.domain.evidence import Evidence


@dataclass(frozen=True)
class ArbiterResult:
    """Final decision outcome produced exclusively by the GuardX Arbiter.

    Attributes:
        verdict: Final GuardX authorization decision (ALLOW, MODIFY, BLOCK, HUMAN_REVIEW).
        reason: Human-readable explanation of the rationale for the verdict.
        reason_code: Machine-readable categorical code explaining why the decision was made.
        decisive_evidence: Evidence records that directly determined the final verdict.
        considered_evidence: Complete set of valid Evidence records reviewed during arbitration.
        missing_guard_coverage: Names of applicable Guards that experienced execution failures.
    """

    verdict: Verdict
    reason: str
    reason_code: str
    decisive_evidence: tuple[Evidence, ...] = field(default_factory=tuple)
    considered_evidence: tuple[Evidence, ...] = field(default_factory=tuple)
    missing_guard_coverage: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, Verdict):
            raise TypeError(f"verdict must be an instance of Verdict enum, got {type(self.verdict).__name__}")
        if not self.reason or not isinstance(self.reason, str):
            raise ValueError("reason must be a non-empty string.")
        if not self.reason_code or not isinstance(self.reason_code, str):
            raise ValueError("reason_code must be a non-empty string.")

        if not isinstance(self.decisive_evidence, tuple):
            object.__setattr__(self, "decisive_evidence", tuple(self.decisive_evidence))
        for item in self.decisive_evidence:
            if not isinstance(item, Evidence):
                raise TypeError(f"All decisive_evidence items must be Evidence instances, got {type(item).__name__}")

        if not isinstance(self.considered_evidence, tuple):
            object.__setattr__(self, "considered_evidence", tuple(self.considered_evidence))
        for item in self.considered_evidence:
            if not isinstance(item, Evidence):
                raise TypeError(f"All considered_evidence items must be Evidence instances, got {type(item).__name__}")

        if not isinstance(self.missing_guard_coverage, tuple):
            object.__setattr__(self, "missing_guard_coverage", tuple(self.missing_guard_coverage))
        for name in self.missing_guard_coverage:
            if not isinstance(name, str):
                raise TypeError(f"All missing_guard_coverage items must be str, got {type(name).__name__}")

    @property
    def is_allowed(self) -> bool:
        """True if the operation was granted full authorization (ALLOW)."""
        return self.verdict == Verdict.ALLOW

    @property
    def is_blocked(self) -> bool:
        """True if the operation was denied (BLOCK)."""
        return self.verdict == Verdict.BLOCK

    @property
    def is_human_review(self) -> bool:
        """True if the operation requires manual human approval (HUMAN_REVIEW)."""
        return self.verdict == Verdict.HUMAN_REVIEW

    @property
    def is_modified(self) -> bool:
        """True if the operation is approved conditional on transformation (MODIFY)."""
        return self.verdict == Verdict.MODIFY
