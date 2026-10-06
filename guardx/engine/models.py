"""Data models representing Risk Engine orchestration results and Guard execution status."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Sequence

from guardx.domain.context import EvaluationContext
from guardx.domain.evidence import Evidence


class GuardExecutionStatus(str, Enum):
    """Execution status for an individual Guard invocation within the Risk Engine."""

    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class GuardExecutionResult:
    """Explicit outcome of running a single Guard against an EvaluationContext.

    Note: Guard execution status is separate from risk Evidence.
    A timeout or error records an execution failure, not the presence/absence of risk.
    """

    guard_name: str
    status: GuardExecutionStatus
    evidence: tuple[Evidence, ...] = field(default_factory=tuple)
    duration_ms: float = 0.0
    error_message: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.guard_name or not isinstance(self.guard_name, str):
            raise ValueError("guard_name must be a non-empty string.")
        if not isinstance(self.status, GuardExecutionStatus):
            raise ValueError(f"status must be a GuardExecutionStatus enum, got {type(self.status).__name__}")
        if not isinstance(self.evidence, tuple):
            object.__setattr__(self, "evidence", tuple(self.evidence))
        for item in self.evidence:
            if not isinstance(item, Evidence):
                raise TypeError(f"All evidence items must be Evidence instances, got {type(item).__name__}")
        if self.duration_ms < 0.0:
            raise ValueError(f"duration_ms must be non-negative, got {self.duration_ms}")

    @property
    def is_success(self) -> bool:
        """True if the Guard ran to completion and produced valid output."""
        return self.status == GuardExecutionStatus.SUCCESS

    @property
    def has_failed(self) -> bool:
        """True if the Guard encountered a timeout, exception, or emitted invalid output."""
        return self.status in (
            GuardExecutionStatus.TIMEOUT,
            GuardExecutionStatus.ERROR,
            GuardExecutionStatus.INVALID_OUTPUT,
        )


@dataclass(frozen=True)
class RiskEngineResult:
    """Aggregated evaluation outcome from the Risk Engine.

    Contains all collected Evidence alongside detailed per-Guard execution records.
    The Risk Engine does NOT produce a final Verdict (that belongs to the Arbiter).
    """

    context: EvaluationContext
    evidence: tuple[Evidence, ...]
    guard_results: tuple[GuardExecutionResult, ...]
    duration_ms: float

    def __post_init__(self) -> None:
        if not isinstance(self.context, EvaluationContext):
            raise TypeError(f"context must be an EvaluationContext, got {type(self.context).__name__}")
        if not isinstance(self.evidence, tuple):
            object.__setattr__(self, "evidence", tuple(self.evidence))
        for item in self.evidence:
            if not isinstance(item, Evidence):
                raise TypeError(f"All evidence items must be Evidence instances, got {type(item).__name__}")
        if not isinstance(self.guard_results, tuple):
            object.__setattr__(self, "guard_results", tuple(self.guard_results))
        for res in self.guard_results:
            if not isinstance(res, GuardExecutionResult):
                raise TypeError(f"All guard_results must be GuardExecutionResult instances, got {type(res).__name__}")
        if self.duration_ms < 0.0:
            raise ValueError(f"duration_ms must be non-negative, got {self.duration_ms}")

    @property
    def has_evidence(self) -> bool:
        """True if any valid Evidence was emitted by successful Guards."""
        return len(self.evidence) > 0

    @property
    def has_failures(self) -> bool:
        """True if any applicable Guard failed during execution (timeout, error, invalid output)."""
        return any(res.has_failed for res in self.guard_results)

    @property
    def successful_guards(self) -> tuple[GuardExecutionResult, ...]:
        """Subset of guard results that completed successfully."""
        return tuple(res for res in self.guard_results if res.is_success)

    @property
    def failed_guards(self) -> tuple[GuardExecutionResult, ...]:
        """Subset of guard results that experienced execution failures."""
        return tuple(res for res in self.guard_results if res.has_failed)
