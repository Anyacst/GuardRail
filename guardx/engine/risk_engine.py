"""Risk Engine orchestrator for concurrent Guard execution, timeout handling, and Evidence aggregation."""

import asyncio
from collections.abc import Mapping, Sequence
import time
from typing import Optional

from guardx.domain.context import EvaluationContext
from guardx.domain.evidence import Evidence
from guardx.engine.models import GuardExecutionResult, GuardExecutionStatus, RiskEngineResult
from guardx.guards.base import Guard


class RiskEngine:
    """Orchestrates multi-Guard safety evaluation across registered Guards.

    Responsibilities:
    1. Select applicable Guards for the given EvaluationContext.
    2. Execute independent Guards concurrently via asyncio.
    3. Enforce per-Guard execution timeouts and isolate errors.
    4. Validate Guard return contracts.
    5. Aggregate valid Evidence records.
    6. Return complete execution metadata without deciding the final Verdict.
    """

    def __init__(
        self,
        guards: Optional[Sequence[Guard]] = None,
        default_timeout: float = 2.0,
        guard_timeouts: Optional[Mapping[str, float]] = None,
    ) -> None:
        """Initialize the Risk Engine.

        Args:
            guards: Optional sequence of initial Guards to register.
            default_timeout: Default timeout in seconds for Guard execution (must be > 0).
            guard_timeouts: Optional mapping of guard names to specific timeout overrides.
        """
        if default_timeout <= 0.0:
            raise ValueError(f"default_timeout must be greater than 0, got {default_timeout}")

        self._default_timeout = float(default_timeout)
        self._guard_timeouts: dict[str, float] = (
            {k: float(v) for k, v in guard_timeouts.items()} if guard_timeouts else {}
        )
        self._guards: list[Guard] = []

        if guards:
            for guard in guards:
                self.register_guard(guard)

    @property
    def default_timeout(self) -> float:
        """Default per-Guard timeout in seconds."""
        return self._default_timeout

    @property
    def guards(self) -> tuple[Guard, ...]:
        """Registered Guards in registration order."""
        return tuple(self._guards)

    def register_guard(self, guard: Guard, timeout: Optional[float] = None) -> None:
        """Register a Guard with optional timeout override.

        Args:
            guard: The Guard instance to register.
            timeout: Optional specific timeout in seconds for this Guard.
        """
        if not isinstance(guard, Guard):
            raise TypeError(f"Expected Guard instance, got {type(guard).__name__}")

        if any(g.name == guard.name for g in self._guards):
            raise ValueError(f"Guard with name '{guard.name}' is already registered.")

        self._guards.append(guard)
        if timeout is not None:
            if timeout <= 0.0:
                raise ValueError(f"timeout must be greater than 0, got {timeout}")
            self._guard_timeouts[guard.name] = float(timeout)

    def get_guard(self, name: str) -> Optional[Guard]:
        """Look up a registered Guard by name."""
        for guard in self._guards:
            if guard.name == name:
                return guard
        return None

    async def _execute_guard(
        self,
        guard: Guard,
        context: EvaluationContext,
        timeout: float,
    ) -> GuardExecutionResult:
        """Execute a single Guard with timeout enforcement, error isolation, and output validation."""
        start_time = time.perf_counter()
        try:
            # asyncio.wait_for wraps the coroutine and cancels the underlying task on timeout
            output = await asyncio.wait_for(guard.evaluate(context), timeout=timeout)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Validate output is a sequence/collection
            if not isinstance(output, (list, tuple)):
                return GuardExecutionResult(
                    guard_name=guard.name,
                    status=GuardExecutionStatus.INVALID_OUTPUT,
                    evidence=(),
                    duration_ms=duration_ms,
                    error_message=(
                        f"Guard '{guard.name}' returned non-sequence output of type '{type(output).__name__}' "
                        f"(expected Sequence[Evidence])."
                    ),
                )

            # Validate each item inside output
            for item in output:
                if not isinstance(item, Evidence):
                    return GuardExecutionResult(
                        guard_name=guard.name,
                        status=GuardExecutionStatus.INVALID_OUTPUT,
                        evidence=(),
                        duration_ms=duration_ms,
                        error_message=(
                            f"Guard '{guard.name}' emitted invalid item of type '{type(item).__name__}' "
                            f"(expected Evidence)."
                        ),
                    )

            return GuardExecutionResult(
                guard_name=guard.name,
                status=GuardExecutionStatus.SUCCESS,
                evidence=tuple(output),
                duration_ms=duration_ms,
                error_message=None,
            )

        except asyncio.TimeoutError:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return GuardExecutionResult(
                guard_name=guard.name,
                status=GuardExecutionStatus.TIMEOUT,
                evidence=(),
                duration_ms=duration_ms,
                error_message=f"Guard '{guard.name}' timed out after {timeout:.3f}s.",
            )

        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return GuardExecutionResult(
                guard_name=guard.name,
                status=GuardExecutionStatus.ERROR,
                evidence=(),
                duration_ms=duration_ms,
                error_message=f"{type(exc).__name__}: {str(exc)}",
            )

    async def evaluate(self, context: EvaluationContext) -> RiskEngineResult:
        """Evaluate all applicable registered Guards concurrently.

        Args:
            context: Contextual event, policy, and state information.

        Returns:
            RiskEngineResult containing aggregated Evidence and per-Guard execution records.
        """
        if not isinstance(context, EvaluationContext):
            raise TypeError(f"Expected EvaluationContext, got {type(context).__name__}")

        start_time = time.perf_counter()

        if not self._guards:
            total_duration_ms = (time.perf_counter() - start_time) * 1000.0
            return RiskEngineResult(
                context=context,
                evidence=(),
                guard_results=(),
                duration_ms=total_duration_ms,
            )

        # Separate applicable and non-applicable guards
        applicable_tasks = []
        applicable_guards = []
        skipped_results: dict[str, GuardExecutionResult] = {}

        for guard in self._guards:
            if guard.is_applicable(context):
                applicable_guards.append(guard)
                timeout = self._guard_timeouts.get(guard.name, self._default_timeout)
                applicable_tasks.append(self._execute_guard(guard, context, timeout))
            else:
                skipped_results[guard.name] = GuardExecutionResult(
                    guard_name=guard.name,
                    status=GuardExecutionStatus.SKIPPED,
                    evidence=(),
                    duration_ms=0.0,
                    error_message=None,
                )

        # Run applicable guards concurrently
        executed_results = await asyncio.gather(*applicable_tasks) if applicable_tasks else []
        results_by_name = {res.guard_name: res for res in executed_results}
        results_by_name.update(skipped_results)

        # Preserve exact registration order in guard_results
        ordered_guard_results = tuple(results_by_name[g.name] for g in self._guards)

        # Aggregate evidence strictly from SUCCESS execution results
        aggregated_evidence: list[Evidence] = []
        for res in ordered_guard_results:
            if res.status == GuardExecutionStatus.SUCCESS:
                aggregated_evidence.extend(res.evidence)

        total_duration_ms = (time.perf_counter() - start_time) * 1000.0

        return RiskEngineResult(
            context=context,
            evidence=tuple(aggregated_evidence),
            guard_results=ordered_guard_results,
            duration_ms=total_duration_ms,
        )
