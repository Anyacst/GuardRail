"""Deterministic Arbiter baseline for GuardX authorization decisions."""

from typing import Optional, Sequence

from guardx.arbiter.models import ArbiterResult
from guardx.domain.enums import InterceptionPoint, RecommendedAction, RiskCategory, Verdict
from guardx.domain.evidence import Evidence
from guardx.engine.models import GuardExecutionResult, GuardExecutionStatus, RiskEngineResult
from guardx.guards.policy.risk_types import PolicyRiskType


class Arbiter:
    """Deterministic decision engine owning the final GuardX authorization decision.

    Core Invariants:
    1. Guards recommend; Arbiter decides.
    2. Decisions are deterministic and auditable.
    3. No majority voting: a single relevant high-impact finding takes precedence.
    4. Severity != Verdict: decisions evaluate evidence meaning, category, policy, and coverage.
    5. Missing guard coverage (timeouts, errors) triggers explicit fail-safe behavior.
    """

    def arbitrate(self, result: RiskEngineResult) -> ArbiterResult:
        """Arbitrate the collected evaluation result and produce the final GuardX Verdict.

        Args:
            result: The aggregated evaluation result from RiskEngine.

        Returns:
            ArbiterResult containing final Verdict, reason, reason_code, decisive evidence,
            considered evidence, and missing guard coverage.
        """
        if not isinstance(result, RiskEngineResult):
            raise TypeError(f"Expected RiskEngineResult, got {type(result).__name__}")

        interception_point = result.context.event.interception_point
        considered_evidence = result.evidence

        # Identify guards with execution failures (TIMEOUT, ERROR, INVALID_OUTPUT)
        # Note: SKIPPED is not a failure (the guard was intentionally non-applicable)
        failed_guard_results = tuple(r for r in result.guard_results if r.has_failed)
        missing_guard_names = tuple(r.guard_name for r in failed_guard_results)
        applicable_guard_results = tuple(
            r for r in result.guard_results if r.status != GuardExecutionStatus.SKIPPED
        )

        # -------------------------------------------------------------
        # Precedence 1: Explicit Deterministic Policy Constraints
        # -------------------------------------------------------------
        policy_evidence = tuple(
            e for e in considered_evidence if e.risk_category == RiskCategory.POLICY
        )
        for ev in policy_evidence:
            if ev.risk_type == PolicyRiskType.FORBIDDEN_ACTION.value:
                return ArbiterResult(
                    verdict=Verdict.BLOCK,
                    reason=f"Action is forbidden by application policy: {ev.description}",
                    reason_code="POLICY_FORBIDDEN_ACTION",
                    decisive_evidence=(ev,),
                    considered_evidence=considered_evidence,
                    missing_guard_coverage=missing_guard_names,
                )
            if ev.risk_type == PolicyRiskType.FORBIDDEN_DESTINATION.value:
                return ArbiterResult(
                    verdict=Verdict.BLOCK,
                    reason=f"Destination is forbidden by application policy: {ev.description}",
                    reason_code="POLICY_FORBIDDEN_DESTINATION",
                    decisive_evidence=(ev,),
                    considered_evidence=considered_evidence,
                    missing_guard_coverage=missing_guard_names,
                )
            if ev.risk_type == PolicyRiskType.MALFORMED_POLICY.value:
                return ArbiterResult(
                    verdict=Verdict.BLOCK,
                    reason=f"Evaluation aborted due to malformed policy configuration: {ev.description}",
                    reason_code="POLICY_MALFORMED",
                    decisive_evidence=(ev,),
                    considered_evidence=considered_evidence,
                    missing_guard_coverage=missing_guard_names,
                )

        # -------------------------------------------------------------
        # Precedence 2: Critical / High-Confidence BLOCK Recommendations
        # -------------------------------------------------------------
        block_evidence = tuple(
            e for e in considered_evidence if e.recommended_action == RecommendedAction.BLOCK
        )
        if block_evidence:
            first_block = block_evidence[0]
            return ArbiterResult(
                verdict=Verdict.BLOCK,
                reason=f"Blocked due to {first_block.risk_category.value.lower()} finding: {first_block.description}",
                reason_code=f"{first_block.risk_category.name}_BLOCK_RECOMMENDED",
                decisive_evidence=block_evidence,
                considered_evidence=considered_evidence,
                missing_guard_coverage=missing_guard_names,
            )

        # -------------------------------------------------------------
        # Precedence 3: Missing Guard Coverage Fail-Safe Handling
        # -------------------------------------------------------------
        if failed_guard_results:
            all_failed = len(failed_guard_results) == len(applicable_guard_results) and len(applicable_guard_results) > 0
            if all_failed:
                if interception_point == InterceptionPoint.ACTION:
                    return ArbiterResult(
                        verdict=Verdict.BLOCK,
                        reason=(
                            f"All applicable Guards failed ({', '.join(missing_guard_names)}) during "
                            "action authorization; failing closed toward safety."
                        ),
                        reason_code="ALL_GUARDS_FAILED_ACTION",
                        decisive_evidence=(),
                        considered_evidence=considered_evidence,
                        missing_guard_coverage=missing_guard_names,
                    )
                return ArbiterResult(
                    verdict=Verdict.HUMAN_REVIEW,
                    reason=(
                        f"All applicable Guards failed ({', '.join(missing_guard_names)}) during "
                        "evaluation; requiring human review."
                    ),
                    reason_code="ALL_GUARDS_FAILED",
                    decisive_evidence=(),
                    considered_evidence=considered_evidence,
                    missing_guard_coverage=missing_guard_names,
                )

            # Partial guard failure
            if interception_point == InterceptionPoint.ACTION:
                return ArbiterResult(
                    verdict=Verdict.BLOCK,
                    reason=(
                        f"Missing required Guard coverage ({', '.join(missing_guard_names)}) during "
                        "action authorization; failing closed toward safety."
                    ),
                    reason_code="PARTIAL_GUARD_FAILURE_ACTION",
                    decisive_evidence=(),
                    considered_evidence=considered_evidence,
                    missing_guard_coverage=missing_guard_names,
                )
            return ArbiterResult(
                verdict=Verdict.HUMAN_REVIEW,
                reason=(
                    f"Missing Guard coverage ({', '.join(missing_guard_names)}) during "
                    "evaluation; requiring human review."
                ),
                reason_code="PARTIAL_GUARD_FAILURE",
                decisive_evidence=(),
                considered_evidence=considered_evidence,
                missing_guard_coverage=missing_guard_names,
            )

        # -------------------------------------------------------------
        # Precedence 4: Human Review Requirements
        # -------------------------------------------------------------
        review_evidence = tuple(
            e for e in considered_evidence if e.recommended_action == RecommendedAction.HUMAN_REVIEW
        )
        if review_evidence:
            first_review = review_evidence[0]
            reason_code = (
                "POLICY_HUMAN_REVIEW_REQUIRED"
                if first_review.risk_category == RiskCategory.POLICY
                else "HUMAN_REVIEW_REQUIRED"
            )
            return ArbiterResult(
                verdict=Verdict.HUMAN_REVIEW,
                reason=f"Operation requires human approval: {first_review.description}",
                reason_code=reason_code,
                decisive_evidence=review_evidence,
                considered_evidence=considered_evidence,
                missing_guard_coverage=missing_guard_names,
            )

        # -------------------------------------------------------------
        # Precedence 5: MODIFY Recommendations
        # -------------------------------------------------------------
        modify_evidence = tuple(
            e for e in considered_evidence if e.recommended_action == RecommendedAction.MODIFY
        )
        if modify_evidence:
            first_modify = modify_evidence[0]
            return ArbiterResult(
                verdict=Verdict.MODIFY,
                reason=f"Modification required: {first_modify.description}",
                reason_code="MODIFY_RECOMMENDED",
                decisive_evidence=modify_evidence,
                considered_evidence=considered_evidence,
                missing_guard_coverage=missing_guard_names,
            )

        # -------------------------------------------------------------
        # Precedence 6: Lower-Risk Findings (ALLOW with noted properties)
        # -------------------------------------------------------------
        if considered_evidence:
            # All existing findings have RecommendedAction.ALLOW (e.g. personal identifiers in legitimate context)
            return ArbiterResult(
                verdict=Verdict.ALLOW,
                reason="Operation authorized with noted sensitive properties.",
                reason_code="ALLOW_WITH_NOTED_PROPERTIES",
                decisive_evidence=considered_evidence,
                considered_evidence=considered_evidence,
                missing_guard_coverage=missing_guard_names,
            )

        # -------------------------------------------------------------
        # Precedence 7: Default Clean Evaluation
        # -------------------------------------------------------------
        return ArbiterResult(
            verdict=Verdict.ALLOW,
            reason="Operation evaluated safe with zero findings.",
            reason_code="CLEAN_EVALUATION",
            decisive_evidence=(),
            considered_evidence=(),
            missing_guard_coverage=(),
        )

    def decide(self, result: RiskEngineResult) -> ArbiterResult:
        """Ergonomic alias for arbitrate()."""
        return self.arbitrate(result)
