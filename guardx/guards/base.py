"""Base Guard interface and abstractions."""

from abc import ABC, abstractmethod
from typing import Sequence

from guardx.domain.context import EvaluationContext
from guardx.domain.enums import RiskCategory
from guardx.domain.evidence import Evidence


class Guard(ABC):
    """Abstract base class defining the contract for all specialized Guards.

    Guards perform domain-specific safety analysis and emit structured Evidence.
    Guards do not independently authorize actions or own the final system decision.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Name identifying this Guard."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Version identifier of this Guard."""
        ...

    @property
    @abstractmethod
    def risk_category(self) -> RiskCategory:
        """The primary risk domain evaluated by this Guard."""
        ...

    def is_applicable(self, context: EvaluationContext) -> bool:
        """Determine whether this Guard is applicable for the given context.

        Args:
            context: Contextual event, policy, and state information.

        Returns:
            True if this Guard should be evaluated for the context, False to skip.
            Defaults to True unless overridden by a specialized Guard.
        """
        return True

    @abstractmethod
    async def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        """Asynchronously evaluate the provided EvaluationContext and return Evidence.

        Args:
            context: Contextual event, policy, and state information.

        Returns:
            A sequence of structured Evidence records (empty if no findings).
        """
        ...
