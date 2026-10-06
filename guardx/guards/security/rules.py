"""Deterministic security rules for the Security Guard."""

from abc import ABC, abstractmethod
import re
from typing import Any, Optional, Pattern, Sequence

from guardx.domain.context import EvaluationContext
from guardx.domain.enums import Confidence, InterceptionPoint, RecommendedAction, RiskCategory, Severity
from guardx.domain.evidence import Evidence
from guardx.guards.security.risk_types import SecurityRiskType


def _extract_text(payload: Any) -> str:
    """Extract string representation from various payload structures."""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        # Extract text or command field from dict payloads
        for key in ("text", "prompt", "query", "command", "cmd", "body", "content"):
            if key in payload and isinstance(payload[key], str):
                return payload[key]
        return str(payload)
    return "" if payload is None else str(payload)


class SecurityRule(ABC):
    """Abstract base class for modular, deterministic security rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Stable machine-readable identifier for this rule."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this rule detects."""
        ...

    @property
    @abstractmethod
    def supported_interception_points(self) -> tuple[InterceptionPoint, ...]:
        """Interception points where this rule is active."""
        ...

    @abstractmethod
    def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        """Evaluate the context deterministically and return any Evidence records."""
        ...


class InstructionOverrideRule(SecurityRule):
    """Detects explicit user or content attempts to override system instructions (T-01, T-02)."""

    rule_id: str = "SEC-RULE-001"
    description: str = "Detects explicit attempts to override prior/system instructions or prompts."
    supported_interception_points: tuple[InterceptionPoint, ...] = (
        InterceptionPoint.INPUT,
        InterceptionPoint.TOOL_RESULT,
    )

    # Patterns indicating imperative instruction overrides
    _OVERRIDE_PATTERNS: tuple[Pattern[str], ...] = (
        re.compile(
            r"\b(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|existing|above|system)\s+(instructions?|prompts?|rules?|directives?|guidelines?)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(you\s+are\s+now|act\s+as)\s+an?\s+(?:(?:unrestricted|unfiltered|jailbroken|evil)\s+)+(ai|assistant|model|agent|bot)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(do\s+anything\s+now|DAN\s+mode|developer\s+mode\s+enabled)\b",
            re.IGNORECASE,
        ),
    )

    # Patterns indicating benign educational discussion ABOUT prompt injection
    _BENIGN_EXPLANATION_PATTERN: Pattern[str] = re.compile(
        r"^(what\s+is|explain|describe|define|how\s+does|how\s+to\s+prevent|tell\s+me\s+about)\s+.*(prompt\s+injection|instruction\s+override)",
        re.IGNORECASE,
    )

    def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        text = _extract_text(context.event.payload).strip()
        if not text:
            return ()

        # False positive protection: benign questions about the concept
        if self._BENIGN_EXPLANATION_PATTERN.search(text) and not any(
            p.search(text) for p in self._OVERRIDE_PATTERNS
        ):
            return ()

        findings: list[Evidence] = []
        for pattern in self._OVERRIDE_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    Evidence(
                        source_guard="SecurityGuard",
                        guard_version="1.0.0",
                        risk_category=RiskCategory.SECURITY,
                        risk_type=SecurityRiskType.INSTRUCTION_OVERRIDE.value,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description="Explicit instruction override attempt detected.",
                        affected_entities=(context.event.event_id,),
                        supporting_data={
                            "rule_id": self.rule_id,
                            "matched_pattern": match.group(0),
                        },
                        recommended_action=RecommendedAction.BLOCK,
                    )
                )
                # One finding per rule is sufficient
                break

        return tuple(findings)


class SystemPromptExtractionRule(SecurityRule):
    """Detects imperative requests to leak or extract system/developer instructions (T-04)."""

    rule_id: str = "SEC-RULE-002"
    description: str = "Detects attempts to extract or display hidden system/developer prompts."
    supported_interception_points: tuple[InterceptionPoint, ...] = (InterceptionPoint.INPUT,)

    _EXTRACTION_PATTERNS: tuple[Pattern[str], ...] = (
        re.compile(
            r"\b(reveal|show|print|display|dump|leak|output|tell\s+me)\s+(your\s+|the\s+)?(system\s+prompt|developer\s+instructions?|initial\s+prompt|system\s+instructions?|hidden\s+prompt)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(repeat|recite|echo)\s+(your\s+|the\s+)?(instructions\s+above|system\s+prompt|pre-prompt)\b",
            re.IGNORECASE,
        ),
    )

    _BENIGN_QUESTION_PATTERN: Pattern[str] = re.compile(
        r"^(what\s+is|how\s+do\s+you\s+write|how\s+to\s+write|explain)\s+an?\s+(system\s+prompt|developer\s+instruction)",
        re.IGNORECASE,
    )

    def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        text = _extract_text(context.event.payload).strip()
        if not text:
            return ()

        if self._BENIGN_QUESTION_PATTERN.search(text) and not any(
            p.search(text) for p in self._EXTRACTION_PATTERNS
        ):
            return ()

        findings: list[Evidence] = []
        for pattern in self._EXTRACTION_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    Evidence(
                        source_guard="SecurityGuard",
                        guard_version="1.0.0",
                        risk_category=RiskCategory.SECURITY,
                        risk_type=SecurityRiskType.SYSTEM_PROMPT_EXTRACTION.value,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description="System/developer prompt extraction attempt detected.",
                        affected_entities=(context.event.event_id,),
                        supporting_data={
                            "rule_id": self.rule_id,
                            "matched_pattern": match.group(0),
                        },
                        recommended_action=RecommendedAction.BLOCK,
                    )
                )
                break

        return tuple(findings)


class IndirectInjectionMarkerRule(SecurityRule):
    """Detects embedded prompt-injection payload markers inside external tool results (T-02, T-11)."""

    rule_id: str = "SEC-RULE-003"
    description: str = "Detects embedded adversarial injection markers in tool results or retrieved content."
    supported_interception_points: tuple[InterceptionPoint, ...] = (InterceptionPoint.TOOL_RESULT,)

    _INDIRECT_PATTERNS: tuple[Pattern[str], ...] = (
        re.compile(r"\[\s*SYSTEM\s*OVERRIDE\s*\]", re.IGNORECASE),
        re.compile(r"<!--\s*SYSTEM:\s*.*-->", re.IGNORECASE),
        re.compile(r"\b(NEW\s+SYSTEM\s+INSTRUCTION|ADMIN\s+OVERRIDE):", re.IGNORECASE),
        re.compile(
            r"\bSYSTEM\s+PROMPT\s+OVERRIDE:\s*(ignore|disregard|forget)\b",
            re.IGNORECASE,
        ),
    )

    def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        text = _extract_text(context.event.payload).strip()
        if not text:
            return ()

        findings: list[Evidence] = []
        for pattern in self._INDIRECT_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    Evidence(
                        source_guard="SecurityGuard",
                        guard_version="1.0.0",
                        risk_category=RiskCategory.SECURITY,
                        risk_type=SecurityRiskType.INDIRECT_PROMPT_INJECTION.value,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description="Adversarial indirect prompt injection marker detected in tool result.",
                        affected_entities=(context.event.event_id,),
                        supporting_data={
                            "rule_id": self.rule_id,
                            "matched_pattern": match.group(0),
                        },
                        recommended_action=RecommendedAction.BLOCK,
                    )
                )
                break

        return tuple(findings)


class SuspiciousCommandExecutionRule(SecurityRule):
    """Detects dangerous or destructive shell execution commands in proposed actions (T-08, T-10)."""

    rule_id: str = "SEC-RULE-004"
    description: str = "Detects dangerous shell execution commands or destructive payload patterns."
    supported_interception_points: tuple[InterceptionPoint, ...] = (InterceptionPoint.ACTION,)

    _DANGEROUS_COMMAND_PATTERNS: tuple[Pattern[str], ...] = (
        re.compile(r"\brm\s+-[rRfF]{1,3}\s+[/~]", re.IGNORECASE),
        re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:", re.IGNORECASE),  # Fork bomb
        re.compile(r"\b(curl|wget)\s+.*\|\s*(ba)?sh\b", re.IGNORECASE),
        re.compile(r"\bchmod\s+(-R\s+)?777\s+[/~]", re.IGNORECASE),
        re.compile(r"\bmkfs(\.[a-z0-9]+)?\s+/dev/", re.IGNORECASE),
        re.compile(r"\bdd\s+if=/dev/zero\s+of=/dev/", re.IGNORECASE),
    )

    def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        text = _extract_text(context.event.payload).strip()
        if not text:
            return ()

        findings: list[Evidence] = []
        for pattern in self._DANGEROUS_COMMAND_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    Evidence(
                        source_guard="SecurityGuard",
                        guard_version="1.0.0",
                        risk_category=RiskCategory.SECURITY,
                        risk_type=SecurityRiskType.SUSPICIOUS_EXECUTION_COMMAND.value,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        description="Destructive or dangerous command execution pattern detected in action.",
                        affected_entities=(context.event.event_id,),
                        supporting_data={
                            "rule_id": self.rule_id,
                            "matched_command": match.group(0),
                        },
                        recommended_action=RecommendedAction.BLOCK,
                    )
                )
                break

        return tuple(findings)
