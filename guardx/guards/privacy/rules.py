"""Deterministic privacy rules for the Privacy Guard."""

from abc import ABC, abstractmethod
import re
from typing import Any, Pattern, Sequence

from guardx.domain.context import EvaluationContext
from guardx.domain.enums import Confidence, InterceptionPoint, RecommendedAction, RiskCategory, Severity
from guardx.domain.evidence import Evidence
from guardx.guards.privacy.risk_types import PrivacyRiskType


def _extract_text(payload: Any) -> str:
    """Extract string representation from various payload structures."""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        for key in ("text", "prompt", "query", "command", "cmd", "body", "content", "arguments", "params"):
            if key in payload and isinstance(payload[key], str):
                return payload[key]
        return str(payload)
    return "" if payload is None else str(payload)


def _mask_secret(value: str) -> str:
    """Mask secret value for safe inclusion in evidence supporting_data."""
    if len(value) <= 6:
        return "***"
    return f"{value[:3]}***{value[-2:]}"


class PrivacyRule(ABC):
    """Abstract base class for modular, deterministic privacy rules."""

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


class CredentialExposureRule(PrivacyRule):
    """Detects exposed API keys, bearer tokens, private keys, and database passwords (T-05)."""

    rule_id: str = "PRIV-RULE-001"
    description: str = "Detects exposed API keys, bearer tokens, private keys, or credential connection strings."
    supported_interception_points: tuple[InterceptionPoint, ...] = (
        InterceptionPoint.INPUT,
        InterceptionPoint.OUTPUT,
        InterceptionPoint.ACTION,
        InterceptionPoint.TOOL_RESULT,
    )

    _PRIVATE_KEY_PATTERN: Pattern[str] = re.compile(
        r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----",
        re.IGNORECASE,
    )

    _CREDENTIAL_PATTERNS: tuple[tuple[Pattern[str], str], ...] = (
        (re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"), "OpenAI API Key"),
        (re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"), "GitHub Personal Access Token"),
        (re.compile(r"\bBearer\s+[a-zA-Z0-9_\-\.]{25,}\b", re.IGNORECASE), "Bearer Token"),
        (
            re.compile(
                r"\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?\b"
            ),
            "AWS Secret Access Key",
        ),
        (
            re.compile(r"\b(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_]+:[^@\s]{4,}@[a-zA-Z0-9_\.-]+"),
            "Database Connection String with Credentials",
        ),
    )

    _BENIGN_EXPLANATION_PATTERN: Pattern[str] = re.compile(
        r"^(what\s+is|explain|describe|how\s+does|how\s+to\s+use|tell\s+me\s+about)\s+.*(api\s+key|private\s+key|bearer\s+token|secret|token)",
        re.IGNORECASE,
    )

    _PLACEHOLDER_PATTERN: Pattern[str] = re.compile(
        r"(YOUR_API_KEY|YOUR_KEY_HERE|YOUR_TOKEN_HERE|EXAMPLE_KEY|sk-placeholder)",
        re.IGNORECASE,
    )

    def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        text = _extract_text(context.event.payload).strip()
        if not text:
            return ()

        # False-positive protection for benign educational queries
        if self._BENIGN_EXPLANATION_PATTERN.search(text) and not any(
            p.search(text) for p, _ in self._CREDENTIAL_PATTERNS
        ) and not self._PRIVATE_KEY_PATTERN.search(text):
            return ()

        # Check for placeholder examples
        if self._PLACEHOLDER_PATTERN.search(text):
            return ()

        findings: list[Evidence] = []

        # Check private keys
        pk_match = self._PRIVATE_KEY_PATTERN.search(text)
        if pk_match:
            findings.append(
                Evidence(
                    source_guard="PrivacyGuard",
                    guard_version="1.0.0",
                    risk_category=RiskCategory.PRIVACY,
                    risk_type=PrivacyRiskType.CREDENTIAL_EXPOSURE.value,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description="Private cryptographic key material detected in payload.",
                    affected_entities=(context.event.event_id,),
                    supporting_data={
                        "rule_id": self.rule_id,
                        "credential_type": "Private Key",
                        "matched_header": pk_match.group(0),
                    },
                    recommended_action=RecommendedAction.BLOCK,
                )
            )

        # Check API keys and tokens
        for pattern, cred_type in self._CREDENTIAL_PATTERNS:
            match = pattern.search(text)
            if match:
                matched_val = match.group(0)
                findings.append(
                    Evidence(
                        source_guard="PrivacyGuard",
                        guard_version="1.0.0",
                        risk_category=RiskCategory.PRIVACY,
                        risk_type=PrivacyRiskType.CREDENTIAL_EXPOSURE.value,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"Exposed secret or credential ({cred_type}) detected in payload.",
                        affected_entities=(context.event.event_id,),
                        supporting_data={
                            "rule_id": self.rule_id,
                            "credential_type": cred_type,
                            "masked_value": _mask_secret(matched_val),
                        },
                        recommended_action=RecommendedAction.BLOCK,
                    )
                )
                break

        return tuple(findings)


class PersonalIdentifierRule(PrivacyRule):
    """Detects personal identifiers such as email addresses and phone numbers (T-06)."""

    rule_id: str = "PRIV-RULE-002"
    description: str = "Detects personal identifiers (email addresses, phone numbers) for privacy tracking."
    supported_interception_points: tuple[InterceptionPoint, ...] = (
        InterceptionPoint.INPUT,
        InterceptionPoint.OUTPUT,
        InterceptionPoint.ACTION,
        InterceptionPoint.TOOL_RESULT,
    )

    _EMAIL_PATTERN: Pattern[str] = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    )

    _PHONE_PATTERN: Pattern[str] = re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"
    )

    _BENIGN_QUESTION_PATTERN: Pattern[str] = re.compile(
        r"^(what\s+is|explain|how\s+to\s+validate|describe)\s+.*(email|phone\s+number)",
        re.IGNORECASE,
    )

    def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        text = _extract_text(context.event.payload).strip()
        if not text:
            return ()

        if self._BENIGN_QUESTION_PATTERN.search(text) and not self._EMAIL_PATTERN.search(text) and not self._PHONE_PATTERN.search(text):
            return ()

        findings: list[Evidence] = []

        email_match = self._EMAIL_PATTERN.search(text)
        if email_match:
            findings.append(
                Evidence(
                    source_guard="PrivacyGuard",
                    guard_version="1.0.0",
                    risk_category=RiskCategory.PRIVACY,
                    risk_type=PrivacyRiskType.PERSONAL_IDENTIFIER.value,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="Personal identifier (email address) detected in payload.",
                    affected_entities=(context.event.event_id,),
                    supporting_data={
                        "rule_id": self.rule_id,
                        "identifier_type": "email",
                        "masked_identifier": _mask_secret(email_match.group(0)),
                    },
                    recommended_action=RecommendedAction.ALLOW,
                )
            )

        phone_match = self._PHONE_PATTERN.search(text)
        if phone_match:
            findings.append(
                Evidence(
                    source_guard="PrivacyGuard",
                    guard_version="1.0.0",
                    risk_category=RiskCategory.PRIVACY,
                    risk_type=PrivacyRiskType.PERSONAL_IDENTIFIER.value,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="Personal identifier (phone number) detected in payload.",
                    affected_entities=(context.event.event_id,),
                    supporting_data={
                        "rule_id": self.rule_id,
                        "identifier_type": "phone",
                        "masked_identifier": _mask_secret(phone_match.group(0)),
                    },
                    recommended_action=RecommendedAction.ALLOW,
                )
            )

        return tuple(findings)


class SensitiveResourceRule(PrivacyRule):
    """Detects access or references to known sensitive system configuration and credential files."""

    rule_id: str = "PRIV-RULE-003"
    description: str = "Detects references to sensitive system resources, key files, and credentials."
    supported_interception_points: tuple[InterceptionPoint, ...] = (
        InterceptionPoint.INPUT,
        InterceptionPoint.ACTION,
        InterceptionPoint.TOOL_RESULT,
    )

    _SENSITIVE_PATHS: tuple[Pattern[str], ...] = (
        re.compile(r"/(etc/(?:shadow|sudoers|master\.passwd))\b"),
        re.compile(r"(\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys))\b"),
        re.compile(r"(\.aws/(?:credentials|config))\b"),
        re.compile(r"(?<![a-zA-Z0-9_])(\.env(?:\.[a-zA-Z0-9_\-]+)?)\b"),
    )

    def evaluate(self, context: EvaluationContext) -> Sequence[Evidence]:
        text = _extract_text(context.event.payload).strip()
        if not text:
            return ()

        findings: list[Evidence] = []
        for pattern in self._SENSITIVE_PATHS:
            match = pattern.search(text)
            if match:
                findings.append(
                    Evidence(
                        source_guard="PrivacyGuard",
                        guard_version="1.0.0",
                        risk_category=RiskCategory.PRIVACY,
                        risk_type=PrivacyRiskType.SENSITIVE_RESOURCE.value,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"Access to sensitive resource '{match.group(1)}' detected.",
                        affected_entities=(context.event.event_id,),
                        supporting_data={
                            "rule_id": self.rule_id,
                            "resource_path": match.group(1),
                        },
                        recommended_action=RecommendedAction.BLOCK,
                    )
                )
                break

        return tuple(findings)
