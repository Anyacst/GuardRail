"""Core enumeration and value types for GuardX domain models."""

from enum import Enum


class InterceptionPoint(str, Enum):
    """Interception points where GuardX evaluates safety-relevant events."""

    INPUT = "INPUT"
    OUTPUT = "OUTPUT"
    ACTION = "ACTION"
    TOOL_RESULT = "TOOL_RESULT"


class RiskCategory(str, Enum):
    """Initial risk domains evaluated by specialized Guards."""

    SECURITY = "SECURITY"
    PRIVACY = "PRIVACY"
    CONTENT_SAFETY = "CONTENT_SAFETY"
    POLICY = "POLICY"


class Severity(str, Enum):
    """Potential impact of a detected safety issue if correct."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class Confidence(str, Enum):
    """Certainty level of a finding."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RecommendedAction(str, Enum):
    """Action recommended by a Guard in structured Evidence."""

    ALLOW = "ALLOW"
    MODIFY = "MODIFY"
    BLOCK = "BLOCK"
    HUMAN_REVIEW = "HUMAN_REVIEW"


class Verdict(str, Enum):
    """Final decision produced exclusively by the Arbiter."""

    ALLOW = "ALLOW"
    MODIFY = "MODIFY"
    BLOCK = "BLOCK"
    HUMAN_REVIEW = "HUMAN_REVIEW"
