"""Stable machine-readable risk type identifiers for Security Guard findings."""

from enum import Enum


class SecurityRiskType(str, Enum):
    """Enumeration of stable machine-readable risk types detected by the Security Guard."""

    INSTRUCTION_OVERRIDE = "SECURITY_INSTRUCTION_OVERRIDE"
    SYSTEM_PROMPT_EXTRACTION = "SECURITY_SYSTEM_PROMPT_EXTRACTION"
    INDIRECT_PROMPT_INJECTION = "SECURITY_INDIRECT_PROMPT_INJECTION"
    SUSPICIOUS_EXECUTION_COMMAND = "SECURITY_SUSPICIOUS_EXECUTION_COMMAND"
