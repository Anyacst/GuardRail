"""Stable, machine-readable risk types for the Policy Guard."""

from enum import Enum


class PolicyRiskType(str, Enum):
    """Machine-readable risk identifiers for Policy findings."""

    FORBIDDEN_ACTION = "policy.forbidden_action"
    FORBIDDEN_DESTINATION = "policy.forbidden_destination"
    HUMAN_REVIEW_REQUIRED = "policy.human_review_required"
    MALFORMED_POLICY = "policy.malformed_policy"
