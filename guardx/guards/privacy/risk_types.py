"""Stable, machine-readable risk types for the Privacy Guard."""

from enum import Enum


class PrivacyRiskType(str, Enum):
    """Machine-readable risk identifiers for Privacy findings."""

    CREDENTIAL_EXPOSURE = "privacy.credential_exposure"
    PERSONAL_IDENTIFIER = "privacy.personal_identifier"
    SENSITIVE_RESOURCE = "privacy.sensitive_resource"
    UNAUTHORIZED_DISCLOSURE = "privacy.unauthorized_disclosure"
