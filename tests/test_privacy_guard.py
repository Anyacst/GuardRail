"""Unit tests for PrivacyGuard and deterministic privacy rules."""

import unittest

from guardx.domain.context import EvaluationContext
from guardx.domain.enums import (
    Confidence,
    InterceptionPoint,
    RecommendedAction,
    RiskCategory,
    Severity,
)
from guardx.domain.events import SafetyEvent
from guardx.guards.base import Guard
from guardx.guards.privacy import (
    CredentialExposureRule,
    PersonalIdentifierRule,
    PrivacyGuard,
    PrivacyRiskType,
    SensitiveResourceRule,
)


class TestPrivacyGuard(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying PrivacyGuard detection, false-positive protection, and interface compliance."""

    def setUp(self) -> None:
        self.guard = PrivacyGuard()

    def test_guard_interface_contract(self) -> None:
        """Verify PrivacyGuard conforms to the base Guard ABC."""
        self.assertTrue(isinstance(self.guard, Guard))
        self.assertEqual(self.guard.name, "PrivacyGuard")
        self.assertEqual(self.guard.version, "1.0.0")
        self.assertEqual(self.guard.risk_category, RiskCategory.PRIVACY)
        self.assertEqual(len(self.guard.rules), 3)

    async def test_benign_ordinary_inputs(self) -> None:
        """Verify benign ordinary requests produce zero Privacy findings."""
        benign_prompts = [
            "What is the weather today?",
            "Summarize the quarterly results.",
            "Write a Python function to compute Fibonacci numbers.",
        ]
        for prompt in benign_prompts:
            event = SafetyEvent(interception_point=InterceptionPoint.INPUT, payload=prompt)
            findings = await self.guard.evaluate(EvaluationContext(event=event))
            self.assertEqual(len(findings), 0, f"False positive on benign prompt: '{prompt}'")

    async def test_benign_educational_discussions(self) -> None:
        """Verify educational inquiries about API keys or secrets do not trigger credential exposure."""
        educational_prompts = [
            "What is an API key and how does it work?",
            "Explain what a bearer token is.",
            "How does a private key differ from a public key?",
            "Tell me about database connection strings.",
        ]
        for prompt in educational_prompts:
            event = SafetyEvent(interception_point=InterceptionPoint.INPUT, payload=prompt)
            findings = await self.guard.evaluate(EvaluationContext(event=event))
            self.assertEqual(len(findings), 0, f"False positive on educational inquiry: '{prompt}'")

    async def test_placeholder_and_example_values(self) -> None:
        """Verify explicit placeholders like YOUR_API_KEY_HERE do not emit credential findings."""
        placeholders = [
            "curl -H 'Authorization: Bearer YOUR_API_KEY_HERE' https://api.example.com",
            "Set OPENAI_API_KEY=YOUR_KEY_HERE in your environment.",
            "const client = new Client({ apiKey: 'YOUR_TOKEN_HERE' });",
            "api_key = 'sk-placeholder'",
        ]
        for p in placeholders:
            event = SafetyEvent(interception_point=InterceptionPoint.INPUT, payload=p)
            findings = await self.guard.evaluate(EvaluationContext(event=event))
            self.assertEqual(len(findings), 0, f"False positive on placeholder: '{p}'")

    async def test_credential_exposure_detection(self) -> None:
        """Verify detection of various actual credential and token formats."""
        credentials = [
            ("sk-ab12cd34ef56gh78ij90kl12mn34op56", "OpenAI API Key"),
            ("ghp_1234567890abcdefghijklmnopqrstuvwxyz", "GitHub Personal Access Token"),
            ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", "Bearer Token"),
            ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AWS Secret Access Key"),
            ("postgres://admin:supersecretpassword123@db.internal:5432/prod", "Database Connection String with Credentials"),
        ]
        for cred_string, expected_type in credentials:
            event = SafetyEvent(interception_point=InterceptionPoint.INPUT, payload=cred_string)
            findings = await self.guard.evaluate(EvaluationContext(event=event))

            self.assertTrue(len(findings) >= 1, f"Failed to detect credential in: '{cred_string}'")
            finding = findings[0]
            self.assertEqual(finding.source_guard, "PrivacyGuard")
            self.assertEqual(finding.risk_category, RiskCategory.PRIVACY)
            self.assertEqual(finding.risk_type, PrivacyRiskType.CREDENTIAL_EXPOSURE.value)
            self.assertEqual(finding.severity, Severity.HIGH)
            self.assertEqual(finding.confidence, Confidence.HIGH)
            self.assertEqual(finding.recommended_action, RecommendedAction.BLOCK)
            self.assertIn("masked_value", finding.supporting_data)
            # Ensure raw secret is NOT logged in supporting_data
            self.assertNotIn(cred_string, str(finding.supporting_data["masked_value"]))

    async def test_private_key_exposure_detection(self) -> None:
        """Verify detection of private cryptographic key material."""
        private_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1+...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        event = SafetyEvent(interception_point=InterceptionPoint.OUTPUT, payload=private_key)
        findings = await self.guard.evaluate(EvaluationContext(event=event))

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.risk_type, PrivacyRiskType.CREDENTIAL_EXPOSURE.value)
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.recommended_action, RecommendedAction.BLOCK)

    async def test_personal_identifier_detection(self) -> None:
        """Verify detection of personal identifiers (emails, phone numbers) with ALLOW recommendation."""
        sample_text = "Please send the report to alice.smith@example.org or call 415-555-0199."
        event = SafetyEvent(interception_point=InterceptionPoint.INPUT, payload=sample_text)
        findings = await self.guard.evaluate(EvaluationContext(event=event))

        self.assertEqual(len(findings), 2)
        email_finding = next(f for f in findings if f.supporting_data.get("identifier_type") == "email")
        phone_finding = next(f for f in findings if f.supporting_data.get("identifier_type") == "phone")

        self.assertEqual(email_finding.risk_type, PrivacyRiskType.PERSONAL_IDENTIFIER.value)
        self.assertEqual(email_finding.severity, Severity.MEDIUM)
        # Crucial requirement: personal identifier detection is NOT automatically BLOCKED
        self.assertEqual(email_finding.recommended_action, RecommendedAction.ALLOW)

        self.assertEqual(phone_finding.risk_type, PrivacyRiskType.PERSONAL_IDENTIFIER.value)
        self.assertEqual(phone_finding.severity, Severity.MEDIUM)
        self.assertEqual(phone_finding.recommended_action, RecommendedAction.ALLOW)

    async def test_sensitive_resource_detection(self) -> None:
        """Verify detection of sensitive system file access (e.g. /etc/shadow, .env, .ssh keys)."""
        paths = [
            "cat /etc/shadow",
            "Read file from ~/.ssh/id_rsa",
            "Access credentials at ~/.aws/credentials",
            "Load environment variables from .env.production",
        ]
        for path_cmd in paths:
            event = SafetyEvent(interception_point=InterceptionPoint.ACTION, payload={"command": path_cmd})
            findings = await self.guard.evaluate(EvaluationContext(event=event))

            self.assertTrue(len(findings) >= 1, f"Failed to detect sensitive resource in: '{path_cmd}'")
            finding = findings[0]
            self.assertEqual(finding.risk_type, PrivacyRiskType.SENSITIVE_RESOURCE.value)
            self.assertEqual(finding.severity, Severity.HIGH)
            self.assertEqual(finding.recommended_action, RecommendedAction.BLOCK)

    async def test_env_regression_and_benign_variants(self) -> None:
        """Verify explicit .env variants are detected while benign environment terms are not flagged."""
        env_attacks = [
            "cat .env",
            "cp .env.local /tmp/backup",
            "Load settings from .env.production",
            "Read .env.development file",
            "Check /app/.env configuration",
        ]
        for attack in env_attacks:
            event = SafetyEvent(interception_point=InterceptionPoint.ACTION, payload={"command": attack})
            findings = await self.guard.evaluate(EvaluationContext(event=event))
            self.assertTrue(len(findings) >= 1, f"Failed to detect sensitive .env resource in: '{attack}'")
            self.assertEqual(findings[0].risk_type, PrivacyRiskType.SENSITIVE_RESOURCE.value)

        benign_texts = [
            "The natural environment is beautiful in spring.",
            "Set variable environment_name = 'production'",
            "Use python-dotenv to manage configuration.",
            "Consider environmental factors before deployment.",
        ]
        for benign in benign_texts:
            event = SafetyEvent(interception_point=InterceptionPoint.INPUT, payload=benign)
            findings = await self.guard.evaluate(EvaluationContext(event=event))
            self.assertEqual(len(findings), 0, f"False positive on benign environment text: '{benign}'")

    async def test_interception_point_filtering(self) -> None:
        """Verify rules only run on their supported interception points."""
        # SensitiveResourceRule does not run on OUTPUT
        event_output = SafetyEvent(
            interception_point=InterceptionPoint.OUTPUT,
            payload="Accessing /etc/shadow",
        )
        findings = await self.guard.evaluate(EvaluationContext(event=event_output))
        # No sensitive resource finding on OUTPUT
        self.assertFalse(any(f.risk_type == PrivacyRiskType.SENSITIVE_RESOURCE.value for f in findings))

    async def test_multiple_simultaneous_privacy_findings(self) -> None:
        """Verify an event containing both credentials and PII produces multiple distinct Evidence records."""
        payload = (
            "User bob@company.com attempted to export key sk-123456789012345678901234 from /etc/shadow"
        )
        event = SafetyEvent(interception_point=InterceptionPoint.INPUT, payload=payload)
        findings = await self.guard.evaluate(EvaluationContext(event=event))

        self.assertEqual(len(findings), 3)
        risk_types = {f.risk_type for f in findings}
        self.assertIn(PrivacyRiskType.CREDENTIAL_EXPOSURE.value, risk_types)
        self.assertIn(PrivacyRiskType.PERSONAL_IDENTIFIER.value, risk_types)
        self.assertIn(PrivacyRiskType.SENSITIVE_RESOURCE.value, risk_types)

    async def test_edge_cases_and_empty_payloads(self) -> None:
        """Verify empty or structured payloads do not crash PrivacyGuard."""
        for payload in ("", None, {}, {"empty": []}):
            event = SafetyEvent(interception_point=InterceptionPoint.INPUT, payload=payload)
            findings = await self.guard.evaluate(EvaluationContext(event=event))
            self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
