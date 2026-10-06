"""Tests for GuardX Phase 9 Showcase Demonstration.

Verifies:
1. Benign request -> live pipeline produces ALLOW
2. Prompt injection -> live pipeline produces BLOCK
3. Benign personal identifier -> live pipeline produces ALLOW
4. Policy forbidden action -> live pipeline produces BLOCK
5. Customers.csv exfiltration -> live pipeline produces BLOCK with provenance & authorization findings
6. Safe contrasting data flow -> live pipeline produces ALLOW
7. Predefined scenarios contain NO hardcoded final Verdict or ArbiterResult
8. DemoRunner produces real ArbiterResult and immutable Evidence instances
9. Showcase DAG executes actual graph traversal and property propagation
10. Step-by-step walkthrough incrementally evaluates the DAG pipeline
"""

import unittest

from demo.runner import DemoRunner, serialize_execution_result
from demo.scenarios import SCENARIOS, DemoScenario
from guardx.arbiter.models import ArbiterResult
from guardx.domain.enums import Verdict
from guardx.domain.evidence import Evidence
from guardx.provenance.models import SafetyProperty


class TestGuardXDemo(unittest.TestCase):
    """Test suite for the Phase 9 demonstration runner and scenarios."""

    def setUp(self) -> None:
        self.runner = DemoRunner()

    def test_no_scenario_hardcodes_verdict(self) -> None:
        """Verify that scenario definitions do NOT contain hardcoded final verdicts."""
        for scenario_id, scenario in SCENARIOS.items():
            self.assertFalse(hasattr(scenario, "verdict"), f"Scenario {scenario_id} must not define 'verdict'")
            self.assertFalse(hasattr(scenario, "final_decision"), f"Scenario {scenario_id} must not define 'final_decision'")
            self.assertFalse(hasattr(scenario, "arbiter_result"), f"Scenario {scenario_id} must not define 'arbiter_result'")

    def test_scenario_benign_produces_allow(self) -> None:
        """Scenario 1: Benign request must run through real RiskEngine and produce ALLOW."""
        scenario = SCENARIOS["benign"]
        result = self.runner.run_scenario(scenario)

        # Result verification
        self.assertIsInstance(result.arbiter_result, ArbiterResult)
        self.assertEqual(result.arbiter_result.verdict, Verdict.ALLOW)
        self.assertEqual(result.arbiter_result.reason_code, "CLEAN_EVALUATION")
        self.assertGreater(len(result.risk_result.guard_results), 0)

    def test_scenario_prompt_injection_produces_block(self) -> None:
        """Scenario 2: Prompt injection must be flagged by SecurityGuard and produce BLOCK."""
        scenario = SCENARIOS["prompt_injection"]
        result = self.runner.run_scenario(scenario)

        self.assertIsInstance(result.arbiter_result, ArbiterResult)
        self.assertEqual(result.arbiter_result.verdict, Verdict.BLOCK)
        self.assertIn("SECURITY", result.arbiter_result.reason_code)

        # Verify evidence emitted by SecurityGuard
        security_evidence = [e for e in result.evidence_records if e.source_guard == "SecurityGuard"]
        self.assertGreater(len(security_evidence), 0)
        self.assertTrue(any(e.risk_type == "SECURITY_INSTRUCTION_OVERRIDE" for e in security_evidence))

    def test_scenario_privacy_personal_identifier_allows(self) -> None:
        """Scenario 3a: Benign personal identifier detected does not automatically BLOCK."""
        scenario = SCENARIOS["privacy_personal_identifier"]
        result = self.runner.run_scenario(scenario)

        self.assertIsInstance(result.arbiter_result, ArbiterResult)
        self.assertEqual(result.arbiter_result.verdict, Verdict.ALLOW)

        # Verify PrivacyGuard actually ran and emitted evidence
        privacy_evidence = [e for e in result.evidence_records if e.source_guard == "PrivacyGuard"]
        self.assertGreater(len(privacy_evidence), 0)
        self.assertEqual(privacy_evidence[0].recommended_action.name, "ALLOW")

    def test_scenario_policy_forbidden_action_blocks(self) -> None:
        """Scenario 3b: Action forbidden by policy produces BLOCK."""
        scenario = SCENARIOS["policy_forbidden_action"]
        result = self.runner.run_scenario(scenario)

        self.assertIsInstance(result.arbiter_result, ArbiterResult)
        self.assertEqual(result.arbiter_result.verdict, Verdict.BLOCK)
        self.assertIn("POLICY", result.arbiter_result.reason_code)

        # Verify PolicyGuard emitted evidence
        policy_evidence = [e for e in result.evidence_records if e.source_guard == "PolicyGuard"]
        self.assertGreater(len(policy_evidence), 0)

    def test_scenario_data_exfiltration_unsafe_blocks(self) -> None:
        """Scenario 4: customers.csv data exfiltration produces BLOCK via DAG propagation and ActionAuthorization."""
        scenario = SCENARIOS["data_exfiltration_unsafe"]
        result = self.runner.run_scenario(scenario)

        self.assertIsInstance(result.arbiter_result, ArbiterResult)
        self.assertEqual(result.arbiter_result.verdict, Verdict.BLOCK)
        self.assertEqual(result.arbiter_result.reason_code, "POLICY_BLOCK_RECOMMENDED")

        # Verify effective properties were computed from DAG
        self.assertIsNotNone(result.effective_properties)
        exfil_props = result.effective_properties.get("data:summary", ())
        self.assertIn("PII", exfil_props)
        self.assertIn("CONFIDENTIAL", exfil_props)

        # Verify Action Authorization Engine emitted evidence
        auth_evidence = [e for e in result.evidence_records if e.source_guard == "ActionAuthorizationEngine"]
        self.assertGreater(len(auth_evidence), 0)
        self.assertEqual(auth_evidence[0].risk_type, "policy.unauthorized_sensitive_data_transfer")
        self.assertIn("CONFIDENTIAL", auth_evidence[0].supporting_data.get("violating_properties", ()))

    def test_scenario_data_exfiltration_safe_contrasting_allows(self) -> None:
        """Scenario 5: Contrasting safe data transfer with internal destination produces ALLOW."""
        scenario = SCENARIOS["data_exfiltration_safe"]
        result = self.runner.run_scenario(scenario)

        self.assertIsInstance(result.arbiter_result, ArbiterResult)
        self.assertEqual(result.arbiter_result.verdict, Verdict.ALLOW)
        self.assertEqual(result.arbiter_result.reason_code, "CLEAN_EVALUATION")

        # In ActionAuthorizationEngine, clean actions produce zero evidence (clean evaluation -> ALLOW)
        auth_evidence = [e for e in result.evidence_records if e.source_guard == "ActionAuthorizationEngine"]
        self.assertEqual(len(auth_evidence), 0)

    def test_step_by_step_execution(self) -> None:
        """Verify incremental step-by-step DAG building and execution."""
        scenario = SCENARIOS["data_exfiltration_unsafe"]

        # Step 1: Read customers.csv
        res_step1 = self.runner.run_scenario(scenario, up_to_step=1)
        self.assertEqual(len(res_step1.dag_nodes), 1)
        self.assertEqual(res_step1.dag_nodes[0]["id"], "res:customers.csv")

        # Step 3: Summarize customer data
        res_step3 = self.runner.run_scenario(scenario, up_to_step=3)
        self.assertEqual(len(res_step3.dag_nodes), 4)

        # Step 6: Full pipeline
        res_step6 = self.runner.run_scenario(scenario, up_to_step=6)
        self.assertEqual(len(res_step6.dag_nodes), 4)
        self.assertEqual(res_step6.arbiter_result.verdict, Verdict.BLOCK)

    def test_serialization(self) -> None:
        """Verify that serialization produces valid dict format for Web UI API."""
        scenario = SCENARIOS["data_exfiltration_unsafe"]
        result = self.runner.run_scenario(scenario)
        payload = serialize_execution_result(result)

        self.assertIn("scenario", payload)
        self.assertIn("arbiter", payload)
        self.assertEqual(payload["arbiter"]["verdict"], "BLOCK")
        self.assertIn("evidence", payload)
        self.assertIn("dag", payload)
        self.assertEqual(len(payload["dag"]["nodes"]), 4)


class TestGuardXDemoHTTPServer(unittest.TestCase):
    """Integration test suite for the GuardX showcase HTTP server."""

    @classmethod
    def setUpClass(cls) -> None:
        import threading
        import time
        from demo.server import create_demo_server

        cls.server = create_demo_server(host="127.0.0.1", port=8991)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_get_root_html(self) -> None:
        """Verify GET / returns HTTP 200 with HTML document."""
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:8991/") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            content = resp.read().decode("utf-8")
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("GuardX", content)

    def test_get_favicon_no_content(self) -> None:
        """Verify GET /favicon.ico returns HTTP 204 No Content without error."""
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:8991/favicon.ico") as resp:
            self.assertEqual(resp.status, 204)

    def test_get_api_scenarios(self) -> None:
        """Verify GET /api/scenarios returns valid JSON dictionary with all registered scenarios."""
        import json
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:8991/api/scenarios") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("application/json", resp.headers.get("Content-Type", ""))
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIsInstance(data, dict)
            for sc_id in SCENARIOS:
                self.assertIn(sc_id, data)
                item = data[sc_id]
                self.assertEqual(item["scenario_id"], sc_id)
                self.assertEqual(item["id"], sc_id)
                self.assertIn("title", item)
                self.assertIn("category", item)
                self.assertIn("description", item)
                self.assertIn("steps", item)

    def test_post_api_run_all_scenarios(self) -> None:
        """Verify POST /api/run executes every scenario through real GuardX pipeline via HTTP."""
        import json
        import urllib.request

        expected_verdicts = {
            "benign": "ALLOW",
            "prompt_injection": "BLOCK",
            "privacy_personal_identifier": "ALLOW",
            "policy_forbidden_action": "BLOCK",
            "data_exfiltration_unsafe": "BLOCK",
            "data_exfiltration_safe": "ALLOW",
        }

        for sc_id, expected_verdict in expected_verdicts.items():
            req_body = json.dumps({"scenario_id": sc_id}).encode("utf-8")
            req = urllib.request.Request(
                "http://127.0.0.1:8991/api/run",
                data=req_body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertIn("arbiter", data)
                self.assertEqual(
                    data["arbiter"]["verdict"],
                    expected_verdict,
                    f"HTTP API produced incorrect verdict for {sc_id}",
                )
                self.assertIn("execution_time_ms", data)
                self.assertIn("evidence", data)

    def test_post_api_run_data_exfiltration_step_by_step(self) -> None:
        """Verify step-by-step execution through the HTTP API."""
        import json
        import urllib.request

        req_body = json.dumps({
            "scenario_id": "data_exfiltration_unsafe",
            "up_to_step": 1,
        }).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:8991/api/run",
            data=req_body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(len(data["dag"]["nodes"]), 1)
            self.assertEqual(data["dag"]["nodes"][0]["id"], "res:customers.csv")


if __name__ == "__main__":
    unittest.main()
