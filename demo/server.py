"""GuardX Showcase Demonstration - HTTP Server.

Lightweight, zero-external-dependency local HTTP server using Python's standard library
http.server. Serves the interactive web interface and provides JSON API endpoints
for live GuardX execution.
"""

from __future__ import annotations

import json
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

# Ensure project root is in sys.path
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from demo.runner import DemoRunner, serialize_execution_result
from demo.scenarios import SCENARIOS


class GuardXDemoHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the GuardX showcase demo."""

    runner = DemoRunner()

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path in ("/", "/index.html"):
            self._serve_static_file("demo/web/index.html", "text/html; charset=utf-8")
        elif self.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
        elif self.path == "/api/scenarios":
            self._handle_api_scenarios()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Resource not found")

    def do_POST(self) -> None:
        """Handle POST requests."""
        if self.path == "/api/run":
            self._handle_api_run()
        elif self.path == "/api/analyze":
            self._handle_api_analyze()
        elif self.path == "/api/analyze/action":
            self._handle_api_analyze_action()
        elif self.path == "/api/analyze/trace":
            self._handle_api_analyze_trace()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def _serve_static_file(self, relative_path: str, content_type: str) -> None:
        file_path = os.path.join(_PROJECT_ROOT, relative_path)
        if not os.path.exists(file_path):
            self.send_error(HTTPStatus.NOT_FOUND, f"File {relative_path} not found")
            return

        with open(file_path, "rb") as f:
            content = f.read()

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _read_json_body(self) -> tuple[dict[str, Any] | None, str | None]:
        """Read and parse JSON body from incoming request with validation."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return None, "Empty request body"

        raw_body = self.rfile.read(content_length)
        try:
            body = json.loads(raw_body.decode("utf-8"))
            if not isinstance(body, dict):
                return None, "Request body must be a JSON object"
            return body, None
        except json.JSONDecodeError as exc:
            return None, f"Malformed JSON payload: {str(exc)}"

    def _handle_api_scenarios(self) -> None:
        payload = {
            s.scenario_id: {
                "scenario_id": s.scenario_id,
                "id": s.scenario_id,
                "title": s.title,
                "category": s.category,
                "description": s.description,
                "has_dag": s.dag_builder is not None,
                "total_steps": len(s.steps),
                "steps": [
                    {
                        "step_number": st.step_number,
                        "title": st.title,
                        "description": st.description,
                        "action_type": st.action_type,
                        "detail": st.detail,
                    }
                    for st in s.steps
                ],
            }
            for s in SCENARIOS.values()
        }
        self._send_json(payload)

    def _handle_api_run(self) -> None:
        body, err = self._read_json_body()
        if err:
            self._send_json({"error": err}, status=HTTPStatus.BAD_REQUEST)
            return

        scenario_id = body.get("scenario_id")
        up_to_step = body.get("up_to_step")

        if not scenario_id or scenario_id not in SCENARIOS:
            self._send_json({"error": f"Scenario '{scenario_id}' not found"}, status=HTTPStatus.NOT_FOUND)
            return

        scenario = SCENARIOS[scenario_id]
        try:
            result = self.runner.run_scenario(scenario, up_to_step=up_to_step)
            data = serialize_execution_result(result)
            self._send_json(data)
        except Exception as e:
            self._send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_api_analyze(self) -> None:
        """Analyze arbitrary user-supplied content for INPUT, OUTPUT, or TOOL_RESULT events."""
        body, err = self._read_json_body()
        if err:
            self._send_json({"error": err}, status=HTTPStatus.BAD_REQUEST)
            return

        interception_point = body.get("interception_point")
        if not interception_point or not isinstance(interception_point, str):
            self._send_json(
                {"error": "Field 'interception_point' is required and must be a string (e.g. 'INPUT', 'OUTPUT', 'TOOL_RESULT', 'ACTION')"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        valid_points = {"INPUT", "OUTPUT", "TOOL_RESULT", "ACTION"}
        if interception_point.strip().upper() not in valid_points:
            self._send_json(
                {"error": f"Invalid interception_point '{interception_point}'. Valid choices: {sorted(list(valid_points))}"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        if "payload" not in body:
            self._send_json(
                {"error": "Field 'payload' is required"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        payload = body.get("payload")
        policies = body.get("policies")
        if policies is not None and not isinstance(policies, dict):
            self._send_json(
                {"error": "Optional field 'policies' must be a JSON object"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        try:
            result = self.runner.analyze_arbitrary_event(
                interception_point=interception_point.strip().upper(),
                payload=payload,
                policies=policies,
            )
            data = serialize_execution_result(result)
            self._send_json(data)
        except ValueError as ve:
            self._send_json({"error": str(ve)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as e:
            self._send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_api_analyze_action(self) -> None:
        """Inspect and authorize arbitrary user-supplied ACTION request."""
        body, err = self._read_json_body()
        if err:
            self._send_json({"error": err}, status=HTTPStatus.BAD_REQUEST)
            return

        action_name = body.get("action_name")
        if not action_name or not isinstance(action_name, str) or not action_name.strip():
            self._send_json(
                {"error": "Field 'action_name' is required and must be a non-empty string"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        destination = body.get("destination")
        if destination is not None and not isinstance(destination, str):
            self._send_json(
                {"error": "Field 'destination' must be a string"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        arguments = body.get("arguments")
        if arguments is not None and not isinstance(arguments, dict):
            self._send_json(
                {"error": "Field 'arguments' must be a JSON object"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        permissions = body.get("permissions")
        if permissions is not None:
            if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
                self._send_json(
                    {"error": "Field 'permissions' must be an array of strings"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

        policies = body.get("policies")
        if policies is not None and not isinstance(policies, dict):
            self._send_json(
                {"error": "Field 'policies' must be a JSON object"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        try:
            result = self.runner.analyze_arbitrary_action(
                action_name=action_name,
                destination=destination,
                arguments=arguments,
                permissions=permissions,
                policies=policies,
            )
            data = serialize_execution_result(result)
            self._send_json(data)
        except ValueError as ve:
            self._send_json({"error": str(ve)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as e:
            self._send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_api_analyze_trace(self) -> None:
        """Build simulated ActionProvenanceDAG and authorize action lineage."""
        body, err = self._read_json_body()
        if err:
            self._send_json({"error": err}, status=HTTPStatus.BAD_REQUEST)
            return

        resource_name = body.get("resource_name")
        if not resource_name or not isinstance(resource_name, str) or not resource_name.strip():
            self._send_json(
                {"error": "Field 'resource_name' is required and must be a non-empty string"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        safety_properties = body.get("safety_properties")
        if safety_properties is None or not isinstance(safety_properties, list) or not all(isinstance(p, str) for p in safety_properties):
            self._send_json(
                {"error": "Field 'safety_properties' is required and must be an array of strings (e.g. ['PII', 'CONFIDENTIAL'])"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        transformation = body.get("transformation") or body.get("transformation_type")
        if not transformation or not isinstance(transformation, str) or not transformation.strip():
            self._send_json(
                {"error": "Field 'transformation' is required and must be a non-empty string (e.g. 'SUMMARIZE', 'VERIFIED_PII_REDACTION')"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        action_name = body.get("action_name")
        if not action_name or not isinstance(action_name, str) or not action_name.strip():
            self._send_json(
                {"error": "Field 'action_name' is required and must be a non-empty string"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        destination = body.get("destination")
        if not destination or not isinstance(destination, str) or not destination.strip():
            self._send_json(
                {"error": "Field 'destination' is required and must be a non-empty string"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        policies = body.get("policies")
        if policies is not None and not isinstance(policies, dict):
            self._send_json(
                {"error": "Field 'policies' must be a JSON object"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        try:
            result = self.runner.analyze_arbitrary_trace(
                resource_name=resource_name,
                safety_properties=safety_properties,
                transformation_type=transformation,
                action_name=action_name,
                destination=destination,
                policies=policies,
            )
            data = serialize_execution_result(result)
            self._send_json(data)
        except ValueError as ve:
            self._send_json({"error": str(ve)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as e:
            self._send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        serialized = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(serialized)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(serialized)

    def log_message(self, format: str, *args: Any) -> None:
        """Override to suppress standard noisy logging or format cleanly."""
        sys.stderr.write(f"[GuardX Demo Server] {self.address_string()} - {format % args}\n")


def create_demo_server(host: str = "127.0.0.1", port: int = 8080) -> HTTPServer:
    """Create and return a configured HTTPServer instance."""
    return HTTPServer((host, port), GuardXDemoHandler)


def start_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Start the demonstration server on the specified host and port."""
    server = create_demo_server(host, port)
    print(f"============================================================")
    print(f"  GuardX Showcase Demonstration Server Running")
    print(f"  URL: http://{host}:{port}")
    print(f"  Zero external dependencies (Python standard library)")
    print(f"  Press Ctrl+C to stop.")
    print(f"============================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down GuardX Demo Server...")
    finally:
        server.server_close()
