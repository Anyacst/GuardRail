"""GuardX Showcase Demonstration - Unified Entrypoint.

Provides a unified CLI and Web UI launcher for demonstrating GuardX
runtime safety across prompt injection, privacy/policy controls, and
provenance-aware data exfiltration defense.
"""

from __future__ import annotations

import argparse
import os
import sys

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from demo.cli import main as cli_main, run_single_scenario
from demo.server import start_server


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GuardX Showcase Demonstration Runner (CLI & Web UI)"
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run interactive ANSI terminal demonstration instead of Web UI",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="Run a specific scenario by ID directly in the CLI (e.g., 'data_exfiltration_unsafe')",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address for the demo web server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for the demo web server (default: 8080)",
    )

    args = parser.parse_args()

    if args.scenario:
        run_single_scenario(args.scenario)
    elif args.cli:
        cli_main()
    else:
        start_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
