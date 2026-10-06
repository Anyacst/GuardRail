"""Interactive Terminal (CLI) Demonstration Runner for GuardX.

Provides rich visual terminal presentation using pure standard library Python
with ANSI color styling, ASCII/Unicode box drawing, and step-by-step walkthroughs.
"""

import argparse
import os
import sys
from typing import Any

# Ensure repository root is on sys.path for direct invocation
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from demo.runner import DemoExecutionResult, DemoRunner
from demo.scenarios import SCENARIOS


# ANSI Color Codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"


def print_banner() -> None:
    """Print the GuardX header banner."""
    print(f"\n{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}{BOLD}║                                 GUARDX RUNTIME                                   ║{RESET}")
    print(f"{CYAN}{BOLD}║                  Runtime Safety Framework for Agentic AI Systems                 ║{RESET}")
    print(f"{CYAN}{BOLD}╚══════════════════════════════════════════════════════════════════════════════════╝{RESET}\n")


def print_verdict_badge(verdict: str) -> None:
    """Print large stylized verdict badge."""
    if verdict == "BLOCK":
        print(f"  {BG_RED}{WHITE}{BOLD} ✖ VERDICT: BLOCK {RESET}")
    elif verdict == "ALLOW":
        print(f"  {BG_GREEN}{WHITE}{BOLD} ✔ VERDICT: ALLOW {RESET}")
    elif verdict == "HUMAN_REVIEW":
        print(f"  {BG_YELLOW}{WHITE}{BOLD} ⚠ VERDICT: HUMAN REVIEW {RESET}")
    elif verdict == "MODIFY":
        print(f"  {BG_YELLOW}{WHITE}{BOLD} ✎ VERDICT: MODIFY {RESET}")
    else:
        print(f"  {BOLD} VERDICT: {verdict} {RESET}")


def display_scenario_result(result: DemoExecutionResult, debug: bool = False) -> None:
    """Display comprehensive visual result of a demo scenario run."""
    scenario = result.scenario

    print(f"{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
    print(f"{CYAN}{BOLD}SCENARIO:{RESET} {scenario.title}")
    print(f"{DIM}Category:{RESET} {scenario.category}")
    print(f"{DIM}Description:{RESET} {scenario.description}\n")

    # Real vs Simulated Callout
    print(f"{BLUE}┌─ REAL VS SIMULATED BREAKDOWN ──────────────────────────────────────────────────┐{RESET}")
    for k, v in scenario.simulated_context.items():
        print(f"{BLUE}│{RESET}  {DIM}• {k}:{RESET} {v}")
    print(f"{BLUE}└────────────────────────────────────────────────────────────────────────────────┘{RESET}\n")

    # Event Details
    print(f"{YELLOW}▶ EVENT INTERCEPTION ({result.event.interception_point.name}){RESET}")
    payload = result.event.payload
    if hasattr(payload, "action_name"):
        print(f"  Action:      {BOLD}{payload.action_name}{RESET}")
        print(f"  Destination: {payload.destination or 'None'}")
        print(f"  Arguments:   {dict(payload.arguments)}")
        if payload.provenance_refs:
            print(f"  Inputs Ref:  {payload.provenance_refs}")
    elif isinstance(payload, dict):
        print(f"  Action Dict: {payload}")
    else:
        print(f"  Input Text:  \"{payload}\"")
    print()

    # Provenance Graph if present
    if result.dag is not None and len(result.dag) > 0:
        print(f"{MAGENTA}▶ PROVENANCE LINEAGE DAG & PROPERTY PROPAGATION{RESET}")
        for node in result.dag.get_nodes():
            props = result.effective_properties.get(node.node_id, ())
            props_str = f"{RED}[{', '.join(props)}]{RESET}" if props else f"{GREEN}[CLEAN]{RESET}"
            print(f"  • Node: {BOLD}{node.node_id}{RESET} ({node.node_type.name}) -> Effective: {props_str}")
            if node.description:
                print(f"    {DIM}Description: {node.description}{RESET}")
        edges = result.dag.get_edges()
        if edges:
            print(f"  {DIM}Lineage Edges:{RESET}")
            for e in edges:
                print(f"    {e.source_id} ──[{e.edge_type.name}]──▶ {e.destination_id}")
        print()

    # Guard Execution Records
    print(f"{CYAN}▶ GUARD ANALYSIS RESULTS{RESET}")
    for gr in result.risk_result.guard_results:
        status_color = GREEN if gr.is_success else RED
        print(f"  • {BOLD}{gr.guard_name}{RESET}: {status_color}{gr.status.name}{RESET} ({gr.duration_ms:.2f}ms) — Findings: {len(gr.evidence)}")

    # Evidence Records
    if result.evidence:
        print(f"\n{RED}▶ COLLECTED EVIDENCE FINDINGS ({len(result.evidence)}){RESET}")
        for i, ev in enumerate(result.evidence, 1):
            rec_color = RED if ev.recommended_action and ev.recommended_action.name == "BLOCK" else YELLOW
            print(f"  {BOLD}[Finding {i}]{RESET} {BOLD}{ev.risk_type}{RESET} by {ev.source_guard}")
            print(f"    Severity: {ev.severity.name} | Confidence: {ev.confidence.name} | Recommended: {rec_color}{ev.recommended_action.name if ev.recommended_action else 'None'}{RESET}")
            print(f"    Detail:   {ev.description}")
            if ev.supporting_data:
                print(f"    Data:     {dict(ev.supporting_data)}")
    else:
        print(f"\n{GREEN}▶ COLLECTED EVIDENCE FINDINGS: Zero risk findings (Clean evaluation){RESET}")
    print()

    # Final Decision
    print(f"{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
    print(f"{BOLD}FINAL ARBITER DECISION:{RESET}")
    print_verdict_badge(result.verdict)
    print(f"\n  {DIM}Reason:{RESET}      {result.arbiter_result.reason}")
    print(f"  {DIM}Reason Code:{RESET} {BOLD}{result.arbiter_result.reason_code}{RESET}")
    print(f"  {DIM}Engine Latency:{RESET} {result.duration_ms:.2f} ms")
    print(f"{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}\n")

    if debug:
        print(f"{DIM}[DEBUG VIEW]")
        print(f"Event ID: {result.event.event_id}")
        if result.evidence:
            for ev in result.evidence:
                print(f"Evidence ID: {ev.evidence_id} | Timestamp: {ev.timestamp.isoformat()}")
        print(f"{RESET}")


def run_step_by_step(scenario_id: str = "data_exfiltration_unsafe") -> None:
    """Run an interactive step-by-step presentation of the showcase scenario."""
    runner = DemoRunner()
    scenario = SCENARIOS[scenario_id]

    print_banner()
    print(f"{CYAN}{BOLD}STEP-BY-STEP WALKTHROUGH: {scenario.title}{RESET}\n")

    for step in scenario.steps:
        print(f"{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        print(f"{YELLOW}{BOLD}STEP {step.step_number}/6: {step.title}{RESET}")
        print(f"Action Type: {BOLD}{step.action_type}{RESET}")
        print(f"Description: {step.description}")
        print(f"Detail:      {step.detail}\n")

        result = runner.run_scenario(scenario_id, up_to_step=step.step_number)

        if result.dag is not None:
            print(f"  {MAGENTA}Current Provenance DAG ({len(result.dag)} nodes):{RESET}")
            for node in result.dag.get_nodes():
                props = result.effective_properties.get(node.node_id, ())
                props_str = f"{RED}[{', '.join(props)}]{RESET}" if props else f"{GREEN}[CLEAN]{RESET}"
                print(f"    • {node.node_id} ({node.node_type.name}) {props_str}")

        if step.step_number >= 5:
            print(f"\n  {CYAN}Authorization Evidence Emitted:{RESET}")
            for ev in result.evidence:
                print(f"    • {ev.risk_type} -> Recommended: {ev.recommended_action.name if ev.recommended_action else 'None'}")
            print(f"\n  {BOLD}Step {step.step_number} Arbiter Outcome:{RESET}")
            print_verdict_badge(result.verdict)
            print(f"  Reason: {result.arbiter_result.reason}")

        print(f"{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        if step.step_number < len(scenario.steps):
            try:
                input(f"\n{DIM}Press [Enter] to advance to Step {step.step_number + 1}...{RESET}")
            except (EOFError, KeyboardInterrupt):
                print("\nExiting step walkthrough.")
                return


def run_single_scenario(scenario_id: str, debug: bool = False) -> None:
    """Run a single scenario by ID and display formatted results."""
    runner = DemoRunner()
    print_banner()
    res = runner.run_scenario(scenario_id)
    display_scenario_result(res, debug=debug)


def main() -> None:
    """CLI Entry point for GuardX Demonstration."""
    parser = argparse.ArgumentParser(description="GuardX Runtime Safety Demonstration CLI")
    parser.add_argument(
        "--scenario",
        "-s",
        choices=list(SCENARIOS.keys()) + ["all"],
        default=None,
        help="Run a specific scenario (or 'all')",
    )
    parser.add_argument(
        "--steps",
        action="store_true",
        help="Run data-exfiltration scenario in step-by-step interactive mode",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show detailed technical/debug metadata",
    )

    args = parser.parse_args()

    if args.steps:
        run_step_by_step("data_exfiltration_unsafe")
        return

    runner = DemoRunner()

    if args.scenario == "all":
        print_banner()
        for sid in SCENARIOS:
            res = runner.run_scenario(sid)
            display_scenario_result(res, debug=args.debug)
        return

    if args.scenario:
        print_banner()
        res = runner.run_scenario(args.scenario)
        display_scenario_result(res, debug=args.debug)
        return

    # Interactive menu if no scenario specified
    print_banner()
    print(f"{BOLD}Select a demonstration scenario to execute:{RESET}\n")
    scenario_list = list(SCENARIOS.items())
    for idx, (sid, sc) in enumerate(scenario_list, 1):
        print(f"  {CYAN}{BOLD}[{idx}]{RESET} {sc.title}")
        print(f"      {DIM}{sc.description[:85]}...{RESET}")
    print(f"  {CYAN}{BOLD}[7]{RESET} Step-by-Step Data Exfiltration Walkthrough")
    print(f"  {CYAN}{BOLD}[8]{RESET} Run All Scenarios Consecutively")
    print(f"  {CYAN}{BOLD}[0]{RESET} Exit\n")

    try:
        choice = input(f"{BOLD}Enter selection (0-8): {RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
        return

    if choice == "0":
        return
    elif choice == "7":
        run_step_by_step("data_exfiltration_unsafe")
    elif choice == "8":
        for sid in SCENARIOS:
            res = runner.run_scenario(sid)
            display_scenario_result(res, debug=args.debug)
    else:
        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(scenario_list):
                chosen_id = scenario_list[choice_idx][0]
                res = runner.run_scenario(chosen_id)
                display_scenario_result(res, debug=args.debug)
            else:
                print(f"{RED}Invalid option.{RESET}")
        except ValueError:
            print(f"{RED}Invalid input.{RESET}")


if __name__ == "__main__":
    main()
