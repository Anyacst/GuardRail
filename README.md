# GuardX

**A runtime safety framework for LLM applications and agentic AI systems.**

> ℹ️ **Status: Phases 1–9 Complete — Deterministic Execution-Aware Core & Showcase Demo**
>
> GuardX features a functional deterministic core in Python covering domain models,
> specialized Guards (Security, Privacy, Policy), Risk Engine orchestration, Arbiter,
> Action Provenance DAG, Semantic Property Propagation, Action Authorization,
> and an interactive Showcase Demonstration layer.

## What Is GuardX

GuardX is intended to be a runtime safety layer that sits between users,
LLMs, AI agents, tools, and external systems. Its purpose is to observe
safety-relevant events and determine whether an operation should be:

- **ALLOW** — proceed normally
- **MODIFY** — proceed with changes (e.g., redaction)
- **BLOCK** — prevent the operation
- **HUMAN_REVIEW** — escalate for human decision

GuardX investigates a context-aware, execution-aware approach to AI safety
rather than simple input/output classification.

## What Currently Exists

- Architectural documentation (`docs/`)
- Claude Code subagent definitions for development workflow (`.claude/agents/`)
- Project scaffolding

See `docs/CURRENT_STATE.md` for the detailed inventory.

## Planned Architecture

The following describes the **target architecture** — none of this is implemented yet.

```
                    ┌─────────────────────────────────┐
                    │           GuardX Core            │
  User/App ───────▶│                                  │───────▶ LLM / Agent
                    │  ┌───────┐ ┌───────┐ ┌───────┐  │
  LLM / Agent ────▶│  │Guards │ │Risk   │ │Arbiter│  │───────▶ User/App
                    │  │       │ │Engine │ │       │  │
  Agent Actions ──▶│  └───┬───┘ └───┬───┘ └───┬───┘  │───────▶ Tool Execution
                    │      │        │        │        │
                    │  ┌───▼────────▼────────▼───┐    │
                    │  │  Risk Memory │ Provenance│    │
                    │  └─────────────────────────┘    │
                    │           Audit Log              │
                    └─────────────────────────────────┘
```

**Planned components:**

- **Specialized Guards** — Pluggable evaluators for security, privacy, content safety, and policy compliance. Not necessarily LLM-based; may use rules, regex, classifiers, or combinations.
- **Evidence Model** — Common structured format for guard findings, distinguishing severity from confidence.
- **Risk Engine** — Orchestrates guard execution, collects evidence, detects disagreements.
- **Arbiter** — Makes final decisions. Primarily deterministic; LLM-aided only for genuinely ambiguous cases.
- **Risk Memory** — Session-scoped safety state for detecting multi-turn risk patterns.
- **Action Provenance** — Data lineage tracking for understanding information flow.
- **Risk Propagation** — Safety labels that follow data through transformations.
- **Audit Log** — Complete record of evaluations and decisions.

See `docs/ARCHITECTURE.md` for the full technical design.

## Project Structure

```
guardrails/
├── AGENTS.md                    # Permanent development rules and project invariants
├── CLAUDE.md                    # Instructions for Claude Code agents
├── README.md                    # This file
├── docs/
│   ├── ARCHITECTURE.md          # Technical architecture
│   ├── CURRENT_STATE.md         # What currently exists
│   ├── DESIGN_DECISIONS.md      # Decision records
│   ├── EVALUATION_PLAN.md       # Evaluation strategy, baselines, and research questions
│   ├── ROADMAP.md               # Implementation phases
│   └── THREAT_MODEL.md          # Threat model and risk taxonomy
├── .agents/
│   └── rules/                   # Workspace agent rules (architecture, security, coding, testing)
└── .claude/
    └── agents/                  # Claude Code subagent definitions
        ├── architect.md
        ├── code-reviewer.md
        ├── security-reviewer.md
        └── test-engineer.md
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | Full technical architecture |
| [Design Decisions](docs/DESIGN_DECISIONS.md) | Decision records with rationale |
| [Roadmap](docs/ROADMAP.md) | Implementation phases and dependencies |
| [Current State](docs/CURRENT_STATE.md) | What is and isn't implemented |
| [Threat Model](docs/THREAT_MODEL.md) | Threat taxonomy and defense mapping |
| [Evaluation Plan](docs/EVALUATION_PLAN.md) | Baselines, metrics, and empirical evaluation |

## Interactive Showcase Demonstration (Phase 9)

GuardX includes a presentable demonstration layer that exercises the **real** GuardX core pipeline (zero hardcoded verdicts or mocked safety outcomes).

### Available Interfaces
1. **Interactive Web Dashboard**: Modern, zero-dependency browser UI with SVG DAG visualizer, live guard status cards, evidence inspector, and a 6-step data-flow walkthrough.
2. **Terminal CLI Runner**: Rich ANSI terminal demonstration with lineage graphs and interactive menus.

### Running the Demo
The demonstration uses only Python standard library components (`http.server`, `urllib`, `dataclasses`, `asyncio`):

```bash
# Launch the Interactive Web UI (Default: http://127.0.0.1:8080)
python3 demo/app.py

# Launch the Interactive ANSI Terminal CLI
python3 demo/app.py --cli

# Run a specific scenario directly
python3 demo/app.py --scenario data_exfiltration_unsafe
```

### Predefined Scenarios
- **Scenario 1 — Benign Request**: Clean query ("What is the capital of Japan?") evaluated concurrently -> `ALLOW`.
- **Scenario 2 — Prompt Injection**: Direct override attack evaluated deterministically by `SecurityGuard` -> `BLOCK`.
- **Scenario 3A — Conversational PII**: Personal identifier (email) flagged for audit tracking without false-positive blocking -> `ALLOW`.
- **Scenario 3B — Policy-Forbidden Tool**: Shell execution restricted by organizational policy -> `BLOCK`.
- **Scenario 4 — Primary Showcase (Data Exfiltration)**: Agent accesses `customers.csv` [PII, CONFIDENTIAL], derives a summary, and attempts `send_email` to an external domain. Semantic properties propagate through the `ActionProvenanceDAG`, `ActionAuthorizationEngine` identifies unauthorized egress, and `Arbiter` blocks the action -> `BLOCK`.
- **Scenario 5 — Safe Contrasting Data Flow**: Same action (`send_email`) accessing public data sent to an internal recipient -> `ALLOW`.

### Real vs. Simulated Components
- **Simulated**: The mock database export (`customers.csv`), tool execution (`send_email`, `read_file`), and network endpoints (no real emails sent or networks touched).
- **Real**: `SafetyEvent`, `EvaluationContext`, `SecurityGuard`, `PrivacyGuard`, `PolicyGuard`, `RiskEngine`, `ActionProvenanceDAG`, `PropertyPropagationEngine`, `ActionAuthorizationEngine`, and `Arbiter`.

## License

[OPEN QUESTION] License has not been selected.
