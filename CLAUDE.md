# GuardX — Agent Instructions

## What Is GuardX

GuardX is a runtime safety framework for LLM applications and agentic AI systems.

It sits between users, LLMs, agents, tools, resources, and external systems to evaluate safety-relevant operations and determine whether they should be:

- ALLOW
- MODIFY
- BLOCK
- HUMAN_REVIEW

GuardX is intended to protect not only prompts and model responses, but also agent actions, tool calls, data access, data transformations, and external data flows.

**Current status: Phase 0 — Architecture and specification only. No production GuardX code exists.**

GuardX must NOT be reduced to:

    Prompt
      ↓
    Multiple LLM classifiers
      ↓
    Majority vote
      ↓
    Allow / Block

The project instead investigates context-aware and execution-aware safety mechanisms including Risk Memory, Action Provenance, Risk Propagation, disagreement detection, targeted investigation, and evidence-based arbitration.

---

# Core Architectural Principles

## 1. Deterministic First

Prefer deterministic mechanisms when they can reliably perform the task.

Examples may include:

- explicit policy rules
- permission checks
- schema validation
- pattern matching
- deterministic security rules
- provenance checks
- known safety constraints

LLM reasoning should be used only when deterministic mechanisms are insufficient for the required contextual judgment.

Every LLM dependency must be replaceable behind an interface.

---

## 2. Evidence-Based Decisions

Guards produce structured Evidence.

They do not merely output:

    SAFE
    UNSAFE

Evidence should explain:

- what risk was detected,
- what caused the finding,
- how severe the potential consequence is,
- how confident the detector is,
- what entities/resources/actions are affected,
- and what supporting context exists.

Final decisions must be traceable to evidence.

---

## 3. Separation of Detection and Decision

Guards are specialized risk detectors/investigators.

They do NOT independently own the final GuardX authorization decision.

Conceptually:

    Event
      ↓
    Guards
      ↓
    Evidence
      ↓
    Risk Engine
      ↓
    Arbiter
      ↓
    ALLOW / MODIFY / BLOCK / HUMAN_REVIEW

A Guard may recommend an action, but the final authorization belongs to the Arbiter subject to explicit deterministic safety and policy overrides.

---

## 4. Explicit Trust Boundaries

Nothing entering GuardX should automatically be considered trusted.

Potentially untrusted inputs include:

- user input
- LLM output
- agent plans
- tool-call arguments
- tool results
- retrieved documents
- external API responses
- files
- generated data
- guard/model output

Guard output itself is not assumed to be infallible.

Trust must be explicit rather than implicit.

---

## 5. Fail-Safe Behavior

GuardX must define explicit behavior for:

- guard failure,
- provider failure,
- timeout,
- malformed evidence,
- missing context,
- conflicting evidence,
- unavailable policy information,
- and investigation failure.

High-impact operations must never silently fail open.

Depending on operation impact and available evidence, failure may result in:

- BLOCK
- HUMAN_REVIEW
- or another explicitly defined safe fallback.

Low-impact failure behavior must be defined separately rather than assuming every failure requires blocking.

---

## 6. Modularity

Major GuardX components must communicate through clean interfaces.

Implementations should be independently replaceable where practical.

Do not tightly couple:

- guards to specific models,
- guards to specific providers,
- policy evaluation to an LLM,
- provenance representation to a particular database,
- Risk Memory to a particular storage system,
- or arbitration to one model provider.

Architecture defines capabilities first.

Technology choices come later.

---

## 7. Provider Independence

GuardX must not require a specific LLM provider, model vendor, safety API, or hosted service.

Provider-specific functionality must be isolated behind adapters/interfaces.

---

## 8. Bounded Cost and Latency

GuardX runs in the execution path of AI systems.

Therefore:

- guard execution should support concurrency where appropriate,
- expensive analysis should be conditional,
- investigation loops must be bounded,
- LLM calls must have explicit justification,
- provider calls require timeouts,
- and failure behavior must be defined.

Do not perform expensive investigation on every event.

---

## 9. Data Minimization

GuardX itself must not unnecessarily create a privacy risk.

Risk Memory, audit logs, Evidence, and provenance records should contain only the information necessary for safety analysis and auditability.

Do not retain raw sensitive content merely because GuardX inspected it.

Prefer:

- references,
- classifications,
- hashes where appropriate,
- metadata,
- derived safety properties,
- and minimal evidence excerpts

over unnecessary duplication of sensitive information.

Retention policies remain an architectural decision and must be explicitly defined.

---

## 10. Auditability

Important GuardX decisions must be explainable after execution.

The system should be able to answer:

- What event was evaluated?
- Which guards executed?
- What evidence was produced?
- What policy applied?
- What relevant risk state existed?
- Was investigation triggered?
- Why was the final decision made?
- Was an action modified?
- Was human review requested?

Do not silently overwrite historical evidence.

---

# Core Terminology

| Term | Definition |
|---|---|
| **Event** | A safety-relevant occurrence evaluated by GuardX, such as user input, model output, tool call, tool result, data transformation, or external action. |
| **Guard** | A specialized component that evaluates an Event for a particular risk dimension and produces structured Evidence. A Guard is not necessarily LLM-based. |
| **Evidence** | A structured finding produced by a Guard describing a detected or investigated safety concern. Once emitted, an Evidence record is immutable. Re-evaluation creates new Evidence linked to the previous finding rather than modifying it. |
| **Security Guard** | Evaluates attacks or manipulation against the AI/application, such as prompt injection, instruction manipulation, or unsafe tool exploitation. |
| **Privacy Guard** | Evaluates sensitive-data exposure, access, transformation, and transfer risks. |
| **Content Safety Guard** | Evaluates safety risks associated with requested or generated content. |
| **Policy Guard** | Evaluates application-specific or organization-specific rules, permissions, restrictions, and required approvals. |
| **Risk Engine** | Coordinates guard evaluation, collects Evidence, evaluates relevant risk context, detects meaningful disagreement/uncertainty, and determines whether additional investigation is required. |
| **Arbiter** | Produces the final ALLOW / MODIFY / BLOCK / HUMAN_REVIEW decision using Evidence, explicit policy constraints, relevant Risk Memory, provenance-derived context, and investigation results. Deterministic constraints take precedence where explicitly defined. |
| **Risk Memory** | Session-scoped safety state containing information relevant to future safety decisions. It is not a copy of conversation history. |
| **Action Provenance** | Representation of where safety-relevant information originated, how it was transformed, which actions consumed it, and where it was transferred. |
| **Risk Propagation** | Mechanism by which safety-relevant properties may be preserved, increased, reduced, removed, or transformed as data moves through an execution/data-flow chain. |
| **Investigation** | Bounded additional analysis triggered by uncertainty, conflicting evidence, missing information, or high-impact operations. |
| **Action Authorization** | Pre-execution evaluation of a proposed agent/tool action using its arguments, permissions, policy constraints, data provenance, destination, and relevant risk state. |

---
## Technology

- **Primary language:** Python
- GuardX core components must be implemented in Python.
- The architecture remains framework-independent.
- Do not introduce another implementation language without an accepted design decision.
- No API framework, database, graph library, LLM framework, or persistence technology is currently mandated.

# Guard Responsibilities

GuardX currently proposes four specialized guard domains:

1. Security
2. Privacy
3. Content Safety
4. Policy

These boundaries are architectural proposals until finalized in `docs/DESIGN_DECISIONS.md`.

Guards should:

- inspect relevant Events,
- detect specialized risks,
- produce structured Evidence,
- expose uncertainty,
- identify affected resources/entities where appropriate,
- and request further investigation when justified.

Guards should NOT:

- independently control the complete GuardX decision,
- silently modify another Guard's Evidence,
- assume their own output is correct,
- require an LLM unless necessary,
- or rely on majority voting.

---

# Evidence Rules

Severity and confidence are different concepts.

**Severity**

    How serious would the consequence be if the finding is correct?

**Confidence**

    How certain is the detector that the finding is correct?

Example:

    severity   = CRITICAL
    confidence = LOW

is valid.

It means:

    "This would be extremely serious if true,
     but the current evidence is uncertain."

Do not combine severity and confidence into arbitrary mathematical scores unless the scoring method has been explicitly designed, justified, and documented.

Do not invent risk weights for the appearance of mathematical sophistication.

---

# Risk Memory

Risk Memory exists to preserve safety-relevant state across related events.

Potential examples include:

- previous risk findings,
- sensitive resources accessed,
- unresolved safety concerns,
- previous policy violations,
- suspicious intent progression,
- relevant authorization state.

Risk Memory must NOT automatically store complete conversations.

Risk Memory design must address:

- data minimization,
- entry creation,
- expiration,
- invalidation,
- false-risk accumulation,
- session boundaries,
- sensitive-data handling,
- and auditability.

The exact representation remains subject to architecture review.

---

# Action Provenance

GuardX investigates execution/data lineage so safety decisions can consider sequences of actions rather than isolated operations.

Conceptually:

    User Request
        ↓
    read_file()
        ↓
    customers.csv
        ↓
    customer_data
        ↓
    summarize()
        ↓
    customer_summary
        ↓
    send_email()
        ↓
    external destination

The provenance system should help answer:

- Where did information originate?
- What transformed it?
- Which actions consumed it?
- Which resources were accessed?
- Where did the resulting information go?
- Did information cross a trust boundary?

Do NOT assume a specific graph database or graph library.

The required data model and operations must be defined before selecting storage technology.

---

# Risk Propagation

Risk must not be treated as a single number that is blindly copied through the system.

Safety properties may behave differently across transformations.

A transformation may:

- preserve a risk,
- increase a risk,
- reduce a risk,
- remove a particular risk property,
- or introduce a new risk.

Example:

    sensitive customer data
              ↓
          summarization
              ↓
    may remain sensitive

while:

    sensitive customer data
              ↓
    verified anonymization
              ↓
    some privacy properties may be reduced

Do not invent propagation formulas before the semantics are defined.

Calibration and quantitative scoring should be treated as experimental work unless explicitly accepted otherwise.

---

# Disagreement and Investigation

GuardX must not use simple majority voting as its safety mechanism.

Example:

    Security: LOW
    Privacy: HIGH
    Content: LOW
    Policy: MEDIUM

The Privacy finding must not be discarded because other guards report lower risk.

Meaningful disagreement may depend on:

- risk category,
- severity,
- confidence,
- evidence quality,
- guard specialization,
- policy constraints,
- and operation impact.

When evidence is uncertain, contradictory, incomplete, or high-impact, GuardX may trigger targeted investigation.

Investigation must be bounded.

It requires:

- explicit trigger conditions,
- maximum iterations,
- termination conditions,
- cost limits,
- latency limits,
- and failure behavior.

Do not create autonomous unbounded debate loops between agents.

---

# Arbiter Principles

The Arbiter owns the final GuardX authorization decision.

Possible outcomes:

### ALLOW

The operation may proceed.

### MODIFY

The operation may proceed only after an explicitly defined safety-preserving modification.

Examples may include:

- redaction,
- removal of sensitive fields,
- narrowing tool arguments,
- sanitization.

The modified operation should be re-evaluated when necessary.

### BLOCK

The operation must not proceed.

### HUMAN_REVIEW

Execution is suspended pending explicit human authorization/review.

The Arbiter should be deterministic where explicit rules or policy constraints are sufficient.

Model reasoning may assist ambiguous cases but must not silently override explicit deterministic constraints.

---

# GuardX Interception Points

The architecture must support evaluation at multiple points.

## Input

    User/Application
        ↓
      GuardX
        ↓
      LLM/Agent

## Output

    LLM/Agent
        ↓
      GuardX
        ↓
      User/Application

## Tool/Action

    Agent proposes action
        ↓
      GuardX
        ↓
    authorize?
     /      \
   yes       no
    ↓         ↓
 execute    BLOCK /
           MODIFY /
           HUMAN_REVIEW

## Tool Result

    Tool
      ↓
    result
      ↓
    GuardX
      ↓
    provenance/risk update
      ↓
    Agent

The architecture must distinguish content evaluation from action authorization.

---

# Engineering Constraints

- **Language:** Python `[ASSUMPTION — to be confirmed]`
- Core evaluation paths should support asynchronous execution.
- External provider/model calls require explicit timeout handling.
- Investigation must have bounded iteration.
- Evidence records are immutable after emission.
- Re-evaluation produces new linked Evidence.
- Important decisions require structured audit records.
- External model/API calls must be mockable for deterministic testing.
- Safety-critical behavior must not depend solely on an LLM response.
- No production infrastructure technology is selected during Phase 0 unless explicitly documented as an accepted design decision.

---

# Technology Selection Rules

Do not introduce a technology simply because it appears suitable.

Do not automatically introduce:

- FastAPI
- Pydantic
- NetworkX
- Neo4j
- PostgreSQL
- Redis
- LangGraph
- Kafka
- Kubernetes
- vector databases

without a demonstrated requirement.

First define:

1. required capability,
2. interface,
3. expected scale,
4. consistency requirements,
5. latency requirements,
6. persistence requirements.

Then evaluate implementation technologies.

---

# Source-of-Truth Documents

| Document | Purpose |
|---|---|
| `docs/ARCHITECTURE.md` | Primary technical architecture and system boundaries |
| `docs/DESIGN_DECISIONS.md` | Accepted/proposed architectural decisions and rationale |
| `docs/ROADMAP.md` | Implementation phases, dependencies, tests, and exit criteria |
| `docs/CURRENT_STATE.md` | Verified description of what currently exists |

If documents conflict:

1. Do not silently choose one.
2. Report the conflict.
3. Determine whether an accepted design decision resolves it.
4. If not, mark it as an OPEN QUESTION.

---

# Rules for Coding Agents

## 1. Read Before Changing

Before any major implementation or architecture change:

1. Read `CLAUDE.md`.
2. Read the relevant section of `docs/ARCHITECTURE.md`.
3. Read relevant accepted decisions in `docs/DESIGN_DECISIONS.md`.
4. Inspect the existing implementation.
5. Inspect relevant tests.

Do not design from assumptions when repository evidence is available.

---

## 2. Preserve Accepted Decisions

Never silently contradict a design decision marked `ACCEPTED`.

If implementation evidence shows an accepted decision is problematic:

1. document the conflict,
2. propose a revision,
3. explain consequences,
4. wait for approval when the change is architectural.

---

## 3. Maintain Current State

After completing implementation work, update:

    docs/CURRENT_STATE.md

Record only verified repository state.

Do not describe planned functionality as implemented.

---

## 4. Epistemic Honesty

Use these labels when relevant:

**[FACT]**

Verified from repository state, project requirements, tests, or an authoritative source actually inspected.

**[DESIGN DECISION]**

An intentional GuardX architectural choice.

**[PROPOSAL]**

A possible design that has not been accepted.

**[ASSUMPTION]**

Something temporarily assumed because required information is missing.

**[OPEN QUESTION]**

Something requiring investigation or explicit decision.

If information cannot be verified, say:

    Unverified

or:

    Requires research

Do not guess.

---

## 5. No Fabricated Evidence

Do not fabricate:

- benchmark results,
- accuracy numbers,
- latency numbers,
- attack success rates,
- dataset results,
- research citations,
- library/API capabilities,
- existing functionality,
- security guarantees.

Do not claim:

    "GuardX prevents X"

unless the implementation and evaluation support that claim.

Prefer:

    "GuardX is designed to..."
    "GuardX proposes..."
    "GuardX investigates..."

---

## 6. No Unsupported Novelty Claims

Do not claim:

    "GuardX is the first..."
    "GuardX uniquely..."
    "No existing system..."

without an appropriate literature review.

Project contribution and scientific novelty are different concepts.

Scientific novelty remains:

    UNVERIFIED

until appropriate research is completed.

---

## 7. Testing Requirements

Every implemented component requires tests.

Prefer:

- deterministic tests,
- explicit edge cases,
- failure-path tests,
- malformed-input tests,
- timeout/provider-failure tests,
- policy-conflict tests,
- risk-state tests,
- provenance tests.

Mock external LLM/API calls where appropriate.

Do not modify production behavior merely to make tests pass.

---

## 8. Security Review

Security-critical components should be reviewed adversarially.

Particular attention should be given to:

- prompt injection,
- indirect prompt injection,
- policy bypass,
- unsafe tool execution,
- sensitive-data leakage,
- privilege escalation,
- provenance manipulation,
- guard bypass,
- fail-open behavior,
- malicious tool results,
- malformed model output.

---

## 9. Keep the Architecture Simple

Do not add complexity without a demonstrated requirement.

Prefer the smallest architecture capable of testing the project's research questions.

Prototype first.

Measure.

Then increase complexity when evidence justifies it.

---

# Phase Rules

## Phase 0 — Architecture and Specification

Current phase.

Allowed:

- architecture documents,
- design decisions,
- terminology,
- interfaces at the conceptual level,
- threat analysis,
- research questions,
- roadmap design.

Not allowed unless explicitly approved:

- production GuardX modules,
- API servers,
- databases,
- framework installation,
- provider integrations,
- implementation-specific infrastructure.

Phase 0 ends only after architecture and major design decisions receive human review.

---

# Current Research Direction

GuardX currently investigates whether combining:

- specialized risk analysis,
- safety-relevant Risk Memory,
- action/data provenance,
- risk propagation,
- disagreement-aware investigation,
- and evidence-based arbitration

can improve runtime safety reasoning for agentic AI systems compared with simpler single-pass guardrail approaches.

This is a research direction, NOT a validated result and NOT a novelty claim.

Evaluation methodology and baselines must be defined before making performance claims.