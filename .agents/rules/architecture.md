---
trigger: model_decision
description: "Apply when designing, reviewing, or changing GuardX architecture, component boundaries, evidence, risk memory, provenance, propagation, investigation, or arbitration."
---

# GuardX Architecture Rules

Before making a significant architectural change, read:

- `AGENTS.md`
- `docs/ARCHITECTURE.md`
- `docs/DESIGN_DECISIONS.md`
- `docs/CURRENT_STATE.md`
- `docs/THREAT_MODEL.md`
- `docs/EVALUATION_PLAN.md`

## Preserve Accepted Decisions

Do not silently contradict a decision marked ACCEPTED in
`docs/DESIGN_DECISIONS.md`.

If an accepted decision appears incorrect:

1. identify the conflict,
2. explain why it matters,
3. propose a replacement,
4. describe trade-offs,
5. do not implement the architectural change until it is accepted.

## Architecture Priorities

Optimize for:

1. correctness,
2. safety,
3. explainability,
4. auditability,
5. testability,
6. modularity,
7. provider independence,
8. bounded latency and cost,
9. simplicity.

Do not add architectural complexity merely because it appears sophisticated.

## Core Boundaries

Maintain clear separation between:

- Safety Events
- Evaluation Context
- Guards
- Evidence
- Risk Engine
- Risk Memory
- Provenance
- Risk Propagation
- Disagreement Detection
- Investigation
- Arbiter
- Action Authorization
- Audit

Avoid components taking responsibilities owned by another layer.

## Guards

Guards detect specialized risks and produce Evidence.

They do not own the final GuardX decision.

A Guard is not necessarily an LLM agent.

Prefer deterministic implementations where sufficient.

## Evidence

Evidence must remain structured and auditable.

Severity and confidence are separate.

Do not silently mutate existing Evidence.

Investigation or re-evaluation creates new linked Evidence.

## Risk Memory

Risk Memory stores safety-relevant state, not complete conversation history.

Apply data minimization.

Avoid permanent or unbounded accumulation.

## Provenance

Provenance should represent safety-relevant data/action lineage.

The current proposal is a lightweight in-memory DAG.

Do not introduce a graph database unless demonstrated requirements justify it.

The representation must support branching and merging.

## Risk Propagation

Prefer semantic safety properties over arbitrary global numeric risk scores.

Do not invent mathematical risk formulas without experimental justification.

## Investigation

Investigation must be conditional and bounded.

Do not create recursive debate loops.

## Arbiter

The Arbiter owns the final:

- ALLOW
- MODIFY
- BLOCK
- HUMAN_REVIEW

decision.

Explicit deterministic policy/safety constraints cannot be overridden by
model reasoning.

Severity alone must not determine the verdict.

## Technology

Python is the accepted primary implementation language.

Do not introduce frameworks, databases, graph systems, LLM frameworks, or
infrastructure until a requirement justifies them.

## Architecture Changes

When architecture changes:

1. update `docs/ARCHITECTURE.md`,
2. record the decision in `docs/DESIGN_DECISIONS.md`,
3. update `docs/CURRENT_STATE.md` if implementation state changed,
4. update `docs/ROADMAP.md` if implementation order changed.