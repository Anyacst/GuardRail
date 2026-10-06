# GuardX — Design Decisions

This document records significant architectural decisions for GuardX.

Statuses:

- ACCEPTED
- PROPOSED
- REJECTED
- SUPERSEDED

A PROPOSED decision must not be treated as final architecture.

---

## DD-001 — Primary Implementation Language

**Status:** ACCEPTED

### Decision

GuardX will use Python as its primary implementation language.

### Rationale

GuardX requires:

- AI/model integration
- asynchronous provider calls
- policy evaluation
- data processing
- security analysis
- evaluation tooling
- rapid research iteration

Python provides a mature ecosystem for these requirements.

### Alternatives Considered

- TypeScript
- Go
- Rust

### Trade-offs

Python provides rapid development and a strong AI ecosystem but lower raw runtime performance than compiled languages.

### Revisit When

A demonstrated performance, deployment, or security requirement cannot be adequately satisfied with Python.

---

## DD-002 — Deterministic-First Safety

**Status:** ACCEPTED

### Decision

GuardX prefers deterministic mechanisms when they are sufficient.

LLM reasoning is used only when contextual judgment cannot reasonably be handled deterministically.

### Rationale

Deterministic mechanisms provide:

- predictable behavior
- lower latency
- lower cost
- easier testing
- easier auditing

### Alternatives Considered

LLM-first safety evaluation.

### Rejected Because

Using an LLM for every safety decision increases latency, cost, nondeterminism, and dependency on external providers.

---

## DD-003 — Guards Produce Evidence, Not Final Decisions

**Status:** ACCEPTED

### Decision

Specialized Guards produce structured Evidence.

The Arbiter owns the final GuardX authorization decision.

### Rationale

Separating detection from decision:

- prevents majority-voting behavior,
- preserves specialized findings,
- improves auditability,
- allows decision policy to evolve independently.

### Consequence

A Guard may recommend an action but cannot independently authorize execution.

---

## DD-004 — Common Evidence Model

**Status:** ACCEPTED

### Decision

All Guards communicate findings through a common Evidence abstraction.

Evidence must distinguish at minimum:

- risk category
- severity
- confidence
- explanation/support
- affected entities/resources
- provenance references where relevant

### Rationale

A common representation allows the Risk Engine and Arbiter to process heterogeneous Guard implementations consistently.

### Important Constraint

Severity and confidence are separate concepts.

No arbitrary numeric aggregation formula is accepted at this stage.

---

## DD-005 — Evidence Immutability

**Status:** ACCEPTED

### Decision

Evidence records are immutable after emission.

Investigation/re-evaluation creates new Evidence linked to earlier Evidence rather than modifying previous findings.

### Rationale

This preserves auditability and allows GuardX to reconstruct how a decision evolved.

---

## DD-006 — Risk Memory Is Safety State, Not Conversation Memory

**Status:** ACCEPTED

### Decision

Risk Memory stores only safety-relevant state required for future evaluations.

It does not automatically store complete conversation history.

### Potential Contents

- previous significant findings
- sensitive resources accessed
- unresolved findings
- relevant previous verdicts
- suspicious multi-event patterns

### Constraints

- data minimization
- bounded retention
- session scope by default
- explicit expiry

---

## DD-007 — Action Provenance Uses a DAG Data Model

**Status:** PROPOSED

### Decision

Represent safety-relevant execution/data lineage as a directed acyclic graph (DAG).

The initial prototype should use a simple in-memory Python representation.

A graph database is NOT required.

### Rationale

Agent execution may branch and merge.

Example:

customers.csv
      |
customer_data
   /       \
names    balances
   \       /
    summary
       |
   send_email

A single-parent linked list cannot naturally represent multi-source derivation.

### Alternatives Considered

1. Linked lineage chain
2. Full graph database
3. Relational event table

### Trade-offs

A DAG adds modest complexity compared with a linked list but accurately represents branching and merging without requiring graph infrastructure.

### Revisit When

Prototype requirements demonstrate that simpler lineage is sufficient or persistence/query scale requires another backend.

---

## DD-008 — Risk Propagation Uses Safety Properties

**Status:** PROPOSED

### Decision

Risk propagation should primarily operate on semantic safety properties/labels rather than a single numeric risk score.

Possible properties include:

- PII
- CREDENTIAL
- FINANCIAL_DATA
- CONFIDENTIAL
- UNTRUSTED_SOURCE
- EXTERNAL_DESTINATION
- MALICIOUS_CONTENT

### Rationale

Different risks behave differently under transformations.

A single numeric score loses this semantic information.

### Example

PII data
   |
aggregate
   v
aggregated statistics

The PII property may be reduced or removed if the transformation is verified.

CONFIDENTIAL may remain.

### Constraint

Risk reduction must not be assumed automatically.

Only known/verified transformations may declare reduction/removal of properties.

---

## DD-009 — No Majority Voting

**Status:** ACCEPTED

### Decision

GuardX does not determine safety by counting how many Guards consider an event safe or unsafe.

### Rationale

One specialized Guard may identify a critical risk invisible to other Guards.

Example:

Security: LOW
Privacy: CRITICAL
Content: LOW
Policy: LOW

The Privacy finding must not be overridden by three unrelated low-risk findings.

---

## DD-010 — Bounded Investigation

**Status:** ACCEPTED

### Decision

Investigation must have explicit bounds.

The initial architecture supports:

- explicit trigger conditions
- maximum iterations
- provider timeout
- cost limits
- termination conditions

Investigation cannot recursively trigger unlimited further investigation.

### Rationale

GuardX operates in the runtime path and must maintain bounded latency and cost.

---

## DD-011 — Arbiter Is Deterministic First

**Status:** ACCEPTED

### Decision

Explicit deterministic policy/safety constraints take precedence.

Model-assisted arbitration may be considered only for cases unresolved by deterministic logic.

### Constraint

An LLM must never override an explicit deterministic BLOCK rule.

---

## DD-012 — Severity Does Not Directly Determine Verdict

**Status:** PROPOSED

### Decision

Severity alone must not directly map to BLOCK / ALLOW.

The Arbiter should consider:

- risk category
- severity
- confidence
- operation impact
- policy
- provenance
- available mitigation
- investigation results

### Example

HIGH privacy risk may be safely resolved through redaction:

HIGH PRIVACY
      |
redaction available
      v
MODIFY

while:

HIGH destructive-action risk
      |
human approval required
      v
HUMAN_REVIEW

### Consequence

Any initial severity-to-verdict table is an experimental baseline rather than validated policy.

---

## DD-013 — Multiple Interception Points

**Status:** ACCEPTED

GuardX evaluates safety at:

- INPUT
- OUTPUT
- ACTION
- TOOL_RESULT

Action authorization is distinct from content moderation.

---

## DD-014 — Provider Independence

**Status:** ACCEPTED

GuardX must not depend on a specific LLM/model provider.

Provider-specific functionality must be behind interfaces/adapters.

---

## DD-015 — Technology Selection Is Deferred

**Status:** ACCEPTED

### Decision

Do not select infrastructure until required capabilities are defined.

The following are NOT currently accepted dependencies:

- FastAPI
- Pydantic
- NetworkX
- Neo4j
- PostgreSQL
- Redis
- LangGraph
- Kafka

Python itself is accepted.

Libraries/frameworks will be selected during implementation planning based on demonstrated requirements.

---

# Unresolved Decisions

The following remain open:

1. Exact Evidence schema.
2. Exact Risk Memory expiry policy.
3. Content Safety / Policy Guard boundary.
4. MODIFY execution semantics.
5. Action-impact classification.
6. Investigation trigger calibration.
7. Arbiter baseline rules.
8. Audit persistence.
9. Whether model-assisted arbitration improves results.
10. Whether provenance DAG complexity is justified experimentally.

These must not be silently treated as resolved.