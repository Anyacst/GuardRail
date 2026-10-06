# GuardX — Technical Architecture

> **Status:** Phase 0 — Architecture and Specification
>
> This document describes the target GuardX architecture.
> No production GuardX implementation currently exists.
>
> Python is the accepted primary implementation language.
> Frameworks, databases, graph libraries, and model providers remain
> implementation choices unless explicitly accepted in DESIGN_DECISIONS.md.

---

# 1. Purpose

GuardX is a runtime safety framework for LLM applications and autonomous/
agentic AI systems.

GuardX evaluates safety-relevant events occurring between:

- users/applications,
- LLMs,
- agents,
- tools,
- resources,
- and external systems.

GuardX determines whether an operation should result in:

- ALLOW
- MODIFY
- BLOCK
- HUMAN_REVIEW

GuardX is designed to evaluate not only isolated prompts but also execution
context, data lineage, prior safety-relevant state, and agent actions.

---

# 2. Goals

[DESIGN DECISION]

GuardX should:

1. Evaluate multiple safety dimensions through specialized Guards.
2. Produce structured, auditable Evidence.
3. Preserve safety-relevant context across related events.
4. Track the origin and movement of safety-relevant data.
5. Evaluate agent/tool actions before execution.
6. Detect meaningful uncertainty and disagreement.
7. Perform bounded additional investigation when necessary.
8. Prefer deterministic safety mechanisms where sufficient.
9. Support model-assisted reasoning without depending on a specific provider.
10. Produce explainable final decisions.

---

# 3. Non-Goals

The initial GuardX prototype will NOT:

- train a foundation model,
- implement a distributed microservice architecture,
- require Kubernetes,
- require a graph database,
- permanently store complete conversations,
- run dozens of autonomous safety agents,
- autonomously modify safety policies,
- claim zero false positives or false negatives,
- replace provider-level safety systems,
- claim scientific novelty without literature review,
- or provide production-grade infrastructure.

GuardX should initially be the smallest implementation capable of testing
its architectural and research hypotheses.

---

# 4. Implementation Language

[DESIGN DECISION]

GuardX will be implemented primarily in **Python**.

Python is selected because the project requires:

- AI/model integration,
- asynchronous execution,
- policy evaluation,
- data processing,
- experimentation,
- testing,
- and security/ML tooling.

The architecture remains framework-independent.

The following are NOT currently architecture requirements:

- FastAPI
- Pydantic
- NetworkX
- Neo4j
- PostgreSQL
- Redis
- LangGraph
- Kafka

Libraries will be selected only after implementation requirements are clear.

---

# 5. System Boundary

GuardX acts as an intermediary safety layer.

Conceptually:

    User / Application
            |
            v
        +--------+
        | GuardX |
        +--------+
            |
            v
       LLM / Agent
            |
            v
          Tools
            |
            v
    Resources / External Systems

GuardX controls:

- its evaluation pipeline,
- Guards,
- Evidence,
- Risk Engine,
- Risk Memory,
- provenance state,
- arbitration,
- audit information.

GuardX does NOT control:

- LLM internals,
- user behavior,
- tool implementations,
- external systems,
- network reliability,
- or the host application's enforcement behavior.

[ASSUMPTION]

The host application cooperates with GuardX and enforces GuardX decisions.

A malicious host application can bypass GuardX.

---

# 6. Trust Model

The following are treated as untrusted:

- user input,
- LLM output,
- retrieved documents,
- tool results,
- external API responses,
- agent-generated arguments.

Guard output is considered partially trusted.

A Guard may:

- contain bugs,
- produce false positives,
- produce false negatives,
- fail,
- time out,
- or be manipulated.

GuardX configuration and explicitly configured policies are assumed trusted
when supplied by an authorized operator.

The GuardX runtime itself is assumed uncompromised.

---

# 7. Safety Event Model

GuardX evaluates **Events**.

An Event represents something safety-relevant occurring in the host
application.

Initial event types:

    INPUT
    OUTPUT
    ACTION
    TOOL_RESULT

Future event types may be introduced without changing the fundamental
evaluation pipeline.

Conceptually:

    SafetyEvent:
        event_id
        session_id
        event_type
        payload
        metadata
        provenance_refs
        timestamp

The exact implementation schema will be finalized in Phase 1.

---

# 8. High-Level Architecture

                         Safety Event
                              |
                              v
                     +------------------+
                     | Evaluation       |
                     | Context Builder  |
                     +--------+---------+
                              |
                 +------------+-------------+
                 |                          |
                 v                          v
            Risk Memory              Provenance DAG
                 |                          |
                 +------------+-------------+
                              |
                              v
                     +------------------+
                     |   Risk Engine    |
                     +--------+---------+
                              |
               +--------------+--------------+
               |              |              |
               v              v              v
           Security        Privacy        Content
             Guard           Guard          Guard
               \              |              /
                \             |             /
                 +------------+------------+
                              |
                              v
                         Policy Guard
                              |
                              v
                       Evidence Set
                              |
                              v
                  Disagreement / Uncertainty
                           Detection
                              |
                         investigation?
                         /            \
                       yes             no
                        |               |
                        v               |
                 Bounded Investigation  |
                        |               |
                        +-------+-------+
                                |
                                v
                            Arbiter
                                |
               +----------------+----------------+
               |                |                |
               v                v                v
             ALLOW            MODIFY           BLOCK
                                                 |
                                           HUMAN_REVIEW

Supporting state:

    Risk Memory
    Provenance DAG
    Audit Trail

---

# 9. Evaluation Context

Before Guards execute, GuardX constructs an EvaluationContext.

The context may contain:

- current SafetyEvent,
- relevant Risk Memory entries,
- relevant provenance nodes/edges,
- applicable policies,
- action metadata,
- destination information,
- permission information,
- trust-boundary information.

The context must contain only information required for the current evaluation.

Do not automatically provide complete conversation history to every Guard.

---

# 10. Guard Abstraction

[DESIGN DECISION]

A Guard is a specialized safety evaluator.

Conceptual interface:

    Guard:
        name
        version
        risk_category

        async evaluate(context) -> Evidence[]

A Guard may internally use:

- deterministic rules,
- regex/pattern detection,
- policy evaluation,
- classifiers,
- static analysis,
- provenance analysis,
- external safety services,
- LLM reasoning,
- or combinations of these.

A Guard is NOT synonymous with an LLM agent.

---

# 11. Initial Guard Domains

[PROPOSAL]

GuardX initially investigates four Guard domains.

## Security Guard

Responsible for risks such as:

- prompt injection,
- indirect prompt injection,
- instruction manipulation,
- malicious tool usage,
- suspicious command execution,
- system manipulation.

## Privacy Guard

Responsible for:

- PII,
- credentials,
- secrets,
- sensitive resources,
- unauthorized data exposure,
- data exfiltration.

## Content Safety Guard

Responsible for application-relevant harmful-content risks.

Its exact scope requires evaluation because content-safety requirements
depend on deployment context.

## Policy Guard

Responsible for application/organization-specific constraints:

- permissions,
- forbidden operations,
- required approvals,
- data-transfer restrictions,
- tool restrictions.

[OPEN QUESTION]

The exact boundary between Content Safety and Policy must be validated.

---

# 12. Evidence Model

Evidence is the common language between Guards and the rest of GuardX.

Conceptually:

    Evidence:
        evidence_id
        source_guard
        guard_version

        risk_category
        risk_type

        severity
        confidence

        description

        affected_entities
        provenance_refs

        supporting_data

        recommended_action
        recommended_modification

        investigation_requested

        timestamp

        previous_evidence_ref

Exact field names remain a Phase 1 implementation decision.

---

## Severity

Severity describes potential impact:

    CRITICAL
    HIGH
    MEDIUM
    LOW
    NONE

## Confidence

Confidence describes certainty:

    HIGH
    MEDIUM
    LOW

These concepts MUST remain separate.

Example:

    severity = CRITICAL
    confidence = LOW

means:

    "The consequence would be extremely serious if this finding is true,
     but the current evidence is uncertain."

---

# 13. Evidence Immutability

[DESIGN DECISION]

Evidence is immutable after emission.

Investigation never silently changes previous Evidence.

Instead:

    Evidence E1
         |
         v
    Investigation
         |
         v
    Evidence E2
      references E1

This allows GuardX to reconstruct how a decision evolved.

---

# 14. Risk Memory

Risk Memory stores safety-relevant state across related Events.

It is NOT conversation memory.

Potential Risk Memory entries include:

- previous significant findings,
- sensitive resources accessed,
- unresolved uncertainty,
- previous policy violations,
- relevant previous verdicts,
- suspicious multi-event patterns.

Risk Memory should not automatically store:

- complete conversation text,
- unrelated user interactions,
- unnecessary PII,
- complete tool results.

---

## Risk Memory Lifecycle

An entry has:

    creation
       |
       v
    active
       |
       +----> resolved
       |
       +----> expired

Entries should support:

- creation,
- resolution,
- expiry,
- invalidation.

[OPEN QUESTION]

Exact expiry policy remains unresolved.

Candidate strategies:

- turn-based,
- time-based,
- event-based,
- hybrid.

---

# 15. Action Provenance DAG

[PROPOSAL]

GuardX represents safety-relevant data/execution lineage using a **directed
acyclic graph (DAG)**.

The initial implementation should be a small in-memory Python representation.

A graph database is NOT required.

---

## Why a DAG

Agent execution may branch:

                 customer_data
                  /          \
                 /            \
             names           balances
                 \            /
                  \          /
                     summary
                        |
                        v
                    send_email

A single-parent linked list cannot naturally represent this.

---

## Provenance Nodes

Potential node types:

    USER_INPUT
    MODEL_OUTPUT
    TOOL_CALL
    TOOL_RESULT
    RESOURCE
    DATA
    TRANSFORMATION
    EXTERNAL_DESTINATION

Conceptually:

    ProvenanceNode:
        node_id
        node_type
        description
        resource_ref
        safety_properties
        metadata
        timestamp

---

## Provenance Edges

Potential relationships:

    READS
    PRODUCES
    DERIVED_FROM
    TRANSFORMS
    USES
    SENDS_TO
    RETURNS

Conceptually:

    ProvenanceEdge:
        source
        destination
        relationship
        metadata

The exact graph representation remains an implementation detail.

---

# 16. Safety Properties

Risk propagation should primarily operate on semantic safety properties.

Potential properties include:

    PII
    CREDENTIAL
    SECRET
    FINANCIAL_DATA
    CONFIDENTIAL
    UNTRUSTED_SOURCE
    MALICIOUS_CONTENT

Properties are different from final risk severity.

Example:

    customer.csv

    properties:
        PII
        CONFIDENTIAL

---

# 17. Risk Propagation

[PROPOSAL]

Risk/safety properties can propagate through provenance relationships.

Default behavior should be conservative.

## Preserve

Operations such as:

    copy
    formatting
    serialization

normally preserve relevant properties.

## Reduce

Verified transformations may reduce specific properties.

Example:

    PII
     |
     v
    verified aggregation
     |
     v
    aggregated statistics

The PII property may no longer apply.

## Introduce

An operation may introduce a new risk.

Example:

    CONFIDENTIAL data
          +
    external destination
          |
          v
    data-transfer policy risk

## Combine

Combining multiple inputs may create a property not present individually.

No arbitrary numerical propagation formula is accepted during Phase 0.

---

# 18. Risk Engine

The Risk Engine orchestrates evaluation.

Responsibilities:

1. Select applicable Guards.
2. Execute independent Guards concurrently where appropriate.
3. Collect Evidence.
4. Detect meaningful disagreement/uncertainty.
5. Trigger bounded Investigation when required.
6. Assemble decision context for the Arbiter.
7. Coordinate post-decision state updates.

The Risk Engine does NOT itself perform specialized risk detection.

---

# 19. Guard Selection

Not every Guard needs to execute for every Event.

Example:

    INPUT
       Security
       Privacy
       Content
       Policy

    ACTION
       Security
       Privacy
       Policy

    TOOL_RESULT
       Security
       Privacy
       Content when relevant

Guard selection should eventually be configurable.

This reduces unnecessary cost and latency.

---

# 20. Disagreement Detection

GuardX explicitly rejects majority voting.

Meaningful disagreement exists when conflicting findings could materially
change the final decision.

Example:

    Privacy:
        severity = HIGH
        confidence = LOW

    Policy:
        no violation detected

This may require investigation.

However:

    Security: NONE
    Privacy: HIGH

is not automatically disagreement.

The Guards evaluate different dimensions.

---

# 21. Investigation

Investigation is additional analysis performed only when necessary.

Potential triggers:

- high severity + low confidence,
- contradictory Evidence,
- explicit Guard investigation request,
- unresolved provenance,
- significant Risk Memory pattern,
- high-impact action with insufficient evidence.

Potential actions:

- re-run a specialized Guard with additional context,
- inspect provenance,
- evaluate a specific policy,
- obtain a second specialized assessment,
- request human review.

---

## Investigation Bounds

[DESIGN DECISION]

Investigation must be bounded.

Initial prototype:

    maximum investigation rounds = 1

Investigation must also have:

- timeout,
- provider-call limits,
- termination conditions.

Investigation cannot recursively trigger another Investigation.

---

# 22. Arbiter

The Arbiter produces the final GuardX decision.

Inputs may include:

- Evidence,
- policy constraints,
- Risk Memory,
- provenance-derived context,
- investigation results,
- operation impact,
- available mitigations.

Outputs:

    ALLOW
    MODIFY
    BLOCK
    HUMAN_REVIEW

---

## Deterministic Overrides

Explicit deterministic constraints take precedence.

Example:

    policy:
        production_database.delete:
            requires_human_review: true

An LLM cannot override this policy.

---

## Severity Is Not Verdict

GuardX does NOT assume:

    HIGH -> BLOCK
    MEDIUM -> ALLOW

The decision depends on context.

Example:

    HIGH privacy finding
          |
    redaction possible
          |
          v
        MODIFY

versus:

    destructive production action
          |
    approval required
          |
          v
    HUMAN_REVIEW

---

## Model-Assisted Arbitration

[PROPOSAL]

Model reasoning may assist cases that deterministic logic cannot resolve.

Requirements:

- optional,
- bounded,
- structured output,
- provider-independent,
- auditable,
- unable to override deterministic safety constraints.

Whether model-assisted arbitration improves results must be evaluated.

---

# 23. Action Authorization

GuardX distinguishes:

    Content Evaluation

from:

    Action Authorization

Action Authorization occurs before an agent/tool action executes.

Conceptual request:

    ActionRequest:
        action_name
        arguments
        provenance_refs
        destination
        permissions
        context

GuardX evaluates:

- what operation will happen,
- what data is involved,
- where that data came from,
- destination,
- permissions,
- policy,
- relevant previous risk state.

---

# 24. Example: Data Exfiltration Detection

Consider:

    User:
        "Find our highest-value customers
         and email me a summary."

                   |
                   v

        read_file(customers.csv)

                   |
                   v

            customer_data
          properties:
             PII
             CONFIDENTIAL

                   |
                   v

               summarize()

                   |
                   v

               summary
          properties:
             CONFIDENTIAL

                   |
                   v

       send_email(
          destination=external@gmail.com
       )

GuardX sees:

    confidential-derived data
              +
       external destination
              +
          policy rules
              |
              v
       BLOCK / HUMAN_REVIEW

The risk emerges from the execution/data-flow chain, not necessarily from
any isolated prompt or tool call.

---

# 25. MODIFY Semantics

[OPEN QUESTION]

MODIFY requires explicit ownership.

Possible design:

    Guard recommends modification
             |
             v
    Arbiter returns MODIFY + ModificationPlan
             |
             v
    Host applies modification
             |
             v
    GuardX re-evaluates modified operation
             |
             v
    ALLOW / BLOCK / HUMAN_REVIEW

GuardX should not assume a modification is safe without re-evaluation.

Exact ModificationPlan semantics will be resolved before implementing MODIFY.

---

# 26. Audit Trail

Every important evaluation should generate structured audit information.

Potential audit events:

- evaluation started,
- Guard executed,
- Evidence emitted,
- Guard failure,
- disagreement detected,
- Investigation triggered,
- Investigation result,
- Arbiter decision,
- Risk Memory update,
- provenance update,
- timeout/provider failure.

Audit data should be append-oriented.

Sensitive raw data should not automatically be logged.

---

# 27. Failure Handling

GuardX must explicitly handle failures.

## Guard Failure

If one Guard fails:

- record the failure,
- continue when remaining evidence is sufficient,
- account for missing evidence in arbitration.

For high-impact operations where missing evidence prevents a safe decision:

    HUMAN_REVIEW
    or
    BLOCK

depending on configured policy.

## All Guards Fail

Do not ALLOW silently.

Default:

    BLOCK or HUMAN_REVIEW

## Arbiter Failure

Default:

    BLOCK

for safety-critical/action authorization paths.

## Risk Memory Failure

GuardX may continue statelessly only where policy allows.

The Arbiter must know that Risk Memory was unavailable.

## Provenance Failure

For operations whose safety depends on provenance, missing provenance must
not silently be treated as safe.

This may trigger:

    HUMAN_REVIEW
    or
    BLOCK.

## Audit Failure

Audit failure must be surfaced.

Whether it blocks execution depends on configured compliance requirements.

---

# 28. Security Considerations

GuardX itself introduces an attack surface.

Important threats include:

- prompt injection against LLM-based Guards,
- malicious tool results,
- provenance manipulation,
- Risk Memory poisoning,
- policy tampering,
- Guard bypass,
- malformed Evidence,
- fail-open behavior,
- sensitive-data leakage through logs,
- compromised external safety services.

GuardX assumes its own runtime and authorized configuration source are trusted.

---

# 29. Extensibility

Potential extension points:

- new Guard implementations,
- new risk categories,
- new SafetyEvent types,
- new policy evaluators,
- new provenance backends,
- new Risk Memory stores,
- new audit sinks,
- new transformation/property rules,
- new model providers.

Extensions must preserve the core contracts.

---

# 30. Open Questions

## Must Resolve Before / During Early Implementation

1. Final Evidence schema.
2. Exact Event/EvaluationContext schema.
3. Risk Memory expiry policy.
4. MODIFY execution semantics.
5. Action-impact classification.
6. Content Safety / Policy boundary.
7. Exact provenance DAG API.
8. Initial safety-property vocabulary.

## Experimental Questions

9. Which disagreement triggers provide useful signal?
10. Does targeted investigation improve safety enough to justify latency?
11. Does model-assisted arbitration improve deterministic arbitration?
12. How should propagation rules be calibrated?
13. What false-positive / false-negative trade-off is acceptable?
14. Which four-Guard configuration performs best compared with simpler baselines?

## Future Operational Questions

15. Audit persistence mechanism.
16. Cross-session Risk Memory.
17. Third-party Guard isolation.
18. Out-of-process deployment.
19. Persistent provenance backend.

---

# 31. Architectural Invariants

The following must remain true unless explicitly changed through an accepted
design decision:

1. Guards produce Evidence; they do not own the final decision.
2. Severity and confidence remain distinct.
3. Evidence is immutable after emission.
4. Majority voting is not the safety mechanism.
5. Deterministic constraints cannot be overridden by model reasoning.
6. Investigation is bounded.
7. Risk Memory is not complete conversation memory.
8. GuardX evaluates agent actions, not only text.
9. Provenance tracks safety-relevant data flow.
10. No arbitrary numerical risk formula is treated as validated.
11. GuardX remains provider-independent.
12. Planned functionality must not be represented as implemented.