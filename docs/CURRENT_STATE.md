# GuardX — Current State

## Current Phase

**Phase 9 Completed — GuardX Interactive Playground & Showcase Demonstration**

Phase 1 foundational domain models, Phase 2 deterministic Security Guard, Phase 3 Risk Engine Guard orchestration layer, Phase 4 Privacy & Policy Guards, Phase 5 Deterministic Arbiter, Phase 6 Action Provenance DAG, Phase 7 Semantic Safety Property Propagation, Phase 8 Action Authorization, and Phase 9 Interactive Demonstration (GuardX Playground, Agent Trace Playground, Predefined Examples, Presentation vs Developer views, and REST APIs) have been implemented and verified with 197 passing unit and integration tests (170 baseline tests + 27 Phase 9 demonstration and HTTP integration tests).



---

## Completed

### Project Setup & Specification (Phase 0)

- GuardX repository initialized and specification reviewed.
- Architectural documentation and design decisions established.
- Claude Code subagent definitions configured.

### Core Domain Models & Interfaces (Phase 1)

Implemented in `guardx/` with zero third-party dependencies using Python standard library:

1. **Domain Enums (`guardx.domain.enums`):**
   - `InterceptionPoint`: `INPUT`, `OUTPUT`, `ACTION`, `TOOL_RESULT` (DD-013).
   - `RiskCategory`: `SECURITY`, `PRIVACY`, `CONTENT_SAFETY`, `POLICY`.
   - `Severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`.
   - `Confidence`: `HIGH`, `MEDIUM`, `LOW`.
   - `RecommendedAction`: `ALLOW`, `MODIFY`, `BLOCK`, `HUMAN_REVIEW` (Guard recommendations).
   - `Verdict`: `ALLOW`, `MODIFY`, `BLOCK`, `HUMAN_REVIEW` (Arbiter decisions).

2. **Safety Event Model (`guardx.domain.events.SafetyEvent`):**
   - Typed, frozen representation of intercepted events with validation.

3. **Evaluation Context (`guardx.domain.context.EvaluationContext`):**
   - Carries event, policy, risk memory, and provenance context to Guards.

4. **Evidence Model (`guardx.domain.evidence.Evidence`):**
   - Deeply immutable structured safety findings with recursive collection freezing.
   - Preserves strict separation between `severity` and `confidence`.
   - Supports investigation lineage tracking via `previous_evidence_ref`.

5. **Guard Contract (`guardx.guards.base.Guard`):**
   - Abstract base class for specialized risk analysis with `is_applicable()` hook.

### Minimal Security Guard (Phase 2)

Implemented in `guardx/guards/security/`:

1. **Risk Types (`guardx.guards.security.risk_types`):**
   - `SecurityRiskType` enum providing stable, machine-readable risk identifiers (`INSTRUCTION_OVERRIDE`, `SYSTEM_PROMPT_EXTRACTION`, `INDIRECT_PROMPT_INJECTION`, `SUSPICIOUS_EXECUTION_COMMAND`).

2. **Deterministic Security Rules (`guardx.guards.security.rules`):**
   - Modular `SecurityRule` base class for pluggable, testable deterministic rules.
   - `InstructionOverrideRule` (`SEC-RULE-001`): Detects explicit instruction override/jailbreak attempts at `INPUT` and `TOOL_RESULT` with false-positive filtering for benign educational queries.
   - `SystemPromptExtractionRule` (`SEC-RULE-002`): Detects prompt exfiltration attempts at `INPUT` with false-positive protection for prompt engineering inquiries.
   - `IndirectInjectionMarkerRule` (`SEC-RULE-003`): Detects embedded prompt-injection payload markers at `TOOL_RESULT`.
   - `SuspiciousCommandExecutionRule` (`SEC-RULE-004`): Detects destructive or dangerous shell payloads at `ACTION`.

3. **Security Guard Implementation (`guardx.guards.security.guard.SecurityGuard`):**
   - Conforms to the `Guard` ABC.
   - Dispatches only applicable rules based on event `InterceptionPoint`.
   - Emits deeply immutable `Evidence` with `RecommendedAction.BLOCK` (preserving Guard/Arbiter boundaries).

### Risk Engine & Guard Orchestration (Phase 3)

Implemented in `guardx/engine/`:

1. **Execution Outcome Models (`guardx.engine.models`):**
   - `GuardExecutionStatus`: `SUCCESS`, `TIMEOUT`, `ERROR`, `INVALID_OUTPUT`, `SKIPPED`.
   - `GuardExecutionResult`: Explicitly separates execution status/error metadata from risk Evidence.
   - `RiskEngineResult`: Encapsulates aggregated Evidence and detailed per-Guard execution records.

2. **Risk Engine Orchestrator (`guardx.engine.risk_engine.RiskEngine`):**
   - Asynchronous concurrent Guard dispatch via `asyncio.gather`.
   - Per-Guard execution timeouts and cancellation cleanup via `asyncio.wait_for`.
   - Complete exception and failure isolation (a failing/timed-out Guard does not crash evaluation).
   - Strict Guard output validation (non-sequence or invalid items marked `INVALID_OUTPUT`).
   - Pure Python standard library implementation with zero external dependencies.

### Privacy Guard & Policy Guard (Phase 4)

Implemented in `guardx/guards/privacy/` and `guardx/guards/policy/`:

1. **Privacy Guard (`guardx.guards.privacy.PrivacyGuard`):**
   - Stable risk types (`PrivacyRiskType`): `CREDENTIAL_EXPOSURE`, `PERSONAL_IDENTIFIER`, `SENSITIVE_RESOURCE`, `UNAUTHORIZED_DISCLOSURE`.
   - `CredentialExposureRule` (`PRIV-RULE-001`): Detects API keys (OpenAI, GitHub, AWS), Bearer tokens, private keys, database passwords with secret masking and educational false-positive filtering (`RecommendedAction.BLOCK`).
   - `PersonalIdentifierRule` (`PRIV-RULE-002`): Detects email addresses and phone numbers for sensitive property tracking without automatically blocking benign requests (`RecommendedAction.ALLOW`).
   - `SensitiveResourceRule` (`PRIV-RULE-003`): Detects references to credentials and sensitive config files (`/etc/shadow`, `.ssh/id_rsa`, `.aws/credentials`, `.env`, `.env.production`, etc.) (`RecommendedAction.BLOCK`).

2. **Policy Guard (`guardx.guards.policy.PolicyGuard`):**
   - Stable risk types (`PolicyRiskType`): `FORBIDDEN_ACTION`, `FORBIDDEN_DESTINATION`, `HUMAN_REVIEW_REQUIRED`, `MALFORMED_POLICY`.
   - `ForbiddenActionRule` (`POL-RULE-001`): Evaluates application-configured `forbidden_actions` against `ACTION` payloads (`RecommendedAction.BLOCK`).
   - `ForbiddenDestinationRule` (`POL-RULE-002`): Evaluates `forbidden_destination_domains` against URLs, domains, and action destinations (`RecommendedAction.BLOCK`).
   - `HumanReviewRequiredRule` (`POL-RULE-003`): Evaluates `require_human_review` for high-impact actions (`RecommendedAction.HUMAN_REVIEW`).
   - Explicit policy validation: malformed policies emit `MALFORMED_POLICY` Evidence rather than silently failing open.

3. **Multi-Guard Integration:**
   - Generic orchestration of `SecurityGuard`, `PrivacyGuard`, and `PolicyGuard` concurrently via `RiskEngine`.
   - Multi-domain Evidence aggregation verified across Security, Privacy, and Policy findings for a single event without majority voting.

4. **Deterministic Arbiter (Phase 5):**
   - Implemented in `guardx/arbiter/` (`Arbiter`, `ArbiterResult`).
   - Immutable structured `ArbiterResult` capturing `verdict`, `reason`, `reason_code`, `decisive_evidence`, `considered_evidence`, `missing_guard_coverage`.
   - Strict 7-level deterministic precedence enforcing DD-011 and DD-016:
     1. Deterministic hard policy constraints (`policy.forbidden_action`, `policy.forbidden_destination`, `policy.malformed_policy` -> `BLOCK`).
     2. Critical/high-confidence security/privacy block recommendations -> `BLOCK`.
     3. Missing Guard coverage fail-safe handling (`ALL_GUARDS_FAILED` on `ACTION` or any failed Guard on executing `ACTION` -> `BLOCK`; non-action/input failures -> `HUMAN_REVIEW`).
     4. Policy or Guard human review requirements -> `HUMAN_REVIEW`.
     5. Modification recommendations -> `MODIFY`.
     6. Lower-risk findings with `RecommendedAction.ALLOW` (e.g. personal identifiers) -> `ALLOW`.
     7. Clean evaluation default -> `ALLOW`.
   - No majority voting, no LLM usage, no collapsing of severity and confidence into arbitrary formulas.

5. **Unit & Integration Test Suite (`tests/`):**
5. **Action Provenance DAG (Phase 6):**
   - Implemented in `guardx/provenance/` (`ActionProvenanceDAG`, `ProvenanceNode`, `ProvenanceEdge`, `ProvenanceNodeType`, `ProvenanceEdgeType`).
   - Pure standard-library Python in-memory representation tracking data and execution lineage.
   - Enforces graph invariants: unique node IDs, cycle prevention (`ProvenanceCycleError` on self-loops or multi-node cycles), session boundary isolation (`SessionMismatchError`), and deterministic BFS traversals.
   - Provides key lineage queries: `derives_from(target, source)`, `get_ancestors()`, `get_descendants()`, `get_direct_parents()`, `get_direct_children()`.
   - Adheres strictly to data minimization: stores safe identifiers, references, descriptions, and metadata rather than raw payloads or conversation logs.
   - Compatible placeholder for Phase 7 semantic safety properties (`safety_properties` sequence on nodes).

6. **Semantic Safety Property Propagation (Phase 7):**
   - Implemented in `guardx/provenance/` (`PropertyPropagationEngine`, `TransformationRule`, `TransformationType`, `SafetyProperty`).
   - Typed semantic property vocabulary: `PII`, `CREDENTIAL`, `SECRET`, `CONFIDENTIAL`, `FINANCIAL_DATA`, `UNTRUSTED_SOURCE`.
   - Conservative default: unverified operations (e.g. summarization, format conversion) strictly preserve sensitive properties.
   - Trusted reduction: property removal requires an explicitly registered, authorized `TransformationRule(is_trusted_reduction=True)`.
   - Property introduction: sources or operations can introduce properties (e.g. `EXTERNAL_INGESTION` introduces `UNTRUSTED_SOURCE`).
   - Multi-parent union: combining branches merges safety properties conservatively via set union.
   - Non-destructive computation: historical `ProvenanceNode` objects remain immutable; effective properties are computed dynamically over DAG topological ordering.

8. **Action Authorization (Phase 8):**
   - Implemented in `guardx/authorization/` (`ActionAuthorizationEngine`, `ActionRequest`, `AuthorizationRiskType`).
   - Pure standard-library Python pre-execution inspection of proposed `ACTION` events.
   - Stable machine-readable risk types: `policy.unauthorized_sensitive_data_transfer`, `policy.missing_action_permission`, `policy.restricted_resource_use`, `policy.action_human_review_required`, `policy.malformed_action_request`.
   - Inspects proposed actions before execution: resolves action names, parameters, destination addresses, and permissions.
   - Integrates directly with `ActionProvenanceDAG` and `PropertyPropagationEngine`: resolves upstream data lineage, computes effective propagated properties, and evaluates data egress rules.
   - Evaluates policy constraints: required permissions for sensitive actions, human review gates, restricted destinations, external vs internal domains, and forbidden property egress rules.
   - Emits structured, deeply immutable `Evidence` records with recommended actions (`RecommendedAction.BLOCK`, `RecommendedAction.HUMAN_REVIEW`) feeding directly into deterministic `Arbiter` (preserving Arbiter final decision ownership).
   - Validated against end-to-end showcase: `customers.csv` [PII, CONFIDENTIAL] exfiltration via `send_email` blocked with `Verdict.BLOCK`; contrasting non-sensitive data flow cleanly allowed with `Verdict.ALLOW`.

9. **Unit & Integration Test Suite (`tests/`):**
   - 170 total passing tests:
     - 27 Phase 1 domain model & contract tests
     - 11 Phase 2 SecurityGuard tests
     - 14 Phase 3 RiskEngine tests
     - 12 Phase 4 PrivacyGuard tests
     - 10 Phase 4 PolicyGuard tests
     - 4 Multi-Guard orchestration tests
     - 17 Phase 5 Arbiter unit and full-pipeline integration tests
     - 24 Phase 6 Action Provenance DAG tests
     - 27 Phase 7 Semantic Safety Property Propagation tests
     - 24 Phase 8 Action Authorization unit, integration, and showcase tests

---

## In Progress

Preparing for **Phase 9 — Showcase Demonstration & Interactive CLI / Runner**.

---

## Not Implemented

The following do NOT currently exist as production code:

- Content Safety Guard (Phase 14)
- Risk Memory (Phase 9 / later)
- Disagreement detector (Phase 9)
- Bounded Investigation mechanism (Phase 10)
- MODIFY workflow (Phase 12)
- Audit system (Phase 13)
- External provider integrations or API servers

---

## Accepted Decisions

### Showcase Demonstration (Phase 9)

Implemented in `demo/`:

1. **Interactive Demo Runner (`demo.runner.DemoRunner`):**
   - Pure live pipeline orchestrator exercising real `RiskEngine`, `SecurityGuard`, `PrivacyGuard`, `PolicyGuard`, `ActionProvenanceDAG`, `PropertyPropagationEngine`, `ActionAuthorizationEngine`, and `Arbiter`.
   - **Zero hardcoded verdicts**: All decisions dynamically emerge from live component evaluation.
2. **Predefined Scenarios (`demo.scenarios`):**
   - Benign query (`What is the capital of Japan?`) -> `ALLOW`.
   - Direct prompt injection -> `BLOCK`.
   - Conversational PII (email detection) -> `ALLOW` (informational audit finding).
   - Policy-forbidden shell command -> `BLOCK`.
   - Customers.csv exfiltration with multi-step DAG lineage -> `BLOCK`.
   - Contrasting safe internal transfer -> `ALLOW`.
3. **Presentable Interfaces:**
   - Interactive modern Web UI dashboard (`demo/web/index.html`) served via zero-dependency Python `http.server`. Features interactive 6-step data flow stepper, live SVG graph visualization with semantic property labels, guard findings grid, and technical inspector.
   - Rich ANSI Terminal CLI (`demo.cli`) with ASCII box diagrams and interactive walkthrough.
   - Unified application launcher (`demo/app.py`).

---

## Accepted Decisions

- Primary implementation language: Python (DD-001).
- Deterministic-first safety (DD-002).
- Guards produce structured Evidence; Arbiter produces final Verdict (DD-003).
- Common Evidence model distinguishing severity and confidence (DD-004).
- Evidence records are deeply immutable after creation (DD-005).
- Safety-relevant context is stored separately from full conversation history (DD-006).
- Action Provenance uses an in-memory DAG data model (DD-007).
- Risk propagation uses semantic safety properties (DD-008).
- Simple majority voting is not used for final safety decisions (DD-009).
- Investigation must be bounded (DD-010).
- Arbiter is deterministic-first (DD-011).
- Multiple interception points: INPUT, OUTPUT, ACTION, TOOL_RESULT (DD-013).
- GuardX must remain model-provider independent (DD-014).
- Technology selection is deferred until required (DD-015).

---

## Proposed / Under Review

- Severity alone does not directly map to verdict (DD-012).
- Deterministic Arbiter baseline precedence (DD-016).
- Four initial guard categories: Security, Privacy, Content Safety, Policy.
- Optional model-assisted investigation and arbitration for ambiguous cases.

---

## Known Issues / Open Questions

- Exact Risk Memory expiry policy is unresolved.
- Exact action-impact classification is unresolved.
- MODIFY execution semantics need definition.
- Arbiter baseline rules require evaluation on benchmark datasets.
- Investigation trigger conditions require evaluation.
- Audit persistence beyond a session is unresolved.
- Content Safety / Policy guard overlap needs evaluation.
- Scientific novelty has not been established and requires literature review.

---

## Next Step

**Phase 10 — Risk Memory Baseline.**

Implement the first safety-relevant session risk memory tracking significant previous findings and sensitive resources accessed across multi-turn interactions.