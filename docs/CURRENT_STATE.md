# GuardX — Current State

## Current Phase

**Phase 4 Completed — Ready for Phase 5 (Deterministic Arbiter)**

Phase 1 foundational domain models, Phase 2 deterministic Security Guard, Phase 3 Risk Engine Guard orchestration layer, and Phase 4 Privacy & Policy Guards have been implemented and verified with 78 unit tests.

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

4. **Unit Test Suite (`tests/`):**
   - 78 total passing tests (27 Phase 1 + 11 Phase 2 + 14 Phase 3 + 12 Privacy + 10 Policy + 4 Multi-Guard integration).

---

## In Progress

Preparing for **Phase 5 — Arbiter & Final Verdict Decision Layer**.

---

## Not Implemented

The following do NOT currently exist as production code:

- Content Safety Guard (Phase 4 / Phase 14)
- Arbiter decision engine (Phase 5)
- Risk Memory (Phase 6)
- Action Provenance DAG (Phase 7)
- Risk / Safety Property Propagation (Phase 8)
- Disagreement detector (Phase 9)
- Bounded Investigation mechanism (Phase 10)
- Action Authorization (Phase 11)
- MODIFY workflow (Phase 12)
- Audit system (Phase 13)
- External provider integrations or API servers

---

## Accepted Decisions

- Primary implementation language: Python (DD-001).
- Deterministic-first safety (DD-002).
- Guards produce structured Evidence; Arbiter produces final Verdict (DD-003).
- Common Evidence model distinguishing severity and confidence (DD-004).
- Evidence records are deeply immutable after creation (DD-005).
- Safety-relevant context is stored separately from full conversation history (DD-006).
- Simple majority voting is not used for final safety decisions (DD-009).
- Investigation must be bounded (DD-010).
- Arbiter is deterministic-first (DD-011).
- Multiple interception points: INPUT, OUTPUT, ACTION, TOOL_RESULT (DD-013).
- GuardX must remain model-provider independent (DD-014).
- Technology selection is deferred until required (DD-015).

---

## Proposed / Under Review

- Provenance represented as an in-memory DAG for the prototype (DD-007).
- Risk propagation based primarily on safety properties/labels rather than a single numeric risk score (DD-008).
- Severity alone does not directly map to verdict (DD-012).
- Four initial guard categories: Security, Privacy, Content Safety, Policy.
- Optional model-assisted investigation and arbitration for ambiguous cases.

---

## Known Issues / Open Questions

- Exact Risk Memory expiry policy is unresolved.
- Exact action-impact classification is unresolved.
- MODIFY execution semantics need definition.
- Arbiter baseline rules require evaluation.
- Investigation trigger conditions require evaluation.
- Audit persistence beyond a session is unresolved.
- Content Safety / Policy guard overlap needs evaluation.
- Scientific novelty has not been established and requires literature review.

---

## Next Step

**Phase 2 — Minimal Security Guard.**

Implement the first deterministic Security Guard end-to-end to detect obvious prompt-injection patterns and dangerous action requests.