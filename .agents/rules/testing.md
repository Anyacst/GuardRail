---
trigger: glob
globs: "tests/**/*.py, **/test_*.py, **/*_test.py"
description: "Testing rules for GuardX Python tests and evaluation fixtures."
---

# GuardX Testing Rules

Tests are part of GuardX's safety argument.

Prefer deterministic, reproducible tests.

External model/API calls should normally be mocked for unit tests.

## Every Component

Where applicable test:

- expected behavior,
- edge cases,
- malformed input,
- empty input,
- boundary conditions,
- exception handling,
- timeout behavior,
- dependency/provider failure,
- invalid structured output.

## Guard Tests

Test:

- true positive cases,
- benign cases,
- false-positive-oriented cases,
- malformed EvaluationContext,
- multiple findings,
- no findings,
- deterministic failure paths.

Do not test only obvious attacks.

## Evidence Tests

Verify:

- required fields,
- severity/confidence separation,
- immutability,
- provenance references,
- linked re-evaluation Evidence.

## Risk Engine Tests

Test:

- one Guard,
- multiple Guards,
- applicable-Guard selection,
- parallel execution where implemented,
- Guard timeout,
- Guard exception,
- malformed Guard output,
- all Guards failing.

## Risk Memory Tests

Test:

- session isolation,
- creation,
- relevant retrieval,
- resolution,
- expiry,
- false-positive cleanup,
- data minimization.

Ensure unrelated state does not contaminate future decisions.

## Provenance Tests

Test:

- linear lineage,
- branching,
- merging,
- multiple parents,
- ancestor lookup,
- descendant lookup,
- invalid edges,
- cycle rejection if DAG semantics are enforced,
- session isolation.

## Risk Propagation Tests

Test transformations that:

- preserve properties,
- explicitly reduce/remove properties,
- introduce properties,
- combine properties.

Default behavior should be conservative.

## Arbiter Tests

Use explicit decision tables.

Test:

- ALLOW,
- MODIFY,
- BLOCK,
- HUMAN_REVIEW,
- deterministic overrides,
- incomplete Evidence,
- uncertainty,
- conflicting Evidence,
- available mitigation,
- policy-required approval.

Do not encode arbitrary severity-to-verdict assumptions unless they are
accepted policy.

## Investigation Tests

Verify:

- correct triggering,
- no unnecessary triggering,
- bounded iteration,
- timeout,
- unresolved uncertainty,
- new Evidence linked to original Evidence,
- no recursive Investigation loop.

## Action Authorization Tests

Test:

- allowed action,
- forbidden action,
- restricted destination,
- missing permission,
- sensitive data transfer,
- destructive operation,
- modified action,
- provenance-dependent decision.

Use simulated tools.

Never run destructive tests against real systems.

## Security Regression Tests

Every confirmed security bug should receive a regression test when practical.

The regression test should fail before the fix and pass after the fix.

## Test Quality

Do not:

- weaken production logic to make tests pass,
- mock the component under test,
- assert only that "no exception occurred",
- depend on live external APIs for unit tests,
- use flaky timing assumptions.

Tests should explain what safety property they protect.

## Evaluation vs Unit Tests

Do not confuse:

    unit tests

with:

    empirical safety evaluation.

Unit tests verify expected implementation behavior.

`docs/EVALUATION_PLAN.md` defines how GuardX's effectiveness should eventually
be measured against datasets, attacks, and baselines.