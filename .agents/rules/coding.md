---
trigger: glob
globs: "**/*.py"
description: "Python implementation rules for GuardX production code."
---

# GuardX Python Coding Rules

GuardX uses Python.

Before implementing a component:

1. read `AGENTS.md`,
2. read the relevant architecture section,
3. inspect relevant accepted design decisions,
4. inspect existing implementation,
5. inspect existing tests.

Do not implement from assumptions when repository evidence exists.

## General Principles

Prefer:

- simple code,
- explicit types,
- small focused modules,
- clear interfaces,
- dependency injection where it improves testability,
- deterministic behavior,
- explicit error handling.

Avoid:

- hidden global state,
- unnecessary inheritance,
- premature abstraction,
- unnecessary frameworks,
- unnecessary model calls,
- broad exception swallowing,
- magic constants,
- duplicated safety logic.

## Async

Core Guard execution should support asynchronous operation where external or
parallel work is expected.

Do not make purely local deterministic functions async without reason.

## Types

Use Python type hints for public interfaces.

Important domain concepts should have explicit representations rather than
unstructured dictionaries where practical.

Do not select a validation library until the project accepts one.

## Guards

Guard implementations must conform to the common Guard contract.

A Guard should:

- receive evaluation context,
- analyze its risk domain,
- produce Evidence.

A Guard should not:

- directly execute user actions,
- modify other Guards' Evidence,
- silently make the global authorization decision.

## Evidence

Evidence must be immutable after emission.

Never update an existing Evidence object to represent a changed conclusion.

Create new linked Evidence.

## External Models / APIs

All external model/provider calls must:

- have timeouts,
- expose failure clearly,
- be replaceable behind an interface,
- be mockable in tests,
- validate returned data.

Do not couple domain logic to one provider SDK.

## Risk Memory

Store only safety-relevant state.

Do not persist complete prompts, responses, tool results, or sensitive
contents without explicit justification.

## Provenance

Do not lose provenance when transforming safety-relevant data.

When derived data is created, preserve its relationship to source nodes.

Do not silently reduce safety properties.

## Errors

Errors in safety-critical paths must be explicit.

Do not write:

    try:
        ...
    except:
        pass

Safety failures require defined behavior and audit information.

## Logging

Never log secrets.

Prefer identifiers and safety metadata over raw sensitive data.

## Dependencies

Before adding a dependency:

1. identify the required capability,
2. determine whether the standard library is sufficient,
3. explain why the dependency is justified.

Do not add libraries simply because they are popular.

## Scope

Implement only the current roadmap phase.

Do not opportunistically implement future phases.

After implementation:

- run relevant tests,
- perform security review where appropriate,
- update `docs/CURRENT_STATE.md`.