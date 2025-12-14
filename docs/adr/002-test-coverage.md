# ADR-002: Test Coverage

## Status

Accepted

## Context

The wallet backend handles sensitive operations including user authentication, credential management, and cryptographic operations. High reliability is essential.

## Decision

This project will aim for >70% test coverage overall, with higher coverage (>80%) for:
- Storage layer implementations
- Authentication and authorization
- Cryptographic operations
- API handlers

## Rationale

A high degree of test coverage leads to more robust code. Given our use of AI-assisted programming, comprehensive tests help reduce the effect of hallucination and catch regressions early.

Test coverage serves multiple purposes:
- Validates correct behavior
- Documents expected functionality
- Enables safe refactoring
- Catches regressions early

## Consequences

- All new code must include tests
- PRs should not decrease overall coverage
- CI pipeline enforces coverage thresholds
- Test-driven development is encouraged
