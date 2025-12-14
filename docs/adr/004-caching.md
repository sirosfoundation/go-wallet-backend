# ADR-004: Caching Strategy

## Status

Accepted

## Context

The wallet backend needs caching for:
- WebAuthn challenges (short TTL)
- Issuer metadata (longer TTL)
- Session data (configurable TTL)
- JWK sets from external sources

## Decision

We use the `github.com/jellydator/ttlcache/v3` library to provide caching across the project.

## Rationale

A single implementation of a central concept serves to:
- Simplify the code
- Make caching behavior more consistent
- Provide automatic expiration
- Support thread-safe operations
- Enable easy testing with mock caches

## Consequences

- All caching should use ttlcache
- TTL values should be configurable
- Cache metrics should be exposed for monitoring
- Tests should verify cache behavior
