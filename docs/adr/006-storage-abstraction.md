# ADR-006: Storage Abstraction

## Status

Accepted

## Context

The original wallet-backend-server was tightly coupled to MySQL. For cloud-native deployment and horizontal scaling, we need flexibility in storage backends.

## Decision

The storage layer is fully abstracted through interfaces:

```go
type Store interface {
    Users() UserStore
    Credentials() CredentialStore
    Presentations() PresentationStore
    Challenges() ChallengeStore
    Issuers() IssuerStore
    Verifiers() VerifierStore
    Close() error
    Ping(ctx context.Context) error
}
```

Implementations:
- **Memory**: For development and testing
- **SQLite**: For single-instance deployments
- **MongoDB**: For production horizontal scaling

## Rationale

- **Flexibility**: Choose the right storage for the deployment scenario
- **Testing**: In-memory storage enables fast, isolated tests
- **Cloud-native**: MongoDB supports horizontal scaling
- **No vendor lock-in**: Easy to switch storage backends
- **Single-instance support**: SQLite for simpler deployments

## Consequences

- All storage access goes through interfaces
- New storage backends can be added without changing business logic
- Tests use in-memory storage by default
- Configuration determines which backend is used
