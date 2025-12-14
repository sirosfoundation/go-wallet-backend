# ADR-001: Cryptographic Libraries

## Status

Accepted

## Context

The wallet backend handles sensitive cryptographic operations including:
- Password hashing
- JWT signing and verification
- WebAuthn credential management
- DID key generation

## Decision

This project avoids implementing cryptographic primitives, favouring the reuse of existing, well-tested libraries:

- **Password hashing**: `golang.org/x/crypto/bcrypt`
- **JWT operations**: `github.com/golang-jwt/jwt/v5` and `github.com/lestrrat-go/jwx/v3`
- **WebAuthn**: `github.com/go-webauthn/webauthn`
- **DID operations**: Reuse from `github.com/dc4eu/vc` project

## Rationale

Cryptography is hard to get right. Making a mistake when implementing a cryptographic primitive will have serious implications for the security of protocols that build upon those primitives.

Using well-tested, widely-adopted libraries:
- Reduces the risk of security vulnerabilities
- Benefits from community review and auditing
- Provides better compatibility with standards
- Simplifies maintenance

## Consequences

- Dependencies on external libraries must be kept up-to-date
- Library choices should be evaluated for security and maintenance status
- Custom crypto code is prohibited without explicit review
