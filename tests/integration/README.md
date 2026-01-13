# Integration Tests

This directory contains integration tests that verify API compatibility between
go-wallet-backend and wallet-frontend.

## Overview

These tests simulate the HTTP requests that wallet-frontend makes to the backend,
ensuring that:

1. Response formats match what the frontend expects
2. WebAuthn flows work correctly end-to-end
3. Session management behaves as expected
4. Storage APIs handle credentials correctly

## Running Tests

```bash
# Run all integration tests
go test ./tests/integration/... -v

# Run specific test suite
go test ./tests/integration/... -v -run TestWebAuthn

# Run with race detection
go test ./tests/integration/... -v -race
```

## Test Structure

- `harness.go` - Test harness for spinning up test server instances
- `webauthn_test.go` - WebAuthn registration and login flow tests
- `session_test.go` - Session management tests
- `storage_test.go` - Credential and presentation storage tests
- `golden/` - Golden files containing expected API responses
- `testdata/` - Test fixtures and mock data

## Golden File Tests

Golden files capture the expected JSON response format from the TypeScript
wallet-backend-server. To update golden files:

```bash
go test ./tests/integration/... -v -update-golden
```

## WebAuthn Testing

Since we can't use real WebAuthn authenticators in automated tests, we use
the go-webauthn library's test utilities to simulate authenticator responses.
This includes:

- Creating mock credentials
- Generating valid attestation responses
- Creating authentication assertions
