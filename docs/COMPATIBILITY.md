# API Compatibility with Reference Implementation

This document describes the compatibility between `go-wallet-backend` and the reference TypeScript implementation (`wallet-backend-server`).

## Overview

The Go implementation is designed to be a drop-in replacement for the TypeScript wallet-backend-server. All API endpoints use the same JSON field naming conventions and response structures to ensure frontend compatibility.

## JSON Field Naming Convention

Both implementations use **camelCase** for JSON field names:

| Domain Model | JSON Fields |
|--------------|-------------|
| VerifiableCredential | `holderDID`, `credentialIdentifier`, `credentialConfigurationId`, `credentialIssuerIdentifier`, `instanceId`, `sigCount` |
| VerifiablePresentation | `holderDID`, `presentationIdentifier`, `presentationSubmission`, `includedVerifiableCredentialIdentifiers`, `audience`, `issuanceDate` |
| CredentialIssuer | `credentialIssuerIdentifier`, `clientId`, `visible` |
| Verifier | `name`, `url` |

## Tagged Binary Encoding

The wallet-frontend encodes binary data (Uint8Array/ArrayBuffer) using a tagged binary format:

```json
{"$b64u": "base64url-encoded-string"}
```

This format is used in WebAuthn credential responses where binary fields like `rawId`, `authenticatorData`, `clientDataJSON`, and `signature` need to be transmitted in JSON.

### Example: WebAuthn Credential Request

Frontend sends:
```json
{
  "challengeId": "abc123",
  "credential": {
    "type": "public-key",
    "id": "credential-id",
    "rawId": {"$b64u": "Y3JlZGVudGlhbC1pZA"},
    "response": {
      "authenticatorData": {"$b64u": "YXV0aERhdGE"},
      "clientDataJSON": {"$b64u": "Y2xpZW50RGF0YQ"},
      "signature": {"$b64u": "c2lnbmF0dXJl"}
    }
  }
}
```

The Go backend automatically decodes this to:
```json
{
  "challengeId": "abc123",
  "credential": {
    "type": "public-key",
    "id": "credential-id",
    "rawId": "Y3JlZGVudGlhbC1pZA",
    "response": {
      "authenticatorData": "YXV0aERhdGE",
      "clientDataJSON": "Y2xpZW50RGF0YQ",
      "signature": "c2lnbmF0dXJl"
    }
  }
}
```

This is handled by the `pkg/taggedbinary` package and is transparent to the WebAuthn library which expects plain base64url strings.

### Server Response Encoding

The Go backend also encodes binary fields in responses using the tagged format. This ensures the frontend can properly decode binary data using `jsonParseTaggedBinary`.

**Fields encoded as tagged binary in responses:**
- `privateData` - User's encrypted private data
- `credentialId` - WebAuthn credential identifier in account info

Example server response:
```json
{
  "uuid": "user-uuid",
  "appToken": "jwt-token",
  "displayName": "User Name",
  "privateData": {"$b64u": "ZW5jcnlwdGVkLWRhdGE"}
}
```

The `TaggedBytes` type in `pkg/taggedbinary` handles this marshaling automatically.

## WebAuthn Response Format

The WebAuthn responses match the reference implementation's structure:

### Registration

```json
{
  "challengeId": "uuid-challenge-id",
  "createOptions": {
    "publicKey": {
      "rp": { "name": "Wallet", "id": "localhost" },
      "user": { "id": "base64-encoded", "name": "username", "displayName": "Username" },
      "challenge": "base64url-encoded",
      "pubKeyCredParams": [...],
      "timeout": 60000,
      "authenticatorSelection": {...},
      "attestation": "direct"
    }
  }
}
```

### Login

```json
{
  "challengeId": "uuid-challenge-id",
  "getOptions": {
    "publicKey": {
      "challenge": "base64url-encoded",
      "timeout": 60000,
      "rpId": "localhost",
      "allowCredentials": [...],
      "userVerification": "preferred"
    }
  }
}
```

## API Endpoints

### Implemented (Reference-Compatible)

#### User Authentication (Public - No Auth Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status` | GET | Service status |
| `/user/register-webauthn-begin` | POST | Begin WebAuthn registration |
| `/user/register-webauthn-finish` | POST | Complete WebAuthn registration |
| `/user/login-webauthn-begin` | POST | Begin WebAuthn login |
| `/user/login-webauthn-finish` | POST | Complete WebAuthn login |
| `/helper/auth-check` | GET, POST | Relay authentication check |

#### User Session (Authenticated)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/user/session/account-info` | GET | Get account information |
| `/user/session/settings` | POST | Update user settings |
| `/user/session/private-data` | GET | Get private data with ETag support |
| `/user/session/private-data` | POST | Update private data with ETag support |
| `/user/session/` | DELETE | Delete user account and all data |
| `/user/session/webauthn/register-begin` | POST | Begin adding WebAuthn credential |
| `/user/session/webauthn/register-finish` | POST | Complete adding WebAuthn credential |
| `/user/session/webauthn/credential/:id/rename` | POST | Rename WebAuthn credential |
| `/user/session/webauthn/credential/:id/delete` | POST | Delete WebAuthn credential |

#### Storage (Authenticated)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/storage/vc` | GET | Get all credentials for holder |
| `/storage/vc` | POST | Store credentials (batch) |
| `/storage/vc/update` | POST | Update a credential |
| `/storage/vc/:credential_identifier` | GET | Get credential by identifier |
| `/storage/vc/:credential_identifier` | DELETE | Delete credential |
| `/storage/vp` | GET | Get all presentations for holder |
| `/storage/vp` | POST | Store a presentation |
| `/storage/vp/:presentation_identifier` | GET | Get presentation by identifier |

#### Registry (Authenticated)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/issuer/all` | GET | List all credential issuers |
| `/verifier/all` | GET | List all verifiers |

#### Helper (Authenticated)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/proxy` | POST | Proxy HTTP requests |
| `/helper/get-cert` | POST | Get SSL certificate chain |
| `/wallet-provider/key-attestation/generate` | POST | Generate key attestation JWT |

### Extended (Go-Only)

The following endpoints extend the functionality beyond the reference implementation:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status` | GET | Extended status with service info |
| `/keystore/status` | GET | Check if keystore client is connected |
| `/ws/keystore` | WS | WebSocket for client-side keystore |

## Intentional Extensions

The Go implementation includes several intentional extensions beyond the reference implementation. These extensions are backward-compatible and do not affect frontend compatibility.

### 1. Storage Abstraction

The Go implementation provides a pluggable storage layer:

- **In-Memory**: For development and testing
- **MongoDB**: For production deployments

The reference implementation is tied to a specific database. The Go version allows choosing backends via configuration:

```yaml
storage:
  type: "mongodb"  # or "memory"
  mongodb:
    uri: "mongodb://localhost:27017"
    database: "wallet"
```

### 2. Cloud-Native Design

Extensions for cloud deployment:

- **Stateless architecture**: All state in external storage
- **Graceful shutdown**: Proper cleanup on SIGTERM
- **Structured logging**: JSON logs with zap

### 3. Configuration Flexibility

Configuration via multiple sources (in order of precedence):

1. Command-line flags
2. Environment variables (prefixed with `WALLET_`)
3. YAML configuration file

### 4. WebSocket Client Keystore

Extended WebSocket-based keystore for client-side key management:

- **`/ws/keystore`**: WebSocket endpoint for keystore clients
- **`/keystore/status`**: Check if a user's keystore client is connected

This allows the wallet frontend to maintain keys client-side while the server can request signatures.

### 5. Deprecated Password Authentication

The Go implementation deprecates password-based authentication:

- `/user/register` and `/user/login` return HTTP 410 Gone
- Users are directed to use WebAuthn endpoints instead
- This improves security by enforcing passwordless authentication

### 6. Extended Error Responses

More informative error responses with consistent structure:

```json
{
  "error": "Challenge not found"
}
```

Error codes are HTTP status codes that match the reference implementation:
- 400: Bad request / Invalid input
- 401: Unauthorized
- 403: Forbidden  
- 404: Not found
- 409: Conflict (e.g., last WebAuthn credential)
- 410: Gone (expired challenge, deprecated endpoints)
- 412: Precondition failed (ETag mismatch)
- 500: Internal server error

### 7. Prepared Future Extensions

The following capabilities are prepared but not yet exposed as API endpoints:

- **Presentation deletion**: `DELETE /storage/vp/:identifier` (handler exists, route not registered)
- **GetIssuerByID**: Individual issuer lookup beyond the `/all` endpoint
- **Prometheus metrics**: Infrastructure ready for `/metrics` endpoint

## Schema Compatibility

### VerifiableCredential

| Field | TypeScript | Go | Notes |
|-------|------------|-----|-------|
| id | ✓ | ✓ | Auto-generated |
| holderDID | ✓ | ✓ | |
| credentialIdentifier | ✓ | ✓ | |
| credential | ✓ | ✓ | Base64/JSON encoded |
| format | ✓ | ✓ | `vc+sd-jwt`, `jwt_vc`, etc. |
| credentialConfigurationId | ✓ | ✓ | |
| credentialIssuerIdentifier | ✓ | ✓ | |
| instanceId | ✓ | ✓ | |
| sigCount | ✓ | ✓ | |

### VerifiablePresentation

| Field | TypeScript | Go | Notes |
|-------|------------|-----|-------|
| id | ✓ | ✓ | Auto-generated |
| holderDID | ✓ | ✓ | |
| presentationIdentifier | ✓ | ✓ | |
| presentation | ✓ | ✓ | Encoded VP |
| presentationSubmission | ✓ | ✓ | JSON object |
| includedVerifiableCredentialIdentifiers | ✓ | ✓ | Array of credential IDs |
| audience | ✓ | ✓ | Verifier identifier |
| issuanceDate | ✓ | ✓ | RFC3339 timestamp |

### CredentialIssuer

| Field | TypeScript | Go | Notes |
|-------|------------|-----|-------|
| id | ✓ | ✓ | Auto-generated |
| credentialIssuerIdentifier | ✓ | ✓ | Issuer URL |
| clientId | ✓ | ✓ | OAuth client ID |
| visible | ✓ | ✓ | Show in UI |

### Verifier

| Field | TypeScript | Go | Notes |
|-------|------------|-----|-------|
| id | ✓ | ✓ | Auto-generated |
| name | ✓ | ✓ | Display name |
| url | ✓ | ✓ | Verifier endpoint |

## Migration Notes

### From TypeScript to Go

1. **Database Migration**: Export data and import into Go storage backend
2. **Configuration**: Convert `.env` to YAML or use environment variables with `WALLET_` prefix
3. **Session Handling**: Sessions are not compatible; users will need to re-authenticate

### Frontend Compatibility

The Go backend is designed to work with the existing `wallet-frontend` without modifications:

- Same API endpoints
- Same JSON field names
- Same response structures
- Same authentication flow (WebAuthn)

## Testing Compatibility

Run the integration test suite against both implementations to verify compatibility:

```bash
# Against TypeScript
npm run test:integration -- --server=http://localhost:3000

# Against Go
npm run test:integration -- --server=http://localhost:8080
```

## Version Compatibility Matrix

| Go Version | TypeScript Version | Frontend Version | Notes |
|------------|-------------------|------------------|-------|
| 1.0.0 | 1.x | 1.x | Full compatibility |

## Reporting Issues

If you find a compatibility issue:

1. Check this document for intentional differences
2. Verify the issue with both implementations
3. Open an issue with:
   - Request/response examples from both implementations
   - Frontend version if applicable
   - Steps to reproduce
