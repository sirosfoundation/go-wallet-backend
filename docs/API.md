# API Reference

This document describes the public wallet API. For the internal administration API, see [Admin API (OpenAPI)](./openapi-admin.yaml).

## Base URL

```
http://localhost:8080
```

## Admin API

The admin API runs on a separate port (default: 8081) and provides multi-tenant management capabilities:

- Tenant management (CRUD)
- User membership management
- Issuer configuration per tenant
- Verifier configuration per tenant

See [openapi-admin.yaml](./openapi-admin.yaml) for the complete OpenAPI 3.0 specification.

## Authentication

Most endpoints require a JWT token in the `Authorization` header:

```
Authorization: Bearer <token>
```

## Endpoints

### Status

#### GET /status

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "service": "wallet-backend"
}
```

---

### User Management

#### POST /user/register

Register a new user.

**Request:**
```json
{
  "username": "alice",
  "display_name": "Alice Smith",
  "password": "secret123",
  "wallet_type": "db"
}
```

**Response:**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "did": "did:key:550e8400-e29b-41d4-a716-446655440000",
  "display_name": "Alice Smith"
}
```

#### POST /user/login

Login with username and password.

**Request:**
```json
{
  "username": "alice",
  "password": "secret123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "display_name": "Alice Smith"
}
```

#### POST /user/webauthn/register/start

Start WebAuthn registration (passwordless).

**Request:**
```json
{
  "username": "alice",
  "display_name": "Alice Smith"
}
```

**Response:**
```json
{
  "options": {
    "publicKey": {
      "challenge": "...",
      "rp": {...},
      "user": {...},
      "pubKeyCredParams": [...]
    }
  }
}
```

#### POST /user/webauthn/register/finish

Finish WebAuthn registration.

**Request:**
```json
{
  "credential": {
    "id": "...",
    "rawId": "...",
    "response": {...},
    "type": "public-key"
  }
}
```

**Response:**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "did": "did:key:..."
}
```

---

#### Wallet instance lifecycle (SID-AUTH-06)

A wallet instance is one wallet installation, identified by the JWK thumbprint of
its instance key and registered when it first obtains a Wallet Instance
Attestation. A user can inspect and manage their own instances; a provider
manages them through the admin API (`/admin/tenants/{id}/instances`). Both paths
share one lifecycle: `active` → `suspended` (reversible) or `revoked`
(terminal), `suspended` → `active` or `revoked`. Any change away from `active`
drops the user's live sessions and refuses new WIAs for that instance. Login with
the passkey linked to a suspended or revoked instance is refused with `403
WALLET_SUSPENDED` / `WALLET_REVOKED`; the user's other, non-revoked devices
still log in.

Wallet instances are per tenant. Revoking the last non-revoked instance of a
user in a tenant deactivates the wallet in that tenant: the credentials and
presentations held there are erased, every passkey of the user is refused at
login in that tenant (`403 WALLET_REVOKED`), and a new enrollment is required.
The `message` field of the 403 tells the two cases apart for the user. The
user-level data shared across tenants - the encrypted private data (the
custodian of the wallet's keys) and pending challenges - is erased once no
non-revoked instance remains in any tenant the user belongs to.

The status change is recorded before the cascade runs. If dropping sessions or
erasing data then fails, the status change stands and the request answers
`409 ERASURE_INCOMPLETE` (with the new `status`); repeating the same request
re-runs the erasure, so the client retries until it gets `200`.

Any change away from `active` also cuts off bearer tokens issued before it:
legacy access and refresh tokens, and access tokens validated by the backend
or accepted for a WebSocket handshake, are refused with `401` when their `iat`
is not after the cut-off, even if they have not expired. The one exception is
the token that made the self-service request: it stays valid, so the user can
reactivate a suspended instance or repeat a request after `409
ERASURE_INCOMPLETE` from the same session. Admin-initiated changes exempt no
token. Tokens obtained after a reactivation work normally. A login or token
refresh that races with a lifecycle change is refused rather than handed a
token that would be rejected on first use.

An engine deployed without the backend role in the same process enforces the
cut-off only when persistent storage is configured; with memory storage it
logs a warning at startup and relies on the token lifetime.

Revoked instances of a user are retained as lifecycle records: they are what
keeps login and new attestations refused for that wallet. The admin API
answers `409 REVOKED_INSTANCE_RETAINED` to `DELETE
/admin/tenants/{id}/instances/{instance_id}` for such an instance; records
without a user (stray attestation records) can still be deleted.

The passkey link is recorded when the wallet passes its passkey's base64url
credential id as `credential_id` to `POST /wallet-provider/wia/generate`.

##### GET /user/session/instances

List the caller's wallet instances in the current tenant.

**Response:**
```json
{ "instances": [ { "id": "<jkt>", "status": "active", "wscd_type": "native_android", "last_attested_at": "..." } ] }
```

##### PUT /user/session/instances/{instance_id}/status

Change the status of one of the caller's instances.

**Request:**
```json
{ "status": "suspended", "reason": "lost phone" }
```

**Response:** `200 {"id": "<jkt>", "status": "suspended"}`; `404` if the instance
is not the caller's; `409 {"error": "invalid status transition"}` for an invalid
transition (e.g. reactivating a revoked instance); `409 {"error":
"ERASURE_INCOMPLETE", "id": ..., "status": "revoked"}` when the change was
recorded but the erasure must be retried.

##### POST /user/session/instances/revoke-all

Deactivate the wallet: revoke every instance of the caller and erase the wallet
data.

**Request (optional):** `{ "reason": "device stolen" }`

**Response:** `200 {"revoked": 2}`; `409 {"error": "ERASURE_INCOMPLETE",
"revoked": 2}` when the instances were revoked but the erasure must be retried
(repeat the request; it answers `200 {"revoked": 0}` once complete).

### Credential Management

All credential endpoints require authentication.

#### GET /storage/vc

Get all credentials for the authenticated user.

**Response:**
```json
[
  {
    "id": 1,
    "holder_did": "did:key:...",
    "credential_identifier": "urn:credential:123",
    "credential": "eyJhbGciOiJFUzI1NiJ9...",
    "format": "jwt_vc",
    "credential_configuration_id": "UniversityDegree",
    "credential_issuer_identifier": "https://issuer.example.com",
    "created_at": "2023-12-13T10:00:00Z"
  }
]
```

#### POST /storage/vc

Store a new credential.

**Request:**
```json
{
  "holder_did": "did:key:...",
  "credential_identifier": "urn:credential:123",
  "credential": "eyJhbGciOiJFUzI1NiJ9...",
  "format": "jwt_vc",
  "credential_configuration_id": "UniversityDegree",
  "credential_issuer_identifier": "https://issuer.example.com"
}
```

**Response:**
```json
{
  "id": 1,
  "message": "Credential stored successfully"
}
```

#### GET /storage/vc/:credential_identifier

Get a specific credential.

**Response:**
```json
{
  "id": 1,
  "holder_did": "did:key:...",
  "credential_identifier": "urn:credential:123",
  "credential": "eyJhbGciOiJFUzI1NiJ9...",
  "format": "jwt_vc"
}
```

#### DELETE /storage/vc/:credential_identifier

Delete a credential.

**Response:**
```json
{
  "message": "Credential deleted successfully"
}
```

#### PUT /storage/vc/update

Update credential metadata.

**Request:**
```json
{
  "credential_identifier": "urn:credential:123",
  "instance_id": 1,
  "sig_count": 5
}
```

**Response:**
```json
{
  "message": "Credential updated successfully"
}
```

---

### Presentation Management

#### GET /storage/vp

Get all presentations for the authenticated user.

**Response:**
```json
[
  {
    "id": 1,
    "holder_did": "did:key:...",
    "presentation_identifier": "urn:presentation:456",
    "presentation": "eyJhbGciOiJFUzI1NiJ9...",
    "credential_identifiers": ["urn:credential:123"],
    "audience_did": "did:key:verifier...",
    "nonce": "abc123",
    "created_at": "2023-12-13T11:00:00Z"
  }
]
```

#### POST /storage/vp

Store a new presentation.

**Request:**
```json
{
  "holder_did": "did:key:...",
  "presentation_identifier": "urn:presentation:456",
  "presentation": "eyJhbGciOiJFUzI1NiJ9...",
  "credential_identifiers": ["urn:credential:123"],
  "audience_did": "did:key:verifier...",
  "nonce": "abc123"
}
```

**Response:**
```json
{
  "id": 1,
  "message": "Presentation stored successfully"
}
```

---

### Issuer Registry

#### GET /issuer/all

Get all registered credential issuers.

**Response:**
```json
[
  {
    "id": 1,
    "identifier": "https://issuer.example.com",
    "name": "Example University",
    "url": "https://issuer.example.com",
    "credential_endpoint": "https://issuer.example.com/credential",
    "authorization_server": "https://issuer.example.com/oauth",
    "supported_credentials": ["UniversityDegree", "EmployeeID"]
  }
]
```

---

### Verifier Registry

#### GET /verifier/all

Get all registered verifiers.

**Response:**
```json
[
  {
    "id": 1,
    "name": "Example Verifier",
    "did": "did:key:verifier...",
    "url": "https://verifier.example.com"
  }
]
```

---

### Proxy

#### POST /proxy

Proxy a request to an external service.

**Request:**
```json
{
  "url": "https://external-api.example.com/endpoint",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": {...}
}
```

**Response:**
```json
{
  "status": 200,
  "headers": {...},
  "body": {...}
}
```

---

## Error Responses

All endpoints may return error responses in the following format:

```json
{
  "error": "Error message description"
}
```

### Common HTTP Status Codes

- `200 OK` - Success
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Missing or invalid authentication
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource already exists
- `500 Internal Server Error` - Server error
- `501 Not Implemented` - Feature not yet implemented

---

## Rate Limiting

TODO: Rate limiting is not yet implemented.

When implemented, rate limit information will be included in headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1702468800
```

---

## Versioning

The API does not currently use versioning. When versioning is introduced, it will use URL path versioning:

```
/v1/storage/vc
/v2/storage/vc
```

---

## WebSocket API

TODO: WebSocket support for client-side keystores is not yet implemented.

When implemented, the WebSocket endpoint will be:

```
ws://localhost:8080/ws
```

### Message Format

```json
{
  "message_id": "unique-id",
  "action": "sign_presentation",
  "payload": {...}
}
```
