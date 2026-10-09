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

#### POST /user/register and POST /user/login

Removed. Password authentication no longer exists; both endpoints return
HTTP 410 Gone. Use the WebAuthn endpoints below.

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

### Token Status Lists

#### POST /status/v1/lists

Fetches, verifies and trust-evaluates one or more IETF Token Status Lists
([draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/))
on behalf of the client and returns them. Clients (web frontend, Kotlin SDK,
Swift SDK) call this **in the background** to learn whether their credentials
were revoked or suspended. **The wallet engine does not check status when you
present**; see [ADR-013](adr/013-status-checking-outside-the-engine.md).

The client **trusts the backend's verification** and reads its own credential's
entry from the returned list **locally**. The backend never learns which
credential, or which index, a client is interested in, only which list.

Authenticated callers only (`Authorization: Bearer <token>`, audience
`wallet-backend`, `tac` containing `r` when go-tokenauth is enforced); anonymous
tokens are rejected. Rate limited per user (falling back to the tenant), see
`status_check.rate_limit`. OpenAPI: [openapi-status.yaml](openapi-status.yaml).

**Request:**
```json
{
  "lists": [
    { "uri": "https://status.example.org/statuslists/7", "etag": "\"1f2e3d4c5b6a79881f2e3d4c5b6a7988\"" }
  ]
}
```

- `lists`: 1 to `status_check.max_lists_per_request` items (default 20). Over
  the cap: `400 TOO_MANY_URIS`. **Clients should send one to three per request**
  (see Privacy); the server only enforces the cap.
- `uri`: the exact `status.status_list.uri` string of the credential, `https`
  only. A repeated `uri` is collapsed: one result per distinct `uri`, in first-
  occurrence order. A `uri` that is not an acceptable `https` URI gets a result
  with `reason: "uri_not_allowed"` rather than failing the request.
- `etag` (optional): the `etag` of the version the client already holds.

**Response `200`** (partial failure is still `200`; every item stands alone):
```json
{
  "results": [
    {
      "uri": "https://status.example.org/statuslists/7",
      "state": "verified",
      "bits": 2,
      "lst": "eNrbuRgAAhcBXQ",
      "iat": 1790000000,
      "exp": 1790086400,
      "ttl": 900,
      "expires_at": 1790000900,
      "etag": "\"1f2e3d4c5b6a79881f2e3d4c5b6a7988\"",
      "signer_trust": "status-list-signer"
    },
    { "uri": "https://other.example/l/1", "state": "undetermined", "reason": "signer_untrusted" },
    { "uri": "https://third.example/l/9", "state": "not_modified", "etag": "\"...\"", "expires_at": 1790000900, "signer_trust": "status-list-signer" }
  ]
}
```

| Field | Meaning |
|---|---|
| `state` | `verified`, `undetermined` or `not_modified`. **There is no "valid" state**: the response is about the *list*, never a verdict on a credential. |
| `reason` | Only with `undetermined`: `fetch_failed`, `unsupported_media_type`, `signature_invalid`, `signer_untrusted`, `trust_unavailable`, `no_signer_key`, `expired`, `not_yet_valid`, `malformed`, `too_large`, `budget_exhausted`, `list_too_small`, `uri_not_allowed`. |
| `bits` | Bits per entry: 1, 2, 4 or 8. |
| `lst` | base64url (no padding) of the zlib-compressed bit string, **byte-identical to the `lst` of the signed token** (not re-encoded). At most `status_check.max_list_bytes` (default 2 MiB) compressed; a larger list is `undetermined`/`too_large`, never truncated. |
| `iat`, `exp`, `ttl` | The token's claims (unix seconds / seconds); `exp` and `ttl` only when the token has them. |
| `expires_at` | Unix time until which the backend treats this version as fresh (bounded by the token's `ttl`/`exp`, by the list host's `Cache-Control: max-age` and by one hour). Refresh before it. |
| `etag` | Quoted opaque version id: a stable hash of the list URI and the token version, identical for every caller and across refetches of an unchanged token. Send it back as `etag` to get `not_modified` instead of the list. |
| `signer_trust` | The trust action that accepted the signer: `status-list-signer`, or `credential-issuer` when the go-trust fallback applied. |

A list is `verified` only if the backend fetched it, verified its signature
(JWT `x5c`/`jwk`, or CWT `x5chain`), `typ`, `sub` (equal to the `uri`) and
`iat`/`nbf`/`exp`/`ttl`, and the signer key was accepted by go-trust for the
tenant (`status-list-signer`, see [ADR-012](adr/012-trust-evaluation-architecture.md)).
Anything else, including no trust service being configured, is `undetermined`.

When the list host supports it the backend refetches with `If-None-Match`; a
`304` refreshes its cache (the signer trust decision and the token's `exp` are
re-checked first).

**Response headers:** `Cache-Control: private, max-age=<n>` with `n` the
shortest remaining freshness over the returned lists, limited by each list's
`ttl`; `Cache-Control: private, no-store` when any item is `undetermined`;
`ETag` (the list's `etag`) for a single-list response; `Vary: Authorization`.
The `no-cache` headers of the other authenticated routes are deliberately not
applied.

**Errors** (JSON `{"error": CODE, "message": ...}`):

| Status | `error` | When |
|---|---|---|
| 400 | `INVALID_REQUEST` | not a JSON object, no `lists`, an item without `uri`, an over-long `etag`, trailing data |
| 400 | `TOO_MANY_URIS` | more than `status_check.max_lists_per_request` items (response includes `max`) |
| 401 | | missing/invalid token |
| 403 | | token not for audience `wallet-backend`, or lacking `r` |
| 413 | `REQUEST_TOO_LARGE` | body over 128 KiB |
| 429 | `RATE_LIMIT_EXCEEDED` | rate limit; `Retry-After` is set |
| 503 | `STATUS_NOT_SUPPORTED` | `status_check.enabled` is false |

The whole request has a deadline (`status_check.request_timeout_seconds`,
default 8 s, at most 12 s, below the 15 s server write timeout); lists not
finished then are `undetermined`/`budget_exhausted`.

##### Reading a credential's entry (client side)

For a credential with `status.status_list = {idx, uri}`:

1. Decode `lst` from base64url and zlib-inflate it (inflate at most 32 MiB).
2. With `bits` = 1, 2, 4 or 8: `byte = idx * bits / 8` (integer division),
   `shift = (idx * bits) % 8`, `value = (list[byte] >> shift) & ((1 << bits) - 1)`.
   Bits are packed **least significant bit first** within a byte. An `idx` past
   `len(list) * 8 / bits` is an error, not VALID.
3. `value` 0 is VALID, 1 is INVALID (revoked), 2 is SUSPENDED; any other value is
   application specific and **must be treated as not valid**.

**Fail-closed rule:** only `state` `verified` (or `not_modified`, which refers to
a version the client already verified through this API) with an in-range index
and `value` 0 may be shown as valid. `undetermined`, an HTTP/transport error, a
timeout or a malformed answer means **unknown**: show it as unknown, never as
valid, and keep the last confirmed state (do not downgrade a credential to
"revoked" on `undetermined` either: it says nothing about the credential).

##### Recommended client behaviour

- Check in the **background**, never as part of a presentation and never
  blocking one: a presentation must work offline and without this API.
- **One list per request** (at most three). Requesting several lists in one
  call lets the server see which issuers a user's credentials come from
  together; one at a time keeps the call about a single list.
- **Refresh at a randomized time within the `expires_at` window** (for example
  uniformly between 50% and 90% of the time remaining), not on a fixed schedule
  and not at app start for every credential at once. Send the stored `etag`.
- Back off on `429`/`503`/`undetermined`; honour `Retry-After`.
- Do not request lists for credentials that carry no `status.status_list`.

##### Privacy properties

The list URIs a user asks for reveal which issuers and credential types the
user holds, so the backend is built not to learn or keep that:

- The request is a `POST` body: URIs are not in URLs or access logs.
- URIs are **never logged**, at any level, alone or with a user or subject
  identifier. The service logs counts, outcomes and durations only, and
  errors that may contain a URI are never logged. The go-trust evaluation of the
  signer is redacted the same way.
- **No audit events** are emitted for status lists, and nothing is stored per
  user about which lists were requested.
- The service is handed the tenant, **not the user**; the rate limiter keeps
  a counter per caller, never what was asked.
- The only state is an in-process cache keyed by tenant and URI that holds
  public data (the signed list and its metadata); it cannot say who asked.
- The backend does not learn the credential or the index: clients compute the
  entry locally from the returned list.

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
