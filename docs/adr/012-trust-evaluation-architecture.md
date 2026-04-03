# ADR-012: Trust Evaluation Architecture Across Transports

## Status

Accepted

## Context

The wallet supports multiple transport mechanisms for credential issuance (OID4VCI) 
and presentation (OID4VP) flows:

1. **Engine/WebSocket**: Server-side orchestration with persistent connections
2. **HTTP Proxy**: Frontend orchestration via `/proxy` endpoint
3. **Direct**: Frontend makes direct CORS requests (future)

All trust evaluation MUST be delegated to AuthZEN via frontend calls to `/v1/evaluate`.
There must never be local trust evaluation in the frontend or backend outside of the
AuthZEN integration. This ensures a single, consistent trust evaluation path regardless
of the transport mechanism.

## Decision

### Unified Trust Evaluation via Frontend

All three transports use the same trust evaluation path:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    UNIFIED TRUST EVALUATION ARCHITECTURE                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Frontend                                         Backend                    │
│  ────────                                         ───────                    │
│     │                                                │                       │
│     │──── POST /v1/evaluate ────────────────────────▶│                       │
│     │     {                                          │                       │
│     │       subject: { type, id },                   │──▶ AuthZEN PDP        │
│     │       resource: { type, key },                 │                       │
│     │       action: { name: "evaluate" }             │                       │
│     │     }                                          │                       │
│     │                                                │                       │
│     │◀─── { decision: true/false, context: {...} } ──│                       │
│     │                                                │                       │
│  [BLOCK IF decision=false]                           │                       │
│     │                                                │                       │
│     │──── Protocol operations (varies by transport)  │                       │
│     │                                                │                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Transport-Specific Flows

#### Engine/WebSocket Transport

The engine extracts key material and sends it to the frontend for evaluation:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ENGINE/WEBSOCKET TRANSPORT                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Frontend                           Backend (Engine)                         │
│  ────────                           ────────────────                         │
│     │                                    │                                   │
│     │──── WS: flow_start (offer/req) ───▶│                                   │
│     │                                    │                                   │
│     │                              ┌─────┴─────┐                            │
│     │                              │ Parse     │                            │
│     │                              │ Request   │                            │
│     │                              │ Extract   │                            │
│     │                              │ Key Mat.  │                            │
│     │                              └─────┬─────┘                            │
│     │                                    │                                   │
│     │◀─ WS: flow_progress ───────────────│                                   │
│     │   step: evaluating_trust           │                                   │
│     │   trust_evaluation_required: true  │                                   │
│     │   request: {                       │                                   │
│     │     subject_id, subject_type,      │                                   │
│     │     key_material, context          │                                   │
│     │   }                                │                                   │
│     │                                    │                                   │
│  ┌──┴──┐                                 │                                   │
│  │ POST /v1/evaluate ───────────────────▶│──▶ AuthZEN PDP                   │
│  │◀─── decision ────────────────────────│                                   │
│  └──┬──┘                                 │                                   │
│     │                                    │                                   │
│     │──── WS: flow_action ──────────────▶│                                   │
│     │     action: trust_result           │                                   │
│     │     { trusted, name, logo, ... }   │                                   │
│     │                                    │                                   │
│     │                         [BLOCK IF !trusted]                           │
│     │                                    │                                   │
│     │◀─── WS: flow continues... ─────────│                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Implementation**: 

- Engine sends `TrustEvaluationRequest` via `flow_progress` with `trust_evaluation_required: true`
- Frontend calls POST `/v1/evaluate` with the request data
- Frontend sends `flow_action` with `action: trust_result` containing `TrustResultPayload`
- Engine continues or aborts based on the trusted flag

#### HTTP Proxy Transport

Trust is evaluated **before** protocol operations:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    HTTP PROXY TRANSPORT                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Frontend                                         Backend                    │
│  ────────                                         ───────                    │
│     │                                                │                       │
│     │──── POST /v1/evaluate ────────────────────────▶│                       │
│     │     (trust check before protocol)              │──▶ AuthZEN PDP        │
│     │◀─── { decision: true/false, ... } ────────────│                       │
│     │                                                │                       │
│  [BLOCK IF !trusted - show error, abort flow]        │                       │
│     │                                                │                       │
│     │──── POST /proxy (protocol requests) ──────────▶│                       │
│     │◀─── { response } ─────────────────────────────│                       │
│     │                                                │                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Implementation**:

- `TrustEvaluator.ts`: `createTrustEvaluator()` and `createIssuerTrustEvaluator()`
- `OpenID4VPServerAPI.ts`: Calls `evaluateTrust()` before proceeding
- `OpenID4VCI.ts`: Calls `evaluateIssuerTrust()` in `handleCredentialOffer()`

#### Direct Transport

Identical to HTTP Proxy, but protocol requests go directly to external parties:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DIRECT TRANSPORT                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Frontend                                  Backend       External            │
│  ────────                                  ───────       ────────            │
│     │                                         │             │                │
│     │──── POST /v1/evaluate ─────────────────▶│             │                │
│     │                                         │──▶ AuthZEN  │                │
│     │◀─── { decision: true/false } ───────────│             │                │
│     │                                         │             │                │
│  [BLOCK IF !trusted]                          │             │                │
│     │                                         │             │                │
│     │──── Direct HTTPS request ─────────────────────────────▶│              │
│     │     (bypasses backend entirely)         │             │                │
│     │◀─── Response ─────────────────────────────────────────│                │
│     │                                         │             │                │
│  Note: Backend never sees protocol traffic in Direct mode   │                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### DID Resolution Flow

For DID-based client_id schemes (e.g., `did:web`), the frontend must first resolve
the DID document to obtain the verifier's public keys before evaluating trust:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DID RESOLUTION FLOW (client_id_scheme=did)                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Engine                  Frontend                         Backend            │
│  ──────                  ────────                         ───────            │
│     │                        │                               │               │
│     │──── flow_progress ────▶│                               │               │
│     │     requires_resolution: true                          │               │
│     │     request_jwt: "eyJ..."                              │               │
│     │     subject_id: "did:web:verifier.example.com"         │               │
│     │                        │                               │               │
│     │                 ┌──────┴──────┐                        │               │
│     │                 │ 1. Resolve  │                        │               │
│     │                 └──────┬──────┘                        │               │
│     │                        │                               │               │
│     │                        │──── POST /v1/resolve ────────▶│               │
│     │                        │     { subject_id: "did:..." } │──▶ PDP        │
│     │                        │                               │               │
│     │                        │◀─── { keys: [...], ... } ─────│               │
│     │                        │                               │               │
│     │                 ┌──────┴──────┐                        │               │
│     │                 │ 2. Verify   │                        │               │
│     │                 │ JWT with    │                        │               │
│     │                 │ resolved    │                        │               │
│     │                 │ keys        │                        │               │
│     │                 └──────┬──────┘                        │               │
│     │                        │                               │               │
│     │                        │──── POST /v1/evaluate ───────▶│               │
│     │                        │     { keys: [...], ... }      │──▶ PDP        │
│     │                        │                               │               │
│     │                        │◀─── { decision, context } ────│               │
│     │                        │                               │               │
│     │◀─── flow_action ───────│                               │               │
│     │     action: trust_result                               │               │
│     │     { trusted, name, framework: "did" }                │               │
│     │                        │                               │               │
└─────────────────────────────────────────────────────────────────────────────┘
```

The engine sends `TrustEvaluationRequest` with:
- `requires_resolution: true` - indicates frontend must resolve DID
- `request_jwt` - the signed request JWT for frontend to verify
- `subject_id` - the DID to resolve

Frontend flow:
1. Call `POST /v1/resolve` with the DID to get the DID document
2. Extract verification methods (public keys) from the response
3. Verify the `request_jwt` signature using the resolved keys
4. Call `POST /v1/evaluate` with the resolved keys for trust policy check
5. Return `trust_result` action with the trust decision

This ensures that:
- DID document resolution is performed via AuthZEN (consistent with all trust operations)
- JWT signature is verified against keys bound to the DID
- Trust policies can be applied to DID-identified verifiers

### AuthZEN Proxy Configuration

The `/v1/evaluate` and `/v1/resolve` endpoints are configured via:

```yaml
authzen_proxy:
  enabled: true
  pdp_url: "https://trust.example.com"  # Default PDP
  rules_file: "/etc/wallet/spocp-rules.conf"
  timeout: 30

trust:
  pdp_url: "https://trust.example.com"  # Fallback if authzen_proxy.pdp_url not set
  issuer_pdp_url: ""  # Per-flow override for issuers
  verifier_pdp_url: ""  # Per-flow override for verifiers
```

### SPOCP Authorization

All `/v1/evaluate` and `/v1/resolve` queries are authorized via SPOCP rules:

```lisp
; Allow trust evaluation for credential issuers
(authzen
  (tenant *)
  (action evaluate)
  (resource (type credential_issuer) (id *))
  (subject (type urn:authzen:user) (id *)))

; Allow trust evaluation for credential verifiers  
(authzen
  (tenant *)
  (action evaluate)
  (resource (type credential_verifier) (id *))
  (subject (type urn:authzen:user) (id *)))

; Allow DID resolution for client_id_scheme=did
(authzen
  (tenant *)
  (resource (type resolution) (id *))
  (subject (type key) (id *)))
```

### Trust Evaluation Flow

All transports use the same AuthZEN request format via `/v1/evaluate`:

```json
{
  "subject": {
    "type": "urn:authzen:user",
    "id": "<user_id>"
  },
  "action": {
    "name": "evaluate"
  },
  "resource": {
    "type": "credential_issuer|credential_verifier",
    "id": "https://issuer.example.com|did:web:verifier.example.com",
    "key": [
      { "kty": "EC", "crv": "P-256", ... }
    ]
  }
}
```

The PDP returns:
```json
{
  "decision": true,
  "context": {
    "trust_framework": "openid_federation|etsi_tsl|did",
    "name": "Example Issuer",
    "logo": "https://example.com/logo.png"
  }
}
```

### Engine WebSocket Protocol Messages

For the engine transport, trust evaluation uses these message types:

**Server → Client (trust request with key material - x509_san_dns scheme):**
```json
{
  "type": "flow_progress",
  "flow_id": "...",
  "step": "evaluating_trust",
  "payload": {
    "trust_evaluation_required": true,
    "request": {
      "subject_id": "verifier.example.com",
      "subject_type": "credential_verifier",
      "key_material": {
        "type": "x5c",
        "x5c": ["MIIB..."]
      },
      "context": {
        "client_id_scheme": "x509_san_dns",
        "response_uri": "https://verifier.example.com/callback"
      }
    }
  }
}
```

**Server → Client (trust request with DID resolution - did scheme):**
```json
{
  "type": "flow_progress",
  "flow_id": "...",
  "step": "evaluating_trust",
  "payload": {
    "trust_evaluation_required": true,
    "request": {
      "subject_id": "did:web:verifier.example.com",
      "subject_type": "credential_verifier",
      "requires_resolution": true,
      "request_jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ...",
      "context": {
        "client_id_scheme": "did",
        "response_uri": "https://verifier.example.com/callback"
      }
    }
  }
}
```

For DID schemes, the frontend must:
1. Call `/v1/resolve` with `subject_id` to get the DID document
2. Verify `request_jwt` signature using resolved keys
3. Call `/v1/evaluate` with the verified keys
4. Return the trust result

**Client → Server (trust result):**
```json
{
  "type": "flow_action",
  "flow_id": "...",
  "action": "trust_result",
  "payload": {
    "trusted": true,
    "name": "Example Verifier",
    "logo": "https://verifier.example.com/logo.png",
    "framework": "did",
    "reason": ""
  }
}
```

## Consequences

### Positive

- **Unified trust path**: All transports use the same /v1/evaluate endpoint
- **Consistent behavior**: Trust decisions are identical regardless of transport
- **Centralized policy**: Trust policies managed in PDP, not scattered in code
- **Audit trail**: All trust decisions logged at single PDP endpoint
- **Flexibility**: PDP can implement complex trust logic (TSLs, Federation, DIDs)
- **Frontend control**: User sees trust decisions before any protocol operations

### Negative

- **Latency**: Extra round-trip for WebSocket transport (server → client → server)
- **Dependency**: PDP availability is critical for all protocol flows
- **Complexity**: Engine must now wait for async trust evaluation from frontend

### Mitigations

- Cache trust decisions with short TTL (5 minutes)
- PDP health checks with graceful degradation
- Frontend trust evaluation is part of protocol libraries (wallet-common)

## Security Considerations

### Fail-Closed Design

The trust evaluation system follows fail-closed principles:

1. **No PDP configured**: Returns `trusted: false` - operations are blocked
2. **SPOCP authorizer fails in production**: Server refuses to start
3. **NoOpAuthorizer**: Cannot be used in production (GIN_MODE=release)

### Concurrent Flow Limit

Each WebSocket session is limited to `MaxPendingFlowsPerSession` (default: 3) concurrent
pending flows to prevent DoS attacks. Attempting to start additional flows returns
`TOO_MANY_REQUESTS` error. The flow limit check is performed atomically under a write
lock to prevent race conditions.

### Per-Step Timeouts

Trust evaluation uses separate, shorter timeouts than user interaction steps:

| Operation | Timeout | Constant |
|-----------|---------|----------|
| Trust evaluation (including DID resolution) | 2 minutes | `TrustEvaluationTimeout` |
| User interaction (consent, selection) | 5 minutes | `UserInteractionTimeout` |

This prevents DID resolution or PDP failures from hanging for the full 5-minute
user interaction timeout.

### DID Resolution Error Handling

For DID-based client_id schemes (`client_id_scheme=did`), the frontend must:

1. Receive `TrustEvaluationRequest` with `requires_resolution: true` and `request_jwt`
2. Call `POST /v1/resolve` with the DID to get the DID document
3. Verify `request_jwt` signature using resolved keys
4. Call `POST /v1/evaluate` with the resolved key material
5. Return `trust_result` action within `TrustEvaluationTimeout`

**Error cases handled by the backend:**
- `TrustEvaluationRequest` validation fails → Flow rejected with error
- `RequestJWT` empty when `RequiresResolution=true` → Validation error
- Frontend doesn't respond within 2 minutes → `ErrFlowTimeout`
- Trust result validation fails → Flow rejected with error

**Important**: The backend validates that `RequestJWT` is present when
`RequiresResolution=true`. Issuers with DID-based identifiers do not require
a signed request JWT (issuance is initiated by the issuer).

### Input Validation

The backend validates all trust evaluation messages:

**TrustEvaluationRequest validation:**
- `SubjectID` must be non-empty
- `SubjectType` must be `credential_issuer` or `credential_verifier`
- `RequestJWT` required when `RequiresResolution=true` (for verifiers)
- `KeyMaterial.Type` must be `x5c` or `jwk` (if provided)

**TrustResultPayload validation:**
- All trust results are validated before use
- Missing `trusted` field defaults to `false` (fail-closed)
- Results are audit logged for security traceability

### Trust Result Binding (Future Enhancement)

**Current state**: The backend trusts the frontend's trust evaluation result via
WebSocket `flow_action`. A compromised frontend could falsify trust decisions.

**Planned enhancement**: The `/v1/evaluate` proxy will sign its responses with a
backend-held key, allowing the engine to verify trust results are authentic:

```
Frontend → POST /v1/evaluate → Backend Proxy → External PDP
                                     ↓
                              Sign response with backend key
                                     ↓
Frontend receives signed JWT ← { decision_token: "eyJ..." }
                                     ↓
Frontend returns signed token via WebSocket flow_action
                                     ↓
                              Backend verifies its own signature
                              Confirms decision bound to request
```

The signed decision token will include:
- `decision`: true/false
- `subject`: The evaluated subject (e.g., issuer/verifier ID)
- `resource_hash`: SHA-256 hash of the key material
- `nonce`: Correlation ID from the original request
- `iat`/`exp`: Timestamps for freshness validation

This ensures:
- Frontend cannot forge trust decisions
- Decision is bound to specific request (via nonce + resource_hash)
- Token is short-lived (60 seconds)

### SAN DNS Validation

For `x509_san_dns` client_id_scheme, the PDP is responsible for validating that
the certificate's SAN DNS names match the `client_id`. The backend extracts
key material but delegates all policy decisions to the PDP.

## Related

- ADR-003: AuthZEN Integration
- ADR-010: Trust Service Architecture
- ADR-011: Multi-Tenancy
