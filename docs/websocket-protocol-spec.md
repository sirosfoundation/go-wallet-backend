# Wallet Protocol Channel Specification

**Version**: 0.1.0 (Draft)  
**Status**: Design Discussion  
**Date**: 2026-02-18

## Overview

This specification defines a unified WebSocket protocol channel for wallet operations,
replacing the combination of REST APIs and generic HTTP proxy with a single, protocol-aware
communication channel.

### Goals

1. **Eliminate open proxy** - No arbitrary URL fetching; only protocol-defined operations
2. **Integrated signing** - Client-side key operations seamlessly integrated with protocol flows
3. **Streaming progress** - Real-time status updates for long-running operations
4. **Deferred operations** - Server-initiated push for async credential delivery
5. **Single security model** - One authenticated channel for all operations

### Non-Goals (Deferred)

- End-to-end encryption of credential content (future enhancement)
- Multi-device synchronization
- Offline operation queuing

## Architecture Overview

### Deployment Model

The WebSocket endpoint is served by the **engine** mode of the wallet backend
hybrid binary. The engine can be deployed in multiple configurations:

| Mode | Description | Privacy |
|------|-------------|---------|
| Embedded (`--mode=all`) | Single binary, development use | Backend sees all flows |
| Cloud Engine | Separate container/pod | Backend sees all flows |
| Local Engine | Native app embeds engine | Cloud sees nothing |

See `proxy-elimination-plan.md` for full deployment architecture.

### Privacy Properties

**Key principle**: The engine is designed to minimize data exposure:

1. **Keys never leave client** - Signing happens locally via `sign_request`/`sign_response`
2. **Client-side credential matching** - Engine sends `presentation_definition`, client
   matches locally and returns only selected credentials
3. **Engine sees credentials one-at-a-time** - During signing, not full inventory
4. **Storage is separate** - Encrypted blobs go client → storage service directly
5. **Local engine option** - Native apps can run engine locally; cloud never sees flows

### Data Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           ENGINE DATA VISIBILITY                             │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Engine SEES:                        Engine DOES NOT SEE:                    │
│  ─────────────                       ────────────────────                    │
│  • Flow type (OID4VCI, OID4VP)       • Full credential inventory             │
│  • Issuer/verifier being contacted   • Credential content (only during sign) │
│  • Presentation definition           • Private keys                          │
│  • One credential at signing time    • Decrypted credential store            │
│  • Trust evaluation results          • User password/biometrics              │
│                                                                              │
│  Mitigations:                                                                │
│  ────────────                                                                │
│  • Client does credential matching locally                                   │
│  • Local engine mode eliminates cloud visibility                             │
│  • Minimal logging (no credential content, no nonces)                        │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Connection Lifecycle

### Endpoint

```
wss://{backend}/api/v2/wallet
```

### Authentication

Connection is authenticated via JWT token in the initial handshake message:

```
Client → Server:
{
  "type": "handshake",
  "app_token": "<JWT from login/registration>"
}
```

The server validates the JWT and responds:

```
Server → Client (success):
{
  "type": "handshake_complete",
  "session_id": "<uuid>",
  "capabilities": ["oid4vci", "oid4vp", "vctm"]
}

Server → Client (failure):
{
  "type": "error",
  "code": "AUTH_FAILED",
  "message": "Invalid or expired token"
}
```

### Keepalive

Clients SHOULD send ping frames every 30 seconds. Servers MUST respond with pong.
Connections idle for >60 seconds without ping/pong MAY be terminated.

### Reconnection

On unexpected disconnect:
1. Client reconnects with same `app_token`
2. In-flight flows are abandoned (client must restart)
3. Deferred credentials pending delivery are re-queued

## Message Format

All messages are JSON objects with a common envelope:

```typescript
interface Message {
  // Message type - determines interpretation of payload
  type: string;
  
  // Flow identifier for multi-step operations (optional)
  flow_id?: string;
  
  // Correlation ID for request/response pairs (optional)
  message_id?: string;
  
  // Timestamp (ISO 8601, optional)
  timestamp?: string;
  
  // Type-specific payload
  [key: string]: unknown;
}
```

### Message Types

| Type | Direction | Description |
|------|-----------|-------------|
| `handshake` | C→S | Initial authentication |
| `handshake_complete` | S→C | Authentication successful |
| `flow_start` | C→S | Begin a protocol flow |
| `flow_progress` | S→C | Status update during flow |
| `flow_complete` | S→C | Flow finished successfully |
| `flow_error` | S→C | Flow failed |
| `flow_action` | C→S | Client action during flow |
| `sign_request` | S→C | Server requests signature |
| `sign_response` | C→S | Client provides signature |
| `push` | S→C | Server-initiated notification |
| `error` | S→C | Protocol-level error |

## Protocol Flows

### OpenID4VCI Credential Issuance

#### Starting the Flow

Client initiates with scanned offer or deeplink:

```
Client → Server:
{
  "type": "flow_start",
  "flow_id": "<client-generated-uuid>",
  "protocol": "oid4vci",
  "offer": "openid-credential-offer://..."
}
```

Alternative for `credential_offer_uri`:

```
Client → Server:
{
  "type": "flow_start",
  "flow_id": "<uuid>",
  "protocol": "oid4vci",
  "credential_offer_uri": "https://issuer.example.com/offers/abc123"
}
```

#### Flow Progression

Server executes the protocol, sending progress updates:

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "parsing_offer",
  "message": "Parsing credential offer"
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "offer_parsed",
  "offer": {
    "credential_issuer": "https://issuer.example.com",
    "credential_configuration_ids": ["UniversityDegree_jwt_vc_json"],
    "grants": {
      "authorization_code": { "issuer_state": "..." }
    }
  }
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "fetching_metadata",
  "message": "Fetching issuer metadata"
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "metadata_fetched",
  "issuer_metadata": {
    "credential_issuer": "https://issuer.example.com",
    "credential_endpoint": "https://issuer.example.com/credential",
    "display": [{
      "name": "Example University",
      "logo": { "uri": "data:image/png;base64,..." }  // Embedded
    }],
    "credential_configurations_supported": { ... }
  }
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "evaluating_trust",
  "message": "Evaluating issuer trust"
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "trust_evaluated",
  "trust": {
    "trusted": true,
    "framework": "eudi",
    "reason": "Issuer certificate chains to EUDI root",
    "certificates": ["-----BEGIN CERTIFICATE-----..."]
  }
}
```

#### User Selection

Flow pauses for user to select credential configuration:

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "awaiting_selection",
  "available_credentials": [
    {
      "id": "UniversityDegree_jwt_vc_json",
      "display": { "name": "University Degree", ... },
      "format": "jwt_vc_json",
      "vct": "https://example.com/credentials/degree"
    }
  ]
}
```

Client responds:

```
Client → Server:
{
  "type": "flow_action",
  "flow_id": "<uuid>",
  "action": "select_credential",
  "credential_configuration_id": "UniversityDegree_jwt_vc_json"
}
```

#### Authorization

If authorization is required:

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "authorization_required",
  "authorization_url": "https://auth.example.com/authorize?...",
  "expected_redirect_uri": "https://wallet.example.com/callback"
}
```

Client opens browser/popup, user completes authorization, then:

```
Client → Server:
{
  "type": "flow_action",
  "flow_id": "<uuid>",
  "action": "authorization_complete",
  "code": "abc123",
  "state": "xyz789"
}
```

For pre-authorized flows:

```
Client → Server:
{
  "type": "flow_action",
  "flow_id": "<uuid>",
  "action": "provide_pin",
  "tx_code": "123456"
}
```

#### Token Exchange

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "exchanging_token",
  "message": "Exchanging authorization code for token"
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "token_obtained"
}
```

#### Proof Generation (Signing)

Server requests client to generate proof:

```
Server → Client:
{
  "type": "sign_request",
  "flow_id": "<uuid>",
  "message_id": "<uuid>",
  "action": "generate_proof",
  "params": {
    "audience": "https://issuer.example.com",
    "nonce": "n-0S6_WzA2Mj",
    "proof_type": "jwt"
  }
}
```

Client generates proof using local key and returns:

```
Client → Server:
{
  "type": "sign_response",
  "flow_id": "<uuid>",
  "message_id": "<uuid>",
  "proof_jwt": "eyJ..."
}
```

#### Credential Request

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "requesting_credential",
  "message": "Requesting credential from issuer"
}
```

#### Flow Completion

Immediate issuance:

```
Server → Client:
{
  "type": "flow_complete",
  "flow_id": "<uuid>",
  "credentials": [
    {
      "format": "jwt_vc_json",
      "credential": "eyJ...",
      "vct": "https://example.com/credentials/degree",
      "type_metadata": { ... }  // From VCTM registry, with embedded images
    }
  ]
}
```

Deferred issuance:

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "deferred",
  "transaction_id": "tx-123",
  "interval": 5,
  "message": "Credential issuance is pending"
}
```

Later, server polls and pushes result:

```
Server → Client:
{
  "type": "push",
  "push_type": "credential_ready",
  "flow_id": "<uuid>",
  "credentials": [ ... ]
}
```

#### Flow Errors

```
Server → Client:
{
  "type": "flow_error",
  "flow_id": "<uuid>",
  "step": "trust_evaluated",
  "error": {
    "code": "UNTRUSTED_ISSUER",
    "message": "Issuer is not trusted by any configured trust framework",
    "details": {
      "issuer": "https://malicious.example.com",
      "reason": "No valid certificate chain found"
    }
  }
}
```

### OpenID4VP Credential Presentation

#### Starting the Flow

```
Client → Server:
{
  "type": "flow_start",
  "flow_id": "<uuid>",
  "protocol": "oid4vp",
  "request_uri": "openid4vp://authorize?..."
}
```

Or with `request_uri` that needs fetching:

```
Client → Server:
{
  "type": "flow_start",
  "flow_id": "<uuid>",
  "protocol": "oid4vp",
  "request_uri_ref": "https://verifier.example.com/requests/456"
}
```

#### Request Processing

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "parsing_request"
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "evaluating_verifier_trust",
  "verifier": "https://verifier.example.com"
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "request_parsed",
  "verifier": {
    "name": "Example Verifier",
    "logo": { "uri": "data:image/png;base64,..." },
    "trusted": true,
    "framework": "eudi"
  },
  "presentation_definition": { ... },
  "requested_claims": [
    { "path": "$.given_name", "required": true },
    { "path": "$.family_name", "required": true },
    { "path": "$.birthdate", "required": false }
  ]
}
```

#### Client-Side Credential Matching (Privacy-Preserving)

**Important**: The engine does NOT have access to the user's credential store.
Credential matching happens client-side to preserve privacy. The engine only
sees credentials one-at-a-time during the signing step.

Server sends the presentation_definition to client for local matching:

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "match_credentials",
  "presentation_definition": {
    "id": "example_presentation",
    "input_descriptors": [
      {
        "id": "id_card",
        "format": { "vc+sd-jwt": {} },
        "constraints": {
          "fields": [
            { "path": ["$.given_name"], "filter": {} },
            { "path": ["$.family_name"], "filter": {} }
          ]
        }
      }
    ]
  }
}
```

Client performs matching locally against its encrypted credential store, then
responds with matched credentials (without revealing the full inventory):

```
Client → Server:
{
  "type": "flow_action",
  "flow_id": "<uuid>",
  "action": "credentials_matched",
  "matches": [
    {
      "input_descriptor_id": "id_card",
      "credential_id": "local-cred-id-1",
      "format": "vc+sd-jwt",
      "vct": "https://example.com/id-card",
      "available_claims": ["given_name", "family_name", "birthdate"]
    }
  ]
}
```

If no credentials match:

```
Client → Server:
{
  "type": "flow_action",
  "flow_id": "<uuid>",
  "action": "credentials_matched",
  "matches": [],
  "no_match_reason": "no_qualifying_credentials"
}
```

#### User Consent

Server prompts for user consent with the matched credentials:

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "awaiting_consent",
  "matched_credentials": [
    {
      "input_descriptor_id": "id_card",
      "credential_id": "local-cred-id-1",
      "credential_display": { "name": "ID Card", ... },  // From VCTM
      "disclosable_claims": ["given_name", "family_name", "birthdate"],
      "required_claims": ["given_name", "family_name"]
    }
  ],
  "verifier": {
    "name": "Example Verifier",
    "trusted": true
  }
}
```

Client responds after user consent:

```
Client → Server:
{
  "type": "flow_action",
  "flow_id": "<uuid>",
  "action": "consent",
  "selected_credentials": [
    {
      "credential_id": "local-cred-id-1",
      "disclosed_claims": ["given_name", "family_name"]  // User deselected birthdate
    }
  ]
}
```

Or user declines:

```
Client → Server:
{
  "type": "flow_action",
  "flow_id": "<uuid>",
  "action": "decline",
  "reason": "user_cancelled"
}
```

#### VP Signing

```
Server → Client:
{
  "type": "sign_request",
  "flow_id": "<uuid>",
  "message_id": "<uuid>",
  "action": "sign_presentation",
  "params": {
    "audience": "https://verifier.example.com",
    "nonce": "verifier-nonce-123",
    "credentials_to_include": [
      {
        "credential_id": "local-cred-id-1",
        "disclosed_claims": ["given_name", "family_name"]
      }
    ]
  }
}
```

```
Client → Server:
{
  "type": "sign_response",
  "flow_id": "<uuid>",
  "message_id": "<uuid>",
  "vp_token": "eyJ..."
}
```

#### Response Submission

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "submitting_response"
}
```

```
Server → Client:
{
  "type": "flow_complete",
  "flow_id": "<uuid>",
  "redirect_uri": "https://verifier.example.com/done?session=abc"
}
```

### VCTM Registry Lookup

Simple synchronous lookup (doesn't require full flow):

```
Client → Server:
{
  "type": "flow_start",
  "flow_id": "<uuid>",
  "protocol": "vctm",
  "vct": "https://example.com/credentials/degree"
}
```

```
Server → Client:
{
  "type": "flow_complete",
  "flow_id": "<uuid>",
  "type_metadata": {
    "vct": "https://example.com/credentials/degree",
    "name": "University Degree",
    "display": [...],  // Images embedded as data: URIs
    "claims": [...]
  }
}
```

## Error Codes

| Code | Description |
|------|-------------|
| `AUTH_FAILED` | Invalid or expired authentication token |
| `INVALID_MESSAGE` | Malformed message |
| `UNKNOWN_FLOW` | `flow_id` not recognized |
| `FLOW_TIMEOUT` | Flow exceeded maximum duration |
| `OFFER_PARSE_ERROR` | Could not parse credential offer |
| `OFFER_FETCH_ERROR` | Could not fetch `credential_offer_uri` |
| `METADATA_FETCH_ERROR` | Could not fetch issuer/verifier metadata |
| `UNTRUSTED_ISSUER` | Issuer not trusted by any framework |
| `UNTRUSTED_VERIFIER` | Verifier not trusted by any framework |
| `AUTHORIZATION_FAILED` | OAuth authorization flow failed |
| `TOKEN_ERROR` | Token endpoint returned error |
| `CREDENTIAL_ERROR` | Credential endpoint returned error |
| `SIGN_TIMEOUT` | Client did not respond to sign request |
| `SIGN_ERROR` | Client signature was invalid |
| `PRESENTATION_ERROR` | VP creation or submission failed |
| `INTERNAL_ERROR` | Server-side error |

## Protocol Extensibility

The WebSocket protocol is designed to support multiple credential protocols beyond
OID4VCI/OID4VP. This section describes how to extend the protocol for new credential
exchange mechanisms.

### Extension Points

1. **Protocol identifier** in `flow_start`: The `protocol` field determines which
   flow logic the server executes
2. **Step vocabulary**: Each protocol defines its own progression steps
3. **Sign request actions**: New signing operations can be added
4. **Error codes**: Protocol-specific error codes with unique prefixes

### Adding a New Protocol

To add support for a new credential protocol:

1. Define a unique `protocol` identifier (e.g., `"iso18013"`, `"didcomm"`)
2. Document the flow steps and their payloads
3. Define any new `sign_request` action types
4. Add protocol-specific error codes
5. Implement server-side flow handler

### ISO 18013-5 (mDL Proximity Presentation)

ISO 18013-5 defines proximity-based credential presentation over BLE, NFC, or WiFi Aware.
This differs fundamentally from HTTP-based protocols because the data transfer happens
directly between devices.

**Role of WebSocket Channel**:

The backend cannot proxy BLE/NFC communication, but can assist with:
- Reader authentication and trust evaluation
- Session transcript preparation
- Certificate chain validation
- Device engagement QR code generation

**Proposed Flow**:

```
Client → Server:
{
  "type": "flow_start",
  "flow_id": "<uuid>",
  "protocol": "iso18013",
  "mode": "presentation",
  "transport": "ble",  // or "nfc", "wifi_aware"
  "device_engagement": "<mdoc device engagement from QR/NFC>"
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "parsing_device_engagement"
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "evaluating_reader_trust",
  "reader_certificate": "..."
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "reader_trust_evaluated",
  "reader": {
    "name": "Border Control Station 42",
    "organization": "National Border Agency",
    "trusted": true,
    "framework": "eudi",
    "permissions": ["age_over_18", "portrait", "document_number"]
  },
  "requested_elements": [
    { "namespace": "org.iso.18013.5.1", "element": "age_over_18" },
    { "namespace": "org.iso.18013.5.1", "element": "portrait" }
  ]
}
```

**Key Difference**: After trust evaluation and user consent, the actual mDL data
transfer happens device-to-device over BLE/NFC. The WebSocket channel provides:

1. **Pre-flight trust check** before user decides to engage
2. **Session key derivation assistance** (if keys are server-held)
3. **Audit logging** (optional, with user consent)

```
Client → Server:
{
  "type": "flow_action",
  "flow_id": "<uuid>",
  "action": "consent",
  "selected_elements": ["age_over_18"],
  "denied_elements": ["portrait"]
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "ready_for_transfer",
  "session_transcript": "<base64 CBOR>",
  "device_authentication": "<prepared for signing>"
}
```

```
Server → Client:
{
  "type": "sign_request",
  "flow_id": "<uuid>",
  "message_id": "<uuid>",
  "action": "sign_mdoc_device_auth",
  "params": {
    "session_transcript_hash": "<sha256>",
    "credential_id": "mdl-credential-id"
  }
}
```

After client signs and performs BLE/NFC transfer locally:

```
Client → Server:
{
  "type": "flow_action",
  "flow_id": "<uuid>",
  "action": "transfer_complete",
  "status": "success"  // or "cancelled", "error"
}
```

```
Server → Client:
{
  "type": "flow_complete",
  "flow_id": "<uuid>"
}
```

**Hybrid Mode**: For online mDOC verification (not proximity), the flow would be
similar to OID4VP, with the server handling the HTTP-based exchange.

### DIDComm 2.1

DIDComm 2.1 is an asynchronous, peer-to-peer messaging protocol used for credential
exchange and other interactions. It differs from OID4VCI/OID4VP in several ways:

- **Asynchronous**: Messages may arrive out of order, with delays
- **Peer-to-peer or mediated**: Direct or through relay/mediator nodes
- **Conversation-based**: Long-running threads with state
- **Rich protocol suite**: Trust ping, out-of-band, issue-credential, present-proof, etc.

**Role of WebSocket Channel**:

The backend can serve multiple roles:
1. **Mediator/Relay**: Route messages for clients without public endpoints
2. **Message processor**: Pack/unpack DIDComm messages, verify signatures
3. **Protocol orchestrator**: Execute DIDComm protocols (issue-credential, present-proof)

**Connection-Oriented Model**:

DIDComm naturally maps to WebSocket because both are bidirectional:

```
Client → Server:
{
  "type": "flow_start",
  "flow_id": "<uuid>",
  "protocol": "didcomm",
  "didcomm_protocol": "https://didcomm.org/issue-credential/3.0",
  "initiation": "oob",  // out-of-band invitation
  "oob_url": "https://issuer.example.com/oob/abc123"
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "resolving_oob",
  "message": "Fetching out-of-band invitation"
}
```

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "oob_resolved",
  "invitation": {
    "type": "https://didcomm.org/out-of-band/2.0/invitation",
    "from": "did:web:issuer.example.com",
    "body": {
      "goal": "Issue University Credential",
      "goal_code": "issue-vc"
    }
  },
  "peer": {
    "did": "did:web:issuer.example.com",
    "display_name": "Example University",
    "trusted": true
  }
}
```

**Bidirectional Message Flow**:

DIDComm protocols involve back-and-forth messaging. The WebSocket channel handles this:

```
Server → Client:
{
  "type": "flow_progress",
  "flow_id": "<uuid>",
  "step": "didcomm_message_received",
  "message_type": "https://didcomm.org/issue-credential/3.0/offer-credential",
  "decoded_content": {
    "credential_preview": { ... },
    "formats": [ ... ]
  }
}
```

```
Client → Server:
{
  "type": "flow_action",
  "flow_id": "<uuid>",
  "action": "accept_offer"
}
```

Server generates and sends request-credential message, waits for response...

```
Server → Client:
{
  "type": "sign_request",
  "flow_id": "<uuid>",
  "message_id": "<uuid>",
  "action": "sign_didcomm_message",
  "params": {
    "message_hash": "<sha256>",
    "recipient_did": "did:web:issuer.example.com"
  }
}
```

**Long-Running Conversations**:

DIDComm conversations can span hours or days. The WebSocket protocol handles this:

1. **Flow persists across reconnects**: Server stores conversation state
2. **Push notifications**: Server pushes when new messages arrive
3. **Thread tracking**: Messages are correlated by DIDComm `thid` (thread ID)

```
Server → Client (after reconnect):
{
  "type": "push",
  "push_type": "didcomm_message",
  "flow_id": "<uuid-from-original-flow>",
  "message": {
    "type": "https://didcomm.org/issue-credential/3.0/issue-credential",
    "credential": "..."
  }
}
```

**Mediator Role**:

The backend can act as a DIDComm mediator for the client:

```
Client → Server:
{
  "type": "flow_start",
  "flow_id": "<uuid>",
  "protocol": "didcomm",
  "didcomm_protocol": "https://didcomm.org/coordinate-mediation/3.0",
  "action": "register_as_recipient"
}
```

This enables:
- Receiving messages when client is offline (queued)
- Routable DID for the client (backend's endpoint)
- Forward secrecy via key rotation

### Protocol Comparison Matrix

| Aspect | OID4VCI | OID4VP | ISO 18013-5 | DIDComm 2.1 |
|--------|---------|--------|-------------|-------------|
| Transport | HTTP | HTTP | BLE/NFC/WiFi | HTTP/WS/custom |
| Direction | Pull | Pull | Proximity | Peer-to-peer |
| Session | Short | Short | Short | Long-running |
| Server role | Proxy | Proxy | Trust advisor | Mediator/Processor |
| Trust model | Well-known endpoints | Well-known endpoints | Certificate chains | DIDs + trust frameworks |
| Async | Deferred only | No | No | Yes, built-in |
| Signing | Proof JWT | VP JWT | Device auth | Message signatures |

### Generic Flow Handlers

To support multiple protocols cleanly, the server implements a flow handler interface:

```go
type FlowHandler interface {
    // Protocol returns the protocol identifier
    Protocol() string
    
    // Start initializes a new flow from the start message
    Start(ctx context.Context, msg FlowStartMessage) (*FlowState, error)
    
    // HandleAction processes a client action
    HandleAction(ctx context.Context, state *FlowState, action FlowActionMessage) error
    
    // HandleSignResponse processes a signature from the client
    HandleSignResponse(ctx context.Context, state *FlowState, resp SignResponse) error
    
    // Resume restores a flow from persisted state (for long-running flows)
    Resume(ctx context.Context, state *FlowState) error
    
    // Cancel cleans up a flow
    Cancel(ctx context.Context, state *FlowState) error
}
```

Each protocol provides its own implementation:

```go
var handlers = map[string]FlowHandler{
    "oid4vci":   NewOID4VCIHandler(deps),
    "oid4vp":    NewOID4VPHandler(deps),
    "vctm":      NewVCTMHandler(deps),
    "iso18013":  NewISO18013Handler(deps),
    "didcomm":   NewDIDCommHandler(deps),
}
```

### Versioning for Protocol Extensions

Protocol handlers can have versions:

```json
{
  "type": "handshake_complete",
  "session_id": "<uuid>",
  "capabilities": {
    "oid4vci": { "version": "1.0", "drafts": ["15"] },
    "oid4vp": { "version": "1.0", "drafts": ["20"] },
    "iso18013": { "version": "1.0" },
    "didcomm": { "version": "2.1", "protocols": [
      "https://didcomm.org/issue-credential/3.0",
      "https://didcomm.org/present-proof/3.0",
      "https://didcomm.org/trust-ping/2.0"
    ]}
  }
}
```

Clients can check capabilities before starting flows.

## Security Considerations

### SSRF Mitigation

The server MUST implement strict controls on outbound requests:

1. **URL validation**: Only fetch from protocol-defined paths:
   - `/.well-known/openid-credential-issuer`
   - `/.well-known/oauth-authorization-server`
   - `/.well-known/openid-configuration`
   - Endpoints declared in fetched metadata

2. **IP blocklist**: Reject requests to:
   - Private IP ranges (10.x, 172.16-31.x, 192.168.x)
   - Localhost (127.x, ::1)
   - Link-local addresses (169.254.x)
   - Cloud metadata endpoints (169.254.169.254)

3. **Response validation**: All fetched content MUST validate against expected schemas:
   - Credential offers → OID4VCI CredentialOffer schema
   - Issuer metadata → OpenID4VCI Credential Issuer Metadata schema
   - Authorization server metadata → RFC 8414 schema

4. **Size limits**: Response bodies MUST NOT exceed 1MB (10MB for image embedding)

5. **Timeouts**: Individual HTTP requests timeout after 10 seconds

### Rate Limiting

Per-connection rate limits:
- Flow starts: 10/minute
- Sign requests: 20/minute
- Total messages: 100/minute

### Token Security

- JWT tokens MUST use short expiration (e.g., 1 hour)
- Tokens MUST be bound to connection (server validates on each message)
- Compromised tokens can be revoked via admin API

## Privacy Considerations

### Privacy Model

The WebSocket protocol is designed with privacy in mind:

| Property | How Achieved |
|----------|--------------|
| Keys never leave client | `sign_request`/`sign_response` pattern |
| Client controls credential matching | `match_credentials` step with local matching |
| Engine sees minimal data | Only one credential at a time during signing |
| Full privacy option | Local engine mode for native apps |

### Cloud Engine Limitations

When using a cloud-hosted engine, these limitations apply:
- Engine sees which issuers/verifiers user interacts with
- Engine can correlate issuance and presentation events
- Engine sees credential type (vct) during flows

These are **inherent to the cloud backend model** chosen for CORS avoidance.

### Local Engine: Full Privacy

Native apps can embed the engine locally, eliminating cloud visibility:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LOCAL ENGINE PRIVACY MODEL                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Native App with Local Engine                                              │
│   ────────────────────────────                                              │
│                                                                             │
│   Cloud services see:              Cloud services do NOT see:               │
│   ───────────────────              ─────────────────────────                │
│   • Login/authentication           • Which issuers contacted                │
│   • Encrypted credential blobs     • Which verifiers contacted              │
│   • Sync timestamps                • Presentation definitions               │
│   • VCTM lookups (cacheable)       • Credential content                     │
│                                    • Flow timing/correlation                │
│                                                                             │
│   All protocol flows happen locally on user's device.                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Mitigations for Cloud Engine

When local engine is not available, these mitigations reduce privacy impact:

1. **Minimal logging**: Engine SHOULD NOT log:
   - Credential content
   - User-selected claims
   - Nonces (which could enable correlation)

2. **No persistent flow state**: Flow state SHOULD be ephemeral (memory only)

3. **Aggregated metrics only**: Analytics SHOULD only track:
   - Flow counts by protocol (not by issuer)
   - Error rates by category (not by issuer)

4. **Client-side credential matching**: Engine never sees full credential inventory

### Future Enhancements

Possible additional privacy improvements:

1. **OHTTP integration**: Route protocol messages through OHTTP relay
2. **Issuer anonymization**: k-anonymity via batch requests
3. **Encrypted flows**: End-to-end encryption between client and issuer/verifier

## Implementation Notes

### Server State Machine

Each flow maintains state:

```go
type FlowState struct {
    FlowID     string
    Protocol   string        // "oid4vci", "oid4vp", "vctm"
    Step       string
    StartedAt  time.Time
    
    // OID4VCI state
    Offer      *CredentialOffer
    Metadata   *IssuerMetadata
    TokenResp  *TokenResponse
    
    // OID4VP state
    Request    *AuthorizationRequest
    
    // Pending sign request
    PendingSign *SignRequest
}
```

### Client State

Clients MUST track:
- Active `flow_id` for each in-progress flow
- Pending `message_id` for sign requests

Clients SHOULD reconnect and restart flows on disconnect (flows are not resumable).

### Timeouts

| Operation | Timeout |
|-----------|---------|
| Handshake | 10s |
| Flow total | 5min |
| Sign request | 60s |
| HTTP fetch | 10s |
| User selection | 5min |

## Changelog

- **0.1.0** (2026-02-18): Initial draft

## Open Questions

### 1. Batch Operations

**Question**: Should we support starting multiple flows simultaneously?

**Context**: A user might scan a QR code that triggers both credential issuance and
a presentation request, or the wallet might want to prefetch metadata for multiple
issuers in the background.

**Options**:

A. **No batching** (current design): Each flow is independent. Client sends multiple
   `flow_start` messages if needed.
   - Pro: Simpler state management
   - Pro: Clear error handling per flow
   - Con: More round trips for related operations

B. **Batch start**: Allow starting multiple flows in one message:
   ```json
   {
     "type": "flow_start_batch",
     "flows": [
       { "flow_id": "a", "protocol": "vctm", "vct": "..." },
       { "flow_id": "b", "protocol": "vctm", "vct": "..." }
     ]
   }
   ```
   - Pro: Efficient for prefetching
   - Con: Complex error handling (partial success?)

C. **Implicit batching**: Server automatically batches outbound requests internally
   when multiple flows target the same issuer.
   - Pro: Client simplicity
   - Con: Hidden behavior, harder to debug

**Recommendation**: Start with (A), add (C) as server-side optimization later.

---

### 2. Flow Cancellation

**Question**: Should clients be able to cancel in-progress flows?

**Context**: User might close a modal, navigate away, or decide not to proceed after
seeing trust evaluation results.

**Scenarios**:
- User starts issuance, sees "untrusted issuer" warning, wants to abort
- User starts presentation, closes browser tab
- Timeout on user selection (5 min) - implicit cancellation

**Proposed Message**:
```json
{
  "type": "flow_cancel",
  "flow_id": "<uuid>",
  "reason": "user_cancelled"  // or "timeout", "navigation", etc.
}
```

**Server Behavior on Cancel**:
1. Stop any pending HTTP requests
2. Release held tokens (if any)
3. Clean up flow state
4. Send acknowledgment:
   ```json
   {
     "type": "flow_cancelled",
     "flow_id": "<uuid>"
   }
   ```

**Edge Cases**:
- Cancel during sign request: Should server retry or immediately fail?
- Cancel after credential issued but before delivery: Credential is lost?
- Cancel during token exchange: Token may be consumed, credential lost

**Recommendation**: Support cancellation, but document that cancellation during
token exchange or credential request may result in lost credentials (inherent to
the protocol).

---

### 3. Credential Storage Integration

**Question**: Should flow completion automatically store credentials, or should
client explicitly request storage?

**Context**: The current architecture already has server-side credential storage,
but with **client-side encryption**. The flow is:
1. Client receives credential from issuer
2. Client encrypts credential locally (keys never leave client)
3. Client sends encrypted blob to server for storage
4. Server stores opaque encrypted data
5. On retrieval, client decrypts locally

This preserves privacy (server cannot read credentials) while enabling cross-device
sync (encrypted blobs are available from any device with the user's keys).

**Options for WebSocket Integration**:

A. **Current pattern via WS**: `flow_complete` returns credential, client encrypts
   and sends storage request via separate API call (existing `/api/credentials`).
   - Pro: No change to storage layer
   - Con: Extra round trip after flow completion

B. **Integrated storage in flow**: Add storage step to protocol flow:
   ```
   flow_complete with credential
   → client encrypts
   → client sends: { "type": "flow_action", "action": "store", "encrypted": "..." }
   → server stores, confirms
   ```
   - Pro: Single flow handles entire lifecycle
   - Con: Mixes protocol execution with storage

C. **Storage as separate WS message type**: Not part of flows, but via same channel:
   ```json
   {
     "type": "credential_store",
     "credential_id": "<uuid>",
     "encrypted_data": "..."
   }
   ```
   - Pro: Clean separation of concerns
   - Pro: Can store credentials from any source (not just WS flows)
   - Con: More message types

**Recommendation**: Option (C) - keep storage as separate message type on the same
WebSocket channel. This maintains the existing privacy model (client encrypts,
server stores opaque blob) while consolidating all wallet operations onto one channel.

---

### 4. Error Recovery

**Question**: Should some errors allow retry without restarting the full flow?

**Context**: Some failures are transient (network timeout, temporary server error)
while others are permanent (invalid credential, untrusted issuer).

**Recoverable Errors**:
| Error | Recoverable? | Recovery Action |
|-------|--------------|-----------------|
| Sign timeout | Yes | Re-send sign_request |
| Network timeout (metadata fetch) | Yes | Retry fetch |
| Token endpoint 5xx | Maybe | Retry with backoff |
| Credential endpoint 5xx | Maybe | Retry with backoff |
| Invalid signature | No | User needs to re-authenticate |
| Untrusted issuer | No | Policy decision |
| Invalid offer | No | Bad QR code |

**Proposed Mechanism**:

Add `recoverable` flag to `flow_error`:
```json
{
  "type": "flow_error",
  "flow_id": "<uuid>",
  "step": "requesting_credential",
  "error": {
    "code": "CREDENTIAL_ENDPOINT_ERROR",
    "message": "Credential endpoint returned 503",
    "recoverable": true,
    "retry_after": 5
  }
}
```

Client can then:
```json
{
  "type": "flow_action",
  "flow_id": "<uuid>",
  "action": "retry"
}
```

**Alternative**: Server automatically retries transient errors with backoff,
client only sees final success/failure.
- Pro: Simpler client
- Con: Less visibility into what's happening

**Recommendation**: Server auto-retries transient HTTP errors (up to 3 times with
backoff). Only surface to client if retries exhausted, with `recoverable: false`.

---

### 5. Multi-Credential Presentation

**Question**: How to handle VP requesting credentials from multiple SD-JWT VCs
with different keys?

**Context**: A presentation_definition might require multiple credentials:
- Driver's license (SD-JWT, key A)
- Proof of employment (SD-JWT, key B)
- Age verification (mDOC, key C)

Each credential may be bound to a different key, requiring multiple signatures.

**Options**:

A. **Sequential sign requests**: Server sends multiple `sign_request` messages:
   ```
   sign_request (key A) → sign_response
   sign_request (key B) → sign_response
   sign_request (key C) → sign_response
   → flow_complete with combined VP
   ```
   - Pro: Works with existing message format
   - Con: Multiple round trips

B. **Batch sign request**: Single request for multiple signatures:
   ```json
   {
     "type": "sign_request",
     "flow_id": "<uuid>",
     "message_id": "<uuid>",
     "action": "sign_presentation_multi",
     "params": {
       "presentations": [
         { "key_id": "key-a", "credential_id": "cred-1", "nonce": "...", ... },
         { "key_id": "key-b", "credential_id": "cred-2", "nonce": "...", ... }
       ]
     }
   }
   ```
   - Pro: Single round trip
   - Con: Client must support batch signing

C. **Server builds, client signs combined**: Server constructs the VP structure,
   client signs the outer container only.
   - Pro: Single signature
   - Con: Only works if all credentials can be holder-bound to same key

**Additional Complexity**: SD-JWT selective disclosure requires the client to
construct the disclosure array, not just sign.

**Recommendation**: Start with (A) - sequential. The latency cost is acceptable
for typical cases (1-2 credentials). Optimize to (B) if performance becomes an issue.

---

### 6. Connection Multiplexing

**Question**: Allow multiple concurrent flows per connection?

**Current Design**: Yes, flows are identified by `flow_id` and can run concurrently.

**Scenarios**:
- User scans QR while previous issuance is deferred (waiting)
- Background VCTM prefetch while user is in presentation flow
- Multiple credentials being issued in parallel (batch issuance)

**Concerns**:

1. **Resource exhaustion**: Malicious client starts 1000 flows
   - Mitigation: Per-connection flow limit (e.g., 5 active)

2. **Ordering guarantees**: Are messages for flow A delivered before flow B?
   - WebSocket guarantees order, but server may process async
   - Each flow should be independent, no cross-flow ordering needed

3. **Sign request conflicts**: Two flows request signature simultaneously
   - Client must handle: queue locally, sign sequentially
   - Server should avoid if possible (serialize sign requests)

**Proposed Limits**:
```
Active flows per connection: 5
Waiting (deferred) flows: 10
Total flow lifetime: 30 minutes (then auto-cancelled)
```

**Recommendation**: Keep multiplexing, add limits. Benefits outweigh complexity.

---

### 7. Binary Messages

**Question**: Use binary WebSocket frames for credential transfer?

**Context**: Credentials can be large, especially mDOC with embedded images.
Binary encoding (CBOR, protobuf) is more compact than JSON.

**Size Comparison** (typical SD-JWT VC):
| Format | Size |
|--------|------|
| JSON (current) | ~5KB |
| CBOR | ~3KB |
| JSON + gzip | ~1.5KB |

**Options**:

A. **All JSON** (current): Simple, human-readable, good tooling
   - Pro: Easy debugging, no schema versioning
   - Con: ~40% larger than binary

B. **Binary for credentials only**: `flow_complete` uses binary frame
   - Pro: Optimized where it matters
   - Con: Mixed mode complexity

C. **Full binary protocol**: All messages in CBOR or protobuf
   - Pro: Maximum efficiency
   - Con: Debugging nightmare, schema management

D. **JSON + compression**: Enable WebSocket per-message compression (RFC 7692)
   - Pro: Transparent to application
   - Con: Not all clients support, CPU overhead

**Recommendation**: Start with (A) + investigate (D). Credentials are typically
<10KB even with embedded images (already data: URIs). Network latency dominates
over payload size for most operations. Add binary option later if profiling shows
serialization is a bottleneck.

---

### 8. Anonymous/Unauthenticated Operations

**Question**: Should some operations work without authentication?

**Context**: The VCTM registry (`/type-metadata`) already serves unauthenticated
requests - it's a public read-only cache of credential type metadata. This pattern
could extend to other read-only operations.

**Current Architecture**:
```
Unauthenticated (REST):
  GET /type-metadata?vct=...     ← VCTM registry (already implemented)
  GET /status                    ← Health check

Authenticated (REST + WS):
  POST /api/*                    ← All other operations
  WS /api/v2/wallet              ← Protocol channel
```

**Proposed Extension**:

Add more unauthenticated REST endpoints that complement the WebSocket protocol:

```
GET /type-metadata?vct=...           ← VCTM (existing)
GET /issuer-metadata?issuer=...      ← Cached issuer metadata with embedded images
GET /trust-status?entity=...&role=...← Trust evaluation result
```

These serve as:
1. **Pre-login preview**: User can see credential info before signing up
2. **Public API**: Other applications can query trust status
3. **Cacheable**: CDN-friendly, reduces WebSocket load for read-only ops
4. **Fallback**: Works if WebSocket unavailable

**Integration with WebSocket Protocol**:

The WebSocket `vctm` and `trust_check` flows would internally use the same
services as these REST endpoints. For authenticated users, WS provides:
- Streaming progress
- Batching capability
- Consistent channel

But unauthenticated users can use REST directly.

**Rate Limiting for Anonymous**:
```
/type-metadata:    100 req/min per IP (cacheable, low risk)
/issuer-metadata:  30 req/min per IP (fetches external resources)
/trust-status:     30 req/min per IP (fetches trust lists)
```

**SSRF Concerns for Anonymous Endpoints**:

The `/issuer-metadata` endpoint accepts an issuer URL parameter. Mitigations:
1. Only fetch from `/.well-known/` paths (protocol-defined)
2. Schema validation on response
3. IP blocklist for private ranges
4. Aggressive caching (same issuer → cache hit)
5. Lower rate limit than authenticated

**Recommendation**: Extend the VCTM registry pattern to issuer metadata and
trust status. Keep these as REST endpoints (cacheable, simple) while the
WebSocket protocol handles stateful flows (issuance, presentation).

**Unified Architecture**:
```
┌─────────────────────────────────────────────────────────────┐
│                      Client                                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────┐    ┌──────────────────────────────┐   │
│  │  REST (public)  │    │  WebSocket (authenticated)   │   │
│  │  - VCTM         │    │  - OID4VCI flows             │   │
│  │  - Issuer meta  │    │  - OID4VP flows              │   │
│  │  - Trust status │    │  - Signing requests          │   │
│  └────────┬────────┘    │  - Credential storage        │   │
│           │             │  - Push notifications        │   │
│           │             └──────────────┬───────────────┘   │
│           │                            │                    │
├───────────┼────────────────────────────┼────────────────────┤
│           │         Backend            │                    │
│           ▼                            ▼                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Shared Services Layer                   │   │
│  │  - VCTMFetcher  - ImageEmbedder  - TrustEvaluator  │   │
│  │  - MetadataCache  - IssuerDiscovery                 │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Relationship to External Fetches Analysis

This specification should be read alongside `wallet-frontend-external-fetches.md`,
which analyzes the current proxy usage and identifies elimination targets. This
section reconciles the two documents and ensures a coherent overall design.

### Document Alignment

| External Fetches Concern | WebSocket Protocol Solution |
|--------------------------|----------------------------|
| VCT metadata via proxy | `vctm` flow or REST `/type-metadata` |
| Images in VCTM | Embedded by server (ImageEmbedder) |
| Issuer metadata via proxy | `oid4vci` flow fetches internally |
| Issuer logos/images | Embedded in `metadata_fetched` step |
| Authorization server metadata | Fetched internally during flow |
| Credential offer URIs | `oid4vci` flow with `credential_offer_uri` param |
| mDOC IACAs | Fetched and cached during `oid4vci` flow |
| Token endpoints | Called server-side during flow |
| Credential endpoints | Called server-side during flow |
| OHTTP gateway keys | Remains separate (direct fetch by client) |

### Proxy Elimination Mapping

The external-fetches document estimated **~85% proxy traffic reduction** through
purpose-specific APIs. Detailed analysis of actual proxy usage in wallet-frontend
reveals that **100% of current protocol flows** can be handled by the WebSocket
protocol, achieving **complete proxy elimination** for standard operations:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PROXY TRAFFIC ELIMINATION ROADMAP                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Current State (all via /proxy):                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ ████████████████████████████████████████████████████████████████████│   │
│  │ 100% proxy traffic                                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  After VCTM Registry (PR #22):                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ ░░░░░░░░░░░░░░░░░████████████████████████████████████████████████████│   │
│  │ ^^^^^^^^^^^^^^^  75% proxy traffic                                  │   │
│  │ VCTM (25%)                                                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  After WebSocket Protocol (this spec):                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ ░░░░░░░░░░░░░░░░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│   │
│  │ VCTM (25%)       OID4VCI/VP flows (75%)                     0% proxy│   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Legend: ░ = REST endpoint  ▓ = WebSocket flow                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Remaining Proxy Uses: Detailed Analysis

Analyzing the actual `httpProxy` usage in wallet-frontend reveals that **all current
proxy calls** can be handled by the WebSocket protocol:

#### GET Requests Currently Via Proxy

| Location | Purpose | WebSocket Solution |
|----------|---------|-------------------|
| `initializeCredentialEngine.ts` | VCT metadata | VCTM Registry REST ✅ |
| `OpenID4VCIHelper.ts:20` | Well-known metadata | `oid4vci` flow internal ✅ |
| `OpenID4VCIHelper.ts:194` | Logo prefetching | Embedded in metadata ✅ |
| `OpenID4VP.ts` | Authorization request | `oid4vp` flow internal ✅ |
| `OpenID4VCI.ts:604` | credential_offer_uri | `oid4vci` flow validates ✅ |

#### POST Requests Currently Via Proxy

| Location | Purpose | WebSocket Solution |
|----------|---------|-------------------|
| `TokenRequest.ts` | Token endpoint | `oid4vci` flow internal ✅ |
| `CredentialRequest.ts:248` | Credential endpoint | `oid4vci` flow internal ✅ |
| `CredentialRequest.ts:134` | Deferred credential | `oid4vci` flow internal ✅ |
| `PushedAuthorizationRequest.ts` | PAR endpoint | `oid4vci` flow internal ✅ |
| `OpenID4VCI.ts:217` | Nonce endpoint | `oid4vci` flow internal ✅ |
| `OpenID4VP.ts:169` | VP response_uri | `oid4vp` flow internal ✅ |

**Conclusion**: Every single current proxy use is covered by the WebSocket protocol.

#### Why Keep the Proxy Endpoint?

Even though WebSocket covers 100% of current usage, we retain `/proxy` for:

1. **Backwards Compatibility**
   - Existing credentials with external resource references
   - Old frontend versions during migration period
   - Third-party integrations that may depend on it

2. **Non-Conformant Implementations**
   - Issuers/verifiers that don't follow standards
   - Non-standard metadata locations
   - Custom credential rendering services

3. **Edge Cases Not Yet Identified**
   - Future protocol extensions
   - Rare credential types with unusual resource needs
   - Debug/development scenarios

4. **Graceful Degradation**
   - If WebSocket connection fails, frontend could fall back
   - Useful for debugging protocol issues

#### Proxy Deprecation Strategy

```
Phase 1: WebSocket Available (Initial)
├─ Proxy: Unrestricted, full functionality
├─ WebSocket: Opt-in via feature flag
└─ Monitoring: Track proxy vs WebSocket usage

Phase 2: WebSocket Primary (After Stabilization)
├─ Proxy: Rate limited (e.g., 10 req/min)
├─ WebSocket: Default for all flows
└─ Logging: Warn on proxy usage

Phase 3: Proxy Restricted (Before Deprecation)
├─ Proxy: Only for known edge cases
├─ WebSocket: Required for standard flows
└─ Analysis: Review remaining proxy traffic

Phase 4: Proxy Removed (Final)
├─ Proxy: Disabled or removed
├─ WebSocket: Only option
└─ Exception: May keep for admin/debug with auth
```

#### What About OHTTP?

OHTTP is **orthogonal** to the proxy question:

- **Current**: Client fetches OHTTP gateway keys directly (not via proxy)
- **OHTTP relay**: Used as alternative transport for proxy requests
- **WebSocket**: Server could use OHTTP for its outbound requests (future enhancement)

OHTTP provides **IP address privacy** (issuer can't see client IP), which is a
different concern than the **open proxy problem** (arbitrary URL fetching).

### OHTTP Integration

The external-fetches document mentions OHTTP as a separate mechanism. The WebSocket
protocol can integrate with OHTTP for enhanced privacy:

**Current OHTTP Usage** (unchanged by this spec):
- Client fetches OHTTP gateway keys directly
- Client can route requests through OHTTP relay
- Provides IP address privacy from target servers

**Potential Future Integration**:

```
┌──────────┐         ┌──────────┐         ┌──────────┐         ┌──────────┐
│  Client  │◄───────►│ Backend  │◄───────►│  OHTTP   │◄───────►│ Issuer/  │
│          │   WS    │          │  OHTTP  │  Relay   │  HTTP   │ Verifier │
└──────────┘         └──────────┘         └──────────┘         └──────────┘
```

The backend could route its outbound requests through an OHTTP relay, providing:
- IP privacy for the backend (issuer can't see backend IP)
- Aggregated anonymity (many backends share relay)
- User-backend binding still exists, but issuer sees less

This is a **potential future enhancement**, not part of the initial specification.

### Migration Path

The external-fetches document implicitly assumes incremental migration. Here's the
explicit migration strategy:

**Phase 1: VCTM Registry** (✅ Complete - PR #22)
- REST endpoint `/type-metadata`
- Image embedding
- No frontend changes required (same HTTP interface)

**Phase 2: Discovery/Trust REST API** (⏳ In Progress - api-versioning-discovery-trust)
- REST endpoints `/issuer-metadata`, `/trust-status`
- Can be adopted incrementally by frontend
- No WebSocket dependency

**Phase 3: WebSocket Protocol Channel** (📋 This Specification)
- Parallel implementation alongside REST
- Frontend can migrate flows incrementally
- Feature flag to enable per-flow

**Phase 4: Deprecate Generic Proxy** (Future)
- Once WebSocket adoption is high
- Rate limit proxy, then disable
- Maintain for edge cases if needed

### Frontend Changes Required

The external-fetches document lists affected frontend files. Here's the mapping to
WebSocket adoption:

| Frontend Component | Current | After WebSocket |
|-------------------|---------|-----------------|
| `OpenID4VCIHelper.ts` | httpProxy calls | WS `oid4vci` flow |
| `OpenID4VCI.ts` | Direct fetch + proxy | WS `oid4vci` flow |
| `getSdJwtVcMetadata.ts` | httpProxy | WS `vctm` flow or REST |
| `openID4VCICredentialRendering.ts` | Image proxy | Embedded in flow responses |
| `ohttpHelpers.ts` | Direct fetch | No change (OHTTP separate) |
| `StatusContextProvider.tsx` | Direct backend call | No change |

**New Frontend Components Needed**:
- `WebSocketManager.ts` - Connection lifecycle, reconnection
- `FlowManager.ts` - Track active flows, handle messages
- `SigningBridge.ts` - Respond to server sign_request messages

### Gap Analysis

Reviewing both documents together, these gaps were identified:

#### 1. Credential Refresh/Update Flows

**Gap**: Neither document addresses how credentials are refreshed when they expire
or when the issuer updates them.

**Proposed Addition**: Add `credential_refresh` flow type:
```json
{
  "type": "flow_start",
  "protocol": "oid4vci",
  "mode": "refresh",
  "credential_id": "<existing-credential-id>",
  "refresh_token": "<if available>"
}
```

#### 2. Revocation Checking

**Gap**: Neither document addresses credential revocation status checks.

**Proposed Addition**: The backend should check revocation during relevant flows:
- Before presentation (OID4VP): Check if credentials being presented are revoked
- Periodically for stored credentials: Push notification if revoked

```json
{
  "type": "push",
  "push_type": "credential_revoked",
  "credential_id": "<id>",
  "reason": "issuer_revocation"
}
```

#### 3. Credential Deletion/Lifecycle

**Gap**: No mechanism for server-assisted credential deletion (e.g., when user
deletes from one device, sync to others).

**Proposed Addition**: `credential_lifecycle` message type:
```json
{
  "type": "credential_lifecycle",
  "action": "delete",
  "credential_ids": ["<id1>", "<id2>"]
}
```

#### 4. Batch Credential Issuance

**Gap**: OID4VCI supports batch issuance (multiple credentials in one flow).
Neither document explicitly addresses this.

**Already Supported**: The `flow_complete` message includes `credentials` array,
implicitly supporting batch. Should be documented explicitly.

#### 5. Notification Preferences

**Gap**: No mechanism for users to configure what push notifications they receive.

**Proposed Addition**: Configuration via handshake or separate message:
```json
{
  "type": "configure",
  "notifications": {
    "credential_expiring": true,
    "credential_revoked": true,
    "deferred_ready": true,
    "didcomm_message": false
  }
}
```

#### 6. Audit/Activity Log

**Gap**: Neither document addresses activity logging for user visibility.

**Consideration**: Should the backend track (with user consent):
- Issuance attempts (success/failure)
- Presentation events
- Trust evaluation results

This could be a separate REST API or included in WebSocket responses.

### Unified Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            WALLET ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         WALLET FRONTEND                              │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────┐   │   │
│  │  │  Credential   │  │  Issuance/    │  │    WebSocket          │   │   │
│  │  │  Display &    │  │  Presentation │  │    Client             │   │   │
│  │  │  Rendering    │  │  UI           │  │    ┌───────────────┐  │   │   │
│  │  └───────┬───────┘  └───────┬───────┘  │    │ FlowManager   │  │   │   │
│  │          │                  │          │    │ SigningBridge │  │   │   │
│  │          │                  │          │    │ PushHandler   │  │   │   │
│  │          │                  │          │    └───────┬───────┘  │   │   │
│  │          │                  │          └────────────┼──────────┘   │   │
│  │          │                  │                       │              │   │
│  │          ▼                  ▼                       ▼              │   │
│  │  ┌─────────────────────────────────────────────────────────────┐  │   │
│  │  │                    LOCAL STORAGE                             │  │   │
│  │  │  Encrypted credentials │ Keys │ Preferences │ Cache         │  │   │
│  │  └─────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│           ┌────────────────────────┼────────────────────────┐              │
│           │                        │                        │              │
│           ▼                        ▼                        ▼              │
│  ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐    │
│  │  REST (Public)  │      │  REST (Auth'd)  │      │   WebSocket     │    │
│  │  /type-metadata │      │  /api/*         │      │   /api/v2/wallet│    │
│  │  /issuer-meta   │      │  /credentials   │      │                 │    │
│  │  /trust-status  │      │  /proxy (⚠️)    │      │   Protocol      │    │
│  └────────┬────────┘      └────────┬────────┘      │   Flows         │    │
│           │                        │               └────────┬────────┘    │
│           │                        │                        │              │
├───────────┼────────────────────────┼────────────────────────┼──────────────┤
│           │              WALLET BACKEND                     │              │
│           ▼                        ▼                        ▼              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       SHARED SERVICES LAYER                          │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │   │
│  │  │ VCTMFetcher │ │ ImageEmbed  │ │ TrustEval   │ │ MetadataCache│  │   │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘   │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │   │
│  │  │ OID4VCI     │ │ OID4VP      │ │ DIDComm     │ │ ISO18013    │   │   │
│  │  │ Handler     │ │ Handler     │ │ Handler     │ │ Handler     │   │   │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         EXTERNAL SERVICES                            │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │   │
│  │  │ Issuers     │ │ Verifiers   │ │ Trust       │ │ VCTM        │   │   │
│  │  │ (OID4VCI)   │ │ (OID4VP)    │ │ Frameworks  │ │ Sources     │   │   │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Note: /proxy marked ⚠️ - to be deprecated after WebSocket adoption        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Summary of Compatibility

The two documents are **compatible and complementary**:

- **External Fetches**: Analyzes the problem (what fetches exist, where traffic goes)
- **WebSocket Protocol**: Defines the solution (how to execute flows without proxy)

Key alignments:
1. Both aim to eliminate the generic proxy
2. Both use purpose-specific APIs
3. Both embed images to avoid secondary fetches
4. Both leverage go-trust for trust evaluation

The gap analysis above identifies six areas needing attention:
1. Credential refresh flows
2. Revocation checking
3. Credential lifecycle management
4. Batch issuance documentation
5. Notification preferences
6. Audit logging

These should be addressed as the specification matures.
