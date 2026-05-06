# WMP Migration Plan

## go-wallet-backend — Migration to WMP

**Status:** Planning  
**Date:** 2026-04-29

## 1. Overview

This document describes how to migrate the existing wallet-frontend ↔ go-wallet-backend
WebSocket protocol to WMP (Wallet Messaging Protocol). For the WMP specification itself,
see the [WMP repository](../../wmp/).

## 2. Current Architecture

The existing wallet system uses a custom WebSocket protocol between wallet-frontend and go-wallet-backend with two protocol versions:

- **Legacy protocol** — Authentication + signing operations (client-side keystore)
- **V2 engine protocol** — Flow-based orchestration (OID4VCI/OID4VP/VCTM)

See also: [websocket-protocol-spec.md](websocket-protocol-spec.md) and
[frontend-websocket-integration.md](frontend-websocket-integration.md).

## 3. Protocol Mapping

| Current Protocol | WMP Equivalent |
|-----------------|---------------|
| `handshake` / `auth` | `wmp.session.create` with bearer token auth |
| `handshake_complete` / `FIN_INIT` | `wmp.session.create` result with capabilities |
| `flow_start` | `wmp.flow.start` |
| `flow_progress` | `wmp.flow.progress` |
| `flow_action` | `wmp.flow.action` |
| `flow_complete` | `wmp.flow.complete` |
| `flow_error` | `wmp.flow.error` |
| `sign_request` | `wmp.flow.sign` (request) |
| `sign_response` | `wmp.flow.sign` (response) |
| `match_request` | `wmp.flow.action` with `action: "match"` |
| `match_response` | `wmp.flow.action` response |
| `push` | `wmp.message.deliver` (notification) |

## 4. Example: OID4VCI Flow over WMP

```
wallet-frontend                    go-wallet-backend
      │                                    │
      │─── wmp.session.create ────────────>│
      │    {auth: bearer_token,            │
      │     capabilities: ["oid4vci"]}     │
      │<── result {session_id, caps} ──────│
      │                                    │
      │─── wmp.flow.start ───────────────>│
      │    {flow_type: "oid4vci",          │
      │     params: {offer: "openid..."}}  │
      │                                    │
      │<── wmp.flow.progress ──────────────│
      │    {step: "metadata_fetched",      │
      │     payload: {issuer_metadata}}    │
      │                                    │
      │<── wmp.flow.progress ──────────────│
      │    {step: "awaiting_selection",    │
      │     payload: {credentials: [...]}} │
      │                                    │
      │─── wmp.flow.action ──────────────>│
      │    {action: "select_credential",   │
      │     params: {selected_index: 0}}   │
      │                                    │
      │<── wmp.flow.sign (request) ────────│
      │    {action: "generate_proof",      │
      │     nonce: "...", audience: "..."}  │
      │                                    │
      │─── wmp.flow.sign (response) ──────>│
      │    {proof_jwt: "eyJ..."}           │
      │                                    │
      │<── wmp.flow.complete ──────────────│
      │    {credentials: [{...}]}          │
      │                                    │
```

## 5. Migration Strategy

1. **Phase 1** — Implement WMP WebSocket binding in go-wallet-backend alongside existing protocol on a `/wmp` endpoint.
2. **Phase 2** — Add WMP transport layer to wallet-frontend, connecting via `WebSocketTransport`.
3. **Phase 3** — Deprecate legacy protocol, route all flows through WMP.
4. **Phase 4** — Enable MLS for E2E encryption on sensitive flows.

## 6. Deployment Considerations

The migration preserves the existing deployment model options documented in
[websocket-protocol-spec.md](websocket-protocol-spec.md):

| Mode | WMP Endpoint | Notes |
|------|-------------|-------|
| Embedded (`--mode=all`) | `ws://localhost:PORT/wmp` | Development use |
| Cloud Engine | `wss://engine.example.com/wmp` | Backend sees orchestration traffic |
| Local Engine | `ws://localhost:PORT/wmp` | Maximum privacy |

In `mls-optional` mode, the cloud engine processes orchestration traffic in plaintext
(flow steps, tool invocations) while relay/E2E traffic remains encrypted. This matches
the current privacy model where keys never leave the client.

## 7. Compatibility

During migration (Phases 1–2), both protocols are available simultaneously:
- Legacy: `ws://host/ws` (existing path)
- WMP: `ws://host/wmp` (new path, `wmp.v1` subprotocol)

The frontend's transport abstraction layer (see [frontend-websocket-integration.md](frontend-websocket-integration.md))
allows switching between transport mechanisms via configuration.
