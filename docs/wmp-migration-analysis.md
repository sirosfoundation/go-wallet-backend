# WMP in the engine

The engine serves the Wallet Messaging Protocol (WMP, `sirosfoundation/wmp`:
Core and the OpenID4x profile) over HTTP+SSE next to its WebSocket protocol
(`websocket-protocol-spec.md`). The protocol lives in
[go-wmp](https://github.com/sirosfoundation/go-wmp) (v0.12.0); the backend is a
thin bridge between it and the engine's flow handlers. This document describes
the bridge. The wire behaviour is the specification's, not this document's.

## What go-wmp does and what the backend does

| go-wmp | go-wallet-backend (`internal/engine/wmp*.go`) |
|---|---|
| `wmp.SessionService`: create, resume, close, server-assigned unguessable IDs, owner binding, single-use rotating resumption tokens, TTL and expiry sweep | `Authenticate`: bearer token to `wmp.Principal` (the only place a `*http.Request` is read) |
| `httpsse.NewSecuredServerHandler`: every request authenticated, per-session Peer and Handler, event log with `Last-Event-ID` replay, heartbeat, write deadlines, `410 Gone` on a replay gap, replay redaction (`SplitReplaySecrets`) | `wmpFlowProfile`: a go-wmp `AsyncFlowProfile` whose flow function starts the engine flow |
| `Peer`: dispatch, capability gating (-31005), `wmp.message.*` answered as a tls-mode orchestrator (-31008), sub-flow routing | `wmpTransport`: engine messages to `FlowContext` progress, completion, error and `RequestSign` / `RequestMatch` |
| `FlowContext.RequestSubFlow`, `openid4x.RequestSign`, `RequestMatch`, `SubFlowError.Rejected()` | `wmpGuard`: the token's TAC on every request |
| `openid4x`: closed `select_credentials` and match types, result validation, capability descriptors | `wmpHandler`: `CredentialNotification`, `Resolve` (vctm), `CapabilityList`, session close |

The engine itself (`Session`, flow handlers) knows no WMP. A `Session` has a
`SessionTransport` instead of a WebSocket connection when WMP carries it
(`transport.go`); everything the engine sends goes through `Session.Send`.

## Endpoints

```
POST /api/v2/wallet/rpc                 JSON-RPC 2.0 (session.create, flow.start, flow.action, ...)
GET  /api/v2/wallet/rpc/events          SSE event stream (also /api/v2/wallet/events)
GET  /.well-known/wmp-configuration     discovery, no authentication
```

go-wmp's client takes one base URL and opens the stream at `base + "/events"`,
hence the stream at `/rpc/events`; discovery advertises both. The external URL is
`server.external_urls.engine_url` (`wss://` is mapped to `https://`; plaintext only
for loopback hosts); without a usable one discovery answers 503. CORS allows the
`Wmp-Session-Id` and `Last-Event-ID` headers by default.

A session is named by the `Wmp-Session-Id` header (or `params.wmp.session_id`); the
server assigns it at `wmp.session.create`. The resumption token is single-use and
rotated on every `wmp.session.resume`. A stream reconnect carries `Last-Event-ID`;
if the cursor is older than the replay window the answer is `410 Gone` and the
client resumes with `wmp.session.resume`.

## Authentication and permissions

`Authenticate` validates the bearer token with the engine's own rules (signature,
audience, user and token revocation) on **every** request and returns a
`wmp.Principal{Subject: user (or "jti:<jti>" for an anonymous token), Tenant,
Claims: *wmpClaims{UserID, TenantID, TokenID, TAC}}`. A session belongs to its
Principal; another user, or the same user in another tenant, gets `-31000`, as for
an unknown session.

The TAC is read from the Principal of the request being served, never cached. For
`wmp.flow.start`, `flow.action`, `flow.cancel`, flow results and
`wmp.credential.notification`, both the TAC the session was created with and the
current request's must grant the permission of the flow's protocol (`i` for
oid4vci, `r` for oid4vp); otherwise `-31002` with `data.reason`. The results of a
sign or match sub-flow are judged by the protocol of the flow waiting for them.

Two kinds of message reach a session without passing the Peer's request guard:
attaching an event stream (everything the session emits, credentials included) and
a JSON-RPC response to a sign or match request (it can fail the flow that waits
for it). `ServeAuthenticated` checks both with `CheckSessionAccess`: the token's
TAC must grant every permission the session was created with, else `403` (the
owner's weak token is refused; a session that is unknown, expired or someone
else's is answered by go-wmp as before). A stream is authorized when it is
attached; it ends when the session does (user revoked, superseded, closed).

The Peer's `Authorizer` also refuses a request from another Principal than the
session's owner and one that names another session than the Peer's, so a Peer an
in-process caller built from `NewSessionHandler` is as closed as the HTTP one. An
in-process caller that feeds responses to a Peer itself calls `CheckSessionAccess`
first.

An embedder that has its own Principal needs no HTTP: `NewWMPPrincipal(...)`,
`WMPAdapter.NewSessionHandler(ctx, principal, sessionID)` (the handler and Peer
options of a session) and `WMPAdapter.Service()` drive the same engine over any
`wmp.Transport`, with the Principal in the context
(`TestWMPBridge_InProcessWithoutHTTP`).

## Flows

| WMP | Engine |
|---|---|
| `wmp.flow.start` `oid4vci` / `oid4vp` (needs the capability of the same name) | `Manager.handleFlowStart`; `params` is a `FlowStartMessage`; transaction_data is enabled only for a client that offered the `transaction_data` capability with version 1 |
| `wmp.flow.action` `accept_offer`, `provide_tx_code`, `authorize`, `cancel` | `consent`, `provide_pin`, `authorization_complete`, `decline` |
| `wmp.flow.action` `select_credentials` (closed: `consent`, `selections[{query_id, selection_handle}]`) | `consent` with the query ids and the handle (see below), or `decline` |
| `wmp.flow.cancel` | cancels the engine flow |
| progress, complete, error | `wmp.flow.progress`, `wmp.flow.complete`, `wmp.flow.error` |
| sign request | sign sub-flow (`openid4x.RequestSign`); the result becomes the engine's `sign_response` |
| match request | match sub-flow (`openid4x.RequestMatch`); only satisfiability is relayed |
| `wmp.resolve` type `vctm` (capability `resolve`) | the VCTM lookup of the engine's VCTM handler; `vctm` is not a flow type |
| `wmp.credential.notification` | `dispatchCredentialNotification` |
| `wmp.message.deliver` (request) | `-31008`; `ack` and `status` are logged and dropped |

A `select_credentials` the closed shape refuses is answered `-32602` without
data and the flow ends with a terminal `-32602` without data. If the flow is
waiting for the selection it is declined (the verifier is told `access_denied`);
if it is already past that step nothing would consume a decline, so it is stopped
at once and the verifier is not told.

A flow that ends without a result, or outlives the timeout the client named in
`wmp.flow.start` (capped at 5 minutes), is reported as `-31006`.

### Errors

Engine error codes map to `wmp.flow.error` codes: `AUTH_FAILED`, `FORBIDDEN` to
`-31002`; `INVALID_MESSAGE` to `-32600`; `TOO_MANY_REQUESTS` to `-31007`;
`INTERNAL_ERROR` to `-32603`; everything else, `SIGN_ERROR` included, to `-31006`.
`UNSUPPORTED_TRANSACTION_DATA` is `-31005` with
`data {"unsupported": "transaction_data", "redirect_uri": ...}`; `redirect_uri` is
the verifier's, additive to the profile's data, so a query or fragment response
mode does not lose it.

A sign sub-flow that fails reaches the engine as a `SignError`; only the codes the
engine acts on survive, and nothing of the wallet's text or data is relayed. A
wallet that answers `-31005` with `data.unsupported == "transaction_data"` is
refusing the request's transaction_data; any other failure is a plain sign error.

### Replay

The event log is go-wmp's (200 events, 4 MiB, per session). A replayed
`wmp.flow.complete` has `refresh_token`, `dpop_jwk` and `dpop_key_id` removed and
lists them in `redacted_members`; the live copy has them. Nothing else is
withheld (`credential_metadata` is already restricted to display members by the
engine).

## Capabilities

Advertised from the flow handlers registered on the manager, with go-wmp's
descriptors: `oid4vci` (grants, formats), `oid4vp` (response modes, formats),
`transaction_data` (versions), `flows` (`max_concurrent`) and `resolve`
(`supported_types: ["vctm"]`). The session negotiates the offered capabilities
that the engine serves; offering none negotiates none. `transaction_data` needs a
version the client offered.

## Operation

- Sessions: at most 10 per bearer token and the engine's global connection limit
  (shared with WebSocket connections). A newer session of the same (tenant, user)
  supersedes the older one, as on WebSocket. Session TTL: the client's, default
  1 hour, at most 24 hours. The resumption token lives 10 minutes.
- Session state is process-local: see "WMP session affinity" in `DEPLOYMENT.md`.
- Shutdown: the provider drains the adapter (503), closes the secured server (ends
  streams and peers) and ends every engine session, before the listeners stop.

## Not done here

- The engine's own consent protocol is still the old shape (credential ids, claim
  names): over WMP the engine accepts the closed `select_credentials` and sends
  the closed `credentials_to_include` / `selection_handle`. Moving the engine and
  the WebSocket protocol to the credential-data-free shape is go-wallet-backend#502.
- The interactive steps and actions of OpenID4x 3.1.2, 3.1.3 and 3.2.2 are not
  translated: progress steps keep the engine's names (`credential_selection`,
  `awaiting_selection`, `authorization_required`), and `accept_offer` and
  `authorize` map to the engine's actions without reshaping `selected_indices`
  or `auth_code` and the OAuth state. This is as before the go-wmp rebuild.
- A credential notification that needs a client-held DPoP signature after the
  issuance completed has no flow to run the sign sub-flow in: go-wmp sub-flows
  belong to a running flow. Over WMP such a notification is not forwarded.
- `holder_commitments` (the legacy proof-claim advert) is not relayed: go-wmp has
  no such member. Credential Auxiliary Data (go-wallet-backend#480) replaces it.
- The engine's match request is not used for OID4VP (the client matches inside the
  consent step); the match bridge relays satisfiability only.
- A Redis `SessionStore` / `EventLog` for go-wmp, and engine flows that survive a
  replica change.
