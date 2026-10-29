# WMP in the engine

The engine serves the Wallet Messaging Protocol (WMP, `sirosfoundation/wmp`:
Core and the OpenID4x profile) over HTTP+SSE next to its WebSocket protocol
(`websocket-protocol-spec.md`). The protocol lives in
[go-wmp](https://github.com/sirosfoundation/go-wmp) (v0.12.1); the backend is a
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
| `wmp.flow.action` `accept_offer`, `provide_tx_code`, `authorize`, `cancel` | `select_credential` (the index names the configuration the engine offered), `provide_pin`, `authorization_complete` (`auth_code` becomes `code`; `state` is an additive param), a cancelled flow (OID4VCI) or `decline` (OID4VP) |
| `wmp.flow.action` `select_credentials` (closed: `consent`, `selections[{query_id, selection_handle}]`) | the transport-neutral consent answer (see "Consent"), or `decline` |
| `wmp.flow.cancel` | cancels the engine flow |
| progress, complete, error | `wmp.flow.progress`, `wmp.flow.complete`, `wmp.flow.error` |
| sign request | sign sub-flow (`openid4x.RequestSign`); the result becomes the engine's `sign_response` |
| match request | match sub-flow (`openid4x.RequestMatch`); only satisfiability is relayed |
| `wmp.resolve` type `vctm` (capability `resolve`) | the VCTM lookup of the engine's VCTM handler (see "Resolve"); `vctm` is not a flow type |
| `wmp.flow.start` `credential_notification` (capability of the same name) | go-wmp's `NotificationFlow` over the engine's notification context (see "Credential notification") |
| `wmp.credential.notification` | `dispatchCredentialNotification`. **Superseded** by the `credential_notification` flow (it is not in the profile, has no result and cannot ask for a DPoP proof); kept as it was, no removal. It finds a context only in a session that negotiated `credential_notification` (nothing is retained otherwise) |
| `wmp.message.deliver` (request) | `-31008`; `ack` and `status` are logged and dropped |

Only the actions of the profile are accepted: the engine's own action names
(`consent`, `decline`, `provide_pin`, `authorization_complete`, `select_credential`,
`credentials_matched`) are refused `-32602`. `trust_result` (the engine asking the
client to evaluate trust) is the one additive action.

A `select_credentials` the closed shape refuses is answered `-32602` without
data and the flow ends with a terminal `-32602` without data. If the flow is
waiting for the selection it is declined (the verifier is told `access_denied`);
if it is already past that step nothing would consume a decline, so it is stopped
at once and the verifier is not told.

A flow that ends without a result, or outlives the timeout the client named in
`wmp.flow.start` (capped at 5 minutes), is reported as `-31006`.

### Steps and payloads

The engine keeps its own step names and payloads (the WebSocket protocol is
unchanged); `translateProgress` in `wmp_translate.go` maps them to OpenID4x 3.1.2
and 3.2.2 at the bridge. A step the profile has no counterpart for
(`exchanging_token`, `token_obtained`, `submitting_response`) is not sent;
`generating_proof` and `generating_presentation` are sent when the sign
sub-flow starts. The complete table, with the payload of every step and action,
is in the wire-change document handed to the SDK and wallet-frontend owners. A test asserts that every engine step is
either translated or deliberately dropped.

### Consent

One transport-neutral component decides every consent, `consent.go`: a
transport translates its wire to a `consentAnswer` (WebSocket: `consent_ws.go`;
WMP: `consentFromSelectCredentials`, which parses the closed `select_credentials`
with go-wmp) and the OID4VP flow asks `consentPolicy.Decide` whether the answer is
acceptable for the request it sent. The component owns the vetting against the
verifier's DCQL query (`presentation.dcql_consent_check`: `off`, `warn` (default),
`enforce`), the refusal outcomes and what the sign request carries afterwards
(`consentDecision.signInclusion`: the credential references and the selection
handle, nothing else). Both transports therefore apply the same checks with the
same refusal semantics; what differs is the wire (the WebSocket `consent` action
carries `credential_id` and `disclosed_claims`, which the engine vets and relays as
before; a WMP `select_credentials` is a closed set and carries neither, and a
selection handle that the WebSocket protocol does not have).

A transport that has a decision to report to its client implements `consentObserver`:
the WMP bridge answers a `select_credentials` the policy refuses (a query not in the
request) with the correlated `-32602` before acknowledging it (it waits up to 3 s for
the flow's decision), a second selection for a flow is refused, and a malformed one
after a valid one ends the flow (the bridge tracks that a selection was handed over).

A consent the policy refuses ends the flow, the verifier is told `access_denied`
without a description, and the client gets the flow error; over WMP a refusal for a
query id that is not in the verifier's request, or repeated, is the terminal
`-32602` without data of OpenID4x 3.2.3.1.

### Issuer entitlement

The enforcement of go-wallet-backend#522 is in the engine core and applies to every
transport. The bridge (`wmp_entitlement.go`) maps its outcomes with go-wmp v0.13.0's
types: the refusal `ISSUER_NOT_ENTITLED` is `wmp.ErrIssuerNotEntitled` (`-31020`,
`openid4x.IssuerNotEntitledMessage`) with `openid4x.NewIssuerNotEntitledData`, the
decision bounded by `IssuerEntitlement.Bounded()`; a trust-decision refusal
`UNTRUSTED_ISSUER` stays `-31006` with `openid4x.NewUntrustedIssuerData()`
(`{reason: "untrusted_issuer", retryable: false}`); never both for one flow. The
findings progress (`trust_evaluated` with `issuer_entitlement_evaluated`) is relayed
as `openid4x.NewIssuerEntitlementPayload`, without `trust_info`, bounded by go-wmp
(at most 16 findings, a finding whose code is not of the defined form dropped, an
over-long or non-printable `message` / `credential_type` left out, the
certificate's own `entitlements` not relayed). A progress go-wmp refuses is not
relayed; a refusal go-wmp does not accept as one (no issuer, not `allowed:false`,
`mode:fail` with a finding) ends the flow with a plain `-31006` without data, never a
made-up decision. An engine error code the bridge does not know is `-31006`. The
shapes are those of #522 (`ISSUER_NOT_ENTITLED` details `{issuer,
issuer_entitlement}` where the decision is `issuertrust.Decision.Summary()`); the
engine constant is declared locally until #522 lands. A client cannot select a
configuration outside the offer over WMP: `accept_offer` names an index of the
credentials the engine listed.

### Resolve

`wmp.resolve` type `vctm` (Core 5.8.1) answers with go-wmp's helpers. The engine looks
the `vct` up as the VCTM flow does (registry first; on a miss or an unreachable
registry, the `vct` itself when it is an absolute URL; any other outcome of the
registry lookup is a failure and does not fall through), and the result carries
exactly `vct`, `name`, `description`, `display`, `claims` and `schema` of the
document (`ProjectVCTM`; `vct` is the uri when the document has none). A lookup that
finds no document, cannot reach one, or finds one that is not an object is `-32603`
`{"reason": "metadata_fetch_error"}` with nothing of the failure; `metadata: null` only
when the registry says it has no entry and the `vct` is not a URL to try; an empty
uri is `-32602`. The lookup carries the session's tenant (`X-Tenant-ID`). A URL is fetched with the engine's HTTP client policy: loopback,
private, link-local and metadata addresses and non-HTTPS are refused, redirects
included, unless the deployment is configured for local development; the document is
read up to 1 MiB.

### Credential notification

After an issuance completes the wallet reports an OID4VCI notification with a new
`credential_notification` flow (OpenID4x 3.4; go-wmp's `NotificationFlow`,
`NotificationStartMiddleware`, `ParseCredentialNotificationStart`; the engine
implements `NotificationForwarder` in `wmp_notification.go`). The engine advertises
the `credential_notification` capability (events `credential_accepted`,
`credential_failure`, `context_ttl_seconds` the engine's 5 minutes) and registers the
flow on the profile and the start middleware on the Peer (a start in a session that did
not negotiate it is `-31005`, invalid params `-32602 {"member"}`, both as the response
to the start; the flow type is authorized exactly as `oid4vci`).

- The notification context (`notificationContextStore`) is kept only when the session
  negotiated the capability, bound to the issuance session and the principal that ran
  it (a WebSocket session keeps it as before). Each `notification_id` is single use
  (`claim`); an encrypted issuer response, whose ids the engine never saw, accepts the
  wallet's ids once each, up to 256. The context lives until its TTL. The legacy
  `wmp.credential.notification` method reads and writes the same per-id record for a
  WMP context, so an id forwarded by one cannot be forwarded by the other.
- The flow takes a slot of the session's concurrent-flow limit (`reserveFlow`, the same
  atomic check as every flow; at the limit it ends `busy`, retryable) and is registered
  as an `oid4vci` flow, so the guard requires the issuance permission for every
  message about it and its sign sub-flow. It has no actions.
- The completion gains `notification_endpoint` (when a context was retained) and keeps
  `credentials[].notification_id` for plain responses only, each within the profile's
  bounds (256 and 2048 characters).
- Forwarding: the forwarding limit is checked first (`busy`, retryable, the context
  and id are kept), then the id is claimed (`context_unavailable` for an absent,
  expired, other-session, other-principal, unknown or spent context, not
  distinguished). A token bound to a key the wallet holds gets its proof from a
  `sign_client_auth` sub-flow of the notification flow (`htu` = the endpoint without
  query and fragment, `openid4x.NotificationHTU`; the request goes to the full
  endpoint; no `key_id`; each proof bounded by go-wmp's 20 s); a wallet that
  fails or answers without a proof is `signing_failed`; the issuer's refusal is
  `forward_failed`; the flow's own timeout (the client's, default 1 minute) is
  `timeout`. Only the reason and `retryable` reach the wallet. The engine-held key
  needs no sub-flow.
- The DPoP `htu` of a notification is now the endpoint without query and fragment on
  every transport (RFC 9449 4.2); the request goes to the full endpoint.

The older `wmp.credential.notification` method is not in the profile; it is
superseded by this flow and kept unchanged.

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
`transaction_data` (versions), `credential_notification`, `flows` (`max_concurrent`) and
`resolve` (`supported_types: ["vctm"]`). The session negotiates the offered capabilities
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

- The engine's own WebSocket consent protocol is still the old shape (`consent`
  with credential ids and claim names): moving it to the credential-data-free
  shape is go-wallet-backend#502 and a WebSocket wire change for the SDKs and
  wallet-frontend. Over WMP the engine accepts the closed `select_credentials`
  and sends the closed `credentials_to_include` / `selection_handle`.
- The WMP bridge mirrors the WebSocket path (behaviour, defaults, refusal semantics,
  what the verifier and issuer see): no WMP-only strictness. OpenID4x 3.2.3.1 requires
  refusing a `select_credentials` whose `query_id` is not in the request; the engine
  applies `dcql_consent_check` (default `warn`: logged, accepted) to both transports,
  so by default the spec's MUST-refuse does not hold. Under `enforce` the refusal is the
  terminal `-32602`. Owner decision: `dcql_consent_check` is not flipped for WMP.
- The engine does not run the `match` flow for OID4VP (nor on WebSocket), so the
  selection handle is not compared with a match result's. A wallet that holds nothing
  declines (`select_credentials` with `consent: false`): the verifier-visible outcome is
  identical to the WebSocket `credentials_matched` with no match
  (`NO_MATCHING_CREDENTIALS`): `access_denied` with the same generic description. What
  the client sees differs: the WebSocket client gets the flow error
  `NO_MATCHING_CREDENTIALS` with `requested_types`, `no_match_reason` and the verifier's
  `redirect_uri`; a WMP client gets the decline's `-31006` "User declined the request"
  with `redirect_uri` and nothing else (the WMP wallet matched locally and already knows
  what it holds).
- The profile has no step for deferred issuance, no `state` on `authorize` and no
  action for the engine's request that the client evaluates trust itself
  (`trust_result`); they travel as additive members (see the wire-change document).
- `holder_commitments` (the legacy proof-claim advert) is not relayed: go-wmp has
  no such member. Credential Auxiliary Data (go-wallet-backend#480) replaces it.
- The engine's match request is not used for OID4VP (the client matches inside the
  consent step); the match bridge relays satisfiability only.
- A Redis `SessionStore` / `EventLog` for go-wmp, and engine flows that survive a
  replica change.
