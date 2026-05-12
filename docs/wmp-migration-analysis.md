# WMP Migration Analysis: Engine → go-wmp

**Version**: 0.3.0  
**Date**: 2026-05-12  
**Status**: Updated — HTTP+SSE as primary transport  
**Previous version**: websocket-protocol-spec.md (2026-02-18)

## Executive Summary

This document analyzes migrating the wallet backend's WebSocket engine
(`internal/engine/`) and the wallet frontend's WebSocket transport
(`OIDFlowWebSocketTransport`) to the WMP protocol implemented by
`github.com/sirosfoundation/go-wmp`, with **HTTP+SSE as the primary transport**.

### Why Not WebSockets?

The current WebSocket transport causes recurring operational problems:

1. **Mobile WebView redirects kill the connection** — OAuth redirects in OID4VCI
   flows navigate away from the page, destroying the WebSocket. This is the root
   cause of the reconnection bugs fixed in PR #126.
2. **Connection lifecycle complexity** — Reconnection logic (exponential backoff,
   budget tracking, foreground-aware reset) adds 400+ lines of fragile code.
3. **Tenant routing at handshake time** — WebSocket connections are long-lived, so
   tenant context must be established once and maintained. HTTP requests naturally
   carry tenant context per-request.
4. **Load balancer stickiness** — WebSocket connections must stay pinned to one
   backend instance, complicating scaling (hence the Redis session store).
5. **Proxy/firewall issues** — Some networks block WebSocket upgrades or have
   aggressive timeout policies.

The actual communication pattern (client starts flow → server streams progress →
client occasionally responds to prompts) is **textbook SSE + REST**. The only
"bidirectional" need is the sign request/response, which is a request-response
pattern — not streaming.

### Recommended Approach

**HTTP+SSE as primary transport** with WebSocket as optional fallback:

```
POST /wmp/rpc                     → JSON-RPC requests (flow.start, flow.action, etc.)
GET  /wmp/events?session_id=...   → SSE stream of server notifications (progress, sign_request, etc.)
```

This eliminates all WebSocket connection management while preserving the exact
same WMP protocol semantics. go-wmp already has an `httpsse` transport package.

## What Changed Since the February Spec

### Engine (go-wallet-backend)

| Area | February | Now |
|------|----------|-----|
| OID4VP | Stub | Fully implemented (DCQL matching, consent, VP signing) |
| Trust evaluation | Server-side only | Delegated to frontend via progress step + `trust_result` action |
| Credential matching | Not implemented | Privacy-preserving DCQL `match_request`/`match_response` |
| Issuer metadata | External fetch | `RegistryClient` with local resolution for registered issuers |
| Flow actions | `select_credential`, `consent` | + `trust_result`, `credentials_matched`, `decline`, `provide_pin`, `authorization_complete` |
| Session store | Memory only | + Redis option for horizontal scaling |

### go-wmp

| Area | February | Now |
|------|----------|-----|
| Methods | 14 | 19 (added `session.authenticate`, `message.status`, `flow.cancel`) |
| Profiles | Concept only | Implemented (`Profile`, `FlowHandler`, `MethodHandler`, `ResolveHandler`, `IdentifierResolver`) |
| OpenID4x | None | `openid4x` profile with OID4VCI/OID4VP flow routing, step constants, capability types |
| Session store | None | `SessionStore` interface + `MemorySessionStore` |
| Middleware | None | Implemented (chain of `MiddlewareFunc`) |
| Context | None | `ContextWithSender`, `ContextWithSession` propagation |
| Discovery | None | `DiscoverConfig`, `DiscoverConfigForDID`, `ExtractDomain` |
| Options | Fixed config | `PeerOption` pattern (`WithLogger`, `WithMaxMessageSize`) |
| Transport | WebSocket only | `Transport` interface (WS, HTTPS+SSE) |
| Tests | Minimal | 62.5% coverage, integration tests for all features |

### Frontend

| Area | February | Now |
|------|----------|-----|
| Transport | Single WS class | `IOIDFlowTransport` interface with WS, HTTP proxy, and direct implementations |
| OID4VP | Not wired | Fully wired (request parsing, DCQL matching, consent, VP signing) |
| Trust | Server-decided | Client-side trust evaluation with `trust_result` action callback |
| Reconnection | Basic | Exponential backoff with foreground/online-aware budget reset |
| Sign handler | Inline | `useWebSocketSignHandler` hook (single, batch, attestation proofs) |
| Match handler | None | Client-side DCQL query evaluator |

## Transport Architecture: HTTP+SSE

### How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           HTTP+SSE Transport                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Client                                Server                           │
│  ──────                                ──────                           │
│                                                                         │
│  POST /wmp/rpc ───────────────────────►  Handle JSON-RPC request        │
│    {method: "wmp.session.create"}        Return JSON-RPC response        │
│  ◄─────────────────────────────────────  {result: {session_id: "..."}}  │
│                                                                         │
│  GET /wmp/events?session_id=... ──────►  Open SSE stream                │
│  ◄─ event: notification ──────────────   Server pushes notifications    │
│     data: {method: "wmp.flow.progress",  (progress, sign_request,       │
│            params: {step: "..."}}         match_request, complete, etc.) │
│                                                                         │
│  POST /wmp/rpc ───────────────────────►  Handle action                  │
│    {method: "wmp.flow.action",           Return acknowledgment          │
│     params: {action: "sign_response"}}                                  │
│  ◄─────────────────────────────────────  {result: {status: "accepted"}} │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Why This Is Better

| Concern | WebSocket | HTTP+SSE |
|---------|-----------|----------|
| OAuth redirects | Connection dies, must reconnect + resume | SSE auto-reconnects with `Last-Event-ID`; POST requests are stateless |
| Tenant routing | Must establish at handshake, maintain for lifetime | Every POST carries `Authorization` + `X-Tenant-ID` headers |
| Load balancing | Sticky sessions required | Standard HTTP load balancing; SSE can reconnect to any instance |
| Mobile WebView | Connection lost on background/navigate | SSE reconnects on foreground; pending POSTs just retry |
| Proxy/firewall | Upgrade negotiation blocked by some | Standard HTTP/2, universally supported |
| Code complexity | 1200+ lines of connection management | ~200 lines (EventSource + fetch) |
| Debugging | Opaque binary frames | Standard HTTP requests visible in DevTools |
| Latency impact | ~20ms per frame | ~50ms per HTTP round-trip (irrelevant for user flows) |

### SSE Reconnection

The native browser `EventSource` API cannot send custom headers (no
`Authorization`, no `X-Tenant-ID`). We use **`@microsoft/fetch-event-source`**
(2.8k stars, MIT, ~3KB) which wraps `fetch()` to provide:

- Custom headers on the SSE connection
- Full control over reconnection strategy
- Built-in Page Visibility API integration (closes on tab hide, reconnects on
  visible with `Last-Event-ID`)
- `AbortController` support

```typescript
import { fetchEventSource } from '@microsoft/fetch-event-source';

const ctrl = new AbortController();
await fetchEventSource(`/wmp/events?session_id=${sessionId}`, {
  headers: {
    'Authorization': `Bearer ${token}`,
    'X-Tenant-ID': tenantId,
  },
  signal: ctrl.signal,
  onmessage(ev) {
    handleNotification(JSON.parse(ev.data));
  },
  onclose() {
    // Server closed — retry automatically
    throw new RetriableError();
  },
  onerror(err) {
    if (err instanceof FatalError) throw err; // stop retrying
    // Return retry interval in ms, or undefined for default
  },
});
```

The server includes event IDs in each SSE frame:

```
id: evt-42
event: notification
data: {"method":"wmp.flow.progress","params":{...}}
```

On reconnect, `fetch-event-source` sends `Last-Event-ID: evt-42` and the
server replays missed events.

This means **OAuth redirects are a non-issue** — when the user returns from the
authorization server, the SSE stream reconnects and the server replays any missed
progress events. The client then POSTs the authorization code as a normal action.

### Server-Side Implementation

The go-wmp `httpsse` package already provides the SSE transport. The backend
exposes two endpoints:

```go
// POST /wmp/rpc — handles JSON-RPC requests
func handleRPC(w http.ResponseWriter, r *http.Request) {
    sessionID := extractSession(r)  // from header or query
    tenantID := r.Header.Get("X-Tenant-ID")
    
    var req wmp.Request
    json.NewDecoder(r.Body).Decode(&req)
    
    // Dispatch to WMP peer/handler
    result, err := peer.HandleRequest(ctx, &req)
    
    // Return JSON-RPC response
    json.NewEncoder(w).Encode(result)
}

// GET /wmp/events — SSE stream for server→client notifications  
func handleEvents(w http.ResponseWriter, r *http.Request) {
    sessionID := r.URL.Query().Get("session_id")
    lastEventID := r.Header.Get("Last-Event-ID")
    
    flusher := w.(http.Flusher)
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    
    // Replay missed events if Last-Event-ID is set
    replayFrom(w, sessionID, lastEventID)
    
    // Stream new events
    for event := range session.Events() {
        fmt.Fprintf(w, "id: %s\nevent: notification\ndata: %s\n\n", event.ID, event.Data)
        flusher.Flush()
    }
}
```

### Frontend Implementation

The frontend transport becomes dramatically simpler:

```typescript
class OIDFlowHTTPSSETransport implements IOIDFlowTransport {
  private events: EventSource | null = null;
  private sessionId: string | null = null;
  
  async connect(token: string, tenantId: string): Promise<void> {
    // Create session via POST
    const result = await this.rpc('wmp.session.create', {
      wmp: { version: '0.1' },
      security: { mode: 'tls' }
    });
    this.sessionId = result.wmp.session_id;
    
    // Authenticate
    await this.rpc('wmp.session.authenticate', {
      wmp: { version: '0.1', session_id: this.sessionId },
      auth: { type: 'bearer', token }
    });
    
    // Open SSE stream for notifications (with auth headers)
    this.ctrl = new AbortController();
    fetchEventSource(`/wmp/events?session_id=${this.sessionId}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Tenant-ID': tenantId,
      },
      signal: this.ctrl.signal,
      onmessage: (ev) => this.handleNotification(JSON.parse(ev.data)),
      onclose: () => { throw new RetriableError(); },
    });
  }
  
  async startFlow(protocol: string, params: any): Promise<any> {
    return this.rpc('wmp.flow.start', {
      wmp: { version: '0.1', session_id: this.sessionId },
      flow_type: protocol,
      flow_id: crypto.randomUUID(),
      params,
    });
  }
  
  async sendAction(flowId: string, action: string, params: any): Promise<any> {
    return this.rpc('wmp.flow.action', {
      wmp: { version: '0.1', session_id: this.sessionId },
      flow_id: flowId,
      action,
      params,
    });
  }
  
  private async rpc(method: string, params: any): Promise<any> {
    const resp = await fetch('/wmp/rpc', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`,
        'X-Tenant-ID': this.tenantId,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: crypto.randomUUID(),
        method,
        params,
      }),
    });
    const result = await resp.json();
    if (result.error) throw new WMPError(result.error);
    return result.result;
  }
  
  private handleNotification(msg: any) {
    // Route to flow handlers based on msg.method
    switch (msg.method) {
      case 'wmp.flow.progress':
        this.onProgress(msg.params);
        break;
      case 'wmp.flow.complete':
        this.onComplete(msg.params);
        break;
      case 'wmp.flow.error':
        this.onError(msg.params);
        break;
    }
  }
}
```

Compare this to the current 1200-line `OIDFlowWebSocketTransport` with its
reconnection budget, foreground detection, ping/pong, and connection state machine.

### WebSocket as Fallback

WebSocket remains available as a fallback transport for:
- Native apps with persistent connections (iOS/Android wrappers)
- Long-running DIDComm conversations (future)
- Environments where SSE is unsupported (rare, but possible behind certain proxies)

The go-wmp `Transport` interface abstracts this — the same `Peer` and handler
logic works over either transport. The frontend's `IOIDFlowTransport` interface
similarly abstracts the transport choice.

### Event Replay and Flow Resumption

HTTP+SSE has a built-in mechanism for handling disconnects that WebSocket lacks:

1. Server assigns monotonic event IDs to each notification
2. On reconnect, browser sends `Last-Event-ID` header
3. Server replays all events since that ID

This means:
- **OAuth redirects**: User leaves page, comes back, SSE reconnects, server
  replays the `authorization_required` progress step. Client POSTs the auth code.
- **Mobile background**: App goes to background, SSE disconnects. On foreground,
  reconnect + replay. No lost events.
- **Network hiccup**: Browser auto-reconnects EventSource. Server replays from
  last confirmed event.

For longer disconnects (session timeout), the client uses `wmp.session.resume`
via POST to restore the full session state.

## Detailed Mapping

### Wire Protocol

| Engine (custom) | WMP (JSON-RPC 2.0) | Notes |
|----------------|---------------------|-------|
| `{"type":"handshake","app_token":"..."}` | `wmp.session.create` + `wmp.session.authenticate` | WMP separates session creation from auth |
| `{"type":"handshake_complete","session_id":"...","capabilities":[...]}` | `SessionCreateResult{WMP, Capabilities, Security}` | WMP capabilities are typed `map[string]json.RawMessage` |
| `{"type":"flow_start","protocol":"oid4vci",...}` | `wmp.flow.start` with `flow_type:"oid4vci"` | Direct map; WMP adds `timeout` parameter |
| `{"type":"flow_progress","step":"...","payload":{}}` | `wmp.flow.progress` notification | Direct map |
| `{"type":"flow_action","action":"...","payload":{}}` | `wmp.flow.action` request | WMP returns `FlowActionResult`; engine is fire-and-forget |
| `{"type":"flow_complete","credentials":[...]}` | `wmp.flow.complete` notification | WMP result is generic `json.RawMessage` |
| `{"type":"flow_error","error":{"code":"...","message":"..."}}` | `wmp.flow.error` notification | WMP uses integer codes; engine uses strings |
| `{"type":"sign_request","action":"...","params":{}}` | **No direct equivalent** | See "Sign Convention" below |
| `{"type":"sign_response","proof_jwt":"..."}` | **No direct equivalent** | See "Sign Convention" below |
| `{"type":"match_request","dcql_query":{}}` | **No direct equivalent** | See "Match Convention" below |
| `{"type":"match_response","matches":[...]}` | **No direct equivalent** | See "Match Convention" below |
| `{"type":"push","push_type":"credential_ready"}` | `wmp.message.deliver` notification | WMP is more general |
| `{"type":"error","code":"..."}` | JSON-RPC error response | Standard JSON-RPC framing |
| No cancel | `wmp.flow.cancel` request | WMP already has this |
| No resume | `wmp.session.resume` request | WMP already has this |

### Session Model

| Engine | WMP | Gap |
|--------|-----|-----|
| `Session{ID, UserID, TenantID, conn}` | `Session{ID, Participants, Capabilities, Security}` | **WMP needs UserID/TenantID** — or map via Participants |
| `userIndex` (1 active session per user) | No user→session index | Need to add or handle externally |
| JWT HMAC validation | `AuthObject{type, token, proof}` | WMP is more flexible (bearer, DPoP, mTLS, DID auth) |
| `SessionStore` with `GetByUser`, `List`, `Cleanup` | `SessionStore` with `Create`, `Get`, `Update`, `Delete` | **WMP needs**: `GetByUser`, `List`, `Cleanup` |
| `MaxPendingFlowsPerSession = 3` | No flow limit | Add via middleware |
| 120s idle timeout | No timeout management | Add via transport or middleware |
| Redis session store | Memory only | Need Redis implementation of `wmp.SessionStore` |

### Flow Handlers

| Engine | WMP | Compatibility |
|--------|-----|---------------|
| `FlowHandler` interface (Execute) | `FlowHandler` interface (StartFlow, HandleAction, etc.) | **Different models** — see below |
| `FlowHandlerFactory(flow, cfg, logger, ...)` | `Profile.Init(PeerContext)` | WMP is simpler; factory deps must be injected differently |
| `BaseHandler` (Progress, Error, Complete, RequestSign, RequestMatch) | No flow base handler | **GAP**: Need `FlowContext` helper for sending progress/sign/match |
| `Flow{ID, Protocol, SessionID, state, channels}` | `FlowStartParams` + profile tracking | Engine has richer per-flow state |
| Goroutine-per-flow (coroutine model) | Event-driven callbacks | **Fundamental difference** |

#### Coroutine vs. Event-Driven

The engine uses a **coroutine model**: each flow runs as a goroutine that
calls blocking helpers (`RequestSign`, `WaitForAction`) and progresses linearly:

```go
// Engine pattern (coroutine)
func (h *OID4VCIHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
    h.Progress("parsing_offer", nil)
    offer, err := parseOffer(msg.Offer)
    
    h.Progress("fetching_metadata", nil)
    metadata, err := fetchMetadata(offer.Issuer)
    
    h.Progress("evaluating_trust", trustReq)
    trustResult, err := h.WaitForAction(ctx)   // blocks
    
    h.Progress("generating_proof", nil)
    proof, err := h.RequestSign(ctx, "generate_proof", params)  // blocks
    
    credential, err := requestCredential(proof)
    h.Complete(credential)
    return nil
}
```

WMP uses an **event-driven model**: the profile receives discrete callbacks:

```go
// WMP pattern (event-driven)
func (p *Profile) StartFlow(ctx context.Context, params *FlowStartParams) (*FlowStartResult, error) {
    // Must return immediately; cannot block for sign/match
}

func (p *Profile) HandleAction(ctx context.Context, params *FlowActionParams) (*FlowActionResult, error) {
    // Receives each action as it arrives
}
```

#### Bridging Strategy

Use a **goroutine bridge** that converts WMP events into channel sends,
allowing the engine's coroutine-style handlers to run unchanged:

```go
type FlowBridge struct {
    peer     wmp.PeerContext
    actionCh chan *wmp.FlowActionParams
    signCh   chan *wmp.FlowActionParams
    matchCh  chan *wmp.FlowActionParams
}

// StartFlow launches the coroutine
func (b *FlowBridge) StartFlow(ctx context.Context, params *wmp.FlowStartParams) (*wmp.FlowStartResult, error) {
    go b.handler.Execute(ctx, toEngineMsg(params))
    return &wmp.FlowStartResult{...}, nil
}

// HandleAction routes to the appropriate channel
func (b *FlowBridge) HandleAction(ctx context.Context, params *wmp.FlowActionParams) (*wmp.FlowActionResult, error) {
    switch classifyAction(params.Action) {
    case "sign_response":
        b.signCh <- params
    case "match_response":
        b.matchCh <- params
    default:
        b.actionCh <- params
    }
    return &wmp.FlowActionResult{Status: "accepted"}, nil
}

// RequestSign sends a progress notification and blocks on signCh
func (b *FlowBridge) RequestSign(ctx context.Context, action string, signParams interface{}) (json.RawMessage, error) {
    peer.Notify(ctx, wmp.MethodFlowProgress, &wmp.FlowProgressParams{
        FlowID: b.flowID,
        Step:   "sign_request",
        Payload: marshalSignRequest(action, signParams),
    })
    select {
    case resp := <-b.signCh:
        return resp.Params, nil
    case <-time.After(30 * time.Second):
        return nil, ErrSignTimeout
    case <-ctx.Done():
        return nil, ctx.Err()
    }
}
```

This preserves the engine's linear flow logic while using WMP as the wire protocol.

### Sign Convention

WMP does not have dedicated `sign_request`/`sign_response` message types.
There are two options:

#### Option A: Flow Progress + Action (Recommended)

Use `wmp.flow.progress` as the "request" and `wmp.flow.action` as the "response":

```
Server → Client: wmp.flow.progress notification
{
  "wmp": {"version": "0.1", "session_id": "..."},
  "flow_id": "flow-123",
  "step": "sign_request",
  "payload": {
    "message_id": "sign-001",
    "action": "generate_proof",
    "params": {
      "audience": "https://issuer.example.com",
      "nonce": "n-0S6_WzA2Mj",
      "proof_type": "jwt"
    }
  }
}

Client → Server: wmp.flow.action request
{
  "wmp": {"version": "0.1", "session_id": "..."},
  "flow_id": "flow-123",
  "action": "sign_response",
  "params": {
    "message_id": "sign-001",
    "proof_jwt": "eyJ..."
  }
}
```

**Pros**: Uses existing WMP methods, no protocol extension needed.  
**Cons**: `flow.action` returns a result (synchronous), which means the server
acknowledges receiving the signature — this is actually correct behavior.

#### Option B: Custom Methods via MethodHandler

Register `wmp.sign.request` and `wmp.match.request` as custom methods:

```go
type SignProfile struct { ... }

func (p *SignProfile) Methods() []string {
    return []string{"wmp.sign.request", "wmp.match.request"}
}

func (p *SignProfile) HandleMethod(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
    // ...
}
```

**Pros**: Clean separation, explicit semantics.  
**Cons**: Adds methods outside the WMP spec; may confuse interop.

**Recommendation**: Option A. The `flow.progress` → `flow.action` round-trip
maps naturally to the engine's `RequestSign` → `sign_response` pattern. The
`step` field disambiguates sign requests from other progress notifications.

### Match Convention

Same pattern as signing — use flow progress/action:

```
Server → Client: wmp.flow.progress notification
{
  "flow_id": "flow-123",
  "step": "match_request",
  "payload": {
    "message_id": "match-001",
    "dcql_query": { ... }
  }
}

Client → Server: wmp.flow.action request
{
  "flow_id": "flow-123",
  "action": "match_response",
  "params": {
    "message_id": "match-001",
    "matches": [
      {
        "credential_query_id": "id_card",
        "credential_id": "local-cred-1",
        "format": "vc+sd-jwt",
        "vct": "https://example.com/id-card",
        "available_claims": ["given_name", "family_name"]
      }
    ]
  }
}
```

### Trust Evaluation Convention

The engine delegates trust evaluation to the frontend via a progress step.
This maps directly:

```
Server → Client: wmp.flow.progress notification
{
  "flow_id": "flow-123",
  "step": "evaluating_trust",
  "payload": {
    "subject_id": "https://issuer.example.com",
    "subject_type": "issuer",
    "key_material": { ... }
  }
}

Client → Server: wmp.flow.action request
{
  "flow_id": "flow-123",
  "action": "trust_result",
  "params": {
    "trusted": true,
    "name": "Example University",
    "framework": "eudi"
  }
}
```

Alternatively, trust resolution could use `wmp.resolve` with `type: "trust"`,
which is already supported by the resolve handler system. However, the current
engine pattern of embedding trust evaluation in the flow is simpler for the
frontend (no need to handle a separate resolve call outside the flow context).

### Error Code Mapping

| Engine (string) | WMP (integer) | Mapping |
|-----------------|---------------|---------|
| `AUTH_FAILED` | `ErrNotAuthorized (-31002)` | Direct |
| `INVALID_MESSAGE` | `ErrInvalidRequest (-32600)` | Standard JSON-RPC |
| `UNKNOWN_FLOW` | `ErrFlowError (-31006)` | Subsume under flow error |
| `FLOW_TIMEOUT` | `ErrFlowError (-31006)` | With timeout data |
| `OFFER_PARSE_ERROR` | `ErrInvalidParams (-32602)` | Standard JSON-RPC |
| `OFFER_FETCH_ERROR` | `ErrFlowError (-31006)` | With fetch error data |
| `METADATA_FETCH_ERROR` | `ErrFlowError (-31006)` | With fetch error data |
| `UNTRUSTED_ISSUER` | `ErrFlowError (-31006)` | With trust data |
| `UNTRUSTED_VERIFIER` | `ErrFlowError (-31006)` | With trust data |
| `AUTHORIZATION_FAILED` | `ErrNotAuthorized (-31002)` | Direct |
| `TOKEN_ERROR` | `ErrFlowError (-31006)` | With token error data |
| `CREDENTIAL_ERROR` | `ErrFlowError (-31006)` | With credential error data |
| `SIGN_TIMEOUT` | `ErrFlowError (-31006)` | With timeout data |
| `SIGN_ERROR` | `ErrSignatureInvalid (-31010)` | Direct |
| `PRESENTATION_ERROR` | `ErrFlowError (-31006)` | With presentation error data |
| `INTERNAL_ERROR` | `ErrInternalError (-32603)` | Standard JSON-RPC |
| `TOO_MANY_REQUESTS` | `ErrRateLimited (-31007)` | Direct |

**Observation**: Most engine-specific error codes collapse into `ErrFlowError`
with structured `data` payloads. This is actually cleaner — the flow error data
carries the domain-specific detail, while the code indicates the error class.

The engine's `UserFacingMessage()` function maps to the WMP `ErrorMessage()` pattern.

## Migration Plan

### Phase 1: go-wmp HTTP+SSE Transport (no engine changes)

**Goal**: Make go-wmp's `httpsse` transport production-ready for the engine.

| Task | Effort | Priority |
|------|--------|----------|
| Implement event ID tracking and replay in `httpsse` transport | Medium | P0 |
| Add `FlowContext` helper (Progress, RequestSign, RequestMatch via channels) | Medium | P0 |
| Extend `SessionStore` with `GetByUser`, `List`, `Cleanup` | Small | P0 |
| Add `Session.UserID` / `Session.TenantID` (or use Participants) | Small | P0 |
| Add per-session event buffer for SSE replay | Medium | P0 |
| Add flow concurrency limit middleware | Small | P1 |
| Add session TTL / idle expiry | Small | P1 |
| Implement Redis `SessionStore` | Medium | P1 |

### Phase 2: Backend HTTP+SSE Endpoints

**Goal**: Expose WMP over HTTP+SSE alongside existing WebSocket engine.

| Task | Effort | Priority |
|------|--------|----------|
| Add `POST /wmp/rpc` endpoint (JSON-RPC dispatch to `wmp.Peer`) | Medium | P0 |
| Add `GET /wmp/events` SSE endpoint (session-scoped notification stream) | Medium | P0 |
| Implement `FlowBridge` (goroutine bridge for engine coroutine handlers) | Medium | P0 |
| Wire engine `FlowHandlerFactory` to WMP `Profile` registration | Small | P0 |
| Map engine `HandshakeMessage` to `wmp.session.create` + `wmp.session.authenticate` | Small | P0 |
| JWT auth middleware for `/wmp/rpc` and `/wmp/events` | Small | P0 |
| Tenant extraction from request headers | Small | P1 |
| Map engine error codes to WMP error codes | Small | P1 |
| Rate limiting middleware | Small | P1 |

### Phase 3: Frontend HTTP+SSE Transport

**Goal**: Implement `IOIDFlowTransport` backed by HTTP+SSE.

| Task | Effort | Priority |
|------|--------|----------|
| `OIDFlowHTTPTransport` class (~200 LoC: fetch + EventSource) | Medium | P0 |
| JSON-RPC 2.0 request/response helpers | Small | P0 |
| Map existing sign handler to `flow.action` with action `sign_response` | Small | P0 |
| Map existing match handler to `flow.action` with action `match_response` | Small | P0 |
| Map incoming SSE `flow.progress` to existing event callbacks | Small | P0 |
| Handle `Last-Event-ID` for reconnection after OAuth redirect | Small | P0 |
| Transport selection: prefer HTTP+SSE, fall back to WebSocket | Small | P1 |
| Add `wmp.flow.cancel` support | Small | P1 |
| Feature flag for gradual rollout | Small | P1 |
| Remove old WebSocket transport (after validation) | Small | P2 |

### Phase 4: Cleanup and Optimization

**Goal**: Remove WebSocket dependency for standard web flows.

| Task | Effort | Priority |
|------|--------|----------|
| Remove `OIDFlowWebSocketTransport` (or keep as fallback for native apps) | Small | P1 |
| Remove gorilla/websocket dependency from engine path | Small | P1 |
| Deprecate v1 WebSocket signing proxy | Small | P2 |
| Implement HTTP/2 server push for notifications (optional optimization) | Medium | P3 |

## What WMP + HTTP+SSE Gives Us for Free

Features we gain from this migration:

1. **Survives OAuth redirects** — SSE auto-reconnects with `Last-Event-ID` replay.
   The root cause of PR #126 bugs ceases to exist.
2. **No connection management** — browser handles EventSource reconnection natively.
   Eliminates 400+ lines of reconnection logic.
3. **Standard HTTP semantics** — every request carries auth + tenant headers.
   No handshake-time context establishment.
4. **Standard load balancing** — no sticky sessions. SSE reconnects can hit any
   backend instance (session state in Redis).
5. **DevTools visibility** — all requests visible in Network tab. SSE events are
   inspectable. No WebSocket frame debugging needed.
6. **Session resume** — `wmp.session.resume` with `last_message_id` for clean
   recovery from extended disconnects.
7. **Flow cancel** — `wmp.flow.cancel` with reason codes (user_cancelled, timeout).
8. **Capability negotiation** — dynamic `wmp.capability.update/list`.
9. **Endpoint discovery** — `.well-known/wmp-configuration` for multi-domain deploys.
10. **Middleware chain** — composable auth, rate limiting, logging, tenant isolation.
11. **Profile plugins** — clean extension for ISO 18013, DIDComm without core changes.
12. **Transport fallback** — WebSocket available for native apps that benefit from
    persistent connections.

## What Needs Careful Handling

### 1. Tenant Isolation

The engine has `TenantID` baked into sessions, propagated via `X-Tenant-ID`
headers on internal service calls. WMP has no tenant concept.

**With HTTP+SSE this is simpler**: every POST to `/wmp/rpc` carries the
`X-Tenant-ID` header. The SSE endpoint `/wmp/events` receives it as a query
parameter or header on connection. No need to establish tenant at handshake
and maintain it — it's on every request.

```go
func TenantMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tenantID := r.Header.Get("X-Tenant-ID")
        if tenantID == "" {
            http.Error(w, "missing tenant", http.StatusBadRequest)
            return
        }
        ctx := context.WithValue(r.Context(), tenantKey, tenantID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

### 2. Signing Timeout Semantics

The engine has a 30-second hard timeout on sign requests. With HTTP+SSE:
- Server sends sign request via SSE notification
- Client computes signature
- Client POSTs `wmp.flow.action` with the signed result

The flow handler's goroutine bridge still enforces the 30s timeout on its
channel wait. If the client doesn't POST back in time, the flow errors.

This is actually more robust than WebSocket — if the WebSocket disconnects
during signing, the sign is lost. With HTTP+SSE, the client can POST the
sign response even if the SSE stream briefly disconnected and reconnected.

### 3. Trust Evaluation Round-Trip

Trust evaluation currently works as:
1. Engine sends `evaluating_trust` progress step (→ SSE notification)
2. Frontend evaluates trust (calls `/v1/evaluate` or local logic)
3. Frontend sends `trust_result` action (→ POST `/wmp/rpc`)

This maps directly — no change in semantics, just transport.

### 4. Legacy v1 Protocol

The v1 WebSocket protocol (`internal/websocket/`) is still in use for the
legacy signing proxy. This is independent of the WMP migration — it should
be deprecated separately once all clients use the v2 engine flows.

### 5. Frontend Transport Interface

The frontend's `IOIDFlowTransport` interface abstracts the transport layer.
The new `OIDFlowHTTPTransport` implements this same interface, making the
migration transparent to the rest of the frontend:

```typescript
class OIDFlowHTTPTransport implements IOIDFlowTransport {
  // fetch() for requests, EventSource for notifications
  // Same IOIDFlowTransport callbacks as WebSocket version
}
```

### 6. SSE Connection Limits

Browsers limit concurrent SSE connections per domain (typically 6 per domain
in HTTP/1.1). Mitigations:
- Use HTTP/2 (multiplexed, no per-domain limit)
- One SSE stream per session (not per flow)
- The wallet has only one active session at a time

With HTTP/2 this is a non-issue. The backend should enforce HTTP/2 for the
SSE endpoint.

### 7. Event Buffer Size

The server must buffer events for replay on SSE reconnect. Considerations:
- Buffer per session, bounded (e.g., last 100 events or last 5 minutes)
- Events older than the buffer are lost; client must use `wmp.session.resume`
- Flows are typically short (< 30s for OID4VCI), so buffer is small
- For deferred credentials (hours/days), use `wmp.message.poll` on reconnect

## Recommended Sequence

```
Week 1-2: go-wmp HTTP+SSE hardening (Phase 1)
  ├─ Event ID tracking and replay in httpsse transport
  ├─ Per-session event buffer
  ├─ FlowContext helper with channel-based sign/match
  ├─ SessionStore extensions (GetByUser, List, Cleanup)
  └─ Session tenant/user fields + Redis SessionStore

Week 3-4: Backend HTTP+SSE endpoints (Phase 2)
  ├─ POST /wmp/rpc endpoint with JSON-RPC dispatch
  ├─ GET /wmp/events SSE endpoint with reconnect replay
  ├─ FlowBridge implementation (goroutine ↔ WMP events)
  ├─ JWT auth + tenant middleware
  └─ Run alongside existing WebSocket engine (feature flag)

Week 5-6: Frontend HTTP+SSE transport (Phase 3)
  ├─ OIDFlowHTTPTransport (fetch + EventSource, ~200 LoC)
  ├─ Sign/match/trust via flow.action
  ├─ SSE reconnection with Last-Event-ID
  └─ Feature-flagged rollout (HTTP+SSE vs WebSocket)

Week 7: Integration testing
  ├─ End-to-end OID4VCI flow via HTTP+SSE
  ├─ End-to-end OID4VP flow via HTTP+SSE
  ├─ OAuth redirect survival (the key test case)
  └─ Mobile WebView background/foreground cycle

Week 8: Cleanup
  ├─ Default transport = HTTP+SSE
  ├─ WebSocket transport → fallback only
  ├─ Remove feature flags
  └─ Update documentation
```

## Open Questions

1. ~~Should the SSE stream use `text/event-stream` or fetch streaming?~~
   **Decided**: Use `@microsoft/fetch-event-source` (~3KB, MIT, from Azure).
   Wraps `fetch()` to parse SSE streams with full header control, custom
   reconnection, and built-in Page Visibility API integration. No token-in-URL
   needed — `Authorization` and `X-Tenant-ID` headers on every SSE connection.

2. **Event buffer sizing and eviction policy?**
   Options: fixed count (100 events), time-based (5 min), or flow-scoped
   (keep events for active flows only). Need to balance memory vs replay.
   **Leaning toward**: Per-session ring buffer of 100 events.

3. **Should tenant context be a WMP concept or application-level?**
   Multi-tenant wallets are common. Could add `wmp.session.create` param
   for tenant or keep as HTTP header (transparent to WMP).
   **Leaning toward**: HTTP header (X-Tenant-ID), extracted in middleware,
   injected into WMP context. Keeps WMP protocol clean.

4. **When should the WebSocket transport be fully removed?**
   Native iOS/Android wrappers may benefit from persistent connections.
   **Leaning toward**: Keep WebSocket as opt-in fallback indefinitely,
   remove only if no clients use it after 6 months.

5. **Should `wmp.flow.progress` with `step: "sign_request"` be promoted
   to a first-class WMP method (`wmp.sign.request`)?**
   Explicit methods improve interop but add protocol surface area.
   **Leaning toward**: Keep as flow progress/action — it's more flexible
   and doesn't require WMP spec changes.
