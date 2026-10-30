package engine

// WMP bridge. go-wmp owns the protocol: session create, resume, expiry and the
// resumption token (wmp.SessionService), the authenticated HTTP+SSE server with
// event log, replay redaction and the 410 gap (httpsse.NewSecuredServerHandler),
// flow routing, sub-flows (RequestSign, RequestMatch), capability gating and the
// orchestrator's answers to wmp.message.* (-31008). This file is only the seam
// to the engine:
//
//   - Principal: the validated token (subject, tenant, TAC, jti) as a
//     wmp.Principal. HTTP bearer extraction is confined to Authenticate; every
//     other function takes the Principal from the context, so an in-process
//     caller (see NewSessionHandler) drives the same engine without a
//     *http.Request.
//   - Hooks: a WMP session owns one engine Session for its life.
//   - wmp_flow.go translates between the engine's messages and WMP flows.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/httpsse"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"go.uber.org/zap"
)

// Public paths of the WMP endpoints, advertised by the discovery document.
//
// go-wmp's HTTPS+SSE client takes ONE base URL, POSTs JSON-RPC to it and opens
// SSE at base + "/events", so the stream is also served at WMPRPCPath +
// "/events" (WMPClientEventsPath). WMPEventsPath remains as an alias.
const (
	WMPRPCPath          = "/api/v2/wallet/rpc"
	WMPEventsPath       = "/api/v2/wallet/events"
	WMPClientEventsPath = WMPRPCPath + "/events"
)

const (
	// maxWMPSessionsPerToken bounds live WMP sessions per bearer token. Anonymous
	// tokens are not indexed by user, so without it one token could create
	// unlimited sessions.
	maxWMPSessionsPerToken = 10

	// maxWMPSessionTTL caps the lifetime a client may request for a session.
	maxWMPSessionTTL = 24 * time.Hour
	// defaultWMPSessionTTL applies when the client names none.
	defaultWMPSessionTTL = time.Hour
	// wmpResumptionTTL is the lifetime of a resumption token.
	wmpResumptionTTL = 10 * time.Minute

	// maxWMPLoggedEvents and maxWMPEventBytes bound the per-session event log
	// that serves Last-Event-ID replay.
	maxWMPLoggedEvents = 200
	maxWMPEventBytes   = 4 << 20

	// maxFlowIDLength limits client-supplied flow IDs to prevent memory abuse.
	maxFlowIDLength = 128

	// defaultFlowTimeout is the server-side default, and the cap, for the
	// timeout a client may name in wmp.flow.start.
	defaultFlowTimeout = 5 * time.Minute

	// msgWMPShuttingDown is the answer to a request that arrives while the
	// adapter drains.
	msgWMPShuttingDown = "server shutting down"

	// wmpOrphanSweepInterval is how often engine sessions whose WMP session has
	// left the store are ended.
	wmpOrphanSweepInterval = time.Minute
)

// wmpClaims is what Principal.Claims carries: the validated token. go-wmp never
// looks inside it. The TAC in it is the TAC of the token that authenticated the
// request being served, so every request is judged by its own token, never by
// one cached at session creation.
type wmpClaims struct {
	UserID   string
	TenantID string
	TokenID  string // jti; may be empty
	TAC      claims.TAC
}

// NewWMPPrincipal is the Principal of a validated token. It is the seam for a
// caller that has its own token validation (an in-process embedder): put the
// result in the context of the Peer or SessionService calls with
// wmp.ContextWithPrincipal. A token that names neither a user nor a jti
// yields a Principal that owns nothing (go-wmp refuses it).
func NewWMPPrincipal(userID, tenantID, tokenID string, tac claims.TAC) wmp.Principal {
	subject := userID
	if subject == "" && tokenID != "" {
		// Anonymous sessions are told apart only by jti.
		subject = "jti:" + tokenID
	}
	return wmp.Principal{
		Subject: subject,
		Tenant:  normalizeTenant(tenantID),
		Claims:  &wmpClaims{UserID: userID, TenantID: normalizeTenant(tenantID), TokenID: tokenID, TAC: tac},
	}
}

// wmpClaimsFrom returns the claims of the Principal in ctx; ok is false when
// there is none or it was not made by NewWMPPrincipal (fail closed).
func wmpClaimsFrom(ctx context.Context) (*wmpClaims, bool) {
	p, ok := wmp.PrincipalFromContext(ctx)
	if !ok {
		return nil, false
	}
	c, ok := p.Claims.(*wmpClaims)
	return c, ok && c != nil
}

// WMPAdapter exposes the engine over WMP.
type WMPAdapter struct {
	manager *Manager
	logger  *zap.Logger
	// bearerToken extracts the bearer credential from an HTTP request. It is
	// injected because the engine cannot import pkg/middleware, and it is used
	// by Authenticate only.
	bearerToken func(*http.Request) string

	svc    *wmp.SessionService
	events httpsse.EventLog
	server *httpsse.ServerHandler

	// inboundMessages and inboundRefused count wmp.message.* an orchestrator
	// Peer intercepted (see ObserveInboundMessage).
	inboundMessages atomic.Int64
	inboundRefused  atomic.Int64

	mu          sync.Mutex
	sessions    map[string]*wmpSession // by WMP session ID
	tokenSlots  map[string]int         // live sessions per bearer token
	externalURL string
	draining    bool

	stopOnce sync.Once
	stopCh   chan struct{}
	loopDone chan struct{}
}

// wmpSession ties a WMP session to the engine Session it owns.
type wmpSession struct {
	id      string
	session *Session
	tr      *wmpTransport
	release func() // returns the session budget; idempotent
}

// NewWMPAdapter creates the adapter and its secured server. Register the flow
// handlers on the manager first: the capabilities offered to clients follow
// them.
func NewWMPAdapter(manager *Manager, logger *zap.Logger, bearerToken func(*http.Request) string) *WMPAdapter {
	a := &WMPAdapter{
		manager:     manager,
		logger:      logger,
		bearerToken: bearerToken,
		events:      httpsse.NewMemoryEventLog(maxWMPLoggedEvents, maxWMPEventBytes),
		sessions:    make(map[string]*wmpSession),
		tokenSlots:  make(map[string]int),
		stopCh:      make(chan struct{}),
		loopDone:    make(chan struct{}),
	}
	a.svc = wmp.NewSessionService(wmp.SessionServiceConfig{
		Store:         wmp.NewMemorySessionStore(),
		Capabilities:  a.negotiate,
		SecurityModes: []string{"tls"}, // the engine terminates TLS at the edge; no MLS
		DefaultTTL:    defaultWMPSessionTTL,
		MaxTTL:        maxWMPSessionTTL,
		ResumptionTTL: wmpResumptionTTL,
		Replay:        httpsse.ReplayerFor(a.events),
		ExpireHooks:   []wmp.SessionExpirer{wmpExpirer{a}},
	})
	a.server = httpsse.NewSecuredServerHandler(httpsse.ServerConfig{
		Service:    a.svc,
		NewHandler: a.NewSessionHandler,
		Stream:     httpsse.StreamConfig{Log: a.events},
	})
	go a.sweepOrphans()
	return a
}

// Authenticate establishes the Principal of an HTTP request from its bearer
// token. It is the only place a *http.Request is read; the Principal then
// travels in the context.
func (a *WMPAdapter) Authenticate(r *http.Request) (wmp.Principal, error) {
	token := a.bearerToken(r)
	if token == "" {
		return wmp.Principal{}, errors.New("missing bearer token")
	}
	return a.PrincipalForToken(r.Context(), token)
}

// PrincipalForToken validates token with the engine's rules (signature, audience,
// revocation) and returns its Principal. Called on every request, so a revoked
// token stops working at once.
func (a *WMPAdapter) PrincipalForToken(ctx context.Context, token string) (wmp.Principal, error) {
	id, err := a.manager.validateTokenAuth(ctx, token)
	if err != nil {
		a.logger.Warn("WMP authentication failed", zap.Error(err))
		return wmp.Principal{}, err
	}
	p := NewWMPPrincipal(id.UserID, id.TenantID, id.JTI, id.TAC)
	if p.Key() == "" {
		return wmp.Principal{}, errors.New("anonymous token without jti cannot own a session")
	}
	return p, nil
}

// ServeHTTP serves the WMP endpoints (POST JSON-RPC, GET event stream): it
// authenticates the request, then serves it as ServeAuthenticated does.
func (a *WMPAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.isDraining() {
		http.Error(w, msgWMPShuttingDown, http.StatusServiceUnavailable)
		return
	}
	p, err := a.Authenticate(r)
	if err != nil || p.Key() == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	a.ServeAuthenticated(w, r, p)
}

// wmpRoute is the part of a JSON-RPC message go-wmp routes on: the sessions it
// names in the params.
type wmpRoute struct {
	Params struct {
		WMP       wmpSessionRef `json:"wmp"`
		SessionID string        `json:"session_id"`
	} `json:"params"`
}

type wmpSessionRef struct {
	SessionID string `json:"session_id"`
}

// maxWMPBody bounds the POST body read to tell a response from a request.
const maxWMPBody = 1 << 20

// ServeAuthenticated serves a request for an already authenticated Principal
// (see NewWMPPrincipal), skipping the bearer-token step.
//
// go-wmp checks that the Principal owns the session. Two kinds of message reach
// a session without passing the Peer's request guard, so they are checked here:
// attaching an event stream (everything the session emits, issued credentials
// included, goes to it) and a JSON-RPC response (it answers a sign or match
// request and can fail the flow that waits for it). Both need a token that
// grants every permission the session was created with (CheckSessionAccess).
func (a *WMPAdapter) ServeAuthenticated(w http.ResponseWriter, r *http.Request, p wmp.Principal) {
	if a.isDraining() {
		http.Error(w, msgWMPShuttingDown, http.StatusServiceUnavailable)
		return
	}
	ids := []string{r.Header.Get("Wmp-Session-Id")}
	switch r.Method {
	case http.MethodGet:
		ids = append(ids, r.URL.Query().Get("session_id"))
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, maxWMPBody+1))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		if len(body) > maxWMPBody {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		// go-wmp's classification: anything with a result or an error is a
		// response, whatever else it carries; what does not decode is gated too.
		msg, err := wmp.DecodeMessage(body)
		if err != nil || msg.IsResponse() {
			// The sources go-wmp routes on: the header and the session named in
			// the params (a response has none of its own).
			var named wmpRoute
			_ = json.Unmarshal(body, &named)
			ids = append(ids, named.Params.WMP.SessionID, named.Params.SessionID)
		} else {
			ids = nil // a request: the Peer's guard judges it
		}
	}
	for _, id := range ids {
		if id != "" && !a.CheckSessionAccess(p, id) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	a.server.ServeAuthenticated(w, r, p)
}

// CheckSessionAccess reports whether p may attach an event stream to, or answer a
// request of, the session: the TAC of p's token must grant every permission the
// session was created with. It refuses only the owner whose token is too weak.
// A session that is unknown, expired or owned by someone else passes: go-wmp
// answers all three alike (-31000 or -31001), so this check is no existence
// oracle. An in-process embedder that feeds responses to a Peer itself calls it
// first.
func (a *WMPAdapter) CheckSessionAccess(p wmp.Principal, sessionID string) bool {
	ws := a.session(sessionID)
	if ws == nil {
		return true
	}
	if rec, ok := a.svc.Store().Get(sessionID); !ok || rec.IsExpired() || !rec.OwnedBy(p.Key()) {
		return true
	}
	cl, ok := p.Claims.(*wmpClaims)
	return ok && cl != nil && ws.session.TAC.IsSubsetOf(cl.TAC)
}

// Service is the SessionService, for a caller that drives sessions in-process
// over a wmp.Peer (see NewSessionHandler).
func (a *WMPAdapter) Service() *wmp.SessionService { return a.svc }

// NewSessionHandler is the httpsse.ServerConfig.NewHandler of the engine: the
// Handler and Peer options of one session. It reads no HTTP request. An
// in-process caller builds its Peer from it:
//
//	h, opts := adapter.NewSessionHandler(ctx, principal, sessionID)
//	peer := wmp.NewPeer(transport, h, opts...)
//
// and serves it with a context carrying the Principal.
//
// sessionID is empty for the throw-away Peer that dispatches
// wmp.session.create, which cannot know the ID yet.
func (a *WMPAdapter) NewSessionHandler(_ context.Context, _ wmp.Principal, sessionID string) (wmp.Handler, []wmp.PeerOption) {
	prof := newWMPFlowProfile(a, sessionID)
	h := &wmpHandler{SessionHandler: wmp.NewSessionHandler(a.svc), a: a, sessionID: sessionID}
	opts := []wmp.PeerOption{
		wmp.WithAuthorizer(prof.guard),
		wmp.WithProfile(prof),
		// A tls-mode orchestrator relays nothing: wmp.message.deliver requests
		// are answered -31008, ack and status are logged and dropped.
		wmp.WithOrchestratorMessages(wmp.OrchestratorMessageOptions{Observer: a}),
		// The store is the session service's: the Peer reads the negotiated
		// capabilities and the version from it.
		wmp.WithSessionStore(a.svc.Store()),
	}
	if sessionID != "" {
		opts = append(opts, wmp.WithSessionIdentity(sessionID, ""))
	}
	return h, opts
}

// ObserveInboundMessage implements wmp.InboundMessageObserver.
func (a *WMPAdapter) ObserveInboundMessage(_ context.Context, _ string, refused bool) {
	a.inboundMessages.Add(1)
	if refused {
		a.inboundRefused.Add(1)
	}
}

// negotiate grants the offered capabilities the engine serves, with the
// engine's parameters. transaction_data needs a version the client offered, not
// merely the name.
func (a *WMPAdapter) negotiate(_ context.Context, offered wmp.Capabilities) wmp.Capabilities {
	out := wmp.Capabilities{}
	for name, params := range a.serverCapabilities() {
		if _, ok := offered[name]; !ok {
			continue
		}
		if name == wmp.CapabilityTransactionData && !offered.OffersTransactionData(wmp.TransactionDataVersion1) {
			continue
		}
		out[name] = params
	}
	return out
}

// serverCapabilities is what the engine can serve over WMP, from the flow
// handlers registered on the manager (OpenID4x profile 2.1 to 2.3, Core 5.8).
func (a *WMPAdapter) serverCapabilities() wmp.Capabilities {
	var cfg openid4x.CapabilityConfig
	a.manager.handlersMu.RLock()
	_, hasVCI := a.manager.flowHandlers[ProtocolOID4VCI]
	_, hasVP := a.manager.flowHandlers[ProtocolOID4VP]
	_, hasVCTM := a.manager.flowHandlers[ProtocolVCTM]
	a.manager.handlersMu.RUnlock()

	if hasVCI {
		cfg.OID4VCI = &openid4x.OID4VCICapability{
			SupportedGrants:  []string{"authorization_code", "pre-authorized_code"},
			SupportedFormats: openid4x.AllFormats(),
		}
		// The engine retains the issuance context for a notification after the
		// completion (OpenID4x 2.4, 3.4); a session that offers the capability
		// gets it.
		cfg.CredentialNotification = &openid4x.CredentialNotificationCap{
			Events:            notificationEvents(),
			ContextTTLSeconds: int(notificationContextTTL / time.Second),
		}
	}
	if hasVP {
		cfg.OID4VP = &openid4x.OID4VPCapability{
			SupportedResponseModes: []string{ResponseModeDirectPost, ResponseModeDirectPostJWT},
			SupportedFormats:       openid4x.AllFormats(),
		}
		// The engine forwards transaction_data only to a client that offers it
		// (see wmpFlowProfile.features).
		cfg.TransactionData = &wmp.TransactionDataCap{Versions: []int{wmp.TransactionDataVersion1}}
	}
	caps, err := openid4x.CapabilityDescriptors(cfg)
	if err != nil { // a static descriptor: cannot fail
		a.logger.Error("WMP capability descriptors", zap.Error(err))
		caps = wmp.Capabilities{}
	}
	flows, _ := json.Marshal(map[string]int{"max_concurrent": MaxPendingFlowsPerSession})
	caps["flows"] = flows
	if hasVCTM {
		// VCTM is resolved with wmp.resolve, not a flow (OpenID4x 2).
		resolve, _ := json.Marshal(wmp.ResolveCap{SupportedTypes: []string{wmp.ResolveTypeVCTM}})
		caps["resolve"] = resolve
	}
	return caps
}

// --- session lifecycle -------------------------------------------------------

// create makes the engine Session of a new WMP session.
func (a *WMPAdapter) create(ctx context.Context, sess *wmp.Session) error {
	cl, ok := wmpClaimsFrom(ctx)
	if !ok {
		return wmp.NewRPCError(wmp.ErrNotAuthorized, nil)
	}
	release, ok := a.reserveSlot(cl)
	if !ok {
		a.logger.Warn("WMP session.create rejected: session limit reached")
		return wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{"reason": "too many sessions"})
	}
	label := sess.ID
	if cl.UserID != "" {
		label = cl.UserID
	}
	tr := &wmpTransport{a: a, id: sess.ID, flows: make(map[string]*wmpFlow)}
	session := &Session{
		ID:            sess.ID,
		UserID:        cl.UserID,
		TenantID:      cl.TenantID,
		TAC:           cl.TAC,
		transport:     tr,
		flows:         make(map[string]*Flow),
		logger:        a.logger.With(zap.String("session", label[:min(8, len(label))])),
		closeCh:       make(chan struct{}, 1),
		notifications: newNotificationContextStore(),

		consentObserver: tr,
	}
	ws := &wmpSession{id: sess.ID, session: session, tr: tr, release: release}

	a.mu.Lock()
	if a.draining {
		a.mu.Unlock()
		release()
		return wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{"reason": msgWMPShuttingDown})
	}
	a.sessions[sess.ID] = ws
	a.mu.Unlock()

	// A false return means the user was revoked since token validation.
	if !a.manager.registerSession(session) {
		a.mu.Lock()
		delete(a.sessions, sess.ID)
		a.mu.Unlock()
		release()
		return wmp.NewRPCError(wmp.ErrNotAuthorized, map[string]string{"reason": "invalid or expired token"})
	}
	return nil
}

// reserveSlot claims a session against the engine's global connection limit
// (shared with WebSocket connections) and the per-token limit. The returned
// func gives it back once.
func (a *WMPAdapter) reserveSlot(cl *wmpClaims) (func(), bool) {
	key := "jti:" + cl.TokenID
	if cl.TokenID == "" {
		key = "user:" + cl.TenantID + ":" + cl.UserID
	}
	a.mu.Lock()
	if a.tokenSlots[key] >= maxWMPSessionsPerToken {
		a.mu.Unlock()
		return nil, false
	}
	a.tokenSlots[key]++
	a.mu.Unlock()

	giveBack := func() {
		a.mu.Lock()
		if a.tokenSlots[key] <= 1 {
			delete(a.tokenSlots, key)
		} else {
			a.tokenSlots[key]--
		}
		a.mu.Unlock()
	}
	if a.manager.activeConnections.Add(1) > maxConnections {
		a.manager.activeConnections.Add(-1)
		giveBack()
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			giveBack()
			a.manager.activeConnections.Add(-1)
		})
	}, true
}

// session returns the WMP session's engine binding, or nil.
func (a *WMPAdapter) session(id string) *wmpSession {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessions[id]
}

// endSession ends the engine side of a WMP session. When dropWMP is set (the
// engine ended it: user revoked, superseded, shutdown) the WMP side goes too:
// the stored session is deleted and the server's Peer and streams closed. A
// session the client closed or that expired is already gone from the store, and
// the server has dropped it itself.
func (a *WMPAdapter) endSession(id string, dropWMP bool) {
	a.mu.Lock()
	ws := a.sessions[id]
	delete(a.sessions, id)
	a.mu.Unlock()
	if ws != nil {
		ws.session.endSession()
		a.manager.unregisterSession(ws.session)
		ws.release()
	}
	if dropWMP {
		_ = a.svc.Store().Delete(id)
		a.server.Drop(id)
	}
}

// wmpExpirer ends the engine session of a session go-wmp expired.
type wmpExpirer struct{ a *WMPAdapter }

func (e wmpExpirer) OnSessionExpire(_ context.Context, s *wmp.Session) { e.a.endSession(s.ID, false) }

// sweepOrphans ends engine sessions whose WMP session is gone from the store
// (a create that failed after the engine session existed, a deletion by
// another path), so none outlives its WMP session.
func (a *WMPAdapter) sweepOrphans() {
	defer close(a.loopDone)
	t := time.NewTicker(wmpOrphanSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-t.C:
			a.reapOrphans()
		}
	}
}

// reapOrphans ends the engine sessions whose stored WMP session is gone or
// expired.
func (a *WMPAdapter) reapOrphans() {
	a.mu.Lock()
	ids := make([]string, 0, len(a.sessions))
	for id := range a.sessions {
		ids = append(ids, id)
	}
	a.mu.Unlock()
	for _, id := range ids {
		if rec, ok := a.svc.Store().Get(id); !ok || rec.IsExpired() {
			a.endSession(id, false)
		}
	}
}

// --- shutdown ----------------------------------------------------------------

func (a *WMPAdapter) isDraining() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.draining
}

// Drain makes the adapter refuse new requests and sessions (503). Idempotent.
func (a *WMPAdapter) Drain() {
	a.mu.Lock()
	a.draining = true
	a.mu.Unlock()
}

// Close drains and closes without a deadline; see CloseContext.
func (a *WMPAdapter) Close() { a.CloseContext(context.Background()) }

// CloseContext drains, waits for requests in flight and closes the server (its
// peers and streams) until ctx is done, then ends every engine session.
func (a *WMPAdapter) CloseContext(ctx context.Context) {
	a.Drain()
	a.stopOnce.Do(func() { close(a.stopCh) })
	select {
	case <-a.loopDone:
	case <-ctx.Done():
	}
	if err := a.server.Close(ctx); err != nil {
		a.logger.Warn("WMP server close", zap.Error(err))
	}
	a.mu.Lock()
	ids := make([]string, 0, len(a.sessions))
	for id := range a.sessions {
		ids = append(ids, id)
	}
	a.mu.Unlock()
	// Ending a session deletes its persisted state, which a slow store can hold up:
	// the work is bounded by ctx, and carries on in the background past it.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, id := range ids {
			a.endSession(id, false)
		}
	}()
	select {
	case <-done:
	case <-ctx.Done():
		a.logger.Warn("WMP shutdown deadline passed while ending sessions", zap.Int("sessions", len(ids)))
	}
}

// --- discovery ---------------------------------------------------------------

// SetExternalURL sets the public base URL of the WMP endpoints. Only https URLs
// with a host and no query or fragment are accepted (discovery advertises
// security mode "tls"); plain http only for loopback. A ws:// or wss:// URL
// (engine_url) maps to http:// (loopback only) or https://.
func (a *WMPAdapter) SetExternalURL(raw string) error {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err == nil {
		switch u.Scheme {
		case "wss":
			u.Scheme = "https"
		case "ws":
			u.Scheme = "http"
		}
	}
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("invalid WMP external URL %q", raw)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("WMP external URL %q must use https (or wss): plaintext http/ws is only allowed for loopback hosts", raw)
	}
	a.mu.Lock()
	a.externalURL = u.String()
	a.mu.Unlock()
	return nil
}

// isLoopbackHost reports whether host is localhost or a loopback IP literal.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// HasExternalURL reports whether SetExternalURL has succeeded.
func (a *WMPAdapter) HasExternalURL() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.externalURL != ""
}

// HandleWMPConfiguration serves /.well-known/wmp-configuration. Endpoints are
// absolute URLs from SetExternalURL; without one it fails closed with 503.
func (a *WMPAdapter) HandleWMPConfiguration(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	base := a.externalURL
	a.mu.Unlock()
	if base == "" {
		http.Error(w, "WMP discovery unavailable: no external URL configured", http.StatusServiceUnavailable)
		return
	}
	caps := make(map[string]interface{})
	for name, raw := range a.serverCapabilities() {
		var v interface{}
		if err := json.Unmarshal(raw, &v); err == nil {
			caps[name] = v
		}
	}
	body, err := json.Marshal(wmp.WellKnownConfig{
		SupportedVersions: wmp.SupportedVersions,
		SecurityModes:     []string{"tls"},
		Capabilities:      caps,
		Endpoints: map[string]string{
			"rpc":    base + WMPRPCPath,
			"events": base + WMPClientEventsPath,
		},
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(body)
}
