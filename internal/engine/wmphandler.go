package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"go.uber.org/zap"
)

// specToEngineAction maps WMP spec action names to engine-internal action names.
// The WMP specification (wmp-openid4x) defines canonical action names for
// OpenID4VCI/VP flows. The engine uses its own action vocabulary internally.
// This map ensures WMP clients can use spec-compliant action names.
var specToEngineAction = map[string]string{
	openid4x.ActionAcceptOffer:       ActionConsent,
	openid4x.ActionProvideTxCode:     ActionProvidePin,
	openid4x.ActionAuthorize:         ActionAuthorizationComplete,
	openid4x.ActionSelectCredentials: ActionConsent,
	openid4x.ActionCancel:            ActionDecline,
}

// WMPAdapter wraps the engine Manager and exposes it as WMP JSON-RPC.
// It manages one wmp.Peer per engine Session, each backed by a
// ChannelTransport whose outbound channel feeds the SSE event stream.
type WMPAdapter struct {
	manager *Manager
	logger  *zap.Logger
	// bearerToken extracts the bearer credential from an HTTP request.
	bearerToken func(*http.Request) string

	mu                sync.RWMutex
	peers             map[string]*wmpSession      // keyed by WMP session ID
	resumptionTokens  map[string]*resumptionEntry // token -> entry with session ID and expiry
	eventBufs         map[string]*wmpEventBuffer  // keyed by WMP session ID; survives resume unlike peers
	outbound          map[string]outboundRequest  // server->client request IDs awaiting a response (see trackOutbound)
	externalURL       string                      // public base URL for discovery (SetExternalURL)
	draining          bool                        // set by Drain/Close; new sessions and requests are refused
	beforeCreateToken func(sessionID string)      // test hook: runs between publishing a new peer and issuing its token

	// tokenSlotsMu guards tokenSlots, the number of live WMP sessions per
	// bearer token (see reserveSlot).
	tokenSlotsMu sync.Mutex
	tokenSlots   map[string]int

	stopCh   chan struct{}
	stopOnce sync.Once
	loopDone chan struct{} // closed when cleanupLoop has exited
}

// maxWMPSessionsPerToken bounds how many live WMP sessions one bearer token
// may hold. Anonymous tokens are not indexed by user in the engine (and every
// user-less session would otherwise be unaccounted), so without this a single
// token could create sessions without limit.
const maxWMPSessionsPerToken = 10

// wmpSlot is one reserved unit of the global (Manager.activeConnections) and
// per-token session budget. release is idempotent, so every teardown path can
// call it without double-freeing.
type wmpSlot struct {
	a    *WMPAdapter
	key  string
	once sync.Once
}

func (s *wmpSlot) release() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		s.a.tokenSlotsMu.Lock()
		if s.a.tokenSlots[s.key] <= 1 {
			delete(s.a.tokenSlots, s.key)
		} else {
			s.a.tokenSlots[s.key]--
		}
		s.a.tokenSlotsMu.Unlock()
		s.a.manager.activeConnections.Add(-1)
	})
}

// reserveSlot atomically claims a session slot against the engine's global
// connection limit (shared with WebSocket connections) and the per-token
// limit. It returns nil if either is exhausted.
func (a *WMPAdapter) reserveSlot(key string) *wmpSlot {
	a.tokenSlotsMu.Lock()
	if a.tokenSlots == nil {
		a.tokenSlots = make(map[string]int)
	}
	if a.tokenSlots[key] >= maxWMPSessionsPerToken {
		a.tokenSlotsMu.Unlock()
		return nil
	}
	a.tokenSlots[key]++
	a.tokenSlotsMu.Unlock()

	if a.manager.activeConnections.Add(1) > maxConnections {
		a.manager.activeConnections.Add(-1)
		a.tokenSlotsMu.Lock()
		if a.tokenSlots[key] <= 1 {
			delete(a.tokenSlots, key)
		} else {
			a.tokenSlots[key]--
		}
		a.tokenSlotsMu.Unlock()
		return nil
	}
	return &wmpSlot{a: a, key: key}
}

// maxWMPBufferedEvents bounds how many past SSE events are retained per
// session for Last-Event-ID replay on reconnect (including across a
// wmp.session.resume, which installs a brand new ChannelTransport whose own
// buffer starts empty).
const maxWMPBufferedEvents = 200

// wmpBufferedEvent is one retained SSE frame, tagged with a session-durable
// sequence number (not reset per HTTP connection, unlike the previous
// per-connection counter).
type wmpBufferedEvent struct {
	ID   int64
	Data []byte
}

// wmpEventBuffer retains recent outbound SSE events for a session so a
// reconnecting client (including after wmp.session.resume, or a plain SSE
// drop during e.g. an OAuth redirect) can replay what it missed via
// Last-Event-ID, instead of silently losing progress/sign_request/
// flow_complete notifications emitted while disconnected.
//
// Events are appended at emission time by the session's pump goroutine (see
// pumpEvents), not when an SSE handler happens to consume them, so
// notifications emitted while no client is connected - or in the window of
// a resume - are retained.
type wmpEventBuffer struct {
	mu     sync.Mutex
	events []wmpBufferedEvent
	nextID int64

	// wake is closed (and replaced) on every append so SSE handlers can
	// block until there is something new; done is closed when the session
	// ends so they can terminate.
	wake     chan struct{}
	done     chan struct{}
	doneOnce sync.Once

	// active is the cancel function of the currently-streaming SSE
	// connection, if any. A new connection supersedes it (see acquire).
	active *wmpStream
}

// wmpStream identifies one SSE connection registered on a buffer.
type wmpStream struct {
	cancel context.CancelFunc
}

// ensure lazily initialises the signalling channels (so the zero value is
// usable). Callers must hold b.mu.
func (b *wmpEventBuffer) ensure() {
	if b.wake == nil {
		b.wake = make(chan struct{})
	}
	if b.done == nil {
		b.done = make(chan struct{})
	}
}

// acquire registers a new SSE connection and supersedes any previous one by
// cancelling its context so its handler exits. A stale connection (e.g. an
// unclean mobile disconnect whose context is not yet cancelled) therefore can
// never block a reconnect. The buffer is replay-only and cursor-driven, so
// the superseded handler losing its stream drops nothing: the new connection
// replays from its own Last-Event-ID. Callers must call release with the
// returned stream when the connection ends.
func (b *wmpEventBuffer) acquire(cancel context.CancelFunc) *wmpStream {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active != nil {
		b.active.cancel()
	}
	s := &wmpStream{cancel: cancel}
	b.active = s
	return s
}

// release clears the active connection if s is still the registered one (a
// release from an already-superseded connection must not clear a newer one).
func (b *wmpEventBuffer) release(s *wmpStream) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active == s {
		b.active = nil
	}
}

// append records data as a new event, wakes waiting SSE handlers and returns
// the event's sequence ID.
func (b *wmpEventBuffer) append(data []byte) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ensure()
	b.nextID++
	id := b.nextID
	b.events = append(b.events, wmpBufferedEvent{ID: id, Data: data})
	if len(b.events) > maxWMPBufferedEvents {
		b.events = b.events[len(b.events)-maxWMPBufferedEvents:]
	}
	close(b.wake)
	b.wake = make(chan struct{})
	return id
}

// after returns the retained events with an ID greater than cursor, and a
// channel that is closed when a newer event is appended.
func (b *wmpEventBuffer) after(cursor int64) ([]wmpBufferedEvent, <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ensure()
	var out []wmpBufferedEvent
	for _, ev := range b.events {
		if ev.ID > cursor {
			out = append(out, ev)
		}
	}
	return out, b.wake
}

// doneCh is closed when the owning session has ended.
func (b *wmpEventBuffer) doneCh() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ensure()
	return b.done
}

// close marks the session ended and wakes every waiting SSE handler.
func (b *wmpEventBuffer) close() {
	b.mu.Lock()
	b.ensure()
	done := b.done
	b.mu.Unlock()
	b.doneOnce.Do(func() { close(done) })
}

// replaySince returns buffered events with an ID greater than lastEventID.
// Returns nil if lastEventID doesn't parse (e.g. empty, or a stale ID from
// before this buffer existed) — replay is best-effort, not required.
func (b *wmpEventBuffer) replaySince(lastEventID string) []wmpBufferedEvent {
	lastID, err := strconv.ParseInt(lastEventID, 10, 64)
	if err != nil {
		return nil
	}
	evs, _ := b.after(lastID)
	return evs
}

// pendingCount returns the number of currently-buffered events.
func (b *wmpEventBuffer) pendingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

// missedSince counts the events a client that last received lastReceivedID
// has not seen. When the client supplies no (parseable) cursor every retained
// event counts, since the server keeps no delivery state and will replay them
// all; a cursor older than the retained window likewise counts everything
// retained (older events are evicted and cannot be replayed).
func (b *wmpEventBuffer) missedSince(lastReceivedID string) int {
	cursor, err := strconv.ParseInt(lastReceivedID, 10, 64)
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil || lastReceivedID == "" {
		cursor = 0
	}
	n := 0
	for _, ev := range b.events {
		if ev.ID > cursor {
			n++
		}
	}
	return n
}

// pumpEvents moves a session transport's outbound notifications into the
// session's event buffer as they are emitted. It exits when ctx (the
// wmpSession's context) is cancelled, after draining whatever is still
// queued, and then closes done.
func pumpEvents(ctx context.Context, ct *wmp.ChannelTransport, buf *wmpEventBuffer, done chan<- struct{}, onOut func([]byte)) {
	defer close(done)
	out := ct.Out()
	emit := func(data []byte) {
		// Track before the event becomes visible to the client, so a
		// response can never arrive ahead of its registration.
		if onOut != nil {
			onOut(data)
		}
		buf.append(data)
	}
	for {
		select {
		case data := <-out:
			emit(data)
		case <-ctx.Done():
			for {
				select {
				case data := <-out:
					emit(data)
				default:
					return
				}
			}
		}
	}
}

// resumptionEntry holds a resumption token's session binding and expiry.
type resumptionEntry struct {
	sessionID string
	expiresAt time.Time
}

// wmpSessionIdleTimeout is the maximum time a WMP session can be idle
// (no RPC activity) before being automatically closed.
const wmpSessionIdleTimeout = 10 * time.Minute

// resumptionTokenTTL is the lifetime of a resumption token. After this
// duration the token is invalid and the client must create a new session.
const resumptionTokenTTL = 10 * time.Minute

// capSeconds converts a client-supplied number of seconds to a Duration,
// capped at limit. The cap is applied to the integer BEFORE multiplying, so
// values near MaxInt cannot overflow time.Duration into a negative (and thus
// uncapped) value. Non-positive input yields 0 ("not set").
func capSeconds(seconds int, limit time.Duration) time.Duration {
	if seconds <= 0 {
		return 0
	}
	maxSeconds := int64(limit / time.Second)
	if int64(seconds) >= maxSeconds {
		return limit
	}
	return time.Duration(seconds) * time.Second
}

// maxFlowIDLength limits client-supplied flow IDs to prevent memory abuse.
const maxFlowIDLength = 128

// defaultFlowTimeout is the server-side default when the client does not
// supply a timeout in wmp.flow.start.
const defaultFlowTimeout = 5 * time.Minute

// maxSessionTTL caps the TTL a client may request for a session.
const maxSessionTTL = 24 * time.Hour

// flowActionSendWait bounds how long FlowAction blocks trying to enqueue a
// response onto a full sign/match/action channel before rejecting with
// ErrRateLimited. A legitimate single in-flight sign_response/match_response
// (the common case: at most one outstanding request per flow) can land in a
// momentarily-full channel and would otherwise have no way to recover short
// of waiting out the engine's own server-side timeout; a brief wait here
// gives room to drain without changing the channel's bounded depth.
const flowActionSendWait = 3 * time.Second

// childFlowStartTimeout bounds the wmp.flow.start Call() used to kick off a
// nested sign/match sub-flow. This blocks the engine goroutine that
// requested the signature/match until the client acks the child flow.start
// (not until the actual result arrives, which comes later via
// flow.complete) — an unresponsive client must not be able to stall it
// indefinitely.
const childFlowStartTimeout = 30 * time.Second

// wmpSession associates a wmp.Peer with its channel transport and engine session.
type wmpSession struct {
	peer         *wmp.Peer
	transport    *wmp.ChannelTransport
	handler      *wmpEngineHandler
	session      *Session
	cancel       context.CancelFunc
	pumpDone     chan struct{} // closed once the event pump has drained and exited
	lastActivity time.Time
	capabilities wmp.Capabilities // negotiated capabilities for resume echo
	security     wmp.SecurityMode // negotiated security mode for resume echo
	expiresAt    time.Time        // absolute session deadline from TTL
	// ownerTokenID is the jti of the token the session was created with. It
	// is compared for sessions with no user identity (anonymous tokens all
	// have UserID == ""), which user/tenant alone cannot tell apart.
	ownerTokenID string
	// slot is the session budget reserved at creation; released once, by
	// teardown. Shared (not re-reserved) across resumes of the same session.
	slot *wmpSlot
}

// wmpCaller is the identity validated from a request's bearer token.
type wmpCaller struct {
	UserID   string
	TenantID string
	TokenID  string // jti; may be empty
	// TAC is the token-authorized-capabilities of THIS request's token. It
	// bounds what the request may do, independent of the TAC captured when
	// the session was created, so a session cannot be driven with more
	// privilege than the token presented now. Empty means legacy auth.
	TAC claims.TAC
	// EnforceTAC is the token's provenance: true for a modern token, whose
	// TAC is authoritative even when empty (no permissions); false only for a
	// genuine legacy token, which has no TAC concept. A non-empty TAC is
	// always enforced.
	EnforceTAC bool
}

// wmpCallerTACKey carries the request's wmpTACInfo in the context.
type wmpCallerTACKey struct{}

type wmpTACInfo struct {
	TAC     claims.TAC
	Enforce bool
}

// requestTAC returns the TAC of the token that authenticated the current
// request (empty when none, i.e. legacy auth or an in-process call).
func requestTAC(ctx context.Context) claims.TAC {
	return requestTACInfo(ctx).TAC
}

// requestTACInfo returns the request token's TAC and whether it is enforced.
func requestTACInfo(ctx context.Context) wmpTACInfo {
	t, _ := ctx.Value(wmpCallerTACKey{}).(wmpTACInfo)
	return t
}

// NewWMPAdapter creates an adapter that bridges WMP JSON-RPC to the engine.
// bearerToken extracts the bearer credential from an HTTP request ("" when
// absent or malformed); it is injected because the engine cannot import
// pkg/middleware (which depends on the engine through the service layer).
func NewWMPAdapter(manager *Manager, logger *zap.Logger, bearerToken func(*http.Request) string) *WMPAdapter {
	a := &WMPAdapter{
		bearerToken:      bearerToken,
		manager:          manager,
		logger:           logger.Named("wmp"),
		peers:            make(map[string]*wmpSession),
		resumptionTokens: make(map[string]*resumptionEntry),
		eventBufs:        make(map[string]*wmpEventBuffer),
		outbound:         make(map[string]outboundRequest),
		stopCh:           make(chan struct{}),
		loopDone:         make(chan struct{}),
	}
	go a.cleanupLoop()
	return a
}

// Drain marks the adapter as draining: from now on the HTTP handlers answer
// 503 and session.create / session.resume are refused. It is idempotent and
// is the first step of Close, but can be called earlier to stop accepting
// work while the HTTP listener is still up.
func (a *WMPAdapter) Drain() {
	a.mu.Lock()
	a.draining = true
	a.mu.Unlock()
}

// isDraining reports whether Drain/Close has been called.
func (a *WMPAdapter) isDraining() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.draining
}

// Close stops the cleanup loop and waits for it to exit. Safe to call more
// than once. Live sessions are closed when the engine Manager is closed.
func (a *WMPAdapter) Close() {
	// Refuse new requests and sessions before anything is torn down, so a
	// session.create racing with shutdown cannot register a session after
	// the snapshot below and leak it.
	a.Drain()
	a.stopOnce.Do(func() { close(a.stopCh) })
	if a.loopDone != nil {
		<-a.loopDone
	}
	// End every live session. This closes each session's event buffer, which
	// terminates any SSE handler streaming from it; without it a graceful
	// HTTP shutdown waits out its whole timeout on those long-lived streams.
	a.mu.RLock()
	ids := make([]string, 0, len(a.peers))
	for sid := range a.peers {
		ids = append(ids, sid)
	}
	a.mu.RUnlock()
	for _, sid := range ids {
		a.CloseSession(sid)
	}
}

// cleanupLoop periodically removes expired resumption tokens and idle sessions.
func (a *WMPAdapter) cleanupLoop() {
	if a.loopDone != nil {
		defer close(a.loopDone)
	}
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.cleanupExpired()
		case <-a.stopCh:
			return
		}
	}
}

// cleanupExpired removes expired resumption tokens and closes idle sessions.
func (a *WMPAdapter) cleanupExpired() {
	now := time.Now()

	a.mu.Lock()
	// Remove expired resumption tokens.
	for token, entry := range a.resumptionTokens {
		if now.After(entry.expiresAt) {
			delete(a.resumptionTokens, token)
		}
	}
	// Remove outbound requests whose Call() has long since timed out.
	for id, o := range a.outbound {
		if now.After(o.expiresAt) {
			delete(a.outbound, id)
		}
	}

	// Collect idle or TTL-expired sessions to close.
	var expiredSessions []string
	for sid, ws := range a.peers {
		if now.Sub(ws.lastActivity) > wmpSessionIdleTimeout {
			expiredSessions = append(expiredSessions, sid)
		} else if !ws.expiresAt.IsZero() && now.After(ws.expiresAt) {
			expiredSessions = append(expiredSessions, sid)
		}
	}
	a.mu.Unlock()

	for _, sid := range expiredSessions {
		a.logger.Info("Closing expired/idle WMP session", zap.String("session_id", sid[:8]))
		a.CloseSession(sid)
	}
}

// verifySessionOwnership checks that the session belongs to the authenticated user.
// Returns false if the session doesn't exist or the user/tenant don't match.
// For sessions without a user identity (anonymous tokens) the token's jti
// must also match the one the session was created with, and such sessions
// are never addressable by a caller whose token carries no jti.
func (a *WMPAdapter) verifySessionOwnership(sessionID string, caller wmpCaller) bool {
	a.mu.RLock()
	ws, ok := a.peers[sessionID]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	return ownsSession(ws, caller)
}

// defaultWMPTenant is the tenant a token without a tenant_id claim belongs to
// (matches pkg/middleware/tokenauth.go).
const defaultWMPTenant = "default"

func normalizeWMPTenant(t string) string {
	if t == "" {
		return defaultWMPTenant
	}
	return t
}

func ownsSession(ws *wmpSession, caller wmpCaller) bool {
	if ws.session.UserID != caller.UserID {
		return false
	}
	// Exact tenant equality after normalisation. An empty tenant claim must
	// not act as a wildcard: the HTTP middleware maps a missing tenant_id to
	// the default tenant, so both sides are compared in that form.
	if normalizeWMPTenant(ws.session.TenantID) != normalizeWMPTenant(caller.TenantID) {
		return false
	}
	if ws.session.UserID == "" {
		if ws.ownerTokenID == "" || caller.TokenID != ws.ownerTokenID {
			return false
		}
	}
	return true
}

// touchSession updates the last activity timestamp for idle timeout tracking.
func (a *WMPAdapter) touchSession(sessionID string) {
	a.mu.Lock()
	if ws, ok := a.peers[sessionID]; ok {
		ws.lastActivity = time.Now()
	}
	a.mu.Unlock()
}

// HandleRPC handles a single JSON-RPC request (from HTTP POST /wmp/rpc).
// It is HandleRPCAs for a caller with no token ID.
func (a *WMPAdapter) HandleRPC(ctx context.Context, sessionID, userID, tenantID string, body []byte) ([]byte, error) {
	return a.HandleRPCAs(ctx, sessionID, wmpCaller{UserID: userID, TenantID: tenantID}, body)
}

// HandleRPCAs handles a single JSON-RPC request. The sessionID is extracted
// from the request's Wmp-Session-Id header by the HTTP handler and passed
// here; empty for session.create. caller is the identity validated from the
// caller's bearer token by the HTTP layer (HandleWMPRPC); it is required to
// authorize wmp.session.resume against the session being resumed — see
// handleSessionResume.
func (a *WMPAdapter) HandleRPCAs(ctx context.Context, sessionID string, caller wmpCaller, body []byte) ([]byte, error) {
	// Decode with go-wmp's decoder so the JSON-RPC envelope (jsonrpc == "2.0",
	// size and depth limits, no trailing data) is enforced for session.create
	// and session.resume exactly as it is for every other method.
	msg, err := wmp.DecodeMessage(body)
	if err != nil {
		return wmpErrorBytes(nil, wmp.ErrParseError, nil)
	}

	if msg.Method == wmp.MethodSessionCreate {
		return a.handleSessionCreate(ctx, msg)
	}
	if msg.Method == wmp.MethodSessionResume {
		return a.handleSessionResume(ctx, caller, msg)
	}

	// A response carries no session identity of its own: go-wmp's HTTPS+SSE
	// client sets only the headers it was configured with at construction
	// (before session.create), and a response has no params.wmp.session_id.
	// Route it by the server-initiated request ID it answers.
	if msg.IsResponse() {
		return a.routeResponse(ctx, sessionID, caller, msg, body)
	}

	// All other methods require an existing session.
	if sessionID == "" {
		return wmpErrorBytes(nil, wmp.ErrNotAuthorized, map[string]string{
			"reason": "missing session ID",
		})
	}

	a.mu.RLock()
	ws, ok := a.peers[sessionID]
	a.mu.RUnlock()
	if !ok {
		return wmpErrorBytes(nil, wmp.ErrSessionNotFound, nil)
	}

	// Update activity timestamp for idle timeout tracking.
	a.touchSession(sessionID)

	return ws.peer.HandleRequestSync(context.WithValue(ctx, wmpCallerTACKey{}, wmpTACInfo{TAC: caller.TAC, Enforce: caller.EnforceTAC || caller.TAC != ""}), body)
}

// Events returns a channel of the session's outbound notifications, as the
// SSE stream would deliver them, starting with the events still retained in
// the session's buffer (bounded ring) and then live ones. It is a convenience subscription; the HTTP SSE
// handler reads the event buffer directly. The channel is closed when the
// session ends.
func (a *WMPAdapter) Events(sessionID string) (<-chan []byte, error) {
	a.mu.RLock()
	_, ok := a.peers[sessionID]
	buf := a.eventBufs[sessionID]
	a.mu.RUnlock()
	if !ok || buf == nil {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	out := make(chan []byte, maxWMPBufferedEvents)
	go func() {
		defer close(out)
		var cursor int64
		done := buf.doneCh()
		for {
			evs, wake := buf.after(cursor)
			for _, ev := range evs {
				cursor = ev.ID
				select {
				case out <- ev.Data:
				case <-done:
					return
				}
			}
			select {
			case <-wake:
			case <-done:
				return
			}
		}
	}()
	return out, nil
}

// getOrCreateEventBuffer returns the persistent SSE replay buffer for
// sessionID, creating it if this is the first time it's requested. Unlike
// wmpSession, this buffer is not replaced on resume.
func (a *WMPAdapter) getOrCreateEventBuffer(sessionID string) *wmpEventBuffer {
	a.mu.Lock()
	defer a.mu.Unlock()
	buf, ok := a.eventBufs[sessionID]
	if !ok {
		buf = &wmpEventBuffer{}
		a.eventBufs[sessionID] = buf
	}
	return buf
}

// CloseSession closes a WMP session and its associated engine session.
func (a *WMPAdapter) CloseSession(sessionID string) {
	a.mu.Lock()
	ws, ok := a.peers[sessionID]
	if ok {
		delete(a.peers, sessionID)
	}
	a.dropSessionStateLocked(sessionID)
	a.mu.Unlock()
	if ok {
		a.teardown(ws)
	}
}

// dropSessionStateLocked removes the session's event buffer (waking and
// terminating any SSE handler streaming from it) and resumption tokens.
// Callers must hold a.mu.
func (a *WMPAdapter) dropSessionStateLocked(sessionID string) {
	if buf, ok := a.eventBufs[sessionID]; ok {
		buf.close()
		delete(a.eventBufs, sessionID)
	}
	for token, entry := range a.resumptionTokens {
		if entry.sessionID == sessionID {
			delete(a.resumptionTokens, token)
		}
	}
	for id, o := range a.outbound {
		if o.sessionID == sessionID {
			delete(a.outbound, id)
		}
	}
}

// teardown ends a wmpSession that has been removed from a.peers: it stops the
// peer, closes the transport, and ends the engine session the same way a
// WebSocket disconnect does (closeCh closed, active flows cancelled).
func (a *WMPAdapter) teardown(ws *wmpSession) {
	ws.cancel()
	_ = ws.transport.Close()
	ws.session.endSession()
	a.manager.unregisterSession(ws.session)
	ws.slot.release()
}

// closeSessionIfCurrent tears down sessionID's peer.Serve goroutine cleanup,
// but only if ws is still the active wmpSession for that ID. It is used by
// the deferred cleanup in the goroutine started by handleSessionCreate/
// handleSessionResume: peer.Serve returning (e.g. because a resume closed
// this peer's transport) does not by itself mean the session as a whole
// should be torn down — a resume may have already installed a new
// wmpSession for the same ID, and that replacement must not be destroyed by
// the outgoing goroutine's own cleanup.
func (a *WMPAdapter) closeSessionIfCurrent(sessionID string, ws *wmpSession) {
	a.mu.Lock()
	current, ok := a.peers[sessionID]
	if !ok || current != ws {
		// Superseded by a resume (or already removed) — nothing to do.
		a.mu.Unlock()
		return
	}
	delete(a.peers, sessionID)
	a.dropSessionStateLocked(sessionID)
	a.mu.Unlock()

	a.teardown(ws)
}

// handleSessionCreate creates a new engine session and wmp.Peer.
func (a *WMPAdapter) handleSessionCreate(_ context.Context, msg *wmp.Message) ([]byte, error) {
	req := msg.AsRequest()

	var params wmp.SessionCreateParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return wmpErrorBytes(req.ID, wmp.ErrInvalidParams, nil)
	}

	// Version negotiation: reject unsupported versions.
	if params.WMP.Version != "" && !wmp.IsSupportedVersion(params.WMP.Version) {
		return wmpErrorBytes(req.ID, wmp.ErrVersionNotSupported, map[string]interface{}{
			"supported_versions": wmp.SupportedVersions,
		})
	}

	// Security mode validation: this server supports TLS only (no MLS layer),
	// which is also the only mode it advertises. An omitted mode means the
	// transport default (tls); anything else is rejected per spec §2.1 rather
	// than echoed back as if negotiated.
	switch params.Security.Mode {
	case "":
		params.Security.Mode = "tls"
	case "tls":
	default:
		return wmpErrorBytes(req.ID, wmp.ErrInvalidParams, map[string]string{
			"reason": fmt.Sprintf("security mode %q is not supported; use 'tls'", params.Security.Mode),
		})
	}

	// Extract bearer token from auth object.
	var userID, tenantID, tokenID string
	var tac claims.TAC
	var enforceTAC bool
	if params.Auth != nil && params.Auth.Token != "" {
		if params.Auth.Type != "" && params.Auth.Type != "bearer" {
			return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
				"reason": "unsupported auth type; only 'bearer' is supported",
			})
		}
		var err error
		var id tokenIdentity
		id, err = a.manager.validateTokenAuth(params.Auth.Token)
		userID, tenantID, tac, tokenID, enforceTAC = id.UserID, id.TenantID, id.TAC, id.JTI, id.EnforceTAC
		if err != nil {
			a.logger.Warn("WMP auth failed", zap.Error(err))
			return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
				"reason": "invalid or expired token",
			})
		}
		tenantID = normalizeWMPTenant(tenantID)
	} else {
		return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
			"reason": "auth required",
		})
	}

	// A session without a user identity (anonymous token) can only be told
	// apart from other anonymous sessions by its token's jti; without one
	// there is nothing to bind ownership to, so fail closed.
	if userID == "" && tokenID == "" {
		return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
			"reason": "anonymous token without jti cannot own a session",
		})
	}

	// Reserve a session slot (global + per-token) before allocating anything.
	slotKey := "jti:" + tokenID
	if tokenID == "" {
		slotKey = "user:" + tenantID + ":" + userID
	}
	slot := a.reserveSlot(slotKey)
	if slot == nil {
		a.logger.Warn("WMP session.create rejected: session limit reached")
		return wmpErrorBytes(req.ID, wmp.ErrRateLimited, map[string]string{
			"reason": "too many sessions",
		})
	}

	sessionID := uuid.New().String()

	// Compute session expiry from client TTL (capped).
	var expiresAt time.Time
	if ttl := capSeconds(params.TTL, maxSessionTTL); ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	// Create the channel transport for this session.
	ct := wmp.NewChannelTransport(50, 200)

	// Create the WMP handler that bridges flow methods to the engine.
	handler := &wmpEngineHandler{
		adapter:   a,
		sessionID: sessionID,
	}

	// Create the peer with the channel transport.
	peer := wmp.NewPeer(ct, handler, wmp.WithLogger(slog.Default()))

	// Create the engine session with a translating transport that converts
	// engine message types to WMP JSON-RPC notifications via the peer.
	wmpTransport := newWMPSessionTransport(peer, ct)
	wmpTransport.handler = handler

	session := &Session{
		ID:            sessionID,
		UserID:        userID,
		TenantID:      tenantID,
		TAC:           tac,
		TACEnforced:   enforceTAC,
		transport:     wmpTransport,
		flows:         make(map[string]*Flow),
		logger:        a.logger.With(zap.String("session", userID[:min(8, len(userID))])),
		actionCh:      make(chan *FlowActionMessage, 50),
		signCh:        make(chan *SignResponseMessage, 20),
		matchCh:       make(chan *MatchResponseMessage, 20),
		closeCh:       make(chan struct{}, 1),
		notifications: newNotificationContextStore(),
	}

	// Store handler's session reference (needed for FlowStart/FlowAction).
	handler.session = session

	// Register with engine manager. A false result means the user was
	// revoked between token validation and now (registerSession has already
	// closed the transport): refuse, as the WebSocket handshake does, rather
	// than storing a dead session and reporting success.
	if !a.manager.registerSession(session) {
		slot.release()
		a.logger.Warn("WMP session.create rejected: user revoked between token validation and session registration")
		return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
			"reason": "invalid or expired token",
		})
	}

	// Derive server capabilities from registered flow handlers (spec §4.2.1)
	// and negotiate against what the client offered.
	serverCaps := a.serverCapabilities()
	negotiated := serverCaps
	if len(params.CapabilitiesOffered) > 0 {
		negotiated = make(wmp.Capabilities)
		for name, val := range serverCaps {
			if _, offered := params.CapabilitiesOffered[name]; offered {
				negotiated[name] = val
			}
		}
	}

	// Store the WMP session. All fields are set before it is published in
	// a.peers so concurrent readers never see a half-initialised session.
	sessionCtx, cancel := context.WithCancel(context.Background())
	ws := &wmpSession{
		peer:         peer,
		transport:    ct,
		handler:      handler,
		session:      session,
		cancel:       cancel,
		pumpDone:     make(chan struct{}),
		lastActivity: time.Now(),
		capabilities: negotiated,
		security:     params.Security,
		expiresAt:    expiresAt,
		ownerTokenID: tokenID,
		slot:         slot,
	}
	buf := &wmpEventBuffer{}

	a.mu.Lock()
	if a.draining {
		// Shutdown began after the request was admitted: nothing will ever
		// close this session, so refuse it instead of publishing it.
		a.mu.Unlock()
		a.teardown(ws)
		return wmpErrorBytes(req.ID, wmp.ErrRateLimited, map[string]string{
			"reason": "server shutting down",
		})
	}
	a.peers[sessionID] = ws
	a.eventBufs[sessionID] = buf
	a.mu.Unlock()

	// Buffer notifications as they are emitted (see pumpEvents).
	go pumpEvents(sessionCtx, ct, buf, ws.pumpDone, func(data []byte) { a.trackOutbound(sessionID, data) })

	// Start the peer's read loop in a goroutine (for processing responses
	// to outbound Call() requests, if any).
	go func() {
		_ = peer.Serve(sessionCtx)
		a.closeSessionIfCurrent(sessionID, ws)
	}()

	if a.beforeCreateToken != nil {
		a.beforeCreateToken(sessionID)
	}
	// Issue the token only while this exact peer is still installed: a
	// revocation, replacement or close in the window since publication must
	// fail the create rather than report success for a nonexistent session.
	// This also surfaces a crypto/rand failure instead of an empty token.
	token, ok := a.issueResumptionTokenIfCurrent(sessionID, ws)
	if !ok {
		a.logger.Warn("WMP session.create: session closed or token unavailable during creation", zap.String("session_id", sessionID))
		a.closeSessionIfCurrent(sessionID, ws)
		return wmpErrorBytes(req.ID, wmp.ErrInternalError, map[string]string{
			"reason": "session closed during creation",
		})
	}

	result := wmp.SessionCreateResult{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: sessionID,
		},
		Capabilities:    negotiated,
		Security:        params.Security,
		ResumptionToken: token,
	}

	return wmpResponseBytes(req.ID, result)
}

// issueResumptionTokenIfCurrent issues a token (spec §4.5.2: >=128 bits of entropy, rotated on each resume) for sessionID only if ws is
// still the installed peer, atomically with respect to CloseSession and
// closeSessionIfCurrent (which remove the peer and its tokens under a.mu).
func (a *WMPAdapter) issueResumptionTokenIfCurrent(sessionID string, ws *wmpSession) (string, bool) {
	return a.issueResumptionToken(sessionID, ws)
}

// issueResumptionToken creates and stores a token. With a non-nil ws the peer
// check and the insertion happen under one a.mu critical section.
func (a *WMPAdapter) issueResumptionToken(sessionID string, ws *wmpSession) (string, bool) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		// Should never happen with crypto/rand
		a.logger.Error("failed to generate resumption token", zap.Error(err))
		return "", ws == nil
	}
	token := base64.RawURLEncoding.EncodeToString(b)

	a.mu.Lock()
	defer a.mu.Unlock()
	if ws != nil && a.peers[sessionID] != ws {
		return "", false
	}
	a.resumptionTokens[token] = &resumptionEntry{
		sessionID: sessionID,
		expiresAt: time.Now().Add(resumptionTokenTTL),
	}
	return token, true
}

// serverCapabilities builds the capability map from registered flow handlers.
// This avoids hardcoding and ensures the advertised capabilities reflect the
// actual server configuration (spec §4.2.1).
func (a *WMPAdapter) serverCapabilities() wmp.Capabilities {
	caps := wmp.Capabilities{
		"sign": json.RawMessage(`{"proof_types": ["jwt"]}`),
	}
	// Derive supported flow types from registered handlers.
	a.manager.handlersMu.RLock()
	flowTypes := make([]string, 0, len(a.manager.flowHandlers))
	for p := range a.manager.flowHandlers {
		flowTypes = append(flowTypes, string(p))
	}
	a.manager.handlersMu.RUnlock()

	flowsJSON, _ := json.Marshal(map[string]interface{}{
		"max_concurrent": MaxPendingFlowsPerSession,
		"supported":      flowTypes,
	})
	caps["flows"] = json.RawMessage(flowsJSON)
	return caps
}

// replayActiveFlowProgress re-sends the latest flow.progress for each active
// flow after a session resume, allowing the client to recover UI state.
func (a *WMPAdapter) replayActiveFlowProgress(sessionID string, peer *wmp.Peer) {
	a.mu.RLock()
	ws, ok := a.peers[sessionID]
	a.mu.RUnlock()
	if !ok {
		return
	}

	ws.session.flowsMu.RLock()
	defer ws.session.flowsMu.RUnlock()

	for _, flow := range ws.session.flows {
		// State is written under flow.mu (BaseHandler.Progress); flowsMu only
		// protects the map itself.
		flow.mu.RLock()
		state := flow.State
		flow.mu.RUnlock()
		if state == "" {
			continue
		}
		_ = peer.Notify(context.Background(), wmp.MethodFlowProgress, &wmp.FlowProgressParams{
			WMP: wmp.Metadata{
				Version:   wmp.Version,
				SessionID: sessionID,
			},
			FlowID: flow.ID,
			Step:   string(state),
		})
	}
}

// handleSessionResume validates a resumption token, rotates it, and reconnects
// the client to the existing engine session with a new transport/peer.
//
// caller is the bearer-authenticated identity from the HTTP layer.
// Possession of a resumption token alone is not sufficient to resume a
// session — without also checking that the caller's identity matches the
// session's owner, any authenticated user who obtains another user's
// resumption token (e.g. via a leaked SSE reconnect URL) could take over
// their session. The token is consumed only after every check has passed, so
// a rejected attempt with a stolen token cannot burn the owner's token.
func (a *WMPAdapter) handleSessionResume(_ context.Context, caller wmpCaller, msg *wmp.Message) ([]byte, error) {
	req := msg.AsRequest()

	var params wmp.SessionResumeParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return wmpErrorBytes(req.ID, wmp.ErrInvalidParams, nil)
	}

	// Version negotiation.
	if params.WMP.Version != "" && !wmp.IsSupportedVersion(params.WMP.Version) {
		return wmpErrorBytes(req.ID, wmp.ErrVersionNotSupported, map[string]interface{}{
			"supported_versions": wmp.SupportedVersions,
		})
	}

	invalidToken := func() ([]byte, error) {
		return wmpErrorBytes(req.ID, wmp.ErrSessionNotFound, map[string]string{
			"reason": "invalid or expired resumption token",
		})
	}

	// Look the token up without consuming it: it must exist, be unexpired
	// and be bound to the session named in the request.
	a.mu.Lock()
	entry, validToken := a.resumptionTokens[params.ResumptionToken]
	if validToken && time.Now().After(entry.expiresAt) {
		delete(a.resumptionTokens, params.ResumptionToken)
		validToken = false
	}
	var oldWS *wmpSession
	if validToken && entry.sessionID == params.SessionID {
		oldWS = a.peers[params.SessionID]
	}
	a.mu.Unlock()

	if !validToken || entry == nil || entry.sessionID != params.SessionID {
		return invalidToken()
	}
	if oldWS == nil {
		return wmpErrorBytes(req.ID, wmp.ErrSessionNotFound, nil)
	}

	// Reject resume attempts where the bearer-authenticated caller doesn't
	// own the session — a valid resumption token is not sufficient on its
	// own (see doc comment above).
	if !ownsSession(oldWS, caller) {
		return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
			"reason": "resumption token does not belong to the authenticated caller",
		})
	}

	// Build the replacement connection state. Negotiated state (capabilities,
	// security, TTL deadline, owner binding) and outstanding sub-flow
	// correlation carry over from the session being resumed.
	ct := wmp.NewChannelTransport(50, 200)
	handler := &wmpEngineHandler{
		adapter:   a,
		sessionID: params.SessionID,
		session:   oldWS.session,
		children:  oldWS.handler.table(), // shared, not moved: a losing resume leaves it untouched
	}
	peer := wmp.NewPeer(ct, handler, wmp.WithLogger(slog.Default()))
	wmpTransport := newWMPSessionTransport(peer, ct)
	wmpTransport.handler = handler

	sessionCtx, cancel := context.WithCancel(context.Background())
	ws := &wmpSession{
		peer:         peer,
		transport:    ct,
		handler:      handler,
		session:      oldWS.session,
		cancel:       cancel,
		pumpDone:     make(chan struct{}),
		lastActivity: time.Now(),
		capabilities: oldWS.capabilities,
		security:     oldWS.security,
		expiresAt:    oldWS.expiresAt,
		ownerTokenID: oldWS.ownerTokenID,
		slot:         oldWS.slot,
	}

	// Atomically consume the token and install the replacement, but only if
	// the session being resumed is still the current one. The replacement is
	// published BEFORE the old peer is cancelled below, so the old peer's
	// Serve goroutine (whose cleanup only acts if it is still current) can
	// never tear down the resumed session.
	a.mu.Lock()
	_, tokenStillValid := a.resumptionTokens[params.ResumptionToken]
	if !tokenStillValid || a.peers[params.SessionID] != oldWS || a.draining {
		a.mu.Unlock()
		cancel()
		_ = ct.Close()
		return invalidToken()
	}
	delete(a.resumptionTokens, params.ResumptionToken)
	a.peers[params.SessionID] = ws
	buf := a.eventBufs[params.SessionID]
	a.mu.Unlock()
	if buf == nil {
		buf = a.getOrCreateEventBuffer(params.SessionID)
	}

	// Abort any blocking sign/match Call still holding Session.Send's read
	// lock on the old transport (the client may have disconnected without
	// acknowledging it); otherwise the write lock below would wait out the
	// call timeout. Queued notifications are unaffected.
	prevTransport := oldWS.session.currentTransport()
	if old, ok := prevTransport.(*wmpSessionTransport); ok {
		old.retire()
	}

	// Rewire the engine session's transport to the new peer/channel. The
	// write lock waits for in-flight Session.Send calls (which hold the read
	// lock for the whole send), so nothing is written to the old transport
	// after this point.
	oldWS.session.transportMu.Lock()
	oldWS.session.transport = wmpTransport
	oldWS.session.transportMu.Unlock()
	// Child-flow starts interrupted by retire() are reissued on the new peer.
	if old, ok := prevTransport.(*wmpSessionTransport); ok {
		old.handOff(wmpTransport)
	}

	// Retire the old connection and wait for its pump to move everything it
	// had queued into the event buffer, before the new pump starts, so
	// replayed events keep their emission order.
	oldWS.cancel()
	_ = oldWS.transport.Close()
	<-oldWS.pumpDone

	// Re-check revocation now that the replacement transport is installed.
	// The caller's token was validated before this point; an account
	// revocation that closed the OLD transport (and finished its scan of live
	// sessions) before the swap above would otherwise leave this resumed
	// session open. Revocation marks the user before it closes sessions, so
	// either the mark is visible here, or the closing scan runs after the swap
	// and closes the new transport.
	if a.manager.userRevoked(caller.UserID) {
		a.logger.Warn("WMP session.resume rejected: user revoked", zap.String("session_id", params.SessionID))
		a.closeSessionIfCurrent(params.SessionID, ws)
		return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
			"reason": "invalid or expired token",
		})
	}

	go pumpEvents(sessionCtx, ct, buf, ws.pumpDone, func(data []byte) { a.trackOutbound(params.SessionID, data) })
	go func() {
		_ = peer.Serve(sessionCtx)
		a.closeSessionIfCurrent(params.SessionID, ws)
	}()

	// Issue a new rotated token, but only while this exact peer is still the
	// installed one: CloseSession removes the peer and its tokens under a.mu,
	// so checking and issuing under the same lock gives close and resume a
	// single linearization point (no token for a session that no longer
	// exists, and no "resumed: true" for it either).
	newToken, stillCurrent := a.issueResumptionTokenIfCurrent(params.SessionID, ws)
	if !stillCurrent {
		a.logger.Warn("WMP session.resume: session closed during resume", zap.String("session_id", params.SessionID))
		return invalidToken()
	}

	// Echo the negotiated capabilities and security from the original session
	// per spec §4.5.1 / §4.5.3. MissedMessages is the number of events after
	// the client's last_received_id (or, with no cursor, not yet written to
	// any SSE connection) that the SSE event buffer can replay.
	result := wmp.SessionResumeResult{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: params.SessionID,
		},
		Resumed:         true,
		ResumptionToken: newToken,
		MissedMessages:  buf.missedSince(params.LastReceivedID),
		Capabilities:    ws.capabilities,
		Security:        ws.security,
	}

	// Per spec §6.2.1, re-send the latest flow.progress for each active flow
	// so the client can recover flow state after reconnection.
	go a.replayActiveFlowProgress(params.SessionID, peer)

	return wmpResponseBytes(req.ID, result)
}

// ---------------------------------------------------------------------------
// wmpEngineHandler — bridges WMP Handler interface to the engine
// ---------------------------------------------------------------------------

// wmpEngineHandler implements wmp.Handler. It handles flow lifecycle methods
// directly (FlowStart, FlowAction) and delegates session cleanup to the adapter.
// No AsyncFlowProfile is used — the engine's own goroutine-per-flow model
// drives flow execution, and WMP flow.action calls are routed to the engine
// session's channels (actionCh, signCh, matchCh).
type wmpEngineHandler struct {
	wmp.BaseHandler
	adapter   *WMPAdapter
	sessionID string
	session   *Session

	// children holds outstanding sub-flow correlation state. It is shared
	// (by pointer) between a session's successive connections' handlers, so
	// resuming needs no transfer step that a losing concurrent resume could
	// corrupt. Lazily created; see table().
	childOnce sync.Once
	children  *childFlowTable
}

// childFlowTable is the child-flow correlation map with its lock.
type childFlowTable struct {
	mu    sync.Mutex
	flows map[string]*childFlowInfo // childFlowID → info
}

func (h *wmpEngineHandler) table() *childFlowTable {
	h.childOnce.Do(func() {
		if h.children == nil {
			h.children = &childFlowTable{}
		}
	})
	return h.children
}

// childFlowInfo tracks a nested sub-flow (sign or match) so that when
// the client sends wmp.flow.complete for the child, we can route the
// result back to the appropriate engine channel.
type childFlowInfo struct {
	parentFlowID string
	messageID    string
	flowType     string // "sign" or "match"
}

func (h *wmpEngineHandler) registerChildFlow(childFlowID, parentFlowID, messageID, flowType string) {
	t := h.table()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.flows == nil {
		t.flows = make(map[string]*childFlowInfo)
	}
	t.flows[childFlowID] = &childFlowInfo{
		parentFlowID: parentFlowID,
		messageID:    messageID,
		flowType:     flowType,
	}
}

func (h *wmpEngineHandler) peekChildFlow(childFlowID string) (childFlowInfo, bool) {
	t := h.table()
	t.mu.Lock()
	defer t.mu.Unlock()
	info, ok := t.flows[childFlowID]
	if !ok {
		return childFlowInfo{}, false
	}
	return *info, true
}

// purgeChildFlows drops every child mapping owned by parentFlowID. It runs
// when the parent flow is torn down (completion, timeout, cancellation), so a
// child that never completed cannot leave its entry behind for the session's
// lifetime.
func (h *wmpEngineHandler) purgeChildFlows(parentFlowID string) {
	t := h.table()
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, info := range t.flows {
		if info.parentFlowID == parentFlowID {
			delete(t.flows, id)
		}
	}
}

func (h *wmpEngineHandler) popChildFlow(childFlowID string) (*childFlowInfo, bool) {
	t := h.table()
	t.mu.Lock()
	defer t.mu.Unlock()
	info, ok := t.flows[childFlowID]
	if ok {
		delete(t.flows, childFlowID)
	}
	return info, ok
}

// SessionClose cleans up when the client closes the session.
func (h *wmpEngineHandler) SessionClose(_ context.Context, params *wmp.SessionCloseParams) {
	reason := "unknown"
	if params != nil && params.Reason != "" {
		reason = params.Reason
	}
	h.adapter.logger.Info("WMP session closed by client",
		zap.String("session_id", h.sessionID),
		zap.String("reason", reason))
	h.adapter.CloseSession(h.sessionID)
}

// logger returns the adapter's logger, or a no-op one for a bare handler.
func (h *wmpEngineHandler) logger() *zap.Logger {
	if h.adapter == nil || h.adapter.logger == nil {
		return zap.NewNop()
	}
	return h.adapter.logger
}

// authorizeProtocol enforces the TAC permission the given flow protocol
// requires (see requiredTACForProtocol) for the CURRENT request. It applies
// to every state-changing method, not only FlowStart: a token lacking the
// "i"/"r" permission must not be able to drive, cancel or complete an
// existing flow of that protocol just because it belongs to the same user.
//
// Both the TAC captured at session creation and the current request's TAC
// must grant the permission. A TAC is skipped only for a genuine legacy token
// (no TAC concept); a modern token with an empty TAC has no permissions and
// is refused.
func (h *wmpEngineHandler) authorizeProtocol(ctx context.Context, protocol Protocol, logger *zap.Logger) *wmp.RPCError {
	required, ok := requiredTACForProtocol[protocol]
	if !ok {
		return nil
	}
	req := requestTACInfo(ctx)
	reqTAC := req.TAC
	if ((h.session.TACEnforced || h.session.TAC != "") && !h.session.TAC.HasAll(required)) ||
		((req.Enforce || reqTAC != "") && !reqTAC.HasAll(required)) {
		logger.Warn("Rejected WMP request - insufficient TAC",
			zap.String("session_tac", string(h.session.TAC)),
			zap.String("request_tac", string(reqTAC)),
			zap.String("required", required),
		)
		return wmp.NewRPCError(wmp.ErrNotAuthorized, map[string]string{
			"reason": "insufficient permissions for flow type",
		})
	}
	return nil
}

// authorizeFlow looks up the flow and enforces its protocol's TAC permission.
// The returned flow is nil when it is not registered (no authorization
// decision is made then; callers report their own not-found error).
func (h *wmpEngineHandler) authorizeFlow(ctx context.Context, flowID string) (flow *Flow, rpcErr *wmp.RPCError) {
	h.session.flowsMu.RLock()
	flow = h.session.flows[flowID]
	h.session.flowsMu.RUnlock()
	if flow == nil {
		return nil, nil
	}
	return flow, h.authorizeProtocol(ctx, flow.Protocol, h.logger().With(zap.String("flow_id", flowID)))
}

// FlowStart handles wmp.flow.start — launches an engine flow goroutine.
func (h *wmpEngineHandler) FlowStart(ctx context.Context, params *wmp.FlowStartParams) (*wmp.FlowStartResult, error) {
	protocol := Protocol(params.FlowType)
	flowID := params.FlowID
	if flowID == "" {
		flowID = uuid.New().String()
	}
	if len(flowID) > maxFlowIDLength {
		return nil, wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{
			"reason": "flow_id exceeds maximum length",
		})
	}

	logger := h.adapter.logger.With(
		zap.String("flow_id", flowID[:min(8, len(flowID))]),
		zap.String("protocol", string(protocol)),
	)

	// Get handler factory.
	h.adapter.manager.handlersMu.RLock()
	factory, ok := h.adapter.manager.flowHandlers[protocol]
	h.adapter.manager.handlersMu.RUnlock()
	if !ok {
		return nil, wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{
			"reason": "unsupported flow type",
		})
	}

	// TAC check, mirroring the WebSocket path (Manager.handleFlowStart): only
	// enforced when the session actually has a TAC to check (empty means
	// legacy auth, which has no TAC concept), so a token without "i" cannot
	// start issuance nor one without "r" a presentation.
	// Both the TAC captured at session creation AND the current request's
	// TAC must grant the flow, so a reduced-permission token cannot drive a
	// session created with a broader one.
	if rpcErr := h.authorizeProtocol(ctx, protocol, logger); rpcErr != nil {
		return nil, rpcErr
	}

	// Parse WMP params into engine FlowStartMessage.
	var startMsg FlowStartMessage
	if params.Params != nil {
		if err := json.Unmarshal(params.Params, &startMsg); err != nil {
			logger.Warn("invalid flow_start params", zap.Error(err))
			return nil, wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{
				"reason": "invalid flow params",
			})
		}
	}
	startMsg.FlowID = flowID
	startMsg.Protocol = protocol

	// checkSlot rejects a duplicate client-supplied flow_id (which would
	// overwrite a live flow's map entry, bypassing the limit, and let either
	// flow's completion delete the other's registration) and enforces the
	// concurrent-flow limit. Callers hold flowsMu.
	checkSlot := func() *wmp.RPCError {
		if _, dup := h.session.flows[flowID]; dup {
			return wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{"reason": "flow_id already in use"})
		}
		if len(h.session.flows) >= MaxPendingFlowsPerSession {
			return wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{"reason": "too many pending flows"})
		}
		return nil
	}

	// Early rejection before doing any work.
	h.session.flowsMu.RLock()
	rpcErr := checkSlot()
	h.session.flowsMu.RUnlock()
	if rpcErr != nil {
		return nil, rpcErr
	}

	// Build the flow and its handler BEFORE the flow becomes visible in
	// session.flows: a concurrent wmp.flow.cancel/action (or session
	// teardown) must never observe a registered flow whose Handler is not yet
	// set - it would report "cancelled" and then let the handler run anyway.
	flow := &Flow{
		ID:        flowID,
		Protocol:  protocol,
		Session:   h.session,
		State:     FlowStep("started"),
		StartTime: time.Now(),
		Data:      make(map[string]interface{}),
	}
	m := h.adapter.manager
	handler, err := factory(flow, m.cfg, logger, m.trustService, m.registryClient, m.verifierStore, m.trustCache)
	if err != nil {
		return nil, wmp.NewRPCError(wmp.ErrInternalError, map[string]string{
			"reason": "failed to create flow handler",
		})
	}
	flow.Handler = handler

	// Publish atomically with the authoritative duplicate/limit check.
	h.session.flowsMu.Lock()
	if rpcErr := checkSlot(); rpcErr != nil {
		h.session.flowsMu.Unlock()
		handler.Cancel()
		return nil, rpcErr
	}
	h.session.flows[flowID] = flow
	h.session.flowsMu.Unlock()

	// Determine flow timeout: client-supplied (spec §6.2) or server default.
	flowTimeout := defaultFlowTimeout
	if clientTimeout := capSeconds(params.Timeout, defaultFlowTimeout); clientTimeout > 0 {
		flowTimeout = clientTimeout
	}

	// Launch the engine flow goroutine. The engine handler calls
	// Session.SendProgress, Session.RequestSign, etc., which go through
	// the wmpSessionTransport and are converted to WMP notifications.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in WMP flow handler", zap.Any("panic", r))
				_ = h.session.SendFlowError(flowID, "", ErrCodeInternalError, "Internal error in flow handler")
			}
			h.session.removeFlow(flowID, flow)
			h.purgeChildFlows(flowID)
		}()

		flowCtx, cancel := context.WithTimeout(context.Background(), flowTimeout)
		defer cancel()

		logger.Info("Starting WMP flow")
		if err := handler.Execute(flowCtx, &startMsg); err != nil {
			logger.Error("WMP flow failed", zap.Error(err))
		} else {
			logger.Info("WMP flow completed")
		}
	}()

	return &wmp.FlowStartResult{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: h.sessionID,
		},
		FlowID:   flowID,
		FlowType: string(protocol),
	}, nil
}

// FlowAction handles wmp.flow.action — routes actions to engine session channels.
//
// The engine's flow handlers block on session channels waiting for client input:
//   - Session.WaitForAction reads from actionCh (for consent, trust_result, etc.)
//   - Session.RequestSign waits on signCh (for proof JWT responses)
//   - Session.RequestMatch waits on matchCh (for DCQL match responses)
//
// This method converts WMP flow.action params into engine message types and
// delivers them to the appropriate channel.
func (h *wmpEngineHandler) FlowAction(ctx context.Context, params *wmp.FlowActionParams) (*wmp.FlowActionResult, error) {
	flowID := params.FlowID

	// Verify flow exists and that this request's token may drive it.
	flow, rpcErr := h.authorizeFlow(ctx, flowID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if flow == nil {
		return nil, wmp.NewRPCError(wmp.ErrFlowError, map[string]string{
			"reason": "flow not found or already completed",
		})
	}

	// Translate spec action names to engine-internal names.
	// This allows WMP clients to use spec-compliant action names
	// (e.g. "accept_offer") while the engine expects its own vocabulary
	// (e.g. "consent"). Engine-native names are also accepted for
	// backwards compatibility and for engine extensions (sign_response,
	// match_response, trust_result) that have no spec equivalent.
	action := params.Action
	if engineAction, ok := specToEngineAction[action]; ok {
		action = engineAction
	}

	switch action {
	case "sign_response":
		var signResp SignResponseMessage
		if params.Params != nil {
			if err := json.Unmarshal(params.Params, &signResp); err != nil {
				return nil, wmp.NewRPCError(wmp.ErrInvalidParams, nil)
			}
		}
		signResp.FlowID = flowID
		// Extract message_id from the raw params if not set by struct unmarshal.
		if signResp.MessageID == "" {
			var raw struct {
				MessageID string `json:"message_id"`
			}
			if params.Params != nil {
				_ = json.Unmarshal(params.Params, &raw)
			}
			signResp.MessageID = raw.MessageID
		}
		select {
		case h.session.signCh <- &signResp:
		case <-time.After(flowActionSendWait):
			return nil, wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{
				"reason": "server overloaded",
			})
		case <-ctx.Done():
			return nil, wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{
				"reason": "server overloaded",
			})
		}

	case "match_response":
		var matchResp MatchResponseMessage
		if params.Params != nil {
			if err := json.Unmarshal(params.Params, &matchResp); err != nil {
				return nil, wmp.NewRPCError(wmp.ErrInvalidParams, nil)
			}
		}
		matchResp.FlowID = flowID
		// Extract message_id from the raw params if not set by struct unmarshal.
		if matchResp.MessageID == "" {
			var raw struct {
				MessageID string `json:"message_id"`
			}
			if params.Params != nil {
				_ = json.Unmarshal(params.Params, &raw)
			}
			matchResp.MessageID = raw.MessageID
		}
		select {
		case h.session.matchCh <- &matchResp:
		case <-time.After(flowActionSendWait):
			return nil, wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{
				"reason": "server overloaded",
			})
		case <-ctx.Done():
			return nil, wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{
				"reason": "server overloaded",
			})
		}

	default:
		// Generic flow actions (consent, trust_result, select_credential, etc.)
		actionMsg := &FlowActionMessage{
			Message: Message{
				FlowID: flowID,
			},
			Action:  action,
			Payload: params.Params,
		}
		select {
		case h.session.actionCh <- actionMsg:
		case <-time.After(flowActionSendWait):
			return nil, wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{
				"reason": "server overloaded",
			})
		case <-ctx.Done():
			return nil, wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{
				"reason": "server overloaded",
			})
		}
	}

	return &wmp.FlowActionResult{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: h.sessionID,
		},
		FlowID: flowID,
		Action: params.Action,
		Status: "accepted",
	}, nil
}

// FlowCancel handles wmp.flow.cancel — cancels an active engine flow.
// Per spec §6.2, returns -31006 with reason "already_terminal" if the flow
// has already completed.
func (h *wmpEngineHandler) FlowCancel(ctx context.Context, params *wmp.FlowCancelParams) (*wmp.FlowCancelResult, error) {
	flow, rpcErr := h.authorizeFlow(ctx, params.FlowID)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if flow == nil {
		// Flow not in map — already reached a terminal state.
		return nil, wmp.NewRPCError(wmp.ErrFlowError, map[string]string{
			"reason": "already_terminal",
		})
	}
	if flow.Handler != nil {
		flow.Handler.Cancel()
	}
	return &wmp.FlowCancelResult{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: h.sessionID,
		},
		FlowID: params.FlowID,
		Status: "cancelled",
	}, nil
}

// FlowComplete handles wmp.flow.complete notifications. For child sub-flows
// (sign/match), this routes the result back to the engine session's signCh
// or matchCh so the blocking RequestSign/RequestMatch calls can complete.
//
// The child mapping is claimed before delivery (so concurrent duplicates
// cannot both deliver) but restored if delivery fails, so a momentarily full
// channel does not lose the only result and strand the parent flow: delivery
// waits up to flowActionSendWait (as FlowAction does) before giving up.
func (h *wmpEngineHandler) FlowComplete(ctx context.Context, params *wmp.FlowCompleteParams) {
	// A child result drives its parent flow, so the request's token must be
	// authorised for the PARENT's protocol. Checked before the mapping is
	// claimed so a denied caller cannot consume it.
	if pending, ok := h.peekChildFlow(params.FlowID); ok {
		if _, rpcErr := h.authorizeFlow(ctx, pending.parentFlowID); rpcErr != nil {
			return
		}
	}
	info, ok := h.popChildFlow(params.FlowID)
	if !ok {
		// Not a child flow — top-level flow completion (handled elsewhere).
		return
	}

	var delivered bool
	switch info.flowType {
	case "sign":
		var resp SignResponseMessage
		if params.Result != nil {
			if err := json.Unmarshal(params.Result, &resp); err != nil {
				// Never turn undecodable data into a zero-value success.
				resp = SignResponseMessage{Error: "malformed sign result from client: " + err.Error()}
			}
		}
		resp.FlowID = info.parentFlowID
		resp.MessageID = info.messageID
		select {
		case h.session.signCh <- &resp:
			delivered = true
		case <-time.After(flowActionSendWait):
		case <-ctx.Done():
		}

	case "match":
		var resp MatchResponseMessage
		if params.Result != nil {
			if err := json.Unmarshal(params.Result, &resp); err != nil {
				resp = MatchResponseMessage{Error: "malformed match result from client: " + err.Error()}
			}
		}
		resp.FlowID = info.parentFlowID
		resp.MessageID = info.messageID
		select {
		case h.session.matchCh <- &resp:
			delivered = true
		case <-time.After(flowActionSendWait):
		case <-ctx.Done():
		}
	default:
		// Unknown type: nothing can be delivered, do not restore.
		return
	}

	if !delivered {
		h.adapter.logger.Warn("child flow result not delivered (channel full); mapping kept for retry",
			zap.String("child_flow_id", params.FlowID))
		h.registerChildFlow(params.FlowID, info.parentFlowID, info.messageID, info.flowType)
	}
}

// FlowError handles wmp.flow.error notifications. For a server-created child
// sub-flow (sign/match) it consumes the child mapping and fails the parent
// RequestSign/RequestMatch immediately instead of letting it wait out its
// timeout. Errors for any other flow are not child-flow failures and are
// ignored here.
func (h *wmpEngineHandler) FlowError(ctx context.Context, params *wmp.FlowErrorParams) {
	if pending, ok := h.peekChildFlow(params.FlowID); ok {
		if _, rpcErr := h.authorizeFlow(ctx, pending.parentFlowID); rpcErr != nil {
			return
		}
	}
	info, ok := h.popChildFlow(params.FlowID)
	if !ok {
		return
	}
	reason := params.Message
	if reason == "" {
		reason = "client reported child flow failure"
	}

	var delivered bool
	switch info.flowType {
	case "sign":
		resp := &SignResponseMessage{Message: Message{Type: TypeSignResponse, FlowID: info.parentFlowID, MessageID: info.messageID}, Error: reason}
		select {
		case h.session.signCh <- resp:
			delivered = true
		case <-time.After(flowActionSendWait):
		case <-ctx.Done():
		}
	case "match":
		resp := &MatchResponseMessage{Message: Message{Type: TypeMatchResponse, FlowID: info.parentFlowID, MessageID: info.messageID}, Error: reason}
		select {
		case h.session.matchCh <- resp:
			delivered = true
		case <-time.After(flowActionSendWait):
		case <-ctx.Done():
		}
	default:
		return
	}
	if !delivered {
		h.adapter.logger.Warn("child flow error not delivered (channel full); mapping kept for retry",
			zap.String("child_flow_id", params.FlowID))
		h.registerChildFlow(params.FlowID, info.parentFlowID, info.messageID, info.flowType)
	}
}

// CapabilityList returns the negotiated capabilities for this session.
func (h *wmpEngineHandler) CapabilityList(_ context.Context, _ *wmp.CapabilityListParams) (*wmp.CapabilityListResult, error) {
	h.adapter.mu.RLock()
	ws, ok := h.adapter.peers[h.sessionID]
	h.adapter.mu.RUnlock()
	if !ok {
		return nil, wmp.NewRPCError(wmp.ErrSessionNotFound, nil)
	}
	return &wmp.CapabilityListResult{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: h.sessionID,
		},
		Capabilities: ws.capabilities,
		Security:     ws.security,
	}, nil
}

// CredentialNotification handles wmp.credential.notification from the client.
// It routes the OID4VCI §10 credential lifecycle event to the engine's
// notification forwarding logic (same path as WebSocket credential_notification).
func (h *wmpEngineHandler) CredentialNotification(ctx context.Context, params *wmp.CredentialNotificationParams) {
	// Credential notifications are an OID4VCI lifecycle event: they need the
	// issuance permission, whether or not the flow is still registered.
	if rpcErr := h.authorizeProtocol(ctx, ProtocolOID4VCI, h.logger().With(zap.String("flow_id", params.FlowID))); rpcErr != nil {
		_ = h.session.SendNotificationAck(params.FlowID, params.NotificationID, "rejected", "insufficient permissions")
		return
	}
	msg := &CredentialNotificationMessage{
		Message: Message{
			Type:   TypeCredentialNotification,
			FlowID: params.FlowID,
		},
		NotificationID:   params.NotificationID,
		Event:            params.Event,
		EventDescription: params.EventDescription,
	}
	h.adapter.manager.dispatchCredentialNotification(h.session, msg)
}

// ---------------------------------------------------------------------------
// wmpSessionTransport — translates engine messages to WMP JSON-RPC
// ---------------------------------------------------------------------------

// wmpSessionTransport implements engine SessionTransport. It intercepts
// outgoing engine messages (FlowProgressMessage, SignRequestMessage, etc.)
// and converts them to WMP JSON-RPC notifications sent via Peer.Notify.
// For sign/match requests, it starts nested sub-flows per the WMP spec.
type wmpSessionTransport struct {
	peer    *wmp.Peer
	ct      *wmp.ChannelTransport
	handler *wmpEngineHandler

	// retireCtx is cancelled by retire when a session resume supersedes this
	// transport. Blocking Peer.Call sends (sign/match sub-flow starts) derive
	// their context from it so an unacknowledged call cannot keep
	// Session.Send's read lock - and therefore the resume's write lock -
	// held for the full call timeout.
	retireCtx    context.Context
	retireCancel context.CancelFunc

	// successor is the transport that replaced this one on session.resume.
	// handedOff is closed once it is set; a child-flow start that was in
	// flight when this transport retired waits on it to be reissued there.
	successor   *wmpSessionTransport
	handedOff   chan struct{}
	handoffOnce sync.Once
}

func newWMPSessionTransport(peer *wmp.Peer, ct *wmp.ChannelTransport) *wmpSessionTransport {
	ctx, cancel := context.WithCancel(context.Background())
	return &wmpSessionTransport{peer: peer, ct: ct, retireCtx: ctx, retireCancel: cancel, handedOff: make(chan struct{})}
}

// handOff records next as the transport that replaced t. Called by
// session.resume after the engine session's transport has been swapped, so
// child-flow starts interrupted by retire() can be reissued on next.
func (t *wmpSessionTransport) handOff(next *wmpSessionTransport) {
	t.handoffOnce.Do(func() {
		t.successor = next
		if t.handedOff != nil {
			close(t.handedOff)
		}
	})
}

// startChildFlow sends the wmp.flow.start for a sign/match sub-flow and waits
// for the client's acknowledgement. If the transport is retired by a
// session.resume while the acknowledgement is pending, the request is NOT
// reported as a failure (which would make Session.Send fail and end the
// parent flow before RequestSign/RequestMatch starts waiting for the result,
// even though the child-flow table survives the resume). Instead it is
// reissued, under the same child flow ID, on the replacement transport.
func (t *wmpSessionTransport) startChildFlow(childFlowID, flowType string, params json.RawMessage) error {
	callCtx, cancel := context.WithTimeout(t.callContext(), childFlowStartTimeout)
	defer cancel()
	var startResult wmp.FlowStartResult
	err := t.peer.Call(callCtx, wmp.MethodFlowStart, &wmp.FlowStartParams{
		WMP:      t.wmpMeta(),
		FlowType: flowType,
		FlowID:   childFlowID,
		Params:   params,
	}, &startResult)
	if err != nil && t.retireCtx != nil && t.retireCtx.Err() != nil {
		go t.reissueChildFlow(childFlowID, flowType, params)
		return nil
	}
	return err
}

// startChildFlowOrForget is startChildFlow, dropping the child mapping when
// the start fails outright so a failed start leaves nothing behind.
func (t *wmpSessionTransport) startChildFlowOrForget(childFlowID, flowType string, params json.RawMessage) error {
	if err := t.startChildFlow(childFlowID, flowType, params); err != nil {
		t.handler.popChildFlow(childFlowID)
		return err
	}
	return nil
}

// reissueChildFlow waits for the replacement transport and starts the child
// flow there. On failure the child mapping is dropped and the parent's
// sign/match wait is left to its own timeout or session end.
func (t *wmpSessionTransport) reissueChildFlow(childFlowID, flowType string, params json.RawMessage) {
	timer := time.NewTimer(childFlowStartTimeout)
	defer timer.Stop()
	var next *wmpSessionTransport
	select {
	case <-t.handedOff:
		next = t.successor
	case <-t.handler.session.closeCh:
		return
	case <-timer.C:
	}
	if next == nil {
		t.handler.popChildFlow(childFlowID)
		t.handler.adapter.logger.Warn("child flow start not reissued: no replacement transport",
			zap.String("child_flow_id", childFlowID))
		return
	}
	if err := next.startChildFlow(childFlowID, flowType, params); err != nil {
		t.handler.popChildFlow(childFlowID)
		t.handler.adapter.logger.Warn("child flow start failed on resumed transport",
			zap.String("child_flow_id", childFlowID), zap.Error(err))
	}
}

// retire aborts any in-flight blocking Call on this transport without closing
// the underlying channel, so queued notifications are still drained into the
// event buffer by the resume. Safe to call more than once.
func (t *wmpSessionTransport) retire() {
	if t.retireCancel != nil {
		t.retireCancel()
	}
}

// callContext is the parent context for blocking Peer.Call sends.
func (t *wmpSessionTransport) callContext() context.Context {
	if t.retireCtx != nil {
		return t.retireCtx
	}
	return context.Background()
}

// SendJSON intercepts engine message structs and translates them to WMP
// JSON-RPC notifications. The peer writes to the ChannelTransport, which
// feeds the SSE event stream.
// wmpMeta returns a Metadata with version and session ID pre-filled.
func (t *wmpSessionTransport) wmpMeta() wmp.Metadata {
	return wmp.Metadata{
		Version:   wmp.Version,
		SessionID: t.handler.sessionID,
	}
}

func (t *wmpSessionTransport) SendJSON(msg interface{}) error {
	ctx := context.Background()

	switch m := msg.(type) {
	case *FlowProgressMessage:
		return t.peer.Notify(ctx, wmp.MethodFlowProgress, &wmp.FlowProgressParams{
			WMP:     t.wmpMeta(),
			FlowID:  m.FlowID,
			Step:    string(m.Step),
			Payload: m.Payload,
		})

	case *FlowCompleteMessage:
		result, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return t.peer.Notify(ctx, wmp.MethodFlowComplete, &wmp.FlowCompleteParams{
			WMP:    t.wmpMeta(),
			FlowID: m.FlowID,
			Result: result,
		})

	case *FlowErrorMessage:
		// Carry Error.Details (e.g. OID4VP's redirect_uri) in Data so the
		// WMP client sees what a WebSocket client would.
		var data json.RawMessage
		if len(m.Error.Details) > 0 {
			b, err := json.Marshal(m.Error.Details)
			if err != nil {
				return err
			}
			data = b
		}
		return t.peer.Notify(ctx, wmp.MethodFlowError, &wmp.FlowErrorParams{
			WMP:     t.wmpMeta(),
			FlowID:  m.FlowID,
			Code:    mapErrorCode(m.Error.Code),
			Message: m.Error.Message,
			Data:    data,
		})

	case *SignRequestMessage:
		// Start a nested sign sub-flow per WMP spec. The client handles
		// the flow.start, performs the signing, then sends flow.complete
		// with the proof. FlowComplete routes the result to signCh.
		childFlowID := uuid.New().String()
		t.handler.registerChildFlow(childFlowID, m.FlowID, m.MessageID, "sign")

		subFlowParams := openid4x.SignSubFlowParams{
			Action:                string(m.Action),
			Nonce:                 m.Params.Nonce,
			Audience:              m.Params.Audience,
			ProofType:             m.Params.ProofType,
			ParentFlowID:          m.FlowID,
			TransactionData:       convertTransactionData(m.Params.TransactionData),
			Issuer:                m.Params.Issuer,
			ProofTypesSupported:   m.Params.ProofTypesSupported,
			Count:                 m.Params.Count,
			ResponseURI:           m.Params.ResponseURI,
			VerifierJWKThumbprint: m.Params.VerifierJwkThumbprint,
			VerifierSessionID:     m.Params.VerifierSessionID,
			CredentialsToInclude:  convertCredentialsToInclude(m.Params.CredentialsToInclude),
			ReissuanceKid:         m.Params.ReissuanceKid,
			HTM:                   m.Params.HTM,
			HTU:                   m.Params.HTU,
			DPoPNonce:             m.Params.DPoPNonce,
			ATH:                   m.Params.ATH,
			KeyID:                 m.Params.KeyID,
			AttestationChallenge:  m.Params.AttestationChallenge,
		}
		paramsJSON, err := json.Marshal(subFlowParams)
		if err != nil {
			t.handler.popChildFlow(childFlowID)
			return err
		}
		return t.startChildFlowOrForget(childFlowID, wmp.FlowTypeSign, paramsJSON)

	case *MatchRequestMessage:
		// Start a nested match sub-flow. Same pattern as sign.
		childFlowID := uuid.New().String()
		t.handler.registerChildFlow(childFlowID, m.FlowID, m.MessageID, "match")

		matchParams := map[string]interface{}{
			"dcql_query":     m.DCQLQuery,
			"parent_flow_id": m.FlowID,
		}
		paramsJSON, err := json.Marshal(matchParams)
		if err != nil {
			t.handler.popChildFlow(childFlowID)
			return err
		}
		return t.startChildFlowOrForget(childFlowID, "match", paramsJSON)

	default:
		// Fallback for engine messages with no dedicated WMP method
		// (PushMessage, credential-notification acks, ...): wrap the legacy
		// object in a wmp.message.deliver notification so every event on
		// the stream is valid JSON-RPC.
		data, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		var probe struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(data, &probe)
		return t.peer.Notify(ctx, wmp.MethodMessageDeliver, &wmp.MessageDeliverParams{
			WMP:         t.wmpMeta(),
			ContentType: "application/json",
			MessageType: probe.Type,
			Body:        data,
		})
	}
}

// convertTransactionData converts the engine's TransactionData (sent over
// the native WebSocket transport) to its WMP wire equivalent. The two types
// are field-for-field identical; this only exists so the two transports
// don't share a Go type across the engine/wmp package boundary.
func convertTransactionData(in []TransactionData) []openid4x.TransactionData {
	if in == nil {
		return nil
	}
	out := make([]openid4x.TransactionData, len(in))
	for i, td := range in {
		out[i] = openid4x.TransactionData{
			Type:                     td.Type,
			Params:                   td.Params,
			CredentialIDs:            td.CredentialIDs,
			HashAlgorithm:            td.HashAlgorithm,
			TransactionDataHashesAlg: td.TransactionDataHashesAlg,
		}
	}
	return out
}

// convertCredentialsToInclude converts the engine's CredentialRef (sent over
// the native WebSocket transport) to its WMP wire equivalent, CredentialSelection.
func convertCredentialsToInclude(in []CredentialRef) []openid4x.CredentialSelection {
	if in == nil {
		return nil
	}
	out := make([]openid4x.CredentialSelection, len(in))
	for i, ref := range in {
		out[i] = openid4x.CredentialSelection{
			CredentialID:      ref.CredentialID,
			CredentialQueryID: ref.CredentialQueryID,
			DisclosedClaims:   ref.DisclosedClaims,
		}
	}
	return out
}

func (t *wmpSessionTransport) ReadMessage(ctx context.Context) ([]byte, error) {
	return t.ct.ReadMessage(ctx)
}

func (t *wmpSessionTransport) Close() error {
	return t.ct.Close()
}

// ---------------------------------------------------------------------------
// Error code mapping
// ---------------------------------------------------------------------------

// mapErrorCode converts engine string error codes to WMP integer codes.
func mapErrorCode(code ErrorCode) int {
	switch code {
	case ErrCodeAuthFailed, ErrCodeAuthorizationFail:
		return wmp.ErrNotAuthorized
	case ErrCodeInvalidMessage:
		return wmp.ErrInvalidRequest
	case ErrCodeSignError:
		return wmp.ErrSignatureInvalid
	case ErrCodeTooManyRequests:
		return wmp.ErrRateLimited
	case ErrCodeInternalError:
		return wmp.ErrInternalError
	default:
		// Most engine errors map to the generic flow error with details
		// carried in the message field.
		return wmp.ErrFlowError
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func wmpErrorBytes(id json.RawMessage, code int, data interface{}) ([]byte, error) {
	resp := wmp.NewErrorResponse(id, wmp.NewRPCError(code, data))
	return json.Marshal(resp)
}

func wmpResponseBytes(id json.RawMessage, result interface{}) ([]byte, error) {
	resp, err := wmp.NewResponse(id, result)
	if err != nil {
		return wmpErrorBytes(id, wmp.ErrInternalError, nil)
	}
	return json.Marshal(resp)
}

// wmpOutboundRequestTTL bounds how long a tracked server-initiated request ID
// stays routable: the Call() timeout plus slack. Entries are also removed when
// answered and when their session closes.
const wmpOutboundRequestTTL = childFlowStartTimeout + 30*time.Second

// outboundRequest is a server->client JSON-RPC request awaiting its response.
type outboundRequest struct {
	sessionID string
	expiresAt time.Time
}

// trackOutbound records the ID of a server-initiated request (a message with
// both an id and a method) emitted on the session's transport, so the client's
// response envelope can be routed back to the session without a session header.
func (a *WMPAdapter) trackOutbound(sessionID string, data []byte) {
	var env struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if json.Unmarshal(data, &env) != nil || env.Method == "" || len(env.ID) == 0 || string(env.ID) == "null" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.outbound == nil {
		a.outbound = make(map[string]outboundRequest)
	}
	a.outbound[string(env.ID)] = outboundRequest{sessionID: sessionID, expiresAt: time.Now().Add(wmpOutboundRequestTTL)}
}

// routeResponse delivers a client response to the session that has the
// matching outstanding server-initiated request. With a session ID (header or
// metadata) the session is the one named, already ownership-checked by the
// HTTP layer; the matching tracked ID, if any, is consumed. Without one the
// session is found via the request ID, and the caller must own it. IDs are
// one-shot; unknown, expired, already-answered, or foreign IDs are rejected
// identically so nothing is revealed about other users' requests.
func (a *WMPAdapter) routeResponse(ctx context.Context, sessionID string, caller wmpCaller, msg *wmp.Message, body []byte) ([]byte, error) {
	key := string(msg.ID)
	var ws *wmpSession

	a.mu.Lock()
	o, tracked := a.outbound[key]
	if tracked && time.Now().After(o.expiresAt) {
		delete(a.outbound, key)
		tracked = false
	}
	if sessionID != "" {
		if tracked && o.sessionID == sessionID {
			delete(a.outbound, key)
		}
		ws = a.peers[sessionID]
	} else if tracked {
		if cand, ok := a.peers[o.sessionID]; ok && ownsSession(cand, caller) {
			// Consume only for the owner: a foreign token must not be able to
			// burn another user's pending ID.
			delete(a.outbound, key)
			ws = cand
			sessionID = o.sessionID
		}
	}
	a.mu.Unlock()

	if ws == nil {
		if sessionID != "" {
			return wmpErrorBytes(nil, wmp.ErrSessionNotFound, nil)
		}
		return wmpErrorBytes(nil, wmp.ErrNotAuthorized, map[string]string{
			"reason": "unknown or unauthorized response ID",
		})
	}
	a.touchSession(sessionID)
	return ws.peer.HandleRequestSync(ctx, body)
}
