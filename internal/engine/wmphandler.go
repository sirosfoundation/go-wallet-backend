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

// specToEngineAction maps WMP spec action names to engine action names.
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

	mu                  sync.RWMutex
	peers               map[string]*wmpSession      // keyed by WMP session ID
	resumptionTokens    map[string]*resumptionEntry // token -> entry with session ID and expiry
	eventBufs           map[string]*wmpEventBuffer  // keyed by WMP session ID; survives resume unlike peers
	outbound            map[string]outboundRequest  // server->client request IDs awaiting a response (see trackOutbound)
	externalURL         string                      // public base URL for discovery (SetExternalURL)
	draining            bool                        // set by Drain/Close; new sessions and requests are refused
	afterExpiryScan     func()                      // test hook: runs between cleanupExpired's scan and its closes
	beforeResumePublish func(sessionID string)      // test hook: runs between a resume's validation and its publication
	afterRegister       func(sessionID string)      // test hook: runs between manager registration and peer publication
	beforeCreateToken   func(sessionID string)      // test hook: runs between publishing a new peer and issuing its token

	// tokenSlotsMu guards tokenSlots, the number of live WMP sessions per
	// bearer token (see reserveSlot).
	tokenSlotsMu sync.Mutex
	tokenSlots   map[string]int

	stopCh      chan struct{}
	stopOnce    sync.Once
	loopStarted chan struct{} // closed when cleanupLoop begins running
	loopDone    chan struct{} // closed when cleanupLoop has exited
}

// maxWMPSessionsPerToken bounds live WMP sessions per bearer token. Anonymous
// tokens are not indexed by user, so without it one token could create unlimited
// sessions.
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

// maxWMPBufferedEvents bounds the SSE events retained per session for Last-
// Event-ID replay (also across wmp.session.resume).
const maxWMPBufferedEvents = 200

// wmpBufferedEvent is one retained SSE frame with a session-durable sequence
// number.
type wmpBufferedEvent struct {
	ID   int64
	Data []byte
}

// wmpEventBuffer retains recent outbound SSE events so a reconnecting client
// (after a resume or an SSE drop) can replay them via Last-Event-ID.
//
// Events are appended by the session's pump goroutine (see pumpEvents) at
// emission time, so notifications emitted while no client is connected are
// retained.
type wmpEventBuffer struct {
	mu     sync.Mutex
	events []wmpBufferedEvent
	nextID int64

	// wake is closed and replaced on every append; done is closed when the
	// session ends.
	wake     chan struct{}
	done     chan struct{}
	doneOnce sync.Once

	// active is the currently streaming SSE connection; a new one supersedes it
	// (see acquire).
	active *wmpStream
}

// wmpStream identifies one SSE connection registered on a buffer.
type wmpStream struct {
	cancel context.CancelFunc
}

// ensure lazily initialises the signalling channels. Callers must hold b.mu.
func (b *wmpEventBuffer) ensure() {
	if b.wake == nil {
		b.wake = make(chan struct{})
	}
	if b.done == nil {
		b.done = make(chan struct{})
	}
}

// acquire registers a new SSE connection and cancels any previous one, so a
// stale connection cannot block a reconnect. Nothing is lost: replay is cursor-
// driven from the new connection's Last-Event-ID. Callers must release the
// returned stream.
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

// release clears the active connection only if s is still the registered one.
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

// replaySince returns buffered events after lastEventID, or nil if it does not
// parse (replay is best-effort).
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

// missedSince counts the events a client that last received lastReceivedID has
// not seen. A missing or too-old cursor counts every retained event.
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

// pumpEvents moves a transport's outbound notifications into buf as they are
// emitted, until ctx is cancelled (after draining the queue), then closes done.
func pumpEvents(ctx context.Context, ct *wmp.ChannelTransport, buf *wmpEventBuffer, done chan<- struct{}, onOut func([]byte)) {
	defer close(done)
	out := ct.Out()
	emit := func(data []byte) {
		// Track before the event is visible so a response cannot precede its
		// registration.
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

// resumptionEntry binds a resumption token to a session.
//
// A resume rotates the token. To survive a lost response, a consumed token stays
// redeemable once more for resumptionGraceWindow, but only while its successor
// is unused. Using either token retires both, so at most one resume succeeds per
// rotation.
type resumptionEntry struct {
	sessionID string
	expiresAt time.Time

	// used marks a token a resume already consumed; it is redeemable only while
	// its successor is outstanding and expiresAt has not passed.
	used        bool
	successor   string // token issued by the resume that consumed this one
	predecessor string // token whose resume issued this one
}

// resumptionGraceWindow bounds how long a consumed token stays redeemable (lost
// resume response).
const resumptionGraceWindow = 2 * time.Minute

// wmpSessionIdleTimeout closes a WMP session after this much inactivity.
const wmpSessionIdleTimeout = 10 * time.Minute

// resumptionTokenTTL is the lifetime of a resumption token.
const resumptionTokenTTL = 10 * time.Minute

// capSeconds converts client-supplied seconds to a Duration capped at limit. The
// cap is applied before multiplying so values near MaxInt cannot overflow. Non-
// positive input yields 0.
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

// flowActionSendWait bounds how long FlowAction waits to enqueue onto a full
// response channel before returning ErrRateLimited, giving a legitimate in-
// flight response room to drain.
const flowActionSendWait = 3 * time.Second

// childFlowStartTimeout bounds the wmp.flow.start Call() for a nested sign/match
// sub-flow, so an unresponsive client cannot stall the requesting engine
// goroutine (it waits for the ack, not the result).
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
	// offered is what the client offered in wmp.session.create. Feature gating
	// reads this, never capabilities, which falls back to all server
	// capabilities when none are offered.
	offered   wmp.Capabilities
	security  wmp.SecurityMode // negotiated security mode for resume echo
	expiresAt time.Time        // absolute session deadline from TTL
	// ownerTokenID is the creating token's jti; it tells anonymous sessions
	// (UserID == "") apart.
	ownerTokenID string
	// slot is the session budget reserved at creation, released once by teardown
	// and shared across resumes.
	slot *wmpSlot
}

// wmpCaller is the identity validated from a request's bearer token.
type wmpCaller struct {
	UserID   string
	TenantID string
	TokenID  string // jti; may be empty
	// TAC is this request's token-authorized-capabilities. It bounds the request
	// independently of the session's creation-time TAC. Empty means legacy auth.
	TAC claims.TAC
	// EnforceTAC is true for a modern token, whose TAC is authoritative even
	// when empty; false only for a legacy token. A non-empty TAC is always
	// enforced.
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

// NewWMPAdapter creates an adapter bridging WMP JSON-RPC to the engine.
// bearerToken is injected because the engine cannot import pkg/middleware.
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
		loopStarted:      make(chan struct{}),
		loopDone:         make(chan struct{}),
	}
	go a.cleanupLoop()
	return a
}

// CleanupStarted returns a channel that is closed once this adapter's cleanup
// goroutine is running.
func (a *WMPAdapter) CleanupStarted() <-chan struct{} { return a.loopStarted }

// CleanupStopped returns a channel that is closed once this adapter's cleanup
// goroutine has exited.
func (a *WMPAdapter) CleanupStopped() <-chan struct{} { return a.loopDone }

// Drain refuses new work: HTTP handlers answer 503 and session.create/resume are
// rejected. Idempotent; the first step of Close.
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
	// Refuse new work first so a racing session.create cannot register after the
	// snapshot below.
	a.Drain()
	a.stopOnce.Do(func() { close(a.stopCh) })
	if a.loopDone != nil {
		<-a.loopDone
	}
	// End every live session so SSE handlers terminate; otherwise graceful
	// shutdown waits out its timeout.
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
	if a.loopStarted != nil {
		close(a.loopStarted)
	}
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

	// Keep the scanned *wmpSession, not just its ID: a resume may replace the
	// peer after the scan, and the stale decision must not close the
	// replacement.
	type expiredEntry struct {
		sid string
		ws  *wmpSession
	}
	var expiredSessions []expiredEntry
	for sid, ws := range a.peers {
		if wmpSessionExpiredLocked(ws, now) {
			expiredSessions = append(expiredSessions, expiredEntry{sid, ws})
		}
	}
	a.mu.Unlock()

	if a.afterExpiryScan != nil {
		a.afterExpiryScan()
	}

	for _, e := range expiredSessions {
		// Re-check under the lock: the session may have been touched since the
		// scan.
		if a.closeSessionIf(e.sid, e.ws, func(ws *wmpSession) bool {
			return wmpSessionExpiredLocked(ws, time.Now())
		}) {
			a.logger.Info("Closed expired/idle WMP session", zap.String("session_id", shortID(e.sid)))
		}
	}
}

func shortID(sid string) string {
	if len(sid) > 8 {
		return sid[:8]
	}
	return sid
}

// wmpSessionExpiredLocked reports whether ws is idle or past its TTL at now.
// Callers must hold a.mu (lastActivity is written under it).
func wmpSessionExpiredLocked(ws *wmpSession, now time.Time) bool {
	if now.Sub(ws.lastActivity) > wmpSessionIdleTimeout {
		return true
	}
	return !ws.expiresAt.IsZero() && now.After(ws.expiresAt)
}

// verifySessionOwnership reports whether the session belongs to the caller (see
// ownsSession).
func (a *WMPAdapter) verifySessionOwnership(sessionID string, caller wmpCaller) bool {
	a.mu.RLock()
	ws, ok := a.peers[sessionID]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	return ownsSession(ws, caller)
}

// sameIdentity reports whether a validated token identity is the caller's: same
// user, same normalised tenant and, for an anonymous token, same jti.
func sameIdentity(id tokenIdentity, caller wmpCaller) bool {
	if id.UserID != caller.UserID || normalizeTenant(id.TenantID) != normalizeTenant(caller.TenantID) {
		return false
	}
	if id.UserID == "" && (id.JTI == "" || id.JTI != caller.TokenID) {
		return false
	}
	return true
}

func ownsSession(ws *wmpSession, caller wmpCaller) bool {
	if ws.session.UserID != caller.UserID {
		return false
	}
	// Compare normalised tenants: an empty claim must not act as a wildcard (the
	// middleware maps a missing tenant_id to the default).
	if normalizeTenant(ws.session.TenantID) != normalizeTenant(caller.TenantID) {
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

// HandleRPC handles one JSON-RPC request in-process (not network-reachable). For
// session.create the identity comes from params.auth; otherwise it is
// HandleRPCAs for a caller with no token ID.
func (a *WMPAdapter) HandleRPC(ctx context.Context, sessionID, userID, tenantID string, body []byte) ([]byte, error) {
	if msg, err := wmp.DecodeMessage(body); err == nil && msg.Method == wmp.MethodSessionCreate {
		var params wmp.SessionCreateParams
		if json.Unmarshal(msg.AsRequest().Params, &params) == nil && params.Auth != nil && params.Auth.Token != "" {
			if id, verr := a.manager.validateTokenAuth(ctx, params.Auth.Token); verr == nil {
				return a.HandleRPCAs(ctx, sessionID, wmpCaller{UserID: id.UserID, TenantID: id.TenantID, TokenID: id.JTI, TAC: id.TAC, EnforceTAC: id.EnforceTAC}, body)
			}
		}
	}
	return a.HandleRPCAs(ctx, sessionID, wmpCaller{UserID: userID, TenantID: tenantID}, body)
}

// HandleRPCAs handles one JSON-RPC request. sessionID comes from the Wmp-
// Session-Id header (empty for session.create); caller is the identity validated
// from the bearer token, needed to authorize wmp.session.resume.
func (a *WMPAdapter) HandleRPCAs(ctx context.Context, sessionID string, caller wmpCaller, body []byte) ([]byte, error) {
	// Decode with go-wmp's decoder so the envelope limits are enforced for
	// session.create/resume like every other method.
	msg, err := wmp.DecodeMessage(body)
	if err != nil {
		return wmpErrorBytes(nil, wmp.ErrParseError, nil)
	}

	if msg.Method == wmp.MethodSessionCreate {
		return a.handleSessionCreate(ctx, caller, msg)
	}
	if msg.Method == wmp.MethodSessionResume {
		return a.handleSessionResume(ctx, caller, msg)
	}

	// A response carries no session identity; route it by the server-initiated
	// request ID it answers.
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

	a.touchSession(sessionID)

	return ws.peer.HandleRequestSync(context.WithValue(ctx, wmpCallerTACKey{}, wmpTACInfo{TAC: caller.TAC, Enforce: caller.EnforceTAC || caller.TAC != ""}), body)
}

// Events returns the session's outbound notifications (retained events, then
// live ones) on a channel closed when the session ends. A convenience
// subscription; the SSE handler reads the buffer directly.
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

// getOrCreateEventBuffer returns the session's persistent SSE replay buffer,
// which is not replaced on resume.
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

// dropSessionStateLocked removes the session's event buffer (terminating SSE
// handlers), resumption tokens and outbound entries. Callers must hold a.mu.
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

// teardown ends a wmpSession already removed from a.peers, as a WebSocket
// disconnect would.
func (a *WMPAdapter) teardown(ws *wmpSession) {
	ws.cancel()
	_ = ws.transport.Close()
	ws.session.endSession()
	a.manager.unregisterSession(ws.session)
	ws.slot.release()
}

// closeSessionIfCurrent tears down sessionID only if ws is still its active
// wmpSession. peer.Serve returning (e.g. a resume closed this transport) must
// not destroy the replacement the resume installed.
func (a *WMPAdapter) closeSessionIfCurrent(sessionID string, ws *wmpSession) {
	a.closeSessionIf(sessionID, ws, nil)
}

// closeSessionIf is closeSessionIfCurrent with an extra predicate evaluated
// under a.mu once ws is confirmed current; a false result leaves the session
// alone. It reports whether the session was closed.
func (a *WMPAdapter) closeSessionIf(sessionID string, ws *wmpSession, pred func(*wmpSession) bool) bool {
	a.mu.Lock()
	current, ok := a.peers[sessionID]
	if !ok || current != ws || (pred != nil && !pred(ws)) {
		// Superseded by a resume, already removed, or no longer eligible.
		a.mu.Unlock()
		return false
	}
	delete(a.peers, sessionID)
	a.dropSessionStateLocked(sessionID)
	a.mu.Unlock()

	a.teardown(ws)
	return true
}

// closeSessionIfHandler closes sessionID only if h is the installed peer's
// handler, so a close arriving on a connection a resume replaced cannot end the
// resumed session.
func (a *WMPAdapter) closeSessionIfHandler(sessionID string, h *wmpEngineHandler) {
	a.mu.RLock()
	ws, ok := a.peers[sessionID]
	a.mu.RUnlock()
	if !ok {
		return
	}
	a.closeSessionIf(sessionID, ws, func(cur *wmpSession) bool { return cur.handler == h })
}

// supersedeSession drops the adapter state (peer, tokens, buffer) of a session
// the manager replaced for the same user, then tears it down. No-op if it was
// never published or now belongs to another engine session.
func (a *WMPAdapter) supersedeSession(sessionID string, session *Session) {
	a.mu.Lock()
	ws, ok := a.peers[sessionID]
	if !ok || ws.session != session {
		a.mu.Unlock()
		return
	}
	delete(a.peers, sessionID)
	a.dropSessionStateLocked(sessionID)
	a.mu.Unlock()
	a.teardown(ws)
}

// handleSessionCreate creates a new engine session and wmp.Peer.
func (a *WMPAdapter) handleSessionCreate(ctx context.Context, caller wmpCaller, msg *wmp.Message) ([]byte, error) {
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

	// This server supports TLS only; an omitted mode means tls. Anything else is
	// rejected (spec §2.1), not echoed.
	switch params.Security.Mode {
	case "":
		params.Security.Mode = "tls"
	case "tls":
	default:
		return wmpErrorBytes(req.ID, wmp.ErrInvalidParams, map[string]string{
			"reason": fmt.Sprintf("security mode %q is not supported; use 'tls'", params.Security.Mode),
		})
	}

	// The HTTP-validated caller owns the session. params.auth is optional but
	// must resolve to the same identity; a mismatch gets the invalid-token error
	// so it does not reveal whether another token is valid.
	if params.Auth != nil && params.Auth.Token != "" {
		if params.Auth.Type != "" && params.Auth.Type != "bearer" {
			return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
				"reason": "unsupported auth type; only 'bearer' is supported",
			})
		}
		id, err := a.manager.validateTokenAuth(ctx, params.Auth.Token)
		if err != nil || !sameIdentity(id, caller) {
			if err != nil {
				a.logger.Warn("WMP auth failed", zap.Error(err))
			} else {
				a.logger.Warn("WMP session.create rejected: params.auth does not match the authenticated caller")
			}
			return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
				"reason": "invalid or expired token",
			})
		}
	}
	userID, tokenID := caller.UserID, caller.TokenID
	tenantID := normalizeTenant(caller.TenantID)
	tac, enforceTAC := caller.TAC, caller.EnforceTAC

	// Anonymous sessions are told apart only by jti; without one, fail closed.
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

	ct := wmp.NewChannelTransport(50, 200)

	handler := &wmpEngineHandler{
		adapter:   a,
		sessionID: sessionID,
	}

	peer := wmp.NewPeer(ct, handler, wmp.WithLogger(slog.Default()))

	// Engine transport that translates engine messages to WMP notifications.
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

	handler.session = session
	session.onSuperseded = func() { a.supersedeSession(sessionID, session) }

	// Register with the engine manager. False means the user was revoked since
	// token validation (the transport is already closed): refuse, as the
	// WebSocket handshake does.
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

	// Fully initialise before publishing in a.peers.
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
		offered:      params.CapabilitiesOffered,
		security:     params.Security,
		expiresAt:    expiresAt,
		ownerTokenID: tokenID,
		slot:         slot,
	}
	buf := &wmpEventBuffer{}

	if a.afterRegister != nil {
		a.afterRegister(sessionID)
	}

	a.mu.Lock()
	if a.draining {
		// Shutdown began after admission: nothing would close this session.
		a.mu.Unlock()
		a.teardown(ws)
		return wmpErrorBytes(req.ID, wmp.ErrRateLimited, map[string]string{
			"reason": "server shutting down",
		})
	}
	// A concurrent create for the same user may have superseded this session
	// after registerSession. Checking under a.mu (which guards publication)
	// makes a superseded create fail instead of publishing a doomed peer.
	if !a.manager.isCurrentSession(session) {
		a.mu.Unlock()
		a.teardown(ws)
		a.logger.Warn("WMP session.create rejected: superseded by a newer session during creation", zap.String("session_id", sessionID))
		return wmpErrorBytes(req.ID, wmp.ErrInternalError, map[string]string{
			"reason": "session superseded during creation",
		})
	}
	a.peers[sessionID] = ws
	a.eventBufs[sessionID] = buf
	a.mu.Unlock()

	// Buffer notifications as they are emitted (see pumpEvents).
	go pumpEvents(sessionCtx, ct, buf, ws.pumpDone, func(data []byte) { a.trackOutbound(sessionID, data) })

	// Serve the peer's read loop (responses to outbound Call()s).
	go func() {
		_ = peer.Serve(sessionCtx)
		a.closeSessionIfCurrent(sessionID, ws)
	}()

	if a.beforeCreateToken != nil {
		a.beforeCreateToken(sessionID)
	}
	// Issue the token only while this peer is still installed, so a revocation,
	// replacement or close since publication fails the create. Also surfaces a
	// crypto/rand failure.
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

// issueResumptionTokenIfCurrent issues a token (spec §4.5.2: >=128 bits, rotated
// on resume) for sessionID only if ws is still the installed peer, atomically
// with CloseSession.
func (a *WMPAdapter) issueResumptionTokenIfCurrent(sessionID string, ws *wmpSession) (string, bool) {
	return a.issueResumptionToken(sessionID, ws, "")
}

// issueRotatedResumptionToken is issueResumptionTokenIfCurrent for a resume;
// prev links the rotation pair (see resumptionEntry).
func (a *WMPAdapter) issueRotatedResumptionToken(sessionID string, ws *wmpSession, prev string) (string, bool) {
	return a.issueResumptionToken(sessionID, ws, prev)
}

// usableResumptionTokenLocked returns token's entry if redeemable: unexpired
// and, if already consumed, its successor is still unused (the resume response
// was presumably lost). Expired entries are dropped. Caller holds a.mu.
func (a *WMPAdapter) usableResumptionTokenLocked(token string) (*resumptionEntry, bool) {
	entry, ok := a.resumptionTokens[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(a.resumptionTokens, token)
		return nil, false
	}
	if entry.used {
		succ, ok := a.resumptionTokens[entry.successor]
		if entry.successor == "" || !ok || succ.used {
			return nil, false
		}
	}
	return entry, true
}

// consumeResumptionTokenLocked redeems token: a fresh one is marked used and
// kept for the grace window, a used one is deleted; either way its rotation
// partner is retired so a pair yields one resume. Caller holds a.mu after
// usableResumptionTokenLocked succeeded.
func (a *WMPAdapter) consumeResumptionTokenLocked(token string) {
	entry, ok := a.resumptionTokens[token]
	if !ok {
		return
	}
	if entry.predecessor != "" {
		delete(a.resumptionTokens, entry.predecessor)
		entry.predecessor = ""
	}
	if entry.used {
		delete(a.resumptionTokens, entry.successor)
		delete(a.resumptionTokens, token)
		return
	}
	entry.used = true
	if grace := time.Now().Add(resumptionGraceWindow); grace.Before(entry.expiresAt) {
		entry.expiresAt = grace
	}
}

// issueResumptionToken creates and stores a token. With a non-nil ws the peer
// check and the insertion happen under one a.mu critical section.
func (a *WMPAdapter) issueResumptionToken(sessionID string, ws *wmpSession, prev string) (string, bool) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		a.logger.Error("failed to generate resumption token", zap.Error(err))
		return "", ws == nil
	}
	token := base64.RawURLEncoding.EncodeToString(b)

	a.mu.Lock()
	defer a.mu.Unlock()
	if ws != nil && (a.peers[sessionID] != ws || !a.manager.isCurrentSession(ws.session)) {
		return "", false
	}
	a.resumptionTokens[token] = &resumptionEntry{
		sessionID:   sessionID,
		expiresAt:   time.Now().Add(resumptionTokenTTL),
		predecessor: prev,
	}
	if p, ok := a.resumptionTokens[prev]; ok && prev != "" && p.used && p.sessionID == sessionID {
		p.successor = token
	}
	return token, true
}

// serverCapabilities builds the capability map from registered flow handlers
// (spec §4.2.1).
func (a *WMPAdapter) serverCapabilities() wmp.Capabilities {
	caps := wmp.Capabilities{
		"sign": json.RawMessage(`{"proof_types": ["jwt"]}`),
	}
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
		// State is written under flow.mu; flowsMu only guards the map.
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

// handleSessionResume validates a resumption token, rotates it and reconnects
// the client to the existing engine session with a new transport/peer.
//
// The token alone is not enough: caller must own the session, or anyone who
// obtains another user's token (e.g. a leaked SSE reconnect URL) could take it
// over. The token is consumed only after every check passes, so a rejected
// attempt cannot burn the owner's token.
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

	// Look the token up without consuming it.
	a.mu.Lock()
	entry, validToken := a.usableResumptionTokenLocked(params.ResumptionToken)
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

	// The caller must own the session (see doc comment).
	if !ownsSession(oldWS, caller) {
		return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
			"reason": "resumption token does not belong to the authenticated caller",
		})
	}

	// Build the replacement connection state; negotiated state and sub-flow
	// correlation carry over.
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
		offered:      oldWS.offered,
		security:     oldWS.security,
		expiresAt:    oldWS.expiresAt,
		ownerTokenID: oldWS.ownerTokenID,
		slot:         oldWS.slot,
	}

	// Atomically consume the token and install the replacement if the resumed
	// session is still current. Publishing BEFORE cancelling the old peer keeps
	// the old Serve cleanup (which acts only if current) from tearing down the
	// resumed session.
	if a.beforeResumePublish != nil {
		a.beforeResumePublish(params.SessionID)
	}
	a.mu.Lock()
	_, tokenStillValid := a.usableResumptionTokenLocked(params.ResumptionToken)
	// A create for the same user may have superseded the session since the
	// lookup.
	superseded := !a.manager.isCurrentSession(oldWS.session)
	if !tokenStillValid || a.peers[params.SessionID] != oldWS || a.draining || superseded {
		a.mu.Unlock()
		cancel()
		_ = ct.Close()
		if superseded {
			// Gone from the manager: end the adapter side too.
			a.closeSessionIfCurrent(params.SessionID, oldWS)
		}
		return invalidToken()
	}
	a.consumeResumptionTokenLocked(params.ResumptionToken)
	a.peers[params.SessionID] = ws
	buf := a.eventBufs[params.SessionID]
	a.mu.Unlock()
	if buf == nil {
		buf = a.getOrCreateEventBuffer(params.SessionID)
	}

	// Abort a blocking sign/match Call still holding Session.Send's read lock on
	// the old transport (the client may have vanished), so the write lock below
	// does not wait out the call timeout.
	prevTransport := oldWS.session.currentTransport()
	if old, ok := prevTransport.(*wmpSessionTransport); ok {
		old.retire()
	}

	// Rewire to the new transport; the write lock waits for in-flight Send
	// calls, so nothing is written to the old one afterwards.
	oldWS.session.transportMu.Lock()
	oldWS.session.transport = wmpTransport
	oldWS.session.transportMu.Unlock()
	// Child-flow starts interrupted by retire() are reissued on the new peer.
	if old, ok := prevTransport.(*wmpSessionTransport); ok {
		old.handOff(wmpTransport)
	}

	// Retire the old connection and wait for its pump to flush into the buffer
	// before the new pump starts, preserving event order.
	oldWS.cancel()
	_ = oldWS.transport.Close()
	<-oldWS.pumpDone

	// Re-check revocation now the replacement is installed. Revocation marks the
	// user before closing sessions, so either the mark is visible here or the
	// closing scan runs after the swap and closes the new transport.
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

	// Issue a rotated token only while this peer is still installed; checking
	// and issuing under a.mu gives close and resume one linearization point.
	newToken, stillCurrent := a.issueRotatedResumptionToken(params.SessionID, ws, params.ResumptionToken)
	if !stillCurrent {
		a.logger.Warn("WMP session.resume: session closed or superseded during resume", zap.String("session_id", params.SessionID))
		a.closeSessionIfCurrent(params.SessionID, ws)
		return invalidToken()
	}

	// Echo negotiated capabilities and security (spec §4.5.1/§4.5.3).
	// MissedMessages counts the events the buffer can replay after
	// last_received_id.
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

	// Re-send the latest flow.progress per active flow (spec §6.2.1).
	go a.replayActiveFlowProgress(params.SessionID, peer)

	return wmpResponseBytes(req.ID, result)
}

// ---------------------------------------------------------------------------
// wmpEngineHandler — bridges WMP Handler interface to the engine
// ---------------------------------------------------------------------------

// wmpEngineHandler implements wmp.Handler: flow methods go to the engine
// session's channels (actionCh, signCh, matchCh), session cleanup to the
// adapter. No AsyncFlowProfile; the engine runs a goroutine per flow.
type wmpEngineHandler struct {
	wmp.BaseHandler
	adapter   *WMPAdapter
	sessionID string
	session   *Session

	// children holds sub-flow correlation state, shared by pointer across a
	// session's successive handlers so a resume needs no transfer step. Lazily
	// created; see table().
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

// childFlowInfo tracks a nested sign/match sub-flow so its flow.complete can be
// routed to the engine channel.
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

// purgeChildFlows drops every child mapping of parentFlowID when the parent is
// torn down, so unfinished children do not linger.
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
	h.adapter.closeSessionIfHandler(h.sessionID, h)
}

// logger returns the adapter's logger, or a no-op one for a bare handler.
func (h *wmpEngineHandler) logger() *zap.Logger {
	if h.adapter == nil || h.adapter.logger == nil {
		return zap.NewNop()
	}
	return h.adapter.logger
}

// authorizeProtocol enforces the TAC permission the flow protocol requires (see
// requiredTACForProtocol) for the CURRENT request, on every state-changing
// method, so a token lacking "i"/"r" cannot drive an existing flow of that
// protocol.
//
// Both the session's creation-time TAC and the current request's TAC must grant
// it. A TAC is skipped only for a legacy token; a modern token with an empty TAC
// has no permissions.
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
// The flow is nil when not registered (callers report their own not-found).
func (h *wmpEngineHandler) authorizeFlow(ctx context.Context, flowID string) (flow *Flow, rpcErr *wmp.RPCError) {
	h.session.flowsMu.RLock()
	flow = h.session.flows[flowID]
	h.session.flowsMu.RUnlock()
	if flow == nil {
		return nil, nil
	}
	return flow, h.authorizeProtocol(ctx, flow.Protocol, h.logger().With(zap.String("flow_id", flowID)))
}

// declaredFeatures maps the capabilities the client offered to engine feature
// declarations (FlowStartMessage.Features), so transaction_data goes only to a
// client that can handle it, as on WebSocket.
func (h *wmpEngineHandler) declaredFeatures() []string {
	h.adapter.mu.RLock()
	ws, ok := h.adapter.peers[h.sessionID]
	h.adapter.mu.RUnlock()
	if !ok {
		return nil
	}
	var features []string
	if ws.offered.OffersTransactionData(wmp.TransactionDataVersion1) {
		features = append(features, FeatureTransactionDataV1)
	}
	return features
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

	h.adapter.manager.handlersMu.RLock()
	factory, ok := h.adapter.manager.flowHandlers[protocol]
	h.adapter.manager.handlersMu.RUnlock()
	if !ok {
		return nil, wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{
			"reason": "unsupported flow type",
		})
	}

	// TAC check, mirroring the WebSocket path (Manager.handleFlowStart); see
	// authorizeProtocol.
	if rpcErr := h.authorizeProtocol(ctx, protocol, logger); rpcErr != nil {
		return nil, rpcErr
	}

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
	// Declared features come from what the session offered, not from flow
	// params, so a client cannot slip in a `features` member.
	startMsg.Features = h.declaredFeatures()

	// checkSlot rejects a duplicate client-supplied flow_id (which would
	// overwrite a live flow, bypassing the limit) and enforces the concurrent-
	// flow limit. Callers hold flowsMu.
	checkSlot := func() *wmp.RPCError {
		if h.session.closed {
			return wmp.NewRPCError(wmp.ErrFlowError, map[string]string{"reason": "session closed"})
		}
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

	// Build the flow and its handler BEFORE publishing it in session.flows, so a
	// concurrent cancel/action or teardown never sees a flow with no Handler.
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

	if hook := h.session.testHookBeforePublish; hook != nil {
		hook()
	}

	// Publish atomically with the authoritative duplicate/limit/closed check.
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

	// Launch the engine flow goroutine; its output goes through
	// wmpSessionTransport.
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

// FlowAction handles wmp.flow.action, routing the action to the session channel
// the engine's handlers block on: actionCh (consent etc.), signCh (proofs),
// matchCh (DCQL matches).
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

	// Translate spec action names to engine names. Engine-native names are also
	// accepted, including extensions with no spec equivalent (sign_response,
	// match_response, trust_result).
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

// FlowComplete handles wmp.flow.complete. For child sub-flows (sign/match) it
// routes the result to signCh/matchCh to unblock RequestSign/RequestMatch.
//
// The child mapping is claimed before delivery (so duplicates cannot both
// deliver) and restored if delivery fails, so a momentarily full channel does
// not lose the only result. Delivery waits up to flowActionSendWait.
func (h *wmpEngineHandler) FlowComplete(ctx context.Context, params *wmp.FlowCompleteParams) {
	// A child result drives its parent, so the token must be authorised for the
	// PARENT's protocol. Checked before claiming the mapping so a denied caller
	// cannot consume it.
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

// FlowError handles wmp.flow.error. For a child sub-flow it consumes the mapping
// and fails the parent RequestSign/RequestMatch immediately; other flows are
// ignored.
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

// CredentialNotification routes a wmp.credential.notification (OID4VCI §10) to
// the engine's notification forwarding.
func (h *wmpEngineHandler) CredentialNotification(ctx context.Context, params *wmp.CredentialNotificationParams) {
	// Needs the issuance permission whether or not the flow is still registered.
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

// wmpSessionTransport implements SessionTransport, converting outgoing engine
// messages to WMP notifications via Peer.Notify. Sign/match requests start
// nested sub-flows.
type wmpSessionTransport struct {
	peer    *wmp.Peer
	ct      *wmp.ChannelTransport
	handler *wmpEngineHandler

	// retireCtx is cancelled by retire when a resume supersedes this transport.
	// Blocking Peer.Call sends derive from it, so an unacknowledged call cannot
	// hold Session.Send's read lock (and the resume's write lock) for the full
	// timeout.
	retireCtx    context.Context
	retireCancel context.CancelFunc

	// successor is the transport that replaced this one on resume; handedOff
	// closes once it is set, so an in-flight child-flow start can be reissued
	// there.
	successor   *wmpSessionTransport
	handedOff   chan struct{}
	handoffOnce sync.Once
}

func newWMPSessionTransport(peer *wmp.Peer, ct *wmp.ChannelTransport) *wmpSessionTransport {
	ctx, cancel := context.WithCancel(context.Background())
	return &wmpSessionTransport{peer: peer, ct: ct, retireCtx: ctx, retireCancel: cancel, handedOff: make(chan struct{})}
}

// handOff records next as the transport that replaced t, so child-flow starts
// interrupted by retire() can be reissued on it.
func (t *wmpSessionTransport) handOff(next *wmpSessionTransport) {
	t.handoffOnce.Do(func() {
		t.successor = next
		if t.handedOff != nil {
			close(t.handedOff)
		}
	})
}

// startChildFlow sends wmp.flow.start for a sign/match sub-flow and waits for
// the ack. If a resume retires the transport meanwhile, the start is reissued
// under the same child flow ID on the replacement, rather than failing
// Session.Send and ending the parent flow (the child-flow table survives the
// resume).
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

// startChildFlowOrForget is startChildFlow, dropping the child mapping if the
// start fails.
func (t *wmpSessionTransport) startChildFlowOrForget(childFlowID, flowType string, params json.RawMessage) error {
	if err := t.startChildFlow(childFlowID, flowType, params); err != nil {
		t.handler.popChildFlow(childFlowID)
		return err
	}
	return nil
}

// reissueChildFlow starts the child flow on the replacement transport once
// available. On failure the mapping is dropped and the parent's wait is left to
// its own timeout.
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

// retire aborts in-flight blocking Calls without closing the channel, so queued
// notifications still drain into the event buffer. Idempotent.
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

// wmpMeta returns Metadata with version and session ID filled in.
func (t *wmpSessionTransport) wmpMeta() wmp.Metadata {
	return wmp.Metadata{
		Version:   wmp.Version,
		SessionID: t.handler.sessionID,
	}
}

// SendJSON translates engine message structs to WMP JSON-RPC notifications
// written via the peer to the ChannelTransport (the SSE event stream).
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
		// Carry Error.Details (e.g. OID4VP's redirect_uri) in Data, as on
		// WebSocket.
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
		// Start a nested sign sub-flow; FlowComplete routes the client's result
		// to signCh.
		childFlowID := uuid.New().String()
		t.handler.registerChildFlow(childFlowID, m.FlowID, m.MessageID, "sign")

		subFlowParams := openid4x.SignSubFlowParams{
			Action:                string(m.Action),
			Nonce:                 m.Params.Nonce,
			Audience:              m.Params.Audience,
			ProofType:             m.Params.ProofType,
			ParentFlowID:          m.FlowID,
			TransactionData:       convertTransactionData(m.Params.TransactionData),
			ResponseMode:          m.Params.ResponseMode,
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
		// No dedicated WMP method (PushMessage, notification acks, ...): wrap in
		// wmp.message.deliver so every stream event is valid JSON-RPC.
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

// convertTransactionData converts the engine's TransactionData to its field-for-
// field identical WMP wire type, so the transports share no Go type.
func convertTransactionData(in []TransactionData) []openid4x.TransactionData {
	if in == nil {
		return nil
	}
	out := make([]openid4x.TransactionData, len(in))
	for i, td := range in {
		out[i] = openid4x.TransactionData{
			Type:                     td.Type,
			Raw:                      td.Raw,
			Payload:                  td.Payload,
			CredentialIDs:            td.CredentialIDs,
			TransactionDataHashesAlg: openid4x.HashAlgs(td.TransactionDataHashesAlg),
		}
		// Params and HashAlgorithm are deprecated in go-wmp but still copied:
		// pre-TS12 entries carry their members there.
		out[i].Params = td.Params               //nolint:staticcheck // deprecated, kept for pre-TS12 entries
		out[i].HashAlgorithm = td.HashAlgorithm //nolint:staticcheck // deprecated, kept for pre-TS12 entries
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
		// Most engine errors map to the generic flow error; details travel in
		// the message.
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
// stays routable (Call() timeout plus slack).
const wmpOutboundRequestTTL = childFlowStartTimeout + 30*time.Second

// outboundRequest is a server->client JSON-RPC request awaiting its response.
type outboundRequest struct {
	sessionID string
	expiresAt time.Time
}

// trackOutbound records the ID of a server-initiated request so the client's
// response can be routed to the session without a session header.
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

// routeResponse delivers a client response to the session with the matching
// outstanding server-initiated request. With a session ID (already ownership-
// checked) the matching tracked ID is consumed; without one the session is found
// via the request ID and the caller must own it. IDs are one-shot; unknown,
// expired, answered or foreign IDs are rejected identically so nothing leaks
// about other users' requests.
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
			// Consume only for the owner so a foreign token cannot burn another
			// user's pending ID.
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
