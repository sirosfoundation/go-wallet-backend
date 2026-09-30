package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"go.uber.org/zap"
)

// maxWMPRPCBodyBytes is the maximum allowed body size for WMP JSON-RPC requests.
// JSON-RPC messages are small; 256KB is generous for any flow action payload.
// Public paths of the WMP endpoints, as mounted by the server router and
// advertised by the /.well-known/wmp-configuration discovery document.
const (
	WMPRPCPath    = "/api/v2/wallet/rpc"
	WMPEventsPath = "/api/v2/wallet/events"
)

const maxWMPRPCBodyBytes = 256 * 1024

// wmpSSEWriteTimeout bounds every individual SSE write/flush. The stream as a
// whole is long-lived (it outlives the http.Server WriteTimeout), but a
// client that stops reading must not be able to pin the handler in a blocked
// socket write indefinitely - closing the event buffer cannot interrupt one.
// It is a variable so tests can shorten it.
var wmpSSEWriteTimeout = 15 * time.Second

// HandleWMPRPC handles POST /api/v2/wallet/rpc — a single JSON-RPC request/response.
func (a *WMPAdapter) HandleWMPRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.isDraining() {
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}

	// Extract and validate JWT from Authorization header.
	token := a.bearerToken(r)
	if token == "" {
		http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	userID, tenantID, tac, tokenID, err := a.manager.validateTokenID(token)
	if err != nil {
		a.logger.Warn("WMP HTTP auth failed", zap.Error(err))
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Read body (bounded to RPC-appropriate size).
	// http.MaxBytesReader (not io.LimitReader) so an oversized body fails
	// with 413 instead of being silently truncated into a confusing parse error.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWMPRPCBodyBytes))
	if err != nil {
		writeBodyReadError(w, err)
		return
	}

	// Session ID from header (empty for session.create).
	sessionID := r.Header.Get("Wmp-Session-Id")

	caller := wmpCaller{UserID: userID, TenantID: tenantID, TokenID: tokenID, TAC: tac}

	// For methods that target an existing session, verify ownership.
	if sessionID != "" {
		if !a.verifySessionOwnership(sessionID, caller) {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
	}

	// Dispatch. HandleRPC's own protocol-level errors are already returned as
	// (bytes, nil) — a marshaled JSON-RPC error envelope. A non-nil err here
	// means something failed before an envelope could even be built (e.g.
	// ws.peer.HandleRequestSync's own internal parse failure); respond with
	// a JSON-RPC error envelope here too rather than plain text, so the
	// caller (a JSON-RPC client expecting a JSON-RPC response body) doesn't
	// fail trying to parse it.
	resp, err := a.HandleRPCAs(r.Context(), sessionID, caller, body)
	if err != nil {
		a.logger.Error("WMP RPC dispatch failed", zap.Error(err))
		errResp, marshalErr := wmpErrorBytes(nil, wmp.ErrInternalError, nil)
		if marshalErr != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(errResp)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if resp == nil {
		// Notification — no response body.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// HandleWMPEvents handles GET /api/v2/wallet/events — SSE stream of server notifications.
func (a *WMPAdapter) HandleWMPEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.isDraining() {
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}

	// Auth.
	token := a.bearerToken(r)
	if token == "" {
		http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}
	userID, tenantID, tac, tokenID, err := a.manager.validateTokenID(token)
	if err != nil {
		a.logger.Warn("WMP SSE auth failed", zap.Error(err))
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "missing session_id query parameter", http.StatusBadRequest)
		return
	}

	// Verify the session belongs to the authenticated user.
	if !a.verifySessionOwnership(sessionID, wmpCaller{UserID: userID, TenantID: tenantID, TokenID: tokenID}) {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// Same user and tenant is not enough: the stream carries the flow
	// notifications of a session that may have been created with broader
	// privileges than this token holds. The presented token must grant every
	// capability the session was created with.
	if !a.tokenCoversSession(sessionID, tac) {
		a.logger.Warn("WMP SSE rejected - token lacks the session's capabilities",
			zap.String("request_tac", string(tac)))
		http.Error(w, "token lacks the session's capabilities", http.StatusForbidden)
		return
	}

	a.mu.RLock()
	buf := a.eventBufs[sessionID]
	a.mu.RUnlock()
	if buf == nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	_, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Reject a second concurrent connection for this session rather than
	// letting it interleave with the first on the same event stream. Must
	// run before any header is written — an implicit 200 from
	// flusher.Flush() below can't be undone afterward.
	ctx := r.Context()
	if !buf.tryAcquire(ctx) {
		http.Error(w, "another connection is already streaming events for this session", http.StatusConflict)
		return
	}
	defer buf.release(ctx)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx

	// Each write+flush gets its own fresh deadline (replacing the
	// connection-wide WriteTimeout, which would cut the stream off); a
	// writer without deadline support falls back to the server's own.
	rc := http.NewResponseController(w)
	armWrite := func() { _ = rc.SetWriteDeadline(time.Now().Add(wmpSSEWriteTimeout)) }
	armWrite()
	if err := rc.Flush(); err != nil {
		return
	}

	// Events are appended to the session's buffer as they are emitted (see
	// pumpEvents), whether or not a client is connected, and IDs are durable
	// across reconnects and wmp.session.resume. A reconnecting client's
	// Last-Event-ID selects where to replay from; without one the stream
	// starts at the first event not yet written to any connection.
	cursor := buf.delivered()
	if lastEventID := r.Header.Get("Last-Event-ID"); lastEventID != "" {
		if id, err := strconv.ParseInt(lastEventID, 10, 64); err == nil {
			cursor = id
		}
	}
	done := buf.doneCh()

	for {
		events, wake := buf.after(cursor)
		for _, ev := range events {
			armWrite()
			if _, err := fmt.Fprintf(w, "id: %d\nevent: wmp\ndata: %s\n\n", ev.ID, ev.Data); err != nil {
				return // client gone or too slow: stop, the event stays replayable
			}
			cursor = ev.ID
		}
		if len(events) > 0 {
			armWrite()
			// Only a successful flush means the events left the server:
			// advance the delivered mark after it, never before, so a
			// connection dropped between Write and Flush cannot make the
			// next one skip them (a duplicate is safer than a loss).
			if err := rc.Flush(); err != nil {
				return
			}
			buf.markDelivered(cursor)
		}
		select {
		case <-ctx.Done():
			return
		case <-done:
			return // session closed (client close, expiry, revocation, shutdown)
		case <-wake:
		}
	}
}

// tokenCoversSession reports whether a token with the given TAC may observe the
// session: every capability the session was created with must be granted by
// the token. A session created without a TAC (legacy auth) has nothing to
// cover. A token with no TAC cannot read a session that has one.
func (a *WMPAdapter) tokenCoversSession(sessionID string, tac claims.TAC) bool {
	a.mu.RLock()
	ws, ok := a.peers[sessionID]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	return ws.session.TAC.IsSubsetOf(tac)
}

// HandleWMPConfiguration serves the /.well-known/wmp-configuration discovery endpoint.
// This allows WMP clients to discover server capabilities without establishing a session.
// The document is the go-wmp library's own WellKnownConfig type, so it always
// matches the schema wmp.DiscoverConfig expects.
func (a *WMPAdapter) HandleWMPConfiguration(w http.ResponseWriter, _ *http.Request) {
	caps := make(map[string]interface{})
	for name, raw := range a.serverCapabilities() {
		var v interface{}
		if err := json.Unmarshal(raw, &v); err != nil {
			continue
		}
		caps[name] = v
	}
	cfg := wmp.WellKnownConfig{
		SupportedVersions: wmp.SupportedVersions,
		SecurityModes:     []string{"tls"},
		Capabilities:      caps,
		Endpoints: map[string]string{
			"rpc":    WMPRPCPath,
			"events": WMPEventsPath,
		},
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(body)
}

// writeBodyReadError maps a request-body read failure to 413 when the body
// exceeded the http.MaxBytesReader limit, and 400 otherwise.
func writeBodyReadError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "failed to read body", http.StatusBadRequest)
}
