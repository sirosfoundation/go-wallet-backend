package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"go.uber.org/zap"
)

// maxWMPRPCBodyBytes is the maximum allowed body size for WMP JSON-RPC requests.
// JSON-RPC messages are small; 256KB is generous for any flow action payload.
// Public paths of the WMP endpoints, as mounted by the server router and
// advertised by the /.well-known/wmp-configuration discovery document.
//
// go-wmp's HTTPS+SSE client (httpsse.NewClientTransport) takes ONE base URL,
// POSTs JSON-RPC to it and opens the SSE stream at base + "/events". So the
// RPC path doubles as that base and the stream is ALSO served at
// WMPRPCPath + "/events" (WMPClientEventsPath), which is the events endpoint
// the discovery document advertises. WMPEventsPath remains as the original
// alias for existing clients.
const (
	WMPRPCPath          = "/api/v2/wallet/rpc"
	WMPEventsPath       = "/api/v2/wallet/events"
	WMPClientEventsPath = WMPRPCPath + "/events"
)

const maxWMPRPCBodyBytes = 256 * 1024

// wmpSSEWriteTimeout bounds every individual SSE write/flush. The stream as a
// whole is long-lived (it outlives the http.Server WriteTimeout), but a
// client that stops reading must not be able to pin the handler in a blocked
// socket write indefinitely - closing the event buffer cannot interrupt one.
// It is a variable so tests can shorten it.
var wmpSSEWriteTimeout = 15 * time.Second

// wmpSSEHeartbeatInterval is how often an idle SSE stream emits a comment
// frame so dead connections are detected by a failing (bounded) write.
var wmpSSEHeartbeatInterval = 20 * time.Second

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

	id, err := a.manager.validateTokenAuth(token)
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

	// Session ID from the Wmp-Session-Id header, else from the request's own
	// params.wmp.session_id metadata (go-wmp's HTTPS+SSE client does not set
	// the header; its ServerHandler falls back to the body the same way).
	// Empty for session.create. When both are present they must agree.
	sessionID := r.Header.Get("Wmp-Session-Id")
	if metaID := bodySessionID(body); sessionID == "" {
		sessionID = metaID
	} else if metaID != "" && metaID != sessionID {
		http.Error(w, "session ID mismatch between header and request metadata", http.StatusBadRequest)
		return
	}

	caller := wmpCaller{UserID: id.UserID, TenantID: id.TenantID, TokenID: id.JTI, TAC: id.TAC, EnforceTAC: id.EnforceTAC}

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
		// Notification — no response body. 202 (not 204): go-wmp's HTTPS+SSE
		// client accepts only 200 or 202 from WriteMessage.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// bodySessionID extracts params.wmp.session_id from a JSON-RPC body ("" when
// absent or the body is not shaped that way; the dispatcher reports parse
// errors itself).
func bodySessionID(body []byte) string {
	var env struct {
		Params struct {
			WMP struct {
				SessionID string `json:"session_id"`
			} `json:"wmp"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &env) != nil {
		return ""
	}
	return env.Params.WMP.SessionID
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
	id, err := a.manager.validateTokenAuth(token)
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
	if !a.verifySessionOwnership(sessionID, wmpCaller{UserID: id.UserID, TenantID: id.TenantID, TokenID: id.JTI}) {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// Same user and tenant is not enough: the stream carries the flow
	// notifications of a session that may have been created with broader
	// privileges than this token holds. The presented token must grant every
	// capability the session was created with.
	if !a.tokenCoversSession(sessionID, id.TAC) {
		a.logger.Warn("WMP SSE rejected - token lacks the session's capabilities",
			zap.String("request_tac", string(id.TAC)))
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

	// A new connection supersedes any previous one for this session: the
	// old stream's context is cancelled so its handler exits. A stale
	// connection (unclean mobile/network drop that the server has not yet
	// noticed) must never lock the client out. Ownership and capability
	// checks above have already passed, so only an authorized caller can
	// supersede. Replay is cursor-driven, so nothing is lost.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stream := buf.acquire(cancel)
	defer buf.release(stream)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx

	// Each write+flush gets its own fresh deadline (replacing the
	// connection-wide WriteTimeout, which would cut the stream off); a
	// writer without deadline support falls back to the server's own.
	// SetWriteDeadline is persistent, so the deadline is cleared after every
	// successful flush: an idle healthy stream must not expire before the
	// next event, while a write to a non-reading client is still bounded.
	rc := http.NewResponseController(w)
	armWrite := func() { _ = rc.SetWriteDeadline(time.Now().Add(wmpSSEWriteTimeout)) }
	clearWrite := func() { _ = rc.SetWriteDeadline(time.Time{}) }
	armWrite()
	if err := rc.Flush(); err != nil {
		return
	}
	clearWrite()

	// Events are appended to the session's buffer as they are emitted (see
	// pumpEvents), whether or not a client is connected, and IDs are durable
	// across reconnects and wmp.session.resume. Replay is driven solely by
	// the client's Last-Event-ID cursor: the server keeps no delivery state,
	// because a successful Flush only hands bytes to the connection or a
	// proxy and does not prove the client parsed the frame. Without a cursor
	// every retained event is replayed; duplicates are possible and clients
	// dedupe by the monotonic event ID.
	var cursor int64
	if lastEventID := r.Header.Get("Last-Event-ID"); lastEventID != "" {
		if id, err := strconv.ParseInt(lastEventID, 10, 64); err == nil {
			cursor = id
		}
	}
	done := buf.doneCh()
	heartbeat := time.NewTicker(wmpSSEHeartbeatInterval)
	defer heartbeat.Stop()

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
			if err := rc.Flush(); err != nil {
				return
			}
			clearWrite()
		}
		select {
		case <-ctx.Done():
			return
		case <-done:
			return // session closed (client close, expiry, revocation, shutdown)
		case <-wake:
		case <-heartbeat.C:
			// Comment frame: ignored by SSE clients, but forces a write so
			// a dead socket is detected within the bounded write deadline.
			armWrite()
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			clearWrite()
		}
	}
}

// SetExternalURL sets the public base URL (scheme://host[:port][/prefix])
// under which the WMP endpoints are reachable; the discovery document
// advertises absolute URLs built from it. Only http(s) URLs with a host and
// no query or fragment are accepted. A WebSocket URL - which is what
// server.external_urls.engine_url holds - is mapped to the HTTP URL of the
// same host: wss:// to https://, ws:// to http://.
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
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid WMP external URL %q", raw)
	}
	a.mu.Lock()
	a.externalURL = u.String()
	a.mu.Unlock()
	return nil
}

// tokenCoversSession reports whether a token with the given TAC may observe the
// session: every capability the session was created with must be granted by
// the token. A session created without a TAC (legacy auth) has nothing to
// cover. A token with no TAC (including a modern token with an empty TAC)
// cannot read a session that has one.
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
//
// The endpoints are absolute https URLs derived from the configured external
// URL (SetExternalURL), because go-wmp's client rejects relative ones. Without
// a usable external URL the endpoint fails closed with 503 rather than
// advertising something no client can consume.
func (a *WMPAdapter) HandleWMPConfiguration(w http.ResponseWriter, _ *http.Request) {
	a.mu.RLock()
	base := a.externalURL
	a.mu.RUnlock()
	if base == "" {
		http.Error(w, "WMP discovery unavailable: no external URL configured", http.StatusServiceUnavailable)
		return
	}
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
			"rpc":    base + WMPRPCPath,
			"events": base + WMPClientEventsPath,
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

// HasExternalURL reports whether SetExternalURL has succeeded.
func (a *WMPAdapter) HasExternalURL() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.externalURL != ""
}
