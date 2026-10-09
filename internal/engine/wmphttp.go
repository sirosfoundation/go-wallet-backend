package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"go.uber.org/zap"
)

// maxWMPRPCBodyBytes is the maximum allowed body size for WMP JSON-RPC requests.
// JSON-RPC messages are small; 256KB is generous for any flow action payload.
// Public paths of the WMP endpoints, advertised by the discovery document.
//
// go-wmp's HTTPS+SSE client takes ONE base URL, POSTs JSON-RPC to it and
// opens SSE at base + "/events", so the stream is also served at
// WMPRPCPath + "/events" (WMPClientEventsPath). WMPEventsPath remains as an
// alias for existing clients.
const (
	WMPRPCPath          = "/api/v2/wallet/rpc"
	WMPEventsPath       = "/api/v2/wallet/events"
	WMPClientEventsPath = WMPRPCPath + "/events"
)

const maxWMPRPCBodyBytes = 256 * 1024

// wmpSSEWriteTimeout bounds each SSE write/flush: the stream outlives the
// http.Server WriteTimeout, but a non-reading client must not pin the handler
// in a blocked socket write. A variable so tests can shorten it.
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

	id, err := a.manager.validateTokenAuth(r.Context(), token)
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

	// Dispatch. A non-nil err means failure before an envelope could be built;
	// still answer with a JSON-RPC error envelope, not plain text.
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
	id, err := a.manager.validateTokenAuth(r.Context(), token)
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

	// Same user and tenant is not enough: the token must grant every capability
	// the session was created with.
	if !a.tokenCoversSession(sessionID, id.TAC, id.EnforceTAC) {
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

	// A new connection supersedes any previous one (cancelling its context) so a
	// stale connection never locks the client out; ownership and capability
	// checks above already passed. Replay is cursor-driven, so nothing is lost.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stream := buf.acquire(cancel)
	defer buf.release(stream)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx

	// Each write+flush gets a fresh deadline (the connection-wide WriteTimeout
	// would cut the stream off); the deadline is cleared after each flush so an
	// idle healthy stream does not expire.
	rc := http.NewResponseController(w)
	armWrite := func() { _ = rc.SetWriteDeadline(time.Now().Add(wmpSSEWriteTimeout)) }
	clearWrite := func() { _ = rc.SetWriteDeadline(time.Time{}) }
	armWrite()
	if err := rc.Flush(); err != nil {
		return
	}
	clearWrite()

	// Events are buffered as emitted (see pumpEvents) with IDs durable across
	// reconnects and resume. Replay is driven solely by Last-Event-ID: a
	// successful Flush does not prove the client parsed the frame. Without a
	// cursor every retained event is replayed; clients dedupe by event ID.
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

// SetExternalURL sets the public base URL of the WMP endpoints. Only https
// URLs with a host and no query or fragment are accepted (discovery
// advertises security mode "tls"); plain http only for loopback. A ws:// or
// wss:// URL (engine_url) maps to http:// (loopback only) or https://.
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
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("WMP external URL %q must use https (or wss): plaintext http/ws is only allowed for loopback hosts", raw)
	}
	a.mu.Lock()
	a.externalURL = u.String()
	a.mu.Unlock()
	return nil
}

// isLoopbackHost reports whether host is localhost or a loopback IP literal
// (127.0.0.0/8, ::1).
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// legacySessionEffectiveTAC is what a legacy-token session is treated as
// holding: every permission authorizeProtocol gates on. A modern token must
// cover it, so an empty-TAC token cannot read such a session.
func legacySessionEffectiveTAC() claims.TAC {
	var b []byte
	for _, perm := range requiredTACForProtocol {
		for i := 0; i < len(perm); i++ {
			if !strings.Contains(string(b), perm[i:i+1]) {
				b = append(b, perm[i])
			}
		}
	}
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
	return claims.TAC(b)
}

// tokenCoversSession reports whether the token may observe the session: it
// must grant every capability the session holds (legacy-created sessions hold
// legacySessionEffectiveTAC, which a legacy token trivially covers).
func (a *WMPAdapter) tokenCoversSession(sessionID string, tac claims.TAC, enforce bool) bool {
	a.mu.RLock()
	ws, ok := a.peers[sessionID]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	sess := ws.session
	if sess.TACEnforced || sess.TAC != "" {
		return sess.TAC.IsSubsetOf(tac)
	}
	// Legacy-created session.
	if !enforce && tac == "" {
		return true
	}
	return legacySessionEffectiveTAC().IsSubsetOf(tac)
}

// HandleWMPConfiguration serves /.well-known/wmp-configuration using go-wmp's
// WellKnownConfig. Endpoints are absolute https URLs from SetExternalURL
// (go-wmp rejects relative ones); without one it fails closed with 503.
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
