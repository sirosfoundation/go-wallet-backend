package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

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

// HandleWMPRPC handles POST /api/v2/wallet/rpc — a single JSON-RPC request/response.
func (a *WMPAdapter) HandleWMPRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract and validate JWT from Authorization header.
	token := extractBearerToken(r)
	if token == "" {
		http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	userID, tenantID, _, tokenID, err := a.manager.validateTokenID(token)
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

	caller := wmpCaller{UserID: userID, TenantID: tenantID, TokenID: tokenID}

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

	// Auth.
	token := extractBearerToken(r)
	if token == "" {
		http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}
	userID, tenantID, _, tokenID, err := a.manager.validateTokenID(token)
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

	a.mu.RLock()
	buf := a.eventBufs[sessionID]
	a.mu.RUnlock()
	if buf == nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
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
	flusher.Flush()

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
			_, _ = fmt.Fprintf(w, "id: %d\nevent: wmp\ndata: %s\n\n", ev.ID, ev.Data)
			cursor = ev.ID
			buf.markDelivered(ev.ID)
		}
		if len(events) > 0 {
			flusher.Flush()
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

// HandleWMPConfiguration serves the /.well-known/wmp-configuration discovery endpoint.
// This allows WMP clients to discover server capabilities without establishing a session.
func (a *WMPAdapter) HandleWMPConfiguration(w http.ResponseWriter, _ *http.Request) {
	caps := a.serverCapabilities()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = fmt.Fprintf(w, `{"version":"%s","security":{"mode":"tls"},"capabilities":%s,"endpoints":{"rpc":"%s","events":"%s"}}`,
		"1.0", mustMarshalJSON(caps), WMPRPCPath, WMPEventsPath)
}

func mustMarshalJSON(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(data)
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
