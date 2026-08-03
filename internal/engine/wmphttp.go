package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"go.uber.org/zap"
)

// maxWMPRPCBodyBytes is the maximum allowed body size for WMP JSON-RPC requests.
// JSON-RPC messages are small; 256KB is generous for any flow action payload.
const maxWMPRPCBodyBytes = 256 * 1024

// HandleWMPRPC handles POST /wmp/rpc — a single JSON-RPC request/response.
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

	userID, tenantID, err := a.manager.validateToken(token)
	if err != nil {
		a.logger.Warn("WMP HTTP auth failed", zap.Error(err))
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Read body (bounded to RPC-appropriate size).
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWMPRPCBodyBytes))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Session ID from header (empty for session.create).
	sessionID := r.Header.Get("Wmp-Session-Id")

	// For methods that target an existing session, verify ownership.
	if sessionID != "" {
		if !a.verifySessionOwnership(sessionID, userID, tenantID) {
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
	resp, err := a.HandleRPC(r.Context(), sessionID, userID, tenantID, body)
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

// HandleWMPEvents handles GET /wmp/events — SSE stream of server notifications.
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
	userID, tenantID, err := a.manager.validateToken(token)
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
	if !a.verifySessionOwnership(sessionID, userID, tenantID) {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	events, err := a.Events(sessionID)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Reject a second concurrent connection for this session rather than
	// letting it race the first to read from the same events channel: only
	// one of them would see any given notification, silently splitting the
	// stream between them. Must run before any header is written — an
	// implicit 200 from flusher.Flush() below can't be undone afterward.
	ctx := r.Context()
	buf := a.getOrCreateEventBuffer(sessionID)
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

	// Replay events the client missed while disconnected — e.g. a plain SSE
	// drop, or reconnecting after a wmp.session.resume (which installs a new
	// ChannelTransport whose own event channel starts empty; the session's
	// event buffer is what actually survives resume). IDs are durable across
	// reconnects, unlike a per-connection counter, so the client's
	// automatically-resent Last-Event-ID header means something here.
	if lastEventID := r.Header.Get("Last-Event-ID"); lastEventID != "" {
		for _, ev := range buf.replaySince(lastEventID) {
			_, _ = fmt.Fprintf(w, "id: %d\nevent: wmp\ndata: %s\n\n", ev.ID, ev.Data)
		}
		flusher.Flush()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-events:
			if !ok {
				return // channel closed
			}
			id := buf.append(data)
			_, _ = fmt.Fprintf(w, "id: %d\nevent: wmp\ndata: %s\n\n", id, data)
			flusher.Flush()
		}
	}
}

// HandleWMPConfiguration serves the /.well-known/wmp-configuration discovery endpoint.
// This allows WMP clients to discover server capabilities without establishing a session.
func (a *WMPAdapter) HandleWMPConfiguration(w http.ResponseWriter, _ *http.Request) {
	caps := a.serverCapabilities()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = fmt.Fprintf(w, `{"version":"%s","security":{"mode":"tls"},"capabilities":%s,"endpoints":{"rpc":"/wmp/rpc","events":"/wmp/events"}}`,
		"1.0", mustMarshalJSON(caps))
}

func mustMarshalJSON(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(data)
}
