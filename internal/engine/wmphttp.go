package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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

	// Dispatch.
	resp, err := a.HandleRPC(r.Context(), sessionID, body)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
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

	// SSE headers.
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx
	flusher.Flush()

	ctx := r.Context()
	eventID := 0
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-events:
			if !ok {
				return // channel closed
			}
			eventID++
			_, _ = fmt.Fprintf(w, "id: %d\nevent: wmp\ndata: %s\n\n", eventID, data)
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
