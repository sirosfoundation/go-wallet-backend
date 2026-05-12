package engine

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// HandleRPC handles POST requests for JSON-RPC style messages over HTTP.
// Authentication is via Authorization: Bearer <jwt> header — same token
// validation as the WebSocket handshake.
func (m *Manager) HandleRPC(w http.ResponseWriter, r *http.Request) {
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

	userID, tenantID, err := m.validateToken(token)
	if err != nil {
		m.logger.Warn("HTTP auth failed", zap.Error(err))
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Read request body (bounded).
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxHTTPResponseBodyBytes))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Parse the message type.
	var msg Message
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Handle session creation (handshake equivalent).
	if msg.Type == TypeHandshake {
		m.handleHTTPHandshake(w, userID, tenantID)
		return
	}

	// All other messages require an existing session.
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		http.Error(w, "missing X-Session-ID header", http.StatusBadRequest)
		return
	}

	session, err := m.GetSession(sessionID)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// Verify the session belongs to this user (same security as WS: session is bound to JWT identity).
	if session.UserID != userID {
		http.Error(w, "session not found", http.StatusNotFound) // Don't leak that the session exists
		return
	}

	// Verify tenant matches (same as WS tenant binding).
	if tenantID != "" && session.TenantID != tenantID {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// Push the message into the session's transport for the message loop to process.
	sseT, ok := session.transport.(*sseTransport)
	if !ok {
		http.Error(w, "session transport mismatch", http.StatusConflict)
		return
	}

	if err := sseT.pushMessage(body); err != nil {
		http.Error(w, "session overloaded", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted"}`))
}

// HandleEvents handles GET requests for SSE event streams.
// Authentication is via Authorization: Bearer <jwt> header.
func (m *Manager) HandleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract and validate JWT.
	token := extractBearerToken(r)
	if token == "" {
		http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	userID, tenantID, err := m.validateToken(token)
	if err != nil {
		m.logger.Warn("SSE auth failed", zap.Error(err))
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "missing session_id", http.StatusBadRequest)
		return
	}

	session, err := m.GetSession(sessionID)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// Verify ownership (same security as WS).
	if session.UserID != userID {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if tenantID != "" && session.TenantID != tenantID {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	sseT, ok := session.transport.(*sseTransport)
	if !ok {
		http.Error(w, "session transport mismatch", http.StatusConflict)
		return
	}

	// Delegate to SSE transport (handles Last-Event-ID replay, blocking).
	sseT.serveSSE(w, r)
}

// handleHTTPHandshake creates a new session over HTTP+SSE (equivalent to WS handshake).
func (m *Manager) handleHTTPHandshake(w http.ResponseWriter, userID, tenantID string) {
	transport := newSSETransport(200)

	session := &Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		TenantID:  tenantID,
		transport: transport,
		flows:     make(map[string]*Flow),
		logger:    m.logger.With(zap.String("session", userID[:8])),
		actionCh:  make(chan *FlowActionMessage, 50),
		signCh:    make(chan *SignResponseMessage, 20),
		matchCh:   make(chan *MatchResponseMessage, 20),
		closeCh:   make(chan struct{}, 1),
	}

	m.registerSession(session)

	// Start the message loop (same as WebSocket).
	go func() {
		defer m.unregisterSession(session)
		m.handleSession(session)
	}()

	capabilities := m.getCapabilities()
	resp := HandshakeCompleteMessage{
		Message: Message{
			Type:      TypeHandshakeComplete,
			Timestamp: Now(),
		},
		SessionID:    session.ID,
		Capabilities: capabilities,
	}

	session.logger.Info("HTTP+SSE session established",
		zap.String("session_id", session.ID),
		zap.Strings("capabilities", capabilities))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}
