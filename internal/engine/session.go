package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

var (
	ErrSessionNotFound     = errors.New("session not found")
	ErrFlowNotFound        = errors.New("flow not found")
	ErrFlowTimeout         = errors.New("flow timeout")
	ErrUnexpectedMessage   = errors.New("unexpected message")
	ErrSignTimeout         = errors.New("sign request timeout")
	ErrTooManyPendingFlows = errors.New("too many pending flows")
)

// MaxPendingFlowsPerSession limits concurrent flows to prevent DoS.
// A session cannot start a new flow if it already has this many pending flows.
const MaxPendingFlowsPerSession = 3

// Session represents an authenticated WebSocket session
type Session struct {
	ID       string
	UserID   string
	TenantID string
	conn     *websocket.Conn
	sendMu   sync.Mutex
	flows    map[string]*Flow
	flowsMu  sync.RWMutex
	logger   *zap.Logger

	// Channels for flow coordination
	actionCh chan *FlowActionMessage
	signCh   chan *SignResponseMessage
	closeCh  chan struct{}
}

// Flow represents an active credential flow
type Flow struct {
	ID        string
	Protocol  Protocol
	Session   *Session
	State     FlowStep
	StartTime time.Time
	Handler   FlowHandler

	// Flow-specific data
	Data map[string]interface{}
	mu   sync.RWMutex
}

// Manager manages WebSocket sessions and flows
type Manager struct {
	cfg      *config.Config
	logger   *zap.Logger
	upgrader websocket.Upgrader

	sessionsMu sync.RWMutex
	sessions   map[string]*Session // sessionID -> session (active connections only)
	userIndex  map[string]*Session // userID -> session (last connection wins)

	flowHandlers map[Protocol]FlowHandlerFactory
	handlersMu   sync.RWMutex

	trustService   *TrustService
	registryClient *RegistryClient
	verifierStore  storage.VerifierStore

	// Persistent session store (optional, for horizontal scaling)
	sessionStore SessionStore
}

// NewManager creates a new session manager
func NewManager(cfg *config.Config, logger *zap.Logger) *Manager {
	m := &Manager{
		cfg:    cfg,
		logger: logger.Named("engine"),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin: func(r *http.Request) bool {
				// TODO: Make configurable for production
				return true
			},
		},
		sessions:       make(map[string]*Session),
		userIndex:      make(map[string]*Session),
		flowHandlers:   make(map[Protocol]FlowHandlerFactory),
		trustService:   NewTrustService(cfg, logger),
		registryClient: NewRegistryClient(cfg, logger),
		sessionStore:   NewMemorySessionStore(logger), // Default to memory
	}
	return m
}

// SetSessionStore sets the session store (for Redis scaling)
func (m *Manager) SetSessionStore(store SessionStore) {
	m.sessionStore = store
}

// SessionStore returns the session store instance.
func (m *Manager) SessionStore() SessionStore {
	return m.sessionStore
}

// SetVerifierStore sets the verifier store for trust caching
func (m *Manager) SetVerifierStore(store storage.VerifierStore) {
	m.verifierStore = store
}

// RegisterFlowHandler registers a handler factory for a protocol
func (m *Manager) RegisterFlowHandler(protocol Protocol, factory FlowHandlerFactory) {
	m.handlersMu.Lock()
	defer m.handlersMu.Unlock()
	m.flowHandlers[protocol] = factory
}

// HandleConnection handles a new WebSocket connection
func (m *Manager) HandleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := m.upgrader.Upgrade(w, r, nil)
	if err != nil {
		m.logger.Error("Failed to upgrade connection", zap.Error(err))
		return
	}

	m.logger.Debug("WebSocket client connected")
	go m.handleNewConnection(conn)
}

func (m *Manager) handleNewConnection(conn *websocket.Conn) {
	defer func() { _ = conn.Close() }()

	// Wait for handshake message
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, message, err := conn.ReadMessage()
	if err != nil {
		m.logger.Error("Failed to read handshake", zap.Error(err))
		return
	}
	_ = conn.SetReadDeadline(time.Time{}) // Clear deadline

	// Parse handshake
	var msg Message
	if err := json.Unmarshal(message, &msg); err != nil {
		m.sendError(conn, "", ErrCodeInvalidMessage, "Invalid message format")
		return
	}

	if msg.Type != TypeHandshake {
		m.sendError(conn, "", ErrCodeInvalidMessage, "Expected handshake message")
		return
	}

	// Parse full handshake message
	var handshake HandshakeMessage
	if err := json.Unmarshal(message, &handshake); err != nil {
		m.sendError(conn, "", ErrCodeInvalidMessage, "Invalid handshake format")
		return
	}

	// Validate token and extract claims
	userID, tenantID, err := m.validateToken(handshake.AppToken)
	if err != nil {
		m.logger.Warn("Authentication failed", zap.Error(err))
		m.sendError(conn, "", ErrCodeAuthFailed, "Invalid or expired token")
		return
	}

	// Create session
	session := &Session{
		ID:       uuid.New().String(),
		UserID:   userID,
		TenantID: tenantID,
		conn:     conn,
		flows:    make(map[string]*Flow),
		logger:   m.logger.With(zap.String("session", userID[:8])),
		actionCh: make(chan *FlowActionMessage, 50),
		signCh:   make(chan *SignResponseMessage, 20),
		closeCh:  make(chan struct{}, 1), // Buffered to prevent deadlock
	}

	// Register session
	m.registerSession(session)
	defer m.unregisterSession(session)

	// Send handshake complete
	capabilities := m.getCapabilities()
	completeMsg := HandshakeCompleteMessage{
		Message: Message{
			Type:      TypeHandshakeComplete,
			Timestamp: Now(),
		},
		SessionID:    session.ID,
		Capabilities: capabilities,
	}
	if err := session.Send(&completeMsg); err != nil {
		m.logger.Error("Failed to send handshake complete", zap.Error(err))
		return
	}

	session.logger.Info("Session established",
		zap.String("session_id", session.ID),
		zap.Strings("capabilities", capabilities))

	// Main message loop
	m.handleSession(session)
}

func (m *Manager) handleSession(session *Session) {
	defer func() {
		close(session.closeCh)
		// Cancel all active flows
		session.flowsMu.Lock()
		for _, flow := range session.flows {
			if flow.Handler != nil {
				flow.Handler.Cancel()
			}
		}
		session.flowsMu.Unlock()
	}()

	for {
		_, message, err := session.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				session.logger.Error("Read error", zap.Error(err))
			}
			return
		}

		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			session.logger.Warn("Invalid message", zap.Error(err))
			continue
		}

		switch msg.Type {
		case TypeFlowStart:
			var startMsg FlowStartMessage
			if err := json.Unmarshal(message, &startMsg); err != nil {
				_ = session.SendFlowError(msg.FlowID, "", ErrCodeInvalidMessage, "Invalid flow_start format")
				continue
			}
			go m.handleFlowStart(session, &startMsg)

		case TypeFlowAction:
			var actionMsg FlowActionMessage
			if err := json.Unmarshal(message, &actionMsg); err != nil {
				_ = session.SendFlowError(msg.FlowID, "", ErrCodeInvalidMessage, "Invalid flow_action format")
				continue
			}
			// Check if flow exists before routing - prevents action loss for unknown flows
			session.flowsMu.RLock()
			_, flowExists := session.flows[actionMsg.FlowID]
			session.flowsMu.RUnlock()
			if !flowExists {
				session.logger.Warn("Action for unknown flow",
					zap.String("flow_id", actionMsg.FlowID),
					zap.String("action", actionMsg.Action))
				_ = session.SendFlowError(actionMsg.FlowID, "", ErrCodeUnknownFlow, "Flow not found or already completed")
				continue
			}
			// Route to the flow - send error if channel full instead of dropping
			select {
			case session.actionCh <- &actionMsg:
			default:
				session.logger.Error("Action channel full, sending error to client",
					zap.String("flow_id", actionMsg.FlowID),
					zap.String("action", actionMsg.Action))
				_ = session.SendFlowError(actionMsg.FlowID, "", ErrCodeTooManyRequests, "Server overloaded, please retry")
			}

		case TypeSignResponse:
			var signMsg SignResponseMessage
			if err := json.Unmarshal(message, &signMsg); err != nil {
				session.logger.Warn("Invalid sign_response", zap.Error(err))
				continue
			}
			// Route to waiting flow - send error if channel full instead of dropping
			select {
			case session.signCh <- &signMsg:
			default:
				session.logger.Error("Sign channel full, sending error to client",
					zap.String("message_id", signMsg.MessageID))
				_ = session.SendFlowError("", "", ErrCodeTooManyRequests, "Server overloaded, please retry")
			}

		default:
			session.logger.Warn("Unknown message type", zap.String("type", string(msg.Type)))
		}
	}
}

func (m *Manager) handleFlowStart(session *Session, msg *FlowStartMessage) {
	flowID := msg.FlowID
	if flowID == "" {
		flowID = uuid.New().String()
	}

	logger := session.logger.With(zap.String("flow_id", flowID[:8]), zap.String("protocol", string(msg.Protocol)))

	// Ensure cleanup happens even on panic
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in flow handler", zap.Any("panic", r))
			_ = session.SendFlowError(flowID, "", ErrCodeInternalError, "Internal error in flow handler")
		}
	}()

	// Get handler factory first (before acquiring flow lock)
	m.handlersMu.RLock()
	factory, ok := m.flowHandlers[msg.Protocol]
	m.handlersMu.RUnlock()

	if !ok {
		_ = session.SendFlowError(flowID, "", ErrCodeInvalidMessage, "Unknown protocol: "+string(msg.Protocol))
		return
	}

	// Check concurrent flow limit and register atomically to prevent race condition.
	// We hold the lock from check through registration to ensure atomic check-and-add.
	session.flowsMu.Lock()
	pendingFlows := len(session.flows)
	if pendingFlows >= MaxPendingFlowsPerSession {
		session.flowsMu.Unlock()
		_ = session.SendFlowError(flowID, "", ErrCodeTooManyRequests, "Too many pending flows. Complete or cancel existing flows before starting new ones.")
		logger.Warn("Rejected flow start - too many pending flows",
			zap.Int("pending_flows", pendingFlows),
			zap.Int("limit", MaxPendingFlowsPerSession))
		return
	}

	// Create flow while still holding lock
	flow := &Flow{
		ID:        flowID,
		Protocol:  msg.Protocol,
		Session:   session,
		State:     FlowStep("started"),
		StartTime: time.Now(),
		Data:      make(map[string]interface{}),
	}

	// Register flow immediately to reserve slot
	session.flows[flowID] = flow
	session.flowsMu.Unlock()

	// Create handler (after releasing lock to avoid holding it during potentially slow operations)
	handler, err := factory(flow, m.cfg, logger, m.trustService, m.registryClient, m.verifierStore)
	if err != nil {
		// Remove the reserved flow slot on error
		session.flowsMu.Lock()
		delete(session.flows, flowID)
		session.flowsMu.Unlock()
		_ = session.SendFlowError(flowID, "", ErrCodeInternalError, "Failed to create flow handler")
		logger.Error("Failed to create handler", zap.Error(err))
		return
	}
	flow.Handler = handler

	defer func() {
		session.flowsMu.Lock()
		delete(session.flows, flowID)
		session.flowsMu.Unlock()
	}()

	// Execute flow
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	logger.Info("Starting flow")
	if err := handler.Execute(ctx, msg); err != nil {
		logger.Error("Flow failed", zap.Error(err))
		// Error should have been sent by handler
		return
	}
	logger.Info("Flow completed")
}

func (m *Manager) registerSession(session *Session) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	// Close existing session for this user
	if existing, ok := m.userIndex[session.UserID]; ok {
		m.logger.Debug("Closing existing session", zap.String("user_id", session.UserID))
		_ = existing.conn.Close()
		delete(m.sessions, existing.ID)
		// Also remove from persistent store
		if m.sessionStore != nil {
			_ = m.sessionStore.DeleteByUser(context.Background(), session.UserID)
		}
	}

	m.sessions[session.ID] = session
	m.userIndex[session.UserID] = session

	// Persist to store
	if m.sessionStore != nil {
		sessionData := &SessionData{
			ID:        session.ID,
			UserID:    session.UserID,
			TenantID:  session.TenantID,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour), // TODO: configurable
		}
		if err := m.sessionStore.Put(context.Background(), sessionData); err != nil {
			m.logger.Warn("Failed to persist session", zap.Error(err))
		}
	}
}

func (m *Manager) unregisterSession(session *Session) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	delete(m.sessions, session.ID)
	if current, ok := m.userIndex[session.UserID]; ok && current == session {
		delete(m.userIndex, session.UserID)
	}

	// Remove from persistent store
	if m.sessionStore != nil {
		_ = m.sessionStore.Delete(context.Background(), session.ID)
	}

	session.logger.Info("Session closed")
}

func (m *Manager) validateToken(tokenString string) (userID, tenantID string, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(m.cfg.JWT.Secret), nil
	})

	if err != nil {
		return "", "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Support both "user_id" (go-wallet-backend native) and "uuid" (wallet-backend-server compat)
		userID, _ = claims["user_id"].(string)
		if userID == "" {
			userID, _ = claims["uuid"].(string)
		}
		tenantID, _ = claims["tenant_id"].(string)
		if userID == "" {
			return "", "", errors.New("invalid token claims: missing user_id or uuid")
		}
		return userID, tenantID, nil
	}

	return "", "", errors.New("invalid token")
}

func (m *Manager) getCapabilities() []string {
	m.handlersMu.RLock()
	defer m.handlersMu.RUnlock()

	caps := make([]string, 0, len(m.flowHandlers))
	for protocol := range m.flowHandlers {
		caps = append(caps, string(protocol))
	}
	return caps
}

func (m *Manager) sendError(conn *websocket.Conn, flowID string, code ErrorCode, message string) {
	msg := ErrorMessage{
		Message: Message{
			Type:      TypeError,
			FlowID:    flowID,
			Timestamp: Now(),
		},
		Code:    code,
		Details: message,
	}
	_ = conn.WriteJSON(msg)
}

// GetSession returns a session by ID
func (m *Manager) GetSession(sessionID string) (*Session, error) {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	session, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return session, nil
}

// GetSessionByUser returns a session by user ID
func (m *Manager) GetSessionByUser(userID string) (*Session, error) {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	session, ok := m.userIndex[userID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return session, nil
}

// ListSessions returns all sessions for a tenant from the persistent store
func (m *Manager) ListSessions(ctx context.Context, tenantID string) ([]*SessionData, error) {
	if m.sessionStore == nil {
		return nil, nil
	}
	return m.sessionStore.List(ctx, tenantID)
}

// CleanupSessions removes expired sessions from the persistent store
func (m *Manager) CleanupSessions(ctx context.Context) (int64, error) {
	if m.sessionStore == nil {
		return 0, nil
	}
	return m.sessionStore.Cleanup(ctx)
}

// Close closes all sessions
func (m *Manager) Close() {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	for _, session := range m.sessions {
		_ = session.conn.Close()
	}
	m.sessions = make(map[string]*Session)
	m.userIndex = make(map[string]*Session)

	// Close session store
	if m.sessionStore != nil {
		_ = m.sessionStore.Close()
	}
}

// IsHealthy returns true if the manager is able to accept new connections.
// This is used for readiness checks.
func (m *Manager) IsHealthy() bool {
	// Manager is healthy if it exists and has been initialized
	// (sessions map is non-nil). During shutdown, sessions become nil.
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	return m.sessions != nil
}

// Send sends a message to the client
func (s *Session) Send(msg interface{}) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.conn.WriteJSON(msg)
}

// SendProgress sends a flow progress message
func (s *Session) SendProgress(flowID string, step FlowStep, payload interface{}) error {
	var payloadJSON json.RawMessage
	if payload != nil {
		var err error
		payloadJSON, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}

	msg := FlowProgressMessage{
		Message: Message{
			Type:      TypeFlowProgress,
			FlowID:    flowID,
			Timestamp: Now(),
		},
		Step:    step,
		Payload: payloadJSON,
	}
	return s.Send(&msg)
}

// SendFlowComplete sends a flow completion message
func (s *Session) SendFlowComplete(flowID string, credentials []CredentialResult, redirectURI string) error {
	msg := FlowCompleteMessage{
		Message: Message{
			Type:      TypeFlowComplete,
			FlowID:    flowID,
			Timestamp: Now(),
		},
		Credentials: credentials,
		RedirectURI: redirectURI,
	}
	return s.Send(&msg)
}

// SendFlowError sends a flow error message
func (s *Session) SendFlowError(flowID string, step FlowStep, code ErrorCode, message string) error {
	msg := FlowErrorMessage{
		Message: Message{
			Type:      TypeFlowError,
			FlowID:    flowID,
			Timestamp: Now(),
		},
		Step: step,
		Error: FlowError{
			Code:    code,
			Message: message,
		},
	}
	return s.Send(&msg)
}

// RequestSign sends a signing request and waits for response
func (s *Session) RequestSign(ctx context.Context, flowID string, action SignAction, params SignRequestParams) (*SignResponseMessage, error) {
	messageID := uuid.New().String()

	msg := SignRequestMessage{
		Message: Message{
			Type:      TypeSignRequest,
			FlowID:    flowID,
			MessageID: messageID,
			Timestamp: Now(),
		},
		Action: action,
		Params: params,
	}

	if err := s.Send(&msg); err != nil {
		return nil, err
	}

	// Wait for response
	timeout := time.After(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, ErrSignTimeout
		case <-s.closeCh:
			return nil, errors.New("session closed")
		case resp := <-s.signCh:
			if resp.MessageID == messageID {
				return resp, nil
			}
			// Wrong message ID, keep waiting
		}
	}
}

// TrustEvaluationTimeout is the timeout for trust evaluation (including DID resolution).
// This is shorter than the full flow timeout to allow faster feedback on failures.
const TrustEvaluationTimeout = 2 * time.Minute

// UserInteractionTimeout is the default timeout for user interaction steps.
const UserInteractionTimeout = 5 * time.Minute

// WaitForAction waits for a flow action from the client
func (s *Session) WaitForAction(ctx context.Context, flowID string, expectedActions ...string) (*FlowActionMessage, error) {
	return s.WaitForActionWithTimeout(ctx, flowID, UserInteractionTimeout, expectedActions...)
}

// WaitForActionWithTimeout waits for a flow action with a custom timeout
func (s *Session) WaitForActionWithTimeout(ctx context.Context, flowID string, timeout time.Duration, expectedActions ...string) (*FlowActionMessage, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, ErrFlowTimeout
		case <-s.closeCh:
			return nil, errors.New("session closed")
		case action := <-s.actionCh:
			if action.FlowID != flowID {
				continue // Wrong flow
			}
			// Check if action is expected
			if len(expectedActions) > 0 {
				found := false
				for _, expected := range expectedActions {
					if action.Action == expected {
						found = true
						break
					}
				}
				if !found {
					continue // Unexpected action
				}
			}
			return action, nil
		}
	}
}
