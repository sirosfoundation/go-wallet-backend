package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	ws "github.com/sirosfoundation/go-wallet-backend/internal/websocket"
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

// TokenBlacklistChecker is the subset of a token blacklist this package
// needs to reject a revoked token during the WebSocket handshake - either
// individually by jti (explicit logout) or in bulk for a user (account
// deletion - see service.TokenBlacklist.RevokeUser). Mirrors
// pkg/middleware.TokenBlacklistChecker's shape; *service.TokenBlacklist
// satisfies this.
//
// validateToken's go-tokenauth branch relies on the shared
// *tokenvalidator.Validator (see SetTokenValidator) already having its own
// per-jti Revocation checker wired to the same blacklist instance (see
// internal/server.blacklistRevocationChecker) - this field only adds the
// user-level check that checker's interface can't express, and is the ONLY
// revocation check at all for the legacy HMAC branch, which the shared
// Validator never touches (#391 review, round 2: this handshake path was
// found to bypass both TokenAuthMiddleware's own user-level check and, for
// legacy tokens, revocation entirely).
type TokenBlacklistChecker interface {
	IsBlacklisted(ctx context.Context, jti string) bool
	IsUserRevoked(ctx context.Context, userID string) bool
}

// MaxPendingFlowsPerSession limits concurrent flows to prevent DoS.
// A session cannot start a new flow if it already has this many pending flows.
const MaxPendingFlowsPerSession = 3

const (
	// defaultWSPingInterval/defaultWSPongTimeout are the fallback keepalive
	// tunables used when config.ServerConfig.EngineWSPingInterval/
	// EngineWSPongTimeout is unset (zero) - e.g. a Config built directly by a
	// test rather than through config.Load(), which applies the real
	// defaults. See EngineWSPingInterval's doc comment in pkg/config for why
	// these particular numbers.
	defaultWSPingInterval = 3 * time.Second
	defaultWSPongTimeout  = 5 * time.Second

	// maxConnections is the maximum concurrent WebSocket sessions allowed.
	maxConnections = 10000
)

// wsKeepalive resolves this Manager's configured ping interval and pong
// timeout, falling back to defaultWSPingInterval/defaultWSPongTimeout for
// whichever one is unset - see their doc comment.
func (m *Manager) wsKeepalive() (pingInterval, pongTimeout time.Duration) {
	pingInterval, pongTimeout = m.cfg.Server.EngineWSPingInterval, m.cfg.Server.EngineWSPongTimeout
	if pingInterval <= 0 {
		pingInterval = defaultWSPingInterval
	}
	if pongTimeout <= 0 {
		pongTimeout = defaultWSPongTimeout
	}
	return pingInterval, pongTimeout
}

// Session represents an authenticated session (WebSocket or WMP)
type Session struct {
	ID       string
	UserID   string
	TenantID string
	// TAC is only ever populated on the go-tokenauth path - see
	// Manager.validateToken. An empty TAC means "not applicable" (legacy
	// auth, no TAC concept at all), not "no permissions" - handleFlowStart's
	// per-protocol check must treat it as a no-op, exactly like
	// requireTACIfEnforced does for HTTP routes.
	TAC claims.TAC
	// TACEnforced: the session was created by a modern token, so its TAC is
	// authoritative even when empty (no permissions). False only for legacy
	// tokens, which have no TAC concept.
	TACEnforced bool

	// onSuperseded, when set before registration, is called (without any
	// manager lock held) after a later registerSession for the same user
	// replaces this session. The WMP adapter uses it to invalidate the
	// session's resume state (token, peer) so it cannot be resumed.
	onSuperseded func()
	transport    SessionTransport
	transportMu  sync.RWMutex // guards transport reassignment during session resume
	flows        map[string]*Flow
	flowsMu      sync.RWMutex
	// closed is set by endSession under flowsMu, before it scans flows. Every
	// path that publishes a flow into flows checks it under the same lock, so
	// a flow is either visible to endSession's cancellation scan or refused.
	closed bool
	// testHookBeforePublish, when set (tests only), runs in the WMP FlowStart
	// after the handler is built and before it is published.
	testHookBeforePublish func()
	logger                *zap.Logger

	// Channels for flow coordination
	actionCh chan *FlowActionMessage
	signCh   chan *SignResponseMessage
	matchCh  chan *MatchResponseMessage
	closeCh  chan struct{}
	// stash parks client responses that arrived on the shared channels above
	// but belong to a different concurrent flow/request than the waiter that
	// read them, so no flow can consume (and lose) another flow's input.
	stash responseStash
	// closeOnce makes endSession idempotent: the transport-specific read
	// loop (handleSession) and the WMP adapter's session teardown can both
	// end the same session.
	closeOnce sync.Once

	// notifications holds ephemeral, TTL-bounded OID4VCI §10 notification
	// contexts keyed by flow ID. It lets the backend forward a client-reported
	// credential lifecycle event to the issuer using the issuance access token,
	// without persisting anything.
	notifications *notificationContextStore

	// stopPing signals the ping goroutine to exit.
	stopPing chan struct{}

	// pingInterval/pongTimeout are this session's resolved keepalive
	// tunables (see Manager.wsKeepalive) - set once at session creation and
	// used by pingLoop and the read-deadline resets around it, and reported
	// to the client via HandshakeCompleteMessage.Config so both sides agree
	// on the same cadence.
	pingInterval time.Duration
	pongTimeout  time.Duration
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

// userKey identifies the one live session a user may hold per tenant.
// Users can belong to several tenants, so keying by UserID alone would let
// a connection in one tenant tear down the same user's session in another.
type userKey struct {
	TenantID string
	UserID   string
}

// defaultTenant is the tenant a token without a tenant_id claim belongs to
// (matches pkg/middleware/tokenauth.go).
const defaultTenant = "default"

// normalizeTenant maps a missing tenant claim to the default tenant. It is
// the single normalisation shared by WebSocket and WMP session creation, the
// (tenant, user) index, session ownership checks and the persisted store, so
// the same tokenless-tenant user always resolves to the same tenant.
func normalizeTenant(t string) string {
	if t == "" {
		return defaultTenant
	}
	return t
}

// userKey returns the session's (tenant, user) index key.
func (s *Session) userKey() userKey {
	return userKey{TenantID: normalizeTenant(s.TenantID), UserID: s.UserID}
}

// Manager manages WebSocket sessions and flows
type Manager struct {
	cfg      *config.Config
	logger   *zap.Logger
	upgrader websocket.Upgrader

	sessionsMu sync.RWMutex
	sessions   map[string]*Session  // sessionID -> session (active connections only)
	userIndex  map[userKey]*Session // (tenant, user) -> session (last connection wins)
	// draining is set (under sessionsMu) by Drain/Close and never cleared:
	// no connection may register once it is set, so a WebSocket accepted
	// just before shutdown cannot slip in after Close has cleared the maps.
	draining bool
	// beforeRegisterHook, if set, runs in handleNewConnection immediately
	// before registerSession. Tests use it to hold a connection in the
	// accepted-but-unregistered window while shutdown begins.
	beforeRegisterHook func()

	flowHandlers map[Protocol]FlowHandlerFactory
	handlersMu   sync.RWMutex

	trustService   *TrustService
	registryClient *RegistryClient
	verifierStore  storage.VerifierStore
	trustCache     *TrustCache

	// notificationSem bounds the number of concurrent OID4VCI §10 notification
	// forwards across all sessions, providing backpressure against a client
	// flooding credential_notification messages.
	notificationSem chan struct{}

	// Persistent session store (optional, for horizontal scaling)
	sessionStore SessionStore

	// tokenValidator validates access tokens via go-tokenauth (optional).
	// When set, validateToken uses it instead of direct HMAC parsing.
	tokenValidator *tokenvalidator.Validator

	// blacklist checks token/user revocation during the handshake (optional
	// - see TokenBlacklistChecker's doc comment).
	blacklist TokenBlacklistChecker

	// revokedUsersMu guards revokedUsers.
	revokedUsersMu sync.RWMutex

	// revokedUsers is the engine's own, always-on record of users whose
	// account has been deleted, populated by RevokeUser and consulted by
	// isUserRevoked. Deliberately independent of blacklist/
	// TokenBlacklistChecker: that checker no-ops entirely when the
	// optional security.token_blacklist feature is configured disabled,
	// which meant session-level closure/rejection at the engine used to
	// silently stop working too whenever that unrelated feature flag was
	// off (#403 - filed against #393/#399, now fixed by giving the engine
	// this signal of its own rather than relying on an optional,
	// separately-configured feature). TokenBlacklist remains the
	// mechanism for token-level (HTTP) revocation; this is purely the
	// engine's session-level one.
	revokedUsers map[string]struct{}

	// activeConnections counts every upgraded connection, handshaked or not.
	// The connection limit must be enforced against this, not len(sessions):
	// sessions are only registered post-handshake, so counting only sessions
	// lets an attacker open unlimited unauthenticated connections that never
	// complete the handshake, bypassing the limit entirely.
	activeConnections atomic.Int64
}

// NewManager creates a new session manager
func NewManager(cfg *config.Config, logger *zap.Logger) *Manager {
	m := &Manager{
		cfg:    cfg,
		logger: logger.Named("engine"),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin:     ws.CheckOriginFromConfig(cfg),
		},
		sessions:        make(map[string]*Session),
		userIndex:       make(map[userKey]*Session),
		revokedUsers:    make(map[string]struct{}),
		flowHandlers:    make(map[Protocol]FlowHandlerFactory),
		trustService:    NewTrustService(cfg, logger),
		registryClient:  NewRegistryClient(cfg, logger),
		trustCache:      NewTrustCache(cfg.Trust.VerifierCacheTTL()),
		notificationSem: make(chan struct{}, maxConcurrentNotifications),
		sessionStore:    NewMemorySessionStore(logger), // Default to memory
	}
	// Say so loudly. Running without the trust cache means every flow asks the
	// PDP again, which is the point when testing trust configuration and a
	// needless load on it otherwise - either way an operator should not have
	// to read the config to find out which mode this process is in.
	if ttl := cfg.Trust.VerifierCacheTTL(); ttl <= 0 {
		m.logger.Warn("Verifier trust cache is DISABLED; every flow will re-evaluate with the PDP")
	} else {
		m.logger.Debug("Verifier trust cache enabled", zap.Duration("ttl", ttl))
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

// SetTokenValidator sets the go-tokenauth validator for WebSocket handshake auth.
func (m *Manager) SetTokenValidator(v *tokenvalidator.Validator) {
	m.tokenValidator = v
}

// SetTokenBlacklist sets the token blacklist consulted during the
// WebSocket handshake - see TokenBlacklistChecker's doc comment for what
// this covers versus what the shared *tokenvalidator.Validator already
// checks on its own.
func (m *Manager) SetTokenBlacklist(b TokenBlacklistChecker) {
	m.blacklist = b
}

// RegisterFlowHandler registers a handler factory for a protocol
func (m *Manager) RegisterFlowHandler(protocol Protocol, factory FlowHandlerFactory) {
	m.handlersMu.Lock()
	defer m.handlersMu.Unlock()
	m.flowHandlers[protocol] = factory
}

// HandleConnection handles a new WebSocket connection
func (m *Manager) HandleConnection(w http.ResponseWriter, r *http.Request) {
	// Refuse upgrades once shutdown has begun. registerSession re-checks
	// under the lock for connections accepted before this point.
	if m.isDraining() {
		http.Error(w, "server is shutting down", http.StatusServiceUnavailable)
		return
	}

	// Reserve a slot atomically before checking the limit. Checking
	// Load() >= maxConnections and only then incrementing is racy: multiple
	// concurrent requests can all pass the check before any of them
	// increments, overshooting maxConnections under load. Add(1) returns the
	// post-increment value, so only requests that actually push the counter
	// over the limit roll back.
	if m.activeConnections.Add(1) > maxConnections {
		m.activeConnections.Add(-1)
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}

	responseHeader := http.Header{}
	if servedBy := m.cfg.Server.ResolvedServedBy(); servedBy != "" {
		responseHeader.Set("X-Served-By", servedBy)
	}
	conn, err := m.upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		m.activeConnections.Add(-1)
		m.logger.Error("Failed to upgrade connection", zap.Error(err))
		return
	}

	// Clear the write deadline inherited from net/http's WriteTimeout.
	// After upgrade, the WebSocket connection manages its own deadlines;
	// the stale deadline would cause writes to fail after the timeout elapses.
	_ = conn.SetWriteDeadline(time.Time{})

	m.logger.Debug("WebSocket client connected")
	go m.handleNewConnection(conn)
}

func (m *Manager) handleNewConnection(conn *websocket.Conn) {
	defer m.activeConnections.Add(-1)
	transport := newWSTransport(conn)
	defer func() { _ = transport.Close() }()

	// Wait for handshake message
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, message, err := conn.ReadMessage()
	if err != nil {
		m.logger.Error("Failed to read handshake", zap.Error(err))
		return
	}
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
	id, err := m.validateTokenAuth(handshake.AppToken)
	userID, tenantID, tac := id.UserID, id.TenantID, id.TAC
	if err != nil {
		m.logger.Warn("Authentication failed",
			zap.Error(err),
			zap.Int("token_len", len(handshake.AppToken)),
		)
		m.sendError(conn, "", ErrCodeAuthFailed, "Invalid or expired token")
		return
	}

	// Configure WebSocket ping/pong keepalive.
	// The pong handler resets the read deadline each time the client responds,
	// keeping the connection alive across idle periods. Browser WebSocket
	// implementations respond to protocol-level pings automatically.
	pingInterval, pongTimeout := m.wsKeepalive()
	_ = conn.SetReadDeadline(time.Now().Add(pingInterval + pongTimeout))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(pingInterval + pongTimeout))
		return nil
	})

	// Create session
	sessionID := uuid.New().String()
	logLabel := sessionID[:8]
	if userID != "" {
		logLabel = userID[:min(8, len(userID))]
	}
	session := &Session{
		ID:            sessionID,
		UserID:        userID,
		TenantID:      tenantID,
		TAC:           tac,
		TACEnforced:   id.EnforceTAC,
		transport:     transport,
		flows:         make(map[string]*Flow),
		logger:        m.logger.With(zap.String("session", logLabel)),
		actionCh:      make(chan *FlowActionMessage, 50),
		signCh:        make(chan *SignResponseMessage, 20),
		matchCh:       make(chan *MatchResponseMessage, 20),
		closeCh:       make(chan struct{}, 1), // Buffered to prevent deadlock
		stopPing:      make(chan struct{}),
		notifications: newNotificationContextStore(),
		pingInterval:  pingInterval,
		pongTimeout:   pongTimeout,
	}

	// Register session. A rejection here means the user was revoked in the
	// narrow window between validateToken's own check above and this call -
	// registerSession has already closed the connection itself in that
	// case, so there is nothing left to unregister.
	if m.beforeRegisterHook != nil {
		m.beforeRegisterHook()
	}
	if !m.registerSession(session) {
		session.logger.Warn("Handshake rejected: user revoked or server draining between token validation and session registration")
		return
	}
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
		Config: SessionConfig{
			PingIntervalMs: pingInterval.Milliseconds(),
		},
	}
	if err := session.Send(&completeMsg); err != nil {
		m.logger.Error("Failed to send handshake complete", zap.Error(err))
		return
	}

	session.logger.Info("Session established",
		zap.String("session_id", session.ID),
		zap.Strings("capabilities", capabilities),
		zap.Duration("ping_interval", pingInterval))

	// Start ping keepalive goroutine
	go session.pingLoop()

	// Main message loop
	m.handleSession(session)
}

// pingLoop sends WebSocket ping frames at s.pingInterval.
// Browser WebSocket implementations respond with pong automatically.
func (s *Session) pingLoop() {
	wst, ok := s.transport.(*wsTransport)
	if !ok {
		return // non-WebSocket transports don't need ping/pong
	}

	ticker := time.NewTicker(s.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			wst.sendMu.Lock()
			err := wst.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(s.pongTimeout))
			wst.sendMu.Unlock()
			if err != nil {
				return // connection is dead; ReadMessage will surface the error
			}
		case <-s.stopPing:
			return
		}
	}
}

// endSession signals every goroutine blocked on this session (closeCh) and
// cancels all active flows. It is idempotent and shared by all transports, so
// a WMP session torn down by the adapter (client close, idle expiry, account
// revocation, shutdown) stops its flows exactly like a WebSocket disconnect.
func (s *Session) endSession() {
	s.closeOnce.Do(func() {
		if s.closeCh != nil {
			close(s.closeCh)
		}
		s.flowsMu.Lock()
		s.closed = true
		for _, flow := range s.flows {
			if flow.Handler != nil {
				flow.Handler.Cancel()
			}
		}
		s.flowsMu.Unlock()
	})
}

// currentTransport returns the session's transport under transportMu (the
// transport is swapped on WMP session resume).
func (s *Session) currentTransport() SessionTransport {
	s.transportMu.RLock()
	defer s.transportMu.RUnlock()
	return s.transport
}

func (m *Manager) handleSession(session *Session) {
	defer func() {
		if session.stopPing != nil {
			close(session.stopPing) // stop the ping goroutine (WebSocket only)
		}
		session.endSession()
	}()

	for {
		message, err := session.transport.ReadMessage(context.Background())
		if err != nil {
			session.logger.Debug("Session read ended", zap.Error(err))
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

		case TypeMatchResponse:
			var matchMsg MatchResponseMessage
			if err := json.Unmarshal(message, &matchMsg); err != nil {
				session.logger.Warn("Invalid match_response", zap.Error(err))
				continue
			}
			// Route to waiting flow - send error if channel full instead of dropping
			select {
			case session.matchCh <- &matchMsg:
			default:
				session.logger.Error("Match channel full, sending error to client",
					zap.String("flow_id", matchMsg.FlowID),
					zap.String("message_id", matchMsg.MessageID))
				_ = session.SendFlowError(matchMsg.FlowID, StepMatchCredentials, ErrCodeTooManyRequests, "Server overloaded, please retry")
			}

		case TypeCredentialNotification:
			var notifMsg CredentialNotificationMessage
			if err := json.Unmarshal(message, &notifMsg); err != nil {
				session.logger.Warn("Invalid credential_notification", zap.Error(err))
				continue
			}
			// Validate synchronously so malformed/unsupported requests are
			// rejected inline and never enter the bounded async forwarding
			// path. Only well-formed requests with a live notification context
			// spawn a goroutine (capped by m.notificationSem).
			m.dispatchCredentialNotification(session, &notifMsg)

		default:
			session.logger.Warn("Unknown message type", zap.String("type", string(msg.Type)))
		}
	}
}

// requiredTACForProtocol maps each flow protocol to the TAC permission its
// action semantically requires: OID4VP shares an existing credential (read),
// OID4VCI receives a new one (insert). Only enforced when the session
// actually has a TAC to check - see handleFlowStart.
var requiredTACForProtocol = map[Protocol]string{
	ProtocolOID4VP:  "r",
	ProtocolOID4VCI: "i",
}

func (m *Manager) handleFlowStart(session *Session, msg *FlowStartMessage) {
	flowID := msg.FlowID
	if flowID == "" {
		flowID = uuid.New().String()
	}

	// Ensure cleanup happens even on panic. Registered before anything else
	// touches the client-controlled flowID: a flow_id shorter than the log
	// truncation below must not be able to panic ahead of this defer.
	logger := session.logger
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in flow handler", zap.Any("panic", r))
			_ = session.SendFlowError(flowID, "", ErrCodeInternalError, "Internal error in flow handler")
		}
	}()

	loggedFlowID := flowID
	if len(loggedFlowID) > 8 {
		loggedFlowID = loggedFlowID[:8]
	}
	logger = session.logger.With(zap.String("flow_id", loggedFlowID), zap.String("protocol", string(msg.Protocol)))

	// Get handler factory first (before acquiring flow lock)
	m.handlersMu.RLock()
	factory, ok := m.flowHandlers[msg.Protocol]
	m.handlersMu.RUnlock()

	if !ok {
		_ = session.SendFlowError(flowID, "", ErrCodeInvalidMessage, "Unknown protocol: "+string(msg.Protocol))
		return
	}

	// TAC check: only enforced when the session actually has a TAC to check
	// (empty means legacy auth, which has no TAC concept - see
	// Manager.validateToken - not "no permissions"), mirroring
	// requireTACIfEnforced's identical conditional enforcement for HTTP
	// routes (internal/server/providers.go).
	// A modern token (session.TACEnforced) is always checked, even with an
	// empty TAC, which means "no permissions".
	if session.TACEnforced || session.TAC != "" {
		if required, ok := requiredTACForProtocol[msg.Protocol]; ok && !session.TAC.HasAll(required) {
			_ = session.SendFlowError(flowID, "", ErrCodeForbidden, "insufficient permissions for protocol: "+string(msg.Protocol))
			logger.Warn("Rejected flow start - insufficient TAC",
				zap.String("tac", string(session.TAC)),
				zap.String("required", required),
			)
			return
		}
	}

	// Check concurrent flow limit and register atomically to prevent race condition.
	// We hold the lock from check through registration to ensure atomic check-and-add.
	session.flowsMu.Lock()
	if session.closed {
		session.flowsMu.Unlock()
		_ = session.SendFlowError(flowID, "", ErrCodeInternalError, "Session closed")
		return
	}
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
	handler, err := factory(flow, m.cfg, logger, m.trustService, m.registryClient, m.verifierStore, m.trustCache)
	if err != nil {
		// Remove the reserved flow slot on error
		session.removeFlow(flowID, flow)
		_ = session.SendFlowError(flowID, "", ErrCodeInternalError, "Failed to create flow handler")
		logger.Error("Failed to create handler", zap.Error(err))
		return
	}
	// Publish the handler under flowsMu and re-check closed: endSession may
	// have scanned flows while Handler was still nil and so skipped Cancel.
	session.flowsMu.Lock()
	if session.closed {
		session.flowsMu.Unlock()
		handler.Cancel()
		session.removeFlow(flowID, flow)
		_ = session.SendFlowError(flowID, "", ErrCodeInternalError, "Session closed")
		return
	}
	flow.Handler = handler
	session.flowsMu.Unlock()

	defer session.removeFlow(flowID, flow)

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

// registerSession adds session to the manager's live-session bookkeeping
// and returns true, unless userID was revoked between validateToken's own
// check (in handleNewConnection, immediately before this call) and this
// call actually acquiring the lock - in which case it closes the
// connection itself and returns false without registering anything.
//
// That recheck closes a narrow TOCTOU window found in review: DeleteUser's
// session cleaner (see service.UserService.DeleteUser and
// Manager.CloseUserSessions) only ever closes sessions already present in
// m.sessions at the moment it runs. Without this recheck, a handshake that
// passed validateToken just before the user was deleted, but that only
// finishes registering after CloseUserSessions's scan already ran, would
// become a permanent zombie - immune to every check #393 exists to add.
// Rechecking here, atomically with insertion under the same sessionsMu
// that CloseUserSessions scans under, closes that gap: any session that
// registers after the revocation is caught here; any that registered
// before it is caught by the scan that necessarily follows (see
// service.UserService.DeleteUser, which revokes before it cleans up
// sessions).
//
// This recheck (and validateToken's identical one) used to only have a
// blacklist to consult when m.blacklist was set at all, and
// TokenBlacklist.IsUserRevoked always reports false when the optional
// security.token_blacklist feature is configured disabled - meaning
// nothing anywhere in the engine could distinguish a deleted user's
// handshake from anyone else's whenever that unrelated feature flag was
// off (#403, filed against an earlier version of this fix). Also
// consulting m.isUserRevoked - the engine's own always-on signal, set by
// RevokeUser regardless of that feature flag - closes that gap
// unconditionally: registering after RevokeUser marks the user revoked is
// always caught here (RevokeUser sets revokedUsers before it scans for
// and closes existing sessions, so there's no ordering to get wrong);
// registering before it is caught by that same scan.
func (m *Manager) registerSession(session *Session) bool {
	m.sessionsMu.Lock()

	// Drain gate: Close/Drain flip draining under this same lock, so a
	// registration is either ordered before it (and closed by Close's
	// sweep) or sees the flag here and is refused. It can never land after
	// Close has cleared the maps.
	if m.draining {
		m.sessionsMu.Unlock()
		session.closeWithReason("server shutting down")
		return false
	}
	if session.UserID != "" {
		if m.userRevoked(session.UserID) {
			m.sessionsMu.Unlock()
			session.closeWithReason("account deleted")
			return false
		}
	}
	// A superseded session's onSuperseded hook runs after sessionsMu is
	// released: it takes the owning adapter's lock, and adapters take their
	// lock before consulting the manager (isCurrentSession).
	var superseded *Session
	defer func() {
		m.sessionsMu.Unlock()
		if superseded != nil && superseded.onSuperseded != nil {
			superseded.onSuperseded()
		}
	}()

	// Close the existing session for this (tenant, user) pair (skip for
	// anonymous sessions). The same user's sessions in other tenants are
	// independent and left alone.
	if session.UserID != "" {
		if existing, ok := m.userIndex[session.userKey()]; ok {
			superseded = existing
			m.logger.Debug("Closing existing session",
				zap.String("user_id", session.UserID), zap.String("tenant_id", session.TenantID))
			_ = existing.currentTransport().Close()
			delete(m.sessions, existing.ID)
			// Also remove from persistent store
			if m.sessionStore != nil {
				_ = m.sessionStore.Delete(context.Background(), existing.ID)
			}
		}
	}

	m.sessions[session.ID] = session
	if session.UserID != "" {
		m.userIndex[session.userKey()] = session
	}

	// Persist to store
	if m.sessionStore != nil {
		sessionData := &SessionData{
			ID:        session.ID,
			UserID:    session.UserID,
			TenantID:  normalizeTenant(session.TenantID),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour), // TODO: configurable
		}
		if err := m.sessionStore.Put(context.Background(), sessionData); err != nil {
			m.logger.Warn("Failed to persist session", zap.Error(err))
		}
	}
	return true
}

// isCurrentSession reports whether session is still the registered session
// (and, for an identified user, still the user's current one): a later
// registerSession for the same user supersedes it and closes its transport.
// Callers publishing a freshly registered session use it to fail a create
// that lost that race instead of reporting success for a session that is
// already being torn down.
func (m *Manager) isCurrentSession(session *Session) bool {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	if m.sessions[session.ID] != session {
		return false
	}
	if session.UserID != "" && m.userIndex[session.userKey()] != session {
		return false
	}
	return true
}

func (m *Manager) unregisterSession(session *Session) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	delete(m.sessions, session.ID)
	if session.UserID != "" {
		if current, ok := m.userIndex[session.userKey()]; ok && current == session {
			delete(m.userIndex, session.userKey())
		}
	}

	// Remove from persistent store
	if m.sessionStore != nil {
		_ = m.sessionStore.Delete(context.Background(), session.ID)
	}

	// "session" (session.logger's bound field) is the user's short ID, not
	// this session's own - deliberately shared across every reconnect for
	// that user so log lines from the same user grep together. Without an
	// explicit session_id here (unlike "Session established", which already
	// logs one), two rapid reconnects for one user produce two "Session
	// closed" lines that are indistinguishable from each other, which read
	// as a session-eviction bug when reconnects were simply frequent.
	session.logger.Info("Session closed", zap.String("session_id", session.ID))
}

// validateToken authenticates tokenString and returns its identity.
// tac is only ever populated on the go-tokenauth path - the legacy HMAC
// path (below) has no TAC concept at all, so callers must treat an empty
// tac as "not applicable here", not "no permissions", exactly like
// requireTACIfEnforced does for HTTP routes (see internal/server/providers.go).
func (m *Manager) validateToken(tokenString string) (userID, tenantID string, tac claims.TAC, err error) {
	userID, tenantID, tac, _, err = m.validateTokenID(tokenString)
	return
}

// validateTokenID is validateToken that also returns the token's jti (empty
// if the token carries none). The WMP adapter binds sessions to it so
// anonymous callers (UserID == "") cannot address each other's sessions.
func (m *Manager) validateTokenID(tokenString string) (userID, tenantID string, tac claims.TAC, jti string, err error) {
	id, err := m.validateTokenAuth(tokenString)
	return id.UserID, id.TenantID, id.TAC, id.JTI, err
}

// tokenIdentity is what validateTokenAuth learned about a bearer token.
type tokenIdentity struct {
	UserID, TenantID string
	TAC              claims.TAC
	JTI              string
	// EnforceTAC reports whether the token's TAC is authoritative: true for
	// every modern (go-tokenauth session-mode) token, including one whose TAC
	// is empty - that means "no permissions", not "not applicable". Only a
	// genuine legacy token (HMAC all-in-one, no TAC concept) is false.
	EnforceTAC bool
}

// validateTokenAuth is validateTokenID that also reports token provenance
// (see tokenIdentity.EnforceTAC).
func (m *Manager) validateTokenAuth(tokenString string) (tokenIdentity, error) {
	userID, tenantID, tac, jti, enforce, err := m.validateTokenFull(tokenString)
	return tokenIdentity{UserID: userID, TenantID: normalizeTenant(tenantID), TAC: tac, JTI: jti, EnforceTAC: enforce}, err
}

func (m *Manager) validateTokenFull(tokenString string) (userID, tenantID string, tac claims.TAC, jti string, enforceTAC bool, err error) {
	// Use go-tokenauth validator when available (supports both new-style and legacy tokens)
	if m.tokenValidator != nil {
		result, err := m.tokenValidator.Validate(context.Background(), tokenString)
		if err != nil {
			return "", "", "", "", false, err
		}
		// The engine transport, like the AuthZEN proxy, only needs a
		// wallet-registry or wallet-backend audience - never a broader one.
		if !result.HasAudience("wallet-registry", "wallet-backend") {
			return "", "", "", "", false, errors.New("token audience not permitted for engine transport")
		}
		// Per-jti revocation is already enforced inside Validate itself (the
		// shared Validator's own Revocation checker - see
		// internal/server.blacklistRevocationChecker); user-level revocation
		// is not, since that checker's interface only ever sees a jti (see
		// #391 review, round 2). Checked against both the optional
		// TokenBlacklist feature and the engine's own always-on
		// revokedUsers (#403) - either one saying revoked is enough to
		// reject.
		if (m.blacklist != nil && m.blacklist.IsUserRevoked(context.Background(), result.UserID)) || m.isUserRevoked(result.UserID) {
			return "", "", "", "", false, errors.New("token has been revoked")
		}
		// UserID may be empty for anonymous tokens — that is acceptable.
		return result.UserID, result.TenantID, result.TAC, result.JTI, result.Mode != claims.ModeLegacy, nil
	}

	// Legacy path: direct HMAC validation. Unlike the go-tokenauth branch
	// above, nothing else in this path ever checks revocation at all, so
	// both checks below are needed, not just the user-level one (#391
	// review, round 2).
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(m.cfg.JWT.Secret), nil
	}, jwt.WithLeeway(config.JWTLeeway))

	if err != nil {
		return "", "", "", "", false, err
	}

	if mapClaims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Support both "user_id" (go-wallet-backend native) and "uuid" (wallet-backend-server compat)
		userID, _ = mapClaims["user_id"].(string)
		if userID == "" {
			userID, _ = mapClaims["uuid"].(string)
		}
		tenantID, _ = mapClaims["tenant_id"].(string)
		if userID == "" {
			return "", "", "", "", false, errors.New("invalid token claims: missing user_id or uuid")
		}
		if m.blacklist != nil {
			ctx := context.Background()
			if jti, _ := mapClaims["jti"].(string); jti != "" && m.blacklist.IsBlacklisted(ctx, jti) {
				return "", "", "", "", false, errors.New("token has been revoked")
			}
			if m.blacklist.IsUserRevoked(ctx, userID) {
				return "", "", "", "", false, errors.New("token has been revoked")
			}
		}
		// Checked unconditionally (unlike the m.blacklist block above,
		// which is skipped entirely when no blacklist is wired): the
		// engine's own revokedUsers works regardless of whether that
		// optional feature is configured at all (#403).
		if m.isUserRevoked(userID) {
			return "", "", "", "", false, errors.New("token has been revoked")
		}
		jti, _ = mapClaims["jti"].(string)
		return userID, tenantID, "", jti, false, nil
	}

	return "", "", "", "", false, errors.New("invalid token")
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
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	_ = conn.WriteMessage(websocket.TextMessage, data)
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

// GetSessionByUser returns the current session of userID within tenantID.
// A user may hold one session per tenant.
func (m *Manager) GetSessionByUser(tenantID, userID string) (*Session, error) {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	session, ok := m.userIndex[userKey{TenantID: normalizeTenant(tenantID), UserID: userID}]
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
	return m.sessionStore.List(ctx, normalizeTenant(tenantID))
}

// CleanupSessions removes expired sessions from the persistent store
func (m *Manager) CleanupSessions(ctx context.Context) (int64, error) {
	if m.sessionStore == nil {
		return 0, nil
	}
	return m.sessionStore.Cleanup(ctx)
}

// DeleteByUser implements service.SessionCleaner (duck-typed - engine must
// not import package service): it permanently marks userID revoked for
// this engine process (see RevokeUser) and closes every live WebSocket
// session it currently holds for that user, e.g. because the account was
// just deleted.
//
// This is a separate cleaner from the persistent SessionStore's own
// DeleteByUser (see cmd/server/main.go, which wires both): that one only
// ever purged the persisted SessionData bookkeeping record, never the
// *websocket.Conn* itself, so an already-established connection for a
// deleted user stayed open and usable until it disconnected on its own
// (#393 - found as a follow-up to #391, which closed the equivalent gap
// for new handshakes via IsUserRevoked, but not for connections that were
// already past the handshake).
//
// Sessions live on other backend replicas (Redis-backed horizontal
// scaling) are out of scope here: only this process's own live connections
// can be closed directly.
func (m *Manager) DeleteByUser(_ context.Context, userID string) error {
	m.RevokeUser(userID)
	return nil
}

// RevokeUser permanently marks userID revoked for this engine process:
// every current and future WebSocket session for that user is rejected
// from now on (see isUserRevoked, consulted by validateToken and
// registerSession), and any of the user's sessions already live in this
// process are closed immediately (see CloseUserSessions). This works
// regardless of whether the optional security.token_blacklist feature is
// configured at all - see revokedUsers' doc comment for why this exists
// as the engine's own signal rather than being derived from
// TokenBlacklistChecker (#403).
//
// Like TokenBlacklist's own userRevocations map, this entry is never
// expired: user IDs (domain.NewUserID()) are never reissued after
// deletion, so there is no "issued before/after the revocation" window to
// reason about - the revocation is simply permanent for that ID for the
// life of this process, and the map only grows by one entry per account
// ever deleted, which is acceptable given how small and infrequent that
// is.
func (m *Manager) RevokeUser(userID string) {
	if userID == "" {
		return
	}

	m.revokedUsersMu.Lock()
	m.revokedUsers[userID] = struct{}{}
	m.revokedUsersMu.Unlock()

	m.CloseUserSessions(userID, "account deleted")
}

// userRevoked reports whether userID is revoked according to either the
// engine's own always-on set or the optional token blacklist.
func (m *Manager) userRevoked(userID string) bool {
	if userID == "" {
		return false
	}
	if m.isUserRevoked(userID) {
		return true
	}
	return m.blacklist != nil && m.blacklist.IsUserRevoked(context.Background(), userID)
}

// isUserRevoked reports whether userID was marked revoked via RevokeUser.
// Unlike TokenBlacklistChecker.IsUserRevoked, this never depends on any
// optional feature configuration - see revokedUsers' doc comment.
func (m *Manager) isUserRevoked(userID string) bool {
	if userID == "" {
		return false
	}
	m.revokedUsersMu.RLock()
	defer m.revokedUsersMu.RUnlock()
	_, revoked := m.revokedUsers[userID]
	return revoked
}

// CloseUserSessions closes every live session belonging to userID (sending
// a close frame with reason where the connection can still accept one) and
// returns how many were closed. A user can hold more than one concurrent
// session (multiple devices), so this closes all of them, not just the one
// in userIndex ("last connection wins" per tenant - see registerSession),
// and across every tenant the user belongs to, since a user-wide
// revocation is not tenant-scoped. Matching is
// strictly by exact Session.UserID equality (and userID must be non-empty),
// so this can never close an anonymous session or a different user's
// session.
func (m *Manager) CloseUserSessions(userID string, reason string) int {
	if userID == "" {
		// Never treat "no user" as "match anonymous sessions" - every
		// unauthenticated/anonymous session also has an empty UserID, and
		// closing all of those would be a foot-gun this must not allow.
		return 0
	}

	m.sessionsMu.RLock()
	matches := make([]*Session, 0, 1)
	for _, s := range m.sessions {
		if s.UserID == userID {
			matches = append(matches, s)
		}
	}
	m.sessionsMu.RUnlock()

	for _, s := range matches {
		s.closeWithReason(reason)
	}
	return len(matches)
}

// closeWithReason sends a WebSocket close frame carrying reason (best
// effort - the connection may already be broken or busy) and then closes
// the underlying connection. This unblocks the session's read loop with an
// error exactly like a client-initiated disconnect, so the Manager's normal
// per-connection teardown (unregisterSession, flow cancellation, stopping
// the ping goroutine - see handleSession/handleNewConnection) runs
// unchanged rather than being duplicated here.
//
// Deliberately does NOT take the transport's sendMu: per gorilla/websocket's own
// concurrency contract, WriteControl (unlike WriteJSON/WriteMessage, which
// s.Send serializes via sendMu) may be called concurrently with any other
// write. Taking sendMu here would let a backpressured client - whose peer
// never reads, and whose write deadline was cleared after upgrade, see
// handleNewConnection - block this call, and therefore account deletion,
// indefinitely on an in-flight s.Send. WriteControl's own deadline bounds
// this call regardless of whether it succeeds, and Close is unconditional.
func (s *Session) closeWithReason(reason string) {
	t := s.currentTransport()
	if wst, ok := t.(*wsTransport); ok {
		_ = wst.conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, reason),
			time.Now().Add(time.Second),
		)
	}
	// Non-WebSocket transports (WMP) have no close frame to carry a
	// reason; closing the transport is sufficient to end the session.
	_ = t.Close()
}

// Drain stops the manager accepting new connections and sessions: further
// WebSocket upgrades get 503 and any in-flight handshake is refused at
// registration. Existing sessions are left running; Close ends them. It is
// idempotent.
func (m *Manager) Drain() {
	m.sessionsMu.Lock()
	m.draining = true
	m.sessionsMu.Unlock()
}

func (m *Manager) isDraining() bool {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	return m.draining
}

// Close drains the manager, then closes all sessions.
func (m *Manager) Close() {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	m.draining = true

	for _, session := range m.sessions {
		_ = session.currentTransport().Close()
	}
	m.sessions = make(map[string]*Session)
	m.userIndex = make(map[userKey]*Session)

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
//
// The read lock is held for the whole send, not just the pointer copy: a
// concurrent WMP session resume swaps (and closes) the transport under the
// write lock, so it waits for in-flight sends instead of closing the old
// transport between the copy and SendJSON and losing the notification.
func (s *Session) Send(msg interface{}) error {
	s.transportMu.RLock()
	defer s.transportMu.RUnlock()
	return s.transport.SendJSON(msg)
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
	return s.sendFlowComplete(flowID, credentials, redirectURI, "", "", "")
}

// SendFlowCompleteWithRefreshToken is SendFlowComplete plus an OID4VCI
// refresh_token (and the DPoP key it's bound to) to relay to the client -
// see FlowCompleteMessage.RefreshToken/DPoPJWK.
func (s *Session) SendFlowCompleteWithRefreshToken(flowID string, credentials []CredentialResult, redirectURI string, refreshToken string, dpopJWK string, dpopKeyID string) error {
	return s.sendFlowComplete(flowID, credentials, redirectURI, refreshToken, dpopJWK, dpopKeyID)
}

func (s *Session) sendFlowComplete(flowID string, credentials []CredentialResult, redirectURI string, refreshToken string, dpopJWK string, dpopKeyID string) error {
	s.flowsMu.RLock()
	flow := s.flows[flowID]
	s.flowsMu.RUnlock()

	msg := FlowCompleteMessage{
		Message: Message{
			Type:      TypeFlowComplete,
			FlowID:    flowID,
			Timestamp: Now(),
		},
		Credentials:  credentials,
		RedirectURI:  redirectURI,
		RefreshToken: refreshToken,
		DPoPJWK:      dpopJWK,
		DPoPKeyID:    dpopKeyID,
	}
	if flow != nil {
		flow.mu.RLock()
		if v, ok := flow.Data["credential_issuer"]; ok {
			msg.CredentialIssuer, _ = v.(string)
		}
		if v, ok := flow.Data["selected_credential_configuration_id"]; ok {
			msg.SelectedCredentialConfigurationID, _ = v.(string)
		}
		flow.mu.RUnlock()
	}
	return s.Send(&msg)
}

// SendFlowError sends a flow error message. An optional details map (e.g. a
// redirect_uri returned by a verifier's error-response endpoint per OID4VP
// §8.2/§8.5) can be passed as a trailing argument without touching the many
// existing 4-arg call sites.
func (s *Session) SendFlowError(flowID string, step FlowStep, code ErrorCode, message string, details ...map[string]interface{}) error {
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
	if len(details) > 0 {
		msg.Error.Details = details[0]
	}
	return s.Send(&msg)
}

// SendNotificationAck sends an acknowledgement for a credential_notification.
func (s *Session) SendNotificationAck(flowID, notificationID, status, errMsg string) error {
	msg := NotificationAckMessage{
		Message: Message{
			Type:      TypeNotificationAck,
			FlowID:    flowID,
			Timestamp: Now(),
		},
		NotificationID: notificationID,
		Status:         status,
		Error:          errMsg,
	}
	return s.Send(&msg)
}

// dispatchCredentialNotification validates a client-reported OID4VCI §10
// credential lifecycle event synchronously, then forwards it to the issuer on a
// bounded background worker. Validation (missing notification_id, unsupported
// event, absent/expired context, or a notification_id that does not match the
// one issued for the flow) is performed inline so that malformed or
// unauthorized requests are rejected immediately and never consume a worker
// slot. Only well-formed, authorized requests enter the async forwarding path,
// which is capped by m.notificationSem to provide backpressure.
//
// The notification_id is validated against the value the issuer returned at
// issuance (OID4VCI §8.3/§11 define exactly one notification_id per Credential
// Response). This prevents a client from using the still-valid issuance token
// to post an arbitrary notification_id to the issuer.
func (m *Manager) dispatchCredentialNotification(session *Session, msg *CredentialNotificationMessage) {
	logger := session.logger.With(zap.String("flow_id", msg.FlowID), zap.String("event", msg.Event))

	if msg.NotificationID == "" {
		_ = session.SendNotificationAck(msg.FlowID, "", "rejected", "missing notification_id")
		return
	}
	if !isValidNotificationEvent(msg.Event) {
		// credential_deleted and any other event are not forwardable.
		_ = session.SendNotificationAck(msg.FlowID, msg.NotificationID, "rejected", "unsupported event")
		return
	}
	// Reject (without consuming) when there is no live context for the flow or
	// the supplied notification_id does not match the issued one. This keeps
	// invalid requests out of the bounded async path.
	if !session.notifications.hasValid(msg.FlowID, msg.NotificationID) {
		logger.Debug("no matching notification context for flow (absent, expired, or id mismatch)")
		_ = session.SendNotificationAck(msg.FlowID, msg.NotificationID, "rejected", "notification context unavailable")
		return
	}

	// Acquire a worker slot without blocking the session read loop. If the
	// backend is already forwarding the maximum number of notifications, shed
	// load by rejecting; the client may retry (§10 notifications are idempotent
	// and best-effort).
	select {
	case m.notificationSem <- struct{}{}:
	default:
		logger.Warn("notification forwarding at capacity, rejecting")
		_ = session.SendNotificationAck(msg.FlowID, msg.NotificationID, "rejected", "server busy, please retry")
		return
	}

	go func() {
		defer func() { <-m.notificationSem }()
		m.forwardCredentialNotification(session, msg, logger)
	}()
}

// forwardCredentialNotification consumes the ephemeral issuance context and
// performs the authenticated POST to the issuer's notification endpoint. It is
// invoked only after dispatchCredentialNotification has validated the request.
// No credential data is stored or looked up; the backend remains zero-knowledge
// about credential contents.
func (m *Manager) forwardCredentialNotification(session *Session, msg *CredentialNotificationMessage, logger *zap.Logger) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in credential notification handler", zap.Any("panic", r))
		}
	}()

	nc := session.notifications.take(msg.FlowID)
	if nc == nil {
		// Raced with TTL expiry or another in-flight notification for the same
		// flow consumed the one-shot context.
		logger.Debug("notification context no longer available at forward time")
		_ = session.SendNotificationAck(msg.FlowID, msg.NotificationID, "rejected", "notification context unavailable")
		return
	}
	// Defence in depth: re-check the id match after consuming, in case the
	// stored context changed between the inline check and here.
	if nc.notificationID != "" && nc.notificationID != msg.NotificationID {
		logger.Warn("notification_id mismatch at forward time")
		_ = session.SendNotificationAck(msg.FlowID, msg.NotificationID, "rejected", "notification_id mismatch")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	httpClient := m.cfg.HTTPClient.NewHTTPClient(0)
	if err := sendNotification(ctx, httpClient, nc, msg.NotificationID, msg.Event, msg.EventDescription, logger); err != nil {
		logger.Warn("failed to forward credential notification to issuer", zap.Error(err))
		_ = session.SendNotificationAck(msg.FlowID, msg.NotificationID, "rejected", "forwarding failed")
		return
	}

	logger.Debug("credential notification forwarded to issuer")
	_ = session.SendNotificationAck(msg.FlowID, msg.NotificationID, "forwarded", "")
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
	timer := time.NewTimer(3 * time.Minute)
	defer timer.Stop()
	for {
		wake := s.stash.waitChan()
		if resp := s.stash.takeSign(messageID); resp != nil {
			return signResult(resp)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, ErrSignTimeout
		case <-s.closeCh:
			return nil, errors.New("session closed")
		case <-wake:
		case resp := <-s.signCh:
			if resp.MessageID == messageID {
				return signResult(resp)
			}
			// Another request's response: park it for its waiter.
			s.stash.putSign(resp)
		}
	}
}

// signResult turns a client-reported sign failure into an error.
func signResult(resp *SignResponseMessage) (*SignResponseMessage, error) {
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return resp, nil
}

// MatchTimeout is the timeout for credential matching requests.
// This is generous to allow client-side matching across many credentials.
const MatchTimeout = 30 * time.Second

// ErrMatchTimeout is returned when credential matching times out
var ErrMatchTimeout = errors.New("credential matching timed out")

// RequestMatch sends a credential matching request and waits for response.
// This is the privacy-preserving credential matching protocol where the client
// matches credentials locally against the DCQL query.
func (s *Session) RequestMatch(ctx context.Context, flowID string, dcql json.RawMessage) (*MatchResponseMessage, error) {
	messageID := uuid.New().String()

	msg := MatchRequestMessage{
		Message: Message{
			Type:      TypeMatchRequest,
			FlowID:    flowID,
			MessageID: messageID,
			Timestamp: Now(),
		},
		DCQLQuery: dcql,
	}

	if err := s.Send(&msg); err != nil {
		return nil, err
	}

	// Wait for response with proper timer cleanup
	timer := time.NewTimer(MatchTimeout)
	defer timer.Stop()

	for {
		wake := s.stash.waitChan()
		resp := s.stash.takeMatch(flowID, messageID)
		if resp == nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-timer.C:
				return nil, ErrMatchTimeout
			case <-s.closeCh:
				return nil, errors.New("session closed")
			case <-wake:
				continue
			case r := <-s.matchCh:
				// Verify both flow_id and message_id for proper correlation
				if r.FlowID != flowID || r.MessageID != messageID {
					// Another request's response: park it for its waiter.
					s.stash.putMatch(r)
					continue
				}
				resp = r
			}
		}
		// Check for error in response
		if resp.Error != "" {
			return nil, errors.New(resp.Error)
		}
		return resp, nil
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
		wake := s.stash.waitChan()
		if action := s.stash.takeAction(flowID, expectedActions); action != nil {
			return action, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, ErrFlowTimeout
		case <-s.closeCh:
			return nil, errors.New("session closed")
		case <-wake:
		case action := <-s.actionCh:
			if action.FlowID != flowID {
				// Another concurrent flow's action: park it for that flow's
				// waiter instead of discarding it.
				s.stashAction(action)
				continue
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

// Bounds for parked responses, so a misbehaving client cannot grow a
// session's memory without limit.
const (
	maxStashedActionsPerFlow = 50
	// maxStashedActionsPerSession bounds parked actions across ALL flows of
	// a session, so many flows cannot each fill their per-flow allowance.
	maxStashedActionsPerSession = 200
	maxStashedResponses         = 64
)

// responseStash holds client responses read off the session's shared
// channels by a waiter they were not meant for. Each waiter drains its own
// entries first (takeAction/takeSign/takeMatch), so concurrent flows on one
// session behave as if each had a private queue. The zero value is ready.
type responseStash struct {
	mu      sync.Mutex
	actions map[string][]*FlowActionMessage // by flow ID
	signs   map[string]*SignResponseMessage // by message ID
	matches map[string]*MatchResponseMessage
	wake    chan struct{}
}

// waitChan returns a channel closed on the next put. Callers must obtain it
// BEFORE checking the stash so a put in between is never missed.
func (r *responseStash) waitChan() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.wake == nil {
		r.wake = make(chan struct{})
	}
	return r.wake
}

// broadcastLocked wakes every waiter. Callers must hold r.mu.
func (r *responseStash) broadcastLocked() {
	if r.wake != nil {
		close(r.wake)
	}
	r.wake = make(chan struct{})
}

// stashAction parks an action for another flow, unless that flow no longer
// exists (nothing would ever consume it).
func (s *Session) stashAction(a *FlowActionMessage) {
	// The read lock is held through the insertion: removeFlow takes the write
	// lock before dropFlow cleans the stash, so a removal either happens
	// before this check (nothing is stashed) or waits for the insertion and
	// its dropFlow then clears the entry. Lock order is flowsMu -> stash.mu.
	s.flowsMu.RLock()
	defer s.flowsMu.RUnlock()
	if _, ok := s.flows[a.FlowID]; !ok {
		return
	}
	r := &s.stash
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.actions == nil {
		r.actions = make(map[string][]*FlowActionMessage)
	}
	if len(r.actions[a.FlowID]) >= maxStashedActionsPerFlow || r.totalActionsLocked() >= maxStashedActionsPerSession {
		return
	}
	r.actions[a.FlowID] = append(r.actions[a.FlowID], a)
	r.broadcastLocked()
}

func (r *responseStash) totalActionsLocked() int {
	n := 0
	for _, q := range r.actions {
		n += len(q)
	}
	return n
}

// dropFlow discards everything parked for flowID - queued actions and the
// sign/match responses addressed to it; called on flow teardown so a finished
// flow's leftovers cannot linger for the life of the session (and, for the
// bounded sign/match maps, eventually fill them).
func (r *responseStash) dropFlow(flowID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.actions, flowID)
	for id, m := range r.signs {
		if m.FlowID == flowID {
			delete(r.signs, id)
		}
	}
	for id, m := range r.matches {
		if m.FlowID == flowID {
			delete(r.matches, id)
		}
	}
}

// removeFlow unregisters flow (if flowID still maps to it) and clears what
// was parked for it: actions and sign/match responses. The cleanup only runs
// when this flow instance is the registered one, so a stale flow's teardown
// cannot purge the entries of a replacement that reuses the same ID.
func (s *Session) removeFlow(flowID string, flow *Flow) {
	// flowsMu stays held through dropFlow: a replacement flow reusing flowID
	// registers under the same lock, so its stashed actions cannot be deleted
	// by this (stale) flow's cleanup. Lock order is flowsMu -> stash.mu.
	s.flowsMu.Lock()
	defer s.flowsMu.Unlock()
	if s.flows[flowID] == flow {
		delete(s.flows, flowID)
		s.stash.dropFlow(flowID)
	}
}

// takeAction removes and returns the oldest parked action for flowID that is
// one of expected (any, if expected is empty). Parked actions for the flow
// that are not expected are dropped, as WaitForAction always did.
func (r *responseStash) takeAction(flowID string, expected []string) *FlowActionMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	q := r.actions[flowID]
	for i, a := range q {
		ok := len(expected) == 0
		for _, e := range expected {
			if a.Action == e {
				ok = true
				break
			}
		}
		if ok {
			rest := q[i+1:]
			if len(rest) == 0 {
				delete(r.actions, flowID)
			} else {
				r.actions[flowID] = rest
			}
			return a
		}
	}
	delete(r.actions, flowID)
	return nil
}

func (r *responseStash) putSign(m *SignResponseMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.signs == nil {
		r.signs = make(map[string]*SignResponseMessage)
	}
	if len(r.signs) >= maxStashedResponses {
		return
	}
	r.signs[m.MessageID] = m
	r.broadcastLocked()
}

func (r *responseStash) takeSign(messageID string) *SignResponseMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.signs[messageID]
	delete(r.signs, messageID)
	return m
}

func (r *responseStash) putMatch(m *MatchResponseMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.matches == nil {
		r.matches = make(map[string]*MatchResponseMessage)
	}
	if len(r.matches) >= maxStashedResponses {
		return
	}
	r.matches[m.MessageID] = m
	r.broadcastLocked()
}

func (r *responseStash) takeMatch(flowID, messageID string) *MatchResponseMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.matches[messageID]
	if m == nil || m.FlowID != flowID {
		return nil
	}
	delete(r.matches, messageID)
	return m
}
