package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	ws "github.com/sirosfoundation/go-wallet-backend/internal/websocket"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audience"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/legacytoken"
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

	// IsFamilyRevoked reports whether sid - a refresh-token family/session
	// id (see service.WebAuthnService.generateToken's doc comment) - has
	// been revoked via RevokeFamily (what api.Handlers.Logout calls). Added
	// for #402/#414 (Copilot review): without this, an access token from an
	// earlier rotation of a since-logged-out session - its own jti never
	// individually blacklisted - could still authenticate a NEW WebSocket
	// handshake to this engine even after the HTTP paths (pkg/middleware.
	// AuthMiddlewareWithBlacklist/TokenAuthMiddleware) already reject it.
	IsFamilyRevoked(ctx context.Context, sid string) bool
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

// Session represents an authenticated WebSocket session
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
	// tokenIssuedAt is the handshake token's iat, for the SID-AUTH-06
	// re-check on every flow start (Manager.recheckToken).
	tokenIssuedAt time.Time
	conn          *websocket.Conn
	sendMu        sync.Mutex
	flows         map[string]*Flow
	flowsMu       sync.RWMutex
	logger        *zap.Logger

	// Channels for flow coordination
	actionCh chan *FlowActionMessage
	signCh   chan *SignResponseMessage
	matchCh  chan *MatchResponseMessage
	closeCh  chan struct{}

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

	// cancel stops the flow's own context, and is set before the flow is
	// published on the session. Cancelling through the handler alone is not
	// enough: a handler is built after the flow becomes visible, and each
	// handler installs its own cancel at the top of Execute, so a revocation
	// arriving in that window would find nothing to cancel and the flow
	// would run on regardless. The context exists from the moment anyone
	// can see the flow, so cancelling it always lands.
	cancel context.CancelFunc

	// Flow-specific data
	Data map[string]interface{}
	mu   sync.RWMutex
}

// Cancel stops the flow: its own context first, which always exists, then
// the handler if one has been built yet. Safe to call more than once, and
// safe to call on a flow whose handler is still being constructed.
func (f *Flow) Cancel() {
	f.mu.Lock()
	cancel, handler := f.cancel, f.Handler
	f.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if handler != nil {
		handler.Cancel()
	}
}

// setHandler publishes the handler under the flow's own lock, so a concurrent
// Cancel either sees it or does not, rather than racing the assignment.
func (f *Flow) setHandler(h FlowHandler) {
	f.mu.Lock()
	f.Handler = h
	f.mu.Unlock()
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
	trustCache     *TrustCache

	// notificationSem bounds the number of concurrent OID4VCI §10 notification
	// forwards across all sessions, providing backpressure against a client
	// flooding credential_notification messages.
	notificationSem chan struct{}

	// Persistent session store (optional, for horizontal scaling)
	sessionStore SessionStore

	// tokenGate refuses tokens issued before the user's SID-AUTH-06
	// authorization cut-off (optional; see internal/tokengate).
	tokenGate *tokengate.Gate

	// beforeRegister, when non-nil, runs after the handshake token has been
	// validated and the session built, but before registerSession. Tests use
	// it to land a cut-off in exactly that window.
	beforeRegister func()

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
		userIndex:       make(map[string]*Session),
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

// SetRegistryHandler makes VCTM lookups call a registry served in this process
// (handler serves the registry routes under /registry) instead of going over
// the network.
func (m *Manager) SetRegistryHandler(h http.Handler) {
	m.registryClient.SetHandler(h)
}

// SetTokenValidator sets the go-tokenauth validator for WebSocket handshake auth.
func (m *Manager) SetTokenValidator(v *tokenvalidator.Validator) {
	m.tokenValidator = v
}

// SetTokenGate wires the SID-AUTH-06 token cut-off check into handshake
// authentication: a token issued before the user's wallet was revoked cannot
// open a new engine session. The same check runs again at every flow start,
// because a socket held by another engine process survives the cascade's
// DeleteByUser and an issuance or a presentation is exactly what a revoked
// wallet must not perform.
func (m *Manager) SetTokenGate(g *tokengate.Gate) {
	m.tokenGate = g
}

// recheckToken re-applies the token cut-off to an established session (see
// handleFlowStart). No gate configured means no cut-off enforcement, as at
// the handshake.
func (m *Manager) recheckToken(session *Session) error {
	return m.tokenGate.Check(context.Background(), session.UserID, session.tokenIssuedAt)
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
	defer func() { _ = conn.Close() }()

	// Handshake-scoped context: the upgrade request's own context is
	// cancelled as soon as ServeHTTP returns (this runs in a goroutine after
	// the connection was hijacked), so bound the handshake explicitly with
	// the same 30s budget as the read deadline below.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
	userID, tenantID, tac, err := m.validateToken(ctx, handshake.AppToken)
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
		logLabel = userID[:8]
	}
	session := &Session{
		ID:            sessionID,
		UserID:        userID,
		TenantID:      tenantID,
		TAC:           tac,
		tokenIssuedAt: tokengate.IssuedAt(handshake.AppToken),
		conn:          conn,
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

	if m.beforeRegister != nil {
		m.beforeRegister()
	}

	// Register session. A rejection here means the user was revoked in the
	// narrow window between validateToken's own check above and this call -
	// registerSession has already closed the connection itself in that
	// case, so there is nothing left to unregister.
	if !m.registerSession(session) {
		session.logger.Warn("Handshake rejected: user revoked between token validation and session registration")
		return
	}
	defer m.unregisterSession(session)

	// SID-AUTH-06: a cut-off that landed between validateToken and the
	// registration above would have been missed by DeleteByUser (nothing to
	// close yet). Re-check now that the session is visible.
	if err := m.recheckToken(session); err != nil {
		m.logger.Warn("Session refused after registration", zap.Error(err))
		m.sendError(conn, "", ErrCodeAuthFailed, "Authorization revoked")
		// Fail closed: drop the socket right away with a policy-violation
		// close frame rather than waiting for the deferred teardown.
		session.closeWithReason("authorization revoked")
		return
	}

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
	ticker := time.NewTicker(s.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.sendMu.Lock()
			err := s.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(s.pongTimeout))
			s.sendMu.Unlock()
			if err != nil {
				return // connection is dead; ReadMessage will surface the error
			}
		case <-s.stopPing:
			return
		}
	}
}

func (m *Manager) handleSession(session *Session) {
	defer func() {
		close(session.stopPing) // stop the ping goroutine
		close(session.closeCh)
		// Cancel all active flows
		session.flowsMu.Lock()
		for _, flow := range session.flows {
			flow.Cancel()
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

// anonymousProtocols are the flow protocols a session with no user (a token the
// AS issued without "sub") may run: lookups of public metadata. Everything else
// acts for a wallet (receives or presents credentials) and needs an identity,
// so an anonymous session is refused for it at flow start.
var anonymousProtocols = map[Protocol]bool{
	ProtocolVCTM: true,
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

	// SID-AUTH-06: an established session keeps running until a flow starts;
	// re-check the handshake token against the user's cut-off here so a
	// revocation that DeleteByUser could not reach - another engine process
	// or instance in a split or scaled deployment - still stops the wallet
	// at its next flow. The gate reads the shared store.
	//
	// After the logger above, not before it: this is the one refusal on this
	// path that a reader will go looking for, and it is worth a lot more
	// with the flow id and protocol attached.
	if err := m.recheckToken(session); err != nil {
		logger.Warn("Flow refused: authorization revoked", zap.Error(err))
		_ = session.SendFlowError(flowID, "", ErrCodeAuthFailed, "Authorization revoked")
		_ = session.conn.Close()
		return
	}

	// An anonymous token is for registry/metadata lookups only: it may not
	// start a flow that acts for a wallet. The handshake itself stays open to
	// it, since a lookup flow needs the connection.
	if session.UserID == "" && !anonymousProtocols[msg.Protocol] {
		logger.Warn("Flow refused: anonymous session")
		_ = session.SendFlowError(flowID, "", ErrCodeForbidden, "anonymous tokens are not accepted for protocol: "+string(msg.Protocol))
		return
	}

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
	if session.TAC != "" {
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
	pendingFlows := len(session.flows)
	if pendingFlows >= MaxPendingFlowsPerSession {
		session.flowsMu.Unlock()
		_ = session.SendFlowError(flowID, "", ErrCodeTooManyRequests, "Too many pending flows. Complete or cancel existing flows before starting new ones.")
		logger.Warn("Rejected flow start - too many pending flows",
			zap.Int("pending_flows", pendingFlows),
			zap.Int("limit", MaxPendingFlowsPerSession))
		return
	}

	// The flow's context is created before the flow is published, so a
	// revocation that arrives while the handler is still being built has
	// something to cancel.
	flowCtx, cancelFlow := context.WithTimeout(context.Background(), 5*time.Minute)

	// Create flow while still holding lock
	flow := &Flow{
		ID:        flowID,
		Protocol:  msg.Protocol,
		Session:   session,
		State:     FlowStep("started"),
		StartTime: time.Now(),
		cancel:    cancelFlow,
		Data:      make(map[string]interface{}),
	}

	// Register flow immediately to reserve slot
	session.flows[flowID] = flow
	session.flowsMu.Unlock()
	defer cancelFlow()

	// Create handler (after releasing lock to avoid holding it during potentially slow operations)
	handler, err := factory(flow, m.cfg, logger, m.trustService, m.registryClient, m.verifierStore, m.trustCache)
	if err != nil {
		// Remove the reserved flow slot on error
		session.flowsMu.Lock()
		delete(session.flows, flowID)
		session.flowsMu.Unlock()
		_ = session.SendFlowError(flowID, "", ErrCodeInternalError, "Failed to create flow handler")
		logger.Error("Failed to create handler", zap.Error(err))
		return
	}
	flow.setHandler(handler)

	defer func() {
		session.flowsMu.Lock()
		delete(session.flows, flowID)
		session.flowsMu.Unlock()
	}()

	// A revocation between publishing the flow and here has already
	// cancelled flowCtx, so do not start the work.
	if err := flowCtx.Err(); err != nil {
		logger.Info("Flow cancelled before it started", zap.Error(err))
		return
	}

	logger.Info("Starting flow")
	if err := handler.Execute(flowCtx, msg); err != nil {
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

	if session.UserID != "" {
		revoked := m.isUserRevoked(session.UserID)
		if !revoked && m.blacklist != nil {
			revoked = m.blacklist.IsUserRevoked(context.Background(), session.UserID)
		}
		if revoked {
			m.sessionsMu.Unlock()
			session.closeWithReason("account deleted")
			return false
		}
	}
	defer m.sessionsMu.Unlock()

	// Close existing session for this user (skip for anonymous sessions)
	if session.UserID != "" {
		if existing, ok := m.userIndex[session.UserID]; ok {
			m.logger.Debug("Closing existing session", zap.String("user_id", session.UserID))
			_ = existing.conn.Close()
			delete(m.sessions, existing.ID)
			// Also remove from persistent store
			if m.sessionStore != nil {
				_ = m.sessionStore.DeleteByUser(context.Background(), session.UserID)
			}
		}
	}

	m.sessions[session.ID] = session
	if session.UserID != "" {
		m.userIndex[session.UserID] = session
	}

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
	return true
}

func (m *Manager) unregisterSession(session *Session) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	delete(m.sessions, session.ID)
	if session.UserID != "" {
		if current, ok := m.userIndex[session.UserID]; ok && current == session {
			delete(m.userIndex, session.UserID)
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

// engineAdmitsLegacyTokens is whether the engine transport accepts ModeLegacy
// (HMAC login) tokens without an audience match. True today, as for every
// other guarded route group; see audience.Allowed.
const engineAdmitsLegacyTokens = true

// validateToken authenticates tokenString and returns its identity.
// tac is only ever populated on the go-tokenauth path - the legacy HMAC
// path (below) has no TAC concept at all, so callers must treat an empty
// tac as "not applicable here", not "no permissions", exactly like
// requireTACIfEnforced does for HTTP routes (see internal/server/providers.go).
//
// ctx is the handshake-scoped context and is passed to every validator and
// revocation lookup. If it is already done, validation fails closed (a
// revocation check that could not be run to completion must never read as
// "not revoked").
func (m *Manager) validateToken(ctx context.Context, tokenString string) (userID, tenantID string, tac claims.TAC, err error) {
	if err := ctx.Err(); err != nil {
		return "", "", "", fmt.Errorf("token validation aborted: %w", err)
	}
	// Use go-tokenauth validator when available (supports both new-style and legacy tokens)
	if m.tokenValidator != nil {
		result, err := m.tokenValidator.Validate(ctx, tokenString)
		if err != nil {
			return "", "", "", err
		}
		// The engine transport, like the AuthZEN proxy, only needs a
		// wallet-registry or wallet-backend audience - never a broader one.
		//
		// Legacy (HMAC) tokens are exempt, exactly like
		// middleware.RequireAudience (see audience.Allowed for why:
		// they carry aud=Server.RPID, already validated against
		// AS.Audiences). The exemption is an explicit opt-in constant, not an
		// implicit special case: if the engine transport is ever restricted
		// to a narrower audience that ordinary login tokens must not reach,
		// flip engineAdmitsLegacyTokens to false. Session-mode tokens always
		// keep the strict check.
		if !audience.Allowed(result, engineAdmitsLegacyTokens, "wallet-registry", "wallet-backend") {
			return "", "", "", errors.New("token audience not permitted for engine transport")
		}
		// Per-jti revocation is already enforced inside Validate itself (the
		// shared Validator's own Revocation checker - see
		// internal/server.blacklistRevocationChecker); user-level revocation
		// is not, since that checker's interface only ever sees a jti (see
		// #391 review, round 2). Checked against both the optional
		// TokenBlacklist feature and the engine's own always-on
		// revokedUsers (#403) - either one saying revoked is enough to
		// reject.
		if (m.blacklist != nil && m.blacklist.IsUserRevoked(ctx, result.UserID)) || m.isUserRevoked(result.UserID) {
			return "", "", "", errors.New("token has been revoked")
		}
		// Refresh-token family revocation (#402/#414), legacy-mode tokens
		// only: go-tokenauth "auto-detects new-style vs legacy" tokens, so a
		// WebAuthnService-issued legacy HMAC token can reach this branch
		// too whenever the AS is enabled. go-tokenauth's shared
		// *claims.Result has no "sid" field at all (it's shared with
		// AS-issued tokens, which have no family concept in this codebase),
		// so this reuses legacytoken.SID to re-parse the same
		// already-validated raw token independently and reach that one
		// extra claim - the same helper TokenAuthMiddleware itself uses,
		// for the identical reason. New-style AS-issued tokens (ModeSession)
		// are skipped entirely.
		if m.blacklist != nil && result.Mode == claims.ModeLegacy {
			// Fail closed if the family cannot be determined.
			sid, sidErr := legacytoken.ParseSID(m.cfg.JWT.Secret, tokenString)
			if sidErr != nil {
				return "", "", "", errors.New("cannot determine token family")
			}
			// Re-check ctx right before the lookup: fail closed rather than
			// treat an abandoned handshake's lookup as "not revoked".
			if err := ctx.Err(); err != nil {
				return "", "", "", fmt.Errorf("family revocation check aborted: %w", err)
			}
			if sid != "" && m.blacklist.IsFamilyRevoked(ctx, sid) {
				return "", "", "", errors.New("token has been revoked")
			}
		}
		// UserID may be empty for anonymous tokens — that is acceptable.
		// See SetTokenGate for why the engine checks at all.
		if err := m.tokenGate.Check(ctx, result.UserID, tokengate.IssuedAt(tokenString)); err != nil {
			return "", "", "", err
		}
		return result.UserID, result.TenantID, result.TAC, nil
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
		return "", "", "", err
	}

	if mapClaims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Support both "user_id" (go-wallet-backend native) and "uuid" (wallet-backend-server compat)
		userID, _ = mapClaims["user_id"].(string)
		if userID == "" {
			userID, _ = mapClaims["uuid"].(string)
		}
		tenantID, _ = mapClaims["tenant_id"].(string)
		if userID == "" {
			return "", "", "", errors.New("invalid token claims: missing user_id or uuid")
		}
		if m.blacklist != nil {
			if jti, _ := mapClaims["jti"].(string); jti != "" && m.blacklist.IsBlacklisted(ctx, jti) {
				return "", "", "", errors.New("token has been revoked")
			}
			if m.blacklist.IsUserRevoked(ctx, userID) {
				return "", "", "", errors.New("token has been revoked")
			}
			// Refresh-token family revocation (#402/#414) - see the
			// go-tokenauth branch above's identical check for why.
			if sid, _ := mapClaims["sid"].(string); sid != "" && m.blacklist.IsFamilyRevoked(ctx, sid) {
				return "", "", "", errors.New("token has been revoked")
			}
		}
		// Checked unconditionally (unlike the m.blacklist block above,
		// which is skipped entirely when no blacklist is wired): the
		// engine's own revokedUsers works regardless of whether that
		// optional feature is configured at all (#403).
		if m.isUserRevoked(userID) {
			return "", "", "", errors.New("token has been revoked")
		}
		// See SetTokenGate for why the engine checks at all.
		if err := m.tokenGate.Check(ctx, userID, tokengate.IssuedAtFromClaims(mapClaims)); err != nil {
			return "", "", "", err
		}
		return userID, tenantID, "", nil
	}

	return "", "", "", errors.New("invalid token")
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

// DeleteByUser drops the user's live WebSocket session as well as its
// persisted record. It is the engine's service.SessionCleaner: SessionStore
// alone only forgets the SessionData, while the Manager keeps the
// authenticated Session and its socket in sessions/userIndex and would let an
// already-connected client continue flows after its wallet instance was
// revoked (SID-AUTH-06). Closing the connection ends the read
// loop, which unregisters the session; the maps are cleared here as well so
// the user is gone from the Manager the moment this returns.
func (m *Manager) DeleteByUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	// The persisted delete runs under the same lock as the in-memory one.
	// Releasing it first left a window in which a session registering for
	// this user wrote its record and then had it deleted by this call,
	// leaving a live socket with nothing in the store and nothing to restore
	// after a restart. registerSession already holds this lock across its
	// own store writes, so serializing here costs no more than it does
	// there and makes the two operations agree on an order.
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	if live, ok := m.userIndex[userID]; ok {
		m.logger.Info("Closing live session for user", zap.String("user_id", userID))
		// Cancel the flows here rather than leaving it to handleSession's
		// deferred cleanup. That cleanup does run, but only once the read
		// loop notices the closed connection, so this call would otherwise
		// return while an issuance or presentation started before the
		// revocation was still working. Each flow runs on its own context,
		// not the connection's, so closing the socket does not reach it.
		live.flowsMu.Lock()
		for _, flow := range live.flows {
			flow.Cancel()
		}
		live.flowsMu.Unlock()
		_ = live.conn.Close()
		delete(m.sessions, live.ID)
		delete(m.userIndex, userID)
	}
	if m.sessionStore == nil {
		return nil
	}
	return m.sessionStore.DeleteByUser(ctx, userID)
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

// (Manager.DeleteByUser, above, is the engine's service.SessionCleaner: it
// drops the user's sessions but does NOT bar the user from reconnecting,
// because wallet-instance revocation and "log out everywhere" (SID-AUTH-06)
// use the same cleaner and the user's other devices must stay able to log
// in. Permanent, account-deletion-grade revocation is the separate
// RevokeUser below, wired only into UserService.DeleteUser via
// service.UserRevoker - see cmd/server/main.go. On main these two were one
// method; they diverged when the lifecycle cascade needed the non-permanent
// behaviour.)
//
// Sessions live on other backend replicas (Redis-backed horizontal
// scaling) are out of scope for RevokeUser: only this process's own live
// connections can be closed directly (#393).
//
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
// in userIndex ("last connection wins" - see registerSession). Matching is
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
// Deliberately does NOT take s.sendMu: per gorilla/websocket's own
// concurrency contract, WriteControl (unlike WriteJSON/WriteMessage, which
// s.Send serializes via sendMu) may be called concurrently with any other
// write. Taking sendMu here would let a backpressured client - whose peer
// never reads, and whose write deadline was cleared after upgrade, see
// handleNewConnection - block this call, and therefore account deletion,
// indefinitely on an in-flight s.Send. WriteControl's own deadline bounds
// this call regardless of whether it succeeds, and Close is unconditional.
func (s *Session) closeWithReason(reason string) {
	_ = s.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.ClosePolicyViolation, reason),
		time.Now().Add(time.Second),
	)
	_ = s.conn.Close()
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
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
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
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, ErrMatchTimeout
		case <-s.closeCh:
			return nil, errors.New("session closed")
		case resp := <-s.matchCh:
			// Verify both flow_id and message_id for proper correlation
			if resp.FlowID == flowID && resp.MessageID == messageID {
				// Check for error in response
				if resp.Error != "" {
					return nil, errors.New(resp.Error)
				}
				return resp, nil
			}
			// Wrong flow_id or message_id, keep waiting
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
