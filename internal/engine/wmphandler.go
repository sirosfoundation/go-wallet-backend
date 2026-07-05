package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"go.uber.org/zap"
)

// specToEngineAction maps WMP spec action names to engine-internal action names.
// The WMP specification (wmp-openid4x) defines canonical action names for
// OpenID4VCI/VP flows. The engine uses its own action vocabulary internally.
// This map ensures WMP clients can use spec-compliant action names.
var specToEngineAction = map[string]string{
	openid4x.ActionAcceptOffer:       ActionConsent,
	openid4x.ActionProvideTxCode:     ActionProvidePin,
	openid4x.ActionAuthorize:         ActionAuthorizationComplete,
	openid4x.ActionSelectCredentials: ActionConsent,
	openid4x.ActionCancel:            ActionDecline,
}

// WMPAdapter wraps the engine Manager and exposes it as WMP JSON-RPC.
// It manages one wmp.Peer per engine Session, each backed by a
// ChannelTransport whose outbound channel feeds the SSE event stream.
type WMPAdapter struct {
	manager *Manager
	logger  *zap.Logger

	mu               sync.RWMutex
	peers            map[string]*wmpSession      // keyed by WMP session ID
	resumptionTokens map[string]*resumptionEntry // token -> entry with session ID and expiry

	stopCh   chan struct{}
	stopOnce sync.Once
}

// resumptionEntry holds a resumption token's session binding and expiry.
type resumptionEntry struct {
	sessionID string
	expiresAt time.Time
}

// wmpSessionIdleTimeout is the maximum time a WMP session can be idle
// (no RPC activity) before being automatically closed.
const wmpSessionIdleTimeout = 10 * time.Minute

// resumptionTokenTTL is the lifetime of a resumption token. After this
// duration the token is invalid and the client must create a new session.
const resumptionTokenTTL = 10 * time.Minute

// maxFlowIDLength limits client-supplied flow IDs to prevent memory abuse.
const maxFlowIDLength = 128

// wmpSession associates a wmp.Peer with its channel transport and engine session.
type wmpSession struct {
	peer         *wmp.Peer
	transport    *wmp.ChannelTransport
	session      *Session
	cancel       context.CancelFunc
	lastActivity time.Time
}

// NewWMPAdapter creates an adapter that bridges WMP JSON-RPC to the engine.
func NewWMPAdapter(manager *Manager, logger *zap.Logger) *WMPAdapter {
	a := &WMPAdapter{
		manager:          manager,
		logger:           logger.Named("wmp"),
		peers:            make(map[string]*wmpSession),
		resumptionTokens: make(map[string]*resumptionEntry),
		stopCh:           make(chan struct{}),
	}
	go a.cleanupLoop()
	return a
}

// Close stops the cleanup loop.
func (a *WMPAdapter) Close() {
	a.stopOnce.Do(func() { close(a.stopCh) })
}

// cleanupLoop periodically removes expired resumption tokens and idle sessions.
func (a *WMPAdapter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.cleanupExpired()
		case <-a.stopCh:
			return
		}
	}
}

// cleanupExpired removes expired resumption tokens and closes idle sessions.
func (a *WMPAdapter) cleanupExpired() {
	now := time.Now()

	a.mu.Lock()
	// Remove expired resumption tokens.
	for token, entry := range a.resumptionTokens {
		if now.After(entry.expiresAt) {
			delete(a.resumptionTokens, token)
		}
	}

	// Collect idle sessions to close (avoid calling CloseSession under lock).
	var idleSessions []string
	for sid, ws := range a.peers {
		if now.Sub(ws.lastActivity) > wmpSessionIdleTimeout {
			idleSessions = append(idleSessions, sid)
		}
	}
	a.mu.Unlock()

	for _, sid := range idleSessions {
		a.logger.Info("Closing idle WMP session", zap.String("session_id", sid[:8]))
		a.CloseSession(sid)
	}
}

// verifySessionOwnership checks that the session belongs to the authenticated user.
// Returns false if the session doesn't exist or the user/tenant don't match.
func (a *WMPAdapter) verifySessionOwnership(sessionID, userID, tenantID string) bool {
	a.mu.RLock()
	ws, ok := a.peers[sessionID]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	if ws.session.UserID != userID {
		return false
	}
	if tenantID != "" && ws.session.TenantID != tenantID {
		return false
	}
	return true
}

// touchSession updates the last activity timestamp for idle timeout tracking.
func (a *WMPAdapter) touchSession(sessionID string) {
	a.mu.Lock()
	if ws, ok := a.peers[sessionID]; ok {
		ws.lastActivity = time.Now()
	}
	a.mu.Unlock()
}

// HandleRPC handles a single JSON-RPC request (from HTTP POST /wmp/rpc).
// The sessionID is extracted from the request's Wmp-Session-Id header by the
// HTTP handler and passed here; empty for session.create.
func (a *WMPAdapter) HandleRPC(ctx context.Context, sessionID string, body []byte) ([]byte, error) {
	// For session.create we don't have a peer yet — peek at the method.
	var peek struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return wmpErrorBytes(nil, wmp.ErrParseError, nil)
	}

	if peek.Method == wmp.MethodSessionCreate {
		return a.handleSessionCreate(ctx, body)
	}
	if peek.Method == wmp.MethodSessionResume {
		return a.handleSessionResume(ctx, body)
	}

	// All other methods require an existing session.
	if sessionID == "" {
		return wmpErrorBytes(nil, wmp.ErrNotAuthorized, map[string]string{
			"reason": "missing session ID",
		})
	}

	a.mu.RLock()
	ws, ok := a.peers[sessionID]
	a.mu.RUnlock()
	if !ok {
		return wmpErrorBytes(nil, wmp.ErrSessionNotFound, nil)
	}

	// Update activity timestamp for idle timeout tracking.
	a.touchSession(sessionID)

	return ws.peer.HandleRequestSync(ctx, body)
}

// Events returns the outbound notification channel for the given session.
// The HTTP SSE handler reads from this channel and writes SSE frames.
func (a *WMPAdapter) Events(sessionID string) (<-chan []byte, error) {
	a.mu.RLock()
	ws, ok := a.peers[sessionID]
	a.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	return ws.transport.Out(), nil
}

// CloseSession closes a WMP session and its associated engine session.
func (a *WMPAdapter) CloseSession(sessionID string) {
	a.mu.Lock()
	ws, ok := a.peers[sessionID]
	if ok {
		delete(a.peers, sessionID)
	}
	// Clean up any resumption tokens for this session.
	for token, entry := range a.resumptionTokens {
		if entry.sessionID == sessionID {
			delete(a.resumptionTokens, token)
		}
	}
	a.mu.Unlock()
	if ok {
		ws.cancel()
		_ = ws.transport.Close()
		a.manager.unregisterSession(ws.session)
	}
}

// handleSessionCreate creates a new engine session and wmp.Peer.
func (a *WMPAdapter) handleSessionCreate(ctx context.Context, body []byte) ([]byte, error) {
	// Parse the full JSON-RPC request to extract auth from params.
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return wmpErrorBytes(nil, wmp.ErrParseError, nil)
	}

	var params wmp.SessionCreateParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return wmpErrorBytes(req.ID, wmp.ErrInvalidParams, nil)
	}

	// Version negotiation: reject unsupported versions.
	if params.WMP.Version != "" && !wmp.IsSupportedVersion(params.WMP.Version) {
		return wmpErrorBytes(req.ID, wmp.ErrVersionNotSupported, map[string]interface{}{
			"supported_versions": wmp.SupportedVersions,
		})
	}

	// Extract bearer token from auth object.
	var userID, tenantID string
	if params.Auth != nil {
		tokenStr := params.Auth.Token
		if tokenStr == "" {
			return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
				"reason": "missing auth token",
			})
		}
		var err error
		userID, tenantID, err = a.manager.validateToken(tokenStr)
		if err != nil {
			a.logger.Warn("WMP auth failed", zap.Error(err))
			return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
				"reason": "invalid or expired token",
			})
		}
	} else {
		return wmpErrorBytes(req.ID, wmp.ErrNotAuthorized, map[string]string{
			"reason": "auth required",
		})
	}

	sessionID := uuid.New().String()

	// Create the channel transport for this session.
	ct := wmp.NewChannelTransport(50, 200)

	// Create the WMP handler that bridges flow methods to the engine.
	handler := &wmpEngineHandler{
		adapter:   a,
		sessionID: sessionID,
	}

	// Create the peer with the channel transport.
	peer := wmp.NewPeer(ct, handler, wmp.WithLogger(slog.Default()))

	// Create the engine session with a translating transport that converts
	// engine message types to WMP JSON-RPC notifications via the peer.
	wmpTransport := newWMPSessionTransport(peer, ct)
	wmpTransport.handler = handler

	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		TenantID:  tenantID,
		transport: wmpTransport,
		flows:     make(map[string]*Flow),
		logger:    a.logger.With(zap.String("session", userID[:min(8, len(userID))])),
		actionCh:  make(chan *FlowActionMessage, 50),
		signCh:    make(chan *SignResponseMessage, 20),
		matchCh:   make(chan *MatchResponseMessage, 20),
		closeCh:   make(chan struct{}, 1),
	}

	// Store handler's session reference (needed for FlowStart/FlowAction).
	handler.session = session

	// Register with engine manager.
	a.manager.registerSession(session)

	// Store the WMP session.
	sessionCtx, cancel := context.WithCancel(context.Background())
	ws := &wmpSession{
		peer:         peer,
		transport:    ct,
		session:      session,
		cancel:       cancel,
		lastActivity: time.Now(),
	}

	a.mu.Lock()
	a.peers[sessionID] = ws
	a.mu.Unlock()

	// Start the peer's read loop in a goroutine (for processing responses
	// to outbound Call() requests, if any).
	go func() {
		_ = peer.Serve(sessionCtx)
		a.CloseSession(sessionID)
	}()

	// Build response with capability negotiation.
	// The server advertises the capabilities it supports. If the client
	// sent capabilities_offered, the result is the intersection; otherwise
	// the server returns all its capabilities (per spec §4.2.1).
	serverCaps := wmp.Capabilities{
		"flows": json.RawMessage(`{"max_concurrent": 5}`),
		"sign":  json.RawMessage(`{"proof_types": ["jwt"]}`),
	}
	negotiated := serverCaps
	if len(params.CapabilitiesOffered) > 0 {
		negotiated = make(wmp.Capabilities)
		for name, val := range serverCaps {
			if _, offered := params.CapabilitiesOffered[name]; offered {
				negotiated[name] = val
			}
		}
	}

	result := wmp.SessionCreateResult{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: sessionID,
		},
		Capabilities:    negotiated,
		Security:        params.Security,
		ResumptionToken: a.generateResumptionToken(sessionID),
	}

	return wmpResponseBytes(req.ID, result)
}

// generateResumptionToken creates a cryptographically random resumption token
// and stores the token→sessionID mapping. Per spec §4.5.2, tokens MUST have
// at least 128 bits of entropy and are rotated on each successful resume.
func (a *WMPAdapter) generateResumptionToken(sessionID string) string {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		// Should never happen with crypto/rand
		a.logger.Error("failed to generate resumption token", zap.Error(err))
		return ""
	}
	token := base64.RawURLEncoding.EncodeToString(b)

	a.mu.Lock()
	a.resumptionTokens[token] = &resumptionEntry{
		sessionID: sessionID,
		expiresAt: time.Now().Add(resumptionTokenTTL),
	}
	a.mu.Unlock()

	return token
}

// handleSessionResume validates a resumption token, rotates it, and reconnects
// the client to the existing engine session with a new transport/peer.
func (a *WMPAdapter) handleSessionResume(ctx context.Context, body []byte) ([]byte, error) {
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return wmpErrorBytes(nil, wmp.ErrParseError, nil)
	}

	var params wmp.SessionResumeParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return wmpErrorBytes(req.ID, wmp.ErrInvalidParams, nil)
	}

	// Version negotiation.
	if params.WMP.Version != "" && !wmp.IsSupportedVersion(params.WMP.Version) {
		return wmpErrorBytes(req.ID, wmp.ErrVersionNotSupported, map[string]interface{}{
			"supported_versions": wmp.SupportedVersions,
		})
	}

	// Validate resumption token — one-time use, must match session, must not be expired.
	a.mu.Lock()
	entry, validToken := a.resumptionTokens[params.ResumptionToken]
	if validToken {
		// Consume the token (one-time use per spec §4.5.2).
		delete(a.resumptionTokens, params.ResumptionToken)
		// Check expiry.
		if time.Now().After(entry.expiresAt) {
			validToken = false
		}
	}
	a.mu.Unlock()

	if !validToken || entry == nil || entry.sessionID != params.SessionID {
		return wmpErrorBytes(req.ID, wmp.ErrSessionNotFound, map[string]string{
			"reason": "invalid or expired resumption token",
		})
	}

	// Look up the existing session.
	a.mu.RLock()
	oldWS, exists := a.peers[params.SessionID]
	a.mu.RUnlock()
	if !exists {
		return wmpErrorBytes(req.ID, wmp.ErrSessionNotFound, nil)
	}

	// Close the old transport (SSE connection may have dropped) but keep the
	// engine session alive.
	oldWS.cancel()
	_ = oldWS.transport.Close()

	// Create a new channel transport and peer for the resumed connection.
	ct := wmp.NewChannelTransport(50, 200)
	handler := &wmpEngineHandler{
		adapter:   a,
		sessionID: params.SessionID,
		session:   oldWS.session,
	}
	peer := wmp.NewPeer(ct, handler, wmp.WithLogger(slog.Default()))

	// Rewire the engine session's transport to use the new peer/channel.
	wmpTransport := newWMPSessionTransport(peer, ct)
	wmpTransport.handler = handler
	oldWS.session.transportMu.Lock()
	oldWS.session.transport = wmpTransport
	oldWS.session.transportMu.Unlock()

	// Replace the old wmpSession entry.
	sessionCtx, cancel := context.WithCancel(context.Background())
	ws := &wmpSession{
		peer:         peer,
		transport:    ct,
		session:      oldWS.session,
		cancel:       cancel,
		lastActivity: time.Now(),
	}

	a.mu.Lock()
	a.peers[params.SessionID] = ws
	a.mu.Unlock()

	go func() {
		_ = peer.Serve(sessionCtx)
		a.CloseSession(params.SessionID)
	}()

	// Issue a new rotated token.
	newToken := a.generateResumptionToken(params.SessionID)

	result := wmp.SessionResumeResult{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: params.SessionID,
		},
		Resumed:         true,
		ResumptionToken: newToken,
		MissedMessages:  0, // TODO: implement message replay via last_received_id
		Security:        wmp.SecurityMode{Mode: "tls"},
	}

	return wmpResponseBytes(req.ID, result)
}

// ---------------------------------------------------------------------------
// wmpEngineHandler — bridges WMP Handler interface to the engine
// ---------------------------------------------------------------------------

// wmpEngineHandler implements wmp.Handler. It handles flow lifecycle methods
// directly (FlowStart, FlowAction) and delegates session cleanup to the adapter.
// No AsyncFlowProfile is used — the engine's own goroutine-per-flow model
// drives flow execution, and WMP flow.action calls are routed to the engine
// session's channels (actionCh, signCh, matchCh).
type wmpEngineHandler struct {
	wmp.BaseHandler
	adapter   *WMPAdapter
	sessionID string
	session   *Session

	childFlowsMu sync.Mutex
	childFlows   map[string]*childFlowInfo // childFlowID → info
}

// childFlowInfo tracks a nested sub-flow (sign or match) so that when
// the client sends wmp.flow.complete for the child, we can route the
// result back to the appropriate engine channel.
type childFlowInfo struct {
	parentFlowID string
	messageID    string
	flowType     string // "sign" or "match"
}

func (h *wmpEngineHandler) registerChildFlow(childFlowID, parentFlowID, messageID, flowType string) {
	h.childFlowsMu.Lock()
	defer h.childFlowsMu.Unlock()
	if h.childFlows == nil {
		h.childFlows = make(map[string]*childFlowInfo)
	}
	h.childFlows[childFlowID] = &childFlowInfo{
		parentFlowID: parentFlowID,
		messageID:    messageID,
		flowType:     flowType,
	}
}

func (h *wmpEngineHandler) popChildFlow(childFlowID string) (*childFlowInfo, bool) {
	h.childFlowsMu.Lock()
	defer h.childFlowsMu.Unlock()
	info, ok := h.childFlows[childFlowID]
	if ok {
		delete(h.childFlows, childFlowID)
	}
	return info, ok
}

// SessionClose cleans up when the client closes the session.
func (h *wmpEngineHandler) SessionClose(_ context.Context, _ *wmp.SessionCloseParams) {
	h.adapter.CloseSession(h.sessionID)
}

// FlowStart handles wmp.flow.start — launches an engine flow goroutine.
func (h *wmpEngineHandler) FlowStart(ctx context.Context, params *wmp.FlowStartParams) (*wmp.FlowStartResult, error) {
	protocol := Protocol(params.FlowType)
	flowID := params.FlowID
	if flowID == "" {
		flowID = uuid.New().String()
	}
	if len(flowID) > maxFlowIDLength {
		return nil, wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{
			"reason": "flow_id exceeds maximum length",
		})
	}

	logger := h.adapter.logger.With(
		zap.String("flow_id", flowID[:min(8, len(flowID))]),
		zap.String("protocol", string(protocol)),
	)

	// Get handler factory.
	h.adapter.manager.handlersMu.RLock()
	factory, ok := h.adapter.manager.flowHandlers[protocol]
	h.adapter.manager.handlersMu.RUnlock()
	if !ok {
		return nil, wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{
			"reason": "unsupported flow type",
		})
	}

	// Check concurrent flow limit.
	h.session.flowsMu.Lock()
	if len(h.session.flows) >= MaxPendingFlowsPerSession {
		h.session.flowsMu.Unlock()
		return nil, wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{
			"reason": "too many pending flows",
		})
	}

	// Create and register engine flow.
	flow := &Flow{
		ID:        flowID,
		Protocol:  protocol,
		Session:   h.session,
		State:     FlowStep("started"),
		StartTime: time.Now(),
		Data:      make(map[string]interface{}),
	}
	h.session.flows[flowID] = flow
	h.session.flowsMu.Unlock()

	// Parse WMP params into engine FlowStartMessage.
	var startMsg FlowStartMessage
	if params.Params != nil {
		if err := json.Unmarshal(params.Params, &startMsg); err != nil {
			h.session.flowsMu.Lock()
			delete(h.session.flows, flowID)
			h.session.flowsMu.Unlock()
			return nil, wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{
				"reason": "invalid flow params: " + err.Error(),
			})
		}
	}
	startMsg.FlowID = flowID
	startMsg.Protocol = protocol

	// Create engine handler via factory.
	m := h.adapter.manager
	handler, err := factory(flow, m.cfg, logger, m.trustService, m.registryClient, m.verifierStore, m.trustCache)
	if err != nil {
		h.session.flowsMu.Lock()
		delete(h.session.flows, flowID)
		h.session.flowsMu.Unlock()
		return nil, wmp.NewRPCError(wmp.ErrInternalError, map[string]string{
			"reason": "failed to create flow handler",
		})
	}
	flow.Handler = handler

	// Launch the engine flow goroutine. The engine handler calls
	// Session.SendProgress, Session.RequestSign, etc., which go through
	// the wmpSessionTransport and are converted to WMP notifications.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in WMP flow handler", zap.Any("panic", r))
				_ = h.session.SendFlowError(flowID, "", ErrCodeInternalError, "Internal error in flow handler")
			}
			h.session.flowsMu.Lock()
			delete(h.session.flows, flowID)
			h.session.flowsMu.Unlock()
		}()

		flowCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		logger.Info("Starting WMP flow")
		if err := handler.Execute(flowCtx, &startMsg); err != nil {
			logger.Error("WMP flow failed", zap.Error(err))
		} else {
			logger.Info("WMP flow completed")
		}
	}()

	return &wmp.FlowStartResult{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: h.sessionID,
		},
		FlowID:   flowID,
		FlowType: string(protocol),
	}, nil
}

// FlowAction handles wmp.flow.action — routes actions to engine session channels.
//
// The engine's flow handlers block on session channels waiting for client input:
//   - Session.WaitForAction reads from actionCh (for consent, trust_result, etc.)
//   - Session.RequestSign waits on signCh (for proof JWT responses)
//   - Session.RequestMatch waits on matchCh (for DCQL match responses)
//
// This method converts WMP flow.action params into engine message types and
// delivers them to the appropriate channel.
func (h *wmpEngineHandler) FlowAction(_ context.Context, params *wmp.FlowActionParams) (*wmp.FlowActionResult, error) {
	flowID := params.FlowID

	// Verify flow exists.
	h.session.flowsMu.RLock()
	_, exists := h.session.flows[flowID]
	h.session.flowsMu.RUnlock()
	if !exists {
		return nil, wmp.NewRPCError(wmp.ErrFlowError, map[string]string{
			"reason": "flow not found or already completed",
		})
	}

	// Translate spec action names to engine-internal names.
	// This allows WMP clients to use spec-compliant action names
	// (e.g. "accept_offer") while the engine expects its own vocabulary
	// (e.g. "consent"). Engine-native names are also accepted for
	// backwards compatibility and for engine extensions (sign_response,
	// match_response, trust_result) that have no spec equivalent.
	action := params.Action
	if engineAction, ok := specToEngineAction[action]; ok {
		action = engineAction
	}

	switch action {
	case "sign_response":
		var signResp SignResponseMessage
		if params.Params != nil {
			if err := json.Unmarshal(params.Params, &signResp); err != nil {
				return nil, wmp.NewRPCError(wmp.ErrInvalidParams, nil)
			}
		}
		signResp.FlowID = flowID
		// Extract message_id from the raw params if not set by struct unmarshal.
		if signResp.MessageID == "" {
			var raw struct {
				MessageID string `json:"message_id"`
			}
			if params.Params != nil {
				_ = json.Unmarshal(params.Params, &raw)
			}
			signResp.MessageID = raw.MessageID
		}
		select {
		case h.session.signCh <- &signResp:
		default:
			return nil, wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{
				"reason": "server overloaded",
			})
		}

	case "match_response":
		var matchResp MatchResponseMessage
		if params.Params != nil {
			if err := json.Unmarshal(params.Params, &matchResp); err != nil {
				return nil, wmp.NewRPCError(wmp.ErrInvalidParams, nil)
			}
		}
		matchResp.FlowID = flowID
		// Extract message_id from the raw params if not set by struct unmarshal.
		if matchResp.MessageID == "" {
			var raw struct {
				MessageID string `json:"message_id"`
			}
			if params.Params != nil {
				_ = json.Unmarshal(params.Params, &raw)
			}
			matchResp.MessageID = raw.MessageID
		}
		select {
		case h.session.matchCh <- &matchResp:
		default:
			return nil, wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{
				"reason": "server overloaded",
			})
		}

	default:
		// Generic flow actions (consent, trust_result, select_credential, etc.)
		actionMsg := &FlowActionMessage{
			Message: Message{
				FlowID: flowID,
			},
			Action:  action,
			Payload: params.Params,
		}
		select {
		case h.session.actionCh <- actionMsg:
		default:
			return nil, wmp.NewRPCError(wmp.ErrRateLimited, map[string]string{
				"reason": "server overloaded",
			})
		}
	}

	return &wmp.FlowActionResult{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: h.sessionID,
		},
		FlowID: flowID,
		Action: params.Action,
		Status: "accepted",
	}, nil
}

// FlowCancel handles wmp.flow.cancel — cancels an active engine flow.
func (h *wmpEngineHandler) FlowCancel(_ context.Context, params *wmp.FlowCancelParams) (*wmp.FlowCancelResult, error) {
	h.session.flowsMu.RLock()
	flow, exists := h.session.flows[params.FlowID]
	h.session.flowsMu.RUnlock()
	if !exists {
		return nil, wmp.NewRPCError(wmp.ErrFlowError, map[string]string{
			"reason": "flow not found",
		})
	}
	if flow.Handler != nil {
		flow.Handler.Cancel()
	}
	return &wmp.FlowCancelResult{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: h.sessionID,
		},
		FlowID: params.FlowID,
		Status: "cancelled",
	}, nil
}

// FlowComplete handles wmp.flow.complete notifications. For child sub-flows
// (sign/match), this routes the result back to the engine session's signCh
// or matchCh so the blocking RequestSign/RequestMatch calls can complete.
func (h *wmpEngineHandler) FlowComplete(_ context.Context, params *wmp.FlowCompleteParams) {
	info, ok := h.popChildFlow(params.FlowID)
	if !ok {
		// Not a child flow — top-level flow completion (handled elsewhere).
		return
	}

	switch info.flowType {
	case "sign":
		var resp SignResponseMessage
		if params.Result != nil {
			_ = json.Unmarshal(params.Result, &resp)
		}
		resp.FlowID = info.parentFlowID
		resp.MessageID = info.messageID
		select {
		case h.session.signCh <- &resp:
		default:
			h.adapter.logger.Warn("sign channel full, dropping child flow result",
				zap.String("child_flow_id", params.FlowID))
		}

	case "match":
		var resp MatchResponseMessage
		if params.Result != nil {
			_ = json.Unmarshal(params.Result, &resp)
		}
		resp.FlowID = info.parentFlowID
		resp.MessageID = info.messageID
		select {
		case h.session.matchCh <- &resp:
		default:
			h.adapter.logger.Warn("match channel full, dropping child flow result",
				zap.String("child_flow_id", params.FlowID))
		}
	}
}

// ---------------------------------------------------------------------------
// wmpSessionTransport — translates engine messages to WMP JSON-RPC
// ---------------------------------------------------------------------------

// wmpSessionTransport implements engine SessionTransport. It intercepts
// outgoing engine messages (FlowProgressMessage, SignRequestMessage, etc.)
// and converts them to WMP JSON-RPC notifications sent via Peer.Notify.
// For sign/match requests, it starts nested sub-flows per the WMP spec.
type wmpSessionTransport struct {
	peer    *wmp.Peer
	ct      *wmp.ChannelTransport
	handler *wmpEngineHandler
}

func newWMPSessionTransport(peer *wmp.Peer, ct *wmp.ChannelTransport) *wmpSessionTransport {
	return &wmpSessionTransport{peer: peer, ct: ct}
}

// SendJSON intercepts engine message structs and translates them to WMP
// JSON-RPC notifications. The peer writes to the ChannelTransport, which
// feeds the SSE event stream.
func (t *wmpSessionTransport) SendJSON(msg interface{}) error {
	ctx := context.Background()

	switch m := msg.(type) {
	case *FlowProgressMessage:
		return t.peer.Notify(ctx, wmp.MethodFlowProgress, &wmp.FlowProgressParams{
			FlowID:  m.FlowID,
			Step:    string(m.Step),
			Payload: m.Payload,
		})

	case *FlowCompleteMessage:
		result, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return t.peer.Notify(ctx, wmp.MethodFlowComplete, &wmp.FlowCompleteParams{
			FlowID: m.FlowID,
			Result: result,
		})

	case *FlowErrorMessage:
		return t.peer.Notify(ctx, wmp.MethodFlowError, &wmp.FlowErrorParams{
			FlowID:  m.FlowID,
			Code:    mapErrorCode(m.Error.Code),
			Message: m.Error.Message,
		})

	case *SignRequestMessage:
		// Start a nested sign sub-flow per WMP spec. The client handles
		// the flow.start, performs the signing, then sends flow.complete
		// with the proof. FlowComplete routes the result to signCh.
		childFlowID := uuid.New().String()
		t.handler.registerChildFlow(childFlowID, m.FlowID, m.MessageID, "sign")

		subFlowParams := openid4x.SignSubFlowParams{
			Action:       string(m.Action),
			Nonce:        m.Params.Nonce,
			Audience:     m.Params.Audience,
			ProofType:    m.Params.ProofType,
			ParentFlowID: m.FlowID,
		}
		paramsJSON, err := json.Marshal(subFlowParams)
		if err != nil {
			return err
		}
		var startResult wmp.FlowStartResult
		err = t.peer.Call(ctx, wmp.MethodFlowStart, &wmp.FlowStartParams{
			FlowType: wmp.FlowTypeSign,
			FlowID:   childFlowID,
			Params:   paramsJSON,
		}, &startResult)
		return err

	case *MatchRequestMessage:
		// Start a nested match sub-flow. Same pattern as sign.
		childFlowID := uuid.New().String()
		t.handler.registerChildFlow(childFlowID, m.FlowID, m.MessageID, "match")

		matchParams := map[string]interface{}{
			"dcql_query":     m.DCQLQuery,
			"parent_flow_id": m.FlowID,
		}
		paramsJSON, err := json.Marshal(matchParams)
		if err != nil {
			return err
		}
		var startResult wmp.FlowStartResult
		err = t.peer.Call(ctx, wmp.MethodFlowStart, &wmp.FlowStartParams{
			FlowType: "match",
			FlowID:   childFlowID,
			Params:   paramsJSON,
		}, &startResult)
		return err

	default:
		// Fallback: marshal as raw JSON and write directly.
		// This handles PushMessage and other types that don't have
		// a WMP equivalent yet.
		data, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		return t.ct.WriteMessage(ctx, data)
	}
}

func (t *wmpSessionTransport) ReadMessage(ctx context.Context) ([]byte, error) {
	return t.ct.ReadMessage(ctx)
}

func (t *wmpSessionTransport) Close() error {
	return t.ct.Close()
}

// ---------------------------------------------------------------------------
// Error code mapping
// ---------------------------------------------------------------------------

// mapErrorCode converts engine string error codes to WMP integer codes.
func mapErrorCode(code ErrorCode) int {
	switch code {
	case ErrCodeAuthFailed, ErrCodeAuthorizationFail:
		return wmp.ErrNotAuthorized
	case ErrCodeInvalidMessage:
		return wmp.ErrInvalidRequest
	case ErrCodeSignError:
		return wmp.ErrSignatureInvalid
	case ErrCodeTooManyRequests:
		return wmp.ErrRateLimited
	case ErrCodeInternalError:
		return wmp.ErrInternalError
	default:
		// Most engine errors map to the generic flow error with details
		// carried in the message field.
		return wmp.ErrFlowError
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func wmpErrorBytes(id json.RawMessage, code int, data interface{}) ([]byte, error) {
	resp := wmp.NewErrorResponse(id, wmp.NewRPCError(code, data))
	return json.Marshal(resp)
}

func wmpResponseBytes(id json.RawMessage, result interface{}) ([]byte, error) {
	resp, err := wmp.NewResponse(id, result)
	if err != nil {
		return wmpErrorBytes(id, wmp.ErrInternalError, nil)
	}
	return json.Marshal(resp)
}
