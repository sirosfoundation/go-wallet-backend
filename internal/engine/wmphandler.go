package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"go.uber.org/zap"
)

// WMPAdapter wraps the engine Manager and exposes it as WMP JSON-RPC.
// It manages one wmp.Peer per engine Session, each backed by a
// ChannelTransport whose outbound channel feeds the SSE event stream.
type WMPAdapter struct {
	manager *Manager
	logger  *zap.Logger

	mu    sync.RWMutex
	peers map[string]*wmpSession // keyed by WMP session ID
}

// wmpSession associates a wmp.Peer with its channel transport and engine session.
type wmpSession struct {
	peer      *wmp.Peer
	transport *wmp.ChannelTransport
	session   *Session
	cancel    context.CancelFunc
}

// NewWMPAdapter creates an adapter that bridges WMP JSON-RPC to the engine.
func NewWMPAdapter(manager *Manager, logger *zap.Logger) *WMPAdapter {
	return &WMPAdapter{
		manager: manager,
		logger:  logger.Named("wmp"),
		peers:   make(map[string]*wmpSession),
	}
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
	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		TenantID:  tenantID,
		transport: newWMPSessionTransport(peer, ct),
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
		peer:      peer,
		transport: ct,
		session:   session,
		cancel:    cancel,
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

	// Build response.
	result := wmp.SessionCreateResult{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: sessionID,
		},
		Security: params.Security,
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
			"reason": "unknown protocol: " + string(protocol),
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

	switch params.Action {
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
			Action:  params.Action,
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

// ---------------------------------------------------------------------------
// wmpSessionTransport — translates engine messages to WMP JSON-RPC
// ---------------------------------------------------------------------------

// wmpSessionTransport implements engine SessionTransport. It intercepts
// outgoing engine messages (FlowProgressMessage, SignRequestMessage, etc.)
// and converts them to WMP JSON-RPC notifications sent via Peer.Notify.
// This ensures the SSE stream emits proper WMP-formatted messages.
type wmpSessionTransport struct {
	peer *wmp.Peer
	ct   *wmp.ChannelTransport
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
		// Sign requests are sent as flow.progress with step="sign_request"
		// per the migration plan (Option A: flow progress + action).
		payload, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return t.peer.Notify(ctx, wmp.MethodFlowProgress, &wmp.FlowProgressParams{
			FlowID:  m.FlowID,
			Step:    "sign_request",
			Payload: payload,
		})

	case *MatchRequestMessage:
		// Match requests are sent as flow.progress with step="match_request".
		payload, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return t.peer.Notify(ctx, wmp.MethodFlowProgress, &wmp.FlowProgressParams{
			FlowID:  m.FlowID,
			Step:    "match_request",
			Payload: payload,
		})

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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
