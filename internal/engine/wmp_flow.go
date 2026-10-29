package engine

// The engine <-> WMP flow bridge. A WMP flow is run by go-wmp's
// AsyncFlowProfile; its FlowFunc starts the engine flow (Manager.handleFlowStart)
// and the engine's output, which it writes with Session.Send, reaches the
// client through the flow's wmp.FlowContext: progress, completion, error, and
// sign/match sub-flows (openid4x.RequestSign, RequestMatch). Client input
// goes the other way: wmp.flow.action to Session.dispatchAction, a sub-flow's
// result to Session.dispatchSignResponse.

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"go.uber.org/zap"
)

// subFlowTimeout bounds a sign or match sub-flow, as Session.RequestSign does.
const subFlowTimeout = 3 * time.Minute

// specToEngineAction maps WMP spec action names to engine action names. The
// presentation consent, select_credentials, is handled apart (see
// translateSelectCredentials).
var specToEngineAction = map[string]string{
	openid4x.ActionAcceptOffer:   ActionConsent,
	openid4x.ActionProvideTxCode: ActionProvidePin,
	openid4x.ActionAuthorize:     ActionAuthorizationComplete,
	openid4x.ActionCancel:        ActionDecline,
}

// wmpFlowTypes maps the flow types served over WMP to the engine protocols and
// the capability that gates each (Core 10.3). vctm is not a WMP flow type
// (OpenID4x 2 routes VCTM through wmp.resolve).
var wmpFlowTypes = map[string]Protocol{
	openid4x.FlowTypeOID4VCI: ProtocolOID4VCI,
	openid4x.FlowTypeOID4VP:  ProtocolOID4VP,
}

// wmpFlowProfile is the per-session profile: go-wmp's AsyncFlowProfile with the
// engine's start validation, action translation and capability gating.
type wmpFlowProfile struct {
	*wmp.AsyncFlowProfile
	a         *WMPAdapter
	sessionID string
	guard     *wmpGuard
	// timeouts holds the timeout a client named in wmp.flow.start (Core 6.2) from
	// StartFlow to the flow function, which only sees the flow's params.
	timeouts sync.Map // flow ID -> time.Duration
}

func newWMPFlowProfile(a *WMPAdapter, sessionID string) *wmpFlowProfile {
	p := &wmpFlowProfile{AsyncFlowProfile: wmp.NewAsyncFlowProfile("siros-engine"), a: a, sessionID: sessionID}
	p.guard = &wmpGuard{a: a, sessionID: sessionID}
	a.manager.handlersMu.RLock()
	defer a.manager.handlersMu.RUnlock()
	for flowType, protocol := range wmpFlowTypes {
		if _, ok := a.manager.flowHandlers[protocol]; ok {
			p.Handle(flowType, p.run(protocol))
		}
	}
	return p
}

// Init binds the long-lived Peer to the session's transport and installs the
// TAC guard as middleware (the Authorizer is installed as a Peer option).
func (p *wmpFlowProfile) Init(pc wmp.PeerContext) error {
	if err := p.AsyncFlowProfile.Init(pc); err != nil {
		return err
	}
	if mw, ok := pc.(interface{ UseMiddleware(wmp.Middleware) }); ok {
		mw.UseMiddleware(p.guard.middleware)
	}
	if ws := p.a.session(p.sessionID); ws != nil {
		ws.tr.setPeer(pc)
	}
	return nil
}

// RequiredCapability implements wmp.CapabilityRequirer: a flow type needs the
// capability of the same name negotiated, else -31005 (Core 10.3).
func (p *wmpFlowProfile) RequiredCapability(flowType string) string {
	if _, ok := wmpFlowTypes[flowType]; ok {
		return flowType
	}
	return ""
}

// OnSessionCreate implements wmp.SessionHook: the session owns an engine
// Session for its life.
func (p *wmpFlowProfile) OnSessionCreate(ctx context.Context, s *wmp.Session, _ *wmp.SessionCreateParams) error {
	return p.a.create(ctx, s)
}

// OnSessionClose implements wmp.SessionHook. The engine session ends with the
// stored session (see wmpHandler.SessionClose), not here: go-wmp has not
// necessarily deleted it yet.
func (p *wmpFlowProfile) OnSessionClose(context.Context, *wmp.Session, *wmp.SessionCloseParams) {
	// Nothing to do here, on purpose: see above.
}

// parseStart decodes the engine's flow start from the wmp.flow.start params.
func parseStart(params *wmp.FlowStartParams) (*FlowStartMessage, error) {
	var start FlowStartMessage
	if len(params.Params) > 0 {
		if err := json.Unmarshal(params.Params, &start); err != nil {
			return nil, wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{"reason": "invalid flow params"})
		}
	}
	// The profile names the OID4VCI offer credential_offer (OpenID4x 3.1.1); the
	// engine's own message calls it offer.
	var named struct {
		CredentialOffer string `json:"credential_offer"`
	}
	if len(params.Params) > 0 {
		_ = json.Unmarshal(params.Params, &named)
	}
	if start.Offer == "" {
		start.Offer = named.CredentialOffer
	}
	start.FlowID = params.FlowID
	start.Protocol = wmpFlowTypes[params.FlowType]
	return &start, nil
}

// StartFlow validates the start synchronously, so a bad request is answered
// -32602, then lets go-wmp run the flow.
func (p *wmpFlowProfile) StartFlow(ctx context.Context, params *wmp.FlowStartParams) (*wmp.FlowStartResult, error) {
	if len(params.FlowID) > maxFlowIDLength {
		return nil, wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{"reason": "flow_id exceeds maximum length"})
	}
	if _, err := parseStart(params); err != nil {
		return nil, err
	}
	if p.a.session(p.sessionID) == nil {
		return nil, wmp.NewRPCError(wmp.ErrSessionNotFound, nil)
	}
	if params.Timeout > 0 {
		p.timeouts.Store(params.FlowID, capSeconds(params.Timeout, defaultFlowTimeout))
	}
	res, err := p.AsyncFlowProfile.StartFlow(ctx, params)
	if err != nil {
		p.timeouts.Delete(params.FlowID)
	}
	return res, err
}

// features maps the negotiated capabilities to engine feature declarations
// (FlowStartMessage.Features), so transaction_data goes only to a client that
// offered it. The negotiated set only holds what the client offered (see
// WMPAdapter.negotiate).
func features(s *wmp.Session) []string {
	if s != nil && s.Capabilities.OffersTransactionData(wmp.TransactionDataVersion1) {
		return []string{FeatureTransactionDataV1}
	}
	return nil
}

// run is the FlowFunc of an engine protocol: it runs the engine flow to its end.
func (p *wmpFlowProfile) run(protocol Protocol) wmp.FlowFunc {
	return func(ctx context.Context, fc *wmp.FlowContext) error {
		ws := p.a.session(p.sessionID)
		if ws == nil {
			return errors.New("session closed")
		}
		var params wmp.FlowStartParams
		params.FlowID, params.FlowType, params.Params = fc.FlowID, fc.FlowType, fc.Params
		start, err := parseStart(&params)
		if err != nil {
			return err
		}
		start.Protocol = protocol
		// Declared features come from what the session negotiated, not from the
		// flow params, so a client cannot slip in a `features` member.
		start.Features = features(wmp.SessionFromContext(ctx))

		// A client-named timeout (Core 6.2) shortens the engine's own.
		timeout := defaultFlowTimeout
		if v, ok := p.timeouts.LoadAndDelete(fc.FlowID); ok {
			if d, isDuration := v.(time.Duration); isDuration {
				timeout = d
			}
		}
		parent := ctx
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		f := &wmpFlow{fc: fc, session: wmp.SessionFromContext(ctx)}
		ws.tr.add(fc.FlowID, f)
		defer ws.tr.remove(fc.FlowID)

		// A cancel, the timeout or the end of the Peer ends the engine flow from
		// its first step: ctx is the engine's.
		p.a.manager.handleFlowStartContext(ctx, ws.session, start)

		if !f.terminal.Load() && parent.Err() == nil && f.malformed.Load() {
			// A refused sign request ended the flow without an engine message of
			// its own: it ends with the terminal -32602 all the same.
			f.endMalformed()
			return nil
		}
		if !f.terminal.Load() && parent.Err() == nil {
			// The engine ended the flow without a result (it timed out, or ended
			// silently); the client was not cancelled, so go-wmp tells it.
			return errors.New("flow ended without a result")
		}
		return nil
	}
}

// capSeconds converts client-supplied seconds to a Duration capped at limit. The
// cap is applied before multiplying so values near MaxInt cannot overflow.
// Non-positive input yields 0.
func capSeconds(seconds int, limit time.Duration) time.Duration {
	if seconds <= 0 {
		return 0
	}
	if int64(seconds) >= int64(limit/time.Second) {
		return limit
	}
	return time.Duration(seconds) * time.Second
}

// HandleAction translates a wmp.flow.action to the engine's action and hands it
// to the flow. The checks that need the engine's tables (flow known, closed
// shape of select_credentials) are answered synchronously.
func (p *wmpFlowProfile) HandleAction(_ context.Context, params *wmp.FlowActionParams) (*wmp.FlowActionResult, error) {
	ws := p.a.session(p.sessionID)
	if ws == nil {
		return nil, wmp.NewRPCError(wmp.ErrSessionNotFound, nil)
	}
	ws.session.flowsMu.RLock()
	_, known := ws.session.flows[params.FlowID]
	ws.session.flowsMu.RUnlock()
	if !known {
		return nil, wmp.NewRPCError(wmp.ErrFlowError, map[string]string{"reason": "flow not found or already completed"})
	}

	if err := openid4x.ValidateAction(wmpFlowTypeOf(ws, params.FlowID), params.Action); err != nil {
		return nil, err
	}
	action, payload := params.Action, params.Params
	if action == openid4x.ActionSelectCredentials {
		var err error
		if action, payload, err = translateSelectCredentials(params.Params); err != nil {
			// -32602 without data (OpenID4x 3.2.3.1): nothing of the params is
			// echoed. The flow is declined, so the verifier is told access_denied,
			// and it ends -32602 (see wmpFlow.malformed); the offending members go
			// no further.
			f := ws.tr.flow(params.FlowID)
			if f != nil {
				f.malformed.Store(true)
			}
			ws.session.dispatchAction(&FlowActionMessage{Message: Message{Type: TypeFlowAction, FlowID: params.FlowID}, Action: ActionDecline})
			if f != nil && !ws.session.awaitsSelection(params.FlowID) {
				// The flow is not waiting for the selection (it is signing, or
				// submitting): nothing would consume the decline and the flow would
				// run on. A pending sign request is refused, so the engine tells the
				// verifier access_denied and the flow ends with the terminal -32602;
				// without one the flow ends now, with the same terminal -32602.
				if !ws.session.refuseSignRequests(params.FlowID) {
					f.endMalformed()
				}
			}
			return nil, wmp.NewRPCError(wmp.ErrInvalidParams, nil)
		}
	} else if engineAction, ok := specToEngineAction[action]; ok {
		action = engineAction
	}
	ws.session.dispatchAction(&FlowActionMessage{
		Message: Message{Type: TypeFlowAction, FlowID: params.FlowID},
		Action:  action,
		Payload: payload,
	})
	return &wmp.FlowActionResult{
		WMP:    wmp.Metadata{Version: wmp.Version, SessionID: p.sessionID},
		FlowID: params.FlowID,
		Action: params.Action,
		Status: "accepted",
	}, nil
}

// refuseSignRequests answers every sign request pending for flowID with
// SIGN_REFUSED and reports whether it did: true only if every pending request
// took the refusal. A request the wallet has already answered (its result is
// buffered, or the waiter has taken it and is submitting) is not refused: the
// first reply wins, decided once by the request's reply state, so the caller has to
// end the flow another way.
func (s *Session) refuseSignRequests(flowID string) bool {
	s.flowsMu.RLock()
	defer s.flowsMu.RUnlock()
	refused := false
	for id, p := range s.outstandingRequests {
		if p.flowID != flowID || p.sign == nil {
			continue
		}
		if !p.reply.CompareAndSwap(replyNone, replyRefused) {
			if p.reply.Load() == replyRefused {
				// Already refused by an earlier (or overlapping) malformed action:
				// that refusal is being carried out, not cut short.
				refused = true
				continue
			}
			return false // the wallet's result came first
		}
		p.sign <- &SignResponseMessage{
			Message:   Message{Type: TypeSignResponse, FlowID: flowID, MessageID: id},
			ErrorCode: ErrCodeSignRefused,
		}
		refused = true
	}
	return refused
}

// awaitsSelection reports whether the flow can still consume a selection: its
// last reported step is the credential selection and no sign request is pending
// (after the consent the step stays credential_selection until the next
// progress, so the step alone does not say the selection is still awaited).
func (s *Session) awaitsSelection(flowID string) bool {
	s.flowsMu.RLock()
	f := s.flows[flowID]
	pending := false
	for _, p := range s.outstandingRequests {
		if p.flowID == flowID {
			pending = true
			break
		}
	}
	s.flowsMu.RUnlock()
	if f == nil || pending {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.State == StepCredentialSelection
}

// wmpFlowTypeOf is the WMP flow type of an engine flow.
func wmpFlowTypeOf(ws *wmpSession, flowID string) string {
	ws.session.flowsMu.RLock()
	defer ws.session.flowsMu.RUnlock()
	if f := ws.session.flows[flowID]; f != nil {
		return string(f.Protocol)
	}
	return ""
}

// translateSelectCredentials maps the closed select_credentials params
// (OpenID4x 3.2.3.1) to the engine's consent action. The engine learns the
// verifier's query ids and the opaque selection handle, nothing about the
// credentials; a decline is the engine's decline. See also #502, which moves
// the engine's own protocol to this shape.
func translateSelectCredentials(raw json.RawMessage) (action string, payload json.RawMessage, err error) {
	sel, err := openid4x.ParseSelectCredentials(raw)
	if err != nil {
		return "", nil, err
	}
	if !sel.Consent {
		return ActionDecline, nil, nil
	}
	consent := ConsentPayload{SelectionHandle: sel.Selections[0].SelectionHandle}
	for _, s := range sel.Selections {
		consent.SelectedCredentials = append(consent.SelectedCredentials, ConsentSelection{CredentialQueryID: s.QueryID})
	}
	payload, err = json.Marshal(consent)
	return ActionConsent, payload, err
}

// --- transport ---------------------------------------------------------------

// wmpFlow is a running WMP flow: its FlowContext, and the WMP session it runs in.
type wmpFlow struct {
	fc      *wmp.FlowContext
	session *wmp.Session
	// terminal is set once the engine sent the flow's completion or error.
	terminal atomic.Bool
	// malformed is set when the wallet sent a select_credentials the closed shape
	// refuses: the flow is declined, and ends -32602 with no data (OpenID4x
	// 3.2.3.1), not as an ordinary decline.
	malformed atomic.Bool
}

// endMalformed ends the flow with the terminal -32602 of a malformed
// select_credentials (no data), once. It cancels the flow, so nothing the engine
// does afterwards reaches the client.
func (f *wmpFlow) endMalformed() {
	if f.terminal.CompareAndSwap(false, true) {
		_ = f.fc.Error(f.context(), wmp.ErrInvalidParams, wmp.ErrorMessage(wmp.ErrInvalidParams), nil)
	}
}

// context is the context for what the engine sends on the flow. It carries the
// WMP session (RequestMatch checks the negotiated capability in it) and is not
// cancelled with the flow: the terminal message is sent as the flow ends, and a
// sub-flow ends with its parent through the FlowContext.
func (f *wmpFlow) context() context.Context {
	return wmp.ContextWithSession(context.Background(), f.session)
}

// wmpTransport is the engine's SessionTransport for a WMP session: it turns
// what the engine sends into WMP messages on the session's flows.
type wmpTransport struct {
	a  *WMPAdapter
	id string

	mu    sync.Mutex
	peer  wmp.PeerContext // the session's long-lived Peer
	flows map[string]*wmpFlow
}

func (t *wmpTransport) setPeer(p wmp.PeerContext) {
	t.mu.Lock()
	t.peer = p
	t.mu.Unlock()
}

func (t *wmpTransport) add(id string, f *wmpFlow) {
	t.mu.Lock()
	t.flows[id] = f
	t.mu.Unlock()
}

func (t *wmpTransport) remove(id string) {
	t.mu.Lock()
	delete(t.flows, id)
	t.mu.Unlock()
}

func (t *wmpTransport) flow(id string) *wmpFlow {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.flows[id]
}

func (t *wmpTransport) peerContext() wmp.PeerContext {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peer
}

// Close ends the session from the engine's side (user revoked, superseded,
// shutdown). It may be called with the manager's locks held, so the work is
// done asynchronously.
func (t *wmpTransport) Close() error {
	go t.a.endSession(t.id, true)
	return nil
}

var errNoWMPPeer = errors.New("WMP session has no live peer")

// SendJSON translates an engine message to its WMP form.
func (t *wmpTransport) SendJSON(msg interface{}) error {
	switch m := msg.(type) {
	case *FlowProgressMessage:
		f := t.flow(m.FlowID)
		if f == nil || f.terminal.Load() {
			return nil // the flow is over; nothing to report progress on
		}
		return f.fc.Progress(f.context(), string(m.Step), m.Payload)

	case *FlowCompleteMessage:
		f := t.flow(m.FlowID)
		if f == nil {
			return errNoFlow
		}
		if !f.terminal.CompareAndSwap(false, true) {
			return nil // the flow already ended (a malformed selection): one terminal message
		}
		return f.fc.Complete(f.context(), m)

	case *FlowErrorMessage:
		return t.sendFlowError(m)

	case *SignRequestMessage:
		f := t.flow(m.FlowID)
		if f == nil {
			return errNoFlow
		}
		go t.relaySign(f, m)
		return nil

	case *MatchRequestMessage:
		f := t.flow(m.FlowID)
		if f == nil {
			return errNoFlow
		}
		go t.relayMatch(f, m)
		return nil

	default:
		// No dedicated WMP method (notification acks, push): wrap in
		// wmp.message.deliver so every stream event is valid JSON-RPC.
		peer := t.peerContext()
		if peer == nil {
			return errNoWMPPeer
		}
		data, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		var probe struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(data, &probe)
		return peer.Notify(context.Background(), wmp.MethodMessageDeliver, &wmp.MessageDeliverParams{
			WMP:         wmp.Metadata{Version: wmp.Version, SessionID: t.id},
			ContentType: "application/json",
			MessageType: probe.Type,
			Body:        data,
		})
	}
}

var errNoFlow = errors.New("flow is not running over WMP")

// sendFlowError ends a flow with wmp.flow.error. Error.Details (for example
// OID4VP's redirect_uri) travel in data, as on WebSocket. A transaction_data
// refusal is -31005 {"unsupported":"transaction_data"} (OpenID4x 2.3) with the
// redirect_uri as an additive member.
func (t *wmpTransport) sendFlowError(m *FlowErrorMessage) error {
	code := mapErrorCode(m.Error.Code)
	var data interface{}
	if len(m.Error.Details) > 0 {
		data = m.Error.Details
	}
	if m.Error.Code == ErrCodeUnsupportedTransactionData {
		redirect, _ := m.Error.Details["redirect_uri"].(string)
		data = openid4x.TransactionDataUnsupportedData(redirect)
	}
	if f := t.flow(m.FlowID); f != nil {
		if !f.terminal.CompareAndSwap(false, true) {
			return nil // already ended: one terminal message
		}
		if f.malformed.Load() {
			// The terminal error of a malformed select_credentials: -32602, and
			// nothing of the engine's decline (or of the params) in it.
			return f.fc.Error(f.context(), wmp.ErrInvalidParams, wmp.ErrorMessage(wmp.ErrInvalidParams), nil)
		}
		return f.fc.Error(f.context(), code, m.Error.Message, data)
	}
	// An error about no running flow (a message for an unknown flow): go-wmp
	// has no FlowContext to send it on, so it goes straight to the Peer.
	peer := t.peerContext()
	if peer == nil {
		return errNoWMPPeer
	}
	var raw json.RawMessage
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return err
		}
		raw = b
	}
	return peer.Notify(context.Background(), wmp.MethodFlowError, &wmp.FlowErrorParams{
		WMP:     wmp.Metadata{Version: wmp.Version, SessionID: t.id},
		FlowID:  m.FlowID,
		Code:    code,
		Message: m.Error.Message,
		Data:    raw,
	})
}

// relaySign runs a sign sub-flow and hands its outcome to the engine's waiting
// RequestSign, as a sign_response.
func (t *wmpTransport) relaySign(f *wmpFlow, m *SignRequestMessage) {
	resp := &SignResponseMessage{Message: Message{Type: TypeSignResponse, FlowID: m.FlowID, MessageID: m.MessageID}}
	params, err := signSubFlowParams(m)
	if err == nil {
		var result json.RawMessage
		result, err = openid4x.RequestSign(f.context(), f.fc, params, subFlowTimeout)
		if err == nil {
			if jerr := json.Unmarshal(result, resp); jerr != nil {
				err = jerr
			}
			resp.Type, resp.FlowID, resp.MessageID = TypeSignResponse, m.FlowID, m.MessageID
		}
	}
	if err != nil {
		resp = signFailure(m, err)
	}
	if ws := t.a.session(t.id); ws != nil {
		ws.session.dispatchSignResponse(resp)
	}
}

// signFailure is the engine's view of a failed sign sub-flow. Wallet text and
// data never travel on: the engine keeps only the allowlisted code
// (SIGN_REFUSED for a rejection, UNSUPPORTED_TRANSACTION_DATA below). A wallet
// that cannot process the request's transaction_data answers -31005
// {"unsupported":"transaction_data"}; the OID4VP flow uses it to tell the
// verifier.
func signFailure(m *SignRequestMessage, err error) *SignResponseMessage {
	resp := &SignResponseMessage{
		Message: Message{Type: TypeSignResponse, FlowID: m.FlowID, MessageID: m.MessageID},
		Error:   "sign sub-flow failed",
	}
	var sfe *wmp.SubFlowError
	if errors.As(err, &sfe) && sfe.Rejected() {
		// The wallet declined (Core 6.2, data.reason "rejected"): not a failure,
		// so the OID4VP flow answers the verifier access_denied with no
		// description and ends -31006 (OpenID4x 3.2.6).
		resp.Error, resp.ErrorCode = "", ErrCodeSignRefused
		return resp
	}
	if errors.As(err, &sfe) && sfe.Code == wmp.ErrCapabilityNotSupported {
		var d struct {
			Unsupported string `json:"unsupported"`
		}
		if json.Unmarshal(sfe.Data, &d) == nil && d.Unsupported == wmp.CapabilityTransactionData {
			resp.ErrorCode = ErrCodeUnsupportedTransactionData
		}
	}
	return resp
}

// relayMatch runs a match sub-flow (OpenID4x 3.3): the wallet answers whether it
// can satisfy the query, with no credential data. The engine's own matching
// protocol is not used for OID4VP (the client matches inside the consent step),
// so only satisfiability is relayed.
func (t *wmpTransport) relayMatch(f *wmpFlow, m *MatchRequestMessage) {
	resp := &MatchResponseMessage{Message: Message{Type: TypeMatchResponse, FlowID: m.FlowID, MessageID: m.MessageID}}
	result, err := openid4x.RequestMatch(f.context(), f.fc, openid4x.MatchSubFlowParams{
		DCQLQuery:       m.DCQLQuery,
		ClientMetadata:  m.ClientMetadata,
		VerifiedRequest: marshalOrNil(m.VerifiedRequest),
	}, subFlowTimeout)
	switch {
	case err != nil:
		resp.Error = "match sub-flow failed"
	default:
		var r openid4x.MatchResult
		if json.Unmarshal(result, &r) != nil || !r.Satisfiable {
			resp.NoMatchReason = r.Code
		}
	}
	if ws := t.a.session(t.id); ws != nil {
		ws.session.dispatchMatchResponse(resp)
	}
}

func marshalOrNil(v *VerifiedRequestInputs) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// signSubFlowParams is the sign sub-flow of an engine sign request. The
// consent's credential_query_ids and selection handle travel; credential ids
// and claim names are not part of the closed WMP shape (OpenID4x 3.2.5).
func signSubFlowParams(m *SignRequestMessage) (openid4x.SignSubFlowParams, error) {
	p := m.Params
	var verifiedRequest json.RawMessage
	if p.VerifiedRequest != nil {
		b, err := json.Marshal(p.VerifiedRequest)
		if err != nil {
			return openid4x.SignSubFlowParams{}, err
		}
		verifiedRequest = b
	}
	var responseEncryption json.RawMessage
	if p.ResponseEncryption != nil {
		b, err := json.Marshal(p.ResponseEncryption)
		if err != nil {
			return openid4x.SignSubFlowParams{}, err
		}
		responseEncryption = b
	}
	out := openid4x.SignSubFlowParams{
		Action:                string(m.Action),
		Nonce:                 p.Nonce,
		Audience:              p.Audience,
		ProofType:             p.ProofType,
		TransactionData:       convertTransactionData(p.TransactionData),
		ResponseMode:          p.ResponseMode,
		Issuer:                p.Issuer,
		ProofTypesSupported:   p.ProofTypesSupported,
		Count:                 p.Count,
		ResponseURI:           p.ResponseURI,
		VerifierJWKThumbprint: p.VerifierJwkThumbprint,
		VerifierSessionID:     p.VerifierSessionID,
		CredentialsToInclude:  convertCredentialsToInclude(p.CredentialsToInclude),
		SelectionHandle:       p.SelectionHandle,
		ReissuanceKid:         p.ReissuanceKid,
		HTM:                   p.HTM,
		HTU:                   p.HTU,
		DPoPNonce:             p.DPoPNonce,
		ATH:                   p.ATH,
		KeyID:                 p.KeyID,
		AttestationChallenge:  p.AttestationChallenge,
		ClientMetadata:        p.ClientMetadata,
		VerifiedRequest:       verifiedRequest,
		ResponseEncryption:    responseEncryption,
		State:                 p.State,
		CredentialType:        p.CredentialType,
		CredentialIssuer:      p.CredentialIssuer,
		JWE:                   p.JWE,
		Deferred:              p.Deferred,
	}
	if e := p.CredentialResponseEncryption; e != nil {
		out.CredentialResponseEncryption = &openid4x.CredentialResponseEncryption{Alg: e.Alg, Enc: e.Enc, Required: e.Required}
	}
	return out, nil
}

// convertTransactionData converts the engine's TransactionData to its field-for-
// field identical WMP wire type, so the transports share no Go type.
func convertTransactionData(in []TransactionData) []openid4x.TransactionData {
	if in == nil {
		return nil
	}
	out := make([]openid4x.TransactionData, len(in))
	for i, td := range in {
		out[i] = openid4x.TransactionData{
			Type:                     td.Type,
			Raw:                      td.Raw,
			Payload:                  td.Payload,
			CredentialIDs:            td.CredentialIDs,
			TransactionDataHashesAlg: openid4x.HashAlgs(td.TransactionDataHashesAlg),
		}
		// Params and HashAlgorithm are deprecated in go-wmp but still copied:
		// pre-TS12 entries carry their members there.
		out[i].Params = td.Params               //nolint:staticcheck // deprecated, kept for pre-TS12 entries
		out[i].HashAlgorithm = td.HashAlgorithm //nolint:staticcheck // deprecated, kept for pre-TS12 entries
	}
	return out
}

// convertCredentialsToInclude is the closed WMP form of the consent: the
// credential query ids only (OpenID4x 3.2.5).
func convertCredentialsToInclude(in []CredentialRef) []openid4x.CredentialQueryRef {
	if len(in) == 0 {
		return nil
	}
	out := make([]openid4x.CredentialQueryRef, len(in))
	for i, ref := range in {
		out[i] = openid4x.CredentialQueryRef{CredentialQueryID: ref.CredentialQueryID}
	}
	return out
}

// mapErrorCode converts engine string error codes to WMP integer codes.
func mapErrorCode(code ErrorCode) int {
	switch code {
	case ErrCodeAuthFailed, ErrCodeAuthorizationFail, ErrCodeForbidden:
		return wmp.ErrNotAuthorized
	case ErrCodeInvalidMessage:
		return wmp.ErrInvalidRequest
	case ErrCodeUnsupportedTransactionData:
		// OpenID4x 2.3: transaction_data to a wallet without the capability.
		return wmp.ErrCapabilityNotSupported
	case ErrCodeTooManyRequests:
		return wmp.ErrRateLimited
	case ErrCodeInternalError:
		return wmp.ErrInternalError
	default:
		// Most engine errors map to the generic flow error; details travel in
		// the message.
		return wmp.ErrFlowError
	}
}

// --- request guard -----------------------------------------------------------

// wmpGuard enforces the token's TAC on every request, from the Principal in the
// request's context (never from anything cached): the Authorizer is the
// backstop that refuses a request without a valid engine Principal, the
// middleware the per-method check that can answer -31002 with data.
type wmpGuard struct {
	a         *WMPAdapter
	sessionID string
}

// Authorize implements wmp.Authorizer. It refuses a request that does not come
// from the Principal that owns the session the Peer is bound to (the HTTP server
// checks that before it builds the Peer; a Peer built by an in-process caller
// has no such check), a request that names another session than the Peer's, and
// one without an engine Principal.
func (g *wmpGuard) Authorize(ctx context.Context, _ string, params json.RawMessage) bool {
	p, ok := wmp.PrincipalFromContext(ctx)
	if !ok {
		return false
	}
	if _, ok := wmpClaimsFrom(ctx); !ok {
		return false
	}
	if g.sessionID == "" {
		return true // the throw-away Peer of wmp.session.create or resume: the service decides
	}
	rec, found := g.a.svc.Store().Get(g.sessionID)
	if !found || rec.IsExpired() || !rec.OwnedBy(p.Key()) {
		return false
	}
	var named struct {
		WMP struct {
			SessionID string `json:"session_id"`
		} `json:"wmp"`
	}
	if json.Unmarshal(params, &named) == nil && named.WMP.SessionID != "" && named.WMP.SessionID != g.sessionID {
		return false
	}
	return true
}

var errInsufficientTAC = map[string]string{"reason": "insufficient permissions for flow type"}

// middleware implements wmp.Middleware.
func (g *wmpGuard) middleware(ctx context.Context, method string, params json.RawMessage, next wmp.MiddlewareFunc) (interface{}, error) {
	protocol, gated := g.protocolOf(method, params)
	if gated {
		cl, ok := wmpClaimsFrom(ctx)
		if !ok {
			return nil, wmp.NewRPCError(wmp.ErrNotAuthorized, nil)
		}
		required, needs := requiredTACForProtocol[protocol]
		// Both the TAC the session was created with and this request's must
		// grant it; an empty TAC has no permissions.
		ws := g.a.session(g.sessionID)
		if needs && (ws == nil || !ws.session.TAC.HasAll(required) || !cl.TAC.HasAll(required)) {
			g.a.logger.Warn("Rejected WMP request - insufficient TAC",
				zap.String("method", method), zap.String("required", required), zap.String("request_tac", string(cl.TAC)))
			return nil, wmp.NewRPCError(wmp.ErrNotAuthorized, errInsufficientTAC)
		}
	}
	return next(ctx, method, params)
}

// protocolOf is the engine protocol a request acts on, and whether it is gated
// at all. A request about a flow the session does not know is not gated: its
// handler reports it unknown.
func (g *wmpGuard) protocolOf(method string, params json.RawMessage) (Protocol, bool) {
	var p struct {
		FlowType string `json:"flow_type"`
		FlowID   string `json:"flow_id"`
	}
	switch method {
	case wmp.MethodCredentialNotification:
		return ProtocolOID4VCI, true
	case wmp.MethodFlowStart:
		_ = json.Unmarshal(params, &p)
		protocol, ok := wmpFlowTypes[p.FlowType]
		return protocol, ok
	case wmp.MethodFlowAction, wmp.MethodFlowCancel, wmp.MethodFlowProgress, wmp.MethodFlowComplete, wmp.MethodFlowError:
		_ = json.Unmarshal(params, &p)
		ws := g.a.session(g.sessionID)
		if ws == nil || p.FlowID == "" {
			return "", false
		}
		return g.flowProtocol(ws, p.FlowID)
	}
	return "", false
}

// flowProtocol is the protocol of flow id: a flow of the session, or, for the
// result of a sign or match sub-flow, the flow that is waiting for it (a
// result can fail that flow, so it needs the permission that flow's protocol
// requires).
func (g *wmpGuard) flowProtocol(ws *wmpSession, id string) (Protocol, bool) {
	ws.session.flowsMu.RLock()
	f := ws.session.flows[id]
	ws.session.flowsMu.RUnlock()
	if f != nil {
		return f.Protocol, true
	}
	return ws.tr.parentProtocol(ws.session, id)
}

// parentProtocol is the protocol of the flow whose pending sub-flow is id.
func (t *wmpTransport) parentProtocol(session *Session, id string) (Protocol, bool) {
	t.mu.Lock()
	flows := make([]*wmpFlow, 0, len(t.flows))
	for _, f := range t.flows {
		flows = append(flows, f)
	}
	t.mu.Unlock()
	for _, f := range flows {
		for _, sub := range f.fc.PendingSubFlows() {
			if sub.FlowID != id {
				continue
			}
			session.flowsMu.RLock()
			parent := session.flows[f.fc.FlowID]
			session.flowsMu.RUnlock()
			if parent != nil {
				return parent.Protocol, true
			}
		}
	}
	return "", false
}
