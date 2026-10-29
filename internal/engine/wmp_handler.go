package engine

import (
	"context"
	"errors"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"go.uber.org/zap"
)

// wmpHandler is the Handler of one WMP session. The session methods are
// go-wmp's SessionService; wmp.message.deliver, ack and status never reach it
// (the Peer answers them as a tls-mode orchestrator, see
// wmp.WithOrchestratorMessages); flows are run by the profile. What is left is
// what only the engine can answer.
type wmpHandler struct {
	wmp.SessionHandler
	a         *WMPAdapter
	sessionID string
}

// SessionClose ends the session. The service deletes the stored session only
// for its owner; the engine session ends with it.
func (h *wmpHandler) SessionClose(ctx context.Context, p *wmp.SessionCloseParams) {
	h.SessionHandler.SessionClose(ctx, p)
	if _, ok := h.a.svc.Store().Get(p.WMP.SessionID); !ok {
		h.a.endSession(p.WMP.SessionID, false)
	}
}

// CapabilityList returns the negotiated capabilities of the session.
func (h *wmpHandler) CapabilityList(ctx context.Context, _ *wmp.CapabilityListParams) (*wmp.CapabilityListResult, error) {
	sess := wmp.SessionFromContext(ctx)
	if sess == nil {
		return nil, wmp.NewRPCError(wmp.ErrSessionNotFound, nil)
	}
	return &wmp.CapabilityListResult{
		WMP:          wmp.Metadata{Version: wmp.Version, SessionID: sess.ID},
		Capabilities: sess.Capabilities,
		Security:     sess.Security,
	}, nil
}

// CredentialNotification routes a wmp.credential.notification (OID4VCI 10) to
// the engine's notification forwarding. The TAC check ran in the guard.
func (h *wmpHandler) CredentialNotification(_ context.Context, params *wmp.CredentialNotificationParams) {
	ws := h.a.session(h.sessionID)
	if ws == nil {
		return
	}
	h.a.manager.dispatchCredentialNotification(ws.session, &CredentialNotificationMessage{
		Message:          Message{Type: TypeCredentialNotification, FlowID: params.FlowID},
		NotificationID:   params.NotificationID,
		Event:            params.Event,
		EventDescription: params.EventDescription,
	})
}

// Resolve answers wmp.resolve for vctm (Core 5.8.1, OpenID4x 2): the type
// metadata of a vct, looked up as the VCTM flow does, as the six members the
// resolution carries (go-wmp's ProjectVCTM). A lookup that finds no document,
// cannot reach one or finds one that is not an object is the -32603 error
// {"reason": "metadata_fetch_error"}, carrying nothing of the failure; null
// metadata is only for a lookup that knows the type is unknown (the registry
// has no entry and the vct is not a URL). An empty uri is -32602; the egress
// policy (loopback, private, non-HTTPS refused) is that of the lookup's HTTP
// client. Every other type is unsupported (-31005).
func (h *wmpHandler) Resolve(ctx context.Context, params *wmp.ResolveParams) (*wmp.ResolveResult, error) {
	sess := wmp.SessionFromContext(ctx)
	if params.Type != wmp.ResolveTypeVCTM {
		return nil, wmp.NewUnsupportedError(params.Type, nil)
	}
	if sess == nil || !sess.HasCapability("resolve") {
		return nil, wmp.NewUnsupportedError("resolve", nil)
	}
	if err := wmp.ValidateVCTMResolveParams(params); err != nil {
		return nil, err
	}
	h.a.manager.handlersMu.RLock()
	factory, ok := h.a.manager.flowHandlers[ProtocolVCTM]
	h.a.manager.handlersMu.RUnlock()
	if !ok {
		return nil, wmp.NewUnsupportedError(params.Type, nil)
	}
	m := h.a.manager
	handler, err := factory(&Flow{ID: "resolve"}, m.cfg, h.a.logger, m.trustService, m.registryClient, m.verifierStore, m.trustCache)
	if err != nil {
		return nil, wmp.NewRPCError(wmp.ErrInternalError, nil)
	}
	vctm, ok := handler.(*VCTMHandler)
	if !ok {
		return nil, wmp.NewUnsupportedError(params.Type, nil)
	}
	doc, err := vctm.lookupVCTDocument(ctx, params.URI)
	if errors.Is(err, errVCTMUnknown) {
		return wmp.NewUnknownResolveResult(sess.ID, params.Type, params.URI), nil
	}
	if err != nil {
		h.a.logger.Debug("WMP resolve vctm failed", zap.Error(err))
		return nil, wmp.NewMetadataFetchError()
	}
	res, err := wmp.NewVCTMResolveResult(sess.ID, params.URI, doc)
	if err != nil {
		h.a.logger.Debug("WMP resolve vctm: document cannot be carried", zap.Error(err))
		return nil, wmp.NewMetadataFetchError()
	}
	return res, nil
}
