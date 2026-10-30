package engine

// The credential_notification flow over WMP (OpenID4x 3.4): after an issuance has
// completed, the wallet starts a new flow that reports an OID4VCI notification
// event, and the engine forwards it to the issuer from the context it retained at
// the completion (see registerNotificationContext). go-wmp runs the flow
// (openid4x.NotificationFlow); this file is the engine's side of it, the
// openid4x.NotificationForwarder:
//
//   - the context is the issuance's, in this session and for this principal;
//   - each notification_id is used once (notificationContextStore.claim);
//   - a token bound to a key only the wallet holds gets its DPoP proof from a
//     nested sign_client_auth flow, for the htu the profile fixes (the endpoint
//     without query and fragment); the request goes to the full endpoint;
//   - nothing of the issuer or the wallet reaches the wallet's error: only
//     the reason.
//
// The older wmp.credential.notification method (wmpHandler.CredentialNotification)
// is not in the profile and cannot ask for a DPoP proof: it is superseded by
// this flow and kept as it was.

import (
	"context"
	"errors"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"go.uber.org/zap"
)

// defaultNotificationFlowTimeout bounds a credential_notification flow that names
// no timeout of its own: up to two DPoP proofs (each bounded by go-wmp's
// sign timeout) and the request to the issuer.
const defaultNotificationFlowTimeout = time.Minute

// notificationEvents are the events the engine forwards (OpenID4x 2.4, 3.4.1).
// credential_deleted is not forwarded: the token is gone by then.
func notificationEvents() []string {
	return []string{notificationEventAccepted, notificationEventFailure}
}

// runNotification is the FlowFunc of the credential_notification flow type.
func (p *wmpFlowProfile) runNotification() wmp.FlowFunc {
	flow := openid4x.NotificationFlow(&wmpNotificationForwarder{a: p.a, sessionID: p.sessionID},
		openid4x.NotificationFlowOptions{Events: notificationEvents()})
	return func(ctx context.Context, fc *wmp.FlowContext) error {
		ws := p.a.session(p.sessionID)
		if ws == nil {
			return errors.New("session closed")
		}
		timeout := defaultNotificationFlowTimeout
		if v, ok := p.timeouts.LoadAndDelete(fc.FlowID); ok {
			if d, isDuration := v.(time.Duration); isDuration {
				timeout = d
			}
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		defer p.guard.starting.Delete(fc.FlowID)
		// The flow ends with the engine session: endSession cancels only flows
		// that have a Handler (this one has none), and an in-process peer is not
		// closed with the session, so without this an unanswered sign request or
		// a slow issuer would hold the forwarding slot until the timeout.
		go func() {
			select {
			case <-ws.session.closeCh:
				cancel()
			case <-ctx.Done():
			}
		}()
		// The flow takes a slot of the session's concurrent-flow limit, like every
		// flow (an unanswered sign request holds it until the flow's timeout), and
		// is registered as an oid4vci flow: that is what makes the guard require the
		// issuance permission of every message about it and about its sign
		// sub-flow. A flow_id already in use is not a new flow. At the limit the
		// flow ends busy, retryable.
		if _, err := ws.session.reserveFlow(fc.FlowID, ProtocolOID4VCI, true); err != nil {
			if errors.Is(err, errFlowIDInUse) || errors.Is(err, errSessionEnded) {
				return err
			}
			return fc.Error(ctx, wmp.ErrFlowError, wmp.ErrorMessage(wmp.ErrFlowError),
				openid4x.NotificationErrorData{Reason: openid4x.NotificationReasonBusy, Retryable: true})
		}
		defer ws.session.releaseFlow(fc.FlowID)
		if !ws.tr.addIfAbsent(fc.FlowID, &wmpFlow{fc: fc, session: wmp.SessionFromContext(ctx)}) {
			return errFlowIDInUse
		}
		defer ws.tr.remove(fc.FlowID)
		return flow(ctx, fc)
	}
}

// wmpNotificationForwarder implements openid4x.NotificationForwarder over the
// engine's notification context store.
type wmpNotificationForwarder struct {
	a         *WMPAdapter
	sessionID string
}

// ForwardNotification forwards the notification of req to the issuer. The errors
// select the flow's reason (openid4x.NotificationFailure): no usable context,
// the forwarding limit (the context is kept), a refused or failed DPoP signing,
// anything else from the issuer.
func (f *wmpNotificationForwarder) ForwardNotification(ctx context.Context, req openid4x.NotificationRequest, sign openid4x.ClientAuthSigner) error {
	ws := f.a.session(f.sessionID)
	principal, ok := wmp.PrincipalFromContext(ctx)
	if ws == nil || req.SessionID != f.sessionID || !ok || principal.Key() == "" || ws.session.notifications == nil {
		return openid4x.ErrNotificationContextUnavailable
	}
	// The limit is checked before the context is used: a notification turned
	// away as busy leaves the context, and the id, for the wallet's retry.
	m := f.a.manager
	select {
	case m.notificationSem <- struct{}{}:
		defer func() { <-m.notificationSem }()
	default:
		return openid4x.ErrNotificationBusy
	}
	nc := ws.session.notifications.claim(req.IssuanceFlowID, principal.Key(), req.NotificationID)
	if nc == nil {
		return openid4x.ErrNotificationContextUnavailable
	}
	if _, clientHeld := nc.dpopSigner.(*clientHeldDPoPSigner); clientHeld {
		// The key is the wallet's: ask for each proof with a nested sign flow
		// of this notification flow (the legacy signer addresses the issuance
		// flow, which has ended).
		nc.dpopSigner = &subFlowDPoPSigner{sign: sign, audience: nc.issuer}
	}
	httpClient := m.cfg.HTTPClient.NewHTTPClient(0)
	logger := f.a.logger.With(zap.String("flow", req.FlowID))
	if err := sendNotification(ctx, httpClient, nc, req.NotificationID, req.Event, req.EventDescription, logger); err != nil {
		logger.Warn("failed to forward credential notification to issuer", zap.Error(err))
		return err
	}
	logger.Debug("credential notification forwarded to issuer")
	return nil
}

// subFlowDPoPSigner is the dpopProofSigner of a notification whose key the wallet
// holds: each proof is a sign_client_auth sub-flow of the notification flow.
type subFlowDPoPSigner struct {
	sign     openid4x.ClientAuthSigner
	audience string
}

// Proof asks the wallet for a proof over htm and htu (already the endpoint
// without query and fragment) and the hash of the access token.
func (s *subFlowDPoPSigner) Proof(ctx context.Context, htm, htu, accessToken, nonce string) (string, error) {
	return s.sign(ctx, openid4x.ClientAuthRequest{
		HTM: htm, HTU: htu, ATH: accessTokenHash(accessToken), DPoPNonce: nonce, Audience: s.audience,
	})
}
