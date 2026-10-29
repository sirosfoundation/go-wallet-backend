package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"go.uber.org/zap"
)

// notificationContextTTL bounds how long the backend retains the ephemeral
// issuance context needed to authenticate an OID4VCI §10 notification. It is
// intentionally short: notifications for credential_accepted/credential_failure
// are sent by the client immediately after a flow completes, while the
// issuance access token is still valid. The context is never persisted.
const notificationContextTTL = 5 * time.Minute

// maxConcurrentNotifications bounds how many credential notifications may be
// forwarded to issuers concurrently across all sessions. It provides
// backpressure so a client cannot spawn an unbounded number of outbound HTTP
// requests by flooding credential_notification messages.
const maxConcurrentNotifications = 32

// Valid OID4VCI §10 notification events that the client may report to the
// backend for forwarding. credential_deleted is intentionally unsupported:
// it occurs long after issuance, when the access token has expired and the
// notification can no longer be authenticated.
const (
	notificationEventAccepted = "credential_accepted"
	notificationEventFailure  = "credential_failure"
)

// notificationContext holds the minimal, ephemeral state required to forward a
// single OID4VCI §10 notification to the issuer's notification endpoint. It is
// captured at flow completion and discarded after first use or TTL expiry. It
// is never written to storage — the backend remains zero-knowledge about the
// credential itself.
type notificationContext struct {
	endpoint    string
	accessToken string
	tokenType   string
	// dpopSigner signs the DPoP proof when the issuance token was DPoP-bound:
	// the engine-held key in legacy mode, or a client-held signer that asks
	// the client over the still-open session (see clientHeldDPoPSigner).
	dpopSigner dpopProofSigner
	dpopNonce  string
	// notificationID is the value the issuer returned for this Credential
	// Response. Per OID4VCI §8.3/§11 there is exactly one notification_id per
	// response (covering one or more credentials), so the client-supplied ID
	// is validated against this value before any notification is forwarded.
	notificationID string
	expiresAt      time.Time

	// issuer is the credential issuer identifier (the DPoP audience of a
	// client-signed proof). principal is the WMP principal that ran the
	// issuance, "" over WebSocket, where the connection is the binding; a WMP
	// notification flow can use only a context of its own principal.
	issuer    string
	principal string
	// notified are the notification_ids already forwarded over WMP: each id is
	// single use (WMP OpenID4x 3.4.2). A context whose notificationID is empty
	// (an encrypted response, whose id the engine never saw) accepts any id
	// the wallet names, once each, up to maxBlindNotificationIDs.
	notified map[string]struct{}
}

// maxBlindNotificationIDs bounds the ids a context that knows none accepts
// (WMP OpenID4x 3.4.2: 256 per issuance).
const maxBlindNotificationIDs = 256

// notificationContextStore is an in-memory, TTL-bounded registry of
// notificationContext values keyed by flow ID. All state is ephemeral and
// scoped to a live WebSocket session; nothing is persisted.
type notificationContextStore struct {
	mu  sync.Mutex
	ctx map[string]*notificationContext
}

func newNotificationContextStore() *notificationContextStore {
	return &notificationContextStore{ctx: make(map[string]*notificationContext)}
}

// put registers a notification context for the given flow ID with a bounded TTL.
func (s *notificationContextStore) put(flowID string, nc *notificationContext) {
	if flowID == "" || nc == nil || nc.endpoint == "" {
		return
	}
	nc.expiresAt = time.Now().Add(notificationContextTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	s.ctx[flowID] = nc
}

// take returns and removes the notification context for the given flow ID.
// It returns nil if the context is absent or expired (one-shot semantics).
func (s *notificationContextStore) take(flowID string) *notificationContext {
	s.mu.Lock()
	defer s.mu.Unlock()
	nc, ok := s.ctx[flowID]
	if !ok {
		return nil
	}
	delete(s.ctx, flowID)
	if time.Now().After(nc.expiresAt) {
		return nil
	}
	return nc
}

// claim is the WMP counterpart of take: it marks notificationID of the context
// of flowID as notified and returns a copy of the context to forward with, or nil
// when there is none to use: the context is absent, expired, retained for
// another principal, the id is not one the context knows or was already
// notified, or a context that knows no id has accepted its maximum. The
// reasons are not told apart. The context stays for the issuance's other ids
// until its TTL; once its only known id is notified it is gone.
func (s *notificationContextStore) claim(flowID, principal, notificationID string) *notificationContext {
	if principal == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	nc, ok := s.ctx[flowID]
	if !ok || nc.principal != principal {
		return nil
	}
	return s.useLocked(flowID, nc, notificationID)
}

// useLocked marks notificationID of nc notified, once, and returns a copy of the
// context to forward with; nil when the context expired, the id is empty,
// unknown, already notified, or a context that knows no id has accepted its
// maximum. It is the one consumption record both notification entry points
// (the flow and the legacy method) use. Caller must hold s.mu.
func (s *notificationContextStore) useLocked(flowID string, nc *notificationContext, notificationID string) *notificationContext {
	if time.Now().After(nc.expiresAt) || notificationID == "" || utf8.RuneCountInString(notificationID) > openid4x.MaxNotificationIDLen {
		// An id beyond the profile's bound is never recorded: a context that
		// knows no id would otherwise hold up to 256 of them, however long.
		return nil
	}
	if _, done := nc.notified[notificationID]; done {
		return nil
	}
	if nc.notificationID != "" {
		if nc.notificationID != notificationID {
			return nil
		}
		delete(s.ctx, flowID) // its one id is used
	} else {
		if len(nc.notified) >= maxBlindNotificationIDs {
			return nil
		}
		if nc.notified == nil {
			nc.notified = make(map[string]struct{})
		}
		nc.notified[notificationID] = struct{}{}
	}
	used := *nc
	used.notified = nil
	return &used
}

// takeForNotification is the legacy wmp.credential.notification / WebSocket
// counterpart of claim: a WebSocket context (no principal) is consumed whole, as
// take does; a context retained for a WMP session is used per notification_id
// through the same record as claim, so an id forwarded by the flow cannot be
// forwarded again by the legacy method, and the unused ids stay usable.
func (s *notificationContextStore) takeForNotification(flowID, notificationID string) *notificationContext {
	s.mu.Lock()
	nc, ok := s.ctx[flowID]
	if ok && nc.principal != "" {
		defer s.mu.Unlock()
		return s.useLocked(flowID, nc, notificationID)
	}
	s.mu.Unlock()
	return s.take(flowID)
}

// wmpEndpointFor is the notification endpoint of the live context of flowID, when
// it was retained for a WMP principal, or "": what the WMP completion tells the
// wallet to record.
func (s *notificationContextStore) wmpEndpointFor(flowID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	nc, ok := s.ctx[flowID]
	if !ok || time.Now().After(nc.expiresAt) || nc.principal == "" {
		return ""
	}
	return nc.endpoint
}

// hasValid reports whether a non-expired notification context exists for the
// given flow ID whose stored notification_id matches the supplied value. It
// does not consume the context. An empty stored notificationID matches any
// supplied value. That is the normal case for an encrypted issuer response: the
// engine cannot read the notification_id, registers the context with an empty
// id and the client supplies the real one (see registerNotificationContext).
func (s *notificationContextStore) hasValid(flowID, notificationID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	nc, ok := s.ctx[flowID]
	if !ok || time.Now().After(nc.expiresAt) {
		return false
	}
	if _, done := nc.notified[notificationID]; done {
		return false
	}
	return nc.notificationID == "" || nc.notificationID == notificationID
}

// pruneLocked removes expired entries. Caller must hold s.mu.
func (s *notificationContextStore) pruneLocked() {
	now := time.Now()
	for id, nc := range s.ctx {
		if now.After(nc.expiresAt) {
			delete(s.ctx, id)
		}
	}
}

// isValidNotificationEvent reports whether event is a client-reportable
// OID4VCI §10 notification event that the backend is willing to forward.
func isValidNotificationEvent(event string) bool {
	switch event {
	case notificationEventAccepted, notificationEventFailure:
		return true
	default:
		return false
	}
}

// notificationRequestBody is the OID4VCI §10 Notification Request payload.
type notificationRequestBody struct {
	NotificationID   string `json:"notification_id"`
	Event            string `json:"event"`
	EventDescription string `json:"event_description,omitempty"`
}

// sendNotification POSTs a single OID4VCI §10 Notification Request to the
// issuer's notification endpoint using the ephemeral issuance credentials held
// in nc. The supplied httpClient is expected to enforce SSRF protections.
func sendNotification(ctx context.Context, httpClient *http.Client, nc *notificationContext, notificationID, event, eventDescription string, logger *zap.Logger) error {
	payload := notificationRequestBody{
		NotificationID:   notificationID,
		Event:            event,
		EventDescription: eventDescription,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal notification request: %w", err)
	}

	// Notification request with DPoP nonce retry (RFC 9449 §8), mirroring the
	// credential request path.
	dpopNonce := nc.dpopNonce
	for attempt := 0; attempt < 2; attempt++ {
		req, err := newNotificationRequest(ctx, nc, bodyBytes, dpopNonce)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("notification request failed: %w", err)
		}

		if attempt == 0 && isDPoPNonceError(resp) {
			if newNonce := resp.Header.Get("DPoP-Nonce"); newNonce != "" {
				dpopNonce = newNonce
			}
			_ = resp.Body.Close()
			continue
		}

		return notificationResult(resp, logger)
	}
	return fmt.Errorf("notification request failed after DPoP nonce retry")
}

// notificationResult is the outcome of the issuer's answer to a Notification
// Request: per OID4VCI §10 it responds with 204 No Content on success.
func notificationResult(resp *http.Response, logger *zap.Logger) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	if logger != nil {
		logger.Debug("notification endpoint returned non-success status",
			zap.Int("status", resp.StatusCode),
			zap.String("body", string(body)))
	}
	return fmt.Errorf("notification endpoint returned status %d", resp.StatusCode)
}

// dpopHTU is the htu of a DPoP proof for the request to endpoint: the endpoint
// without query and fragment (RFC 9449 section 4.2); the request itself goes to
// the full endpoint. WMP OpenID4x 3.4.3 has the wallet sign exactly this.
func dpopHTU(endpoint string) string {
	if htu, err := openid4x.NotificationHTU(endpoint); err == nil {
		return htu
	}
	return endpoint
}

// newNotificationRequest builds the Notification Request to the full endpoint,
// authorized with the retained token and, when the token is DPoP-bound, with a
// proof over the endpoint without query and fragment.
func newNotificationRequest(ctx context.Context, nc *notificationContext, body []byte, dpopNonce string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nc.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	setNotificationAuthHeader(req, nc)
	if nc.dpopSigner != nil && strings.EqualFold(nc.tokenType, "DPoP") {
		proof, err := nc.dpopSigner.Proof(ctx, req.Method, dpopHTU(nc.endpoint), nc.accessToken, dpopNonce)
		if err != nil {
			return nil, fmt.Errorf("failed to create DPoP proof for notification: %w", err)
		}
		req.Header.Set("DPoP", proof)
	}
	return req, nil
}

// setNotificationAuthHeader sets the Authorization header using the DPoP scheme
// when the issuance token was DPoP-bound, otherwise Bearer.
func setNotificationAuthHeader(req *http.Request, nc *notificationContext) {
	if strings.EqualFold(nc.tokenType, "DPoP") {
		req.Header.Set("Authorization", "DPoP "+nc.accessToken)
	} else {
		req.Header.Set("Authorization", "Bearer "+nc.accessToken)
	}
}
