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
	// seq identifies this registration within its store (set by put), so a
	// restore can tell it apart from a newer one for the same flow ID.
	seq uint64
}

// notificationContextStore is an in-memory, TTL-bounded registry of
// notificationContext values keyed by flow ID. All state is ephemeral and
// scoped to a live WebSocket session; nothing is persisted.
type notificationContextStore struct {
	mu  sync.Mutex
	ctx map[string]*notificationContext
	// latest records the newest registration per flow ID, whether or not it is
	// still in ctx (it may be in flight), so restore never revives a
	// superseded one. Entries are pruned once older than the context TTL.
	latest map[string]latestRegistration
	seq    uint64
	// closed is set when the session ends: nothing is registered or restored
	// afterwards.
	closed bool
}

type latestRegistration struct {
	seq uint64
	at  time.Time
}

func newNotificationContextStore() *notificationContextStore {
	return &notificationContextStore{ctx: make(map[string]*notificationContext), latest: make(map[string]latestRegistration)}
}

// put registers a notification context for the given flow ID with a bounded TTL.
func (s *notificationContextStore) put(flowID string, nc *notificationContext) {
	if flowID == "" || nc == nil || nc.endpoint == "" {
		return
	}
	nc.expiresAt = time.Now().Add(notificationContextTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.pruneLocked()
	s.seq++
	nc.seq = s.seq
	s.latest[flowID] = latestRegistration{seq: nc.seq, at: time.Now()}
	s.ctx[flowID] = nc
}

// invalidate drops whatever context the flow ID holds and makes it the newest
// generation, so a context of an earlier issuance that is in flight cannot be
// restored under it. The flow ID is the client's choice and may be reused: a
// flow that takes the ID starts with no context, and only its own registration
// can create one. Without this, a second issuance that registers nothing (no
// notification endpoint, a failure, another issuer) would leave the first
// issuance's context reachable, and a notification for the second would be sent
// to the first issuer with the first issuer's token.
func (s *notificationContextStore) invalidate(flowID string) {
	if flowID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ctx, flowID)
	if s.closed {
		return
	}
	s.seq++
	s.latest[flowID] = latestRegistration{seq: s.seq, at: time.Now()}
}

// clear drops every context, with the token and signer each holds, when the
// session ends, and refuses any later registration.
func (s *notificationContextStore) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	clear(s.ctx)
	clear(s.latest)
}

// take returns and removes the notification context for the given flow ID.
// The caller spends it by contacting the issuer; if the request never left
// (see notificationNotSentError) it hands the context back with restore.
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
	return nc.notificationID == "" || nc.notificationID == notificationID
}

// restore puts back a context that take removed but whose notification never
// reached the issuer, keeping its original expiry so a retry cannot extend the
// context's life. It does nothing when the context has expired or the flow has
// registered a newer one in the meantime.
func (s *notificationContextStore) restore(flowID string, nc *notificationContext) {
	if flowID == "" || nc == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || time.Now().After(nc.expiresAt) {
		return
	}
	if _, taken := s.ctx[flowID]; taken {
		return
	}
	if l, ok := s.latest[flowID]; !ok || l.seq != nc.seq {
		return // superseded by a newer registration, which owns the flow ID now
	}
	s.ctx[flowID] = nc
}

// notificationNotSentError marks a notification that failed before anything was
// sent to the issuer (the DPoP proof could not be obtained). The single-use
// context is spent only when the issuer was contacted, so this is the one
// failure after which the caller puts the context back for a retry.
type notificationNotSentError struct{ err error }

func (e *notificationNotSentError) Error() string { return e.err.Error() }
func (e *notificationNotSentError) Unwrap() error { return e.err }

// pruneLocked removes expired entries. Caller must hold s.mu.
func (s *notificationContextStore) pruneLocked() {
	now := time.Now()
	for id, nc := range s.ctx {
		if now.After(nc.expiresAt) {
			delete(s.ctx, id)
		}
	}
	for id, l := range s.latest {
		if now.Sub(l.at) > notificationContextTTL {
			delete(s.latest, id)
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
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, nc.endpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		setNotificationAuthHeader(req, nc)
		if nc.dpopSigner != nil && strings.EqualFold(nc.tokenType, "DPoP") {
			proof, err := nc.dpopSigner.Proof(ctx, req.Method, nc.endpoint, nc.accessToken, dpopNonce)
			if err != nil {
				err = fmt.Errorf("failed to create DPoP proof for notification: %w", err)
				if attempt == 0 {
					// Nothing has reached the issuer yet. On the nonce retry
					// it has, so the context stays spent.
					return &notificationNotSentError{err: err}
				}
				return err
			}
			req.Header.Set("DPoP", proof)
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

		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
		_ = resp.Body.Close()

		// Per OID4VCI §10, the issuer responds with 204 No Content on success.
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
	return fmt.Errorf("notification request failed after DPoP nonce retry")
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
