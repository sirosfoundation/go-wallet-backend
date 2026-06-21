package engine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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
	dpopKey     *ecdsa.PrivateKey
	dpopNonce   string
	expiresAt   time.Time
}

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
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, nc.endpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		setNotificationAuthHeader(req, nc)
		if nc.dpopKey != nil && strings.EqualFold(nc.tokenType, "DPoP") {
			proof, err := createDPoPProof(nc.dpopKey, req.Method, nc.endpoint, nc.accessToken, dpopNonce)
			if err != nil {
				return fmt.Errorf("failed to create DPoP proof for notification: %w", err)
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
