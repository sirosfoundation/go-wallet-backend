package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestSendNotification_Success(t *testing.T) {
	var received atomic.Value

	// Mock issuer notification endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req notificationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		received.Store(req)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	h := &OID4VCIHandler{
		BaseHandler: BaseHandler{Logger: logger},
		httpClient:  srv.Client(),
	}

	metadata := &IssuerMetadata{
		NotificationEndpoint: srv.URL,
	}
	token := &TokenResponse{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
	}

	h.sendNotification(t.Context(), metadata, token, "notif-123", NotificationEventAccepted, "")

	req := received.Load().(notificationRequest)
	assert.Equal(t, "notif-123", req.NotificationID)
	assert.Equal(t, "credential_accepted", req.Event)
	assert.Empty(t, req.EventDescription)
}

func TestSendNotification_WithDescription(t *testing.T) {
	var received atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req notificationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		received.Store(req)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	h := &OID4VCIHandler{
		BaseHandler: BaseHandler{Logger: logger},
		httpClient:  srv.Client(),
	}

	metadata := &IssuerMetadata{NotificationEndpoint: srv.URL}
	token := &TokenResponse{AccessToken: "tok", TokenType: "Bearer"}

	h.sendNotification(t.Context(), metadata, token, "notif-456", NotificationEventDeleted, "User removed credential")

	req := received.Load().(notificationRequest)
	assert.Equal(t, "notif-456", req.NotificationID)
	assert.Equal(t, "credential_deleted", req.Event)
	assert.Equal(t, "User removed credential", req.EventDescription)
}

func TestSendNotification_NoEndpoint(t *testing.T) {
	logger := zap.NewNop()
	h := &OID4VCIHandler{
		BaseHandler: BaseHandler{Logger: logger},
		httpClient:  http.DefaultClient,
	}

	// Should not panic or make any HTTP call
	metadata := &IssuerMetadata{NotificationEndpoint: ""}
	token := &TokenResponse{AccessToken: "tok", TokenType: "Bearer"}
	h.sendNotification(t.Context(), metadata, token, "notif-789", NotificationEventAccepted, "")
}

func TestSendNotification_NoNotificationID(t *testing.T) {
	logger := zap.NewNop()
	h := &OID4VCIHandler{
		BaseHandler: BaseHandler{Logger: logger},
		httpClient:  http.DefaultClient,
	}

	metadata := &IssuerMetadata{NotificationEndpoint: "http://example.com/notify"}
	token := &TokenResponse{AccessToken: "tok", TokenType: "Bearer"}
	// Empty notification_id should be a no-op
	h.sendNotification(t.Context(), metadata, token, "", NotificationEventAccepted, "")
}

func TestSendNotification_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	h := &OID4VCIHandler{
		BaseHandler: BaseHandler{Logger: logger},
		httpClient:  srv.Client(),
	}

	metadata := &IssuerMetadata{NotificationEndpoint: srv.URL}
	token := &TokenResponse{AccessToken: "tok", TokenType: "Bearer"}

	// Should not panic — errors are logged but not returned
	h.sendNotification(t.Context(), metadata, token, "notif-err", NotificationEventAccepted, "")
}

func TestHandleCredentialNotification_Success(t *testing.T) {
	var received atomic.Value

	// Mock issuer notification endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req notificationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		received.Store(req)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	cfg := &config.Config{
		JWT:        config.JWTConfig{Secret: "test-secret"},
		HTTPClient: config.HTTPClientConfig{AllowPrivateIPs: true},
	}
	m := NewManager(cfg, logger)

	// Set up in-memory credential store
	store := memory.NewStore()
	m.SetCredentialStore(store.Credentials())

	// Store a credential with notification info
	cred := &domain.VerifiableCredential{
		TenantID:                   "default",
		HolderDID:                  "user-123",
		CredentialIdentifier:       "cred-abc",
		Credential:                 "jwt-here",
		Format:                     "vc+sd-jwt",
		CredentialConfigurationID:  "config-1",
		CredentialIssuerIdentifier: "https://issuer.example.com",
		NotificationID:             "notif-stored",
		NotificationEndpoint:       srv.URL,
	}
	err := store.Credentials().Create(t.Context(), cred)
	require.NoError(t, err)

	// Simulate a session
	session := &Session{
		UserID:   "user-123",
		TenantID: "default",
		logger:   logger,
	}

	// Handle the notification message
	msg := &CredentialNotificationMessage{
		CredentialIdentifier: "cred-abc",
		Event:                "credential_deleted",
		EventDescription:     "User deleted credential",
	}
	m.handleCredentialNotification(session, msg)

	req := received.Load().(notificationRequest)
	assert.Equal(t, "notif-stored", req.NotificationID)
	assert.Equal(t, "credential_deleted", req.Event)
	assert.Equal(t, "User deleted credential", req.EventDescription)
}

func TestHandleCredentialNotification_InvalidEvent(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{
		JWT: config.JWTConfig{Secret: "test-secret"},
	}
	m := NewManager(cfg, logger)

	session := &Session{
		UserID:   "user-123",
		TenantID: "default",
		logger:   logger,
	}

	msg := &CredentialNotificationMessage{
		CredentialIdentifier: "cred-abc",
		Event:                "invalid_event",
	}

	// Should not panic
	m.handleCredentialNotification(session, msg)
}

func TestHandleCredentialNotification_RejectsAccepted(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{
		JWT: config.JWTConfig{Secret: "test-secret"},
	}
	m := NewManager(cfg, logger)

	session := &Session{
		UserID:   "user-123",
		TenantID: "default",
		logger:   logger,
	}

	msg := &CredentialNotificationMessage{
		CredentialIdentifier: "cred-abc",
		Event:                "credential_accepted",
	}

	// Should not panic — credential_accepted is rejected from frontend
	m.handleCredentialNotification(session, msg)
}

func TestHandleCredentialNotification_NoCredentialStore(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{
		JWT: config.JWTConfig{Secret: "test-secret"},
	}
	m := NewManager(cfg, logger)

	session := &Session{
		UserID:   "user-123",
		TenantID: "default",
		logger:   logger,
	}

	msg := &CredentialNotificationMessage{
		CredentialIdentifier: "cred-abc",
		Event:                "credential_deleted",
	}

	// Should not panic when credentialStore is nil
	m.handleCredentialNotification(session, msg)
}

func TestBuildCredentialResults_IncludesNotificationFields(t *testing.T) {
	logger := zap.NewNop()
	h := &OID4VCIHandler{
		BaseHandler: BaseHandler{Logger: logger},
	}

	metadata := &IssuerMetadata{
		NotificationEndpoint: "https://issuer.example.com/notify",
	}
	resp := &CredentialResponse{
		Credential:     "eyJhbGciOi...",
		NotificationID: "notif-xyz",
	}
	cfg := &CredentialConfig{
		Format: "vc+sd-jwt",
		VCT:    "https://example.com/vct/1",
	}

	results := h.buildCredentialResults(t.Context(), resp, cfg, nil, metadata)
	require.Len(t, results, 1)
	assert.Equal(t, "notif-xyz", results[0].NotificationID)
	assert.Equal(t, "https://issuer.example.com/notify", results[0].NotificationEndpoint)
	assert.Equal(t, "eyJhbGciOi...", results[0].Credential)
	assert.Equal(t, "vc+sd-jwt", results[0].Format)
}

func TestCredentialNotificationMessage_JSONRoundtrip(t *testing.T) {
	msg := CredentialNotificationMessage{
		Message:              Message{Type: TypeCredentialNotification},
		CredentialIdentifier: "cred-123",
		Event:                "credential_deleted",
		EventDescription:     "Removed by user",
	}

	data, err := json.Marshal(msg)
	require.NoError(t, err)

	var parsed CredentialNotificationMessage
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, TypeCredentialNotification, parsed.Type)
	assert.Equal(t, "cred-123", parsed.CredentialIdentifier)
	assert.Equal(t, "credential_deleted", parsed.Event)
	assert.Equal(t, "Removed by user", parsed.EventDescription)
}
