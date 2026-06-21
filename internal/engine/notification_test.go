package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ===== notificationContextStore tests =====

func TestNotificationContextStore_PutTake_OneShot(t *testing.T) {
	s := newNotificationContextStore()
	s.put("flow-1", &notificationContext{endpoint: "https://issuer.example.com/notify"})

	got := s.take("flow-1")
	require.NotNil(t, got)
	assert.Equal(t, "https://issuer.example.com/notify", got.endpoint)

	// Second take must return nil (one-shot semantics).
	assert.Nil(t, s.take("flow-1"))
}

func TestNotificationContextStore_Put_IgnoresEmptyEndpoint(t *testing.T) {
	s := newNotificationContextStore()
	s.put("flow-1", &notificationContext{endpoint: ""})
	assert.Nil(t, s.take("flow-1"))
}

func TestNotificationContextStore_Take_ExpiredReturnsNil(t *testing.T) {
	s := newNotificationContextStore()
	s.ctx["flow-1"] = &notificationContext{
		endpoint:  "https://issuer.example.com/notify",
		expiresAt: time.Now().Add(-time.Minute),
	}
	assert.Nil(t, s.take("flow-1"))
}

func TestNotificationContextStore_Take_MissingReturnsNil(t *testing.T) {
	s := newNotificationContextStore()
	assert.Nil(t, s.take("nope"))
}

func TestNotificationContextStore_Put_PrunesExpired(t *testing.T) {
	s := newNotificationContextStore()
	s.ctx["old"] = &notificationContext{
		endpoint:  "https://issuer.example.com/notify",
		expiresAt: time.Now().Add(-time.Minute),
	}
	// put triggers pruneLocked.
	s.put("new", &notificationContext{endpoint: "https://issuer.example.com/notify"})

	s.mu.Lock()
	_, oldExists := s.ctx["old"]
	s.mu.Unlock()
	assert.False(t, oldExists, "expired entry should be pruned")
}

// ===== isValidNotificationEvent tests =====

func TestIsValidNotificationEvent(t *testing.T) {
	cases := map[string]bool{
		notificationEventAccepted: true,
		notificationEventFailure:  true,
		"credential_deleted":      false,
		"":                        false,
		"bogus":                   false,
	}
	for event, want := range cases {
		assert.Equalf(t, want, isValidNotificationEvent(event), "event=%q", event)
	}
}

// ===== sendNotification tests =====

func TestSendNotification_BearerSuccess(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	nc := &notificationContext{
		endpoint:    srv.URL,
		accessToken: "tok-123",
		tokenType:   "Bearer",
		expiresAt:   time.Now().Add(time.Minute),
	}

	err := sendNotification(context.Background(), srv.Client(), nc,
		"notif-1", notificationEventAccepted, "stored ok", zap.NewNop())
	require.NoError(t, err)

	assert.Equal(t, "Bearer tok-123", gotAuth)

	var payload notificationRequestBody
	require.NoError(t, json.Unmarshal([]byte(gotBody), &payload))
	assert.Equal(t, "notif-1", payload.NotificationID)
	assert.Equal(t, notificationEventAccepted, payload.Event)
	assert.Equal(t, "stored ok", payload.EventDescription)
}

func TestSendNotification_DPoPSuccess(t *testing.T) {
	var gotAuth, gotDPoP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotDPoP = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	nc := &notificationContext{
		endpoint:    srv.URL,
		accessToken: "tok-dpop",
		tokenType:   "DPoP",
		dpopKey:     key,
		expiresAt:   time.Now().Add(time.Minute),
	}

	err = sendNotification(context.Background(), srv.Client(), nc,
		"notif-2", notificationEventFailure, "", zap.NewNop())
	require.NoError(t, err)

	assert.Equal(t, "DPoP tok-dpop", gotAuth)
	assert.NotEmpty(t, gotDPoP, "DPoP proof header must be present for DPoP-bound tokens")
}

func TestSendNotification_DPoPNonceRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.Header().Set("DPoP-Nonce", "fresh-nonce")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	nc := &notificationContext{
		endpoint:    srv.URL,
		accessToken: "tok-dpop",
		tokenType:   "DPoP",
		dpopKey:     key,
		expiresAt:   time.Now().Add(time.Minute),
	}

	err = sendNotification(context.Background(), srv.Client(), nc,
		"notif-3", notificationEventAccepted, "", zap.NewNop())
	require.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "should retry once after DPoP nonce challenge")
}

func TestSendNotification_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	nc := &notificationContext{
		endpoint:    srv.URL,
		accessToken: "tok",
		tokenType:   "Bearer",
		expiresAt:   time.Now().Add(time.Minute),
	}

	err := sendNotification(context.Background(), srv.Client(), nc,
		"notif-4", notificationEventAccepted, "", zap.NewNop())
	require.Error(t, err)
}

// ===== handleCredentialNotification tests =====

// notifTestManager builds a Manager whose HTTP client targets the given issuer.
func notifTestManager() *Manager {
	return &Manager{
		cfg:    testConfig(),
		logger: zap.NewNop(),
	}
}

// notifTestSession returns a Session with the notification store initialized.
func notifTestSession(conn *websocket.Conn) *Session {
	s := testSession(conn)
	s.notifications = newNotificationContextStore()
	return s
}

func TestHandleCredentialNotification_ForwardsAndAcks(t *testing.T) {
	var issuerCalls int32
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&issuerCalls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer issuer.Close()

	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var ack map[string]interface{}
		_ = json.Unmarshal(data, &ack)
		_ = srvConn.WriteJSON(ack)
	})
	defer cleanup()

	session := notifTestSession(conn)
	session.notifications.put("flow-9", &notificationContext{
		endpoint:    issuer.URL,
		accessToken: "tok",
		tokenType:   "Bearer",
	})

	m := notifTestManager()
	m.handleCredentialNotification(session, &CredentialNotificationMessage{
		Message:        Message{Type: TypeCredentialNotification, FlowID: "flow-9"},
		NotificationID: "notif-9",
		Event:          notificationEventAccepted,
	})

	var ack NotificationAckMessage
	require.NoError(t, conn.ReadJSON(&ack))
	assert.Equal(t, "forwarded", ack.Status)
	assert.Equal(t, "notif-9", ack.NotificationID)
	assert.Equal(t, int32(1), atomic.LoadInt32(&issuerCalls))

	// Context must be consumed (one-shot).
	assert.Nil(t, session.notifications.take("flow-9"))
}

func TestHandleCredentialNotification_RejectsUnsupportedEvent(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var ack map[string]interface{}
		_ = json.Unmarshal(data, &ack)
		_ = srvConn.WriteJSON(ack)
	})
	defer cleanup()

	session := notifTestSession(conn)
	// Even with a valid context present, credential_deleted must be rejected.
	session.notifications.put("flow-1", &notificationContext{endpoint: "https://issuer.example.com/notify"})

	m := notifTestManager()
	m.handleCredentialNotification(session, &CredentialNotificationMessage{
		Message:        Message{Type: TypeCredentialNotification, FlowID: "flow-1"},
		NotificationID: "notif-1",
		Event:          "credential_deleted",
	})

	var ack NotificationAckMessage
	require.NoError(t, conn.ReadJSON(&ack))
	assert.Equal(t, "rejected", ack.Status)
	assert.Contains(t, ack.Error, "unsupported event")
}

func TestHandleCredentialNotification_RejectsMissingNotificationID(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var ack map[string]interface{}
		_ = json.Unmarshal(data, &ack)
		_ = srvConn.WriteJSON(ack)
	})
	defer cleanup()

	session := notifTestSession(conn)
	m := notifTestManager()
	m.handleCredentialNotification(session, &CredentialNotificationMessage{
		Message: Message{Type: TypeCredentialNotification, FlowID: "flow-1"},
		Event:   notificationEventAccepted,
	})

	var ack NotificationAckMessage
	require.NoError(t, conn.ReadJSON(&ack))
	assert.Equal(t, "rejected", ack.Status)
	assert.Contains(t, ack.Error, "missing notification_id")
}

func TestHandleCredentialNotification_RejectsMissingContext(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var ack map[string]interface{}
		_ = json.Unmarshal(data, &ack)
		_ = srvConn.WriteJSON(ack)
	})
	defer cleanup()

	session := notifTestSession(conn)
	m := notifTestManager()
	m.handleCredentialNotification(session, &CredentialNotificationMessage{
		Message:        Message{Type: TypeCredentialNotification, FlowID: "unknown-flow"},
		NotificationID: "notif-1",
		Event:          notificationEventAccepted,
	})

	var ack NotificationAckMessage
	require.NoError(t, conn.ReadJSON(&ack))
	assert.Equal(t, "rejected", ack.Status)
	assert.Contains(t, ack.Error, "notification context unavailable")
}

// ===== message serialization tests =====

func TestCredentialNotificationMessage_Roundtrip(t *testing.T) {
	original := CredentialNotificationMessage{
		Message:          Message{Type: TypeCredentialNotification, FlowID: "flow-1"},
		NotificationID:   "notif-1",
		Event:            notificationEventAccepted,
		EventDescription: "user accepted",
	}
	data, err := json.Marshal(original)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"credential_notification"`)

	var decoded CredentialNotificationMessage
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, original.NotificationID, decoded.NotificationID)
	assert.Equal(t, original.Event, decoded.Event)
	assert.Equal(t, original.EventDescription, decoded.EventDescription)
}

func TestCredentialResult_IncludesNotificationID(t *testing.T) {
	r := CredentialResult{
		Format:         "dc+sd-jwt",
		Credential:     "eyJ...",
		NotificationID: "notif-xyz",
	}
	data, err := json.Marshal(r)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"notification_id":"notif-xyz"`)
}

func TestCredentialResult_OmitsEmptyNotificationID(t *testing.T) {
	r := CredentialResult{Format: "dc+sd-jwt", Credential: "eyJ..."}
	data, err := json.Marshal(r)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "notification_id")
}
