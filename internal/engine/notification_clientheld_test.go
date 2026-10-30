package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests drive the credential_notification path for a CLIENT-HELD
// DPoP-bound token end to end over a real websocket: the issuance flow has
// already ended (it is not in session.flows), so the DPoP proof for the
// notification must come from a request context that outlives the flow.

type heldClientMode int

const (
	heldClientSigns heldClientMode = iota
	heldClientRefuses
	heldClientSilent
)

// heldNotifRig is a session whose issuance flow "flow-ended" is over, holding a
// client-held-DPoP notification context, plus a scripted client on the socket.
type heldNotifRig struct {
	session *Session
	mgr     *Manager
	client  *websocket.Conn
	issuer  *httptest.Server
	calls   *int32      // issuer requests received
	dpop    chan string // DPoP header of each issuer request
	signs   chan SignRequestMessage
	mode    atomic.Int32
}

func newHeldNotifRig(t *testing.T, issuedID string) *heldNotifRig {
	t.Helper()
	r := &heldNotifRig{dpop: make(chan string, 8), signs: make(chan SignRequestMessage, 8)}
	var calls int32
	r.calls = &calls
	r.issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		r.dpop <- req.Header.Get("DPoP")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.issuer.Close)

	// The real read loop (handleSession) receives the client's messages, so the
	// routing of a reply for an ended flow is exercised, not bypassed.
	r.mgr = notifTestManager()
	client, s := unknownFlowHarnessOn(t, r.mgr)
	s.notifications = newNotificationContextStore()
	r.session, r.client = s, client
	// "flow-ended" is deliberately NOT registered in s.flows.
	s.notifications.put("flow-ended", &notificationContext{
		endpoint:       r.issuer.URL,
		accessToken:    "at",
		tokenType:      "DPoP",
		dpopSigner:     &clientHeldDPoPSigner{session: s, flowID: "flow-ended", keyID: "key-1"},
		notificationID: issuedID,
	})
	return r
}

// run answers the engine's sign requests on the socket per r.mode and returns
// the notification_ack once it arrives.
func (r *heldNotifRig) ack(t *testing.T) NotificationAckMessage {
	t.Helper()
	for {
		_ = r.client.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, data, err := r.client.ReadMessage()
		require.NoError(t, err)
		var m Message
		require.NoError(t, json.Unmarshal(data, &m))
		switch m.Type {
		case TypeSignRequest:
			var req SignRequestMessage
			require.NoError(t, json.Unmarshal(data, &req))
			r.signs <- req
			resp := &SignResponseMessage{Message: Message{Type: TypeSignResponse, FlowID: req.FlowID, MessageID: req.MessageID}}
			switch heldClientMode(r.mode.Load()) {
			case heldClientSigns:
				resp.DPoPProof = "client-proof"
			case heldClientRefuses:
				resp.Error = "user said no: secret detail"
			case heldClientSilent:
				continue
			}
			require.NoError(t, r.client.WriteJSON(resp))
		case TypeNotificationAck:
			var a NotificationAckMessage
			require.NoError(t, json.Unmarshal(data, &a))
			return a
		}
	}
}

func (r *heldNotifRig) notify(id string) {
	_ = r.client.WriteJSON(&CredentialNotificationMessage{
		Message:        Message{Type: TypeCredentialNotification, FlowID: "flow-ended"},
		NotificationID: id,
		Event:          notificationEventAccepted,
	})
}

func TestClientHeldNotification_AfterFlowEnded_ForwardsWithClientProof(t *testing.T) {
	r := newHeldNotifRig(t, "n-1")
	r.notify("n-1")
	a := r.ack(t)
	require.Equal(t, "forwarded", a.Status)
	assert.Equal(t, "client-proof", recvOrFail(t, r.dpop), "issuer must receive the client-signed proof")
	req := recvOrFail(t, r.signs)
	assert.Equal(t, SignActionSignClientAuth, req.Action)
	assert.Equal(t, "key-1", req.Params.KeyID)
	assert.Equal(t, accessTokenHash("at"), req.Params.ATH)
	assert.Equal(t, int32(1), atomic.LoadInt32(r.calls))
}

func TestClientHeldNotification_ClientRefusal_DoesNotBurnContext(t *testing.T) {
	r := newHeldNotifRig(t, "n-1")
	r.mode.Store(int32(heldClientRefuses))
	r.notify("n-1")
	a := r.ack(t)
	assert.Equal(t, "rejected", a.Status)
	assert.NotContains(t, a.Error, "secret detail", "client text must never be echoed")
	assert.Equal(t, int32(0), atomic.LoadInt32(r.calls), "issuer must not be contacted without a proof")

	// The issuer was never contacted, so the context is still usable.
	r.mode.Store(int32(heldClientSigns))
	r.notify("n-1")
	assert.Equal(t, "forwarded", r.ack(t).Status)
	assert.Equal(t, int32(1), atomic.LoadInt32(r.calls))
}

func TestClientHeldNotification_ClientTimeout_DoesNotBurnContext(t *testing.T) {
	old := clientAuthRequestTimeout
	clientAuthRequestTimeout = 200 * time.Millisecond
	t.Cleanup(func() { clientAuthRequestTimeout = old })

	r := newHeldNotifRig(t, "n-1")
	r.mode.Store(int32(heldClientSilent))
	r.notify("n-1")
	assert.Equal(t, "rejected", r.ack(t).Status)
	assert.Equal(t, int32(0), atomic.LoadInt32(r.calls))

	r.mode.Store(int32(heldClientSigns))
	r.notify("n-1")
	assert.Equal(t, "forwarded", r.ack(t).Status)
}

func TestClientHeldNotification_ReplayAfterForwardIsRejected(t *testing.T) {
	r := newHeldNotifRig(t, "n-1")
	r.notify("n-1")
	assert.Equal(t, "forwarded", r.ack(t).Status)

	r.notify("n-1")
	a := r.ack(t)
	assert.Equal(t, "rejected", a.Status)
	assert.Equal(t, int32(1), atomic.LoadInt32(r.calls), "a replay must not reach the issuer again")
}

func TestClientHeldNotification_IssuerError_ConsumesContext(t *testing.T) {
	r := newHeldNotifRig(t, "n-1")
	r.issuer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(r.calls, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_notification_id","error_description":"issuer text"}`))
	})
	r.notify("n-1")
	a := r.ack(t)
	assert.Equal(t, "rejected", a.Status)
	assert.NotContains(t, a.Error, "issuer text")

	// The issuer was contacted and answered: that is the single use.
	r.notify("n-1")
	assert.Equal(t, "rejected", r.ack(t).Status)
	assert.Equal(t, int32(1), atomic.LoadInt32(r.calls))
}

func TestEngineHeldNotification_AfterFlowEnded_Forwards(t *testing.T) {
	r := newHeldNotifRig(t, "n-1")
	nc := dpopNotifContext(t, r.issuer.URL)
	nc.notificationID = "n-1"
	r.session.notifications.put("flow-ended", nc)
	r.notify("n-1")
	require.Equal(t, "forwarded", r.ack(t).Status)
	assert.NotEmpty(t, recvOrFail(t, r.dpop))
	assert.Empty(t, r.signs, "an engine-held key needs no client round trip")
}

func TestNotificationContextStore_Restore(t *testing.T) {
	s := newNotificationContextStore()
	s.put("f", &notificationContext{endpoint: "https://issuer.example.com/n"})
	nc := s.take("f")
	require.NotNil(t, nc)
	exp := nc.expiresAt

	s.restore("f", nc)
	got := s.take("f")
	require.NotNil(t, got, "a restored context is usable again")
	assert.Equal(t, exp, got.expiresAt, "restoring must not extend the TTL")

	// Expired: not resurrected.
	nc.expiresAt = time.Now().Add(-time.Second)
	s.restore("f", nc)
	assert.Nil(t, s.take("f"))

	// A newer context registered meanwhile is not overwritten.
	s.put("f", &notificationContext{endpoint: "https://new.example.com/n"})
	old := &notificationContext{endpoint: "https://old.example.com/n", expiresAt: time.Now().Add(time.Minute)}
	s.restore("f", old)
	assert.Equal(t, "https://new.example.com/n", s.take("f").endpoint)
}

func TestNotificationContextStore_Restore_SupersededRegistrationIsNotRevived(t *testing.T) {
	s := newNotificationContextStore()
	s.put("f", &notificationContext{endpoint: "https://old.example.com/n"})
	old := s.take("f")
	s.put("f", &notificationContext{endpoint: "https://new.example.com/n"}) // reused flow ID
	newer := s.take("f")                                                    // in flight: not in the map
	s.restore("f", old)                                                     // the superseded one must not come back
	assert.Nil(t, s.take("f"))
	s.restore("f", newer) // the newer one's own failure may be retried
	require.NotNil(t, s.take("f"))
}

func TestClientHeldNotification_SigningFailureOnNonceRetry_ConsumesContext(t *testing.T) {
	r := newHeldNotifRig(t, "n-1")
	r.issuer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if atomic.AddInt32(r.calls, 1) > 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("DPoP-Nonce", "nonce-1")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
	})
	// First proof is signed, the retry's is refused: the issuer was contacted.
	r.session.notifications.take("flow-ended")
	var n atomic.Int32
	r.session.notifications.put("flow-ended", &notificationContext{
		endpoint: r.issuer.URL, accessToken: "at", tokenType: "DPoP", notificationID: "n-1",
		dpopSigner: dpopSignerFunc(func() (string, error) {
			if n.Add(1) == 2 {
				return "", assert.AnError // the nonce retry's proof
			}
			return "p", nil
		}),
	})
	r.notify("n-1")
	assert.Equal(t, "rejected", r.ack(t).Status)
	assert.Equal(t, int32(1), atomic.LoadInt32(r.calls))
	r.notify("n-1")
	assert.Equal(t, "rejected", r.ack(t).Status)
	assert.Equal(t, int32(1), atomic.LoadInt32(r.calls), "context must stay spent once the issuer was contacted")
}

type dpopSignerFunc func() (string, error)

func (f dpopSignerFunc) Proof(_ context.Context, _, _, _, _ string) (string, error) { return f() }

// recvOrFail reads one value or fails the test instead of blocking forever.
func recvOrFail[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		require.FailNow(t, "timed out waiting for a value")
		panic("unreachable")
	}
}
