package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// lifecycleRoutingFixture is a live manager with one handshaken session that has
// a registered flow (with its own action channel and a cancel hook) and a sign
// request pending on it, so a lifecycle gate firing meets per-flow routing.
type lifecycleRoutingFixture struct {
	m         *Manager
	store     *memory.Store
	uid       domain.UserID
	ws        *websocket.Conn
	session   *Session
	flow      *Flow
	cancelled chan struct{}
	signErr   chan error
}

func newLifecycleRoutingFixture(t *testing.T) *lifecycleRoutingFixture {
	t.Helper()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	f := &lifecycleRoutingFixture{m: NewManager(cfg, zap.NewNop()), store: memory.NewStore(), uid: domain.NewUserID(),
		cancelled: make(chan struct{}), signErr: make(chan error, 1)}
	require.NoError(t, f.store.Users().Create(context.Background(), &domain.User{UUID: f.uid}))
	f.m.SetTokenGate(tokengate.New(f.store.Users()))

	server := httptest.NewServer(http.HandlerFunc(f.m.HandleConnection))
	t.Cleanup(server.Close)
	f.ws = dialAndHandshakeAsUser(t, f.m, "ws"+strings.TrimPrefix(server.URL, "http"), f.uid.String())
	t.Cleanup(func() { _ = f.ws.Close() })

	f.m.sessionsMu.RLock()
	for _, s := range f.m.sessions {
		f.session = s
	}
	f.m.sessionsMu.RUnlock()
	require.NotNil(t, f.session)

	f.flow = registerTestFlow(f.session, "flow-1")
	f.flow.cancel = func() { close(f.cancelled) }

	// A sign request pending on the flow (no reply will ever come).
	go func() {
		_, err := f.session.RequestSign(context.Background(), "flow-1", SignActionSignPresentation, SignRequestParams{})
		f.signErr <- err
	}()
	require.Eventually(t, func() bool {
		f.session.flowsMu.RLock()
		defer f.session.flowsMu.RUnlock()
		return len(f.session.outstandingRequests) == 1
	}, 2*time.Second, 5*time.Millisecond, "sign request was not registered")
	return f
}

// assertReleased checks the waiter got a refusal (not a reply) and that the
// session's per-request table is empty and the flow was cancelled.
func (f *lifecycleRoutingFixture) assertReleased(t *testing.T) {
	t.Helper()
	select {
	case err := <-f.signErr:
		require.Error(t, err, "the pending sign request must be refused, not answered")
	case <-time.After(3 * time.Second):
		t.Fatal("pending sign request was not released")
	}
	select {
	case <-f.cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("flow was not cancelled")
	}
	require.Eventually(t, func() bool {
		f.session.flowsMu.RLock()
		defer f.session.flowsMu.RUnlock()
		return len(f.session.outstandingRequests) == 0
	}, 2*time.Second, 5*time.Millisecond, "pending-request entry leaked")
	// A late reply for the released request has no owner and is not queued.
	f.session.dispatchSignResponse(&SignResponseMessage{Message: Message{Type: TypeSignResponse, MessageID: "gone", FlowID: "flow-1"}})
	assert.Empty(t, f.flow.actions, "nothing parked on the flow")
}

// Account deletion while a sign request is pending on a flow releases the
// waiter with a refusal and cancels the flow.
func TestLifecycle_RevokeUserWhileSignPending_ReleasesWaiter(t *testing.T) {
	f := newLifecycleRoutingFixture(t)
	f.m.RevokeUser(f.uid.String())
	f.assertReleased(t)
}

// A token cut-off that fires at flow start (recheckToken) with other flows and a
// pending sign request registered refuses the flow start, closes the socket,
// and releases the existing waiter and flow.
func TestLifecycle_RecheckTokenRefusalWithFlowsRegistered_ReleasesWaiter(t *testing.T) {
	f := newLifecycleRoutingFixture(t)
	require.NoError(t, f.store.Users().InvalidateAuthBefore(context.Background(), f.uid, time.Now().Add(time.Minute)))

	require.NoError(t, f.ws.WriteJSON(FlowStartMessage{
		Message:  Message{Type: TypeFlowStart, FlowID: "flow-2"},
		Protocol: ProtocolOID4VCI,
	}))
	var sawAuthFailed bool
	_ = f.ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		var fe FlowErrorMessage
		if err := f.ws.ReadJSON(&fe); err != nil {
			break
		}
		if fe.Type == TypeFlowError && fe.Error.Code == ErrCodeAuthFailed {
			sawAuthFailed = true
		}
	}
	assert.True(t, sawAuthFailed, "flow start refused with AUTH_FAILED")
	f.session.flowsMu.RLock()
	_, started := f.session.flows["flow-2"]
	f.session.flowsMu.RUnlock()
	assert.False(t, started, "the refused flow was never registered")
	f.assertReleased(t)
}
