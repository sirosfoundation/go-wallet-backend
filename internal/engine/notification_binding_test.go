package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// These tests pin what a notification context is bound to. The context is
// keyed by the flow ID the CLIENT chose, so a flow ID that is reused must never
// let the second issuance's notification reach the first issuance's issuer
// with the first issuance's token.

// reuseRig is a live session (real read loop) with a context registered for
// flow "F" by an earlier issuance at issuer 1, and a manager whose oid4vci
// flow handler is the given one.
type reuseRig struct {
	session *Session
	mgr     *Manager
	issuer1 *httptest.Server
	calls1  *int32
	acks    chan NotificationAckMessage
	types   chan MessageType
	client  *websocket.Conn
}

func newReuseRig(t *testing.T, factory FlowHandlerFactory, ctxID string) *reuseRig {
	t.Helper()
	r := &reuseRig{acks: make(chan NotificationAckMessage, 8), types: make(chan MessageType, 64)}
	var calls int32
	r.calls1 = &calls
	r.issuer1 = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.issuer1.Close)

	cfg := testConfig()
	r.mgr = NewManager(cfg, zap.NewNop())
	r.mgr.RegisterFlowHandler(ProtocolOID4VCI, factory)
	client, s := unknownFlowHarnessOn(t, r.mgr)
	s.TAC = "i"
	r.session = s
	s.notifications.put("F", &notificationContext{
		endpoint:       r.issuer1.URL,
		accessToken:    "token-of-issuer-1",
		tokenType:      "Bearer",
		notificationID: ctxID,
	})
	go func() {
		for {
			_, data, err := client.ReadMessage()
			if err != nil {
				return
			}
			var m Message
			if json.Unmarshal(data, &m) == nil {
				select {
				case r.types <- m.Type:
				default:
				}
			}
			if json.Unmarshal(data, &m) == nil && m.Type == TypeNotificationAck {
				var a NotificationAckMessage
				if json.Unmarshal(data, &a) == nil {
					r.acks <- a
				}
			}
		}
	}()
	t.Cleanup(func() { _ = client.Close() })
	r.client = client
	return r
}

func (r *reuseRig) notify(t *testing.T, flowID, id string) NotificationAckMessage {
	t.Helper()
	require.NoError(t, r.client.WriteJSON(&CredentialNotificationMessage{
		Message:          Message{Type: TypeCredentialNotification, FlowID: flowID},
		NotificationID:   id,
		Event:            notificationEventFailure,
		EventDescription: "client text for issuance two",
	}))
	select {
	case a := <-r.acks:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("no notification_ack")
		return NotificationAckMessage{}
	}
}

func stubFactory(h FlowHandler) FlowHandlerFactory {
	return func(*Flow, *config.Config, *zap.Logger, *TrustService, *RegistryClient, storage.VerifierStore, *TrustCache) (FlowHandler, error) {
		return h, nil
	}
}

func startFlow(r *reuseRig, flowID string) {
	r.mgr.handleFlowStart(r.session, &FlowStartMessage{Message: Message{FlowID: flowID}, Protocol: ProtocolOID4VCI})
}

// Scenario (a), blind context: an encrypted issuer response registers a context
// with no notification_id, which accepts whatever id the client names. A second
// issuance that reuses the flow ID and registers nothing used to leave it in
// place, so issuance two's notification (its id, event and text) went to
// issuer one, authenticated with issuer one's token.
func TestNotificationContext_FlowIDReuse_BlindContextDoesNotReachFirstIssuer(t *testing.T) {
	r := newReuseRig(t, stubFactory(stubFlowHandler{}), "")
	startFlow(r, "F") // second issuance, same flow ID, registers no context

	a := r.notify(t, "F", "id-of-issuance-two")
	assert.Equal(t, "rejected", a.Status)
	assert.Equal(t, int32(0), atomic.LoadInt32(r.calls1), "issuer one must not be contacted for issuance two")
}

// Scenario (a), known id: the flow ID is reused, so the earlier issuance's
// context is gone whatever id the client names, including its own.
func TestNotificationContext_FlowIDReuse_StaleContextIsDiscarded(t *testing.T) {
	r := newReuseRig(t, stubFactory(stubFlowHandler{}), "id-of-issuance-one")
	startFlow(r, "F")

	a := r.notify(t, "F", "id-of-issuance-one")
	assert.Equal(t, "rejected", a.Status)
	assert.Equal(t, int32(0), atomic.LoadInt32(r.calls1))
}

// Without reuse the context still works (the fix must not disable notifying).
func TestNotificationContext_NoReuse_StillForwards(t *testing.T) {
	r := newReuseRig(t, stubFactory(stubFlowHandler{}), "id-of-issuance-one")
	startFlow(r, "other-flow")

	a := r.notify(t, "F", "id-of-issuance-one")
	assert.Equal(t, "forwarded", a.Status)
	assert.Equal(t, int32(1), atomic.LoadInt32(r.calls1))
}

// A flow start that is refused or that never becomes a flow must not destroy a
// live issuance's context: only a flow that actually takes the ID does.
func TestNotificationContext_RefusedFlowStartKeepsContext(t *testing.T) {
	r := newReuseRig(t, stubFactory(stubFlowHandler{}), "id-of-issuance-one")
	r.session.TAC = "" // insufficient permissions: refused before taking the ID
	startFlow(r, "F")

	a := r.notify(t, "F", "id-of-issuance-one")
	assert.Equal(t, "forwarded", a.Status)
}

// Scenario (b): a second issuance that does register replaces the first
// atomically; the first's id no longer matches and the second's does.
func TestNotificationContext_FlowIDReuse_SecondRegistrationReplacesFirst(t *testing.T) {
	r := newReuseRig(t, stubFactory(stubFlowHandler{}), "id-of-issuance-one")
	issuer2, calls2 := newCountingIssuer(t)
	startFlow(r, "F")
	r.session.notifications.put("F", &notificationContext{
		endpoint: issuer2.URL, accessToken: "token-of-issuer-2", tokenType: "Bearer", notificationID: "id-of-issuance-two",
	})

	a := r.notify(t, "F", "id-of-issuance-one")
	assert.Equal(t, "rejected", a.Status)
	a = r.notify(t, "F", "id-of-issuance-two")
	assert.Equal(t, "forwarded", a.Status)
	assert.Equal(t, int32(0), atomic.LoadInt32(r.calls1))
	assert.Equal(t, int32(1), atomic.LoadInt32(calls2))
}

// Scenario (b'), the restore interplay: a context handed out for a forward that
// never reached the issuer is put back by restore, but not once the flow ID has
// been reused by a flow that registered nothing.
func TestNotificationContextStore_Restore_NotRevivedByFlowIDReuse(t *testing.T) {
	s := newNotificationContextStore()
	s.put("F", &notificationContext{endpoint: "https://issuer-1.example/notify", notificationID: "n1"})
	taken := s.take("F")
	require.NotNil(t, taken)

	s.invalidate("F") // a new flow takes the ID and registers nothing
	s.restore("F", taken)

	assert.Nil(t, s.take("F"), "a superseded issuance's context must stay gone")
	assert.False(t, s.hasValid("F", "n1"))
}

// Scenario (c): the store belongs to the session. Another session (another user
// or the same user on a second connection) naming the same flow ID finds
// nothing and reaches no issuer.
func TestNotificationContext_OtherSessionCannotUseContext(t *testing.T) {
	r := newReuseRig(t, stubFactory(stubFlowHandler{}), "id-of-issuance-one")
	m := r.mgr
	clientB, sessionB := unknownFlowHarnessOn(t, m)
	sessionB.UserID = "user-b"

	require.NoError(t, clientB.WriteJSON(&CredentialNotificationMessage{
		Message:        Message{Type: TypeCredentialNotification, FlowID: "F"},
		NotificationID: "id-of-issuance-one",
		Event:          notificationEventAccepted,
	}))
	_ = clientB.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := clientB.ReadMessage()
	require.NoError(t, err)
	var ack NotificationAckMessage
	require.NoError(t, json.Unmarshal(data, &ack))
	assert.Equal(t, "rejected", ack.Status)
	assert.Equal(t, "notification context unavailable", ack.Error)
	assert.Equal(t, int32(0), atomic.LoadInt32(r.calls1))
	// A's context is untouched by B's attempt.
	assert.True(t, r.session.notifications.hasValid("F", "id-of-issuance-one"))
}

// blockingFlowHandler stays live until released or cancelled.
type cancellableFlowHandler struct {
	started   chan struct{}
	release   chan struct{}
	cancelled chan struct{}
	once      sync.Once
}

func newCancellableFlowHandler() *cancellableFlowHandler {
	return &cancellableFlowHandler{started: make(chan struct{}), release: make(chan struct{}), cancelled: make(chan struct{})}
}

func (c *cancellableFlowHandler) Execute(ctx context.Context, _ *FlowStartMessage) error {
	close(c.started)
	select {
	case <-c.release:
	case <-c.cancelled:
	case <-ctx.Done():
	}
	return nil
}
func (c *cancellableFlowHandler) Cancel() { c.once.Do(func() { close(c.cancelled) }) }

// A flow ID that a live flow still holds goes to the new flow: the earlier flow
// is cancelled, the new flow keeps the slot (the earlier flow's cleanup must
// not delete it), and the client is not refused, because the earlier flow's
// slot is released a moment after its completion is sent.
func TestNotificationContext_LiveFlowIDIsSupersededNotOrphaned(t *testing.T) {
	first, second := newCancellableFlowHandler(), newCancellableFlowHandler()
	var n atomic.Int32
	factory := func(*Flow, *config.Config, *zap.Logger, *TrustService, *RegistryClient, storage.VerifierStore, *TrustCache) (FlowHandler, error) {
		if n.Add(1) == 1 {
			return first, nil
		}
		return second, nil
	}
	r := newReuseRig(t, factory, "id-of-issuance-one")
	firstDone, secondDone := make(chan struct{}), make(chan struct{})
	go func() { startFlow(r, "F"); close(firstDone) }()
	<-first.started
	go func() { startFlow(r, "F"); close(secondDone) }()
	<-second.started

	select {
	case <-first.cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the superseded flow was not cancelled")
	}
	<-firstDone // its cleanup has run
	r.session.flowsMu.RLock()
	live := r.session.flows["F"]
	r.session.flowsMu.RUnlock()
	require.NotNil(t, live, "the earlier flow's cleanup must not delete the new flow's slot")
	live.mu.RLock()
	assert.Same(t, second, live.Handler)
	live.mu.RUnlock()
	close(second.release)
	<-secondDone
	r.session.flowsMu.RLock()
	_, stillThere := r.session.flows["F"]
	r.session.flowsMu.RUnlock()
	assert.False(t, stillThere, "the owner releases its own slot")
}

// completeThenHoldHandler publishes flow_complete from Execute and then keeps
// the flow (and its slot) for a moment, as a real flow does between sending its
// completion and returning.
type completeThenHoldHandler struct {
	flow    *Flow
	started chan struct{}
	release chan struct{}
}

func (c *completeThenHoldHandler) Execute(ctx context.Context, _ *FlowStartMessage) error {
	_ = c.flow.Session.SendFlowComplete(c.flow.ID, nil, "")
	close(c.started)
	select {
	case <-c.release:
	case <-ctx.Done():
	}
	return nil
}
func (c *completeThenHoldHandler) Cancel() {}

// Over the wire: a client that starts a new flow under the ID right after the
// previous flow's flow_complete is not refused, although the previous flow's
// slot is released only after the completion went out.
func TestNotificationContext_RestartRightAfterCompleteIsNotRefused(t *testing.T) {
	var handlers []*completeThenHoldHandler
	var mu sync.Mutex
	factory := func(f *Flow, _ *config.Config, _ *zap.Logger, _ *TrustService, _ *RegistryClient, _ storage.VerifierStore, _ *TrustCache) (FlowHandler, error) {
		h := &completeThenHoldHandler{flow: f, started: make(chan struct{}), release: make(chan struct{})}
		mu.Lock()
		handlers = append(handlers, h)
		mu.Unlock()
		return h, nil
	}
	r := newReuseRig(t, factory, "")
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, h := range handlers {
			select {
			case <-h.release:
			default:
				close(h.release)
			}
		}
	})
	start := func() {
		require.NoError(t, r.client.WriteJSON(&FlowStartMessage{
			Message: Message{Type: TypeFlowStart, FlowID: "G"}, Protocol: ProtocolOID4VCI,
		}))
	}
	start()
	expectType := func(want MessageType) {
		t.Helper()
		select {
		case got := <-r.types:
			require.Equal(t, want, got)
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s", want)
		}
	}
	expectType(TypeFlowComplete)
	start() // right after the completion, while the first flow still holds its slot
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		if len(handlers) < 2 {
			return false
		}
		select {
		case <-handlers[1].started:
			return true
		default:
			return false
		}
	}, 5*time.Second, 5*time.Millisecond, "the restarted flow must run")
	expectType(TypeFlowComplete) // the second flow's completion, and no flow_error before it
}

// The session's contexts, with the issuance token and the signer they hold, are
// dropped when the session ends, and nothing can be registered afterwards.
func TestNotificationContext_ClearedWhenSessionEnds(t *testing.T) {
	r := newReuseRig(t, stubFactory(stubFlowHandler{}), "id-of-issuance-one")
	require.True(t, r.session.notifications.hasValid("F", "id-of-issuance-one"))
	_ = r.client.Close()

	require.Eventually(t, func() bool {
		return !r.session.notifications.hasValid("F", "id-of-issuance-one")
	}, 5*time.Second, 10*time.Millisecond)
	r.session.notifications.put("late", &notificationContext{endpoint: "https://issuer.example/notify"})
	assert.Nil(t, r.session.notifications.take("late"), "a late registration must not outlive the session")
}

// The read loop admits a flow_start before it handles the next message, so a
// credential_notification that follows a flow_start on the wire is always
// handled after the flow ID changed hands. Over the real socket, many times:
// admission used to race with the notification (the flow was launched
// asynchronously) and could let it take the previous issuer's context.
func TestNotificationContext_WireStartThenNotify_NeverReachesPreviousIssuer(t *testing.T) {
	r := newReuseRig(t, stubFactory(stubFlowHandler{}), "")
	for i := 0; i < 200; i++ {
		id := "wire-" + time.Now().Format("150405.000000000") + string(rune('a'+i%26)) + string(rune('A'+i/26))
		r.session.notifications.put(id, &notificationContext{
			endpoint: r.issuer1.URL, accessToken: "token-of-issuer-1", tokenType: "Bearer",
		})
		require.NoError(t, r.client.WriteJSON(&FlowStartMessage{
			Message: Message{Type: TypeFlowStart, FlowID: id}, Protocol: ProtocolOID4VCI,
		}))
		require.NoError(t, r.client.WriteJSON(&CredentialNotificationMessage{
			Message: Message{Type: TypeCredentialNotification, FlowID: id}, NotificationID: "id-two",
			Event: notificationEventFailure,
		}))
		select {
		case a := <-r.acks:
			require.Equal(t, "rejected", a.Status, "iteration %d", i)
		case <-time.After(5 * time.Second):
			t.Fatal("no notification_ack")
		}
	}
	assert.Equal(t, int32(0), atomic.LoadInt32(r.calls1))
}

// Every accepted flow records a generation; the history is pruned by it, so a
// session that never registers a context does not keep every flow ID it used.
func TestNotificationContextStore_Invalidate_PrunesExpiredHistory(t *testing.T) {
	s := newNotificationContextStore()
	s.latest["old"] = latestRegistration{seq: 1, at: time.Now().Add(-2 * notificationContextTTL)}
	s.invalidate("new")

	s.mu.Lock()
	defer s.mu.Unlock()
	_, oldKept := s.latest["old"]
	_, newKept := s.latest["new"]
	assert.False(t, oldKept, "an expired generation must be pruned")
	assert.True(t, newKept)
}

// A notification is checked on the read loop and forwarded by a worker that
// runs later. If the flow ID is reused in between and the new issuance
// registers a context, the worker must neither send the old notification with
// the new issuance's token nor consume the new context.
func TestNotificationContext_DelayedWorker_DoesNotUseOrConsumeReplacement(t *testing.T) {
	r := newReuseRig(t, stubFactory(stubFlowHandler{}), "")
	issuer2, calls2 := newCountingIssuer(t)
	msg := &CredentialNotificationMessage{
		Message:        Message{Type: TypeCredentialNotification, FlowID: "F"},
		NotificationID: "id-of-issuance-one",
		Event:          notificationEventAccepted,
	}
	seq, ok := r.session.notifications.validGeneration("F", msg.NotificationID)
	require.True(t, ok) // the check the read loop made

	// The flow ID changes hands and the new issuance registers a blind context.
	startFlow(r, "F")
	r.session.notifications.put("F", &notificationContext{
		endpoint: issuer2.URL, accessToken: "token-of-issuer-2", tokenType: "Bearer",
	})

	r.mgr.forwardCredentialNotification(r.session, msg, seq, zap.NewNop()) // the delayed worker
	select {
	case a := <-r.acks:
		assert.Equal(t, "rejected", a.Status)
	case <-time.After(5 * time.Second):
		t.Fatal("no notification_ack")
	}
	assert.Equal(t, int32(0), atomic.LoadInt32(r.calls1))
	assert.Equal(t, int32(0), atomic.LoadInt32(calls2), "the replacement's issuer must not receive the old notification")
	assert.True(t, r.session.notifications.hasValid("F", "the-new-issuances-id"), "the replacement context must survive")
}
