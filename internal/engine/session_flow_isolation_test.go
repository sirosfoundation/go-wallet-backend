package engine

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Concurrent flows (and requests) on one session share the actionCh, signCh
// and matchCh channels. These tests pin that no waiter consumes - and loses -
// another waiter's input, for actions, sign responses and match responses.

func flowName(i int) string { return "flow-" + string(rune('a'+i)) }

func newIsolationSession(t *testing.T) (*Session, *websocket.Conn) {
	t.Helper()
	srvConnCh := make(chan *websocket.Conn, 1)
	clientConn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) { srvConnCh <- srvConn })
	t.Cleanup(cleanup)
	return &Session{
		ID:       "iso",
		conn:     <-srvConnCh,
		flows:    make(map[string]*Flow),
		logger:   zap.NewNop(),
		actionCh: make(chan *FlowActionMessage, 50),
		signCh:   make(chan *SignResponseMessage, 20),
		matchCh:  make(chan *MatchResponseMessage, 20),
		closeCh:  make(chan struct{}, 1),
		stopPing: make(chan struct{}),
	}, clientConn
}

func TestSession_ConcurrentFlowsDoNotLoseActions(t *testing.T) {
	s, _ := newIsolationSession(t)
	for i := 0; i < 3; i++ {
		s.flows[flowName(i)] = &Flow{ID: flowName(i)}
	}
	wait := func(id string) <-chan error {
		ch := make(chan error, 1)
		go func() {
			a, err := s.WaitForActionWithTimeout(context.Background(), id, 3*time.Second, "consent")
			if err == nil && a.FlowID != id {
				err = assert.AnError
			}
			ch <- err
		}()
		return ch
	}

	// Only flow-a is waiting when the actions for flow-b and flow-c arrive,
	// so its waiter is the one that reads them. It must park them, not drop
	// them, for the waiters that start afterwards.
	resA := wait(flowName(0))
	time.Sleep(50 * time.Millisecond) // let flow-a's waiter start consuming
	s.actionCh <- &FlowActionMessage{Message: Message{FlowID: flowName(2)}, Action: "consent"}
	s.actionCh <- &FlowActionMessage{Message: Message{FlowID: flowName(1)}, Action: "consent"}
	time.Sleep(50 * time.Millisecond) // flow-a's waiter has read both
	resB := wait(flowName(1))
	resC := wait(flowName(2))
	s.actionCh <- &FlowActionMessage{Message: Message{FlowID: flowName(0)}, Action: "consent"}

	for name, ch := range map[string]<-chan error{"a": resA, "b": resB, "c": resC} {
		require.NoError(t, <-ch, "flow %s lost its action", name)
	}
}

// Three flows each have a sign and a match request pending on one session;
// the client answers all six in reverse order of arrival. Every waiter must
// get exactly its own reply.
func TestSession_ConcurrentSignAndMatchResponsesRouted(t *testing.T) {
	s, clientConn := newIsolationSession(t)

	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 3; i++ {
		wg.Add(2)
		fid := flowName(i)
		go func() {
			defer wg.Done()
			r, err := s.RequestSign(context.Background(), fid, SignActionGenerateProof, SignRequestParams{JWE: fid})
			if err == nil && r.TransactionID != fid {
				err = assert.AnError
			}
			errs <- err
		}()
		go func() {
			defer wg.Done()
			r, err := s.RequestMatch(context.Background(), fid, []byte(`{}`))
			if err == nil && r.FlowID != fid {
				err = assert.AnError
			}
			errs <- err
		}()
	}

	// Collect all six requests, then answer them in reverse order.
	var reqs [][]byte
	for len(reqs) < 6 {
		_, raw, err := clientConn.ReadMessage()
		require.NoError(t, err)
		reqs = append(reqs, raw)
	}
	for i := len(reqs) - 1; i >= 0; i-- {
		var m Message
		require.NoError(t, json.Unmarshal(reqs[i], &m))
		switch m.Type {
		case TypeSignRequest:
			var req SignRequestMessage
			require.NoError(t, json.Unmarshal(reqs[i], &req))
			s.signCh <- &SignResponseMessage{
				Message:       Message{Type: TypeSignResponse, FlowID: req.FlowID, MessageID: req.MessageID},
				TransactionID: req.Params.JWE, // tag the reply with its owner
			}
		case TypeMatchRequest:
			s.matchCh <- &MatchResponseMessage{Message: Message{Type: TypeMatchResponse, FlowID: m.FlowID, MessageID: m.MessageID}}
		default:
			t.Fatalf("unexpected message type %q", m.Type)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

// A match response for another flow's request must not be accepted by a
// waiter on a different flow even when the message IDs are mixed up, and
// must stay available for its owner.
func TestSession_RequestMatch_OtherFlowsResponseIsParkedNotDropped(t *testing.T) {
	s, clientConn := newIsolationSession(t)

	type result struct {
		resp *MatchResponseMessage
		err  error
	}
	resA := make(chan result, 1)
	resB := make(chan result, 1)
	go func() { r, err := s.RequestMatch(context.Background(), "flow-a", []byte(`{}`)); resA <- result{r, err} }()
	var reqA MatchRequestMessage
	require.NoError(t, clientConn.ReadJSON(&reqA))
	go func() { r, err := s.RequestMatch(context.Background(), "flow-b", []byte(`{}`)); resB <- result{r, err} }()
	var reqB MatchRequestMessage
	require.NoError(t, clientConn.ReadJSON(&reqB))

	// B's response first: A's waiter reads it and must park it for B.
	s.matchCh <- &MatchResponseMessage{Message: Message{FlowID: "flow-b", MessageID: reqB.MessageID}}
	s.matchCh <- &MatchResponseMessage{Message: Message{FlowID: "flow-a", MessageID: reqA.MessageID}}
	for name, ch := range map[string]chan result{"a": resA, "b": resB} {
		select {
		case r := <-ch:
			require.NoError(t, r.err)
			assert.Equal(t, "flow-"+name, r.resp.FlowID)
		case <-time.After(5 * time.Second):
			t.Fatalf("flow %s never got its match response", name)
		}
	}
}

// A response whose request is no longer pending (timed out or cancelled) is
// dropped, not parked forever: parking it would use up the stash's bounded
// capacity and starve live requests.
func TestSession_StaleResponsesAreNotParked(t *testing.T) {
	s, _ := newIsolationSession(t)

	for i := 0; i < maxStashedResponses+10; i++ {
		id := "stale-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		s.stashSign(&SignResponseMessage{Message: Message{MessageID: id}})
		s.stashMatch(&MatchResponseMessage{Message: Message{FlowID: "f", MessageID: id}})
	}
	assert.Empty(t, s.stash.signs)
	assert.Empty(t, s.stash.matches)

	// A pending request's response is parked and consumed exactly once.
	done := s.trackRequest("live", "f")
	defer done()
	s.stashSign(&SignResponseMessage{Message: Message{MessageID: "live"}})
	require.NotNil(t, s.stash.takeSign("live"))
	assert.Nil(t, s.stash.takeSign("live"))
}

// Parked actions are bounded per flow, ignored for unknown flows, and
// discarded when the flow ends.
func TestResponseStash_ActionsBoundedAndDroppedWithFlow(t *testing.T) {
	s, _ := newIsolationSession(t)
	s.flows["f"] = &Flow{ID: "f"}

	s.stashAction(&FlowActionMessage{Message: Message{FlowID: "gone"}, Action: "x"})
	assert.Empty(t, s.stash.actions, "no one would consume an action for an unknown flow")

	for i := 0; i < maxStashedActionsPerFlow+5; i++ {
		s.stashAction(&FlowActionMessage{Message: Message{FlowID: "f"}, Action: "x"})
	}
	assert.Len(t, s.stash.actions["f"], maxStashedActionsPerFlow)

	s.stash.dropFlow("f")
	assert.Empty(t, s.stash.actions)
}

// A reply parked for a request is discarded when the request ends, and a late
// reply for it is not parked afterwards: nothing can consume either, and they
// would fill the stash's bounded capacity.
func TestSession_ParkedRepliesDropWhenRequestEnds(t *testing.T) {
	s, _ := newIsolationSession(t)

	done := s.trackRequest("req", "f")
	s.stashSign(&SignResponseMessage{Message: Message{MessageID: "req"}})
	s.stashMatch(&MatchResponseMessage{Message: Message{FlowID: "f", MessageID: "req"}})
	require.Len(t, s.stash.signs, 1)
	require.Len(t, s.stash.matches, 1)

	done() // the request timed out or was cancelled before consuming its reply
	assert.Empty(t, s.stash.signs)
	assert.Empty(t, s.stash.matches)

	s.stashSign(&SignResponseMessage{Message: Message{MessageID: "req"}})
	s.stashMatch(&MatchResponseMessage{Message: Message{FlowID: "f", MessageID: "req"}})
	assert.Empty(t, s.stash.signs)
	assert.Empty(t, s.stash.matches)
}

// A reply carrying the right message ID but the wrong flow ID must not replace
// (or block) the valid parked reply for that request.
func TestSession_WrongFlowMatchReplyDoesNotOverwriteValidOne(t *testing.T) {
	s, _ := newIsolationSession(t)
	done := s.trackRequest("req", "flow-a")
	defer done()

	s.stashMatch(&MatchResponseMessage{Message: Message{FlowID: "flow-a", MessageID: "req"}, Error: "valid"})
	s.stashMatch(&MatchResponseMessage{Message: Message{FlowID: "flow-wrong", MessageID: "req"}, Error: "impostor"})

	got := s.stash.takeMatch("flow-a", "req")
	require.NotNil(t, got)
	assert.Equal(t, "valid", got.Error)
}

// Flow teardown (delete under the write lock, then dropFlow) must never leave
// a parked-action queue behind, even when actions for the ending flow are being
// stashed concurrently.
func TestSession_StashAction_RacingFlowTeardownLeavesNoQueue(t *testing.T) {
	s, _ := newIsolationSession(t)
	for round := 0; round < 200; round++ {
		s.flowsMu.Lock()
		s.flows["f"] = &Flow{ID: "f"}
		s.flowsMu.Unlock()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				s.stashAction(&FlowActionMessage{Message: Message{FlowID: "f"}, Action: "x"})
			}
		}()
		go func() {
			defer wg.Done()
			s.flowsMu.Lock()
			delete(s.flows, "f")
			s.flowsMu.Unlock()
			s.stash.dropFlow("f")
		}()
		wg.Wait()
		require.Empty(t, s.stash.actions, "round %d left a queue for an ended flow", round)
	}
}

// Replies with a pending message ID but many distinct wrong flow IDs must not
// fill the match stash: only the requesting flow can own the reply, so a valid
// reply arriving afterwards is still parked and delivered.
func TestSession_WrongFlowMatchRepliesCannotExhaustStash(t *testing.T) {
	s, _ := newIsolationSession(t)
	done := s.trackRequest("req", "flow-a")
	defer done()

	for i := 0; i < maxStashedResponses+10; i++ {
		s.stashMatch(&MatchResponseMessage{Message: Message{FlowID: "wrong-" + string(rune('a'+i%26)) + string(rune('a'+i/26)), MessageID: "req"}})
	}
	assert.Empty(t, s.stash.matches)

	s.stashMatch(&MatchResponseMessage{Message: Message{FlowID: "flow-a", MessageID: "req"}})
	require.NotNil(t, s.stash.takeMatch("flow-a", "req"))
}

// Actions for one flow are delivered in the order the client sent them, even
// when another flow's waiter reads the first one off the shared channel and is
// descheduled before parking it: the flow's own waiter must not be able to
// read its second action in the meantime.
func TestSession_ActionsForOneFlowStayInOrderAcrossWaiters(t *testing.T) {
	s, _ := newIsolationSession(t)
	s.flows[flowName(0)] = &Flow{ID: flowName(0)}
	s.flows[flowName(1)] = &Flow{ID: flowName(1)}

	readFirst := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	s.stash.afterForeignActionRead = func() {
		once.Do(func() {
			close(readFirst) // persistent signal, never lost if the test is not yet receiving
			<-release        // pause the waiter that read flow-b's first action
		})
	}

	// flow-a's waiter competes for the channel but never gets an action.
	ctxA, cancelA := context.WithCancel(context.Background())
	doneA := make(chan struct{})
	go func() {
		defer close(doneA)
		_, _ = s.WaitForActionWithTimeout(ctxA, flowName(0), 5*time.Second, "never")
	}()
	time.Sleep(50 * time.Millisecond) // flow-a's waiter is reading the channel

	s.actionCh <- &FlowActionMessage{Message: Message{FlowID: flowName(1)}, Action: "first"}
	select {
	case <-readFirst: // flow-a's waiter holds flow-b's first action, not yet parked
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("flow-a's waiter never read flow-b's first action")
	}
	s.actionCh <- &FlowActionMessage{Message: Message{FlowID: flowName(1)}, Action: "second"}

	got := make(chan string, 2)
	go func() {
		for i := 0; i < 2; i++ {
			a, err := s.WaitForActionWithTimeout(context.Background(), flowName(1), 3*time.Second)
			if err != nil {
				got <- "error: " + err.Error()
				return
			}
			got <- a.Action
		}
	}()
	time.Sleep(100 * time.Millisecond) // flow-b's waiter has had every chance to read "second"
	close(release)

	// Fatal on the first mismatch: after an error the worker sends nothing more.
	require.Equal(t, "first", <-got)
	require.Equal(t, "second", <-got)
	cancelA()
	<-doneA
}

// If the handler factory fails after the flow slot was reserved, actions that
// other waiters parked for that flow in the meantime must not be left behind.
func TestHandleFlowStart_FactoryFailureDropsParkedActions(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	s, _ := newIsolationSession(t)
	s.TenantID, s.TAC = "default", "i"

	m.RegisterFlowHandler(ProtocolOID4VCI, func(flow *Flow, _ *config.Config, _ *zap.Logger, _ *TrustService, _ *RegistryClient, _ storage.VerifierStore, _ *TrustCache) (FlowHandler, error) {
		// The flow is registered while the factory runs; a concurrent waiter
		// parks an action for it.
		s.stashAction(&FlowActionMessage{Message: Message{FlowID: flow.ID}, Action: "x"})
		return nil, assert.AnError
	})

	m.handleFlowStart(s, &FlowStartMessage{Message: Message{FlowID: "flow-factory-fails"}, Protocol: ProtocolOID4VCI})
	assert.Empty(t, s.stash.actions)
	assert.Empty(t, s.flows)
}
