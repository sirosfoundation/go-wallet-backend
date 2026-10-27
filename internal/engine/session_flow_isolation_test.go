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
	done := s.trackRequest("live")
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
