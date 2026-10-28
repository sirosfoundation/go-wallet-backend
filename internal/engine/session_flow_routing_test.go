package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// The session's read loop routes each client message to the one owner that can
// consume it: an action to its Flow's channel, a sign/match reply to the
// outstanding request it answers. These tests pin that concurrent flows and
// requests on one session never see, consume or lose each other's messages,
// and that anything without an owner is answered and dropped, not parked.

const routingTimeout = 5 * time.Second

func newRoutingSession(t *testing.T) (*Session, *websocket.Conn) {
	t.Helper()
	srvConnCh := make(chan *websocket.Conn, 1)
	clientConn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) { srvConnCh <- srvConn })
	t.Cleanup(cleanup)
	return &Session{
		ID:       "routing",
		conn:     <-srvConnCh,
		flows:    make(map[string]*Flow),
		logger:   zap.NewNop(),
		closeCh:  make(chan struct{}, 1),
		stopPing: make(chan struct{}),
	}, clientConn
}

func action(flowID, name string) *FlowActionMessage {
	return &FlowActionMessage{Message: Message{Type: TypeFlowAction, FlowID: flowID}, Action: name}
}

func outstandingCount(s *Session) int {
	s.flowsMu.RLock()
	defer s.flowsMu.RUnlock()
	return len(s.outstandingRequests)
}

func waitAction(s *Session, flowID string, expected ...string) <-chan *FlowActionMessage {
	ch := make(chan *FlowActionMessage, 1)
	go func() {
		a, err := s.WaitForActionWithTimeout(context.Background(), flowID, routingTimeout, expected...)
		if err != nil {
			a = nil
		}
		ch <- a
	}()
	return ch
}

func TestRouting_ActionsGoToTheirOwnFlow(t *testing.T) {
	s, _ := newRoutingSession(t)
	for i := 0; i < 3; i++ {
		registerTestFlow(s, fmt.Sprintf("flow-%d", i))
	}
	waiters := make([]<-chan *FlowActionMessage, 3)
	for i := range waiters {
		waiters[i] = waitAction(s, fmt.Sprintf("flow-%d", i), "consent")
	}
	// Delivered in an order unrelated to the waiters', after they started.
	for _, i := range []int{2, 0, 1} {
		s.dispatchAction(action(fmt.Sprintf("flow-%d", i), "consent"))
	}
	for i, w := range waiters {
		a := <-w
		require.NotNil(t, a, "flow-%d lost its action", i)
		assert.Equal(t, fmt.Sprintf("flow-%d", i), a.FlowID)
	}
}

// A flow that is not waiting yet keeps its action while other flows run.
func TestRouting_ActionIsKeptForItsFlowWhileOthersWait(t *testing.T) {
	s, _ := newRoutingSession(t)
	registerTestFlow(s, "a")
	registerTestFlow(s, "b")
	waitA := waitAction(s, "a", "consent")

	s.dispatchAction(action("b", "consent")) // arrives while only a is waiting
	s.dispatchAction(action("a", "consent"))
	require.NotNil(t, <-waitA)

	got, err := s.WaitForActionWithTimeout(context.Background(), "b", routingTimeout, "consent")
	require.NoError(t, err, "b's action was consumed by a's waiter")
	assert.Equal(t, "b", got.FlowID)
}

func TestRouting_OneFlowsActionsStayInOrder(t *testing.T) {
	s, _ := newRoutingSession(t)
	registerTestFlow(s, "a")
	registerTestFlow(s, "b")
	for i := 0; i < 10; i++ {
		s.dispatchAction(action("a", fmt.Sprintf("step-%d", i)))
		s.dispatchAction(action("b", "noise"))
	}
	for i := 0; i < 10; i++ {
		got, err := s.WaitForActionWithTimeout(context.Background(), "a", routingTimeout)
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("step-%d", i), got.Action)
	}
}

func TestRouting_UnexpectedActionIsSkipped(t *testing.T) {
	s, _ := newRoutingSession(t)
	registerTestFlow(s, "a")
	s.dispatchAction(action("a", "other"))
	s.dispatchAction(action("a", "consent"))
	got, err := s.WaitForActionWithTimeout(context.Background(), "a", routingTimeout, "consent")
	require.NoError(t, err)
	assert.Equal(t, "consent", got.Action)
}

func TestRouting_WaitForActionOnUnknownFlowFailsClosed(t *testing.T) {
	s, _ := newRoutingSession(t)
	_, err := s.WaitForActionWithTimeout(context.Background(), "gone", routingTimeout)
	assert.ErrorIs(t, err, ErrFlowNotFound)

	// A flow that cannot receive actions (no channel) is unknown too.
	s.flows["bare"] = &Flow{ID: "bare"}
	_, err = s.WaitForActionWithTimeout(context.Background(), "bare", routingTimeout)
	assert.ErrorIs(t, err, ErrFlowNotFound)
}

func TestRouting_ActionForUnknownFlowIsAnsweredAndNotQueued(t *testing.T) {
	s, client := newRoutingSession(t)
	registerTestFlow(s, "live")
	s.flows["bare"] = &Flow{ID: "bare"}

	for _, id := range []string{"gone", "bare"} {
		s.dispatchAction(action(id, "consent"))
		fe := readFlowError(t, client)
		assert.Equal(t, ErrCodeUnknownFlow, fe.Error.Code)
		assert.Equal(t, id, fe.FlowID)
	}
	assert.Empty(t, s.flows["live"].actions, "a foreign action leaked into a live flow")
}

func TestRouting_ActionChannelFullIsBoundedAndAnswered(t *testing.T) {
	s, client := newRoutingSession(t)
	flow := registerTestFlow(s, "a")
	for i := 0; i < flowActionBuffer; i++ {
		s.dispatchAction(action("a", "x"))
	}
	require.Len(t, flow.actions, flowActionBuffer)

	s.dispatchAction(action("a", "overflow"))
	fe := readFlowError(t, client)
	assert.Equal(t, ErrCodeTooManyRequests, fe.Error.Code)
	assert.Len(t, flow.actions, flowActionBuffer, "memory is bounded by the buffer")

	// Another flow is unaffected by a's backlog.
	registerTestFlow(s, "b")
	s.dispatchAction(action("b", "x"))
	assert.Len(t, s.flows["b"].actions, 1)
}

// A flow's channel is released with the flow: nothing is left in the session.
func TestRouting_EndedFlowReleasesItsChannelAndRejectsLateActions(t *testing.T) {
	s, client := newRoutingSession(t)
	registerTestFlow(s, "a")
	s.dispatchAction(action("a", "x"))

	s.flowsMu.Lock()
	delete(s.flows, "a") // what handleFlowStart does when the flow ends
	s.flowsMu.Unlock()

	s.dispatchAction(action("a", "late"))
	assert.Equal(t, ErrCodeUnknownFlow, readFlowError(t, client).Error.Code)
	assert.Nil(t, s.flowActions("a"))
}

// readRequests reads n sign/match requests the session sent to the client.
func readRequests(t *testing.T, client *websocket.Conn, n int) []Message {
	t.Helper()
	var out []Message
	for len(out) < n {
		_ = client.SetReadDeadline(time.Now().Add(routingTimeout))
		_, data, err := client.ReadMessage()
		require.NoError(t, err)
		var m Message
		require.NoError(t, json.Unmarshal(data, &m))
		out = append(out, m)
	}
	return out
}

func TestRouting_ConcurrentMatchRequestsGetOwnReplies(t *testing.T) {
	s, client := newRoutingSession(t)
	type result struct {
		resp *MatchResponseMessage
		err  error
	}
	results := map[string]chan result{}
	for _, flowID := range []string{"flow-a", "flow-b"} {
		ch := make(chan result, 1)
		results[flowID] = ch
		go func() {
			r, err := s.RequestMatch(context.Background(), flowID, json.RawMessage(`{}`))
			ch <- result{r, err}
		}()
	}
	reqs := readRequests(t, client, 2)
	for i := len(reqs) - 1; i >= 0; i-- { // reverse arrival order
		s.dispatchMatchResponse(&MatchResponseMessage{
			Message:       Message{Type: TypeMatchResponse, FlowID: reqs[i].FlowID, MessageID: reqs[i].MessageID},
			NoMatchReason: reqs[i].FlowID,
		})
	}
	for flowID, ch := range results {
		r := <-ch
		require.NoError(t, r.err)
		assert.Equal(t, flowID, r.resp.NoMatchReason, "flow %s got another flow's reply", flowID)
	}
	assert.Zero(t, outstandingCount(s))
}

func TestRouting_ConcurrentSignRequestsOnDifferentFlowsGetOwnReplies(t *testing.T) {
	s, client := newRoutingSession(t)
	type result struct {
		resp *SignResponseMessage
		err  error
	}
	results := map[string]chan result{}
	for _, flowID := range []string{"flow-a", "flow-b", "finished"} {
		ch := make(chan result, 1)
		results[flowID] = ch
		go func() {
			r, err := s.RequestSign(context.Background(), flowID, SignActionGenerateProof, SignRequestParams{})
			ch <- result{r, err}
		}()
	}
	reqs := readRequests(t, client, 3)
	for i := len(reqs) - 1; i >= 0; i-- {
		s.dispatchSignResponse(&SignResponseMessage{
			Message:       Message{Type: TypeSignResponse, FlowID: reqs[i].FlowID, MessageID: reqs[i].MessageID},
			TransactionID: reqs[i].FlowID,
		})
	}
	for flowID, ch := range results {
		r := <-ch
		require.NoError(t, r.err)
		assert.Equal(t, flowID, r.resp.TransactionID)
	}
	assert.Zero(t, outstandingCount(s))
}

// startSign runs RequestSign and returns its message id once the request is on
// the wire, plus the call's result channel.
func startSign(t *testing.T, s *Session, client *websocket.Conn, ctx context.Context, flowID string) (string, <-chan error) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		_, err := s.RequestSign(ctx, flowID, SignActionGenerateProof, SignRequestParams{})
		errCh <- err
	}()
	return readRequests(t, client, 1)[0].MessageID, errCh
}

func TestRouting_SignReplyMustMatchRequestFlowAndKind(t *testing.T) {
	s, client := newRoutingSession(t)
	id, errCh := startSign(t, s, client, context.Background(), "flow-a")

	// Right message_id, wrong flow: dropped, the request stays pending.
	s.dispatchSignResponse(&SignResponseMessage{Message: Message{Type: TypeSignResponse, FlowID: "flow-b", MessageID: id}})
	assert.Equal(t, ErrCodeUnknownFlow, readFlowError(t, client).Error.Code)
	// A match reply for a sign request: dropped.
	s.dispatchMatchResponse(&MatchResponseMessage{Message: Message{Type: TypeMatchResponse, FlowID: "flow-a", MessageID: id}})
	assert.Equal(t, ErrCodeUnknownFlow, readFlowError(t, client).Error.Code)
	assert.Equal(t, 1, outstandingCount(s))
	select {
	case err := <-errCh:
		t.Fatalf("request completed on a reply that was not its own: %v", err)
	default:
	}

	// Without a flow_id the reply is correlated by message_id alone.
	s.dispatchSignResponse(&SignResponseMessage{Message: Message{Type: TypeSignResponse, MessageID: id}})
	require.NoError(t, <-errCh)
}

func TestRouting_MatchReplyMustNameTheRequestFlow(t *testing.T) {
	s, client := newRoutingSession(t)
	errCh := make(chan error, 1)
	go func() {
		_, err := s.RequestMatch(context.Background(), "flow-a", json.RawMessage(`{}`))
		errCh <- err
	}()
	id := readRequests(t, client, 1)[0].MessageID

	for _, flowID := range []string{"flow-b", ""} {
		s.dispatchMatchResponse(&MatchResponseMessage{Message: Message{Type: TypeMatchResponse, FlowID: flowID, MessageID: id}})
		assert.Equal(t, ErrCodeUnknownFlow, readFlowError(t, client).Error.Code)
	}
	s.dispatchSignResponse(&SignResponseMessage{Message: Message{Type: TypeSignResponse, MessageID: id}})
	assert.Equal(t, ErrCodeUnknownFlow, readFlowError(t, client).Error.Code, "a sign reply must not complete a match request")
	assert.Equal(t, 1, outstandingCount(s))

	s.dispatchMatchResponse(&MatchResponseMessage{Message: Message{Type: TypeMatchResponse, FlowID: "flow-a", MessageID: id}})
	require.NoError(t, <-errCh)
	assert.Zero(t, outstandingCount(s))
}

func TestRouting_DuplicateReplyIsDropped(t *testing.T) {
	s, client := newRoutingSession(t)
	reply, done := s.trackSign("m", "f")
	defer done()
	first := &SignResponseMessage{Message: Message{MessageID: "m"}, TransactionID: "first"}

	s.dispatchSignResponse(first)
	s.dispatchSignResponse(&SignResponseMessage{Message: Message{MessageID: "m"}, TransactionID: "second"})
	assertNoFurtherReply(t, client) // the request has an owner: no UNKNOWN_FLOW

	require.Len(t, reply, 1, "the duplicate must not be queued")
	assert.Equal(t, "first", (<-reply).TransactionID)
}

// A reply that arrives after the request completed, timed out or was
// cancelled has no owner: it is answered and dropped, and nothing is retained.
func TestRouting_LateReplyAfterCancelIsDroppedNotParked(t *testing.T) {
	s, client := newRoutingSession(t)
	ctx, cancel := context.WithCancel(context.Background())
	id, errCh := startSign(t, s, client, ctx, "f")
	cancel()
	require.ErrorIs(t, <-errCh, context.Canceled)
	assert.Zero(t, outstandingCount(s), "a cancelled request must release its entry")

	s.dispatchSignResponse(&SignResponseMessage{Message: Message{Type: TypeSignResponse, FlowID: "f", MessageID: id}})
	assert.Equal(t, ErrCodeUnknownFlow, readFlowError(t, client).Error.Code)

	// A new request is not fed the stale reply.
	id2, errCh2 := startSign(t, s, client, context.Background(), "f")
	assert.NotEqual(t, id, id2)
	select {
	case err := <-errCh2:
		t.Fatalf("a new request completed from a stale reply: %v", err)
	default:
	}
	s.dispatchSignResponse(&SignResponseMessage{Message: Message{MessageID: id2}})
	require.NoError(t, <-errCh2)
}

func TestRouting_LateReplyAfterMatchTimeoutIsDropped(t *testing.T) {
	s, client := newRoutingSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	_, err := s.RequestMatch(ctx, "f", json.RawMessage(`{}`))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Zero(t, outstandingCount(s))

	id := readRequests(t, client, 1)[0].MessageID
	s.dispatchMatchResponse(&MatchResponseMessage{Message: Message{Type: TypeMatchResponse, FlowID: "f", MessageID: id}})
	assert.Equal(t, ErrCodeUnknownFlow, readFlowError(t, client).Error.Code)
}

func TestRouting_SessionCloseReleasesWaiters(t *testing.T) {
	s, client := newRoutingSession(t)
	registerTestFlow(s, "a")
	waitA := make(chan error, 1)
	go func() {
		_, err := s.WaitForActionWithTimeout(context.Background(), "a", routingTimeout)
		waitA <- err
	}()
	_, errCh := startSign(t, s, client, context.Background(), "a")
	close(s.closeCh)
	assert.Error(t, <-waitA)
	assert.Error(t, <-errCh)
	assert.Zero(t, outstandingCount(s))
}

// End to end through the real read loop: two flows and a sign request on one
// socket, with client messages interleaved across them.
func TestRouting_ReadLoopDeliversInterleavedMessagesToTheirOwners(t *testing.T) {
	cl, s := unknownFlowHarness(t, "a", "b")
	waitA := waitAction(s, "a", "consent")
	waitB := waitAction(s, "b", "consent")
	signErr := make(chan error, 1)
	go func() {
		_, err := s.RequestSign(context.Background(), "a", SignActionGenerateProof, SignRequestParams{})
		signErr <- err
	}()
	_ = cl.SetReadDeadline(time.Now().Add(routingTimeout))
	var req SignRequestMessage
	require.NoError(t, cl.ReadJSON(&req))

	require.NoError(t, cl.WriteJSON(action("b", "consent")))
	require.NoError(t, cl.WriteJSON(SignResponseMessage{Message: Message{Type: TypeSignResponse, FlowID: "a", MessageID: req.MessageID}}))
	require.NoError(t, cl.WriteJSON(action("a", "consent")))

	require.NoError(t, <-signErr)
	assert.Equal(t, "a", (<-waitA).FlowID)
	assert.Equal(t, "b", (<-waitB).FlowID)
}
