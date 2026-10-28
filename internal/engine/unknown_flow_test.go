package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// unknownFlowHarness runs Manager.handleSession for a Session whose flow
// table the test controls, and returns the client side of the connection.
func unknownFlowHarness(t *testing.T, flows ...string) (*websocket.Conn, *Session) {
	t.Helper()
	return unknownFlowHarnessOn(t, NewManager(&config.Config{JWT: config.JWTConfig{Secret: "s", Issuer: "i"}}, zap.NewNop()), flows...)
}

// unknownFlowHarnessOn is unknownFlowHarness on a caller-supplied Manager, so
// several sessions can share one.
func unknownFlowHarnessOn(t *testing.T, m *Manager, flows ...string) (*websocket.Conn, *Session) {
	t.Helper()
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	sessCh := make(chan *Session, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		s := testSession(c)
		for _, id := range flows {
			registerTestFlow(s, id)
		}
		sessCh <- s
		m.handleSession(s)
	}))
	t.Cleanup(srv.Close)
	cl, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cl.Close() })
	return cl, <-sessCh
}

func readFlowError(t *testing.T, cl *websocket.Conn) FlowErrorMessage {
	t.Helper()
	_ = cl.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, data, err := cl.ReadMessage()
	require.NoError(t, err, "expected a flow_error reply, got silence")
	var fe FlowErrorMessage
	require.NoError(t, json.Unmarshal(data, &fe))
	return fe
}

func assertNoFurtherReply(t *testing.T, cl *websocket.Conn) {
	t.Helper()
	_ = cl.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, data, err := cl.ReadMessage()
	assert.Error(t, err, "unexpected extra frame: %s", data)
}

func TestUnknownFlow_EveryFlowReferencingMessageGetsOneFlowError(t *testing.T) {
	cases := map[string]string{
		"flow_action decline": `{"type":"flow_action","flow_id":"gone-1","action":"decline"}`,
		"sign_response":       `{"type":"sign_response","flow_id":"gone-1","message_id":"m1"}`,
		"match_response":      `{"type":"match_response","flow_id":"gone-1","message_id":"m1","matches":[]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			cl, _ := unknownFlowHarness(t)
			require.NoError(t, cl.WriteMessage(websocket.TextMessage, []byte(raw)))
			fe := readFlowError(t, cl)
			assert.Equal(t, TypeFlowError, fe.Type)
			assert.Equal(t, "gone-1", fe.FlowID)
			assert.Equal(t, ErrCodeUnknownFlow, fe.Error.Code)
			assertNoFurtherReply(t, cl)
		})
	}
}

func TestUnknownFlow_OtherSessionsFlowIsIndistinguishable(t *testing.T) {
	m := NewManager(&config.Config{JWT: config.JWTConfig{Secret: "s", Issuer: "i"}}, zap.NewNop())
	// "theirs" is live, but only in the second session's table.
	cl1, _ := unknownFlowHarnessOn(t, m, "mine")
	cl2, s2 := unknownFlowHarnessOn(t, m, "theirs")

	for name, raw := range map[string]string{
		"flow_action":    `{"type":"flow_action","flow_id":"%s","action":"decline"}`,
		"sign_response":  `{"type":"sign_response","flow_id":"%s","message_id":"m1"}`,
		"match_response": `{"type":"match_response","flow_id":"%s","message_id":"m1","matches":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			var replies [2]FlowErrorMessage
			for i, id := range []string{"theirs", "absent"} {
				require.NoError(t, cl1.WriteMessage(websocket.TextMessage, []byte(strings.Replace(raw, "%s", id, 1))))
				replies[i] = readFlowError(t, cl1)
				assert.Equal(t, id, replies[i].FlowID)
			}
			assert.Equal(t, ErrCodeUnknownFlow, replies[0].Error.Code)
			// Identical apart from the echoed flow_id.
			replies[1].FlowID, replies[1].Timestamp = replies[0].FlowID, replies[0].Timestamp
			assert.Equal(t, replies[0], replies[1])
		})
	}
	// The other session's flow is untouched and still routable there.
	require.NoError(t, cl2.WriteMessage(websocket.TextMessage,
		[]byte(`{"type":"flow_action","flow_id":"theirs","action":"decline"}`)))
	select {
	case a := <-s2.flows["theirs"].actions:
		assert.Equal(t, "theirs", a.FlowID)
	case <-time.After(2 * time.Second):
		t.Fatal("live flow on its own session was not routed")
	}
}

func TestUnknownFlow_LiveFlowSignAndMatchResponsesAreDelivered(t *testing.T) {
	cl, s := unknownFlowHarness(t, "live")
	signCh, doneSign := s.trackSign("s1", "live")
	defer doneSign()
	matchCh, doneMatch := s.trackMatch("m1", "live")
	defer doneMatch()
	require.NoError(t, cl.WriteMessage(websocket.TextMessage,
		[]byte(`{"type":"sign_response","flow_id":"live","message_id":"s1"}`)))
	require.NoError(t, cl.WriteMessage(websocket.TextMessage,
		[]byte(`{"type":"match_response","flow_id":"live","message_id":"m1","matches":[]}`)))
	select {
	case r := <-signCh:
		assert.Equal(t, "s1", r.MessageID)
	case <-time.After(2 * time.Second):
		t.Fatal("sign_response for a live flow was not routed")
	}
	select {
	case r := <-matchCh:
		assert.Equal(t, "m1", r.MessageID)
	case <-time.After(2 * time.Second):
		t.Fatal("match_response for a live flow was not routed")
	}
	assertNoFurtherReply(t, cl)
}

// client-held DPoP signing addresses sign requests to a flow that has already
// completed; the response must still reach RequestSign.
func TestUnknownFlow_SignResponseForCompletedFlowDeliveredWhileRequestOutstanding(t *testing.T) {
	cl, s := unknownFlowHarness(t) // the flow "done" no longer exists
	type result struct {
		resp *SignResponseMessage
		err  error
	}
	res := make(chan result, 1)
	go func() {
		r, err := s.RequestSign(context.Background(), "done", SignActionSignClientAuth, SignRequestParams{})
		res <- result{r, err}
	}()
	_ = cl.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, data, err := cl.ReadMessage()
	require.NoError(t, err)
	var req SignRequestMessage
	require.NoError(t, json.Unmarshal(data, &req))
	require.NoError(t, cl.WriteJSON(SignResponseMessage{
		Message: Message{Type: TypeSignResponse, FlowID: "done", MessageID: req.MessageID},
	}))
	select {
	case r := <-res:
		require.NoError(t, r.err)
		assert.Equal(t, req.MessageID, r.resp.MessageID)
	case <-time.After(2 * time.Second):
		t.Fatal("response for an outstanding request on a completed flow was rejected")
	}
	// Once answered, a replay is unknown.
	require.NoError(t, cl.WriteJSON(SignResponseMessage{
		Message: Message{Type: TypeSignResponse, FlowID: "done", MessageID: req.MessageID},
	}))
	assert.Equal(t, ErrCodeUnknownFlow, readFlowError(t, cl).Error.Code)
}

func TestUnknownFlow_KnownFlowUnaffected(t *testing.T) {
	cl, s := unknownFlowHarness(t, "live")
	require.NoError(t, cl.WriteMessage(websocket.TextMessage,
		[]byte(`{"type":"flow_action","flow_id":"live","action":"decline"}`)))
	select {
	case a := <-s.flows["live"].actions:
		assert.Equal(t, "live", a.FlowID)
		assert.Equal(t, ActionDecline, a.Action)
	case <-time.After(2 * time.Second):
		t.Fatal("action for a known flow was not routed")
	}
	assertNoFurtherReply(t, cl)

	// sign/match responses without a flow_id keep their message_id-only routing.
	signCh, doneSign := s.trackSign("m1", "live")
	defer doneSign()
	require.NoError(t, cl.WriteMessage(websocket.TextMessage, []byte(`{"type":"sign_response","message_id":"m1"}`)))
	select {
	case r := <-signCh:
		assert.Equal(t, "m1", r.MessageID)
	case <-time.After(2 * time.Second):
		t.Fatal("sign_response without flow_id was not routed")
	}
}

func TestUnknownFlow_RepliesAreRateLimited(t *testing.T) {
	cl, _ := unknownFlowHarness(t)
	const sent = 200
	for i := 0; i < sent; i++ {
		require.NoError(t, cl.WriteMessage(websocket.TextMessage,
			[]byte(`{"type":"flow_action","flow_id":"gone","action":"decline"}`)))
	}
	replies := 0
	for {
		_ = cl.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, _, err := cl.ReadMessage(); err != nil {
			break
		}
		replies++
	}
	assert.GreaterOrEqual(t, replies, unknownFlowErrorBurst)
	assert.Less(t, replies, sent/2, "a flood of unknown-flow messages must not be echoed 1:1")
}
