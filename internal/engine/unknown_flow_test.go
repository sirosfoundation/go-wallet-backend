package engine

import (
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
	m := NewManager(&config.Config{JWT: config.JWTConfig{Secret: "s", Issuer: "i"}}, zap.NewNop())
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
			s.flows[id] = &Flow{ID: id, Session: s}
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
	// "theirs" exists, but only in another session's table.
	cl, _ := unknownFlowHarness(t, "mine")
	require.NoError(t, cl.WriteMessage(websocket.TextMessage,
		[]byte(`{"type":"flow_action","flow_id":"theirs","action":"decline"}`)))
	fe := readFlowError(t, cl)
	assert.Equal(t, ErrCodeUnknownFlow, fe.Error.Code)
	assert.Equal(t, "theirs", fe.FlowID)
	assert.Equal(t, "Flow not found or already completed", fe.Error.Message)
}

func TestUnknownFlow_KnownFlowUnaffected(t *testing.T) {
	cl, s := unknownFlowHarness(t, "live")
	require.NoError(t, cl.WriteMessage(websocket.TextMessage,
		[]byte(`{"type":"flow_action","flow_id":"live","action":"decline"}`)))
	select {
	case a := <-s.actionCh:
		assert.Equal(t, "live", a.FlowID)
		assert.Equal(t, ActionDecline, a.Action)
	case <-time.After(2 * time.Second):
		t.Fatal("action for a known flow was not routed")
	}
	assertNoFurtherReply(t, cl)

	// sign/match responses without a flow_id keep their message_id-only routing.
	require.NoError(t, cl.WriteMessage(websocket.TextMessage, []byte(`{"type":"sign_response","message_id":"m1"}`)))
	select {
	case r := <-s.signCh:
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
