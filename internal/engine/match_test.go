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
)

// wsTestServer creates an httptest server that upgrades to WebSocket and
// returns a connected client *websocket.Conn for testing.
func wsTestServer(t *testing.T, handler func(conn *websocket.Conn)) (*websocket.Conn, func()) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		handler(c)
	}))
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	return conn, func() { conn.Close(); server.Close() }
}

// testSession creates a Session with channels wired and the given conn.
func testSession(conn *websocket.Conn) *Session {
	return &Session{
		ID:       "test-session",
		UserID:   "test-user",
		TenantID: "default",
		conn:     conn,
		flows:    make(map[string]*Flow),
		logger:   zap.NewNop(),
		actionCh: make(chan *FlowActionMessage, 50),
		signCh:   make(chan *SignResponseMessage, 20),
		matchCh:  make(chan *MatchResponseMessage, 20),
		closeCh:  make(chan struct{}, 1),
	}
}

// --- RequestMatch tests ---

func TestSession_RequestMatch_Success(t *testing.T) {
	// Server side: read the match_request, send match_response
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		// Read the match_request message from the session
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var req MatchRequestMessage
		if err := json.Unmarshal(data, &req); err != nil {
			return
		}
		// Reply with a match_response carrying the same flow_id and message_id
		resp := MatchResponseMessage{
			Message: Message{
				Type:      TypeMatchResponse,
				FlowID:    req.FlowID,
				MessageID: req.MessageID,
				Timestamp: Now(),
			},
			Matches: []CredentialMatch{
				{CredentialQueryID: "id-1", CredentialID: "cred-abc"},
			},
		}
		_ = srvConn.WriteJSON(resp)
	})
	defer cleanup()

	session := testSession(conn)

	// Simulate the server-side delivery by reading from the ws client
	// and pushing into matchCh (mimicking handleSession's routing)
	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var matchMsg MatchResponseMessage
		if err := json.Unmarshal(data, &matchMsg); err != nil {
			return
		}
		session.matchCh <- &matchMsg
	}()

	ctx := context.Background()
	dcql := json.RawMessage(`{"credentials":[{"id":"id-1"}]}`)

	resp, err := session.RequestMatch(ctx, "flow-1", dcql)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Matches, 1)
	assert.Equal(t, "cred-abc", resp.Matches[0].CredentialID)
}

func TestSession_RequestMatch_Timeout(t *testing.T) {
	// Use a noop websocket server — never responds
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		// Read but never reply
		_, _, _ = srvConn.ReadMessage()
		time.Sleep(5 * time.Second) // outlive the test
	})
	defer cleanup()

	session := testSession(conn)

	// Override MatchTimeout to avoid waiting 30s in tests.
	// RequestMatch uses the package-level MatchTimeout constant,
	// so we test via context cancellation instead.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	pd := json.RawMessage(`{"credentials":[{"id":"timeout"}]}`)
	_, err := session.RequestMatch(ctx, "flow-timeout", pd)
	require.Error(t, err)
	// Either context deadline or match timeout, both are acceptable
	assert.True(t, err == context.DeadlineExceeded || err == ErrMatchTimeout,
		"expected DeadlineExceeded or ErrMatchTimeout, got: %v", err)
}

func TestSession_RequestMatch_ErrorInResponse(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var req MatchRequestMessage
		if err := json.Unmarshal(data, &req); err != nil {
			return
		}
		// Reply with an error response
		resp := MatchResponseMessage{
			Message: Message{
				Type:      TypeMatchResponse,
				FlowID:    req.FlowID,
				MessageID: req.MessageID,
				Timestamp: Now(),
			},
			Error: "client-side matching failed",
		}
		_ = srvConn.WriteJSON(resp)
	})
	defer cleanup()

	session := testSession(conn)

	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var matchMsg MatchResponseMessage
		if err := json.Unmarshal(data, &matchMsg); err != nil {
			return
		}
		session.matchCh <- &matchMsg
	}()

	ctx := context.Background()
	dcql := json.RawMessage(`{"credentials":[{"id":"error"}]}`)
	_, err := session.RequestMatch(ctx, "flow-error", dcql)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client-side matching failed")
}

func TestSession_RequestMatch_NoMatchReason(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var req MatchRequestMessage
		if err := json.Unmarshal(data, &req); err != nil {
			return
		}
		resp := MatchResponseMessage{
			Message: Message{
				Type:      TypeMatchResponse,
				FlowID:    req.FlowID,
				MessageID: req.MessageID,
				Timestamp: Now(),
			},
			Matches:       nil,
			NoMatchReason: "no credentials match the requested criteria",
		}
		_ = srvConn.WriteJSON(resp)
	})
	defer cleanup()

	session := testSession(conn)

	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var matchMsg MatchResponseMessage
		if err := json.Unmarshal(data, &matchMsg); err != nil {
			return
		}
		session.matchCh <- &matchMsg
	}()

	ctx := context.Background()
	dcql := json.RawMessage(`{"credentials":[{"id":"nomatch"}]}`)
	resp, err := session.RequestMatch(ctx, "flow-nomatch", dcql)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Matches)
	assert.Equal(t, "no credentials match the requested criteria", resp.NoMatchReason)
}

func TestSession_RequestMatch_SessionClosed(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, _, _ = srvConn.ReadMessage()
		time.Sleep(5 * time.Second)
	})
	defer cleanup()

	session := testSession(conn)

	// Close the session channel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(session.closeCh)
	}()

	ctx := context.Background()
	dcql := json.RawMessage(`{"credentials":[{"id":"close"}]}`)
	_, err := session.RequestMatch(ctx, "flow-close", dcql)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session closed")
}

func TestSession_RequestMatch_WrongFlowID_Ignored(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var req MatchRequestMessage
		if err := json.Unmarshal(data, &req); err != nil {
			return
		}
		// First: send a response with wrong flow_id
		wrong := MatchResponseMessage{
			Message: Message{
				Type:      TypeMatchResponse,
				FlowID:    "wrong-flow",
				MessageID: req.MessageID,
				Timestamp: Now(),
			},
			Matches: []CredentialMatch{{CredentialID: "should-be-ignored"}},
		}
		_ = srvConn.WriteJSON(wrong)
		// Then: send the correct response
		correct := MatchResponseMessage{
			Message: Message{
				Type:      TypeMatchResponse,
				FlowID:    req.FlowID,
				MessageID: req.MessageID,
				Timestamp: Now(),
			},
			Matches: []CredentialMatch{{CredentialID: "correct-cred"}},
		}
		_ = srvConn.WriteJSON(correct)
	})
	defer cleanup()

	session := testSession(conn)

	// Route both messages from the ws client into matchCh
	go func() {
		for i := 0; i < 2; i++ {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var matchMsg MatchResponseMessage
			if err := json.Unmarshal(data, &matchMsg); err != nil {
				return
			}
			session.matchCh <- &matchMsg
		}
	}()

	ctx := context.Background()
	dcql := json.RawMessage(`{"credentials":[{"id":"filter"}]}`)
	resp, err := session.RequestMatch(ctx, "flow-filter", dcql)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "correct-cred", resp.Matches[0].CredentialID)
}

// --- handleSession match_response routing test ---

func TestMatchResponseChannelRouting(t *testing.T) {
	// Test that a MatchResponseMessage pushed into matchCh is received
	session := &Session{
		matchCh: make(chan *MatchResponseMessage, 20),
		closeCh: make(chan struct{}, 1),
		logger:  zap.NewNop(),
	}

	msg := &MatchResponseMessage{
		Message: Message{
			Type:      TypeMatchResponse,
			FlowID:    "flow-1",
			MessageID: "msg-1",
		},
		Matches: []CredentialMatch{
			{CredentialQueryID: "id-1", CredentialID: "cred-1"},
		},
	}

	// Simulate handleSession's TypeMatchResponse branch
	select {
	case session.matchCh <- msg:
	default:
		t.Fatal("matchCh should accept message")
	}

	// Verify it comes out the other side
	select {
	case received := <-session.matchCh:
		assert.Equal(t, "flow-1", received.FlowID)
		assert.Equal(t, "msg-1", received.MessageID)
		assert.Len(t, received.Matches, 1)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for match response")
	}
}

func TestMatchResponseChannelFull(t *testing.T) {
	// When matchCh is full, the message should be dropped (select default branch)
	session := &Session{
		matchCh: make(chan *MatchResponseMessage), // unbuffered = immediately full
		closeCh: make(chan struct{}, 1),
		logger:  zap.NewNop(),
	}

	msg := &MatchResponseMessage{
		Message: Message{
			Type:   TypeMatchResponse,
			FlowID: "flow-full",
		},
	}

	// This should not block — hits the default case
	select {
	case session.matchCh <- msg:
		t.Fatal("should not have sent to unbuffered channel without receiver")
	default:
		// Expected: channel full, message dropped
	}
}

// --- BaseHandler.RequestMatch delegation test ---

func TestBaseHandler_RequestMatch(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var req MatchRequestMessage
		if err := json.Unmarshal(data, &req); err != nil {
			return
		}
		resp := MatchResponseMessage{
			Message: Message{
				Type:      TypeMatchResponse,
				FlowID:    req.FlowID,
				MessageID: req.MessageID,
				Timestamp: Now(),
			},
			Matches: []CredentialMatch{{CredentialID: "handler-cred"}},
		}
		_ = srvConn.WriteJSON(resp)
	})
	defer cleanup()

	session := testSession(conn)
	flow := &Flow{
		ID:      "flow-handler",
		Session: session,
	}
	handler := &BaseHandler{
		Flow:   flow,
		Logger: zap.NewNop(),
	}

	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var matchMsg MatchResponseMessage
		if err := json.Unmarshal(data, &matchMsg); err != nil {
			return
		}
		session.matchCh <- &matchMsg
	}()

	ctx := context.Background()
	dcql := json.RawMessage(`{"credentials":[{"id":"handler"}]}`)
	resp, err := handler.RequestMatch(ctx, dcql)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "handler-cred", resp.Matches[0].CredentialID)
}

func TestSession_RequestMatch_SendError(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		srvConn.Close() // close immediately so the client Send fails
	})
	defer cleanup()

	session := testSession(conn)

	// Close the client connection to trigger a Send error
	conn.Close()

	ctx := context.Background()
	dcql := json.RawMessage(`{"credentials":[{"id":"send-error"}]}`)
	_, err := session.RequestMatch(ctx, "flow-send-err", dcql)
	require.Error(t, err)
}
