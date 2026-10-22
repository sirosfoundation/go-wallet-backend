package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// keepaliveHarness serves one real read loop (Manager.handleSession) with the
// production keepalive wiring and short timings, and returns the client conn
// plus a channel closed when the server's read loop exits.
func keepaliveHarness(t *testing.T) (*websocket.Conn, *Session, <-chan struct{}) {
	t.Helper()
	m := NewManager(&config.Config{JWT: config.JWTConfig{Secret: "s", Issuer: "i"}}, zap.NewNop())
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	sessCh := make(chan *Session, 1)
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		s := testSession(c)
		s.pingInterval, s.pongTimeout = 100*time.Millisecond, 150*time.Millisecond
		configureKeepalive(c, s.pingInterval+s.pongTimeout)
		sessCh <- s
		m.handleSession(s)
		close(done)
	}))
	t.Cleanup(srv.Close)
	cl, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cl.Close() })
	return cl, <-sessCh, done
}

// A client that is actively sending but whose pongs never arrive (it never
// reads, so gorilla never answers pings) must not be timed out.
func TestKeepalive_InboundDataFramesExtendReadDeadline(t *testing.T) {
	cl, _, done := keepaliveHarness(t)
	for i := 0; i < 12; i++ { // ~720ms of traffic against a 250ms window
		require.NoError(t, cl.WriteMessage(websocket.TextMessage, []byte(`{"type":"nope"}`)))
		time.Sleep(60 * time.Millisecond)
		select {
		case <-done:
			t.Fatalf("session timed out after %d frames despite continuous inbound traffic", i+1)
		default:
		}
	}
	// ...and a silent peer is still dropped.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("silent peer was not timed out")
	}
}

// A client ping (answered with a pong) counts as life too.
func TestKeepalive_ClientPingExtendsReadDeadlineAndIsAnswered(t *testing.T) {
	cl, _, done := keepaliveHarness(t)
	var pongs atomic.Int32
	cl.SetPongHandler(func(string) error { pongs.Add(1); return nil })
	// The client does not read while pinging, so it never answers the
	// server's pings: only its own pings can keep the session alive.
	for i := 0; i < 10; i++ {
		require.NoError(t, cl.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)))
		time.Sleep(60 * time.Millisecond)
		select {
		case <-done:
			t.Fatal("session timed out despite client pings")
		default:
		}
	}
	_ = cl.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	for {
		if _, _, err := cl.ReadMessage(); err != nil {
			break
		}
	}
	assert.Positive(t, pongs.Load(), "client ping was not answered with a pong")
}

// A data write that is blocked while holding sendMu must not stop pings.
func TestPingLoop_NotBlockedByHeldSendMutex(t *testing.T) {
	cl, s, _ := keepaliveHarness(t)
	var pings atomic.Int32
	cl.SetPingHandler(func(string) error {
		pings.Add(1)
		return cl.WriteControl(websocket.PongMessage, nil, time.Now().Add(time.Second))
	})
	go func() {
		for {
			if _, _, err := cl.ReadMessage(); err != nil {
				return
			}
		}
	}()

	s.sendMu.Lock() // simulates an in-flight, blocked s.Send
	defer s.sendMu.Unlock()
	go s.pingLoop()
	defer close(s.stopPing)

	require.Eventually(t, func() bool { return pings.Load() >= 2 }, 2*time.Second, 20*time.Millisecond,
		"pingLoop must keep pinging while sendMu is held")
}
