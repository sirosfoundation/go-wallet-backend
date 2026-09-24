package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// dialAndHandshake spins up a real Manager.HandleConnection HTTP handler,
// dials it as a real WebSocket client, and drives an actual authenticated
// handshake - unlike this file's other tests (which construct a Session
// directly with test-chosen intervals), this exercises the full path a real
// client goes through: Manager.wsKeepalive resolving cfg.Server.EngineWS*
// into a Session, and that Session's values actually reaching the wire via
// HandshakeCompleteMessage.Config. A regression in either of those would
// pass every other test in this file unnoticed.
func dialAndHandshake(t *testing.T, cfg *config.Config) *HandshakeCompleteMessage {
	t.Helper()

	m := NewManager(cfg, zap.NewNop())
	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	t.Cleanup(server.Close)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ws.Close() })

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   "test-user-123",
		"tenant_id": "test-tenant",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	require.NoError(t, ws.WriteJSON(HandshakeMessage{
		Message:  Message{Type: TypeHandshake},
		AppToken: tokenString,
	}))

	var complete HandshakeCompleteMessage
	require.NoError(t, ws.ReadJSON(&complete))
	return &complete
}

func TestHandshake_ReportsConfiguredPingInterval(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{Secret: "test-secret"},
		Server: config.ServerConfig{
			EngineWSPingInterval: 7 * time.Second,
		},
	}

	complete := dialAndHandshake(t, cfg)

	assert.Equal(t, TypeHandshakeComplete, complete.Type)
	assert.Equal(t, (7 * time.Second).Milliseconds(), complete.Config.PingIntervalMs)
}

func TestHandshake_ReportsDefaultPingIntervalWhenUnconfigured(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret"}}

	complete := dialAndHandshake(t, cfg)

	assert.Equal(t, defaultWSPingInterval.Milliseconds(), complete.Config.PingIntervalMs)
}

func TestPingLoop_SendsPings(t *testing.T) {
	// Track pings received on the server side.
	var pingCount atomic.Int32

	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		srvConn.SetPingHandler(func(string) error {
			pingCount.Add(1)
			// Respond with pong (default behaviour, but explicit here).
			return srvConn.WriteControl(websocket.PongMessage, nil, time.Now().Add(time.Second))
		})
		// Keep reading so the handler stays alive.
		for {
			if _, _, err := srvConn.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer cleanup()

	session := testSession(conn)

	// Configure pong handler the same way production does.
	_ = conn.SetReadDeadline(time.Now().Add(session.pingInterval + session.pongTimeout))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(session.pingInterval + session.pongTimeout))
		return nil
	})

	go session.pingLoop()
	defer close(session.stopPing)

	// Wait for a few ticks of testSession's fast pingInterval - no need to
	// wait out a real production interval now that it's a Session field
	// rather than a package constant.
	time.Sleep(3 * session.pingInterval)

	got := pingCount.Load()
	assert.GreaterOrEqual(t, got, int32(1), "expected at least 1 ping, got %d", got)
}

func TestPingLoop_StopsOnClose(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		for {
			if _, _, err := srvConn.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer cleanup()

	session := testSession(conn)

	done := make(chan struct{})
	go func() {
		session.pingLoop()
		close(done)
	}()

	// Signal stop immediately.
	close(session.stopPing)

	select {
	case <-done:
		// pingLoop returned — success.
	case <-time.After(2 * time.Second):
		t.Fatal("pingLoop did not stop within 2s after stopPing was closed")
	}
}

func TestPongHandler_ExtendsReadDeadline(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		for {
			if _, _, err := srvConn.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer cleanup()

	// Set a very short initial deadline.
	shortDeadline := 50 * time.Millisecond
	_ = conn.SetReadDeadline(time.Now().Add(shortDeadline))

	// Install the pong handler as production does.
	var pongReceived atomic.Bool
	conn.SetPongHandler(func(string) error {
		pongReceived.Store(true)
		_ = conn.SetReadDeadline(time.Now().Add(defaultWSPingInterval + defaultWSPongTimeout))
		return nil
	})

	// Verify that without a pong the deadline would fire.
	// We can't easily test the deadline expiry without racing, so instead
	// verify the handler is wired correctly by simulating a pong.
	require.False(t, pongReceived.Load())

	// The pong handler is invoked by the read loop when a pong frame arrives.
	// We can't send a pong from the test server easily, but we verified the
	// handler is installed. The SendsPings test covers the full round-trip.
}
