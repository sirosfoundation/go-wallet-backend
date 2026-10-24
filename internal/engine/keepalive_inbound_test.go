package engine

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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
	return keepaliveHarnessWindow(t, 250*time.Millisecond)
}

// keepaliveHarnessWindow is keepaliveHarness with an explicit initial read-deadline window.
func keepaliveHarnessWindow(t *testing.T, window time.Duration) (*websocket.Conn, *Session, <-chan struct{}) {
	t.Helper()
	return keepaliveHarnessConn(t, window, nil)
}

// keepaliveHarnessConn is keepaliveHarnessWindow with the accepted server-side
// net.Conn optionally wrapped (wrap may be nil), so a test can control the
// socket write path deterministically.
func keepaliveHarnessConn(t *testing.T, window time.Duration, wrap func(net.Conn) net.Conn) (*websocket.Conn, *Session, <-chan struct{}) {
	t.Helper()
	m := NewManager(&config.Config{JWT: config.JWTConfig{Secret: "s", Issuer: "i"}}, zap.NewNop())
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	sessCh := make(chan *Session, 1)
	done := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		s := testSession(c)
		s.pingInterval, s.pongTimeout = 100*time.Millisecond, 150*time.Millisecond
		configureKeepalive(c, window)
		sessCh <- s
		m.handleSession(s)
		close(done)
	}))
	if wrap != nil {
		srv.Listener = &wrapListener{Listener: srv.Listener, wrap: wrap}
	}
	srv.Start()
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
	go s.pingLoop() // stopped by handleSession's cleanup, which owns stopPing

	require.Eventually(t, func() bool { return pings.Load() >= 2 }, 2*time.Second, 20*time.Millisecond,
		"pingLoop must keep pinging while sendMu is held")
}

// A message that arrives in fragments spanning several keepalive windows,
// with no pong or ping in between, is continuous liveness.
func TestKeepalive_FragmentedMessageExtendsReadDeadline(t *testing.T) {
	m := NewManager(&config.Config{JWT: config.JWTConfig{Secret: "s", Issuer: "i"}}, zap.NewNop())
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
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
		m.handleSession(s)
		close(done)
	}))
	t.Cleanup(srv.Close)
	d := websocket.Dialer{WriteBufferSize: 256} // small buffer => a frame per chunk
	cl, _, err := d.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cl.Close() })

	w, err := cl.NextWriter(websocket.TextMessage)
	require.NoError(t, err)
	_, err = w.Write([]byte(`{"type":"nope","pad":"`))
	require.NoError(t, err)
	for i := 0; i < 10; i++ { // ~800ms against a 250ms window
		_, err = w.Write([]byte(strings.Repeat("x", 300))) // exceeds the buffer: flushes a fragment
		require.NoError(t, err)
		time.Sleep(80 * time.Millisecond)
		select {
		case <-done:
			t.Fatalf("session timed out mid-message after %d fragments", i+1)
		default:
		}
	}
	_, err = w.Write([]byte(`"}`))
	require.NoError(t, err)
	require.NoError(t, w.Close())
}

// A data write stuck in the socket for longer than a ping's deadline makes
// WriteControl time out; the ping loop must survive that and resume.
func TestPingLoop_SurvivesBlockedTransportWrite(t *testing.T) {
	cl, s, _ := keepaliveHarnessWindow(t, time.Minute)
	var pings atomic.Int32
	cl.SetPingHandler(func(string) error { pings.Add(1); return nil })

	// Fill the socket buffers while the client is not reading, so s.Send
	// blocks inside the transport write.
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		big := map[string]string{"pad": strings.Repeat("x", 1<<20)}
		for i := 0; i < 64; i++ {
			if s.Send(big) != nil {
				return
			}
		}
	}()
	go s.pingLoop()
	time.Sleep(600 * time.Millisecond) // several ping deadlines pass while the write is stuck

	go func() { // client starts draining: the write and the pings flow again
		for {
			if _, _, err := cl.ReadMessage(); err != nil {
				return
			}
		}
	}()
	before := pings.Load()
	require.Eventually(t, func() bool { return pings.Load() >= before+2 }, 5*time.Second, 20*time.Millisecond,
		"pings did not resume after a transport write stall")
}

type wrapListener struct {
	net.Listener
	wrap func(net.Conn) net.Conn
}

func (l *wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.wrap(c), nil
}

// stalledWriteConn is a net.Conn whose Write, once armed, blocks until the
// write deadline passes and then fails with a timeout error, exactly as a
// socket with a full send buffer behaves. Unlike a real socket it can never
// absorb a small write into leftover buffer space, so it is deterministic.
type stalledWriteConn struct {
	net.Conn
	armed    atomic.Bool
	deadline atomic.Int64 // unix nanos; 0 = none
}

func (c *stalledWriteConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.deadline.Store(0)
	} else {
		c.deadline.Store(t.UnixNano())
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *stalledWriteConn) Write(p []byte) (int, error) {
	if !c.armed.Load() {
		return c.Conn.Write(p)
	}
	d := c.deadline.Load()
	if d == 0 {
		return 0, os.ErrDeadlineExceeded // never block forever
	}
	time.Sleep(time.Until(time.Unix(0, d)))
	return 0, os.ErrDeadlineExceeded
}

// When the ping's own socket write times out the connection can no longer
// send anything; it must be closed, not retried forever.
func TestPingLoop_ClosesConnectionWhenControlWriteItselfTimesOut(t *testing.T) {
	var stall *stalledWriteConn
	cl, s, done := keepaliveHarnessConn(t, time.Minute, func(c net.Conn) net.Conn {
		stall = &stalledWriteConn{Conn: c}
		return stall
	})
	_ = cl
	stall.armed.Store(true) // every socket write from now on times out
	go s.pingLoop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connection was not closed after the ping write itself timed out")
	}
}
