package engine

import (
	"context"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- wsTransport ---
//
// wsTestServer (defined in match_test.go) spins up a real WebSocket server
// and returns a connected client *websocket.Conn, which is what wsTransport
// wraps in production — so these tests exercise ReadMessage/Close against an
// actual connection rather than a mock.

func TestWSTransport_ReadMessage(t *testing.T) {
	want := []byte(`{"hello":"world"}`)
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_ = srvConn.WriteMessage(websocket.TextMessage, want)
	})
	defer cleanup()

	wst := newWSTransport(conn)

	data, err := wst.ReadMessage(context.Background())
	require.NoError(t, err)
	assert.Equal(t, want, data)
}

// TestWSTransport_ReadMessage_AfterClose verifies ReadMessage surfaces an
// error once the underlying connection has been closed by the peer, rather
// than blocking forever or returning stale data.
func TestWSTransport_ReadMessage_AfterClose(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		// Close immediately; the client's blocking ReadMessage must return
		// an error rather than hang.
		srvConn.Close()
	})
	defer cleanup()

	wst := newWSTransport(conn)

	_, err := wst.ReadMessage(context.Background())
	assert.Error(t, err)
}

// TestWSTransport_Close verifies Close closes the underlying connection: a
// subsequent read on the same transport must fail rather than block.
func TestWSTransport_Close(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		// Keep the server side alive long enough to observe the client-side
		// close; the assertion is entirely about the client's own
		// wsTransport, not what the server sees.
		_, _, _ = srvConn.ReadMessage()
	})
	defer cleanup()

	wst := newWSTransport(conn)

	require.NoError(t, wst.Close())

	_, err := wst.ReadMessage(context.Background())
	assert.Error(t, err, "reading from a closed wsTransport must fail")
}
