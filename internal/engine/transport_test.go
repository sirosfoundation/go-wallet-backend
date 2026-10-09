package engine

import (
	"context"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- wsTransport ---
// wsTestServer (match_test.go) provides a real WebSocket connection, as in production.

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

// TestWSTransport_ReadMessage_AfterClose verifies ReadMessage errors after the peer closes.
func TestWSTransport_ReadMessage_AfterClose(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		// Close immediately; the client's ReadMessage must return an error.
		srvConn.Close()
	})
	defer cleanup()

	wst := newWSTransport(conn)

	_, err := wst.ReadMessage(context.Background())
	assert.Error(t, err)
}

// TestWSTransport_Close verifies a read after Close fails rather than blocks.
func TestWSTransport_Close(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		// Keep the server side alive; the assertion is about the client's wsTransport.
		_, _, _ = srvConn.ReadMessage()
	})
	defer cleanup()

	wst := newWSTransport(conn)

	require.NoError(t, wst.Close())

	_, err := wst.ReadMessage(context.Background())
	assert.Error(t, err, "reading from a closed wsTransport must fail")
}
