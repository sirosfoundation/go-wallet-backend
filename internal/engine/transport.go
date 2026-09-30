package engine

import (
	"context"
	"sync"

	"github.com/gorilla/websocket"
)

// SessionTransport abstracts the underlying communication channel for a session.
// WebSocket and WMP (see wmpSessionTransport) implement this interface, allowing the engine
// to be transport-agnostic.
type SessionTransport interface {
	// SendJSON marshals and sends a message to the client.
	SendJSON(msg interface{}) error

	// ReadMessage blocks until a message is received from the client.
	// Returns the raw JSON bytes. For HTTP+SSE this is fed from POST requests.
	ReadMessage(ctx context.Context) ([]byte, error)

	// Close closes the transport.
	Close() error
}

// wsTransport wraps a gorilla/websocket.Conn as a SessionTransport.
type wsTransport struct {
	conn   *websocket.Conn
	sendMu sync.Mutex
}

func newWSTransport(conn *websocket.Conn) *wsTransport {
	return &wsTransport{conn: conn}
}

func (t *wsTransport) SendJSON(msg interface{}) error {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	return t.conn.WriteJSON(msg)
}

func (t *wsTransport) ReadMessage(_ context.Context) ([]byte, error) {
	_, data, err := t.conn.ReadMessage()
	return data, err
}

func (t *wsTransport) Close() error {
	return t.conn.Close()
}
