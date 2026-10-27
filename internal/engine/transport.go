package engine

import (
	"context"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// SessionTransport abstracts the communication channel for a session
// (WebSocket or WMP), keeping the engine transport-agnostic.
type SessionTransport interface {
	// SendJSON marshals and sends a message to the client.
	SendJSON(msg interface{}) error

	// ReadMessage blocks until a message is received from the client.
	// Returns the raw JSON bytes. For HTTP+SSE this is fed from POST requests.
	ReadMessage(ctx context.Context) ([]byte, error)

	// Close closes the transport.
	Close() error
}

// ReplaceableTransport is implemented by a transport that can be swapped out
// while a session is live (e.g. a resumed connection). Session.ReplaceTransport
// calls retire before the swap and handOff, with the successor, after it.
type ReplaceableTransport interface {
	SessionTransport
	retire()
	handOff(next SessionTransport)
}

// wsTransport wraps a gorilla/websocket.Conn as a SessionTransport.
type wsTransport struct {
	conn   *websocket.Conn
	sendMu sync.Mutex

	// readWindow, when positive, makes ReadMessage count any inbound frame
	// (including a data message that arrives in fragments) as liveness by
	// pushing the read deadline out by this much. Set once before the read
	// loop starts.
	readWindow time.Duration
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
	if t.readWindow > 0 {
		_, data, err := readMessageRefreshingDeadline(t.conn, t.readWindow)
		return data, err
	}
	_, data, err := t.conn.ReadMessage()
	return data, err
}

func (t *wsTransport) Close() error {
	return t.conn.Close()
}
