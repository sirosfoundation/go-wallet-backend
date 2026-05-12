package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

// SessionTransport abstracts the underlying communication channel for a session.
// Both WebSocket and HTTP+SSE implement this interface, allowing the engine
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

// sseTransport implements SessionTransport for HTTP+SSE.
// POST requests feed incoming messages; SSE stream sends outgoing messages.
type sseTransport struct {
	incoming  chan []byte
	closeCh   chan struct{}
	closeOnce sync.Once

	// SSE event buffering for Last-Event-ID replay.
	bufMu     sync.Mutex
	events    []sseEvent
	nextID    int64
	maxEvents int

	// SSE writer (set when client connects to GET /events).
	sseMu  sync.Mutex
	sseW   http.ResponseWriter
	sseFl  http.Flusher
	sseCtx context.Context
}

type sseEvent struct {
	ID   string
	Data []byte
}

func newSSETransport(maxEvents int) *sseTransport {
	if maxEvents <= 0 {
		maxEvents = 200
	}
	return &sseTransport{
		incoming:  make(chan []byte, 64),
		closeCh:   make(chan struct{}),
		maxEvents: maxEvents,
	}
}

func (t *sseTransport) SendJSON(msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Buffer the event.
	t.bufMu.Lock()
	t.nextID++
	id := fmt.Sprintf("evt-%d", t.nextID)
	t.events = append(t.events, sseEvent{ID: id, Data: data})
	if len(t.events) > t.maxEvents {
		t.events = t.events[len(t.events)-t.maxEvents:]
	}
	t.bufMu.Unlock()

	// Write to SSE stream if connected.
	t.sseMu.Lock()
	w, fl, ctx := t.sseW, t.sseFl, t.sseCtx
	t.sseMu.Unlock()

	if w != nil && ctx != nil && ctx.Err() == nil {
		_, _ = fmt.Fprintf(w, "id: %s\nevent: message\ndata: %s\n\n", id, data)
		fl.Flush()
	}

	return nil
}

func (t *sseTransport) ReadMessage(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.closeCh:
		return nil, fmt.Errorf("transport closed")
	case data := <-t.incoming:
		return data, nil
	}
}

func (t *sseTransport) Close() error {
	t.closeOnce.Do(func() {
		close(t.closeCh)
	})
	return nil
}

// pushMessage is called by POST handlers to feed a message into the transport.
func (t *sseTransport) pushMessage(data []byte) error {
	select {
	case t.incoming <- data:
		return nil
	case <-t.closeCh:
		return fmt.Errorf("transport closed")
	default:
		return fmt.Errorf("message queue full")
	}
}

// serveSSE handles the GET /events SSE connection, replaying missed events.
func (t *sseTransport) serveSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	// Replay missed events.
	lastEventID := r.Header.Get("Last-Event-ID")
	if lastEventID != "" {
		t.bufMu.Lock()
		var replay []sseEvent
		for i, ev := range t.events {
			if ev.ID == lastEventID && i+1 < len(t.events) {
				replay = make([]sseEvent, len(t.events)-i-1)
				copy(replay, t.events[i+1:])
				break
			}
		}
		t.bufMu.Unlock()
		for _, ev := range replay {
			_, _ = fmt.Fprintf(w, "id: %s\nevent: message\ndata: %s\n\n", ev.ID, ev.Data)
		}
		flusher.Flush()
	}

	// Register as active SSE writer.
	t.sseMu.Lock()
	t.sseW = w
	t.sseFl = flusher
	t.sseCtx = r.Context()
	t.sseMu.Unlock()

	defer func() {
		t.sseMu.Lock()
		t.sseW = nil
		t.sseFl = nil
		t.sseCtx = nil
		t.sseMu.Unlock()
	}()

	// Block until client disconnects or transport closes.
	select {
	case <-r.Context().Done():
	case <-t.closeCh:
	}
}
