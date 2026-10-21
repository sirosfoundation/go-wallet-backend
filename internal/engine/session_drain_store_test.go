package engine

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// stuckPutStore is a session store whose Put only returns when its context ends,
// like an unavailable Redis. entered is closed when the first Put starts.
type stuckPutStore struct {
	*MemorySessionStore
	entered chan struct{}
}

func (s *stuckPutStore) Put(ctx context.Context, _ *SessionData) error {
	select {
	case <-s.entered:
	default:
		close(s.entered)
	}
	<-ctx.Done()
	return ctx.Err()
}

// closeOnlyTransport is a SessionTransport that only supports Close.
type closeOnlyTransport struct{ SessionTransport }

func (closeOnlyTransport) Close() error { return nil }

// registerSession holds sessionsMu across store I/O. Drain must not wait for it
// (it is the first, synchronous shutdown step), and must cancel the stalled
// registration so it releases the lock.
func TestManager_Drain_NotBlockedByRegistrationStuckInStore(t *testing.T) {
	m := testManager()
	store := &stuckPutStore{MemorySessionStore: NewMemorySessionStore(zap.NewNop()), entered: make(chan struct{})}
	m.SetSessionStore(store)

	session := &Session{ID: "stuck-reg", UserID: "u", TenantID: "t", transport: closeOnlyTransport{}, flows: make(map[string]*Flow), logger: zap.NewNop(), closeCh: make(chan struct{}, 1)}
	registered := make(chan bool, 1)
	go func() { registered <- m.registerSession(session) }()
	select {
	case <-store.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("registration never reached the store")
	}

	drained := make(chan struct{})
	go func() { m.Drain(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("Drain blocked behind a registration stalled in the session store")
	}
	select {
	case ok := <-registered:
		assert.True(t, ok, "the in-flight registration completes (Close sweeps it)")
	case <-time.After(2 * time.Second):
		t.Fatal("Drain did not cancel the stalled registration")
	}
	require.True(t, m.isDraining())

	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked")
	}
}
