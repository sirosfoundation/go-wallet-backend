package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// stuckStore is a session store whose Delete only returns when its context ends,
// like an unavailable Redis. onDelete runs at the start of every Delete.
type stuckStore struct {
	*MemorySessionStore
	onDelete func()
}

func (s *stuckStore) Delete(ctx context.Context, _ string) error {
	if s.onDelete != nil {
		s.onDelete()
	}
	<-ctx.Done()
	return ctx.Err()
}

// CloseContext ends every live session before touching the persistent store and
// returns once ctx expires, however many sessions a stuck store would hold up.
func TestWMPAdapter_CloseContext_BoundedByContextAndStopsSessionsFirst(t *testing.T) {
	a, m := testWMPAdapter()
	var sessions []*Session
	for _, user := range []string{"u1", "u2", "u3"} {
		sid, _, _ := createSessionFull(t, a, user, "t", nil)
		a.mu.RLock()
		sessions = append(sessions, a.peers[sid].session)
		a.mu.RUnlock()
	}

	var firstDelete sync.Once
	allEndedAtFirstDelete := false
	m.sessionStore = &stuckStore{MemorySessionStore: NewMemorySessionStore(zap.NewNop()), onDelete: func() {
		firstDelete.Do(func() {
			allEndedAtFirstDelete = true
			for _, s := range sessions {
				select {
				case <-s.closeCh:
				default:
					allEndedAtFirstDelete = false
				}
			}
		})
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { a.CloseContext(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("CloseContext did not return after its context expired")
	}
	require.Len(t, sessions, 3)
	assert.True(t, allEndedAtFirstDelete, "every session must be stopped before the first store delete")
	a.mu.RLock()
	assert.Empty(t, a.peers)
	a.mu.RUnlock()
}
