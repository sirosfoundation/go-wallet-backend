package engine

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stashAction must hold the flows read lock until the entry is inserted.
func TestStashAction_HoldsFlowReadLockThroughInsertion(t *testing.T) {
	s := &Session{flows: map[string]*Flow{"f": {ID: "f"}}}

	s.stash.mu.Lock() // make the insertion block after the existence check
	done := make(chan struct{})
	go func() {
		s.stashAction(&FlowActionMessage{Message: Message{FlowID: "f"}, Action: "x"})
		close(done)
	}()

	require.Eventually(t, func() bool {
		// Once stashAction holds the read lock, a writer cannot get in.
		if s.flowsMu.TryLock() {
			s.flowsMu.Unlock()
			return false
		}
		return true
	}, time.Second, time.Millisecond, "flowsMu must be read-held while inserting")

	s.stash.mu.Unlock()
	<-done
}
