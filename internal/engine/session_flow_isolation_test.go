package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- concurrent flows on one session must not lose each other's input ---

func TestSession_ConcurrentFlowsDoNotLoseActions(t *testing.T) {
	s := &Session{
		flows:    map[string]*Flow{},
		actionCh: make(chan *FlowActionMessage, 50),
		signCh:   make(chan *SignResponseMessage, 20),
		matchCh:  make(chan *MatchResponseMessage, 20),
		closeCh:  make(chan struct{}, 1),
	}
	const n = 3
	for i := 0; i < n; i++ {
		s.flows[flowName(i)] = &Flow{ID: flowName(i)}
	}

	type result struct {
		flow string
		act  *FlowActionMessage
		err  error
	}
	results := make(chan result, n)
	for i := 0; i < n; i++ {
		go func(id string) {
			a, err := s.WaitForActionWithTimeout(context.Background(), id, 3*time.Second, "consent")
			results <- result{id, a, err}
		}(flowName(i))
	}
	time.Sleep(50 * time.Millisecond) // let the waiters start consuming

	// Deliver in reverse order so every waiter reads other flows' actions.
	for i := n - 1; i >= 0; i-- {
		s.actionCh <- &FlowActionMessage{Message: Message{FlowID: flowName(i)}, Action: "consent"}
	}
	for i := 0; i < n; i++ {
		r := <-results
		require.NoError(t, r.err, "flow %s lost its action", r.flow)
		assert.Equal(t, r.flow, r.act.FlowID)
	}
}

func TestSession_ConcurrentSignAndMatchResponsesRouted(t *testing.T) {
	s := &Session{
		flows:    map[string]*Flow{},
		actionCh: make(chan *FlowActionMessage, 50),
		signCh:   make(chan *SignResponseMessage, 20),
		matchCh:  make(chan *MatchResponseMessage, 20),
		closeCh:  make(chan struct{}, 1),
	}
	tr := &recordingTransport{}
	s.transport = tr

	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 3; i++ {
		wg.Add(2)
		fid := flowName(i)
		go func() {
			defer wg.Done()
			r, err := s.RequestSign(context.Background(), fid, SignActionGenerateProof, SignRequestParams{})
			if err == nil && r.FlowID != fid {
				err = assert.AnError
			}
			errs <- err
		}()
		go func() {
			defer wg.Done()
			r, err := s.RequestMatch(context.Background(), fid, []byte(`{}`))
			if err == nil && r.FlowID != fid {
				err = assert.AnError
			}
			errs <- err
		}()
	}
	// Wait for all six requests, then answer them in reverse order.
	require.Eventually(t, func() bool { return tr.count() == 6 }, 2*time.Second, 5*time.Millisecond)
	reqs := tr.snapshot()
	for i := len(reqs) - 1; i >= 0; i-- {
		switch m := reqs[i].(type) {
		case *SignRequestMessage:
			s.signCh <- &SignResponseMessage{Message: Message{FlowID: m.FlowID, MessageID: m.MessageID}}
		case *MatchRequestMessage:
			s.matchCh <- &MatchResponseMessage{Message: Message{FlowID: m.FlowID, MessageID: m.MessageID}}
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

func flowName(i int) string { return "flow-" + string(rune('a'+i)) }

// recordingTransport records messages sent to the client.
type recordingTransport struct {
	mu   sync.Mutex
	msgs []interface{}
}

func (r *recordingTransport) SendJSON(msg interface{}) error {
	r.mu.Lock()
	r.msgs = append(r.msgs, msg)
	r.mu.Unlock()
	return nil
}
func (r *recordingTransport) ReadMessage(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (r *recordingTransport) Close() error { return nil }
func (r *recordingTransport) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.msgs)
}
func (r *recordingTransport) snapshot() []interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]interface{}(nil), r.msgs...)
}

func TestSession_StashActionSessionWideCap(t *testing.T) {
	s := &Session{flows: map[string]*Flow{}}
	const flows = 20 // 20 * per-flow cap far exceeds the session cap
	for i := 0; i < flows; i++ {
		s.flows[flowName(i)] = &Flow{ID: flowName(i)}
	}
	for i := 0; i < flows; i++ {
		for j := 0; j < maxStashedActionsPerFlow; j++ {
			s.stashAction(&FlowActionMessage{Message: Message{FlowID: flowName(i)}, Action: "x"})
		}
	}
	s.stash.mu.Lock()
	total := s.stash.totalActionsLocked()
	s.stash.mu.Unlock()
	assert.Equal(t, maxStashedActionsPerSession, total)
}

func TestSession_RemoveFlowClearsStash(t *testing.T) {
	s := &Session{flows: map[string]*Flow{}}
	f1, f2 := &Flow{ID: "a"}, &Flow{ID: "b"}
	s.flows["a"], s.flows["b"] = f1, f2
	s.stashAction(&FlowActionMessage{Message: Message{FlowID: "a"}, Action: "x"})
	s.stashAction(&FlowActionMessage{Message: Message{FlowID: "b"}, Action: "x"})

	s.removeFlow("a", f1)

	s.flowsMu.RLock()
	_, aOK := s.flows["a"]
	_, bOK := s.flows["b"]
	s.flowsMu.RUnlock()
	assert.False(t, aOK)
	assert.True(t, bOK)
	s.stash.mu.Lock()
	defer s.stash.mu.Unlock()
	assert.NotContains(t, s.stash.actions, "a", "finished flow's stash must be dropped")
	assert.Contains(t, s.stash.actions, "b")
}
