package engine

import "sync"

// Bounds for parked messages, so a misbehaving client cannot grow a
// session's memory without limit.
const (
	maxStashedActionsPerFlow = 50
	maxStashedResponses      = 64
)

// responseStash holds client messages read off the session's shared channels
// (actionCh, signCh, matchCh) by a waiter they were not meant for. Each waiter
// drains its own entries first (takeAction/takeSign/takeMatch), so concurrent
// flows and requests on one session behave as if each had a private queue.
// The zero value is ready to use.
type responseStash struct {
	mu      sync.Mutex
	actions map[string][]*FlowActionMessage // by flow ID
	signs   map[string]*SignResponseMessage // by message ID
	matches map[string]*MatchResponseMessage
	wake    chan struct{}
}

// waitChan returns a channel closed on the next put. Callers must obtain it
// BEFORE checking the stash so a put in between is never missed.
func (r *responseStash) waitChan() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.wake == nil {
		r.wake = make(chan struct{})
	}
	return r.wake
}

// broadcastLocked wakes every waiter. Callers must hold r.mu.
func (r *responseStash) broadcastLocked() {
	if r.wake != nil {
		close(r.wake)
	}
	r.wake = make(chan struct{})
}

// stashAction parks an action for another flow, unless that flow no longer
// exists (nothing would ever consume it).
func (s *Session) stashAction(a *FlowActionMessage) {
	s.flowsMu.RLock()
	_, ok := s.flows[a.FlowID]
	s.flowsMu.RUnlock()
	if !ok {
		return
	}
	r := &s.stash
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.actions == nil {
		r.actions = make(map[string][]*FlowActionMessage)
	}
	if len(r.actions[a.FlowID]) >= maxStashedActionsPerFlow {
		return
	}
	r.actions[a.FlowID] = append(r.actions[a.FlowID], a)
	r.broadcastLocked()
}

// isOutstanding reports whether messageID is a sign/match request still
// awaiting its response (see trackRequest).
func (s *Session) isOutstanding(messageID string) bool {
	s.flowsMu.RLock()
	defer s.flowsMu.RUnlock()
	_, ok := s.outstandingRequests[messageID]
	return ok
}

// stashSign parks a sign response for the request that is still waiting for
// it. A response for a request that is no longer pending (it timed out or was
// cancelled) is dropped: nothing would ever consume it, and it would use up
// the stash's bounded capacity.
func (s *Session) stashSign(m *SignResponseMessage) {
	if !s.isOutstanding(m.MessageID) {
		return
	}
	r := &s.stash
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.signs == nil {
		r.signs = make(map[string]*SignResponseMessage)
	}
	if len(r.signs) >= maxStashedResponses {
		return
	}
	r.signs[m.MessageID] = m
	r.broadcastLocked()
}

// stashMatch is stashSign for match responses.
func (s *Session) stashMatch(m *MatchResponseMessage) {
	if !s.isOutstanding(m.MessageID) {
		return
	}
	r := &s.stash
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.matches == nil {
		r.matches = make(map[string]*MatchResponseMessage)
	}
	if len(r.matches) >= maxStashedResponses {
		return
	}
	r.matches[m.MessageID] = m
	r.broadcastLocked()
}

// takeAction removes and returns the oldest parked action for flowID that is
// one of expected (any, if expected is empty). Parked actions for the flow
// that are not expected are dropped, as WaitForAction always did.
func (r *responseStash) takeAction(flowID string, expected []string) *FlowActionMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	q := r.actions[flowID]
	for i, a := range q {
		ok := len(expected) == 0
		for _, e := range expected {
			if a.Action == e {
				ok = true
				break
			}
		}
		if ok {
			rest := q[i+1:]
			if len(rest) == 0 {
				delete(r.actions, flowID)
			} else {
				r.actions[flowID] = rest
			}
			return a
		}
	}
	delete(r.actions, flowID)
	return nil
}

// takeSign removes and returns the parked sign response for messageID.
func (r *responseStash) takeSign(messageID string) *SignResponseMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.signs[messageID]
	delete(r.signs, messageID)
	return m
}

// takeMatch removes and returns the parked match response for messageID,
// provided it belongs to flowID.
func (r *responseStash) takeMatch(flowID, messageID string) *MatchResponseMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.matches[messageID]
	if m == nil || m.FlowID != flowID {
		return nil
	}
	delete(r.matches, messageID)
	return m
}

// dropFlow discards anything still parked for a flow that has ended.
func (r *responseStash) dropFlow(flowID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.actions, flowID)
}
