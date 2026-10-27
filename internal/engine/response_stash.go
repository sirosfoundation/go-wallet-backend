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
	matches map[matchKey]*MatchResponseMessage
	wake    chan struct{}
}

// matchKey keys a parked match response by both its flow and message ID, so a
// reply with the right message ID but the wrong flow ID can never replace the
// valid reply for that request.
type matchKey struct{ flowID, messageID string }

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
// exists (nothing would ever consume it). flowsMu is held for reading through
// the insertion so flow teardown (which deletes the flow under the write lock
// and then calls dropFlow) cannot overtake it and leave a queue behind.
func (s *Session) stashAction(a *FlowActionMessage) {
	s.flowsMu.RLock()
	defer s.flowsMu.RUnlock()
	if _, ok := s.flows[a.FlowID]; !ok {
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

// stashSign parks a sign response for the request that is still waiting for
// it. A response for a request that is no longer pending (it timed out or was
// cancelled) is dropped: nothing would ever consume it, and it would use up
// the stash's bounded capacity. flowsMu is held for reading through the
// insertion, and trackRequest's cleanup removes the request under the write
// lock, so a request cannot end between the pending check and the insertion.
func (s *Session) stashSign(m *SignResponseMessage) {
	s.flowsMu.RLock()
	defer s.flowsMu.RUnlock()
	if _, ok := s.outstandingRequests[m.MessageID]; !ok {
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
	s.flowsMu.RLock()
	defer s.flowsMu.RUnlock()
	// Only the flow that made the request can own its reply: a reply naming any
	// other flow is never consumable, so it must not take up stash capacity.
	if flowID, ok := s.outstandingRequests[m.MessageID]; !ok || flowID != m.FlowID {
		return
	}
	r := &s.stash
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.matches == nil {
		r.matches = make(map[matchKey]*MatchResponseMessage)
	}
	k := matchKey{m.FlowID, m.MessageID}
	if _, dup := r.matches[k]; !dup && len(r.matches) >= maxStashedResponses {
		return
	}
	r.matches[k] = m
	r.broadcastLocked()
}

// actionExpected reports whether action is one of expected (any, if expected
// is empty).
func actionExpected(action string, expected []string) bool {
	if len(expected) == 0 {
		return true
	}
	for _, e := range expected {
		if action == e {
			return true
		}
	}
	return false
}

// takeAction removes and returns the oldest parked action for flowID that is
// one of expected (any, if expected is empty). Parked actions for the flow
// that are not expected are dropped, as WaitForAction always did.
func (r *responseStash) takeAction(flowID string, expected []string) *FlowActionMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	q := r.actions[flowID]
	for i, a := range q {
		if actionExpected(a.Action, expected) {
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
	k := matchKey{flowID, messageID}
	m := r.matches[k]
	delete(r.matches, k)
	return m
}

// dropRequest discards any response still parked for a sign/match request that
// is no longer pending. The caller holds the session's flowsMu for writing.
func (r *responseStash) dropRequest(messageID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.signs, messageID)
	for k := range r.matches {
		if k.messageID == messageID {
			delete(r.matches, k)
		}
	}
}

// dropFlow discards anything still parked for a flow that has ended.
func (r *responseStash) dropFlow(flowID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.actions, flowID)
}
