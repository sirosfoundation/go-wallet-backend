package engine

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The WebSocket wire of the consent only translates; see consent_test.go for
// what is decided.
func TestConsentFromWebSocket(t *testing.T) {
	t.Run("consent", func(t *testing.T) {
		a, err := consentAnswerFrom(&FlowActionMessage{Action: ActionConsent,
			Payload: json.RawMessage(`{"selected_credentials":[{"credential_query_id":"pid","credential_id":"c1","disclosed_claims":["given_name"]}]}`)})
		require.NoError(t, err)
		assert.False(t, a.Declined)
		assert.Equal(t, []ConsentSelection{{CredentialQueryID: "pid", CredentialID: "c1", DisclosedClaims: []string{"given_name"}}}, a.Selections)
	})

	t.Run("decline keeps the client's reason for the log", func(t *testing.T) {
		a, err := consentAnswerFrom(&FlowActionMessage{Action: ActionDecline, Payload: json.RawMessage(`{"reason":"no"}`)})
		require.NoError(t, err)
		assert.True(t, a.Declined)
		assert.Equal(t, "no", a.Reason)
	})

	t.Run("a payload that is not an object is an error", func(t *testing.T) {
		_, err := consentAnswerFrom(&FlowActionMessage{Action: ActionConsent, Payload: json.RawMessage(`"x"`)})
		assert.Error(t, err)
	})

	// The WebSocket protocol has no selection handle: one a client sends must
	// not reach the sign request as if the selection had produced it.
	t.Run("a selection_handle member is not read", func(t *testing.T) {
		a, err := consentAnswerFrom(&FlowActionMessage{Action: ActionConsent,
			Payload: json.RawMessage(`{"selected_credentials":[{"credential_query_id":"q"}],"selection_handle":"abcdefghijklmnopqrstuv"}`)})
		require.NoError(t, err)
		assert.Empty(t, a.Handle)
	})
}

// The whole WebSocket path through the flow: a consent reaches the sign request
// as the decision says, a refusal reaches the verifier and the client.
func TestWebSocketConsent_ThroughTheFlow(t *testing.T) {
	h, session, received, cleanup := newSelectionTestHandler(t)
	defer cleanup()

	feedAction(t, session, h.Flow.ID, ActionConsent, map[string]any{
		"selected_credentials": []any{map[string]any{"credential_query_id": "q1", "credential_id": "c1"}},
		"selection_handle":     "abcdefghijklmnopqrstuv",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	decision, err := h.requestCredentialSelection(ctx, &AuthorizationRequest{}, &VerifierInfo{})
	require.NoError(t, err)
	refs, handle := decision.signInclusion()
	assert.Equal(t, []CredentialRef{{CredentialQueryID: "q1", CredentialID: "c1"}}, refs)
	assert.Empty(t, handle)
	_ = awaitMessage(t, received, string(TypeFlowProgress))
}

// recordingConsentObserver records what the flow tells its session's transport.
type recordingConsentObserver struct {
	mu     sync.Mutex
	events []string
}

func (r *recordingConsentObserver) consentAwaited(flowID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, "awaited:"+flowID)
}

func (r *recordingConsentObserver) consentDecided(flowID, refusal string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, "decided:"+flowID+":"+refusal)
}

func (r *recordingConsentObserver) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

// A transport that reports the consent in its own terms is told, by the flow,
// that a consent is awaited and how it was decided: an accepted answer and a
// decline carry no refusal, a refused one carries its reason class. A session
// without an observer (WebSocket) is not affected.
func TestConsentObserver_IsToldTheDecision(t *testing.T) {
	run := func(t *testing.T, action string, payload any) (*recordingConsentObserver, error) {
		h, session, _, cleanup := newSelectionTestHandler(t)
		defer cleanup()
		obs := &recordingConsentObserver{}
		session.consentObserver = obs
		feedAction(t, session, h.Flow.ID, action, payload)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := h.requestCredentialSelection(ctx, &AuthorizationRequest{}, &VerifierInfo{})
		return obs, err
	}

	t.Run("accepted", func(t *testing.T) {
		obs, err := run(t, ActionConsent, map[string]any{"selected_credentials": []any{map[string]any{"credential_query_id": "q1"}}})
		require.NoError(t, err)
		assert.Equal(t, []string{"awaited:flow-1", "decided:flow-1:"}, obs.got())
	})
	t.Run("declined is not a refusal", func(t *testing.T) {
		obs, err := run(t, ActionDecline, map[string]any{"reason": "no"})
		require.Error(t, err)
		assert.Equal(t, []string{"awaited:flow-1", "decided:flow-1:"}, obs.got())
	})
	t.Run("an answer that selects nothing is refused with its reason class", func(t *testing.T) {
		obs, err := run(t, ActionConsent, map[string]any{"selected_credentials": []any{}})
		require.Error(t, err)
		assert.Equal(t, []string{"awaited:flow-1", "decided:flow-1:" + consentReasonNoSelection}, obs.got())
	})
}
