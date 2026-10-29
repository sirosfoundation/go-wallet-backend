package engine

import (
	"context"
	"encoding/json"
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
