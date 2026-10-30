package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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

// signRequestOf runs requestVPSignature for decision and returns the params of
// the sign_request the client was sent (the flow is then abandoned).
func signRequestOf(t *testing.T, h *OID4VPHandler, received chan map[string]any, decision consentDecision) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = h.requestVPSignature(ctx, &AuthorizationRequest{ClientID: "verifier.example", Nonce: "n", State: "s"}, decision, "")
	}()
	msg := awaitMessage(t, received, "sign_request")
	cancel()
	<-done
	params, _ := msg["params"].(map[string]any)
	require.NotNil(t, params)
	return params
}

// A transport that has already translated its wire hands the answer over as the
// action's consent member and no payload at all: the flow decides it as it
// decides a WebSocket answer, and the sign request that follows carries exactly
// the credential references and the selection handle of that answer, unchanged.
func TestPretranslatedConsent_ThroughTheFlowToTheSignRequest(t *testing.T) {
	const handle = "abcdefghijklmnopqrstuv"
	h, session, received, cleanup := newSelectionTestHandler(t)
	defer cleanup()

	session.dispatchAction(&FlowActionMessage{
		Message: Message{Type: TypeFlowAction, FlowID: h.Flow.ID},
		Action:  ActionConsent,
		consent: &consentAnswer{Handle: handle, Selections: []ConsentSelection{{CredentialQueryID: "q1"}}},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	decision, err := h.requestCredentialSelection(ctx, &AuthorizationRequest{}, &VerifierInfo{})
	require.NoError(t, err, "no WebSocket payload is parsed for a pretranslated answer")
	assert.Equal(t, handle, decision.Handle)

	params := signRequestOf(t, h, received, decision)
	assert.Equal(t, handle, params["selection_handle"])
	assert.Equal(t, []any{map[string]any{"credential_query_id": "q1", "credential_id": ""}}, params["credentials_to_include"])
}

// The same through the WebSocket wire: it has no handle, so the sign request
// carries none, whatever the client sent, and carries the credential ids and
// claims the client chose.
func TestWebSocketConsent_SignRequestCarriesNoHandle(t *testing.T) {
	h, session, received, cleanup := newSelectionTestHandler(t)
	defer cleanup()

	feedAction(t, session, h.Flow.ID, ActionConsent, map[string]any{
		"selected_credentials": []any{map[string]any{"credential_query_id": "q1", "credential_id": "c1", "disclosed_claims": []any{"given_name"}}},
		"selection_handle":     "abcdefghijklmnopqrstuv",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	decision, err := h.requestCredentialSelection(ctx, &AuthorizationRequest{}, &VerifierInfo{})
	require.NoError(t, err)

	params := signRequestOf(t, h, received, decision)
	assert.NotContains(t, params, "selection_handle")
	assert.Equal(t, []any{map[string]any{"credential_query_id": "q1", "credential_id": "c1", "disclosed_claims": []any{"given_name"}}}, params["credentials_to_include"])
}

// A WebSocket consent that selects nothing is reported to the client as
// PRESENTATION_ERROR "No credentials selected" and the verifier is NOT told
// (the user was asked and chose nothing): not the generic refusal, and no
// access_denied.
func TestWebSocketConsent_EmptySelectionIsReportedToTheClientOnly(t *testing.T) {
	h, session, received, cleanup := newSelectionTestHandler(t)
	defer cleanup()
	var told int32
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&told, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer verifier.Close()

	feedAction(t, session, h.Flow.ID, ActionConsent, map[string]any{"selected_credentials": []any{}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := h.requestCredentialSelection(ctx, &AuthorizationRequest{ResponseURI: verifier.URL, State: "s"}, &VerifierInfo{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credentials selected")

	msg := awaitMessage(t, received, string(TypeFlowError))
	flowErr := msg["error"].(map[string]any)
	assert.Equal(t, string(ErrCodePresentationError), flowErr["code"])
	assert.Equal(t, "No credentials selected", flowErr["message"])
	assert.EqualValues(t, 0, atomic.LoadInt32(&told), "the verifier is not told")
}
