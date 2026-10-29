package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// secretRefusalText stands in for wallet-internal detail that must never reach
// the verifier.
const secretRefusalText = "verifier cert chain rejected by local trust policy (issuer=secret.example)"

// refusalWire is the exact sign_response a client sends to refuse the sign step.
func refusalWire(flowID, messageID string, withText bool) string {
	m := map[string]string{
		"type": "sign_response", "flow_id": flowID, "message_id": messageID,
		"error_code": "SIGN_REFUSED",
	}
	if withText {
		m["error"] = secretRefusalText
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// runRefusedPresentationSign drives requestVPSignature + failSign against a real
// verifier endpoint, answering the sign_request with the given sign_response
// builder. It returns the verifier's form, the client's flow errors, and how long
// the sign step took.
func runRefusedPresentationSign(t *testing.T, respond func(reqMsgID string) string, mode string) (url.Values, []FlowErrorMessage, time.Duration, string) {
	t.Helper()
	old := signResponseTimeout
	signResponseTimeout = 5 * time.Second // stands in for the 3 minute ceiling
	t.Cleanup(func() { signResponseTimeout = old })

	var form url.Values
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		form = r.PostForm
		w.WriteHeader(http.StatusOK)
	}))
	defer verifier.Close()

	errs := make(chan FlowErrorMessage, 4)
	reqs := make(chan string, 1)
	conn, cleanup := wsTestServer(t, func(srv *websocket.Conn) {
		defer srv.Close()
		for {
			_, data, err := srv.ReadMessage()
			if err != nil {
				return
			}
			var m struct {
				Type      MessageType `json:"type"`
				MessageID string      `json:"message_id"`
			}
			_ = json.Unmarshal(data, &m)
			switch m.Type {
			case TypeSignRequest:
				reqs <- m.MessageID
			case TypeFlowError:
				var fe FlowErrorMessage
				if json.Unmarshal(data, &fe) == nil {
					errs <- fe
				}
			}
		}
	})
	defer cleanup()

	sess := testSession(conn)
	go func() {
		id := <-reqs
		var resp SignResponseMessage
		if err := json.Unmarshal([]byte(respond(id)), &resp); err != nil {
			panic(err)
		}
		sess.dispatchSignResponse(&resp)
	}()

	h := &OID4VPHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop(), Flow: &Flow{ID: "flow-1", Session: sess}}
	h.httpClient = verifier.Client()
	authReq := &AuthorizationRequest{
		ClientID: "https://verifier.example.com", ResponseMode: mode,
		State: "st-1", Nonce: "n",
	}
	if mode == ResponseModeDirectPost {
		authReq.ResponseURI = verifier.URL
	} else {
		authReq.RedirectURI = "https://verifier.example.com/cb"
	}

	start := time.Now()
	_, err := h.requestVPSignature(context.Background(), authReq, decisionOf(ConsentSelection{CredentialID: "c1"}), "https://verifier.example.com")
	took := time.Since(start)
	require.Error(t, err)
	h.failSign(context.Background(), authReq, err)

	select {
	case m := <-errs:
		return form, []FlowErrorMessage{m}, took, err.Error()
	case <-time.After(2 * time.Second):
		t.Fatal("client never received a flow_error")
	}
	return nil, nil, 0, ""
}

func TestSignRefusal_EndsRequestSignPromptlyAndTellsVerifier(t *testing.T) {
	form, errs, took, _ := runRefusedPresentationSign(t, func(id string) string {
		return refusalWire("flow-1", id, true)
	}, ResponseModeDirectPost)

	assert.Less(t, took, time.Second, "refusal must end RequestSign at once, not wait for the sign timeout")
	assert.Equal(t, "access_denied", form.Get("error"))
	assert.Equal(t, "st-1", form.Get("state"))
	assert.False(t, form.Has("error_description"), "OpenID4x 3.2.6: no error_description")
	assert.Equal(t, ErrCodePresentationError, errs[0].Error.Code)
}

func TestSignRefusal_NoWalletTextLeaksToVerifier(t *testing.T) {
	form, errs, _, _ := runRefusedPresentationSign(t, func(id string) string {
		return refusalWire("flow-1", id, true)
	}, ResponseModeDirectPost)
	assert.NotContains(t, form.Encode(), "secret.example")
	assert.NotContains(t, form.Encode(), "trust policy")
	b, _ := json.Marshal(errs)
	assert.NotContains(t, string(b), "secret.example", "wallet text is logged, not echoed")
}

// The code alone is a refusal: no error text is required.
func TestSignRefusal_CodeAloneSuffices(t *testing.T) {
	form, _, took, _ := runRefusedPresentationSign(t, func(id string) string {
		return refusalWire("flow-1", id, false)
	}, ResponseModeDirectPost)
	assert.Less(t, took, time.Second)
	assert.Equal(t, "access_denied", form.Get("error"))
}

// In a redirect response mode the refusal reaches the verifier as a redirect
// carrying access_denied and no error_description.
func TestSignRefusal_RedirectModeCarriesAccessDeniedOnly(t *testing.T) {
	_, errs, _, _ := runRefusedPresentationSign(t, func(id string) string {
		return refusalWire("flow-1", id, true)
	}, ResponseModeQuery)
	require.NotNil(t, errs[0].Error.Details)
	redirect, _ := errs[0].Error.Details["redirect_uri"].(string)
	require.NotEmpty(t, redirect)
	u, err := url.Parse(redirect)
	require.NoError(t, err)
	assert.Equal(t, "access_denied", u.Query().Get("error"))
	assert.False(t, u.Query().Has("error_description"), "OpenID4x 3.2.6: no error_description")
	assert.Equal(t, "st-1", u.Query().Get("state"))
	assert.NotContains(t, redirect, "secret")
}

// Other stages are unaffected: an error-bearing sign_response without the
// refusal code is still a SIGN_ERROR, and the verifier is not contacted.
func TestSignRefusal_OtherSignFailuresUnchanged(t *testing.T) {
	form, errs, _, _ := runRefusedPresentationSign(t, func(id string) string {
		return `{"type":"sign_response","flow_id":"flow-1","message_id":"` + id + `","error":"hsm down"}`
	}, ResponseModeDirectPost)
	assert.Nil(t, form)
	assert.Equal(t, ErrCodeSignError, errs[0].Error.Code)
}

func TestSignRefusal_SuccessfulSignStillReturnsResponse(t *testing.T) {
	resp, err := signResult(&SignResponseMessage{VPToken: "tok"})
	require.NoError(t, err)
	assert.Equal(t, "tok", resp.VPToken)
}

func TestSignRefusal_SignErrorMessageFallback(t *testing.T) {
	_, err := signResult(&SignResponseMessage{ErrorCode: ErrCodeSignRefused})
	require.Error(t, err)
	assert.NotEmpty(t, err.Error())
}
