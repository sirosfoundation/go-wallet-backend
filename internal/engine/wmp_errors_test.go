package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UNTRUSTED_ISSUER ends the flow -31006 with go-wmp's closed data; the engine
// attaches nothing to it, and nothing the engine did attach is relayed.
func TestWMPBridge_UntrustedIssuerRefusal(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VCI, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
		return f.Session.SendFlowError(f.ID, StepEvaluatingTrust, ErrCodeUntrustedIssuer, ErrCodeUntrustedIssuer.UserFacingMessage(),
			map[string]interface{}{"reason": "from-the-engine", "other": 1})
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vci")
	st, _ := e.openStream(tok, sid, "")
	require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "f1")).code())
	ev := st.nextMethod(t, wmp.MethodFlowError)
	assert.EqualValues(t, wmp.ErrFlowError, params(ev)["code"])
	data := params(ev)["data"].(map[string]any)
	assert.Equal(t, map[string]any{"reason": "untrusted_issuer", "retryable": false}, data)
	d, isRefusal, err := openid4x.ParseUntrustedIssuerData(mustJSON(t, data))
	require.NoError(t, err)
	assert.True(t, isRefusal)
	assert.Equal(t, openid4x.NewUntrustedIssuerData(), d)
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// The verifier's refusal keeps its reason next to the engine's details, and the
// reason wins over a member of the same name.
func TestWMPBridge_UntrustedRefusalData(t *testing.T) {
	assert.Equal(t, openid4x.NewUntrustedIssuerData(), untrustedRefusalData(ErrCodeUntrustedIssuer, map[string]interface{}{"x": 1}))
	assert.Equal(t, map[string]interface{}{"reason": "untrusted_verifier", "other": 1},
		untrustedRefusalData(ErrCodeUntrustedVerifier, map[string]interface{}{"reason": "from-the-engine", "other": 1}))
	assert.Nil(t, untrustedRefusalData(ErrCodeSignError, nil))
}

// An engine error code the bridge does not know is a flow error (-31006), never
// an internal error. That includes ISSUER_NOT_ENTITLED (go-wallet-backend#522)
// until the entitlement mapping is wired in (see the SEAM in errorWire): a code
// the engine on main does not send yet.
func TestWMPBridge_UnknownEngineErrorCodeIsAFlowError(t *testing.T) {
	assert.Equal(t, wmp.ErrFlowError, mapErrorCode("SOME_FUTURE_CODE"))
	assert.Equal(t, wmp.ErrFlowError, mapErrorCode("ISSUER_NOT_ENTITLED"))
	assert.Equal(t, wmp.ErrFlowError, mapErrorCode(ErrCodeUntrustedIssuer))
}
