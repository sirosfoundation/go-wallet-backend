package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func registerStubFlowTypes(m *Manager, protocols ...Protocol) {
	for _, p := range protocols {
		m.RegisterFlowHandler(p, func(*Flow, *config.Config, *zap.Logger, *TrustService, *RegistryClient, storage.VerifierStore, *TrustCache) (FlowHandler, error) {
			return stubFlowHandler{}, nil
		})
	}
}

func offerOnly(caps ...string) func(*wmp.SessionCreateParams) {
	return func(p *wmp.SessionCreateParams) {
		p.CapabilitiesOffered = wmp.Capabilities{}
		for _, c := range caps {
			p.CapabilitiesOffered[c] = json.RawMessage(`{}`)
		}
	}
}

func flowStartErr(t *testing.T, a *WMPAdapter, sid, flowType, flowID string) *wmp.RPCError {
	t.Helper()
	resp, err := a.HandleRPC(context.Background(), sid, "u", "t", startFlowBody(sid, flowType, flowID))
	require.NoError(t, err)
	var r wmp.Response
	require.NoError(t, json.Unmarshal(resp, &r))
	return r.Error
}

// OpenID4x 2.1 and 2.2: the engine advertises oid4vci and oid4vp with their
// parameters, and vctm (not a WMP flow type) is not advertised as a flow.
func TestWMP_ServerCapabilities_AdvertiseOpenID4x(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	registerStubFlowTypes(m, ProtocolOID4VCI, ProtocolOID4VP, ProtocolVCTM)

	_, _, res := createSessionFull(t, a, "u", "t", nil)

	var vci openid4x.OID4VCICapability
	require.Contains(t, res.Capabilities, "oid4vci")
	require.NoError(t, json.Unmarshal(res.Capabilities["oid4vci"], &vci))
	assert.Contains(t, vci.SupportedGrants, "authorization_code")
	assert.Contains(t, vci.SupportedGrants, "pre-authorized_code")
	assert.NotEmpty(t, vci.SupportedFormats)

	var vp openid4x.OID4VPCapability
	require.Contains(t, res.Capabilities, "oid4vp")
	require.NoError(t, json.Unmarshal(res.Capabilities["oid4vp"], &vp))
	assert.Contains(t, vp.SupportedResponseModes, "direct_post")
	assert.NotEmpty(t, vp.SupportedFormats)

	assert.NotContains(t, res.Capabilities, "vctm")
	var flows struct {
		Supported []string `json:"supported"`
	}
	require.NoError(t, json.Unmarshal(res.Capabilities["flows"], &flows))
	assert.Equal(t, []string{"oid4vci", "oid4vp"}, flows.Supported)
}

// Core 10.3: a flow type whose capability the session did not negotiate is
// refused with -31005, an unknown or non-WMP type likewise.
func TestWMP_FlowStart_RefusesFlowTypeNotNegotiated(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	registerStubFlowTypes(m, ProtocolOID4VCI, ProtocolOID4VP, ProtocolVCTM)

	// The client offered oid4vp only: oid4vci was not negotiated.
	sid, _, res := createSessionFull(t, a, "u", "t", offerOnly("oid4vp"))
	require.NotContains(t, res.Capabilities, "oid4vci")

	rpcErr := flowStartErr(t, a, sid, "oid4vci", "f-1")
	require.NotNil(t, rpcErr)
	assert.Equal(t, wmp.ErrCapabilityNotSupported, rpcErr.Code)
	assert.JSONEq(t, `{"unsupported":"oid4vci"}`, string(rpcErr.Data))

	assert.Nil(t, flowStartErr(t, a, sid, "oid4vp", "f-2"), "a negotiated flow type starts")

	for _, ft := range []string{"nonexistent", "vctm", "sign"} {
		rpcErr = flowStartErr(t, a, sid, ft, "f-x-"+ft)
		require.NotNil(t, rpcErr, ft)
		assert.Equal(t, wmp.ErrCapabilityNotSupported, rpcErr.Code, ft)
	}

	// Even a session that offered vctm cannot start it: it is not a WMP flow type.
	sid2, _, _ := createSessionFull(t, a, "u2", "t", offerOnly("vctm", "oid4vci"))
	rpcErr = flowStartErr(t, a, sid2, "vctm", "f-3")
	require.NotNil(t, rpcErr)
	assert.Equal(t, wmp.ErrCapabilityNotSupported, rpcErr.Code)
}

// A client that offers no capabilities gets every server capability, so every
// advertised flow type starts.
func TestWMP_FlowStart_NoOfferNegotiatesEveryFlowType(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	registerStubFlowTypes(m, ProtocolOID4VCI)

	sid, _, _ := createSessionFull(t, a, "u", "t", nil)
	assert.Nil(t, flowStartErr(t, a, sid, "oid4vci", "f-1"))
}

// OpenID4x 2.3: a transaction_data refusal ends the flow with -31005 and data
// {"unsupported": "transaction_data"}, not -31006; the verifier redirect stays
// as an extension member.
func TestWMP_FlowError_TransactionDataUnsupported_Is31005(t *testing.T) {
	ct := wmp.NewChannelTransport(5, 5)
	handler := &wmpEngineHandler{sessionID: "s"}
	peer := wmp.NewPeer(ct, handler)
	transport := newWMPSessionTransport(peer, ct)
	transport.handler = handler

	require.NoError(t, transport.SendJSON(&FlowErrorMessage{
		Message: Message{FlowID: "flow-1"},
		Error: FlowError{
			Code: ErrCodeUnsupportedTransactionData, Message: "m",
			Details: map[string]interface{}{"redirect_uri": "https://v.example/cb?error=invalid_transaction_data"},
		},
	}))
	var notif struct {
		Params wmp.FlowErrorParams `json:"params"`
	}
	require.NoError(t, json.Unmarshal(<-ct.Out(), &notif))
	assert.Equal(t, wmp.ErrCapabilityNotSupported, notif.Params.Code)
	assert.JSONEq(t, `{"unsupported":"transaction_data","redirect_uri":"https://v.example/cb?error=invalid_transaction_data"}`, string(notif.Params.Data))

	// Without details, data is exactly the spec's.
	require.NoError(t, transport.SendJSON(&FlowErrorMessage{
		Message: Message{FlowID: "flow-1"},
		Error:   FlowError{Code: ErrCodeUnsupportedTransactionData, Message: "m"},
	}))
	require.NoError(t, json.Unmarshal(<-ct.Out(), &notif))
	assert.JSONEq(t, `{"unsupported":"transaction_data"}`, string(notif.Params.Data))
}

// A failed sign ends the parent with -31006, never -31010 (Core 3.8: signature
// verification failure).
func TestWMP_FlowError_SignFailureIsFlowError(t *testing.T) {
	assert.Equal(t, wmp.ErrFlowError, mapErrorCode(ErrCodeSignError))
	assert.NotEqual(t, wmp.ErrSignatureInvalid, mapErrorCode(ErrCodeSignError))
}

// Core 10.3 and 5: wmp.message.deliver, ack and status need capabilities the
// engine never negotiates (messaging, offline); a request is rejected with
// -31005 instead of reaching go-wmp's no-op handler, and flow methods are
// unaffected.
func TestWMP_MessageMethods_RejectedWhenNotNegotiated(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)

	meta := wmp.Metadata{Version: wmp.Version, SessionID: sid}
	cases := []struct {
		method, capability string
		params             interface{}
	}{
		{wmp.MethodMessageDeliver, "messaging", wmp.MessageDeliverParams{WMP: meta, To: []string{"x"}, ContentType: "application/json", Body: json.RawMessage(`{}`)}},
		{wmp.MethodMessageAck, "messaging", wmp.MessageAckParams{WMP: meta, MessageIDs: []string{"m"}, Status: "received"}},
		{wmp.MethodMessageStatus, "offline", wmp.MessageStatusParams{WMP: meta, MessageID: "m", Status: "queued"}},
	}
	for _, c := range cases {
		resp, err := a.HandleRPC(context.Background(), sid, "user-1", "tenant-a", wmpRequest("9", c.method, c.params))
		require.NoError(t, err)
		var r wmp.Response
		require.NoError(t, json.Unmarshal(resp, &r))
		require.NotNil(t, r.Error, c.method)
		assert.Equal(t, wmp.ErrCapabilityNotSupported, r.Error.Code, c.method)
		assert.JSONEq(t, `{"unsupported":"`+c.capability+`"}`, string(r.Error.Data), c.method)
	}

	// A notification has no response.
	resp, err := a.HandleRPC(context.Background(), sid, "user-1", "tenant-a", wmpNotification(wmp.MethodMessageAck, cases[1].params))
	require.NoError(t, err)
	assert.Empty(t, resp)

	// Other methods still work.
	resp, err = a.HandleRPC(context.Background(), sid, "user-1", "tenant-a", wmpRequest("10", wmp.MethodCapabilityList, wmp.CapabilityListParams{WMP: meta}))
	require.NoError(t, err)
	var r wmp.Response
	require.NoError(t, json.Unmarshal(resp, &r))
	assert.Nil(t, r.Error)
}
