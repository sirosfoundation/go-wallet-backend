package engine

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// featureCapture records the FlowStartMessage the engine hands it, to see which features the engine believes the client declared.
type featureCapture struct{ got chan *FlowStartMessage }

func (h featureCapture) Execute(_ context.Context, msg *FlowStartMessage) error {
	h.got <- msg
	return nil
}
func (featureCapture) HandleAction(context.Context, *FlowActionMessage) error { return nil }
func (featureCapture) Cancel()                                                {}

// registerCapture registers the "capture" flow type. It must run before the
// session is created: a flow type is startable only if its capability was
// negotiated at session.create (Core 10.3).
func registerCapture(m *Manager) chan *FlowStartMessage {
	got := make(chan *FlowStartMessage, 1)
	m.RegisterFlowHandler("capture", func(*Flow, *config.Config, *zap.Logger, *TrustService, *RegistryClient, storage.VerifierStore, *TrustCache) (FlowHandler, error) {
		return featureCapture{got: got}, nil
	})
	return got
}

func startCaptureFlow(t *testing.T, a *WMPAdapter, got chan *FlowStartMessage, sessionID, user, tenant string, flowParams string) *FlowStartMessage {
	t.Helper()
	var params json.RawMessage
	if flowParams != "" {
		params = json.RawMessage(flowParams)
	}
	body := wmpRequest("flow", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "capture",
		FlowID:   "flow-" + time.Now().Format("150405.000000"),
		Params:   params,
	})
	resp, err := a.HandleRPC(context.Background(), sessionID, user, tenant, body)
	require.NoError(t, err)
	var r wmp.Response
	require.NoError(t, json.Unmarshal(resp, &r))
	require.Nil(t, r.Error, "%v", r.Error)
	select {
	case m := <-got:
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("flow handler never ran")
		return nil
	}
}

func offered(raw string) func(*wmp.SessionCreateParams) {
	return func(p *wmp.SessionCreateParams) {
		if raw != "" {
			p.CapabilitiesOffered = wmp.Capabilities{
				"transaction_data": json.RawMessage(raw),
				"capture":          json.RawMessage(`{}`),
			}
		}
	}
}

// A session that offered transaction_data v1 declares the feature, so the
// engine may forward transaction_data to it.
func TestWMP_FlowStart_DeclaresTransactionDataWhenOffered(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	got := registerCapture(m)
	sid, _, _ := createSessionFull(t, a, "u", "t", offered(`{"versions":[1],"hash_algs":["sha-256"]}`))

	msg := startCaptureFlow(t, a, got, sid, "u", "t", "")
	assert.True(t, msg.Supports(FeatureTransactionDataV1))
}

// The capability the engine acts on is advertised and negotiated: it is in the
// session.create result exactly when the client offered it.
func TestWMP_SessionCreate_NegotiatesTransactionData(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	_, _, res := createSessionFull(t, a, "u", "t", offered(`{"versions":[1],"hash_algs":["sha-256"]}`))
	assert.True(t, res.Capabilities.OffersTransactionData(wmp.TransactionDataVersion1))

	_, _, res = createSessionFull(t, a, "u", "t", func(p *wmp.SessionCreateParams) {
		p.CapabilitiesOffered = wmp.Capabilities{"sign": json.RawMessage(`{}`)}
	})
	assert.NotContains(t, res.Capabilities, wmp.CapabilityTransactionData)

	_, _, res = createSessionFull(t, a, "u", "t", nil)
	assert.True(t, res.Capabilities.OffersTransactionData(wmp.TransactionDataVersion1), "no offer: every server capability")
}

// Negotiation falls back to every server capability when a client offers none; that must not read as transaction_data support.
func TestWMP_FlowStart_DoesNotDeclareWhenNotOffered(t *testing.T) {
	cases := map[string]string{
		"offered nothing at all":     "",
		"only a future version":      `{"versions":[2]}`,
		"capability without version": `{}`,
		"malformed capability":       `"yes"`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			a, m := testWMPAdapter()
			defer cleanupWMP(a, m)
			got := registerCapture(m)
			sid, _, _ := createSessionFull(t, a, "u", "t", offered(raw))

			msg := startCaptureFlow(t, a, got, sid, "u", "t", "")
			assert.False(t, msg.Supports(FeatureTransactionDataV1))
			assert.Empty(t, msg.Features)
		})
	}
}

// A `features` member in flow params unmarshals into FlowStartMessage but must not stand in for the session-level capability.
func TestWMP_FlowStart_FeaturesInFlowParamsCannotForgeTheCapability(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	got := registerCapture(m)
	sid, _, _ := createSessionFull(t, a, "u", "t", offered(""))

	msg := startCaptureFlow(t, a, got, sid, "u", "t", `{"features":["transaction_data.v1"]}`)
	assert.False(t, msg.Supports(FeatureTransactionDataV1), "a flow-param declaration must be ignored")
}

// An offered capability survives a session resume.
func TestWMP_FlowStart_DeclarationSurvivesResume(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	got := registerCapture(m)
	sid, token, _ := createSessionFull(t, a, "u", "t", offered(`{"versions":[1]}`))

	_, rpcErr := doResume(t, a, "u", "t", resumeBody(sid, token, ""))
	require.Nil(t, rpcErr)

	msg := startCaptureFlow(t, a, got, sid, "u", "t", "")
	assert.True(t, msg.Supports(FeatureTransactionDataV1))
}

// And a session that did not offer it still does not after a resume.
func TestWMP_FlowStart_NonDeclarationSurvivesResume(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	got := registerCapture(m)
	sid, token, _ := createSessionFull(t, a, "u", "t", offered(""))

	_, rpcErr := doResume(t, a, "u", "t", resumeBody(sid, token, ""))
	require.Nil(t, rpcErr)

	msg := startCaptureFlow(t, a, got, sid, "u", "t", "")
	assert.False(t, msg.Supports(FeatureTransactionDataV1))
}
