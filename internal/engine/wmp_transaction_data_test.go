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

// featureCapture is a flow handler that records the FlowStartMessage the
// engine hands it, so a test can see which features the engine believes this
// client declared.
type featureCapture struct{ got chan *FlowStartMessage }

func (h featureCapture) Execute(_ context.Context, msg *FlowStartMessage) error {
	h.got <- msg
	return nil
}
func (featureCapture) HandleAction(context.Context, *FlowActionMessage) error { return nil }
func (featureCapture) Cancel()                                                {}

func startCaptureFlow(t *testing.T, a *WMPAdapter, sessionID, user, tenant string, flowParams string) *FlowStartMessage {
	t.Helper()
	got := make(chan *FlowStartMessage, 1)
	a.manager.RegisterFlowHandler("capture", func(*Flow, *config.Config, *zap.Logger, *TrustService, *RegistryClient, storage.VerifierStore, *TrustCache) (FlowHandler, error) {
		return featureCapture{got: got}, nil
	})
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
			p.CapabilitiesOffered = wmp.Capabilities{"transaction_data": json.RawMessage(raw)}
		}
	}
}

// A session that offered transaction_data v1 declares the feature, so the
// engine may forward transaction_data to it.
func TestWMP_FlowStart_DeclaresTransactionDataWhenOffered(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, _, _ := createSessionFull(t, a, "u", "t", offered(`{"versions":[1],"hash_algs":["sha-256"]}`))

	msg := startCaptureFlow(t, a, sid, "u", "t", "")
	assert.True(t, msg.Supports(FeatureTransactionDataV1))
}

// The core of the gate over WMP. Negotiation falls back to every server
// capability when a client offers none; none of that may read as the client
// supporting transaction_data.
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
			sid, _, _ := createSessionFull(t, a, "u", "t", offered(raw))

			msg := startCaptureFlow(t, a, sid, "u", "t", "")
			assert.False(t, msg.Supports(FeatureTransactionDataV1))
			assert.Empty(t, msg.Features)
		})
	}
}

// WMP defines the capability at session level. A `features` member a client
// puts in the flow params unmarshals into FlowStartMessage, and it must not
// stand in for the capability.
func TestWMP_FlowStart_FeaturesInFlowParamsCannotForgeTheCapability(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, _, _ := createSessionFull(t, a, "u", "t", offered(""))

	msg := startCaptureFlow(t, a, sid, "u", "t", `{"features":["transaction_data.v1"]}`)
	assert.False(t, msg.Supports(FeatureTransactionDataV1), "a flow-param declaration must be ignored")
}

// An offered capability survives a session resume.
func TestWMP_FlowStart_DeclarationSurvivesResume(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, token, _ := createSessionFull(t, a, "u", "t", offered(`{"versions":[1]}`))

	_, rpcErr := doResume(t, a, "u", "t", resumeBody(sid, token, ""))
	require.Nil(t, rpcErr)

	msg := startCaptureFlow(t, a, sid, "u", "t", "")
	assert.True(t, msg.Supports(FeatureTransactionDataV1))
}

// And a session that did not offer it still does not after a resume.
func TestWMP_FlowStart_NonDeclarationSurvivesResume(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, token, _ := createSessionFull(t, a, "u", "t", offered(""))

	_, rpcErr := doResume(t, a, "u", "t", resumeBody(sid, token, ""))
	require.Nil(t, rpcErr)

	msg := startCaptureFlow(t, a, sid, "u", "t", "")
	assert.False(t, msg.Supports(FeatureTransactionDataV1))
}
