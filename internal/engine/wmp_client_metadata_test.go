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

const testClientMetadata = `{"vp_formats_supported":{"zkp_req":{"system_id_values":["longfellow-libzk-v1"],"proof_system_values":["vega"]}}}`

// clientMetadataFlowHandler emits a credential_selection progress carrying
// client_metadata and then a match request with client_metadata (when cm is
// non-nil), the two engine messages that carry it besides sign_request.
type clientMetadataFlowHandler struct {
	flow *Flow
	cm   json.RawMessage
}

func (h *clientMetadataFlowHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	payload := map[string]interface{}{"dcql_query": json.RawMessage(`{}`)}
	if h.cm != nil {
		payload["client_metadata"] = h.cm
	}
	_ = h.flow.Session.SendProgress(h.flow.ID, StepCredentialSelection, payload)
	_, _ = h.flow.Session.RequestMatchWithClientMetadata(ctx, h.flow.ID, json.RawMessage(`{"credentials":[]}`), h.cm)
	return nil
}

func (h *clientMetadataFlowHandler) Cancel() {}

// collectWMPEvents runs a flow of the given type and returns the
// credential_selection progress payload and the match sub-flow start params.
func runClientMetadataFlow(t *testing.T, cm json.RawMessage) (progress map[string]json.RawMessage, matchParams map[string]json.RawMessage) {
	t.Helper()
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	m.RegisterFlowHandler("cm_test", func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return &clientMetadataFlowHandler{flow: flow, cm: cm}, nil
	})
	sessionID := createWMPSession(t, a)
	_, err := a.HandleRPC(context.Background(), sessionID, "", "", wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "cm_test",
		FlowID:   "flow-cm",
	}))
	require.NoError(t, err)

	events, err := a.Events(sessionID)
	require.NoError(t, err)
	timeout := time.After(3 * time.Second)
	for progress == nil || matchParams == nil {
		select {
		case ev := <-events:
			var n struct {
				Method string `json:"method"`
				Params struct {
					Step     string                     `json:"step"`
					Payload  map[string]json.RawMessage `json:"payload"`
					FlowType string                     `json:"flow_type"`
					Params   map[string]json.RawMessage `json:"params"`
				} `json:"params"`
			}
			if json.Unmarshal(ev, &n) != nil {
				continue
			}
			switch {
			case n.Method == wmp.MethodFlowProgress && n.Params.Step == string(StepCredentialSelection):
				progress = n.Params.Payload
			case n.Method == wmp.MethodFlowStart && n.Params.FlowType == "match":
				matchParams = n.Params.Params
			}
		case <-timeout:
			t.Fatalf("timeout: progress=%v match=%v", progress != nil, matchParams != nil)
		}
	}
	return progress, matchParams
}

func TestWMP_ClientMetadata_ForwardedOnMatchAndCredentialSelection(t *testing.T) {
	progress, match := runClientMetadataFlow(t, json.RawMessage(testClientMetadata))

	require.Contains(t, match, "client_metadata", "match sub-flow params must carry client_metadata")
	assert.JSONEq(t, testClientMetadata, string(match["client_metadata"]))
	assert.Contains(t, match, "dcql_query")
	assert.Contains(t, match, "parent_flow_id")

	require.Contains(t, progress, "client_metadata", "credential_selection progress must carry client_metadata")
	assert.JSONEq(t, testClientMetadata, string(progress["client_metadata"]))
}

func TestWMP_ClientMetadata_OmittedWhenAbsent(t *testing.T) {
	_, match := runClientMetadataFlow(t, nil)
	assert.NotContains(t, match, "client_metadata")
}
