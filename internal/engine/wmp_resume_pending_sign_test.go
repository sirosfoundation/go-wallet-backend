package engine

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// A disconnect followed by session.resume while a sign prompt is pending
// (the client never acknowledged the child wmp.flow.start) must keep the
// parent flow alive and deliver the prompt again on the replacement peer.
func TestWMP_Resume_DuringPendingSignPrompt_KeepsFlowAndRedelivers(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	signReceived := make(chan *SignResponseMessage, 1)
	m.RegisterFlowHandler("sign_test", func(flow *Flow, _ *config.Config, _ *zap.Logger, _ *TrustService, _ *RegistryClient, _ storage.VerifierStore, _ *TrustCache) (FlowHandler, error) {
		return &signFlowHandler{flow: flow, signReceived: signReceived}, nil
	})

	sid, token := createWMPSessionWithToken(t, a, "user-1", "tenant-a")
	events, err := a.Events(sid)
	require.NoError(t, err)

	resp, err := a.HandleRPC(context.Background(), sid, "", "", wmpRequest("2", wmp.MethodFlowStart, wmp.FlowStartParams{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: sid}, FlowType: "sign_test", FlowID: "parent",
	}))
	require.NoError(t, err)
	var sr wmp.Response
	require.NoError(t, json.Unmarshal(resp, &sr))
	require.Nil(t, sr.Error)

	// nextChildStart returns the child flow id of the next sign sub-flow
	// start delivered on the event stream.
	nextChildStart := func() string {
		t.Helper()
		deadline := time.After(3 * time.Second)
		for {
			select {
			case ev := <-events:
				var n struct {
					Method string              `json:"method"`
					Params wmp.FlowStartParams `json:"params"`
				}
				if json.Unmarshal(ev, &n) == nil && n.Method == wmp.MethodFlowStart && n.Params.FlowType == wmp.FlowTypeSign {
					return n.Params.FlowID
				}
			case <-deadline:
				t.Fatal("no sign sub-flow start delivered")
			}
		}
	}
	child := nextChildStart() // pending: nobody acknowledges it

	res, rpcErr := doResume(t, a, "user-1", "tenant-a", resumeBody(sid, token, ""))
	require.Nil(t, rpcErr)
	require.True(t, res.Resumed)

	assert.Equal(t, child, nextChildStart(), "the pending prompt must be re-delivered on the new peer")

	a.mu.RLock()
	sess := a.peers[sid].session
	a.mu.RUnlock()
	sess.flowsMu.RLock()
	_, alive := sess.flows["parent"]
	sess.flowsMu.RUnlock()
	assert.True(t, alive, "parent flow must survive the resume")

	// The client completes the child on the resumed session: the parent
	// receives the result.
	_, err = a.HandleRPC(context.Background(), sid, "", "", wmpNotification(wmp.MethodFlowComplete, wmp.FlowCompleteParams{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: sid}, FlowID: child, Result: json.RawMessage(`{"proof_jwt":"p"}`),
	}))
	require.NoError(t, err)
	select {
	case got := <-signReceived:
		assert.Equal(t, "p", got.ProofJWT)
	case <-time.After(3 * time.Second):
		t.Fatal("parent flow did not receive the sign result after resume")
	}
}
