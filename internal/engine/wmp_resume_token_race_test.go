package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A token must never be issued for a peer that CloseSession already removed.
func TestWMP_ResumptionTokenNotIssuedForClosedPeer(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)

	a.mu.RLock()
	ws := a.peers[sid]
	a.mu.RUnlock()

	tok, ok := a.issueResumptionTokenIfCurrent(sid, ws)
	require.True(t, ok)
	require.NotEmpty(t, tok)

	a.CloseSession(sid)

	tok, ok = a.issueResumptionTokenIfCurrent(sid, ws)
	assert.False(t, ok)
	assert.Empty(t, tok)
	a.mu.RLock()
	for _, e := range a.resumptionTokens {
		assert.NotEqual(t, sid, e.sessionID, "no token may be recreated for a closed session")
	}
	a.mu.RUnlock()
}

// A session closed between publication and token issuance must fail the
// create instead of reporting success with a token for a nonexistent session.
func TestWMP_SessionCreateFailsWhenPeerRemovedBeforeToken(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	a.beforeCreateToken = func(sid string) { a.CloseSession(sid) }

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-1", "tenant-a")},
	})
	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
	require.NoError(t, err)
	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error, "create must fail")

	a.mu.RLock()
	defer a.mu.RUnlock()
	assert.Empty(t, a.peers)
	assert.Empty(t, a.resumptionTokens, "no token may survive for the closed session")
}
