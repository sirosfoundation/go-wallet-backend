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

// A create that is superseded by a second create for the same user between
// manager registration and peer publication must fail rather than return a
// session (and resumption token) that is already torn down. The hook
// interleaves the two creates deterministically.
func TestWMP_SessionCreateFailsWhenSupersededBeforePublication(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	create := func(id string) *wmp.Response {
		body := wmpRequest(id, "wmp.session.create", wmp.SessionCreateParams{
			WMP:      wmp.Metadata{Version: wmp.Version},
			Security: wmp.SecurityMode{Mode: "tls"},
			Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-1", "tenant-a")},
		})
		resp, err := a.HandleRPC(context.Background(), "", "", "", body)
		require.NoError(t, err)
		var rpcResp wmp.Response
		require.NoError(t, json.Unmarshal(resp, &rpcResp))
		return &rpcResp
	}

	var second *wmp.Response
	fired := false
	a.afterRegister = func(string) {
		if fired {
			return
		}
		fired = true
		second = create("2") // registers, superseding the first create
	}

	first := create("1")
	require.NotNil(t, first.Error, "superseded create must fail")
	require.NotNil(t, second)
	require.Nil(t, second.Error, "the newer create must succeed")

	a.mu.RLock()
	defer a.mu.RUnlock()
	assert.Len(t, a.peers, 1, "only the newer session may be published")
	assert.Len(t, a.resumptionTokens, 1, "no token may exist for the superseded session")
}

// A resume that already captured the old peer must fail, and clean up what it
// built, when a create for the same user supersedes the session before the
// resume publishes its replacement. dropHook=true removes the supersede
// invalidation so the manager-currency recheck is exercised on its own.
func testWMPResumeSupersededBeforePublication(t *testing.T, dropHook bool) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	oldSID, oldToken, _ := createSessionFull(t, a, "user-1", "tenant-a", nil)
	a.mu.RLock()
	oldSession := a.peers[oldSID].session
	a.mu.RUnlock()
	if dropHook {
		oldSession.onSuperseded = nil
	}

	var newSID string
	fired := false
	a.beforeResumePublish = func(string) {
		if fired {
			return
		}
		fired = true
		newSID, _, _ = createSessionFull(t, a, "user-1", "tenant-a", nil)
	}

	_, rpcErr := doResume(t, a, "user-1", "tenant-a", resumeBody(oldSID, oldToken, ""))
	require.NotNil(t, rpcErr, "resume of a superseded session must fail")
	require.NotEmpty(t, newSID)

	a.mu.RLock()
	defer a.mu.RUnlock()
	assert.Len(t, a.peers, 1, "only the newer session may remain published")
	assert.Contains(t, a.peers, newSID)
	assert.NotContains(t, a.resumptionTokens, oldToken)
	for _, e := range a.resumptionTokens {
		assert.Equal(t, newSID, e.sessionID, "no token may survive for the superseded session")
	}
	assert.True(t, m.isCurrentSession(a.peers[newSID].session))
}

func TestWMP_ResumeFailsWhenSupersededBeforePublication(t *testing.T) {
	testWMPResumeSupersededBeforePublication(t, false)
}

func TestWMP_ResumeRecheckFailsWhenSupersededBeforePublication(t *testing.T) {
	testWMPResumeSupersededBeforePublication(t, true)
}

// Superseding a session invalidates its adapter resume state at once.
func TestWMP_SupersedeInvalidatesResumeState(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	oldSID, oldToken, _ := createSessionFull(t, a, "user-1", "tenant-a", nil)
	newSID, _, _ := createSessionFull(t, a, "user-1", "tenant-a", nil)
	require.NotEqual(t, oldSID, newSID)

	a.mu.RLock()
	_, peerLeft := a.peers[oldSID]
	_, tokLeft := a.resumptionTokens[oldToken]
	a.mu.RUnlock()
	assert.False(t, peerLeft)
	assert.False(t, tokLeft)

	_, rpcErr := doResume(t, a, "user-1", "tenant-a", resumeBody(oldSID, oldToken, ""))
	require.NotNil(t, rpcErr)
}
