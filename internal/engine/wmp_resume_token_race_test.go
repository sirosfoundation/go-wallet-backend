package engine

import (
	"testing"

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
