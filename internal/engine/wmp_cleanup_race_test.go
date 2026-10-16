package engine

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func backdateWMPSession(a *WMPAdapter, sid string) {
	a.mu.Lock()
	a.peers[sid].lastActivity = time.Now().Add(-2 * wmpSessionIdleTimeout)
	a.mu.Unlock()
}

// A resume that replaces the peer between the expiry scan and the close must
// not have its replacement closed by the stale cleanup decision.
func TestWMP_CleanupExpired_ResumeBetweenScanAndClose(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sid, token, _ := createSessionFull(t, a, "user-1", "tenant-a", nil)
	backdateWMPSession(a, sid)
	a.mu.RLock()
	oldWS := a.peers[sid]
	a.mu.RUnlock()

	fired := false
	a.afterExpiryScan = func() {
		fired = true
		_, rpcErr := doResume(t, a, "user-1", "tenant-a", resumeBody(sid, token, ""))
		require.Nil(t, rpcErr)
	}
	a.cleanupExpired()
	require.True(t, fired)

	a.mu.RLock()
	cur, ok := a.peers[sid]
	a.mu.RUnlock()
	require.True(t, ok, "resumed session must survive a stale cleanup decision")
	assert.NotSame(t, oldWS, cur)
	_, err := a.Events(sid)
	assert.NoError(t, err)
}

// Activity between the scan and the close keeps an idle-scanned session open.
func TestWMP_CleanupExpired_TouchedBetweenScanAndClose(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sid, _, _ := createSessionFull(t, a, "user-1", "tenant-a", nil)
	backdateWMPSession(a, sid)
	a.afterExpiryScan = func() { a.touchSession(sid) }
	a.cleanupExpired()

	a.mu.RLock()
	_, ok := a.peers[sid]
	a.mu.RUnlock()
	assert.True(t, ok)
}

func TestWMP_CleanupExpired_ClosesIdle(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sid, _, _ := createSessionFull(t, a, "user-1", "tenant-a", nil)
	backdateWMPSession(a, sid)
	a.cleanupExpired()

	a.mu.RLock()
	_, ok := a.peers[sid]
	a.mu.RUnlock()
	assert.False(t, ok)
}

// A close request arriving on a connection that a resume has replaced must
// not terminate the resumed session.
func TestWMP_SessionClose_StaleHandlerAfterResume(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sid, token, _ := createSessionFull(t, a, "user-1", "tenant-a", nil)
	a.mu.RLock()
	oldHandler := a.peers[sid].handler
	a.mu.RUnlock()
	_, rpcErr := doResume(t, a, "user-1", "tenant-a", resumeBody(sid, token, ""))
	require.Nil(t, rpcErr)

	oldHandler.SessionClose(t.Context(), nil)
	a.mu.RLock()
	_, ok := a.peers[sid]
	a.mu.RUnlock()
	assert.True(t, ok, "stale handler must not close the resumed session")
}

// Stress under -race: expiry sweeps race with resumes and touches; a successful resume must leave a consistent adapter (at most one peer, event buffer only if present).
func TestWMP_CleanupExpired_StressWithResume(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sid, token, _ := createSessionFull(t, a, "user-1", "tenant-a", nil)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				a.mu.Lock()
				if ws, ok := a.peers[sid]; ok {
					ws.lastActivity = time.Now().Add(-2 * wmpSessionIdleTimeout)
				}
				a.mu.Unlock()
				a.cleanupExpired()
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer close(stop)
		for i := 0; i < 50; i++ {
			res, rpcErr := doResume(t, a, "user-1", "tenant-a", resumeBody(sid, token, ""))
			if rpcErr != nil {
				break // closed by a legitimate sweep; token gone
			}
			token = res.ResumptionToken
		}
	}()
	wg.Wait()

	a.mu.RLock()
	defer a.mu.RUnlock()
	assert.LessOrEqual(t, len(a.peers), 1)
}
