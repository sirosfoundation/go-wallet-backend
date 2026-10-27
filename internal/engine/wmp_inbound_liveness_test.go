package engine

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// The WebSocket transport counts any inbound frame as liveness by pushing its
// read deadline out. A WMP session has no socket read deadline; its liveness
// is wmpSession.lastActivity, which the idle sweep (cleanupExpired) compares
// against wmpSessionIdleTimeout. Every kind of authorized inbound traffic - a
// request, a notification and a response to a server-initiated request - must
// refresh it, so a session that is actively being used is never reaped as idle.
func TestWMP_AnyInboundMessageCountsAsLiveness(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	signReceived := make(chan *SignResponseMessage, 1)
	registerSignTest(m, signReceived)
	sid := createWMPSession(t, a)

	makeIdle := func() {
		a.mu.Lock()
		a.peers[sid].lastActivity = time.Now().Add(-2 * wmpSessionIdleTimeout)
		a.mu.Unlock()
	}
	idle := func() bool {
		a.mu.RLock()
		defer a.mu.RUnlock()
		return wmpSessionExpiredLocked(a.peers[sid], time.Now())
	}

	respID, _ := pendingChildStart(t, a, sid) // also a request (flow.start)

	cases := []struct {
		name string
		send func()
	}{
		{"request", func() {
			_, err := a.HandleRPC(context.Background(), sid, "", "", wmpRequest("9", wmp.MethodFlowCancel, map[string]string{"flow_id": "nope"}))
			require.NoError(t, err)
		}},
		{"notification", func() {
			_, err := a.HandleRPC(context.Background(), sid, "", "", wmpNotification(wmp.MethodFlowCancel, map[string]string{"flow_id": "nope"}))
			require.NoError(t, err)
		}},
		{"response", func() {
			_, err := a.HandleRPC(context.Background(), sid, "", "", wmpResponseTo(respID))
			require.NoError(t, err)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			makeIdle()
			require.True(t, idle(), "precondition: the session is idle")
			tc.send()
			assert.False(t, idle(), "inbound %s must count as liveness", tc.name)
		})
	}
}
