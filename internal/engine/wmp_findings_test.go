package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- tenant: exact equality, no empty-claim wildcard ---

func TestOwnsSession_TenantExactEquality(t *testing.T) {
	user := &wmpSession{session: &Session{UserID: "u", TenantID: "t1"}}
	assert.False(t, ownsSession(user, wmpCaller{UserID: "u", TenantID: ""}),
		"empty tenant must not match a session in another tenant")
	assert.False(t, ownsSession(user, wmpCaller{UserID: "u", TenantID: "t2"}))
	assert.True(t, ownsSession(user, wmpCaller{UserID: "u", TenantID: "t1"}))

	// A session created for a token with no tenant lives in "default", and is
	// addressed by "" or "default" alike, but not by another tenant.
	def := &wmpSession{session: &Session{UserID: "u", TenantID: "default"}}
	assert.True(t, ownsSession(def, wmpCaller{UserID: "u", TenantID: ""}))
	assert.True(t, ownsSession(def, wmpCaller{UserID: "u", TenantID: "default"}))
	assert.False(t, ownsSession(def, wmpCaller{UserID: "u", TenantID: "t1"}))
}

func TestWMP_SessionCreate_MissingTenantNormalisedToDefault(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sid, _, _ := createSessionFull(t, a, "user-d", "", nil)
	a.mu.RLock()
	ws := a.peers[sid]
	a.mu.RUnlock()
	assert.Equal(t, "default", ws.session.TenantID)
	assert.True(t, a.verifySessionOwnership(sid, wmpCaller{UserID: "user-d", TenantID: "default"}))
	assert.False(t, a.verifySessionOwnership(sid, wmpCaller{UserID: "user-d", TenantID: "other"}))

	// A tenant-scoped session is not reachable with an empty tenant.
	sid2, _, _ := createSessionFull(t, a, "user-e", "t1", nil)
	assert.False(t, a.verifySessionOwnership(sid2, wmpCaller{UserID: "user-e", TenantID: ""}))
}

// --- session limits ---

func TestWMPSlots_PerTokenLimitAndIdempotentRelease(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	var slots []*wmpSlot
	for i := 0; i < maxWMPSessionsPerToken; i++ {
		s := a.reserveSlot("jti:x")
		require.NotNil(t, s)
		slots = append(slots, s)
	}
	assert.Nil(t, a.reserveSlot("jti:x"), "per-token limit")
	assert.NotNil(t, a.reserveSlot("jti:y"), "other tokens unaffected")
	assert.Equal(t, int64(maxWMPSessionsPerToken+1), m.activeConnections.Load())

	slots[0].release()
	slots[0].release() // idempotent
	assert.Equal(t, int64(maxWMPSessionsPerToken), m.activeConnections.Load())
	assert.NotNil(t, a.reserveSlot("jti:x"))
}

func TestWMPSlots_ConcurrentReservationsNeverExceedGlobalLimit(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	const room = 5
	m.activeConnections.Store(maxConnections - room)

	var wg sync.WaitGroup
	var mu sync.Mutex
	got := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if a.reserveSlot("jti:"+string(rune('a'+i%26))+string(rune('a'+i/26))) != nil {
				mu.Lock()
				got++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	assert.Equal(t, room, got)
	assert.Equal(t, int64(maxConnections), m.activeConnections.Load())
}

func TestWMP_SessionCreate_RejectedAtGlobalLimit(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	m.activeConnections.Store(maxConnections)

	resp, err := a.HandleRPC(context.Background(), "", "", "", wmpCreateBody(testToken("u", "t"), nil))
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrRateLimited, rpcErrCode(t, resp))
	assert.Equal(t, int64(maxConnections), m.activeConnections.Load(), "rejected create must not leak a slot")
	a.mu.RLock()
	defer a.mu.RUnlock()
	assert.Empty(t, a.peers)
}

func TestWMP_SessionSlot_ReleasedOnEveryTeardownPath(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	base := m.activeConnections.Load()

	// CloseSession.
	sid, tok, _ := createSessionFull(t, a, "u1", "t", nil)
	assert.Equal(t, base+1, m.activeConnections.Load())

	// Resume keeps the same single slot.
	_, rerr := doResume(t, a, "u1", "t", resumeBody(sid, tok, ""))
	require.Nil(t, rerr)
	assert.Equal(t, base+1, m.activeConnections.Load())
	a.CloseSession(sid)
	assert.Equal(t, base, m.activeConnections.Load())
	a.CloseSession(sid)
	assert.Equal(t, base, m.activeConnections.Load(), "double close must not double release")

	// Peer transport closing (client disconnect) -> closeSessionIfCurrent.
	sid2, _, _ := createSessionFull(t, a, "u2", "t", nil)
	a.mu.RLock()
	ws := a.peers[sid2]
	a.mu.RUnlock()
	_ = ws.transport.Close()
	require.Eventually(t, func() bool { return m.activeConnections.Load() == base }, 2*time.Second, 10*time.Millisecond)

	// Idle expiry (cleanupExpired).
	sid3, _, _ := createSessionFull(t, a, "u3", "t", nil)
	a.mu.Lock()
	a.peers[sid3].lastActivity = time.Now().Add(-2 * wmpSessionIdleTimeout)
	a.mu.Unlock()
	a.cleanupExpired()
	assert.Equal(t, base, m.activeConnections.Load())

	// Revoked between validation and registration.
	m.SetTokenBlacklist(&revokeOnSecondCheck{})
	resp, err := a.HandleRPC(context.Background(), "", "", "", wmpCreateBody(testToken("ur", "t"), nil))
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, resp))
	assert.Equal(t, base, m.activeConnections.Load())
	a.tokenSlotsMu.Lock()
	defer a.tokenSlotsMu.Unlock()
	assert.Empty(t, a.tokenSlots, "per-token counters must be released too")
}

// A token without a tenant_id claim belongs to the default tenant on every
// transport. The WebSocket and WMP sessions of such a user therefore share
// one (tenant, user) index key and supersede each other.
func TestTokenlessTenant_WebSocketAndWMPShareDefaultTenantIndex(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	dialWS := func() *websocket.Conn {
		ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		require.NoError(t, err)
		require.NoError(t, ws.WriteJSON(HandshakeMessage{
			Message:  Message{Type: TypeHandshake},
			AppToken: testToken("user-nt", ""),
		}))
		var complete HandshakeCompleteMessage
		require.NoError(t, ws.ReadJSON(&complete))
		require.Equal(t, TypeHandshakeComplete, complete.Type)
		return ws
	}
	waitClosed := func(ws *websocket.Conn) {
		_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				return
			}
		}
	}

	// 1. WebSocket session lands under the default tenant.
	ws1 := dialWS()
	defer func() { _ = ws1.Close() }()
	wsSess, err := m.GetSessionByUser("default", "user-nt")
	require.NoError(t, err, "WebSocket session must be indexed under the default tenant")
	assert.Equal(t, "default", wsSess.TenantID)
	_, err = m.GetSessionByUser("", "user-nt")
	assert.NoError(t, err, "an empty tenant resolves to default on lookup too")

	// 2. A WMP session of the same user supersedes the WebSocket session.
	wmpID, _ := createWMPSessionWithToken(t, a, "user-nt", "")
	waitClosed(ws1)
	cur, err := m.GetSessionByUser("default", "user-nt")
	require.NoError(t, err)
	assert.Equal(t, wmpID, cur.ID)
	assert.False(t, m.isCurrentSession(wsSess))

	// 3. A new WebSocket session supersedes the WMP session.
	ws2 := dialWS()
	defer func() { _ = ws2.Close() }()
	cur2, err := m.GetSessionByUser("default", "user-nt")
	require.NoError(t, err)
	assert.NotEqual(t, wmpID, cur2.ID)
	assert.Eventually(t, func() bool {
		a.mu.RLock()
		defer a.mu.RUnlock()
		_, ok := a.peers[wmpID]
		return !ok
	}, 5*time.Second, 20*time.Millisecond, "WMP session must be superseded by the WebSocket one")
}
