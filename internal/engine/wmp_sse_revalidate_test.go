package engine

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// revokeWithoutClosing marks the user revoked the way validation sees it, without
// RevokeUser's side effect of closing the sessions: the stream's own token check
// is what must end it.
func revokeWithoutClosing(m *Manager, userID string) {
	m.revokedUsersMu.Lock()
	m.revokedUsers[userID] = struct{}{}
	m.revokedUsersMu.Unlock()
}

func openSSE(t *testing.T, a *WMPAdapter, sessionID string) (*bufio.Reader, func()) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(a.HandleWMPEvents))
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?session_id="+sessionID, nil)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return bufio.NewReader(resp.Body), func() { resp.Body.Close(); ts.Close() }
}

// expectStreamEnds reads until EOF within the timeout, failing if any line carries leak.
func expectStreamEnds(t *testing.T, br *bufio.Reader, leak string) {
	t.Helper()
	res := make(chan error, 1)
	go func() {
		for {
			line, err := br.ReadString('\n')
			if strings.Contains(line, leak) {
				res <- http.ErrNotSupported
				return
			}
			if err != nil {
				res <- nil
				return
			}
		}
	}()
	select {
	case err := <-res:
		require.NoError(t, err, "an event was delivered after the token was revoked")
	case <-time.After(3 * time.Second):
		t.Fatal("the SSE stream kept running after its token was revoked")
	}
}

// A token revoked while the stream is open must not keep receiving flow results.
func TestWMP_SSE_EndsWhenTokenRevokedBeforeNextEvent(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)
	buf := a.getOrCreateEventBuffer(sid)

	br, closeFn := openSSE(t, a, sid)
	defer closeFn()
	buf.append([]byte(`{"n":1}`))
	readSSEUntil(t, br, `"n":1`)

	revokeWithoutClosing(m, "user-1")
	buf.append([]byte(`{"secret":"after-revocation"}`))
	expectStreamEnds(t, br, "after-revocation")
}

// An idle stream notices the revocation on its next heartbeat.
func TestWMP_SSE_EndsOnHeartbeatWhenTokenRevokedWhileIdle(t *testing.T) {
	old := wmpSSEHeartbeatInterval
	wmpSSEHeartbeatInterval = 20 * time.Millisecond
	defer func() { wmpSSEHeartbeatInterval = old }()

	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)

	br, closeFn := openSSE(t, a, sid)
	defer closeFn()
	readSSEUntil(t, br, ": keepalive")

	revokeWithoutClosing(m, "user-1")
	expectStreamEnds(t, br, "never-sent")
}

// A legacy token (no TAC concept, enforcement off) may reconnect to a session created
// with a modern token holding permissions, as authorizeProtocol lets it drive that
// session; a modern empty-TAC token must still be refused.
func TestWMP_SSE_LegacyTokenMayReadSessionWithPermissions(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, _, _ := createSessionFull(t, a, "u", "t", nil)
	a.mu.RLock()
	sess := a.peers[sid].session
	a.mu.RUnlock()
	a.mu.Lock()
	sess.TAC, sess.TACEnforced = "ir", true
	a.mu.Unlock()

	assert.True(t, a.tokenCoversSession(sid, "", false), "legacy token is exempt from the session's permissions")
	assert.False(t, a.tokenCoversSession(sid, "", true), "modern empty-TAC token must be refused")
	assert.False(t, a.tokenCoversSession(sid, "r", true))
	assert.True(t, a.tokenCoversSession(sid, "ir", true))
}

// revokeAfterFirstEventWriter revokes the user once the first event has been
// written, i.e. in the middle of a replay batch.
type revokeAfterFirstEventWriter struct {
	*syncRecorder
	revoke func()
	once   sync.Once
}

func (w *revokeAfterFirstEventWriter) Write(b []byte) (int, error) {
	n, err := w.syncRecorder.Write(b)
	if strings.Contains(string(b), "data: ") {
		w.once.Do(w.revoke)
	}
	return n, err
}

// A token revoked while a multi-event replay batch is being written must stop the
// batch: authorization is re-checked before every event, not once per batch.
func TestWMP_SSE_RevalidatesBeforeEveryEventOfABatch(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)
	buf := a.getOrCreateEventBuffer(sid)
	buf.append([]byte(`{"n":1}`))
	buf.append([]byte(`{"secret":"second-event"}`))
	buf.append([]byte(`{"secret":"third-event"}`))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, WMPEventsPath+"?session_id="+sid, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	w := &revokeAfterFirstEventWriter{syncRecorder: &syncRecorder{ResponseRecorder: httptest.NewRecorder()}, revoke: func() { revokeWithoutClosing(m, "user-1") }}
	done := make(chan struct{})
	go func() { a.HandleWMPEvents(w, req); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the stream kept running after its token was revoked mid-batch")
	}
	body := w.String()
	assert.Contains(t, body, `"n":1`)
	assert.NotContains(t, body, "second-event")
	assert.NotContains(t, body, "third-event")
}
