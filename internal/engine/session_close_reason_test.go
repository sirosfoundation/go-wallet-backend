package engine

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func closedCount(t *testing.T, reason string) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, wsSessionClosedTotal.WithLabelValues(reason).Write(&m))
	return m.GetCounter().GetValue()
}

func TestClassifyClose(t *testing.T) {
	timeoutErr := fmt.Errorf("read: %w", os.ErrDeadlineExceeded)
	tests := []struct {
		name     string
		pending  string
		err      error
		want     string
		wantCode int
	}{
		{"read deadline", "", timeoutErr, closeReasonReadDeadline, 0},
		{"peer close frame", "", &websocket.CloseError{Code: websocket.CloseGoingAway, Text: "secret"}, closeReasonPeerClose, websocket.CloseGoingAway},
		{"peer close wrapped", "", fmt.Errorf("x: %w", &websocket.CloseError{Code: 4001}), closeReasonPeerClose, 4001},
		{"other read error", "", errors.New("boom"), closeReasonReadError, 0},
		{"superseded wins over closed-conn error", closeReasonSuperseded, errors.New("use of closed network connection"), closeReasonSuperseded, 0},
		{"write error wins over timeout", closeReasonWriteError, timeoutErr, closeReasonWriteError, 0},
		{"shutdown", closeReasonServerShutdown, nil, closeReasonServerShutdown, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, code := classifyClose(tt.pending, tt.err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantCode, code)
		})
	}
}

func TestCloseReasonFromText(t *testing.T) {
	assert.Equal(t, closeReasonAccountDeleted, closeReasonFromText("account deleted"))
	assert.Equal(t, closeReasonTokenRevoked, closeReasonFromText("token revoked"))
	assert.Equal(t, closeReasonRevocationFailed, closeReasonFromText("revocation check unavailable"))
	assert.Equal(t, closeReasonServerClose, closeReasonFromText("anything else"))
}

func newObservedManager(t *testing.T, cfg *config.Config) (*Manager, *observer.ObservedLogs, string) {
	t.Helper()
	core, logs := observer.New(zap.DebugLevel)
	m := NewManager(cfg, zap.New(core))
	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	t.Cleanup(server.Close)
	return m, logs, "ws" + strings.TrimPrefix(server.URL, "http")
}

func testCfg() *config.Config {
	return &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
}

func closeEntry(t *testing.T, logs *observer.ObservedLogs, reason string) map[string]interface{} {
	t.Helper()
	var found map[string]interface{}
	require.Eventually(t, func() bool {
		for _, e := range logs.FilterMessage("Session close reason").All() {
			if e.ContextMap()["reason"] == reason {
				found = e.ContextMap()
				return true
			}
		}
		return false
	}, 3*time.Second, 10*time.Millisecond, "no close line with reason %q", reason)
	return found
}

func TestCloseReason_ReadDeadline(t *testing.T) {
	cfg := testCfg()
	cfg.Server.EngineWSPingInterval = 50 * time.Millisecond
	cfg.Server.EngineWSPongTimeout = 100 * time.Millisecond
	m, logs, wsURL := newObservedManager(t, cfg)
	before := closedCount(t, closeReasonReadDeadline)

	// The client never reads, so it never answers a ping: the server's read
	// deadline must expire.
	ws := dialAndHandshakeAsUser(t, m, wsURL, "deadline-user-1234")
	defer func() { _ = ws.Close() }()

	f := closeEntry(t, logs, closeReasonReadDeadline)
	assert.NotEmpty(t, f["session_id"])
	assert.NotEmpty(t, f["remote_addr"])
	assert.Contains(t, f, "read_window")
	assert.Contains(t, f, "since_last_inbound")
	assert.Contains(t, f, "session_age")
	assert.Contains(t, f, "ping_interval")
	assert.Contains(t, f, "pong_timeout")
	assert.Greater(t, closedCount(t, closeReasonReadDeadline), before)
}

func TestCloseReason_PeerClose_LogsOnlyNumericCode(t *testing.T) {
	m, logs, wsURL := newObservedManager(t, testCfg())
	ws := dialAndHandshakeAsUser(t, m, wsURL, "peer-user-12345678")

	require.NoError(t, ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(4001, "PEER-SUPPLIED-FREE-TEXT"), time.Now().Add(time.Second)))
	_ = ws.Close()

	f := closeEntry(t, logs, closeReasonPeerClose)
	assert.EqualValues(t, 4001, f["close_code"])
	// (The pre-existing "Read error" line still logs err verbatim for
	// unexpected close codes; this PR deliberately does not touch it.)
	for _, e := range logs.FilterMessage("Session close reason").All() {
		assert.NotContains(t, fmt.Sprint(e.ContextMap()), "PEER-SUPPLIED-FREE-TEXT")
	}
}

func TestCloseReason_ServerPaths(t *testing.T) {
	m, logs, wsURL := newObservedManager(t, testCfg())
	ws := dialAndHandshakeAsUser(t, m, wsURL, "deleted-user-123456")
	defer func() { _ = ws.Close() }()
	require.Equal(t, 1, m.CloseUserSessions("deleted-user-123456", "account deleted"))
	closeEntry(t, logs, closeReasonAccountDeleted)

	ws2 := dialAndHandshakeAsUser(t, m, wsURL, "shutdown-user-12345")
	defer func() { _ = ws2.Close() }()
	m.Close()
	closeEntry(t, logs, closeReasonServerShutdown)
}

func TestCloseReason_Superseded_LogsBothSessions(t *testing.T) {
	m, logs, wsURL := newObservedManager(t, testCfg())
	const user = "dup-user-1234567890"

	ws1 := dialAndHandshakeAsUser(t, m, wsURL, user)
	defer func() { _ = ws1.Close() }()
	m.sessionsMu.RLock()
	oldID := m.userIndex[userKey{TenantID: "test-tenant", UserID: user}].ID
	m.sessionsMu.RUnlock()

	ws2 := dialAndHandshakeAsUser(t, m, wsURL, user)
	defer func() { _ = ws2.Close() }()

	var newID string
	require.Eventually(t, func() bool {
		m.sessionsMu.RLock()
		defer m.sessionsMu.RUnlock()
		newID = m.userIndex[userKey{TenantID: "test-tenant", UserID: user}].ID
		return newID != oldID
	}, time.Second, 10*time.Millisecond)

	var closing map[string]interface{}
	require.Eventually(t, func() bool {
		es := logs.FilterMessage("Closing existing session").All()
		if len(es) == 0 {
			return false
		}
		closing = es[0].ContextMap()
		return true
	}, time.Second, 10*time.Millisecond)
	assert.Equal(t, zap.InfoLevel, logs.FilterMessage("Closing existing session").All()[0].Level)
	assert.Equal(t, oldID, closing["old_session_id"])
	assert.Equal(t, newID, closing["new_session_id"])
	assert.Contains(t, closing, "old_session_age")
	assert.Contains(t, closing, "new_session_age")
	assert.NotEmpty(t, closing["old_remote_addr"])
	assert.NotEmpty(t, closing["new_remote_addr"])

	f := closeEntry(t, logs, closeReasonSuperseded)
	assert.Equal(t, oldID, f["session_id"])
	assert.Equal(t, newID, f["superseded_by_session_id"])

	// The new connection reports what it superseded.
	require.Eventually(t, func() bool {
		return logs.FilterMessage("Session established").Len() == 2
	}, time.Second, 10*time.Millisecond)
	established := map[string]map[string]interface{}{}
	for _, e := range logs.FilterMessage("Session established").All() {
		c := e.ContextMap()
		established[c["session_id"].(string)] = c
	}
	require.Contains(t, established, oldID)
	require.Contains(t, established, newID)
	assert.Equal(t, "", established[oldID]["superseded_session_id"])
	assert.Equal(t, oldID, established[newID]["superseded_session_id"])

	// No secrets anywhere in the logs.
	for _, e := range logs.All() {
		s := fmt.Sprint(e.ContextMap(), e.Message)
		// dialAndHandshakeAsUser mints its own bearer tokens; any JWT would start with eyJ.
		assert.NotContains(t, s, "eyJ")
		assert.NotContains(t, s, "app_token")
	}
}

func TestMarkClosing_DoesNotOverrideRecordedReadError(t *testing.T) {
	s := &Session{closeInfo: newCloseBookkeeping(nil)}
	s.noteReadError(&websocket.CloseError{Code: 4001})
	assert.False(t, s.markClosing(closeReasonSuperseded, "x"))
	assert.True(t, (&Session{closeInfo: newCloseBookkeeping(nil)}).markClosing(closeReasonSuperseded, "x"))
	reason, code := classifyClose(s.closeInfo.pending, s.closeInfo.readErr)
	assert.Equal(t, closeReasonPeerClose, reason)
	assert.Equal(t, 4001, code)
}

// Under the tenant-scoped index a session is superseded only by a later
// session of the same (tenant, user); the reason attribution follows that key.
func TestCloseReason_Superseded_TenantScopedKey(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	m := NewManager(testCfg(), zap.New(core))
	defer m.Close()
	mk := func(id, tenant string) *Session {
		s := newMultiTenantTestSession(t, id, tenant, "user-1")
		s.closeInfo = newCloseBookkeeping(s.conn)
		return s
	}

	a1, b1 := mk("a1", "tenant-a"), mk("b1", "tenant-b")
	require.True(t, m.registerSession(a1))
	require.True(t, m.registerSession(b1))
	// Same user in another tenant is not a supersession.
	assert.Equal(t, 0, logs.FilterMessage("Closing existing session").Len())
	assert.Empty(t, a1.closeInfo.pending)
	assert.Empty(t, b1.supersededID())

	a2 := mk("a2", "tenant-a")
	require.True(t, m.registerSession(a2))

	assert.Equal(t, closeReasonSuperseded, a1.closeInfo.pending)
	assert.Equal(t, "a2", a1.closeInfo.supersededBy)
	assert.Equal(t, "a1", a2.supersededID())
	assert.Empty(t, b1.closeInfo.pending, "tenant B session must not be attributed a close")

	es := logs.FilterMessage("Closing existing session").All()
	require.Len(t, es, 1)
	f := es[0].ContextMap()
	assert.Equal(t, zap.InfoLevel, es[0].Level)
	assert.Equal(t, "tenant-a", f["tenant_id"])
	assert.Equal(t, "a1", f["old_session_id"])
	assert.Equal(t, "a2", f["new_session_id"])
}
