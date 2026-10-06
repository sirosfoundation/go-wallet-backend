package engine

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// unusedPort returns a TCP port with nothing listening on it.
func unusedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// runVCTMFlow runs the registered ProtocolVCTM flow through the Manager's
// real flow-start path and returns the message the session sent.
func runVCTMFlow(t *testing.T, m *Manager, vct string) map[string]any {
	t.Helper()
	m.RegisterFlowHandler(ProtocolVCTM, NewVCTMHandler)
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		m.handleFlowStart(testSession(srvConn), &FlowStartMessage{
			Message:  Message{Type: TypeFlowStart, FlowID: "f1"},
			Protocol: ProtocolVCTM,
			VCT:      vct,
		})
	})
	defer cleanup()
	var out map[string]any
	require.NoError(t, conn.ReadJSON(&out))
	return out
}

func TestVCTMFlow_DefaultClientUsesConfiguredRegistryURL(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		assert.Equal(t, "/type-metadata", r.URL.Path)
		assert.Equal(t, "urn:example:id", r.URL.Query().Get("vct"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vct":"urn:example:id","name":"From http"}`))
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Trust.RegistryURL = srv.URL
	m := NewManager(cfg, zap.NewNop()) // no SetRegistryHandler: default HTTP client

	out := runVCTMFlow(t, m, "urn:example:id")
	assert.Equal(t, string(TypeFlowComplete), out["type"])
	assert.EqualValues(t, 1, hits.Load())
}
