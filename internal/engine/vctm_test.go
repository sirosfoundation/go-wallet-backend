package engine

import (
	"encoding/json"
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

func TestVCTMFlow_UsesInProcessRegistryClient(t *testing.T) {
	cfg := testConfig()
	cfg.Server.RegistryPort = unusedPort(t) // nothing listens: only the in-process path can answer
	m := NewManager(cfg, zap.NewNop())

	var hits atomic.Int32
	m.SetRegistryHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/registry/vctm/urn:example:id" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vct":"urn:example:id","name":"From fake"}`))
	}))

	out := runVCTMFlow(t, m, "urn:example:id")
	assert.Equal(t, string(TypeFlowComplete), out["type"])
	assert.EqualValues(t, 1, hits.Load())
	var md TypeMetadata
	raw, err := json.Marshal(out["type_metadata"])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &md))
	assert.Equal(t, "From fake", md.Name)
}

func TestVCTMFlow_DefaultClientUsesConfiguredRegistryURL(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		assert.Equal(t, "/vctm/urn:example:id", r.URL.Path)
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
