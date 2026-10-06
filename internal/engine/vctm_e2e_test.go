package engine_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// realRegistryHandler serves the ACTUAL registry handler (not a fake) under
// /registry, exactly as RegistryProvider.InProcessHandler does, over a store
// holding the given entries. Paths the real handler does not register 404.
func realRegistryHandler(t *testing.T, entries ...*registry.VCTMEntry) (http.Handler, *atomic.Int32) {
	t.Helper()
	store := registry.NewStore("")
	for _, e := range entries {
		store.Put(e)
	}
	h := registry.NewHandler(store, nil, nil, zap.NewNop())
	t.Cleanup(h.Close)
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	h.RegisterRoutes(r.Group("/registry"))
	var hits atomic.Int32
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		r.ServeHTTP(w, req)
	}), &hits
}

func vctmName(t *testing.T, out map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(out["type_metadata"])
	require.NoError(t, err)
	var md engine.TypeMetadata
	require.NoError(t, json.Unmarshal(raw, &md))
	return md.Name
}

// End-to-end: the ProtocolVCTM flow against the real registry handler and a
// store containing the (non-URL) VCT. The metadata must come from the
// registry; the direct-VCT-fetch fallback must not run.
func TestVCTMFlow_RealRegistryHandlerInProcess(t *testing.T) {
	// A server for the direct-fetch fallback: any hit is a failure.
	var directHits atomic.Int32
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		_, _ = w.Write([]byte(`{"vct":"x","name":"From direct"}`))
	}))
	defer direct.Close()

	cfg := &config.Config{HTTPClient: config.HTTPClientConfig{AllowPrivateIPs: true}}
	cfg.Server.RegistryPort = 1 // nothing listens: only the in-process path can answer
	m := engine.NewManager(cfg, zap.NewNop())

	h, hits := realRegistryHandler(t,
		&registry.VCTMEntry{VCT: "urn:example:id", Name: "ignored",
			Metadata: json.RawMessage(`{"vct":"urn:example:id","name":"From registry store"}`)},
		&registry.VCTMEntry{VCT: direct.URL + "/vct", Name: "ignored",
			Metadata: json.RawMessage(`{"vct":"u","name":"URL from registry store"}`)},
	)
	m.SetRegistryHandler(h)

	out := engine.RunVCTMFlow(t, m, "urn:example:id")
	assert.Equal(t, string(engine.TypeFlowComplete), out["type"])
	assert.Equal(t, "From registry store", vctmName(t, out))

	// URL-shaped VCT present in the store: still served by the registry.
	out = engine.RunVCTMFlow(t, m, direct.URL+"/vct")
	assert.Equal(t, string(engine.TypeFlowComplete), out["type"])
	assert.Equal(t, "URL from registry store", vctmName(t, out))

	assert.EqualValues(t, 2, hits.Load(), "registry handler must answer both lookups")
	assert.EqualValues(t, 0, directHits.Load(), "no direct VCT fetch may happen")

	// Not in the store and not a URL: the flow errors (404 -> direct fallback fails).
	out = engine.RunVCTMFlow(t, m, "urn:example:missing")
	assert.Equal(t, string(engine.TypeFlowError), out["type"])
}
