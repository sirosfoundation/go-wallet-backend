package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/internal/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestStandaloneRegistryBinaryIsGone(t *testing.T) {
	_, err := os.Stat(filepath.Join("..", "registry"))
	assert.True(t, os.IsNotExist(err), "cmd/registry was retired: the registry is a role of cmd/server")
}

func TestRegistryListenAddr(t *testing.T) {
	h, p := registryListenAddr("0.0.0.0:8097")
	assert.Equal(t, "0.0.0.0", h)
	assert.Equal(t, 8097, p)

	h, p = registryListenAddr("127.0.0.1:9100")
	assert.Equal(t, "127.0.0.1", h)
	assert.Equal(t, 9100, p)

	h, p = registryListenAddr("garbage")
	assert.Equal(t, "garbage", h)
	assert.Equal(t, 8097, p)

	_, p = registryListenAddr("host:notaport")
	assert.Equal(t, 8097, p)
}

func TestSetupRegistryConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
		return p
	}

	t.Run("registry-only defaults, no deprecated config", func(t *testing.T) {
		cfg, err := config.LoadRegistryOnly(write("a.yaml", "registry:\n  cache:\n    path: /x/c.json\n"))
		require.NoError(t, err)
		w, err := setupRegistryConfig(cfg, filepath.Join(dir, "absent.yaml"), true)
		require.NoError(t, err)
		assert.Empty(t, w)
		host, port := registryListenAddr(cfg.Server.RegistryAddress())
		assert.Equal(t, "0.0.0.0", host)
		assert.Equal(t, 8097, port, "registry-only keeps the retired binary's default port")
	})

	t.Run("deprecated file still works and warns", func(t *testing.T) {
		cfg, err := config.LoadRegistryOnly(filepath.Join(dir, "nobackend.yaml"))
		require.NoError(t, err)
		old := write("registry.yaml", "server:\n  port: 9300\ncache:\n  path: /old/c.json\n")
		w, err := setupRegistryConfig(cfg, old, true)
		require.NoError(t, err)
		require.NotEmpty(t, w)
		assert.Contains(t, w[0], "DEPRECATED")
		assert.Equal(t, "/old/c.json", cfg.Registry.Cache.Path)
		_, port := registryListenAddr(cfg.Server.RegistryAddress())
		assert.Equal(t, 9300, port)
	})

	t.Run("require_auth without as.* fields fails naming them", func(t *testing.T) {
		cfg, err := config.LoadRegistryOnly(write("b.yaml", "registry:\n  require_auth: true\n"))
		require.NoError(t, err)
		_, err = setupRegistryConfig(cfg, "", true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "as.external_url")
	})

	t.Run("deprecated overlay is revalidated (port 70000)", func(t *testing.T) {
		cfg, err := config.LoadRegistryOnly("")
		require.NoError(t, err)
		old := write("badport.yaml", "server:\n  port: 70000\n")
		_, err = setupRegistryConfig(cfg, old, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "registry_port")
	})

	t.Run("invalid registry section", func(t *testing.T) {
		cfg, err := config.LoadRegistryOnly(write("c.yaml", "registry:\n  cache:\n    path: \"\"\n"))
		require.NoError(t, err)
		_, err = setupRegistryConfig(cfg, "", true)
		assert.Error(t, err)
	})

	t.Run("unreadable deprecated file", func(t *testing.T) {
		cfg, err := config.LoadRegistryOnly("")
		require.NoError(t, err)
		_, err = setupRegistryConfig(cfg, dir, true) // a directory
		assert.Error(t, err)
	})
}

func TestLoggingConfig(t *testing.T) {
	assert.Nil(t, loggingConfig(nil, nil))

	backend, err := config.LoadRegistryOnly("")
	require.NoError(t, err)
	backend.Logging.Level = "debug"
	backend.Logging.Format = "text"
	reg, err := config.LoadRegistryOnly("")
	require.NoError(t, err)
	reg.Logging.Level = "warn"

	got := loggingConfig(backend, nil)
	require.NotNil(t, got)
	assert.Equal(t, "debug", got.Level, "backend roles without registry keep their logging config")
	assert.Equal(t, "text", got.Format)

	got = loggingConfig(backend, reg)
	assert.Equal(t, "debug", got.Level, "backend config wins when both are loaded")

	got = loggingConfig(nil, reg)
	assert.Equal(t, "warn", got.Level)
}

// Default combined wiring end to end: the engine's VCTM client reaches the
// registry handler in-process (no network, so the outbound loopback/HTTP
// guards do not apply).
func TestColocatedEngineClientReachesRegistry(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "vctm.json"),
		[]byte(`{"vct":"https://example.org/cred/v1","name":"Example"}`), 0o600))

	cfg, err := config.LoadRegistryOnly("")
	require.NoError(t, err)
	cfg.Registry.Cache.Path = filepath.Join(dir, "cache.json")
	cfg.Registry.Source.LocalOverrides = []string{filepath.Join(dir, "vctm.json")}
	cfg.Registry.Source.URL = "http://127.0.0.1:1/x.json"
	cfg.Registry.RequireAuth = true            // internal calls bypass auth and rate limiting
	cfg.AS.ExternalURL = "https://127.0.0.1:1" // JWKS source (never contacted by the in-process handler)

	p, err := server.NewRegistryProvider(cfg, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	// Default HTTP client policy: a network call to loopback would be refused.
	client := engine.NewRegistryClient(cfg, zap.NewNop())
	client.SetHandler(p.InProcessHandler())

	md, err := client.FetchTypeMetadata(context.Background(), "https://example.org/cred/v1")
	require.NoError(t, err)
	require.NotNil(t, md, "engine client must find the VCTM through the co-located registry")
	assert.Equal(t, "https://example.org/cred/v1", md.VCT)

	md, err = client.FetchTypeMetadata(context.Background(), "https://example.org/unknown")
	require.NoError(t, err)
	assert.Nil(t, md)
}

// Deprecated registry.yaml with an HMAC secret on a registry-only process. The
// legacy HMAC authorization server is gone, so the secret has nothing left to
// validate: it is ignored with a loud warning, and a deployment that relied on
// it for jwt.require_auth fails startup unless the AS JWKS (as.external_url) is
// configured - exactly as as.legacy.enabled=true fails startup.
func TestDeprecatedRegistryConfigHMACSecretIgnored(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	dir := t.TempDir()
	old := filepath.Join(dir, "registry.yaml")
	require.NoError(t, os.WriteFile(old, []byte("cache:\n  path: "+filepath.Join(dir, "c.json")+"\n"+
		"source:\n  url: http://127.0.0.1:1/x.json\n"+
		"jwt:\n  secret: \""+secret+"\"\n  issuer: wallet-backend\n  require_auth: true\n"), 0o600))

	// No as.external_url: HMAC-only auth no longer exists -> startup fails.
	cfg, err := config.LoadRegistryOnly("")
	require.NoError(t, err)
	_, err = setupRegistryConfig(cfg, old, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "as.external_url")

	// With the AS JWKS configured it starts; the secret is ignored (loudly).
	cfg, err = config.LoadRegistryOnly("")
	require.NoError(t, err)
	cfg.AS.ExternalURL = "https://127.0.0.1:1" // never reachable (SSRF guard); only HMAC tokens are probed
	w, err := setupRegistryConfig(cfg, old, true)
	require.NoError(t, err)
	assert.Contains(t, strings.Join(w, "\n"), "IGNORED")
	assert.Empty(t, cfg.JWT.Secret, "the old secret is not adopted")
	cfg.Registry.DynamicCache.Enabled = false

	p, err := server.NewRegistryProvider(cfg, zap.NewNop())
	require.NoError(t, err)
	require.NoError(t, p.Start(context.Background()))
	t.Cleanup(func() { _ = p.Close() })

	hmac := func(mod func(jwt.MapClaims)) string {
		c := jwt.MapClaims{"iss": "wallet-backend", "user_id": "u", "tenant_id": "acme", "jti": "j1",
			"aud": "wallet-registry", "exp": time.Now().Add(time.Hour).Unix()}
		if mod != nil {
			mod(c)
		}
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(secret))
		require.NoError(t, err)
		return "Bearer " + s
	}
	get := func(authz string) int {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		p.RegisterRoutes(r)
		req := httptest.NewRequest(http.MethodGet, "/registry/status", nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Code
	}
	assert.Equal(t, http.StatusUnauthorized, get(""))
	assert.Equal(t, http.StatusUnauthorized, get(hmac(nil)), "a valid HMAC token signed with the old secret is rejected")

	// as.legacy.enabled=true is refused for a registry-only process too.
	n, err := config.LoadRegistryOnly("")
	require.NoError(t, err)
	yes := true
	n.AS.Legacy.Enabled = &yes
	_, err = setupRegistryConfig(n, "", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "as.legacy.enabled=true")
}
