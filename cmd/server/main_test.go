package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

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
	cfg.Registry.RequireAuth = true // internal calls bypass auth and rate limiting

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
