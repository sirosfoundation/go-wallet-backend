package server

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func sharedBlacklistConfig(storageType, backend string, enabled bool) *config.Config {
	cfg := &config.Config{}
	cfg.Storage.Type = storageType
	cfg.Storage.MongoDB = config.MongoDBConfig{URI: "mongodb://127.0.0.1:1", Database: "x", Timeout: 1}
	cfg.Security.TokenBlacklist = config.TokenBlacklistConfig{Enabled: enabled, Backend: backend}
	return cfg
}

func TestNewSharedBlacklist_NotShared(t *testing.T) {
	for name, cfg := range map[string]*config.Config{
		"disabled":                  sharedBlacklistConfig("mongodb", "", false),
		"backend memory":            sharedBlacklistConfig("mongodb", "memory", true),
		"unset, non-MongoDB":        sharedBlacklistConfig("memory", "", true),
		"unset, storage type empty": sharedBlacklistConfig("", "", true),
	} {
		t.Run(name, func(t *testing.T) {
			b, err := NewSharedBlacklist(context.Background(), cfg, zap.NewNop())
			require.NoError(t, err)
			require.Nil(t, b, "a process-local blacklist would never see a revocation")
		})
	}
}

func TestNewSharedBlacklist_ConfiguredButUnusable(t *testing.T) {
	for name, cfg := range map[string]*config.Config{
		"storage without MongoDB": sharedBlacklistConfig("memory", "storage", true),
		"unset, MongoDB down":     sharedBlacklistConfig("mongodb", "", true),
		"storage, MongoDB down":   sharedBlacklistConfig("mongodb", "storage", true),
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			b, err := NewSharedBlacklist(ctx, cfg, zap.NewNop())
			require.Error(t, err, "startup must fail rather than fall back to memory")
			require.Nil(t, b)
		})
	}
}

// mongoSharedConfig returns a MongoDB config on a throwaway database, or
// skips (TEST_MONGODB=1 / MONGODB_TEST_URI, as in the service tests).
func mongoSharedConfig(t *testing.T) *config.Config {
	t.Helper()
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" && os.Getenv("TEST_MONGODB") == "" {
		t.Skip("Skipping MongoDB test: set MONGODB_TEST_URI or TEST_MONGODB=1 to enable")
	}
	if uri == "" {
		uri = "mongodb://localhost:27017"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil || client.Ping(ctx, nil) != nil {
		t.Skip("MongoDB not available")
	}
	db := fmt.Sprintf("wb_test_shared_blacklist_%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = client.Database(db).Drop(context.Background())
		_ = client.Disconnect(context.Background())
	})
	cfg := sharedBlacklistConfig("mongodb", "", true)
	cfg.Storage.MongoDB = config.MongoDBConfig{URI: uri, Database: db, Timeout: 5}
	return cfg
}

// A process without storage of its own sees the revocations written by
// another process over the same database.
func TestNewSharedBlacklist_SeesOtherProcessRevocations(t *testing.T) {
	cfg := mongoSharedConfig(t)
	ctx := context.Background()
	writer, err := NewSharedBlacklist(ctx, cfg, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, writer)
	defer writer.Close()
	reader, err := NewSharedBlacklist(ctx, cfg, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, reader)
	defer reader.Close()

	require.NoError(t, writer.Add(ctx, "jti-1", time.Now().Add(time.Hour)))
	require.NoError(t, writer.RevokeUser(ctx, "user-1"))
	require.True(t, reader.IsBlacklisted(ctx, "jti-1"))
	require.True(t, reader.IsUserRevoked(ctx, "user-1"))
	require.False(t, reader.IsBlacklisted(ctx, "jti-2"))
	require.False(t, reader.IsUserRevoked(ctx, "user-2"))
}

func walletProviderMongoConfig(t *testing.T, backend string) *config.Config {
	t.Helper()
	cfg := mongoSharedConfig(t)
	cfg.Security.TokenBlacklist.Backend = backend
	keyPath, certPath := writeTestECKeyAndCert(t, t.TempDir(), "wallet-provider")
	cfg.Server = config.ServerConfig{Host: "localhost", Port: 8080, RPID: "localhost", RPOrigin: "http://localhost:8080"}
	cfg.JWT = config.JWTConfig{Secret: "test-secret-that-is-at-least-32-bytes!", Issuer: "test-issuer"}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath
	cfg.WalletProvider.WIA.RateLimit = config.AuthRateLimitConfig{Enabled: false}
	return cfg
}

// The isolated wallet-provider constructs its own MongoDB backend, so it must
// warn about process-local revocations like NewAuthProvider does, and share
// the revocation store when that is configured.
func TestNewWalletProviderProvider_RevocationStore(t *testing.T) {
	t.Run("warns when revocations stay in memory", func(t *testing.T) {
		core, logs := observer.New(zap.WarnLevel)
		p, err := NewWalletProviderProvider(walletProviderMongoConfig(t, "memory"), zap.New(core))
		require.NoError(t, err)
		defer func() { _ = p.Close() }()
		require.Equal(t, 1, logs.FilterMessageSnippet("token_blacklist.backend=memory").Len())
	})

	t.Run("shares revocations with other processes", func(t *testing.T) {
		cfg := walletProviderMongoConfig(t, "")
		core, logs := observer.New(zap.WarnLevel)
		p, err := NewWalletProviderProvider(cfg, zap.New(core))
		require.NoError(t, err)
		defer func() { _ = p.Close() }()
		require.Equal(t, 0, logs.Len())

		ctx := context.Background()
		other, err := NewSharedBlacklist(ctx, cfg, zap.NewNop())
		require.NoError(t, err)
		defer other.Close()
		require.NoError(t, other.Add(ctx, "jti-1", time.Now().Add(time.Hour)))
		require.True(t, p.services.TokenBlacklist.IsBlacklisted(ctx, "jti-1"))
	})
}
