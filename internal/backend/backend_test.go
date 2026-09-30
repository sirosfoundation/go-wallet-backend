package backend

import (
	"context"
	"testing"

	"go.mongodb.org/mongo-driver/mongo"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/mongodb"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNew_MemoryBackend(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "memory",
		},
	}

	backend, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Verify all stores are accessible
	if backend.Users() == nil {
		t.Error("expected Users() to return non-nil store")
	}
	if backend.Credentials() == nil {
		t.Error("expected Credentials() to return non-nil store")
	}
	if backend.Presentations() == nil {
		t.Error("expected Presentations() to return non-nil store")
	}
	if backend.Challenges() == nil {
		t.Error("expected Challenges() to return non-nil store")
	}
	if backend.Issuers() == nil {
		t.Error("expected Issuers() to return non-nil store")
	}
	if backend.Verifiers() == nil {
		t.Error("expected Verifiers() to return non-nil store")
	}
}

func TestNew_DefaultToMemory(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "", // Empty should default to memory
		},
	}

	backend, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected no error for empty type, got %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Should be able to use the backend
	if backend.Users() == nil {
		t.Error("expected Users() to return non-nil store")
	}
}

func TestNew_UnsupportedType(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "unsupported",
		},
	}

	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for unsupported storage type")
	}
}

func TestNew_MongoDBWithInvalidURI(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "mongodb",
			MongoDB: config.MongoDBConfig{
				URI:      "mongodb://invalid-host-that-does-not-exist:27017",
				Database: "test",
				Timeout:  1, // Short timeout for faster test failure
			},
		},
	}

	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for invalid MongoDB URI")
	}
}

func TestMemoryBackend_Close(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "memory",
		},
	}

	backend, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Close should not return an error for memory backend
	if err := backend.Close(); err != nil {
		t.Errorf("expected no error on Close(), got %v", err)
	}
}

func TestMemoryBackend_TenantStores(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "memory",
		},
	}

	backend, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Test Tenants store
	if backend.Tenants() == nil {
		t.Error("expected Tenants() to return non-nil store")
	}

	// Test UserTenants store
	if backend.UserTenants() == nil {
		t.Error("expected UserTenants() to return non-nil store")
	}
}

func TestMemoryBackend_Ping(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "memory",
		},
	}

	backend, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Ping should succeed for memory backend
	if err := backend.Ping(context.Background()); err != nil {
		t.Errorf("expected no error on Ping(), got %v", err)
	}
}

func TestMemoryBackend_Invites(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "memory",
		},
	}

	backend, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Test Invites store
	if backend.Invites() == nil {
		t.Error("expected Invites() to return non-nil store")
	}
}

func TestBackendTypes(t *testing.T) {
	// Test that the type constants are defined correctly
	if TypeMemory != "memory" {
		t.Errorf("TypeMemory = %q, want %q", TypeMemory, "memory")
	}
	if TypeMongoDB != "mongodb" {
		t.Errorf("TypeMongoDB = %q, want %q", TypeMongoDB, "mongodb")
	}
}

// TestMongoBackend_ImplementsDatabaseProvider is a regression test: services.go
// detects a MongoDB-backed deployment via `store.(interface{ Database() *mongo.Database })`
// to select the horizontally-scalable WIA challenge store (see issue #224). Without
// mongoBackend forwarding Database() from its wrapped *mongodb.Store, that type
// assertion always failed and every MongoDB deployment silently fell back to the
// in-memory (single-instance-only) challenge store.
func TestMongoBackend_ImplementsDatabaseProvider(t *testing.T) {
	var b Backend = &mongoBackend{store: &mongodb.Store{}}

	type databaseProvider interface {
		Database() *mongo.Database
	}

	if _, ok := b.(databaseProvider); !ok {
		t.Fatal("mongoBackend does not implement databaseProvider — MongoDB WIA challenge store will never be selected")
	}
}

// TestMemoryBackend_DoesNotImplementDatabaseProvider documents the expected
// counterpart: memoryBackend has no MongoDB database, so it correctly does
// NOT satisfy databaseProvider, and callers must fall back to the in-memory
// challenge store for memory-backed deployments.
func TestMemoryBackend_DoesNotImplementDatabaseProvider(t *testing.T) {
	var b Backend = &memoryBackend{store: memory.NewStore()}

	type databaseProvider interface {
		Database() *mongo.Database
	}

	if _, ok := b.(databaseProvider); ok {
		t.Fatal("memoryBackend unexpectedly implements databaseProvider")
	}
}
