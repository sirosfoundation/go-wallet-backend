package backend

import (
	"context"
	"testing"

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
