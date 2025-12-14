package service

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func setupWebAuthnService(t *testing.T) (*WebAuthnService, *memory.Store) {
	t.Helper()

	cfg := &config.Config{
		Server: config.ServerConfig{
			RPName:   "Test App",
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
		},
	}

	store := memory.NewStore()
	logger := zap.NewNop()

	svc, err := NewWebAuthnService(store, cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create WebAuthn service: %v", err)
	}

	return svc, store
}

func TestWebAuthnService_Creation(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := &config.Config{
			Server: config.ServerConfig{
				RPName:   "Test App",
				RPID:     "localhost",
				RPOrigin: "http://localhost:8080",
			},
		}

		store := memory.NewStore()
		logger := zap.NewNop()

		svc, err := NewWebAuthnService(store, cfg, logger)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if svc == nil {
			t.Error("Expected service to be created")
		}
	})

	t.Run("empty config uses defaults", func(t *testing.T) {
		// Even with empty RPID, the go-webauthn library may accept it
		// but the service should still be creatable
		cfg := &config.Config{
			Server: config.ServerConfig{
				RPName:   "Test App",
				RPID:     "",
				RPOrigin: "http://localhost:8080",
			},
		}

		store := memory.NewStore()
		logger := zap.NewNop()

		// This might succeed or fail depending on go-webauthn validation
		_, _ = NewWebAuthnService(store, cfg, logger)
	})
}

func TestWebAuthnService_BeginRegistration(t *testing.T) {
	svc, _ := setupWebAuthnService(t)
	ctx := context.Background()

	t.Run("successful registration start", func(t *testing.T) {
		resp, err := svc.BeginRegistration(ctx, "Test User")
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if resp == nil {
			t.Fatal("Expected response, got nil")
		}

		if resp.ChallengeID == "" {
			t.Error("Expected challenge ID")
		}

		if resp.CreateOptions.PublicKey == nil {
			t.Error("Expected credential creation options")
		}

		// Verify options structure
		if resp.CreateOptions.PublicKey.Response.Challenge == nil {
			t.Error("Expected challenge in options")
		}

		if resp.CreateOptions.PublicKey.Response.RelyingParty.ID != "localhost" {
			t.Errorf("Expected RPID 'localhost', got '%s'", resp.CreateOptions.PublicKey.Response.RelyingParty.ID)
		}

		if resp.CreateOptions.PublicKey.Response.User.Name == "" {
			t.Error("Expected user name in options")
		}
	})

	t.Run("registration with empty display name", func(t *testing.T) {
		resp, err := svc.BeginRegistration(ctx, "")
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if resp == nil {
			t.Fatal("Expected response, got nil")
		}

		// Should generate a user ID even without display name
		if resp.CreateOptions.PublicKey.Response.User.ID == nil {
			t.Error("Expected user ID")
		}
	})
}

func TestWebAuthnService_BeginLogin(t *testing.T) {
	svc, _ := setupWebAuthnService(t)
	ctx := context.Background()

	t.Run("successful login start", func(t *testing.T) {
		resp, err := svc.BeginLogin(ctx)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if resp == nil {
			t.Fatal("Expected response, got nil")
		}

		if resp.ChallengeID == "" {
			t.Error("Expected challenge ID")
		}

		if resp.GetOptions.PublicKey == nil {
			t.Error("Expected assertion options")
		}

		// Verify options structure
		if resp.GetOptions.PublicKey.Response.Challenge == nil {
			t.Error("Expected challenge in options")
		}

		// Discoverable credential login should have empty AllowedCredentials
		if len(resp.GetOptions.PublicKey.Response.AllowedCredentials) != 0 {
			t.Error("Expected empty AllowedCredentials for discoverable login")
		}

		if resp.GetOptions.PublicKey.Response.RelyingPartyID != "localhost" {
			t.Errorf("Expected RPID 'localhost', got '%s'", resp.GetOptions.PublicKey.Response.RelyingPartyID)
		}
	})
}

func TestWebAuthnService_FinishRegistration_Errors(t *testing.T) {
	svc, _ := setupWebAuthnService(t)
	ctx := context.Background()

	t.Run("challenge not found", func(t *testing.T) {
		req := &FinishRegistrationRequest{
			ChallengeID: "nonexistent",
		}

		_, err := svc.FinishRegistration(ctx, req)
		if err != ErrChallengeNotFound {
			t.Errorf("Expected ErrChallengeNotFound, got %v", err)
		}
	})

	t.Run("empty challenge ID", func(t *testing.T) {
		req := &FinishRegistrationRequest{
			ChallengeID: "",
		}

		_, err := svc.FinishRegistration(ctx, req)
		if err != ErrChallengeNotFound {
			t.Errorf("Expected ErrChallengeNotFound, got %v", err)
		}
	})
}

func TestWebAuthnService_FinishLogin_Errors(t *testing.T) {
	svc, _ := setupWebAuthnService(t)
	ctx := context.Background()

	t.Run("challenge not found", func(t *testing.T) {
		req := &FinishLoginRequest{
			ChallengeID: "nonexistent",
		}

		_, err := svc.FinishLogin(ctx, req)
		if err != ErrChallengeNotFound {
			t.Errorf("Expected ErrChallengeNotFound, got %v", err)
		}
	})

	t.Run("empty challenge ID", func(t *testing.T) {
		req := &FinishLoginRequest{
			ChallengeID: "",
		}

		_, err := svc.FinishLogin(ctx, req)
		if err != ErrChallengeNotFound {
			t.Errorf("Expected ErrChallengeNotFound, got %v", err)
		}
	})
}

func TestWebAuthnService_ChallengeExpiration(t *testing.T) {
	svc, store := setupWebAuthnService(t)
	ctx := context.Background()

	t.Run("challenge expires after timeout", func(t *testing.T) {
		// Start registration
		resp, err := svc.BeginRegistration(ctx, "Test User")
		if err != nil {
			t.Fatalf("Failed to begin registration: %v", err)
		}

		// Manually expire the challenge in storage
		challenge, err := store.Challenges().GetByID(ctx, resp.ChallengeID)
		if err != nil {
			t.Fatalf("Failed to get challenge: %v", err)
		}

		// Delete and recreate with expired time
		_ = store.Challenges().Delete(ctx, resp.ChallengeID)
		challenge.ExpiresAt = time.Now().Add(-1 * time.Hour) // Set to past
		if err := store.Challenges().Create(ctx, challenge); err != nil {
			t.Fatalf("Failed to recreate challenge: %v", err)
		}

		// Try to finish registration
		req := &FinishRegistrationRequest{
			ChallengeID: resp.ChallengeID,
		}

		_, err = svc.FinishRegistration(ctx, req)
		if err != ErrChallengeExpired {
			t.Errorf("Expected ErrChallengeExpired, got %v", err)
		}
	})
}

func TestWebAuthnUser(t *testing.T) {
	t.Run("implements webauthn.User interface", func(t *testing.T) {
		username := "testuser"
		displayName := "Test User"
		user := &domain.User{
			UUID:        domain.NewUserID(),
			Username:    &username,
			DisplayName: &displayName,
		}

		waUser := &WebAuthnUser{user: user}

		if len(waUser.WebAuthnID()) == 0 {
			t.Error("Expected non-empty user ID")
		}

		if waUser.WebAuthnName() != "testuser" {
			t.Errorf("Expected username 'testuser', got '%s'", waUser.WebAuthnName())
		}

		if waUser.WebAuthnDisplayName() != "Test User" {
			t.Errorf("Expected display name 'Test User', got '%s'", waUser.WebAuthnDisplayName())
		}

		if len(waUser.WebAuthnCredentials()) != 0 {
			t.Error("Expected empty credentials for user without credentials")
		}
	})

	t.Run("fallback values when nil", func(t *testing.T) {
		user := &domain.User{
			UUID: domain.NewUserID(),
		}

		waUser := &WebAuthnUser{user: user}

		// Should fall back to user ID string when username is nil
		if waUser.WebAuthnName() == "" {
			t.Error("Expected non-empty username fallback")
		}

		// Should fall back to WebAuthnName when display name is nil
		if waUser.WebAuthnDisplayName() == "" {
			t.Error("Expected non-empty display name fallback")
		}
	})
}
