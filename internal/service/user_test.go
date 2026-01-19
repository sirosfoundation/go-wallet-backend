package service

import (
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Port:     8080,
			Host:     "localhost",
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
		},
		JWT: config.JWTConfig{
			Secret:      "test-secret-key-for-testing-only",
			Issuer:      "test-issuer",
			ExpiryHours: 24,
		},
	}
}

func testLogger() *zap.Logger {
	return zap.NewNop()
}

func TestNewUserService(t *testing.T) {
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()

	service := NewUserService(store, cfg, logger)

	if service == nil {
		t.Fatal("NewUserService() returned nil")
	}

	if service.store == nil {
		t.Error("UserService.store is nil")
	}

	if service.cfg == nil {
		t.Error("UserService.cfg is nil")
	}
}

func TestUserService_Register(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	username := "testuser"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "Test User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
		Keys:        []byte("key-data"),
		PrivateData: []byte("private-data"),
	}

	user, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if user == nil {
		t.Fatal("Register() returned nil user")
	}

	if user.UUID.String() == "" {
		t.Error("User UUID should be set")
	}

	if user.DID == "" {
		t.Error("User DID should be set")
	}

	if user.Username == nil || *user.Username != username {
		t.Error("Username not set correctly")
	}

	if user.WalletType != domain.WalletTypeDB {
		t.Error("WalletType not set correctly")
	}

	if user.PasswordHash == nil {
		t.Error("PasswordHash should be set")
	}
}

func TestUserService_Register_DuplicateUsername(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	username := "duplicate"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "User 1",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
	}

	_, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("First Register() error = %v", err)
	}

	// Try to register with same username
	req2 := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "User 2",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
	}

	_, err = service.Register(ctx, req2)
	if err != ErrUserExists {
		t.Errorf("Register() with duplicate username should return ErrUserExists, got %v", err)
	}
}

func TestUserService_Register_NoUsername(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register without username (anonymous user)
	req := &domain.RegisterRequest{
		DisplayName: "Anonymous User",
		WalletType:  domain.WalletTypeClient,
	}

	user, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if user == nil {
		t.Fatal("Register() returned nil user")
	}

	if user.UUID.String() == "" {
		t.Error("User UUID should be set even for anonymous users")
	}
}

func TestUserService_Login(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register user first
	username := "logintest"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "Login Test User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
	}

	_, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Login
	user, token, err := service.Login(ctx, username, password)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if user == nil {
		t.Fatal("Login() returned nil user")
	}

	if token == "" {
		t.Error("Login() returned empty token")
	}

	if user.Username == nil || *user.Username != username {
		t.Error("Login() returned wrong user")
	}
}

func TestUserService_Login_WrongPassword(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register user first
	username := "wrongpass"
	password := "correctpassword"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "Wrong Pass User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
	}

	_, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Try login with wrong password
	_, _, err = service.Login(ctx, username, "wrongpassword")
	if err != ErrInvalidCredentials {
		t.Errorf("Login() with wrong password should return ErrInvalidCredentials, got %v", err)
	}
}

func TestUserService_Login_NonexistentUser(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	_, _, err := service.Login(ctx, "nonexistent", "password")
	if err != ErrInvalidCredentials {
		t.Errorf("Login() with nonexistent user should return ErrInvalidCredentials, got %v", err)
	}
}

func TestUserService_GetUserByID(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register user first
	username := "getbyid"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "Get By ID User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
	}

	user, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Get by ID
	retrieved, err := service.GetUserByID(ctx, user.UUID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}

	if retrieved.UUID.String() != user.UUID.String() {
		t.Error("GetUserByID() returned wrong user")
	}
}

func TestUserService_ValidateToken(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register and login to get token
	username := "validatetoken"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "Validate Token User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
	}

	user, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	_, token, err := service.Login(ctx, username, password)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// Validate token
	userID, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if userID.String() != user.UUID.String() {
		t.Errorf("ValidateToken() returned wrong user ID, got %q, want %q", userID.String(), user.UUID.String())
	}
}

func TestUserService_ValidateToken_Invalid(t *testing.T) {
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	_, err := service.ValidateToken("invalid-token")
	if err == nil {
		t.Error("ValidateToken() with invalid token should return error")
	}
}

func TestUserService_ValidateToken_WrongSecret(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register and login to get token
	username := "wrongsecret"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "Wrong Secret User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
	}

	_, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	_, token, err := service.Login(ctx, username, password)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// Create service with different secret
	cfg2 := testConfig()
	cfg2.JWT.Secret = "different-secret"
	service2 := NewUserService(store, cfg2, logger)

	// Try to validate with wrong secret
	_, err = service2.ValidateToken(token)
	if err == nil {
		t.Error("ValidateToken() with wrong secret should return error")
	}
}

func TestUserService_GetPrivateData(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register user with private data
	username := "privatedata"
	password := "password123"
	privateData := []byte(`{"key": "value"}`)
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "Private Data User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
		PrivateData: privateData,
	}

	user, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Get private data
	data, etag, err := service.GetPrivateData(ctx, user.UUID)
	if err != nil {
		t.Fatalf("GetPrivateData() error = %v", err)
	}

	if string(data) != string(privateData) {
		t.Errorf("GetPrivateData() data = %s, want %s", data, privateData)
	}

	if etag == "" {
		t.Error("GetPrivateData() etag should not be empty")
	}
}

func TestUserService_UpdatePrivateData(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register user
	username := "updateprivate"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "Update Private User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
		PrivateData: []byte("initial"),
	}

	user, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Get initial ETag
	_, initialEtag, err := service.GetPrivateData(ctx, user.UUID)
	if err != nil {
		t.Fatalf("GetPrivateData() error = %v", err)
	}

	// Update private data
	newData := []byte("updated")
	newEtag, err := service.UpdatePrivateData(ctx, user.UUID, newData, initialEtag)
	if err != nil {
		t.Fatalf("UpdatePrivateData() error = %v", err)
	}

	if newEtag == initialEtag {
		t.Error("UpdatePrivateData() should return new ETag")
	}

	// Verify update
	data, _, err := service.GetPrivateData(ctx, user.UUID)
	if err != nil {
		t.Fatalf("GetPrivateData() error = %v", err)
	}

	if string(data) != "updated" {
		t.Errorf("GetPrivateData() after update = %s, want updated", data)
	}
}

func TestUserService_UpdatePrivateData_ETagConflict(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register user
	username := "etagconflict"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "ETag Conflict User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
		PrivateData: []byte("initial"),
	}

	user, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Try to update with wrong ETag
	_, err = service.UpdatePrivateData(ctx, user.UUID, []byte("new"), "wrong-etag")
	if err != ErrPrivateDataConflict {
		t.Errorf("UpdatePrivateData() with wrong ETag should return ErrPrivateDataConflict, got %v", err)
	}
}

func TestUserService_DeleteUser(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register user
	username := "deleteuser"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "Delete User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
	}

	user, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Delete user
	err = service.DeleteUser(ctx, user.UUID, user.DID)
	if err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}

	// Verify user is deleted
	_, err = service.GetUserByID(ctx, user.UUID)
	if err == nil {
		t.Error("GetUserByID() after deletion should return error")
	}
}

func TestUserService_GenerateTokenForUser(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register user
	username := "generatetoken"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "Generate Token User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
	}

	user, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Generate token directly
	token, err := service.GenerateTokenForUser(user)
	if err != nil {
		t.Fatalf("GenerateTokenForUser() error = %v", err)
	}

	if token == "" {
		t.Error("GenerateTokenForUser() returned empty token")
	}

	// Validate the token
	userID, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if userID.String() != user.UUID.String() {
		t.Errorf("ValidateToken() returned wrong user ID")
	}
}

func TestUserService_UpdateUser(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register user
	username := "updateuser"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "Original Name",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
	}

	user, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Update user
	newName := "Updated Name"
	user.DisplayName = &newName
	err = service.UpdateUser(ctx, user)
	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	// Verify update
	updated, err := service.GetUserByID(ctx, user.UUID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}

	if updated.DisplayName == nil || *updated.DisplayName != newName {
		t.Errorf("UpdateUser() DisplayName = %v, want %s", updated.DisplayName, newName)
	}
}

func TestUserService_DeleteWebAuthnCredential(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register user
	username := "webauthnuser"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "WebAuthn User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
	}

	user, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Add multiple WebAuthn credentials to the user
	user.WebauthnCredentials = []domain.WebauthnCredential{
		{ID: "cred1", PublicKey: []byte("key1")},
		{ID: "cred2", PublicKey: []byte("key2")},
	}
	if err := service.UpdateUser(ctx, user); err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	t.Run("deletes credential successfully", func(t *testing.T) {
		_, err := service.DeleteWebAuthnCredential(ctx, user.UUID, "cred1", []byte("{}"), "")
		if err != nil {
			t.Errorf("DeleteWebAuthnCredential() error = %v", err)
		}

		// Verify credential was deleted
		updated, _ := service.GetUserByID(ctx, user.UUID)
		if len(updated.WebauthnCredentials) != 1 {
			t.Errorf("Expected 1 credential, got %d", len(updated.WebauthnCredentials))
		}
	})

	t.Run("fails on last credential", func(t *testing.T) {
		_, err := service.DeleteWebAuthnCredential(ctx, user.UUID, "cred2", []byte("{}"), "")
		if err != ErrLastWebAuthnCredential {
			t.Errorf("Expected ErrLastWebAuthnCredential, got %v", err)
		}
	})

	t.Run("fails on non-existent credential", func(t *testing.T) {
		// Add another credential first
		u, _ := service.GetUserByID(ctx, user.UUID)
		u.WebauthnCredentials = append(u.WebauthnCredentials, domain.WebauthnCredential{
			ID: "cred3", PublicKey: []byte("key3"),
		})
		_ = service.UpdateUser(ctx, u)

		_, err := service.DeleteWebAuthnCredential(ctx, user.UUID, "nonexistent", []byte("{}"), "")
		if err == nil {
			t.Error("Expected error for non-existent credential")
		}
	})

	t.Run("fails on ETag mismatch", func(t *testing.T) {
		u, _ := service.GetUserByID(ctx, user.UUID)
		_, err := service.DeleteWebAuthnCredential(ctx, user.UUID, "cred2", []byte("{}"), "wrong-etag")
		if err != ErrPrivateDataConflict {
			t.Errorf("Expected ErrPrivateDataConflict, got %v", err)
		}
		_ = u
	})
}

func TestUserService_RenameWebAuthnCredential(t *testing.T) {
	ctx := t.Context()
	store := memory.NewStore()
	cfg := testConfig()
	logger := testLogger()
	service := NewUserService(store, cfg, logger)

	// Register user
	username := "renameuser"
	password := "password123"
	req := &domain.RegisterRequest{
		Username:    &username,
		DisplayName: "Rename User",
		Password:    &password,
		WalletType:  domain.WalletTypeDB,
	}

	user, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Add a WebAuthn credential
	user.WebauthnCredentials = []domain.WebauthnCredential{
		{ID: "cred1", PublicKey: []byte("key1")},
	}
	if err := service.UpdateUser(ctx, user); err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	t.Run("renames credential successfully", func(t *testing.T) {
		err := service.RenameWebAuthnCredential(ctx, user.UUID, "cred1", "My Key")
		if err != nil {
			t.Errorf("RenameWebAuthnCredential() error = %v", err)
		}

		// Verify rename
		updated, _ := service.GetUserByID(ctx, user.UUID)
		if updated.WebauthnCredentials[0].Nickname == nil || *updated.WebauthnCredentials[0].Nickname != "My Key" {
			t.Error("Nickname was not updated")
		}
	})

	t.Run("fails on non-existent credential", func(t *testing.T) {
		err := service.RenameWebAuthnCredential(ctx, user.UUID, "nonexistent", "Name")
		if err == nil {
			t.Error("Expected error for non-existent credential")
		}
	})

	t.Run("fails on non-existent user", func(t *testing.T) {
		err := service.RenameWebAuthnCredential(ctx, domain.NewUserID(), "cred1", "Name")
		if err == nil {
			t.Error("Expected error for non-existent user")
		}
	})
}
