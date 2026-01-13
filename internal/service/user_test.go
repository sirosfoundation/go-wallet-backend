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
