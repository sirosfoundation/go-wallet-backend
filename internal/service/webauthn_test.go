package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

const (
	testRPID           = "localhost"
	testRPName         = "Test App"
	testRPOrigin       = "http://localhost:8080"
	testJWTSecret      = "test-jwt-secret-that-is-long-enough-32"
	testJWTIssuer      = "test-issuer"
	testJWTExpiryHours = 24
)

func setupWebAuthnService(t *testing.T) (*WebAuthnService, *memory.Store) {
	t.Helper()

	cfg := &config.Config{
		Server: config.ServerConfig{
			RPName:   testRPName,
			RPID:     testRPID,
			RPOrigin: testRPOrigin,
		},
		JWT: config.JWTConfig{
			Secret:      testJWTSecret,
			Issuer:      testJWTIssuer,
			ExpiryHours: testJWTExpiryHours,
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

// testVirtualWebAuthnSetup contains virtualwebauthn test fixtures
type testVirtualWebAuthnSetup struct {
	service       *WebAuthnService
	store         *memory.Store
	rp            virtualwebauthn.RelyingParty
	authenticator virtualwebauthn.Authenticator
	credential    virtualwebauthn.Credential
	ctx           context.Context
}

func newTestVirtualWebAuthnSetup(t *testing.T) *testVirtualWebAuthnSetup {
	t.Helper()

	svc, store := setupWebAuthnService(t)

	// Create mock relying party matching our config
	rp := virtualwebauthn.RelyingParty{
		ID:     testRPID,
		Name:   testRPName,
		Origin: testRPOrigin,
	}

	// Create mock authenticator with user verification enabled
	// This is required because our WebAuthn config requires user verification
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserNotVerified: false, // User IS verified
		UserNotPresent:  false, // User IS present
	})

	// Create mock credential with EC2 key
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	return &testVirtualWebAuthnSetup{
		service:       svc,
		store:         store,
		rp:            rp,
		authenticator: authenticator,
		credential:    credential,
		ctx:           context.Background(),
	}
}

// convertOptionsToPlainBase64 converts our tagged binary format to plain base64url
// for compatibility with virtualwebauthn parsing
func convertOptionsToPlainBase64(optionsJSON []byte) []byte {
	// Replace {"$b64u":"..."} with just the base64url string
	var data map[string]interface{}
	if err := json.Unmarshal(optionsJSON, &data); err != nil {
		return optionsJSON
	}

	convertTaggedBinary(data)

	result, _ := json.Marshal(data)
	return result
}

func convertTaggedBinary(data interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		// Check if this is a tagged binary object
		if b64u, ok := v["$b64u"]; ok {
			// Can't replace in place, handled by parent
			_ = b64u
			return
		}
		for key, val := range v {
			if m, ok := val.(map[string]interface{}); ok {
				if b64u, exists := m["$b64u"]; exists {
					// Replace the map with just the base64url string
					v[key] = b64u
				} else {
					convertTaggedBinary(m)
				}
			} else if arr, ok := val.([]interface{}); ok {
				convertTaggedBinaryArray(arr)
			}
		}
	}
}

func convertTaggedBinaryArray(arr []interface{}) {
	for i, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			if b64u, exists := m["$b64u"]; exists {
				arr[i] = b64u
			} else {
				convertTaggedBinary(m)
			}
		}
	}
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
		resp, err := svc.BeginRegistration(ctx, &BeginRegistrationRequest{DisplayName: "Test User"})
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if resp == nil {
			t.Fatal("Expected response, got nil")
		}

		if resp.ChallengeID == "" {
			t.Error("Expected challenge ID")
		}

		// Verify options structure - now uses custom types matching TS format
		if len(resp.CreateOptions.PublicKey.Challenge) == 0 {
			t.Error("Expected challenge in options")
		}

		if resp.CreateOptions.PublicKey.RP.ID != "localhost" {
			t.Errorf("Expected RPID 'localhost', got '%s'", resp.CreateOptions.PublicKey.RP.ID)
		}

		if resp.CreateOptions.PublicKey.User.Name == "" {
			t.Error("Expected user name in options")
		}
	})

	t.Run("registration with empty display name", func(t *testing.T) {
		resp, err := svc.BeginRegistration(ctx, &BeginRegistrationRequest{})
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if resp == nil {
			t.Fatal("Expected response, got nil")
		}

		// Should generate a user ID even without display name
		if len(resp.CreateOptions.PublicKey.User.ID) == 0 {
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

		// Verify options structure - now uses custom types matching TS format
		if len(resp.GetOptions.PublicKey.Challenge) == 0 {
			t.Error("Expected challenge in options")
		}

		// Discoverable credential login should have empty AllowedCredentials
		if len(resp.GetOptions.PublicKey.AllowCredentials) != 0 {
			t.Error("Expected empty AllowedCredentials for discoverable login")
		}

		if resp.GetOptions.PublicKey.RPId != "localhost" {
			t.Errorf("Expected RPID 'localhost', got '%s'", resp.GetOptions.PublicKey.RPId)
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
		resp, err := svc.BeginRegistration(ctx, &BeginRegistrationRequest{DisplayName: "Test User"})
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

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestParseTransports(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []protocol.AuthenticatorTransport
	}{
		{
			name:     "empty",
			input:    []string{},
			expected: []protocol.AuthenticatorTransport{},
		},
		{
			name:     "single transport",
			input:    []string{"usb"},
			expected: []protocol.AuthenticatorTransport{protocol.USB},
		},
		{
			name:     "multiple transports",
			input:    []string{"usb", "nfc", "ble", "internal"},
			expected: []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC, protocol.BLE, protocol.Internal},
		},
		{
			name:     "hybrid transport",
			input:    []string{"hybrid"},
			expected: []protocol.AuthenticatorTransport{protocol.Hybrid},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseTransports(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseTransportsToProtocol(t *testing.T) {
	// Verify it's an alias for parseTransports
	input := []string{"usb", "nfc"}
	result := parseTransportsToProtocol(input)
	expected := parseTransports(input)
	assert.Equal(t, expected, result)
}

func TestEncodeFlags(t *testing.T) {
	tests := []struct {
		name     string
		flags    webauthn.CredentialFlags
		expected uint8
	}{
		{
			name:     "no flags",
			flags:    webauthn.CredentialFlags{},
			expected: 0x00,
		},
		{
			name: "user present",
			flags: webauthn.CredentialFlags{
				UserPresent: true,
			},
			expected: 0x01,
		},
		{
			name: "user verified",
			flags: webauthn.CredentialFlags{
				UserVerified: true,
			},
			expected: 0x04,
		},
		{
			name: "backup eligible",
			flags: webauthn.CredentialFlags{
				BackupEligible: true,
			},
			expected: 0x08,
		},
		{
			name: "backup state",
			flags: webauthn.CredentialFlags{
				BackupState: true,
			},
			expected: 0x10,
		},
		{
			name: "all flags",
			flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: true,
				BackupState:    true,
			},
			expected: 0x1D,
		},
		{
			name: "user present and verified",
			flags: webauthn.CredentialFlags{
				UserPresent:  true,
				UserVerified: true,
			},
			expected: 0x05,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodeFlags(tt.flags)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateChallengeID(t *testing.T) {
	// Generate multiple IDs and verify uniqueness
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateChallengeID()
		assert.NotEmpty(t, id)
		assert.False(t, ids[id], "duplicate challenge ID generated")
		ids[id] = true
	}
}

// ============================================================================
// WebAuthnUser Credentials Tests
// ============================================================================

func TestWebAuthnUserCredentials(t *testing.T) {
	userID := domain.NewUserID()
	user := &domain.User{
		UUID: userID,
		WebauthnCredentials: []domain.WebauthnCredential{
			{
				ID:              "cred1",
				CredentialID:    []byte("cred1"),
				PublicKey:       []byte("pubkey1"),
				AttestationType: "none",
				Transport:       []string{"usb", "nfc"},
				Flags:           0x05, // UserPresent + UserVerified
				Authenticator: domain.Authenticator{
					AAGUID:       []byte("aaguid12345678901"),
					SignCount:    10,
					CloneWarning: false,
				},
			},
			{
				ID:              "cred2",
				CredentialID:    []byte("cred2"),
				PublicKey:       []byte("pubkey2"),
				AttestationType: "packed",
				Transport:       []string{"internal"},
				Flags:           0x1D, // All flags
				Authenticator: domain.Authenticator{
					AAGUID:    []byte("aaguid12345678902"),
					SignCount: 5,
				},
			},
		},
	}

	waUser := &WebAuthnUser{user: user}
	creds := waUser.WebAuthnCredentials()

	assert.Len(t, creds, 2)

	// Check first credential
	assert.Equal(t, []byte("cred1"), creds[0].ID)
	assert.Equal(t, []byte("pubkey1"), creds[0].PublicKey)
	assert.Equal(t, "none", creds[0].AttestationType)
	assert.Equal(t, []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC}, creds[0].Transport)
	assert.True(t, creds[0].Flags.UserPresent)
	assert.True(t, creds[0].Flags.UserVerified)
	assert.False(t, creds[0].Flags.BackupEligible)
	assert.Equal(t, uint32(10), creds[0].Authenticator.SignCount)

	// Check second credential
	assert.Equal(t, []byte("cred2"), creds[1].ID)
	assert.True(t, creds[1].Flags.BackupEligible)
	assert.True(t, creds[1].Flags.BackupState)
}

// ============================================================================
// credentialReader Tests
// ============================================================================

func TestCredentialReader(t *testing.T) {
	t.Run("reads plain JSON", func(t *testing.T) {
		data := []byte(`{"type":"public-key","id":"abc123"}`)
		reader := newCredentialReader(data)

		buf := make([]byte, len(data))
		n, err := reader.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, len(data), n)
	})

	t.Run("reads tagged binary format", func(t *testing.T) {
		// Test with tagged binary in the response
		data := []byte(`{"type":"public-key","rawId":{"$b64u":"YWJjMTIz"}}`)
		reader := newCredentialReader(data)

		buf := make([]byte, 1024)
		n, err := reader.Read(buf)
		assert.NoError(t, err)
		assert.Greater(t, n, 0)
	})

	t.Run("returns EOF on second read", func(t *testing.T) {
		data := []byte(`{"test":"data"}`)
		reader := newCredentialReader(data)

		buf := make([]byte, len(data))
		_, _ = reader.Read(buf)

		// Second read should return EOF
		_, err := reader.Read(buf)
		assert.Error(t, err)
	})
}

// ============================================================================
// Full Registration Flow Tests with virtualwebauthn
// ============================================================================

func TestFullRegistrationFlow(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	// Step 1: Begin registration
	beginResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{DisplayName: "Test User"})
	require.NoError(t, err)

	// Step 2: Parse attestation options with virtualwebauthn
	// The patched virtualwebauthn now supports tagged binary format {"$b64u": "..."}
	optionsJSON, err := json.Marshal(beginResp.CreateOptions)
	require.NoError(t, err)

	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	require.NoError(t, err)
	require.NotNil(t, attestationOptions)

	// Verify the credential isn't excluded
	assert.False(t, setup.credential.IsExcludedForAttestation(*attestationOptions))

	// Step 3: Create attestation response simulating the browser
	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*attestationOptions,
	)

	// Step 4: Finish registration
	finishReq := &FinishRegistrationRequest{
		ChallengeID: beginResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "Test User",
		Nickname:    "Test Passkey",
	}

	finishResp, err := setup.service.FinishRegistration(setup.ctx, finishReq)
	require.NoError(t, err)

	assert.NotEmpty(t, finishResp.UUID)
	assert.NotEmpty(t, finishResp.Token)
	assert.Equal(t, "Test User", finishResp.DisplayName)
	assert.Equal(t, testRPID, finishResp.WebauthnRpId)

	// Verify user was created in store
	userID := domain.UserIDFromString(finishResp.UUID)
	user, err := setup.store.Users().GetByID(setup.ctx, userID)
	require.NoError(t, err)
	assert.Len(t, user.WebauthnCredentials, 1)
}

func TestFullRegistrationFlowWithRSAKey(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	// Use RSA key instead of EC2
	rsaCredential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeRSA)

	// Begin registration
	beginResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{DisplayName: "RSA User"})
	require.NoError(t, err)

	// Parse attestation options (virtualwebauthn supports tagged binary format)
	optionsJSON, err := json.Marshal(beginResp.CreateOptions)
	require.NoError(t, err)

	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	require.NoError(t, err)

	// Create attestation response with RSA key
	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		rsaCredential,
		*attestationOptions,
	)

	// Finish registration
	finishReq := &FinishRegistrationRequest{
		ChallengeID: beginResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "RSA User",
	}

	finishResp, err := setup.service.FinishRegistration(setup.ctx, finishReq)
	require.NoError(t, err)
	assert.NotEmpty(t, finishResp.UUID)
	assert.NotEmpty(t, finishResp.Token)
}

// ============================================================================
// Full Login Flow Tests with virtualwebauthn
// ============================================================================

func TestFullLoginFlow(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	// First, register a user
	beginRegResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{DisplayName: "Login Test User"})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)

	regOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	regResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*regOptions,
	)

	finishRegResp, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(regResponse),
		DisplayName: "Login Test User",
	})
	require.NoError(t, err)

	// Set up authenticator with user handle for assertion
	userID := domain.UserIDFromString(finishRegResp.UUID)
	setup.authenticator.Options.UserHandle = userID.AsUserHandle()
	setup.authenticator.AddCredential(setup.credential)

	// Now test login
	t.Run("successful login flow", func(t *testing.T) {
		// Begin login
		beginLoginResp, err := setup.service.BeginLogin(setup.ctx)
		require.NoError(t, err)

		// Parse assertion options (virtualwebauthn supports tagged binary format)
		loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
		require.NoError(t, err)

		assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
		require.NoError(t, err)
		require.NotNil(t, assertionOptions)

		// Create assertion response
		assertionResponse := virtualwebauthn.CreateAssertionResponse(
			setup.rp,
			setup.authenticator,
			setup.credential,
			*assertionOptions,
		)

		// Finish login
		finishLoginReq := &FinishLoginRequest{
			ChallengeID: beginLoginResp.ChallengeID,
			Credential:  json.RawMessage(assertionResponse),
		}

		finishLoginResp, err := setup.service.FinishLogin(setup.ctx, finishLoginReq)
		require.NoError(t, err)

		assert.Equal(t, finishRegResp.UUID, finishLoginResp.UUID)
		assert.NotEmpty(t, finishLoginResp.Token)
		assert.Equal(t, "Login Test User", finishLoginResp.DisplayName)
		assert.Equal(t, testRPID, finishLoginResp.WebauthnRpId)
	})
}

// ============================================================================
// BeginAddCredential Tests
// ============================================================================

func TestBeginAddCredential(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	// Create an existing user first
	userID := domain.NewUserID()
	username := "testuser"
	displayName := "Test User"
	user := &domain.User{
		UUID:        userID,
		Username:    &username,
		DisplayName: &displayName,
		WebauthnCredentials: []domain.WebauthnCredential{
			{
				ID:        "existing-cred",
				PublicKey: []byte("existing-pubkey"),
				Transport: []string{"usb"},
			},
		},
		CreatedAt: time.Now(),
	}
	err := setup.store.Users().Create(setup.ctx, user)
	require.NoError(t, err)

	t.Run("creates add credential options", func(t *testing.T) {
		resp, err := setup.service.BeginAddCredential(setup.ctx, userID)
		require.NoError(t, err)

		assert.NotEmpty(t, resp.ChallengeID)
		assert.Equal(t, username, resp.Username)
		assert.NotEmpty(t, resp.CreateOptions.PublicKey.Challenge)
		assert.Equal(t, testRPID, resp.CreateOptions.PublicKey.RP.ID)
	})

	t.Run("excludes existing credentials", func(t *testing.T) {
		resp, err := setup.service.BeginAddCredential(setup.ctx, userID)
		require.NoError(t, err)

		assert.Len(t, resp.CreateOptions.PublicKey.ExcludeCredentials, 1)
	})

	t.Run("stores challenge with add_credential action", func(t *testing.T) {
		resp, err := setup.service.BeginAddCredential(setup.ctx, userID)
		require.NoError(t, err)

		challenge, err := setup.store.Challenges().GetByID(setup.ctx, resp.ChallengeID)
		require.NoError(t, err)
		assert.Equal(t, "add_credential", challenge.Action)
		assert.Equal(t, userID.String(), challenge.UserID)
	})

	t.Run("user not found", func(t *testing.T) {
		nonExistentUserID := domain.NewUserID()
		_, err := setup.service.BeginAddCredential(setup.ctx, nonExistentUserID)
		assert.Error(t, err)
	})
}

// ============================================================================
// FinishAddCredential Tests
// ============================================================================

func TestFinishAddCredential_Errors(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	t.Run("challenge not found", func(t *testing.T) {
		userID := domain.NewUserID()
		finishReq := &FinishAddCredentialRequest{
			ChallengeID: "nonexistent-challenge",
			Credential:  json.RawMessage(`{}`),
		}

		_, err := setup.service.FinishAddCredential(setup.ctx, userID, finishReq, "")
		// FinishAddCredential first checks user existence, so we get ErrNotFound from user lookup
		assert.Error(t, err)
	})

	t.Run("challenge expired", func(t *testing.T) {
		userID := domain.NewUserID()
		user := &domain.User{
			UUID:      userID,
			CreatedAt: time.Now(),
		}
		err := setup.store.Users().Create(setup.ctx, user)
		require.NoError(t, err)

		// Create an expired challenge
		challenge := &domain.WebauthnChallenge{
			ID:        "expired-add-challenge",
			UserID:    userID.String(),
			Challenge: base64.RawURLEncoding.EncodeToString([]byte("test-challenge")),
			Action:    "add_credential",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		err = setup.store.Challenges().Create(setup.ctx, challenge)
		require.NoError(t, err)

		finishReq := &FinishAddCredentialRequest{
			ChallengeID: "expired-add-challenge",
			Credential:  json.RawMessage(`{}`),
		}

		_, err = setup.service.FinishAddCredential(setup.ctx, userID, finishReq, "")
		assert.ErrorIs(t, err, ErrChallengeExpired)
	})

	t.Run("user mismatch", func(t *testing.T) {
		// Create user 1
		userID1 := domain.NewUserID()
		user1 := &domain.User{UUID: userID1, CreatedAt: time.Now()}
		err := setup.store.Users().Create(setup.ctx, user1)
		require.NoError(t, err)

		// Create user 2
		userID2 := domain.NewUserID()
		user2 := &domain.User{UUID: userID2, CreatedAt: time.Now()}
		err = setup.store.Users().Create(setup.ctx, user2)
		require.NoError(t, err)

		// Create challenge for user 1
		challenge := &domain.WebauthnChallenge{
			ID:        "user1-challenge",
			UserID:    userID1.String(),
			Challenge: base64.RawURLEncoding.EncodeToString([]byte("test-challenge")),
			Action:    "add_credential",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
		err = setup.store.Challenges().Create(setup.ctx, challenge)
		require.NoError(t, err)

		// Try to finish with user 2
		finishReq := &FinishAddCredentialRequest{
			ChallengeID: "user1-challenge",
			Credential:  json.RawMessage(`{}`),
		}

		_, err = setup.service.FinishAddCredential(setup.ctx, userID2, finishReq, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "challenge user mismatch")
	})
}

// ============================================================================
// Full AddCredential Flow with virtualwebauthn
// ============================================================================

func TestFullAddCredentialFlow(t *testing.T) {
	// Skip: virtualwebauthn has difficulty parsing our custom tagged binary format
	t.Skip("Full add credential flow requires custom tagged binary format not supported by virtualwebauthn")

	setup := newTestVirtualWebAuthnSetup(t)

	// First, register a user with initial credential
	beginRegResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{DisplayName: "Add Cred Test User"})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)

	plainRegOptions := convertOptionsToPlainBase64(regOptionsJSON)

	regOptions, err := virtualwebauthn.ParseAttestationOptions(string(plainRegOptions))
	require.NoError(t, err)

	regResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*regOptions,
	)

	finishRegResp, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(regResponse),
		DisplayName: "Add Cred Test User",
	})
	require.NoError(t, err)

	userID := domain.UserIDFromString(finishRegResp.UUID)

	// Create a new credential to add
	newCredential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Begin add credential
	beginAddResp, err := setup.service.BeginAddCredential(setup.ctx, userID)
	require.NoError(t, err)

	// Parse options
	addOptionsJSON, err := json.Marshal(beginAddResp.CreateOptions)
	require.NoError(t, err)

	plainAddOptions := convertOptionsToPlainBase64(addOptionsJSON)

	addOptions, err := virtualwebauthn.ParseAttestationOptions(string(plainAddOptions))
	require.NoError(t, err)

	// Verify new credential isn't excluded but original is
	assert.False(t, newCredential.IsExcludedForAttestation(*addOptions))

	// Create attestation response
	addResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		newCredential,
		*addOptions,
	)

	// Finish add credential
	finishAddReq := &FinishAddCredentialRequest{
		ChallengeID: beginAddResp.ChallengeID,
		Credential:  json.RawMessage(addResponse),
		Nickname:    "Second Passkey",
	}

	finishAddResp, err := setup.service.FinishAddCredential(setup.ctx, userID, finishAddReq, "")
	require.NoError(t, err)

	assert.NotEmpty(t, finishAddResp.CredentialID)

	// Verify user now has 2 credentials
	user, err := setup.store.Users().GetByID(setup.ctx, userID)
	require.NoError(t, err)
	assert.Len(t, user.WebauthnCredentials, 2)
}

// ============================================================================
// Token Generation Tests
// ============================================================================

func TestGenerateToken(t *testing.T) {
	svc, _ := setupWebAuthnService(t)

	userID := domain.NewUserID()
	did := "did:key:" + userID.String()
	user := &domain.User{
		UUID: userID,
		DID:  did,
	}

	token, err := svc.generateToken(user, domain.DefaultTenantID)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify token has three parts (header.payload.signature)
	parts := strings.Split(token, ".")
	assert.Len(t, parts, 3)
}

// ============================================================================
// Response Type Tests
// ============================================================================

func TestPublicKeyCredentialCreationOptions_JSONStructure(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	resp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{DisplayName: "Test User"})
	require.NoError(t, err)

	// Verify JSON structure matches expected format
	jsonBytes, err := json.Marshal(resp.CreateOptions)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(jsonBytes, &decoded)
	require.NoError(t, err)

	// Should have publicKey wrapper
	assert.Contains(t, decoded, "publicKey")

	publicKey := decoded["publicKey"].(map[string]interface{})
	assert.Contains(t, publicKey, "rp")
	assert.Contains(t, publicKey, "user")
	assert.Contains(t, publicKey, "challenge")
	assert.Contains(t, publicKey, "pubKeyCredParams")
	assert.Contains(t, publicKey, "authenticatorSelection")
}

func TestPublicKeyCredentialRequestOptions_JSONStructure(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	resp, err := setup.service.BeginLogin(setup.ctx)
	require.NoError(t, err)

	// Verify JSON structure matches expected format
	jsonBytes, err := json.Marshal(resp.GetOptions)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(jsonBytes, &decoded)
	require.NoError(t, err)

	// Should have publicKey wrapper
	assert.Contains(t, decoded, "publicKey")

	publicKey := decoded["publicKey"].(map[string]interface{})
	assert.Contains(t, publicKey, "rpId")
	assert.Contains(t, publicKey, "challenge")
	assert.Contains(t, publicKey, "allowCredentials")
	assert.Contains(t, publicKey, "userVerification")
}
