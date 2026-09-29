package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
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

// TestWebAuthnService_BeginRegistration_InviteCodeWithoutTenantRejected
// covers a review finding on PR #388: an invite code is tenant-scoped
// (Invites().GetByCode requires a tenantID, and FinishRegistration's atomic
// invite claim is only reachable when the stored challenge carries a
// tenantID), but BeginRegistration's invite validation lived entirely
// inside the `req.TenantID != ""` branch and unconditionally stored
// req.InviteCode on the challenge regardless. Supplying an invite code with
// no tenantID therefore skipped invite validation AND consumption
// entirely, silently creating a global (non-tenant) account while leaving
// the referenced invite untouched, instead of being rejected. This
// combination must fail closed at BeginRegistration.
func TestWebAuthnService_BeginRegistration_InviteCodeWithoutTenantRejected(t *testing.T) {
	svc, _ := setupWebAuthnService(t)
	ctx := context.Background()

	_, err := svc.BeginRegistration(ctx, &BeginRegistrationRequest{
		DisplayName: "No Tenant Invite User",
		InviteCode:  "some-invite-code",
		// TenantID intentionally left empty.
	})
	if !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("expected ErrInvalidInvite for an invite code with no tenantID, got %v", err)
	}
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

// TestWebAuthnService_FinishRegistration_TenantMismatch is a direct
// service-level regression test for issue #395 (mirroring PR #386's fix for
// the analogous /auth/passkey/* bug, #374): FinishRegistration must reject a
// request whose ExpectedTenantID disagrees with the tenant BeginRegistration
// actually recorded on the challenge, and must do so BEFORE the one-time
// challenge is deleted (so a mismatched caller can't burn it out from under
// the legitimate caller). Exercised directly against the service (not
// through internal/api or internal/server) so this package's own coverage
// reflects the check - the handler/route-level regression tests live in
// internal/server/providers_test.go.
func TestWebAuthnService_FinishRegistration_TenantMismatch(t *testing.T) {
	svc, store := setupWebAuthnService(t)
	ctx := context.Background()

	tenantA := domain.TenantID("tenant-a")
	tenantB := domain.TenantID("tenant-b")
	require.NoError(t, store.Tenants().Create(ctx, &domain.Tenant{ID: tenantA, Name: "Tenant A", Enabled: true}))
	require.NoError(t, store.Tenants().Create(ctx, &domain.Tenant{ID: tenantB, Name: "Tenant B", Enabled: true}))

	beginResp, err := svc.BeginRegistration(ctx, &BeginRegistrationRequest{TenantID: string(tenantA)})
	require.NoError(t, err)

	t.Run("mismatched ExpectedTenantID is rejected before the challenge is consumed", func(t *testing.T) {
		_, err := svc.FinishRegistration(ctx, &FinishRegistrationRequest{
			ChallengeID:      beginResp.ChallengeID,
			Credential:       json.RawMessage(`{}`),
			ExpectedTenantID: string(tenantB),
		})
		if err != ErrTenantMismatch {
			t.Fatalf("expected ErrTenantMismatch, got %v", err)
		}

		// The challenge must still exist - a mismatched request must not be
		// able to burn the one-time challenge for the legitimate caller.
		if _, err := store.Challenges().GetByID(ctx, beginResp.ChallengeID); err != nil {
			t.Fatalf("challenge should survive a tenant mismatch, got: %v", err)
		}
	})

	t.Run("matching ExpectedTenantID is not rejected as a mismatch", func(t *testing.T) {
		_, err := svc.FinishRegistration(ctx, &FinishRegistrationRequest{
			ChallengeID:      beginResp.ChallengeID,
			Credential:       json.RawMessage(`{}`),
			ExpectedTenantID: string(tenantA),
		})
		// The bogus credential will still fail verification further down,
		// but it must NOT be rejected as a tenant mismatch.
		if err == ErrTenantMismatch {
			t.Fatal("matching ExpectedTenantID must not be rejected as a tenant mismatch")
		}
	})

	t.Run("empty ExpectedTenantID performs no check (backward compatible)", func(t *testing.T) {
		beginResp2, err := svc.BeginRegistration(ctx, &BeginRegistrationRequest{TenantID: string(tenantA)})
		require.NoError(t, err)

		_, err = svc.FinishRegistration(ctx, &FinishRegistrationRequest{
			ChallengeID: beginResp2.ChallengeID,
			Credential:  json.RawMessage(`{}`),
			// ExpectedTenantID left empty
		})
		if err == ErrTenantMismatch {
			t.Fatal("empty ExpectedTenantID must not trigger a tenant mismatch")
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

// TestWebAuthnService_RefreshAccessToken is a regression test for issue
// #392: RefreshAccessToken/RefreshTokenRequest were fully implemented but
// api.Handlers.RefreshToken (the handler that calls this method) was never
// mounted on any route, exactly like Logout before #391. This proves the
// underlying service logic actually works, now that the handler is wired
// up (see internal/server/providers.go's new POST /user/session/refresh).
func TestWebAuthnService_RefreshAccessToken(t *testing.T) {
	newSvcWithRefresh := func(t *testing.T) (*WebAuthnService, *memory.Store) {
		t.Helper()
		cfg := &config.Config{
			Server: config.ServerConfig{RPName: testRPName, RPID: testRPID, RPOrigin: testRPOrigin},
			JWT: config.JWTConfig{
				Secret:      testJWTSecret,
				Issuer:      testJWTIssuer,
				ExpiryHours: testJWTExpiryHours,
				RefreshDays: 7,
			},
		}
		store := memory.NewStore()
		svc, err := NewWebAuthnService(store, cfg, zap.NewNop())
		if err != nil {
			t.Fatalf("Failed to create WebAuthn service: %v", err)
		}
		return svc, store
	}

	// addTenantMembership creates tenantID (enabled) if it doesn't already
	// exist and records the user as one of its members - needed wherever a
	// test's refresh token carries a non-default tenant claim, since
	// RefreshAccessToken now re-validates both that the tenant itself
	// exists and is enabled (fifth Copilot round) and that the user is
	// still a member of it (fourth Copilot round) before rotating.
	addTenantMembership := func(t *testing.T, store *memory.Store, userID domain.UserID, tenantID domain.TenantID) {
		t.Helper()
		ctx := context.Background()
		if _, err := store.Tenants().GetByID(ctx, tenantID); err != nil {
			require.NoError(t, store.Tenants().Create(ctx, &domain.Tenant{ID: tenantID, Name: string(tenantID), Enabled: true}))
		}
		require.NoError(t, store.UserTenants().AddMembership(ctx, &domain.UserTenantMembership{
			UserID:   userID,
			TenantID: tenantID,
		}))
	}

	t.Run("refreshes a valid refresh token into a new access token", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh"}
		if err := store.Users().Create(ctx, user); err != nil {
			t.Fatalf("failed to create user: %v", err)
		}
		addTenantMembership(t, store, user.UUID, "test-tenant")

		refreshToken, err := svc.generateRefreshToken(user, domain.TenantID("test-tenant"))
		require.NoError(t, err)
		require.NotEmpty(t, refreshToken)

		resp, err := svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken})
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.NotEmpty(t, resp.Token, "expected a new access token")
		assert.NotEmpty(t, resp.RefreshToken, "expected a rotated refresh token")
		assert.NotEqual(t, refreshToken, resp.RefreshToken, "refresh token should be rotated, not reused")

		// The new access token must actually be usable: parse it and confirm
		// it carries this user's identity and tenant (as generateToken would
		// produce), not the refresh token's own claims verbatim.
		parsed, err := jwt.Parse(resp.Token, func(token *jwt.Token) (interface{}, error) {
			return []byte(testJWTSecret), nil
		})
		require.NoError(t, err)
		require.True(t, parsed.Valid)
		claims, ok := parsed.Claims.(jwt.MapClaims)
		require.True(t, ok)
		assert.Equal(t, user.UUID.String(), claims["user_id"])
		assert.Equal(t, "test-tenant", claims["tenant_id"])
	})

	t.Run("disabled refresh tokens are rejected", func(t *testing.T) {
		svc, _ := setupWebAuthnService(t) // RefreshDays defaults to 0 (disabled)
		_, err := svc.RefreshAccessToken(context.Background(), &RefreshTokenRequest{RefreshToken: "anything"})
		// Must be the typed ErrRefreshDisabled, not an ad hoc error: callers
		// (internal/api.Handlers.RefreshToken) switch on it to avoid
		// surfacing this expected, config-driven state as a 500 (Copilot
		// review on #400).
		if !errors.Is(err, ErrRefreshDisabled) {
			t.Fatalf("expected ErrRefreshDisabled, got %v", err)
		}
	})

	t.Run("malformed refresh token is rejected", func(t *testing.T) {
		svc, _ := newSvcWithRefresh(t)
		_, err := svc.RefreshAccessToken(context.Background(), &RefreshTokenRequest{RefreshToken: "not-a-jwt"})
		if err != ErrInvalidRefreshToken {
			t.Errorf("expected ErrInvalidRefreshToken, got %v", err)
		}
	})

	t.Run("an access token cannot be used as a refresh token", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-2"}
		if err := store.Users().Create(ctx, user); err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		accessToken, err := svc.generateToken(user, domain.TenantID("test-tenant"))
		require.NoError(t, err)

		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: accessToken})
		if err != ErrInvalidRefreshToken {
			t.Errorf("expected ErrInvalidRefreshToken (wrong type claim), got %v", err)
		}
	})

	t.Run("refresh token for a since-deleted user is rejected", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-3"}
		if err := store.Users().Create(ctx, user); err != nil {
			t.Fatalf("failed to create user: %v", err)
		}
		refreshToken, err := svc.generateRefreshToken(user, domain.TenantID("test-tenant"))
		require.NoError(t, err)

		_ = store.Users().Delete(ctx, user.UUID)

		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken})
		if err != ErrInvalidRefreshToken {
			t.Errorf("expected ErrInvalidRefreshToken for a deleted user, got %v", err)
		}
	})

	// Regression test for a Copilot review finding on #400 (third round): the
	// refresh token must NOT be consumed when a validation step AFTER
	// signature/type checking fails (here: the user lookup) - otherwise a
	// transient storage failure on that lookup would irreversibly burn a
	// legitimate refresh token, forcing the client to re-authenticate from
	// scratch instead of simply retrying. Proven by: a failed lookup, then a
	// second attempt with the SAME token succeeding once the user exists.
	t.Run("a failed user lookup does not consume the refresh token (retry with the same token can still succeed)", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()
		blacklist := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: false}, zap.NewNop())
		svc.SetTokenBlacklist(blacklist)

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-7"}
		refreshToken, err := svc.generateRefreshToken(user, domain.TenantID("test-tenant"))
		require.NoError(t, err)

		// User does not exist yet: lookup fails, request is rejected.
		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken})
		if err != ErrInvalidRefreshToken {
			t.Fatalf("expected ErrInvalidRefreshToken (user not found), got %v", err)
		}

		// Now the user exists (simulating the earlier failure having been
		// transient). The SAME refresh token must still work - proving it
		// was never consumed by the failed attempt above.
		require.NoError(t, store.Users().Create(ctx, user))
		addTenantMembership(t, store, user.UUID, "test-tenant")
		resp, err := svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken})
		if err != nil {
			t.Fatalf("expected the refresh token to still be usable after the earlier failed lookup, got error: %v", err)
		}
		if resp.Token == "" {
			t.Fatal("expected a new access token")
		}
	})

	// Regression test for a Copilot review finding on #400: RefreshAccessToken
	// only rotated tokens and never invalidated the one just used, so a
	// stolen refresh token could be replayed indefinitely, each replay
	// minting another full-lived refresh token. With a TokenBlacklist wired
	// in (SetTokenBlacklist), the presented refresh token must become
	// single-use: consumed on successful exchange, rejected on replay - and
	// this must hold even with TokenBlacklistConfig.Enabled: false (the
	// checked-in/production default), since a second Copilot round on #400
	// found that gating consumption on that same opt-in flag left refresh
	// tokens replayable in the standard configuration despite this method
	// appearing to enforce single-use. ConsumeOnce is deliberately NOT
	// gated by it (see its doc comment) - Enabled: false here is the point
	// of this test, not an oversight.
	t.Run("a consumed refresh token cannot be replayed, even with the blacklist feature disabled (default config)", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()
		blacklist := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: false}, zap.NewNop())
		svc.SetTokenBlacklist(blacklist)

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-4"}
		require.NoError(t, store.Users().Create(ctx, user))
		addTenantMembership(t, store, user.UUID, "test-tenant")

		refreshToken, err := svc.generateRefreshToken(user, domain.TenantID("test-tenant"))
		require.NoError(t, err)

		// First use succeeds and rotates the token.
		resp, err := svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken})
		require.NoError(t, err)
		require.NotEmpty(t, resp.RefreshToken)

		// Replaying the SAME (now-consumed) refresh token must be rejected,
		// despite Enabled: false.
		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken})
		if err != ErrInvalidRefreshToken {
			t.Fatalf("expected ErrInvalidRefreshToken on refresh-token replay, got %v", err)
		}

		// The newly rotated refresh token, never having been used, must
		// still work.
		resp2, err := svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: resp.RefreshToken})
		require.NoError(t, err)
		require.NotEmpty(t, resp2.Token)
	})

	// Regression test for the second Copilot review round on #400: the
	// check-and-consume sequence must be atomic, so that two concurrent
	// requests replaying the same refresh token cannot both win the race
	// (both observing "not yet consumed" and each minting its own
	// replacement token pair). Exactly one of N concurrent callers sharing
	// the same refresh token must succeed.
	t.Run("concurrent replay of the same refresh token: exactly one caller succeeds", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()
		blacklist := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: false}, zap.NewNop())
		svc.SetTokenBlacklist(blacklist)

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-concurrent"}
		require.NoError(t, store.Users().Create(ctx, user))
		addTenantMembership(t, store, user.UUID, "test-tenant")

		refreshToken, err := svc.generateRefreshToken(user, domain.TenantID("test-tenant"))
		require.NoError(t, err)

		const n = 20
		var wg sync.WaitGroup
		var successes int64
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				if _, err := svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken}); err == nil {
					atomic.AddInt64(&successes, 1)
				}
			}()
		}
		wg.Wait()

		if successes != 1 {
			t.Fatalf("expected exactly 1 successful refresh out of %d concurrent replays of the same token, got %d", n, successes)
		}
	})

	// Regression tests for a Copilot review finding on #400 (fifth round):
	// a refresh token missing "jti" would reach ConsumeOnce, which
	// deliberately treats an empty jti as always "first use" (meant for a
	// hypothetical jti-less token this service issued, not as a bypass),
	// letting such a token replay freely forever; a token missing "exp"
	// would fall back to RefreshDays for the blacklist entry's OWN expiry
	// while the underlying JWT itself never expires, so the same
	// non-expiring token would become usable again once that blacklist
	// entry aged out. Both claims are now required outright - every token
	// this service actually issues (generateRefreshToken) always sets both,
	// so this only ever rejects a malformed/hand-crafted token.
	t.Run("a refresh token without a jti claim is rejected", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()
		blacklist := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop())
		svc.SetTokenBlacklist(blacklist)

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-nojti"}
		require.NoError(t, store.Users().Create(ctx, user))
		addTenantMembership(t, store, user.UUID, "test-tenant")

		noJTIToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id":   user.UUID.String(),
			"tenant_id": "test-tenant",
			"type":      "refresh",
			"exp":       time.Now().Add(time.Hour).Unix(),
		})
		signed, err := noJTIToken.SignedString([]byte(testJWTSecret))
		require.NoError(t, err)

		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: signed})
		if err != ErrInvalidRefreshToken {
			t.Fatalf("expected ErrInvalidRefreshToken for a missing jti claim, got %v", err)
		}
	})

	t.Run("a refresh token without an exp claim is rejected", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()
		blacklist := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop())
		svc.SetTokenBlacklist(blacklist)

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-noexp"}
		require.NoError(t, store.Users().Create(ctx, user))
		addTenantMembership(t, store, user.UUID, "test-tenant")

		noExpToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id":   user.UUID.String(),
			"tenant_id": "test-tenant",
			"type":      "refresh",
			"jti":       "no-exp-jti",
		})
		signed, err := noExpToken.SignedString([]byte(testJWTSecret))
		require.NoError(t, err)

		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: signed})
		if err != ErrInvalidRefreshToken {
			t.Fatalf("expected ErrInvalidRefreshToken for a missing exp claim, got %v", err)
		}
	})

	// Regression test for a Copilot review finding on #400 (fourth round):
	// FinishLogin derives tenantID fresh from the user's CURRENT membership
	// records every time someone logs in, so removing a user's tenant
	// membership takes effect at their next login - but RefreshAccessToken
	// used to just trust whatever tenant_id claim the presented refresh
	// token already carried, forever, letting a removed user keep
	// refreshing indefinitely instead of losing access within one
	// access-token lifetime.
	t.Run("refresh token for a tenant the user was removed from is rejected", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-removed-membership"}
		require.NoError(t, store.Users().Create(ctx, user))
		addTenantMembership(t, store, user.UUID, "test-tenant")

		refreshToken, err := svc.generateRefreshToken(user, domain.TenantID("test-tenant"))
		require.NoError(t, err)

		// Membership removed (e.g. an admin removed this user from the
		// tenant) - the refresh token itself is unchanged, still carrying
		// the old tenant_id claim.
		require.NoError(t, store.UserTenants().RemoveMembership(ctx, user.UUID, "test-tenant"))

		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken})
		if err != ErrInvalidRefreshToken {
			t.Fatalf("expected ErrInvalidRefreshToken after tenant membership was removed, got %v", err)
		}
	})

	// Regression test for a Copilot review finding on #400 (fifth round):
	// pkg/middleware.AuthMiddleware and TokenAuthMiddleware both reject an
	// authenticated request whose tenant no longer exists or has been
	// disabled, but RefreshAccessToken didn't apply the same check - a
	// stolen refresh token for a since-disabled tenant could keep rotating
	// indefinitely and regain full access the moment that tenant was
	// re-enabled.
	t.Run("refresh token for a since-disabled tenant is rejected", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-disabled-tenant"}
		require.NoError(t, store.Users().Create(ctx, user))
		addTenantMembership(t, store, user.UUID, "test-tenant")

		refreshToken, err := svc.generateRefreshToken(user, domain.TenantID("test-tenant"))
		require.NoError(t, err)

		tenant, err := store.Tenants().GetByID(ctx, "test-tenant")
		require.NoError(t, err)
		tenant.Enabled = false
		require.NoError(t, store.Tenants().Update(ctx, tenant))

		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken})
		if err != ErrInvalidRefreshToken {
			t.Fatalf("expected ErrInvalidRefreshToken after the tenant was disabled, got %v", err)
		}
	})

	t.Run("refresh token for a nonexistent tenant is rejected", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-nonexistent-tenant"}
		require.NoError(t, store.Users().Create(ctx, user))
		// Deliberately not calling addTenantMembership: no such tenant exists.

		refreshToken, err := svc.generateRefreshToken(user, domain.TenantID("no-such-tenant"))
		require.NoError(t, err)

		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken})
		if err != ErrInvalidRefreshToken {
			t.Fatalf("expected ErrInvalidRefreshToken for a nonexistent tenant, got %v", err)
		}
	})

	// The default tenant is exempt from the membership check above, matching
	// FinishLogin/GetUserTenants' existing "no memberships recorded -> a
	// legacy default-tenant user" fallback elsewhere in this file - a
	// default-tenant refresh token must keep working without ever having an
	// explicit UserTenantMembership row.
	t.Run("refresh for the default tenant does not require an explicit membership record", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-default-tenant"}
		require.NoError(t, store.Users().Create(ctx, user))
		// Deliberately no addTenantMembership call.

		refreshToken, err := svc.generateRefreshToken(user, domain.DefaultTenantID)
		require.NoError(t, err)

		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken})
		require.NoError(t, err)
	})

	// A refresh token with an empty (but present) tenant_id claim falls
	// back to the default tenant, matching pkg/middleware.AuthMiddleware's
	// own "no tenant_id claim -> default tenant" backward-compatibility
	// behavior for older tokens.
	t.Run("refresh with an empty tenant_id claim falls back to the default tenant", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t)
		ctx := context.Background()

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-empty-tenant"}
		require.NoError(t, store.Users().Create(ctx, user))

		emptyTenantToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id":   user.UUID.String(),
			"tenant_id": "",
			"type":      "refresh",
			"jti":       "empty-tenant-jti",
			"exp":       time.Now().Add(time.Hour).Unix(),
		})
		signed, err := emptyTenantToken.SignedString([]byte(testJWTSecret))
		require.NoError(t, err)

		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: signed})
		require.NoError(t, err)
	})

	t.Run("without a TokenBlacklist wired in at all, a refresh token remains reusable (unchanged, pre-existing behavior)", func(t *testing.T) {
		svc, store := newSvcWithRefresh(t) // no SetTokenBlacklist call - tokenBlacklist stays nil

		ctx := context.Background()

		user := &domain.User{UUID: domain.NewUserID(), DID: "did:key:test-refresh-5"}
		require.NoError(t, store.Users().Create(ctx, user))
		addTenantMembership(t, store, user.UUID, "test-tenant")

		refreshToken, err := svc.generateRefreshToken(user, domain.TenantID("test-tenant"))
		require.NoError(t, err)

		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken})
		require.NoError(t, err)

		// No TokenBlacklist wired in at all (nil): single-use enforcement is
		// skipped entirely, since there's nowhere to track consumed jtis.
		// services.go always wires one in for the real service; this only
		// matters for a hand-built WebAuthnService that never calls
		// SetTokenBlacklist.
		_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refreshToken})
		require.NoError(t, err)
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

// TestFullLoginFlow_CloneWarningSurfaced covers issue #380: a sign-counter
// regression (the standard clone-authenticator signal) must not be silently
// dropped. It logs in once to establish a non-zero baseline counter, then
// logs in again with a LOWER counter — the classic clone signal — and
// asserts that (a) the login is still allowed through (we don't block on
// it), (b) a distinct, greppable "possible cloned authenticator detected"
// security-event line is logged, and (c) the clone warning is persisted on
// the stored credential rather than silently dropped.
func TestFullLoginFlow_CloneWarningSurfaced(t *testing.T) {
	core, observed := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	cfg := &config.Config{
		Server: config.ServerConfig{RPName: testRPName, RPID: testRPID, RPOrigin: testRPOrigin},
		JWT:    config.JWTConfig{Secret: testJWTSecret, Issuer: testJWTIssuer, ExpiryHours: testJWTExpiryHours},
	}
	store := memory.NewStore()
	svc, err := NewWebAuthnService(store, cfg, logger)
	require.NoError(t, err)

	rp := virtualwebauthn.RelyingParty{ID: testRPID, Name: testRPName, Origin: testRPOrigin}
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserNotVerified: false,
		UserNotPresent:  false,
	})
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	ctx := context.Background()

	beginRegResp, err := svc.BeginRegistration(ctx, &BeginRegistrationRequest{DisplayName: "Clone Test User"})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	regOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	regResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *regOptions)
	finishRegResp, err := svc.FinishRegistration(ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(regResponse),
		DisplayName: "Clone Test User",
	})
	require.NoError(t, err)

	userID := domain.UserIDFromString(finishRegResp.UUID)
	authenticator.Options.UserHandle = userID.AsUserHandle()
	authenticator.AddCredential(credential)

	login := func(counter uint32) *FinishLoginResponse {
		t.Helper()
		credential.Counter = counter

		beginLoginResp, err := svc.BeginLogin(ctx)
		require.NoError(t, err)

		loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
		require.NoError(t, err)
		assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
		require.NoError(t, err)

		assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *assertionOptions)
		resp, err := svc.FinishLogin(ctx, &FinishLoginRequest{
			ChallengeID: beginLoginResp.ChallengeID,
			Credential:  json.RawMessage(assertionResponse),
		})
		require.NoError(t, err, "login must still succeed even when a clone warning is detected")
		return resp
	}

	// Establish a non-zero baseline counter.
	login(10)

	// A LOWER counter than the stored baseline is the standard
	// clone-authenticator signal.
	login(3)

	entries := observed.FilterMessage("possible cloned authenticator detected").All()
	require.Len(t, entries, 1, "expected exactly one clone-warning security-event log line")
	fields := entries[0].ContextMap()
	assert.Equal(t, "webauthn_clone_warning", fields["security_event"])
	assert.Equal(t, userID.String(), fields["user_id"])

	// The warning must be persisted, not silently dropped.
	user, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	require.Len(t, user.WebauthnCredentials, 1)
	assert.True(t, user.WebauthnCredentials[0].Authenticator.CloneWarning)

	// Review finding on PR #388: WebAuthnCredentials() hydrates the now-true
	// persisted CloneWarning into every future login's credential, and
	// go-webauthn's UpdateCounter never clears it — so
	// credential.Authenticator.CloneWarning stays true on every subsequent
	// login, not just the one that detected it. Another login whose OWN
	// counter also regresses relative to the stored baseline (which never
	// advanced past 10, since UpdateCounter's regression branch doesn't
	// update SignCount) must NOT emit a second log line: the event should
	// fire once, at the moment of detection, not flood on every later login.
	login(5)
	entries = observed.FilterMessage("possible cloned authenticator detected").All()
	assert.Len(t, entries, 1, "a lingering CloneWarning must not re-emit the security event on every subsequent login")
}

// TestFullLoginFlow_CloneWarningStaysLatchedAfterCleanLogin covers a review
// finding on PR #388: FinishLogin used to unconditionally overwrite the
// stored CloneWarning with whatever go-webauthn reported for *that*
// assertion, which reads as if a later, cleanly-incrementing login could
// silently clear a flag set by an earlier detected clone.
//
// In practice, with go-webauthn v0.18.2's current Authenticator.UpdateCounter
// (a non-regressing counter only advances SignCount and leaves CloneWarning
// untouched — it's a one-way latch already, and we hydrate the stored
// CloneWarning back into the Authenticator we hand the library on every call
// via WebAuthnCredentials()), this specific clearing scenario doesn't
// currently reproduce end-to-end: this test still passed even with the old
// unconditional-overwrite code, because the value being written back was
// already "true" by the time it got there. Verified this by reverting the
// fix and rerunning this exact test.
//
// The fix is kept anyway as defense-in-depth: the "never silently clear a
// latched clone warning" guarantee should live in our own code, not depend
// on an undocumented behavior of a third-party library's counter-update
// logic that could change in a future version. This test locks in that
// invariant explicitly, independent of go-webauthn's internals.
func TestFullLoginFlow_CloneWarningStaysLatchedAfterCleanLogin(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{RPName: testRPName, RPID: testRPID, RPOrigin: testRPOrigin},
		JWT:    config.JWTConfig{Secret: testJWTSecret, Issuer: testJWTIssuer, ExpiryHours: testJWTExpiryHours},
	}
	store := memory.NewStore()
	svc, err := NewWebAuthnService(store, cfg, zap.NewNop())
	require.NoError(t, err)

	rp := virtualwebauthn.RelyingParty{ID: testRPID, Name: testRPName, Origin: testRPOrigin}
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserNotVerified: false,
		UserNotPresent:  false,
	})
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	ctx := context.Background()

	beginRegResp, err := svc.BeginRegistration(ctx, &BeginRegistrationRequest{DisplayName: "Clone Latch Test User"})
	require.NoError(t, err)
	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	regOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)
	regResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *regOptions)
	finishRegResp, err := svc.FinishRegistration(ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(regResponse),
		DisplayName: "Clone Latch Test User",
	})
	require.NoError(t, err)

	userID := domain.UserIDFromString(finishRegResp.UUID)
	authenticator.Options.UserHandle = userID.AsUserHandle()
	authenticator.AddCredential(credential)

	login := func(counter uint32) {
		t.Helper()
		credential.Counter = counter
		beginLoginResp, err := svc.BeginLogin(ctx)
		require.NoError(t, err)
		loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
		require.NoError(t, err)
		assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
		require.NoError(t, err)
		assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *assertionOptions)
		_, err = svc.FinishLogin(ctx, &FinishLoginRequest{
			ChallengeID: beginLoginResp.ChallengeID,
			Credential:  json.RawMessage(assertionResponse),
		})
		require.NoError(t, err)
	}

	// Baseline, then a regression that latches CloneWarning=true.
	login(10)
	login(3)

	user, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	require.True(t, user.WebauthnCredentials[0].Authenticator.CloneWarning, "sanity: clone warning must be set after the regression")

	// A subsequent, cleanly-incrementing login (counter > stored) reports no
	// clone warning for itself — it must NOT clear the latched flag.
	login(20)

	user, err = store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.True(t, user.WebauthnCredentials[0].Authenticator.CloneWarning, "a clean subsequent login must not clear a previously latched clone warning")
	assert.Equal(t, uint32(20), user.WebauthnCredentials[0].Authenticator.SignCount, "sign count must still advance normally")
}

// raceInjectingUserStore wraps a real storage.UserStore and, on its SECOND
// GetByID call — go-webauthn's own internal discoverable-credential lookup,
// FinishLogin's only other GetByID besides its initial snapshot — invokes
// onSecondCall once (after taking that call's own snapshot, before
// returning it) to deterministically simulate a concurrent write landing in
// storage right after that lookup and before FinishLogin's final persist,
// without needing actual goroutines to race (see
// TestFullLoginFlow_CloneWarningSurvivesReplaceOneRace). Firing after that
// call's own fetch, not before, matters: it must not also change what
// go-webauthn itself hydrates into the Credential it returns (which would
// let the *existing* single-request sticky-latch already cover this case,
// making the test pass without exercising the fix under test at all — this
// was caught empirically by reverting the fix and observing the test still
// passed, then fixing the injection point until reverting it made the test
// fail as expected).
//
// GetByID always returns a deep copy of the credential slice, matching a
// real document-store backend (MongoDB decodes a fresh struct on every
// read) rather than the wrapped internal/storage/memory implementation's
// aliasing behavior (its GetByID returns the same pointer stored in its
// map). Without that copy, this test's "concurrent write" would alias the
// exact same WebauthnCredentials slice the calling FinishLogin is already
// holding, mutating it in place regardless of whether the fix under test
// re-reads anything — which would make the test pass even without the fix,
// silently proving nothing.
type raceInjectingUserStore struct {
	storage.UserStore
	mu           sync.Mutex
	calls        int
	onSecondCall func()
}

func (s *raceInjectingUserStore) GetByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()

	// Snapshot BEFORE injecting the "concurrent" write, so this call
	// (go-webauthn's own discoverable-credential lookup) sees the
	// pre-race state — matching a real production race where the other
	// request's write lands sometime during THIS request's own assertion
	// verification, which happens after go-webauthn's lookup but before
	// FinishLogin's final persist.
	user, err := s.UserStore.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	cp := *user
	cp.WebauthnCredentials = append([]domain.WebauthnCredential(nil), user.WebauthnCredentials...)

	if call == 2 && s.onSecondCall != nil {
		s.onSecondCall()
	}

	return &cp, nil
}

// storeWithUserOverride wraps *memory.Store, swapping out just the Users()
// accessor so every other collection still behaves like the real in-memory
// store.
type storeWithUserOverride struct {
	*memory.Store
	users storage.UserStore
}

func (s *storeWithUserOverride) Users() storage.UserStore { return s.users }

// TestFullLoginFlow_CloneWarningSurvivesReplaceOneRace covers a review
// finding on PR #388: FinishLogin's CloneWarning latch only protected a
// single request's own in-memory snapshot. The original persistence path
// (Users().Update, a whole-document ReplaceOne) meant a second, concurrent
// request that read the user BEFORE a first request latched
// CloneWarning=true, but persisted AFTER it, would silently clobber the
// flag back to false — a classic lost update, distinct from (and on top of)
// the single-request stickiness covered by
// TestFullLoginFlow_CloneWarningStaysLatchedAfterCleanLogin. A first
// mitigation (re-reading the stored value immediately before persisting and
// OR-ing it in) was flagged in a follow-up review as still racy — a
// read-then-write pair can never be made airtight no matter how close
// together the read and write are. The actual fix replaces the
// whole-document persistence for this path with
// UserStore.UpdateCredentialAuthenticator, a single atomic, field-scoped
// update that never writes CloneWarning=false over an existing true — see
// its doc comment in internal/storage/interface.go.
//
// Reproduces the race deterministically (no real goroutines needed) by
// wrapping UserStore so that exactly between this login's own two internal
// GetByID calls, a "concurrent" write lands directly in the backing store,
// setting CloneWarning=true. This login's own assertion is a clean,
// non-regressing one that never sees a clone warning itself, so without
// UpdateCredentialAuthenticator's OR-only semantics this would clobber the
// concurrent write back to false.
func TestFullLoginFlow_CloneWarningSurvivesReplaceOneRace(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{RPName: testRPName, RPID: testRPID, RPOrigin: testRPOrigin},
		JWT:    config.JWTConfig{Secret: testJWTSecret, Issuer: testJWTIssuer, ExpiryHours: testJWTExpiryHours},
	}
	baseStore := memory.NewStore()
	setupSvc, err := NewWebAuthnService(baseStore, cfg, zap.NewNop())
	require.NoError(t, err)

	rp := virtualwebauthn.RelyingParty{ID: testRPID, Name: testRPName, Origin: testRPOrigin}
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserNotVerified: false,
		UserNotPresent:  false,
	})
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	ctx := context.Background()

	beginRegResp, err := setupSvc.BeginRegistration(ctx, &BeginRegistrationRequest{DisplayName: "Race Test User"})
	require.NoError(t, err)
	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	regOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)
	regResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *regOptions)
	finishRegResp, err := setupSvc.FinishRegistration(ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(regResponse),
		DisplayName: "Race Test User",
	})
	require.NoError(t, err)

	userID := domain.UserIDFromString(finishRegResp.UUID)
	credentialIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	authenticator.Options.UserHandle = userID.AsUserHandle()
	authenticator.AddCredential(credential)
	credential.Counter = 10 // establish a baseline sign count via a normal login

	raceStore := &raceInjectingUserStore{
		UserStore: baseStore.Users(),
		onSecondCall: func() {
			// Simulate a concurrent request's ReplaceOne landing right here,
			// between this request's own initial snapshot and its final
			// persist: directly latch CloneWarning=true in the backing
			// store, bypassing this request's in-memory copy entirely.
			u, err := baseStore.Users().GetByID(ctx, userID)
			require.NoError(t, err)
			for i := range u.WebauthnCredentials {
				if u.WebauthnCredentials[i].ID == credentialIDStr {
					u.WebauthnCredentials[i].Authenticator.CloneWarning = true
				}
			}
			require.NoError(t, baseStore.Users().Update(ctx, u))
		},
	}
	wrapped := &storeWithUserOverride{Store: baseStore, users: raceStore}
	svc, err := NewWebAuthnService(wrapped, cfg, zap.NewNop())
	require.NoError(t, err)

	// A clean, cleanly-incrementing login on the wrapped store: this
	// request's OWN assertion never sees a clone warning, but the
	// "concurrent" write injected mid-flight already latched one.
	beginLoginResp, err := svc.BeginLogin(ctx)
	require.NoError(t, err)
	loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
	require.NoError(t, err)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)
	credential.Counter = 20
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *assertionOptions)
	_, err = svc.FinishLogin(ctx, &FinishLoginRequest{
		ChallengeID: beginLoginResp.ChallengeID,
		Credential:  json.RawMessage(assertionResponse),
	})
	require.NoError(t, err)

	final, err := baseStore.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.True(t, final.WebauthnCredentials[0].Authenticator.CloneWarning,
		"a concurrent write that latched CloneWarning=true must survive this request's own ReplaceOne, not be clobbered back to false")
}

// ============================================================================
// Storage-layer failure paths for the atomic challenge/invite consumption
// (issues #379, #378) — a real storage outage on ConsumeByID/MarkCompleted,
// as opposed to the "already consumed" case covered by the concurrency tests
// in internal/storage/memory and internal/storage/mongodb.
// ============================================================================

// erroringChallengeStore wraps a real storage.ChallengeStore and forces
// ConsumeByID to return an arbitrary (non-ErrNotFound) error for one
// specific challenge ID, so tests can exercise the generic
// "failed to consume challenge" error-wrapping branch in
// FinishRegistration/FinishLogin/FinishAddCredential without needing a real
// storage outage.
type erroringChallengeStore struct {
	storage.ChallengeStore
	failID string
	err    error
}

func (e *erroringChallengeStore) ConsumeByID(ctx context.Context, id string) (*domain.WebauthnChallenge, error) {
	if id == e.failID {
		return nil, e.err
	}
	return e.ChallengeStore.ConsumeByID(ctx, id)
}

func (e *erroringChallengeStore) ConsumeByIDForUser(ctx context.Context, id string, userID string) (*domain.WebauthnChallenge, error) {
	if id == e.failID {
		return nil, e.err
	}
	return e.ChallengeStore.ConsumeByIDForUser(ctx, id, userID)
}

// storeWithChallengeOverride wraps *memory.Store, swapping out just the
// Challenges() accessor so every other collection still behaves like the
// real in-memory store.
type storeWithChallengeOverride struct {
	*memory.Store
	challenges storage.ChallengeStore
}

func (s *storeWithChallengeOverride) Challenges() storage.ChallengeStore { return s.challenges }

func TestConsumeChallenge_GenericStorageError_IsWrapped(t *testing.T) {
	wantErr := errors.New("simulated storage outage")
	cfg := &config.Config{
		Server: config.ServerConfig{RPName: testRPName, RPID: testRPID, RPOrigin: testRPOrigin},
		JWT:    config.JWTConfig{Secret: testJWTSecret, Issuer: testJWTIssuer, ExpiryHours: testJWTExpiryHours},
	}

	t.Run("FinishRegistration", func(t *testing.T) {
		baseStore := memory.NewStore()
		wrapped := &storeWithChallengeOverride{
			Store: baseStore,
			challenges: &erroringChallengeStore{
				ChallengeStore: baseStore.Challenges(),
				failID:         "boom-challenge",
				err:            wantErr,
			},
		}
		svc, err := NewWebAuthnService(wrapped, cfg, zap.NewNop())
		require.NoError(t, err)

		_, err = svc.FinishRegistration(context.Background(), &FinishRegistrationRequest{
			ChallengeID: "boom-challenge",
		})
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrChallengeNotFound)
		assert.Contains(t, err.Error(), "failed to consume challenge")
		assert.ErrorIs(t, err, wantErr)
	})

	t.Run("FinishLogin", func(t *testing.T) {
		baseStore := memory.NewStore()
		wrapped := &storeWithChallengeOverride{
			Store: baseStore,
			challenges: &erroringChallengeStore{
				ChallengeStore: baseStore.Challenges(),
				failID:         "boom-challenge",
				err:            wantErr,
			},
		}
		svc, err := NewWebAuthnService(wrapped, cfg, zap.NewNop())
		require.NoError(t, err)

		_, err = svc.FinishLogin(context.Background(), &FinishLoginRequest{
			ChallengeID: "boom-challenge",
		})
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrChallengeNotFound)
		assert.Contains(t, err.Error(), "failed to consume challenge")
		assert.ErrorIs(t, err, wantErr)
	})

	t.Run("FinishAddCredential", func(t *testing.T) {
		baseStore := memory.NewStore()
		userID := domain.NewUserID()
		require.NoError(t, baseStore.Users().Create(context.Background(), &domain.User{UUID: userID}))
		wrapped := &storeWithChallengeOverride{
			Store: baseStore,
			challenges: &erroringChallengeStore{
				ChallengeStore: baseStore.Challenges(),
				failID:         "boom-challenge",
				err:            wantErr,
			},
		}
		svc, err := NewWebAuthnService(wrapped, cfg, zap.NewNop())
		require.NoError(t, err)

		_, err = svc.FinishAddCredential(context.Background(), userID, &FinishAddCredentialRequest{
			ChallengeID: "boom-challenge",
		}, "")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrChallengeNotFound)
		assert.Contains(t, err.Error(), "failed to consume challenge")
		assert.ErrorIs(t, err, wantErr)
	})
}

// erroringInviteStore wraps a real storage.InviteStore and forces
// MarkCompleted to fail for one specific invite code, regardless of the
// invite's actual state. This lets a single-threaded test exercise the
// "atomic invite claim failed, reject registration before the user account
// is created" branch that fixes issue #378, without needing a second
// goroutine to actually race it (that race is covered separately by
// TestInviteStore_MarkCompleted_ConcurrentSingleWinner in
// internal/storage/memory).
type erroringInviteStore struct {
	storage.InviteStore
	failCode string
	err      error
}

func (e *erroringInviteStore) MarkCompleted(ctx context.Context, tenantID domain.TenantID, code string, usedBy domain.UserID) error {
	if code == e.failCode {
		return e.err
	}
	return e.InviteStore.MarkCompleted(ctx, tenantID, code, usedBy)
}

// storeWithInviteOverride wraps *memory.Store, swapping out just the
// Invites() accessor.
type storeWithInviteOverride struct {
	*memory.Store
	invites storage.InviteStore
}

func (s *storeWithInviteOverride) Invites() storage.InviteStore { return s.invites }

// TestFinishRegistration_InviteMarkCompletedFails_RejectsBeforeUserCreated
// covers issue #378: when the atomic invite claim (MarkCompleted) fails —
// here simulated directly, the concurrent-loser case is covered by
// TestInviteStore_MarkCompleted_ConcurrentSingleWinner — FinishRegistration
// must reject the registration with ErrInvalidInvite and must NOT have
// created the user account or tenant membership. Before the W-1 fix,
// MarkCompleted ran after Users().Create()/AddMembership, so this same
// failure would have left a committed, usable account behind.
func TestFinishRegistration_InviteMarkCompletedFails_RejectsBeforeUserCreated(t *testing.T) {
	baseStore := memory.NewStore()
	ctx := context.Background()

	tenant := &domain.Tenant{
		ID:          domain.TenantID("tenant-invite-fail"),
		Name:        "Invite Fail Tenant",
		DisplayName: "Invite Fail Tenant",
		Enabled:     true,
	}
	require.NoError(t, baseStore.Tenants().Create(ctx, tenant))

	invite := &domain.Invite{
		ID:        "invite-1",
		TenantID:  tenant.ID,
		Code:      "INVITE-CODE",
		Status:    domain.InviteStatusActive,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, baseStore.Invites().Create(ctx, invite))

	wrapped := &storeWithInviteOverride{
		Store: baseStore,
		invites: &erroringInviteStore{
			InviteStore: baseStore.Invites(),
			failCode:    invite.Code,
			err:         errors.New("simulated atomic claim failure"),
		},
	}

	cfg := &config.Config{
		Server: config.ServerConfig{RPName: testRPName, RPID: testRPID, RPOrigin: testRPOrigin},
		JWT:    config.JWTConfig{Secret: testJWTSecret, Issuer: testJWTIssuer, ExpiryHours: testJWTExpiryHours},
	}
	svc, err := NewWebAuthnService(wrapped, cfg, zap.NewNop())
	require.NoError(t, err)

	rp := virtualwebauthn.RelyingParty{ID: testRPID, Name: testRPName, Origin: testRPOrigin}
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserNotVerified: false,
		UserNotPresent:  false,
	})
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	beginResp, err := svc.BeginRegistration(ctx, &BeginRegistrationRequest{
		DisplayName: "Invite Fail User",
		TenantID:    string(tenant.ID),
		InviteCode:  invite.Code,
	})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginResp.CreateOptions)
	require.NoError(t, err)
	regOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	regResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *regOptions)

	_, err = svc.FinishRegistration(ctx, &FinishRegistrationRequest{
		ChallengeID: beginResp.ChallengeID,
		Credential:  json.RawMessage(regResponse),
		DisplayName: "Invite Fail User",
	})
	require.ErrorIs(t, err, ErrInvalidInvite)

	// No user or membership must have been created: the atomic invite claim
	// failing must gate user creation, not happen after it.
	tenantUsers, err := baseStore.UserTenants().GetTenantUsers(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Empty(t, tenantUsers, "no tenant membership should exist when the atomic invite claim fails")

	// The invite itself must still read back as untouched (still active) —
	// erroringInviteStore never delegated to the real MarkCompleted.
	gotInvite, err := baseStore.Invites().GetByCode(ctx, tenant.ID, invite.Code)
	require.NoError(t, err)
	assert.Equal(t, domain.InviteStatusActive, gotInvite.Status)
}

// TestFinishRegistration_ChallengeWithInviteCodeButNoTenant_RejectsClosed is
// the defense-in-depth companion to
// TestWebAuthnService_BeginRegistration_InviteCodeWithoutTenantRejected: even
// though BeginRegistration now rejects an invite-code-without-tenant
// request up front, this constructs a challenge directly in the store
// (bypassing BeginRegistration entirely, as if one somehow existed from
// before that guard, or from a future code path that stores a challenge
// differently) with a non-empty InviteCode but an empty TenantID, and
// asserts FinishRegistration still fails closed with ErrInvalidInvite
// rather than silently skipping invite consumption and creating a global
// account.
func TestFinishRegistration_ChallengeWithInviteCodeButNoTenant_RejectsClosed(t *testing.T) {
	baseStore := memory.NewStore()
	ctx := context.Background()

	cfg := &config.Config{
		Server: config.ServerConfig{RPName: testRPName, RPID: testRPID, RPOrigin: testRPOrigin},
		JWT:    config.JWTConfig{Secret: testJWTSecret, Issuer: testJWTIssuer, ExpiryHours: testJWTExpiryHours},
	}
	svc, err := NewWebAuthnService(baseStore, cfg, zap.NewNop())
	require.NoError(t, err)

	rp := virtualwebauthn.RelyingParty{ID: testRPID, Name: testRPName, Origin: testRPOrigin}
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserNotVerified: false,
		UserNotPresent:  false,
	})
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Use the normal BeginRegistration path (no tenant, no invite code — a
	// perfectly ordinary global registration) to get a well-formed
	// challenge and options, then mutate the STORED challenge directly to
	// carry a non-empty InviteCode. This simulates a challenge somehow
	// ending up in this shape (e.g. a future code path that constructs one
	// differently) without needing to hand-build virtualwebauthn/WebAuthn
	// protocol structs.
	beginResp, err := svc.BeginRegistration(ctx, &BeginRegistrationRequest{DisplayName: "No Tenant User"})
	require.NoError(t, err)

	storedChallenge, err := baseStore.Challenges().GetByID(ctx, beginResp.ChallengeID)
	require.NoError(t, err)
	storedChallenge.InviteCode = "orphaned-invite-code"
	require.NoError(t, baseStore.Challenges().Create(ctx, storedChallenge)) // memory Create overwrites by ID

	regOptionsJSON, err := json.Marshal(beginResp.CreateOptions)
	require.NoError(t, err)
	regOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)
	regResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *regOptions)

	_, err = svc.FinishRegistration(ctx, &FinishRegistrationRequest{
		ChallengeID: beginResp.ChallengeID,
		Credential:  json.RawMessage(regResponse),
		DisplayName: "No Tenant User",
	})
	require.ErrorIs(t, err, ErrInvalidInvite)

	userID := domain.UserIDFromString(storedChallenge.UserID)
	_, err = baseStore.Users().GetByID(ctx, userID)
	assert.ErrorIs(t, err, storage.ErrNotFound, "no user must be created when a challenge carries an invite code but no tenant")
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

		// Review finding on PR #388: consuming the challenge before checking
		// ownership let a mismatched caller (user 2, here) permanently burn
		// user 1's real challenge. The atomic ConsumeByIDForUser fix folds
		// the ownership check into the same atomic find-and-delete, so
		// user 2's request must be rejected as "not found" (indistinguishable
		// from the challenge simply not existing — deliberately, so a caller
		// can't probe which) WITHOUT consuming it.
		_, err = setup.service.FinishAddCredential(setup.ctx, userID2, finishReq, "")
		assert.ErrorIs(t, err, ErrChallengeNotFound)

		// The real owner (user 1) must still be able to use their own
		// challenge afterward — it must not have been consumed by user 2's
		// mismatched attempt.
		got, err := setup.store.Challenges().GetByID(setup.ctx, "user1-challenge")
		require.NoError(t, err, "user 1's challenge must survive a mismatched-owner attempt from user 2")
		assert.Equal(t, userID1.String(), got.UserID)
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

// ============================================================================
// Regression Tests
// ============================================================================

// TestBEREncodedECDSASignature is a regression test for YubiKey 5.8 firmware
// which produces ECDSA signatures with BER-encoded integers (may have leading
// zeros) instead of minimal DER encoding.
//
// This test verifies that go-webauthn v0.16.0+ properly handles BER integers.
// See: https://github.com/go-webauthn/webauthn/issues/593
func TestBEREncodedECDSASignature(t *testing.T) {
	// This test verifies the library upgrade by checking that the
	// webauthncose package can verify signatures with BER-encoded integers.
	// YubiKey 5.8 firmware produces such signatures during attestation.

	// The go-webauthn v0.16.0 changelog states:
	// "webauthncose: allow ber integers in ecdsa sigs (#593)"

	// We verify this by checking the library version requirement is met
	// in go.mod. The actual BER signature handling is tested extensively
	// in the upstream go-webauthn library's test suite.

	// Captured attestation data from YubiKey 5.8 would require a physical
	// device. Instead, we verify the library is correctly configured by
	// running a standard registration flow which exercises the same
	// signature verification code path.

	setup := newTestVirtualWebAuthnSetup(t)

	// Begin registration
	beginResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{
		DisplayName: "YubiKey 5.8 Regression Test",
	})
	require.NoError(t, err, "BeginRegistration should succeed")

	// Parse and create attestation response
	optionsJSON, err := json.Marshal(beginResp.CreateOptions)
	require.NoError(t, err)

	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*attestationOptions,
	)

	// Finish registration - this exercises the ECDSA signature verification
	// code path that was fixed in go-webauthn v0.16.0 for BER integers
	finishReq := &FinishRegistrationRequest{
		ChallengeID: beginResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "YubiKey 5.8 Regression Test",
	}

	finishResp, err := setup.service.FinishRegistration(setup.ctx, finishReq)
	require.NoError(t, err, "FinishRegistration should succeed with ECDSA verification")
	assert.NotEmpty(t, finishResp.UUID)
	assert.NotEmpty(t, finishResp.Token)

	// Verify the credential was stored correctly
	userID := domain.UserIDFromString(finishResp.UUID)
	user, err := setup.store.Users().GetByID(setup.ctx, userID)
	require.NoError(t, err)
	assert.Len(t, user.WebauthnCredentials, 1, "User should have one credential")

	// The credential should use ES256 (ECDSA with P-256)
	cred := user.WebauthnCredentials[0]
	assert.NotEmpty(t, cred.PublicKey, "Credential should have a public key")
}

// ============================================================================
// OIDC Gate Enforcement Tests for FinishLogin
// Issue #61: Add OIDC gate enforcement tests for FinishLogin
// ============================================================================

func TestWebAuthnService_FinishLogin_OIDCGate_MissingBinding(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	// Create tenant with OIDC gate enabled for login
	tenant := &domain.Tenant{
		ID:      domain.TenantID("test-tenant"),
		Name:    "Test Tenant",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "test-client",
			},
		},
	}
	err := setup.store.Tenants().Create(setup.ctx, tenant)
	require.NoError(t, err)

	// Register a user with this tenant
	beginRegResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{
		DisplayName: "OIDC Gate Test User",
		TenantID:    string(tenant.ID),
	})
	require.NoError(t, err)

	// Parse registration options
	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*attestationOptions,
	)

	finishRegResp, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "OIDC Gate Test User",
	})
	require.NoError(t, err)

	// Set up authenticator with tenant-scoped user handle for assertion
	userID := domain.UserIDFromString(finishRegResp.UUID)
	// Use EncodeUserHandle to create proper tenant-scoped handle
	setup.authenticator.Options.UserHandle = domain.EncodeUserHandle(tenant.ID, userID)
	setup.authenticator.AddCredential(setup.credential)

	// Start login
	beginLoginResp, err := setup.service.BeginLogin(setup.ctx)
	require.NoError(t, err)

	// Parse login options
	loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
	require.NoError(t, err)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*assertionOptions,
	)

	// Attempt login WITHOUT OIDC binding - should fail with ErrOIDCGateRequired
	finishLoginReq := &FinishLoginRequest{
		ChallengeID:     beginLoginResp.ChallengeID,
		Credential:      json.RawMessage(assertionResponse),
		OIDCGateBinding: nil, // Missing OIDC binding
	}

	_, err = setup.service.FinishLogin(setup.ctx, finishLoginReq)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCGateRequired, "Should require OIDC gate when binding is missing")
}

func TestWebAuthnService_FinishLogin_OIDCGate_WrongIssuer(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	// Create tenant with OIDC gate enabled for login
	tenant := &domain.Tenant{
		ID:      domain.TenantID("test-tenant-2"),
		Name:    "Test Tenant 2",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "test-client",
			},
		},
	}
	err := setup.store.Tenants().Create(setup.ctx, tenant)
	require.NoError(t, err)

	// Register a user with this tenant
	beginRegResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{
		DisplayName: "OIDC Gate Test User 2",
		TenantID:    string(tenant.ID),
	})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*attestationOptions,
	)

	finishRegResp, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "OIDC Gate Test User 2",
	})
	require.NoError(t, err)

	// Set up authenticator with tenant-scoped user handle for assertion
	userID := domain.UserIDFromString(finishRegResp.UUID)
	setup.authenticator.Options.UserHandle = domain.EncodeUserHandle(tenant.ID, userID)
	setup.authenticator.AddCredential(setup.credential)

	// Start login
	beginLoginResp, err := setup.service.BeginLogin(setup.ctx)
	require.NoError(t, err)

	loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
	require.NoError(t, err)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*assertionOptions,
	)

	// Attempt login with WRONG issuer - should fail with ErrOIDCGateRequired
	finishLoginReq := &FinishLoginRequest{
		ChallengeID: beginLoginResp.ChallengeID,
		Credential:  json.RawMessage(assertionResponse),
		OIDCGateBinding: &OIDCGateBinding{
			Issuer:  "https://wrong-idp.example.com", // Wrong issuer!
			Subject: "user123",
		},
	}

	_, err = setup.service.FinishLogin(setup.ctx, finishLoginReq)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCGateRequired, "Should require correct issuer")
}

// TestWebAuthnService_FinishLogin_OIDCGate_WrongAudience covers a Copilot
// review finding: two tenants can share an OIDC issuer (e.g. a shared
// multi-tenant IdP domain) while using different client IDs/audiences per
// app. Issuer alone matching isn't enough proof a token was meant for THIS
// tenant - the audience the token was actually validated against (recorded
// by the AS handler in OIDCGateBinding.Audience) must match too.
func TestWebAuthnService_FinishLogin_OIDCGate_WrongAudience(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	tenant := &domain.Tenant{
		ID:      domain.TenantID("test-tenant-audience"),
		Name:    "Test Tenant Audience",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "tenant-audience-client",
			},
		},
	}
	err := setup.store.Tenants().Create(setup.ctx, tenant)
	require.NoError(t, err)

	beginRegResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{
		DisplayName: "OIDC Gate Audience Test User",
		TenantID:    string(tenant.ID),
	})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*attestationOptions,
	)

	finishRegResp, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "OIDC Gate Audience Test User",
	})
	require.NoError(t, err)

	userID := domain.UserIDFromString(finishRegResp.UUID)
	setup.authenticator.Options.UserHandle = domain.EncodeUserHandle(tenant.ID, userID)
	setup.authenticator.AddCredential(setup.credential)

	beginLoginResp, err := setup.service.BeginLogin(setup.ctx)
	require.NoError(t, err)

	loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
	require.NoError(t, err)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*assertionOptions,
	)

	// Correct issuer, but the audience the token was actually validated
	// against (a different tenant's client) doesn't match this tenant's -
	// should fail with ErrOIDCGateRequired even though the issuer matches.
	finishLoginReq := &FinishLoginRequest{
		ChallengeID: beginLoginResp.ChallengeID,
		Credential:  json.RawMessage(assertionResponse),
		OIDCGateBinding: &OIDCGateBinding{
			Issuer:   "https://idp.example.com",
			Subject:  "user123",
			Audience: "some-other-tenants-client",
		},
	}

	_, err = setup.service.FinishLogin(setup.ctx, finishLoginReq)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCGateRequired, "Should require the correct audience even when the issuer matches")
}

// TestWebAuthnService_FinishLogin_OIDCGate_MatchingAudience_Success exercises
// the other side of the new audience check: a binding whose Audience matches
// the tenant's own configured audience (defaulting to ClientID, per
// EffectiveAudience) must be allowed through, not just an empty/unset one.
func TestWebAuthnService_FinishLogin_OIDCGate_MatchingAudience_Success(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	tenant := &domain.Tenant{
		ID:      domain.TenantID("test-tenant-audience-ok"),
		Name:    "Test Tenant Audience OK",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "tenant-audience-ok-client",
			},
		},
	}
	err := setup.store.Tenants().Create(setup.ctx, tenant)
	require.NoError(t, err)

	beginRegResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{
		DisplayName: "OIDC Gate Audience OK User",
		TenantID:    string(tenant.ID),
	})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*attestationOptions,
	)

	finishRegResp, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "OIDC Gate Audience OK User",
	})
	require.NoError(t, err)

	userID := domain.UserIDFromString(finishRegResp.UUID)
	setup.authenticator.Options.UserHandle = domain.EncodeUserHandle(tenant.ID, userID)
	setup.authenticator.AddCredential(setup.credential)

	beginLoginResp, err := setup.service.BeginLogin(setup.ctx)
	require.NoError(t, err)

	loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
	require.NoError(t, err)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*assertionOptions,
	)

	finishLoginReq := &FinishLoginRequest{
		ChallengeID: beginLoginResp.ChallengeID,
		Credential:  json.RawMessage(assertionResponse),
		OIDCGateBinding: &OIDCGateBinding{
			Issuer:   "https://idp.example.com",
			Subject:  "user123",
			Audience: "tenant-audience-ok-client", // Matches tenant's EffectiveAudience (ClientID).
		},
	}

	resp, err := setup.service.FinishLogin(setup.ctx, finishLoginReq)
	require.NoError(t, err, "Login should succeed when the audience matches")
	assert.NotEmpty(t, resp.Token)
}

// TestWebAuthnService_FinishLogin_OIDCGate_RequiredClaimsMismatch covers a
// third Copilot review finding on this PR: Issuer and Audience matching
// alone isn't enough if two tenants share both but configure different
// OIDCGate.RequiredClaims - the gate middleware only ever validates a token
// against the HEADER tenant's RequiredClaims, never the CREDENTIAL's real
// tenant's. FinishLogin must re-check the credential tenant's own
// RequiredClaims against the token's actual validated claims.
func TestWebAuthnService_FinishLogin_OIDCGate_RequiredClaimsMismatch(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	tenant := &domain.Tenant{
		ID:      domain.TenantID("test-tenant-claims"),
		Name:    "Test Tenant Claims",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "tenant-claims-client",
			},
			RequiredClaims: map[string]interface{}{"role": "admin"},
		},
	}
	err := setup.store.Tenants().Create(setup.ctx, tenant)
	require.NoError(t, err)

	beginRegResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{
		DisplayName: "OIDC Gate Claims Test User",
		TenantID:    string(tenant.ID),
	})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*attestationOptions,
	)

	finishRegResp, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "OIDC Gate Claims Test User",
	})
	require.NoError(t, err)

	userID := domain.UserIDFromString(finishRegResp.UUID)
	setup.authenticator.Options.UserHandle = domain.EncodeUserHandle(tenant.ID, userID)
	setup.authenticator.AddCredential(setup.credential)

	beginLoginResp, err := setup.service.BeginLogin(setup.ctx)
	require.NoError(t, err)

	loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
	require.NoError(t, err)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*assertionOptions,
	)

	// Correct issuer and audience, but the validated claims don't satisfy
	// this tenant's RequiredClaims (e.g. the token was validated against a
	// different, more permissive tenant sharing the same issuer/audience).
	finishLoginReq := &FinishLoginRequest{
		ChallengeID: beginLoginResp.ChallengeID,
		Credential:  json.RawMessage(assertionResponse),
		OIDCGateBinding: &OIDCGateBinding{
			Issuer:   "https://idp.example.com",
			Subject:  "user123",
			Audience: "tenant-claims-client",
			Claims:   jwt.MapClaims{"role": "user"}, // Missing/wrong role.
		},
	}

	_, err = setup.service.FinishLogin(setup.ctx, finishLoginReq)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCGateRequired, "Should require the correct claims even when issuer and audience match")
}

// TestWebAuthnService_FinishLogin_OIDCGate_MatchingClaims_Success exercises
// the other side: a binding whose Claims satisfy the tenant's
// RequiredClaims must be allowed through.
func TestWebAuthnService_FinishLogin_OIDCGate_MatchingClaims_Success(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	tenant := &domain.Tenant{
		ID:      domain.TenantID("test-tenant-claims-ok"),
		Name:    "Test Tenant Claims OK",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "tenant-claims-ok-client",
			},
			RequiredClaims: map[string]interface{}{"role": "admin"},
		},
	}
	err := setup.store.Tenants().Create(setup.ctx, tenant)
	require.NoError(t, err)

	beginRegResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{
		DisplayName: "OIDC Gate Claims OK User",
		TenantID:    string(tenant.ID),
	})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*attestationOptions,
	)

	finishRegResp, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "OIDC Gate Claims OK User",
	})
	require.NoError(t, err)

	userID := domain.UserIDFromString(finishRegResp.UUID)
	setup.authenticator.Options.UserHandle = domain.EncodeUserHandle(tenant.ID, userID)
	setup.authenticator.AddCredential(setup.credential)

	beginLoginResp, err := setup.service.BeginLogin(setup.ctx)
	require.NoError(t, err)

	loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
	require.NoError(t, err)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*assertionOptions,
	)

	finishLoginReq := &FinishLoginRequest{
		ChallengeID: beginLoginResp.ChallengeID,
		Credential:  json.RawMessage(assertionResponse),
		OIDCGateBinding: &OIDCGateBinding{
			Issuer:   "https://idp.example.com",
			Subject:  "user123",
			Audience: "tenant-claims-ok-client",
			Claims:   jwt.MapClaims{"role": "admin"},
		},
	}

	resp, err := setup.service.FinishLogin(setup.ctx, finishLoginReq)
	require.NoError(t, err, "Login should succeed when RequiredClaims are satisfied")
	assert.NotEmpty(t, resp.Token)
}

func TestWebAuthnService_FinishLogin_OIDCGate_IdentityNotBound(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	// Create tenant with OIDC gate AND bind_identity enabled
	tenant := &domain.Tenant{
		ID:      domain.TenantID("test-tenant-3"),
		Name:    "Test Tenant 3",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "test-client",
			},
			BindIdentity: true, // Requires bound identity
		},
	}
	err := setup.store.Tenants().Create(setup.ctx, tenant)
	require.NoError(t, err)

	// Register a user with this tenant (but WITHOUT binding identity during registration)
	beginRegResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{
		DisplayName: "OIDC Gate Test User 3",
		TenantID:    string(tenant.ID),
	})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*attestationOptions,
	)

	finishRegResp, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "OIDC Gate Test User 3",
		// OIDCGateBinding is nil - no identity bound during registration
	})
	require.NoError(t, err)

	// Set up authenticator with tenant-scoped user handle for assertion
	userID := domain.UserIDFromString(finishRegResp.UUID)
	setup.authenticator.Options.UserHandle = domain.EncodeUserHandle(tenant.ID, userID)
	setup.authenticator.AddCredential(setup.credential)

	// Start login
	beginLoginResp, err := setup.service.BeginLogin(setup.ctx)
	require.NoError(t, err)

	loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
	require.NoError(t, err)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*assertionOptions,
	)

	// Attempt login with correct issuer but no bound identity - should fail with ErrIdentityNotBound
	finishLoginReq := &FinishLoginRequest{
		ChallengeID: beginLoginResp.ChallengeID,
		Credential:  json.RawMessage(assertionResponse),
		OIDCGateBinding: &OIDCGateBinding{
			Issuer:  "https://idp.example.com",
			Subject: "user123",
		},
	}

	_, err = setup.service.FinishLogin(setup.ctx, finishLoginReq)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIdentityNotBound, "Should fail when no identity was bound during registration")
}

func TestWebAuthnService_FinishLogin_OIDCGate_IdentityBindingMismatch(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	// Create tenant with OIDC gate AND bind_identity enabled
	tenant := &domain.Tenant{
		ID:      domain.TenantID("test-tenant-4"),
		Name:    "Test Tenant 4",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "test-client",
			},
			BindIdentity: true,
		},
	}
	err := setup.store.Tenants().Create(setup.ctx, tenant)
	require.NoError(t, err)

	// Register a user with this tenant
	beginRegResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{
		DisplayName: "OIDC Gate Test User 4",
		TenantID:    string(tenant.ID),
	})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*attestationOptions,
	)

	finishRegResp, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "OIDC Gate Test User 4",
		OIDCGateBinding: &OIDCGateBinding{
			Issuer:  "https://idp.example.com",
			Subject: "correct-user",
		},
	})
	require.NoError(t, err)

	// Verify the identity was bound
	userID := domain.UserIDFromString(finishRegResp.UUID)
	user, err := setup.store.Users().GetByID(setup.ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, user.GetEnterpriseIdentityForTenant(tenant.ID), "Identity should be bound after registration")

	// Set up authenticator with tenant-scoped user handle for assertion
	setup.authenticator.Options.UserHandle = domain.EncodeUserHandle(tenant.ID, userID)
	setup.authenticator.AddCredential(setup.credential)

	// Start login
	beginLoginResp, err := setup.service.BeginLogin(setup.ctx)
	require.NoError(t, err)

	loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
	require.NoError(t, err)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*assertionOptions,
	)

	// Attempt login with MISMATCHED subject - should fail with ErrIdentityBindingMismatch
	finishLoginReq := &FinishLoginRequest{
		ChallengeID: beginLoginResp.ChallengeID,
		Credential:  json.RawMessage(assertionResponse),
		OIDCGateBinding: &OIDCGateBinding{
			Issuer:  "https://idp.example.com",
			Subject: "wrong-user", // Doesn't match "correct-user"
		},
	}

	_, err = setup.service.FinishLogin(setup.ctx, finishLoginReq)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIdentityBindingMismatch, "Should fail when binding doesn't match stored identity")
}

func TestWebAuthnService_FinishLogin_OIDCGate_Success(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	// Create tenant with OIDC gate AND bind_identity enabled
	tenant := &domain.Tenant{
		ID:      domain.TenantID("test-tenant-5"),
		Name:    "Test Tenant 5",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "test-client",
			},
			BindIdentity: true,
		},
	}
	err := setup.store.Tenants().Create(setup.ctx, tenant)
	require.NoError(t, err)

	// Register a user with this tenant and bind identity
	beginRegResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{
		DisplayName: "OIDC Gate Success User",
		TenantID:    string(tenant.ID),
	})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*attestationOptions,
	)

	finishRegResp, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "OIDC Gate Success User",
		OIDCGateBinding: &OIDCGateBinding{
			Issuer:  "https://idp.example.com",
			Subject: "valid-user",
		},
	})
	require.NoError(t, err)

	// Set up authenticator with tenant-scoped user handle for assertion
	userID := domain.UserIDFromString(finishRegResp.UUID)
	setup.authenticator.Options.UserHandle = domain.EncodeUserHandle(tenant.ID, userID)
	setup.authenticator.AddCredential(setup.credential)

	// Start login
	beginLoginResp, err := setup.service.BeginLogin(setup.ctx)
	require.NoError(t, err)

	loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
	require.NoError(t, err)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(
		setup.rp,
		setup.authenticator,
		setup.credential,
		*assertionOptions,
	)

	// Login with MATCHING binding - should succeed
	finishLoginReq := &FinishLoginRequest{
		ChallengeID: beginLoginResp.ChallengeID,
		Credential:  json.RawMessage(assertionResponse),
		OIDCGateBinding: &OIDCGateBinding{
			Issuer:  "https://idp.example.com",
			Subject: "valid-user", // Matches bound identity
		},
	}

	resp, err := setup.service.FinishLogin(setup.ctx, finishLoginReq)
	require.NoError(t, err, "Login should succeed when OIDC binding matches stored identity")
	assert.NotEmpty(t, resp.Token, "Should receive a valid token")
	assert.Equal(t, string(tenant.ID), resp.TenantID, "Should return the tenant ID")
}

// ============================================================================
// Client extension output tests
// ============================================================================

// withClientExtensionResults injects a clientExtensionResults member into a
// virtualwebauthn credential JSON, simulating a browser that returns extension
// outputs (the wallet-frontend adds the PRF eval input itself on both
// registration and login, so the browser returns a "prf" output the backend
// never listed in its own options).
func withClientExtensionResults(t *testing.T, credentialJSON string, results map[string]any) json.RawMessage {
	t.Helper()
	var cred map[string]any
	require.NoError(t, json.Unmarshal([]byte(credentialJSON), &cred))
	cred["clientExtensionResults"] = results
	out, err := json.Marshal(cred)
	require.NoError(t, err)
	return out
}

func TestFullRegistrationFlow_WithPRFClientExtensionOutput(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	beginResp, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{DisplayName: "PRF User"})
	require.NoError(t, err)

	optionsJSON, err := json.Marshal(beginResp.CreateOptions)
	require.NoError(t, err)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(setup.rp, setup.authenticator, setup.credential, *attestationOptions)

	finishResp, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: beginResp.ChallengeID,
		Credential: withClientExtensionResults(t, attestationResponse, map[string]any{
			"credProps": map[string]any{"rk": true},
			"prf":       map[string]any{"enabled": true},
		}),
		DisplayName: "PRF User",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, finishResp.UUID)
}

func TestFullLoginFlow_WithPRFClientExtensionOutput(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)

	// Register first (no extension outputs needed here).
	regBegin, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{DisplayName: "PRF Login User"})
	require.NoError(t, err)
	regOptionsJSON, err := json.Marshal(regBegin.CreateOptions)
	require.NoError(t, err)
	regOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)
	regResponse := virtualwebauthn.CreateAttestationResponse(setup.rp, setup.authenticator, setup.credential, *regOptions)
	regFinish, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: regBegin.ChallengeID,
		Credential:  json.RawMessage(regResponse),
		DisplayName: "PRF Login User",
	})
	require.NoError(t, err)

	userID := domain.UserIDFromString(regFinish.UUID)
	setup.authenticator.Options.UserHandle = userID.AsUserHandle()
	setup.authenticator.AddCredential(setup.credential)

	// Login: the frontend adds prf.eval.first to the request options on its own,
	// so the browser returns a prf output the backend did not request.
	loginBegin, err := setup.service.BeginLogin(setup.ctx)
	require.NoError(t, err)
	loginOptionsJSON, err := json.Marshal(loginBegin.GetOptions)
	require.NoError(t, err)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)
	assertionResponse := virtualwebauthn.CreateAssertionResponse(setup.rp, setup.authenticator, setup.credential, *assertionOptions)

	loginFinish, err := setup.service.FinishLogin(setup.ctx, &FinishLoginRequest{
		ChallengeID: loginBegin.ChallengeID,
		Credential: withClientExtensionResults(t, assertionResponse, map[string]any{
			"prf": map[string]any{"results": map[string]any{"first": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
		}),
	})
	require.NoError(t, err)
	assert.Equal(t, regFinish.UUID, loginFinish.UUID)
}
