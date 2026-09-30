package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
	"github.com/sirosfoundation/go-wallet-backend/pkg/oidc"
)

// Regression tests for #408/#409: FinishWebAuthnLogin (/user/*) has the same
// audience-binding and required-claims gaps that #386 fixed for the AS
// passkey path (internal/as.PasskeyHandlers.LoginFinish). Two tenants can
// share an OIDC issuer while using different client IDs/audiences or
// different OIDCGate.RequiredClaims per app; the OIDC gate middleware only
// ever validates a token against the HEADER tenant's config, never the
// CREDENTIAL's real tenant's - so FinishLogin must re-check both against the
// credential's real tenant, and the handler must actually populate
// OIDCGateBinding.Audience/.Claims for that check to have anything to work
// with. These tests exercise the real HTTP handler + real
// service.WebAuthnService + a real WebAuthn ceremony (not mocks), the same
// way internal/service/webauthn_test.go's OIDCGate tests do, mirroring
// TestWebAuthnService_FinishLogin_OIDCGate_WrongAudience/
// RequiredClaimsMismatch but through FinishWebAuthnLogin's own wiring.

const (
	loginGateTestRPID     = "localhost"
	loginGateTestRPName   = "Test App"
	loginGateTestRPOrigin = "http://localhost:8080"
	loginGateTestIssuer   = "https://idp.example.com"
)

// loginGateTestSetup registers one WebAuthn credential for the given tenant
// (via the real service, not HTTP - registration itself isn't what's under
// test here) and returns everything needed to exercise FinishWebAuthnLogin
// through the real HTTP handler with a fake OIDC-gate-result/tenant context
// injector standing in for TenantHeaderMiddleware + OIDCGateMiddleware
// (which need a live IdP/JWKS server to drive for real).
type loginGateTestSetup struct {
	handlers      *Handlers
	store         *memory.Store
	rp            virtualwebauthn.RelyingParty
	authenticator virtualwebauthn.Authenticator
	credential    virtualwebauthn.Credential
	ctx           context.Context
}

func newLoginGateTestSetup(t *testing.T, credentialTenant *domain.Tenant) *loginGateTestSetup {
	t.Helper()

	cfg := &config.Config{
		Server: config.ServerConfig{
			RPName:   loginGateTestRPName,
			RPID:     loginGateTestRPID,
			RPOrigin: loginGateTestRPOrigin,
		},
		JWT: config.JWTConfig{
			Secret:      "test-jwt-secret-that-is-long-enough-32",
			Issuer:      "test-issuer",
			ExpiryHours: 24,
		},
	}

	store := memory.NewStore()
	logger := zap.NewNop()
	ctx := context.Background()

	require.NoError(t, store.Tenants().Create(ctx, credentialTenant))

	services := service.NewServices(store, cfg, logger)
	require.NotNil(t, services.WebAuthn, "WebAuthn service must be constructed")
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	rp := virtualwebauthn.RelyingParty{ID: loginGateTestRPID, Name: loginGateTestRPName, Origin: loginGateTestRPOrigin}
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserNotVerified: false,
		UserNotPresent:  false,
	})
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Register a user under the credential tenant via the real service.
	beginRegResp, err := services.WebAuthn.BeginRegistration(ctx, &service.BeginRegistrationRequest{
		DisplayName: "Login Gate Test User",
		TenantID:    string(credentialTenant.ID),
	})
	require.NoError(t, err)

	regOptionsJSON, err := json.Marshal(beginRegResp.CreateOptions)
	require.NoError(t, err)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *attestationOptions)

	finishRegResp, err := services.WebAuthn.FinishRegistration(ctx, &service.FinishRegistrationRequest{
		ChallengeID: beginRegResp.ChallengeID,
		Credential:  json.RawMessage(attestationResponse),
		DisplayName: "Login Gate Test User",
	})
	require.NoError(t, err)

	userID := domain.UserIDFromString(finishRegResp.UUID)
	authenticator.Options.UserHandle = domain.EncodeUserHandle(credentialTenant.ID, userID)
	authenticator.AddCredential(credential)

	return &loginGateTestSetup{
		handlers:      handlers,
		store:         store,
		rp:            rp,
		authenticator: authenticator,
		credential:    credential,
		ctx:           ctx,
	}
}

// finishLogin drives a real WebAuthn login ceremony (BeginLogin + assertion)
// through the real HTTP handler, with headerTenant/oidcResult injected into
// context exactly where TenantHeaderMiddleware/OIDCGateMiddleware would put
// them.
func (s *loginGateTestSetup) finishLogin(t *testing.T, headerTenant *domain.Tenant, oidcResult *oidc.ValidationResult) *httptest.ResponseRecorder {
	t.Helper()

	beginLoginResp, err := s.handlers.services.WebAuthn.BeginLogin(s.ctx)
	require.NoError(t, err)

	loginOptionsJSON, err := json.Marshal(beginLoginResp.GetOptions)
	require.NoError(t, err)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)
	assertionResponse := virtualwebauthn.CreateAssertionResponse(s.rp, s.authenticator, s.credential, *assertionOptions)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		if headerTenant != nil {
			c.Set("tenant", headerTenant)
		}
		if oidcResult != nil {
			c.Set(middleware.OIDCGateContextKey, oidcResult)
		}
		c.Next()
	})
	router.POST("/login/finish", s.handlers.FinishWebAuthnLogin)

	body, err := json.Marshal(service.FinishLoginRequest{
		ChallengeID: beginLoginResp.ChallengeID,
		Credential:  json.RawMessage(assertionResponse),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestFinishWebAuthnLogin_OIDCGate_AudienceMismatch(t *testing.T) {
	credentialTenant := &domain.Tenant{
		ID:      domain.TenantID("credential-tenant-aud"),
		Name:    "Credential Tenant",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode:    domain.OIDCGateModeLogin,
			LoginOP: &domain.OIDCProviderConfig{Issuer: loginGateTestIssuer, ClientID: "credential-tenant-client"},
		},
	}
	setup := newLoginGateTestSetup(t, credentialTenant)

	// Header tenant shares the issuer but has a DIFFERENT audience (client ID).
	headerTenant := &domain.Tenant{
		ID:      domain.TenantID("header-tenant-aud"),
		Name:    "Header Tenant",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode:    domain.OIDCGateModeLogin,
			LoginOP: &domain.OIDCProviderConfig{Issuer: loginGateTestIssuer, ClientID: "header-tenant-client"},
		},
	}

	w := setup.finishLogin(t, headerTenant, &oidc.ValidationResult{
		Issuer:  loginGateTestIssuer,
		Subject: "user-1",
	})

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (audience mismatch), got %d: %s", w.Code, w.Body.String())
	}
}

func TestFinishWebAuthnLogin_OIDCGate_AudienceMatch_Success(t *testing.T) {
	credentialTenant := &domain.Tenant{
		ID:      domain.TenantID("credential-tenant-aud-ok"),
		Name:    "Credential Tenant",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode:    domain.OIDCGateModeLogin,
			LoginOP: &domain.OIDCProviderConfig{Issuer: loginGateTestIssuer, ClientID: "shared-client"},
		},
	}
	setup := newLoginGateTestSetup(t, credentialTenant)

	// Header tenant is the SAME tenant here (the common case: header and
	// credential tenant agree), so the audience matches.
	w := setup.finishLogin(t, credentialTenant, &oidc.ValidationResult{
		Issuer:  loginGateTestIssuer,
		Subject: "user-1",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (audience matches), got %d: %s", w.Code, w.Body.String())
	}
}

func TestFinishWebAuthnLogin_OIDCGate_RequiredClaimsMismatch(t *testing.T) {
	credentialTenant := &domain.Tenant{
		ID:      domain.TenantID("credential-tenant-claims"),
		Name:    "Credential Tenant",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode:           domain.OIDCGateModeLogin,
			LoginOP:        &domain.OIDCProviderConfig{Issuer: loginGateTestIssuer, ClientID: "shared-client"},
			RequiredClaims: map[string]interface{}{"role": "admin"},
		},
	}
	setup := newLoginGateTestSetup(t, credentialTenant)

	// Same tenant used as header (so audience matches), but the token's
	// actual claims don't satisfy this tenant's RequiredClaims.
	w := setup.finishLogin(t, credentialTenant, &oidc.ValidationResult{
		Issuer:  loginGateTestIssuer,
		Subject: "user-1",
		Claims:  map[string]interface{}{"role": "user"},
	})

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (required claims mismatch), got %d: %s", w.Code, w.Body.String())
	}
}

func TestFinishWebAuthnLogin_OIDCGate_RequiredClaimsMatch_Success(t *testing.T) {
	credentialTenant := &domain.Tenant{
		ID:      domain.TenantID("credential-tenant-claims-ok"),
		Name:    "Credential Tenant",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode:           domain.OIDCGateModeLogin,
			LoginOP:        &domain.OIDCProviderConfig{Issuer: loginGateTestIssuer, ClientID: "shared-client"},
			RequiredClaims: map[string]interface{}{"role": "admin"},
		},
	}
	setup := newLoginGateTestSetup(t, credentialTenant)

	w := setup.finishLogin(t, credentialTenant, &oidc.ValidationResult{
		Issuer:  loginGateTestIssuer,
		Subject: "user-1",
		Claims:  map[string]interface{}{"role": "admin"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (required claims satisfied), got %d: %s", w.Code, w.Body.String())
	}
}
