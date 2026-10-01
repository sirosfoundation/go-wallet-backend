package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4/jwt"
	legacyjwt "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// Anonymous tokens (no user) are for registry lookups and public metadata.
// Every route that acts on a wallet, an account or a tenant's configuration
// on a user's behalf must refuse them; the lookups keep working.

// anonymousOKPrefixes are routes an anonymous token may use, or that take no
// bearer token at all. Every other route the providers register must be
// wallet-scoped and refuse an anonymous token; a new route that is in neither
// list fails the test until somebody classifies it.
var anonymousOKPrefixes = []string{
	"/v1/",                                              // AuthZEN trust evaluation/resolution: registry lookups
	"/user/register-webauthn-", "/user/login-webauthn-", // no bearer token
	"/user/session/refresh",        // the refresh token is the credential
	"/tenant/", "/api/v1/tenants/", // public tenant configuration
	"/helper/auth-check",      // checks a token, acts for nobody
	"/.well-known/", "/auth/", // public metadata, AS endpoints (cookie/public)
	"/wallet-provider/status-list", // public Token Status List, no bearer token
	"/registry/",                   // registry lookups (own middleware)
}

func isAnonymousOK(path string) bool {
	for _, p := range anonymousOKPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func concretePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		if strings.HasPrefix(s, ":") || strings.HasPrefix(s, "*") {
			parts[i] = "x"
		}
	}
	return strings.Join(parts, "/")
}

// walletScopedRoutes returns every registered route that is not classified as
// anonymous-OK, failing the test for a route that looks public but is not
// classified (there is nothing to tell them apart but the list).
func walletScopedRoutes(t *testing.T, router *gin.Engine) []gin.RouteInfo {
	t.Helper()
	var out []gin.RouteInfo
	for _, r := range router.Routes() {
		if !isAnonymousOK(r.Path) {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		t.Fatal("no wallet-scoped routes found - the test would pass vacuously")
	}
	return out
}

func anonymousConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := minimalTestConfig()
	cfg.Features.ProxyEnabled = true
	cfg.Features.CredentialStorageEnabled = true
	keyPath, certPath := writeTestECKeyAndCert(t, t.TempDir(), "wallet-provider")
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath
	cfg.WalletProvider.WIA.Enabled = true
	cfg.WalletProvider.WIA.RateLimit = config.AuthRateLimitConfig{Enabled: false}
	return cfg
}

func serve(router *gin.Engine, method, path, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	return w
}

func refusedAsAnonymous(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), middleware.AnonymousTokenMessage)
}

func assertAnonymousRefusedEverywhere(t *testing.T, router *gin.Engine, anonymous, user string) {
	t.Helper()
	for _, r := range walletScopedRoutes(t, router) {
		path := concretePath(r.Path)
		if w := serve(router, r.Method, path, anonymous); !refusedAsAnonymous(w) {
			t.Errorf("%s %s: anonymous token got %d %s, want 403 %q", r.Method, path, w.Code, w.Body.String(), middleware.AnonymousTokenMessage)
		}
		// Control: the same route is reachable with a token that names a user
		// (whatever the handler then answers), so the refusal above is the
		// anonymous check and not a dead route.
		if w := serve(router, r.Method, path, user); refusedAsAnonymous(w) {
			t.Errorf("%s %s: a token naming a user was refused as anonymous", r.Method, path)
		}
	}
}

func TestAnonymousTokens_RefusedOnEveryWalletScopedRoute_TokenAuth(t *testing.T) {
	v, key, issuer := setupServerTokenValidatorTest(t)
	cfg := anonymousConfig(t)
	store := newTestMemoryBackend(t)

	authProvider := NewAuthProvider(cfg, store, zap.NewNop(), nil)
	defer func() { _ = authProvider.Close() }()
	authProvider.tokenValidator = v
	storageProvider := NewStorageProvider(cfg, store, zap.NewNop(), nil)
	storageProvider.tokenValidator = v
	provider := &BackendProvider{
		auth: authProvider, storage: storageProvider, store: store, cfg: cfg,
		authzenHandler: newTestAuthZENHandler(cfg, zap.NewNop()), tokenValidator: v, logger: zap.NewNop(),
	}
	router := gin.New()
	provider.RegisterRoutes(router)

	aud := jwt.Audience{"wallet-backend", "wallet-registry"}
	anonymous := signServerToken(t, key, issuer, claims.AccessTokenClaims{
		Claims: jwt.Claims{Audience: aud}, TenantID: string(domain.DefaultTenantID), TAC: "rl", ACR: "urn:siros:acr:passkey",
	})
	user := signServerToken(t, key, issuer, claims.AccessTokenClaims{
		Claims: jwt.Claims{Subject: "user-123", Audience: aud}, TenantID: string(domain.DefaultTenantID), TAC: "rwlid", ACR: "urn:siros:acr:passkey",
	})
	assertAnonymousRefusedEverywhere(t, router, anonymous, user)

	// The registry lookups keep working for an anonymous token.
	for _, path := range []string{"/v1/evaluate", "/v1/resolve"} {
		if w := serve(router, http.MethodPost, path, anonymous); w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized || w.Code == http.StatusNotFound {
			t.Errorf("POST %s: anonymous token got %d %s, want it to reach the handler", path, w.Code, w.Body.String())
		}
	}
}

func TestAnonymousTokens_RefusedOnEveryWalletScopedRoute_Legacy(t *testing.T) {
	cfg := anonymousConfig(t)
	store := newTestMemoryBackend(t)

	authProvider := NewAuthProvider(cfg, store, zap.NewNop(), nil)
	defer func() { _ = authProvider.Close() }()
	storageProvider := NewStorageProvider(cfg, store, zap.NewNop(), nil)
	router := gin.New()
	authProvider.RegisterRoutes(router)
	storageProvider.RegisterRoutes(router)

	mint := func(userID string) string {
		tok, err := legacyjwt.NewWithClaims(legacyjwt.SigningMethodHS256, legacyjwt.MapClaims{
			"user_id": userID, "tenant_id": string(domain.DefaultTenantID),
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString([]byte(cfg.JWT.Secret))
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	assertAnonymousRefusedEverywhere(t, router, mint(""), mint("user-123"))
}

func TestAnonymousTokens_RefusedOnEveryWalletScopedRoute_StandaloneWalletProvider(t *testing.T) {
	v, key, issuer := setupServerTokenValidatorTest(t)
	cfg := anonymousConfig(t)
	cfg.JWT.Secret = "test-secret-that-is-at-least-32-bytes!"

	p, err := NewWalletProviderProvider(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewWalletProviderProvider: %v", err)
	}
	defer func() { _ = p.Close() }()
	p.tokenValidator = v
	router := gin.New()
	p.RegisterRoutes(router)

	aud := jwt.Audience{"wallet-backend"}
	anonymous := signServerToken(t, key, issuer, claims.AccessTokenClaims{
		Claims: jwt.Claims{Audience: aud}, TenantID: string(domain.DefaultTenantID), TAC: "rl", ACR: "urn:siros:acr:passkey",
	})
	user := signServerToken(t, key, issuer, claims.AccessTokenClaims{
		Claims: jwt.Claims{Subject: "user-123", Audience: aud}, TenantID: string(domain.DefaultTenantID), TAC: "rwlid", ACR: "urn:siros:acr:passkey",
	})
	assertAnonymousRefusedEverywhere(t, router, anonymous, user)
}

var _ = tokenvalidator.Config{}
