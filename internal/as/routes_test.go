package as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// writeTestSigningKey writes a fresh EC P-256 private key PEM to a temp
// file, for constructing a KeyManager/TokenIssuer in tests.
func writeTestSigningKey(t *testing.T, dir string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "as-key.pem")
	f, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return keyPath
}

// TestNewASModule_WiresBlacklistAndRegistersRoutes is a direct,
// package-local test of NewASModule/RegisterRoutes (previously entirely
// untested within this package - only exercised indirectly, and therefore
// uncounted, via internal/server's NewBackendProvider tests). Proves the
// Blacklist passed in reaches the registered /auth/token route, and that
// the route set includes the endpoints RegisterRoutes documents.
func TestNewASModule_WiresBlacklistAndRegistersRoutes(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestSigningKey(t, dir)

	cfg := &config.ASConfig{
		SigningKeyPath: keyPath,
		Issuer:         "https://as.example.com",
		ExternalURL:    "https://as.example.com",
		Legacy:         config.ASLegacyConfig{Enabled: true},
	}
	cfg.SetDefaults()
	jwtCfg := &config.JWTConfig{Secret: "test-secret-that-is-at-least-32-bytes!", Issuer: "test-issuer"}

	store := memory.NewStore()
	blacklist := &fakeBlacklist{revoked: map[string]bool{"jti-revoked": true}}

	m, err := NewASModule(context.Background(), cfg, jwtCfg, nil, store, blacklist, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("NewASModule() error = %v", err)
	}
	if m.Blacklist != blacklist {
		t.Error("expected ASModule.Blacklist to be the instance passed to NewASModule")
	}

	router := gin.New()
	authGroup := router.Group("/auth")
	m.RegisterRoutes(authGroup)

	routes := router.Routes()
	wantPaths := map[string]string{
		"/auth/.well-known/jwks.json": http.MethodGet,
		"/auth/passkey/login/begin":   http.MethodPost,
		"/auth/oidc/login":            http.MethodGet,
		"/auth/token":                 http.MethodPost,
		"/auth/session":               http.MethodDelete,
	}
	for path, method := range wantPaths {
		found := false
		for _, r := range routes {
			if r.Path == path && r.Method == method {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected route %s %s to be registered", method, path)
		}
	}

	// Exercise the delegation-exchange path end-to-end through the real
	// route registration, proving the Blacklist wired via NewASModule
	// actually reaches the /auth/token handler (see #382/#383): a
	// non-revoked parent token successfully delegates...
	parentToken, err := m.TokenIssuer.Issue("user-1", "api", "tenant-1", TAC("rwlk"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	body := `{"aud":"downstream-api","tac":"r"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+parentToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delegation with non-revoked parent: status = %d, body = %s", w.Code, w.Body.String())
	}

	// ...while one whose jti this test's Blacklist already knows about is
	// rejected (jti-specific rejection is covered in depth by
	// token_endpoint_test.go; this just proves the same Blacklist instance
	// is reachable via the real route, not a substitute built internally).
	parentClaims, err := m.TokenIssuer.ParseAndVerify(parentToken, nil)
	if err != nil {
		t.Fatalf("ParseAndVerify: %v", err)
	}
	blacklist.revoked[parentClaims.ID] = true

	req = httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+parentToken)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("delegation with revoked parent: status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// TestNewASModule_LegacyIssuerUsesJWTIssuerNotASIssuer proves the #391
// review fix (round 3): m.LegacyIssuer must validate legacy appTokens
// against jwtCfg.Issuer, not cfg.Issuer (the AS's own, separately
// configurable, asymmetric-token issuer identity) - a real legacy appToken
// (as minted by UserService/WebAuthnService's generateToken) always
// carries "iss": jwtCfg.Issuer, never cfg.Issuer. This test deliberately
// configures the two differently, mirroring the deployment shape the
// review flagged.
func TestNewASModule_LegacyIssuerUsesJWTIssuerNotASIssuer(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestSigningKey(t, dir)

	cfg := &config.ASConfig{
		SigningKeyPath: keyPath,
		Issuer:         "https://as.example.com", // deliberately different from jwtCfg.Issuer below
		ExternalURL:    "https://as.example.com",
		Legacy:         config.ASLegacyConfig{Enabled: true},
	}
	cfg.SetDefaults()
	jwtCfg := &config.JWTConfig{
		Secret:      "test-secret-that-is-at-least-32-bytes!",
		Issuer:      "test-wallet-backend-issuer",
		ExpiryHours: 24,
	}

	store := memory.NewStore()
	m, err := NewASModule(context.Background(), cfg, jwtCfg, nil, store, nil, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("NewASModule() error = %v", err)
	}
	if m.LegacyIssuer == nil {
		t.Fatal("expected LegacyIssuer to be constructed (Legacy.Enabled=true)")
	}

	// Simulate a real legacy appToken exactly as UserService/WebAuthnService
	// mint one: signed with the same secret, "iss" = jwtCfg.Issuer.
	legacyAppTokenIssuer := NewLegacyTokenIssuer([]byte(jwtCfg.Secret), jwtCfg.Issuer, time.Hour)
	appToken, err := legacyAppTokenIssuer.Issue("user-1", "did:key:user-1", "tenant-1", "test-rp")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := m.LegacyIssuer.Validate(appToken); err != nil {
		t.Errorf("expected a real legacy appToken (iss=jwtCfg.Issuer) to validate against m.LegacyIssuer, got: %v", err)
	}
}
