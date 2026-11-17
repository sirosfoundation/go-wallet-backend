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
	"github.com/golang-jwt/jwt/v5"
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

// A legacy HMAC token (HS256, jwt.secret, jwt.issuer) must not authenticate through the
// session auth middleware of a real ASModule, with or without the session cookie.
func TestNewASModule_LegacyHMACBearerRejected(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestSigningKey(t, dir)
	cfg := &config.ASConfig{
		SigningKeyPath: keyPath,
		Issuer:         "https://as.example.com",
		ExternalURL:    "https://as.example.com",
	}
	cfg.SetDefaults()
	jwtCfg := &config.JWTConfig{Secret: "test-secret-that-is-at-least-32-bytes!", Issuer: "test-issuer"}

	m, err := NewASModule(context.Background(), cfg, jwtCfg, nil, memory.NewStore(), nil, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("NewASModule() error = %v", err)
	}

	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": jwtCfg.Issuer, "aud": "rp", "sub": "user-1", "user_id": "user-1",
		"tenant_id": "t", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(jwtCfg.Secret))
	if err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(SessionAuthMiddleware(m.Sessions, m.TokenIssuer, []string{"rp"}, true, zap.NewNop()))
	router.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("legacy bearer must be rejected for authentication, got %d", w.Code)
	}
}
