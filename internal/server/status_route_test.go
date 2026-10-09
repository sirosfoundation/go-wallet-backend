package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4/jwt"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
	"github.com/sirosfoundation/go-wallet-backend/pkg/statuslist"
)

type routeLister struct{ calls int }

func (r *routeLister) List(context.Context, string) (*statuslist.VerifiedList, error) {
	r.calls++
	return &statuslist.VerifiedList{
		Bits: 1, Lst: []byte{0x78, 0x9c, 0x01}, IssuedAt: time.Now().Add(-time.Minute),
		FreshUntil: time.Now().Add(5 * time.Minute), ETag: `"deadbeefdeadbeefdeadbeef"`,
	}, nil
}

// statusRouteProvider is an AuthProvider with a fake-backed status service,
// registered on a fresh router.
func statusRouteProvider(t *testing.T, mutate func(*config.Config)) (*AuthProvider, *gin.Engine, *routeLister, string) {
	t.Helper()
	cfg := minimalTestConfig()
	cfg.StatusCheck = config.StatusCheckConfig{
		Enabled:   true,
		RateLimit: config.AuthRateLimitConfig{Enabled: false},
	}
	if mutate != nil {
		mutate(cfg)
	}
	provider := NewAuthProvider(cfg, newTestMemoryBackend(t), zap.NewNop(), nil)
	t.Cleanup(func() { _ = provider.Close() })
	fake := &routeLister{}
	if cfg.StatusCheck.Enabled {
		provider.services.Status = service.NewStatusServiceWithLister(fake, cfg.StatusCheck, zap.NewNop())
	}
	router := gin.New()
	provider.RegisterRoutes(router)
	return provider, router, fake, createLegacyTestToken(cfg.JWT.Secret, "user-status", "default", "jti-status")
}

func postLists(router *gin.Engine, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/status/v1/lists", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

const oneList = `{"lists":[{"uri":"https://status.example/l/1"}]}`

func TestAuthProvider_StatusRoute_AuthenticatedAndCacheable(t *testing.T) {
	_, router, fake, token := statusRouteProvider(t, nil)
	if !hasRoute(router.Routes(), http.MethodPost, "/status/v1/lists") {
		t.Fatal("POST /status/v1/lists is not registered")
	}

	// No token: 401, and the handler never ran.
	if w := postLists(router, "", oneList); w.Code != http.StatusUnauthorized || fake.calls != 0 {
		t.Fatalf("anonymous: status = %d calls = %d, want 401 and no fetch", w.Code, fake.calls)
	}

	w := postLists(router, token, oneList)
	if w.Code != http.StatusOK || fake.calls != 1 {
		t.Fatalf("authenticated: status = %d calls = %d body = %s", w.Code, fake.calls, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"state":"verified"`) {
		t.Fatalf("body = %s", w.Body.String())
	}
	// NoCacheMiddleware must NOT be applied: the response is privately cacheable.
	if cc := w.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "private, max-age=") || cc == middleware.NoCacheControlValue {
		t.Fatalf("Cache-Control = %q", cc)
	}
	if w.Header().Get("Pragma") != "" || w.Header().Get("Expires") != "" {
		t.Fatalf("NoCacheMiddleware headers present: %v", w.Header())
	}
}

func TestAuthProvider_StatusRoute_DisabledIs503(t *testing.T) {
	_, router, _, token := statusRouteProvider(t, func(c *config.Config) { c.StatusCheck.Enabled = false })
	w := postLists(router, token, oneList)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "STATUS_NOT_SUPPORTED") {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
}

func TestAuthProvider_StatusRoute_RateLimited(t *testing.T) {
	_, router, fake, token := statusRouteProvider(t, func(c *config.Config) {
		c.StatusCheck.RateLimit = config.AuthRateLimitConfig{Enabled: true, MaxAttempts: 2, WindowSeconds: 3600, LockoutSeconds: 60}
	})
	var last *httptest.ResponseRecorder
	for i := 0; i < 6; i++ {
		last = postLists(router, token, oneList)
	}
	if last.Code != http.StatusTooManyRequests || !strings.Contains(last.Body.String(), "RATE_LIMIT_EXCEEDED") {
		t.Fatalf("status = %d body = %s", last.Code, last.Body.String())
	}
	if last.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q", last.Header().Get("Retry-After"))
	}
	if fake.calls >= 6 {
		t.Fatalf("rate-limited requests reached the service (%d calls)", fake.calls)
	}
	// Another caller has its own bucket.
	other := createLegacyTestToken("test-secret-key", "someone-else", "default", "jti-other")
	if w := postLists(router, other, oneList); w.Code != http.StatusOK {
		t.Fatalf("other caller: %d %s", w.Code, w.Body.String())
	}
}

func TestAuthProvider_StatusRoute_AudienceAndTAC(t *testing.T) {
	v, key, issuer := setupServerTokenValidatorTest(t)
	provider := newTestBackendProviderWithValidator(t, v)
	fake := &routeLister{}
	provider.auth.cfg.StatusCheck = config.StatusCheckConfig{Enabled: true}
	provider.auth.services.Status = service.NewStatusServiceWithLister(fake, provider.auth.cfg.StatusCheck, zap.NewNop())
	router := gin.New()
	provider.RegisterRoutes(router)

	tok := func(aud, tac string) string {
		return signServerToken(t, key, issuer, claims.AccessTokenClaims{
			Claims:   jwt.Claims{Subject: "user-123", Audience: jwt.Audience{aud}},
			TenantID: string(domain.DefaultTenantID), TAC: claims.TAC(tac), ACR: "urn:siros:acr:passkey",
		})
	}
	// Authenticated callers only: an identity-free anonymous token is refused.
	if w := postLists(router, tok("wallet-registry", "r"), oneList); w.Code != http.StatusForbidden || fake.calls != 0 {
		t.Fatalf("wallet-registry token: %d %s", w.Code, w.Body.String())
	}
	// "r" is required.
	if w := postLists(router, tok("wallet-backend", "w"), oneList); w.Code != http.StatusForbidden || fake.calls != 0 {
		t.Fatalf("token without r: %d %s", w.Code, w.Body.String())
	}
	if w := postLists(router, tok("wallet-backend", "r"), oneList); w.Code != http.StatusOK || fake.calls != 1 {
		t.Fatalf("wallet-backend token with r: %d %s", w.Code, w.Body.String())
	}
}
