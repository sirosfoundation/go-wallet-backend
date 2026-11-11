package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirosfoundation/go-tokenauth/claims"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

// storeReads counts every per-user lookup the middleware makes.
type storeReads struct{ n int }

func (s *storeReads) IsBlacklisted(context.Context, string) (bool, error) { return false, nil }
func (s *storeReads) IsUserRevoked(context.Context, string) (bool, error) { s.n++; return false, nil }
func (s *storeReads) GetAuthCutoff(context.Context, domain.UserID) (time.Time, error) {
	s.n++
	return time.Time{}, storage.ErrNotFound
}
func (s *storeReads) GetDeletionTombstone(context.Context, string) (*domain.DeletionTombstone, error) {
	s.n++
	return nil, storage.ErrNotFound
}

// The AS's pseudonymous engine token (sub = p-<uuid>, tac capped at "ri") names
// no user: it reaches no per-user store, gets no user_id, and so is refused by
// RequireUser exactly like an anonymous token.
func TestTokenAuthMiddleware_PseudonymousTokenNamesNoUser(t *testing.T) {
	v, key, issuer := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{
		"test-tenant": {ID: "test-tenant", Enabled: true},
	}}
	sign := func(sub string) string {
		return signToken(t, key, issuer, claims.AccessTokenClaims{
			Claims:   jwt.Claims{Subject: sub, Audience: jwt.Audience{testTokenAudience}},
			TenantID: "test-tenant",
			TAC:      "ri",
		})
	}
	call := func(token string, reads *storeReads) (int, bool) {
		var sawUser bool
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.Use(TokenAuthMiddleware(v, tenants, reads, reads, zap.NewNop()))
		r.GET("/open", func(c *gin.Context) { _, sawUser = c.Get("user_id"); c.Status(200) })
		r.GET("/wallet", RequireUser(), func(c *gin.Context) { c.Status(200) })
		code := 0
		for _, path := range []string{"/open", "/wallet"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			code = w.Code
		}
		return code, sawUser
	}

	pseudonym := &storeReads{}
	if code, sawUser := call(sign(tokengate.PseudonymPrefix+"6f1c2d3e-0000-4000-8000-000000000000"), pseudonym); code != http.StatusForbidden || sawUser {
		t.Errorf("pseudonymous token: wallet route = %d, user_id set = %v; want 403 and no user_id", code, sawUser)
	}
	if pseudonym.n != 0 {
		t.Errorf("pseudonymous token caused %d per-user store reads, want 0", pseudonym.n)
	}

	named := &storeReads{}
	if code, sawUser := call(sign("user-123"), named); code != http.StatusOK || !sawUser {
		t.Errorf("named token: wallet route = %d, user_id set = %v; want 200 and user_id", code, sawUser)
	}
	if named.n == 0 {
		t.Error("a named user's token must still be checked against the stores")
	}
}
