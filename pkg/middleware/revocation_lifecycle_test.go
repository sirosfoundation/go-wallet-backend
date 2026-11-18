package middleware

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirosfoundation/go-tokenauth/claims"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// A user revoked in the shared revocation store and the SID-AUTH-06 wallet
// lifecycle cut-off are independent gates in TokenAuthMiddleware; a request
// must pass both. The revoked user's deletion exemption (DELETE
// /user/session) relaxes only the store check, never the cut-off.
func TestTokenAuthMiddleware_RevocationStoreAndLifecycleCutoffBothApply(t *testing.T) {
	v, key, issuer := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{
		"test-tenant": {ID: "test-tenant", Enabled: true},
	}}
	ctx := context.Background()

	type tc struct {
		name         string
		revoked      bool // revoked via the shared store (TokenBlacklist.RevokeUser)
		cutoff       time.Time
		method, path string
		want         int
	}
	stale := time.Now().Add(time.Minute) // the token's iat predates it
	fresh := time.Now().Add(-time.Hour)  // the token's iat postdates it
	cases := []tc{
		{"neither: passes", false, fresh, "GET", "/user/session/account-info", 200},
		{"revoked in store: refused", true, fresh, "GET", "/user/session/account-info", 401},
		{"lifecycle cut-off: refused", false, stale, "GET", "/user/session/account-info", 401},
		{"revoked and behind the cut-off: refused", true, stale, "GET", "/user/session/account-info", 401},
		{"revoked, fresh token, deletion: reachable to complete it", true, fresh, "DELETE", "/user/session", 200},
		{"revoked, token behind the cut-off, deletion: cut-off still refuses", true, stale, "DELETE", "/user/session", 401},
		{"live user behind the cut-off, deletion: refused", false, stale, "DELETE", "/user/session", 401},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := memory.NewStore()
			uid := domain.NewUserID()
			if err := store.Users().Create(ctx, &domain.User{UUID: uid}); err != nil {
				t.Fatal(err)
			}
			if err := store.Users().InvalidateAuthBefore(ctx, uid, c.cutoff); err != nil {
				t.Fatal(err)
			}
			bl := service.NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop())
			if c.revoked {
				if err := bl.RevokeUser(ctx, uid.String()); err != nil {
					t.Fatal(err)
				}
			}
			token := signToken(t, key, issuer, claims.AccessTokenClaims{
				Claims: jwt.Claims{Subject: uid.String(), Audience: jwt.Audience{testTokenAudience}}, TenantID: "test-tenant", TAC: "rwld",
			})
			r := gin.New()
			r.Use(TokenAuthMiddleware(v, tenants, bl, store.Users(), zap.NewNop()))
			ok := func(c *gin.Context) { c.Status(200) }
			r.GET("/user/session/account-info", ok)
			r.DELETE("/user/session", ok)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(c.method, c.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			r.ServeHTTP(w, req)
			if w.Code != c.want {
				t.Fatalf("got %d, want %d: %s", w.Code, c.want, w.Body.String())
			}
		})
	}
}
