package as

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

// The shared revocation store (a revoked user) and the wallet-lifecycle
// cut-off (SID-AUTH-06) are independent gates on the session-cookie token
// path: a session must pass BOTH. Neither may relax the other; in particular
// the deletion-only exemption of a revoked owner does not lift the cut-off.
func TestTokenEndpoint_SessionCookie_RevocationStoreAndLifecycleCutoffBothApply(t *testing.T) {
	gin.SetMode(gin.TestMode)
	issuer := newTestTokenIssuer(t)
	ttl := func(string) time.Duration { return 2 * time.Minute }

	users := memory.NewStore().Users()
	uid := domain.NewUserID()
	if err := users.Create(context.Background(), &domain.User{UUID: uid}); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().Add(-5 * time.Second)
	if err := users.InvalidateAuthBefore(context.Background(), uid, cutoff); err != nil {
		t.Fatal(err)
	}

	type outcome struct {
		name       string
		bl         *fakeBlacklist
		sessionAt  time.Time // session creation relative to the cut-off
		tac        string
		anonymous  bool
		wantStatus int
	}
	before, after := cutoff.Add(-5*time.Second), time.Now()
	revoked := func() *fakeBlacklist { return &fakeBlacklist{revokedUsers: map[string]bool{uid.String(): true}} }
	cases := []outcome{
		{"live user, session after cut-off", &fakeBlacklist{}, after, "d", false, http.StatusOK},
		{"live user, session before cut-off: lifecycle refuses", &fakeBlacklist{}, before, "d", false, http.StatusUnauthorized},
		{"revoked user, session after cut-off, deletion-only token", revoked(), after, "d", false, http.StatusOK},
		{"revoked user, session after cut-off, broader token", revoked(), after, "r", false, http.StatusUnauthorized},
		{"revoked user, session after cut-off, anonymous", revoked(), after, "r", true, http.StatusUnauthorized},
		{"revoked user, session before cut-off: deletion exemption does not lift the cut-off", revoked(), before, "d", false, http.StatusUnauthorized},
		{"store cannot say, session after cut-off", &fakeBlacklist{userErr: errors.New("store down")}, after, "d", false, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessions := NewMemorySessionStore()
			router := gin.New()
			RegisterTokenEndpoint(router.Group("/auth"), TokenEndpointConfig{
				Store: sessions, Issuer: issuer, Policy: AllowAllPolicy{}, TTLFunc: ttl,
				Blacklist: tc.bl, InsecureCookies: true, Gate: tokengate.New(users), Logger: zap.NewNop(),
			})
			if err := sessions.Create(context.Background(), &Session{
				JTI: "s", UserID: uid.String(), TenantID: "tenant-1", ACR: "urn:siros:acr:passkey",
				MaxTAC: TAC("rwld"), CreatedAt: tc.sessionAt, ExpiresAt: time.Now().Add(time.Hour),
			}); err != nil {
				t.Fatal(err)
			}
			body := `{"aud":"wallet-backend","tac":"` + tc.tac + `"`
			if tc.anonymous {
				body += `,"anonymous":true`
			}
			req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body+"}"))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "s"})
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}
