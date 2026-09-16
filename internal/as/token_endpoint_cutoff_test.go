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

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

// SID-AUTH-06: a session that predates the user's token cut-off cannot mint a
// fresh bearer token, even when the lifecycle cascade failed to drop it.
func TestTokenEndpoint_SessionPredatingCutoffIsRefused(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "ec.pem")
	f, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	f.Close()
	km, err := NewKeyManager(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	ttl := func(string) time.Duration { return 2 * time.Minute }
	issuer := NewTokenIssuer(km, "test-issuer", ttl)

	users := memory.NewStore().Users()
	uid := domain.NewUserID()
	if err := users.Create(context.Background(), &domain.User{UUID: uid}); err != nil {
		t.Fatal(err)
	}
	sessions := NewMemorySessionStore()
	router := gin.New()
	RegisterTokenEndpoint(router.Group("/auth"), sessions, issuer, AllowAllPolicy{}, ttl, true, tokengate.New(users), zap.NewNop())

	newSession := func(jti string, createdAt time.Time) {
		if err := sessions.Create(context.Background(), &Session{
			JTI: jti, UserID: uid.String(), TenantID: "tenant-1", ACR: "urn:siros:acr:passkey",
			MaxTAC: TAC("rwl"), CreatedAt: createdAt, ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	post := func(jti, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: jti})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	// Explicit timestamps rather than sleeps: the cut-off comparison is at
	// whole seconds (tokengate.IssuedBeforeCutoff).
	cutoff := time.Now().Add(-5 * time.Second)
	newSession("before", cutoff.Add(-5*time.Second))
	if got := post("before", `{"aud":"wallet-backend"}`); got != http.StatusOK {
		t.Fatalf("without a cut-off the session mints a token, got %d", got)
	}

	// The wallet is suspended: the cut-off lands, but the session survives
	// (the cascade's session drop failed and returned ERASURE_INCOMPLETE).
	if err := users.InvalidateAuthBefore(context.Background(), uid, cutoff, "acting-token"); err != nil {
		t.Fatal(err)
	}
	if got := post("before", `{"aud":"wallet-backend"}`); got != http.StatusUnauthorized {
		t.Fatalf("a session predating the cut-off must not mint a token, got %d", got)
	}
	if got := post("before", `{"aud":"wallet-backend","anonymous":true}`); got != http.StatusUnauthorized {
		t.Fatalf("the anonymous path is gated too, got %d", got)
	}

	// A new login after the change works normally.
	newSession("after", time.Now())
	if got := post("after", `{"aud":"wallet-backend"}`); got != http.StatusOK {
		t.Fatalf("a session created after the cut-off mints a token, got %d", got)
	}
}
