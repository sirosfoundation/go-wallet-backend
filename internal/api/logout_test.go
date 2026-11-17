package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	gojose "github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	tokenauthclaims "github.com/sirosfoundation/go-tokenauth/claims"
	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// setupLogoutTestHandlers is like setupTestHandlers but with the token
// blacklist enabled - setupTestHandlers leaves it at its zero-value
// (disabled) default, which would make every blacklist check in these
// tests a silent no-op.
func setupLogoutTestHandlers(t *testing.T) (*Handlers, *gin.Engine) {
	t.Helper()
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
			RPName:   "Test Wallet",
		},
		JWT: config.JWTConfig{
			Secret: "test-secret",
			Issuer: "test-wallet",
		},
		Security: config.SecurityConfig{
			TokenBlacklist: config.TokenBlacklistConfig{Enabled: true},
		},
	}

	store := memory.NewStore()
	services := service.NewServices(store, cfg, logger)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	return handlers, gin.New()
}

// TestHandlers_Logout_NoToken proves logging out with no token present
// (already logged out, or never authenticated) is a harmless 200 - not an
// error.
func TestHandlers_Logout_NoToken(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)
	router.POST("/logout", handlers.Logout)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandlers_Logout_ASToken: when the request was authenticated via go-tokenauth ("tokenauth_result"
// in context), Logout blacklists the jti from that validated result (the raw token cannot be re-parsed).
func TestHandlers_Logout_ASToken(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)

	result := &tokenauthclaims.Result{
		UserID: "user-1",
		JTI:    "jti-as-logout",
		Mode:   tokenauthclaims.ModeSession,
	}

	router.POST("/logout", func(c *gin.Context) {
		c.Set("token", "an-opaque-es256-token")
		c.Set("tokenauth_result", result)
		c.Next()
	}, handlers.Logout)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !blacklisted(t, handlers.services.TokenBlacklist, context.Background(), "jti-as-logout") {
		t.Error("expected the AS-issued token's jti to be blacklisted via tokenauth_result")
	}
}

// A raw HMAC token in the context without a validated tokenauth_result is never parsed: Logout revokes nothing.
func TestHandlers_Logout_HMACTokenWithoutValidatedResultRevokesNothing(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)

	hmacToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "user-1",
		"jti":     "jti-hmac-logout",
		"exp":     time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	router.POST("/logout", func(c *gin.Context) {
		c.Set("token", hmacToken)
		c.Next()
	}, handlers.Logout)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/logout", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if blacklisted(t, handlers.services.TokenBlacklist, context.Background(), "jti-hmac-logout") {
		t.Error("an HMAC token must not be parsed or blacklisted by Logout any more")
	}
}

// TestMaxConfiguredASTokenTTL proves the #391 review fix (round 2): the
// blacklist entry Logout creates for an AS-issued token is sized from the
// AS's own configured TTLs, not a fixed guess that an operator's
// AudienceTTLs/DefaultTokenTTL could exceed.
func TestMaxConfiguredASTokenTTL(t *testing.T) {
	cfg := &config.Config{
		AS: config.ASConfig{
			DefaultTokenTTL: 2 * time.Minute,
			AudienceTTLs: map[string]time.Duration{
				"wallet-backend": time.Minute,
				"wallet-engine":  48 * time.Hour, // longer than the old fixed 24h fallback
			},
		},
	}

	got := maxConfiguredASTokenTTL(cfg)
	want := 48 * time.Hour
	if got != want {
		t.Errorf("maxConfiguredASTokenTTL() = %v, want %v", got, want)
	}
}

func TestMaxConfiguredASTokenTTL_NoAudienceOverrides(t *testing.T) {
	cfg := &config.Config{
		AS: config.ASConfig{DefaultTokenTTL: 2 * time.Minute},
	}

	got := maxConfiguredASTokenTTL(cfg)
	want := 2 * time.Minute
	if got != want {
		t.Errorf("maxConfiguredASTokenTTL() = %v, want %v", got, want)
	}
}

// revocationReader is the check half of a revocation checker.
type revocationReader interface {
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
	IsUserRevoked(ctx context.Context, userID string) (bool, error)
}

func blacklisted(t *testing.T, r revocationReader, ctx context.Context, jti string) bool {
	t.Helper()
	ok, err := r.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	return ok
}

// flakyAddStore is a RevocationStore whose Add fails while failing is set.
type flakyAddStore struct {
	failing bool
	jtis    map[string]bool
}

func (s *flakyAddStore) Add(_ context.Context, jti string, _ time.Time) error {
	if s.failing {
		return errors.New("store write failed")
	}
	s.jtis[jti] = true
	return nil
}
func (s *flakyAddStore) Has(_ context.Context, jti string) (bool, error) { return s.jtis[jti], nil }
func (s *flakyAddStore) RevokeUser(context.Context, string) error        { return nil }
func (s *flakyAddStore) IsUserRevoked(context.Context, string) (bool, error) {
	return false, nil
}

// A failed jti blacklist write fails the logout (500) instead of being
// logged; the retry then succeeds.
func TestLogout_FailedJTIBlacklistWrite_FailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "wallet.example.com"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, Issuer: "test-wallet"},
	}
	store := &flakyAddStore{failing: true, jtis: map[string]bool{}}
	services := service.NewServices(memory.NewStore(), cfg, logger)
	services.TokenBlacklist = service.NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, logger, store)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	router := gin.New()
	router.POST("/logout", func(c *gin.Context) {
		c.Set("tokenauth_result", &tokenauthclaims.Result{UserID: "user-1", JTI: "jti-w", Mode: tokenauthclaims.ModeSession})
		c.Next()
	}, handlers.Logout)
	do := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/logout", nil))
		return w
	}

	w := do()
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), "Logged out successfully")
	require.False(t, store.jtis["jti-w"])

	store.failing = false
	require.Equal(t, http.StatusOK, do().Code, "retry")
	require.True(t, store.jtis["jti-w"])
}

type failingRevoker struct{}

func (failingRevoker) RevokeUser(context.Context, string) error {
	return errors.New("store write failed")
}

// A failed user-revocation write answers 500 and leaves the user in place.
func TestDeleteUser_RevocationFailureAnswers500(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "localhost", RPOrigin: "http://localhost:8080"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, Issuer: "test"},
	}
	services := service.NewServices(memory.NewStore(), cfg, logger)
	services.User.SetTokenBlacklist(failingRevoker{})
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	name := "del-user"
	user, err := services.User.Register(context.Background(), &domain.RegisterRequest{Username: &name, DisplayName: "d", WalletType: domain.WalletTypeDB})
	require.NoError(t, err)

	router := gin.New()
	router.DELETE("/user", func(c *gin.Context) { c.Set("user_id", user.UUID.String()); c.Next() }, handlers.DeleteUser)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/user", nil))
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "Failed to revoke tokens")
}

// sessionTokenRig serves a JWKS and signs ES256 session tokens, so a test can
// drive the real go-tokenauth validator and TokenAuthMiddleware.
type sessionTokenRig struct {
	key       *ecdsa.PrivateKey
	validator *tokenvalidator.Validator
}

const rigIssuer, rigAudience = "test-issuer", "wallet-backend"

func newSessionTokenRig(t *testing.T, revocation tokenvalidatorRevocation) *sessionTokenRig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwks := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: string(gojose.ES256)}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	v := tokenvalidator.New(tokenvalidator.Config{
		JWKSURL: srv.URL, Issuer: rigIssuer, Audiences: []string{rigAudience}, Revocation: revocation,
	})
	v.Start(context.Background())
	t.Cleanup(v.Stop)
	r := &sessionTokenRig{key: key, validator: v}
	// Wait until the JWKS is loaded, using a token with a jti the checker
	// does not know.
	probe := r.sign(t, "probe-user", "probe-jti")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := v.Validate(context.Background(), probe); err == nil {
			break
		}
		require.True(t, time.Now().Before(deadline), "validator did not fetch the JWKS in time")
		time.Sleep(10 * time.Millisecond)
	}
	return r
}

func (r *sessionTokenRig) sign(t *testing.T, user, jti string) string {
	t.Helper()
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.ES256, Key: r.key},
		(&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k"))
	require.NoError(t, err)
	now := time.Now()
	raw, err := gojosejwt.Signed(signer).Claims(tokenauthclaims.AccessTokenClaims{
		Claims: gojosejwt.Claims{
			Issuer: rigIssuer, Subject: user, ID: jti, Audience: gojosejwt.Audience{rigAudience},
			IssuedAt: gojosejwt.NewNumericDate(now), NotBefore: gojosejwt.NewNumericDate(now.Add(-time.Second)),
			Expiry: gojosejwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
		TenantID: "default",
	}).Serialize()
	require.NoError(t, err)
	return raw
}

// tokenvalidatorRevocation is go-tokenauth's revocation.Checker.
type tokenvalidatorRevocation interface {
	IsRevoked(ctx context.Context, jti string) bool
}

// tokenRevocationChecker mirrors internal/server's adapter (which this
// package cannot import): store errors reject, a revoked jti is admitted only
// for the logout call.
type tokenRevocationChecker struct{ bl *service.TokenBlacklist }

func (c tokenRevocationChecker) IsRevoked(ctx context.Context, jti string) bool {
	revoked, err := c.bl.IsBlacklisted(ctx, jti)
	if err != nil {
		return true
	}
	return revoked && !middleware.IsLogoutCompletion(ctx)
}

// lostAckJTIStore applies Add and then reports an error, like a MongoDB
// update whose majority acknowledgement timed out after it was applied.
type lostAckJTIStore struct {
	jtis     map[string]bool
	failNext bool
}

func (s *lostAckJTIStore) Add(_ context.Context, jti string, _ time.Time) error {
	s.jtis[jti] = true
	if s.failNext {
		s.failNext = false
		return errors.New("write concern timeout")
	}
	return nil
}
func (s *lostAckJTIStore) Has(_ context.Context, jti string) (bool, error) { return s.jtis[jti], nil }
func (s *lostAckJTIStore) RevokeUser(context.Context, string) error        { return nil }
func (s *lostAckJTIStore) IsUserRevoked(context.Context, string) (bool, error) {
	return false, nil
}

// logoutRig wires the real TokenAuthMiddleware and go-tokenauth validator in
// front of Logout plus a protected route, around the given jti store.
func logoutRig(t *testing.T, store service.RevocationStore) (router http.Handler, tok string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "wallet.example.com"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, Issuer: "test-wallet"},
	}
	mem := memory.NewStore()
	services := service.NewServices(mem, cfg, logger)
	services.TokenBlacklist = service.NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, logger, store)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	rig := newSessionTokenRig(t, tokenRevocationChecker{services.TokenBlacklist})
	r := gin.New()
	r.Use(middleware.TokenAuthMiddleware(rig.validator, mem.Tenants(), services.TokenBlacklist, logger))
	r.POST("/user/session/logout", handlers.Logout)
	r.GET("/user/session/protected", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r, rig.sign(t, "user-1", "jti-x")
}

func doReq(router http.Handler, method, path, tok string) int {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	router.ServeHTTP(w, req)
	return w.Code
}

// An Add error does not prove the jti write was rejected. When the write was
// applied and only its acknowledgement was lost, the first logout fails but
// the jti is revoked; the retry with the same token must still get through
// the real middleware and validator (middleware.IsLogout) and report success,
// and afterwards the token must be dead everywhere else.
func TestLogout_LostAckJTIWrite_RetryCompletesThroughRealMiddleware(t *testing.T) {
	store := &lostAckJTIStore{jtis: map[string]bool{}, failNext: true}
	router, tok := logoutRig(t, store)

	require.Equal(t, http.StatusInternalServerError, doReq(router, http.MethodPost, "/user/session/logout", tok))
	require.True(t, store.jtis["jti-x"], "the write was applied despite the error")
	require.Equal(t, http.StatusUnauthorized, doReq(router, http.MethodGet, "/user/session/protected", tok),
		"a revoked jti is refused everywhere except the logout call")

	require.Equal(t, http.StatusOK, doReq(router, http.MethodPost, "/user/session/logout", tok), "retry")
	require.Equal(t, http.StatusOK, doReq(router, http.MethodPost, "/user/session/logout", tok), "logout is idempotent")
	require.Equal(t, http.StatusUnauthorized, doReq(router, http.MethodGet, "/user/session/protected", tok))
}

// userStore records a user revocation and fails the first write anyway, like
// a MongoDB write whose majority acknowledgement was lost after it applied.
type lostAckUserStore struct {
	users    map[string]bool
	failNext bool
}

func (s *lostAckUserStore) Add(context.Context, string, time.Time) error { return nil }
func (s *lostAckUserStore) Has(context.Context, string) (bool, error)    { return false, nil }
func (s *lostAckUserStore) RevokeUser(_ context.Context, id string) error {
	s.users[id] = true
	if s.failNext {
		s.failNext = false
		return errors.New("write concern timeout")
	}
	return nil
}
func (s *lostAckUserStore) IsUserRevoked(_ context.Context, id string) (bool, error) {
	return s.users[id], nil
}

// A revocation that was stored although its write reported an error leaves
// the user revoked but undeleted; the retry must still reach the deletion
// through the real auth middleware, and other routes must stay closed to the
// revoked user.
func TestDeleteUser_LostAckRevocation_RetryCompletesThroughRealMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "wallet.example.com"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, Issuer: "test-wallet"},
	}
	mem := memory.NewStore()
	rs := &lostAckUserStore{users: map[string]bool{}, failNext: true}
	services := service.NewServices(mem, cfg, logger)
	bl := service.NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, logger, rs)
	services.TokenBlacklist = bl
	services.User.SetTokenBlacklist(bl)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	name := "lost-ack"
	user, err := services.User.Register(context.Background(), &domain.RegisterRequest{Username: &name, DisplayName: "d", WalletType: domain.WalletTypeDB})
	require.NoError(t, err)

	rig := newSessionTokenRig(t, tokenRevocationChecker{bl})
	router := gin.New()
	router.Use(middleware.TokenAuthMiddleware(rig.validator, mem.Tenants(), bl, logger))
	router.DELETE("/user/session", handlers.DeleteUser)
	router.GET("/user/session/account-info", func(c *gin.Context) { c.Status(http.StatusOK) })

	tok := rig.sign(t, user.UUID.String(), "jti-d")

	require.Equal(t, http.StatusInternalServerError, doReq(router, http.MethodDelete, "/user/session", tok))
	_, err = mem.Users().GetByID(context.Background(), user.UUID)
	require.NoError(t, err, "the user survives the failed attempt")
	require.True(t, rs.users[user.UUID.String()], "precondition: the revocation was stored")

	require.Equal(t, http.StatusUnauthorized, doReq(router, http.MethodGet, "/user/session/account-info", tok), "a revoked user stays locked out of every other route")
	require.Equal(t, http.StatusOK, doReq(router, http.MethodDelete, "/user/session", tok), "the retry completes the deletion")
	_, err = mem.Users().GetByID(context.Background(), user.UUID)
	require.Error(t, err, "the user is deleted")
}
