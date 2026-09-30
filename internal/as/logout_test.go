package as

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestLogoutHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	// Create a session.
	sess := &Session{
		JTI:       "sess-logout",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	router := gin.New()
	router.DELETE("/auth/session", LogoutHandler(store, nil, nil, nil, time.Hour, true, logger))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-logout"})
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}

	// Session should be revoked.
	s, _ := store.Get(context.Background(), "sess-logout")
	if s == nil {
		t.Fatal("session should still exist (revoked, not deleted)")
	}
	if !s.Revoked {
		t.Error("expected session to be revoked")
	}

	// Cookie should be cleared (MaxAge=-1).
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieInsecure && c.MaxAge < 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected session cookie to be cleared")
	}
}

func TestLogoutHandler_NoSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	router := gin.New()
	router.DELETE("/auth/session", LogoutHandler(store, nil, nil, nil, time.Hour, true, logger))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestLogoutHandler_BlacklistsPresentedBearerToken proves the #391 review
// fix: logging out doesn't just revoke the session (which only prevents
// minting NEW tokens from it) - it also blacklists the specific bearer
// access token presented alongside the session cookie, closing the gap
// where a delegation-capable token could otherwise keep re-delegating
// itself indefinitely after "logout" (delegation needs no live session at
// all).
func TestLogoutHandler_BlacklistsPresentedBearerToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	sess := &Session{
		JTI:       "sess-logout-2",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	issuer := newTestTokenIssuer(t)
	accessToken, err := issuer.Issue("user-1", "api", "tenant-1", TAC("rwlk"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatal(err)
	}
	parentClaims, err := issuer.ParseAndVerify(accessToken, nil)
	if err != nil {
		t.Fatal(err)
	}

	blacklist := &fakeBlacklist{}

	router := gin.New()
	router.DELETE("/auth/session", LogoutHandler(store, issuer, nil, blacklist, time.Hour, true, logger))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-logout-2"})
	req.Header.Set("Authorization", "Bearer "+accessToken)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	if !blacklist.IsBlacklisted(context.Background(), parentClaims.ID) {
		t.Error("expected the presented bearer token's jti to be blacklisted on logout")
	}
}

// TestLogoutHandler_RefusesToBlacklistOtherUsersToken proves the #391
// review fix (round 2): a caller with their own valid session can't use it
// to blacklist an unrelated user's bearer token by presenting it in the
// Authorization header - that would let anyone hand another user's
// (possibly delegation-capable) token a denial-of-service.
func TestLogoutHandler_RefusesToBlacklistOtherUsersToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	// The session belongs to "user-1"...
	sess := &Session{
		JTI:       "sess-logout-3",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	issuer := newTestTokenIssuer(t)
	// ...but the presented bearer token belongs to "user-2".
	otherUsersToken, err := issuer.Issue("user-2", "api", "tenant-1", TAC("rwlk"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatal(err)
	}
	otherUsersClaims, err := issuer.ParseAndVerify(otherUsersToken, nil)
	if err != nil {
		t.Fatal(err)
	}

	blacklist := &fakeBlacklist{}

	router := gin.New()
	router.DELETE("/auth/session", LogoutHandler(store, issuer, nil, blacklist, time.Hour, true, logger))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-logout-3"})
	req.Header.Set("Authorization", "Bearer "+otherUsersToken)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 (session logout still succeeds), got %d: %s", w.Code, w.Body.String())
	}
	if blacklist.IsBlacklisted(context.Background(), otherUsersClaims.ID) {
		t.Error("must not blacklist a bearer token belonging to a different user than the session")
	}
}

// TestLogoutHandler_BlacklistsLegacyBearerToken proves the #391 review fix
// (round 2): a legacy HMAC bearer token presented alongside the session
// cookie is blacklisted too, not just an asymmetric AS-issued one -
// PasskeyHandlers can mint either kind alongside the same kind of session.
func TestLogoutHandler_BlacklistsLegacyBearerToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	sess := &Session{
		JTI:       "sess-logout-4",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	legacyIssuer := NewLegacyTokenIssuer([]byte("test-legacy-secret-32-bytes-long!"), "test-issuer", time.Hour)
	legacyToken, err := legacyIssuer.Issue("user-1", "did:key:user-1", "tenant-1", "test-rp")
	if err != nil {
		t.Fatal(err)
	}
	legacyClaims, err := legacyIssuer.Validate(legacyToken)
	if err != nil {
		t.Fatal(err)
	}

	blacklist := &fakeBlacklist{}

	router := gin.New()
	// issuer (the asymmetric one) is nil here to simulate its
	// ParseAndVerify failing on a legacy-shaped token and falling through
	// to the legacy issuer, without needing a real mismatched key.
	router.DELETE("/auth/session", LogoutHandler(store, nil, legacyIssuer, blacklist, time.Hour, true, logger))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-logout-4"})
	req.Header.Set("Authorization", "Bearer "+legacyToken)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if !blacklist.IsBlacklisted(context.Background(), legacyClaims.ID) {
		t.Error("expected the legacy bearer token's jti to be blacklisted on logout")
	}
}

// TestLogoutHandler_RefusesToBlacklistOtherUsersLegacyToken is the legacy
// -issuer counterpart of TestLogoutHandler_RefusesToBlacklistOtherUsersToken.
func TestLogoutHandler_RefusesToBlacklistOtherUsersLegacyToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	sess := &Session{
		JTI:       "sess-logout-5",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	legacyIssuer := NewLegacyTokenIssuer([]byte("test-legacy-secret-32-bytes-long!"), "test-issuer", time.Hour)
	otherUsersToken, err := legacyIssuer.Issue("user-2", "did:key:user-2", "tenant-1", "test-rp")
	if err != nil {
		t.Fatal(err)
	}
	otherUsersClaims, err := legacyIssuer.Validate(otherUsersToken)
	if err != nil {
		t.Fatal(err)
	}

	blacklist := &fakeBlacklist{}

	router := gin.New()
	router.DELETE("/auth/session", LogoutHandler(store, nil, legacyIssuer, blacklist, time.Hour, true, logger))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-logout-5"})
	req.Header.Set("Authorization", "Bearer "+otherUsersToken)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if blacklist.IsBlacklisted(context.Background(), otherUsersClaims.ID) {
		t.Error("must not blacklist a legacy bearer token belonging to a different user than the session")
	}
}

// erroringBlacklist wraps fakeBlacklist but makes Add always fail, to
// exercise the "failed to blacklist ... on logout" warn-log paths in
// blacklistOwnBearerToken - which must not turn logout itself into a
// failure (the handler still returns 204).
type erroringBlacklist struct {
	fakeBlacklist
}

func (e *erroringBlacklist) Add(ctx context.Context, jti string, expiry time.Time) error {
	return errors.New("simulated blacklist write failure")
}

// TestLogoutHandler_BlacklistAddErrorDoesNotFailLogout proves a blacklist
// write failure while logging out (asymmetric-token path) is logged but
// doesn't turn session logout itself into a failure.
func TestLogoutHandler_BlacklistAddErrorDoesNotFailLogout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	sess := &Session{
		JTI:       "sess-logout-6",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	issuer := newTestTokenIssuer(t)
	accessToken, err := issuer.Issue("user-1", "api", "tenant-1", TAC("rwlk"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.DELETE("/auth/session", LogoutHandler(store, issuer, nil, &erroringBlacklist{}, time.Hour, true, logger))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-logout-6"})
	req.Header.Set("Authorization", "Bearer "+accessToken)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 even when the blacklist write fails, got %d: %s", w.Code, w.Body.String())
	}
}

// TestLogoutHandler_LegacyBlacklistAddErrorDoesNotFailLogout is the
// legacy-issuer counterpart of the test above.
func TestLogoutHandler_LegacyBlacklistAddErrorDoesNotFailLogout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	sess := &Session{
		JTI:       "sess-logout-7",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	legacyIssuer := NewLegacyTokenIssuer([]byte("test-legacy-secret-32-bytes-long!"), "test-issuer", time.Hour)
	legacyToken, err := legacyIssuer.Issue("user-1", "did:key:user-1", "tenant-1", "test-rp")
	if err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.DELETE("/auth/session", LogoutHandler(store, nil, legacyIssuer, &erroringBlacklist{}, time.Hour, true, logger))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-logout-7"})
	req.Header.Set("Authorization", "Bearer "+legacyToken)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 even when the blacklist write fails, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogoutHandler_NonexistentSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	router := gin.New()
	router.DELETE("/auth/session", LogoutHandler(store, nil, nil, nil, time.Hour, true, logger))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "nonexistent"})
	router.ServeHTTP(w, req)

	// Should still clear the cookie and return 204 (graceful).
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204 even for nonexistent session, got %d", w.Code)
	}
}

// failingGetStore makes Get fail, to exercise the fail-closed path when the
// session (and so its refresh-token family) cannot be looked up.
type failingGetStore struct{ *MemorySessionStore }

func (failingGetStore) Get(context.Context, string) (*Session, error) {
	return nil, errors.New("simulated session lookup failure")
}

func logoutWithFamily(t *testing.T, store SessionStore, blacklist TokenBlacklistChecker, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.DELETE("/auth/session", LogoutHandler(store, nil, nil, blacklist, 48*time.Hour, true, zap.NewNop()))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: cookie})
	router.ServeHTTP(w, req)
	return w
}

// TestLogoutHandler_RevokesRefreshTokenFamily proves AS logout revokes the
// family recorded on the session at login (#402), with the configured
// retention.
func TestLogoutHandler_RevokesRefreshTokenFamily(t *testing.T) {
	store := NewMemorySessionStore()
	_ = store.Create(context.Background(), &Session{
		JTI: "sess-fam", UserID: "user-1", TenantID: "t", FamilyID: "sid-1",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	bl := &fakeBlacklist{}
	w := logoutWithFamily(t, store, bl, "sess-fam")
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	exp, ok := bl.families["sid-1"]
	if !ok {
		t.Fatal("expected family sid-1 to be revoked")
	}
	if d := time.Until(exp); d < 47*time.Hour || d > 49*time.Hour {
		t.Errorf("family expiry %v not ~48h", d)
	}
}

func TestLogoutHandler_NoFamilyNoRevoke(t *testing.T) {
	store := NewMemorySessionStore()
	_ = store.Create(context.Background(), &Session{
		JTI: "sess-nofam", UserID: "user-1", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	bl := &fakeBlacklist{}
	if w := logoutWithFamily(t, store, bl, "sess-nofam"); w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if len(bl.families) != 0 {
		t.Errorf("no family should be revoked, got %v", bl.families)
	}
}

// TestLogoutHandler_FamilyRevokeErrorFailsClosed proves a failing
// RevokeFamily is not reported as a clean logout.
func TestLogoutHandler_FamilyRevokeErrorFailsClosed(t *testing.T) {
	store := NewMemorySessionStore()
	_ = store.Create(context.Background(), &Session{
		JTI: "sess-fam-err", UserID: "user-1", FamilyID: "sid-1",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	bl := &fakeBlacklist{familyErr: errors.New("boom")}
	w := logoutWithFamily(t, store, bl, "sess-fam-err")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	// Session is still revoked and the cookie cleared.
	if s, _ := store.Get(context.Background(), "sess-fam-err"); s == nil || !s.Revoked {
		t.Error("session should be revoked even when family revocation fails")
	}
}

func TestLogoutHandler_SessionLookupErrorFailsClosed(t *testing.T) {
	w := logoutWithFamily(t, failingGetStore{NewMemorySessionStore()}, &fakeBlacklist{}, "whatever")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when the session (family) cannot be looked up, got %d", w.Code)
	}
}
