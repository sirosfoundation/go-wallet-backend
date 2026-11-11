package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// instanceFailStore makes the wallet-instance listing of DeleteUser fail
// while fail is set, which answers 409 DELETION_INCOMPLETE.
type instanceFailStore struct {
	storage.Store
	fail atomic.Bool
}

type instanceFailInstances struct {
	storage.WalletInstanceStore
	s *instanceFailStore
}

func (s *instanceFailStore) WalletInstances() storage.WalletInstanceStore {
	return &instanceFailInstances{s.Store.WalletInstances(), s}
}

func (i *instanceFailInstances) GetAllByUser(ctx context.Context, id domain.UserID) ([]*domain.WalletInstance, error) {
	if i.s.fail.Load() {
		return nil, errors.New("db down")
	}
	return i.WalletInstanceStore.GetAllByUser(ctx, id)
}

type stepUpUser struct {
	id         domain.UserID
	auth       virtualwebauthn.Authenticator
	credential virtualwebauthn.Credential
}

type stepUpEnv struct {
	t        *testing.T
	store    *instanceFailStore
	mem      *memory.Store
	services *service.Services
	handlers *Handlers
	router   *gin.Engine
	rp       virtualwebauthn.RelyingParty
}

func newStepUpEnv(t *testing.T, requireStepUp bool) *stepUpEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "localhost", RPOrigin: "http://localhost:8080", RPName: "Test Wallet"},
		JWT:    config.JWTConfig{Secret: "test-secret-that-is-long-enough-32", ExpiryHours: 24, Issuer: "test-wallet"},
		User:   config.UserConfig{Delete: config.UserDeleteConfig{RequireStepUp: requireStepUp}},
	}
	mem := memory.NewStore()
	store := &instanceFailStore{Store: mem}
	logger := zap.NewNop()
	services := service.NewServices(store, cfg, logger)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	// The caller is named by a header, standing in for the token middleware.
	as := func(c *gin.Context) {
		if id := c.GetHeader("X-Test-User"); id != "" {
			c.Set("user_id", id)
			c.Set("did", domain.HolderDID(id))
		}
		c.Next()
	}
	router := gin.New()
	router.POST("/user/session/delete-begin", as, handlers.BeginDeleteAccount)
	router.DELETE("/user/session", as, handlers.DeleteUser)
	return &stepUpEnv{
		t: t, store: store, mem: mem, services: services, handlers: handlers, router: router,
		rp: virtualwebauthn.RelyingParty{ID: "localhost", Name: "Test Wallet", Origin: "http://localhost:8080"},
	}
}

func (e *stepUpEnv) register(name string) *stepUpUser {
	e.t.Helper()
	ctx := context.Background()
	begin, err := e.services.WebAuthn.BeginRegistration(ctx, &service.BeginRegistrationRequest{DisplayName: name})
	require.NoError(e.t, err)
	optsJSON, err := json.Marshal(begin.CreateOptions)
	require.NoError(e.t, err)
	opts, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
	require.NoError(e.t, err)
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	auth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{})
	resp := virtualwebauthn.CreateAttestationResponse(e.rp, auth, cred, *opts)
	fin, err := e.services.WebAuthn.FinishRegistration(ctx, &service.FinishRegistrationRequest{
		ChallengeID: begin.ChallengeID, Credential: json.RawMessage(resp), DisplayName: name,
	})
	require.NoError(e.t, err)
	id := domain.UserIDFromString(fin.UUID)
	auth.Options.UserHandle = id.AsUserHandle()
	auth.AddCredential(cred)
	return &stepUpUser{id: id, auth: auth, credential: cred}
}

func (e *stepUpEnv) do(method, path, userID string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if userID != "" {
		req.Header.Set("X-Test-User", userID)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

type beginResult struct {
	ChallengeID string          `json:"challengeId"`
	PublicKey   json.RawMessage `json:"publicKey"`
	raw         []byte
}

func (e *stepUpEnv) begin(userID domain.UserID) beginResult {
	e.t.Helper()
	w := e.do(http.MethodPost, "/user/session/delete-begin", userID.String(), nil)
	require.Equal(e.t, http.StatusOK, w.Code, w.Body.String())
	var r beginResult
	require.NoError(e.t, json.Unmarshal(w.Body.Bytes(), &r))
	r.raw = w.Body.Bytes()
	return r
}

// sign has u's passkey answer the options of b.
func (e *stepUpEnv) sign(u *stepUpUser, b beginResult) json.RawMessage {
	e.t.Helper()
	opts, err := virtualwebauthn.ParseAssertionOptions(string(b.raw))
	require.NoError(e.t, err)
	return json.RawMessage(virtualwebauthn.CreateAssertionResponse(e.rp, u.auth, u.credential, *opts))
}

func stepUpBody(challengeID string, credential json.RawMessage, confirm string) []byte {
	b, _ := json.Marshal(deleteAccountRequest{ChallengeID: challengeID, Credential: credential, Confirm: confirm})
	return b
}

func (e *stepUpEnv) exists(id domain.UserID) bool {
	_, err := e.mem.Users().GetByID(context.Background(), id)
	return err == nil
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var r map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &r), w.Body.String())
	s, _ := r["error"].(string)
	return s
}

func TestBeginDeleteAccount(t *testing.T) {
	e := newStepUpEnv(t, false)
	alice := e.register("Alice")
	_ = e.register("Bob")

	t.Run("returns options for the caller's own passkeys", func(t *testing.T) {
		b := e.begin(alice.id)
		assert.NotEmpty(t, b.ChallengeID)
		var pk struct {
			AllowCredentials []map[string]any `json:"allowCredentials"`
			UserVerification string           `json:"userVerification"`
		}
		require.NoError(t, json.Unmarshal(b.PublicKey, &pk))
		assert.Len(t, pk.AllowCredentials, 1)
		assert.Equal(t, "required", pk.UserVerification)
	})
	t.Run("needs an authenticated caller", func(t *testing.T) {
		w := e.do(http.MethodPost, "/user/session/delete-begin", "", nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
	t.Run("a user without a passkey is told so", func(t *testing.T) {
		require.NoError(t, e.mem.Users().Create(context.Background(), &domain.User{UUID: domain.UserIDFromString("oidc-only")}))
		w := e.do(http.MethodPost, "/user/session/delete-begin", "oidc-only", nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, errCodeNoPasskey, errorCode(t, w))
	})
}

func TestDeleteAccount_StepUp_Success_ErasesAndMintsNothing(t *testing.T) {
	e := newStepUpEnv(t, true)
	alice := e.register("Alice")
	bob := e.register("Bob")

	// Holder data under Alice's DID must be erased with her.
	aliceUser, err := e.mem.Users().GetByID(context.Background(), alice.id)
	require.NoError(t, err)
	require.NoError(t, e.mem.Credentials().Create(context.Background(), &domain.VerifiableCredential{
		HolderDID: aliceUser.DID, TenantID: domain.DefaultTenantID, CredentialIdentifier: "c1", Credential: "x", Format: "dc+sd-jwt",
	}))

	b := e.begin(alice.id)
	w := e.do(http.MethodDelete, "/user/session", alice.id.String(), stepUpBody(b.ChallengeID, e.sign(alice, b), "DELETE"))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"result":"DELETED"}`, w.Body.String(), "no token, session or other credential in the response")
	assert.False(t, e.exists(alice.id), "the account is erased")
	assert.True(t, e.exists(bob.id), "other accounts are untouched")
	creds, err := e.mem.Credentials().GetAllByHolder(context.Background(), domain.DefaultTenantID, aliceUser.DID)
	require.NoError(t, err)
	assert.Empty(t, creds, "holder data is erased")
	_, err = e.mem.Challenges().GetByID(context.Background(), b.ChallengeID)
	assert.Error(t, err, "the challenge is consumed")
	assert.Empty(t, w.Header().Get("Set-Cookie"), "no session cookie")
}

func TestDeleteAccount_FlagControlsBodylessRequest(t *testing.T) {
	t.Run("off: the bodyless request still deletes", func(t *testing.T) {
		e := newStepUpEnv(t, false)
		u := e.register("Alice")
		w := e.do(http.MethodDelete, "/user/session", u.id.String(), nil)
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.False(t, e.exists(u.id))
	})
	t.Run("on: the bodyless request is refused", func(t *testing.T) {
		e := newStepUpEnv(t, true)
		u := e.register("Alice")
		w := e.do(http.MethodDelete, "/user/session", u.id.String(), nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, errCodeStepUpRequired, errorCode(t, w))
		assert.True(t, e.exists(u.id))
	})
	t.Run("on: a blank body is the bodyless request", func(t *testing.T) {
		e := newStepUpEnv(t, true)
		u := e.register("Alice")
		w := e.do(http.MethodDelete, "/user/session", u.id.String(), []byte("  \n"))
		assert.Equal(t, errCodeStepUpRequired, errorCode(t, w))
		assert.True(t, e.exists(u.id))
	})
	t.Run("off: a body never falls back to the bodyless path", func(t *testing.T) {
		e := newStepUpEnv(t, false)
		u := e.register("Alice")
		w := e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody("bogus", json.RawMessage(`{}`), "DELETE"))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, errCodeStepUpFailed, errorCode(t, w))
		assert.True(t, e.exists(u.id))
	})
}

func TestDeleteAccount_StepUp_Errors(t *testing.T) {
	t.Run("wrong or missing confirm is 400 and keeps the assertion usable", func(t *testing.T) {
		e := newStepUpEnv(t, true)
		u := e.register("Alice")
		b := e.begin(u.id)
		assertion := e.sign(u, b)

		for _, confirm := range []string{"", "delete", "YES"} {
			w := e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody(b.ChallengeID, assertion, confirm))
			assert.Equal(t, http.StatusBadRequest, w.Code, confirm)
			assert.Equal(t, errCodeConfirmationRequired, errorCode(t, w), confirm)
			assert.True(t, e.exists(u.id))
		}
		w := e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody(b.ChallengeID, assertion, "DELETE"))
		assert.Equal(t, http.StatusOK, w.Code, "a typo did not burn the assertion: %s", w.Body.String())
	})

	t.Run("expired is 410", func(t *testing.T) {
		e := newStepUpEnv(t, true)
		u := e.register("Alice")
		b := e.begin(u.id)
		ch, err := e.mem.Challenges().GetByID(context.Background(), b.ChallengeID)
		require.NoError(t, err)
		ch.ValidUntil = time.Now().Add(-time.Second)

		w := e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody(b.ChallengeID, e.sign(u, b), "DELETE"))
		assert.Equal(t, http.StatusGone, w.Code)
		assert.Equal(t, errCodeStepUpExpired, errorCode(t, w))
		assert.True(t, e.exists(u.id))
	})

	t.Run("a replayed challenge is refused", func(t *testing.T) {
		e := newStepUpEnv(t, true)
		u := e.register("Alice")
		b := e.begin(u.id)
		assertion := e.sign(u, b)
		e.store.fail.Store(true)
		first := e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody(b.ChallengeID, assertion, "DELETE"))
		require.Equal(t, http.StatusConflict, first.Code, first.Body.String())
		assert.Equal(t, errCodeDeletionIncomplete, errorCode(t, first))
		assert.True(t, e.exists(u.id), "a 409 leaves the account")

		// The retry after a 409 needs a fresh assertion.
		e.store.fail.Store(false)
		replay := e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody(b.ChallengeID, assertion, "DELETE"))
		assert.Equal(t, http.StatusUnauthorized, replay.Code)
		assert.Equal(t, errCodeStepUpFailed, errorCode(t, replay))
		assert.True(t, e.exists(u.id))

		fresh := e.begin(u.id)
		ok := e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody(fresh.ChallengeID, e.sign(u, fresh), "DELETE"))
		assert.Equal(t, http.StatusOK, ok.Code, ok.Body.String())
		assert.False(t, e.exists(u.id))
	})

	t.Run("another user's credential is refused", func(t *testing.T) {
		e := newStepUpEnv(t, true)
		alice := e.register("Alice")
		bob := e.register("Bob")

		b := e.begin(alice.id)
		w := e.do(http.MethodDelete, "/user/session", alice.id.String(), stepUpBody(b.ChallengeID, e.sign(bob, b), "DELETE"))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, errCodeStepUpFailed, errorCode(t, w))
		assert.True(t, e.exists(alice.id))

		// Bob presenting Alice's challenge as himself neither deletes Bob nor burns Alice's.
		b = e.begin(alice.id)
		w = e.do(http.MethodDelete, "/user/session", bob.id.String(), stepUpBody(b.ChallengeID, e.sign(bob, b), "DELETE"))
		assert.Equal(t, errCodeStepUpFailed, errorCode(t, w))
		assert.True(t, e.exists(bob.id))
		w = e.do(http.MethodDelete, "/user/session", alice.id.String(), stepUpBody(b.ChallengeID, e.sign(alice, b), "DELETE"))
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})

	t.Run("a login challenge is refused", func(t *testing.T) {
		e := newStepUpEnv(t, true)
		u := e.register("Alice")
		login, err := e.services.WebAuthn.BeginLogin(context.Background())
		require.NoError(t, err)
		raw, err := json.Marshal(login.GetOptions)
		require.NoError(t, err)
		opts, err := virtualwebauthn.ParseAssertionOptions(string(raw))
		require.NoError(t, err)
		assertion := virtualwebauthn.CreateAssertionResponse(e.rp, u.auth, u.credential, *opts)

		w := e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody(login.ChallengeID, json.RawMessage(assertion), "DELETE"))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, errCodeStepUpFailed, errorCode(t, w))
		assert.True(t, e.exists(u.id))
	})

	t.Run("a malformed or incomplete body is STEP_UP_FAILED", func(t *testing.T) {
		e := newStepUpEnv(t, true)
		u := e.register("Alice")
		for name, body := range map[string][]byte{
			"not json":      []byte("{nope"),
			"no challenge":  []byte(`{"confirm":"DELETE"}`),
			"no credential": []byte(`{"challengeId":"x","confirm":"DELETE"}`),
		} {
			w := e.do(http.MethodDelete, "/user/session", u.id.String(), body)
			assert.Equal(t, http.StatusUnauthorized, w.Code, name)
			assert.Equal(t, errCodeStepUpFailed, errorCode(t, w), name)
			assert.True(t, e.exists(u.id), name)
		}
	})
}
