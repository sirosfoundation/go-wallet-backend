package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

// An AS passkey session's access token has at most the default max TAC `rwl`.
// These tests run DELETE /user/session through the real go-tokenauth chain.

type deleteTACEnv struct {
	router *gin.Engine
	store  *memory.Store
	rp     virtualwebauthn.RelyingParty
	token  string
	user   domain.UserID
	auth   virtualwebauthn.Authenticator
	cred   virtualwebauthn.Credential
}

func newDeleteTACEnv(t *testing.T, requireStepUp bool, tac string) *deleteTACEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	v, key, issuer := setupServerTokenValidatorTest(t)
	cfg := minimalTestConfig()
	cfg.Server.RPName = "Test Wallet"
	cfg.User.Delete.RequireStepUp = requireStepUp

	mem := memory.NewStore()
	store := &memoryBackend{store: mem}
	authProvider := NewAuthProvider(cfg, store, zap.NewNop(), nil)
	t.Cleanup(func() { _ = authProvider.Close() })
	authProvider.tokenValidator = v
	router := gin.New()
	authProvider.RegisterRoutes(router)

	rp := virtualwebauthn.RelyingParty{ID: "localhost", Name: "Test Wallet", Origin: "http://localhost:8080"}
	ctx := context.Background()
	begin, err := authProvider.services.WebAuthn.BeginRegistration(ctx, &service.BeginRegistrationRequest{DisplayName: "Alice"})
	require.NoError(t, err)
	raw, err := json.Marshal(begin.CreateOptions)
	require.NoError(t, err)
	opts, err := virtualwebauthn.ParseAttestationOptions(string(raw))
	require.NoError(t, err)
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	auth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{})
	fin, err := authProvider.services.WebAuthn.FinishRegistration(ctx, &service.FinishRegistrationRequest{
		ChallengeID: begin.ChallengeID, DisplayName: "Alice",
		Credential: json.RawMessage(virtualwebauthn.CreateAttestationResponse(rp, auth, cred, *opts)),
	})
	require.NoError(t, err)
	id := domain.UserIDFromString(fin.UUID)
	auth.Options.UserHandle = id.AsUserHandle()
	auth.AddCredential(cred)

	token := signServerToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Subject: id.String(), Audience: jwt.Audience{"wallet-backend"}},
		TenantID: string(domain.DefaultTenantID), TAC: claims.TAC(tac), ACR: "urn:siros:acr:passkey",
	})
	return &deleteTACEnv{router: router, store: mem, rp: rp, token: token, user: id, auth: auth, cred: cred}
}

func (e *deleteTACEnv) do(method, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e.token)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

func (e *deleteTACEnv) exists(t *testing.T) bool {
	t.Helper()
	_, err := e.store.Users().GetByID(context.Background(), e.user)
	return err == nil
}

// stepUpBody runs delete-begin and signs the options with the user's passkey.
func (e *deleteTACEnv) stepUpBody(t *testing.T, confirm string) []byte {
	t.Helper()
	w := e.do(http.MethodPost, "/user/session/delete-begin", nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var b struct {
		ChallengeID string `json:"challengeId"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &b))
	opts, err := virtualwebauthn.ParseAssertionOptions(w.Body.String())
	require.NoError(t, err)
	assertion := virtualwebauthn.CreateAssertionResponse(e.rp, e.auth, e.cred, *opts)
	body, err := json.Marshal(map[string]any{"challengeId": b.ChallengeID, "credential": json.RawMessage(assertion), "confirm": confirm})
	require.NoError(t, err)
	return body
}

// The bodyless request needs TAC `d`, which a passkey session (max `rwl`)
// never holds: this is why the step-up assertion is the route's authorisation.
func TestDeleteAccount_TAC_BodylessNeedsDeleteScope(t *testing.T) {
	e := newDeleteTACEnv(t, false, "rwl")
	w := e.do(http.MethodDelete, "/user/session", nil)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	assert.True(t, e.exists(t))

	w = e.do(http.MethodDelete, "/user/session", []byte("  "))
	assert.Equal(t, http.StatusForbidden, w.Code, "a blank body is still the bodyless request")
	assert.True(t, e.exists(t))
}

func TestDeleteAccount_TAC_StepUpAuthorisesWithoutDeleteScope(t *testing.T) {
	e := newDeleteTACEnv(t, true, "rwl")

	// delete-begin is reachable with `rwl`.
	body := e.stepUpBody(t, "DELETE")
	w := e.do(http.MethodDelete, "/user/session", body)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"result":"DELETED"}`, w.Body.String())
	assert.False(t, e.exists(t))
}

// With a body the TAC is not consulted, so the assertion alone must authorise:
// an invalid one deletes nothing.
func TestDeleteAccount_TAC_BodyDoesNotBypassVerification(t *testing.T) {
	for _, requireStepUp := range []bool{false, true} {
		e := newDeleteTACEnv(t, requireStepUp, "rwl")
		for name, body := range map[string][]byte{
			"unknown challenge": []byte(`{"challengeId":"nope","credential":{"id":"x"},"confirm":"DELETE"}`),
			"not an assertion":  []byte(`x`),
		} {
			w := e.do(http.MethodDelete, "/user/session", body)
			assert.Equal(t, http.StatusUnauthorized, w.Code, "%s: %s", name, w.Body.String())
			assert.True(t, e.exists(t), name)
		}
	}
}

// A read-only token cannot mint the challenge.
func TestDeleteAccount_TAC_BeginNeedsWriteScope(t *testing.T) {
	e := newDeleteTACEnv(t, true, "rl")
	w := e.do(http.MethodPost, "/user/session/delete-begin", nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDeleteAccount_TAC_BodylessWithDeleteScopeAndFlag(t *testing.T) {
	e := newDeleteTACEnv(t, true, "rwld")
	w := e.do(http.MethodDelete, "/user/session", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "STEP_UP_REQUIRED")
	assert.True(t, e.exists(t))

	e = newDeleteTACEnv(t, false, "rwld")
	w = e.do(http.MethodDelete, "/user/session", nil)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.False(t, e.exists(t))
}

// An oversized body is refused in the step-up error shape, and nothing is deleted.
func TestDeleteAccount_TAC_OversizedBodyUsesStepUpErrorShape(t *testing.T) {
	e := newDeleteTACEnv(t, true, "rwl")
	w := e.do(http.MethodDelete, "/user/session", bytes.Repeat([]byte("a"), maxStepUpBody+1))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var got map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "STEP_UP_FAILED", got["error"])
	assert.NotEmpty(t, got["message"])
	assert.True(t, e.exists(t))
}

// A token holding `i` and `w` can reach enrolment, but with only the token the
// enrolment is refused, so the attacker's passkey cannot sign the deletion.
func TestDeleteAccount_TAC_StolenTokenCannotEnrolPasskeyThenDelete(t *testing.T) {
	e := newDeleteTACEnv(t, true, "rwli")

	w := e.do(http.MethodPost, "/user/session/webauthn/register-begin", nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var begin struct {
		ChallengeID   string          `json:"challengeId"`
		CreateOptions json.RawMessage `json:"createOptions"`
		Authorization json.RawMessage `json:"authorization"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &begin))
	require.NotEmpty(t, begin.Authorization, "the existing passkey is asked to authorise")
	opts, err := virtualwebauthn.ParseAttestationOptions(string(begin.CreateOptions))
	require.NoError(t, err)

	attackerCred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	attackerAuth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: e.user.AsUserHandle()})
	attestation := virtualwebauthn.CreateAttestationResponse(e.rp, attackerAuth, attackerCred, *opts)
	body, err := json.Marshal(map[string]any{"challengeId": begin.ChallengeID, "credential": json.RawMessage(attestation)})
	require.NoError(t, err)

	w = e.do(http.MethodPost, "/user/session/webauthn/register-finish", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "ENROLLMENT_AUTHORIZATION_REQUIRED")

	// The attacker's passkey is not enrolled, so it cannot sign a step-up.
	attackerAuth.AddCredential(attackerCred)
	w = e.do(http.MethodPost, "/user/session/delete-begin", nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var su struct {
		ChallengeID string `json:"challengeId"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &su))
	aopts, err := virtualwebauthn.ParseAssertionOptions(w.Body.String())
	require.NoError(t, err)
	forged := virtualwebauthn.CreateAssertionResponse(e.rp, attackerAuth, attackerCred, *aopts)
	body, err = json.Marshal(map[string]any{"challengeId": su.ChallengeID, "credential": json.RawMessage(forged), "confirm": "DELETE"})
	require.NoError(t, err)
	w = e.do(http.MethodDelete, "/user/session", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.True(t, e.exists(t))
}
