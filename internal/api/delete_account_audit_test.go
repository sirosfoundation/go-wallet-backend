package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-siros-set/set"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// auditedEvents attaches a capturing emitter to e with the given account
// events selected; the result lists the emitted SET records.
func auditedEvents(t *testing.T, e *stepUpEnv, events ...string) func() []map[string]any {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := set.NewSigner(key, jose.ES256, "k")
	require.NoError(t, err)
	var buf bytes.Buffer
	e.services.User.SetAudit(audit.New("https://wallet.example", signer, slog.New(slog.NewJSONHandler(&buf, nil))),
		config.AuditConfig{Enabled: true, AccountEvents: events})
	return func() []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var rec struct {
				JWS string `json:"jws"`
			}
			require.NoError(t, json.Unmarshal([]byte(line), &rec))
			payload, err := base64.RawURLEncoding.DecodeString(strings.Split(rec.JWS, ".")[1])
			require.NoError(t, err)
			var claims map[string]any
			require.NoError(t, json.Unmarshal(payload, &claims))
			out = append(out, claims)
		}
		return out
	}
}

func eventURIs(recs []map[string]any) []string {
	var out []string
	for _, r := range recs {
		for uri := range r["events"].(map[string]any) {
			out = append(out, uri)
		}
	}
	return out
}

func TestDeleteAccount_Audit_StepUpRequestedThenSucceeded(t *testing.T) {
	e := newStepUpEnv(t, true)
	records := auditedEvents(t, e, config.AuditAccountRequested, config.AuditAccountSucceeded, config.AuditAccountCleanupPending)
	u := e.register("Alice")

	b := e.begin(u.id)
	assertion := e.sign(u, b)
	// A failed attempt is not a request: nothing is emitted.
	e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody(b.ChallengeID, assertion, "nope"))
	e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody("bogus", assertion, "DELETE"))
	require.Empty(t, records())

	w := e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody(b.ChallengeID, assertion, "DELETE"))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	recs := records()
	assert.Equal(t, []string{string(service.EventAccountDeletionRequested), string(service.EventAccountDeletionSucceeded)}, eventURIs(recs))
	text, err := json.Marshal(recs)
	require.NoError(t, err)
	assert.NotContains(t, string(text), u.id.String(), "the subject is hashed")
	assert.NotContains(t, string(text), "credential", "no credential content")
	data := recs[0]["events"].(map[string]any)[string(service.EventAccountDeletionRequested)].(map[string]any)
	assert.Equal(t, true, data["step_up"])
}

func TestDeleteAccount_Audit_UnselectedEventsAreSilent(t *testing.T) {
	e := newStepUpEnv(t, true)
	records := auditedEvents(t, e, config.AuditAccountSucceeded)
	u := e.register("Alice")
	b := e.begin(u.id)
	w := e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody(b.ChallengeID, e.sign(u, b), "DELETE"))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []string{string(service.EventAccountDeletionSucceeded)}, eventURIs(records()))
}

func TestDeleteAccount_Audit_CleanupPending(t *testing.T) {
	e := newStepUpEnv(t, false)
	records := auditedEvents(t, e, config.AuditAccountRequested, config.AuditAccountSucceeded, config.AuditAccountCleanupPending)
	u := e.register("Alice")

	e.services.User.SetTokenBlacklist(okRevoker{})
	e.services.User.SetSessionCleaner(&failingSecondCleaner{})
	w := e.do(http.MethodDelete, "/user/session", u.id.String(), nil)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())

	recs := records()
	assert.Equal(t, []string{string(service.EventAccountDeletionRequested), string(service.EventAccountDeletionCleanupPending)}, eventURIs(recs))
	data := recs[0]["events"].(map[string]any)[string(service.EventAccountDeletionRequested)].(map[string]any)
	assert.Equal(t, false, data["step_up"], "the bodyless request is recorded as such")
}

// The account is gone but a later sweep failed: also a cleanup-pending event.
func TestDeleteAccount_Audit_CleanupPendingAfterRemoval(t *testing.T) {
	e := newStepUpEnv(t, false)
	inner := memory.NewStore()
	const userID = "user-cleanup-pending-audit"
	require.NoError(t, inner.Users().Create(context.Background(), &domain.User{
		UUID: domain.UserIDFromString(userID), DID: domain.HolderDID(userID),
	}))
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "localhost", RPOrigin: "http://localhost:8080"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, Issuer: "test-wallet"},
	}
	e.services = service.NewServices(&removalFailStore{Store: inner}, cfg, zap.NewNop())
	records := auditedEvents(t, e, config.AuditAccountSucceeded, config.AuditAccountCleanupPending)
	handlers := NewHandlers(e.services, cfg, zap.NewNop(), []string{"test"})
	router := gin.New()
	router.DELETE("/user", legacyAuthContext(userID), handlers.DeleteUser)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/user", nil))
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	assert.Equal(t, []string{string(service.EventAccountDeletionCleanupPending)}, eventURIs(records()))
}

func TestDeleteAccount_Audit_DefaultEmitsNothing(t *testing.T) {
	e := newStepUpEnv(t, true)
	records := auditedEvents(t, e)
	u := e.register("Alice")
	b := e.begin(u.id)
	e.do(http.MethodDelete, "/user/session", u.id.String(), stepUpBody(b.ChallengeID, e.sign(u, b), "DELETE"))
	assert.Empty(t, records())
}
