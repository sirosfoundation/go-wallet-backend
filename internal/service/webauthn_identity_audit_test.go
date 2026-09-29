package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-siros-set/set"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func identityAuditService(t *testing.T, events ...string) (*WebAuthnService, *bytes.Buffer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := set.NewSigner(key, jose.ES256, "k")
	require.NoError(t, err)
	var buf bytes.Buffer
	emitter := audit.New("https://wallet.example", signer, slog.New(slog.NewJSONHandler(&buf, nil)))
	s := &WebAuthnService{audit: emitter}
	s.SetAuditIdentityConfig(config.AuditConfig{Enabled: true, IdentityEvents: events})
	return s, &buf
}

// By default no identity event is emitted, even with audit enabled (#66).
func TestAuditIdentity_DefaultEmitsNothing(t *testing.T) {
	s, buf := identityAuditService(t)
	s.auditIdentity(config.AuditIdentityBound, EventIdentityBound, "u1", domain.TenantID("t"), "https://idp", "alice", nil)
	s.auditIdentity(config.AuditIdentityMismatch, EventIdentityMismatch, "u1", domain.TenantID("t"), "https://idp", "alice", nil)
	require.Empty(t, buf.String())
}

// Only the selected events are emitted, and the subject is hashed.
func TestAuditIdentity_EmitsOnlySelectedAndHashesSubject(t *testing.T) {
	s, buf := identityAuditService(t, config.AuditIdentityMismatch)

	s.auditIdentity(config.AuditIdentityBound, EventIdentityBound, "u1", domain.TenantID("t"), "https://idp", "alice", nil)
	require.Empty(t, buf.String(), "an unselected event must not be emitted")

	s.auditIdentity(config.AuditIdentityMismatch, EventIdentityMismatch, "u1", domain.TenantID("t"), "https://idp", "alice",
		map[string]any{"reason": "identity"})
	out := buf.String()
	require.NotEmpty(t, out)
	require.Contains(t, out, "identity:mismatch")

	// The SET payload is base64url inside the JWS, so decode it before
	// asserting anything about what it carries.
	var rec struct {
		JWS string `json:"jws"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &rec))
	parts := strings.Split(rec.JWS, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	require.NotContains(t, string(payload), "alice", "the subject must never appear in the clear")
	require.Contains(t, string(payload), `"sub":"`+subjectHash("https://idp", "alice")+`"`)
}

func TestSubjectHash_IsStableAndIssuerScoped(t *testing.T) {
	require.Equal(t, subjectHash("i", "s"), subjectHash("i", "s"))
	require.NotEqual(t, subjectHash("i1", "s"), subjectHash("i2", "s"))
	require.True(t, strings.HasPrefix(subjectHash("i", "s"), "sha256:"))
}
