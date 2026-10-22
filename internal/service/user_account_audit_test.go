package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-siros-set/set"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func accountAuditService(t *testing.T, events ...string) (*UserService, *bytes.Buffer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := set.NewSigner(key, jose.ES256, "k")
	require.NoError(t, err)
	var buf bytes.Buffer
	svc := NewUserService(memory.NewStore(), &config.Config{}, zap.NewNop())
	svc.SetAudit(audit.New("https://wallet.example", signer, slog.New(slog.NewJSONHandler(&buf, nil))),
		config.AuditConfig{Enabled: true, AccountEvents: events})
	return svc, &buf
}

func TestAuditAccountEvent_DefaultEmitsNothing(t *testing.T) {
	svc, buf := accountAuditService(t)
	for _, name := range []string{config.AuditAccountRequested, config.AuditAccountSucceeded, config.AuditAccountCleanupPending} {
		svc.AuditAccountEvent(name, domain.UserIDFromString("u1"), nil)
	}
	require.Empty(t, buf.String())
}

func TestAuditAccountEvent_NoEmitterIsANoOp(t *testing.T) {
	svc := NewUserService(memory.NewStore(), &config.Config{}, zap.NewNop())
	svc.auditCfg = config.AuditConfig{AccountEvents: []string{config.AuditAccountSucceeded}}
	require.NotPanics(t, func() { svc.AuditAccountEvent(config.AuditAccountSucceeded, domain.UserIDFromString("u1"), nil) })
}

func TestAuditAccountEvent_EmitsOnlySelectedWithHashedSubject(t *testing.T) {
	svc, buf := accountAuditService(t, config.AuditAccountSucceeded)

	svc.AuditAccountEvent(config.AuditAccountRequested, domain.UserIDFromString("user-123"), nil)
	require.Empty(t, buf.String(), "an unselected event must not be emitted")

	svc.AuditAccountEvent(config.AuditAccountSucceeded, domain.UserIDFromString("user-123"), map[string]any{"step_up": true})
	recs := (&capturedAudit{t: t, buf: buf}).records()
	require.Len(t, recs, 1)
	text, err := json.Marshal(recs[0])
	require.NoError(t, err)
	require.Contains(t, string(text), "account:deletion_succeeded")
	require.NotContains(t, string(text), "user-123", "the subject must never appear in the clear")
	require.Equal(t, subjectHash("urn:siros:user", "user-123"), recs[0]["sub"])
}

func TestAuditAccountEvent_EachNameHasItsOwnEvent(t *testing.T) {
	svc, buf := accountAuditService(t, config.AuditAccountRequested, config.AuditAccountSucceeded, config.AuditAccountCleanupPending)
	for _, name := range []string{config.AuditAccountRequested, config.AuditAccountSucceeded, config.AuditAccountCleanupPending} {
		svc.AuditAccountEvent(name, domain.UserIDFromString("u1"), nil)
	}
	uris := (&capturedAudit{t: t, buf: buf}).URIs()
	require.Equal(t, []string{
		string(EventAccountDeletionRequested), string(EventAccountDeletionSucceeded), string(EventAccountDeletionCleanupPending),
	}, uris)
}
