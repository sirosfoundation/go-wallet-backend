package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
)

// Every lifecycle transition is audited as a SET; with no emitter configured
// the service stays silent instead of panicking.
func TestWalletLifecycle_EmitAudit(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	require.NoError(t, err)

	withAudit := NewWalletLifecycleService(memory.NewStore(), zap.NewNop(), audit.New("test-issuer", signer, nil))
	withoutAudit := NewWalletLifecycleService(memory.NewStore(), zap.NewNop(), nil)
	actor := LifecycleActor{Kind: "admin"}

	for _, status := range []domain.InstanceStatus{
		domain.InstanceStatusRevoked, domain.InstanceStatusActive, domain.InstanceStatus("unknown"),
	} {
		require.NotPanics(t, func() { withAudit.emitAudit("inst-1", status, "test", actor) }, string(status))
		require.NotPanics(t, func() { withoutAudit.emitAudit("inst-1", status, "test", actor) }, string(status))
	}
}
