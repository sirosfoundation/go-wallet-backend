package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

// The evidence is recorded only for an instance that is live and belongs to the
// authenticated tenant and user: keyAttestationTrustsBatch treats it as
// trusted later.
func TestFIDO2AttestationService_Verify_InstanceGate(t *testing.T) {
	base := context.Background()
	owner, other := domain.NewUserID(), domain.NewUserID()
	insts := map[string]*domain.WalletInstance{
		"live":    {ID: "live", TenantID: "acme", UserID: &owner, Status: domain.InstanceStatusActive},
		"revoked": {ID: "revoked", TenantID: "acme", UserID: &owner, Status: domain.InstanceStatusRevoked},
		"unbound": {ID: "unbound", TenantID: "acme", Status: domain.InstanceStatusActive},
		"foreign": {ID: "foreign", TenantID: "other", UserID: &owner, Status: domain.InstanceStatusActive},
	}
	for _, tc := range []struct {
		name, instance, tenant string
		caller                 domain.UserID
		want                   error // nil = recorded
	}{
		{"live, owned", "live", "acme", owner, nil},
		{"another user's live instance", "live", "acme", other, ErrKeyAttestationInstanceRefused},
		{"revoked instance of the caller", "revoked", "acme", owner, tokengate.ErrRevoked},
		{"unbound instance", "unbound", "acme", owner, ErrKeyAttestationInstanceRefused},
		{"instance of another tenant", "foreign", "acme", owner, ErrKeyAttestationInstanceRefused},
		{"unknown instance", "nope", "acme", owner, ErrKeyAttestationInstanceRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := memory.NewStore()
			for _, in := range insts {
				cp := *in
				require.NoError(t, store.WalletInstances().Upsert(base, &cp))
			}
			svc := NewFIDO2AttestationService(testFIDO2AttestationConfig(true), store.WalletInstances(), store.KeyAttestations(),
				newTestTrustService(t, &stubEvaluator{decision: true}), zap.NewNop())
			hash := make([]byte, 32)
			attObj, pub := buildTestAttestationObject(t, uuid.New(), hash)
			ctx := WithKeyAttestationTenant(tokengate.WithSubject(base, tc.caller.String(), time.Now()), domain.TenantID(tc.tenant))

			err := svc.Verify(ctx, &FIDO2AttestationRequest{WalletInstanceID: tc.instance, AttestationObject: attObj, ClientDataHash: hash})

			_, gerr := store.KeyAttestations().GetByKeyThumbprint(base, expectedThumbprint(t, pub))
			if tc.want == nil {
				require.NoError(t, err)
				assert.NoError(t, gerr, "evidence recorded")
				return
			}
			require.ErrorIs(t, err, tc.want)
			assert.Error(t, gerr, "no evidence may be recorded for an instance the caller may not use")
		})
	}
}
