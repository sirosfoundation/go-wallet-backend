package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

type usersOverrideStore struct {
	storage.Store
	users storage.UserStore
}

func (s *usersOverrideStore) Users() storage.UserStore { return s.users }

// SID-AUTH-06: issuer and verifier configuration writes recheck the token's
// cut-off at the mutation boundary. The cut-off lands between admission (the
// middleware's check) and the write, so the write must be refused and
// nothing persisted or removed.
func TestIssuerVerifierWrites_CutoffAfterAdmissionIsRefused(t *testing.T) {
	base := context.Background()
	mem := memory.NewStore()
	uid := domain.NewUserID()
	require.NoError(t, mem.Users().Create(base, &domain.User{UUID: uid}))
	cutoff := time.Now().Truncate(time.Second)
	ctx := tokengate.WithSubject(base, uid.String(), cutoff.Add(-time.Minute))
	tenant := domain.DefaultTenantID

	// Seed one of each through an unjudged context so update/delete have a target.
	seed := &domain.CredentialIssuer{TenantID: tenant, CredentialIssuerIdentifier: "https://seed.example"}
	require.NoError(t, mem.Issuers().Create(base, seed))
	vseed := &domain.Verifier{TenantID: tenant, Name: "seed", URL: "https://v.example"}
	require.NoError(t, mem.Verifiers().Create(base, vseed))

	// after: 0 means the cut-off is already in force at the write's read.
	newStore := func() storage.Store {
		return &usersOverrideStore{Store: mem, users: &cutoffAdvancingUsers{UserStore: mem.Users(), after: 0, cutoff: cutoff}}
	}
	isvc := NewIssuerService(newStore(), zap.NewNop())
	vsvc := NewVerifierService(newStore(), zap.NewNop())

	t.Run("issuer create", func(t *testing.T) {
		err := isvc.Create(ctx, tenant, &domain.CredentialIssuer{CredentialIssuerIdentifier: "https://new.example"})
		assert.ErrorIs(t, err, tokengate.ErrRevoked)
		_, gerr := mem.Issuers().GetByIdentifier(base, tenant, "https://new.example")
		assert.ErrorIs(t, gerr, storage.ErrNotFound)
	})
	t.Run("issuer update", func(t *testing.T) {
		upd := *seed
		upd.ClientID = "changed"
		assert.ErrorIs(t, isvc.Update(ctx, &upd), tokengate.ErrRevoked)
		got, err := mem.Issuers().GetByID(base, tenant, seed.ID)
		require.NoError(t, err)
		assert.NotEqual(t, "changed", got.ClientID)
	})
	t.Run("issuer delete", func(t *testing.T) {
		assert.ErrorIs(t, isvc.Delete(ctx, tenant, seed.ID), tokengate.ErrRevoked)
		_, err := mem.Issuers().GetByID(base, tenant, seed.ID)
		assert.NoError(t, err, "the issuer must survive")
	})
	t.Run("verifier create", func(t *testing.T) {
		err := vsvc.Create(ctx, tenant, &domain.Verifier{Name: "new", URL: "https://n.example"})
		assert.ErrorIs(t, err, tokengate.ErrRevoked)
		all, gerr := mem.Verifiers().GetAll(base, tenant)
		require.NoError(t, gerr)
		assert.Len(t, all, 1)
	})
	t.Run("verifier update", func(t *testing.T) {
		upd := *vseed
		upd.Name = "changed"
		assert.ErrorIs(t, vsvc.Update(ctx, &upd), tokengate.ErrRevoked)
		got, err := mem.Verifiers().GetByID(base, tenant, vseed.ID)
		require.NoError(t, err)
		assert.Equal(t, "seed", got.Name)
	})
	t.Run("verifier delete", func(t *testing.T) {
		assert.ErrorIs(t, vsvc.Delete(ctx, tenant, vseed.ID), tokengate.ErrRevoked)
		_, err := mem.Verifiers().GetByID(base, tenant, vseed.ID)
		assert.NoError(t, err, "the verifier must survive")
	})
	t.Run("token not cut off still writes", func(t *testing.T) {
		okSvc := NewIssuerService(mem, zap.NewNop())
		require.NoError(t, okSvc.Create(ctx, tenant, &domain.CredentialIssuer{CredentialIssuerIdentifier: "https://ok.example"}))
	})
}
