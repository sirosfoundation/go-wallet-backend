package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func TestHolderKeySet(t *testing.T) {
	uid := domain.NewUserID()
	canonical := domain.HolderDID(uid.String())
	assert.Equal(t, []string{"did:x", canonical, uid.String()}, holderKeySet(uid, "did:x"))
	assert.Equal(t, []string{canonical, uid.String()}, holderKeySet(uid, ""), "an empty stored DID adds nothing")
	assert.Equal(t, []string{canonical, uid.String()}, holderKeySet(uid, canonical, uid.String()), "duplicates collapse")
	assert.Equal(t, []string{"did:a", "did:b", canonical, uid.String()}, holderKeySet(uid, "did:a", "did:b"))
}

func seedHolderData(t *testing.T, store storage.Store, tid domain.TenantID, holder string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.Credentials().Create(ctx, &domain.VerifiableCredential{
		TenantID: tid, HolderDID: holder, CredentialIdentifier: "c", Credential: "jwt", Format: domain.CredentialFormat("jwt_vc"),
	}))
	require.NoError(t, store.Presentations().Create(ctx, &domain.VerifiablePresentation{
		TenantID: tid, HolderDID: holder, PresentationIdentifier: "p", Presentation: "jwt",
	}))
}

// Credentials are written under domain.HolderDID(userID) by the HTTP handlers;
// the stored DID can be empty or differ. Deletion and the revoke cascade must
// sweep that key too.
func TestHolderData_CanonicalDIDIsSweptWhenStoredDIDIsEmptyOrDiffers(t *testing.T) {
	ctx := context.Background()
	for name, storedDID := range map[string]string{"empty stored DID": "", "different stored DID": "did:example:other"} {
		t.Run(name+"/DeleteUser", func(t *testing.T) {
			store := memory.NewStore()
			svc := NewUserService(store, testConfig(), zap.NewNop())
			uid := domain.NewUserID()
			canonical := domain.HolderDID(uid.String())
			require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: uid, DID: storedDID}))
			seedHolderData(t, store, domain.DefaultTenantID, canonical)

			require.NoError(t, svc.DeleteUser(ctx, uid, uid.String()))
			assert.Zero(t, holderDataCount(t, store, domain.DefaultTenantID, canonical))
		})
		t.Run(name+"/cascade", func(t *testing.T) {
			store := memory.NewStore()
			svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
			uid := domain.NewUserID()
			canonical := domain.HolderDID(uid.String())
			require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: uid, DID: storedDID, PrivateData: []byte("v")}))
			require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
				ID: "inst-hk", TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusActive,
			}))
			seedHolderData(t, store, domain.DefaultTenantID, canonical)

			_, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "deactivate")
			require.NoError(t, err)
			assert.Zero(t, holderDataCount(t, store, domain.DefaultTenantID, canonical))
		})
	}
}
