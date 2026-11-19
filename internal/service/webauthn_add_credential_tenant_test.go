package service

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// A passkey added from wallet settings (#560) has to carry the tenant the way a
// signup passkey does: the user handle encodes it and the stored credential
// names it. Otherwise login reads a tenant-less handle on a tenant member and
// answers ErrTenantAccessDenied.

func addCredentialTenantUser(t *testing.T, setup *testVirtualWebAuthnSetup, tenant domain.TenantID) domain.UserID {
	t.Helper()
	userID := domain.NewUserID()
	require.NoError(t, setup.store.Users().Create(setup.ctx, &domain.User{UUID: userID, CreatedAt: time.Now()}))
	if tenant != "" {
		require.NoError(t, setup.store.Tenants().Create(setup.ctx, &domain.Tenant{ID: tenant, Name: string(tenant), Enabled: true}))
		require.NoError(t, setup.store.UserTenants().AddMembership(setup.ctx, &domain.UserTenantMembership{
			UserID: userID, TenantID: tenant, Role: "user",
		}))
	}
	return userID
}

func beginAddAndAttest(t *testing.T, setup *testVirtualWebAuthnSetup, userID domain.UserID, tenant domain.TenantID) (*BeginAddCredentialResponse, *FinishAddCredentialRequest, virtualwebauthn.Credential) {
	t.Helper()
	begin, err := setup.service.BeginAddCredential(setup.ctx, userID, tenant)
	require.NoError(t, err)
	raw, err := json.Marshal(begin.CreateOptions)
	require.NoError(t, err)
	opts, err := virtualwebauthn.ParseAttestationOptions(string(convertOptionsToPlainBase64(raw)))
	require.NoError(t, err)
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	resp := virtualwebauthn.CreateAttestationResponse(setup.rp, setup.authenticator, cred, *opts)
	return begin, &FinishAddCredentialRequest{ChallengeID: begin.ChallengeID, Credential: json.RawMessage(resp)}, cred
}

func TestAddCredential_TenantMemberPasskeyCanLogIn(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	userID := addCredentialTenantUser(t, setup, "acme")

	begin, finishReq, cred := beginAddAndAttest(t, setup, userID, "acme")
	wantHandle := domain.EncodeUserHandle("acme", userID)
	assert.Equal(t, []byte(wantHandle), []byte(begin.CreateOptions.PublicKey.User.ID), "the passkey's user handle names the tenant")

	_, err := setup.service.FinishAddCredential(setup.ctx, userID, "acme", finishReq, "")
	require.NoError(t, err)

	u, err := setup.store.Users().GetByID(setup.ctx, userID)
	require.NoError(t, err)
	require.Len(t, u.WebauthnCredentials, 1)
	assert.Equal(t, domain.TenantID("acme"), u.WebauthnCredentials[0].TenantID, "the credential is stored with its tenant")

	// The added passkey signs in.
	setup.authenticator.Options.UserHandle = wantHandle
	setup.authenticator.AddCredential(cred)
	login, err := setup.service.BeginLogin(setup.ctx)
	require.NoError(t, err)
	loginOpts, err := json.Marshal(login.GetOptions)
	require.NoError(t, err)
	assertionOpts, err := virtualwebauthn.ParseAssertionOptions(string(loginOpts))
	require.NoError(t, err)
	assertion := virtualwebauthn.CreateAssertionResponse(setup.rp, setup.authenticator, cred, *assertionOpts)
	resp, err := setup.service.FinishLogin(setup.ctx, &FinishLoginRequest{ChallengeID: login.ChallengeID, Credential: json.RawMessage(assertion)})
	require.NoError(t, err, "a tenant member's added passkey must not be refused as a legacy handle")
	assert.Equal(t, userID.String(), resp.UUID)
	assert.Equal(t, "acme", resp.TenantID)
}

func TestAddCredential_DefaultTenantKeepsThePlainHandle(t *testing.T) {
	for _, tenant := range []domain.TenantID{"", domain.DefaultTenantID} {
		t.Run("tenant="+string(tenant), func(t *testing.T) {
			setup := newTestVirtualWebAuthnSetup(t)
			userID := addCredentialTenantUser(t, setup, "")

			begin, finishReq, _ := beginAddAndAttest(t, setup, userID, tenant)
			assert.Equal(t, []byte(userID.AsUserHandle()), []byte(begin.CreateOptions.PublicKey.User.ID))

			_, err := setup.service.FinishAddCredential(setup.ctx, userID, tenant, finishReq, "")
			require.NoError(t, err)
			u, err := setup.store.Users().GetByID(setup.ctx, userID)
			require.NoError(t, err)
			require.Len(t, u.WebauthnCredentials, 1)
			assert.Empty(t, u.WebauthnCredentials[0].TenantID)
		})
	}
}

func TestAddCredential_RefusesATenantTheUserDoesNotBelongTo(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	userID := addCredentialTenantUser(t, setup, "acme")

	_, err := setup.service.BeginAddCredential(setup.ctx, userID, "other")
	assert.ErrorIs(t, err, ErrTenantAccessDenied)
}

func TestAddCredential_FinishMustRunInTheTenantItWasBegunIn(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	userID := addCredentialTenantUser(t, setup, "acme")
	require.NoError(t, setup.store.UserTenants().AddMembership(setup.ctx, &domain.UserTenantMembership{
		UserID: userID, TenantID: "other", Role: "user",
	}))

	_, finishReq, _ := beginAddAndAttest(t, setup, userID, "acme")
	_, err := setup.service.FinishAddCredential(setup.ctx, userID, "other", finishReq, "")
	require.ErrorIs(t, err, ErrTenantAccessDenied)

	u, err := setup.store.Users().GetByID(setup.ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, u.WebauthnCredentials, "nothing is stored")
}
