package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func TestValidatePrivateDataOwnership_Container(t *testing.T) {
	creds := []domain.WebauthnCredential{{ID: testCredID("a")}, {ID: testCredID("b")}}
	uid := domain.NewUserID()

	tests := []struct {
		name    string
		data    []byte
		refused bool
	}{
		{"own credential", testPrivateDataContainer(testCredID("a")), false},
		{"all own credentials", testPrivateDataContainer(testCredID("a"), testCredID("b")), false},
		{"partial overlap accepted", testPrivateDataContainer(testCredID("a"), testCredID("stale")), false},
		{"foreign credential", testPrivateDataContainer(testCredID("x")), true},
		{"several foreign credentials", testPrivateDataContainer(testCredID("x"), testCredID("y")), true},
		{"empty prfKeys", testPrivateDataContainer(), true},
		{"nil data", nil, true},
		{"empty data", []byte{}, true},
		{"not JSON", []byte("test-private-data"), true},
		{"truncated JSON", []byte(`{"prfKeys":[`), true},
		{"JSON null", []byte(`null`), true},
		{"JSON array", []byte(`[]`), true},
		{"JSON string", []byte(`"x"`), true},
		{"missing prfKeys", []byte(`{"mainKey":{},"jwe":"a.b.c.d.e"}`), true},
		{"jwe missing", []byte(`{"mainKey":{},"prfKeys":[{"credentialId":{"$b64u":"` + testCredID("a") + `"}}]}`), true},
		{"jwe null", []byte(`{"mainKey":{},"jwe":null,"prfKeys":[{"credentialId":{"$b64u":"` + testCredID("a") + `"}}]}`), true},
		{"jwe wrong type", []byte(`{"mainKey":{},"jwe":{},"prfKeys":[{"credentialId":{"$b64u":"` + testCredID("a") + `"}}]}`), true},
		{"jwe empty", []byte(`{"mainKey":{},"jwe":"","prfKeys":[{"credentialId":{"$b64u":"` + testCredID("a") + `"}}]}`), true},
		{"jwe not compact", []byte(`{"mainKey":{},"jwe":"abc","prfKeys":[{"credentialId":{"$b64u":"` + testCredID("a") + `"}}]}`), true},
		{"jwe empty ciphertext", []byte(`{"jwe":"a.b.c..e","prfKeys":[{"credentialId":{"$b64u":"` + testCredID("a") + `"}}]}`), true},
		{"mainKey null", []byte(`{"mainKey":null,"jwe":"a.b.c.d.e","prfKeys":[{"credentialId":{"$b64u":"` + testCredID("a") + `"}}]}`), true},
		{"mainKey wrong type", []byte(`{"mainKey":"x","jwe":"a.b.c.d.e","prfKeys":[{"credentialId":{"$b64u":"` + testCredID("a") + `"}}]}`), true},
		{"mainKey absent accepted (older containers)", []byte(`{"jwe":"a..c.d.e","prfKeys":[{"credentialId":{"$b64u":"` + testCredID("a") + `"}}]}`), false},
		{"prfKeys null", []byte(`{"prfKeys":null}`), true},
		{"prfKeys not array", []byte(`{"prfKeys":{}}`), true},
		{"entry null", []byte(`{"prfKeys":[null]}`), true},
		{"entry not object", []byte(`{"prfKeys":["x"]}`), true},
		{"credentialId missing", []byte(`{"prfKeys":[{}]}`), true},
		{"credentialId null", []byte(`{"prfKeys":[{"credentialId":null}]}`), true},
		{"credentialId plain string", []byte(`{"prfKeys":[{"credentialId":"` + testCredID("a") + `"}]}`), true},
		{"credentialId tagged non-string", []byte(`{"prfKeys":[{"credentialId":{"$b64u":1}}]}`), true},
		{"credentialId tagged null", []byte(`{"prfKeys":[{"credentialId":{"$b64u":null}}]}`), true},
		{"credentialId extra key", []byte(`{"prfKeys":[{"credentialId":{"$b64u":"` + testCredID("a") + `","x":"y"}}]}`), true},
		{"credentialId invalid base64", []byte(`{"prfKeys":[{"credentialId":{"$b64u":"!!!"}}]}`), true},
		{"credentialId empty", []byte(`{"prfKeys":[{"credentialId":{"$b64u":""}}]}`), true},
		{"valid entry plus malformed entry", []byte(`{"prfKeys":[{"credentialId":{"$b64u":"` + testCredID("a") + `"}},{"credentialId":null}]}`), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePrivateDataOwnership(zap.NewNop(), uid, creds, tt.data)
			if tt.refused {
				require.ErrorIs(t, err, ErrPrivateDataOwnership)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidatePrivateDataOwnership_CredentialEncodings(t *testing.T) {
	raw := []byte{0xfb, 0xff, 0xfe, 0x01, 0x02} // base64url and std alphabets differ for these bytes
	forms := map[string]string{
		"base64url no pad": base64.RawURLEncoding.EncodeToString(raw),
		"base64url padded": base64.URLEncoding.EncodeToString(raw),
		"std no pad":       base64.RawStdEncoding.EncodeToString(raw),
		"std padded":       base64.StdEncoding.EncodeToString(raw),
	}
	container := func(idText string) []byte {
		return testPrivateDataContainer(idText)
	}
	for storedName, stored := range forms {
		for _, withBytes := range []bool{true, false} {
			cred := domain.WebauthnCredential{ID: stored}
			if withBytes {
				cred.CredentialID = raw
			}
			// the container always carries url-safe forms of the same bytes
			for _, cname := range []string{"base64url no pad", "base64url padded"} {
				name := storedName + "/bytes=" + map[bool]string{true: "yes", false: "no"}[withBytes] + "/container " + cname
				t.Run(name, func(t *testing.T) {
					err := validatePrivateDataOwnership(zap.NewNop(), domain.NewUserID(), []domain.WebauthnCredential{cred}, container(forms[cname]))
					require.NoError(t, err)
				})
			}
		}
	}
	t.Run("raw bytes match despite unrelated stored ID text", func(t *testing.T) {
		cred := domain.WebauthnCredential{ID: "legacy-opaque-id", CredentialID: raw}
		require.NoError(t, validatePrivateDataOwnership(zap.NewNop(), domain.NewUserID(), []domain.WebauthnCredential{cred}, container(forms["base64url no pad"])))
	})
	t.Run("different bytes still refused", func(t *testing.T) {
		cred := domain.WebauthnCredential{ID: forms["std padded"], CredentialID: raw}
		err := validatePrivateDataOwnership(zap.NewNop(), domain.NewUserID(), []domain.WebauthnCredential{cred}, container(testCredID("other")))
		require.ErrorIs(t, err, ErrPrivateDataOwnership)
	})
}

func TestValidatePrivateDataOwnership_DoesNotLogContainer(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)
	secret := "SECRET-MARKER"
	data := []byte(`{"prfKeys":[{"credentialId":{"$b64u":"` + testCredID("x") + `"}}],"jwe":"` + secret + `"}`)
	err := validatePrivateDataOwnership(logger, domain.NewUserID(), nil, data)
	require.ErrorIs(t, err, ErrPrivateDataOwnership)
	require.NotZero(t, logs.Len())
	for _, e := range logs.All() {
		assert.NotContains(t, e.Message, secret)
		for _, f := range e.Context {
			assert.NotContains(t, f.String, secret)
			assert.NotContains(t, f.String, testCredID("x"))
		}
	}
	assert.NotContains(t, err.Error(), secret)
}

func newPrivateDataUserService(t *testing.T) (*UserService, *memory.Store, *domain.User) {
	t.Helper()
	store := memory.NewStore()
	svc := NewUserService(store, testConfig(), testLogger())
	ctx := context.Background()
	user, err := svc.Register(ctx, &domain.RegisterRequest{DisplayName: "PD User", WalletType: domain.WalletTypeClient})
	require.NoError(t, err)
	user.WebauthnCredentials = []domain.WebauthnCredential{{ID: testCredID("a")}, {ID: testCredID("b")}}
	user.UpdatePrivateData(testPrivateDataContainer(testCredID("a")))
	require.NoError(t, svc.UpdateUser(ctx, user))
	return svc, store, user
}

func TestUserService_UpdatePrivateData_Ownership(t *testing.T) {
	ctx := context.Background()

	t.Run("foreign container refused, stored data and ETag unchanged", func(t *testing.T) {
		svc, store, user := newPrivateDataUserService(t)
		before, _ := store.Users().GetByID(ctx, user.UUID)

		_, err := svc.UpdatePrivateData(ctx, user.UUID, testPrivateDataContainer(testCredID("x")), "")
		require.ErrorIs(t, err, ErrPrivateDataOwnership)

		after, _ := store.Users().GetByID(ctx, user.UUID)
		assert.Equal(t, before.PrivateData, after.PrivateData)
		assert.Equal(t, before.PrivateDataETag, after.PrivateDataETag)
	})

	t.Run("partial overlap accepted", func(t *testing.T) {
		svc, _, user := newPrivateDataUserService(t)
		data := testPrivateDataContainer(testCredID("b"), testCredID("stale"))
		etag, err := svc.UpdatePrivateData(ctx, user.UUID, data, "")
		require.NoError(t, err)
		got, gotEtag, _ := svc.GetPrivateData(ctx, user.UUID)
		assert.Equal(t, data, got)
		assert.Equal(t, etag, gotEtag)
	})

	t.Run("empty prfKeys refused", func(t *testing.T) {
		svc, _, user := newPrivateDataUserService(t)
		_, err := svc.UpdatePrivateData(ctx, user.UUID, testPrivateDataContainer(), "")
		require.ErrorIs(t, err, ErrPrivateDataOwnership)
	})

	t.Run("garbage refused", func(t *testing.T) {
		svc, _, user := newPrivateDataUserService(t)
		for _, d := range [][]byte{[]byte("test-private-data"), []byte("null"), nil, []byte(`{"prfKeys":null}`)} {
			_, err := svc.UpdatePrivateData(ctx, user.UUID, d, "")
			require.ErrorIs(t, err, ErrPrivateDataOwnership, string(d))
		}
	})

	t.Run("ownership refusal is distinct from ETag conflict", func(t *testing.T) {
		svc, _, user := newPrivateDataUserService(t)
		_, err := svc.UpdatePrivateData(ctx, user.UUID, testPrivateDataContainer(testCredID("a")), "wrong")
		require.ErrorIs(t, err, ErrPrivateDataConflict)
		assert.NotErrorIs(t, err, ErrPrivateDataOwnership)
	})
}

func TestUserService_Register_PrivateDataOwnership(t *testing.T) {
	svc := NewUserService(memory.NewStore(), testConfig(), testLogger())
	// A freshly registered user has no credentials, so no container can belong to it.
	_, err := svc.Register(context.Background(), &domain.RegisterRequest{
		DisplayName: "x",
		WalletType:  domain.WalletTypeClient,
		PrivateData: testPrivateDataContainer(testCredID("a")),
	})
	require.ErrorIs(t, err, ErrPrivateDataOwnership)
}

func TestUserService_DeleteWebAuthnCredential_Ownership(t *testing.T) {
	ctx := context.Background()

	t.Run("foreign container refused, nothing changes", func(t *testing.T) {
		svc, store, user := newPrivateDataUserService(t)
		before, _ := store.Users().GetByID(ctx, user.UUID)

		_, err := svc.DeleteWebAuthnCredential(ctx, user.UUID, testCredID("a"), testPrivateDataContainer(testCredID("x")), "")
		require.ErrorIs(t, err, ErrPrivateDataOwnership)

		after, _ := store.Users().GetByID(ctx, user.UUID)
		assert.Equal(t, before.PrivateData, after.PrivateData)
		assert.Equal(t, before.PrivateDataETag, after.PrivateDataETag)
		assert.Len(t, after.WebauthnCredentials, 2, "credential must not be deleted on refusal")
	})

	t.Run("container without the deleted credential accepted", func(t *testing.T) {
		svc, store, user := newPrivateDataUserService(t)
		data := testPrivateDataContainer(testCredID("b"))
		_, err := svc.DeleteWebAuthnCredential(ctx, user.UUID, testCredID("a"), data, "")
		require.NoError(t, err)
		after, _ := store.Users().GetByID(ctx, user.UUID)
		assert.Equal(t, data, after.PrivateData)
		assert.Len(t, after.WebauthnCredentials, 1)
	})

	t.Run("container only for the deleted credential refused", func(t *testing.T) {
		svc, store, user := newPrivateDataUserService(t)
		_, err := svc.DeleteWebAuthnCredential(ctx, user.UUID, testCredID("a"), testPrivateDataContainer(testCredID("a")), "")
		require.ErrorIs(t, err, ErrPrivateDataOwnership)
		after, _ := store.Users().GetByID(ctx, user.UUID)
		assert.Len(t, after.WebauthnCredentials, 2)
	})

	t.Run("empty and invalid refused", func(t *testing.T) {
		svc, _, user := newPrivateDataUserService(t)
		for _, d := range [][]byte{nil, []byte("null"), []byte("opaque"), testPrivateDataContainer()} {
			_, err := svc.DeleteWebAuthnCredential(ctx, user.UUID, testCredID("a"), d, "")
			require.ErrorIs(t, err, ErrPrivateDataOwnership)
		}
	})
}

func vwaOptions(t *testing.T, v any) virtualwebauthn.AttestationOptions {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	opts, err := virtualwebauthn.ParseAttestationOptions(string(b))
	require.NoError(t, err)
	return *opts
}

func storedID(c virtualwebauthn.Credential) string {
	return base64.RawURLEncoding.EncodeToString(c.ID)
}

func TestFinishRegistration_PrivateDataOwnership(t *testing.T) {
	ctx := context.Background()

	register := func(t *testing.T, privateData []byte) (*WebAuthnService, *memory.Store, *domain.Tenant, error) {
		t.Helper()
		setup := newTestVirtualWebAuthnSetup(t)
		tenant := &domain.Tenant{ID: "pd-tenant", Name: "PD", DisplayName: "PD", Enabled: true}
		require.NoError(t, setup.store.Tenants().Create(ctx, tenant))
		begin, err := setup.service.BeginRegistration(ctx, &BeginRegistrationRequest{DisplayName: "PD", TenantID: string(tenant.ID)})
		require.NoError(t, err)
		opts := vwaOptions(t, begin.CreateOptions)
		resp := virtualwebauthn.CreateAttestationResponse(setup.rp, setup.authenticator, setup.credential, opts)
		if privateData != nil {
			// build the container for the credential this registration creates
			privateData = bytesReplace(privateData, "SELF", storedID(setup.credential))
		}
		_, err = setup.service.FinishRegistration(ctx, &FinishRegistrationRequest{
			ChallengeID: begin.ChallengeID,
			Credential:  json.RawMessage(resp),
			DisplayName: "PD",
			PrivateData: privateData,
		})
		return setup.service, setup.store, tenant, err
	}

	t.Run("foreign container refused, no user created", func(t *testing.T) {
		_, store, tenant, err := register(t, testPrivateDataContainer(testCredID("x")))
		require.ErrorIs(t, err, ErrPrivateDataOwnership)
		users, err := store.UserTenants().GetTenantUsers(ctx, tenant.ID)
		require.NoError(t, err)
		assert.Empty(t, users)
	})

	for name, d := range map[string][]byte{
		"empty prfKeys": testPrivateDataContainer(),
		"not JSON":      []byte("test-private-data"),
		"null":          []byte("null"),
	} {
		t.Run(name+" refused", func(t *testing.T) {
			_, _, _, err := register(t, d)
			require.ErrorIs(t, err, ErrPrivateDataOwnership)
		})
	}

	t.Run("container with the new credential accepted", func(t *testing.T) {
		_, store, tenant, err := register(t, testPrivateDataContainer("SELF", testCredID("stale")))
		require.NoError(t, err)
		users, err := store.UserTenants().GetTenantUsers(ctx, tenant.ID)
		require.NoError(t, err)
		assert.Len(t, users, 1)
	})

	t.Run("no private data still accepted", func(t *testing.T) {
		_, _, _, err := register(t, nil)
		require.NoError(t, err)
	})
}

func TestFinishAddCredential_PrivateDataOwnership(t *testing.T) {
	ctx := context.Background()

	// An existing user with one real credential and private data for it.
	prepare := func(t *testing.T) (*testVirtualWebAuthnSetup, *domain.User, virtualwebauthn.Credential, virtualwebauthn.AttestationOptions, string) {
		t.Helper()
		setup := newTestVirtualWebAuthnSetup(t)
		user := &domain.User{
			UUID:                domain.NewUserID(),
			WebauthnCredentials: []domain.WebauthnCredential{{ID: testCredID("a"), CredentialID: []byte("cred-a")}},
		}
		user.UpdatePrivateData(testPrivateDataContainer(testCredID("a")))
		require.NoError(t, setup.store.Users().Create(ctx, user))

		begin, err := setup.service.BeginAddCredential(ctx, user.UUID)
		require.NoError(t, err)
		opts := vwaOptions(t, begin.CreateOptions)
		return setup, user, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), opts, begin.ChallengeID
	}
	finish := func(setup *testVirtualWebAuthnSetup, user *domain.User, cred virtualwebauthn.Credential, opts virtualwebauthn.AttestationOptions, challengeID string, pd []byte) error {
		resp := virtualwebauthn.CreateAttestationResponse(setup.rp, setup.authenticator, cred, opts)
		_, err := setup.service.FinishAddCredential(ctx, user.UUID, &FinishAddCredentialRequest{
			ChallengeID: challengeID,
			Credential:  json.RawMessage(resp),
			PrivateData: pd,
		}, "")
		return err
	}

	t.Run("foreign container refused, nothing stored", func(t *testing.T) {
		setup, user, cred, opts, cid := prepare(t)
		before, _ := setup.store.Users().GetByID(ctx, user.UUID)

		err := finish(setup, user, cred, opts, cid, testPrivateDataContainer(testCredID("x")))
		require.ErrorIs(t, err, ErrPrivateDataOwnership)

		after, _ := setup.store.Users().GetByID(ctx, user.UUID)
		assert.Equal(t, before.PrivateData, after.PrivateData)
		assert.Equal(t, before.PrivateDataETag, after.PrivateDataETag)
		assert.Len(t, after.WebauthnCredentials, 1, "credential must not be added on refusal")
	})

	t.Run("container with only the new credential accepted", func(t *testing.T) {
		setup, user, cred, opts, cid := prepare(t)
		data := testPrivateDataContainer(storedID(cred))
		require.NoError(t, finish(setup, user, cred, opts, cid, data))
		after, _ := setup.store.Users().GetByID(ctx, user.UUID)
		assert.Equal(t, data, after.PrivateData)
		assert.Len(t, after.WebauthnCredentials, 2)
	})

	t.Run("partial overlap accepted", func(t *testing.T) {
		setup, user, cred, opts, cid := prepare(t)
		require.NoError(t, finish(setup, user, cred, opts, cid, testPrivateDataContainer(testCredID("a"), testCredID("stale"))))
	})

	t.Run("empty prfKeys and garbage refused", func(t *testing.T) {
		for _, d := range [][]byte{testPrivateDataContainer(), []byte("opaque"), []byte("null")} {
			setup, user, cred, opts, cid := prepare(t)
			require.ErrorIs(t, finish(setup, user, cred, opts, cid, d), ErrPrivateDataOwnership)
		}
	})

	t.Run("no private data supplied leaves it untouched", func(t *testing.T) {
		setup, user, cred, opts, cid := prepare(t)
		before, _ := setup.store.Users().GetByID(ctx, user.UUID)
		require.NoError(t, finish(setup, user, cred, opts, cid, nil))
		after, _ := setup.store.Users().GetByID(ctx, user.UUID)
		assert.Equal(t, before.PrivateData, after.PrivateData)
		assert.Len(t, after.WebauthnCredentials, 2)
	})
}

func bytesReplace(b []byte, old, new string) []byte {
	return []byte(strings.ReplaceAll(string(b), old, new))
}

func TestPrivateDataWritePaths_RefuseBrokenEnvelope(t *testing.T) {
	ctx := context.Background()

	t.Run("UpdatePrivateData", func(t *testing.T) {
		for name, d := range testBrokenEnvelopes(testCredID("a")) {
			svc, store, user := newPrivateDataUserService(t)
			before, _ := store.Users().GetByID(ctx, user.UUID)
			_, err := svc.UpdatePrivateData(ctx, user.UUID, d, "")
			require.ErrorIs(t, err, ErrPrivateDataOwnership, name)
			after, _ := store.Users().GetByID(ctx, user.UUID)
			assert.Equal(t, before.PrivateData, after.PrivateData, name)
			assert.Equal(t, before.PrivateDataETag, after.PrivateDataETag, name)
		}
	})

	t.Run("DeleteWebAuthnCredential", func(t *testing.T) {
		for name, d := range testBrokenEnvelopes(testCredID("b")) {
			svc, store, user := newPrivateDataUserService(t)
			_, err := svc.DeleteWebAuthnCredential(ctx, user.UUID, testCredID("a"), d, "")
			require.ErrorIs(t, err, ErrPrivateDataOwnership, name)
			after, _ := store.Users().GetByID(ctx, user.UUID)
			assert.Len(t, after.WebauthnCredentials, 2, name)
		}
	})

	t.Run("Register", func(t *testing.T) {
		// no credentials: refused regardless, but the broken envelope must not change that
		svc := NewUserService(memory.NewStore(), testConfig(), testLogger())
		for name, d := range testBrokenEnvelopes(testCredID("a")) {
			_, err := svc.Register(ctx, &domain.RegisterRequest{DisplayName: "x", PrivateData: d})
			require.ErrorIs(t, err, ErrPrivateDataOwnership, name)
		}
	})

	t.Run("FinishAddCredential", func(t *testing.T) {
		setup := newTestVirtualWebAuthnSetup(t)
		for name, d := range testBrokenEnvelopes(testCredID("a")) {
			user := &domain.User{
				UUID:                domain.NewUserID(),
				WebauthnCredentials: []domain.WebauthnCredential{{ID: testCredID("a"), CredentialID: []byte("cred-a")}},
			}
			user.UpdatePrivateData(testPrivateDataContainer(testCredID("a")))
			require.NoError(t, setup.store.Users().Create(ctx, user))
			begin, err := setup.service.BeginAddCredential(ctx, user.UUID)
			require.NoError(t, err)
			opts := vwaOptions(t, begin.CreateOptions)
			resp := virtualwebauthn.CreateAttestationResponse(setup.rp, setup.authenticator, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), opts)
			_, err = setup.service.FinishAddCredential(ctx, user.UUID, &FinishAddCredentialRequest{
				ChallengeID: begin.ChallengeID, Credential: json.RawMessage(resp), PrivateData: d,
			}, "")
			require.ErrorIs(t, err, ErrPrivateDataOwnership, name)
			after, _ := setup.store.Users().GetByID(ctx, user.UUID)
			assert.Len(t, after.WebauthnCredentials, 1, name)
		}
	})

	t.Run("FinishRegistration", func(t *testing.T) {
		for name, d := range testBrokenEnvelopes("SELF") {
			setup := newTestVirtualWebAuthnSetup(t)
			begin, err := setup.service.BeginRegistration(ctx, &BeginRegistrationRequest{DisplayName: "PD"})
			require.NoError(t, err)
			opts := vwaOptions(t, begin.CreateOptions)
			resp := virtualwebauthn.CreateAttestationResponse(setup.rp, setup.authenticator, setup.credential, opts)
			d = bytesReplace(d, "SELF", storedID(setup.credential))
			_, err = setup.service.FinishRegistration(ctx, &FinishRegistrationRequest{
				ChallengeID: begin.ChallengeID, Credential: json.RawMessage(resp), DisplayName: "PD", PrivateData: d,
			})
			require.ErrorIs(t, err, ErrPrivateDataOwnership, name)
		}
	})
}
