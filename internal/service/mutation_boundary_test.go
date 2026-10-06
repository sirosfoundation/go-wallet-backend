package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// SID-AUTH-06: a request admitted before a cut-off must be refused at the
// mutation/minting boundary of each wallet-scoped service, with the cut-off
// landing between admission and the mint/write.

func TestGenerateKeyAttestation_CutoffBetweenAdmissionAndMintIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after int
	}{
		{"before minting", 0},
		{"while signing", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := context.Background()
			store := memory.NewStore()
			uid := domain.NewUserID()
			require.NoError(t, store.Users().Create(base, &domain.User{UUID: uid}))
			cutoff := time.Now().Truncate(time.Second)
			svc := newTestWalletProviderService(t)
			svc.SetUsers(&cutoffAdvancingUsers{UserStore: store.Users(), after: tc.after, cutoff: cutoff})

			ctx := tokengate.WithSubject(base, uid.String(), cutoff.Add(-time.Minute))
			ka, err := svc.GenerateKeyAttestation(ctx, []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}}, "n", nil, "", "")
			assert.ErrorIs(t, err, tokengate.ErrRevoked)
			assert.Empty(t, ka, "no key attestation may be released")
		})
	}
}

func TestFIDO2AttestationService_Verify_CutoffBeforeWriteIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name         string
		after        int
		wantRecorded bool
	}{
		{"before the write", 0, false},
		{"during the write", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := context.Background()
			store := memory.NewStore()
			uid := domain.NewUserID()
			require.NoError(t, store.Users().Create(base, &domain.User{UUID: uid}))
			require.NoError(t, store.WalletInstances().Upsert(base, &domain.WalletInstance{ID: "inst", UserID: &uid, Status: domain.InstanceStatusActive}))
			cutoff := time.Now().Truncate(time.Second)

			svc := NewFIDO2AttestationService(testFIDO2AttestationConfig(true), store.WalletInstances(), store.KeyAttestations(),
				newTestTrustService(t, &stubEvaluator{decision: true}), zap.NewNop())
			svc.SetUsers(&cutoffAdvancingUsers{UserStore: store.Users(), after: tc.after, cutoff: cutoff})

			hash := make([]byte, 32)
			attObj, pub := buildTestAttestationObject(t, uuid.New(), hash)
			ctx := tokengate.WithSubject(base, uid.String(), cutoff.Add(-time.Minute))
			err := svc.Verify(ctx, &FIDO2AttestationRequest{WalletInstanceID: "inst", AttestationObject: attObj, ClientDataHash: hash})
			assert.ErrorIs(t, err, tokengate.ErrRevoked)

			_, gerr := store.KeyAttestations().GetByKeyThumbprint(base, expectedThumbprint(t, pub))
			if tc.wantRecorded {
				assert.NoError(t, gerr)
			} else {
				assert.Error(t, gerr, "a refused request must not record the evidence")
			}
		})
	}
}

func TestProxyService_Execute_CutoffAfterAdmissionIsRefused(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()

	base := context.Background()
	store := memory.NewStore()
	uid := domain.NewUserID()
	require.NoError(t, store.Users().Create(base, &domain.User{UUID: uid}))
	cutoff := time.Now().Truncate(time.Second)
	svc := NewProxyService(&config.Config{HTTPClient: config.HTTPClientConfig{AllowPrivateIPs: true}}, zap.NewNop())
	svc.SetUsers(&cutoffAdvancingUsers{UserStore: store.Users(), after: 0, cutoff: cutoff})

	ctx := tokengate.WithSubject(base, uid.String(), cutoff.Add(-time.Minute))
	_, _, err := svc.Execute(ctx, &ProxyRequest{URL: server.URL, Method: "GET"})
	assert.ErrorIs(t, err, tokengate.ErrRevoked)
	assert.Zero(t, hits.Load(), "the outbound request must not be made")
}

// The early check passes, then the cut-off lands during marshaling, request
// construction or header processing: the final recheck immediately before
// dispatch must still stop the outbound request.
func TestProxyService_Execute_CutoffBetweenEarlyCheckAndDispatchIsRefused(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()

	base := context.Background()
	store := memory.NewStore()
	uid := domain.NewUserID()
	require.NoError(t, store.Users().Create(base, &domain.User{UUID: uid}))
	cutoff := time.Now().Truncate(time.Second)
	svc := NewProxyService(&config.Config{HTTPClient: config.HTTPClientConfig{AllowPrivateIPs: true}}, zap.NewNop())
	users := &cutoffAdvancingUsers{UserStore: store.Users(), after: 1, cutoff: cutoff}
	svc.SetUsers(users)

	ctx := tokengate.WithSubject(base, uid.String(), cutoff.Add(-time.Minute))
	resp, _, err := svc.Execute(ctx, &ProxyRequest{URL: server.URL, Method: "POST", Data: map[string]string{"a": "b"}})
	assert.ErrorIs(t, err, tokengate.ErrRevoked)
	assert.Nil(t, resp)
	assert.Zero(t, hits.Load(), "the outbound request must not be made")
	assert.Equal(t, 2, users.reads, "the early and the pre-dispatch check must both read the cut-off")
}

// The user-wide cut-off is not the instance's state: a token that is fresh
// for its user can name a revoked instance (or another user's) and must not
// obtain a KA for it, including a revoked native-attested one that
// keyAttestationTrustsBatch would otherwise treat as trusted.
func TestGenerateKeyAttestation_RefusesNonLiveOrForeignInstance(t *testing.T) {
	base := context.Background()
	svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
	owner, other := domain.NewUserID(), domain.NewUserID()
	for _, inst := range []*domain.WalletInstance{
		{ID: "live", TenantID: "t", UserID: &owner, Status: domain.InstanceStatusActive},
		{ID: "revoked", TenantID: "t", UserID: &owner, Status: domain.InstanceStatusActive, AttestationSource: "ios_app_attest"},
		{ID: "weird", TenantID: "t", UserID: &owner, Status: domain.InstanceStatus("bogus")},
	} {
		require.NoError(t, instances.Upsert(base, inst))
	}
	require.NoError(t, instances.UpdateStatus(base, "revoked", "t", domain.InstanceStatusRevoked, "stolen"))

	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}}
	ctx := tokengate.WithSubject(base, owner.String(), time.Now())

	ka, err := svc.GenerateKeyAttestation(ctx, jwks, "n", nil, "live", "")
	require.NoError(t, err)
	assert.NotEmpty(t, ka)
	_, err = svc.GenerateKeyAttestation(ctx, jwks, "n", &SecurityProperties{KeyStorage: []string{"iso_18045_high"}}, "revoked", "")
	assert.ErrorIs(t, err, tokengate.ErrRevoked)
	_, err = svc.GenerateKeyAttestation(ctx, jwks, "n", nil, "weird", "")
	assert.ErrorIs(t, err, tokengate.ErrRevoked, "an unknown status fails closed")
	_, err = svc.GenerateKeyAttestation(tokengate.WithSubject(base, other.String(), time.Now()), jwks, "n", nil, "live", "")
	assert.ErrorIs(t, err, ErrKeyAttestationInstanceRefused)
}

// An instance not yet bound to a user is nobody's: a token with a subject must
// not mint a KA for it merely by knowing its id. Once bound to the caller it
// is accepted.
func TestGenerateKeyAttestation_RefusesUnboundInstanceForSubject(t *testing.T) {
	base := context.Background()
	svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
	user := domain.NewUserID()
	require.NoError(t, instances.Upsert(base, &domain.WalletInstance{ID: "anon", TenantID: "t", Status: domain.InstanceStatusActive}))
	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}}
	ctx := tokengate.WithSubject(base, user.String(), time.Now())

	ka, err := svc.GenerateKeyAttestation(ctx, jwks, "n", nil, "anon", "")
	assert.ErrorIs(t, err, ErrKeyAttestationInstanceRefused)
	assert.Empty(t, ka)

	require.NoError(t, instances.Upsert(base, &domain.WalletInstance{ID: "anon", TenantID: "t", UserID: &user, Status: domain.InstanceStatusActive}))
	_, err = svc.GenerateKeyAttestation(ctx, jwks, "n", nil, "anon", "")
	assert.NoError(t, err, "bound to the caller")
}

// flipAfterGets reports a revoked status from the nth GetByID on, modelling an
// instance revoked while the KA is being signed.
type flipAfterGets struct {
	storage.WalletInstanceStore
	after, calls int
}

func (f *flipAfterGets) GetByID(ctx context.Context, id string) (*domain.WalletInstance, error) {
	inst, err := f.WalletInstanceStore.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	f.calls++
	if f.calls > f.after {
		cp := *inst
		cp.Status = domain.InstanceStatusRevoked
		return &cp, nil
	}
	return inst, nil
}

// An instance revoked between the pre-mint check and release withholds the KA.
func TestGenerateKeyAttestation_InstanceRevokedWhileSigningIsRefused(t *testing.T) {
	base := context.Background()
	svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
	owner := domain.NewUserID()
	require.NoError(t, instances.Upsert(base, &domain.WalletInstance{ID: "inst", TenantID: "t", UserID: &owner, Status: domain.InstanceStatusActive}))
	// No security_properties: the pre-mint check is the only GetByID before
	// the post-signing one, so after=1 flips exactly the last look.
	svc.instances = &flipAfterGets{WalletInstanceStore: instances, after: 1}

	ka, err := svc.GenerateKeyAttestation(tokengate.WithSubject(base, owner.String(), time.Now()),
		[]map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}}, "n", nil, "inst", "")
	assert.ErrorIs(t, err, tokengate.ErrRevoked)
	assert.Empty(t, ka, "no key attestation may be released")
}

// An instance recorded in another tenant is not accepted for the caller's.
func TestGenerateKeyAttestation_RefusesInstanceOfAnotherTenant(t *testing.T) {
	base := context.Background()
	svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
	require.NoError(t, instances.Upsert(base, &domain.WalletInstance{ID: "inst", TenantID: "other", Status: domain.InstanceStatusActive}))
	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}}

	_, err := svc.GenerateKeyAttestation(WithKeyAttestationTenant(base, "acme"), jwks, "n", nil, "inst", "")
	assert.ErrorIs(t, err, ErrKeyAttestationInstanceRefused)
	_, err = svc.GenerateKeyAttestation(WithKeyAttestationTenant(base, "other"), jwks, "n", nil, "inst", "")
	assert.NoError(t, err)
}
