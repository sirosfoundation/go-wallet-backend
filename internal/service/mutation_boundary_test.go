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
			require.NoError(t, store.WalletInstances().Upsert(base, &domain.WalletInstance{ID: "inst"}))
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
