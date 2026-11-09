package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// recordingEvaluator is a PDP stand-in that records the requests it receives.
type recordingEvaluator struct {
	mu       sync.Mutex
	requests []*trust.EvaluationRequest
	decision bool
}

func (r *recordingEvaluator) Evaluate(_ context.Context, req *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
	if !r.decision {
		return &trust.EvaluationResponse{Decision: false, Reason: "no registry returned positive match"}, nil
	}
	return &trust.EvaluationResponse{Decision: true}, nil
}
func (r *recordingEvaluator) Name() string                                 { return "recording" }
func (r *recordingEvaluator) SupportedResourceTypes() []trust.ResourceType { return nil }
func (r *recordingEvaluator) Healthy() bool                                { return true }

func signerTrustHandler(t *testing.T, ev *recordingEvaluator) *OID4VCIHandler {
	t.Helper()
	cfg := testConfig()
	cfg.Trust.PDPURL = "https://pdp.example.com"
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return ev, nil })
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		for {
			if _, _, err := srvConn.ReadMessage(); err != nil {
				return
			}
		}
	})
	t.Cleanup(cleanup)
	flow := registerTestFlow(testSession(conn), "test-flow")
	return &OID4VCIHandler{BaseHandler: BaseHandler{Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc}}
}

// An application/jwt issuer's payload carries no jwks or signed_metadata, so
// the verified signer's chain from the resolver is the only key material the
// PDP can be given (#540).
func TestEvaluateTrust_SignerChainReachesThePDP(t *testing.T) {
	ev := &recordingEvaluator{decision: true}
	h := signerTrustHandler(t, ev)

	metadata := &IssuerMetadata{
		CredentialIssuer: "https://issuer.example.com",
		CredentialConfigurationsSupported: CredentialConfigurations{
			"pid": {VCT: "urn:eudi:pid:1"},
		},
	}
	signer := &issuermetadata.SignerKeyMaterial{Type: "x5c", X5C: []string{"MIIleaf", "MIIca"}}

	info, err := h.evaluateTrust(context.Background(), "https://issuer.example.com", metadata, true, signer)
	require.NoError(t, err)
	assert.True(t, info.Trusted)

	require.Len(t, ev.requests, 1)
	req := ev.requests[0]
	assert.Equal(t, "x5c", string(req.GetKeyType()), "the PDP must be given the signer chain, not the URL alone")
	assert.NotNil(t, req.GetKey())
	assert.Equal(t, "urn:eudi:pid:1", req.CredentialType, "the credential type is still attached on the signer path")
}

// Without a signer (an unsigned issuer) the request is the resolution-only one
// it always was.
func TestEvaluateTrust_NoSignerStaysResolutionOnly(t *testing.T) {
	ev := &recordingEvaluator{decision: false}
	h := signerTrustHandler(t, ev)

	info, err := h.evaluateTrust(context.Background(), "https://issuer.example.com",
		&IssuerMetadata{CredentialIssuer: "https://issuer.example.com"}, false, nil)
	require.Error(t, err)
	assert.False(t, info.Trusted)

	require.Len(t, ev.requests, 1)
	assert.Empty(t, string(ev.requests[0].GetKeyType()), "no key material may be invented without a signer")
	assert.Nil(t, ev.requests[0].GetKey())
}

// Key material from the metadata body keeps priority over the signer fallback.
func TestEvaluateTrust_MetadataKeyMaterialWinsOverSigner(t *testing.T) {
	ev := &recordingEvaluator{decision: true}
	h := signerTrustHandler(t, ev)

	metadata := &IssuerMetadata{
		CredentialIssuer: "https://issuer.example.com",
		JWKS:             []byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`),
	}
	signer := &issuermetadata.SignerKeyMaterial{Type: "x5c", X5C: []string{"MIIleaf"}}

	_, err := h.evaluateTrust(context.Background(), "https://issuer.example.com", metadata, true, signer)
	require.NoError(t, err)
	require.Len(t, ev.requests, 1)
	assert.Equal(t, "jwk", string(ev.requests[0].GetKeyType()))
}

func TestKeyMaterialFromSigner(t *testing.T) {
	assert.Nil(t, trust.KeyMaterialFromSigner(nil))
	km := trust.KeyMaterialFromSigner(&issuermetadata.SignerKeyMaterial{Type: "x5c", X5C: []string{"a", "b"}})
	require.NotNil(t, km)
	assert.Equal(t, "x5c", km.Type)
	assert.Equal(t, []string{"a", "b"}, km.X5C)
	jwk := map[string]any{"kty": "EC"}
	km = trust.KeyMaterialFromSigner(&issuermetadata.SignerKeyMaterial{Type: "jwk", JWK: jwk})
	assert.Equal(t, jwk, km.JWK)
}
