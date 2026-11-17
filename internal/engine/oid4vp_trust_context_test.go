package engine

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// contextPDP always trusts and answers with a fixed response context.
type contextPDP struct {
	calls int
	ctx   json.RawMessage
}

func (p *contextPDP) Evaluate(_ context.Context, _ *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	p.calls++
	return &trust.EvaluationResponse{Decision: true, Reason: "pdp says yes", Context: p.ctx}, nil
}
func (p *contextPDP) Name() string { return "context-pdp" }
func (p *contextPDP) SupportedResourceTypes() []trust.ResourceType {
	return []trust.ResourceType{trust.ResourceTypeX5C}
}
func (p *contextPDP) Healthy() bool { return true }

const verifierIDsContext = `{"verifier_ids":[` +
	`{"verifier_id_type":"semantic","verifier_id":"semantic_id:VATSE-556000000101","basis":"x5c-chain"},` +
	`{"verifier_id_type":"x509_san_dns","verifier_id":"verifier.example.com","basis":"client-id-binding"}]}`

// trustProgressHarness runs evaluateVerifierTrust against a PDP answering with
// pdpCtx and collects every verifier_trust_evaluated progress payload sent.
func trustProgressHarness(t *testing.T, pdpCtx json.RawMessage) (eval func() error, payloads func() []map[string]json.RawMessage, pdp *contextPDP) {
	t.Helper()
	jwtStr, _ := makeSignedJWTWithX5C(t)
	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	pdp = &contextPDP{ctx: pdpCtx}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return pdp, nil })

	got := make(chan []byte, 16)
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		for {
			_, b, err := srvConn.ReadMessage()
			if err != nil {
				return
			}
			got <- b
		}
	})
	t.Cleanup(cleanup)

	flow := &Flow{ID: "f", Session: testSession(conn), Data: make(map[string]interface{})}
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: NewTrustCache(time.Hour),
	}}
	authReq := &AuthorizationRequest{
		ClientID:       "x509_san_dns:verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     jwtStr,
	}
	eval = func() error {
		_, err := h.evaluateVerifierTrust(context.Background(), authReq)
		return err
	}
	payloads = func() []map[string]json.RawMessage {
		var out []map[string]json.RawMessage
		for {
			select {
			case b := <-got:
				var m FlowProgressMessage
				require.NoError(t, json.Unmarshal(b, &m))
				var p map[string]json.RawMessage
				if json.Unmarshal(m.Payload, &p) == nil {
					if _, ok := p["verifier_trust_evaluated"]; ok {
						out = append(out, p)
					}
				}
			case <-time.After(300 * time.Millisecond):
				return out
			}
		}
	}
	return eval, payloads, pdp
}

// Fresh evaluation and cache hit both carry the narrowed verifier_ids context.
func TestEvaluateVerifierTrust_ProgressCarriesPDPContext_FreshAndCacheHit(t *testing.T) {
	eval, payloads, pdp := trustProgressHarness(t, json.RawMessage(verifierIDsContext))

	require.NoError(t, eval())
	require.NoError(t, eval())
	require.Equal(t, 1, pdp.calls, "second evaluation must be a cache hit")

	ps := payloads()
	require.Len(t, ps, 2, "fresh evaluation and cache hit each emit verifier_trust_evaluated")
	for i, p := range ps {
		assert.JSONEq(t, verifierIDsContext, string(p["context"]), "payload %d", i)
		assert.JSONEq(t, `true`, string(p["trusted"]))
		assert.JSONEq(t, `"pdp says yes"`, string(p["reason"]), "payload %d: reason survives a cache hit", i)
	}
}

// No PDP context -> no "context" member at all, fresh or cached.
func TestEvaluateVerifierTrust_ProgressOmitsContextWhenPDPGaveNone(t *testing.T) {
	eval, payloads, _ := trustProgressHarness(t, nil)

	require.NoError(t, eval())
	require.NoError(t, eval())

	ps := payloads()
	require.Len(t, ps, 2)
	for i, p := range ps {
		_, has := p["context"]
		assert.False(t, has, "payload %d must not carry an empty context", i)
	}
}

const adminContext = `{"reason":{"admin":"secret detail"},"trust_metadata":{"k":"v"},"extra":1,"verifier_ids":[` +
	`{"verifier_id_type":"x509_san_dns","verifier_id":"verifier.example.com","basis":"client-id-binding","internal":"x"}]}`

// reason and trust_metadata (and any other member) must never be forwarded,
// fresh or cached, nor retained in the cache record.
func TestEvaluateVerifierTrust_ProgressDoesNotForwardAdminContext(t *testing.T) {
	eval, payloads, _ := trustProgressHarness(t, json.RawMessage(adminContext))

	require.NoError(t, eval())
	require.NoError(t, eval())

	want := `{"verifier_ids":[{"verifier_id_type":"x509_san_dns","verifier_id":"verifier.example.com","basis":"client-id-binding"}]}`
	ps := payloads()
	require.Len(t, ps, 2)
	for i, p := range ps {
		assert.JSONEq(t, want, string(p["context"]), "payload %d", i)
		assert.NotContains(t, string(p["context"]), "secret detail")
		assert.NotContains(t, string(p["context"]), "trust_metadata")
	}
}

// A context with no verifier_ids (only admin members) yields no context member.
func TestEvaluateVerifierTrust_ProgressOmitsContextWithoutVerifierIDs(t *testing.T) {
	eval, payloads, _ := trustProgressHarness(t, json.RawMessage(`{"reason":{"a":1},"trust_metadata":{}}`))
	require.NoError(t, eval())
	require.NoError(t, eval())
	ps := payloads()
	require.Len(t, ps, 2)
	for i, p := range ps {
		_, has := p["context"]
		assert.False(t, has, "payload %d", i)
	}
}

func TestNarrowVerifierContext(t *testing.T) {
	assert.Nil(t, narrowVerifierContext(nil))
	assert.Nil(t, narrowVerifierContext(json.RawMessage(`not json`)))
	assert.Nil(t, narrowVerifierContext(json.RawMessage(`{"verifier_ids":[]}`)))
	assert.Nil(t, narrowVerifierContext(json.RawMessage(`{"verifier_ids":[{"verifier_id_type":"x"}]}`)))
	assert.JSONEq(t, `{"verifier_ids":[{"verifier_id_type":"a","verifier_id":"b"}]}`,
		string(narrowVerifierContext(json.RawMessage(`{"reason":1,"verifier_ids":[{"verifier_id_type":"a","verifier_id":"b","z":1}]}`))))
}

// The cache stores the context it was given, so a hit can replay it.
func TestTrustCacheRecord_RoundTripsContext(t *testing.T) {
	c := NewTrustCache(time.Hour)
	c.Set("t", "k", &TrustCacheRecord{Trusted: true, Context: json.RawMessage(`{"verifier_ids":[]}`)})
	got := c.Get("t", "k")
	require.NotNil(t, got)
	assert.JSONEq(t, `{"verifier_ids":[]}`, string(got.Context))
}
