package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// evalVerified runs evaluateVerifierTrust and returns the inputs it built. With
// withPDP false no verifier PDP is configured, so the call blocks on the
// frontend trust_result that never comes; the inputs are built before that.
func evalVerified(t *testing.T, authReq *AuthorizationRequest, withPDP bool, stub *stubDIDResolver) *VerifiedRequestInputs {
	t.Helper()
	cfg := testConfig()
	if withPDP {
		cfg.Trust.PDPURL = "http://pdp.test"
	}
	if stub == nil {
		stub = &stubDIDResolver{decisionOk: true, decision: true}
	}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	conn, cleanup := wsTestServer(t, func(c *websocket.Conn) {
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	})
	t.Cleanup(cleanup)
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow:   &Flow{ID: "f", Session: testSession(conn), Data: map[string]interface{}{}},
		Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: NewTrustCache(time.Hour),
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, _ = h.evaluateVerifierTrust(ctx, authReq)
	require.NotNil(t, authReq.Verified, "evaluateVerifierTrust must build the inputs")
	return authReq.Verified
}

func TestVerifiedRequestInputs_PerScheme(t *testing.T) {
	x5cJWT, _ := makeSignedJWTWithX5C(t)
	cnf, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	attested := makeAttestedRequestJWT(t, "verifier.example.com", cnf, cnf)

	didKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	const did = "did:web:verifier.example.com"
	didStub := &stubDIDResolver{decisionOk: true, decision: true, didDoc: map[string]interface{}{
		"id": did,
		"verificationMethod": []interface{}{map[string]interface{}{
			"id": did + "#k", "type": "JsonWebKey2020", "controller": did,
			"publicKeyJwk": ecPublicJWK(&didKey.PublicKey, did+"#k"),
		}},
	}}
	didJWT := buildKidSignedJWT(t, didKey, did+"#k")

	for _, tc := range []struct {
		name, clientID, scheme, jwt string
		pdp                         bool
		stub                        *stubDIDResolver
		signed                      bool
		state                       string
	}{
		{"x509_san_dns", "x509_san_dns:verifier.example.com", ClientIDSchemeX509SANDNS, x5cJWT, true, nil, true, SignatureVerified},
		{"x509_san_uri", "x509_san_uri:https://verifier.example.com", ClientIDSchemeX509SANURI, x5cJWT, true, nil, true, SignatureVerified},
		{"x509_hash", "x509_hash:abc", ClientIDSchemeX509Hash, x5cJWT, true, nil, true, SignatureVerified},
		{"did with PDP", did, ClientIDSchemeDID, didJWT, true, didStub, true, SignatureVerified},
		{"did without PDP is deferred", did, ClientIDSchemeDID, didJWT, false, nil, false, SignatureDeferred},
		{"verifier_attestation with PDP", "verifier_attestation:verifier.example.com", ClientIDSchemeVerifierAttestation, attested, true, nil, true, SignatureVerified},
		{"verifier_attestation without PDP is deferred", "verifier_attestation:verifier.example.com", ClientIDSchemeVerifierAttestation, attested, false, nil, false, SignatureDeferred},
		// A valid embedded key proves possession only.
		{"redirect_uri self-signed", "https://verifier.example.com", ClientIDSchemeRedirectURI, x5cJWT, true, nil, false, SignatureNone},
		{"redirect_uri unsigned", "https://verifier.example.com", ClientIDSchemeRedirectURI, "", true, nil, false, SignatureNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authReq := &AuthorizationRequest{
				ClientID: tc.clientID, ClientIDScheme: tc.scheme, Nonce: "n",
				ResponseMode: "direct_post.jwt", ResponseURI: "https://verifier.example.com/response",
				RequestJWT:        tc.jwt,
				ClientMetadataRaw: json.RawMessage(`{"client_name":"x"}`),
			}
			got := evalVerified(t, authReq, tc.pdp, tc.stub)
			assert.Equal(t, tc.clientID, got.ClientID, "the request's own client_id, not the VP audience")
			assert.Equal(t, tc.scheme, got.ClientIDScheme)
			assert.Equal(t, "direct_post.jwt", got.ResponseMode)
			assert.Equal(t, "https://verifier.example.com/response", got.ResponseURI)
			assert.Equal(t, tc.signed, got.Signed)
			assert.Equal(t, tc.state, got.SignatureVerification)
			assert.JSONEq(t, `{"client_name":"x"}`, string(got.ClientMetadata))
		})
	}
}

// credential_selection, match_request and sign_presentation must carry the
// same inputs, value for value.
func TestVerifiedRequestInputs_IdenticalAtAllEmissionPoints(t *testing.T) {
	h, session, received, cleanup := newSelectionTestHandler(t)
	defer cleanup()
	authReq := &AuthorizationRequest{
		ClientID: "x509_san_dns:verifier.example.com", ClientIDScheme: ClientIDSchemeX509SANDNS,
		ResponseMode: "direct_post", ResponseURI: "https://verifier.example.com/response", Nonce: "n",
		DCQLQuery:         json.RawMessage(`{"credentials":[{"id":"q","format":"dc+sd-jwt"}]}`),
		ClientMetadataRaw: json.RawMessage(zkpClientMetadata),
	}
	authReq.Verified = newVerifiedRequestInputs(authReq, SignatureVerified)
	want, err := json.Marshal(authReq.Verified)
	require.NoError(t, err)

	feedAction(t, session, h.Flow.ID, ActionDecline, map[string]string{"reason": "x"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = h.requestCredentialSelection(ctx, authReq, &VerifierInfo{ClientID: "admin-configured-audience"})
	sel := awaitMessage(t, received, "flow_progress")
	selPayload, ok := sel["payload"].(map[string]any)
	require.True(t, ok, "msg: %v", sel)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	_, _ = h.RequestMatchWithClientMetadata(ctx2, authReq.DCQLQuery, authReq.Verified)
	match := awaitMessage(t, received, "match_request")

	ctx3, cancel3 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel3()
	_, _ = h.requestVPSignature(ctx3, authReq, []ConsentSelection{{CredentialID: "c", CredentialQueryID: "q"}}, "admin-configured-audience")
	sign := awaitMessage(t, received, "sign_request")
	signParams, _ := sign["params"].(map[string]any)

	for name, got := range map[string]any{
		"credential_selection": selPayload["verified_request"],
		"match_request":        match["verified_request"],
		"sign_presentation":    signParams["verified_request"],
	} {
		raw, err := json.Marshal(got)
		require.NoError(t, err)
		assert.JSONEq(t, string(want), string(raw), name)
	}
}

// A request that never went through evaluateVerifierTrust is reported as
// nothing verified, never as more.
func TestVerifiedInputs_DefaultsToNothingVerified(t *testing.T) {
	got := verifiedInputs(&AuthorizationRequest{ClientID: "x509_san_dns:a", ClientIDScheme: ClientIDSchemeX509SANDNS})
	assert.False(t, got.Signed)
	assert.Equal(t, SignatureNone, got.SignatureVerification)
}
