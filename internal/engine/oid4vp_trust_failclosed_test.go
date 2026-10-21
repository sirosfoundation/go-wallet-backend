package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// keyRecordingPDP is a trust evaluator that always trusts and records what
// identity inputs (subject and key) reached it, so a test can assert that
// attacker-controlled key material never gets that far.
type keyRecordingPDP struct {
	subjects []string
	keys     []interface{}
}

func (p *keyRecordingPDP) Evaluate(_ context.Context, req *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	p.subjects = append(p.subjects, req.SubjectID)
	p.keys = append(p.keys, req.Key)
	return &trust.EvaluationResponse{Decision: true}, nil
}
func (p *keyRecordingPDP) Name() string { return "key-recording-pdp" }
func (p *keyRecordingPDP) SupportedResourceTypes() []trust.ResourceType {
	return []trust.ResourceType{trust.ResourceTypeJWK, trust.ResourceTypeX5C}
}
func (p *keyRecordingPDP) Healthy() bool { return true }

// tamperJWTSignature returns jwtStr with its signature replaced by a
// well-formed but wrong one, leaving header and payload (and so any embedded
// x5c/jwk) intact: the shape of an attacker replaying a victim's public key
// without holding its private key.
func tamperJWTSignature(t *testing.T, jwtStr string) string {
	t.Helper()
	i := strings.LastIndex(jwtStr, ".")
	require.Positive(t, i)
	return jwtStr[:i+1] + strings.Repeat("A", 86)
}

func newKeyRecordingHandler(t *testing.T) (*OID4VPHandler, *keyRecordingPDP) {
	t.Helper()
	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	pdp := &keyRecordingPDP{}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return pdp, nil })
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		for {
			if _, _, err := srvConn.ReadMessage(); err != nil {
				return
			}
		}
	})
	t.Cleanup(cleanup)
	flow := &Flow{ID: "test-flow", Session: testSession(conn), Data: make(map[string]interface{})}
	return &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc,
		TrustCache: NewTrustCache(time.Hour),
	}}, pdp
}

// A request object whose signature does not verify must never yield a trusted
// identity under the default (redirect_uri) scheme, and its unverified header
// key must never reach the PDP.
func TestEvaluateVerifierTrust_RedirectURI_BadSignatureFailsClosed(t *testing.T) {
	good, _ := makeSignedJWTWithX5C(t)
	h, pdp := newKeyRecordingHandler(t)

	authReq := &AuthorizationRequest{
		ClientID:       "https://verifier.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     tamperJWTSignature(t, good),
	}
	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.Error(t, err)
	assert.Nil(t, verifier)
	assert.Empty(t, pdp.subjects, "an unverified request object must not reach the PDP at all")
}

// Control for the test above: the same request with a VALID signature still
// evaluates, and its (now proven) header key is what reaches the PDP.
func TestEvaluateVerifierTrust_RedirectURI_ValidSignatureForwardsVerifiedKey(t *testing.T) {
	good, _ := makeSignedJWTWithX5C(t)
	h, pdp := newKeyRecordingHandler(t)

	authReq := &AuthorizationRequest{
		ClientID:       "https://verifier.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     good,
	}
	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.True(t, verifier.Trusted)
	require.Len(t, pdp.keys, 1)
	assert.NotNil(t, pdp.keys[0], "a key proven by a valid signature is forwarded")
}

// client_metadata is attacker-supplied and carries no proof of possession, so
// keys in it must not be presented to the PDP as the verifier's identity key.
func TestEvaluateVerifierTrust_RedirectURI_ClientMetadataKeysNotForwarded(t *testing.T) {
	good, _ := makeSignedJWTWithX5C(t)
	victimX5C := trust.ExtractKeyMaterialFromJWT(good).X5C

	for name, meta := range map[string]*ClientMetadata{
		"x5c":  {X5C: victimX5C},
		"jwks": {JWKS: []byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`)},
	} {
		t.Run(name, func(t *testing.T) {
			h, pdp := newKeyRecordingHandler(t)
			authReq := &AuthorizationRequest{
				ClientID:       "https://verifier.example.com",
				ClientIDScheme: ClientIDSchemeRedirectURI,
				Nonce:          "n",
				ResponseURI:    "https://verifier.example.com/response",
				ClientMetadata: meta,
			}
			_, err := h.evaluateVerifierTrust(context.Background(), authReq)
			require.NoError(t, err)
			require.Len(t, pdp.keys, 1)
			assert.Nil(t, pdp.keys[0], "unproven client_metadata key material must not reach the PDP")
		})
	}
}

// A client_id that carries a signed-required scheme prefix must not be
// evaluated under a different declared scheme: declaring redirect_uri for
// "x509_san_dns:..." would skip the signature check that scheme requires
// while the PDP (which parses the prefix itself) still treats the client_id
// as a certificate-bound identity.
func TestValidateAuthorizationRequest_DeclaredSchemeMustMatchClientIDPrefix(t *testing.T) {
	for _, tc := range []struct{ clientID, declared string }{
		{"x509_san_dns:verifier.example.com", ClientIDSchemeRedirectURI},
		{"x509_san_uri:https://verifier.example.com", ClientIDSchemeRedirectURI},
		{"x509_hash:abc", ClientIDSchemeRedirectURI},
		{"verifier_attestation:verifier.example.com", ClientIDSchemeRedirectURI},
		{"did:web:verifier.example.com", ClientIDSchemeRedirectURI},
		{"decentralized_identifier:did:web:verifier.example.com", ClientIDSchemeRedirectURI},
		{"x509_san_dns:verifier.example.com", ClientIDSchemeX509Hash},
	} {
		t.Run(tc.clientID+"/"+tc.declared, func(t *testing.T) {
			h := &OID4VPHandler{}
			err := h.validateAuthorizationRequest(&AuthorizationRequest{
				Nonce:          "n",
				ResponseMode:   ResponseModeDirectPost,
				ResponseURI:    "https://verifier.example.com/response",
				ClientID:       tc.clientID,
				ClientIDScheme: tc.declared,
			}, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "does not match")
		})
	}
}

// Prefixed and draft-style (separate client_id_scheme) forms that DO agree,
// and the did / decentralized_identifier spellings of one scheme, stay valid.
func TestValidateAuthorizationRequest_ConsistentSchemeStillAccepted(t *testing.T) {
	good, _ := makeSignedJWTWithX5C(t)
	for _, tc := range []struct{ clientID, declared string }{
		{"https://verifier.example.com", ClientIDSchemeRedirectURI},
		{"did:web:verifier.example.com", ClientIDSchemeDecentralizedIdentifier},
		{"did:web:verifier.example.com", ClientIDSchemeDID},
		{"decentralized_identifier:did:web:verifier.example.com", ClientIDSchemeDecentralizedIdentifier},
		{"verifier.example.com", ClientIDSchemeX509SANDNS},
		{"x509_san_dns:verifier.example.com", ClientIDSchemeX509SANDNS},
	} {
		t.Run(tc.clientID+"/"+tc.declared, func(t *testing.T) {
			h := &OID4VPHandler{}
			req := &AuthorizationRequest{
				Nonce:          "n",
				ResponseMode:   ResponseModeDirectPost,
				ResponseURI:    "https://verifier.example.com/response",
				ClientID:       tc.clientID,
				ClientIDScheme: tc.declared,
			}
			if tc.declared == ClientIDSchemeX509SANDNS {
				req.RequestJWT = good
			}
			require.NoError(t, h.validateAuthorizationRequest(req, nil))
		})
	}
}

// Every scheme that requires a signed request object must refuse a bad or
// absent signature before anything is sent to the PDP.
func TestEvaluateVerifierTrust_SignedSchemes_BadOrMissingSignatureFailClosed(t *testing.T) {
	good, _ := makeSignedJWTWithX5C(t)
	for _, tc := range []struct{ clientID, scheme string }{
		{"x509_san_dns:verifier.example.com", ClientIDSchemeX509SANDNS},
		{"x509_san_uri:https://verifier.example.com", ClientIDSchemeX509SANURI},
		{"x509_hash:abc", ClientIDSchemeX509Hash},
		{"verifier_attestation:verifier.example.com", ClientIDSchemeVerifierAttestation},
	} {
		for name, jwtStr := range map[string]string{"bad-signature": tamperJWTSignature(t, good), "absent": ""} {
			t.Run(tc.scheme+"/"+name, func(t *testing.T) {
				h, pdp := newKeyRecordingHandler(t)
				_, err := h.evaluateVerifierTrust(context.Background(), &AuthorizationRequest{
					ClientID:       tc.clientID,
					ClientIDScheme: tc.scheme,
					Nonce:          "n",
					ResponseURI:    "https://verifier.example.com/response",
					RequestJWT:     jwtStr,
				})
				require.Error(t, err)
				assert.Empty(t, pdp.subjects)
			})
		}
	}
}
