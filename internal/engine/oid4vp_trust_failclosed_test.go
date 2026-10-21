package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// A verdict reached with a proven key must not be served to a later request
// for the same client_id that does not prove that key (or proves a different
// one): the cache identity is bound to the verified key.
func TestEvaluateVerifierTrust_RedirectURI_CacheBoundToVerifiedKey(t *testing.T) {
	signedA, _ := makeSignedJWTWithX5C(t)
	signedB, _ := makeSignedJWTWithX5C(t)
	h, pdp := newKeyRecordingHandler(t)

	req := func(jwtStr string) *AuthorizationRequest {
		return &AuthorizationRequest{
			ClientID:       "https://verifier.example.com",
			ClientIDScheme: ClientIDSchemeRedirectURI,
			Nonce:          "n",
			ResponseURI:    "https://verifier.example.com/response",
			RequestJWT:     jwtStr,
		}
	}
	_, err := h.evaluateVerifierTrust(context.Background(), req(signedA))
	require.NoError(t, err)
	require.Len(t, pdp.subjects, 1)

	_, err = h.evaluateVerifierTrust(context.Background(), req(""))
	require.NoError(t, err)
	assert.Len(t, pdp.subjects, 2, "an unsigned request must not reuse the verdict of a key-proven one")

	_, err = h.evaluateVerifierTrust(context.Background(), req(signedB))
	require.NoError(t, err)
	assert.Len(t, pdp.subjects, 3, "a different proven key must not reuse another key's verdict")

	_, err = h.evaluateVerifierTrust(context.Background(), req(signedA))
	require.NoError(t, err)
	assert.Len(t, pdp.subjects, 3, "the same proven key is still served from cache")
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

// makeAttestedRequestJWT builds a verifier_attestation request object: an
// attestation JWT (in the "jwt" header) binding cnfKey, and a request JWT
// signed with signKey. The attestation's own signature is the PDP's concern.
func makeAttestedRequestJWT(t *testing.T, sub string, cnfKey, signKey *ecdsa.PrivateKey) string {
	t.Helper()
	b64 := func(v interface{}) string {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	attestation := b64(map[string]interface{}{"alg": "ES256"}) + "." +
		b64(map[string]interface{}{
			"iss": "https://attester.example.com",
			"sub": sub,
			"cnf": map[string]interface{}{"jwk": ecPublicJWK(&cnfKey.PublicKey, "k")},
		}) + ".c2ln"
	signingInput := b64(map[string]interface{}{"alg": "ES256", "kid": "k", "jwt": attestation}) + "." +
		b64(map[string]interface{}{"iss": sub})
	sig, err := jwt.SigningMethodES256.Sign(signingInput, signKey)
	require.NoError(t, err)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString([]byte(sig))
}

// verifier_attestation: a request object not signed by the attestation's cnf
// key must be refused; the same request signed by it is accepted (control,
// so the refusal is about the signature and nothing else).
func TestEvaluateVerifierTrust_VerifierAttestation_RequestSignatureMustMatchCnf(t *testing.T) {
	cnf, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	const sub = "verifier.example.com"

	eval := func(jwtStr string) (*keyRecordingPDP, error) {
		h, pdp := newKeyRecordingHandler(t)
		_, err := h.evaluateVerifierTrust(context.Background(), &AuthorizationRequest{
			ClientID:       "verifier_attestation:" + sub,
			ClientIDScheme: ClientIDSchemeVerifierAttestation,
			Nonce:          "n",
			ResponseURI:    "https://verifier.example.com/response",
			RequestJWT:     jwtStr,
		})
		return pdp, err
	}

	pdp, err := eval(makeAttestedRequestJWT(t, sub, cnf, other))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match attestation cnf key")
	assert.Empty(t, pdp.subjects)

	pdp, err = eval(makeAttestedRequestJWT(t, sub, cnf, cnf))
	require.NoError(t, err)
	assert.Len(t, pdp.subjects, 1)
}

// A signed client_id must not be able to forge the cache key of an unsigned
// request: with response_uri R and key fingerprint F, signed client_id
// "R|client_id:X" and unsigned client_id "X:F" used to produce one key.
func TestEvaluateVerifierTrust_RedirectURI_SignedCacheKeyCannotCollideWithUnsigned(t *testing.T) {
	signed, _ := makeSignedJWTWithX5C(t)
	km := trust.ExtractKeyMaterialFromJWT(signed)
	fp := keyMaterialFingerprint(&KeyMaterial{Type: km.Type, X5C: km.X5C})
	require.NotEmpty(t, fp)
	const resp = "https://verifier.example.com/response"
	const x = "https://victim.example.com"
	h, pdp := newKeyRecordingHandler(t)

	_, err := h.evaluateVerifierTrust(context.Background(), &AuthorizationRequest{
		ClientID: resp + "|client_id:" + x, ClientIDScheme: ClientIDSchemeRedirectURI,
		Nonce: "n", ResponseURI: resp, RequestJWT: signed,
	})
	require.NoError(t, err)
	require.Len(t, pdp.subjects, 1)

	_, err = h.evaluateVerifierTrust(context.Background(), &AuthorizationRequest{
		ClientID: x + ":" + fp, ClientIDScheme: ClientIDSchemeRedirectURI,
		Nonce: "n", ResponseURI: resp,
	})
	require.NoError(t, err)
	assert.Len(t, pdp.subjects, 2, "the unsigned request must reach the PDP itself, not reuse the signed verdict")
}
