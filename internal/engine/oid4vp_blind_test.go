package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// The engine is blind to a direct_post.jwt response: it resolves the verifier
// key and algorithms, the CLIENT builds and encrypts the JARM response, and the
// engine relays the compact JWE.

const blindSentinel = "SENTINEL-vp-token-never-in-the-engine"

// clientEncryptJARM does what a client does with a sign_presentation request:
// builds the JARM claims around its vp_token and encrypts them to the verifier
// key the request carried.
func clientEncryptJARM(t *testing.T, params map[string]any, aud string, vpToken any) string {
	t.Helper()
	re, ok := params["response_encryption"].(map[string]any)
	require.True(t, ok, "params: %v", params)
	rawJWK, err := json.Marshal(re["jwk"])
	require.NoError(t, err)
	var jwk jose.JSONWebKey
	require.NoError(t, jwk.UnmarshalJSON(rawJWK))
	claims := map[string]any{
		"iss": "https://self-issued.me/v2", "aud": aud,
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"vp_token": vpToken,
	}
	if st, ok := params["state"].(string); ok {
		claims["state"] = st
	}
	plain, err := json.Marshal(claims)
	require.NoError(t, err)
	enc, err := jose.NewEncrypter(jose.ContentEncryption(re["enc"].(string)),
		jose.Recipient{Algorithm: jose.KeyAlgorithm(re["alg"].(string)), Key: jwk.Key, KeyID: jwk.KeyID},
		(&jose.EncrypterOptions{}).WithContentType("JWT"))
	require.NoError(t, err)
	obj, err := enc.Encrypt(plain)
	require.NoError(t, err)
	out, err := obj.CompactSerialize()
	require.NoError(t, err)
	return out
}

func ecJWKS(t *testing.T, kid string) (*ecdsa.PrivateKey, json.RawMessage) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k, makeJWKS(jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Use: "enc"})
}

// --- key and algorithm resolution (the engine's existing selection) ---

func TestResolveResponseEncryption(t *testing.T) {
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}}

	t.Run("explicit alg and enc, kid carried", func(t *testing.T) {
		_, jwks := ecJWKS(t, "enc-key-1")
		got, err := h.resolveResponseEncryption(&AuthorizationRequest{ClientMetadata: &ClientMetadata{
			JWKS: jwks, AuthorizationEncryptedResponseAlg: "ECDH-ES", AuthorizationEncryptedResponseEnc: "A256GCM"}})
		require.NoError(t, err)
		assert.Equal(t, "ECDH-ES", got.Alg)
		assert.Equal(t, "A256GCM", got.Enc)
		var jwk map[string]any
		require.NoError(t, json.Unmarshal(got.JWK, &jwk))
		assert.Equal(t, "enc-key-1", jwk["kid"])
		assert.NotContains(t, jwk, "d", "never a private member")
	})
	t.Run("default enc is A128GCM, alg inferred from an EC key", func(t *testing.T) {
		_, jwks := ecJWKS(t, "k")
		got, err := h.resolveResponseEncryption(&AuthorizationRequest{ClientMetadata: &ClientMetadata{JWKS: jwks}})
		require.NoError(t, err)
		assert.Equal(t, "ECDH-ES", got.Alg)
		assert.Equal(t, "A128GCM", got.Enc)
	})
	t.Run("JWK alg honoured when it is a JARM key-management alg", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		got, err := h.resolveResponseEncryption(&AuthorizationRequest{ClientMetadata: &ClientMetadata{
			JWKS: makeJWKS(jose.JSONWebKey{Key: &k.PublicKey, KeyID: "k", Use: "enc", Algorithm: "ECDH-ES+A256KW"})}})
		require.NoError(t, err)
		assert.Equal(t, "ECDH-ES+A256KW", got.Alg)
	})
	t.Run("a signature alg on the JWK is ignored", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		got, err := h.resolveResponseEncryption(&AuthorizationRequest{ClientMetadata: &ClientMetadata{
			JWKS: makeJWKS(jose.JSONWebKey{Key: &k.PublicKey, KeyID: "k", Use: "enc", Algorithm: "ES256"})}})
		require.NoError(t, err)
		assert.Equal(t, "ECDH-ES", got.Alg)
	})
	t.Run("RSA key infers RSA-OAEP", func(t *testing.T) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		got, err := h.resolveResponseEncryption(&AuthorizationRequest{ClientMetadata: &ClientMetadata{
			JWKS: makeJWKS(jose.JSONWebKey{Key: &k.PublicKey, KeyID: "r", Use: "enc"})}})
		require.NoError(t, err)
		assert.Equal(t, "RSA-OAEP", got.Alg)
	})
	t.Run("x5c key with no client_metadata", func(t *testing.T) {
		leaf, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "v"},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &leaf.PublicKey, leaf)
		require.NoError(t, err)
		got, err := h.resolveResponseEncryption(&AuthorizationRequest{
			RequestJWT: buildMinimalJWT(t, leaf, base64.StdEncoding.EncodeToString(der))})
		require.NoError(t, err)
		assert.Equal(t, "ECDH-ES", got.Alg)
		assert.Equal(t, "A128GCM", got.Enc)
	})
	t.Run("no key refuses", func(t *testing.T) {
		_, err := h.resolveResponseEncryption(&AuthorizationRequest{ClientMetadata: &ClientMetadata{}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorization_encrypted_response_alg")
	})
	t.Run("a private JWK is refused, never relayed", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		_, err := h.resolveResponseEncryption(&AuthorizationRequest{ClientMetadata: &ClientMetadata{
			JWKS: makeJWKS(jose.JSONWebKey{Key: k, KeyID: "k", Use: "enc"})}})
		require.Error(t, err)
	})
	t.Run("unsupported alg or enc refuses", func(t *testing.T) {
		_, jwks := ecJWKS(t, "k")
		_, err := h.resolveResponseEncryption(&AuthorizationRequest{ClientMetadata: &ClientMetadata{
			JWKS: jwks, AuthorizationEncryptedResponseAlg: "dir"}})
		require.Error(t, err)
		_, err = h.resolveResponseEncryption(&AuthorizationRequest{ClientMetadata: &ClientMetadata{
			JWKS: jwks, AuthorizationEncryptedResponseEnc: "A192GCM-x"}})
		require.Error(t, err)
	})
}

// --- response_jwe shape ---

func TestValidateResponseJWE(t *testing.T) {
	_, jwks := ecJWKS(t, "kid-1")
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}}
	want, err := h.resolveResponseEncryption(&AuthorizationRequest{ClientMetadata: &ClientMetadata{JWKS: jwks}})
	require.NoError(t, err)
	var params map[string]any
	b, _ := json.Marshal(SignRequestParams{ResponseEncryption: want})
	require.NoError(t, json.Unmarshal(b, &params))
	good := clientEncryptJARM(t, params, "aud", blindSentinel)
	require.NoError(t, validateResponseJWE(good, want))

	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	hdr := func(alg, enc, kid string) string {
		return b64(fmt.Sprintf(`{"alg":%q,"enc":%q,"kid":%q}`, alg, enc, kid))
	}
	seg := strings.Split(good, ".")
	for name, jwe := range map[string]string{
		"empty":            "",
		"four segments":    strings.Join(seg[:4], "."),
		"six segments":     good + ".AA",
		"not base64url":    "!!." + strings.Join(seg[1:], "."),
		"json serial":      `{"protected":"x"}`,
		"empty header":     strings.Join([]string{"", seg[1], seg[2], seg[3], seg[4]}, "."),
		"empty ciphertext": strings.Join([]string{seg[0], seg[1], seg[2], "", seg[4]}, "."),
		"empty tag":        strings.Join([]string{seg[0], seg[1], seg[2], seg[3], ""}, "."),
		"empty iv":         strings.Join([]string{seg[0], seg[1], "", seg[3], seg[4]}, "."),
		"header not json":  strings.Join([]string{b64("nope"), seg[1], seg[2], seg[3], seg[4]}, "."),
		"wrong alg":        strings.Join([]string{hdr("RSA-OAEP", "A128GCM", "kid-1"), seg[1], seg[2], seg[3], seg[4]}, "."),
		"wrong enc":        strings.Join([]string{hdr("ECDH-ES", "A256GCM", "kid-1"), seg[1], seg[2], seg[3], seg[4]}, "."),
		"wrong kid":        strings.Join([]string{hdr("ECDH-ES", "A128GCM", "other"), seg[1], seg[2], seg[3], seg[4]}, "."),
		"oversize":         strings.Repeat("A", maxResponseJWEBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			err := validateResponseJWE(jwe, want)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), blindSentinel)
		})
	}
	assert.Error(t, validateResponseJWE(good, nil), "no encryption requested: nothing is acceptable")

	// An encrypted key is required unless the key agreement is direct.
	kw := &ResponseEncryption{JWK: want.JWK, Alg: "ECDH-ES+A128KW", Enc: "A128GCM"}
	assert.Error(t, validateResponseJWE(strings.Join([]string{hdr("ECDH-ES+A128KW", "A128GCM", "kid-1"), "", seg[2], seg[3], seg[4]}, "."), kw))

	// A direct ECDH-ES JWE must not carry an encrypted key.
	assert.Error(t, validateResponseJWE(strings.Join([]string{seg[0], b64("k"), seg[2], seg[3], seg[4]}, "."), want), "ECDH-ES with a nonempty encrypted key")
}

// --- the sign request / response exchange ---

type blindFixture struct {
	h        *OID4VPHandler
	session  *Session
	received chan map[string]any
	authReq  *AuthorizationRequest
	verifier *ecdsa.PrivateKey
	logs     *observer.ObservedLogs
	cleanup  func()

	mu   sync.Mutex
	sent []string // every message the engine sent the client, as JSON
}

func (f *blindFixture) record(m map[string]any) {
	b, _ := json.Marshal(m)
	f.mu.Lock()
	f.sent = append(f.sent, string(b))
	f.mu.Unlock()
}

// allSent returns everything the engine sent the client so far.
func (f *blindFixture) allSent() string {
	for {
		select {
		case m := <-f.received:
			f.record(m)
		default:
			f.mu.Lock()
			defer f.mu.Unlock()
			return strings.Join(f.sent, "\n")
		}
	}
}

func newBlindFixture(t *testing.T) *blindFixture {
	t.Helper()
	h, session, received, cleanup := newSelectionTestHandler(t)
	core, logs := observer.New(zap.DebugLevel)
	h.Logger = zap.New(core)
	vk, jwks := ecJWKS(t, "verifier-enc-1")
	authReq := &AuthorizationRequest{
		ClientID:       "x509_san_dns:verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		ResponseMode:   ResponseModeDirectPostJWT,
		Nonce:          "n-1",
		State:          "state-1",
		DCQLQuery:      json.RawMessage(`{"credentials":[{"id":"q","format":"dc+sd-jwt"}]}`),
		ClientMetadata: &ClientMetadata{JWKS: jwks, AuthorizationEncryptedResponseAlg: "ECDH-ES", AuthorizationEncryptedResponseEnc: "A128GCM"},
	}
	authReq.Verified = newVerifiedRequestInputs(authReq, SignatureVerified)
	return &blindFixture{h: h, session: session, received: received, authReq: authReq, verifier: vk, logs: logs, cleanup: cleanup}
}

// answer plays the client: waits for the sign_request and queues reply(params).
func (f *blindFixture) answer(t *testing.T, reply func(params map[string]any) *SignResponseMessage) {
	t.Helper()
	go func() {
		deadline := time.After(5 * time.Second)
		for {
			select {
			case msg := <-f.received:
				f.record(msg)
				if msg["type"] != "sign_request" {
					continue
				}
				params, _ := msg["params"].(map[string]any)
				resp := reply(params)
				resp.Type = TypeSignResponse
				resp.FlowID = f.h.Flow.ID
				resp.MessageID, _ = msg["message_id"].(string)
				f.session.signCh <- resp
				return
			case <-deadline:
				return
			}
		}
	}()
}

func (f *blindFixture) sign(t *testing.T) (*vpSubmission, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return f.h.requestVPSignature(ctx, f.authReq, []ConsentSelection{{CredentialID: "c1", CredentialQueryID: "q"}}, "")
}

func TestRequestVPSignature_DirectPostJWT_ClientEncrypts(t *testing.T) {
	f := newBlindFixture(t)
	defer f.cleanup()

	var seen map[string]any
	f.answer(t, func(params map[string]any) *SignResponseMessage {
		seen = params
		vp := map[string]any{"q": []string{blindSentinel}}
		return &SignResponseMessage{ResponseJWE: clientEncryptJARM(t, params, "x509_san_dns:verifier.example.com", vp)}
	})
	sub, err := f.sign(t)
	require.NoError(t, err)
	require.NotEmpty(t, sub.responseJWE)
	assert.Empty(t, sub.vpToken, "the engine holds no vp_token")

	// The sign request carries the resolved recipient and the state.
	re, _ := seen["response_encryption"].(map[string]any)
	require.NotNil(t, re)
	assert.Equal(t, "ECDH-ES", re["alg"])
	assert.Equal(t, "A128GCM", re["enc"])
	assert.Equal(t, "verifier-enc-1", re["jwk"].(map[string]any)["kid"])
	assert.Equal(t, "state-1", seen["state"])
	assert.NotNil(t, seen["verified_request"])

	// POST target is the validated response_uri and the form carries only the JWE.
	posted := make(chan url.Values, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		posted <- r.PostForm
		_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example.com/done"}`))
	}))
	defer srv.Close()
	f.authReq.ResponseURI = srv.URL
	f.h.httpClient = srv.Client()
	redirect, err := f.h.submitResponse(context.Background(), f.authReq, sub)
	require.NoError(t, err)
	assert.Equal(t, "https://verifier.example.com/done", redirect)
	form := <-posted
	assert.Equal(t, sub.responseJWE, form.Get("response"))
	assert.Len(t, form, 1, "only response=<jwe>: %v", form)

	// The verifier can decrypt it and finds the DCQL vp_token the client built.
	obj, err := jose.ParseEncrypted(form.Get("response"), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A128GCM})
	require.NoError(t, err)
	plain, err := obj.Decrypt(f.verifier)
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(plain, &claims))
	assert.Equal(t, "x509_san_dns:verifier.example.com", claims["aud"])
	assert.Equal(t, "state-1", claims["state"])
	assert.Equal(t, map[string]any{"q": []any{blindSentinel}}, claims["vp_token"])

	// (a) The engine never held the vp_token: not in anything it sent to the
	// client, logged, or kept in flow state.
	sent := f.allSent()
	assert.Contains(t, sent, "sign_request", "the check covers the sign request")
	assert.NotContains(t, sent, blindSentinel)
	for _, e := range f.logs.All() {
		assert.NotContains(t, fmt.Sprintf("%v %v", e.Message, e.ContextMap()), blindSentinel)
	}
	state, _ := json.Marshal(f.h.Flow.Data)
	assert.NotContains(t, string(state), blindSentinel)
	assert.NotContains(t, sub.responseJWE, blindSentinel, "it is ciphertext")
}

func TestRequestVPSignature_DirectPostJWT_Refusals(t *testing.T) {
	good := func(params map[string]any) string {
		return clientEncryptJARM(t, params, "aud", blindSentinel)
	}
	for name, reply := range map[string]func(map[string]any) *SignResponseMessage{
		"no response_jwe": func(map[string]any) *SignResponseMessage { return &SignResponseMessage{} },
		"legacy plaintext vp_token": func(map[string]any) *SignResponseMessage {
			return &SignResponseMessage{VPToken: blindSentinel}
		},
		"vp_token next to a valid jwe": func(p map[string]any) *SignResponseMessage {
			return &SignResponseMessage{VPToken: blindSentinel, ResponseJWE: good(p)}
		},
		"not compact": func(map[string]any) *SignResponseMessage {
			return &SignResponseMessage{ResponseJWE: `{"protected":"` + blindSentinel + `"}`}
		},
		"wrong shape": func(map[string]any) *SignResponseMessage {
			return &SignResponseMessage{ResponseJWE: "a.b.c"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newBlindFixture(t)
			defer f.cleanup()
			f.answer(t, reply)
			sub, err := f.sign(t)
			require.Error(t, err)
			assert.Nil(t, sub)
			var encErr *responseEncryptionError
			require.ErrorAs(t, err, &encErr)
			assert.NotContains(t, err.Error(), blindSentinel, "no detail leaks")
			for _, e := range f.logs.All() {
				assert.NotContains(t, fmt.Sprintf("%v %v", e.Message, e.ContextMap()), blindSentinel)
			}

			// The verifier is told access_denied, with the generic description.
			posted := make(chan url.Values, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				posted <- r.PostForm
			}))
			defer srv.Close()
			f.authReq.ResponseURI = srv.URL
			f.h.httpClient = srv.Client()
			f.h.refuseVerifierOnEncryptionError(context.Background(), f.authReq, err)
			form := <-posted
			assert.Equal(t, "access_denied", form.Get("error"))
			assert.Equal(t, verifierRefusedDescription, form.Get("error_description"))
			assert.Empty(t, form.Get("response"))
		})
	}
}

func TestFailSign_RedirectURIReachesFlowError(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want any
	}{
		"redirect":    {`{"redirect_uri":"https://verifier.example/done"}`, "https://verifier.example/done"},
		"no redirect": {`{}`, nil},
	} {
		t.Run(name, func(t *testing.T) {
			f := newBlindFixture(t)
			defer f.cleanup()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				assert.Equal(t, "access_denied", r.PostForm.Get("error"))
				assert.Equal(t, verifierRefusedDescription, r.PostForm.Get("error_description"))
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			f.authReq.ResponseURI = srv.URL
			f.h.httpClient = srv.Client()

			f.h.failSign(context.Background(), f.authReq, &responseEncryptionError{errors.New("SECRET detail")})
			msg := awaitMessage(t, f.received, string(TypeFlowError))
			flowErr := msg["error"].(map[string]any)
			assert.Equal(t, string(ErrCodeSignError), flowErr["code"])
			details, _ := flowErr["details"].(map[string]any)
			assert.Equal(t, tc.want, details["redirect_uri"])
			if tc.want == nil {
				assert.Empty(t, details)
			}
			b, _ := json.Marshal(msg)
			assert.NotContains(t, string(b), "SECRET")
		})
	}
}

func TestResolveResponseEncryption_KeyAlgMismatch(t *testing.T) {
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}}
	ec := func(c elliptic.Curve) json.RawMessage {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		require.NoError(t, err)
		return makeJWKS(jose.JSONWebKey{Key: &k.PublicKey, KeyID: "k", Use: "enc"})
	}
	rsaKey := func(bits int) json.RawMessage {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		require.NoError(t, err)
		return makeJWKS(jose.JSONWebKey{Key: &k.PublicKey, KeyID: "k", Use: "enc"})
	}
	resolve := func(jwks json.RawMessage, alg string) (*ResponseEncryption, error) {
		return h.resolveResponseEncryption(&AuthorizationRequest{ClientMetadata: &ClientMetadata{
			JWKS: jwks, AuthorizationEncryptedResponseAlg: alg}})
	}
	p256, p384, p521, rsa2048 := ec(elliptic.P256()), ec(elliptic.P384()), ec(elliptic.P521()), rsaKey(2048)

	for _, alg := range []string{"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"} {
		for name, jwks := range map[string]json.RawMessage{"P-256": p256, "P-384": p384, "P-521": p521} {
			got, err := resolve(jwks, alg)
			require.NoError(t, err, "%s with %s", alg, name)
			assert.Equal(t, alg, got.Alg)
		}
		_, err := resolve(rsa2048, alg)
		assert.Error(t, err, "%s must refuse an RSA key", alg)
	}
	for _, alg := range []string{"RSA-OAEP", "RSA-OAEP-256"} {
		got, err := resolve(rsa2048, alg)
		require.NoError(t, err)
		assert.Equal(t, alg, got.Alg)
		_, err = resolve(p256, alg)
		assert.Error(t, err, "%s must refuse an EC key", alg)
		_, err = resolve(rsaKey(1024), alg)
		assert.Error(t, err, "%s must refuse a short RSA key", alg)
	}
}

func TestRequestVPSignature_DirectPostJWT_KeyAlgMismatchNeverReachesTheClient(t *testing.T) {
	f := newBlindFixture(t)
	defer f.cleanup()
	f.authReq.ClientMetadata.AuthorizationEncryptedResponseAlg = "RSA-OAEP" // the fixture key is EC
	_, err := f.sign(t)
	require.Error(t, err)
	var encErr *responseEncryptionError
	require.ErrorAs(t, err, &encErr)
	select {
	case m := <-f.received:
		t.Fatalf("no sign_request may be sent: %v", m)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestRequestVPSignature_DirectPostJWT_NoKeyNeverReachesTheClient(t *testing.T) {
	f := newBlindFixture(t)
	defer f.cleanup()
	f.authReq.ClientMetadata = &ClientMetadata{}
	_, err := f.sign(t)
	require.Error(t, err)
	var encErr *responseEncryptionError
	require.ErrorAs(t, err, &encErr)
	select {
	case m := <-f.received:
		t.Fatalf("no sign_request may be sent: %v", m)
	case <-time.After(150 * time.Millisecond):
	}
}

// Plain response modes are engine-visible by the verifier's choice: the vp_token
// still goes through the engine, and the DCQL object is still built there.
func TestRequestVPSignature_PlainModesUnchanged(t *testing.T) {
	f := newBlindFixture(t)
	defer f.cleanup()
	f.authReq.ResponseMode = ResponseModeDirectPost
	var seen map[string]any
	f.answer(t, func(params map[string]any) *SignResponseMessage {
		seen = params
		return &SignResponseMessage{VPToken: "tok"}
	})
	sub, err := f.sign(t)
	require.NoError(t, err)
	assert.JSONEq(t, `{"q":["tok"]}`, sub.vpToken)
	assert.Empty(t, sub.responseJWE)
	assert.NotContains(t, seen, "response_encryption")
	assert.NotContains(t, seen, "state")

	// A response_jwe in a mode that does not encrypt is refused.
	f2 := newBlindFixture(t)
	defer f2.cleanup()
	f2.authReq.ResponseMode = ResponseModeDirectPost
	f2.answer(t, func(map[string]any) *SignResponseMessage { return &SignResponseMessage{ResponseJWE: "a.b.c.d.e"} })
	_, err = f2.sign(t)
	require.Error(t, err)
}
