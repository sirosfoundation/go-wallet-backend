package engine

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/statuslist"
)

func statusJWK(k *ecdsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(k.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(k.Y.FillBytes(make([]byte, 32))),
	}
}

func signJWT(t *testing.T, key *ecdsa.PrivateKey, header map[string]any, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	for k, v := range header {
		tok.Header[k] = v
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// statusFixture serves a status list with entry 1 revoked and returns a
// handler wired to it plus a function minting credentials pointing at it.
func statusFixture(t *testing.T, serverBroken bool) (*OID4VPHandler, func(idx int, withStatus bool) string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var uri string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serverBroken {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		_, _ = zw.Write([]byte{0b10, 0, 0, 0, 0, 0, 0, 0}) // idx 1 = 1
		_ = zw.Close()
		_, _ = w.Write([]byte(signJWT(t, key, map[string]any{"typ": "statuslist+jwt", "jwk": statusJWK(&key.PublicKey)}, jwt.MapClaims{
			"sub": uri, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"status_list": map[string]any{"bits": 1, "lst": base64.RawURLEncoding.EncodeToString(buf.Bytes())},
		})))
	}))
	t.Cleanup(srv.Close)
	uri = srv.URL + "/statuslists/1"

	h := &OID4VPHandler{
		BaseHandler:   BaseHandler{Logger: zap.NewNop()},
		statusChecker: statuslist.NewChecker(srv.Client(), false),
	}
	mint := func(idx int, withStatus bool) string {
		claims := jwt.MapClaims{"iss": "https://issuer", "vct": "urn:test"}
		if withStatus {
			claims["status"] = map[string]any{"status_list": map[string]any{"idx": idx, "uri": uri}}
		}
		// Same key signs the credential: exercises the signer binding too.
		return signJWT(t, key, map[string]any{"typ": "dc+sd-jwt", "jwk": statusJWK(&key.PublicKey)}, claims) + "~WyJzIiwiayIsInYiXQ~"
	}
	return h, mint
}

func TestCheckPresentationStatus(t *testing.T) {
	ctx := context.Background()
	h, mint := statusFixture(t, false)

	if err := h.checkPresentationStatus(ctx, mint(0, true)); err != nil {
		t.Fatalf("valid credential refused: %v", err)
	}
	if err := h.checkPresentationStatus(ctx, mint(1, true)); err == nil {
		t.Fatal("revoked credential accepted")
	}
	if err := h.checkPresentationStatus(ctx, mint(1, false)); err != nil {
		t.Fatalf("credential without status claim must pass: %v", err)
	}

	// DCQL shapes: the revoked one anywhere in the object refuses it all.
	obj, _ := json.Marshal(map[string][]string{"a": {mint(0, true)}, "b": {mint(1, true)}})
	if err := h.checkPresentationStatus(ctx, string(obj)); err == nil {
		t.Fatal("revoked credential inside DCQL vp_token accepted")
	}
	ok, _ := json.Marshal(map[string]string{"a": mint(0, true)})
	if err := h.checkPresentationStatus(ctx, string(ok)); err != nil {
		t.Fatalf("valid DCQL vp_token refused: %v", err)
	}
	if err := h.checkPresentationStatus(ctx, mint(0, true)+"\n"+mint(1, true)); err == nil {
		t.Fatal("revoked credential in newline-separated vp_token accepted")
	}

	// mdoc-shaped (not JWT) is not examined.
	if err := h.checkPresentationStatus(ctx, "o2d2ZXJzaW9uYzEuMA"); err != nil {
		t.Fatalf("non-JWT token must be skipped: %v", err)
	}
}

func TestCheckPresentationStatus_FailClosed(t *testing.T) {
	h, mint := statusFixture(t, true)
	if err := h.checkPresentationStatus(context.Background(), mint(0, true)); err == nil {
		t.Fatal("unreachable status list must refuse the presentation")
	}
	// Malformed status claim also refuses.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bad := signJWT(t, key, map[string]any{}, jwt.MapClaims{"status": map[string]any{"status_list": "x"}}) + "~"
	if err := h.checkPresentationStatus(context.Background(), bad); err == nil {
		t.Fatal("malformed status claim must refuse the presentation")
	}
}

func TestCheckPresentationStatus_Disabled(t *testing.T) {
	h, mint := statusFixture(t, true)
	h.statusChecker = nil
	if err := h.checkPresentationStatus(context.Background(), mint(1, true)); err != nil {
		t.Fatalf("disabled check must not refuse: %v", err)
	}
}

func TestPresentedTokens_Shapes(t *testing.T) {
	assert.Nil(t, presentedTokens("  "))
	assert.ElementsMatch(t, []string{"a", "b", "c"}, presentedTokens(`{"q1":"a","q2":["b","c"]}`))
	assert.ElementsMatch(t, []string{"a", "b"}, presentedTokens(`["a","b"]`))
	assert.Equal(t, []string{"a", "b"}, presentedTokens("a\nb"))
	// Malformed JSON-looking input falls back to being treated as raw tokens.
	assert.Equal(t, []string{`{"q":`}, presentedTokens(`{"q":`))
	assert.Equal(t, []string{`[1,2]`}, presentedTokens(`[1,2]`))
}

func TestDecodeJWTSegment_Errors(t *testing.T) {
	var v map[string]any
	assert.Error(t, decodeJWTSegment("!!", &v))
	assert.Error(t, decodeJWTSegment(base64.RawURLEncoding.EncodeToString([]byte("nope")), &v))
	assert.NoError(t, decodeJWTSegment(base64.RawURLEncoding.EncodeToString([]byte(`{"a":1}`)), &v))
}
