package statuslist

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// serviceToken reproduces, claim for claim, what siros-status-service's
// internal/statuslist.BuildToken emits (docs/design.md §4, §9): ES256, header
// {alg, typ:"statuslist+jwt", kid} and NO x5c/jwk, claims {sub, iat, ttl,
// status_list:{bits, lst}} and NO exp/iss, lst = zlib + base64url without
// padding over an LSB-first packed bitmap, bits=2 by default.
func serviceToken(t *testing.T, key *ecdsa.PrivateKey, listURL string, values map[int]int) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": listURL,
		"iat": time.Now().Unix(),
		"ttl": 900,
		"status_list": map[string]any{
			"bits": 2,
			"lst":  packList(t, 2, values, 64),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "statuslist+jwt"
	tok.Header["kid"] = "prototype-1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func jwkSigner(k *ecdsa.PrivateKey) *trust.KeyMaterial {
	return &trust.KeyMaterial{Type: "jwk", JWK: jwkOf(&k.PublicKey)}
}

func x5cSigner(t *testing.T, k *ecdsa.PrivateKey) *trust.KeyMaterial {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "issuer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return &trust.KeyMaterial{Type: "x5c", X5C: []string{base64.StdEncoding.EncodeToString(der)}}
}

func TestInterop_SirosStatusServiceShape(t *testing.T) {
	ctx := context.Background()
	key := newKey(t)
	var accept string
	var uri string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		w.Header().Set("ETag", `"7"`)
		w.Header().Set("Cache-Control", "public, max-age=900")
		_, _ = w.Write([]byte(serviceToken(t, key, uri, map[int]int{3: 1, 4: 2, 5: 3})))
	}))
	defer srv.Close()
	uri = srv.URL + "/lists/shard-a-abc"

	for _, signer := range []*trust.KeyMaterial{jwkSigner(key), x5cSigner(t, key)} {
		c := NewChecker(srv.Client(), false)
		if err := c.Check(ctx, &Reference{Idx: 2, URI: uri}, signer); err != nil {
			t.Fatalf("valid entry of a service token refused (%s): %v", signer.Type, err)
		}
		if accept != "application/statuslist+jwt" {
			t.Fatalf("Accept = %q", accept)
		}
		// INVALID (1), SUSPENDED (2) and application-specific (3) are all not valid.
		for _, idx := range []int64{3, 4, 5} {
			if err := c.Check(ctx, &Reference{Idx: idx, URI: uri}, signer); !errors.Is(err, ErrRevoked) {
				t.Fatalf("idx %d: want ErrRevoked, got %v", idx, err)
			}
		}
	}

	// The service embeds no key, so without the credential's key the token
	// cannot be verified: an indeterminate result, never a revocation.
	err := NewChecker(srv.Client(), false).Check(ctx, &Reference{Idx: 3, URI: uri}, nil)
	if err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("keyless token without signer must be indeterminate, got %v", err)
	}

	// Signed by the service's key while the credential was issued under another key.
	err = NewChecker(srv.Client(), false).Check(ctx, &Reference{Idx: 3, URI: uri}, jwkSigner(newKey(t)))
	if err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("token signed by another key must be indeterminate, got %v", err)
	}
}

func TestVerifyWithKey_Errors(t *testing.T) {
	key := newKey(t)
	tok := serviceToken(t, key, "https://x/1", nil)
	for name, km := range map[string]*trust.KeyMaterial{
		"no key":        {Type: "jwk"},
		"bad x5c b64":   {Type: "x5c", X5C: []string{"!!"}},
		"bad x5c cert":  {Type: "x5c", X5C: []string{base64.StdEncoding.EncodeToString([]byte("nope"))}},
		"bad jwk":       {Type: "jwk", JWK: map[string]any{"kty": "EC"}},
		"unmarshalable": {Type: "jwk", JWK: func() {}},
	} {
		if err := verifyWithKey(tok, km); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if err := verifyWithKey("not-a-jws", jwkSigner(key)); err == nil {
		t.Error("garbage token verified")
	}
	if err := verifyWithKey(tok, jwkSigner(key)); err != nil {
		t.Errorf("good key rejected: %v", err)
	}
}
