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

// x5cServiceToken is the expected future service shape: the service header
// plus the signer's x5c chain (and optionally a jwk), which is what lets a
// wallet verify and trust-evaluate the list. jwkMode is "", "match" or
// "mismatch" (a jwk that is not the leaf key).
func x5cServiceToken(t *testing.T, key *ecdsa.PrivateKey, listURL string, values map[int]int, jwkMode string) (string, *trust.KeyMaterial) {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "status service"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	x5c := []string{base64.StdEncoding.EncodeToString(der)}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": listURL, "iat": time.Now().Unix(), "ttl": 900,
		"status_list": map[string]any{"bits": 2, "lst": packList(t, 2, values, 64)},
	})
	tok.Header["typ"] = "statuslist+jwt"
	tok.Header["kid"] = "prototype-1"
	tok.Header["x5c"] = x5c
	switch jwkMode {
	case "match":
		tok.Header["jwk"] = jwkOf(&key.PublicKey)
	case "mismatch":
		tok.Header["jwk"] = jwkOf(&newKey(t).PublicKey)
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s, &trust.KeyMaterial{Type: "x5c", X5C: x5c}
}

func TestInterop_SirosStatusServiceShape(t *testing.T) {
	ctx := context.Background()
	key := newKey(t)
	var accept, uri string
	var withX5C bool
	var jwkMode string
	var wantKM *trust.KeyMaterial
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		w.Header().Set("ETag", `"7"`)
		w.Header().Set("Cache-Control", "public, max-age=900")
		vals := map[int]int{3: 1, 4: 2, 5: 3}
		if withX5C {
			tok, km := x5cServiceToken(t, key, uri, vals, jwkMode)
			wantKM = km
			_, _ = w.Write([]byte(tok))
			return
		}
		_, _ = w.Write([]byte(serviceToken(t, key, uri, vals)))
	}))
	defer srv.Close()
	uri = srv.URL + "/lists/shard-a-abc"

	// Kid only (no embedded key; the service is being updated to send x5c/jwk):
	// unverifiable, never a verdict, even for a revoked index.
	c := NewChecker(srv.Client(), false, trustAll)
	err := c.Check(ctx, &Reference{Idx: 3, URI: uri})
	if !errors.Is(err, ErrNoSignerKey) || errors.Is(err, ErrRevoked) {
		t.Fatalf("kid-only service token must be unverifiable, got %v", err)
	}
	if accept != "application/statuslist+jwt" {
		t.Fatalf("Accept = %q", accept)
	}

	// With an x5c chain (and kid) in the header and a positive trust decision the list is authoritative. INVALID (1),
	// SUSPENDED (2) and application-specific (3) are all not valid.
	withX5C = true
	var gotSubject string
	var gotKM *trust.KeyMaterial
	c = NewChecker(srv.Client(), false, func(_ context.Context, subject string, km *trust.KeyMaterial) (bool, error) {
		gotSubject, gotKM = subject, km
		return true, nil
	})
	if err := c.Check(ctx, &Reference{Idx: 2, URI: uri}); err != nil {
		t.Fatalf("valid entry refused: %v", err)
	}
	for _, idx := range []int64{3, 4, 5} {
		if err := c.Check(ctx, &Reference{Idx: idx, URI: uri}); !errors.Is(err, ErrRevoked) {
			t.Fatalf("idx %d: want ErrRevoked, got %v", idx, err)
		}
	}
	// No iss claim: the subject is the list URI's origin; the resource key is
	// the header's x5c chain.
	if gotSubject != srv.URL || gotKM == nil || gotKM.Type != "x5c" || gotKM.X5C[0] != wantKM.X5C[0] {
		t.Fatalf("trust call got subject=%q km=%+v", gotSubject, gotKM)
	}
}

func TestCheck_HeaderKeyPrecedence(t *testing.T) {
	ctx := context.Background()
	key := newKey(t)
	for _, tc := range []struct {
		mode     string
		wantType string // key type handed to trust; "" = unverifiable
	}{
		{"", "x5c"},
		{"match", "x5c"}, // both present and consistent: x5c is evaluated
		{"mismatch", ""}, // jwk is not the leaf key: unverifiable
	} {
		var uri string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, _ := x5cServiceToken(t, key, uri, map[int]int{1: 1}, tc.mode)
			_, _ = w.Write([]byte(tok))
		}))
		uri = srv.URL + "/lists/1"
		var gotType string
		c := NewChecker(srv.Client(), false, func(_ context.Context, _ string, km *trust.KeyMaterial) (bool, error) {
			gotType = km.Type
			return true, nil
		})
		err := c.Check(ctx, &Reference{Idx: 1, URI: uri})
		srv.Close()
		if tc.wantType == "" {
			if !errors.Is(err, errKeyMismatch) || errors.Is(err, ErrRevoked) || gotType != "" {
				t.Fatalf("mode %q: want unverifiable key mismatch without a trust call, got %v (trust type %q)", tc.mode, err, gotType)
			}
			continue
		}
		if !errors.Is(err, ErrRevoked) || gotType != tc.wantType {
			t.Fatalf("mode %q: want verdict via %s, got %v (type %q)", tc.mode, tc.wantType, err, gotType)
		}
	}
}

func TestCheckJWKMatchesLeaf_Errors(t *testing.T) {
	key := newKey(t)
	_, km := x5cServiceToken(t, key, "https://x/1", nil, "")
	jwk := jwkOf(&key.PublicKey)
	if err := checkJWKMatchesLeaf(nil, km.X5C[0]); err != nil {
		t.Errorf("absent jwk: %v", err)
	}
	if err := checkJWKMatchesLeaf(jwk, km.X5C[0]); err != nil {
		t.Errorf("matching jwk: %v", err)
	}
	if checkJWKMatchesLeaf(jwk, "!!") == nil || checkJWKMatchesLeaf(jwk, base64.StdEncoding.EncodeToString([]byte("x"))) == nil {
		t.Error("bad leaf must fail")
	}
	if checkJWKMatchesLeaf(map[string]any{"kty": "EC"}, km.X5C[0]) == nil {
		t.Error("bad jwk must fail")
	}
	if checkJWKMatchesLeaf(map[string]any{"f": func() {}}, km.X5C[0]) == nil {
		t.Error("unmarshalable jwk must fail")
	}
}

func TestCheck_SignerTrustDecisions(t *testing.T) {
	ctx := context.Background()
	key := newKey(t)
	mk := func(u string) string {
		return makeToken(t, tokenOpts{sub: u, key: key, values: map[int]int{1: 1}})
	}
	type ctxKey struct{}
	tests := []struct {
		name       string
		trust      SignerTrust
		wantRevoke bool
		wantErr    error
	}{
		{"trusted honours the verdict", func(context.Context, string, *trust.KeyMaterial) (bool, error) { return true, nil }, true, nil},
		{"untrusted is unverifiable", func(context.Context, string, *trust.KeyMaterial) (bool, error) { return false, nil }, false, ErrSignerUntrusted},
		{"trust error is unverifiable", func(context.Context, string, *trust.KeyMaterial) (bool, error) {
			return false, errors.New("pdp down")
		}, false, ErrTrustUnavailable},
		{"no trust service is unverifiable", nil, false, ErrTrustUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, uri, _ := serve(t, mk, "")
			c.trust = tc.trust
			err := c.Check(ctx, &Reference{Idx: 1, URI: uri})
			if tc.wantRevoke != errors.Is(err, ErrRevoked) {
				t.Fatalf("ErrRevoked=%v want %v (%v)", errors.Is(err, ErrRevoked), tc.wantRevoke, err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
			// An untrusted list must not be cached as if it were good.
			if tc.wantErr != nil {
				if err2 := c.Check(ctx, &Reference{Idx: 1, URI: uri}); errors.Is(err2, ErrRevoked) || err2 == nil {
					t.Fatalf("second check must still be unverifiable, got %v", err2)
				}
			}
		})
	}

	// The context reaches the trust call (tenant propagation) and an iss
	// claim, when present, is the subject.
	c, uri, _ := serve(t, func(u string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": u, "iss": "https://status.example", "iat": time.Now().Unix(),
			"status_list": map[string]any{"bits": 1, "lst": packList(t, 1, nil, 64)}})
		tok.Header["typ"] = "statuslist+jwt"
		tok.Header["jwk"] = jwkOf(&key.PublicKey)
		s, _ := tok.SignedString(key)
		return s
	}, "")
	var subj string
	var tenant any
	c.trust = func(ctx context.Context, subject string, _ *trust.KeyMaterial) (bool, error) {
		subj, tenant = subject, ctx.Value(ctxKey{})
		return true, nil
	}
	if err := c.Check(context.WithValue(ctx, ctxKey{}, "tenant-1"), &Reference{Idx: 1, URI: uri}); err != nil {
		t.Fatal(err)
	}
	if subj != "https://status.example" || tenant != "tenant-1" {
		t.Fatalf("subject=%q ctx value=%v", subj, tenant)
	}
}

func TestEvaluateSigner_NoIdentity(t *testing.T) {
	c := NewChecker(nil, false, trustAll)
	if err := c.evaluateSigner(context.Background(), "", "not a url", &trust.KeyMaterial{}); !errors.Is(err, ErrTrustUnavailable) {
		t.Fatalf("got %v", err)
	}
}
