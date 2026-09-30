package statuslist

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

func trustAll(context.Context, string, *trust.KeyMaterial) (bool, error) { return true, nil }

func jwkOf(k *ecdsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(k.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(k.Y.FillBytes(make([]byte, 32))),
	}
}

func packList(t *testing.T, bits int, values map[int]int, size int) string {
	t.Helper()
	raw := make([]byte, (size*bits+7)/8)
	for idx, v := range values {
		pos := idx * bits
		raw[pos/8] |= byte(v) << uint(pos%8)
	}
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(raw)
	_ = w.Close()
	return base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

type tokenOpts struct {
	typ, sub string
	exp, nbf time.Time
	bits     int
	values   map[int]int
	key      *ecdsa.PrivateKey
}

func makeToken(t *testing.T, o tokenOpts) string {
	t.Helper()
	if o.bits == 0 {
		o.bits = 1
	}
	if o.typ == "" {
		o.typ = "statuslist+jwt"
	}
	claims := jwt.MapClaims{
		"sub": o.sub, "iat": time.Now().Unix(),
		"status_list": map[string]any{"bits": o.bits, "lst": packList(t, o.bits, o.values, 64)},
	}
	if !o.exp.IsZero() {
		claims["exp"] = o.exp.Unix()
	}
	if !o.nbf.IsZero() {
		claims["nbf"] = o.nbf.Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = o.typ
	tok.Header["jwk"] = jwkOf(&o.key.PublicKey)
	s, err := tok.SignedString(o.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// serve returns a checker against a TLS server that answers with body, and the
// list URI (which must equal the token's sub).
func serve(t *testing.T, mk func(uri string) string, ctype string) (*Checker, string, *int) {
	hits := new(int)
	var uri string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		if ctype == "" {
			ctype = mediaTypeJWT
		}
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write([]byte(mk(uri)))
	}))
	t.Cleanup(srv.Close)
	uri = srv.URL + "/statuslists/1"
	return NewChecker(srv.Client(), false, trustAll), uri, hits
}

func TestCheck(t *testing.T) {
	key := newKey(t)
	ctx := context.Background()
	future := time.Now().Add(time.Hour)

	tests := []struct {
		name    string
		opts    func(uri string) tokenOpts
		idx     int64
		ctype   string
		wantErr string
		revoked bool
	}{
		{name: "valid", opts: func(u string) tokenOpts {
			return tokenOpts{sub: u, exp: future, key: key, values: map[int]int{4: 1}}
		}, idx: 3},
		{name: "revoked", opts: func(u string) tokenOpts {
			return tokenOpts{sub: u, exp: future, key: key, values: map[int]int{4: 1}}
		}, idx: 4, revoked: true},
		{name: "suspended 2-bit", opts: func(u string) tokenOpts {
			return tokenOpts{sub: u, bits: 2, key: key, values: map[int]int{5: 2}}
		}, idx: 5, revoked: true},
		{name: "2-bit valid neighbour", opts: func(u string) tokenOpts {
			return tokenOpts{sub: u, bits: 2, key: key, values: map[int]int{5: 2}}
		}, idx: 6},
		{name: "index out of range", opts: func(u string) tokenOpts {
			return tokenOpts{sub: u, key: key}
		}, idx: 9999, wantErr: "out of range"},
		{name: "expired", opts: func(u string) tokenOpts {
			return tokenOpts{sub: u, exp: time.Now().Add(-time.Minute), key: key}
		}, idx: 1, wantErr: "expired"},
		{name: "wrong sub", opts: func(u string) tokenOpts {
			return tokenOpts{sub: "https://other/x", key: key}
		}, idx: 1, wantErr: "does not match"},
		{name: "wrong typ", opts: func(u string) tokenOpts {
			return tokenOpts{sub: u, typ: "JWT", key: key}
		}, idx: 1, wantErr: "typ"},
		{name: "bad bits", opts: func(u string) tokenOpts {
			return tokenOpts{sub: u, bits: 3, key: key}
		}, idx: 1, wantErr: "bits"},
		{name: "cwt refused", opts: func(u string) tokenOpts {
			return tokenOpts{sub: u, key: key}
		}, idx: 1, ctype: "application/statuslist+cwt", wantErr: "CWT"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, uri, _ := serve(t, func(u string) string { return makeToken(t, tc.opts(u)) }, tc.ctype)
			err := c.Check(ctx, &Reference{Idx: tc.idx, URI: uri})
			switch {
			case tc.revoked:
				if !errors.Is(err, ErrRevoked) {
					t.Fatalf("want ErrRevoked, got %v", err)
				}
			case tc.wantErr != "":
				if err == nil || !bytes.Contains([]byte(err.Error()), []byte(tc.wantErr)) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				if errors.Is(err, ErrRevoked) {
					t.Fatal("infrastructure failure must not read as revocation")
				}
			case err != nil:
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCheck_TamperedSignature(t *testing.T) {
	key := newKey(t)
	c, uri, _ := serve(t, func(u string) string {
		// Sign with a different key but keep the original key's JWK in the header.
		other := newKey(t)
		bad := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": u,
			"status_list": map[string]any{"bits": 1, "lst": packList(t, 1, nil, 64)}})
		bad.Header["typ"] = "statuslist+jwt"
		bad.Header["jwk"] = jwkOf(&key.PublicKey)
		s, _ := bad.SignedString(other)
		return s
	}, "")
	if err := c.Check(context.Background(), &Reference{Idx: 1, URI: uri}); err == nil {
		t.Fatal("forged status list accepted")
	}
}

func TestCheck_FetchFailuresFailClosed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := NewChecker(srv.Client(), false, trustAll)
	if err := c.Check(context.Background(), &Reference{Idx: 1, URI: srv.URL}); err == nil {
		t.Fatal("http 500 must be an error")
	}
	if err := c.Check(context.Background(), &Reference{Idx: 1, URI: "http://example.invalid/x"}); err == nil {
		t.Fatal("plain http must be refused")
	}
}

func TestCheck_Cache(t *testing.T) {
	key := newKey(t)
	c, uri, hits := serve(t, func(u string) string {
		return makeToken(t, tokenOpts{sub: u, key: key, exp: time.Now().Add(time.Hour)})
	}, "")
	for i := 0; i < 3; i++ {
		if err := c.Check(context.Background(), &Reference{Idx: 1, URI: uri}); err != nil {
			t.Fatal(err)
		}
	}
	if *hits != 1 {
		t.Fatalf("want 1 fetch, got %d", *hits)
	}
	c.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	_ = c.Check(context.Background(), &Reference{Idx: 1, URI: uri})
	if *hits != 2 {
		t.Fatalf("want refetch after ttl, got %d fetches", *hits)
	}
}

func TestReferenceFromCredentialClaims(t *testing.T) {
	ok := map[string]any{"status": map[string]any{"status_list": map[string]any{"idx": float64(7), "uri": "https://x/y"}}}
	ref, present, err := ReferenceFromCredentialClaims(ok)
	if err != nil || !present || ref.Idx != 7 || ref.URI != "https://x/y" {
		t.Fatalf("got %+v %v %v", ref, present, err)
	}
	if _, present, _ := ReferenceFromCredentialClaims(map[string]any{}); present {
		t.Fatal("no status claim must be reported absent")
	}
	for name, claims := range map[string]map[string]any{
		"not object":  {"status": "x"},
		"null":        {"status": nil},
		"no list":     {"status": map[string]any{"other": 1}},
		"no idx":      {"status": map[string]any{"status_list": map[string]any{"uri": "u"}}},
		"neg idx":     {"status": map[string]any{"status_list": map[string]any{"idx": float64(-1), "uri": "u"}}},
		"frac idx":    {"status": map[string]any{"status_list": map[string]any{"idx": 1.5, "uri": "u"}}},
		"missing uri": {"status": map[string]any{"status_list": map[string]any{"idx": float64(1)}}},
	} {
		if _, present, err := ReferenceFromCredentialClaims(claims); !present || err == nil {
			t.Errorf("%s: malformed status must be present+error, got present=%v err=%v", name, present, err)
		}
	}
}

func TestEntry_Bounds(t *testing.T) {
	list := []byte{0b00000010, 0xff}
	if v, err := entry(1, list, 1); err != nil || v != 1 {
		t.Errorf("entry(1,1) = %d, %v", v, err)
	}
	if v, err := entry(2, list, 0); err != nil || v != 2 {
		t.Errorf("entry(2,0) = %d, %v", v, err)
	}
	if _, err := entry(1, list, 16); err == nil {
		t.Error("index past the list must fail")
	}
	if _, err := entry(1, list, -1); err == nil {
		t.Error("negative index must fail")
	}
	// A credential-controlled idx must not wrap idx*bits around to a valid
	// position (2^62*4 wraps to 0) or a negative one (which would panic).
	for _, bits := range []int{1, 2, 4, 8} {
		for _, idx := range []int64{1 << 62, 1<<62 + 1, 1<<63 - 1, 1 << 61, -1 << 63} {
			if _, err := entry(bits, list, idx); err == nil {
				t.Errorf("entry(bits=%d, idx=%d) must be out of range", bits, idx)
			}
		}
	}
	// The last valid index of each width still reads.
	for _, bits := range []int{1, 2, 4, 8} {
		if _, err := entry(bits, list, int64(len(list))*8/int64(bits)-1); err != nil {
			t.Errorf("last index at bits=%d: %v", bits, err)
		}
	}
}

func TestInflate_Errors(t *testing.T) {
	if _, err := inflate([]byte("not zlib")); err == nil {
		t.Error("non-zlib data must fail")
	}
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write(make([]byte, maxInflateBytes+1))
	_ = zw.Close()
	if _, err := inflate(buf.Bytes()); err == nil {
		t.Error("an oversized inflation must fail (zip bomb)")
	}
}

func TestDecodeSegment_Errors(t *testing.T) {
	var v map[string]any
	if err := decodeSegment("!!", &v); err == nil {
		t.Error("bad base64 must fail")
	}
	if err := decodeSegment(base64.RawURLEncoding.EncodeToString([]byte("not json")), &v); err == nil {
		t.Error("bad json must fail")
	}
}

func TestCheck_RequiresIat(t *testing.T) {
	key := newKey(t)
	c, uri, _ := serve(t, func(u string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": u,
			"status_list": map[string]any{"bits": 1, "lst": packList(t, 1, nil, 64)}})
		tok.Header["typ"] = "statuslist+jwt"
		tok.Header["jwk"] = jwkOf(&key.PublicKey)
		s, _ := tok.SignedString(key)
		return s
	}, "")
	err := c.Check(context.Background(), &Reference{Idx: 1, URI: uri})
	if err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("token without iat must be rejected as unverifiable: %v", err)
	}
}

func TestCheck_NotBefore(t *testing.T) {
	ctx := context.Background()
	key := newKey(t)
	for _, tc := range []struct {
		name    string
		nbf     time.Time
		wantErr bool
	}{
		{"future nbf rejected", time.Now().Add(time.Hour), true},
		{"past nbf accepted", time.Now().Add(-time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, uri, _ := serve(t, func(u string) string { return makeToken(t, tokenOpts{sub: u, key: key, nbf: tc.nbf}) }, "")
			err := c.Check(ctx, &Reference{Idx: 1, URI: uri})
			if tc.wantErr != (err != nil) || errors.Is(err, ErrRevoked) {
				t.Fatalf("wantErr=%v got %v", tc.wantErr, err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "nbf") {
				t.Fatalf("got %v", err)
			}
		})
	}
}
