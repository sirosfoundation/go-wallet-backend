package statuslist

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

type cwtOpts struct {
	key       *ecdsa.PrivateKey // signing key (default: fresh P-256)
	alg       int64             // default ES256 for P-256
	sub       string
	iss       string
	noIat     bool
	exp       time.Time
	nbf       time.Time
	claims    map[int64]any // raw overrides applied last (type-violation tests)
	bits      int
	values    map[int]int
	typ       any // default "application/statuslist+cwt"; nil-able via noTyp
	noTyp     bool
	typUnprot bool // typ only in the unprotected header
	noX5Chain bool
	x5cInUnp  bool                // put x5chain in the unprotected header
	wrap      func(arr []any) any // overrides the default tag 18 envelope
	textKeys  bool                // draft CDDL: "bits"/"lst" text keys in status_list
	legacy    bool                // vc#703 layout: status_list=65534, ttl=65535
	badSig    bool
	rawLst    []byte
}

func selfSigned(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cwt signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func zlibBytes(t *testing.T, bits int, values map[int]int) []byte {
	t.Helper()
	raw := make([]byte, (64*bits+7)/8)
	for idx, v := range values {
		pos := idx * bits
		raw[pos/8] |= byte(v) << uint(pos%8)
	}
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(raw)
	_ = w.Close()
	return buf.Bytes()
}

func makeCWT(t *testing.T, o cwtOpts) []byte {
	t.Helper()
	if o.key == nil {
		o.key = newKey(t)
	}
	curve := o.key.Curve
	if o.alg == 0 {
		switch curve {
		case elliptic.P384():
			o.alg = coseAlgES384
		case elliptic.P521():
			o.alg = coseAlgES512
		default:
			o.alg = coseAlgES256
		}
	}
	if o.bits == 0 {
		o.bits = 2
	}
	lst := o.rawLst
	if lst == nil {
		lst = zlibBytes(t, o.bits, o.values)
	}
	slLabel, ttlLabel := int64(cwtClaimStatusList), int64(cwtClaimTTL)
	if o.legacy {
		slLabel, ttlLabel = cwtClaimLegacyStatusList, cwtClaimLegacyTTL
	}
	claims := map[int64]any{
		cwtClaimSub: o.sub,
		ttlLabel:    900,
		slLabel:     map[int64]any{statusListKeyBits: o.bits, statusListKeyLst: lst},
	}
	if o.textKeys {
		claims[slLabel] = map[string]any{"bits": o.bits, "lst": lst}
	}
	if o.iss != "" {
		claims[cwtClaimIss] = o.iss
	}
	if !o.noIat {
		claims[cwtClaimIat] = time.Now().Unix()
	}
	if !o.exp.IsZero() {
		claims[cwtClaimExp] = o.exp.Unix()
	}
	if !o.nbf.IsZero() {
		claims[cwtClaimNbf] = o.nbf.Unix()
	}
	for k, v := range o.claims {
		claims[k] = v
	}
	payload, err := cbor.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	prot := map[int64]any{coseHdrAlg: o.alg}
	unprot := map[int64]any{4: []byte("prototype-1")} // kid
	if !o.noTyp {
		if o.typ == nil {
			o.typ = "application/statuslist+cwt"
		}
		if o.typUnprot {
			unprot[coseHdrTyp] = o.typ
		} else {
			prot[coseHdrTyp] = o.typ
		}
	}
	if !o.noX5Chain {
		chain := []any{selfSigned(t, o.key)}
		if o.x5cInUnp {
			unprot[coseHdrX5Chain] = chain
		} else {
			prot[coseHdrX5Chain] = chain
		}
	}
	protBytes, _ := cbor.Marshal(prot)
	tbs, _ := cbor.Marshal([]any{"Signature1", protBytes, []byte{}, payload})
	var h crypto.Hash
	size := (curve.Params().BitSize + 7) / 8
	switch o.alg {
	case coseAlgES384:
		h = crypto.SHA384
	case coseAlgES512:
		h = crypto.SHA512
	default:
		h = crypto.SHA256
	}
	hh := h.New()
	hh.Write(tbs)
	r, s, err := ecdsa.Sign(rand.Reader, o.key, hh.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	if o.badSig {
		sig[0] ^= 0xff
	}
	arr := []any{protBytes, unprot, payload, sig}
	var out []byte
	if o.wrap != nil {
		out, err = cbor.Marshal(o.wrap(arr))
	} else {
		out, err = cbor.Marshal(cbor.Tag{Number: coseTagSign1, Content: arr})
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// serveCWT serves body with the given Content-Type and records Accept.
func serveCWT(t *testing.T, mk func(uri string) []byte, ctype string, tr SignerTrust) (*Checker, string, *string) {
	accept := new(string)
	var uri string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*accept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write(mk(uri))
	}))
	t.Cleanup(srv.Close)
	uri = srv.URL + "/lists/1"
	return NewChecker(srv.Client(), false, tr), uri, accept
}

func TestCWT_VerifyAndVerdicts(t *testing.T) {
	ctx := context.Background()
	future := time.Now().Add(time.Hour)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	for name, o := range map[string]cwtOpts{
		"tagged":                      {},
		"x5chain unprot":              {x5cInUnp: true},
		"ES384":                       {key: p384},
		"ES512":                       {key: p521},
		"typ short form":              {typ: "statuslist+cwt"},
		"exp":                         {exp: future},
		"legacy vc#703":               {legacy: true},
		"1 bit":                       {bits: 1},
		"text keys (draft CDDL)":      {textKeys: true},
		"text keys, vc legacy labels": {textKeys: true, legacy: true},
	} {
		t.Run(name, func(t *testing.T) {
			o.values = map[int]int{3: 1, 4: 1}
			o2 := o
			c, uri, accept := serveCWT(t, func(u string) []byte { o2.sub = u; return makeCWT(t, o2) }, mediaTypeCWT, trustAll)
			if err := c.Check(ctx, &Reference{Idx: 2, URI: uri}); err != nil {
				t.Fatalf("valid entry: %v", err)
			}
			if err := c.Check(ctx, &Reference{Idx: 3, URI: uri}); !errors.Is(err, ErrRevoked) {
				t.Fatalf("want ErrRevoked, got %v", err)
			}
			if *accept != mediaTypeJWT+", "+mediaTypeCWT+";q=0.8" {
				t.Fatalf("Accept = %q", *accept)
			}
		})
	}
}

func TestCWT_Rejections(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		o       cwtOpts
		mutate  func([]byte) []byte
		wantErr string
		want    error
	}{
		{"forged signature", cwtOpts{badSig: true}, nil, "signature", nil},
		{"wrong sub", cwtOpts{sub: "https://other/x"}, nil, "does not match", nil},
		{"missing iat", cwtOpts{noIat: true}, nil, "no iat", nil},
		{"expired", cwtOpts{exp: time.Now().Add(-time.Minute)}, nil, "expired", nil},
		{"future iat", cwtOpts{claims: map[int64]any{cwtClaimIat: time.Now().Add(time.Hour).Unix()}}, nil, "issued in the future", nil},
		{"bad bits", cwtOpts{bits: 3}, nil, "bits", nil},
		{"unknown alg", cwtOpts{alg: -8}, nil, "unsupported COSE alg", nil},
		{"alg/key mismatch", cwtOpts{alg: coseAlgES384}, nil, "does not match alg", nil},
		{"wrong typ", cwtOpts{typ: "application/cwt"}, nil, "typ", nil},
		{"missing typ", cwtOpts{noTyp: true}, nil, "typ", nil},
		{"typ only in unprotected header", cwtOpts{typUnprot: true}, nil, "typ", nil},
		{"no key material", cwtOpts{noX5Chain: true}, nil, "", ErrNoSignerKey},
		{"empty lst", cwtOpts{rawLst: []byte{}}, nil, "lst", nil},
		{"garbage lst", cwtOpts{rawLst: []byte("not zlib")}, nil, "lst", nil},
		{"not cose", cwtOpts{}, func([]byte) []byte { return []byte{0x01} }, "COSE_Sign1", nil},
		{"untagged", cwtOpts{wrap: func(a []any) any { return a }}, nil, "tag 18", nil},
		{"tag 61 alone", cwtOpts{wrap: func(a []any) any { return cbor.Tag{Number: 61, Content: a} }}, nil, "tag 61", nil},
		{"61 wrapping 18", cwtOpts{wrap: func(a []any) any {
			return cbor.Tag{Number: 61, Content: cbor.Tag{Number: 18, Content: a}}
		}}, nil, "tag 61", nil},
		{"18 wrapping 61", cwtOpts{wrap: func(a []any) any {
			return cbor.Tag{Number: 18, Content: cbor.Tag{Number: 61, Content: a}}
		}}, nil, "nested", nil},
		{"double tag 18", cwtOpts{wrap: func(a []any) any {
			return cbor.Tag{Number: 18, Content: cbor.Tag{Number: 18, Content: a}}
		}}, nil, "nested", nil},
		{"COSE_Mac0 tag 17", cwtOpts{wrap: func(a []any) any { return cbor.Tag{Number: 17, Content: a} }}, nil, "tag 17", nil},
		{"wrong tag", cwtOpts{}, func([]byte) []byte { return []byte{0xc1, 0x80} }, "tag", nil},
		{"truncated", cwtOpts{}, func(b []byte) []byte { return b[:len(b)/2] }, "CWT", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, uri, _ := serveCWT(t, func(u string) []byte {
				o := tc.o
				if o.sub == "" {
					o.sub = u
				}
				b := makeCWT(t, o)
				if tc.mutate != nil {
					b = tc.mutate(b)
				}
				return b
			}, mediaTypeCWT, trustAll)
			err := c.Check(ctx, &Reference{Idx: 1, URI: uri})
			if err == nil || errors.Is(err, ErrRevoked) {
				t.Fatalf("must be unverifiable, got %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if tc.wantErr != "" && !bytes.Contains([]byte(err.Error()), []byte(tc.wantErr)) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// A present claim of the wrong CBOR type is rejected, never read as absent.
func TestCWT_ClaimTypeViolations(t *testing.T) {
	ctx := context.Background()
	future := time.Now().Add(time.Hour).Unix()
	tests := []struct {
		name  string
		o     cwtOpts
		claim string
	}{
		{"sub as int", cwtOpts{claims: map[int64]any{cwtClaimSub: 7}}, "sub"},
		{"iss as int", cwtOpts{claims: map[int64]any{cwtClaimIss: 7}}, "iss"},
		{"iss as bytes", cwtOpts{claims: map[int64]any{cwtClaimIss: []byte("x")}}, "iss"},
		{"iss as bool", cwtOpts{claims: map[int64]any{cwtClaimIss: false}}, "iss"},
		{"iss empty", cwtOpts{claims: map[int64]any{cwtClaimIss: ""}}, "iss"},
		{"iss whitespace", cwtOpts{claims: map[int64]any{cwtClaimIss: "  \t"}}, "iss"},
		{"sub empty", cwtOpts{claims: map[int64]any{cwtClaimSub: ""}}, "sub"},
		{"sub whitespace", cwtOpts{claims: map[int64]any{cwtClaimSub: " "}}, "sub"},
		{"exp as text", cwtOpts{claims: map[int64]any{cwtClaimExp: "1"}}, "exp"},
		{"exp as float", cwtOpts{claims: map[int64]any{cwtClaimExp: 1.5}}, "exp"},
		{"exp as bytes", cwtOpts{claims: map[int64]any{cwtClaimExp: []byte{1}}}, "exp"},
		{"nbf as text", cwtOpts{claims: map[int64]any{cwtClaimNbf: "1"}}, "nbf"},
		{"iat as text", cwtOpts{claims: map[int64]any{cwtClaimIat: "1"}}, "iat"},
		{"ttl as text", cwtOpts{claims: map[int64]any{cwtClaimTTL: "900"}}, "ttl"},
		{"legacy ttl as text", cwtOpts{legacy: true, claims: map[int64]any{cwtClaimLegacyTTL: "900"}}, "ttl"},
		{"exp too large for int64", cwtOpts{claims: map[int64]any{cwtClaimExp: uint64(1) << 63}}, "exp"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			c, uri, _ := serveCWT(t, func(u string) []byte {
				o := tc.o
				o.sub = u
				if _, ok := o.claims[cwtClaimSub]; ok {
					o.sub = ""
				}
				if o.claims == nil {
					o.claims = map[int64]any{}
				}
				return makeCWT(t, o)
			}, mediaTypeCWT, func(context.Context, string, *trust.KeyMaterial) (bool, error) {
				called = true
				return true, nil
			})
			err := c.Check(ctx, &Reference{Idx: 1, URI: uri})
			if err == nil || errors.Is(err, ErrRevoked) || !errors.Is(err, errCWT) ||
				!strings.Contains(err.Error(), "claim "+tc.claim) {
				t.Fatalf("want CWT claim %s type error, got %v", tc.claim, err)
			}
			if called {
				t.Fatal("trust consulted for a malformed token")
			}
		})
	}
	// Sanity: the same claims with correct types are accepted.
	c, uri, _ := serveCWT(t, func(u string) []byte {
		return makeCWT(t, cwtOpts{sub: u, iss: "https://issuer.example", claims: map[int64]any{cwtClaimExp: future, cwtClaimNbf: 1}})
	}, mediaTypeCWT, trustAll)
	if err := c.Check(ctx, &Reference{Idx: 1, URI: uri}); err != nil {
		t.Fatalf("valid claims: %v", err)
	}
}

func TestCWT_NotBefore(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		nbf     time.Time
		wantErr bool
	}{
		{"future nbf rejected", time.Now().Add(time.Hour), true},
		{"past nbf accepted", time.Now().Add(-time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, uri, _ := serveCWT(t, func(u string) []byte { return makeCWT(t, cwtOpts{sub: u, nbf: tc.nbf}) }, mediaTypeCWT, trustAll)
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

func TestCWT_Oversized(t *testing.T) {
	c, uri, _ := serveCWT(t, func(string) []byte { return make([]byte, maxTokenBytes+2) }, mediaTypeCWT, trustAll)
	if err := c.Check(context.Background(), &Reference{Idx: 1, URI: uri}); err == nil {
		t.Fatal("oversized token accepted")
	}
}

func TestCWT_Trust(t *testing.T) {
	ctx := context.Background()
	mk := func(t *testing.T, iss string) func(string) []byte {
		return func(u string) []byte {
			return makeCWT(t, cwtOpts{sub: u, iss: iss, values: map[int]int{1: 1}})
		}
	}
	for name, tc := range map[string]struct {
		trust   SignerTrust
		revoked bool
		want    error
	}{
		"trusted":   {trustAll, true, nil},
		"untrusted": {func(context.Context, string, *trust.KeyMaterial) (bool, error) { return false, nil }, false, ErrSignerUntrusted},
		"error": {func(context.Context, string, *trust.KeyMaterial) (bool, error) {
			return false, errors.New("down")
		}, false, ErrTrustUnavailable},
		"no pdp": {nil, false, ErrTrustUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			c, uri, _ := serveCWT(t, mk(t, ""), mediaTypeCWT, tc.trust)
			err := c.Check(ctx, &Reference{Idx: 1, URI: uri})
			if errors.Is(err, ErrRevoked) != tc.revoked || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v", err)
			}
		})
	}

	// Subject is the iss claim (CWT claim 1) else the URI origin; the key
	// material handed over is the x5chain, base64 DER.
	for _, iss := range []string{"https://status.example", ""} {
		var subj string
		var km *trust.KeyMaterial
		c, uri, _ := serveCWT(t, mk(t, iss), mediaTypeCWT, func(_ context.Context, s string, k *trust.KeyMaterial) (bool, error) {
			subj, km = s, k
			return true, nil
		})
		if err := c.Check(ctx, &Reference{Idx: 1, URI: uri}); !errors.Is(err, ErrRevoked) {
			t.Fatal(err)
		}
		want := iss
		if want == "" {
			want = uri[:len(uri)-len("/lists/1")]
		}
		if subj != want || km == nil || km.Type != "x5c" || len(km.X5C) != 1 {
			t.Fatalf("iss %q: subject=%q km=%+v", iss, subj, km)
		}
	}
}

func TestContentTypeDispatch(t *testing.T) {
	ctx := context.Background()
	key := newKey(t)
	jwtBody := func(u string) string { return makeToken(t, tokenOpts{sub: u, key: key}) }

	// Unknown media type: unverifiable.
	c, uri, _ := serve(t, jwtBody, "text/html")
	if err := c.Check(ctx, &Reference{Idx: 1, URI: uri}); err == nil {
		t.Fatal("unknown media type accepted")
	}
	// Media type parameters are ignored.
	c, uri, _ = serve(t, jwtBody, "application/statuslist+jwt; charset=utf-8")
	if err := c.Check(ctx, &Reference{Idx: 1, URI: uri}); err != nil {
		t.Fatalf("jwt with parameters: %v", err)
	}
	// A CWT body labelled as JWT, and a JWT body labelled as CWT, both fail.
	c, uri, _ = serveCWT(t, func(u string) []byte { return makeCWT(t, cwtOpts{sub: u}) }, mediaTypeJWT, trustAll)
	if err := c.Check(ctx, &Reference{Idx: 1, URI: uri}); err == nil {
		t.Fatal("CWT body served as JWT accepted")
	}
	c, uri, _ = serveCWT(t, func(u string) []byte { return []byte(jwtBody(u)) }, mediaTypeCWT, trustAll)
	if err := c.Check(ctx, &Reference{Idx: 1, URI: uri}); err == nil {
		t.Fatal("JWT body served as CWT accepted")
	}
}

func TestContentTypeMalformedVsMissing(t *testing.T) {
	ctx := context.Background()
	key := newKey(t)
	run := func(t *testing.T, header []string) error {
		var uri string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A nil slice suppresses net/http's content sniffing, so the
			// response truly carries no Content-Type.
			w.Header()["Content-Type"] = header
			_, _ = w.Write([]byte(makeToken(t, tokenOpts{sub: uri, key: key})))
		}))
		t.Cleanup(srv.Close)
		uri = srv.URL + "/statuslists/1"
		return NewChecker(srv.Client(), false, trustAll).Check(ctx, &Reference{Idx: 1, URI: uri})
	}
	// Absent header: the intentional JWT path.
	if err := run(t, nil); err != nil {
		t.Fatalf("missing Content-Type: %v", err)
	}
	// Malformed non-empty values are unverifiable, never a verdict. The
	// second one parses to the JWT media type alongside an error.
	for _, ct := range []string{
		"/",
		"application/statuslist+jwt; charset",
		"application/statuslist+jwt; =x",
		"application/statuslist+jwt;;",
		"not a media type",
	} {
		t.Run(ct, func(t *testing.T) {
			err := run(t, []string{ct})
			if err == nil || errors.Is(err, ErrRevoked) || !strings.Contains(err.Error(), "malformed Content-Type") {
				t.Fatalf("want malformed Content-Type error, got %v", err)
			}
		})
	}
}

func TestCWTHelpers(t *testing.T) {
	if _, ok := toInt64(uint64(1) << 63); ok {
		t.Error("huge uint64 must not narrow")
	}
	if _, ok := toInt64("x"); ok {
		t.Error("string is not an int")
	}
	if _, ok := anyMap("x"); ok {
		t.Error("anyMap accepted a string")
	}
	for _, m := range []any{map[any]any{"a": 1}, map[int64]any{1: 1}, map[string]any{"a": 1}} {
		if got, ok := anyMap(m); !ok || len(got) != 1 {
			t.Errorf("anyMap(%T)", m)
		}
	}
	if member(map[any]any{"bits": 2}, "bits", 1) != 2 || member(map[any]any{uint64(1): 3}, "bits", 1) != 3 ||
		member(map[any]any{int64(1): 4}, "bits", 1) != 4 || member(map[any]any{"x": 1}, "bits", 1) != nil {
		t.Error("member lookup")
	}
	if _, err := x5chain(7); err == nil {
		t.Error("bad x5chain type accepted")
	}
	if _, err := x5chain([]any{7}); err == nil {
		t.Error("bad x5chain entry accepted")
	}
	if b, err := x5chain([]byte{1}); err != nil || len(b) != 1 {
		t.Error("single-cert x5chain")
	}
	if m, _, err := decodeHeaderMap(nil); err != nil || len(m) != 0 {
		t.Error("empty protected header")
	}
}

func TestCWT_MinEntries(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		min     int
		wantErr bool
	}{{0, false}, {64, false}, {65, true}} {
		c, uri, _ := serveCWT(t, func(u string) []byte { return makeCWT(t, cwtOpts{sub: u}) }, mediaTypeCWT, trustAll)
		c.WithMinEntries(tc.min)
		err := c.Check(ctx, &Reference{Idx: 1, URI: uri})
		if tc.wantErr != (err != nil) || errors.Is(err, ErrRevoked) {
			t.Fatalf("min %d: wantErr=%v got %v", tc.min, tc.wantErr, err)
		}
	}
}

// signedCWTWithPayload builds a CWT around an exact claims payload.
func signedCWTWithPayload(t *testing.T, payload []byte) []byte {
	t.Helper()
	key := newKey(t)
	prot, _ := cbor.Marshal(map[int64]any{
		coseHdrAlg: coseAlgES256, coseHdrTyp: "application/statuslist+cwt",
		coseHdrX5Chain: []any{selfSigned(t, key)},
	})
	tbs, _ := cbor.Marshal([]any{"Signature1", prot, []byte{}, payload})
	sum := sha256.Sum256(tbs)
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	out, err := cbor.Marshal(cbor.Tag{Number: coseTagSign1, Content: []any{prot, map[int64]any{}, payload, sig}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCWT_ExtensionAndDuplicateClaims(t *testing.T) {
	ctx := context.Background()
	lst := zlibBytes(t, 2, map[int]int{3: 1})
	payloadFor := func(uri string, extra ...[2]any) []byte {
		// Hand-built so the key order and repeats are exact.
		var b []byte
		items := [][2]any{
			{int64(cwtClaimSub), uri}, {int64(cwtClaimIat), time.Now().Unix()},
			{int64(cwtClaimTTL), 900},
			{int64(cwtClaimStatusList), map[int64]any{statusListKeyBits: 2, statusListKeyLst: lst}},
		}
		items = append(items, extra...)
		b = append(b, 0xa0+byte(len(items)))
		for _, it := range items {
			k, _ := cbor.Marshal(it[0])
			v, _ := cbor.Marshal(it[1])
			b = append(append(b, k...), v...)
		}
		return b
	}
	t.Run("text-labelled and unknown integer extension claims accepted", func(t *testing.T) {
		c, uri, _ := serveCWT(t, func(u string) []byte {
			return signedCWTWithPayload(t, payloadFor(u,
				[2]any{"x-extension", "v"}, [2]any{"nested", map[string]any{"a": 1}}, [2]any{int64(-70000), true}, [2]any{int64(1000), []byte{1}}))
		}, mediaTypeCWT, trustAll)
		if err := c.Check(ctx, &Reference{Idx: 2, URI: uri}); err != nil {
			t.Fatalf("valid entry: %v", err)
		}
		if err := c.Check(ctx, &Reference{Idx: 3, URI: uri}); !errors.Is(err, ErrRevoked) {
			t.Fatalf("want ErrRevoked, got %v", err)
		}
	})
	t.Run("duplicate keys rejected", func(t *testing.T) {
		for name, extra := range map[string][2]any{
			"integer": {int64(cwtClaimIat), time.Now().Unix()},
			"text":    {"dup", 1},
		} {
			t.Run(name, func(t *testing.T) {
				c, uri, _ := serveCWT(t, func(u string) []byte {
					p := payloadFor(u, [2]any{"dup", 0}, extra)
					return signedCWTWithPayload(t, p)
				}, mediaTypeCWT, trustAll)
				err := c.Check(ctx, &Reference{Idx: 2, URI: uri})
				if err == nil || errors.Is(err, ErrRevoked) {
					t.Fatalf("duplicate claim key must be unverifiable, got %v", err)
				}
			})
		}
	})
	t.Run("known claims stay strict beside extensions", func(t *testing.T) {
		c, uri, _ := serveCWT(t, func(u string) []byte {
			return signedCWTWithPayload(t, payloadFor(u, [2]any{"x", 1}, [2]any{int64(cwtClaimExp), "soon"}))
		}, mediaTypeCWT, trustAll)
		err := c.Check(ctx, &Reference{Idx: 2, URI: uri})
		if err == nil || !strings.Contains(err.Error(), "exp") {
			t.Fatalf("mistyped exp must be rejected, got %v", err)
		}
	})
}

// cborMap hand-builds a definite-length CBOR map so key order and repeats
// are exact.
func cborMap(items ...[2]any) []byte {
	b := []byte{0xa0 + byte(len(items))}
	for _, it := range items {
		k, _ := cbor.Marshal(it[0])
		v, _ := cbor.Marshal(it[1])
		b = append(append(b, k...), v...)
	}
	return b
}

// signedCWTWithHeaders signs a CWT whose protected header carries the
// mandatory parameters plus protExtra, and whose unprotected header is
// unprot (hand-built CBOR).
func signedCWTWithHeaders(t *testing.T, uri string, protExtra [][2]any, unprot []byte) []byte {
	t.Helper()
	key := newKey(t)
	payload := cborMap(
		[2]any{int64(cwtClaimSub), uri}, [2]any{int64(cwtClaimIat), time.Now().Unix()},
		[2]any{int64(cwtClaimTTL), 900},
		[2]any{int64(cwtClaimStatusList), map[int64]any{statusListKeyBits: 2, statusListKeyLst: zlibBytes(t, 2, map[int]int{3: 1})}})
	items := [][2]any{
		{int64(coseHdrAlg), int64(coseAlgES256)}, {int64(coseHdrTyp), "application/statuslist+cwt"},
		{int64(coseHdrX5Chain), []any{selfSigned(t, key)}},
	}
	protBytes := cborMap(append(items, protExtra...)...)
	tbs, _ := cbor.Marshal([]any{"Signature1", protBytes, []byte{}, payload})
	sum := sha256.Sum256(tbs)
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	pb, _ := cbor.Marshal(protBytes)
	payloadB, _ := cbor.Marshal(payload)
	sigB, _ := cbor.Marshal(sig)
	out := append([]byte{0xd2, 0x84}, pb...) // tag 18, array(4)
	out = append(out, unprot...)
	out = append(out, payloadB...)
	return append(out, sigB...)
}

func TestCWT_HeaderLabels(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name      string
		protExtra [][2]any
		unprot    []byte
		ok        bool
	}{
		{"text-labelled non-critical protected header", [][2]any{{"x-ext", "v"}}, cborMap(), true},
		{"text-labelled non-critical unprotected header", nil, cborMap([2]any{"x-ext", 1}, [2]any{int64(4), []byte("kid")}), true},
		{"crit naming understood labels", [][2]any{{int64(coseHdrCrit), []any{int64(coseHdrTyp)}}}, cborMap(), true},
		{"duplicate integer label in protected", [][2]any{{int64(coseHdrAlg), int64(coseAlgES256)}}, cborMap(), false},
		{"duplicate text label in protected", [][2]any{{"dup", 1}, {"dup", 2}}, cborMap(), false},
		{"duplicate text label in unprotected", nil, cborMap([2]any{"dup", 1}, [2]any{"dup", 2}), false},
		{"label in both buckets", nil, cborMap([2]any{int64(coseHdrTyp), "x"}), false},
		{"unknown critical integer label", [][2]any{{int64(-70000), true}, {int64(coseHdrCrit), []any{int64(-70000)}}}, cborMap(), false},
		{"critical text label", [][2]any{{"x-ext", 1}, {int64(coseHdrCrit), []any{"x-ext"}}}, cborMap(), false},
		{"critical label absent from protected header", [][2]any{{int64(coseHdrCrit), []any{int64(99)}}}, cborMap(), false},
		{"crit lists itself", [][2]any{{int64(coseHdrCrit), []any{int64(coseHdrCrit)}}}, cborMap(), false},
		{"crit lists itself among others", [][2]any{{int64(coseHdrCrit), []any{int64(coseHdrTyp), int64(coseHdrCrit)}}}, cborMap(), false},
		{"crit duplicate entries", [][2]any{{int64(coseHdrCrit), []any{int64(coseHdrTyp), int64(coseHdrTyp)}}}, cborMap(), false},
		{"crit two distinct understood labels", [][2]any{{int64(coseHdrCrit), []any{int64(coseHdrTyp), int64(coseHdrAlg)}}}, cborMap(), true},
		{"empty crit", [][2]any{{int64(coseHdrCrit), []any{}}}, cborMap(), false},
		{"crit not an array", [][2]any{{int64(coseHdrCrit), "typ"}}, cborMap(), false},
		{"same text label in both buckets", [][2]any{{"x-ext", "a"}}, cborMap([2]any{"x-ext", "b"}), false},
		{"text label only in unprotected, other text only in protected", [][2]any{{"x-a", 1}}, cborMap([2]any{"x-b", 1}), true},
		{"same integer label in both buckets", [][2]any{{int64(99), 1}}, cborMap([2]any{int64(99), 2}), false},
		{"crit in unprotected header", nil, cborMap([2]any{int64(coseHdrCrit), []any{int64(coseHdrTyp)}}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, uri, _ := serveCWT(t, func(u string) []byte {
				return signedCWTWithHeaders(t, u, tc.protExtra, tc.unprot)
			}, mediaTypeCWT, trustAll)
			err := c.Check(ctx, &Reference{Idx: 3, URI: uri})
			if tc.ok != errors.Is(err, ErrRevoked) {
				t.Fatalf("ok=%v, got %v", tc.ok, err)
			}
		})
	}
}

func TestCWT_NullStandardStatusListIsNotAbsent(t *testing.T) {
	ctx := context.Background()
	lst := zlibBytes(t, 2, map[int]int{3: 1})
	legacy := map[int64]any{statusListKeyBits: 2, statusListKeyLst: lst}
	build := func(std any, withStd bool) func(uri string) []byte {
		return func(u string) []byte {
			items := [][2]any{
				{int64(cwtClaimSub), u}, {int64(cwtClaimIat), time.Now().Unix()},
				{int64(cwtClaimLegacyStatusList), legacy}, {int64(cwtClaimLegacyTTL), 900},
			}
			if withStd {
				items = append(items, [2]any{int64(cwtClaimStatusList), std})
			}
			return signedCWTWithPayload(t, cborMap(items...))
		}
	}
	t.Run("null standard claim with valid legacy map rejected", func(t *testing.T) {
		c, uri, _ := serveCWT(t, build(nil, true), mediaTypeCWT, trustAll)
		err := c.Check(ctx, &Reference{Idx: 3, URI: uri})
		if err == nil || errors.Is(err, ErrRevoked) {
			t.Fatalf("present null status_list must be unverifiable, got %v", err)
		}
	})
	t.Run("absent standard claim still reads legacy layout", func(t *testing.T) {
		c, uri, _ := serveCWT(t, build(nil, false), mediaTypeCWT, trustAll)
		if err := c.Check(ctx, &Reference{Idx: 3, URI: uri}); !errors.Is(err, ErrRevoked) {
			t.Fatalf("want ErrRevoked, got %v", err)
		}
	})
}

// ttl must be a positive integer in the CWT form too (standard and legacy
// labels); an oversized one is capped, not overflowed.
func TestCWT_TTLValues(t *testing.T) {
	ctx := context.Background()
	for _, legacy := range []bool{false, true} {
		label := int64(cwtClaimTTL)
		if legacy {
			label = cwtClaimLegacyTTL
		}
		for _, tc := range []struct {
			name    string
			ttl     any
			wantErr bool
		}{
			{"valid", 900, false},
			{"huge (largest the CWT reader accepts, 2^62)", int64(1) << 62, false},
			{"beyond int64 is not an integer", uint64(1) << 63, true},
			{"zero", 0, true},
			{"negative", -1, true},
			{"min int64", int64(math.MinInt64), true},
		} {
			t.Run(fmt.Sprintf("legacy=%v/%s", legacy, tc.name), func(t *testing.T) {
				called := false
				c, uri, _ := serveCWT(t, func(u string) []byte {
					return makeCWT(t, cwtOpts{sub: u, legacy: legacy, claims: map[int64]any{label: tc.ttl}})
				}, mediaTypeCWT, func(context.Context, string, *trust.KeyMaterial) (bool, error) {
					called = true
					return true, nil
				})
				err := c.Check(ctx, &Reference{Idx: 1, URI: uri})
				if tc.wantErr {
					if err == nil || errors.Is(err, ErrRevoked) || !strings.Contains(err.Error(), "ttl") {
						t.Fatalf("got %v, want a ttl error", err)
					}
					if called {
						t.Fatal("trust consulted for a malformed token")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range c.cache {
					if rem := e.expires.Sub(time.Now()); rem <= 0 || rem > maxCacheTTL {
						t.Fatalf("cached lifetime %v out of (0, %v]", rem, maxCacheTTL)
					}
				}
				if len(c.cache) != 1 {
					t.Fatalf("cache entries = %d, want 1", len(c.cache))
				}
			})
		}
	}
}
