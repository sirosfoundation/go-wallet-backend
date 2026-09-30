package statuslist

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
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
	claims    map[int64]any // raw overrides applied last (type-violation tests)
	bits      int
	values    map[int]int
	typ       any // default "application/statuslist+cwt"; nil-able via noTyp
	noTyp     bool
	typUnprot bool // typ only in the unprotected header
	noX5Chain bool
	x5cInUnp  bool // put x5chain in the unprotected header
	untagged  bool
	cwtTag    bool
	textKeys  bool // draft CDDL: "bits"/"lst" text keys in status_list
	legacy    bool // vc#703 layout: status_list=65534, ttl=65535
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
	switch {
	case o.untagged:
		out, err = cbor.Marshal(arr)
	case o.cwtTag:
		out, err = cbor.Marshal(cbor.Tag{Number: cwtTag, Content: cbor.Tag{Number: coseTagSign1, Content: arr}})
	default:
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
		"untagged":                    {untagged: true},
		"cwt tag":                     {cwtTag: true},
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
		{"exp as text", cwtOpts{claims: map[int64]any{cwtClaimExp: "1"}}, "exp"},
		{"exp as float", cwtOpts{claims: map[int64]any{cwtClaimExp: 1.5}}, "exp"},
		{"exp as bytes", cwtOpts{claims: map[int64]any{cwtClaimExp: []byte{1}}}, "exp"},
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
		return makeCWT(t, cwtOpts{sub: u, iss: "https://issuer.example", claims: map[int64]any{cwtClaimExp: future}})
	}, mediaTypeCWT, trustAll)
	if err := c.Check(ctx, &Reference{Idx: 1, URI: uri}); err != nil {
		t.Fatalf("valid claims: %v", err)
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
	if m, err := decodeHeaderMap(nil); err != nil || len(m) != 0 {
		t.Error("empty protected header")
	}
}
