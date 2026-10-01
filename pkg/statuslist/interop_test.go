package statuslist

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
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
		"iat": testEpoch.Unix(),
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
		NotBefore: testEpoch.Add(-time.Hour), NotAfter: testEpoch.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	x5c := []string{base64.StdEncoding.EncodeToString(der)}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": listURL, "iat": testEpoch.Unix(), "ttl": 900,
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
	case "empty":
		tok.Header["jwk"] = map[string]any{}
	case "null":
		tok.Header["jwk"] = nil
	case "string":
		tok.Header["jwk"] = "not-a-key"
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
	c := newTestChecker(srv.Client(), false, trustAll)
	err := c.Check(ctx, &Reference{Idx: 3, URI: uri})
	if !errors.Is(err, ErrNoSignerKey) || errors.Is(err, ErrRevoked) {
		t.Fatalf("kid-only service token must be unverifiable, got %v", err)
	}
	if accept != "application/statuslist+jwt, application/statuslist+cwt;q=0.8" {
		t.Fatalf("Accept = %q", accept)
	}

	// With an x5c chain (and kid) in the header and a positive trust decision the list is authoritative. INVALID (1),
	// SUSPENDED (2) and application-specific (3) are all not valid.
	withX5C = true
	var gotSubject string
	var gotKM *trust.KeyMaterial
	c = newTestChecker(srv.Client(), false, func(_ context.Context, subject string, km *trust.KeyMaterial) (bool, error) {
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
			w.Header().Set("Content-Type", "application/statuslist+jwt")
			tok, _ := x5cServiceToken(t, key, uri, map[int]int{1: 1}, tc.mode)
			_, _ = w.Write([]byte(tok))
		}))
		uri = srv.URL + "/lists/1"
		var gotType string
		c := newTestChecker(srv.Client(), false, func(_ context.Context, _ string, km *trust.KeyMaterial) (bool, error) {
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

// A jwk header member that is present but empty, null or not a key is malformed
// key material: the list is unverifiable and trust is never consulted.
func TestCheck_PresentButMalformedJWKIsUnverifiable(t *testing.T) {
	ctx := context.Background()
	key := newKey(t)
	for _, mode := range []string{"empty", "null", "string"} {
		var uri string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/statuslist+jwt")
			tok, _ := x5cServiceToken(t, key, uri, map[int]int{1: 1}, mode)
			_, _ = w.Write([]byte(tok))
		}))
		uri = srv.URL + "/lists/1"
		called := false
		c := newTestChecker(srv.Client(), false, func(context.Context, string, *trust.KeyMaterial) (bool, error) {
			called = true
			return true, nil
		})
		err := c.Check(ctx, &Reference{Idx: 1, URI: uri})
		srv.Close()
		if err == nil || errors.Is(err, ErrRevoked) || called {
			t.Errorf("jwk %s: want unverifiable without a trust call, got %v (trust called %v)", mode, err, called)
		}
	}
}

func TestCheckJWKMatchesLeaf_Errors(t *testing.T) {
	key := newKey(t)
	_, km := x5cServiceToken(t, key, "https://x/1", nil, "")
	jwk, err := json.Marshal(jwkOf(&key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	other, err := json.Marshal(jwkOf(&newKey(t).PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf := km.X5C[0]
	if err := checkJWKMatchesLeaf(nil, leaf); err != nil {
		t.Errorf("absent jwk: %v", err)
	}
	if err := checkJWKMatchesLeaf(jwk, leaf); err != nil {
		t.Errorf("matching jwk: %v", err)
	}
	if !errors.Is(checkJWKMatchesLeaf(other, leaf), errKeyMismatch) {
		t.Error("other key must mismatch")
	}
	for name, raw := range map[string]string{
		"empty object": `{}`, "null": `null`, "string": `"x"`, "array": `[]`,
		"incomplete key": `{"kty":"EC"}`, "malformed": `{"kty":`,
	} {
		if checkJWKMatchesLeaf(json.RawMessage(raw), leaf) == nil {
			t.Errorf("%s jwk must fail", name)
		}
	}
	if checkJWKMatchesLeaf(jwk, "!!") == nil || checkJWKMatchesLeaf(jwk, base64.StdEncoding.EncodeToString([]byte("x"))) == nil {
		t.Error("bad leaf must fail")
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
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": u, "iss": "https://status.example", "iat": testEpoch.Unix(),
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
	c := newTestChecker(nil, false, trustAll)
	if err := c.evaluateSigner(context.Background(), "", "not a url", &trust.KeyMaterial{}); !errors.Is(err, ErrTrustUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestCache_TenantScoped(t *testing.T) {
	key := newKey(t)
	trustCalls := 0
	c, uri, hits := serve(t, func(u string) string { return makeToken(t, tokenOpts{sub: u, key: key}) }, "")
	c.trust = func(context.Context, string, *trust.KeyMaterial) (bool, error) { trustCalls++; return true, nil }
	ref := &Reference{Idx: 1, URI: uri}
	a := trust.ContextWithTenant(context.Background(), "tenant-a")
	b := trust.ContextWithTenant(context.Background(), "tenant-b")
	for _, ctx := range []context.Context{a, a, b, b} {
		if err := c.Check(ctx, ref); err != nil {
			t.Fatal(err)
		}
	}
	if *hits != 2 || trustCalls != 2 {
		t.Fatalf("want one fetch and one trust evaluation per tenant, got %d fetches %d trust calls", *hits, trustCalls)
	}
}

func TestCache_ByteBound(t *testing.T) {
	key := newKey(t)
	c, uri, hits := serve(t, func(u string) string { return makeToken(t, tokenOpts{sub: u, key: key}) }, "")
	ref := &Reference{Idx: 1, URI: uri}
	ctx := context.Background()

	// A list larger than the whole budget is never cached.
	c.cacheLimit = 1
	_ = c.Check(ctx, ref)
	_ = c.Check(ctx, ref)
	if *hits != 2 || c.cacheBytes != 0 || len(c.cache) != 0 {
		t.Fatalf("oversized list cached: hits=%d bytes=%d", *hits, c.cacheBytes)
	}

	// Budget for exactly one list: a second URI evicts (resets) the first and
	// the accounted bytes never exceed the limit.
	c.cacheLimit = 12 // one 8-byte list fits, two do not
	for _, tenant := range []string{"a", "b", "c"} {
		_ = c.Check(trust.ContextWithTenant(ctx, tenant), ref)
		if c.cacheBytes > c.cacheLimit {
			t.Fatalf("cache holds %d bytes, limit %d", c.cacheBytes, c.cacheLimit)
		}
	}
	if len(c.cache) != 1 {
		t.Fatalf("want exactly one cached list within the byte budget, got %d", len(c.cache))
	}
}

func TestCache_TTLMeasuredFromIat(t *testing.T) {
	key := newKey(t)
	mk := func(iatAgo time.Duration, ttl int64) func(string) string {
		return func(u string) string {
			tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": u, "iat": testEpoch.Add(-iatAgo).Unix(), "ttl": ttl,
				"status_list": map[string]any{"bits": 1, "lst": packList(t, 1, nil, 64)}})
			tok.Header["typ"] = "statuslist+jwt"
			tok.Header["jwk"] = jwkOf(&key.PublicKey)
			s, _ := tok.SignedString(key)
			return s
		}
	}
	// iat 10 min ago with ttl 5 min: already stale, used once but not cached.
	c, uri, hits := serve(t, mk(10*time.Minute, 300), "")
	for i := 0; i < 2; i++ {
		if err := c.Check(context.Background(), &Reference{Idx: 1, URI: uri}); err != nil {
			t.Fatal(err)
		}
	}
	if *hits != 2 {
		t.Fatalf("stale-by-iat token was cached: %d fetches", *hits)
	}
	// iat 100 s ago with ttl 200 s: cached, but only for the remaining ~100 s.
	c, uri, hits = serve(t, mk(100*time.Second, 200), "")
	_ = c.Check(context.Background(), &Reference{Idx: 1, URI: uri})
	c.now = func() time.Time { return testEpoch.Add(150 * time.Second) }
	_ = c.Check(context.Background(), &Reference{Idx: 1, URI: uri})
	if *hits != 2 {
		t.Fatalf("cache outlived iat+ttl: %d fetches", *hits)
	}
	c.now = func() time.Time { return testEpoch.Add(30 * time.Second) }
	c.cache = map[string]cachedList{}
	_ = c.Check(context.Background(), &Reference{Idx: 1, URI: uri})
	_ = c.Check(context.Background(), &Reference{Idx: 1, URI: uri})
	if *hits != 3 {
		t.Fatalf("token within iat+ttl not cached: %d fetches", *hits)
	}
}

// The trust call can be slow (PDP plus fallback); the cache deadline is fixed
// before it and checked against the clock after it, so it never outlives
// iat+ttl.
func TestCache_DeadlineNotExtendedBySlowTrust(t *testing.T) {
	key := newKey(t)
	c, uri, hits := serve(t, func(u string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": u, "iat": testEpoch.Unix(), "ttl": 60,
			"status_list": map[string]any{"bits": 1, "lst": packList(t, 1, nil, 64)}})
		tok.Header["typ"] = "statuslist+jwt"
		tok.Header["jwk"] = jwkOf(&key.PublicKey)
		s, _ := tok.SignedString(key)
		return s
	}, "")
	clock := testEpoch
	c.now = func() time.Time { return clock }
	// The trust call takes 2 minutes of (fake) time, longer than the ttl.
	c.trust = func(context.Context, string, *trust.KeyMaterial) (bool, error) {
		clock = clock.Add(2 * time.Minute)
		return true, nil
	}
	ref := &Reference{Idx: 1, URI: uri}
	for i := 0; i < 2; i++ {
		if err := c.Check(context.Background(), ref); err != nil {
			t.Fatal(err)
		}
	}
	if *hits != 2 || len(c.cache) != 0 {
		t.Fatalf("list cached past iat+ttl after a slow trust call: hits=%d cached=%d", *hits, len(c.cache))
	}
}

// A present x5c is never read as absent: null, empty, non-array and malformed
// chains are refused even when a valid jwk would verify the token.
func TestParseJWT_PresentX5CValidated(t *testing.T) {
	key := newKey(t)
	good, _ := x5cServiceToken(t, key, "https://x.example/l/1", map[int]int{}, "match")
	hdrPart := func(x5c any, absent bool) string {
		h := map[string]any{"alg": "ES256", "typ": "statuslist+jwt", "jwk": jwkOf(&key.PublicKey)}
		if !absent {
			h["x5c"] = x5c
		}
		b, _ := json.Marshal(h)
		parts := strings.Split(good, ".")
		signing := base64.RawURLEncoding.EncodeToString(b) + "." + parts[1]
		digest := sha256.Sum256([]byte(signing))
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	leaf := strings.Split(good, ".")[0]
	var gh struct {
		X5C []string `json:"x5c"`
	}
	hb, _ := base64.RawURLEncoding.DecodeString(leaf)
	_ = json.Unmarshal(hb, &gh)

	c := newTestChecker(nil, false, trustAll)
	for name, tc := range map[string]struct {
		x5c    any
		absent bool
		reject bool
	}{
		"null":       {x5c: nil, reject: true},
		"empty":      {x5c: []string{}, reject: true},
		"string":     {x5c: gh.X5C[0], reject: true},
		"object":     {x5c: map[string]any{}, reject: true},
		"non-string": {x5c: []any{1}, reject: true},
		"null elem":  {x5c: []any{nil}, reject: true},
		"empty elem": {x5c: []string{""}, reject: true},
		"bad base64": {x5c: []string{"!!!notbase64"}, reject: true},
		"valid":      {x5c: gh.X5C},
		"absent":     {absent: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.parseJWT(context.Background(), hdrPart(tc.x5c, tc.absent), "https://x.example/l/1")
			isX5C := err != nil && strings.Contains(err.Error(), "x5c")
			if tc.reject && !isX5C {
				t.Fatalf("err = %v, want x5c rejection", err)
			}
			if !tc.reject && isX5C {
				t.Fatalf("err = %v, unexpected x5c rejection", err)
			}
		})
	}
}

// A present crit header is never ignored (RFC 7515 section 4.1.11): no critical
// extensions are supported, so null, empty and populated crit are all refused
// even though the signature is valid.
func TestParseJWT_CritHeaderRejected(t *testing.T) {
	key := newKey(t)
	good, _ := x5cServiceToken(t, key, "https://x.example/l/1", map[int]int{}, "match")
	build := func(crit any, absent bool) string {
		h := map[string]any{"alg": "ES256", "typ": "statuslist+jwt", "jwk": jwkOf(&key.PublicKey)}
		if !absent {
			h["crit"] = crit
		}
		b, _ := json.Marshal(h)
		parts := strings.Split(good, ".")
		signing := base64.RawURLEncoding.EncodeToString(b) + "." + parts[1]
		digest := sha256.Sum256([]byte(signing))
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	c := newTestChecker(nil, false, trustAll)
	for name, tc := range map[string]struct {
		crit   any
		absent bool
		reject bool
	}{
		"null":        {crit: nil, reject: true},
		"empty":       {crit: []string{}, reject: true},
		"unknown ext": {crit: []string{"exp-ext"}, reject: true},
		"string":      {crit: "exp-ext", reject: true},
		"absent":      {absent: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.parseJWT(context.Background(), build(tc.crit, tc.absent), "https://x.example/l/1")
			isCrit := err != nil && strings.Contains(err.Error(), "crit")
			if tc.reject && !isCrit {
				t.Fatalf("err = %v, want crit rejection", err)
			}
			if !tc.reject && isCrit {
				t.Fatalf("err = %v, unexpected crit rejection", err)
			}
		})
	}
}

// The x5c leaf is accepted in standard base64 or unpadded base64url, also
// when a jwk header must be matched against it.
func TestX5CLeafEncodingWithJWK(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		urlEnc  bool
		jwkMode string
		wantErr bool
	}{
		{"std x5c + matching jwk", false, "match", false},
		{"base64url x5c + matching jwk", true, "match", false},
		{"base64url x5c + mismatching jwk", true, "mismatch", true},
		{"std x5c + mismatching jwk", false, "mismatch", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := newKey(t)
			var uri string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/statuslist+jwt")
				tok := x5cTokenEncoded(t, key, uri, tc.jwkMode, tc.urlEnc)
				_, _ = w.Write([]byte(tok))
			}))
			defer srv.Close()
			uri = srv.URL + "/l"
			c := newTestChecker(srv.Client(), false, trustAll)
			err := c.Check(ctx, &Reference{Idx: 1, URI: uri})
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, errKeyMismatch) {
				t.Fatalf("want key mismatch, got %v", err)
			}
		})
	}
}

func x5cTokenEncoded(t *testing.T, key *ecdsa.PrivateKey, listURL, jwkMode string, urlEnc bool) string {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "s"},
		NotBefore: testEpoch.Add(-time.Hour), NotAfter: testEpoch.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString(der)
	if urlEnc {
		enc = base64.RawURLEncoding.EncodeToString(der)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": listURL, "iat": testEpoch.Unix(), "ttl": 900,
		"status_list": map[string]any{"bits": 1, "lst": packList(t, 1, map[int]int{3: 1}, 64)},
	})
	tok.Header["typ"] = "statuslist+jwt"
	tok.Header["x5c"] = []string{enc}
	if jwkMode == "match" {
		tok.Header["jwk"] = jwkOf(&key.PublicKey)
	} else {
		tok.Header["jwk"] = jwkOf(&newKey(t).PublicKey)
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
