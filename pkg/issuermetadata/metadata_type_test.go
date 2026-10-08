package issuermetadata

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseMetadataType(t *testing.T) {
	for in, want := range map[string]MetadataType{
		"": MetadataTypePreferSigned, "any": MetadataTypeAny, "prefer-signed": MetadataTypePreferSigned,
		"require-signed": MetadataTypeRequireSigned, "prefer-unsigned": MetadataTypePreferUnsigned,
		"require-unsigned": MetadataTypeRequireUnsigned,
	} {
		got, err := ParseMetadataType(in)
		if err != nil || got != want {
			t.Errorf("ParseMetadataType(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"Prefer-Signed", "signed", "true", " any", "prefer_signed"} {
		if _, err := ParseMetadataType(bad); err == nil {
			t.Errorf("ParseMetadataType(%q) must fail", bad)
		}
	}
	if _, err := New(Config{MetadataType: "bogus"}); err == nil {
		t.Error("New must reject an unknown metadata type")
	}
}

// issuerBehaviour says what a test issuer answers to each Accept value.
type reply int

const (
	r406 reply = iota
	r400
	r500
	r403
	r404
	rSigned   // valid application/jwt
	rBadSig   // application/jwt whose signature does not verify
	rUnsigned // plain JSON
)

type behaviour struct {
	jwt, json, both reply // answer to Accept: application/jwt, application/json, and the two together
}

func TestResolve_MetadataTypeMatrix(t *testing.T) {
	const (
		jwtA  = "application/jwt"
		jsonA = "application/json"
		bothA = "application/jwt, application/json"
	)
	compliantBoth := behaviour{rSigned, rUnsigned, rSigned}
	signedOnly := behaviour{rSigned, r406, rSigned}
	unsignedOnly := behaviour{r406, rUnsigned, rUnsigned}
	jwtBadRequest := behaviour{r400, rUnsigned, rUnsigned}
	jwtForbidden := behaviour{r403, rUnsigned, rUnsigned}
	jwtNotFound := behaviour{r404, rUnsigned, rUnsigned}
	jsonBadRequest := behaviour{rSigned, r400, rSigned}
	jsonForbidden := behaviour{rSigned, r403, rSigned}
	jsonNotFound := behaviour{rSigned, r404, rSigned}
	badSigAndUnsigned := behaviour{rBadSig, rUnsigned, rBadSig}
	badSigOnly := behaviour{rBadSig, r406, rBadSig}
	ignoresAcceptUnsigned := behaviour{rUnsigned, rUnsigned, rUnsigned}
	ignoresAcceptSigned := behaviour{rSigned, rSigned, rSigned}
	down := behaviour{r500, r500, r500}
	none := behaviour{r406, r406, r406}

	type want struct {
		ok      bool
		signed  bool
		accepts []string
	}
	cases := []struct {
		name string
		mode MetadataType
		b    behaviour
		w    want
	}{
		// any: single request, takes whatever is served.
		{"any/both", MetadataTypeAny, compliantBoth, want{true, true, []string{bothA}}},
		{"any/unsignedOnly", MetadataTypeAny, unsignedOnly, want{true, false, []string{bothA}}},
		{"any/none", MetadataTypeAny, none, want{false, false, []string{bothA}}},
		{"any/badSig", MetadataTypeAny, badSigAndUnsigned, want{false, false, []string{bothA}}},

		// prefer-signed.
		{"prefer-signed/both", MetadataTypePreferSigned, compliantBoth, want{true, true, []string{jwtA}}},
		{"prefer-signed/unsignedOnly-406", MetadataTypePreferSigned, unsignedOnly, want{true, false, []string{jwtA, jsonA}}},
		{"prefer-signed/jwt-400-terminal", MetadataTypePreferSigned, jwtBadRequest, want{false, false, []string{jwtA}}},
		{"prefer-signed/jwt-403-terminal", MetadataTypePreferSigned, jwtForbidden, want{false, false, []string{jwtA}}},
		{"prefer-signed/jwt-404-terminal", MetadataTypePreferSigned, jwtNotFound, want{false, false, []string{jwtA}}},
		{"prefer-signed/none", MetadataTypePreferSigned, none, want{false, false, []string{jwtA, jsonA}}},
		{"prefer-signed/badSig-no-downgrade", MetadataTypePreferSigned, badSigAndUnsigned, want{false, false, []string{jwtA}}},
		{"prefer-signed/5xx-terminal", MetadataTypePreferSigned, down, want{false, false, []string{jwtA}}},
		{"prefer-signed/ignores-accept-unsigned", MetadataTypePreferSigned, ignoresAcceptUnsigned, want{true, false, []string{jwtA}}},

		// require-signed: never falls back.
		{"require-signed/both", MetadataTypeRequireSigned, compliantBoth, want{true, true, []string{jwtA}}},
		{"require-signed/unsignedOnly", MetadataTypeRequireSigned, unsignedOnly, want{false, false, []string{jwtA}}},
		{"require-signed/jwt-400", MetadataTypeRequireSigned, jwtBadRequest, want{false, false, []string{jwtA}}},
		{"require-signed/badSig", MetadataTypeRequireSigned, badSigAndUnsigned, want{false, false, []string{jwtA}}},
		{"require-signed/ignores-accept-unsigned", MetadataTypeRequireSigned, ignoresAcceptUnsigned, want{false, false, []string{jwtA}}},

		// prefer-unsigned.
		{"prefer-unsigned/both", MetadataTypePreferUnsigned, compliantBoth, want{true, false, []string{jsonA}}},
		{"prefer-unsigned/signedOnly-406", MetadataTypePreferUnsigned, signedOnly, want{true, true, []string{jsonA, jwtA}}},
		{"prefer-unsigned/json-400-terminal", MetadataTypePreferUnsigned, jsonBadRequest, want{false, false, []string{jsonA}}},
		{"prefer-unsigned/json-403-terminal", MetadataTypePreferUnsigned, jsonForbidden, want{false, false, []string{jsonA}}},
		{"prefer-unsigned/json-404-terminal", MetadataTypePreferUnsigned, jsonNotFound, want{false, false, []string{jsonA}}},
		{"prefer-unsigned/none", MetadataTypePreferUnsigned, none, want{false, false, []string{jsonA, jwtA}}},
		{"prefer-unsigned/badSig-no-fallthrough", MetadataTypePreferUnsigned, behaviour{rBadSig, rBadSig, rBadSig}, want{false, false, []string{jsonA}}},
		{"prefer-unsigned/badSigOnly", MetadataTypePreferUnsigned, badSigOnly, want{false, false, []string{jsonA, jwtA}}},
		{"prefer-unsigned/ignores-accept-signed", MetadataTypePreferUnsigned, ignoresAcceptSigned, want{true, true, []string{jsonA}}},

		// require-unsigned: never falls back, rejects application/jwt.
		{"require-unsigned/both", MetadataTypeRequireUnsigned, compliantBoth, want{true, false, []string{jsonA}}},
		{"require-unsigned/signedOnly", MetadataTypeRequireUnsigned, signedOnly, want{false, false, []string{jsonA}}},
		{"require-unsigned/ignores-accept-signed", MetadataTypeRequireUnsigned, ignoresAcceptSigned, want{false, false, []string{jsonA}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, _ := newTestKey(t)
			cert := newTestCert(t, priv)
			var mu sync.Mutex
			var accepts []string
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				acc := r.Header.Get("Accept")
				mu.Lock()
				accepts = append(accepts, acc)
				mu.Unlock()
				var rep reply
				switch acc {
				case jwtA:
					rep = tc.b.jwt
				case jsonA:
					rep = tc.b.json
				default:
					rep = tc.b.both
				}
				claims := map[string]interface{}{"credential_issuer": server.URL, "sub": server.URL, "iat": time.Now().Unix()}
				switch rep {
				case r406:
					w.WriteHeader(http.StatusNotAcceptable)
				case r400:
					w.WriteHeader(http.StatusBadRequest)
				case r403:
					w.WriteHeader(http.StatusForbidden)
				case r404:
					w.WriteHeader(http.StatusNotFound)
				case r500:
					w.WriteHeader(http.StatusInternalServerError)
				case rSigned, rBadSig:
					tok := signClaimsWithX5C(t, priv, []*x509.Certificate{cert}, "openidvci-issuer-metadata+jwt", claims)
					if rep == rBadSig {
						// Corrupt the signature segment.
						i := strings.LastIndex(tok, ".") + 1
						sig := []byte(tok[i:])
						for j := 0; j < 4; j++ {
							if sig[j] == 'A' {
								sig[j] = 'B'
							} else {
								sig[j] = 'A'
							}
						}
						tok = tok[:i] + string(sig)
					}
					w.Header().Set("Content-Type", "application/jwt")
					_, _ = w.Write([]byte(tok))
				case rUnsigned:
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"credential_issuer":"` + server.URL + `"}`))
				}
			}))
			defer server.Close()

			r, err := New(Config{AllowHTTP: true, MetadataType: tc.mode})
			if err != nil {
				t.Fatal(err)
			}
			res, err := r.ResolveWithInfo(context.Background(), server.URL)
			if (err == nil) != tc.w.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.w.ok)
			}
			if err == nil && res.Signed != tc.w.signed {
				t.Errorf("signed = %v, want %v", res.Signed, tc.w.signed)
			}
			mu.Lock()
			defer mu.Unlock()
			if !reflect.DeepEqual(accepts, tc.w.accepts) {
				t.Errorf("Accept sequence = %q, want %q", accepts, tc.w.accepts)
			}
		})
	}
}

// Only 406 triggers the prefer-* fallback; 429, 4xx and 5xx are terminal.
func TestResolve_PreferModes_TerminalStatuses(t *testing.T) {
	for _, mode := range []MetadataType{MetadataTypePreferSigned, MetadataTypePreferUnsigned} {
		for _, status := range []int{400, 401, 403, 404, 415, 429, 500, 503} {
			var n int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n++
				w.WriteHeader(status)
			}))
			r, _ := New(Config{AllowHTTP: true, MetadataType: mode})
			if _, err := r.Resolve(context.Background(), server.URL); err == nil || n != 1 {
				t.Errorf("%s/%d: err=%v requests=%d, want error and 1 request", mode, status, err, n)
			}
			server.Close()
		}
	}
}

func TestNew_DeprecatedPreferSignedPrecedence(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name string
		cfg  Config
		want MetadataType
	}{
		{"both unset -> default", Config{}, MetadataTypePreferSigned},
		{"PreferSigned true -> prefer-signed", Config{PreferSigned: &yes}, MetadataTypePreferSigned},
		{"PreferSigned false -> prefer-unsigned", Config{PreferSigned: &no}, MetadataTypePreferUnsigned},
		{"MetadataType wins over true", Config{MetadataType: MetadataTypeRequireUnsigned, PreferSigned: &yes}, MetadataTypeRequireUnsigned},
		{"MetadataType wins over false", Config{MetadataType: MetadataTypeRequireSigned, PreferSigned: &no}, MetadataTypeRequireSigned},
		{"MetadataType any wins over false", Config{MetadataType: MetadataTypeAny, PreferSigned: &no}, MetadataTypeAny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if r.cfg.MetadataType != tc.want {
				t.Errorf("effective MetadataType = %q, want %q", r.cfg.MetadataType, tc.want)
			}
		})
	}
	if _, err := New(Config{MetadataType: "bogus", PreferSigned: &yes}); err == nil {
		t.Error("an invalid MetadataType must still be rejected when PreferSigned is set")
	}
}

// A legacy Config{PreferSigned: &false} still compiles and drives the first
// request's Accept header to application/json.
func TestResolve_DeprecatedPreferSignedFalseAsksJSONFirst(t *testing.T) {
	no := false
	var got []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credential_issuer":"` + server.URL + `"}`))
	}))
	defer server.Close()
	r, err := New(Config{AllowHTTP: true, PreferSigned: &no})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveWithInfo(context.Background(), server.URL); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"application/json"}) {
		t.Errorf("Accept sequence = %q", got)
	}
}
