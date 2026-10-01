package statuslist

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// A claim that is present but null or of the wrong type must make the list
// unverifiable, never be read as absent.
func TestParseJWT_PresentClaimsAreStrict(t *testing.T) {
	key := newKey(t)
	now := testEpoch
	good := func(uri string) jwt.MapClaims {
		return jwt.MapClaims{
			"sub": uri, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"nbf": now.Add(-time.Minute).Unix(), "ttl": 300,
			"iss":         "https://issuer.example",
			"status_list": map[string]any{"bits": 1, "lst": packList(t, 1, map[int]int{4: 1}, 64)},
		}
	}
	tests := []struct {
		name    string
		mutate  func(c jwt.MapClaims)
		wantErr string // "" = accepted
	}{
		{name: "all valid"},
		{name: "absent optional claims", mutate: func(c jwt.MapClaims) {
			delete(c, "iss")
			delete(c, "exp")
			delete(c, "nbf")
			delete(c, "ttl")
		}},
		{name: "iss null", mutate: func(c jwt.MapClaims) { c["iss"] = nil }, wantErr: "iss"},
		{name: "iss empty", mutate: func(c jwt.MapClaims) { c["iss"] = "" }, wantErr: "iss"},
		{name: "iss whitespace", mutate: func(c jwt.MapClaims) { c["iss"] = " \t" }, wantErr: "iss"},
		{name: "iss number", mutate: func(c jwt.MapClaims) { c["iss"] = 5 }, wantErr: "iss"},
		{name: "iss object", mutate: func(c jwt.MapClaims) { c["iss"] = map[string]any{} }, wantErr: "iss"},
		{name: "sub null", mutate: func(c jwt.MapClaims) { c["sub"] = nil }, wantErr: "sub"},
		{name: "sub empty", mutate: func(c jwt.MapClaims) { c["sub"] = "" }, wantErr: "sub"},
		{name: "sub whitespace", mutate: func(c jwt.MapClaims) { c["sub"] = " " }, wantErr: "sub"},
		{name: "sub number", mutate: func(c jwt.MapClaims) { c["sub"] = 1 }, wantErr: "sub"},
		{name: "iat null", mutate: func(c jwt.MapClaims) { c["iat"] = nil }, wantErr: "iat"},
		{name: "iat string", mutate: func(c jwt.MapClaims) { c["iat"] = "1" }, wantErr: "iat"},
		{name: "iat fraction", mutate: func(c jwt.MapClaims) { c["iat"] = 1.5 }, wantErr: "iat"},
		{name: "exp null", mutate: func(c jwt.MapClaims) { c["exp"] = nil }, wantErr: "exp"},
		{name: "exp string", mutate: func(c jwt.MapClaims) { c["exp"] = "9999999999" }, wantErr: "exp"},
		{name: "exp bool", mutate: func(c jwt.MapClaims) { c["exp"] = true }, wantErr: "exp"},
		{name: "nbf null", mutate: func(c jwt.MapClaims) { c["nbf"] = nil }, wantErr: "nbf"},
		{name: "nbf string", mutate: func(c jwt.MapClaims) { c["nbf"] = "0" }, wantErr: "nbf"},
		{name: "ttl null", mutate: func(c jwt.MapClaims) { c["ttl"] = nil }, wantErr: "ttl"},
		{name: "ttl string", mutate: func(c jwt.MapClaims) { c["ttl"] = "300" }, wantErr: "ttl"},
		{name: "ttl zero", mutate: func(c jwt.MapClaims) { c["ttl"] = 0 }, wantErr: "ttl"},
		{name: "ttl negative", mutate: func(c jwt.MapClaims) { c["ttl"] = -1 }, wantErr: "ttl"},
		{name: "ttl min int64", mutate: func(c jwt.MapClaims) { c["ttl"] = int64(math.MinInt64) }, wantErr: "ttl"},
		{name: "ttl huge is capped, not overflowed", mutate: func(c jwt.MapClaims) { c["ttl"] = int64(math.MaxInt64) }},
		{name: "ttl array", mutate: func(c jwt.MapClaims) { c["ttl"] = []int{1} }, wantErr: "ttl"},
		{name: "status_list null", mutate: func(c jwt.MapClaims) { c["status_list"] = nil }, wantErr: "status_list"},
		{name: "status_list string", mutate: func(c jwt.MapClaims) { c["status_list"] = "x" }, wantErr: "status_list"},
		{name: "status_list absent", mutate: func(c jwt.MapClaims) { delete(c, "status_list") }, wantErr: "no status_list"},
		{name: "bits null", mutate: func(c jwt.MapClaims) { c["status_list"].(map[string]any)["bits"] = nil }, wantErr: "bits"},
		{name: "bits string", mutate: func(c jwt.MapClaims) { c["status_list"].(map[string]any)["bits"] = "1" }, wantErr: "bits"},
		{name: "lst null", mutate: func(c jwt.MapClaims) { c["status_list"].(map[string]any)["lst"] = nil }, wantErr: "lst"},
		{name: "lst empty", mutate: func(c jwt.MapClaims) { c["status_list"].(map[string]any)["lst"] = "" }, wantErr: "lst"},
		{name: "lst number", mutate: func(c jwt.MapClaims) { c["status_list"].(map[string]any)["lst"] = 3 }, wantErr: "lst"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var uri string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				claims := good(uri)
				if tc.mutate != nil {
					tc.mutate(claims)
				}
				tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
				tok.Header["typ"] = "statuslist+jwt"
				tok.Header["jwk"] = jwkOf(&key.PublicKey)
				s, err := tok.SignedString(key)
				if err != nil {
					t.Error(err)
				}
				w.Header().Set("Content-Type", mediaTypeJWT)
				_, _ = w.Write([]byte(s))
			}))
			defer srv.Close()
			uri = srv.URL + "/statuslists/1"
			var subject string
			c := newTestChecker(srv.Client(), false, func(_ context.Context, sub string, _ *trust.KeyMaterial) (bool, error) {
				subject = sub
				return true, nil
			})
			err := c.Check(context.Background(), &Reference{Idx: 3, URI: uri})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("valid list rejected: %v", err)
				}
				return
			}
			if err == nil || errors.Is(err, ErrRevoked) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want an unverifiable-list error mentioning %q", err, tc.wantErr)
			}
			if subject != "" {
				t.Fatalf("signer trust consulted (subject %q) for a malformed list", subject)
			}
		})
	}
}

// The freshness window derived from ttl is always positive and never longer
// than maxCacheTTL, whatever the claim value (including values whose Duration
// conversion would overflow).
func TestAccept_TTLLifetime(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name    string
		ttl     *int64
		iatAgo  time.Duration
		want    time.Duration // remaining lifetime; 0 with wantErr
		wantErr bool
	}{
		{"absent ttl uses default", nil, 0, defaultCacheTTL, false},
		{"valid ttl", ptr64(300), 0, 300 * time.Second, false},
		{"ttl measured from iat", ptr64(300), 100 * time.Second, 200 * time.Second, false},
		{"ttl above cache cap", ptr64(86400), 0, maxCacheTTL, false},
		{"ttl overflowing a Duration", ptr64(math.MaxInt64), 0, maxCacheTTL, false},
		{"ttl just above Duration overflow", ptr64(10_000_000_000), 0, maxCacheTTL, false},
		{"zero", ptr64(0), 0, 0, true},
		{"negative", ptr64(-5), 0, 0, true},
		{"min int64", ptr64(math.MinInt64), 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestChecker(nil, false, trustAll)
			c.now = func() time.Time { return now }
			iat := now.Add(-tc.iatAgo).Unix()
			pl, err := c.accept(context.Background(), "https://x.example/l", &trust.KeyMaterial{}, listClaims{
				sub: "https://x.example/l", iat: &iat, ttl: tc.ttl, bits: 1, lst: zlibOne(t),
			})
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "ttl") {
					t.Fatalf("got %v, want a ttl error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := pl.expires.Sub(now); got != tc.want || got <= 0 {
				t.Fatalf("lifetime = %v, want %v", got, tc.want)
			}
		})
	}
}

func ptr64(v int64) *int64 { return &v }

func zlibOne(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(packList(t, 1, map[int]int{}, 64))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
