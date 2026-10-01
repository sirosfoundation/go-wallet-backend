package statuslist

import (
	"context"
	"errors"
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
	now := time.Now()
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
		{name: "iss number", mutate: func(c jwt.MapClaims) { c["iss"] = 5 }, wantErr: "iss"},
		{name: "iss object", mutate: func(c jwt.MapClaims) { c["iss"] = map[string]any{} }, wantErr: "iss"},
		{name: "sub null", mutate: func(c jwt.MapClaims) { c["sub"] = nil }, wantErr: "sub"},
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
		{name: "ttl array", mutate: func(c jwt.MapClaims) { c["ttl"] = []int{1} }, wantErr: "ttl"},
		{name: "status_list null", mutate: func(c jwt.MapClaims) { c["status_list"] = nil }, wantErr: "status_list"},
		{name: "status_list string", mutate: func(c jwt.MapClaims) { c["status_list"] = "x" }, wantErr: "status_list"},
		{name: "status_list absent", mutate: func(c jwt.MapClaims) { delete(c, "status_list") }, wantErr: "no status_list"},
		{name: "bits null", mutate: func(c jwt.MapClaims) { c["status_list"].(map[string]any)["bits"] = nil }, wantErr: "bits"},
		{name: "bits string", mutate: func(c jwt.MapClaims) { c["status_list"].(map[string]any)["bits"] = "1" }, wantErr: "bits"},
		{name: "lst null", mutate: func(c jwt.MapClaims) { c["status_list"].(map[string]any)["lst"] = nil }, wantErr: "lst"},
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
			c := NewChecker(srv.Client(), false, func(_ context.Context, sub string, _ *trust.KeyMaterial) (bool, error) {
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
