package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// The AS here is plain http on a loopback address, standing in for a
// cluster-internal http://backend.ns.svc:8080. The global allow_http and
// allow_private_ips switches are OFF; only http_client.trusted_idp_hosts may
// make it reachable.
func TestOwnASJWKS_TrustedIdPHost(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	host := u.Hostname()

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	require.NoError(t, err)
	es, err := gojosejwt.Signed(sig).Claims(map[string]any{
		"iss": "as-issuer", "sub": "u", "tenant_id": "t", "aud": []string{"wallet-backend"},
		"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
	}).Serialize()
	require.NoError(t, err)

	cfg := func(trusted ...string) *config.Config {
		c := &config.Config{}
		c.AS.Enabled = true
		c.AS.Issuer = "as-issuer"
		c.AS.Audiences = []string{"wallet-backend"}
		c.AS.ExternalURL = srv.URL
		c.HTTPClient = config.HTTPClientConfig{TrustedIdPHosts: trusted}
		return c
	}

	t.Run("listed host: standalone engine fetches keys and validates ES256", func(t *testing.T) {
		v, err := NewStandaloneEngineTokenValidator(cfg(host), zap.NewNop())
		require.NoError(t, err)
		defer func() { _ = v.Close() }()
		require.Eventually(t, func() bool {
			_, err := v.Validate(context.Background(), es)
			return err == nil
		}, 3*time.Second, 20*time.Millisecond)
	})

	t.Run("host not listed: startup refused, error names the setting and host", func(t *testing.T) {
		v, err := NewStandaloneEngineTokenValidator(cfg(), zap.NewNop())
		require.Error(t, err)
		assert.Nil(t, v)
		assert.Contains(t, err.Error(), "http_client.trusted_idp_hosts")
		assert.Contains(t, err.Error(), host)
		_, err = NewStandaloneEngineTokenValidator(cfg("other.example"), zap.NewNop())
		assert.ErrorContains(t, err, "http_client.trusted_idp_hosts")
	})

	t.Run("host not listed over https to a private address: fetch refused", func(t *testing.T) {
		tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(set)
		}))
		defer tls.Close()
		c := cfg()
		c.AS.ExternalURL = tls.URL
		c.HTTPClient.InsecureSkipVerify = false
		r, err := newRemoteJWKSRelay(c)
		require.NoError(t, err)
		defer func() { _ = r.Close() }()
		resp, err := http.Get(r.url)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode, "private address without a trusted entry is refused")
	})

	t.Run("cloud metadata stays blocked even when listed", func(t *testing.T) {
		c := cfg("169.254.169.254")
		c.AS.ExternalURL = "http://169.254.169.254"
		client := c.HTTPClient.NewOwnASHTTPClient(2 * time.Second)
		_, err := client.Get("http://169.254.169.254/auth/.well-known/jwks.json") //nolint:bodyclose
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cloud metadata")
	})
}
