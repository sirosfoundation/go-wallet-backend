package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestJWKSRelay_ServesAndFailsClosed(t *testing.T) {
	var fail atomic.Bool
	r, err := startJWKSRelay(func(context.Context) ([]byte, error) {
		if fail.Load() {
			return nil, errors.New("down")
		}
		return []byte(`{"keys":[]}`), nil
	})
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	resp, err := http.Get(r.url)
	require.NoError(t, err)
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
	assert.JSONEq(t, `{"keys":[]}`, string(b))

	fail.Store(true)
	resp, err = http.Get(r.url)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)

	var nilRelay *jwksRelay
	assert.NoError(t, nilRelay.Close())
}

func TestLocalJWKSRelay(t *testing.T) {
	r, err := newLocalJWKSRelay(func() jose.JSONWebKeySet { return jose.JSONWebKeySet{} })
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	resp, err := http.Get(r.url)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var set map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&set))
}

func TestRemoteJWKSRelay_UpstreamErrorsAreBadGateway(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", 500) }))
	defer up.Close()
	c := &config.Config{}
	c.AS.ExternalURL = up.URL
	c.HTTPClient = config.HTTPClientConfig{AllowHTTP: true, AllowPrivateIPs: true}
	r, err := newRemoteJWKSRelay(c)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	resp, err := http.Get(r.url)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

func TestASJWKSURL(t *testing.T) {
	const tail = "/auth/.well-known/jwks.json"
	for name, tc := range map[string]struct {
		in, want string
		wantErr  bool
	}{
		"normal":          {in: "https://as.example", want: "https://as.example" + tail},
		"trailing slash":  {in: "https://as.example/", want: "https://as.example" + tail},
		"path prefix":     {in: "https://as.example/wallet/", want: "https://as.example/wallet" + tail},
		"query":           {in: "https://as.example/?x=1", wantErr: true},
		"fragment":        {in: "https://as.example/#fragment", wantErr: true},
		"empty query":     {in: "https://as.example/?", wantErr: true},
		"empty fragment":  {in: "https://as.example/#", wantErr: true},
		"plain http deny": {in: "http://as.example", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{AS: config.ASConfig{ExternalURL: tc.in}}
			got, err := asJWKSURL(cfg)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
