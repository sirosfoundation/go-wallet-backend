package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestRemoteASIssuerRefusesEmpty(t *testing.T) {
	c := &config.Config{}
	c.AS.ExternalURL = "https://as.example.com"

	_, err := remoteASIssuer(c, "x")
	assert.Error(t, err)

	c.JWT.Issuer = "jwt-iss"
	iss, err := remoteASIssuer(c, "x")
	require.NoError(t, err)
	assert.Equal(t, "jwt-iss", iss)

	c.AS.Issuer = "as-iss"
	iss, err = remoteASIssuer(c, "x")
	require.NoError(t, err)
	assert.Equal(t, "as-iss", iss)
}

func TestASJWKSURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://as.example.com":                "https://as.example.com/auth/.well-known/jwks.json",
		"https://as.example.com/":               "https://as.example.com/auth/.well-known/jwks.json",
		"http://backend.ns.svc:8080/":           "http://backend.ns.svc:8080/auth/.well-known/jwks.json",
		"http://backend.ns.svc:8080/base/path/": "http://backend.ns.svc:8080/base/path/auth/.well-known/jwks.json",
	} {
		c := &config.Config{}
		c.AS.ExternalURL = in
		got, err := asJWKSURL(c)
		require.NoError(t, err, in)
		assert.Equal(t, want, got)
	}
	c := &config.Config{}
	c.AS.ExternalURL = "ftp://x"
	_, err := asJWKSURL(c)
	assert.Error(t, err)
}
