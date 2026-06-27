package as

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTAC_Has(t *testing.T) {
	tac := TAC("rwl")
	assert.True(t, tac.Has(TACRead))
	assert.True(t, tac.Has(TACWrite))
	assert.True(t, tac.Has(TACList))
	assert.False(t, tac.Has(TACAdmin))
	assert.False(t, tac.Has(TACDelegate))
}

func TestTAC_HasAll(t *testing.T) {
	tac := TAC("rwlid")
	assert.True(t, tac.HasAll("rl"))
	assert.True(t, tac.HasAll("rwlid"))
	assert.False(t, tac.HasAll("rwlida"))
}

func TestTAC_IsSubsetOf(t *testing.T) {
	full := TAC("rwlidka")
	subset := TAC("rl")
	assert.True(t, subset.IsSubsetOf(full))
	assert.False(t, full.IsSubsetOf(subset))

	empty := TAC("")
	assert.True(t, empty.IsSubsetOf(full))
	assert.True(t, empty.IsSubsetOf(subset))
}

func TestTAC_Validate(t *testing.T) {
	assert.NoError(t, TAC("rwlidka").Validate())
	assert.NoError(t, TAC("rl").Validate())
	assert.NoError(t, TAC("").Validate())
	assert.Error(t, TAC("rx").Validate())
	assert.Error(t, TAC("r1").Validate())
}

func testKeyManager(t *testing.T) *KeyManager {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dir := t.TempDir()
	path := writeKeyPEM(t, dir, "ec.pem", key, "EC PRIVATE KEY")

	km, err := NewKeyManager(path)
	require.NoError(t, err)
	return km
}

func TestTokenIssuer_Issue(t *testing.T) {
	km := testKeyManager(t)
	ti := NewTokenIssuer(km, "https://as.example.com", func(string) time.Duration {
		return 2 * time.Minute
	})

	token, err := ti.Issue("user-42", "https://api.example.com", "tenant-1", TAC("rl"), "urn:siros:acr:passkey")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestTokenIssuer_Issue_ParseAndVerify(t *testing.T) {
	km := testKeyManager(t)
	issuer := "https://as.example.com"
	audience := "https://api.example.com"

	ti := NewTokenIssuer(km, issuer, func(string) time.Duration {
		return 2 * time.Minute
	})

	raw, err := ti.Issue("user-42", audience, "tenant-1", TAC("rwl"), "urn:siros:acr:passkey")
	require.NoError(t, err)

	claims, err := ti.ParseAndVerify(raw, []string{audience})
	require.NoError(t, err)

	assert.Equal(t, "user-42", claims.Subject)
	assert.Equal(t, "tenant-1", claims.TenantID)
	assert.Equal(t, TAC("rwl"), claims.TAC)
	assert.Equal(t, "urn:siros:acr:passkey", claims.ACR)
	assert.Equal(t, issuer, claims.Issuer)
	assert.Contains(t, claims.Audience, audience)
	assert.NotEmpty(t, claims.ID)
}

func TestTokenIssuer_ParseAndVerify_WrongAudience(t *testing.T) {
	km := testKeyManager(t)
	ti := NewTokenIssuer(km, "https://as.example.com", func(string) time.Duration {
		return 2 * time.Minute
	})

	raw, err := ti.Issue("user-42", "https://api.example.com", "t1", TAC("r"), "")
	require.NoError(t, err)

	_, err = ti.ParseAndVerify(raw, []string{"https://other.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token validation failed")
}

func TestTokenIssuer_ParseAndVerify_Expired(t *testing.T) {
	km := testKeyManager(t)
	ti := NewTokenIssuer(km, "https://as.example.com", func(string) time.Duration {
		return -1 * time.Minute // already expired
	})

	raw, err := ti.Issue("user-42", "https://api.example.com", "t1", TAC("r"), "")
	require.NoError(t, err)

	_, err = ti.ParseAndVerify(raw, []string{"https://api.example.com"})
	require.Error(t, err)
}

func TestTokenIssuer_ParseAndVerify_WrongIssuer(t *testing.T) {
	km := testKeyManager(t)
	ti1 := NewTokenIssuer(km, "https://as1.example.com", func(string) time.Duration {
		return 2 * time.Minute
	})
	ti2 := NewTokenIssuer(km, "https://as2.example.com", func(string) time.Duration {
		return 2 * time.Minute
	})

	raw, err := ti1.Issue("user-42", "https://api.example.com", "t1", TAC("r"), "")
	require.NoError(t, err)

	_, err = ti2.ParseAndVerify(raw, []string{"https://api.example.com"})
	require.Error(t, err)
}

func TestTokenIssuer_ParseAndVerify_DifferentKey(t *testing.T) {
	km1 := testKeyManager(t)
	km2 := testKeyManager(t)

	ti1 := NewTokenIssuer(km1, "https://as.example.com", func(string) time.Duration {
		return 2 * time.Minute
	})
	ti2 := NewTokenIssuer(km2, "https://as.example.com", func(string) time.Duration {
		return 2 * time.Minute
	})

	raw, err := ti1.Issue("user-42", "https://api.example.com", "t1", TAC("r"), "")
	require.NoError(t, err)

	_, err = ti2.ParseAndVerify(raw, []string{"https://api.example.com"})
	require.Error(t, err)
}

func TestTokenIssuer_AudienceTTL(t *testing.T) {
	km := testKeyManager(t)

	ttlFunc := func(aud string) time.Duration {
		if aud == "ws://engine" {
			return 30 * time.Second
		}
		return 2 * time.Minute
	}

	ti := NewTokenIssuer(km, "https://as.example.com", ttlFunc)

	// Both should issue successfully with different TTLs
	t1, err := ti.Issue("u", "https://api", "t", TAC("r"), "")
	require.NoError(t, err)
	assert.NotEmpty(t, t1)

	t2, err := ti.Issue("u", "ws://engine", "t", TAC("r"), "")
	require.NoError(t, err)
	assert.NotEmpty(t, t2)
}
