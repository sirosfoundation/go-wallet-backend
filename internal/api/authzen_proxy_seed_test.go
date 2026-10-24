package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeSecretSeedAdvertisement(t *testing.T) {
	var md map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(`{"credential_configurations_supported":{
		"valid":{"credential_metadata":{"display":[{"name":"A"}],"org.siros.secret_seed":{"namespaces":["x"]}}},
		"hex":{"credential_metadata":{"org.siros.secret_seed":{"ns":"deadbeef"}}},
		"hexmixed":{"credential_metadata":{"org.siros.secret_seed":{"namespaces":["x"],"seed":"deadbeef"}}},
		"scalar":{"credential_metadata":{"org.siros.secret_seed":"deadbeef"}},
		"plain":{"credential_metadata":{"display":[]}},
		"c":{"display":[]}, "d":"junk"}}`), &md))
	sanitizeSecretSeedAdvertisement(md)
	ccs := md["credential_configurations_supported"].(map[string]interface{})
	assert.Contains(t, ccs, "valid")
	assert.Contains(t, ccs, "plain")
	assert.Contains(t, ccs, "c")
	for _, id := range []string{"hex", "hexmixed", "scalar"} {
		assert.NotContains(t, ccs, id)
	}
	out, _ := json.Marshal(md)
	assert.NotContains(t, string(out), "deadbeef")
	assert.Contains(t, string(out), `"org.siros.secret_seed":{"namespaces":["x"]}`)
	sanitizeSecretSeedAdvertisement(map[string]interface{}{}) // no panic
}

func TestSanitizeSecretSeedAdvertisement_DropsSignedJWTOnlyWhenConfigRemoved(t *testing.T) {
	mk := func(adv string) map[string]interface{} {
		var md map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(`{"signed_metadata":"JWT-WITH-PAYLOAD","credential_configurations_supported":{
			"a":{"credential_metadata":{"org.siros.secret_seed":`+adv+`}}}}`), &md))
		return md
	}
	md := mk(`{"namespaces":["x"]}`)
	sanitizeSecretSeedAdvertisement(md)
	assert.Equal(t, "JWT-WITH-PAYLOAD", md["signed_metadata"], "valid advertisement keeps the JWT")

	md = mk(`{"ns":"deadbeef"}`)
	sanitizeSecretSeedAdvertisement(md)
	_, has := md["signed_metadata"]
	assert.False(t, has, "removing a configuration also drops the original JWT")
}

func TestSanitizeAuxiliaryDataAdvertisement(t *testing.T) {
	var md map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(`{"signed_metadata":"JWT","credential_configurations_supported":{
		"valid":{"auxiliary_data_supported":{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["n","ssc"]}],"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["n","psc"],"required":true}]}},
		"opening":{"auxiliary_data_supported":{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["n","ssc"],"opening":"deadbeef"}]}},
		"empty":{"auxiliary_data_supported":{"to_wallet":[]}},
		"scalar":{"auxiliary_data_supported":"deadbeef"},
		"in_metadata":{"credential_metadata":{"auxiliary_data":[{"type":"hash_commitment","opening":"deadbeef"}]}},
		"plain":{"credential_metadata":{"display":[]}}}}`), &md))
	sanitizeSecretSeedAdvertisement(md)
	ccs := md["credential_configurations_supported"].(map[string]interface{})
	assert.Contains(t, ccs, "valid")
	assert.Contains(t, ccs, "plain")
	for _, id := range []string{"opening", "empty", "scalar", "in_metadata"} {
		assert.NotContains(t, ccs, id)
	}
	out, _ := json.Marshal(md)
	assert.NotContains(t, string(out), "deadbeef")
	_, has := md["signed_metadata"]
	assert.False(t, has)
}
