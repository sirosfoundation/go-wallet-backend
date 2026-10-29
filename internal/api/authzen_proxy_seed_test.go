package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeAuxiliaryDataAdvertisement(t *testing.T) {
	var md map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(`{"signed_metadata":"JWT","credential_configurations_supported":{
		"valid":{"auxiliary_data_supported":{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["n","ssc"]}],"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["n","psc"],"required":true}]}},
		"opening":{"auxiliary_data_supported":{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["n","ssc"],"opening":"deadbeef"}]}},
		"empty":{"auxiliary_data_supported":{"to_wallet":[]}},
		"scalar":{"auxiliary_data_supported":"deadbeef"},
		"in_metadata":{"credential_metadata":{"auxiliary_data":[{"type":"hash_commitment","opening":"deadbeef"}]}},
		"legacy_seed":{"credential_metadata":{"org.siros.secret_seed":{"namespaces":["x"]}}},
				"legacy_commitments":{"credential_metadata":{"org.siros.holder_commitments":{"commitments":["psc"]}}},
		"legacy_psc":{"credential_metadata":{"org.siros.psc":"x"}},
		"plain":{"credential_metadata":{"display":[]}},"c":{"display":[]},"d":"junk"}}`), &md))
	sanitizeAuxiliaryDataAdvertisement(md)
	ccs := md["credential_configurations_supported"].(map[string]interface{})
	// The superseded SIROS member names are ordinary unknown members: ignored,
	// so the configurations that carry them are still offered.
	for _, id := range []string{"valid", "plain", "c", "legacy_seed", "legacy_commitments", "legacy_psc"} {
		assert.Contains(t, ccs, id)
	}
	for _, id := range []string{"opening", "empty", "scalar", "in_metadata"} {
		assert.NotContains(t, ccs, id)
	}
	out, _ := json.Marshal(md)
	assert.NotContains(t, string(out), "deadbeef")
	_, has := md["signed_metadata"]
	assert.False(t, has, "removing a configuration also drops the original JWT")
	sanitizeAuxiliaryDataAdvertisement(map[string]interface{}{}) // no panic
}

func TestSanitizeAuxiliaryDataAdvertisement_KeepsSignedJWTWhenNothingRemoved(t *testing.T) {
	var md map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(`{"signed_metadata":"JWT","credential_configurations_supported":{
		"a":{"auxiliary_data_supported":{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["n","ssc"]}]}}}}`), &md))
	sanitizeAuxiliaryDataAdvertisement(md)
	assert.Equal(t, "JWT", md["signed_metadata"])
}
