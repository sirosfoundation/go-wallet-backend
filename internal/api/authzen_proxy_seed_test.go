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
