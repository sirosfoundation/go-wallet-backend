package advertisement

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHolderCommitmentsAdvertisement(t *testing.T) {
	for name, cm := range map[string]string{"none": "", "no member": `{"display":[]}`, "not object": `[1]`} {
		present, _, ok := HolderCommitmentsAdvertisement(json.RawMessage(cm))
		assert.False(t, present, name)
		assert.False(t, ok, name)
	}
	present, names, ok := HolderCommitmentsAdvertisement(json.RawMessage(`{"org.siros.holder_commitments":{"commitments":["psc","other"]}}`))
	assert.True(t, present)
	assert.True(t, ok)
	assert.Equal(t, []string{"psc", "other"}, names)

	hexv := strings.Repeat("ab", 32)
	for name, v := range map[string]string{
		"hex value":        `"` + hexv + `"`,
		"hex name":         `{"commitments":["` + hexv[:16] + `"]}`,
		"values not names": `{"psc":"` + hexv + `"}`,
		"extra member":     `{"commitments":["psc"],"x":"` + hexv + `"}`,
		"empty list":       `{"commitments":[]}`,
		"five names":       `{"commitments":["a","b","c","d","e"]}`,
		"duplicate":        `{"commitments":["psc","psc"]}`,
		"long name":        `{"commitments":["` + strings.Repeat("a", 33) + `"]}`,
		"uppercase":        `{"commitments":["PSC"]}`,
		"non string":       `{"commitments":[7]}`,
		"string list":      `{"commitments":"psc"}`,
		"null":             `null`,
		"empty object":     `{}`,
	} {
		t.Run("malformed/"+name, func(t *testing.T) {
			present, _, ok := HolderCommitmentsAdvertisement(json.RawMessage(`{"org.siros.holder_commitments":` + v + `}`))
			assert.True(t, present)
			assert.False(t, ok)
		})
	}
}

func TestSecretSeedAdvertisement(t *testing.T) {
	for name, cm := range map[string]string{"none": "", "no member": `{"display":[]}`, "not object": `[1]`} {
		present, ok := SecretSeedAdvertisement(json.RawMessage(cm))
		assert.False(t, present, name)
		assert.False(t, ok, name)
	}
	present, ok := SecretSeedAdvertisement(json.RawMessage(`{"org.siros.secret_seed":{"namespaces":["a","b"]}}`))
	assert.True(t, present)
	assert.True(t, ok)

	hexv := strings.Repeat("ab", 32)
	for name, v := range map[string]string{
		"hex value":       `"` + hexv + `"`,
		"extra member":    `{"namespaces":["a"],"seed":"` + hexv + `"}`,
		"empty list":      `{"namespaces":[]}`,
		"nine names":      `{"namespaces":["1","2","3","4","5","6","7","8","9"]}`,
		"duplicate":       `{"namespaces":["a","a"]}`,
		"reserved name":   `{"namespaces":["namespaces"]}`,
		"long name":       `{"namespaces":["` + strings.Repeat("a", 65) + `"]}`,
		"empty name":      `{"namespaces":[""]}`,
		"not a name list": `{"namespaces":"a"}`,
	} {
		t.Run("malformed/"+name, func(t *testing.T) {
			present, ok := SecretSeedAdvertisement(json.RawMessage(`{"org.siros.secret_seed":` + v + `}`))
			assert.True(t, present)
			assert.False(t, ok)
		})
	}
}
