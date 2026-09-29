package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRequiredClaims(t *testing.T) {
	t.Run("key=value pairs", func(t *testing.T) {
		got, err := parseRequiredClaims("department=Engineering, email_verified=true,blocked=false")
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"department":     "Engineering",
			"email_verified": true,
			"blocked":        false,
		}, got)
	})

	t.Run("JSON object keeps arrays and numbers", func(t *testing.T) {
		got, err := parseRequiredClaims(`{"groups":["admin","ops"],"level":2,"email_verified":true}`)
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"groups":         []interface{}{"admin", "ops"},
			"level":          float64(2),
			"email_verified": true,
		}, got)
	})

	t.Run("empty JSON object is a valid clear", func(t *testing.T) {
		got, err := parseRequiredClaims(" {} ")
		require.NoError(t, err)
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})

	// Anything ambiguous must be refused rather than producing a weaker gate.
	for name, in := range map[string]string{
		"empty":          "",
		"blank":          "   ",
		"no equals":      "department",
		"empty value":    "department=",
		"empty key":      "=Engineering",
		"trailing comma": "a=b,",
		"duplicate key":  "a=b,a=c",
		"broken JSON":    `{"a":`,
		"JSON array":     `["a"]`,
		"JSON null":      "null",
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			got, err := parseRequiredClaims(in)
			assert.Error(t, err)
			assert.Nil(t, got)
		})
	}
}

func TestRequiredClaimsEqual(t *testing.T) {
	assert.True(t, requiredClaimsEqual(nil, nil))
	assert.True(t, requiredClaimsEqual(nil, map[string]any{}))
	assert.True(t, requiredClaimsEqual(map[string]any{"a": true}, map[string]any{"a": true}))
	assert.True(t, requiredClaimsEqual(
		map[string]any{"groups": []any{"admin"}},
		map[string]any{"groups": []any{"admin"}}))
	assert.False(t, requiredClaimsEqual(map[string]any{"a": true}, nil))
	assert.False(t, requiredClaimsEqual(nil, map[string]any{"a": true}))
	assert.False(t, requiredClaimsEqual(map[string]any{"a": true}, map[string]any{"a": false}))
	assert.False(t, requiredClaimsEqual(map[string]any{"a": true}, map[string]any{"b": true}))
}
