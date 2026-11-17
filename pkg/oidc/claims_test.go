package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClaimsMatch(t *testing.T) {
	tests := []struct {
		name     string
		expected interface{}
		actual   interface{}
		want     bool
	}{
		// Basic type matching
		{name: "bool true match", expected: true, actual: true, want: true},
		{name: "bool false match", expected: false, actual: false, want: true},
		{name: "bool mismatch", expected: true, actual: false, want: false},
		{name: "string match", expected: "admin", actual: "admin", want: true},
		{name: "string mismatch", expected: "admin", actual: "user", want: false},
		{name: "float match", expected: 1.5, actual: 1.5, want: true},
		{name: "float mismatch", expected: 1.5, actual: 2.5, want: false},
		{name: "int to float match", expected: 42, actual: float64(42), want: true},
		{name: "int to float mismatch", expected: 42, actual: float64(43), want: false},

		// String in array matching (common for groups/roles)
		{name: "string in array", expected: "admin", actual: []interface{}{"admin", "user"}, want: true},
		{name: "string not in array", expected: "superadmin", actual: []interface{}{"admin", "user"}, want: false},
		{name: "string vs empty array", expected: "admin", actual: []interface{}{}, want: false},

		// Array subset matching
		{name: "array exact match", expected: []interface{}{"admin"}, actual: []interface{}{"admin"}, want: true},
		{name: "array subset match", expected: []interface{}{"admin"}, actual: []interface{}{"admin", "user"}, want: true},
		{name: "array superset no match", expected: []interface{}{"admin", "superadmin"}, actual: []interface{}{"admin"}, want: false},
		{name: "array all present", expected: []interface{}{"admin", "user"}, actual: []interface{}{"user", "admin", "guest"}, want: true},
		{name: "array order independent", expected: []interface{}{"b", "a"}, actual: []interface{}{"a", "b", "c"}, want: true},
		{name: "array partial missing", expected: []interface{}{"admin", "missing"}, actual: []interface{}{"admin", "user"}, want: false},

		// Single-element array vs scalar
		{name: "single array vs string", expected: []interface{}{"admin"}, actual: "admin", want: true},
		{name: "single array vs wrong string", expected: []interface{}{"admin"}, actual: "user", want: false},
		{name: "multi array vs string no match", expected: []interface{}{"admin", "user"}, actual: "admin", want: false},

		// Type mismatches
		{name: "string vs bool", expected: "true", actual: true, want: false},
		{name: "bool vs string", expected: true, actual: "true", want: false},
		{name: "string vs number", expected: "42", actual: float64(42), want: false},

		// Complex/unhandled types fall back to reflect.DeepEqual.
		{name: "map deep equal fallback", expected: map[string]interface{}{"a": 1.0}, actual: map[string]interface{}{"a": 1.0}, want: true},
		{name: "map deep equal fallback mismatch", expected: map[string]interface{}{"a": 1.0}, actual: map[string]interface{}{"a": 2.0}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClaimsMatch(tt.expected, tt.actual)
			assert.Equal(t, tt.want, got, "ClaimsMatch(%v, %v) = %v, want %v", tt.expected, tt.actual, got, tt.want)
		})
	}
}
