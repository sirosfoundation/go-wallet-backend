package server

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The no-op lookup (tokengate.NoUserRecords) is for the registry only. Every
// backend-role TokenAuthMiddleware call in this package must be wired to the
// real user store, and the no-op must not appear here at all: a user-scoped
// route behind it would silently lose the SID-AUTH-06 cut-off.
func TestBackendRolesNeverUseNoUserRecords(t *testing.T) {
	src, err := os.ReadFile("providers.go")
	require.NoError(t, err)
	assert.NotContains(t, string(src), "NoUserRecords",
		"the no-op user lookup must not be wired in a backend role")

	calls := regexp.MustCompile(`middleware\.TokenAuthMiddleware\([^\n]*\)`).FindAllString(string(src), -1)
	require.NotEmpty(t, calls, "expected TokenAuthMiddleware call sites in providers.go")
	for _, c := range calls {
		assert.Contains(t, c, "p.store.Users()", "call site must pass the real user store: %s", c)
	}
}
