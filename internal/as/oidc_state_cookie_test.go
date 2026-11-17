package as

import (
	"testing"
)

// TestOIDCStateCookie_HostPrefixRequiresRootPath is a regression test for a
// Copilot review finding on this PR: the state-binding cookie originally
// used the "__Host-" name prefix with Path=/auth/oidc/callback. Browsers
// refuse to store a "__Host-" cookie unless Path=="/" (also requiring
// Secure=true and no Domain attribute), so in production every OIDC
// callback would have failed with "state cookie mismatch" - the cookie
// would never actually have been set by the browser in the first place.
//
// net/http/httptest does not enforce these prefix rules, so a full
// Login->Callback round-trip test (as in oidc_handlers_test.go) does not
// catch this: it exercises Go's cookie jar, not a real browser's. This
// test asserts the cookie's attributes directly instead.
func TestOIDCStateCookie_HostPrefixRequiresRootPath(t *testing.T) {
	ck := oidcStateCookie("some-signed-value", 600, false)

	if ck.Name != oidcStateCookieSecure {
		t.Fatalf("expected production mode to use the %q cookie name, got %q", oidcStateCookieSecure, ck.Name)
	}
	if ck.Path != "/" {
		t.Errorf("__Host- prefixed cookies require Path=\"/\", got %q", ck.Path)
	}
	if !ck.Secure {
		t.Error("__Host- prefixed cookies require Secure=true")
	}
	if ck.Domain != "" {
		t.Errorf("__Host- prefixed cookies must not set Domain, got %q", ck.Domain)
	}
	if !ck.HttpOnly {
		t.Error("expected the state cookie to be HttpOnly")
	}
}

// TestOIDCStateCookie_InsecureModePath verifies the dev-mode (unprefixed)
// cookie also uses Path=/, for consistency between modes.
func TestOIDCStateCookie_InsecureModePath(t *testing.T) {
	ck := oidcStateCookie("some-signed-value", 600, true)

	if ck.Name != oidcStateCookieInsecure {
		t.Fatalf("expected insecure mode to use the %q cookie name, got %q", oidcStateCookieInsecure, ck.Name)
	}
	if ck.Path != "/" {
		t.Errorf("expected Path=\"/\", got %q", ck.Path)
	}
}
