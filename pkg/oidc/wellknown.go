package oidc

import (
	"fmt"
	"net/url"
	"strings"
)

// WellKnownURL constructs a well-known URI per RFC 8615.
//
// Given a base URL like "https://example.com/path/to/issuer" and a suffix
// like "openid-credential-issuer", it returns:
//
//	https://example.com/.well-known/openid-credential-issuer/path/to/issuer
//
// The function preserves percent-encoded path segments (uses EscapedPath)
// and removes any terminating "/" from the identifier's path before inserting
// the well-known string, as OpenID4VCI 1.0 section 12.2.2 and RFC 8414 section
// 3.1 require. This is URL construction only: the identifier itself is never
// altered, and identifiers are compared exactly (no normalisation).
func WellKnownURL(baseURL, suffix string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parsing base URL: %w", err)
	}

	path := strings.TrimRight(parsed.EscapedPath(), "/")

	return fmt.Sprintf("%s://%s/.well-known/%s%s", parsed.Scheme, parsed.Host, suffix, path), nil
}
