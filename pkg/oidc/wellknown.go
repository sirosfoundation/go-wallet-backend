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
// and strips any trailing slash from the path per OID4VCI §12.2.1 (the
// Credential Issuer Identifier must not contain query or fragment components
// and trailing slashes are not part of the canonical identifier).
func WellKnownURL(baseURL, suffix string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parsing base URL: %w", err)
	}

	path := strings.TrimRight(parsed.EscapedPath(), "/")

	return fmt.Sprintf("%s://%s/.well-known/%s%s", parsed.Scheme, parsed.Host, suffix, path), nil
}
