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
// and preserves any trailing slash from the issuer identifier path so the
// well-known URL exactly matches what the issuer expects.
func WellKnownURL(baseURL, suffix string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parsing base URL: %w", err)
	}

	path := parsed.EscapedPath()

	return fmt.Sprintf("%s://%s/.well-known/%s%s", parsed.Scheme, parsed.Host, suffix, path), nil
}

// NormalizeIssuerURL removes a bare root slash from rawURL when the path is empty
// or "/", so both spellings of an issuer produce the same WellKnownURL. It deletes
// only that one character from the original string: every other byte (percent-
// escape case, an empty "#" or "?", scheme spelling, a "/" in the query or
// fragment) is preserved, because the result is compared and used as a cache key.
// Issuers with a real path are unchanged. Use it before WellKnownURL; for comparing
// identifiers use SameIssuerIdentifier.
func NormalizeIssuerURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Path != "/" {
		return rawURL
	}
	// Only the "scheme://authority/" form has a root slash to remove. The "://"
	// must be the one that follows the scheme, not one inside the query.
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd < 0 || !strings.EqualFold(rawURL[:schemeEnd], parsed.Scheme) {
		return rawURL
	}
	// The path is exactly "/", so the first "/" after the authority is the root
	// slash (an earlier "?" or "#" would have made the path empty).
	rest := rawURL[schemeEnd+3:]
	pos := schemeEnd + 3 + strings.IndexByte(rest, '/')
	return rawURL[:pos] + rawURL[pos+1:]
}

// SameIssuerIdentifier reports whether two issuer identifiers denote the same issuer.
// The comparison is exact except for the RFC 3986 6.2.3 equivalence of an empty path
// and "/", applied to both sides; "/tenant" and "/tenant/" differ. Use it for
// metadata issuer / credential_issuer and JWT iss / sub; NormalizeIssuerURL on one
// side only would be wrong.
func SameIssuerIdentifier(a, b string) bool {
	return a == b || NormalizeIssuerURL(a) == NormalizeIssuerURL(b)
}
