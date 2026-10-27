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

// NormalizeIssuerURL trims a bare trailing "/" from rawURL when the path is empty or
// "/", so both spellings of an issuer produce the same WellKnownURL. Issuers with a
// real path are unchanged. Use it before WellKnownURL; for comparing identifiers use
// SameIssuerIdentifier.
func NormalizeIssuerURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if parsed.Path == "/" {
		// Drop only the literal root slash, the first "/" after the authority,
		// from the original string. Rebuilding via parsed.String() would also
		// respell the fragment ("#" becomes "") and percent-encoding.
		if i := strings.Index(rawURL, "//"); i >= 0 {
			if j := strings.IndexByte(rawURL[i+2:], '/'); j >= 0 {
				k := i + 2 + j
				return rawURL[:k] + rawURL[k+1:]
			}
		}
	}
	return rawURL
}

// SameIssuerIdentifier reports whether two issuer identifiers denote the same issuer.
// The comparison is exact except for the RFC 3986 6.2.3 equivalence of an empty path
// and "/", applied to both sides; "/tenant" and "/tenant/" differ. Use it for
// metadata issuer / credential_issuer and JWT iss / sub; NormalizeIssuerURL on one
// side only would be wrong.
func SameIssuerIdentifier(a, b string) bool {
	return a == b || NormalizeIssuerURL(a) == NormalizeIssuerURL(b)
}
