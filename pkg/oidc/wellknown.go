package oidc

import (
	"fmt"
	"net/url"
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

// NormalizeIssuerURL trims a bare trailing "/" from rawURL when it carries
// no meaningful path (i.e. the path is empty or exactly "/"), so that
// "https://issuer.example.com" and "https://issuer.example.com/" are treated
// as the same issuer and produce the same WellKnownURL result. Issuers with
// a meaningful path (e.g. "https://issuer.example.com/tenant/") are returned
// unchanged — WellKnownURL preserves their trailing slash deliberately, per
// its own doc comment.
//
// Callers that construct well-known URIs from a caller-supplied issuer
// identifier should call this before WellKnownURL, so all such call sites
// treat a bare trailing slash identically instead of each reimplementing
// (and potentially diverging on) this normalization.
func NormalizeIssuerURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if parsed.Path == "/" {
		// Clear only the parsed root path and re-serialise, so a "/" that
		// belongs to the query or fragment (e.g. "?redirect=https://client/")
		// is never touched.
		parsed.Path = ""
		parsed.RawPath = ""
		return parsed.String()
	}
	return rawURL
}

// SameIssuerIdentifier reports whether two issuer identifiers denote the same
// issuer. The comparison is exact except for the one equivalence RFC 3986
// §6.2.3 defines for http(s) URLs: an empty path and "/" are the same
// (so "https://issuer.example.com" == "https://issuer.example.com/"). The
// normalisation is applied identically to BOTH sides, so a document that
// declares its identifier with or without the root slash matches a configured
// identifier written either way. Paths, queries and fragments are otherwise
// compared byte for byte; in particular "/tenant" and "/tenant/" differ.
//
// Use this for comparing identifiers (metadata issuer / credential_issuer,
// JWT iss / sub). NormalizeIssuerURL alone is only for building well-known
// URLs and cache keys and must never be applied to just one side of a
// comparison.
func SameIssuerIdentifier(a, b string) bool {
	return a == b || NormalizeIssuerURL(a) == NormalizeIssuerURL(b)
}
