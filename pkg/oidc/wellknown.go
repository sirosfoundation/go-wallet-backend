package oidc

import (
	"fmt"
	"net/url"
	"strings"
)

// Well-known metadata URL construction.
//
// RFC 8615 only defines the "/.well-known/" namespace. How an identifier is
// turned into a metadata URL comes from the metadata's own specification, so
// there is one builder per source. Builders only construct URLs: the identifier
// is never altered and identifiers are always compared exactly (simple string
// comparison, no normalisation).

const (
	credentialIssuerWellKnown    = "openid-credential-issuer"
	authorizationServerWellKnown = "oauth-authorization-server"
	openIDConfigurationWellKnown = "openid-configuration"
)

// CredentialIssuerMetadataURLs returns the ordered candidate URLs at which the
// Credential Issuer Metadata of identifier may be served. Callers try the first
// and fall back to the second only on HTTP 404 (see below).
//
// Version decision (option C): we try the OpenID4VCI 1.0 literal form first
// because the OIDF conformance suite tests 1.0, and the 1.1 draft form second.
//
//  1. OpenID4VCI 1.0 section 12.2.2, literal: "/.well-known/openid-credential-issuer"
//     is inserted between the host and the path, and the path is kept EXACTLY as
//     given, a terminating "/" included:
//     https://h/test/a/x/ -> https://h/.well-known/openid-credential-issuer/test/a/x/
//     https://h/          -> https://h/.well-known/openid-credential-issuer/
//
//  2. OpenID4VCI 1.1 (draft), "Credential Issuer Identifier": when the
//     identifier has a path component, any terminating "/" MUST be removed
//     before inserting (the 1.1 change log says this was added back, 1.0 final
//     has no such rule):
//     https://issuer.example.com/tenant/ -> https://issuer.example.com/.well-known/openid-credential-issuer/tenant
//     A bare "https://host/" is treated as an empty path:
//     https://h/ -> https://h/.well-known/openid-credential-issuer
//     Exactly one terminating "/" is removed. The second form is returned only
//     when it differs from the first.
//
// Identity is not part of this: whichever URL served the document, its
// credential_issuer (or signed-metadata sub) must equal the identifier as
// received, byte for byte.
func CredentialIssuerMetadataURLs(identifier string) ([]string, error) {
	literal, err := insertWellKnown(identifier, credentialIssuerWellKnown, false)
	if err != nil {
		return nil, err
	}
	stripped, err := insertWellKnown(identifier, credentialIssuerWellKnown, true)
	if err != nil {
		return nil, err
	}
	if stripped == literal {
		return []string{literal}, nil
	}
	return []string{literal, stripped}, nil
}

// AuthorizationServerMetadataURLs returns the ordered candidate URLs for the
// metadata of the authorization server identified by issuer. Callers try the
// first and fall back to the next ONLY on HTTP 404 (see
// FetchAuthorizationServerMetadata).
//
//  1. RFC 8414 section 3.1: "/.well-known/oauth-authorization-server" is
//     inserted between the host and the path, after any terminating "/" of the
//     identifier has been removed:
//     https://h/tenant/ -> https://h/.well-known/oauth-authorization-server/tenant
//
//  2. OpenID Connect Discovery 1.0 section 4: "/.well-known/openid-configuration"
//     is APPENDED to the issuer, with a terminating "/" removed first:
//     https://h/tenant/ -> https://h/tenant/.well-known/openid-configuration
//
// Exactly one terminating "/" is removed in each form. Identity is not part of
// this: whichever URL served the document, its issuer must equal the
// identifier as received, byte for byte (RFC 8414 section 3.3, OIDC Discovery
// section 4.3).
func AuthorizationServerMetadataURLs(issuer string) ([]string, error) {
	rfc8414, err := insertWellKnown(issuer, authorizationServerWellKnown, true)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("parsing identifier: %w", err)
	}
	openIDConfig := fmt.Sprintf("%s://%s%s/.well-known/%s", parsed.Scheme, parsed.Host,
		strings.TrimSuffix(parsed.EscapedPath(), "/"), openIDConfigurationWellKnown)
	return []string{rfc8414, openIDConfig}, nil
}

func insertWellKnown(identifier, suffix string, stripTerminatingSlash bool) (string, error) {
	parsed, err := url.Parse(identifier)
	if err != nil {
		return "", fmt.Errorf("parsing identifier: %w", err)
	}
	// EscapedPath keeps percent-encoded segments as written.
	path := parsed.EscapedPath()
	if stripTerminatingSlash {
		path = strings.TrimSuffix(path, "/")
	}
	return fmt.Sprintf("%s://%s/.well-known/%s%s", parsed.Scheme, parsed.Host, suffix, path), nil
}
