package server

import (
	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-tokenauth/revocation"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// tokenJWKSURL returns the JWKS endpoint of the authorization server that
// issues the tokens this process validates. It is always derived from
// as.external_url (there is deliberately no override), whether or not the auth
// role runs in this process.
func tokenJWKSURL(cfg *config.Config) string {
	return cfg.AS.ExternalURL + "/auth/.well-known/jwks.json"
}

// tokenIssuer returns the expected "iss" claim: as.issuer, falling back to
// jwt.issuer.
func tokenIssuer(cfg *config.Config) string {
	if cfg.AS.Issuer != "" {
		return cfg.AS.Issuer
	}
	return cfg.JWT.Issuer
}

// buildTokenValidator is the single place where the go-tokenauth validator
// used by every role is constructed from the backend configuration. It works
// the same whether or not as.enabled is true: a process that does not run the
// AS (for example --mode=registry alone) still validates the tokens the AS
// issues elsewhere, using as.external_url / as.issuer / as.legacy.* /
// jwt.secret.
//
// audiences is the accepted "aud" list handed to the validator; roles that
// enforce a narrower audience themselves (the registry) pass nil.
//
// The returned validator is not started; callers Start() it.
//
// NOTE for the go-tokenauth v0.5.0 bump (#414) and the audience-list change
// (#429): this is the only function that needs to change (Audiences must be
// non-empty and also apply to legacy tokens there, so Legacy.Issuers must be
// set to the jwt issuer and the caller-specific audience list must include
// rp_id for legacy tokens).
func buildTokenValidator(cfg *config.Config, audiences []string, rev revocation.Checker) *tokenvalidator.Validator {
	legacySecret := []byte(cfg.JWT.Secret)
	return tokenvalidator.New(tokenvalidator.Config{
		JWKSURL:   tokenJWKSURL(cfg),
		Issuer:    tokenIssuer(cfg),
		Audiences: audiences,
		Legacy: tokenvalidator.LegacyConfig{
			// Never validate HMAC tokens against an empty key.
			Enabled:    cfg.AS.Legacy.Enabled && len(legacySecret) > 0,
			HMACSecret: legacySecret,
		},
		Revocation: rev,
	})
}
