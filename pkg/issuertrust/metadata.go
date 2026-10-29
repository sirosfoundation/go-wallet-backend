package issuertrust

import (
	"crypto/x509"
	"encoding/base64"
	"strings"
)

// ChainFromX5C decodes the base64 DER certificates the resolver extracted.
// Certificates that do not parse are skipped rather than failing the request:
// the leaf is what the checks need, and the resolver has already verified the
// signature made with it.
func ChainFromX5C(x5c []string) []*x509.Certificate {
	if len(x5c) == 0 {
		return nil
	}
	out := make([]*x509.Certificate, 0, len(x5c))
	for _, encoded := range x5c {
		der, err := decodeX5C(encoded)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		out = append(out, cert)
	}
	return out
}

// decodeX5C accepts both base64 alphabets, matching what the signature
// verification path already tolerates.
//
// RFC 7515 specifies standard base64 for x5c, but
// trust.VerifyJWTWithEmbeddedKey falls back to raw URL encoding, so a chain it
// accepted could be dropped here - and a dropped chain does not surface as a
// decoding problem, it surfaces as "no_access_certificate", which reads as an
// issuer that published nothing rather than one this code failed to read.
func decodeX5C(encoded string) ([]byte, error) {
	if der, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return der, nil
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(encoded, "="))
}

// OffersFor turns the credential configurations the wallet is about to request
// into the (format, type) pairs provides_attestations is expressed in.
//
// credentialTypes names configuration ids from the offer; the metadata says
// what format and vct or doctype each one actually is. Guessing the format
// would make the check meaningless, so an id the metadata does not define is
// skipped. It cannot be issued either: the engine only lets a flow select
// configurations the metadata defines.
func OffersFor(metadata map[string]interface{}, credentialTypes []string) []Offer {
	configs, _ := metadata["credential_configurations_supported"].(map[string]interface{})
	if configs == nil {
		return nil
	}
	var offers []Offer
	for _, id := range credentialTypes {
		cfg, ok := configs[id].(map[string]interface{})
		if !ok {
			continue
		}
		// A configuration with no format is still offered, so it is still
		// checked: an empty format matches no registered attestation, which
		// makes it a finding rather than a way past the check.
		format, _ := cfg["format"].(string)
		offers = append(offers, Offer{Format: format, Type: credentialTypeOf(cfg)})
	}
	return offers
}

// credentialTypeOf reads the type a configuration declares: vct for SD-JWT,
// doctype for mdoc. An empty result means only the format is matched.
func credentialTypeOf(cfg map[string]interface{}) string {
	if vct, ok := cfg["vct"].(string); ok && vct != "" {
		return vct
	}
	if doctype, ok := cfg["doctype"].(string); ok && doctype != "" {
		return doctype
	}
	return ""
}
