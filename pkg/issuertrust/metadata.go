package issuertrust

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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

// ConfigView is the part of a credential configuration the check reads.
type ConfigView struct {
	Format  string
	VCT     string
	Doctype string
}

// OfferFor turns a configuration into the (format, type) pair
// provides_attestations is expressed in. The type discriminator is chosen by
// format, as the credential request will be: doctype for mso_mdoc, vct for
// SD-JWT VC. Reading "whichever field is set" would let a configuration carry
// a registered value in the field its format ignores and an unregistered one
// in the field that counts.
func OfferFor(c ConfigView) Offer {
	switch c.Format {
	case "mso_mdoc":
		return Offer{Format: c.Format, Type: c.Doctype}
	case "dc+sd-jwt", "vc+sd-jwt":
		return Offer{Format: c.Format, Type: c.VCT}
	}
	if c.VCT != "" {
		return Offer{Format: c.Format, Type: c.VCT}
	}
	return Offer{Format: c.Format, Type: c.Doctype}
}

// OffersFromConfigs lists what the wallet is about to request. configs must
// be the configurations the flow can actually select (the engine's parsed
// metadata), not a second reading of the raw document: a configuration the
// selection accepts but this skipped would be issued unchecked. An id that is
// not in configs cannot be selected, so it is skipped.
func OffersFromConfigs(configs map[string]ConfigView, ids []string) []Offer {
	var offers []Offer
	for _, id := range ids {
		cfg, ok := configs[id]
		if !ok {
			continue
		}
		offers = append(offers, OfferFor(cfg))
	}
	return offers
}

// ConfigsFromRaw reads credential_configurations_supported out of a raw
// metadata map the way encoding/json reads it into the engine's typed
// metadata: member names match case-insensitively, a null configuration is an
// empty one (selectable, so checked, and a finding), and a configuration whose
// fields have the wrong type is omitted, as the engine omits it. Two
// members that differ only in case are ambiguous, so every configuration in
// either is treated as empty.
func ConfigsFromRaw(metadata map[string]interface{}) map[string]ConfigView {
	var members []map[string]interface{}
	for k, v := range metadata {
		if !strings.EqualFold(k, "credential_configurations_supported") {
			continue
		}
		if m, ok := v.(map[string]interface{}); ok {
			members = append(members, m)
		}
	}
	out := map[string]ConfigView{}
	for _, m := range members {
		for id, v := range m {
			if len(members) > 1 {
				out[id] = ConfigView{}
				continue
			}
			var view struct {
				Format  string `json:"format"`
				VCT     string `json:"vct"`
				Doctype string `json:"doctype"`
			}
			// A configuration whose fields have the wrong type is not selectable:
			// the engine omits it from its parsed metadata, so it is omitted
			// here too. Anything the engine would keep is kept (this decodes
			// only three fields, so it can only keep more, never less).
			if encoded, err := json.Marshal(v); err == nil && json.Unmarshal(encoded, &view) == nil {
				out[id] = ConfigView{Format: view.Format, VCT: view.VCT, Doctype: view.Doctype}
			}
		}
	}
	return out
}
