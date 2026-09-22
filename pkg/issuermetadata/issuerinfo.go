package issuermetadata

import "encoding/json"

// Media-type-like format identifiers for issuer_info elements, per ETSI
// TS 119 472-3 ISS-MDATA-REG_CERT-4.2.3-05 and -08.
const (
	// FormatRegistrationCert marks the element holding the provider's WRPRC.
	FormatRegistrationCert = "registration_cert"
	// FormatRegistrarDataset marks the element holding the registrar's own
	// record of the provider, for deployments that publish one instead of, or
	// alongside, a registration certificate.
	FormatRegistrarDataset = "registrar_dataset"
)

// IssuerInfoEntry is one attestation about the issuer, carried in the
// issuer_info array of the Credential Issuer Metadata. It mirrors OpenID4VP's
// verifier_info, which ISS-MDATA-REG_CERT-4.2.3-03 says to reuse.
type IssuerInfoEntry struct {
	Format string          `json:"format"`
	Data   json.RawMessage `json:"data"`
	// CredentialIDs optionally scopes the attestation to particular credential
	// configurations. An absent list means it applies to all of them.
	CredentialIDs []string `json:"credential_ids,omitempty"`
}

// IssuerInfo extracts the issuer_info array from resolved metadata.
//
// It returns nil rather than an error when the claim is absent or malformed:
// issuer_info is something a provider may simply not carry yet, and the caller
// distinguishes "no registration certificate" from "a bad one" by what it finds
// in here, not by an error from reading it.
func IssuerInfo(metadata map[string]interface{}) []IssuerInfoEntry {
	raw, ok := metadata["issuer_info"]
	if !ok {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var entries []IssuerInfoEntry
	if err := json.Unmarshal(encoded, &entries); err != nil {
		return nil
	}
	return entries
}

// RegistrationCertificate returns the compact WRPRC from issuer_info, or "".
//
// The data member is a JSON value; a registration certificate is a compact JWT,
// so it arrives as a string. Anything else is ignored rather than coerced —
// guessing at a shape the standard does not define would produce a document
// that fails much later and less clearly.
func RegistrationCertificate(metadata map[string]interface{}) string {
	for _, e := range IssuerInfo(metadata) {
		if e.Format != FormatRegistrationCert {
			continue
		}
		var s string
		if err := json.Unmarshal(e.Data, &s); err == nil && s != "" {
			return s
		}
	}
	return ""
}
