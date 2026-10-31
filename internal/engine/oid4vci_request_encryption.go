package engine

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// CredentialRequestEncryptionConfig is the issuer's credential_request_encryption
// metadata (OID4VCI 1.0 §12.2.4).
type CredentialRequestEncryptionConfig struct {
	// JWKS is kept raw so one unparsable key cannot invalidate the metadata.
	JWKS               json.RawMessage `json:"jwks,omitempty"`
	EncValuesSupported []string        `json:"enc_values_supported,omitempty"`
	ZipValuesSupported []string        `json:"zip_values_supported,omitempty"`
	EncryptionRequired bool            `json:"encryption_required"`
}

var (
	requestKeyAlgs = []jose.KeyAlgorithm{jose.ECDH_ES_A256KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A128KW, jose.ECDH_ES}
	requestEncs    = []jose.ContentEncryption{jose.A256GCM, jose.A128GCM, jose.A256CBC_HS512, jose.A128CBC_HS256}
)

func (h *OID4VCIHandler) opportunisticRequestEncryptionEnabled() bool {
	return h.Config == nil || !h.Config.Features.DisableOpportunisticRequestEncryption
}

// selectKey picks an issuer key usable for ECDH-based key agreement: it needs
// a kid and an alg (§10: the JWE alg MUST match the JWK alg), use "enc" or
// unset, and must be a public EC key.
func (c *CredentialRequestEncryptionConfig) selectKey() (jose.JSONWebKey, jose.KeyAlgorithm, error) {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if len(c.JWKS) == 0 || json.Unmarshal(c.JWKS, &raw) != nil {
		return jose.JSONWebKey{}, "", errors.New("credential_request_encryption has no usable jwks")
	}
	for _, alg := range requestKeyAlgs {
		for _, k := range raw.Keys {
			var jwk jose.JSONWebKey
			if json.Unmarshal(k, &jwk) != nil || !jwk.Valid() || !jwk.IsPublic() {
				continue
			}
			if pub, ok := jwk.Key.(*ecdsa.PublicKey); !ok || pub == nil {
				continue
			}
			if jwk.KeyID == "" || jwk.Algorithm != string(alg) || (jwk.Use != "" && jwk.Use != "enc") {
				continue
			}
			return jwk, alg, nil
		}
	}
	return jose.JSONWebKey{}, "", errors.New("no issuer request-encryption key with kid, use enc and a supported ECDH-ES alg")
}

// encryptRequest encrypts body as a compact JWE to the issuer's key (OID4VCI
// 1.0 §10). No zip is used. The caller sends it with Content-Type
// application/jwt.
func (c *CredentialRequestEncryptionConfig) encryptRequest(body []byte) (string, error) {
	jwk, alg, err := c.selectKey()
	if err != nil {
		return "", err
	}
	var enc jose.ContentEncryption
	for _, e := range requestEncs {
		for _, s := range c.EncValuesSupported {
			if s == string(e) {
				enc = e
				break
			}
		}
		if enc != "" {
			break
		}
	}
	if enc == "" {
		return "", fmt.Errorf("no mutually supported content encryption in enc_values_supported %v", c.EncValuesSupported)
	}
	encrypter, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: alg, Key: &jwk, KeyID: jwk.KeyID}, nil)
	if err != nil {
		return "", fmt.Errorf("cannot build request encrypter: %w", err)
	}
	obj, err := encrypter.Encrypt(body)
	if err != nil {
		return "", fmt.Errorf("cannot encrypt request: %w", err)
	}
	return obj.CompactSerialize()
}
