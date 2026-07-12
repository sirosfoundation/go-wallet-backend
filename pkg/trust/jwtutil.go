package trust

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-cryptoutil"
)

// ExtractKeyMaterialFromJWT extracts key material (x5c or jwk) from a JWT header.
// Returns KeyMaterial with type "x5c" if x5c header is found, "jwk" if jwk header is found,
// or nil if neither is present.
//
// This is a shared utility used by both OID4VCI (signed_metadata) and OID4VP (request JWT).
func ExtractKeyMaterialFromJWT(jwtStr string) *KeyMaterial {
	parts := strings.Split(jwtStr, ".")
	if len(parts) < 2 {
		return nil
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}

	var header struct {
		X5C []string       `json:"x5c"`
		JWK map[string]any `json:"jwk"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil
	}

	// x5c takes precedence
	if len(header.X5C) > 0 {
		return &KeyMaterial{
			Type: "x5c",
			X5C:  header.X5C,
		}
	}

	// Embedded JWK
	if len(header.JWK) > 0 {
		return &KeyMaterial{
			Type: "jwk",
			JWK:  header.JWK,
		}
	}

	return nil
}

// VerifierAttestation holds the parsed content of a Verifier Attestation JWT
// as defined in OID4VP §12.
type VerifierAttestation struct {
	// Issuer is the attestation issuer (iss claim)
	Issuer string
	// Subject is the verifier's client_id (sub claim)
	Subject string
	// CNF contains the verifier's confirmation key (cnf.jwk)
	CNF map[string]interface{}
	// AttestationKeyMaterial is the key material from the attestation JWT's own header
	AttestationKeyMaterial *KeyMaterial
	// RedirectURIs is the optional list of allowed redirect URIs
	RedirectURIs []string
}

// ExtractVerifierAttestation extracts and validates the verifier attestation JWT
// from the request JWT's "jwt" JOSE header parameter (OID4VP §5.9.3.4 / §12).
//
// It parses the attestation JWT, extracts the verifier's cnf key, and verifies
// the request JWT's signature against that key. Returns the parsed attestation
// and the attestation's own key material (for trust evaluation of the issuer).
//
// Returns nil if no "jwt" header parameter is present.
func ExtractVerifierAttestation(requestJWT string) (*VerifierAttestation, error) {
	parts := strings.Split(requestJWT, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid request JWT format")
	}

	// Parse request JWT header to get the "jwt" parameter
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode request JWT header: %w", err)
	}

	var reqHeader struct {
		Alg string `json:"alg"`
		JWT string `json:"jwt"`
	}
	if err := json.Unmarshal(headerBytes, &reqHeader); err != nil {
		return nil, fmt.Errorf("failed to parse request JWT header: %w", err)
	}

	if reqHeader.JWT == "" {
		return nil, nil // no attestation present
	}

	// Parse the attestation JWT header to extract its key material
	attestKM := ExtractKeyMaterialFromJWT(reqHeader.JWT)

	// Parse the attestation JWT payload (without verification — trust evaluation
	// of the attestation issuer is delegated to go-trust PDP)
	attestParts := strings.Split(reqHeader.JWT, ".")
	if len(attestParts) < 2 {
		return nil, errors.New("invalid verifier attestation JWT format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(attestParts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation payload: %w", err)
	}

	var attestPayload struct {
		Iss          string    `json:"iss"`
		Sub          string    `json:"sub"`
		Exp          float64   `json:"exp"`
		CNF          *cnfClaim `json:"cnf"`
		RedirectURIs []string  `json:"redirect_uris"`
	}
	if err := json.Unmarshal(payloadBytes, &attestPayload); err != nil {
		return nil, fmt.Errorf("failed to parse attestation payload: %w", err)
	}

	if attestPayload.Iss == "" {
		return nil, errors.New("attestation JWT missing iss claim")
	}
	if attestPayload.Sub == "" {
		return nil, errors.New("attestation JWT missing sub claim")
	}
	if attestPayload.CNF == nil || attestPayload.CNF.JWK == nil {
		return nil, errors.New("attestation JWT missing cnf.jwk claim")
	}

	// Verify the request JWT signature against the cnf key from the attestation
	cnfKey := attestPayload.CNF.JWK
	matchedJWK, err := VerifyJWTWithResolvedKeys(requestJWT, []interface{}{cnfKey})
	if err != nil {
		return nil, fmt.Errorf("request JWT signature does not match attestation cnf key: %w", err)
	}
	_ = matchedJWK

	return &VerifierAttestation{
		Issuer:                 attestPayload.Iss,
		Subject:                attestPayload.Sub,
		CNF:                    cnfKey,
		AttestationKeyMaterial: attestKM,
		RedirectURIs:           attestPayload.RedirectURIs,
	}, nil
}

// cnfClaim represents the confirmation claim (RFC 7800).
type cnfClaim struct {
	JWK map[string]interface{} `json:"jwk"`
}

// ExtractTrustChainFromJWT extracts the "trust_chain" header parameter from a JWT.
// Per OID4VP §5.9.3.6, a verifier operating under OpenID Federation may include
// a trust_chain array in the JWT header. Returns nil if not present.
func ExtractTrustChainFromJWT(jwtStr string) []string {
	parts := strings.Split(jwtStr, ".")
	if len(parts) < 2 {
		return nil
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}

	var header struct {
		TrustChain []string `json:"trust_chain"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil
	}

	if len(header.TrustChain) == 0 {
		return nil
	}

	return header.TrustChain
}

// ErrNoEmbeddedKey is returned by VerifyJWTWithEmbeddedKey when the JWT header
// contains neither an x5c certificate chain nor an embedded JWK.
var ErrNoEmbeddedKey = errors.New("JWT header contains neither x5c nor jwk")

// VerifyJWTWithEmbeddedKey verifies a JWT's signature using the key material
// embedded in its own header (x5c or jwk). This ensures the JWT was actually
// signed by the claimed key, preventing header injection attacks.
//
// Returns the extracted KeyMaterial on success, or an error if:
//   - No key material is found in the header
//   - The signature verification fails
//   - The key format is unsupported
func VerifyJWTWithEmbeddedKey(jwtStr string, ext ...*cryptoutil.Extensions) (*KeyMaterial, error) {
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format: expected 3 parts")
	}

	// Parse header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header struct {
		Alg string         `json:"alg"`
		X5C []string       `json:"x5c"`
		JWK map[string]any `json:"jwk"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}

	// Extract the public key for verification
	var pubKey crypto.PublicKey
	var km *KeyMaterial

	if len(header.X5C) > 0 {
		// Parse the leaf certificate to get the public key
		certDER, err := base64.StdEncoding.DecodeString(header.X5C[0])
		if err != nil {
			// Try RawURLEncoding as fallback
			certDER, err = base64.RawURLEncoding.DecodeString(header.X5C[0])
			if err != nil {
				return nil, fmt.Errorf("failed to decode x5c leaf certificate: %w", err)
			}
		}
		cert, err := parseCertificateDER(certDER, ext...)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x5c leaf certificate: %w", err)
		}
		pubKey = cert.PublicKey
		km = &KeyMaterial{Type: "x5c", X5C: header.X5C}
	} else if len(header.JWK) > 0 {
		// Convert JWK to crypto.PublicKey
		key, err := jwkToPublicKey(header.JWK)
		if err != nil {
			return nil, fmt.Errorf("failed to convert JWK to public key: %w", err)
		}
		pubKey = key
		km = &KeyMaterial{Type: "jwk", JWK: header.JWK}
	} else {
		return nil, ErrNoEmbeddedKey
	}

	// Verify the JWT signature using the extracted public key
	signingMethod := jwt.GetSigningMethod(header.Alg)
	if signingMethod == nil {
		return nil, fmt.Errorf("unsupported JWT algorithm: %s", header.Alg)
	}

	// The signed data is header.payload (parts[0] + "." + parts[1])
	signingInput := parts[0] + "." + parts[1]

	// Decode the signature
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT signature: %w", err)
	}

	// Verify using golang-jwt's signing method
	if err := signingMethod.Verify(signingInput, sig, pubKey); err != nil {
		return nil, fmt.Errorf("JWT signature verification failed: %w", err)
	}

	return km, nil
}

// jwkToPublicKey converts a JWK map to a crypto.PublicKey.
// Supports EC (P-256, P-384, P-521), RSA, and OKP (Ed25519) key types.
func jwkToPublicKey(jwk map[string]any) (crypto.PublicKey, error) {
	kty, _ := jwk["kty"].(string)

	switch kty {
	case "EC":
		return ecJWKToPublicKey(jwk)
	case "RSA":
		return rsaJWKToPublicKey(jwk)
	case "OKP":
		return okpJWKToPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %s", kty)
	}
}

func ecJWKToPublicKey(jwk map[string]any) (*ecdsa.PublicKey, error) {
	crv, _ := jwk["crv"].(string)

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", crv)
	}

	xStr, _ := jwk["x"].(string)
	yStr, _ := jwk["y"].(string)
	if xStr == "" || yStr == "" {
		return nil, errors.New("EC JWK missing x or y coordinate")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC y coordinate: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func rsaJWKToPublicKey(jwk map[string]any) (*rsa.PublicKey, error) {
	nStr, _ := jwk["n"].(string)
	eStr, _ := jwk["e"].(string)
	if nStr == "" || eStr == "" {
		return nil, errors.New("RSA JWK missing n or e")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA e: %w", err)
	}

	// Convert e bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

func okpJWKToPublicKey(jwk map[string]any) (ed25519.PublicKey, error) {
	crv, _ := jwk["crv"].(string)
	if crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %s", crv)
	}

	xStr, _ := jwk["x"].(string)
	if xStr == "" {
		return nil, errors.New("OKP JWK missing x coordinate")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode OKP x coordinate: %w", err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 key size: %d", len(xBytes))
	}

	return ed25519.PublicKey(xBytes), nil
}

func parseCertificateDER(der []byte, ext ...*cryptoutil.Extensions) (*x509.Certificate, error) {
	if len(ext) > 0 && ext[0] != nil {
		return ext[0].ParseCertificate(der)
	}
	return x509.ParseCertificate(der)
}

// VerifyJWTWithResolvedKeys verifies a JWT's signature against a set of
// externally resolved JWK keys (e.g., from a DID Document). It tries each
// key until one succeeds. Returns the matching JWK on success.
//
// The keys parameter should be a slice of JWK maps ([]interface{} of
// map[string]interface{}), as returned by NormalizeJWKS or DID resolution.
func VerifyJWTWithResolvedKeys(jwtStr string, keys []interface{}) (map[string]interface{}, error) {
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format: expected 3 parts")
	}

	// Parse header for algorithm
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}

	signingMethod := jwt.GetSigningMethod(header.Alg)
	if signingMethod == nil {
		return nil, fmt.Errorf("unsupported JWT algorithm: %s", header.Alg)
	}

	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT signature: %w", err)
	}

	// If kid is present, try matching key first
	if header.Kid != "" {
		for _, k := range keys {
			jwkMap, ok := k.(map[string]interface{})
			if !ok {
				continue
			}
			kid, _ := jwkMap["kid"].(string)
			if kid != header.Kid {
				continue
			}
			pubKey, err := jwkToPublicKey(jwkMap)
			if err != nil {
				continue
			}
			if err := signingMethod.Verify(signingInput, sig, pubKey); err == nil {
				return jwkMap, nil
			}
		}
	}

	// Try all keys
	for _, k := range keys {
		jwkMap, ok := k.(map[string]interface{})
		if !ok {
			continue
		}
		pubKey, err := jwkToPublicKey(jwkMap)
		if err != nil {
			continue
		}
		if err := signingMethod.Verify(signingInput, sig, pubKey); err == nil {
			return jwkMap, nil
		}
	}

	return nil, errors.New("JWT signature does not match any resolved key")
}

// FetchJWKS fetches a JWKS from a URI using the given HTTP client.
// This is a shared utility used by both OID4VCI and OID4VP handlers.
func FetchJWKS(ctx context.Context, uri string, client *http.Client) (interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch returned status %d", resp.StatusCode)
	}

	var jwks interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	return jwks, nil
}
