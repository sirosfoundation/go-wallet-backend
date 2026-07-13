package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// PoPSigner abstracts the cryptographic signing operation for attestation PoPs.
// This interface allows the instance key to be managed by different backends:
//   - Direct *ecdsa.PrivateKey (current: engine-managed DPoP key)
//   - WSCA-managed key (future: siros-wscd-manager via UniFFI/WASM)
//   - Remote signing service (future: R2PS plugin)
//
// Implementations MUST use ES256 (P-256 + SHA-256).
type PoPSigner interface {
	// SignJWT signs a jwt.Token and returns the complete compact-serialized JWT string.
	// The implementation is responsible for choosing the correct signature format.
	SignJWT(token *jwt.Token) (string, error)
	// PublicKey returns the public key corresponding to the signing key.
	PublicKey() *ecdsa.PublicKey
}

// ecdsaPoPSigner wraps an in-memory ECDSA key as a PoPSigner.
type ecdsaPoPSigner struct {
	key *ecdsa.PrivateKey
}

func (s *ecdsaPoPSigner) SignJWT(token *jwt.Token) (string, error) {
	return token.SignedString(s.key)
}

func (s *ecdsaPoPSigner) PublicKey() *ecdsa.PublicKey {
	return &s.key.PublicKey
}

// NewECDSAPoPSigner wraps an ECDSA private key as a PoPSigner.
func NewECDSAPoPSigner(key *ecdsa.PrivateKey) PoPSigner {
	return &ecdsaPoPSigner{key: key}
}

// ClientAttestationProvider supplies OAuth Client Attestation credentials
// per draft-ietf-oauth-attestation-based-client-auth-04 §3.1.
//
// This interface is transport-independent: implementations may obtain the
// WIA from an internal service (server-side model), from a pre-supplied
// value (WebSocket/WMP transport-supplied), or via a callback to the client.
//
// The two HTTP headers produced are:
//   - OAuth-Client-Attestation: the WIA JWT (typ: oauth-client-attestation+jwt)
//   - OAuth-Client-Attestation-PoP: a fresh PoP JWT (typ: oauth-client-attestation-pop+jwt)
type ClientAttestationProvider interface {
	// Available reports whether this provider can supply attestation credentials.
	Available() bool

	// SetHeaders sets the OAuth-Client-Attestation and OAuth-Client-Attestation-PoP
	// headers on the given HTTP request per draft-ietf-oauth-attestation-based-client-auth §3.1.
	// audience is the RFC 8414 issuer identifier of the target authorization server.
	SetHeaders(ctx context.Context, req *http.Request, audience string) error

	// ClientID returns the client_id to use with this attestation
	// (the WIA sub claim = JWK Thumbprint of the instance key).
	ClientID() string
}

// PreSuppliedAttestation implements ClientAttestationProvider using a WIA JWT
// that was supplied by the transport (WebSocket FlowStartMessage, WMP params, etc.)
// along with a PoPSigner for generating fresh PoPs.
//
// The PoPSigner abstracts key access so the instance key can live in:
//   - Engine memory (current: DPoP key)
//   - WSCA/WSCD (future: siros-wscd-manager via Signer interface)
type PreSuppliedAttestation struct {
	WIA    string    // the oauth-client-attestation+jwt
	Signer PoPSigner // signs the PoP; must correspond to cnf.jwk in WIA
	ID     string    // client_id (JWK thumbprint of the signing key)
}

func (p *PreSuppliedAttestation) Available() bool {
	return p != nil && p.WIA != "" && p.Signer != nil
}

func (p *PreSuppliedAttestation) ClientID() string {
	return p.ID
}

func (p *PreSuppliedAttestation) SetHeaders(ctx context.Context, req *http.Request, audience string) error {
	pop, err := createAttestationPoP(p.Signer, p.ID, audience)
	if err != nil {
		return fmt.Errorf("failed to create attestation PoP: %w", err)
	}
	req.Header.Set("OAuth-Client-Attestation", p.WIA)
	req.Header.Set("OAuth-Client-Attestation-PoP", pop)
	return nil
}

// ServerSideAttestation implements ClientAttestationProvider by calling the
// WIA service internally. The engine holds the instance key (via PoPSigner)
// and generates both the WIA (via the service) and fresh PoPs as needed.
//
// This is the primary implementation for backend-managed wallet instances.
type ServerSideAttestation struct {
	WIA    string    // cached WIA JWT (refreshed on expiry)
	Signer PoPSigner // the wallet instance signer (bound as cnf in WIA)
	ID     string    // client_id = JWK Thumbprint of the signing key
}

func (s *ServerSideAttestation) Available() bool {
	return s != nil && s.WIA != "" && s.Signer != nil
}

func (s *ServerSideAttestation) ClientID() string {
	return s.ID
}

func (s *ServerSideAttestation) SetHeaders(ctx context.Context, req *http.Request, audience string) error {
	pop, err := createAttestationPoP(s.Signer, s.ID, audience)
	if err != nil {
		return fmt.Errorf("failed to create attestation PoP: %w", err)
	}
	req.Header.Set("OAuth-Client-Attestation", s.WIA)
	req.Header.Set("OAuth-Client-Attestation-PoP", pop)
	return nil
}

// createAttestationPoP creates an OAuth-Client-Attestation-PoP JWT per
// draft-ietf-oauth-attestation-based-client-auth-04 §5.2.
//
// The PoP proves possession of the key bound in the WIA's cnf claim.
// It is short-lived and audience-bound to the target authorization server.
// The signer abstracts key access for WSCA compatibility.
func createAttestationPoP(signer PoPSigner, clientID, audience string) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    clientID,
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        uuid.New().String(),
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "oauth-client-attestation-pop+jwt"

	// Include JWK in header (required by spec §5.2 — proves which key signed the PoP)
	jwk, err := ecPublicKeyJWK(signer.PublicKey())
	if err != nil {
		return "", fmt.Errorf("failed to serialize public key: %w", err)
	}
	tok.Header["jwk"] = jwk

	// Delegate signing to the PoPSigner — allows WSCA-backed implementations
	return signer.SignJWT(tok)
}

// computeJWKThumbprint computes the RFC 7638 JWK Thumbprint for a P-256 public key.
// Returns the base64url-encoded SHA-256 hash of the canonical JWK representation.
func computeJWKThumbprint(pub *ecdsa.PublicKey) (string, error) {
	jwk, err := ecPublicKeyJWK(pub)
	if err != nil {
		return "", err
	}
	// RFC 7638 requires lexicographically sorted members for EC keys: crv, kty, x, y
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`,
		jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	hash := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// WIAGenerator is the interface for internal WIA generation (server-side model).
// Implemented by the WIA service to allow the engine to obtain attestations
// without going through the HTTP challenge/response flow.
type WIAGenerator interface {
	// GenerateForKey produces a WIA JWT binding the given public key.
	// The implementation handles the challenge/PoP flow internally.
	GenerateForKey(ctx context.Context, pub *ecdsa.PublicKey) (string, error)
}

// NewServerSideAttestation creates a ClientAttestationProvider that generates
// WIA on demand using the given WIAGenerator and signer.
// This is transport-independent: works for both WebSocket and WMP flows.
// The signer can be backed by an in-memory key (NewECDSAPoPSigner) or a
// WSCA-managed key (future: siros-wscd-manager Signer interface).
func NewServerSideAttestation(ctx context.Context, gen WIAGenerator, signer PoPSigner) (*ServerSideAttestation, error) {
	// Generate WIA binding the signer's public key
	wia, err := gen.GenerateForKey(ctx, signer.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to generate WIA: %w", err)
	}
	thumbprint, err := computeJWKThumbprint(signer.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to compute JWK thumbprint: %w", err)
	}
	return &ServerSideAttestation{
		WIA:    wia,
		Signer: signer,
		ID:     thumbprint,
	}, nil
}
