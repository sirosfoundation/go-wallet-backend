// Package native provides a native Go SDK for wallet operations.
// It defines interfaces that can be implemented by different backends
// (HTTP, gRPC, in-process) and authentication providers (FIDO2, software).
package native

import (
	"context"
)

// BackendConnection defines the interface for backend communication.
// This can be implemented over HTTP REST, gRPC, or in-process calls.
type BackendConnection interface {
	// Status checks if the backend is reachable and returns service info.
	Status(ctx context.Context) (*StatusResponse, error)

	// StartRegistration begins a new user registration flow.
	StartRegistration(ctx context.Context, displayName string) (*RegistrationChallenge, error)

	// FinishRegistration completes registration with the attestation response.
	FinishRegistration(ctx context.Context, req *RegistrationResponse) (*AuthResult, error)

	// StartLogin begins a login flow for existing users.
	StartLogin(ctx context.Context) (*LoginChallenge, error)

	// FinishLogin completes login with the assertion response.
	FinishLogin(ctx context.Context, req *LoginResponse) (*AuthResult, error)

	// GetCredentials retrieves all stored verifiable credentials.
	GetCredentials(ctx context.Context) ([]Credential, error)

	// GetAccountInfo retrieves account information including encrypted private data.
	GetAccountInfo(ctx context.Context) (*AccountInfo, error)

	// ConnectStream opens a bidirectional stream for signing operations.
	// Returns ErrStreamingNotSupported if the backend doesn't support streaming.
	ConnectStream(ctx context.Context) (SigningStream, error)
}

// AuthProvider defines the interface for authentication operations.
// This is typically implemented using FIDO2/WebAuthn hardware keys
// or software-based authenticators for testing.
type AuthProvider interface {
	// Register creates a new credential using the authenticator.
	Register(ctx context.Context, opts *RegisterOptions) (*RegisterResult, error)

	// Authenticate performs an assertion using an existing credential.
	Authenticate(ctx context.Context, opts *AuthenticateOptions) (*AuthenticateResult, error)

	// GetPRFOutput evaluates the PRF extension for key derivation.
	// This is used to derive encryption keys for the keystore.
	GetPRFOutput(ctx context.Context, credentialID []byte, salt1, salt2 []byte) (*PRFOutput, error)
}

// KeystoreManager defines the interface for keystore operations.
// The keystore holds private keys encrypted with a PRF-derived key.
type KeystoreManager interface {
	// IsLocked returns true if the keystore is locked.
	IsLocked() bool

	// Unlock decrypts the keystore using the PRF output.
	// encryptedData may be []byte, base64 string, or structured data.
	Unlock(ctx context.Context, credentialID, prfOutput []byte, encryptedData interface{}) error

	// Lock re-locks the keystore, clearing private keys from memory.
	Lock()

	// Sign signs data using the specified key.
	Sign(ctx context.Context, keyID string, payload []byte, algorithm string) ([]byte, error)

	// GenerateProof generates an OID4VCI proof JWT for credential issuance.
	GenerateProof(ctx context.Context, audience, nonce string) (string, error)

	// SignPresentation creates a Verifiable Presentation JWT.
	SignPresentation(ctx context.Context, nonce, audience string, credentials []interface{}) (string, error)
}

// SigningStream provides bidirectional streaming for signing operations.
// This is used for high-performance signing over gRPC.
type SigningStream interface {
	// Send sends a signing request.
	Send(req *SignRequest) error

	// Recv receives a signing response.
	Recv() (*SignResponse, error)

	// Close closes the stream.
	Close() error
}

// SignRequest represents a request to sign data.
type SignRequest struct {
	// RequestID is a unique identifier for correlating responses.
	RequestID string

	// KeyID identifies which key to use for signing.
	KeyID string

	// Payload is the data to sign.
	Payload []byte

	// Algorithm specifies the signing algorithm (e.g., "ES256").
	Algorithm string
}

// SignResponse represents a signing response.
type SignResponse struct {
	// RequestID correlates this response to a request.
	RequestID string

	// Signature is the computed signature.
	Signature []byte

	// Error contains any error message.
	Error string
}
