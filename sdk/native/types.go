package native

// Config holds configuration for the native SDK client.
type Config struct {
	// BackendURL is the base URL of the wallet backend.
	BackendURL string

	// Platform identifies the client platform (e.g., "cli", "mobile", "web").
	Platform string

	// TenantID is the tenant identifier for multi-tenant deployments.
	TenantID string

	// Debug enables debug logging.
	Debug bool
}

// StatusResponse contains backend status information.
type StatusResponse struct {
	// Status is the service status (e.g., "OK", "DEGRADED").
	Status string

	// Service is the service name.
	Service string

	// Version is the service version.
	Version string
}

// RegistrationChallenge contains the data needed to register a new credential.
type RegistrationChallenge struct {
	// ChallengeID is the server-side challenge identifier.
	ChallengeID string

	// Challenge is the cryptographic challenge to sign.
	Challenge []byte

	// RPID is the relying party identifier (domain).
	RPID string

	// RPName is the human-readable relying party name.
	RPName string

	// UserID is the user's unique identifier.
	UserID []byte

	// UserName is the user's account name.
	UserName string

	// Algorithms is the list of acceptable signing algorithms (COSE).
	Algorithms []int
}

// RegistrationResponse contains the attestation data from registration.
type RegistrationResponse struct {
	// ChallengeID is the challenge being responded to.
	ChallengeID string

	// CredentialID is the new credential's identifier.
	CredentialID []byte

	// AttestationObject contains the attestation statement.
	AttestationObject []byte

	// ClientDataJSON is the signed client data.
	ClientDataJSON []byte
}

// AuthResult contains the result of a successful authentication.
type AuthResult struct {
	// UserID is the authenticated user's identifier.
	UserID string

	// Token is the session/access token.
	Token string

	// DisplayName is the user's display name.
	DisplayName string

	// RpID is the relying party ID used for authentication.
	RpID string
}

// LoginChallenge contains the data needed to authenticate.
type LoginChallenge struct {
	// ChallengeID is the server-side challenge identifier.
	ChallengeID string

	// Challenge is the cryptographic challenge to sign.
	Challenge []byte

	// RPID is the relying party identifier.
	RPID string

	// UserVerification specifies the user verification requirement.
	UserVerification string

	// AllowCredentials is the list of allowed credential IDs.
	AllowCredentials [][]byte
}

// LoginResponse contains the assertion data from authentication.
type LoginResponse struct {
	// ChallengeID is the challenge being responded to.
	ChallengeID string

	// CredentialID is the credential used.
	CredentialID []byte

	// AuthenticatorData contains the authenticator state.
	AuthenticatorData []byte

	// Signature is the assertion signature.
	Signature []byte

	// UserHandle identifies the user.
	UserHandle []byte

	// ClientDataJSON is the signed client data.
	ClientDataJSON []byte
}

// Credential represents a stored verifiable credential.
type Credential struct {
	// ID is the unique credential identifier.
	ID string

	// Format is the credential format (e.g., "jwt_vc", "ldp_vc").
	Format string

	// Credential is the raw credential data.
	Credential interface{}

	// Metadata contains additional credential metadata.
	Metadata map[string]interface{}
}

// AccountInfo contains user account information.
type AccountInfo struct {
	// UserID is the user's unique identifier.
	UserID string

	// DisplayName is the user's display name.
	DisplayName string

	// EncryptedPrivateData is the encrypted keystore data.
	// This may be []byte, base64-encoded string, or structured data.
	EncryptedPrivateData interface{}
}

// RegisterOptions contains options for credential registration.
type RegisterOptions struct {
	// Challenge is the cryptographic challenge.
	Challenge []byte

	// RPID is the relying party identifier.
	RPID string

	// RPName is the relying party name.
	RPName string

	// UserID is the user's identifier.
	UserID []byte

	// UserName is the user's account name.
	UserName string

	// UserDisplayName is the user's display name.
	UserDisplayName string

	// PRFEnabled requests PRF extension support.
	PRFEnabled bool
}

// RegisterResult contains the result of credential registration.
type RegisterResult struct {
	// CredentialID is the new credential's identifier.
	CredentialID []byte

	// PublicKey is the credential's public key (COSE format).
	PublicKey []byte

	// AttestationObject is the attestation statement.
	AttestationObject []byte

	// ClientDataJSON is the client data.
	ClientDataJSON []byte

	// PRFSupported indicates if PRF extension was enabled.
	PRFSupported bool
}

// AuthenticateOptions contains options for authentication.
type AuthenticateOptions struct {
	// Challenge is the cryptographic challenge.
	Challenge []byte

	// RPID is the relying party identifier.
	RPID string

	// AllowCredentials lists acceptable credential IDs.
	AllowCredentials [][]byte

	// UserVerification specifies verification requirements.
	UserVerification string

	// PRFInputs provides salt values for PRF evaluation.
	PRFInputs *PRFInputs
}

// PRFInputs contains salt values for PRF extension.
type PRFInputs struct {
	// Salt1 is the first salt value (required).
	Salt1 []byte

	// Salt2 is the second salt value (optional).
	Salt2 []byte
}

// AuthenticateResult contains the result of authentication.
type AuthenticateResult struct {
	// CredentialID is the credential used.
	CredentialID []byte

	// AuthenticatorData is the authenticator state.
	AuthenticatorData []byte

	// Signature is the assertion signature.
	Signature []byte

	// UserHandle identifies the user.
	UserHandle []byte

	// ClientDataJSON is the client data.
	ClientDataJSON []byte

	// PRFOutput contains PRF evaluation results if requested.
	PRFOutput *PRFOutput
}

// PRFOutput contains the result of PRF evaluation.
type PRFOutput struct {
	// First is the result of evaluating with Salt1.
	First []byte

	// Second is the result of evaluating with Salt2 (if provided).
	Second []byte
}
