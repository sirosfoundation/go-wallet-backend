package native

import (
	"context"
	"errors"
	"sync"
)

// Common errors
var (
	ErrNotConfigured         = errors.New("component not configured")
	ErrNotAuthenticated      = errors.New("not authenticated")
	ErrKeystoreLocked        = errors.New("keystore is locked")
	ErrStreamingNotSupported = errors.New("streaming not supported")
)

// Client is the main entry point for the native SDK.
// It coordinates between the backend, authenticator, and keystore.
type Client struct {
	config *Config

	mu       sync.RWMutex
	backend  BackendConnection
	auth     AuthProvider
	keystore KeystoreManager

	// Session state
	token       string
	userID      string
	displayName string
}

// NewClient creates a new SDK client with the given configuration.
func NewClient(config *Config) *Client {
	if config == nil {
		config = &Config{}
	}
	return &Client{
		config: config,
	}
}

// SetBackendConnection sets the backend connection implementation.
func (c *Client) SetBackendConnection(conn BackendConnection) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backend = conn
}

// SetAuthProvider sets the authentication provider implementation.
func (c *Client) SetAuthProvider(provider AuthProvider) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.auth = provider
}

// SetKeystore sets the keystore manager implementation.
func (c *Client) SetKeystore(manager KeystoreManager) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keystore = manager
}

// Config returns the client configuration.
func (c *Client) Config() *Config {
	return c.config
}

// Backend returns the backend connection.
func (c *Client) Backend() BackendConnection {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.backend
}

// Auth returns the auth provider.
func (c *Client) Auth() AuthProvider {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.auth
}

// Keystore returns the keystore manager.
func (c *Client) Keystore() KeystoreManager {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keystore
}

// IsAuthenticated returns true if the client has a valid session.
func (c *Client) IsAuthenticated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token != ""
}

// SetSession sets the current session state.
func (c *Client) SetSession(token, userID, displayName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
	c.userID = userID
	c.displayName = displayName
}

// GetSession returns the current session state.
func (c *Client) GetSession() (token, userID, displayName string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token, c.userID, c.displayName
}

// ClearSession clears the current session.
func (c *Client) ClearSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = ""
	c.userID = ""
	c.displayName = ""
}

// Status checks the backend status.
func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	c.mu.RLock()
	backend := c.backend
	c.mu.RUnlock()

	if backend == nil {
		return nil, ErrNotConfigured
	}
	return backend.Status(ctx)
}

// Register performs a full registration flow.
func (c *Client) Register(ctx context.Context, displayName string) (*AuthResult, error) {
	c.mu.RLock()
	backend := c.backend
	auth := c.auth
	c.mu.RUnlock()

	if backend == nil || auth == nil {
		return nil, ErrNotConfigured
	}

	// Start registration
	challenge, err := backend.StartRegistration(ctx, displayName)
	if err != nil {
		return nil, err
	}

	// Create credential
	regResult, err := auth.Register(ctx, &RegisterOptions{
		Challenge:       challenge.Challenge,
		RPID:            challenge.RPID,
		RPName:          challenge.RPName,
		UserID:          challenge.UserID,
		UserName:        challenge.UserName,
		UserDisplayName: displayName,
		PRFEnabled:      true,
	})
	if err != nil {
		return nil, err
	}

	// Complete registration
	result, err := backend.FinishRegistration(ctx, &RegistrationResponse{
		ChallengeID:       challenge.ChallengeID,
		CredentialID:      regResult.CredentialID,
		AttestationObject: regResult.AttestationObject,
		ClientDataJSON:    regResult.ClientDataJSON,
	})
	if err != nil {
		return nil, err
	}

	// Store session
	c.SetSession(result.Token, result.UserID, result.DisplayName)

	return result, nil
}

// Login performs a full login flow.
func (c *Client) Login(ctx context.Context) (*AuthResult, error) {
	c.mu.RLock()
	backend := c.backend
	auth := c.auth
	c.mu.RUnlock()

	if backend == nil || auth == nil {
		return nil, ErrNotConfigured
	}

	// Start login
	challenge, err := backend.StartLogin(ctx)
	if err != nil {
		return nil, err
	}

	// Authenticate
	authResult, err := auth.Authenticate(ctx, &AuthenticateOptions{
		Challenge:        challenge.Challenge,
		RPID:             challenge.RPID,
		AllowCredentials: challenge.AllowCredentials,
		UserVerification: challenge.UserVerification,
	})
	if err != nil {
		return nil, err
	}

	// Complete login
	result, err := backend.FinishLogin(ctx, &LoginResponse{
		ChallengeID:       challenge.ChallengeID,
		CredentialID:      authResult.CredentialID,
		AuthenticatorData: authResult.AuthenticatorData,
		Signature:         authResult.Signature,
		UserHandle:        authResult.UserHandle,
		ClientDataJSON:    authResult.ClientDataJSON,
	})
	if err != nil {
		return nil, err
	}

	// Store session
	c.SetSession(result.Token, result.UserID, result.DisplayName)

	return result, nil
}

// GetCredentials retrieves all stored credentials.
func (c *Client) GetCredentials(ctx context.Context) ([]Credential, error) {
	c.mu.RLock()
	backend := c.backend
	c.mu.RUnlock()

	if backend == nil {
		return nil, ErrNotConfigured
	}

	if !c.IsAuthenticated() {
		return nil, ErrNotAuthenticated
	}

	return backend.GetCredentials(ctx)
}

// UnlockKeystore unlocks the keystore using FIDO2 PRF.
func (c *Client) UnlockKeystore(ctx context.Context, credentialID, salt1, salt2 []byte) error {
	c.mu.RLock()
	backend := c.backend
	auth := c.auth
	keystore := c.keystore
	c.mu.RUnlock()

	if backend == nil || auth == nil || keystore == nil {
		return ErrNotConfigured
	}

	// Get encrypted data from backend
	accountInfo, err := backend.GetAccountInfo(ctx)
	if err != nil {
		return err
	}

	// Derive key using PRF
	prfOutput, err := auth.GetPRFOutput(ctx, credentialID, salt1, salt2)
	if err != nil {
		return err
	}

	// Unlock keystore
	return keystore.Unlock(ctx, credentialID, prfOutput.First, accountInfo.EncryptedPrivateData)
}

// LockKeystore locks the keystore.
func (c *Client) LockKeystore() {
	c.mu.RLock()
	keystore := c.keystore
	c.mu.RUnlock()

	if keystore != nil {
		keystore.Lock()
	}
}

// IsKeystoreLocked returns true if the keystore is locked.
func (c *Client) IsKeystoreLocked() bool {
	c.mu.RLock()
	keystore := c.keystore
	c.mu.RUnlock()

	if keystore == nil {
		return true
	}
	return keystore.IsLocked()
}
