package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
)

// WalletType defines the type of wallet keystore
type WalletType string

const (
	WalletTypeDB     WalletType = "db"
	WalletTypeClient WalletType = "client"
)

// UserID represents a unique user identifier
type UserID struct {
	ID string `json:"id" bson:"id"`
}

// NewUserID creates a new user ID
func NewUserID() UserID {
	return UserID{ID: uuid.New().String()}
}

// UserIDFromString creates a UserID from a string
func UserIDFromString(id string) UserID {
	return UserID{ID: id}
}

// String returns the string representation
func (u UserID) String() string {
	return u.ID
}

// AsUserHandle returns the ID as bytes for WebAuthn
func (u UserID) AsUserHandle() []byte {
	return []byte(u.ID)
}

// UserIDFromUserHandle creates a UserID from WebAuthn user handle
func UserIDFromUserHandle(handle []byte) UserID {
	return UserID{ID: string(handle)}
}

// EnterpriseIdentity stores a bound enterprise IdP identity
type EnterpriseIdentity struct {
	// TenantID is the tenant this binding belongs to
	TenantID TenantID `json:"tenant_id" bson:"tenant_id"`

	// Issuer is the OIDC issuer URL
	Issuer string `json:"issuer" bson:"issuer"`

	// Subject is the unique identifier from the IdP (sub claim)
	Subject string `json:"subject" bson:"subject"`

	// Email is the user's email from the IdP (optional)
	Email string `json:"email,omitempty" bson:"email,omitempty"`

	// BindingType indicates when this binding was created: "registration" or "login"
	BindingType string `json:"binding_type" bson:"binding_type"`

	// BoundAt is when this identity was bound to the user
	BoundAt time.Time `json:"bound_at" bson:"bound_at"`
}

// MatchesOIDCResult checks if this identity matches an OIDC validation result
func (e *EnterpriseIdentity) MatchesOIDCResult(issuer, subject string) bool {
	return e.Issuer == issuer && e.Subject == subject
}

// User represents a wallet user
type User struct {
	UUID                UserID               `json:"uuid" bson:"_id"`
	Username            *string              `json:"username,omitempty" bson:"username,omitempty"`
	DisplayName         *string              `json:"display_name,omitempty" bson:"display_name,omitempty"`
	DID                 string               `json:"did" bson:"did"`
	PasswordHash        *string              `json:"-" bson:"password_hash,omitempty"`
	PrivateData         []byte               `json:"private_data,omitempty" bson:"private_data,omitempty"`
	Keys                []byte               `json:"keys,omitempty" bson:"keys,omitempty"`
	WalletType          WalletType           `json:"wallet_type" bson:"wallet_type"`
	PrivateDataETag     string               `json:"private_data_etag,omitempty" bson:"private_data_etag,omitempty"`
	WebauthnCredentials []WebauthnCredential `json:"webauthn_credentials,omitempty" bson:"webauthn_credentials,omitempty"`

	// Enterprise identity bindings (from OIDC gates with bind_identity=true)
	EnterpriseIdentities []EnterpriseIdentity `json:"enterprise_identities,omitempty" bson:"enterprise_identities,omitempty"`

	// User settings
	OpenIDRefreshTokenMaxAge int64 `json:"openid_refresh_token_max_age,omitempty" bson:"openid_refresh_token_max_age,omitempty"`

	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

// GetEnterpriseIdentityForTenant returns the enterprise identity for the given tenant, if any
func (u *User) GetEnterpriseIdentityForTenant(tenantID TenantID) *EnterpriseIdentity {
	for i := range u.EnterpriseIdentities {
		if u.EnterpriseIdentities[i].TenantID == tenantID {
			return &u.EnterpriseIdentities[i]
		}
	}
	return nil
}

// HasEnterpriseIdentityForTenant returns true if the user has a bound identity for the tenant
func (u *User) HasEnterpriseIdentityForTenant(tenantID TenantID) bool {
	return u.GetEnterpriseIdentityForTenant(tenantID) != nil
}

// AddEnterpriseIdentity adds or updates an enterprise identity for a tenant
func (u *User) AddEnterpriseIdentity(identity EnterpriseIdentity) {
	// Check if already exists for this tenant
	for i := range u.EnterpriseIdentities {
		if u.EnterpriseIdentities[i].TenantID == identity.TenantID {
			// Update existing
			u.EnterpriseIdentities[i] = identity
			return
		}
	}
	// Add new
	u.EnterpriseIdentities = append(u.EnterpriseIdentities, identity)
}

// WebauthnCredential represents a WebAuthn credential
type WebauthnCredential struct {
	ID              string        `json:"id" bson:"id"`
	TenantID        TenantID      `json:"tenantId" bson:"tenant_id"`
	CredentialID    []byte        `json:"credentialId" bson:"credential_id"`
	PublicKey       []byte        `json:"public_key" bson:"public_key"`
	AttestationType string        `json:"attestation_type" bson:"attestation_type"`
	Transport       []string      `json:"transport" bson:"transport"`
	Flags           uint8         `json:"flags" bson:"flags"`
	Authenticator   Authenticator `json:"authenticator" bson:"authenticator"`
	Nickname        *string       `json:"nickname,omitempty" bson:"nickname,omitempty"`
	PRFCapable      bool          `json:"prfCapable" bson:"prf_capable"`
	CreatedAt       time.Time     `json:"createTime" bson:"created_at"`
	LastUseTime     *time.Time    `json:"lastUseTime,omitempty" bson:"last_use_time,omitempty"`
}

// Authenticator represents the authenticator data
type Authenticator struct {
	AAGUID       []byte `json:"aaguid" bson:"aaguid"`
	SignCount    uint32 `json:"sign_count" bson:"sign_count"`
	CloneWarning bool   `json:"clone_warning" bson:"clone_warning"`
	Attachment   string `json:"attachment" bson:"attachment"`
}

// ComputePrivateDataETag computes an ETag for the private data
func ComputePrivateDataETag(privateData []byte) string {
	hash := sha256.Sum256(privateData)
	return `"` + base64.StdEncoding.EncodeToString(hash[:]) + `"`
}

// UpdatePrivateData updates the private data and its ETag
func (u *User) UpdatePrivateData(data []byte) {
	u.PrivateData = data
	u.PrivateDataETag = ComputePrivateDataETag(data)
	u.UpdatedAt = time.Now()
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Username    *string    `json:"username,omitempty"`
	DisplayName string     `json:"display_name"`
	Password    *string    `json:"password,omitempty"`
	WalletType  WalletType `json:"wallet_type"`
	Keys        []byte     `json:"keys,omitempty"`
	PrivateData []byte     `json:"private_data,omitempty"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token       string `json:"token"`
	UserID      string `json:"user_id"`
	DisplayName string `json:"display_name"`
}
