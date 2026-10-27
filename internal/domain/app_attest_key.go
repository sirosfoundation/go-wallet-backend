package domain

import "time"

// AppAttestEnvironment is the Apple App Attest environment a key was attested
// in. It is the environment the BACKEND is configured for when it verified the
// attestation (and so the AAGUID the attestation carried), never a value the
// client reports.
type AppAttestEnvironment string

const (
	// AppAttestProduction is the production environment (AAGUID
	// "appattest" followed by seven zero bytes).
	AppAttestProduction AppAttestEnvironment = "production"
	// AppAttestDevelopment is the development (sandbox) environment (AAGUID
	// "appattestdevelop"). Keys attested there are test keys: they never
	// yield a verified key home.
	AppAttestDevelopment AppAttestEnvironment = "development"
)

// AppAttestKeyStatus is the lifecycle state of a stored App Attest key.
type AppAttestKeyStatus string

const (
	AppAttestKeyActive  AppAttestKeyStatus = "active"
	AppAttestKeyRevoked AppAttestKeyStatus = "revoked"
)

// AppAttestKeyRecord is the durable record of one attested Apple App Attest
// key. App Attest keys are assertion-only: they cannot sign a JWS, so the
// only later proof of control is an assertion, verified against the public key
// stored here. Apple issues the attestation object once per key, so this is
// the only place the key can ever come from again.
//
// It is stored only after the attestation object was verified in full (chain,
// nonce, keyId, credentialId, counter 0, AAGUID, rpIdHash).
type AppAttestKeyRecord struct {
	// KeyID is base64 (standard, padded) of SHA-256 over the X9.62 uncompressed
	// public key, the identifier Apple defines. Primary key.
	KeyID string `json:"key_id" bson:"_id"`

	// PublicKey is the credCert public key as an X9.62 uncompressed point
	// (65 bytes for P-256). Assertions are verified with it.
	PublicKey []byte `json:"public_key" bson:"public_key"`

	// Counter is the highest assertion counter accepted so far; 0 right
	// after attestation. Updated only through the store's atomic
	// AdvanceCounter, strictly increasing.
	Counter uint32 `json:"counter" bson:"counter"`

	// Environment is the App Attest environment the attestation was
	// verified in.
	Environment AppAttestEnvironment `json:"environment" bson:"environment"`

	// AppID is the App ID (TeamID.BundleID) the rpIdHash matched.
	AppID string `json:"app_id" bson:"app_id"`

	// ChainVerified is true when the attestation certificate chain verified
	// to the configured App Attest root. False only when a development
	// deployment accepted an unverifiable chain; such a key never yields a
	// verified home.
	ChainVerified bool `json:"chain_verified" bson:"chain_verified"`

	// TenantID, UserID and WalletInstanceID bind the key to the context that
	// attested it. UserID is nil when the caller was not user-bound.
	TenantID         TenantID `json:"tenant_id" bson:"tenant_id"`
	UserID           *UserID  `json:"user_id,omitempty" bson:"user_id,omitempty"`
	WalletInstanceID string   `json:"wallet_instance_id,omitempty" bson:"wallet_instance_id,omitempty"`

	// Status is active or revoked. Anything else (including empty) is not
	// active: a record is only usable when positively active.
	Status AppAttestKeyStatus `json:"status" bson:"status"`

	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

// IsActive reports whether the key may be used to verify assertions.
func (r *AppAttestKeyRecord) IsActive() bool { return r.Status == AppAttestKeyActive }

// VerifiedHomeEligible reports whether assertions of this key may yield a
// verified key home: a production key whose attestation chain verified.
func (r *AppAttestKeyRecord) VerifiedHomeEligible() bool {
	return r.Environment == AppAttestProduction && r.ChainVerified
}

// BelongsTo reports whether the key was attested in the given tenant and user
// context. A key attested for a user is only usable by that user; a key
// attested with no user is only usable with no user.
func (r *AppAttestKeyRecord) BelongsTo(tenant TenantID, user *UserID) bool {
	if r.TenantID != tenant {
		return false
	}
	switch {
	case r.UserID == nil && user == nil:
		return true
	case r.UserID == nil || user == nil:
		return false
	}
	return *r.UserID == *user
}

// Clone returns a copy sharing no mutable state with r.
func (r *AppAttestKeyRecord) Clone() *AppAttestKeyRecord {
	c := *r
	c.PublicKey = append([]byte(nil), r.PublicKey...)
	if r.UserID != nil {
		u := *r.UserID
		c.UserID = &u
	}
	return &c
}
