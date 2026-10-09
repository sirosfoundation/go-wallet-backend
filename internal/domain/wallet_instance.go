package domain

import (
	"errors"
	"time"
)

// InstanceStatus represents the lifecycle state of a wallet instance.
type InstanceStatus string

const (
	InstanceStatusActive  InstanceStatus = "active"
	InstanceStatusRevoked InstanceStatus = "revoked"

	// InstanceStatusLegacySuspended is the old reversible "suspended" state
	// still carried by older records. It means "blocked": not live, but may be
	// revoked.
	InstanceStatusLegacySuspended InstanceStatus = "suspended"
)

// IsLive reports whether an instance is live (passkey may log in, may obtain a
// WIA, keeps the wallet from being deactivated). Only "active" is live, so a
// legacy suspended record never restores a login.
func (s InstanceStatus) IsLive() bool { return s == InstanceStatusActive }

// IsKnownNonLive reports whether s positively means "cannot be used" (revoked or
// legacy suspended). Unknown values are neither live nor known non-live, so
// data-destroying callers use this, not !IsLive, and fail closed.
func (s InstanceStatus) IsKnownNonLive() bool {
	return s == InstanceStatusRevoked || s == InstanceStatusLegacySuspended
}

// ErrInvalidStatusTransition is returned when a status transition is not allowed.
var ErrInvalidStatusTransition = errors.New("invalid status transition")

// ValidateStatusTransition checks whether transitioning from current to target
// is a legal state change. Revocation is the only one and it is terminal; a
// legacy suspended record may be revoked. The ARF has no reversible Wallet Unit
// state ("can only be revoked"), hence none here.
func ValidateStatusTransition(current, target InstanceStatus) error {
	if current == target {
		return nil // no-op
	}
	if target == InstanceStatusRevoked && current.IsRevocable() {
		return nil
	}
	return ErrInvalidStatusTransition
}

// RevocableStatuses lists the statuses an instance may be revoked from: active
// and legacy suspended. Anything else, an unknown value included, fails closed,
// since revoking it would let the cascade erase data. Storage filters are built
// from this list.
func RevocableStatuses() []InstanceStatus {
	return []InstanceStatus{InstanceStatusActive, InstanceStatusLegacySuspended}
}

// IsRevocable reports whether s is a legal source state for revocation.
func (s InstanceStatus) IsRevocable() bool {
	for _, r := range RevocableStatuses() {
		if s == r {
			return true
		}
	}
	return false
}

// WSCDType identifies the type of WSCD backing this wallet instance.
type WSCDType string

const (
	// WSCDTypeWebCrypto is a browser-based Web Crypto key store.
	// The passkey PRF output derives the encryption key that protects
	// the credential vault in local storage. The signing key lives in
	// non-extractable CryptoKey objects.
	WSCDTypeWebCrypto WSCDType = "web_crypto"

	// WSCDTypeRemote is a remote HSM-backed WSCD accessed via R2PS.
	// Keys are managed in the PKCS#11 slot identified by client_id.
	WSCDTypeRemote WSCDType = "remote"

	// WSCDTypeNativeIOS uses iOS Secure Enclave via App Attest.
	WSCDTypeNativeIOS WSCDType = "native_ios"

	// WSCDTypeNativeAndroid uses Android StrongBox/TEE via Play Integrity.
	WSCDTypeNativeAndroid WSCDType = "native_android"

	// WSCDTypeFIDO2Hardware uses a FIDO2/CTAP2 hardware security key (e.g.
	// a YubiKey) via the previewSign rawSign plugin.
	WSCDTypeFIDO2Hardware WSCDType = "fido2_hardware"
)

// WalletInstance represents a registered wallet instance identified by
// the JWK Thumbprint (RFC 7638) of its instance key.
//
// # Relationship to Passkeys
//
// In the web frontend, there is a 1:1 mapping between a passkey and a wallet
// instance. The passkey's PRF extension output is used to derive an AES-GCM key
// that encrypts the wallet vault (credentials + signing keys). When the backend
// revokes an instance, the frontend must treat the corresponding passkey
// as unusable — new WIA requests will be rejected.
//
// In native SDKs (iOS/Android), the hardware attestation key serves the same role
// as the passkey — one attestation key = one wallet instance.
//
// For remote WSCA/WSCD (R2PS), the client_id in the R2PS session identifies the
// instance. Keys are HSM-resident and the R2PS admin API manages their lifecycle.
type WalletInstance struct {
	// ID is the JWK Thumbprint (base64url SHA-256) of the instance key.
	// This is the canonical wallet instance identifier across all WSCD types.
	ID string `json:"id" bson:"_id"`

	// TenantID scopes this instance to a specific tenant.
	TenantID TenantID `json:"tenant_id" bson:"tenant_id"`

	// UserID is the user who owns this instance (if known).
	UserID *UserID `json:"user_id,omitempty" bson:"user_id,omitempty"`

	// Status is the lifecycle state (active, revoked, or legacy "suspended");
	// use IsLive.
	Status InstanceStatus `json:"status" bson:"status"`

	// WSCDType identifies the type of WSCD backing this instance.
	WSCDType WSCDType `json:"wscd_type" bson:"wscd_type"`

	// CredentialID is the WebAuthn credential ID (base64url) of the passkey
	// that created this instance; it keys the per-instance login gate
	// (WebAuthnService.checkWalletLifecycle). It must be one of the caller's own
	// passkeys in the tenant (else CREDENTIAL_NOT_OWNED) and the first link
	// wins; binding it to the authenticating passkey is tracked in
	// go-wallet-backend#333.
	CredentialID string `json:"credential_id,omitempty" bson:"credential_id,omitempty"`

	// R2PSClientID is the client_id used in R2PS sessions for this instance.
	// Only set for WSCDTypeRemote instances.
	R2PSClientID string `json:"r2ps_client_id,omitempty" bson:"r2ps_client_id,omitempty"`

	// DeviceInfo contains optional device metadata reported at attestation time.
	DeviceInfo *DeviceInfo `json:"device_info,omitempty" bson:"device_info,omitempty"`

	// AttestationSource identifies how this instance was attested.
	// Values: "backend_attested", "ios_app_attest", "android_play_integrity"
	AttestationSource string `json:"attestation_source" bson:"attestation_source"`

	// SecurityProperties captures the claimed security level (ISO 18045 AVA scale).
	SecurityProperties *SecurityProperties `json:"security_properties,omitempty" bson:"security_properties,omitempty"`

	// LastAttestedAt is the time of the most recent WIA generation.
	LastAttestedAt time.Time `json:"last_attested_at" bson:"last_attested_at"`

	// AttestationCount is the total number of WIAs issued to this instance.
	AttestationCount int64 `json:"attestation_count" bson:"attestation_count"`

	// Generation identifies this exact record: random, assigned at insert, never
	// changed. A deleted and re-attested record has the same id and tenant, so
	// only the generation tells them apart. "" on records written before the
	// field existed.
	Generation string `json:"-" bson:"generation,omitempty"`

	// CreatedAt is when this instance was first seen (first WIA issuance).
	CreatedAt time.Time `json:"created_at" bson:"created_at"`

	// UpdatedAt tracks the last modification time.
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`

	// DeactivatedAt is set when the instance is revoked.
	DeactivatedAt *time.Time `json:"deactivated_at,omitempty" bson:"deactivated_at,omitempty"`

	// DeactivationReason provides context for the revocation.
	DeactivationReason string `json:"deactivation_reason,omitempty" bson:"deactivation_reason,omitempty"`
}

// DeviceInfo contains optional device metadata.
type DeviceInfo struct {
	Platform string `json:"platform,omitempty" bson:"platform,omitempty"` // ios, android, web
	OS       string `json:"os,omitempty" bson:"os,omitempty"`
	Model    string `json:"model,omitempty" bson:"model,omitempty"`
	AppID    string `json:"app_id,omitempty" bson:"app_id,omitempty"`
}

// SecurityProperties captures the claimed security level of the instance's WSCD.
// Aligns with CS-04 §7.1.3 WalletSigner.securityProperties() in the frontend SDK.
type SecurityProperties struct {
	KeyStorage         []string `json:"key_storage" bson:"key_storage"`                         // ISO 18045 AVA_VAN levels
	UserAuthentication []string `json:"user_authentication" bson:"user_authentication"`         // Authentication methods
	Certification      string   `json:"certification,omitempty" bson:"certification,omitempty"` // Certification scheme URI
}

// InstanceBinding identifies the exact record a caller observed: owner (nil if
// unowned) and generation. Conditional store writes apply only while the stored
// record still matches.
type InstanceBinding struct {
	Owner      *UserID
	Generation string
}

// Binding returns the binding of the record as it was read.
func (w *WalletInstance) Binding() InstanceBinding {
	b := InstanceBinding{Generation: w.Generation}
	if w.UserID != nil {
		u := *w.UserID
		b.Owner = &u
	}
	return b
}

// Matches reports whether the record is the one the binding describes.
func (b InstanceBinding) Matches(w *WalletInstance) bool {
	if b.Generation != w.Generation {
		return false
	}
	if b.Owner == nil {
		return w.UserID == nil
	}
	return w.UserID != nil && *w.UserID == *b.Owner
}
