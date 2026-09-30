package domain

import "time"

// KeyAttestationRecord is durable, per-key evidence that a specific
// credential-issuance key was verified as FIDO2/CTAP2 hardware-backed at
// the moment it was created (see FIDO2AttestationService).
//
// This is keyed by the credential key's own JWK Thumbprint (RFC 7638), not
// by wallet instance — a wallet instance's identity key and its
// credential-issuance keys are separate keys, not guaranteed to share a
// WSCD plugin, and a single instance-level flag would incorrectly apply
// one key's evidence to unrelated keys generated later (or via a
// different plugin). WalletInstanceID/TenantID are carried for
// auditing/scoping only, never as the lookup key. No expiry: a credential
// key's hardware backing doesn't change after creation, unlike a Wallet
// Instance Attestation's per-session freshness.
type KeyAttestationRecord struct {
	// KeyThumbprint is the RFC 7638 JWK Thumbprint of the attested
	// credential key. Primary key.
	KeyThumbprint string `json:"key_thumbprint" bson:"_id"`

	// WalletInstanceID is the wallet instance this key was generated for,
	// for auditing/scoping only.
	WalletInstanceID string `json:"wallet_instance_id" bson:"wallet_instance_id"`

	// TenantID scopes this record to a specific tenant.
	TenantID TenantID `json:"tenant_id" bson:"tenant_id"`

	// AAGUID is the FIDO2 authenticator model's AAGUID, as verified against
	// go-trust's fidomds3 registry.
	AAGUID string `json:"aaguid" bson:"aaguid"`

	// VerifiedAt is when this key's attestation was verified.
	VerifiedAt time.Time `json:"verified_at" bson:"verified_at"`

	// CreatedAt is when this record was first stored.
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
}
