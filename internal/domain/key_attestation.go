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

	// UV is the user-verified (UV) flag of the authenticator data of the
	// verified attestation: the authenticator itself reported that the user
	// was verified (PIN or biometric) when the key was created. Records
	// stored before this field existed read as false ("uv none").
	UV bool `json:"uv" bson:"uv"`

	// UserID is the authenticated user the evidence was verified for, set on
	// instance-key evidence (android_key, ...): a cached record is used only
	// for the tenant and user it was verified for. Empty on FIDO2 records.
	UserID string `json:"user_id,omitempty" bson:"user_id,omitempty"`

	// Kind is the family of evidence that produced this record. Records
	// stored before the field existed are FIDO2 records: Normalize applies
	// that default.
	Kind KeyEvidenceKind `json:"kind,omitempty" bson:"kind,omitempty"`

	// Home is where the verified evidence says the key lives. Empty only
	// on records stored before the field existed, which Normalize resolves
	// for FIDO2 records (a FIDO2 attestation verified against the FIDO MDS3
	// registry is a hardware authenticator: KeyHomeFIDO2Hardware).
	Home KeyHome `json:"home,omitempty" bson:"home,omitempty"`

	// SecurityLevel is the attestation security level the evidence reports
	// (for example software, trusted_environment, strongbox). Optional.
	SecurityLevel string `json:"security_level,omitempty" bson:"security_level,omitempty"`

	// VerifiedBootState is the verified boot state reported by the
	// evidence (for example verified, self_signed, unverified). Optional.
	VerifiedBootState string `json:"verified_boot_state,omitempty" bson:"verified_boot_state,omitempty"`

	// DeviceLocked is the bootloader lock state reported by the evidence,
	// nil when the evidence does not say.
	DeviceLocked *bool `json:"device_locked,omitempty" bson:"device_locked,omitempty"`

	// PatchLevel is the OS patch level reported by the evidence. Optional.
	PatchLevel string `json:"patch_level,omitempty" bson:"patch_level,omitempty"`

	// AppDigest is the digest of the application signing certificate(s)
	// reported by the evidence. Optional.
	AppDigest string `json:"app_digest,omitempty" bson:"app_digest,omitempty"`

	// AppPackages are the Android package names the evidence reported for the
	// application, sorted. Optional; kept so a narrowed package allowlist
	// applies to stored evidence.
	AppPackages []string `json:"app_packages,omitempty" bson:"app_packages,omitempty"`

	// TrustAnchorFingerprint is the SHA-256 fingerprint (hex) of the pinned
	// root the verified chain ended in, so evidence is withdrawn when that root
	// is no longer pinned. Records without it cannot be shown to have a pinned
	// root and are treated as unknown.
	TrustAnchorFingerprint string `json:"trust_anchor_fingerprint,omitempty" bson:"trust_anchor_fingerprint,omitempty"`

	// ChainFingerprint is the SHA-256 fingerprint of the evidence's
	// certificate chain leaf, for audit. Optional.
	ChainFingerprint string `json:"chain_fingerprint,omitempty" bson:"chain_fingerprint,omitempty"`

	// ChainNotAfter is the earliest NotAfter in the evidence's certificate
	// chain, zero when there is no chain.
	ChainNotAfter time.Time `json:"chain_not_after,omitempty" bson:"chain_not_after,omitempty"`

	// CertSerials are the serial numbers (lowercase hex, no leading zeros) of
	// the certificates of the verified chain, kept so the chain can be checked
	// against the revocation list again each time the record is used. Records
	// stored before the field existed have none: they cannot be re-checked
	// and so are treated as unknown, never as still good.
	CertSerials []string `json:"cert_serials,omitempty" bson:"cert_serials,omitempty"`

	// RevokedAt is when the evidence was retired: a re-check found it revoked,
	// or a fresh submission replaced it while it was no longer good (expired,
	// no longer qualifying). Zero while it stands. A retired record is kept
	// (never deleted) and is never evidence: readers treat the key as having
	// none.
	RevokedAt time.Time `json:"revoked_at,omitempty" bson:"revoked_at,omitempty"`

	// RevokedReason says why RevokedAt was set (a fixed enum, never client
	// text: status_list_revoked, chain_expired, legacy_no_serials or a
	// no-longer-qualifying reason).
	RevokedReason string `json:"revoked_reason,omitempty" bson:"revoked_reason,omitempty"`

	// VerifiedAt is when this key's attestation was verified.
	VerifiedAt time.Time `json:"verified_at" bson:"verified_at"`

	// CreatedAt is when this record was first stored.
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
}

// KeyEvidenceKind names the family of per-key evidence a record holds.
type KeyEvidenceKind string

const (
	// KeyEvidenceFIDO2 is a verified FIDO2/CTAP2 attestation object. It is
	// the default for records stored before Kind existed.
	KeyEvidenceFIDO2 KeyEvidenceKind = "fido2"

	// KeyEvidenceAndroidKey is a verified Android Key Attestation chain.
	KeyEvidenceAndroidKey KeyEvidenceKind = "android_key"

	// KeyEvidenceAppAttestAssertion is an App Attest assertion over the key.
	KeyEvidenceAppAttestAssertion KeyEvidenceKind = "app_attest_assertion"
)

// KeyHome says where verified evidence puts a key.
type KeyHome string

const (
	KeyHomeStrongBox KeyHome = "strongbox"
	KeyHomeTEE       KeyHome = "tee"
	// KeyHomeSecureEnclaveAsserted is a key an App Attest assertion ties to
	// an attested device: asserted, not attested, so it ranks below tee. It
	// does not prove Secure Enclave residency, so it maps to WSCD type unknown.
	KeyHomeSecureEnclaveAsserted KeyHome = "secure_enclave_asserted"
	KeyHomeFIDO2Hardware         KeyHome = "fido2_hw"
	KeyHomeHSM                   KeyHome = "hsm"
)

// rank orders homes by strength of the guarantee. Unknown or empty homes
// rank 0, so a record with no home never replaces one that has it.
func (h KeyHome) rank() int {
	switch h {
	case KeyHomeSecureEnclaveAsserted:
		return 1
	case KeyHomeTEE:
		return 2
	case KeyHomeStrongBox, KeyHomeFIDO2Hardware, KeyHomeHSM:
		return 3
	}
	return 0
}

// Clone returns a copy that shares no mutable state with r (DeviceLocked is a
// pointer). Stores clone on write and on read so a caller can never change
// stored evidence through a pointer it holds.
func (r *KeyAttestationRecord) Clone() *KeyAttestationRecord {
	c := *r
	if r.DeviceLocked != nil {
		v := *r.DeviceLocked
		c.DeviceLocked = &v
	}
	c.CertSerials = append([]string(nil), r.CertSerials...)
	if len(c.CertSerials) == 0 {
		c.CertSerials = nil
	}
	c.AppPackages = append([]string(nil), r.AppPackages...)
	if len(c.AppPackages) == 0 {
		c.AppPackages = nil
	}
	return &c
}

// Normalize applies the defaults that make a record stored before Kind and
// Home existed read as what it was: a FIDO2 record whose home is a hardware
// authenticator. Stores call it on every read and before every comparison.
func (r *KeyAttestationRecord) Normalize() {
	if r.Kind == "" {
		r.Kind = KeyEvidenceFIDO2
	}
	if r.Home == "" && r.Kind == KeyEvidenceFIDO2 {
		r.Home = KeyHomeFIDO2Hardware
	}
}

// Revoked reports whether a re-check found the evidence revoked.
func (r *KeyAttestationRecord) Revoked() bool { return !r.RevokedAt.IsZero() }

// Supersedes reports whether r may replace existing. A stored record is
// never overwritten by weaker or absent evidence: r must not rank lower by
// Home; at equal rank it must be the same Kind and must not lose the UV bit
// (a different kind of evidence at the same rank does not displace the
// first verified one). A nil existing is always superseded. Both records
// are compared in normalized form.
func (r *KeyAttestationRecord) Supersedes(existing *KeyAttestationRecord) bool {
	if existing == nil {
		return true
	}
	// Revoked evidence is no evidence: a freshly verified record replaces it
	// whatever its rank (the no-downgrade rule protects live evidence only).
	if existing.Revoked() {
		return true
	}
	n, e := *r, *existing
	n.Normalize()
	e.Normalize()
	switch {
	case n.Home.rank() > e.Home.rank():
		return true
	case n.Home.rank() < e.Home.rank():
		return false
	}
	if n.Kind != e.Kind {
		return false
	}
	if e.UV && !n.UV {
		return false
	}
	return true
}
