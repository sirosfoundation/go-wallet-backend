package domain

import (
	"time"
)

// WebauthnChallenge represents a WebAuthn challenge
type WebauthnChallenge struct {
	ID         string    `json:"id" bson:"_id" gorm:"primaryKey"`
	UserID     string    `json:"user_id" bson:"user_id" gorm:"index"`
	TenantID   string    `json:"tenant_id" bson:"tenant_id" gorm:"index"` // Optional tenant ID for tenant-scoped operations
	Challenge  string    `json:"challenge" bson:"challenge" gorm:"not null"`
	Action     string    `json:"action" bson:"action" gorm:"not null"`               // "register" or "login"
	InviteCode string    `json:"invite_code,omitempty" bson:"invite_code,omitempty"` // Invite code used for registration
	ExpiresAt  time.Time `json:"expires_at" bson:"expires_at" gorm:"index;not null"`
	CreatedAt  time.Time `json:"created_at" bson:"created_at" gorm:"autoCreateTime"`

	// CodeVerifier holds the PKCE code_verifier for OIDC authorization-code
	// flows (action "oidc_login"). Generated at /auth/oidc/login, sent back
	// to the token endpoint at /auth/oidc/callback so a party that only
	// intercepts the authorization code (e.g. via an open redirect, a
	// referrer leak, or a malicious/compromised network hop) cannot redeem
	// it without also having captured this value. See go-wallet-backend#373.
	CodeVerifier string `json:"code_verifier,omitempty" bson:"code_verifier,omitempty"`
}

// TableName specifies the table name for GORM
func (WebauthnChallenge) TableName() string {
	return "webauthn_challenges"
}

// IsExpired checks if the challenge has expired
func (c *WebauthnChallenge) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}
