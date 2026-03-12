package domain

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"
)

// InviteStatus represents the lifecycle state of an invite code
type InviteStatus string

const (
	InviteStatusActive    InviteStatus = "active"
	InviteStatusCompleted InviteStatus = "completed"
	InviteStatusRevoked   InviteStatus = "revoked"
)

// InviteCodeLength is the number of random bytes used to generate an invite code
const InviteCodeLength = 32

// Invite represents a per-tenant invite code that pre-authorizes registration
type Invite struct {
	ID        string          `json:"id" bson:"_id"`
	TenantID  TenantID        `json:"tenant_id" bson:"tenant_id"`
	Code      string          `json:"code" bson:"code"`
	Status    InviteStatus    `json:"status" bson:"status"`
	Metadata  json.RawMessage `json:"metadata,omitempty" bson:"metadata,omitempty"`
	UsedBy    *UserID         `json:"used_by,omitempty" bson:"used_by,omitempty"`
	ExpiresAt time.Time       `json:"expires_at" bson:"expires_at"`
	CreatedAt time.Time       `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time       `json:"updated_at" bson:"updated_at"`
}

// IsExpired returns true if the invite has passed its expiry time
func (i *Invite) IsExpired() bool {
	return time.Now().After(i.ExpiresAt)
}

// IsUsable returns true if the invite can be used for registration
func (i *Invite) IsUsable() bool {
	return i.Status == InviteStatusActive && !i.IsExpired()
}

// GenerateInviteCode generates a cryptographically secure invite code
func GenerateInviteCode() (string, error) {
	b := make([]byte, InviteCodeLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
