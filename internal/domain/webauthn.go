package domain

import (
	"time"
)

// WebauthnChallenge represents a WebAuthn challenge
type WebauthnChallenge struct {
	ID        string    `json:"id" bson:"_id" gorm:"primaryKey"`
	UserID    string    `json:"user_id" bson:"user_id" gorm:"index;not null"`
	Challenge string    `json:"challenge" bson:"challenge" gorm:"not null"`
	Action    string    `json:"action" bson:"action" gorm:"not null"` // "register" or "login"
	ExpiresAt time.Time `json:"expires_at" bson:"expires_at" gorm:"index;not null"`
	CreatedAt time.Time `json:"created_at" bson:"created_at" gorm:"autoCreateTime"`
}

// TableName specifies the table name for GORM
func (WebauthnChallenge) TableName() string {
	return "webauthn_challenges"
}

// IsExpired checks if the challenge has expired
func (c *WebauthnChallenge) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}
