package domain

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// TenantID represents a unique tenant identifier (URL-safe slug)
type TenantID string

// DefaultTenantID is the default tenant for backward compatibility
const DefaultTenantID TenantID = "default"

// tenantIDRegex validates that tenant IDs contain only URL-safe characters
// Allowed: lowercase letters, numbers, hyphens, underscores (no colons to avoid conflicts with user handle encoding)
var tenantIDRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// ValidateTenantID checks if a tenant ID is valid (URL-safe slug without colons)
func ValidateTenantID(id TenantID) error {
	s := string(id)
	if len(s) == 0 {
		return fmt.Errorf("tenant ID cannot be empty")
	}
	if len(s) > 63 {
		return fmt.Errorf("tenant ID cannot exceed 63 characters")
	}
	if !tenantIDRegex.MatchString(s) {
		return fmt.Errorf("tenant ID must contain only lowercase letters, numbers, hyphens, and underscores, and must start with a letter or number")
	}
	return nil
}

// String returns the string representation
func (t TenantID) String() string {
	return string(t)
}

// Tenant represents an organizational tenant
type Tenant struct {
	ID          TenantID  `json:"id" bson:"_id" gorm:"primaryKey"`
	Name        string    `json:"name" bson:"name" gorm:"not null"`
	DisplayName string    `json:"display_name" bson:"display_name"`
	Enabled     bool      `json:"enabled" bson:"enabled" gorm:"default:true"`
	CreatedAt   time.Time `json:"created_at" bson:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time `json:"updated_at" bson:"updated_at" gorm:"autoUpdateTime"`
}

// TableName specifies the table name for GORM
func (Tenant) TableName() string {
	return "tenants"
}

// UserTenantMembership represents a user's membership in a tenant
type UserTenantMembership struct {
	ID        int64     `json:"id" bson:"_id,omitempty" gorm:"primaryKey;autoIncrement"`
	UserID    UserID    `json:"user_id" bson:"user_id" gorm:"index;not null"`
	TenantID  TenantID  `json:"tenant_id" bson:"tenant_id" gorm:"index;not null"`
	Role      string    `json:"role" bson:"role" gorm:"default:'user'"` // user, admin
	CreatedAt time.Time `json:"created_at" bson:"created_at" gorm:"autoCreateTime"`
}

// TableName specifies the table name for GORM
func (UserTenantMembership) TableName() string {
	return "user_tenant_memberships"
}

// TenantRoles
const (
	TenantRoleUser  = "user"
	TenantRoleAdmin = "admin"
)

// UserHandle encoding for tenant-scoped WebAuthn
// Format: {tenantId}:{userId}

// EncodeUserHandle creates a tenant-scoped user handle for WebAuthn
func EncodeUserHandle(tenantID TenantID, userID UserID) []byte {
	combined := fmt.Sprintf("%s:%s", tenantID, userID.String())
	return []byte(combined)
}

// DecodeUserHandle extracts tenant and user from a WebAuthn user handle
func DecodeUserHandle(handle []byte) (TenantID, UserID, error) {
	parts := strings.SplitN(string(handle), ":", 2)
	if len(parts) != 2 {
		return "", UserID{}, fmt.Errorf("invalid user handle format: expected tenant:user")
	}
	return TenantID(parts[0]), UserIDFromString(parts[1]), nil
}

// TenantInfo is a public-facing tenant info response
type TenantInfo struct {
	ID          TenantID `json:"id"`
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
}

// ToInfo converts a Tenant to TenantInfo
func (t *Tenant) ToInfo() TenantInfo {
	return TenantInfo{
		ID:          t.ID,
		Name:        t.Name,
		DisplayName: t.DisplayName,
	}
}
