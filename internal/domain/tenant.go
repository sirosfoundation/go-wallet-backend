package domain

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
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
// Format: 1-byte version + 8-byte tenant hash + 16-byte UUID = 25 bytes total
// This fits well within WebAuthn's 64-byte limit for user handles.

const (
	userHandleVersion1 = 0x01 // Version byte for this encoding
	userHandleV1Length = 25   // 1 (version) + 8 (tenant hash) + 16 (UUID)
)

// EncodeUserHandle creates a tenant-scoped user handle for WebAuthn.
// Uses a compact binary format to stay within WebAuthn's 64-byte limit:
// - 1 byte: version (0x01)
// - 8 bytes: truncated SHA-256 hash of tenant ID
// - 16 bytes: raw UUID bytes
// Total: 25 bytes
func EncodeUserHandle(tenantID TenantID, userID UserID) []byte {
	result := make([]byte, userHandleV1Length)

	// Version byte
	result[0] = userHandleVersion1

	// Hash tenant ID and take first 8 bytes
	tenantHash := sha256.Sum256([]byte(tenantID))
	copy(result[1:9], tenantHash[:8])

	// Parse UUID and copy raw bytes
	uid, err := uuid.Parse(userID.String())
	if err != nil {
		// Fallback: hash the user ID string
		userHash := sha256.Sum256([]byte(userID.String()))
		copy(result[9:25], userHash[:16])
	} else {
		// Use raw UUID bytes (16 bytes)
		uidBytes := uid[:]
		copy(result[9:25], uidBytes)
	}

	return result
}

// DecodeUserHandle extracts tenant and user from a WebAuthn user handle.
// Supports both v1 binary format and legacy string format for backward compatibility.
func DecodeUserHandle(handle []byte) (TenantID, UserID, error) {
	if len(handle) == 0 {
		return "", UserID{}, fmt.Errorf("empty user handle")
	}

	// Check for v1 binary format
	if len(handle) == userHandleV1Length && handle[0] == userHandleVersion1 {
		// Binary format - we can extract UUID but not tenant ID (it's hashed)
		// Return empty tenant ID - caller must look up tenant from stored mapping
		uid, err := uuid.FromBytes(handle[9:25])
		if err != nil {
			return "", UserID{}, fmt.Errorf("failed to parse UUID from user handle: %w", err)
		}
		// Note: We cannot recover the original tenant ID from its hash.
		// The caller must use a separate lookup mechanism.
		// Return empty tenant ID to signal this.
		return "", UserIDFromString(uid.String()), nil
	}

	// Legacy string format: "tenantId:userId"
	parts := strings.SplitN(string(handle), ":", 2)
	if len(parts) != 2 {
		return "", UserID{}, fmt.Errorf("invalid user handle format: expected tenant:user")
	}
	return TenantID(parts[0]), UserIDFromString(parts[1]), nil
}

// TenantHashFromHandle extracts the 8-byte tenant hash from a v1 user handle.
// This can be compared against stored tenant hashes to identify the tenant.
func TenantHashFromHandle(handle []byte) ([]byte, error) {
	if len(handle) != userHandleV1Length || handle[0] != userHandleVersion1 {
		return nil, fmt.Errorf("not a v1 user handle")
	}
	return handle[1:9], nil
}

// ComputeTenantHash computes the 8-byte hash used in user handles for a tenant ID.
func ComputeTenantHash(tenantID TenantID) []byte {
	hash := sha256.Sum256([]byte(tenantID))
	return hash[:8]
}

// UserIDFromHandle extracts just the user ID from a user handle.
// Works with both v1 binary format and legacy string format.
func UserIDFromHandle(handle []byte) (UserID, error) {
	_, userID, err := DecodeUserHandle(handle)
	return userID, err
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
