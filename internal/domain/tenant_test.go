package domain

import (
	"testing"
)

func TestValidateTenantID(t *testing.T) {
	tests := []struct {
		name    string
		id      TenantID
		wantErr bool
	}{
		{
			name:    "valid simple id",
			id:      "default",
			wantErr: false,
		},
		{
			name:    "valid with numbers",
			id:      "tenant123",
			wantErr: false,
		},
		{
			name:    "valid with hyphens",
			id:      "my-tenant",
			wantErr: false,
		},
		{
			name:    "valid with underscores",
			id:      "my_tenant",
			wantErr: false,
		},
		{
			name:    "valid mixed",
			id:      "org-123_tenant",
			wantErr: false,
		},
		{
			name:    "valid starting with number",
			id:      "123tenant",
			wantErr: false,
		},
		{
			name:    "empty string",
			id:      "",
			wantErr: true,
		},
		{
			name:    "contains colon",
			id:      "tenant:id",
			wantErr: true,
		},
		{
			name:    "contains uppercase",
			id:      "MyTenant",
			wantErr: true,
		},
		{
			name:    "contains space",
			id:      "my tenant",
			wantErr: true,
		},
		{
			name:    "starts with hyphen",
			id:      "-tenant",
			wantErr: true,
		},
		{
			name:    "starts with underscore",
			id:      "_tenant",
			wantErr: true,
		},
		{
			name:    "too long",
			id:      TenantID("a" + string(make([]byte, 63))),
			wantErr: true,
		},
		{
			name:    "max length valid",
			id:      TenantID(string(make([]byte, 63))),
			wantErr: true, // all nulls, invalid chars
		},
		{
			name:    "63 chars valid",
			id:      "a23456789012345678901234567890123456789012345678901234567890123",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTenantID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTenantID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestTenantID_String(t *testing.T) {
	id := TenantID("test-tenant")
	if got := id.String(); got != "test-tenant" {
		t.Errorf("TenantID.String() = %v, want %v", got, "test-tenant")
	}
}

func TestDefaultTenantID(t *testing.T) {
	if DefaultTenantID != "default" {
		t.Errorf("DefaultTenantID = %v, want %v", DefaultTenantID, "default")
	}
}

func TestTenant_TableName(t *testing.T) {
	tenant := Tenant{}
	if got := tenant.TableName(); got != "tenants" {
		t.Errorf("Tenant.TableName() = %v, want %v", got, "tenants")
	}
}

func TestUserTenantMembership_TableName(t *testing.T) {
	membership := UserTenantMembership{}
	if got := membership.TableName(); got != "user_tenant_memberships" {
		t.Errorf("UserTenantMembership.TableName() = %v, want %v", got, "user_tenant_memberships")
	}
}

func TestEncodeUserHandle(t *testing.T) {
	tenantID := TenantID("test-tenant")
	userID := NewUserID()

	handle := EncodeUserHandle(tenantID, userID)

	// V1 binary format: 1 byte version + 8 bytes tenant hash + 16 bytes UUID = 25 bytes
	if len(handle) != 25 {
		t.Errorf("EncodeUserHandle() length = %d, want 25", len(handle))
	}
	if handle[0] != 0x01 {
		t.Errorf("EncodeUserHandle() version byte = %d, want 1", handle[0])
	}
}

func TestEncodeUserHandle_SizeConstraint(t *testing.T) {
	// Test that even very long tenant IDs produce 25-byte handles (within WebAuthn's 64-byte limit)
	longTenantID := TenantID("this-is-a-very-long-tenant-id-that-would-exceed-64-bytes-combined")
	userID := NewUserID()

	handle := EncodeUserHandle(longTenantID, userID)

	if len(handle) != 25 {
		t.Errorf("EncodeUserHandle() length = %d, want 25 (within 64-byte WebAuthn limit)", len(handle))
	}
}

func TestDecodeUserHandle(t *testing.T) {
	tests := []struct {
		name         string
		handle       []byte
		wantTenantID TenantID
		wantUserID   string
		wantErr      bool
	}{
		{
			name:         "legacy string format with valid tenant",
			handle:       []byte("test-tenant:550e8400-e29b-41d4-a716-446655440000"),
			wantTenantID: "test-tenant",
			wantUserID:   "550e8400-e29b-41d4-a716-446655440000",
			wantErr:      false,
		},
		{
			name:         "legacy string format with default tenant",
			handle:       []byte("default:550e8400-e29b-41d4-a716-446655440000"),
			wantTenantID: "default",
			wantUserID:   "550e8400-e29b-41d4-a716-446655440000",
			wantErr:      false,
		},
		{
			name:    "legacy string format missing colon",
			handle:  []byte("no-colon-here"),
			wantErr: true,
		},
		{
			name:    "empty handle",
			handle:  []byte(""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTenantID, gotUserID, err := DecodeUserHandle(tt.handle)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeUserHandle() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if gotTenantID != tt.wantTenantID {
					t.Errorf("DecodeUserHandle() tenantID = %v, want %v", gotTenantID, tt.wantTenantID)
				}
				if gotUserID.String() != tt.wantUserID {
					t.Errorf("DecodeUserHandle() userID = %v, want %v", gotUserID.String(), tt.wantUserID)
				}
			}
		})
	}
}

func TestEncodeDecodeUserHandle_RoundTrip(t *testing.T) {
	tenantID := TenantID("my-org")
	userID := NewUserID()

	handle := EncodeUserHandle(tenantID, userID)
	// V1 format returns empty tenant ID (can't reverse the hash)
	// but the user ID should be preserved
	_, gotUserID, err := DecodeUserHandle(handle)

	if err != nil {
		t.Fatalf("DecodeUserHandle() error = %v", err)
	}
	// Note: V1 binary format cannot recover tenant ID from its hash
	// gotTenantID will be empty for v1 handles
	if gotUserID.String() != userID.String() {
		t.Errorf("Round trip userID = %v, want %v", gotUserID.String(), userID.String())
	}
}

func TestComputeTenantHash(t *testing.T) {
	// Same tenant should always produce the same hash
	hash1 := ComputeTenantHash("test-tenant")
	hash2 := ComputeTenantHash("test-tenant")
	if len(hash1) != 8 || len(hash2) != 8 {
		t.Errorf("ComputeTenantHash() length should be 8")
	}
	for i := range hash1 {
		if hash1[i] != hash2[i] {
			t.Errorf("ComputeTenantHash() should be deterministic")
		}
	}

	// Different tenants should produce different hashes
	hash3 := ComputeTenantHash("other-tenant")
	same := true
	for i := range hash1 {
		if hash1[i] != hash3[i] {
			same = false
			break
		}
	}
	if same {
		t.Errorf("ComputeTenantHash() should produce different hashes for different tenants")
	}
}

func TestTenantHashFromHandle(t *testing.T) {
	tenantID := TenantID("test-tenant")
	userID := NewUserID()

	handle := EncodeUserHandle(tenantID, userID)
	hash, err := TenantHashFromHandle(handle)
	if err != nil {
		t.Fatalf("TenantHashFromHandle() error = %v", err)
	}

	expectedHash := ComputeTenantHash(tenantID)
	for i := range hash {
		if hash[i] != expectedHash[i] {
			t.Errorf("TenantHashFromHandle() hash mismatch at byte %d", i)
		}
	}
}

func TestTenant_ToInfo(t *testing.T) {
	tenant := &Tenant{
		ID:          "test-tenant",
		Name:        "test",
		DisplayName: "Test Tenant",
		Enabled:     true,
	}

	info := tenant.ToInfo()

	if info.ID != tenant.ID {
		t.Errorf("ToInfo().ID = %v, want %v", info.ID, tenant.ID)
	}
	if info.Name != tenant.Name {
		t.Errorf("ToInfo().Name = %v, want %v", info.Name, tenant.Name)
	}
	if info.DisplayName != tenant.DisplayName {
		t.Errorf("ToInfo().DisplayName = %v, want %v", info.DisplayName, tenant.DisplayName)
	}
}

func TestTenantRoles(t *testing.T) {
	if TenantRoleUser != "user" {
		t.Errorf("TenantRoleUser = %v, want %v", TenantRoleUser, "user")
	}
	if TenantRoleAdmin != "admin" {
		t.Errorf("TenantRoleAdmin = %v, want %v", TenantRoleAdmin, "admin")
	}
}
