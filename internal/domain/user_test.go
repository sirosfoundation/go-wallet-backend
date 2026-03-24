package domain

import (
	"testing"
	"time"
)

func TestNewUserID(t *testing.T) {
	id1 := NewUserID()
	id2 := NewUserID()

	if id1.ID == "" {
		t.Error("NewUserID() should generate non-empty ID")
	}

	if id1.ID == id2.ID {
		t.Error("NewUserID() should generate unique IDs")
	}
}

func TestUserIDFromString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", ""},
		{"uuid string", "550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440000"},
		{"simple string", "test-id", "test-id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UserIDFromString(tt.input)
			if result.ID != tt.expected {
				t.Errorf("UserIDFromString(%q) = %q, want %q", tt.input, result.ID, tt.expected)
			}
		})
	}
}

func TestUserID_String(t *testing.T) {
	id := UserIDFromString("test-123")
	if id.String() != "test-123" {
		t.Errorf("String() = %q, want %q", id.String(), "test-123")
	}
}

func TestUserID_AsUserHandle(t *testing.T) {
	id := UserIDFromString("test-id")
	handle := id.AsUserHandle()

	if string(handle) != "test-id" {
		t.Errorf("AsUserHandle() = %q, want %q", string(handle), "test-id")
	}
}

func TestUserIDFromUserHandle(t *testing.T) {
	handle := []byte("handle-123")
	id := UserIDFromUserHandle(handle)

	if id.ID != "handle-123" {
		t.Errorf("UserIDFromUserHandle() = %q, want %q", id.ID, "handle-123")
	}
}

func TestComputePrivateDataETag(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"simple data", []byte("hello world")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			etag := ComputePrivateDataETag(tt.data)

			// ETag should be quoted
			if len(etag) < 2 || etag[0] != '"' || etag[len(etag)-1] != '"' {
				t.Errorf("ComputePrivateDataETag() should return quoted string, got %q", etag)
			}

			// Same data should produce same ETag
			etag2 := ComputePrivateDataETag(tt.data)
			if etag != etag2 {
				t.Error("ComputePrivateDataETag() should be deterministic")
			}
		})
	}

	// Different data should produce different ETags
	etag1 := ComputePrivateDataETag([]byte("data1"))
	etag2 := ComputePrivateDataETag([]byte("data2"))
	if etag1 == etag2 {
		t.Error("ComputePrivateDataETag() should produce different ETags for different data")
	}
}

func TestUser_UpdatePrivateData(t *testing.T) {
	user := &User{
		UUID:      NewUserID(),
		CreatedAt: time.Now().Add(-time.Hour),
		UpdatedAt: time.Now().Add(-time.Hour),
	}

	originalUpdatedAt := user.UpdatedAt
	newData := []byte("new private data")

	user.UpdatePrivateData(newData)

	if string(user.PrivateData) != string(newData) {
		t.Error("UpdatePrivateData() should update PrivateData")
	}

	if user.PrivateDataETag == "" {
		t.Error("UpdatePrivateData() should set PrivateDataETag")
	}

	if !user.UpdatedAt.After(originalUpdatedAt) {
		t.Error("UpdatePrivateData() should update UpdatedAt")
	}
}

func TestWalletType_Constants(t *testing.T) {
	if WalletTypeDB != "db" {
		t.Errorf("WalletTypeDB = %q, want %q", WalletTypeDB, "db")
	}

	if WalletTypeClient != "client" {
		t.Errorf("WalletTypeClient = %q, want %q", WalletTypeClient, "client")
	}
}

func TestUser_Fields(t *testing.T) {
	username := "testuser"
	displayName := "Test User"
	passwordHash := "hashedpassword"

	user := User{
		UUID:         NewUserID(),
		Username:     &username,
		DisplayName:  &displayName,
		DID:          "did:key:test",
		PasswordHash: &passwordHash,
		WalletType:   WalletTypeDB,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if user.Username == nil || *user.Username != username {
		t.Error("User.Username not set correctly")
	}

	if user.DisplayName == nil || *user.DisplayName != displayName {
		t.Error("User.DisplayName not set correctly")
	}

	if user.DID != "did:key:test" {
		t.Error("User.DID not set correctly")
	}

	if user.WalletType != WalletTypeDB {
		t.Error("User.WalletType not set correctly")
	}
}

func TestWebauthnCredential_Fields(t *testing.T) {
	cred := WebauthnCredential{
		ID:              "cred-123",
		PublicKey:       []byte{0x01, 0x02, 0x03},
		AttestationType: "none",
		Transport:       []string{"usb", "nfc"},
		Flags:           0x01,
		Authenticator: Authenticator{
			AAGUID:       []byte{0x00},
			SignCount:    42,
			CloneWarning: false,
			Attachment:   "platform",
		},
		CreatedAt: time.Now(),
	}

	if cred.ID != "cred-123" {
		t.Error("WebauthnCredential.ID not set correctly")
	}

	if len(cred.PublicKey) != 3 {
		t.Error("WebauthnCredential.PublicKey not set correctly")
	}

	if len(cred.Transport) != 2 {
		t.Error("WebauthnCredential.Transport not set correctly")
	}

	if cred.Authenticator.SignCount != 42 {
		t.Error("WebauthnCredential.Authenticator.SignCount not set correctly")
	}
}

func TestRegisterRequest_Fields(t *testing.T) {
	username := "newuser"
	password := "secret123"

	req := RegisterRequest{
		Username:    &username,
		DisplayName: "New User",
		Password:    &password,
		WalletType:  WalletTypeClient,
		Keys:        []byte("keydata"),
		PrivateData: []byte("privatedata"),
	}

	if req.Username == nil || *req.Username != username {
		t.Error("RegisterRequest.Username not set correctly")
	}

	if req.DisplayName != "New User" {
		t.Error("RegisterRequest.DisplayName not set correctly")
	}

	if req.WalletType != WalletTypeClient {
		t.Error("RegisterRequest.WalletType not set correctly")
	}
}

func TestLoginRequest_Fields(t *testing.T) {
	req := LoginRequest{
		Username: "testuser",
		Password: "password123",
	}

	if req.Username != "testuser" {
		t.Error("LoginRequest.Username not set correctly")
	}

	if req.Password != "password123" {
		t.Error("LoginRequest.Password not set correctly")
	}
}

func TestLoginResponse_Fields(t *testing.T) {
	resp := LoginResponse{
		Token:       "jwt-token-here",
		UserID:      "user-123",
		DisplayName: "Test User",
	}

	if resp.Token != "jwt-token-here" {
		t.Error("LoginResponse.Token not set correctly")
	}

	if resp.UserID != "user-123" {
		t.Error("LoginResponse.UserID not set correctly")
	}

	if resp.DisplayName != "Test User" {
		t.Error("LoginResponse.DisplayName not set correctly")
	}
}

func TestUser_EnterpriseIdentityMethods(t *testing.T) {
	t.Run("GetEnterpriseIdentityForTenant returns nil when no identities", func(t *testing.T) {
		user := &User{
			EnterpriseIdentities: nil,
		}
		result := user.GetEnterpriseIdentityForTenant("tenant1")
		if result != nil {
			t.Error("Expected nil when no enterprise identities exist")
		}
	})

	t.Run("GetEnterpriseIdentityForTenant returns correct identity", func(t *testing.T) {
		now := time.Now()
		user := &User{
			EnterpriseIdentities: []EnterpriseIdentity{
				{TenantID: "tenant1", Issuer: "https://idp1.example.com", Subject: "user1", BoundAt: now},
				{TenantID: "tenant2", Issuer: "https://idp2.example.com", Subject: "user2", BoundAt: now},
			},
		}
		result := user.GetEnterpriseIdentityForTenant("tenant2")
		if result == nil {
			t.Fatal("Expected to find identity for tenant2")
		}
		if result.Issuer != "https://idp2.example.com" {
			t.Errorf("Expected issuer %q, got %q", "https://idp2.example.com", result.Issuer)
		}
		if result.Subject != "user2" {
			t.Errorf("Expected subject %q, got %q", "user2", result.Subject)
		}
	})

	t.Run("GetEnterpriseIdentityForTenant returns nil for non-existent tenant", func(t *testing.T) {
		user := &User{
			EnterpriseIdentities: []EnterpriseIdentity{
				{TenantID: "tenant1", Issuer: "https://idp1.example.com", Subject: "user1"},
			},
		}
		result := user.GetEnterpriseIdentityForTenant("tenant-nonexistent")
		if result != nil {
			t.Error("Expected nil for non-existent tenant")
		}
	})

	t.Run("HasEnterpriseIdentityForTenant returns correct values", func(t *testing.T) {
		user := &User{
			EnterpriseIdentities: []EnterpriseIdentity{
				{TenantID: "tenant1", Issuer: "https://idp1.example.com", Subject: "user1"},
			},
		}
		if !user.HasEnterpriseIdentityForTenant("tenant1") {
			t.Error("Expected HasEnterpriseIdentityForTenant to return true for existing tenant")
		}
		if user.HasEnterpriseIdentityForTenant("tenant2") {
			t.Error("Expected HasEnterpriseIdentityForTenant to return false for non-existing tenant")
		}
	})

	t.Run("AddEnterpriseIdentity adds new identity", func(t *testing.T) {
		user := &User{
			EnterpriseIdentities: nil,
		}
		identity := EnterpriseIdentity{
			TenantID:    "tenant1",
			Issuer:      "https://idp.example.com",
			Subject:     "user123",
			Email:       "user@example.com",
			BindingType: "registration",
			BoundAt:     time.Now(),
		}
		user.AddEnterpriseIdentity(identity)

		if len(user.EnterpriseIdentities) != 1 {
			t.Fatalf("Expected 1 identity, got %d", len(user.EnterpriseIdentities))
		}
		if user.EnterpriseIdentities[0].Issuer != "https://idp.example.com" {
			t.Error("Identity not added correctly")
		}
	})

	t.Run("AddEnterpriseIdentity replaces existing identity for same tenant", func(t *testing.T) {
		user := &User{
			EnterpriseIdentities: []EnterpriseIdentity{
				{TenantID: "tenant1", Issuer: "https://old-idp.example.com", Subject: "old-user"},
			},
		}
		newIdentity := EnterpriseIdentity{
			TenantID: "tenant1",
			Issuer:   "https://new-idp.example.com",
			Subject:  "new-user",
			BoundAt:  time.Now(),
		}
		user.AddEnterpriseIdentity(newIdentity)

		if len(user.EnterpriseIdentities) != 1 {
			t.Fatalf("Expected 1 identity after replacement, got %d", len(user.EnterpriseIdentities))
		}
		if user.EnterpriseIdentities[0].Issuer != "https://new-idp.example.com" {
			t.Error("Identity was not replaced correctly")
		}
		if user.EnterpriseIdentities[0].Subject != "new-user" {
			t.Error("Subject was not updated correctly")
		}
	})

	t.Run("AddEnterpriseIdentity preserves other tenants", func(t *testing.T) {
		user := &User{
			EnterpriseIdentities: []EnterpriseIdentity{
				{TenantID: "tenant1", Issuer: "https://idp1.example.com", Subject: "user1"},
				{TenantID: "tenant2", Issuer: "https://idp2.example.com", Subject: "user2"},
			},
		}
		newIdentity := EnterpriseIdentity{
			TenantID: "tenant3",
			Issuer:   "https://idp3.example.com",
			Subject:  "user3",
			BoundAt:  time.Now(),
		}
		user.AddEnterpriseIdentity(newIdentity)

		if len(user.EnterpriseIdentities) != 3 {
			t.Fatalf("Expected 3 identities, got %d", len(user.EnterpriseIdentities))
		}
	})
}
