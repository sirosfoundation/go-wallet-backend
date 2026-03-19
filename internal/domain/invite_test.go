package domain

import (
	"testing"
	"time"
)

func TestInvite_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		invite   *Invite
		expected bool
	}{
		{
			name: "expired invite",
			invite: &Invite{
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			expected: true,
		},
		{
			name: "not expired invite",
			invite: &Invite{
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			expected: false,
		},
		{
			name: "just expired",
			invite: &Invite{
				ExpiresAt: time.Now().Add(-1 * time.Millisecond),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.invite.IsExpired()
			if result != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestInvite_IsUsable(t *testing.T) {
	tests := []struct {
		name     string
		invite   *Invite
		expected bool
	}{
		{
			name: "active and not expired",
			invite: &Invite{
				Status:    InviteStatusActive,
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			expected: true,
		},
		{
			name: "active but expired",
			invite: &Invite{
				Status:    InviteStatusActive,
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			expected: false,
		},
		{
			name: "completed and not expired",
			invite: &Invite{
				Status:    InviteStatusCompleted,
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			expected: false,
		},
		{
			name: "revoked and not expired",
			invite: &Invite{
				Status:    InviteStatusRevoked,
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.invite.IsUsable()
			if result != tt.expected {
				t.Errorf("IsUsable() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGenerateInviteCode(t *testing.T) {
	// Test that codes are generated successfully
	code, err := GenerateInviteCode()
	if err != nil {
		t.Fatalf("GenerateInviteCode() error = %v", err)
	}

	// Code should be non-empty
	if code == "" {
		t.Error("GenerateInviteCode() returned empty string")
	}

	// Expected length: 32 bytes encoded in base64url = 43 characters
	expectedLen := 43 // 32 bytes * 8 / 6 = 42.67, rounded up to 43 for base64
	if len(code) != expectedLen {
		t.Errorf("GenerateInviteCode() length = %d, want %d", len(code), expectedLen)
	}

	// Test uniqueness
	code2, err := GenerateInviteCode()
	if err != nil {
		t.Fatalf("GenerateInviteCode() error = %v", err)
	}
	if code == code2 {
		t.Error("GenerateInviteCode() generated duplicate codes")
	}
}

func TestInviteStatusConstants(t *testing.T) {
	// Verify constants have expected values
	if InviteStatusActive != "active" {
		t.Errorf("InviteStatusActive = %q, want %q", InviteStatusActive, "active")
	}
	if InviteStatusCompleted != "completed" {
		t.Errorf("InviteStatusCompleted = %q, want %q", InviteStatusCompleted, "completed")
	}
	if InviteStatusRevoked != "revoked" {
		t.Errorf("InviteStatusRevoked = %q, want %q", InviteStatusRevoked, "revoked")
	}
}

func TestInviteCodeLength(t *testing.T) {
	if InviteCodeLength != 32 {
		t.Errorf("InviteCodeLength = %d, want %d", InviteCodeLength, 32)
	}
}
