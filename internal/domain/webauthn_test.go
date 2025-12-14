package domain

import (
	"testing"
	"time"
)

func TestWebauthnChallenge_TableName(t *testing.T) {
	challenge := WebauthnChallenge{}
	if challenge.TableName() != "webauthn_challenges" {
		t.Errorf("TableName() = %q, want %q", challenge.TableName(), "webauthn_challenges")
	}
}

func TestWebauthnChallenge_Fields(t *testing.T) {
	now := time.Now()
	challenge := WebauthnChallenge{
		ID:        "challenge-123",
		UserID:    "user-456",
		Challenge: "random-challenge-string",
		Action:    "register",
		ExpiresAt: now.Add(5 * time.Minute),
		CreatedAt: now,
	}

	if challenge.ID != "challenge-123" {
		t.Error("WebauthnChallenge.ID not set correctly")
	}

	if challenge.UserID != "user-456" {
		t.Error("WebauthnChallenge.UserID not set correctly")
	}

	if challenge.Challenge != "random-challenge-string" {
		t.Error("WebauthnChallenge.Challenge not set correctly")
	}

	if challenge.Action != "register" {
		t.Error("WebauthnChallenge.Action not set correctly")
	}
}

func TestWebauthnChallenge_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "not expired - future",
			expiresAt: time.Now().Add(5 * time.Minute),
			expected:  false,
		},
		{
			name:      "expired - past",
			expiresAt: time.Now().Add(-5 * time.Minute),
			expected:  true,
		},
		{
			name:      "expired - exactly now (edge case)",
			expiresAt: time.Now().Add(-1 * time.Millisecond),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := WebauthnChallenge{
				ID:        "test",
				ExpiresAt: tt.expiresAt,
			}

			if challenge.IsExpired() != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", challenge.IsExpired(), tt.expected)
			}
		})
	}
}

func TestWebauthnChallenge_Actions(t *testing.T) {
	// Test that common action values work correctly
	actions := []string{"register", "login", "authenticate"}

	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			challenge := WebauthnChallenge{
				ID:        "test",
				Action:    action,
				ExpiresAt: time.Now().Add(5 * time.Minute),
			}

			if challenge.Action != action {
				t.Errorf("Action = %q, want %q", challenge.Action, action)
			}
		})
	}
}
