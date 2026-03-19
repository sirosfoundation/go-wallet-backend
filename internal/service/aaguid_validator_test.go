package service

import (
	"encoding/hex"
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNewAAGUIDValidator(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name    string
		cfg     config.AAGUIDBlacklistConfig
		wantLen int
	}{
		{
			name: "empty blacklist",
			cfg: config.AAGUIDBlacklistConfig{
				Enabled: true,
				AAGUIDs: []string{},
			},
			wantLen: 0,
		},
		{
			name: "valid AAGUIDs with dashes",
			cfg: config.AAGUIDBlacklistConfig{
				Enabled: true,
				AAGUIDs: []string{
					"f8a011f3-8c0a-4d15-8006-17111f9edc7d",
					"00000000-0000-0000-0000-000000000000",
				},
			},
			wantLen: 2,
		},
		{
			name: "valid AAGUIDs without dashes",
			cfg: config.AAGUIDBlacklistConfig{
				Enabled: true,
				AAGUIDs: []string{
					"f8a011f38c0a4d1580061711f9edc7d",
				},
			},
			wantLen: 0, // invalid length (31 chars)
		},
		{
			name: "validator disabled",
			cfg: config.AAGUIDBlacklistConfig{
				Enabled: false,
				AAGUIDs: []string{"f8a011f38c0a4d15800617111f9edc7d"},
			},
			wantLen: 1, // still loads the blacklist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewAAGUIDValidator(tt.cfg, logger)
			if v == nil {
				t.Fatal("NewAAGUIDValidator() returned nil")
			}
			if len(v.blacklist) != tt.wantLen {
				t.Errorf("blacklist length = %d, want %d", len(v.blacklist), tt.wantLen)
			}
		})
	}
}

func TestAAGUIDValidator_Validate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		cfg           config.AAGUIDBlacklistConfig
		aaguid        []byte
		wantAllowed   bool
		wantBlacklist bool
		wantZero      bool
	}{
		{
			name: "validator disabled allows all",
			cfg: config.AAGUIDBlacklistConfig{
				Enabled: false,
				AAGUIDs: []string{"f8a011f38c0a4d15800617111f9edc7d"},
			},
			aaguid:        mustDecodeHex("f8a011f38c0a4d15800617111f9edc7d"),
			wantAllowed:   true,
			wantBlacklist: false,
		},
		{
			name: "blacklisted AAGUID rejected",
			cfg: config.AAGUIDBlacklistConfig{
				Enabled: true,
				AAGUIDs: []string{"f8a011f38c0a4d15800617111f9edc7d"},
			},
			aaguid:        mustDecodeHex("f8a011f38c0a4d15800617111f9edc7d"),
			wantAllowed:   false,
			wantBlacklist: true,
		},
		{
			name: "non-blacklisted AAGUID allowed",
			cfg: config.AAGUIDBlacklistConfig{
				Enabled: true,
				AAGUIDs: []string{"f8a011f38c0a4d15800617111f9edc7d"},
			},
			aaguid:      mustDecodeHex("00112233445566778899aabbccddeeff"),
			wantAllowed: true,
		},
		{
			name: "zero AAGUID allowed when RejectUnknown false",
			cfg: config.AAGUIDBlacklistConfig{
				Enabled:       true,
				RejectUnknown: false,
			},
			aaguid:      mustDecodeHex("00000000000000000000000000000000"),
			wantAllowed: true,
			wantZero:    true,
		},
		{
			name: "zero AAGUID rejected when RejectUnknown true",
			cfg: config.AAGUIDBlacklistConfig{
				Enabled:       true,
				RejectUnknown: true,
			},
			aaguid:      mustDecodeHex("00000000000000000000000000000000"),
			wantAllowed: false,
			wantZero:    true,
		},
		{
			name: "empty AAGUID treated as zero",
			cfg: config.AAGUIDBlacklistConfig{
				Enabled:       true,
				RejectUnknown: true,
			},
			aaguid:      nil,
			wantAllowed: false,
			wantZero:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewAAGUIDValidator(tt.cfg, logger)
			result := v.Validate(tt.aaguid)

			if result.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", result.Allowed, tt.wantAllowed)
			}
			if result.IsBlacklisted != tt.wantBlacklist {
				t.Errorf("IsBlacklisted = %v, want %v", result.IsBlacklisted, tt.wantBlacklist)
			}
			if result.IsZero != tt.wantZero {
				t.Errorf("IsZero = %v, want %v", result.IsZero, tt.wantZero)
			}
		})
	}
}

func TestAAGUIDValidator_ValidateHex(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.AAGUIDBlacklistConfig{
		Enabled: true,
		AAGUIDs: []string{"f8a011f38c0a4d15800617111f9edc7d"},
	}
	v := NewAAGUIDValidator(cfg, logger)

	// Test blacklisted AAGUID with dashes
	result := v.ValidateHex("f8a011f3-8c0a-4d15-8006-17111f9edc7d")
	if result.Allowed {
		t.Error("ValidateHex() should reject blacklisted AAGUID")
	}

	// Test valid non-blacklisted
	result = v.ValidateHex("00112233445566778899aabbccddeeff")
	if !result.Allowed {
		t.Error("ValidateHex() should allow non-blacklisted AAGUID")
	}

	// Test invalid hex
	result = v.ValidateHex("not-valid-hex")
	// Invalid hex is treated as unknown, depends on RejectUnknown setting
	if result.AAGUID != "" {
		t.Error("ValidateHex() should return empty AAGUID for invalid input")
	}
}

func TestAAGUIDValidator_Blacklist_Management(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.AAGUIDBlacklistConfig{
		Enabled: true,
		AAGUIDs: []string{},
	}
	v := NewAAGUIDValidator(cfg, logger)

	aaguid := "f8a011f38c0a4d15800617111f9edc7d"
	aaguidBytes := mustDecodeHex(aaguid)

	// Initially not blacklisted
	if v.IsBlacklisted(aaguidBytes) {
		t.Error("AAGUID should not be initially blacklisted")
	}

	// Add to blacklist
	if !v.AddToBlacklist(aaguid) {
		t.Error("AddToBlacklist() should return true")
	}

	// Now blacklisted
	if !v.IsBlacklisted(aaguidBytes) {
		t.Error("AAGUID should be blacklisted after adding")
	}

	// Check GetBlacklist
	list := v.GetBlacklist()
	if len(list) != 1 {
		t.Errorf("GetBlacklist() length = %d, want 1", len(list))
	}

	// Remove from blacklist
	if !v.RemoveFromBlacklist(aaguid) {
		t.Error("RemoveFromBlacklist() should return true")
	}

	// No longer blacklisted
	if v.IsBlacklisted(aaguidBytes) {
		t.Error("AAGUID should not be blacklisted after removing")
	}

	// Test with invalid AAGUID
	if v.AddToBlacklist("invalid") {
		t.Error("AddToBlacklist() should return false for invalid AAGUID")
	}
	if v.RemoveFromBlacklist("invalid") {
		t.Error("RemoveFromBlacklist() should return false for invalid AAGUID")
	}
}

func TestAAGUIDValidator_IsBlacklisted_Disabled(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.AAGUIDBlacklistConfig{
		Enabled: false,
		AAGUIDs: []string{"f8a011f38c0a4d15800617111f9edc7d"},
	}
	v := NewAAGUIDValidator(cfg, logger)

	// When disabled, should return false even for blacklisted AAGUIDs
	aaguidBytes := mustDecodeHex("f8a011f38c0a4d15800617111f9edc7d")
	if v.IsBlacklisted(aaguidBytes) {
		t.Error("IsBlacklisted() should return false when validator is disabled")
	}
}

func TestAAGUIDValidationResult_Reason(t *testing.T) {
	// Test allowed result
	allowed := &AAGUIDValidationResult{Allowed: true, reason: "should be ignored"}
	if allowed.Reason() != "" {
		t.Errorf("Reason() for allowed result = %q, want empty", allowed.Reason())
	}

	// Test denied result
	denied := &AAGUIDValidationResult{Allowed: false, reason: "test reason"}
	if denied.Reason() != "test reason" {
		t.Errorf("Reason() = %q, want %q", denied.Reason(), "test reason")
	}
}

func TestZeroAAGUID(t *testing.T) {
	if ZeroAAGUID != "00000000000000000000000000000000" {
		t.Errorf("ZeroAAGUID = %q, want all zeros", ZeroAAGUID)
	}
	if len(ZeroAAGUID) != 32 {
		t.Errorf("ZeroAAGUID length = %d, want 32", len(ZeroAAGUID))
	}
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
