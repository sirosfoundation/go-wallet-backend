package service

import (
	"encoding/hex"
	"strings"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// AAGUIDValidator validates authenticator AAGUIDs against a blacklist
// and provides hooks for future AAGUID-based policies.
type AAGUIDValidator struct {
	config    config.AAGUIDBlacklistConfig
	logger    *zap.Logger
	blacklist map[string]bool // normalized AAGUID hex strings
}

// NewAAGUIDValidator creates a new AAGUID validator
func NewAAGUIDValidator(cfg config.AAGUIDBlacklistConfig, logger *zap.Logger) *AAGUIDValidator {
	v := &AAGUIDValidator{
		config:    cfg,
		logger:    logger.Named("aaguid-validator"),
		blacklist: make(map[string]bool),
	}

	// Normalize and load blacklist
	for _, aaguid := range cfg.AAGUIDs {
		normalized := v.normalizeAAGUID(aaguid)
		if normalized != "" {
			v.blacklist[normalized] = true
			v.logger.Debug("Added AAGUID to blacklist", zap.String("aaguid", normalized))
		}
	}

	if cfg.Enabled {
		v.logger.Info("AAGUID validator enabled",
			zap.Int("blacklist_count", len(v.blacklist)),
			zap.Bool("reject_unknown", cfg.RejectUnknown),
		)
	} else {
		v.logger.Info("AAGUID validator disabled")
	}

	return v
}

// normalizeAAGUID normalizes an AAGUID string to lowercase hex without dashes
func (v *AAGUIDValidator) normalizeAAGUID(aaguid string) string {
	// Remove dashes and convert to lowercase
	normalized := strings.ToLower(strings.ReplaceAll(aaguid, "-", ""))

	// Validate it's a valid hex string of correct length (32 hex chars = 16 bytes)
	if len(normalized) != 32 {
		v.logger.Warn("Invalid AAGUID length", zap.String("aaguid", aaguid))
		return ""
	}

	// Verify it's valid hex
	if _, err := hex.DecodeString(normalized); err != nil {
		v.logger.Warn("Invalid AAGUID hex", zap.String("aaguid", aaguid), zap.Error(err))
		return ""
	}

	return normalized
}

// normalizeBytes normalizes AAGUID bytes to a hex string
func (v *AAGUIDValidator) normalizeBytes(aaguid []byte) string {
	if len(aaguid) == 0 {
		return ""
	}
	return strings.ToLower(hex.EncodeToString(aaguid))
}

// AAGUIDValidationResult contains the result of AAGUID validation
type AAGUIDValidationResult struct {
	Allowed       bool
	AAGUID        string // normalized hex string
	IsZero        bool   // true if AAGUID is all zeros
	IsBlacklisted bool   // true if AAGUID is on blacklist
	reason        string // internal reason for denial
}

// Reason returns the reason for denial (empty if allowed)
func (r *AAGUIDValidationResult) Reason() string {
	if r.Allowed {
		return ""
	}
	return r.reason
}

// ZeroAAGUID is the all-zero AAGUID indicating an unknown/virtual authenticator
const ZeroAAGUID = "00000000000000000000000000000000"

// Validate checks if an AAGUID is allowed for registration
func (v *AAGUIDValidator) Validate(aaguid []byte) *AAGUIDValidationResult {
	result := &AAGUIDValidationResult{
		Allowed: true,
		AAGUID:  v.normalizeBytes(aaguid),
	}

	// Check if disabled
	if !v.config.Enabled {
		return result
	}

	// Check for zero/unknown AAGUID
	result.IsZero = result.AAGUID == ZeroAAGUID || result.AAGUID == ""

	// Check blacklist
	if v.blacklist[result.AAGUID] {
		result.IsBlacklisted = true
		result.Allowed = false
		result.reason = "AAGUID is blacklisted"

		v.logger.Warn("Registration blocked: AAGUID is blacklisted",
			zap.String("aaguid", result.AAGUID),
		)
		return result
	}

	// Check unknown rejection policy
	if result.IsZero && v.config.RejectUnknown {
		result.Allowed = false
		result.reason = "Unknown authenticator not allowed"

		v.logger.Warn("Registration blocked: unknown AAGUID rejected",
			zap.String("aaguid", result.AAGUID),
		)
		return result
	}

	return result
}

// ValidateHex validates an AAGUID provided as a hex string
func (v *AAGUIDValidator) ValidateHex(aaguid string) *AAGUIDValidationResult {
	normalized := v.normalizeAAGUID(aaguid)
	if normalized == "" {
		// Invalid format - treat as unknown
		return v.Validate(nil)
	}

	bytes, _ := hex.DecodeString(normalized)
	return v.Validate(bytes)
}

// AddToBlacklist adds an AAGUID to the runtime blacklist
// This is useful for dynamic blacklist updates without restart.
func (v *AAGUIDValidator) AddToBlacklist(aaguid string) bool {
	normalized := v.normalizeAAGUID(aaguid)
	if normalized == "" {
		return false
	}

	v.blacklist[normalized] = true
	v.logger.Info("AAGUID added to runtime blacklist",
		zap.String("aaguid", normalized),
	)
	return true
}

// RemoveFromBlacklist removes an AAGUID from the runtime blacklist
func (v *AAGUIDValidator) RemoveFromBlacklist(aaguid string) bool {
	normalized := v.normalizeAAGUID(aaguid)
	if normalized == "" {
		return false
	}

	delete(v.blacklist, normalized)
	v.logger.Info("AAGUID removed from runtime blacklist",
		zap.String("aaguid", normalized),
	)
	return true
}

// IsBlacklisted checks if an AAGUID is currently blacklisted
func (v *AAGUIDValidator) IsBlacklisted(aaguid []byte) bool {
	if !v.config.Enabled {
		return false
	}
	normalized := v.normalizeBytes(aaguid)
	return v.blacklist[normalized]
}

// GetBlacklist returns the current blacklist as a slice of hex strings
func (v *AAGUIDValidator) GetBlacklist() []string {
	result := make([]string, 0, len(v.blacklist))
	for aaguid := range v.blacklist {
		result = append(result, aaguid)
	}
	return result
}
