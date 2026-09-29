package config

import (
	"testing"
	"time"
)

func TestASLegacyConfig_SunsetBoundary(t *testing.T) {
	sunset := time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)
	l := ASLegacyConfig{Enabled: true, SunsetDate: sunset.Format(time.RFC3339)}

	if !l.Active(sunset.Add(-time.Nanosecond)) || l.SunsetPassed(sunset.Add(-time.Nanosecond)) {
		t.Error("legacy must be active just before the sunset instant")
	}
	if l.Active(sunset) || !l.SunsetPassed(sunset) {
		t.Error("the sunset instant itself counts as passed")
	}
	if l.Active(sunset.Add(time.Hour)) {
		t.Error("legacy must be inactive after sunset")
	}
}

func TestASLegacyConfig_ActiveMatrix(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour).Format(time.RFC3339)
	future := now.Add(time.Hour).Format(time.RFC3339)
	cases := []struct {
		name string
		l    ASLegacyConfig
		want bool
	}{
		{"enabled, no sunset", ASLegacyConfig{Enabled: true}, true},
		{"disabled, no sunset", ASLegacyConfig{}, false},
		{"enabled, future sunset", ASLegacyConfig{Enabled: true, SunsetDate: future}, true},
		{"enabled, past sunset", ASLegacyConfig{Enabled: true, SunsetDate: past}, false},
		{"disabled, future sunset", ASLegacyConfig{SunsetDate: future}, false},
		{"malformed sunset fails closed", ASLegacyConfig{Enabled: true, SunsetDate: "soon"}, false},
	}
	for _, tc := range cases {
		if got := tc.l.Active(now); got != tc.want {
			t.Errorf("%s: Active=%v want %v", tc.name, got, tc.want)
		}
	}
}

func TestASLegacyConfig_SunsetTime(t *testing.T) {
	if _, ok, err := (ASLegacyConfig{}).SunsetTime(); ok || err != nil {
		t.Errorf("empty date: ok=%v err=%v", ok, err)
	}
	if _, _, err := (ASLegacyConfig{SunsetDate: "2027-10-01"}).SunsetTime(); err == nil {
		t.Error("date without time must be rejected (RFC 3339 required)")
	}
	tm, ok, err := ASLegacyConfig{SunsetDate: "2027-10-01T00:00:00Z"}.SunsetTime()
	if err != nil || !ok || tm.Year() != 2027 {
		t.Errorf("valid date: %v %v %v", tm, ok, err)
	}
}

func TestConfig_LegacyAllowed(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour).UTC().Format(time.RFC3339)

	c := &Config{}
	c.AS.Legacy = ASLegacyConfig{Enabled: false, SunsetDate: past}
	if !c.LegacyAllowed(now) {
		t.Error("without the AS there is no alternative: HMAC stays allowed")
	}
	c.AS.Enabled = true
	if c.LegacyAllowed(now) {
		t.Error("AS enabled and sunset passed: legacy must be refused")
	}
	c.AS.Legacy = ASLegacyConfig{Enabled: true}
	if !c.LegacyAllowed(now) {
		t.Error("AS enabled and legacy active: allowed")
	}
}

func TestConfig_Validate_AS_LegacySunsetDate(t *testing.T) {
	cfg := validBaseConfig()
	cfg.AS.Enabled = true
	cfg.AS.SigningKeyPath = "/path/to/key"
	cfg.AS.RulesDir = "/tmp/rules"
	cfg.AS.Issuer = "https://as.example"

	cfg.AS.Legacy.SunsetDate = "next tuesday"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for malformed sunset date")
	}
	cfg.AS.Legacy.SunsetDate = "2027-10-01T00:00:00Z"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid sunset date rejected: %v", err)
	}
}
