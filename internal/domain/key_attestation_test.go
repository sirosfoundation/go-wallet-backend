package domain

import (
	"testing"
	"time"
)

func TestKeyAttestationRecord_NormalizeDefaultsOldRows(t *testing.T) {
	r := KeyAttestationRecord{AAGUID: "a"}
	r.Normalize()
	if r.Kind != KeyEvidenceFIDO2 || r.Home != KeyHomeFIDO2Hardware {
		t.Fatalf("got %q/%q", r.Kind, r.Home)
	}
	// A non-FIDO2 kind without a home stays homeless: never guessed.
	a := KeyAttestationRecord{Kind: KeyEvidenceAndroidKey}
	a.Normalize()
	if a.Home != "" {
		t.Fatalf("home guessed: %q", a.Home)
	}
}

func TestKeyAttestationRecord_Supersedes(t *testing.T) {
	rec := func(k KeyEvidenceKind, h KeyHome, uv bool) *KeyAttestationRecord {
		return &KeyAttestationRecord{Kind: k, Home: h, UV: uv}
	}
	cases := []struct {
		name     string
		next     *KeyAttestationRecord
		existing *KeyAttestationRecord
		want     bool
	}{
		{"no existing", rec(KeyEvidenceFIDO2, "", false), nil, true},
		{"stronger", rec(KeyEvidenceAndroidKey, KeyHomeStrongBox, false), rec(KeyEvidenceAndroidKey, KeyHomeTEE, false), true},
		{"weaker", rec(KeyEvidenceAppAttestAssertion, KeyHomeSecureEnclaveAsserted, false), rec(KeyEvidenceAndroidKey, KeyHomeTEE, false), false},
		{"absent home vs tee", rec(KeyEvidenceAndroidKey, "", false), rec(KeyEvidenceAndroidKey, KeyHomeTEE, false), false},
		{"equal rank other kind keeps first", rec(KeyEvidenceAndroidKey, KeyHomeStrongBox, false), rec(KeyEvidenceFIDO2, KeyHomeFIDO2Hardware, false), false},
		{"uv downgrade", rec(KeyEvidenceFIDO2, KeyHomeFIDO2Hardware, false), rec(KeyEvidenceFIDO2, KeyHomeFIDO2Hardware, true), false},
		{"uv upgrade", rec(KeyEvidenceFIDO2, KeyHomeFIDO2Hardware, true), rec(KeyEvidenceFIDO2, KeyHomeFIDO2Hardware, false), true},
		{"old row vs fido2", rec("", "", false), rec(KeyEvidenceFIDO2, KeyHomeFIDO2Hardware, false), true},
	}
	for _, c := range cases {
		if got := c.next.Supersedes(c.existing); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestKeyAttestationRecord_CloneDoesNotShareDeviceLocked(t *testing.T) {
	v := true
	r := &KeyAttestationRecord{DeviceLocked: &v}
	c := r.Clone()
	*c.DeviceLocked = false
	if !*r.DeviceLocked {
		t.Fatal("clone shares DeviceLocked")
	}
}

func TestSupersedes_RevokedEvidenceIsReplacedByAnything(t *testing.T) {
	strong := &KeyAttestationRecord{Kind: KeyEvidenceAndroidKey, Home: KeyHomeStrongBox}
	weak := &KeyAttestationRecord{Kind: KeyEvidenceAndroidKey, Home: KeyHomeTEE}
	if weak.Supersedes(strong) {
		t.Fatal("weaker evidence replaced live stronger evidence")
	}
	strong.RevokedAt = time.Now()
	if !strong.Revoked() || !weak.Supersedes(strong) {
		t.Fatal("a fresh record must replace revoked evidence whatever its rank")
	}
	other := &KeyAttestationRecord{Kind: KeyEvidenceFIDO2, Home: KeyHomeFIDO2Hardware}
	if !other.Supersedes(strong) {
		t.Fatal("revoked evidence blocked another kind")
	}
}

func TestClone_CopiesCertSerials(t *testing.T) {
	r := &KeyAttestationRecord{CertSerials: []string{"1", "2"}}
	c := r.Clone()
	c.CertSerials[0] = "x"
	if r.CertSerials[0] != "1" {
		t.Fatal("clone shares the serial slice")
	}
}
