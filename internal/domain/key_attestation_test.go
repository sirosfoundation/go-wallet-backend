package domain

import "testing"

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
