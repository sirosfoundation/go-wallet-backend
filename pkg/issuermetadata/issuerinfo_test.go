package issuermetadata

import (
	"encoding/json"
	"testing"
)

func metadataWith(t *testing.T, issuerInfo any) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"issuer_info": issuerInfo})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRegistrationCertificateIsFoundByFormat(t *testing.T) {
	m := metadataWith(t, []any{
		map[string]any{"format": "registrar_dataset", "data": map[string]any{"x": 1}},
		map[string]any{"format": "registration_cert", "data": "aaa.bbb.ccc"},
	})
	if got := RegistrationCertificate(m); got != "aaa.bbb.ccc" {
		t.Errorf("RegistrationCertificate = %q", got)
	}
}

func TestRegistrationCertificateAbsent(t *testing.T) {
	if got := RegistrationCertificate(map[string]interface{}{}); got != "" {
		t.Errorf("want empty for metadata with no issuer_info, got %q", got)
	}
	m := metadataWith(t, []any{map[string]any{"format": "registrar_dataset", "data": "x"}})
	if got := RegistrationCertificate(m); got != "" {
		t.Errorf("want empty when no registration_cert element, got %q", got)
	}
}

// A malformed issuer_info must read as "absent", not raise — the caller tells
// "no certificate" from "a bad certificate" by what it gets back, and an error
// here would collapse that distinction at the wrong layer.
func TestMalformedIssuerInfoIsTreatedAsAbsent(t *testing.T) {
	for _, bad := range []any{"not-an-array", 42, map[string]any{"format": "registration_cert"}} {
		m := metadataWith(t, bad)
		if got := RegistrationCertificate(m); got != "" {
			t.Errorf("malformed issuer_info %v yielded %q, want empty", bad, got)
		}
	}
}

// The data member is a JSON value. A registration certificate is a compact JWT,
// so anything that is not a string is ignored rather than coerced.
func TestNonStringRegistrationCertIsIgnored(t *testing.T) {
	m := metadataWith(t, []any{
		map[string]any{"format": "registration_cert", "data": map[string]any{"jwt": "aaa.bbb.ccc"}},
	})
	if got := RegistrationCertificate(m); got != "" {
		t.Errorf("want empty for a non-string data member, got %q", got)
	}
}

func TestIssuerInfoPreservesCredentialIDs(t *testing.T) {
	m := metadataWith(t, []any{
		map[string]any{"format": "registration_cert", "data": "a.b.c", "credential_ids": []any{"pid"}},
	})
	entries := IssuerInfo(m)
	if len(entries) != 1 || len(entries[0].CredentialIDs) != 1 || entries[0].CredentialIDs[0] != "pid" {
		t.Errorf("credential_ids not preserved: %+v", entries)
	}
}
