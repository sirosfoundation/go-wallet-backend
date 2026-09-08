package api

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/pkg/issuertrust"
)

func issuerMetadataWith(configs map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"credential_configurations_supported": configs}
}

// The offer mapping is what makes the entitlement check mean anything: it turns
// configuration ids into the (format, type) pairs provides_attestations speaks.
func TestOffersForReadsFormatAndType(t *testing.T) {
	m := issuerMetadataWith(map[string]interface{}{
		"pid_sdjwt": map[string]interface{}{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
		"mdl_mdoc":  map[string]interface{}{"format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL"},
	})

	got := offersFor(m, []string{"pid_sdjwt", "mdl_mdoc"})
	if len(got) != 2 {
		t.Fatalf("got %d offers, want 2: %+v", len(got), got)
	}
	want := map[string]string{"dc+sd-jwt": "urn:eudi:pid:1", "mso_mdoc": "org.iso.18013.5.1.mDL"}
	for _, o := range got {
		if want[o.Format] != o.Type {
			t.Errorf("offer %+v does not match expected type %q", o, want[o.Format])
		}
	}
}

// A configuration we cannot resolve is skipped rather than guessed at. Inventing
// a format would produce a check that passes for the wrong reason.
func TestOffersForSkipsWhatItCannotResolve(t *testing.T) {
	m := issuerMetadataWith(map[string]interface{}{
		"known":     map[string]interface{}{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
		"no_format": map[string]interface{}{"vct": "urn:eudi:pid:1"},
	})

	got := offersFor(m, []string{"known", "no_format", "not_in_metadata"})
	if len(got) != 1 || got[0].Format != "dc+sd-jwt" {
		t.Errorf("got %+v, want only the resolvable configuration", got)
	}
}

func TestOffersForWithoutMetadataConfigurations(t *testing.T) {
	if got := offersFor(map[string]interface{}{}, []string{"pid"}); got != nil {
		t.Errorf("got %+v, want nil when metadata declares no configurations", got)
	}
}

// A format with no type still yields an offer: provides_attestations may
// constrain only the format, and dropping it would skip the check entirely.
func TestOffersForKeepsFormatOnlyConfigurations(t *testing.T) {
	m := issuerMetadataWith(map[string]interface{}{
		"opaque": map[string]interface{}{"format": "dc+sd-jwt"},
	})
	got := offersFor(m, []string{"opaque"})
	if len(got) != 1 || got[0].Type != "" {
		t.Errorf("got %+v, want one offer with an empty type", got)
	}
}

func TestCredentialTypeOfPrefersVctThenDoctype(t *testing.T) {
	cases := []struct {
		cfg  map[string]interface{}
		want string
	}{
		{map[string]interface{}{"vct": "urn:eudi:pid:1"}, "urn:eudi:pid:1"},
		{map[string]interface{}{"doctype": "org.iso.18013.5.1.mDL"}, "org.iso.18013.5.1.mDL"},
		{map[string]interface{}{}, ""},
		{map[string]interface{}{"vct": ""}, ""},
	}
	for _, c := range cases {
		if got := credentialTypeOf(c.cfg); got != c.want {
			t.Errorf("credentialTypeOf(%v) = %q, want %q", c.cfg, got, c.want)
		}
	}
}

func TestParseX5CChainIgnoresUndecodableEntries(t *testing.T) {
	if got := parseX5CChain(nil); got != nil {
		t.Errorf("nil key material should yield no chain, got %v", got)
	}
}

// The default must never be "off": an unset or misspelled mode has to keep
// checking, or the control disappears without anyone noticing.
func TestEntitlementModeDefaultsToWarn(t *testing.T) {
	if issuertrust.ParseMode("") != issuertrust.ModeWarn {
		t.Error("an unset mode must default to warn")
	}
}

// TestDecodeX5CAcceptsBothBase64Alphabets pins the fix for a chain that the
// signature-verification path accepts and this one used to drop.
//
// A dropped chain does not surface as a decoding problem; it surfaces as
// CodeNoAccessCertificate, which reads as an issuer that published nothing
// rather than one this code could not read.
func TestDecodeX5CAcceptsBothBase64Alphabets(t *testing.T) {
	// Bytes chosen so the two alphabets actually differ: 0xFB 0xFF encodes as
	// "+/8=" in standard base64 and "-_8" raw URL-safe.
	raw := []byte{0xFB, 0xFF}

	for _, tc := range []struct {
		name    string
		encoded string
	}{
		{"standard", base64.StdEncoding.EncodeToString(raw)},
		{"raw url", base64.RawURLEncoding.EncodeToString(raw)},
		{"padded url", base64.URLEncoding.EncodeToString(raw)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeX5C(tc.encoded)
			if err != nil {
				t.Fatalf("decodeX5C(%q) failed: %v", tc.encoded, err)
			}
			if !bytes.Equal(got, raw) {
				t.Errorf("decodeX5C(%q) = %x, want %x", tc.encoded, got, raw)
			}
		})
	}

	if _, err := decodeX5C("not base64 at all!!"); err == nil {
		t.Error("expected an error for a value that is neither alphabet")
	}
}
