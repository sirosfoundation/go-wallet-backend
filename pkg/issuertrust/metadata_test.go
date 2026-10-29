package issuertrust

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func issuerMetadataWith(configs map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"credential_configurations_supported": configs}
}

func offersFromRaw(m map[string]interface{}, ids ...string) []Offer {
	return OffersFromConfigs(ConfigsFromRaw(m), ids)
}

// The offer mapping is what makes the entitlement check mean anything: it turns
// configuration ids into the (format, type) pairs provides_attestations speaks.
func TestOffersReadFormatAndType(t *testing.T) {
	m := issuerMetadataWith(map[string]interface{}{
		"pid_sdjwt": map[string]interface{}{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
		"mdl_mdoc":  map[string]interface{}{"format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL"},
	})

	got := offersFromRaw(m, "pid_sdjwt", "mdl_mdoc")
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

// The discriminator is chosen by format. A configuration carrying a registered
// value in the field its format ignores, and an unregistered one in the field
// that counts, must be checked against the one that counts.
func TestOfferForUsesTheFormatsDiscriminator(t *testing.T) {
	mdoc := OfferFor(ConfigView{Format: "mso_mdoc", VCT: "registered", Doctype: "unregistered"})
	if mdoc.Type != "unregistered" {
		t.Errorf("mdoc checked against %q, want its doctype", mdoc.Type)
	}
	sd := OfferFor(ConfigView{Format: "dc+sd-jwt", VCT: "unregistered", Doctype: "registered"})
	if sd.Type != "unregistered" {
		t.Errorf("sd-jwt checked against %q, want its vct", sd.Type)
	}
	if o := OfferFor(ConfigView{Format: "jwt_vc_json", Doctype: "x"}); o.Type != "x" {
		t.Errorf("unknown format falls back to whichever is set, got %q", o.Type)
	}
}

// An id the metadata does not define is skipped (it cannot be selected
// either). A defined configuration with no format is kept with an empty
// format, which matches no registered attestation: skipping it would leave a
// selectable configuration unchecked.
func TestOffersSkipOnlyWhatCannotBeSelected(t *testing.T) {
	m := issuerMetadataWith(map[string]interface{}{
		"known":     map[string]interface{}{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
		"no_format": map[string]interface{}{"vct": "urn:eudi:pid:1"},
	})

	got := offersFromRaw(m, "known", "no_format", "not_in_metadata")
	if len(got) != 2 || got[0].Format != "dc+sd-jwt" || got[1].Format != "" {
		t.Errorf("got %+v, want the known configuration and the format-less one, not the undefined id", got)
	}
}

// encoding/json, which the engine decodes the metadata with, matches member
// names case-insensitively and turns null into an empty, selectable
// configuration. Reading the raw map by exact name would skip both, and what
// is skipped is not checked.
func TestConfigsFromRawReadsTheWayTheEngineDoes(t *testing.T) {
	m := map[string]interface{}{
		"Credential_Configurations_Supported": map[string]interface{}{
			"upper": map[string]interface{}{"Format": "dc+sd-jwt", "VCT": "urn:x"},
			"null":  nil,
			"typed": map[string]interface{}{"format": 5},
		},
	}
	// "typed" has a wrongly typed format: the engine drops it from its parsed
	// metadata (it cannot be selected), so it must not become a finding that
	// refuses an otherwise entitled offer.
	got := offersFromRaw(m, "upper", "null", "typed")
	if len(got) != 2 {
		t.Fatalf("got %+v, want an offer for each selectable configuration and none for the dropped one", got)
	}
	if got[0].Format != "dc+sd-jwt" || got[0].Type != "urn:x" {
		t.Errorf("case-variant names not read: %+v", got[0])
	}
	if got[1].Format != "" {
		t.Errorf("a null configuration must be an empty offer: %+v", got[1])
	}
}

func TestConfigsFromRawTreatsAmbiguousMembersAsEmpty(t *testing.T) {
	m := map[string]interface{}{
		"credential_configurations_supported": map[string]interface{}{"a": map[string]interface{}{"format": "dc+sd-jwt", "vct": "v"}},
		"CREDENTIAL_CONFIGURATIONS_SUPPORTED": map[string]interface{}{"a": map[string]interface{}{"format": "dc+sd-jwt", "vct": "w"}},
	}
	got := offersFromRaw(m, "a")
	if len(got) != 1 || got[0].Format != "" {
		t.Errorf("ambiguous metadata must not resolve to either reading: %+v", got)
	}
}

func TestOffersWithoutMetadataConfigurations(t *testing.T) {
	if got := offersFromRaw(map[string]interface{}{}, "pid"); got != nil {
		t.Errorf("got %+v, want nil when metadata declares no configurations", got)
	}
}

func TestChainFromX5CWithoutEntriesYieldsNoChain(t *testing.T) {
	if got := ChainFromX5C(nil); got != nil {
		t.Errorf("nil key material should yield no chain, got %v", got)
	}
}

// The default must never be "off": an unset or misspelled mode has to keep
// checking, or the control disappears without anyone noticing.
func TestEntitlementModeDefaultsToWarn(t *testing.T) {
	if ParseMode("") != ModeWarn {
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

// ChainFromX5C keeps what parses, in order, in either base64 alphabet, and
// drops the rest: the resolver accepted the chain, so a dropped entry must not
// turn a signed document into "no access certificate" silently for the others.
func TestChainFromX5C(t *testing.T) {
	if got := ChainFromX5C(nil); got != nil {
		t.Errorf("nil x5c = %v, want nil", got)
	}
	leaf := wrpac(t, testIdentifier)
	other := plainCert(t)
	std := base64.StdEncoding.EncodeToString(leaf.Raw)
	rawURL := base64.RawURLEncoding.EncodeToString(other.Raw)

	got := ChainFromX5C([]string{std, "!!not base64!!", base64.StdEncoding.EncodeToString([]byte("not a cert")), rawURL})
	if len(got) != 2 || !got[0].Equal(leaf) || !got[1].Equal(other) {
		t.Fatalf("got %d certificates, want the leaf then the other, bad entries skipped", len(got))
	}
}
