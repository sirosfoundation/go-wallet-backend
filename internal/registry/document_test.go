package registry

import "testing"

func TestParseDocumentHeader_VCT(t *testing.T) {
	body := []byte(`{"vct": "urn:eudi:pid:1", "name": "PID", "description": "desc"}`)
	h := parseDocumentHeader(body)

	if got := h.identifier(); got != "urn:eudi:pid:1" {
		t.Errorf("identifier() = %q, want %q", got, "urn:eudi:pid:1")
	}
	if got := h.displayName(); got != "PID" {
		t.Errorf("displayName() = %q, want %q", got, "PID")
	}
	if got := h.displayDescription(); got != "desc" {
		t.Errorf("displayDescription() = %q, want %q", got, "desc")
	}
}

func TestParseDocumentHeader_Doctype(t *testing.T) {
	// mso_mdoc (MDDL) documents have no "vct" at all — "doctype" is the
	// identifier, and name/description live under display[], not top-level.
	body := []byte(`{
		"format": "mso_mdoc",
		"doctype": "org.iso.18013.5.1.mDL",
		"display": [{"locale": "en-US", "name": "mDL", "description": "Mobile Driving Licence"}]
	}`)
	h := parseDocumentHeader(body)

	if got := h.identifier(); got != "org.iso.18013.5.1.mDL" {
		t.Errorf("identifier() = %q, want %q", got, "org.iso.18013.5.1.mDL")
	}
	if got := h.displayName(); got != "mDL" {
		t.Errorf("displayName() = %q, want %q", got, "mDL")
	}
	if got := h.displayDescription(); got != "Mobile Driving Licence" {
		t.Errorf("displayDescription() = %q, want %q", got, "Mobile Driving Licence")
	}
}

func TestParseDocumentHeader_VCTPreferredOverDoctype(t *testing.T) {
	// A document should never have both, but vct wins if it somehow does —
	// sd-jwt credentials are the common case and vct is the more specific field.
	body := []byte(`{"vct": "urn:eudi:pid:1", "doctype": "eu.europa.ec.eudi.pid.1"}`)
	h := parseDocumentHeader(body)

	if got := h.identifier(); got != "urn:eudi:pid:1" {
		t.Errorf("identifier() = %q, want %q", got, "urn:eudi:pid:1")
	}
}

func TestParseDocumentHeader_NoIdentifier(t *testing.T) {
	h := parseDocumentHeader([]byte(`{"name": "no id"}`))
	if got := h.identifier(); got != "" {
		t.Errorf("identifier() = %q, want empty", got)
	}
}

func TestParseDocumentHeader_TopLevelNameWinsOverDisplay(t *testing.T) {
	body := []byte(`{
		"vct": "urn:test:1",
		"name": "Top Level Name",
		"display": [{"locale": "en-US", "name": "Display Name"}]
	}`)
	h := parseDocumentHeader(body)

	if got := h.displayName(); got != "Top Level Name" {
		t.Errorf("displayName() = %q, want %q", got, "Top Level Name")
	}
}

func TestParseDocumentHeader_NoDisplayNoTopLevel(t *testing.T) {
	h := parseDocumentHeader([]byte(`{"vct": "urn:test:1"}`))
	if got := h.displayName(); got != "" {
		t.Errorf("displayName() = %q, want empty", got)
	}
	if got := h.displayDescription(); got != "" {
		t.Errorf("displayDescription() = %q, want empty", got)
	}
}

func TestParseDocumentHeader_InvalidJSON(t *testing.T) {
	h := parseDocumentHeader([]byte(`not json`))
	if got := h.identifier(); got != "" {
		t.Errorf("identifier() = %q, want empty on invalid JSON", got)
	}
}
