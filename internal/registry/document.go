package registry

import "encoding/json"

// documentHeader holds the fields we can extract generically from a
// credential type metadata document, regardless of whether it's a VCTM
// (sd-jwt, identified by "vct") or an MDDL (mso_mdoc, identified by
// "doctype"). Both formats nest their human-readable name/description under
// a locale-keyed "display" array rather than top-level fields; a few
// top-level name/description/organization fields are also checked first for
// forward compatibility with documents that do set them directly.
type documentHeader struct {
	VCT            string         `json:"vct"`
	DocType        string         `json:"doctype"`
	Name           string         `json:"name"`
	Description    string         `json:"description"`
	Organization   string         `json:"organization"`
	Display        []displayEntry `json:"display"`
	AttestationLoS string         `json:"attestation_los"`
}

// displayEntry is a single locale's display properties within a "display"
// array, as used by both VCTM and MDDL documents.
type displayEntry struct {
	Locale      string `json:"locale"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// parseDocumentHeader best-effort parses the identifying fields out of a
// credential type metadata document. Parse errors are ignored; callers get
// the zero value, matching how header extraction has always been treated as
// advisory rather than required (the caller decides what to do when fields
// are missing).
func parseDocumentHeader(body []byte) documentHeader {
	var h documentHeader
	_ = json.Unmarshal(body, &h)
	return h
}

// identifier returns the document's identifier: its "vct" if present
// (sd-jwt), otherwise its "doctype" (mso_mdoc). Returns "" if neither is set.
func (h documentHeader) identifier() string {
	if h.VCT != "" {
		return h.VCT
	}
	return h.DocType
}

// displayName returns a top-level "name" if the document set one, otherwise
// the first display[] entry's name.
func (h documentHeader) displayName() string {
	if h.Name != "" {
		return h.Name
	}
	if len(h.Display) > 0 {
		return h.Display[0].Name
	}
	return ""
}

// displayDescription returns a top-level "description" if the document set
// one, otherwise the first display[] entry's description.
func (h documentHeader) displayDescription() string {
	if h.Description != "" {
		return h.Description
	}
	if len(h.Display) > 0 {
		return h.Display[0].Description
	}
	return ""
}
