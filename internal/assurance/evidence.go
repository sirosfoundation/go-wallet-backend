// Package assurance implements the backend-owned assurance policy: a set of
// SPOCP rules applied to evidence decides the values the Key Attestation
// carries. See docs/assurance-policy.md.
package assurance

import (
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// SchemaVersion is the version of the evidence slot schema (the fixed slot
// order of the evidence S-expression). Bump it whenever a slot is added,
// removed or reordered: positional matching means rules written against an
// older order silently stop matching. It is surfaced in startup logs, the
// audit line and the policy info metric.
const SchemaVersion = 1

// UVPresent is the Fido2Verified.UV value for proven user verification.
const UVPresent = "present"

// None is the atom emitted for an absent slot or value.
const None = "none"

// maxAtomLen bounds any single atom that originates from a client or from
// stored data, so a hostile value cannot bloat queries or logs.
const maxAtomLen = 256

// Fido2Verified is what the backend verified about the FIDO2/CTAP2 hardware
// attestation of every key in a batch (see domain.KeyAttestationRecord).
// Its presence means the attestation chain was accepted by the FIDO MDS3
// registry, which is rendered as (mds3 trusted).
type Fido2Verified struct {
	AAGUID string
	// UV is UVPresent when user verification was proven by the attestation
	// (the user-verified flag of its authenticator data, for every key in the
	// batch); anything else is rendered none.
	UV string
	// Cert identifies the attestation certificate; empty renders none.
	Cert string
}

// PlatformVerified is what the backend verified about the wallet instance's
// platform attestation (WalletInstance.AttestationSource).
type PlatformVerified struct {
	// Source is the stored attestation source string, verbatim:
	// platform_attested, development_attested or backend_attested.
	Source string
	// AppID is the verified application id; empty renders none.
	AppID string
}

// HSMVerified is what the backend verified about a hardware security module
// backing the keys. Reserved: nothing populates it yet.
type HSMVerified struct {
	ID string
}

// Claimed is what the client asserted in the request. It is never copied
// into the verified group. Empty strings render none.
type Claimed struct {
	Plugin             string
	KeyStorage         string
	UserAuthentication string
	Certification      string
}

// Evidence is the full input to the policy. Nil verified slots render none.
type Evidence struct {
	Fido2    *Fido2Verified
	Platform *PlatformVerified
	HSM      *HSMVerified
	Claimed  Claimed
}

// atom builds an atom from untrusted text. Empty or over-long values become
// none so a slot is never malformed and never carries unbounded data. The
// value is never concatenated into a string form: it is stored as an atom
// element, whose canonical encoding is length-prefixed, so characters such
// as parentheses or spaces cannot escape the atom.
func atom(v string) *sexp.Atom {
	if v == "" || len(v) > maxAtomLen {
		return sexp.NewAtom(None)
	}
	return sexp.NewAtom(v)
}

func field(tag, v string) *sexp.List { return sexp.NewList(tag, atom(v)) }

// Element renders the evidence as one S-expression with a fixed slot order,
// provenance first:
//
//	(evidence
//	  (verified
//	    (fido2 (mds3 trusted|none)(aaguid X)(uv present|none)(cert C))
//	    (platform (source S)(app_id A))
//	    (hsm (id I)))
//	  (claimed (plugin P)(key_storage T)(user_authentication T)(certification C)))
//
// An absent verified slot is (slot none). Every slot is always emitted:
// rules express "don't care" with the bare empty list, e.g. (platform),
// which still requires the slot to exist in the query.
func (e Evidence) Element() *sexp.List {
	fido2 := sexp.NewList("fido2", sexp.NewAtom(None))
	if e.Fido2 != nil {
		uv := None
		if e.Fido2.UV == UVPresent {
			uv = UVPresent
		}
		fido2 = sexp.NewList("fido2",
			field("mds3", "trusted"),
			field("aaguid", e.Fido2.AAGUID),
			field("uv", uv),
			field("cert", e.Fido2.Cert),
		)
	}
	platform := sexp.NewList("platform", sexp.NewAtom(None))
	if e.Platform != nil {
		platform = sexp.NewList("platform",
			field("source", e.Platform.Source),
			field("app_id", e.Platform.AppID),
		)
	}
	hsm := sexp.NewList("hsm", sexp.NewAtom(None))
	if e.HSM != nil {
		hsm = sexp.NewList("hsm", field("id", e.HSM.ID))
	}
	return sexp.NewList("evidence",
		sexp.NewList("verified", fido2, platform, hsm),
		sexp.NewList("claimed",
			field("plugin", e.Claimed.Plugin),
			field("key_storage", e.Claimed.KeyStorage),
			field("user_authentication", e.Claimed.UserAuthentication),
			field("certification", e.Claimed.Certification),
		),
	)
}
