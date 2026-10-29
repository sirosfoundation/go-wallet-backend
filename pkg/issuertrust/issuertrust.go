// Package issuertrust evaluates whether a PID or attestation provider is
// entitled to issue what it is offering.
//
// Under CIR (EU) 2025/848 a provider is a registered wallet-relying party in
// its own right, so it presents the same two documents a verifier does: an
// access certificate (WRPAC) proving who it is, and a registration certificate
// (WRPRC) saying what it registered for. Per ETSI TS 119 472-3 the provider
// puts both in its OpenID4VCI Issuer Metadata — the WRPAC as the signing
// certificate, the WRPRC in issuer_info.
//
// This package covers the three steps go-trust's model splits apart: verify the
// signature, extract the trust information, evaluate it. The metadata JWS is
// verified by the resolver before this package is called. The registration
// certificate is a different signed object, issued by a Registrar rather than
// by the provider: AuthenticateRegistrationCert verifies its signature and
// defers the question "is that a trusted Registrar" to the caller's trust path
// (the go-trust PDP). Evaluate reads the certificate's claims only when that
// came back AuthVerified, so a provider cannot vouch for its own registration.
package issuertrust

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
)

// Mode decides what a failed check does.
type Mode string

const (
	// ModeWarn records failures and still allows issuance. This is the default
	// on purpose: the ARF obligation to verify registration certificates only
	// applies 24 months after the amending Regulation enters into force, and
	// until then rejecting a provider that has not yet been registered would
	// break issuance that is currently legitimate.
	ModeWarn Mode = "warn"
	// ModeFail turns the same failures into a refusal to request issuance.
	ModeFail Mode = "fail"
	// ModeOff skips evaluation entirely.
	ModeOff Mode = "off"
)

// ParseMode maps configuration to a Mode, defaulting to warn.
//
// An unrecognised value becomes warn rather than off, so that a typo cannot
// silently disable the check — the same choice go-trust made for revocation.
func ParseMode(s string) Mode {
	switch Mode(s) {
	case ModeOff:
		return ModeOff
	case ModeFail:
		return ModeFail
	default:
		return ModeWarn
	}
}

// Code identifies why an evaluation failed, so a caller can act on the reason
// rather than parse a sentence.
type Code string

const (
	CodeNoAccessCertificate   Code = "no_access_certificate"
	CodeNotWRPAC              Code = "access_certificate_not_wrpac"
	CodeNoRegistrationCert    Code = "no_registration_certificate"
	CodeRegistrationMalformed Code = "registration_certificate_malformed"
	CodeRegistrationExpired   Code = "registration_certificate_expired"
	CodeRegistrationOverlong  Code = "registration_certificate_validity_too_long"
	CodeBindingMismatch       Code = "registration_certificate_not_bound"
	CodeNotProvider           Code = "not_an_attestation_provider"
	CodeTypeNotRegistered     Code = "attestation_type_not_registered"
	// CodeRegistrationUnverified means the registration certificate's signature
	// could not be verified (or nobody checked). Its claims are then not used.
	CodeRegistrationUnverified Code = "registration_certificate_unverified"
	// CodeRegistrarNotTrusted means the signature is valid but the trust
	// evaluation did not recognise the signer as a Registrar.
	CodeRegistrarNotTrusted Code = "registrar_not_trusted"
	// CodeAccessCertificateNotTrusted means nothing established that the
	// certificate chain that signed the metadata (the WRPAC) is trusted.
	CodeAccessCertificateNotTrusted Code = "access_certificate_not_trusted"
)

// Bounds on what a Decision carries. The values come from issuer-controlled
// documents and the decision is reported to clients, so none of it is
// unbounded and no finding message contains issuer text.
const (
	// MaxFindings caps Decision.Findings; the rest are counted, not listed.
	MaxFindings = 16
	// MaxCredentialTypeLen caps Finding.CredentialType, in bytes.
	MaxCredentialTypeLen = 128
	// MaxEntitlements and MaxEntitlementLen cap the display-only Entitlements.
	MaxEntitlements   = 16
	MaxEntitlementLen = 256
)

// Finding is one thing that did not check out.
type Finding struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	// CredentialType names the offered type when the finding is about one. It
	// is issuer-controlled: sanitised and at most MaxCredentialTypeLen bytes.
	CredentialType string `json:"credential_type,omitempty"`
}

// Decision is the outcome of evaluating a provider.
type Decision struct {
	// Allowed is whether issuance may proceed. In warn mode it stays true even
	// with findings; the findings are still reported so a wallet can surface them.
	Allowed bool `json:"allowed"`
	// Mode records which mode produced this decision, so a caller can tell
	// "passed" apart from "would have failed but we are in warn mode".
	Mode Mode `json:"mode"`
	// Evaluated is false when there was nothing to evaluate against — no
	// registration certificate, or mode off. It is deliberately distinct from
	// Allowed: "not checked" must never read as "checked and fine".
	Evaluated bool      `json:"evaluated"`
	Findings  []Finding `json:"findings,omitempty"`
	// FindingsTruncated is true when more than MaxFindings findings arose.
	// Allowed already reflects all of them.
	FindingsTruncated bool `json:"findings_truncated,omitempty"`
	// Entitlements is what the registration certificate claimed, for display.
	Entitlements []string `json:"entitlements,omitempty"`
	// Subject is the provider identifier from the registration certificate.
	Subject string `json:"subject,omitempty"`
}

// Offer is a credential the provider proposes to issue, in the terms
// provides_attestations uses.
type Offer struct {
	// Format is an OpenID4VCI credential format identifier, e.g. "dc+sd-jwt".
	Format string
	// Type is the vct for SD-JWT or the doctype for mdoc. May be empty, in
	// which case only the format is matched.
	Type string
}

// Input is everything needed to evaluate. The metadata signature must already
// have been verified by the resolver; the registration certificate's own
// signature is reported through RegistrationAuth.
type Input struct {
	// Chain is the certificate chain that signed the Issuer Metadata, leaf
	// first. Its signature has already been checked by the resolver.
	Chain []*x509.Certificate
	// RegistrationCert is the compact WRPRC JWT from issuer_info, if present.
	RegistrationCert string
	// Offers are the credentials the wallet is about to request.
	Offers []Offer
	// ChainAnchored says the trust path accepted Chain as a trusted issuer
	// chain. The profile check below is about its shape, not who vouches for
	// it, and a WRPRC is public: without this, anyone could mint a certificate
	// carrying a victim's organisation identifier and present the victim's
	// registration certificate beside it. The zero value is false.
	ChainAnchored bool
	// RegistrationAuth is the outcome of authenticating RegistrationCert's
	// signer (see AuthenticateRegistrationCert). The zero value is
	// AuthUnchecked, so a caller that forgets this step gets findings and no
	// claims from an unauthenticated document, never a pass.
	RegistrationAuth AuthResult
}

// Evaluate applies the wallet-side checks of ARF §6.6.2.3.
func Evaluate(in Input, mode Mode) *Decision {
	d := &Decision{Allowed: true, Mode: mode}
	if mode == ModeOff {
		return d
	}

	if len(in.Chain) == 0 {
		return d.add(mode, Finding{
			Code:    CodeNoAccessCertificate,
			Message: "issuer metadata was not signed by a certificate chain",
		})
	}

	if !in.ChainAnchored {
		d.add(mode, Finding{
			Code:    CodeAccessCertificateNotTrusted,
			Message: "the certificate that signed the issuer metadata is not known to be trusted",
		})
	}

	// The chain must actually be a WRPAC. Accepting any chain the trust
	// registry happens to know would let a document-signing certificate stand
	// in for an access certificate.
	if err := rpcert.NewWRPACProfile().ValidateCredential(in.Chain[0]); err != nil {
		d.add(mode, Finding{
			Code:    CodeNotWRPAC,
			Message: "access certificate does not meet the WRPAC profile",
		})
	}

	if in.RegistrationCert == "" {
		// No registration certificate is not the same as a bad one. Say so, and
		// leave Evaluated false so nothing downstream reads this as a pass.
		return d.add(mode, Finding{
			Code:    CodeNoRegistrationCert,
			Message: "issuer metadata carries no registration certificate in issuer_info",
		})
	}

	// Nothing below may read the document's claims until its signer has been
	// authenticated: the metadata signature vouches for the metadata, not for
	// the registration certificate inside it, so a provider with a valid WRPAC
	// could otherwise write its own provides_attestations.
	switch in.RegistrationAuth {
	case AuthVerified:
	case AuthUntrustedRegistrar:
		return d.add(mode, Finding{
			Code:    CodeRegistrarNotTrusted,
			Message: "registration certificate was not issued by a trusted registrar",
		})
	default:
		return d.add(mode, Finding{
			Code:    CodeRegistrationUnverified,
			Message: "registration certificate signature could not be verified",
		})
	}

	payload, err := rpcert.ParseWRPRCJWTPayload(in.RegistrationCert)
	if err != nil {
		return d.add(mode, Finding{
			Code:    CodeRegistrationMalformed,
			Message: "registration certificate is not a readable rc-wrp+jwt",
		})
	}
	ent, err := rpcert.ParseWRPRCClaims(payload)
	if err != nil {
		return d.add(mode, Finding{
			Code:    CodeRegistrationMalformed,
			Message: "registration certificate claims could not be parsed",
		})
	}

	d.Evaluated = true
	d.Entitlements = boundedList(ent.EntitlementURIs, MaxEntitlements, MaxEntitlementLen)
	d.Subject = sanitizeText(ent.RPIdentifier, MaxEntitlementLen)

	// Two different validity questions, and conflating them is how one of them
	// stops being asked. CheckWRPRCValidityPeriod is a conformance check on the
	// document — GEN-5.2.4-08 caps validity at twelve months from issuance —
	// and says nothing about whether the certificate is current.
	if err := rpcert.CheckWRPRCValidityPeriod(ent); err != nil {
		d.add(mode, Finding{
			Code:    CodeRegistrationOverlong,
			Message: "registration certificate validity period is not conformant",
		})
	}
	// Whether it is current has to be asked separately. RPEntitlements.IsValid
	// cannot be used: the parser deliberately leaves RegistrationStatus unknown
	// because status is the caller's to determine, so IsValid would report
	// false for every parsed certificate.
	//
	// Note this is expiry only. Whether the registration was suspended or
	// revoked is a status-list question, not something the document can answer
	// about itself.
	now := time.Now()
	switch {
	case ent.ValidFrom != nil && now.Before(*ent.ValidFrom):
		d.add(mode, Finding{
			Code:    CodeRegistrationExpired,
			Message: fmt.Sprintf("registration certificate is not valid until %s", ent.ValidFrom.Format(time.RFC3339)),
		})
	case ent.ValidUntil != nil && now.After(*ent.ValidUntil):
		d.add(mode, Finding{
			Code:    CodeRegistrationExpired,
			Message: fmt.Sprintf("registration certificate expired at %s", ent.ValidUntil.Format(time.RFC3339)),
		})
	}

	// The registration certificate must describe the party that signed the
	// metadata. Without this a provider could present a genuine certificate
	// belonging to somebody else entirely.
	if err := checkBinding(in.Chain[0], ent); err != nil {
		d.add(mode, Finding{
			Code:    CodeBindingMismatch,
			Message: "registration certificate does not describe the provider that signed the metadata",
		})
	}

	if !ent.IsAttestationProvider() {
		d.add(mode, Finding{
			Code:    CodeNotProvider,
			Message: "registered entitlements do not include a PID or attestation provider role",
		})
	}

	for _, o := range in.Offers {
		if !ent.ProvidesAttestation(o.Format, o.Type) {
			d.add(mode, Finding{
				Code:           CodeTypeNotRegistered,
				Message:        "provider is not registered to issue this credential",
				CredentialType: sanitizeText(o.Type, MaxCredentialTypeLen),
			})
		}
	}
	return d
}

// checkBinding ties the registration certificate to the access certificate, by
// organisation identifier and — when both carry one — service identifier.
func checkBinding(leaf *x509.Certificate, ent *rpcert.RPEntitlements) error {
	identity, err := rpcert.NewWRPACProfile().ExtractIdentity(leaf)
	if err != nil {
		return fmt.Errorf("could not read the access certificate's identity: %w", err)
	}
	orgID, _ := identity["organization_identifier"].(string)
	if orgID == "" {
		return errors.New("access certificate carries no organization identifier to bind against")
	}
	if err := rpcert.CheckWRPACWRPRCBinding(orgID, ent); err != nil {
		return fmt.Errorf("registration certificate does not describe this provider: %w", err)
	}
	// The service identifier is optional in TS5 — a party with one service and
	// no intermediary may omit it. go-trust treats an absent identifier on
	// either side as not-applicable, so this is called unconditionally rather
	// than second-guessing it here.
	svcID, _ := identity["service_identifier"].(string)
	if err := rpcert.CheckWRPACWRPRCServiceBinding(svcID, ent); err != nil {
		return fmt.Errorf("registration certificate is for a different service: %w", err)
	}
	return nil
}

// add records a finding and, in fail mode, withholds permission.
func (d *Decision) add(mode Mode, f Finding) *Decision {
	if mode == ModeFail {
		d.Allowed = false
	}
	if len(d.Findings) >= MaxFindings {
		d.FindingsTruncated = true
		return d
	}
	d.Findings = append(d.Findings, f)
	return d
}

// Summary is the decision as it is sent in flow progress: the verdict and the
// bounded findings, without the registration certificate's own content
// (Entitlements, Subject), which is issuer-controlled and display-only.
func (d *Decision) Summary() *Decision {
	c := *d
	c.Entitlements = nil
	c.Subject = ""
	return &c
}

// sanitizeText drops control and non-printable characters and cuts s to at
// most max bytes on a rune boundary.
func sanitizeText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func boundedList(in []string, maxN, maxLen int) []string {
	if len(in) > maxN {
		in = in[:maxN]
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, sanitizeText(v, maxLen))
	}
	return out
}
