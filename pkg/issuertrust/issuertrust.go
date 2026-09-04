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
// This package is the third of the three steps go-trust's model splits apart:
// verify the signature, extract the trust information, evaluate it. The first
// two happen before this package is called — the metadata resolver verifies the
// JWS, and go-trust's rpcert parses the WRPRC — so nothing here does I/O or
// signature checking, and nothing here can be fooled into believing it did.
package issuertrust

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

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
)

// Finding is one thing that did not check out.
type Finding struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	// CredentialType names the offered type when the finding is about one.
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

// Input is everything needed to evaluate, all of it already verified.
type Input struct {
	// Chain is the certificate chain that signed the Issuer Metadata, leaf
	// first. Its signature has already been checked by the resolver.
	Chain []*x509.Certificate
	// RegistrationCert is the compact WRPRC JWT from issuer_info, if present.
	RegistrationCert string
	// Offers are the credentials the wallet is about to request.
	Offers []Offer
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

	// The chain must actually be a WRPAC. Accepting any chain the trust
	// registry happens to know would let a document-signing certificate stand
	// in for an access certificate.
	if err := rpcert.NewWRPACProfile().ValidateCredential(in.Chain[0]); err != nil {
		d.add(mode, Finding{
			Code:    CodeNotWRPAC,
			Message: fmt.Sprintf("access certificate does not meet the WRPAC profile: %v", err),
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

	payload, err := rpcert.ParseWRPRCJWTPayload(in.RegistrationCert)
	if err != nil {
		return d.add(mode, Finding{
			Code:    CodeRegistrationMalformed,
			Message: fmt.Sprintf("registration certificate is not a readable rc-wrp+jwt: %v", err),
		})
	}
	ent, err := rpcert.ParseWRPRCClaims(payload)
	if err != nil {
		return d.add(mode, Finding{
			Code:    CodeRegistrationMalformed,
			Message: fmt.Sprintf("registration certificate claims could not be parsed: %v", err),
		})
	}

	d.Evaluated = true
	d.Entitlements = ent.EntitlementURIs
	d.Subject = ent.RPIdentifier

	// Two different validity questions, and conflating them is how one of them
	// stops being asked. CheckWRPRCValidityPeriod is a conformance check on the
	// document — GEN-5.2.4-08 caps validity at twelve months from issuance —
	// and says nothing about whether the certificate is current.
	if err := rpcert.CheckWRPRCValidityPeriod(ent); err != nil {
		d.add(mode, Finding{
			Code:    CodeRegistrationOverlong,
			Message: fmt.Sprintf("registration certificate is not conformant: %v", err),
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
			Message: err.Error(),
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
				Message:        fmt.Sprintf("provider is not registered to issue %s of type %q", o.Format, o.Type),
				CredentialType: o.Type,
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
	d.Findings = append(d.Findings, f)
	if mode == ModeFail {
		d.Allowed = false
	}
	return d
}
