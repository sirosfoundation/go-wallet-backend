package engine

// The consent component: what an OID4VP flow decides about the answer to its
// credential selection, independent of the transport that carried it.
//
// A transport (the WebSocket handler, the WMP bridge) translates its wire to a
// consentAnswer and hands it to the flow; the flow asks consentPolicy.Decide
// whether the answer is acceptable for the request it sent, and acts on the
// consentDecision or the *consentRefusal that comes back. Everything that
// decides, in particular the vetting against the verifier's DCQL query and
// what the sign request may carry afterwards, is here and only here. See
// consent_ws.go and wmp_consent.go for the two wires.

import (
	"encoding/json"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// More reason classes for a consent that cannot be acted on (the DCQL ones are
// in oid4vp_consent.go). Like those they are the only thing logged about a
// refusal.
const (
	consentReasonNoSelection = "consent_no_selection"
)

// consentAnswer is a transport-neutral answer to the credential selection: the
// user declined, or consented to answer some of the request's credential
// queries.
type consentAnswer struct {
	// Declined is true when the user declined. Reason is the client's own
	// words for it, only ever logged, never relayed.
	Declined bool
	Reason   string
	// Selections are the credential queries the user consented to answer. Only
	// the query id is common to the transports; the credential id and the
	// disclosed claims are members of the WebSocket wire alone (a WMP
	// select_credentials is a closed set and carries neither).
	Selections []ConsentSelection
	// Handle is the opaque selection handle of a transport that has one (WMP
	// OpenID4x 3.2.3.1). It is not interpreted: the sign request carries it
	// back unchanged.
	Handle string
}

// consentDecision is an answer the policy accepted.
type consentDecision struct {
	// Declined mirrors the answer; nothing below is set then.
	Declined bool
	Reason   string
	// Selected and Handle are what the user consented to. They are the only
	// source of what the sign request names (see signInclusion).
	Selected []ConsentSelection
	Handle   string
}

// signInclusion is what the sign request that follows a consenting answer
// carries: the credential references (the WebSocket wire still relays the
// credential id and the claims the client chose; every other member is empty)
// and the selection handle, unchanged.
func (d consentDecision) signInclusion() ([]CredentialRef, string) {
	refs := make([]CredentialRef, len(d.Selected))
	for i, s := range d.Selected {
		refs[i] = CredentialRef(s)
	}
	return refs, d.Handle
}

// consentRefusal is an answer the policy refused. Its text and its logging
// carry the reason class and, for a query id the request itself defines, that
// id; never a claim name or value.
type consentRefusal struct {
	Reason  string
	QueryID string
}

func (r *consentRefusal) Error() string {
	return "consent refused: " + r.Reason
}

// consentPolicy is the configured vetting of consent answers.
type consentPolicy struct {
	mode   config.DCQLConsentCheckMode
	logger *zap.Logger
}

func newConsentPolicy(cfg *config.Config, logger *zap.Logger) consentPolicy {
	mode := config.DCQLConsentCheckWarn
	if cfg != nil {
		mode = cfg.Presentation.DCQLConsentCheck.Effective()
	}
	return consentPolicy{mode: mode, logger: logger}
}

// Decide is the single decision "is this answer acceptable for this request".
// dcql is the verifier's query as the engine sent it (empty for a request
// without one, which has nothing to compare with).
//
// A declined answer is accepted as it is. A consenting one is refused when it
// selects nothing, and otherwise vetted against the query as configured by
// dcql_consent_check: off compares nothing, warn logs a violation and accepts,
// enforce refuses. A query that cannot be interpreted is a violation: "cannot
// compare" never means "allowed".
func (p consentPolicy) Decide(dcql json.RawMessage, a consentAnswer) (consentDecision, error) {
	if a.Declined {
		return consentDecision{Declined: true, Reason: a.Reason}, nil
	}
	if len(a.Selections) == 0 {
		return consentDecision{}, &consentRefusal{Reason: consentReasonNoSelection}
	}
	if err := p.vet(dcql, a.Selections); err != nil {
		return consentDecision{}, err
	}
	return consentDecision{Selected: a.Selections, Handle: a.Handle}, nil
}

// vet applies the configured dcql_consent_check. It returns a non-nil error
// only when the presentation must be refused; in warn mode a violation is
// logged and nil returned.
func (p consentPolicy) vet(dcql json.RawMessage, selected []ConsentSelection) error {
	if p.mode == config.DCQLConsentCheckOff || len(dcql) == 0 {
		return nil
	}
	v, err := checkConsentAgainstDCQL(dcql, selected)
	if err != nil {
		v = &consentViolation{Reason: consentReasonUnparseable}
	}
	if v == nil {
		return nil
	}
	if p.mode == config.DCQLConsentCheckEnforce {
		p.logger.Warn("consent refused: does not fit the DCQL query",
			zap.String("reason", v.Reason), zap.String("credential_query_id", loggableID(v.QueryID)))
		return &consentRefusal{Reason: v.Reason, QueryID: v.QueryID}
	}
	p.logger.Warn("consent does not fit the DCQL query (warn mode, proceeding)",
		zap.String("reason", v.Reason), zap.String("credential_query_id", loggableID(v.QueryID)))
	return nil
}

// consentObserver is implemented by a SessionTransport that reports the
// consent decision in its own terms (the WMP bridge answers the select_credentials
// action with -32602 and ends the flow so, as OpenID4x 3.2.3.1 says of a selection
// that is not in the request).
type consentObserver interface {
	// consentAwaited announces that the flow decides consents itself.
	consentAwaited(flowID string)
	// consentDecided reports the decision: refusal is the reason class of a
	// refusal, empty when the consent was accepted (or declined).
	consentDecided(flowID, refusal string)
}

// noteConsentAwaited tells the session's transport, if it cares, that flowID is
// about to wait for a consent.
func (s *Session) noteConsentAwaited(flowID string) {
	if o, ok := s.transport.(consentObserver); ok {
		o.consentAwaited(flowID)
	}
}

// noteConsentDecided tells the session's transport, if it cares, how the consent
// of flowID was decided.
func (s *Session) noteConsentDecided(flowID, refusal string) {
	if o, ok := s.transport.(consentObserver); ok {
		o.consentDecided(flowID, refusal)
	}
}
