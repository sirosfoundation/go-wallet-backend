package statuslist

import (
	"context"
	"errors"
)

// Reason names why a status list could not be used. It is the stable,
// machine-readable classification of a failure that the verified status list
// API reports (see Classify). None of the reasons means "the credential is
// valid"; every one of them means the list is undetermined.
type Reason string

// The reasons. Anything an error does not name explicitly is ReasonMalformed
// (the token was fetched but is not an acceptable Status List Token).
const (
	ReasonFetchFailed          Reason = "fetch_failed"
	ReasonUnsupportedMediaType Reason = "unsupported_media_type"
	ReasonSignatureInvalid     Reason = "signature_invalid"
	ReasonSignerUntrusted      Reason = "signer_untrusted"
	ReasonTrustUnavailable     Reason = "trust_unavailable"
	ReasonNoSignerKey          Reason = "no_signer_key"
	ReasonExpired              Reason = "expired"
	ReasonNotYetValid          Reason = "not_yet_valid"
	ReasonMalformed            Reason = "malformed"
	ReasonTooLarge             Reason = "too_large"
	ReasonBudgetExhausted      Reason = "budget_exhausted"
	ReasonListTooSmall         Reason = "list_too_small"
	ReasonURINotAllowed        Reason = "uri_not_allowed"
)

// classifiedError carries a Reason while keeping the original message and
// chain, so existing error text and errors.Is checks are unaffected.
type classifiedError struct {
	reason Reason
	err    error
}

func (e *classifiedError) Error() string { return e.err.Error() }
func (e *classifiedError) Unwrap() error { return e.err }

// classify tags err with reason.
func classify(reason Reason, err error) error {
	return &classifiedError{reason: reason, err: err}
}

// Classify maps an error from loading a status list to its Reason. A context
// cancellation or deadline is ReasonBudgetExhausted (the caller's time ran
// out, nothing about the list is known).
func Classify(err error) Reason {
	var ce *classifiedError
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrSignerUntrusted):
		return ReasonSignerUntrusted
	case errors.Is(err, ErrTrustUnavailable):
		return ReasonTrustUnavailable
	case errors.Is(err, ErrNoSignerKey):
		return ReasonNoSignerKey
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ReasonBudgetExhausted
	case errors.As(err, &ce):
		return ce.reason
	}
	return ReasonMalformed
}
