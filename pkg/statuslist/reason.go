package statuslist

import (
	"context"
	"errors"
)

// Reason is the stable, machine-readable classification of a status list
// failure (see Classify). Every reason means the list is undetermined, never
// that the credential is valid.
type Reason string

// The reasons. An unclassified error is ReasonMalformed.
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

// classifiedError carries a Reason and keeps the original message and chain.
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

// Classify maps an error from loading a status list to its Reason; a context
// cancellation or deadline is ReasonBudgetExhausted.
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
