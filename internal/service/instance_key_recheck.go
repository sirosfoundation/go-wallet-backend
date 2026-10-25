package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// Stored instance-key evidence is not trusted forever. Each time a stored
// record backs a decision (a WIA, the assurance preview) it is checked again:
// a certificate in its chain may have been revoked since it was submitted, or
// the chain may have expired. A record kind that has a status source registers
// an InstanceKeyEvidenceRechecker (android_key does; FIDO2 evidence is a fact
// about key creation and needs none).
//
// What the caller sees of a record that fails:
//
//   - revoked: the record is marked revoked in the store (never deleted) and
//     reads as no evidence, so instance_key is "none" and wscd_type unknown;
//   - expired, or a legacy record that cannot be re-checked: no evidence
//     (home unknown); nothing is changed in the store;
//   - the status source is unavailable: an error wrapping
//     ErrWIAKeyAttestationUnavailable. A WIA is then refused (HTTP 503); a
//     read-only path that cannot return 503 treats the evidence as absent.
//
// A fresh, valid re-submission replaces a revoked record whatever its rank
// (KeyAttestationRecord.Supersedes).

// RecheckVerdict is the outcome of re-checking a stored record.
type RecheckVerdict int

const (
	// RecheckGood: the record may be used.
	RecheckGood RecheckVerdict = iota
	// RecheckRevoked: a certificate of the evidence was revoked.
	RecheckRevoked
	// RecheckExpired: the evidence's chain is past its validity.
	RecheckExpired
	// RecheckUnknown: the record cannot be re-checked (legacy, no serials).
	RecheckUnknown
)

// Fixed reasons recorded on revoked marks and in logs.
const (
	RecheckReasonRevoked = "status_list_revoked"
	RecheckReasonExpired = "chain_expired"
	RecheckReasonLegacy  = "legacy_no_serials"
)

// RecheckResult is what an InstanceKeyEvidenceRechecker found.
type RecheckResult struct {
	Verdict RecheckVerdict
	// Reason is one of the RecheckReason* values.
	Reason string
	// Serial is the revoked serial (hex) for RecheckRevoked, for the log.
	Serial string
}

// InstanceKeyEvidenceRechecker re-verifies stored evidence of one kind. It
// returns an error (which the caller wraps in ErrWIAKeyAttestationUnavailable)
// when it cannot judge.
type InstanceKeyEvidenceRechecker interface {
	Kind() domain.KeyEvidenceKind
	Recheck(ctx context.Context, rec *domain.KeyAttestationRecord, now time.Time) (RecheckResult, error)
}

// Kind implements InstanceKeyEvidenceRechecker.
func (v *AndroidKeyAttestationVerifier) Kind() domain.KeyEvidenceKind {
	return domain.KeyEvidenceAndroidKey
}

// instanceKeyChecker applies the registered rechecks to stored records. It
// is shared by every service that reads instance-key evidence so they all
// give the same answer.
type instanceKeyChecker struct {
	logger   *zap.Logger
	now      func() time.Time
	rechecks map[domain.KeyEvidenceKind]InstanceKeyEvidenceRechecker
}

func newInstanceKeyChecker(logger *zap.Logger) *instanceKeyChecker {
	return &instanceKeyChecker{
		logger:   logger.Named("instance-key-recheck"),
		now:      func() time.Time { return time.Now().UTC() },
		rechecks: make(map[domain.KeyEvidenceKind]InstanceKeyEvidenceRechecker),
	}
}

func (c *instanceKeyChecker) register(r InstanceKeyEvidenceRechecker) { c.rechecks[r.Kind()] = r }

// usable returns rec when it may back a decision now, nil when it is no
// evidence, and an error wrapping ErrWIAKeyAttestationUnavailable when that
// cannot be decided. A nil checker (or one without a recheck for a kind that
// needs it) fails closed for android_key records.
func (c *instanceKeyChecker) usable(ctx context.Context, store storage.KeyAttestationStore, rec *domain.KeyAttestationRecord) (*domain.KeyAttestationRecord, error) {
	if rec == nil {
		return nil, nil
	}
	n := *rec
	n.Normalize()
	logger := zap.NewNop()
	if c != nil {
		logger = c.logger
	}
	jkt := n.KeyThumbprint
	if len(jkt) > 8 {
		jkt = jkt[:8] + "..."
	}
	if n.Revoked() {
		instanceKeyRecheck.WithLabelValues("already_revoked").Inc()
		return nil, nil
	}
	var rc InstanceKeyEvidenceRechecker
	if c != nil {
		rc = c.rechecks[n.Kind]
	}
	if rc == nil {
		if n.Kind == domain.KeyEvidenceAndroidKey {
			// Evidence that needs a status check and has no checker wired is
			// not evidence.
			instanceKeyRecheck.WithLabelValues("unavailable").Inc()
			logger.Warn("android_key evidence cannot be re-checked: no checker wired; treating as none", zap.String("jkt", jkt))
			return nil, nil
		}
		return rec, nil
	}
	now := c.now()
	res, err := rc.Recheck(ctx, &n, now)
	if err != nil {
		instanceKeyRecheck.WithLabelValues("unavailable").Inc()
		logger.Warn("stored instance key evidence cannot be re-checked", zap.String("jkt", jkt), zap.Error(err))
		return nil, fmt.Errorf("%w: %v", ErrWIAKeyAttestationUnavailable, err)
	}
	switch res.Verdict {
	case RecheckGood:
		instanceKeyRecheck.WithLabelValues("ok").Inc()
		return rec, nil
	case RecheckRevoked:
		instanceKeyRecheck.WithLabelValues("revoked").Inc()
		marked := false
		if store != nil {
			ok, err := store.MarkKeyRevoked(ctx, n.KeyThumbprint, n.ChainFingerprint, res.Reason, now)
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("failed to mark instance key evidence revoked", zap.String("jkt", jkt), zap.Error(err))
			}
			marked = ok
		}
		logger.Warn("stored instance key evidence is revoked; treating as none",
			zap.String("jkt", jkt), zap.String("reason", res.Reason), zap.String("serial", res.Serial), zap.Bool("marked", marked))
	case RecheckExpired:
		instanceKeyRecheck.WithLabelValues("expired").Inc()
		logger.Info("stored instance key evidence has expired; treating as none", zap.String("jkt", jkt), zap.String("reason", res.Reason))
	default:
		instanceKeyRecheck.WithLabelValues("legacy_unknown").Inc()
		logger.Info("stored instance key evidence cannot be re-checked; treating as none", zap.String("jkt", jkt), zap.String("reason", res.Reason))
	}
	return nil, nil
}
