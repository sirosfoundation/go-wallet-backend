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
//   - expired, no longer qualifying under the CURRENT configuration (a
//     tightened allowlist, or reject-mode boot/patch requirements), or a
//     legacy record that cannot be re-checked: no evidence (home unknown);
//     nothing is changed in the store, so relaxing the configuration again
//     restores a record that was only tightened away;
//   - the status source is unavailable: an error wrapping
//     ErrWIAKeyAttestationUnavailable. A WIA is then refused (HTTP 503); a
//     read-only path that cannot return 503 treats the evidence as absent.
//
// A fresh, valid re-submission replaces a record that is no longer good
// whatever its rank: a revoked record by Supersedes, and one that is merely
// stale (expired, no longer qualifying, legacy, revoked but not marked yet)
// because the submission path replaces it in one conditional write
// (replaceStale), so the no-downgrade rule only ever protects evidence that
// still stands.

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
	// RecheckNotQualifying: the current configuration no longer accepts what
	// the record says (a tightened allowlist or boot/patch requirement).
	RecheckNotQualifying
)

// Fixed reasons recorded on revoked marks and in logs.
const (
	RecheckReasonRevoked = "status_list_revoked"
	RecheckReasonExpired = "chain_expired"
	RecheckReasonLegacy  = "legacy_no_serials"
	// RecheckReasonNoChecker: an android_key record and nothing wired to check it.
	RecheckReasonNoChecker = "no_checker"
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

// evaluate decides about one record without touching the store. rc is nil
// when no recheck is registered for the kind. A nil result with a nil error
// means the record is no evidence; a non-nil result carries the verdict.
func (c *instanceKeyChecker) evaluate(ctx context.Context, n *domain.KeyAttestationRecord) (RecheckResult, bool, error) {
	var rc InstanceKeyEvidenceRechecker
	if c != nil {
		rc = c.rechecks[n.Kind]
	}
	if rc == nil {
		if n.Kind == domain.KeyEvidenceAndroidKey {
			// Evidence that needs a status check and has no checker wired is
			// not evidence.
			return RecheckResult{Verdict: RecheckUnknown, Reason: RecheckReasonNoChecker}, true, nil
		}
		return RecheckResult{Verdict: RecheckGood}, false, nil
	}
	res, err := rc.Recheck(ctx, n, c.clock())
	return res, true, err
}

func shortJKT(n *domain.KeyAttestationRecord) string {
	if len(n.KeyThumbprint) > 8 {
		return n.KeyThumbprint[:8] + "..."
	}
	return n.KeyThumbprint
}

// clock is the checker's now; a nil checker uses the wall clock.
func (c *instanceKeyChecker) clock() time.Time {
	if c == nil {
		return time.Now().UTC()
	}
	return c.now()
}

func (c *instanceKeyChecker) log() *zap.Logger {
	if c == nil {
		return zap.NewNop()
	}
	return c.logger
}

// usable returns rec when it may back a decision now, nil when it is no
// evidence, and an error wrapping ErrWIAKeyAttestationUnavailable when that
// cannot be decided. A nil checker (or one without a recheck for a kind that
// needs it) fails closed for android_key records. A record found revoked is
// marked in the store.
func (c *instanceKeyChecker) usable(ctx context.Context, store storage.KeyAttestationStore, rec *domain.KeyAttestationRecord) (*domain.KeyAttestationRecord, error) {
	if rec == nil {
		return nil, nil
	}
	n := *rec
	n.Normalize()
	logger, jkt := c.log(), shortJKT(&n)
	if n.Revoked() {
		instanceKeyRecheck.WithLabelValues("already_revoked").Inc()
		return nil, nil
	}
	res, checked, err := c.evaluate(ctx, &n)
	if err != nil {
		instanceKeyRecheck.WithLabelValues("unavailable").Inc()
		logger.Warn("stored instance key evidence cannot be re-checked", zap.String("jkt", jkt), zap.Error(err))
		return nil, fmt.Errorf("%w: %v", ErrWIAKeyAttestationUnavailable, err)
	}
	if !checked {
		return rec, nil
	}
	switch res.Verdict {
	case RecheckGood:
		instanceKeyRecheck.WithLabelValues("ok").Inc()
		return rec, nil
	case RecheckRevoked:
		instanceKeyRecheck.WithLabelValues("revoked").Inc()
		marked := false
		if store != nil {
			ok, err := store.MarkKeyRevoked(ctx, n.KeyThumbprint, n.ChainFingerprint, res.Reason, c.clock())
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
	case RecheckNotQualifying:
		instanceKeyRecheck.WithLabelValues("not_qualifying").Inc()
		logger.Info("stored instance key evidence no longer qualifies under the current configuration; treating as none",
			zap.String("jkt", jkt), zap.String("reason", noHomeReasonLabel(res.Reason)))
	default:
		instanceKeyRecheck.WithLabelValues("legacy_unknown").Inc()
		logger.Info("stored instance key evidence cannot be re-checked; treating as none", zap.String("jkt", jkt), zap.String("reason", res.Reason))
	}
	return nil, nil
}

// replaceStale makes room for a freshly verified record rec without a
// two-step write. When the stored record for the same key would win the
// no-downgrade comparison (it ranks higher) but is no longer good (revoked on
// the list but not marked yet, expired, no longer qualifying, legacy), rec
// replaces it in ONE conditional store operation (ReplaceKeyEvidence, only if
// the stored record is still that chain). Nothing is marked beforehand, so a
// failed or interrupted write leaves the old record exactly as it was. Evidence
// that still stands is left alone: weaker evidence never replaces it. replaced
// is true when rec was written; the caller then must not write it again. An
// error wraps ErrWIAKeyAttestationUnavailable: whether the stored record
// stands, or the replacement, could not be decided.
func (c *instanceKeyChecker) replaceStale(ctx context.Context, store storage.KeyAttestationStore, rec *domain.KeyAttestationRecord) (replaced bool, err error) {
	if store == nil {
		return false, nil
	}
	existing, err := store.GetByKeyThumbprint(ctx, rec.KeyThumbprint)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("%w: look up stored instance key evidence: %w", ErrWIAKeyAttestationUnavailable, err)
	}
	if rec.Supersedes(existing) {
		return false, nil // the ordinary write replaces it
	}
	n := *existing
	n.Normalize()
	res, checked, err := c.evaluate(ctx, &n)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrWIAKeyAttestationUnavailable, err)
	}
	if !checked || res.Verdict == RecheckGood {
		return false, nil
	}
	ok, err := store.ReplaceKeyEvidence(ctx, rec, n.ChainFingerprint)
	if err != nil {
		return false, fmt.Errorf("%w: replace stale instance key evidence: %w", ErrWIAKeyAttestationUnavailable, err)
	}
	if ok {
		reason := res.Reason
		if res.Verdict == RecheckNotQualifying {
			reason = noHomeReasonLabel(reason)
		}
		instanceKeyRecheck.WithLabelValues("replaced_stale").Inc()
		c.log().Info("stale stored instance key evidence replaced by a fresh submission",
			zap.String("jkt", shortJKT(&n)), zap.String("reason", reason))
	}
	return ok, nil
}
