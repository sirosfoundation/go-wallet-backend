package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// KeyAttestationStore implements storage.KeyAttestationStore using MongoDB.
type KeyAttestationStore struct {
	collection *mongo.Collection
	// now is the clock the undo log ages by; nil means time.Now.
	now func() time.Time
}

// keyAttestationDoc is the stored shape: the record plus an optimistic
// concurrency revision (absent on documents written before it existed).
type keyAttestationDoc struct {
	domain.KeyAttestationRecord `bson:",inline"`
	Rev                         int64 `bson:"rev"`
	// UndoLog is the record's undo log (storage.UndoLog), nil on documents
	// written before it existed. Every write changes it together with the
	// record in one compare-and-set on Rev, so it never disagrees with it.
	UndoLog *storage.UndoLog[domain.KeyAttestationRecord] `bson:"undo_log,omitempty"`
}

// logged returns d's undo log with this write recorded (before: the record as it
// was, nil for a create), for the document that replaces d.
func (d *keyAttestationDoc) logged(now time.Time, token string, before *domain.KeyAttestationRecord) *storage.UndoLog[domain.KeyAttestationRecord] {
	var l storage.UndoLog[domain.KeyAttestationRecord]
	if d != nil && d.UndoLog != nil {
		l = append(l, *d.UndoLog...)
	}
	l.Push(now, token, before)
	return &l
}

// snapshot is the stored record as the write's before: normalized, without
// Previous, and with its own write token.
func (d *keyAttestationDoc) snapshot() *domain.KeyAttestationRecord {
	prev := d.KeyAttestationRecord
	prev.Normalize()
	prev.Previous = nil
	return &prev
}

// Every failed compare-and-set means another writer made progress, so a
// writer fails at most once per concurrent writer; 32 is far above any real
// concurrency on one key.
const markKeyAttestedMaxTries = 32

// MarkKeyAttested stores rec unless the stored record is stronger (see
// domain.KeyAttestationRecord.Supersedes): weaker or absent evidence never
// overwrites it, and that is not an error. The decision and the write are one
// compare-and-set on a revision, so two concurrent registrations cannot undo
// each other's decision.
//
// A write that lands sets rec.WriteToken to a fresh value and rec.Previous to
// the evidence it replaced (nil on first insert), for a conditional rollback; a
// write that does not land (weaker evidence) leaves both empty, so a rollback of
// it is a no-op.
func (s *KeyAttestationStore) MarkKeyAttested(ctx context.Context, rec *domain.KeyAttestationRecord) error {
	rec.WriteToken, rec.Previous = "", nil
	next := *rec.Clone()
	next.Normalize()
	next.Previous = nil
	next.WriteToken = storage.NewWriteToken()
	for try := 0; try < markKeyAttestedMaxTries; try++ {
		var cur keyAttestationDoc
		err := s.collection.FindOne(ctx, bson.M{"_id": rec.KeyThumbprint}).Decode(&cur)
		if err != nil && err != mongo.ErrNoDocuments {
			return fmt.Errorf("%w: mark key attested: %v", storage.ErrDatabase, err)
		}
		if err == mongo.ErrNoDocuments {
			if next.CreatedAt.IsZero() {
				next.CreatedAt = time.Now().UTC()
			}
			_, err = s.collection.InsertOne(ctx, keyAttestationDoc{KeyAttestationRecord: next, Rev: 1, UndoLog: (*keyAttestationDoc)(nil).logged(undoClock(s.now), next.WriteToken, nil)})
			if err == nil {
				rec.CreatedAt = next.CreatedAt
				rec.WriteToken = next.WriteToken
				return nil
			}
			if mongo.IsDuplicateKeyError(err) {
				continue // someone inserted first: re-evaluate against it
			}
			return fmt.Errorf("%w: mark key attested: %v", storage.ErrDatabase, err)
		}
		if !next.Supersedes(&cur.KeyAttestationRecord) {
			return nil
		}
		next.CreatedAt = cur.CreatedAt
		res, err := s.collection.ReplaceOne(ctx, casFilter(rec.KeyThumbprint, &cur), keyAttestationDoc{KeyAttestationRecord: next, Rev: cur.Rev + 1, UndoLog: cur.logged(undoClock(s.now), next.WriteToken, cur.snapshot())})
		if err != nil {
			return fmt.Errorf("%w: mark key attested: %v", storage.ErrDatabase, err)
		}
		if res.MatchedCount == 1 {
			rec.CreatedAt = next.CreatedAt
			rec.WriteToken = next.WriteToken
			rec.Previous = cur.snapshot()
			return nil
		}
	}
	return fmt.Errorf("%w: mark key attested: too much contention", storage.ErrDatabase)
}

// casFilter matches exactly the stored document cur was read from: its
// revision (absent on legacy documents) and its write token (absent before the
// field existed). The token is unique per write, so a delete-then-reinsert of
// the same thumbprint can never match a stale read by revision alone.
func casFilter(thumbprint string, cur *keyAttestationDoc) bson.M {
	f := bson.M{"_id": thumbprint}
	if cur.Rev == 0 {
		f["rev"] = bson.M{"$exists": false}
	} else {
		f["rev"] = cur.Rev
	}
	if cur.WriteToken == "" {
		f["write_token"] = bson.M{"$exists": false}
	} else {
		f["write_token"] = cur.WriteToken
	}
	return f
}

func (s *KeyAttestationStore) GetByKeyThumbprint(ctx context.Context, thumbprint string) (*domain.KeyAttestationRecord, error) {
	var doc keyAttestationDoc
	err := s.collection.FindOne(ctx, bson.M{"_id": thumbprint}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("%w: get key attestation: %v", storage.ErrDatabase, err)
	}
	rec := doc.KeyAttestationRecord
	rec.Normalize()
	return &rec, nil
}

// RestoreIfUnchanged undoes the write that set written.WriteToken (see
// storage.UndoLog): the newest write's record goes back to what it replaced, an
// older write is spliced out and the newer writes' values stay. previous is
// ignored for records that have an undo log (the log, not what the caller read,
// says what the write replaced); it is used only for a record written before
// the log existed.
func (s *KeyAttestationStore) RestoreIfUnchanged(ctx context.Context, written, previous *domain.KeyAttestationRecord) error {
	if previous == nil {
		return storage.ErrNotFound
	}
	return s.rollback(ctx, written.KeyThumbprint, written.WriteToken, previous)
}

// DeleteIfUnchanged undoes the write that set writeToken, exactly as
// RestoreIfUnchanged does; a first insert is deleted.
func (s *KeyAttestationStore) DeleteIfUnchanged(ctx context.Context, thumbprint, writeToken string) error {
	return s.rollback(ctx, thumbprint, writeToken, nil)
}

// rollback is one compare-and-set on the revision per attempt, so the log and
// the record change together and a concurrent write or rollback makes it
// re-read. legacyPrevious serves a record that has no undo log (written before
// it existed): conditional on the current write token only.
func (s *KeyAttestationStore) rollback(ctx context.Context, thumbprint, writeToken string, legacyPrevious *domain.KeyAttestationRecord) error {
	if writeToken == "" {
		return storage.ErrNotFound
	}
	for try := 0; try < markKeyAttestedMaxTries; try++ {
		var cur keyAttestationDoc
		err := s.collection.FindOne(ctx, bson.M{"_id": thumbprint}).Decode(&cur)
		if errors.Is(err, mongo.ErrNoDocuments) {
			return storage.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("%w: roll back key attestation: %v", storage.ErrDatabase, err)
		}
		var (
			res *mongo.UpdateResult
			del *mongo.DeleteResult
		)
		if cur.UndoLog == nil {
			if cur.WriteToken != writeToken {
				return storage.ErrNotFound
			}
			if legacyPrevious == nil {
				del, err = s.collection.DeleteOne(ctx, casFilter(thumbprint, &cur))
			} else {
				restored := *legacyPrevious.Clone()
				restored.KeyThumbprint = thumbprint
				restored.Previous = nil
				restored.WriteToken = storage.NewWriteToken() // a restore is itself a new write
				res, err = s.collection.ReplaceOne(ctx, casFilter(thumbprint, &cur), keyAttestationDoc{KeyAttestationRecord: restored, Rev: cur.Rev + 1})
			}
		} else {
			log := append(storage.UndoLog[domain.KeyAttestationRecord](nil), *cur.UndoLog...)
			kind, before := log.Take(undoClock(s.now), writeToken)
			switch {
			case kind == storage.UndoMissing:
				return storage.ErrNotFound
			case kind == storage.UndoHead && before == nil:
				del, err = s.collection.DeleteOne(ctx, casFilter(thumbprint, &cur))
			case kind == storage.UndoHead:
				restored := *before.Clone()
				restored.KeyThumbprint = thumbprint
				restored.Previous = nil
				res, err = s.collection.ReplaceOne(ctx, casFilter(thumbprint, &cur), keyAttestationDoc{KeyAttestationRecord: restored, Rev: cur.Rev + 1, UndoLog: &log})
			default: // spliced: the record stays, only the log changes
				kept := cur
				kept.Rev = cur.Rev + 1
				kept.UndoLog = &log
				res, err = s.collection.ReplaceOne(ctx, casFilter(thumbprint, &cur), kept)
			}
		}
		if err != nil {
			return fmt.Errorf("%w: roll back key attestation: %v", storage.ErrDatabase, err)
		}
		if (res != nil && res.MatchedCount == 1) || (del != nil && del.DeletedCount == 1) {
			return nil
		}
		// Another writer made progress: re-read.
	}
	return fmt.Errorf("%w: roll back key attestation: too much contention", storage.ErrDatabase)
}

// MarkKeyRevoked implements storage.KeyAttestationStore. It is one
// compare-and-set on the revision that matches only the record with the given
// chain fingerprint that is not yet revoked, so a concurrent MarkKeyAttested
// that decided on the old document fails its own compare-and-set and
// re-evaluates. The revocation is a write of its own on top of the undo log: a
// rollback of the write that stored this record is spliced out below it and
// cannot undo it.
func (s *KeyAttestationStore) MarkKeyRevoked(ctx context.Context, thumbprint, chainFingerprint, reason string, at time.Time) (bool, error) {
	for try := 0; try < markKeyAttestedMaxTries; try++ {
		var cur keyAttestationDoc
		err := s.collection.FindOne(ctx, bson.M{"_id": thumbprint}).Decode(&cur)
		if errors.Is(err, mongo.ErrNoDocuments) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("%w: mark key revoked: %v", storage.ErrDatabase, err)
		}
		if cur.Revoked() || cur.ChainFingerprint != chainFingerprint {
			return false, nil
		}
		next := cur
		next.RevokedAt = at.UTC()
		next.RevokedReason = reason
		next.WriteToken = storage.NewWriteToken()
		next.Rev = cur.Rev + 1
		next.UndoLog = cur.logged(undoClock(s.now), next.WriteToken, cur.snapshot())
		res, err := s.collection.ReplaceOne(ctx, casFilter(thumbprint, &cur), next)
		if err != nil {
			return false, fmt.Errorf("%w: mark key revoked: %v", storage.ErrDatabase, err)
		}
		if res.MatchedCount == 1 {
			return true, nil
		}
	}
	return false, fmt.Errorf("%w: mark key revoked: too much contention", storage.ErrDatabase)
}

// ReplaceKeyEvidence implements storage.KeyAttestationStore: one compare-and-set
// on the revision, conditioned on the stale record's chain fingerprint.
func (s *KeyAttestationStore) ReplaceKeyEvidence(ctx context.Context, rec *domain.KeyAttestationRecord, staleChainFingerprint string) (bool, error) {
	next := *rec.Clone()
	next.Normalize()
	next.Previous = nil
	next.WriteToken = storage.NewWriteToken() // a replacement is a new write: no earlier rollback may undo it
	for try := 0; try < markKeyAttestedMaxTries; try++ {
		var cur keyAttestationDoc
		err := s.collection.FindOne(ctx, bson.M{"_id": rec.KeyThumbprint}).Decode(&cur)
		if err == mongo.ErrNoDocuments {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("%w: replace key evidence: %v", storage.ErrDatabase, err)
		}
		if cur.ChainFingerprint != staleChainFingerprint {
			return false, nil
		}
		next.CreatedAt = cur.CreatedAt
		res, err := s.collection.ReplaceOne(ctx, casFilter(rec.KeyThumbprint, &cur), keyAttestationDoc{KeyAttestationRecord: next, Rev: cur.Rev + 1, UndoLog: cur.logged(undoClock(s.now), next.WriteToken, cur.snapshot())})
		if err != nil {
			return false, fmt.Errorf("%w: replace key evidence: %v", storage.ErrDatabase, err)
		}
		if res.MatchedCount == 1 {
			rec.CreatedAt = next.CreatedAt
			rec.WriteToken = next.WriteToken
			rec.Previous = cur.snapshot()
			return true, nil
		}
	}
	return false, fmt.Errorf("%w: replace key evidence: too much contention", storage.ErrDatabase)
}
