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
}

// keyAttestationDoc is the stored shape: the record plus an optimistic
// concurrency revision (absent on documents written before it existed).
type keyAttestationDoc struct {
	domain.KeyAttestationRecord `bson:",inline"`
	Rev                         int64 `bson:"rev"`
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
			_, err = s.collection.InsertOne(ctx, keyAttestationDoc{KeyAttestationRecord: next, Rev: 1})
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
		res, err := s.collection.ReplaceOne(ctx, casFilter(rec.KeyThumbprint, &cur), keyAttestationDoc{KeyAttestationRecord: next, Rev: cur.Rev + 1})
		if err != nil {
			return fmt.Errorf("%w: mark key attested: %v", storage.ErrDatabase, err)
		}
		if res.MatchedCount == 1 {
			rec.CreatedAt = next.CreatedAt
			rec.WriteToken = next.WriteToken
			prev := cur.KeyAttestationRecord
			prev.Normalize()
			prev.Previous = nil
			rec.Previous = &prev
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

// RestoreIfUnchanged replaces the record with previous by one compare-and-set on
// the thumbprint, the write token of the write being undone and the revision
// read with it; a record rewritten (or revoked, which rotates the token) in the
// meantime is left alone.
func (s *KeyAttestationStore) RestoreIfUnchanged(ctx context.Context, written, previous *domain.KeyAttestationRecord) error {
	if written.WriteToken == "" || previous == nil {
		return storage.ErrNotFound
	}
	var cur keyAttestationDoc
	err := s.collection.FindOne(ctx, bson.M{"_id": written.KeyThumbprint, "write_token": written.WriteToken}).Decode(&cur)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return storage.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("%w: restore key attestation: %v", storage.ErrDatabase, err)
	}
	restored := *previous.Clone()
	restored.KeyThumbprint = written.KeyThumbprint
	restored.Previous = nil
	restored.WriteToken = storage.NewWriteToken() // a restore is itself a new write
	result, err := s.collection.ReplaceOne(ctx, casFilter(written.KeyThumbprint, &cur), keyAttestationDoc{KeyAttestationRecord: restored, Rev: cur.Rev + 1})
	if err != nil {
		return fmt.Errorf("%w: restore key attestation: %v", storage.ErrDatabase, err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteIfUnchanged is one atomic filtered DeleteOne on the write token.
func (s *KeyAttestationStore) DeleteIfUnchanged(ctx context.Context, thumbprint, writeToken string) error {
	if writeToken == "" {
		return storage.ErrNotFound
	}
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": thumbprint, "write_token": writeToken})
	if err != nil {
		return fmt.Errorf("%w: delete key attestation: %v", storage.ErrDatabase, err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// MarkKeyRevoked implements storage.KeyAttestationStore. It is one atomic
// update that matches only the record with the given chain fingerprint that is
// not yet revoked, and bumps the revision so a concurrent MarkKeyAttested that
// decided on the old document fails its compare-and-set and re-evaluates.
func (s *KeyAttestationStore) MarkKeyRevoked(ctx context.Context, thumbprint, chainFingerprint, reason string, at time.Time) (bool, error) {
	res, err := s.collection.UpdateOne(ctx,
		bson.M{"_id": thumbprint, "chain_fingerprint": chainFingerprint, "revoked_at": bson.M{"$exists": false}},
		bson.M{
			// A new write token: a rollback of the write that stored this record
			// must not undo the revocation.
			"$set": bson.M{"revoked_at": at.UTC(), "revoked_reason": reason, "write_token": storage.NewWriteToken()},
			"$inc": bson.M{"rev": 1},
		})
	if err != nil {
		return false, fmt.Errorf("%w: mark key revoked: %v", storage.ErrDatabase, err)
	}
	return res.ModifiedCount == 1, nil
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
		res, err := s.collection.ReplaceOne(ctx, casFilter(rec.KeyThumbprint, &cur), keyAttestationDoc{KeyAttestationRecord: next, Rev: cur.Rev + 1})
		if err != nil {
			return false, fmt.Errorf("%w: replace key evidence: %v", storage.ErrDatabase, err)
		}
		if res.MatchedCount == 1 {
			rec.CreatedAt = next.CreatedAt
			rec.WriteToken = next.WriteToken
			prev := cur.KeyAttestationRecord
			prev.Normalize()
			prev.Previous = nil
			rec.Previous = &prev
			return true, nil
		}
	}
	return false, fmt.Errorf("%w: replace key evidence: too much contention", storage.ErrDatabase)
}
