package mongodb

import (
	"context"
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
func (s *KeyAttestationStore) MarkKeyAttested(ctx context.Context, rec *domain.KeyAttestationRecord) error {
	next := *rec
	next.Normalize()
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
		filter := bson.M{"_id": rec.KeyThumbprint, "rev": cur.Rev}
		if cur.Rev == 0 {
			filter = bson.M{"_id": rec.KeyThumbprint, "rev": bson.M{"$exists": false}}
		}
		res, err := s.collection.ReplaceOne(ctx, filter, keyAttestationDoc{KeyAttestationRecord: next, Rev: cur.Rev + 1})
		if err != nil {
			return fmt.Errorf("%w: mark key attested: %v", storage.ErrDatabase, err)
		}
		if res.MatchedCount == 1 {
			rec.CreatedAt = next.CreatedAt
			return nil
		}
	}
	return fmt.Errorf("%w: mark key attested: too much contention", storage.ErrDatabase)
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
