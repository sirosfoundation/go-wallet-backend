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

// CredentialStore implements MongoDB credential storage
type CredentialStore struct {
	collection *mongo.Collection
	counter    *mongo.Collection // For auto-increment IDs
	// now is the clock the undo log ages by; nil means time.Now.
	now func() time.Time
}

func (s *CredentialStore) getNextID(ctx context.Context) (int64, error) {
	return nextSequence(ctx, s.counter, "credential_id")
}

func (s *CredentialStore) Create(ctx context.Context, credential *domain.VerifiableCredential) error {
	id, err := s.getNextID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next ID: %w", err)
	}

	credential.ID = id
	credential.CreatedAt = time.Now()
	credential.UpdatedAt = time.Now()
	credential.WriteToken = storage.NewWriteToken()

	doc, err := withUndoLog(credential, undoClock(s.now), credential.WriteToken)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}
	_, err = s.collection.InsertOne(ctx, doc)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("failed to create credential: %w", err)
	}
	return nil
}

// toDoc is the bson document of a record.
func toDoc(record any) (bson.D, error) {
	raw, err := bson.Marshal(record)
	if err != nil {
		return nil, err
	}
	var doc bson.D
	if err := bson.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// withUndoLog is the document of a record being created: its fields plus an undo
// log holding the creating write (before: null).
func withUndoLog(record any, now time.Time, token string) (bson.D, error) {
	doc, err := toDoc(record)
	if err != nil {
		return nil, err
	}
	return append(doc, bson.E{Key: undoField, Value: bson.A{bson.M{"token": token, "at": now, "before": nil}}}), nil
}

func (s *CredentialStore) GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.VerifiableCredential, error) {
	var credential domain.VerifiableCredential
	err := s.collection.FindOne(ctx, bson.M{"_id": id, "tenant_id": string(tenantID)}).Decode(&credential)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}
	return &credential, nil
}

func (s *CredentialStore) GetByIdentifier(ctx context.Context, tenantID domain.TenantID, holderDID, credentialIdentifier string) (*domain.VerifiableCredential, error) {
	var credential domain.VerifiableCredential
	err := s.collection.FindOne(ctx, bson.M{
		"tenant_id":             string(tenantID),
		"holder_did":            holderDID,
		"credential_identifier": credentialIdentifier,
	}).Decode(&credential)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}
	return &credential, nil
}

func (s *CredentialStore) GetAllByHolder(ctx context.Context, tenantID domain.TenantID, holderDID string) ([]*domain.VerifiableCredential, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"tenant_id": string(tenantID), "holder_did": holderDID})
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	credentials := make([]*domain.VerifiableCredential, 0)
	if err := cursor.All(ctx, &credentials); err != nil {
		return nil, fmt.Errorf("failed to decode credentials: %w", err)
	}
	return credentials, nil
}

// Update replaces the credential and records the write in the undo log (the
// record as it was becomes the write's before). One atomic pipeline update.
func (s *CredentialStore) Update(ctx context.Context, credential *domain.VerifiableCredential) error {
	credential.UpdatedAt = time.Now()
	credential.WriteToken = storage.NewWriteToken()
	fields, err := toDoc(credential)
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}
	now := undoClock(s.now)
	result, err := s.collection.UpdateOne(ctx, bson.M{"_id": credential.ID}, mongo.Pipeline{{{Key: "$replaceWith", Value: bson.M{
		"$mergeObjects": bson.A{
			bson.M{"$literal": fields},
			bson.M{undoField: pushedLogExpr(now, credential.WriteToken, withoutUndoLogExpr())},
		},
	}}}})
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *CredentialStore) Delete(ctx context.Context, tenantID domain.TenantID, holderDID, credentialIdentifier string) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{
		"tenant_id":             string(tenantID),
		"holder_did":            holderDID,
		"credential_identifier": credentialIdentifier,
	})
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteIfUnchanged undoes the write that set writeToken (see storage.UndoLog):
// a create is deleted, an update goes back to the record it replaced, and a
// write with newer writes on top is spliced out of the log while their values
// stay. ErrNotFound if the token is not one of the record's recent writes.
func (s *CredentialStore) DeleteIfUnchanged(ctx context.Context, tenantID domain.TenantID, id int64, writeToken string) error {
	return s.rollback(ctx, tenantID, id, writeToken, nil)
}

// RestoreIfUnchanged undoes the write that set written.WriteToken, exactly as
// DeleteIfUnchanged does. previous is ignored for records that have an undo log
// (the log, not what the caller read, says what the write replaced); it is used
// only for a record written before the log existed.
func (s *CredentialStore) RestoreIfUnchanged(ctx context.Context, written, previous *domain.VerifiableCredential) error {
	return s.rollback(ctx, written.TenantID, written.ID, written.WriteToken, previous)
}

// rollbackMaxTries bounds the retries of a rollback whose state changed between
// its atomic steps.
const rollbackMaxTries = 8

// rollback tries three atomic, individually conditional steps until one lands or
// the write is no longer in the log: delete a newest create; restore a newest
// update or splice an older write out (one pipeline update); the legacy path for
// a record that has no log. Each step re-checks its own condition, so concurrent
// rollbacks and writes cannot interleave inside one.
func (s *CredentialStore) rollback(ctx context.Context, tenantID domain.TenantID, id int64, writeToken string, legacyPrevious *domain.VerifiableCredential) error {
	if writeToken == "" {
		return storage.ErrNotFound
	}
	match := bson.M{"_id": id, "tenant_id": string(tenantID)}
	for try := 0; try < rollbackMaxTries; try++ {
		now := undoClock(s.now)
		withToken := func(extra ...bson.M) bson.M {
			conds := bson.A{match, loggedWrite(writeToken, now)}
			for _, e := range extra {
				conds = append(conds, e)
			}
			return bson.M{"$and": conds}
		}
		// The newest write created the record: undoing it deletes the record.
		del, err := s.collection.DeleteOne(ctx, withToken(
			bson.M{"write_token": writeToken}, bson.M{"$expr": headIsCreate()}))
		if err != nil {
			return fmt.Errorf("failed to roll back credential: %w", err)
		}
		if del.DeletedCount == 1 {
			return nil
		}
		// Restore the newest update's before, or splice an older write out.
		upd, err := s.collection.UpdateOne(ctx, withToken(bson.M{"$expr": bson.M{"$not": bson.A{headIsCreate()}}}),
			mongo.Pipeline{{{Key: "$replaceWith", Value: rollbackLet(now, writeToken, bson.M{"$cond": bson.A{
				"$$isHead",
				bson.M{"$mergeObjects": bson.A{"$$entry.before", bson.M{undoField: "$$below"}}},
				bson.M{"$mergeObjects": bson.A{"$$ROOT", bson.M{undoField: "$$spliced"}}},
			}})}}})
		if err != nil {
			return fmt.Errorf("failed to roll back credential: %w", err)
		}
		if upd.MatchedCount == 1 {
			return nil
		}
		// Still in the log (the state moved under us): try again. Otherwise this
		// may be a record that has no log at all.
		n, err := s.collection.CountDocuments(ctx, withToken())
		if err != nil {
			return fmt.Errorf("failed to roll back credential: %w", err)
		}
		if n > 0 {
			continue
		}
		return s.rollbackLegacy(ctx, id, match, writeToken, legacyPrevious)
	}
	return fmt.Errorf("failed to roll back credential: too much contention")
}

// rollbackLegacy is the rollback for a record written before the undo log
// existed (no undo_log field): conditional on the current write token only.
func (s *CredentialStore) rollbackLegacy(ctx context.Context, id int64, match bson.M, writeToken string, previous *domain.VerifiableCredential) error {
	filter := bson.M{"$and": bson.A{match, bson.M{"write_token": writeToken}, bson.M{undoField: bson.M{"$exists": false}}}}
	if previous == nil {
		res, err := s.collection.DeleteOne(ctx, filter)
		if err != nil {
			return fmt.Errorf("failed to roll back credential: %w", err)
		}
		if res.DeletedCount == 0 {
			return storage.ErrNotFound
		}
		return nil
	}
	restored := *previous
	restored.ID = id
	restored.WriteToken = storage.NewWriteToken() // a restore is itself a new write
	res, err := s.collection.ReplaceOne(ctx, filter, &restored)
	if err != nil {
		return fmt.Errorf("failed to roll back credential: %w", err)
	}
	if res.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// PresentationStore implements MongoDB presentation storage
type PresentationStore struct {
	collection *mongo.Collection
	counter    *mongo.Collection
}

func (s *PresentationStore) getNextID(ctx context.Context) (int64, error) {
	return nextSequence(ctx, s.counter, "presentation_id")
}

func (s *PresentationStore) Create(ctx context.Context, presentation *domain.VerifiablePresentation) error {
	id, err := s.getNextID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next ID: %w", err)
	}

	presentation.ID = id
	if presentation.IssuanceDate.IsZero() {
		presentation.IssuanceDate = time.Now()
	}

	_, err = s.collection.InsertOne(ctx, presentation)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("failed to create presentation: %w", err)
	}
	return nil
}

func (s *PresentationStore) GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.VerifiablePresentation, error) {
	var presentation domain.VerifiablePresentation
	err := s.collection.FindOne(ctx, bson.M{"_id": id, "tenant_id": string(tenantID)}).Decode(&presentation)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get presentation: %w", err)
	}
	return &presentation, nil
}

func (s *PresentationStore) GetByIdentifier(ctx context.Context, tenantID domain.TenantID, holderDID, presentationIdentifier string) (*domain.VerifiablePresentation, error) {
	var presentation domain.VerifiablePresentation
	err := s.collection.FindOne(ctx, bson.M{
		"tenant_id":               string(tenantID),
		"holder_did":              holderDID,
		"presentation_identifier": presentationIdentifier,
	}).Decode(&presentation)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get presentation: %w", err)
	}
	return &presentation, nil
}

func (s *PresentationStore) GetAllByHolder(ctx context.Context, tenantID domain.TenantID, holderDID string) ([]*domain.VerifiablePresentation, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"tenant_id": string(tenantID), "holder_did": holderDID})
	if err != nil {
		return nil, fmt.Errorf("failed to get presentations: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	presentations := make([]*domain.VerifiablePresentation, 0)
	if err := cursor.All(ctx, &presentations); err != nil {
		return nil, fmt.Errorf("failed to decode presentations: %w", err)
	}
	return presentations, nil
}

func (s *PresentationStore) DeleteByCredentialID(ctx context.Context, tenantID domain.TenantID, holderDID, credentialID string) error {
	_, err := s.collection.DeleteMany(ctx, bson.M{
		"tenant_id":              string(tenantID),
		"holder_did":             holderDID,
		"credential_identifiers": credentialID,
	})
	if err != nil {
		return fmt.Errorf("failed to delete presentations: %w", err)
	}
	return nil
}

func (s *PresentationStore) Delete(ctx context.Context, tenantID domain.TenantID, holderDID, presentationIdentifier string) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{
		"tenant_id":               string(tenantID),
		"holder_did":              holderDID,
		"presentation_identifier": presentationIdentifier,
	})
	if err != nil {
		return fmt.Errorf("failed to delete presentation: %w", err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *PresentationStore) DeleteByID(ctx context.Context, tenantID domain.TenantID, id int64) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": id, "tenant_id": string(tenantID)})
	if err != nil {
		return fmt.Errorf("failed to delete presentation: %w", err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}
