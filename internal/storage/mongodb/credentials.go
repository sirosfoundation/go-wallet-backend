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
}

func (s *CredentialStore) getNextID(ctx context.Context) (int64, error) {
	// Use a counter document for auto-increment
	result := s.counter.FindOneAndUpdate(
		ctx,
		bson.M{"_id": "credential_id"},
		bson.M{"$inc": bson.M{"value": 1}},
		nil,
	)

	var doc struct {
		Value int64 `bson:"value"`
	}

	if err := result.Decode(&doc); err != nil {
		if err == mongo.ErrNoDocuments {
			// Initialize counter
			_, err := s.counter.InsertOne(ctx, bson.M{"_id": "credential_id", "value": int64(1)})
			if err != nil {
				return 0, err
			}
			return 1, nil
		}
		return 0, err
	}
	return doc.Value, nil
}

func (s *CredentialStore) Create(ctx context.Context, credential *domain.VerifiableCredential) error {
	id, err := s.getNextID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next ID: %w", err)
	}

	credential.ID = id
	credential.CreatedAt = time.Now()
	credential.UpdatedAt = time.Now()

	_, err = s.collection.InsertOne(ctx, credential)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("failed to create credential: %w", err)
	}
	return nil
}

func (s *CredentialStore) GetByID(ctx context.Context, id int64) (*domain.VerifiableCredential, error) {
	var credential domain.VerifiableCredential
	err := s.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&credential)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}
	return &credential, nil
}

func (s *CredentialStore) GetByIdentifier(ctx context.Context, holderDID, credentialIdentifier string) (*domain.VerifiableCredential, error) {
	var credential domain.VerifiableCredential
	err := s.collection.FindOne(ctx, bson.M{
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

func (s *CredentialStore) GetAllByHolder(ctx context.Context, holderDID string) ([]*domain.VerifiableCredential, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"holder_did": holderDID})
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var credentials []*domain.VerifiableCredential
	if err := cursor.All(ctx, &credentials); err != nil {
		return nil, fmt.Errorf("failed to decode credentials: %w", err)
	}
	return credentials, nil
}

func (s *CredentialStore) Update(ctx context.Context, credential *domain.VerifiableCredential) error {
	credential.UpdatedAt = time.Now()
	result, err := s.collection.ReplaceOne(ctx, bson.M{"_id": credential.ID}, credential)
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *CredentialStore) Delete(ctx context.Context, holderDID, credentialIdentifier string) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{
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

// PresentationStore implements MongoDB presentation storage
type PresentationStore struct {
	collection *mongo.Collection
	counter    *mongo.Collection
}

func (s *PresentationStore) getNextID(ctx context.Context) (int64, error) {
	result := s.counter.FindOneAndUpdate(
		ctx,
		bson.M{"_id": "presentation_id"},
		bson.M{"$inc": bson.M{"value": 1}},
		nil,
	)

	var doc struct {
		Value int64 `bson:"value"`
	}

	if err := result.Decode(&doc); err != nil {
		if err == mongo.ErrNoDocuments {
			_, err := s.counter.InsertOne(ctx, bson.M{"_id": "presentation_id", "value": int64(1)})
			if err != nil {
				return 0, err
			}
			return 1, nil
		}
		return 0, err
	}
	return doc.Value, nil
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

func (s *PresentationStore) GetByID(ctx context.Context, id int64) (*domain.VerifiablePresentation, error) {
	var presentation domain.VerifiablePresentation
	err := s.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&presentation)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get presentation: %w", err)
	}
	return &presentation, nil
}

func (s *PresentationStore) GetByIdentifier(ctx context.Context, holderDID, presentationIdentifier string) (*domain.VerifiablePresentation, error) {
	var presentation domain.VerifiablePresentation
	err := s.collection.FindOne(ctx, bson.M{
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

func (s *PresentationStore) GetAllByHolder(ctx context.Context, holderDID string) ([]*domain.VerifiablePresentation, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"holder_did": holderDID})
	if err != nil {
		return nil, fmt.Errorf("failed to get presentations: %w", err)
	}
	defer cursor.Close(ctx)

	var presentations []*domain.VerifiablePresentation
	if err := cursor.All(ctx, &presentations); err != nil {
		return nil, fmt.Errorf("failed to decode presentations: %w", err)
	}
	return presentations, nil
}

func (s *PresentationStore) DeleteByCredentialID(ctx context.Context, holderDID, credentialID string) error {
	_, err := s.collection.DeleteMany(ctx, bson.M{
		"holder_did":             holderDID,
		"credential_identifiers": credentialID,
	})
	if err != nil {
		return fmt.Errorf("failed to delete presentations: %w", err)
	}
	return nil
}

func (s *PresentationStore) Delete(ctx context.Context, holderDID, presentationIdentifier string) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{
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
