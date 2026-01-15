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

// ChallengeStore implements MongoDB challenge storage
type ChallengeStore struct {
	collection *mongo.Collection
}

func (s *ChallengeStore) Create(ctx context.Context, challenge *domain.WebauthnChallenge) error {
	_, err := s.collection.InsertOne(ctx, challenge)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("failed to create challenge: %w", err)
	}
	return nil
}

func (s *ChallengeStore) GetByID(ctx context.Context, id string) (*domain.WebauthnChallenge, error) {
	var challenge domain.WebauthnChallenge
	err := s.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&challenge)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get challenge: %w", err)
	}
	return &challenge, nil
}

func (s *ChallengeStore) Delete(ctx context.Context, id string) error {
	_, err := s.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete challenge: %w", err)
	}
	return nil
}

func (s *ChallengeStore) DeleteExpired(ctx context.Context) error {
	_, err := s.collection.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now()},
	})
	if err != nil {
		return fmt.Errorf("failed to delete expired challenges: %w", err)
	}
	return nil
}

// IssuerStore implements MongoDB issuer storage
type IssuerStore struct {
	collection *mongo.Collection
	counter    *mongo.Collection
}

func (s *IssuerStore) getNextID(ctx context.Context) (int64, error) {
	result := s.counter.FindOneAndUpdate(
		ctx,
		bson.M{"_id": "issuer_id"},
		bson.M{"$inc": bson.M{"value": 1}},
		nil,
	)

	var doc struct {
		Value int64 `bson:"value"`
	}

	if err := result.Decode(&doc); err != nil {
		if err == mongo.ErrNoDocuments {
			_, err := s.counter.InsertOne(ctx, bson.M{"_id": "issuer_id", "value": int64(1)})
			if err != nil {
				return 0, err
			}
			return 1, nil
		}
		return 0, err
	}
	return doc.Value, nil
}

func (s *IssuerStore) Create(ctx context.Context, issuer *domain.CredentialIssuer) error {
	id, err := s.getNextID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next ID: %w", err)
	}

	issuer.ID = id

	_, err = s.collection.InsertOne(ctx, issuer)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("failed to create issuer: %w", err)
	}
	return nil
}

func (s *IssuerStore) GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.CredentialIssuer, error) {
	var issuer domain.CredentialIssuer
	err := s.collection.FindOne(ctx, bson.M{"_id": id, "tenant_id": string(tenantID)}).Decode(&issuer)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get issuer: %w", err)
	}
	return &issuer, nil
}

func (s *IssuerStore) GetByIdentifier(ctx context.Context, tenantID domain.TenantID, identifier string) (*domain.CredentialIssuer, error) {
	var issuer domain.CredentialIssuer
	err := s.collection.FindOne(ctx, bson.M{"tenant_id": string(tenantID), "credential_issuer_identifier": identifier}).Decode(&issuer)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get issuer: %w", err)
	}
	return &issuer, nil
}

func (s *IssuerStore) GetAll(ctx context.Context, tenantID domain.TenantID) ([]*domain.CredentialIssuer, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"tenant_id": string(tenantID)})
	if err != nil {
		return nil, fmt.Errorf("failed to get issuers: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var issuers []*domain.CredentialIssuer
	if err := cursor.All(ctx, &issuers); err != nil {
		return nil, fmt.Errorf("failed to decode issuers: %w", err)
	}
	return issuers, nil
}

func (s *IssuerStore) Update(ctx context.Context, issuer *domain.CredentialIssuer) error {
	result, err := s.collection.ReplaceOne(ctx, bson.M{"_id": issuer.ID}, issuer)
	if err != nil {
		return fmt.Errorf("failed to update issuer: %w", err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *IssuerStore) Delete(ctx context.Context, tenantID domain.TenantID, id int64) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": id, "tenant_id": string(tenantID)})
	if err != nil {
		return fmt.Errorf("failed to delete issuer: %w", err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// VerifierStore implements MongoDB verifier storage
type VerifierStore struct {
	collection *mongo.Collection
	counter    *mongo.Collection
}

func (s *VerifierStore) getNextID(ctx context.Context) (int64, error) {
	result := s.counter.FindOneAndUpdate(
		ctx,
		bson.M{"_id": "verifier_id"},
		bson.M{"$inc": bson.M{"value": 1}},
		nil,
	)

	var doc struct {
		Value int64 `bson:"value"`
	}

	if err := result.Decode(&doc); err != nil {
		if err == mongo.ErrNoDocuments {
			_, err := s.counter.InsertOne(ctx, bson.M{"_id": "verifier_id", "value": int64(1)})
			if err != nil {
				return 0, err
			}
			return 1, nil
		}
		return 0, err
	}
	return doc.Value, nil
}

func (s *VerifierStore) Create(ctx context.Context, verifier *domain.Verifier) error {
	id, err := s.getNextID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next ID: %w", err)
	}

	verifier.ID = id

	_, err = s.collection.InsertOne(ctx, verifier)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("failed to create verifier: %w", err)
	}
	return nil
}

func (s *VerifierStore) GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.Verifier, error) {
	var verifier domain.Verifier
	err := s.collection.FindOne(ctx, bson.M{"_id": id, "tenant_id": string(tenantID)}).Decode(&verifier)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get verifier: %w", err)
	}
	return &verifier, nil
}

func (s *VerifierStore) GetAll(ctx context.Context, tenantID domain.TenantID) ([]*domain.Verifier, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"tenant_id": string(tenantID)})
	if err != nil {
		return nil, fmt.Errorf("failed to get verifiers: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var verifiers []*domain.Verifier
	if err := cursor.All(ctx, &verifiers); err != nil {
		return nil, fmt.Errorf("failed to decode verifiers: %w", err)
	}
	return verifiers, nil
}

func (s *VerifierStore) Update(ctx context.Context, verifier *domain.Verifier) error {
	result, err := s.collection.ReplaceOne(ctx, bson.M{"_id": verifier.ID}, verifier)
	if err != nil {
		return fmt.Errorf("failed to update verifier: %w", err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *VerifierStore) Delete(ctx context.Context, tenantID domain.TenantID, id int64) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": id, "tenant_id": string(tenantID)})
	if err != nil {
		return fmt.Errorf("failed to delete verifier: %w", err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}
