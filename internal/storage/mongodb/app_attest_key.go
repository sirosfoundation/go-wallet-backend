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

// AppAttestKeyStore implements storage.AppAttestKeyStore using MongoDB.
type AppAttestKeyStore struct {
	collection *mongo.Collection
}

// appAttestKeyDoc is the stored shape. The counter is an int64 so every
// uint32 value is representable and compares numerically in a filter.
type appAttestKeyDoc struct {
	KeyID            string                      `bson:"_id"`
	PublicKey        []byte                      `bson:"public_key"`
	Counter          int64                       `bson:"counter"`
	Environment      domain.AppAttestEnvironment `bson:"environment"`
	AppID            string                      `bson:"app_id"`
	ChainVerified    bool                        `bson:"chain_verified"`
	TenantID         domain.TenantID             `bson:"tenant_id"`
	UserID           *domain.UserID              `bson:"user_id,omitempty"`
	WalletInstanceID string                      `bson:"wallet_instance_id,omitempty"`
	Status           domain.AppAttestKeyStatus   `bson:"status"`
	CreatedAt        time.Time                   `bson:"created_at"`
	UpdatedAt        time.Time                   `bson:"updated_at"`
}

func (d *appAttestKeyDoc) record() *domain.AppAttestKeyRecord {
	counter := d.Counter
	if counter < 0 {
		counter = 0
	}
	if counter > int64(^uint32(0)) {
		counter = int64(^uint32(0))
	}
	return &domain.AppAttestKeyRecord{
		KeyID: d.KeyID, PublicKey: d.PublicKey, Counter: uint32(counter),
		Environment: d.Environment, AppID: d.AppID, ChainVerified: d.ChainVerified,
		TenantID: d.TenantID, UserID: d.UserID, WalletInstanceID: d.WalletInstanceID,
		Status: d.Status, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
}

func (s *AppAttestKeyStore) Create(ctx context.Context, rec *domain.AppAttestKeyRecord) error {
	created := rec.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	doc := appAttestKeyDoc{
		KeyID: rec.KeyID, PublicKey: rec.PublicKey, Counter: int64(rec.Counter),
		Environment: rec.Environment, AppID: rec.AppID, ChainVerified: rec.ChainVerified,
		TenantID: rec.TenantID, UserID: rec.UserID, WalletInstanceID: rec.WalletInstanceID,
		Status: rec.Status, CreatedAt: created, UpdatedAt: created,
	}
	if _, err := s.collection.InsertOne(ctx, doc); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("%w: create app attest key: %v", storage.ErrDatabase, err)
	}
	return nil
}

func (s *AppAttestKeyStore) Get(ctx context.Context, keyID string) (*domain.AppAttestKeyRecord, error) {
	var doc appAttestKeyDoc
	if err := s.collection.FindOne(ctx, bson.M{"_id": keyID}).Decode(&doc); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("%w: get app attest key: %v", storage.ErrDatabase, err)
	}
	return doc.record(), nil
}

// AdvanceCounter is one conditional update: the filter holds the whole
// compare (active and stored counter below next), so the check and the write
// cannot be separated by a concurrent writer.
func (s *AppAttestKeyStore) AdvanceCounter(ctx context.Context, keyID string, next uint32) error {
	res, err := s.collection.UpdateOne(ctx,
		bson.M{"_id": keyID, "status": domain.AppAttestKeyActive, "counter": bson.M{"$lt": int64(next)}},
		bson.M{"$set": bson.M{"counter": int64(next), "updated_at": time.Now().UTC()}})
	if err != nil {
		return fmt.Errorf("%w: advance app attest counter: %v", storage.ErrDatabase, err)
	}
	if res.MatchedCount == 1 {
		return nil
	}
	n, err := s.collection.CountDocuments(ctx, bson.M{"_id": keyID})
	if err != nil {
		return fmt.Errorf("%w: advance app attest counter: %v", storage.ErrDatabase, err)
	}
	if n == 0 {
		return storage.ErrNotFound
	}
	return storage.ErrCounterNotAdvanced
}

func (s *AppAttestKeyStore) Revoke(ctx context.Context, keyID string) error {
	res, err := s.collection.UpdateOne(ctx, bson.M{"_id": keyID},
		bson.M{"$set": bson.M{"status": domain.AppAttestKeyRevoked, "updated_at": time.Now().UTC()}})
	if err != nil {
		return fmt.Errorf("%w: revoke app attest key: %v", storage.ErrDatabase, err)
	}
	if res.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}
