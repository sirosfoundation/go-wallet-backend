package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

const (
	revokedTokensCollection = "revoked_tokens"
	revokedUsersCollection  = "revoked_users"

	// revocationOpTimeout bounds each operation, so an unreachable database
	// produces a prompt error instead of waiting out server selection.
	revocationOpTimeout = 5 * time.Second
)

// RevocationInitTimeout bounds setting the store up (connecting, creating the
// TTL index).
var RevocationInitTimeout = 30 * time.Second

// mongoRevocationStore is a RevocationStore shared by every process using
// the same database, and surviving restarts.
//
// revoked_tokens has one document per jti with a TTL index on expires_at.
// MongoDB's TTL monitor runs about once a minute, so Has compares expires_at
// itself and an unswept expired entry is never reported revoked.
//
// revoked_users has one document per revoked user and no TTL: a user
// revocation is permanent (see TokenBlacklist), and the collection grows by
// one small document per deleted account.
//
// Both collections are read from the primary and written with a majority
// write concern, so a revocation is visible to the next check on any replica.
type mongoRevocationStore struct {
	tokens *mongo.Collection
	users  *mongo.Collection
}

// NewMongoRevocationStore creates the store and the TTL index on
// revoked_tokens.expires_at.
func NewMongoRevocationStore(ctx context.Context, db *mongo.Database) (RevocationStore, error) {
	ctx, cancel := context.WithTimeout(ctx, RevocationInitTimeout)
	defer cancel()
	opts := options.Collection().
		SetReadPreference(readpref.Primary()).
		SetWriteConcern(writeconcern.Majority())
	s := &mongoRevocationStore{
		tokens: db.Collection(revokedTokensCollection, opts),
		users:  db.Collection(revokedUsersCollection, opts),
	}
	_, err := s.tokens.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0).SetName("revoked_tokens_ttl"),
	})
	if err != nil {
		return nil, fmt.Errorf("create %s TTL index: %w", revokedTokensCollection, err)
	}
	return s, nil
}

// Add records jti until expiry. Re-adding never shortens an existing entry.
func (s *mongoRevocationStore) Add(ctx context.Context, jti string, expiry time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, revocationOpTimeout)
	defer cancel()
	_, err := s.tokens.UpdateOne(ctx,
		bson.M{"_id": jti},
		bson.M{"$max": bson.M{"expires_at": expiry}},
		options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

func (s *mongoRevocationStore) Has(ctx context.Context, jti string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, revocationOpTimeout)
	defer cancel()
	err := s.tokens.FindOne(ctx,
		bson.M{"_id": jti, "expires_at": bson.M{"$gt": time.Now()}},
		options.FindOne().SetProjection(bson.M{"_id": 1})).Err()
	return foundOrErr(err, "check token revocation")
}

// Remove deletes the revocation of jti, if any.
func (s *mongoRevocationStore) Remove(ctx context.Context, jti string) error {
	ctx, cancel := context.WithTimeout(ctx, revocationOpTimeout)
	defer cancel()
	if _, err := s.tokens.DeleteOne(ctx, bson.M{"_id": jti}); err != nil {
		return fmt.Errorf("remove token revocation: %w", err)
	}
	return nil
}

func (s *mongoRevocationStore) RevokeUser(ctx context.Context, userID string) error {
	ctx, cancel := context.WithTimeout(ctx, revocationOpTimeout)
	defer cancel()
	_, err := s.users.UpdateOne(ctx,
		bson.M{"_id": userID},
		bson.M{"$setOnInsert": bson.M{"revoked_at": time.Now()}},
		options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("revoke user: %w", err)
	}
	return nil
}

func (s *mongoRevocationStore) IsUserRevoked(ctx context.Context, userID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, revocationOpTimeout)
	defer cancel()
	err := s.users.FindOne(ctx, bson.M{"_id": userID},
		options.FindOne().SetProjection(bson.M{"_id": 1})).Err()
	return foundOrErr(err, "check user revocation")
}

// foundOrErr maps a FindOne error: no document is (false, nil), any other
// error is unknown.
func foundOrErr(err error, what string) (bool, error) {
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return false, nil
	default:
		return false, fmt.Errorf("%s: %w", what, err)
	}
}

// databaseProvider is implemented by the MongoDB storage backends.
type databaseProvider interface {
	Database() *mongo.Database
}

// NewRevocationStore picks the RevocationStore for cfg.Backend. A nil store
// means the in-memory one, which is also what a disabled blacklist gets.
func NewRevocationStore(ctx context.Context, cfg config.TokenBlacklistConfig, store storage.Store, logger *zap.Logger) (RevocationStore, error) {
	if !cfg.Enabled {
		// Disabled: nothing is kept in a shared store, so a failed MongoDB
		// setup must not install an unavailable store (and fail readiness).
		return nil, nil
	}
	dbp, hasMongo := store.(databaseProvider)
	switch cfg.Backend {
	case "":
		if !hasMongo {
			logger.Info("Token revocation: in-memory store (storage backend is not MongoDB; revocations are per process and lost on restart)")
			return nil, nil
		}
	case config.TokenBlacklistBackendMemory:
		logger.Info("Token revocation: in-memory store (security.token_blacklist.backend=memory; revocations are per process and lost on restart)")
		return nil, nil
	case config.TokenBlacklistBackendStorage:
		if !hasMongo {
			return nil, errors.New("security.token_blacklist.backend=storage requires the MongoDB storage backend")
		}
	default:
		return nil, fmt.Errorf("security.token_blacklist.backend: unknown value %q (memory or storage)", cfg.Backend)
	}
	rs, err := NewMongoRevocationStore(ctx, dbp.Database())
	if err != nil {
		return nil, err
	}
	logger.Info("Token revocation: MongoDB store (shared by replicas, survives restarts)")
	return rs, nil
}

// unavailableRevocationStore stands in when the configured store could not be
// set up: every operation fails, so nothing is accepted on its say-so.
type unavailableRevocationStore struct{ err error }

// Unavailable reports why the store could not be set up, so readiness can
// surface it instead of reporting healthy while every request is refused.
func (u unavailableRevocationStore) Unavailable() error { return u.err }

func (u unavailableRevocationStore) Add(context.Context, string, time.Time) error { return u.err }
func (u unavailableRevocationStore) Has(context.Context, string) (bool, error)    { return false, u.err }
func (u unavailableRevocationStore) RevokeUser(context.Context, string) error     { return u.err }
func (u unavailableRevocationStore) IsUserRevoked(context.Context, string) (bool, error) {
	return false, u.err
}
