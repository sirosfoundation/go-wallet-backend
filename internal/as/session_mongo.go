package as

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// asSessionsCollection is the MongoDB collection holding AS sessions.
const asSessionsCollection = "as_sessions"

// sessionDoc is the stored form of a Session. The document id is
// HashSessionID(jti); the raw JTI is never written (see HashSessionID).
type sessionDoc struct {
	ID              string    `bson:"_id"`
	UserID          string    `bson:"user_id"`
	DID             string    `bson:"did,omitempty"`
	TenantID        string    `bson:"tenant_id"`
	ACR             string    `bson:"acr"`
	MaxTAC          string    `bson:"max_tac"`
	CreatedAt       time.Time `bson:"created_at"`
	AuthenticatedAt time.Time `bson:"authenticated_at,omitempty"`
	ExpiresAt       time.Time `bson:"expires_at"`
	Revoked         bool      `bson:"revoked"`
}

// MongoSessionStore is a SessionStore backed by MongoDB, so sessions survive
// restarts and are shared between instances (go-wallet-backend#324).
//
// Expiry is enforced twice: Session.IsValid on every read, and a TTL index on
// expires_at that removes documents shortly after they expire (MongoDB's TTL
// monitor runs about once a minute), which replaces MemorySessionStore's
// cleanup goroutine. Revocation flips a flag and leaves the document to the
// TTL index, so a lookup for a cookie still in circulation finds a revoked
// session rather than nothing. The client is refused with 401 either way;
// the distinction is kept for the store and for SessionMiddleware's logging.
type MongoSessionStore struct {
	coll *mongo.Collection
}

// NewMongoSessionStore creates the store and its indexes: the TTL index on
// expires_at and a user_id index for DeleteByUser.
func NewMongoSessionStore(ctx context.Context, db *mongo.Database) (*MongoSessionStore, error) {
	coll := db.Collection(asSessionsCollection)
	_, err := coll.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0).SetName("as_sessions_ttl"),
		},
		{
			Keys:    bson.D{{Key: "user_id", Value: 1}},
			Options: options.Index().SetName("as_sessions_user_id"),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create as_sessions indexes: %w", err)
	}
	return &MongoSessionStore{coll: coll}, nil
}

// Create stores a new session. Returns an error if the JTI already exists.
func (s *MongoSessionStore) Create(ctx context.Context, session *Session) error {
	doc := sessionDoc{
		ID:              HashSessionID(session.JTI),
		UserID:          session.UserID,
		DID:             session.DID,
		TenantID:        session.TenantID,
		ACR:             session.ACR,
		MaxTAC:          string(session.MaxTAC),
		CreatedAt:       session.CreatedAt,
		AuthenticatedAt: session.AuthenticatedAt,
		ExpiresAt:       session.ExpiresAt,
		Revoked:         session.Revoked,
	}
	if _, err := s.coll.InsertOne(ctx, doc); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("session %s already exists", session.JTI)
		}
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// Get retrieves a session by JTI. Returns nil, nil if not found.
func (s *MongoSessionStore) Get(ctx context.Context, jti string) (*Session, error) {
	var doc sessionDoc
	err := s.coll.FindOne(ctx, bson.M{"_id": HashSessionID(jti)}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, fmt.Errorf("get session: %w", err)
	}
	return &Session{
		JTI:             jti, // only the hash is stored; the caller presented the real value
		UserID:          doc.UserID,
		DID:             doc.DID,
		TenantID:        doc.TenantID,
		ACR:             doc.ACR,
		MaxTAC:          TAC(doc.MaxTAC),
		CreatedAt:       doc.CreatedAt,
		AuthenticatedAt: doc.AuthenticatedAt,
		ExpiresAt:       doc.ExpiresAt,
		Revoked:         doc.Revoked,
	}, nil
}

// Revoke marks a session as revoked.
func (s *MongoSessionStore) Revoke(ctx context.Context, jti string) error {
	res, err := s.coll.UpdateOne(ctx, bson.M{"_id": HashSessionID(jti)}, bson.M{"$set": bson.M{"revoked": true}})
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	if res.MatchedCount == 0 {
		return fmt.Errorf("session %s not found", jti)
	}
	return nil
}

// Delete removes a session.
func (s *MongoSessionStore) Delete(ctx context.Context, jti string) error {
	if _, err := s.coll.DeleteOne(ctx, bson.M{"_id": HashSessionID(jti)}); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// DeleteByUser revokes every session belonging to userID.
func (s *MongoSessionStore) DeleteByUser(ctx context.Context, userID string) error {
	if _, err := s.coll.UpdateMany(ctx, bson.M{"user_id": userID, "revoked": false}, bson.M{"$set": bson.M{"revoked": true}}); err != nil {
		return fmt.Errorf("revoke sessions for user: %w", err)
	}
	return nil
}
