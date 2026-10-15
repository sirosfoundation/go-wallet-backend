package service

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// revocationMongoClient connects to the test MongoDB or skips (same
// convention as skipIfNoMongo: MONGODB_TEST_URI / TEST_MONGODB=1).
func revocationMongoClient(t *testing.T) *mongo.Client {
	t.Helper()
	if os.Getenv("MONGODB_TEST_URI") == "" && os.Getenv("TEST_MONGODB") == "" {
		t.Skip("Skipping MongoDB test: set MONGODB_TEST_URI or TEST_MONGODB=1 to enable")
	}
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		uri = "mongodb://localhost:27017"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Skipf("MongoDB not available: %v", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		t.Skipf("MongoDB not available: %v", err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	return client
}

// revocationTestDB returns a fresh database that is dropped afterwards.
func revocationTestDB(t *testing.T, client *mongo.Client) *mongo.Database {
	t.Helper()
	name := fmt.Sprintf("wb_test_revocation_%d", time.Now().UnixNano())
	db := client.Database(name)
	t.Cleanup(func() { _ = db.Drop(context.Background()) })
	return db
}

func TestMongoRevocationStore_Contract(t *testing.T) {
	client := revocationMongoClient(t)
	runRevocationStoreContract(t, func(t *testing.T) RevocationStore {
		s, err := NewMongoRevocationStore(context.Background(), revocationTestDB(t, client))
		require.NoError(t, err)
		return s
	})
}

func TestMongoRevocationStore_TTLIndex(t *testing.T) {
	client := revocationMongoClient(t)
	db := revocationTestDB(t, client)
	ctx := context.Background()
	_, err := NewMongoRevocationStore(ctx, db)
	require.NoError(t, err)

	cur, err := db.Collection(revokedTokensCollection).Indexes().List(ctx)
	require.NoError(t, err)
	var idx []bson.M
	require.NoError(t, cur.All(ctx, &idx))
	var ttl []bson.M
	for _, i := range idx {
		if _, ok := i["expireAfterSeconds"]; ok {
			ttl = append(ttl, i)
		}
	}
	require.Len(t, ttl, 1, "revoked_tokens must have exactly one TTL index")
	require.EqualValues(t, 0, ttl[0]["expireAfterSeconds"])
	key := bsonMap(ttl[0]["key"])
	require.Len(t, key, 1)
	require.EqualValues(t, 1, key["expires_at"])

	cur, err = db.Collection(revokedUsersCollection).Indexes().List(ctx)
	require.NoError(t, err)
	idx = nil
	require.NoError(t, cur.All(ctx, &idx))
	for _, i := range idx {
		require.NotContains(t, i, "expireAfterSeconds", "revoked_users is permanent and must not have a TTL")
	}
}

func bsonMap(v any) bson.M {
	if m, ok := v.(bson.M); ok {
		return m
	}
	return nil
}

// The TTL monitor is lazy (about once a minute), so an expired document can
// still be present; Has must not report it.
func TestMongoRevocationStore_ExpiredDocumentStillPresent(t *testing.T) {
	client := revocationMongoClient(t)
	db := revocationTestDB(t, client)
	ctx := context.Background()
	s, err := NewMongoRevocationStore(ctx, db)
	require.NoError(t, err)

	// Without the TTL index nothing can sweep the document before Has runs.
	_, err = db.Collection(revokedTokensCollection).Indexes().DropAll(ctx)
	require.NoError(t, err)

	_, err = db.Collection(revokedTokensCollection).InsertOne(ctx,
		bson.M{"_id": "expired", "expires_at": time.Now().Add(-time.Second)})
	require.NoError(t, err)

	n, err := db.Collection(revokedTokensCollection).CountDocuments(ctx, bson.M{"_id": "expired"})
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "precondition: the expired document has not been swept yet")
	require.False(t, mustHas(t, s, "expired"))
}

func TestMongoRevocationStore_ReAddNeverShortens(t *testing.T) {
	client := revocationMongoClient(t)
	s, err := NewMongoRevocationStore(context.Background(), revocationTestDB(t, client))
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, s.Add(ctx, "j", time.Now().Add(time.Hour)))
	require.NoError(t, s.Add(ctx, "j", time.Now().Add(-time.Hour)))
	require.True(t, mustHas(t, s, "j"), "a later Add with an earlier expiry must not un-revoke the jti")
}

func TestMongoRevocationStore_SharedAndPersistent(t *testing.T) {
	client := revocationMongoClient(t)
	db := revocationTestDB(t, client)
	ctx := context.Background()

	replicaA, err := NewMongoRevocationStore(ctx, db)
	require.NoError(t, err)
	replicaB, err := NewMongoRevocationStore(ctx, db)
	require.NoError(t, err)

	require.NoError(t, replicaA.Add(ctx, "jti-from-a", time.Now().Add(time.Hour)))
	require.NoError(t, replicaA.RevokeUser(ctx, "user-from-a"))
	require.True(t, mustHas(t, replicaB, "jti-from-a"), "a revocation on one replica must be seen by another")
	require.True(t, mustUserRevoked(t, replicaB, "user-from-a"))

	// "Restart": a new client and store over the same database.
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		uri = "mongodb://localhost:27017"
	}
	client2, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	require.NoError(t, err)
	defer func() { _ = client2.Disconnect(ctx) }()
	restarted, err := NewMongoRevocationStore(ctx, client2.Database(db.Name()))
	require.NoError(t, err)
	require.True(t, mustHas(t, restarted, "jti-from-a"), "revocations must survive a restart")
	require.True(t, mustUserRevoked(t, restarted, "user-from-a"))
}

// Two TokenBlacklists over one database behave like two replicas.
func TestTokenBlacklist_MongoStoreSharedBetweenInstances(t *testing.T) {
	client := revocationMongoClient(t)
	db := revocationTestDB(t, client)
	ctx := context.Background()
	mk := func() *TokenBlacklist {
		s, err := NewMongoRevocationStore(ctx, db)
		require.NoError(t, err)
		return NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop(), s)
	}
	a, b := mk(), mk()
	require.NoError(t, a.Add(ctx, "j", time.Now().Add(time.Hour)))
	require.True(t, blacklisted(t, b, ctx, "j"))
	require.NoError(t, a.RevokeUser(ctx, "u"))
	require.True(t, userRevoked(t, b, ctx, "u"))
}

// deadMongoDB returns a database whose server is unreachable.
func deadMongoDB(t *testing.T) *mongo.Database {
	t.Helper()
	client, err := mongo.Connect(context.Background(), options.Client().
		ApplyURI("mongodb://127.0.0.1:1").
		SetServerSelectionTimeout(200*time.Millisecond))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	return client.Database("unreachable")
}

// An unreachable database yields errors, and the blacklist refuses on them;
// it must never answer "not revoked".
func TestMongoRevocationStore_OutageRefuses(t *testing.T) {
	ctx := context.Background()
	opts := options.Collection()
	s := &mongoRevocationStore{
		tokens: deadMongoDB(t).Collection(revokedTokensCollection, opts),
		users:  deadMongoDB(t).Collection(revokedUsersCollection, opts),
	}

	_, err := s.Has(ctx, "j")
	require.Error(t, err)
	_, err = s.IsUserRevoked(ctx, "u")
	require.Error(t, err)
	require.Error(t, s.Add(ctx, "j", time.Now().Add(time.Hour)))
	require.Error(t, s.RevokeUser(ctx, "u"))

	b := NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop(), s)
	_, err = b.IsBlacklisted(ctx, "j")
	require.Error(t, err, "a store outage must be reported, not read as 'not revoked'")
	_, err = b.IsUserRevoked(ctx, "u")
	require.Error(t, err)
	require.Error(t, b.Add(ctx, "j", time.Now().Add(time.Hour)), "a failed revocation write must be reported")
}

// mongoStoreFake makes a memory store look like a MongoDB-backed one.
type mongoStoreFake struct {
	storage.Store
	db *mongo.Database
}

func (f mongoStoreFake) Database() *mongo.Database { return f.db }

func TestNewRevocationStore_Selection(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	plain := memory.NewStore()
	dead := mongoStoreFake{Store: plain, db: deadMongoDB(t)}

	t.Run("default with non-MongoDB storage is memory", func(t *testing.T) {
		s, err := NewRevocationStore(ctx, config.TokenBlacklistConfig{}, plain, logger)
		require.NoError(t, err)
		require.Nil(t, s)
	})
	t.Run("explicit memory with MongoDB storage is memory", func(t *testing.T) {
		s, err := NewRevocationStore(ctx, config.TokenBlacklistConfig{Backend: "memory"}, dead, logger)
		require.NoError(t, err)
		require.Nil(t, s)
	})
	t.Run("storage needs MongoDB", func(t *testing.T) {
		_, err := NewRevocationStore(ctx, config.TokenBlacklistConfig{Backend: "storage"}, plain, logger)
		require.Error(t, err)
	})
	t.Run("unknown backend", func(t *testing.T) {
		_, err := NewRevocationStore(ctx, config.TokenBlacklistConfig{Backend: "redis"}, plain, logger)
		require.Error(t, err)
	})
	t.Run("default with MongoDB storage uses MongoDB", func(t *testing.T) {
		// The dead database cannot create its index, which proves the
		// MongoDB store was selected without a server.
		_, err := NewRevocationStore(ctx, config.TokenBlacklistConfig{}, dead, logger)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), revokedTokensCollection), err.Error())
	})
}

func TestNewServices_RevocationStoreFailureIsReported(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.TokenBlacklist = config.TokenBlacklistConfig{Enabled: true, Backend: "storage"}
	cfg.Server.RPID = "localhost"
	cfg.Server.RPOrigin = "http://localhost"
	// Storage is not MongoDB, so backend=storage cannot be honoured.
	svc := NewServices(memory.NewStore(), cfg, zap.NewNop())
	ctx := context.Background()
	_, err := svc.TokenBlacklist.IsBlacklisted(ctx, "any")
	require.Error(t, err)
	_, err = svc.TokenBlacklist.IsUserRevoked(ctx, "any")
	require.Error(t, err)
	require.Error(t, svc.TokenBlacklist.Add(ctx, "any", time.Now().Add(time.Hour)))
}

func TestMongoRevocationStore_Remove(t *testing.T) {
	client := revocationMongoClient(t)
	ctx := context.Background()
	s, err := NewMongoRevocationStore(ctx, revocationTestDB(t, client))
	require.NoError(t, err)
	b := NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop(), s)

	require.NoError(t, b.Add(ctx, "j", time.Now().Add(time.Hour)))
	revoked, err := b.IsBlacklisted(ctx, "j")
	require.NoError(t, err)
	require.True(t, revoked)
	require.NoError(t, b.Remove(ctx, "j"))
	revoked, err = b.IsBlacklisted(ctx, "j")
	require.NoError(t, err)
	require.False(t, revoked)
	require.NoError(t, b.Remove(ctx, "never-added"), "removing an absent jti is not an error")
}

// deadMongoDBSlowSelection is unreachable and, unlike deadMongoDB, would wait
// out the driver's default 30 s server selection.
func deadMongoDBSlowSelection(t *testing.T) *mongo.Database {
	t.Helper()
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://127.0.0.1:1"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	return client.Database("unreachable")
}

// Operations on a caller context without a deadline return promptly.
func TestMongoRevocationStore_OperationsAreBounded(t *testing.T) {
	db := deadMongoDBSlowSelection(t)
	s := &mongoRevocationStore{tokens: db.Collection(revokedTokensCollection), users: db.Collection(revokedUsersCollection)}
	start := time.Now()
	_, err := s.Has(context.Background(), "j")
	require.Error(t, err)
	require.Less(t, time.Since(start), 10*time.Second)
}

// Setting the store up returns an error within RevocationInitTimeout.
func TestNewMongoRevocationStore_InitIsBounded(t *testing.T) {
	old := RevocationInitTimeout
	RevocationInitTimeout = time.Second
	defer func() { RevocationInitTimeout = old }()
	start := time.Now()
	_, err := NewMongoRevocationStore(context.Background(), deadMongoDBSlowSelection(t))
	require.Error(t, err)
	require.Less(t, time.Since(start), 5*time.Second)
}
