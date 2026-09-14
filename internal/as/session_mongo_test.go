package as

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// mongoSessionStoreForTest connects to the test MongoDB (same env contract as
// internal/storage/mongodb's tests), using a per-test database that is
// dropped on cleanup.
func mongoSessionStoreForTest(t *testing.T) *MongoSessionStore {
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
	require.NoError(t, err)
	db := client.Database("as_sessions_test_" + strconv.FormatInt(time.Now().UnixNano(), 36))
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = db.Drop(c)
		_ = client.Disconnect(c)
	})
	store, err := NewMongoSessionStore(ctx, db)
	require.NoError(t, err)
	return store
}

func testSession(jti, userID string) *Session {
	now := time.Now().Truncate(time.Millisecond)
	return &Session{
		JTI: jti, UserID: userID, DID: "did:example:" + userID, TenantID: "default", ACR: "passkey",
		MaxTAC: "rwl", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func TestMongoSessionStore_RoundTrip(t *testing.T) {
	store := mongoSessionStoreForTest(t)
	ctx := context.Background()
	jti, err := GenerateSessionID()
	require.NoError(t, err)

	require.NoError(t, store.Create(ctx, testSession(jti, "user-1")))

	got, err := store.Get(ctx, jti)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, jti, got.JTI, "the presented JTI is handed back; only its hash is stored")
	assert.Equal(t, "user-1", got.UserID)
	assert.Equal(t, TAC("rwl"), got.MaxTAC)
	assert.Equal(t, "passkey", got.ACR)
	assert.True(t, got.IsValid())

	// Duplicate JTI is refused, like the memory store.
	assert.Error(t, store.Create(ctx, testSession(jti, "user-1")))

	// Unknown JTI is nil, nil - the middleware turns that into 401 "session not found".
	missing, err := store.Get(ctx, "nope")
	require.NoError(t, err)
	assert.Nil(t, missing)
}

func TestMongoSessionStore_StoresOnlyTheHash(t *testing.T) {
	store := mongoSessionStoreForTest(t)
	ctx := context.Background()
	jti, _ := GenerateSessionID()
	require.NoError(t, store.Create(ctx, testSession(jti, "user-1")))

	var raw bson.M
	require.NoError(t, store.coll.FindOne(ctx, bson.M{}).Decode(&raw))
	assert.Equal(t, HashSessionID(jti), raw["_id"], "document id is the hash of the JTI")
	for k, v := range raw {
		assert.NotEqual(t, jti, v, "raw JTI must not appear in field %s", k)
	}
}

func TestMongoSessionStore_RevokeKeepsDocumentAsRevoked(t *testing.T) {
	store := mongoSessionStoreForTest(t)
	ctx := context.Background()
	jti, _ := GenerateSessionID()
	require.NoError(t, store.Create(ctx, testSession(jti, "user-1")))

	require.NoError(t, store.Revoke(ctx, jti))
	got, err := store.Get(ctx, jti)
	require.NoError(t, err)
	require.NotNil(t, got, "a revoked session is still found, so the client is told 'revoked', not 'not found'")
	assert.True(t, got.Revoked)
	assert.False(t, got.IsValid())

	assert.Error(t, store.Revoke(ctx, "unknown"), "revoking an unknown session is an error, like the memory store")

	require.NoError(t, store.Delete(ctx, jti))
	gone, err := store.Get(ctx, jti)
	require.NoError(t, err)
	assert.Nil(t, gone)
}

func TestMongoSessionStore_DeleteByUserRevokesOnlyThatUser(t *testing.T) {
	store := mongoSessionStoreForTest(t)
	ctx := context.Background()
	a1, _ := GenerateSessionID()
	a2, _ := GenerateSessionID()
	b1, _ := GenerateSessionID()
	require.NoError(t, store.Create(ctx, testSession(a1, "alice")))
	require.NoError(t, store.Create(ctx, testSession(a2, "alice")))
	require.NoError(t, store.Create(ctx, testSession(b1, "bob")))

	require.NoError(t, store.DeleteByUser(ctx, "alice"))

	for _, jti := range []string{a1, a2} {
		got, err := store.Get(ctx, jti)
		require.NoError(t, err)
		assert.True(t, got.Revoked, "alice's sessions are revoked")
	}
	bob, err := store.Get(ctx, b1)
	require.NoError(t, err)
	assert.True(t, bob.IsValid(), "bob is untouched")
	assert.NoError(t, store.DeleteByUser(ctx, "nobody"), "no sessions is not an error")
}

func TestMongoSessionStore_CreatesTTLAndUserIndexes(t *testing.T) {
	store := mongoSessionStoreForTest(t)
	ctx := context.Background()
	cur, err := store.coll.Indexes().List(ctx)
	require.NoError(t, err)
	var idx []bson.M
	require.NoError(t, cur.All(ctx, &idx))
	names := map[string]bson.M{}
	for _, i := range idx {
		names[i["name"].(string)] = i
	}
	ttl, ok := names["as_sessions_ttl"]
	require.True(t, ok, "TTL index missing: %v", names)
	assert.EqualValues(t, 0, ttl["expireAfterSeconds"], "documents expire at expires_at")
	_, ok = names["as_sessions_user_id"]
	assert.True(t, ok, "user_id index missing")

	// Constructing the store again must be idempotent (indexes already exist).
	_, err = NewMongoSessionStore(ctx, store.coll.Database())
	require.NoError(t, err)
}
