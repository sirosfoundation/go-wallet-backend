package mongodb

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func getTestMongoURI() string {
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		uri = "mongodb://localhost:27017"
	}
	return uri
}

func skipIfNoMongo(t *testing.T) *Store {
	if os.Getenv("MONGODB_TEST_URI") == "" && os.Getenv("TEST_MONGODB") == "" {
		t.Skip("Skipping MongoDB test: set MONGODB_TEST_URI or TEST_MONGODB=1 to enable")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := &config.MongoDBConfig{
		URI:      getTestMongoURI(),
		Database: "wallet_backend_test",
		Timeout:  5,
	}

	store, err := NewStore(ctx, cfg)
	if err != nil {
		t.Skipf("MongoDB not available: %v", err)
		return nil
	}

	// Clean up test database
	t.Cleanup(func() {
		ctx := context.Background()
		_ = store.database.Drop(ctx)
		_ = store.Close()
	})

	return store
}

func TestNewStore(t *testing.T) {
	store := skipIfNoMongo(t)
	require.NotNil(t, store)
}

func TestStore_Ping(t *testing.T) {
	store := skipIfNoMongo(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := store.Ping(ctx)
	assert.NoError(t, err)
}

func TestStore_Close(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := &config.MongoDBConfig{
		URI:      getTestMongoURI(),
		Database: "wallet_backend_test_close",
		Timeout:  5,
	}

	store, err := NewStore(ctx, cfg)
	if err != nil {
		t.Skipf("MongoDB not available: %v", err)
		return
	}

	err = store.Close()
	assert.NoError(t, err)
}

func TestStore_SubStores(t *testing.T) {
	store := skipIfNoMongo(t)

	assert.NotNil(t, store.Users())
	assert.NotNil(t, store.Tenants())
	assert.NotNil(t, store.UserTenants())
	assert.NotNil(t, store.Credentials())
	assert.NotNil(t, store.Presentations())
	assert.NotNil(t, store.Challenges())
	assert.NotNil(t, store.Issuers())
	assert.NotNil(t, store.Verifiers())
}

func TestTenantStore_CRUD(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	// Create tenant
	tenant := &domain.Tenant{
		ID:          domain.TenantID("test-tenant"),
		Name:        "Test Tenant",
		DisplayName: "Test Tenant Display",
		Enabled:     true,
	}

	err := store.Tenants().Create(ctx, tenant)
	require.NoError(t, err)

	// Get by ID
	retrieved, err := store.Tenants().GetByID(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Equal(t, tenant.Name, retrieved.Name)
	assert.Equal(t, tenant.DisplayName, retrieved.DisplayName)

	// Update
	tenant.DisplayName = "Updated Display"
	err = store.Tenants().Update(ctx, tenant)
	require.NoError(t, err)

	retrieved, err = store.Tenants().GetByID(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Display", retrieved.DisplayName)

	// Delete
	err = store.Tenants().Delete(ctx, tenant.ID)
	require.NoError(t, err)

	_, err = store.Tenants().GetByID(ctx, tenant.ID)
	assert.Error(t, err)
}

func TestUserStore_CRUD(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	// Create user
	username := "testuser"
	displayName := "Test User"
	user := &domain.User{
		UUID:        domain.NewUserID(),
		DID:         "did:key:test123",
		DisplayName: &displayName,
		Username:    &username,
		CreatedAt:   time.Now(),
	}

	err := store.Users().Create(ctx, user)
	require.NoError(t, err)

	// Get by ID
	retrieved, err := store.Users().GetByID(ctx, user.UUID)
	require.NoError(t, err)
	assert.Equal(t, user.DID, retrieved.DID)
	assert.Equal(t, *user.DisplayName, *retrieved.DisplayName)

	// Get by username
	retrieved, err = store.Users().GetByUsername(ctx, username)
	require.NoError(t, err)
	assert.Equal(t, user.UUID, retrieved.UUID)

	// Get by DID
	retrieved, err = store.Users().GetByDID(ctx, user.DID)
	require.NoError(t, err)
	assert.Equal(t, user.UUID, retrieved.UUID)

	// Update
	updatedName := "Updated User"
	user.DisplayName = &updatedName
	err = store.Users().Update(ctx, user)
	require.NoError(t, err)

	retrieved, err = store.Users().GetByID(ctx, user.UUID)
	require.NoError(t, err)
	assert.Equal(t, "Updated User", *retrieved.DisplayName)

	// Delete
	err = store.Users().Delete(ctx, user.UUID)
	require.NoError(t, err)

	_, err = store.Users().GetByID(ctx, user.UUID)
	assert.Error(t, err)
}

// TestUserStore_UpdateCredentialAuthenticator_SetsFields covers the basic
// happy path against a real MongoDB: the arrayFilter-based UpdateOne
// correctly targets the right credential within the array and sets both
// fields.
func TestUserStore_UpdateCredentialAuthenticator_SetsFields(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	user := &domain.User{
		UUID: domain.NewUserID(),
		WebauthnCredentials: []domain.WebauthnCredential{
			{ID: "cred-other", Authenticator: domain.Authenticator{SignCount: 99}},
			{ID: "cred-1", Authenticator: domain.Authenticator{SignCount: 1}},
		},
	}
	require.NoError(t, store.Users().Create(ctx, user))

	transitioned, err := store.Users().UpdateCredentialAuthenticator(ctx, user.UUID, "cred-1", 5, true)
	require.NoError(t, err)
	assert.True(t, transitioned, "this call moved CloneWarning from false to true")

	got, err := store.Users().GetByID(ctx, user.UUID)
	require.NoError(t, err)
	require.Len(t, got.WebauthnCredentials, 2)
	assert.Equal(t, uint32(5), got.WebauthnCredentials[1].Authenticator.SignCount)
	assert.True(t, got.WebauthnCredentials[1].Authenticator.CloneWarning)
	// The other credential in the array must be untouched.
	assert.Equal(t, uint32(99), got.WebauthnCredentials[0].Authenticator.SignCount)
	assert.False(t, got.WebauthnCredentials[0].Authenticator.CloneWarning)
}

// TestUserStore_UpdateCredentialAuthenticator_CloneWarningIsORonly covers
// the exact property PR #388's review demanded, against a real MongoDB:
// this method must never write CloneWarning=false over an existing true,
// via a single atomic UpdateOne with no read-then-write window at all.
func TestUserStore_UpdateCredentialAuthenticator_CloneWarningIsORonly(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	user := &domain.User{
		UUID: domain.NewUserID(),
		WebauthnCredentials: []domain.WebauthnCredential{
			{ID: "cred-1"},
		},
	}
	require.NoError(t, store.Users().Create(ctx, user))

	// First call latches CloneWarning=true.
	transitioned, err := store.Users().UpdateCredentialAuthenticator(ctx, user.UUID, "cred-1", 3, true)
	require.NoError(t, err)
	assert.True(t, transitioned, "first call should report transitioned=true")

	// A later call with cloneWarning=false (a clean, non-regressing login)
	// must NOT clear it, and must not itself report a transition.
	transitioned, err = store.Users().UpdateCredentialAuthenticator(ctx, user.UUID, "cred-1", 10, false)
	require.NoError(t, err)
	assert.False(t, transitioned, "a call with cloneWarning=false must never report transitioned=true")

	got, err := store.Users().GetByID(ctx, user.UUID)
	require.NoError(t, err)
	assert.True(t, got.WebauthnCredentials[0].Authenticator.CloneWarning,
		"CloneWarning must stay true — a call with cloneWarning=false must never clear it")
	assert.Equal(t, uint32(10), got.WebauthnCredentials[0].Authenticator.SignCount)
}

// TestUserStore_UpdateCredentialAuthenticator_SignCountMonotonic covers a
// review finding on PR #388: SignCount must never decrease. Against a real
// MongoDB, this exercises the $max operator directly.
func TestUserStore_UpdateCredentialAuthenticator_SignCountMonotonic(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	user := &domain.User{
		UUID: domain.NewUserID(),
		WebauthnCredentials: []domain.WebauthnCredential{
			{ID: "cred-1"},
		},
	}
	require.NoError(t, store.Users().Create(ctx, user))

	_, err := store.Users().UpdateCredentialAuthenticator(ctx, user.UUID, "cred-1", 20, false)
	require.NoError(t, err)
	// A lower counter arriving after must not decrease the stored baseline.
	_, err = store.Users().UpdateCredentialAuthenticator(ctx, user.UUID, "cred-1", 10, false)
	require.NoError(t, err)

	got, err := store.Users().GetByID(ctx, user.UUID)
	require.NoError(t, err)
	assert.Equal(t, uint32(20), got.WebauthnCredentials[0].Authenticator.SignCount,
		"a lower value must never decrease the stored counter")
}

func TestUserStore_UpdateCredentialAuthenticator_UserNotFound(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	_, err := store.Users().UpdateCredentialAuthenticator(ctx, domain.UserIDFromString("nonexistent"), "cred-1", 1, true)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// TestUserStore_UpdateCredentialAuthenticator_TransitionedOnlyOnce covers
// the review finding that a caller-side "was this already latched" check
// can let concurrent callers duplicate a one-time side effect: many
// goroutines race to call UpdateCredentialAuthenticator(cloneWarning=true)
// on the same credential against a real MongoDB, and exactly one of them
// must see transitioned=true.
func TestUserStore_UpdateCredentialAuthenticator_TransitionedOnlyOnce(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	user := &domain.User{
		UUID: domain.NewUserID(),
		WebauthnCredentials: []domain.WebauthnCredential{
			{ID: "cred-1"},
		},
	}
	require.NoError(t, store.Users().Create(ctx, user))

	const attempts = 16
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			transitioned, err := store.Users().UpdateCredentialAuthenticator(ctx, user.UUID, "cred-1", 1, true)
			if err == nil && transitioned {
				successes.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), successes.Load(), "expected exactly 1 of %d concurrent calls to report transitioned=true", attempts)
}

func TestChallengeStore_CRUD(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	// Create challenge
	challenge := &domain.WebauthnChallenge{
		ID:        "test-challenge-id",
		Challenge: "test-challenge-string",
		Action:    "register",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
	}

	err := store.Challenges().Create(ctx, challenge)
	require.NoError(t, err)

	// Get by ID
	retrieved, err := store.Challenges().GetByID(ctx, challenge.ID)
	require.NoError(t, err)
	assert.Equal(t, challenge.Action, retrieved.Action)

	// Delete
	err = store.Challenges().Delete(ctx, challenge.ID)
	require.NoError(t, err)

	_, err = store.Challenges().GetByID(ctx, challenge.ID)
	assert.Error(t, err)
}

func TestChallengeStore_DeleteExpired(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	// Create expired challenge
	expired := &domain.WebauthnChallenge{
		ID:        "expired-challenge",
		Challenge: "test",
		Action:    "register",
		ExpiresAt: time.Now().Add(-1 * time.Minute), // Already expired
		CreatedAt: time.Now().Add(-2 * time.Minute),
	}
	err := store.Challenges().Create(ctx, expired)
	require.NoError(t, err)

	// Create valid challenge
	valid := &domain.WebauthnChallenge{
		ID:        "valid-challenge",
		Challenge: "test",
		Action:    "register",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
	}
	err = store.Challenges().Create(ctx, valid)
	require.NoError(t, err)

	// Delete expired
	err = store.Challenges().DeleteExpired(ctx)
	require.NoError(t, err)

	// Expired should be gone
	_, err = store.Challenges().GetByID(ctx, expired.ID)
	assert.Error(t, err)

	// Valid should still exist
	_, err = store.Challenges().GetByID(ctx, valid.ID)
	assert.NoError(t, err)
}

func TestCredentialStore_CRUD(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	tenantID := domain.DefaultTenantID
	holderDID := "did:key:holder123"

	// Create credential
	cred := &domain.VerifiableCredential{
		TenantID:             tenantID,
		HolderDID:            holderDID,
		CredentialIdentifier: "urn:credential:test1",
		Credential:           "eyJhbGciOiJFUzI1NiJ9...",
		Format:               "jwt_vc",
		CreatedAt:            time.Now(),
	}

	err := store.Credentials().Create(ctx, cred)
	require.NoError(t, err)
	assert.Greater(t, cred.ID, int64(0)) // Should have auto-generated ID

	// Get by ID
	retrieved, err := store.Credentials().GetByID(ctx, tenantID, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, cred.CredentialIdentifier, retrieved.CredentialIdentifier)

	// Get by identifier
	retrieved, err = store.Credentials().GetByIdentifier(ctx, tenantID, holderDID, cred.CredentialIdentifier)
	require.NoError(t, err)
	assert.Equal(t, cred.ID, retrieved.ID)

	// Get all by holder
	all, err := store.Credentials().GetAllByHolder(ctx, tenantID, holderDID)
	require.NoError(t, err)
	assert.Len(t, all, 1)

	// Delete
	err = store.Credentials().Delete(ctx, tenantID, holderDID, cred.CredentialIdentifier)
	require.NoError(t, err)

	_, err = store.Credentials().GetByID(ctx, tenantID, cred.ID)
	assert.Error(t, err)
}

func TestIssuerStore_CRUD(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	tenantID := domain.DefaultTenantID

	// Create issuer
	issuer := &domain.CredentialIssuer{
		TenantID:                   tenantID,
		CredentialIssuerIdentifier: "https://issuer.example.com",
		ClientID:                   "client123",
		Visible:                    true,
	}

	err := store.Issuers().Create(ctx, issuer)
	require.NoError(t, err)
	assert.Greater(t, issuer.ID, int64(0))

	// Get by ID
	retrieved, err := store.Issuers().GetByID(ctx, tenantID, issuer.ID)
	require.NoError(t, err)
	assert.Equal(t, issuer.CredentialIssuerIdentifier, retrieved.CredentialIssuerIdentifier)

	// Get by identifier
	retrieved, err = store.Issuers().GetByIdentifier(ctx, tenantID, issuer.CredentialIssuerIdentifier)
	require.NoError(t, err)
	assert.Equal(t, issuer.ID, retrieved.ID)

	// Get all
	all, err := store.Issuers().GetAll(ctx, tenantID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(all), 1)

	// Update
	issuer.ClientID = "updated-client"
	err = store.Issuers().Update(ctx, issuer)
	require.NoError(t, err)

	retrieved, err = store.Issuers().GetByID(ctx, tenantID, issuer.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated-client", retrieved.ClientID)

	// Delete
	err = store.Issuers().Delete(ctx, tenantID, issuer.ID)
	require.NoError(t, err)

	_, err = store.Issuers().GetByID(ctx, tenantID, issuer.ID)
	assert.Error(t, err)
}

// TestIssuerStore_UniqueConstraint_SameTenant tests that duplicate issuers in the same tenant are rejected
func TestIssuerStore_UniqueConstraint_SameTenant(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	tenantID := domain.DefaultTenantID
	identifier := "https://issuer-duplicate-test.example.com"

	// Create first issuer
	issuer1 := &domain.CredentialIssuer{
		TenantID:                   tenantID,
		CredentialIssuerIdentifier: identifier,
		ClientID:                   "client1",
		Visible:                    true,
	}
	err := store.Issuers().Create(ctx, issuer1)
	require.NoError(t, err)

	// Attempt to create second issuer with same identifier in same tenant
	issuer2 := &domain.CredentialIssuer{
		TenantID:                   tenantID,
		CredentialIssuerIdentifier: identifier,
		ClientID:                   "client2",
		Visible:                    true,
	}
	err = store.Issuers().Create(ctx, issuer2)

	// Should fail with ErrAlreadyExists (duplicate key)
	assert.Error(t, err, "Creating duplicate issuer in same tenant should fail")
}

// TestIssuerStore_UniqueConstraint_DifferentTenants tests that same identifier works in different tenants
func TestIssuerStore_UniqueConstraint_DifferentTenants(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	identifier := "https://issuer-multi-tenant.example.com"

	// Create tenant 1
	tenant1 := &domain.Tenant{
		ID:          domain.TenantID("test-tenant-issuer-1"),
		Name:        "Test Tenant 1",
		DisplayName: "Test Tenant 1",
		Enabled:     true,
	}
	err := store.Tenants().Create(ctx, tenant1)
	require.NoError(t, err)

	// Create tenant 2
	tenant2 := &domain.Tenant{
		ID:          domain.TenantID("test-tenant-issuer-2"),
		Name:        "Test Tenant 2",
		DisplayName: "Test Tenant 2",
		Enabled:     true,
	}
	err = store.Tenants().Create(ctx, tenant2)
	require.NoError(t, err)

	// Create issuer in tenant 1
	issuer1 := &domain.CredentialIssuer{
		TenantID:                   tenant1.ID,
		CredentialIssuerIdentifier: identifier,
		ClientID:                   "client1",
		Visible:                    true,
	}
	err = store.Issuers().Create(ctx, issuer1)
	require.NoError(t, err)

	// Create issuer with same identifier in tenant 2 - should succeed
	issuer2 := &domain.CredentialIssuer{
		TenantID:                   tenant2.ID,
		CredentialIssuerIdentifier: identifier,
		ClientID:                   "client2",
		Visible:                    true,
	}
	err = store.Issuers().Create(ctx, issuer2)
	assert.NoError(t, err, "Same identifier in different tenants should succeed")
}

// TestVerifierStore_UniqueConstraint_SameTenant tests that duplicate verifiers in the same tenant are rejected
func TestVerifierStore_UniqueConstraint_SameTenant(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	tenantID := domain.DefaultTenantID
	url := "https://verifier-duplicate-test.example.com"

	// Create first verifier
	verifier1 := &domain.Verifier{
		TenantID: tenantID,
		Name:     "Verifier 1",
		URL:      url,
	}
	err := store.Verifiers().Create(ctx, verifier1)
	require.NoError(t, err)

	// Attempt to create second verifier with same URL in same tenant
	verifier2 := &domain.Verifier{
		TenantID: tenantID,
		Name:     "Verifier 2",
		URL:      url,
	}
	err = store.Verifiers().Create(ctx, verifier2)

	// Should fail with ErrAlreadyExists (duplicate key)
	assert.Error(t, err, "Creating duplicate verifier in same tenant should fail")
}

// TestVerifierStore_UniqueConstraint_DifferentTenants tests that same URL works in different tenants
func TestVerifierStore_UniqueConstraint_DifferentTenants(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	url := "https://verifier-multi-tenant.example.com"

	// Create tenant 1
	tenant1 := &domain.Tenant{
		ID:          domain.TenantID("test-tenant-verifier-1"),
		Name:        "Verifier Test Tenant 1",
		DisplayName: "Verifier Test Tenant 1",
		Enabled:     true,
	}
	err := store.Tenants().Create(ctx, tenant1)
	require.NoError(t, err)

	// Create tenant 2
	tenant2 := &domain.Tenant{
		ID:          domain.TenantID("test-tenant-verifier-2"),
		Name:        "Verifier Test Tenant 2",
		DisplayName: "Verifier Test Tenant 2",
		Enabled:     true,
	}
	err = store.Tenants().Create(ctx, tenant2)
	require.NoError(t, err)

	// Create verifier in tenant 1
	verifier1 := &domain.Verifier{
		TenantID: tenant1.ID,
		Name:     "Verifier 1",
		URL:      url,
	}
	err = store.Verifiers().Create(ctx, verifier1)
	require.NoError(t, err)

	// Create verifier with same URL in tenant 2 - should succeed
	verifier2 := &domain.Verifier{
		TenantID: tenant2.ID,
		Name:     "Verifier 2",
		URL:      url,
	}
	err = store.Verifiers().Create(ctx, verifier2)
	assert.NoError(t, err, "Same URL in different tenants should succeed")
}

// TestIndexes_FieldNamesMatchDomainModels validates that index field names match the bson tags in domain models.
// This is a meta-test to prevent index/model mismatches like issue #31.
func TestIndexes_FieldNamesMatchDomainModels(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	// Expected index fields for each collection based on domain model bson tags
	type indexSpec struct {
		collection     string
		expectedFields []string // Fields that should be present in at least one index
	}

	// These are the critical fields that MUST be indexed correctly to match the domain models
	specs := []indexSpec{
		{
			collection: "issuers",
			expectedFields: []string{
				"credential_issuer_identifier", // bson:"credential_issuer_identifier" from CredentialIssuer struct
				"tenant_id",                    // bson:"tenant_id" from CredentialIssuer struct (multi-tenant uniqueness)
			},
		},
		{
			collection: "verifiers",
			expectedFields: []string{
				"url",       // bson:"url" from Verifier struct
				"tenant_id", // bson:"tenant_id" from Verifier struct (multi-tenant uniqueness)
			},
		},
	}

	for _, spec := range specs {
		t.Run(spec.collection, func(t *testing.T) {
			collection := store.database.Collection(spec.collection)
			cursor, err := collection.Indexes().List(ctx)
			require.NoError(t, err)
			defer cursor.Close(ctx)

			var indexes []bson.M
			err = cursor.All(ctx, &indexes)
			require.NoError(t, err)

			// Collect all indexed field names across all indexes
			indexedFields := make(map[string]bool)
			for _, idx := range indexes {
				if key, ok := idx["key"].(bson.M); ok {
					for fieldName := range key {
						indexedFields[fieldName] = true
					}
				}
			}

			// Verify each expected field appears in at least one index
			for _, expectedField := range spec.expectedFields {
				assert.True(t, indexedFields[expectedField],
					"Collection %q should have index on field %q (bson tag from domain model)",
					spec.collection, expectedField)
			}

			// Verify incorrect field names are NOT present (regression check)
			invalidFields := map[string][]string{
				"issuers":   {"identifier"}, // Bug #31: was incorrectly "identifier"
				"verifiers": {"did"},        // Bug #31: was incorrectly "did"
			}
			for _, invalidField := range invalidFields[spec.collection] {
				assert.False(t, indexedFields[invalidField],
					"Collection %q should NOT have index on incorrect field %q",
					spec.collection, invalidField)
			}
		})
	}
}

// TestNewStore_TLSErrors tests TLS configuration error paths that don't require MongoDB connection
func TestNewStore_TLSErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("missing CA file", func(t *testing.T) {
		cfg := &config.MongoDBConfig{
			URI:        "mongodb://localhost:27017",
			Database:   "test",
			Timeout:    5,
			TLSEnabled: true,
			CAPath:     "/nonexistent/ca.pem",
		}

		_, err := NewStore(ctx, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read MongoDB CA certificate")
	})

	t.Run("invalid CA PEM", func(t *testing.T) {
		// Create temp file with invalid PEM content
		tmpFile, err := os.CreateTemp("", "invalid-ca-*.pem")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString("not a valid PEM certificate")
		require.NoError(t, err)
		tmpFile.Close()

		cfg := &config.MongoDBConfig{
			URI:        "mongodb://localhost:27017",
			Database:   "test",
			Timeout:    5,
			TLSEnabled: true,
			CAPath:     tmpFile.Name(),
		}

		_, err = NewStore(ctx, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse MongoDB CA certificate")
	})

	t.Run("missing client cert file", func(t *testing.T) {
		cfg := &config.MongoDBConfig{
			URI:        "mongodb://localhost:27017",
			Database:   "test",
			Timeout:    5,
			TLSEnabled: true,
			CertPath:   "/nonexistent/cert.pem",
			KeyPath:    "/nonexistent/key.pem",
		}

		_, err := NewStore(ctx, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load MongoDB client certificate")
	})
}

// TestChallengeStore_ConsumeByID verifies the atomic FindOneAndDelete
// primitive that fixes issue #379 (non-atomic WebAuthn challenge
// consumption): a single ConsumeByID call both returns and deletes the
// challenge.
func TestChallengeStore_ConsumeByID(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	challenge := &domain.WebauthnChallenge{
		ID:        "consume-challenge-id",
		Challenge: "test-challenge-string",
		Action:    "login",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.Challenges().Create(ctx, challenge))

	consumed, err := store.Challenges().ConsumeByID(ctx, challenge.ID)
	require.NoError(t, err)
	assert.Equal(t, challenge.Action, consumed.Action)

	_, err = store.Challenges().GetByID(ctx, challenge.ID)
	assert.Error(t, err)

	// A second consume of the same, now-deleted ID must fail.
	_, err = store.Challenges().ConsumeByID(ctx, challenge.ID)
	assert.Error(t, err)
}

// TestChallengeStore_ConsumeByID_GenericError exercises ConsumeByID's other
// error path: a real driver-level failure (as opposed to the "no such
// document" case covered above). Codecov flagged this exact line
// (`return nil, fmt.Errorf("failed to consume challenge: %w", err)`) as
// untested on PR #388 — a cancelled context forces mongo's FindOneAndDelete
// to fail with something other than mongo.ErrNoDocuments, so ConsumeByID
// must wrap and return it rather than mistaking it for storage.ErrNotFound.
func TestChallengeStore_ConsumeByID_GenericError(t *testing.T) {
	store := skipIfNoMongo(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.Challenges().ConsumeByID(ctx, "any-id")
	require.Error(t, err)
	assert.NotErrorIs(t, err, storage.ErrNotFound)
	assert.Contains(t, err.Error(), "failed to consume challenge")
}

// TestChallengeStore_ConsumeByID_ConcurrentSingleWinner reproduces the W-2 /
// issue #379 production incident directly against MongoDB: many goroutines
// race FindOneAndDelete on the exact same challenge ID. Exactly one must get
// a non-nil challenge back.
func TestChallengeStore_ConsumeByID_ConcurrentSingleWinner(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	challenge := &domain.WebauthnChallenge{
		ID:        "consume-race-id",
		Challenge: "test-challenge-string",
		Action:    "login",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.Challenges().Create(ctx, challenge))

	const attempts = 16
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if c, err := store.Challenges().ConsumeByID(ctx, challenge.ID); err == nil && c != nil {
				successes.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), successes.Load(), "expected exactly 1 of %d concurrent ConsumeByID calls to succeed", attempts)
}

// TestInviteStore_MarkCompleted_ConcurrentSingleWinner exercises the atomic
// update-if-active operation the W-1 / issue #378 fix relies on: many
// goroutines race to claim the same single-use invite code. Exactly one must
// win.
func TestInviteStore_MarkCompleted_ConcurrentSingleWinner(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	invite := &domain.Invite{
		ID:        "invite-race-id",
		TenantID:  domain.DefaultTenantID,
		Code:      "RACE-CODE",
		Status:    domain.InviteStatusActive,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, store.Invites().Create(ctx, invite))

	const attempts = 16
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			userID := domain.UserIDFromString("racer")
			if err := store.Invites().MarkCompleted(ctx, domain.DefaultTenantID, invite.Code, userID); err == nil {
				successes.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), successes.Load(), "expected exactly 1 of %d concurrent MarkCompleted calls to succeed", attempts)

	got, err := store.Invites().GetByID(ctx, invite.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.InviteStatusCompleted, got.Status)
}

// TestInviteStore_MarkCompleted_ExpiredInviteRejected covers a review
// finding on PR #388: MarkCompleted's atomic filter only checked
// status == active, not expiry, as a separate condition. An invite that
// ticks over its expiry between an earlier IsUsable() check and this call
// (e.g. while WebAuthn verification is still in flight) must not still be
// claimable — expiry has to be part of the same atomic filter.
func TestInviteStore_MarkCompleted_ExpiredInviteRejected(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()

	invite := &domain.Invite{
		ID:        "invite-expired-id",
		TenantID:  domain.DefaultTenantID,
		Code:      "EXPIRED-CODE",
		Status:    domain.InviteStatusActive,
		ExpiresAt: time.Now().Add(-time.Minute), // active status, but expired
	}
	require.NoError(t, store.Invites().Create(ctx, invite))

	userID := domain.UserIDFromString("racer")
	err := store.Invites().MarkCompleted(ctx, domain.DefaultTenantID, invite.Code, userID)
	assert.ErrorIs(t, err, storage.ErrNotFound, "MarkCompleted on an expired-but-active invite should return ErrNotFound")

	got, err := store.Invites().GetByID(ctx, invite.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.InviteStatusActive, got.Status, "MarkCompleted must not have claimed an expired invite")
}

// On a fresh database the counter must hand out 1, 2, 3, ...: with the
// driver's default "return the document before the update" the first two
// callers both got 1 and the second insert failed with a duplicate _id.
func TestNextSequence_FreshDatabaseIsMonotonic(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	counters := store.database.Collection("counters")
	// Start from a known-absent counter so a rerun against a persistent
	// MONGODB_TEST_URI (or after an interrupted run) still exercises the
	// fresh-database path rather than continuing from a leftover value.
	if _, err := counters.DeleteOne(ctx, bson.M{"_id": "test_seq"}); err != nil {
		t.Fatalf("reset test_seq counter: %v", err)
	}
	for want := int64(1); want <= 3; want++ {
		got, err := nextSequence(ctx, counters, "test_seq")
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
}
