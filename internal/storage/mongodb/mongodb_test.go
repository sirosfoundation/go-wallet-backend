package mongodb

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
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
