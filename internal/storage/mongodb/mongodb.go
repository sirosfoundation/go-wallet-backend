package mongodb

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Store implements MongoDB storage
type Store struct {
	client   *mongo.Client
	database *mongo.Database
	cfg      *config.MongoDBConfig

	users         *UserStore
	tenants       *TenantStore
	userTenants   *UserTenantStore
	credentials   *CredentialStore
	presentations *PresentationStore
	challenges    *ChallengeStore
	issuers       *IssuerStore
	verifiers     *VerifierStore
}

// NewStore creates a new MongoDB store
func NewStore(ctx context.Context, cfg *config.MongoDBConfig) (*Store, error) {
	clientOptions := options.Client().
		ApplyURI(cfg.URI).
		SetConnectTimeout(time.Duration(cfg.Timeout) * time.Second)

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping the database to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	database := client.Database(cfg.Database)
	counters := database.Collection("counters")

	s := &Store{
		client:   client,
		database: database,
		cfg:      cfg,
	}

	// Initialize sub-stores
	s.users = &UserStore{collection: database.Collection("users")}
	s.tenants = &TenantStore{collection: database.Collection("tenants")}
	s.userTenants = &UserTenantStore{collection: database.Collection("user_tenants")}
	s.credentials = &CredentialStore{collection: database.Collection("credentials"), counter: counters}
	s.presentations = &PresentationStore{collection: database.Collection("presentations"), counter: counters}
	s.challenges = &ChallengeStore{collection: database.Collection("challenges")}
	s.issuers = &IssuerStore{collection: database.Collection("issuers"), counter: counters}
	s.verifiers = &VerifierStore{collection: database.Collection("verifiers"), counter: counters}

	// Initialize default tenant
	if err := s.initializeDefaultTenant(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize default tenant: %w", err)
	}

	// Create indexes
	if err := s.createIndexes(ctx); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	return s, nil
}

func (s *Store) createIndexes(ctx context.Context) error {
	// Users collection indexes
	_, err := s.users.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "username", Value: 1}}, Options: options.Index().SetUnique(true).SetSparse(true)},
		{Keys: bson.D{{Key: "did", Value: 1}}, Options: options.Index().SetUnique(true)},
	})
	if err != nil {
		return fmt.Errorf("failed to create user indexes: %w", err)
	}

	// Credentials collection indexes
	_, err = s.credentials.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "holder_did", Value: 1}, {Key: "credential_identifier", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "holder_did", Value: 1}}},
	})
	if err != nil {
		return fmt.Errorf("failed to create credential indexes: %w", err)
	}

	// Presentations collection indexes
	_, err = s.presentations.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "holder_did", Value: 1}, {Key: "presentation_identifier", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "holder_did", Value: 1}}},
	})
	if err != nil {
		return fmt.Errorf("failed to create presentation indexes: %w", err)
	}

	// Challenges collection indexes - with TTL for automatic expiration
	_, err = s.challenges.collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	})
	if err != nil {
		return fmt.Errorf("failed to create challenge indexes: %w", err)
	}

	// Issuers collection indexes
	_, err = s.issuers.collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "identifier", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create issuer indexes: %w", err)
	}

	// Verifiers collection indexes
	_, err = s.verifiers.collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "did", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create verifier indexes: %w", err)
	}

	// Tenants collection indexes
	_, err = s.tenants.collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "name", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create tenant indexes: %w", err)
	}

	// User-tenant membership indexes
	_, err = s.userTenants.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "tenant_id", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "user_id", Value: 1}}},
		{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
	})
	if err != nil {
		return fmt.Errorf("failed to create user-tenant indexes: %w", err)
	}

	return nil
}

// initializeDefaultTenant creates the default tenant if it doesn't exist
func (s *Store) initializeDefaultTenant(ctx context.Context) error {
	defaultTenant := &domain.Tenant{
		ID:          domain.DefaultTenantID,
		Name:        "default",
		DisplayName: "Default Tenant",
		Enabled:     true,
	}

	// Try to find existing default tenant
	_, err := s.tenants.GetByID(ctx, domain.DefaultTenantID)
	if err == nil {
		return nil // Already exists
	}
	if err != storage.ErrNotFound {
		return fmt.Errorf("failed to check default tenant: %w", err)
	}

	// Create default tenant
	if err := s.tenants.Create(ctx, defaultTenant); err != nil {
		return fmt.Errorf("failed to create default tenant: %w", err)
	}

	return nil
}

func (s *Store) Users() storage.UserStore                 { return s.users }
func (s *Store) Tenants() storage.TenantStore             { return s.tenants }
func (s *Store) UserTenants() storage.UserTenantStore     { return s.userTenants }
func (s *Store) Credentials() storage.CredentialStore     { return s.credentials }
func (s *Store) Presentations() storage.PresentationStore { return s.presentations }
func (s *Store) Challenges() storage.ChallengeStore       { return s.challenges }
func (s *Store) Issuers() storage.IssuerStore             { return s.issuers }
func (s *Store) Verifiers() storage.VerifierStore         { return s.verifiers }

func (s *Store) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.client.Disconnect(ctx)
}

func (s *Store) Ping(ctx context.Context) error {
	return s.client.Ping(ctx, nil)
}

// UserStore implements MongoDB user storage
type UserStore struct {
	collection *mongo.Collection
}

func (s *UserStore) Create(ctx context.Context, user *domain.User) error {
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	_, err := s.collection.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

func (s *UserStore) GetByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	var user domain.User
	err := s.collection.FindOne(ctx, bson.M{"id.id": id.String()}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

func (s *UserStore) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	var user domain.User
	err := s.collection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

func (s *UserStore) GetByDID(ctx context.Context, did string) (*domain.User, error) {
	var user domain.User
	err := s.collection.FindOne(ctx, bson.M{"did": did}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

func (s *UserStore) Update(ctx context.Context, user *domain.User) error {
	user.UpdatedAt = time.Now()
	result, err := s.collection.ReplaceOne(ctx, bson.M{"_id": user.UUID.String()}, user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *UserStore) Delete(ctx context.Context, id domain.UserID) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": id.String()})
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *UserStore) UpdatePrivateData(ctx context.Context, id domain.UserID, data []byte, ifMatch string) error {
	filter := bson.M{"id.id": id.String()}
	if ifMatch != "" {
		filter["private_data_etag"] = ifMatch
	}

	// Generate new ETag
	newETag := fmt.Sprintf("%d", time.Now().UnixNano())

	update := bson.M{
		"$set": bson.M{
			"private_data":      data,
			"private_data_etag": newETag,
			"updated_at":        time.Now(),
		},
	}

	result, err := s.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update private data: %w", err)
	}
	if result.MatchedCount == 0 {
		// Could be not found or ETag mismatch
		var user domain.User
		err := s.collection.FindOne(ctx, bson.M{"id.id": id.String()}).Decode(&user)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return storage.ErrNotFound
			}
			return fmt.Errorf("failed to check user: %w", err)
		}
		return storage.ErrInvalidInput // ETag mismatch
	}
	return nil
}
