package mongodb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
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

	users           *UserStore
	tenants         *TenantStore
	userTenants     *UserTenantStore
	credentials     *CredentialStore
	presentations   *PresentationStore
	challenges      *ChallengeStore
	issuers         *IssuerStore
	verifiers       *VerifierStore
	invites         *InviteStore
	walletInstances *WalletInstanceStore
	keyAttestations *KeyAttestationStore
}

// NewStore creates a MongoDB store and runs startup initialization (default tenant, indexes).
func NewStore(ctx context.Context, cfg *config.MongoDBConfig) (*Store, error) {
	return newStore(ctx, cfg, true)
}

// NewReadOnlyStore connects like NewStore but performs no startup writes, for
// a process that only reads (e.g. a standalone engine checking a token cut-off).
// Its principal needs read rights on users and user_deletion_tombstones; the
// gate fails closed if the tombstone read is denied.
func NewReadOnlyStore(ctx context.Context, cfg *config.MongoDBConfig) (*Store, error) {
	return newStore(ctx, cfg, false)
}

func newStore(ctx context.Context, cfg *config.MongoDBConfig, initialize bool) (*Store, error) {
	clientOptions := options.Client().
		ApplyURI(cfg.URI).
		SetConnectTimeout(time.Duration(cfg.Timeout) * time.Second)

	if cfg.TLSEnabled {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAPath != "" {
			caCert, err := os.ReadFile(cfg.CAPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read MongoDB CA certificate: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse MongoDB CA certificate")
			}
			tlsCfg.RootCAs = pool
		}
		if cfg.CertPath != "" && cfg.KeyPath != "" {
			cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load MongoDB client certificate: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		clientOptions.SetTLSConfig(tlsCfg)
	}

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
	s.users = &UserStore{collection: database.Collection("users"), tombstones: database.Collection("user_deletion_tombstones")}
	s.tenants = &TenantStore{collection: database.Collection("tenants")}
	s.userTenants = &UserTenantStore{collection: database.Collection("user_tenants")}
	s.credentials = &CredentialStore{collection: database.Collection("credentials"), counter: counters}
	s.presentations = &PresentationStore{collection: database.Collection("presentations"), counter: counters}
	s.challenges = &ChallengeStore{collection: database.Collection("challenges")}
	s.issuers = &IssuerStore{collection: database.Collection("issuers"), counter: counters}
	s.verifiers = &VerifierStore{collection: database.Collection("verifiers"), counter: counters}
	s.invites = &InviteStore{collection: database.Collection("invites")}
	s.walletInstances = &WalletInstanceStore{collection: database.Collection("wallet_instances")}
	s.keyAttestations = &KeyAttestationStore{collection: database.Collection("key_attestations")}

	if !initialize {
		return s, nil
	}

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

	// Drop old incorrect issuers collection indexes
	_, _ = s.issuers.collection.Indexes().DropOne(ctx, "identifier_1")

	// Issuers collection indexes
	_, err = s.issuers.collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "credential_issuer_identifier", Value: 1},
			{Key: "tenant_id", Value: 1},
		},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create issuer indexes: %w", err)
	}

	// Drop old incorrect verifiers collection indexes
	_, _ = s.verifiers.collection.Indexes().DropOne(ctx, "did_1")

	// Verifiers collection indexes
	_, err = s.verifiers.collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "url", Value: 1},
			{Key: "tenant_id", Value: 1},
		},
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

	// Invites collection indexes
	_, err = s.invites.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "code", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "status", Value: 1}}},
	})
	if err != nil {
		return fmt.Errorf("failed to create invite indexes: %w", err)
	}

	// Wallet instances collection indexes
	_, err = s.walletInstances.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "status", Value: 1}}},
		{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "user_id", Value: 1}}},
		// user_id alone, for cross-tenant lookups (GetAllByUser): the compound
		// index above is led by tenant_id and cannot serve them.
		{Keys: bson.D{{Key: "user_id", Value: 1}}},
	})
	if err != nil {
		return fmt.Errorf("failed to create wallet instance indexes: %w", err)
	}

	// Deletion tombstones expire at their own expires_at; the service sweeper
	// does the same, so a lagging TTL monitor is harmless.
	_, err = s.users.tombstones.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	})
	if err != nil {
		return fmt.Errorf("failed to create deletion tombstone indexes: %w", err)
	}

	// Key attestations collection indexes
	_, err = s.keyAttestations.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "wallet_instance_id", Value: 1}}},
		{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
	})
	if err != nil {
		return fmt.Errorf("failed to create key attestation indexes: %w", err)
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

func (s *Store) Users() storage.UserStore                     { return s.users }
func (s *Store) Tenants() storage.TenantStore                 { return s.tenants }
func (s *Store) UserTenants() storage.UserTenantStore         { return s.userTenants }
func (s *Store) Credentials() storage.CredentialStore         { return s.credentials }
func (s *Store) Presentations() storage.PresentationStore     { return s.presentations }
func (s *Store) Challenges() storage.ChallengeStore           { return s.challenges }
func (s *Store) Issuers() storage.IssuerStore                 { return s.issuers }
func (s *Store) Verifiers() storage.VerifierStore             { return s.verifiers }
func (s *Store) Invites() storage.InviteStore                 { return s.invites }
func (s *Store) WalletInstances() storage.WalletInstanceStore { return s.walletInstances }
func (s *Store) KeyAttestations() storage.KeyAttestationStore { return s.keyAttestations }

// Database returns the underlying MongoDB database for creating additional
// collections (e.g., WIA challenge store with TTL indexes).
func (s *Store) Database() *mongo.Database { return s.database }

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
	// tombstones holds domain.DeletionTombstone documents, _id = user id.
	tombstones *mongo.Collection
}

func (s *UserStore) PutDeletionTombstone(ctx context.Context, t *domain.DeletionTombstone) error {
	if t == nil || t.UserID == "" {
		return storage.ErrInvalidInput
	}
	update := bson.M{
		// A retry keeps the earliest deleted_at and only moves expires_at later.
		"$min": bson.M{"deleted_at": t.DeletedAt},
		"$max": bson.M{"expires_at": t.ExpiresAt},
	}
	if len(t.TenantIDs) > 0 {
		update["$addToSet"] = bson.M{"tenant_ids": bson.M{"$each": t.TenantIDs}}
	}
	_, err := s.tombstones.UpdateOne(ctx, bson.M{"_id": t.UserID}, update, options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("%w: put deletion tombstone: %v", storage.ErrDatabase, err)
	}
	return nil
}

func (s *UserStore) GetDeletionTombstone(ctx context.Context, userID string) (*domain.DeletionTombstone, error) {
	var t domain.DeletionTombstone
	if err := s.tombstones.FindOne(ctx, bson.M{"_id": userID}).Decode(&t); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("%w: get deletion tombstone: %v", storage.ErrDatabase, err)
	}
	return &t, nil
}

func (s *UserStore) DeleteExpiredDeletionTombstones(ctx context.Context, now time.Time) (int, error) {
	res, err := s.tombstones.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": now}})
	if err != nil {
		return 0, fmt.Errorf("%w: delete expired deletion tombstones: %v", storage.ErrDatabase, err)
	}
	return int(res.DeletedCount), nil
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
	// False positive: bson.M is a typed document builder, not a query string.
	// The key here ("_id.id") is a fixed literal; id.String() is only ever used
	// as a plain field VALUE, which the driver BSON-encodes as a string and
	// compares by equality. A string value can never be interpreted as a Mongo
	// query operator (only "$"-prefixed map KEYS are), so untrusted input
	// reaching this call site cannot inject query semantics.
	err := s.collection.FindOne(ctx, bson.M{"_id.id": id.String()}).Decode(&user) // codeql[go/sql-injection]
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
	// Whole-document replace, matching only while the stored fence has not
	// advanced past the caller's copy, so a copy loaded before a lifecycle write
	// cannot write the old cut-off or erased data back.
	filter := bson.M{
		"_id.id":     user.UUID.String(),
		"auth_fence": bson.M{"$not": bson.M{"$gt": user.AuthFence}},
	}
	result, err := s.collection.ReplaceOne(ctx, filter, user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	if result.MatchedCount == 0 {
		n, err := s.collection.CountDocuments(ctx, bson.M{"_id.id": user.UUID.String()})
		if err != nil {
			return fmt.Errorf("failed to update user: %w", err)
		}
		if n == 0 {
			return storage.ErrNotFound
		}
		return storage.ErrStaleWrite
	}
	return nil
}

func (s *UserStore) Delete(ctx context.Context, id domain.UserID) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id.id": id.String()})
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// cutoffStage is the update-pipeline stage behind both lifecycle writes: it
// advances auth_invalid_before to t ($max, so a delayed older event cannot roll
// it back) and always advances auth_fence, so UserStore.Update refuses any
// record loaded before this write.
func cutoffStage(t time.Time, extra bson.D) bson.D {
	set := bson.D{
		{Key: "auth_fence", Value: bson.D{{Key: "$add", Value: bson.A{bson.D{{Key: "$ifNull", Value: bson.A{"$auth_fence", 0}}}, 1}}}},
		{Key: "auth_invalid_before", Value: bson.D{{Key: "$max", Value: bson.A{t, "$auth_invalid_before"}}}},
	}
	set = append(set, extra...)
	return bson.D{{Key: "$set", Value: set}}
}

func (s *UserStore) InvalidateAuthBefore(ctx context.Context, id domain.UserID, t time.Time) error {
	result, err := s.collection.UpdateOne(ctx, bson.M{"_id.id": id.String()}, mongo.Pipeline{cutoffStage(t, nil)})
	if err != nil {
		return fmt.Errorf("failed to set auth cut-off: %w", err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// cutoffNotRefusingFilter matches the user whose stored cut-off does not refuse
// a token issued at tokenIssuedAt (unset, or before the token's second; see
// tokengate.IssuedBeforeCutoff). A zero tokenIssuedAt adds no condition.
func cutoffNotRefusingFilter(id domain.UserID, tokenIssuedAt time.Time) bson.M {
	filter := bson.M{"_id.id": id.String()}
	if !tokenIssuedAt.IsZero() {
		filter["$or"] = bson.A{
			bson.M{"auth_invalid_before": bson.M{"$lt": time.Unix(tokenIssuedAt.Unix(), 0)}},
			bson.M{"auth_invalid_before": nil}, // unset or null (zero cut-off is omitted)
		}
	}
	return filter
}

func (s *UserStore) InvalidateAuthBeforeForToken(ctx context.Context, id domain.UserID, t time.Time, tokenIssuedAt time.Time) error {
	// One conditional UpdateOne: check and advance are a single atomic write.
	result, err := s.collection.UpdateOne(ctx, cutoffNotRefusingFilter(id, tokenIssuedAt), mongo.Pipeline{cutoffStage(t, nil)})
	if err != nil {
		return fmt.Errorf("failed to set auth cut-off: %w", err)
	}
	if result.MatchedCount == 0 {
		n, err := s.collection.CountDocuments(ctx, bson.M{"_id.id": id.String()})
		if err != nil {
			return fmt.Errorf("failed to set auth cut-off: %w", err)
		}
		if n == 0 {
			return storage.ErrNotFound
		}
		return storage.ErrStaleWrite
	}
	return nil
}

func (s *UserStore) EraseWalletData(ctx context.Context, id domain.UserID, fence time.Time) error {
	// One pipeline update: erasure and fence advance land together.
	stage := cutoffStage(fence, bson.D{
		{Key: "private_data", Value: "$$REMOVE"},
		{Key: "private_data_etag", Value: "$$REMOVE"},
		{Key: "keys", Value: "$$REMOVE"},
		{Key: "updated_at", Value: time.Now()},
	})
	result, err := s.collection.UpdateOne(ctx, bson.M{"_id.id": id.String()}, mongo.Pipeline{stage})
	if err != nil {
		return fmt.Errorf("failed to erase wallet data: %w", err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *UserStore) GetAuthCutoff(ctx context.Context, id domain.UserID) (time.Time, error) {
	var doc struct {
		Cutoff time.Time `bson:"auth_invalid_before"`
	}
	err := s.collection.FindOne(ctx, bson.M{"_id.id": id.String()},
		options.FindOne().SetProjection(bson.M{"auth_invalid_before": 1})).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return time.Time{}, storage.ErrNotFound
		}
		return time.Time{}, fmt.Errorf("failed to read auth cut-off: %w", err)
	}
	return doc.Cutoff, nil
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

func (s *UserStore) UpdateCredentialAuthenticator(ctx context.Context, id domain.UserID, credentialID string, signCount uint32, cloneWarning bool) (bool, error) {
	setFields := bson.M{
		"updated_at": time.Now(),
	}
	// OR-only: only ever include clone_warning in the $set when it's true.
	// Omitting the field entirely when false leaves whatever is currently
	// stored untouched — this single UpdateOne is the whole operation, so
	// there is no read-then-write window at all: it can never overwrite an
	// existing true with false, regardless of how concurrent calls
	// interleave.
	if cloneWarning {
		setFields["webauthn_credentials.$[cred].authenticator.clone_warning"] = true
	}

	// SignCount must be monotonic non-decreasing: two concurrent logins can
	// persist out of order (e.g. a counter=20 assertion lands before a
	// counter=10 one from an earlier, slower request), and a plain
	// unconditional overwrite would let the later write lower the stored
	// baseline — which would falsely flag a subsequent legitimate assertion
	// as a clone regression, and could let an actually-regressing counter
	// slip through as "non-regressing" against the artificially-lowered
	// baseline. $max is MongoDB's atomic "only update if greater" operator:
	// combined with $set in the same update document, this whole operation
	// is still a single atomic write.
	update := bson.M{
		"$set": setFields,
		"$max": bson.M{
			"webauthn_credentials.$[cred].authenticator.sign_count": signCount,
		},
	}

	opts := options.FindOneAndUpdate().
		SetArrayFilters(options.ArrayFilters{
			Filters: []interface{}{bson.M{"cred.id": credentialID}},
		}).
		// Return the PRE-image (the document as it was immediately before
		// this update was applied), not the default post-image, so we can
		// inspect what CloneWarning was a moment before this exact write —
		// this is what makes the returned "transitioned" value a genuine
		// compare-and-set outcome of the single atomic operation, rather
		// than a separate, racy read.
		SetReturnDocument(options.Before)

	var before domain.User
	err := s.collection.FindOneAndUpdate(ctx, bson.M{"_id.id": id.String()}, update, opts).Decode(&before)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false, storage.ErrNotFound
		}
		return false, fmt.Errorf("failed to update credential authenticator: %w", err)
	}

	if !cloneWarning {
		return false, nil
	}
	for _, c := range before.WebauthnCredentials {
		if c.ID == credentialID {
			return !c.Authenticator.CloneWarning, nil
		}
	}
	// Credential not found in the pre-image: the arrayFilter matched zero
	// array elements (see the interface doc comment on the silent no-op
	// case) — conservatively report no transition.
	return false, nil
}

// idFilter returns a BSON filter that matches a document by _id.
// Go typed strings in bson.D Value fields are always encoded as BSON strings
// by the driver — never as documents or query operators — so this is safe
// from NoSQL injection. CodeQL alerts on these are dismissed as false positives.
func idFilter(id string) bson.D {
	return bson.D{{Key: "_id", Value: id}}
}

// fieldFilter returns a BSON filter matching a single field to a string value.
func fieldFilter(key, value string) bson.D {
	return bson.D{{Key: key, Value: value}}
}
