package memory

import (
	"context"
	"sync"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// Store implements an in-memory storage
type Store struct {
	users         *UserStore
	tenants       *TenantStore
	userTenants   *UserTenantStore
	credentials   *CredentialStore
	presentations *PresentationStore
	challenges    *ChallengeStore
	issuers       *IssuerStore
	verifiers     *VerifierStore
}

// NewStore creates a new in-memory store
func NewStore() *Store {
	s := &Store{
		users:         &UserStore{data: make(map[string]*domain.User)},
		tenants:       &TenantStore{data: make(map[domain.TenantID]*domain.Tenant)},
		userTenants:   &UserTenantStore{data: make(map[string]*domain.UserTenantMembership)},
		credentials:   &CredentialStore{data: make(map[int64]*domain.VerifiableCredential)},
		presentations: &PresentationStore{data: make(map[int64]*domain.VerifiablePresentation)},
		challenges:    &ChallengeStore{data: make(map[string]*domain.WebauthnChallenge)},
		issuers:       &IssuerStore{data: make(map[int64]*domain.CredentialIssuer)},
		verifiers:     &VerifierStore{data: make(map[int64]*domain.Verifier)},
	}

	// Create default tenant
	s.tenants.data[domain.DefaultTenantID] = &domain.Tenant{
		ID:          domain.DefaultTenantID,
		Name:        "Default",
		DisplayName: "Default Tenant",
		Enabled:     true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return s
}

func (s *Store) Users() storage.UserStore                 { return s.users }
func (s *Store) Tenants() storage.TenantStore             { return s.tenants }
func (s *Store) UserTenants() storage.UserTenantStore     { return s.userTenants }
func (s *Store) Credentials() storage.CredentialStore     { return s.credentials }
func (s *Store) Presentations() storage.PresentationStore { return s.presentations }
func (s *Store) Challenges() storage.ChallengeStore       { return s.challenges }
func (s *Store) Issuers() storage.IssuerStore             { return s.issuers }
func (s *Store) Verifiers() storage.VerifierStore         { return s.verifiers }
func (s *Store) Close() error                             { return nil }
func (s *Store) Ping(ctx context.Context) error           { return nil }

// TenantStore implements in-memory tenant storage
type TenantStore struct {
	mu   sync.RWMutex
	data map[domain.TenantID]*domain.Tenant
}

func (s *TenantStore) Create(ctx context.Context, tenant *domain.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[tenant.ID]; exists {
		return storage.ErrAlreadyExists
	}

	tenant.CreatedAt = time.Now()
	tenant.UpdatedAt = time.Now()
	s.data[tenant.ID] = tenant
	return nil
}

func (s *TenantStore) GetByID(ctx context.Context, id domain.TenantID) (*domain.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenant, exists := s.data[id]
	if !exists {
		return nil, storage.ErrNotFound
	}
	return tenant, nil
}

func (s *TenantStore) GetAll(ctx context.Context) ([]*domain.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenants := make([]*domain.Tenant, 0, len(s.data))
	for _, tenant := range s.data {
		tenants = append(tenants, tenant)
	}
	return tenants, nil
}

func (s *TenantStore) GetAllEnabled(ctx context.Context) ([]*domain.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenants := make([]*domain.Tenant, 0)
	for _, tenant := range s.data {
		if tenant.Enabled {
			tenants = append(tenants, tenant)
		}
	}
	return tenants, nil
}

func (s *TenantStore) Update(ctx context.Context, tenant *domain.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[tenant.ID]; !exists {
		return storage.ErrNotFound
	}

	tenant.UpdatedAt = time.Now()
	s.data[tenant.ID] = tenant
	return nil
}

func (s *TenantStore) Delete(ctx context.Context, id domain.TenantID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[id]; !exists {
		return storage.ErrNotFound
	}

	delete(s.data, id)
	return nil
}

// UserTenantStore implements in-memory user-tenant membership storage
type UserTenantStore struct {
	mu     sync.RWMutex
	data   map[string]*domain.UserTenantMembership // key: "userID:tenantID"
	nextID int64
}

func membershipKey(userID domain.UserID, tenantID domain.TenantID) string {
	return userID.String() + ":" + string(tenantID)
}

func (s *UserTenantStore) AddMembership(ctx context.Context, membership *domain.UserTenantMembership) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := membershipKey(membership.UserID, membership.TenantID)
	if _, exists := s.data[key]; exists {
		return storage.ErrAlreadyExists
	}

	s.nextID++
	membership.ID = s.nextID
	membership.CreatedAt = time.Now()
	s.data[key] = membership
	return nil
}

func (s *UserTenantStore) RemoveMembership(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := membershipKey(userID, tenantID)
	if _, exists := s.data[key]; !exists {
		return storage.ErrNotFound
	}

	delete(s.data, key)
	return nil
}

func (s *UserTenantStore) GetUserTenants(ctx context.Context, userID domain.UserID) ([]domain.TenantID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenants := make([]domain.TenantID, 0)
	for _, membership := range s.data {
		if membership.UserID == userID {
			tenants = append(tenants, membership.TenantID)
		}
	}
	return tenants, nil
}

func (s *UserTenantStore) GetTenantUsers(ctx context.Context, tenantID domain.TenantID) ([]domain.UserID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]domain.UserID, 0)
	for _, membership := range s.data {
		if membership.TenantID == tenantID {
			users = append(users, membership.UserID)
		}
	}
	return users, nil
}

func (s *UserTenantStore) IsMember(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := membershipKey(userID, tenantID)
	_, exists := s.data[key]
	return exists, nil
}

func (s *UserTenantStore) GetMembership(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) (*domain.UserTenantMembership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := membershipKey(userID, tenantID)
	membership, exists := s.data[key]
	if !exists {
		return nil, storage.ErrNotFound
	}
	return membership, nil
}

// UserStore implements in-memory user storage
type UserStore struct {
	mu   sync.RWMutex
	data map[string]*domain.User
}

func (s *UserStore) Create(ctx context.Context, user *domain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[user.UUID.String()]; exists {
		return storage.ErrAlreadyExists
	}

	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	s.data[user.UUID.String()] = user
	return nil
}

func (s *UserStore) GetByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.data[id.String()]
	if !exists {
		return nil, storage.ErrNotFound
	}
	return user, nil
}

func (s *UserStore) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.data {
		if user.Username != nil && *user.Username == username {
			return user, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *UserStore) GetByDID(ctx context.Context, did string) (*domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.data {
		if user.DID == did {
			return user, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *UserStore) Update(ctx context.Context, user *domain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[user.UUID.String()]; !exists {
		return storage.ErrNotFound
	}

	user.UpdatedAt = time.Now()
	s.data[user.UUID.String()] = user
	return nil
}

func (s *UserStore) Delete(ctx context.Context, id domain.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[id.String()]; !exists {
		return storage.ErrNotFound
	}

	delete(s.data, id.String())
	return nil
}

func (s *UserStore) UpdatePrivateData(ctx context.Context, id domain.UserID, data []byte, ifMatch string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.data[id.String()]
	if !exists {
		return storage.ErrNotFound
	}

	// Check ETag for optimistic locking
	if ifMatch != "" && user.PrivateDataETag != ifMatch {
		return storage.ErrInvalidInput
	}

	user.UpdatePrivateData(data)
	return nil
}

// CredentialStore implements in-memory credential storage
type CredentialStore struct {
	mu     sync.RWMutex
	data   map[int64]*domain.VerifiableCredential
	nextID int64
}

func (s *CredentialStore) Create(ctx context.Context, credential *domain.VerifiableCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextID++
	credential.ID = s.nextID
	credential.CreatedAt = time.Now()
	credential.UpdatedAt = time.Now()
	s.data[credential.ID] = credential
	return nil
}

func (s *CredentialStore) GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.VerifiableCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	credential, exists := s.data[id]
	if !exists {
		return nil, storage.ErrNotFound
	}
	// Tenant isolation check
	if credential.TenantID != tenantID {
		return nil, storage.ErrNotFound
	}
	return credential, nil
}

func (s *CredentialStore) GetByIdentifier(ctx context.Context, tenantID domain.TenantID, holderDID, credentialIdentifier string) (*domain.VerifiableCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, cred := range s.data {
		if cred.TenantID == tenantID && cred.HolderDID == holderDID && cred.CredentialIdentifier == credentialIdentifier {
			return cred, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *CredentialStore) GetAllByHolder(ctx context.Context, tenantID domain.TenantID, holderDID string) ([]*domain.VerifiableCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	credentials := make([]*domain.VerifiableCredential, 0)
	for _, cred := range s.data {
		if cred.TenantID == tenantID && cred.HolderDID == holderDID {
			credentials = append(credentials, cred)
		}
	}
	return credentials, nil
}

func (s *CredentialStore) Update(ctx context.Context, credential *domain.VerifiableCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[credential.ID]; !exists {
		return storage.ErrNotFound
	}

	credential.UpdatedAt = time.Now()
	s.data[credential.ID] = credential
	return nil
}

func (s *CredentialStore) Delete(ctx context.Context, tenantID domain.TenantID, holderDID, credentialIdentifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, cred := range s.data {
		if cred.TenantID == tenantID && cred.HolderDID == holderDID && cred.CredentialIdentifier == credentialIdentifier {
			delete(s.data, id)
			return nil
		}
	}
	return storage.ErrNotFound
}

// PresentationStore implements in-memory presentation storage
type PresentationStore struct {
	mu     sync.RWMutex
	data   map[int64]*domain.VerifiablePresentation
	nextID int64
}

func (s *PresentationStore) Create(ctx context.Context, presentation *domain.VerifiablePresentation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextID++
	presentation.ID = s.nextID
	if presentation.IssuanceDate.IsZero() {
		presentation.IssuanceDate = time.Now()
	}
	s.data[presentation.ID] = presentation
	return nil
}

func (s *PresentationStore) GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.VerifiablePresentation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	presentation, exists := s.data[id]
	if !exists {
		return nil, storage.ErrNotFound
	}
	// Tenant isolation check
	if presentation.TenantID != tenantID {
		return nil, storage.ErrNotFound
	}
	return presentation, nil
}

func (s *PresentationStore) GetByIdentifier(ctx context.Context, tenantID domain.TenantID, holderDID, presentationIdentifier string) (*domain.VerifiablePresentation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, pres := range s.data {
		if pres.TenantID == tenantID && pres.HolderDID == holderDID && pres.PresentationIdentifier == presentationIdentifier {
			return pres, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *PresentationStore) GetAllByHolder(ctx context.Context, tenantID domain.TenantID, holderDID string) ([]*domain.VerifiablePresentation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	presentations := make([]*domain.VerifiablePresentation, 0)
	for _, pres := range s.data {
		if pres.TenantID == tenantID && pres.HolderDID == holderDID {
			presentations = append(presentations, pres)
		}
	}
	return presentations, nil
}

func (s *PresentationStore) DeleteByCredentialID(ctx context.Context, tenantID domain.TenantID, holderDID, credentialID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, pres := range s.data {
		if pres.TenantID == tenantID && pres.HolderDID == holderDID {
			for _, credID := range pres.IncludedVerifiableCredentialIdentifiers {
				if credID == credentialID {
					delete(s.data, id)
					break
				}
			}
		}
	}
	return nil
}

func (s *PresentationStore) Delete(ctx context.Context, tenantID domain.TenantID, holderDID, presentationIdentifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, pres := range s.data {
		if pres.TenantID == tenantID && pres.HolderDID == holderDID && pres.PresentationIdentifier == presentationIdentifier {
			delete(s.data, id)
			return nil
		}
	}
	return storage.ErrNotFound
}

// ChallengeStore implements in-memory challenge storage
type ChallengeStore struct {
	mu   sync.RWMutex
	data map[string]*domain.WebauthnChallenge
}

func (s *ChallengeStore) Create(ctx context.Context, challenge *domain.WebauthnChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[challenge.ID] = challenge
	return nil
}

func (s *ChallengeStore) GetByID(ctx context.Context, id string) (*domain.WebauthnChallenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	challenge, exists := s.data[id]
	if !exists {
		return nil, storage.ErrNotFound
	}
	return challenge, nil
}

func (s *ChallengeStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, id)
	return nil
}

func (s *ChallengeStore) DeleteExpired(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, challenge := range s.data {
		if now.After(challenge.ExpiresAt) {
			delete(s.data, id)
		}
	}
	return nil
}

// IssuerStore implements in-memory issuer storage
type IssuerStore struct {
	mu     sync.RWMutex
	data   map[int64]*domain.CredentialIssuer
	nextID int64
}

func (s *IssuerStore) Create(ctx context.Context, issuer *domain.CredentialIssuer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextID++
	issuer.ID = s.nextID
	s.data[issuer.ID] = issuer
	return nil
}

func (s *IssuerStore) GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.CredentialIssuer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	issuer, exists := s.data[id]
	if !exists {
		return nil, storage.ErrNotFound
	}
	// Tenant isolation check
	if issuer.TenantID != tenantID {
		return nil, storage.ErrNotFound
	}
	return issuer, nil
}

func (s *IssuerStore) GetByIdentifier(ctx context.Context, tenantID domain.TenantID, identifier string) (*domain.CredentialIssuer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, issuer := range s.data {
		if issuer.TenantID == tenantID && issuer.CredentialIssuerIdentifier == identifier {
			return issuer, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *IssuerStore) GetAll(ctx context.Context, tenantID domain.TenantID) ([]*domain.CredentialIssuer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	issuers := make([]*domain.CredentialIssuer, 0)
	for _, issuer := range s.data {
		if issuer.TenantID == tenantID {
			issuers = append(issuers, issuer)
		}
	}
	return issuers, nil
}

func (s *IssuerStore) Update(ctx context.Context, issuer *domain.CredentialIssuer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[issuer.ID]; !exists {
		return storage.ErrNotFound
	}

	s.data[issuer.ID] = issuer
	return nil
}

func (s *IssuerStore) Delete(ctx context.Context, tenantID domain.TenantID, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	issuer, exists := s.data[id]
	if !exists || issuer.TenantID != tenantID {
		return storage.ErrNotFound
	}

	delete(s.data, id)
	return nil
}

// VerifierStore implements in-memory verifier storage
type VerifierStore struct {
	mu     sync.RWMutex
	data   map[int64]*domain.Verifier
	nextID int64
}

func (s *VerifierStore) Create(ctx context.Context, verifier *domain.Verifier) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextID++
	verifier.ID = s.nextID
	s.data[verifier.ID] = verifier
	return nil
}

func (s *VerifierStore) GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.Verifier, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	verifier, exists := s.data[id]
	if !exists {
		return nil, storage.ErrNotFound
	}
	// Tenant isolation check
	if verifier.TenantID != tenantID {
		return nil, storage.ErrNotFound
	}
	return verifier, nil
}

func (s *VerifierStore) GetAll(ctx context.Context, tenantID domain.TenantID) ([]*domain.Verifier, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	verifiers := make([]*domain.Verifier, 0)
	for _, verifier := range s.data {
		if verifier.TenantID == tenantID {
			verifiers = append(verifiers, verifier)
		}
	}
	return verifiers, nil
}

func (s *VerifierStore) Update(ctx context.Context, verifier *domain.Verifier) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[verifier.ID]; !exists {
		return storage.ErrNotFound
	}

	s.data[verifier.ID] = verifier
	return nil
}

func (s *VerifierStore) Delete(ctx context.Context, tenantID domain.TenantID, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	verifier, exists := s.data[id]
	if !exists || verifier.TenantID != tenantID {
		return storage.ErrNotFound
	}

	delete(s.data, id)
	return nil
}
