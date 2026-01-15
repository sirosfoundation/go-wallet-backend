package memory

import (
	"slices"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

func TestNewStore(t *testing.T) {
	store := NewStore()

	if store == nil {
		t.Fatal("NewStore() returned nil")
	}

	if store.users == nil {
		t.Error("NewStore() users store not initialized")
	}

	if store.credentials == nil {
		t.Error("NewStore() credentials store not initialized")
	}
}

func TestStore_Users(t *testing.T) {
	store := NewStore()
	userStore := store.Users()

	if userStore == nil {
		t.Fatal("Users() returned nil")
	}
}

func TestStore_Credentials(t *testing.T) {
	store := NewStore()
	credStore := store.Credentials()

	if credStore == nil {
		t.Fatal("Credentials() returned nil")
	}
}

func TestStore_Presentations(t *testing.T) {
	store := NewStore()
	presStore := store.Presentations()

	if presStore == nil {
		t.Fatal("Presentations() returned nil")
	}
}

func TestStore_Challenges(t *testing.T) {
	store := NewStore()
	chalStore := store.Challenges()

	if chalStore == nil {
		t.Fatal("Challenges() returned nil")
	}
}

func TestStore_Issuers(t *testing.T) {
	store := NewStore()
	issuerStore := store.Issuers()

	if issuerStore == nil {
		t.Fatal("Issuers() returned nil")
	}
}

func TestStore_Verifiers(t *testing.T) {
	store := NewStore()
	verifierStore := store.Verifiers()

	if verifierStore == nil {
		t.Fatal("Verifiers() returned nil")
	}
}

func TestStore_Close(t *testing.T) {
	store := NewStore()
	err := store.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestStore_Ping(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	err := store.Ping(ctx)
	if err != nil {
		t.Errorf("Ping() error = %v", err)
	}
}

// User Store Tests

func TestUserStore_Create(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	users := store.Users()

	username := "testuser"
	user := &domain.User{
		UUID:     domain.NewUserID(),
		Username: &username,
		DID:      "did:key:test",
	}

	err := users.Create(ctx, user)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify user was stored
	retrieved, err := users.GetByID(ctx, user.UUID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.UUID.String() != user.UUID.String() {
		t.Error("Retrieved user UUID doesn't match")
	}
}

func TestUserStore_Create_DuplicateID(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	users := store.Users()

	username := "testuser"
	user := &domain.User{
		UUID:     domain.NewUserID(),
		Username: &username,
		DID:      "did:key:test",
	}

	err := users.Create(ctx, user)
	if err != nil {
		t.Fatalf("First Create() error = %v", err)
	}

	// Try to create user with same ID
	username2 := "testuser2"
	user2 := &domain.User{
		UUID:     user.UUID, // Same UUID
		Username: &username2,
		DID:      "did:key:test2",
	}

	err = users.Create(ctx, user2)
	if err != storage.ErrAlreadyExists {
		t.Errorf("Create() with duplicate UUID should return ErrAlreadyExists, got %v", err)
	}
}

func TestUserStore_GetByID_NotFound(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	users := store.Users()

	_, err := users.GetByID(ctx, domain.UserIDFromString("nonexistent"))
	if err != storage.ErrNotFound {
		t.Errorf("GetByID() for nonexistent user should return ErrNotFound, got %v", err)
	}
}

func TestUserStore_GetByUsername(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	users := store.Users()

	username := "findme"
	user := &domain.User{
		UUID:     domain.NewUserID(),
		Username: &username,
		DID:      "did:key:test",
	}

	err := users.Create(ctx, user)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := users.GetByUsername(ctx, username)
	if err != nil {
		t.Fatalf("GetByUsername() error = %v", err)
	}

	if *retrieved.Username != username {
		t.Errorf("Retrieved username = %q, want %q", *retrieved.Username, username)
	}
}

func TestUserStore_GetByUsername_NotFound(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	users := store.Users()

	_, err := users.GetByUsername(ctx, "nonexistent")
	if err != storage.ErrNotFound {
		t.Errorf("GetByUsername() for nonexistent user should return ErrNotFound, got %v", err)
	}
}

func TestUserStore_GetByDID(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	users := store.Users()

	username := "testuser"
	user := &domain.User{
		UUID:     domain.NewUserID(),
		Username: &username,
		DID:      "did:key:findme",
	}

	err := users.Create(ctx, user)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := users.GetByDID(ctx, "did:key:findme")
	if err != nil {
		t.Fatalf("GetByDID() error = %v", err)
	}

	if retrieved.DID != "did:key:findme" {
		t.Errorf("Retrieved DID = %q, want %q", retrieved.DID, "did:key:findme")
	}
}

func TestUserStore_Update(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	users := store.Users()

	username := "updateme"
	user := &domain.User{
		UUID:     domain.NewUserID(),
		Username: &username,
		DID:      "did:key:original",
	}

	err := users.Create(ctx, user)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Update user
	user.DID = "did:key:updated"

	err = users.Update(ctx, user)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify update
	retrieved, err := users.GetByID(ctx, user.UUID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.DID != "did:key:updated" {
		t.Errorf("DID not updated, got %q", retrieved.DID)
	}
}

func TestUserStore_Update_NotFound(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	users := store.Users()

	username := "ghost"
	user := &domain.User{
		UUID:     domain.NewUserID(),
		Username: &username,
		DID:      "did:key:test",
	}

	err := users.Update(ctx, user)
	if err != storage.ErrNotFound {
		t.Errorf("Update() for nonexistent user should return ErrNotFound, got %v", err)
	}
}

func TestUserStore_Delete(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	users := store.Users()

	username := "deleteme"
	user := &domain.User{
		UUID:     domain.NewUserID(),
		Username: &username,
		DID:      "did:key:test",
	}

	err := users.Create(ctx, user)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = users.Delete(ctx, user.UUID)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deletion
	_, err = users.GetByID(ctx, user.UUID)
	if err != storage.ErrNotFound {
		t.Error("User should be deleted")
	}
}

func TestUserStore_Delete_NotFound(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	users := store.Users()

	err := users.Delete(ctx, domain.NewUserID())
	if err != storage.ErrNotFound {
		t.Errorf("Delete() for nonexistent user should return ErrNotFound, got %v", err)
	}
}

func TestUserStore_UpdatePrivateData(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	users := store.Users()

	username := "testuser"
	user := &domain.User{
		UUID:     domain.NewUserID(),
		Username: &username,
		DID:      "did:key:test",
	}

	err := users.Create(ctx, user)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Update private data
	newData := []byte("new private data")
	err = users.UpdatePrivateData(ctx, user.UUID, newData, "")
	if err != nil {
		t.Fatalf("UpdatePrivateData() error = %v", err)
	}
}

// Credential Store Tests

func TestCredentialStore_Create(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	credentials := store.Credentials()

	cred := &domain.VerifiableCredential{
		HolderDID:            "did:key:holder",
		CredentialIdentifier: "urn:credential:123",
		Credential:           "eyJhbGciOi...",
		Format:               domain.FormatJWTVC,
	}

	err := credentials.Create(ctx, cred)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if cred.ID == 0 {
		t.Error("Create() should assign an ID")
	}
}

func TestCredentialStore_GetByIdentifier(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	credentials := store.Credentials()

	holderDID := "did:key:holder"
	credIdentifier := "urn:credential:findme"
	tenantID := domain.DefaultTenantID

	cred := &domain.VerifiableCredential{
		TenantID:             tenantID,
		HolderDID:            holderDID,
		CredentialIdentifier: credIdentifier,
		Credential:           "eyJhbGciOi...",
		Format:               domain.FormatJWTVC,
	}

	err := credentials.Create(ctx, cred)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := credentials.GetByIdentifier(ctx, tenantID, holderDID, credIdentifier)
	if err != nil {
		t.Fatalf("GetByIdentifier() error = %v", err)
	}

	if retrieved.CredentialIdentifier != credIdentifier {
		t.Errorf("Retrieved credential identifier = %q, want %q", retrieved.CredentialIdentifier, credIdentifier)
	}
}

func TestCredentialStore_GetByIdentifier_NotFound(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	credentials := store.Credentials()

	_, err := credentials.GetByIdentifier(ctx, domain.DefaultTenantID, "did:key:holder", "nonexistent")
	if err != storage.ErrNotFound {
		t.Errorf("GetByIdentifier() for nonexistent credential should return ErrNotFound, got %v", err)
	}
}

func TestCredentialStore_GetAllByHolder(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	credentials := store.Credentials()

	holderDID := "did:key:holder"
	tenantID := domain.DefaultTenantID

	// Create multiple credentials
	for i := 0; i < 3; i++ {
		cred := &domain.VerifiableCredential{
			TenantID:             tenantID,
			HolderDID:            holderDID,
			CredentialIdentifier: "urn:credential:" + string(rune('a'+i)),
			Credential:           "eyJhbGciOi...",
			Format:               domain.FormatJWTVC,
		}
		err := credentials.Create(ctx, cred)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Create credential for different holder
	otherCred := &domain.VerifiableCredential{
		TenantID:             tenantID,
		HolderDID:            "did:key:other",
		CredentialIdentifier: "urn:credential:other",
		Credential:           "eyJhbGciOi...",
		Format:               domain.FormatJWTVC,
	}
	err := credentials.Create(ctx, otherCred)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	creds, err := credentials.GetAllByHolder(ctx, tenantID, holderDID)
	if err != nil {
		t.Fatalf("GetAllByHolder() error = %v", err)
	}

	if len(creds) != 3 {
		t.Errorf("GetAllByHolder() returned %d credentials, want 3", len(creds))
	}

	for _, cred := range creds {
		if cred.HolderDID != holderDID {
			t.Errorf("Credential HolderDID = %q, want %q", cred.HolderDID, holderDID)
		}
	}
}

func TestCredentialStore_Update(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	credentials := store.Credentials()
	tenantID := domain.DefaultTenantID

	cred := &domain.VerifiableCredential{
		TenantID:             tenantID,
		HolderDID:            "did:key:holder",
		CredentialIdentifier: "urn:credential:update",
		Credential:           "original",
		Format:               domain.FormatJWTVC,
		SigCount:             0,
	}

	err := credentials.Create(ctx, cred)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	cred.SigCount = 5
	cred.Credential = "updated"

	err = credentials.Update(ctx, cred)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	retrieved, err := credentials.GetByID(ctx, tenantID, cred.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.SigCount != 5 {
		t.Errorf("SigCount not updated, got %d", retrieved.SigCount)
	}
}

func TestCredentialStore_Delete(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	credentials := store.Credentials()
	tenantID := domain.DefaultTenantID

	holderDID := "did:key:holder"
	credIdentifier := "urn:credential:delete"

	cred := &domain.VerifiableCredential{
		TenantID:             tenantID,
		HolderDID:            holderDID,
		CredentialIdentifier: credIdentifier,
		Credential:           "eyJhbGciOi...",
		Format:               domain.FormatJWTVC,
	}

	err := credentials.Create(ctx, cred)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = credentials.Delete(ctx, tenantID, holderDID, credIdentifier)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = credentials.GetByIdentifier(ctx, tenantID, holderDID, credIdentifier)
	if err != storage.ErrNotFound {
		t.Error("Credential should be deleted")
	}
}

// Presentation Store Tests

func TestPresentationStore_Create(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	presentations := store.Presentations()

	pres := &domain.VerifiablePresentation{
		HolderDID:                               "did:key:holder",
		PresentationIdentifier:                  "urn:presentation:123",
		Presentation:                            "eyJhbGciOi...",
		IncludedVerifiableCredentialIdentifiers: []string{"urn:credential:1"},
	}

	err := presentations.Create(ctx, pres)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if pres.ID == 0 {
		t.Error("Create() should assign an ID")
	}
}

func TestPresentationStore_GetByIdentifier(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	presentations := store.Presentations()
	tenantID := domain.DefaultTenantID

	holderDID := "did:key:holder"
	presIdentifier := "urn:presentation:find"

	pres := &domain.VerifiablePresentation{
		TenantID:                                tenantID,
		HolderDID:                               holderDID,
		PresentationIdentifier:                  presIdentifier,
		Presentation:                            "eyJhbGciOi...",
		IncludedVerifiableCredentialIdentifiers: []string{"urn:credential:1"},
	}

	err := presentations.Create(ctx, pres)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := presentations.GetByIdentifier(ctx, tenantID, holderDID, presIdentifier)
	if err != nil {
		t.Fatalf("GetByIdentifier() error = %v", err)
	}

	if retrieved.PresentationIdentifier != presIdentifier {
		t.Errorf("Retrieved presentation identifier = %q, want %q", retrieved.PresentationIdentifier, presIdentifier)
	}
}

func TestPresentationStore_GetAllByHolder(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	presentations := store.Presentations()
	tenantID := domain.DefaultTenantID

	holderDID := "did:key:holder"

	for i := 0; i < 2; i++ {
		pres := &domain.VerifiablePresentation{
			TenantID:               tenantID,
			HolderDID:              holderDID,
			PresentationIdentifier: "urn:presentation:" + string(rune('a'+i)),
			Presentation:           "eyJhbGciOi...",
		}
		err := presentations.Create(ctx, pres)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	presList, err := presentations.GetAllByHolder(ctx, tenantID, holderDID)
	if err != nil {
		t.Fatalf("GetAllByHolder() error = %v", err)
	}

	if len(presList) != 2 {
		t.Errorf("GetAllByHolder() returned %d presentations, want 2", len(presList))
	}
}

func TestPresentationStore_Delete(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	presentations := store.Presentations()
	tenantID := domain.DefaultTenantID

	holderDID := "did:key:holder"
	presIdentifier := "urn:presentation:delete"

	pres := &domain.VerifiablePresentation{
		TenantID:               tenantID,
		HolderDID:              holderDID,
		PresentationIdentifier: presIdentifier,
		Presentation:           "eyJhbGciOi...",
	}

	err := presentations.Create(ctx, pres)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = presentations.Delete(ctx, tenantID, holderDID, presIdentifier)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = presentations.GetByIdentifier(ctx, tenantID, holderDID, presIdentifier)
	if err != storage.ErrNotFound {
		t.Error("Presentation should be deleted")
	}
}

func TestPresentationStore_DeleteByCredentialID(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	presentations := store.Presentations()
	tenantID := domain.DefaultTenantID

	holderDID := "did:key:holder"
	credID := "urn:credential:linked"

	pres := &domain.VerifiablePresentation{
		TenantID:                                tenantID,
		HolderDID:                               holderDID,
		PresentationIdentifier:                  "urn:presentation:linked",
		Presentation:                            "eyJhbGciOi...",
		IncludedVerifiableCredentialIdentifiers: []string{credID, "urn:credential:other"},
	}

	err := presentations.Create(ctx, pres)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = presentations.DeleteByCredentialID(ctx, tenantID, holderDID, credID)
	if err != nil {
		t.Fatalf("DeleteByCredentialID() error = %v", err)
	}
}

// Challenge Store Tests

func TestChallengeStore_Create(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	challenges := store.Challenges()

	challenge := &domain.WebauthnChallenge{
		ID:        "challenge-123",
		UserID:    "user-456",
		Challenge: "random-challenge",
		Action:    "register",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	err := challenges.Create(ctx, challenge)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := challenges.GetByID(ctx, "challenge-123")
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Challenge != "random-challenge" {
		t.Errorf("Challenge = %q, want %q", retrieved.Challenge, "random-challenge")
	}
}

func TestChallengeStore_GetByID_NotFound(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	challenges := store.Challenges()

	_, err := challenges.GetByID(ctx, "nonexistent")
	if err != storage.ErrNotFound {
		t.Errorf("GetByID() for nonexistent challenge should return ErrNotFound, got %v", err)
	}
}

func TestChallengeStore_Delete(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	challenges := store.Challenges()

	challenge := &domain.WebauthnChallenge{
		ID:        "challenge-delete",
		UserID:    "user-456",
		Challenge: "random-challenge",
		Action:    "register",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	err := challenges.Create(ctx, challenge)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = challenges.Delete(ctx, "challenge-delete")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = challenges.GetByID(ctx, "challenge-delete")
	if err != storage.ErrNotFound {
		t.Error("Challenge should be deleted")
	}
}

func TestChallengeStore_DeleteExpired(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	challenges := store.Challenges()

	// Create expired challenge
	expired := &domain.WebauthnChallenge{
		ID:        "expired",
		UserID:    "user-1",
		Challenge: "expired-challenge",
		Action:    "register",
		ExpiresAt: time.Now().Add(-5 * time.Minute), // Already expired
	}

	// Create valid challenge
	valid := &domain.WebauthnChallenge{
		ID:        "valid",
		UserID:    "user-2",
		Challenge: "valid-challenge",
		Action:    "register",
		ExpiresAt: time.Now().Add(5 * time.Minute), // Not expired
	}

	err := challenges.Create(ctx, expired)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = challenges.Create(ctx, valid)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = challenges.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired() error = %v", err)
	}

	// Expired should be gone
	_, err = challenges.GetByID(ctx, "expired")
	if err != storage.ErrNotFound {
		t.Error("Expired challenge should be deleted")
	}

	// Valid should still exist
	_, err = challenges.GetByID(ctx, "valid")
	if err != nil {
		t.Error("Valid challenge should still exist")
	}
}

// Issuer Store Tests

func TestIssuerStore_Create(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	issuers := store.Issuers()

	issuer := &domain.CredentialIssuer{
		CredentialIssuerIdentifier: "https://issuer.example.com",
		ClientID:                   "client123",
		Visible:                    true,
	}

	err := issuers.Create(ctx, issuer)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if issuer.ID == 0 {
		t.Error("Create() should assign an ID")
	}
}

func TestIssuerStore_GetByIdentifier(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	issuers := store.Issuers()
	tenantID := domain.DefaultTenantID

	issuer := &domain.CredentialIssuer{
		TenantID:                   tenantID,
		CredentialIssuerIdentifier: "https://issuer.example.com",
		ClientID:                   "client123",
		Visible:                    true,
	}

	err := issuers.Create(ctx, issuer)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := issuers.GetByIdentifier(ctx, tenantID, "https://issuer.example.com")
	if err != nil {
		t.Fatalf("GetByIdentifier() error = %v", err)
	}

	if retrieved.CredentialIssuerIdentifier != "https://issuer.example.com" {
		t.Errorf("Issuer identifier = %q, want %q", retrieved.CredentialIssuerIdentifier, "https://issuer.example.com")
	}
}

func TestIssuerStore_GetAll(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	issuers := store.Issuers()
	tenantID := domain.DefaultTenantID

	for i := 0; i < 3; i++ {
		issuer := &domain.CredentialIssuer{
			TenantID:                   tenantID,
			CredentialIssuerIdentifier: "https://issuer" + string(rune('0'+i)) + ".example.com",
			ClientID:                   "client" + string(rune('0'+i)),
			Visible:                    true,
		}
		err := issuers.Create(ctx, issuer)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	issuerList, err := issuers.GetAll(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetAll() error = %v", err)
	}

	if len(issuerList) != 3 {
		t.Errorf("GetAll() returned %d issuers, want 3", len(issuerList))
	}
}

func TestIssuerStore_Update(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	issuers := store.Issuers()
	tenantID := domain.DefaultTenantID

	issuer := &domain.CredentialIssuer{
		TenantID:                   tenantID,
		CredentialIssuerIdentifier: "https://issuer.example.com",
		ClientID:                   "original",
		Visible:                    false,
	}

	err := issuers.Create(ctx, issuer)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	issuer.ClientID = "updated"
	issuer.Visible = true
	err = issuers.Update(ctx, issuer)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	retrieved, err := issuers.GetByID(ctx, tenantID, issuer.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.ClientID != "updated" {
		t.Errorf("ClientID not updated, got %q", retrieved.ClientID)
	}
}

func TestIssuerStore_Delete(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	issuers := store.Issuers()
	tenantID := domain.DefaultTenantID

	issuer := &domain.CredentialIssuer{
		TenantID:                   tenantID,
		CredentialIssuerIdentifier: "https://issuer.example.com",
		ClientID:                   "client123",
		Visible:                    true,
	}

	err := issuers.Create(ctx, issuer)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = issuers.Delete(ctx, tenantID, issuer.ID)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = issuers.GetByID(ctx, tenantID, issuer.ID)
	if err != storage.ErrNotFound {
		t.Error("Issuer should be deleted")
	}
}

// Verifier Store Tests

func TestVerifierStore_Create(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	verifiers := store.Verifiers()

	verifier := &domain.Verifier{
		Name: "Test Verifier",
		URL:  "https://verifier.example.com",
	}

	err := verifiers.Create(ctx, verifier)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if verifier.ID == 0 {
		t.Error("Create() should assign an ID")
	}
}

func TestVerifierStore_GetByID(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	verifiers := store.Verifiers()
	tenantID := domain.DefaultTenantID

	verifier := &domain.Verifier{
		TenantID: tenantID,
		Name:     "Test Verifier",
		URL:      "https://verifier.example.com",
	}

	err := verifiers.Create(ctx, verifier)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := verifiers.GetByID(ctx, tenantID, verifier.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Name != "Test Verifier" {
		t.Errorf("Verifier name = %q, want %q", retrieved.Name, "Test Verifier")
	}
}

func TestVerifierStore_GetAll(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	verifiers := store.Verifiers()
	tenantID := domain.DefaultTenantID

	for i := 0; i < 2; i++ {
		verifier := &domain.Verifier{
			TenantID: tenantID,
			Name:     "Verifier " + string(rune('A'+i)),
			URL:      "https://verifier" + string(rune('0'+i)) + ".example.com",
		}
		err := verifiers.Create(ctx, verifier)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	verifierList, err := verifiers.GetAll(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetAll() error = %v", err)
	}

	if len(verifierList) != 2 {
		t.Errorf("GetAll() returned %d verifiers, want 2", len(verifierList))
	}
}

// Concurrency Tests

func TestStore_ConcurrentUserCreation(t *testing.T) {
	ctx := t.Context()
	store := NewStore()
	users := store.Users()

	// Create users concurrently
	done := make(chan bool)
	numUsers := 100

	for i := 0; i < numUsers; i++ {
		go func(idx int) {
			username := "user" + string(rune('0'+idx%10)) + string(rune('0'+idx/10))
			user := &domain.User{
				UUID:     domain.NewUserID(),
				Username: &username,
				DID:      "did:key:" + username,
			}
			_ = users.Create(ctx, user)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numUsers; i++ {
		<-done
	}

	// Just verify no panics occurred - some creates may have failed due to duplicate usernames
}

// Test slices.Contains usage per ADR-005
func TestSlicesContains(t *testing.T) {
	formats := []domain.CredentialFormat{
		domain.FormatJWTVC,
		domain.FormatJWTVCJSON,
		domain.FormatLDPVC,
		domain.FormatSDJWTVC,
	}

	if !slices.Contains(formats, domain.FormatJWTVC) {
		t.Error("slices.Contains should find FormatJWTVC")
	}

	if slices.Contains(formats, domain.CredentialFormat("unknown")) {
		t.Error("slices.Contains should not find unknown format")
	}
}

// Tenant Store Tests

func TestStore_Tenants(t *testing.T) {
	store := NewStore()
	tenantStore := store.Tenants()

	if tenantStore == nil {
		t.Fatal("Tenants() returned nil")
	}
}

func TestStore_UserTenants(t *testing.T) {
	store := NewStore()
	userTenantStore := store.UserTenants()

	if userTenantStore == nil {
		t.Fatal("UserTenants() returned nil")
	}
}

func TestTenantStore_Create(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	tenant := &domain.Tenant{
		ID:          "test-tenant",
		Name:        "Test",
		DisplayName: "Test Tenant",
		Enabled:     true,
	}

	err := store.Tenants().Create(ctx, tenant)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Try creating duplicate
	err = store.Tenants().Create(ctx, tenant)
	if err != storage.ErrAlreadyExists {
		t.Errorf("Create() duplicate error = %v, want ErrAlreadyExists", err)
	}
}

func TestTenantStore_GetByID(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	// Get default tenant
	tenant, err := store.Tenants().GetByID(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if tenant.ID != domain.DefaultTenantID {
		t.Errorf("GetByID() tenant ID = %v, want %v", tenant.ID, domain.DefaultTenantID)
	}

	// Get non-existent tenant
	_, err = store.Tenants().GetByID(ctx, "non-existent")
	if err != storage.ErrNotFound {
		t.Errorf("GetByID() non-existent error = %v, want ErrNotFound", err)
	}
}

func TestTenantStore_GetAll(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	// Create additional tenant
	tenant := &domain.Tenant{
		ID:      "tenant2",
		Name:    "Tenant 2",
		Enabled: true,
	}
	if err := store.Tenants().Create(ctx, tenant); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	tenants, err := store.Tenants().GetAll(ctx)
	if err != nil {
		t.Fatalf("GetAll() error = %v", err)
	}

	if len(tenants) < 2 {
		t.Errorf("GetAll() returned %d tenants, want at least 2", len(tenants))
	}
}

func TestTenantStore_GetAllEnabled(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	// Create enabled and disabled tenants
	enabled := &domain.Tenant{ID: "enabled", Name: "Enabled", Enabled: true}
	disabled := &domain.Tenant{ID: "disabled", Name: "Disabled", Enabled: false}

	if err := store.Tenants().Create(ctx, enabled); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Tenants().Create(ctx, disabled); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	tenants, err := store.Tenants().GetAllEnabled(ctx)
	if err != nil {
		t.Fatalf("GetAllEnabled() error = %v", err)
	}

	for _, tenant := range tenants {
		if !tenant.Enabled {
			t.Errorf("GetAllEnabled() returned disabled tenant: %s", tenant.ID)
		}
	}
}

func TestTenantStore_Update(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	tenant := &domain.Tenant{
		ID:          "update-test",
		Name:        "Original",
		DisplayName: "Original Name",
		Enabled:     true,
	}
	if err := store.Tenants().Create(ctx, tenant); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	tenant.DisplayName = "Updated Name"
	if err := store.Tenants().Update(ctx, tenant); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	got, err := store.Tenants().GetByID(ctx, "update-test")
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if got.DisplayName != "Updated Name" {
		t.Errorf("Update() DisplayName = %s, want Updated Name", got.DisplayName)
	}

	// Update non-existent tenant
	nonExistent := &domain.Tenant{ID: "non-existent", Name: "Test"}
	if err := store.Tenants().Update(ctx, nonExistent); err != storage.ErrNotFound {
		t.Errorf("Update() non-existent error = %v, want ErrNotFound", err)
	}
}

func TestTenantStore_Delete(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	tenant := &domain.Tenant{ID: "delete-test", Name: "Delete", Enabled: true}
	if err := store.Tenants().Create(ctx, tenant); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := store.Tenants().Delete(ctx, "delete-test"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err := store.Tenants().GetByID(ctx, "delete-test")
	if err != storage.ErrNotFound {
		t.Errorf("GetByID() after delete error = %v, want ErrNotFound", err)
	}

	// Delete non-existent
	if err := store.Tenants().Delete(ctx, "non-existent"); err != storage.ErrNotFound {
		t.Errorf("Delete() non-existent error = %v, want ErrNotFound", err)
	}
}

// UserTenant Store Tests

func TestUserTenantStore_AddMembership(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	userID := domain.NewUserID()
	membership := &domain.UserTenantMembership{
		UserID:   userID,
		TenantID: domain.DefaultTenantID,
		Role:     domain.TenantRoleUser,
	}

	if err := store.UserTenants().AddMembership(ctx, membership); err != nil {
		t.Fatalf("AddMembership() error = %v", err)
	}

	// Try adding duplicate
	err := store.UserTenants().AddMembership(ctx, membership)
	if err != storage.ErrAlreadyExists {
		t.Errorf("AddMembership() duplicate error = %v, want ErrAlreadyExists", err)
	}
}

func TestUserTenantStore_IsMember(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	userID := domain.NewUserID()
	membership := &domain.UserTenantMembership{
		UserID:   userID,
		TenantID: domain.DefaultTenantID,
		Role:     domain.TenantRoleUser,
	}

	// Check before adding
	isMember, err := store.UserTenants().IsMember(ctx, userID, domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("IsMember() error = %v", err)
	}
	if isMember {
		t.Error("IsMember() = true before adding, want false")
	}

	// Add membership
	if err := store.UserTenants().AddMembership(ctx, membership); err != nil {
		t.Fatalf("AddMembership() error = %v", err)
	}

	// Check after adding
	isMember, err = store.UserTenants().IsMember(ctx, userID, domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("IsMember() error = %v", err)
	}
	if !isMember {
		t.Error("IsMember() = false after adding, want true")
	}
}

func TestUserTenantStore_GetMembership(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	userID := domain.NewUserID()
	membership := &domain.UserTenantMembership{
		UserID:   userID,
		TenantID: domain.DefaultTenantID,
		Role:     domain.TenantRoleAdmin,
	}

	if err := store.UserTenants().AddMembership(ctx, membership); err != nil {
		t.Fatalf("AddMembership() error = %v", err)
	}

	got, err := store.UserTenants().GetMembership(ctx, userID, domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("GetMembership() error = %v", err)
	}
	if got.Role != domain.TenantRoleAdmin {
		t.Errorf("GetMembership().Role = %s, want %s", got.Role, domain.TenantRoleAdmin)
	}

	// Get non-existent
	_, err = store.UserTenants().GetMembership(ctx, domain.NewUserID(), domain.DefaultTenantID)
	if err != storage.ErrNotFound {
		t.Errorf("GetMembership() non-existent error = %v, want ErrNotFound", err)
	}
}

func TestUserTenantStore_GetUserTenants(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	userID := domain.NewUserID()

	// Create tenants
	tenant1 := &domain.Tenant{ID: "user-tenants-1", Name: "T1", Enabled: true}
	tenant2 := &domain.Tenant{ID: "user-tenants-2", Name: "T2", Enabled: true}
	if err := store.Tenants().Create(ctx, tenant1); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Tenants().Create(ctx, tenant2); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Add memberships
	m1 := &domain.UserTenantMembership{UserID: userID, TenantID: "user-tenants-1", Role: "user"}
	m2 := &domain.UserTenantMembership{UserID: userID, TenantID: "user-tenants-2", Role: "user"}
	if err := store.UserTenants().AddMembership(ctx, m1); err != nil {
		t.Fatalf("AddMembership() error = %v", err)
	}
	if err := store.UserTenants().AddMembership(ctx, m2); err != nil {
		t.Fatalf("AddMembership() error = %v", err)
	}

	tenantIDs, err := store.UserTenants().GetUserTenants(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserTenants() error = %v", err)
	}

	if len(tenantIDs) != 2 {
		t.Errorf("GetUserTenants() returned %d tenants, want 2", len(tenantIDs))
	}
}

func TestUserTenantStore_GetTenantUsers(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	tenant := &domain.Tenant{ID: "tenant-users", Name: "TU", Enabled: true}
	if err := store.Tenants().Create(ctx, tenant); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	user1 := domain.NewUserID()
	user2 := domain.NewUserID()

	m1 := &domain.UserTenantMembership{UserID: user1, TenantID: "tenant-users", Role: "user"}
	m2 := &domain.UserTenantMembership{UserID: user2, TenantID: "tenant-users", Role: "user"}
	if err := store.UserTenants().AddMembership(ctx, m1); err != nil {
		t.Fatalf("AddMembership() error = %v", err)
	}
	if err := store.UserTenants().AddMembership(ctx, m2); err != nil {
		t.Fatalf("AddMembership() error = %v", err)
	}

	userIDs, err := store.UserTenants().GetTenantUsers(ctx, "tenant-users")
	if err != nil {
		t.Fatalf("GetTenantUsers() error = %v", err)
	}

	if len(userIDs) != 2 {
		t.Errorf("GetTenantUsers() returned %d users, want 2", len(userIDs))
	}
}

func TestUserTenantStore_RemoveMembership(t *testing.T) {
	ctx := t.Context()
	store := NewStore()

	userID := domain.NewUserID()
	membership := &domain.UserTenantMembership{
		UserID:   userID,
		TenantID: domain.DefaultTenantID,
		Role:     domain.TenantRoleUser,
	}

	if err := store.UserTenants().AddMembership(ctx, membership); err != nil {
		t.Fatalf("AddMembership() error = %v", err)
	}

	if err := store.UserTenants().RemoveMembership(ctx, userID, domain.DefaultTenantID); err != nil {
		t.Fatalf("RemoveMembership() error = %v", err)
	}

	isMember, _ := store.UserTenants().IsMember(ctx, userID, domain.DefaultTenantID)
	if isMember {
		t.Error("IsMember() = true after removal, want false")
	}

	// Remove non-existent
	err := store.UserTenants().RemoveMembership(ctx, domain.NewUserID(), domain.DefaultTenantID)
	if err != storage.ErrNotFound {
		t.Errorf("RemoveMembership() non-existent error = %v, want ErrNotFound", err)
	}
}
