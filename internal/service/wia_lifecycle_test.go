package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	jwkpkg "github.com/sirosfoundation/go-wallet-backend/pkg/jwk"
)

func seedWIAInstance(t *testing.T, instances interface {
	Upsert(context.Context, *domain.WalletInstance) error
	UpdateStatus(context.Context, string, domain.InstanceStatus, string) error
}, id string, userID domain.UserID, status domain.InstanceStatus) {
	t.Helper()
	ctx := context.Background()
	if err := instances.Upsert(ctx, &domain.WalletInstance{
		ID: id, TenantID: domain.DefaultTenantID, UserID: &userID, Status: domain.InstanceStatusActive,
	}); err != nil {
		t.Fatalf("Upsert %s: %v", id, err)
	}
	if status != domain.InstanceStatusActive {
		if err := instances.UpdateStatus(ctx, id, status, "seed"); err != nil {
			t.Fatalf("UpdateStatus %s: %v", id, err)
		}
	}
}

// A deactivated wallet (every instance revoked, data erased) must not be
// revived by attesting a brand-new instance key with an access token that
// outlived the deactivation: that would record a new active instance and
// re-open passkey login without the required new enrollment.
func TestWIAService_GenerateWIA_RefusesNewKeyForDeactivatedWallet(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	ctx := context.Background()
	uid := domain.UserIDFromString("user-deactivated")
	seedWIAInstance(t, instances, "old-key-1", uid, domain.InstanceStatusRevoked)
	seedWIAInstance(t, instances, "old-key-2", uid, domain.InstanceStatusRevoked)

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	pop, _ := createTestPop(t, challenge) // a fresh instance key

	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	if !errors.Is(err, ErrWIAInstanceDeactivated) {
		t.Fatalf("GenerateWIA with a new key for a deactivated wallet: got err=%v, want ErrWIAInstanceDeactivated", err)
	}

	byUser, err := instances.GetByUser(ctx, domain.DefaultTenantID, uid)
	if err != nil {
		t.Fatalf("GetByUser: %v", err)
	}
	if len(byUser) != 2 {
		t.Fatalf("instances after refused attempt = %d, want the 2 revoked ones only (no new instance recorded)", len(byUser))
	}
	for _, inst := range byUser {
		if inst.Status != domain.InstanceStatusRevoked {
			t.Errorf("instance %s status = %s, want revoked", inst.ID, inst.Status)
		}
	}
}

// A suspended instance is reactivatable, so the wallet is not deactivated and
// the user may still enroll another device.
func TestWIAService_GenerateWIA_AllowsNewKeyWhileAnInstanceIsSuspended(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	ctx := context.Background()
	uid := domain.UserIDFromString("user-suspended")
	seedWIAInstance(t, instances, "old-key-1", uid, domain.InstanceStatusRevoked)
	seedWIAInstance(t, instances, "old-key-2", uid, domain.InstanceStatusSuspended)

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	pop, _ := createTestPop(t, challenge)

	if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
		t.Fatalf("GenerateWIA with a suspended (live) instance remaining: %v", err)
	}
	byUser, err := instances.GetByUser(ctx, domain.DefaultTenantID, uid)
	if err != nil {
		t.Fatalf("GetByUser: %v", err)
	}
	if len(byUser) != 3 {
		t.Errorf("instances = %d, want 3 (the new key was recorded)", len(byUser))
	}
}

// failingUpsertInstances makes Upsert fail: the instance record is the
// enforcement boundary for suspension/revocation, so a WIA must not be
// issued when it cannot be written.
type failingUpsertInstances struct{ storage.WalletInstanceStore }

func (failingUpsertInstances) Upsert(context.Context, *domain.WalletInstance) error {
	return errors.New("db down")
}

func TestWIAService_GenerateWIA_FailsWhenInstanceCannotBeRecorded(t *testing.T) {
	base := memory.NewStore().WalletInstances()
	svc := newTestWIAServiceUsing(t, failingUpsertInstances{base})
	ctx := context.Background()
	uid := domain.UserIDFromString("user-record-fail")
	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, _ := createTestPop(t, challenge)
	wia, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil || wia != "" {
		t.Fatalf("expected no WIA when the instance record cannot be written, got wia=%q err=%v", wia, err)
	}
}

// racingRevokeInstances simulates a wallet deactivation landing between
// GenerateWIA's lifecycle check and the insert of the new instance: right
// after the first Upsert it revokes every *other* instance of the user.
type racingRevokeInstances struct {
	storage.WalletInstanceStore
	userID domain.UserID
	fired  bool
}

func (r *racingRevokeInstances) Upsert(ctx context.Context, inst *domain.WalletInstance) error {
	if err := r.WalletInstanceStore.Upsert(ctx, inst); err != nil {
		return err
	}
	if r.fired {
		return nil
	}
	r.fired = true
	others, err := r.WalletInstanceStore.GetByUser(ctx, inst.TenantID, r.userID)
	if err != nil {
		return err
	}
	for _, o := range others {
		if o.ID != inst.ID && o.Status != domain.InstanceStatusRevoked {
			if err := r.WalletInstanceStore.UpdateStatus(ctx, o.ID, domain.InstanceStatusRevoked, "raced"); err != nil {
				return err
			}
		}
	}
	return nil
}

func TestWIAService_GenerateWIA_RevokesNewKeyWhenWalletDeactivatedMeanwhile(t *testing.T) {
	uid := domain.UserIDFromString("user-racing")
	base := memory.NewStore().WalletInstances()
	seedWIAInstance(t, base, "old-key", uid, domain.InstanceStatusActive) // live at check time
	racing := &racingRevokeInstances{WalletInstanceStore: base, userID: uid}
	svc := newTestWIAServiceUsing(t, racing)
	ctx := context.Background()

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, _ := createTestPop(t, challenge)
	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	if !errors.Is(err, ErrWIAInstanceDeactivated) {
		t.Fatalf("expected ErrWIAInstanceDeactivated after a concurrent deactivation, got %v", err)
	}
	byUser, err := base.GetByUser(ctx, domain.DefaultTenantID, uid)
	if err != nil {
		t.Fatal(err)
	}
	if len(byUser) != 2 {
		t.Fatalf("instances = %d, want 2 (old + the new one, both revoked)", len(byUser))
	}
	for _, inst := range byUser {
		if inst.Status != domain.InstanceStatusRevoked {
			t.Errorf("instance %s status = %s, want revoked: the new key must not stand as a live instance of a deactivated wallet", inst.ID, inst.Status)
		}
	}
}

// revokeAllRacingInstances models a revoke-all that lands between the
// lifecycle check and the post-insert re-check and takes the new record with
// it. Its UpdateStatus reports revoked -> revoked as an invalid transition the
// way the Mongo store does (the memory store treats it as a no-op).
type revokeAllRacingInstances struct {
	storage.WalletInstanceStore
	userID domain.UserID
	fired  bool
}

func (r *revokeAllRacingInstances) Upsert(ctx context.Context, inst *domain.WalletInstance) error {
	if err := r.WalletInstanceStore.Upsert(ctx, inst); err != nil {
		return err
	}
	if r.fired {
		return nil
	}
	r.fired = true
	all, err := r.WalletInstanceStore.GetByUser(ctx, inst.TenantID, r.userID)
	if err != nil {
		return err
	}
	for _, o := range all {
		if o.Status != domain.InstanceStatusRevoked {
			if err := r.WalletInstanceStore.UpdateStatus(ctx, o.ID, domain.InstanceStatusRevoked, "revoke-all raced"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *revokeAllRacingInstances) UpdateStatus(ctx context.Context, id string, status domain.InstanceStatus, reason string) error {
	cur, err := r.WalletInstanceStore.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if cur.Status == domain.InstanceStatusRevoked {
		return domain.ErrInvalidStatusTransition
	}
	return r.WalletInstanceStore.UpdateStatus(ctx, id, status, reason)
}

// A revoke-all that wins the race and revokes the just-inserted instance
// before the re-check gets to it must still surface as "wallet deactivated",
// not as a generic WIA failure from the refused revoked -> revoked update.
func TestWIAService_GenerateWIA_RevokeAllWinningRaceRefusesAsDeactivated(t *testing.T) {
	uid := domain.UserIDFromString("user-revoke-all-raced")
	base := memory.NewStore().WalletInstances()
	seedWIAInstance(t, base, "old-key", uid, domain.InstanceStatusActive)
	racing := &revokeAllRacingInstances{WalletInstanceStore: base, userID: uid}
	svc := newTestWIAServiceUsing(t, racing)
	ctx := context.Background()

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, _ := createTestPop(t, challenge)
	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	if !errors.Is(err, ErrWIAInstanceDeactivated) {
		t.Fatalf("expected ErrWIAInstanceDeactivated when a revoke-all already revoked the new instance, got %v", err)
	}
	byUser, err := base.GetByUser(ctx, domain.DefaultTenantID, uid)
	if err != nil {
		t.Fatal(err)
	}
	for _, inst := range byUser {
		if inst.Status != domain.InstanceStatusRevoked {
			t.Errorf("instance %s status = %s, want revoked", inst.ID, inst.Status)
		}
	}
}

// signTestPopWithKey signs a WIA-PoP for nonce with an existing instance key
// (a re-attestation of the same instance) and returns it with the key's jkt.
func signTestPopWithKey(t *testing.T, nonce string, key *ecdsa.PrivateKey) (pop, jkt string) {
	t.Helper()
	xBytes, yBytes := key.PublicKey.X.Bytes(), key.PublicKey.Y.Bytes()
	for len(xBytes) < 32 {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < 32 {
		yBytes = append([]byte{0}, yBytes...)
	}
	jwk := map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(xBytes),
		"y": base64.RawURLEncoding.EncodeToString(yBytes),
	}
	var err error
	if jkt, err = jwkpkg.Thumbprint(jwk); err != nil {
		t.Fatalf("jwk.Thumbprint: %v", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, &WIAPopClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "urn:wallet:instance:test",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce: nonce,
	})
	token.Header["typ"] = "oauth-client-attestation-pop+jwt"
	token.Header["jwk"] = jwk
	if pop, err = token.SignedString(key); err != nil {
		t.Fatalf("sign pop: %v", err)
	}
	return pop, jkt
}

// attestOnce runs a first attestation for uid in tenant and returns the
// instance key so the same instance can re-attest.
func attestOnce(t *testing.T, svc *WIAService, tenant domain.TenantID, uid *domain.UserID) *ecdsa.PrivateKey {
	t.Helper()
	ctx := context.Background()
	challenge, _, err := svc.CreateChallenge(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	pop, key := createTestPop(t, challenge)
	if _, err := svc.GenerateWIA(ctx, tenant, uid, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
		t.Fatalf("first GenerateWIA: %v", err)
	}
	return key
}

// An existing instance record must not be re-parented: the same instance key
// presented by another user, or from another tenant, is refused instead of
// Upsert moving tenant_id/user_id out from under the original owner.
func TestWIAService_GenerateWIA_RefusesInstanceBoundElsewhere(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	ctx := context.Background()
	owner := domain.UserIDFromString("user-owner")
	other := domain.UserIDFromString("user-other")
	key := attestOnce(t, svc, domain.DefaultTenantID, &owner)

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, jkt := signTestPopWithKey(t, challenge, key)
	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, &other, &WIARequest{Pop: pop, Challenge: challenge})
	if !errors.Is(err, ErrWIAInstanceNotOwned) {
		t.Fatalf("re-attestation by another user: got err=%v, want ErrWIAInstanceNotOwned", err)
	}

	challenge, _, err = svc.CreateChallenge(ctx, "other-tenant")
	if err != nil {
		t.Fatal(err)
	}
	pop, _ = signTestPopWithKey(t, challenge, key)
	_, err = svc.GenerateWIA(ctx, "other-tenant", &owner, &WIARequest{Pop: pop, Challenge: challenge})
	if !errors.Is(err, ErrWIAInstanceNotOwned) {
		t.Fatalf("re-attestation from another tenant: got err=%v, want ErrWIAInstanceNotOwned", err)
	}

	got, err := instances.GetByID(ctx, jkt)
	if err != nil {
		t.Fatal(err)
	}
	if got.TenantID != domain.DefaultTenantID || got.UserID == nil || *got.UserID != owner {
		t.Errorf("instance binding changed to tenant=%s user=%v; must stay with the original owner", got.TenantID, got.UserID)
	}

	// The owner re-attesting, and an anonymous re-attestation, stay allowed.
	for _, uid := range []*domain.UserID{&owner, nil} {
		challenge, _, err = svc.CreateChallenge(ctx, domain.DefaultTenantID)
		if err != nil {
			t.Fatal(err)
		}
		pop, _ = signTestPopWithKey(t, challenge, key)
		if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, uid, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
			t.Errorf("re-attestation by owner/anonymous (user=%v): %v", uid, err)
		}
	}
}

// revokeOnReattestInstances simulates a revocation landing between
// GenerateWIA's status check and the instance write of a re-attestation:
// when Upsert hits an existing record it first revokes that record.
type revokeOnReattestInstances struct{ storage.WalletInstanceStore }

func (r revokeOnReattestInstances) Upsert(ctx context.Context, inst *domain.WalletInstance) error {
	if _, err := r.WalletInstanceStore.GetByID(ctx, inst.ID); err == nil {
		if err := r.WalletInstanceStore.UpdateStatus(ctx, inst.ID, domain.InstanceStatusRevoked, "raced"); err != nil {
			return err
		}
	}
	return r.WalletInstanceStore.Upsert(ctx, inst)
}

func TestWIAService_GenerateWIA_RefusesReattestationRevokedMeanwhile(t *testing.T) {
	base := memory.NewStore().WalletInstances()
	svc := newTestWIAServiceUsing(t, revokeOnReattestInstances{base})
	ctx := context.Background()
	uid := domain.UserIDFromString("user-reattest-race")
	key := attestOnce(t, svc, domain.DefaultTenantID, &uid)

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, jkt := signTestPopWithKey(t, challenge, key)
	wia, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	if !errors.Is(err, ErrWIAInstanceDeactivated) || wia != "" {
		t.Fatalf("re-attestation revoked mid-flight: got wia=%q err=%v, want no WIA and ErrWIAInstanceDeactivated", wia, err)
	}
	got, err := base.GetByID(ctx, jkt)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != domain.InstanceStatusRevoked {
		t.Errorf("status = %s, want revoked preserved", got.Status)
	}
}

// bindingRaceInstances binds an anonymous instance to another user right
// before the caller's own Upsert runs, simulating two authenticated
// attestations racing for the same anonymous instance.
type bindingRaceInstances struct {
	storage.WalletInstanceStore
	winner domain.UserID
	fired  bool
}

func (r *bindingRaceInstances) Upsert(ctx context.Context, inst *domain.WalletInstance) error {
	if !r.fired && inst.UserID != nil {
		r.fired = true
		w := r.winner
		clone := *inst
		clone.UserID = &w
		if err := r.WalletInstanceStore.Upsert(ctx, &clone); err != nil {
			return err
		}
	}
	return r.WalletInstanceStore.Upsert(ctx, inst)
}

func TestWIAService_GenerateWIA_LoserOfBindingRaceGetsNoWIA(t *testing.T) {
	ctx := context.Background()
	base := memory.NewStore().WalletInstances()
	loser := domain.UserIDFromString("user-loser")
	winner := domain.UserIDFromString("user-winner")
	racing := &bindingRaceInstances{WalletInstanceStore: base, winner: winner}
	svc := newTestWIAServiceUsing(t, racing)

	// First attest anonymously so the instance exists without a user.
	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, key := createTestPop(t, challenge)
	if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
		t.Fatalf("anonymous attestation: %v", err)
	}

	// Now the loser attests with the same key while the winner binds first.
	challenge2, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop2 := createTestPopWithKey(t, challenge2, key)
	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, &loser, &WIARequest{Pop: pop2, Challenge: challenge2})
	if !errors.Is(err, ErrWIAInstanceNotOwned) {
		t.Fatalf("expected ErrWIAInstanceNotOwned for the loser, got %v", err)
	}
	all, err := base.GetByUser(ctx, domain.DefaultTenantID, winner)
	if err != nil || len(all) != 1 {
		t.Fatalf("the instance must be bound to the winner: %v %v", err, all)
	}
}

// tenantRaceInstances records the caller's brand-new instance in another
// tenant right before the caller's own Upsert, simulating two first
// attestations of the same key racing in two tenants.
type tenantRaceInstances struct {
	storage.WalletInstanceStore
	fired bool
}

func (r *tenantRaceInstances) Upsert(ctx context.Context, inst *domain.WalletInstance) error {
	if !r.fired {
		r.fired = true
		clone := *inst
		clone.TenantID = "other-tenant"
		clone.UserID = nil
		if err := r.WalletInstanceStore.Upsert(ctx, &clone); err != nil {
			return err
		}
	}
	return r.WalletInstanceStore.Upsert(ctx, inst)
}

func TestWIAService_GenerateWIA_LoserOfTenantRaceGetsNoWIA(t *testing.T) {
	ctx := context.Background()
	base := memory.NewStore().WalletInstances()
	svc := newTestWIAServiceUsing(t, &tenantRaceInstances{WalletInstanceStore: base})
	uid := domain.UserIDFromString("user-tenant-race")
	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, _ := createTestPop(t, challenge)
	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	if !errors.Is(err, ErrWIAInstanceNotOwned) {
		t.Fatalf("expected ErrWIAInstanceNotOwned when the record landed in another tenant, got %v", err)
	}
	mine, err := base.GetByUser(ctx, domain.DefaultTenantID, uid)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		t.Fatal(err)
	}
	if len(mine) != 0 {
		t.Fatalf("no instance may exist for the loser in its tenant: %v", mine)
	}
}

// An anonymously attested instance that a deactivated wallet's user then
// tries to bind must be refused like a brand-new key: otherwise the
// new-enrollment requirement could be bypassed via an unowned record.
func TestWIAService_GenerateWIA_RefusesBindingUnownedInstanceToDeactivatedWallet(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	ctx := context.Background()
	uid := domain.UserIDFromString("user-deactivated-bind")
	seedWIAInstance(t, instances, "old-key", uid, domain.InstanceStatusRevoked)

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, key := createTestPop(t, challenge)
	if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
		t.Fatalf("anonymous attestation: %v", err)
	}

	challenge2, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: createTestPopWithKey(t, challenge2, key), Challenge: challenge2})
	if !errors.Is(err, ErrWIAInstanceDeactivated) {
		t.Fatalf("binding an unowned instance to a deactivated wallet must be refused, got %v", err)
	}
}

// The passkey link decides whether suspension and revocation refuse login
// with that passkey, and the first link recorded for an instance wins, so a
// client must not be able to claim a passkey that is not its own.
func TestWIAService_GenerateWIA_RefusesUnownedCredentialID(t *testing.T) {
	svc, store := newTestWIAServiceWithUsers(t)
	ctx := context.Background()
	uid := domain.NewUserID()
	other := domain.NewUserID()
	// "mine" carries no tenant (registered before tenants existed) and so
	// counts as the default one; "elsewhere" is registered in another tenant
	// and can never authenticate in the default one.
	if err := store.Users().Create(ctx, &domain.User{UUID: uid, WebauthnCredentials: []domain.WebauthnCredential{
		{ID: "mine"},
		{ID: "elsewhere", TenantID: domain.TenantID("other-tenant")},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Users().Create(ctx, &domain.User{UUID: other, WebauthnCredentials: []domain.WebauthnCredential{{ID: "theirs"}}}); err != nil {
		t.Fatal(err)
	}
	attest := func(userID *domain.UserID, credentialID string) error {
		challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
		if err != nil {
			t.Fatal(err)
		}
		pop, _ := createTestPop(t, challenge)
		_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, userID, &WIARequest{Pop: pop, Challenge: challenge, CredentialID: credentialID})
		return err
	}

	if err := attest(&uid, "mine"); err != nil {
		t.Fatalf("the caller's own passkey is accepted: %v", err)
	}
	if err := attest(&uid, ""); err != nil {
		t.Fatalf("claiming no passkey stays optional: %v", err)
	}
	for _, tc := range []struct {
		name         string
		userID       *domain.UserID
		credentialID string
	}{
		{"another user's passkey", &uid, "theirs"},
		{"a passkey that does not exist", &uid, "made-up"},
		{"anonymous attestation claiming a passkey", nil, "mine"},
		{"the caller's own passkey from another tenant", &uid, "elsewhere"},
	} {
		if err := attest(tc.userID, tc.credentialID); !errors.Is(err, ErrWIACredentialNotOwned) {
			t.Errorf("%s: expected ErrWIACredentialNotOwned, got %v", tc.name, err)
		}
	}
}
