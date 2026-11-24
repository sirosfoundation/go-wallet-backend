package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

// afterMarkStore runs after once each time a MarkKeyAttested write has landed:
// the window in which a revocation can race the evidence write.
type afterMarkStore struct {
	storage.KeyAttestationStore
	after func()
}

func (s afterMarkStore) MarkKeyAttested(ctx context.Context, rec *domain.KeyAttestationRecord) error {
	err := s.KeyAttestationStore.MarkKeyAttested(ctx, rec)
	if err == nil && s.after != nil {
		s.after()
	}
	return err
}

// keyEvidenceLifecycleEnv is a WIA service with a fake android_key verifier,
// an instance for a fresh PoP key and the evidence store under test.
type keyEvidenceLifecycleEnv struct {
	svc       *WIAService
	instances storage.WalletInstanceStore
	keys      storage.KeyAttestationStore
	verifier  *fakeKeyVerifier
	jkt       string
	request   func(tenant domain.TenantID, user *domain.UserID) error
}

func newKeyEvidenceLifecycleEnv(t *testing.T, inst *domain.WalletInstance, wrap func(storage.KeyAttestationStore) storage.KeyAttestationStore) *keyEvidenceLifecycleEnv {
	t.Helper()
	ctx := context.Background()
	svc, instances := newTestWIAServiceWithInstances(t)
	keys := memory.NewStore().KeyAttestations()
	if wrap != nil {
		svc.SetKeyAttestations(wrap(keys))
	} else {
		svc.SetKeyAttestations(keys)
	}
	f := &fakeKeyVerifier{typ: KeyAttestationAndroidKey, res: &InstanceKeyEvidenceResult{Record: androidRecord()}}
	svc.RegisterInstanceKeyVerifier(f)

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, key := createTestPop(t, challenge)
	jkt := expectedThumbprint(t, &key.PublicKey)
	if inst != nil {
		inst.ID = jkt
		if inst.TenantID == "" {
			inst.TenantID = domain.DefaultTenantID
		}
		inst.LastAttestedAt, inst.CreatedAt, inst.UpdatedAt = time.Now().UTC(), time.Now().UTC(), time.Now().UTC()
		if err := instances.Upsert(ctx, inst); err != nil {
			t.Fatal(err)
		}
	}
	env := &keyEvidenceLifecycleEnv{svc: svc, instances: instances, keys: keys, verifier: f, jkt: jkt}
	first := true
	env.request = func(tenant domain.TenantID, user *domain.UserID) error {
		c, p := challenge, pop
		if !first {
			c, _, _ = svc.CreateChallenge(ctx, tenant)
			p = resignPop(t, key, c)
		}
		first = false
		_, err := svc.GenerateWIA(ctx, tenant, user, &WIARequest{Pop: p, Challenge: c,
			KeyAttestation: &KeyAttestation{Type: KeyAttestationAndroidKey, Raw: json.RawMessage(`{"type":"android_key"}`)}})
		return err
	}
	return env
}

func (e *keyEvidenceLifecycleEnv) noRecord(t *testing.T) {
	t.Helper()
	if rec, err := e.keys.GetByKeyThumbprint(context.Background(), e.jkt); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("key evidence was written: %+v (%v)", rec, err)
	}
}

// A revoked or suspended instance lends no evidence and takes no evidence
// write: the request is refused before the verifier runs.
func TestWIAKeyAttestation_NonLiveInstanceTakesNoEvidenceWrite(t *testing.T) {
	alice := domain.UserIDFromString("alice")
	for _, status := range []domain.InstanceStatus{domain.InstanceStatusRevoked, domain.InstanceStatusLegacySuspended} {
		t.Run(string(status), func(t *testing.T) {
			e := newKeyEvidenceLifecycleEnv(t, &domain.WalletInstance{UserID: &alice, Status: status}, nil)
			if err := e.request(domain.DefaultTenantID, &alice); !errors.Is(err, ErrWIAInstanceDeactivated) {
				t.Fatalf("err = %v, want ErrWIAInstanceDeactivated", err)
			}
			if e.verifier.calls != 0 {
				t.Fatalf("the verifier ran for a non-live instance (%d calls)", e.verifier.calls)
			}
			e.noRecord(t)
		})
	}
}

// An instance with no status is not live (unset is not active): same refusal.
func TestWIAKeyAttestation_UnsetStatusInstanceTakesNoEvidenceWrite(t *testing.T) {
	alice := domain.UserIDFromString("alice")
	e := newKeyEvidenceLifecycleEnv(t, &domain.WalletInstance{UserID: &alice}, nil)
	if err := e.request(domain.DefaultTenantID, &alice); err == nil {
		t.Fatal("an instance without a status was treated as live")
	}
	e.noRecord(t)
}

// A foreign-owned instance (other user, other tenant) takes no evidence write.
func TestWIAKeyAttestation_ForeignInstanceTakesNoEvidenceWrite(t *testing.T) {
	alice := domain.UserIDFromString("alice")
	bob := domain.UserIDFromString("bob")
	t.Run("other user", func(t *testing.T) {
		e := newKeyEvidenceLifecycleEnv(t, &domain.WalletInstance{UserID: &alice, Status: domain.InstanceStatusActive}, nil)
		if err := e.request(domain.DefaultTenantID, &bob); !errors.Is(err, ErrWIAInstanceNotOwned) {
			t.Fatalf("err = %v, want ErrWIAInstanceNotOwned", err)
		}
		if e.verifier.calls != 0 {
			t.Fatal("the verifier ran for a foreign instance")
		}
		e.noRecord(t)
	})
	t.Run("other tenant", func(t *testing.T) {
		e := newKeyEvidenceLifecycleEnv(t, &domain.WalletInstance{TenantID: "tenant-a", UserID: &alice, Status: domain.InstanceStatusActive}, nil)
		if err := e.request(domain.DefaultTenantID, &alice); !errors.Is(err, ErrWIAInstanceNotOwned) {
			t.Fatalf("err = %v, want ErrWIAInstanceNotOwned", err)
		}
		e.noRecord(t)
	})
}

// The instance is revoked after the evidence write landed: the refused request
// must not leave the evidence behind.
func TestWIAKeyAttestation_RevocationDuringWriteUndoesNewEvidence(t *testing.T) {
	alice := domain.UserIDFromString("alice")
	var e *keyEvidenceLifecycleEnv
	revoke := func() {
		if err := e.instances.UpdateStatus(context.Background(), e.jkt, domain.DefaultTenantID, domain.InstanceStatusRevoked, "race"); err != nil {
			t.Error(err)
		}
	}
	e = newKeyEvidenceLifecycleEnv(t, &domain.WalletInstance{UserID: &alice, Status: domain.InstanceStatusActive},
		func(inner storage.KeyAttestationStore) storage.KeyAttestationStore {
			return afterMarkStore{KeyAttestationStore: inner, after: func() { revoke() }}
		})
	if err := e.request(domain.DefaultTenantID, &alice); !errors.Is(err, ErrWIAInstanceDeactivated) {
		t.Fatalf("err = %v, want ErrWIAInstanceDeactivated", err)
	}
	e.noRecord(t)
}

// An overwrite is undone by restoring the evidence it replaced, not by
// deleting it.
func TestWIAKeyAttestation_RevocationDuringWriteRestoresReplacedEvidence(t *testing.T) {
	alice := domain.UserIDFromString("alice")
	var e *keyEvidenceLifecycleEnv
	e = newKeyEvidenceLifecycleEnv(t, &domain.WalletInstance{UserID: &alice, Status: domain.InstanceStatusActive},
		func(inner storage.KeyAttestationStore) storage.KeyAttestationStore {
			return afterMarkStore{KeyAttestationStore: inner, after: func() {
				if err := e.instances.UpdateStatus(context.Background(), e.jkt, domain.DefaultTenantID, domain.InstanceStatusRevoked, "race"); err != nil {
					t.Error(err)
				}
			}}
		})
	// Weaker evidence (tee) is already on file for this key; the submission
	// (strongbox) supersedes it.
	older := &domain.KeyAttestationRecord{
		KeyThumbprint: e.jkt, WalletInstanceID: e.jkt, TenantID: domain.DefaultTenantID, UserID: alice.String(),
		Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, SecurityLevel: "tee", VerifiedAt: time.Now().UTC(),
	}
	if err := e.keys.MarkKeyAttested(context.Background(), older); err != nil {
		t.Fatal(err)
	}
	if err := e.request(domain.DefaultTenantID, &alice); !errors.Is(err, ErrWIAInstanceDeactivated) {
		t.Fatalf("err = %v, want ErrWIAInstanceDeactivated", err)
	}
	got, err := e.keys.GetByKeyThumbprint(context.Background(), e.jkt)
	if err != nil || got.Home != domain.KeyHomeTEE {
		t.Fatalf("replaced evidence not restored: %+v (%v)", got, err)
	}
}

// A request that is accepted keeps its evidence (the undo is for refusals).
func TestWIAKeyAttestation_AcceptedRequestKeepsItsEvidence(t *testing.T) {
	alice := domain.UserIDFromString("alice")
	e := newKeyEvidenceLifecycleEnv(t, &domain.WalletInstance{UserID: &alice, Status: domain.InstanceStatusActive}, nil)
	if err := e.request(domain.DefaultTenantID, &alice); err != nil {
		t.Fatal(err)
	}
	if rec, err := e.keys.GetByKeyThumbprint(context.Background(), e.jkt); err != nil || rec.Home != domain.KeyHomeStrongBox {
		t.Fatalf("evidence missing after an accepted request: %+v (%v)", rec, err)
	}
}

// Assurance evidence for key attestation: a revoked instance, another
// instance's record and a record of a non-live instance lend no FIDO2 evidence.
func TestFIDO2EvidenceFor_LifecycleAndInstanceScope(t *testing.T) {
	svc, instances, keys := assuranceSvc(t, nil, uvRules)
	ctx := context.Background()
	for _, id := range []string{"live", "dead", "other"} {
		if err := instances.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: domain.DefaultTenantID, Status: domain.InstanceStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: "k-live", WalletInstanceID: "live", AAGUID: "aa1", UV: true})
	putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: "k-dead", WalletInstanceID: "dead", AAGUID: "aa1", UV: true})
	if got := svc.fido2EvidenceFor(ctx, "live", []string{"k-live"}, nil); got == nil {
		t.Fatal("a live instance's own evidence was not lent")
	}
	if got := svc.fido2EvidenceFor(ctx, "", []string{"k-live"}, nil); got == nil {
		t.Fatal("evidence of a live instance was not lent to an unnamed request")
	}
	if got := svc.fido2EvidenceFor(ctx, "other", []string{"k-live"}, nil); got != nil {
		t.Fatal("another instance's evidence was lent")
	}
	if err := instances.UpdateStatus(ctx, "dead", domain.DefaultTenantID, domain.InstanceStatusRevoked, "test"); err != nil {
		t.Fatal(err)
	}
	if got := svc.fido2EvidenceFor(ctx, "dead", []string{"k-dead"}, nil); got != nil {
		t.Fatal("a revoked instance lent evidence (named)")
	}
	if got := svc.fido2EvidenceFor(ctx, "", []string{"k-dead"}, nil); got != nil {
		t.Fatal("a revoked instance lent evidence (unnamed request)")
	}
}

// The preview's authenticated caller scopes stored FIDO2 evidence: another
// user's (or tenant's) live instance, or a record tied to no instance, lends
// nothing to it, named or not.
func TestFIDO2EvidenceFor_PreviewCallerOwnership(t *testing.T) {
	svc, instances, keys := assuranceSvc(t, nil, uvRules)
	ctx := context.Background()
	alice, bob := domain.UserIDFromString("alice"), domain.UserIDFromString("bob")
	for id, u := range map[string]*domain.UserID{"alice-inst": &alice, "bob-inst": &bob} {
		if err := instances.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: domain.DefaultTenantID, UserID: u, Status: domain.InstanceStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: "k-alice", WalletInstanceID: "alice-inst", AAGUID: "aa1", UV: true})
	putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: "k-legacy", AAGUID: "aa1", UV: true})
	asAlice := WithKeyAttestationCaller(ctx, KeyAttestationCaller{TenantID: domain.DefaultTenantID, UserID: alice.String()})
	asBob := WithKeyAttestationCaller(ctx, KeyAttestationCaller{TenantID: domain.DefaultTenantID, UserID: bob.String()})
	asOtherTenant := WithKeyAttestationCaller(ctx, KeyAttestationCaller{TenantID: "other", UserID: alice.String()})

	if svc.fido2EvidenceFor(asAlice, "alice-inst", []string{"k-alice"}, nil) == nil || svc.fido2EvidenceFor(asAlice, "", []string{"k-alice"}, nil) == nil {
		t.Fatal("the owner's own evidence was not lent")
	}
	for name, c := range map[string]context.Context{"other user": asBob, "other tenant": asOtherTenant} {
		if svc.fido2EvidenceFor(c, "alice-inst", []string{"k-alice"}, nil) != nil {
			t.Errorf("%s: evidence lent (named instance)", name)
		}
		if svc.fido2EvidenceFor(c, "", []string{"k-alice"}, nil) != nil {
			t.Errorf("%s: evidence lent (unnamed request)", name)
		}
	}
	if svc.fido2EvidenceFor(asAlice, "", []string{"k-legacy"}, nil) != nil {
		t.Error("a record tied to no instance was lent to a known caller")
	}
}
