package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

// fido2WIAEnv is a WIA service whose policy issues only to a wallet with
// verified FIDO2 evidence for its instance key, with the fido2 key_attestation
// verifier registered, over a stub PDP that records whether it was asked.
type fido2WIAEnv struct {
	svc       *WIAService
	instances storage.WalletInstanceStore
	keys      storage.KeyAttestationStore
	pdp       *stubEvaluator
	aaguid    uuid.UUID
}

const fido2OnlyWIARules = "# id: fido2-only\n(assure-wia-issue (evidence (verified (fido2 (mds3 trusted)))))\n"

func newFIDO2WIAEnv(t *testing.T, trusted bool) *fido2WIAEnv {
	t.Helper()
	svc, instances := wiaAssuranceSvc(t, fido2OnlyWIARules)
	store := memory.NewStore()
	keys := store.KeyAttestations()
	svc.SetKeyAttestations(keys)
	pdp := &stubEvaluator{decision: trusted}
	fido2 := NewFIDO2AttestationService(testFIDO2AttestationConfig(true), instances, keys, newTestTrustService(t, pdp), zap.NewNop())
	registerFIDO2InstanceKeyVerifier(fido2, svc, zap.NewNop())
	return &fido2WIAEnv{svc: svc, instances: instances, keys: keys, pdp: pdp, aaguid: uuid.New()}
}

func newPoPKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// fido2KeyAttestation attests attested and wraps the object as the request's
// key_attestation.
func (e *fido2WIAEnv) fido2KeyAttestation(t *testing.T, attested *ecdsa.PrivateKey) *KeyAttestation {
	t.Helper()
	hash := make([]byte, 32)
	obj := buildTestAttestationObjectForKey(t, attested, e.aaguid, hash, 0x40)
	raw, err := json.Marshal(fido2InstanceKeyRequest{
		Type:              KeyAttestationFIDO2,
		AttestationObject: base64.RawURLEncoding.EncodeToString(obj),
		ClientDataHash:    base64.RawURLEncoding.EncodeToString(hash),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &KeyAttestation{Type: KeyAttestationFIDO2, Raw: raw}
}

func (e *fido2WIAEnv) generate(t *testing.T, tenant domain.TenantID, user *domain.UserID, pop *ecdsa.PrivateKey, ka *KeyAttestation) (string, error) {
	t.Helper()
	challenge, _, err := e.svc.CreateChallenge(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	return e.svc.GenerateWIA(context.Background(), tenant, user, &WIARequest{
		Pop: createTestPopWithKey(t, challenge, pop), Challenge: challenge, KeyAttestation: ka,
	})
}

// nothingLeftBehind asserts the refused request created no instance and no
// evidence for the PoP key.
func (e *fido2WIAEnv) nothingLeftBehind(t *testing.T, pop *ecdsa.PrivateKey) {
	t.Helper()
	jkt := expectedThumbprint(t, &pop.PublicKey)
	if inst, err := e.instances.GetByID(context.Background(), jkt); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("an instance was left behind: %+v (%v)", inst, err)
	}
	if rec, err := e.keys.GetByKeyThumbprint(context.Background(), jkt); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("key evidence was left behind: %+v (%v)", rec, err)
	}
}

// The first WIA of a fresh client under a FIDO2-requiring policy: no instance
// exists yet, so the evidence has to travel with the request.
func TestWIAFIDO2InstanceKey_FirstWIAUnderFIDO2Policy(t *testing.T) {
	e := newFIDO2WIAEnv(t, true)
	alice := domain.UserIDFromString("alice")
	pop := newPoPKey(t)

	// The policy refuses a first WIA without evidence.
	if _, err := e.generate(t, domain.DefaultTenantID, &alice, pop, nil); !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("without evidence: err = %v, want ErrWIARefusedByPolicy", err)
	}
	e.nothingLeftBehind(t, pop)

	tok, err := e.generate(t, domain.DefaultTenantID, &alice, pop, e.fido2KeyAttestation(t, pop))
	if err != nil {
		t.Fatalf("first WIA with FIDO2 evidence: %v", err)
	}
	if tok == "" {
		t.Fatal("no WIA issued")
	}
	jkt := expectedThumbprint(t, &pop.PublicKey)
	inst, err := e.instances.GetByID(context.Background(), jkt)
	if err != nil {
		t.Fatalf("the instance was not created: %v", err)
	}
	if inst.UserID == nil || *inst.UserID != alice || inst.Status != domain.InstanceStatusActive {
		t.Fatalf("instance = %+v", inst)
	}
	rec, err := e.keys.GetByKeyThumbprint(context.Background(), jkt)
	if err != nil {
		t.Fatalf("no evidence stored for the PoP key: %v", err)
	}
	if rec.Kind != domain.KeyEvidenceFIDO2 || rec.AAGUID != e.aaguid.String() ||
		rec.TenantID != domain.DefaultTenantID || rec.UserID != "alice" || rec.WalletInstanceID != jkt {
		t.Fatalf("record = %+v", rec)
	}
}

// Evidence about another key is not evidence about the PoP key: the request is
// refused and neither an instance nor a record exists afterwards.
func TestWIAFIDO2InstanceKey_AttestedKeyMustBeThePoPKey(t *testing.T) {
	e := newFIDO2WIAEnv(t, true)
	pop, other := newPoPKey(t), newPoPKey(t)

	_, err := e.generate(t, domain.DefaultTenantID, nil, pop, e.fido2KeyAttestation(t, other))
	if !errors.Is(err, ErrWIAKeyAttestationInvalid) {
		t.Fatalf("err = %v, want ErrWIAKeyAttestationInvalid", err)
	}
	e.nothingLeftBehind(t, pop)
	// The other key's own record was not written either.
	if _, err := e.keys.GetByKeyThumbprint(context.Background(), expectedThumbprint(t, &other.PublicKey)); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("evidence for the attested key was stored: %v", err)
	}
}

func TestWIAFIDO2InstanceKey_UntrustedAuthenticatorIsRefused(t *testing.T) {
	e := newFIDO2WIAEnv(t, false)
	pop := newPoPKey(t)
	if _, err := e.generate(t, domain.DefaultTenantID, nil, pop, e.fido2KeyAttestation(t, pop)); !errors.Is(err, ErrWIAKeyAttestationInvalid) {
		t.Fatalf("err = %v, want ErrWIAKeyAttestationInvalid", err)
	}
	e.nothingLeftBehind(t, pop)
}

func TestWIAFIDO2InstanceKey_MalformedEvidenceIsRefused(t *testing.T) {
	e := newFIDO2WIAEnv(t, true)
	for name, raw := range map[string]string{
		"not an object":       `"x"`,
		"no attestation":      `{"type":"fido2"}`,
		"null attestation":    `{"type":"fido2","attestation_object":null,"client_data_hash":null}`,
		"padded base64":       `{"type":"fido2","attestation_object":"AAAA=","client_data_hash":"AAAA"}`,
		"not an attestation":  `{"type":"fido2","attestation_object":"AAAA","client_data_hash":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`,
		"short client data":   `{"type":"fido2","attestation_object":"AAAA","client_data_hash":"AAAA"}`,
		"absent client hash":  `{"type":"fido2","attestation_object":"AAAA"}`,
		"empty attestation":   `{"type":"fido2","attestation_object":"","client_data_hash":""}`,
		"unknown extra field": `{"type":"fido2","x":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			pop := newPoPKey(t)
			_, err := e.generate(t, domain.DefaultTenantID, nil, pop, &KeyAttestation{Type: KeyAttestationFIDO2, Raw: json.RawMessage(raw)})
			if !errors.Is(err, ErrWIAKeyAttestationInvalid) {
				t.Fatalf("err = %v, want ErrWIAKeyAttestationInvalid", err)
			}
			e.nothingLeftBehind(t, pop)
		})
	}
}

// A foreign or revoked instance is refused before the evidence is verified
// (the PDP is never asked) and takes no evidence write.
func TestWIAFIDO2InstanceKey_ForeignAndRevokedInstancesAreRefusedFirst(t *testing.T) {
	alice, bob := domain.UserIDFromString("alice"), domain.UserIDFromString("bob")
	cases := []struct {
		name   string
		inst   *domain.WalletInstance
		caller *domain.UserID
		want   error
	}{
		{"foreign", &domain.WalletInstance{UserID: &alice, Status: domain.InstanceStatusActive}, &bob, ErrWIAInstanceNotOwned},
		{"revoked", &domain.WalletInstance{UserID: &alice, Status: domain.InstanceStatusRevoked}, &alice, ErrWIAInstanceDeactivated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFIDO2WIAEnv(t, true)
			pop := newPoPKey(t)
			jkt := expectedThumbprint(t, &pop.PublicKey)
			c.inst.ID, c.inst.TenantID = jkt, domain.DefaultTenantID
			c.inst.CreatedAt, c.inst.UpdatedAt, c.inst.LastAttestedAt = time.Now().UTC(), time.Now().UTC(), time.Now().UTC()
			if err := e.instances.Upsert(context.Background(), c.inst); err != nil {
				t.Fatal(err)
			}
			if _, err := e.generate(t, domain.DefaultTenantID, c.caller, pop, e.fido2KeyAttestation(t, pop)); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if e.pdp.gotSubjectID != "" {
				t.Fatal("the evidence was verified for a refused instance")
			}
			if rec, err := e.keys.GetByKeyThumbprint(context.Background(), jkt); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("key evidence was written: %+v (%v)", rec, err)
			}
		})
	}
}

// Without FIDO2 attestation enabled there is no fido2 type: the request is
// rejected as unsupported before the challenge is consumed.
func TestWIAFIDO2InstanceKey_NotRegisteredWhenFIDO2Disabled(t *testing.T) {
	svc, instances := wiaAssuranceSvc(t, fido2OnlyWIARules)
	keys := memory.NewStore().KeyAttestations()
	fido2 := NewFIDO2AttestationService(testFIDO2AttestationConfig(false), instances, keys, nil, zap.NewNop())
	registerFIDO2InstanceKeyVerifier(fido2, svc, zap.NewNop())
	for _, typ := range svc.InstanceKeyVerifierTypes() {
		if typ == string(KeyAttestationFIDO2) {
			t.Fatal("fido2 verifier registered while FIDO2 attestation is disabled")
		}
	}
	challenge, _, err := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{
		Pop: createTestPopWithKey(t, challenge, newPoPKey(t)), Challenge: challenge,
		KeyAttestation: &KeyAttestation{Type: KeyAttestationFIDO2, Raw: json.RawMessage(`{"type":"fido2"}`)},
	})
	if !errors.Is(err, ErrWIAKeyAttestationTypeUnsupported) {
		t.Fatalf("err = %v, want ErrWIAKeyAttestationTypeUnsupported", err)
	}
}
