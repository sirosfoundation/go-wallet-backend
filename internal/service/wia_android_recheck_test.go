package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// recheckClock drives both the status list's cache and the checker's notion
// of now.
type recheckClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *recheckClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *recheckClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// rcWIA is an akWIA whose clock is controlled and whose first WIA, with
// verified evidence, has been issued.
type rcWIA struct {
	*akWIA
	clock *recheckClock
	key   *ecdsa.PrivateKey
	jkt   string
	// leafSerial is the serial of the leaf the evidence carried.
	leafSerial int64
}

func newRCWIA(t *testing.T, rules string) *rcWIA {
	t.Helper()
	a := newAKWIA(t, rules)
	if rules == "" {
		a.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	}
	clock := &recheckClock{t: time.Now().UTC()}
	a.svc.keyVerifiers[KeyAttestationAndroidKey].(*AndroidKeyAttestationVerifier).setStatusClock(clock.Now)
	a.svc.keyChecker.now = clock.Now
	ctx := context.Background()
	challenge, _, err := a.svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, key := createTestPop(t, challenge)
	a.fx.serial += 100
	serial := a.fx.serial // later fixture serials count on from here
	chain := a.fx.leaf(&key.PublicKey, encodeKeyDescription(goodParams(InstanceKeyAttestationChallenge(challenge))), leafOpts{Serial: serial})
	raw, _ := json.Marshal(map[string]any{"type": "android_key", "x5c": b64chain(chain)})
	if _, err := a.svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge, KeyAttestation: &KeyAttestation{Type: KeyAttestationAndroidKey, Raw: raw}}); err != nil {
		t.Fatalf("first WIA: %v", err)
	}
	return &rcWIA{akWIA: a, clock: clock, key: key, jkt: expectedThumbprint(t, &key.PublicKey), leafSerial: serial}
}

// later issues a WIA for the same key with no key_attestation field.
func (r *rcWIA) later() (string, error) {
	r.t.Helper()
	c, _, err := r.svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	if err != nil {
		r.t.Fatal(err)
	}
	return r.svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: signPopWithKey(r.t, r.key, c), Challenge: c})
}

func (r *rcWIA) revokeLeaf() {
	r.fetch.body = `{"entries":{"` + big.NewInt(r.leafSerial).Text(16) + `":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}`
	r.clock.Advance(2 * time.Hour) // past the cached list's life
}

func (r *rcWIA) wscd() domain.WSCDType { return instanceType(r.t, r.inst, r.jkt) }

func TestRecheck_StoredRecordCarriesTheChainSerials(t *testing.T) {
	r := newRCWIA(t, "")
	rec := r.record(r.jkt)
	if len(rec.CertSerials) != 3 || rec.CertSerials[0] != normalizeSerialHex(big.NewInt(r.leafSerial).Text(16)) {
		t.Fatalf("cert serials = %v", rec.CertSerials)
	}
	if rec.Revoked() {
		t.Fatal("fresh record is revoked")
	}
}

// A serial revoked AFTER submission flips the slot: the next WIA sees no
// instance key, the type reads unknown, and the record is marked, not deleted.
func TestRecheck_RevokedAfterSubmissionFlipsTheSlot(t *testing.T) {
	r := newRCWIA(t, wiaNeedsAndroidRules)
	// While good, a WIA with no submission still issues from the record.
	if _, err := r.later(); err != nil {
		t.Fatalf("good record: %v", err)
	}
	if r.wscd() != domain.WSCDTypeNativeAndroid {
		t.Fatalf("wscd = %s", r.wscd())
	}

	r.revokeLeaf()
	if _, err := r.later(); !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("a revoked record still satisfied (instance_key (kind android_key)): %v", err)
	}
	rec := r.record(r.jkt) // never deleted
	if !rec.Revoked() || rec.RevokedReason != RecheckReasonRevoked || rec.Home != domain.KeyHomeTEE {
		t.Fatalf("record not marked: %+v", rec)
	}
	// The stored evidence stays marked on later reads, with no more list traffic needed.
	calls := r.fetch.callCount()
	if _, err := r.later(); !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("err = %v", err)
	}
	if r.fetch.callCount() != calls {
		t.Fatal("a marked record triggered another fetch")
	}
}

// With the policy off the same WIA issues, but the instance reads wscd unknown.
func TestRecheck_RevokedRecordReadsWSCDUnknown(t *testing.T) {
	r := newRCWIA(t, "")
	r.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	if _, err := r.later(); err != nil || r.wscd() != domain.WSCDTypeNativeAndroid {
		t.Fatalf("err=%v wscd=%s", err, r.wscd())
	}
	r.revokeLeaf()
	if _, err := r.later(); err != nil {
		t.Fatal(err)
	}
	if r.wscd() != domain.WSCDTypeUnknown {
		t.Fatalf("wscd = %s after revocation", r.wscd())
	}
}

// A fresh valid re-submission replaces a revoked record, whatever its rank.
func TestRecheck_FreshSubmissionSupersedesARevokedRecord(t *testing.T) {
	r := newRCWIA(t, wiaNeedsAndroidRules)
	r.revokeLeaf()
	if _, err := r.later(); !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("err = %v", err)
	}
	if !r.record(r.jkt).Revoked() {
		t.Fatal("not marked")
	}
	// Fresh chain (new serial, not on the list) from the same key: first a
	// strongbox one (stronger than the revoked TEE record), then, once that
	// is revoked too, a TEE one: weaker than the revoked strongbox record it
	// replaces, which the no-downgrade rule must not protect.
	for _, strong := range []bool{true, false} {
		ctx := context.Background()
		c, _, _ := r.svc.CreateChallenge(ctx, domain.DefaultTenantID)
		k := goodParams(InstanceKeyAttestationChallenge(c))
		if strong {
			k.AttLevel, k.KmLevel = androidLevelStrongBox, androidLevelStrongBox
		}
		chain := r.fx.leaf(&r.key.PublicKey, encodeKeyDescription(k), leafOpts{})
		raw, _ := json.Marshal(map[string]any{"type": "android_key", "x5c": b64chain(chain)})
		if _, err := r.svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: signPopWithKey(t, r.key, c), Challenge: c, KeyAttestation: &KeyAttestation{Type: KeyAttestationAndroidKey, Raw: raw}}); err != nil {
			t.Fatalf("fresh submission (strong=%v): %v", strong, err)
		}
		rec := r.record(r.jkt)
		if rec.Revoked() {
			t.Fatalf("the fresh record is marked revoked (strong=%v)", strong)
		}
		if _, err := r.later(); err != nil {
			t.Fatalf("WIA from the fresh record: %v", err)
		}
		if want := map[bool]domain.KeyHome{true: domain.KeyHomeStrongBox, false: domain.KeyHomeTEE}[strong]; rec.Home != want {
			t.Fatalf("home = %s, want %s", rec.Home, want)
		}
		if !strong {
			break
		}
		// Revoke the fresh strongbox record too, to try the weaker rank next.
		r.fetch.body = `{"entries":{"` + rec.CertSerials[0] + `":{"status":"REVOKED"}}}`
		r.clock.Advance(2 * time.Hour)
		if _, err := r.later(); !errors.Is(err, ErrWIARefusedByPolicy) {
			t.Fatalf("err = %v", err)
		}
	}
}

// A mark is only set on the record that was found revoked: a record a fresh
// submission replaced in the meantime is left alone.
func TestRecheck_MarkOnlyTheRecordThatWasChecked(t *testing.T) {
	r := newRCWIA(t, "")
	stale := r.record(r.jkt)
	// Replace the record with another chain (a different fingerprint).
	repl := stale.Clone()
	repl.ChainFingerprint = "another-chain"
	repl.Home = domain.KeyHomeStrongBox
	if err := r.keys.MarkKeyAttested(context.Background(), repl); err != nil {
		t.Fatal(err)
	}
	ok, err := r.keys.MarkKeyRevoked(context.Background(), r.jkt, stale.ChainFingerprint, RecheckReasonRevoked, time.Now())
	if err != nil || ok {
		t.Fatalf("marked a record it did not check: ok=%v err=%v", ok, err)
	}
	if r.record(r.jkt).Revoked() {
		t.Fatal("replacement record was marked")
	}
}

// List unavailable: a WIA issued from the record is 503; the preview, which
// cannot answer 503, treats the evidence as absent and falls to the lowest tier.
func TestRecheck_StatusListUnavailable(t *testing.T) {
	r := newRCWIA(t, wiaNeedsAndroidRules)
	svcP, instP, keysP := previewSvc(t, wiaNeedsAndroidRules, true)
	svcP.SetInstanceKeyChecker(r.svc.keyChecker)
	if err := instP.Upsert(context.Background(), &domain.WalletInstance{ID: r.jkt, TenantID: domain.DefaultTenantID, Status: domain.InstanceStatusActive, LastAttestedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	putRecord(t, keysP, *r.record(r.jkt))
	preview := func() bool {
		t.Helper()
		got, err := svcP.PreviewAssurance(context.Background(), &AssurancePreviewRequest{WalletInstanceID: r.jkt})
		if err != nil {
			t.Fatal(err)
		}
		return got.WIAIssue
	}
	if !preview() {
		t.Fatal("preview does not see the good record")
	}

	r.fetch.err = errors.New("status endpoint down")
	r.clock.Advance(2 * time.Hour) // the cached list is no longer fresh
	_, err := r.later()
	if !errors.Is(err, ErrWIAKeyAttestationUnavailable) {
		t.Fatalf("WIA from a record whose status cannot be checked: %v", err)
	}
	if preview() {
		t.Fatal("preview used evidence it could not re-check")
	}
	// Nothing was marked: an outage is not a revocation.
	if r.record(r.jkt).Revoked() {
		t.Fatal("outage marked the record revoked")
	}
	// The list returns: the evidence is good again.
	r.fetch.err = nil
	r.clock.Advance(10 * time.Second) // past the failure backoff
	if _, err := r.later(); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	if !preview() {
		t.Fatal("preview did not recover")
	}
}

// chain_not_after passed: the evidence is expired and the home unknown; the
// record is neither deleted nor marked.
func TestRecheck_ExpiredChainIsNoEvidence(t *testing.T) {
	r := newRCWIA(t, wiaNeedsAndroidRules)
	rec := r.record(r.jkt)
	if rec.ChainNotAfter.IsZero() {
		t.Fatal("no chain_not_after recorded")
	}
	r.clock.t = rec.ChainNotAfter.Add(time.Second)
	// The list is still fresh enough? Make it unusable: expiry must not need it.
	r.fetch.err = errors.New("down")
	if _, err := r.later(); !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("an expired chain still backed the slot: %v", err)
	}
	if got := r.record(r.jkt); got.Revoked() {
		t.Fatalf("expiry marked the record: %+v", got)
	}
	r.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	if _, err := r.later(); err != nil || r.wscd() != domain.WSCDTypeUnknown {
		t.Fatalf("err=%v wscd=%s", err, r.wscd())
	}
}

// A record stored before serials were kept cannot be re-checked: unknown, fail
// closed, without consulting the list.
func TestRecheck_LegacyRecordWithoutSerialsIsUnknown(t *testing.T) {
	r := newRCWIA(t, wiaNeedsAndroidRules)
	// A second key with a record shaped as an earlier release stored it: the
	// same evidence, but no serials.
	key2 := genKey(t)
	legacy := r.record(r.jkt).Clone()
	legacy.CertSerials = nil
	legacy.KeyThumbprint = expectedThumbprint(t, &key2.PublicKey)
	legacy.WalletInstanceID = legacy.KeyThumbprint
	putRecord(t, r.keys, *legacy)
	r.key, r.jkt = key2, legacy.KeyThumbprint
	if got := r.record(r.jkt); len(got.CertSerials) != 0 {
		t.Fatalf("legacy record kept serials: %v", got.CertSerials)
	}
	calls := r.fetch.callCount()
	if _, err := r.later(); !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("a legacy record backed the slot: %v", err)
	}
	if r.fetch.callCount() != calls {
		t.Fatal("a legacy record caused a list fetch")
	}
	if got := r.record(r.jkt); got.Revoked() {
		t.Fatal("legacy record marked revoked")
	}
	r.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	if _, err := r.later(); err != nil || r.wscd() != domain.WSCDTypeUnknown {
		t.Fatalf("err=%v wscd=%s", err, r.wscd())
	}
	// A fresh submission repairs it.
	ctx := context.Background()
	c, _, _ := r.svc.CreateChallenge(ctx, domain.DefaultTenantID)
	chain := r.fx.leaf(&r.key.PublicKey, encodeKeyDescription(goodParams(InstanceKeyAttestationChallenge(c))), leafOpts{})
	raw, _ := json.Marshal(map[string]any{"type": "android_key", "x5c": b64chain(chain)})
	if _, err := r.svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: signPopWithKey(t, r.key, c), Challenge: c, KeyAttestation: &KeyAttestation{Type: KeyAttestationAndroidKey, Raw: raw}}); err != nil {
		t.Fatal(err)
	}
	if got := r.record(r.jkt); len(got.CertSerials) == 0 {
		t.Fatal("a fresh submission did not give the record serials")
	}
	if r.wscd() != domain.WSCDTypeNativeAndroid {
		t.Fatalf("wscd = %s", r.wscd())
	}
}

// FIDO2 records are not re-checked and keep backing the slot.
func TestRecheck_FIDO2RecordsAreNotRechecked(t *testing.T) {
	c := newInstanceKeyChecker(zap.NewNop())
	rec := &domain.KeyAttestationRecord{KeyThumbprint: "k", Kind: domain.KeyEvidenceFIDO2, AAGUID: "a"}
	got, err := c.usable(context.Background(), nil, rec)
	if err != nil || got == nil {
		t.Fatalf("got=%v err=%v", got, err)
	}
	// A nil checker still lets FIDO2 through but never an android_key record.
	var none *instanceKeyChecker
	if got, err := none.usable(context.Background(), nil, rec); err != nil || got == nil {
		t.Fatalf("nil checker, fido2: got=%v err=%v", got, err)
	}
	ak := &domain.KeyAttestationRecord{KeyThumbprint: "k", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, CertSerials: []string{"1"}, ChainNotAfter: time.Now().Add(time.Hour)}
	if got, err := none.usable(context.Background(), nil, ak); err != nil || got != nil {
		t.Fatalf("nil checker must fail closed for android_key: got=%v err=%v", got, err)
	}
	if got, err := c.usable(context.Background(), nil, ak); err != nil || got != nil {
		t.Fatalf("checker without an android re-check must fail closed: got=%v err=%v", got, err)
	}
}
