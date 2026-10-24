package service

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

const testAppAttestAppID = "TEAM123.com.example.test"

type appAttestHarness struct {
	svc   *NativeAttestationService
	keys  storage.AppAttestKeyStore
	ca    *testAppleCA
	appID string
}

// newAppAttestHarness builds a verifier for env ("production" or
// "development") that trusts the test CA instead of the Apple root.
func newAppAttestHarness(t *testing.T, env string) *appAttestHarness {
	t.Helper()
	cfg := testNativeAttestationConfig(true)
	cfg.WalletProvider.Attestation.NativeAttestation.AppleAppID = testAppAttestAppID
	cfg.WalletProvider.Attestation.NativeAttestation.AppleAppAttestEnvironment = env
	svc := NewNativeAttestationService(cfg, zap.NewNop())
	ca := newTestAppleCA(t)
	svc.appRoots = ca.pool
	keys := memory.NewStore().AppAttestKeys()
	svc.SetAppAttestKeys(keys)
	return &appAttestHarness{svc: svc, keys: keys, ca: ca, appID: testAppAttestAppID}
}

var testBinding = NativeAttestationBinding{TenantID: "acme", UserID: userPtr("u1"), WalletInstanceID: "inst-1"}

func userPtr(id string) *domain.UserID { u := domain.UserIDFromString(id); return &u }

func (h *appAttestHarness) verify(t *testing.T, bind NativeAttestationBinding, d *testAppAttestDevice, keyID, challenge string, o attOpts) (*NativeAttestationResult, error) {
	t.Helper()
	if o.appID == "" {
		o.appID = h.appID
	}
	return h.svc.VerifyBound(context.Background(), bind, &NativeAttestationRequest{
		Type: NativeAttestationAppleAppAttest, KeyID: keyID, Challenge: challenge,
		Token: d.attestation(t, h.ca, challenge, o),
	})
}

func requireRejected(t *testing.T, h *appAttestHarness, d *testAppAttestDevice, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatal("attestation accepted, want rejection")
	}
	if !errors.Is(err, ErrNativeAttestationInvalid) {
		t.Fatalf("error %v is not ErrNativeAttestationInvalid", err)
	}
	if want != "" && !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not mention %q", err, want)
	}
	if _, gerr := h.keys.Get(context.Background(), d.keyIDB64()); !errors.Is(gerr, storage.ErrNotFound) {
		t.Fatalf("a rejected attestation stored a key (get: %v)", gerr)
	}
}

func TestAppAttest_ValidAttestationStoresKey(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	d := newTestAppAttestDevice(t)
	res, err := h.verify(t, testBinding, d, d.keyIDB64(), "chal-1", attOpts{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Verified || res.AttestationSource != "platform_attested" {
		t.Fatalf("result = %+v", res)
	}
	rec, err := h.keys.Get(context.Background(), d.keyIDB64())
	if err != nil {
		t.Fatalf("key not stored: %v", err)
	}
	pub, _ := d.key.PublicKey.ECDH()
	if string(rec.PublicKey) != string(pub.Bytes()) {
		t.Error("stored public key is not the credCert key")
	}
	if rec.Counter != 0 || rec.Environment != domain.AppAttestProduction || !rec.ChainVerified || !rec.IsActive() {
		t.Errorf("record = %+v", rec)
	}
	if rec.TenantID != "acme" || rec.UserID == nil || rec.UserID.ID != "u1" || rec.WalletInstanceID != "inst-1" || rec.AppID != testAppAttestAppID {
		t.Errorf("binding = %+v", rec)
	}
	if !rec.VerifiedHomeEligible() {
		t.Error("a verified production key must be eligible for a verified home")
	}
}

func TestAppAttest_KeyIDAcceptedEncodings(t *testing.T) {
	d := newTestAppAttestDevice(t)
	for name, enc := range map[string]string{
		"std":    base64.StdEncoding.EncodeToString(d.keyID),
		"rawstd": base64.RawStdEncoding.EncodeToString(d.keyID),
		"url":    base64.URLEncoding.EncodeToString(d.keyID),
		"rawurl": base64.RawURLEncoding.EncodeToString(d.keyID),
	} {
		t.Run(name, func(t *testing.T) {
			h := newAppAttestHarness(t, "production")
			if _, err := h.verify(t, testBinding, d, enc, "c", attOpts{}); err != nil {
				t.Fatal(err)
			}
			if _, err := h.keys.Get(context.Background(), d.keyIDB64()); err != nil {
				t.Fatalf("not stored under the canonical id: %v", err)
			}
		})
	}
}

func TestAppAttest_RejectsWrongKeyID(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	d, other := newTestAppAttestDevice(t), newTestAppAttestDevice(t)
	// A key id that is well formed but belongs to another key.
	_, err := h.verify(t, testBinding, d, other.keyIDB64(), "c", attOpts{})
	requireRejected(t, h, d, err, "key_id does not match")
	if _, gerr := h.keys.Get(context.Background(), other.keyIDB64()); !errors.Is(gerr, storage.ErrNotFound) {
		t.Fatal("the client-supplied key id was stored")
	}
}

func TestAppAttest_RejectsMalformedKeyID(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	d := newTestAppAttestDevice(t)
	for name, id := range map[string]string{
		"empty":     "",
		"notbase64": "!!!notbase64!!!",
		"short":     base64.StdEncoding.EncodeToString(d.keyID[:16]),
		"long":      base64.StdEncoding.EncodeToString(append(append([]byte{}, d.keyID...), 0)),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.verify(t, testBinding, d, id, "c", attOpts{})
			requireRejected(t, h, d, err, "key_id")
		})
	}
}

func TestAppAttest_RejectsCredentialIDMismatch(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	d := newTestAppAttestDevice(t)
	// keyId matches the certificate key; the credentialId in authData does not.
	bad := make([]byte, 32)
	_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{credID: bad})
	requireRejected(t, h, d, err, "credentialId")
}

func TestAppAttest_RejectsShortCredentialID(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	d := newTestAppAttestDevice(t)
	_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{shortCredID: true})
	requireRejected(t, h, d, err, "credentialId")
}

func TestAppAttest_RejectsCredentialIDLengthBeyondAuthData(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	d := newTestAppAttestDevice(t)
	// The declared length is 32 (as the key id is) but authData is cut short
	// right after the length field: slicing the credential id must not run past it.
	_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{truncateAuth: appAttestAttestedDataOffset + 4})
	requireRejected(t, h, d, err, "credentialId")
	// A declared length beyond what is present.
	_, err = h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{credLen: 32, truncateAuth: appAttestAttestedDataOffset + 10})
	requireRejected(t, h, d, err, "credentialId")
}

// App Attest keys are P-256; a certificate for another curve is refused even
// though its key id would be self-consistent.
func TestAppAttest_RejectsNonP256Key(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	d := newTestAppAttestDeviceOnCurve(t, elliptic.P384())
	_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{credID: d.keyID})
	requireRejected(t, h, d, err, "P-256")
}

func TestAppAttest_RejectsNonZeroCounter(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	d := newTestAppAttestDevice(t)
	_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{counter: 1})
	requireRejected(t, h, d, err, "counter")
}

func TestAppAttest_AAGUIDMustMatchEnvironment(t *testing.T) {
	t.Run("development attestation rejected by production", func(t *testing.T) {
		h := newAppAttestHarness(t, "production")
		d := newTestAppAttestDevice(t)
		_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{aaguid: testAAGUIDDev})
		requireRejected(t, h, d, err, "AAGUID")
	})
	t.Run("production attestation rejected by development", func(t *testing.T) {
		h := newAppAttestHarness(t, "development")
		d := newTestAppAttestDevice(t)
		_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{aaguid: testAAGUIDProd})
		requireRejected(t, h, d, err, "AAGUID")
	})
	t.Run("unknown aaguid rejected", func(t *testing.T) {
		h := newAppAttestHarness(t, "production")
		d := newTestAppAttestDevice(t)
		_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{aaguid: [16]byte{1}})
		requireRejected(t, h, d, err, "AAGUID")
	})
	t.Run("unsupported configured environment refused", func(t *testing.T) {
		h := newAppAttestHarness(t, "staging")
		d := newTestAppAttestDevice(t)
		_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{})
		requireRejected(t, h, d, err, "environment")
	})
}

func TestAppAttest_DevelopmentKeyIsNeverVerifiedHomeEligible(t *testing.T) {
	h := newAppAttestHarness(t, "development")
	d := newTestAppAttestDevice(t)
	res, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{aaguid: testAAGUIDDev})
	if err != nil {
		t.Fatal(err)
	}
	if res.AttestationSource != "development_attested" {
		t.Errorf("source = %q", res.AttestationSource)
	}
	rec, _ := h.keys.Get(context.Background(), d.keyIDB64())
	if rec.Environment != domain.AppAttestDevelopment || rec.VerifiedHomeEligible() {
		t.Errorf("development key eligible for a verified home: %+v", rec)
	}
}

func TestAppAttest_ChainMustReachRoot(t *testing.T) {
	t.Run("production rejects an unknown root", func(t *testing.T) {
		h := newAppAttestHarness(t, "production")
		d := newTestAppAttestDevice(t)
		_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{unknownRoot: true})
		requireRejected(t, h, d, err, "x5c chain")
	})
	t.Run("development stores an unverifiable chain as unverified", func(t *testing.T) {
		h := newAppAttestHarness(t, "development")
		d := newTestAppAttestDevice(t)
		if _, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{aaguid: testAAGUIDDev, unknownRoot: true}); err != nil {
			t.Fatal(err)
		}
		rec, _ := h.keys.Get(context.Background(), d.keyIDB64())
		if rec.ChainVerified {
			t.Error("an unverifiable chain was recorded as verified")
		}
	})
	t.Run("default pool is the pinned Apple root", func(t *testing.T) {
		h := newAppAttestHarness(t, "production")
		h.svc.appRoots = nil // a test-CA chain cannot reach the real Apple root
		d := newTestAppAttestDevice(t)
		_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{})
		requireRejected(t, h, d, err, "x5c chain")
	})
}

func TestAppAttest_NonceAndRPIDChecked(t *testing.T) {
	d := newTestAppAttestDevice(t)
	cases := map[string]struct {
		o    attOpts
		want string
	}{
		"nonce for another challenge": {attOpts{nonceFor: "other-challenge"}, "nonce"},
		"missing nonce extension":     {attOpts{skipNonceExt: true}, "nonce"},
		"garbage nonce":               {attOpts{wrongNonceExt: []byte("short")}, "nonce"},
		"wrong app id":                {attOpts{appID: "TEAM123.com.evil"}, "rpIdHash"},
		"no attested data flag":       {attOpts{flags: 0x01}, "attested credential"},
		"truncated authData":          {attOpts{truncateAuth: 40}, "authData"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newAppAttestHarness(t, "production")
			_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", c.o)
			requireRejected(t, h, d, err, c.want)
		})
	}
}

func TestAppAttest_MalformedAndOversize(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	d := newTestAppAttestDevice(t)
	for name, tok := range map[string]string{
		"not base64":  "@@@",
		"not cbor":    base64.StdEncoding.EncodeToString([]byte("not-cbor")),
		"empty":       "",
		"oversize":    base64.StdEncoding.EncodeToString(make([]byte, maxAppAttestObjectLen+1)),
		"cbor string": base64.StdEncoding.EncodeToString([]byte{0x63, 'a', 'b', 'c'}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.svc.VerifyBound(context.Background(), testBinding, &NativeAttestationRequest{
				Type: NativeAttestationAppleAppAttest, KeyID: d.keyIDB64(), Challenge: "c", Token: tok,
			})
			requireRejected(t, h, d, err, "")
		})
	}
}

// An otherwise fully valid attestation is refused for its size alone, while
// the same object with a modest receipt is accepted.
func TestAppAttest_OversizeRefusedByLengthAlone(t *testing.T) {
	d := newTestAppAttestDevice(t)
	h := newAppAttestHarness(t, "production")
	if _, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{receiptPad: 1000}); err != nil {
		t.Fatalf("modest receipt rejected: %v", err)
	}
	h2 := newAppAttestHarness(t, "production")
	_, err := h2.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{receiptPad: maxAppAttestObjectLen})
	requireRejected(t, h2, d, err, "too large")
}

func TestAppAttest_UnboundVerifyDoesNotStore(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	d := newTestAppAttestDevice(t)
	res, err := h.svc.Verify(context.Background(), &NativeAttestationRequest{
		Type: NativeAttestationAppleAppAttest, KeyID: d.keyIDB64(), Challenge: "c",
		Token: d.attestation(t, h.ca, "c", attOpts{appID: h.appID}),
	})
	if err != nil || !res.Verified {
		t.Fatalf("verify: %v %+v", err, res)
	}
	if _, gerr := h.keys.Get(context.Background(), d.keyIDB64()); !errors.Is(gerr, storage.ErrNotFound) {
		t.Fatal("Verify without a caller binding stored a key")
	}
}

func TestAppAttest_ReattestationKeepsCounterAndChecksContext(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	d := newTestAppAttestDevice(t)
	ctx := context.Background()
	if _, err := h.verify(t, testBinding, d, d.keyIDB64(), "c1", attOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := h.keys.AdvanceCounter(ctx, d.keyIDB64(), 9); err != nil {
		t.Fatal(err)
	}

	// The same caller presenting the attestation again must not reset the counter.
	if _, err := h.verify(t, testBinding, d, d.keyIDB64(), "c2", attOpts{}); err != nil {
		t.Fatalf("re-attestation by the owner: %v", err)
	}
	rec, _ := h.keys.Get(ctx, d.keyIDB64())
	if rec.Counter != 9 {
		t.Fatalf("re-attestation reset the counter to %d", rec.Counter)
	}

	// Another tenant, another user, or no user cannot adopt the key.
	for name, b := range map[string]NativeAttestationBinding{
		"other tenant": {TenantID: "evil", UserID: userPtr("u1")},
		"other user":   {TenantID: "acme", UserID: userPtr("u2")},
		"no user":      {TenantID: "acme"},
	} {
		if _, err := h.verify(t, b, d, d.keyIDB64(), "c3", attOpts{}); err == nil || !errors.Is(err, ErrNativeAttestationInvalid) {
			t.Errorf("%s: adopted an attested key (err=%v)", name, err)
		}
	}

	// A revoked key is not revived by attesting again.
	if err := h.keys.Revoke(ctx, d.keyIDB64()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.verify(t, testBinding, d, d.keyIDB64(), "c4", attOpts{}); err == nil {
		t.Error("revoked key re-attested")
	}
}

func TestAppAttest_NoStoreStillVerifies(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	h.svc.SetAppAttestKeys(nil)
	d := newTestAppAttestDevice(t)
	if _, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{}); err != nil {
		t.Fatal(err)
	}
}

func TestAppAttest_BoundCallerNeedsTenantWhenStoring(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	d := newTestAppAttestDevice(t)
	_, err := h.verify(t, NativeAttestationBinding{UserID: userPtr("u")}, d, d.keyIDB64(), "c", attOpts{})
	requireRejected(t, h, d, err, "tenant")
}

func TestDecodeAppAttestKeyID(t *testing.T) {
	raw := sha256.Sum256([]byte("x"))
	if got, err := decodeAppAttestKeyID(base64.StdEncoding.EncodeToString(raw[:])); err != nil || string(got) != string(raw[:]) {
		t.Fatalf("got %x %v", got, err)
	}
	if _, err := decodeAppAttestKeyID("AAAA"); err == nil {
		t.Fatal("3-byte id accepted")
	}
}

// Regression: development mode may bypass x5c chain verification (no real
// Apple hardware in test), but must NEVER bypass the nonce check, otherwise a
// forged attestation with an arbitrary nonce would be accepted.
func TestAppAttest_DevModeStillEnforcesNonce(t *testing.T) {
	h := newAppAttestHarness(t, "development")
	d := newTestAppAttestDevice(t)
	_, err := h.verify(t, testBinding, d, d.keyIDB64(), "chal", attOpts{aaguid: testAAGUIDDev, unknownRoot: true, nonceFor: "another"})
	requireRejected(t, h, d, err, "nonce")
	if _, err := h.verify(t, testBinding, d, d.keyIDB64(), "chal", attOpts{aaguid: testAAGUIDDev, unknownRoot: true}); err != nil {
		t.Fatalf("correct nonce rejected: %v", err)
	}
}
