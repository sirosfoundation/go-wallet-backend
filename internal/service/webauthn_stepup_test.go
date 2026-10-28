package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// stepUpUser is a registered user with a virtual authenticator holding its passkey.
type stepUpUser struct {
	id         domain.UserID
	auth       virtualwebauthn.Authenticator
	credential virtualwebauthn.Credential
}

func registerStepUpUser(t *testing.T, setup *testVirtualWebAuthnSetup, name string) *stepUpUser {
	t.Helper()
	begin, err := setup.service.BeginRegistration(setup.ctx, &BeginRegistrationRequest{DisplayName: name})
	require.NoError(t, err)
	optsJSON, err := json.Marshal(begin.CreateOptions)
	require.NoError(t, err)
	opts, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
	require.NoError(t, err)

	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	auth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{})
	resp := virtualwebauthn.CreateAttestationResponse(setup.rp, auth, cred, *opts)
	fin, err := setup.service.FinishRegistration(setup.ctx, &FinishRegistrationRequest{
		ChallengeID: begin.ChallengeID,
		Credential:  json.RawMessage(resp),
		DisplayName: name,
	})
	require.NoError(t, err)

	id := domain.UserIDFromString(fin.UUID)
	auth.Options.UserHandle = id.AsUserHandle()
	auth.AddCredential(cred)
	return &stepUpUser{id: id, auth: auth, credential: cred}
}

// assertFor signs the options of a step-up begin response with u's passkey.
func (u *stepUpUser) assertFor(t *testing.T, setup *testVirtualWebAuthnSetup, resp *BeginStepUpResponse) json.RawMessage {
	t.Helper()
	optsJSON, err := json.Marshal(resp)
	require.NoError(t, err)
	opts, err := virtualwebauthn.ParseAssertionOptions(string(optsJSON))
	require.NoError(t, err)
	return json.RawMessage(virtualwebauthn.CreateAssertionResponse(setup.rp, u.auth, u.credential, *opts))
}

func TestBeginDeleteAccountStepUp_ChallengeShape(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")
	_ = registerStepUpUser(t, setup, "Bob")

	resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
	require.NoError(t, err)

	user, err := setup.store.Users().GetByID(setup.ctx, alice.id)
	require.NoError(t, err)
	require.Len(t, user.WebauthnCredentials, 1)
	require.Len(t, resp.PublicKey.AllowCredentials, 1, "only the caller's own credentials")
	assert.Equal(t, []byte(user.WebauthnCredentials[0].CredentialID), []byte(resp.PublicKey.AllowCredentials[0].ID))
	assert.Equal(t, "required", string(resp.PublicKey.UserVerification))
	assert.Equal(t, testRPID, resp.PublicKey.RPId)

	ch, err := setup.store.Challenges().GetByID(setup.ctx, resp.ChallengeID)
	require.NoError(t, err)
	assert.Equal(t, ChallengeActionDeleteAccount, ch.Action)
	assert.Equal(t, alice.id.String(), ch.UserID)
	assert.WithinDuration(t, time.Now().Add(DeleteAccountChallengeTTL), ch.ValidUntil, 5*time.Second)
	assert.Equal(t, deleteAccountChallengeGrace, ch.ExpiresAt.Sub(ch.ValidUntil), "kept past its validity")
}

func TestBeginDeleteAccountStepUp_NoPasskey(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	u := &domain.User{UUID: domain.UserIDFromString("oidc-only")}
	require.NoError(t, setup.store.Users().Create(setup.ctx, u))
	_, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, u.UUID)
	assert.ErrorIs(t, err, ErrCredentialNotFound)
}

func TestVerifyDeleteAccountStepUp_Success_SingleUse(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")

	resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
	require.NoError(t, err)
	assertion := alice.assertFor(t, setup, resp)

	require.NoError(t, setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, assertion))

	// The same challenge and assertion cannot be replayed.
	err = setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, assertion)
	assert.ErrorIs(t, err, ErrStepUpFailed)
	_, err = setup.store.Challenges().GetByID(setup.ctx, resp.ChallengeID)
	assert.Error(t, err, "the challenge is consumed")
}

func TestVerifyDeleteAccountStepUp_ConcurrentReplayOnlyOnce(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")
	resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
	require.NoError(t, err)
	assertion := alice.assertFor(t, setup, resp)

	const n = 16
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			results <- setup.service.VerifyDeleteAccountStepUp(context.Background(), alice.id, resp.ChallengeID, assertion)
		}()
	}
	ok := 0
	for i := 0; i < n; i++ {
		if <-results == nil {
			ok++
		}
	}
	assert.Equal(t, 1, ok, "exactly one concurrent caller may succeed")
}

func TestVerifyDeleteAccountStepUp_OtherUsersCredentialRefused(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")
	bob := registerStepUpUser(t, setup, "Bob")

	t.Run("bob signs alice's challenge", func(t *testing.T) {
		resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
		require.NoError(t, err)
		// Bob's authenticator signs Alice's challenge with Bob's own handle.
		bobAssertion := bob.assertFor(t, setup, resp)
		err = setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, bobAssertion)
		assert.ErrorIs(t, err, ErrStepUpFailed)
	})

	t.Run("bob signs alice's challenge claiming alice's handle", func(t *testing.T) {
		resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
		require.NoError(t, err)
		forgedAuth := bob.auth
		forgedAuth.Options.UserHandle = alice.id.AsUserHandle()
		forged := &stepUpUser{id: bob.id, auth: forgedAuth, credential: bob.credential}
		err = setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, forged.assertFor(t, setup, resp))
		assert.ErrorIs(t, err, ErrStepUpFailed)
	})

	t.Run("bob presents alice's challenge id as himself", func(t *testing.T) {
		resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
		require.NoError(t, err)
		err = setup.service.VerifyDeleteAccountStepUp(setup.ctx, bob.id, resp.ChallengeID, bob.assertFor(t, setup, resp))
		assert.ErrorIs(t, err, ErrStepUpFailed)
		// Alice's pending challenge is not burned by the mismatch.
		require.NoError(t, setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, alice.assertFor(t, setup, resp)))
	})
}

func TestVerifyDeleteAccountStepUp_ExpiredChallenge(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")
	resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
	require.NoError(t, err)
	assertion := alice.assertFor(t, setup, resp)

	ch, err := setup.store.Challenges().GetByID(setup.ctx, resp.ChallengeID)
	require.NoError(t, err)
	ch.ValidUntil = time.Now().Add(-time.Second)

	// The cleanup worker leaves the challenge: it is only past its validity.
	require.NoError(t, setup.store.Challenges().DeleteExpired(setup.ctx))

	err = setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, assertion)
	assert.ErrorIs(t, err, ErrChallengeExpired)

	// An expired challenge is still consumed and never usable.
	err = setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, assertion)
	assert.ErrorIs(t, err, ErrStepUpFailed)
}

func TestVerifyDeleteAccountStepUp_ChallengeForOtherActionRefused(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")

	t.Run("login challenge", func(t *testing.T) {
		login, err := setup.service.BeginLogin(setup.ctx)
		require.NoError(t, err)
		loginJSON, err := json.Marshal(login.GetOptions)
		require.NoError(t, err)
		opts, err := virtualwebauthn.ParseAssertionOptions(string(loginJSON))
		require.NoError(t, err)
		assertion := virtualwebauthn.CreateAssertionResponse(setup.rp, alice.auth, alice.credential, *opts)
		err = setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, login.ChallengeID, json.RawMessage(assertion))
		assert.ErrorIs(t, err, ErrStepUpFailed)
	})

	t.Run("same user, different action", func(t *testing.T) {
		resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
		require.NoError(t, err)
		ch, err := setup.store.Challenges().GetByID(setup.ctx, resp.ChallengeID)
		require.NoError(t, err)
		ch.Action = "add_credential"
		err = setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, alice.assertFor(t, setup, resp))
		assert.ErrorIs(t, err, ErrStepUpFailed)
	})
}

func TestVerifyDeleteAccountStepUp_MalformedInput(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")
	resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
	require.NoError(t, err)

	assert.ErrorIs(t, setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, "", json.RawMessage(`{}`)), ErrStepUpFailed)
	assert.ErrorIs(t, setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, nil), ErrStepUpFailed)
	assert.ErrorIs(t, setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, "nope", json.RawMessage(`{}`)), ErrStepUpFailed)
	assert.ErrorIs(t, setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, json.RawMessage(`{"id":1}`)), ErrStepUpFailed)
}

func TestVerifyDeleteAccountStepUp_AssertionForAnotherChallengeRefused(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")
	first, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
	require.NoError(t, err)
	second, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
	require.NoError(t, err)

	err = setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, second.ChallengeID, alice.assertFor(t, setup, first))
	assert.ErrorIs(t, err, ErrStepUpFailed)
}

// A sign-counter regression is accepted, as at login, but leaves the same
// security log line and SET event, once, and the flag persisted.
func TestVerifyDeleteAccountStepUp_CloneWarningSurfaced(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	core, observed := observer.New(zap.WarnLevel)
	setup.service.logger = zap.New(core)
	captured := attachIdentityAudit(t, setup.service)
	alice := registerStepUpUser(t, setup, "Alice")

	stepUp := func(counter uint32) {
		t.Helper()
		alice.credential.Counter = counter
		resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
		require.NoError(t, err)
		require.NoError(t, setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, alice.assertFor(t, setup, resp)))
	}
	stepUp(10)
	require.Empty(t, observed.FilterMessage("possible cloned authenticator detected").All())
	stepUp(3)

	entries := observed.FilterMessage("possible cloned authenticator detected").All()
	require.Len(t, entries, 1)
	assert.Equal(t, "webauthn_clone_warning", entries[0].ContextMap()["security_event"])
	assert.Equal(t, alice.id.String(), entries[0].ContextMap()["user_id"])
	assert.Equal(t, []string{string(EventWebAuthnCloneWarning)}, captured.URIs())

	user, err := setup.store.Users().GetByID(setup.ctx, alice.id)
	require.NoError(t, err)
	assert.True(t, user.WebauthnCredentials[0].Authenticator.CloneWarning)

	stepUp(2)
	assert.Len(t, observed.FilterMessage("possible cloned authenticator detected").All(), 1, "latched: no repeat")
}

// enrolment is a begun add-credential ceremony and the new passkey's response.
type enrolment struct {
	begin    *BeginAddCredentialResponse
	finish   *FinishAddCredentialRequest
	passkey  *stepUpUser
	signable json.RawMessage // the authorisation options, as JSON
}

// beginEnrol starts adding a passkey to u's account and answers the
// registration ceremony with a new passkey; it sets no authorisation.
func beginEnrol(t *testing.T, setup *testVirtualWebAuthnSetup, u *stepUpUser) *enrolment {
	t.Helper()
	begin, err := setup.service.BeginAddCredential(setup.ctx, u.id)
	require.NoError(t, err)
	optsJSON, err := json.Marshal(begin.CreateOptions)
	require.NoError(t, err)
	opts, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
	require.NoError(t, err)
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	auth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: u.id.AsUserHandle()})
	resp := virtualwebauthn.CreateAttestationResponse(setup.rp, auth, cred, *opts)
	auth.AddCredential(cred)
	e := &enrolment{
		begin: begin,
		finish: &FinishAddCredentialRequest{
			ChallengeID: begin.ChallengeID, Credential: json.RawMessage(resp), Nickname: "added",
		},
		passkey: &stepUpUser{id: u.id, auth: auth, credential: cred},
	}
	if begin.Authorization != nil {
		e.signable, err = json.Marshal(begin.Authorization)
		require.NoError(t, err)
	}
	return e
}

// authorizeWith signs the enrolment's authorisation options with u's passkey.
func (e *enrolment) authorizeWith(t *testing.T, setup *testVirtualWebAuthnSetup, u *stepUpUser) {
	t.Helper()
	opts, err := virtualwebauthn.ParseAssertionOptions(string(e.signable))
	require.NoError(t, err)
	e.finish.Authorization = json.RawMessage(virtualwebauthn.CreateAssertionResponse(setup.rp, u.auth, u.credential, *opts))
}

// enrollPasskey adds a second passkey to u's account, authorised by u's own.
func enrollPasskey(t *testing.T, setup *testVirtualWebAuthnSetup, u *stepUpUser) *stepUpUser {
	t.Helper()
	e := beginEnrol(t, setup, u)
	e.authorizeWith(t, setup, u)
	_, err := setup.service.FinishAddCredential(setup.ctx, u.id, e.finish, "")
	require.NoError(t, err)
	return e.passkey
}

func credentialCount(t *testing.T, setup *testVirtualWebAuthnSetup, u *stepUpUser) int {
	t.Helper()
	user, err := setup.store.Users().GetByID(setup.ctx, u.id)
	require.NoError(t, err)
	return len(user.WebauthnCredentials)
}

// With only the bearer token, enrolling a passkey is refused, and so the
// attacker has no passkey to sign a deletion step-up with.
func TestEnrollment_StolenTokenCannotEnrolThenDeleteAccount(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")

	e := beginEnrol(t, setup, alice)
	require.NotNil(t, e.begin.Authorization, "an account with a passkey asks for authorisation")
	_, err := setup.service.FinishAddCredential(setup.ctx, alice.id, e.finish, "")
	assert.ErrorIs(t, err, ErrEnrollmentAuthorizationRequired)
	assert.Equal(t, 1, credentialCount(t, setup, alice))

	// Nor can the attacker satisfy it with their own key.
	e = beginEnrol(t, setup, alice)
	e.authorizeWith(t, setup, e.passkey)
	_, err = setup.service.FinishAddCredential(setup.ctx, alice.id, e.finish, "")
	assert.ErrorIs(t, err, ErrEnrollmentAuthorizationFailed)
	assert.Equal(t, 1, credentialCount(t, setup, alice))

	// The deletion step-up then refuses the attacker's passkey.
	resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
	require.NoError(t, err)
	err = setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, e.passkey.assertFor(t, setup, resp))
	assert.ErrorIs(t, err, ErrStepUpFailed)
}

func TestEnrollment_AuthorisedByExistingPasskeySucceeds(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")
	_ = enrollPasskey(t, setup, alice)
	assert.Equal(t, 2, credentialCount(t, setup, alice))
}

// An assertion over another challenge (here a deletion step-up) does not
// authorise an enrolment, and the authorisation is single use with it.
func TestEnrollment_AssertionForAnotherChallengeRefused(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")

	e := beginEnrol(t, setup, alice)
	su, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
	require.NoError(t, err)
	e.finish.Authorization = alice.assertFor(t, setup, su)
	_, err = setup.service.FinishAddCredential(setup.ctx, alice.id, e.finish, "")
	assert.ErrorIs(t, err, ErrEnrollmentAuthorizationFailed)
	assert.Equal(t, 1, credentialCount(t, setup, alice))

	// The enrolment challenge is consumed by the refusal.
	e2 := beginEnrol(t, setup, alice)
	e2.authorizeWith(t, setup, alice)
	_, err = setup.service.FinishAddCredential(setup.ctx, alice.id, e2.finish, "")
	require.NoError(t, err)
	_, err = setup.service.FinishAddCredential(setup.ctx, alice.id, e2.finish, "")
	assert.ErrorIs(t, err, ErrChallengeNotFound)
}

func TestEnrollment_OtherUsersPasskeyCannotAuthorise(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")
	bob := registerStepUpUser(t, setup, "Bob")

	e := beginEnrol(t, setup, alice)
	e.authorizeWith(t, setup, bob)
	_, err := setup.service.FinishAddCredential(setup.ctx, alice.id, e.finish, "")
	assert.ErrorIs(t, err, ErrEnrollmentAuthorizationFailed)
	assert.Equal(t, 1, credentialCount(t, setup, alice))
}

// An account with no passkey has nothing to authorise with.
func TestEnrollment_AccountWithoutPasskeyNeedsNoAuthorization(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")
	user, err := setup.store.Users().GetByID(setup.ctx, alice.id)
	require.NoError(t, err)
	user.WebauthnCredentials = nil
	require.NoError(t, setup.store.Users().Update(setup.ctx, user))

	e := beginEnrol(t, setup, alice)
	assert.Nil(t, e.begin.Authorization)
	_, err = setup.service.FinishAddCredential(setup.ctx, alice.id, e.finish, "")
	require.NoError(t, err)
}

// A passkey whose enrolment an existing passkey authorised can authorise a deletion.
func TestStepUp_AuthorisedPasskeyAcceptedForDeletion(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")
	added := enrollPasskey(t, setup, alice)

	resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
	require.NoError(t, err)
	require.Len(t, resp.PublicKey.AllowCredentials, 2)
	require.NoError(t, setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, added.assertFor(t, setup, resp)))
}

// The authorising passkey's counter advance and latched clone warning,
// persisted while verifying the authorisation, must survive the enrolment's
// own write of the user record.
func TestEnrollment_KeepsTheAuthorisingPasskeysCounterAndCloneWarning(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	alice := registerStepUpUser(t, setup, "Alice")

	// A prior use leaves a high stored counter, so the next assertion (lower)
	// latches the clone warning.
	alice.credential.Counter = 50
	resp, err := setup.service.BeginDeleteAccountStepUp(setup.ctx, alice.id)
	require.NoError(t, err)
	require.NoError(t, setup.service.VerifyDeleteAccountStepUp(setup.ctx, alice.id, resp.ChallengeID, alice.assertFor(t, setup, resp)))

	alice.credential.Counter = 3
	e := beginEnrol(t, setup, alice)
	e.authorizeWith(t, setup, alice)
	_, err = setup.service.FinishAddCredential(setup.ctx, alice.id, e.finish, "")
	require.NoError(t, err)

	user, err := setup.store.Users().GetByID(setup.ctx, alice.id)
	require.NoError(t, err)
	require.Len(t, user.WebauthnCredentials, 2)
	first := user.WebauthnCredentials[0].Authenticator
	assert.True(t, first.CloneWarning, "the clone warning latched by the authorising assertion must survive the enrolment")
	assert.Greater(t, first.SignCount, uint32(0), "the authorising passkey's counter must survive the enrolment")
}
