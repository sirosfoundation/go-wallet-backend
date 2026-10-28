package as

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

// The policy is a pure function over a Session or a parent token's claims, so
// these exercise every rule without a *gin.Context, an HTTP recorder or a
// session store. Before the extraction none of this was reachable except by
// driving the endpoint.

func TestAuthorizeSessionToken(t *testing.T) {
	for _, tc := range []struct {
		name       string
		session    Session
		req        TokenRequest
		wantTenant string
		wantTAC    TAC
		wantErr    *tokenError
	}{
		{
			name:       "defaults to the session's tenant and full MaxTAC",
			session:    Session{TenantID: "acme", MaxTAC: TAC("rw")},
			req:        TokenRequest{},
			wantTenant: "acme",
			wantTAC:    TAC("rw"),
		},
		{
			name:       "a narrower TAC is honoured",
			session:    Session{TenantID: "acme", MaxTAC: TAC("rw")},
			req:        TokenRequest{TAC: "r"},
			wantTenant: "acme",
			wantTAC:    TAC("r"),
		},
		{
			name:       "a cross-tenant session may be narrowed",
			session:    Session{TenantID: "*", MaxTAC: TAC("rw")},
			req:        TokenRequest{TenantID: "acme"},
			wantTenant: "acme",
			wantTAC:    TAC("rw"),
		},
		{
			name:    "a tenant-bound session may not target another tenant",
			session: Session{TenantID: "acme", MaxTAC: TAC("rw")},
			req:     TokenRequest{TenantID: "other"},
			wantErr: errTenantMismatch,
		},
		{
			name:    "an empty MaxTAC grants nothing",
			session: Session{TenantID: "acme", MaxTAC: TAC("")},
			req:     TokenRequest{TAC: "r"},
			wantErr: errNoGrantedPerms,
		},
		{
			name:    "a TAC beyond MaxTAC is refused",
			session: Session{TenantID: "acme", MaxTAC: TAC("r")},
			req:     TokenRequest{TAC: "rw"},
			wantErr: errTACExceedsSession,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant, tac, err := authorizeSessionToken(&tc.session, &tc.req)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantTenant, tenant)
			assert.Equal(t, tc.wantTAC, tac)
		})
	}
}

func TestAuthorizeAnonymousToken(t *testing.T) {
	for _, tc := range []struct {
		name       string
		session    Session
		req        TokenRequest
		wantTenant string
		wantTAC    TAC
		wantErr    *tokenError
	}{
		{
			name:       "defaults to read-only, not to the session's MaxTAC",
			session:    Session{TenantID: "acme", MaxTAC: TAC("rw"), ACR: "pwd"},
			req:        TokenRequest{},
			wantTenant: "acme",
			wantTAC:    anonymousDefaultTAC,
		},
		{
			name:    "a session with no ACR mints nothing",
			session: Session{TenantID: "acme", MaxTAC: TAC("rw")},
			req:     TokenRequest{},
			wantErr: errNoAuthContext,
		},
		{
			name:    "capped to read-only even when MaxTAC allows more",
			session: Session{TenantID: "acme", MaxTAC: TAC("rw"), ACR: "pwd"},
			req:     TokenRequest{TAC: "rw"},
			wantErr: errAnonymousReadOnly,
		},
		{
			// Both checks are needed: the cap does not subsume MaxTAC.
			name:    "a write-only session cannot mint even a read-only token",
			session: Session{TenantID: "acme", MaxTAC: TAC("w"), ACR: "pwd"},
			req:     TokenRequest{TAC: "r"},
			wantErr: errTACExceedsSession,
		},
		{
			name:    "tenant scoping applies here too",
			session: Session{TenantID: "acme", MaxTAC: TAC("rw"), ACR: "pwd"},
			req:     TokenRequest{TenantID: "other"},
			wantErr: errTenantMismatch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant, tac, err := authorizeAnonymousToken(&tc.session, &tc.req)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantTenant, tenant)
			assert.Equal(t, tc.wantTAC, tac)
		})
	}
}

func delegationParent(tenant string, tac TAC) *AccessTokenClaims {
	return &AccessTokenClaims{
		Claims:   jwt.Claims{Subject: "user-1"},
		TenantID: tenant,
		TAC:      tac,
	}
}

func TestAuthorizeDelegationToken(t *testing.T) {
	for _, tc := range []struct {
		name       string
		parent     *AccessTokenClaims
		req        TokenRequest
		wantTenant string
		wantTAC    TAC
		wantErr    *tokenError
	}{
		{
			name:       "k is stripped by default",
			parent:     delegationParent("acme", TAC("rwk")),
			req:        TokenRequest{},
			wantTenant: "acme",
			wantTAC:    TAC("rw"),
		},
		{
			name:       "re-delegation is possible when asked for explicitly",
			parent:     delegationParent("acme", TAC("rwk")),
			req:        TokenRequest{TAC: "rk"},
			wantTenant: "acme",
			wantTAC:    TAC("rk"),
		},
		{
			name:       "a cross-tenant parent may be narrowed",
			parent:     delegationParent("*", TAC("rk")),
			req:        TokenRequest{TenantID: "acme"},
			wantTenant: "acme",
			wantTAC:    TAC("r"),
		},
		{
			name:    "a parent without k cannot delegate",
			parent:  delegationParent("acme", TAC("rw")),
			req:     TokenRequest{},
			wantErr: errNoDelegatePerm,
		},
		{
			name:    "delegation cannot change tenant",
			parent:  delegationParent("acme", TAC("rk")),
			req:     TokenRequest{TenantID: "other"},
			wantErr: errDelegationTenant,
		},
		{
			name:    "a delegated token can never exceed its parent",
			parent:  delegationParent("acme", TAC("rk")),
			req:     TokenRequest{TAC: "rw"},
			wantErr: errTACExceedsParent,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant, tac, err := authorizeDelegationToken(tc.parent, &tc.req)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantTenant, tenant)
			assert.Equal(t, tc.wantTAC, tac)
		})
	}
}

// Every refusal must carry a registered RFC 6749 section 5.2 code, so the
// later switch to emitting it cannot silently ship an empty or invented one.
func TestTokenErrorsCarryRegisteredOAuthCodes(t *testing.T) {
	registered := map[string]bool{
		oauthErrInvalidRequest: true,
		oauthErrInvalidGrant:   true,
		oauthErrInvalidScope:   true,
		oauthErrInvalidClient:  true,
	}
	for _, e := range []*tokenError{
		errInvalidSession, errNoAuthContext, errNoDelegateAuth, errInvalidParent,
		errParentRevoked, errParentUserGone, errTenantMismatch, errNoGrantedPerms,
		errTACExceedsSession, errAnonymousReadOnly, errNoDelegatePerm,
		errDelegationTenant, errTACExceedsParent,
	} {
		assert.True(t, registered[e.Code], "%q is not an RFC 6749 section 5.2 code (%s)", e.Code, e.Message)
		assert.NotEmpty(t, e.Message)
		assert.NotZero(t, e.Status)
	}
}

// respondTokenError must not leak a non-tokenError's text to the client.
func TestRespondTokenErrorHidesUnknownErrors(t *testing.T) {
	var te *tokenError
	require.False(t, errors.As(errors.New("mongo: connection refused to db-7"), &te))
}

// These reuse the package's existing fakeBlacklist (token_endpoint_test.go).

var errStoreDown = errors.New("revocation store unreachable")

func TestSessionOwnerRevoked(t *testing.T) {
	session := &Session{UserID: "user-1"}
	for _, tc := range []struct {
		name         string
		bl           *fakeBlacklist
		deletionOnly bool
		tac          TAC
		wantErr      error
	}{
		{
			name: "a live owner may have a token",
			bl:   &fakeBlacklist{},
		},
		{
			name:    "a revoked owner may not",
			bl:      &fakeBlacklist{revokedUsers: map[string]bool{"user-1": true}},
			wantErr: errInvalidSession,
		},
		{
			name:         "except exactly the deletion permission",
			bl:           &fakeBlacklist{revokedUsers: map[string]bool{"user-1": true}},
			deletionOnly: true,
			tac:          TAC(string(TACDelete)),
		},
		{
			// The exemption is for DELETE /user/session alone, not for any
			// token that merely includes "d".
			name:         "not a wider TAC that happens to include d",
			bl:           &fakeBlacklist{revokedUsers: map[string]bool{"user-1": true}},
			deletionOnly: true,
			tac:          TAC("rd"),
			wantErr:      errInvalidSession,
		},
		{
			name:         "and not on a path that does not allow it",
			bl:           &fakeBlacklist{revokedUsers: map[string]bool{"user-1": true}},
			deletionOnly: false,
			tac:          TAC(string(TACDelete)),
			wantErr:      errInvalidSession,
		},
		{
			name:    "a store that cannot answer is not an allow",
			bl:      &fakeBlacklist{userErr: errStoreDown},
			wantErr: errStoreDown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sessionOwnerRevoked(context.Background(), tc.bl, session, tc.deletionOnly, tc.tac)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestParentTokenRevoked(t *testing.T) {
	parent := func(jti string) *AccessTokenClaims {
		return &AccessTokenClaims{Claims: jwt.Claims{ID: jti, Subject: "user-1"}}
	}
	for _, tc := range []struct {
		name    string
		parent  *AccessTokenClaims
		bl      *fakeBlacklist
		wantErr error
	}{
		{
			name:   "a live parent may be exchanged",
			parent: parent("jti-1"),
			bl:     &fakeBlacklist{},
		},
		{
			name:    "a revoked jti may not",
			parent:  parent("jti-1"),
			bl:      &fakeBlacklist{revoked: map[string]bool{"jti-1": true}},
			wantErr: errParentRevoked,
		},
		{
			// #391: a different, never-blacklisted token of a deleted user
			// was still exchangeable when only the jti was checked.
			name:    "a revoked user may not, even with a clean jti",
			parent:  parent("jti-1"),
			bl:      &fakeBlacklist{revokedUsers: map[string]bool{"user-1": true}},
			wantErr: errParentUserGone,
		},
		{
			name:    "an unreadable jti check is not an allow",
			parent:  parent("jti-1"),
			bl:      &fakeBlacklist{jtiErr: errStoreDown},
			wantErr: errStoreDown,
		},
		{
			name:    "an unreadable user check is not an allow either",
			parent:  parent("jti-1"),
			bl:      &fakeBlacklist{userErr: errStoreDown},
			wantErr: errStoreDown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := parentTokenRevoked(context.Background(), tc.bl, tc.parent)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// A parent with no jti skips that check, but must still be checked by user:
// the skip is the one implicit path in parentTokenRevoked, so pin it.
func TestParentTokenRevoked_NoJTISkipsThatCheckOnly(t *testing.T) {
	// jtiErr would surface if the jti check ran at all, so reaching the
	// user refusal proves the empty jti was skipped and nothing else was.
	bl := &fakeBlacklist{
		jtiErr:       errStoreDown,
		revokedUsers: map[string]bool{"user-1": true},
	}
	err := parentTokenRevoked(context.Background(), bl, &AccessTokenClaims{
		Claims: jwt.Claims{Subject: "user-1"},
	})
	assert.ErrorIs(t, err, errParentUserGone, "the user check still runs")
	assert.NotErrorIs(t, err, errStoreDown, "an empty jti must not be looked up")
}

// fakeCutoffUsers is the tokengate.UserLookup behind the cut-off tests: one
// cut-off per user id, or an error for every lookup.
type fakeCutoffUsers struct {
	cutoffs map[string]time.Time
	err     error
}

func (f fakeCutoffUsers) GetAuthCutoff(_ context.Context, id domain.UserID) (time.Time, error) {
	if f.err != nil {
		return time.Time{}, f.err
	}
	return f.cutoffs[id.String()], nil
}

func (fakeCutoffUsers) GetDeletionTombstone(context.Context, string) (*domain.DeletionTombstone, error) {
	return nil, nil
}

// The SID-AUTH-06 cut-off is a policy rule like the others: it refuses a
// session or delegating token that predates the user's cut-off, and answers a
// store that cannot say with a failure (never an allow).
func TestSessionPredatesCutoff(t *testing.T) {
	uid := domain.NewUserID().String()
	cutoff := time.Now().Add(-time.Minute)
	gate := tokengate.New(fakeCutoffUsers{cutoffs: map[string]time.Time{uid: cutoff}})
	session := func(at time.Time) *Session { return &Session{UserID: uid, CreatedAt: at} }

	assert.NoError(t, sessionPredatesCutoff(context.Background(), gate, session(time.Now())))
	assert.ErrorIs(t, sessionPredatesCutoff(context.Background(), gate, session(cutoff.Add(-time.Hour))), errSessionPredatesCutoff)

	// The login's own authentication instant wins over the record's creation
	// time: a session written after the cut-off by a login that began before
	// it is still refused.
	late := &Session{UserID: uid, CreatedAt: time.Now(), AuthenticatedAt: cutoff.Add(-time.Hour)}
	assert.ErrorIs(t, sessionPredatesCutoff(context.Background(), gate, late), errSessionPredatesCutoff)

	// No gate: no lifecycle gating.
	assert.NoError(t, sessionPredatesCutoff(context.Background(), nil, session(cutoff.Add(-time.Hour))))

	broken := tokengate.New(fakeCutoffUsers{err: errStoreDown})
	err := sessionPredatesCutoff(context.Background(), broken, session(time.Now()))
	var cc *cutoffCheckError
	require.ErrorAs(t, err, &cc)
	assert.ErrorIs(t, err, errStoreDown)
	var te *tokenError
	assert.False(t, errors.As(err, &te), "a store failure is not a policy refusal")
}

func TestParentAndIssuePhaseCutoff(t *testing.T) {
	uid := domain.NewUserID().String()
	cutoff := time.Now().Add(-time.Minute)
	gate := tokengate.New(fakeCutoffUsers{cutoffs: map[string]time.Time{uid: cutoff}})
	old := cutoffSubject{userID: uid, issuedAt: cutoff.Add(-time.Hour)}
	fresh := cutoffSubject{userID: uid, issuedAt: time.Now()}

	assert.NoError(t, parentPredatesCutoff(context.Background(), gate, fresh))
	assert.ErrorIs(t, parentPredatesCutoff(context.Background(), gate, old), errParentPredatesCutoff)
	assert.NoError(t, issuedAfterCutoff(context.Background(), gate, fresh))
	assert.ErrorIs(t, issuedAfterCutoff(context.Background(), gate, old), errRevokedWhileIssuing)
}

// A revoked owner's deletion-only exemption (sessionOwnerRevoked) and the
// lifecycle cut-off are independent: the exemption lifts the first and never
// the second, in whichever order the endpoint applies them.
func TestRevokedOwnerExemptionDoesNotLiftCutoff(t *testing.T) {
	uid := domain.NewUserID().String()
	cutoff := time.Now().Add(-time.Minute)
	gate := tokengate.New(fakeCutoffUsers{cutoffs: map[string]time.Time{uid: cutoff}})
	bl := &fakeBlacklist{revokedUsers: map[string]bool{uid: true}}
	del := TAC(string(TACDelete))

	for _, tc := range []struct {
		name       string
		created    time.Time
		wantCutoff error
		wantOwner  error
	}{
		{"session after cut-off: the exemption lets the deletion token through", time.Now(), nil, nil},
		{"session before cut-off: the cut-off still refuses", cutoff.Add(-time.Hour), errSessionPredatesCutoff, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{UserID: uid, CreatedAt: tc.created}
			assert.ErrorIs(t, sessionPredatesCutoff(context.Background(), gate, s), tc.wantCutoff)
			// The owner check alone passes in both cases: only the cut-off differs.
			assert.NoError(t, sessionOwnerRevoked(context.Background(), bl, s, true, del))
		})
	}
	// Without the exemption the owner check refuses regardless of the cut-off.
	s := &Session{UserID: uid, CreatedAt: time.Now()}
	assert.NoError(t, sessionPredatesCutoff(context.Background(), gate, s))
	assert.ErrorIs(t, sessionOwnerRevoked(context.Background(), bl, s, false, ""), errInvalidSession)
}
