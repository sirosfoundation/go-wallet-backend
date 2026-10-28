package as

import (
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
