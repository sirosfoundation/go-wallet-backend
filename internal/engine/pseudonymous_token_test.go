package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// The pseudonymous engine token's subject names nobody, so the handshake
// consults neither the revocation store nor the cut-off for it: the AS refused
// the owner at the mint. The stores here fail every lookup, so a consultation
// would refuse the handshake (revocation checks fail closed); a named user
// under the same stores is refused, which shows the stores really are broken.
func TestManager_validateToken_PseudonymousTokenIsNotJudgedPerUser(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	v, key, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)
	m.SetTokenBlacklist(&fakeEngineBlacklist{userErr: errors.New("revocation store down")})
	m.SetTokenGate(tokengate.New(failingUsers{memory.NewStore().Users()}))

	token := func(sub string) string {
		return signEngineToken(t, key, issuer, claims.AccessTokenClaims{
			Claims:   gojosejwt.Claims{Audience: gojosejwt.Audience{"wallet-registry"}, Subject: sub},
			TenantID: "test-tenant",
			TAC:      "ri",
		})
	}

	user, tenant, tac, err := m.validateToken(context.Background(), token(tokengate.PseudonymPrefix+"6f1c2d3e-0000-4000-8000-000000000000"))
	require.NoError(t, err)
	assert.Equal(t, "test-tenant", tenant)
	assert.Equal(t, claims.TAC("ri"), tac)
	assert.NotEmpty(t, user)

	_, _, _, err = m.validateToken(context.Background(), token("a-named-user"))
	assert.Error(t, err, "a named user is still judged, and the broken stores refuse it")
}

// failingUsers fails every per-user lookup.
type failingUsers struct{ tokengate.UserLookup }

func (failingUsers) GetAuthCutoff(context.Context, domain.UserID) (time.Time, error) {
	return time.Time{}, errors.New("user store down")
}
