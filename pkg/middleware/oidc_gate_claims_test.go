package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

const (
	claimsTestIssuer   = "https://idp.example.com"
	claimsTestAudience = "wallet-client"
	claimsTestKID      = "claims-test-key"
)

// newClaimsGateRouter builds a router guarded by the registration gate for a
// tenant with the given RequiredClaims, backed by a real JWKS endpoint, and
// returns a function that signs tokens with the matching key.
func newClaimsGateRouter(t *testing.T, required map[string]interface{}) (*gin.Engine, func(extra jwt.MapClaims) string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := fmt.Sprintf(`{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":%q}`,
		claimsTestKID,
		base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()))

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[%s]}`, jwk)
	}))
	t.Cleanup(jwks.Close)

	logger := zaptest.NewLogger(t)
	tenant := &domain.Tenant{
		ID:   "claims-tenant",
		Name: "Claims Tenant",
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeRegistration,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   claimsTestIssuer,
				ClientID: claimsTestAudience,
				JWKSURI:  jwks.URL,
			},
			RequiredClaims: required,
		},
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant", tenant)
		c.Next()
	})
	router.Use(OIDCGateMiddleware(NewValidatorCache(nil, logger), GateTypeRegistration, logger))
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	sign := func(extra jwt.MapClaims) string {
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": claimsTestIssuer,
			"aud": claimsTestAudience,
			"sub": "user-1",
			"exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(),
			"nbf": now.Unix(),
		}
		for k, v := range extra {
			claims[k] = v
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = claimsTestKID
		s, err := tok.SignedString(key)
		require.NoError(t, err)
		return s
	}
	return router, sign
}

func postWithToken(router *gin.Engine, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestOIDCGateMiddleware_RequiredClaims(t *testing.T) {
	required := map[string]interface{}{
		"email_verified": true,
		"department":     "Engineering",
		"groups":         []interface{}{"admin"},
	}
	router, sign := newClaimsGateRouter(t, required)

	tests := []struct {
		name    string
		claims  jwt.MapClaims
		want    int
		wantMsg string
	}{
		{
			name: "all claims match",
			claims: jwt.MapClaims{
				"email_verified": true,
				"department":     "Engineering",
				"groups":         []string{"admin"},
			},
			want: http.StatusOK,
		},
		{
			name: "array containment ignores order and extra elements",
			claims: jwt.MapClaims{
				"email_verified": true,
				"department":     "Engineering",
				"groups":         []string{"users", "ops", "admin"},
			},
			want: http.StatusOK,
		},
		{
			name:    "required claim missing",
			claims:  jwt.MapClaims{"email_verified": true, "groups": []string{"admin"}},
			want:    http.StatusUnauthorized,
			wantMsg: "Missing required claim: department",
		},
		{
			name: "scalar claim mismatch",
			claims: jwt.MapClaims{
				"email_verified": true,
				"department":     "Sales",
				"groups":         []string{"admin"},
			},
			want:    http.StatusUnauthorized,
			wantMsg: "Claim mismatch: department",
		},
		{
			name: "bool claim is not satisfied by a string",
			claims: jwt.MapClaims{
				"email_verified": "true",
				"department":     "Engineering",
				"groups":         []string{"admin"},
			},
			want:    http.StatusUnauthorized,
			wantMsg: "Claim mismatch: email_verified",
		},
		{
			name: "array claim missing the expected element",
			claims: jwt.MapClaims{
				"email_verified": true,
				"department":     "Engineering",
				"groups":         []string{"users"},
			},
			want:    http.StatusUnauthorized,
			wantMsg: "Claim mismatch: groups",
		},
		{
			name: "array claim of wrong type",
			claims: jwt.MapClaims{
				"email_verified": true,
				"department":     "Engineering",
				"groups":         map[string]interface{}{"admin": true},
			},
			want:    http.StatusUnauthorized,
			wantMsg: "Claim mismatch: groups",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := postWithToken(router, sign(tt.claims))
			assert.Equal(t, tt.want, w.Code, w.Body.String())
			if tt.wantMsg != "" {
				var resp map[string]interface{}
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
				assert.Equal(t, "oidc_gate_required", resp["error"])
				assert.Contains(t, w.Body.String(), tt.wantMsg)
			}
		})
	}
}

func TestOIDCGateMiddleware_NoRequiredClaims(t *testing.T) {
	router, sign := newClaimsGateRouter(t, nil)
	w := postWithToken(router, sign(nil))
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
