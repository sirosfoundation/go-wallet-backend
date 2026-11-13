package engine

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

const authorizationContextPurpose = "oid4vci-authorization-context.v1"

// authorizationContext survives a same-tab redirect without trusting the
// callback or rediscovered metadata to describe the original transaction.
type authorizationContext struct {
	jwt.RegisteredClaims
	TenantID         string `json:"tenant_id"`
	AuthorizationAS  string `json:"authorization_server"`
	CredentialIssuer string `json:"credential_issuer"`
	TokenEndpoint    string `json:"token_endpoint"`
	ClientID         string `json:"client_id"`
	RedirectURI      string `json:"redirect_uri"`
	State            string `json:"state"`
	CodeChallenge    string `json:"code_challenge"`
	PKCERequired     bool   `json:"pkce_required"`
	IssuerRequired   bool   `json:"issuer_required"`
}

func (h *OID4VCIHandler) authorizationContextKey() ([]byte, error) {
	if h.Config == nil || len(h.Config.JWT.Secret) < 32 {
		return nil, errors.New("OID4VCI authorization requires jwt.secret of at least 32 bytes")
	}
	mac := hmac.New(sha256.New, []byte(h.Config.JWT.Secret))
	_, _ = mac.Write([]byte(authorizationContextPurpose))
	return mac.Sum(nil), nil
}

func (h *OID4VCIHandler) requiresAuthorizationIssuer() bool {
	return h.Config != nil && h.Config.Security.RequireAuthorizationResponseIssuer
}

func authorizationServerIdentifier(metadata *IssuerMetadata) string {
	if as := metadata.authorizationServer(); as != "" {
		return as
	}
	return metadata.CredentialIssuer
}

func (h *OID4VCIHandler) newAuthorizationContext(metadata *IssuerMetadata, oauthMeta *oauthServerMetadata, state, verifier string) (*authorizationContext, string, error) {
	key, err := h.authorizationContextKey()
	if err != nil {
		return nil, "", err
	}
	tokenEndpoint := metadata.TokenEndpoint
	if tokenEndpoint == "" {
		tokenEndpoint = oauthMeta.TokenEndpoint
	}
	if tokenEndpoint == "" {
		tokenEndpoint = strings.TrimSuffix(metadata.CredentialIssuer, "/") + "/token"
	}
	transaction := &authorizationContext{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{authorizationContextPurpose},
			Subject:   h.Flow.Session.UserID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(UserInteractionTimeout)),
		},
		TenantID:         h.Flow.Session.TenantID,
		AuthorizationAS:  authorizationServerIdentifier(metadata),
		CredentialIssuer: metadata.CredentialIssuer,
		TokenEndpoint:    tokenEndpoint,
		ClientID:         h.clientID,
		RedirectURI:      h.redirectURI,
		State:            state,
		CodeChallenge:    computeCodeChallenge(verifier),
		PKCERequired:     oauthMeta.supportsPKCE(),
		IssuerRequired:   oauthMeta.AuthorizationResponseIssParameterSupported || h.requiresAuthorizationIssuer(),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, transaction).SignedString(key)
	return transaction, signed, err
}

func (h *OID4VCIHandler) parseAuthorizationContext(encoded string, metadata *IssuerMetadata) (*authorizationContext, error) {
	if encoded == "" {
		return nil, errors.New("authorization_context is required for flow resumption")
	}
	key, err := h.authorizationContextKey()
	if err != nil {
		return nil, err
	}
	var transaction authorizationContext
	_, err = jwt.ParseWithClaims(encoded, &transaction, func(*jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithAudience(authorizationContextPurpose), jwt.WithExpirationRequired())
	if err != nil {
		return nil, errors.New("invalid or expired authorization_context")
	}
	if transaction.Subject != h.Flow.Session.UserID || transaction.TenantID != h.Flow.Session.TenantID ||
		transaction.CredentialIssuer != metadata.CredentialIssuer ||
		transaction.AuthorizationAS != authorizationServerIdentifier(metadata) ||
		transaction.ClientID != h.clientID {
		return nil, errors.New("authorization_context does not match this flow")
	}
	return &transaction, nil
}

func (h *OID4VCIHandler) validateAuthorizationResponse(transaction *authorizationContext, state string, issuer *string) error {
	if state == "" || state != transaction.State {
		return errors.New("state parameter mismatch (possible CSRF)")
	}
	if issuer == nil {
		if transaction.IssuerRequired || h.requiresAuthorizationIssuer() {
			return errors.New("authorization response is missing iss")
		}
		return nil
	}
	if *issuer == "" {
		return errors.New("authorization response has empty iss")
	}
	if *issuer != transaction.AuthorizationAS {
		return errors.New("authorization response issuer mismatch")
	}
	return nil
}

func (h *OID4VCIHandler) failAuthorizationResponse(err error) error {
	h.Logger.Warn("authorization response rejected", zap.Error(err))
	_ = h.Error(StepAuthorizationReq, ErrCodeAuthorizationFail, err.Error())
	return err
}

// Reject repeated or non-string issuer fields instead of allowing JSON's
// last-value-wins decoding to hide an invalid response.
func validateAuthorizationIssuerJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return errors.New("invalid authorization response")
	}
	seen := false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("invalid authorization response")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return errors.New("invalid authorization response")
		}
		name, ok := token.(string)
		if ok && strings.EqualFold(name, "iss") {
			if seen {
				return errors.New("authorization response has duplicate iss")
			}
			seen = true
			var issuer string
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &issuer) != nil {
				return errors.New("authorization response iss must be a string")
			}
		}
	}
	return nil
}
