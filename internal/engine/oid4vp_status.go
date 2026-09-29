package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/statuslist"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// checkPresentationStatus looks up the Token Status List entry of every
// presented credential that carries a `status.status_list` claim and returns
// an error if any is not VALID or cannot be checked (fail closed).
//
// Only JWT-shaped credentials (SD-JWT VC, JWT VC) are examined: the status
// claim is in the issuer-signed JWT and is never selectively disclosable, so
// it is readable without the disclosures. mdoc credentials carry their status
// in the MSO and are not checked here.
func (h *OID4VPHandler) checkPresentationStatus(ctx context.Context, vpToken string) error {
	if h.statusChecker == nil {
		return nil
	}
	for _, tok := range presentedTokens(vpToken) {
		if err := h.checkTokenStatus(ctx, tok); err != nil {
			return err
		}
	}
	return nil
}

func (h *OID4VPHandler) checkTokenStatus(ctx context.Context, token string) error {
	issuerJWT, _, _ := strings.Cut(strings.TrimSpace(token), "~")
	parts := strings.Split(issuerJWT, ".")
	if len(parts) != 3 {
		h.Logger.Debug("presented credential is not JWT-shaped; status not checked")
		return nil
	}
	var claims map[string]any
	if err := decodeJWTSegment(parts[1], &claims); err != nil {
		// Not a credential JWT after all (e.g. an opaque token).
		h.Logger.Debug("presented credential payload unreadable; status not checked", zap.Error(err))
		return nil
	}
	ref, present, err := statuslist.ReferenceFromCredentialClaims(claims)
	if !present {
		return nil
	}
	if err != nil {
		return fmt.Errorf("credential status claim: %w", err)
	}

	var header struct {
		X5C []string `json:"x5c"`
		JWK any      `json:"jwk"`
	}
	_ = decodeJWTSegment(parts[0], &header)
	var signer *trust.KeyMaterial
	switch {
	case len(header.X5C) > 0:
		signer = &trust.KeyMaterial{Type: KeyMaterialTypeX5C, X5C: header.X5C}
	case header.JWK != nil:
		signer = &trust.KeyMaterial{Type: KeyMaterialTypeJWK, JWK: header.JWK}
	}
	if err := h.statusChecker.Check(ctx, ref, signer); err != nil {
		return fmt.Errorf("credential status (%s idx %d): %w", ref.URI, ref.Idx, err)
	}
	return nil
}

// presentedTokens flattens a vp_token into the individual presentations: a
// DCQL JSON object (query id -> string or array of strings), a JSON array, or
// one/newline-separated raw tokens.
func presentedTokens(vpToken string) []string {
	vpToken = strings.TrimSpace(vpToken)
	if vpToken == "" {
		return nil
	}
	if strings.HasPrefix(vpToken, "{") {
		var obj map[string]json.RawMessage
		if json.Unmarshal([]byte(vpToken), &obj) == nil {
			var out []string
			for _, raw := range obj {
				out = append(out, stringsOrOne(raw)...)
			}
			return out
		}
	}
	if strings.HasPrefix(vpToken, "[") {
		if out := stringsOrOne(json.RawMessage(vpToken)); out != nil {
			return out
		}
	}
	return strings.Split(vpToken, "\n")
}

func stringsOrOne(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

func decodeJWTSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return errors.New("bad base64url")
	}
	return json.Unmarshal(b, v)
}
