package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/statuslist"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

var (
	statusCheckersMu sync.Mutex
	statusCheckers   = map[*config.Config]*statuslist.Checker{}
)

// sharedStatusChecker returns the process-wide Checker for cfg. Handlers are
// built per flow, so a Checker made there would drop its list cache after
// every presentation; one per config lets the token's ttl deduplicate fetches
// across presentations. The Checker is safe for concurrent use.
func sharedStatusChecker(cfg *config.Config) *statuslist.Checker {
	statusCheckersMu.Lock()
	defer statusCheckersMu.Unlock()
	c, ok := statusCheckers[cfg]
	if !ok {
		c = statuslist.NewChecker(cfg.HTTPClient.NewHTTPClient(0), cfg.HTTPClient.AllowsPlaintext())
		statusCheckers[cfg] = c
	}
	return c
}

// checkPresentationStatus looks up the Token Status List entry of every
// presented credential that carries a `status.status_list` claim.
//
// Which outcomes refuse the presentation depends on presentation.status_check:
//
//   - warn: never; a positively not-valid credential is logged.
//   - enforce-revoked (default): only a positive determination (list fetched,
//     typ/sub/exp/signature verified, entry non-zero). If the list cannot be
//     obtained or verified the wallet logs a warning and proceeds, because a
//     list may be reachable by the issuer and verifier but not by the wallet
//     and the verifier owns the authoritative check.
//   - strict: also refuses when the status cannot be determined.
//
// Only JWT-shaped credentials (SD-JWT VC, JWT VC) are examined: the status
// claim is in the issuer-signed JWT and is never selectively disclosable, so
// it is readable without the disclosures. mdoc credentials carry their status
// in the MSO and are not checked here (follow-up).
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

// statusOutcome applies the configured mode to a check result. Log fields are
// the list host and an error class; never the token, the claims or the index.
func (h *OID4VPHandler) statusOutcome(err error, uri string) error {
	if err == nil {
		return nil
	}
	host := listHost(uri)
	if errors.Is(err, statuslist.ErrRevoked) {
		if h.statusMode == config.StatusCheckWarn {
			h.Logger.Warn("presented credential is not valid per its status list; presenting anyway (status_check=warn)",
				zap.String("status_list_host", host))
			return nil
		}
		return fmt.Errorf("credential status (%s): %w", host, err)
	}
	if h.statusMode == config.StatusCheckStrict {
		return fmt.Errorf("credential status (%s) could not be determined: %w", host, err)
	}
	h.Logger.Warn("credential status could not be determined; presenting, the verifier is responsible for the status check",
		zap.String("status_list_host", host),
		zap.String("status_check", string(h.statusMode)),
		zap.Error(err))
	return nil
}

func listHost(uri string) string {
	if u, err := url.Parse(uri); err == nil && u.Host != "" {
		return u.Host
	}
	return "unknown"
}

func (h *OID4VPHandler) checkTokenStatus(ctx context.Context, token string) error {
	issuerJWT, _, _ := strings.Cut(strings.TrimSpace(token), "~")
	parts := strings.Split(issuerJWT, ".")
	if len(parts) != 3 {
		// mdoc (base64url CBOR DeviceResponse): the status is in the MSO.
		h.Logger.Debug("presented credential is not JWT-shaped (e.g. mdoc); status not checked")
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
		return h.statusOutcome(fmt.Errorf("credential status claim: %w", err), "")
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
	return h.statusOutcome(h.statusChecker.Check(ctx, ref, signer), ref.URI)
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
