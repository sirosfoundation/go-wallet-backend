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
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/statuslist"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

var (
	statusCheckersMu sync.Mutex
	statusCheckers   = map[statusCheckerKey]*statuslist.Checker{}
)

type statusCheckerKey struct {
	cfg *config.Config
	svc *TrustService
}

// statusSignerTrust adapts the go-trust backed TrustService to
// statuslist.SignerTrust. The call is EvaluateStatusListSigner: action.name
// "status-list-signer" first; a negative there is final, and only an error
// falls back (when presentation.status_list_signer_fallback is on) to the
// credential-issuer role; resource type x5c or jwk, issuer PDP
// endpoint. The go-trust deployment must define a policy named
// status-list-signer (else go-trust applies its default policy; see
// docs/adr/012). The tenant travels in ctx (trust.ContextWithTenant, set by
// Execute) and is applied by the PDP client's TenantTransport. "No PDP
// configured" and "evaluation failed" come back from the service as
// untrusted, so they are turned into errors here to keep them apart from a
// genuine negative decision.
func statusSignerTrust(svc *TrustService, fallbackOnError bool) statuslist.SignerTrust {
	if svc == nil {
		return nil
	}
	return func(ctx context.Context, subject string, km *trust.KeyMaterial) (bool, error) {
		info, err := svc.EvaluateStatusListSigner(ctx, subject, "", km, fallbackOnError)
		if err != nil {
			return false, err
		}
		if info.Trusted {
			return true, nil
		}
		if info.Framework == trust.FrameworkNone {
			return false, errors.New("no trust PDP configured")
		}
		if info.EvaluationFailed {
			return false, errors.New("trust evaluation failed")
		}
		return false, nil
	}
}

// sharedStatusChecker returns the process-wide Checker for cfg. Handlers are
// built per flow, so a Checker made there would drop its list cache after
// every presentation; one per config lets the token's ttl deduplicate fetches
// across presentations. The Checker is safe for concurrent use.
func sharedStatusChecker(cfg *config.Config, svc *TrustService) *statuslist.Checker {
	statusCheckersMu.Lock()
	defer statusCheckersMu.Unlock()
	k := statusCheckerKey{cfg, svc}
	c, ok := statusCheckers[k]
	if !ok {
		c = statuslist.NewChecker(cfg.HTTPClient.NewHTTPClient(0), cfg.HTTPClient.AllowsPlaintext(), statusSignerTrust(svc, cfg.Presentation.StatusListSignerFallback)).WithMinEntries(cfg.Presentation.StatusListMinEntries).WithMaxConcurrentLoads(cfg.Presentation.StatusListMaxConcurrentLoads)
		statusCheckers[k] = c
	}
	return c
}

// checkPresentationStatus looks up the Token Status List entry of every
// presented credential that carries a `status.status_list` claim.
//
// Which outcomes refuse the presentation depends on presentation.status_check:
//
//   - warn (default): never; every problem, including a positively revoked
//     credential ("credential status revoked"), is logged.
//   - enforce-revoked: only a positive determination (list fetched,
//     typ/sub/exp/signature verified, entry non-zero). If the list cannot be
//     obtained or verified the wallet logs a warning and proceeds, because a
//     list may be reachable by the issuer and verifier but not by the wallet
//     and the verifier owns the authoritative check.
//   - strict: also refuses when the status cannot be determined.
//
// Only JWT-shaped credentials (SD-JWT VC, JWT VC) are examined; a JWT VP is
// unwrapped and each credential JWT in vp.verifiableCredential is checked: the status
// claim is in the issuer-signed JWT and is never selectively disclosable, so
// it is readable without the disclosures. mdoc credentials carry their status
// in the MSO and are not checked here (follow-up).
func (h *OID4VPHandler) checkPresentationStatus(ctx context.Context, vpToken string) error {
	if h.statusChecker == nil {
		return nil
	}
	b := h.newStatusBudget()
	ts := presentedTokens(vpToken)
	// Every readable member is checked before a strict refusal for the
	// malformed ones, so a revoked credential is reported as revoked.
	for _, tok := range ts.tokens {
		if err := h.checkTokenStatus(ctx, tok, b); err != nil {
			return err
		}
	}
	if err := h.malformedOutcome(ts.malformed); err != nil {
		return err
	}
	if b.skipped > 0 {
		h.Logger.Warn("status check budget exhausted; remaining status checks skipped",
			zap.Int("skipped", b.skipped),
			zap.Duration("budget", b.total),
			zap.String("status_check", string(h.statusMode.Effective())))
	}
	return nil
}

// defaultStatusCheckBudget is the total status-check time per presentation
// when presentation.status_check_budget_seconds is 0.
const defaultStatusCheckBudget = 30 * time.Second

// errStatusBudgetExhausted marks a check that was skipped or cut off because
// the per-presentation status-check budget ran out.
var errStatusBudgetExhausted = errors.New("status check budget exhausted")

// statusBudget is the running time budget of one presentation's checks.
type statusBudget struct {
	now     func() time.Time
	start   time.Time
	total   time.Duration
	skipped int
}

func (h *OID4VPHandler) newStatusBudget() *statusBudget {
	total := h.statusBudget
	if total <= 0 {
		total = defaultStatusCheckBudget
	}
	now := h.statusNow
	if now == nil {
		now = time.Now
	}
	return &statusBudget{now: now, start: now(), total: total}
}

// remaining is the budget left; <= 0 means exhausted.
func (b *statusBudget) remaining() time.Duration {
	return b.total - b.now().Sub(b.start)
}

// errStatusUndetermined is the redacted class error returned in strict mode
// for a status that could not be determined for any other reason.
var errStatusUndetermined = errors.New("status list unverifiable")

// statusOutcome applies the configured mode to a check result. Log fields are
// the list host and an error class; never the token, the claims or the index.
func (h *OID4VPHandler) statusOutcome(err error, uri string) error {
	if err == nil {
		return nil
	}
	host := listHost(uri)
	mode := h.statusMode.Effective()
	if errors.Is(err, statuslist.ErrRevoked) {
		// Stable, greppable message; no token contents, index or holder data.
		refused := mode != config.StatusCheckWarn
		h.Logger.Warn("credential status revoked",
			zap.String("status_list_host", host),
			zap.String("status_check", string(mode)),
			zap.Bool("presentation_refused", refused))
		if !refused {
			return nil
		}
		// Wrap the sentinel, not the detailed error (redaction).
		return fmt.Errorf("credential status (%s): %w", host, statuslist.ErrRevoked)
	}
	msg := "credential status could not be determined; the verifier is responsible for the status check"
	reason := "list_unverifiable"
	class := errStatusUndetermined
	switch {
	case errors.Is(err, statuslist.ErrSignerUntrusted):
		// A negative trust decision, not an error: its own greppable event.
		msg = "credential status list signer not trusted; list ignored"
		reason = "signer_untrusted"
		class = statuslist.ErrSignerUntrusted
	case errors.Is(err, statuslist.ErrNoSignerKey):
		reason = "no_signer_key"
		class = statuslist.ErrNoSignerKey
	case errors.Is(err, errStatusBudgetExhausted):
		reason = "budget_exhausted"
		class = errStatusBudgetExhausted
	case errors.Is(err, statuslist.ErrTrustUnavailable):
		reason = "trust_unavailable"
		class = statuslist.ErrTrustUnavailable
	}
	// The raw error is deliberately not logged or returned: it can carry the
	// list URL, claim values or parser detail. Host and class only.
	h.Logger.Warn(msg,
		zap.String("status_list_host", host),
		zap.String("status_check", string(mode)),
		zap.String("reason", reason))
	if mode == config.StatusCheckStrict {
		return fmt.Errorf("credential status (%s) could not be determined (%s): %w", host, reason, class)
	}
	return nil
}

func listHost(uri string) string {
	if u, err := url.Parse(uri); err == nil && u.Host != "" {
		return u.Host
	}
	return "unknown"
}

func (h *OID4VPHandler) checkTokenStatus(ctx context.Context, token string, b *statusBudget) error {
	return h.checkTokenStatusDepth(ctx, token, b, 0)
}

// maxVPNesting is how deep embedded credentials are followed: the presented
// token may be a JWT VP (depth 0) whose vp.verifiableCredential entries are
// the credentials (depth 1). A credential is not itself unwrapped again.
const maxVPNesting = 1

// embeddedCredentials returns the credential JWTs a JWT VP carries in
// vp.verifiableCredential (a string or an array). Every array member is
// examined individually; objects (Data Integrity credentials) are skipped and
// members of any other type are counted as malformed.
func embeddedCredentials(claims map[string]any) tokenSet {
	var ts tokenSet
	vp, ok := claims["vp"].(map[string]any)
	if !ok {
		return ts
	}
	switch vc := vp["verifiableCredential"].(type) {
	case nil:
	case string:
		ts.tokens = append(ts.tokens, vc)
	case map[string]any:
	case []any:
		for _, e := range vc {
			switch v := e.(type) {
			case string:
				ts.tokens = append(ts.tokens, v)
			case map[string]any:
			default:
				ts.malformed++
			}
		}
	default:
		ts.malformed++
	}
	return ts
}

// malformedOutcome applies the mode to token-container members that could not
// be read: strict refuses; the other modes log a redacted warning and carry on
// with every other member.
func (h *OID4VPHandler) malformedOutcome(n int) error {
	if n == 0 {
		return nil
	}
	mode := h.statusMode.Effective()
	h.Logger.Warn("presented token collection has malformed members; they were skipped",
		zap.Int("malformed", n),
		zap.String("status_check", string(mode)))
	if mode == config.StatusCheckStrict {
		return fmt.Errorf("credential status could not be determined (malformed presentation): %w", errStatusUndetermined)
	}
	return nil
}

func (h *OID4VPHandler) checkTokenStatusDepth(ctx context.Context, token string, b *statusBudget, depth int) error {
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
	// A jwt_vc / jwt_vc_json presentation is a JWT VP: the status claims live
	// in the credential JWTs it embeds, not in its own payload. Every embedded
	// credential is checked, under the same shared budget.
	if depth < maxVPNesting {
		emb := embeddedCredentials(claims)
		for _, vc := range emb.tokens {
			if err := h.checkTokenStatusDepth(ctx, vc, b, depth+1); err != nil {
				return err
			}
		}
		if err := h.malformedOutcome(emb.malformed); err != nil {
			return err
		}
	}
	ref, present, err := statuslist.ReferenceFromCredentialClaims(claims)
	if !present {
		return nil
	}
	if err != nil {
		return h.statusOutcome(fmt.Errorf("credential status claim: %w", err), "")
	}

	// The lookup runs under what is left of the presentation's budget so that
	// unreachable lists cannot consume the flow deadline. An exhausted budget
	// skips the check; in strict mode that refuses, otherwise it proceeds.
	rem := b.remaining()
	if rem <= 0 {
		b.skipped++
		return h.statusOutcome(errStatusBudgetExhausted, ref.URI)
	}
	cctx, cancel := context.WithTimeout(ctx, rem)
	defer cancel()
	err = h.statusChecker.Check(cctx, ref)
	if err != nil && ctx.Err() == nil && cctx.Err() != nil {
		// Only the budget expired, not the flow: the check was cut off.
		b.skipped++
		err = errStatusBudgetExhausted
	}
	return h.statusOutcome(err, ref.URI)
}

// tokenSet is the result of flattening client-supplied token containers.
// Collections are decoded element by element so one odd member can never hide
// the others: tokens holds every string member, malformed counts members that
// are neither strings nor objects (objects, e.g. Data Integrity credentials,
// are legitimately not JWTs and are skipped silently).
type tokenSet struct {
	tokens    []string
	malformed int
}

// addValue classifies one JSON value into the set.
func (t *tokenSet) addValue(raw json.RawMessage) {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	switch {
	case len(raw) == 0:
		t.malformed++
	case raw[0] == '"':
		var s string
		if json.Unmarshal(raw, &s) != nil {
			t.malformed++
			return
		}
		t.tokens = append(t.tokens, s)
	case raw[0] == '{':
		// Not a JWT; nothing to check.
	default:
		t.malformed++
	}
}

// addStringsOrOne adds a string, or every member of an array.
func (t *tokenSet) addStringsOrOne(raw json.RawMessage) {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) > 0 && raw[0] == '[' {
		elems, ok := jsonArrayElements(raw)
		if !ok {
			t.malformed++
			return
		}
		for _, e := range elems {
			t.addValue(e)
		}
		return
	}
	t.addValue(raw)
}

// jsonArrayElements splits a JSON array into its raw elements.
func jsonArrayElements(raw json.RawMessage) ([]json.RawMessage, bool) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, false
	}
	var out []json.RawMessage
	for dec.More() {
		var e json.RawMessage
		if dec.Decode(&e) != nil {
			return nil, false
		}
		out = append(out, e)
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
		return nil, false
	}
	return out, true
}

// jsonObjectValues returns every member value of a JSON object in document
// order, keeping duplicate keys (a map would keep only the last one and let
// a repeated key hide a revoked credential).
func jsonObjectValues(raw string) ([]json.RawMessage, bool) {
	dec := json.NewDecoder(strings.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var out []json.RawMessage
	for dec.More() {
		if _, err := dec.Token(); err != nil { // key
			return nil, false
		}
		var v json.RawMessage
		if dec.Decode(&v) != nil {
			return nil, false
		}
		out = append(out, v)
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	return out, true
}

// presentedTokens flattens a vp_token into the individual presentations: a
// DCQL JSON object (query id -> string or array of strings), a JSON array, or
// one/newline-separated raw tokens. Containers are walked member by member.
func presentedTokens(vpToken string) tokenSet {
	var ts tokenSet
	vpToken = strings.TrimSpace(vpToken)
	if vpToken == "" {
		return ts
	}
	switch vpToken[0] {
	case '{':
		vals, ok := jsonObjectValues(vpToken)
		if !ok {
			ts.malformed++
			return ts
		}
		for _, raw := range vals {
			ts.addStringsOrOne(raw)
		}
		return ts
	case '[':
		ts.addStringsOrOne(json.RawMessage(vpToken))
		return ts
	}
	ts.tokens = strings.Split(vpToken, "\n")
	return ts
}

func decodeJWTSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return errors.New("bad base64url")
	}
	return json.Unmarshal(b, v)
}
