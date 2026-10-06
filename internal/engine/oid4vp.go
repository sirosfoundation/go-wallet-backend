package engine

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/go-jose/go-jose/v4"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// OID4VPHandler handles OpenID4VP credential presentation flows
type OID4VPHandler struct {
	BaseHandler
	httpClient *http.Client
}

// NewOID4VPHandler creates a new OID4VP flow handler
func NewOID4VPHandler(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
	return &OID4VPHandler{
		BaseHandler: BaseHandler{
			Flow:       flow,
			Config:     cfg,
			Logger:     logger,
			TrustSvc:   trustSvc,
			Registry:   registry,
			Verifiers:  verifiers,
			TrustCache: trustCache,
		},
		httpClient: cfg.HTTPClient.NewHTTPClient(0),
	}, nil
}

// OID4VP data structures

// ClientIDScheme constants for OID4VP client identification
const (
	ClientIDSchemeRedirectURI = "redirect_uri"
	ClientIDSchemeDID         = "did"
	// ClientIDSchemeDecentralizedIdentifier is OpenID4VP 1.0's name for the
	// scheme the drafts called "did". Verifiers built against the final
	// specification send this one, and it means exactly the same thing, so
	// everything below treats the two as one scheme.
	ClientIDSchemeDecentralizedIdentifier = "decentralized_identifier"
	ClientIDSchemeX509SANDNS              = "x509_san_dns"
	ClientIDSchemeX509SANURI              = "x509_san_uri"
	ClientIDSchemeX509Hash                = "x509_hash"
	ClientIDSchemeVerifierAttestation     = "verifier_attestation"
	// clientIDSchemeVerifierAttestationPrefix is ClientIDSchemeVerifierAttestation
	// spelled as the client_id prefix it actually appears as on the wire
	// ("verifier_attestation:<sub>"), per OID4VP §5.9.3.4.
	clientIDSchemeVerifierAttestationPrefix = ClientIDSchemeVerifierAttestation + ":"
)

// Response mode constants
const (
	ResponseModeDirectPost    = "direct_post"
	ResponseModeDirectPostJWT = "direct_post.jwt"
	// Modes that hand the result back through the user agent rather than a
	// POST from the wallet (previously spelled inline in submitResponse).
	ResponseModeQuery    = "query"
	ResponseModeFragment = "fragment"
)

// HTTP header/content type constants
const (
	hdrContentType     = "Content-Type"
	mimeFormURLEncoded = "application/x-www-form-urlencoded"
)

// TransactionData represents a single transaction data object from
// the verifier's OID4VP authorization request (TS12/SCA per OID4VP draft §7.4).
type TransactionData struct {
	Type string `json:"type"`
	// Raw is the entry exactly as the verifier sent it: the base64url string
	// from the request's transaction_data array. It is the only valid input to
	// the transaction_data_hashes a presentation carries (OID4VP 1.0
	// Appendix B hashes the string as received, without decoding it first), and
	// the only thing a client may trust: the other members are what the engine
	// decoded from it. Always set by decodeTransactionData from the received
	// string, never from the decoded JSON.
	Raw string `json:"raw,omitempty"`
	// Payload is the decoded entry's `payload` object (EC TS12 Section 4.2), for
	// the client's validation and display. Never hash it.
	Payload       json.RawMessage        `json:"payload,omitempty"`
	Params        map[string]interface{} `json:"params,omitempty"`
	CredentialIDs []string               `json:"credential_ids,omitempty"`
	HashAlgorithm string                 `json:"hash_alg,omitempty"`
	// TransactionDataHashesAlg is the verifier's list of acceptable hash
	// algorithms for this entry (OID4VP 1.0 Appendix B: an array in the
	// request; the KB-JWT carries the single chosen one as a string).
	TransactionDataHashesAlg HashAlgList `json:"transaction_data_hashes_alg,omitempty"`
}

// HashAlgList is the request-side `transaction_data_hashes_alg` member: a
// non-empty array of hash algorithm names. It also accepts a bare string,
// which some verifiers send for a single algorithm; typing the member as a
// string made every spec-conformant array fail to unmarshal, so a verifier
// that followed the specification had its whole request rejected as invalid
// JSON.
type HashAlgList []string

// UnmarshalJSON accepts either a JSON string or an array of strings.
//
// The list must be non-empty and hold non-empty names: OID4VP defines the
// member as a non-empty array of algorithm identifiers, one of which the
// wallet must use, so an empty list leaves it nothing valid to choose. Anything
// else is rejected as invalid transaction_data, and `null` is not the same as
// leaving the member out.
func (l *HashAlgList) UnmarshalJSON(b []byte) error {
	errInvalid := errors.New("transaction_data_hashes_alg must be a non-empty string or a non-empty array of non-empty strings")
	var algs []string
	var one string
	if err := json.Unmarshal(b, &one); err == nil && string(b) != "null" {
		algs = []string{one}
	} else if err := json.Unmarshal(b, &algs); err != nil || algs == nil {
		return errInvalid
	}
	if len(algs) == 0 {
		return errInvalid
	}
	for _, a := range algs {
		if a == "" {
			return errInvalid
		}
	}
	*l = HashAlgList(algs)
	return nil
}

// AuthorizationRequest represents an OpenID4VP authorization request
type AuthorizationRequest struct {
	ResponseType      string          `json:"response_type"`
	ClientID          string          `json:"client_id"`
	ClientIDScheme    string          `json:"client_id_scheme,omitempty"`
	ResponseMode      string          `json:"response_mode,omitempty"`
	ResponseURI       string          `json:"response_uri,omitempty"`
	RedirectURI       string          `json:"redirect_uri,omitempty"`
	Nonce             string          `json:"nonce,omitempty"`
	State             string          `json:"state,omitempty"`
	Scope             string          `json:"scope,omitempty"`
	DCQLQuery         json.RawMessage `json:"dcql_query,omitempty"`
	ClientMetadata    *ClientMetadata `json:"client_metadata,omitempty"`
	ClientMetadataURI string          `json:"client_metadata_uri,omitempty"`
	// TransactionData carries TS12 transaction data from the verifier (OID4VP draft §7.4).
	// Per spec, this is an array of base64url-encoded JSON strings in the request.
	TransactionDataRaw json.RawMessage `json:"transaction_data,omitempty"`
	// TransactionData holds the decoded transaction data objects (populated during validation).
	TransactionData []TransactionData `json:"-"`
	// RequestJWT stores the raw request JWT (if the request was JWT-secured).
	// Used to extract x5c/jwk key material from the JWT header for trust evaluation.
	RequestJWT string `json:"-"`
	// VerifierSessionID is the verifier-assigned "sessionId" query parameter
	// carried on the request_uri we fetched the signed request object from
	// (e.g. ".../openid4vpRequest?sessionId=X"). A real ZK/PPID pseudonym's
	// verifier_context binds to THIS specific presentation session (per
	// zk-cred-longfellow's V8/PPID reference implementation), not to the
	// verifier's static identity - confirmed 2026-08-17 via direct report
	// from that implementation's author. Empty for non-ZK presentations or
	// request URIs that never carried a sessionId to begin with.
	VerifierSessionID string `json:"-"`
}

// ClientMetadata represents verifier/client metadata
type ClientMetadata struct {
	ClientName    string                 `json:"client_name,omitempty"`
	LogoURI       string                 `json:"logo_uri,omitempty"`
	ClientPurpose string                 `json:"client_purpose,omitempty"`
	VPFormats     map[string]interface{} `json:"vp_formats,omitempty"`
	JWKS          json.RawMessage        `json:"jwks,omitempty"`
	JWKsURI       string                 `json:"jwks_uri,omitempty"`
	X5C           []string               `json:"x5c,omitempty"`
	// JARM (JWT Secured Authorization Response Mode)
	AuthorizationEncryptedResponseAlg string `json:"authorization_encrypted_response_alg,omitempty"`
	AuthorizationEncryptedResponseEnc string `json:"authorization_encrypted_response_enc,omitempty"`
	AuthorizationSignedResponseAlg    string `json:"authorization_signed_response_alg,omitempty"`
}

// CredentialsMatchedPayload is the payload for credentials_matched action
type CredentialsMatchedPayload struct {
	Matches       []CredentialMatch `json:"matches"`
	NoMatchReason string            `json:"no_match_reason,omitempty"`
}

// ConsentPayload is the payload for consent action
type ConsentPayload struct {
	SelectedCredentials []ConsentSelection `json:"selected_credentials"`
}

// Execute runs the OID4VP flow
func (h *OID4VPHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	ctx, cancel := context.WithCancel(ctx)
	h.cancel = cancel
	defer cancel()

	// Add tenant context for X-Tenant-ID propagation
	if h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		ctx = ContextWithTenant(ctx, h.Flow.Session.TenantID)
	}

	// Step 1: Parse authorization request
	authReq, err := h.parseRequest(ctx, msg)
	if err != nil {
		h.Logger.Debug("failed to parse request", zap.Error(err))
		var fetchErr *requestFetchError
		if errors.As(err, &fetchErr) {
			_ = h.Error(StepParsingRequest, ErrCodeRequestFetchError, ErrCodeRequestFetchError.UserFacingMessage())
		} else {
			_ = h.Error(StepParsingRequest, ErrCodeRequestParseError, ErrCodeRequestParseError.UserFacingMessage())
		}
		return err
	}

	// Infer client_id_scheme if not explicitly provided
	if authReq.ClientIDScheme == "" {
		authReq.ClientIDScheme = inferClientIDScheme(authReq.ClientID)
	}

	// OID4VP §5 / §6: Validate request parameters before proceeding
	// A transaction_data problem does not end the flow yet. Telling the
	// verifier means contacting the response_uri the request itself supplied,
	// and until verifier trust has been established that is an arbitrary,
	// attacker-chosen URL: an unauthenticated request could aim the backend at
	// an internal service just by carrying transaction_data. The request is
	// refused below, after trust evaluation, and the verifier is told only then.
	var pendingTransactionDataErr *transactionDataError
	var validationErr error
	if err := h.validateAuthorizationRequest(authReq, msg); err != nil {
		h.Logger.Debug("authorization request validation failed", zap.Error(err))
		if !errors.As(err, &pendingTransactionDataErr) {
			_ = h.Error(StepParsingRequest, ErrCodeInvalidMessage, ErrCodeInvalidMessage.UserFacingMessage())
			return err
		}
		validationErr = err
	}

	h.SetData("auth_request", authReq)

	// Step 2: Evaluate verifier trust
	verifier, err := h.evaluateVerifierTrust(ctx, authReq)
	if err != nil {
		h.Logger.Debug("verifier trust evaluation failed", zap.Error(err))
		_ = h.Error(StepEvaluatingVerifierTrust, ErrCodeUntrustedVerifier, ErrCodeUntrustedVerifier.UserFacingMessage())
		return err
	}
	if pendingTransactionDataErr != nil {
		// The verifier is trusted now, so it may be told.
		h.failTransactionData(ctx, authReq, pendingTransactionDataErr)
		return validationErr
	}

	// Step 3: Send credential_selection with dcql_query + verifier; wait for consent or decline
	selectedCredentials, err := h.requestCredentialSelection(ctx, authReq, verifier)
	if err != nil {
		return err
	}

	// Step 4: Request VP signing from client (use configured ClientID for audience if set)
	vpToken, err := h.requestVPSignature(ctx, authReq, selectedCredentials, verifier.ClientID)
	if err != nil {
		h.Logger.Debug("VP signature failed", zap.Error(err))
		_ = h.Error(StepSubmittingResponse, ErrCodeSignError, ErrCodeSignError.UserFacingMessage())
		return err
	}

	// Step 5: Submit VP response to verifier
	redirectURI, err := h.submitResponse(ctx, authReq, vpToken)
	if err != nil {
		h.Logger.Debug("VP submission failed", zap.Error(err))
		_ = h.Error(StepSubmittingResponse, ErrCodePresentationError, ErrCodePresentationError.UserFacingMessage())
		return err
	}

	// Step 6: Complete
	return h.Complete(nil, redirectURI)
}

func (h *OID4VPHandler) parseRequest(ctx context.Context, msg *FlowStartMessage) (*AuthorizationRequest, error) {
	_ = h.ProgressMessage(StepParsingRequest, "Parsing authorization request")

	h.Logger.Debug("parsing authorization request",
		zap.String("request_uri", redactURIForLogging(msg.RequestURI)),
		zap.String("request_uri_ref", redactURIForLogging(msg.RequestURIRef)))

	var authReq AuthorizationRequest

	if msg.RequestURI != "" {
		// Parse from openid4vp://, haip://, haip-vp://, mdoc-openid4vp://, or
		// a direct https:// URL. HAIP (OpenID4VC High Assurance
		// Interoperability Profile) and ISO 18013-7 Annex B's mdoc-specific
		// scheme both use the same openid4vp://?client_id=...&request_uri=...
		// wire shape as plain OID4VP, just under their own scheme(s) - treat
		// them all identically. "haip://" was HAIP's early-draft (1-3)
		// scheme; HAIP 1.0 final replaced it with "haip-vp://" (presentation)
		// - real verifiers (e.g. Multipaz) already emit the new one, and
		// omitting it here fell through to the raw-https-URL branch below,
		// which treats the whole thing as either an inline query string or a
		// fetchable reference URL - neither is right for a haip-vp:// link
		// carrying its own request_uri query param, so it never dereferenced
		// that reference and failed with a generic "invalid message format".
		requestStr := msg.RequestURI
		if strings.HasPrefix(requestStr, "openid4vp://") || strings.HasPrefix(requestStr, "haip://") || strings.HasPrefix(requestStr, "haip-vp://") || strings.HasPrefix(requestStr, "mdoc-openid4vp://") {
			u, err := url.Parse(requestStr)
			if err != nil {
				return nil, fmt.Errorf("invalid request URL: %w", err)
			}
			// Check for request_uri parameter
			requestURIRef := u.Query().Get("request_uri")
			if requestURIRef != "" {
				return h.fetchRequestFromURI(ctx, requestURIRef)
			}
			// Parse inline parameters
			return h.parseRequestFromURL(u)
		}
		// requestStr may be a raw query string with no scheme at all (e.g.
		// "client_id=foo&nonce=bar", as validateResponseURIOrigin already
		// anticipates) rather than a URL. Anything that doesn't itself start
		// with a URL scheme is a raw query string - parse it as inline
		// params directly, the same as before this fix. This check must
		// come before ever calling url.Parse on requestStr: a raw query
		// string can contain a "://" inside a parameter value (e.g.
		// client_id=https://verifier...), which url.Parse rejects with
		// "first path segment ... cannot contain colon" since the string
		// itself has no leading scheme.
		if !hasURLScheme(requestStr) {
			return h.parseRequestFromURL(&url.URL{RawQuery: requestStr})
		}
		// Direct https:// URL: either a by-value request with inline query
		// parameters, or a bare reference URL (no query at all) that must be
		// fetched to obtain the actual request object - e.g. a QR/link that
		// itself IS the request_uri, with no openid4vp://... wrapper. A
		// query-less URL can't carry inline params, so treating requestStr as
		// a literal RawQuery in that case silently yields every field empty
		// (this is exactly what broke: a bare https://.../haip-vp link with
		// no "=" characters parsed to nonce="" and failed on "missing
		// required 'nonce' parameter", never even attempting to fetch it).
		u, err := url.Parse(requestStr)
		if err != nil {
			return nil, fmt.Errorf("invalid request URL: %w", err)
		}
		if u.RawQuery == "" {
			return h.fetchRequestFromURI(ctx, requestStr)
		}
		return h.parseRequestFromURL(u)
	} else if msg.RequestURIRef != "" {
		return h.fetchRequestFromURI(ctx, msg.RequestURIRef)
	}

	return &authReq, errors.New("no request provided")
}

// hasURLScheme reports whether s begins with a URL scheme ("scheme://...",
// per RFC 3986: a letter followed by letters/digits/+/-/. up to "://").
// Used to tell an actual URL apart from a raw query string that happens to
// contain "://" inside a parameter value.
func hasURLScheme(s string) bool {
	idx := strings.Index(s, "://")
	if idx <= 0 {
		return false
	}
	scheme := s[:idx]
	for i := 0; i < len(scheme); i++ {
		c := scheme[i]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if i == 0 {
			if !isLetter {
				return false
			}
			continue
		}
		isDigit := c >= '0' && c <= '9'
		if !isLetter && !isDigit && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// redactURIForLogging returns a form of uri safe to log: scheme and host
// only. The query string (and, for a bare raw-query value, the entire
// string) may carry sensitive material - nonces, reference tokens, embedded
// JWTs - so neither is ever included.
func redactURIForLogging(uri string) string {
	if uri == "" {
		return ""
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme == "" {
		return "<non-url>"
	}
	// Host is legitimately empty for some valid, non-sensitive requests -
	// e.g. "haip://?client_id=..." (no callback/authority segment) parses
	// with an empty Host. Requiring a non-empty Host here would misclassify
	// those as "<non-url>" instead of the more informative "haip://".
	return u.Scheme + "://" + u.Host
}

func (h *OID4VPHandler) parseRequestFromURL(u *url.URL) (*AuthorizationRequest, error) {
	q := u.Query()

	authReq := &AuthorizationRequest{
		ResponseType:   q.Get("response_type"),
		ClientID:       q.Get("client_id"),
		ClientIDScheme: q.Get("client_id_scheme"),
		ResponseMode:   q.Get("response_mode"),
		ResponseURI:    q.Get("response_uri"),
		RedirectURI:    q.Get("redirect_uri"),
		Nonce:          q.Get("nonce"),
		State:          q.Get("state"),
		Scope:          q.Get("scope"),
	}

	// Parse dcql_query
	if dcqlStr := q.Get("dcql_query"); dcqlStr != "" {
		if !json.Valid([]byte(dcqlStr)) {
			return nil, fmt.Errorf("invalid dcql_query: not valid JSON")
		}
		authReq.DCQLQuery = json.RawMessage(dcqlStr)
	}

	// Parse transaction_data. By value in a query string it is a JSON array of
	// base64url strings, like dcql_query is JSON. It must be kept even though
	// nothing here interprets it: dropping it made a request that carried a
	// transaction look like one that did not, so it bypassed the checks in
	// validateTransactionData and the client presented without the hashes. The
	// signed-JWT and fetched-object forms already keep it through their
	// `transaction_data` struct tag.
	if tdStr := q.Get("transaction_data"); tdStr != "" {
		if !json.Valid([]byte(tdStr)) {
			return nil, fmt.Errorf("invalid transaction_data: not valid JSON")
		}
		authReq.TransactionDataRaw = json.RawMessage(tdStr)
	}

	// Parse client_metadata if inline
	if cmStr := q.Get("client_metadata"); cmStr != "" {
		var cm ClientMetadata
		if err := json.Unmarshal([]byte(cmStr), &cm); err != nil {
			return nil, fmt.Errorf("invalid client_metadata: %w", err)
		}
		authReq.ClientMetadata = &cm
	}
	authReq.ClientMetadataURI = q.Get("client_metadata_uri")

	// Handle request JWT if present
	if requestJWT := q.Get("request"); requestJWT != "" {
		return h.parseRequestJWT(requestJWT)
	}

	return authReq, nil
}

func (h *OID4VPHandler) parseRequestJWT(jwtStr string) (*AuthorizationRequest, error) {
	// Parse JWT without verification (verification happens during trust evaluation)
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid request JWT format")
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var authReq AuthorizationRequest
	if err := json.Unmarshal(payload, &authReq); err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	// Store the raw JWT so we can extract key material from its header later
	authReq.RequestJWT = jwtStr

	return &authReq, nil
}

// requestFetchError distinguishes a failure to retrieve the request object
// (network error, non-200 status) from a failure to parse it once
// retrieved, so Execute() can report ErrCodeRequestFetchError instead of the
// generic ErrCodeRequestParseError for what's really a connectivity/lookup
// problem against the verifier's request_uri (e.g. an already-expired
// reference), not a malformed request.
type requestFetchError struct{ err error }

func (e *requestFetchError) Error() string { return e.err.Error() }
func (e *requestFetchError) Unwrap() error { return e.err }

func (h *OID4VPHandler) fetchRequestFromURI(ctx context.Context, uri string) (*AuthorizationRequest, error) {
	h.Logger.Debug("fetching authorization request object", zap.String("uri", redactURIForLogging(uri)))

	// The verifier assigns this session id itself (it's the query param on
	// the request_uri it handed us) - extract it up front from the URI
	// string directly, rather than from the fetched request object, since
	// it never appears inside the JWT/JSON body itself.
	var verifierSessionID string
	if parsedURI, err := url.Parse(uri); err == nil {
		verifierSessionID = parsedURI.Query().Get("sessionId")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, &requestFetchError{fmt.Errorf("failed to fetch request: %w", err)}
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		// Only the length is logged, not the body itself: the body comes from
		// a verifier-controlled endpoint and could contain session tokens,
		// diagnostic detail, or embedded JWTs - the same class of concern
		// redactURIForLogging already avoids for request_uri query strings.
		// A bare status code alone can't tell a dead/expired request_uri
		// apart from a wrong path or an unrelated server error, but the
		// content length is enough of a differential signal for that
		// without echoing untrusted content into logs.
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, MaxHTTPResponseBodyBytes))
		h.Logger.Debug("request fetch returned non-200 status",
			zap.Int("status", resp.StatusCode),
			zap.Int64("body_length", n))
		return nil, &requestFetchError{fmt.Errorf("request fetch returned status %d", resp.StatusCode)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxHTTPResponseBodyBytes))
	if err != nil {
		return nil, err
	}

	// Check if response is JWT or JSON
	bodyStr := strings.TrimSpace(string(body))

	// If the response is a JSON-encoded string unquote it
	if strings.HasPrefix(bodyStr, "\"") {
		var unquoted string
		if err := json.Unmarshal([]byte(bodyStr), &unquoted); err == nil {
			bodyStr = unquoted
		}
	}

	var authReq *AuthorizationRequest
	if strings.HasPrefix(bodyStr, "{") || strings.HasPrefix(bodyStr, "[") {
		// A dot count can't reliably distinguish JWT from JSON: a JSON
		// request object can easily contain exactly two '.' characters (for
		// example a response_uri like "https://a.b.c/path"), which would
		// misclassify it as a JWT and fail to parse. JSON always starts with
		// '{' or '[' once whitespace is trimmed, and a JWT never does, so
		// check that instead.
		authReq = &AuthorizationRequest{}
		err = json.Unmarshal([]byte(bodyStr), authReq)
		if err != nil {
			err = fmt.Errorf("failed to parse request: %w", err)
		}
	} else {
		// Likely a JWT
		authReq, err = h.parseRequestJWT(bodyStr)
	}
	if err != nil {
		return nil, err
	}

	authReq.VerifierSessionID = verifierSessionID
	return authReq, nil
}

func (h *OID4VPHandler) evaluateVerifierTrust(ctx context.Context, authReq *AuthorizationRequest) (*VerifierInfo, error) {
	_ = h.ProgressMessage(StepEvaluatingVerifierTrust, "Evaluating verifier trust")

	// Fetch client metadata if needed
	var clientMeta *ClientMetadata
	if authReq.ClientMetadata != nil {
		clientMeta = authReq.ClientMetadata
	} else if authReq.ClientMetadataURI != "" {
		cm, err := h.fetchClientMetadata(ctx, authReq.ClientMetadataURI)
		if err != nil {
			h.Logger.Warn("Failed to fetch client metadata", zap.Error(err))
		} else {
			clientMeta = cm
			// Store fetched metadata on the request so downstream steps
			// (e.g. submitDirectPostJWT) can access JARM parameters.
			authReq.ClientMetadata = cm
		}
	}

	// Build verifier info. Name is always the client_id itself - the
	// identifier the trust decision below is actually made about - never
	// client_metadata.client_name.
	//
	// client_metadata is sent by the verifier itself, before any trust
	// evaluation runs, and go-trust's PDP response has no validated display
	// name of its own to substitute (see EvaluationResult in
	// pkg/trust/service.go: Framework/Reason/Certificates only). Trusting
	// client_name here would mean a PDP-approved cache entry - and every
	// cache hit against it for the rest of the cache TTL - still shows
	// whatever arbitrary string the verifier chose, not something the trust
	// decision actually vouches for. See #398.
	verifier := &VerifierInfo{
		Name:           authReq.ClientID,
		ClientIDScheme: authReq.ClientIDScheme,
		Domain:         extractDomain(authReq.ClientID),
	}

	if clientMeta != nil {
		if clientMeta.LogoURI != "" {
			verifier.Logo = &LogoInfo{URI: clientMeta.LogoURI}
		}
	}

	// Scheme-aware key material extraction and JWT verification. This MUST
	// run before any cache lookup below (see the cache check further down):
	// a cache hit must never let a request bypass signature verification for
	// did:/x509_*/verifier_attestation schemes, and verifiedIdentity - the
	// authenticated identity the cache is keyed by - only exists once this
	// has run.
	var keyMaterial *KeyMaterial
	var requiresResolution bool
	var requestJWT string
	var attestationContext map[string]interface{}
	var verifiedIdentity string
	// cacheable is false whenever a scheme's identity claim (client_id or
	// attestation subject) does not, on its own, bind to one specific key:
	// x509_san_dns's SAN can be presented by any certificate naming that DNS
	// name; this handler never itself checks that an x509_hash client_id
	// equals the presented certificate's actual hash (that binding check
	// belongs to the PDP); and verifier_attestation's "sub" is asserted by
	// an attestation JWT this handler does not itself verify against a
	// trusted issuer. For those schemes cacheable only becomes true once a
	// stable fingerprint of the actual key material is folded into
	// verifiedIdentity (see keyMaterialFingerprint) - if that fingerprint
	// can't be computed, the request is never cached at all rather than
	// falling back to a weaker key a different key's request could collide
	// with.
	cacheable := true

	switch authReq.ClientIDScheme {
	case ClientIDSchemeDID, ClientIDSchemeDecentralizedIdentifier:
		// DID scheme: request MUST be JWT-secured
		// Resolve DID document server-side via go-trust, then verify JWT.
		// Under OpenID4VP 1.0 the client_id carries its scheme as a prefix,
		// so resolution uses the DID itself while trust evaluation keeps the
		// client_id exactly as the verifier sent it.
		did := didFromClientID(authReq.ClientID)
		if !strings.HasPrefix(did, "did:") {
			return nil, fmt.Errorf("client_id_scheme=%s but client_id is not a DID", authReq.ClientIDScheme)
		}
		if authReq.RequestJWT == "" {
			return nil, fmt.Errorf("client_id_scheme=%s requires a signed request JWT", authReq.ClientIDScheme)
		}

		if h.Config.Trust.GetVerifierPDPURL() == "" {
			// No verifier PDP configured at all - the intentional,
			// permissive dev/no-PDP mode. h.TrustSvc.ResolveDID always
			// resolves against GetVerifierPDPURL() itself (an empty
			// trustEndpoint override falls back to exactly this same
			// config value), so calling it here would only ever fail with
			// "no trust evaluator configured for DID resolution" - it can
			// never actually succeed in this mode. Defer DID resolution
			// and request JWT verification to the frontend/SDK entirely
			// instead (mirrors OID4VCIHandler.evaluateTrustViaFrontend,
			// which never attempts server-side resolution for a did:
			// issuer either): keyMaterial stays nil so the frontend knows
			// to resolve it, and this request is never cached - there is
			// no verified identity yet to scope a cache entry to, and
			// evaluateVerifierTrustViaFrontend never writes to the cache
			// regardless.
			requiresResolution = true
			requestJWT = authReq.RequestJWT
			cacheable = false
			break
		}

		// Resolve DID document to get verification method keys
		tenantID := ""
		if h.Flow != nil && h.Flow.Session != nil {
			tenantID = h.Flow.Session.TenantID
		}
		resolvedKeys, err := h.TrustSvc.ResolveDID(
			trust.ContextWithTenant(ctx, tenantID),
			did,
			"", // use default verifier PDP endpoint
		)
		if err != nil {
			return nil, fmt.Errorf("DID resolution failed for %s: %w", did, err)
		}
		if len(resolvedKeys) == 0 {
			return nil, fmt.Errorf("DID %s resolved but contains no verification method keys", did)
		}

		// Verify JWT signature against resolved DID keys
		matchedJWK, err := trust.VerifyJWTWithResolvedKeys(authReq.RequestJWT, resolvedKeys)
		if err != nil {
			return nil, fmt.Errorf("DID request JWT verification failed: %w", err)
		}

		h.Logger.Debug("DID request JWT verified",
			zap.String("did", did),
			zap.Any("matched_kid", matchedJWK["kid"]))

		keyMaterial = &KeyMaterial{
			Type: "jwk",
			JWK:  matchedJWK,
		}
		// Cache identity is the resolved, JWT-verified DID itself - but a
		// DID document can list multiple active verification methods (key
		// rotation overlap), and the PDP evaluates trust against this
		// SPECIFIC matched key, not the DID in the abstract. Fold in a
		// fingerprint of that key so a request verified against a
		// different resolved key for the same DID can never reuse this
		// verdict.
		if fp := keyMaterialFingerprint(keyMaterial); fp != "" {
			verifiedIdentity = "did:" + did + ":" + fp
		} else {
			cacheable = false
		}
		// This handler has already resolved the DID and verified the
		// request JWT itself (above, since a verifier PDP is configured),
		// so evaluateVerifierTrustViaPDP never needs requiresResolution/
		// requestJWT - only the no-PDP branch above sets them, for
		// evaluateVerifierTrustViaFrontend's benefit.

	case ClientIDSchemeX509SANDNS:
		// X.509 scheme: request MUST be JWT-secured; verify signature with x5c
		// NOTE: client_id vs SAN DNS validation is performed by go-trust PDP via /v1/evaluate
		if authReq.RequestJWT == "" {
			return nil, errors.New("x509_san_dns scheme requires a signed request JWT")
		}
		km, verifyErr := trust.VerifyJWTWithEmbeddedKey(authReq.RequestJWT)
		if verifyErr != nil {
			return nil, fmt.Errorf("x509_san_dns JWT verification failed: %w", verifyErr)
		}
		if km.Type != "x5c" {
			return nil, errors.New("x509_san_dns scheme requires x5c in JWT header")
		}
		keyMaterial = km
		// The request JWT's signature proves possession of the embedded
		// x5c's private key, but a SAN DNS name is not unique to one
		// certificate - a different cert naming the same domain would claim
		// the same client_id. Fold in the leaf certificate's own fingerprint
		// so the cache is scoped to this specific certificate, not just the
		// domain it claims.
		if fp := keyMaterialFingerprint(keyMaterial); fp != "" {
			verifiedIdentity = pdpSubjectID(authReq) + ":" + fp
		} else {
			cacheable = false
		}

	case ClientIDSchemeX509SANURI:
		// X.509 scheme: request MUST be JWT-secured; verify signature with
		// x5c. Same shape as x509_san_dns immediately above, just for a SAN
		// URI entry instead of a SAN DNS name.
		// NOTE: client_id vs SAN URI validation is performed by go-trust PDP via /v1/evaluate
		if authReq.RequestJWT == "" {
			return nil, errors.New("x509_san_uri scheme requires a signed request JWT")
		}
		km, verifyErr := trust.VerifyJWTWithEmbeddedKey(authReq.RequestJWT)
		if verifyErr != nil {
			return nil, fmt.Errorf("x509_san_uri JWT verification failed: %w", verifyErr)
		}
		if km.Type != "x5c" {
			return nil, errors.New("x509_san_uri scheme requires x5c in JWT header")
		}
		keyMaterial = km
		// The request JWT's signature proves possession of the embedded
		// x5c's private key, but a SAN URI entry is not unique to one
		// certificate - a different cert naming the same URI would claim
		// the same client_id. Fold in the leaf certificate's own fingerprint
		// so the cache is scoped to this specific certificate, not just the
		// URI it claims.
		if fp := keyMaterialFingerprint(keyMaterial); fp != "" {
			verifiedIdentity = pdpSubjectID(authReq) + ":" + fp
		} else {
			cacheable = false
		}

	case ClientIDSchemeX509Hash:
		// X.509 hash scheme: client_id is the leaf cert's own digest rather
		// than a SAN entry, so (unlike x509_san_dns) there's no domain/origin
		// to check here at all - go-trust's PDP already has the client_id-vs-
		// cert-hash comparison (added alongside its x509_hash skip-chain-
		// validation support), so this case only needs to verify the request
		// JWT's signature against its embedded x5c, same as x509_san_dns.
		if authReq.RequestJWT == "" {
			return nil, errors.New("x509_hash scheme requires a signed request JWT")
		}
		km, verifyErr := trust.VerifyJWTWithEmbeddedKey(authReq.RequestJWT)
		if verifyErr != nil {
			return nil, fmt.Errorf("x509_hash JWT verification failed: %w", verifyErr)
		}
		if km.Type != "x5c" {
			return nil, errors.New("x509_hash scheme requires x5c in JWT header")
		}
		keyMaterial = km
		// client_id is SUPPOSED to be the certificate's own hash under this
		// scheme, but this handler never itself checks that binding - only
		// go-trust's PDP does. Without a fingerprint here, a request
		// presenting a different certificate but claiming the same (stale,
		// previously-trusted) client_id hash would reuse a cached verdict
		// the PDP never evaluated for that certificate.
		if fp := keyMaterialFingerprint(keyMaterial); fp != "" {
			verifiedIdentity = pdpSubjectID(authReq) + ":" + fp
		} else {
			cacheable = false
		}

	case ClientIDSchemeVerifierAttestation:
		// Verifier attestation scheme (OID4VP §5.9.3.4 / §12):
		// 1. Extract attestation JWT from "jwt" header parameter
		// 2. Extract verifier's cnf key from attestation
		// 3. Verify request JWT signature against cnf key
		// 4. Send attestation issuer's key material for trust evaluation
		if authReq.RequestJWT == "" {
			return nil, errors.New("verifier_attestation scheme requires a signed request JWT")
		}

		attestation, err := trust.ExtractVerifierAttestation(authReq.RequestJWT)
		if err != nil {
			return nil, fmt.Errorf("verifier attestation extraction failed: %w", err)
		}
		if attestation == nil {
			return nil, errors.New("verifier_attestation scheme requires jwt header parameter with attestation")
		}

		// Validate that attestation sub matches client_id (without the scheme prefix)
		expectedSub := strings.TrimPrefix(authReq.ClientID, clientIDSchemeVerifierAttestationPrefix)
		if attestation.Subject != expectedSub {
			return nil, fmt.Errorf("attestation sub %q does not match client_id %q", attestation.Subject, expectedSub)
		}

		h.Logger.Debug("Verifier attestation validated",
			zap.String("attestation_issuer", attestation.Issuer),
			zap.String("verifier_sub", attestation.Subject))

		// Use the attestation issuer's key material for trust evaluation.
		// The PDP validates whether the attestation issuer is trusted.
		// We also forward the attestation issuer identity and the raw
		// attestation JWT so the PDP has full context.
		if attestation.AttestationKeyMaterial != nil {
			keyMaterial = attestation.AttestationKeyMaterial
		} else {
			// Attestation has no embedded key — send the cnf JWK for resolution
			keyMaterial = &KeyMaterial{
				Type: "jwk",
				JWK:  attestation.CNF,
			}
		}
		// Store attestation context for the trust evaluation request.
		// The raw JWT is forwarded so the PDP can verify the attestation
		// signature and validate claims (exp, aud, scope).
		attestationContext = map[string]interface{}{
			"attestation_issuer":  attestation.Issuer,
			"attestation_subject": attestation.Subject,
			"attestation_jwt":     attestation.RawJWT,
		}
		// The trust decision the PDP makes for this scheme depends on the
		// WHOLE attestation JWT - its signature, issuer chain, expiry, and
		// redirect_uris claims (that's why attestation_jwt is forwarded as
		// context) - not just the subject/key it asserts. A new, expired,
		// or revoked attestation can share the same subject and even the
		// same cnf key as a previously-trusted one, so the cache identity
		// must bind to this specific attestation JWT, not to what it
		// claims. This is always computable once extraction succeeded
		// (attestation.RawJWT is never empty here), so - unlike the other
		// schemes above - there is no "fingerprint unavailable" case to
		// fall back on.
		verifiedIdentity = clientIDSchemeVerifierAttestationPrefix + attestation.Subject + ":" + sha256Hex(attestation.RawJWT)

	default:
		// redirect_uri and other schemes: extract key material best-effort
		if clientMeta != nil {
			keyMaterial = h.extractVerifierKeyMaterial(ctx, clientMeta)
		}
		// Fallback: extract key material from the request JWT header
		if keyMaterial == nil && authReq.RequestJWT != "" {
			// Verify JWT signature if present (opportunistic verification)
			km, verifyErr := trust.VerifyJWTWithEmbeddedKey(authReq.RequestJWT)
			if verifyErr != nil {
				h.Logger.Warn("Request JWT signature verification failed, falling back to header extraction",
					zap.Error(verifyErr))
				keyMaterial = trust.ExtractKeyMaterialFromJWT(authReq.RequestJWT)
			} else {
				keyMaterial = km
			}
		}
	}

	canonicalURL := getCanonicalVerifierURL(authReq)

	// The identity fingerprint above (a matched key, a certificate, an
	// attestation JWT hash) only proves who signed the request - it says
	// nothing about the OTHER fields the PDP evaluates a request against:
	// response_uri/redirect_uri (a policy may only trust a verifier for a
	// specific callback endpoint) and, when present, an OIDF trust_chain.
	// The same verified identity presenting DIFFERENT PDP-relevant context
	// must not reuse a verdict the PDP evaluated for the FIRST context, so
	// fold a hash of that context into the cache key too. authCtx must be
	// built before this, and is reused unchanged by evaluateVerifierTrustViaPDP/
	// evaluateVerifierTrustViaFrontend below.
	authCtx := verifierAuthContext{
		keyMaterial:        keyMaterial,
		attestationContext: attestationContext,
		requiresResolution: requiresResolution,
		requestJWT:         requestJWT,
	}
	contextHash := hashEvalContext(buildVerifierEvalContext(authReq, authCtx, h.Logger))

	// cacheKey identifies this verifier AND the PDP-relevant context of
	// this specific request for the trust cache. Prefer the identity
	// signature verification just bound above (a DID that verified, a
	// client_id+certificate/key fingerprint pairing, an attested subject
	// bound to its key) - falling back to canonicalURL+client_id only for
	// schemes where no scheme-bound signature verification exists at all
	// (e.g. redirect_uri). client_id is included explicitly alongside
	// canonicalURL (not just relied on as canonicalURL's fallback value)
	// because canonicalURL prioritizes response_uri/redirect_uri over
	// client_id - two unsigned requests sharing a response_uri but
	// claiming DIFFERENT client_ids would otherwise collide on the same
	// key. When cacheable is false, a scheme that needed a key-material
	// fingerprint couldn't produce one; this request's result is never
	// read from or written to the cache at all, rather than falling back
	// to a weaker key a different key's request could collide with (see
	// the per-scheme comments above). The same applies if the context
	// itself can't be hashed.
	cacheKey := verifiedIdentity
	if cacheKey == "" && cacheable {
		cacheKey = canonicalURL + "|client_id:" + authReq.ClientID
	}
	if cacheKey != "" && contextHash != "" {
		cacheKey += "|ctx:" + contextHash
	} else {
		cacheable = false
	}

	// Check the in-memory trust cache. This runs after signature
	// verification above, and only ever hits on a PDP-backed verdict: a
	// client-asserted verdict (the no-PDP fallback path below) is never
	// written to the cache in the first place - see
	// evaluateVerifierTrustViaFrontend and cacheVerifierTrust.
	if cacheable {
		if cached := h.getCachedVerifierTrust(cacheKey); cached != nil {
			verifier.Trusted = cached.Trusted
			verifier.Framework = cached.TrustFramework
			verifier.TrustedStatus = string(cached.TrustStatus)
			if cached.Name != "" {
				verifier.Name = cached.Name
			}
			if clientID := h.getAdminClientID(ctx, canonicalURL); clientID != "" {
				verifier.ClientID = clientID
			}
			if !verifier.Trusted {
				return nil, fmt.Errorf("untrusted verifier %s (cached)", authReq.ClientID)
			}
			h.Logger.Debug("Using cached verifier trust result",
				zap.String("verifier", authReq.ClientID),
				zap.Bool("trusted", cached.Trusted))
			return verifier, nil
		}
	}

	// Try server-side direct evaluation first (preferred path). The backend
	// calls the go-trust PDP directly - no frontend round-trip needed. This
	// only activates when a verifier PDP is configured. Mirrors
	// OID4VCIHandler.evaluateTrust's issuer-side pattern (see oid4vci.go): if
	// the PDP call errors, that fails closed (untrusted) rather than
	// falling back to asking the client.
	if trustEndpoint := h.Config.Trust.GetVerifierPDPURL(); trustEndpoint != "" {
		return h.evaluateVerifierTrustViaPDP(ctx, authReq, verifier, authCtx, trustEndpoint, cacheKey, canonicalURL)
	}

	// Fallback: frontend-mediated trust evaluation (legacy path). Used only
	// when no verifier PDP is configured at all - the intentional,
	// permissive dev/no-PDP mode. Its verdict is never cached.
	return h.evaluateVerifierTrustViaFrontend(ctx, authReq, verifier, authCtx, canonicalURL)
}

// evaluateVerifierTrustViaPDP evaluates verifier trust by calling the
// go-trust PDP directly via h.TrustSvc.EvaluateVerifier. This is the
// preferred path when a verifier PDP is configured (h.Config.Trust.
// GetVerifierPDPURL() is non-empty).
//
// If the PDP call itself errors, this fails closed and returns an untrusted
// error - it must NEVER fall back to evaluateVerifierTrustViaFrontend, since
// that would let a network blip (or an attacker able to disrupt the PDP)
// downgrade a PDP-backed decision into a client-asserted one. This mirrors
// the corrected shape of OID4VCIHandler.evaluateTrust for issuers.
//
// Only a result produced by this function is ever written to the trust
// cache (via cacheVerifierTrust) - a client-asserted verdict from
// evaluateVerifierTrustViaFrontend never is.
func (h *OID4VPHandler) evaluateVerifierTrustViaPDP(ctx context.Context, authReq *AuthorizationRequest, verifier *VerifierInfo, authCtx verifierAuthContext, trustEndpoint, cacheKey, canonicalURL string) (*VerifierInfo, error) {
	evalCtx := ctx
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		evalCtx = trust.ContextWithTenant(ctx, h.Flow.Session.TenantID)
	}

	var tkm *trust.KeyMaterial
	if authCtx.keyMaterial != nil {
		tkm = &trust.KeyMaterial{
			Type: authCtx.keyMaterial.Type,
			X5C:  authCtx.keyMaterial.X5C,
			JWK:  authCtx.keyMaterial.JWK,
		}
	}

	// Forward the same trust_chain/attestation/URI context the frontend
	// path has always carried in TrustEvaluationRequest.Context - without
	// this, a request that depends on either (an OIDF federation entity JAR
	// signs with a trust_chain header, or a verifier_attestation-scheme
	// request) would reach the PDP with no way to validate it.
	evalContext := buildVerifierEvalContext(authReq, authCtx, h.Logger)

	// pdpSubjectID (not the raw authReq.ClientID) is what go-trust's own
	// contract requires for x509_san_dns/x509_san_uri/x509_hash - see its
	// doc comment (#404).
	directResult, err := h.TrustSvc.EvaluateVerifierWithContext(evalCtx, pdpSubjectID(authReq), trustEndpoint, tkm, evalContext)
	if err != nil {
		// Fail closed: a PDP error is never equivalent to "no PDP
		// configured" and must never fall back to asking the client.
		h.Logger.Warn("Server-side verifier trust evaluation failed; failing closed (untrusted)",
			zap.String("verifier", authReq.ClientID),
			zap.Error(err))
		return nil, fmt.Errorf("untrusted verifier %s: trust evaluation error: %w", authReq.ClientID, err)
	}

	verifier.Trusted = directResult.Trusted
	verifier.Framework = directResult.Framework
	verifier.Reason = directResult.Reason
	if directResult.Trusted {
		verifier.TrustedStatus = string(domain.TrustStatusTrusted)
	} else {
		verifier.TrustedStatus = string(domain.TrustStatusUntrusted)
	}

	h.Logger.Info("Server-side verifier trust evaluation",
		zap.String("verifier", authReq.ClientID),
		zap.Bool("trusted", verifier.Trusted),
		zap.String("framework", verifier.Framework))

	// Send result to frontend/SDK as informational progress
	_ = h.Progress(StepTrustEvaluated, map[string]interface{}{
		"verifier_trust_evaluated": true,
		"verifier":                 authReq.ClientID,
		"trusted":                  verifier.Trusted,
		"framework":                verifier.Framework,
		"reason":                   verifier.Reason,
	})

	// Cache the PDP-backed verdict. This is the only call site that ever
	// populates the trust cache. An empty cacheKey means the caller decided
	// this request isn't safely cacheable at all (see evaluateVerifierTrust's
	// cacheable/cacheKey computation) - skip writing rather than caching
	// under an empty/ambiguous key.
	if cacheKey != "" {
		h.cacheVerifierTrust(cacheKey, verifier)
	}

	// Look up admin-configured ClientID for VP audience (read-only)
	if clientID := h.getAdminClientID(ctx, canonicalURL); clientID != "" {
		verifier.ClientID = clientID
	}

	if !verifier.Trusted {
		reason := verifier.Reason
		if reason == "" {
			reason = "verifier not trusted"
		}
		h.Logger.Warn("Blocking untrusted verifier",
			zap.String("verifier", authReq.ClientID),
			zap.String("reason", reason))
		return nil, fmt.Errorf("untrusted verifier %s: %s", authReq.ClientID, reason)
	}

	return verifier, nil
}

// verifierAuthContext bundles the scheme-derived material
// evaluateVerifierTrust extracts (see its switch over authReq.ClientIDScheme)
// before dispatching to either evaluateVerifierTrustViaPDP or
// evaluateVerifierTrustViaFrontend, so callers don't have to thread each
// field through as its own parameter.
type verifierAuthContext struct {
	keyMaterial        *KeyMaterial
	attestationContext map[string]interface{}
	requiresResolution bool
	requestJWT         string
}

// buildVerifierTrustRequest constructs the TrustEvaluationRequest sent to the
// frontend for verifier trust evaluation: base subject/key-material fields,
// response/redirect URI context, any JAR trust_chain header (OID4VP
// §5.9.3.6), and any verifier_attestation context.
func buildVerifierTrustRequest(authReq *AuthorizationRequest, authCtx verifierAuthContext, logger *zap.Logger) *TrustEvaluationRequest {
	trustReq := &TrustEvaluationRequest{
		// SubjectID is pdpSubjectID(authReq): the original, wire-form
		// client_id for every scheme except x509_san_dns/x509_san_uri/
		// x509_hash, which need their client_id_scheme prefix present (or
		// re-applied, if the wire form carried it as a separate parameter
		// instead) for go-trust's ParseClientIDScheme/VerifyLeafBinding to
		// actually run (#404) - see pdpSubjectID's doc comment. This is
		// what /v1/evaluate must see, matching evaluateVerifierTrustViaPDP
		// below, which evaluates the identical pdpSubjectID(authReq). Per
		// docs/client-id-strategy.md's client-id-strategy table, the
		// decentralized_identifier: prefix specifically is stripped for
		// resolution only, never for evaluation: a no-PDP and a PDP-backed
		// flow must evaluate the same subject. See ResolutionSubjectID
		// below for what /v1/resolve actually needs - a DIFFERENT
		// identifier that one field can't also serve.
		SubjectID:          pdpSubjectID(authReq),
		SubjectType:        SubjectTypeCredentialVerifier,
		RequiresResolution: authCtx.requiresResolution,
		RequestJWT:         authCtx.requestJWT,
		Context:            buildVerifierEvalContext(authReq, authCtx, logger),
	}

	if authCtx.requiresResolution {
		// didFromClientID strips the decentralized_identifier: prefix when
		// present (a no-op for the older did: spelling, which never carries
		// it to begin with) - /v1/resolve needs the bare DID, the same
		// reason the server-side PDP branch above resolves via
		// didFromClientID(authReq.ClientID) rather than the raw client_id.
		trustReq.ResolutionSubjectID = didFromClientID(authReq.ClientID)
	}

	// Convert key material for frontend
	if authCtx.keyMaterial != nil {
		trustReq.KeyMaterial = &TrustKeyMaterial{
			Type: authCtx.keyMaterial.Type,
			X5C:  authCtx.keyMaterial.X5C,
			JWK:  authCtx.keyMaterial.JWK,
		}
	}

	return trustReq
}

// buildVerifierEvalContext computes the additional evaluation context a
// verifier trust decision may depend on: the client_id_scheme and
// response/redirect URI, any OIDF trust_chain forwarded from the JAR header
// (OID4VP §5.9.3.6), and any verifier_attestation context (OID4VP §5.9.3.4).
//
// Both evaluateVerifierTrustViaFrontend (via buildVerifierTrustRequest) and
// evaluateVerifierTrustViaPDP (via EvaluateVerifierWithContext) use this, so
// a PDP-first evaluation gets exactly the same context a frontend-mediated
// one always has - without it, go-trust has no OIDF trust chain or
// attestation JWT to validate a request against, for the schemes that
// depend on either.
func buildVerifierEvalContext(authReq *AuthorizationRequest, authCtx verifierAuthContext, logger *zap.Logger) map[string]interface{} {
	context := map[string]interface{}{
		"client_id_scheme": authReq.ClientIDScheme,
	}

	if authReq.ResponseURI != "" {
		context["response_uri"] = authReq.ResponseURI
	}
	if authReq.RedirectURI != "" {
		context["redirect_uri"] = authReq.RedirectURI
	}

	// Extract and forward trust_chain from JAR header (OID4VP §5.9.3.6)
	// This allows go-trust to validate a pre-supplied OIDF trust chain
	// instead of resolving it from scratch.
	if authReq.RequestJWT != "" {
		if trustChain := trust.ExtractTrustChainFromJWT(authReq.RequestJWT); len(trustChain) > 0 {
			context["trust_chain"] = trustChain
			logger.Debug("Forwarding trust_chain from JAR header",
				zap.String("verifier", authReq.ClientID),
				zap.Int("chain_length", len(trustChain)))
		}
	}

	// Forward attestation context if present (verifier_attestation scheme)
	for k, v := range authCtx.attestationContext {
		context[k] = v
	}

	return context
}

// evaluateVerifierTrustViaFrontend delegates trust evaluation to the
// frontend/SDK. This is the legacy path: used only when no verifier PDP is
// configured at all (h.Config.Trust.GetVerifierPDPURL() is empty) - the
// intentional, permissive dev/no-PDP mode. The engine sends a
// trust_evaluation_required progress, the frontend calls /v1/evaluate, and
// sends back a trust_result action.
//
// The resulting verdict is client-asserted, not independently checked by a
// PDP, so - unlike evaluateVerifierTrustViaPDP - it is deliberately never
// written to the trust cache. Caching it would let a single
// attacker-controlled answer (plus attacker-controlled name/logo from
// client_metadata) stand in as ground truth for every subsequent request
// against this identity for the whole cache TTL.
func (h *OID4VPHandler) evaluateVerifierTrustViaFrontend(ctx context.Context, authReq *AuthorizationRequest, verifier *VerifierInfo, authCtx verifierAuthContext, canonicalURL string) (*VerifierInfo, error) {
	trustReq := buildVerifierTrustRequest(authReq, authCtx, h.Logger)

	// Send trust evaluation request to frontend
	if err := trustReq.Validate(); err != nil {
		return nil, fmt.Errorf("invalid trust evaluation request: %w", err)
	}
	_ = h.Progress(StepEvaluatingVerifierTrust, map[string]interface{}{
		"trust_evaluation_required": true,
		"request":                   trustReq,
	})

	// Wait for frontend to evaluate trust via /v1/evaluate and respond
	// Use shorter timeout for trust evaluation (frontend should respond quickly)
	action, err := h.Flow.Session.WaitForActionWithTimeout(ctx, h.Flow.ID, TrustEvaluationTimeout, ActionTrustResult)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for trust evaluation: %w", err)
	}

	// Parse trust result from frontend
	var trustResult TrustResultPayload
	if err := json.Unmarshal(action.Payload, &trustResult); err != nil {
		return nil, fmt.Errorf("failed to parse trust result: %w", err)
	}

	// Validate and mark as processed
	if err := trustResult.Validate(); err != nil {
		return nil, fmt.Errorf("invalid trust result from frontend: %w", err)
	}

	// Audit log the trust result (for security audit trail)
	h.Logger.Info("Trust evaluation result received",
		zap.String("verifier", authReq.ClientID),
		zap.Bool("trusted", trustResult.Trusted),
		zap.String("framework", trustResult.Framework),
		zap.String("reason", trustResult.Reason))

	// Update verifier info from trust result
	verifier.Trusted = trustResult.Trusted
	verifier.Framework = trustResult.Framework
	verifier.Reason = trustResult.Reason
	if trustResult.Trusted {
		verifier.TrustedStatus = string(domain.TrustStatusTrusted)
	} else {
		verifier.TrustedStatus = string(domain.TrustStatusUntrusted)
	}

	// Unlike Trusted/Framework/Reason above - which this permissive no-PDP
	// dev-mode path has always accepted from the frontend at face value,
	// since there is no PDP to check them against and configuring no PDP
	// at all is an explicit operator choice to trust that path's
	// evaluation - the displayed name is not overridden from
	// trustResult.Name here (#406). Consistent with #398's fix to the
	// PDP-backed path: this wallet-backend has no way to tell a frontend's
	// own independently-verified display name apart from one it simply
	// echoed back from the verifier's own unauthenticated
	// client_metadata.client_name, so verifier.Name stays whatever it was
	// already set to (authReq.ClientID, per evaluateVerifierTrust - the
	// identifier this evaluation was actually about) rather than trusting
	// an asserted string either path received. logo_uri is unaffected here
	// too, same as #398 left client_metadata.logo_uri alone on the
	// PDP-backed path - a separate, narrower field, out of this fix's
	// scope.
	if trustResult.Logo != "" {
		verifier.Logo = &LogoInfo{URI: trustResult.Logo}
	}

	// Deliberately NOT cached - see the function-level comment: this is a
	// client-asserted verdict, not one a PDP has independently checked.

	// Look up admin-configured ClientID for VP audience (read-only)
	if clientID := h.getAdminClientID(ctx, canonicalURL); clientID != "" {
		verifier.ClientID = clientID
	}

	// Enforce trust decision: block untrusted verifiers
	if !verifier.Trusted {
		reason := "verifier not trusted"
		if trustResult.Reason != "" {
			reason = trustResult.Reason
		}
		h.Logger.Warn("Blocking untrusted verifier",
			zap.String("verifier", authReq.ClientID),
			zap.String("reason", reason))
		return nil, fmt.Errorf("untrusted verifier %s: %s", authReq.ClientID, reason)
	}

	return verifier, nil
}

// verifyDIDRequest validates a DID-identified verifier's request.
// Deprecated: DID verification is now delegated to frontend via /v1/resolve.
// The frontend resolves the DID document to get keys and verifies the JWT.
// This function is kept for reference but should not be used.
func (h *OID4VPHandler) verifyDIDRequest(authReq *AuthorizationRequest) (*KeyMaterial, error) {
	// Validate client_id is a valid DID, allowing OpenID4VP 1.0's
	// decentralized_identifier: prefix in front of it.
	did := didFromClientID(authReq.ClientID)
	if !strings.HasPrefix(did, "did:") {
		return nil, errors.New("client_id_scheme=did but client_id is not a DID")
	}
	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("invalid DID format: %s", did)
	}

	// Request must be JWT-secured
	if authReq.RequestJWT == "" {
		return nil, errors.New("client_id_scheme=did requires a signed request JWT")
	}

	// Verify JWT signature with embedded key material
	km, err := trust.VerifyJWTWithEmbeddedKey(authReq.RequestJWT)
	if err != nil {
		return nil, fmt.Errorf("DID request JWT verification failed: %w", err)
	}

	return km, nil
}

// sha256Hex returns the hex-encoded SHA-256 digest of s - used to fold an
// arbitrary string (e.g. a raw attestation JWT) into a trust-cache identity
// without embedding the string itself.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// hashEvalContext returns a stable digest of the PDP-relevant evaluation
// context (response_uri/redirect_uri, an OIDF trust_chain, verifier_attestation
// fields - see buildVerifierEvalContext) so the trust cache can be scoped to
// that context, not just the verifier's identity. json.Marshal of a
// map[string]interface{} sorts keys, so this is deterministic across calls
// with the same content. Returns "" if the context can't be marshaled -
// callers must treat that as "not cacheable", not as an empty/absent
// context, so two requests that differ only in an unhashable context field
// are never conflated.
func hashEvalContext(evalContext map[string]interface{}) string {
	raw, err := json.Marshal(evalContext)
	if err != nil {
		return ""
	}
	return sha256Hex(string(raw))
}

// keyMaterialFingerprint returns a stable identifier for the specific key
// material a request proved possession of via its signature: SHA-256 of an
// x5c leaf certificate's DER bytes, or the RFC 7638 JWK thumbprint of a JWK.
// Returns "" if km is nil, empty, or its key material can't be decoded.
//
// This exists so the trust cache can be scoped to the actual key a request
// signed with, not just a claimed identity string - see the did:,
// x509_san_dns, and x509_hash cases in evaluateVerifierTrust, none of which
// bind a claimed client_id/DID to one specific key on their own (a DID
// document can list multiple active verification methods, and the
// certificate/SAN trust check itself is the PDP's job). Without this, a
// second request presenting a different key but the same claimed identity
// could reuse a cached verdict the PDP never evaluated for that key.
// verifier_attestation uses sha256Hex(attestation.RawJWT) instead, not this
// function - see its case in evaluateVerifierTrust for why.
func keyMaterialFingerprint(km *KeyMaterial) string {
	if km == nil {
		return ""
	}
	switch km.Type {
	case "x5c":
		if len(km.X5C) == 0 {
			return ""
		}
		der, err := base64.StdEncoding.DecodeString(km.X5C[0])
		if err != nil {
			der, err = base64.RawURLEncoding.DecodeString(km.X5C[0])
			if err != nil {
				return ""
			}
		}
		sum := sha256.Sum256(der)
		return "sha256:" + hex.EncodeToString(sum[:])
	case "jwk":
		normalized := trust.NormalizeJWKS(km.JWK)
		if len(normalized) == 0 {
			return ""
		}
		raw, err := json.Marshal(normalized[0])
		if err != nil {
			return ""
		}
		var parsedJWK jose.JSONWebKey
		if err := parsedJWK.UnmarshalJSON(raw); err != nil {
			return ""
		}
		thumb, err := parsedJWK.Thumbprint(crypto.SHA256)
		if err != nil {
			return ""
		}
		return "jwk:" + hex.EncodeToString(thumb)
	default:
		return ""
	}
}

// getCanonicalVerifierURL returns the canonical URL for a verifier from an authorization request.
// This is used for consistent verifier lookup and caching.
// Priority: response_uri > redirect_uri > client_id
func getCanonicalVerifierURL(authReq *AuthorizationRequest) string {
	if authReq.ResponseURI != "" {
		return authReq.ResponseURI
	}
	if authReq.RedirectURI != "" {
		return authReq.RedirectURI
	}
	return authReq.ClientID
}

// getCachedVerifierTrust looks up a cached verdict by cacheKey - the
// authenticated identity computed in evaluateVerifierTrust (see
// verifiedIdentity there), not a bare client-supplied URL. Only entries
// written by cacheVerifierTrust (always PDP-backed) are ever found here.
// Returns nil if no cache is available or the entry has expired.
func (h *OID4VPHandler) getCachedVerifierTrust(cacheKey string) *TrustCacheRecord {
	if h.TrustCache == nil {
		return nil
	}

	tenantID := domain.DefaultTenantID
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		tenantID = domain.TenantID(h.Flow.Session.TenantID)
	}

	return h.TrustCache.Get(tenantID, cacheKey)
}

// getAdminClientID looks up the admin-configured ClientID for a verifier URL.
// This is a read-only lookup against the admin VerifierStore.
func (h *OID4VPHandler) getAdminClientID(ctx context.Context, verifierURL string) string {
	if h.Verifiers == nil {
		return ""
	}

	tenantID := domain.DefaultTenantID
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		tenantID = domain.TenantID(h.Flow.Session.TenantID)
	}

	stored, err := h.Verifiers.GetByURL(ctx, tenantID, verifierURL)
	if err != nil || stored == nil {
		return ""
	}
	return stored.ClientID
}

// cacheVerifierTrust stores a verifier trust evaluation result in the
// in-memory cache, keyed by cacheKey (the authenticated identity computed in
// evaluateVerifierTrust - see verifiedIdentity there - falling back to the
// canonical verifier URL only for schemes with no scheme-bound signature
// verification). This avoids writing to VerifierStore, which would pollute
// the admin registry.
//
// This must ONLY ever be called with a PDP-backed result
// (evaluateVerifierTrustViaPDP is the sole call site). A client-asserted
// verdict from evaluateVerifierTrustViaFrontend must never reach this
// function: caching it would let a single attacker-controlled answer stand
// in as ground truth for every subsequent request against this identity for
// the whole cache TTL, without ever consulting the PDP again.
func (h *OID4VPHandler) cacheVerifierTrust(cacheKey string, verifier *VerifierInfo) {
	if h.TrustCache == nil {
		return
	}

	tenantID := domain.DefaultTenantID
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		tenantID = domain.TenantID(h.Flow.Session.TenantID)
	}

	var trustStatus domain.TrustStatus
	if verifier.Trusted {
		trustStatus = domain.TrustStatusTrusted
	} else {
		trustStatus = domain.TrustStatusUntrusted
	}

	h.TrustCache.Set(tenantID, cacheKey, &TrustCacheRecord{
		Name:           verifier.Name,
		URL:            cacheKey,
		ClientIDScheme: verifier.ClientIDScheme,
		TrustStatus:    trustStatus,
		TrustFramework: verifier.Framework,
		Trusted:        verifier.Trusted,
	})
}

// extractDomain extracts a domain name from a client_id (URL or DID).
//
// OpenID4VP 1.0's decentralized_identifier: prefix is stripped first: it makes
// the client_id an opaque URI with no authority, so without this the very same
// verifier would show a domain under the draft spelling and none under the
// final one (see didFromClientID).
func extractDomain(clientID string) string {
	clientID = didFromClientID(clientID)
	if strings.HasPrefix(clientID, "did:web:") {
		// did:web:example.com → example.com (colons become dots in full spec, but the host is the 3rd segment)
		parts := strings.SplitN(clientID, ":", 4)
		if len(parts) >= 3 {
			return parts[2]
		}
	}
	if u, err := url.Parse(clientID); err == nil && u.Host != "" {
		return u.Host
	}
	return ""
}

// extractVerifierKeyMaterial extracts key material from client metadata for trust evaluation.
// Priority: x5c > jwks > jwks_uri (for DIDs where client_id starts with did:, returns nil)
func (h *OID4VPHandler) extractVerifierKeyMaterial(ctx context.Context, clientMeta *ClientMetadata) *KeyMaterial {
	// X5C certificate chain takes priority
	if len(clientMeta.X5C) > 0 {
		return &KeyMaterial{
			Type: "x5c",
			X5C:  clientMeta.X5C,
		}
	}

	// Inline JWKS
	if len(clientMeta.JWKS) > 0 {
		var jwks interface{}
		if err := json.Unmarshal(clientMeta.JWKS, &jwks); err == nil {
			return &KeyMaterial{
				Type: "jwk",
				JWK:  jwks,
			}
		}
		h.Logger.Warn("Failed to parse inline JWKS", zap.Error(fmt.Errorf("invalid JSON")))
	}

	// Fetch from jwks_uri
	if clientMeta.JWKsURI != "" {
		jwks, err := trust.FetchJWKS(ctx, clientMeta.JWKsURI, h.httpClient)
		if err != nil {
			h.Logger.Warn("Failed to fetch JWKS from URI", zap.String("uri", clientMeta.JWKsURI), zap.Error(err))
		} else {
			return &KeyMaterial{
				Type: "jwk",
				JWK:  jwks,
			}
		}
	}

	// No key material available - will use resolution-only mode (for DIDs)
	return nil
}

func (h *OID4VPHandler) fetchClientMetadata(ctx context.Context, uri string) (*ClientMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata fetch returned status %d", resp.StatusCode)
	}

	var cm ClientMetadata
	if err := json.NewDecoder(resp.Body).Decode(&cm); err != nil {
		return nil, err
	}

	return &cm, nil
}

// requestCredentialSelection sends dcql_query + verifier to the client in a single
// credential_selection progress message and waits for the user to consent or decline.
// The frontend is responsible for local credential matching and the consent UI.
//
// A client that finds nothing to present answers with credentials_matched and
// an empty match set instead, which ends the flow here. Without that answer
// the only ways out were a decline - untrue, the user was never asked - or
// silence until the user-interaction timeout, which is what a wallet missing
// the PID an issuer demands used to hit.
func (h *OID4VPHandler) requestCredentialSelection(ctx context.Context, authReq *AuthorizationRequest, verifier *VerifierInfo) ([]ConsentSelection, error) {
	_ = h.Progress(StepCredentialSelection, map[string]interface{}{
		"dcql_query": authReq.DCQLQuery,
		"verifier":   verifier,
	})

	action, err := h.waitForSelectionAction(ctx, authReq)
	if err != nil {
		return nil, err
	}

	if action.Action == ActionDecline {
		var decline struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(action.Payload, &decline)
		h.Logger.Info("user declined presentation", zap.String("reason", decline.Reason))
		redirectURI := h.submitErrorResponse(ctx, authReq, "access_denied", verifierRefusedDescription)
		if redirectURI != "" {
			_ = h.ErrorWithDetails(StepCredentialSelection, ErrCodePresentationError, "User declined the request",
				map[string]interface{}{"redirect_uri": redirectURI})
		} else {
			_ = h.Error(StepCredentialSelection, ErrCodePresentationError, "User declined the request")
		}
		return nil, errors.New("user declined presentation")
	}

	var payload ConsentPayload
	if err := json.Unmarshal(action.Payload, &payload); err != nil {
		_ = h.Error(StepCredentialSelection, ErrCodeInvalidMessage, "Invalid consent payload")
		return nil, fmt.Errorf("invalid consent payload: %w", err)
	}

	if len(payload.SelectedCredentials) == 0 {
		_ = h.Error(StepCredentialSelection, ErrCodePresentationError, "No credentials selected")
		return nil, errors.New("no credentials selected")
	}

	// The client is not trusted to have honoured the query it was sent: compare
	// the consent with it before anything is signed.
	if err := h.vetConsent(authReq, payload.SelectedCredentials); err != nil {
		redirectURI := h.submitErrorResponse(ctx, authReq, "access_denied", verifierRefusedDescription)
		if redirectURI != "" {
			_ = h.ErrorWithDetails(StepCredentialSelection, ErrCodePresentationError, ErrCodePresentationError.UserFacingMessage(),
				map[string]interface{}{"redirect_uri": redirectURI})
		} else {
			_ = h.Error(StepCredentialSelection, ErrCodePresentationError, ErrCodePresentationError.UserFacingMessage())
		}
		return nil, err
	}

	return payload.SelectedCredentials, nil
}

// waitForSelectionAction waits for the client's answer to a
// credential_selection message. credentials_matched with an empty match set
// terminates the flow; with a non-empty one it is informational and the wait
// continues, so a client that reports its matches before asking the user
// behaves exactly as one that does not.
//
// The user-interaction deadline is taken once, before the first wait, and each
// later wait gets only what is left of it. WaitForAction starts a fresh
// UserInteractionTimeout per call, so without this a client repeating the
// informational action would reset the clock every time and could hold a
// pending flow slot open indefinitely without ever obtaining consent.
func (h *OID4VPHandler) waitForSelectionAction(ctx context.Context, authReq *AuthorizationRequest) (*FlowActionMessage, error) {
	return h.waitForSelectionActionUntil(ctx, authReq, time.Now().Add(UserInteractionTimeout))
}

// waitForSelectionActionUntil is waitForSelectionAction against an explicit
// deadline, so a test can exercise the loop without waiting five minutes.
func (h *OID4VPHandler) waitForSelectionActionUntil(ctx context.Context, authReq *AuthorizationRequest, deadline time.Time) (*FlowActionMessage, error) {
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, ErrFlowTimeout
		}

		action, err := h.Flow.Session.WaitForActionWithTimeout(ctx, h.Flow.ID, remaining,
			ActionConsent, ActionDecline, ActionCredentialsMatched)
		if err != nil {
			return nil, err
		}
		if action.Action != ActionCredentialsMatched {
			return action, nil
		}

		var matched CredentialsMatchedPayload
		if err := json.Unmarshal(action.Payload, &matched); err != nil {
			_ = h.Error(StepCredentialSelection, ErrCodeInvalidMessage, "Invalid credentials_matched payload")
			return nil, fmt.Errorf("invalid credentials_matched payload: %w", err)
		}
		if len(matched.Matches) > 0 {
			continue
		}

		return nil, h.failNoMatchingCredential(ctx, authReq, matched.NoMatchReason)
	}
}

// verifierRefusedDescription is the error_description every refusal sends to
// the verifier, whether the user declined or the wallet held nothing that
// matched. OpenID4VP answers both with access_denied so a verifier cannot
// learn which happened - and therefore cannot probe what a holder has by
// asking and watching the reason. Two different descriptions would hand that
// distinction straight back.
const verifierRefusedDescription = "The wallet did not fulfil the request"

// failNoMatchingCredential ends the flow when the wallet holds nothing the
// verifier asked for. The verifier is told as well, so its session ends now
// rather than expiring: OpenID4VP has no dedicated code for "holder has no
// such credential", and access_denied is the response the specification
// provides for a request the wallet will not fulfil.
func (h *OID4VPHandler) failNoMatchingCredential(ctx context.Context, authReq *AuthorizationRequest, reason string) error {
	requested := requestedCredentialTypes(authReq.DCQLQuery)

	h.Logger.Info("no credential matches the verifier's query",
		zap.Strings("requested_types", requested), zap.String("client_reason", reason))

	details := map[string]interface{}{}
	if len(requested) > 0 {
		details["requested_types"] = requested
	}
	if reason != "" {
		details["no_match_reason"] = reason
	}
	// The verifier gets the same description a decline sends, not this
	// message: naming what the wallet does not hold would tell the verifier
	// whether the holder has a credential it asked about, which is exactly
	// what one access_denied for both outcomes is there to prevent. The
	// detailed text is for the wallet, which is showing it to its own user.
	if redirectURI := h.submitErrorResponse(ctx, authReq, "access_denied", verifierRefusedDescription); redirectURI != "" {
		details["redirect_uri"] = redirectURI
	}

	// The wallet is the one showing this to a person, and it is the only
	// party that knows their language, so it gets the code and the requested
	// types and composes its own sentence. The string here is the same
	// per-code English fallback every other flow error carries; an
	// interpolated one would be worse than useless, since a client cannot
	// translate a sentence it did not build.
	_ = h.ErrorWithDetails(StepCredentialSelection, ErrCodeNoMatchingCredentials,
		ErrCodeNoMatchingCredentials.UserFacingMessage(), details)

	return errors.New("no credential matches the verifier's query")
}

// requestedCredentialTypes lists the credential types a DCQL query asks for,
// so the error can name what is missing rather than say "nothing matched".
// Best-effort: an unparseable or exotic query simply yields no names.
func requestedCredentialTypes(dcql json.RawMessage) []string {
	if len(dcql) == 0 {
		return nil
	}
	var query struct {
		Credentials []struct {
			ID   string `json:"id"`
			Meta struct {
				VCTValues     []string `json:"vct_values"`
				DoctypeValue  string   `json:"doctype_value"`
				DoctypeValues []string `json:"doctype_values"`
			} `json:"meta"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(dcql, &query); err != nil {
		return nil
	}

	var types []string
	seen := map[string]bool{}
	add := func(v string) {
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		types = append(types, v)
	}
	for _, c := range query.Credentials {
		for _, vct := range c.Meta.VCTValues {
			add(vct)
		}
		add(c.Meta.DoctypeValue)
		for _, dt := range c.Meta.DoctypeValues {
			add(dt)
		}
		if len(c.Meta.VCTValues) == 0 && c.Meta.DoctypeValue == "" && len(c.Meta.DoctypeValues) == 0 {
			add(c.ID)
		}
	}
	return types
}

func (h *OID4VPHandler) requestVPSignature(ctx context.Context, authReq *AuthorizationRequest, selected []ConsentSelection, audience string) (string, error) {
	credRefs := make([]CredentialRef, len(selected))
	for i, s := range selected {
		credRefs[i] = CredentialRef(s)
	}

	if audience == "" {
		audience = authReq.ClientID
	}

	responseURI := authReq.ResponseURI
	if responseURI == "" {
		responseURI = authReq.RedirectURI
	}

	verifierJwkThumbprint := h.computeVerifierJWKThumbprint(authReq)

	params := SignRequestParams{
		Audience:              audience,
		Nonce:                 authReq.Nonce,
		CredentialsToInclude:  credRefs,
		ResponseURI:           responseURI,
		VerifierJwkThumbprint: verifierJwkThumbprint,
		VerifierSessionID:     authReq.VerifierSessionID,
		TransactionData:       authReq.TransactionData,
	}
	// EC TS12 puts the request's response_mode in the key binding JWT of an SCA
	// presentation. Sent only with transaction data, so every other
	// presentation's sign request is unchanged.
	if len(authReq.TransactionData) > 0 {
		params.ResponseMode = authReq.ResponseMode
	}
	resp, err := h.RequestSign(ctx, SignActionSignPresentation, params)
	if err != nil {
		return "", err
	}

	if len(authReq.DCQLQuery) > 0 {
		return buildDCQLVPToken(resp.VPToken, selected)
	}

	return resp.VPToken, nil
}

// computeVerifierJWKThumbprint returns the verifier JWK thumbprint for direct_post.jwt,
// or empty string for other response modes.
func (h *OID4VPHandler) computeVerifierJWKThumbprint(authReq *AuthorizationRequest) string {
	if authReq.ResponseMode != ResponseModeDirectPostJWT {
		return ""
	}
	jwk, err := h.extractVerifierEncryptionJWK(authReq)
	if err != nil {
		h.Logger.Warn("could not extract verifier encryption JWK for mdoc session transcript", zap.Error(err))
		return ""
	}
	thumbBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		h.Logger.Warn("could not compute JWK thumbprint for mdoc session transcript", zap.Error(err))
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(thumbBytes)
}

// buildDCQLVPToken restructures a newline-separated vp_token into a JSON object
// keyed by credential query ID per OID4VP 1.0 Final §8.1.
// If vpToken is already a valid JSON object, it is returned as-is.
func buildDCQLVPToken(vpToken string, selected []ConsentSelection) (string, error) {
	// If the frontend already returned a JSON object, pass it through.
	if strings.HasPrefix(strings.TrimSpace(vpToken), "{") && json.Valid([]byte(vpToken)) {
		return vpToken, nil
	}
	tokens := strings.Split(vpToken, "\n")
	if len(tokens) != len(selected) {
		return "", fmt.Errorf("DCQL vp_token has %d tokens but %d credentials selected", len(tokens), len(selected))
	}
	vpObj := make(map[string][]string, len(selected))
	for i, s := range selected {
		if s.CredentialQueryID != "" {
			vpObj[s.CredentialQueryID] = append(vpObj[s.CredentialQueryID], tokens[i])
		}
	}
	vpJSON, err := json.Marshal(vpObj)
	if err != nil {
		return "", fmt.Errorf("failed to marshal DCQL vp_token: %w", err)
	}
	return string(vpJSON), nil
}

// sanitizeEndpointURL validates and reconstructs an endpoint URL to prevent SSRF.
// It parses the URL, ensures the scheme is https or http, and rebuilds the URL
// from its validated components — breaking the taint chain for CodeQL analysis.
func sanitizeEndpointURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid response endpoint URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("invalid response endpoint URL scheme: %s", u.Scheme)
	}
	// Rebuild URL from validated components to break taint propagation.
	clean := &url.URL{
		Scheme:   u.Scheme,
		Host:     u.Host,
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}
	return clean.String(), nil
}

func (h *OID4VPHandler) submitResponse(ctx context.Context, authReq *AuthorizationRequest, vpToken string) (string, error) {
	_ = h.ProgressMessage(StepSubmittingResponse, "Submitting VP response")

	// Determine response endpoint
	responseEndpoint := authReq.ResponseURI
	if responseEndpoint == "" {
		responseEndpoint = authReq.RedirectURI
	}
	if responseEndpoint == "" {
		return "", errors.New("no response endpoint in request")
	}

	// Validate and sanitize the endpoint URL to prevent SSRF
	sanitizedEndpoint, err := sanitizeEndpointURL(responseEndpoint)
	if err != nil {
		return "", err
	}

	// Determine response mode
	responseMode := authReq.ResponseMode
	if responseMode == "" {
		responseMode = ResponseModeDirectPost
	}

	switch responseMode {
	case ResponseModeDirectPost:
		return h.submitDirectPost(ctx, sanitizedEndpoint, authReq, vpToken)
	case ResponseModeDirectPostJWT:
		return h.submitDirectPostJWT(ctx, sanitizedEndpoint, authReq, vpToken)
	case ResponseModeFragment:
		return h.buildFragmentRedirect(sanitizedEndpoint, authReq, vpToken), nil
	case ResponseModeQuery:
		return h.buildQueryRedirect(sanitizedEndpoint, authReq, vpToken), nil
	default:
		return "", fmt.Errorf("unsupported response_mode: %s", responseMode)
	}
}

func (h *OID4VPHandler) submitDirectPost(ctx context.Context, endpoint string, authReq *AuthorizationRequest, vpToken string) (string, error) {
	data := url.Values{}
	data.Set("vp_token", vpToken)
	if authReq.State != "" {
		data.Set("state", authReq.State)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set(hdrContentType, mimeFormURLEncoded)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit response: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Check for redirect
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		var result struct {
			RedirectURI string `json:"redirect_uri"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.RedirectURI != "" {
			return result.RedirectURI, nil
		}
		return "", nil
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.Header.Get("Location"), nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
	return "", fmt.Errorf("response submission failed with status %d: %s", resp.StatusCode, string(body))
}

// buildErrorRedirect returns the URL the user agent is sent to when a
// query/fragment-mode request ends in an error rather than a vp_token.
func buildErrorRedirect(endpoint, state, errCode, errDesc string, inFragment bool) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	params := u.Query()
	if inFragment {
		params = url.Values{}
	}
	params.Set("error", errCode)
	if errDesc != "" {
		params.Set("error_description", errDesc)
	}
	if state != "" {
		params.Set("state", state)
	}
	if inFragment {
		u.Fragment = params.Encode()
	} else {
		u.RawQuery = params.Encode()
	}
	return u.String()
}

func (h *OID4VPHandler) buildFragmentRedirect(endpoint string, authReq *AuthorizationRequest, vpToken string) string {
	u, _ := url.Parse(endpoint)
	fragment := url.Values{}
	fragment.Set("vp_token", vpToken)
	if authReq.State != "" {
		fragment.Set("state", authReq.State)
	}
	u.Fragment = fragment.Encode()
	return u.String()
}

func (h *OID4VPHandler) buildQueryRedirect(endpoint string, authReq *AuthorizationRequest, vpToken string) string {
	u, _ := url.Parse(endpoint)
	q := u.Query()
	q.Set("vp_token", vpToken)
	if authReq.State != "" {
		q.Set("state", authReq.State)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// inferClientIDScheme infers the client_id_scheme from the client_id format
// when the verifier does not provide it explicitly.
// didFromClientID returns the DID a client_id names, with OpenID4VP 1.0's
// decentralized_identifier: prefix removed when present. The prefix is part of
// the identifier the verifier signs and is trusted under, so it is stripped
// only where a DID itself is needed - resolution and format checks - never
// where the client_id is compared or evaluated.
func didFromClientID(clientID string) string {
	return strings.TrimPrefix(clientID, ClientIDSchemeDecentralizedIdentifier+":")
}

// pdpSubjectID returns the identifier sent as the AuthZEN Subject.ID for a
// verifier trust evaluation: to go-trust's PDP directly
// (evaluateVerifierTrustViaPDP), and to whatever a no-PDP frontend fallback
// forwards to its own /v1/evaluate call (buildVerifierTrustRequest's
// SubjectID) - both consumers need the identical value go-trust's own
// contract expects.
//
// For x509_san_dns/x509_san_uri/x509_hash, go-trust's ParseClientIDScheme
// only recognizes the client_id_scheme claim - and therefore only invokes
// VerifyLeafBinding to check the presented certificate is actually bound to
// it, rather than merely chained to a trusted CA - when Subject.ID itself
// carries the "<scheme>:" prefix (see go-trust's
// pkg/registry/clientid.go's ParseClientIDScheme/VerifyLeafBinding, and
// pkg/registry/static/whitelist.go's isCertificateArrayResourceType doc
// comment: "'x5c' is what real callers (e.g. go-wallet-backend) always
// send, encoding the client_id_scheme in Subject.ID instead").
//
// This wallet accepts client_id on the wire two ways (see
// inferClientIDScheme): the client_id_scheme prefix already embedded in
// client_id itself (OpenID4VP 1.0 final - e.g. "x509_san_dns:example.com"),
// or a bare client_id with client_id_scheme as a separate parameter (the
// earlier draft convention, still supported - e.g. client_id="example.com",
// client_id_scheme="x509_san_dns"). Only the first form happened to already
// satisfy go-trust's contract by accident, because nothing here ever
// stripped the embedded prefix; the second form sent a bare value with no
// prefix at all, so ParseClientIDScheme could never recognize it and
// VerifyLeafBinding was silently never invoked - the certificate was
// trusted on chain validity alone, never checked against the claimed
// SAN/hash (#404).
//
// strings.TrimPrefix first strips any pre-existing prefix before
// re-applying it, so a client_id already carrying it (the first wire form)
// is never double-prefixed.
func pdpSubjectID(authReq *AuthorizationRequest) string {
	var prefix string
	switch authReq.ClientIDScheme {
	case ClientIDSchemeX509SANDNS:
		prefix = ClientIDSchemeX509SANDNS + ":"
	case ClientIDSchemeX509SANURI:
		prefix = ClientIDSchemeX509SANURI + ":"
	case ClientIDSchemeX509Hash:
		prefix = ClientIDSchemeX509Hash + ":"
	default:
		return authReq.ClientID
	}
	return prefix + strings.TrimPrefix(authReq.ClientID, prefix)
}

func inferClientIDScheme(clientID string) string {
	switch {
	case strings.HasPrefix(clientID, ClientIDSchemeDecentralizedIdentifier+":"):
		return ClientIDSchemeDecentralizedIdentifier
	case strings.HasPrefix(clientID, "did:"):
		return ClientIDSchemeDID
	case strings.HasPrefix(clientID, "x509_san_dns:"):
		return ClientIDSchemeX509SANDNS
	case strings.HasPrefix(clientID, "x509_san_uri:"):
		return ClientIDSchemeX509SANURI
	case strings.HasPrefix(clientID, clientIDSchemeVerifierAttestationPrefix):
		return ClientIDSchemeVerifierAttestation
	case strings.HasPrefix(clientID, "https://"), strings.HasPrefix(clientID, "http://"):
		// HTTPS/HTTP URLs default to redirect_uri scheme
		return ClientIDSchemeRedirectURI
	default:
		// Check if client_id has a colon-separated prefix that looks like
		// an explicit (but unrecognized) client_id_scheme
		if idx := strings.Index(clientID, ":"); idx > 0 {
			prefix := clientID[:idx]
			// If it contains dots or slashes, it's likely a domain/path, not a scheme
			if !strings.ContainsAny(prefix, "./") {
				return prefix // Return the raw prefix for validation to reject
			}
		}
		return ClientIDSchemeRedirectURI
	}
}

// submitErrorResponse posts an OAuth 2.0 error response to the verifier's
// response_uri per OID4VP §8.2 / §8.5. This allows the conformance suite
// (and real verifiers) to learn why the wallet rejected the request instead
// of timing out waiting for a response. Some verifiers (e.g. multipaz-based
// ones, mirroring their direct_post.jwt success response) return a
// redirect_uri here too, so the user can still be sent back to the
// verifier's own page even on decline/error - returned as a best-effort
// string, empty if the verifier didn't provide one or the POST failed.
func (h *OID4VPHandler) submitErrorResponse(ctx context.Context, authReq *AuthorizationRequest, errCode, errDesc string) string {
	if authReq == nil {
		return ""
	}

	// query and fragment carry the error back through the user agent, the
	// way submitResponse carries a vp_token in those modes: the caller gets a
	// URL to redirect to and nothing is sent from here. Only looking at
	// response_uri, which these verifiers do not set, meant they were never
	// told and sat waiting for a response that was never coming.
	//
	// The endpoint is chosen exactly as submitResponse chooses it - response_uri
	// first, redirect_uri otherwise. validateAuthorizationRequest only forbids
	// redirect_uri for the direct_post modes, so a query/fragment request may
	// carry both; picking differently here would deliver the vp_token to one
	// endpoint and the failure to the other, leaving the verifier waiting.
	if authReq.ResponseMode == ResponseModeQuery || authReq.ResponseMode == ResponseModeFragment {
		target := authReq.ResponseURI
		if target == "" {
			target = authReq.RedirectURI
		}
		if target == "" {
			return ""
		}
		endpoint, err := sanitizeEndpointURL(target)
		if err != nil {
			h.Logger.Debug("refusing to build an error redirect for an unusable endpoint", zap.Error(err))
			return ""
		}
		return buildErrorRedirect(endpoint, authReq.State, errCode, errDesc,
			authReq.ResponseMode == ResponseModeFragment)
	}

	if authReq.ResponseURI == "" {
		return ""
	}

	data := url.Values{}
	data.Set("error", errCode)
	if errDesc != "" {
		data.Set("error_description", errDesc)
	}
	if authReq.State != "" {
		data.Set("state", authReq.State)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", authReq.ResponseURI, strings.NewReader(data.Encode()))
	if err != nil {
		h.Logger.Debug("failed to create error response request", zap.Error(err))
		return ""
	}
	req.Header.Set(hdrContentType, mimeFormURLEncoded)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		h.Logger.Debug("failed to send error response to response_uri", zap.Error(err))
		return ""
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
	h.Logger.Debug("sent error response to response_uri",
		zap.String("response_uri", authReq.ResponseURI),
		zap.String("error", errCode),
		zap.Int("status", resp.StatusCode),
		zap.String("body", string(respBody)))

	var result struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal(respBody, &result); err == nil {
		return result.RedirectURI
	}
	return ""
}

// validateAuthorizationRequest performs OID4VP 1.0 Final spec-mandated validation
// on the parsed authorization request before proceeding with trust evaluation.
func (h *OID4VPHandler) validateAuthorizationRequest(authReq *AuthorizationRequest, msg *FlowStartMessage) error {
	// OID4VP §5: nonce is REQUIRED
	if authReq.Nonce == "" {
		return errors.New("missing required 'nonce' parameter")
	}

	// OID4VP §5: redirect_uri MUST NOT be present when response_mode is direct_post or direct_post.jwt
	responseMode := authReq.ResponseMode
	if responseMode == "" {
		responseMode = ResponseModeDirectPost
	}
	isDirectPost := responseMode == ResponseModeDirectPost || responseMode == ResponseModeDirectPostJWT
	if isDirectPost && authReq.RedirectURI != "" {
		return errors.New("redirect_uri must not be present with direct_post response mode")
	}

	// OID4VP §5: Validate client_id_scheme prefix is recognized
	switch authReq.ClientIDScheme {
	case ClientIDSchemeRedirectURI, ClientIDSchemeDID, ClientIDSchemeDecentralizedIdentifier,
		ClientIDSchemeX509SANDNS, ClientIDSchemeX509SANURI, ClientIDSchemeX509Hash,
		ClientIDSchemeVerifierAttestation:
		// Known scheme
	default:
		return fmt.Errorf("unsupported client_id_scheme: %s", authReq.ClientIDScheme)
	}

	// OID4VP §5: For direct_post, response_uri must be present
	if isDirectPost && authReq.ResponseURI == "" {
		return errors.New("response_uri is required for direct_post response mode")
	}

	// OID4VP §5: client_id in the URL must match client_id in the JWT request object
	if err := validateClientIDMatch(authReq, msg); err != nil {
		return err
	}

	// OID4VP §7.3: For x509_san_dns, verify JWT signature against x5c before
	// anything else (including trust cache and evaluateVerifierTrust's
	// unconditional client_metadata_uri fetch). This prevents cached trust
	// from bypassing signature verification on tampered requests. A missing
	// RequestJWT is rejected here too, not just an invalid one (#405): the
	// scheme switch's own "requires a signed request JWT" check runs after
	// that fetch, so leaving a missing JWT unrejected here let an entirely
	// unauthenticated x509_san_dns request still trigger it - the same class
	// of gap #401 fixed for x509_san_uri.
	if authReq.ClientIDScheme == ClientIDSchemeX509SANDNS {
		if authReq.RequestJWT == "" {
			return errors.New("x509_san_dns scheme requires a signed request JWT")
		}
		km, err := trust.VerifyJWTWithEmbeddedKey(authReq.RequestJWT)
		if err != nil {
			return fmt.Errorf("x509_san_dns JWT signature verification failed: %w", err)
		}
		if km.Type != "x5c" {
			return fmt.Errorf("x509_san_dns scheme requires x5c in JWT header, got %q", km.Type)
		}
	}

	// x509_hash has the same trust-cache-bypass and unauthenticated-fetch
	// risk as x509_san_dns above - verify the JWT signature against its
	// embedded x5c before anything else, rather than only inside
	// evaluateVerifierTrust's scheme switch (which runs after both the
	// in-memory trust cache check and the client_metadata_uri fetch, so
	// would never fire in time to prevent either for a tampered or entirely
	// unsigned request). See #405.
	if authReq.ClientIDScheme == ClientIDSchemeX509Hash {
		if authReq.RequestJWT == "" {
			return errors.New("x509_hash scheme requires a signed request JWT")
		}
		km, err := trust.VerifyJWTWithEmbeddedKey(authReq.RequestJWT)
		if err != nil {
			return fmt.Errorf("x509_hash JWT signature verification failed: %w", err)
		}
		if km.Type != "x5c" {
			return fmt.Errorf("x509_hash scheme requires x5c in JWT header, got %q", km.Type)
		}
	}

	// x509_san_uri has the same risk as x509_san_dns/x509_hash above - but
	// here it's not just the trust cache: evaluateVerifierTrust fetches
	// client_metadata_uri (an outbound HTTP request to a verifier-controlled
	// URL) unconditionally, before its scheme switch ever runs, so an
	// invalidly-signed - or entirely unsigned - x509_san_uri request could
	// otherwise trigger that fetch before ever being rejected. Reject a
	// missing RequestJWT here too, not just an invalid one, so no
	// unauthenticated x509_san_uri request - signed or not - ever reaches
	// that fetch.
	if authReq.ClientIDScheme == ClientIDSchemeX509SANURI {
		if authReq.RequestJWT == "" {
			return errors.New("x509_san_uri scheme requires a signed request JWT")
		}
		km, err := trust.VerifyJWTWithEmbeddedKey(authReq.RequestJWT)
		if err != nil {
			return fmt.Errorf("x509_san_uri JWT signature verification failed: %w", err)
		}
		if km.Type != "x5c" {
			return fmt.Errorf("x509_san_uri scheme requires x5c in JWT header, got %q", km.Type)
		}
	}

	// OID4VP §5: For direct_post, response_uri origin must be consistent with request_uri origin.
	if err := validateResponseURIOrigin(authReq, msg); err != nil {
		return err
	}

	// OID4VP §7.4: Decode and validate transaction_data if present.
	return validateTransactionData(authReq, msg)
}

// validateClientIDMatch checks that client_id in the URL matches the JWT request object.
func validateClientIDMatch(authReq *AuthorizationRequest, msg *FlowStartMessage) error {
	if msg == nil || msg.RequestURI == "" || authReq.RequestJWT == "" {
		return nil
	}
	u, err := url.Parse(msg.RequestURI)
	if err != nil {
		return nil
	}
	urlClientID := u.Query().Get("client_id")
	if urlClientID != "" && urlClientID != authReq.ClientID {
		return fmt.Errorf("client_id mismatch: URL has %q but request object has %q", urlClientID, authReq.ClientID)
	}
	return nil
}

// validateResponseURIOrigin checks that response_uri origin matches request_uri origin.
// This check only applies to x509_san_dns with direct_post/direct_post.jwt per OID4VP §5.
func validateResponseURIOrigin(authReq *AuthorizationRequest, msg *FlowStartMessage) error {
	if authReq.ClientIDScheme != ClientIDSchemeX509SANDNS {
		return nil
	}
	if authReq.ResponseURI == "" || msg == nil || msg.RequestURI == "" {
		return nil
	}
	requestURL := msg.RequestURI
	if strings.HasPrefix(requestURL, "openid4vp://") || strings.HasPrefix(requestURL, "haip://") || strings.HasPrefix(requestURL, "haip-vp://") || strings.HasPrefix(requestURL, "mdoc-openid4vp://") {
		if u, err := url.Parse(requestURL); err == nil {
			requestURL = u.Query().Get("request_uri")
		}
	}
	if requestURL == "" {
		return nil
	}
	reqURL, err1 := url.Parse(requestURL)
	if err1 != nil || reqURL.Scheme == "" || reqURL.Host == "" {
		// Not a proper URL (e.g. raw query string) — skip origin check.
		return nil
	}
	respURL, err2 := url.Parse(authReq.ResponseURI)
	if err2 != nil {
		return nil
	}
	reqOrigin := reqURL.Scheme + "://" + reqURL.Host
	respOrigin := respURL.Scheme + "://" + respURL.Host
	if !strings.EqualFold(reqOrigin, respOrigin) {
		return fmt.Errorf("response_uri origin %q does not match request_uri origin %q", respOrigin, reqOrigin)
	}
	return nil
}

// transactionDataError is a transaction_data problem that gets its own
// handling: the verifier is told invalid_transaction_data (OID4VP 1.0 requires
// the wallet to error rather than carry on) and the client gets code, not the
// generic invalid-request error every other validation failure maps to.
type transactionDataError struct {
	code ErrorCode
	err  error
}

func (e *transactionDataError) Error() string { return e.err.Error() }
func (e *transactionDataError) Unwrap() error { return e.err }

func newTransactionDataError(code ErrorCode, format string, args ...any) error {
	return &transactionDataError{code: code, err: fmt.Errorf(format, args...)}
}

// decodedTransactionData pairs a decoded entry with the exact string the
// verifier sent. The string, not the decoded object, is what a presentation
// binds to: OID4VP hashes the base64url string as received and does not
// decode it first, and re-encoding a decoded object does not reproduce it
// (key order, whitespace, escapes and number formatting all differ).
type decodedTransactionData struct {
	Raw  string
	Data TransactionData
}

// decodeTransactionData decodes the transaction_data array structurally: an
// array of base64url strings, each a JSON object. It decides nothing about
// which types are supported.
func decodeTransactionData(raw json.RawMessage) ([]decodedTransactionData, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	// Reject JSON null: transaction_data must be an array if present.
	if string(raw) == "null" {
		return nil, newTransactionDataError(ErrCodeInvalidMessage, "invalid transaction_data: must be an array, not null")
	}
	var rawStrings []string
	if err := json.Unmarshal(raw, &rawStrings); err != nil {
		return nil, newTransactionDataError(ErrCodeInvalidMessage, "invalid transaction_data: expected array of base64url strings: %w", err)
	}
	out := make([]decodedTransactionData, 0, len(rawStrings))
	for i, encoded := range rawStrings {
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, newTransactionDataError(ErrCodeInvalidMessage, "transaction_data[%d]: invalid base64url encoding: %w", i, err)
		}
		var td TransactionData
		if err := json.Unmarshal(decoded, &td); err != nil {
			return nil, newTransactionDataError(ErrCodeInvalidMessage, "transaction_data[%d]: invalid JSON: %w", i, err)
		}
		// The verifier controls the decoded JSON, so a `raw` member in it would
		// land in td.Raw. Overwrite it: Raw is what was received, nothing else.
		td.Raw = encoded
		out = append(out, decodedTransactionData{Raw: encoded, Data: td})
	}
	return out, nil
}

// validateTransactionData decodes and validates the transaction_data array for
// the client that started the flow.
//
// A request that carries transaction_data is only passed on to a client that
// declared FeatureTransactionDataV1. Clients that predate it ignore unknown
// fields, so forwarding the request would have them sign a presentation
// without the transaction hashes and without showing the user the transaction.
// Refusing is the only safe answer for them, and it costs nothing that worked:
// such a presentation has never been accepted by a verifier that checks the
// hashes.
func validateTransactionData(authReq *AuthorizationRequest, msg *FlowStartMessage) error {
	entries, err := decodeTransactionData(authReq.TransactionDataRaw)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if !msg.Supports(FeatureTransactionDataV1) {
		return newTransactionDataError(ErrCodeUnsupportedTransactionData,
			"request carries transaction_data but the client did not declare %q", FeatureTransactionDataV1)
	}
	dcqlIDs := dcqlCredentialIDs(authReq.DCQLQuery)
	for i, e := range entries {
		if err := checkTransactionDataEntry(i, e.Data, dcqlIDs); err != nil {
			return err
		}
		authReq.TransactionData = append(authReq.TransactionData, e.Data)
	}
	return nil
}

// checkTransactionDataEntry is the structural check OID4VP 1.0 puts on an
// entry: a type, and a non-empty list of credential_ids each naming a
// credential in the request's DCQL query. It does not decide whether the type
// is supported. That depends on the type metadata of the attestation the
// entry is bound to, which the wallet resolves, so the engine passes every
// well-formed entry to a client that declared FeatureTransactionDataV1 and the
// client refuses what it cannot handle.
func checkTransactionDataEntry(i int, td TransactionData, dcqlIDs map[string]bool) error {
	if td.Type == "" {
		return newTransactionDataError(ErrCodeInvalidMessage, "transaction_data[%d]: missing type", i)
	}
	if len(td.CredentialIDs) == 0 {
		return newTransactionDataError(ErrCodeInvalidMessage, "transaction_data[%d]: credential_ids must be a non-empty array", i)
	}
	if dcqlIDs == nil {
		return nil
	}
	for _, id := range td.CredentialIDs {
		if !dcqlIDs[id] {
			return newTransactionDataError(ErrCodeInvalidMessage, "transaction_data[%d]: credential_ids references %q, which is not a credential in dcql_query", i, id)
		}
	}
	return nil
}

// dcqlCredentialIDs returns the credential query ids of a DCQL query, or nil
// when there is no query or it cannot be read (so there is nothing to check
// against; other validation reports an unreadable query).
func dcqlCredentialIDs(dcql json.RawMessage) map[string]bool {
	if len(dcql) == 0 {
		return nil
	}
	var q struct {
		Credentials []struct {
			ID string `json:"id"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(dcql, &q); err != nil || len(q.Credentials) == 0 {
		return nil
	}
	ids := make(map[string]bool, len(q.Credentials))
	for _, c := range q.Credentials {
		ids[c.ID] = true
	}
	return ids
}

// failTransactionData ends the flow for a transaction_data problem. The
// verifier is told so its session ends now, as for a decline, and the client
// gets the error code (and any redirect the verifier returned) to explain it to
// the user in their own language.
//
// Only call it once the verifier's trust has been established (see Execute).
func (h *OID4VPHandler) failTransactionData(ctx context.Context, authReq *AuthorizationRequest, tdErr *transactionDataError) {
	details := map[string]interface{}{}
	if authReq.ResponseMode == ResponseModeDirectPostJWT {
		// An error for direct_post.jwt must itself be a JWT (JARM), which
		// submitErrorResponse does not build: it posts plain form fields that
		// such a verifier rejects. Sending that would only produce a failed
		// request, so the verifier is not contacted and its session ends by
		// timeout, as it does for every other failure in this mode today.
		h.Logger.Info("not notifying a direct_post.jwt verifier of the transaction_data failure: error responses in this mode are not implemented")
	} else if redirectURI := h.submitErrorResponse(ctx, authReq, "invalid_transaction_data", transactionDataVerifierDescription); redirectURI != "" {
		details["redirect_uri"] = redirectURI
	}
	_ = h.ErrorWithDetails(StepParsingRequest, tdErr.code, tdErr.code.UserFacingMessage(), details)
}

// transactionDataVerifierDescription is deliberately generic: it says the
// wallet cannot handle this transaction data, not which client feature is
// missing.
const transactionDataVerifierDescription = "The wallet cannot process the transaction data in this request"

func (h *OID4VPHandler) submitDirectPostJWT(ctx context.Context, endpoint string, authReq *AuthorizationRequest, vpToken string) (string, error) {
	now := time.Now()

	var vpTokenValue interface{} = vpToken
	if json.Valid([]byte(vpToken)) {
		var parsed interface{}
		if err := json.Unmarshal([]byte(vpToken), &parsed); err == nil {
			vpTokenValue = parsed
		}
	}

	// Build JWT claims per OID4VP §6.2 / JARM §4.1
	claims := map[string]interface{}{
		"iss":      "https://self-issued.me/v2",
		"aud":      authReq.ClientID,
		"exp":      now.Add(5 * time.Minute).Unix(),
		"iat":      now.Unix(),
		"vp_token": vpTokenValue,
	}
	if authReq.State != "" {
		claims["state"] = authReq.State
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JARM claims: %w", err)
	}

	// Determine JARM mode from client_metadata
	var encAlg, encEnc string
	if authReq.ClientMetadata != nil {
		encAlg = authReq.ClientMetadata.AuthorizationEncryptedResponseAlg
		encEnc = authReq.ClientMetadata.AuthorizationEncryptedResponseEnc
	}

	// Per spec, authorization_encrypted_response_alg is required for direct_post.jwt.
	// When absent (e.g. x509_san_dns verifiers that omit client_metadata), infer a
	// sensible default from the available public key material rather than failing hard:
	//   EC key  → ECDH-ES  (RFC 7518 §4.6)
	//   RSA key → RSA-OAEP (RFC 7518 §4.3)
	// This allows interoperability with verifiers that embed their key in the request
	// JWT x5c header but do not explicitly declare JARM encryption parameters.
	if encAlg == "" {
		inferredKey, _, jwkAlg, keyErr := h.extractVerifierEncryptionKey(authReq)
		if keyErr != nil {
			return "", fmt.Errorf("direct_post.jwt requires authorization_encrypted_response_alg in client_metadata (key inference also failed: %w)", keyErr)
		}
		// Only honor the JWK's declared "alg" when it is a JARM key-management
		// algorithm we support.
		if jwkAlg != "" {
			if _, err := mapKeyAlgorithm(jwkAlg); err == nil {
				encAlg = jwkAlg
			}
		}
		if encAlg == "" {
			switch inferredKey.(type) {
			case *ecdsa.PublicKey:
				encAlg = "ECDH-ES"
			case *rsa.PublicKey:
				encAlg = "RSA-OAEP"
			default:
				return "", fmt.Errorf("direct_post.jwt: cannot infer encryption algorithm from key type %T; set authorization_encrypted_response_alg in client_metadata", inferredKey)
			}
		}
		h.Logger.Info("direct_post.jwt: selected encryption algorithm",
			zap.String("alg", encAlg),
			zap.String("verifier", authReq.ClientID))
	}
	if encEnc == "" {
		// A128CBC-HS256 is RFC 7518's first mandatory-to-implement JWE
		// "enc" algorithm, but it is not universally implemented in
		// practice: confirmed live against verifier.multipaz.org, whose
		// own JsonWebEncryption decrypter (multipaz/src/commonMain/kotlin/
		// org/multipaz/crypto/JsonWebEncryption.kt) only implements the
		// GCM family (A128GCM/A192GCM/A256GCM) and rejects CBC-HS256
		// outright with "No algorithm with JOSE identifier A128CBC-HS256" -
		// despite not declaring encrypted_response_enc_values_supported to
		// signal that restriction. GCM is an equally spec-valid default
		// choice absent an explicit verifier preference and has broader
		// real-world interop, so prefer it.
		encEnc = "A128GCM"
	}

	// Extract verifier's public key for encryption
	verifierKey, kid, _, err := h.extractVerifierEncryptionKey(authReq)
	if err != nil {
		return "", fmt.Errorf("failed to extract verifier encryption key: %w", err)
	}

	// Map algorithm strings to go-jose constants
	keyAlg, err := mapKeyAlgorithm(encAlg)
	if err != nil {
		return "", err
	}
	contentEnc, err := mapContentEncryption(encEnc)
	if err != nil {
		return "", err
	}

	// Build JWE
	encrypter, err := jose.NewEncrypter(
		contentEnc,
		jose.Recipient{Algorithm: keyAlg, Key: verifierKey, KeyID: kid},
		(&jose.EncrypterOptions{}).WithContentType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create JWE encrypter: %w", err)
	}

	jweObj, err := encrypter.Encrypt(claimsJSON)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt JARM response: %w", err)
	}

	jweString, err := jweObj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWE: %w", err)
	}

	// POST response=<jwe> per OID4VP §6.2
	data := url.Values{}
	data.Set("response", jweString)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set(hdrContentType, mimeFormURLEncoded)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit JARM response: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
	h.Logger.Debug("direct_post.jwt: verifier response received",
		zap.String("endpoint", endpoint),
		zap.Int("status", resp.StatusCode),
		zap.String("body", string(respBody)))

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		var result struct {
			RedirectURI                string `json:"redirect_uri"`
			PresentationDuringIssuance string `json:"presentation_during_issuance_session"`
		}
		if err := json.Unmarshal(respBody, &result); err == nil {
			if result.RedirectURI != "" {
				return result.RedirectURI, nil
			}
		}
		return "", nil
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.Header.Get("Location"), nil
	}

	return "", fmt.Errorf("JARM response submission failed with status %d: %s", resp.StatusCode, string(respBody))
}

func (h *OID4VPHandler) extractVerifierEncryptionKey(authReq *AuthorizationRequest) (interface{}, string, string, error) {
	// Prefer client_metadata.jwks — this is where verifiers put their
	// ephemeral encryption key for JARM (ECDH-ES key agreement).
	if authReq.ClientMetadata != nil && len(authReq.ClientMetadata.JWKS) > 0 {
		var jwks struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(authReq.ClientMetadata.JWKS, &jwks); err == nil && len(jwks.Keys) > 0 {
			// Select the best key for encryption: prefer use="enc", else fall
			// back to the first parseable key. The JWK's own "alg" is returned
			// so the caller can honor the verifier's declared algorithm instead
			// of inferring one from the key type.
			var fallbackKey *jose.JSONWebKey
			for _, raw := range jwks.Keys {
				var jwk jose.JSONWebKey
				if err := jwk.UnmarshalJSON(raw); err != nil {
					continue
				}
				if jwk.Use == "enc" {
					return jwk.Key, jwk.KeyID, jwk.Algorithm, nil
				}
				if fallbackKey == nil {
					k := jwk // copy
					fallbackKey = &k
				}
			}
			if fallbackKey != nil {
				return fallbackKey.Key, fallbackKey.KeyID, fallbackKey.Algorithm, nil
			}
		}
	}

	// Fallback: x5c from request JWT header (signing key, used when no
	// dedicated encryption key is provided in client_metadata). The x5c
	// certificate carries no JARM key-management alg, so none is returned
	// and the caller infers one from the key type.
	if authReq.RequestJWT != "" {
		parts := strings.Split(authReq.RequestJWT, ".")
		var kid string
		if len(parts) >= 2 {
			headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err == nil {
				var header struct {
					Kid string `json:"kid"`
				}
				_ = json.Unmarshal(headerBytes, &header)
				kid = header.Kid
			}
		}

		km := trust.ExtractKeyMaterialFromJWT(authReq.RequestJWT)
		if km != nil && km.Type == "x5c" && len(km.X5C) > 0 {
			certDER, err := base64.StdEncoding.DecodeString(km.X5C[0])
			if err != nil {
				certDER, err = base64.RawURLEncoding.DecodeString(km.X5C[0])
				if err != nil {
					return nil, "", "", fmt.Errorf("failed to decode x5c certificate: %w", err)
				}
			}
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return nil, "", "", fmt.Errorf("failed to parse x5c certificate: %w", err)
			}
			return cert.PublicKey, kid, "", nil
		}
	}

	return nil, "", "", errors.New("no verifier encryption key found in client_metadata.jwks or request JWT x5c")
}

// Returns the verifier's encryption key as a JSONWebKey.
// Used to compute the JWK thumbprint for the mdoc OID4VP session transcript.
// Mirrors extractVerifierEncryptionKey: prefers client_metadata.jwks, then falls
// back to an x5c-derived public key from the request JWT header.
func (h *OID4VPHandler) extractVerifierEncryptionJWK(authReq *AuthorizationRequest) (*jose.JSONWebKey, error) {
	if authReq.ClientMetadata != nil && len(authReq.ClientMetadata.JWKS) > 0 {
		var jwks struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(authReq.ClientMetadata.JWKS, &jwks); err != nil {
			return nil, fmt.Errorf("failed to unmarshal verifier encryption JWKS: %w", err)
		}

		var fallback *jose.JSONWebKey
		for _, raw := range jwks.Keys {
			var jwk jose.JSONWebKey
			if err := jwk.UnmarshalJSON(raw); err != nil {
				continue
			}
			if jwk.Use == "enc" {
				return &jwk, nil
			}
			if fallback == nil {
				k := jwk
				fallback = &k
			}
		}
		if fallback != nil {
			return fallback, nil
		}
	}

	// Fallback: x5c from request JWT header (signing key, used when no
	// dedicated encryption key is provided in client_metadata)
	if authReq.RequestJWT != "" {
		var kid string
		parts := strings.Split(authReq.RequestJWT, ".")
		if len(parts) >= 2 {
			headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err == nil {
				var header struct {
					Kid string `json:"kid"`
				}
				// kid extraction is best-effort; an absent or unparseable kid is fine
				// since the actual public key comes from the x5c certificate.
				_ = json.Unmarshal(headerBytes, &header)
				kid = header.Kid
			}
		}

		km := trust.ExtractKeyMaterialFromJWT(authReq.RequestJWT)
		if km != nil && km.Type == "x5c" && len(km.X5C) > 0 {
			certDER, err := base64.StdEncoding.DecodeString(km.X5C[0])
			if err != nil {
				certDER, err = base64.RawURLEncoding.DecodeString(km.X5C[0])
				if err != nil {
					return nil, fmt.Errorf("failed to decode x5c certificate: %w", err)
				}
			}
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return nil, fmt.Errorf("failed to parse x5c certificate: %w", err)
			}
			return &jose.JSONWebKey{Key: cert.PublicKey, KeyID: kid}, nil
		}
	}

	return nil, errors.New("no verifier encryption JWK found in client_metadata.jwks or request JWT x5c")
}

func mapKeyAlgorithm(alg string) (jose.KeyAlgorithm, error) {
	switch alg {
	case "ECDH-ES":
		return jose.ECDH_ES, nil
	case "ECDH-ES+A128KW":
		return jose.ECDH_ES_A128KW, nil
	case "ECDH-ES+A256KW":
		return jose.ECDH_ES_A256KW, nil
	case "RSA-OAEP":
		return jose.RSA_OAEP, nil
	case "RSA-OAEP-256":
		return jose.RSA_OAEP_256, nil
	default:
		return "", fmt.Errorf("unsupported JARM key algorithm: %s", alg)
	}
}

func mapContentEncryption(enc string) (jose.ContentEncryption, error) {
	switch enc {
	case "A128CBC-HS256":
		return jose.A128CBC_HS256, nil
	case "A256CBC-HS512":
		return jose.A256CBC_HS512, nil
	case "A128GCM":
		return jose.A128GCM, nil
	case "A256GCM":
		return jose.A256GCM, nil
	default:
		return "", fmt.Errorf("unsupported JARM content encryption: %s", enc)
	}
}
