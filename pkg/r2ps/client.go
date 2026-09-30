package r2ps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ErrInvalidInput is returned (wrapped) when a caller-supplied argument fails
// validation before any request is sent to the R2PS service. Callers can use
// errors.Is(err, ErrInvalidInput) to distinguish client input errors (400)
// from upstream/network failures (502).
var ErrInvalidInput = errors.New("r2ps: invalid input")

// ErrNotFound matches (via errors.Is) a *StatusError whose upstream status was
// 404, so callers can map it to a 404 of their own.
var ErrNotFound = errors.New("r2ps: not found")

// StatusError is returned when the R2PS service answers with an unexpected
// HTTP status. It preserves the upstream status code.
type StatusError struct {
	Op         string
	StatusCode int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("r2ps: %s: status %d", e.Op, e.StatusCode)
}

// Is reports a 404 as ErrNotFound.
func (e *StatusError) Is(target error) bool {
	return target == ErrNotFound && e.StatusCode == http.StatusNotFound
}

// Client is a Go HTTP client for the go-r2ps-service admin API.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	allowHTTP  bool
	token      string
}

// ClientOption configures the R2PS client.
type ClientOption func(*Client)

// WithTimeout sets the HTTP client timeout (default 10s).
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

// WithHTTPClient replaces the underlying HTTP client. Production wiring passes
// the SSRF-guarded client built from http_client configuration
// (config.HTTPClientConfig.NewHTTPClient). A nil client is ignored.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) {
		if hc != nil {
			// Copy so redirect hardening (and WithTimeout) never mutate the
			// caller's client.
			cp := *hc
			c.httpClient = &cp
		}
	}
}

// WithAllowPlaintext permits an http:// base URL. By default only https is
// accepted. Wire it from HTTPClientConfig.AllowsPlaintext() so the R2PS
// client follows the same convention as the other outbound clients.
func WithAllowPlaintext(allow bool) ClientOption {
	return func(c *Client) {
		c.allowHTTP = allow
	}
}

// WithBearerToken makes the client send "Authorization: Bearer <token>" on
// every request. go-r2ps-service's admin listener requires a bearer token
// (a JWT validated against R2PS_ADMIN_JWKS_URL, or its static development
// token). The token is never logged or included in error strings. An empty
// token means no Authorization header is sent.
func WithBearerToken(token string) ClientOption {
	return func(c *Client) {
		c.token = strings.TrimSpace(token)
	}
}

// NewClient creates a new R2PS admin client.
// baseURL is the R2PS admin endpoint (e.g. "https://r2ps-admin:8444"). It is
// parsed and validated once here: it must be an absolute https URL (http only
// with WithAllowPlaintext), have a host, and carry no userinfo, query or
// fragment. Every request the client makes is derived from this URL plus
// individually validated path segments, so no per-call argument can change
// the request host.
func NewClient(baseURL string, opts ...ClientOption) (*Client, error) {
	c := &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	// The upstream admin API has fixed endpoints: never follow redirects. A
	// followed 301/302/303 would turn a PUT into a GET (reported as success)
	// and could forward the bearer token to another host. Every 3xx is
	// returned as-is and surfaces as a *StatusError (502 at the API layer).
	c.httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("r2ps: invalid base URL: %w", err)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && c.allowHTTP:
	case u.Scheme == "http":
		return nil, fmt.Errorf("r2ps: base URL %q must use https (plaintext http is not allowed)", baseURL)
	default:
		return nil, fmt.Errorf("r2ps: base URL %q must be an absolute http(s) URL", baseURL)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("r2ps: base URL %q has no host", baseURL)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("r2ps: base URL %q must not contain userinfo, query or fragment", baseURL)
	}
	c.baseURL = u
	return c, nil
}

// StatusEntry represents a status list entry from R2PS.
type StatusEntry struct {
	Category string `json:"category"`
	Index    int    `json:"idx"`
	Status   int    `json:"status"` // 0=valid, 1=revoked, 2=suspended
	Label    string `json:"label,omitempty"`
	Used     bool   `json:"used"`
}

// PublicKeyInfo represents a WSCD public key from R2PS.
type PublicKeyInfo struct {
	KID          string `json:"kid"`
	Curve        string `json:"curve"`
	PubKey       string `json:"pub_key"` // base64
	CreationTime int64  `json:"creation_time"`
	ClientID     string `json:"client_id"`
}

// StatusListEntry represents a status entry with label from R2PS admin.
type StatusListEntry struct {
	Idx    int    `json:"idx"`
	Status int    `json:"status"`
	Label  string `json:"label"`
}

// isValidPathSegment reports whether s is safe to use as a single URL path
// segment when building an R2PS admin API request path. url.JoinPath
// normalizes ".." components (and treats "/" within an element as an
// additional separator), so an unvalidated caller-supplied value could
// escape the intended "admin/store/..." prefix and reach an unrelated path
// on the R2PS service. Rejecting anything but a plain segment closes that off.
//
// "%" is rejected outright rather than just "/" and "\": net/url's URL.Path
// is the unescaped form, and it is impossible in general to tell a raw "/"
// apart from a percent-encoded "%2f" (or "\" from "%5c") once decoded. A
// value like "..%2fadmin" contains no literal slash so it would pass a
// slash-only check, yet can still decode into a path-traversal segment
// downstream. None of the legitimate identifiers accepted here (category,
// client_id, kid) ever need a literal "%", so banning it entirely is safe.
func isValidPathSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
		switch r {
		case '/', '\\', '%', '?', '#':
			return false
		}
	}
	return true
}

// buildURL returns the request URL for the given path segments below the
// configured base URL. Callers must have validated every segment with
// isValidPathSegment.
func (c *Client) buildURL(elem ...string) string {
	return c.baseURL.JoinPath(elem...).String()
}

// validateIdx rejects status-list indices that cannot exist upstream.
func validateIdx(idx int) error {
	if idx < 0 {
		return fmt.Errorf("%w: invalid index %d (must be >= 0)", ErrInvalidInput, idx)
	}
	return nil
}

// ListStatuses returns all status entries for a category.
func (c *Client) ListStatuses(ctx context.Context, category string) ([]StatusListEntry, error) {
	if !isValidPathSegment(category) {
		return nil, fmt.Errorf("%w: invalid category %q", ErrInvalidInput, category)
	}
	reqURL := c.buildURL("admin", "store", "statuses", category)
	resp, err := c.doGet(ctx, reqURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Op: "list statuses", StatusCode: resp.StatusCode}
	}

	var result struct {
		Category string            `json:"category"`
		Count    int               `json:"count"`
		Entries  []StatusListEntry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("r2ps: decode statuses: %w", err)
	}
	// An empty upstream store encodes as null; the documented contract is an
	// array, so never hand a nil slice to callers that serialise it.
	if result.Entries == nil {
		return []StatusListEntry{}, nil
	}
	return result.Entries, nil
}

// GetClientStatuses returns the status list entries (idx, status, label) for a
// given client in a category.
func (c *Client) GetClientStatuses(ctx context.Context, clientID, category string) ([]StatusListEntry, error) {
	if !isValidPathSegment(clientID) {
		return nil, fmt.Errorf("%w: invalid client_id %q", ErrInvalidInput, clientID)
	}
	if !isValidPathSegment(category) {
		return nil, fmt.Errorf("%w: invalid category %q", ErrInvalidInput, category)
	}
	reqURL := c.buildURL("admin", "store", "clients", clientID, category)
	resp, err := c.doGet(ctx, reqURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Op: "get client statuses", StatusCode: resp.StatusCode}
	}

	var result struct {
		Indices []StatusListEntry `json:"indices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("r2ps: decode response: %w", err)
	}
	if result.Indices == nil {
		return []StatusListEntry{}, nil
	}
	return result.Indices, nil
}

// GetStatus returns the status for a specific index.
func (c *Client) GetStatus(ctx context.Context, category string, idx int) (*StatusEntry, error) {
	if !isValidPathSegment(category) {
		return nil, fmt.Errorf("%w: invalid category %q", ErrInvalidInput, category)
	}
	if err := validateIdx(idx); err != nil {
		return nil, err
	}
	reqURL := c.buildURL("admin", "store", "status", category, strconv.Itoa(idx))
	resp, err := c.doGet(ctx, reqURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Op: "get status", StatusCode: resp.StatusCode}
	}

	var entry StatusEntry
	if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
		return nil, fmt.Errorf("r2ps: decode status: %w", err)
	}
	return &entry, nil
}

// SetStatus sets the status for a specific index.
func (c *Client) SetStatus(ctx context.Context, category string, idx int, status int) error {
	if !isValidPathSegment(category) {
		return fmt.Errorf("%w: invalid category %q", ErrInvalidInput, category)
	}
	if err := validateIdx(idx); err != nil {
		return err
	}
	if status < 0 || status > 2 {
		return fmt.Errorf("%w: invalid status %d (must be 0, 1 or 2)", ErrInvalidInput, status)
	}
	reqURL := c.buildURL("admin", "store", "status", category, strconv.Itoa(idx))
	body := fmt.Sprintf(`{"status":%d}`, status)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("r2ps: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.authorize(req)

	// The request host comes from the base URL validated in NewClient; the
	// per-call category/idx are validated path segments below it.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("r2ps: set status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return &StatusError{Op: "set status", StatusCode: resp.StatusCode}
	}
	return nil
}

// ListKeys returns all public keys, optionally filtered by client_id.
func (c *Client) ListKeys(ctx context.Context, clientID string) ([]PublicKeyInfo, error) {
	reqURL := c.buildURL("admin", "store", "keys")
	if clientID != "" {
		reqURL += "?" + url.Values{"client_id": {clientID}}.Encode()
	}

	resp, err := c.doGet(ctx, reqURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Op: "list keys", StatusCode: resp.StatusCode}
	}

	var result struct {
		Keys []PublicKeyInfo `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("r2ps: decode keys: %w", err)
	}
	// An empty upstream store encodes as {"keys":null}; normalise so the proxy
	// emits [] as documented by R2PSKeyList.keys.
	if result.Keys == nil {
		return []PublicKeyInfo{}, nil
	}
	return result.Keys, nil
}

// GetKey returns a single public key by kid.
func (c *Client) GetKey(ctx context.Context, kid string) (*PublicKeyInfo, error) {
	if !isValidPathSegment(kid) {
		return nil, fmt.Errorf("%w: invalid kid %q", ErrInvalidInput, kid)
	}
	reqURL := c.buildURL("admin", "store", "keys", kid)
	resp, err := c.doGet(ctx, reqURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Op: "get key", StatusCode: resp.StatusCode}
	}

	var key PublicKeyInfo
	if err := json.NewDecoder(resp.Body).Decode(&key); err != nil {
		return nil, fmt.Errorf("r2ps: decode key: %w", err)
	}
	return &key, nil
}

func (c *Client) doGet(ctx context.Context, reqURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("r2ps: create request: %w", err)
	}
	c.authorize(req)
	// reqURL derives from the base URL validated in NewClient plus path
	// segments validated by the callers.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("r2ps: request failed: %w", err)
	}
	return resp, nil
}

// authorize attaches the bearer token, if one is configured.
func (c *Client) authorize(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}
