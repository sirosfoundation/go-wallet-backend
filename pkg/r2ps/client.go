package r2ps

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a Go HTTP client for the go-r2ps-service admin API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// ClientOption configures the R2PS client.
type ClientOption func(*Client)

// WithTimeout sets the HTTP client timeout (default 10s).
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

// NewClient creates a new R2PS admin client.
// baseURL is the R2PS admin endpoint (e.g. "http://localhost:8444").
func NewClient(baseURL string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// StatusEntry represents a status list entry from R2PS.
type StatusEntry struct {
	Category string `json:"category"`
	Index    int    `json:"idx"`
	Status   int    `json:"status"` // 0=valid, 1=revoked, 2=suspended
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

// ListStatuses returns all status entries for a category.
func (c *Client) ListStatuses(ctx context.Context, category string) ([]StatusListEntry, error) {
	reqURL, _ := url.JoinPath(c.baseURL, "admin", "store", "statuses", category)
	resp, err := c.doGet(ctx, reqURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("r2ps: list statuses: status %d", resp.StatusCode)
	}

	var result struct {
		Category string            `json:"category"`
		Count    int               `json:"count"`
		Entries  []StatusListEntry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("r2ps: decode statuses: %w", err)
	}
	return result.Entries, nil
}

// GetClientStatuses returns all status list indices for a given client in a category.
func (c *Client) GetClientStatuses(ctx context.Context, clientID, category string) ([]int, error) {
	reqURL, _ := url.JoinPath(c.baseURL, "admin", "store", "clients", clientID, category)
	resp, err := c.doGet(ctx, reqURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("r2ps: get client statuses: status %d", resp.StatusCode)
	}

	var result struct {
		Indices []int `json:"indices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("r2ps: decode response: %w", err)
	}
	return result.Indices, nil
}

// GetStatus returns the status for a specific index.
func (c *Client) GetStatus(ctx context.Context, category string, idx int) (*StatusEntry, error) {
	reqURL, _ := url.JoinPath(c.baseURL, "admin", "store", "status", category, fmt.Sprintf("%d", idx))
	resp, err := c.doGet(ctx, reqURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("r2ps: get status: status %d", resp.StatusCode)
	}

	var entry StatusEntry
	if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
		return nil, fmt.Errorf("r2ps: decode status: %w", err)
	}
	return &entry, nil
}

// SetStatus sets the status for a specific index.
func (c *Client) SetStatus(ctx context.Context, category string, idx int, status int) error {
	reqURL, _ := url.JoinPath(c.baseURL, "admin", "store", "status", category, fmt.Sprintf("%d", idx))
	body := fmt.Sprintf(`{"status":%d}`, status)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("r2ps: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("r2ps: set status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("r2ps: set status: status %d", resp.StatusCode)
	}
	return nil
}

// ListKeys returns all public keys, optionally filtered by client_id.
func (c *Client) ListKeys(ctx context.Context, clientID string) ([]PublicKeyInfo, error) {
	reqURL, _ := url.JoinPath(c.baseURL, "admin", "store", "keys")
	if clientID != "" {
		reqURL += "?client_id=" + url.QueryEscape(clientID)
	}

	resp, err := c.doGet(ctx, reqURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("r2ps: list keys: status %d", resp.StatusCode)
	}

	var result struct {
		Keys []PublicKeyInfo `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("r2ps: decode keys: %w", err)
	}
	return result.Keys, nil
}

// GetKey returns a single public key by kid.
func (c *Client) GetKey(ctx context.Context, kid string) (*PublicKeyInfo, error) {
	reqURL, _ := url.JoinPath(c.baseURL, "admin", "store", "keys", kid)
	resp, err := c.doGet(ctx, reqURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("r2ps: get key: status %d", resp.StatusCode)
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
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("r2ps: request failed: %w", err)
	}
	return resp, nil
}
