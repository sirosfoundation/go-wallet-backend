// Package cmd contains all CLI commands for wallet-admin.
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	adminURL string
	output   string
)

// Client wraps HTTP client for admin API calls
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new admin API client
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Request makes an HTTP request to the admin API
func (c *Client) Request(method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	url := c.baseURL + path
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// printJSON formats and prints JSON output
func printJSON(data []byte) error {
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, data, "", "  "); err != nil {
		// If it's not valid JSON, just print as-is
		fmt.Println(string(data))
		return nil
	}
	fmt.Println(formatted.String())
	return nil
}

// printTable prints data in a simple table format
func printTable(headers []string, rows [][]string) {
	// Calculate column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header
	for i, h := range headers {
		fmt.Printf("%-*s  ", widths[i], h)
	}
	fmt.Println()

	// Print separator
	for i := range headers {
		fmt.Printf("%s  ", strings.Repeat("-", widths[i]))
	}
	fmt.Println()

	// Print rows
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) {
				fmt.Printf("%-*s  ", widths[i], cell)
			}
		}
		fmt.Println()
	}
}

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "wallet-admin",
	Short: "CLI tool for managing the wallet backend",
	Long: `wallet-admin is a command-line tool for managing the wallet backend
multi-tenant infrastructure through the admin API.

It provides commands for managing:
  - Tenants: Create, list, update, and delete tenants
  - Users: Manage user memberships within tenants
  - Issuers: Configure credential issuers per tenant
  - Verifiers: Configure verifiers per tenant

Examples:
  # List all tenants
  wallet-admin tenant list

  # Create a new tenant
  wallet-admin tenant create --id my-tenant --name "My Tenant"

  # Add an issuer to a tenant
  wallet-admin issuer create --tenant my-tenant --url https://issuer.example.com

Environment Variables:
  WALLET_ADMIN_URL  Base URL of the admin API (default: http://localhost:8081)`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&adminURL, "url", "u", getEnvOrDefault("WALLET_ADMIN_URL", "http://localhost:8081"), "Admin API base URL")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "table", "Output format: table, json")
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
