package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// Issuer represents an issuer in a tenant
type Issuer struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	TenantID          string   `json:"tenant_id"`
	CredentialTypes   []string `json:"credential_types,omitempty"`
	Enabled           bool     `json:"enabled"`
	IssuerURL         string   `json:"issuer_url,omitempty"`
	AuthorizationURL  string   `json:"authorization_url,omitempty"`
	TokenURL          string   `json:"token_url,omitempty"`
	CredentialURL     string   `json:"credential_url,omitempty"`
	ClientID          string   `json:"client_id,omitempty"`
}

// IssuerListResponse represents the list issuers response
type IssuerListResponse struct {
	Issuers []Issuer `json:"issuers"`
}

var issuerCmd = &cobra.Command{
	Use:   "issuer",
	Short: "Manage issuers in a tenant",
	Long:  `Commands for managing credential issuers within a specific tenant.`,
}

var issuerListTenantID string

var issuerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List issuers in a tenant",
	Long:  `List all issuers in a specific tenant.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if issuerListTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}

		client := NewClient(adminURL)
		data, err := client.Request("GET", "/admin/tenants/"+issuerListTenantID+"/issuers", nil)
		if err != nil {
			return err
		}

		if output == "json" {
			return printJSON(data)
		}

		var resp IssuerListResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		if len(resp.Issuers) == 0 {
			fmt.Println("No issuers found.")
			return nil
		}

		headers := []string{"ID", "NAME", "ISSUER URL", "ENABLED"}
		rows := make([][]string, len(resp.Issuers))
		for i, iss := range resp.Issuers {
			enabled := "yes"
			if !iss.Enabled {
				enabled = "no"
			}
			issuerURL := iss.IssuerURL
			if issuerURL == "" {
				issuerURL = "-"
			}
			rows[i] = []string{iss.ID, iss.Name, issuerURL, enabled}
		}
		printTable(headers, rows)
		return nil
	},
}

var (
	issuerGetTenantID string
)

var issuerGetCmd = &cobra.Command{
	Use:   "get [issuer-id]",
	Short: "Get a specific issuer",
	Long:  `Get details of a specific issuer.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if issuerGetTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}

		client := NewClient(adminURL)
		data, err := client.Request("GET", "/admin/tenants/"+issuerGetTenantID+"/issuers/"+args[0], nil)
		if err != nil {
			return err
		}

		return printJSON(data)
	},
}

var (
	issuerCreateTenantID       string
	issuerCreateID             string
	issuerCreateName           string
	issuerCreateIssuerURL      string
	issuerCreateAuthURL        string
	issuerCreateTokenURL       string
	issuerCreateCredentialURL  string
	issuerCreateClientID       string
	issuerCreateClientSecret   string
	issuerCreateCredTypes      []string
	issuerCreateEnabled        bool
)

var issuerCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new issuer",
	Long: `Create a new issuer in a tenant.

An issuer represents a credential issuing authority that users can 
request credentials from. Issuers are configured with OAuth/OpenID 
endpoints for authentication and credential issuance.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if issuerCreateTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}
		if issuerCreateID == "" {
			return fmt.Errorf("--id is required")
		}
		if issuerCreateName == "" {
			return fmt.Errorf("--name is required")
		}

		client := NewClient(adminURL)
		reqBody := map[string]interface{}{
			"id":       issuerCreateID,
			"name":     issuerCreateName,
			"enabled":  issuerCreateEnabled,
		}
		if issuerCreateIssuerURL != "" {
			reqBody["issuer_url"] = issuerCreateIssuerURL
		}
		if issuerCreateAuthURL != "" {
			reqBody["authorization_url"] = issuerCreateAuthURL
		}
		if issuerCreateTokenURL != "" {
			reqBody["token_url"] = issuerCreateTokenURL
		}
		if issuerCreateCredentialURL != "" {
			reqBody["credential_url"] = issuerCreateCredentialURL
		}
		if issuerCreateClientID != "" {
			reqBody["client_id"] = issuerCreateClientID
		}
		if issuerCreateClientSecret != "" {
			reqBody["client_secret"] = issuerCreateClientSecret
		}
		if len(issuerCreateCredTypes) > 0 {
			reqBody["credential_types"] = issuerCreateCredTypes
		}

		data, err := client.Request("POST", "/admin/tenants/"+issuerCreateTenantID+"/issuers", reqBody)
		if err != nil {
			return err
		}

		fmt.Printf("Issuer '%s' created successfully in tenant '%s'.\n", issuerCreateID, issuerCreateTenantID)
		if output == "json" {
			return printJSON(data)
		}
		return nil
	},
}

var (
	issuerUpdateTenantID       string
	issuerUpdateName           string
	issuerUpdateIssuerURL      string
	issuerUpdateAuthURL        string
	issuerUpdateTokenURL       string
	issuerUpdateCredentialURL  string
	issuerUpdateClientID       string
	issuerUpdateClientSecret   string
	issuerUpdateCredTypes      []string
)

var issuerUpdateCmd = &cobra.Command{
	Use:   "update [issuer-id]",
	Short: "Update an issuer",
	Long:  `Update an existing issuer's configuration.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if issuerUpdateTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}
		issuerID := args[0]

		// First get the existing issuer
		client := NewClient(adminURL)
		data, err := client.Request("GET", "/admin/tenants/"+issuerUpdateTenantID+"/issuers/"+issuerID, nil)
		if err != nil {
			return err
		}

		var existing Issuer
		if err := json.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("failed to parse issuer: %w", err)
		}

		// Build update request preserving existing values
		reqBody := map[string]interface{}{
			"id":      issuerID,
			"name":    existing.Name,
			"enabled": existing.Enabled,
		}

		if issuerUpdateName != "" {
			reqBody["name"] = issuerUpdateName
		}
		if issuerUpdateIssuerURL != "" {
			reqBody["issuer_url"] = issuerUpdateIssuerURL
		} else if existing.IssuerURL != "" {
			reqBody["issuer_url"] = existing.IssuerURL
		}
		if issuerUpdateAuthURL != "" {
			reqBody["authorization_url"] = issuerUpdateAuthURL
		} else if existing.AuthorizationURL != "" {
			reqBody["authorization_url"] = existing.AuthorizationURL
		}
		if issuerUpdateTokenURL != "" {
			reqBody["token_url"] = issuerUpdateTokenURL
		} else if existing.TokenURL != "" {
			reqBody["token_url"] = existing.TokenURL
		}
		if issuerUpdateCredentialURL != "" {
			reqBody["credential_url"] = issuerUpdateCredentialURL
		} else if existing.CredentialURL != "" {
			reqBody["credential_url"] = existing.CredentialURL
		}
		if issuerUpdateClientID != "" {
			reqBody["client_id"] = issuerUpdateClientID
		} else if existing.ClientID != "" {
			reqBody["client_id"] = existing.ClientID
		}
		if issuerUpdateClientSecret != "" {
			reqBody["client_secret"] = issuerUpdateClientSecret
		}
		if len(issuerUpdateCredTypes) > 0 {
			reqBody["credential_types"] = issuerUpdateCredTypes
		} else if len(existing.CredentialTypes) > 0 {
			reqBody["credential_types"] = existing.CredentialTypes
		}

		data, err = client.Request("PUT", "/admin/tenants/"+issuerUpdateTenantID+"/issuers/"+issuerID, reqBody)
		if err != nil {
			return err
		}

		fmt.Printf("Issuer '%s' updated successfully.\n", issuerID)
		if output == "json" {
			return printJSON(data)
		}
		return nil
	},
}

var issuerDeleteTenantID string

var issuerDeleteCmd = &cobra.Command{
	Use:   "delete [issuer-id]",
	Short: "Delete an issuer",
	Long: `Delete an issuer from a tenant.

WARNING: This will remove the issuer and may affect users who have
credentials from this issuer.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if issuerDeleteTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}

		client := NewClient(adminURL)
		_, err := client.Request("DELETE", "/admin/tenants/"+issuerDeleteTenantID+"/issuers/"+args[0], nil)
		if err != nil {
			return err
		}

		fmt.Printf("Issuer '%s' deleted successfully.\n", args[0])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(issuerCmd)
	issuerCmd.AddCommand(issuerListCmd)
	issuerCmd.AddCommand(issuerGetCmd)
	issuerCmd.AddCommand(issuerCreateCmd)
	issuerCmd.AddCommand(issuerUpdateCmd)
	issuerCmd.AddCommand(issuerDeleteCmd)

	// List flags
	issuerListCmd.Flags().StringVar(&issuerListTenantID, "tenant", "", "Tenant ID (required)")
	issuerListCmd.MarkFlagRequired("tenant")

	// Get flags
	issuerGetCmd.Flags().StringVar(&issuerGetTenantID, "tenant", "", "Tenant ID (required)")
	issuerGetCmd.MarkFlagRequired("tenant")

	// Create flags
	issuerCreateCmd.Flags().StringVar(&issuerCreateTenantID, "tenant", "", "Tenant ID (required)")
	issuerCreateCmd.Flags().StringVar(&issuerCreateID, "id", "", "Issuer ID (required)")
	issuerCreateCmd.Flags().StringVar(&issuerCreateName, "name", "", "Issuer name (required)")
	issuerCreateCmd.Flags().StringVar(&issuerCreateIssuerURL, "issuer-url", "", "Issuer URL")
	issuerCreateCmd.Flags().StringVar(&issuerCreateAuthURL, "auth-url", "", "Authorization endpoint URL")
	issuerCreateCmd.Flags().StringVar(&issuerCreateTokenURL, "token-url", "", "Token endpoint URL")
	issuerCreateCmd.Flags().StringVar(&issuerCreateCredentialURL, "credential-url", "", "Credential endpoint URL")
	issuerCreateCmd.Flags().StringVar(&issuerCreateClientID, "client-id", "", "OAuth client ID")
	issuerCreateCmd.Flags().StringVar(&issuerCreateClientSecret, "client-secret", "", "OAuth client secret")
	issuerCreateCmd.Flags().StringSliceVar(&issuerCreateCredTypes, "credential-type", nil, "Credential types (can be repeated)")
	issuerCreateCmd.Flags().BoolVar(&issuerCreateEnabled, "enabled", true, "Whether issuer is enabled")
	issuerCreateCmd.MarkFlagRequired("tenant")
	issuerCreateCmd.MarkFlagRequired("id")
	issuerCreateCmd.MarkFlagRequired("name")

	// Update flags
	issuerUpdateCmd.Flags().StringVar(&issuerUpdateTenantID, "tenant", "", "Tenant ID (required)")
	issuerUpdateCmd.Flags().StringVar(&issuerUpdateName, "name", "", "New issuer name")
	issuerUpdateCmd.Flags().StringVar(&issuerUpdateIssuerURL, "issuer-url", "", "New issuer URL")
	issuerUpdateCmd.Flags().StringVar(&issuerUpdateAuthURL, "auth-url", "", "New authorization endpoint URL")
	issuerUpdateCmd.Flags().StringVar(&issuerUpdateTokenURL, "token-url", "", "New token endpoint URL")
	issuerUpdateCmd.Flags().StringVar(&issuerUpdateCredentialURL, "credential-url", "", "New credential endpoint URL")
	issuerUpdateCmd.Flags().StringVar(&issuerUpdateClientID, "client-id", "", "New OAuth client ID")
	issuerUpdateCmd.Flags().StringVar(&issuerUpdateClientSecret, "client-secret", "", "New OAuth client secret")
	issuerUpdateCmd.Flags().StringSliceVar(&issuerUpdateCredTypes, "credential-type", nil, "New credential types (can be repeated)")
	issuerUpdateCmd.MarkFlagRequired("tenant")

	// Delete flags
	issuerDeleteCmd.Flags().StringVar(&issuerDeleteTenantID, "tenant", "", "Tenant ID (required)")
	issuerDeleteCmd.MarkFlagRequired("tenant")
}
