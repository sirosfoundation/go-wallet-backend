package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

// Issuer represents an issuer in a tenant (matching API response)
type Issuer struct {
	ID                         int64  `json:"id"`
	TenantID                   string `json:"tenant_id"`
	CredentialIssuerIdentifier string `json:"credential_issuer_identifier"`
	ClientID                   string `json:"client_id,omitempty"`
	Visible                    bool   `json:"visible"`
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

		client := NewClient(adminURL, adminToken)
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

		headers := []string{"ID", "CREDENTIAL ISSUER IDENTIFIER", "CLIENT ID", "VISIBLE"}
		rows := make([][]string, len(resp.Issuers))
		for i, iss := range resp.Issuers {
			visible := "yes"
			if !iss.Visible {
				visible = "no"
			}
			clientID := iss.ClientID
			if clientID == "" {
				clientID = "-"
			}
			rows[i] = []string{strconv.FormatInt(iss.ID, 10), iss.CredentialIssuerIdentifier, clientID, visible}
		}
		printTable(headers, rows)
		return nil
	},
}

var issuerGetTenantID string

var issuerGetCmd = &cobra.Command{
	Use:   "get [issuer-id]",
	Short: "Get a specific issuer",
	Long:  `Get details of a specific issuer by its numeric ID.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if issuerGetTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}

		client := NewClient(adminURL, adminToken)
		data, err := client.Request("GET", "/admin/tenants/"+issuerGetTenantID+"/issuers/"+args[0], nil)
		if err != nil {
			return err
		}

		return printJSON(data)
	},
}

var (
	issuerCreateTenantID   string
	issuerCreateIdentifier string
	issuerCreateClientID   string
	issuerCreateVisible    bool
)

var issuerCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new issuer",
	Long: `Create a new issuer in a tenant.

An issuer represents a credential issuing authority that users can 
request credentials from. The credential_issuer_identifier is typically
the URL of the issuer's OpenID4VCI credential issuer endpoint.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if issuerCreateTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}
		if issuerCreateIdentifier == "" {
			return fmt.Errorf("--identifier is required")
		}

		client := NewClient(adminURL, adminToken)
		reqBody := map[string]interface{}{
			"credential_issuer_identifier": issuerCreateIdentifier,
			"visible":                      issuerCreateVisible,
		}
		if issuerCreateClientID != "" {
			reqBody["client_id"] = issuerCreateClientID
		}

		data, err := client.Request("POST", "/admin/tenants/"+issuerCreateTenantID+"/issuers", reqBody)
		if err != nil {
			return err
		}

		fmt.Printf("Issuer created successfully in tenant '%s'.\n", issuerCreateTenantID)
		if output == "json" {
			return printJSON(data)
		}
		return nil
	},
}

var (
	issuerUpdateTenantID   string
	issuerUpdateIdentifier string
	issuerUpdateClientID   string
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
		client := NewClient(adminURL, adminToken)
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
			"credential_issuer_identifier": existing.CredentialIssuerIdentifier,
			"visible":                      existing.Visible,
		}

		if issuerUpdateIdentifier != "" {
			reqBody["credential_issuer_identifier"] = issuerUpdateIdentifier
		}
		if issuerUpdateClientID != "" {
			reqBody["client_id"] = issuerUpdateClientID
		} else if existing.ClientID != "" {
			reqBody["client_id"] = existing.ClientID
		}

		// Handle visible flag - check if either --visible or --hidden was passed
		if cmd.Flags().Changed("visible") {
			visible, _ := cmd.Flags().GetBool("visible")
			reqBody["visible"] = visible
		} else if cmd.Flags().Changed("hidden") {
			hidden, _ := cmd.Flags().GetBool("hidden")
			reqBody["visible"] = !hidden
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

		client := NewClient(adminURL, adminToken)
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
	_ = issuerListCmd.MarkFlagRequired("tenant")

	// Get flags
	issuerGetCmd.Flags().StringVar(&issuerGetTenantID, "tenant", "", "Tenant ID (required)")
	_ = issuerGetCmd.MarkFlagRequired("tenant")

	// Create flags
	issuerCreateCmd.Flags().StringVar(&issuerCreateTenantID, "tenant", "", "Tenant ID (required)")
	issuerCreateCmd.Flags().StringVar(&issuerCreateIdentifier, "identifier", "", "Credential issuer identifier/URL (required)")
	issuerCreateCmd.Flags().StringVar(&issuerCreateClientID, "client-id", "", "OAuth client ID")
	issuerCreateCmd.Flags().BoolVar(&issuerCreateVisible, "visible", true, "Whether issuer is visible to users")
	_ = issuerCreateCmd.MarkFlagRequired("tenant")
	_ = issuerCreateCmd.MarkFlagRequired("identifier")

	// Update flags
	issuerUpdateCmd.Flags().StringVar(&issuerUpdateTenantID, "tenant", "", "Tenant ID (required)")
	issuerUpdateCmd.Flags().StringVar(&issuerUpdateIdentifier, "identifier", "", "New credential issuer identifier/URL")
	issuerUpdateCmd.Flags().StringVar(&issuerUpdateClientID, "client-id", "", "New OAuth client ID")
	issuerUpdateCmd.Flags().Bool("visible", true, "Make issuer visible")
	issuerUpdateCmd.Flags().Bool("hidden", false, "Hide the issuer")
	_ = issuerUpdateCmd.MarkFlagRequired("tenant")

	// Delete flags
	issuerDeleteCmd.Flags().StringVar(&issuerDeleteTenantID, "tenant", "", "Tenant ID (required)")
	_ = issuerDeleteCmd.MarkFlagRequired("tenant")
}
