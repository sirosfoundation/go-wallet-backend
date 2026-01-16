package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// Verifier represents a verifier in a tenant
type Verifier struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	TenantID              string   `json:"tenant_id"`
	AcceptedCredentials   []string `json:"accepted_credentials,omitempty"`
	Enabled               bool     `json:"enabled"`
	VerificationEndpoint  string   `json:"verification_endpoint,omitempty"`
	PresentationDefID     string   `json:"presentation_definition_id,omitempty"`
	ClientID              string   `json:"client_id,omitempty"`
}

// VerifierListResponse represents the list verifiers response
type VerifierListResponse struct {
	Verifiers []Verifier `json:"verifiers"`
}

var verifierCmd = &cobra.Command{
	Use:   "verifier",
	Short: "Manage verifiers in a tenant",
	Long:  `Commands for managing credential verifiers within a specific tenant.`,
}

var verifierListTenantID string

var verifierListCmd = &cobra.Command{
	Use:   "list",
	Short: "List verifiers in a tenant",
	Long:  `List all verifiers in a specific tenant.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if verifierListTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}

		client := NewClient(adminURL)
		data, err := client.Request("GET", "/admin/tenants/"+verifierListTenantID+"/verifiers", nil)
		if err != nil {
			return err
		}

		if output == "json" {
			return printJSON(data)
		}

		var resp VerifierListResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		if len(resp.Verifiers) == 0 {
			fmt.Println("No verifiers found.")
			return nil
		}

		headers := []string{"ID", "NAME", "ENDPOINT", "ENABLED"}
		rows := make([][]string, len(resp.Verifiers))
		for i, v := range resp.Verifiers {
			enabled := "yes"
			if !v.Enabled {
				enabled = "no"
			}
			endpoint := v.VerificationEndpoint
			if endpoint == "" {
				endpoint = "-"
			}
			rows[i] = []string{v.ID, v.Name, endpoint, enabled}
		}
		printTable(headers, rows)
		return nil
	},
}

var verifierGetTenantID string

var verifierGetCmd = &cobra.Command{
	Use:   "get [verifier-id]",
	Short: "Get a specific verifier",
	Long:  `Get details of a specific verifier.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if verifierGetTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}

		client := NewClient(adminURL)
		data, err := client.Request("GET", "/admin/tenants/"+verifierGetTenantID+"/verifiers/"+args[0], nil)
		if err != nil {
			return err
		}

		return printJSON(data)
	},
}

var (
	verifierCreateTenantID          string
	verifierCreateID                string
	verifierCreateName              string
	verifierCreateEndpoint          string
	verifierCreatePresentationDefID string
	verifierCreateClientID          string
	verifierCreateClientSecret      string
	verifierCreateAcceptedCreds     []string
	verifierCreateEnabled           bool
)

var verifierCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new verifier",
	Long: `Create a new verifier in a tenant.

A verifier represents a relying party that can request and verify 
credentials from wallet users. Verifiers are configured with 
presentation definitions and verification endpoints.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if verifierCreateTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}
		if verifierCreateID == "" {
			return fmt.Errorf("--id is required")
		}
		if verifierCreateName == "" {
			return fmt.Errorf("--name is required")
		}

		client := NewClient(adminURL)
		reqBody := map[string]interface{}{
			"id":      verifierCreateID,
			"name":    verifierCreateName,
			"enabled": verifierCreateEnabled,
		}
		if verifierCreateEndpoint != "" {
			reqBody["verification_endpoint"] = verifierCreateEndpoint
		}
		if verifierCreatePresentationDefID != "" {
			reqBody["presentation_definition_id"] = verifierCreatePresentationDefID
		}
		if verifierCreateClientID != "" {
			reqBody["client_id"] = verifierCreateClientID
		}
		if verifierCreateClientSecret != "" {
			reqBody["client_secret"] = verifierCreateClientSecret
		}
		if len(verifierCreateAcceptedCreds) > 0 {
			reqBody["accepted_credentials"] = verifierCreateAcceptedCreds
		}

		data, err := client.Request("POST", "/admin/tenants/"+verifierCreateTenantID+"/verifiers", reqBody)
		if err != nil {
			return err
		}

		fmt.Printf("Verifier '%s' created successfully in tenant '%s'.\n", verifierCreateID, verifierCreateTenantID)
		if output == "json" {
			return printJSON(data)
		}
		return nil
	},
}

var (
	verifierUpdateTenantID          string
	verifierUpdateName              string
	verifierUpdateEndpoint          string
	verifierUpdatePresentationDefID string
	verifierUpdateClientID          string
	verifierUpdateClientSecret      string
	verifierUpdateAcceptedCreds     []string
)

var verifierUpdateCmd = &cobra.Command{
	Use:   "update [verifier-id]",
	Short: "Update a verifier",
	Long:  `Update an existing verifier's configuration.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if verifierUpdateTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}
		verifierID := args[0]

		// First get the existing verifier
		client := NewClient(adminURL)
		data, err := client.Request("GET", "/admin/tenants/"+verifierUpdateTenantID+"/verifiers/"+verifierID, nil)
		if err != nil {
			return err
		}

		var existing Verifier
		if err := json.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("failed to parse verifier: %w", err)
		}

		// Build update request preserving existing values
		reqBody := map[string]interface{}{
			"id":      verifierID,
			"name":    existing.Name,
			"enabled": existing.Enabled,
		}

		if verifierUpdateName != "" {
			reqBody["name"] = verifierUpdateName
		}
		if verifierUpdateEndpoint != "" {
			reqBody["verification_endpoint"] = verifierUpdateEndpoint
		} else if existing.VerificationEndpoint != "" {
			reqBody["verification_endpoint"] = existing.VerificationEndpoint
		}
		if verifierUpdatePresentationDefID != "" {
			reqBody["presentation_definition_id"] = verifierUpdatePresentationDefID
		} else if existing.PresentationDefID != "" {
			reqBody["presentation_definition_id"] = existing.PresentationDefID
		}
		if verifierUpdateClientID != "" {
			reqBody["client_id"] = verifierUpdateClientID
		} else if existing.ClientID != "" {
			reqBody["client_id"] = existing.ClientID
		}
		if verifierUpdateClientSecret != "" {
			reqBody["client_secret"] = verifierUpdateClientSecret
		}
		if len(verifierUpdateAcceptedCreds) > 0 {
			reqBody["accepted_credentials"] = verifierUpdateAcceptedCreds
		} else if len(existing.AcceptedCredentials) > 0 {
			reqBody["accepted_credentials"] = existing.AcceptedCredentials
		}

		data, err = client.Request("PUT", "/admin/tenants/"+verifierUpdateTenantID+"/verifiers/"+verifierID, reqBody)
		if err != nil {
			return err
		}

		fmt.Printf("Verifier '%s' updated successfully.\n", verifierID)
		if output == "json" {
			return printJSON(data)
		}
		return nil
	},
}

var verifierDeleteTenantID string

var verifierDeleteCmd = &cobra.Command{
	Use:   "delete [verifier-id]",
	Short: "Delete a verifier",
	Long: `Delete a verifier from a tenant.

WARNING: This will remove the verifier. Any presentation definitions
or configurations associated with this verifier will be removed.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if verifierDeleteTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}

		client := NewClient(adminURL)
		_, err := client.Request("DELETE", "/admin/tenants/"+verifierDeleteTenantID+"/verifiers/"+args[0], nil)
		if err != nil {
			return err
		}

		fmt.Printf("Verifier '%s' deleted successfully.\n", args[0])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(verifierCmd)
	verifierCmd.AddCommand(verifierListCmd)
	verifierCmd.AddCommand(verifierGetCmd)
	verifierCmd.AddCommand(verifierCreateCmd)
	verifierCmd.AddCommand(verifierUpdateCmd)
	verifierCmd.AddCommand(verifierDeleteCmd)

	// List flags
	verifierListCmd.Flags().StringVar(&verifierListTenantID, "tenant", "", "Tenant ID (required)")
	verifierListCmd.MarkFlagRequired("tenant")

	// Get flags
	verifierGetCmd.Flags().StringVar(&verifierGetTenantID, "tenant", "", "Tenant ID (required)")
	verifierGetCmd.MarkFlagRequired("tenant")

	// Create flags
	verifierCreateCmd.Flags().StringVar(&verifierCreateTenantID, "tenant", "", "Tenant ID (required)")
	verifierCreateCmd.Flags().StringVar(&verifierCreateID, "id", "", "Verifier ID (required)")
	verifierCreateCmd.Flags().StringVar(&verifierCreateName, "name", "", "Verifier name (required)")
	verifierCreateCmd.Flags().StringVar(&verifierCreateEndpoint, "endpoint", "", "Verification endpoint URL")
	verifierCreateCmd.Flags().StringVar(&verifierCreatePresentationDefID, "presentation-def-id", "", "Presentation definition ID")
	verifierCreateCmd.Flags().StringVar(&verifierCreateClientID, "client-id", "", "OAuth client ID")
	verifierCreateCmd.Flags().StringVar(&verifierCreateClientSecret, "client-secret", "", "OAuth client secret")
	verifierCreateCmd.Flags().StringSliceVar(&verifierCreateAcceptedCreds, "accepted-credential", nil, "Accepted credential types (can be repeated)")
	verifierCreateCmd.Flags().BoolVar(&verifierCreateEnabled, "enabled", true, "Whether verifier is enabled")
	verifierCreateCmd.MarkFlagRequired("tenant")
	verifierCreateCmd.MarkFlagRequired("id")
	verifierCreateCmd.MarkFlagRequired("name")

	// Update flags
	verifierUpdateCmd.Flags().StringVar(&verifierUpdateTenantID, "tenant", "", "Tenant ID (required)")
	verifierUpdateCmd.Flags().StringVar(&verifierUpdateName, "name", "", "New verifier name")
	verifierUpdateCmd.Flags().StringVar(&verifierUpdateEndpoint, "endpoint", "", "New verification endpoint URL")
	verifierUpdateCmd.Flags().StringVar(&verifierUpdatePresentationDefID, "presentation-def-id", "", "New presentation definition ID")
	verifierUpdateCmd.Flags().StringVar(&verifierUpdateClientID, "client-id", "", "New OAuth client ID")
	verifierUpdateCmd.Flags().StringVar(&verifierUpdateClientSecret, "client-secret", "", "New OAuth client secret")
	verifierUpdateCmd.Flags().StringSliceVar(&verifierUpdateAcceptedCreds, "accepted-credential", nil, "New accepted credential types (can be repeated)")
	verifierUpdateCmd.MarkFlagRequired("tenant")

	// Delete flags
	verifierDeleteCmd.Flags().StringVar(&verifierDeleteTenantID, "tenant", "", "Tenant ID (required)")
	verifierDeleteCmd.MarkFlagRequired("tenant")
}
