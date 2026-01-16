package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

// Verifier represents a verifier in a tenant (matching API response)
type Verifier struct {
	ID       int64  `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
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

		headers := []string{"ID", "NAME", "URL"}
		rows := make([][]string, len(resp.Verifiers))
		for i, v := range resp.Verifiers {
			url := v.URL
			if url == "" {
				url = "-"
			}
			rows[i] = []string{strconv.FormatInt(v.ID, 10), v.Name, url}
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
	verifierCreateTenantID string
	verifierCreateName     string
	verifierCreateURL      string
)

var verifierCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new verifier",
	Long: `Create a new verifier in a tenant.

A verifier represents a relying party that can request and verify 
credentials from wallet users.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if verifierCreateTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}
		if verifierCreateName == "" {
			return fmt.Errorf("--name is required")
		}
		if verifierCreateURL == "" {
			return fmt.Errorf("--url is required")
		}

		client := NewClient(adminURL)
		reqBody := map[string]interface{}{
			"name": verifierCreateName,
			"url":  verifierCreateURL,
		}

		data, err := client.Request("POST", "/admin/tenants/"+verifierCreateTenantID+"/verifiers", reqBody)
		if err != nil {
			return err
		}

		fmt.Printf("Verifier '%s' created successfully in tenant '%s'.\n", verifierCreateName, verifierCreateTenantID)
		if output == "json" {
			return printJSON(data)
		}
		return nil
	},
}

var (
	verifierUpdateTenantID string
	verifierUpdateName     string
	verifierUpdateURL      string
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
			"name": existing.Name,
			"url":  existing.URL,
		}

		if verifierUpdateName != "" {
			reqBody["name"] = verifierUpdateName
		}
		if verifierUpdateURL != "" {
			reqBody["url"] = verifierUpdateURL
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
	verifierCreateCmd.Flags().StringVar(&verifierCreateName, "name", "", "Verifier name (required)")
	verifierCreateCmd.Flags().StringVar(&verifierCreateURL, "verifier-url", "", "Verifier URL (required)")
	verifierCreateCmd.MarkFlagRequired("tenant")
	verifierCreateCmd.MarkFlagRequired("name")
	verifierCreateCmd.MarkFlagRequired("verifier-url")

	// Update flags
	verifierUpdateCmd.Flags().StringVar(&verifierUpdateTenantID, "tenant", "", "Tenant ID (required)")
	verifierUpdateCmd.Flags().StringVar(&verifierUpdateName, "name", "", "New verifier name")
	verifierUpdateCmd.Flags().StringVar(&verifierUpdateURL, "verifier-url", "", "New verifier URL")
	verifierUpdateCmd.MarkFlagRequired("tenant")

	// Delete flags
	verifierDeleteCmd.Flags().StringVar(&verifierDeleteTenantID, "tenant", "", "Tenant ID (required)")
	verifierDeleteCmd.MarkFlagRequired("tenant")
}
