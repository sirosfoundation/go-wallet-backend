package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// UserListResponse represents the list users response
// The API returns just user IDs as strings
type UserListResponse struct {
	Users []string `json:"users"`
}

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users in a tenant",
	Long:  `Commands for managing users within a specific tenant.`,
}

var userListTenantID string

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users in a tenant",
	Long:  `List all users in a specific tenant.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if userListTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}

		client := NewClient(adminURL, adminToken)
		data, err := client.Request("GET", "/admin/tenants/"+userListTenantID+"/users", nil)
		if err != nil {
			return err
		}

		if output == "json" {
			return printJSON(data)
		}

		var resp UserListResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		if len(resp.Users) == 0 {
			fmt.Println("No users found.")
			return nil
		}

		headers := []string{"USER ID"}
		rows := make([][]string, len(resp.Users))
		for i, userID := range resp.Users {
			rows[i] = []string{userID}
		}
		printTable(headers, rows)
		return nil
	},
}

var (
	userAddTenantID string
	userAddID       string
	userAddRole     string
)

var userAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a user to a tenant",
	Long:  `Add a new user to a specific tenant.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if userAddTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}
		if userAddID == "" {
			return fmt.Errorf("--id is required")
		}

		client := NewClient(adminURL, adminToken)
		reqBody := map[string]interface{}{
			"user_id": userAddID,
		}
		if userAddRole != "" {
			reqBody["role"] = userAddRole
		}

		data, err := client.Request("POST", "/admin/tenants/"+userAddTenantID+"/users", reqBody)
		if err != nil {
			return err
		}

		fmt.Printf("User '%s' added to tenant '%s' successfully.\n", userAddID, userAddTenantID)
		if output == "json" {
			return printJSON(data)
		}
		return nil
	},
}

var (
	userRemoveTenantID string
	userRemoveID       string
)

var userRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a user from a tenant",
	Long:  `Remove a user from a specific tenant.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if userRemoveTenantID == "" {
			return fmt.Errorf("--tenant is required")
		}
		if userRemoveID == "" {
			return fmt.Errorf("--id is required")
		}

		client := NewClient(adminURL, adminToken)
		_, err := client.Request("DELETE", "/admin/tenants/"+userRemoveTenantID+"/users/"+userRemoveID, nil)
		if err != nil {
			return err
		}

		fmt.Printf("User '%s' removed from tenant '%s' successfully.\n", userRemoveID, userRemoveTenantID)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(userCmd)
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userAddCmd)
	userCmd.AddCommand(userRemoveCmd)

	// List flags
	userListCmd.Flags().StringVar(&userListTenantID, "tenant", "", "Tenant ID (required)")
	userListCmd.MarkFlagRequired("tenant")

	// Add flags
	userAddCmd.Flags().StringVar(&userAddTenantID, "tenant", "", "Tenant ID (required)")
	userAddCmd.Flags().StringVar(&userAddID, "id", "", "User ID (required)")
	userAddCmd.Flags().StringVar(&userAddRole, "role", "", "User role")
	userAddCmd.MarkFlagRequired("tenant")
	userAddCmd.MarkFlagRequired("id")

	// Remove flags
	userRemoveCmd.Flags().StringVar(&userRemoveTenantID, "tenant", "", "Tenant ID (required)")
	userRemoveCmd.Flags().StringVar(&userRemoveID, "id", "", "User ID (required)")
	userRemoveCmd.MarkFlagRequired("tenant")
	userRemoveCmd.MarkFlagRequired("id")
}
