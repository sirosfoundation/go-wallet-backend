package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

// Tenant represents a tenant response
type Tenant struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// TenantListResponse represents the list tenants response
type TenantListResponse struct {
	Tenants []Tenant `json:"tenants"`
}

var tenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Manage tenants",
	Long:  `Commands for managing tenants in the wallet backend.`,
}

var tenantListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tenants",
	Long:  `List all tenants in the wallet backend.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient(adminURL, adminToken)
		data, err := client.Request("GET", "/admin/tenants", nil)
		if err != nil {
			return err
		}

		if output == "json" {
			return printJSON(data)
		}

		var resp TenantListResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		if len(resp.Tenants) == 0 {
			fmt.Println("No tenants found.")
			return nil
		}

		headers := []string{"ID", "NAME", "DISPLAY NAME", "ENABLED"}
		rows := make([][]string, len(resp.Tenants))
		for i, t := range resp.Tenants {
			enabled := "yes"
			if !t.Enabled {
				enabled = "no"
			}
			rows[i] = []string{t.ID, t.Name, t.DisplayName, enabled}
		}
		printTable(headers, rows)
		return nil
	},
}

var tenantGetCmd = &cobra.Command{
	Use:   "get [tenant-id]",
	Short: "Get a specific tenant",
	Long:  `Get details of a specific tenant.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient(adminURL, adminToken)
		data, err := client.Request("GET", "/admin/tenants/"+args[0], nil)
		if err != nil {
			return err
		}

		return printJSON(data)
	},
}

var (
	tenantCreateID          string
	tenantCreateName        string
	tenantCreateDisplayName string
	tenantCreateEnabled     bool
)

var tenantCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new tenant",
	Long: `Create a new tenant in the wallet backend.

Tenant IDs must:
  - Be lowercase alphanumeric with hyphens
  - Start with a letter
  - Be 2-50 characters long`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if tenantCreateID == "" {
			return fmt.Errorf("--id is required")
		}
		if tenantCreateName == "" {
			return fmt.Errorf("--name is required")
		}

		client := NewClient(adminURL, adminToken)
		reqBody := map[string]interface{}{
			"id":      tenantCreateID,
			"name":    tenantCreateName,
			"enabled": tenantCreateEnabled,
		}
		if tenantCreateDisplayName != "" {
			reqBody["display_name"] = tenantCreateDisplayName
		}

		data, err := client.Request("POST", "/admin/tenants", reqBody)
		if err != nil {
			return err
		}

		fmt.Printf("Tenant '%s' created successfully.\n", tenantCreateID)
		if output == "json" {
			return printJSON(data)
		}
		return nil
	},
}

var (
	tenantUpdateName        string
	tenantUpdateDisplayName string
	tenantUpdateEnabled     *bool
)

var tenantUpdateCmd = &cobra.Command{
	Use:   "update [tenant-id]",
	Short: "Update a tenant",
	Long:  `Update an existing tenant's configuration.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tenantID := args[0]

		// First get the existing tenant
		client := NewClient(adminURL, adminToken)
		data, err := client.Request("GET", "/admin/tenants/"+tenantID, nil)
		if err != nil {
			return err
		}

		var existing Tenant
		if err := json.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("failed to parse tenant: %w", err)
		}

		// Build update request
		reqBody := map[string]interface{}{
			"id":   tenantID,
			"name": existing.Name,
		}

		if tenantUpdateName != "" {
			reqBody["name"] = tenantUpdateName
		}
		if tenantUpdateDisplayName != "" {
			reqBody["display_name"] = tenantUpdateDisplayName
		} else if existing.DisplayName != "" {
			reqBody["display_name"] = existing.DisplayName
		}
		if tenantUpdateEnabled != nil {
			reqBody["enabled"] = *tenantUpdateEnabled
		}

		data, err = client.Request("PUT", "/admin/tenants/"+tenantID, reqBody)
		if err != nil {
			return err
		}

		fmt.Printf("Tenant '%s' updated successfully.\n", tenantID)
		if output == "json" {
			return printJSON(data)
		}
		return nil
	},
}

var tenantDeleteCmd = &cobra.Command{
	Use:   "delete [tenant-id]",
	Short: "Delete a tenant",
	Long: `Delete a tenant and all associated data.

WARNING: This is a destructive operation. All users, credentials,
issuers, and verifiers associated with this tenant will be deleted.

The default tenant cannot be deleted.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient(adminURL, adminToken)
		_, err := client.Request("DELETE", "/admin/tenants/"+args[0], nil)
		if err != nil {
			return err
		}

		fmt.Printf("Tenant '%s' deleted successfully.\n", args[0])
		return nil
	},
}

// OIDC gate configuration flags
var (
	oidcGateMode               string
	oidcGateRegistrationOP     string
	oidcGateRegistrationClID   string
	oidcGateRegistrationName   string
	oidcGateRegistrationScopes string
	oidcGateLoginOP            string
	oidcGateLoginClID          string
	oidcGateLoginName          string
	oidcGateLoginScopes        string
	oidcGateBindIdentity       bool
	oidcGateTrustAdminClaim    bool
	oidcGateRequiredClaims     string
	oidcGateClear              bool
)

var tenantOIDCGateCmd = &cobra.Command{
	Use:   "configure-oidc-gate [tenant-id]",
	Short: "Configure OIDC gate for a tenant",
	Long: `Configure OIDC authentication gate for tenant registration/login endpoints.

The OIDC gate requires users to authenticate with an external OIDC provider
(e.g., enterprise IdP) before accessing wallet registration or login.

Modes:
  none         - No OIDC gate (default)
  registration - Gate on registration endpoint only
  login        - Gate on login endpoint only
  both         - Gate on both endpoints

Identity Binding:
  When --bind-identity is enabled, the enterprise identity (issuer + subject)
  is stored with the wallet user. On subsequent logins (if gated), the user
  must authenticate with the same enterprise identity.

Admin Claim Trust:
  --trust-admin-claim opts this tenant in to minting elevated (admin +
  delegation) session permissions when a login_op ID token's
  groups/roles/realm_roles claim contains "admin". OFF BY DEFAULT: the AS
  does not control the IdP's claim semantics, so only enable this if you
  trust the IdP to gate its own "admin" claim correctly.

Required Claims:
  --required-claims restricts the gate to tokens whose claims match. Give
  either a JSON object or comma-separated key=value pairs:
    --required-claims '{"department":"Engineering","groups":["admin"]}'
    --required-claims email_verified=true,department=Engineering
  key=value accepts only true/false (bool) or string values; use JSON for
  numbers, arrays and objects. A string value also matches when it is an
  element of an array claim (e.g. groups=admin matches ["admin","user"]),
  and an array value matches when every element is present in the token's
  array (order and extra elements ignored). Use --required-claims '{}' to
  remove all required claims; omitting the flag leaves them unchanged.

Examples:
  # Enable registration gate with Keycloak
  wallet-admin tenant configure-oidc-gate my-tenant \
    --mode registration \
    --registration-issuer https://idp.example.com/realms/corp \
    --registration-client-id wallet-reg \
    --registration-display-name "Corporate SSO"

  # Enable both gates with identity binding
  wallet-admin tenant configure-oidc-gate my-tenant \
    --mode both \
    --bind-identity \
    --registration-issuer https://idp.example.com/realms/corp \
    --registration-client-id wallet-reg \
    --login-issuer https://idp.example.com/realms/corp \
    --login-client-id wallet-login

  # Disable OIDC gate
  wallet-admin tenant configure-oidc-gate my-tenant --clear`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tenantID := args[0]
		client := NewClient(adminURL, adminToken)

		// If --clear, set mode to none and clear all gate settings
		if oidcGateClear {
			reqBody := map[string]interface{}{
				"oidc_gate": map[string]interface{}{
					"mode":              "none",
					"registration_op":   nil,
					"login_op":          nil,
					"bind_identity":     false,
					"trust_admin_claim": false,
					"required_claims":   nil,
				},
			}

			_, err := client.Request("PUT", "/admin/tenants/"+tenantID, reqBody)
			if err != nil {
				return err
			}

			fmt.Printf("OIDC gate cleared for tenant '%s'.\n", tenantID)
			return nil
		}

		// Validate mode
		validModes := map[string]bool{"none": true, "registration": true, "login": true, "both": true}
		if !validModes[oidcGateMode] {
			return fmt.Errorf("invalid mode '%s': must be one of: none, registration, login, both", oidcGateMode)
		}

		// Build OIDC gate config
		oidcGate := map[string]interface{}{
			"mode":              oidcGateMode,
			"bind_identity":     oidcGateBindIdentity,
			"trust_admin_claim": oidcGateTrustAdminClaim,
		}

		if cmd.Flags().Changed("required-claims") {
			claims, err := parseRequiredClaims(oidcGateRequiredClaims)
			if err != nil {
				return err
			}
			oidcGate["required_claims"] = claims
		}

		// Registration provider config
		if oidcGateMode == "registration" || oidcGateMode == "both" {
			if oidcGateRegistrationOP == "" {
				return fmt.Errorf("--registration-issuer is required for mode '%s'", oidcGateMode)
			}
			if oidcGateRegistrationClID == "" {
				return fmt.Errorf("--registration-client-id is required for mode '%s'", oidcGateMode)
			}
			regOP := map[string]interface{}{
				"issuer":    oidcGateRegistrationOP,
				"client_id": oidcGateRegistrationClID,
			}
			if oidcGateRegistrationName != "" {
				regOP["display_name"] = oidcGateRegistrationName
			}
			if oidcGateRegistrationScopes != "" {
				regOP["scopes"] = oidcGateRegistrationScopes
			}
			oidcGate["registration_op"] = regOP
		}

		// Login provider config
		if oidcGateMode == "login" || oidcGateMode == "both" {
			if oidcGateLoginOP == "" {
				return fmt.Errorf("--login-issuer is required for mode '%s'", oidcGateMode)
			}
			if oidcGateLoginClID == "" {
				return fmt.Errorf("--login-client-id is required for mode '%s'", oidcGateMode)
			}
			loginOP := map[string]interface{}{
				"issuer":    oidcGateLoginOP,
				"client_id": oidcGateLoginClID,
			}
			if oidcGateLoginName != "" {
				loginOP["display_name"] = oidcGateLoginName
			}
			if oidcGateLoginScopes != "" {
				loginOP["scopes"] = oidcGateLoginScopes
			}
			oidcGate["login_op"] = loginOP
		}

		// Update tenant with OIDC gate config
		reqBody := map[string]interface{}{
			"oidc_gate": oidcGate,
		}

		data, err := client.Request("PUT", "/admin/tenants/"+tenantID, reqBody)
		if err != nil {
			return err
		}

		fmt.Printf("OIDC gate configured for tenant '%s' with mode '%s'.\n", tenantID, oidcGateMode)
		if output == "json" {
			return printJSON(data)
		}
		return nil
	},
}

// parseRequiredClaims parses the --required-claims flag value: either a JSON
// object or comma-separated key=value pairs (values "true"/"false" become
// booleans, everything else is a string). Anything it cannot parse
// unambiguously is an error, so a typo can never silently weaken the gate.
func parseRequiredClaims(raw string) (map[string]interface{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("--required-claims must not be empty (use '{}' to remove all required claims)")
	}

	claims := map[string]interface{}{}
	if strings.HasPrefix(raw, "{") {
		// encoding/json keeps the last of two equal keys without complaint,
		// so {"groups":["admin"],"groups":[]} would silently weaken the gate.
		if err := rejectDuplicateJSONKeys([]byte(raw)); err != nil {
			return nil, fmt.Errorf("invalid --required-claims JSON: %w", err)
		}
		if err := json.Unmarshal([]byte(raw), &claims); err != nil {
			return nil, fmt.Errorf("invalid --required-claims JSON: %w", err)
		}
		return claims, nil
	}

	for _, pair := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(pair, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			return nil, fmt.Errorf("invalid --required-claims entry %q: expected key=value", pair)
		}
		if _, dup := claims[key]; dup {
			return nil, fmt.Errorf("duplicate --required-claims key %q", key)
		}
		switch value {
		case "true":
			claims[key] = true
		case "false":
			claims[key] = false
		default:
			claims[key] = value
		}
	}
	return claims, nil
}

// rejectDuplicateJSONKeys returns an error if any object in data, at any
// depth, repeats a key, or if data has trailing content after the first value.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := checkJSONValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("unexpected content after the JSON value")
	}
	return nil
}

func checkJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := keyTok.(string)
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = struct{}{}
			if err := checkJSONValue(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := checkJSONValue(dec); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // closing delimiter
	return err
}

func init() {
	rootCmd.AddCommand(tenantCmd)
	tenantCmd.AddCommand(tenantListCmd)
	tenantCmd.AddCommand(tenantGetCmd)
	tenantCmd.AddCommand(tenantCreateCmd)
	tenantCmd.AddCommand(tenantUpdateCmd)
	tenantCmd.AddCommand(tenantDeleteCmd)
	tenantCmd.AddCommand(tenantOIDCGateCmd)

	// Create flags
	tenantCreateCmd.Flags().StringVar(&tenantCreateID, "id", "", "Tenant ID (required)")
	tenantCreateCmd.Flags().StringVar(&tenantCreateName, "name", "", "Tenant name (required)")
	tenantCreateCmd.Flags().StringVar(&tenantCreateDisplayName, "display-name", "", "Display name")
	tenantCreateCmd.Flags().BoolVar(&tenantCreateEnabled, "enabled", true, "Whether tenant is enabled")

	// Update flags
	tenantUpdateCmd.Flags().StringVar(&tenantUpdateName, "name", "", "New tenant name")
	tenantUpdateCmd.Flags().StringVar(&tenantUpdateDisplayName, "display-name", "", "New display name")
	tenantUpdateCmd.Flags().Bool("enabled", true, "Whether tenant is enabled")
	tenantUpdateCmd.Flags().Bool("disabled", false, "Disable the tenant")

	// OIDC gate flags
	tenantOIDCGateCmd.Flags().StringVar(&oidcGateMode, "mode", "none", "OIDC gate mode: none, registration, login, both")
	tenantOIDCGateCmd.Flags().StringVar(&oidcGateRegistrationOP, "registration-issuer", "", "OIDC issuer URL for registration gate")
	tenantOIDCGateCmd.Flags().StringVar(&oidcGateRegistrationClID, "registration-client-id", "", "OIDC client ID for registration gate")
	tenantOIDCGateCmd.Flags().StringVar(&oidcGateRegistrationName, "registration-display-name", "", "Display name for registration IdP (e.g., 'Corporate SSO')")
	tenantOIDCGateCmd.Flags().StringVar(&oidcGateRegistrationScopes, "registration-scopes", "", "OIDC scopes for registration (default: 'openid profile email')")
	tenantOIDCGateCmd.Flags().StringVar(&oidcGateLoginOP, "login-issuer", "", "OIDC issuer URL for login gate")
	tenantOIDCGateCmd.Flags().StringVar(&oidcGateLoginClID, "login-client-id", "", "OIDC client ID for login gate")
	tenantOIDCGateCmd.Flags().StringVar(&oidcGateLoginName, "login-display-name", "", "Display name for login IdP (e.g., 'Enterprise SSO')")
	tenantOIDCGateCmd.Flags().StringVar(&oidcGateLoginScopes, "login-scopes", "", "OIDC scopes for login (default: 'openid profile email')")
	tenantOIDCGateCmd.Flags().BoolVar(&oidcGateBindIdentity, "bind-identity", false, "Bind enterprise identity to wallet user (verify on login)")
	tenantOIDCGateCmd.Flags().BoolVar(&oidcGateTrustAdminClaim, "trust-admin-claim", false, "Mint elevated admin permissions from the login IdP's groups/roles claim (off by default)")
	tenantOIDCGateCmd.Flags().StringVar(&oidcGateRequiredClaims, "required-claims", "", "Claims the ID token must carry: JSON object or key=value,key=value ('{}' removes all)")
	tenantOIDCGateCmd.Flags().BoolVar(&oidcGateClear, "clear", false, "Clear OIDC gate configuration")
}
