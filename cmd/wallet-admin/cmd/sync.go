package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// --- YAML config types ---

// SyncConfig is the top-level YAML configuration for syncing tenant state.
type SyncConfig struct {
	Tenants []SyncTenant `yaml:"tenants"`
}

// SyncTenant defines the desired state for a tenant.
type SyncTenant struct {
	ID            string           `yaml:"id"`
	Name          string           `yaml:"name"`
	DisplayName   string           `yaml:"display_name,omitempty"`
	Enabled       *bool            `yaml:"enabled,omitempty"`
	RequireInvite *bool            `yaml:"require_invite,omitempty"`
	TrustConfig   *SyncTrustConfig `yaml:"trust_config,omitempty"`
	OIDCGate      *SyncOIDCGate    `yaml:"oidc_gate,omitempty"`
	Issuers       []SyncIssuer     `yaml:"issuers,omitempty"`
	Verifiers     []SyncVerifier   `yaml:"verifiers,omitempty"`
}

// SyncTrustConfig defines trust evaluation configuration for a tenant.
type SyncTrustConfig struct {
	TrustEndpoint string `yaml:"trust_endpoint,omitempty"`
	TrustTTL      *int   `yaml:"trust_ttl,omitempty"`
}

// SyncOIDCGate defines OIDC gate configuration for a tenant.
type SyncOIDCGate struct {
	Mode           string            `yaml:"mode"` // none, registration, login, both
	RegistrationOP *SyncOIDCProvider `yaml:"registration_op,omitempty"`
	LoginOP        *SyncOIDCProvider `yaml:"login_op,omitempty"`
	RequiredClaims map[string]any    `yaml:"required_claims,omitempty"`
	BindIdentity   *bool             `yaml:"bind_identity,omitempty"`
}

// SyncOIDCProvider defines an OIDC provider configuration for sync.
type SyncOIDCProvider struct {
	DisplayName string `yaml:"display_name,omitempty"`
	Issuer      string `yaml:"issuer"`
	ClientID    string `yaml:"client_id"`
	JWKSURI     string `yaml:"jwks_uri,omitempty"`
	Audience    string `yaml:"audience,omitempty"`
	Scopes      string `yaml:"scopes,omitempty"`
}

// SyncIssuer defines the desired state for an issuer within a tenant.
type SyncIssuer struct {
	CredentialIssuerIdentifier string `yaml:"credential_issuer_identifier"`
	ClientID                   string `yaml:"client_id,omitempty"`
	Visible                    *bool  `yaml:"visible,omitempty"`
}

// SyncVerifier defines the desired state for a verifier within a tenant.
type SyncVerifier struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

// --- API response types for sync (extended to include trust_config and oidc_gate) ---

type syncTenantResp struct {
	ID            string               `json:"id"`
	Name          string               `json:"name"`
	DisplayName   string               `json:"display_name,omitempty"`
	Enabled       bool                 `json:"enabled"`
	RequireInvite bool                 `json:"require_invite"`
	TrustConfig   *syncTrustConfigResp `json:"trust_config,omitempty"`
	OIDCGate      *syncOIDCGateResp    `json:"oidc_gate,omitempty"`
}

type syncTrustConfigResp struct {
	TrustEndpoint string `json:"trust_endpoint,omitempty"`
	TrustTTL      int    `json:"trust_ttl"`
}

type syncOIDCGateResp struct {
	Mode           string                `json:"mode"`
	RegistrationOP *syncOIDCProviderResp `json:"registration_op,omitempty"`
	LoginOP        *syncOIDCProviderResp `json:"login_op,omitempty"`
	RequiredClaims map[string]any        `json:"required_claims,omitempty"`
	BindIdentity   bool                  `json:"bind_identity"`
}

type syncOIDCProviderResp struct {
	DisplayName string `json:"display_name,omitempty"`
	Issuer      string `json:"issuer"`
	ClientID    string `json:"client_id"`
	JWKSURI     string `json:"jwks_uri,omitempty"`
	Audience    string `json:"audience,omitempty"`
	Scopes      string `json:"scopes,omitempty"`
}

type syncTenantsListResp struct {
	Tenants []syncTenantResp `json:"tenants"`
}

// --- Command flags ---

var (
	syncConfigFile string
	syncDryRun     bool
	syncPrune      bool
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync tenant configuration from a YAML file",
	Long: `Sync the desired tenant, issuer, and verifier state from a YAML
configuration file to the wallet backend via the admin API.

The sync command compares the desired state in the YAML file with the
current state in the backend and applies the necessary create/update
operations to converge.

Matching rules:
  - Tenants are matched by ID
  - Issuers are matched by credential_issuer_identifier within a tenant
  - Verifiers are matched by name within a tenant

By default, entities present in the backend but absent from the config
file are left untouched. Use --prune to remove them.

Examples:
  # Dry-run to preview changes
  wallet-admin sync --config tenants.yaml --dry-run

  # Apply configuration
  wallet-admin sync --config tenants.yaml

  # Apply and remove entities not in config
  wallet-admin sync --config tenants.yaml --prune`,
	RunE: runSync,
}

func init() {
	rootCmd.AddCommand(syncCmd)
	syncCmd.Flags().StringVarP(&syncConfigFile, "config", "c", "", "Path to YAML configuration file (required)")
	syncCmd.Flags().BoolVar(&syncDryRun, "dry-run", false, "Preview changes without applying them")
	syncCmd.Flags().BoolVar(&syncPrune, "prune", false, "Delete entities not present in the config file")
	_ = syncCmd.MarkFlagRequired("config")
}

// --- sync action tracking ---

type syncAction struct {
	Kind     string // "tenant", "issuer", "verifier"
	TenantID string
	Name     string // human-readable identifier
	Action   string // "create", "update", "delete", "unchanged"
}

func (a syncAction) String() string {
	prefix := ""
	switch a.Action {
	case "create":
		prefix = "+"
	case "update":
		prefix = "~"
	case "delete":
		prefix = "-"
	case "unchanged":
		prefix = " "
	}
	if a.TenantID != "" && a.Kind != "tenant" {
		return fmt.Sprintf("  %s %s %s/%s", prefix, a.Kind, a.TenantID, a.Name)
	}
	return fmt.Sprintf("  %s %s %s", prefix, a.Kind, a.Name)
}

// --- main sync logic ---

func runSync(cmd *cobra.Command, args []string) error {
	// Load config
	cfg, err := loadSyncConfig(syncConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := validateSyncConfig(cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	client := NewClient(adminURL, adminToken)
	var actions []syncAction

	// Fetch current tenants
	remoteTenants, err := fetchTenants(client)
	if err != nil {
		return fmt.Errorf("failed to fetch tenants: %w", err)
	}
	remoteTenantMap := make(map[string]syncTenantResp)
	for _, t := range remoteTenants {
		remoteTenantMap[t.ID] = t
	}

	// Build set of desired tenant IDs for prune
	desiredTenantIDs := make(map[string]bool)
	for _, t := range cfg.Tenants {
		desiredTenantIDs[t.ID] = true
	}

	// Sync each tenant
	for _, desired := range cfg.Tenants {
		existing, exists := remoteTenantMap[desired.ID]
		tenantIsNew := false
		if !exists {
			tenantIsNew = true
			actions = append(actions, syncAction{Kind: "tenant", Name: desired.ID, Action: "create"})
			if !syncDryRun {
				if err := createTenantFromConfig(client, desired); err != nil {
					return fmt.Errorf("failed to create tenant %s: %w", desired.ID, err)
				}
			}
		} else if tenantNeedsUpdate(desired, existing) {
			actions = append(actions, syncAction{Kind: "tenant", Name: desired.ID, Action: "update"})
			if !syncDryRun {
				if err := updateTenantFromConfig(client, desired); err != nil {
					return fmt.Errorf("failed to update tenant %s: %w", desired.ID, err)
				}
			}
		} else {
			actions = append(actions, syncAction{Kind: "tenant", Name: desired.ID, Action: "unchanged"})
		}

		// For dry-run of a brand-new tenant, we can't fetch issuers/verifiers
		// from the API (the tenant doesn't exist yet). Just mark everything as "create".
		if syncDryRun && tenantIsNew {
			for _, iss := range desired.Issuers {
				actions = append(actions, syncAction{
					Kind: "issuer", TenantID: desired.ID,
					Name: iss.CredentialIssuerIdentifier, Action: "create",
				})
			}
			for _, v := range desired.Verifiers {
				actions = append(actions, syncAction{
					Kind: "verifier", TenantID: desired.ID,
					Name: v.Name, Action: "create",
				})
			}
			continue
		}

		// Sync issuers within this tenant
		issuerActions, err := syncIssuers(client, desired.ID, desired.Issuers)
		if err != nil {
			return fmt.Errorf("failed to sync issuers for tenant %s: %w", desired.ID, err)
		}
		actions = append(actions, issuerActions...)

		// Sync verifiers within this tenant
		verifierActions, err := syncVerifiers(client, desired.ID, desired.Verifiers)
		if err != nil {
			return fmt.Errorf("failed to sync verifiers for tenant %s: %w", desired.ID, err)
		}
		actions = append(actions, verifierActions...)
	}

	// Prune tenants not in config
	if syncPrune {
		for _, remote := range remoteTenants {
			if !desiredTenantIDs[remote.ID] && remote.ID != "default" {
				actions = append(actions, syncAction{Kind: "tenant", Name: remote.ID, Action: "delete"})
				if !syncDryRun {
					if _, err := client.Request("DELETE", "/admin/tenants/"+remote.ID, nil); err != nil {
						return fmt.Errorf("failed to delete tenant %s: %w", remote.ID, err)
					}
				}
			}
		}
	}

	// Print summary
	printSyncSummary(actions)
	return nil
}

// --- config loading and validation ---

func loadSyncConfig(path string) (*SyncConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg SyncConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	return &cfg, nil
}

func validateSyncConfig(cfg *SyncConfig) error {
	if len(cfg.Tenants) == 0 {
		return fmt.Errorf("no tenants defined")
	}
	seen := make(map[string]bool)
	for _, t := range cfg.Tenants {
		if t.ID == "" {
			return fmt.Errorf("tenant missing required field 'id'")
		}
		if t.Name == "" {
			return fmt.Errorf("tenant %q missing required field 'name'", t.ID)
		}
		if seen[t.ID] {
			return fmt.Errorf("duplicate tenant id %q", t.ID)
		}
		seen[t.ID] = true

		// Validate issuers
		issuerIDs := make(map[string]bool)
		for _, iss := range t.Issuers {
			if iss.CredentialIssuerIdentifier == "" {
				return fmt.Errorf("tenant %q: issuer missing required field 'credential_issuer_identifier'", t.ID)
			}
			if issuerIDs[iss.CredentialIssuerIdentifier] {
				return fmt.Errorf("tenant %q: duplicate issuer identifier %q", t.ID, iss.CredentialIssuerIdentifier)
			}
			issuerIDs[iss.CredentialIssuerIdentifier] = true
		}

		// Validate verifiers
		verifierNames := make(map[string]bool)
		for _, v := range t.Verifiers {
			if v.Name == "" {
				return fmt.Errorf("tenant %q: verifier missing required field 'name'", t.ID)
			}
			if v.URL == "" {
				return fmt.Errorf("tenant %q: verifier %q missing required field 'url'", t.ID, v.Name)
			}
			if verifierNames[v.Name] {
				return fmt.Errorf("tenant %q: duplicate verifier name %q", t.ID, v.Name)
			}
			verifierNames[v.Name] = true
		}
	}
	return nil
}

// --- API helpers ---

func fetchTenants(client *Client) ([]syncTenantResp, error) {
	data, err := client.Request("GET", "/admin/tenants", nil)
	if err != nil {
		return nil, err
	}
	var resp syncTenantsListResp
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse tenants response: %w", err)
	}
	return resp.Tenants, nil
}

func fetchIssuers(client *Client, tenantID string) ([]Issuer, error) {
	data, err := client.Request("GET", "/admin/tenants/"+tenantID+"/issuers", nil)
	if err != nil {
		return nil, err
	}
	var resp IssuerListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse issuers response: %w", err)
	}
	return resp.Issuers, nil
}

func fetchVerifiers(client *Client, tenantID string) ([]Verifier, error) {
	data, err := client.Request("GET", "/admin/tenants/"+tenantID+"/verifiers", nil)
	if err != nil {
		return nil, err
	}
	var resp VerifierListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse verifiers response: %w", err)
	}
	return resp.Verifiers, nil
}

// --- tenant sync ---

func tenantNeedsUpdate(desired SyncTenant, existing syncTenantResp) bool {
	if desired.Name != existing.Name {
		return true
	}
	if desired.DisplayName != existing.DisplayName {
		return true
	}
	desiredEnabled := true
	if desired.Enabled != nil {
		desiredEnabled = *desired.Enabled
	}
	if desiredEnabled != existing.Enabled {
		return true
	}
	// Check require_invite
	if desired.RequireInvite != nil && *desired.RequireInvite != existing.RequireInvite {
		return true
	}
	// Check trust config
	if desired.TrustConfig != nil {
		if existing.TrustConfig == nil {
			return true
		}
		if desired.TrustConfig.TrustEndpoint != existing.TrustConfig.TrustEndpoint {
			return true
		}
		if desired.TrustConfig.TrustTTL != nil && *desired.TrustConfig.TrustTTL != existing.TrustConfig.TrustTTL {
			return true
		}
	}
	// Check OIDC gate config
	if oidcGateNeedsUpdate(desired.OIDCGate, existing.OIDCGate) {
		return true
	}
	return false
}

// oidcGateNeedsUpdate checks if the OIDC gate configuration needs to be updated
func oidcGateNeedsUpdate(desired *SyncOIDCGate, existing *syncOIDCGateResp) bool {
	if desired == nil {
		return false // No desired config means no change
	}
	if existing == nil {
		return desired.Mode != "" && desired.Mode != "none"
	}
	if desired.Mode != existing.Mode {
		return true
	}
	if desired.BindIdentity != nil && *desired.BindIdentity != existing.BindIdentity {
		return true
	}
	if oidcProviderNeedsUpdate(desired.RegistrationOP, existing.RegistrationOP) {
		return true
	}
	if oidcProviderNeedsUpdate(desired.LoginOP, existing.LoginOP) {
		return true
	}
	return false
}

// oidcProviderNeedsUpdate checks if an OIDC provider configuration needs to be updated
func oidcProviderNeedsUpdate(desired *SyncOIDCProvider, existing *syncOIDCProviderResp) bool {
	if desired == nil && existing == nil {
		return false
	}
	if desired == nil || existing == nil {
		return true
	}
	if desired.Issuer != existing.Issuer {
		return true
	}
	if desired.ClientID != existing.ClientID {
		return true
	}
	if desired.DisplayName != existing.DisplayName {
		return true
	}
	if desired.Scopes != existing.Scopes {
		return true
	}
	if desired.JWKSURI != existing.JWKSURI {
		return true
	}
	if desired.Audience != existing.Audience {
		return true
	}
	return false
}

func buildTenantRequestBody(t SyncTenant) map[string]interface{} {
	enabled := true
	if t.Enabled != nil {
		enabled = *t.Enabled
	}
	body := map[string]interface{}{
		"id":      t.ID,
		"name":    t.Name,
		"enabled": enabled,
	}
	if t.DisplayName != "" {
		body["display_name"] = t.DisplayName
	}
	if t.RequireInvite != nil {
		body["require_invite"] = *t.RequireInvite
	}
	if t.TrustConfig != nil {
		tc := map[string]interface{}{}
		if t.TrustConfig.TrustEndpoint != "" {
			tc["trust_endpoint"] = t.TrustConfig.TrustEndpoint
		}
		if t.TrustConfig.TrustTTL != nil {
			tc["trust_ttl"] = *t.TrustConfig.TrustTTL
		}
		body["trust_config"] = tc
	}
	if t.OIDCGate != nil {
		body["oidc_gate"] = buildOIDCGateBody(t.OIDCGate)
	}
	return body
}

// buildOIDCGateBody builds the request body for OIDC gate configuration
func buildOIDCGateBody(gate *SyncOIDCGate) map[string]interface{} {
	body := map[string]interface{}{
		"mode": gate.Mode,
	}
	if gate.BindIdentity != nil {
		body["bind_identity"] = *gate.BindIdentity
	}
	if gate.RegistrationOP != nil {
		body["registration_op"] = buildOIDCProviderBody(gate.RegistrationOP)
	}
	if gate.LoginOP != nil {
		body["login_op"] = buildOIDCProviderBody(gate.LoginOP)
	}
	if len(gate.RequiredClaims) > 0 {
		body["required_claims"] = gate.RequiredClaims
	}
	return body
}

// buildOIDCProviderBody builds the request body for an OIDC provider configuration
func buildOIDCProviderBody(provider *SyncOIDCProvider) map[string]interface{} {
	body := map[string]interface{}{
		"issuer":    provider.Issuer,
		"client_id": provider.ClientID,
	}
	if provider.DisplayName != "" {
		body["display_name"] = provider.DisplayName
	}
	if provider.JWKSURI != "" {
		body["jwks_uri"] = provider.JWKSURI
	}
	if provider.Audience != "" {
		body["audience"] = provider.Audience
	}
	if provider.Scopes != "" {
		body["scopes"] = provider.Scopes
	}
	return body
}

func createTenantFromConfig(client *Client, t SyncTenant) error {
	_, err := client.Request("POST", "/admin/tenants", buildTenantRequestBody(t))
	return err
}

func updateTenantFromConfig(client *Client, t SyncTenant) error {
	_, err := client.Request("PUT", "/admin/tenants/"+t.ID, buildTenantRequestBody(t))
	return err
}

// --- issuer sync ---

func syncIssuers(client *Client, tenantID string, desired []SyncIssuer) ([]syncAction, error) {
	remote, err := fetchIssuers(client, tenantID)
	if err != nil {
		return nil, err
	}

	// Index remote by credential_issuer_identifier
	remoteByIdentifier := make(map[string]Issuer)
	for _, iss := range remote {
		remoteByIdentifier[iss.CredentialIssuerIdentifier] = iss
	}

	desiredIdentifiers := make(map[string]bool)
	var actions []syncAction

	for _, d := range desired {
		desiredIdentifiers[d.CredentialIssuerIdentifier] = true
		existing, exists := remoteByIdentifier[d.CredentialIssuerIdentifier]

		if !exists {
			actions = append(actions, syncAction{
				Kind:     "issuer",
				TenantID: tenantID,
				Name:     d.CredentialIssuerIdentifier,
				Action:   "create",
			})
			if !syncDryRun {
				if err := createIssuerFromConfig(client, tenantID, d); err != nil {
					return nil, err
				}
			}
		} else if issuerNeedsUpdate(d, existing) {
			actions = append(actions, syncAction{
				Kind:     "issuer",
				TenantID: tenantID,
				Name:     d.CredentialIssuerIdentifier,
				Action:   "update",
			})
			if !syncDryRun {
				if err := updateIssuerFromConfig(client, tenantID, existing.ID, d); err != nil {
					return nil, err
				}
			}
		} else {
			actions = append(actions, syncAction{
				Kind:     "issuer",
				TenantID: tenantID,
				Name:     d.CredentialIssuerIdentifier,
				Action:   "unchanged",
			})
		}
	}

	// Prune
	if syncPrune {
		for _, r := range remote {
			if !desiredIdentifiers[r.CredentialIssuerIdentifier] {
				actions = append(actions, syncAction{
					Kind:     "issuer",
					TenantID: tenantID,
					Name:     r.CredentialIssuerIdentifier,
					Action:   "delete",
				})
				if !syncDryRun {
					path := fmt.Sprintf("/admin/tenants/%s/issuers/%s", tenantID, strconv.FormatInt(r.ID, 10))
					if _, err := client.Request("DELETE", path, nil); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	return actions, nil
}

func issuerNeedsUpdate(desired SyncIssuer, existing Issuer) bool {
	if desired.ClientID != existing.ClientID {
		return true
	}
	desiredVisible := true
	if desired.Visible != nil {
		desiredVisible = *desired.Visible
	}
	if desiredVisible != existing.Visible {
		return true
	}
	return false
}

func createIssuerFromConfig(client *Client, tenantID string, iss SyncIssuer) error {
	visible := true
	if iss.Visible != nil {
		visible = *iss.Visible
	}
	body := map[string]interface{}{
		"credential_issuer_identifier": iss.CredentialIssuerIdentifier,
		"visible":                      visible,
	}
	if iss.ClientID != "" {
		body["client_id"] = iss.ClientID
	}
	_, err := client.Request("POST", "/admin/tenants/"+tenantID+"/issuers", body)
	return err
}

func updateIssuerFromConfig(client *Client, tenantID string, issuerID int64, iss SyncIssuer) error {
	visible := true
	if iss.Visible != nil {
		visible = *iss.Visible
	}
	body := map[string]interface{}{
		"credential_issuer_identifier": iss.CredentialIssuerIdentifier,
		"visible":                      visible,
	}
	if iss.ClientID != "" {
		body["client_id"] = iss.ClientID
	}
	path := fmt.Sprintf("/admin/tenants/%s/issuers/%s", tenantID, strconv.FormatInt(issuerID, 10))
	_, err := client.Request("PUT", path, body)
	return err
}

// --- verifier sync ---

func syncVerifiers(client *Client, tenantID string, desired []SyncVerifier) ([]syncAction, error) {
	remote, err := fetchVerifiers(client, tenantID)
	if err != nil {
		return nil, err
	}

	// Index remote by name
	remoteByName := make(map[string]Verifier)
	for _, v := range remote {
		remoteByName[v.Name] = v
	}

	desiredNames := make(map[string]bool)
	var actions []syncAction

	for _, d := range desired {
		desiredNames[d.Name] = true
		existing, exists := remoteByName[d.Name]

		if !exists {
			actions = append(actions, syncAction{
				Kind:     "verifier",
				TenantID: tenantID,
				Name:     d.Name,
				Action:   "create",
			})
			if !syncDryRun {
				if err := createVerifierFromConfig(client, tenantID, d); err != nil {
					return nil, err
				}
			}
		} else if verifierNeedsUpdate(d, existing) {
			actions = append(actions, syncAction{
				Kind:     "verifier",
				TenantID: tenantID,
				Name:     d.Name,
				Action:   "update",
			})
			if !syncDryRun {
				if err := updateVerifierFromConfig(client, tenantID, existing.ID, d); err != nil {
					return nil, err
				}
			}
		} else {
			actions = append(actions, syncAction{
				Kind:     "verifier",
				TenantID: tenantID,
				Name:     d.Name,
				Action:   "unchanged",
			})
		}
	}

	// Prune
	if syncPrune {
		for _, r := range remote {
			if !desiredNames[r.Name] {
				actions = append(actions, syncAction{
					Kind:     "verifier",
					TenantID: tenantID,
					Name:     r.Name,
					Action:   "delete",
				})
				if !syncDryRun {
					path := fmt.Sprintf("/admin/tenants/%s/verifiers/%s", tenantID, strconv.FormatInt(r.ID, 10))
					if _, err := client.Request("DELETE", path, nil); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	return actions, nil
}

func verifierNeedsUpdate(desired SyncVerifier, existing Verifier) bool {
	return desired.URL != existing.URL
}

func createVerifierFromConfig(client *Client, tenantID string, v SyncVerifier) error {
	body := map[string]interface{}{
		"name": v.Name,
		"url":  v.URL,
	}
	_, err := client.Request("POST", "/admin/tenants/"+tenantID+"/verifiers", body)
	return err
}

func updateVerifierFromConfig(client *Client, tenantID string, verifierID int64, v SyncVerifier) error {
	body := map[string]interface{}{
		"name": v.Name,
		"url":  v.URL,
	}
	path := fmt.Sprintf("/admin/tenants/%s/verifiers/%s", tenantID, strconv.FormatInt(verifierID, 10))
	_, err := client.Request("PUT", path, body)
	return err
}

// --- output ---

func printSyncSummary(actions []syncAction) {
	if len(actions) == 0 {
		fmt.Println("Nothing to do.")
		return
	}

	if syncDryRun {
		fmt.Println("Dry-run mode — no changes applied.")
		fmt.Println()
	}

	created, updated, deleted, unchanged := 0, 0, 0, 0
	for _, a := range actions {
		switch a.Action {
		case "create":
			created++
		case "update":
			updated++
		case "delete":
			deleted++
		case "unchanged":
			unchanged++
		}
		fmt.Println(a)
	}

	fmt.Println()
	fmt.Printf("Summary: %d created, %d updated, %d deleted, %d unchanged\n",
		created, updated, deleted, unchanged)
}
