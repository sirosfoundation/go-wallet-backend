package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// --- loadSyncConfig tests ---

func TestLoadSyncConfig(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		path := writeTempYAML(t, `
tenants:
  - id: test-tenant
    name: Test Tenant
    display_name: Test
    enabled: true
    issuers:
      - credential_issuer_identifier: https://issuer.example.com
        client_id: my-client
        visible: true
    verifiers:
      - name: My Verifier
        url: https://verifier.example.com
`)
		cfg, err := loadSyncConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.Tenants) != 1 {
			t.Fatalf("expected 1 tenant, got %d", len(cfg.Tenants))
		}
		if cfg.Tenants[0].ID != "test-tenant" {
			t.Errorf("expected id 'test-tenant', got %q", cfg.Tenants[0].ID)
		}
		if cfg.Tenants[0].Name != "Test Tenant" {
			t.Errorf("expected name 'Test Tenant', got %q", cfg.Tenants[0].Name)
		}
		if len(cfg.Tenants[0].Issuers) != 1 {
			t.Fatalf("expected 1 issuer, got %d", len(cfg.Tenants[0].Issuers))
		}
		if cfg.Tenants[0].Issuers[0].CredentialIssuerIdentifier != "https://issuer.example.com" {
			t.Errorf("unexpected issuer identifier: %q", cfg.Tenants[0].Issuers[0].CredentialIssuerIdentifier)
		}
		if len(cfg.Tenants[0].Verifiers) != 1 {
			t.Fatalf("expected 1 verifier, got %d", len(cfg.Tenants[0].Verifiers))
		}
	})

	t.Run("config with trust_config", func(t *testing.T) {
		path := writeTempYAML(t, `
tenants:
  - id: t1
    name: T1
    trust_config:
      trust_endpoint: https://trust.example.com
      trust_ttl: 3600
`)
		cfg, err := loadSyncConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tc := cfg.Tenants[0].TrustConfig
		if tc == nil {
			t.Fatal("expected trust_config to be set")
		}
		if tc.TrustEndpoint != "https://trust.example.com" {
			t.Errorf("unexpected trust_endpoint: %q", tc.TrustEndpoint)
		}
		if tc.TrustTTL == nil || *tc.TrustTTL != 3600 {
			t.Errorf("expected trust_ttl 3600, got %v", tc.TrustTTL)
		}
	})

	t.Run("enabled defaults to nil (not set)", func(t *testing.T) {
		path := writeTempYAML(t, `
tenants:
  - id: t1
    name: T1
`)
		cfg, err := loadSyncConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Tenants[0].Enabled != nil {
			t.Error("expected Enabled to be nil when not specified")
		}
	})

	t.Run("explicit enabled false", func(t *testing.T) {
		path := writeTempYAML(t, `
tenants:
  - id: t1
    name: T1
    enabled: false
`)
		cfg, err := loadSyncConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Tenants[0].Enabled == nil || *cfg.Tenants[0].Enabled != false {
			t.Error("expected Enabled to be false")
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := loadSyncConfig("/tmp/this-file-does-not-exist-12345.yaml")
		if err == nil {
			t.Error("expected error for non-existent file")
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		path := writeTempYAML(t, `
tenants:
  - id: [[[broken
`)
		_, err := loadSyncConfig(path)
		if err == nil {
			t.Error("expected error for invalid YAML")
		}
	})

	t.Run("multiple tenants with issuers and verifiers", func(t *testing.T) {
		path := writeTempYAML(t, `
tenants:
  - id: tenant-a
    name: Tenant A
    issuers:
      - credential_issuer_identifier: https://issuer-a.example.com
      - credential_issuer_identifier: https://issuer-b.example.com
    verifiers:
      - name: Verifier A
        url: https://va.example.com
  - id: tenant-b
    name: Tenant B
    verifiers:
      - name: Verifier B
        url: https://vb.example.com
`)
		cfg, err := loadSyncConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.Tenants) != 2 {
			t.Fatalf("expected 2 tenants, got %d", len(cfg.Tenants))
		}
		if len(cfg.Tenants[0].Issuers) != 2 {
			t.Errorf("expected 2 issuers in tenant-a, got %d", len(cfg.Tenants[0].Issuers))
		}
		if len(cfg.Tenants[1].Verifiers) != 1 {
			t.Errorf("expected 1 verifier in tenant-b, got %d", len(cfg.Tenants[1].Verifiers))
		}
	})
}

// --- validateSyncConfig tests ---

func TestValidateSyncConfig(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := &SyncConfig{
			Tenants: []SyncTenant{
				{ID: "t1", Name: "Tenant 1"},
			},
		}
		if err := validateSyncConfig(cfg); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("no tenants", func(t *testing.T) {
		cfg := &SyncConfig{}
		if err := validateSyncConfig(cfg); err == nil {
			t.Error("expected error for empty tenants")
		}
	})

	t.Run("missing tenant id", func(t *testing.T) {
		cfg := &SyncConfig{
			Tenants: []SyncTenant{{Name: "No ID"}},
		}
		if err := validateSyncConfig(cfg); err == nil {
			t.Error("expected error for missing tenant ID")
		}
	})

	t.Run("missing tenant name", func(t *testing.T) {
		cfg := &SyncConfig{
			Tenants: []SyncTenant{{ID: "t1"}},
		}
		if err := validateSyncConfig(cfg); err == nil {
			t.Error("expected error for missing tenant name")
		}
	})

	t.Run("duplicate tenant id", func(t *testing.T) {
		cfg := &SyncConfig{
			Tenants: []SyncTenant{
				{ID: "dup", Name: "First"},
				{ID: "dup", Name: "Second"},
			},
		}
		if err := validateSyncConfig(cfg); err == nil {
			t.Error("expected error for duplicate tenant ID")
		}
	})

	t.Run("missing issuer identifier", func(t *testing.T) {
		cfg := &SyncConfig{
			Tenants: []SyncTenant{
				{ID: "t1", Name: "T1", Issuers: []SyncIssuer{{}}},
			},
		}
		if err := validateSyncConfig(cfg); err == nil {
			t.Error("expected error for missing issuer identifier")
		}
	})

	t.Run("duplicate issuer identifier", func(t *testing.T) {
		cfg := &SyncConfig{
			Tenants: []SyncTenant{
				{ID: "t1", Name: "T1", Issuers: []SyncIssuer{
					{CredentialIssuerIdentifier: "https://iss.example.com"},
					{CredentialIssuerIdentifier: "https://iss.example.com"},
				}},
			},
		}
		if err := validateSyncConfig(cfg); err == nil {
			t.Error("expected error for duplicate issuer identifier")
		}
	})

	t.Run("missing verifier name", func(t *testing.T) {
		cfg := &SyncConfig{
			Tenants: []SyncTenant{
				{ID: "t1", Name: "T1", Verifiers: []SyncVerifier{{URL: "https://v.example.com"}}},
			},
		}
		if err := validateSyncConfig(cfg); err == nil {
			t.Error("expected error for missing verifier name")
		}
	})

	t.Run("missing verifier url", func(t *testing.T) {
		cfg := &SyncConfig{
			Tenants: []SyncTenant{
				{ID: "t1", Name: "T1", Verifiers: []SyncVerifier{{Name: "V"}}},
			},
		}
		if err := validateSyncConfig(cfg); err == nil {
			t.Error("expected error for missing verifier URL")
		}
	})

	t.Run("duplicate verifier name", func(t *testing.T) {
		cfg := &SyncConfig{
			Tenants: []SyncTenant{
				{ID: "t1", Name: "T1", Verifiers: []SyncVerifier{
					{Name: "V", URL: "https://v1.example.com"},
					{Name: "V", URL: "https://v2.example.com"},
				}},
			},
		}
		if err := validateSyncConfig(cfg); err == nil {
			t.Error("expected error for duplicate verifier name")
		}
	})
}

// --- tenantNeedsUpdate tests ---

func TestTenantNeedsUpdate(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	t.Run("same values no update", func(t *testing.T) {
		desired := SyncTenant{ID: "t1", Name: "T1", DisplayName: "T1 Display", Enabled: boolPtr(true)}
		existing := syncTenantResp{ID: "t1", Name: "T1", DisplayName: "T1 Display", Enabled: true}
		if tenantNeedsUpdate(desired, existing) {
			t.Error("expected no update needed")
		}
	})

	t.Run("name changed", func(t *testing.T) {
		desired := SyncTenant{ID: "t1", Name: "New Name"}
		existing := syncTenantResp{ID: "t1", Name: "Old Name"}
		if !tenantNeedsUpdate(desired, existing) {
			t.Error("expected update needed for name change")
		}
	})

	t.Run("display_name changed", func(t *testing.T) {
		desired := SyncTenant{ID: "t1", Name: "T1", DisplayName: "New Display"}
		existing := syncTenantResp{ID: "t1", Name: "T1", DisplayName: "Old Display"}
		if !tenantNeedsUpdate(desired, existing) {
			t.Error("expected update needed for display_name change")
		}
	})

	t.Run("enabled changed", func(t *testing.T) {
		desired := SyncTenant{ID: "t1", Name: "T1", Enabled: boolPtr(false)}
		existing := syncTenantResp{ID: "t1", Name: "T1", Enabled: true}
		if !tenantNeedsUpdate(desired, existing) {
			t.Error("expected update needed for enabled change")
		}
	})

	t.Run("enabled nil defaults to true matches existing true", func(t *testing.T) {
		desired := SyncTenant{ID: "t1", Name: "T1"}
		existing := syncTenantResp{ID: "t1", Name: "T1", Enabled: true}
		if tenantNeedsUpdate(desired, existing) {
			t.Error("expected no update: nil enabled should default to true")
		}
	})

	t.Run("trust_config added", func(t *testing.T) {
		desired := SyncTenant{ID: "t1", Name: "T1", TrustConfig: &SyncTrustConfig{TrustEndpoint: "https://trust.example.com"}}
		existing := syncTenantResp{ID: "t1", Name: "T1"}
		if !tenantNeedsUpdate(desired, existing) {
			t.Error("expected update needed when trust_config added")
		}
	})

	t.Run("trust_config endpoint changed", func(t *testing.T) {
		desired := SyncTenant{ID: "t1", Name: "T1", TrustConfig: &SyncTrustConfig{TrustEndpoint: "https://new-trust.example.com"}}
		existing := syncTenantResp{ID: "t1", Name: "T1", TrustConfig: &syncTrustConfigResp{TrustEndpoint: "https://old-trust.example.com"}}
		if !tenantNeedsUpdate(desired, existing) {
			t.Error("expected update needed for trust_endpoint change")
		}
	})

	t.Run("trust_config ttl changed", func(t *testing.T) {
		ttl := 7200
		desired := SyncTenant{ID: "t1", Name: "T1", TrustConfig: &SyncTrustConfig{TrustTTL: &ttl}}
		existing := syncTenantResp{ID: "t1", Name: "T1", TrustConfig: &syncTrustConfigResp{TrustTTL: 3600}}
		if !tenantNeedsUpdate(desired, existing) {
			t.Error("expected update needed for trust_ttl change")
		}
	})

	t.Run("require_invite changed true to false", func(t *testing.T) {
		desired := SyncTenant{ID: "t1", Name: "T1", RequireInvite: boolPtr(false)}
		existing := syncTenantResp{ID: "t1", Name: "T1", Enabled: true, RequireInvite: true}
		if !tenantNeedsUpdate(desired, existing) {
			t.Error("expected update needed for require_invite change")
		}
	})

	t.Run("require_invite changed false to true", func(t *testing.T) {
		desired := SyncTenant{ID: "t1", Name: "T1", RequireInvite: boolPtr(true)}
		existing := syncTenantResp{ID: "t1", Name: "T1", Enabled: true, RequireInvite: false}
		if !tenantNeedsUpdate(desired, existing) {
			t.Error("expected update needed for require_invite change")
		}
	})

	t.Run("require_invite nil does not trigger update", func(t *testing.T) {
		// When require_invite is nil in config, we don't manage it - no update needed
		desired := SyncTenant{ID: "t1", Name: "T1", RequireInvite: nil}
		existing := syncTenantResp{ID: "t1", Name: "T1", Enabled: true, RequireInvite: true}
		if tenantNeedsUpdate(desired, existing) {
			t.Error("expected no update: nil require_invite means 'do not manage'")
		}
	})

	t.Run("require_invite matches existing", func(t *testing.T) {
		desired := SyncTenant{ID: "t1", Name: "T1", RequireInvite: boolPtr(true)}
		existing := syncTenantResp{ID: "t1", Name: "T1", Enabled: true, RequireInvite: true}
		if tenantNeedsUpdate(desired, existing) {
			t.Error("expected no update: require_invite matches")
		}
	})
}

// --- issuerNeedsUpdate tests ---

func TestIssuerNeedsUpdate(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	t.Run("same values no update", func(t *testing.T) {
		desired := SyncIssuer{CredentialIssuerIdentifier: "https://iss.example.com", ClientID: "cid", Visible: boolPtr(true)}
		existing := Issuer{CredentialIssuerIdentifier: "https://iss.example.com", ClientID: "cid", Visible: true}
		if issuerNeedsUpdate(desired, existing) {
			t.Error("expected no update needed")
		}
	})

	t.Run("client_id changed", func(t *testing.T) {
		desired := SyncIssuer{CredentialIssuerIdentifier: "https://iss.example.com", ClientID: "new-cid"}
		existing := Issuer{CredentialIssuerIdentifier: "https://iss.example.com", ClientID: "old-cid"}
		if !issuerNeedsUpdate(desired, existing) {
			t.Error("expected update needed for client_id change")
		}
	})

	t.Run("visible changed", func(t *testing.T) {
		desired := SyncIssuer{CredentialIssuerIdentifier: "https://iss.example.com", Visible: boolPtr(false)}
		existing := Issuer{CredentialIssuerIdentifier: "https://iss.example.com", Visible: true}
		if !issuerNeedsUpdate(desired, existing) {
			t.Error("expected update needed for visible change")
		}
	})

	t.Run("nil visible defaults to true", func(t *testing.T) {
		desired := SyncIssuer{CredentialIssuerIdentifier: "https://iss.example.com"}
		existing := Issuer{CredentialIssuerIdentifier: "https://iss.example.com", Visible: true}
		if issuerNeedsUpdate(desired, existing) {
			t.Error("expected no update: nil visible should default to true")
		}
	})
}

// --- verifierNeedsUpdate tests ---

func TestVerifierNeedsUpdate(t *testing.T) {
	t.Run("same values no update", func(t *testing.T) {
		desired := SyncVerifier{Name: "V", URL: "https://v.example.com"}
		existing := Verifier{Name: "V", URL: "https://v.example.com"}
		if verifierNeedsUpdate(desired, existing) {
			t.Error("expected no update needed")
		}
	})

	t.Run("url changed", func(t *testing.T) {
		desired := SyncVerifier{Name: "V", URL: "https://new-v.example.com"}
		existing := Verifier{Name: "V", URL: "https://old-v.example.com"}
		if !verifierNeedsUpdate(desired, existing) {
			t.Error("expected update needed for URL change")
		}
	})
}

// --- buildTenantRequestBody tests ---

func TestBuildTenantRequestBody(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	intPtr := func(i int) *int { return &i }

	t.Run("minimal tenant", func(t *testing.T) {
		body := buildTenantRequestBody(SyncTenant{ID: "t1", Name: "T1"})
		if body["id"] != "t1" {
			t.Errorf("expected id 't1', got %v", body["id"])
		}
		if body["name"] != "T1" {
			t.Errorf("expected name 'T1', got %v", body["name"])
		}
		if body["enabled"] != true {
			t.Errorf("expected enabled true, got %v", body["enabled"])
		}
		if _, ok := body["display_name"]; ok {
			t.Error("display_name should not be set when empty")
		}
		if _, ok := body["trust_config"]; ok {
			t.Error("trust_config should not be set when nil")
		}
	})

	t.Run("full tenant", func(t *testing.T) {
		body := buildTenantRequestBody(SyncTenant{
			ID:          "t1",
			Name:        "T1",
			DisplayName: "Full Tenant",
			Enabled:     boolPtr(false),
			TrustConfig: &SyncTrustConfig{
				TrustEndpoint: "https://trust.example.com",
				TrustTTL:      intPtr(7200),
			},
		})
		if body["enabled"] != false {
			t.Errorf("expected enabled false, got %v", body["enabled"])
		}
		if body["display_name"] != "Full Tenant" {
			t.Errorf("expected display_name 'Full Tenant', got %v", body["display_name"])
		}
		tc, ok := body["trust_config"].(map[string]interface{})
		if !ok {
			t.Fatal("expected trust_config to be a map")
		}
		if tc["trust_endpoint"] != "https://trust.example.com" {
			t.Errorf("unexpected trust_endpoint: %v", tc["trust_endpoint"])
		}
		if tc["trust_ttl"] != 7200 {
			t.Errorf("expected trust_ttl 7200, got %v", tc["trust_ttl"])
		}
	})

	t.Run("require_invite true", func(t *testing.T) {
		body := buildTenantRequestBody(SyncTenant{ID: "t1", Name: "T1", RequireInvite: boolPtr(true)})
		if body["require_invite"] != true {
			t.Errorf("expected require_invite true, got %v", body["require_invite"])
		}
	})

	t.Run("require_invite false", func(t *testing.T) {
		body := buildTenantRequestBody(SyncTenant{ID: "t1", Name: "T1", RequireInvite: boolPtr(false)})
		if body["require_invite"] != false {
			t.Errorf("expected require_invite false, got %v", body["require_invite"])
		}
	})

	t.Run("require_invite nil - omitted from body", func(t *testing.T) {
		body := buildTenantRequestBody(SyncTenant{ID: "t1", Name: "T1", RequireInvite: nil})
		if _, ok := body["require_invite"]; ok {
			t.Error("require_invite should not be set when nil")
		}
	})

	t.Run("oidc_gate with registration mode", func(t *testing.T) {
		body := buildTenantRequestBody(SyncTenant{
			ID:   "t1",
			Name: "T1",
			OIDCGate: &SyncOIDCGate{
				Mode:         "registration",
				BindIdentity: boolPtr(true),
				RegistrationOP: &SyncOIDCProvider{
					Issuer:      "https://idp.example.com",
					ClientID:    "wallet-reg",
					DisplayName: "Corporate SSO",
					Scopes:      "openid profile email groups",
				},
			},
		})
		gate, ok := body["oidc_gate"].(map[string]interface{})
		if !ok {
			t.Fatal("expected oidc_gate to be a map")
		}
		if gate["mode"] != "registration" {
			t.Errorf("expected mode 'registration', got %v", gate["mode"])
		}
		if gate["bind_identity"] != true {
			t.Errorf("expected bind_identity true, got %v", gate["bind_identity"])
		}
		regOP, ok := gate["registration_op"].(map[string]interface{})
		if !ok {
			t.Fatal("expected registration_op to be a map")
		}
		if regOP["issuer"] != "https://idp.example.com" {
			t.Errorf("unexpected issuer: %v", regOP["issuer"])
		}
		if regOP["client_id"] != "wallet-reg" {
			t.Errorf("unexpected client_id: %v", regOP["client_id"])
		}
		if regOP["display_name"] != "Corporate SSO" {
			t.Errorf("unexpected display_name: %v", regOP["display_name"])
		}
	})

	t.Run("oidc_gate with both mode", func(t *testing.T) {
		body := buildTenantRequestBody(SyncTenant{
			ID:   "t1",
			Name: "T1",
			OIDCGate: &SyncOIDCGate{
				Mode: "both",
				RegistrationOP: &SyncOIDCProvider{
					Issuer:   "https://idp.example.com/realms/reg",
					ClientID: "wallet-reg",
				},
				LoginOP: &SyncOIDCProvider{
					Issuer:   "https://idp.example.com/realms/login",
					ClientID: "wallet-login",
				},
			},
		})
		gate, ok := body["oidc_gate"].(map[string]interface{})
		if !ok {
			t.Fatal("expected oidc_gate to be a map")
		}
		if gate["mode"] != "both" {
			t.Errorf("expected mode 'both', got %v", gate["mode"])
		}
		if _, ok := gate["registration_op"]; !ok {
			t.Error("expected registration_op to be set")
		}
		if _, ok := gate["login_op"]; !ok {
			t.Error("expected login_op to be set")
		}
	})

	t.Run("oidc_gate with required_claims", func(t *testing.T) {
		body := buildTenantRequestBody(SyncTenant{
			ID:   "t1",
			Name: "T1",
			OIDCGate: &SyncOIDCGate{
				Mode:           "registration",
				RequiredClaims: map[string]any{"email_verified": true, "groups": "staff"},
				RegistrationOP: &SyncOIDCProvider{
					Issuer:   "https://idp.example.com",
					ClientID: "wallet-reg",
				},
			},
		})
		gate, ok := body["oidc_gate"].(map[string]interface{})
		if !ok {
			t.Fatal("expected oidc_gate to be a map")
		}
		reqClaims, ok := gate["required_claims"].(map[string]any)
		if !ok {
			t.Fatal("expected required_claims to be a map")
		}
		if reqClaims["email_verified"] != true {
			t.Errorf("expected email_verified true, got %v", reqClaims["email_verified"])
		}
		if reqClaims["groups"] != "staff" {
			t.Errorf("expected groups 'staff', got %v", reqClaims["groups"])
		}
	})

	t.Run("oidc_gate nil - omitted from body", func(t *testing.T) {
		body := buildTenantRequestBody(SyncTenant{ID: "t1", Name: "T1", OIDCGate: nil})
		if _, ok := body["oidc_gate"]; ok {
			t.Error("oidc_gate should not be set when nil")
		}
	})
}

// --- OIDC gate update detection tests ---

func TestOIDCGateNeedsUpdate(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	t.Run("nil desired returns false", func(t *testing.T) {
		if oidcGateNeedsUpdate(nil, nil) {
			t.Error("nil desired should return false")
		}
		if oidcGateNeedsUpdate(nil, &syncOIDCGateResp{Mode: "registration"}) {
			t.Error("nil desired with existing should return false")
		}
	})

	t.Run("mode changed", func(t *testing.T) {
		desired := &SyncOIDCGate{Mode: "both"}
		existing := &syncOIDCGateResp{Mode: "registration"}
		if !oidcGateNeedsUpdate(desired, existing) {
			t.Error("mode change should trigger update")
		}
	})

	t.Run("bind_identity changed", func(t *testing.T) {
		desired := &SyncOIDCGate{Mode: "registration", BindIdentity: boolPtr(true)}
		existing := &syncOIDCGateResp{Mode: "registration", BindIdentity: false}
		if !oidcGateNeedsUpdate(desired, existing) {
			t.Error("bind_identity change should trigger update")
		}
	})

	t.Run("same values no update", func(t *testing.T) {
		desired := &SyncOIDCGate{
			Mode: "registration",
			RegistrationOP: &SyncOIDCProvider{
				Issuer:   "https://idp.example.com",
				ClientID: "wallet-reg",
			},
		}
		existing := &syncOIDCGateResp{
			Mode: "registration",
			RegistrationOP: &syncOIDCProviderResp{
				Issuer:   "https://idp.example.com",
				ClientID: "wallet-reg",
			},
		}
		if oidcGateNeedsUpdate(desired, existing) {
			t.Error("same values should not trigger update")
		}
	})

	t.Run("provider issuer changed", func(t *testing.T) {
		desired := &SyncOIDCGate{
			Mode: "registration",
			RegistrationOP: &SyncOIDCProvider{
				Issuer:   "https://new-idp.example.com",
				ClientID: "wallet-reg",
			},
		}
		existing := &syncOIDCGateResp{
			Mode: "registration",
			RegistrationOP: &syncOIDCProviderResp{
				Issuer:   "https://idp.example.com",
				ClientID: "wallet-reg",
			},
		}
		if !oidcGateNeedsUpdate(desired, existing) {
			t.Error("issuer change should trigger update")
		}
	})

	t.Run("required_claims changed", func(t *testing.T) {
		desired := &SyncOIDCGate{
			Mode:           "registration",
			RequiredClaims: map[string]any{"email_verified": true},
		}
		existing := &syncOIDCGateResp{
			Mode:           "registration",
			RequiredClaims: map[string]any{"email_verified": false},
		}
		if !oidcGateNeedsUpdate(desired, existing) {
			t.Error("required_claims change should trigger update")
		}
	})

	t.Run("required_claims added", func(t *testing.T) {
		desired := &SyncOIDCGate{
			Mode:           "registration",
			RequiredClaims: map[string]any{"groups": "admins"},
		}
		existing := &syncOIDCGateResp{
			Mode: "registration",
		}
		if !oidcGateNeedsUpdate(desired, existing) {
			t.Error("adding required_claims should trigger update")
		}
	})

	t.Run("same required_claims no update", func(t *testing.T) {
		desired := &SyncOIDCGate{
			Mode:           "registration",
			RequiredClaims: map[string]any{"email_verified": true},
		}
		existing := &syncOIDCGateResp{
			Mode:           "registration",
			RequiredClaims: map[string]any{"email_verified": true},
		}
		if oidcGateNeedsUpdate(desired, existing) {
			t.Error("same required_claims should not trigger update")
		}
	})
}

func TestSyncActionString(t *testing.T) {
	tests := []struct {
		action   syncAction
		expected string
	}{
		{
			action:   syncAction{Kind: "tenant", Name: "t1", Action: "create"},
			expected: "  + tenant t1",
		},
		{
			action:   syncAction{Kind: "tenant", Name: "t1", Action: "update"},
			expected: "  ~ tenant t1",
		},
		{
			action:   syncAction{Kind: "tenant", Name: "t1", Action: "delete"},
			expected: "  - tenant t1",
		},
		{
			action:   syncAction{Kind: "tenant", Name: "t1", Action: "unchanged"},
			expected: "    tenant t1",
		},
		{
			action:   syncAction{Kind: "issuer", TenantID: "t1", Name: "https://iss.example.com", Action: "create"},
			expected: "  + issuer t1/https://iss.example.com",
		},
		{
			action:   syncAction{Kind: "verifier", TenantID: "t1", Name: "My Verifier", Action: "delete"},
			expected: "  - verifier t1/My Verifier",
		},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.action.String()
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

// --- helpers ---

func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}
