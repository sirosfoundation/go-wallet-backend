package modes

import (
	"strings"
	"testing"
)

func TestRole_IsValid(t *testing.T) {
	tests := []struct {
		role  Role
		valid bool
	}{
		{RoleBackend, true},
		{RoleRegistry, true},
		{RoleAuth, true},
		{RoleStorage, true},
		{RoleAdmin, true},
		{RoleWalletProvider, true},
		{Role("invalid"), false},
		{Role(""), false},
	}

	for _, tt := range tests {
		if got := tt.role.IsValid(); got != tt.valid {
			t.Errorf("Role(%q).IsValid() = %v, want %v", tt.role, got, tt.valid)
		}
	}
}

func TestNewRoleSet(t *testing.T) {
	rs := NewRoleSet([]Role{RoleBackend, RoleRegistry})

	if !rs.Has(RoleBackend) {
		t.Error("expected Has(backend) = true")
	}
	if !rs.Has(RoleRegistry) {
		t.Error("expected Has(registry) = true")
	}
	if rs.Has(RoleAdmin) {
		t.Error("expected Has(admin) = false")
	}
}

func TestRoleSet_List(t *testing.T) {
	rs := NewRoleSet([]Role{RoleRegistry, RoleBackend})
	list := rs.List()

	if len(list) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(list))
	}
	// List() should return sorted
	if list[0] != RoleBackend {
		t.Errorf("list[0] = %q, want backend", list[0])
	}
	if list[1] != RoleRegistry {
		t.Errorf("list[1] = %q, want registry", list[1])
	}
}

func TestRoleSet_Strings(t *testing.T) {
	rs := NewRoleSet([]Role{RoleAdmin, RoleBackend})
	strs := rs.Strings()

	if len(strs) != 2 {
		t.Fatalf("expected 2 strings, got %d", len(strs))
	}
	if strs[0] != "admin" {
		t.Errorf("strs[0] = %q, want admin", strs[0])
	}
}

func TestParseRoles(t *testing.T) {
	t.Run("single role", func(t *testing.T) {
		rs, err := ParseRoles("backend")
		if err != nil {
			t.Fatalf("ParseRoles: %v", err)
		}
		if !rs.Has(RoleBackend) {
			t.Error("expected backend role")
		}
	})

	t.Run("multiple roles", func(t *testing.T) {
		rs, err := ParseRoles("backend,registry,admin")
		if err != nil {
			t.Fatalf("ParseRoles: %v", err)
		}
		if !rs.Has(RoleBackend) || !rs.Has(RoleRegistry) || !rs.Has(RoleAdmin) {
			t.Error("missing expected roles")
		}
	})

	t.Run("all shorthand", func(t *testing.T) {
		rs, err := ParseRoles("all")
		if err != nil {
			t.Fatalf("ParseRoles: %v", err)
		}
		for _, role := range ValidRoles {
			if !rs.Has(role) {
				t.Errorf("all should include %s", role)
			}
		}
	})

	t.Run("all within list", func(t *testing.T) {
		rs, err := ParseRoles("all,wallet-provider")
		if err != nil {
			t.Fatalf("ParseRoles: %v", err)
		}
		if !rs.Has(RoleWalletProvider) {
			t.Error("expected wallet-provider")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := ParseRoles("")
		if err == nil {
			t.Error("expected error for empty string")
		}
	})

	t.Run("invalid role", func(t *testing.T) {
		_, err := ParseRoles("invalid-role")
		if err == nil {
			t.Error("expected error for invalid role")
		}
	})

	t.Run("duplicate roles", func(t *testing.T) {
		rs, err := ParseRoles("backend,backend,registry")
		if err != nil {
			t.Fatalf("ParseRoles: %v", err)
		}
		if len(rs.List()) != 2 {
			t.Errorf("expected 2 unique roles, got %d", len(rs.List()))
		}
	})

	t.Run("whitespace handling", func(t *testing.T) {
		rs, err := ParseRoles(" backend , registry ")
		if err != nil {
			t.Fatalf("ParseRoles: %v", err)
		}
		if !rs.Has(RoleBackend) || !rs.Has(RoleRegistry) {
			t.Error("expected whitespace-trimmed roles")
		}
	})
}

func TestParseRoles_EngineRoleWasRemoved(t *testing.T) {
	for _, mode := range []string{"engine", "backend,engine", "all,engine"} {
		_, err := ParseRoles(mode)
		if err == nil || !strings.Contains(err.Error(), "was removed") {
			t.Errorf("ParseRoles(%q) error = %v, want a removal error", mode, err)
		}
	}
	rs, err := ParseRoles("all")
	if err != nil {
		t.Fatalf("ParseRoles(all): %v", err)
	}
	for _, r := range rs.List() {
		if r == removedRoleEngine {
			t.Error(`"all" must not include the removed engine role`)
		}
	}
}
