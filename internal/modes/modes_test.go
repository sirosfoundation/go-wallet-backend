package modes

import (
	"testing"
)

func TestRole_IsValid(t *testing.T) {
	tests := []struct {
		role  Role
		valid bool
	}{
		{RoleBackend, true},
		{RoleRegistry, true},
		{RoleEngine, true},
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
	rs := NewRoleSet([]Role{RoleBackend, RoleEngine})

	if !rs.Has(RoleBackend) {
		t.Error("expected Has(backend) = true")
	}
	if !rs.Has(RoleEngine) {
		t.Error("expected Has(engine) = true")
	}
	if rs.Has(RoleAdmin) {
		t.Error("expected Has(admin) = false")
	}
}

func TestRoleSet_List(t *testing.T) {
	rs := NewRoleSet([]Role{RoleEngine, RoleBackend})
	list := rs.List()

	if len(list) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(list))
	}
	// List() should return sorted
	if list[0] != RoleBackend {
		t.Errorf("list[0] = %q, want backend", list[0])
	}
	if list[1] != RoleEngine {
		t.Errorf("list[1] = %q, want engine", list[1])
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
		rs, err := ParseRoles("backend,engine,admin")
		if err != nil {
			t.Fatalf("ParseRoles: %v", err)
		}
		if !rs.Has(RoleBackend) || !rs.Has(RoleEngine) || !rs.Has(RoleAdmin) {
			t.Error("missing expected roles")
		}
	})

	t.Run("all shorthand", func(t *testing.T) {
		rs, err := ParseRoles("all")
		if err != nil {
			t.Fatalf("ParseRoles: %v", err)
		}
		if !rs.Has(RoleBackend) || !rs.Has(RoleEngine) || !rs.Has(RoleAdmin) {
			t.Error("all should include backend, engine, admin")
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
		rs, err := ParseRoles("backend,backend,engine")
		if err != nil {
			t.Fatalf("ParseRoles: %v", err)
		}
		if len(rs.List()) != 2 {
			t.Errorf("expected 2 unique roles, got %d", len(rs.List()))
		}
	})

	t.Run("whitespace handling", func(t *testing.T) {
		rs, err := ParseRoles(" backend , engine ")
		if err != nil {
			t.Fatalf("ParseRoles: %v", err)
		}
		if !rs.Has(RoleBackend) || !rs.Has(RoleEngine) {
			t.Error("expected whitespace-trimmed roles")
		}
	})
}
