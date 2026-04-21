// Package modes defines operating roles for the hybrid wallet-backend binary.
//
// Roles can be combined via comma-separated list:
//
//	--mode=backend              (just backend)
//	--mode=backend,engine       (backend + websocket)
//	--mode=all                  (all roles)
package modes

import (
	"fmt"
	"sort"
	"strings"
)

// Role represents a single operating role for the hybrid binary
type Role string

const (
	RoleBackend  Role = "backend"
	RoleRegistry Role = "registry"
	RoleEngine   Role = "engine"
	RoleAuth     Role = "auth"
	RoleStorage  Role = "storage"
	RoleAdmin    Role = "admin"
)

// ValidRoles lists all valid operating roles
var ValidRoles = []Role{RoleBackend, RoleRegistry, RoleEngine, RoleAuth, RoleStorage, RoleAdmin}

// IsValid checks if a role string is valid
func (r Role) IsValid() bool {
	for _, valid := range ValidRoles {
		if r == valid {
			return true
		}
	}
	return false
}

// RoleSet represents a set of active roles
type RoleSet struct {
	roles map[Role]bool
}

// NewRoleSet creates a new role set from a list of roles
func NewRoleSet(roles []Role) *RoleSet {
	rs := &RoleSet{roles: make(map[Role]bool)}
	for _, r := range roles {
		rs.roles[r] = true
	}
	return rs
}

// Has checks if a role is in the set
func (rs *RoleSet) Has(role Role) bool {
	return rs.roles[role]
}

// List returns the roles as a sorted slice
func (rs *RoleSet) List() []Role {
	roles := make([]Role, 0, len(rs.roles))
	for r := range rs.roles {
		roles = append(roles, r)
	}
	sort.Slice(roles, func(i, j int) bool {
		return roles[i] < roles[j]
	})
	return roles
}

// Strings returns the roles as a sorted string slice (for JSON serialization)
func (rs *RoleSet) Strings() []string {
	roles := rs.List()
	strs := make([]string, len(roles))
	for i, r := range roles {
		strs[i] = string(r)
	}
	return strs
}

// ParseRoles parses a comma-separated mode string into a RoleSet
// Supports "all" as a shorthand for all roles
func ParseRoles(s string) (*RoleSet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("mode cannot be empty")
	}

	// Handle "all" as a special case
	if s == "all" {
		return NewRoleSet([]Role{RoleBackend, RoleRegistry, RoleEngine, RoleAdmin}), nil
	}

	parts := strings.Split(s, ",")
	roles := make([]Role, 0, len(parts))
	seen := make(map[Role]bool)

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		// Handle "all" within a list
		if p == "all" {
			for _, r := range ValidRoles {
				if !seen[r] {
					roles = append(roles, r)
					seen[r] = true
				}
			}
			continue
		}

		role := Role(p)
		if !role.IsValid() {
			return nil, fmt.Errorf("invalid role %q, valid roles: %v", p, ValidRoles)
		}
		if !seen[role] {
			roles = append(roles, role)
			seen[role] = true
		}
	}

	if len(roles) == 0 {
		return nil, fmt.Errorf("no valid roles specified")
	}

	return NewRoleSet(roles), nil
}
