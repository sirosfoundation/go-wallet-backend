// Package modes provides the mode dispatcher for the hybrid binary.
// The wallet-backend binary can run in different modes (roles):
// - backend: runs the wallet backend API server
// - registry: runs the VCTM registry server
// - engine: runs the WebSocket v2 engine
//
// Roles can be combined via comma-separated list:
// - --mode=backend (just backend)
// - --mode=backend,engine (backend + websocket)
// - --mode=backend,registry,engine (all roles)
package modes

import (
	"context"
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
)

// ValidRoles lists all valid operating roles
var ValidRoles = []Role{RoleBackend, RoleRegistry, RoleEngine, RoleAuth, RoleStorage}

// IsValid checks if a role string is valid
func (r Role) IsValid() bool {
	for _, valid := range ValidRoles {
		if r == valid {
			return true
		}
	}
	return false
}

// Mode is a deprecated alias for Role, kept for backward compatibility
type Mode = Role

// Deprecated mode constants - use Role constants instead
const (
	ModeAll      Mode = "all" // Special: expands to all roles
	ModeBackend  Mode = RoleBackend
	ModeRegistry Mode = RoleRegistry
	ModeEngine   Mode = RoleEngine
)

// ValidModes is deprecated, use ValidRoles instead
var ValidModes = []Mode{ModeAll, ModeBackend, ModeRegistry, ModeEngine}

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
		return NewRoleSet([]Role{RoleBackend, RoleRegistry, RoleEngine}), nil
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

// ParseMode parses a mode string into a Mode (single role), returning an error if invalid
// Deprecated: Use ParseRoles for multi-role support
func ParseMode(s string) (Mode, error) {
	mode := Mode(s)
	for _, valid := range ValidModes {
		if mode == valid {
			return mode, nil
		}
	}
	return "", fmt.Errorf("invalid mode %q, valid modes: %v", s, ValidModes)
}

// Runner is the interface for role-specific runners
type Runner interface {
	// Role returns the role this runner implements
	Role() Role

	// Name returns the mode name (deprecated, use Role())
	Name() Mode

	// Run starts the role's services and blocks until shutdown
	Run(ctx context.Context) error

	// Shutdown gracefully shuts down the role's services
	Shutdown(ctx context.Context) error
}

// RunnerFactory creates a Runner for the given role
type RunnerFactory func(cfg interface{}) (Runner, error)

// registry of runner factories by role
var runners = make(map[Role]RunnerFactory)

// Register registers a runner factory for a role
func Register(role Role, factory RunnerFactory) {
	runners[role] = factory
}

// NewRunner creates a runner for the given role
// Deprecated: Use NewRunnerForRole instead
func NewRunner(mode Mode, cfg interface{}) (Runner, error) {
	return NewRunnerForRole(mode, cfg)
}

// NewRunnerForRole creates a runner for the given role
func NewRunnerForRole(role Role, cfg interface{}) (Runner, error) {
	factory, ok := runners[role]
	if !ok {
		return nil, fmt.Errorf("no runner registered for role %q", role)
	}
	return factory(cfg)
}

// ListRegistered returns the list of registered roles
func ListRegistered() []Role {
	var roles []Role
	for r := range runners {
		roles = append(roles, r)
	}
	return roles
}
