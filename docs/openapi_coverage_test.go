package docs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"go.uber.org/zap"
)

// TestAdminOpenAPIRouteCoverage verifies that every route registered on the admin
// router has a corresponding path+method entry in the OpenAPI spec. This test
// fails when a new admin endpoint is added without updating docs/openapi-admin.yaml.
func TestAdminOpenAPIRouteCoverage(t *testing.T) {
	specPath := resolveSpecPath("openapi-admin.yaml")
	if _, err := os.Stat(specPath); os.IsNotExist(err) {
		t.Fatalf("OpenAPI spec not found at %s — spec must exist for CI enforcement", specPath)
	}

	// Load and validate spec
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		t.Fatalf("Failed to load OpenAPI spec: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("OpenAPI spec validation failed: %v", err)
	}

	// Build set of spec paths (method + normalized path)
	specRoutes := make(map[string]bool)
	specOriginal := make(map[string]string) // normalized → original for error messages
	for path, pathItem := range doc.Paths.Map() {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
			op := pathItem.GetOperation(method)
			if op != nil {
				norm := method + " " + normalizePathParams(path)
				specRoutes[norm] = true
				specOriginal[norm] = method + " " + path
			}
		}
	}

	// Build admin router with real route registrations
	gin.SetMode(gin.TestMode)
	router := gin.New()
	adminGroup := router.Group("/admin")
	store := memory.NewStore()
	logger := zap.NewNop()
	handlers := api.NewAdminHandlers(store, logger)
	handlers.RegisterRoutes(adminGroup)

	// Add /admin/status which is registered separately in the server
	router.GET("/admin/status", func(c *gin.Context) {})

	// Check every registered route has spec coverage
	var missing []string
	registeredNorm := make(map[string]bool)
	for _, route := range router.Routes() {
		specPath := ginPathToOpenAPIPath(route.Path)
		norm := route.Method + " " + normalizePathParams(specPath)
		registeredNorm[norm] = true
		if !specRoutes[norm] {
			missing = append(missing, route.Method+" "+specPath)
		}
	}

	if len(missing) > 0 {
		t.Errorf("The following admin routes are NOT documented in %s:\n  %s\n\nUpdate the OpenAPI spec to include these endpoints.",
			filepath.Base(specPath), strings.Join(missing, "\n  "))
	}

	// Reverse check: spec paths that don't have registered routes (dead docs)
	var stale []string
	for norm, original := range specOriginal {
		if !registeredNorm[norm] {
			stale = append(stale, original)
		}
	}

	if len(stale) > 0 {
		t.Errorf("The following spec entries have no matching registered route (stale docs):\n  %s",
			strings.Join(stale, "\n  "))
	}
}

// ginPathToOpenAPIPath converts Gin's :param syntax to OpenAPI's {param} syntax.
// e.g. /admin/tenants/:id/users/:user_id → /admin/tenants/{id}/users/{user_id}
func ginPathToOpenAPIPath(ginPath string) string {
	re := regexp.MustCompile(`:([a-zA-Z_][a-zA-Z0-9_]*)`)
	return re.ReplaceAllString(ginPath, `{$1}`)
}

// normalizePathParams replaces all {paramName} segments with a canonical {_}
// placeholder so that paths can be compared regardless of parameter naming
// conventions (e.g. {tenantId} vs {id}).
func normalizePathParams(path string) string {
	re := regexp.MustCompile(`\{[^}]+\}`)
	return re.ReplaceAllString(path, `{_}`)
}

// resolveSpecPath returns the absolute path to the spec file relative to the package
// working directory. This is stable under -trimpath unlike runtime.Caller(0).
func resolveSpecPath(filename string) string {
	return filepath.Join(".", filename)
}

// TestOpenAPISpecValid ensures the spec itself is valid OpenAPI 3.x.
func TestOpenAPISpecValid(t *testing.T) {
	specPath := resolveSpecPath("openapi-admin.yaml")
	if _, err := os.Stat(specPath); os.IsNotExist(err) {
		t.Fatalf("OpenAPI spec not found at %s — spec must exist for CI enforcement", specPath)
	}

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		t.Fatalf("Failed to load OpenAPI spec: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("OpenAPI spec is invalid: %v", err)
	}

	// Basic sanity checks
	if doc.Info == nil || doc.Info.Title == "" {
		t.Error("Spec missing info.title")
	}
	if doc.Paths == nil || doc.Paths.Len() == 0 {
		t.Error("Spec has no paths defined")
	}

	t.Logf("OpenAPI spec v%s: %d paths, %d schemas",
		doc.Info.Version,
		doc.Paths.Len(),
		len(doc.Components.Schemas))

	// Verify all paths use consistent parameter naming
	for path := range doc.Paths.Map() {
		if strings.Contains(path, ":") {
			t.Errorf("Path %q uses Gin-style :param syntax instead of OpenAPI {param}", path)
		}
	}

	// Check for undocumented operations (operations without descriptions)
	var undocumented []string
	for path, pathItem := range doc.Paths.Map() {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
			op := pathItem.GetOperation(method)
			if op != nil && op.Summary == "" && op.Description == "" {
				undocumented = append(undocumented, fmt.Sprintf("%s %s", method, path))
			}
		}
	}
	if len(undocumented) > 0 {
		t.Logf("Warning: %d operations without summary/description:\n  %s",
			len(undocumented), strings.Join(undocumented, "\n  "))
	}
}
