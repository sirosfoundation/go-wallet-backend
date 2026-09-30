package middleware

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TokenAuthMiddleware is kept for source compatibility and enforces no user
// cut-off. No production code in this module may route requests through it.
func TestNoProductionCallerUsesTheWeakTokenAuthMiddleware(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// The definition and its doc comment live in this package.
		if filepath.Base(path) == "tokenauth.go" && strings.Contains(filepath.ToSlash(path), "pkg/middleware/") {
			return nil
		}
		if strings.Contains(string(b), "TokenAuthMiddleware(") {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("production code calls the cut-off-less TokenAuthMiddleware: %v (use TokenAuthMiddlewareWithUsers)", offenders)
	}
}
