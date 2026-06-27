package as

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	spocp "github.com/sirosfoundation/go-spocp"
	"github.com/sirosfoundation/go-spocp/pkg/persist"
	"go.uber.org/zap"
)

// PolicyEngine evaluates token issuance requests against SPOCP policy rules.
type PolicyEngine interface {
	// Evaluate returns true if the given S-expression query is permitted.
	Evaluate(query string) (bool, error)
	// RuleCount returns the number of loaded rules.
	RuleCount() int
}

// SPOCPEngine wraps the go-spocp AdaptiveEngine for policy evaluation.
type SPOCPEngine struct {
	mu     sync.RWMutex
	engine *spocp.AdaptiveEngine
	logger *zap.Logger
}

// NewSPOCPEngine creates a new policy engine.
func NewSPOCPEngine(logger *zap.Logger) *SPOCPEngine {
	return &SPOCPEngine{
		engine: spocp.New(),
		logger: logger,
	}
}

// LoadRulesFromDir loads all .spocp files from the given directory.
func (pe *SPOCPEngine) LoadRulesFromDir(dir string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("as: failed to read rules directory %s: %w", dir, err)
	}

	loaded := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".rules" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		opts := persist.DefaultLoadOptions()
		opts.Format = persist.FormatCanonical
		if err := pe.engine.LoadRulesFromFileWithOptions(path, opts); err != nil {
			return fmt.Errorf("as: failed to load rules from %s: %w", path, err)
		}
		loaded++
		pe.logger.Info("loaded SPOCP rules",
			zap.String("file", entry.Name()),
			zap.Int("total_rules", pe.engine.RuleCount()),
		)
	}

	if loaded == 0 {
		pe.logger.Warn("no SPOCP rule files found", zap.String("dir", dir))
	}

	return nil
}

// Evaluate checks the query against loaded rules.
func (pe *SPOCPEngine) Evaluate(query string) (bool, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	return pe.engine.Query(query)
}

// RuleCount returns the number of loaded rules.
func (pe *SPOCPEngine) RuleCount() int {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	return pe.engine.RuleCount()
}

// AllowAllPolicy is a PolicyEngine that permits every request.
// Used in tests and development when no SPOCP rules are configured.
type AllowAllPolicy struct{}

// Evaluate always returns true.
func (AllowAllPolicy) Evaluate(_ string) (bool, error) { return true, nil }

// RuleCount returns 0.
func (AllowAllPolicy) RuleCount() int { return 0 }
