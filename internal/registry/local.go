package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// LoadLocalOverrides reads VCTM JSON files from the configured paths and
// inserts them into the store with IsLocal=true. Each path may be a regular
// file or a directory; directories are scanned for *.json files (non-recursive).
// The "vct" field in each JSON document is used as the store key.
func LoadLocalOverrides(store *Store, paths []string, logger *zap.Logger) error {
	var loaded int
	for _, p := range paths {
		n, err := loadPath(store, p, logger)
		if err != nil {
			return fmt.Errorf("loading %s: %w", p, err)
		}
		loaded += n
	}
	if loaded > 0 {
		logger.Info("Loaded local VCTM overrides", zap.Int("entries", loaded))
	}
	return nil
}

// loadPath handles a single path which may be a file or directory.
func loadPath(store *Store, p string, logger *zap.Logger) (int, error) {
	info, err := os.Stat(p)
	if err != nil {
		return 0, fmt.Errorf("stat: %w", err)
	}

	if !info.IsDir() {
		if err := loadFile(store, p, logger); err != nil {
			return 0, err
		}
		return 1, nil
	}

	entries, err := os.ReadDir(p)
	if err != nil {
		return 0, fmt.Errorf("reading directory: %w", err)
	}

	var count int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		fp := filepath.Join(p, e.Name())
		if err := loadFile(store, fp, logger); err != nil {
			logger.Warn("Skipping invalid local VCTM file",
				zap.String("path", fp), zap.Error(err))
			continue
		}
		count++
	}
	return count, nil
}

// loadFile reads a single VCTM JSON file, extracts the "vct" field, and puts
// it into the store as a local override.
func loadFile(store *Store, path string, logger *zap.Logger) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	if !json.Valid(data) {
		return fmt.Errorf("invalid JSON")
	}

	// Extract the top-level "vct" and optional "name" / "description" fields.
	var header struct {
		VCT         string `json:"vct"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return fmt.Errorf("unmarshal header: %w", err)
	}
	if header.VCT == "" {
		return fmt.Errorf("missing or empty \"vct\" field")
	}

	entry := &VCTMEntry{
		VCT:         header.VCT,
		Name:        header.Name,
		Description: header.Description,
		Metadata:    json.RawMessage(data),
		FetchedAt:   time.Now(),
		IsLocal:     true,
	}

	store.Put(entry)
	logger.Debug("Loaded local VCTM override",
		zap.String("vct", header.VCT),
		zap.String("path", path))
	return nil
}
