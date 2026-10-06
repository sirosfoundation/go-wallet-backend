package engine

import "testing"

// RunVCTMFlow lets the external engine_test package (which may import
// internal/registry without an import cycle) drive a ProtocolVCTM flow through
// the Manager's real flow-start path.
func RunVCTMFlow(t *testing.T, m *Manager, vct string) map[string]any {
	t.Helper()
	return runVCTMFlow(t, m, vct)
}
