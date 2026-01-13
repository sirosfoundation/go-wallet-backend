package integration

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false, "Update golden files with current output")

// normalizeJSON removes dynamic values from JSON for stable comparison
func normalizeJSON(data []byte) ([]byte, error) {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}

	normalized := normalizeValue(v)
	return json.MarshalIndent(normalized, "", "  ")
}

func normalizeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, v := range val {
			// Replace dynamic values with placeholders
			switch k {
			case "challengeId":
				result[k] = "<CHALLENGE_ID>"
			case "$b64u":
				// Check if this looks like a UUID-based value or a challenge
				if s, ok := v.(string); ok {
					if len(s) > 40 { // Likely a challenge (32+ bytes base64)
						result[k] = "<CHALLENGE_B64U>"
					} else {
						result[k] = "<USER_ID_B64U>"
					}
				} else {
					result[k] = normalizeValue(v)
				}
			case "name":
				// Check if the value looks like a UUID
				if s, ok := v.(string); ok && isUUID(s) {
					result[k] = "<USER_UUID>"
				} else {
					result[k] = normalizeValue(v)
				}
			default:
				result[k] = normalizeValue(v)
			}
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, v := range val {
			result[i] = normalizeValue(v)
		}
		return result
	default:
		return v
	}
}

// isUUID checks if a string looks like a UUID
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	// Check for dashes at expected positions
	return s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}

// GoldenTest represents a golden file test case
type GoldenTest struct {
	Name     string
	Request  func(h *TestHarness) *Response
	Filename string
}

// RunGoldenTests runs a set of golden file tests
func RunGoldenTests(t *testing.T, tests []GoldenTest) {
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			h := NewTestHarness(t)
			resp := tt.Request(h)

			actualBody := resp.Body()
			normalized, err := normalizeJSON(actualBody)
			if err != nil {
				t.Fatalf("Failed to normalize JSON: %v\nBody: %s", err, string(actualBody))
			}

			goldenPath := filepath.Join("golden", tt.Filename)

			if *updateGolden {
				if err := os.WriteFile(goldenPath, normalized, 0644); err != nil {
					t.Fatalf("Failed to write golden file: %v", err)
				}
				t.Logf("Updated golden file: %s", goldenPath)
				return
			}

			expected, err := os.ReadFile(goldenPath)
			if err != nil {
				if os.IsNotExist(err) {
					t.Fatalf("Golden file not found: %s\nRun with -update-golden to create it.\nActual output:\n%s", goldenPath, string(normalized))
				}
				t.Fatalf("Failed to read golden file: %v", err)
			}

			// Compare normalized JSON
			if string(normalized) != string(expected) {
				t.Errorf("Response does not match golden file %s\n\nExpected:\n%s\n\nActual:\n%s",
					goldenPath, string(expected), string(normalized))
			}
		})
	}
}

// CompareJSONStructure compares the structure of two JSON documents, ignoring values
func CompareJSONStructure(t *testing.T, expected, actual []byte) bool {
	t.Helper()

	var expectedMap, actualMap interface{}
	if err := json.Unmarshal(expected, &expectedMap); err != nil {
		t.Errorf("Failed to parse expected JSON: %v", err)
		return false
	}
	if err := json.Unmarshal(actual, &actualMap); err != nil {
		t.Errorf("Failed to parse actual JSON: %v", err)
		return false
	}

	return compareStructure(t, "", expectedMap, actualMap)
}

func compareStructure(t *testing.T, path string, expected, actual interface{}) bool {
	t.Helper()

	switch ev := expected.(type) {
	case map[string]interface{}:
		av, ok := actual.(map[string]interface{})
		if !ok {
			t.Errorf("At %s: expected object, got %T", path, actual)
			return false
		}

		// Check all expected keys exist
		for k := range ev {
			if _, ok := av[k]; !ok {
				t.Errorf("At %s: missing key %q", path, k)
				return false
			}
			if !compareStructure(t, path+"."+k, ev[k], av[k]) {
				return false
			}
		}

		// Check for unexpected keys
		for k := range av {
			if _, ok := ev[k]; !ok {
				t.Errorf("At %s: unexpected key %q", path, k)
				return false
			}
		}

		return true

	case []interface{}:
		av, ok := actual.([]interface{})
		if !ok {
			t.Errorf("At %s: expected array, got %T", path, actual)
			return false
		}

		// For arrays, just check that both have elements (structure check, not content)
		if len(ev) > 0 && len(av) == 0 {
			t.Errorf("At %s: expected non-empty array, got empty", path)
			return false
		}

		return true

	default:
		// For scalar values, just ensure both are scalar (structure check)
		return true
	}
}

// ExtractPattern extracts a value matching a regex from JSON
func ExtractPattern(data []byte, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindSubmatch(data)
	if len(matches) > 1 {
		return string(matches[1])
	}
	return ""
}

// JSONPath extracts a value from JSON using a simple dot-notation path
func JSONPath(data []byte, path string) interface{} {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil
	}

	parts := strings.Split(path, ".")
	for _, part := range parts {
		m, ok := v.(map[string]interface{})
		if !ok {
			return nil
		}
		v = m[part]
	}
	return v
}
