package api

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// bruteLargestFit returns the longest cleaned prefix of body that fits, by
// scanning every byte offset (no reliance on monotonicity).
func bruteLargestFit(msg, body string) (string, bool) {
	best, found := "", false
	for n := 0; n <= len(body); n++ {
		d := strings.ToValidUTF8(body[:n], "")
		if serializedLen(map[string]interface{}{"error": msg, "details": d}) <= maxPDPErrorBodyBytes && (!found || len(d) >= len(best)) {
			best, found = d, true
		}
	}
	return best, found
}

func TestTruncatedPDPErrorBody(t *testing.T) {
	const msg = "trust evaluation request rejected by PDP"
	cases := []struct {
		name string
		body string
	}{
		{"larger than cap ascii", strings.Repeat("a", 10000)},
		{"multibyte 2-byte runes", strings.Repeat("é", 5000)},
		{"multibyte 3-byte runes", strings.Repeat("€", 5000)},
		{"multibyte 4-byte runes", strings.Repeat("😀", 5000)},
		{"mixed width at the cut", strings.Repeat("a€😀é", 1500)},
		{"heavy escaping NUL", strings.Repeat("\x00", 3000)},
		{"heavy escaping quotes", strings.Repeat(`"`, 3000)},
		{"html escapes", strings.Repeat("<&>", 2000)},
		{"invalid utf8 inside", strings.Repeat("ab\xff\xfe", 2000)},
		{"small body", "plain text problem"},
		{"single char", "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Non-JSON so the truncation path is taken.
			out := pdpErrorBody(msg, tc.body)
			b, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			if len(b) > maxPDPErrorBodyBytes {
				t.Fatalf("response %d bytes exceeds cap", len(b))
			}
			d, ok := out["details"].(string)
			if !ok {
				t.Fatalf("details missing/not string: %v", out)
			}
			if !utf8.ValidString(d) {
				t.Errorf("details not valid UTF-8")
			}
			want, _ := bruteLargestFit(msg, tc.body)
			if d != want {
				t.Errorf("not the largest fitting prefix: got %d bytes, want %d", len(d), len(want))
			}
			if len(tc.body) < 1000 && strings.ToValidUTF8(tc.body, "") != d {
				t.Errorf("small body altered: %q", d)
			}
		})
	}
}

func TestPDPErrorBodyEmpty(t *testing.T) {
	out := pdpErrorBody("m", "  \n")
	if _, ok := out["details"]; ok || out["error"] != "m" {
		t.Errorf("empty body: %v", out)
	}
}

// A long msg that cannot fit even with an empty prefix falls back to the bare envelope.
func TestTruncatedPDPErrorBodyEnvelopeOnly(t *testing.T) {
	out := truncatedPDPErrorBody(strings.Repeat("m", maxPDPErrorBodyBytes), "body")
	if _, ok := out["details"]; ok {
		t.Errorf("expected bare envelope, got %v", out)
	}
}
