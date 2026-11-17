package middleware

import (
	"net/http"
	"testing"
)

func TestAddHeaderToken(t *testing.T) {
	tests := []struct {
		name, in, token, want string
	}{
		{"absent header", "", "Authorization", "Authorization"},
		{"appends keeping existing", "Origin, Accept-Encoding", "authorization", "Origin, Accept-Encoding, authorization"},
		{"case-insensitive duplicate", "Origin, Authorization", "authorization", "Origin, Authorization"},
		{"wildcard subsumes", "*", "Authorization", "*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.in != "" {
				h.Add("Vary", tt.in)
			}
			AddHeaderToken(h, "Vary", tt.token)
			if got := h.Get("Vary"); got != tt.want {
				t.Fatalf("Vary = %q, want %q", got, tt.want)
			}
		})
	}
}
