package statuslist

import (
	"context"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

func TestCanonicalOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://status.example/l/1":         "https://status.example",
		"https://STATUS.Example:443/l/1":     "https://status.example",
		"HTTPS://Status.EXAMPLE/l/1":         "https://status.example",
		"http://status.example:80/l":         "http://status.example",
		"https://status.example./l":          "https://status.example",
		"https://status.example:8443/l":      "https://status.example:8443",
		"http://status.example:443/l":        "http://status.example:443",
		"https://status.example:80/l":        "https://status.example:80",
		"https://BÜCHER.example/l":           "https://xn--bcher-kva.example",
		"https://xn--bcher-kva.example:443/": "https://xn--bcher-kva.example",
		"https://[2001:DB8::1]:443/l":        "https://[2001:db8::1]",
		"https://127.0.0.1:8443/l":           "https://127.0.0.1:8443",
		"https://user@status.example/l?q=1":  "https://status.example",
	} {
		got, err := canonicalOrigin(in)
		if err != nil || got != want {
			t.Errorf("canonicalOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "/relative", "https:///x", "https://bad host/"} {
		if got, err := canonicalOrigin(in); err == nil {
			t.Errorf("canonicalOrigin(%q) = %q, want error", in, got)
		}
	}
}

func TestEvaluateSigner_CanonicalSubject(t *testing.T) {
	var subjects []string
	c := newTestChecker(nil, false, func(_ context.Context, subject string, _ *trust.KeyMaterial) (bool, error) {
		subjects = append(subjects, subject)
		return true, nil
	})
	for _, uri := range []string{"https://STATUS.Example:443/a", "https://status.example./b", "https://status.example/c"} {
		if err := c.evaluateSigner(context.Background(), "", uri, nil); err != nil {
			t.Fatal(err)
		}
	}
	for i, s := range subjects {
		if s != "https://status.example" {
			t.Errorf("call %d: subject %q", i, s)
		}
	}
	// An explicit iss is used as given.
	subjects = nil
	_ = c.evaluateSigner(context.Background(), "https://Issuer.Example", "https://x/", nil)
	if len(subjects) != 1 || subjects[0] != "https://Issuer.Example" {
		t.Errorf("iss subject: %v", subjects)
	}
}
