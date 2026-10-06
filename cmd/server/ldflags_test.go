package main

import (
	"os"
	"regexp"
	"testing"
)

// The Go linker silently ignores -X for symbols that do not exist, so a typo
// in a Dockerfile leaves the binary reporting version=dev. Check that every
// -X main.<name> the server images pass names a real package-level string.
func TestDockerfileLinkerSymbolsExist(t *testing.T) {
	known := map[string]*string{"version": &version, "commit": &commit}
	re := regexp.MustCompile(`-X main\.(\w+)=`)
	for _, f := range []string{"../../Dockerfile", "../../Dockerfile.registry"} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		matches := re.FindAllStringSubmatch(string(data), -1)
		if len(matches) == 0 {
			t.Errorf("%s: no -X main.* linker flags found", f)
		}
		for _, m := range matches {
			if known[m[1]] == nil {
				t.Errorf("%s: -X main.%s does not match a variable in cmd/server", f, m[1])
			}
		}
	}
}
