package middleware

import (
	"net/http"
	"strings"
)

// AddHeaderToken appends token to a comma-separated header (e.g. Vary) without
// dropping values set earlier, such as Vary: Origin from the CORS middleware,
// and without duplicating it (case-insensitive). A "*" already present
// subsumes any token, so nothing is added.
func AddHeaderToken(h http.Header, key, token string) {
	var toks []string
	for _, v := range h.Values(key) {
		for _, t := range strings.Split(v, ",") {
			t = strings.TrimSpace(t)
			if t == "*" || strings.EqualFold(t, token) {
				return
			}
			if t != "" {
				toks = append(toks, t)
			}
		}
	}
	h.Set(key, strings.Join(append(toks, token), ", "))
}
