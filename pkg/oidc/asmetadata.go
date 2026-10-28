package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Errors returned by FetchAuthorizationServerMetadata. Their messages are
// static (no identifier or document content) so they are safe to log and to
// map to client-facing errors.
var (
	// ErrASMetadataNotFound means every candidate URL answered HTTP 404: the
	// authorization server publishes no discoverable metadata. It is the only
	// outcome for which callers may fall back to guessed endpoints.
	ErrASMetadataNotFound = errors.New("authorization server metadata not found")
	// ErrASIssuerMismatch means a document was served but its "issuer" is not
	// identical to the identifier it was discovered for (RFC 8414 section 3.3).
	ErrASIssuerMismatch = errors.New("authorization server metadata issuer does not match identifier")
	// ErrASMetadataInvalid means the response was not a JSON object, or was
	// larger than the size limit.
	ErrASMetadataInvalid = errors.New("authorization server metadata invalid")
)

// ASMetadataStatusError reports a non-200, non-404 response from a candidate
// URL. No further candidate is tried after it.
type ASMetadataStatusError struct{ Status int }

func (e *ASMetadataStatusError) Error() string {
	return fmt.Sprintf("authorization server metadata endpoint returned HTTP %d", e.Status)
}

// FetchAuthorizationServerMetadata discovers the metadata document of the
// authorization server identified by identifier and returns its raw JSON.
//
// Candidates come from AuthorizationServerMetadataURLs, in order. The next
// candidate is tried ONLY after an HTTP 404; any other status, a network
// error or a timeout ends discovery after that one request. Every request uses
// client (callers pass their SSRF-guarded client) and the body is limited to
// maxBytes.
//
// The "issuer" of the first document served must equal identifier exactly
// (simple string comparison, RFC 8414 section 3.3 / OIDC Discovery section
// 4.3); otherwise the document MUST NOT be used and ErrASIssuerMismatch is
// returned without trying further candidates.
func FetchAuthorizationServerMetadata(ctx context.Context, client *http.Client, identifier string, maxBytes int64) ([]byte, error) {
	urls, err := AuthorizationServerMetadataURLs(identifier)
	if err != nil {
		return nil, err
	}
	for _, u := range urls {
		body, status, err := fetchASCandidate(ctx, client, u, maxBytes)
		if err != nil {
			return nil, err
		}
		if status == http.StatusNotFound {
			continue
		}
		if status != http.StatusOK {
			return nil, &ASMetadataStatusError{Status: status}
		}
		var doc struct {
			Issuer string `json:"issuer"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, ErrASMetadataInvalid
		}
		if doc.Issuer != identifier {
			return nil, ErrASIssuerMismatch
		}
		return body, nil
	}
	return nil, ErrASMetadataNotFound
}

func fetchASCandidate(ctx context.Context, client *http.Client, u string, maxBytes int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	// The AS identifier is issuer-chosen by design; callers pass the SSRF-guarded
	// client (private/loopback/metadata addresses refused at dial, incl. redirects).
	resp, err := client.Do(req) // codeql[go/request-forgery]
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(body)) > maxBytes {
		return nil, 0, ErrASMetadataInvalid
	}
	return body, resp.StatusCode, nil
}
