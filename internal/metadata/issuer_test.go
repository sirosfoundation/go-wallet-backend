package metadata

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverIssuer_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(IssuerMetadata{
			CredentialIssuer:   "https://issuer.example.com",
			CredentialEndpoint: "https://issuer.example.com/credential",
		})
	}))
	defer ts.Close()

	result := DiscoverIssuer(t.Context(), ts.URL, ts.Client())
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if result.Metadata == nil || result.Metadata.CredentialIssuer != "https://issuer.example.com" {
		t.Fatalf("unexpected metadata: %+v", result.Metadata)
	}
	if result.Partial {
		t.Error("expected Partial=false when there's no mdoc_iacas_uri")
	}
}

// TestDiscoverIssuer_TrailingSlashNormalized exercises the
// oidc.NormalizeIssuerURL call inside fetchIssuerMetadata: a bare trailing
// slash on the issuer URL must not change the constructed well-known path.
func TestDiscoverIssuer_TrailingSlashNormalized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			t.Errorf("unexpected path %q (issuer URL trailing slash should have been trimmed)", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(IssuerMetadata{CredentialIssuer: "https://issuer.example.com"})
	}))
	defer ts.Close()

	result := DiscoverIssuer(t.Context(), ts.URL+"/", ts.Client())
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
}

func TestDiscoverIssuer_MetadataFetchError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	result := DiscoverIssuer(t.Context(), ts.URL, ts.Client())
	if result.Error == nil {
		t.Fatal("expected an error when the well-known endpoint fails")
	}
	if result.Metadata != nil {
		t.Errorf("expected nil metadata on error, got %+v", result.Metadata)
	}
}

func TestDiscoverIssuer_IACAPartialFailure(t *testing.T) {
	var iacasURL string
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	defer ts.Close()
	iacasURL = ts.URL + "/iacas"

	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(IssuerMetadata{
			CredentialIssuer: ts.URL,
			MdocIacasURI:     iacasURL,
		})
	})
	mux.HandleFunc("/iacas", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	result := DiscoverIssuer(t.Context(), ts.URL, ts.Client())
	if result.Metadata == nil {
		t.Fatal("expected metadata to be populated despite IACA failure")
	}
	if !result.Partial {
		t.Error("expected Partial=true when IACA fetch fails")
	}
	if result.Error == nil {
		t.Error("expected a non-nil Error describing the IACA failure")
	}
}

func TestDiscoverIssuer_IACASuccess(t *testing.T) {
	var iacasURL string
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	defer ts.Close()
	iacasURL = ts.URL + "/iacas"

	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(IssuerMetadata{
			CredentialIssuer: ts.URL,
			MdocIacasURI:     iacasURL,
		})
	})
	mux.HandleFunc("/iacas", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(IACAsResponse{
			Iacas: []IACACertificate{{Certificate: "deadbeef"}},
		})
	})

	result := DiscoverIssuer(t.Context(), ts.URL, ts.Client())
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if result.Partial {
		t.Error("expected Partial=false on full success")
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("unexpected certificates: %+v", result.Certificates)
	}
	want := "-----BEGIN CERTIFICATE-----\ndeadbeef\n-----END CERTIFICATE-----"
	if result.Certificates[0] != want {
		t.Errorf("Certificates[0] = %q, want %q", result.Certificates[0], want)
	}
}

func TestDiscoverIssuer_DefaultClient(t *testing.T) {
	// nil httpClient should not panic; DiscoverIssuer falls back to a
	// default client internally. Use an unroutable address so this fails
	// fast rather than actually hitting the network.
	result := DiscoverIssuer(t.Context(), "http://127.0.0.1:0", nil)
	if result.Error == nil {
		t.Fatal("expected an error connecting to an unroutable address")
	}
}
