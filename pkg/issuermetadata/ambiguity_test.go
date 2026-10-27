package issuermetadata

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// signRaw signs payload (exact bytes, so a repeated member survives) as a
// compact JWS, with an x5c header when certs are given.
func signRaw(t *testing.T, privKey interface{}, certs []*x509.Certificate, typ string, payload []byte) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	if len(certs) > 0 {
		b64 := make([]interface{}, len(certs))
		for i, c := range certs {
			b64[i] = base64.StdEncoding.EncodeToString(c.Raw)
		}
		opts = opts.WithHeader("x5c", b64)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privKey}, opts)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

const aux = `{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["a","ssc"]}]}`

// document builds an issuer metadata document from members of its own and the
// configurations (a JSON object body). ISS is replaced by the issuer URL.
func document(own, configs string) string {
	if own != "" {
		own += ","
	}
	return `{"credential_issuer":"ISS","sub":"ISS","iat":1,` + own + `"credential_configurations_supported":` + configs + `}`
}

type ingress struct {
	name string
	// serve returns a resolver result for the document text.
	serve func(t *testing.T, doc string) (*ResolveResult, error)
}

func ingresses() []ingress {
	return []ingress{
		{"plain JSON", func(t *testing.T, doc string) (*ResolveResult, error) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(strings.ReplaceAll(doc, "ISS", srv.URL)))
			}))
			t.Cleanup(srv.Close)
			return newTestResolver(t).ResolveWithInfo(context.Background(), srv.URL)
		}},
		{"signed_metadata payload", func(t *testing.T, doc string) (*ResolveResult, error) {
			priv, pub := newTestKey(t)
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := signRaw(t, priv, nil, "JWT", []byte(strings.ReplaceAll(doc, "ISS", srv.URL)))
				outer := map[string]interface{}{"credential_issuer": srv.URL, "jwks": inlineJWKS(t, pub), "signed_metadata": token}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, mustJSON(t, outer))
			}))
			t.Cleanup(srv.Close)
			return newTestResolver(t).ResolveWithInfo(context.Background(), srv.URL)
		}},
		{"application/jwt payload", func(t *testing.T, doc string) (*ResolveResult, error) {
			priv, _ := newTestKey(t)
			cert := newTestCert(t, priv)
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/jwt")
				_, _ = w.Write([]byte(signRaw(t, priv, []*x509.Certificate{cert}, "openidvci-issuer-metadata+jwt",
					[]byte(strings.ReplaceAll(strings.ReplaceAll(doc, "ISS", srv.URL), `"iat":1`, fmt.Sprintf(`"iat":%d`, time.Now().Unix()))))))
			}))
			t.Cleanup(srv.Close)
			r, err := New(Config{CacheTTL: time.Minute, AllowHTTP: true})
			if err != nil {
				t.Fatal(err)
			}
			return r.ResolveWithInfo(context.Background(), srv.URL)
		}},
	}
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := jsonMarshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The resolver reads the raw bytes once, before they are decoded into maps: a
// configuration whose security-relevant members are ambiguous is not offered;
// a document ambiguous where no configuration can be dropped fails the fetch;
// everything else, including a repeat in an unrelated member, is unchanged.
func TestResolve_AmbiguousAdvertisements(t *testing.T) {
	good := `"good":{"format":"vc+sd-jwt","auxiliary_data_supported":` + aux + `}`
	cfgs := func(bad string) string { return `{` + good + `,` + bad + `}` }
	for name, tc := range map[string]struct {
		doc     string
		removed []string // ids not offered
		fails   bool
	}{
		"valid document": {doc: document("", cfgs(`"other":{"format":"mso_mdoc"}`))},
		"repeat in an unrelated member (display) is not judged": {
			doc: document("", cfgs(`"other":{"format":"x","display":[{"name":"A","name":"B"}]}`))},
		"case variant in an unrelated member is not judged": {
			doc: document("", cfgs(`"other":{"format":"x","claims":{"Type":1,"type":2}}`))},
		"repeated to_wallet": {
			doc:     document("", cfgs(`"bad":{"auxiliary_data_supported":`+aux[:len(aux)-1]+`,"to_wallet":[{"type":"https://x.example/t"}]}}`)),
			removed: []string{"bad"}},
		"case-variant to_wallet": {
			doc:     document("", cfgs(`"bad":{"auxiliary_data_supported":{"to_issuer":[{"type":"https://x.example/t"}],"To_Issuer":[]}}`)),
			removed: []string{"bad"}},
		"nested repeat in an entry": {
			doc:     document("", cfgs(`"bad":{"auxiliary_data_supported":{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","alg":"x","path":["a"]}]}}`)),
			removed: []string{"bad"}},
		"nested case-variant opening": {
			doc:     document("", cfgs(`"bad":{"auxiliary_data_supported":{"to_wallet":[{"type":"hash_commitment","Opening":"S"}]}}`)),
			removed: []string{"bad"}},
		"repeated credential_metadata member": {
			doc:     document("", cfgs(`"bad":{"credential_metadata":{"x":1,"x":2}}`)),
			removed: []string{"bad"}},
		"repeated proof_types_supported member": {
			doc:     document("", cfgs(`"bad":{"proof_types_supported":{"jwt":{},"jwt":{}}}`)),
			removed: []string{"bad"}},
		"repeated auxiliary_data_supported": {
			doc:     document("", cfgs(`"bad":{"auxiliary_data_supported":{"to_issuer":[{"type":"https://x.example/t"}]},"auxiliary_data_supported":`+aux+`}`)),
			removed: []string{"bad"}},
		"case-variant configuration member": {
			doc:     document("", cfgs(`"bad":{"auxiliary_data_supported":`+aux+`,"Auxiliary_Data_Supported":{"to_issuer":[{"type":"https://x.example/t"}]}}`)),
			removed: []string{"bad"}},
		"two bad configurations": {
			doc:     document("", `{`+good+`,"b1":{"credential_metadata":{"a":1,"a":2}},"b2":{"auxiliary_data_supported":{"x":1,"x":1}}}`),
			removed: []string{"b1", "b2"}},
		"repeated credential_response_encryption member": {
			doc:   document(`"credential_response_encryption":{"encryption_required":false,"encryption_required":true}`, cfgs(`"o":{}`)),
			fails: true},
		"case-variant credential_request_encryption member": {
			doc:   document(`"credential_request_encryption":{"encryption_required":true,"Encryption_Required":false}`, cfgs(`"o":{}`)),
			fails: true},
		"repeated credential_configurations_supported": {
			doc:   `{"credential_issuer":"ISS","sub":"ISS","iat":1,"credential_configurations_supported":{},"credential_configurations_supported":{}}`,
			fails: true},
		"repeated configuration id": {
			doc:   document("", `{"a":{"format":"x"},"a":{"format":"y"}}`),
			fails: true},
		"case-variant document member": {
			doc:   `{"credential_issuer":"ISS","sub":"ISS","iat":1,"credential_configurations_supported":{},"Credential_Configurations_Supported":{"x":{}}}`,
			fails: true},
	} {
		for _, in := range ingresses() {
			t.Run(name+"/"+in.name, func(t *testing.T) {
				res, err := in.serve(t, tc.doc)
				if tc.fails {
					if err == nil {
						t.Fatal("expected the fetch to fail closed")
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				ccs, _ := res.Metadata["credential_configurations_supported"].(map[string]interface{})
				if _, ok := ccs["good"]; !ok {
					t.Error("the unambiguous configuration must stay offered")
				}
				for _, id := range tc.removed {
					if _, ok := ccs[id]; ok {
						t.Errorf("configuration %q must not be offered", id)
					}
				}
				if fmt.Sprint(res.AmbiguousConfigurations) != fmt.Sprint(tc.removed) && !(len(tc.removed) == 0 && len(res.AmbiguousConfigurations) == 0) {
					t.Errorf("AmbiguousConfigurations = %v, want %v", res.AmbiguousConfigurations, tc.removed)
				}
				if len(tc.removed) == 0 {
					if len(ccs) < 2 {
						t.Errorf("a valid document must be unchanged, got %d configurations", len(ccs))
					}
				}
			})
		}
	}
}

func jsonMarshal(v interface{}) ([]byte, error) { return json.Marshal(v) }
