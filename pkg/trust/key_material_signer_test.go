package trust

import (
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
)

func TestKeyMaterialFromSigner(t *testing.T) {
	if KeyMaterialFromSigner(nil) != nil {
		t.Fatal("a nil signer must give nil key material")
	}

	km := KeyMaterialFromSigner(&issuermetadata.SignerKeyMaterial{Type: "x5c", X5C: []string{"a", "b"}})
	if km == nil || km.Type != "x5c" || len(km.X5C) != 2 || km.X5C[0] != "a" || km.X5C[1] != "b" {
		t.Fatalf("x5c signer converted wrongly: %+v", km)
	}

	jwk := map[string]any{"kty": "EC"}
	km = KeyMaterialFromSigner(&issuermetadata.SignerKeyMaterial{Type: "jwk", JWK: jwk})
	if km == nil || km.Type != "jwk" || km.JWK == nil {
		t.Fatalf("jwk signer converted wrongly: %+v", km)
	}
}
