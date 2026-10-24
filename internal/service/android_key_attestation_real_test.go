package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

const realAndroidDir = "testdata/android"

// loadAndroidChainPEM reads a chain file (PEM CERTIFICATE blocks, leaf first)
// as the x5c list the request carries.
func loadAndroidChainPEM(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var x5c []string
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s: unexpected PEM block %q", path, block.Type)
		}
		x5c = append(x5c, base64.StdEncoding.EncodeToString(block.Bytes))
	}
	if len(x5c) == 0 {
		return nil, fmt.Errorf("%s: no certificates", path)
	}
	return x5c, nil
}

func TestLoadAndroidChainPEM(t *testing.T) {
	fx := newChainFixture(t)
	chain := fx.leaf(&genKey(t).PublicKey, encodeKeyDescription(goodParams(nil)), leafOpts{})
	var pemData []byte
	for _, d := range chain {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	path := filepath.Join(t.TempDir(), "c.pem")
	if err := writeFile(path, string(pemData)); err != nil {
		t.Fatal(err)
	}
	x5c, err := loadAndroidChainPEM(path)
	if err != nil || len(x5c) != 3 || x5c[0] != b64chain(chain)[0] {
		t.Fatalf("x5c=%d err=%v", len(x5c), err)
	}
	if err := writeFile(path, "nothing"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAndroidChainPEM(path); err == nil {
		t.Fatal("empty file loaded")
	}
}

type realChainMeta struct {
	WIAChallenge string `json:"wia_challenge"`
	CapturedAt   string `json:"captured_at"`
	AppDigest    string `json:"app_digest"`
	ExpectHome   string `json:"expect_home"`
}

// TestAndroidKeyAttestation_RealPixelChains verifies chains captured on real
// devices, once they exist. See testdata/android/README.md for how to capture
// them. Until then it is skipped (no real Android chain was available when the
// verifier was written; the synthetic tests cover the logic, this slot covers
// real-world encodings: RKP chains, real roots, real KeyDescription versions).
func TestAndroidKeyAttestation_RealPixelChains(t *testing.T) {
	chains, _ := filepath.Glob(filepath.Join(realAndroidDir, "*.pem"))
	var captured []string
	for _, c := range chains {
		if filepath.Base(c) != "roots.pem" {
			captured = append(captured, c)
		}
	}
	if len(captured) == 0 {
		t.Skip("no real Android chains in internal/service/testdata/android: capture them on a Pixel (see its README.md)")
	}
	roots, err := os.ReadFile(filepath.Join(realAndroidDir, "roots.pem"))
	if err != nil {
		t.Fatalf("roots.pem (Google's attestation roots) is required next to the chains: %v", err)
	}
	for _, path := range captured {
		name := strings.TrimSuffix(filepath.Base(path), ".pem")
		t.Run(name, func(t *testing.T) {
			var meta realChainMeta
			raw, err := os.ReadFile(strings.TrimSuffix(path, ".pem") + ".json")
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &meta); err != nil {
				t.Fatal(err)
			}
			at, err := time.Parse(time.RFC3339, meta.CapturedAt)
			if err != nil {
				t.Fatalf("captured_at: %v", err)
			}
			x5c, err := loadAndroidChainPEM(path)
			if err != nil {
				t.Fatal(err)
			}
			der, _ := base64.StdEncoding.DecodeString(x5c[0])
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			pop, ok := leaf.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("leaf key is not EC")
			}
			v, err := NewAndroidKeyAttestationVerifier(config.AndroidKeyAttestationConfig{
				TrustAnchorsPEM: string(roots), AllowedAppDigests: []string{meta.AppDigest},
			}, zap.NewNop(), &fakeStatusFetcher{body: emptyStatusList, maxAge: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(map[string]any{"type": "android_key", "x5c": x5c})
			res, err := v.Verify(context.Background(), &InstanceKeyEvidenceInput{
				Payload: payload, PoPKey: pop, WIAChallenge: meta.WIAChallenge, Now: at,
			})
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			got := "none"
			if res.Record != nil {
				got = string(res.Record.Home)
				locked := "unknown"
				if res.Record.DeviceLocked != nil {
					locked = fmt.Sprint(*res.Record.DeviceLocked)
				}
				t.Logf("record: home=%s level=%s boot=%s locked=%s patch=%s app=%s", res.Record.Home, res.Record.SecurityLevel,
					res.Record.VerifiedBootState, locked, res.Record.PatchLevel, res.Record.AppDigest)
			} else {
				t.Logf("no home: %s", res.Reason)
			}
			if got != meta.ExpectHome {
				t.Fatalf("home = %s, want %s", got, meta.ExpectHome)
			}
			if res.Record != nil && res.Record.Kind != domain.KeyEvidenceAndroidKey {
				t.Fatalf("kind = %s", res.Record.Kind)
			}
		})
	}
}
