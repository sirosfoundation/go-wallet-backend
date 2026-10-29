package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuertrust"
)

func selfSignedX5C(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not a wrpac"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(der)
}

func metaWithIssuerInfo(registrationCert string) map[string]interface{} {
	m := map[string]interface{}{
		"credential_configurations_supported": map[string]interface{}{
			"pid": map[string]interface{}{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
		},
	}
	if registrationCert != "" {
		m["issuer_info"] = []interface{}{
			map[string]interface{}{"format": issuermetadata.FormatRegistrationCert, "data": registrationCert},
		}
	}
	return m
}

func findingCodes(d *issuertrust.Decision) []issuertrust.Code {
	var out []issuertrust.Code
	for _, f := range d.Findings {
		out = append(out, f.Code)
	}
	return out
}

func TestEntitlementFor_OffChecksNothing(t *testing.T) {
	assert.Nil(t, entitlementFor(issuertrust.ModeOff, &metadataResult{Raw: metaWithIssuerInfo("")}, []string{"pid"}, entitlementAuth{}))
}

// Metadata that was not signed by a certificate chain has no access
// certificate. In fail mode that must refuse; reading it as "nothing to check"
// would let any unsigned issuer through the very control meant to stop it.
func TestEntitlementFor_FailRefusesUnsignedMetadata(t *testing.T) {
	d := entitlementFor(issuertrust.ModeFail, &metadataResult{Raw: metaWithIssuerInfo("")}, []string{"pid"}, entitlementAuth{})

	require.NotNil(t, d)
	assert.False(t, d.Allowed)
	assert.False(t, d.Evaluated)
	assert.Contains(t, findingCodes(d), issuertrust.CodeNoAccessCertificate)
}

func TestEntitlementFor_WarnReportsButAllows(t *testing.T) {
	d := entitlementFor(issuertrust.ModeWarn, &metadataResult{Raw: metaWithIssuerInfo("")}, []string{"pid"}, entitlementAuth{})

	require.NotNil(t, d)
	assert.True(t, d.Allowed)
	assert.NotEmpty(t, d.Findings)
}

// The raw metadata is what carries issuer_info. The typed IssuerMetadata drops
// it, so a regression to reading that would report "no registration
// certificate" for an issuer that published one.
func TestEntitlementFor_ReadsRegistrationCertificateFromRawMetadata(t *testing.T) {
	meta := &metadataResult{
		Raw:       metaWithIssuerInfo("not.a.jwt"),
		SignerX5C: []string{selfSignedX5C(t)},
	}

	d := entitlementFor(issuertrust.ModeFail, meta, []string{"pid"}, entitlementAuth{registration: issuertrust.AuthVerified, chainAnchored: true})

	require.NotNil(t, d)
	assert.False(t, d.Allowed)
	codes := findingCodes(d)
	assert.Contains(t, codes, issuertrust.CodeNotWRPAC, "the signing certificate was read")
	assert.Contains(t, codes, issuertrust.CodeRegistrationMalformed, "the registration certificate was read")
	assert.NotContains(t, codes, issuertrust.CodeNoRegistrationCert)
}

func newEntitlementTestHandler(t *testing.T, mode string) *OID4VCIHandler {
	t.Helper()
	conn, cleanup := wsTestServer(t, func(srv *websocket.Conn) {
		defer srv.Close()
		for {
			if _, _, err := srv.ReadMessage(); err != nil {
				return
			}
		}
	})
	t.Cleanup(cleanup)
	session := testSession(conn)
	flow := &Flow{ID: "flow-ent", Session: session, Data: make(map[string]interface{})}
	h := &OID4VCIHandler{}
	h.BaseHandler = BaseHandler{
		Flow:   flow,
		Logger: zap.NewNop(),
		Config: &config.Config{AuthZENProxy: config.AuthZENProxyConfig{IssuerEntitlementMode: mode}},
	}
	return h
}

func TestCheckIssuerEntitlement_FailModeBlocksFlow(t *testing.T) {
	h := newEntitlementTestHandler(t, "fail")
	offer := &CredentialOffer{CredentialIssuer: "https://issuer.example", CredentialConfigurationIDs: []string{"pid"}}

	err := h.checkIssuerEntitlement(context.Background(), offer.CredentialIssuer, &metadataResult{Raw: metaWithIssuerInfo("")}, offer)

	require.Error(t, err)
	assert.Contains(t, err.Error(), string(issuertrust.CodeNoAccessCertificate))
}

func TestCheckIssuerEntitlement_WarnModeContinues(t *testing.T) {
	h := newEntitlementTestHandler(t, "warn")
	offer := &CredentialOffer{CredentialIssuer: "https://issuer.example", CredentialConfigurationIDs: []string{"pid"}}

	assert.NoError(t, h.checkIssuerEntitlement(context.Background(), offer.CredentialIssuer, &metadataResult{Raw: metaWithIssuerInfo("")}, offer))
}

func TestCheckIssuerEntitlement_UnsetModeIsWarnNotOff(t *testing.T) {
	h := newEntitlementTestHandler(t, "")
	offer := &CredentialOffer{CredentialIssuer: "https://issuer.example", CredentialConfigurationIDs: []string{"pid"}}

	// Findings are produced (so the check ran) and issuance continues.
	assert.NoError(t, h.checkIssuerEntitlement(context.Background(), offer.CredentialIssuer, &metadataResult{Raw: metaWithIssuerInfo("")}, offer))
	d := entitlementFor(issuertrust.ParseMode(""), &metadataResult{Raw: metaWithIssuerInfo("")}, offer.CredentialConfigurationIDs, entitlementAuth{})
	require.NotNil(t, d)
	assert.Equal(t, issuertrust.ModeWarn, d.Mode)
}

type fakeMetadataResolver struct{ result *issuermetadata.ResolveResult }

func (f fakeMetadataResolver) ResolveWithInfo(context.Context, string) (*issuermetadata.ResolveResult, error) {
	return f.result, nil
}

// fetchMetadata is where the engine decides what the entitlement check will
// see. Without the raw map and the signer chain the check would silently
// evaluate nothing.
func TestFetchMetadata_KeepsRawMetadataAndSignerChain(t *testing.T) {
	x5c := selfSignedX5C(t)
	raw := metaWithIssuerInfo("a.b.c")
	raw["credential_issuer"] = "https://issuer.example"
	h := newEntitlementTestHandler(t, "fail")
	h.metadataResolver = fakeMetadataResolver{result: &issuermetadata.ResolveResult{
		Metadata:          raw,
		Signed:            true,
		SignerKeyMaterial: &issuermetadata.SignerKeyMaterial{Type: "x5c", X5C: []string{x5c}},
	}}

	got, err := h.fetchMetadata(context.Background(), "https://issuer.example")

	require.NoError(t, err)
	assert.Equal(t, "a.b.c", issuermetadata.RegistrationCertificate(got.Raw))
	assert.Equal(t, []string{x5c}, got.SignerX5C)
}
