package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuertrust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
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

// metaOf builds what fetchMetadata returns: the raw document, and the typed
// metadata parsed from it the same way.
func metaOf(t *testing.T, raw map[string]interface{}, signerX5C ...string) *metadataResult {
	t.Helper()
	b, err := json.Marshal(raw)
	require.NoError(t, err)
	var typed IssuerMetadata
	require.NoError(t, json.Unmarshal(b, &typed))
	return &metadataResult{Metadata: &typed, Raw: raw, SignerX5C: signerX5C}
}

func TestEntitlementFor_OffChecksNothing(t *testing.T) {
	assert.Nil(t, entitlementFor(context.Background(), issuertrust.ModeOff, metaOf(t, metaWithIssuerInfo("")), []string{"pid"}, nil, false))
}

// Metadata that was not signed by a certificate chain has no access
// certificate. In fail mode that must refuse; reading it as "nothing to check"
// would let any unsigned issuer through the very control meant to stop it.
func TestEntitlementFor_FailRefusesUnsignedMetadata(t *testing.T) {
	d := entitlementFor(context.Background(), issuertrust.ModeFail, metaOf(t, metaWithIssuerInfo("")), []string{"pid"}, nil, false)

	require.NotNil(t, d)
	assert.False(t, d.Allowed)
	assert.False(t, d.Evaluated)
	assert.Contains(t, findingCodes(d), issuertrust.CodeNoAccessCertificate)
}

func TestEntitlementFor_WarnReportsButAllows(t *testing.T) {
	d := entitlementFor(context.Background(), issuertrust.ModeWarn, metaOf(t, metaWithIssuerInfo("")), []string{"pid"}, nil, false)

	require.NotNil(t, d)
	assert.True(t, d.Allowed)
	assert.NotEmpty(t, d.Findings)
}

func trustingRegistrar(context.Context, *trust.KeyMaterial) (bool, error) { return true, nil }

// The raw metadata is what carries issuer_info. The typed IssuerMetadata drops
// it, so a regression to reading that would report "no registration
// certificate" for an issuer that published one.
func TestEntitlementFor_ReadsRegistrationCertificateFromRawMetadata(t *testing.T) {
	meta := metaOf(t, metaWithIssuerInfo(signedRegistrationCert(t, forgedClaims)), selfSignedX5C(t))

	d := entitlementFor(context.Background(), issuertrust.ModeFail, meta, []string{"pid"}, trustingRegistrar, true)

	require.NotNil(t, d)
	assert.False(t, d.Allowed)
	codes := findingCodes(d)
	assert.Contains(t, codes, issuertrust.CodeNotWRPAC, "the signing certificate was read")
	assert.NotContains(t, codes, issuertrust.CodeNoRegistrationCert, "the registration certificate was read")
	assert.NotContains(t, codes, issuertrust.CodeRegistrationUnverified)
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
		Config: &config.Config{Trust: config.TrustConfig{IssuerEntitlementMode: mode}},
	}
	return h
}

func TestCheckIssuerEntitlement_FailModeBlocksFlow(t *testing.T) {
	h := newEntitlementTestHandler(t, "fail")
	offer := &CredentialOffer{CredentialIssuer: "https://issuer.example", CredentialConfigurationIDs: []string{"pid"}}

	_, err := h.checkIssuerEntitlement(context.Background(), offer.CredentialIssuer, metaOf(t, metaWithIssuerInfo("")), offer)

	require.Error(t, err)
	assert.Contains(t, err.Error(), string(issuertrust.CodeNoAccessCertificate))
}

func TestCheckIssuerEntitlement_WarnModeContinues(t *testing.T) {
	h := newEntitlementTestHandler(t, "warn")
	offer := &CredentialOffer{CredentialIssuer: "https://issuer.example", CredentialConfigurationIDs: []string{"pid"}}

	_, err := h.checkIssuerEntitlement(context.Background(), offer.CredentialIssuer, metaOf(t, metaWithIssuerInfo("")), offer)
	assert.NoError(t, err)
}

func TestCheckIssuerEntitlement_UnsetModeIsWarnNotOff(t *testing.T) {
	h := newEntitlementTestHandler(t, "")
	offer := &CredentialOffer{CredentialIssuer: "https://issuer.example", CredentialConfigurationIDs: []string{"pid"}}

	// Findings are produced (so the check ran) and issuance continues.
	_, err := h.checkIssuerEntitlement(context.Background(), offer.CredentialIssuer, metaOf(t, metaWithIssuerInfo("")), offer)
	assert.NoError(t, err)
	d := entitlementFor(context.Background(), issuertrust.ParseMode(""), metaOf(t, metaWithIssuerInfo("")), offer.CredentialConfigurationIDs, nil, false)
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

// What is checked is what can be selected. The offers come from the parsed
// metadata, which decodes the way encoding/json does (member names match
// case-insensitively, a null configuration is an empty, selectable one), not
// from a second, exact-name reading of the raw document. Both configurations
// below are issuable and neither is registered.
func TestEntitlementFor_ChecksWhatTheParsedMetadataCanSelect(t *testing.T) {
	raw := map[string]interface{}{
		"Credential_Configurations_Supported": map[string]interface{}{
			"pid":     map[string]interface{}{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
			"nul":     nil,
			"diploma": map[string]interface{}{"Format": "dc+sd-jwt", "VCT": "urn:eudi:diploma:1"},
		},
		"issuer_info": []interface{}{map[string]interface{}{
			"format": "registration_cert", "data": signedRegistrationCert(t, forgedClaims),
		}},
	}
	meta := metaOf(t, raw, selfSignedX5C(t))
	require.Len(t, meta.Metadata.CredentialConfigurationsSupported, 3, "precondition: all three are selectable")

	d := entitlementFor(context.Background(), issuertrust.ModeFail, meta, []string{"pid", "nul", "diploma"}, trustingRegistrar, true)

	require.NotNil(t, d)
	assert.False(t, d.Allowed)
	var unregistered int
	for _, c := range findingCodes(d) {
		if c == issuertrust.CodeTypeNotRegistered {
			unregistered++
		}
	}
	assert.Equal(t, 2, unregistered, "the null and the case-variant configurations were checked")
}

// An unsigned document that spells the member "Signed_Metadata" fills the typed
// field (encoding/json is case-insensitive) although the resolver never
// verified it. Trust and the signer chain must not be recovered from it: a
// replayed authentic JWT would otherwise stand in for the issuer's own.
func TestFetchMetadata_IgnoresSignedMetadataTheResolverDidNotVerify(t *testing.T) {
	replayed := signedRegistrationCert(t, jwt.MapClaims{"sub": "victim"}) // an authentic JWT with an x5c header
	raw := metaWithIssuerInfo("")
	raw["credential_issuer"] = "https://issuer.example"
	raw["Signed_Metadata"] = replayed
	h := newEntitlementTestHandler(t, "fail")
	h.metadataResolver = fakeMetadataResolver{result: &issuermetadata.ResolveResult{Metadata: raw, Signed: false}}

	got, err := h.fetchMetadata(context.Background(), "https://issuer.example")

	require.NoError(t, err)
	assert.Empty(t, got.Metadata.SignedMetadata)
	assert.Nil(t, got.SignerX5C, "no chain may be recovered from an unverified JWT")
	assert.Nil(t, h.extractIssuerKeyMaterial(context.Background(), got.Metadata), "nor key material for the trust decision")
}
