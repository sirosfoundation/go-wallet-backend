package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransportSuppliedAttestation_Available(t *testing.T) {
	// nil provider
	var p *TransportSuppliedAttestation
	assert.False(t, p.Available())

	// Missing PoP
	p = &TransportSuppliedAttestation{WIA: "wia.jwt", ID: "test"}
	assert.False(t, p.Available())

	// Missing WIA
	p = &TransportSuppliedAttestation{PoP: "pop.jwt", ID: "test"}
	assert.False(t, p.Available())

	// Complete
	p = &TransportSuppliedAttestation{WIA: "wia.jwt", PoP: "pop.jwt", ID: "test"}
	assert.True(t, p.Available())
}

func TestTransportSuppliedAttestation_SetHeaders(t *testing.T) {
	provider := &TransportSuppliedAttestation{
		WIA: "eyJ0eXAiOiJvYXV0aC1jbGllbnQtYXR0ZXN0YXRpb24rand0In0.payload.sig",
		PoP: "eyJ0eXAiOiJvYXV0aC1jbGllbnQtYXR0ZXN0YXRpb24tcG9wK2p3dCJ9.payload.sig",
		ID:  "client-thumbprint-123",
	}

	req, _ := http.NewRequest("POST", "https://as.example.com/token", nil)
	err := provider.SetHeaders(context.Background(), req)
	require.NoError(t, err)

	// Verify headers are forwarded exactly as-is (no modification by backend)
	assert.Equal(t, provider.WIA, req.Header.Get("OAuth-Client-Attestation"))
	assert.Equal(t, provider.PoP, req.Header.Get("OAuth-Client-Attestation-PoP"))
}

func TestTransportSuppliedAttestation_ClientID(t *testing.T) {
	p := &TransportSuppliedAttestation{WIA: "w", PoP: "p", ID: "my-thumbprint"}
	assert.Equal(t, "my-thumbprint", p.ClientID())
}

func TestClientAttestationProvider_Interface(t *testing.T) {
	// Verify TransportSuppliedAttestation satisfies the interface
	var _ ClientAttestationProvider = &TransportSuppliedAttestation{}
}
