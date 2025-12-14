package domain

import (
	"testing"
	"time"
)

func TestCredentialFormat_Constants(t *testing.T) {
	tests := []struct {
		format   CredentialFormat
		expected string
	}{
		{FormatJWTVC, "jwt_vc"},
		{FormatJWTVCJSON, "jwt_vc_json"},
		{FormatLDPVC, "ldp_vc"},
		{FormatSDJWTVC, "vc+sd-jwt"},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			if string(tt.format) != tt.expected {
				t.Errorf("Format = %q, want %q", tt.format, tt.expected)
			}
		})
	}
}

func TestVerifiableCredential_TableName(t *testing.T) {
	vc := VerifiableCredential{}
	if vc.TableName() != "verifiable_credentials" {
		t.Errorf("TableName() = %q, want %q", vc.TableName(), "verifiable_credentials")
	}
}

func TestVerifiableCredential_Fields(t *testing.T) {
	now := time.Now()
	vc := VerifiableCredential{
		ID:                         1,
		HolderDID:                  "did:key:holder",
		CredentialIdentifier:       "urn:credential:123",
		Credential:                 "eyJhbGciOiJFUzI1NiJ9...",
		Format:                     FormatJWTVC,
		CredentialConfigurationID:  "UniversityDegree",
		CredentialIssuerIdentifier: "https://issuer.example.com",
		InstanceID:                 1,
		SigCount:                   5,
		CreatedAt:                  now,
		UpdatedAt:                  now,
	}

	if vc.ID != 1 {
		t.Error("VerifiableCredential.ID not set correctly")
	}

	if vc.HolderDID != "did:key:holder" {
		t.Error("VerifiableCredential.HolderDID not set correctly")
	}

	if vc.CredentialIdentifier != "urn:credential:123" {
		t.Error("VerifiableCredential.CredentialIdentifier not set correctly")
	}

	if vc.Format != FormatJWTVC {
		t.Error("VerifiableCredential.Format not set correctly")
	}

	if vc.SigCount != 5 {
		t.Error("VerifiableCredential.SigCount not set correctly")
	}
}

func TestVerifiablePresentation_TableName(t *testing.T) {
	vp := VerifiablePresentation{}
	if vp.TableName() != "verifiable_presentations" {
		t.Errorf("TableName() = %q, want %q", vp.TableName(), "verifiable_presentations")
	}
}

func TestVerifiablePresentation_Fields(t *testing.T) {
	now := time.Now()
	vp := VerifiablePresentation{
		ID:                                      1,
		HolderDID:                               "did:key:holder",
		PresentationIdentifier:                  "urn:presentation:456",
		Presentation:                            "eyJhbGciOiJFUzI1NiJ9...",
		PresentationSubmission:                  `{"definition_id":"test"}`,
		IncludedVerifiableCredentialIdentifiers: []string{"urn:credential:123", "urn:credential:456"},
		Audience:                                "did:key:verifier",
		IssuanceDate:                            now,
	}

	if vp.ID != 1 {
		t.Error("VerifiablePresentation.ID not set correctly")
	}

	if vp.HolderDID != "did:key:holder" {
		t.Error("VerifiablePresentation.HolderDID not set correctly")
	}

	if len(vp.IncludedVerifiableCredentialIdentifiers) != 2 {
		t.Error("VerifiablePresentation.IncludedVerifiableCredentialIdentifiers not set correctly")
	}

	if vp.Audience != "did:key:verifier" {
		t.Error("VerifiablePresentation.Audience not set correctly")
	}

	if vp.PresentationSubmission != `{"definition_id":"test"}` {
		t.Error("VerifiablePresentation.PresentationSubmission not set correctly")
	}
}

func TestStoreCredentialRequest_Fields(t *testing.T) {
	req := StoreCredentialRequest{
		HolderDID:                  "did:key:holder",
		CredentialIdentifier:       "urn:credential:123",
		Credential:                 "credential-data",
		Format:                     FormatSDJWTVC,
		CredentialConfigurationID:  "EmployeeID",
		CredentialIssuerIdentifier: "https://employer.example.com",
		InstanceID:                 0,
	}

	if req.HolderDID != "did:key:holder" {
		t.Error("StoreCredentialRequest.HolderDID not set correctly")
	}

	if req.Format != FormatSDJWTVC {
		t.Error("StoreCredentialRequest.Format not set correctly")
	}
}

func TestUpdateCredentialRequest_Fields(t *testing.T) {
	req := UpdateCredentialRequest{
		CredentialIdentifier: "urn:credential:123",
		InstanceID:           2,
		SigCount:             10,
	}

	if req.CredentialIdentifier != "urn:credential:123" {
		t.Error("UpdateCredentialRequest.CredentialIdentifier not set correctly")
	}

	if req.InstanceID != 2 {
		t.Error("UpdateCredentialRequest.InstanceID not set correctly")
	}

	if req.SigCount != 10 {
		t.Error("UpdateCredentialRequest.SigCount not set correctly")
	}
}

func TestStorePresentationRequest_Fields(t *testing.T) {
	req := StorePresentationRequest{
		HolderDID:                               "did:key:holder",
		PresentationIdentifier:                  "urn:presentation:789",
		Presentation:                            "presentation-data",
		PresentationSubmission:                  map[string]any{"definition_id": "test"},
		IncludedVerifiableCredentialIdentifiers: []string{"cred1", "cred2"},
		Audience:                                "did:key:audience",
	}

	if req.HolderDID != "did:key:holder" {
		t.Error("StorePresentationRequest.HolderDID not set correctly")
	}

	if len(req.IncludedVerifiableCredentialIdentifiers) != 2 {
		t.Error("StorePresentationRequest.IncludedVerifiableCredentialIdentifiers not set correctly")
	}
}

func TestCredentialIssuer_TableName(t *testing.T) {
	issuer := CredentialIssuer{}
	if issuer.TableName() != "credential_issuers" {
		t.Errorf("TableName() = %q, want %q", issuer.TableName(), "credential_issuers")
	}
}

func TestCredentialIssuer_Fields(t *testing.T) {
	issuer := CredentialIssuer{
		ID:                         1,
		CredentialIssuerIdentifier: "https://issuer.example.com",
		ClientID:                   "client123",
		Visible:                    true,
	}

	if issuer.ID != 1 {
		t.Error("CredentialIssuer.ID not set correctly")
	}

	if issuer.CredentialIssuerIdentifier != "https://issuer.example.com" {
		t.Error("CredentialIssuer.CredentialIssuerIdentifier not set correctly")
	}

	if issuer.ClientID != "client123" {
		t.Error("CredentialIssuer.ClientID not set correctly")
	}

	if !issuer.Visible {
		t.Error("CredentialIssuer.Visible not set correctly")
	}
}

func TestVerifier_TableName(t *testing.T) {
	verifier := Verifier{}
	if verifier.TableName() != "verifiers" {
		t.Errorf("TableName() = %q, want %q", verifier.TableName(), "verifiers")
	}
}

func TestVerifier_Fields(t *testing.T) {
	verifier := Verifier{
		ID:   1,
		Name: "Example Verifier",
		URL:  "https://verifier.example.com",
	}

	if verifier.ID != 1 {
		t.Error("Verifier.ID not set correctly")
	}

	if verifier.Name != "Example Verifier" {
		t.Error("Verifier.Name not set correctly")
	}

	if verifier.URL != "https://verifier.example.com" {
		t.Error("Verifier.URL not set correctly")
	}
}
