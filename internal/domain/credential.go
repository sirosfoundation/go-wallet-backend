package domain

import (
	"time"
)

// CredentialFormat represents the format of a credential
type CredentialFormat string

const (
	FormatJWTVC     CredentialFormat = "jwt_vc"
	FormatJWTVCJSON CredentialFormat = "jwt_vc_json"
	FormatLDPVC     CredentialFormat = "ldp_vc"
	FormatSDJWTVC   CredentialFormat = "vc+sd-jwt"
)

// VerifiableCredential represents a stored verifiable credential
type VerifiableCredential struct {
	ID                         int64            `json:"id" bson:"_id,omitempty" gorm:"primaryKey;autoIncrement"`
	TenantID                   TenantID         `json:"tenantId" bson:"tenant_id" gorm:"index;not null;default:'default'"`
	HolderDID                  string           `json:"holderDID" bson:"holder_did" gorm:"index;not null"`
	CredentialIdentifier       string           `json:"credentialIdentifier" bson:"credential_identifier" gorm:"index;not null"`
	Credential                 string           `json:"credential" bson:"credential" gorm:"type:text;not null"`
	Format                     CredentialFormat `json:"format" bson:"format" gorm:"not null"`
	CredentialConfigurationID  string           `json:"credentialConfigurationId" bson:"credential_configuration_id" gorm:"not null"`
	CredentialIssuerIdentifier string           `json:"credentialIssuerIdentifier" bson:"credential_issuer_identifier" gorm:"not null"`
	InstanceID                 int              `json:"instanceId" bson:"instance_id" gorm:"default:0"`
	SigCount                   int              `json:"sigCount" bson:"sig_count" gorm:"default:0"`
	CreatedAt                  time.Time        `json:"createdAt,omitempty" bson:"created_at" gorm:"autoCreateTime"`
	UpdatedAt                  time.Time        `json:"updatedAt,omitempty" bson:"updated_at" gorm:"autoUpdateTime"`
}

// TableName specifies the table name for GORM
func (VerifiableCredential) TableName() string {
	return "verifiable_credentials"
}

// StoreCredentialRequest represents a request to store a credential
type StoreCredentialRequest struct {
	HolderDID                  string           `json:"holderDID"`
	CredentialIdentifier       string           `json:"credentialIdentifier" binding:"required"`
	Credential                 string           `json:"credential" binding:"required"`
	Format                     CredentialFormat `json:"format" binding:"required"`
	CredentialConfigurationID  string           `json:"credentialConfigurationId"`
	CredentialIssuerIdentifier string           `json:"credentialIssuerIdentifier"`
	InstanceID                 int              `json:"instanceId"`
}

// UpdateCredentialRequest represents a request to update a credential
type UpdateCredentialRequest struct {
	CredentialIdentifier string `json:"credentialIdentifier" binding:"required"`
	InstanceID           int    `json:"instanceId"`
	SigCount             int    `json:"sigCount"`
}

// VerifiablePresentation represents a stored verifiable presentation
type VerifiablePresentation struct {
	ID                                      int64     `json:"id" bson:"_id,omitempty" gorm:"primaryKey;autoIncrement"`
	TenantID                                TenantID  `json:"tenantId" bson:"tenant_id" gorm:"index;not null;default:'default'"`
	HolderDID                               string    `json:"holderDID" bson:"holder_did" gorm:"index;not null"`
	PresentationIdentifier                  string    `json:"presentationIdentifier" bson:"presentation_identifier" gorm:"index;not null"`
	Presentation                            string    `json:"presentation" bson:"presentation" gorm:"type:text;not null"`
	PresentationSubmission                  string    `json:"presentationSubmission" bson:"presentation_submission" gorm:"type:text;default:'{}'"`
	IncludedVerifiableCredentialIdentifiers []string  `json:"includedVerifiableCredentialIdentifiers" bson:"included_vc_identifiers" gorm:"serializer:json"`
	Audience                                string    `json:"audience" bson:"audience"`
	IssuanceDate                            time.Time `json:"issuanceDate" bson:"issuance_date" gorm:"autoCreateTime"`
}

// TableName specifies the table name for GORM
func (VerifiablePresentation) TableName() string {
	return "verifiable_presentations"
}

// StorePresentationRequest represents a request to store a presentation
type StorePresentationRequest struct {
	HolderDID                               string    `json:"holderDID"`
	PresentationIdentifier                  string    `json:"presentationIdentifier" binding:"required"`
	Presentation                            string    `json:"presentation" binding:"required"`
	PresentationSubmission                  any       `json:"presentationSubmission"`
	IncludedVerifiableCredentialIdentifiers []string  `json:"includedVerifiableCredentialIdentifiers"`
	Audience                                string    `json:"audience"`
	IssuanceDate                            time.Time `json:"issuanceDate"`
}

// CredentialIssuer represents a trusted credential issuer
type CredentialIssuer struct {
	ID                         int64    `json:"id" bson:"_id,omitempty" gorm:"primaryKey;autoIncrement"`
	TenantID                   TenantID `json:"tenantId" bson:"tenant_id" gorm:"index;not null;default:'default'"`
	CredentialIssuerIdentifier string   `json:"credentialIssuerIdentifier" bson:"credential_issuer_identifier" gorm:"index;not null"`
	ClientID                   string   `json:"clientId,omitempty" bson:"client_id"`
	Visible                    bool     `json:"visible" bson:"visible"`
}

// TableName specifies the table name for GORM
func (CredentialIssuer) TableName() string {
	return "credential_issuers"
}

// Verifier represents a trusted verifier
type Verifier struct {
	ID       int64    `json:"id" bson:"_id,omitempty" gorm:"primaryKey;autoIncrement"`
	TenantID TenantID `json:"tenantId" bson:"tenant_id" gorm:"index;not null;default:'default'"`
	Name     string   `json:"name" bson:"name" gorm:"not null"`
	URL      string   `json:"url" bson:"url" gorm:"not null"`
}

// TableName specifies the table name for GORM
func (Verifier) TableName() string {
	return "verifiers"
}
