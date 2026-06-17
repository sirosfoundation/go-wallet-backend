//go:build pkcs11

package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/miekg/pkcs11"
)

// PKCS11Config holds configuration for a PKCS#11 token.
type PKCS11Config struct {
	ModulePath string `yaml:"module_path" envconfig:"MODULE_PATH"`
	SlotID     uint   `yaml:"slot_id" envconfig:"SLOT_ID"`
	PIN        string `yaml:"pin" envconfig:"PIN"`
	KeyLabel   string `yaml:"key_label" envconfig:"KEY_LABEL"`
}

// PKCS11Signer implements crypto.Signer backed by a PKCS#11 token.
// It holds a long-lived session and is safe for concurrent use.
type PKCS11Signer struct {
	mu         sync.Mutex
	ctx        *pkcs11.Ctx
	session    pkcs11.SessionHandle
	privateKey pkcs11.ObjectHandle
	publicKey  *ecdsa.PublicKey
}

// NewPKCS11Signer creates a signer backed by a PKCS#11 token.
// The key must be an EC P-256 key identified by label.
func NewPKCS11Signer(cfg *PKCS11Config) (*PKCS11Signer, error) {
	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", cfg.ModulePath)
	}

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11 initialize: %w", err)
	}

	session, err := ctx.OpenSession(cfg.SlotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		ctx.Finalize()
		return nil, fmt.Errorf("pkcs11 open session slot %d: %w", cfg.SlotID, err)
	}

	if err := ctx.Login(session, pkcs11.CKU_USER, cfg.PIN); err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		return nil, fmt.Errorf("pkcs11 login: %w", err)
	}

	s := &PKCS11Signer{ctx: ctx, session: session}
	if err := s.findKey(cfg.KeyLabel); err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

// Public returns the EC public key stored on the token.
func (s *PKCS11Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign implements crypto.Signer. It hashes the digest (already hashed by caller
// when opts.HashFunc() != 0) and signs via the PKCS#11 token.
func (s *PKCS11Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// CKM_ECDSA expects a pre-hashed digest
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}

	if err := s.ctx.SignInit(s.session, mechanism, s.privateKey); err != nil {
		return nil, fmt.Errorf("pkcs11 SignInit: %w", err)
	}

	// PKCS#11 CKM_ECDSA returns raw (r||s) — we need to convert to ASN.1 DER
	// because crypto.Signer contract returns ASN.1 for ECDSA.
	rawSig, err := s.ctx.Sign(s.session, digest)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 Sign: %w", err)
	}

	// Convert raw r||s to ASN.1 DER
	keyBytes := len(rawSig) / 2
	r := new(big.Int).SetBytes(rawSig[:keyBytes])
	sVal := new(big.Int).SetBytes(rawSig[keyBytes:])

	return asn1EncodeSignature(r, sVal), nil
}

// Close releases the PKCS#11 session and context.
func (s *PKCS11Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ctx != nil {
		s.ctx.Logout(s.session)
		s.ctx.CloseSession(s.session)
		s.ctx.Finalize()
		s.ctx = nil
	}
	return nil
}

// findKey locates the private key by label and extracts the matching public key.
func (s *PKCS11Signer) findKey(label string) error {
	// Find private key
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := s.ctx.FindObjectsInit(s.session, template); err != nil {
		return fmt.Errorf("FindObjectsInit (private): %w", err)
	}
	objs, _, err := s.ctx.FindObjects(s.session, 1)
	if err != nil {
		return fmt.Errorf("FindObjects (private): %w", err)
	}
	if err := s.ctx.FindObjectsFinal(s.session); err != nil {
		return fmt.Errorf("FindObjectsFinal (private): %w", err)
	}
	if len(objs) == 0 {
		return fmt.Errorf("no private key found with label %q", label)
	}
	s.privateKey = objs[0]

	// Find matching public key
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := s.ctx.FindObjectsInit(s.session, pubTemplate); err != nil {
		return fmt.Errorf("FindObjectsInit (public): %w", err)
	}
	pubObjs, _, err := s.ctx.FindObjects(s.session, 1)
	if err != nil {
		return fmt.Errorf("FindObjects (public): %w", err)
	}
	if err := s.ctx.FindObjectsFinal(s.session); err != nil {
		return fmt.Errorf("FindObjectsFinal (public): %w", err)
	}
	if len(pubObjs) == 0 {
		return fmt.Errorf("no public key found with label %q", label)
	}

	// Extract EC point from public key
	attrs, err := s.ctx.GetAttributeValue(s.session, pubObjs[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	})
	if err != nil {
		return fmt.Errorf("GetAttributeValue: %w", err)
	}

	ecPoint := attrs[0].Value
	// EC_POINT is DER-encoded OCTET STRING containing uncompressed point
	// Strip the ASN.1 OCTET STRING wrapper if present
	if len(ecPoint) > 0 && ecPoint[0] == 0x04 {
		// Already uncompressed point
	} else if len(ecPoint) > 2 && ecPoint[0] == 0x04 && ecPoint[1] == 0x41 {
		// OCTET STRING { uncompressed point }
		ecPoint = ecPoint[2:]
	} else if len(ecPoint) > 2 {
		// Try stripping DER OCTET STRING header
		ecPoint = ecPoint[2:]
	}

	// Parse as P-256 uncompressed point (0x04 || x || y)
	pubKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), ecPoint)
	if err != nil {
		return fmt.Errorf("parse EC point: %w", err)
	}
	s.publicKey = pubKey

	return nil
}

// asn1EncodeSignature encodes (r, s) as ASN.1 DER SEQUENCE { INTEGER, INTEGER }.
func asn1EncodeSignature(r, s *big.Int) []byte {
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Pad with leading zero if high bit set (ASN.1 INTEGER is signed)
	if len(rBytes) > 0 && rBytes[0]&0x80 != 0 {
		rBytes = append([]byte{0}, rBytes...)
	}
	if len(sBytes) > 0 && sBytes[0]&0x80 != 0 {
		sBytes = append([]byte{0}, sBytes...)
	}

	// SEQUENCE { INTEGER r, INTEGER s }
	rEnc := append([]byte{0x02, byte(len(rBytes))}, rBytes...)
	sEnc := append([]byte{0x02, byte(len(sBytes))}, sBytes...)
	seq := append(rEnc, sEnc...)
	return append([]byte{0x30, byte(len(seq))}, seq...)
}
