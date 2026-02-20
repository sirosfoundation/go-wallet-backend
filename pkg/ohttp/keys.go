// Package ohttp implements Oblivious HTTP (RFC 9458) for the wallet backend.
//
// OHTTP provides IP unlinkability between wallet users and target servers
// (issuers, verifiers) by encrypting HTTP requests/responses through a gateway.
//
// This implementation supports two modes:
//  1. Integrated relay: Backend acts as both relay and gateway
//  2. External relay: Backend acts as gateway only, with external relay
package ohttp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// Algorithm constants matching the frontend implementation.
// The frontend uses @hpke/dhkem-x25519 + @hpke/core with these values.
const (
	// KemID is X25519 with HKDF-SHA256 (0x0020)
	KemID = hpke.KEM_X25519_HKDF_SHA256

	// KdfID is HKDF-SHA256 (0x0001)
	KdfID = hpke.KDF_HKDF_SHA256

	// AeadID is AES-128-GCM (0x0001)
	AeadID = hpke.AEAD_AES128GCM
)

// KeyConfig holds the gateway's OHTTP key configuration.
type KeyConfig struct {
	// KeyID uniquely identifies this key (1-255)
	KeyID uint8

	// PrivateKey is the gateway's private key for decryption
	PrivateKey kem.PrivateKey

	// PublicKey is the gateway's public key (published for clients)
	PublicKey kem.PublicKey

	// Suite is the HPKE cipher suite
	Suite hpke.Suite
}

// NewKeyConfig generates a new OHTTP key configuration with a random keypair.
func NewKeyConfig(keyID uint8) (*KeyConfig, error) {
	if keyID == 0 {
		return nil, fmt.Errorf("key ID must be non-zero")
	}

	suite := hpke.NewSuite(KemID, KdfID, AeadID)
	scheme := KemID.Scheme()

	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	return &KeyConfig{
		KeyID:      keyID,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Suite:      suite,
	}, nil
}

// LoadKeyConfig loads a key configuration from a file.
// If the file doesn't exist and create is true, generates a new key and saves it.
func LoadKeyConfig(path string, keyID uint8, create bool) (*KeyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && create {
			// Generate new key and save
			kc, err := NewKeyConfig(keyID)
			if err != nil {
				return nil, err
			}
			if err := kc.SavePrivateKey(path); err != nil {
				return nil, fmt.Errorf("failed to save new key: %w", err)
			}
			return kc, nil
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return UnmarshalKeyConfig(data, keyID)
}

// UnmarshalKeyConfig deserializes a key configuration from raw bytes.
func UnmarshalKeyConfig(data []byte, keyID uint8) (*KeyConfig, error) {
	scheme := KemID.Scheme()

	privateKey, err := scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	publicKey := privateKey.Public()

	return &KeyConfig{
		KeyID:      keyID,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Suite:      hpke.NewSuite(KemID, KdfID, AeadID),
	}, nil
}

// SavePrivateKey saves the private key to a file.
func (kc *KeyConfig) SavePrivateKey(path string) error {
	data, err := kc.PrivateKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Secure file permissions (owner read/write only)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// MarshalBinary serializes the public key configuration for /.well-known/ohttp-keys.
// Format per RFC 9458 §3:
//
//	KeyConfig {
//	   Key Identifier (8 bits),
//	   KEM Identifier (16 bits),
//	   Public Key (Npk bytes),
//	   Cipher Suites Length (16 bits),
//	   Cipher Suites (4 * n bytes) {
//	     KDF Identifier (16 bits),
//	     AEAD Identifier (16 bits),
//	   } ...
//	}
//
// The wire format has a 2-byte length prefix before each KeyConfig.
func (kc *KeyConfig) MarshalBinary() ([]byte, error) {
	pubBytes, err := kc.PublicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Calculate config length:
	// KeyID(1) + KemID(2) + PubKey(32) + SuitesLen(2) + Suite(4) = 41 bytes
	configLen := 1 + 2 + len(pubBytes) + 2 + 4
	buf := make([]byte, 2+configLen)

	// Length prefix (2 bytes, big-endian)
	binary.BigEndian.PutUint16(buf[0:2], uint16(configLen))
	offset := 2

	// Key Identifier (1 byte)
	buf[offset] = kc.KeyID
	offset++

	// KEM Identifier (2 bytes, big-endian)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(KemID))
	offset += 2

	// Public Key (32 bytes for X25519)
	copy(buf[offset:], pubBytes)
	offset += len(pubBytes)

	// Cipher Suites Length (2 bytes) - one suite = 4 bytes
	binary.BigEndian.PutUint16(buf[offset:offset+2], 4)
	offset += 2

	// KDF Identifier (2 bytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(KdfID))
	offset += 2

	// AEAD Identifier (2 bytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(AeadID))

	return buf, nil
}

// PublicKeyHex returns the public key as a hex string (for debugging/logging).
func (kc *KeyConfig) PublicKeyHex() string {
	pubBytes, _ := kc.PublicKey.MarshalBinary()
	return fmt.Sprintf("%x", pubBytes)
}

// randomBytes generates n random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
