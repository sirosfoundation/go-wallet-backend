package ohttp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyConfig(t *testing.T) {
	t.Run("generates valid key", func(t *testing.T) {
		kc, err := NewKeyConfig(1)
		require.NoError(t, err)
		require.NotNil(t, kc)

		assert.Equal(t, uint8(1), kc.KeyID)
		assert.NotNil(t, kc.PrivateKey)
		assert.NotNil(t, kc.PublicKey)
		assert.NotNil(t, kc.Suite)
	})

	t.Run("rejects zero key ID", func(t *testing.T) {
		_, err := NewKeyConfig(0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key ID must be non-zero")
	})

	t.Run("different keys each time", func(t *testing.T) {
		kc1, err := NewKeyConfig(1)
		require.NoError(t, err)

		kc2, err := NewKeyConfig(1)
		require.NoError(t, err)

		// Public keys should be different
		pub1, _ := kc1.PublicKey.MarshalBinary()
		pub2, _ := kc2.PublicKey.MarshalBinary()
		assert.NotEqual(t, pub1, pub2)
	})
}

func TestKeyConfig_MarshalBinary(t *testing.T) {
	kc, err := NewKeyConfig(42)
	require.NoError(t, err)

	data, err := kc.MarshalBinary()
	require.NoError(t, err)

	// Expected structure:
	// Length prefix (2 bytes)
	// KeyID (1 byte) = 42
	// KemID (2 bytes) = 0x0020 (X25519)
	// PublicKey (32 bytes)
	// SuitesLen (2 bytes) = 4
	// KdfID (2 bytes) = 0x0001 (HKDF-SHA256)
	// AeadID (2 bytes) = 0x0001 (AES-128-GCM)
	// Total: 2 + 1 + 2 + 32 + 2 + 2 + 2 = 43 bytes

	assert.Len(t, data, 43)

	// Verify length prefix
	configLen := int(data[0])<<8 | int(data[1])
	assert.Equal(t, 41, configLen) // 43 - 2 byte prefix

	// Verify KeyID
	assert.Equal(t, uint8(42), data[2])

	// Verify KemID (X25519 = 0x0020)
	kemID := int(data[3])<<8 | int(data[4])
	assert.Equal(t, 0x0020, kemID)

	// Skip public key (32 bytes at offset 5)

	// Verify SuitesLen
	suitesLen := int(data[37])<<8 | int(data[38])
	assert.Equal(t, 4, suitesLen)

	// Verify KdfID (HKDF-SHA256 = 0x0001)
	kdfID := int(data[39])<<8 | int(data[40])
	assert.Equal(t, 0x0001, kdfID)

	// Verify AeadID (AES-128-GCM = 0x0001)
	aeadID := int(data[41])<<8 | int(data[42])
	assert.Equal(t, 0x0001, aeadID)
}

func TestKeyConfig_SaveLoad(t *testing.T) {
	// Create a temp file
	tmpFile := t.TempDir() + "/test-key.bin"

	// Generate and save key
	kc1, err := NewKeyConfig(7)
	require.NoError(t, err)

	err = kc1.SavePrivateKey(tmpFile)
	require.NoError(t, err)

	// Load key
	kc2, err := LoadKeyConfig(tmpFile, 7, false)
	require.NoError(t, err)

	// Verify same key
	pub1, _ := kc1.PublicKey.MarshalBinary()
	pub2, _ := kc2.PublicKey.MarshalBinary()
	assert.Equal(t, pub1, pub2)
	assert.Equal(t, kc1.KeyID, kc2.KeyID)
}

func TestLoadKeyConfig_CreateIfMissing(t *testing.T) {
	tmpFile := t.TempDir() + "/new-key.bin"

	// Load with create=true should generate new key
	kc, err := LoadKeyConfig(tmpFile, 5, true)
	require.NoError(t, err)
	require.NotNil(t, kc)
	assert.Equal(t, uint8(5), kc.KeyID)

	// Load again should get same key
	kc2, err := LoadKeyConfig(tmpFile, 5, false)
	require.NoError(t, err)

	pub1, _ := kc.PublicKey.MarshalBinary()
	pub2, _ := kc2.PublicKey.MarshalBinary()
	assert.Equal(t, pub1, pub2)
}

func TestLoadKeyConfig_FileNotFound(t *testing.T) {
	tmpFile := t.TempDir() + "/nonexistent.bin"

	// Load with create=false should fail
	_, err := LoadKeyConfig(tmpFile, 1, false)
	require.Error(t, err)
}

func TestKeyConfig_PublicKeyHex(t *testing.T) {
	kc, err := NewKeyConfig(1)
	require.NoError(t, err)

	hex := kc.PublicKeyHex()
	assert.Len(t, hex, 64) // 32 bytes * 2 hex chars
	assert.Regexp(t, "^[0-9a-f]+$", hex)
}
