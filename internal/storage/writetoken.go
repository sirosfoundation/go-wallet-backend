package storage

import (
	"crypto/rand"
	"encoding/hex"
)

// NewWriteToken returns a fresh random token for VerifiableCredential.WriteToken.
func NewWriteToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("storage: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
