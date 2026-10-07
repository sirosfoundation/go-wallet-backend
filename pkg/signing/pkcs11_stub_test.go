//go:build !pkcs11

package signing

import "testing"

func TestPKCS11Stub(t *testing.T) {
	// NewPKCS11Signer should return ErrPKCS11NotSupported
	_, err := NewPKCS11Signer(&PKCS11Config{})
	if err != ErrPKCS11NotSupported {
		t.Errorf("NewPKCS11Signer() = %v, want ErrPKCS11NotSupported", err)
	}
}

func TestPKCS11Stub_Methods(t *testing.T) {
	s := &PKCS11Signer{}
	// Sign should return error
	_, err := s.Sign(nil, nil, nil)
	if err != ErrPKCS11NotSupported {
		t.Errorf("Sign() = %v, want ErrPKCS11NotSupported", err)
	}
	// Close should not error
	if err := s.Close(); err != nil {
		t.Errorf("Close() = %v", err)
	}
}

func TestPKCS11Stub_Public_ReturnsNil(t *testing.T) {
	s := &PKCS11Signer{}
	pub := s.Public()
	if pub != nil {
		t.Errorf("Public() should return nil, got %T", pub)
	}
}
