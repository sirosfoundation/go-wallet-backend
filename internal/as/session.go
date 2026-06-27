package as

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// Session represents a server-side session created after authentication.
type Session struct {
	// JTI is the unique session identifier (also used as the cookie value).
	JTI string `json:"jti"`

	// UserID is the authenticated user's identifier.
	UserID string `json:"user_id"`

	// DID is the user's decentralized identifier.
	DID string `json:"did,omitempty"`

	// TenantID is the tenant context for this session.
	TenantID string `json:"tenant_id"`

	// ACR is the authentication context class reference.
	ACR string `json:"acr"`

	// MaxTAC is the maximum TAC permissions this session can grant.
	MaxTAC TAC `json:"max_tac"`

	// CreatedAt is when the session was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the session expires.
	ExpiresAt time.Time `json:"expires_at"`

	// Revoked indicates the session has been explicitly revoked.
	Revoked bool `json:"revoked"`
}

// IsExpired returns true if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsValid returns true if the session is neither expired nor revoked.
func (s *Session) IsValid() bool {
	return !s.Revoked && !s.IsExpired()
}

// SessionStore is the interface for session persistence.
type SessionStore interface {
	// Create stores a new session. Returns an error if the JTI already exists.
	Create(ctx context.Context, session *Session) error

	// Get retrieves a session by JTI. Returns nil if not found.
	Get(ctx context.Context, jti string) (*Session, error)

	// Revoke marks a session as revoked.
	Revoke(ctx context.Context, jti string) error

	// Delete removes a session (for cleanup of expired sessions).
	Delete(ctx context.Context, jti string) error
}

// MemorySessionStore is an in-memory SessionStore implementation.
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewMemorySessionStore creates a new in-memory session store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*Session),
	}
}

// Create stores a new session.
func (s *MemorySessionStore) Create(_ context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[session.JTI]; exists {
		return fmt.Errorf("session %s already exists", session.JTI)
	}
	s.sessions[session.JTI] = session
	return nil
}

// Get retrieves a session by JTI.
func (s *MemorySessionStore) Get(_ context.Context, jti string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[jti]
	if !ok {
		return nil, nil
	}
	return session, nil
}

// Revoke marks a session as revoked.
func (s *MemorySessionStore) Revoke(_ context.Context, jti string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[jti]
	if !ok {
		return fmt.Errorf("session %s not found", jti)
	}
	session.Revoked = true
	return nil
}

// Delete removes a session.
func (s *MemorySessionStore) Delete(_ context.Context, jti string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, jti)
	return nil
}

// Cleanup removes expired sessions. Call periodically.
func (s *MemorySessionStore) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	removed := 0
	for jti, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, jti)
			removed++
		}
	}
	return removed
}

// StartCleanup runs periodic cleanup in a background goroutine.
// Stops when the context is cancelled.
func (s *MemorySessionStore) StartCleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.Cleanup()
		case <-ctx.Done():
			return
		}
	}
}

// GenerateSessionID creates a cryptographically random session identifier.
// Returns a 32-byte base64url-encoded string (no padding).
func GenerateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
