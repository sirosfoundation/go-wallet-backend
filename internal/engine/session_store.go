// Package engine provides WebSocket v2 protocol implementation.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

var (
	ErrSessionExists = errors.New("session already exists")
)

// SessionData represents serializable session state.
type SessionData struct {
	ID        string            `json:"id"`
	UserID    string            `json:"user_id"`
	TenantID  string            `json:"tenant_id"`
	CreatedAt time.Time         `json:"created_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// SessionStore provides persistent session storage.
// Implementations must be safe for concurrent use.
type SessionStore interface {
	// Get retrieves a session by ID.
	Get(ctx context.Context, sessionID string) (*SessionData, error)

	// GetByUser retrieves the session of a user within a tenant. A user
	// holds at most one session per tenant.
	GetByUser(ctx context.Context, tenantID, userID string) (*SessionData, error)

	// Put stores a session. Returns ErrSessionExists if session already exists.
	Put(ctx context.Context, session *SessionData) error

	// Update updates an existing session.
	Update(ctx context.Context, session *SessionData) error

	// Delete removes a session by ID.
	Delete(ctx context.Context, sessionID string) error

	// DeleteByUser removes the user's sessions in every tenant (user-wide
	// revocation, e.g. account deletion).
	DeleteByUser(ctx context.Context, userID string) error

	// List returns all sessions for a tenant.
	List(ctx context.Context, tenantID string) ([]*SessionData, error)

	// Cleanup removes expired sessions.
	Cleanup(ctx context.Context) (int64, error)

	// Close releases resources.
	Close() error
}

// MemorySessionStore is an in-memory session store for development/testing.
type MemorySessionStore struct {
	mu        sync.RWMutex
	sessions  map[string]*SessionData
	userIndex map[userKey]string // (tenant, user) -> sessionID
	logger    *zap.Logger
}

// NewMemorySessionStore creates a new in-memory session store.
func NewMemorySessionStore(logger *zap.Logger) *MemorySessionStore {
	return &MemorySessionStore{
		sessions:  make(map[string]*SessionData),
		userIndex: make(map[userKey]string),
		logger:    logger.Named("memory_store"),
	}
}

func (m *MemorySessionStore) Get(ctx context.Context, sessionID string) (*SessionData, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

func (m *MemorySessionStore) GetByUser(ctx context.Context, tenantID, userID string) (*SessionData, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessionID, ok := m.userIndex[userKey{TenantID: tenantID, UserID: userID}]
	if !ok {
		return nil, ErrSessionNotFound
	}

	session, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

func (m *MemorySessionStore) Put(ctx context.Context, session *SessionData) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[session.ID]; exists {
		return ErrSessionExists
	}

	m.sessions[session.ID] = session
	m.userIndex[userKey{TenantID: session.TenantID, UserID: session.UserID}] = session.ID
	return nil
}

func (m *MemorySessionStore) Update(ctx context.Context, session *SessionData) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[session.ID]; !exists {
		return ErrSessionNotFound
	}

	m.sessions[session.ID] = session
	m.userIndex[userKey{TenantID: session.TenantID, UserID: session.UserID}] = session.ID
	return nil
}

func (m *MemorySessionStore) Delete(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return nil // Idempotent
	}

	// Only drop the index entry if it still points at this session.
	k := userKey{TenantID: session.TenantID, UserID: session.UserID}
	if m.userIndex[k] == sessionID {
		delete(m.userIndex, k)
	}
	delete(m.sessions, sessionID)
	return nil
}

func (m *MemorySessionStore) DeleteByUser(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, session := range m.sessions {
		if session.UserID == userID {
			delete(m.sessions, id)
		}
	}
	for k := range m.userIndex {
		if k.UserID == userID {
			delete(m.userIndex, k)
		}
	}
	return nil
}

func (m *MemorySessionStore) List(ctx context.Context, tenantID string) ([]*SessionData, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*SessionData
	now := time.Now()
	for _, session := range m.sessions {
		if session.TenantID == tenantID && now.Before(session.ExpiresAt) {
			result = append(result, session)
		}
	}
	return result, nil
}

func (m *MemorySessionStore) Cleanup(ctx context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var count int64
	now := time.Now()
	for id, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			k := userKey{TenantID: session.TenantID, UserID: session.UserID}
			if m.userIndex[k] == id {
				delete(m.userIndex, k)
			}
			delete(m.sessions, id)
			count++
		}
	}

	if count > 0 {
		m.logger.Debug("Cleaned up expired sessions", zap.Int64("count", count))
	}
	return count, nil
}

func (m *MemorySessionStore) Close() error {
	return nil
}

// compareAndDeleteScript deletes KEYS[1] only if its value equals ARGV[1]. It
// runs atomically inside Redis.
var compareAndDeleteScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
end
return 0
`)

// RedisSessionStore stores sessions in Redis for horizontal scaling.
type RedisSessionStore struct {
	client     *redis.Client
	keyPrefix  string
	defaultTTL time.Duration
	logger     *zap.Logger
}

// RedisSessionConfig configures a Redis session store.
type RedisSessionConfig struct {
	Address    string
	Password   string
	DB         int
	KeyPrefix  string
	DefaultTTL time.Duration
}

// NewRedisSessionStore creates a new Redis session store.
func NewRedisSessionStore(cfg *RedisSessionConfig, logger *zap.Logger) (*RedisSessionStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "ws:session:"
	}

	ttl := cfg.DefaultTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	return &RedisSessionStore{
		client:     client,
		keyPrefix:  prefix,
		defaultTTL: ttl,
		logger:     logger.Named("redis_store"),
	}, nil
}

func (r *RedisSessionStore) sessionKey(sessionID string) string {
	return r.keyPrefix + sessionID
}

// userKey is the per-(tenant, user) pointer to that user's current session.
func (r *RedisSessionStore) userKey(tenantID, userID string) string {
	return r.keyPrefix + "user:" + url.PathEscape(tenantID) + ":" + url.PathEscape(userID)
}

// userSetKey holds the IDs of all of a user's sessions across tenants, so a
// user-wide DeleteByUser can find them.
func (r *RedisSessionStore) userSetKey(userID string) string {
	return r.keyPrefix + "userall:" + url.PathEscape(userID)
}

func (r *RedisSessionStore) tenantKey(tenantID string) string {
	return r.keyPrefix + "tenant:" + tenantID
}

func (r *RedisSessionStore) Get(ctx context.Context, sessionID string) (*SessionData, error) {
	data, err := r.client.Get(ctx, r.sessionKey(sessionID)).Bytes()
	if err == redis.Nil {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	var session SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionNotFound
	}

	return &session, nil
}

func (r *RedisSessionStore) GetByUser(ctx context.Context, tenantID, userID string) (*SessionData, error) {
	sessionID, err := r.client.Get(ctx, r.userKey(tenantID, userID)).Result()
	if err == redis.Nil {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	return r.Get(ctx, sessionID)
}

func (r *RedisSessionStore) Put(ctx context.Context, session *SessionData) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		ttl = r.defaultTTL
	}

	// Use transaction for atomicity
	pipe := r.client.TxPipeline()
	pipe.SetNX(ctx, r.sessionKey(session.ID), data, ttl)
	pipe.Set(ctx, r.userKey(session.TenantID, session.UserID), session.ID, ttl)
	pipe.SAdd(ctx, r.tenantKey(session.TenantID), session.ID)
	pipe.SAdd(ctx, r.userSetKey(session.UserID), session.ID)

	_, err = pipe.Exec(ctx)
	return err
}

func (r *RedisSessionStore) Update(ctx context.Context, session *SessionData) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		ttl = r.defaultTTL
	}

	// Check exists first
	exists, err := r.client.Exists(ctx, r.sessionKey(session.ID)).Result()
	if err != nil {
		return err
	}
	if exists == 0 {
		return ErrSessionNotFound
	}

	pipe := r.client.TxPipeline()
	pipe.Set(ctx, r.sessionKey(session.ID), data, ttl)
	pipe.Set(ctx, r.userKey(session.TenantID, session.UserID), session.ID, ttl)

	_, err = pipe.Exec(ctx)
	return err
}

func (r *RedisSessionStore) Delete(ctx context.Context, sessionID string) error {
	// Get session first to clean up indexes
	session, err := r.Get(ctx, sessionID)
	if err == ErrSessionNotFound {
		return nil // Idempotent
	}
	if err != nil {
		return err
	}

	pipe := r.client.TxPipeline()
	pipe.Del(ctx, r.sessionKey(sessionID))
	pipe.SRem(ctx, r.tenantKey(session.TenantID), sessionID)
	pipe.SRem(ctx, r.userSetKey(session.UserID), sessionID)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return err
	}
	// Drop the (tenant, user) pointer only if it still names this session; a
	// newer session may have replaced it. The compare and the delete must be
	// one atomic step: with a separate GET and DEL another replica could
	// repoint the key in between and the DEL would remove the live
	// replacement's pointer.
	return compareAndDeleteScript.Run(ctx, r.client,
		[]string{r.userKey(session.TenantID, session.UserID)}, sessionID).Err()
}

func (r *RedisSessionStore) DeleteByUser(ctx context.Context, userID string) error {
	ids, err := r.client.SMembers(ctx, r.userSetKey(userID)).Result()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := r.Delete(ctx, id); err != nil {
			return err
		}
	}
	return r.client.Del(ctx, r.userSetKey(userID)).Err()
}

func (r *RedisSessionStore) List(ctx context.Context, tenantID string) ([]*SessionData, error) {
	sessionIDs, err := r.client.SMembers(ctx, r.tenantKey(tenantID)).Result()
	if err != nil {
		return nil, err
	}

	var result []*SessionData
	for _, id := range sessionIDs {
		session, err := r.Get(ctx, id)
		if err == ErrSessionNotFound {
			// Clean up stale reference
			r.client.SRem(ctx, r.tenantKey(tenantID), id)
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, session)
	}

	return result, nil
}

func (r *RedisSessionStore) Cleanup(ctx context.Context) (int64, error) {
	// Redis handles TTL-based expiration automatically.
	// This method is mainly for cleaning up tenant set references.
	// In production, run this periodically.
	r.logger.Debug("Redis cleanup - TTL handles session expiration")
	return 0, nil
}

func (r *RedisSessionStore) Close() error {
	return r.client.Close()
}
