// Package engine provides WebSocket v2 protocol implementation.
package engine

import (
	"context"
	"encoding/base64"
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

	sessionID, ok := m.userIndex[userKey{TenantID: normalizeTenant(tenantID), UserID: userID}]
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
	m.userIndex[userKey{TenantID: normalizeTenant(session.TenantID), UserID: session.UserID}] = session.ID
	return nil
}

func (m *MemorySessionStore) Update(ctx context.Context, session *SessionData) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[session.ID]; !exists {
		return ErrSessionNotFound
	}

	m.sessions[session.ID] = session
	m.userIndex[userKey{TenantID: normalizeTenant(session.TenantID), UserID: session.UserID}] = session.ID
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
	k := userKey{TenantID: normalizeTenant(session.TenantID), UserID: session.UserID}
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
		if normalizeTenant(session.TenantID) == normalizeTenant(tenantID) && now.Before(session.ExpiresAt) {
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
			k := userKey{TenantID: normalizeTenant(session.TenantID), UserID: session.UserID}
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

// userSessionsAddScript records a session in the user's sorted set, scored by
// expiry (unix ms), drops expired members and expires the set with its
// longest-lived member, so a set cannot outlive the sessions it indexes.
// Time comes from the Redis server so replicas with skewed clocks agree.
// KEYS[1] = set, ARGV[1] = session TTL (ms), ARGV[2] = session ID.
var userSessionsAddScript = redis.NewScript(`
local t = redis.call("TIME")
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call("ZADD", KEYS[1], string.format("%.0f", now + tonumber(ARGV[1])), ARGV[2])
redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", string.format("%.0f", now))
local top = redis.call("ZRANGE", KEYS[1], -1, -1, "WITHSCORES")
if top[2] then
	redis.call("PEXPIREAT", KEYS[1], string.format("%.0f", tonumber(top[2])))
end
return 1
`)

// RedisSessionStore stores sessions in Redis for horizontal scaling.
type RedisSessionStore struct {
	client     *redis.Client
	keyPrefix  string
	defaultTTL time.Duration
	logger     *zap.Logger

	// betweenDeleteBatches is a test hook run after each DeleteByUser batch.
	betweenDeleteBatches func()
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

// userKey is the per-(tenant, user) pointer to the user's current session.
//
// It lives in its own `usert:` namespace, disjoint from the legacy
// `user:<userID>` pointer, and encodes both fields as unpadded base64url
// (never ':'), so distinct pairs cannot collide; sharing the legacy namespace
// would let legacy user "default:u" collide with (tenant "default", user "u").
func (r *RedisSessionStore) userKey(tenantID, userID string) string {
	enc := base64.RawURLEncoding
	return r.keyPrefix + "usert:" +
		enc.EncodeToString([]byte(normalizeTenant(tenantID))) + ":" +
		enc.EncodeToString([]byte(userID))
}

// userSetKey is the expiry-scored set of all of a user's session IDs across
// tenants, for DeleteByUser. TTL'd and pruned on every add.
func (r *RedisSessionStore) userSetKey(userID string) string {
	return r.keyPrefix + "userall:" + url.PathEscape(userID)
}

// legacyUserKey is the pre-tenant-scoping pointer (`<prefix>user:<userID>`, raw,
// so ambiguous when IDs contain ':'; readers must verify the named session's
// user and tenant). Never written now; read and removed so sessions from
// replicas on the previous release stay reachable during a rolling upgrade.
// Bounded by the maximum session TTL (DefaultTTL, 24h by default).
func (r *RedisSessionStore) legacyUserKey(userID string) string {
	return r.keyPrefix + "user:" + userID
}

// legacyTenantKey is the pre-normalisation tenant set (raw tenant ID).
func (r *RedisSessionStore) legacyTenantKey(tenantID string) string {
	return r.keyPrefix + "tenant:" + tenantID
}

func (r *RedisSessionStore) tenantKey(tenantID string) string {
	return r.keyPrefix + "tenant:" + normalizeTenant(tenantID)
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
		return r.getByLegacyUser(ctx, tenantID, userID)
	}
	if err != nil {
		return nil, err
	}

	return r.Get(ctx, sessionID)
}

// getByLegacyUser resolves a session through the legacy pointer. It is
// returned only if it belongs to the requested user and (normalised) tenant,
// so no other tenant's session leaks. A match is lazily backfilled into the
// new pointer (SET NX, never overwriting a newer session) and user index.
func (r *RedisSessionStore) getByLegacyUser(ctx context.Context, tenantID, userID string) (*SessionData, error) {
	sessionID, err := r.client.Get(ctx, r.legacyUserKey(userID)).Result()
	if err == redis.Nil {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	session, err := r.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session.UserID != userID || normalizeTenant(session.TenantID) != normalizeTenant(tenantID) {
		return nil, ErrSessionNotFound
	}

	if ttl := time.Until(session.ExpiresAt); ttl > 0 {
		pipe := r.client.TxPipeline()
		// SET NX: another replica may have Put a newer session since the miss; an
		// unconditional SET would repoint the user to this older one. The set
		// memberships below are idempotent.
		pipe.SetNX(ctx, r.userKey(session.TenantID, session.UserID), session.ID, ttl)
		pipe.SAdd(ctx, r.tenantKey(session.TenantID), session.ID)
		r.indexUserSession(ctx, pipe, session, ttl)
		if _, err := pipe.Exec(ctx); err != nil {
			r.logger.Warn("Failed to backfill legacy session indexes", zap.Error(err))
		}
	}
	return session, nil
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
	r.indexUserSession(ctx, pipe, session, ttl)

	_, err = pipe.Exec(ctx)
	return err
}

// indexUserSession queues the expiry-scored user-set update on pipe.
func (r *RedisSessionStore) indexUserSession(ctx context.Context, pipe redis.Pipeliner, session *SessionData, ttl time.Duration) {
	userSessionsAddScript.Eval(ctx, pipe, []string{r.userSetKey(session.UserID)},
		ttl.Milliseconds(), session.ID)
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
	r.indexUserSession(ctx, pipe, session, ttl)

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
	pipe.ZRem(ctx, r.userSetKey(session.UserID), sessionID)
	if raw := r.legacyTenantKey(session.TenantID); raw != r.tenantKey(session.TenantID) {
		pipe.SRem(ctx, raw, sessionID)
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return err
	}
	// A legacy pointer naming this session must go too (rolling upgrade).
	if err := compareAndDeleteScript.Run(ctx, r.client,
		[]string{r.legacyUserKey(session.UserID)}, sessionID).Err(); err != nil {
		return err
	}
	// Drop the pointer only if it still names this session, atomically: with a
	// separate GET and DEL another replica could repoint it in between and the
	// DEL would remove the live replacement's pointer.
	return compareAndDeleteScript.Run(ctx, r.client,
		[]string{r.userKey(session.TenantID, session.UserID)}, sessionID).Err()
}

// deleteBatchSize bounds how many sessions one DeleteByUser script call
// removes, keeping each (blocking) script short.
const deleteBatchSize = 100

// deleteUserBatchScript atomically removes a batch of one user's sessions and
// ZREMs exactly those members (a concurrent Put's member is found next round).
// KEYS[1] = user set, ARGV[1] = legacy pointer key, then groups of 5: session
// ID, session key, pointer key, tenant set key, raw tenant set key. Empty keys
// are skipped. Pointers are removed only if they still name the session.
var deleteUserBatchScript = redis.NewScript(`
for i = 2, #ARGV, 5 do
	local id = ARGV[i]
	if ARGV[i+1] ~= "" then redis.call("DEL", ARGV[i+1]) end
	if ARGV[i+2] ~= "" and redis.call("GET", ARGV[i+2]) == id then redis.call("DEL", ARGV[i+2]) end
	if redis.call("GET", ARGV[1]) == id then redis.call("DEL", ARGV[1]) end
	if ARGV[i+3] ~= "" then redis.call("SREM", ARGV[i+3], id) end
	if ARGV[i+4] ~= "" then redis.call("SREM", ARGV[i+4], id) end
	redis.call("ZREM", KEYS[1], id)
end
return 1
`)

// deleteUserSetIfEmptyScript deletes KEYS[1] only if empty, returning 1 if
// gone. Atomic, so a concurrent Put either lands before (caller loops) or
// after (creates a fresh set that indexes it).
var deleteUserSetIfEmptyScript = redis.NewScript(`
if redis.call("ZCARD", KEYS[1]) == 0 then
	redis.call("DEL", KEYS[1])
	return 1
end
return 0
`)

// DeleteByUser removes the user's sessions in every tenant. It deletes bounded
// batches until an atomic check finds the set empty.
//
// Every session indexed at the final check (and every legacy-pointer session)
// is removed, and none is left indexed-but-undiscoverable. A session created
// after the final check is not removed here; the engine's user-revocation
// gate refuses and closes it.
func (r *RedisSessionStore) DeleteByUser(ctx context.Context, userID string) error {
	for {
		// Oldest-expiring first; expired members' keys are simply absent.
		ids, err := r.client.ZRange(ctx, r.userSetKey(userID), 0, deleteBatchSize-1).Result()
		if err != nil {
			return err
		}
		// Pre-upgrade sessions are known only via the legacy pointer: include the
		// session it names (if this user's) and always remove the pointer.
		legacyID, err := r.client.Get(ctx, r.legacyUserKey(userID)).Result()
		if err != nil && err != redis.Nil {
			return err
		}
		hasLegacy := err == nil
		if hasLegacy {
			ids = append(ids, legacyID)
		}

		if len(ids) == 0 {
			done, err := deleteUserSetIfEmptyScript.Run(ctx, r.client, []string{r.userSetKey(userID)}).Int()
			if err != nil {
				return err
			}
			if done == 1 {
				return nil
			}
			continue
		}

		args := []any{r.legacyUserKey(userID)}
		for i, id := range ids {
			isLegacy := hasLegacy && i == len(ids)-1
			var sk, pk, tk, rtk string
			if sess, gerr := r.rawSession(ctx, id); gerr == nil && (!isLegacy || sess.UserID == userID) {
				sk = r.sessionKey(id)
				pk = r.userKey(sess.TenantID, sess.UserID)
				tk = r.tenantKey(sess.TenantID)
				if raw := r.legacyTenantKey(sess.TenantID); raw != tk {
					rtk = raw
				}
			} else if gerr != nil && gerr != ErrSessionNotFound {
				return gerr
			}
			args = append(args, id, sk, pk, tk, rtk)
		}
		if err := deleteUserBatchScript.Run(ctx, r.client, []string{r.userSetKey(userID)}, args...).Err(); err != nil {
			return err
		}
		if r.betweenDeleteBatches != nil {
			r.betweenDeleteBatches()
		}
	}
}

// rawSession reads a session without the expiry check, for cleanup.
func (r *RedisSessionStore) rawSession(ctx context.Context, sessionID string) (*SessionData, error) {
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
	return &session, nil
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
	// Redis handles TTL-based expiration of session keys automatically.
	// User session sets are pruned on every add (userSessionsAddScript); tenant
	// set members lazily by List. Nothing to do here.
	r.logger.Debug("Redis cleanup - TTL handles session expiration")
	return 0, nil
}

func (r *RedisSessionStore) Close() error {
	return r.client.Close()
}
