// Package engine provides WebSocket v2 protocol implementation.
package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
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

	// Delete removes a session by ID. tenantID and userID name the session's
	// indexes: they are the fallback when the record itself is already gone
	// (expired or lost), so the indexes are cleaned even then.
	Delete(ctx context.Context, tenantID, userID, sessionID string) error

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

	// A user holds one session per tenant: the one the index names is superseded
	// and dropped, so replaced sessions do not accumulate until Cleanup.
	k := userKey{TenantID: normalizeTenant(session.TenantID), UserID: session.UserID}
	// Anonymous sessions (empty user ID) share one key and are independent, so
	// they never supersede each other.
	if old, ok := m.userIndex[k]; ok && session.UserID != "" {
		delete(m.sessions, old)
	}
	m.sessions[session.ID] = session
	m.userIndex[k] = session.ID
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

func (m *MemorySessionStore) Delete(ctx context.Context, tenantID, userID, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		// The record is gone (e.g. dropped by Cleanup) but the index entry may
		// still name it: remove it by the caller's (tenant, user).
		k := userKey{TenantID: normalizeTenant(tenantID), UserID: userID}
		if m.userIndex[k] == sessionID {
			delete(m.userIndex, k)
		}
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

// compareAndSetScript updates a pointer only if it still names the value that
// was observed, so a concurrent Put cannot be overwritten by reconciliation.
var compareAndSetScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
	redis.call("SET", KEYS[1], ARGV[2], "PX", ARGV[3])
	return 1
end
return 0
`)

// indexAddLua records a session ID in an expiry-scored sorted set (the user set
// and the tenant set share it), scored by expiry (unix ms), drops expired
// members and expires the set with its longest-lived member, so a set cannot
// outlive the sessions it indexes. It is wrapped in do/end so it can be
// repeated in one script. Time
// comes from the Redis server so replicas with skewed clocks agree. ZADD GT
// never lowers an existing member's expiry: a delayed legacy backfill that read
// a session before Update extended it must not overwrite the renewed score with
// the older, shorter one.
const indexAddLua = `
do
local t = redis.call("TIME")
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call("ZADD", %[1]s, "GT", string.format("%%.0f", now + tonumber(%[2]s)), %[3]s)
redis.call("ZREMRANGEBYSCORE", %[1]s, "-inf", string.format("%%.0f", now))
local top = redis.call("ZRANGE", %[1]s, -1, -1, "WITHSCORES")
if top[2] then
	redis.call("PEXPIREAT", %[1]s, string.format("%%.0f", tonumber(top[2])))
end
end
`

// indexAddScript adds a session to one expiry-scored sorted set.
// KEYS[1] = set, ARGV[1] = session TTL (ms), ARGV[2] = session ID.
var indexAddScript = redis.NewScript(fmt.Sprintf(indexAddLua, "KEYS[1]", "ARGV[1]", "ARGV[2]") + `
return 1
`)

// putSessionScript stores a new session and indexes it, or does nothing and
// returns 0 when the session key already exists: a duplicate ID must not
// repoint the user's pointer or add index entries for data that was not
// stored.
// KEYS = session, user pointer, tenant set, user set (both expiry-scored);
// ARGV = session JSON, TTL (ms), session ID.
var putSessionScript = redis.NewScript(`
if not redis.call("SET", KEYS[1], ARGV[1], "NX", "PX", ARGV[2]) then
	return 0
end
redis.call("SET", KEYS[2], ARGV[3], "PX", ARGV[2])
` + fmt.Sprintf(indexAddLua, "KEYS[3]", "ARGV[2]", "ARGV[3]") +
	fmt.Sprintf(indexAddLua, "KEYS[4]", "ARGV[2]", "ARGV[3]") + `
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

// legacyTenantKey is the pre-expiry-scoring tenant SET (`tenant:<raw tenant
// ID>`), which had no TTL. Never written now; List reads it and Delete,
// DeleteByUser and List remove members from it so sessions of replicas on the
// previous release stay visible during a rolling upgrade and the set drains.
func (r *RedisSessionStore) legacyTenantKey(tenantID string) string {
	return r.keyPrefix + "tenant:" + tenantID
}

// tenantKey is the expiry-scored sorted set of a tenant's session IDs, indexed
// like userSetKey: pruned on every add and expired with its longest-lived
// member. It lives in its own namespace because the legacy `tenant:` key is a
// plain SET and a sorted set cannot share its name.
func (r *RedisSessionStore) tenantKey(tenantID string) string {
	return r.keyPrefix + "tenantx:" + url.PathEscape(normalizeTenant(tenantID))
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
	uk := r.userKey(tenantID, userID)
	for {
		sessionID, err := r.client.Get(ctx, uk).Result()
		if err == redis.Nil {
			legacy, err := r.getByLegacyUser(ctx, tenantID, userID)
			if err != nil && err != ErrSessionNotFound {
				return nil, err
			}
			currentID, currentErr := r.client.Get(ctx, uk).Result()
			if currentErr == redis.Nil {
				return legacy, err
			}
			if currentErr != nil {
				return nil, currentErr
			}
			if err == nil && currentID == legacy.ID {
				return legacy, nil
			}
			continue
		}
		if err != nil {
			return nil, err
		}

		session, err := r.Get(ctx, sessionID)
		if err == ErrSessionNotFound {
			// The pointer names a session that is gone. During a rolling
			// upgrade an old replica can replace it under the legacy pointer.
			// Drop this pointer only if it still names the dead session.
			if err := compareAndDeleteScript.Run(ctx, r.client, []string{uk}, sessionID).Err(); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		if session.UserID != userID || normalizeTenant(session.TenantID) != normalizeTenant(tenantID) {
			if err := compareAndDeleteScript.Run(ctx, r.client, []string{uk}, sessionID).Err(); err != nil {
				return nil, err
			}
			continue
		}

		legacy, err := r.getByLegacyUser(ctx, tenantID, userID)
		if err == ErrSessionNotFound || (err == nil && !legacy.CreatedAt.After(session.CreatedAt)) {
			return session, nil
		}
		if err != nil {
			return nil, err
		}

		ttl := time.Until(legacy.ExpiresAt)
		if ttl <= 0 {
			return session, nil
		}
		updated, err := compareAndSetScript.Run(ctx, r.client, []string{uk}, sessionID, legacy.ID, max(1, ttl.Milliseconds())).Int()
		if err != nil {
			return nil, err
		}
		if updated == 1 {
			return legacy, nil
		}
		// The scoped pointer changed concurrently; read it again and compare
		// the current live sessions rather than returning a stale candidate.
	}
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
		r.indexSession(ctx, pipe, session, ttl)
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

	created, err := putSessionScript.Run(ctx, r.client,
		[]string{
			r.sessionKey(session.ID),
			r.userKey(session.TenantID, session.UserID),
			r.tenantKey(session.TenantID),
			r.userSetKey(session.UserID),
		},
		data, ttl.Milliseconds(), session.ID).Int()
	if err != nil {
		return err
	}
	if created == 0 {
		return ErrSessionExists
	}
	return nil
}

// indexSession queues the expiry-scored tenant-set and user-set updates on
// pipe. Both use ZADD GT, so a delayed backfill never lowers an expiry that
// Update has extended.
func (r *RedisSessionStore) indexSession(ctx context.Context, pipe redis.Pipeliner, session *SessionData, ttl time.Duration) {
	for _, key := range []string{r.tenantKey(session.TenantID), r.userSetKey(session.UserID)} {
		indexAddScript.Eval(ctx, pipe, []string{key}, ttl.Milliseconds(), session.ID)
	}
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
	r.indexSession(ctx, pipe, session, ttl)

	_, err = pipe.Exec(ctx)
	return err
}

func (r *RedisSessionStore) Delete(ctx context.Context, tenantID, userID, sessionID string) error {
	// The record, if present (even past ExpiresAt, until Redis drops the key),
	// names the indexes authoritatively. When it is gone - a WebSocket open
	// longer than the session TTL, or a lost record - the caller's tenant and
	// user still name them, so the indexes are cleaned either way instead of
	// keeping a member for a session that no longer exists.
	session, err := r.rawSession(ctx, sessionID)
	if err != nil && err != ErrSessionNotFound {
		return err
	}
	if err == nil {
		tenantID, userID = session.TenantID, session.UserID
	}

	// Everything goes in one transaction, so a connection failure cannot commit
	// the session deletion but lose the pointer cleanup (a retry would find the
	// session already gone and never clean the pointers up). The pointers are
	// dropped only if they still name this session, atomically inside the
	// transaction: a separate GET and DEL would let another replica repoint a
	// pointer in between and the DEL would remove the live replacement's.
	// A legacy pointer naming this session must go too (rolling upgrade).
	pipe := r.client.TxPipeline()
	pipe.Del(ctx, r.sessionKey(sessionID))
	pipe.ZRem(ctx, r.tenantKey(tenantID), sessionID)
	pipe.ZRem(ctx, r.userSetKey(userID), sessionID)
	for _, legacy := range r.legacyTenantKeys(tenantID) {
		pipe.SRem(ctx, legacy, sessionID)
	}
	compareAndDeleteScript.Eval(ctx, pipe, []string{r.legacyUserKey(userID)}, sessionID)
	compareAndDeleteScript.Eval(ctx, pipe, []string{r.userKey(tenantID, userID)}, sessionID)
	_, err = pipe.Exec(ctx)
	return err
}

// legacyTenantKeys returns the legacy tenant SET keys that may hold a session
// of tenantID: the normalised ID's and, when it differs, the raw one's.
func (r *RedisSessionStore) legacyTenantKeys(tenantID string) []string {
	keys := []string{r.legacyTenantKey(normalizeTenant(tenantID))}
	if raw := r.legacyTenantKey(tenantID); raw != keys[0] {
		keys = append(keys, raw)
	}
	return keys
}

// deleteBatchSize bounds how many sessions one DeleteByUser script call
// removes, keeping each (blocking) script short.
const deleteBatchSize = 100

// deleteUserBatchScript atomically removes a batch of one user's sessions and
// ZREMs exactly those members (a concurrent Put's member is found next round).
// KEYS[1] = user set, ARGV[1] = legacy pointer key, then groups of 6: session
// ID, session key, pointer key, tenant set key, legacy tenant set key, raw
// legacy tenant set key. Empty keys
// are skipped. Pointers are removed only if they still name the session.
var deleteUserBatchScript = redis.NewScript(`
for i = 2, #ARGV, 6 do
	local id = ARGV[i]
	if ARGV[i+1] ~= "" then redis.call("DEL", ARGV[i+1]) end
	if ARGV[i+2] ~= "" and redis.call("GET", ARGV[i+2]) == id then redis.call("DEL", ARGV[i+2]) end
	if redis.call("GET", ARGV[1]) == id then redis.call("DEL", ARGV[1]) end
	if ARGV[i+3] ~= "" then redis.call("ZREM", ARGV[i+3], id) end
	if ARGV[i+4] ~= "" then redis.call("SREM", ARGV[i+4], id) end
	if ARGV[i+5] ~= "" then redis.call("SREM", ARGV[i+5], id) end
	redis.call("ZREM", KEYS[1], id)
end
return 1
`)

// deleteUserSetIfEmptyScript deletes KEYS[1] (the user's set) only if it is
// empty and no legacy pointer (KEYS[2]) exists, returning 1 if done. Atomic, so
// a concurrent Put either lands before (caller loops) or after (creates a fresh
// set that indexes it). The legacy pointer is checked too because a replica on
// the previous release writes sessions that no set indexes: one created after
// the caller read the pointer must not be reported as deleted.
var deleteUserSetIfEmptyScript = redis.NewScript(`
if redis.call("ZCARD", KEYS[1]) == 0 and redis.call("EXISTS", KEYS[2]) == 0 then
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
		ids, hasLegacy, err := r.userDeleteCandidates(ctx, userID)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			done, err := r.dropUserSetIfEmpty(ctx, userID)
			if err != nil || done {
				return err
			}
			continue
		}
		if err := r.deleteBatch(ctx, userID, ids, hasLegacy); err != nil {
			return err
		}
	}
}

// dropUserSetIfEmpty atomically removes the user's set if it is empty and
// reports whether it is gone.
func (r *RedisSessionStore) dropUserSetIfEmpty(ctx context.Context, userID string) (bool, error) {
	done, err := deleteUserSetIfEmptyScript.Run(ctx, r.client, []string{r.userSetKey(userID), r.legacyUserKey(userID)}).Int()
	return done == 1, err
}

// deleteBatch removes one batch of the user's sessions atomically.
func (r *RedisSessionStore) deleteBatch(ctx context.Context, userID string, ids []string, hasLegacy bool) error {
	args, err := r.deleteBatchArgs(ctx, userID, ids, hasLegacy)
	if err != nil {
		return err
	}
	if err := deleteUserBatchScript.Run(ctx, r.client, []string{r.userSetKey(userID)}, args...).Err(); err != nil {
		return err
	}
	if r.betweenDeleteBatches != nil {
		r.betweenDeleteBatches()
	}
	return nil
}

// userDeleteCandidates returns the next batch of the user's session IDs,
// oldest-expiring first (expired members' keys are simply absent). Pre-upgrade
// sessions are known only via the legacy pointer, so the session it names, if
// any, is appended last and hasLegacy is true.
func (r *RedisSessionStore) userDeleteCandidates(ctx context.Context, userID string) (ids []string, hasLegacy bool, err error) {
	ids, err = r.client.ZRange(ctx, r.userSetKey(userID), 0, deleteBatchSize-1).Result()
	if err != nil {
		return nil, false, err
	}
	legacyID, err := r.client.Get(ctx, r.legacyUserKey(userID)).Result()
	if err != nil && err != redis.Nil {
		return nil, false, err
	}
	if err == nil {
		ids = append(ids, legacyID)
		hasLegacy = true
	}
	return ids, hasLegacy, nil
}

// deleteBatchArgs builds the deleteUserBatchScript arguments for ids: the
// legacy pointer key, then per session its ID, session key, scoped pointer
// key, tenant set key, legacy tenant set key and raw legacy tenant set key. A
// session that is already gone
// contributes only its ID (to be ZREMed); the legacy session is only deleted
// if it really belongs to userID.
func (r *RedisSessionStore) deleteBatchArgs(ctx context.Context, userID string, ids []string, hasLegacy bool) ([]any, error) {
	args := []any{r.legacyUserKey(userID)}
	for i, id := range ids {
		isLegacy := hasLegacy && i == len(ids)-1
		var sk, pk, tk, ltk, rtk string
		sess, err := r.rawSession(ctx, id)
		switch {
		case err == nil && (!isLegacy || sess.UserID == userID):
			sk = r.sessionKey(id)
			pk = r.userKey(sess.TenantID, sess.UserID)
			tk = r.tenantKey(sess.TenantID)
			legacy := r.legacyTenantKeys(sess.TenantID)
			ltk = legacy[0]
			if len(legacy) > 1 {
				rtk = legacy[1]
			}
		case err != nil && err != ErrSessionNotFound:
			return nil, err
		}
		args = append(args, id, sk, pk, tk, ltk, rtk)
	}
	return args, nil
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
	seen := make(map[string]struct{})
	ids, err := r.client.ZRange(ctx, r.tenantKey(tenantID), 0, -1).Result()
	if err != nil {
		return nil, err
	}
	result, err := r.liveSessions(ctx, ids, tenantID, seen, func(id string) {
		r.client.ZRem(ctx, r.tenantKey(tenantID), id)
	})
	if err != nil {
		return nil, err
	}

	// Sessions written by replicas on the previous release sit in plain SETs
	// (the raw empty-tenant one now means the default tenant), so read those
	// too until they expire.
	keys := r.legacyTenantKeys(tenantID)
	if raw := r.legacyTenantKey(""); normalizeTenant(tenantID) == domain.DefaultTenantID.String() && !slices.Contains(keys, raw) {
		keys = append(keys, raw)
	}
	for _, key := range keys {
		ids, err := r.client.SMembers(ctx, key).Result()
		if err != nil {
			return nil, err
		}
		sessions, err := r.liveSessions(ctx, ids, tenantID, seen, func(id string) {
			r.client.SRem(ctx, key, id)
		})
		if err != nil {
			return nil, err
		}
		result = append(result, sessions...)
	}
	return result, nil
}

// liveSessions returns the live sessions among ids that belong to tenantID
// (after normalisation) and are not already in seen, recording each id it
// visits in seen. onStale is called for ids whose session is gone.
func (r *RedisSessionStore) liveSessions(ctx context.Context, ids []string, tenantID string, seen map[string]struct{}, onStale func(id string)) ([]*SessionData, error) {
	var result []*SessionData
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		session, err := r.Get(ctx, id)
		if err == ErrSessionNotFound {
			onStale(id)
			continue
		}
		if err != nil {
			return nil, err
		}
		if normalizeTenant(session.TenantID) == normalizeTenant(tenantID) {
			result = append(result, session)
		}
	}
	return result, nil
}

// Cleanup is a no-op for Redis, which needs no sweep: session keys carry a TTL
// and both indexes are expiry-scored sorted sets pruned of expired members on
// every add and expired with their longest-lived member, so none grows without
// bound. Only the legacy tenant SETs (written by the previous release, never by
// this one) are drained lazily, by List, Delete and DeleteByUser.
func (r *RedisSessionStore) Cleanup(ctx context.Context) (int64, error) {
	r.logger.Debug("Redis cleanup - TTL and expiry-scored indexes handle expiration")
	return 0, nil
}

func (r *RedisSessionStore) Close() error {
	return r.client.Close()
}
